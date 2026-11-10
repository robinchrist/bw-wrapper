package main

// Coordination between everything that touches one vault root.
//
// It lives in <root>/.bw-wrapper/, inside the Bitwarden CLI's own data
// directory, because that is the one place every process working on the same
// vault agrees on: runtime directories, TMPDIR and socket overrides differ
// between a desktop shell and a cron job. No credentials are stored there.
//
//	meta.lock   short lock around reads and writes of the files below
//	state       the session protocol state (see coordState)
//	op.lock     held, exclusively, by the one session operation that is
//	            running; the real CLI it runs inherits it
//	owner       who holds op.lock (pid of the wrapper, pid of its real CLI),
//	            so that a lock/logout can cancel a login/unlock
//	revoke.lock shared by every lock or logout from the moment it revokes
//	            until its outcome is recorded: a revocation that is pending
//	use.lock    shared by every command that was admitted to use an existing
//	            session (its lease), for as long as it runs and writes
//	            output; a lock or logout waits until those are gone
//	leases/     one file per process that holds a lease (named after its
//	            pid): how a lock or logout finds the processes it has to
//	            wait for or stop, on every system
//	activity/   one file per session (named after its tag): its modification
//	            time is when that session was last used through the wrapper
//	data.lock   held by every real-CLI process the wrapper starts on this
//	            root: exclusively by a run whose data file snapshot may be
//	            restored (hold mode) and by session commands, shared by all
//	            others
//	daemons/    one file per daemon, named after its session tag, containing
//	            its socket path
//
// # The session protocol
//
// Three values, always changed together under the metadata lock:
//
//	gen     cache generation. A loaded vault belongs to one generation and is
//	        answered from only while that generation is current. Every
//	        session operation starts a new one before it may change anything.
//	epoch   revocation epoch. Advanced by lock and logout (manual or
//	        automatic). A login or unlock remembers the epoch it was started
//	        under and gives up if the epoch has moved: a request made before
//	        a lock can never open the vault after it.
//	access  open      normal
//	        revoking  a lock or logout has begun and not yet reported
//	        blocked   a lock or logout began and did not succeed
//
// A lock or logout is pending from its revocation until it has recorded its
// outcome (it holds revoke.lock for that time; if its process dies, the
// kernel drops the lock). While one is pending, nothing is given out, and no
// login or unlock starts or counts: a revocation keeps its place in the
// order of session commands even before it holds the operation lock.
//
// While access is not open and a session is still usable on disk, the wrapper
// gives out nothing: no vault is loaded or published, no snapshot restored,
// and no command that needs the vault is handed to the real CLI. A lock that
// fails therefore still ends access through the wrapper; it does not quietly
// become "cache evicted". Only a login or unlock that was started after the
// revocation, and succeeds, opens access again.
//
// Whether a command may use an existing session is decided in one place,
// coord.admit, with three outcomes: allowed, denied, unknown. Unknown (the
// state cannot be read, a lock file cannot be taken) is treated as denied.
// An admitted command holds a lease (use.lock) until it has exited, whether
// its answer comes from a daemon or from the real CLI.
//
// The rules, in one place:
//
//	publish a loaded vault   generation unchanged during the load, no session
//	                         operation active, access not blocked
//	answer from memory       the vault's generation is the current one
//	use an existing session  admitted (coord.admit): access not blocked, the
//	(cached or real CLI)     session not idle beyond auto_lock; checked again
//	                         right before the real CLI starts
//	restore a snapshot       same generation as at the snapshot, no operation
//	                         active, access not blocked (hold.go)
//	enter hold               session vanished while generation and epoch
//	                         stayed, no operation active
//	login / unlock           no revocation pending, epoch unchanged between
//	                         request and completion; access opens again only
//	                         if the new session is verified on disk
//	lock / logout            epoch+1, access=revoking, new generation first;
//	                         then cancel a running login/unlock, wipe caches,
//	                         wait for real-CLI runs that started earlier (and
//	                         stop them if they do not end), run the real
//	                         command, record the outcome as the data file
//	                         shows it (exit codes are not evidence)
//	auto-lock                the same sequence, entered only if (holding
//	                         op.lock) the session is still ours and idle.
//	                         Idle time is the root's (activity), checked
//	                         before a command renews it.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type coord struct {
	dir  string
	root string
}

// openCoord returns the coordination directory of root, creating it if
// needed. It refuses a directory that is not private to the user.
//
// Two kinds of failure are told apart, because they mean different things
// for a command that wants to use an existing session:
//
//   - errNoCoord: the directory does not exist and cannot be created (a
//     read-only root). No session state was ever recorded for this root, so
//     there is nothing a command could violate; nothing is cached either.
//   - anything else: the directory is there but cannot be used. What it says
//     about revocations is unknown, and unknown means denied.
func openCoord(root string) (*coord, error) {
	dir := filepath.Join(root, ".bw-wrapper")
	_, statErr := os.Lstat(dir)
	if err := os.MkdirAll(filepath.Join(dir, "daemons"), 0o700); err != nil {
		if os.IsNotExist(statErr) {
			return nil, fmt.Errorf("%w: %v", errNoCoord, err)
		}
		return nil, err
	}
	for _, sub := range []string{"activity", "leases"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	for _, p := range []string{dir, filepath.Join(dir, "daemons"), filepath.Join(dir, "activity"), filepath.Join(dir, "leases")} {
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 || (ok && int(st.Uid) != os.Getuid()) {
			return nil, fmt.Errorf("%s must be a directory owned by you with mode 0700", p)
		}
	}
	return &coord{dir: dir, root: root}, nil
}

var errNoCoord = errors.New("no coordination directory")

func (c *coord) path(name string) string { return filepath.Join(c.dir, name) }

// lockMeta takes the short metadata lock. It is never held while waiting
// for a daemon or a child process.
func (c *coord) lockMeta() (unlock func(), err error) {
	f, err := os.OpenFile(c.path("meta.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr == nil && cerr == nil {
		werr = os.Rename(tmp.Name(), path)
	}
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	return nil
}

// ---------- state ----------

const (
	accessOpen     = "open"
	accessRevoking = "revoking"
	accessBlocked  = "blocked"
)

// coordState is the persistent session protocol state of a root.
type coordState struct {
	Gen    string `json:"gen"`
	Epoch  int64  `json:"epoch"`
	Access string `json:"access"`
	Reason string `json:"reason,omitempty"` // why access is not open
}

// mark is the coordination state at one moment.
type mark struct {
	coordState
	active bool // a session operation holds op.lock
	// revoking: a lock or logout has revoked and not yet recorded its outcome
	revoking bool
	st       stateStat // identity of the state file, for a one-stat "still current?"
}

type stateStat struct {
	ino         uint64
	size, mtime int64
}

func (c *coord) statState() (stateStat, error) {
	fi, err := os.Stat(c.path("state"))
	if err != nil {
		return stateStat{}, err
	}
	st := stateStat{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		st.ino = sys.Ino
	}
	return st, nil
}

func newToken() string {
	var nonce [16]byte
	rand.Read(nonce[:])
	return hex.EncodeToString(nonce[:])
}

// readStateLocked reads the state, creating the initial one. The caller
// holds the metadata lock. A state file that cannot be understood is an
// error: the caller then caches and restores nothing.
func (c *coord) readStateLocked() (coordState, error) {
	b, err := os.ReadFile(c.path("state"))
	if os.IsNotExist(err) {
		s := coordState{Gen: newToken(), Access: accessOpen}
		return s, c.writeStateLocked(s)
	}
	if err != nil {
		return coordState{}, err
	}
	var s coordState
	if err := json.Unmarshal(b, &s); err != nil || s.Gen == "" ||
		(s.Access != accessOpen && s.Access != accessRevoking && s.Access != accessBlocked) {
		return coordState{}, fmt.Errorf("%s is damaged", c.path("state"))
	}
	return s, nil
}

func (c *coord) writeStateLocked(s coordState) error {
	b, _ := json.Marshal(s)
	return writeAtomic(c.path("state"), b)
}

func (c *coord) markLocked() (mark, error) {
	s, err := c.readStateLocked()
	if err != nil {
		return mark{}, err
	}
	st, err := c.statState()
	if err != nil {
		return mark{}, err
	}
	return mark{coordState: s, active: c.opActiveLocked(), revoking: c.heldLocked("revoke.lock"), st: st}, nil
}

// mark reads state and operation activity consistently.
func (c *coord) mark() (mark, error) {
	unlock, err := c.lockMeta()
	if err != nil {
		return mark{}, err
	}
	defer unlock()
	return c.markLocked()
}

// update changes the state in one step under the metadata lock. change
// returns false to leave the state as it is.
func (c *coord) update(change func(s *coordState) bool) (coordState, error) {
	unlock, err := c.lockMeta()
	if err != nil {
		return coordState{}, err
	}
	defer unlock()
	s, err := c.readStateLocked()
	if err != nil {
		return coordState{}, err
	}
	if change(&s) {
		err = c.writeStateLocked(s)
	}
	return s, err
}

// newGeneration voids every vault cached and every snapshot taken so far.
// It does not touch the revocation epoch: a reload or an unlock that begins
// does not cancel a pending login.
func (c *coord) newGeneration() error {
	_, err := c.update(func(s *coordState) bool { s.Gen = newToken(); return true })
	return err
}

// revocation is a lock or logout between its first step and its last. It
// holds revoke.lock (shared: several can be pending) for that time, and the
// real CLI it runs inherits the lock.
type revocation struct {
	epoch int64
	f     *os.File
}

// done ends the pending state. Call it after settle.
func (r *revocation) done() { r.f.Close() }

// revoke begins a lock or logout: in one step, under the metadata lock, it
// becomes pending, the epoch advances (logins and unlocks requested so far
// are cancelled), access is no longer open and a new generation starts.
func (c *coord) revoke(reason string) (*revocation, error) {
	unlock, err := c.lockMeta()
	if err != nil {
		return nil, err
	}
	defer unlock()
	f, err := os.OpenFile(c.path("revoke.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		f.Close()
		return nil, err
	}
	s, err := c.readStateLocked()
	if err == nil {
		s.Epoch++
		s.Gen = newToken()
		s.Access = accessRevoking
		s.Reason = reason
		err = c.writeStateLocked(s)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return &revocation{epoch: s.Epoch, f: f}, nil
}

// settle records how the lock or logout that revoked at epoch ended. If a
// later revocation happened meanwhile, its own outcome decides.
func (c *coord) settle(epoch int64, ok bool, reason string) error {
	_, err := c.update(func(s *coordState) bool {
		if s.Epoch != epoch {
			return false
		}
		if ok {
			s.Access, s.Reason = accessOpen, ""
		} else {
			s.Access, s.Reason = accessBlocked, reason
		}
		return true
	})
	return err
}

// reopen is the last step of a login or unlock that was started under epoch
// and whose new session has been verified. It reports false if a lock or
// logout revoked in the meantime or is still pending: then this unlock does
// not count.
func (c *coord) reopen(epoch int64) (bool, error) {
	matched := false
	_, err := c.update(func(s *coordState) bool {
		if s.Epoch != epoch || c.heldLocked("revoke.lock") {
			return false
		}
		matched = true
		s.Access, s.Reason = accessOpen, ""
		return true
	})
	return matched && err == nil, err
}

// current reports whether m is still the current generation. The common
// case is one stat; the state is only read when the file was replaced.
func (c *coord) current(m mark) bool {
	st, err := c.statState()
	if err != nil {
		return false
	}
	if st == m.st {
		return true
	}
	now, err := c.mark()
	return err == nil && now.Gen == m.Gen
}

// sessionUsable reports whether the CLI's data file still holds a session
// somebody could use: logged in, with a stored (session-protected) user key.
// If the file cannot be read, the answer is yes: doubt keeps access blocked.
func sessionUsable(root string) bool {
	_, top, err := readDataFile(root)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return true
	}
	// A stored user key is a usable session whatever else the file says (the
	// account keys may be named differently in another CLI version). Any
	// other protected value counts while the CLI is logged in.
	authed := loginStateOf(top).authed
	for k := range top {
		if strings.HasPrefix(k, "__PROTECTED__") && (authed || strings.HasSuffix(k, "_user_auto")) {
			return true
		}
	}
	return false
}

// blocked reports whether the wrapper must give out nothing for this root:
// a lock or logout is pending, or one began and has not succeeded and there
// is still a session to protect (or an operation is still running). Once the data file shows no
// usable session, the revocation has achieved what it wanted, whatever
// happened to the process that was supposed to record it.
func (c *coord) blocked(m mark) bool {
	if m.revoking {
		return true
	}
	return m.Access != accessOpen && (m.active || sessionUsable(c.root))
}

// ---------- session operations ----------

// opActiveLocked probes op.lock; the caller holds the metadata lock, so two
// probes never mistake each other for an operation. Doubt counts as active.
func (c *coord) opActiveLocked() bool { return c.heldLocked("op.lock") }

// heldLocked reports whether anybody holds the named lock file. The caller
// holds the metadata lock. Doubt counts as held.
func (c *coord) heldLocked(name string) bool {
	f, err := os.OpenFile(c.path(name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return true
	}
	defer f.Close()
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil
}

// sessionOp is the exclusive right to change the CLI's session state.
type sessionOp struct {
	c *coord
	f *os.File // holds op.lock; passed to the real CLI so the lock lives as long as it does
}

type opOwner struct {
	PID   int    `json:"pid"`
	Start uint64 `json:"start,omitempty"` // start time of PID: a recycled pid is not the owner
	Child int    `json:"child,omitempty"`
	// ChildStart is the start time of Child.
	ChildStart uint64 `json:"child_start,omitempty"`
	Kind       string `json:"kind"`
}

// sameProcess reports whether pid is still the process that had the given
// start time. Where start times are not available (0), the pid has to do.
func sameProcess(pid int, start uint64) bool {
	if pid <= 1 {
		return false
	}
	return start == 0 || procStart(pid) == start
}

// opLogin marks the operations that create a session. They queue behind
// every pending revocation and are the ones a lock or logout cancels.
func opLogin(kind string) bool { return kind == "login" || kind == "unlock" }

// tryBeginOp takes op.lock if no operation is running (nil, nil if busy).
// A login or unlock also counts the root as busy while a lock or logout is
// pending: the revocation was there first, whoever gets to op.lock first.
func (c *coord) tryBeginOp(kind string) (*sessionOp, error) {
	unlock, err := c.lockMeta()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if opLogin(kind) && c.heldLocked("revoke.lock") {
		return nil, nil
	}
	f, err := os.OpenFile(c.path("op.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, nil // busy
	}
	op := &sessionOp{c: c, f: f}
	op.record(opOwner{PID: os.Getpid(), Start: procStart(os.Getpid()), Kind: kind})
	return op, nil
}

var errOpBusy = errors.New("another login, unlock, lock or logout is still running for this vault")

// opPoll is how often a waiting operation looks at op.lock again.
const opPoll = 10 * time.Millisecond

// opKillAfter is how long a lock or logout gives a login or unlock it asked
// to stop before it kills whatever still holds the operation lock.
var opKillAfter = 5 * time.Second

// beginOp waits for op.lock. With cancel set it first asks the running
// operation to stop: a lock or logout does not queue behind an unlock that
// sits at its password prompt. stillWanted, if given, is asked on every
// round; when it says no, the wait ends with errCancelled.
func (c *coord) beginOp(kind string, cancel bool, wait time.Duration, stillWanted func() bool) (*sessionOp, error) {
	start := time.Now()
	signalled, killed := false, false
	for {
		if stillWanted != nil && !stillWanted() {
			return nil, errCancelled
		}
		op, err := c.tryBeginOp(kind)
		if err != nil || op != nil {
			return op, err
		}
		waited := time.Since(start)
		if cancel && !signalled {
			c.signalOwner(syscall.SIGTERM, false)
			signalled = true
		}
		if cancel && !killed && waited > opKillAfter {
			// The owner file does not know every holder: a wrapper killed
			// right after starting its real CLI leaves a child that still
			// holds the lock. Those are found by the lock file itself. A
			// lock or logout that is alive is left to finish.
			c.signalOwner(syscall.SIGKILL, true)
			killed = true
		}
		if wait > 0 && waited > wait {
			return nil, errOpBusy
		}
		time.Sleep(opPoll)
	}
}

var errCancelled = errors.New("cancelled: the vault was locked or logged out in the meantime")

func (op *sessionOp) record(o opOwner) {
	b, _ := json.Marshal(o)
	writeAtomic(op.c.path("owner"), b)
}

// setChild records the real CLI process the operation runs.
func (op *sessionOp) setChild(pid int) {
	unlock, err := op.c.lockMeta()
	if err != nil {
		return
	}
	defer unlock()
	var o opOwner
	if b, err := os.ReadFile(op.c.path("owner")); err == nil && json.Unmarshal(b, &o) == nil && o.PID == os.Getpid() {
		o.Child, o.ChildStart = pid, procStart(pid)
		op.record(o)
	}
}

// end gives up the operation. The lock itself is released when the last
// process holding it (this one, or a real CLI child that inherited it) lets go.
func (op *sessionOp) end() {
	if unlock, err := op.c.lockMeta(); err == nil {
		var o opOwner
		if b, err := os.ReadFile(op.c.path("owner")); err == nil && json.Unmarshal(b, &o) == nil && o.PID == os.Getpid() {
			os.Remove(op.c.path("owner"))
		}
		unlock()
	}
	op.f.Close()
}

// signalOwner signals the process that runs the active operation (and, with
// child set, the real CLI it started), if that operation is a login or
// unlock. A running lock or logout is never cancelled: it does what the
// caller wants done. cancellable reports whether the holders of op.lock may
// be stopped: the operation is a login or unlock, or nobody who is alive
// owns it.
//
// With child set (the kill stage) every process that has op.lock open is
// killed as well. That is done here, under the metadata lock: op.lock is
// otherwise only opened under that lock (to take it or to probe it), so
// what has it open now is the operation itself or what it left behind,
// never a bystander that was just looking.
func (c *coord) signalOwner(sig syscall.Signal, child bool) (cancellable bool) {
	unlock, err := c.lockMeta()
	if err != nil {
		return false
	}
	defer unlock()
	if !c.opActiveLocked() {
		return false
	}
	var o opOwner
	b, err := os.ReadFile(c.path("owner"))
	recorded := err == nil && json.Unmarshal(b, &o) == nil
	ownerAlive := recorded && sameProcess(o.PID, o.Start) && syscall.Kill(o.PID, 0) == nil
	childAlive := recorded && sameProcess(o.Child, o.ChildStart) && syscall.Kill(o.Child, 0) == nil
	if recorded && !opLogin(o.Kind) && (ownerAlive || childAlive) {
		return false // a lock or logout at work
	}
	// Only the processes that were recorded, not whoever got their pid since.
	if child && childAlive {
		syscall.Kill(o.Child, sig)
	}
	if o.PID != os.Getpid() && ownerAlive {
		syscall.Kill(o.PID, sig)
	}
	if child {
		for _, pid := range lockHolders(c.path("op.lock")) {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	return true
}

// ---------- admission: commands that use an existing session ----------

type verdict int

const (
	admitAllowed verdict = iota
	admitDenied          // a lock or logout is pending or did not succeed
	admitUnknown         // the state could not be established: treated as denied
	admitExpired         // the session has been idle longer than the limit: lock it first
)

// admit is the one decision whether a command may use the root's existing
// session, from a daemon's memory or through the real CLI.
//
// An admitted command gets a lease: use.lock, shared. The lease is held
// until the process exits and is inherited by a real CLI it starts. A lock or
// logout revokes first and then waits for all leases (drainUse), so a command
// admitted before the revocation is waited for or stopped, and a command that
// comes later is refused here.
//
// tag names the session (sessionTag; "" if the command has none) and limit
// is the caller's auto-lock time (0: none). Idle time belongs to the root:
// the last admitted use of that session, whichever path answered it. The
// deadline is checked before the use is recorded, so a command that arrives
// after the deadline cannot revive the session, even if no timer has acted
// on it yet.
//
// Every failure to establish the state is admitUnknown, and the caller must
// treat it like admitDenied.
func (c *coord) admit(tag string, limit time.Duration) (lease *os.File, v verdict, why string) {
	unlock, err := c.lockMeta()
	if err != nil {
		return nil, admitUnknown, err.Error()
	}
	defer unlock()
	m, err := c.markLocked()
	if err != nil {
		return nil, admitUnknown, err.Error()
	}
	if c.blocked(m) {
		why := m.Reason
		if why == "" || m.revoking {
			why = "a lock or logout is in progress"
		}
		return nil, admitDenied, why
	}
	if tag != "" {
		last, known := c.activityLocked(tag)
		if known && limit > 0 && time.Since(last) > limit {
			return nil, admitExpired, ""
		}
		if err := c.touchLocked(tag); err != nil {
			return nil, admitUnknown, err.Error()
		}
	}
	// The lease is taken last, still under the metadata lock: only commands
	// that were admitted ever have use.lock open, so everything a lock or
	// logout finds holding it (drainUse) is a command to wait for, and a
	// revocation, which needs the metadata lock, cannot slip in between the
	// check and the lease.
	lease, err = c.enterUse()
	if err != nil {
		return nil, admitUnknown, err.Error()
	}
	return lease, admitAllowed, ""
}

// joinWait bounds how long a process without a session waits for a pending
// lock or logout before it gives up.
var joinWait = 2 * time.Minute

// join gives a lease to a real-CLI process that gets no session (help, a
// local command, a status that was not admitted). Such a process needs no
// open session state, but it is still a process on this vault root: it
// holds a lease like every other, so a lock or logout waits for it or stops
// it, and it does not start while a lock or logout is pending.
func (c *coord) join() (lease *os.File, err error) {
	for start := time.Now(); ; time.Sleep(opPoll) {
		unlock, err := c.lockMeta()
		if err != nil {
			return nil, err
		}
		if !c.heldLocked("revoke.lock") {
			lease, err = c.enterUse()
			unlock()
			return lease, err
		}
		unlock()
		if time.Since(start) > joinWait {
			return nil, errors.New("a lock or logout on this vault did not finish")
		}
	}
}

// admitted re-checks an admission later in the life of a command, right
// before it starts the real CLI.
func (c *coord) admitted() (v verdict, why string) {
	m, err := c.mark()
	if err != nil {
		return admitUnknown, err.Error()
	}
	if c.blocked(m) {
		if m.Reason == "" || m.revoking {
			return admitDenied, "a lock or logout is in progress"
		}
		return admitDenied, m.Reason
	}
	return admitAllowed, ""
}

// ---------- activity: the root's idle clock ----------

// Each session has its own record, activity/<tag>, so that a command with
// another session key (a stale BW_SESSION in some shell) can neither erase
// nor renew this session's clock.
func (c *coord) activityFile(tag string) string { return filepath.Join(c.dir, "activity", tag) }

// activityLocked returns when the session with the given tag was last used
// through the wrapper. known=false: there is no record of it.
func (c *coord) activityLocked(tag string) (last time.Time, known bool) {
	fi, err := os.Lstat(c.activityFile(tag))
	if err != nil || !fi.Mode().IsRegular() {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

// touchLocked records a use now: one system call when the record exists.
func (c *coord) touchLocked(tag string) error {
	now := time.Now()
	if err := os.Chtimes(c.activityFile(tag), now, now); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return writeAtomic(c.activityFile(tag), nil)
}

// activity is activityLocked for callers that do not hold the metadata lock.
func (c *coord) activity(tag string) (time.Time, bool) {
	unlock, err := c.lockMeta()
	if err != nil {
		return time.Time{}, false
	}
	defer unlock()
	return c.activityLocked(tag)
}

// renew records the end of a use. The deadline was checked when the command
// was admitted; a command that took long (a cold load) must not leave the
// session looking idle since its start. A record that is gone (the session
// was locked meanwhile) is not brought back.
func (c *coord) renew(tag string) {
	if unlock, err := c.lockMeta(); err == nil {
		if _, known := c.activityLocked(tag); known {
			c.touchLocked(tag)
		}
		unlock()
	}
}

// startActivity starts the idle clock of a session (a new unlock). Every
// other record is dropped: a new session on disk ends all earlier ones.
func (c *coord) startActivity(tag string) {
	if unlock, err := c.lockMeta(); err == nil {
		c.clearActivityLocked()
		c.touchLocked(tag)
		unlock()
	}
}

// forgetActivity drops the record of one session.
func (c *coord) forgetActivity(tag string) {
	if unlock, err := c.lockMeta(); err == nil {
		os.Remove(c.activityFile(tag))
		unlock()
	}
}

// clearActivity drops all records: no session is left on disk.
func (c *coord) clearActivity() {
	if unlock, err := c.lockMeta(); err == nil {
		c.clearActivityLocked()
		unlock()
	}
}

func (c *coord) clearActivityLocked() {
	entries, _ := os.ReadDir(filepath.Join(c.dir, "activity"))
	for _, e := range entries {
		os.Remove(filepath.Join(c.dir, "activity", e.Name()))
	}
}

// ---------- real-CLI runs and the CLI's data file ----------

// lockData orders real-CLI runs that the wrapper starts with the root's
// login. A run that snapshots the data file to restore it later (hold mode)
// takes the lock exclusively, from its snapshot to its restore decision, so
// that no other run can change the file in between and be overwritten. Other
// runs share it. giveUp (optional) is asked while waiting, and the wait is
// bounded by dataLockWait: a run that never ends (a `bw serve` started
// through the wrapper) must not stall everything else for good.
func (c *coord) lockData(exclusive bool, giveUp func() bool) (f *os.File, err error) {
	start := time.Now()
	f, err = os.OpenFile(c.path("data.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	for {
		if err = syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err == nil {
			return f, nil
		}
		if err != syscall.EWOULDBLOCK {
			break
		}
		if (giveUp != nil && giveUp()) || time.Since(start) > dataLockWait {
			err = errors.New("another Bitwarden CLI run on this vault did not finish; gave up waiting for it")
			break
		}
		time.Sleep(opPoll)
	}
	f.Close()
	return nil, err
}

// dataLockWait bounds the wait for data.lock.
var dataLockWait = 5 * time.Minute

// sessionDataWait is how long a lock or logout waits for data.lock.
var sessionDataWait = 10 * time.Second

// ---------- leases ----------

// enterUse shares use.lock: the lease of a command admitted to use an
// existing session (see admit).
func (c *coord) enterUse() (*os.File, error) {
	f, err := os.OpenFile(c.path("use.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// ---------- who holds a lease ----------
//
// A lock is released by the kernel when its holders are gone, but the kernel
// does not say who they are (only Linux lets one look, through /proc). So
// every process that holds a lease is also on record: the wrapper client
// itself, the real CLI it starts, and the real CLIs a daemon starts. A lock
// or logout that has waited long enough stops the processes on record.
// Records are removed when the process ends normally; one left behind by a
// killed process is dropped when it is next looked at, and never leads to a
// signal: the process must still be the one that registered (leaseHeldBy).

func (c *coord) leaseFile(pid int) string {
	return filepath.Join(c.dir, "leases", strconv.Itoa(pid))
}

// registerLease records pid as a holder of a lease.
func (c *coord) registerLease(pid int) {
	writeAtomic(c.leaseFile(pid), []byte(leaseIdentity(pid)))
}

func (c *coord) unregisterLease(pid int) { os.Remove(c.leaseFile(pid)) }

// leaseHolders returns the processes on record that still exist. Linux adds
// what /proc shows (a process that died before it could register its child
// leaves a holder that is on no record).
func (c *coord) leaseHolders() []int {
	seen := map[int]bool{os.Getpid(): true}
	var pids []int
	add := func(pid int) {
		if !seen[pid] {
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(c.dir, "leases"))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		identity, _ := os.ReadFile(c.leaseFile(pid))
		if leaseHeldBy(pid, string(identity), fi.ModTime()) {
			add(pid)
		} else {
			os.Remove(c.leaseFile(pid))
		}
	}
	for _, pid := range lockHolders(c.path("use.lock")) {
		add(pid)
	}
	return pids
}

// useDrainWait is how long a lock or logout waits for commands that were
// admitted before it (a real CLI still running, a client still writing a
// cached answer into a slow pipe). After that they are stopped.
var useDrainWait = 10 * time.Second

// drainUse returns once no command admitted before the revocation is left.
// Those that do not end within wait are terminated, then killed. It runs
// while the revocation is pending, so nobody new is admitted meanwhile:
// whoever is found holding a lease (leaseHolders) got it before the
// revocation.
// false: some are still there and could not be stopped.
func (c *coord) drainUse(wait time.Duration) bool {
	f, err := os.OpenFile(c.path("use.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	start := time.Now()
	termed, killed := false, false
	for {
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			return true
		}
		waited := time.Since(start)
		switch {
		case waited > wait+4*time.Second:
			return false
		case waited > wait+2*time.Second && !killed:
			for _, pid := range c.leaseHolders() {
				syscall.Kill(pid, syscall.SIGKILL)
			}
			killed = true
		case waited > wait && !termed:
			for _, pid := range c.leaseHolders() {
				syscall.Kill(pid, syscall.SIGTERM)
			}
			termed = true
		}
		time.Sleep(opPoll)
	}
}

// ---------- the lock sequence ----------

// lockPlan describes a lock or logout for finishLock.
type lockPlan struct {
	kind string
	// run executes the real session command and returns its exit code. The
	// files (operation lock, revocation) are for the real CLI to inherit, so
	// that both last as long as it does.
	run func(inherit []*os.File) int
	// stillOurs is asked before a retry (auto-lock only): if the session on
	// disk is no longer the one this lock was meant for, there is nothing
	// left to lock and nothing may be locked.
	stillOurs func() bool
	retries   int
	// except is the caller's own daemon socket, which is not asked to stop.
	except string
	// log receives progress and failures.
	log func(format string, a ...any)
}

// retryPause separates attempts of a failing real lock command.
var retryPause = time.Second

// finishLock is the part of a lock or logout that manual and automatic
// locking share. On entry the caller holds the operation lock and has
// revoked (coord.revoke) at the given epoch. It
//
//  1. wipes the root's caches and stops their real-CLI children,
//  2. waits until real-CLI runs that got the session before the revocation
//     are gone (drainUse),
//  3. runs the real session command (retrying if the plan allows it),
//  4. records the outcome: open again if no usable session is left on disk,
//     blocked otherwise.
//
// The caller ends the revocation (rev.done) after this returns.
// ok=false means the real command did not end the session; access stays
// blocked for this root until a later lock succeeds or a new unlock is made.
// drained=false means a real-CLI run that started before the lock is still
// running and could not be stopped: it may still print what it has read.
func (c *coord) finishLock(rev *revocation, op *sessionOp, p lockPlan) (code int, ok, drained bool) {
	epoch := rev.epoch
	if p.log == nil {
		p.log = func(string, ...any) {}
	}
	if _, failed := stopDaemons(c, p.except); len(failed) > 0 {
		p.log("%s: %d daemon(s) did not confirm their wipe; their vaults are void by generation", p.kind, len(failed))
	}
	drained = c.drainUse(useDrainWait)
	// The real command rewrites the data file: it holds data.lock like every
	// other run. After the drain nobody the wrapper started should hold it;
	// a lock or logout does not wait long for it and is never given up.
	inherit := []*os.File{op.f, rev.f}
	patience := time.Now().Add(sessionDataWait)
	if data, err := c.lockData(true, func() bool { return time.Now().After(patience) }); err == nil {
		defer data.Close()
		inherit = append(inherit, data)
	} else {
		p.log("%s: proceeding without the data file lock: %v", p.kind, err)
	}
	for attempt := 0; ; attempt++ {
		code = p.run(inherit)
		// Judged by what the data file shows, never by the exit code: with
		// --cleanexit or BW_CLEANEXIT the CLI exits 0 after a failure, and
		// `bw logout` on a root that is already logged out fails although
		// nothing is left to protect.
		ok = !sessionUsable(c.root)
		if ok || attempt >= p.retries {
			break
		}
		if p.stillOurs != nil && !p.stillOurs() {
			// Somebody unlocked anew with the real CLI directly: the session
			// we set out to end is gone, and the new one is not ours to lock.
			p.log("%s: the session on disk is no longer ours, not retrying", p.kind)
			ok = true
			break
		}
		p.log("%s: the real command failed (exit %d), retrying", p.kind, code)
		time.Sleep(retryPause)
	}
	// Daemons that came up while the command ran hold nothing valid either.
	stopDaemons(c, p.except)
	reason := ""
	if !ok {
		reason = fmt.Sprintf("%s did not complete (the Bitwarden CLI exited with %d)", p.kind, code)
		p.log("%s FAILED; access through the wrapper stays blocked for %s", p.kind, c.root)
	}
	if err := c.settle(epoch, ok, reason); err != nil {
		p.log("%s: cannot record the outcome: %v", p.kind, err)
	}
	if ok {
		c.clearActivity() // no session left: no idle clocks left
	}
	if !drained {
		p.log("%s: a command that was admitted earlier is still running and could not be stopped", p.kind)
	}
	return code, ok, drained
}

// ---------- daemon registry ----------

func sessionTag(session string) string { return hashHex(16, "bww-sock", session) }

func (c *coord) entry(tag string) string { return filepath.Join(c.dir, "daemons", tag) }

// lookup returns the socket of the daemon serving a session tag ("" if none).
func (c *coord) lookup(tag string) string {
	b, err := os.ReadFile(c.entry(tag))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// daemons lists the sockets of all registered daemons of this root.
func (c *coord) daemons() map[string]string {
	out := map[string]string{}
	entries, _ := os.ReadDir(filepath.Join(c.dir, "daemons"))
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			if sock := c.lookup(e.Name()); sock != "" {
				out[e.Name()] = sock
			}
		}
	}
	return out
}

// unregister removes a registry entry if it still points at sock.
func (c *coord) unregister(tag, sock string) {
	unlock, err := c.lockMeta()
	if err != nil {
		return
	}
	defer unlock()
	if c.lookup(tag) == sock {
		os.Remove(c.entry(tag))
	}
}
