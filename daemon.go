package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// daemonInit is handed to a new daemon on stdin, so the session token never
// appears in argv or in the daemon's environment.
type daemonInit struct {
	// Everything that depends on the caller's environment is resolved by the
	// client before the daemon detaches: the vault root, the absolute path
	// of the real CLI, and the runtime directory for the socket.
	Root           string `json:"root"`
	Session        string `json:"session"`
	RealBW         string `json:"realBW"`
	RuntimeDir     string `json:"runtimeDir"`
	AutoLock       int64  `json:"autoLock"` // seconds
	AutoLockAction string `json:"autoLockAction"`
	UseServe       bool   `json:"useServe"` // load through `bw serve` (faster cold start)
	Hold           bool   `json:"hold"`
	HoldMax        int64  `json:"holdMax"` // seconds, 0 = no limit
}

const realTimeout = 3 * time.Minute

// tick is how often an idle daemon looks after itself.
var tick = 15 * time.Second

type daemon struct {
	root     string
	realBW   string
	useServe bool
	auth     [32]byte
	co       *coord // coordination state of the root (coord.go)
	tag      string // registry name: the session tag
	dir      string // runtime directory holding our socket
	sock     string
	ln       net.Listener
	started  time.Time

	// The snapshot requests are answered from: the vault and where it came
	// from. v and src are replaced together, in publish and nowhere else, so
	// "what is in memory" and "what it was loaded from" cannot drift apart:
	// a load that fails leaves both as they were.
	mu      sync.RWMutex // guards v, and the pairing of v with src
	v       *vault
	src     atomic.Pointer[source]
	ready   chan struct{} // closed once the first load has finished
	loadErr error

	reloadMu sync.Mutex
	invalid  atomic.Int64 // notices that the vault changed (a sync through the wrapper)
	retryAt  atomic.Int64 // unix nanoseconds: no reload attempt before this (after a failed one)
	seen     atomic.Value // observed: the last look at the data file
	noSeal   atomic.Bool  // the seal check does not work with this CLI version

	macKey  []byte      // MAC half of the session key: verifies the CLI's sealed user key
	sockIno uint64      // inode of the socket we bound
	closing atomic.Bool // shutdown has begun
	kids    launches    // every real-CLI process this daemon starts
	endMu   sync.Mutex  // guards ended and linger
	ended   bool        // shutdown is complete: children gone, memory wiped, unregistered
	linger  bool        // somebody was told "not stopped yet": exit when ended

	hold    atomic.Bool  // hold mode enabled (see hold.go)
	holdMax atomic.Int64 // nanoseconds, 0 = no limit
	// heldSince: since when the snapshot is one that cannot be refreshed
	// (the CLI is logged out on disk, or reloading fails). Unix nanoseconds;
	// 0 = the snapshot is current. hold_max counts from here.
	heldSince atomic.Int64

	autoLock   atomic.Int64 // nanoseconds, 0 = never
	lockAction atomic.Value // string
	down       sync.Once
	wake       chan struct{} // settings or state changed: re-evaluate timers
}

// source is where the vault in memory came from. Immutable.
type source struct {
	fp  dataFP // the CLI's data file as it was when the load began
	gen mark   // the coordination state the load ran under
	seq int64  // d.invalid when the load began
}

// observed is one look at the CLI's data file, judged against a source.
type observed struct {
	fp      dataFP
	verdict int
	of      *source
}

// childStopWait is how long a shutdown request waits for the daemon's
// real-CLI launches to be over before it answers "not stopped yet".
var childStopWait = 5 * time.Second

// reloadRetry is how long a failed reload is not repeated.
var reloadRetry = 30 * time.Second

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s [%d] %s\n", time.Now().Format("2006-01-02 15:04:05"), os.Getpid(), fmt.Sprintf(format, a...))
}

var (
	errOpActive   = errors.New("a lock, logout, login or unlock is running for this vault")
	errSuperseded = errors.New("a lock, logout, login or unlock replaced the session state during the load")
	errBlocked    = errors.New("a lock or logout for this vault did not complete: access is blocked")
)

func runDaemon() int {
	var init daemonInit
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&init); err != nil {
		logf("bad init message: %v", err)
		return 2
	}
	os.Stdin.Close()
	hardenProcess()
	syscall.Umask(0o077)

	dir, err := privateDir(init.RuntimeDir)
	if err != nil {
		logf("%v", err)
		return 2
	}
	// Without the root's coordination state nothing may be cached.
	co, err := openCoord(init.Root)
	if err != nil {
		logf("no coordination directory, not caching: %v", err)
		return 2
	}
	d := &daemon{
		root:     init.Root,
		realBW:   init.RealBW,
		useServe: init.UseServe,
		auth:     authHash(init.Session),
		co:       co,
		tag:      sessionTag(init.Session),
		dir:      dir,
		sock:     socketPath(dir, init.Root, init.Session),
		started:  time.Now(),
		ready:    make(chan struct{}),
		wake:     make(chan struct{}, 1),
	}
	d.autoLock.Store(init.AutoLock * int64(time.Second))
	d.lockAction.Store(init.AutoLockAction)
	d.hold.Store(init.Hold)
	d.holdMax.Store(init.HoldMax * int64(time.Second))
	if key, err := base64.StdEncoding.DecodeString(init.Session); err == nil && len(key) == 64 {
		d.macKey = append([]byte(nil), key[32:]...)
		wipe(key)
	}

	// One daemon per (root, session), whatever runtime directory it was
	// started from: the root's registry says who serves the session.
	// Registration is serialized by the metadata lock.
	unlock, err := co.lockMeta()
	if err != nil {
		logf("%v", err)
		return 2
	}
	if other := co.lookup(d.tag); other != "" {
		if c, err := net.DialTimeout("unix", other, time.Second); err == nil {
			c.Close()
			unlock()
			return 0 // another daemon already serves this session
		}
	}
	os.Remove(d.sock)
	if d.ln, err = net.Listen("unix", d.sock); err == nil {
		err = writeAtomic(co.entry(d.tag), []byte(d.sock))
	}
	if err != nil {
		unlock()
		logf("cannot listen and register: %v", err)
		return 2
	}
	d.sockIno = inode(d.sock)
	unlock()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		s := <-sig
		d.quit("signal "+s.String(), 0)
	}()

	go d.firstLoad(init.Session)
	init.Session = ""
	go d.timerLoop()

	for {
		conn, err := d.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				select {} // shutting down; the goroutine that closed us exits the process
			}
			continue
		}
		go d.handle(conn.(*net.UnixConn))
	}
}

func inode(path string) uint64 {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 1
}

// ---------- loading ----------

// loadCurrent loads a vault and returns it with the coordination mark it is
// valid for. Nothing is loaded while a session operation runs.
func (d *daemon) loadCurrent(session string) (*vault, *source, error) {
	mark, err := d.co.mark()
	if err != nil {
		return nil, nil, err
	}
	if mark.active {
		return nil, nil, errOpActive
	}
	if d.co.blocked(mark) {
		return nil, nil, errBlocked
	}
	// Taken before loading: a change during the load is caught next time.
	src := &source{gen: mark, seq: d.invalid.Load(), fp: d.loadFP()}
	v, err := d.load(session)
	if err != nil {
		return nil, nil, err
	}
	d.adoptFP(&src.fp)
	return v, src, nil
}

// publish makes v the vault requests are answered from, if it is still
// valid: the generation did not move during the load and no session
// operation is running. Otherwise v is wiped. This is the only place where
// the snapshot (v and its source) changes.
func (d *daemon) publish(v *vault, src *source) error {
	loaded := src.gen
	d.mu.Lock()
	if d.closing.Load() {
		d.mu.Unlock()
		v.wipe()
		return errors.New("shutting down")
	}
	now, err := d.co.mark()
	if err == nil && (now.active || now.Gen != loaded.Gen || d.co.blocked(now)) {
		err = errSuperseded
	}
	if err != nil {
		d.mu.Unlock()
		v.wipe()
		return err
	}
	old := d.v
	d.v = v
	d.src.Store(&source{fp: src.fp, gen: now, seq: src.seq})
	d.mu.Unlock()
	old.wipe()
	return nil
}

func (d *daemon) firstLoad(session string) {
	t0 := time.Now()
	v, src, err := d.loadCurrent(session)
	if err == nil {
		err = d.publish(v, src)
	}
	if d.closing.Load() {
		return // locked while loading; the locking goroutine exits the process
	}
	if err != nil {
		d.loadErr = err
		close(d.ready)
		logf("load failed: %v", err)
		// Give clients that are already waiting their fallback answer.
		time.Sleep(500 * time.Millisecond)
		d.quit("load failed", 1)
	}
	close(d.ready)
	logf("loaded %d items from %s in %s", v.count(), d.root, time.Since(t0).Round(time.Millisecond))
}

// reload replaces the snapshot with a fresh one from the real CLI. have is
// the source the caller found wanting. If the load fails, nothing changes:
// the snapshot in memory keeps its old source and stays "not current".
func (d *daemon) reload(session string, have *source) error {
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	if d.src.Load() != have {
		return nil // another request already did it
	}
	t0 := time.Now()
	v, src, err := d.loadCurrent(session)
	if err == nil {
		err = d.publish(v, src)
	}
	if err != nil {
		return err
	}
	logf("reloaded %d items in %s", v.count(), time.Since(t0).Round(time.Millisecond))
	return nil
}

// launches is the one record of the real-CLI processes a daemon starts,
// shared by every launcher (realWith, startServe). Its protocol is what
// makes "stopped" true when a daemon says it:
//
//	reserve   before Start. Refused once shutdown has begun, so no process
//	          can come into being after the daemon looked.
//	started   the process exists. If shutdown began meanwhile, it is killed.
//	done      the process has been waited for (or never started): only now
//	          does the launch stop counting.
//
// Shutdown closes the record (no further launches, kill what runs) and is
// complete when no launch is left: not when the processes were signalled,
// and not while one sits between Start and registration.
type launches struct {
	mu      sync.Mutex
	closed  bool
	pending int // reserved and not yet done
	procs   map[*os.Process]struct{}
}

var errStopping = errors.New("the daemon is shutting down")

func (l *launches) reserve() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.pending++
	return true
}

func (l *launches) started(p *os.Process) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.procs == nil {
		l.procs = map[*os.Process]struct{}{}
	}
	l.procs[p] = struct{}{}
	if l.closed {
		p.Kill()
	}
}

// done ends a launch; p is nil if the process never started.
func (l *launches) done(p *os.Process) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.procs, p)
	l.pending--
}

// close refuses further launches and kills the running processes.
func (l *launches) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	for p := range l.procs {
		p.Kill()
	}
}

func (l *launches) left() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pending
}

// dataRun is the daemon's rule for starting the real CLI, the counterpart
// of client.realRun. The run is admitted (coord.admit) and gets a lease; it
// is ordered by the root's data.lock; and in hold mode the data file is
// snapshotted and put back if the CLI logged itself out. run receives the
// lease and the lock and must let every process it starts inherit both.
// They then last as long as the last of those processes, not just as long
// as this daemon: if the daemon is killed while a child still runs, a lock
// or logout still finds that child and waits for it or stops it, and no
// other run overlaps it.
func (d *daemon) dataRun(run func(inherit []*os.File) error) error {
	lease, v, why := d.co.admit("", 0)
	if v != admitAllowed {
		return fmt.Errorf("%w (%s)", errBlocked, why)
	}
	defer lease.Close()
	hold := d.hold.Load()
	lock, err := d.co.lockData(hold, d.closing.Load)
	if err != nil {
		return err
	}
	defer lock.Close()
	if hold {
		after := guardData(d.co)
		defer func() {
			if after() {
				logf("hold: restored the data file after the CLI logged itself out")
			}
		}()
	}
	return run([]*os.File{lease, lock})
}

// guarded returns the function requests use to run the real CLI.
func (d *daemon) guarded(session string) realFunc {
	return func(args ...string) (out []byte, err error) {
		err = d.dataRun(func(inherit []*os.File) error {
			out, err = d.realWith(session, inherit)(args...)
			return err
		})
		return out, err
	}
}

// realWith returns a function running the real CLI with the given session,
// inside a dataRun whose lease and lock the child inherits.
func (d *daemon) realWith(session string, inherit []*os.File) realFunc {
	return func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), realTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, d.realBW, append(args, "--response", "--nointeraction")...)
		cmd.Env = d.childEnv(session)
		cmd.SysProcAttr = childAttr()
		cmd.ExtraFiles = inherit
		out, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		// The child dies with the thread that started it (see childAttr),
		// so that thread must stay ours until the child is done.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if !d.kids.reserve() {
			return nil, errStopping
		}
		if err := cmd.Start(); err != nil {
			d.kids.done(nil)
			return nil, err
		}
		testHook("child-started")
		d.kids.started(cmd.Process)
		d.co.registerLease(cmd.Process.Pid) // it holds our lease: on record, so a lock finds it without us
		buf := readAllWiping(out)
		err = cmd.Wait()
		d.co.unregisterLease(cmd.Process.Pid)
		testHook("child-reaped")
		d.kids.done(cmd.Process)
		return buf, err
	}
}

// childEnv is the environment of a real-CLI child: the daemon's own
// (already reduced to supported variables by the client, see daemonEnv),
// the root, and the session key only where a child needs it.
func (d *daemon) childEnv(session string) []string {
	drop := map[string]bool{
		"BW_SESSION": true, "BW_PRETTY": true, "BW_RAW": true, "BW_RESPONSE": true,
		"BW_QUIET": true, "BW_CLEANEXIT": true, "BW_NOINTERACTION": true,
		"BWW_DAEMON": true, "BITWARDENCLI_APPDATA_DIR": true,
	}
	var env []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !drop[k] {
			env = append(env, kv)
		}
	}
	// The root was resolved once, by the client; every child is told it.
	env = append(env, "BITWARDENCLI_APPDATA_DIR="+d.root)
	if session != "" {
		env = append(env, "BW_SESSION="+session)
	}
	return env
}

// readAllWiping is io.ReadAll that zeroes the buffers it outgrows.
func readAllWiping(r io.Reader) []byte {
	buf := make([]byte, 0, 64<<10)
	for {
		if len(buf) == cap(buf) {
			bigger := make([]byte, len(buf), 2*cap(buf))
			copy(bigger, buf)
			wipe(buf)
			buf = bigger
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err != nil {
			return buf
		}
	}
}

// ---------- watching the CLI's data file ----------

func (d *daemon) loadFP() dataFP {
	return readFP(d.root, d.macKey, !d.noSeal.Load())
}

// adoptFP is called after a successful load. If the seal check claimed the
// session was foreign although the real CLI just accepted it, the check does
// not understand this CLI version: stop trusting it.
func (d *daemon) adoptFP(fp *dataFP) {
	if fp.sealed == sealForeign && !d.noSeal.Swap(true) {
		logf("session seal check disabled: it disagrees with the real CLI")
		*fp = readFP(d.root, d.macKey, false)
	}
}

// What a look at the CLI's data file found.
const (
	dataSame      = iota // nothing relevant changed
	dataChanged          // vault content differs from what was loaded
	dataLocked           // still logged in, but our session key no longer unlocks it
	dataLoggedOut        // the CLI is logged out
)

// checkData judges the CLI's data file against the source of the snapshot
// in memory. looked is false when the file is untouched since the last look
// (one stat), in which case the last verdict still stands. The verdict is
// always about the snapshot's own source: a snapshot that could not be
// refreshed keeps being reported as dataChanged. This is about changes made
// with the real CLI directly; session commands that go through the wrapper
// are caught earlier, by the generation.
func (d *daemon) checkData(src *source) (verdict int, now dataFP, looked bool) {
	if last, ok := d.seen.Load().(observed); ok && last.of == src && statFP(d.root).sameStat(last.fp) {
		return last.verdict, last.fp, false
	}
	now = d.loadFP()
	switch {
	case now.sealed == sealForeign && !now.authed:
		verdict = dataLoggedOut
	case now.sealed == sealForeign:
		verdict = dataLocked
	case now.digest != src.fp.digest:
		verdict = dataChanged
	}
	d.seen.Store(observed{fp: now, verdict: verdict, of: src})
	return verdict, now, true
}

// current reports whether the vault in memory still belongs to the current
// generation: no lock, logout, login or unlock has begun since it was loaded.
func (d *daemon) current() bool {
	src := d.src.Load()
	return src != nil && d.co.current(src.gen)
}

// mayHold: holding is only for a logout nobody asked for. Generation and
// revocation epoch are the ones the vault was loaded under, access is open,
// and no session operation is running or pending.
func (d *daemon) mayHold() bool {
	src := d.src.Load()
	now, err := d.co.mark()
	return src != nil && err == nil && !now.active && !now.revoking && now.Access == accessOpen &&
		now.Gen == src.gen.Gen && now.Epoch == src.gen.Epoch
}

// lastUse is when this daemon's session was last used: the root's activity
// record (every admitted command, whichever way it was answered), or the
// daemon's start if there is none.
func (d *daemon) lastUse() time.Time {
	if t, ok := d.co.activity(d.tag); ok && t.After(d.started) {
		return t
	}
	return d.started
}

// enterHold: the snapshot cannot be refreshed (the server ended the session
// and the CLI erased its data, or reloading fails) and hold mode says to
// keep what is in memory. The hold_max clock starts with the first call.
func (d *daemon) enterHold(why string) {
	if d.heldSince.CompareAndSwap(0, time.Now().UnixNano()) {
		logf("hold: %s; keeping the vault in memory", why)
		d.poke()
	}
}

// holdExpired reports whether the vault has been held longer than hold_max.
func (d *daemon) holdExpired() (left time.Duration, expired bool) {
	since, limit := d.heldSince.Load(), time.Duration(d.holdMax.Load())
	if since == 0 || limit <= 0 {
		return 0, false
	}
	left = limit - time.Since(time.Unix(0, since))
	return left, left <= 0
}

// sessionLive reports whether our session key is (as far as we can tell)
// still the one that unlocks the vault on disk.
func (d *daemon) sessionLive() bool {
	return d.loadFP().sealed != sealForeign
}

// ---------- lifetime ----------

// shutdown ends the daemon's service: no further real-CLI launches, running
// ones killed, and, once every launch is over, memory wiped and the daemon
// taken off the registry. It reports whether that is complete.
//
// complete=false means the deadline (childStopWait) passed while a launch
// was still open: a process was started and is not yet on record, or was
// killed and has not been reaped. The daemon then says so to whoever asked,
// stays registered and reachable so that the unfinished shutdown can be
// found and asked again, finishes in the background, and exits on its own
// when it is done. It never claims "stopped" before that.
func (d *daemon) shutdown(reason string) (complete bool) {
	d.down.Do(func() {
		d.closing.Store(true)
		d.kids.close()
		logf("shutting down: %s", reason)
		go func() {
			for d.kids.left() > 0 { // however long it takes
				time.Sleep(2 * time.Millisecond)
			}
			// Requests that were waiting on those processes have let go of
			// the vault lock by now.
			d.mu.Lock()
			d.v.wipe()
			d.v = nil
			d.mu.Unlock()
			wipe(d.macKey)
			if d.ln != nil {
				d.ln.Close()
			}
			if d.sock != "" && inode(d.sock) == d.sockIno {
				os.Remove(d.sock)
			}
			if d.tag != "" {
				d.co.unregister(d.tag, d.sock)
			}
			logf("memory wiped, real-CLI processes gone: shutdown complete")
			d.endMu.Lock()
			d.ended = true
			exit := d.linger
			d.endMu.Unlock()
			if exit {
				os.Exit(0)
			}
		}()
	})
	for deadline := time.Now().Add(childStopWait); ; time.Sleep(2 * time.Millisecond) {
		d.endMu.Lock()
		if d.ended {
			d.endMu.Unlock()
			return true
		}
		if time.Now().After(deadline) {
			d.linger = true // the background part exits the process when it is done
			d.endMu.Unlock()
			logf("shutdown not complete: %d real-CLI launch(es) still open", d.kids.left())
			return false
		}
		d.endMu.Unlock()
	}
}

// quit shuts down and exits. If the shutdown cannot be completed in time,
// the process stays (see shutdown) and this call does not return.
func (d *daemon) quit(reason string, code int) {
	if d.shutdown(reason) {
		os.Exit(code)
	}
	select {}
}

// poke wakes the timer loop after a setting or state change.
func (d *daemon) poke() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// nap sleeps, but wakes early when poked.
func (d *daemon) nap(dur time.Duration) {
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-t.C:
	case <-d.wake:
	}
}

func (d *daemon) timerLoop() {
	for {
		testHook("timer")
		// Unreachable (socket or registration gone): do not keep a vault in
		// memory that nobody can use or lock.
		if inode(d.sock) != d.sockIno || d.co.lookup(d.tag) != d.sock {
			d.quit("socket or registration is gone", 0)
		}
		// A lock, logout, login or unlock began: the vault is void. Requests
		// check this themselves; this is for a daemon nobody is asking.
		if d.src.Load() != nil && !d.current() {
			d.quit("session state replaced by a lock, logout, login or unlock", 0)
		}
		wait := tick
		if left, expired := d.holdExpired(); expired {
			d.quit("hold limit reached", 0)
		} else if left > 0 {
			wait = min(wait, left)
		}
		limit := time.Duration(d.autoLock.Load())
		if limit <= 0 {
			d.nap(wait)
			continue
		}
		idle := time.Since(d.lastUse())
		if idle < limit {
			d.nap(min(limit-idle, wait))
			continue
		}
		action, _ := d.lockAction.Load().(string)
		if d.autoLockNow(limit, action) {
			d.quit("auto-lock", 0)
		}
		d.nap(min(time.Second, wait)) // the root is busy or was just used: look again shortly
	}
}

// autoLockNow is called when the idle limit is reached. It reports whether
// the daemon is done (memory wiped); false means "not now": another session
// operation is running for the root, or the daemon was used in the meantime.
//
// Locking is the same sequence as a manual `bw lock` (coord.finishLock). What
// auto-lock adds comes before it commits: holding the exclusive operation
// lock, it checks that the session on disk is still this daemon's and that
// the daemon is still idle. An unlock in another shell therefore either
// finishes before we look (and we see its session, not ours) or starts after
// we are done. If the real lock fails, access stays blocked: the idle limit
// never silently turns into "cache evicted".
func (d *daemon) autoLockNow(limit time.Duration, action string) (done bool) {
	if action == "evict" {
		// Deliberately not a revocation: memory is freed, the session stays.
		d.shutdown("auto-lock after " + limit.String() + " idle (evict)")
		return true
	}
	op, err := d.co.tryBeginOp("auto-lock")
	if err != nil {
		// Cannot coordinate: free the memory, leave the session alone.
		d.shutdown("auto-lock after " + limit.String() + " idle (memory only: " + err.Error() + ")")
		return true
	}
	if op == nil {
		return false // busy: look again later
	}
	defer op.end()
	// The root's clock, read while no other session command can run: a
	// command admitted in the meantime has renewed it.
	if time.Since(d.lastUse()) < limit {
		return false
	}
	macKey := append([]byte(nil), d.macKey...)
	defer wipe(macKey)
	ours := func() bool { return readFP(d.root, macKey, !d.noSeal.Load()).sealed != sealForeign }
	if !d.current() || !ours() {
		d.shutdown("idle, and the session on disk is someone else's by now")
		return true
	}
	// Commit: revoke first, then wipe.
	rev, rerr := d.co.revoke("auto-lock")
	d.shutdown("auto-lock after " + limit.String() + " idle (" + action + ")")
	if rerr != nil {
		logf("auto-lock: cannot record the revocation, memory wiped only: %v", rerr)
		return true
	}
	d.co.finishLock(rev, op, lockPlan{
		kind:      "auto-lock",
		run:       func(inherit []*os.File) int { return realLock(d.realBW, d.childEnv(""), inherit) },
		stillOurs: ours,
		retries:   2,
		except:    d.sock,
		log:       logf,
	})
	rev.done()
	d.co.forgetActivity(d.tag)
	return true
}

// ---------- requests ----------

func (d *daemon) info() *daemonInfo {
	in := &daemonInfo{
		PID: os.Getpid(), Root: d.root, Started: d.started.Unix(),
		LastUsed: d.lastUse().Unix(),
		AutoLock: d.autoLock.Load() / int64(time.Second),
	}
	in.LockAction, _ = d.lockAction.Load().(string)
	in.Stopping = d.closing.Load()
	in.Held = d.heldSince.Load() / int64(time.Second)
	in.HoldMax = d.holdMax.Load() / int64(time.Second)
	d.mu.RLock()
	if d.v != nil {
		in.Loaded = true
		in.Items = d.v.count()
		var st struct {
			UserEmail string `json:"userEmail"`
		}
		json.Unmarshal(d.v.status, &st)
		in.Email = st.UserEmail
	}
	d.mu.RUnlock()
	return in
}

func send(conn net.Conn, rep *reply, out, errOut []byte) {
	rep.Out, rep.Err = -1, -1
	if out != nil {
		rep.Out = len(out)
	}
	if errOut != nil {
		rep.Err = len(errOut)
	}
	head, _ := json.Marshal(rep)
	bufs := net.Buffers{append(head, '\n'), out, errOut}
	bufs.WriteTo(conn)
}

func (d *daemon) handle(conn *net.UnixConn) {
	defer conn.Close()
	if uid, ok := peerUID(conn); !ok || uid != os.Getuid() {
		return
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReaderSize(io.LimitReader(conn, 1<<20), 16<<10).ReadBytes('\n')
	if err != nil {
		return
	}
	var req request
	if json.Unmarshal(line, &req) != nil {
		return
	}
	wipe(line)

	switch req.Op {
	case opInfo:
		send(conn, &reply{Status: stOK, Info: d.info()}, nil, nil)
		return
	case opLock:
		// Like `bw lock`, this needs no session: it only destroys.
		// "ok" is said only when it is true: every real-CLI process of this
		// daemon is gone and its memory is wiped. Otherwise the caller hears
		// that the daemon is still stopping, and can ask again.
		if !d.shutdown("lock requested") {
			send(conn, &reply{Status: stStopping}, nil, nil)
			return
		}
		send(conn, &reply{Status: stOK}, nil, nil)
		conn.Close()
		os.Exit(0)
	case opInvalidate:
		d.invalid.Add(1)
		send(conn, &reply{Status: stOK}, nil, nil)
		return
	case opRun, opReload:
	default:
		return
	}

	got := authHash(req.Session)
	if subtle.ConstantTimeCompare(got[:], d.auth[:]) != 1 {
		send(conn, &reply{Status: stDenied}, nil, nil)
		return
	}
	if req.AutoLock >= 0 { // the caller sent its settings: adopt them
		if d.autoLock.Swap(req.AutoLock*int64(time.Second)) != req.AutoLock*int64(time.Second) {
			d.poke()
		}
		if req.AutoLockAction != "" {
			d.lockAction.Store(req.AutoLockAction)
		}
		d.hold.Store(req.Hold)
		if d.holdMax.Swap(req.HoldMax*int64(time.Second)) != req.HoldMax*int64(time.Second) {
			d.poke()
		}
	}

	for waiting := true; waiting; { // for the first load, unless a shutdown comes first
		select {
		case <-d.ready:
			waiting = false
		case <-time.After(20 * time.Millisecond):
			waiting = !d.closing.Load()
		}
	}
	if d.closing.Load() || d.loadErr != nil {
		send(conn, &reply{Status: stFallback}, nil, nil)
		return
	}
	die := func(reason string) {
		complete := d.shutdown(reason)
		send(conn, &reply{Status: stFallback}, nil, nil)
		conn.Close()
		if complete {
			os.Exit(0)
		}
		runtime.Goexit() // the shutdown finishes in the background and exits then
	}
	// Rule one: answer from memory only while the vault's generation is the
	// current one. A lock, logout, login or unlock that went through the
	// wrapper anywhere (or coordination we can no longer read) ends it here,
	// whatever hold mode says.
	if !d.current() {
		die("session state replaced by a lock, logout, login or unlock")
	}
	// Then the data file: it may have changed behind our back (a sync, lock,
	// logout or new unlock done with the real CLI directly).
	src := d.src.Load()
	verdict, _, looked := d.checkData(src)
	switch {
	case verdict == dataLoggedOut && d.hold.Load():
		if looked && !d.mayHold() {
			die("logged out by an explicit session command")
		}
		d.enterHold("the CLI is logged out on disk")
	case verdict == dataLocked || verdict == dataLoggedOut:
		logf("session key no longer unlocks %s", d.root)
		die("session ended outside the wrapper")
	}
	if !d.hold.Load() && d.heldSince.Load() != 0 {
		die("hold mode was switched off")
	}
	if _, expired := d.holdExpired(); expired {
		die("hold limit reached")
	}
	// The snapshot is current if the data file still is what it was loaded
	// from and nobody announced a change. If not, it has to be replaced. A
	// reload that fails changes nothing: the snapshot stays "not current"
	// and the next request (after reloadRetry) tries again. Hold mode keeps
	// answering from it meanwhile, for at most hold_max; without hold mode
	// the daemon gives up.
	refreshed := verdict == dataSame && d.invalid.Load() == src.seq && req.Op != opReload
	if !refreshed && verdict != dataLoggedOut {
		if req.Op == opReload || time.Now().UnixNano() >= d.retryAt.Load() {
			err := d.reload(req.Session, src)
			if err == nil {
				d.retryAt.Store(0)
				refreshed = true
			} else {
				logf("reload failed: %v", err)
				// Kept only while the vault is still of the current generation
				// and the data file does not say our session was replaced or
				// locked.
				fp := d.loadFP()
				if !d.hold.Load() || !d.current() || (fp.authed && fp.sealed != sealOurs) || (!fp.authed && !d.mayHold()) {
					die("reload failed")
				}
				d.retryAt.Store(time.Now().Add(reloadRetry).UnixNano())
				d.enterHold("the vault changed on disk and reloading it failed")
			}
		}
	}
	if refreshed && d.heldSince.Swap(0) != 0 {
		logf("hold: the vault in memory is current again")
	}
	if req.Op == opReload {
		send(conn, &reply{Status: stOK}, nil, nil)
		return
	}

	d.mu.RLock()
	if d.v == nil {
		d.mu.RUnlock()
		send(conn, &reply{Status: stFallback}, nil, nil)
		return
	}
	ctx := &reqCtx{real: d.guarded(req.Session)}
	res := d.dispatch(ctx, &req)
	if res.fallback {
		d.mu.RUnlock()
		send(conn, &reply{Status: stFallback}, nil, nil)
		return
	}
	out, errOut, exit := res.render(req.Flags)
	if !res.owned {
		out = bytes.Clone(out) // may alias vault buffers, which a lock wipes
	}
	// Rule one again, now that the answer exists: a lock or logout that
	// revoked while it was being put together must not see it sent.
	still := d.current()
	// Send without holding the vault lock: a slow reader must not delay a lock.
	d.mu.RUnlock()
	if !still {
		wipe(out)
		if res.owned {
			res.wipe()
		}
		die("session state replaced while answering")
	}
	conn.SetWriteDeadline(time.Now().Add(time.Minute))
	send(conn, &reply{Status: stOK, Exit: exit}, out, errOut)
	wipe(out)
	if res.owned {
		res.wipe()
	}
	d.co.renew(d.tag) // idle time counts from the end of the last answer
}

var (
	listObjects = map[string]bool{"items": true, "folders": true, "collections": true, "organizations": true}
	getObjects  = map[string]bool{
		"item": true, "username": true, "password": true, "uri": true, "totp": true, "notes": true,
		"folder": true, "collection": true, "organization": true, "template": true,
	}
)

func (d *daemon) dispatch(ctx *reqCtx, req *request) *result {
	switch req.Cmd {
	case "status":
		return &result{kind: rTmpl, raw: d.v.status}
	case "list":
		if len(req.Pos) == 1 && listObjects[req.Pos[0]] {
			return d.v.list(ctx, req.Pos[0], req.Opts)
		}
	case "get":
		if len(req.Pos) == 2 && getObjects[req.Pos[0]] {
			return d.v.get(ctx, req.Pos[0], req.Pos[1], req.Opts)
		}
	}
	return fallbackResult()
}

// ---------- talking to daemons (used by clients and by auto-lock) ----------

func isDead(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT)
}

// dropStale removes the registry entry (and socket file) of a daemon that
// no longer listens. Under the metadata lock a starting daemon cannot be
// between "bound" and "registered".
func (c *coord) dropStale(tag, sock string) {
	unlock, err := c.lockMeta()
	if err != nil {
		return
	}
	defer unlock()
	if c.lookup(tag) != sock {
		return
	}
	if conn, err := net.DialTimeout("unix", sock, time.Second); err == nil {
		conn.Close()
	} else if isDead(err) {
		os.Remove(c.entry(tag))
		os.Remove(sock)
	}
}

// stopWait is how long a daemon gets to confirm that it wiped its memory.
var stopWait = 30 * time.Second

// stopSocket asks one daemon to wipe and exit. stopped: it confirmed that
// its vault is wiped and its real-CLI children are killed. gone: nothing
// listens there. Anything else (no answer in time, a refused request) is a
// failure: that daemon may still hold a vault.
func stopSocket(sock string) (stopped, gone bool, err error) {
	rep, _, _, err := roundTrip(sock, &request{Op: opLock, AutoLock: -1}, stopWait)
	switch {
	case err == nil && rep.Status == stOK:
		return true, false, nil
	case err == nil:
		return false, false, fmt.Errorf("unexpected reply %q", rep.Status)
	case isDead(err):
		return false, true, nil
	}
	return false, false, err
}

// stopDaemons makes every registered daemon of the root wipe its memory and
// exit, and waits for each to confirm. failed lists the sockets of daemons
// that did not confirm. This frees memory; what makes their vaults unusable
// is the generation, which the caller has already changed. The metadata
// lock is not held while waiting.
func stopDaemons(co *coord, except string) (stopped int, failed []string) {
	for tag, sock := range co.daemons() {
		if sock == except {
			continue
		}
		ok, gone, err := stopSocket(sock)
		switch {
		case ok:
			stopped++
		case gone:
			co.dropStale(tag, sock)
		case err != nil:
			failed = append(failed, sock)
		}
	}
	return stopped, failed
}

// invalidateDaemons tells the root's daemons that the vault data changed.
func invalidateDaemons(co *coord) {
	for tag, sock := range co.daemons() {
		if _, _, _, err := roundTrip(sock, &request{Op: opInvalidate, AutoLock: -1}, 5*time.Second); err != nil && isDead(err) {
			co.dropStale(tag, sock)
		}
	}
}

// runtimeSockets lists daemon sockets in a runtime directory, for the
// management commands, which work without knowing a root.
func runtimeSockets(dir string) []string {
	socks, _ := filepath.Glob(filepath.Join(dir, "*.sock"))
	return socks
}
