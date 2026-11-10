package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type client struct {
	cfg   *config
	real  string
	inv   *invocation
	root  string
	dir   string   // runtime directory for daemon sockets; "" if unavailable
	co    *coord   // coordination state of the root; nil if unavailable
	coErr error    // why co is nil
	lease *os.File // this command's admission (coord.admit); the real CLI inherits it
	data  *os.File // data.lock while the real CLI runs; the real CLI inherits it
}

// debugf prints routing decisions. Messages are fixed texts plus internal
// facts (errors, counts, the root path); command-line arguments are never
// printed, so no password, token or payload can end up in a debug log.
func (c *client) debugf(format string, a ...any) {
	if c.cfg.Debug {
		fmt.Fprintf(os.Stderr, "bw-wrapper: "+format+"\n", a...)
	}
}

// runBW is the drop-in entry point: args are a `bw` command line.
//
// Every decision below is taken from the parsed invocation (args.go) and its
// class; raw arguments are not looked at again.
func runBW(args []string) int {
	cfg := loadConfig()
	real, err := findRealBW(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bw-wrapper:", err)
		return 127
	}
	c := &client{cfg: cfg, real: real, inv: parseArgs(args)}
	if on, _ := parseBool(os.Getenv("BWW_DISABLE")); on {
		return c.execReal("wrapper disabled")
	}
	inv := c.inv
	class := inv.class()
	// The gate comes first: nothing below may hand a write to the real CLI.
	if class == classWrite && !cfg.AllowWrites {
		return c.deny()
	}
	// A line whose command cannot be told for certain is not run even when
	// writes are allowed: it could be a lock, logout, login or unlock of a
	// CLI newer than the wrapper's table, and those must not bypass the
	// session protocol.
	if class == classWrite && inv.cmd == "" {
		return c.fail("bw-wrapper cannot tell which command this line runs (an option or command it does not know comes first), " +
			"so it is not passed to the Bitwarden CLI. Put global options after the command, or set BWW_DISABLE=1 for this one call.")
	}
	c.root = appDataDir(real)
	var dirErr error
	if c.dir, dirErr = runtimeDir(); dirErr != nil {
		c.dir = ""
	}
	if c.co, c.coErr = openCoord(c.root); c.coErr != nil {
		c.co = nil
	}
	canCache := c.dir != "" && c.co != nil

	// From here on, every start of the real CLI follows the launch rules
	// (below, and docs/LIFECYCLE.md). They hold for every line, also for one
	// that prints nothing secret: the CLI unlocks itself with BW_SESSION
	// when it starts, before it looks at its arguments, and stores the key
	// again; and whatever it runs, it reads and may write the data file.
	if class == classInfo {
		return c.execWithoutSession("help or version")
	}
	reportsState := class == classStatus || inv.cmd == "login" || inv.cmd == "unlock" // status, login --check, unlock --check
	if class == classLocal && !reportsState && !inv.sessionOpt {
		return c.execWithoutSession("needs no vault")
	}

	switch class {
	case classSession:
		if inv.cmd == "lock" || inv.cmd == "logout" {
			return c.lockOrLogout()
		}
		return c.unlock()
	case classStatus, classLocal:
		// These reveal nothing from the vault and are never refused for what
		// they print. But the real CLI gets the session only for an admitted
		// command; otherwise it runs without it (and reports "locked", which
		// for this wrapper is the truth).
		if inv.session != "" && c.admit(true) == admitAllowed {
			if class == classStatus && canCache {
				if code, ok := c.fast(); ok {
					return code
				}
			}
			return c.realRun(true)
		}
		if inv.sessionOpt {
			return c.refuse(admitDenied, "the session given with --session cannot be used now")
		}
		return c.execWithoutSession("not admitted: without the session")
	}

	// Everything below uses a session that is already there. It needs the
	// one admission, whichever way it is going to be answered.
	if v := c.admit(false); v != admitAllowed {
		return 1
	}
	switch {
	case inv.cmd == "get" || inv.cmd == "list":
		if canCache {
			if code, ok := c.fast(); ok {
				return code
			}
		} else {
			c.debugf("no cached answers (runtime dir: %v, coordination: %v)", dirErr, c.coErr)
		}
		return c.realRun(true)
	case inv.cmd == "sync" && inv.exact && inv.has("last"):
		return c.realRun(true)
	case inv.cmd == "sync":
		if code, refused := c.refuseExpired(); refused {
			return code
		}
		code := c.realRun(false) // we have work to do when it is done
		if code == 0 {
			c.refresh()
		}
		return code
	case class == classWrite: // allowed by configuration
		if code, refused := c.refuseExpired(); refused {
			return code
		}
		code := c.realRun(false)
		c.refresh()
		return code
	}
	return c.realRun(true)
}

// fail prints an error the way the real CLI does and returns its exit code.
func (c *client) fail(msg string) int {
	f := c.inv.flags
	f.Color = chalkColor()
	out, errOut, code := errResult(msg).render(f)
	emit(out, errOut)
	return code
}

// refuse answers "Vault is locked." in place of the real CLI or a daemon.
func (c *client) refuse(v verdict, why string) int {
	if v == admitUnknown {
		c.fail(fmt.Sprintf("Vault is locked.\nbw-wrapper: cannot establish whether a lock or logout is in force for this vault (%s). "+
			"Nothing that uses a session is run until %s can be used again.", why, filepath.Join(c.root, ".bw-wrapper")))
		return 1
	}
	c.fail("Vault is locked.\nbw-wrapper: " + why + ". Nothing is read through bw-wrapper until `bw lock` succeeds or you unlock again with `bw unlock`.")
	return 1
}

// admit is the mandatory admission of a command that uses an existing
// session (coord.admit): allowed, denied, or unknown, and unknown is denied.
// On success the command holds its lease until the process ends. Unless
// quiet, a refusal is printed.
//
// If the session has been idle beyond auto_lock, it is locked first (the
// same sequence as the daemon's timer and a manual `bw lock`), and the
// command then meets a locked vault like any other.
func (c *client) admit(quiet bool) verdict {
	if c.co == nil {
		if errors.Is(c.coErr, errNoCoord) {
			// No state was ever recorded for this root and none can be:
			// nothing to violate, nothing cached. The real CLI answers.
			return admitAllowed
		}
		if !quiet {
			c.refuse(admitUnknown, c.coErr.Error())
		}
		return admitUnknown
	}
	tag := ""
	if c.inv.session != "" {
		tag = sessionTag(c.inv.session)
	}
	var limit time.Duration
	if c.cfg.AutoLockAction != "evict" {
		limit = c.cfg.AutoLock
	}
	lease, v, why := c.co.admit(tag, limit)
	if v == admitExpired {
		if c.expire(tag, limit) {
			lease, v, why = c.co.admit(tag, 0)
		} else {
			v, why = admitDenied, "the session was idle longer than auto_lock and is being locked"
		}
	}
	if v != admitAllowed {
		if !quiet {
			c.refuse(v, why)
		}
		return v
	}
	c.lease = lease
	return admitAllowed
}

// expire locks a session that has been idle beyond the limit. It reports
// whether the command may ask for admission again: the lock sequence ran
// (whatever its outcome, the state now says so), or the session on disk
// turned out not to be the idle one.
func (c *client) expire(tag string, limit time.Duration) (again bool) {
	op, err := c.co.tryBeginOp("auto-lock")
	if err != nil || op == nil {
		return false // another session command is running: not now
	}
	defer op.end()
	if last, known := c.co.activity(tag); !known || time.Since(last) <= limit {
		return true // somebody else settled it meanwhile
	}
	var macKey []byte
	if key, err := base64.StdEncoding.DecodeString(c.inv.session); err == nil && len(key) == 64 {
		macKey = key[32:]
	}
	ours := func() bool { return readFP(c.root, macKey, true).sealed != sealForeign }
	if !ours() {
		// The session on disk is a newer one, made with the real CLI
		// directly. It is not ours to lock, and ours is dead anyway.
		c.co.forgetActivity(tag)
		return true
	}
	rev, err := c.co.revoke("auto-lock")
	if err != nil {
		return false
	}
	c.debugf("session idle beyond auto_lock: locking")
	c.co.finishLock(rev, op, lockPlan{
		kind:      "auto-lock",
		run:       func(inherit []*os.File) int { return realLock(c.real, withoutSession(os.Environ()), inherit) },
		stillOurs: ours,
		retries:   2,
		log:       c.debugf,
	})
	rev.done()
	c.co.forgetActivity(tag)
	return true
}

// realLock runs the real `bw lock` for an automatic lock (daemon timer or
// admission). It returns the exit code, which the caller does not trust.
func realLock(realBW string, env []string, inherit []*os.File) int {
	cmd := exec.Command(realBW, "lock", "--quiet", "--nointeraction")
	cmd.Env = env
	cmd.ExtraFiles = inherit // operation and revocation last as long as the real CLI does
	err := cmd.Run()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() > 0 {
		return ee.ExitCode()
	}
	return 127
}

// testHook lets a test stop a process at a named point (see TestMain). In
// production it does nothing.
var testHook = func(point string) {}

// lockOrLogout ends the session for every shell that uses this root.
//
//  1. Revoke (coord.revoke): the revocation is pending, epoch+1, access not
//     open, new generation. From this moment no cached vault of the root
//     answers, no pending restore applies, no command is admitted, and every
//     login or unlock requested earlier is cancelled, wherever its process
//     runs or waits. A login or unlock requested later waits until this
//     revocation is finished: the revocation has its place in the order
//     from here on, not only once it holds the operation lock.
//  2. Take the operation lock. A login or unlock still running in another
//     shell is told to stop, and we wait until it and its real CLI are gone:
//     nothing may rewrite the session after we return.
//  3. coord.finishLock, the sequence shared with auto-lock: wipe caches,
//     wait for admitted commands, run the real command, record the outcome
//     as the data file shows it. If a usable session is left, access stays
//     blocked and this command fails, whatever the real CLI's exit code.
//
// If the coordination state cannot be used, the real command still runs,
// but the result is reported as a failure: the wrapper cannot vouch that no
// daemon elsewhere still holds this vault.
func (c *client) lockOrLogout() int {
	uncoordinated := func(why error) int {
		if c.dir != "" { // best effort: daemons with sockets in our own runtime directory
			for _, s := range runtimeSockets(c.dir) {
				if strings.HasPrefix(filepath.Base(s), sockPrefix(c.root)) {
					stopSocket(s)
				}
			}
		}
		code := c.runReal(os.Stdout)
		fmt.Fprintln(os.Stderr)
		c.fail(fmt.Sprintf("bw-wrapper could not coordinate this %s with other shells (%v). The Bitwarden CLI command above was run, "+
			"but a bw-wrapper daemon started elsewhere may still hold this vault in memory. Run `bw-wrapper stop` there.", c.inv.cmd, why))
		if code == 0 {
			code = 1
		}
		return code
	}
	if c.co == nil {
		return uncoordinated(c.coErr)
	}
	rev, err := c.co.revoke(c.inv.cmd)
	if err != nil {
		return uncoordinated(err)
	}
	defer rev.done()
	c.debugf("revoked: epoch %d for %s", rev.epoch, c.root)
	testHook("revoked")
	op, err := c.co.beginOp(c.inv.cmd, true, 30*time.Second, nil)
	if err != nil {
		// Access stays revoked: fail closed.
		c.fail(fmt.Sprintf("bw-wrapper: %v, and it did not stop when asked. `%s` was not run. Access through bw-wrapper stays blocked; try again.", err, c.inv.cmd))
		return 1
	}
	defer op.end()
	code, ok, drained := c.co.finishLock(rev, op, lockPlan{
		kind: c.inv.cmd,
		run:  func(inherit []*os.File) int { code, _ := c.runRealOp(op, inherit, os.Stdout); return code },
		log:  c.debugf,
	})
	if !ok {
		fmt.Fprintln(os.Stderr)
		c.fail(fmt.Sprintf("bw-wrapper: `%s` did not complete, so the session may still be valid for the Bitwarden CLI itself. "+
			"Access through bw-wrapper stays blocked until `bw %s` succeeds or you unlock again.", c.inv.cmd, c.inv.cmd))
		if code == 0 {
			code = 1
		}
	} else if !drained {
		fmt.Fprintln(os.Stderr)
		c.fail(fmt.Sprintf("bw-wrapper: the %s itself succeeded, but a command that was started before it is still running and could not be stopped. "+
			"It may still print what it has already read.", c.inv.cmd))
		if code == 0 {
			code = 1
		}
	}
	return code
}

// Launch rules. Every start of the real CLI by a client goes through one of
// three functions. Whichever it is, the process holds a lease (use.lock) and
// the root's data lock from before it starts until it has exited, because
// it inherits both: a lock or logout waits for it or stops it, and no
// snapshot is restored over what it writes. docs/LIFECYCLE.md has the table.
//
//	execWithoutSession  The line needs no session (help, version, local
//	                    commands, a status that was not admitted). The CLI is
//	                    started without BW_SESSION, so it cannot unlock itself
//	                    at startup and cannot store a key. It does not start
//	                    while a lock or logout is pending.
//	realRun             An admitted command: the CLI gets the session. If the
//	                    caller has work to do afterwards, the CLI runs as a
//	                    child and the data lock is released before that work;
//	                    the process is only replaced (exec) when nothing
//	                    follows.
//	runRealOp           The body of a session operation (lock, logout, login,
//	                    unlock). The CLI inherits the operation lock; for
//	                    lock and logout also the pending revocation and the
//	                    data lock, held exclusively.
//
// execReal itself is used directly only where there is nothing to
// coordinate with: BWW_DISABLE, and a root where no coordination state can
// exist. The daemon's counterpart is daemon.dataRun.

// realRun hands an admitted command to the real CLI. final says that the
// caller has nothing to do afterwards.
//
// The run is ordered against other real-CLI runs on this root by data.lock:
// shared normally, exclusive in hold mode, where the data file is
// snapshotted before the run and put back if the CLI logged itself out
// (hold.go). The admission is checked again once the lock is ours: waiting
// for a daemon or for the lock can take long, and a lock or logout that
// began in the meantime must not see the old session handed out.
func (c *client) realRun(final bool) int {
	if c.co == nil {
		return c.execReal("no coordination")
	}
	var err error
	if c.data, err = c.co.lockData(c.cfg.Hold, nil); err != nil {
		return c.refuse(admitUnknown, err.Error())
	}
	if v, why := c.co.admitted(); v != admitAllowed {
		return c.refuse(v, why)
	}
	if final && !c.cfg.Hold {
		return c.execReal("not answered from memory") // takes the lease and the data lock with it
	}
	after := func() bool { return false }
	if c.cfg.Hold {
		after = guardData(c.co)
	}
	code := c.runReal(os.Stdout)
	restored := after()
	// Released before the caller's follow-up work: a daemon that reloads
	// needs the lock itself.
	c.data.Close()
	c.data = nil
	if restored && !c.inv.flags.Quiet {
		fmt.Fprintln(os.Stderr, "\n"+holdRestoredNote)
	}
	return code
}

// execWithoutSession replaces this process with the real CLI for a line
// that needs no session. BW_SESSION is removed from its environment: the CLI
// unlocks itself with it on every start and stores the key again, which no
// process outside an admission may do. The process still joins the root: a
// lease, taken when no lock or logout is pending, and the data lock, shared.
func (c *client) execWithoutSession(why string) int {
	c.debugf("real CLI without a session (%s)", why)
	if c.co != nil {
		var err error
		if c.lease, err = c.co.join(); err == nil {
			c.data, err = c.co.lockData(false, nil)
		}
		if err != nil {
			return c.refuse(admitUnknown, err.Error())
		}
	} else if !errors.Is(c.coErr, errNoCoord) {
		return c.refuse(admitUnknown, c.coErr.Error())
	}
	env := withoutSession(os.Environ())
	for _, f := range c.inherit() {
		syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_SETFD, 0)
	}
	err := syscall.Exec(c.real, append([]string{"bw"}, c.inv.args...), env)
	fmt.Fprintf(os.Stderr, "bw-wrapper: cannot run %s: %v\n", c.real, err)
	return 127
}

// refuseExpired is the hold-mode check before a command that needs the
// server: if the refresh token is past its own expiry, the real CLI could
// only fail and log itself out, so it is not run.
func (c *client) refuseExpired() (code int, refused bool) {
	if !c.cfg.Hold {
		return 0, false
	}
	st := readLoginState(c.root)
	if !st.authed || !st.hasExp || time.Now().Before(st.refreshExp) {
		return 0, false
	}
	msg := fmt.Sprintf("The login session expired on %s. bw-wrapper (hold mode) did not run `%s`, because the Bitwarden CLI would log itself out and erase its local vault. "+
		"Reading still works; to reach the server again, log in anew (bw logout, then bw login).",
		st.refreshExp.Local().Format("2006-01-02 15:04"), c.inv.cmd)
	f := c.inv.flags
	f.Color = chalkColor()
	out, errOut, code := errResult(msg).render(f)
	emit(out, errOut)
	return code, true
}

// withoutSession returns env without BW_SESSION.
func withoutSession(env []string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "BW_SESSION=") {
			out = append(out, kv)
		}
	}
	return out
}

// execReal replaces this process with the real CLI, session included.
func (c *client) execReal(why string) int {
	c.debugf("real CLI (%s)", why)
	for _, f := range c.inherit() { // the real CLI takes over the lease and the data lock
		syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_SETFD, 0)
	}
	err := syscall.Exec(c.real, append([]string{"bw"}, c.inv.args...), os.Environ())
	fmt.Fprintf(os.Stderr, "bw-wrapper: cannot run %s: %v\n", c.real, err)
	return 127
}

// inherit lists the lock files a real CLI started for this command must
// keep holding.
func (c *client) inherit() []*os.File {
	var files []*os.File
	for _, f := range []*os.File{c.lease, c.data} {
		if f != nil {
			files = append(files, f)
		}
	}
	return files
}

func exitCode(real string, err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "bw-wrapper: cannot run %s: %v\n", real, err)
	return 127
}

// runReal runs the real CLI as a child and returns its exit code.
func (c *client) runReal(stdout io.Writer, extraEnv ...string) int {
	c.debugf("real CLI as a child process")
	cmd := exec.Command(c.real, c.inv.args...)
	cmd.Args[0] = "bw"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, os.Stderr
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.ExtraFiles = c.inherit()
	// The child shares our terminal and gets the signals itself.
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	defer signal.Reset(syscall.SIGINT, syscall.SIGQUIT)
	return exitCode(c.real, cmd.Run())
}

// runRealOp runs the real CLI as the body of a session operation. The child
// inherits the operation lock, so the operation counts as running for as
// long as the real CLI lives, even if this process is killed. A lock or
// logout in another shell cancels it with SIGTERM: the child is stopped,
// and only when it is gone does this function return (cancelled=true).
func (c *client) runRealOp(op *sessionOp, inherit []*os.File, stdout io.Writer, extraEnv ...string) (code int, cancelled bool) {
	c.debugf("real CLI as a session operation")
	cmd := exec.Command(c.real, c.inv.args...)
	cmd.Args[0] = "bw"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, os.Stderr
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.ExtraFiles = inherit
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	defer signal.Reset(syscall.SIGINT, syscall.SIGQUIT)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(stop)
	if err := cmd.Start(); err != nil {
		return exitCode(c.real, err), false
	}
	op.setChild(cmd.Process.Pid)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return exitCode(c.real, err), false
	case <-stop:
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		return 128 + int(syscall.SIGTERM), true
	}
}

// deny refuses a command in read-only mode, in the real CLI's error format.
func (c *client) deny() int {
	msg := fmt.Sprintf("bw-wrapper is read-only: `%s` is not passed to the Bitwarden CLI. "+
		"Set allow_writes = true in %s (or BWW_ALLOW_WRITES=1) to allow it.", c.inv.cmd, configPath())
	f := c.inv.flags
	f.Color = chalkColor()
	out, errOut, code := errResult(msg).render(f)
	emit(out, errOut)
	return code
}

// emit writes the answer the way CliUtils.writeLn does: the final newline is
// only added when the stream is a terminal. Delivering the output is part of
// the command: an error (a full disk, a closed descriptor) is returned and
// the caller must not report success.
func emit(out, errOut []byte) error {
	return emitTo(os.Stdout, os.Stderr, isTTY(os.Stdout.Fd()), isTTY(os.Stderr.Fd()), out, errOut)
}

func emitTo(stdout, stderr io.Writer, outTTY, errTTY bool, out, errOut []byte) error {
	var first error
	write := func(w io.Writer, b []byte, tty bool) {
		if b == nil {
			return
		}
		if tty {
			b = append(b, '\n')
		}
		if n, err := w.Write(b); err != nil && first == nil {
			first = err
		} else if err == nil && n < len(b) && first == nil {
			first = io.ErrShortWrite
		}
	}
	write(stdout, out, outTTY)
	write(stderr, errOut, errTTY)
	return first
}

var termColorRE = regexp.MustCompile(`(?i)^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux`)

// chalkColor mirrors chalk's decision (it looks at stdout even for text that
// goes to stderr).
func chalkColor() bool {
	if v, ok := os.LookupEnv("FORCE_COLOR"); ok {
		return v != "0" && v != "false"
	}
	if !isTTY(os.Stdout.Fd()) {
		return false
	}
	term := os.Getenv("TERM")
	if term == "dumb" {
		return false
	}
	_, colorterm := os.LookupEnv("COLORTERM")
	return colorterm || termColorRE.MatchString(term)
}

// fast answers get/list/status from the daemon of this (root, session).
// ok=false means: use the real CLI.
func (c *client) fast() (int, bool) {
	inv := c.inv
	opts, ok := inv.cached()
	if !ok || inv.session == "" {
		return 0, false
	}
	switch inv.cmd {
	case "list":
		if !listObjects[inv.pos[0]] {
			return 0, false
		}
	case "get":
		if !getObjects[inv.pos[0]] {
			return 0, false
		}
	}
	req := &request{
		Op: opRun, Session: inv.session, Cmd: inv.cmd, Pos: inv.pos, Opts: opts,
		Flags: inv.flags, AutoLock: int64(c.cfg.AutoLock / time.Second), AutoLockAction: c.cfg.AutoLockAction,
		Hold: c.cfg.Hold, HoldMax: int64(c.cfg.HoldMax / time.Second),
	}
	req.Flags.Color = chalkColor()
	rep, out, errOut, err := c.ask(req, true)
	if err != nil {
		c.debugf("daemon unavailable (%v), using the real CLI", err)
		return 0, false
	}
	if rep.Status != stOK {
		c.debugf("daemon says %s, using the real CLI", rep.Status)
		return 0, false
	}
	if err := emit(out, errOut); err != nil {
		// The answer did not arrive: that is a failure, whatever it was.
		fmt.Fprintf(os.Stderr, "bw-wrapper: cannot write the answer: %v\n", err)
		return 1, true
	}
	return rep.Exit, true
}

// daemonSock finds the daemon serving a session of this root in the root's
// registry, whatever runtime directory it was started from. The socket must
// be ours: the session token is sent to it.
func (c *client) daemonSock(session string) string {
	sock := c.co.lookup(sessionTag(session))
	if sock == "" {
		return ""
	}
	fi, err := os.Lstat(sock)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return ""
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return ""
	}
	return sock
}

// ask sends a request to this session's daemon, starting one if needed.
func (c *client) ask(req *request, spawn bool) (*reply, []byte, []byte, error) {
	const timeout = realTimeout + 30*time.Second // a cold start loads the vault first
	try := func() (*reply, []byte, []byte, error) {
		sock := c.daemonSock(c.inv.session)
		if sock == "" {
			return nil, nil, nil, syscall.ENOENT
		}
		return roundTrip(sock, req, timeout)
	}
	rep, out, errOut, err := try()
	if err == nil || !isDead(err) || !spawn {
		return rep, out, errOut, err
	}
	if err := c.spawnDaemon(c.inv.session); err != nil {
		return nil, nil, nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rep, out, errOut, err = try()
		if err == nil || !isDead(err) || time.Now().After(deadline) {
			return rep, out, errOut, err
		}
		time.Sleep(3 * time.Millisecond)
	}
}

// spawnDaemon starts a detached daemon for the session. The token travels
// over a pipe; it is neither in argv nor in the daemon's environment.
func (c *client) spawnDaemon(session string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	init, _ := json.Marshal(daemonInit{
		Root: c.root, Session: session, RealBW: c.real, RuntimeDir: c.dir,
		AutoLock:       int64(c.cfg.AutoLock / time.Second),
		AutoLockAction: c.cfg.AutoLockAction,
		UseServe:       c.cfg.LoadViaServe,
		Hold:           c.cfg.Hold,
		HoldMax:        int64(c.cfg.HoldMax / time.Second),
	})
	logPath := filepath.Join(c.dir, "daemon.log")
	if fi, err := os.Stat(logPath); err == nil && fi.Size() > 1<<20 {
		os.Remove(logPath)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "__daemon")
	cmd.Args[0] = "bw-wrapper"
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pr, logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Env = append(daemonEnv(c.cfg.PassEnv, c.inv.passwordEnvs()), "BWW_DAEMON=1")
	err = cmd.Start()
	pr.Close()
	if err != nil {
		pw.Close()
		return err
	}
	pw.Write(init)
	pw.Close()
	wipe(init)
	c.debugf("started daemon pid %d for %s", cmd.Process.Pid, c.root)
	return cmd.Process.Release()
}

// daemonEnv is the environment a daemon gets, and through it every real-CLI
// run the daemon starts. It is built from an explicit list of variables that
// Node and the CLI need; nothing else of the caller's environment crosses
// into the long-running process. Everything environment-dependent that the
// wrapper itself needs (root, real CLI, runtime directory, settings) is
// resolved by the client and passed in the init message instead.
//
// extra are additional names from the pass_env setting. drop are the
// variables the command line names as holding a password (--passwordenv,
// every occurrence): they never pass, not even when they match the list or
// pass_env.
func daemonEnv(extra []string, drop []string) []string {
	dropped := map[string]bool{"BW_SESSION": true}
	for _, k := range drop {
		dropped[k] = true
	}
	allowed := map[string]bool{
		"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
		"LANG": true, "LANGUAGE": true, "TZ": true, "TMPDIR": true, "TERM": true,
		"SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
		"NODE_EXTRA_CA_CERTS": true, "NODE_OPTIONS": true, "NODE_PATH": true,
		"NODE_TLS_REJECT_UNAUTHORIZED": true, "NODE_NO_WARNINGS": true,
		"BITWARDENCLI_DEBUG": true,
	}
	for _, k := range extra {
		allowed[k] = true
	}
	proxy := map[string]bool{"http_proxy": true, "https_proxy": true, "no_proxy": true, "all_proxy": true}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if dropped[k] {
			continue
		}
		if allowed[k] || strings.HasPrefix(k, "LC_") || proxy[strings.ToLower(k)] {
			if k == "PATH" {
				kv = "PATH=" + absolutePath(kv[len("PATH="):])
			}
			env = append(env, kv)
		}
	}
	return env
}

// absolutePath drops the relative entries of a PATH. The daemon runs in "/",
// where "." or "bin" would name other directories than in the caller's
// shell, and the real CLI finds its interpreter (node) through PATH.
func absolutePath(path string) string {
	var keep []string
	for _, dir := range filepath.SplitList(path) {
		if filepath.IsAbs(dir) {
			keep = append(keep, dir)
		}
	}
	return strings.Join(keep, string(os.PathListSeparator))
}

// refresh makes the daemons of this root pick up changed vault data; the
// caller's own daemon reloads right away so the next command is fast again.
func (c *client) refresh() {
	if c.co == nil {
		return
	}
	invalidateDaemons(c.co)
	if c.inv.session == "" {
		return
	}
	req := &request{Op: opReload, Session: c.inv.session, AutoLock: -1}
	if _, _, _, err := c.ask(req, false); err != nil {
		c.debugf("no daemon to reload (%v)", err)
	}
}

var sessionRE = regexp.MustCompile(`BW_SESSION="([A-Za-z0-9+/=]+)"`)

// extractSession finds the new session key in the output of unlock/login,
// whichever output mode was used: --response JSON, the human-readable
// message, or --raw (the bare key).
func extractSession(out []byte) string {
	valid := func(s string) bool {
		raw, err := base64.StdEncoding.DecodeString(s)
		return err == nil && len(raw) == 64
	}
	var env struct {
		Data struct {
			Raw string `json:"raw"`
		} `json:"data"`
	}
	if json.Unmarshal(out, &env) == nil && valid(env.Data.Raw) {
		return env.Data.Raw
	}
	if m := sessionRE.FindSubmatch(out); m != nil && valid(string(m[1])) {
		return string(m[1])
	}
	if s := strings.TrimSpace(string(out)); valid(s) {
		return s
	}
	return ""
}

// sealsDisk reports whether the user key in the CLI's data file is sealed
// with the given session key: proof that this session is the one on disk.
func sealsDisk(root, session string) bool {
	key, err := base64.StdEncoding.DecodeString(session)
	if err != nil || len(key) != 64 {
		return false
	}
	defer wipe(key)
	return readFP(root, key[32:], true).sealed == sealOurs
}

// unlock runs the real unlock/login as a session operation, then starts a
// daemon for the new session so the vault is already in memory when the
// first command arrives.
//
// The request is bound to the revocation epoch it was made under. If a lock
// or logout revokes while this unlock waits for its turn, runs, or has just
// finished, the unlock does not count: it stops, or its result is not
// accepted, and the lock (which waits for us) locks whatever it left. A lock
// or logout that revoked before this request and is still pending goes
// first: we wait for it.
//
// What the command achieved is read from its result, not from its exit
// code: access is opened again only if the command printed a session key
// and the user key on disk is sealed with exactly that key. `bw login
// --cleanexit` reporting "already logged in" with exit code 0 proves
// nothing and changes nothing.
func (c *client) unlock() int {
	if c.co == nil {
		if errors.Is(c.coErr, errNoCoord) {
			return c.execReal("no coordination: not caching")
		}
		return c.fail(fmt.Sprintf("bw-wrapper: cannot use %s (%v), so the session state of this vault is unknown. `%s` was not run; "+
			"repair or remove that directory first.", filepath.Join(c.root, ".bw-wrapper"), c.coErr, c.inv.cmd))
	}
	cancelled := func() int {
		return c.fail(fmt.Sprintf("bw-wrapper: %s cancelled: the vault was locked or logged out in another shell after this %s was requested.", c.inv.cmd, c.inv.cmd))
	}
	broken := func(err error) int {
		return c.fail(fmt.Sprintf("bw-wrapper: cannot use the coordination state of this vault (%v); %s was not run.", err, c.inv.cmd))
	}
	requested, err := c.co.mark() // the epoch this request belongs to
	if err != nil {
		return broken(err)
	}
	wanted := func() bool {
		m, err := c.co.mark()
		return err == nil && m.Epoch == requested.Epoch
	}
	// One session operation at a time per root, and none while a lock or
	// logout is pending. If the root is busy (an unlock at its prompt in
	// another shell, a lock), wait.
	op, err := c.co.tryBeginOp(c.inv.cmd)
	if err == nil && op == nil {
		if !c.inv.flags.Quiet {
			fmt.Fprintln(os.Stderr, "bw-wrapper: waiting for another login, unlock or lock on this vault to finish...")
		}
		op, err = c.co.beginOp(c.inv.cmd, false, 0, wanted)
	}
	if errors.Is(err, errCancelled) {
		return cancelled()
	}
	if err != nil {
		return broken(err)
	}
	// Our turn. Still the same epoch? Then, before the real CLI can change
	// the session, start a new generation: everything cached or snapshotted
	// for this root is void. (This does not touch the epoch: an unlock does
	// not cancel other pending unlocks.)
	admitted := false
	if _, err := c.co.update(func(s *coordState) bool {
		if s.Epoch != requested.Epoch {
			return false
		}
		admitted = true
		s.Gen = newToken()
		return true
	}); err != nil || !admitted {
		op.end()
		if err != nil {
			return broken(err)
		}
		return cancelled()
	}

	// No data.lock here: an unlock can sit at its password prompt for a long
	// time and must not keep every other command waiting. It does not need
	// it either. A snapshot is not taken while an operation is active and is
	// not restored once the generation has changed (hold.go), so no restore
	// can overwrite what this command writes.
	var buf bytes.Buffer
	buf.Grow(64 << 10) // no reallocation, so no stray copy of the session key
	tty := isTTY(os.Stdout.Fd())
	var env []string
	if _, set := os.LookupEnv("FORCE_COLOR"); tty && !set {
		env = append(env, "FORCE_COLOR=1") // stdout is a pipe for the child; keep its colours
	}
	code, stopped := c.runRealOp(op, []*os.File{op.f}, io.MultiWriter(os.Stdout, &buf), env...)
	out := buf.Bytes()
	defer wipe(out)
	if tty && len(out) > 0 && out[len(out)-1] != '\n' {
		os.Stdout.Write([]byte{'\n'})
	}
	if stopped {
		op.end()
		fmt.Fprintf(os.Stderr, "\nbw-wrapper: %s cancelled by a lock or logout in another shell.\n", c.inv.cmd)
		return code
	}
	plain := regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAll(out, nil)
	defer wipe(plain)
	session := extractSession(plain)
	if session == "" || !sealsDisk(c.root, session) {
		// No new session that can be verified: nothing is opened. If access
		// was blocked, it still is.
		op.end()
		if m, err := c.co.mark(); (err != nil || c.co.blocked(m)) && code == 0 && !c.inv.flags.Quiet {
			fmt.Fprintf(os.Stderr, "\nbw-wrapper: this %s did not create a session that bw-wrapper could verify, so access through bw-wrapper stays blocked. "+
				"Run `bw lock`, then `bw unlock`.\n", c.inv.cmd)
		}
		return code
	}
	// A verified new session counts only if no lock or logout revoked
	// meanwhile. If one did, it is waiting for our operation lock and will
	// lock what we unlocked; we do not open access and do not cache.
	if ok, _ := c.co.reopen(requested.Epoch); !ok {
		op.end()
		fmt.Fprintln(os.Stderr)
		cancelled()
		return 1
	}
	c.co.startActivity(sessionTag(session))                  // the new session's idle clock starts now
	if _, failed := stopDaemons(c.co, ""); len(failed) > 0 { // daemons of the sessions this unlock replaced: free their memory
		c.debugf("%d daemon(s) of replaced sessions did not confirm their wipe (their vaults are void)", len(failed))
	}
	op.end() // the new session's daemon starts outside the operation
	if c.cfg.Preload && c.dir != "" {
		if err := c.spawnDaemon(session); err != nil {
			c.debugf("cannot start daemon: %v", err)
			return code
		}
		// Return once the daemon listens (a few ms; it keeps loading in the
		// background), so a command issued right after unlock finds it.
		for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			if sock := c.daemonSock(session); sock != "" {
				if _, _, _, err := roundTrip(sock, &request{Op: opInfo, AutoLock: -1}, time.Second); err == nil {
					break
				}
			}
		}
	}
	return code
}
