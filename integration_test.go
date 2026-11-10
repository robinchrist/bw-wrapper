package main

// Process-level tests with a stand-in for the real CLI. The test binary
// re-executes itself as the wrapper client ("__bw") and as the daemon
// ("__daemon"), so the real client, daemon, socket and coordination code
// run, while the stand-in lets a test stop a logout, unlock or sync exactly
// where it wants. Concurrency is ordered with barrier files, not sleeps.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// hookAt makes testHook stop the process at a point for which the test has
// created "<point>-hold" in dir: it reports "<point>-started" and waits for
// "<point>-release".
func hookAt(dir string) {
	if dir == "" {
		return
	}
	testHook = func(point string) {
		if _, err := os.Stat(filepath.Join(dir, point+"-hold")); err != nil {
			return
		}
		os.WriteFile(filepath.Join(dir, point+"-started"), nil, 0o600)
		for {
			if _, err := os.Stat(filepath.Join(dir, point+"-release")); err == nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestMain(m *testing.M) {
	hookAt(os.Getenv("BWW_TEST_FAKE_DIR"))
	if os.Getenv("BWW_TEST_NO_PDEATHSIG") != "" { // behave like a system without a parent-death signal
		childAttr = func() *syscall.SysProcAttr { return nil }
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "__daemon":
			if v, err := time.ParseDuration(os.Getenv("BWW_TEST_TICK")); err == nil && v > 0 {
				tick = v
			}
			if v, err := time.ParseDuration(os.Getenv("BWW_TEST_RETRY_PAUSE")); err == nil && v > 0 {
				retryPause = v
			}
			if v, err := time.ParseDuration(os.Getenv("BWW_TEST_RELOAD_RETRY")); err == nil && v > 0 {
				reloadRetry = v
			}
			if v, err := time.ParseDuration(os.Getenv("BWW_TEST_CHILD_STOP_WAIT")); err == nil && v > 0 {
				childStopWait = v
			}
			os.Exit(runDaemon())
		case "__bw":
			if v, err := time.ParseDuration(os.Getenv("BWW_TEST_USE_DRAIN")); err == nil && v > 0 {
				useDrainWait = v
			}
			if v, err := time.ParseDuration(os.Getenv("BWW_TEST_RETRY_PAUSE")); err == nil && v > 0 {
				retryPause = v
			}
			os.Exit(runBW(os.Args[2:]))
		case "__admin":
			if v, err := time.ParseDuration(os.Getenv("BWW_TEST_STOP_WAIT")); err == nil && v > 0 {
				stopWait = v
			}
			os.Exit(admin(os.Args[2:]))
		}
	}
	os.Exit(m.Run())
}

// fakeCLI answers like the Bitwarden CLI for the few commands the wrapper
// needs, from the login state in data.json. Session commands and sync
// announce themselves ("<cmd>-started", with their pid in "<cmd>-pid") and
// then wait for "<cmd>-release" before they change anything. Every run is
// counted ("<cmd>-runs") and leaves its environment in "env-<cmd>.<pid>".
// With "lock-fail" present, lock fails without touching the session. `export`
// stands for any command the real CLI answers with an existing session; with
// "load-hold" present, a daemon's vault load waits at the barrier "load".
// Further switches: "lock-noop" and "unlock-noop" (exit 0 without doing
// anything, like a failure under --cleanexit), "unlock-liar" (prints a
// session key without creating the session), "load-fail", "export-logout"
// (the CLI logs itself out), "sync-ok" (a sync that writes "state-rev2"),
// and the files "password" and "notes" for the item's content.
const fakeCLI = `#!/bin/sh
data="$BITWARDENCLI_APPDATA_DIR/data.json"
fake="$BWW_TEST_FAKE_DIR"
env > "$fake/env-$1.$$"
echo x >> "$fake/$1-runs"
barrier() {
	echo $$ > "$fake/$1-pid"
	: > "$fake/$1-started"
	while [ ! -e "$fake/$1-release" ]; do sleep 0.01; done
}
put() { cp "$fake/$1" "$data.tmp" && mv "$data.tmp" "$data"; }
# With "any-hold" present every run waits at the barrier "any" first.
if [ -e "$fake/any-hold" ]; then barrier any; fi
# Like the real CLI, which unlocks itself with BW_SESSION when it starts,
# before it looks at its arguments, and stores the key again: with
# "startup-hold" present, a run that was given a session reads the data file,
# waits at the barrier "startup", and writes back what it read.
if [ -n "$BW_SESSION" ] && [ -e "$fake/startup-hold" ]; then
	cp "$data" "$fake/startup-copy.$$"
	barrier startup
	cp "$fake/startup-copy.$$" "$data.tmp" && mv "$data.tmp" "$data"
fi
pw=pw1; [ -e "$fake/password" ] && pw=$(cat "$fake/password")
notes=null; [ -e "$fake/notes" ] && notes="\"$(cat "$fake/notes")\""
case "$1" in
logout) barrier logout; put state-out; printf 'You have logged out.'; exit 0 ;;
lock) barrier lock
	if [ -e "$fake/lock-fail" ]; then printf 'lock failed' >&2; exit 1; fi
	if [ -e "$fake/lock-noop" ]; then exit 0; fi
	put state-locked; printf 'Your vault is locked.'; exit 0 ;;
unlock|login) barrier unlock
	if [ -e "$fake/unlock-noop" ]; then
		if [ -e "$fake/unlock-noop-json" ]; then printf '{"success":false,"message":"You are already logged in as u@example.test."}'
		else printf 'You are already logged in as u@example.test.' >&2; fi
		exit 0
	fi
	if [ -e "$fake/unlock-liar" ]; then cat "$fake/new-session"; exit 0; fi
	put state-new; cat "$fake/new-session"; exit 0 ;;
export) barrier export
	grep -q '__PROTECTED__' "$data" || { printf 'Vault is locked.' >&2; exit 1; }
	if [ -e "$fake/export-logout" ]; then put state-out; printf 'invalid_grant' >&2; exit 1; fi
	printf 'exported %s' "$pw"; exit 0 ;;
sync) barrier sync
	if [ -e "$fake/sync-ok" ]; then put state-rev2; printf 'Syncing complete.'; exit 0; fi
	put state-out; printf 'Syncing failed: invalid_grant' >&2; exit 1 ;;
esac
fail() { printf '{"success":false,"message":"%s"}' "$1"; exit 1; }
grep -q '"global_account_activeAccountId":"u1"' "$data" || fail "You are not logged in."
grep -q '__PROTECTED__' "$data" || fail "Vault is locked."
item='{"object":"item","id":"11111111-1111-4111-8111-111111111111","organizationId":null,"folderId":null,"type":1,"name":"x","notes":'"$notes"',"login":{"username":"u","password":"'"$pw"'","totp":null,"uris":[]},"collectionIds":[]}'
case "$*" in
"get password x"*) printf '%s' "$pw" ;;
"status --response"*) printf '%s' '{"success":true,"data":{"object":"template","template":{"serverUrl":null,"lastSync":"2026-01-01T00:00:00.000Z","userEmail":"u@example.test","userId":"u1","status":"unlocked"}}}' ;;
"list items --response"*) if [ -e "$fake/load-hold" ]; then barrier load; fi
	if [ -e "$fake/load-fail" ]; then fail "load failed"; fi
	printf '{"success":true,"data":{"object":"list","data":[%s]}}' "$item" ;;
"list "*) printf '%s' '{"success":true,"data":{"object":"list","data":[]}}' ;;
*) fail "Not found." ;;
esac
`

type fakeEnv struct {
	t          *testing.T
	root       string // CLI data dir
	dirA, dirB string // two runtime dirs: a desktop shell and a job without XDG_RUNTIME_DIR
	fake       string // control files of the stand-in CLI
	env        []string
	session    string // the session the root is unlocked with at the start
	newSession string // the session a (fake) unlock produces
	co         *coord
}

func sealedState(sessionB64 string) string {
	key, _ := base64.StdEncoding.DecodeString(sessionB64)
	iv, ct := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 80)
	mac := hmac.New(sha256.New, key[32:])
	mac.Write(iv)
	mac.Write(ct)
	blob := append(append(append([]byte{2}, iv...), mac.Sum(nil)...), ct...)
	return `{"global_account_activeAccountId":"u1","user_u1_token_accessToken":"tok","user_u1_ciphers_ciphers":{},"__PROTECTED__u1_user_auto":"` +
		base64.StdEncoding.EncodeToString(blob) + `"}`
}

// rev2State is the vault of sealedState with different content: a newer
// revision of the same session.
func rev2State(sessionB64 string) string {
	return strings.Replace(sealedState(sessionB64), `"user_u1_ciphers_ciphers":{}`, `"user_u1_ciphers_ciphers":{"rev":2}`, 1)
}

const (
	fakeLoggedOut = `{"global_account_activeAccountId":null,"user_u1_token_accessToken":null}`
	fakeLocked    = `{"global_account_activeAccountId":"u1","user_u1_token_accessToken":"tok","user_u1_ciphers_ciphers":{}}`
)

func newFakeEnv(t *testing.T) *fakeEnv {
	t.Helper()
	base, err := os.MkdirTemp("", "bww") // short paths: runtime dirs hold unix sockets
	if err != nil {
		t.Fatal(err)
	}
	e := &fakeEnv{t: t, root: filepath.Join(base, "root"), dirA: filepath.Join(base, "runA"), dirB: filepath.Join(base, "runB"), fake: filepath.Join(base, "fake")}
	for _, p := range []string{e.root, e.dirA, e.dirB, e.fake} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.root = canonicalPath(e.root)
	cli := filepath.Join(e.fake, "bw")
	e.session = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 64))
	e.newSession = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 64))
	for name, content := range map[string]string{
		"bw": fakeCLI, "state-out": fakeLoggedOut, "state-locked": fakeLocked,
		"state-new": sealedState(e.newSession), "new-session": e.newSession,
		"state-rev2": rev2State(e.session),
	} {
		if err := os.WriteFile(filepath.Join(e.fake, name), []byte(content), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !strings.HasPrefix(k, "BW") && k != "BITWARDENCLI_APPDATA_DIR" {
			e.env = append(e.env, kv)
		}
	}
	e.env = append(e.env,
		"BWW_REAL_BW="+cli, "BWW_CONFIG="+filepath.Join(base, "no-config"),
		"BITWARDENCLI_APPDATA_DIR="+e.root, "BWW_TEST_FAKE_DIR="+e.fake, "BWW_TEST_TICK=50ms",
		"BWW_HOLD=1", "BWW_HOLD_MAX=0", "BWW_AUTO_LOCK=0", "BWW_LOAD_VIA_SERVE=0", "BW_NOINTERACTION=true",
		// the daemon gets an explicit environment; what the stand-in CLI and
		// the test hooks need has to be named
		"BWW_TEST_RETRY_PAUSE=10ms", "BWW_TEST_RELOAD_RETRY=1ms", "BWW_PASS_ENV=BWW_TEST_FAKE_DIR,BWW_TEST_TICK,BWW_TEST_RETRY_PAUSE,BWW_TEST_RELOAD_RETRY,BWW_TEST_NO_PDEATHSIG,BWW_TEST_CHILD_STOP_WAIT",
	)
	e.write(sealedState(e.session))
	if e.co, err = openCoord(e.root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, name := range []string{"logout", "lock", "unlock", "sync", "export", "load", "revoked", "timer", "startup", "any", "child-started", "child-reaped"} {
			e.release(name) // let anything still waiting at a barrier finish
		}
		stopDaemons(e.co, "")
		os.RemoveAll(base)
	})
	return e
}

func (e *fakeEnv) write(data string) {
	e.t.Helper()
	tmp := filepath.Join(e.root, "data.json.new")
	if err := os.WriteFile(tmp, []byte(data), 0o600); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(e.root, "data.json")); err != nil {
		e.t.Fatal(err)
	}
}

func (e *fakeEnv) data() string {
	b, _ := os.ReadFile(filepath.Join(e.root, "data.json"))
	return string(b)
}

// release opens a barrier of the stand-in CLI (now or for a later run).
func (e *fakeEnv) release(name string) {
	os.WriteFile(filepath.Join(e.fake, name+"-release"), nil, 0o600)
}

// started waits until the stand-in CLI has reached a barrier.
func (e *fakeEnv) started(name string) {
	e.t.Helper()
	e.waitUntil(name+" to reach its barrier", func() bool { _, err := os.Stat(filepath.Join(e.fake, name+"-started")); return err == nil })
}

func (e *fakeEnv) fakePid(name string) int {
	b, _ := os.ReadFile(filepath.Join(e.fake, name+"-pid"))
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

func alive(pid int) bool { return pid > 1 && syscall.Kill(pid, 0) == nil }

// runs is how often the stand-in CLI was run with a command.
func (e *fakeEnv) runs(name string) int {
	b, _ := os.ReadFile(filepath.Join(e.fake, name+"-runs"))
	return bytes.Count(b, []byte("x"))
}

// childEnvs returns the environments the stand-in CLI saw for a command.
func (e *fakeEnv) childEnvs(name string) []string {
	files, _ := filepath.Glob(filepath.Join(e.fake, "env-"+name+".*"))
	var envs []string
	for _, f := range files {
		b, _ := os.ReadFile(f)
		envs = append(envs, string(b))
	}
	return envs
}

func (e *fakeEnv) access() string {
	m, err := e.co.mark()
	if err != nil {
		return "error: " + err.Error()
	}
	return m.Access
}

// mustBlock: the wrapper itself answers "Vault is locked." and neither a
// daemon nor the real CLI is asked.
func (e *fakeEnv) mustBlock(when, dir string, args ...string) {
	e.t.Helper()
	before := e.runs(args[0])
	r := e.run(e.cmd(dir, e.session, nil, args...))
	if r.code != 1 || r.stdout != "" || !strings.HasPrefix(r.stderr, "Vault is locked.") {
		e.t.Errorf("%s: bw %v gave (%d, %q, %q), want the wrapper's 'Vault is locked.'", when, args, r.code, r.stdout, r.stderr)
	}
	if e.runs(args[0]) != before {
		e.t.Errorf("%s: bw %v was handed to the real CLI", when, args)
	}
	if pids := e.loaded(); len(pids) != 0 {
		e.t.Errorf("%s: daemon(s) %v hold a vault", when, pids)
	}
}

// cmd prepares a wrapper invocation from the shell with runtime dir `dir`.
func (e *fakeEnv) cmd(dir, session string, extraEnv []string, args ...string) *exec.Cmd {
	c := exec.Command(os.Args[0], append([]string{"__bw"}, args...)...)
	c.Env = append(append([]string(nil), e.env...), "BWW_RUNTIME_DIR="+dir)
	if session != "" {
		c.Env = append(c.Env, "BW_SESSION="+session)
	}
	c.Env = append(c.Env, extraEnv...)
	return c
}

type cmdResult struct {
	code           int
	stdout, stderr string
}

func (e *fakeEnv) run(c *exec.Cmd) cmdResult {
	e.t.Helper()
	var out, errOut bytes.Buffer
	c.Stdout, c.Stderr = &out, &errOut
	err := c.Run()
	r := cmdResult{stdout: out.String(), stderr: errOut.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// read runs `bw get password x` through the wrapper, from runtime dir `dir`.
func (e *fakeEnv) read(dir string) cmdResult {
	e.t.Helper()
	return e.run(e.cmd(dir, e.session, nil, "get", "password", "x"))
}

func (e *fakeEnv) daemons() []*daemonInfo {
	var infos []*daemonInfo
	for _, s := range e.co.daemons() {
		if rep, _, _, err := roundTrip(s, &request{Op: opInfo, AutoLock: -1}, 5*time.Second); err == nil && rep.Info != nil {
			infos = append(infos, rep.Info)
		}
	}
	return infos
}

// loaded returns the daemons that hold a vault.
func (e *fakeEnv) loaded() (pids []int) {
	for _, d := range e.daemons() {
		if d.Loaded {
			pids = append(pids, d.PID)
		}
	}
	return pids
}

func (e *fakeEnv) waitUntil(what string, cond func() bool) {
	e.t.Helper()
	for deadline := time.Now().Add(20 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// cached makes sure a daemon holds the vault, and returns its pid.
func (e *fakeEnv) cached(dir string) int {
	e.t.Helper()
	if r := e.read(dir); r.code != 0 || r.stdout != "pw1" {
		e.t.Fatalf("read gave (%d, %q, %q), want the password", r.code, r.stdout, r.stderr)
	}
	e.waitUntil("a daemon to hold the vault", func() bool { return len(e.loaded()) == 1 })
	return e.loaded()[0]
}

// mustRefuse: nothing answers with the password any more and no daemon
// holds a vault.
func (e *fakeEnv) mustRefuse(when, dir string) {
	e.t.Helper()
	if r := e.read(dir); r.code == 0 || strings.Contains(r.stdout, "pw1") {
		e.t.Errorf("%s: the password was still answered (%d, %q)", when, r.code, r.stdout)
	}
	if pids := e.loaded(); len(pids) != 0 {
		e.t.Errorf("%s: daemon(s) %v still hold a vault", when, pids)
	}
	// The refused read may have started a daemon; with nothing to load it
	// has no vault and exits by itself.
	e.waitUntil("all daemons to be gone", func() bool { return len(e.daemons()) == 0 })
}

// Control: without any explicit session command, hold mode does keep a
// daemon answering after the CLI is logged out on disk. The tests below
// would be meaningless if it did not.
func TestHoldKeepsUnrequestedLogout(t *testing.T) {
	e := newFakeEnv(t)
	pid := e.cached(e.dirA)
	e.write(fakeLoggedOut) // the CLI logged itself out behind the wrapper's back
	if r := e.read(e.dirA); r.code != 0 || r.stdout != "pw1" {
		t.Fatalf("not held after an unrequested logout: (%d, %q)", r.code, r.stdout)
	}
	if d := e.daemons(); len(d) != 1 || d[0].PID != pid || d[0].Held == 0 {
		t.Errorf("the same daemon should be holding: %+v", d)
	}
	// ... and from the other runtime directory it is the same daemon
	if r := e.read(e.dirB); r.code != 0 || r.stdout != "pw1" || len(e.daemons()) != 1 {
		t.Errorf("second runtime directory: (%d, %q), %d daemons", r.code, r.stdout, len(e.daemons()))
	}
}

// One vault root, two runtime directories (a desktop shell with
// XDG_RUNTIME_DIR, a job without it). Logout from one must end cached access
// in the other.
func TestLogoutAcrossRuntimeDirs(t *testing.T) {
	e := newFakeEnv(t)
	pid := e.cached(e.dirA) // the desktop shell's daemon; hold mode is on
	e.release("logout")
	r := e.run(e.cmd(e.dirB, "", nil, "logout")) // the job logs out
	if r.code != 0 || r.stdout != "You have logged out." {
		t.Fatalf("logout: (%d, %q, %q)", r.code, r.stdout, r.stderr)
	}
	if pids := e.loaded(); len(pids) != 0 {
		t.Errorf("daemon %v (started from the other runtime directory: %d) survived the logout", pids, pid)
	}
	if socks, _ := filepath.Glob(filepath.Join(e.dirA, "*.sock")); len(socks) != 0 {
		t.Errorf("its socket is still there: %v", socks)
	}
	e.mustRefuse("read from the desktop shell after the job's logout", e.dirA)
	e.mustRefuse("read from the job after its logout", e.dirB)
}

// The same split for a pending restore: a guarded command in one runtime
// directory, logout in the other.
func TestRestoreAcrossRuntimeDirs(t *testing.T) {
	e := newFakeEnv(t)
	sync := e.cmd(e.dirA, e.session, nil, "sync") // guarded (hold mode): snapshots the vault first
	var syncErr bytes.Buffer
	sync.Stderr = &syncErr
	if err := sync.Start(); err != nil {
		t.Fatal(err)
	}
	e.started("sync") // the snapshot is taken, the real sync is running

	e.release("logout")
	if r := e.run(e.cmd(e.dirB, "", nil, "logout")); r.code != 0 {
		t.Fatalf("logout: (%d, %q)", r.code, r.stderr)
	}
	e.release("sync") // the sync now fails and its CLI "logs itself out"
	sync.Wait()
	if strings.Contains(syncErr.String(), "restored") {
		t.Errorf("the guard claims a restore: %s", syncErr.String())
	}
	if e.data() != fakeLoggedOut {
		t.Errorf("the logout was undone on disk: %s", e.data())
	}
	e.mustRefuse("after logout and the late sync", e.dirA)
}

// Without an explicit session command, the same late sync IS restored
// (control for the test above).
func TestRestoreAfterSelfLogout(t *testing.T) {
	e := newFakeEnv(t)
	before := e.data()
	e.release("sync")
	r := e.run(e.cmd(e.dirA, e.session, nil, "sync"))
	if r.code != 1 || !strings.Contains(r.stderr, "Hold mode restored the local vault") || e.data() != before {
		t.Errorf("sync: (%d, %q), data restored: %v", r.code, r.stderr, e.data() == before)
	}
}

// A read that arrives while a logout is running, before the real CLI has
// cleared the vault: access was revoked when the logout began, so the read
// gets nothing, neither from a daemon (none may load now) nor from the real
// CLI (which would still answer). After the logout nothing answers either.
func TestReadDuringLogout(t *testing.T) {
	e := newFakeEnv(t)
	logout := e.cmd(e.dirB, "", nil, "logout")
	var out bytes.Buffer
	logout.Stdout = &out
	if err := logout.Start(); err != nil {
		t.Fatal(err)
	}
	e.started("logout") // past its sweep, inside the real CLI, vault not cleared yet

	e.mustBlock("while the logout runs", e.dirA, "get", "password", "x")
	if d := e.daemons(); len(d) != 0 {
		t.Errorf("a daemon was started while the logout was running: %+v", d)
	}

	e.release("logout")
	if err := logout.Wait(); err != nil || out.String() != "You have logged out." {
		t.Fatalf("logout: %v, output %q", err, out.String())
	}
	if e.access() != accessOpen {
		t.Errorf("access after a successful logout: %s", e.access())
	}
	e.mustRefuse("after the logout returned", e.dirA)
}

// A new generation alone ends cached access; no sweep has to find the daemon.
func TestGenerationVoidsCache(t *testing.T) {
	t.Run("asked", func(t *testing.T) {
		e := newFakeEnv(t)
		pid := e.cached(e.dirA)
		if err := e.co.newGeneration(); err != nil { // a session command began somewhere; its sweep missed this daemon
			t.Fatal(err)
		}
		e.write(fakeLoggedOut)
		e.mustRefuse("after a generation change", e.dirA)
		e.waitUntil("the old daemon to exit", func() bool { return !alive(pid) })
	})
	t.Run("nobody asks: the idle daemon wipes itself", func(t *testing.T) {
		e := newFakeEnv(t)
		pid := e.cached(e.dirA)
		if err := e.co.newGeneration(); err != nil {
			t.Fatal(err)
		}
		e.waitUntil("the idle daemon to exit", func() bool { return !alive(pid) && len(e.daemons()) == 0 })
	})
	t.Run("an operation that left the session valid costs one reload", func(t *testing.T) {
		e := newFakeEnv(t)
		pid := e.cached(e.dirA)
		op := testOp(t, e.co) // e.g. an unlock that then failed on a wrong password
		op.end()
		e.waitUntil("the old daemon to exit", func() bool { return !alive(pid) })
		if again := e.cached(e.dirA); again == pid {
			t.Error("the daemon from before the operation is still answering")
		}
		e.write(fakeLoggedOut) // later, an unrequested logout: holding works again
		if r := e.read(e.dirA); r.code != 0 || r.stdout != "pw1" {
			t.Errorf("not held after a later, unrequested logout: (%d, %q)", r.code, r.stdout)
		}
	})
	t.Run("no coordination possible, no cache", func(t *testing.T) {
		// A root where the wrapper never could record anything (read-only):
		// nothing to violate, so the real CLI answers; nothing is cached.
		e := newFakeEnv(t)
		os.RemoveAll(e.co.dir)
		if err := os.Chmod(e.root, 0o500); err != nil {
			t.Fatal(err)
		}
		r := e.read(e.dirA)
		os.Chmod(e.root, 0o700)
		if r.code != 0 || r.stdout != "pw1" {
			t.Fatalf("read: (%d, %q, %q)", r.code, r.stdout, r.stderr)
		}
		if _, err := os.Stat(e.co.dir); err == nil {
			t.Fatal("test setup: the coordination directory was created")
		}
		os.MkdirAll(filepath.Join(e.co.dir, "daemons"), 0o700)
		if d := e.daemons(); len(d) != 0 {
			t.Errorf("a daemon was started without coordination state: %+v", d)
		}
	})
}

// If the coordination state cannot be used, lock still locks, but does not
// claim that cached access everywhere is over.
func TestLockWithoutCoordination(t *testing.T) {
	e := newFakeEnv(t)
	e.cached(e.dirA)
	if err := os.Chmod(e.co.dir, 0o755); err != nil { // no longer private: refused
		t.Fatal(err)
	}
	e.release("lock")
	r := e.run(e.cmd(e.dirA, "", nil, "lock"))
	os.Chmod(e.co.dir, 0o700)
	if e.data() != fakeLocked || r.stdout != "Your vault is locked." {
		t.Errorf("the real lock did not run: stdout %q, data %s", r.stdout, e.data())
	}
	if r.code == 0 || !strings.Contains(r.stderr, "could not coordinate") {
		t.Errorf("lock reported success without coordination: (%d, %q)", r.code, r.stderr)
	}
	// the daemon in the same runtime directory was still reached (best effort) ...
	if pids := e.loaded(); len(pids) != 0 {
		t.Errorf("daemon(s) %v still hold the vault", pids)
	}
	// ... and whatever else there is refuses once it sees the locked vault
	e.mustRefuse("after the uncoordinated lock", e.dirA)
}

// Interruption during a session operation: a logout must not queue behind an
// unlock sitting at its prompt, and must not return while that unlock could
// still rewrite the session.
func TestLogoutCancelsUnlock(t *testing.T) {
	e := newFakeEnv(t)
	unlock := e.cmd(e.dirA, "", nil, "unlock")
	var unlockOut, unlockErr bytes.Buffer
	unlock.Stdout, unlock.Stderr = &unlockOut, &unlockErr
	if err := unlock.Start(); err != nil {
		t.Fatal(err)
	}
	e.started("unlock") // the real CLI is "at its password prompt"
	child := e.fakePid("unlock")

	e.release("logout")
	r := e.run(e.cmd(e.dirB, "", nil, "logout"))
	if r.code != 0 || r.stdout != "You have logged out." {
		t.Fatalf("logout: (%d, %q, %q)", r.code, r.stdout, r.stderr)
	}
	// logout has returned: the unlock and its real CLI must be gone already
	if alive(child) {
		t.Error("the unlock's real CLI was still running when logout returned")
	}
	err := unlock.Wait()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 128+int(syscall.SIGTERM) {
		t.Errorf("the cancelled unlock exited with %v", err)
	}
	if !strings.Contains(unlockErr.String(), "cancelled by a lock or logout") || strings.Contains(unlockOut.String(), e.newSession) {
		t.Errorf("unlock output: %q / %q", unlockOut.String(), unlockErr.String())
	}
	if e.data() != fakeLoggedOut {
		t.Errorf("after logout the data file is: %s", e.data())
	}
	if m, _ := e.co.mark(); m.active {
		t.Error("a session operation is still marked active")
	}
}

// A wrapper process killed in the middle of a session operation: the
// operation stays active for as long as its real CLI lives, because that
// child inherited the lock.
func TestKilledSessionOperation(t *testing.T) {
	e := newFakeEnv(t)
	pid := e.cached(e.dirA)
	unlock := e.cmd(e.dirA, "", nil, "unlock")
	if err := unlock.Start(); err != nil {
		t.Fatal(err)
	}
	e.started("unlock")
	e.waitUntil("the old session's daemon to wipe itself", func() bool { return !alive(pid) })

	unlock.Process.Kill() // SIGKILL: no cleanup of any kind
	unlock.Wait()
	child := e.fakePid("unlock")
	if !alive(child) {
		t.Fatal("test setup: the stand-in unlock should still be running")
	}
	if m, _ := e.co.mark(); !m.active {
		t.Fatal("the operation ended with the wrapper although its real CLI is still running")
	}
	if r := e.read(e.dirA); r.code != 0 || len(e.loaded()) != 0 { // answered by the real CLI, cached by nobody
		t.Errorf("read during the orphaned operation: code %d, loaded daemons %v", r.code, e.loaded())
	}
	if op, _ := e.co.tryBeginOp("lock"); op != nil {
		op.end()
		t.Error("another session operation could begin while the orphaned real CLI is running")
	}

	e.release("unlock") // the orphaned real CLI finishes its unlock
	e.waitUntil("the orphaned real CLI to exit", func() bool { return !alive(child) })
	e.waitUntil("the operation to end with it", func() bool { m, _ := e.co.mark(); return !m.active })
	e.session = e.newSession
	e.cached(e.dirA) // and the new session can be cached normally
}

// Debug output and the daemon log must not contain command-line arguments:
// they can be master passwords, session keys or payloads.
func TestDebugOutputHasNoArguments(t *testing.T) {
	e := newFakeEnv(t)
	const secret = "hunter2-Master-Passw0rd"
	debug := []string{"BWW_DEBUG=1"}
	for _, name := range []string{"logout", "lock", "unlock", "sync"} {
		e.release(name)
	}
	invocations := []struct {
		env  []string
		args []string
	}{
		{debug, []string{"unlock", secret}},
		{debug, []string{"unlock", secret, "--raw"}},
		{append([]string{"BWW_DISABLE=1"}, debug...), []string{"unlock", secret}},
		{debug, []string{"login", "user@example.test", secret}},
		{debug, []string{"--session", secret, "get", "password", "x"}},
		{debug, []string{"get", "password", secret}},
		{debug, []string{"get", "item", secret, "--session=" + secret}},
		{debug, []string{"list", "items", "--url", "https://user:" + secret + "@example.test"}},
		{debug, []string{"list", "items", "--search", secret}},
		{debug, []string{"sync", "--session", secret}},
		{debug, []string{"lock", secret}},
		{append([]string{"BWW_ALLOW_WRITES=1"}, debug...), []string{"create", "item", secret}},
		{debug, []string{"create", "item", secret}},
		{debug, []string{"generate", "--" + secret}},
	}
	sawDebug := false
	for _, inv := range invocations {
		r := e.run(e.cmd(e.dirA, e.session, inv.env, inv.args...))
		if strings.Contains(r.stderr, secret) || strings.Contains(r.stdout, secret) {
			t.Errorf("bw %v: an argument was printed:\nstdout: %s\nstderr: %s", inv.args, r.stdout, r.stderr)
		}
		sawDebug = sawDebug || strings.Contains(r.stderr, "bw-wrapper: ")
	}
	if !sawDebug {
		t.Error("test setup: no debug output was produced at all")
	}
	for _, dir := range []string{e.dirA, e.dirB} {
		if log, _ := os.ReadFile(filepath.Join(dir, "daemon.log")); bytes.Contains(log, []byte(secret)) || bytes.Contains(log, []byte(e.session)) {
			t.Errorf("the daemon log in %s contains an argument or the session key", dir)
		}
	}
}

// The unauthenticated info request must not carry vault data or the session
// key, and nothing in the coordination directory is a credential.
func TestInfoShowsNoSecrets(t *testing.T) {
	e := newFakeEnv(t)
	e.cached(e.dirA)
	b, _ := json.Marshal(e.daemons())
	if strings.Contains(string(b), "pw1") || strings.Contains(string(b), e.session) {
		t.Errorf("daemon info leaks secrets: %s", b)
	}
	filepath.Walk(e.co.dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			if c, _ := os.ReadFile(p); bytes.Contains(c, []byte(e.session)) || bytes.Contains(c, []byte("pw1")) {
				t.Errorf("%s contains a credential", p)
			}
		}
		return nil
	})
}

// Two unlocks followed by a lock: the unlock that was waiting must not open
// the vault after the lock has completed.
func TestQueuedUnlockCannotUndoLock(t *testing.T) {
	e := newFakeEnv(t)
	a := e.cmd(e.dirA, "", nil, "unlock")
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	e.started("unlock") // unlock A is "at its password prompt"

	bErrPath := filepath.Join(e.fake, "unlock-b.stderr")
	bErr, _ := os.Create(bErrPath)
	b := e.cmd(e.dirB, "", nil, "unlock")
	var bOut bytes.Buffer
	b.Stdout, b.Stderr = &bOut, bErr
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	e.waitUntil("unlock B to queue behind A", func() bool {
		c, _ := os.ReadFile(bErrPath)
		return bytes.Contains(c, []byte("waiting for another"))
	})

	e.release("lock")
	if r := e.run(e.cmd(e.dirA, "", nil, "lock")); r.code != 0 || r.stdout != "Your vault is locked." {
		t.Fatalf("lock: (%d, %q, %q)", r.code, r.stdout, r.stderr)
	}
	// The lock has completed. If B were to run the real unlock now, nothing
	// would stop it: open its barrier and see that it never gets there.
	e.release("unlock")
	a.Wait()
	bErrWait := b.Wait()
	bErr.Close()
	if ee, ok := bErrWait.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
		t.Errorf("the queued unlock exited with %v, want 1", bErrWait)
	}
	if c, _ := os.ReadFile(bErrPath); !bytes.Contains(c, []byte("cancelled")) || strings.Contains(bOut.String(), e.newSession) {
		t.Errorf("the queued unlock: stdout %q, stderr %q", bOut.String(), c)
	}
	if n := e.runs("unlock"); n != 1 {
		t.Errorf("the real unlock ran %d times; only A's (cancelled) run is allowed", n)
	}
	if e.data() != fakeLocked {
		t.Errorf("the vault is not locked after a successful lock: %s", e.data())
	}
	if m, _ := e.co.mark(); m.Access != accessOpen || m.active {
		t.Errorf("state after the lock: %+v", m)
	}
	// a fresh unlock, requested after the lock, works
	if r := e.run(e.cmd(e.dirB, "", nil, "unlock")); r.code != 0 || !strings.Contains(r.stdout, e.newSession) {
		t.Errorf("a fresh unlock after the lock: (%d, %q, %q)", r.code, r.stdout, r.stderr)
	}
}

// The real lock command fails before it invalidates the session: the wrapper
// must not hand out anything for that root any more, from any shell, in any
// later process, until a lock succeeds or a new unlock is made.
func TestFailedLockBlocksAccess(t *testing.T) {
	e := newFakeEnv(t)
	e.cached(e.dirA)
	unlocked := e.data()
	os.WriteFile(filepath.Join(e.fake, "lock-fail"), nil, 0o600)
	e.release("lock")
	r := e.run(e.cmd(e.dirA, "", nil, "lock"))
	if r.code == 0 || !strings.Contains(r.stderr, "stays blocked") {
		t.Fatalf("a failed lock must fail loudly: (%d, %q)", r.code, r.stderr)
	}
	if e.data() != unlocked || e.access() != accessBlocked {
		t.Fatalf("test setup: data changed=%v access=%s", e.data() != unlocked, e.access())
	}
	// The session is still valid for the real CLI. Through the wrapper it is not.
	e.mustBlock("same shell", e.dirA, "get", "password", "x")
	e.mustBlock("another runtime directory", e.dirB, "get", "password", "x")
	e.mustBlock("list", e.dirA, "list", "items")
	e.mustBlock("sync", e.dirA, "sync")
	e.mustBlock("export", e.dirA, "export")
	if d := e.daemons(); len(d) != 0 {
		t.Errorf("daemons after a failed lock: %+v", d)
	}
	// commands that need no vault are not affected
	if e.run(e.cmd(e.dirA, e.session, nil, "generate")); e.runs("generate") != 1 {
		t.Error("`generate` was not handed to the real CLI")
	}
	// an unlock requested before the failed lock cannot reopen (unit-tested in
	// TestRevocationState); a lock that then succeeds does
	os.Remove(filepath.Join(e.fake, "lock-fail"))
	if r := e.run(e.cmd(e.dirB, "", nil, "lock")); r.code != 0 || e.data() != fakeLocked || e.access() != accessOpen {
		t.Fatalf("the repeated lock: (%d, %q), access %s", r.code, r.stderr, e.access())
	}
	before := e.runs("get")
	if r := e.read(e.dirA); r.code != 1 || !strings.Contains(r.stdout, "Vault is locked.") || e.runs("get") != before+1 {
		t.Errorf("after a successful lock the real CLI answers again: (%d, %q)", r.code, r.stdout)
	}
}

func TestUnlockReopensAfterFailedLock(t *testing.T) {
	e := newFakeEnv(t)
	os.WriteFile(filepath.Join(e.fake, "lock-fail"), nil, 0o600)
	e.release("lock")
	e.run(e.cmd(e.dirA, "", nil, "lock"))
	e.mustBlock("after the failed lock", e.dirA, "get", "password", "x")
	e.release("unlock")
	if r := e.run(e.cmd(e.dirA, "", nil, "unlock")); r.code != 0 || e.access() != accessOpen {
		t.Fatalf("a fresh unlock: (%d, %q), access %s", r.code, r.stderr, e.access())
	}
	e.session = e.newSession
	e.cached(e.dirA)
}

// The same failure through auto-lock: the idle limit must not silently
// become "cache evicted".
func TestFailedAutoLockBlocksAccess(t *testing.T) {
	e := newFakeEnv(t)
	os.WriteFile(filepath.Join(e.fake, "lock-fail"), nil, 0o600)
	e.release("lock")
	idle := []string{"BWW_AUTO_LOCK=1"}
	if r := e.run(e.cmd(e.dirA, e.session, idle, "get", "password", "x")); r.code != 0 {
		t.Fatalf("read: (%d, %q)", r.code, r.stderr)
	}
	e.waitUntil("the auto-lock to give up", func() bool { return e.access() == accessBlocked })
	if n := e.runs("lock"); n != 3 {
		t.Errorf("the real lock ran %d times, want 3 (one plus two retries)", n)
	}
	e.waitUntil("the daemon to be gone", func() bool { return len(e.daemons()) == 0 })
	e.mustBlock("old session after a failed auto-lock", e.dirA, "get", "password", "x")
	e.mustBlock("old session, other runtime directory", e.dirB, "list", "items")
}

// The wrapper is killed in the middle of a lock.
func TestKilledLock(t *testing.T) {
	for name, lockFails := range map[string]bool{"the real lock then succeeds": false, "the real lock then fails": true} {
		t.Run(name, func(t *testing.T) {
			e := newFakeEnv(t)
			e.cached(e.dirA)
			if lockFails {
				os.WriteFile(filepath.Join(e.fake, "lock-fail"), nil, 0o600)
			}
			lock := e.cmd(e.dirA, "", nil, "lock")
			if err := lock.Start(); err != nil {
				t.Fatal(err)
			}
			e.started("lock") // revoked, caches wiped, the real lock is running
			lock.Process.Kill()
			lock.Wait()
			if m, _ := e.co.mark(); m.Access != accessRevoking || !m.active {
				t.Fatalf("state with the wrapper dead and its real lock alive: %+v", m)
			}
			e.mustBlock("while the orphaned lock runs", e.dirA, "get", "password", "x")

			child := e.fakePid("lock")
			e.release("lock")
			e.waitUntil("the orphaned real lock to exit", func() bool { return !alive(child) })
			e.waitUntil("the operation to end", func() bool { m, _ := e.co.mark(); return !m.active })
			// Nobody recorded the outcome. What counts is what is on disk.
			if lockFails {
				e.mustBlock("the lock failed and nobody recorded it", e.dirA, "get", "password", "x")
				e.mustBlock("in a later process, another shell", e.dirB, "list", "items")
			} else {
				before := e.runs("get")
				if r := e.read(e.dirA); r.code != 1 || !strings.Contains(r.stdout, "Vault is locked.") || e.runs("get") != before+1 {
					t.Errorf("the lock succeeded on disk: the real CLI should answer 'locked': (%d, %q, %q)", r.code, r.stdout, r.stderr)
				}
			}
		})
	}
}

// Stop succeeds only if every daemon in its scope confirmed its wipe.
func TestStopReportsFailures(t *testing.T) {
	e := newFakeEnv(t)
	pid := e.cached(e.dirA) // a responsive daemon
	// ... and one that accepts connections and never answers
	hung := filepath.Join(e.dirA, "hung.sock")
	ln, err := net.Listen("unix", hung)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	writeAtomic(e.co.entry("hung-daemon"), []byte(hung))

	stop := exec.Command(os.Args[0], "__admin", "stop")
	stop.Env = append(append([]string(nil), e.env...), "BWW_RUNTIME_DIR="+e.dirA, "BWW_TEST_STOP_WAIT=300ms")
	r := e.run(stop)
	if r.code == 0 {
		t.Errorf("stop reported success although a daemon did not confirm")
	}
	if !strings.Contains(r.stdout, "stopped 1 daemon(s), 1 FAILED") || !strings.Contains(r.stdout, "scope: ") || !strings.Contains(r.stdout, "not covered") {
		t.Errorf("stop output: %q", r.stdout)
	}
	if !strings.Contains(r.stderr, hung) {
		t.Errorf("the daemon that failed is not named: %q", r.stderr)
	}
	e.waitUntil("the responsive daemon to be gone", func() bool { return !alive(pid) })
	// with only stoppable daemons left, stop succeeds
	ln.Close()
	os.Remove(e.co.entry("hung-daemon"))
	e.cached(e.dirA)
	stop = exec.Command(os.Args[0], "__admin", "stop")
	stop.Env = append(append([]string(nil), e.env...), "BWW_RUNTIME_DIR="+e.dirA)
	if r := e.run(stop); r.code != 0 || !strings.Contains(r.stdout, "stopped 1 daemon(s)\n") {
		t.Errorf("stop with a responsive daemon: (%d, %q, %q)", r.code, r.stdout, r.stderr)
	}
}

// Installation stops when the installed version's daemons cannot be stopped.
func TestInstallAbortsWhenStopFails(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not available")
	}
	bindir := t.TempDir()
	stub := filepath.Join(bindir, "bw-wrapper")
	const old = "#!/bin/sh\n# the installed version; one of its daemons cannot be stopped\n[ \"$1\" = stop ] && { echo 'stopped 0 daemon(s), 1 FAILED'; exit 1; }\n"
	os.WriteFile(stub, []byte(old), 0o755)
	// -o: do not rebuild the binary for this test
	mk := exec.Command("make", "-o", "bw-wrapper", "install", "BINDIR="+bindir)
	out, err := mk.CombinedOutput()
	if err == nil {
		t.Errorf("make install succeeded although stop failed:\n%s", out)
	}
	if now, _ := os.ReadFile(stub); string(now) != old {
		t.Error("the installed binary was replaced although its daemons could not be stopped")
	}
	if _, err := os.Lstat(filepath.Join(bindir, "bw")); err == nil {
		t.Error("the bw link was installed")
	}
}

// Everything that depends on the caller's environment is fixed before the
// daemon detaches.
func TestSubprocessBoundary(t *testing.T) {
	t.Run("a relative real CLI path works for the daemon too", func(t *testing.T) {
		e := newFakeEnv(t)
		c := e.cmd(e.dirA, e.session, []string{"BWW_REAL_BW=./bw"}, "get", "password", "x")
		c.Dir = e.fake
		if r := e.run(c); r.code != 0 || r.stdout != "pw1" {
			t.Fatalf("read: (%d, %q, %q)", r.code, r.stdout, r.stderr)
		}
		e.waitUntil("the daemon (working directory /) to load through the relative path", func() bool { return len(e.loaded()) == 1 })
	})
	t.Run("the wrapper is not accepted as the real CLI", func(t *testing.T) {
		e := newFakeEnv(t)
		r := e.run(e.cmd(e.dirA, e.session, []string{"BWW_REAL_BW=" + os.Args[0]}, "get", "password", "x"))
		if r.code != 127 || !strings.Contains(r.stderr, "bw-wrapper itself") {
			t.Errorf("self-reference: (%d, %q)", r.code, r.stderr)
		}
	})
	t.Run("what the daemon's children see", func(t *testing.T) {
		e := newFakeEnv(t)
		const master, cloud = "synthetic-master-pw-1", "synthetic-cloud-secret-2"
		extra := []string{
			"BWW_MASTER_PASSWORD=" + master, // under the wrapper's own prefix, and named in pass_env below
			"AWS_SECRET_ACCESS_KEY=" + cloud, "EXTRA_OK=fine",
			"BWW_PASS_ENV=BWW_TEST_FAKE_DIR,BWW_TEST_TICK,EXTRA_OK,BWW_MASTER_PASSWORD",
		}
		e.release("unlock")
		if r := e.run(e.cmd(e.dirA, "", extra, "unlock", "--passwordenv", "BWW_MASTER_PASSWORD")); r.code != 0 {
			t.Fatalf("unlock: (%d, %q)", r.code, r.stderr)
		}
		e.session = e.newSession
		e.cached(e.dirA) // the daemon this unlock started has loaded through the stand-in CLI
		// control: the client's own child, the real unlock, needs the password variable and has it
		if envs := e.childEnvs("unlock"); len(envs) != 1 || !strings.Contains(envs[0], master) {
			t.Fatalf("test setup: the real unlock should have seen the password variable")
		}
		daemonChildren := append(e.childEnvs("list"), e.childEnvs("status")...)
		if len(daemonChildren) < 5 {
			t.Fatalf("test setup: only %d daemon-side CLI runs recorded", len(daemonChildren))
		}
		for _, env := range daemonChildren {
			for _, secret := range []string{master, cloud} {
				if strings.Contains(env, secret) {
					t.Errorf("a daemon-side CLI run saw %q", secret)
				}
			}
			for _, want := range []string{"EXTRA_OK=fine", "BITWARDENCLI_APPDATA_DIR=" + e.root, "BW_SESSION=" + e.newSession, "BW_NOINTERACTION="} {
				if !strings.Contains(env, want) && want != "BW_NOINTERACTION=" {
					t.Errorf("a daemon-side CLI run lacks %s", want)
				}
			}
			for _, unwanted := range []string{"BWW_HOLD=", "BWW_REAL_BW=", "BWW_AUTO_LOCK=", "BWW_DAEMON="} {
				if strings.Contains(env, unwanted) {
					t.Errorf("a daemon-side CLI run inherited %s", unwanted)
				}
			}
		}
	})
}

// A command whose daemon goes away while it waits must not fall back to the
// real CLI with the old session once a lock has begun: the check made when
// the command started is long out of date by then.
func TestFallbackRechecksBlock(t *testing.T) {
	for _, hold := range []string{"BWW_HOLD=1", "BWW_HOLD=0"} { // the two ways the real CLI is started
		t.Run(hold, func(t *testing.T) { testFallbackRechecksBlock(t, hold) })
	}
}

func testFallbackRechecksBlock(t *testing.T, hold string) {
	e := newFakeEnv(t)
	unlocked := e.data()
	os.WriteFile(filepath.Join(e.fake, "load-hold"), nil, 0o600)
	os.WriteFile(filepath.Join(e.fake, "lock-fail"), nil, 0o600)
	e.release("lock")
	read := e.cmd(e.dirA, e.session, []string{hold}, "get", "password", "x")
	var out, errOut bytes.Buffer
	read.Stdout, read.Stderr = &out, &errOut
	if err := read.Start(); err != nil {
		t.Fatal(err)
	}
	e.started("load") // the read passed its first check and waits for its daemon
	if r := e.run(e.cmd(e.dirB, "", nil, "lock")); r.code == 0 {
		t.Fatalf("test setup: the lock was meant to fail: %q", r.stderr)
	}
	read.Wait()
	if e.data() != unlocked {
		t.Fatal("test setup: the session was meant to stay usable")
	}
	if out.Len() != 0 || !strings.HasPrefix(errOut.String(), "Vault is locked.") || e.runs("get") != 0 {
		t.Errorf("the read fell back to the real CLI after the lock began: (%q, %q), real get runs: %d", out.String(), errOut.String(), e.runs("get"))
	}
}

// A real-CLI run that got the session before the lock is waited for: when
// the lock runs (and so when it returns), that run is over.
func TestLockWaitsForRunningRead(t *testing.T) {
	for _, hold := range []string{"BWW_HOLD=1", "BWW_HOLD=0"} {
		t.Run(hold, func(t *testing.T) { testLockWaitsForRunningRead(t, hold) })
	}
}

func testLockWaitsForRunningRead(t *testing.T, hold string) {
	e := newFakeEnv(t)
	read := e.cmd(e.dirA, e.session, []string{hold}, "export")
	var out bytes.Buffer
	read.Stdout = &out
	if err := read.Start(); err != nil {
		t.Fatal(err)
	}
	e.started("export")
	lock := e.cmd(e.dirB, "", nil, "lock")
	if err := lock.Start(); err != nil {
		t.Fatal(err)
	}
	e.waitUntil("the lock to revoke", func() bool { return e.access() == accessRevoking })
	time.Sleep(300 * time.Millisecond) // a lock that does not wait would have started the real command by now
	if e.runs("lock") != 0 {
		t.Fatal("the real lock ran while a real-CLI read with the old session was still running")
	}
	e.mustBlock("a new read during the wait", e.dirA, "export")
	e.release("export")
	read.Wait()
	if out.String() != "exported pw1" {
		t.Fatalf("the read that was waited for gave %q", out.String())
	}
	e.release("lock")
	if err := lock.Wait(); err != nil || e.data() != fakeLocked || e.access() != accessOpen {
		t.Fatalf("lock: %v, access %s", err, e.access())
	}
}

// A real-CLI run that does not end is stopped; the lock is not held up for
// good and nothing is printed after it.
func TestLockStopsHangingRead(t *testing.T) {
	e := newFakeEnv(t)
	read := e.cmd(e.dirA, e.session, nil, "export")
	var out bytes.Buffer
	read.Stdout = &out
	if err := read.Start(); err != nil {
		t.Fatal(err)
	}
	e.started("export")
	pid := e.fakePid("export")
	e.release("lock")
	r := e.run(e.cmd(e.dirB, "", []string{"BWW_TEST_USE_DRAIN=100ms"}, "lock"))
	if r.code != 0 || e.data() != fakeLocked || e.access() != accessOpen {
		t.Fatalf("lock: (%d, %q), access %s", r.code, r.stderr, e.access())
	}
	e.waitUntil("the hanging real CLI to be gone", func() bool { return !alive(pid) })
	read.Wait()
	if out.Len() != 0 {
		t.Errorf("the stopped read still printed %q", out.String())
	}
}

// Without a runtime directory there is no daemon, but login and unlock still
// follow the session protocol.
func TestUnlockWithoutRuntimeDir(t *testing.T) {
	e := newFakeEnv(t)
	noDir := filepath.Join(e.fake, "bw", "run") // below a regular file: cannot exist
	os.WriteFile(filepath.Join(e.fake, "lock-fail"), nil, 0o600)
	e.release("lock")
	e.run(e.cmd(e.dirA, "", nil, "lock"))
	if e.access() != accessBlocked {
		t.Fatalf("test setup: access %s", e.access())
	}
	e.release("unlock")
	gen, _ := e.co.mark()
	r := e.run(e.cmd(noDir, "", nil, "unlock"))
	now, _ := e.co.mark()
	if r.code != 0 || !strings.Contains(r.stdout, e.newSession) {
		t.Fatalf("unlock: (%d, %q, %q)", r.code, r.stdout, r.stderr)
	}
	if now.Access != accessOpen || now.Gen == gen.Gen {
		t.Errorf("the unlock bypassed the protocol: access %s, new generation: %v", now.Access, now.Gen != gen.Gen)
	}
	if d := e.daemons(); len(d) != 0 {
		t.Errorf("daemons without a runtime directory: %+v", d)
	}
}

func (e *fakeEnv) flag(name string)   { os.WriteFile(filepath.Join(e.fake, name), nil, 0o600) }
func (e *fakeEnv) unflag(name string) { os.Remove(filepath.Join(e.fake, name)) }

// failedLock leaves the root the way a lock that did not work leaves it:
// the session still usable on disk, access blocked.
func (e *fakeEnv) failedLock() {
	e.t.Helper()
	e.flag("lock-fail")
	e.release("lock")
	e.run(e.cmd(e.dirA, "", nil, "lock"))
	e.unflag("lock-fail")
	if e.access() != accessBlocked || e.data() != sealedState(e.session) {
		e.t.Fatalf("test setup: access %s after the failed lock", e.access())
	}
}

// Finding 1. What a session command achieved is read from the session state,
// not from its exit code: a login or unlock that did not create a new
// session opens nothing, in whatever output mode it "succeeds".
func TestUnverifiedUnlockCannotReopen(t *testing.T) {
	modes := map[string]struct {
		env  []string
		args []string
		json bool
	}{
		"BW_CLEANEXIT":           {[]string{"BW_CLEANEXIT=true"}, []string{"login"}, false},
		"--cleanexit":            {nil, []string{"login", "--cleanexit"}, false},
		"--quiet --cleanexit":    {nil, []string{"unlock", "--quiet", "--cleanexit"}, false},
		"--response --cleanexit": {nil, []string{"login", "--response", "--cleanexit"}, true},
		"BW_RESPONSE BW_QUIET":   {[]string{"BW_RESPONSE=true", "BW_QUIET=true", "BW_CLEANEXIT=1"}, []string{"unlock"}, true},
		"--raw --cleanexit":      {nil, []string{"unlock", "--raw", "--cleanexit"}, false},
	}
	for name, m := range modes {
		t.Run("exit 0 without a new session/"+name, func(t *testing.T) {
			e := newFakeEnv(t)
			e.failedLock()
			e.flag("unlock-noop")
			if m.json {
				e.flag("unlock-noop-json")
			}
			e.release("unlock")
			r := e.run(e.cmd(e.dirA, "", m.env, m.args...))
			if r.code != 0 || e.runs(m.args[0]) != 1 {
				t.Fatalf("test setup: the stand-in was meant to exit 0: (%d, %q)", r.code, r.stderr)
			}
			if e.access() != accessBlocked {
				t.Fatalf("access is %s after a %s that created no session", e.access(), m.args[0])
			}
			e.mustBlock("after the unsuccessful "+m.args[0], e.dirA, "get", "password", "x")
			e.mustBlock("after the unsuccessful "+m.args[0], e.dirB, "export")
		})
	}
	t.Run("prints a session key that is not the one on disk", func(t *testing.T) {
		e := newFakeEnv(t)
		e.failedLock()
		e.flag("unlock-liar")
		e.release("unlock")
		if r := e.run(e.cmd(e.dirA, "", nil, "unlock")); r.code != 0 || !strings.Contains(r.stdout, e.newSession) {
			t.Fatalf("test setup: (%d, %q)", r.code, r.stdout)
		}
		if e.access() != accessBlocked {
			t.Fatalf("access is %s after an unlock whose session is not on disk", e.access())
		}
		e.mustBlock("old session", e.dirA, "get", "password", "x")
		e.session = e.newSession
		e.mustBlock("the claimed session", e.dirA, "get", "password", "x")
	})
	t.Run("a real unlock reopens in every mode that shows the key", func(t *testing.T) {
		for _, args := range [][]string{{"unlock"}, {"unlock", "--raw"}, {"login", "--cleanexit"}} {
			e := newFakeEnv(t)
			e.failedLock()
			e.release("unlock")
			if r := e.run(e.cmd(e.dirA, "", nil, args...)); r.code != 0 || e.access() != accessOpen {
				t.Fatalf("%v: (%d, %q), access %s", args, r.code, r.stderr, e.access())
			}
			e.session = e.newSession
			e.cached(e.dirA)
		}
	})
}

// Finding 1, the lock side: a lock that exits 0 but leaves the session
// usable (as under --cleanexit) has failed.
func TestLockOutcomeIsReadFromTheSession(t *testing.T) {
	for _, extra := range [][]string{nil, {"BW_CLEANEXIT=true"}} {
		e := newFakeEnv(t)
		e.cached(e.dirA)
		e.flag("lock-noop")
		e.release("lock")
		r := e.run(e.cmd(e.dirA, "", extra, "lock"))
		if r.code == 0 || !strings.Contains(r.stderr, "stays blocked") || e.access() != accessBlocked {
			t.Fatalf("a lock that changed nothing: (%d, %q), access %s", r.code, r.stderr, e.access())
		}
		e.mustBlock("after the lock that changed nothing", e.dirA, "get", "password", "x")
	}
}

// Finding 3. A lock that has revoked keeps its place in the order of session
// commands, even before it holds the operation lock.
func TestPendingLockKeepsItsPlace(t *testing.T) {
	start := func(t *testing.T, c *exec.Cmd) (*exec.Cmd, *lockedBuffer) {
		errOut := &lockedBuffer{}
		c.Stderr = errOut
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		return c, errOut
	}
	hooked := func(e *fakeEnv, name string) {
		e.t.Helper()
		e.waitUntil(name+" to be reached", func() bool { _, err := os.Stat(filepath.Join(e.fake, name+"-started")); return err == nil })
	}
	t.Run("a later unlock waits for the pending lock", func(t *testing.T) {
		e := newFakeEnv(t)
		e.cached(e.dirA)
		e.flag("revoked-hold")
		lock, _ := start(t, e.cmd(e.dirA, "", nil, "lock"))
		hooked(e, "revoked") // revoked, not yet holding the operation lock
		e.unflag("revoked-hold")
		e.release("unlock")
		unlock, _ := start(t, e.cmd(e.dirB, "", nil, "unlock")) // requested after the revocation
		time.Sleep(300 * time.Millisecond)                      // an unlock that does not wait would have run by now
		if e.runs("unlock") != 0 {
			t.Fatal("the unlock ran ahead of a lock that had already revoked")
		}
		e.mustBlock("while the lock is pending", e.dirA, "get", "password", "x")
		e.release("revoked")
		e.started("lock") // the lock is running its real command
		if e.runs("unlock") != 0 {
			t.Fatal("the unlock ran while the lock was running")
		}
		e.mustBlock("while the lock runs", e.dirB, "export")
		e.release("lock")
		if err := lock.Wait(); err != nil {
			t.Fatalf("lock: %v", err)
		}
		if err := unlock.Wait(); err != nil {
			t.Fatalf("the unlock requested after the lock: %v", err)
		}
		// lock first, unlock second: the order in which they were requested
		if e.data() != sealedState(e.newSession) || e.access() != accessOpen || e.runs("lock") != 1 || e.runs("unlock") != 1 {
			t.Fatalf("after lock then unlock: access %s, lock runs %d, unlock runs %d", e.access(), e.runs("lock"), e.runs("unlock"))
		}
		e.session = e.newSession
		e.cached(e.dirA)
	})
	t.Run("a competing lock does not end the first one's claim", func(t *testing.T) {
		e := newFakeEnv(t)
		e.cached(e.dirA)
		e.flag("revoked-hold")
		first, _ := start(t, e.cmd(e.dirA, "", nil, "lock"))
		hooked(e, "revoked")
		e.unflag("revoked-hold")
		e.release("unlock")
		unlock, unlockErr := start(t, e.cmd(e.dirB, "", nil, "unlock")) // after the first lock, before the second
		// "before the second" must be a fact, not a hope: the unlock has taken
		// note of the epoch once it says that it is waiting.
		e.waitUntil("the unlock to register and wait", func() bool { return strings.Contains(unlockErr.String(), "waiting for another") })
		e.release("lock")
		if r := e.run(e.cmd(e.dirB, "", nil, "lock")); r.code != 0 || e.data() != fakeLocked { // the competing lock runs to completion
			t.Fatalf("competing lock: (%d, %q)", r.code, r.stderr)
		}
		// It succeeded and recorded "open", but the first lock is still
		// pending: nothing is given out and no unlock begins.
		if m, _ := e.co.mark(); !e.co.blocked(m) {
			t.Fatalf("not blocked although the first lock is still pending: %+v", m)
		}
		e.write(sealedState(e.session)) // even if a session were usable again
		e.mustBlock("first lock still pending", e.dirA, "get", "password", "x")
		// The unlock was requested before the second lock: cancelled by it.
		if err := unlock.Wait(); err == nil || !strings.Contains(unlockErr.String(), "cancelled") || e.runs("unlock") != 0 {
			t.Fatalf("the unlock requested before the second lock: %v, %q, runs %d", err, unlockErr.String(), e.runs("unlock"))
		}
		e.release("revoked")
		if err := first.Wait(); err != nil {
			t.Fatalf("first lock: %v", err)
		}
		if e.data() != fakeLocked || e.runs("lock") != 2 {
			t.Fatalf("the first lock did not lock what was there: runs %d", e.runs("lock"))
		}
		if m, _ := e.co.mark(); e.co.blocked(m) || m.revoking {
			t.Fatalf("still blocked after both locks finished: %+v", m)
		}
	})
	t.Run("a pending lock whose process dies leaves a usable session blocked", func(t *testing.T) {
		e := newFakeEnv(t)
		e.flag("revoked-hold")
		lock, _ := start(t, e.cmd(e.dirA, "", nil, "lock"))
		hooked(e, "revoked")
		lock.Process.Kill()
		lock.Wait()
		if m, _ := e.co.mark(); m.revoking {
			t.Fatal("the dead lock is still pending")
		}
		e.mustBlock("after the lock died", e.dirA, "get", "password", "x")
		e.unflag("revoked-hold")
		e.release("unlock") // an unlock requested afterwards is not held up by it
		if r := e.run(e.cmd(e.dirA, "", nil, "unlock")); r.code != 0 || e.access() != accessOpen {
			t.Fatalf("unlock after the dead lock: (%d, %q), access %s", r.code, r.stderr, e.access())
		}
	})
}

// Finding 4. When the state cannot be established, the answer is no: for
// cached answers and for the real CLI alike.
func TestUnknownStateDenies(t *testing.T) {
	breakages := map[string]func(e *fakeEnv) (repair func()){
		"malformed state": func(e *fakeEnv) func() {
			os.WriteFile(e.co.path("state"), []byte(`{"gen":"x","epoch":"many"`), 0o600)
			return func() { os.Remove(e.co.path("state")) }
		},
		"state of an unknown shape": func(e *fakeEnv) func() {
			os.WriteFile(e.co.path("state"), []byte(`{"gen":"x","epoch":3,"access":"maybe"}`), 0o600)
			return func() { os.Remove(e.co.path("state")) }
		},
		"coordination directory without permission": func(e *fakeEnv) func() {
			os.Chmod(e.co.dir, 0)
			return func() { os.Chmod(e.co.dir, 0o700) }
		},
		"coordination directory open to others": func(e *fakeEnv) func() {
			os.Chmod(e.co.dir, 0o755)
			return func() { os.Chmod(e.co.dir, 0o700) }
		},
		"state file without permission": func(e *fakeEnv) func() {
			os.Chmod(e.co.path("state"), 0)
			return func() { os.Chmod(e.co.path("state"), 0o600) }
		},
		"metadata lock cannot be opened": func(e *fakeEnv) func() {
			os.Chmod(e.co.path("meta.lock"), 0)
			return func() { os.Chmod(e.co.path("meta.lock"), 0o600) }
		},
		"lease file cannot be opened": func(e *fakeEnv) func() {
			os.Remove(e.co.path("use.lock"))
			os.Mkdir(e.co.path("use.lock"), 0o700)
			return func() { os.Remove(e.co.path("use.lock")) }
		},
		"activity record cannot be written": func(e *fakeEnv) func() {
			os.RemoveAll(e.co.path("activity"))
			os.Mkdir(e.co.path("activity"), 0o500)
			return func() { os.Chmod(e.co.path("activity"), 0o700) }
		},
		"data lock cannot be opened": func(e *fakeEnv) func() {
			os.Remove(e.co.path("data.lock"))
			os.Mkdir(e.co.path("data.lock"), 0o700)
			return func() { os.Remove(e.co.path("data.lock")) }
		},
	}
	denied := func(e *fakeEnv, when string, args ...string) {
		e.t.Helper()
		e.release(args[0]) // if it does reach the stand-in CLI, it must not wait there
		before := e.runs(args[0])
		r := e.run(e.cmd(e.dirA, e.session, nil, args...))
		if r.code != 1 || r.stdout != "" || !strings.HasPrefix(r.stderr, "Vault is locked.") {
			e.t.Errorf("%s: bw %v gave (%d, %q, %q), want the wrapper's refusal", when, args, r.code, r.stdout, r.stderr)
		}
		if e.runs(args[0]) != before {
			e.t.Errorf("%s: bw %v was handed to the real CLI", when, args)
		}
	}
	for name, breakIt := range breakages {
		t.Run("after a failed lock/"+name, func(t *testing.T) {
			e := newFakeEnv(t)
			e.failedLock()
			repair := breakIt(e)
			defer repair()
			denied(e, name, "export")
			if name != "data lock cannot be opened" { // (get would be refused as blocked before it gets that far)
				denied(e, name, "get", "password", "x")
			}
			denied(e, name, "list", "items")
		})
		t.Run("with a vault in memory/"+name, func(t *testing.T) {
			e := newFakeEnv(t)
			e.cached(e.dirA)
			e.read(e.dirA) // every lock file exists
			repair := breakIt(e)
			defer repair()
			if name == "data lock cannot be opened" {
				denied(e, name, "export") // only the real-CLI path needs it
				return
			}
			denied(e, name, "get", "password", "x") // not from memory either
			denied(e, name, "export")
		})
	}
}

// Finding 5. A command that was admitted holds its lease until it has
// written its output, also when the answer came from a daemon: a lock waits
// for it or stops it, and nothing is written after the lock returns.
func TestLockStopsCachedOutput(t *testing.T) {
	e := newFakeEnv(t)
	os.WriteFile(filepath.Join(e.fake, "notes"), bytes.Repeat([]byte("n"), 400<<10), 0o600) // far more than a pipe holds
	e.cached(e.dirA)
	loads := e.runs("list")
	whole := e.run(e.cmd(e.dirA, e.session, nil, "list", "items"))
	if whole.code != 0 || len(whole.stdout) < 400<<10 || e.runs("list") != loads { // answered from memory
		t.Fatalf("test setup: list gave %d bytes (code %d), real list runs %d", len(whole.stdout), whole.code, e.runs("list"))
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	list := e.cmd(e.dirA, e.session, nil, "list", "items")
	list.Stdout = pw
	if err := list.Start(); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	first := make([]byte, 1)
	if _, err := pr.Read(first); err != nil { // the client has the answer and is writing it; the pipe is full
		t.Fatal(err)
	}
	e.release("lock")
	r := e.run(e.cmd(e.dirB, "", []string{"BWW_TEST_USE_DRAIN=100ms"}, "lock"))
	if r.code != 0 || e.data() != fakeLocked {
		t.Fatalf("lock: (%d, %q)", r.code, r.stderr)
	}
	// The lock has returned. Whatever is still in the pipe was written before
	// that; the writer is gone and nothing follows.
	if err := list.Process.Signal(syscall.Signal(0)); err == nil {
		if !zombie(list.Process.Pid) {
			t.Fatal("the client that was writing cached output is still running after the lock returned")
		}
	}
	rest, _ := io.ReadAll(pr)
	list.Wait()
	if got := 1 + len(rest); got >= len(whole.stdout) {
		t.Errorf("the whole answer (%d bytes) was written although the lock stopped the writer", got)
	}
}

func (e *fakeEnv) backdateActivity(by time.Duration) {
	e.t.Helper()
	then := time.Now().Add(-by)
	if err := os.Chtimes(e.co.activityFile(sessionTag(e.session)), then, then); err != nil {
		e.t.Fatal(err)
	}
}

// Finding 6. Idle expiry is decided at admission, against the root's clock,
// before the command renews it. A timer that has not run yet changes nothing.
func TestIdleExpiryAtAdmission(t *testing.T) {
	idle := []string{"BWW_AUTO_LOCK=60"}
	t.Run("a request after the deadline does not revive the session", func(t *testing.T) {
		e := newFakeEnv(t)
		e.flag("timer-hold") // the daemon's timer never gets to act
		if r := e.run(e.cmd(e.dirA, e.session, idle, "get", "password", "x")); r.code != 0 || r.stdout != "pw1" {
			t.Fatalf("read: (%d, %q)", r.code, r.stderr)
		}
		e.waitUntil("a daemon to hold the vault", func() bool { return len(e.loaded()) == 1 })
		e.backdateActivity(2 * time.Minute) // idle beyond the limit; the timer is held
		e.release("lock")
		r := e.run(e.cmd(e.dirA, e.session, idle, "get", "password", "x"))
		if r.code == 0 || strings.Contains(r.stdout, "pw1") {
			t.Fatalf("the expired session answered: (%d, %q)", r.code, r.stdout)
		}
		if e.runs("lock") != 1 || e.data() != fakeLocked {
			t.Errorf("the expired session was not locked: lock runs %d", e.runs("lock"))
		}
		if pids := e.loaded(); len(pids) != 0 {
			t.Errorf("daemon(s) %v still hold the vault", pids)
		}
	})
	t.Run("the same without any daemon", func(t *testing.T) {
		e := newFakeEnv(t)
		e.release("export")
		if r := e.run(e.cmd(e.dirA, e.session, idle, "export")); r.code != 0 { // admitted: the clock starts
			t.Fatalf("export: (%d, %q)", r.code, r.stderr)
		}
		e.backdateActivity(2 * time.Minute)
		e.release("lock")
		r := e.run(e.cmd(e.dirA, e.session, idle, "export"))
		if r.code == 0 || strings.Contains(r.stdout, "pw1") || e.runs("lock") != 1 || e.data() != fakeLocked {
			t.Fatalf("expired session through the real CLI: (%d, %q), lock runs %d", r.code, r.stdout, e.runs("lock"))
		}
		if envs := e.childEnvs("lock"); len(envs) != 1 || strings.Contains(envs[0], "BW_SESSION=") {
			t.Error("the automatic lock was given the session key")
		}
	})
	t.Run("an expired session whose lock fails stays blocked", func(t *testing.T) {
		e := newFakeEnv(t)
		e.release("export")
		e.run(e.cmd(e.dirA, e.session, idle, "export"))
		e.backdateActivity(2 * time.Minute)
		e.flag("lock-fail")
		e.release("lock")
		r := e.run(e.cmd(e.dirA, e.session, append(idle, "BWW_TEST_RETRY_PAUSE=1ms"), "export"))
		if r.code != 1 || !strings.HasPrefix(r.stderr, "Vault is locked.") || e.runs("export") != 1 || e.access() != accessBlocked {
			t.Fatalf("(%d, %q), export runs %d, access %s", r.code, r.stderr, e.runs("export"), e.access())
		}
	})
	t.Run("another session value cannot erase or renew the clock", func(t *testing.T) {
		e := newFakeEnv(t)
		e.release("export")
		e.run(e.cmd(e.dirA, e.session, idle, "export"))
		e.backdateActivity(2 * time.Minute)
		// a shell with a stale BW_SESSION, and one with garbage
		for _, other := range []string{e.newSession, "not-a-session"} {
			e.run(e.cmd(e.dirB, other, idle, "export"))
		}
		if last, known := e.co.activity(sessionTag(e.session)); !known || time.Since(last) < time.Minute {
			t.Fatalf("the idle session's clock was touched by another session value: %v (known: %v)", last, known)
		}
		e.release("lock")
		r := e.run(e.cmd(e.dirA, e.session, idle, "export"))
		if r.code == 0 || e.runs("lock") != 1 || e.data() != fakeLocked {
			t.Fatalf("the expired session was revived: (%d, %q), lock runs %d", r.code, r.stdout, e.runs("lock"))
		}
	})
	t.Run("idle time counts from the end of an answer, not from its admission", func(t *testing.T) {
		e := newFakeEnv(t)
		e.flag("load-hold") // a cold start that takes its time
		read := e.cmd(e.dirA, e.session, idle, "get", "password", "x")
		var out bytes.Buffer
		read.Stdout = &out
		if err := read.Start(); err != nil {
			t.Fatal(err)
		}
		e.started("load")                    // admitted long ago ...
		e.backdateActivity(50 * time.Second) // ... as far as the clock is concerned
		e.release("load")
		read.Wait()
		if out.String() != "pw1" {
			t.Fatalf("read: %q", out.String())
		}
		if last, known := e.co.activity(sessionTag(e.session)); !known || time.Since(last) > 10*time.Second {
			t.Errorf("after the answer the session counts as idle since %v ago", time.Since(last).Round(time.Second))
		}
	})
	t.Run("reads answered by the real CLI count as use", func(t *testing.T) {
		e := newFakeEnv(t)
		e.release("export")
		e.run(e.cmd(e.dirA, e.session, idle, "get", "password", "x"))
		e.waitUntil("a daemon to hold the vault", func() bool { return len(e.loaded()) == 1 })
		e.backdateActivity(45 * time.Second) // within the limit
		tag := sessionTag(e.session)
		if last, known := e.co.activity(tag); !known || time.Since(last) < 40*time.Second {
			t.Fatalf("test setup: last use %v (known: %v)", last, known)
		}
		if r := e.run(e.cmd(e.dirA, e.session, idle, "export")); r.code != 0 || e.runs("export") != 1 {
			t.Fatalf("export: (%d, %q)", r.code, r.stderr)
		}
		// The root's clock, which the daemon's timer reads (TestAutoLock), was renewed.
		if last, known := e.co.activity(tag); !known || time.Since(last) > 10*time.Second {
			t.Errorf("a read answered by the real CLI did not count as use: last use %v ago", time.Since(last))
		}
		if d := e.daemons(); len(d) != 1 || time.Since(time.Unix(d[0].LastUsed, 0)) > 10*time.Second {
			t.Errorf("the daemon does not see that use: %+v", d)
		}
		if e.runs("lock") != 0 {
			t.Error("the session was locked although it was in use")
		}
	})
}

// Finding 7. A reload that fails never makes the old vault "current": it is
// retried, hold mode keeps answering from the old one for at most hold_max,
// and when loading works again the new content is served.
func TestFailedReloadKeepsSnapshotStale(t *testing.T) {
	change := func(e *fakeEnv) {
		e.write(rev2State(e.session)) // the vault changed on disk, same session
		os.WriteFile(filepath.Join(e.fake, "password"), []byte("pw2"), 0o600)
	}
	held := func(e *fakeEnv) int64 {
		if d := e.daemons(); len(d) == 1 {
			return d[0].Held
		}
		return -1
	}
	t.Run("recovers once loading works again", func(t *testing.T) {
		e := newFakeEnv(t)
		e.cached(e.dirA)
		change(e)
		e.flag("load-fail")
		for i := 1; i <= 3; i++ {
			loads := e.runs("list")
			if r := e.read(e.dirA); r.code != 0 || r.stdout != "pw1" {
				t.Fatalf("read %d during the failure: (%d, %q), want the held old answer", i, r.code, r.stdout)
			}
			if e.runs("list") == loads {
				t.Fatalf("read %d did not try to reload: the old vault counts as current", i)
			}
			if held(e) <= 0 {
				t.Fatalf("read %d: the daemon does not report a held (not current) vault", i)
			}
		}
		e.unflag("load-fail")
		if r := e.read(e.dirA); r.code != 0 || r.stdout != "pw2" {
			t.Fatalf("after loading works again: (%d, %q), want the new content", r.code, r.stdout)
		}
		if held(e) != 0 {
			t.Error("still reported as held after a successful reload")
		}
	})
	t.Run("is given up at the hold limit", func(t *testing.T) {
		e := newFakeEnv(t)
		limit := []string{"BWW_HOLD_MAX=1"}
		if r := e.run(e.cmd(e.dirA, e.session, limit, "get", "password", "x")); r.stdout != "pw1" {
			t.Fatal("test setup")
		}
		e.waitUntil("a daemon to hold the vault", func() bool { return len(e.loaded()) == 1 })
		change(e)
		e.flag("load-fail")
		if r := e.run(e.cmd(e.dirA, e.session, limit, "get", "password", "x")); r.stdout != "pw1" {
			t.Fatalf("held answer: %q", r.stdout)
		}
		e.waitUntil("the daemon to give up the vault it cannot refresh", func() bool { return len(e.daemons()) == 0 })
	})
	t.Run("without hold mode the old vault is not served at all", func(t *testing.T) {
		e := newFakeEnv(t)
		off := []string{"BWW_HOLD=0"}
		e.run(e.cmd(e.dirA, e.session, off, "get", "password", "x"))
		e.waitUntil("a daemon to hold the vault", func() bool { return len(e.loaded()) == 1 })
		change(e)
		e.flag("load-fail")
		if r := e.run(e.cmd(e.dirA, e.session, off, "get", "password", "x")); r.stdout != "pw2" { // the real CLI answers
			t.Fatalf("got %q, want the real CLI's current answer", r.stdout)
		}
	})
}

// Finding 9. A hold-mode restore puts back the newest state a wrapper-run
// command left, never an older one: runs that may rewrite the data file do
// not overlap.
func TestRestoreCannotOverwriteNewerRevision(t *testing.T) {
	t.Run("a sync cannot slip in between snapshot and restore", func(t *testing.T) {
		e := newFakeEnv(t)
		e.flag("export-logout")
		e.flag("sync-ok")
		e.release("sync")
		failing := e.cmd(e.dirA, e.session, nil, "export") // snapshots revision 1, then its CLI logs out
		if err := failing.Start(); err != nil {
			t.Fatal(err)
		}
		e.started("export")
		sync := e.cmd(e.dirB, e.session, nil, "sync") // would write revision 2
		if err := sync.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		if e.runs("sync") != 0 {
			t.Fatal("a sync ran between another command's snapshot and its restore")
		}
		e.release("export")
		failing.Wait()
		if err := sync.Wait(); err != nil {
			t.Fatalf("sync: %v", err)
		}
		if e.data() != rev2State(e.session) {
			t.Fatalf("the newer revision was lost:\n%s", e.data())
		}
	})
	t.Run("a restore after a sync restores what the sync left", func(t *testing.T) {
		e := newFakeEnv(t)
		e.flag("sync-ok")
		e.release("sync")
		if r := e.run(e.cmd(e.dirA, e.session, nil, "sync")); r.code != 0 || e.data() != rev2State(e.session) {
			t.Fatalf("sync: (%d, %q)", r.code, r.stderr)
		}
		e.flag("export-logout")
		e.release("export")
		if r := e.run(e.cmd(e.dirB, e.session, nil, "export")); r.code == 0 {
			t.Fatal("test setup: the export was meant to fail")
		}
		if e.data() != rev2State(e.session) {
			t.Fatalf("not restored to the newest revision:\n%s", e.data())
		}
	})
	t.Run("a command without hold mode is ordered too", func(t *testing.T) {
		e := newFakeEnv(t)
		e.flag("export-logout")
		e.flag("sync-ok")
		e.release("sync")
		failing := e.cmd(e.dirA, e.session, nil, "export")
		if err := failing.Start(); err != nil {
			t.Fatal(err)
		}
		e.started("export")
		sync := e.cmd(e.dirB, e.session, []string{"BWW_HOLD=0"}, "sync")
		if err := sync.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		if e.runs("sync") != 0 {
			t.Fatal("a sync without hold mode ran between a snapshot and its restore")
		}
		e.release("export")
		failing.Wait()
		sync.Wait()
		if e.data() != rev2State(e.session) {
			t.Fatalf("the newer revision was lost:\n%s", e.data())
		}
	})
}

// With writes allowed, a line whose command cannot be told for certain is
// still not run: it could be a session command of a newer CLI.
func TestUncertainLineIsNotRun(t *testing.T) {
	e := newFakeEnv(t)
	allow := []string{"BWW_ALLOW_WRITES=1"}
	for _, args := range [][]string{{"--newflag", "logout"}, {"--newflag", "unlock"}, {"--newflag=x", "lock"}, {"brandnewcommand", "x"}, {"--", "--raw", "logout"}} {
		r := e.run(e.cmd(e.dirA, e.session, allow, args...))
		if r.code != 1 || !strings.Contains(r.stderr, "cannot tell which command") {
			t.Errorf("bw %v: (%d, %q)", args, r.code, r.stderr)
		}
	}
	if files, _ := filepath.Glob(filepath.Join(e.fake, "*-runs")); len(files) != 0 {
		t.Errorf("the real CLI was run: %v", files)
	}
	if e.data() != sealedState(e.session) {
		t.Error("the session changed")
	}
}

// The real CLI unlocks itself with BW_SESSION at startup, whatever the
// command, and stores the key again. So "prints nothing secret" is not
// "may be started freely": a process is given the session only as an
// admitted command, and then a lock waits for it or stops it.
func TestNoSessionWithoutAdmission(t *testing.T) {
	hasSession := func(env string) bool { return strings.Contains(env, "BW_SESSION=") }
	t.Run("help, version and local commands never get the session", func(t *testing.T) {
		e := newFakeEnv(t)
		e.flag("startup-hold") // a run that got the session would go through the startup unlock
		e.release("startup")   // (and must not wait there: the check below reports it)
		for _, args := range [][]string{{"--help"}, {"get", "--help"}, {"help", "get"}, {"--version"}, {"generate"}, {"config", "server"}, {"encode"}} {
			c := e.cmd(e.dirA, e.session, nil, args...)
			c.Stdin = strings.NewReader("")
			e.run(c)
			envs := e.childEnvs(args[0])
			if len(envs) != 1 || hasSession(envs[0]) {
				t.Errorf("bw %v: real CLI runs %d, got the session: %v", args, len(envs), len(envs) == 1 && hasSession(envs[0]))
			}
		}
		if _, err := os.Stat(filepath.Join(e.fake, "startup-started")); err == nil {
			t.Error("a run without admission went through the CLI's startup unlock")
		}
	})
	for _, args := range [][]string{{"status"}, {"unlock", "--check"}, {"login", "--check"}} {
		t.Run("a lock does not return while an admitted `"+strings.Join(args, " ")+"` is in its startup", func(t *testing.T) {
			e := newFakeEnv(t)
			e.flag("startup-hold")
			e.release("unlock")
			query := e.cmd(e.dirA, e.session, nil, args...) // admitted: gets the session, holds a lease
			if err := query.Start(); err != nil {
				t.Fatal(err)
			}
			e.started("startup") // it has read the stored key and is about to store it again
			pid := e.fakePid("startup")
			e.unflag("startup-hold")
			e.release("lock")
			r := e.run(e.cmd(e.dirB, "", []string{"BWW_TEST_USE_DRAIN=100ms"}, "lock"))
			if r.code != 0 || e.data() != fakeLocked {
				t.Fatalf("lock: (%d, %q)", r.code, r.stderr)
			}
			if alive(pid) {
				t.Fatal("the lock returned while the process holding the old key was still alive")
			}
			e.release("startup") // nobody is left to resume
			query.Wait()
			if e.data() != fakeLocked {
				t.Fatal("the old session was stored again after the lock completed")
			}
		})
	}
	t.Run("status that is not admitted runs without the session", func(t *testing.T) {
		e := newFakeEnv(t)
		e.failedLock()
		e.flag("startup-hold")
		e.release("startup")
		e.release("unlock") // (the stand-in does not know --check)
		for _, args := range [][]string{{"status"}, {"unlock", "--check"}} {
			e.run(e.cmd(e.dirA, e.session, nil, args...))
			if envs := e.childEnvs(args[0]); len(envs) != 1 || hasSession(envs[0]) {
				t.Errorf("bw %v while blocked: real CLI runs %d, got the session: %v", args, len(envs), len(envs) == 1 && hasSession(envs[0]))
			}
		}
		// given on the command line it cannot be withheld: refused
		if r := e.run(e.cmd(e.dirA, "", nil, "status", "--session", e.session)); r.code != 1 || !strings.HasPrefix(r.stderr, "Vault is locked.") || len(e.childEnvs("status")) != 1 {
			t.Errorf("status --session while blocked: (%d, %q)", r.code, r.stderr)
		}
	})
}

// A command with work to do after the real CLI (sync, writes) gets a child
// that returns, in every mode: the daemon has reloaded when sync returns.
func TestSyncReloadsBeforeReturning(t *testing.T) {
	for _, hold := range []string{"BWW_HOLD=0", "BWW_HOLD=1"} {
		t.Run(hold, func(t *testing.T) {
			e := newFakeEnv(t)
			mode := []string{hold}
			if r := e.run(e.cmd(e.dirA, e.session, mode, "get", "password", "x")); r.stdout != "pw1" {
				t.Fatal("test setup")
			}
			e.waitUntil("a daemon to hold the vault", func() bool { return len(e.loaded()) == 1 })
			e.flag("sync-ok") // the sync brings a new revision
			os.WriteFile(filepath.Join(e.fake, "password"), []byte("pw2"), 0o600)
			e.release("sync")
			loads := e.runs("list")
			if r := e.run(e.cmd(e.dirA, e.session, mode, "sync")); r.code != 0 || r.stdout != "Syncing complete." {
				t.Fatalf("sync: (%d, %q, %q)", r.code, r.stdout, r.stderr)
			}
			after := e.runs("list")
			if after == loads {
				t.Fatal("sync returned before the daemon reloaded")
			}
			if r := e.run(e.cmd(e.dirA, e.session, mode, "get", "password", "x")); r.stdout != "pw2" || e.runs("list") != after || e.runs("get") != 0 {
				t.Errorf("after sync: %q, further loads %d, real get runs %d", r.stdout, e.runs("list")-after, e.runs("get"))
			}
		})
	}
}

// The data lock belongs to the real-CLI processes, not to the daemon that
// started them: where no parent-death signal exists, a killed daemon leaves
// its child running, and that child still keeps other runs out.
func TestDaemonChildKeepsDataLock(t *testing.T) {
	e := newFakeEnv(t)
	e.env = append(e.env, "BWW_TEST_NO_PDEATHSIG=1")
	e.flag("load-hold")
	read := e.cmd(e.dirA, e.session, nil, "get", "password", "x")
	var out bytes.Buffer
	read.Stdout = &out
	if err := read.Start(); err != nil {
		t.Fatal(err)
	}
	e.started("load") // the daemon's loader child is in the middle of its run
	child := e.fakePid("load")
	d := e.daemons()
	if len(d) != 1 {
		t.Fatalf("test setup: daemons %v", d)
	}
	syscall.Kill(d[0].PID, syscall.SIGKILL)
	e.waitUntil("the daemon to be gone", func() bool { return !alive(d[0].PID) || zombie(d[0].PID) })
	if !alive(child) {
		t.Fatal("test setup: the child died with the daemon")
	}
	// The read falls back to the real CLI: a guarded run (hold mode) that
	// needs the data lock exclusively.
	time.Sleep(300 * time.Millisecond)
	if e.runs("get") != 0 {
		t.Fatal("another real-CLI run started while the dead daemon's child was still running")
	}
	e.release("load")
	read.Wait()
	if out.String() != "pw1" || e.runs("get") != 1 {
		t.Errorf("after the child exited: %q, real get runs %d", out.String(), e.runs("get"))
	}
}

// zombie reports whether a process has exited and is only waiting to be
// reaped (or is gone altogether).
func zombie(pid int) bool {
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		return bytes.Contains(b, []byte(") Z "))
	}
	out, _ := exec.Command("ps", "-o", "state=", "-p", strconv.Itoa(pid)).Output()
	state := strings.TrimSpace(string(out))
	return state == "" || strings.HasPrefix(state, "Z")
}

// The interaction matrix of docs/LIFECYCLE.md: every kind of real-CLI
// process against lock completion and against snapshot ordering. (Admitted
// commands and cached output: TestLockWaitsForRunningRead,
// TestLockStopsHangingRead, TestLockStopsCachedOutput. Login and unlock:
// TestLogoutCancelsUnlock, TestPendingLockKeepsItsPlace.)
func TestEveryProcessIsCoordinated(t *testing.T) {
	bg := func(t *testing.T, c *exec.Cmd) *exec.Cmd {
		c.Stdin = strings.NewReader("")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	quiet := func(e *fakeEnv, what string, cond func() bool) {
		e.t.Helper()
		time.Sleep(300 * time.Millisecond)
		if !cond() {
			e.t.Fatal(what)
		}
	}
	hooked := func(e *fakeEnv, name string) {
		e.t.Helper()
		e.waitUntil(name+" to be reached", func() bool { _, err := os.Stat(filepath.Join(e.fake, name+"-started")); return err == nil })
	}
	sessionless := [][]string{{"--help"}, {"generate"}, {"config", "server"}}

	for _, args := range sessionless {
		t.Run("lock completion: a running `bw "+strings.Join(args, " ")+"` is waited for, then stopped", func(t *testing.T) {
			e := newFakeEnv(t)
			e.flag("any-hold")
			proc := bg(t, e.cmd(e.dirA, e.session, nil, args...))
			e.started("any")
			pid := e.fakePid("any")
			e.unflag("any-hold")
			e.release("lock")
			lock := bg(t, e.cmd(e.dirB, "", []string{"BWW_TEST_USE_DRAIN=600ms"}, "lock"))
			quiet(e, "the real lock ran while an earlier real-CLI process was still running", func() bool { return e.runs("lock") == 0 })
			if err := lock.Wait(); err != nil || e.data() != fakeLocked {
				t.Fatalf("lock: %v", err)
			}
			if alive(pid) && !zombie(pid) {
				t.Fatal("the lock returned while an earlier real-CLI process was still alive")
			}
			proc.Wait()
		})
		t.Run("lock completion: `bw "+strings.Join(args, " ")+"` does not start while a lock is pending", func(t *testing.T) {
			e := newFakeEnv(t)
			e.flag("revoked-hold")
			lock := bg(t, e.cmd(e.dirA, "", nil, "lock"))
			hooked(e, "revoked")
			e.unflag("revoked-hold")
			proc := bg(t, e.cmd(e.dirB, e.session, nil, args...))
			quiet(e, "a real-CLI process started while a lock was pending", func() bool { return e.runs(args[0]) == 0 })
			e.release("lock")
			e.release("revoked")
			if err := lock.Wait(); err != nil {
				t.Fatalf("lock: %v", err)
			}
			proc.Wait()
			if e.runs(args[0]) != 1 || e.data() != fakeLocked {
				t.Fatalf("after the lock: runs %d", e.runs(args[0]))
			}
		})
		t.Run("snapshot ordering: `bw "+strings.Join(args, " ")+"` does not run inside a guarded run", func(t *testing.T) {
			e := newFakeEnv(t)
			guarded := bg(t, e.cmd(e.dirA, e.session, nil, "export")) // hold mode: snapshot taken, CLI running
			e.started("export")
			proc := bg(t, e.cmd(e.dirB, e.session, nil, args...))
			quiet(e, "a real-CLI process ran between a snapshot and its restore decision", func() bool { return e.runs(args[0]) == 0 })
			e.release("export")
			guarded.Wait()
			proc.Wait()
			if e.runs(args[0]) != 1 {
				t.Fatalf("it never ran: runs %d", e.runs(args[0]))
			}
		})
	}
	t.Run("lock completion: the child of a killed daemon is found and stopped", func(t *testing.T) {
		e := newFakeEnv(t)
		e.env = append(e.env, "BWW_TEST_NO_PDEATHSIG=1")
		e.flag("load-hold")
		read := bg(t, e.cmd(e.dirA, e.session, nil, "get", "password", "x"))
		e.started("load")
		child := e.fakePid("load")
		d := e.daemons()
		if len(d) != 1 {
			t.Fatalf("test setup: daemons %v", d)
		}
		syscall.Kill(d[0].PID, syscall.SIGKILL)
		e.waitUntil("the daemon to be gone", func() bool { return !alive(d[0].PID) || zombie(d[0].PID) })
		if !alive(child) {
			t.Fatal("test setup: the child died with the daemon")
		}
		e.release("lock")
		r := e.run(e.cmd(e.dirB, "", []string{"BWW_TEST_USE_DRAIN=100ms"}, "lock"))
		if r.code != 0 || e.data() != fakeLocked {
			t.Fatalf("lock: (%d, %q)", r.code, r.stderr)
		}
		if alive(child) && !zombie(child) {
			t.Fatal("the lock returned while a real-CLI process with the old session was still alive")
		}
		read.Wait()
	})
	t.Run("a daemon confirms its stop only when its children are gone", func(t *testing.T) {
		e := newFakeEnv(t)
		e.env = append(e.env, "BWW_TEST_NO_PDEATHSIG=1")
		e.flag("load-hold")
		read := bg(t, e.cmd(e.dirA, e.session, nil, "get", "password", "x"))
		e.started("load")
		child := e.fakePid("load")
		if stopped, failed := stopDaemons(e.co, ""); stopped != 1 || len(failed) != 0 {
			t.Fatalf("stop: %d stopped, failed %v", stopped, failed)
		}
		if alive(child) && !zombie(child) {
			t.Fatal("the daemon confirmed its stop while its real-CLI child was still alive")
		}
		e.release("load")
		e.release("get")
		read.Wait()
	})
}

// The stop contract, end to end: `bw-wrapper stop` (and `make install`,
// which depends on it) succeeds only when the daemon's real-CLI processes
// are gone. A daemon that cannot establish that in time says so, stays
// registered, and can be asked again.
func TestStopIsNotAcknowledgedEarly(t *testing.T) {
	for point, what := range map[string]string{
		"child-started": "a real CLI was started and is not on record yet",
		"child-reaped":  "a killed real CLI has exited but the launch is not closed yet",
	} {
		t.Run(what, func(t *testing.T) {
			e := newFakeEnv(t)
			e.env = append(e.env, "BWW_TEST_CHILD_STOP_WAIT=200ms")
			e.flag("load-hold")
			e.flag(point + "-hold") // the daemon's launcher stops at this point
			read := e.cmd(e.dirA, e.session, nil, "get", "password", "x")
			if err := read.Start(); err != nil {
				t.Fatal(err)
			}
			defer read.Wait()
			defer e.release("get")
			if point == "child-started" {
				e.waitUntil("the launcher to stop after Start", func() bool { _, err := os.Stat(filepath.Join(e.fake, point+"-started")); return err == nil })
			} else {
				e.started("load") // the child runs; the launcher will stop after reaping it
			}
			e.waitUntil("the daemon to be registered", func() bool { return len(e.daemons()) == 1 })
			pid := e.daemons()[0].PID

			stopped, failed := stopDaemons(e.co, "")
			if stopped != 0 || len(failed) != 1 {
				t.Fatalf("stop was acknowledged (%d stopped, failed %v) although %s", stopped, failed, what)
			}
			// through the command the user runs, too
			admin := exec.Command(os.Args[0], "__admin", "stop")
			admin.Env = append(append([]string(nil), e.env...), "BWW_RUNTIME_DIR="+e.dirA)
			if out, err := admin.CombinedOutput(); err == nil || !strings.Contains(string(out), "FAILED") {
				t.Fatalf("bw-wrapper stop: %v, %q", err, out)
			}
			// the unfinished shutdown stays discoverable
			d := e.daemons()
			if len(d) != 1 || d[0].PID != pid || !d[0].Stopping || !alive(pid) {
				t.Fatalf("the daemon with the unfinished shutdown is not on the registry any more: %+v", d)
			}
			if d[0].Loaded {
				t.Fatal("a stopping daemon still offers a vault")
			}

			e.release(point) // the launcher goes on: registers (and kills) the child, or closes the launch
			e.waitUntil("the daemon to finish its shutdown and exit", func() bool { return !alive(pid) || zombie(pid) })
			if d := e.daemons(); len(d) != 0 {
				t.Fatalf("registry after the shutdown completed: %+v", d)
			}
			if child := e.fakePid("load"); alive(child) && !zombie(child) {
				t.Fatal("the real-CLI child outlived the daemon")
			}
		})
	}
}

// lockedBuffer collects a process's output while the test looks at it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// An answer that could not be written is not a success.
func TestOutputFailureIsFailure(t *testing.T) {
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/full")
	}
	defer full.Close()
	e := newFakeEnv(t)
	e.cached(e.dirA)
	loads := e.runs("list")
	for _, args := range [][]string{{"get", "password", "x"}, {"list", "items"}, {"status"}} {
		c := e.cmd(e.dirA, e.session, nil, args...)
		c.Stdout = full // every write fails: no space left on device
		var errOut bytes.Buffer
		c.Stderr = &errOut
		err := c.Run()
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 || !strings.Contains(errOut.String(), "cannot write the answer") {
			t.Errorf("bw %v with output that cannot be written: %v, %q", args, err, errOut.String())
		}
	}
	if e.runs("get") != 0 || e.runs("list") != loads || e.runs("status") != 1 {
		t.Error("test setup: the commands were meant to be answered from memory")
	}
}

// Uninstalling follows the install rule: the installed binary stops its
// daemons first, and if it cannot, nothing is removed.
func TestUninstallAbortsWhenStopFails(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not available")
	}
	bindir := t.TempDir()
	stub, link := filepath.Join(bindir, "bw-wrapper"), filepath.Join(bindir, "bw")
	calls := filepath.Join(t.TempDir(), "calls")
	script := func(exit int) string {
		return fmt.Sprintf("#!/bin/sh\necho \"$1\" >> '%s'\n[ \"$1\" = stop ] && { echo 'stopped 0 daemon(s), 1 FAILED'; exit %d; }\n", calls, exit)
	}
	os.WriteFile(stub, []byte(script(1)), 0o755)
	os.Symlink("bw-wrapper", link)
	out, err := exec.Command("make", "uninstall", "BINDIR="+bindir).CombinedOutput()
	if err == nil {
		t.Errorf("make uninstall succeeded although a daemon could not be stopped:\n%s", out)
	}
	if _, err := os.Stat(stub); err != nil {
		t.Error("the installed binary was removed although its daemons could not be stopped")
	}
	if to, _ := os.Readlink(link); to != "bw-wrapper" {
		t.Error("the bw link was removed")
	}
	// when stop succeeds, it was asked first and both are removed
	os.WriteFile(stub, []byte(script(0)), 0o755)
	os.Remove(calls)
	if out, err := exec.Command("make", "uninstall", "BINDIR="+bindir).CombinedOutput(); err != nil {
		t.Fatalf("make uninstall: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(calls); strings.TrimSpace(string(b)) != "stop" {
		t.Errorf("the installed binary was called with %q, want one `stop`", b)
	}
	if _, err := os.Lstat(stub); err == nil {
		t.Error("binary not removed")
	}
	if _, err := os.Lstat(link); err == nil {
		t.Error("link not removed")
	}
	// nothing installed: nothing to stop, no error
	if out, err := exec.Command("make", "uninstall", "BINDIR="+bindir).CombinedOutput(); err != nil {
		t.Fatalf("make uninstall with nothing installed: %v\n%s", err, out)
	}
}

// `make install` checks the destination before it changes anything: a `bw`
// that is not the wrapper's own link is never replaced.
func TestInstallPreservesForeignBw(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not available")
	}
	if _, err := os.Stat("bw-wrapper"); err != nil {
		t.Skip("no built bw-wrapper to install (run make first)")
	}
	install := func(bindir string) ([]byte, error) {
		// -o: do not rebuild the binary for this test
		mk := exec.Command("make", "-o", "bw-wrapper", "install", "BINDIR="+bindir)
		scratch := t.TempDir() // the installed binary's `stop` must not look at anything real
		mk.Env = append(os.Environ(), "BWW_RUNTIME_DIR="+filepath.Join(scratch, "run"), "BITWARDENCLI_APPDATA_DIR="+filepath.Join(scratch, "root"), "BWW_REAL_BW=/bin/true")
		return mk.CombinedOutput()
	}
	const realCLI = "#!/bin/sh\necho the real bw\n"
	t.Run("an executable named bw", func(t *testing.T) {
		bindir := t.TempDir()
		os.WriteFile(filepath.Join(bindir, "bw"), []byte(realCLI), 0o755)
		out, err := install(bindir)
		if err == nil || !strings.Contains(string(out), "refusing to install") {
			t.Fatalf("make install: %v\n%s", err, out)
		}
		if b, _ := os.ReadFile(filepath.Join(bindir, "bw")); string(b) != realCLI {
			t.Error("the existing bw was changed")
		}
		if _, err := os.Lstat(filepath.Join(bindir, "bw-wrapper")); err == nil {
			t.Error("something was installed before the check")
		}
	})
	t.Run("a link to something else", func(t *testing.T) {
		bindir := t.TempDir()
		target := filepath.Join(t.TempDir(), "real-bw")
		os.WriteFile(target, []byte(realCLI), 0o755)
		os.Symlink(target, filepath.Join(bindir, "bw"))
		out, err := install(bindir)
		if err == nil || !strings.Contains(string(out), "refusing to install") {
			t.Fatalf("make install: %v\n%s", err, out)
		}
		if to, _ := os.Readlink(filepath.Join(bindir, "bw")); to != target {
			t.Errorf("the existing link now points to %q", to)
		}
		if _, err := os.Lstat(filepath.Join(bindir, "bw-wrapper")); err == nil {
			t.Error("something was installed before the check")
		}
	})
	t.Run("a dangling link to something else", func(t *testing.T) {
		bindir := t.TempDir()
		os.Symlink("/nonexistent/bw", filepath.Join(bindir, "bw"))
		if out, err := install(bindir); err == nil {
			t.Fatalf("make install replaced a foreign link:\n%s", out)
		}
	})
	t.Run("nothing there, directory missing; then again over its own link", func(t *testing.T) {
		bindir := filepath.Join(t.TempDir(), "not", "yet", "bin dir") // created by install; a space in the path
		for i := 0; i < 2; i++ {
			if out, err := install(bindir); err != nil {
				t.Fatalf("install %d: %v\n%s", i+1, err, out)
			}
			if to, _ := os.Readlink(filepath.Join(bindir, "bw")); to != "bw-wrapper" {
				t.Fatalf("bw link: %q", to)
			}
			if fi, err := os.Stat(filepath.Join(bindir, "bw-wrapper")); err != nil || fi.Mode().Perm() != 0o755 {
				t.Fatalf("installed binary: %v", err)
			}
		}
	})
}

// `bw --is-wrapper` tells the wrapper from the real CLI, and only as the
// whole command line.
func TestIsWrapper(t *testing.T) {
	e := newFakeEnv(t)
	r := e.run(e.cmd(e.dirA, e.session, nil, "--is-wrapper"))
	if r.code != 0 || !strings.HasPrefix(r.stdout, "bw-wrapper ") || !strings.Contains(r.stdout, "real bw: "+filepath.Join(e.fake, "bw")) {
		t.Errorf("bw --is-wrapper: (%d, %q, %q)", r.code, r.stdout, r.stderr)
	}
	if files, _ := filepath.Glob(filepath.Join(e.fake, "*-runs")); len(files) != 0 {
		t.Errorf("the real CLI was run: %v", files)
	}
	// with the wrapper bypassed, the real CLI gets the line (and rejects it)
	e.run(e.cmd(e.dirA, e.session, []string{"BWW_DISABLE=1"}, "--is-wrapper"))
	if e.runs("--is-wrapper") != 1 {
		t.Error("BWW_DISABLE=1 did not hand the line to the real CLI")
	}
	// anywhere else it is an ordinary (unknown) option, not a question to the wrapper
	for _, args := range [][]string{{"status", "--is-wrapper"}, {"--is-wrapper", "status"}, {"get", "password", "x", "--output", "--is-wrapper"}} {
		if r := e.run(e.cmd(e.dirA, e.session, nil, args...)); strings.HasPrefix(r.stdout, "bw-wrapper ") {
			t.Errorf("bw %v was answered as --is-wrapper", args)
		}
	}
}
