#!/usr/bin/env python3
"""Lifecycle test for bw-wrapper against the fixture: unlock/preload, routing
by root and session, lock, sync, auto-lock, read-only gate, and what happens
when the real CLI is used behind the wrapper's back.

    source test/fixture/env.sh && test/lifecycle.py

Uses its own CLI roots under /tmp/bww-dev (logs in if needed) and its own
runtime directory, so it does not disturb other daemons.
"""
import json, os, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.environ.get("REAL_BW") or sys.exit("source test/fixture/env.sh first")
BIN = os.path.abspath(os.path.join(HERE, "..", "bw-wrapper"))
sys.path.insert(0, os.path.join(HERE, "fixture"))
import safety  # noqa: E402

BASE = safety.DEV_ROOT
# The developer's own ~/.config/bw-wrapper/config must not change the results.
os.environ["BWW_CONFIG"] = safety.DEV_ROOT + "/no-config"
RUN = f"{BASE}/run-lifecycle"
ROOTS = {"bob": f"{BASE}/lc-bob", "alice": f"{BASE}/lc-alice", "hold": f"{BASE}/lc-hold"}
CRED = {"bob": ("BOB_EMAIL", "BOB_PW"), "alice": ("ALICE_EMAIL", "ALICE_PW"), "hold": ("ALICE_EMAIL", "ALICE_PW")}

safety.create_root(BASE)  # a marked fixture directory, or nothing runs
for _root in ROOTS.values():
    safety.fixture_path(_root)  # raises before anything is touched

failures = []


def env_for(who, session=None, **extra):
    e = dict(os.environ)
    for k in ("BW_SESSION", "BW_PRETTY", "BW_RAW", "BW_RESPONSE", "BW_QUIET", "BW_CLEANEXIT", "BW_NOINTERACTION"):
        e.pop(k, None)
    e.update(BITWARDENCLI_APPDATA_DIR=ROOTS[who], BWW_RUNTIME_DIR=RUN, BWW_AUTO_LOCK="0")
    if session:
        e["BW_SESSION"] = session
    e.update({k: str(v) for k, v in extra.items()})
    return e


def bw(who, *args, session=None, real=False, **extra):
    """Run through the wrapper (or the real CLI). Returns (rc, stdout, stderr, seconds)."""
    cmd = [REAL, *args] if real else [BIN, "bw", *args]
    t0 = time.perf_counter()
    p = subprocess.run(cmd, env=env_for(who, session, **extra), stdin=subprocess.DEVNULL, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr, time.perf_counter() - t0


def daemons():
    p = subprocess.run([BIN, "status"], env=env_for("bob"), capture_output=True, text=True)
    return [l for l in p.stdout.splitlines() if l.startswith("pid ")]


def wait_for(cond, timeout, what):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.2)
    check(False, f"timed out waiting for {what}")
    return False


def check(ok, what, detail=""):
    print(("  ok   " if ok else "  FAIL ") + what + (f"  [{detail}]" if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(what)


def section(title):
    print(f"\n== {title}", flush=True)


def ensure_login(who):
    os.makedirs(ROOTS[who], exist_ok=True)
    rc, out, _, _ = bw(who, "status", real=True)
    if rc == 0 and json.loads(out).get("status") != "unauthenticated":
        return
    bw(who, "config", "server", os.environ["BWW_FIXTURE_URL"], real=True)
    em, pw = CRED[who]
    rc, _, err, _ = bw(who, "login", os.environ[em], "--passwordenv", pw, "--raw", "--nointeraction", real=True)
    if rc != 0:
        sys.exit(f"login {who} failed: {err}")
    bw(who, "lock", real=True)


def fresh_login(who):
    """Log the root out and in again, so it has valid tokens."""
    bw(who, "logout", real=True)
    ensure_login(who)


def expire(who, mode):
    """Simulate a login session that ended on the server (see expire_session.py)."""
    subprocess.run([sys.executable, os.path.join(HERE, "expire_session.py"), ROOTS[who], mode], check=True)


def real_status(who, session=None):
    return json.loads(bw(who, "status", session=session, real=True)[1]).get("status")


def hold_tests():
    H = {"BWW_HOLD": "1"}
    NI = {"BW_NOINTERACTION": "true"}

    section("expired session without hold mode (default): the real CLI's behaviour")
    fresh_login("hold")
    s, _ = unlock("hold")
    rc, pw, err, _ = bw("hold", "get", "password", "Café Müller", session=s)
    check(rc == 0 and pw != "", "read works before the session ends", pw + err)
    expire("hold", "server")
    rc, out, err, _ = bw("hold", "sync", session=s)
    check(rc == 1 and "invalid_grant" in out + err, "sync fails with the server's rejection", out + err)
    check(real_status("hold", s) == "unauthenticated", "the real CLI logged itself out")
    rc, out, err, _ = bw("hold", "get", "password", "Café Müller", session=s, **NI)
    check(rc == 1 and "You are not logged in." in err and len(daemons()) == 0, "and the wrapper follows: no answer from memory", out + err)

    section("hold mode: refresh token past its own expiry")
    fresh_login("hold")
    s, _ = unlock("hold", **H)
    bw("hold", "status", session=s, **H)
    expire("hold", "clock")
    rc, out, err, dt = bw("hold", "sync", session=s, **H)
    check(rc == 1 and out == "" and "login session expired" in err and dt < 0.5, "sync is refused before the real CLI runs", f"{dt:.2f}s " + out + err)
    rc, out, err, _ = bw("hold", "sync", "--response", session=s, **H)
    check(rc == 1 and json.loads(out)["success"] is False, "refusal honours --response", out + err)
    check(real_status("hold", s) == "unlocked", "the CLI's data file is untouched (still unlocked)")
    rc, out, err, dt = bw("hold", "get", "password", "Café Müller", session=s, **H)
    check(rc == 0 and out == pw and dt < 0.25, "reading still works, from memory", out + err)
    rc, out, err, _ = bw("hold", "sync", "--last", session=s, **H)
    check(rc == 0 and out != "", "sync --last (local) still passes through", out + err)

    section("hold mode: server rejects the session (not visible locally)")
    expire("hold", "server")
    rc, out, err, _ = bw("hold", "sync", session=s, **H)
    check(rc == 1 and "invalid_grant" in out + err, "sync runs and fails with the server's rejection", out + err)
    check("Hold mode restored the local vault" in err, "the wrapper says it restored the local vault", err)
    check(real_status("hold", s) == "unlocked", "the real CLI is logged in and unlocked again (data file restored)")
    rc, out, err, dt = bw("hold", "list", "folders", session=s, real=True)
    check(rc == 0 and out.startswith("["), "the real CLI can read locally again", out + err)
    rc, out, err, dt = bw("hold", "get", "password", "Café Müller", session=s, **H)
    check(rc == 0 and out == pw and dt < 0.25, "wrapper reads work and are fast", f"{dt:.2f}s " + out + err)
    check("HOLDING" not in " ".join(daemons()), "daemon is not in holding state (the session is back on disk)", str(daemons()))
    bw("hold", "lock", **H)
    check(len(daemons()) == 0, "bw lock still wipes the daemon")
    s, dt = unlock("hold", **H)
    rc, out, err, _ = bw("hold", "get", "password", "Café Müller", session=s, **H)
    check(rc == 0 and out == pw, "after a restore the vault can even be unlocked and loaded again (survives a daemon restart)", out + err)

    section("hold mode: the real CLI logs itself out behind the wrapper's back")
    rc, items_before, _, _ = bw("hold", "list", "items", session=s, **H)
    bw("hold", "sync", session=s, real=True)  # bypasses the wrapper: no guard, the CLI erases its data
    check(real_status("hold", s) == "unauthenticated", "the CLI is logged out on disk")
    rc, out, err, dt = bw("hold", "get", "password", "Café Müller", session=s, **H)
    check(rc == 0 and out == pw and dt < 0.25, "the daemon keeps answering from memory", out + err)
    check("HOLDING" in " ".join(daemons()), "bw-wrapper status shows the holding state", str(daemons()))
    rc, out, _, _ = bw("hold", "list", "items", session=s, **H)
    check(rc == 0 and out == items_before, "list items still returns the whole vault")
    rc, out, err, _ = bw("hold", "status", session=s, **H)
    check(rc == 0 and json.loads(out)["status"] == "unlocked", "status is answered from memory")
    rc, out, err, _ = bw("hold", "get", "item", "00000000-0000-4000-8000-000000000000", session=s, **H, **NI)
    check(rc == 1 and "You are not logged in." in err, "what needs the real CLI gets its 'You are not logged in.'", out + err)
    rc, out, err, _ = bw("hold", "get", "password", "Café Müller", session="A" * 86 + "==", **H, **NI)
    check(rc == 1 and out == "", "a wrong session key still gets nothing", out + err)
    rc, out, err, _ = bw("hold", "lock", **H)
    check(len(daemons()) == 0, "bw lock through the wrapper wipes a holding daemon at once", str(daemons()))
    rc, out, err, _ = bw("hold", "get", "password", "Café Müller", session=s, **H, **NI)
    check(rc == 1 and out == "", "and then nothing is answered any more", out + err)

    section("hold mode: an explicit logout while a guarded command is running")
    fresh_login("hold")
    s, _ = unlock("hold", **H)
    bw("hold", "status", session=s, **H)
    expire("hold", "server")
    # `sync` will fail, the CLI will log itself out, and the guard would restore
    # the data file -- unless a logout came in meanwhile.
    slow = subprocess.Popen([BIN, "bw", "sync"], env=env_for("hold", s, **H), stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    time.sleep(0.3)  # let it take its snapshot and start the real CLI
    rc, out, err, _ = bw("hold", "logout", **H)
    slow_err = slow.communicate()[1]
    check(slow.returncode == 1, "the overlapping sync failed as expected", slow_err[:200])
    check("restored the local vault" not in slow_err, "its guard did not restore anything", slow_err[-300:])
    check(real_status("hold", s) == "unauthenticated", "the logout stands: the CLI is logged out")
    rc, out, err, _ = bw("hold", "get", "password", "Café Müller", session=s, **H, **NI)
    check(rc == 1 and out == "" and len(daemons()) == 0, "and nothing is answered with the old session key", out + err)
    check(not [f for f in os.listdir(ROOTS["hold"]) if f.startswith(".data.json.bww-")], "no temporary restore files left", str(os.listdir(ROOTS["hold"])))

    section("hold mode: a guarded command that starts while a logout is running")
    fresh_login("hold")
    s, _ = unlock("hold", **H)
    bw("hold", "status", session=s, **H)
    expire("hold", "server")
    out_p = subprocess.Popen([BIN, "bw", "logout"], env=env_for("hold", **H), stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.3)  # the logout is marked active and its real CLI is starting
    rc, out, err, _ = bw("hold", "sync", session=s, **H)  # snapshots a vault the logout has not cleared yet
    out_p.communicate()
    check("restored the local vault" not in err, "the sync's guard did not restore anything", err[-300:])
    check(out_p.returncode == 0 and real_status("hold", s) == "unauthenticated", "the logout succeeded and stands", str(out_p.returncode))
    rc, out, err, _ = bw("hold", "get", "password", "Café Müller", session=s, **H, **NI)
    check(rc == 1 and out == "" and len(daemons()) == 0, "nothing is answered with the old session key", out + err)

    section("hold mode: limits")
    fresh_login("hold")
    s, _ = unlock("hold", **H)
    bw("hold", "status", session=s, **H)
    bw("hold", "lock", real=True)  # a deliberate lock with the real CLI: still logged in, not ours any more
    rc, out, err, _ = bw("hold", "get", "password", "Café Müller", session=s, **H, **NI)
    check(rc == 1 and "Vault is locked." in err and len(daemons()) == 0, "a real lock behind the wrapper's back is not held against", out + err)
    s, _ = unlock("hold", **H)
    bw("hold", "status", session=s, **H)
    expire("hold", "server")
    bw("hold", "sync", session=s, real=True)
    rc, out, err, _ = bw("hold", "get", "password", "Café Müller", session=s, BWW_HOLD="1", BWW_HOLD_MAX="3")
    check(rc == 0 and out == pw and "wipes in" in " ".join(daemons()), "holding with hold_max=3s", out + err + str(daemons()))
    t0 = time.time()
    wait_for(lambda: len(daemons()) == 0, 30, "hold limit")
    print(f"       holding daemon wiped itself after {time.time() - t0:.1f}s")
    rc, out, err, _ = bw("hold", "get", "password", "Café Müller", session=s, **H, **NI)
    check(rc == 1 and out == "", "after hold_max nothing is answered", out + err)
    bw("hold", "logout", real=True)


def unlock(who, **extra):
    rc, out, err, dt = bw(who, "unlock", "--passwordenv", CRED[who][1], "--raw", "--nointeraction", **extra)
    if rc != 0:
        sys.exit(f"unlock {who} failed: {err}")
    return out.strip(), dt


def main():
    shutil.rmtree(RUN, ignore_errors=True)
    os.makedirs(RUN, mode=0o700)
    for who in ROOTS:
        ensure_login(who)

    section("unlock starts a daemon and preloads the vault")
    s1, dt = unlock("bob")
    check(len(s1) == 88, "unlock --raw prints only the session key", s1[:20])
    check(len(daemons()) == 1, "one daemon after unlock", str(daemons()))
    rc, out, err, cold = bw("bob", "status", session=s1)
    check(rc == 0 and json.loads(out)["status"] == "unlocked", "status says unlocked", out + err)
    print(f"       unlock {dt:.2f}s, first command (waits for the preload) {cold:.2f}s")
    check("3001 items" in " ".join(daemons()), "daemon holds bob's 3001 items", str(daemons()))

    section("speed (bob, 3001 items)")
    rc, out, _, _ = bw("bob", "list", "items", "--search", "0042", session=s1)
    name = json.loads(out)[0]["name"]
    iid = json.loads(out)[0]["id"]
    for label, args in (("get password <name>", ["get", "password", name]), ("get item <id>", ["get", "item", iid]),
                        ("list items --search", ["list", "items", "--search", "alpha"]), ("list items (all)", ["list", "items"]),
                        ("status", ["status"])):
        ts = sorted(bw("bob", *args, session=s1)[3] for _ in range(15))
        rrc, rout, _, rdt = bw("bob", *args, session=s1, real=True)
        wrc, wout, _, _ = bw("bob", *args, session=s1)
        check((rrc, rout) == (wrc, wout), f"{label}: same output as the real CLI")
        print(f"       {label:24s} wrapper {1000 * ts[len(ts) // 2]:7.1f} ms   real {1000 * rdt:7.0f} ms   x{rdt / ts[len(ts) // 2]:.0f}")
        check(ts[len(ts) // 2] < 0.25, f"{label} answers fast")

    section("routing by session token and root")
    rc, out, err, _ = bw("bob", "get", "password", name, session="A" * 86 + "==", BW_NOINTERACTION="true")
    check(rc == 1 and out == "" and "Vault is locked." in err, "wrong session key gets the real CLI's 'Vault is locked.'", out + err)
    check(len(daemons()) == 1, "a wrong session key leaves no daemon behind", str(daemons()))
    rc, out, err, _ = bw("bob", "get", "password", name, BW_NOINTERACTION="true")
    check(rc == 1 and "Vault is locked." in err, "no session key: real CLI answers", out + err)
    sa, _ = unlock("alice")
    check(len(daemons()) == 2, "second daemon runs as soon as alice's unlock returns", str(daemons()))
    rc, out, _, _ = bw("alice", "status", session=sa)
    check(rc == 0 and json.loads(out)["userEmail"] == os.environ["ALICE_EMAIL"], "alice's root answers as alice")
    rc, out, _, _ = bw("bob", "status", session=s1)
    check(rc == 0 and json.loads(out)["userEmail"] == os.environ["BOB_EMAIL"], "bob's root still answers as bob")
    rc, out, err, _ = bw("bob", "get", "item", "github", session=sa, BW_NOINTERACTION="true")
    check(rc == 1 and "Vault is locked." in err, "alice's session key is useless in bob's root", out + err)
    rc, out, err, _ = bw("alice", "--session", sa, "get", "username", "Café Müller")
    check(rc == 0 and out != "", "--session option routes like BW_SESSION", out + err)
    check(len(daemons()) == 2, "still exactly two daemons", str(daemons()))

    section("read-only gate")
    for args in (["create", "folder", "eyJuYW1lIjoieCJ9"], ["delete", "item", iid], ["edit", "item", iid, "e30="],
                 ["import", "bitwardenjson", "/dev/null"], ["send", "hello"], ["serve"], ["frobnicate"]):
        rc, out, err, dt = bw("bob", *args, session=s1)
        why = "cannot tell which command" if args[0] == "frobnicate" else "read-only"
        check(rc == 1 and out == "" and why in err and dt < 0.5, f"`{args[0]}` is refused", out + err)
    # `delete item <id> --help` is help, for the real CLI and so for the wrapper
    rc, out, err, _ = bw("bob", "delete", "item", iid, "--help", session=s1)
    check(rc == 0 and out.startswith("Usage: bw delete"), "`delete item <id> --help` prints help, like the real CLI", out + err)
    for args in (["--", "delete", "item", iid], ["send", "-n", "-h", "text"], ["delete", "item", "--", iid, "--help"],
                 ["create", "attachment", "--file", "--help", "--itemid", iid],
                 ["--pretty", "--", "create", "folder", "eyJuYW1lIjoieCJ9"]):
        rc, out, err, dt = bw("bob", *args, session=s1)
        check(rc == 1 and out == "" and "read-only" in err and dt < 0.5, f"gate bypass attempt `{' '.join(args[:3])}` is refused", out + err)
    rc, out, err, _ = bw("bob", "list", "folders", "--search", "bww-lifecycle", session=s1, real=True)
    check(out.strip() == "[]", "and nothing was created", out + err)
    rc, out, err, _ = bw("bob", "create", "folder", "x", "--response", session=s1)
    check(rc == 1 and json.loads(out)["success"] is False, "refusal honours --response", out + err)
    rc, out, err, _ = bw("bob", "generate", "--length", "20", session=s1)
    check(rc == 0 and len(out.strip()) == 20, "harmless commands pass through (generate)", out + err)
    rc, out, err, _ = bw("bob", "create", "--help", session=s1)
    check(rc == 0 and "Usage: bw create" in out, "--help of a write command passes through", err)

    section("sync reloads")
    rc, before, _, _ = bw("bob", "status", session=s1)
    rc, out, err, dt = bw("bob", "sync", session=s1)
    check(rc == 0 and out == "Syncing complete.", "sync output is the real one", out + err)
    rc, after, _, dt2 = bw("bob", "status", session=s1)
    check(json.loads(after)["lastSync"] != json.loads(before)["lastSync"], "status shows the new lastSync right after sync")
    check(dt2 < 0.25, "and is fast again (reload happened inside sync)", f"{dt2:.2f}s")
    print(f"       sync incl. reload {dt:.2f}s")
    rc, out, err, _ = bw("bob", "sync", "--last", session=s1)
    check(rc == 0 and out == json.loads(after)["lastSync"], "sync --last passes through", out + err)

    section("writes allowed by configuration invalidate the cache")
    payload = subprocess.run([REAL, "encode"], input='{"name":"bww-lifecycle-folder"}', capture_output=True, text=True, env=env_for("bob")).stdout
    rc, out, err, _ = bw("bob", "create", "folder", payload, session=s1, BWW_ALLOW_WRITES="1")
    check(rc == 0 and json.loads(out)["name"] == "bww-lifecycle-folder", "create passes through with BWW_ALLOW_WRITES=1", out + err)
    fid = json.loads(out)["id"] if rc == 0 else ""
    rc, out, err, dt = bw("bob", "get", "folder", "bww-lifecycle-folder", session=s1)
    check(rc == 0 and json.loads(out)["id"] == fid and dt < 0.25, "the new folder is visible from memory", out + err)
    rc, out, err, _ = bw("bob", "delete", "folder", fid, session=s1, BWW_ALLOW_WRITES="1")
    rc2, out2, err2, _ = bw("bob", "get", "folder", "bww-lifecycle-folder", session=s1)
    check(rc == 0 and rc2 == 1 and "Not found." in err2, "and gone after delete", out + err + out2 + err2)

    section("real CLI used behind the wrapper's back")
    bw("bob", "list", "folders", session=s1, real=True)  # a read: only bookkeeping changes on disk
    rc, out, err, dt = bw("bob", "status", session=s1)
    check(rc == 0 and dt < 0.25, "a real read does not trigger a reload", f"{dt:.2f}s")
    bw("bob", "sync", session=s1, real=True)
    rc, out2, err, dt = bw("bob", "status", session=s1)
    check(rc == 0 and json.loads(out2)["lastSync"] != json.loads(after)["lastSync"], "a real sync is noticed (fresh lastSync)", out2)
    print(f"       command after external sync (reloads) {dt:.2f}s")
    rc, s2, err, _ = bw("bob", "unlock", "--passwordenv", "BOB_PW", "--raw", "--nointeraction", real=True)
    s2 = s2.strip()
    rc, out, err, _ = bw("bob", "get", "password", name, session=s1, BW_NOINTERACTION="true")
    check(rc == 1 and out == "" and "Vault is locked." in err, "old session is dead after a real re-unlock", out + err)
    check(len(daemons()) == 1, "and its daemon wiped itself", str(daemons()))
    rc, out, err, dt = bw("bob", "get", "password", name, session=s2)
    check(rc == 0 and out != "", "the new session works (daemon started on first use)", out + err)
    print(f"       cold start on first use {dt:.2f}s")
    bw("bob", "lock", real=True)
    rc, out, err, _ = bw("bob", "get", "password", name, session=s2, BW_NOINTERACTION="true")
    check(rc == 1 and out == "" and "Vault is locked." in err, "a real lock is noticed: no answer from memory", out + err)
    check(len(daemons()) == 1, "and the daemon is gone", str(daemons()))

    section("lock")
    s3, _ = unlock("bob")
    bw("bob", "status", session=s3)
    check(len(daemons()) == 2, "daemon running before lock", str(daemons()))
    rc, out, err, dt = bw("bob", "lock")
    check(rc == 0 and out == "Your vault is locked.", "lock output is the real one", out + err)
    check(len(daemons()) == 1, "bob's daemon is gone when lock returns, alice's is untouched", str(daemons()))
    rc, out, err, _ = bw("bob", "get", "password", name, session=s3, BW_NOINTERACTION="true")
    check(rc == 1 and "Vault is locked." in err, "session is dead after lock", out + err)
    rc, out, _, _ = bw("alice", "status", session=sa)
    check(rc == 0 and json.loads(out)["status"] == "unlocked", "alice is still unlocked")

    section("lock through another spelling of the same root (symlink)")
    alias = f"{BASE}/lc-bob-alias"
    # Never reuse what is there: a link left behind (or planted) could point
    # anywhere. Remove the name and create the link anew, to a validated root.
    safety.fixture_path(os.path.dirname(alias))
    if os.path.lexists(alias):
        os.unlink(alias)
    os.symlink(safety.fixture_path(ROOTS["bob"]), alias)
    assert os.readlink(alias) == ROOTS["bob"]
    sy, _ = unlock("bob", BITWARDENCLI_APPDATA_DIR=alias)
    rc, out, err, dt = bw("bob", "status", session=sy)  # real path, daemon was started through the alias
    check(rc == 0 and len(daemons()) == 2, "alias and real path share one daemon", str(daemons()))
    rc, out, err, _ = bw("bob", "get", "item", iid, session=sy, BITWARDENCLI_APPDATA_DIR=alias + "/.")
    check(rc == 0 and json.loads(out)["id"] == iid, "a third spelling reaches it too", out + err)
    rc, out, err, _ = bw("bob", "lock")  # through the real path
    check(rc == 0 and out == "Your vault is locked." and len(daemons()) == 1, "lock through the real path stops the daemon started through the alias", out + err + str(daemons()))
    sy, _ = unlock("bob")
    bw("bob", "status", session=sy)
    rc, out, err, _ = bw("bob", "logout", BITWARDENCLI_APPDATA_DIR=alias, BWW_HOLD="1")  # and the other way round, with hold mode on
    check(len(daemons()) == 1, "logout through the alias stops the daemon started through the real path", out + err + str(daemons()))
    ensure_login("bob")

    section("lock from a shell with a different runtime directory")
    run2 = RUN + "-other"
    shutil.rmtree(run2, ignore_errors=True)
    os.makedirs(run2, mode=0o700)
    sz, _ = unlock("bob")
    bw("bob", "status", session=sz)  # wait for the preload
    rc, out, err, dt = bw("bob", "get", "item", iid, session=sz, BWW_RUNTIME_DIR=run2)
    check(rc == 0 and dt < 0.25 and len(daemons()) == 2 and not [f for f in os.listdir(run2) if f.endswith(".sock")],
          "a shell with another runtime directory uses the same daemon", f"{dt:.2f}s " + err + str(daemons()))
    rc, out, err, _ = bw("bob", "lock", BWW_RUNTIME_DIR=run2)
    check(rc == 0 and out == "Your vault is locked." and len(daemons()) == 1, "and its lock stops that daemon", out + err + str(daemons()))
    rc, out, err, _ = bw("bob", "get", "item", iid, session=sz, BW_NOINTERACTION="true")
    check(rc == 1 and "Vault is locked." in err, "nothing answers afterwards", out + err)
    check(os.path.isdir(os.path.join(ROOTS["bob"], ".bw-wrapper")) and oct(os.stat(os.path.join(ROOTS["bob"], ".bw-wrapper")).st_mode & 0o777) == "0o700",
          "coordination state lives in the root, private to the user")

    section("lock while the vault is still loading")
    sx, _ = unlock("bob")
    rc, out, err, _ = bw("bob", "lock")  # the preload started by unlock is still running
    check(rc == 0 and len(daemons()) == 1, "daemon is gone", str(daemons()))
    left = subprocess.run(["pgrep", "-af", f"serve --hostname unix://{RUN}"], capture_output=True, text=True).stdout.strip()
    check(left == "", "no `bw serve` loader process is left behind", left)

    section("unlock replaces the previous session's daemon")
    s4, _ = unlock("bob")
    bw("bob", "status", session=s4)
    s5, _ = unlock("bob")
    bw("bob", "status", session=s5)
    check(len(daemons()) == 2, "old daemon was dropped, one per root remains", str(daemons()))
    rc, out, err, _ = bw("bob", "get", "password", name, session=s4, BW_NOINTERACTION="true")
    check(rc == 1 and "Vault is locked." in err, "previous session key no longer answers", out + err)

    section("timeout settings below one second are rejected, not read as 'never'")
    p = subprocess.run([BIN, "config"], env=env_for("bob", BWW_AUTO_LOCK="500ms", BWW_HOLD_MAX="250ms"), capture_output=True, text=True)
    check("below one second" in p.stderr and "auto_lock         15m0s" in p.stdout and "hold_max          12h0m0s" in p.stdout,
          "500ms is refused with a warning and the default stays in force", p.stdout + p.stderr)

    section("auto-lock")
    bw("bob", "status", session=s5)  # in use right now: the 3s limit introduced next starts from here
    rc, out, _, _ = bw("bob", "status", session=s5, BWW_AUTO_LOCK="3")
    check(rc == 0, "command with auto_lock=3s")
    check("lock in" in " ".join(daemons()), "running daemon adopted the new timeout", str(daemons()))
    t0 = time.time()
    wait_for(lambda: len(daemons()) == 1, 40, "auto-lock")
    print(f"       daemon gone after {time.time() - t0:.1f}s idle")
    wait_for(lambda: json.loads(bw("bob", "status", real=True)[1])["status"] == "locked", 30, "real lock")
    rc, out, err, _ = bw("bob", "get", "password", name, session=s5, BW_NOINTERACTION="true")
    check(rc == 1 and "Vault is locked." in err, "auto-lock really locked the vault (session key invalid)", out + err)

    s7, _ = unlock("bob", BWW_AUTO_LOCK="3")
    bw("bob", "status", session=s7, BWW_AUTO_LOCK="3")
    rc, s8, err, _ = bw("bob", "unlock", "--passwordenv", "BOB_PW", "--raw", "--nointeraction", real=True)  # behind the wrapper's back
    s8 = s8.strip()
    wait_for(lambda: len(daemons()) == 1, 40, "auto-lock of the superseded daemon")
    rc, out, err, _ = bw("bob", "status", session=s8, real=True)
    check(rc == 0 and json.loads(out)["status"] == "unlocked", "auto-lock of an outdated daemon leaves the newer session alone", out + err)
    bw("bob", "lock", real=True)

    s6, _ = unlock("bob", BWW_AUTO_LOCK="3", BWW_AUTO_LOCK_ACTION="evict")
    bw("bob", "status", session=s6, BWW_AUTO_LOCK="3", BWW_AUTO_LOCK_ACTION="evict")
    wait_for(lambda: len(daemons()) == 1, 40, "auto-evict")
    rc, out, err, dt = bw("bob", "get", "password", name, session=s6)
    check(rc == 0 and out != "", "evict: memory wiped but the session key still works", out + err)
    print(f"       reload after evict {dt:.2f}s")

    section("daemon without its socket exits")
    n = len(daemons())
    for f in os.listdir(RUN):
        if f.endswith(".sock"):
            os.remove(os.path.join(RUN, f))
    print(f"       {n} daemons had sockets; waiting for them to notice")
    logf = os.path.join(RUN, "daemon.log")
    wait_for(lambda: open(logf).read().count("socket or registration is gone") >= n, 40, "daemons to exit")

    hold_tests()

    section("cleanup")
    for who in ROOTS:
        bw(who, "lock")
    check(len(daemons()) == 0, "no daemons left", str(daemons()))
    log = open(logf).read()
    check(not any(s and s in log for s in (s1, s2, s3, s4, s5, s6, s7, s8, sx, sy, sz, sa)), "no session key in the daemon log")
    coord_files = b"".join(open(os.path.join(dp, f), "rb").read() for r in ROOTS.values()
                           for dp, _, fs in os.walk(os.path.join(r, ".bw-wrapper")) for f in fs)
    check(not any(s.encode() in coord_files for s in (s1, s5, s6, sz, sa) if s), "no session key in the coordination directories")
    check(not [f for f in os.listdir(RUN) if f.endswith((".sock", ".srv"))], "no sockets left in the runtime dir", str(os.listdir(RUN)))

    print(f"\n{'FAILED: ' + str(len(failures)) if failures else 'all checks passed'}")
    for f in failures:
        print("  -", f)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
