#!/usr/bin/env python3
"""Differential test: run the same command lines through the real Bitwarden
CLI and through bw-wrapper and compare stdout, stderr and exit code.

Needs the fixture (test/fixture/up.sh + populate.sh) and an unlocked session:

    source test/fixture/env.sh
    export BITWARDENCLI_APPDATA_DIR=$ALICE_APPDATA
    export BW_SESSION=$(fixture_unlock alice)
    test/difftest.py [--jobs 8] [--no-cache] [--only SUBSTRING]

Real-CLI results are cached (they take seconds each); the cache is keyed by
command line and by the data file's last sync, so it survives re-runs only
while the vault is unchanged.
"""
import argparse, hashlib, json, os, pty, select, subprocess, sys, time, unicodedata
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.environ.get("REAL_BW") or sys.exit("REAL_BW not set (source test/fixture/env.sh)")
WRAP = os.environ.get("BWW_BIN", os.path.join(HERE, "..", "bw-wrapper"))
ROOT = os.environ.get("BITWARDENCLI_APPDATA_DIR") or sys.exit("BITWARDENCLI_APPDATA_DIR not set")
sys.path.insert(0, os.path.join(HERE, "fixture"))
import safety  # noqa: E402

try:
    safety.create_root("/tmp/bww-dev")
    ROOT = os.environ["BITWARDENCLI_APPDATA_DIR"] = safety.fixture_path(ROOT)
except safety.SafetyError as e:
    sys.exit(f"refusing to run against a non-fixture app-data dir: {e}")
os.environ.setdefault("BWW_RUNTIME_DIR", "/tmp/bww-dev/run")
os.environ["BWW_AUTO_LOCK"] = "0"  # the test's daemon must not lock the fixture session behind our back
os.makedirs(os.environ["BWW_RUNTIME_DIR"], mode=0o700, exist_ok=True)
CACHE = "/tmp/bww-dev/realcache"
os.makedirs(CACHE, exist_ok=True)


def run(argv0, args, env_extra=None, tty=False):
    env = dict(os.environ)
    for k in ("BW_PRETTY", "BW_RAW", "BW_RESPONSE", "BW_QUIET", "BW_CLEANEXIT", "FORCE_COLOR"):
        env.pop(k, None)
    env.update(env_extra or {})
    if argv0 == WRAP:
        cmd = [WRAP, "bw"] + args
    else:
        cmd = [REAL] + args
    if not tty:
        p = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, capture_output=True)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    mo, so = pty.openpty()
    me, se = pty.openpty()
    p = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=so, stderr=se)
    os.close(so)
    os.close(se)
    bufs = {mo: b"", me: b""}
    live = {mo, me}
    while live:
        r, _, _ = select.select(list(live), [], [], 120)
        if not r:
            break
        for fd in r:
            try:
                d = os.read(fd, 65536)
            except OSError:
                d = b""
            if d:
                bufs[fd] += d
            else:
                live.discard(fd)
    p.wait()
    os.close(mo)
    os.close(me)
    return p.returncode, bufs[mo].decode("utf-8", "replace"), bufs[me].decode("utf-8", "replace")


def real_cached(args, env_extra, tty, stamp, use_cache):
    key = hashlib.sha256(json.dumps([args, env_extra, tty, stamp, ROOT], sort_keys=True).encode()).hexdigest()
    path = os.path.join(CACHE, key)
    if use_cache and os.path.exists(path):
        return tuple(json.load(open(path)))
    res = run(REAL, args, env_extra, tty)
    json.dump(res, open(path, "w"))
    return res


def strip_marks(s):
    return "".join(c for c in unicodedata.normalize("NFD", s) if not unicodedata.combining(c))


def build_cases(items, trash, folders):
    cases = []  # (args, env, tty)
    add = lambda *a, env=None, tty=False: cases.append((list(a), env, tty))

    add("status"); add("status", "--pretty"); add("status", "--response"); add("--raw", "status")
    add("status", "--response", "--pretty"); add("status", "--quiet")
    for obj in ("items", "folders", "collections", "organizations"):
        add("list", obj); add("list", obj, "--pretty"); add("list", obj, "--response")
        add("list", obj, "--search", "e"); add("list", obj, "--search", "ZZnope")
        add("list", obj, "--search", " ")
    add("list", "items", "--response", "--pretty")
    add("list", "items", "--trash"); add("list", "items", "--archived"); add("list", "items", "--trash", "--archived")
    add("list", "items", "--trash", "--search", "e")
    for opt in ("--folderid", "--collectionid", "--organizationid"):
        for val in ("null", "notnull", "", "00000000-0000-0000-0000-000000000000"):
            add("list", "items", opt, val)
    add("list", "items", "--folderid", "null", "--organizationid", "notnull")
    add("list", "items", "--folderid", "notnull", "--search", "git")
    add("list", "items", "--folderid=notnull", "--trash")
    for f in folders:
        if f.get("id"):
            add("list", "items", "--folderid", f["id"])
            add("get", "folder", f["id"])
        add("get", "folder", f["name"]); add("get", "folder", f["name"][:3]); add("list", "folders", "--search", f["name"][:4].upper())
    add("get", "folder", "nope-nope"); add("get", "folder", "o"); add("get", "folder", "o", "--response")
    add("get", "folder", "00000000-0000-0000-0000-000000000000")
    add("list", "collections", "--organizationid", "00000000-0000-0000-0000-000000000000")
    add("get", "collection", "x"); add("get", "organization", "x")
    for url in ("https://github.com", "github.com", "https://example.com/login", "http://192.168.1.10:8443", "nothing.invalid"):
        add("list", "items", "--url", url)
        add("list", "items", "--url", url, "--pretty")
    add("list", "items", "--url", "https://github.com", "--search", "work")
    for t in ("item", "item.login", "item.card", "folder", "item-collections", "nope"):
        add("get", "template", t)
    add("get", "template", "item", "--pretty"); add("get", "template", "item", "--response")

    # every item, every way
    terms = set()
    for it in items + trash:
        iid = it["id"]
        for obj in ("item", "username", "password", "uri", "totp", "notes"):
            add("get", obj, iid)
        add("get", "item", iid.upper())
        terms.add(iid[:8]); terms.add(iid[:7]); terms.add(iid[:13])
        name = it.get("name") or ""
        terms.update({name, name.lower(), name.upper(), strip_marks(name), name.split(" ")[0] if name else ""})
        if len(name.split()) > 1:
            terms.add(" ".join(reversed(name.split())))
        login = it.get("login") or {}
        if login.get("username"):
            terms.add(login["username"]); terms.add(login["username"].split("@")[0])
        for u in login.get("uris") or []:
            if u.get("uri"):
                terms.add(u["uri"])
                host = u["uri"].split("://")[-1].split("/")[0]
                terms.add(host); terms.add(host.split(":")[0])
        for w in (it.get("notes") or "").split()[:3]:
            terms.add(w)
        for sect, keys in (("card", ("brand", "number")), ("identity", ("firstName", "lastName")), ("sshKey", ("keyFingerprint",))):
            for k in keys:
                val = (it.get(sect) or {}).get(k)
                if val:
                    terms.add(val); terms.add(val[-4:]); terms.add("*" + val[-4:])
    terms.update({"git", "GITHUB", "github work", "work   github", "  github  ", "cafe", "café", "CAFÉ", "muller",
                  "example.com", "example", "zzzznotfound", "", " ", "a", "e", "@", "*", "visa", "amex", "john",
                  "John Doe", "doe john", "\t", "naive resume", "日本", "🔑", "'", '"', "\\", "<", "&", "%", "192.168"})
    terms = sorted(terms)
    for t in terms:
        add("get", "item", t)
    for t in terms[::2]:
        add("list", "items", "--search", t)
    for i, t in enumerate(terms[::3]):
        add("get", ("username", "password", "uri", "notes", "totp")[i % 5], t)

    # output switches
    some = [it for it in items if (it.get("login") or {}).get("password")][:3]
    for it in some:
        for flags in (["--raw"], ["--pretty"], ["--response"], ["--response", "--pretty"], ["--quiet"], ["--cleanexit"]):
            add("get", "password", it["id"], *flags)
            add(*flags, "get", "item", it["id"])
        add("get", "item", it["id"], env={"BW_PRETTY": "true"})
        add("get", "item", it["id"], env={"BW_RESPONSE": "true"})
        add("get", "password", it["id"], env={"BW_QUIET": "true"})
        add("get", "password", it["id"], tty=True)
        add("get", "item", it["id"], tty=True)
    for flags in ([], ["--response"], ["--response", "--pretty"], ["--quiet"], ["--cleanexit"], ["--cleanexit", "--response"]):
        add("get", "item", "zzzznotfound", *flags)
        add("get", "password", "git", *flags)
    add("get", "item", "zzzznotfound", env={"BW_CLEANEXIT": "1"})
    add("get", "item", "zzzznotfound", tty=True)
    add("get", "password", "git", tty=True)
    add("get", "item", "zzzznotfound", env={"FORCE_COLOR": "1"})
    add("get", "item", "zzzznotfound", env={"FORCE_COLOR": "0"}, tty=True)
    add("list", "folders", tty=True); add("status", tty=True)

    # things the wrapper must hand to the real CLI untouched
    add("get", "nonsense", "x"); add("list", "nonsense"); add("get", "item"); add("list")
    add("get", "item", "a", "b"); add("list", "items", "--bogus"); add("get", "fingerprint", "me")
    add("list", "items", "--search"); add("status", "extra")
    add("--version"); add("get", "--help"); add("sync", "--last")

    seen, out = set(), []
    for c in cases:
        k = json.dumps(c, sort_keys=True)
        if k not in seen:
            seen.add(k); out.append(c)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--only")
    ap.add_argument("--max-fail", type=int, default=25)
    a = ap.parse_args()

    st = json.loads(run(REAL, ["status"])[1])
    if st.get("status") != "unlocked":
        sys.exit("vault is not unlocked: set BW_SESSION")
    stamp = st["lastSync"]
    items = json.loads(run(REAL, ["list", "items"])[1])
    trash = json.loads(run(REAL, ["list", "items", "--trash"])[1])
    folders = json.loads(run(REAL, ["list", "folders"])[1])
    cases = build_cases(items, trash, folders)
    if a.only:
        cases = [c for c in cases if a.only in " ".join(c[0])]
    print(f"{len(cases)} cases, {len(items)} items, {len(trash)} in trash", flush=True)

    t0 = time.time()
    with ThreadPoolExecutor(a.jobs) as ex:
        reals = list(ex.map(lambda c: real_cached(c[0], c[1], c[2], stamp, not a.no_cache), cases))
    t_real = time.time() - t0
    run(WRAP, ["status"])  # make sure the daemon is warm before timing
    t0 = time.time()
    wraps = [run(WRAP, c[0], c[1], c[2]) for c in cases]
    t_wrap = time.time() - t0

    fails = 0
    for c, r, w in zip(cases, reals, wraps):
        if r == w:
            continue
        if c[0][:2] == ["get", "totp"] and r[0] == 0 and w[0] == 0:
            # codes roll over (also between the two runs): compare back to back, a few times
            for _ in range(4):
                r, w = run(REAL, c[0], c[1], c[2]), run(WRAP, c[0], c[1], c[2])
                if r == w:
                    break
            if r == w:
                continue
        fails += 1
        if fails <= a.max_fail:
            print(f"\nMISMATCH bw {' '.join(map(repr, c[0]))} env={c[1]} tty={c[2]}")
            for label, i in (("exit", 0), ("stdout", 1), ("stderr", 2)):
                if r[i] != w[i]:
                    print(f"  {label}: real={r[i]!r:.600}\n  {' ' * len(label)}  wrap={w[i]!r:.600}")
    subprocess.run([WRAP, "stop"], capture_output=True)
    print(f"\n{len(cases) - fails}/{len(cases)} identical; real CLI {t_real:.1f}s ({a.jobs} jobs), wrapper {t_wrap:.2f}s sequential "
          f"({1000 * t_wrap / max(len(cases), 1):.1f} ms/cmd)")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
