#!/usr/bin/env python3
"""Benchmark retrieval through bw-wrapper against the real Bitwarden CLI.

    source test/fixture/env.sh
    export BITWARDENCLI_APPDATA_DIR=<fixture root> BW_SESSION=<session key>
    test/bench.py [--real-runs 5] [--wrap-runs 200] [--label NAME]

Each command is timed as a full process run (spawn to exit, output captured),
which is what a calling script sees. Outputs of both sides are compared, so a
fast wrong answer shows up as a mismatch instead of a good number.
"""
import argparse, json, os, statistics, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.environ.get("REAL_BW") or sys.exit("REAL_BW not set (source test/fixture/env.sh)")
WRAP = os.path.abspath(os.path.join(HERE, "..", "bw-wrapper"))
ROOT = os.environ.get("BITWARDENCLI_APPDATA_DIR") or sys.exit("BITWARDENCLI_APPDATA_DIR not set")
sys.path.insert(0, os.path.join(HERE, "fixture"))
import safety  # noqa: E402

try:
    safety.create_root(safety.DEV_ROOT)
    ROOT = os.environ["BITWARDENCLI_APPDATA_DIR"] = safety.fixture_path(ROOT)
except safety.SafetyError as e:
    sys.exit(f"refusing to run against a non-fixture app-data dir: {e}")
os.environ.setdefault("BWW_RUNTIME_DIR", safety.DEV_ROOT + "/run-bench")
# The developer's own ~/.config/bw-wrapper/config must not change the results.
os.environ["BWW_CONFIG"] = safety.DEV_ROOT + "/no-config"
os.makedirs(os.environ["BWW_RUNTIME_DIR"], mode=0o700, exist_ok=True)
os.environ["BWW_AUTO_LOCK"] = "0"


def timed(cmd):
    t0 = time.perf_counter()
    p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True)
    return time.perf_counter() - t0, p.returncode, p.stdout


def real(*args):
    return timed([REAL, *args])


def wrap(*args):
    return timed([WRAP, "bw", *args])


def fmt(sec):
    ms = sec * 1000
    return f"{ms:.0f} ms" if ms >= 100 else f"{ms:.1f} ms"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real-runs", type=int, default=5)
    ap.add_argument("--wrap-runs", type=int, default=200)
    ap.add_argument("--label", default=os.path.basename(ROOT))
    a = ap.parse_args()

    subprocess.run([WRAP, "stop"], capture_output=True)
    t_cold, rc, out = wrap("list", "items")
    if rc != 0:
        sys.exit("wrapper could not list items: is BW_SESSION valid?")
    items = json.loads(out)
    folders = [f for f in json.loads(wrap("list", "folders")[2]) if f.get("id")]

    def pick(pred):
        return next((i for i in items if pred(i)), None)

    login = pick(lambda i: (i.get("login") or {}).get("password") and (i.get("login") or {}).get("username")
                 and sum(1 for j in items if i["name"].lower() in (j.get("name") or "").lower()) == 1 and i["name"].isascii())
    with_totp = pick(lambda i: (i.get("login") or {}).get("totp", "").isalnum())
    with_uri = pick(lambda i: any("://" in (u.get("uri") or "") and "." in (u.get("uri") or "") for u in (i.get("login") or {}).get("uris") or []))
    with_notes = pick(lambda i: (i.get("notes") or "").strip())
    word = login["name"].split()[0].lower()

    cases = [
        ("get password <name>", ["get", "password", login["name"]]),
        ("get password <id>", ["get", "password", login["id"]]),
        ("get username <name>", ["get", "username", login["name"]]),
        ("get item <id>", ["get", "item", login["id"]]),
        ("get item <name> --pretty", ["get", "item", login["name"], "--pretty"]),
        ("get item <no match>", ["get", "item", "zz-no-such-entry-zz"]),
    ]
    if with_notes:
        cases.append(("get notes <id>", ["get", "notes", with_notes["id"]]))
    if with_totp:
        cases.append(("get totp <id>", ["get", "totp", with_totp["id"]]))
    cases += [
        (f"list items --search {word}", ["list", "items", "--search", word]),
    ]
    if folders:
        cases.append(("list items --folderid <id>", ["list", "items", "--folderid", folders[0]["id"]]))
    if with_uri:
        uri = next(u["uri"] for u in with_uri["login"]["uris"] if "://" in (u.get("uri") or ""))
        cases.append(("list items --url <url> (2nd call on)", ["list", "items", "--url", uri]))
    cases += [
        ("list items (everything)", ["list", "items"]),
        ("list folders", ["list", "folders"]),
        ("status", ["status"]),
    ]

    print(f"### {a.label}: {len(items)} items, real CLI {a.real_runs} runs, wrapper {a.wrap_runs} runs per command\n")
    print("| command | real `bw` median (min–max) | bw-wrapper median (p95, max) | speedup | same output |")
    print("|---|---|---|---|---|")
    tot_real = tot_wrap = 0.0
    for label, args in cases:
        wrap(*args)  # warm (and fill the memo for --url / totp)
        rs = [real(*args) for _ in range(a.real_runs)]
        ws = [wrap(*args) for _ in range(a.wrap_runs)]
        rt = sorted(r[0] for r in rs)
        wt = sorted(w[0] for w in ws)
        same = "yes" if (rs[0][1], rs[0][2]) == (ws[0][1], ws[0][2]) else "NO"
        if "totp" in label:
            r2, w2 = real(*args), wrap(*args)  # codes roll over; compare back to back
            same = "yes" if (r2[1], r2[2]) == (w2[1], w2[2]) or (real(*args)[2] == wrap(*args)[2]) else "NO"
        rmed, wmed = statistics.median(rt), statistics.median(wt)
        tot_real += rmed
        tot_wrap += wmed
        p95 = wt[int(len(wt) * 0.95) - 1]
        print(f"| `{label}` | {fmt(rmed)} ({fmt(rt[0])}–{fmt(rt[-1])}) | {fmt(wmed)} ({fmt(p95)}, {fmt(wt[-1])}) | {rmed / wmed:,.0f}× | {same} |", flush=True)
    print(f"| **all {len(cases)} commands once** | **{fmt(tot_real)}** | **{fmt(tot_wrap)}** | **{tot_real / tot_wrap:,.0f}×** | |")

    # cold start and process overhead, for context
    t_true = statistics.median(sorted(timed(["/bin/true"])[0] for _ in range(100)))
    print(f"\n- Cold start (no daemon yet; first `list items` loads the vault through the real CLI): {fmt(t_cold)}")
    print(f"- Spawning any process from this harness (`/bin/true`): {fmt(t_true)} — included in every number above")


if __name__ == "__main__":
    main()
