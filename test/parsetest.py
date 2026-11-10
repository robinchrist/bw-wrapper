#!/usr/bin/env python3
"""Differential test of the wrapper's command-line parser against the real CLI.

    source test/fixture/env.sh
    test/parsetest.py [--jobs 12]

For every command line below, the wrapper says how it reads it
(`bw-wrapper classify`), and the real CLI is run with the same arguments on
an empty, logged-out fixture root, where it can only do one of two things:
print help or its version ("info"), or get as far as running the command
(which then fails with "You are not logged in." or an argument error).

Checked:
  1. the wrapper never takes a line for help that the CLI runs (that would
     skip every check the wrapper makes);
  2. when the wrapper claims to understand a line exactly, it agrees with
     the CLI about help in both directions.
Lines the wrapper does not understand exactly are allowed to be read
cautiously (as a command) although the CLI prints help or an error.

No vault is involved: the root is created empty under /tmp/bww-dev and points
at the local fixture server. Lines that would contact a server (login with
credentials, update, receive, serve) are not in the list.
"""
import argparse, concurrent.futures, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REAL = os.environ.get("REAL_BW") or sys.exit("REAL_BW not set (source test/fixture/env.sh)")
WRAP = os.path.abspath(os.path.join(HERE, "..", "bw-wrapper"))
sys.path.insert(0, os.path.join(HERE, "fixture"))
import safety  # noqa: E402

try:
    safety.create_root("/tmp/bww-dev")
    ROOT = safety.fixture_path("/tmp/bww-dev/parse-root")
    URL = safety.fixture_url(os.environ.get("BWW_FIXTURE_URL", "https://127.0.0.1:18087"))
except safety.SafetyError as e:
    sys.exit(f"parsetest.py: {e}")

LINES = """
|--help|-h|--version|-v|help|help get|--pretty|--|-- --help
get --help|get -h|list items -h|list items --help|status --help|unlock --help|create --help|delete -h
send --help|send help|send list --help|send get --help|device-approval --help|device-approval list --help
get password x --output f --help|delete item id --help|--help create folder x|unlock --check --help
create -v|get password x --output -v|unlock --passwordenv --version|list items --search x -v
get password example --output --help|get password x --itemid -h|get password x --output=--help
list items --search --help|list items --search=--help|list items --url -h|list items --folderid --help
get item -- -h|get item -- --help|sync -- --help|export --format --help|export --output -h
unlock --passwordenv --help|unlock --passwordfile -h|unlock -- --help|unlock --passwordenv --check
unlock --check|login --check|unlock --passwordenv X --check|login --sso --check|unlock -- --check
unlock --passwordenv A --passwordenv --check|login --passwordfile --check|login --code -h
create attachment --file --help --itemid x|send -n -h text|send --name --help text|send -d -h x|send -fn -h x
delete item -- --help|-- delete item id|--pretty -- create folder x|-- get item x|-- status
get password x --frob --help|list items --bogus|list items --bogus --help|get password x --output
delete item x --frob --help|send --frob list|send list --frob|device-approval list --frob
--frob get password x|--frob --help|--foo=bar delete item x|-x delete item x|brandnewcommand|brandnewcommand --help
brandnewcommand --opt --help|Create folder x|list items --trash=1|list items --trash --help|status extra
get item|get item a b|get|list|send -n list text|send --hidden list|send list|send template send.text
generate -lusn|generate --length --help|generate --length 20 --help|generate -p --words 3|encode|sdk-version
completion --shell zsh|completion --shell --help|config server|config --help|sync --last|sync -f --help|sync -fh
list items --search a --search b|list --search x items|list items --session S --help|--session --help get item x
get password x --session|--raw --quiet status|lock --help|logout --help|lock -h extra|import --formats
import --formats --help|import --passwordenv --help f p|export --password --help|export --password -h
login --sso -- --check|login --sso --help|login --apikey --help|login --method --help --check
send help|send help list|device-approval|device-approval help|device-approval help list|--raw device-approval
device-approval frob|device-approval frob --help|send -- help|help send|help brandnew|help help|send --hidden help
""".strip("\n").replace("\n", "|").split("|")

VERSION = re.compile(r"^\d{4}\.\d+\.\d+\s*$")


def env():
    e = {k: v for k, v in os.environ.items() if not k.startswith(("BW_", "BWW_"))}
    e.update(BITWARDENCLI_APPDATA_DIR=ROOT, BW_NOINTERACTION="true")
    return e


def one(line):
    args = line.split()
    w = subprocess.run([WRAP, "classify", *args], capture_output=True, text=True, env=env())
    cls, exact = w.stdout.split()
    try:
        r = subprocess.run([REAL, *args], capture_output=True, text=True, env=env(), stdin=subprocess.DEVNULL, timeout=120)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    info = "Usage:" in out or bool(VERSION.match(r.stdout))
    return line, cls, exact == "exact=true", info, out.strip().splitlines()[0][:70] if out.strip() else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=12)
    a = ap.parse_args()
    shutil.rmtree(ROOT, ignore_errors=True)
    os.makedirs(ROOT, mode=0o700)
    subprocess.run([REAL, "config", "server", URL], capture_output=True, env=env(), check=True)
    bad = cautious = 0
    with concurrent.futures.ThreadPoolExecutor(a.jobs) as ex:
        for line, cls, exact, info, first in ex.map(one, LINES):
            verdict = "ok"
            if cls == "info" and not info:
                verdict = "FAIL: wrapper takes it for help, the CLI runs it"
            elif exact and info and cls != "info":
                verdict = "FAIL: wrapper claims an exact reading, but the CLI prints help"
            elif info and cls != "info":
                verdict = "cautious"
                cautious += 1
            if verdict.startswith("FAIL"):
                bad += 1
            if verdict != "ok":
                print(f"{verdict:9} bw {line!r}: wrapper {cls} exact={exact}, CLI: {'info' if info else 'runs'} [{first}]")
    print(f"\n{len(LINES)} command lines, {bad} disagreements, {cautious} read cautiously (not understood exactly)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
