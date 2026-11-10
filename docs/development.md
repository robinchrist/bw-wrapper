# Development

```
make test                      # unit tests
test/fixture/up.sh             # local Vaultwarden + two test accounts (docker)
test/fixture/populate.sh       # fill the test vaults
source test/fixture/env.sh
export BITWARDENCLI_APPDATA_DIR=$ALICE_APPDATA BW_SESSION=$(fixture_unlock alice)
test/difftest.py               # ~2000 command lines: wrapper vs real CLI, byte for byte
test/lifecycle.py              # unlock, routing, lock, sync, auto-lock, read-only gate, hold mode
test/parsetest.py              # how command lines are read: wrapper vs real CLI (no vault involved)
test/bench.py                  # timings against the real CLI
```

`make test` also runs process-level tests against a stand-in CLI (ordering of
lock, logout, unlock, reads and auto-lock across shells, with explicit
barriers) and the fixture's own safety checks. The fixture tools validate
through `test/fixture/safety.py` before they open a file or make a request.
A fixture directory is trusted for what it is, not for its name: it must be a
real directory owned by you (not a symbolic link, not reached through one)
that carries the marker `up.sh` puts there, so an allowed name redirected
onto a real vault is refused. Nothing between it and a file may be a
symbolic link, and files are read and replaced through that one module. The
server URL is parsed and must be the local fixture origin; redirects
elsewhere are refused.
