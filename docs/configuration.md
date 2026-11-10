# Configuration

`~/.config/bw-wrapper/config` (or `$XDG_CONFIG_HOME/bw-wrapper/config`, or the
file named by `BWW_CONFIG`); every setting has an environment override.

```
# Idle time before the daemon locks. Go duration or seconds, at least 1s;
# 0/never disables. (Values below one second are rejected.)
auto_lock = 15m

# lock  = wipe memory and run the real `bw lock` (session key becomes invalid)
# evict = only wipe memory; the session key stays valid and the next command
#         loads the vault again
auto_lock_action = lock

# The real Bitwarden CLI: a path (made absolute) or a name to look up on PATH.
# Default: the next `bw` on PATH. It must not be bw-wrapper itself.
# real_bw = /usr/bin/bw

# Pass create/edit/delete/... through to the real CLI (default: refuse).
allow_writes = false

# Start the daemon right after unlock/login instead of on first use.
preload = true

# Load the vault through one temporary `bw serve` process (fast; Linux only).
# false uses eight separate `bw list …` runs (2-5 times slower cold start).
load_via_serve = true

# Extra environment variables the daemon may keep (see security.md).
# pass_env = MY_CA_BUNDLE,SOME_OTHER_VAR

# Keep read access when the server ends the login session (see hold-mode.md).
hold = false
# How long a daemon keeps a vault whose session is gone on disk. 0 = no limit.
hold_max = 12h
```

| setting | environment |
|---|---|
| `auto_lock` | `BWW_AUTO_LOCK` |
| `auto_lock_action` | `BWW_AUTO_LOCK_ACTION` |
| `real_bw` | `BWW_REAL_BW` |
| `allow_writes` | `BWW_ALLOW_WRITES` |
| `preload` | `BWW_PRELOAD` |
| `load_via_serve` | `BWW_LOAD_VIA_SERVE` |
| `pass_env` | `BWW_PASS_ENV` |
| `hold` | `BWW_HOLD` |
| `hold_max` | `BWW_HOLD_MAX` |
| `debug` | `BWW_DEBUG` (prints routing decisions to stderr) |

Changed `auto_lock` and `hold` settings reach a running daemon with the next
command.
