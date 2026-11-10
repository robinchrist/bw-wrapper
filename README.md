# bw-wrapper

A drop-in wrapper for the Bitwarden CLI (`bw`) that answers from memory.

The real `bw` starts Node.js and decrypts the vault on every call, which
takes seconds. bw-wrapper keeps the unlocked vault in a small daemon, so
`bw get`, `bw list` and `bw status` return in milliseconds with the same
output and exit code. Everything else goes to the real CLI. It is read-only
unless you allow writes.

| command (3001 items, bw 2026.10.1) | real `bw` | bw-wrapper |
|---|---|---|
| `get password <name>` | 3899 ms | 2.3 ms |
| `list items --search …` | 3744 ms | 1.9 ms |
| `list items` (all) | 3727 ms | 5.2 ms |

The first command after `bw unlock` waits for the vault to load once (about
2 s). `test/bench.py` reproduces the numbers.

## Why

- The Bitwarden CLI is unbearably slow. Several seconds per lookup makes it
  unusable for integrations that call it often, for example XPipe.
- Most of that time is not work. On bw 2026.10.1, about 2 s of every call is
  the CLI waiting for two internal 1 s timers before it exits: `bw status`
  takes 2.6 s, and 0.6 s with those timers out of the way. On top of that, a
  lookup by name decrypts the whole vault on every call.
- Alternative clients such as rbw reimplement Bitwarden's protocol and data
  handling, and have had bugs that corrupt data on write.

So this is a wrapper, not another client: the official CLI still does every
login, sync, decryption and write. bw-wrapper only remembers its answers.

## Install

Needs Go ≥ 1.24, Linux or macOS (macOS is untested), and the real Bitwarden
CLI on `PATH`.

```
make install    # ~/.local/bin/bw-wrapper and ~/.local/bin/bw -> bw-wrapper
```

`~/.local/bin` must come before the real `bw` on `PATH`. The install refuses
to replace an existing `bw` that is not its own link. `bw-wrapper config`
shows which real CLI it found. Details: [docs/install.md](docs/install.md).

## Use

Use `bw` as before:

```
export BW_SESSION=$(bw unlock --raw)
bw get password github        # from memory
bw list items --search aws    # from memory
bw lock                       # wipes the daemon, then locks
```

```
bw-wrapper status             # running daemons
bw-wrapper stop               # wipe and stop them (does not lock)
BWW_DISABLE=1 bw …            # bypass the wrapper for one command
```

## Good to know

- Each vault directory and session key gets its own daemon; they never see
  each other's data.
- `bw lock` and `bw logout` end access in every shell that uses that vault,
  and the wrapper stays locked if the real lock fails.
- After 15 minutes without use the vault is locked (`auto_lock`).
- `create`, `edit`, `delete` and other writes are refused unless
  `allow_writes = true`.
- Optional hold mode keeps reading possible when the server ends your login
  session (for example an expired SSO session).

## What is still slow

The daemon gets the vault from the real CLI, so some things still take the
real CLI's time:

- The first load after `bw unlock`, and a reload after `bw sync` or when the
  vault changed behind the wrapper's back (about 2 s).
- Once each, then from memory: `list items --url …` per distinct URL,
  `get template …`, and the first `get totp` (to learn whether TOTP is
  allowed).
- Every time: `get attachment`, `get exposed`, `get fingerprint`, `get send`,
  `list org-collections`, `list org-members`, `export`, and
  `get organization` by search term.
- Every time: passwords of items in a collection with hidden passwords, a
  lookup by an id that is not in memory, and any command line the wrapper
  does not understand exactly.

Full table: [docs/commands.md](docs/commands.md).

## Security

The trade-off is the same as with `bw serve`: while a session is unlocked,
the decrypted vault sits in the memory of a process that runs as you.

- Secrets are kept encrypted in the daemon's memory under a per-process key.
  That is obfuscation against memory scraping, not protection: the key is in
  the same process. Root, or anything that can read that process, can read
  the vault.
- A request is answered only with the right session key, over a unix socket
  in a directory only you can open. The daemon stores a hash of the key, not
  the key.
- `bw lock`, `bw logout` and auto-lock wipe the memory and end the daemon.
- On Linux the daemon cannot be core-dumped or ptraced by your other
  processes.
- The wrapper keeps no secrets of its own on disk. Its files in
  `<vault dir>/.bw-wrapper/` and its daemon log contain none. (Hold mode,
  if you turn it on, can put back the CLI's own data file.)

More: [docs/security.md](docs/security.md).

## Configuration

`~/.config/bw-wrapper/config`; each setting also has a `BWW_…` environment
variable:

```
# 0 = never
auto_lock = 15m
allow_writes = false
hold = false
```

All settings: [docs/configuration.md](docs/configuration.md).

## Documentation

- [How it works](docs/how-it-works.md)
- [Commands](docs/commands.md): what is answered from memory, what is
  refused, differences from the real CLI
- [Sessions](docs/sessions.md): lock, logout, unlock, sync, auto-lock
- [Hold mode](docs/hold-mode.md)
- [Security notes](docs/security.md)
- [Process lifecycle](docs/LIFECYCLE.md): the full coordination rules
- [Development and tests](docs/development.md)

## License

[Mozilla Public License 2.0](LICENSE).
