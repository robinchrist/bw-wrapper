# Commands: what is answered from memory, what is refused, what differs

## Read-only

By default the wrapper refuses every command that can change the vault:
`create`, `edit`, `delete`, `restore`, `move`, `share`, `confirm`, `import`,
`archive`, `send` (except `list`/`get`/`template`/`receive`),
`device-approval` (except `list`), `serve`, and any command it does not know.
The error has the real CLI's format and exit code 1. `bw <command> --help`
still works for these commands.

How a command line is read: once, by a port of the CLI's own argument parser
(commander) with the table of commands and options of bw 2026.10.1. Every
decision (help or not, write or not, which variable holds a password, can the
daemon answer) comes from that one reading. `bw get password x --output
--help` is a password lookup, because `--help` is the value of `--output`,
and is treated as one. Where a line contains something the table does not
know (an option of a newer CLI), the cautious reading applies: it is not
help, it may be a write, and it needs an open session state. If not even the
command can be told for certain (`bw --newflag logout`, a command the table
does not have), the line is not run at all, also with `allow_writes`: it
could be a session command that must not bypass the [session protocol](sessions.md). Put
global options after the command, or use `BWW_DISABLE=1` for that call.
`test/parsetest.py` compares the reading with the real CLI.

With `allow_writes = true` these are passed to the real CLI and the daemon
reloads afterwards.

## What is answered from memory

| command | from memory |
|---|---|
| `status` | yes |
| `list items` with `--search`, `--folderid`, `--collectionid`, `--organizationid`, `--trash`, `--archived` | yes (`--archived` on an account that cannot archive: real CLI) |
| `list items --url …` | real CLI once per distinct query, then from memory until the next reload |
| `list folders`, `list collections`, `list organizations` | yes |
| `get item`, `username`, `password`, `uri`, `notes`, `folder`, `collection` | yes |
| `get totp` | yes, after one real call per vault/organization to learn whether TOTP is allowed (premium) |
| `get organization <id>` | yes (`<search>` goes to the real CLI) |
| `get template …` | real CLI once, then from memory |
| `get attachment`, `get exposed`, `get fingerprint`, `get send`, `list org-collections`, `list org-members`, everything else | real CLI |

Lookups by id that miss the cache go to the real CLI too, so the answer is
never a guess. If an answer from memory cannot be written (disk full, output
closed), the command fails with exit code 1.

## Differences from the real CLI

- Organization event logs: the real CLI reports "item viewed" events to the
  server; answers from memory do not.
- A login in an organization collection with hidden passwords is answered by
  the real CLI for `get password` / `get totp`.
- After `auto_lock` the session key is invalid (with `auto_lock_action =
  lock`); the real CLI never expires a session. This holds without a running
  daemon too: the first command after the idle time locks.
- In hold mode, commands answered by the real CLI run one at a time per root.
- `bw status` reports `locked` while a lock or logout is in progress or did
  not succeed, even if the real CLI on its own would still say `unlocked`.
- `bw --help` and other commands that need no vault wait while a
  `bw lock` / `bw logout` runs, and are stopped by one if they are still
  running 10 seconds into it.
- If `<root>/.bw-wrapper/` exists but is unusable, commands that use a
  session are refused instead of passed on.
- A command line with an option the wrapper does not know is not treated as
  `--help`, even if it ends in `--help`; unless it is a plain read command it
  is refused in read-only mode. A line whose command the wrapper cannot
  determine is refused in every mode.
- The wrapper creates `<root>/.bw-wrapper/` inside the CLI's data directory.
- `bw lock` and `bw logout` cancel a `bw login` / `bw unlock` that is running
  or waiting in another shell.
- `bw lock` and `bw logout` wait for (and after 10 seconds stop) commands
  that the real CLI is still answering with the old session.
- After a `bw lock` / `bw logout` whose real command failed, the wrapper
  answers `Vault is locked.` itself until a lock succeeds or you unlock again.
