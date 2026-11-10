# How it works

One binary plays three roles, chosen by the name it is invoked under:

| invoked as | role |
|---|---|
| `bw` | drop-in client |
| `bw-wrapper` | management (`status`, `stop`, `config`) |
| (internal) | daemon, one per (CLI root, session key) |

1. `bw unlock` / `bw login` run the real CLI. The wrapper reads the new session
   key from its output, stops the daemons of the sessions that unlock just
   invalidated, and starts a daemon for the new one.
2. The daemon loads the vault once through the real CLI (items in every
   state, folders, collections, organizations, status) and keeps the result in
   memory. On Linux it runs one short-lived `bw serve` on a private unix
   socket for this and kills it when the load is done; elsewhere, or if that
   fails, it runs the equivalent `bw list …` commands. It never decrypts
   Bitwarden's data file itself, so it does not depend on Bitwarden's crypto
   formats.
3. `bw get …`, `bw list …`, `bw status` go to the daemon over a unix socket and
   are answered with the same bytes and exit code the real CLI would produce.
4. If no daemon runs for a session yet, the first command starts one (that
   command pays the load time once).
5. Any command line the wrapper does not fully understand is executed by the
   real CLI, so errors and help texts are the real ones.

## Routing: roots and sessions

A daemon belongs to exactly one *CLI root* (the Bitwarden CLI data directory:
`BITWARDENCLI_APPDATA_DIR`, else the platform default; symlinks are resolved,
so every spelling of a directory is the same root) and one *session key*
(`BW_SESSION` or `--session`). The daemon verifies the session key of every
request. Different roots and different sessions never see each other's data;
several can run side by side:

```
$ bw-wrapper status
pid 41250   me@example.com         812 items    up 3m12s    auto-lock: lock in 11m48s   /home/me/.config/Bitwarden CLI
pid 41377   ops@example.com        3003 items   up 41s      auto-lock: lock in 14m19s   /home/me/.config/bw-ops
```

A command without a session key goes to the real CLI, exactly as before.

## One place per vault: `<root>/.bw-wrapper/`

Everything that has to be agreed on between shells is kept inside the CLI
root, in a private directory (mode 0700, no credentials in it): which daemon
serves which session, the session protocol state described in [sessions.md](sessions.md), and the
lock for session commands. A desktop shell, an ssh session and a cron job
have different runtime directories, but they share the root, so they share
this state:

- a shell finds the daemon of its session wherever that daemon's socket is;
- `bw lock` or `bw logout` in one of them ends access in all of them.

If that directory cannot be used, it depends on why:

- It does not exist and cannot be created (a read-only root). Then nothing
  was ever recorded for this root. Commands go to the real CLI; nothing is
  answered from memory and nothing is restored.
- It exists but cannot be used (wrong owner or mode, a damaged state file, a
  lock file that cannot be opened). Then the wrapper does not know whether a
  lock or logout is in force, and what it does not know it treats as "yes":
  every command that would use a session is refused with `Vault is locked.`,
  and `bw login` / `bw unlock` are not run, until the directory is repaired
  or removed. `bw lock` / `bw logout` still run the real command.
