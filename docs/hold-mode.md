# Hold mode: keep reading when the server ends the session

Off by default. Meant for setups where login sessions end early or
unexpectedly (for example an SSO session that timed out).

When a login session has ended on the server, the next `bw` command that
needs the server fails to renew its token, and the real CLI then logs itself
out: it erases its keys and the local vault. From that moment nothing can be
read until you log in again. With `hold = true` the wrapper works against
that in three places:

1. **Refusal.** `bw sync` (and write commands, if you allowed them) is not run
   at all when the stored refresh token is already past its own expiry. You
   get an error that says so, and the local vault stays as it is.
2. **Restore.** Not every ended session is visible locally (the identity
   provider may have ended it earlier). So every real-CLI run is bracketed by
   a snapshot of the CLI's data file. If the run ends with the CLI logged out,
   the snapshot is put back: the CLI is logged in and unlocked again with the
   same session key, reading keeps working, and it even survives a daemon
   restart or reboot. Real-CLI runs that the wrapper starts on one root do
   not overlap a run that holds such a snapshot (in hold mode they run one
   at a time), so what is put back is always the newest state a wrapper-run
   command left, never an older one that would undo a sync.
3. **Hold.** If the real CLI was run directly (not through the wrapper) and
   logged itself out, the daemon keeps answering from memory instead of
   wiping itself. `bw-wrapper status` shows `HOLDING`. This lasts until
   `hold_max` (default 12h), a lock, or the daemon stopping.

The daemon holds in one more case: the vault changed on disk and loading it
again fails (the server cannot be reached, the CLI errors). The vault in
memory then stays marked as not current: `bw-wrapper status` shows `HOLDING`,
the reload is tried again (at most every 30 seconds), and `hold_max` applies.
It never silently becomes "the current vault". Without hold mode a daemon
that cannot reload gives up its vault at once.

What still ends access immediately, also in hold mode: `bw lock` and
`bw logout` through the wrapper, auto-lock, `bw-wrapper stop`, and a lock or a
new unlock done with the real CLI directly.

A restore never crosses a session command, and neither does holding. A
restore applies only if generation and epoch are still the ones its snapshot
was taken under, access is open and no session command is running; a daemon
holds only under the same conditions. So `bw lock`, `bw logout`, `bw unlock`
and `bw login` through the wrapper, from any shell, cancel every pending
restore and end every hold for that root; a command that was running when you
logged out cannot bring the old login back.

What you accept by turning it on:

- Read access outlives the server's session limit. If your access was revoked
  on the server (removed from a collection, account disabled), the secrets
  you had synced stay readable until lock or `hold_max`.
- The data is frozen at the last successful sync.
- Anything that needs the server keeps failing until you log in again:
  `sync`, attachments, writes.
- While holding, `bw status` answers `unlocked` from memory although the real
  CLI on disk is logged out.
- A `bw logout` done with the real CLI directly cannot be told apart from the
  CLI logging itself out, so the daemon holds through it. Use `bw logout`
  through the wrapper, or `bw-wrapper stop`.
- The restore only knows about commands that went through the wrapper. If the
  real CLI is run directly and changes the data file while a wrapper-run
  command is in flight, and that command then logs itself out, the restore
  puts back the state from before both. Do not mix direct `bw sync` with
  hold mode.
- Real-CLI runs on one root are serialized (hold mode), so several commands
  that the daemon cannot answer take their turns. A command gives up with an
  error if the run before it has not ended after 5 minutes.
