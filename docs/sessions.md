# Sessions: lock, logout, unlock, auto-lock

## Lock, logout, unlock: the session protocol

The complete rule set (every place a real CLI is started, the locks, their
order, who cancels whom, and the test for each case) is in
[LIFECYCLE.md](LIFECYCLE.md). This section is the user's view.

`lock`, `logout`, `login` and `unlock` are *session commands*. The state they
share per root:

| part | meaning |
|---|---|
| cache generation | A loaded vault belongs to one generation and is answered from only while that generation is current. |
| revocation epoch | Advanced by every lock and logout. A login or unlock belongs to the epoch it was requested under. |
| access | `open`, `revoking` (a lock or logout has begun) or `blocked` (it began and did not succeed). |
| pending revocations | A lock or logout is *pending* from its first step until it has recorded its outcome. |

**Admission.** Whether a command may use an existing session is decided in
one place, for answers from memory and for the real CLI alike. The outcome is
*allowed*, *denied* or *unknown*, and unknown is treated as denied. A command
is denied while a lock or logout is pending, and while access is not open and
a usable session is still on disk. An admitted command holds a *lease* until
its process has ended, that is, until its output is written.

**`bw lock` / `bw logout`** (and auto-lock, which runs the same sequence):

1. *Revoke.* In one step: the revocation is pending, new epoch, access no
   longer open, new generation. From this moment, in every shell: no cached
   vault of this root answers, no daemon loads one, no hold-mode restore
   applies, no command is admitted, and every login or unlock requested
   earlier is cancelled, whether it is running or still waiting its turn. A
   login or unlock requested *later* waits until this lock or logout is
   finished: the revocation has its place in the order from here on, not
   only once it gets to run.
2. *Take the operation lock.* One session command runs at a time per root. A
   `login` or `unlock` still running in another shell (sitting at its password
   prompt) is told to stop; lock/logout waits until it and its real CLI are
   gone, and kills them after 5 seconds (on Linux that includes a real CLI
   left behind by a wrapper that was killed; the recorded owner is only
   signalled if pid and start time still match). Another lock or logout that
   is running is not interrupted; this one waits for it. If the wait exceeds
   30 seconds, lock/logout fails; access stays revoked.
3. *Wipe.* The root's daemons wipe their memory and confirm.
4. *Wait for the leases.* Commands admitted before step 1 may still be
   running: a `bw export` in the real CLI, or a `bw list items` that got its
   answer from the daemon and is still writing it into a slow pipe.
   Lock/logout waits for them, 10 seconds at most, then stops them. (If one
   cannot be stopped, lock/logout says so and exits with an error although
   the vault is locked.) Nothing is printed by them after lock/logout has
   returned.
5. *Run the real command*, holding the operation lock and the pending
   revocation (the real CLI inherits both, so they last as long as it does,
   even if the wrapper is killed).
6. *Record the outcome*, as the CLI's data file shows it. The exit code is
   not evidence: with `--cleanexit` or `BW_CLEANEXIT` the CLI exits 0 after a
   failure. If no usable session is left on disk, access is open again and
   the real CLI answers for itself ("Vault is locked.", "You are not logged
   in."). If a usable session is left, access stays **blocked** and
   lock/logout exits with an error.

While access is blocked, `bw get`, `bw list`, `bw sync`, `bw export` and
everything else that needs the vault are answered by the wrapper with
`Vault is locked.` and are not passed on. That state is on disk: it holds for
every shell and survives restarts. It ends when a later `bw lock` /
`bw logout` succeeds, or when a `bw login` / `bw unlock` that was requested
*after* the revocation creates a new session. If the wrapper is killed in the
middle, the same rule applies to whatever the data file then shows.

A failed lock therefore still ends access through the wrapper. What the
wrapper cannot do is stop someone from calling the real CLI binary directly
with the old session key; the error message of a failed lock says so.

**`bw login` / `bw unlock`** remember the revocation epoch at the moment they
are requested. They wait while another session command runs or a lock or
logout is pending, start a new cache generation, and run the real CLI. They
count only if the epoch is still the same when they finish, and only if they
really created a session: the command must have printed a session key, and
the key stored in the CLI's data file must be sealed with exactly that key.
An exit code of 0 proves nothing (`bw login --cleanexit` reports "already
logged in" with 0). So:

- An unlock that was waiting, running, or just finished when a lock was
  requested does not open the vault after that lock: it stops, and the lock
  locks whatever it left.
- After a failed lock, a login or unlock that did not create a new session
  leaves access blocked, in every output mode.
- `bw unlock --quiet` prints no key, so it cannot be verified and cannot end
  a block. (Without a block it changes nothing for the wrapper either way.)

Every real-CLI process takes part in this, not only the ones that read the
vault. The real CLI unlocks itself with `BW_SESSION` whenever it starts,
whatever the command, and stores the key again; so the wrapper gives the
session only to a command that was admitted. `bw --help`, `bw generate` and
the like are started without it. `bw status` (and `bw unlock --check`,
`bw login --check`) get it when admitted; when not, they run without it and
report `locked`. All of them hold a lease like any other command, so a lock
or logout waits for them too, and they wait while one is in progress.

Consequences you may notice:

- `bw unlock` ends the current session's cached access when it starts, not
  when it succeeds. After a mistyped password the next command reloads once.
- A read issued while a `bw lock` / `bw logout` is running or pending gets
  `Vault is locked.` right away. The check is made again right before a
  command is handed to the real CLI.
- A command with a session that is still running 10 seconds into a `bw lock`
  / `bw logout` is stopped by it, whether the real CLI or a daemon answers it.
- Without a usable runtime directory no daemon is started, but everything
  above still applies.
- If the coordination state cannot be used, `bw lock` / `bw logout` still run
  the real command but exit with an error: the wrapper cannot vouch that no
  daemon elsewhere still holds the vault.

## Sync, changes behind the wrapper's back, auto-lock

- `bw sync` runs the real sync, then the daemon of that session reloads before
  `bw sync` returns. Daemons of the same root are told their data is outdated.
- The daemon also notices when the real CLI was used directly, behind the
  wrapper's back (a sync, lock, logout or new unlock changes the CLI's data
  file) and revalidates before it answers again; if its session is no longer
  valid it wipes itself.
- Idle time belongs to the vault root, not to a daemon: it is the time since
  the last *admitted* command of that session, whether a daemon or the real
  CLI answered it. Each session has its own clock; a command with another
  session key (a stale `BW_SESSION` in some shell) neither renews nor erases
  it. The deadline is checked at admission, before the command
  renews the clock: a command that arrives after `auto_lock` of inactivity
  does not revive the session, even if no timer has acted yet (the machine
  was suspended, the daemon was stopped). It locks the vault first, with the
  sequence above, and then meets a locked vault. The daemon's timer does the
  same in the background.
- Before an automatic lock commits, holding the operation lock, it checks
  that the session on disk is still the idle one and that it is still idle;
  if the root is busy it looks again a second later. An unlock in another shell is never
  locked away by an old daemon. If the real `bw lock` fails it is retried
  twice (not if the session on disk has meanwhile become someone else's);
  after that access stays blocked. The idle limit does not silently turn into
  "cache evicted".
- `auto_lock_action = evict` is deliberately different: it only frees the
  daemon's memory and revokes nothing.

## Stopping daemons

`bw-wrapper stop` asks daemons to wipe their memory and exit. It evicts
caches; it does not lock anything (that is `bw lock`). It succeeds only if
every daemon in its scope confirmed that its vault is wiped and its real-CLI
children are gone (exited, not merely signalled); otherwise it names the
daemons that did not, and exits with an error. A daemon that could not
establish this in time is not gone: it shows as `STOPPING` in
`bw-wrapper status`, answers nothing, and exits by itself once its processes
have; `bw-wrapper stop` can be run again. Its scope, which it prints: the daemons registered for the
current vault root, and the daemons with a socket in this shell's runtime
directory. Daemons of other roots started from other runtime directories are
not covered. `make install` and `make uninstall` stop the installed version's
daemons first and abort, changing nothing, if that fails.
