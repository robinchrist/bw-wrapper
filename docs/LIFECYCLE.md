# Process lifecycle: closure specification

This is the single statement of how bw-wrapper coordinates real Bitwarden CLI
processes on one vault root. It lists every place a real CLI is started, the
invariants each start must keep, the lock order, who cancels whom, and the
test that proves each cell. The code refers to it; if code and this file
disagree, that is a bug in one of them.

Facts about the real CLI (bw 2026.10.1) that the design rests on:

- **F1.** On every start, before it looks at its arguments, the CLI unlocks
  itself with `BW_SESSION` from its environment and stores the user key
  again (`bw.js` 96989, 34279). A process that was given the session can
  therefore put a session back, whatever command it runs.
- **F2.** Every process reads the data file and may write it (token cleanup,
  configuration, state). Writes re-read the file first, under the CLI's own
  file lock (`readForNoCache` inside `lockDbFile`), so a write changes single
  keys; it does not put back an old copy of the whole file.
- **F3.** `--cleanexit` / `BW_CLEANEXIT` make failures exit with 0.

## 1. Invariants

| | Invariant |
|---|---|
| **I1** | Every real-CLI process the wrapper starts on a vault root takes part in coordination: help, version, local commands, status, reads, sync, writes, loaders, session commands. |
| **I2** | Coordination lasts until the process has exited, also if the wrapper process or daemon that started it dies first. |
| **I3** | When `bw lock` / `bw logout` (or auto-lock) returns success, no process that started earlier can store a key or print vault data any more, and none started in between. |
| **I4** | While a data-file snapshot may still be restored, no other wrapper-started process writes the data file. |
| **I5** | A command with work to do after the real CLI (reload a daemon, restore, record an outcome) returns only when that work is done. |
| **I6** | A real CLI is given a session key only as an admitted command or as the body of a session command. |
| **I7** | What cannot be established is treated as denied. |

Outside the scope, by definition, and stated in the user documentation: a real CLI
started directly (not through the wrapper); `BWW_DISABLE=1`; a root in which
no coordination directory can exist (read-only), where nothing is ever
recorded or cached.

## 2. Locks

All in `<root>/.bw-wrapper/`. All are `flock` locks on files, so the kernel
releases them when the last process holding the descriptor exits. "Inherited"
means the real CLI gets the open descriptor, which is what makes I2 hold.

| Lock | Mode | Held by | From … until |
|---|---|---|---|
| `meta.lock` | exclusive | any wrapper process | around one read or update of the state; never while waiting for anything else |
| `op.lock` | exclusive | the one running session command; inherited by its real CLI | begin of the operation … exit of its real CLI |
| `revoke.lock` | shared | every lock/logout/auto-lock; inherited by its real CLI | revocation … outcome recorded (or process death) |
| `use.lock` (lease) | shared | every other real-CLI process and every client that prints an answer; inherited | admission or join … process exit |
| `use.lock` | exclusive, momentarily | a lock/logout draining leases | — |
| `data.lock` | exclusive | hold-mode runs (snapshot … restore decision); lock, logout, auto-lock | before the real CLI starts … its exit |
| `data.lock` | shared | all other real-CLI processes; inherited | before start … exit |

**Lock order** (a process only ever waits for a lock further right while
holding locks further left):

```
revoke.lock → op.lock → use.lock (lease, or drain) → data.lock → meta.lock
```

`meta.lock` is a leaf: nothing is waited for while it is held (the lease is
taken under it, which never blocks: the only exclusive holder of `use.lock`
releases it at once). No process that holds `data.lock` waits for `op.lock`
or a lease, so there is no cycle. Waits are bounded: `op.lock` 30 s for
lock/logout; leases 10 s, then stopped; `data.lock` 10 s for lock/logout
(which then proceeds, see 4.1), 5 min for others (then refused); a
sessionless process waits at most 2 min for a pending lock.

## 3. Launch paths

Every `exec` of the real CLI in the code base, by function. "Session" says
whether the process gets `BW_SESSION`.

| # | Path (code) | Used for | Session | Lease | `data.lock` | Other locks | Returns to wrapper |
|---|---|---|---|---|---|---|---|
| P1 | `client.execWithoutSession` | help, version, local commands; `status`, `login --check`, `unlock --check` that were not admitted | **no** (removed) | `coord.join`: taken when no lock is pending | shared | — | no (exec) |
| P2 | `client.realRun(final=true)` | admitted commands with nothing to do afterwards: reads the daemon cannot answer, `sync --last`, admitted `status`/`--check` | yes | `coord.admit` | shared; hold mode: exclusive | — | exec; hold mode: child, restore decision |
| P3 | `client.realRun(final=false)` | `sync`, writes | yes | `coord.admit` | as P2 | — | always a child; lock released, then daemons reload |
| P4 | `client.runRealOp` in `lockOrLogout` | `lock`, `logout` | yes | — (it drains them) | exclusive | `revoke.lock`, `op.lock` | child; outcome recorded |
| P5 | `realLock` (client `expire`, daemon `autoLockNow`) | auto-lock | no | — | exclusive | `revoke.lock`, `op.lock` | child; outcome recorded |
| P6 | `client.runRealOp` in `unlock` | `login`, `unlock` | yes | — (cancelled by a lock instead) | — (see I4 below) | `op.lock` | child; verification, reopen, daemon start |
| P7 | `daemon.dataRun` → `realWith`, `startServe` | vault loads, reloads, lookups a daemon passes on | yes | `coord.admit` | shared; hold mode: exclusive | — | child; daemon waits |
| X1 | `client.execReal` | `BWW_DISABLE=1`; root without possible coordination | yes | — | — | — | out of scope |
| X2 | `client.runReal` in `lockOrLogout` (uncoordinated) | `lock`/`logout` when the state is unusable | yes | — | — | — | runs, and is reported as **failed** |

P6 deliberately does not hold `data.lock`: an unlock can sit at its password
prompt indefinitely, and every other command would wait behind it. I4 does
not need it there. The guard (`hold.go`) takes no snapshot while a session
operation is active and restores nothing once the generation has changed,
and an unlock changes the generation before its real CLI starts; both checks
happen under `meta.lock`, which an operation needs to begin.

Mapping to the invariants:

| | I1 takes part | I2 until exit | I3 lock completion | I4 snapshot | I5 post-work | I6 session |
|---|---|---|---|---|---|---|
| P1 | lease + data lock | exec keeps both | waited for, then stopped; does not start while a lock is pending; has no key (F1 cannot happen) | shared lock: excluded from guarded runs | none | none given |
| P2 | lease + data lock | exec, or child inherits | waited for, then stopped | holds the lock itself | hold mode: child, restore | admitted |
| P3 | lease + data lock | child inherits | waited for, then stopped | holds the lock itself | child; reload before return | admitted |
| P4 | is the lock | inherits `op`, `revoke`, `data` | — | exclusive; restores are void by epoch | outcome from the data file (F3) | session command |
| P5 | is the lock | as P4 | — | as P4 | as P4 | none needed |
| P6 | `op.lock` | inherits `op` | cancelled (TERM, KILL after 5 s, orphans included); its result does not count | no snapshot is taken while an operation is active, none is restored after the generation changed | verify, reopen, stop old daemons | session command |
| P7 | lease + data lock | children inherit both | daemon stops and waits for its children; children of a dead daemon are found by their lease and stopped | holds the lock itself | daemon waits | admitted |

## 4. Sequences

### 4.1 `lock`, `logout`, auto-lock

1. **Revoke** (under `meta.lock`): take `revoke.lock`; epoch+1; access not
   open; new generation. From here: nothing is admitted (I3, I7), no P1
   starts, no login/unlock begins or counts, no snapshot is restored, no
   daemon answers or loads.
2. **`op.lock`**: cancel a running login/unlock (4.4); wait for a running
   lock/logout. More than 30 s: fail, access stays revoked.
3. **Stop daemons**: each kills its real-CLI children, waits until they have
   exited, wipes, confirms (4.6).
4. **Drain leases**: wait for every holder of `use.lock` (P1, P2, P3, P7
   children of dead daemons, clients still writing cached output); stop them
   after 10 s.
5. **`data.lock`** exclusive (10 s; proceeds without it if a process that
   could not be stopped holds it: ending a session is never postponed, and a
   restore is void by the epoch anyway).
6. **Run the real command** (P4/P5), inheriting `op`, `revoke`, `data`.
7. **Record the outcome** from the data file: open if no usable session is
   left, blocked otherwise. Release `revoke.lock`.

Returns success only if 7 says open and 4 drained everything.

### 4.2 `login`, `unlock`

1. Remember the epoch. 2. Take `op.lock` when no operation runs and no
revocation is pending (waits; cancelled if the epoch moves). 3. New
generation. 4. Run the real command (P6).
5. Count it only if it printed a session key and the stored user key is
sealed with that key (F3), and the epoch is unchanged and nothing is pending:
then access is open. 6. Stop daemons of replaced sessions, start the new one.

### 4.3 Any other command

`coord.admit` (allowed / denied / unknown→denied / idle beyond auto_lock →
4.1 first) gives the lease. Cached answer: the client holds the lease until
it has written its output. Real CLI: `data.lock`, admission checked again,
then P2 or P3. A line that needs no session: P1.

### 4.4 Cancellation

| Who | Cancels | How |
|---|---|---|
| lock/logout | running login/unlock (wrapper and its real CLI; also a real CLI whose wrapper died) | SIGTERM; after 5 s SIGKILL to every process holding `op.lock` |
| lock/logout | lease holders | waits 10 s; SIGTERM; 2 s later SIGKILL (found through `/proc`; elsewhere it cannot, and reports failure) |
| lock/logout | daemons | stop request; daemon kills and awaits its children |
| lock/logout | queued and later-finishing login/unlock | epoch: they stop or do not count |
| nobody | a running lock/logout | it is waited for |

Signals go only to recorded processes whose start time still matches, or to
processes that have the lock file open.

### 4.6 Daemon shutdown

Every real-CLI process of a daemon (P7: `realWith`, `startServe`) is started
through one record, `launches`:

| Step | Meaning |
|---|---|
| `reserve` | before `Start()`. Refused once shutdown has begun. |
| `started` | the process exists. If shutdown has begun, it is killed at once. |
| `done` | the process has been waited for (or `Start()` failed). Only now is the launch over. |

`shutdown` closes the record (no further launches; kill what runs) and is
**complete** when no launch is open, the vault is wiped and the daemon is
off the registry. A daemon answers a stop request with "ok" only when
shutdown is complete. If that is not established within 5 s it answers
"stopping": `bw-wrapper stop` (and so `make install`) reports failure, a
lock or logout counts the daemon as not confirmed. The daemon stays
registered and reachable (`bw-wrapper status` shows `STOPPING`), answers
nothing from memory, can be asked again, finishes in the background and
exits on its own. So a process between `Start()` and registration, or a
killed process that has not been reaped, can never hide behind a "stopped".

### 4.5 When a process is killed

| Killed | What still holds | Result |
|---|---|---|
| wrapper of P2/P3 (child running) | child: lease, `data.lock` | I3, I4 hold until the child exits |
| wrapper of P4/P5 | real lock: `op`, `revoke`, `data` | pending until it exits; then blocked iff a usable session is on disk |
| wrapper of P6 | real unlock: `op` | a lock finds and kills it; a queued unlock waits for it |
| daemon (P7 child running) | child: lease, `data.lock` (Linux: the child is killed with the daemon) | a lock finds the child by its lease; guarded runs stay excluded |
| lock between revoke and `op.lock` | nothing | access stays not open: blocked iff a usable session is on disk |

## 5. Acceptance tests

Process-level tests with a stand-in CLI that stops at named barriers
(`integration_test.go`); no sleeps decide an outcome except where the
assertion is "nothing happened yet" (300 ms). Each row was also run with the
rule removed (mutation), and failed.

| Invariant × path | Test |
|---|---|
| I6 P1: help, version, local commands never get the session | `TestNoSessionWithoutAdmission/help…` |
| I6 P1: status / `--check` not admitted run without it; `--session` on the line is refused | `TestNoSessionWithoutAdmission/status_that_is_not_admitted…` |
| I3 P2: admitted status / `--check` paused in its startup (key read, not yet stored): lock does not return while it lives; key is not stored afterwards | `TestNoSessionWithoutAdmission/a_lock_does_not_return…` |
| I3 P1: running help / generate / config is waited for, then stopped | `TestEveryProcessIsCoordinated/lock_completion:_a_running…` |
| I3 P1: does not start while a lock is pending | `TestEveryProcessIsCoordinated/lock_completion:…does_not_start…` |
| I3 P2: real-CLI read waited for; hanging one stopped | `TestLockWaitsForRunningRead`, `TestLockStopsHangingRead` |
| I3 cached output on a full pipe | `TestLockStopsCachedOutput` |
| I3 fallback after a lock began | `TestFallbackRechecksBlock` |
| I3 P6: running, queued, later-finishing unlock | `TestLogoutCancelsUnlock`, `TestQueuedUnlockCannotUndoLock`, `TestKilledSessionOperation`, `TestOrphanedOperationHolder` |
| I3 revocation keeps its place; competing locks; dead lock | `TestPendingLockKeepsItsPlace` |
| I3 P7 + I2: child of a killed daemon is found and stopped | `TestEveryProcessIsCoordinated/…child_of_a_killed_daemon…` |
| I3 P7: daemon confirms stop only when children are gone | `TestEveryProcessIsCoordinated/a_daemon_confirms…` |
| Shutdown (4.6): process started but not yet registered; killed process not reaped within the deadline; no launch after shutdown began; answer is "not stopped", daemon stays discoverable and exits when done | `TestShutdownCompletion`, `TestStopIsNotAcknowledgedEarly` (both points, through `bw-wrapper stop`) |
| I6 P5: the automatic lock runs without the session | `TestIdleExpiryAtAdmission/the_same_without_any_daemon` |
| I3 failed lock, exit code 0 without effect, failed auto-lock | `TestFailedLockBlocksAccess`, `TestLockOutcomeIsReadFromTheSession`, `TestFailedAutoLockBlocksAccess`, `TestKilledLock` |
| I3/I6 unlock that created no session, all output modes | `TestUnverifiedUnlockCannotReopen` |
| I4 P3 vs guarded P2, both orders, hold and non-hold | `TestRestoreCannotOverwriteNewerRevision` |
| I4 P1 vs guarded run | `TestEveryProcessIsCoordinated/snapshot_ordering:…` |
| I4 P6 (and P4) vs guarded run, every order of guard start, operation start, logout by the CLI, restore | `TestGuardData`, `TestAutoLock/idle_and_still_ours…` |
| I4 + I2 P7: killed daemon's child keeps other runs out | `TestDaemonChildKeepsDataLock` |
| I4 restore vs session commands, all orders | `TestGuardData`, `TestRestoreAcrossRuntimeDirs`, `TestRestoreAfterSelfLogout` |
| I5 P3: sync has reloaded the daemon when it returns, hold and non-hold | `TestSyncReloadsBeforeReturning` |
| I7 damaged state, permissions, each lock file unusable | `TestUnknownStateDenies` |
| I7 line whose command cannot be told | `TestUncertainLineIsNotRun`, `TestClass` |
| Idle clock at admission | `TestIdleExpiryAtAdmission`, `TestAutoLock` |
| Snapshot in memory vs failed reload | `TestFailedReloadKeepsSnapshotStale` |
| How a line is read (class, values, repeats, `--`) | `TestClass`, `TestParseCached`, `TestPasswordEnvs`, `test/parsetest.py` (against the real CLI) |

End to end against the real CLI and a local server: `test/difftest.py`
(answers byte for byte), `test/lifecycle.py`.

## 6. Limits

- Stopping a process that holds a lease needs `/proc` (Linux). Elsewhere
  lock/logout waits, cannot stop it, and exits with an error although the
  vault is locked.
- A daemon is hardened against inspection, so it is stopped by request, not
  by signal; one that does not confirm leaves lock/logout reporting failure
  if it still holds a lease.
- X1 and X2 above, and a real CLI started directly, are not coordinated.
- The command table is that of bw 2026.10.1. A line it does not explain is
  read cautiously (I7); a CLI that changes F1–F3 needs this file revisited.
