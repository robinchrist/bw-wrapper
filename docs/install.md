# Install

Needs Go ≥ 1.24, Linux or macOS, and the real Bitwarden CLI on `PATH`.

```
make install        # installs ~/.local/bin/bw-wrapper and ~/.local/bin/bw -> bw-wrapper
```

`~/.local/bin` must come **before** the real `bw` on `PATH`. The wrapper finds
the real CLI as the next `bw` on `PATH` that is not itself; set `real_bw` if
you want to pin it. Check with `bw-wrapper config`.

`make install` checks before it changes anything. If the install directory
already has a `bw` that is not the wrapper's own link (the real CLI, a
launcher script, a link to something else), it refuses and leaves it alone:
replacing it could remove the only Bitwarden CLI you have. Move that one to
another directory on `PATH` (or point `real_bw` at it) first, or install with
another `BINDIR`.

To bypass the wrapper for one command: `BWW_DISABLE=1 bw …` (such a command
is outside all coordination described in [sessions.md](sessions.md)).

When you install a new version, daemons of the old one are stopped first
(`bw-wrapper stop`); if one cannot be stopped, the installation stops there.
