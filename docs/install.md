# Install

Needs Go ≥ 1.24, Linux or macOS, and the real Bitwarden CLI on `PATH`.

```
make install        # installs ~/.local/bin/bw-wrapper and ~/.local/bin/bw -> bw-wrapper
```

Or take a release binary (Linux and macOS, amd64 and arm64) from the
releases page, check it against `SHA256SUMS`, and install it by hand:

```
tar xzf bw-wrapper_<version>_<os>_<arch>.tar.gz
install -m755 bw-wrapper_*/bw-wrapper ~/.local/bin/bw-wrapper
ln -s bw-wrapper ~/.local/bin/bw     # only if there is no bw there yet
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
