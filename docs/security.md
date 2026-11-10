# Security notes

- The daemon holds the vault of an unlocked session, like `bw serve` does.
  Item JSON (passwords, TOTP seeds, card numbers, custom fields) and notes are
  kept AES-256-GCM-sealed under a random per-process key and opened only for
  the request that needs them. This is obfuscation against memory scraping,
  not protection: the key is in the same process. Names, usernames, hostnames
  and ids are kept plain for searching.
- Lock (manual or automatic) zeroes the key and the sealed buffers, kills any
  real-CLI process the daemon started, and then exits the daemon. Plaintext
  buffers follow one rule: the function that creates one either wipes it or
  hands it to an owner who does (for example, getting a username wipes the
  decoded password, TOTP seed and notes of that item). Go cannot guarantee
  complete erasure, though: copies made by the runtime, and strings, cannot
  be zeroed in place; they go away with the process.
- The daemon marks itself non-dumpable on Linux (no core dumps, no ptrace or
  `/proc/<pid>/mem` access by other processes of the same user). It does not
  keep the session key: only a hash of it for authenticating requests, and
  its MAC half for checking the CLI's data file. Neither can decrypt anything.
- Sockets live in `$XDG_RUNTIME_DIR/bw-wrapper`, or without that variable in
  `bw-wrapper-<uid>` under the temporary directory, or under `/tmp` where the
  temporary directory's path is too long for a socket address (macOS). The
  directory is created with mode 0700 and refused if it is not yours. A
  `BWW_RUNTIME_DIR` that is too long for a socket address is refused with a
  message; nothing is cached then. Their addresses are
  in `<root>/.bw-wrapper/` (mode 0700), and requests need the right session
  key. A client only talks to a socket it owns. On Linux the daemon also rejects peers of other
  users by their socket credentials; elsewhere the directory mode does that.
- The session key is handed to a new daemon over a pipe, not in `argv`.
  Everything that depends on your shell (vault root, absolute path of the
  real CLI, runtime directory, settings) is resolved before the daemon
  detaches and passed the same way. The daemon's environment is built from an
  explicit list (`PATH` without its relative entries, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`,
  `LANGUAGE`, `LC_*`, `TZ`, `TMPDIR`, `TERM`, `SSL_CERT_FILE`, `SSL_CERT_DIR`,
  `NODE_EXTRA_CA_CERTS`, `NODE_OPTIONS`, `NODE_PATH`,
  `NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_NO_WARNINGS`, `BITWARDENCLI_DEBUG`,
  proxy variables), so an API secret or anything else in your shell does not
  stay in a long-running process. `pass_env = NAME,NAME` (or `BWW_PASS_ENV`)
  lets more variables through if your CLI needs them. The variable named by
  `--passwordenv` never passes, whatever its name and even if `pass_env`
  lists it. The real-CLI runs a daemon starts get that environment plus the
  vault root, and the session key only where they need it.
- While a daemon loads on Linux, a temporary `bw serve` listens on a socket in
  the same private directory for one to two seconds. Like the session key in
  your shell, it is reachable by your own user only, and the kernel kills it
  if the daemon dies. Platforms without that guarantee use `bw list` runs.
- `BWW_DEBUG` output and the daemon log contain fixed messages and internal
  facts only, never command-line arguments: a master password given as an
  argument, a session key or a URL cannot end up in them.
- Responses the daemon keeps for `list items --url …` queries are capped at
  32 MiB per vault; beyond that, new queries are answered by the real CLI
  without being kept.
- The read-only gate protects against accidental writes through this `bw`. It
  is not a security boundary: anything that holds the session key can still
  run the real CLI by its path.
