# bw-wrapper test fixture

A local Vaultwarden server with two accounts, used to differential-test the
wrapper against the real Bitwarden CLI. Nothing here touches the real vault
in `~/.config/Bitwarden CLI/`: every `bw` call runs with
`BITWARDENCLI_APPDATA_DIR` set to a directory under `/tmp/bww-fixture/`.

## Usage

    test/fixture/up.sh         # container + TLS cert + accounts (idempotent)
    test/fixture/populate.sh   # fill both vaults (~2.5 min first time; skips if already filled)
    source test/fixture/env.sh
    export BW_SESSION=$(fixture_unlock alice)
    fixture_bw alice list items
    test/fixture/down.sh       # remove container, volume and /tmp/bww-fixture

Requires docker, openssl, jq, curl, python3 with `cryptography`, and the real
`bw` at `$REAL_BW`.

## Layout

| What | Where |
|---|---|
| Server | container `bww-test-vaultwarden` (`vaultwarden/server:latest`, 1.37.5 when built), `https://127.0.0.1:18087` |
| Server data | docker volume `bww-test-vw-data` |
| TLS CA / cert | `/tmp/bww-fixture/tls/` (`ca.pem` = `$BWW_FIXTURE_CA`) |
| App-data dirs | `/tmp/bww-fixture/alice`, `/tmp/bww-fixture/bob` |
| Accounts | `alice@example.test` / `alice-master-pw-1`, `bob@example.test` / `bob-master-pw-1` (PBKDF2, 600000 iterations) |

`env.sh` exports `BWW_FIXTURE_URL`, `BWW_FIXTURE_CA`, `NODE_EXTRA_CA_CERTS`,
`REAL_BW`, `ALICE_EMAIL/ALICE_PW/ALICE_APPDATA`, `BOB_EMAIL/BOB_PW/BOB_APPDATA`
and defines `fixture_bw alice|bob ARGS...` and `fixture_unlock alice|bob`.

**TLS is required.** bw 2026.10.1 refuses every non-`https://` server URL
(`InsecureUrlNotAllowedError`; the dev-mode bypass is compiled out). `up.sh`
creates a throwaway CA and a server certificate for `127.0.0.1`/`localhost`.
`bw` trusts the CA through `NODE_EXTRA_CA_CERTS`. A Go wrapper that talks to
the server needs to trust `$BWW_FIXTURE_CA` in the same way.

Helper scripts:
- `vw_api.py`: registration through `/identity/accounts/register/send-verification-email`
  (which returns the token directly because there is no mail) and
  `/identity/accounts/register/finish`. It also creates the organization through
  `POST /api/organizations`. It does the client-side crypto that `bw` cannot do.
- `gen_vaults.py`: generates deterministic Bitwarden-JSON import files.

## alice: small vault with many edge cases

Imported with `bw import bitwardenjson` and then changed with bw commands.
The result: 72 visible items (57 logins, 4 secure notes, 5 cards, 4 identities,
2 SSH keys), 5 items in the trash, 2 archived items. There are 8 folders plus
the pseudo-folder "No Folder" (`id: ""`).

- Folders: `Email`, `Email Work`, `Social`, `Finance`, `Dev`, `Ünïcödé Ordner`,
  `Parent/Child`, `Empty Folder`. There is also a login named `Email`.
- Search collisions: `GitHub`, `GitHub Work`, `github backup` and `GitHub Org`
  (org). `bw get item GitHub` finds 4 matches. There are also two items with
  the exact name `Duplicate Name`, and the pair `AWS Console` / `aws console`.
  The login named `3f2c1a9e-0000-4000-8000-000000000abc` has a GUID-like name.
- URIs: https with a path, http, bare `example.com`, a port, userinfo, IPv4,
  IPv6, `androidapp://`, `iosapp://`, match types 0 to 5 (the regex is
  match=4), multiple URIs on one item, an empty list, a null list, and an item
  that has only a URI.
- Usernames and passwords: empty, null, whitespace only (`"   "`), with
  embedded/trailing newlines (`Newline Password` = `line1\nline2\n`), Unicode,
  and 1000 characters.
- Names: `Café Müller`, `naïve résumé`, `日本語サイト`, an emoji name, quotes,
  backslashes, `<tag> & ampersand`, and leading/trailing spaces.
- TOTP: a bare base32 secret (`GitHub`), full `otpauth://` with
  SHA256/8 digits/60 s (`GitHub Work`), `otpauth://` with defaults,
  `steam://` (`Steam`), and an invalid secret (`Invalid TOTP`). For the invalid
  secret, `bw get totp` still prints a code.
- Custom fields (`Custom Fields`): text, hidden, boolean true/false, empty, null,
  linked (username 100, password 101), a duplicate field name, and Unicode.
- `Password History` holds 3 history entries. `Bank` is a favorite with
  reprompt=1. `Multi-line Notes` holds tabs and blank lines.
- Cards: Visa 4111..., Amex 3782... and 3411..., Mastercard, and a card whose
  number is only `1234`, with null fields.
- Identities: full, only first name, only last name, no name.
- SSH keys (type 5): `SSH Key`, `SSH Key Deploy` (deterministic ed25519).
- Trash: `GitHub old (trashed)` and `Trash Me 1`..`4`, deleted with `bw delete item`
  (without `--permanent`).
- Archive: Vaultwarden 1.37.5 supports it. `bw archive item` returned rc=0
  with empty output. After that, the items are absent from `bw list items` and
  `bw get item <name>` ("Not found."), and they are listed by
  `bw list items --archived`.
- Attachment: `attachment.txt` on `Attachment Holder`.
- Organization `BWW Test Org` with collections `Shared Infra` and
  `Shared Marketing`. It holds 5 login items (`Org Infra DB`, `Org Infra VPN`,
  `Org Marketing CMS`, `Org Shared Both` (both collections), `GitHub Org`).
- `bww-fixture-marker`: a secure note that populate.sh uses to detect a vault
  that is already filled.

The import loses some distinctions. An empty username and a null username both
come back without a `username` key. A null text-field value comes back without
`value`. A null password makes `bw get password` print `Not found.`. Items
that need an exact `""` vs `null` difference have to be created with
`bw create item`.

## bob: large vault

3000 deterministic logins (seeded PRNG) plus the marker note, in 20 folders
(`Folder 00`..`Folder 19`, about 70 % of the items are in a folder). Names look
like `Alpha bravo 0042`. Each item has 1 or 2 URIs, a username and a random
password; about 5 % have TOTP.

## Skipped / caveats

Nothing from the original list was skipped. Things to keep in mind:
- `down.sh` deletes the CA. After the next `up.sh`, a new CA must be trusted
  again (`NODE_EXTRA_CA_CERTS` points at the same path, so `bw` needs no change).
- Every `bw` call while unlocked rewrites `data.json`
  (`__PROTECTED__<uid>_user_auto`), so do not compare `data.json` between runs.
