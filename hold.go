package main

// Hold mode (opt-in): keep read access when the server ends the login session.
//
// When a login session expires on the server (an SSO session that timed out,
// a revoked device), the next real-CLI command that needs the server fails to
// refresh its token and the CLI logs itself out, deleting its keys and vault
// data from the data file. Hold mode works against that in three places:
//
//   - refusal: a command that needs the server is not run at all when the
//     refresh token is already past its own expiry;
//   - restore: real-CLI runs are bracketed by a snapshot of the data file,
//     which is put back if the run ended with the CLI logged out;
//   - hold: a daemon that finds the CLI logged out on disk keeps serving
//     what it has in memory, for at most hold_max.
//
// A deliberate lock or logout through the wrapper still wipes at once and
// cancels pending restores, and a lock or new unlock done with the real CLI
// directly is still honoured: only the "logged out" state is held against.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// loginState is what the CLI's data file says about the login session.
type loginState struct {
	ok         bool // file read and understood
	authed     bool // an active account with an access token
	refreshExp time.Time
	hasExp     bool // the refresh token is a JWT carrying its expiry
}

// jwtExp reads the exp claim of a JWT without verifying it.
func jwtExp(tok string) (time.Time, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp *float64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == nil {
		return time.Time{}, false
	}
	return time.Unix(int64(*claims.Exp), 0), true
}

func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// loginStateOf interprets the top level of data.json.
func loginStateOf(top map[string]json.RawMessage) loginState {
	st := loginState{ok: true}
	uid := jsonString(top["global_account_activeAccountId"])
	if uid == "" {
		return st
	}
	st.authed = jsonString(top["user_"+uid+"_token_accessToken"]) != ""
	st.refreshExp, st.hasExp = jwtExp(jsonString(top["user_"+uid+"_token_refreshToken"]))
	return st
}

// readDataFile returns the data file's bytes and its parsed top level. The
// CLI rewrites the file in place, so a failed parse is retried briefly.
func readDataFile(root string) (raw []byte, top map[string]json.RawMessage, err error) {
	for try := 0; ; try++ {
		raw, err = os.ReadFile(filepath.Join(root, "data.json"))
		if err == nil {
			top = nil
			err = json.Unmarshal(raw, &top)
		}
		if err == nil || os.IsNotExist(err) || try >= 10 {
			return raw, top, err
		}
		time.Sleep(30 * time.Millisecond)
	}
}

func readLoginState(root string) loginState {
	_, top, err := readDataFile(root)
	if err != nil {
		return loginState{}
	}
	return loginStateOf(top)
}

// guardData snapshots the data file before a real-CLI run. The returned
// function is called after the run: if the CLI was logged in before, is
// logged out now, and no explicit session operation came anywhere near the
// run, it puts the snapshot back and reports true.
//
// The caller holds the root's data.lock exclusively from before this call
// until after the returned function (coord.lockData). Every real-CLI run the
// wrapper starts with the root's login takes that lock, so no such run can
// write a newer state between the snapshot and the restore: what is put back
// is always the newest state a wrapper-run command left. (A real CLI started
// directly, not through the wrapper, is outside this order; see docs/hold-mode.md.)
//
// "Near" is decided by the root's coordination state (coord.go): the
// generation and revocation epoch must be the ones the snapshot was taken
// under, and no session operation may be active or pending, neither when
// the guard starts nor when it restores. Check and restore happen under the
// metadata lock, and an operation takes that lock to begin, so it either
// sees the restored file or comes first and voids the restore. If the
// coordination state cannot be read, nothing is restored.
//
// It must only bracket commands that are not themselves a logout.
func guardData(co *coord) (after func() (restored bool)) {
	noop := func() bool { return false }
	root := co.root
	// Mark first, snapshot second: a snapshot can then never be older than
	// the generation it is tied to.
	start, err := co.mark()
	if err != nil || start.active || co.blocked(start) {
		return noop // an operation is changing this state, or access is revoked
	}
	snap, top, err := readDataFile(root)
	if err != nil || !loginStateOf(top).authed {
		return noop
	}
	return func() bool {
		unlock, err := co.lockMeta()
		if err != nil {
			return false
		}
		defer unlock() // held across the checks and the restore
		now, err := co.markLocked()
		if err != nil || now.active || now.revoking || now.Gen != start.Gen || now.Epoch != start.Epoch || now.Access != accessOpen {
			return false // locked, logged out or unlocked anew meanwhile: not ours to undo
		}
		_, top, err := readDataFile(root)
		if err != nil || loginStateOf(top).authed {
			return false
		}
		tmp, err := os.CreateTemp(root, ".data.json.bww-*")
		if err != nil {
			return false
		}
		_, werr := tmp.Write(snap)
		cerr := tmp.Close()
		if werr != nil || cerr != nil || os.Rename(tmp.Name(), filepath.Join(root, "data.json")) != nil {
			os.Remove(tmp.Name())
			return false
		}
		return true
	}
}

const holdRestoredNote = "bw-wrapper: the server rejected this login session and the Bitwarden CLI logged itself out. " +
	"Hold mode restored the local vault: reading still works, anything that needs the server requires a new login (bw logout, then bw login)."
