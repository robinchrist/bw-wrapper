package main

// Reading the Bitwarden CLI's data file (data.json) to see whether the
// vault or the session changed behind the daemon's back.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// dataFP identifies a state of the CLI's data file. The stat part is cheap
// and checked on every request. Only when it changed are the contents looked
// at, to tell real changes from the bookkeeping the CLI writes on every run.
type dataFP struct {
	size   int64
	mtime  int64
	ino    uint64
	digest [32]byte // vault-relevant content
	sealed int      // is the stored user key sealed with our session key?
	authed bool     // the CLI is logged in at all
}

const (
	sealUnknown = iota // format not understood: fall back to comparing bytes
	sealOurs
	sealForeign // locked, logged out, or unlocked again with a new session key
)

func (a dataFP) sameStat(b dataFP) bool {
	return a.size == b.size && a.mtime == b.mtime && a.ino == b.ino
}

func statFP(root string) dataFP {
	fi, err := os.Stat(filepath.Join(root, "data.json"))
	if err != nil {
		return dataFP{}
	}
	fp := dataFP{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		fp.ino = st.Ino
	}
	return fp
}

// volatileKey reports whether a top-level key of data.json changes without
// the vault or the session changing (activity timestamps, API tokens, cached
// server configuration). Unknown keys count as relevant.
func volatileKey(k string) bool {
	if k == "global_account_activity" || strings.HasPrefix(k, "global_config_") || strings.HasPrefix(k, "global_clearEvent_") {
		return true
	}
	if strings.HasPrefix(k, "user_") {
		return strings.Contains(k, "_token_") || strings.Contains(k, "_config_")
	}
	return false
}

// sealedWith checks a `__PROTECTED__` value of the CLI: the user key,
// encrypted with the session key as type(1)=2 | iv(16) | mac(32) | ciphertext,
// where mac = HMAC-SHA256(macKey, iv | ciphertext) and macKey is the second
// half of the session key. The CLI
// re-encrypts it on every run, so its bytes always change; what matters is
// whether it still verifies under our session key.
func sealedWith(valueJSON, macKey []byte) int {
	val, ok := unquoteJSON(valueJSON)
	if len(macKey) != 32 || !ok {
		return sealUnknown
	}
	raw, err := base64.StdEncoding.DecodeString(string(val))
	if err != nil || len(raw) < 1+16+32+16 || raw[0] != 2 {
		return sealUnknown
	}
	mac := hmac.New(sha256.New, macKey)
	mac.Write(raw[1:17])
	mac.Write(raw[49:])
	if hmac.Equal(mac.Sum(nil), raw[17:49]) {
		return sealOurs
	}
	return sealForeign
}

// readFP fingerprints the data file. With checkSeal=false the seal check is
// skipped and the protected values are compared as bytes instead.
func readFP(root string, macKey []byte, checkSeal bool) dataFP {
	for try := 0; ; try++ {
		fp := statFP(root)
		raw, err := os.ReadFile(filepath.Join(root, "data.json"))
		var top map[string]json.RawMessage
		if err == nil {
			err = json.Unmarshal(raw, &top)
		}
		if err != nil {
			if try < 10 && !os.IsNotExist(err) {
				time.Sleep(30 * time.Millisecond) // caught the CLI mid-write
				continue
			}
			// Unreadable: no verdict here. The zero digest differs from any
			// loaded state, so the real CLI gets to decide through a reload.
			return fp
		}
		fp.sealed = sealForeign // no protected user key at all: locked
		fp.authed = loginStateOf(top).authed
		var keys, protected []string
		for k := range top {
			switch {
			case strings.HasPrefix(k, "__PROTECTED__"):
				protected = append(protected, k)
			case !volatileKey(k):
				keys = append(keys, k)
			}
		}
		for _, k := range protected {
			if st := sealedWith(top[k], macKey); st == sealOurs || (st == sealUnknown && fp.sealed != sealOurs) {
				fp.sealed = st
			}
		}
		if !checkSeal {
			fp.sealed = sealUnknown
		}
		if fp.sealed == sealUnknown {
			keys = append(keys, protected...)
		}
		sort.Strings(keys)
		h := sha256.New()
		for _, k := range keys {
			fmt.Fprintf(h, "%d:%s%d:", len(k), k, len(top[k]))
			h.Write(top[k])
		}
		h.Sum(fp.digest[:0])
		return fp
	}
}
