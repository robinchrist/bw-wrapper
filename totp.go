package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

const steamChars = "23456789BCDFGHJKMNPQRTVWXY"

// totpNow computes the current code for a Bitwarden TOTP field (bare base32
// secret, otpauth:// URI or steam:// secret). ok=false means the input is not
// in a shape handled here; the caller then asks the real CLI, so only
// unambiguous, well-formed seeds are computed natively.
//
// The seed is passed as bytes the caller wipes; it is looked at in place, not
// copied into a string that would stay in memory.
func totpNow(seed []byte) (string, bool) {
	if len(seed) == 0 {
		return "", false
	}
	return totpAt(unsafe.String(&seed[0], len(seed)), time.Now())
}

func totpAt(key string, now time.Time) (string, bool) {
	digits, period := 6, int64(30)
	var newHash func() hash.Hash = sha1.New
	steam := false
	secret := key
	lower := strings.ToLower(key)
	switch {
	case strings.HasPrefix(lower, "otpauth://"):
		u, err := url.Parse(key)
		if err != nil || !strings.EqualFold(u.Host, "totp") {
			return "", false
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return "", false
		}
		for k, vals := range q {
			if len(vals) != 1 {
				return "", false
			}
			val := vals[0]
			switch strings.ToLower(k) {
			case "secret":
				secret = val
			case "digits":
				n, err := strconv.Atoi(val)
				if err != nil || n < 6 || n > 8 {
					return "", false
				}
				digits = n
			case "period":
				n, err := strconv.ParseInt(val, 10, 64)
				if err != nil || n < 1 || n > 3600 {
					return "", false
				}
				period = n
			case "algorithm":
				switch strings.ToLower(val) {
				case "sha1":
				case "sha256":
					newHash = sha256.New
				case "sha512":
					newHash = sha512.New
				default:
					return "", false
				}
			}
		}
		if secret == key {
			return "", false
		}
	case strings.HasPrefix(lower, "steam://"):
		steam = true
		digits = 5
		secret = key[len("steam://"):]
	}

	secret = strings.ToUpper(secret)
	if secret == "" {
		return "", false
	}
	for i := 0; i < len(secret); i++ {
		c := secret[i]
		if !(c >= 'A' && c <= 'Z' || c >= '2' && c <= '7') {
			return "", false
		}
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	raw, err := enc.DecodeString(secret)
	if err != nil || enc.EncodeToString(raw) != secret {
		return "", false // not canonical base32: let the real CLI decide
	}

	defer wipe(raw)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(now.Unix()/period))
	mac := hmac.New(newHash, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff

	if steam {
		out := make([]byte, digits)
		for i := range out {
			out[i] = steamChars[bin%uint32(len(steamChars))]
			bin /= uint32(len(steamChars))
		}
		return string(out), true
	}
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := strconv.FormatUint(uint64(bin%mod), 10)
	return strings.Repeat("0", digits-len(code)) + code, true
}
