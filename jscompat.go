package main

// Helpers that reproduce the JavaScript string semantics the Bitwarden CLI
// relies on, so that native answers match the real `bw` byte for byte.

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
)

// jsSpace reports whether r is whitespace for String.prototype.trim and /\s/.
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00a0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

func jsTrim(s string) string { return strings.TrimFunc(s, jsSpace) }

// jsFields is s.split(/\s+/).filter(Boolean).
func jsFields(s string) []string { return strings.FieldsFunc(s, jsSpace) }

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// jsLower is String.prototype.toLowerCase (full Unicode case mapping).
func jsLower(s string) string {
	if isASCII(s) {
		return strings.ToLower(s)
	}
	return cases.Lower(language.Und).String(s)
}

// normalizeSearch is the CLI's normalizeSearchQuery: NFD, then drop the
// combining diacritical marks U+0300..U+036F.
func normalizeSearch(s string) string {
	if isASCII(s) {
		return s
	}
	d := norm.NFD.String(s)
	var b strings.Builder
	b.Grow(len(d))
	for _, r := range d {
		if r >= 0x0300 && r <= 0x036f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// searchKey is normalizeSearchQuery(s.toLowerCase()).
func searchKey(s string) string { return normalizeSearch(jsLower(s)) }

// isGUID is Utils.isGuid.
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// jsQuote is JSON.stringify for a string.
func jsQuote(s string) []byte {
	const hex = "0123456789abcdef"
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if c < 0x20 {
				b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			} else {
				b = append(b, c)
			}
		}
	}
	return append(b, '"')
}

// --- hostname extraction (port of tldts getHostname as used by Utils.getHostname) ---

func validHostChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c > 127
}

func isValidHostname(h string) bool {
	if len(h) == 0 || len(h) > 255 {
		return false
	}
	if !validHostChar(h[0]) && h[0] != '.' && h[0] != '_' {
		return false
	}
	lastDot := -1
	last := byte(0)
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c == '.' {
			if i-lastDot > 64 || last == '.' || last == '-' || last == '_' {
				return false
			}
			lastDot = i
		} else if !(validHostChar(c) || c == '-' || c == '_') {
			return false
		}
		last = c
	}
	return len(h)-lastDot-1 <= 63 && last != '-'
}

func extractHostname(url string, alreadyValid bool) (string, bool) {
	start, end := 0, len(url)
	hasUpper := false
	at := func(i int) byte {
		if i < len(url) {
			return url[i]
		}
		return 0
	}
	if !alreadyValid {
		if strings.HasPrefix(url, "data:") {
			return "", false
		}
		for start < len(url) && url[start] <= 32 {
			start++
		}
		for end > start+1 && url[end-1] <= 32 {
			end--
		}
		if at(start) == '/' && at(start+1) == '/' {
			start += 2
		} else if rel := strings.Index(url[start:], ":/"); rel != -1 {
			idx := start + rel
			for i := start; i < idx; i++ {
				c := url[i] | 32
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '+') {
					return "", false
				}
			}
			start = idx + 2
			for at(start) == '/' {
				start++
			}
		}
		ident, bracket, port := -1, -1, -1
		for i := start; i < end; i++ {
			c := url[i]
			if c == '#' || c == '/' || c == '?' {
				end = i
				break
			} else if c == '@' {
				ident = i
			} else if c == ']' {
				bracket = i
			} else if c == ':' {
				port = i
			} else if c >= 'A' && c <= 'Z' {
				hasUpper = true
			}
		}
		if ident != -1 && ident > start && ident < end {
			start = ident + 1
		}
		if at(start) == '[' {
			if bracket != -1 && bracket > start {
				return strings.ToLower(url[start+1 : bracket]), true
			}
			return "", false
		} else if port != -1 && port > start && port < end {
			end = port
		}
	}
	for end > start+1 && url[end-1] == '.' {
		end--
	}
	if start > end {
		return "", false
	}
	h := url[start:end]
	if hasUpper {
		h = strings.ToLower(h)
	}
	return h, true
}

func looksLikeIP(h string) bool {
	if strings.Contains(h, ":") {
		return true
	}
	if len(h) < 7 || len(h) > 15 {
		return false
	}
	dots := 0
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c == '.' {
			dots++
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return dots == 3 && h[0] != '.' && h[len(h)-1] != '.'
}

// uriHostname is Utils.getHostname. ok=false means "no hostname".
func uriHostname(uri string) (string, bool) {
	if jsTrim(uri) == "" {
		return "", false
	}
	uri = jsTrim(uri)
	if strings.HasPrefix(uri, "data:") || strings.HasPrefix(uri, "about:") || strings.HasPrefix(uri, "file:") {
		return "", false
	}
	h, ok := extractHostname(uri, isValidHostname(uri))
	if !ok {
		return "", false
	}
	if looksLikeIP(h) {
		return h, h != ""
	}
	if !isValidHostname(h) {
		return "", false
	}
	return h, true
}
