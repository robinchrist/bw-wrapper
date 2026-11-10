package main

// Rendering reproduces BaseProgram.processResponse of the real CLI: the same
// stdout/stderr bytes and exit code for a given Response and output flags.

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type resultKind int

const (
	rObj  resultKind = iota // data is an object printed as JSON (item, folder, ...)
	rStr                    // StringResponse; raw holds the JSON token (may be null)
	rList                   // ListResponse; list holds the elements
	rTmpl                   // TemplateResponse; raw holds the template
	rErr                    // failure; msg and optional errData
	rNone                   // success without data
)

type result struct {
	kind    resultKind
	raw     []byte
	list    [][]byte
	msg     string
	errData []byte
	// fallback asks the client to run the real CLI instead.
	fallback bool
	// owned: the buffers are private copies holding vault data; wipe them
	// once the answer has been sent.
	owned bool
}

func (r *result) wipe() {
	wipe(r.raw)
	wipe(r.errData)
	for _, e := range r.list {
		wipe(e)
	}
}

func errResult(msg string) *result { return &result{kind: rErr, msg: msg} }
func notFound() *result            { return errResult("Not found.") }
func fallbackResult() *result      { return &result{fallback: true} }

// multipleResults is Response.multipleResults; ids are raw JSON tokens.
func multipleResults(ids [][]byte) *result {
	var b strings.Builder
	b.WriteString("More than one result was found. Try getting a specific object by `id` instead. The following objects were found:")
	for _, id := range ids {
		b.WriteByte('\n')
		if s, ok := unquoteJSON(id); ok {
			b.Write(s)
		} else {
			b.Write(id) // null
		}
	}
	return &result{kind: rErr, msg: b.String(), errData: joinJSON(ids)}
}

func joinJSON(elems [][]byte) []byte {
	n := 2
	for _, e := range elems {
		n += len(e) + 1
	}
	return appendJSONList(make([]byte, 0, n), elems)
}

// appendJSONList writes elems as a JSON array straight into b, so that no
// second buffer holding all of them exists.
func appendJSONList(b []byte, elems [][]byte) []byte {
	b = append(b, '[')
	for i, e := range elems {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, e...)
	}
	return append(b, ']')
}

func jsonOut(compact []byte, pretty bool) []byte {
	if !pretty {
		return compact
	}
	var buf bytes.Buffer
	buf.Grow(2 * len(compact))
	if err := json.Indent(&buf, compact, "", "  "); err != nil {
		return compact
	}
	return buf.Bytes()
}

// chalk wraps every line separately.
func colorize(s, open string) string {
	const closeSeq = "\x1b[39m"
	return open + strings.ReplaceAll(s, "\n", closeSeq+"\n"+open) + closeSeq
}

// envelopeSize is an upper bound for the --response JSON of a result that
// carries vault data.
func (r *result) envelopeSize() int {
	n := 96 + len(r.raw) + 6*len(r.msg) + len(r.errData) + len(r.list)
	for _, e := range r.list {
		n += len(e)
	}
	return n
}

// envelope builds the --response JSON for a result. The result's data is
// written into the one output buffer directly: the buffer is sized up front
// and never grows, and nothing is assembled in a second buffer first, so the
// only copy this makes is the one it returns (which the caller owns).
func (r *result) envelope() []byte {
	b := make([]byte, 0, r.envelopeSize())
	switch r.kind {
	case rErr:
		b = append(b, `{"success":false,"message":`...)
		b = append(b, jsQuote(r.msg)...)
		if r.errData != nil {
			b = append(b, `,"data":`...)
			b = append(b, r.errData...)
		}
	case rNone:
		b = append(b, `{"success":true`...)
	case rObj:
		b = append(b, `{"success":true,"data":`...)
		b = append(b, r.raw...)
	case rStr:
		b = append(b, `{"success":true,"data":{"object":"string","data":`...)
		b = append(b, r.raw...)
		b = append(b, '}')
	case rList:
		b = append(b, `{"success":true,"data":{"object":"list","data":`...)
		b = appendJSONList(b, r.list)
		b = append(b, '}')
	case rTmpl:
		b = append(b, `{"success":true,"data":{"object":"template","template":`...)
		b = append(b, r.raw...)
		b = append(b, '}')
	}
	return append(b, '}')
}

// render returns stdout, stderr (both without the trailing newline the CLI
// adds on a TTY) and the exit code.
func (r *result) render(f outFlags) (stdout, stderr []byte, exit int) {
	// compact is a buffer built here; when it is only the input of the
	// pretty-printer it is wiped, so no extra plaintext copy stays behind.
	finish := func(compact []byte, scratch bool) []byte {
		out := jsonOut(compact, f.Pretty)
		if f.Pretty && scratch && r.owned {
			wipe(compact)
		}
		return out
	}
	if r.kind == rErr {
		if !f.CleanExit {
			exit = 1
		}
		if f.Quiet {
			return
		}
		if f.Response {
			return finish(r.envelope(), true), nil, exit
		}
		msg := r.msg
		if f.Color {
			msg = colorize(msg, "\x1b[91m")
		}
		return nil, []byte(msg), exit
	}
	if f.Quiet {
		return
	}
	if f.Response {
		return finish(r.envelope(), true), nil, 0
	}
	switch r.kind {
	case rObj, rTmpl:
		stdout = finish(r.raw, false)
	case rList:
		stdout = finish(joinJSON(r.list), true)
	case rStr:
		if s, ok := unquoteJSON(r.raw); ok {
			stdout = s
		}
	}
	return
}

// parseRealResponse turns the real CLI's `--response` output into a result,
// so memoized answers are rendered exactly like native ones.
func parseRealResponse(out []byte) (*result, bool) {
	var env struct {
		Success *bool           `json:"success"`
		Message *string         `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &env); err != nil || env.Success == nil {
		return nil, false
	}
	if !*env.Success {
		r := &result{kind: rErr}
		if env.Message != nil {
			r.msg = *env.Message
		}
		if len(env.Data) > 0 {
			r.errData = env.Data
		}
		return r, true
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return &result{kind: rNone}, true
	}
	var head struct {
		Object   string          `json:"object"`
		Data     json.RawMessage `json:"data"`
		Template json.RawMessage `json:"template"`
	}
	if err := json.Unmarshal(env.Data, &head); err != nil {
		return nil, false
	}
	// env.Data and head.* are private copies of (possibly) the whole vault;
	// whatever does not end up in the result is wiped here.
	switch head.Object {
	case "string":
		wipe(env.Data)
		if len(head.Data) == 0 {
			head.Data = []byte("null")
		}
		return &result{kind: rStr, raw: head.Data}, true
	case "list":
		var elems []json.RawMessage
		err := json.Unmarshal(head.Data, &elems)
		wipe(env.Data)
		wipe(head.Data)
		if err != nil {
			return nil, false
		}
		l := make([][]byte, len(elems))
		for i, e := range elems {
			l[i] = e
		}
		return &result{kind: rList, list: l}, true
	case "template":
		wipe(env.Data)
		return &result{kind: rTmpl, raw: head.Template}, true
	case "message":
		wipe(env.Data)
		return nil, false // not produced by the commands we memoize
	}
	wipe(head.Data)
	wipe(head.Template)
	return &result{kind: rObj, raw: env.Data}, true
}

// unquoteJSON decodes a JSON string token into bytes the caller may wipe.
// ok is false for null or anything that is not a string.
func unquoteJSON(raw []byte) ([]byte, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	if bytes.IndexByte(raw, '\\') < 0 {
		out := make([]byte, len(raw)-2)
		copy(out, raw[1:len(raw)-1])
		return out, true
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	hex4 := func(b []byte) (rune, bool) {
		if len(b) < 4 {
			return 0, false
		}
		n, err := strconv.ParseUint(string(b[:4]), 16, 16)
		return rune(n), err == nil
	}
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(in) {
			return nil, false
		}
		switch in[i] {
		case '"', '\\', '/':
			out = append(out, in[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(in[i+1:])
			if !ok {
				return nil, false
			}
			i += 4
			if utf16.IsSurrogate(r) {
				if i+6 < len(in) && in[i+1] == '\\' && in[i+2] == 'u' {
					if r2, ok := hex4(in[i+3:]); ok {
						if d := utf16.DecodeRune(r, r2); d != utf8.RuneError {
							r = d
							i += 6
						}
					}
				}
				if utf16.IsSurrogate(r) {
					r = utf8.RuneError
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			return nil, false
		}
	}
	return out, true
}

// rawBlank is Utils.isNullOrWhitespace on a JSON token.
func rawBlank(raw []byte) bool {
	s, ok := unquoteJSON(raw)
	if !ok {
		return true
	}
	defer wipe(s)
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRune(s[i:])
		if !jsSpace(r) {
			return false
		}
		i += n
	}
	return true
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
