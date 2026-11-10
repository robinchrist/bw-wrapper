package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestParseCached(t *testing.T) {
	t.Setenv("BW_SESSION", "envsess")
	for _, k := range []string{"BW_PRETTY", "BW_RAW", "BW_RESPONSE", "BW_QUIET", "BW_CLEANEXIT"} {
		t.Setenv(k, "")
	}
	cases := []struct {
		args    []string
		cached  bool
		cmd     string
		pos     []string
		opts    map[string]string
		session string
		flags   outFlags
	}{
		{[]string{"get", "password", "github"}, true, "get", []string{"password", "github"}, map[string]string{}, "envsess", outFlags{}},
		{[]string{"--raw", "get", "password", "x", "--session", "S"}, true, "get", []string{"password", "x"}, map[string]string{}, "S", outFlags{Raw: true}},
		// a global option is a global option wherever it stands, even where a value was expected
		{[]string{"--session=S2", "list", "items", "--search", "x", "--pretty"}, true, "list", []string{"items"}, map[string]string{"search": "x"}, "S2", outFlags{Pretty: true}},
		{[]string{"list", "items", "--folderid=null", "--trash", "--response"}, true, "list", []string{"items"}, map[string]string{"folderid": "null", "trash": "true"}, "envsess", outFlags{Response: true}},
		{[]string{"status", "--quiet", "--cleanexit"}, true, "status", nil, map[string]string{}, "envsess", outFlags{Quiet: true, CleanExit: true}},
		// a value option takes the next argument whatever it looks like
		{[]string{"list", "items", "--search", "--trash"}, true, "list", []string{"items"}, map[string]string{"search": "--trash"}, "envsess", outFlags{}},
		{[]string{"get", "password", "x", "--output", "--help"}, true, "get", []string{"password", "x"}, map[string]string{"output": "--help"}, "envsess", outFlags{}},
		// given twice: the last one counts
		{[]string{"list", "items", "--search", "a", "--search", "b"}, true, "list", []string{"items"}, map[string]string{"search": "b"}, "envsess", outFlags{}},
		// after "--" everything is an operand
		{[]string{"get", "password", "--", "--help"}, true, "get", []string{"password", "--help"}, map[string]string{}, "envsess", outFlags{}},
		{[]string{"--", "get", "item", "x"}, true, "get", []string{"item", "x"}, map[string]string{}, "envsess", outFlags{}},
		{[]string{"list", "--search", "x", "items"}, true, "list", []string{"items"}, map[string]string{"search": "x"}, "envsess", outFlags{}},
		// not answered from memory: left to the real CLI
		{[]string{"get", "item"}, false, "get", nil, nil, "", outFlags{}},
		{[]string{"get", "item", "a", "b"}, false, "get", nil, nil, "", outFlags{}},
		{[]string{"list", "items", "--bogus"}, false, "list", nil, nil, "", outFlags{}},
		{[]string{"list", "items", "--search"}, false, "list", nil, nil, "", outFlags{}},
		{[]string{"list", "items", "--search", "--raw"}, false, "list", nil, nil, "", outFlags{}}, // --raw is global: --search has no value
		{[]string{"--search", "x", "list", "items"}, false, "", nil, nil, "", outFlags{}},
		{[]string{"list", "items", "--trash=1"}, false, "list", nil, nil, "", outFlags{}},
		{[]string{"get", "password", "-x"}, false, "get", nil, nil, "", outFlags{}},
		{[]string{"status", "extra"}, false, "status", nil, nil, "", outFlags{}},
	}
	for _, c := range cases {
		inv := parseArgs(c.args)
		opts, cached := inv.cached()
		if cached != c.cached || inv.cmd != c.cmd {
			t.Errorf("%v: cached=%v cmd=%q, want %v %q", c.args, cached, inv.cmd, c.cached, c.cmd)
			continue
		}
		if !c.cached {
			continue
		}
		if !(len(inv.pos) == 0 && len(c.pos) == 0) && !reflect.DeepEqual(inv.pos, c.pos) || !reflect.DeepEqual(opts, c.opts) || inv.session != c.session || inv.flags != c.flags {
			t.Errorf("%v: got pos=%v opts=%v session=%q flags=%+v", c.args, inv.pos, opts, inv.session, inv.flags)
		}
	}
}

func TestParseEnvFlags(t *testing.T) {
	t.Setenv("BW_SESSION", "")
	t.Setenv("BW_RESPONSE", "true")
	t.Setenv("BW_PRETTY", "yes") // only the literal "true" counts
	t.Setenv("BW_CLEANEXIT", "0")
	inv := parseArgs([]string{"get", "item", "x"})
	if !inv.exact || !inv.flags.Response || inv.flags.Pretty || !inv.flags.CleanExit || inv.session != "" {
		t.Errorf("env flags: %+v session=%q", inv.flags, inv.session)
	}
	if f := parseArgs([]string{"create", "folder", "x", "--response", "--cleanexit"}).flags; !f.Response || !f.CleanExit {
		t.Errorf("global flags of non-cached commands: %+v", f)
	}
}

// The class decides everything: info runs without any check, write is
// refused in read-only mode, session/read/write are subject to the session
// state. The cases marked "runs" are lines the real CLI executes although
// they contain a help flag or look like something else.
func TestClass(t *testing.T) {
	t.Setenv("BW_SESSION", "")
	cases := map[string][][]string{
		"write": {
			{"create", "item", "x"}, {"edit", "item", "id"}, {"delete", "item", "id"}, {"restore", "item", "id"},
			{"move", "a", "b"}, {"share", "a", "b"}, {"confirm", "org-member", "x"}, {"import", "f", "p"},
			{"archive", "item", "id"}, {"send", "text"}, {"send", "-f", "file"}, {"send", "create"}, {"send", "delete", "x"},
			{"device-approval", "approve", "x"}, {"serve"}, {"--raw", "create", "folder", "x"},
			{"--session", "list", "create", "item"}, {"brandnewcommand"}, {"brandnewcommand", "--opt", "--help"},
			// runs: the help flag is the value of an option
			{"send", "-n", "-h", "text"}, {"create", "attachment", "--file", "--help", "--itemid", "x"},
			{"send", "--name", "--help", "text"}, {"send", "-d", "-h", "x"}, {"send", "-fn", "-h", "x"},
			// runs: after "--" nothing is an option
			{"--", "delete", "item", "id"}, {"--pretty", "--", "create", "folder", "x"}, {"delete", "item", "--", "--help"},
			// cannot be told for certain: the cautious reading
			{"--", "--raw", "delete"}, {"--foo=bar", "delete", "item", "x"}, {"-x", "delete", "item", "x"}, {"Create", "folder", "x"},
			{"--frob", "get", "password", "x"}, {"send", "--frob", "list"}, {"send", "list", "--frob"},
			{"device-approval", "list", "--frob"}, {"delete", "item", "x", "--frob", "--help"},
			{"send", "-n", "list", "text"}, // "list" is the value of -n: this creates a Send
			{"send", "help"},               // creates a Send with the text "help"
			{"send", "help", "list"}, {"device-approval", "frob"},
		},
		"read": {
			{"get", "item", "x"}, {"list", "items"}, {"sync"}, {"export"}, {"send", "list"}, {"send", "get", "x"},
			{"send", "template", "send.text"}, {"receive", "url"}, {"send", "receive", "url"}, {"device-approval", "list"},
			{"--", "get", "item", "x"}, {"send", "--hidden", "list"}, {"report", "x"},
			// runs: these look like help but are not (the reviewed case first)
			{"get", "password", "example", "--output", "--help"}, {"get", "password", "x", "--itemid", "-h"},
			{"list", "items", "--search", "--help"}, {"list", "items", "--search=--help"}, {"get", "item", "--", "-h"},
			{"export", "--format", "--help"}, {"sync", "--", "--help"}, {"receive", "--passwordenv", "--help", "url"},
			// not understood exactly, but a read command whatever the rest means
			{"get", "password", "x", "--frob", "--help"}, {"list", "items", "--bogus"}, {"get", "password", "x", "--output"},
		},
		"session": {
			{"lock"}, {"logout"}, {"login"}, {"unlock"}, {"unlock", "pw", "--raw"}, {"login", "a@b", "pw", "--method", "0"},
			// runs: --check and --help are values here, not options
			{"unlock", "--passwordenv", "--check"}, {"login", "--passwordfile", "--check"}, {"unlock", "--passwordenv", "--help"},
			{"login", "--code", "-h"}, {"unlock", "--", "--check"}, {"unlock", "--", "--help"}, {"login", "--sso", "--", "--check"},
			{"unlock", "--frob", "--check"}, // not understood: a real unlock for all we know
			{"unlock", "--passwordenv", "A", "--passwordenv", "--check"},
		},
		"local": {
			{"generate", "-lusn"}, {"encode"}, {"config", "server"}, {"completion", "--shell", "zsh"}, {"update"}, {"sdk-version"},
			{"unlock", "--check"}, {"login", "--check"}, {"unlock", "--passwordenv", "X", "--check"}, {"login", "--sso", "--check"},
			{"generate", "--length", "--help"},
		},
		"status": {{"status"}, {"status", "--raw"}, {"--", "status"}},
		"info": {
			{}, {"--"}, {"--help"}, {"-h"}, {"--version"}, {"-v"}, {"help"}, {"help", "create"}, {"--pretty"},
			{"create", "--help"}, {"delete", "-h"}, {"send", "--help"}, {"get", "--help"}, {"list", "items", "-h"},
			{"delete", "item", "id", "--help"}, {"--help", "create", "folder", "x"}, {"send", "list", "--help"},
			{"device-approval", "frob", "--help", "x"}, {"device-approval"}, {"device-approval", "help"}, {"device-approval", "help", "list"}, {"--raw", "device-approval"},
			{"get", "password", "x", "--output", "f", "--help"}, {"unlock", "--help"}, {"unlock", "--check", "--help"},
			// the version option acts wherever it stands, even where a command expected a value
			{"create", "-v"}, {"get", "password", "x", "--output", "-v"}, {"unlock", "--passwordenv", "--version"},
			{"list", "items", "--search", "x", "--sso", "--help"}, // --sso is not an option of list: help follows as first unknown? no: see below
		},
	}
	// The last info case needs its own look: --sso is unknown to `list`, so it
	// is the first unknown argument and the line is NOT certain help.
	cases["info"] = cases["info"][:len(cases["info"])-1]
	cases["read"] = append(cases["read"], []string{"list", "items", "--search", "x", "--sso", "--help"})
	for want, lines := range cases {
		for _, args := range lines {
			if got := parseArgs(args).class().String(); got != want {
				t.Errorf("bw %q is %s, want %s", args, got, want)
			}
		}
	}
}

// Every variable a command line names as holding a password is known, so
// that none of them reaches a daemon.
func TestPasswordEnvs(t *testing.T) {
	for line, want := range map[string][]string{
		"unlock --passwordenv MYPW":                    {"MYPW"},
		"unlock --passwordenv=MYPW --raw":              {"MYPW"},
		"--raw login a@b --passwordenv X":              {"X"},
		"unlock":                                       nil,
		"unlock --passwordenv":                         nil,
		"unlock --passwordenv A --passwordenv B":       {"A", "B"}, // the CLI uses B; neither passes
		"unlock --passwordenv A --passwordenv=B pw":    {"A", "B"},
		"unlock --passwordenv --passwordenv":           {"--passwordenv"},
		"unlock --passwordfile --passwordenv":          nil, // the value of --passwordfile, not an option
		"unlock --passwordfile --passwordenv X":        nil,
		"unlock -- --passwordenv X":                    nil,
		"unlock --frob --passwordenv X":                {"X"}, // not understood: everything that could be one
		"unlock --frob --passwordfile --passwordenv Y": {"Y"},
		"receive url --passwordenv R":                  {"R"},
		"import --passwordenv I f p":                   {"I"},
	} {
		got := parseArgs(strings.Fields(line)).passwordEnvs()
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("bw %s: password variables %q, want %q", line, got, want)
		}
	}
}

func TestTotpRFC6238(t *testing.T) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	k1 := enc.EncodeToString([]byte("12345678901234567890"))
	k256 := enc.EncodeToString([]byte("12345678901234567890123456789012"))
	k512 := enc.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))
	cases := []struct {
		key  string
		unix int64
		want string
	}{
		{"otpauth://totp/x?secret=" + k1 + "&digits=8", 59, "94287082"},
		{"otpauth://totp/x?secret=" + k256 + "&digits=8&algorithm=SHA256", 59, "46119246"},
		{"otpauth://totp/x?secret=" + k512 + "&digits=8&algorithm=sha512", 59, "90693936"},
		{"otpauth://totp/x?secret=" + k1 + "&digits=8", 1111111109, "07081804"},
		{k1, 59, "287082"},
		{"otpauth://totp/a:b?secret=" + k1 + "&issuer=a&period=60&digits=8", 20000000000, totpRef(t, k1, 20000000000, 60)},
	}
	for _, c := range cases {
		got, ok := totpAt(c.key, time.Unix(c.unix, 0))
		if !ok || got != c.want {
			t.Errorf("%s @%d = %q,%v want %q", c.key, c.unix, got, ok, c.want)
		}
	}
	// lower-case secrets are accepted; anything unusual is left to the real CLI
	if got, ok := totpAt("gezdgnbvgy3tqojqgezdgnbvgy3tqojq", time.Unix(59, 0)); !ok || got != "287082" {
		t.Errorf("lowercase secret: %q %v", got, ok)
	}
	for _, bad := range []string{"", "not base32!", "JBSW Y3DP", "JBSWY3DPE", "otpauth://hotp/x?secret=" + k1, "otpauth://totp/x?secret=" + k1 + "&digits=10", "otpauth://totp/x"} {
		if _, ok := totpAt(bad, time.Unix(59, 0)); ok {
			t.Errorf("%q should not be computed natively", bad)
		}
	}
	if got, ok := totpAt("steam://"+k1, time.Unix(59, 0)); !ok || len(got) != 5 {
		t.Errorf("steam: %q %v", got, ok)
	}
}

// totpRef: period 60 at T equals period 30 at T/2.
func totpRef(t *testing.T, key string, unix, period int64) string {
	t.Helper()
	got, ok := totpAt("otpauth://totp/x?secret="+key+"&digits=8", time.Unix(unix/period*30, 0))
	if !ok {
		t.Fatal("reference totp failed")
	}
	return got
}

func TestURIHostname(t *testing.T) {
	cases := map[string]string{
		"https://github.com/login":          "github.com",
		"http://User:pw@Example.COM:8443/x": "example.com",
		"example.com":                       "example.com",
		"example.com/path?q=1":              "example.com",
		"https://sub.example.co.uk.":        "sub.example.co.uk",
		"http://192.168.1.10:8443/admin":    "192.168.1.10",
		"https://[::1]:8080/":               "::1",
		"androidapp://com.example.app":      "com.example.app",
		"  https://spaced.example.org  ":    "spaced.example.org",
		"ftp://files.example.net/pub":       "files.example.net",
		"//cdn.example.com/x":               "cdn.example.com",
		"https://münchen.example/":          "münchen.example",
		"localhost:3000":                    "localhost",
		"data:text/plain,hi":                "",
		"about:blank":                       "",
		"file:///etc/passwd":                "",
		"":                                  "",
		"   ":                               "",
		"https://exa mple.com":              "",
		"https://-bad-.example.com/":        "",
		"we!rd://example.com":               "",
	}
	for in, want := range cases {
		got, ok := uriHostname(in)
		if !ok {
			got = ""
		}
		if got != want {
			t.Errorf("uriHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSearchKey(t *testing.T) {
	cases := map[string]string{
		"Café Müller":  "cafe muller",
		"NAÏVE Résumé": "naive resume",
		"GitHub":       "github",
		"日本語サイト":       "日本語サイト",
		"ΟΔΟΣ":         "οδος",
	}
	for in, want := range cases {
		if got := searchKey(in); got != want {
			t.Errorf("searchKey(%q) = %q, want %q", in, got, want)
		}
	}
	if got := searchTerms("  Work\t GitHub x "); !reflect.DeepEqual(got, []string{"work", "github", "x"}) {
		t.Errorf("searchTerms = %q", got)
	}
	for id, want := range map[string]bool{
		"99ee88d2-6046-4ea7-92c2-acac464b1412": true, "99EE88D2-6046-4EA7-92C2-ACAC464B1412": true,
		"99ee88d2-6046-4ea7-92c2-acac464b141": false, "99ee88d2x6046-4ea7-92c2-acac464b1412": false, "github": false,
	} {
		if isGUID(id) != want {
			t.Errorf("isGUID(%q) != %v", id, want)
		}
	}
}

func TestUnquoteAndQuote(t *testing.T) {
	for _, s := range []string{"", "plain", `q"uo\te`, "tab\there\nnl", "ünï 日本 🔑", " x\u0001", "<&>"} {
		js, _ := json.Marshal(s)
		got, ok := unquoteJSON(js)
		if !ok || string(got) != s {
			t.Errorf("unquoteJSON(%s) = %q,%v", js, got, ok)
		}
		var back string
		if err := json.Unmarshal(jsQuote(s), &back); err != nil || back != s {
			t.Errorf("jsQuote(%q) = %s (%v)", s, jsQuote(s), err)
		}
	}
	if got, ok := unquoteJSON([]byte(`"🔑 é\/"`)); !ok || string(got) != "🔑 é/" {
		t.Errorf("escapes: %q %v", got, ok)
	}
	if _, ok := unquoteJSON([]byte("null")); ok {
		t.Error("null is not a string")
	}
	if string(jsQuote("a<b>& ")) != "\"a<b>& \"" {
		t.Errorf("jsQuote must not escape like encoding/json: %s", jsQuote("a<b>& "))
	}
	for tok, want := range map[string]bool{`null`: true, `""`: true, `"  \t\n"`: true, `" "`: true, `" x "`: false, `"0"`: false} {
		if rawBlank([]byte(tok)) != want {
			t.Errorf("rawBlank(%s) != %v", tok, want)
		}
	}
}

func TestRender(t *testing.T) {
	item := []byte(`{"object":"item","id":"1","list":[],"o":{}}`)
	check := func(name string, r *result, f outFlags, out, errOut string, exit int) {
		t.Helper()
		o, e, x := r.render(f)
		if string(o) != out || string(e) != errOut || x != exit || (o == nil) != (out == "") {
			t.Errorf("%s: got (%q, %q, %d), want (%q, %q, %d)", name, o, e, x, out, errOut, exit)
		}
	}
	check("obj", &result{kind: rObj, raw: item}, outFlags{}, string(item), "", 0)
	check("obj pretty", &result{kind: rObj, raw: item}, outFlags{Pretty: true},
		"{\n  \"object\": \"item\",\n  \"id\": \"1\",\n  \"list\": [],\n  \"o\": {}\n}", "", 0)
	check("obj response", &result{kind: rObj, raw: item}, outFlags{Response: true}, `{"success":true,"data":`+string(item)+`}`, "", 0)
	check("str", &result{kind: rStr, raw: []byte(`"p\"w"`)}, outFlags{}, `p"w`, "", 0)
	check("str response", &result{kind: rStr, raw: []byte(`"p\"w"`)}, outFlags{Response: true}, `{"success":true,"data":{"object":"string","data":"p\"w"}}`, "", 0)
	check("str null", &result{kind: rStr, raw: []byte(`null`)}, outFlags{}, "", "", 0)
	check("list", &result{kind: rList, list: [][]byte{item, item}}, outFlags{}, "["+string(item)+","+string(item)+"]", "", 0)
	check("empty list", &result{kind: rList}, outFlags{}, "[]", "", 0)
	check("list response", &result{kind: rList}, outFlags{Response: true}, `{"success":true,"data":{"object":"list","data":[]}}`, "", 0)
	check("quiet", &result{kind: rObj, raw: item}, outFlags{Quiet: true}, "", "", 0)
	check("err", notFound(), outFlags{}, "", "Not found.", 1)
	check("err color", notFound(), outFlags{Color: true}, "", "\x1b[91mNot found.\x1b[39m", 1)
	check("err cleanexit", notFound(), outFlags{CleanExit: true}, "", "Not found.", 0)
	check("err quiet", notFound(), outFlags{Quiet: true}, "", "", 1)
	check("err response", notFound(), outFlags{Response: true}, `{"success":false,"message":"Not found."}`, "", 1)
	multi := multipleResults([][]byte{[]byte(`"a"`), []byte(`null`)})
	const m = "More than one result was found. Try getting a specific object by `id` instead. The following objects were found:"
	check("multi", multi, outFlags{}, "", m+"\na\nnull", 1)
	check("multi color", multi, outFlags{Color: true}, "", "\x1b[91m"+m+"\x1b[39m\n\x1b[91ma\x1b[39m\n\x1b[91mnull\x1b[39m", 1)
	check("multi response", multi, outFlags{Response: true}, `{"success":false,"message":"`+m+`\na\nnull","data":["a",null]}`, "", 1)
}

func TestParseRealResponse(t *testing.T) {
	cases := []struct {
		in   string
		kind resultKind
		out  string
	}{
		{`{"success":true,"data":{"object":"list","data":[{"a":1},{"b":2}]}}`, rList, `[{"a":1},{"b":2}]`},
		{`{"success":true,"data":{"object":"string","data":"s3cret"}}`, rStr, `s3cret`},
		{`{"success":true,"data":{"object":"template","template":{"x":null}}}`, rTmpl, `{"x":null}`},
		{`{"success":true,"data":{"object":"item","id":"1"}}`, rObj, `{"object":"item","id":"1"}`},
		{`{"success":false,"message":"Vault is locked."}`, rErr, ``},
	}
	for _, c := range cases {
		r, ok := parseRealResponse([]byte(c.in))
		if !ok || r.kind != c.kind {
			t.Errorf("%s: kind %v ok=%v", c.in, r, ok)
			continue
		}
		out, _, _ := r.render(outFlags{})
		if string(out) != c.out {
			t.Errorf("%s: rendered %q, want %q", c.in, out, c.out)
		}
		env, _, _ := r.render(outFlags{Response: true})
		if string(env) != c.in {
			t.Errorf("round trip: %s -> %s", c.in, env)
		}
	}
	for _, bad := range []string{``, `error: unknown option`, `{"success":true,"data":{"object":"message","title":"x"}}`} {
		if _, ok := parseRealResponse([]byte(bad)); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestExtractSession(t *testing.T) {
	key := "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJCrze8SNFZ4kA=="
	human := "Your vault is now unlocked!\n\nTo unlock your vault, set your session key to the `BW_SESSION` environment variable. ex:\n$ export BW_SESSION=\"" + key + "\"\n> $env:BW_SESSION=\"" + key + "\"\n"
	if got := extractSession([]byte(human)); got != key {
		t.Errorf("human output: %q", got)
	}
	if got := extractSession([]byte(key + "\n")); got != key {
		t.Errorf("raw output: %q", got)
	}
	resp := `{"success":true,"data":{"noColor":false,"object":"message","title":"Your vault is now unlocked!","message":"...","raw":"` + key + `"}}`
	if got := extractSession([]byte(resp)); got != key {
		t.Errorf("response output: %q", got)
	}
	for _, junk := range []string{"", "Invalid master password.", "You are logged in!"} {
		if got := extractSession([]byte(junk)); got != "" {
			t.Errorf("junk %q gave %q", junk, got)
		}
	}
}

func TestSocketRouting(t *testing.T) {
	a := socketPath("/run/x", "/home/u/.config/Bitwarden CLI", "sessA")
	b := socketPath("/run/x", "/home/u/.config/Bitwarden CLI", "sessB")
	c := socketPath("/run/x", "/other/root", "sessA")
	if a == b || a == c || b == c {
		t.Errorf("sockets must differ per root and per session: %s %s %s", a, b, c)
	}
	if len(a) > 100 {
		t.Errorf("socket path too long for sun_path: %d", len(a))
	}
	if authHash("sessA") == authHash("sessB") {
		t.Error("auth hashes collide")
	}
}

func TestConfigTimeout(t *testing.T) {
	for in, want := range map[string]time.Duration{"15m": 15 * time.Minute, "90": 90 * time.Second, "0": 0, "never": 0, "off": 0, "1h30m": 90 * time.Minute, "1s": time.Second, "1500ms": time.Second, "0s": 0, "1": time.Second} {
		got, err := parseTimeout(in)
		if err != nil || got != want {
			t.Errorf("parseTimeout(%q) = %v, %v", in, got, err)
		}
	}
	// below one second would be sent as 0 seconds, which means "never"
	for _, bad := range []string{"abc", "-5m", "-1", "500ms", "1ns", "0.5s", "999999999999", "9223372036854775807", "99999999999999999999"} {
		if _, err := parseTimeout(bad); err == nil {
			t.Errorf("parseTimeout(%q) should fail", bad)
		}
	}
}

func TestDaemonEnv(t *testing.T) {
	for k, v := range map[string]string{
		"BW_SESSION": "sess", "BW_PASSWORD": "hunter2", "BW_CLIENTSECRET": "s", "MY_MASTER_PW": "x", "AWS_SECRET_ACCESS_KEY": "y",
		"NODE_EXTRA_CA_CERTS": "/ca.pem", "HTTPS_PROXY": "http://p", "no_proxy": "localhost", "LC_ALL": "C",
		"BWW_MASTER_PASSWORD": "pw-under-wrapper-prefix", "BWW_AUTO_LOCK": "5m", "BWW_REAL_BW": "/x", "NODE_SECRET_THING": "z",
		"XDG_RUNTIME_DIR": "/run/x", "BITWARDENCLI_APPDATA_DIR": "/root", "KEEP_ME": "1", "LC_PASSWORD": "pw-under-lc-prefix",
		"NODE_OPTIONS": "pw-in-an-allowed-name",
	} {
		t.Setenv(k, v)
	}
	names := func(env []string) map[string]bool {
		got := map[string]bool{}
		for _, kv := range env {
			k, _, _ := strings.Cut(kv, "=")
			got[k] = true
		}
		return got
	}
	got := names(daemonEnv([]string{"KEEP_ME"}, nil))
	for _, k := range []string{
		"BW_SESSION", "BW_PASSWORD", "BW_CLIENTSECRET", "MY_MASTER_PW", "AWS_SECRET_ACCESS_KEY",
		// no blanket prefixes: the wrapper's own settings travel in the init message
		"BWW_MASTER_PASSWORD", "BWW_AUTO_LOCK", "BWW_REAL_BW", "NODE_SECRET_THING", "XDG_RUNTIME_DIR", "BITWARDENCLI_APPDATA_DIR",
	} {
		if got[k] {
			t.Errorf("%s must not reach the daemon", k)
		}
	}
	for _, k := range []string{"PATH", "HOME", "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS", "HTTPS_PROXY", "no_proxy", "LC_ALL", "KEEP_ME"} {
		if !got[k] {
			t.Errorf("%s should be passed to the daemon", k)
		}
	}
	t.Setenv("PATH", ".:/usr/bin::bin:/opt/x/bin")
	for _, kv := range daemonEnv(nil, nil) {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok && v != "/usr/bin:/opt/x/bin" {
			t.Errorf("daemon PATH = %q, want only the absolute entries", v)
		}
	}
	// the variable named by --passwordenv never passes: not under an allowed
	// name, not under an allowed prefix, not through pass_env
	for _, pw := range []string{"NODE_OPTIONS", "LC_PASSWORD", "KEEP_ME", "PATH"} {
		if names(daemonEnv([]string{"KEEP_ME"}, []string{"UNRELATED", pw}))[pw] {
			t.Errorf("--passwordenv %s reached the daemon", pw)
		}
	}
}

// The real CLI is resolved to an absolute path before anything detaches, and
// is never the wrapper itself.
func TestFindRealBW(t *testing.T) {
	dir := t.TempDir()
	tools := filepath.Join(dir, "tools")
	os.Mkdir(tools, 0o700)
	cli := filepath.Join(tools, "bw")
	os.WriteFile(cli, []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(tools, "mybw"), []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(tools, "notexec"), []byte("x"), 0o644)
	self, _ := os.Executable()
	selfLink := filepath.Join(dir, "self-link")
	os.Symlink(self, selfLink)
	t.Chdir(dir)

	for _, rel := range []string{"./tools/bw", "tools/bw", "tools/../tools/bw"} {
		got, err := findRealBW(&config{RealBW: rel})
		if err != nil || got != cli || !filepath.IsAbs(got) {
			t.Errorf("real_bw=%s -> %q, %v; want %s", rel, got, err, cli)
		}
	}
	for name, bad := range map[string]string{"the wrapper": self, "a link to the wrapper": selfLink, "missing": "./nope/bw", "not executable": "./tools/notexec", "a directory": "./tools"} {
		if got, err := findRealBW(&config{RealBW: bad}); err == nil {
			t.Errorf("real_bw pointing at %s accepted: %s", name, got)
		}
	}
	// PATH lookup: relative entries become absolute, the wrapper itself is skipped
	selfDir := filepath.Join(dir, "selfdir")
	os.Mkdir(selfDir, 0o700)
	os.Symlink(self, filepath.Join(selfDir, "bw"))
	t.Setenv("PATH", selfDir+string(os.PathListSeparator)+"tools")
	if got, err := findRealBW(&config{}); err != nil || got != cli {
		t.Errorf("PATH lookup -> %q, %v; want %s", got, err, cli)
	}
	if got, err := findRealBW(&config{RealBW: "mybw"}); err != nil || got != filepath.Join(tools, "mybw") {
		t.Errorf("bare name -> %q, %v", got, err)
	}
	t.Setenv("PATH", selfDir)
	if got, err := findRealBW(&config{}); err == nil {
		t.Errorf("only the wrapper on PATH, got %q", got)
	}
}

func TestSealedWith(t *testing.T) {
	macKey := bytes.Repeat([]byte{7}, 32)
	iv := bytes.Repeat([]byte{1}, 16)
	ct := bytes.Repeat([]byte{2}, 80)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(iv)
	mac.Write(ct)
	blob := append(append(append([]byte{2}, iv...), mac.Sum(nil)...), ct...)
	val, _ := json.Marshal(base64.StdEncoding.EncodeToString(blob))
	if got := sealedWith(val, macKey); got != sealOurs {
		t.Errorf("own seal: %d", got)
	}
	if got := sealedWith(val, bytes.Repeat([]byte{8}, 32)); got != sealForeign {
		t.Errorf("foreign seal: %d", got)
	}
	blob[0] = 9
	odd, _ := json.Marshal(base64.StdEncoding.EncodeToString(blob))
	for name, v := range map[string][]byte{"unknown type": odd, "not a string": []byte("null"), "short": []byte(`"AAAA"`)} {
		if got := sealedWith(v, macKey); got != sealUnknown {
			t.Errorf("%s: %d, want unknown", name, got)
		}
	}
	if got := sealedWith(val, nil); got != sealUnknown {
		t.Errorf("no key: %d", got)
	}
}

func TestLoginState(t *testing.T) {
	jwt := func(exp int64) string {
		p := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"x","exp":%d}`, exp)))
		return "eyJhbGciOiJSUzI1NiJ9." + p + ".sig"
	}
	top := func(s string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	in := loginStateOf(top(`{"global_account_activeAccountId":"u1","user_u1_token_accessToken":"` + jwt(100) + `","user_u1_token_refreshToken":"` + jwt(2000000000) + `"}`))
	if !in.authed || !in.hasExp || in.refreshExp.Unix() != 2000000000 {
		t.Errorf("logged in: %+v", in)
	}
	opaque := loginStateOf(top(`{"global_account_activeAccountId":"u1","user_u1_token_accessToken":"a.b.c","user_u1_token_refreshToken":"opaque-token"}`))
	if !opaque.authed || opaque.hasExp {
		t.Errorf("opaque refresh token: %+v", opaque)
	}
	// what the CLI leaves behind after logging itself out
	out := loginStateOf(top(`{"global_account_activeAccountId":null,"user_u1_token_accessToken":null,"user_u1_token_refreshToken":null}`))
	if out.authed || out.hasExp {
		t.Errorf("logged out: %+v", out)
	}
	if st := loginStateOf(top(`{}`)); st.authed {
		t.Errorf("empty file: %+v", st)
	}
	for _, bad := range []string{"", "a.b", "a.!!!.c", "a.e30.c"} {
		if _, ok := jwtExp(bad); ok {
			t.Errorf("jwtExp(%q) should fail", bad)
		}
	}
}

// testOp begins a session operation the way the wrapper does: take the
// exclusive lock, then start a new generation.
func testOp(t *testing.T, co *coord) *sessionOp {
	t.Helper()
	op, err := co.tryBeginOp("test")
	if err != nil || op == nil {
		t.Fatalf("cannot begin a session operation: %v (busy=%v)", err, op == nil)
	}
	if err := co.newGeneration(); err != nil {
		t.Fatal(err)
	}
	return op
}

// testLock begins a lock or logout the way the wrapper does: revoke, then
// take the exclusive lock. end records the outcome and releases the lock.
func testLock(t *testing.T, co *coord) (end func(ok bool)) {
	t.Helper()
	rev, err := co.revoke("test lock")
	if err != nil {
		t.Fatal(err)
	}
	op, err := co.tryBeginOp("lock")
	if err != nil || op == nil {
		t.Fatalf("cannot begin a lock: %v (busy=%v)", err, op == nil)
	}
	return func(ok bool) {
		co.settle(rev.epoch, ok, "test lock failed")
		op.end()
		rev.done()
	}
}

func TestGuardData(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "data.json")
	loggedIn := `{"global_account_activeAccountId":"u1","user_u1_token_accessToken":"tok","user_u1_ciphers_ciphers":{"a":1}}`
	loggedOut := `{"global_account_activeAccountId":null,"user_u1_token_accessToken":null}`
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func() string { b, _ := os.ReadFile(path); return string(b) }
	co, err := openCoord(root)
	if err != nil {
		t.Fatal(err)
	}

	write(loggedIn)
	after := guardData(co)
	write(loggedOut) // the CLI logged itself out during the run
	if !after() || read() != loggedIn {
		t.Errorf("self-logout not restored: %s", read())
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("restored file mode %v", fi.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(root, ".data.json.bww-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}

	after = guardData(co)
	changed := strings.Replace(loggedIn, `"a":1`, `"a":2`, 1)
	write(changed) // a normal run that changed data
	if after() || read() != changed {
		t.Error("a run that stayed logged in must not be touched")
	}

	write(loggedOut)
	after = guardData(co) // not logged in before: nothing to protect
	if after() || read() != loggedOut {
		t.Error("guard must not act when the CLI was logged out before the run")
	}

	// An explicit logout (or lock, or new unlock) through the wrapper, in
	// every ordering against a guarded command. "clears" is the real logout
	// erasing the data file. The guard must never bring the old login back.
	orderings := map[string]func() (restored bool){
		"guard starts before the operation, ends during it": func() bool {
			after := guardData(co)
			op := testOp(t, co)
			defer op.end()
			write(loggedOut)
			return after()
		},
		"guard starts before the operation, ends after it": func() bool {
			after := guardData(co)
			op := testOp(t, co)
			write(loggedOut)
			op.end()
			return after()
		},
		"guard starts during the operation, ends during it": func() bool {
			op := testOp(t, co) // logout begins
			defer op.end()
			after := guardData(co) // another command snapshots the still-unlocked vault
			write(loggedOut)       // the real logout clears the vault
			return after()         // the guard finishes before the logout does
		},
		"guard starts during the operation, ends after it": func() bool {
			op := testOp(t, co)
			after := guardData(co)
			write(loggedOut)
			op.end()
			return after()
		},
		"guard overlaps two operations, the second still running": func() bool {
			testOp(t, co).end()
			after := guardData(co)
			op := testOp(t, co)
			defer op.end()
			write(loggedOut)
			return after()
		},
		// A process that dies inside an operation: the kernel drops its lock.
		"operation in a process that died, guard started before it": func() bool {
			after := guardData(co)
			testOp(t, co).f.Close()
			write(loggedOut)
			return after()
		},
		"operation in a process that died, guard started during it": func() bool {
			op := testOp(t, co)
			after := guardData(co)
			write(loggedOut)
			op.f.Close()
			return after()
		},
		"only the generation changed (a sweep that found nobody)": func() bool {
			after := guardData(co)
			co.newGeneration()
			write(loggedOut)
			return after()
		},
		"a logout revoked, guard started before it": func() bool {
			after := guardData(co)
			end := testLock(t, co)
			write(loggedOut)
			end(true)
			return after()
		},
		"a logout revoked, guard started during it": func() bool {
			end := testLock(t, co)
			after := guardData(co)
			write(loggedOut)
			end(true)
			return after()
		},
	}
	for name, run := range orderings {
		write(loggedIn)
		if run() || read() != loggedOut {
			t.Errorf("%s: the logout was undone (%s)", name, read())
		}
	}
	// ... and once no operation overlaps, guards work again.
	write(loggedIn)
	if m, _ := co.mark(); m.Access != accessOpen || m.active {
		t.Fatalf("test setup: state after the orderings: %+v", m)
	}
	after = guardData(co)
	write(loggedOut)
	if !after() || read() != loggedIn {
		t.Error("guard stayed disarmed after the operations ended")
	}

	// A different root has its own coordination state.
	other, err := openCoord(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write(loggedIn)
	after = guardData(co)
	otherOp := testOp(t, other)
	write(loggedOut)
	if !after() {
		t.Error("a session command in another root must not cancel this root's restore")
	}
	otherOp.end()

	// Several guards finishing at once: exactly the state before, no clash.
	write(loggedIn)
	var afters []func() bool
	for i := 0; i < 8; i++ {
		afters = append(afters, guardData(co))
	}
	write(loggedOut)
	var wg sync.WaitGroup
	for _, a := range afters {
		wg.Add(1)
		go func() { defer wg.Done(); a() }()
	}
	wg.Wait()
	if read() != loggedIn {
		t.Errorf("concurrent restores corrupted the file: %s", read())
	}
	if left, _ := filepath.Glob(filepath.Join(root, ".data.json.bww-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}

	// Without readable coordination state nothing is restored: neither when
	// it is unreadable from the start, nor when it becomes so during the run.
	for _, when := range []string{"before", "during"} {
		write(loggedIn)
		os.Remove(co.path("state"))
		if when == "before" {
			os.WriteFile(co.path("state"), []byte("not json"), 0o600)
		}
		after = guardData(co)
		os.WriteFile(co.path("state"), []byte("not json"), 0o600)
		write(loggedOut)
		if after() || read() != loggedOut {
			t.Errorf("a restore happened although the coordination state was damaged %s the run", when)
		}
	}
	os.Remove(co.path("state"))
}

func TestCoord(t *testing.T) {
	root := t.TempDir()
	co, err := openCoord(root)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := co.mark()
	if err != nil || m1.Gen == "" || m1.active || m1.Access != accessOpen || m1.Epoch != 0 {
		t.Fatalf("first mark: %+v %v", m1, err)
	}
	if !co.current(m1) {
		t.Error("a fresh mark must be current")
	}
	// one session operation at a time
	op := testOp(t, co)
	if co.current(m1) {
		t.Error("beginning an operation must void older marks at once")
	}
	if busy, err := co.tryBeginOp("second"); err != nil || busy != nil {
		t.Fatalf("a second operation got the lock: %v %v", busy, err)
	}
	if _, err := co.beginOp("second", false, 50*time.Millisecond, nil); !errors.Is(err, errOpBusy) {
		t.Errorf("waiting for a busy root: %v", err)
	}
	if _, err := co.beginOp("second", false, 0, func() bool { return false }); !errors.Is(err, errCancelled) {
		t.Errorf("a wait that is no longer wanted: %v", err)
	}
	m2, _ := co.mark()
	if !m2.active || m2.Gen == m1.Gen || m2.Epoch != m1.Epoch {
		t.Errorf("during the operation: %+v (before: %+v)", m2, m1)
	}
	// the lock lives as long as anything holds its descriptor (the real CLI inherits it)
	inherited, err := syscall.Dup(int(op.f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	op.end()
	if m, _ := co.mark(); !m.active {
		t.Error("operation counted as over while its real CLI (inherited lock) is alive")
	}
	syscall.Close(inherited)
	m3, _ := co.mark()
	if m3.active || m3.Gen != m2.Gen || !co.current(m2) {
		t.Errorf("after the operation: %+v", m3)
	}
	if next, err := co.tryBeginOp("next"); err != nil || next == nil {
		t.Fatalf("the lock was not released: %v", err)
	} else {
		next.end()
	}
	// same state through another spelling of the root
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	co2, err := openCoord(canonicalPath(alias))
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := co2.mark(); m.Gen != m3.Gen {
		t.Error("an alias of the root sees a different generation")
	}
	// registry
	if co.lookup("abc") != "" {
		t.Error("empty registry returned a socket")
	}
	writeAtomic(co.entry("abc"), []byte("/run/x/a.sock"))
	if co2.lookup("abc") != "/run/x/a.sock" || len(co.daemons()) != 1 {
		t.Errorf("registry: %v", co.daemons())
	}
	co.unregister("abc", "/other.sock") // not ours: stays
	if co.lookup("abc") == "" {
		t.Error("unregister removed an entry that points elsewhere")
	}
	co.unregister("abc", "/run/x/a.sock")
	if len(co.daemons()) != 0 {
		t.Errorf("registry not empty: %v", co.daemons())
	}
	// only a private directory owned by the user is accepted
	for _, mode := range []os.FileMode{0o755, 0o750, 0o707} {
		os.Chmod(co.dir, mode)
		if _, err := openCoord(root); err == nil {
			t.Errorf("coordination directory with mode %o accepted", mode)
		}
	}
	os.Chmod(co.dir, 0o700)
	// a state file nobody can make sense of means: no caching, no restoring
	good, _ := os.ReadFile(co.path("state"))
	for _, damaged := range []string{"", "{", `{"gen":"","epoch":0,"access":"open"}`, `{"gen":"x","epoch":0,"access":"wide-open"}`} {
		os.WriteFile(co.path("state"), []byte(damaged), 0o600)
		if _, err := co.mark(); err == nil {
			t.Errorf("damaged state %q accepted", damaged)
		}
		if co.current(m3) {
			t.Errorf("a mark counted as current against damaged state %q", damaged)
		}
	}
	os.WriteFile(co.path("state"), good, 0o600)
	os.RemoveAll(co.dir)
	if co.current(m3) {
		t.Error("a mark must not count as current when the coordination state is gone")
	}
}

// Revocation is persistent and separate from cache invalidation.
func TestRevocationState(t *testing.T) {
	root := t.TempDir()
	co, err := openCoord(root)
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data.json")
	unlocked := `{"global_account_activeAccountId":"u1","user_u1_token_accessToken":"tok","__PROTECTED__u1_user_auto":"k"}`
	locked := `{"global_account_activeAccountId":"u1","user_u1_token_accessToken":"tok"}`
	loggedOut := `{"global_account_activeAccountId":null}`
	put := func(s string) { os.WriteFile(data, []byte(s), 0o600) }
	isBlocked := func() bool { m, err := co.mark(); return err != nil || co.blocked(m) }

	// a stored user key counts even when the login state is not understood
	keyOnly := `{"some_future_account_key":"u1","__PROTECTED__u1_user_auto":"k"}`
	otherProtected := `{"global_account_activeAccountId":null,"__PROTECTED__device_thing":"k"}`
	for content, want := range map[string]bool{unlocked: true, locked: false, loggedOut: false, "{not json": true, keyOnly: true, otherProtected: false} {
		put(content)
		if sessionUsable(root) != want {
			t.Errorf("sessionUsable(%s) != %v", content, want)
		}
	}
	os.Remove(data)
	if sessionUsable(root) {
		t.Error("no data file: nothing usable")
	}

	put(unlocked)
	start, _ := co.mark()
	if isBlocked() {
		t.Fatal("blocked from the start")
	}
	// a reload / unlock beginning: new generation, same epoch, access untouched
	co.newGeneration()
	m, _ := co.mark()
	if m.Gen == start.Gen || m.Epoch != start.Epoch || m.Access != accessOpen || isBlocked() {
		t.Errorf("cache invalidation must not revoke: %+v", m)
	}

	// a lock begins
	rev, err := co.revoke("lock")
	if err != nil {
		t.Fatal(err)
	}
	epoch := rev.epoch
	r, _ := co.mark()
	if epoch != start.Epoch+1 || r.Epoch != epoch || r.Gen == m.Gen || r.Access != accessRevoking || !r.revoking {
		t.Errorf("after revoke: %+v", r)
	}
	if !isBlocked() {
		t.Error("access must be blocked from the revocation on")
	}
	// an unlock requested before the lock can never reopen
	if ok, _ := co.reopen(start.Epoch); ok {
		t.Error("an unlock from before the revocation reopened access")
	}
	if !isBlocked() {
		t.Error("the stale unlock changed the access state")
	}
	// the lock fails: blocked, and it stays so across processes (it is on disk)
	co.settle(epoch, false, "lock did not complete")
	rev.done()
	if b, _ := co.mark(); b.Access != accessBlocked || b.Reason == "" || !isBlocked() {
		t.Errorf("after a failed lock: %+v", b)
	}
	if again, _ := openCoord(root); again == nil {
		t.Fatal("cannot reopen coordination")
	} else if m, _ := again.mark(); !again.blocked(m) {
		t.Error("the block did not survive a new process")
	}
	// a second, later lock: the outcome of the first must not overwrite its state
	rev2, _ := co.revoke("lock")
	epoch2 := rev2.epoch
	co.settle(epoch, true, "")
	if m, _ := co.mark(); m.Access != accessRevoking {
		t.Errorf("a stale settle changed the state: %+v", m)
	}
	// While it is pending, everything is blocked, whatever the data file
	// says, and no unlock counts, not even one requested after it.
	put(locked)
	if !isBlocked() {
		t.Error("not blocked while a revocation is pending")
	}
	if ok, _ := co.reopen(epoch2); ok {
		t.Error("an unlock reopened access while a revocation was pending")
	}
	if op, _ := co.tryBeginOp("unlock"); op != nil {
		t.Error("an unlock began while a revocation was pending")
	}
	put(unlocked)
	rev2.done()
	// that lock is interrupted before recording anything. Once the data file
	// shows no usable session, nothing needs protecting any more.
	put(locked)
	if isBlocked() {
		t.Error("blocked although no session is usable on disk")
	}
	put(unlocked) // ... but a session that is usable (again) is still covered
	if !isBlocked() {
		t.Error("an unfinished revocation must cover a usable session")
	}
	// a fresh unlock, requested after the revocation, reopens
	if ok, _ := co.reopen(epoch2); !ok || isBlocked() {
		t.Error("a fresh, successful unlock must reopen access")
	}
	// a successful lock leaves access open (the real CLI answers "locked")
	rev3, _ := co.revoke("lock")
	put(locked)
	co.settle(rev3.epoch, true, "")
	rev3.done()
	if m, _ := co.mark(); m.Access != accessOpen || isBlocked() {
		t.Errorf("after a successful lock: %+v", m)
	}
}

func TestCanonicalRoot(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "actual", "vault")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "vault-alias")
	if err := os.Symlink(realDir, alias); err != nil {
		t.Fatal(err)
	}
	want := canonicalPath(realDir)
	for _, spelled := range []string{alias, alias + "/", alias + "/.", base + "/actual/./vault", base + "/actual/../actual/vault"} {
		t.Setenv("BITWARDENCLI_APPDATA_DIR", spelled)
		if got := appDataDir("/nonexistent/bw"); got != want {
			t.Errorf("root for %q = %q, want %q", spelled, got, want)
		}
	}
	// the daemon of a root is found through any spelling of it
	t.Setenv("BITWARDENCLI_APPDATA_DIR", alias)
	viaAlias := socketPath("/run/x", appDataDir("/nonexistent/bw"), "sess")
	t.Setenv("BITWARDENCLI_APPDATA_DIR", realDir)
	if viaReal := socketPath("/run/x", appDataDir("/nonexistent/bw"), "sess"); viaAlias != viaReal {
		t.Errorf("alias and real path route to different daemons: %s vs %s", viaAlias, viaReal)
	}
	// a root that does not exist yet keeps its missing part, below a resolved parent
	if got := canonicalPath(filepath.Join(alias, "new", "dir")); got != filepath.Join(want, "new", "dir") {
		t.Errorf("not-yet-existing root: %q", got)
	}
}

func TestSealerReleasesKeyPage(t *testing.T) {
	maps := func() int {
		b, err := os.ReadFile("/proc/self/maps")
		if err != nil {
			t.Skip("no /proc/self/maps on this system")
		}
		return bytes.Count(b, []byte("\n"))
	}
	s, err := newSealer()
	if err != nil {
		t.Fatal(err)
	}
	sealed := s.seal([]byte("secret"))
	if string(s.open(sealed)) != "secret" {
		t.Fatal("seal/open round trip failed")
	}
	s.wipe()
	s.wipe() // idempotent
	if s.key != nil || s.page != nil || s.open(sealed) != nil || s.seal([]byte("x")) != nil {
		t.Error("a wiped sealer must hold no key and seal nothing")
	}
	before := maps()
	for i := 0; i < 3000; i++ { // as many load/dispose cycles as years of syncs
		s, err := newSealer()
		if err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		s.wipe()
	}
	if grown := maps() - before; grown > 100 {
		t.Errorf("%d mappings leaked over 3000 load/dispose cycles", grown)
	}
}

// Auto-lock destroys the session on disk. It must do that as a session
// operation: exclusively, and only if (checked under the lock) the session is
// still this daemon's and the daemon is still idle.
func TestAutoLock(t *testing.T) {
	const limit = time.Minute
	type env struct {
		d                *daemon
		co               *coord
		started, release string
		write            func(macKey []byte)
	}
	ourKey, otherKey := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	setup := func(t *testing.T) *env {
		root, tmp := t.TempDir(), t.TempDir()
		co, err := openCoord(root)
		if err != nil {
			t.Fatal(err)
		}
		e := &env{co: co, started: filepath.Join(tmp, "lock-started"), release: filepath.Join(tmp, "lock-release")}
		// A stand-in for the real CLI: reports that `bw lock` started, then
		// stays in it until the test lets it finish.
		fake := filepath.Join(tmp, "bw")
		script := "#!/bin/sh\n: > '" + e.started + "'\nwhile [ ! -e '" + e.release + "' ]; do sleep 0.01; done\n"
		if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		e.write = func(macKey []byte) { // the CLI unlocked with the session that has this MAC key
			iv, ct := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 80)
			mac := hmac.New(sha256.New, macKey)
			mac.Write(iv)
			mac.Write(ct)
			blob := append(append(append([]byte{2}, iv...), mac.Sum(nil)...), ct...)
			data := fmt.Sprintf(`{"global_account_activeAccountId":"u1","user_u1_token_accessToken":"tok","__PROTECTED__u1_user_auto":%q}`, base64.StdEncoding.EncodeToString(blob))
			if err := os.WriteFile(filepath.Join(root, "data.json"), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		e.write(ourKey)
		mark, err := co.mark()
		if err != nil {
			t.Fatal(err)
		}
		e.d = &daemon{root: root, co: co, realBW: fake, macKey: append([]byte(nil), ourKey...), wake: make(chan struct{}, 1),
			tag: "session-tag", started: time.Now().Add(-time.Hour)}
		e.d.src.Store(&source{gen: mark})
		return e
	}
	ran := func(e *env) bool { _, err := os.Stat(e.started); return err == nil }
	waitFor := func(t *testing.T, p string) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(2 * time.Millisecond) {
			if _, err := os.Stat(p); err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", p)
			}
		}
	}

	t.Run("an unlock in another shell finishes while the daemon wants to lock", func(t *testing.T) {
		e := setup(t)
		unlock := testOp(t, e.co) // the unlock is running: lock held, new generation
		if e.d.autoLockNow(limit, "lock") {
			t.Fatal("auto-lock did not wait for the running unlock")
		}
		if ran(e) || e.d.closing.Load() {
			t.Fatal("auto-lock acted while the root was busy")
		}
		e.write(otherKey) // the unlock succeeded: the session on disk is the new one
		unlock.end()
		if !e.d.autoLockNow(limit, "lock") {
			t.Fatal("the superseded daemon should be done now")
		}
		if ran(e) {
			t.Error("auto-lock ran `bw lock` against the newly unlocked session")
		}
		if !e.d.closing.Load() {
			t.Error("the superseded daemon did not wipe its memory")
		}
	})
	t.Run("a new unlock done with the real CLI directly", func(t *testing.T) {
		e := setup(t)
		e.write(otherKey) // no wrapper involved: generation unchanged, but the session is not ours
		if !e.d.autoLockNow(limit, "lock") || ran(e) {
			t.Error("auto-lock must wipe its memory and leave the foreign session alone")
		}
	})
	t.Run("used again before the lock was taken", func(t *testing.T) {
		e := setup(t)
		e.co.startActivity(e.d.tag) // an admitted command, answered by whatever path
		e.co.renew(e.d.tag)         // ... which has finished just now
		if e.d.autoLockNow(limit, "lock") || ran(e) || e.d.closing.Load() {
			t.Error("auto-lock must stand down when the daemon is no longer idle")
		}
		if op, _ := e.co.tryBeginOp("next"); op == nil {
			t.Error("the operation lock was not released")
		} else {
			op.end()
		}
	})
	t.Run("evict only frees memory", func(t *testing.T) {
		e := setup(t)
		before, _ := e.co.mark()
		if !e.d.autoLockNow(limit, "evict") || ran(e) || !e.d.closing.Load() {
			t.Error("evict must wipe memory without running the real CLI")
		}
		if after, _ := e.co.mark(); !e.co.current(before) || after.Epoch != before.Epoch || after.Access != accessOpen {
			t.Errorf("evict must not revoke anything: %+v", after)
		}
	})
	t.Run("idle and still ours: locks as an exclusive session operation", func(t *testing.T) {
		e := setup(t)
		before, _ := e.co.mark()
		loggedIn, _ := os.ReadFile(filepath.Join(e.d.root, "data.json"))
		pending := guardData(e.co) // a guarded command that began before the auto-lock
		done := make(chan bool)
		go func() { done <- e.d.autoLockNow(limit, "lock") }()
		waitFor(t, e.started) // `bw lock` is running
		during, _ := e.co.mark()
		if !during.active || during.Gen == before.Gen || during.Epoch != before.Epoch+1 || during.Access != accessRevoking || e.co.current(before) {
			t.Errorf("while locking: %+v (before: %+v)", during, before)
		}
		if op, _ := e.co.tryBeginOp("unlock"); op != nil {
			t.Error("an unlock could begin while the auto-lock was running")
		}
		late := guardData(e.co) // a guarded command that begins while it runs
		// both guarded commands end with their CLI logged out
		os.WriteFile(filepath.Join(e.d.root, "data.json"), []byte(`{"global_account_activeAccountId":null}`), 0o600)
		if pending() || late() {
			t.Error("a restore happened while the auto-lock was running")
		}
		os.WriteFile(e.release, nil, 0o600)
		if !<-done {
			t.Error("auto-lock did not finish")
		}
		if pending() || late() {
			t.Error("a guard overlapping the auto-lock restored after it finished")
		}
		if b, _ := os.ReadFile(filepath.Join(e.d.root, "data.json")); bytes.Equal(b, loggedIn) {
			t.Error("the data file from before the lock was restored")
		}
		if m, _ := e.co.mark(); m.active {
			t.Error("operation still active after the auto-lock finished")
		}
	})

	// The same failure cases as a manual lock (they share coord.finishLock).
	failing := func(t *testing.T, e *env, body string) (runs func() int) {
		count := filepath.Join(filepath.Dir(e.started), "runs")
		script := "#!/bin/sh\necho x >> '" + count + "'\n" + body + "\n"
		if err := os.WriteFile(e.d.realBW, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		return func() int { b, _ := os.ReadFile(count); return bytes.Count(b, []byte("x")) }
	}
	t.Run("the real lock fails: access stays blocked", func(t *testing.T) {
		retryPause = time.Millisecond
		defer func() { retryPause = time.Second }()
		e := setup(t)
		runs := failing(t, e, "exit 1") // fails before invalidating the session
		if !e.d.autoLockNow(limit, "lock") || !e.d.closing.Load() {
			t.Fatal("the daemon must wipe its memory even when the real lock fails")
		}
		if runs() != 3 {
			t.Errorf("%d attempts, want 3 (one plus two retries)", runs())
		}
		m, _ := e.co.mark()
		if m.Access != accessBlocked || !e.co.blocked(m) || m.active {
			t.Errorf("after a failed auto-lock: %+v", m)
		}
		// the old session cannot load another cache, nor restore, nor reopen
		fresh := &daemon{root: e.d.root, co: e.co, realBW: e.d.realBW, wake: make(chan struct{}, 1)}
		if _, _, err := fresh.loadCurrent("old-session"); !errors.Is(err, errBlocked) {
			t.Errorf("a new daemon for the old session: %v, want errBlocked", err)
		}
		before := guardData(e.co)
		os.WriteFile(filepath.Join(e.d.root, "data.json"), []byte(`{"global_account_activeAccountId":null}`), 0o600)
		if before() {
			t.Error("a restore happened while access is blocked")
		}
	})
	t.Run("a retry never locks a session that is not ours any more", func(t *testing.T) {
		retryPause = time.Millisecond
		defer func() { retryPause = time.Second }()
		e := setup(t)
		newState := filepath.Join(filepath.Dir(e.started), "new-state")
		e.write(otherKey) // prepare what "somebody unlocked with the real CLI" looks like
		b, _ := os.ReadFile(filepath.Join(e.d.root, "data.json"))
		os.WriteFile(newState, b, 0o600)
		e.write(ourKey)
		// first attempt fails; meanwhile the session on disk becomes someone else's
		runs := failing(t, e, "cp '"+newState+"' '"+filepath.Join(e.d.root, "data.json")+"'; exit 1")
		if !e.d.autoLockNow(limit, "lock") {
			t.Fatal("auto-lock did not finish")
		}
		if runs() != 1 {
			t.Errorf("%d attempts: the retry ran against a session that is not ours", runs())
		}
		if now, _ := os.ReadFile(filepath.Join(e.d.root, "data.json")); !bytes.Equal(now, b) {
			t.Error("the newer session was touched")
		}
		if m, _ := e.co.mark(); m.Access != accessOpen {
			t.Errorf("the newer session is left blocked: %+v", m)
		}
	})
}

// Field extraction: every plaintext buffer the decoder made is either handed
// to the caller or wiped; nothing is left that nobody owns.
func TestExtractFieldOwnership(t *testing.T) {
	const itemJSON = `{"id":"1","type":1,"name":"n","notes":"SECRET-NOTES","login":{"username":"SECRET-USER","password":"SECRET-PASS","totp":"SECRET-TOTP","uris":[{"uri":"https://SECRET-URI.example"},{"uri":"https://SECRET-URI2.example"}]}}`
	want := map[filterKind]string{
		fUsername: `"SECRET-USER"`, fPassword: `"SECRET-PASS"`, fTotp: `"SECRET-TOTP"`,
		fNotes: `"SECRET-NOTES"`, fURI: `"https://SECRET-URI.example"`,
	}
	for f, token := range want {
		plain := []byte(itemJSON)
		tok, scratch := extractField(plain, f)
		if string(tok) != token {
			t.Errorf("field %d = %s, want %s", f, tok, token)
		}
		// 1 plaintext item + 6 decoded fields, minus the one handed over
		if len(scratch) != 6 {
			t.Errorf("field %d: %d scratch buffers, want 6", f, len(scratch))
		}
		for _, b := range scratch {
			if len(b) > 0 && len(tok) > 0 && &b[0] == &tok[0] {
				t.Errorf("field %d: the returned buffer is also listed as scratch", f)
			}
		}
		wipeAll(scratch) // what vault.field does
		for i, b := range scratch {
			if bytes.Contains(b, []byte("SECRET")) || bytes.Count(b, []byte{0}) != len(b) {
				t.Errorf("field %d: scratch buffer %d was not wiped: %q", f, i, b)
			}
		}
		if string(tok) != token {
			t.Errorf("field %d: wiping the scratch buffers damaged the result: %q", f, tok)
		}
		wipe(tok) // the owner releases it
	}
	// nothing selected: everything decoded is scratch
	for _, in := range []string{`{"type":2,"notes":"SECRET-NOTES"}`, `{"type":1,"login":{"password":"SECRET-PASS","uris":[]}}`, `not json SECRET`} {
		tok, scratch := extractField([]byte(in), fUsername)
		if string(tok) != "null" {
			t.Errorf("%s: got %s", in, tok)
		}
		wipeAll(scratch)
		for _, b := range scratch {
			if bytes.Contains(b, []byte("SECRET")) {
				t.Errorf("%s: plaintext left behind: %q", in, b)
			}
		}
	}
	// through the vault: the sealed item is untouched, the result is owned by the caller
	seal, err := newSealer()
	if err != nil {
		t.Fatal(err)
	}
	v := &vault{seal: seal, byID: map[string]*item{}, memo: map[string][]byte{}, totpAllowed: map[string]bool{}}
	defer v.wipe()
	if err := v.addItem([]byte(itemJSON), 0); err != nil {
		t.Fatal(err)
	}
	it := v.items[0][0]
	first := v.field(it, fPassword)
	if string(first) != `"SECRET-PASS"` {
		t.Fatalf("field: %s", first)
	}
	wipe(first)
	if again := v.field(it, fPassword); string(again) != `"SECRET-PASS"` {
		t.Errorf("wiping a result damaged the vault: %s", again)
	}
}

// A vault keeps only a bounded amount of memoized real-CLI responses, however
// many distinct queries (changing URLs) are asked.
func TestMemoBudget(t *testing.T) {
	seal, err := newSealer()
	if err != nil {
		t.Fatal(err)
	}
	v := &vault{seal: seal, byID: map[string]*item{}, memo: map[string][]byte{}, totpAllowed: map[string]bool{}}
	defer v.wipe()
	calls := 0
	big := strings.Repeat("x", 1<<20)
	ctx := &reqCtx{real: func(args ...string) ([]byte, error) {
		calls++
		return []byte(`{"success":true,"data":{"object":"list","data":[{"url":"` + args[len(args)-1] + `","pad":"` + big + `"}]}}`), nil
	}}
	const queries = 100 // 100 MiB of distinct answers
	for i := 0; i < queries; i++ {
		url := fmt.Sprintf("https://host-%d.example", i)
		res := v.memoized(ctx, "list", "items", "--url", url)
		if res.kind != rList || len(res.list) != 1 || !bytes.Contains(res.list[0], []byte(url)) {
			t.Fatalf("query %d: wrong answer", i)
		}
		if v.memoBytes > memoBudget {
			t.Fatalf("after %d queries the cache holds %d bytes, budget is %d", i+1, v.memoBytes, memoBudget)
		}
	}
	if calls != queries {
		t.Errorf("%d real runs for %d distinct queries", calls, queries)
	}
	retained := 0
	for k, m := range v.memo {
		retained += len(k) + len(m)
	}
	if retained != v.memoBytes || len(v.memo) == 0 || len(v.memo) >= queries {
		t.Errorf("accounting: %d entries, %d bytes counted, %d bytes retained", len(v.memo), v.memoBytes, retained)
	}
	// cached entries still answer without the real CLI; the rest still answer through it
	v.memoized(ctx, "list", "items", "--url", "https://host-0.example")
	if calls != queries {
		t.Error("a cached query went to the real CLI again")
	}
	if res := v.memoized(ctx, "list", "items", "--url", fmt.Sprintf("https://host-%d.example", queries-1)); res.kind != rList || calls != queries+1 {
		t.Error("a query beyond the budget must still be answered, through the real CLI")
	}
	v.wipe()
	if v.memoBytes != 0 || len(v.memo) != 0 {
		t.Errorf("budget not cleared with the vault: %d bytes, %d entries", v.memoBytes, len(v.memo))
	}
}

// The owner file names a process by pid and start time. A pid that has been
// recycled by an unrelated process must not be signalled.
func TestSignalOwnerChecksIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process start times come from /proc")
	}
	co, err := openCoord(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	op := testOp(t, co)
	defer op.end()
	bystander := exec.Command("sleep", "60")
	if err := bystander.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- bystander.Wait() }()
	defer bystander.Process.Kill()
	pid := bystander.Process.Pid
	start := procStart(pid)
	if start == 0 {
		t.Fatal("no start time for a running process")
	}
	op.record(opOwner{PID: pid, Start: start + 1, Kind: "unlock"}) // same pid, another process
	co.signalOwner(syscall.SIGKILL, false)
	op.record(opOwner{PID: os.Getpid(), Child: pid, ChildStart: start + 1, Kind: "unlock"})
	co.signalOwner(syscall.SIGKILL, true)
	select {
	case <-done:
		t.Fatal("a process that only shares the recorded pid was killed")
	case <-time.After(200 * time.Millisecond):
	}
	op.record(opOwner{PID: pid, Start: start, Kind: "unlock"}) // the recorded process itself
	co.signalOwner(syscall.SIGKILL, false)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the recorded owner was not signalled")
	}
}

// A real CLI that inherited the operation lock from a wrapper that was
// killed before it could record its child is not in the owner file. A lock
// finds it through the lock file and is not shut out.
func TestOrphanedOperationHolder(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("holders of a lock file can only be found through /proc")
	}
	defer func(d time.Duration) { opKillAfter = d }(opKillAfter)
	opKillAfter = 50 * time.Millisecond
	co, err := openCoord(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	op := testOp(t, co)
	orphan := exec.Command("sleep", "60")
	orphan.ExtraFiles = []*os.File{op.f}
	if err := orphan.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- orphan.Wait() }()
	defer orphan.Process.Kill()
	op.end() // the wrapper is gone, its owner record with it; the child holds the lock
	if m, _ := co.mark(); !m.active {
		t.Fatal("test setup: the child does not hold the operation lock")
	}
	lock, err := co.beginOp("lock", true, 10*time.Second, nil)
	if err != nil || lock == nil {
		t.Fatalf("the lock could not take over: %v", err)
	}
	lock.end()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("the orphaned holder is still running")
	}
}

// Finding 10. The --response envelope is written into one buffer that is
// sized up front: no second buffer with the whole list exists, and the one
// buffer never grows (growing would leave the outgrown copy behind).
func TestEnvelopeSingleBuffer(t *testing.T) {
	items := [][]byte{[]byte(`{"id":"a","login":{"password":"s3cret-1"}}`), []byte(`{"id":"b","login":{"password":"s3cret-2"}}`)}
	big := make([][]byte, 3000)
	for i := range big {
		big[i] = items[i%2]
	}
	results := map[string]*result{
		"list":       {kind: rList, list: items, owned: true},
		"long list":  {kind: rList, list: big, owned: true},
		"empty list": {kind: rList, owned: true},
		"object":     {kind: rObj, raw: items[0], owned: true},
		"string":     {kind: rStr, raw: []byte(`"s3cret-1"`), owned: true},
		"template":   {kind: rTmpl, raw: []byte(`{"a":1}`), owned: true},
		"error":      {kind: rErr, msg: "More than one result was found.\n\tx", errData: []byte(`["a","b"]`)},
	}
	for name, r := range results {
		env := r.envelope()
		if cap(env) != r.envelopeSize() {
			t.Errorf("%s: the envelope buffer grew (cap %d, sized %d): an outgrown copy was left behind", name, cap(env), r.envelopeSize())
		}
		if !json.Valid(env) {
			t.Errorf("%s: invalid JSON: %s", name, env)
		}
		if r.kind != rErr { // (an error message is quoted first; it is not vault data)
			if allocs := testing.AllocsPerRun(5, func() { r.envelope() }); allocs != 1 {
				t.Errorf("%s: building the envelope allocates %v buffers, want the one it returns", name, allocs)
			}
		}
		// Same bytes as joining first and wrapping afterwards.
		if r.kind == rList {
			want := `{"success":true,"data":{"object":"list","data":` + string(joinJSON(r.list)) + `}}`
			if string(env) != want {
				t.Errorf("%s: envelope differs from the joined form", name)
			}
		}
		// Every mode still renders, and what render returns is all there is:
		// in --response mode without --pretty the envelope itself is the output.
		out, _, _ := r.render(outFlags{Response: true})
		if string(out) != string(env) {
			t.Errorf("%s: --response output is not the envelope", name)
		}
	}
	// The pretty-printer's input is scratch and is wiped for owned results.
	r := &result{kind: rList, list: items, owned: true}
	if out, _, _ := r.render(outFlags{Response: true, Pretty: true}); !json.Valid(out) || !bytes.Contains(out, []byte("s3cret-1")) {
		t.Errorf("pretty --response output: %s", out)
	}
}

// A daemon says "stopped" only when every launch of a real CLI is over:
// not while a process sits between Start and registration, and not while a
// killed one has not been reaped. Past the deadline the answer is "not
// stopped", and no launch can begin any more.
func TestShutdownCompletion(t *testing.T) {
	defer func(d time.Duration) { childStopWait = d }(childStopWait)
	childStopWait = 100 * time.Millisecond
	newDaemon := func(t *testing.T) *daemon {
		co, err := openCoord(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return &daemon{co: co, wake: make(chan struct{}, 1)}
	}
	sleeper := func(t *testing.T) (*exec.Cmd, chan struct{}) {
		c := exec.Command("sleep", "60")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		exited := make(chan struct{})
		go func() { c.Wait(); close(exited) }()
		t.Cleanup(func() { c.Process.Kill() })
		return c, exited
	}
	gone := func(t *testing.T, exited chan struct{}) {
		t.Helper()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Fatal("the child was not killed")
		}
	}
	t.Run("a process started but not yet registered", func(t *testing.T) {
		d := newDaemon(t)
		if !d.kids.reserve() { // the launcher is between "reserve" and "started"
			t.Fatal("cannot reserve")
		}
		child, exited := sleeper(t)
		if d.shutdown("test") {
			t.Fatal("shutdown reported complete while a started process was not on record yet")
		}
		if d.kids.reserve() {
			t.Fatal("a launch was accepted after shutdown began")
		}
		d.linger = false              // (this test process must not exit)
		d.kids.started(child.Process) // registration arrives late: the process is killed at once
		gone(t, exited)
		if d.shutdown("test") {
			t.Fatal("shutdown reported complete before the process was waited for")
		}
		d.linger = false
		d.kids.done(child.Process)
		if !d.shutdown("test") {
			t.Fatal("shutdown did not complete after the launch was over")
		}
	})
	t.Run("a killed process that is not reaped within the deadline", func(t *testing.T) {
		d := newDaemon(t)
		d.kids.reserve()
		child, exited := sleeper(t)
		d.kids.started(child.Process)
		if d.shutdown("test") {
			t.Fatal("shutdown reported complete past its deadline with a launch still open")
		}
		d.linger = false
		gone(t, exited) // killed, but the launcher has not come back from waiting for it
		if d.shutdown("test") {
			t.Fatal("asked again: still not complete, and must say so")
		}
		d.linger = false
		d.kids.done(child.Process)
		if !d.shutdown("test") {
			t.Fatal("shutdown did not complete after the launch was over")
		}
	})
	t.Run("a launch that never started", func(t *testing.T) {
		d := newDaemon(t)
		d.kids.reserve()
		d.kids.done(nil) // Start failed
		if !d.shutdown("test") {
			t.Fatal("shutdown did not complete with no launch open")
		}
	})
}

// The socket directory is chosen so that a socket address fits the system
// limit, and a directory that cannot work is refused before any daemon is
// started.
func TestRuntimeBase(t *testing.T) {
	mac := "/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T" // a typical macOS TMPDIR
	for _, c := range []struct{ explicit, xdg, tmp, want string }{
		{"/custom/run", "/run/user/1000", "/tmp", "/custom/run"},
		{"", "/run/user/1000", "/tmp", "/run/user/1000/bw-wrapper"},
		{"", "", "/tmp", "/tmp/bw-wrapper-501"},
		{"", "", mac, mac + "/bw-wrapper-501"},
		{"", "", mac + "/a/much/longer/temporary/directory/than/anyone/would/expect", "/tmp/bw-wrapper-501"},
		{"", "/an/unusually/long/runtime/directory/" + strings.Repeat("x", 80), "/tmp", "/tmp/bw-wrapper-501"},
	} {
		got := runtimeBase(c.explicit, c.xdg, c.tmp, 501)
		if got != c.want {
			t.Errorf("runtimeBase(%q, %q, %q) = %q, want %q", c.explicit, c.xdg, c.tmp, got, c.want)
		}
		if c.explicit == "" && !sockFits(got) {
			t.Errorf("%q does not fit a socket address", got)
		}
	}
	// The limit that matters is the smallest supported one (macOS: 104).
	root, session := "/home/x/.config/Bitwarden CLI", "c2Vzc2lvbg=="
	if n := len(socketPath(mac+"/bw-wrapper-501", root, session)); n >= 104 {
		t.Errorf("socket address in a typical macOS temporary directory is %d bytes", n)
	}
	if got := len(filepath.Base(socketPath("/d", root, session))); got != sockNameLen {
		t.Errorf("socket name is %d bytes, sockNameLen says %d", got, sockNameLen)
	}
	// A directory the user chose that cannot hold a socket is an error, not
	// a daemon that never binds.
	t.Setenv("BWW_RUNTIME_DIR", "/tmp/"+strings.Repeat("d", 120))
	if dir, err := runtimeDir(); err == nil {
		t.Errorf("runtimeDir accepted %q", dir)
	}
	if _, err := os.Stat("/tmp/" + strings.Repeat("d", 120)); err == nil {
		t.Error("the unusable directory was created")
	}
}

func TestEmitReportsWriteErrors(t *testing.T) {
	if err := emitTo(io.Discard, io.Discard, false, true, []byte("out"), []byte("err")); err != nil {
		t.Errorf("working writers: %v", err)
	}
	if err := emitTo(failingWriter{}, io.Discard, false, false, []byte("out"), nil); err == nil {
		t.Error("a failing stdout was not reported")
	}
	if err := emitTo(io.Discard, failingWriter{}, false, false, nil, []byte("err")); err == nil {
		t.Error("a failing stderr was not reported")
	}
	if err := emitTo(shortWriter{}, io.Discard, false, false, []byte("out"), nil); err == nil {
		t.Error("a short write was not reported")
	}
	if err := emitTo(failingWriter{}, failingWriter{}, false, false, nil, nil); err != nil {
		t.Errorf("nothing to write: %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, errors.New("no space left on device") }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }
