package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultAutoLock = 15 * time.Minute
	defaultHoldMax  = 12 * time.Hour
)

type config struct {
	AutoLock       time.Duration // 0 = never
	AutoLockAction string        // "lock" or "evict"
	RealBW         string
	AllowWrites    bool
	Preload        bool
	LoadViaServe   bool
	PassEnv        []string      // extra environment variables the daemon may keep
	Hold           bool          // keep read access when the server ends the session
	HoldMax        time.Duration // 0 = no limit
	Debug          bool
}

func configPath() string {
	if p := os.Getenv("BWW_CONFIG"); p != "" {
		return p
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(base, "bw-wrapper", "config")
}

func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off", "":
		return false, true
	}
	return false, false
}

// parseTimeout accepts a Go duration ("15m", "1h30m"), a bare number of
// seconds, or 0/never/off to disable. Timeouts are handled in whole seconds,
// so a positive value below one second is an error rather than a silent
// "never".
func parseTimeout(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "0", "never", "off", "none", "false":
		return 0, nil
	}
	var d time.Duration
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 || n > int64(math.MaxInt64/time.Second) {
			return 0, fmt.Errorf("duration %q is out of range", s)
		}
		d = time.Duration(n) * time.Second
	} else if d, err = time.ParseDuration(s); err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	if d > 0 && d < time.Second {
		return 0, fmt.Errorf("duration %q is below one second (use 0 to disable)", s)
	}
	return d.Truncate(time.Second), nil
}

func (c *config) apply(key, val, src string) {
	warn := func(err any) { fmt.Fprintf(os.Stderr, "bw-wrapper: %s: %s: %v\n", src, key, err) }
	switch key {
	case "auto_lock", "hold_max":
		d, err := parseTimeout(val)
		if err != nil {
			warn(err)
			return
		}
		if key == "hold_max" {
			c.HoldMax = d
		} else {
			c.AutoLock = d
		}
	case "auto_lock_action":
		v := strings.ToLower(val)
		if v != "lock" && v != "evict" {
			warn("must be lock or evict")
			return
		}
		c.AutoLockAction = v
	case "real_bw":
		c.RealBW = val
	case "pass_env":
		c.PassEnv = strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == ' ' })
	case "allow_writes", "preload", "debug", "load_via_serve", "hold":
		b, ok := parseBool(val)
		if !ok {
			warn("must be true or false")
			return
		}
		switch key {
		case "allow_writes":
			c.AllowWrites = b
		case "preload":
			c.Preload = b
		case "load_via_serve":
			c.LoadViaServe = b
		case "hold":
			c.Hold = b
		case "debug":
			c.Debug = b
		}
	default:
		warn("unknown setting")
	}
}

func loadConfig() *config {
	c := &config{AutoLock: defaultAutoLock, AutoLockAction: "lock", Preload: true, LoadViaServe: true, HoldMax: defaultHoldMax}
	if f, err := os.Open(configPath()); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				v = v[1 : len(v)-1]
			}
			c.apply(strings.TrimSpace(k), v, configPath())
		}
		f.Close()
	}
	for env, key := range map[string]string{
		"BWW_AUTO_LOCK": "auto_lock", "BWW_AUTO_LOCK_ACTION": "auto_lock_action",
		"BWW_REAL_BW": "real_bw", "BWW_ALLOW_WRITES": "allow_writes",
		"BWW_PRELOAD": "preload", "BWW_DEBUG": "debug", "BWW_LOAD_VIA_SERVE": "load_via_serve", "BWW_PASS_ENV": "pass_env", "BWW_HOLD": "hold", "BWW_HOLD_MAX": "hold_max",
	} {
		if v, ok := os.LookupEnv(env); ok {
			c.apply(key, v, env)
		}
	}
	return c
}

// findRealBW locates the real Bitwarden CLI: the configured one, or the
// first `bw` on PATH that is not this wrapper. The result is an absolute
// path (a daemon runs it from another working directory), and never the
// wrapper itself (that would be an endless loop).
func findRealBW(c *config) (string, error) {
	self, _ := os.Executable()
	selfInfo, _ := os.Stat(self)
	isSelf := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && selfInfo != nil && os.SameFile(fi, selfInfo)
	}
	usable := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
	}
	name := "bw"
	if c.RealBW != "" {
		if strings.ContainsRune(c.RealBW, filepath.Separator) {
			abs, err := filepath.Abs(c.RealBW)
			if err != nil {
				return "", err
			}
			if !usable(abs) {
				return "", fmt.Errorf("real_bw %s is not an executable file", abs)
			}
			if isSelf(abs) {
				return "", fmt.Errorf("real_bw %s is bw-wrapper itself, not the Bitwarden CLI", abs)
			}
			return abs, nil
		}
		name = c.RealBW // a bare name: looked up on PATH
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		p, err := filepath.Abs(filepath.Join(dir, name))
		if err != nil || !usable(p) || isSelf(p) {
			continue
		}
		return p, nil
	}
	return "", fmt.Errorf("real Bitwarden CLI (%s) not found on PATH (set real_bw in %s or BWW_REAL_BW)", name, configPath())
}

// appDataDir reproduces how the real CLI picks its data directory ("root").
func appDataDir(realBW string) string {
	// A `bw-data` directory next to the CLI's executable wins over everything.
	exe := realBW
	if r, err := filepath.EvalSymlinks(realBW); err == nil {
		exe = r
	}
	if f, err := os.Open(exe); err == nil {
		var magic [2]byte
		f.Read(magic[:])
		f.Close()
		if string(magic[:]) == "#!" { // npm install: process.execPath is node
			if n, err := exec.LookPath("node"); err == nil {
				if r, err := filepath.EvalSymlinks(n); err == nil {
					n = r
				}
				exe = n
			}
		}
	}
	if p := filepath.Join(filepath.Dir(exe), "bw-data"); dirExists(p) {
		return canonicalPath(p)
	}
	if d := os.Getenv("BITWARDENCLI_APPDATA_DIR"); d != "" {
		return canonicalPath(d)
	}
	home := os.Getenv("HOME")
	if runtime.GOOS == "darwin" {
		return canonicalPath(filepath.Join(home, "Library/Application Support/Bitwarden CLI"))
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return canonicalPath(filepath.Join(x, "Bitwarden CLI"))
	}
	return canonicalPath(filepath.Join(home, ".config/Bitwarden CLI"))
}

// canonicalPath makes a root's identity independent of how it was spelled:
// absolute, cleaned, and with symlinks resolved. A daemon started through
// an alias of a directory is then found (and locked) through any other
// spelling of it. Parts that do not exist yet are kept as given.
func canonicalPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	rest := ""
	for cur := p; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// runtimeDir is the private directory holding daemon sockets.
func runtimeDir() (string, error) {
	base := runtimeBase(os.Getenv("BWW_RUNTIME_DIR"), os.Getenv("XDG_RUNTIME_DIR"), os.TempDir(), os.Getuid())
	if abs, err := filepath.Abs(base); err == nil {
		base = abs
	}
	// The whole socket address must fit the system's limit (104 bytes on
	// macOS, 108 on Linux). Checked here, before any daemon is started: a
	// daemon that cannot bind would make every command wait for it in vain.
	if !sockFits(base) {
		return "", fmt.Errorf("runtime directory %s is too long for a socket address (limit %d bytes); set BWW_RUNTIME_DIR to a shorter path", base, sockAddrMax)
	}
	return privateDir(base)
}

// sockNameLen is the length of a socket file name (see socketPath).
const sockNameLen = len("01234567-0123456789abcdef.sock")

func sockFits(dir string) bool { return len(dir)+1+sockNameLen < sockAddrMax }

// runtimeBase chooses the directory for daemon sockets: what the user set;
// else the session's runtime directory; else a per-user directory under the
// temporary directory, or, where that path is too long for a socket address
// (macOS: /var/folders/…/T/), under /tmp. The directory is made private and
// checked for ownership in every case (privateDir). Coordination does not
// depend on it: that lives in the vault root.
func runtimeBase(explicit, xdg, tmp string, uid int) string {
	if explicit != "" {
		return explicit
	}
	if xdg != "" {
		if dir := filepath.Join(xdg, "bw-wrapper"); sockFits(dir) {
			return dir
		}
	}
	name := "bw-wrapper-" + strconv.Itoa(uid)
	if dir := filepath.Join(tmp, name); sockFits(dir) {
		return dir
	}
	return filepath.Join("/tmp", name)
}

func privateDir(dir string) (string, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return "", fmt.Errorf("runtime directory %q is not an absolute path", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 || (ok && int(st.Uid) != os.Getuid()) {
		return "", fmt.Errorf("%s must be a directory owned by you with mode 0700", dir)
	}
	return dir, nil
}

func hashHex(n int, parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:n])
}

func rootTag(root string) string { return hashHex(8, "bww-root", root) }

// sockPrefix starts the socket file names of a root's daemons. Names are
// kept short: the whole address has a small system limit.
func sockPrefix(root string) string { return rootTag(root)[:8] + "-" }

// socketPath routes a (root, session token) pair to its daemon.
func socketPath(dir, root, session string) string {
	return filepath.Join(dir, sockPrefix(root)+hashHex(8, "bww-sock", session)+".sock")
}

// authHash is what a daemon keeps instead of the session token itself.
func authHash(session string) [32]byte {
	return sha256.Sum256([]byte("bww-auth\x00" + session))
}
