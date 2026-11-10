package main

// Loading through `bw serve`.
//
// A cold load needs eight queries (item lists per state, folders,
// collections, organizations, status). As separate CLI runs each one starts
// Node and decrypts the vault again. One short-lived `bw serve` on a private
// unix socket starts Node once, decrypts once and answers the rest in
// milliseconds. Its responses come from the same command classes as the
// CLI's `--response` output. The process is killed as soon as the load is
// done; if anything about it fails, the daemon falls back to plain CLI runs.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type serveSource struct {
	cmd  *exec.Cmd
	sock string
	done chan struct{}
}

var serveSeq atomic.Int64

// servePort is the port `bw serve` assumes when none is given; it checks the
// Host header against it even when listening on a unix socket.
const servePort = "8087"

func (d *daemon) startServe(session string, inherit []*os.File) (*serveSource, error) {
	s := &serveSource{
		sock: filepath.Join(d.dir, fmt.Sprintf("load-%d-%d.srv", os.Getpid(), serveSeq.Add(1))),
		done: make(chan struct{}),
	}
	os.Remove(s.sock)
	s.cmd = exec.Command(d.realBW, "serve", "--hostname", "unix://"+s.sock)
	s.cmd.Env = d.childEnv(session)
	s.cmd.SysProcAttr = childAttr()
	s.cmd.ExtraFiles = inherit // lease and data lock last as long as the loader does
	if !d.kids.reserve() {
		return nil, errStopping
	}
	if err := s.cmd.Start(); err != nil {
		d.kids.done(nil)
		return nil, err
	}
	testHook("child-started")
	d.kids.started(s.cmd.Process)
	go func() { s.cmd.Wait(); testHook("child-reaped"); d.kids.done(s.cmd.Process); close(s.done) }()

	deadline := time.Now().Add(time.Minute)
	for {
		if c, err := net.Dial("unix", s.sock); err == nil {
			c.Close()
			break
		}
		select {
		case <-s.done:
			s.stop()
			return nil, errors.New("`bw serve` exited before listening")
		case <-time.After(15 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			s.stop()
			return nil, errors.New("`bw serve` did not start listening")
		}
	}
	return s, nil
}

func (s *serveSource) stop() {
	s.cmd.Process.Kill()
	<-s.done
	os.Remove(s.sock)
}

// query answers the argument shapes loadVault uses: `status` and
// `list <object> [--trash] [--archived]`.
func (s *serveSource) query(args ...string) ([]byte, error) {
	var path string
	switch {
	case len(args) == 1 && args[0] == "status":
		path = "/status"
	case len(args) >= 2 && args[0] == "list":
		q := url.Values{}
		for _, a := range args[2:] {
			if !strings.HasPrefix(a, "--") {
				return nil, fmt.Errorf("serve: unsupported argument %q", a)
			}
			q.Set(a[2:], "true")
		}
		path = "/list/object/" + url.PathEscape(args[1])
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
	default:
		return nil, fmt.Errorf("serve: unsupported query %v", args)
	}
	return s.get(path)
}

// get is a minimal HTTP/1.1 GET over the unix socket.
func (s *serveSource) get(path string) ([]byte, error) {
	conn, err := net.Dial("unix", s.sock)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(realTimeout))
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: localhost:%s\r\nAccept: application/json\r\nConnection: close\r\n\r\n", path, servePort); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 64<<10)
	status, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if f := strings.Fields(status); len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/1.") {
		return nil, fmt.Errorf("serve: bad status line %q", strings.TrimSpace(status))
	} else if f[1] == "403" || f[1] == "404" {
		return nil, fmt.Errorf("serve: HTTP %s for %s", f[1], path)
	}
	length, chunked := -1, false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, _ := strings.Cut(line, ":")
		v = strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "content-length":
			if length, err = strconv.Atoi(v); err != nil || length < 0 {
				return nil, errors.New("serve: bad content-length")
			}
		case "transfer-encoding":
			chunked = strings.Contains(strings.ToLower(v), "chunked")
		}
	}
	switch {
	case chunked:
		var body []byte
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				wipe(body)
				return nil, err
			}
			size, _, _ := strings.Cut(strings.TrimSpace(line), ";")
			n, err := strconv.ParseInt(size, 16, 32)
			if err != nil || n < 0 {
				wipe(body)
				return nil, errors.New("serve: bad chunk")
			}
			if n == 0 {
				return body, nil
			}
			grown := make([]byte, len(body)+int(n))
			copy(grown, body)
			wipe(body)
			body = grown
			if _, err := io.ReadFull(br, body[len(body)-int(n):]); err != nil {
				wipe(body)
				return nil, err
			}
			br.Discard(2) // CRLF after the chunk
		}
	case length >= 0:
		body := make([]byte, length)
		if _, err := io.ReadFull(br, body); err != nil {
			wipe(body)
			return nil, err
		}
		return body, nil
	}
	return bytes.TrimSpace(readAllWiping(br)), nil
}

// load fills a vault for the session: through `bw serve` when possible,
// otherwise through separate CLI runs.
func (d *daemon) load(session string) (v *vault, err error) {
	err = d.dataRun(func(inherit []*os.File) error {
		v, err = d.loadWith(session, inherit)
		return err
	})
	return v, err
}

func (d *daemon) loadWith(session string, inherit []*os.File) (*vault, error) {
	// `bw serve` is started with "die with the parent thread" (childAttr):
	// keep this thread ours for as long as it runs.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Only where a `bw serve` child is guaranteed to die with this daemon
	// (childAttr): elsewhere a killed daemon would leave an unlocked server
	// behind, so the finite `bw list` runs are used instead.
	if d.useServe && serveSupervised && !d.closing.Load() {
		src, err := d.startServe(session, inherit)
		if err == nil {
			// status first: it makes serve unlock itself with the session key
			if _, err = src.query("status"); err == nil {
				var v *vault
				v, err = loadVault(src.query, true)
				if err == nil || errors.Is(err, errLocked) {
					src.stop()
					return v, err
				}
			}
			src.stop()
		}
		logf("loading through `bw serve` failed (%v), using plain CLI runs", err)
	}
	return loadVault(d.realWith(session, inherit), false)
}
