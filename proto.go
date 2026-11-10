package main

// Wire protocol between client and daemon, over a unix socket in a 0700
// directory. One request per connection:
//
//	client -> daemon: one JSON line (request)
//	daemon -> client: one JSON line (reply), then Out bytes of stdout and
//	                  Err bytes of stderr (each absent when its length is -1)

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	opRun        = "run"        // answer a get/list/status command
	opReload     = "reload"     // re-read the vault through the real CLI
	opInvalidate = "invalidate" // vault changed on disk: reload before the next answer
	opLock       = "lock"       // wipe memory and exit
	opInfo       = "info"       // non-secret daemon facts
)

type request struct {
	Op      string            `json:"op"`
	Session string            `json:"session,omitempty"`
	Cmd     string            `json:"cmd,omitempty"`
	Pos     []string          `json:"pos,omitempty"`
	Opts    map[string]string `json:"opts,omitempty"`
	Flags   outFlags          `json:"flags"`
	// Settings of the caller; the daemon adopts them, so a changed
	// configuration takes effect on the next command. Times are in seconds.
	// AutoLock = -1 means "no settings sent": the daemon keeps all of its own.
	AutoLock       int64  `json:"autoLock"`
	AutoLockAction string `json:"autoLockAction,omitempty"`
	Hold           bool   `json:"hold,omitempty"`
	HoldMax        int64  `json:"holdMax,omitempty"` // 0 = no limit
}

const (
	stOK       = "ok"
	stFallback = "fallback" // run the real CLI instead
	stDenied   = "denied"   // wrong session token
	stStopping = "stopping" // asked to stop, but real-CLI processes of the daemon are still there
)

type reply struct {
	Status string      `json:"status"`
	Exit   int         `json:"exit"`
	Out    int         `json:"out"`
	Err    int         `json:"err"`
	Info   *daemonInfo `json:"info,omitempty"`
}

type daemonInfo struct {
	PID        int    `json:"pid"`
	Stopping   bool   `json:"stopping,omitempty"` // shutdown begun and not complete
	Root       string `json:"root"`
	Started    int64  `json:"started"`
	LastUsed   int64  `json:"lastUsed"`
	Loaded     bool   `json:"loaded"`
	Items      int    `json:"items"`
	AutoLock   int64  `json:"autoLock"` // seconds, 0 = never
	LockAction string `json:"lockAction"`
	Email      string `json:"email,omitempty"`
	Held       int64  `json:"held,omitempty"` // unix time since which the vault is held; 0 = not holding
	HoldMax    int64  `json:"holdMax,omitempty"`
}

// roundTrip sends one request and reads the reply and its payloads.
func roundTrip(sock string, req *request, timeout time.Duration) (*reply, []byte, []byte, error) {
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, nil, nil, err
	}
	defer conn.Close()
	return exchange(conn, req, timeout)
}

func exchange(conn net.Conn, req *request, timeout time.Duration) (*reply, []byte, []byte, error) {
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	line, err := json.Marshal(req)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, nil, nil, err
	}
	br := bufio.NewReaderSize(conn, 64<<10)
	head, err := br.ReadBytes('\n')
	if err != nil {
		return nil, nil, nil, err
	}
	var rep reply
	if err := json.Unmarshal(head, &rep); err != nil {
		return nil, nil, nil, err
	}
	read := func(n int) ([]byte, error) {
		if n < 0 {
			return nil, nil
		}
		if n > 1<<30 {
			return nil, fmt.Errorf("oversized payload")
		}
		b := make([]byte, n)
		_, err := io.ReadFull(br, b)
		return b, err
	}
	out, err := read(rep.Out)
	if err != nil {
		return nil, nil, nil, err
	}
	errOut, err := read(rep.Err)
	if err != nil {
		return nil, nil, nil, err
	}
	return &rep, out, errOut, nil
}
