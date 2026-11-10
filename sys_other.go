//go:build !linux

package main

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func hardenProcess() {
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
}

func lockPage(b []byte) {}

// The socket directory is mode 0700, which already limits peers to the owner.
func peerUID(c *net.UnixConn) (int, bool) { return os.Getuid(), true }

func isTTY(fd uintptr) bool {
	var t syscall.Termios
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGETA, uintptr(unsafe.Pointer(&t)))
	return e == 0
}

// Children inherit the root's data lock instead (daemon.dataRun), so a child
// that outlives a killed daemon still keeps other runs out.
var childAttr = func() *syscall.SysProcAttr { return nil }

// serveSupervised: without a parent-death signal a `bw serve` child could
// outlive a killed daemon, so the serve-based loader is not used here.
const serveSupervised = false

// Without /proc there is no start time to tell a recycled pid apart and no
// way to find the holders of a lock file.
func procStart(pid int) uint64 { return 0 }

func lockHolders(path string) []int { return nil }

// sockAddrMax is the size of a unix socket address on this system; a path
// must be shorter.
const sockAddrMax = 104

// leaseIdentity / leaseHeldBy (see sys_linux.go). Without /proc the check
// is made when it is needed, with ps: the process must exist and must have
// started no later than its registration. A process that got the same pid
// afterwards started later, and is left alone.
func leaseIdentity(pid int) string { return "" }

func leaseHeldBy(pid int, identity string, registered time.Time) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	ps := exec.Command("ps", "-o", "lstart=", "-p", strconv.Itoa(pid))
	ps.Env = append(os.Environ(), "LC_ALL=C")
	out, err := ps.Output()
	if err != nil {
		return false // no such process
	}
	started, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.Join(strings.Fields(string(out)), " "), time.Local)
	if err != nil {
		return true // registered and alive; the start time could not be read
	}
	return !started.After(registered.Add(time.Second)) // ps gives whole seconds
}
