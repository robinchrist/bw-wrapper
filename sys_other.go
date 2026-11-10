//go:build !linux

package main

import (
	"net"
	"os"
	"syscall"
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
