//go:build linux

package main

import (
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// hardenProcess keeps other processes of the same user (and core dumps) away
// from the daemon's memory: a non-dumpable process cannot be ptrace-attached
// or have /proc/<pid>/mem read without CAP_SYS_PTRACE.
func hardenProcess() {
	const prSetDumpable = 4
	syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
}

func lockPage(b []byte) {
	const madvDontDump = 16
	syscall.Madvise(b, madvDontDump)
}

func peerUID(c *net.UnixConn) (int, bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, false
	}
	uid, ok := 0, false
	raw.Control(func(fd uintptr) {
		if cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
			uid, ok = int(cred.Uid), true
		}
	})
	return uid, ok
}

func isTTY(fd uintptr) bool {
	var t syscall.Termios
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return e == 0
}

// childAttr makes the kernel kill a real-CLI child when the daemon thread
// that started it dies, so no `bw serve` outlives a daemon that is killed.
// The starting goroutine must hold its OS thread for the child's lifetime.
var childAttr = func() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// serveSupervised: a `bw serve` child cannot outlive the daemon here.
const serveSupervised = true

// procStart is the start time of a process (clock ticks since boot, field 22
// of /proc/<pid>/stat). Together with the pid it names one process for good:
// a recycled pid has a different start time. 0 if unknown.
func procStart(pid int) uint64 {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	// The command name (field 2) is in parentheses and may contain anything.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return 0
	}
	v, _ := strconv.ParseUint(f[19], 10, 64)
	return v
}

// lockHolders lists the processes of this user that have the file at path
// open, which for a lock file means: everyone who holds or shares the lock,
// including a real CLI that inherited it from a wrapper that is gone.
// Hardened daemons do not show their descriptors and are not listed.
func lockHolders(path string) []int {
	want, err := os.Stat(path)
	if err != nil {
		return nil
	}
	procs, _ := os.ReadDir("/proc")
	var pids []int
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		fds, err := os.ReadDir("/proc/" + p.Name() + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if fi, err := os.Stat("/proc/" + p.Name() + "/fd/" + fd.Name()); err == nil && os.SameFile(want, fi) {
				pids = append(pids, pid)
				break
			}
		}
	}
	return pids
}

// sockAddrMax is the size of a unix socket address on this system; a path
// must be shorter.
const sockAddrMax = 108
