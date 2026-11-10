// bw-wrapper is a read-only, drop-in front end for the Bitwarden CLI (`bw`)
// that answers vault queries from a per-session in-memory daemon.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var version = "dev"

const usage = `bw-wrapper %s - fast read-only front end for the Bitwarden CLI

Install it as "bw" in front of the real CLI on PATH (see README), then use bw
as usual. Invoked under its own name it manages the daemons:

  bw-wrapper status        list running daemons (no secrets shown)
  bw-wrapper stop          wipe and stop all daemons (sessions stay valid)
  bw-wrapper config        show the effective configuration
  bw-wrapper bw <args...>  run a bw command through the wrapper
  bw-wrapper version
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__daemon" && os.Getenv("BWW_DAEMON") == "1" {
		os.Exit(runDaemon())
	}
	name := filepath.Base(os.Args[0])
	if !strings.HasPrefix(name, "bw-wrapper") {
		os.Exit(runBW(os.Args[1:]))
	}
	os.Exit(admin(os.Args[1:]))
}

func admin(args []string) int {
	if len(args) == 0 {
		fmt.Printf(usage, version)
		return 0
	}
	switch args[0] {
	case "bw":
		return runBW(args[1:])
	case "version", "--version", "-v":
		fmt.Println("bw-wrapper", version)
	case "help", "--help", "-h":
		fmt.Printf(usage, version)
	case "classify":
		// How the wrapper reads a bw command line (used by test/parsetest.py
		// to compare with the real CLI). Prints the class and exactness only.
		inv := parseArgs(args[1:])
		fmt.Printf("%s exact=%v\n", inv.class(), inv.exact)
		return 0
	case "config":
		c := loadConfig()
		real, err := findRealBW(c)
		if err != nil {
			real = "(" + err.Error() + ")"
		}
		lock := "never"
		if c.AutoLock > 0 {
			lock = c.AutoLock.String()
		}
		holdMax := "no limit"
		if c.HoldMax > 0 {
			holdMax = c.HoldMax.String()
		}
		fmt.Printf("config file       %s\nreal_bw           %s\nauto_lock         %s\nauto_lock_action  %s\nallow_writes      %v\npreload           %v\nload_via_serve    %v\nhold              %v\nhold_max          %s\n",
			configPath(), real, lock, c.AutoLockAction, c.AllowWrites, c.Preload, c.LoadViaServe, c.Hold, holdMax)
		if err == nil {
			fmt.Printf("current root      %s\n", appDataDir(real))
		}
	case "status":
		n := 0
		for _, s := range adminSockets() {
			rep, _, _, err := roundTrip(s, &request{Op: opInfo, AutoLock: -1}, 5*time.Second)
			if err != nil || rep.Info == nil {
				continue
			}
			in := rep.Info
			n++
			state := "loading"
			if in.Loaded {
				state = fmt.Sprintf("%d items", in.Items)
			}
			if in.Stopping {
				state = "STOPPING (waiting for its Bitwarden CLI processes to exit)"
			}
			lock := "never"
			if in.AutoLock > 0 {
				left := time.Duration(in.LastUsed+in.AutoLock-time.Now().Unix()) * time.Second
				lock = fmt.Sprintf("%s in %s", in.LockAction, max(left, 0))
			}
			held := ""
			if in.Held > 0 {
				held = fmt.Sprintf("  HOLDING for %s (the vault in memory cannot be refreshed from the CLI)", time.Since(time.Unix(in.Held, 0)).Round(time.Second))
				if in.HoldMax > 0 {
					held += fmt.Sprintf(", wipes in %s", max(time.Duration(in.Held+in.HoldMax-time.Now().Unix())*time.Second, 0))
				}
			}
			fmt.Printf("pid %-7d %-22s %-12s up %-8s auto-lock: %-16s %s%s\n", in.PID, in.Email, state,
				time.Since(time.Unix(in.Started, 0)).Round(time.Second), lock, in.Root, held)
		}
		if n == 0 {
			fmt.Println("no daemons running")
		}
	case "stop":
		// Success means: every daemon found in the scope below confirmed
		// that its vault is wiped and its real-CLI children are stopped.
		scope, socks := adminScope()
		stopped, failed := 0, 0
		for _, s := range socks {
			ok, gone, err := stopSocket(s)
			switch {
			case ok:
				stopped++
			case gone:
			default:
				failed++
				fmt.Fprintf(os.Stderr, "bw-wrapper: daemon at %s did not confirm (%v); it may still hold a vault\n", s, err)
			}
		}
		fmt.Printf("stopped %d daemon(s)", stopped)
		if failed > 0 {
			fmt.Printf(", %d FAILED", failed)
		}
		fmt.Printf("\nscope: %s\n", scope)
		if failed > 0 {
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "bw-wrapper: unknown command %q\n\n", args[0])
		fmt.Fprintf(os.Stderr, usage, version)
		return 2
	}
	return 0
}

// adminScope lists the daemons the management commands can see, and says
// what that is: those registered for the current root (wherever their
// sockets are) and those with a socket in this shell's runtime directory
// (whatever their root). Daemons of other roots that were started from
// other runtime directories are outside it.
func adminScope() (scope string, socks []string) {
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			socks = append(socks, s)
		}
	}
	var parts []string
	if real, err := findRealBW(loadConfig()); err == nil {
		root := appDataDir(real)
		if co, err := openCoord(root); err == nil {
			for _, s := range co.daemons() {
				add(s)
			}
			parts = append(parts, "daemons of the vault root "+root)
		}
	}
	if dir, err := runtimeDir(); err == nil {
		for _, s := range runtimeSockets(dir) {
			add(s)
		}
		parts = append(parts, "daemons with sockets in "+dir)
	}
	if len(parts) == 0 {
		return "nothing (no vault root and no runtime directory could be used)", nil
	}
	return strings.Join(parts, "; ") + ". Daemons of other roots started from other runtime directories are not covered.", socks
}

func adminSockets() []string {
	_, socks := adminScope()
	return socks
}
