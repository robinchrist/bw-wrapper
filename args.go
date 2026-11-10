package main

// The one place where a `bw` command line is interpreted.
//
// Every decision the wrapper makes about a command line (is it only help,
// may it change the vault, does it use an existing session, which variable
// holds a password, can it be answered from memory) is read from the
// invocation built here. Nothing else looks at raw arguments.
//
// The parser is a port of how the Bitwarden CLI itself reads its arguments
// (commander 14: Command.parseOptions and Command._parseCommand), driven by a
// table of the CLI's commands and options (taken from bw 2026.10.1). Where a
// command line contains something the table does not explain, the result is
// marked inexact, and inexact always means the cautious reading: not help,
// possibly a write, in need of an open session state.

import (
	"os"
	"regexp"
	"strings"
)

// outFlags are the global output switches of the real CLI. They come from
// command-line options or from the BW_* environment variables.
type outFlags struct {
	Pretty    bool `json:"pretty,omitempty"`
	Raw       bool `json:"raw,omitempty"`
	Response  bool `json:"response,omitempty"`
	Quiet     bool `json:"quiet,omitempty"`
	CleanExit bool `json:"cleanexit,omitempty"`
	Color     bool `json:"color,omitempty"`
}

func envFlags() outFlags {
	return outFlags{
		Pretty:    os.Getenv("BW_PRETTY") == "true",
		Raw:       os.Getenv("BW_RAW") == "true",
		Response:  os.Getenv("BW_RESPONSE") == "true",
		Quiet:     os.Getenv("BW_QUIET") == "true",
		CleanExit: os.Getenv("BW_CLEANEXIT") != "",
	}
}

// ---------- the CLI's command table ----------

type optKind uint8

const (
	optFlag     optKind = iota + 1 // --trash
	optValue                       // --search <value>: takes the next argument, whatever it looks like
	optOptional                    // --sso [value]: takes the next argument unless it looks like an option
)

type optSpec struct {
	name string // long name without dashes
	kind optKind
}

type cmdNode struct {
	name string
	opts map[string]optSpec // by flag as typed: "--search", "-f"
	subs map[string]*cmdNode
	// action: the command does something itself when no subcommand is named
	// (`bw send <data>`). Only a command with subcommands and no action of
	// its own has commander's implicit `help` subcommand: `bw send help`
	// creates a Send with the text "help".
	action bool
}

// node declares a command. opts is a space-separated list in the notation
// "--flag", "--name=" (value), "--name?" (optional value), "-s|--long".
func node(name, opts string, subs ...*cmdNode) *cmdNode {
	n := &cmdNode{name: name, opts: map[string]optSpec{}}
	for _, decl := range strings.Fields(opts) {
		kind := optFlag
		switch {
		case strings.HasSuffix(decl, "="):
			kind, decl = optValue, strings.TrimSuffix(decl, "=")
		case strings.HasSuffix(decl, "?"):
			kind, decl = optOptional, strings.TrimSuffix(decl, "?")
		}
		flags := strings.Split(decl, "|")
		spec := optSpec{name: strings.TrimLeft(flags[len(flags)-1], "-"), kind: kind}
		for _, f := range flags {
			n.opts[f] = spec
		}
	}
	if len(subs) > 0 {
		n.subs = map[string]*cmdNode{}
		for _, s := range subs {
			n.subs[s.name] = s
		}
	}
	return n
}

func withAction(n *cmdNode) *cmdNode { n.action = true; return n }

var receiveNode = node("receive", "--password= --passwordenv= --passwordfile= --obj --output=")

var orgOpt = "--organizationid="

// program mirrors the commands and options of bw 2026.10.1.
var program = node("bw", "--pretty --raw --response --cleanexit --quiet --nointeraction --session= -v|--version",
	node("sdk-version", ""),
	node("login", "--method= --code= --sso? --apikey --passwordenv= --passwordfile= --check"),
	node("logout", ""),
	node("lock", ""),
	node("unlock", "--check --passwordenv= --passwordfile="),
	node("sync", "-f|--force --last"),
	node("generate", "-u|--uppercase -l|--lowercase -n|--number -s|--special -p|--passphrase --length= --words= "+
		"--minNumber= --minSpecial= --separator= -c|--capitalize --includeNumber --ambiguous"),
	node("encode", ""),
	node("config", "--web-vault= --api= --identity= --icons= --notifications= --events= --key-connector="),
	node("update", ""),
	node("completion", "--shell="),
	node("status", ""),
	withAction(node("send", "-f|--file -d|--deleteInDays= --password= --emails= -a|--maxAccessCount= --hidden -n|--name= --notes= --fullObject",
		node("list", ""), node("template", ""), node("get", "--output= --text"), receiveNode,
		node("create", "--file= --text= --hidden"), node("edit", "--itemid="),
		node("remove-password", ""), node("delete", ""))),
	receiveNode,
	node("list", "--search= --url= --folderid= --collectionid= --organizationid= --trash --archived"),
	node("get", "--itemid= --output= --organizationid="),
	node("create", "--file= --itemid= --organizationid="),
	node("edit", orgOpt),
	node("delete", "--itemid= --organizationid= -p|--permanent"),
	node("restore", ""), node("archive", ""), node("move", ""), node("share", ""),
	node("confirm", orgOpt),
	node("import", "--formats --organizationid= --keyfile= --passwordenv= --passwordfile="),
	node("export", "--output= --format= --password? --organizationid="),
	node("serve", "--hostname= --port= --disable-origin-protection"),
	node("device-approval", "",
		node("list", orgOpt), node("approve", orgOpt), node("approve-all", orgOpt),
		node("deny", orgOpt), node("deny-all", orgOpt)),
	node("report", "--no-check-exposed"),
)

// ---------- parsing ----------

func maybeOption(arg string) bool { return len(arg) > 1 && arg[0] == '-' }

var negativeNumberRE = regexp.MustCompile(`^-\d*\.?\d+(e[+-]?\d+)?$`)

func isHelpFlag(arg string) bool { return arg == "-h" || arg == "--help" }

// parseOptions is commander's Command.parseOptions for one command level:
// it takes the options this level knows out of argv and sorts the rest into
// operands and "unknown" (the first option it does not know and everything
// after it, for a subcommand to look at). hit is called for every option
// found; val is nil when the option carries no value. ok=false: an option
// that needs a value is the last argument (commander exits with an error).
func (n *cmdNode) parseOptions(argv []string, hit func(o optSpec, val *string)) (operands, unknown []string, ok bool) {
	args := append([]string(nil), argv...)
	toUnknown := false
	push := func(a ...string) {
		if toUnknown {
			unknown = append(unknown, a...)
		} else {
			operands = append(operands, a...)
		}
	}
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			if toUnknown {
				push(arg)
			}
			push(args...)
			break
		}
		if maybeOption(arg) {
			if o, found := n.opts[arg]; found {
				switch o.kind {
				case optValue:
					if len(args) == 0 {
						return operands, unknown, false
					}
					val := args[0]
					args = args[1:]
					hit(o, &val)
				case optOptional:
					if len(args) > 0 && (!maybeOption(args[0]) || negativeNumberRE.MatchString(args[0])) {
						val := args[0]
						args = args[1:]
						hit(o, &val)
					} else {
						hit(o, nil)
					}
				default:
					hit(o, nil)
				}
				continue
			}
		}
		// Combined short options: -fx, or -dVALUE.
		if len(arg) > 2 && arg[0] == '-' && arg[1] != '-' {
			if o, found := n.opts[arg[:2]]; found {
				if o.kind == optFlag {
					hit(o, nil)
					args = append([]string{"-" + arg[2:]}, args...)
				} else {
					val := arg[2:]
					hit(o, &val)
				}
				continue
			}
		}
		// --name=value
		if strings.HasPrefix(arg, "--") {
			if eq := strings.IndexByte(arg, '='); eq > 2 {
				if o, found := n.opts[arg[:eq]]; found && o.kind != optFlag {
					val := arg[eq+1:]
					hit(o, &val)
					continue
				}
			}
		}
		// Not an option of this level. An unknown option sends everything
		// from here on to "unknown"; a negative number in a command without
		// subcommands is an operand.
		if !toUnknown && maybeOption(arg) && !(n.subs == nil && negativeNumberRE.MatchString(arg)) {
			toUnknown = true
		}
		push(arg)
	}
	return operands, unknown, true
}

// invocation is a parsed `bw` command line.
type invocation struct {
	args []string
	// cmd is the command the CLI will dispatch to ("" if there is none, or
	// if it cannot be told for certain); path is cmd and its subcommands.
	cmd  string
	path []string
	// exact: every argument was accounted for by the command table, so the
	// CLI will read the line the way this struct says. When false, only the
	// cautious reading is safe (see class).
	exact bool
	// info: the line only prints help or the version and runs no command.
	// Only ever set together with certainty about it.
	info bool
	// leafHelp: the certain "info" is the help of the command in path.
	session string
	// sessionOpt: the session key is (also) on the command line (--session),
	// so it cannot be withheld from the real CLI by cleaning its environment.
	sessionOpt bool
	flags      outFlags
	pos        []string            // operands of the last command in path
	opts       map[string][]string // its options, in the order given; a flag has the value ""
}

// has reports whether an option was given (as an option, not as the value
// of another one).
func (inv *invocation) has(name string) bool { return len(inv.opts[name]) > 0 }

// last returns the value the CLI uses for an option given more than once.
func (inv *invocation) last(name string) (string, bool) {
	v := inv.opts[name]
	if len(v) == 0 {
		return "", false
	}
	return v[len(v)-1], true
}

// parseArgs reads a bw command line the way the CLI does. It never fails:
// what the table does not explain leaves exact=false.
func parseArgs(args []string) *invocation {
	inv := &invocation{args: args, flags: envFlags(), session: os.Getenv("BW_SESSION"), opts: map[string][]string{}}
	version := false
	operands, unknown, ok := program.parseOptions(args, func(o optSpec, val *string) {
		switch o.name {
		case "pretty":
			inv.flags.Pretty = true
		case "raw":
			inv.flags.Raw = true
		case "response":
			inv.flags.Response = true
		case "quiet":
			inv.flags.Quiet = true
		case "cleanexit":
			inv.flags.CleanExit = true
		case "session":
			inv.session, inv.sessionOpt = *val, true
		case "version":
			version = true
		}
	})
	if version {
		// The version option acts the moment it is read, wherever it stands.
		inv.info, inv.exact = true, true
		return inv
	}
	if !ok {
		return inv
	}
	n := program
	for {
		if len(operands) == 0 {
			break
		}
		sub := n.subs[operands[0]]
		if sub == nil {
			break
		}
		inv.path = append(inv.path, sub.name)
		n = sub
		var more []string
		more, unknown, ok = n.parseOptions(unknown, func(o optSpec, val *string) {
			v := ""
			if val != nil {
				v = *val
			}
			inv.opts[o.name] = append(inv.opts[o.name], v)
		})
		operands = append(operands[1:], more...)
		if !ok {
			inv.cmd = inv.path[0]
			return inv
		}
	}
	if len(inv.path) > 0 {
		inv.cmd = inv.path[0]
	}
	inv.pos = operands
	switch {
	case n.subs != nil && !n.action && len(operands) > 0 && operands[0] == "help":
		// `bw help [command]`, `bw device-approval help`
		inv.info, inv.exact = true, true
	case len(unknown) > 0 && isHelpFlag(unknown[0]):
		// The first thing this command does not know is the help flag, and
		// everything before it was understood: the CLI prints help.
		inv.info, inv.exact = true, true
	case len(unknown) > 0:
		// An option the table does not know. Today's CLI rejects the line (or
		// prints help, if a help flag follows); a CLI with more options than
		// the table might run it.
	case n.subs != nil && !n.action && len(operands) == 0:
		// A command group without a subcommand (`bw`, `bw device-approval`):
		// the CLI prints its help.
		inv.info, inv.exact = true, true
	case n.subs != nil && !n.action:
		// Not a subcommand the table knows.
	default:
		inv.exact = true
	}
	return inv
}

// ---------- what a command line means for the wrapper ----------

type cmdClass int

const (
	classInfo    cmdClass = iota // prints help or the version; runs no command
	classLocal                   // needs no vault and no session: generate, encode, config, ...
	classStatus                  // `bw status`: reveals nothing from the vault
	classSession                 // lock, logout, login, unlock: changes the session
	classRead                    // works with an existing session, cannot change the vault
	classWrite                   // can change the vault, or cannot be told apart from something that can
)

func (c cmdClass) String() string {
	return [...]string{"info", "local", "status", "session", "read", "write"}[c]
}

var localCmds = map[string]bool{
	"generate": true, "encode": true, "config": true, "update": true, "completion": true, "sdk-version": true,
}

var readCmds = map[string]bool{"get": true, "list": true, "sync": true, "export": true, "receive": true, "report": true}

var sendReadSubs = map[string]bool{"list": true, "get": true, "template": true, "receive": true}

// class is the single classification every routing decision uses. Unknown
// commands and lines that were not understood exactly count as writes: a
// read-only wrapper must not let through what it cannot classify, and
// classWrite is also subject to every check a read is.
func (inv *invocation) class() cmdClass {
	if inv.info {
		return classInfo
	}
	switch {
	case inv.cmd == "":
		return classWrite
	case inv.cmd == "status":
		return classStatus
	case inv.cmd == "lock" || inv.cmd == "logout":
		return classSession
	case inv.cmd == "login" || inv.cmd == "unlock":
		if inv.exact && inv.has("check") {
			return classLocal // only reports the login or lock state
		}
		return classSession
	case localCmds[inv.cmd]:
		return classLocal
	case readCmds[inv.cmd]:
		return classRead
	case inv.cmd == "send":
		if inv.exact && len(inv.path) == 2 && sendReadSubs[inv.path[1]] {
			return classRead
		}
	case inv.cmd == "device-approval":
		if inv.exact && len(inv.path) == 2 && inv.path[1] == "list" {
			return classRead
		}
	}
	return classWrite
}

// passwordEnvs lists every environment variable the command line names as
// holding a password. With an exact parse these are the --passwordenv values
// the CLI sees; otherwise every argument that could be one is included.
func (inv *invocation) passwordEnvs() []string {
	var names []string
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, name := range inv.opts["passwordenv"] {
		add(name)
	}
	if !inv.exact {
		for i, a := range inv.args {
			if a == "--passwordenv" && i+1 < len(inv.args) {
				add(inv.args[i+1])
			}
			if v, ok := strings.CutPrefix(a, "--passwordenv="); ok {
				add(v)
			}
		}
	}
	return names
}

// cached reports whether the line is one the daemon can answer, and returns
// its options in the form the daemon takes them.
func (inv *invocation) cached() (opts map[string]string, ok bool) {
	if !inv.exact || len(inv.path) != 1 {
		return nil, false
	}
	npos := map[string]int{"list": 1, "get": 2, "status": 0}
	want, known := npos[inv.cmd]
	if !known || len(inv.pos) != want {
		return nil, false
	}
	opts = map[string]string{}
	for name := range inv.opts {
		v, _ := inv.last(name)
		if program.subs[inv.cmd].opts["--"+name].kind == optFlag {
			v = "true"
		}
		opts[name] = v
	}
	return opts, true
}
