VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX  ?= $(HOME)/.local
BINDIR  ?= $(PREFIX)/bin

bw-wrapper: *.go go.mod go.sum
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $@ .

.PHONY: test install uninstall clean
test:
	go vet ./...
	go test ./...
	python3 test/test_safety.py

# Installs the binary and a `bw` symlink to it. BINDIR must come before the
# real CLI on PATH.
#
# Nothing is changed before the destination has been checked: `bw` in BINDIR
# may be absent or this wrapper's own link. Anything else (the real CLI, a
# launcher script, a link to something else) is left alone and the
# installation is refused, because replacing it could remove the only
# Bitwarden CLI on PATH.
install: bw-wrapper
	@if [ -e "$(BINDIR)/bw" ] || [ -L "$(BINDIR)/bw" ]; then \
		if [ ! -L "$(BINDIR)/bw" ] || [ "$$(readlink "$(BINDIR)/bw")" != bw-wrapper ]; then \
			echo "refusing to install: $(BINDIR)/bw exists and is not bw-wrapper's own link." >&2; \
			echo "Move it away (the wrapper needs the real CLI elsewhere on PATH, or real_bw in its config), or choose another BINDIR." >&2; \
			exit 1; \
		fi; \
	fi
	# Daemons of the installed version are stopped first: they would keep
	# running by the old version's rules. If one cannot be stopped, the
	# installation stops here.
	[ ! -x "$(BINDIR)/bw-wrapper" ] || "$(BINDIR)/bw-wrapper" stop
	mkdir -p "$(BINDIR)"
	install -m755 bw-wrapper "$(BINDIR)/bw-wrapper"
	ln -sfn bw-wrapper "$(BINDIR)/bw"

# The same rule as for install: daemons are stopped first, by the installed
# binary, and if one cannot be stopped nothing is removed. Otherwise a daemon
# would keep a vault in memory (and lock it later) with the command to manage
# it gone.
uninstall:
	[ ! -x "$(BINDIR)/bw-wrapper" ] || "$(BINDIR)/bw-wrapper" stop
	rm -f "$(BINDIR)/bw-wrapper"
	[ "$$(readlink "$(BINDIR)/bw")" != bw-wrapper ] || rm -f "$(BINDIR)/bw"

clean:
	rm -f bw-wrapper
