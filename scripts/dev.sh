#!/bin/sh
# The inner development loop: build on the VM, deploy to the VPS, drive a browser, read the logs.
#
#   ./scripts/dev.sh test                          # cargo test on the build VM
#   ./scripts/dev.sh build dtls-proxy              # cross compile one binary for the VPS
#   ./scripts/dev.sh deploy dtls-proxy             # build + upload + restart + verify (auto rollback)
#   ./scripts/dev.sh logs dtls-proxy -5min
#   ./scripts/dev.sh e2e tests/vpn.html --units=dtls-proxy,swbrd
#
# `build.sh` is still the full release path (all four daemons + `deno compile`).  This script is for
# turning one crate around quickly: it uses `cargo build -p` against the shared target dir instead of
# `cargo install --path`, which builds in a throwaway directory and so never reuses anything.
set -eu

VM=192.168.64.3            # Debian VM: the only place the daemons compile
VM_DIR=share/src/swbrd     # the same tree as this repo, shared over virtiofs...
MAC_DIR=$HOME/src/swbrd    # ...mounted here on this side
VPS=turn                   # turn.evan-brass.net, reached as user `evan` with passwordless sudo
TARGET=x86_64-unknown-linux-gnu
UNITS='dtls-proxy turnserver ice-dissolve swbrd'
PORT=8000

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
OUT=$ROOT/target/$TARGET/release
SCRATCH=${SWBRD_SCRATCH:-${TMPDIR:-/tmp}}

say() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
ok() { printf '\033[1;32m ok\033[0m %s\n' "$*" >&2; }
bad() { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; }
die() { bad "$*"; exit 1; }

# The whole mount is shared, so a git worktree under .claude/worktrees/<name> is visible on the VM
# at the matching path under $VM_DIR.  Carry that suffix over: without it the VM builds and tests
# the main checkout while you're editing a worktree, and the worktree's changes never run.
case $ROOT in
	"$MAC_DIR") ;;
	"$MAC_DIR"/*) VM_DIR=$VM_DIR${ROOT#"$MAC_DIR"}; say "worktree: $VM_DIR" ;;
	*) die "$ROOT is outside $MAC_DIR — the VM has no view of it" ;;
esac

# Run a command on the build VM, in the shared tree, with the rustup toolchain first on PATH.
# The system /usr/bin/cargo is 1.85 and too old for this workspace.
vm() {
	# shellcheck disable=SC2029  # $* is meant to expand here, not on the VM
	ssh "$VM" "export PATH=\"\$HOME/.cargo/bin:\$HOME/.deno/bin:\$PATH\"; cd $VM_DIR || exit 1; $*"
}

# Run a command on the VPS.
vps() {
	# shellcheck disable=SC2029
	ssh "$VPS" "$*"
}

# Run a command on the VPS as root.  sudo is passwordless there, and -n keeps us from ever
# blocking on a password prompt that has no tty to read from.
vps_root() {
	# shellcheck disable=SC2029
	ssh "$VPS" "sudo -n $*"
}

# `-p a -p b`, or `--workspace` when no crates were named.
pkg_args() {
	if [ $# -eq 0 ]; then
		printf '%s' --workspace
	else
		for p; do printf ' -p %s' "$p"; done
	fi
}

# openssl-sys finds the cross libraries through pkg-config; without these it picks up the VM's
# native aarch64 openssl and the link fails.  Same variables build.sh exports.
cross_env="PKG_CONFIG_PATH= PKG_CONFIG_SYSROOT_DIR= PKG_CONFIG_LIBDIR=/usr/lib/x86_64-linux-gnu/pkgconfig"

cmd_check() {
	vm "cargo check --all-targets $(pkg_args "$@")"
}

cmd_test() {
	vm "cargo test $(pkg_args "$@")"
}

cmd_build() {
	[ $# -gt 0 ] || set -- $UNITS
	say "cross compiling$(pkg_args "$@") for $TARGET"
	vm "$cross_env cargo build --release --target $TARGET $(pkg_args "$@")"
	for b; do
		[ -f "$OUT/$b" ] || die "expected artifact $OUT/$b was not produced"
		ok "$OUT/$b"
	done
}

cmd_deploy() {
	[ $# -gt 0 ] || die 'usage: deploy <unit>...'
	cmd_build "$@"
	rc=0
	for b; do
		deploy_one "$b" || rc=1
	done
	return $rc
}

# Stop, back up, install, start, verify.  If the unit doesn't come back, put the old binary back
# so the next iteration of the loop starts from a working server instead of a dead one.
deploy_one() {
	b=$1
	start=$(date +%s)
	say "deploying $b -> $VPS:/opt/$b"

	scp -q "$OUT/$b" "$VPS:/tmp/$b.new"
	ssh "$VPS" 'sudo -n sh -s' <<-EOF
		set -e
		if [ -f /opt/$b ]; then
			own=\$(stat -c '%U:%G' /opt/$b)
			cp -f /opt/$b /opt/$b.prev
		else
			own=root:root
		fi
		systemctl stop $b
		# install rather than cp: it unlinks first, so a still-mapped binary can't give us ETXTBSY
		install -m 755 -o "\${own%%:*}" -g "\${own##*:}" /tmp/$b.new /opt/$b
		rm -f /tmp/$b.new
		systemctl start $b
	EOF

	# Give it a moment to get past argument parsing and TUN setup before believing it started.
	sleep 3
	if vps "systemctl is-active --quiet $b"; then
		ok "$b is active"
		cmd_logs "$b" "@$start"
		return 0
	fi

	bad "$b did not come back up — rolling back to /opt/$b.prev"
	cmd_logs "$b" "@$start" || true
	cmd_rollback "$b"
	return 1
}

cmd_rollback() {
	b=${1:?usage: rollback <unit>}
	vps "test -f /opt/$b.prev" || die "no /opt/$b.prev to roll back to"
	vps_root "sh -c 'install -m 755 /opt/$b.prev /opt/$b && systemctl restart $b'"
	sleep 2
	if vps "systemctl is-active --quiet $b"; then
		ok "$b rolled back and active"
	else
		die "$b is still down after rollback — needs hands"
	fi
}

# The daemons run at RUST_LOG=trace, and most of that volume is mio::poll churn from a dependency.
# The third argument is a journalctl --grep pattern; the alias `app` keeps systemd's own lines,
# anything above TRACE, and TRACE from our own crates:
#   ./scripts/dev.sh logs turnserver -5min app
#   ./scripts/dev.sh logs turnserver -5min 'relay pool|ERROR'
APP_ONLY='systemd\[|(DEBUG|INFO|WARN|ERROR) |TRACE (swbrd|dtls_proxy|turnserver|ice_dissolve|common)'
cmd_logs() {
	unit=${1:?usage: logs <unit> [since] [grep-pattern|app]}
	since=${2:--2 min}
	pattern=${3:-}
	[ "$pattern" != app ] || pattern=$APP_ONLY
	[ -z "$pattern" ] || pattern="-g '$pattern'"
	vps_root "journalctl -u $unit --since '$since' --no-pager -o short-precise $pattern"
}

# Meant to be started with the Bash tool's run_in_background, or backgrounded by hand.
cmd_watch() {
	[ $# -gt 0 ] || set -- $UNITS
	sel=''
	for u; do sel="$sel -u $u"; done
	vps_root "journalctl -f$sel -o short-precise"
}

# tcpdump on the VPS; the pcap comes back here and the summary is printed there.  The filter is a
# normal pcap expression:
#   ./scripts/dev.sh capture 'ip6 and udp port 9899' 20
#
# The summary has to be decoded on the VPS: `-i any` records LINUX_SLL2, whose per-packet interface
# is an ifindex, and a reader on this machine resolves those against its own interface table — which
# silently renames eth0/dtls-proxy/ice-dissolve into whatever happens to share those indexes here.
cmd_capture() {
	filter=${1:-ip6}
	secs=${2:-20}
	stamp=$(date +%Y%m%d-%H%M%S)
	out=$SCRATCH/cap-$stamp.pcap
	remote=/tmp/swbrd-cap-$stamp.pcap
	say "capturing '$filter' on $VPS for ${secs}s"
	ssh "$VPS" 'sudo -n sh -s' <<-EOF
		# timeout exits 124 when it fires, which is the expected path here.
		timeout $secs tcpdump -i any -nn -s0 -w $remote '$filter' 2>/dev/null || true
		chmod 644 $remote 2>/dev/null || true
		tcpdump -nn -r $remote 2>/dev/null | head -80
	EOF
	scp -q "$VPS:$remote" "$out" 2>/dev/null || true
	ssh "$VPS" "sudo -n rm -f $remote"
	# A pcap with no packets is just the 24 byte file header.
	[ "$(wc -c <"$out" 2>/dev/null || echo 0)" -gt 24 ] || { bad "no packets captured"; return 1; }
	ok "$out ($(wc -c <"$out" | tr -d ' ') bytes)"
}

cmd_perf() {
	unit=${1:?usage: perf <unit> [secs]}
	secs=${2:-10}
	say "profiling $unit for ${secs}s"
	vps_root "sh -c 'pid=\$(systemctl show -p MainPID --value $unit); \
		perf record -F 999 -g -p \$pid -o /tmp/perf-$unit.data -- sleep $secs >/dev/null 2>&1; \
		perf report -i /tmp/perf-$unit.data --stdio --no-children 2>/dev/null | head -60'"
}

# Push etc/nftables.conf and reload.  `nft -c` against the new file first is the whole safety net --
# nft's atomic transaction model means a bad ruleset never gets applied, so unlike deploy_one there's
# nothing to back up or roll back.
cmd_nft() {
	say "checking etc/nftables.conf"
	ssh "$VPS" 'sudo -n /usr/sbin/nft -c -f -' < "$ROOT/etc/nftables.conf" || die "nft -c rejected the new ruleset -- nothing was touched"
	ok "syntax check passed"

	say "deploying etc/nftables.conf -> $VPS:/etc/nftables.conf"
	scp -q "$ROOT/etc/nftables.conf" "$VPS:/tmp/nftables.conf.new"
	vps_root "install -m 644 -o root -g root /tmp/nftables.conf.new /etc/nftables.conf"
	vps "rm -f /tmp/nftables.conf.new"
	vps_root "systemctl reload nftables"

	sleep 1
	if vps "systemctl is-active --quiet nftables"; then
		ok "nftables reloaded"
	else
		bad "nftables is not active -- previous ruleset was almost certainly never replaced (reload aborts before flushing on error)"
		vps_root "journalctl -u nftables -n 30 --no-pager -o short-precise" || true
		die "check the box by hand"
	fi
}

cmd_status() {
	for u in $UNITS; do
		state=$(vps "systemctl is-active $u" || true)
		printf '%-14s %s\n' "$u" "$state"
		[ "$state" = active ] || vps_root "journalctl -u $u -n 10 --no-pager -o short-precise" || true
	done
}

cmd_serve() {
	port=${1:-$PORT}
	if curl -sf -o /dev/null "http://localhost:$port/"; then
		ok "already serving on $port"
		return 0
	fi
	say "starting file-server on $port"
	(cd "$ROOT" && exec file-server -p "$port" --cors -H 'Cache-Control: no-cache') \
		>"$SCRATCH/file-server.log" 2>&1 &
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		curl -sf -o /dev/null "http://localhost:$port/" && { ok "serving $ROOT on $port"; return 0; }
		sleep 0.3
	done
	die "file-server did not come up; see $SCRATCH/file-server.log"
}

cmd_e2e() {
	exec deno run --allow-run --allow-net --allow-read --allow-write --allow-env \
		"$ROOT/scripts/e2e.js" "$@"
}

usage() {
	sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
	cat >&2 <<-EOF

	subcommands:
	  check [crate...]            cargo check on the VM (native, fastest)
	  test [crate...]             cargo test on the VM
	  build [unit...]             cross compile for $TARGET
	  deploy <unit>...            build, upload, restart, verify, roll back on failure
	  rollback <unit>             restore /opt/<unit>.prev
	  logs <unit> [since] [re]    journalctl window ('@<epoch>' works; 're' may be the alias 'app')
	  watch [unit...]             journalctl -f
	  capture [filter] [secs]     tcpdump on the VPS into a local pcap
	  perf <unit> [secs]          perf record + report on the VPS
	  status                      is-active for $UNITS
	  serve [port]                file-server for this tree on localhost:$PORT
	  e2e <page> [opts]           run a tests/*.html page in headless Chrome
	  nft                         check + push etc/nftables.conf, reload
	  vm <cmd>... | vps <cmd>...  raw command on the build VM / the VPS
	EOF
	exit 2
}

sub=${1:-}
[ $# -gt 0 ] && shift || true
case $sub in
	check|test|build|deploy|rollback|logs|watch|capture|perf|status|serve|e2e|nft) "cmd_$sub" "$@" ;;
	vm) vm "$@" ;;
	vps) vps "$@" ;;
	*) usage ;;
esac
