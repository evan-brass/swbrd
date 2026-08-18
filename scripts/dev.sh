#!/bin/sh
# The inner development loop: build on the VM, deploy to the VPS, drive a browser, read the logs.
#
#   ./scripts/dev.sh test                          # cargo test on the build VM
#   ./scripts/dev.sh build dtls-proxy              # cross compile one binary for the VPS
#   ./scripts/dev.sh deploy turnserver             # build + package + apt install + verify (auto rollback)
#   ./scripts/dev.sh logs dtls-proxy -5min
#   ./scripts/dev.sh e2e tests/vpn.html --units=dtls-proxy,swbrd
#
# deploy/rollback work in units of Debian packages built from packaging/: each package owns its
# binary *and* its configuration -- unit file, .network files, sysctls, and its own slice of the
# nftables ruleset.  `legacy-deploy` is the older path that only replaces the binary in /opt; it is
# kept for skipping the packaging round trip, and it is what the box ran before `migrate`.
set -eu

VM=192.168.64.3            # Debian VM: the only place the daemons compile
VM_DIR=share/src/swbrd     # the same tree as this repo, shared over virtiofs...
MAC_DIR=$HOME/src/swbrd    # ...mounted here on this side
VPS=turn                   # turn.evan-brass.net, reached as user `evan` with passwordless sudo
TARGET=x86_64-unknown-linux-gnu
UNITS='dtls-proxy turnserver ice-dissolve swbrd'
PORT=8000

VPS_ROOT=root@turn         # apt wants a real root shell; everything else goes through evan + sudo -n
DEB_ARCH=amd64
VPS_POOL=/var/cache/swbrd-debs  # deployed .debs are kept here so rollback has something to install
POOL_KEEP=10                    # .debs retained per package (2 for the 91MB swbrd-cert-rotate)

# pkg:crate:unit -- `-` where the package has no binary or no unit of its own.
PKG_TABLE='swbrd-common:-:-
swbrd-turnserver:turnserver:turnserver.service
swbrd-ice-dissolve:ice-dissolve:ice-dissolve.service
swbrd-dtls-proxy:dtls-proxy:dtls-proxy.service
swbrd-cert-rotate:cert-rotate:swbrd-cert-rotate.timer'
# swbrd-cert-rotate is out of the default set: it is a 91MB deno binary that changes once a year.
DEFAULT_PKGS='swbrd-common swbrd-turnserver swbrd-ice-dissolve swbrd-dtls-proxy'

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
OUT=$ROOT/target/$TARGET/release
DEBDIR=$ROOT/target/deb
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

cmd_legacy_deploy() {
	[ $# -gt 0 ] || die 'usage: legacy-deploy <unit>...'
	cmd_build "$@"
	rc=0
	for b; do
		deploy_one "$b" || rc=1
	done
	return $rc
}

# Stop, back up, install, start, verify.  If the unit doesn't come back, put the old binary back
# so the next iteration of the loop starts from a working server instead of a dead one.
#
# Note this writes /opt/<unit>, which is where the hand-installed units used to point.  The packaged
# units run /usr/libexec/swbrd/<unit> instead, so on a box that has been through `migrate` this only
# does something if you also put the old /etc/systemd/system unit files back.  Kept as-is on purpose.
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
	cmd_legacy_rollback "$b"
	return 1
}

cmd_legacy_rollback() {
	b=${1:?usage: legacy-rollback <unit>}
	vps "test -f /opt/$b.prev" || die "no /opt/$b.prev to roll back to"
	vps_root "sh -c 'install -m 755 /opt/$b.prev /opt/$b && systemctl restart $b'"
	sleep 2
	if vps "systemctl is-active --quiet $b"; then
		ok "$b rolled back and active"
	else
		die "$b is still down after rollback — needs hands"
	fi
}

# --- packages -----------------------------------------------------------------
#
# Everything below deploys Debian packages built from packaging/.  A package owns
# its binary and its configuration together, so a deploy that changes a firewall
# rule or a unit file rolls back the same way a bad binary does.

# Run a command on the VPS as root.  `sudo -n` covers the read-only inspection the
# rest of this script does; apt wants a real root shell.
vps_su() {
	# shellcheck disable=SC2029
	ssh "$VPS_ROOT" "$*"
}

pkg_names() { echo "$PKG_TABLE" | cut -d: -f1; }

# Accept either the package name or the bare daemon name: `deploy turnserver`.
pkg_normalize() {
	for a; do
		if pkg_names | grep -qxF "$a"; then
			printf '%s ' "$a"
		elif pkg_names | grep -qxF "swbrd-$a"; then
			printf '%s ' "swbrd-$a"
		else
			die "unknown package: $a (have: $(pkg_names | tr '\n' ' '))"
		fi
	done
}

# pkg_field <pkg> crate|unit  -- empty when the package has none.
pkg_field() {
	echo "$PKG_TABLE" | while IFS=: read -r p c u; do
		[ "$p" = "$1" ] || continue
		case $2 in
			crate) [ "$c" = - ] || printf '%s' "$c" ;;
			unit) [ "$u" = - ] || printf '%s' "$u" ;;
		esac
	done
}

# The control file decides: swbrd-common is Architecture: all.
pkg_arch() {
	a=$(sed -n 's/^Architecture: *//p' "$ROOT/packaging/$1/control")
	[ "$a" = '@ARCH@' ] && a=$DEB_ARCH
	printf '%s' "$a"
}

pkg_file() {
	printf '%s/%s_%s_%s.deb' "$DEBDIR" "$1" "$2" "$(pkg_arch "$1")"
}

# apt only ever upgrades, so the version has to increase on every deploy.  A clean
# tree versions by committer date, which makes redeploying the same commit a no-op
# to apt; a dirty tree versions by build time, which is always later than the last
# commit and so keeps the sequence monotonic across the dirty -> commit -> dirty
# cycle of the inner loop.  (`git describe` is useless here: there are no tags.)
pkg_version() {
	if [ -z "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]; then
		stamp=$(git -C "$ROOT" log -1 --format=%cd --date=format-local:%Y%m%d%H%M%S)
	else
		stamp=$(date -u +%Y%m%d%H%M%S)
	fi
	printf '0.1.0+%s.g%s' "$stamp" "$(git -C "$ROOT" rev-parse --short=9 HEAD)"
}

# Build the binaries each named package needs, then assemble the .debs on the VM.
cmd_pkg() {
	[ $# -gt 0 ] || set -- $DEFAULT_PKGS
	pkgs=$(pkg_normalize "$@") || exit 1
	# shellcheck disable=SC2086  # word splitting is the point
	set -- $pkgs
	ver=$(pkg_version)

	crates=
	deno_needed=
	for p; do
		c=$(pkg_field "$p" crate)
		case $c in
			'') ;;
			cert-rotate) deno_needed=yes ;;
			*) crates="$crates $c" ;;
		esac
	done

	# shellcheck disable=SC2086
	[ -z "$crates" ] || cmd_build $crates

	say "staging binaries"
	vm "mkdir -p target/deb/bin && for b in$crates; do cp -f target/$TARGET/release/\$b target/deb/bin/\$b; done"
	if [ -n "$deno_needed" ]; then
		say "deno compile cert-rotate"
		vm "deno compile --target $TARGET --allow-read --allow-write -o target/deb/bin/cert-rotate ./scripts/cert-rotate.js"
	fi

	for p; do
		say "building $p $ver"
		vm "packaging/mk-deb.sh $p $ver $DEB_ARCH target/deb/bin target/deb" >/dev/null
		f=$(pkg_file "$p" "$ver")
		[ -f "$f" ] || die "mk-deb.sh did not produce $f"
		ok "$f ($(wc -c <"$f" | tr -d ' ') bytes)"
	done
}

# Build, upload, install, verify.  Every package installed in one apt transaction
# so inter-package Depends: resolve against the new versions rather than the old.
cmd_deploy() {
	[ $# -gt 0 ] || set -- $DEFAULT_PKGS
	pkgs=$(pkg_normalize "$@") || exit 1
	# shellcheck disable=SC2086
	set -- $pkgs
	ver=$(pkg_version)
	start=$(date +%s)

	cmd_pkg "$@"

	files=
	for p; do files="$files $(pkg_file "$p" "$ver")"; done
	remote=
	for p; do remote="$remote $VPS_POOL/${p}_${ver}_$(pkg_arch "$p").deb"; done

	say "uploading to $VPS_ROOT:$VPS_POOL"
	vps_su "install -d -m 755 $VPS_POOL"
	# shellcheck disable=SC2086
	scp -q $files "$VPS_ROOT:$VPS_POOL/"

	# Record what was installed *before* this deploy: that, not apt's version
	# list, is what rollback restores -- the exact analogue of /opt/<b>.prev.
	for p; do
		vps_su "dpkg-query -W -f='\${Version}' $p 2>/dev/null > $VPS_POOL/.prev-$p || : > $VPS_POOL/.prev-$p"
	done

	say "apt install$remote"
	# --force-confold keeps this non-interactive without ever clobbering a config
	# file edited on the box; dpkg leaves the shipped one as *.dpkg-dist, which we
	# report below so a divergence can't go unnoticed.
	vps_su "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
		-o Dpkg::Options::=--force-confold$remote" || die "apt-get install failed"

	dist=$(vps_su "find /etc -name '*.dpkg-dist' -newermt '-10 minutes' 2>/dev/null" || true)
	[ -z "$dist" ] || bad "config divergence, shipped versions left beside yours:$(printf ' %s' $dist)"

	pkg_prune "$@"

	# Give the units a moment to get past argument parsing and TUN setup.
	sleep 3
	rc=0
	for p; do
		u=$(pkg_field "$p" unit)
		[ -n "$u" ] || { ok "$p installed"; continue; }
		case $u in
			*.timer) vps "systemctl is-active --quiet $u" && ok "$u is active" || { bad "$u is not active"; rc=1; }; continue ;;
		esac
		if vps "systemctl is-active --quiet $u"; then
			ok "$u is active"
			cmd_logs "$u" "@$start" || true
		else
			bad "$u did not come back up -- rolling back $p"
			cmd_logs "$u" "@$start" || true
			cmd_rollback "$p" || true
			rc=1
		fi
	done
	return $rc
}

# Reinstall the version that was installed before the last deploy of this package.
cmd_rollback() {
	p=$(pkg_normalize "${1:?usage: rollback <pkg>}") || exit 1
	p=${p% }
	prev=$(vps_su "cat $VPS_POOL/.prev-$p 2>/dev/null" || true)
	[ -n "$prev" ] || die "no recorded previous version for $p (first install? use 'vps_su apt-get remove $p')"
	f=$VPS_POOL/${p}_${prev}_$(pkg_arch "$p").deb
	vps_su "test -f $f" || die "$f is no longer in the pool"

	say "rolling $p back to $prev"
	vps_su "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
		-o Dpkg::Options::=--force-confold $f" || die "rollback install failed"

	u=$(pkg_field "$p" unit)
	[ -n "$u" ] || { ok "$p rolled back"; return 0; }
	sleep 2
	if vps "systemctl is-active --quiet $u"; then
		ok "$p rolled back to $prev, $u active"
	else
		die "$u is still down after rollback -- needs hands"
	fi
}

# Keep the pool from growing without bound; cert-rotate is 91MB a copy.
pkg_prune() {
	for p; do
		keep=$POOL_KEEP
		[ "$p" = swbrd-cert-rotate ] && keep=2
		vps_su "ls -t $VPS_POOL/${p}_*.deb 2>/dev/null | tail -n +$((keep + 1)) | xargs -r rm -f"
	done
}

# One-time move off the hand-installed layout.  The files in /etc/systemd/system
# shadow the packaged units in /usr/lib/systemd/system by identical filename, so
# skipping this makes the packages install and appear to work while systemd keeps
# running the old binaries out of /opt.
cmd_migrate() {
	say "migrating $VPS off the hand-installed layout"
	vps_su 'sh -s' <<-'EOF'
		set -e
		systemctl disable --now turnserver ice-dissolve dtls-proxy \
			rotate-january.timer rotate-july.timer 2>/dev/null || true
		rm -f /etc/systemd/system/turnserver.service \
		      /etc/systemd/system/ice-dissolve.service \
		      /etc/systemd/system/dtls-proxy.service \
		      /etc/systemd/system/rotate-january.service /etc/systemd/system/rotate-january.timer \
		      /etc/systemd/system/rotate-july.service /etc/systemd/system/rotate-july.timer
		rm -rf /etc/systemd/system/nginx.service.d
		systemctl daemon-reload

		# swbrd.{netdev,network} stay: the VPN daemon is still hand-managed.
		rm -f /etc/systemd/network/turnserver.netdev /etc/systemd/network/turnserver.network \
		      /etc/systemd/network/ice-dissolve.netdev /etc/systemd/network/ice-dissolve.network \
		      /etc/systemd/network/dtls-proxy.netdev /etc/systemd/network/dtls-proxy.network \
		      /etc/systemd/network/transparent.network \
		      /etc/systemd/networkd.conf.d/swbrd.conf
		rm -f /etc/sysctl.d/transparent.conf /etc/sysctl.d/tcp-cookies.conf

		# The table was renamed ip6 swbrd -> ip6 ice_dissolve, so the packages
		# cannot clean the old one up themselves.
		nft destroy table ip6 swbrd 2>/dev/null || true

		install -d -m 755 /etc/nftables.d /etc/nginx/stream-enabled

		# nginx back to the distro conffile; the swbrd parts come back as
		# modules-enabled/90-swbrd-stream.conf + stream-enabled + conf.d.
		if ! dpkg --verify nginx-common 2>/dev/null | grep -q ' /etc/nginx/nginx.conf$'; then
			echo "migrate: /etc/nginx/nginx.conf already matches the distro copy"
		elif [ -f /etc/nginx/nginx.conf.backup ]; then
			cp -a /etc/nginx/nginx.conf /etc/nginx/nginx.conf.preswbrd
			cp /etc/nginx/nginx.conf.backup /etc/nginx/nginx.conf
		else
			echo "migrate: no /etc/nginx/nginx.conf.backup to restore -- do it by hand" >&2
			exit 1
		fi
		# Debian's default site has `listen [::]:80 default_server`, which collides
		# with our `listen [::]:80 ipv6only=off`.
		rm -f /etc/nginx/sites-enabled/default
	EOF
	ok "migrated -- now run: $0 nft && $0 deploy"
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

# Push etc/nftables.conf and reload.  That file is now just `flush ruleset` plus an include of
# /etc/nftables.d/*.nft -- the tables themselves ship inside the packages -- but it still belongs to
# the admin, because /etc/nftables.conf is the `nftables` package's conffile and so is not something
# any swbrd package may own.  `nft -c` against the new file first is the whole safety net: nft's
# atomic transaction model means a bad ruleset never gets applied, so there is nothing to roll back.
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
	sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
	cat >&2 <<-EOF

	subcommands:
	  check [crate...]            cargo check on the VM (native, fastest)
	  test [crate...]             cargo test on the VM
	  build [unit...]             cross compile for $TARGET
	  pkg [pkg...]                build + assemble .debs into target/deb
	  deploy [pkg...]             pkg, apt install on the VPS, verify, roll back on failure
	  rollback <pkg>              reinstall the version that was there before the last deploy
	  migrate                     one-time: drop the hand-installed units/config the packages replace
	  legacy-deploy <unit>...     pre-package path: scp the binary to /opt/<unit> and restart
	  legacy-rollback <unit>      restore /opt/<unit>.prev
	  logs <unit> [since] [re]    journalctl window ('@<epoch>' works; 're' may be the alias 'app')
	  watch [unit...]             journalctl -f
	  capture [filter] [secs]     tcpdump on the VPS into a local pcap
	  perf <unit> [secs]          perf record + report on the VPS
	  status                      is-active for $UNITS
	  serve [port]                file-server for this tree on localhost:$PORT
	  e2e <page> [opts]           run a tests/*.html page in headless Chrome
	  nft                         check + push etc/nftables.conf, reload
	  vm <cmd>... | vps <cmd>...  raw command on the build VM / the VPS
	  root <cmd>...               raw command on the VPS as root ($VPS_ROOT)
	EOF
	exit 2
}

sub=${1:-}
[ $# -gt 0 ] && shift || true
case $sub in
	check|test|build|pkg|deploy|rollback|migrate|logs|watch|capture|perf|status|serve|e2e|nft) "cmd_$sub" "$@" ;;
	legacy-deploy) cmd_legacy_deploy "$@" ;;
	legacy-rollback) cmd_legacy_rollback "$@" ;;
	vm) vm "$@" ;;
	vps) vps "$@" ;;
	root) vps_su "$@" ;;
	*) usage ;;
esac
