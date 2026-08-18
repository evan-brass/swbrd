# shellcheck shell=sh
# Helpers shared by every swbrd package's maintainer scripts.  Shipped by
# swbrd-common, which every other swbrd package depends on.

# /etc/nftables.conf belongs to the nftables package, so no swbrd package can
# ship it.  All we can do is notice when the admin's copy has lost the include
# and say so loudly -- without it the rules survive until the next boot only.
swbrd_check_nft_include() {
	if ! grep -q '/etc/nftables.d' /etc/nftables.conf 2>/dev/null; then
		echo "swbrd: WARNING: /etc/nftables.conf does not include /etc/nftables.d/*.nft;" >&2
		echo "swbrd:          swbrd firewall rules will be lost at the next boot." >&2
		echo "swbrd:          Fix with: ./scripts/dev.sh nft" >&2
	fi
}

# swbrd_nft_apply <fragment-name> <table spec>...
#
# Reapplies a fragment only when its contents changed or one of its tables has
# gone missing.  `delete table` frees the table's sets, so an unconditional
# reload on every upgrade would wipe turn_acct's per-client counters and santa's
# naughty list.  A same-version reinstall is thus a genuine no-op.
swbrd_nft_apply() {
	f=/etc/nftables.d/$1
	shift
	stamp=/var/lib/swbrd-nft/${f##*/}.sha256
	sum=$(sha256sum "$f" | cut -d' ' -f1)
	live=yes
	for t in "$@"; do
		# shellcheck disable=SC2086  # $t is a family+name pair, meant to split
		/usr/sbin/nft list table $t >/dev/null 2>&1 || live=no
	done
	if [ "$live" = yes ] && [ "$(cat "$stamp" 2>/dev/null)" = "$sum" ]; then
		return 0
	fi
	/usr/sbin/nft -f "$f"
	mkdir -p /var/lib/swbrd-nft
	printf '%s\n' "$sum" > "$stamp"
}

# swbrd_nft_drop <fragment-name> <table spec>...
swbrd_nft_drop() {
	f=$1
	shift
	for t in "$@"; do
		# shellcheck disable=SC2086
		/usr/sbin/nft destroy table $t 2>/dev/null || true
	done
	rm -f "/var/lib/swbrd-nft/$f.sha256"
}

# swbrd_sd_enable_start <unit> <old-version-or-empty>
# deb-systemd-helper rather than `systemctl enable`: it records enable state so
# purge/reinstall round-trips, and deb-systemd-invoke honours policy-rc.d.
swbrd_sd_enable_start() {
	unit=$1
	oldver=$2
	deb-systemd-helper unmask "$unit" >/dev/null || true
	# was-enabled is how an admin's `systemctl disable` survives an upgrade.
	if deb-systemd-helper --quiet was-enabled "$unit"; then
		deb-systemd-helper enable "$unit" >/dev/null || true
	fi
	# Unconditionally, so the statefile records the symlinks to clean up on purge.
	deb-systemd-helper update-state "$unit" >/dev/null || true
	[ -d /run/systemd/system ] || return 0
	systemctl --system daemon-reload >/dev/null || true
	if [ -n "$oldver" ]; then
		deb-systemd-invoke restart "$unit" >/dev/null || true
	else
		deb-systemd-invoke start "$unit" >/dev/null || true
	fi
}

# prerm(remove) stops, postrm(remove) masks, postrm(purge) purges the recorded
# state -- the dh_installsystemd lifecycle.  Do *not* disable in prerm: that
# discards the enable state, and deb-systemd-invoke silently skips any unit that
# is not enabled, so the next install would leave the daemon stopped.
swbrd_sd_stop() {
	[ -d /run/systemd/system ] && deb-systemd-invoke stop "$1" >/dev/null || true
}

swbrd_sd_mask() {
	deb-systemd-helper mask "$1" >/dev/null || true
}

swbrd_sd_purge() {
	deb-systemd-helper purge "$1" >/dev/null || true
	deb-systemd-helper unmask "$1" >/dev/null || true
}

# `networkctl reload` picks up .network/.netdev changes, but it never removes an
# interface whose .netdev file has gone away -- that needs an explicit delete.
swbrd_networkd_reload() {
	[ -d /run/systemd/system ] || return 0
	networkctl reload >/dev/null 2>&1 || true
}
