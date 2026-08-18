#!/bin/sh
# Assemble one .deb from packaging/<pkg>/.  Runs on the build VM, in the repo
# root, against the shared tree -- so the finished .deb is visible on the Mac
# side too.  No debhelper, no debian/rules: the staged tree under
# packaging/<pkg>/files is already the filesystem we want, and everything that
# varies (version, arch, size) is a placeholder in packaging/<pkg>/control.
#
#   packaging/mk-deb.sh <pkg> <version> <arch> <bindir> <outdir>
set -eu

pkg=${1:?usage: mk-deb.sh <pkg> <version> <arch> <bindir> <outdir>}
version=${2:?}
arch=${3:?}
bindir=${4:?}
outdir=${5:?}

src=packaging/$pkg
[ -d "$src" ] || { echo "mk-deb: no such package: $src" >&2; exit 1; }
compat=$(cat packaging/compat)

stage=target/deb/stage/$pkg
rm -rf "$stage"
mkdir -p "$stage/DEBIAN" "$outdir"

[ -d "$src/files" ] && cp -a "$src/files/." "$stage/"

# Binaries are built elsewhere (cargo on this VM, or deno compile) and named in
# packaging/<pkg>/binaries as `source-name:/absolute/dest`.
if [ -f "$src/binaries" ]; then
	while IFS=: read -r from to; do
		[ -n "${from:-}" ] || continue
		[ -f "$bindir/$from" ] || { echo "mk-deb: missing binary $bindir/$from" >&2; exit 1; }
		mkdir -p "$stage$(dirname "$to")"
		install -m 0755 "$bindir/$from" "$stage$to"
	done < "$src/binaries"
fi

# Files taken straight out of the repo (not built, and not under packaging/files
# because .gitignore would swallow them there): src:dest:mode, src relative to
# the repo root.
if [ -f "$src/extras" ]; then
	while IFS=: read -r from to mode; do
		[ -n "${from:-}" ] || continue
		[ -f "$from" ] || { echo "mk-deb: missing extra $from" >&2; exit 1; }
		mkdir -p "$stage$(dirname "$to")"
		install -m "$mode" "$from" "$stage$to"
	done < "$src/extras"
fi

# Policy 12.5 puts the licence here and everyone looks here, so every package gets
# one -- see packaging/copyright for why it is a placeholder rather than the real
# thing.
mkdir -p "$stage/usr/share/doc/$pkg"
sed "s|@PACKAGE@|$pkg|g" packaging/copyright > "$stage/usr/share/doc/$pkg/copyright"
chmod 0644 "$stage/usr/share/doc/$pkg/copyright"

find "$stage" -type d -exec chmod 0755 {} +

size=$(du -sk --exclude=DEBIAN "$stage" | cut -f1)
sed -e "s|@VERSION@|$version|g" \
    -e "s|@ARCH@|$arch|g" \
    -e "s|@COMPAT@|$compat|g" \
    -e "s|@INSTALLED_SIZE@|$size|g" \
    "$src/control" > "$stage/DEBIAN/control"

# The control file decides the architecture (swbrd-common is `all`), not the
# caller -- keep the filename honest.
deb_arch=$(sed -n 's/^Architecture: *//p' "$stage/DEBIAN/control")

[ -f "$src/conffiles" ] && install -m 0644 "$src/conffiles" "$stage/DEBIAN/conffiles"
for s in preinst postinst prerm postrm; do
	[ -f "$src/$s" ] && install -m 0755 "$src/$s" "$stage/DEBIAN/$s"
done

# Every file under /etc that a package ships must be listed in conffiles: dpkg
# does not infer them, and an unlisted one is silently clobbered on upgrade and
# orphaned on remove.  Cheap to check here, expensive to discover in production.
if [ -d "$stage/etc" ]; then
	conffiles=$(cd "$(dirname "$src")" && pwd)/$(basename "$src")/conffiles
	missing=$(cd "$stage" && find etc \( -type f -o -type l \) -print | sed 's|^|/|' | while read -r f; do
		grep -qxF "$f" "$conffiles" 2>/dev/null || echo "$f"
	done)
	if [ -n "$missing" ]; then
		echo "mk-deb: $pkg ships these /etc files without listing them in conffiles:" >&2
		echo "$missing" >&2
		exit 1
	fi
fi

out=$outdir/${pkg}_${version}_${deb_arch}.deb
# --root-owner-group instead of fakeroot: every entry becomes root:root, which is
# what we want everywhere.  Anything needing another owner (/var/lib/swbrd) is
# created by tmpfiles.d instead of shipped in the archive.
dpkg-deb --build --root-owner-group -Zxz -z6 "$stage" "$out" >/dev/null
echo "$out"
