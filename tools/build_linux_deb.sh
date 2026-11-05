#!/usr/bin/env bash
# Win's VPN — build a distributable Debian package from a LINKED Linux bundle.
#
#   tools/build_linux_deb.sh <bundle-dir> [arm64|amd64] [outdir]
#
# <bundle-dir> is the directory `flutter build linux --release` produced, i.e.
# the one containing `wins_vpn`, `lib/` and `data/`. This script does NOT build
# it; producing the bundle is tools/build_linux_desktop_container.sh (compile
# recipe) or tools/build_linux_release.sh (signed release pipeline). This is
# only the packaging step, so that a bundle from either producer packages the
# same way.
#
# WHAT THE PACKAGE DOES ON INSTALL
# --------------------------------
# It copies files, refreshes the desktop and icon caches, and reloads systemd
# so the shipped unit is visible. It does NOT connect, does NOT enable or start
# any tunnel, does NOT enable winsvpn-recover.service, does NOT write any
# configuration, and does NOT touch the firewall. `postinst` is auditable in
# full below and deliberately short. An installer that brings a tunnel up is an
# installer that decides for the user when their traffic moves; on the networks
# this product is built for that decision is not an installer's to make.
#
# The one privileged thing the package SHIPS (not runs) is
# winsvpn-recover.service, the boot-time removal of a kill switch that outlived
# its session -- see linux/packaging/winsvpn-recover.service, which explains why
# it is shipped disabled.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

architecture_self_test=0
if [[ "${1:-}" == "--self-test-bundle-architecture" ]]; then
    architecture_self_test=1
    bundle="${2:-}"
    arch="${3:-}"
    outdir=""
else
    bundle="${1:-}"
    arch="${2:-}"
    outdir="${3:-$ROOT/build/linux-deb}"
fi

[[ -n "$bundle" ]] || { echo "usage: $(basename "$0") <bundle-dir> [arm64|amd64] [outdir]" >&2; exit 2; }
[[ -d "$bundle" ]] || { echo "no such bundle directory: $bundle" >&2; exit 2; }
[[ -x "$bundle/wins_vpn" ]] || { echo "bundle has no executable wins_vpn: $bundle" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Architecture: DERIVED from the binary, never trusted from the argument. A
# package labelled arm64 that carries an x86-64 ELF is worse than a failed
# build -- dpkg installs it and the user gets "cannot execute binary file".
# ---------------------------------------------------------------------------
elf_identity() {
    # Read the fixed ELF64 header directly rather than through readelf, so this
    # producer works on a host that has dpkg but no binutils. A matching
    # e_machine field alone is not sufficient: wrong-class, wrong-endian, and
    # non-executable ELF objects must also fail closed.
    local f="$1" magic elf_class elf_data type_low type_high machine_low machine_high
    [[ -f "$f" && ! -L "$f" ]] || return 1
    magic="$(LC_ALL=C od -An -tx1 -N4 "$f" | tr -d ' \n')"
    [[ "$magic" == "7f454c46" ]] || { echo "not an ELF file: $f" >&2; return 1; }
    elf_class="$(LC_ALL=C od -An -tu1 -j4 -N1 "$f" | tr -d ' \n')"
    elf_data="$(LC_ALL=C od -An -tu1 -j5 -N1 "$f" | tr -d ' \n')"
    [[ "$elf_class" == 2 && "$elf_data" == 1 ]] || {
        echo "not a supported little-endian ELF64 file: $f" >&2
        return 1
    }
    IFS=' ' read -r type_low type_high < <(
        LC_ALL=C od -An -tu1 -j16 -N2 "$f" | tr -s ' ' | sed 's/^ //'
    )
    IFS=' ' read -r machine_low machine_high < <(
        LC_ALL=C od -An -tu1 -j18 -N2 "$f" | tr -s ' ' | sed 's/^ //'
    )
    printf '%d %d\n' \
        "$((type_low + 256 * type_high))" \
        "$((machine_low + 256 * machine_high))"
}
IFS=' ' read -r elf_type machine < <(elf_identity "$bundle/wins_vpn") || exit 3
[[ "$elf_type" == 2 || "$elf_type" == 3 ]] || {
    echo "unsupported ELF type in $bundle/wins_vpn: '$elf_type'" >&2
    exit 3
}
case "$machine" in
    183) detected=arm64 ;;   # EM_AARCH64
    62)  detected=amd64 ;;   # EM_X86_64
    *) echo "unsupported ELF machine id in $bundle/wins_vpn: '$machine'" >&2; exit 3 ;;
esac
if [[ -n "$arch" && "$arch" != "$detected" ]]; then
    echo "refusing to mislabel: you asked for '$arch', the binary is '$detected'" >&2
    exit 3
fi
arch="$detected"

assert_bundle_architecture() {
    local root="$1" expected_machine="$2" candidate magic candidate_type candidate_machine
    local -a required_elf=(
        wins_vpn
        winsvpn-bypass-bpf
        winn-datapath
        xray
        awg
        amneziawg-go
        tools/native_messaging/host/wins_bridge_host
    )
    local -a required_library=(
        lib/libapp.so
        lib/libflutter_linux_gtk.so
    )
    for candidate in "${required_elf[@]}"; do
        [[ -f "$root/$candidate" && ! -L "$root/$candidate" && -x "$root/$candidate" ]] || {
            echo "required target ELF is missing or unsafe: $candidate" >&2
            return 3
        }
    done
    [[ -f "$root/awg-quick" && ! -L "$root/awg-quick" && -x "$root/awg-quick" ]] || {
        echo "required architecture-independent runtime is missing or unsafe: awg-quick" >&2
        return 3
    }
    for candidate in "${required_library[@]}"; do
        [[ -f "$root/$candidate" && ! -L "$root/$candidate" ]] || {
            echo "required Flutter/runtime ELF is missing or unsafe: $candidate" >&2
            return 3
        }
    done
    while IFS= read -r -d '' candidate; do
        magic="$(LC_ALL=C od -An -tx1 -N4 "$candidate" | tr -d ' \n')"
        [[ "$magic" == "7f454c46" ]] || continue
        IFS=' ' read -r candidate_type candidate_machine < <(elf_identity "$candidate") || return 3
        [[ "$candidate_type" == 2 || "$candidate_type" == 3 ]] || {
            echo "refusing to package unsupported ELF type $candidate_type: $candidate" >&2
            return 3
        }
        [[ "$candidate_machine" == "$expected_machine" ]] || {
            echo "refusing mixed-architecture bundle: $candidate targets ELF machine $candidate_machine, expected $expected_machine ($arch)" >&2
            return 3
        }
    done < <(find "$root" -type f -print0)
}

expected_machine=62
[[ "$arch" == arm64 ]] && expected_machine=183
assert_bundle_architecture "$bundle" "$expected_machine"

if [[ "$architecture_self_test" == 1 ]]; then
    printf 'LINUX DEB BUNDLE ARCHITECTURE SELF-TEST: PASS (%s)\n' "$arch"
    exit 0
fi

# A Debian package cannot turn a compile-time Dart capability on after the
# fact. Accept only a canonical release bundle whose exact runner, AOT payload,
# winn-datapath, producer, native gates, and single true define are bound by the
# producer-owned attestation. This also rejects raw Flutter Release bundles.
bash "$ROOT/tools/build_linux_release.sh" \
    --verify-winn3-dual-auth-bundle "$bundle"

command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required (apt-get install dpkg-dev)" >&2; exit 2; }

# Version comes from pubspec.yaml, the same single source every other producer
# reads. Flutter's `<semver>+<build>` becomes Debian's `<upstream>-<revision>`
# form `<semver>-<build>`: the build number is exactly a Debian revision, and
# writing it that way makes `dpkg --compare-versions` order two builds of the
# same semver correctly, which `1.0.15+30` would not.
APP_VERSION="$(awk '/^version:[[:space:]]*/ {gsub(/\r/,""); split($2, p, "+"); print p[1]; exit}' "$ROOT/pubspec.yaml")"
BUILD_NUMBER="$(awk '/^version:[[:space:]]*/ {gsub(/\r/,""); split($2, p, "+"); print p[2]; exit}' "$ROOT/pubspec.yaml")"
[[ "$APP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$BUILD_NUMBER" =~ ^[0-9]+$ ]] \
    || { echo "could not read 'version: <semver>+<build>' from pubspec.yaml" >&2; exit 3; }
DEB_VERSION="${APP_VERSION}-${BUILD_NUMBER}"

pkgroot="$(mktemp -d "${TMPDIR:-/tmp}/wins-vpn-deb.XXXXXX")"
trap 'rm -rf "$pkgroot"' EXIT
# mktemp -d gives 0700, and that mode would be recorded for `./` -- the package
# root, which unpacks onto `/`. Make it the ordinary 0755 before anything is
# staged inside it.
chmod 0755 "$pkgroot"

echo "=== staging ${DEB_VERSION} ${arch} ==="

install -d -m 0755 "$pkgroot/DEBIAN"
install -d -m 0755 "$pkgroot/opt/wins-vpn"
install -d -m 0755 "$pkgroot/usr/bin"
install -d -m 0755 "$pkgroot/usr/share/applications"
install -d -m 0755 "$pkgroot/usr/share/metainfo"
install -d -m 0755 "$pkgroot/usr/share/icons/hicolor/512x512/apps"
# /usr/lib/systemd/system, not /lib/systemd/system: both Debian 12 and Ubuntu
# 24.04 are usr-merged, so /lib is a symlink and shipping package files through
# a symlinked directory is what dpkg asks packages not to do.
install -d -m 0755 "$pkgroot/usr/lib/systemd/system"

# The bundle, at the prefix the app resolves its own bundled tools from
# (linux_tunnel_backend.cc FindWinnDatapathExecutable is bundle-only and
# lstat+X_OK checked, so the layout under /opt/wins-vpn must be preserved
# exactly as the bundle produced it).
cp -a "$bundle/." "$pkgroot/opt/wins-vpn/"
chmod 0755 "$pkgroot/opt/wins-vpn/wins_vpn"

# A .deb must not carry a dangling or absolute-escaping symlink, and the
# release installer already refuses any symlink inside the payload; keep the
# package payload symlink-free for the same reason.
if find "$pkgroot/opt/wins-vpn" -type l -print -quit | grep -q .; then
    echo "refusing to package: the bundle contains a symbolic link" >&2
    exit 3
fi

install -D -m 0644 "$ROOT/linux/packaging/RECOVERY.md" \
    "$pkgroot/opt/wins-vpn/share/doc/wins-vpn/RECOVERY.md"
install -D -m 0755 "$ROOT/linux/packaging/winsvpn-recover" \
    "$pkgroot/opt/wins-vpn/share/wins-vpn/winsvpn-recover"
install -D -m 0644 "$ROOT/linux/packaging/winsvpn-recover.service" \
    "$pkgroot/usr/lib/systemd/system/winsvpn-recover.service"
install -D -m 0644 "$ROOT/linux/packaging/org.winsvpn.app.desktop" \
    "$pkgroot/usr/share/applications/org.winsvpn.app.desktop"
install -D -m 0644 "$ROOT/linux/packaging/org.winsvpn.app.metainfo.xml" \
    "$pkgroot/usr/share/metainfo/org.winsvpn.app.metainfo.xml"

icon_src="$ROOT/assets/icon/app_icon.png"
[[ -f "$icon_src" ]] || icon_src="$ROOT/assets/icon/Win's VPN 1MB.png"
[[ -f "$icon_src" ]] || { echo "no application icon found under assets/icon" >&2; exit 3; }
install -D -m 0644 "$icon_src" \
    "$pkgroot/usr/share/icons/hicolor/512x512/apps/org.winsvpn.app.png"

ln -s /opt/wins-vpn/wins_vpn "$pkgroot/usr/bin/wins_vpn"

# ---------------------------------------------------------------------------
# COMPLETENESS. `flutter build linux --release` produces wins_vpn + lib/ +
# data/ and nothing else. tools/build_linux_release.sh then stages the runtime
# binaries INTO THE SAME bundle directory: winn-datapath (the Winn Protocol v3
# engine), xray, awg, awg-quick, amneziawg-go, winsvpn-bypass-bpf.
#
# FindWinnDatapathExecutable (linux_tunnel_backend.cc:1028) is bundle-only and
# lstat + X_OK checked -- it never falls back to PATH. So a package built from
# a bare flutter bundle installs cleanly, launches, and then cannot start a v3
# session at all, with the failure surfacing only when a user presses Connect.
# That is the exact shape of silent breakage this project keeps paying for, so
# it is a refusal here rather than a warning nobody reads.
# ---------------------------------------------------------------------------
missing_tools=()
for tool in \
    winn-datapath \
    xray \
    awg \
    awg-quick \
    amneziawg-go \
    winsvpn-bypass-bpf \
    tools/native_messaging/host/wins_bridge_host; do
    [[ -x "$pkgroot/opt/wins-vpn/$tool" ]] || missing_tools+=("$tool")
done
if (( ${#missing_tools[@]} > 0 )); then
    echo "" >&2
    echo "INCOMPLETE BUNDLE: these runtime binaries are not in $bundle:" >&2
    printf '  %s\n' "${missing_tools[@]}" >&2
    echo "" >&2
    echo "A package without winn-datapath cannot start a Winn Protocol v3" >&2
    echo "session -- FindWinnDatapathExecutable is bundle-only, never PATH." >&2
    echo "Build the bundle with tools/build_linux_release.sh, which stages" >&2
    echo "these into the same directory, then package that." >&2
    echo "" >&2
    echo "Refusing to produce a package without the complete v3-primary and" >&2
    echo "v1-fallback runtime set." >&2
    exit 4
fi

# Every executable ELF in the package must target the architecture declared by
# the application binary. This catches mixed-architecture engine, browser-host,
# plugin, and shared-library bundles before dpkg can label them as installable.
assert_bundle_architecture "$pkgroot/opt/wins-vpn" "$expected_machine"

# The bundle carries an attestation written only after its AOT bytes were
# scanned for the compiled expected ring identity. Packaging an older or
# differently reviewed bundle is fatal.
ring_attestation="$bundle/winn3-descriptor-ring-attestation.json"
[[ -f "$ring_attestation" && ! -L "$ring_attestation" ]] || {
  echo "Standalone v3 bundle lacks winn3-descriptor-ring-attestation.json." >&2
  exit 65
}
python3 - "$ring_attestation" "${WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256:-}" <<'PY'
import json, re, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
actual = str(document.get("identity_sha256", "")).lower()
expected = sys.argv[2].lower()
if not re.fullmatch(r"[0-9a-f]{64}", expected) or actual != expected:
    raise SystemExit("reviewed Winn3 descriptor ring identity mismatch in bundle")
PY

installed_kb="$(du -sk "$pkgroot" | cut -f1)"

# ---------------------------------------------------------------------------
# Dependencies. Derived from what the product actually calls, not guessed:
#
#   libgtk-3-0*, libsecret-1-0, libstdc++6  -- linked by the runner
#                                              (linux/runner/CMakeLists.txt)
#   iproute2                                -- `ip route|address|link`, the
#                                              entire v3 posture allowlist
#   iptables                                -- WINSVPN_KS / WINSVPN_RG* chains
#   nftables                                -- `nft`, required by install.sh's
#                                              own post-dependency check
#   util-linux                              -- `flock`, `setpriv`
#   passwd                                  -- useradd/usermod/userdel/groupdel
#   coreutils, libc-bin, bash, curl         -- same check
#   systemd                                 -- systemctl / systemd-run
#
# The t64 alternatives are Ubuntu 24.04's 64-bit-time_t renames; listing both
# keeps one package installable on Debian 12 and Ubuntu 24.04 alike.
#
# Recommends, not Depends, on purpose:
#   gnome-keyring    -- any Secret Service implementation satisfies
#                       linux_secure_store.cc; a KDE host uses kwalletmanager.
#   openresolv | systemd-resolved -- the v3 promoted posture probes THREE
#                       resolver mechanisms (resolvectl, resolvconf, direct
#                       /etc/resolv.conf rewrite) and picks what the host has;
#                       forcing one would fight the host's own resolver.
#   polkitd | policykit-1 | sudo -- PrivilegedRunner() tries `sudo -n` first
#                       and `pkexec` second; a host needs one, not both.
# ---------------------------------------------------------------------------
cat > "$pkgroot/DEBIAN/control" <<CONTROL
Package: wins-vpn
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: ${arch}
Maintainer: Win's VPN Inc. <admin@winsvpn.org>
Homepage: https://winsvpn.org
Installed-Size: ${installed_kb}
Depends: bash, coreutils, libc-bin, curl, iproute2, iptables, nftables,
 passwd, util-linux, systemd,
 libgtk-3-0t64 | libgtk-3-0, libsecret-1-0, libstdc++6
Recommends: gnome-keyring, polkitd | policykit-1 | sudo,
 openresolv | systemd-resolved
Description: Win's VPN — privacy-focused VPN client
 Win's VPN is a VPN client for people who need reliable access on hostile or
 unstable networks. This package installs the desktop application only.
 .
 Installing this package does not connect anything. No tunnel is started, no
 service is enabled, and no firewall rule is written until the user presses
 Connect in the application.
 .
 The package also ships winsvpn-recover.service, a boot-time oneshot that
 removes a kill switch left behind by a session that ended uncleanly. It is
 shipped DISABLED: see /opt/wins-vpn/share/doc/wins-vpn/RECOVERY.md.
CONTROL

# ---------------------------------------------------------------------------
# postinst: caches and a daemon-reload. Nothing else. Read it and check.
# ---------------------------------------------------------------------------
cat > "$pkgroot/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e

case "$1" in
    configure)
        # Desktop/icon caches, so the app appears in the menu.
        if command -v update-desktop-database >/dev/null 2>&1; then
            update-desktop-database -q /usr/share/applications || true
        fi
        if command -v gtk-update-icon-cache >/dev/null 2>&1; then
            gtk-update-icon-cache -q -f /usr/share/icons/hicolor || true
        fi

        # Make the shipped unit visible to systemd. This is a RELOAD of unit
        # files only: it does not enable, start, or activate anything.
        #
        # winsvpn-recover.service is deliberately NOT enabled here. Removing
        # firewall state automatically at every boot is a decision for the
        # machine's owner. The unit's own header carries the same statement.
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
        fi

        # NO tunnel is started here. NO service is enabled here. NO firewall
        # rule is written here. NO configuration is created here. If a future
        # edit adds any of those to this script, it is a defect: the product
        # must never move a user's traffic because a package was installed.

        echo "Win's VPN installed. Launch it from the app menu, or run: wins_vpn"
        echo "Optional, recommended if this machine is force-rebooted often:"
        echo "  sudo systemctl enable winsvpn-recover.service"
        echo "  (removes a leftover kill switch at boot; it never connects)"
        ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        ;;
esac

exit 0
POSTINST

# ---------------------------------------------------------------------------
# prerm: the one thing an uninstall MUST do. Removing the application while a
# kill switch is installed would leave the machine with no internet and no app
# to press Disconnect in -- the exact stranding RECOVERY.md exists for. So the
# recovery script runs here, while it still exists on disk.
# ---------------------------------------------------------------------------
cat > "$pkgroot/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e

case "$1" in
    remove|deconfigure)
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now winsvpn-recover.service >/dev/null 2>&1 || true
        fi
        # Never strand the machine: drop any leftover kill switch before the
        # app that knows how to remove it is deleted.
        if [ -x /opt/wins-vpn/share/wins-vpn/winsvpn-recover ]; then
            /opt/wins-vpn/share/wins-vpn/winsvpn-recover || true
        fi
        ;;
    upgrade|failed-upgrade)
        ;;
esac

exit 0
PRERM

cat > "$pkgroot/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e

case "$1" in
    remove|purge)
        if command -v update-desktop-database >/dev/null 2>&1; then
            update-desktop-database -q /usr/share/applications || true
        fi
        if command -v gtk-update-icon-cache >/dev/null 2>&1; then
            gtk-update-icon-cache -q -f /usr/share/icons/hicolor || true
        fi
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
        fi
        # User data under ~/.local/share/wins_vpn is NOT deleted, on purge or
        # otherwise: it is per-user, root does not own it, and a package script
        # walking every home directory to delete files is a worse hazard than a
        # leftover directory.
        ;;
esac

exit 0
POSTRM

chmod 0755 "$pkgroot/DEBIAN/postinst" "$pkgroot/DEBIAN/prerm" "$pkgroot/DEBIAN/postrm"

# md5sums over the payload (not the control scripts), the dpkg convention.
( cd "$pkgroot" && find . -path ./DEBIAN -prune -o -type f -print0 \
    | sed -z 's|^\./||' | xargs -0 -r md5sum > DEBIAN/md5sums )

mkdir -p "$outdir"
deb="$outdir/wins-vpn_${DEB_VERSION}_${arch}.deb"
rm -f "$deb"
dpkg-deb --root-owner-group --build "$pkgroot" "$deb" >/dev/null

# Re-open the produced package rather than trusting the staging copy. The .deb
# is accepted only if its installed /opt bundle still satisfies the same exact
# dual-auth artifact binding.
deb_verify_root="$pkgroot/.dual-auth-deb-verify"
mkdir -m 0700 -- "$deb_verify_root"
dpkg-deb -x "$deb" "$deb_verify_root"
bash "$ROOT/tools/build_linux_release.sh" \
    --verify-winn3-dual-auth-bundle "$deb_verify_root/opt/wins-vpn"

echo "=== built $deb ==="
dpkg-deb --info "$deb"
echo "=== contents (top level) ==="
dpkg-deb --contents "$deb" | awk '{print $1, $6, $7, $8}' | head -20
echo "=== size ==="
printf '%s bytes\n' "$(wc -c < "$deb" | tr -d ' ')"
sha256sum "$deb"
