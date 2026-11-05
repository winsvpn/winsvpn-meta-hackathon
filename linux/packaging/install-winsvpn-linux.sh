#!/usr/bin/env bash
set -Eeuo pipefail

# M-2 remediation: linux/packaging/install.sh alone could never safely
# authenticate a downloaded release -- it only ever saw bytes *after* an
# unprivileged `tar xzf` had already extracted them, by which point a
# malicious or corrupted archive had already been trusted. This script is
# the one supported way to install a Win's VPN Linux release from a
# downloaded .tar.gz: it authenticates the *complete, unmodified* archive
# with the same Sigstore/cosign contract tools/build_linux_release.sh already
# signs it with (see sign_linux_release() there and tools/linux_release_signing.py),
# *before* extracting a single
# byte, then extracts directly into a fresh root-owned 0700 stage and hands
# off to install.sh from there with a clean environment. install.sh itself
# now refuses to run any other way (see its WINSVPN_VERIFIED_STAGE check).
#
# H-1 remediation (TOCTOU / use-after-verification): the downloaded archive
# and bundle stay at user-owned pathnames, which cosign, python3, and the
# privileged `tar` would otherwise each open independently. A same-user
# process can atomically swap a verified archive for a path-safe malicious
# one after signature verification but before root extraction. To close that
# window this script first copies both files into an immutable ROOT-OWNED
# snapshot (mode 0444, created with O_NOFOLLOW|O_EXCL by a root python
# helper), then verifies, member-scans, and extracts ONLY that snapshot. A
# race during the copy only yields bytes that fail cosign; once copied, the
# attacker can no longer modify the file that passed verification.
#
# H-2 remediation (attacker-selected verifier): PATH is pinned to trusted
# system directories before anything is resolved, and cosign together with
# every one of its parent directories must be root-owned and not
# group/other-writable before it is trusted -- a self-reported version string
# alone never establishes a verifier's integrity, and the verifier is never
# run under sudo.
#
# Usage:
#   install-winsvpn-linux.sh ARCHIVE BUNDLE
#     ARCHIVE  path to the downloaded wins-vpn-linux-x64.tar.gz
#     BUNDLE   path to the matching wins-vpn-linux-x64.tar.gz.sigstore.json
#   install-winsvpn-linux.sh --uninstall [PREFIX]
#     Remove the authenticated native-messaging host and Chrome/Edge/Firefox
#     manifests from the exact system destinations and the invoking user's
#     per-user dests. PREFIX is an isolated overlay root for tests; inner
#     symlinks and special files under PREFIX are refused.
#   install-winsvpn-linux.sh --verify-native-host-delivery [PREFIX]
#     With PREFIX, verify overlay dests. With no PREFIX, verify live dests.
#   install-winsvpn-linux.sh --self-test-native-host-delivery PREFIX
#     Isolated native-host delivery, Edge identity, rollback, and uninstall.
#
# Requires: cosign v3.1.3 exactly (install it from a signed OS package or a
# separately verified pinned artifact -- never `curl ... | sh`), sudo,
# /usr/bin/python3, tar.

# H-2: pin the search path to trusted, root-owned system directories before
# resolving cosign or any other program. Never inherit the caller's PATH for
# a decision that ends in a root extraction.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

COSIGN_VERSION="v3.1.3"
COSIGN_PATH="/usr/local/bin/cosign"
COSIGN_SHA256_X86_64="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
COSIGN_SHA256_AARCH64="c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a"
STANDARD_BUNDLE_MEDIA_TYPE="application/vnd.dev.sigstore.bundle.v0.3+json"
OFFLINE_TRUST_ANCHOR_ROUTE="/etc/winsvpn/release-signing/cosign.pub"

log() { printf '[WINS-LINUX-BOOTSTRAP] %s\n' "$*"; }
die() { printf '[WINS-LINUX-BOOTSTRAP] ERROR: %s\n' "$*" >&2; exit 65; }

BOOTSTRAP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# Exact Microsoft Edge native-messaging destinations. install.sh is the writer;
# this bootstrap uninstalls and verifies the same paths, including the per-user
# Edge dest the layout uses when registration is not system-wide.
NATIVE_HOST_EDGE_MANIFEST_DIR=/etc/opt/edge/native-messaging-hosts
NATIVE_HOST_EDGE_USER_REL=.config/microsoft-edge/NativeMessagingHosts
NATIVE_HOST_NAME=org.winsvpn.bridge

linux_packaging_install_sh() {
  if [[ -f "$BOOTSTRAP_DIR/install.sh" ]]; then
    printf '%s\n' "$BOOTSTRAP_DIR/install.sh"
  elif [[ -f "$BOOTSTRAP_DIR/linux/packaging/install.sh" ]]; then
    printf '%s\n' "$BOOTSTRAP_DIR/linux/packaging/install.sh"
  else
    die "cannot locate install.sh beside install-winsvpn-linux.sh"
  fi
}

if [[ "${1:-}" == "--self-test-native-host-delivery" ]]; then
  exec /bin/bash "$(linux_packaging_install_sh)" --self-test-native-host-delivery "${2:-}"
fi
installed_install_sh() {
  local candidate=/opt/wins-vpn/install.sh walk uid mode
  [[ -f "$candidate" && ! -L "$candidate" ]] || die "Win's VPN is not installed at /opt/wins-vpn."
  walk="$candidate"
  while :; do
    [[ ! -L "$walk" ]] || die "Refusing a symlinked path to the installed installer: $walk"
    read -r uid mode < <(stat -c '%u %a' -- "$walk") || die "Cannot inspect $walk"
    [[ "$uid" == 0 ]] || die "Refusing $walk: not owned by root."
    (( (8#$mode & 8#022) == 0 )) || die "Refusing $walk: writable by group or others."
    [[ "$walk" == / ]] && break
    walk="${walk%/*}"
    [[ -n "$walk" ]] || walk=/
  done
  printf '%s\n' "$candidate"
}
if [[ "${1:-}" == "--uninstall" ]]; then
  if [[ -n "${2:-}" ]]; then
    exec /bin/bash "$(linux_packaging_install_sh)" \
      --uninstall-native-host "$2"
  fi
  installed_script="$(installed_install_sh)" || exit $?
  exec /usr/bin/sudo -- /bin/bash "$installed_script" \
    --uninstall-native-host
fi
if [[ "${1:-}" == "--verify-native-host-delivery" ]]; then
  exec /bin/bash "$(linux_packaging_install_sh)" --verify-native-host-delivery "${2:-}"
fi

[[ "$(uname -s)" == Linux ]] || die "This installer only supports Linux."
# This bootstrap never opens the payload -- it verifies the archive's signature
# and hands the extracted tree to install.sh -- so the only architecture claim
# it can honestly make here is about THIS COMPUTER. Whether the archive matches
# is decided downstream by install.sh, on manifest-verified bytes, from the ELF
# header of the application binary rather than from the archive's filename.
#
# Until 2026-08-08 this line read `== x86_64` and refused arm64, which is the
# only architecture any Linux session in this project has ever run on.
case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *) die "Win's VPN has no build for this computer's processor type ($(uname -m)). Supported: x86-64 and arm64." ;;
esac

archive="${1:-}"
bundle="${2:-}"
[[ -n "$archive" && -n "$bundle" ]] || \
  die "Usage: $0 ARCHIVE BUNDLE (e.g. wins-vpn-linux-x64.tar.gz wins-vpn-linux-x64.tar.gz.sigstore.json)"
[[ -f "$archive" && ! -L "$archive" ]] || die "Archive not found or is a symbolic link: $archive"
[[ -f "$bundle" && ! -L "$bundle" ]] || die "Sigstore bundle not found or is a symbolic link: $bundle"
archive="$(realpath -e -- "$archive")"
bundle="$(realpath -e -- "$bundle")"

command -v sudo >/dev/null 2>&1 || die "sudo is required."
[[ -x /usr/bin/python3 ]] || die "/usr/bin/python3 is required to snapshot and safety-check the archive before extraction."
command -v tar >/dev/null 2>&1 || die "tar is required."

# H-2: a candidate program is trusted only if it, and every ancestor
# directory up to /, is owned by root (uid 0) and not writable by group or
# other. Every lexical component is inspected without resolving symlinks, so
# an alternate root-owned tree cannot be substituted behind the reviewed path.
trusted_root_path() {
  local candidate="$1" uid mode
  [[ "$candidate" == /* ]] || return 1
  while :; do
    [[ ! -L "$candidate" ]] || return 1
    read -r uid mode < <(stat -c '%u %a' -- "$candidate") || return 1
    [[ "$uid" == 0 ]] || return 1
    (( (8#$mode & 8#022) == 0 )) || return 1
    [[ "$candidate" == / ]] && break
    candidate="${candidate%/*}"
    [[ -n "$candidate" ]] || candidate=/
  done
}

# The local verification key is a required root-owned trust anchor, never an
# archive-controlled sidecar and never a remote certificate identity.
[[ -z "${WINS_LINUX_COSIGN_PUBKEY:-}" || "${WINS_LINUX_COSIGN_PUBKEY}" == "${OFFLINE_TRUST_ANCHOR_ROUTE}" ]] || \
  die "WINS_LINUX_COSIGN_PUBKEY, when set, must name ${OFFLINE_TRUST_ANCHOR_ROUTE}."
offline_pubkey_source="${OFFLINE_TRUST_ANCHOR_ROUTE}"
[[ -f "$offline_pubkey_source" && ! -L "$offline_pubkey_source" ]] || \
  die "The required reviewed cosign trust anchor is not a regular non-symlink file: $offline_pubkey_source"
trusted_root_path "$offline_pubkey_source" || \
  die "The reviewed cosign trust anchor or one of its parent directories is symlinked, writable, or not owned by root."

# Only the reviewed executable path is allowed. The version string is a
# consistency check after the architecture-specific digest authenticates bytes.
cosign_path="$COSIGN_PATH"
[[ -f "$cosign_path" && -x "$cosign_path" && ! -L "$cosign_path" ]] || \
  die "The fixed cosign executable is not a regular non-symlink file: $cosign_path"
trusted_root_path "$cosign_path" || \
  die "The fixed cosign executable or one of its parent directories is symlinked, writable, or not owned by root."
case "$(uname -m)" in
  x86_64|amd64) expected_cosign_sha256="$COSIGN_SHA256_X86_64" ;;
  aarch64|arm64) expected_cosign_sha256="$COSIGN_SHA256_AARCH64" ;;
  *) die "No reviewed cosign digest exists for $(uname -m)." ;;
esac
actual_cosign_sha256="$(sha256sum -- "$cosign_path" | awk '{print $1}')"
[[ "$actual_cosign_sha256" == "$expected_cosign_sha256" ]] || \
  die "Fixed cosign SHA-256 does not match the reviewed platform digest."
cosign_version_output="$("$cosign_path" version 2>&1)"
grep -Eq "^[[:space:]]*GitVersion:[[:space:]]*${COSIGN_VERSION//./\\.}[[:space:]]*$" \
  <<<"$cosign_version_output" \
  || die "Expected exact cosign $COSIGN_VERSION; refusing a different or ambiguous version."

# H-1: snapshot the archive and bundle into a fresh root-owned directory
# *before* verification. The snapshot files are created by root with
# O_NOFOLLOW|O_EXCL and left mode 0444, so once verified they cannot be
# swapped by any non-root process. Everything downstream operates only on the
# snapshot, never on the still-user-writable originals.
snapshot_root="$(sudo mktemp -d /var/tmp/winsvpn-snapshot.XXXXXX)"
cleanup() { sudo rm -rf -- "$snapshot_root"; }
trap cleanup EXIT

snapshot_file() {
  local source_path="$1" destination_path="$2"
  sudo /usr/bin/python3 - "$source_path" "$destination_path" <<'PY'
import os
import stat
import sys

source, destination = sys.argv[1], sys.argv[2]
source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    source_stat = os.fstat(source_fd)
    if not stat.S_ISREG(source_stat.st_mode):
        raise SystemExit("Snapshot source is not a regular file")
    destination_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o400,
    )
    try:
        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            view = memoryview(block)
            while view:
                view = view[os.write(destination_fd, view):]
        os.fsync(destination_fd)
        os.fchmod(destination_fd, 0o444)
    finally:
        os.close(destination_fd)
finally:
    os.close(source_fd)
PY
}

snapshot_archive="$snapshot_root/release.tar.gz"
snapshot_bundle="$snapshot_root/release.sigstore.json"
snapshot_pubkey="$snapshot_root/release.cosign.pub"
log "Creating an immutable root-owned snapshot of the archive and bundle"
snapshot_file "$archive" "$snapshot_archive"
snapshot_file "$bundle" "$snapshot_bundle"
snapshot_file "$offline_pubkey_source" "$snapshot_pubkey"
# The snapshot directory is root-owned; make it traversable so the
# non-privileged cosign verify and member scan can read the 0444 snapshot
# files, while the files themselves stay unmodifiable by non-root users.
sudo chmod 0755 -- "$snapshot_root"

# From here on, only ever touch the immutable snapshot.
archive="$snapshot_archive"
bundle="$snapshot_bundle"

# GHSA-fx35-mq7g-6g98 affects legacy JSON bundles and can bypass certificate
# identity policy in vulnerable Cosign versions. Refuse that format before
# invoking Cosign even though the exact verifier is also pinned to the fixed
# v3.1.3 release.
/usr/bin/python3 - "$bundle" "$STANDARD_BUNDLE_MEDIA_TYPE" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_media_type = sys.argv[2]

def strict_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value

try:
    payload = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=strict_json_object,
    )
except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
    raise SystemExit(f"Sigstore bundle is not valid UTF-8 JSON: {exc}")
if not isinstance(payload, dict) or payload.get("mediaType") != expected_media_type:
    raise SystemExit(
        f"Refusing a legacy or unsupported Sigstore bundle; expected {expected_media_type}"
    )
if not isinstance(payload.get("verificationMaterial"), dict):
    raise SystemExit("Standard Sigstore bundle lacks verificationMaterial")
content = [
    name for name in ("messageSignature", "dsseEnvelope")
    if isinstance(payload.get(name), dict)
]
if len(content) != 1:
    raise SystemExit("Standard Sigstore bundle must contain exactly one signature content type")
print("SIGSTORE STANDARD BUNDLE: PASS")
PY

log "Verifying archive signature: $archive"
pubkey="$snapshot_pubkey"
log "Verifying archive with the required local cosign trust anchor"
"$cosign_path" verify-blob "$archive" \
  --key "$pubkey" \
  --bundle "$bundle" \
  --offline \
  --insecure-ignore-tlog \
  || die "Cosign local-key verification failed. Refusing to extract or install an unauthenticated archive."
log "Cosign local-key verification passed."

log "Checking archive member safety before extraction"
/usr/bin/python3 - "$archive" <<'PY'
import sys
import tarfile

path = sys.argv[1]
seen = set()
with tarfile.open(path, "r:gz") as bundle:
    for member in bundle.getmembers():
        name = member.name
        if name in seen:
            raise SystemExit(f"Duplicate archive member (extraction-order ambiguity): {name!r}")
        seen.add(name)
        if name.startswith("/") or name.startswith("../") or name == ".." or "/../" in f"/{name}/":
            raise SystemExit(f"Unsafe absolute or path-traversal archive member: {name!r}")
        if member.issym() or member.islnk():
            raise SystemExit(f"Archive contains a link, which is never expected in this release: {name!r}")
        if member.isdev() or member.isfifo():
            raise SystemExit(f"Archive contains a device or FIFO, which is never expected in this release: {name!r}")
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"Unsupported archive member type: {name!r}")
    if not seen:
        raise SystemExit("Archive contains no members.")
print(f"ARCHIVE MEMBER SAFETY CHECK: PASS ({len(seen)} members)")
PY

log "Extracting the verified snapshot into a fresh root-owned stage"
stage="$snapshot_root/payload"
sudo mkdir -m 0700 -- "$stage"
sudo tar --extract --gzip --file "$archive" --directory "$stage" \
  --no-same-owner --no-same-permissions
sudo chown -R root:root -- "$stage"
sudo find "$stage" -mindepth 0 -type d -exec chmod 0755 -- {} +

installer="$stage/install.sh"
if ! sudo test -f "$installer"; then
  die "The verified archive does not contain install.sh at its root."
fi
if sudo test -L "$installer"; then
  die "install.sh in the verified stage is unexpectedly a symbolic link."
fi

log "Handing off to the verified install.sh"
sudo env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  WINSVPN_VERIFIED_STAGE=1 "$installer"
# Post-install verification: prove that every bundled runtime the Linux data
# path depends on (awg, awg-quick, amneziawg-go, xray, the Winn Protocol v3
# engine winn-datapath, and winsvpn-bypass-bpf) resolves from the installed
# prefix. install.sh performs its own copy of this check before it returns;
# this explicit call is what makes "--self-test" a first-class property of the
# top-level installer, so a clean-prefix install whose bundled tools were lost
# or made unexecutable in the copy-to-$TARGET step fails HERE, not on the
# user's first launch. The repeated check uses the same source of truth and
# is intentionally not the only one -- see install.sh's post-install gate.
log "Verifying bundled tools resolve from the installed prefix"
sudo env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  "$installer" --self-test /opt/wins-vpn
log "Verifying native-messaging host registration including Microsoft Edge"
sudo env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  "$installer" --verify-native-host-delivery
edge_json="${NATIVE_HOST_EDGE_MANIFEST_DIR}/${NATIVE_HOST_NAME}.json"
[[ -f "$edge_json" && ! -L "$edge_json" ]] || \
  die "Edge native-messaging host was not delivered to ${NATIVE_HOST_EDGE_MANIFEST_DIR}."
