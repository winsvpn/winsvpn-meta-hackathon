#!/usr/bin/env bash
# Operator producer for the consumer-ready macOS native-messaging companion PKG.
#
# This is not a consumer installer. tools/native_messaging/install_macos_native_host.sh
# remains a repository helper and depends on Python. The Mac App Store app cannot
# deliver an out-of-sandbox Chrome, Edge, or Firefox native host. The consumer
# artifact is a Developer ID Installer product PKG that installs a prebuilt
# universal Developer ID Application-signed wins_bridge_host plus exact manifests.
# Owner ruling 2026-10-16: release lines 1.0.16 and 1.0.17 ship an arm64-only (Apple
# silicon) host; the verifier accepts that only for those lines and the Distribution
# then restricts hostArchitectures to arm64 so Intel Macs refuse the install.
#
# This producer never invents a Chrome or Edge store id or a signing identity.
# Missing Developer ID Installer team 5YT8H4U72M, Chrome id, Edge id,
# Application signature, notarization credentials, or source-closure receipt
# inputs stay owner-blocked and do not emit a PKG. Chrome and Edge ids must be
# distinct owner-issued identities. The final product PKG must be signed,
# notarized, and stapled before the verifier prints PASS.
set -euo pipefail
umask 077

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")"
TOOLS_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd -P)"
ROOT="$(cd "${TOOLS_DIR}/.." && pwd -P)"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
LAYOUT="${ROOT}/tools/native_messaging/native_host_layout.py"
VERIFIER="${ROOT}/tools/verify_macos_native_host_companion_pkg.py"
FIREFOX_FRAGMENT="${ROOT}/extension/manifest/firefox.jsonc"
TEAM_ID="5YT8H4U72M"
PACKAGE_IDENTIFIER="org.winsvpn.bridge.nativemessaginghost"
HOST_NAME="org.winsvpn.bridge"
FIREFOX_ID="companion@winsvpn.org"
INSTALLED_HOST_PATH="/Library/Application Support/Win's VPN/NativeMessagingHost/wins_bridge_host"
OWNER_BLOCK_EXIT=78
CHECK_ONLY=0
HOST=""
OUTPUT=""

usage() {
  cat >&2 <<'USAGE'
usage: build_macos_native_host_companion_pkg.sh --host PATH --output PATH [--check-only]

  Packages a prebuilt universal x86_64+arm64 (arm64 only for release lines
  1.0.16 and 1.0.17, owner ruling 2026-10-16) Developer ID Application-signed
  wins_bridge_host as a consumer companion PKG. Sign the built host with
  tools/native_messaging/sign_macos_native_host.sh first. Does not compile the host, does
  not invent Chrome, Edge, or certificate identities, and does not write a PKG
  until every owner gate passes. --check-only stops after the owner gates.
USAGE
  exit 2
}

die() {
  printf 'macos native-host companion PKG: %s\n' "$*" >&2
  exit 1
}

owner_block() {
  printf 'macos native-host companion PKG owner gate: %s\n' "$*" >&2
  exit "${OWNER_BLOCK_EXIT}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --check-only) CHECK_ONLY=1; shift ;;
    -h|--help) usage ;;
    -*) usage ;;
    *) usage ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || die "this producer is macOS-only"
[[ -n "${HOST}" && -n "${OUTPUT}" ]] || usage
[[ "${HOST}" == /* ]] || die "--host must be an absolute path"
[[ "${OUTPUT}" == /* ]] || die "--output must be an absolute path"
[[ "${OUTPUT}" == *.pkg ]] || die "--output must be a .pkg path"
[[ -x "${PYTHON_BIN}" ]] || die "python3 is required on the operator machine at ${PYTHON_BIN}"
[[ -f "${LAYOUT}" && -f "${VERIFIER}" ]] || die "native-host layout or companion verifier is missing"
[[ -f "${FIREFOX_FRAGMENT}" ]] || die "Firefox extension fragment is missing"

case "${OUTPUT}" in
  "${ROOT}"|"${ROOT}"/*)
    die "refusing to write a companion PKG into the repository"
    ;;
esac
[[ ! -e "${OUTPUT}" && ! -L "${OUTPUT}" ]] || die "refusing to overwrite existing output ${OUTPUT}"

[[ -f "${HOST}" && ! -L "${HOST}" && -x "${HOST}" ]] || {
  owner_block "prebuilt wins_bridge_host is missing, symbolic, or not executable"
}

ARCHS="$(/usr/bin/lipo -archs "${HOST}" 2>/dev/null || true)"
case " ${ARCHS} " in
  *" arm64 "*) ;;
  *) owner_block "prebuilt host is missing the arm64 Mach-O slice" ;;
esac
# The x86_64 slice is required for every release line except 1.0.16 and 1.0.17 (owner
# ruling 2026-10-16); the verifier's host-facts pre-flight below enforces it.

CODESIGN_OUT="$(/usr/bin/codesign -d --verbose=4 -- "${HOST}" 2>&1)" || {
  owner_block "Developer ID Application signature is missing on the prebuilt host"
}
printf '%s\n' "${CODESIGN_OUT}" | /usr/bin/grep -q "Authority=Apple Distribution:" && {
  owner_block "App Store signing cannot cover a native-messaging host outside the sandboxed app"
}
printf '%s\n' "${CODESIGN_OUT}" | /usr/bin/grep -qi "3rd Party Mac Developer" && {
  owner_block "App Store signing cannot cover a native-messaging host outside the sandboxed app"
}
printf '%s\n' "${CODESIGN_OUT}" | /usr/bin/grep -q "Authority=Developer ID Application:" || {
  owner_block "prebuilt host signer must be Developer ID Application for team ${TEAM_ID}"
}
printf '%s\n' "${CODESIGN_OUT}" | /usr/bin/grep -q "TeamIdentifier=${TEAM_ID}" || {
  owner_block "prebuilt host team identity is not release-valid"
}
printf '%s\n' "${CODESIGN_OUT}" | /usr/bin/grep -q "Signature=adhoc" && {
  owner_block "prebuilt host Application signature is adhoc, not Developer ID Application"
}
printf '%s\n' "${CODESIGN_OUT}" | /usr/bin/grep -q "(runtime)" || {
  owner_block "prebuilt host Application signature is not notarizable; hardened runtime is missing"
}

/usr/bin/grep -q "\"id\": \"${FIREFOX_ID}\"" "${FIREFOX_FRAGMENT}" || {
  owner_block "Firefox extension id is not the reviewed companion@winsvpn.org identity"
}

CHROME_ID=""
EDGE_ID=""
SNAPSHOT=""
SNAPSHOT_STATUS=0
set +e
SNAPSHOT="$(
  "${PYTHON_BIN}" - "${LAYOUT}" <<'PY'
import sys
from pathlib import Path

layout_path = Path(sys.argv[1])
sys.path.insert(0, str(layout_path.parent))
import native_host_layout as layout
import render_host_manifest as renderer

try:
    ids = renderer.owner_issued_chromium_ids()
except renderer.OwnerIdentityBlocked as error:
    print(f"native-host registration owner gate: {error}", file=sys.stderr)
    raise SystemExit(layout.MISSING_STORE_ID_EXIT)
except (OSError, ValueError) as error:
    print(f"native-host registration refused: {error}", file=sys.stderr)
    raise SystemExit(1)
chrome = ids.get("chrome") or ""
edge = ids.get("edge") or ""
if not chrome or not edge:
    print(
        "native-host registration owner gate: Chrome and Edge store-listing "
        "ids are missing; refusing to invent one",
        file=sys.stderr,
    )
    raise SystemExit(layout.MISSING_STORE_ID_EXIT)
if chrome == edge:
    print(
        "native-host registration refused: Chrome and Edge store-listing ids "
        "must be distinct",
        file=sys.stderr,
    )
    raise SystemExit(1)
print(f"chrome {chrome}")
print(f"edge {edge}")
PY
)"
SNAPSHOT_STATUS=$?
set -e
if [[ "${SNAPSHOT_STATUS}" -eq "${OWNER_BLOCK_EXIT}" ]]; then
  owner_block "Chrome and Edge store-listing ids are missing; refusing to invent one"
fi
if [[ "${SNAPSHOT_STATUS}" -ne 0 ]]; then
  die "owner identity snapshot failed (${SNAPSHOT_STATUS})"
fi
while IFS= read -r line; do
  case "${line}" in
    "chrome "*) CHROME_ID="${line#chrome }" ;;
    "edge "*) EDGE_ID="${line#edge }" ;;
  esac
done <<< "${SNAPSHOT}"
CHROME_ID="$(printf '%s' "${CHROME_ID}" | tr -d '\r\n')"
EDGE_ID="$(printf '%s' "${EDGE_ID}" | tr -d '\r\n')"
if [[ -z "${CHROME_ID}" || -z "${EDGE_ID}" ]]; then
  owner_block "Chrome and Edge store-listing ids are missing; refusing to invent one"
fi
[[ "${CHROME_ID}" =~ ^[a-p]{32}$ ]] || {
  owner_block "Chrome store-listing id is not a reviewed 32-letter identity"
}
[[ "${EDGE_ID}" =~ ^[a-p]{32}$ ]] || {
  owner_block "Edge store-listing id is not a reviewed 32-letter identity"
}
if [[ "${CHROME_ID}" == "${EDGE_ID}" ]]; then
  owner_block "Chrome and Edge store-listing ids must be distinct; refusing to reuse one identity"
fi

INSTALLER_IDENTITY="$(
  /usr/bin/security find-identity -v -p basic 2>/dev/null | /usr/bin/awk -v team="${TEAM_ID}" '
    match($0, /"[^"]+"/) {
      identity = substr($0, RSTART + 1, RLENGTH - 2)
      prefix = "Developer ID Installer:"
      suffix = "(" team ")"
      if (index(identity, prefix) == 1 && index(identity, suffix) > 0) {
        print identity
        exit
      }
    }
  '
)"
[[ -n "${INSTALLER_IDENTITY}" ]] || {
  owner_block "Developer ID Installer identity for team ${TEAM_ID} is missing"
}

if [[ -z "${NOTARYTOOL_KEYCHAIN_PROFILE:-}" ]]; then
  if [[ -z "${APPLE_API_KEY:-}" || -z "${APPLE_API_KEY_ID:-}" || -z "${APPLE_API_ISSUER:-}" ]]; then
    owner_block "notarization credentials are missing; refusing to emit an unstapled PKG"
  fi
fi

PACKAGE_VERSION="$(
  /usr/bin/awk '
    /^version:[[:space:]]*/ {
      raw = $2
      split(raw, parts, "+")
      print parts[1]
      exit
    }
  ' "${ROOT}/pubspec.yaml"
)"
[[ "${PACKAGE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  die "package version could not be read from pubspec.yaml"
}

# The packaged host must be built from the reviewed native-host sources: the
# same closure tools/apple_cross_store_artifact_gate.py pins as
# MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256. Drift is a refusal, never a re-pin.
NATIVE_HOST_SOURCE_DIGEST="$(
  "${PYTHON_BIN}" - "${TOOLS_DIR}" <<'PY'
import sys

sys.path.insert(0, sys.argv[1])
import apple_cross_store_artifact_gate as gate

try:
    print(gate.bind_macos_native_host_source_freeze())
except gate.AppleArtifactGateError as error:
    print(f"macos native-host companion PKG: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
)" || die "native-host source closure does not match the reviewed macOS pin"
[[ "${NATIVE_HOST_SOURCE_DIGEST}" =~ ^[0-9a-f]{64}$ ]] || {
  die "native-host source closure digest is not exact"
}
printf 'macos native-host companion PKG: native-host source closure %s\n' "${NATIVE_HOST_SOURCE_DIGEST}"

HOST_FACTS=""
HOST_FACTS_STATUS=0
set +e
HOST_FACTS="$("${PYTHON_BIN}" "${VERIFIER}" host-facts --host "${HOST}" --package-version "${PACKAGE_VERSION}")"
HOST_FACTS_STATUS=$?
set -e
if [[ "${HOST_FACTS_STATUS}" -ne 0 ]]; then
  owner_block "prebuilt host architecture, minimum macOS, signature, or entitlements are not release-valid (${HOST_FACTS_STATUS})"
fi
HOST_ARCHITECTURES=""
HOST_MINIMUM_MACOS=""
while IFS= read -r line; do
  case "${line}" in
    "host_architectures "*) HOST_ARCHITECTURES="${line#host_architectures }" ;;
    "minimum_macos "*) HOST_MINIMUM_MACOS="${line#minimum_macos }" ;;
  esac
done <<< "${HOST_FACTS}"
case "${HOST_ARCHITECTURES}" in
  arm64|arm64,x86_64) ;;
  *) owner_block "prebuilt host architecture set is not release-valid" ;;
esac
[[ "${HOST_MINIMUM_MACOS}" =~ ^[0-9]+(\.[0-9]+){1,2}$ ]] || {
  owner_block "prebuilt host minimum macOS is not exact"
}

write_preinstall() {
  cat > "$1" <<'PREINSTALL'
#!/bin/sh
set -eu
# Static POSIX preinstall. No Python and no repository path on the consumer.
# Snapshot live files into rollback before payload drop. Fail before mutation
# of live Chrome/Edge/Firefox registration if the snapshot cannot be taken.

fail() {
  printf 'winsvpn native-host companion: %s\n' "$*" >&2
  exit 1
}

VOLUME="${3:-}"
[ -n "${VOLUME}" ] || fail "install volume is missing"
case "${VOLUME}" in
  /) PREFIX="" ;;
  /*)
    case "${VOLUME}" in
      */) fail "install volume must not have a trailing slash" ;;
    esac
    PREFIX="${VOLUME}"
    ;;
  *) fail "install volume must be an absolute path" ;;
esac

if [ "${VOLUME}" = "/" ] && [ "$(/usr/bin/id -u)" != "0" ]; then
  fail "system native-host install requires root"
fi

EXPECTED_HOST="/Library/Application Support/Win's VPN/NativeMessagingHost/wins_bridge_host"
EXPECTED_FIREFOX="/Library/Application Support/Mozilla/NativeMessagingHosts/org.winsvpn.bridge.json"
EXPECTED_CHROME="/Library/Google/Chrome/NativeMessagingHosts/org.winsvpn.bridge.json"
EXPECTED_EDGE="/Library/Microsoft/Edge/NativeMessagingHosts/org.winsvpn.bridge.json"
EXPECTED_RECEIPT="/Library/Application Support/Win's VPN/NativeMessagingHost/macos-native-host-companion-receipt.json"
EXPECTED_UNINSTALL="/Library/Application Support/Win's VPN/NativeMessagingHost/uninstall-winsvpn-native-host.sh"

HOST_PATH="${PREFIX}${EXPECTED_HOST}"
FIREFOX_PATH="${PREFIX}${EXPECTED_FIREFOX}"
CHROME_PATH="${PREFIX}${EXPECTED_CHROME}"
EDGE_PATH="${PREFIX}${EXPECTED_EDGE}"
RECEIPT_PATH="${PREFIX}${EXPECTED_RECEIPT}"
UNINSTALL_PATH="${PREFIX}${EXPECTED_UNINSTALL}"
HOST_DIR="$(/usr/bin/dirname "${HOST_PATH}")"
ROLLBACK="${HOST_DIR}/.winsvpn-native-host-rollback"

refuse_writable() {
  path="$1"
  [ -e "${path}" ] || return 0
  if [ -n "$(/usr/bin/find "${path}" -maxdepth 0 \( -perm -002 -o -perm -020 \) -print)" ]; then
    fail "refusing group/other-writable path ${path}"
  fi
}

ensure_protected_dir() {
  dir="$1"
  if [ -L "${dir}" ]; then
    fail "refusing symlink directory ${dir}"
  fi
  if [ ! -d "${dir}" ]; then
    parent="$(/usr/bin/dirname "${dir}")"
    if [ -L "${parent}" ]; then
      fail "refusing symlink parent ${parent}"
    fi
    if [ ! -d "${parent}" ]; then
      ensure_protected_dir "${parent}"
    fi
    if [ -L "${parent}" ]; then
      fail "refusing symlink parent ${parent}"
    fi
    [ -d "${parent}" ] || fail "required parent is missing: ${parent}"
    /bin/mkdir -m 0755 "${dir}" || fail "cannot create ${dir}"
    if [ "$(/usr/bin/id -u)" = "0" ]; then
      /usr/sbin/chown root:wheel "${dir}" || fail "cannot chown ${dir}"
    fi
    if [ -L "${parent}" ]; then
      fail "refusing symlink parent ${parent}"
    fi
  fi
  [ -d "${dir}" ] && [ ! -L "${dir}" ] || fail "path is not a directory ${dir}"
  parent="$(/usr/bin/dirname "${dir}")"
  if [ "${parent}" != "${dir}" ] && [ -L "${parent}" ]; then
    fail "refusing symlink parent ${parent}"
  fi
  refuse_writable "${dir}"
}

require_existing_protected() {
  dir="$1"
  [ -d "${dir}" ] || fail "required directory is missing: ${dir}"
  [ ! -L "${dir}" ] || fail "refusing symlink directory ${dir}"
  refuse_writable "${dir}"
}

backup_if_present() {
  source="$1"
  name="$2"
  if [ -L "${source}" ]; then
    fail "refusing to replace symlink ${source}"
  fi
  if [ -e "${source}" ]; then
    [ -f "${source}" ] || fail "refusing to replace non-file ${source}"
    /bin/cp -p "${source}" "${ROLLBACK}/${name}" || fail "rollback copy failed for ${source}"
  fi
}

require_existing_protected "${PREFIX}/Library"
ensure_protected_dir "${PREFIX}/Library/Application Support"
ensure_protected_dir "${PREFIX}/Library/Application Support/Win's VPN"
ensure_protected_dir "${HOST_DIR}"
ensure_protected_dir "${PREFIX}/Library/Application Support/Mozilla"
ensure_protected_dir "$(/usr/bin/dirname "${FIREFOX_PATH}")"
ensure_protected_dir "${PREFIX}/Library/Google"
ensure_protected_dir "${PREFIX}/Library/Google/Chrome"
ensure_protected_dir "$(/usr/bin/dirname "${CHROME_PATH}")"
ensure_protected_dir "${PREFIX}/Library/Microsoft"
ensure_protected_dir "${PREFIX}/Library/Microsoft/Edge"
ensure_protected_dir "$(/usr/bin/dirname "${EDGE_PATH}")"

if [ -e "${ROLLBACK}" ] || [ -L "${ROLLBACK}" ]; then
  /bin/rm -rf "${ROLLBACK}" || fail "cannot clear leftover rollback directory"
fi
/bin/mkdir -m 0700 "${ROLLBACK}" || fail "cannot create rollback directory"
if [ "$(/usr/bin/id -u)" = "0" ]; then
  /usr/sbin/chown root:wheel "${ROLLBACK}" || fail "cannot chown rollback directory"
fi

backup_if_present "${HOST_PATH}" host.bin
backup_if_present "${FIREFOX_PATH}" firefox.json
backup_if_present "${CHROME_PATH}" chrome.json
backup_if_present "${EDGE_PATH}" edge.json
backup_if_present "${RECEIPT_PATH}" receipt.json
backup_if_present "${UNINSTALL_PATH}" uninstall.sh
exit 0
PREINSTALL
  /bin/chmod 0755 "$1"
}

write_postinstall() {
  cat > "$1" <<'POSTINSTALL'
#!/bin/sh
set -eu
# Static POSIX postinstall. No Python and no repository path on the consumer.
# Verify the incoming payload and fail before mutation of live files if it is
# incomplete. Journal the per-target mutation marker durably before any live
# replace. Bind the destination parent descriptor-first, stage into an
# exclusive regular file in that held directory, write payload bytes through
# the held descriptor, and replace with /bin/mv -h so a dest symlink-to-directory
# is never followed. restore_rollback on any later failure and keep restoring
# later leaves after an earlier restore fails.

fail() {
  printf 'winsvpn native-host companion: %s\n' "$*" >&2
  exit 1
}

VOLUME="${3:-}"
[ -n "${VOLUME}" ] || fail "install volume is missing"
case "${VOLUME}" in
  /) PREFIX="" ;;
  /*)
    case "${VOLUME}" in
      */) fail "install volume must not have a trailing slash" ;;
    esac
    PREFIX="${VOLUME}"
    ;;
  *) fail "install volume must be an absolute path" ;;
esac

if [ "${VOLUME}" = "/" ] && [ "$(/usr/bin/id -u)" != "0" ]; then
  fail "system native-host install requires root"
fi

EXPECTED_HOST="/Library/Application Support/Win's VPN/NativeMessagingHost/wins_bridge_host"
EXPECTED_FIREFOX="/Library/Application Support/Mozilla/NativeMessagingHosts/org.winsvpn.bridge.json"
EXPECTED_CHROME="/Library/Google/Chrome/NativeMessagingHosts/org.winsvpn.bridge.json"
EXPECTED_EDGE="/Library/Microsoft/Edge/NativeMessagingHosts/org.winsvpn.bridge.json"
EXPECTED_RECEIPT="/Library/Application Support/Win's VPN/NativeMessagingHost/macos-native-host-companion-receipt.json"
EXPECTED_UNINSTALL="/Library/Application Support/Win's VPN/NativeMessagingHost/uninstall-winsvpn-native-host.sh"
EXPECTED_FIREFOX_ID="companion@winsvpn.org"
EXPECTED_IDENTITY="/Library/Application Support/wins_vpn/browser_bridge.identity"

HOST_PATH="${PREFIX}${EXPECTED_HOST}"
FIREFOX_PATH="${PREFIX}${EXPECTED_FIREFOX}"
CHROME_PATH="${PREFIX}${EXPECTED_CHROME}"
EDGE_PATH="${PREFIX}${EXPECTED_EDGE}"
RECEIPT_PATH="${PREFIX}${EXPECTED_RECEIPT}"
UNINSTALL_PATH="${PREFIX}${EXPECTED_UNINSTALL}"
IDENTITY_PATH="${PREFIX}${EXPECTED_IDENTITY}"
HOST_DIR="$(/usr/bin/dirname "${HOST_PATH}")"
INCOMING="${HOST_DIR}/Incoming"
ROLLBACK="${HOST_DIR}/.winsvpn-native-host-rollback"

refuse_writable() {
  path="$1"
  [ -e "${path}" ] || return 0
  if [ -n "$(/usr/bin/find "${path}" -maxdepth 0 \( -perm -002 -o -perm -020 \) -print)" ]; then
    fail "refusing group/other-writable path ${path}"
  fi
}

ensure_protected_dir() {
  dir="$1"
  if [ -L "${dir}" ]; then
    fail "refusing symlink directory ${dir}"
  fi
  if [ ! -d "${dir}" ]; then
    parent="$(/usr/bin/dirname "${dir}")"
    if [ -L "${parent}" ]; then
      fail "refusing symlink parent ${parent}"
    fi
    if [ ! -d "${parent}" ]; then
      ensure_protected_dir "${parent}"
    fi
    if [ -L "${parent}" ]; then
      fail "refusing symlink parent ${parent}"
    fi
    [ -d "${parent}" ] || fail "required parent is missing: ${parent}"
    /bin/mkdir -m 0755 "${dir}" || fail "cannot create ${dir}"
    if [ "$(/usr/bin/id -u)" = "0" ]; then
      /usr/sbin/chown root:wheel "${dir}" || fail "cannot chown ${dir}"
    fi
    if [ -L "${parent}" ]; then
      fail "refusing symlink parent ${parent}"
    fi
  fi
  [ -d "${dir}" ] && [ ! -L "${dir}" ] || fail "path is not a directory ${dir}"
  parent="$(/usr/bin/dirname "${dir}")"
  if [ "${parent}" != "${dir}" ] && [ -L "${parent}" ]; then
    fail "refusing symlink parent ${parent}"
  fi
  refuse_writable "${dir}"
}

json_flatten() {
  /usr/bin/awk '
    BEGIN { max_bytes = 1048576 }
    {
      if (NR > 1) data = data "\n"
      data = data $0
    }
    END {
      n = length(data)
      if (n < 1) fail("JSON is empty")
      if (n > max_bytes) fail("JSON exceeds the reviewed size ceiling")
      pos = 1
      skip_ws()
      if (cur() != "{") fail("JSON must be one object")
      parse_object("")
      skip_ws()
      if (pos <= n) fail("trailing JSON data")
    }
    function fail(msg) {
      printf "%s\n", msg > "/dev/stderr"
      exit 1
    }
    function cur() {
      if (pos > n) return ""
      return substr(data, pos, 1)
    }
    function skip_ws(   c) {
      while (pos <= n) {
        c = substr(data, pos, 1)
        if (c == " " || c == "\t" || c == "\n" || c == "\r") {
          pos++
          continue
        }
        return
      }
    }
    function hexval(h,   i, c, t, v, total) {
      total = 0
      for (i = 1; i <= 4; i++) {
        c = substr(h, i, 1)
        t = index("0123456789abcdef", c)
        if (t == 0) t = index("0123456789ABCDEF", c)
        if (t == 0) fail("bad unicode escape")
        v = (t - 1) % 16
        total = total * 16 + v
      }
      return total
    }
    function parse_string(   c, out, hex, code) {
      if (cur() != "\"") fail("expected string")
      pos++
      out = ""
      while (pos <= n) {
        c = substr(data, pos, 1)
        pos++
        if (c == "\"") return out
        if (c == "\\") {
          if (pos > n) fail("unterminated escape")
          c = substr(data, pos, 1)
          pos++
          if (c == "\"" || c == "\\" || c == "/") out = out c
          else if (c == "u") {
            hex = substr(data, pos, 4)
            if (length(hex) < 4) fail("bad unicode escape")
            pos += 4
            code = hexval(hex)
            if (code < 32 || code > 126) fail("unicode escape is not ASCII")
            out = out sprintf("%c", code)
          } else fail("string escape is not allowed")
          continue
        }
        if (c < " ") fail("control character in string")
        out = out c
      }
      fail("unterminated string")
    }
    function parse_number(   start, c) {
      start = pos
      if (cur() == "-") pos++
      c = cur()
      if (c < "0" || c > "9") fail("bad number")
      if (c == "0") pos++
      else while (cur() >= "0" && cur() <= "9") pos++
      c = cur()
      if (c == "." || c == "e" || c == "E") fail("non-integer number")
      return substr(data, start, pos - start)
    }
    function emit(path, type, value) {
      printf "%s\t%s\t%s\n", path, type, value
    }
    function child_path(prefix, key) {
      if (prefix == "") return key
      return prefix "." key
    }
    function parse_object(prefix,   key, seenkey) {
      if (cur() != "{") fail("expected object")
      pos++
      skip_ws()
      if (prefix != "") emit(prefix, "object", "")
      if (cur() == "}") { pos++; return }
      while (1) {
        skip_ws()
        key = parse_string()
        if (key == "") fail("empty JSON key")
        seenkey = prefix "\t" key
        if (seenkey in seen) fail("duplicate JSON key")
        seen[seenkey] = 1
        skip_ws()
        if (cur() != ":") fail("expected colon")
        pos++
        parse_value(child_path(prefix, key))
        skip_ws()
        if (cur() == "}") { pos++; return }
        if (cur() != ",") fail("expected comma or end of object")
        pos++
        skip_ws()
        if (cur() == "}") fail("trailing comma")
      }
    }
    function parse_array(prefix,   idx) {
      if (cur() != "[") fail("expected array")
      pos++
      skip_ws()
      emit(prefix, "array", "")
      idx = 0
      if (cur() == "]") {
        pos++
        emit(prefix ".length", "number", "0")
        return
      }
      while (1) {
        parse_value(prefix "." idx)
        idx++
        skip_ws()
        if (cur() == "]") {
          pos++
          emit(prefix ".length", "number", idx "")
          return
        }
        if (cur() != ",") fail("expected comma or end of array")
        pos++
        skip_ws()
        if (cur() == "]") fail("trailing comma")
      }
    }
    function parse_value(prefix,   c, s, num) {
      skip_ws()
      c = cur()
      if (c == "{") { parse_object(prefix); return }
      if (c == "[") { parse_array(prefix); return }
      if (c == "\"") {
        s = parse_string()
        emit(prefix, "string", s)
        return
      }
      if (c == "-" || (c >= "0" && c <= "9")) {
        num = parse_number()
        emit(prefix, "number", num)
        return
      }
      fail("JSON value is not exact")
    }
  ' "$1"
}

json_lookup() {
  flat="$1"
  key="$2"
  printf '%s\n' "${flat}" | /usr/bin/awk -v want="${key}" 'BEGIN { FS = "\t" }
    $1 == want {
      if (found) exit 1
      found = 1
      print $2 "\t" $3
    }
    END { if (!found) exit 2 }
  '
}

json_has() {
  flat="$1"
  key="$2"
  printf '%s\n' "${flat}" | /usr/bin/awk -v want="${key}" 'BEGIN { FS = "\t" }
    $1 == want { found=1; exit 0 }
    END { exit found ? 0 : 1 }
  '
}

json_string() {
  flat="$1"
  key="$2"
  got="$(json_lookup "${flat}" "${key}")" || return 1
  type="${got%%	*}"
  value="${got#*	}"
  [ "${type}" = "string" ] || return 1
  printf '%s\n' "${value}"
}

json_number() {
  flat="$1"
  key="$2"
  got="$(json_lookup "${flat}" "${key}")" || return 1
  type="${got%%	*}"
  value="${got#*	}"
  [ "${type}" = "number" ] || return 1
  printf '%s\n' "${value}"
}

json_require_keys() {
  flat="$1"
  allowed="$2"
  printf '%s\n' "${flat}" | /usr/bin/awk -v allowed="${allowed}" '
    BEGIN { FS = "\t" }
    BEGIN {
      n = split(allowed, items, " ")
      for (i = 1; i <= n; i++) {
        ok[items[i]] = 1
        need[items[i]] = 1
      }
    }
    {
      if (!($1 in ok)) exit 1
      seen[$1] = 1
    }
    END {
      for (k in need) if (!(k in seen)) exit 1
    }
  '
}

bind_dest_parent() {
  bdp_dir="$1"
  bdp_start="/"
  bdp_rel="${bdp_dir#/}"
  if [ -n "${PREFIX}" ]; then
    case "${bdp_dir}" in
      "${PREFIX}"/*)
        bdp_start="${PREFIX}"
        bdp_rel="${bdp_dir#"${PREFIX}"/}"
        ;;
      *)
        printf 'winsvpn native-host companion: destination parent is outside the install volume\n' >&2
        return 1
        ;;
    esac
  fi
  cd "${bdp_start}" || return 1
  if [ "${bdp_start}" != "/" ] && [ -L "${bdp_start}" ]; then
    printf 'winsvpn native-host companion: refusing symlink parent %s\n' "${bdp_start}" >&2
    return 1
  fi
  bdp_rest="${bdp_rel}"
  while [ -n "${bdp_rest}" ]; do
    bdp_part="${bdp_rest%%/*}"
    if [ "${bdp_part}" = "${bdp_rest}" ]; then
      bdp_rest=""
    else
      bdp_rest="${bdp_rest#*/}"
    fi
    [ -n "${bdp_part}" ] || continue
    if [ -L "${bdp_part}" ]; then
      printf 'winsvpn native-host companion: refusing symlink parent %s\n' "${bdp_part}" >&2
      return 1
    fi
    if [ ! -d "${bdp_part}" ]; then
      printf 'winsvpn native-host companion: required parent is missing: %s\n' "${bdp_part}" >&2
      return 1
    fi
    bdp_id="$(/usr/bin/stat -f '%d:%i' "${bdp_part}")" || return 1
    cd "${bdp_part}" || return 1
    bdp_now="$(/usr/bin/stat -f '%d:%i' .)" || return 1
    if [ "${bdp_now}" != "${bdp_id}" ]; then
      printf 'winsvpn native-host companion: destination parent changed while it was bound\n' >&2
      return 1
    fi
  done
  if [ ! -d . ]; then
    printf 'winsvpn native-host companion: refusing symlink parent\n' >&2
    return 1
  fi
  return 0
}

refuse_held_leaf() {
  leaf="$1"
  if [ -L "${leaf}" ]; then
    printf 'winsvpn native-host companion: refusing symlink native-host path %s\n' "${leaf}" >&2
    return 1
  fi
  if [ ! -e "${leaf}" ]; then
    return 0
  fi
  if [ -p "${leaf}" ] || [ -S "${leaf}" ] || [ -b "${leaf}" ] || [ -c "${leaf}" ] || [ -d "${leaf}" ]; then
    printf 'winsvpn native-host companion: refusing special native-host path %s\n' "${leaf}" >&2
    return 1
  fi
  if [ ! -f "${leaf}" ]; then
    printf 'winsvpn native-host companion: refusing special native-host path %s\n' "${leaf}" >&2
    return 1
  fi
  nlink="$(/usr/bin/stat -f %l "${leaf}")" || return 1
  if [ "${nlink}" != "1" ]; then
    printf 'winsvpn native-host companion: refusing hardlinked native-host path %s\n' "${leaf}" >&2
    return 1
  fi
  return 0
}

bind_rollback_dir() {
  rollback_parent="$(/usr/bin/dirname "${ROLLBACK}")"
  rollback_leaf="$(/usr/bin/basename "${ROLLBACK}")"
  case "${rollback_leaf}" in
    ""|"."|".."*|*"/"*) return 1 ;;
  esac
  bind_dest_parent "${rollback_parent}" || return 1
  if [ -L "${rollback_leaf}" ]; then
    printf 'winsvpn native-host companion: refusing symlink parent %s\n' "${ROLLBACK}" >&2
    return 1
  fi
  if [ ! -d "${rollback_leaf}" ]; then
    printf 'winsvpn native-host companion: rollback directory is missing\n' >&2
    return 1
  fi
  id="$(/usr/bin/stat -f '%d:%i' "${rollback_leaf}")" || return 1
  cd "${rollback_leaf}" || return 1
  now="$(/usr/bin/stat -f '%d:%i' .)" || return 1
  if [ "${now}" != "${id}" ]; then
    printf 'winsvpn native-host companion: destination parent changed while it was bound\n' >&2
    return 1
  fi
  return 0
}

drop_held_stage() {
  exec 3>&- || true
  if [ -n "${stage_tmp}" ]; then
    /bin/rm -f -- "${stage_tmp}"
    stage_tmp=""
  fi
}

held_stage_replace() {
  leaf="$1"
  mode="$2"
  case "${leaf}" in
    ""|"."|".."*|*"/"*) return 1 ;;
  esac
  stage_tmp=""
  parent_id="$(/usr/bin/stat -f '%d:%i' .)" || return 1
  stage_tmp="$(/usr/bin/mktemp "./.winsvpn-stage.XXXXXX")" || return 1
  if ! exec 3<>"${stage_tmp}"; then
    /bin/rm -f -- "${stage_tmp}"
    stage_tmp=""
    return 1
  fi
  if [ -L "${stage_tmp}" ]; then
    drop_held_stage
    printf 'winsvpn native-host companion: refusing special native-host temp\n' >&2
    return 1
  fi
  path_ino="$(/usr/bin/stat -f %i "${stage_tmp}")" || {
    drop_held_stage
    return 1
  }
  fd_ino="$(/usr/bin/stat -f %i /dev/fd/3)" || {
    drop_held_stage
    return 1
  }
  fd_ht="$(/usr/bin/stat -f %HT /dev/fd/3)" || {
    drop_held_stage
    return 1
  }
  if [ "${fd_ht}" != "Regular File" ] || [ "${path_ino}" != "${fd_ino}" ]; then
    drop_held_stage
    printf 'winsvpn native-host companion: refusing special native-host temp\n' >&2
    return 1
  fi
  orig_nlink="$(/usr/bin/stat -f %l /dev/fd/3)" || {
    drop_held_stage
    return 1
  }
  if [ "${orig_nlink}" != "1" ]; then
    drop_held_stage
    printf 'winsvpn native-host companion: refusing hardlinked native-host temp\n' >&2
    return 1
  fi
  orig_id="${fd_ino}"
  if ! /bin/cat >&3; then
    drop_held_stage
    printf 'winsvpn native-host companion: copy to staging failed\n' >&2
    return 1
  fi
  if [ -L "${stage_tmp}" ]; then
    drop_held_stage
    printf 'winsvpn native-host companion: refusing special native-host temp\n' >&2
    return 1
  fi
  path_ino="$(/usr/bin/stat -f %i "${stage_tmp}")" || {
    drop_held_stage
    return 1
  }
  fd_ino="$(/usr/bin/stat -f %i /dev/fd/3)" || {
    drop_held_stage
    return 1
  }
  fd_ht="$(/usr/bin/stat -f %HT /dev/fd/3)" || {
    drop_held_stage
    return 1
  }
  if [ "${fd_ht}" != "Regular File" ] || [ "${path_ino}" != "${orig_id}" ] || [ "${path_ino}" != "${fd_ino}" ]; then
    drop_held_stage
    printf 'winsvpn native-host companion: refusing special native-host temp\n' >&2
    return 1
  fi
  now_nlink="$(/usr/bin/stat -f %l /dev/fd/3)" || {
    drop_held_stage
    return 1
  }
  if [ "${now_nlink}" != "1" ]; then
    drop_held_stage
    printf 'winsvpn native-host companion: refusing hardlinked native-host temp\n' >&2
    return 1
  fi
  if [ "$(/usr/bin/id -u)" = "0" ]; then
    if ! /usr/sbin/chown root:wheel /dev/fd/3; then
      drop_held_stage
      return 1
    fi
  fi
  if ! /bin/chmod "${mode}" /dev/fd/3; then
    drop_held_stage
    return 1
  fi
  now="$(/usr/bin/stat -f '%d:%i' .)" || {
    drop_held_stage
    return 1
  }
  if [ "${now}" != "${parent_id}" ]; then
    drop_held_stage
    printf 'winsvpn native-host companion: destination parent changed while it was bound\n' >&2
    return 1
  fi
  if ! refuse_held_leaf "${leaf}"; then
    drop_held_stage
    return 1
  fi
  if [ -L "${stage_tmp}" ]; then
    drop_held_stage
    printf 'winsvpn native-host companion: refusing special native-host temp\n' >&2
    return 1
  fi
  path_ino="$(/usr/bin/stat -f %i "${stage_tmp}")" || {
    drop_held_stage
    return 1
  }
  fd_ino="$(/usr/bin/stat -f %i /dev/fd/3)" || {
    drop_held_stage
    return 1
  }
  fd_ht="$(/usr/bin/stat -f %HT /dev/fd/3)" || {
    drop_held_stage
    return 1
  }
  if [ "${fd_ht}" != "Regular File" ] || [ "${path_ino}" != "${orig_id}" ] || [ "${path_ino}" != "${fd_ino}" ]; then
    drop_held_stage
    printf 'winsvpn native-host companion: refusing special native-host temp\n' >&2
    return 1
  fi
  now_nlink="$(/usr/bin/stat -f %l /dev/fd/3)" || {
    drop_held_stage
    return 1
  }
  if [ "${now_nlink}" != "1" ]; then
    drop_held_stage
    printf 'winsvpn native-host companion: refusing hardlinked native-host temp\n' >&2
    return 1
  fi
  if ! /bin/dd if=/dev/null of=/dev/fd/3 conv=notrunc,fsync bs=1 count=0 status=none; then
    drop_held_stage
    printf 'winsvpn native-host companion: cannot durable-sync staging file\n' >&2
    return 1
  fi
  if ! /bin/mv -h -f "${stage_tmp}" "./${leaf}"; then
    drop_held_stage
    printf 'winsvpn native-host companion: atomic replace failed\n' >&2
    return 1
  fi
  stage_tmp=""
  exec 3>&- || true
  return 0
}

mark_mutated() {
  name="$1"
  case "${name}" in
    host.bin|firefox.json|chrome.json|edge.json|receipt.json|uninstall.sh) ;;
    *) fail "cannot record mutation state for ${name}" ;;
  esac
  if ! (
    bind_rollback_dir || exit 1
    if [ -L "./${name}.mutated" ]; then
      printf 'winsvpn native-host companion: refusing symlink native-host path %s\n' "${name}.mutated" >&2
      exit 1
    fi
    if [ -e "./${name}.mutated" ] && [ ! -f "./${name}.mutated" ]; then
      printf 'winsvpn native-host companion: refusing special native-host path %s\n' "${name}.mutated" >&2
      exit 1
    fi
    printf 'mutated\n' | held_stage_replace "${name}.mutated" 0600 || exit 1
    /bin/sync || exit 1
  ); then
    fail "cannot record mutation state for ${name}"
  fi
}

restore_one() {
  dest="$1"
  name="$2"
  restore_dest="$(/usr/bin/dirname "${dest}")"
  restore_leaf="$(/usr/bin/basename "${dest}")"
  case "${restore_leaf}" in
    ""|"."|".."*|*"/"*) return 1 ;;
  esac
  case "${name}" in
    host.bin|firefox.json|chrome.json|edge.json|receipt.json|uninstall.sh) ;;
    *) return 1 ;;
  esac
  check=0
  (
    bind_rollback_dir || exit 1
    if [ ! -f "./${name}.mutated" ] || [ -L "./${name}.mutated" ]; then
      exit 2
    fi
    has_backup=0
    bmode="0644"
    if [ -f "./${name}" ] && [ ! -L "./${name}" ]; then
      bnlink="$(/usr/bin/stat -f %l "./${name}")" || exit 1
      if [ "${bnlink}" != "1" ]; then
        printf 'winsvpn native-host companion: refusing hardlinked native-host path %s\n' "${name}" >&2
        exit 1
      fi
      bmode="$(/usr/bin/stat -f %OLp "./${name}")" || exit 1
      exec 4< "./${name}" || exit 1
      has_backup=1
    fi
    bind_dest_parent "${restore_dest}" || exit 1
    refuse_held_leaf "${restore_leaf}" || exit 1
    if [ "${has_backup}" = "1" ]; then
      held_stage_replace "${restore_leaf}" "${bmode}" <&4 || exit 1
      exec 4>&- || true
      exit 0
    fi
    /bin/rm -f -- "./${restore_leaf}" || exit 1
    exit 0
  ) || check=$?
  if [ "${check}" -eq 2 ]; then
    return 0
  fi
  if [ "${check}" -ne 0 ]; then
    return 1
  fi
  return 0
}

restore_rollback() {
  status=0
  set +e
  restore_one "${HOST_PATH}" host.bin || status=1
  restore_one "${FIREFOX_PATH}" firefox.json || status=1
  restore_one "${CHROME_PATH}" chrome.json || status=1
  restore_one "${EDGE_PATH}" edge.json || status=1
  restore_one "${RECEIPT_PATH}" receipt.json || status=1
  restore_one "${UNINSTALL_PATH}" uninstall.sh || status=1
  set -e
  if [ "${status}" != 0 ]; then
    printf 'winsvpn native-host companion: rollback could not restore every live file\n' >&2
    return 1
  fi
  return 0
}

cleanup_held_names() {
  dest_dir="$1"
  shift
  (
    bind_dest_parent "${dest_dir}" || exit 1
    for leaf in "$@"; do
      case "${leaf}" in
        ""|"."|".."*|*"/"*|*"*"*) exit 1 ;;
      esac
      if [ -L "${leaf}" ]; then
        /bin/rm -f -- "./${leaf}" || exit 1
      elif [ -f "${leaf}" ]; then
        /bin/rm -f -- "./${leaf}" || exit 1
      elif [ -e "${leaf}" ]; then
        printf 'winsvpn native-host companion: refusing special native-host path %s\n' "${leaf}" >&2
        exit 1
      fi
    done
    for staged in ./.winsvpn-stage.*; do
      if [ "${staged}" = "./.winsvpn-stage.*" ] && [ ! -e "${staged}" ] && [ ! -L "${staged}" ]; then
        continue
      fi
      if [ -L "${staged}" ]; then
        /bin/rm -f -- "${staged}" || exit 1
      elif [ -f "${staged}" ]; then
        /bin/rm -f -- "${staged}" || exit 1
      elif [ -e "${staged}" ]; then
        printf 'winsvpn native-host companion: refusing special native-host path %s\n' "${staged}" >&2
        exit 1
      fi
    done
  )
}

cleanup_install_temps() {
  status=0
  cleanup_held_names "${HOST_DIR}" \
    "wins_bridge_host.new" \
    "macos-native-host-companion-receipt.json.new" \
    "uninstall-winsvpn-native-host.sh.new" || status=1
  cleanup_held_names "$(/usr/bin/dirname "${FIREFOX_PATH}")" "org.winsvpn.bridge.json.new" || status=1
  cleanup_held_names "$(/usr/bin/dirname "${CHROME_PATH}")" "org.winsvpn.bridge.json.new" || status=1
  cleanup_held_names "$(/usr/bin/dirname "${EDGE_PATH}")" "org.winsvpn.bridge.json.new" || status=1
  if [ "${status}" != 0 ]; then
    return 1
  fi
  return 0
}

discard_held_dir() {
  dest_dir="$1"
  leaf="$2"
  case "${leaf}" in
    ""|"."|".."*|*"/"*) return 1 ;;
  esac
  (
    bind_dest_parent "${dest_dir}" || exit 1
    if [ -L "${leaf}" ]; then
      printf 'winsvpn native-host companion: refusing symlink directory %s\n' "${leaf}" >&2
      exit 1
    fi
    if [ ! -e "${leaf}" ]; then
      exit 0
    fi
    if [ ! -d "${leaf}" ]; then
      printf 'winsvpn native-host companion: refusing special native-host path %s\n' "${leaf}" >&2
      exit 1
    fi
    /bin/rm -rf -- "./${leaf}" || exit 1
    if [ -e "${leaf}" ] || [ -L "${leaf}" ]; then
      exit 1
    fi
  )
}

verify_incoming() {
  [ -d "${INCOMING}" ] && [ ! -L "${INCOMING}" ] || fail "incoming payload is missing"
  for name in wins_bridge_host firefox.json chrome.json edge.json receipt.json uninstall.sh; do
    path="${INCOMING}/${name}"
    [ ! -L "${path}" ] || fail "incoming ${name} is a symlink"
    [ -f "${path}" ] || fail "incoming ${name} is missing"
    refuse_writable "${path}"
  done
  [ -x "${INCOMING}/wins_bridge_host" ] || fail "incoming host is not executable"
  [ -x "${INCOMING}/uninstall.sh" ] || fail "incoming uninstall helper is not executable"
  is_chromium_id() {
    id="$1"
    [ "${#id}" -eq 32 ] || return 1
    case "${id}" in
      *[!a-p]*) return 1 ;;
    esac
    return 0
  }
  receipt_flat="$(json_flatten "${INCOMING}/receipt.json")" || fail "receipt JSON is not exact"
  firefox_flat="$(json_flatten "${INCOMING}/firefox.json")" || fail "Firefox native-host manifest is not exact"
  chrome_flat="$(json_flatten "${INCOMING}/chrome.json")" || fail "Chrome native-host manifest is not exact"
  edge_flat="$(json_flatten "${INCOMING}/edge.json")" || fail "Edge native-host manifest is not exact"
  RECEIPT_CHROME="$(json_string "${receipt_flat}" chrome_extension_id)" || fail "receipt Chrome id is not exact"
  RECEIPT_EDGE="$(json_string "${receipt_flat}" edge_extension_id)" || fail "receipt Edge id is not exact"
  RECEIPT_FIREFOX="$(json_string "${receipt_flat}" firefox_extension_id)" || fail "receipt Firefox id is not exact"
  is_chromium_id "${RECEIPT_CHROME}" || fail "receipt Chrome id is not exact"
  is_chromium_id "${RECEIPT_EDGE}" || fail "receipt Edge id is not exact"
  [ "${RECEIPT_CHROME}" != "${RECEIPT_EDGE}" ] || fail "Chrome and Edge native-host manifests must be distinct"
  [ "${RECEIPT_FIREFOX}" = "${EXPECTED_FIREFOX_ID}" ] || fail "receipt Firefox id is not exact"
  if /usr/bin/cmp -s "${INCOMING}/chrome.json" "${INCOMING}/edge.json"; then
    fail "Chrome and Edge native-host manifests must be distinct"
  fi
  json_require_keys "${firefox_flat}" "name description path type allowed_extensions allowed_extensions.length allowed_extensions.0" || fail "Firefox native-host manifest is not exact"
  firefox_ext_kind="$(json_lookup "${firefox_flat}" allowed_extensions)" || fail "Firefox native-host manifest is not exact"
  firefox_ext_type="${firefox_ext_kind%%	*}"
  [ "${firefox_ext_type}" = "array" ] || fail "Firefox native-host manifest is not exact"
  firefox_path="$(json_string "${firefox_flat}" path)" || fail "Firefox manifest path is not exact"
  [ "${firefox_path}" = "${EXPECTED_HOST}" ] || fail "Firefox manifest path is not exact"
  firefox_name="$(json_string "${firefox_flat}" name)" || fail "Firefox native-host manifest is not exact"
  [ "${firefox_name}" = "org.winsvpn.bridge" ] || fail "Firefox native-host manifest is not exact"
  firefox_desc="$(json_string "${firefox_flat}" description)" || fail "Firefox native-host manifest is not exact"
  [ "${firefox_desc}" = "Win's VPN browser bridge" ] || fail "Firefox native-host manifest is not exact"
  firefox_type="$(json_string "${firefox_flat}" type)" || fail "Firefox native-host manifest is not exact"
  [ "${firefox_type}" = "stdio" ] || fail "Firefox native-host manifest is not exact"
  firefox_ext_len="$(json_number "${firefox_flat}" allowed_extensions.length)" || fail "Firefox native-host manifest is not exact"
  [ "${firefox_ext_len}" = "1" ] || fail "Firefox native-host manifest is not exact"
  firefox_ext="$(json_string "${firefox_flat}" allowed_extensions.0)" || fail "Firefox extension id is not exact"
  [ "${firefox_ext}" = "${EXPECTED_FIREFOX_ID}" ] || fail "Firefox extension id is not exact"
  json_require_keys "${chrome_flat}" "name description path type allowed_origins allowed_origins.length allowed_origins.0" || fail "Chrome native-host manifest is not exact"
  chrome_origin_kind="$(json_lookup "${chrome_flat}" allowed_origins)" || fail "Chrome native-host manifest is not exact"
  chrome_origin_type="${chrome_origin_kind%%	*}"
  [ "${chrome_origin_type}" = "array" ] || fail "Chrome native-host manifest is not exact"
  chrome_path="$(json_string "${chrome_flat}" path)" || fail "Chrome manifest path is not exact"
  [ "${chrome_path}" = "${EXPECTED_HOST}" ] || fail "Chrome manifest path is not exact"
  chrome_name="$(json_string "${chrome_flat}" name)" || fail "Chrome native-host manifest is not exact"
  [ "${chrome_name}" = "org.winsvpn.bridge" ] || fail "Chrome native-host manifest is not exact"
  chrome_desc="$(json_string "${chrome_flat}" description)" || fail "Chrome native-host manifest is not exact"
  [ "${chrome_desc}" = "Win's VPN browser bridge" ] || fail "Chrome native-host manifest is not exact"
  chrome_type="$(json_string "${chrome_flat}" type)" || fail "Chrome native-host manifest is not exact"
  [ "${chrome_type}" = "stdio" ] || fail "Chrome native-host manifest is not exact"
  chrome_origin_len="$(json_number "${chrome_flat}" allowed_origins.length)" || fail "Chrome native-host manifest is not exact"
  [ "${chrome_origin_len}" = "1" ] || fail "Chrome native-host manifest is not exact"
  chrome_origin="$(json_string "${chrome_flat}" allowed_origins.0)" || fail "Chrome extension id is not exact"
  [ "${chrome_origin}" != "chrome-extension://${RECEIPT_EDGE}/" ] || fail "Chrome native-host manifest reuses the Edge identity"
  [ "${chrome_origin}" = "chrome-extension://${RECEIPT_CHROME}/" ] || fail "Chrome extension id is not exact"
  json_require_keys "${edge_flat}" "name description path type allowed_origins allowed_origins.length allowed_origins.0" || fail "Edge native-host manifest is not exact"
  edge_origin_kind="$(json_lookup "${edge_flat}" allowed_origins)" || fail "Edge native-host manifest is not exact"
  edge_origin_type="${edge_origin_kind%%	*}"
  [ "${edge_origin_type}" = "array" ] || fail "Edge native-host manifest is not exact"
  edge_path="$(json_string "${edge_flat}" path)" || fail "Edge manifest path is not exact"
  [ "${edge_path}" = "${EXPECTED_HOST}" ] || fail "Edge manifest path is not exact"
  edge_name="$(json_string "${edge_flat}" name)" || fail "Edge native-host manifest is not exact"
  [ "${edge_name}" = "org.winsvpn.bridge" ] || fail "Edge native-host manifest is not exact"
  edge_desc="$(json_string "${edge_flat}" description)" || fail "Edge native-host manifest is not exact"
  [ "${edge_desc}" = "Win's VPN browser bridge" ] || fail "Edge native-host manifest is not exact"
  edge_type="$(json_string "${edge_flat}" type)" || fail "Edge native-host manifest is not exact"
  [ "${edge_type}" = "stdio" ] || fail "Edge native-host manifest is not exact"
  edge_origin_len="$(json_number "${edge_flat}" allowed_origins.length)" || fail "Edge native-host manifest is not exact"
  [ "${edge_origin_len}" = "1" ] || fail "Edge native-host manifest is not exact"
  edge_origin="$(json_string "${edge_flat}" allowed_origins.0)" || fail "Edge extension id is not exact"
  [ "${edge_origin}" != "chrome-extension://${RECEIPT_CHROME}/" ] || fail "Edge native-host manifest reuses the Chrome identity"
  [ "${edge_origin}" = "chrome-extension://${RECEIPT_EDGE}/" ] || fail "Edge extension id is not exact"
  inner_kind="$(json_lookup "${receipt_flat}" inner_files)" || fail "receipt inner_files is not exact"
  inner_type="${inner_kind%%	*}"
  [ "${inner_type}" = "array" ] || fail "receipt inner_files is not exact"
  inner_len="$(json_number "${receipt_flat}" inner_files.length)" || fail "receipt inner_files is not exact"
  case "${inner_len}" in
    *[!0-9]*|"") fail "receipt inner_files is not exact" ;;
  esac
  [ "${inner_len}" = "5" ] || fail "receipt inner_files is not exact"
  seen_host=0
  seen_firefox=0
  seen_chrome=0
  seen_edge=0
  seen_uninstall=0
  i=0
  while [ "${i}" -lt "${inner_len}" ]; do
    rel="$(json_string "${receipt_flat}" "inner_files.${i}.path")" || fail "receipt inner file path is missing"
    digest="$(json_string "${receipt_flat}" "inner_files.${i}.sha256")" || fail "receipt inner digest is missing"
    bytes="$(json_number "${receipt_flat}" "inner_files.${i}.bytes")" || fail "receipt inner bytes are missing"
    case "${rel}" in
      *".."*) fail "receipt inner path escapes" ;;
    esac
    base="$(/usr/bin/basename "${rel}")"
    case "${base}" in
      wins_bridge_host)
        [ "${seen_host}" = "0" ] || fail "receipt inner_files is not exact"
        seen_host=1
        ;;
      firefox.json)
        [ "${seen_firefox}" = "0" ] || fail "receipt inner_files is not exact"
        seen_firefox=1
        ;;
      chrome.json)
        [ "${seen_chrome}" = "0" ] || fail "receipt inner_files is not exact"
        seen_chrome=1
        ;;
      edge.json)
        [ "${seen_edge}" = "0" ] || fail "receipt inner_files is not exact"
        seen_edge=1
        ;;
      uninstall.sh)
        [ "${seen_uninstall}" = "0" ] || fail "receipt inner_files is not exact"
        seen_uninstall=1
        ;;
      *) fail "receipt inner path is not exact" ;;
    esac
    expected_rel="Library/Application Support/Win's VPN/NativeMessagingHost/Incoming/${base}"
    [ "${rel}" = "${expected_rel}" ] || fail "receipt inner path is not exact"
    case "${digest}" in
      *[!0-9a-f]*|"" ) fail "receipt inner digest is not SHA-256" ;;
    esac
    [ "${#digest}" -eq 64 ] || fail "receipt inner digest is not SHA-256"
    target="${INCOMING}/${base}"
    actual_digest="$(/usr/bin/shasum -a 256 "${target}" | /usr/bin/awk '{print $1}')"
    [ "${actual_digest}" = "${digest}" ] || fail "receipt-bound inner digest does not match"
    actual_bytes="$(/usr/bin/stat -f %z "${target}")"
    [ "${actual_bytes}" = "${bytes}" ] || fail "receipt-bound inner bytes do not match"
    i=$((i + 1))
  done
  [ "${seen_host}" = "1" ] && [ "${seen_firefox}" = "1" ] && [ "${seen_chrome}" = "1" ] && [ "${seen_edge}" = "1" ] && [ "${seen_uninstall}" = "1" ] || fail "receipt inner_files do not bind every incoming payload file"
}

refuse_live_leaf() {
  path="$1"
  if [ -L "${path}" ]; then
    fail "refusing symlink native-host path ${path}"
  fi
  if [ ! -e "${path}" ]; then
    return 0
  fi
  if [ -p "${path}" ] || [ -S "${path}" ] || [ -b "${path}" ] || [ -c "${path}" ] || [ -d "${path}" ]; then
    fail "refusing special native-host path ${path}"
  fi
  if [ ! -f "${path}" ]; then
    fail "refusing special native-host path ${path}"
  fi
  nlink="$(/usr/bin/stat -f %l "${path}")" || fail "cannot stat ${path}"
  if [ "${nlink}" != "1" ]; then
    fail "refusing hardlinked native-host path ${path}"
  fi
}

atomic_install() {
  source="$1"
  dest="$2"
  mode="$3"
  name="$4"
  dest_dir="$(/usr/bin/dirname "${dest}")"
  leaf="$(/usr/bin/basename "${dest}")"
  case "${leaf}" in
    ""|"."|".."*|*"/"*) fail "destination leaf is not exact" ;;
  esac
  if [ -L "${source}" ] || [ ! -f "${source}" ]; then
    fail "incoming source is not a regular file ${source}"
  fi
  ensure_protected_dir "${dest_dir}"
  refuse_live_leaf "${dest}"
  mark_mutated "${name}"
  if ! (
    bind_dest_parent "${dest_dir}" || exit 1
    refuse_held_leaf "${leaf}" || exit 1
    held_stage_replace "${leaf}" "${mode}" < "${source}" || exit 1
    refuse_held_leaf "${leaf}" || exit 1
  ); then
    fail "atomic replace failed for ${dest}"
  fi
  refuse_live_leaf "${dest}"
  refuse_writable "${dest}"
  [ ! -L "${dest}" ] || fail "destination became a symlink ${dest}"
}

# Browser-bridge trust root shared by the sandboxed app and this host
# (lib/browser_bridge_app_ipc.dart defaultBrowserBridgeAppIpcTrustFile), under
# the contract linux/packaging/install.sh issues at /usr/lib/wins-vpn: exact keys
# v and secret, v == 1, 64 lowercase hex; a regular single-link file, not
# group/other-writable, world-readable, root-owned on the system volume, with
# no symlink or writable ancestor. A valid receipt is kept byte for byte. An
# unsafe or malformed one is left untouched and the install fails before
# mutation. The secret is never printed.
identity_receipt_valid() {
  path="$1"
  [ ! -L "${path}" ] && [ -f "${path}" ] || return 1
  [ "$(/usr/bin/stat -f %l "${path}")" = "1" ] || return 1
  identity_size="$(/usr/bin/stat -f %z "${path}")" || return 1
  case "${identity_size}" in
    *[!0-9]*|"") return 1 ;;
  esac
  [ "${identity_size}" -gt 0 ] && [ "${identity_size}" -le 4096 ] || return 1
  if [ "$(/usr/bin/id -u)" = "0" ]; then
    [ "$(/usr/bin/stat -f %u "${path}")" = "0" ] || return 1
  fi
  [ -z "$(/usr/bin/find "${path}" -maxdepth 0 \( -perm -002 -o -perm -020 \) -print)" ] || return 1
  [ -n "$(/usr/bin/find "${path}" -maxdepth 0 -perm -004 -print)" ] || return 1
  identity_flat="$(json_flatten "${path}")" || return 1
  json_require_keys "${identity_flat}" "v secret" || return 1
  [ "$(json_number "${identity_flat}" v)" = "1" ] || return 1
  identity_secret="$(json_string "${identity_flat}" secret)" || return 1
  [ "${#identity_secret}" -eq 64 ] || return 1
  case "${identity_secret}" in
    *[!0-9a-f]*) return 1 ;;
  esac
  identity_secret=""
  return 0
}

identity_preflight() {
  identity_dir="$(/usr/bin/dirname "${IDENTITY_PATH}")"
  identity_parent="$(/usr/bin/dirname "${identity_dir}")"
  if [ -L "${identity_parent}" ]; then
    fail "refusing symlink parent ${identity_parent}"
  fi
  refuse_writable "${identity_parent}"
  if [ -L "${identity_dir}" ]; then
    fail "refusing symlink parent ${identity_dir}"
  fi
  if [ -e "${identity_dir}" ] && [ ! -d "${identity_dir}" ]; then
    fail "refusing special native-host path ${identity_dir}"
  fi
  refuse_writable "${identity_dir}"
  if [ -e "${IDENTITY_PATH}" ] || [ -L "${IDENTITY_PATH}" ]; then
    identity_receipt_valid "${IDENTITY_PATH}" || fail "browser bridge identity ${IDENTITY_PATH} is not a root-owned, single-link, valid receipt; it was left untouched (fail before mutation)"
  fi
}

issue_identity_receipt() {
  if [ -e "${IDENTITY_PATH}" ] || [ -L "${IDENTITY_PATH}" ]; then
    identity_receipt_valid "${IDENTITY_PATH}" || fail "browser bridge identity changed while it was bound"
    return 0
  fi
  identity_dir="$(/usr/bin/dirname "${IDENTITY_PATH}")"
  ensure_protected_dir "${identity_dir}"
  identity_tmp="$(/usr/bin/mktemp "${identity_dir}/.winsvpn-identity.XXXXXX")" || fail "cannot stage the browser bridge identity"
  identity_secret="$(/usr/bin/od -An -N32 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')" || {
    /bin/rm -f "${identity_tmp}"
    fail "cannot read 32 random bytes for the browser bridge identity"
  }
  case "${identity_secret}" in
    *[!0-9a-f]*|"")
      /bin/rm -f "${identity_tmp}"
      fail "browser bridge identity secret is not lowercase hex"
      ;;
  esac
  if [ "${#identity_secret}" -ne 64 ]; then
    /bin/rm -f "${identity_tmp}"
    fail "browser bridge identity secret is not 64 hex characters"
  fi
  printf '{"secret":"%s","v":1}\n' "${identity_secret}" > "${identity_tmp}" || {
    /bin/rm -f "${identity_tmp}"
    fail "cannot write the browser bridge identity"
  }
  identity_secret=""
  if [ "$(/usr/bin/id -u)" = "0" ]; then
    /usr/sbin/chown root:wheel "${identity_tmp}" || {
      /bin/rm -f "${identity_tmp}"
      fail "cannot chown the browser bridge identity"
    }
  fi
  /bin/chmod 0444 "${identity_tmp}" || {
    /bin/rm -f "${identity_tmp}"
    fail "cannot chmod the browser bridge identity"
  }
  /bin/sync
  # A hard link is an exclusive create: it fails instead of replacing a file
  # that appeared since the preflight.
  /bin/ln "${identity_tmp}" "${IDENTITY_PATH}" || {
    /bin/rm -f "${identity_tmp}"
    fail "browser bridge identity appeared while it was bound"
  }
  /bin/rm -f "${identity_tmp}" || fail "cannot remove the browser bridge identity stage"
  identity_receipt_valid "${IDENTITY_PATH}" || fail "browser bridge identity is not exact after issue"
  /bin/sync
}

verify_incoming || exit 1
identity_preflight

trap 'restore_rollback || true; cleanup_install_temps || true; exit 1' EXIT

atomic_install "${INCOMING}/wins_bridge_host" "${HOST_PATH}" 0755 host.bin
atomic_install "${INCOMING}/firefox.json" "${FIREFOX_PATH}" 0644 firefox.json
atomic_install "${INCOMING}/chrome.json" "${CHROME_PATH}" 0644 chrome.json
atomic_install "${INCOMING}/edge.json" "${EDGE_PATH}" 0644 edge.json
atomic_install "${INCOMING}/receipt.json" "${RECEIPT_PATH}" 0644 receipt.json
atomic_install "${INCOMING}/uninstall.sh" "${UNINSTALL_PATH}" 0755 uninstall.sh
issue_identity_receipt

discard_held_dir "${HOST_DIR}" Incoming || fail "cannot discard incoming payload"
discard_held_dir "${HOST_DIR}" .winsvpn-native-host-rollback || fail "cannot discard rollback directory"
trap - EXIT
exit 0
POSTINSTALL
  /bin/chmod 0755 "$1"
}

write_uninstall() {
  cat > "$1" <<'UNINSTALL'
#!/bin/sh
set -eu
# Explicit safe uninstall helper. It is not run by PKG postinstall. Invoke it
# directly as root to remove only the exact companion files. Orphan
# .winsvpn-stage.* regular files and symlinks in bound rollback directories
# are removed so leftover staging temps cannot wedge uninstall.

fail() {
  printf 'winsvpn native-host companion uninstall: %s\n' "$*" >&2
  exit 1
}

VOLUME="${1:-/}"
case "${VOLUME}" in
  /) PREFIX="" ;;
  /*)
    case "${VOLUME}" in
      */) fail "volume must not have a trailing slash" ;;
    esac
    PREFIX="${VOLUME}"
    ;;
  *) fail "volume must be an absolute path" ;;
esac

if [ "${VOLUME}" = "/" ] && [ "$(/usr/bin/id -u)" != "0" ]; then
  fail "explicit uninstall of the system native host requires root"
fi

EXPECTED_HOST="/Library/Application Support/Win's VPN/NativeMessagingHost/wins_bridge_host"
EXPECTED_FIREFOX="/Library/Application Support/Mozilla/NativeMessagingHosts/org.winsvpn.bridge.json"
EXPECTED_CHROME="/Library/Google/Chrome/NativeMessagingHosts/org.winsvpn.bridge.json"
EXPECTED_EDGE="/Library/Microsoft/Edge/NativeMessagingHosts/org.winsvpn.bridge.json"
EXPECTED_RECEIPT="/Library/Application Support/Win's VPN/NativeMessagingHost/macos-native-host-companion-receipt.json"
EXPECTED_UNINSTALL="/Library/Application Support/Win's VPN/NativeMessagingHost/uninstall-winsvpn-native-host.sh"
PACKAGE_IDENTIFIER="org.winsvpn.bridge.nativemessaginghost"
EXPECTED_IDENTITY="/Library/Application Support/wins_vpn/browser_bridge.identity"

bind_dest_parent() {
  bdp_dir="$1"
  bdp_start="/"
  bdp_rel="${bdp_dir#/}"
  if [ -n "${PREFIX}" ]; then
    case "${bdp_dir}" in
      "${PREFIX}"/*)
        bdp_start="${PREFIX}"
        bdp_rel="${bdp_dir#"${PREFIX}"/}"
        ;;
      *)
        printf 'winsvpn native-host companion uninstall: destination parent is outside the volume\n' >&2
        return 1
        ;;
    esac
  fi
  cd "${bdp_start}" || return 1
  if [ "${bdp_start}" != "/" ] && [ -L "${bdp_start}" ]; then
    printf 'winsvpn native-host companion: refusing symlink parent %s\n' "${bdp_start}" >&2
    return 1
  fi
  bdp_rest="${bdp_rel}"
  while [ -n "${bdp_rest}" ]; do
    bdp_part="${bdp_rest%%/*}"
    if [ "${bdp_part}" = "${bdp_rest}" ]; then
      bdp_rest=""
    else
      bdp_rest="${bdp_rest#*/}"
    fi
    [ -n "${bdp_part}" ] || continue
    if [ -L "${bdp_part}" ]; then
      printf 'winsvpn native-host companion: refusing symlink parent %s\n' "${bdp_part}" >&2
      return 1
    fi
    if [ ! -d "${bdp_part}" ]; then
      printf 'winsvpn native-host companion uninstall: required parent is missing: %s\n' "${bdp_part}" >&2
      return 1
    fi
    bdp_id="$(/usr/bin/stat -f '%d:%i' "${bdp_part}")" || return 1
    cd "${bdp_part}" || return 1
    bdp_now="$(/usr/bin/stat -f '%d:%i' .)" || return 1
    if [ "${bdp_now}" != "${bdp_id}" ]; then
      printf 'winsvpn native-host companion: destination parent changed while it was bound\n' >&2
      return 1
    fi
  done
  if [ ! -d . ]; then
    printf 'winsvpn native-host companion: refusing symlink parent\n' >&2
    return 1
  fi
  return 0
}

remove_held_leaf() {
  dest="$1"
  dest_dir="$(/usr/bin/dirname "${dest}")"
  leaf="$(/usr/bin/basename "${dest}")"
  case "${leaf}" in
    ""|"."|".."*|*"/"*) return 1 ;;
  esac
  (
    bind_dest_parent "${dest_dir}" || exit 1
    if [ -L "${leaf}" ]; then
      printf 'winsvpn native-host companion uninstall: refusing to remove symlink %s\n' "${dest}" >&2
      exit 1
    fi
    if [ -e "${leaf}" ] && [ ! -f "${leaf}" ]; then
      printf 'winsvpn native-host companion uninstall: refusing to remove non-file %s\n' "${dest}" >&2
      exit 1
    fi
    if [ -f "${leaf}" ]; then
      /bin/rm -f -- "./${leaf}" || exit 1
    fi
  )
}

remove_held_named_dir() {
  dest_dir="$1"
  leaf="$2"
  shift 2
  case "${leaf}" in
    ""|"."|".."*|*"/"*) return 1 ;;
  esac
  (
    bind_dest_parent "${dest_dir}" || exit 1
    if [ -L "${leaf}" ]; then
      printf 'winsvpn native-host companion: refusing symlink parent %s\n' "${leaf}" >&2
      exit 1
    fi
    if [ ! -e "${leaf}" ]; then
      exit 0
    fi
    if [ ! -d "${leaf}" ]; then
      printf 'winsvpn native-host companion uninstall: refusing to remove non-file %s\n' "${leaf}" >&2
      exit 1
    fi
    cd "${leaf}" || exit 1
    inner_status=0
    for name in "$@"; do
      case "${name}" in
        ""|"."|".."*|*"/"*) inner_status=1; continue ;;
      esac
      if [ -L "${name}" ]; then
        printf 'winsvpn native-host companion uninstall: refusing to remove symlink %s\n' "${name}" >&2
        inner_status=1
        continue
      fi
      if [ -e "${name}" ] && [ ! -f "${name}" ]; then
        printf 'winsvpn native-host companion uninstall: refusing to remove non-file %s\n' "${name}" >&2
        inner_status=1
        continue
      fi
      if [ -f "${name}" ]; then
        /bin/rm -f -- "./${name}" || inner_status=1
      fi
    done
    for staged in ./.winsvpn-stage.*; do
      if [ "${staged}" = "./.winsvpn-stage.*" ] && [ ! -e "${staged}" ] && [ ! -L "${staged}" ]; then
        continue
      fi
      case "${staged}" in
        "./.winsvpn-stage."*) ;;
        *) inner_status=1; continue ;;
      esac
      if [ -L "${staged}" ]; then
        /bin/rm -f -- "${staged}" || inner_status=1
      elif [ -f "${staged}" ]; then
        /bin/rm -f -- "${staged}" || inner_status=1
      fi
    done
    cd .. || exit 1
    /bin/rmdir "${leaf}" 2>/dev/null || true
    exit "${inner_status}"
  )
}

rmdir_held() {
  dir="$1"
  parent="$(/usr/bin/dirname "${dir}")"
  leaf="$(/usr/bin/basename "${dir}")"
  case "${leaf}" in
    ""|"."|".."*|*"/"*) return 1 ;;
  esac
  (
    bind_dest_parent "${parent}" || exit 1
    if [ -L "${leaf}" ]; then
      printf 'winsvpn native-host companion: refusing symlink parent %s\n' "${leaf}" >&2
      exit 1
    fi
    if [ -d "${leaf}" ]; then
      /bin/rmdir "${leaf}" 2>/dev/null || true
    fi
  )
}

HOST_PATH="${PREFIX}${EXPECTED_HOST}"
FIREFOX_PATH="${PREFIX}${EXPECTED_FIREFOX}"
CHROME_PATH="${PREFIX}${EXPECTED_CHROME}"
EDGE_PATH="${PREFIX}${EXPECTED_EDGE}"
RECEIPT_PATH="${PREFIX}${EXPECTED_RECEIPT}"
UNINSTALL_PATH="${PREFIX}${EXPECTED_UNINSTALL}"
IDENTITY_PATH="${PREFIX}${EXPECTED_IDENTITY}"
HOST_DIR="$(/usr/bin/dirname "${HOST_PATH}")"

status=0
set +e
remove_held_leaf "${HOST_PATH}" || status=1
remove_held_leaf "${FIREFOX_PATH}" || status=1
remove_held_leaf "${CHROME_PATH}" || status=1
remove_held_leaf "${EDGE_PATH}" || status=1
remove_held_leaf "${RECEIPT_PATH}" || status=1
remove_held_named_dir "${HOST_DIR}" Incoming \
  wins_bridge_host firefox.json chrome.json edge.json receipt.json uninstall.sh || status=1
remove_held_named_dir "${HOST_DIR}" .winsvpn-native-host-rollback \
  host.bin firefox.json chrome.json edge.json receipt.json uninstall.sh \
  host.bin.mutated firefox.json.mutated chrome.json.mutated edge.json.mutated \
  receipt.json.mutated uninstall.sh.mutated || status=1
remove_held_leaf "${UNINSTALL_PATH}" || status=1
rmdir_held "${HOST_DIR}" || status=1
rmdir_held "$(/usr/bin/dirname "${FIREFOX_PATH}")" || status=1
rmdir_held "$(/usr/bin/dirname "${CHROME_PATH}")" || status=1
rmdir_held "$(/usr/bin/dirname "${EDGE_PATH}")" || status=1
if [ -e "${IDENTITY_PATH}" ] || [ -L "${IDENTITY_PATH}" ]; then
  remove_held_leaf "${IDENTITY_PATH}" || status=1
  rmdir_held "$(/usr/bin/dirname "${IDENTITY_PATH}")" || status=1
fi
set -e
if [ "${status}" != 0 ]; then
  fail "uninstall could not remove every exact file"
fi

if [ "$(/usr/bin/id -u)" = "0" ] && [ "${VOLUME}" = "/" ]; then
  /usr/sbin/pkgutil --forget "${PACKAGE_IDENTIFIER}" >/dev/null 2>&1 || true
fi
printf 'uninstalled exact Win'\''s VPN native-messaging companion files\n'
exit 0
UNINSTALL
  /bin/chmod 0755 "$1"
}

if [[ "${CHECK_ONLY}" == "1" ]]; then
  printf 'macos native-host companion PKG owner gates passed; no PKG was written\n'
  exit 0
fi

STAGE="$(/usr/bin/mktemp -d /tmp/winsvpn-macos-native-host-companion.XXXXXX)"
cleanup() {
  /bin/rm -rf "${STAGE}"
}
trap cleanup EXIT

PAYLOAD="${STAGE}/payload"
SCRIPTS="${STAGE}/scripts"
INCOMING="${PAYLOAD}/Library/Application Support/Win's VPN/NativeMessagingHost/Incoming"
COMPONENT="${STAGE}/org.winsvpn.bridge.nativemessaginghost.pkg"
PRODUCT="${STAGE}/Win's VPN Native Messaging Host.pkg"
DIST="${STAGE}/distribution.xml"

/bin/mkdir -p "${INCOMING}" "${SCRIPTS}"
# umask 077 makes the payload root 0700; it is archived as "." and lands on
# "/", so it must be 0755 like every other payload directory.
/bin/chmod 0755 "${PAYLOAD}" "${PAYLOAD}/Library" \
  "${PAYLOAD}/Library/Application Support" \
  "${PAYLOAD}/Library/Application Support/Win's VPN" \
  "${PAYLOAD}/Library/Application Support/Win's VPN/NativeMessagingHost" \
  "${INCOMING}" "${SCRIPTS}"

/bin/cp "${HOST}" "${INCOMING}/wins_bridge_host"
/bin/chmod 0755 "${INCOMING}/wins_bridge_host"

"${PYTHON_BIN}" - "${CHROME_ID}" "${EDGE_ID}" "${INCOMING}/firefox.json" "${INCOMING}/chrome.json" "${INCOMING}/edge.json" <<'PY'
import json
import sys

chrome_id, edge_id, firefox_path, chrome_path, edge_path = sys.argv[1:]
if chrome_id == edge_id:
    raise SystemExit("Chrome and Edge store-listing ids must be distinct")
host = "/Library/Application Support/Win's VPN/NativeMessagingHost/wins_bridge_host"
shared = {
    "name": "org.winsvpn.bridge",
    "description": "Win's VPN browser bridge",
    "path": host,
    "type": "stdio",
}
firefox = dict(shared)
firefox["allowed_extensions"] = ["companion@winsvpn.org"]
chrome = dict(shared)
chrome["allowed_origins"] = [f"chrome-extension://{chrome_id}/"]
edge = dict(shared)
edge["allowed_origins"] = [f"chrome-extension://{edge_id}/"]
for path, document in (
    (firefox_path, firefox),
    (chrome_path, chrome),
    (edge_path, edge),
):
    with open(path, "w", encoding="ascii", newline="\n") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=True)
        handle.write("\n")
PY
/bin/chmod 0644 "${INCOMING}/firefox.json" "${INCOMING}/chrome.json" "${INCOMING}/edge.json"

write_preinstall "${SCRIPTS}/preinstall"
write_postinstall "${SCRIPTS}/postinstall"
write_uninstall "${INCOMING}/uninstall.sh"

"${PYTHON_BIN}" "${VERIFIER}" bind-receipt \
  --payload "${PAYLOAD}" \
  --scripts "${SCRIPTS}" \
  --chrome-id "${CHROME_ID}" \
  --edge-id "${EDGE_ID}" \
  --output "${INCOMING}/receipt.json" \
  --repo "${ROOT}" >/dev/null
/bin/chmod 0644 "${INCOMING}/receipt.json"

cat > "${DIST}" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Win's VPN Native Messaging Host</title>
    <options customize="never" require-scripts="true" hostArchitectures="${HOST_ARCHITECTURES}"/>
    <volume-check>
        <allowed-os-versions>
            <os-version min="${HOST_MINIMUM_MACOS}"/>
        </allowed-os-versions>
    </volume-check>
    <choices-outline>
        <line choice="${PACKAGE_IDENTIFIER}"/>
    </choices-outline>
    <choice id="${PACKAGE_IDENTIFIER}" visible="false">
        <pkg-ref id="${PACKAGE_IDENTIFIER}"/>
    </choice>
    <pkg-ref id="${PACKAGE_IDENTIFIER}" version="${PACKAGE_VERSION}" onConclusion="none">org.winsvpn.bridge.nativemessaginghost.pkg</pkg-ref>
</installer-gui-script>
EOF

/usr/bin/pkgbuild \
  --root "${PAYLOAD}" \
  --identifier "${PACKAGE_IDENTIFIER}" \
  --version "${PACKAGE_VERSION}" \
  --install-location / \
  --scripts "${SCRIPTS}" \
  --ownership recommended \
  "${COMPONENT}" >/dev/null

/usr/bin/productbuild \
  --distribution "${DIST}" \
  --package-path "${STAGE}" \
  --sign "${INSTALLER_IDENTITY}" \
  "${PRODUCT}" >/dev/null

if [[ -n "${NOTARYTOOL_KEYCHAIN_PROFILE:-}" ]]; then
  /usr/bin/xcrun notarytool submit "${PRODUCT}" \
    --keychain-profile "${NOTARYTOOL_KEYCHAIN_PROFILE}" \
    --wait
else
  /usr/bin/xcrun notarytool submit "${PRODUCT}" \
    --key "${APPLE_API_KEY}" \
    --key-id "${APPLE_API_KEY_ID}" \
    --issuer "${APPLE_API_ISSUER}" \
    --wait
fi

/usr/bin/stapler staple "${PRODUCT}" >/dev/null
"${PYTHON_BIN}" "${VERIFIER}" "${PRODUCT}"

/bin/cp "${PRODUCT}" "${OUTPUT}.new"
/bin/chmod 0644 "${OUTPUT}.new"
/bin/mv -f "${OUTPUT}.new" "${OUTPUT}"
trap - EXIT
cleanup
printf 'macos native-host companion PKG written: %s\n' "${OUTPUT}"
