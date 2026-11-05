#!/usr/bin/env bash
# Developer ID Application signing for the macOS companion wins_bridge_host.
#
# Signs a built host in place with the team's Developer ID Application identity,
# hardened runtime, a secure timestamp, the fixed identifier
# org.winsvpn.bridge.host, and exactly tools/native_messaging/
# macos_native_host.entitlements:
#   - com.apple.security.application-groups 5YT8H4U72M.group.org.winsvpn.app,
#     the App Group container the sandboxed App Store app writes its IPC
#     discovery file into;
#   - com.apple.security.cs.allow-unsigned-executable-memory, because the Dart
#     AOT runtime executes snapshot pages the kernel does not treat as signed;
#     without it hardened runtime SIGKILLs the host (CODESIGNING Invalid Page).
# Then it re-runs --selftest on the signed bytes. It never invents an identity:
# a missing Developer ID Application identity for the team is an owner block.
set -euo pipefail
umask 077

TEAM_ID="5YT8H4U72M"
IDENTIFIER="org.winsvpn.bridge.host"
OWNER_BLOCK_EXIT=78
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENTITLEMENTS="${SCRIPT_DIR}/macos_native_host.entitlements"
HOST=""

usage() {
  printf 'usage: sign_macos_native_host.sh --host ABSOLUTE_PATH\n' >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || { printf 'native-host signing is macOS-only\n' >&2; exit 65; }
[[ "${HOST}" == /* ]] || usage
[[ -f "${HOST}" && ! -L "${HOST}" && -x "${HOST}" ]] || {
  printf 'native-host signing refused: %s is missing, symbolic, or not executable\n' "${HOST}" >&2
  exit 65
}
[[ -f "${ENTITLEMENTS}" && ! -L "${ENTITLEMENTS}" ]] || {
  printf 'native-host signing refused: reviewed entitlements are missing\n' >&2
  exit 65
}

IDENTITY="$(
  /usr/bin/security find-identity -v -p codesigning 2>/dev/null | /usr/bin/awk -v team="${TEAM_ID}" '
    match($0, /"[^"]+"/) {
      identity = substr($0, RSTART + 1, RLENGTH - 2)
      if (index(identity, "Developer ID Application:") == 1 && index(identity, "(" team ")") > 0) {
        print identity
        exit
      }
    }
  '
)"
[[ -n "${IDENTITY}" ]] || {
  printf 'native-host signing owner gate: Developer ID Application identity for team %s is missing\n' "${TEAM_ID}" >&2
  exit "${OWNER_BLOCK_EXIT}"
}

/usr/bin/codesign --force \
  --sign "${IDENTITY}" \
  --identifier "${IDENTIFIER}" \
  --options runtime \
  --timestamp \
  --entitlements "${ENTITLEMENTS}" \
  -- "${HOST}"
/usr/bin/codesign --verify --strict --verbose=2 -- "${HOST}"
"${HOST}" --selftest >/dev/null
printf 'native host signed (Developer ID Application, team %s, hardened runtime) and self-tested: %s\n' \
  "${TEAM_ID}" "${HOST}"
