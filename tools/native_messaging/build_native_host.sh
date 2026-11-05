#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
HOST_DIR="${SCRIPT_DIR}/host"
OUTPUT=""
DART_BIN="${DART_BIN:-}"
UNIVERSAL=0
ARM_THIN=""
X64_THIN=""

usage() {
  printf 'usage: build_native_host.sh --output ABSOLUTE_PATH [--dart PATH] [--universal]\n' >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --dart) DART_BIN="${2:-}"; shift 2 ;;
    --universal) UNIVERSAL=1; shift ;;
    *) usage ;;
  esac
done

[[ "${OUTPUT}" == /* ]] || usage
if [[ -z "${DART_BIN}" ]]; then
  DART_BIN="$(command -v dart 2>/dev/null || true)"
fi
[[ -n "${DART_BIN}" && -f "${DART_BIN}" && -x "${DART_BIN}" ]] || {
  printf 'native-host build refused: reviewed dart executable is unavailable\n' >&2
  exit 65
}

mkdir -p -- "$(dirname "${OUTPUT}")"
TEMPORARY="${OUTPUT}.new.$$"
cleanup_native_host_temps() {
  rm -f -- "${TEMPORARY}"
  [[ -n "${ARM_THIN}" ]] && rm -f -- "${ARM_THIN}"
  [[ -n "${X64_THIN}" ]] && rm -f -- "${X64_THIN}"
}
trap cleanup_native_host_temps EXIT

(cd "${HOST_DIR}" && "${DART_BIN}" pub get --offline --enforce-lockfile)

if [[ "${UNIVERSAL}" == "1" ]]; then
  [[ "$(uname -s)" == "Darwin" ]] || {
    printf 'universal native-host build is macOS-only\n' >&2
    exit 65
  }
  [[ -x /usr/bin/lipo ]] || {
    printf 'universal native-host build requires /usr/bin/lipo\n' >&2
    exit 65
  }
  ARM_THIN="${OUTPUT}.arm64.$$"
  X64_THIN="${OUTPUT}.x64.$$"
  (cd "${HOST_DIR}" && "${DART_BIN}" compile exe \
    --target-os=macos --target-arch=arm64 \
    bin/wins_bridge_host.dart -o "${ARM_THIN}")
  (cd "${HOST_DIR}" && "${DART_BIN}" compile exe \
    --target-os=macos --target-arch=x64 \
    bin/wins_bridge_host.dart -o "${X64_THIN}")
  /usr/bin/lipo -create "${ARM_THIN}" "${X64_THIN}" -output "${TEMPORARY}"
  chmod 0755 "${TEMPORARY}"
  ARCHS="$(/usr/bin/lipo -archs "${TEMPORARY}")"
  case " ${ARCHS} " in
    *" arm64 "*) ;;
    *)
      printf 'universal native-host is missing the arm64 Mach-O slice: %s\n' "${ARCHS}" >&2
      exit 65
      ;;
  esac
  case " ${ARCHS} " in
    *" x86_64 "*) ;;
    *)
      printf 'universal native-host is missing the x86_64 Mach-O slice: %s\n' "${ARCHS}" >&2
      exit 65
      ;;
  esac
  "${TEMPORARY}" --selftest >/dev/null
  rm -f -- "${ARM_THIN}" "${X64_THIN}"
  ARM_THIN=""
  X64_THIN=""
else
  (cd "${HOST_DIR}" && "${DART_BIN}" compile exe bin/wins_bridge_host.dart -o "${TEMPORARY}")
  chmod 0755 "${TEMPORARY}"
  "${TEMPORARY}" --selftest >/dev/null
fi

mv -f -- "${TEMPORARY}" "${OUTPUT}"
trap - EXIT
printf 'native host built and self-tested: %s\n' "${OUTPUT}"
