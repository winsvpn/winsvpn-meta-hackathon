#!/usr/bin/env bash
#
# verify_apple_winn_seam_burst.sh — run the Apple Winn seam's UNPACED-BURST
# regression against the REAL Go datapath, in one process, on this machine.
#
# WHY THIS IS A SECOND SCRIPT AND NOT A CASE INSIDE verify_apple_winn_seam.sh
#
# That script proves the seam is CORRECT: carrier selection, every validate()
# refusal, the UAPI endpoint repoint, peer pinning, teardown, and that real
# datagrams relay both ways. It is a functional proof, and it passed 98/98
# while the seam was losing a third of an unpaced burst — because correctness
# and rate are different properties and it never offered traffic fast enough to
# test the second one.
#
# WHAT IT PROVES
#
# It links the real apple/EngineWrappers/WinsWinnPacketEngine.m and a Go
# datapath archive built fresh from this tree, drives the real wrapper with
# packet_flow == NULL, and offers an unpaced burst at the loopback seam while a
# socket on the far side of the whole chain records which sequence numbers
# arrived. A control case bursts the same traffic with the seam bypassed, so a
# failure can never be blamed on the harness's own producer or sink.
#
# Baseline before the fix, this machine, arm64 macOS 2026-08-05:
#   20,000 datagrams at ~234,000 pkt/s -> 9,255 lost (46.27%), silently.
#
# Usage: tools/verify_apple_winn_seam_burst.sh
# Env:   WINN_APPLE_SEAM_ARCHIVE    use this archive instead of building one
#        WINN_SEAM_BURST_COUNT      datagrams per case (default 20000)
#        WINN_SEAM_BURST_TOLERANCE  permitted lost datagrams (default 0)

set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "${PROJECT_ROOT}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# The harness executes, so it must be built for the machine running it.
[[ "$(uname -s)" == "Darwin" ]] || die "this harness runs the Apple engine and requires macOS."
[[ "$(uname -m)" == "arm64" ]] \
  || die "this harness runs the Apple engine natively and requires an arm64 Mac; the datapath lane ships no x86_64 Apple archive."

command -v xcrun >/dev/null 2>&1 || die "full Xcode command line tools are required."

CLANG_BIN="$(xcrun -f clang)"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-apple-winn-burst.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

ARCHIVE="${WINN_APPLE_SEAM_ARCHIVE:-}"
if [[ -n "${ARCHIVE}" ]]; then
  [[ -f "${ARCHIVE}" ]] || die "WINN_APPLE_SEAM_ARCHIVE does not exist: ${ARCHIVE}"
  printf 'Using the caller-supplied datapath archive: %s\n' "${ARCHIVE}"
  printf 'NOTE: this bypasses the freshness guarantee this script otherwise provides.\n'
elif [[ -n "${WINS_WINN_RELEASE_DIR:-}" ]]; then
  # Take the archive from a Winn release directory written by
  # tools/winn_release.py. The driver verifies the release (signature against
  # the pinned key, or WINS_WINN_TRUST_PUBLIC_KEY for a test key; digests
  # only with WINS_WINN_ALLOW_UNSIGNED=1 for a dev build) before printing it.
  release_args=(verify --release "${WINS_WINN_RELEASE_DIR}")
  if [[ "${WINS_WINN_ALLOW_UNSIGNED:-0}" == "1" ]]; then
    release_args+=(--allow-unsigned)
  elif [[ -n "${WINS_WINN_TRUST_PUBLIC_KEY:-}" ]]; then
    release_args+=(--trust-public-key "${WINS_WINN_TRUST_PUBLIC_KEY}")
  fi
  release_output="$(/usr/bin/python3 -I tools/winn_release.py "${release_args[@]}" --print-artifact datapath-archive-darwin-arm64)" \
    || die "the Winn release did not verify for datapath-archive-darwin-arm64."
  ARCHIVE="${release_output%%$'\n'*}"
  [[ -f "${ARCHIVE}" && ! -L "${ARCHIVE}" && -s "${ARCHIVE}" ]] \
    || die "the Winn release printed no usable datapath-archive-darwin-arm64 archive."
  printf 'Using the verified Winn release archive: %s\n' "${ARCHIVE}"
else
  command -v go >/dev/null 2>&1 || die "Go is required to build the datapath archive this harness runs against."
  ARCHIVE="${WORK_DIR}/libwinn-datapath-darwin-arm64.a"
  printf 'Building a fresh Winn datapath c-archive from the Go source in this tree...\n'
  # The builder exits 0 only on success and installs nothing on failure, so
  # both the status and the artifact are checked.
  build_status=0
  bash tools/build_winn_protocol_engine.sh datapath-archive-darwin-arm64 "${ARCHIVE}" \
    >"${WORK_DIR}/archive-build.log" 2>&1 || build_status=$?
  if [[ "${build_status}" -ne 0 || ! -s "${ARCHIVE}" ]]; then
    cat "${WORK_DIR}/archive-build.log" >&2
    die "the Winn datapath archive was not produced."
  fi
fi

# Built at the same -Wall -Wextra -Werror bar as the shipping wrapper, and from
# the same source, so this cannot pass against something the real build rejects.
printf 'Compiling the real Winn wrapper and the burst harness...\n'
"${CLANG_BIN}" -target "${TARGET}" -isysroot "${SDK_PATH}" \
  -fobjc-arc -Wall -Wextra -Werror \
  -I apple/EngineWrappers \
  -c apple/EngineWrappers/WinsWinnPacketEngine.m -o "${WORK_DIR}/winn_wrapper.o"

"${CLANG_BIN}" -target "${TARGET}" -isysroot "${SDK_PATH}" \
  -fobjc-arc -Wall -Wextra -Werror \
  -c tools/verify_apple_winn_seam_burst.m -o "${WORK_DIR}/burst.o"

"${CLANG_BIN}" -target "${TARGET}" -isysroot "${SDK_PATH}" \
  "${WORK_DIR}/burst.o" \
  "${WORK_DIR}/winn_wrapper.o" \
  -Xlinker -force_load -Xlinker "${ARCHIVE}" \
  -framework CoreFoundation \
  -framework Foundation \
  -framework Security \
  -lresolv \
  -o "${WORK_DIR}/verify_apple_winn_seam_burst"

"${WORK_DIR}/verify_apple_winn_seam_burst"
