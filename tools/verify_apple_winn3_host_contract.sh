#!/usr/bin/env bash
#
# verify_apple_winn3_host_contract.sh — the Apple half of §4 of
# docs/handoff/WINN3_TUN_LAYER_20260808.md, driven against the REAL Go archive.
#
# WHY THIS IS A SECOND SCRIPT AND NOT MORE CHECKS IN THE FIRST ONE
#
# tools/verify_apple_winn_seam.sh proves the RELAY seam: AmneziaWG owns the tun,
# Winn carries its outer datagrams, and the wrapper's loopback seam and UAPI
# repoint are the thing under test. Its check count is a pinned number that
# lanes quote at each other — "128/128" is how the seam lane proves it neither
# lost a check nor invented one — and folding an unrelated subsystem into that
# count would destroy the only thing the number is good for.
#
# winn/3 STANDALONE is a different datapath with a different entry point, a
# different payload class and a different promotion predicate. It gets its own
# count.
#
# WHAT IT PROVES
#
# It links every apple/WinsTunnelCore Swift source against a FRESH c-archive
# built from the Go source in this tree, and drives the winn/3 half of the C ABI
# through dlsym exactly as the appex does — the appex links no Go archive at
# build time, so a header declaration would prove something the shipping build
# does not do.
#
# Covered: the create refusals (payload class, carrier name, unknown field,
# hostname endpoint, absent admission profile, unpermitted own socket), the
# status document's two promotion numbers, the §4.1 promotion predicate, the
# §4.1/§4.3 bootstrap-posture narrowness check, the carrier-exclusion rule, the
# WinsTunnelConfig carrier gate, and the observability sampler's winn3 keys.
#
# WHAT IT DOES NOT DO
#
# It starts NO tunnel, installs NO network settings, and reaches NO gateway. The
# one create that succeeds is pointed at a UDP socket connected to a listener in
# this same process on 127.0.0.1, so nothing leaves the machine.
#
# Usage: tools/verify_apple_winn3_host_contract.sh
# Env:   WINN_APPLE_SEAM_ARCHIVE  use this archive instead of building one

set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "${PROJECT_ROOT}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || die "this harness runs the Apple host contract and requires macOS."
[[ "$(uname -m)" == "arm64" ]] \
  || die "the datapath lane ships no x86_64 Apple archive; this harness requires an arm64 Mac."

command -v xcrun >/dev/null 2>&1 || die "full Xcode command line tools are required."

CLANG_BIN="$(xcrun -f clang)"
SWIFTC_BIN="$(xcrun -f swiftc)"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
TARGET="arm64-apple-macos13.0"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-apple-winn3-contract.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

ARCHIVE="${WINN_APPLE_SEAM_ARCHIVE:-}"
if [[ -n "${ARCHIVE}" ]]; then
  [[ -f "${ARCHIVE}" ]] || die "WINN_APPLE_SEAM_ARCHIVE does not exist: ${ARCHIVE}"
  printf 'Using the caller-supplied datapath archive: %s\n' "${ARCHIVE}"
  printf 'NOTE: this bypasses the freshness guarantee this script exists to provide.\n'
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

printf 'Compiling the AmneziaWG stand-in and the real Winn wrapper...\n'
"${CLANG_BIN}" -target "${TARGET}" -isysroot "${SDK_PATH}" \
  -fobjc-arc -Wall -Wextra -Werror \
  -c tools/verify_apple_winn_seam_awg_stub.m -o "${WORK_DIR}/awg_stub.o"

"${CLANG_BIN}" -target "${TARGET}" -isysroot "${SDK_PATH}" \
  -fobjc-arc -Wall -Wextra -Werror \
  -I apple/EngineWrappers \
  -c apple/EngineWrappers/WinsWinnPacketEngine.m -o "${WORK_DIR}/winn_wrapper.o"

printf 'Linking the winn3 host-contract harness against the real Swift host...\n'
# Globbed, not listed, so a new core file can never silently drop out of
# coverage — the same rule the seam script follows and for the same reason.
WINS_TUNNEL_CORE_SOURCES=(apple/WinsTunnelCore/*.swift)
[[ -e "${WINS_TUNNEL_CORE_SOURCES[0]}" ]] || die "no apple/WinsTunnelCore/*.swift sources found."

"${SWIFTC_BIN}" -sdk "${SDK_PATH}" -target "${TARGET}" \
  "${WINS_TUNNEL_CORE_SOURCES[@]}" \
  tools/verify_apple_winn3_host_contract_harness.swift \
  "${WORK_DIR}/awg_stub.o" \
  "${WORK_DIR}/winn_wrapper.o" \
  -Xlinker -force_load -Xlinker "${ARCHIVE}" \
  -framework CoreFoundation \
  -framework Foundation \
  -framework NetworkExtension \
  -framework Security \
  -lresolv \
  -Xlinker -export_dynamic \
  -o "${WORK_DIR}/verify_apple_winn3_host_contract"

"${WORK_DIR}/verify_apple_winn3_host_contract"
