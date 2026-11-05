#!/usr/bin/env bash
#
# verify_apple_winn3_host_contract_iossimulator.sh — the SAME winn/3 host
# contract and packet pump as verify_apple_winn3_host_contract.sh, compiled for
# the iOS runtime and executed inside the iOS Simulator.
#
# WHY THIS EXISTS
#
# The macOS script proves the contract and the pump against the real Go archive
# on macOS. That is not evidence about iOS, and this repository has already been
# bitten by exactly that inference: the Apple host is shared source, but the
# ARCHIVE is a different Mach-O platform, the Go runtime's scheduler and its
# thread creation behave differently under the iOS runtime, and the appex's
# memory budget is an iOS-only constraint. A pump that parks a dedicated Thread
# inside a blocking cgo call is precisely the kind of thing that can work on one
# and not the other.
#
# So the same sources are built for arm64-apple-ios-simulator, linked against
# the iOS SIMULATOR slice of the archive, and RUN — not merely compiled.
#
# WHAT THIS IS STILL NOT
#
# A simulator is not a device. It does not prove code signing, it does not
# prove the appex's jetsam budget, it does not prove NEPacketTunnelFlow (which
# no simulator provides), and it does not prove a Release build's linkage. What
# it does prove is that the winn/3 C ABI, the Swift host and the packet pump
# execute correctly on the iOS runtime rather than only on the macOS one.
#
# kWinnHostCapabilities['ios'] stays .absent regardless of this script's result.
#
# Usage: tools/verify_apple_winn3_host_contract_iossimulator.sh [simulator-udid]

set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "${PROJECT_ROOT}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || die "requires macOS."
command -v xcrun >/dev/null 2>&1 || die "full Xcode command line tools are required."

IOS_SIMULATOR_ARM64_DEPLOYMENT_TARGET=14.0
TARGET="arm64-apple-ios${IOS_SIMULATOR_ARM64_DEPLOYMENT_TARGET}-simulator"

CLANG_BIN="$(xcrun --sdk iphonesimulator -f clang)"
SWIFTC_BIN="$(xcrun -f swiftc)"
SDK_PATH="$(xcrun --sdk iphonesimulator --show-sdk-path)"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-apple-winn3-iossim.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

# The simulator this runs on. Any available iPhone will do — nothing here is
# device-specific — but the caller may name one.
SIM_UDID="${1:-}"
if [[ -z "${SIM_UDID}" ]]; then
  SIM_UDID="$(xcrun simctl list devices available -j \
    | /usr/bin/python3 -c 'import json,sys
data=json.load(sys.stdin)["devices"]
for runtime, devices in data.items():
    if "iOS" not in runtime: continue
    for device in devices:
        if device.get("isAvailable") and "iPhone" in device["name"]:
            print(device["udid"]); raise SystemExit
')"
fi
[[ -n "${SIM_UDID}" ]] || die "no available iPhone simulator was found."

if [[ -n "${WINS_WINN_RELEASE_DIR:-}" ]]; then
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
  release_output="$(/usr/bin/python3 -I tools/winn_release.py "${release_args[@]}" --print-artifact datapath-iossimulator-arm64)" \
    || die "the Winn release did not verify for datapath-iossimulator-arm64."
  ARCHIVE="${release_output%%$'\n'*}"
  [[ -f "${ARCHIVE}" && ! -L "${ARCHIVE}" && -s "${ARCHIVE}" ]] \
    || die "the Winn release printed no usable datapath-iossimulator-arm64 archive."
  printf 'Using the verified Winn release archive: %s\n' "${ARCHIVE}"
else
  ARCHIVE="${WORK_DIR}/libwinn-datapath-iossimulator-arm64.a"
  printf 'Building a fresh iOS SIMULATOR Winn datapath c-archive from the Go source in this tree...\n'
  # The builder exits 0 only on success, so both the status and the artifact
  # are checked.
  build_status=0
  bash tools/build_winn_protocol_engine.sh datapath-iossimulator-arm64 "${ARCHIVE}" \
    >"${WORK_DIR}/archive-build.log" 2>&1 || build_status=$?
  if [[ "${build_status}" -ne 0 || ! -s "${ARCHIVE}" ]]; then
    cat "${WORK_DIR}/archive-build.log" >&2
    die "the iOS simulator Winn datapath archive was not produced."
  fi
fi
# The archive's own LC_BUILD_VERSION decides the platform: every member must
# be an iOS SIMULATOR object (platform 7), whichever path supplied it.
archive_platforms="$(/usr/bin/otool -l "${ARCHIVE}")" \
  || die "could not read the load commands of ${ARCHIVE}."
archive_platforms="$(awk '$1 == "platform" { print $2 }' <<<"${archive_platforms}" | sort -u)"
[[ "${archive_platforms}" == "7" || "${archive_platforms}" == "IOSSIMULATOR" ]] \
  || die "the archive is not an IOSSIMULATOR slice (platforms: ${archive_platforms:-none})."

printf 'Compiling the AmneziaWG stand-in and the real Winn wrapper for iOS...\n'
"${CLANG_BIN}" -target "${TARGET}" -isysroot "${SDK_PATH}" \
  -fobjc-arc -Wall -Wextra -Werror \
  -c tools/verify_apple_winn_seam_awg_stub.m -o "${WORK_DIR}/awg_stub.o"

"${CLANG_BIN}" -target "${TARGET}" -isysroot "${SDK_PATH}" \
  -fobjc-arc -Wall -Wextra -Werror \
  -I apple/EngineWrappers \
  -c apple/EngineWrappers/WinsWinnPacketEngine.m -o "${WORK_DIR}/winn_wrapper.o"

printf 'Linking the winn3 host-contract harness for the iOS Simulator...\n'
# Globbed for the same reason the macOS script globs: a new core file can never
# silently drop out of coverage.
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
  -o "${WORK_DIR}/verify_apple_winn3_host_contract_ios"

printf 'Booting simulator %s...\n' "${SIM_UDID}"
xcrun simctl boot "${SIM_UDID}" >/dev/null 2>&1 || true
xcrun simctl bootstatus "${SIM_UDID}" -b >/dev/null 2>&1 || true

printf 'Running the harness INSIDE the iOS Simulator runtime...\n'
xcrun simctl spawn "${SIM_UDID}" "${WORK_DIR}/verify_apple_winn3_host_contract_ios"
