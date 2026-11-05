#!/usr/bin/env bash
#
# verify_apple_winn_seam.sh — run the Apple Winn seam end to end against the
# REAL Go datapath, in one process, on this machine.
#
# WHY THIS EXISTS, AND WHY IT BUILDS ITS OWN ARCHIVE
#
# tools/verify_winn_abi_conformance.sh proves the C ABI agrees. It cannot prove
# the JSON contract agrees, and those are two different things: the wrapper's
# datapath.Config document is decoded with DisallowUnknownFields, so a field the
# archive does not know is a hard create-time refusal that no signature check
# can see.
#
# That failure is not hypothetical. The archives checked into
# tools/winn_conformance_build_out/ were built before s1..s4 were added to
# datapath.AWGHeaderTypes. Their generated header is BYTE-IDENTICAL to a current
# one — the C ABI genuinely did not change — so ABI conformance passes against
# them while WinnTunnelCreate refuses every configuration the wrapper actually
# produces, with `json: unknown field "s1"`.
#
# So this script builds a fresh archive from the Go source in this tree, every
# run, into a temporary directory. A stale artifact cannot produce a false pass,
# and no other lane's build output is touched.
#
# WHAT IT PROVES
#
# It links the real apple/WinsTunnelCore Swift host, the real
# apple/EngineWrappers/WinsWinnPacketEngine.m, and that fresh archive into one
# executable and drives WinsNativePacketTunnelEngine.start(). Only AmneziaWG is
# stubbed, because wgTurnOn() needs a utun device that exists only inside a
# NetworkExtension; the stub records the launch descriptor it was handed, which
# is what makes the ordering claim checkable — the seam must have been created,
# started, and asked for its ephemeral port before that string could exist.
#
# Covered: carrier selection, the transport /32 that keeps the engine's outer
# socket off the tunnel, every validate() refusal, the UAPI endpoint repoint,
# real datagrams relayed both ways through the Go engine, peer pinning, teardown,
# and the fail-closed rule that an unstartable Winn seam must never fall through
# to a classical AmneziaWG start.
#
# Usage: tools/verify_apple_winn_seam.sh
# Env:   WINN_APPLE_SEAM_ARCHIVE  use this archive instead of building one

set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "${PROJECT_ROOT}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# The harness executes, so it must be built for the machine running it. The
# datapath lane produces Apple archives for arm64 only.
[[ "$(uname -s)" == "Darwin" ]] || die "this harness runs the Apple engine and requires macOS."
[[ "$(uname -m)" == "arm64" ]] \
  || die "this harness runs the Apple engine natively and requires an arm64 Mac; the datapath lane ships no x86_64 Apple archive."

command -v xcrun >/dev/null 2>&1 || die "full Xcode command line tools are required."

CLANG_BIN="$(xcrun -f clang)"
SWIFTC_BIN="$(xcrun -f swiftc)"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
TARGET="arm64-apple-macos11.0"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-apple-winn-seam.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

ARCHIVE="${WINN_APPLE_SEAM_ARCHIVE:-}"
if [[ -n "${ARCHIVE}" ]]; then
  [[ -f "${ARCHIVE}" ]] || die "WINN_APPLE_SEAM_ARCHIVE does not exist: ${ARCHIVE}"
  printf 'Using the caller-supplied datapath archive: %s\n' "${ARCHIVE}"
  printf 'NOTE: this bypasses the freshness guarantee this script exists to provide.\n'
else
  command -v go >/dev/null 2>&1 || die "Go is required to build the datapath archive this harness runs against."
  ARCHIVE="${WORK_DIR}/libwinn-datapath-darwin-arm64.a"
  printf 'Building a fresh Winn datapath c-archive from the Go source in this tree...\n'
  # The build script's own validator leaves a RETURN trap that re-fires in the
  # caller under `set -u`, so a successful build can still exit nonzero. The
  # artifact is what is checked, not the status.
  bash tools/build_winn_protocol_engine.sh datapath-archive-darwin-arm64 "${ARCHIVE}" \
    >"${WORK_DIR}/archive-build.log" 2>&1 || true
  if [[ ! -s "${ARCHIVE}" ]]; then
    cat "${WORK_DIR}/archive-build.log" >&2
    die "the Winn datapath archive was not produced."
  fi
fi

printf 'Compiling the AmneziaWG stand-in and the real Winn wrapper...\n'
"${CLANG_BIN}" -target "${TARGET}" -isysroot "${SDK_PATH}" \
  -fobjc-arc -Wall -Wextra -Werror \
  -c tools/verify_apple_winn_seam_awg_stub.m -o "${WORK_DIR}/awg_stub.o"

# Built at the same -Wall -Wextra -Werror bar as the shipping wrapper, and with
# the same source, so this cannot pass against something the real build rejects.
"${CLANG_BIN}" -target "${TARGET}" -isysroot "${SDK_PATH}" \
  -fobjc-arc -Wall -Wextra -Werror \
  -I apple/EngineWrappers \
  -c apple/EngineWrappers/WinsWinnPacketEngine.m -o "${WORK_DIR}/winn_wrapper.o"

printf 'Linking the harness against the real Swift host...\n'
# Every WinsTunnelCore source, globbed rather than listed, so a new core file
# can never silently drop out of coverage.
WINS_TUNNEL_CORE_SOURCES=(apple/WinsTunnelCore/*.swift)
[[ -e "${WINS_TUNNEL_CORE_SOURCES[0]}" ]] || die "no apple/WinsTunnelCore/*.swift sources found."

# -export_dynamic puts the wrapper's symbols in the executable's dynamic symbol
# table, which is how WinsNativeEngineComponent.linkedProcessHandle finds a
# component linked into the process instead of dlopened from a bundle -- the
# same path the appex takes for a statically linked engine.
"${SWIFTC_BIN}" -sdk "${SDK_PATH}" -target "${TARGET}" \
  "${WINS_TUNNEL_CORE_SOURCES[@]}" \
  tools/verify_apple_winn_seam_harness.swift \
  "${WORK_DIR}/awg_stub.o" \
  "${WORK_DIR}/winn_wrapper.o" \
  -Xlinker -force_load -Xlinker "${ARCHIVE}" \
  -framework CoreFoundation \
  -framework Foundation \
  -framework Security \
  -lresolv \
  -Xlinker -export_dynamic \
  -o "${WORK_DIR}/verify_apple_winn_seam"

"${WORK_DIR}/verify_apple_winn_seam"
