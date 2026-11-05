#!/usr/bin/env bash
#
# verify_apple_winn3_lifecycle.sh: the Apple host consuming the Winn v3
# engine's lifecycle status (Round A3, lane L6).
#
# Compiles every apple/WinsTunnelCore Swift source with
# tools/verify_apple_winn3_lifecycle_harness.swift and runs it. The harness is
# pure: it feeds status documents through the provider's own sampler, promotion
# gate and lifecycle verdict, so it needs no Go archive, starts no tunnel,
# installs no network settings and opens no socket.
#
# Usage: tools/verify_apple_winn3_lifecycle.sh

set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "${PROJECT_ROOT}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || die "this harness compiles the Apple host sources and requires macOS."
command -v xcrun >/dev/null 2>&1 || die "full Xcode command line tools are required."

SWIFTC_BIN="$(xcrun -f swiftc)"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
TARGET="$(uname -m)-apple-macos13.0"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-apple-winn3-lifecycle.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

# Globbed, not listed, so a new core file can never silently drop out.
WINS_TUNNEL_CORE_SOURCES=(apple/WinsTunnelCore/*.swift)
[[ -e "${WINS_TUNNEL_CORE_SOURCES[0]}" ]] || die "no apple/WinsTunnelCore/*.swift sources found."

"${SWIFTC_BIN}" -sdk "${SDK_PATH}" -target "${TARGET}" \
  "${WINS_TUNNEL_CORE_SOURCES[@]}" \
  tools/verify_apple_winn3_lifecycle_harness.swift \
  -framework CoreFoundation \
  -framework Foundation \
  -framework NetworkExtension \
  -framework Security \
  -o "${WORK_DIR}/verify_apple_winn3_lifecycle"

"${WORK_DIR}/verify_apple_winn3_lifecycle"
