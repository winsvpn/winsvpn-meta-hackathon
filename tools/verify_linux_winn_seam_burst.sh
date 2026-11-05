#!/usr/bin/env bash
#
# verify_linux_winn_seam_burst.sh — run the Linux Winn seam's UNPACED-BURST
# regression against the REAL cmd/winn-datapath engine, on this machine.
#
# WHY THIS IS A SEPARATE SCRIPT
#
# The Linux seam was recorded as proven because a 4 MiB transfer completed with
# a matching SHA-256. That transfer was moved with `nc` over TCP, whose
# congestion control PACES the sender, so it never created the condition this
# script tests. Correctness and rate are different properties. The paced proof
# could not have caught a burst defect, and did not.
#
# WHAT IT PROVES
#
# It links the real linux/runner/linux_winn_host.cc, starts the real
# winn-datapath engine subprocess, and offers the 4 MiB burst of record at the
# rate that burst actually ran at while a socket on the far side of the whole
# chain records which sequence numbers arrived. A control case bursts the same
# traffic with the seam bypassed, so a failure can never be blamed on the
# harness's own producer or sink.
#
# Baseline BEFORE the fix, measured on an idle arm64 Ubuntu laptop 2026-08-05:
#   4,195 datagrams at 190,034 pkt/s -> 1,112 lost (26.51%), silently,
#   with the kernel's UDP RcvbufErrors moving by exactly 1,112.
# AFTER: 4,195 of 4,195, zero lost, zero kernel drops, 10/10 consecutive runs.
#
# Usage: tools/verify_linux_winn_seam_burst.sh
# Env:   WINN_LINUX_SEAM_ENGINE   use this winn-datapath binary instead of
#                                 building one (for example the path printed by
#                                 tools/winn_release.py verify --release DIR
#                                 --print-artifact datapath-linux-<arch>)
#        WINS_WINN_GO_ARCHIVE     pinned Go archive for the builder's direct
#                                 mode (tools/winn_release.py build-one)
#        WINN_SEAM_BURST_COUNT    datagrams per case (default 4195)
#        WINN_SEAM_SWEEP=1        also print the rate-vs-loss characterisation

set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "${PROJECT_ROOT}"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# The harness executes the Linux host and reads /proc/net/snmp, so it must run
# on Linux. Saying so beats producing a number that means nothing.
[[ "$(uname -s)" == "Linux" ]] \
  || die "this harness runs the Linux Winn host and requires Linux (found $(uname -s)).
       From a Mac: run it in a container, or on a Linux host over ssh."

command -v g++ >/dev/null 2>&1 || die "g++ is required."

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-linux-winn-burst.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

ENGINE="${WINN_LINUX_SEAM_ENGINE:-}"
if [[ -n "${ENGINE}" ]]; then
  [[ -x "${ENGINE}" ]] || die "WINN_LINUX_SEAM_ENGINE is not executable: ${ENGINE}"
  printf 'Using the caller-supplied engine: %s\n' "${ENGINE}"
  printf 'NOTE: this bypasses the freshness guarantee this script otherwise provides.\n'
else
  case "$(uname -m)" in
    aarch64|arm64) TARGET="datapath-linux-arm64" ;;
    x86_64|amd64)  TARGET="datapath-linux-amd64" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  ENGINE="${WORK_DIR}/winn-datapath"
  printf 'Building a fresh winn-datapath engine from the Go source in this tree (%s)...\n' \
    "${TARGET}"
  # Without WINS_WINN_SOURCE_ROOT the builder runs tools/winn_release.py
  # build-one: a sealed two-build of this checkout's committed source (it
  # refuses a dirty tree or a non-git tree) using the pinned Go archive. Its
  # exit status is authoritative; exit 3 means a pinned toolchain is missing.
  BUILD_STATUS=0
  bash tools/build_winn_protocol_engine.sh "${TARGET}" "${ENGINE}" \
    >"${WORK_DIR}/engine-build.log" 2>&1 || BUILD_STATUS=$?
  if [[ "${BUILD_STATUS}" -ne 0 || ! -s "${ENGINE}" ]]; then
    cat "${WORK_DIR}/engine-build.log" >&2
    if [[ "${BUILD_STATUS}" -eq 3 ]]; then
      die "the winn-datapath engine did not build: a pinned toolchain is missing (see TOOLCHAIN-MISSING above)."
    fi
    die "the winn-datapath engine did not build (exit ${BUILD_STATUS})."
  fi
  chmod +x "${ENGINE}"
fi

printf 'Compiling the harness against the REAL linux/runner/linux_winn_host.cc...\n'
# The shipping bar. A warning here is a defect here.
g++ -std=c++17 -O2 -Wall -Wextra -Werror -pthread \
  tools/verify_linux_winn_seam_burst.cc \
  linux/runner/linux_winn_host.cc \
  -o "${WORK_DIR}/verify_linux_winn_seam_burst" \
  || die "the harness did not compile."

printf 'net.core.rmem_max = %s  (SO_RCVBUF is CLAMPED to this; the granted value is reported below)\n' \
  "$(cat /proc/sys/net/core/rmem_max 2>/dev/null || echo 'unreadable')"
printf '\n'

set +e
"${WORK_DIR}/verify_linux_winn_seam_burst" "${ENGINE}"
STATUS=$?
set -e

printf '\n'
if [[ ${STATUS} -eq 0 ]]; then
  printf 'RESULT: PASS\n'
else
  printf 'RESULT: FAIL (exit %d)\n' "${STATUS}"
fi
exit "${STATUS}"
