#!/usr/bin/env bash
# Build the Winn Protocol v3 Windows tun relay for windows/amd64 and
# windows/arm64.
#
# WHAT THIS BUILDS, and why it is not one of the other two Windows binaries.
#
# windows/winn3_engine/ owns the Wintun adapter "winsvpn3" and moves RAW INNER
# IP PACKETS between it and cmd/winn-datapath's `device.kind: loopback-udp`
# seam. It performs no cryptography, holds no key material, makes no routing
# decision and never touches the network. It is not:
#
#   winsvpn_awg_engine.exe  -- windows/awg_engine, which IS AmneziaWG: it owns
#                              the adapter "winsvpn" AND does the cryptography,
#                              and emits already-encrypted outer datagrams.
#   winn-datapath.exe       -- the datapath engine, which under -winn3-profile
#                              IS the winn/3 cryptography.
#   winn_framing_fixture    -- a conformance fixture and never a transport.
#
# Getting those confused is the one mistake on this boundary that puts
# CLEARTEXT ON THE WIRE, which is why this artifact has its own name, its own
# adapter name, its own stop event and its own build script rather than being
# folded into tools/build_windows_winn_engine.sh.
#
# WHY THE NAME MATTERS. windows/runner/winn3_supervisor.cpp resolves
# `winsvpn_winn3_engine.exe` beside the service image and has NO fallback search
# path for it: a supervisor that fell back to another name could start the
# AmneziaWG engine and hand an inner-packet datapath to a layer that already
# encrypted. The output name below and that constant are the same string, and
# changing one without the other produces a legible "not installed beside this
# application" refusal rather than a wrong start.
#
# THE MODULE HAS NO amneziawg-go, DELIBERATELY. windows/winn3_engine/go.mod
# depends on golang.zx2c4.com/wintun directly -- the upstream WireGuard
# project's Wintun binding, which contains no WireGuard protocol code -- pinned
# to the same revision windows/awg_engine already resolves transitively, so both
# Windows binaries drive the same ring code against the same wintun.dll the
# installer ships. Reaching for amneziawg-go's tun wrapper here because it is
# familiar would drag a WireGuard implementation into the v3 datapath, which is
# exactly what the standalone ruling removed from datapath/.
#
# DEV PATH ONLY. Release relays are built by the Winn release driver as
# targets winn3-relay-windows-{amd64,arm64} (tools/winn_release.py, two
# byte-identical builds, signed manifest) and staged by
# tools/build_windows_winn_engine.sh --release DIR or verified directly by
# installer/windows/build_installer.ps1. The Windows installer never invokes
# this script, and its arch-suffixed outputs are never release input. It still
# runs the relay's vet and race tests on this host, and it must name one
# reviewed Go executable through WINS_RELEASE_GO; there is no PATH /
# command -v fallback.

set -euo pipefail

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
relay_dir="${repo_root}/windows/winn3_engine"
output_dir="${1:-${repo_root}/build/windows/winn3}"
pin_manifest="${repo_root}/tools/toolchain-pins.json"
PIN_PYTHON_BIN="/usr/bin/python3"
FILE_BIN="/usr/bin/file"

if [[ ! -f "${relay_dir}/main_windows.go" ]]; then
  die "The v3 relay source is missing at ${relay_dir}/main_windows.go"
fi

read_wins_toolchain_pin() {
  local pin_key="${1:?read_wins_toolchain_pin: missing key}"
  [[ -f "${PIN_PYTHON_BIN}" && -x "${PIN_PYTHON_BIN}" && ! -L "${PIN_PYTHON_BIN}" ]] || \
    die "TOOLCHAIN PIN ERROR: ${PIN_PYTHON_BIN} is required to read ${pin_manifest}."
  [[ -f "${pin_manifest}" && ! -L "${pin_manifest}" ]] || \
    die "TOOLCHAIN PIN ERROR: ${pin_manifest} does not exist; cannot resolve ${pin_key}."
  "${PIN_PYTHON_BIN}" - "${pin_manifest}" "${pin_key}" <<'WINS_PIN_EOF'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
sys.stdout.write(str(value))
WINS_PIN_EOF
}

REQUIRED_GO_VERSION="$(read_wins_toolchain_pin tools.go.version)"
[[ "${REQUIRED_GO_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
  die "TOOLCHAIN PIN ERROR: tools.go.version is not a dotted Go release: ${REQUIRED_GO_VERSION}"

go_bin="${WINS_RELEASE_GO:-}"
[[ -n "${go_bin}" ]] || \
  die "WINS_RELEASE_GO must name the exact reviewed Go executable; ambient PATH go is not used."
case "${go_bin}" in
  /*) ;;
  *) die "WINS_RELEASE_GO must be an absolute path to a regular non-symlink executable." ;;
esac
[[ -f "${go_bin}" && -x "${go_bin}" && ! -L "${go_bin}" ]] || \
  die "WINS_RELEASE_GO must be an absolute regular non-symlink executable: ${go_bin}"

host_os=""
host_arch=""
case "$(uname -s)" in
  Darwin) host_os=darwin ;;
  Linux) host_os=linux ;;
  MINGW*|MSYS*|CYGWIN*) host_os=windows ;;
  *) die "Unsupported Winn v3 relay build host OS: $(uname -s)" ;;
esac
case "$(uname -m)" in
  arm64|aarch64) host_arch=arm64 ;;
  x86_64|amd64) host_arch=amd64 ;;
  *) die "Unsupported Winn v3 relay build host architecture: $(uname -m)" ;;
esac

export GOENV=off
export GOTOOLCHAIN=local
unset GOTOOLDIR
unset GOROOT
unset GOPATH
unset GOMODCACHE

expected_identity="go version go${REQUIRED_GO_VERSION} ${host_os}/${host_arch}"
go_identity="$("${go_bin}" version)"
[[ "${go_identity}" == "${expected_identity}" ]] || \
  die "Reviewed Go toolchain identity mismatch: expected ${expected_identity}; got ${go_identity}"

go_host_os="$("${go_bin}" env GOHOSTOS)"
go_host_arch="$("${go_bin}" env GOHOSTARCH)"
[[ "${go_host_os}" == "${host_os}" && "${go_host_arch}" == "${host_arch}" ]] || \
  die "Reviewed Go host identity mismatch: expected ${host_os}/${host_arch}; got ${go_host_os}/${go_host_arch}"

echo "Winn Protocol v3 relay toolchain: ${go_identity} (${go_bin})"

if [[ -e "${output_dir}" && ( ! -d "${output_dir}" || -L "${output_dir}" ) ]]; then
  die "Winn v3 relay output directory must be a non-symlink directory: ${output_dir}"
fi
mkdir -p "${output_dir}"
[[ -d "${output_dir}" && ! -L "${output_dir}" ]] || \
  die "Winn v3 relay output directory is not a regular directory: ${output_dir}"

for arch in amd64 arm64; do
  rm -f \
    "${output_dir}/winsvpn_winn3_engine_${arch}.exe" \
    "${output_dir}/winsvpn_winn3_engine_${arch}.exe.provenance.json"
done
rm -f "${output_dir}/winsvpn_winn3_engine.go-identity"

architectures=(amd64 arm64)
expected_machine=("x86-64" "Aarch64")

verify_pe() {
  local path="$1" arch="$2" machine="$3"
  if [[ ! -f "${path}" ]]; then
    echo "MISSING: ${path} (windows/${arch})" >&2
    exit 1
  fi
  [[ -x "${FILE_BIN}" && ! -L "${FILE_BIN}" ]] || \
    die "PE identity verifier is unavailable at ${FILE_BIN}; refusing windows/${arch}."
  local description
  description="$("${FILE_BIN}" -b "${path}")"
  if [[ "${description}" != *"PE32+"* || "${description}" != *"${machine}"* ]]; then
    echo "WRONG MACHINE TYPE for windows/${arch}: ${description}" >&2
    exit 1
  fi
  echo "  OK windows/${arch}: ${description}"
  if command -v shasum >/dev/null 2>&1; then
    printf '  '; shasum -a 256 "${path}"
  elif command -v sha256sum >/dev/null 2>&1; then
    printf '  '; sha256sum "${path}"
  fi
}

require_windows_target_identity() {
  local arch="$1" target_os target_arch
  target_os="$("${go_bin}" env GOOS)"
  target_arch="$("${go_bin}" env GOARCH)"
  [[ "${target_os}" == "windows" && "${target_arch}" == "${arch}" ]] || \
    die "Intended target identity mismatch: expected windows/${arch}; got ${target_os}/${target_arch}"
}

# The PORTABLE half is tested first, on this host, before anything is shipped.
#
# packet.go carries no build tag on purpose: the inner-packet rules -- what may
# cross the relay, and the refusal of the 1223-byte trap MTU -- are the part
# most worth testing, and if they lived in the Wintun half they would be
# untestable everywhere the work is actually done. relay.go's two pumps are
# reached through a three-method interface that relay_test.go implements over a
# channel and main_windows.go implements over wintun.Session, so every decision
# about whether a packet may move is the same code in both cases and is
# exercised here.
echo "Winn Protocol v3 relay: portable half, on this host"
(
  cd "${relay_dir}"
  GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOENV=off \
    "${go_bin}" vet ./...
  GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOENV=off \
    "${go_bin}" test -race ./...
) | sed 's/^/  /'

echo "Winn Protocol v3 relay (windows/winn3_engine):"
for index in "${!architectures[@]}"; do
  arch="${architectures[$index]}"
  output="${output_dir}/winsvpn_winn3_engine_${arch}.exe"
  (
    cd "${relay_dir}"
    export CGO_ENABLED=0
    export GOOS=windows
    export GOARCH="${arch}"
    export GOTOOLCHAIN=local
    export GOFLAGS=-mod=readonly
    export GOENV=off
    unset GOTOOLDIR
    require_windows_target_identity "${arch}"
    "${go_bin}" build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
      -o "${output}" .
  )
  verify_pe "${output}" "${arch}" "${expected_machine[$index]}"
done

{
  printf '%s\n' "${go_identity}"
  printf 'executable %s\n' "${go_bin}"
  printf 'role relay\n'
  printf 'targets windows/amd64 windows/arm64\n'
} >"${output_dir}/winsvpn_winn3_engine.go-identity"

# The installer stages this as `winsvpn_winn3_engine.exe`, unsuffixed, beside
# the service image -- which is the exact name winn3_supervisor.cpp resolves.
echo
echo "STAGE AS: winsvpn_winn3_engine.exe (no arch suffix), beside"
echo "          wins_vpn_tunnel_service.exe and winn-datapath.exe."
echo "BUILT AND VERIFIED, NOT EXECUTED: these are Windows binaries and no"
echo "Windows host ran either of them. The portable half above WAS executed,"
echo "on this host, under -race."
echo "WINDOWS WINN3 RELAY BUILD: PASS (amd64 + arm64)"
