#!/usr/bin/env bash
set -Eeuo pipefail
# Engine bytes depend on the builder's umask (archive member and output modes
# are recorded); the release producer runs under umask 077, so every build
# does, including a direct WP-A1 rebuild (R11a, measured 2026-10-15).
umask 077

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
APPLE_ENGINE_WRAPPER_SOURCE_DIR="${APPLE_ENGINE_WRAPPER_SOURCE_DIR:-${PROJECT_ROOT}/apple/EngineWrappers}"
APPLE_WG_GO_OUTPUT_DIR="${APPLE_WG_GO_OUTPUT_DIR:-${PROJECT_ROOT}/.artifacts/apple-wg-go}"
APPLE_ENGINE_WRAPPER_OUTPUT_ROOT="${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT:-${PROJECT_ROOT}/apple/EngineArtifacts}"
APPLE_AWG_BRIDGE_PROVENANCE_FILE="${APPLE_WG_GO_OUTPUT_DIR}/apple_awg_31_bridge_provenance.json"
APPLE_AWG_ENGINE_PROVENANCE_FILE="${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}/apple_awg_31_engine_provenance.json"
APPLE_WINN_ENGINE_PROVENANCE_FILE="${APPLE_WINN_ENGINE_PROVENANCE_FILE:-${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}/apple_winn_v3_engine_provenance.json}"
APPLE_XRAY_ENGINE_PROVENANCE_FILE="${APPLE_XRAY_ENGINE_PROVENANCE_FILE:-${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}/apple_xray_vless_ws_engine_provenance.json}"
APPLE_XRAY_WRAPPER_SOURCE="${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsXrayVlessWsTransport.m"
APPLE_AWG_WRAPPER_SOURCE="${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsAmneziaWGPacketEngine.m"
APPLE_XRAY_ENGINE_PROVENANCE_SCHEMA="${PROJECT_ROOT}/tools/apple_xray_vless_ws_engine_provenance.schema.json"
APPLE_XRAY_ENGINE_PROVENANCE_TOOL="${PROJECT_ROOT}/tools/apple_xray_vless_ws_engine_provenance.py"
WINS_WRAPPER_TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
WINN_EXPECTED_MODULE="winsvpn.local/winnprotocol"
# The sealed release driver and its pinned authority key are resolved beside
# this script, never through PROJECT_ROOT, so an environment override cannot
# substitute the verifier that accepts a release.
WINN_RELEASE_DRIVER="${WINS_WRAPPER_TOOLS_DIR}/winn_release.py"
WINN_RELEASE_AUTHORITY="${WINS_WRAPPER_TOOLS_DIR}/winn_release_authority.json"
WINN_RELEASE_PYTHON="/usr/bin/python3"
WINS_WINN_RELEASE_DIR="${WINS_WINN_RELEASE_DIR:-}"
WINS_WINN_ALLOW_UNSIGNED=0
APPLE_ENGINE_WRAPPER_ARCHS="${APPLE_ENGINE_WRAPPER_ARCHS:-}"
WINS_SKIP_APPLE_WG_GO_BUILD="${WINS_SKIP_APPLE_WG_GO_BUILD:-0}"
WINN_DATAPATH_ARCHIVE_DIR="${WINN_DATAPATH_ARCHIVE_DIR:-${PROJECT_ROOT}/tools/winn_conformance_build_out}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
APPLE_MACOS_DEPLOYMENT_TARGET="${APPLE_MACOS_DEPLOYMENT_TARGET:-13.0}"
APPLE_IOS_DEPLOYMENT_TARGET="${APPLE_IOS_DEPLOYMENT_TARGET:-13.0}"
APPLE_IOS_SIMULATOR_DEPLOYMENT_TARGET="${APPLE_IOS_SIMULATOR_DEPLOYMENT_TARGET:-14.0}"

APPLE_AWG_EXPECTED_REPOSITORY="https://github.com/amnezia-vpn/amneziawg-apple.git"
APPLE_AWG_EXPECTED_TAG="v3.1.20260814"
APPLE_AWG_EXPECTED_COMMIT="fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d"
APPLE_AWG_EXPECTED_TREE="24183de0cc22b957ff9e34ac3494a80f515ac565"
APPLE_AWG_EXPECTED_GENERATION="3.1"
APPLE_AWG_EXPECTED_GO_VERSION="1.27.1"
APPLE_AWG_EXPECTED_GO_MOD_SHA256="790252dad6cad8aa668ccc4dafdfdac4f2fa3d3fbefce16ded750f0a46cabe0d"
APPLE_AWG_EXPECTED_GO_SUM_SHA256="1a806e7973118c0ce8832e15d246fea0c44335a31fc4a0abe36a2ed165fada9d"
APPLE_AWG_EXPECTED_GO_DARWIN_ARM64_SHA256="ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12"
APPLE_AWG_EXPECTED_GO_DARWIN_AMD64_SHA256="8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4"
APPLE_AWG_EXPECTED_XRAY_VERSION="v1.260924.0"
APPLE_AWG_EXPECTED_XRAY_COMMIT="77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3"
APPLE_AWG_EXPECTED_XRAY_SUM="h1:4PniqnMxVxC54OdTx3e73BOMH/GD6jf85iaRyApAwGQ="
APPLE_AWG_EXPECTED_XRAY_GO_MOD_SUM="h1:VwJOtL3vj2w+8TWa6MZE1q88NsfrWvOXGJ+5wZ2N2ro="
# Upstream publishes no zip digest. This is the SHA-256 of the
# amnezia-xray-core v1.260924.0 module zip served by proxy.golang.org, measured
# 2026-10-15 (its h1: dirhash equals APPLE_AWG_EXPECTED_XRAY_SUM and the
# sum.golang.org record); it must equal AMNEZIA_XRAY_ZIP_SHA256 in
# tools/build_apple_wg_go_bridge.sh.
APPLE_AWG_EXPECTED_XRAY_ZIP_SHA256="7df5ebc400da6cc4ab13f5578e2fd19b855f98807f1ef1d86a30afc2cd213c40"

AWG_REQUIRED_SYMBOLS=(
  wins_amneziawg_packet_engine_contract_version
  wins_amneziawg_packet_engine_create
  wins_amneziawg_packet_engine_start
  wins_amneziawg_packet_engine_listen_port
  wins_amneziawg_packet_engine_stop
  wins_amneziawg_packet_engine_destroy
  wgTurnOn
  wgTurnOff
  LibXrayRunXray
  LibXrayStopXray
  LibXraySetSockCallback
)

XRAY_REQUIRED_SYMBOLS=(
  wins_xray_vless_ws_transport_contract_version
  wins_xray_vless_ws_transport_configure
  wins_xray_vless_ws_transport_start
  wins_xray_vless_ws_transport_stop
)

# Production imports that a provenance-bound delivered dylib must retain.
# Compiling WinsXrayVlessWsTransport.m in a test harness is not evidence that
# the staged iOS/macos/simulator dylib was built from that source. These four
# undefined symbols are the socket-protection path; a stale dylib can still
# export the v1 C ABI while lacking all of them.
XRAY_REQUIRED_UNDEFINED_SYMBOLS=(
  LibXraySetSockCallback
  dup2
  getifaddrs
  setsockopt
)

# Winn Protocol is the additive second packet carrier, and an OPTIONAL
# component: tools/stage_apple_engine_artifacts.sh already supports it, and an
# absent Winn artifact never fails a build. Until this target existed nothing
# produced one, so no Winn artifact could be built for Apple at all.
#
# The first five symbols are the v1 Win's VPN C ABI the Swift loader looks up
# through dlsym; they are the reason the wrapper exists, because a dylib made
# from the raw c-archive exports none of them.
#
# The last nine are the datapath archive's own exports, and they are required
# here on purpose. The wrapper is built -fvisibility=hidden, so a Winn dylib
# built against apple/EngineWrappers/WinnTunnelTestDouble.c, which is compiled
# into the dylib rather than force-loaded from an archive, cannot export them.
# Requiring them is therefore a gate that tells a real archive from the test
# double, which the staging gate on its own cannot do.
#
# wins_winn_packet_engine_awg_seam_port is the additive sixth wrapper symbol,
# outside the v1 five-symbol carrier ABI the generic loader resolves. It reports
# the ephemeral loopback port the AmneziaWG peer endpoint must be rewritten to,
# and it is required here because losing it would not break the build: the
# wrapper would load, start, and carry nothing, because the AWG engine would
# still be talking to the gateway from its own socket.
#
# wins_winn_packet_engine_seam_stats and wins_winn_packet_engine_status_json are
# the additive seventh and eighth, and they are gated for the same reason: their
# absence is silent. The seam lost 34% of an unpaced burst on 2026-08-04 without
# a single counter moving anywhere in the system, because the datagrams were
# discarded by the kernel before any code could see them. seam_stats is the only
# view of that boundary; status_json is the Go engine's view, which stayed at a
# healthy zero throughout. A build that quietly stopped exporting either one
# would restore exactly the blindness that let the defect ship.
#
# WinnTunnelCreateWinn3 is the additive create for the STANDALONE winn/3 shape,
# and it is gated here because its absence was, until 2026-08-09, completely
# silent all the way into the App Store. Every symbol above it belongs to the
# v1 relay carrier, so a dylib built from a datapath archive that predates
# winn/3 exports all seventeen of them, validates clean, stages, and ships. That
# is not hypothetical either: the dylib staged at apple/EngineArtifacts on
# 2026-08-05 11:30 exported exactly ten WinnTunnel* symbols and none of them was
# this one, while all 122 live winn3/*.go files were newer than it. Runner.app,
# PacketTunnel.appex, WinsWinnPacketEngine.framework and the 1.0.14+29 App Store
# .ipa each contained ZERO winn3 strings as a direct result.
#
# The runtime shape of the failure is what makes gating it mandatory rather than
# merely tidy: the Apple pump resolves this create through dlsym, so a missing
# export is not a link error. It is dlsym returning NULL, which the Swift host
# reports as StartError.symbolsUnavailable, a start failure with no build,
# stage or sign step anywhere upstream having noticed. The promotion predicate
# in WinsWinn3HostContract.swift is correct and simply never runs.
WINN_REQUIRED_SYMBOLS=(
  wins_winn_packet_engine_contract_version
  wins_winn_packet_engine_create
  wins_winn_packet_engine_start
  wins_winn_packet_engine_stop
  wins_winn_packet_engine_destroy
  wins_winn_packet_engine_awg_seam_port
  wins_winn_packet_engine_expect_awg_port
  wins_winn_packet_engine_seam_stats
  wins_winn_packet_engine_status_json
  WinnTunnelFreeString
  WinnTunnelContractVersion
  WinnTunnelProtocolVersion
  WinnTunnelMaxDatagram
  WinnTunnelCreate
  WinnTunnelCreateWithCarrier
  WinnTunnelCreateWinn3
  WinnTunnelWriteInbound
  WinnTunnelReadOutbound
  WinnTunnelStatusJSON
  WinnTunnelClose
)

WINN_COMMON_REQUIRED_SYMBOLS=(
  WinnTunnelFreeString
  WinnTunnelContractVersion
  WinnTunnelProtocolVersion
  WinnTunnelMaxDatagram
  WinnTunnelWriteInbound
  WinnTunnelReadOutbound
  WinnTunnelStatusJSON
  WinnTunnelClose
)

WINN_RELAY_REQUIRED_SYMBOLS=(
  WinnTunnelCreate
  WinnTunnelCreateWithCarrier
)

WINN_CORE_REQUIRED_SYMBOLS=(
  WinnTunnelCreateWinn3
)

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

WINS_SHA256_BIN="/usr/bin/shasum"
WINS_LIPO_BIN="/usr/bin/lipo"
WINS_FILE_BIN="/usr/bin/file"
WINS_OTOOL_BIN="/usr/bin/otool"
WINS_NM_BIN="/usr/bin/nm"
WINS_MKTEMP_BIN="/usr/bin/mktemp"
WINS_CP_BIN="/bin/cp"
WINS_STRIP_BIN="/usr/bin/strip"

# Bash 3.2 ignores `set -e` for `local x=$(cmd)` and for many commands inside
# `$(function)`. Hash helpers therefore return status explicitly and callers
# must use `|| die`.
wins_sha256() {
  local path="$1"
  local digest=""
  [[ -n "${path}" ]] || return 1
  [[ -f "${path}" && ! -L "${path}" && -s "${path}" ]] || return 1
  [[ -x "${WINS_SHA256_BIN}" && ! -L "${WINS_SHA256_BIN}" ]] || return 1
  digest="$("${WINS_SHA256_BIN}" -a 256 "${path}")" || return 1
  digest="${digest%% *}"
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${digest}"
}

stable_snapshot_file() {
  local src="$1"
  local dest="$2"
  command -v "${PYTHON_BIN}" >/dev/null 2>&1 || return 1
  "${PYTHON_BIN}" - "${src}" "${dest}" <<'PY'
import os
import pathlib
import stat
import sys

src = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
nofollow = getattr(os, "O_NOFOLLOW", 0)
if not nofollow:
    raise SystemExit("O_NOFOLLOW is required for Apple engine snapshots")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
fd = os.open(src, flags)
try:
    before = os.fstat(fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_uid != os.getuid()
    ):
        raise SystemExit(f"unsafe snapshot source: {src}")
    chunks = []
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    after = os.fstat(fd)
finally:
    os.close(fd)
latest = src.lstat()
identity = lambda value: (
    value.st_dev,
    value.st_ino,
    value.st_uid,
    value.st_mode,
    value.st_nlink,
    value.st_size,
    value.st_mtime_ns,
    value.st_ctime_ns,
)
if identity(before) != identity(after) or identity(after) != identity(latest):
    raise SystemExit(f"snapshot source changed: {src}")
payload = b"".join(chunks)
if not payload:
    raise SystemExit(f"snapshot source is empty: {src}")
dest.parent.mkdir(parents=True, exist_ok=True)
write_flags = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | nofollow
)
out = os.open(dest, write_flags, 0o600)
try:
    view = memoryview(payload)
    while view:
        written = os.write(out, view)
        if written <= 0:
            raise SystemExit("short snapshot write")
        view = view[written:]
    os.fsync(out)
    info = os.fstat(out)
    if info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"snapshot is not a single-link regular file: {dest}")
finally:
    os.close(out)
PY
}

# Fully resolve a path to a real on-disk file, on both GNU and BSD userlands.
# GNU realpath takes -e; the BSD realpath macOS ships does not, and already
# fails on a path that does not exist, so the fallback is equivalent. Without
# this fallback ensure_tools below died on every macOS host, which is the only
# host that can run this script at all.
resolve_real_file() {
  realpath -e -- "$1" 2>/dev/null && return 0
  realpath -- "$1" 2>/dev/null && return 0
  return 1
}

ensure_tools() {
  command -v xcrun >/dev/null 2>&1 || die "full Xcode command line tools are required."
  command -v git >/dev/null 2>&1 || die "git is required."
  command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "Python 3 is required."
  # xcrun -f only proved a tool resolved *once*, at preflight time; every
  # actual build/inspection call below then re-resolved the same tool name
  # through xcrun again, with no proof any of those calls landed on the
  # same real, on-disk regular file rather than a symlink, alias, or shell
  # function shadowing it in between. Resolve each once here, verify it,
  # and thread the same resolved path through every call site below.
  local tool candidate resolved
  for tool in clang nm vtool lipo ar otool file strip; do
    candidate="$(xcrun -f "${tool}" 2>/dev/null || true)"
    [[ -n "${candidate}" ]] || die "${tool} from Xcode is required."
    resolved="$(resolve_real_file "${candidate}" || true)"
    [[ -n "${resolved}" && -f "${resolved}" && -x "${resolved}" && ! -L "${resolved}" ]] \
      || die "${tool} from Xcode must resolve to a real regular executable file, not a symlink: ${candidate}"
    case "${tool}" in
      clang) CLANG_BIN="${resolved}" ;;
      nm) NM_BIN="${resolved}" ;;
      vtool) VTOOL_BIN="${resolved}" ;;
      lipo) LIPO_BIN="${resolved}" ;;
      ar) AR_BIN="${resolved}" ;;
      otool) OTOOL_BIN="${resolved}" ;;
      file) FILE_BIN="${resolved}"; WINS_FILE_BIN="${resolved}" ;;
      strip) STRIP_BIN="${resolved}"; WINS_STRIP_BIN="${resolved}" ;;
    esac
  done
}

platform_output_dir() {
  case "$1" in
    macosx) printf '%s/macos\n' "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}" ;;
    iphoneos) printf '%s/ios/iphoneos\n' "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}" ;;
    iphonesimulator) printf '%s/ios/iphonesimulator\n' "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}" ;;
    *) die "Unknown Apple platform '$1'." ;;
  esac
}

expected_platform() {
  case "$1" in
    macosx) printf 'MACOS\n' ;;
    iphoneos) printf 'IOS\n' ;;
    iphonesimulator) printf 'IOSSIMULATOR\n' ;;
    *) die "Unknown Apple platform '$1'." ;;
  esac
}

target_triple() {
  local platform="$1"
  local minos="$2"
  local arch="$3"
  case "${platform}" in
    macosx) printf '%s-apple-macos%s\n' "${arch}" "${minos}" ;;
    iphoneos) printf '%s-apple-ios%s\n' "${arch}" "${minos}" ;;
    iphonesimulator) printf '%s-apple-ios%s-simulator\n' "${arch}" "${minos}" ;;
    *) die "Unknown Apple platform '$platform'." ;;
  esac
}

platform_archs() {
  if [[ -n "${APPLE_ENGINE_WRAPPER_ARCHS// }" ]]; then
    printf '%s\n' "${APPLE_ENGINE_WRAPPER_ARCHS}"
    return 0
  fi

  case "$1" in
    macosx) printf 'arm64 x86_64\n' ;;
    iphoneos) printf 'arm64\n' ;;
    iphonesimulator) printf 'arm64 x86_64\n' ;;
    *) die "Unknown Apple platform '$1'." ;;
  esac
}

archive_go_object_metadata() {
  local archive="$1"
  local arch="$2"
  local tmp_dir snapshot archs kind
  tmp_dir="$("${WINS_MKTEMP_BIN}" -d "${TMPDIR:-/tmp}/wins-wrapper-meta.XXXXXX")" \
    || die "Could not create archive metadata directory."
  snapshot="${tmp_dir}/snapshot.a"
  stable_snapshot_file "${archive}" "${snapshot}" \
    || die "Could not snapshot archive ${archive}."
  kind="$("${WINS_FILE_BIN}" -b "${snapshot}")" \
    || die "Could not classify archive ${archive}."
  archs="$("${LIPO_BIN}" -archs "${snapshot}")" \
    || die "Could not read architectures from ${archive}."
  [[ -n "${archs// }" ]] || die "No inspectable architectures in ${archive}."
  # A 1-architecture Mach-O universal wrapper is still fat. Copying it as
  # thin.a makes `ar -x go.o` fail, which is how an iphoneos arm64-only
  # libwg-go.a blocked AWG wrapper rebinding after the live bridge rebuild.
  # Copy only a true thin ar archive; always lipo -thin universal inputs.
  if [[ "${archs}" == "${arch}" && "${kind}" != *[Uu]niversal* ]]; then
    "${WINS_CP_BIN}" "${snapshot}" "${tmp_dir}/thin.a" \
      || die "Could not copy already-thin archive ${archive}."
  else
    [[ " ${archs} " == *" ${arch} "* ]] \
      || die "${archive} is missing architecture ${arch}; found ${archs}."
    [[ "${kind}" == *[Uu]niversal* || "${kind}" == *"Mach-O"* ]] \
      || die "Refusing a thin substitute for ${arch} from non-fat ${archive} (${kind}; found ${archs})."
    "${LIPO_BIN}" "${snapshot}" -thin "${arch}" -output "${tmp_dir}/thin.a" \
      || die "Refusing a thin substitute for ${arch} from ${archive} (found ${archs})."
  fi
  (cd "${tmp_dir}" && "${AR_BIN}" -x thin.a go.o)
  [[ -f "${tmp_dir}/go.o" ]] || die "Could not extract go.o from ${archive}."
  "${VTOOL_BIN}" -show-build "${tmp_dir}/go.o"
  rm -rf "${tmp_dir}"
}

archive_minos() {
  local archive="$1"
  local arch="$2"
  local minos
  minos="$(archive_go_object_metadata "${archive}" "${arch}" \
    | awk '/^[[:space:]]*minos[[:space:]]+[0-9.]+[[:space:]]*$/ { print $2; exit }')"
  [[ -n "${minos}" ]] || die "Could not read minos from ${archive}."
  printf '%s\n' "${minos}"
}

require_symbols() {
  local binary="$1"
  shift
  local symbols
  symbols="$("${NM_BIN}" -gU "${binary}" 2>/dev/null | awk '{ print $NF }' | sed 's/^_//' | sort -u)"
  [[ -n "${symbols}" ]] || die "No exported symbols found in ${binary}."
  local symbol
  for symbol in "$@"; do
    grep -qx "${symbol}" <<<"${symbols}" \
      || die "Missing symbol ${symbol} in ${binary}."
  done
}

require_undefined_symbols() {
  local binary="$1"
  shift
  local archs arch nm_out symbol
  archs="$("${LIPO_BIN}" -archs "${binary}" 2>/dev/null || true)"
  [[ -n "${archs// }" ]] || die "No inspectable architectures in ${binary}."
  [[ -x "${WINS_NM_BIN}" && ! -L "${WINS_NM_BIN}" ]] \
    || die "Apple Xray import inspection requires absolute /usr/bin/nm."
  for arch in ${archs}; do
    nm_out="$("${NM_BIN:-${WINS_NM_BIN}}" -m -arch "${arch}" "${binary}" 2>/dev/null || true)"
    [[ -n "${nm_out}" ]] || die "No Mach-O symbols found in ${binary} slice ${arch}."
    for symbol in "$@"; do
      grep -E "undefined.*[[:space:]]_${symbol}([[:space:]]|$)" <<<"${nm_out}" >/dev/null \
        || die "Missing required production import ${symbol} in ${binary} slice ${arch}."
    done
  done
}

require_platform() {
  local binary="$1"
  local platform="$2"
  local expected
  expected="$(expected_platform "${platform}")"
  local platforms
  platforms="$("${VTOOL_BIN}" -show-build "${binary}" 2>/dev/null \
    | awk '/^[[:space:]]*platform[[:space:]]+[A-Z0-9_]+[[:space:]]*$/ { print $2 }' \
    | sort -u)"
  [[ -n "${platforms}" ]] || die "Missing LC_BUILD_VERSION metadata in ${binary}."
  local actual
  for actual in ${platforms}; do
    [[ "${actual}" == "${expected}" ]] \
      || die "${binary} targets ${actual}; expected ${expected}."
  done
}

require_minimum_os() {
  local binary="$1"
  local platform="$2"
  local arch actual expected
  for arch in $("${LIPO_BIN}" -archs "${binary}"); do
    case "${platform}:${arch}" in
      macosx:*) expected="${APPLE_MACOS_DEPLOYMENT_TARGET}" ;;
      iphoneos:*) expected="${APPLE_IOS_DEPLOYMENT_TARGET}" ;;
      # The reviewed Go bridge builds both simulator slices at the arm64
      # simulator floor, while the independently built Winn x86_64 datapath
      # archive retains the iOS 13 floor. Both are simulator-only and valid;
      # arm64 must remain at 14 because that is the reviewed Apple-silicon
      # simulator target.
      iphonesimulator:arm64) expected="${APPLE_IOS_SIMULATOR_DEPLOYMENT_TARGET}" ;;
      iphonesimulator:x86_64) expected="${APPLE_IOS_DEPLOYMENT_TARGET} ${APPLE_IOS_SIMULATOR_DEPLOYMENT_TARGET}" ;;
      *) die "Unknown Apple platform/architecture '${platform}:${arch}'." ;;
    esac
    actual="$("${VTOOL_BIN}" -arch "${arch}" -show-build "${binary}" 2>/dev/null \
      | awk '/^[[:space:]]*minos[[:space:]]+[0-9.]+[[:space:]]*$/ { print $2; exit }')"
    [[ -n "${actual}" ]] || die "Missing minimum OS metadata for ${arch} in ${binary}."
    [[ " ${expected} " == *" ${actual} "* ]] \
      || die "${binary} ${arch} has minimum OS ${actual}; expected one of ${expected}."
  done
}

require_archs() {
  local binary="$1"
  local required_archs="$2"
  local archs
  archs="$("${LIPO_BIN}" -archs "${binary}" 2>/dev/null || true)"
  [[ -n "${archs// }" ]] || die "No inspectable architectures in ${binary}."
  local required_arch
  for required_arch in ${required_archs}; do
    [[ " ${archs} " == *" ${required_arch} "* ]] \
      || die "${binary} is missing architecture ${required_arch}; found ${archs}."
  done
}

require_install_name() {
  local binary="$1"
  local expected="$2"
  local arch install_name
  for arch in $("${LIPO_BIN}" -archs "${binary}"); do
    install_name="$(${OTOOL_BIN} -arch "${arch}" -D "${binary}" 2>/dev/null \
      | awk 'NF && $0 !~ / \(architecture / { value=$0 } END { print value }')"
    [[ "${install_name}" == "${expected}" ]] \
      || die "${binary} ${arch} has install name ${install_name:-<missing>}; expected ${expected}."
  done
}

require_stripped() {
  local binary="$1"
  local arch symbols
  [[ -x "${NM_BIN}" && ! -L "${NM_BIN}" ]] \
    || die "Apple Winn strip validation requires absolute /usr/bin/nm."
  for arch in $("${LIPO_BIN}" -archs "${binary}"); do
    symbols="$(${NM_BIN} -arch "${arch}" -m "${binary}" 2>/dev/null)" \
      || die "Could not inspect stripped symbols in ${binary} slice ${arch}."
    [[ -n "${symbols}" ]] || die "No symbols found while validating stripped ${binary} slice ${arch}."
    if grep -E '(^|[[:space:]])non-external([[:space:]]|$)' <<<"${symbols}" >/dev/null; then
      die "${binary} slice ${arch} still contains non-external symbols."
    fi
  done
}

# The Winn link already passes -Wl,-x, so ld64 writes no local symbols. A
# second `strip -x` over a Go-linked dylib adds the ld64 placeholder stab
# "OPT radr://5614542" (nlocalsym becomes 1), which the staging producer's
# strict engine_delivery_is_stripped check rejects. Measured 2026-10-09 with
# Go 1.27.1 and WinsWinnPacketEngine.m: the -Wl,-x link output has nlocalsym 0
# and no stab; the same file after `strip -x` has the radr stab. So this step
# validates the link output and never rewrites it.
# -Wl,-S is passed beside -Wl,-x because the signed Winn release c-archives
# keep DWARF in go.o: measured 2026-10-15 with release manifest ae44a427...,
# the -Wl,-x link alone wrote a 43951-entry debug map (nlocalsym 43951) whose
# OSO stab names the random transaction path of the archive snapshot, so the
# gate below refused it and no two runs could produce the same bytes.
strip_and_validate_dylib() {
  local binary="$1" load_commands
  require_stripped "${binary}"
  [[ -x "${OTOOL_BIN}" && ! -L "${OTOOL_BIN}" ]] \
    || die "Apple Winn strip validation requires absolute otool."
  load_commands="$("${OTOOL_BIN}" -l "${binary}")" \
    || die "Could not read load commands of ${binary}."
  # Every stab, including the radr placeholder, is a local symbol entry.
  if grep -Eq '^[[:space:]]*nlocalsym[[:space:]]+[1-9]' <<<"${load_commands}"; then
    die "${binary} retains local or stab symbols; the -Wl,-x link did not strip them."
  fi
}

verify_awg_provenance() {
  local mode="${1:-engine}"
  "${PYTHON_BIN}" - "${mode}" \
    "${APPLE_AWG_BRIDGE_PROVENANCE_FILE}" "${APPLE_AWG_ENGINE_PROVENANCE_FILE}" \
    "${APPLE_WG_GO_OUTPUT_DIR}" "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}" \
    "${APPLE_AWG_EXPECTED_REPOSITORY}" "${APPLE_AWG_EXPECTED_TAG}" \
    "${APPLE_AWG_EXPECTED_COMMIT}" "${APPLE_AWG_EXPECTED_TREE}" \
    "${APPLE_AWG_EXPECTED_GENERATION}" "${APPLE_AWG_EXPECTED_GO_VERSION}" \
    "${APPLE_AWG_EXPECTED_GO_MOD_SHA256}" "${APPLE_AWG_EXPECTED_GO_SUM_SHA256}" \
    "${APPLE_AWG_EXPECTED_GO_DARWIN_ARM64_SHA256}" \
    "${APPLE_AWG_EXPECTED_GO_DARWIN_AMD64_SHA256}" \
    "${APPLE_AWG_EXPECTED_XRAY_VERSION}" "${APPLE_AWG_EXPECTED_XRAY_COMMIT}" \
    "${APPLE_AWG_EXPECTED_XRAY_SUM}" "${APPLE_AWG_EXPECTED_XRAY_GO_MOD_SUM}" \
    "${APPLE_AWG_EXPECTED_XRAY_ZIP_SHA256}" "${APPLE_AWG_WRAPPER_SOURCE}" <<'PY'
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

(
    mode,
    bridge_manifest_path,
    engine_manifest_path,
    bridge_root,
    engine_root,
    repository,
    tag,
    commit,
    tree,
    generation,
    go_version,
    go_mod_sha256,
    go_sum_sha256,
    go_darwin_arm64_sha256,
    go_darwin_amd64_sha256,
    xray_version,
    xray_commit,
    xray_sum,
    xray_go_mod_sum,
    xray_zip_sha256,
    awg_wrapper_source,
) = sys.argv[1:]


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(raw_path, label):
    path = pathlib.Path(raw_path)
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{label} is missing, non-regular, or symbolic: {path}")
    if path.stat().st_size > 1024 * 1024:
        raise SystemExit(f"{label} exceeds the 1 MiB provenance limit: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"{label} is invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be a JSON object")
    return path, value


def expect_equal(actual, expected, label):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected {expected!r}, found {actual!r}")


def signature_normalized_sha256(path):
    # Same procedure as write_engine_provenance, the macOS verifier and the
    # cross-store gate: ad hoc re-sign a private copy, remove the signature,
    # hash the result.
    scratch = tempfile.mkdtemp(prefix="wins-awg-normalize-")
    try:
        os.chmod(scratch, 0o700)
        copy = pathlib.Path(scratch) / "engine"
        shutil.copyfile(path, copy)
        for arguments in (
            ["--force", "--sign", "-", "--timestamp=none", str(copy)],
            ["--remove-signature", str(copy)],
        ):
            completed = subprocess.run(
                ["/usr/bin/codesign", *arguments], capture_output=True, check=False
            )
            if completed.returncode != 0:
                raise SystemExit(
                    f"codesign signature normalization failed for {path}: "
                    + completed.stderr.decode("utf-8", "replace").strip()
                )
        return sha256(copy)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def verify_artifact(root, entry, expected_path, expected_architectures, label, normalized=False):
    if not isinstance(entry, dict):
        raise SystemExit(f"{label} provenance entry is missing")
    expect_equal(entry.get("path"), expected_path, f"{label} path")
    expect_equal(
        entry.get("architectures"), expected_architectures, f"{label} architectures"
    )
    path = pathlib.Path(root) / expected_path
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{label} artifact is missing, non-regular, or symbolic: {path}")
    expect_equal(entry.get("sha256"), sha256(path), f"{label} SHA-256")
    if normalized:
        expect_equal(
            entry.get("signature_normalized_sha256"),
            signature_normalized_sha256(path),
            f"{label} signature-normalized SHA-256",
        )


bridge_path, bridge = load_manifest(
    bridge_manifest_path, "Apple AWG 3.1 bridge provenance"
)
expect_equal(bridge.get("schema_version"), 1, "bridge schema_version")
expect_equal(bridge.get("component"), "amneziawg-apple", "bridge component")
expect_equal(bridge.get("generation"), generation, "bridge generation")
expect_equal(
    bridge.get("source"),
    {
        "commit": commit,
        "go_mod_sha256": go_mod_sha256,
        "go_sum_sha256": go_sum_sha256,
        "repository": repository,
        "tag": tag,
        "tree": tree,
    },
    "bridge source",
)
expect_equal(
    bridge.get("go_toolchain"),
    {
        "darwin_amd64_archive_sha256": go_darwin_amd64_sha256,
        "darwin_arm64_archive_sha256": go_darwin_arm64_sha256,
        "version": go_version,
    },
    "bridge Go toolchain",
)
expect_equal(
    bridge.get("xray_replacement"),
    {
        "commit": xray_commit,
        "go_mod_sum": xray_go_mod_sum,
        "module_sum": xray_sum,
        "replaced_module": "github.com/xtls/xray-core",
        "source_module": "github.com/amnezia-vpn/amnezia-xray-core",
        "version": xray_version,
        "zip_sha256": xray_zip_sha256,
    },
    "bridge Xray replacement",
)
archive_specs = {
    "iphoneos": ("iphoneos/libwg-go.a", ["arm64"]),
    "iphonesimulator": (
        "iphonesimulator/libwg-go.a",
        ["arm64", "x86_64"],
    ),
    "macosx": ("macosx/libwg-go.a", ["arm64", "x86_64"]),
}
archives = bridge.get("archives")
if not isinstance(archives, dict) or set(archives) != set(archive_specs):
    raise SystemExit("Bridge provenance must describe exactly the three Apple platforms")
for platform, (relative, architectures) in archive_specs.items():
    verify_artifact(
        bridge_root,
        archives.get(platform),
        relative,
        architectures,
        f"bridge {platform}",
    )

if mode == "bridge":
    raise SystemExit(0)
if mode != "engine":
    raise SystemExit(f"Unknown Apple AWG provenance verification mode: {mode}")

engine_path, engine = load_manifest(
    engine_manifest_path, "Apple AWG 3.1 engine provenance"
)
expect_equal(engine.get("schema_version"), 2, "engine schema_version")
expect_equal(
    engine.get("component"),
    "amneziawg-apple-engine-wrappers",
    "engine component",
)
expect_equal(engine.get("generation"), generation, "engine generation")
expect_equal(
    engine.get("bridge_provenance_sha256"),
    sha256(bridge_path),
    "engine bridge provenance SHA-256",
)
for key in ("source", "go_toolchain", "xray_replacement"):
    expect_equal(engine.get(key), bridge.get(key), f"engine {key}")
expect_equal(engine.get("bridge_archives"), archives, "engine bridge archives")
awg_source_path = pathlib.Path(awg_wrapper_source)
if not awg_source_path.is_file() or awg_source_path.is_symlink():
    raise SystemExit(
        f"Apple AWG wrapper source is missing, non-regular, or symbolic: {awg_source_path}"
    )
expect_equal(
    engine.get("awg_wrapper_source"),
    {
        "path": "apple/EngineWrappers/WinsAmneziaWGPacketEngine.m",
        "sha256": sha256(awg_source_path),
    },
    "engine AWG wrapper source",
)

wrapper_specs = {
    "iphoneos": {
        "amneziawg_packet_engine": (
            "ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib",
            ["arm64"],
        ),
        "xray_vless_ws_transport": (
            "ios/iphoneos/libWinsXrayVlessWsTransport.dylib",
            ["arm64"],
        ),
    },
    "iphonesimulator": {
        "amneziawg_packet_engine": (
            "ios/iphonesimulator/libWinsAmneziaWGPacketEngine.dylib",
            ["arm64", "x86_64"],
        ),
        "xray_vless_ws_transport": (
            "ios/iphonesimulator/libWinsXrayVlessWsTransport.dylib",
            ["arm64", "x86_64"],
        ),
    },
    "macosx": {
        "amneziawg_packet_engine": (
            "macos/libWinsAmneziaWGPacketEngine.dylib",
            ["arm64", "x86_64"],
        ),
        "xray_vless_ws_transport": (
            "macos/libWinsXrayVlessWsTransport.dylib",
            ["arm64", "x86_64"],
        ),
    },
}
wrappers = engine.get("wrappers")
if not isinstance(wrappers, dict) or set(wrappers) != set(wrapper_specs):
    raise SystemExit("Engine provenance must describe exactly the three Apple platforms")
for platform, components in wrapper_specs.items():
    value = wrappers.get(platform)
    if not isinstance(value, dict) or set(value) != set(components):
        raise SystemExit(f"Engine provenance has unexpected {platform} components")
    for component, (relative, architectures) in components.items():
        verify_artifact(
            engine_root,
            value.get(component),
            relative,
            architectures,
            f"engine {platform} {component}",
            normalized=platform == "macosx",
        )
PY
}

write_engine_provenance() {
  verify_awg_provenance bridge
  mkdir -p "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}"
  [[ ! -L "${APPLE_AWG_ENGINE_PROVENANCE_FILE}" ]] \
    || die "Apple AWG engine provenance path must not be symbolic."
  local output_tmp
  output_tmp="$(mktemp "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}/.apple-awg-31-engine-provenance.XXXXXX")"
  "${PYTHON_BIN}" - "${output_tmp}" "${APPLE_AWG_BRIDGE_PROVENANCE_FILE}" \
    "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}" "${APPLE_AWG_WRAPPER_SOURCE}" <<'PY'
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

output_path, bridge_manifest_path, engine_root, awg_wrapper_source = sys.argv[1:]
bridge_path = pathlib.Path(bridge_manifest_path)
bridge = json.loads(bridge_path.read_text(encoding="utf-8"))
root = pathlib.Path(engine_root)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def signature_normalized_sha256(path):
    # Staging and Xcode export re-sign the macOS frameworks after this record
    # is written. Re-sign a private copy ad hoc (replacing any linker, ad hoc
    # or distribution signature), remove the signature, and hash the result:
    # the macOS verifier and the cross-store gate compute the same digest.
    scratch = tempfile.mkdtemp(prefix="wins-awg-normalize-")
    try:
        os.chmod(scratch, 0o700)
        copy = pathlib.Path(scratch) / "engine"
        shutil.copyfile(path, copy)
        for arguments in (
            ["--force", "--sign", "-", "--timestamp=none", str(copy)],
            ["--remove-signature", str(copy)],
        ):
            completed = subprocess.run(
                ["/usr/bin/codesign", *arguments], capture_output=True, check=False
            )
            if completed.returncode != 0:
                raise SystemExit(
                    f"codesign signature normalization failed for {path}: "
                    + completed.stderr.decode("utf-8", "replace").strip()
                )
        return sha256(copy)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def artifact(relative, architectures):
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"Apple AWG wrapper is missing or symbolic: {path}")
    record = {
        "architectures": architectures,
        "path": relative,
        "sha256": sha256(path),
    }
    if relative.startswith("macos/"):
        record["signature_normalized_sha256"] = signature_normalized_sha256(path)
    return record


manifest = {
    "awg_wrapper_source": {
        "path": "apple/EngineWrappers/WinsAmneziaWGPacketEngine.m",
        "sha256": sha256(pathlib.Path(awg_wrapper_source)),
    },
    "bridge_archives": bridge["archives"],
    "bridge_provenance_sha256": sha256(bridge_path),
    "component": "amneziawg-apple-engine-wrappers",
    "generation": bridge["generation"],
    "go_toolchain": bridge["go_toolchain"],
    "schema_version": 2,
    "source": bridge["source"],
    "wrappers": {
        "iphoneos": {
            "amneziawg_packet_engine": artifact(
                "ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib", ["arm64"]
            ),
            "xray_vless_ws_transport": artifact(
                "ios/iphoneos/libWinsXrayVlessWsTransport.dylib", ["arm64"]
            ),
        },
        "iphonesimulator": {
            "amneziawg_packet_engine": artifact(
                "ios/iphonesimulator/libWinsAmneziaWGPacketEngine.dylib",
                ["arm64", "x86_64"],
            ),
            "xray_vless_ws_transport": artifact(
                "ios/iphonesimulator/libWinsXrayVlessWsTransport.dylib",
                ["arm64", "x86_64"],
            ),
        },
        "macosx": {
            "amneziawg_packet_engine": artifact(
                "macos/libWinsAmneziaWGPacketEngine.dylib", ["arm64", "x86_64"]
            ),
            "xray_vless_ws_transport": artifact(
                "macos/libWinsXrayVlessWsTransport.dylib", ["arm64", "x86_64"]
            ),
        },
    },
    "xray_replacement": bridge["xray_replacement"],
}
pathlib.Path(output_path).write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
  chmod 0600 "${output_tmp}"
  mv -f "${output_tmp}" "${APPLE_AWG_ENGINE_PROVENANCE_FILE}"
  verify_awg_provenance engine
  local published_sha=""
  published_sha="$(wins_sha256 "${APPLE_AWG_ENGINE_PROVENANCE_FILE}")" \
    || die "Apple AWG engine provenance hash command failed."
  printf 'Apple AWG 3.1 engine provenance: %s (sha256=%s)\n' \
    "${APPLE_AWG_ENGINE_PROVENANCE_FILE}" \
    "${published_sha}"
}

apple_refuse_live_xray_provenance_hash_without_rebuild() {
  local resolved_output="" resolved_live=""
  resolved_live="$(cd "${PROJECT_ROOT}/apple/EngineArtifacts" && pwd -P)" \
    || die "Live Apple EngineArtifacts directory is missing."
  resolved_output="$(cd "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}" && pwd -P)" \
    || die "Apple engine wrapper output root is missing."
  if [[ "${resolved_output}" == "${resolved_live}" ]]; then
    die "Refusing to hash live apple/EngineArtifacts into Xray VLESS-WS provenance without a verified rebuild. Cached Xray dylibs are owner-blocked."
  fi
}

run_xray_provenance_tool() {
  local command="$1"
  command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "Python 3 is required."
  [[ -f "${APPLE_XRAY_ENGINE_PROVENANCE_TOOL}" && ! -L "${APPLE_XRAY_ENGINE_PROVENANCE_TOOL}" ]] \
    || die "Apple Xray VLESS-WS provenance verifier is missing or symbolic."
  [[ -f "${APPLE_XRAY_ENGINE_PROVENANCE_SCHEMA}" && ! -L "${APPLE_XRAY_ENGINE_PROVENANCE_SCHEMA}" ]] \
    || die "Apple Xray VLESS-WS provenance schema is missing or symbolic."
  [[ -f "${APPLE_XRAY_WRAPPER_SOURCE}" && ! -L "${APPLE_XRAY_WRAPPER_SOURCE}" ]] \
    || die "Apple Xray wrapper source is missing or symbolic: ${APPLE_XRAY_WRAPPER_SOURCE}"
  "${PYTHON_BIN}" "${APPLE_XRAY_ENGINE_PROVENANCE_TOOL}" \
    "${command}" \
    "${APPLE_XRAY_ENGINE_PROVENANCE_FILE}" \
    "${PROJECT_ROOT}" \
    "${APPLE_XRAY_WRAPPER_SOURCE}" \
    "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}" \
    "${APPLE_XRAY_ENGINE_PROVENANCE_SCHEMA}" \
    "${PROJECT_ROOT}/tools/build_apple_engine_wrappers.sh" \
    "${WINS_LIPO_BIN}" \
    "${WINS_FILE_BIN}" \
    "${WINS_OTOOL_BIN}" \
    "${WINS_NM_BIN}"
}

verify_xray_provenance() {
  run_xray_provenance_tool verify \
    || die "Apple Xray VLESS-WS engine provenance verification failed. Cached Xray artifacts are owner-blocked until a verified rebuild refreshes provenance."
  printf 'APPLE XRAY VLESS-WS ENGINE PROVENANCE: PASS\n'
}

write_xray_provenance() {
  local published_sha=""
  mkdir -p "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}"
  [[ ! -L "${APPLE_XRAY_ENGINE_PROVENANCE_FILE}" ]] \
    || die "Apple Xray VLESS-WS engine provenance path must not be symbolic."
  run_xray_provenance_tool write \
    || die "Apple Xray VLESS-WS engine provenance could not be refreshed. Incomplete or stale Xray artifacts are rebuild-required."
  published_sha="$(wins_sha256 "${APPLE_XRAY_ENGINE_PROVENANCE_FILE}")" \
    || die "Apple Xray VLESS-WS engine provenance hash command failed."
  printf 'Apple Xray VLESS-WS engine provenance: %s (sha256=%s)\n' \
    "${APPLE_XRAY_ENGINE_PROVENANCE_FILE}" \
    "${published_sha}"
}

apple_reject_hostile_release_go_environment() {
  local name value expected
  for name in GOFLAGS GOWORK GOPROXY GOSUMDB GOEXPERIMENT; do
    value="${!name-}"
    case "${name}" in
      GOFLAGS) expected="-mod=readonly" ;;
      GOWORK|GOPROXY|GOSUMDB) expected="off" ;;
      GOEXPERIMENT) expected="" ;;
    esac
    if [[ -n "${value}" && "${value}" != "${expected}" ]]; then
      die "hostile ${name} is refused for the Apple Winn release build."
    fi
  done
}

# Go never runs in this script. The five Apple datapath archives come from a
# Winn release directory that tools/winn_release.py built twice from a sealed
# source snapshot with pinned Go, compared byte for byte, and (for release use)
# signed with the owner's release authority key. These refusals keep the
# wrapper pass from mixing those bytes with reused engines, a narrowed
# architecture set, or an untrusted verifier.
apple_require_exact_winn_release_inputs() {
  apple_reject_hostile_release_go_environment
  [[ -z "${APPLE_ENGINE_ARTIFACTS_DIR:-}" ]] \
    || die "APPLE_ENGINE_ARTIFACTS_DIR reuse is forbidden for an Apple Winn release rebuild."
  [[ -z "${APPLE_ENGINE_WRAPPER_ARCHS// }" ]] \
    || die "APPLE_ENGINE_WRAPPER_ARCHS overrides are forbidden; the Apple Winn release requires the exact declared universal architecture sets."
  [[ -f "${WINN_RELEASE_DRIVER}" && ! -L "${WINN_RELEASE_DRIVER}" && -r "${WINN_RELEASE_DRIVER}" ]] \
    || die "Winn release driver is missing, unreadable, or symbolic: ${WINN_RELEASE_DRIVER}"
  [[ -f "${WINN_RELEASE_PYTHON}" && -x "${WINN_RELEASE_PYTHON}" && ! -L "${WINN_RELEASE_PYTHON}" ]] \
    || die "Winn release verification requires ${WINN_RELEASE_PYTHON}."
  if [[ -n "${WINS_WINN_RELEASE_DIR}" ]]; then
    [[ "${WINS_WINN_RELEASE_DIR}" == /* ]] \
      || die "The Winn release directory must be an absolute path: ${WINS_WINN_RELEASE_DIR}"
    [[ -d "${WINS_WINN_RELEASE_DIR}" && ! -L "${WINS_WINN_RELEASE_DIR}" ]] \
      || die "The Winn release directory is missing or symbolic: ${WINS_WINN_RELEASE_DIR}"
  elif [[ "${WINS_APPLE_WINN3_RELEASE:-0}" == "1" ]]; then
    die "Release mode requires a signed Winn release directory (--release DIR or WINS_WINN_RELEASE_DIR); a dev build through the driver is refused."
  fi
  if [[ "${WINS_WINN_ALLOW_UNSIGNED}" == "1" ]]; then
    [[ "${WINS_APPLE_WINN3_RELEASE:-0}" != "1" ]] \
      || die "Release mode never accepts an unsigned Winn release."
    [[ -n "${WINS_WINN_RELEASE_DIR}" ]] \
      || die "--allow-unsigned requires --release DIR."
  fi
  if [[ -n "${WINS_WINN_TRUST_PUBLIC_KEY:-}" && "${WINS_APPLE_WINN3_RELEASE:-0}" == "1" ]]; then
    die "Release mode trusts only the pinned release authority key; WINS_WINN_TRUST_PUBLIC_KEY is refused."
  fi
}

apple_refuse_live_winn_provenance_hash_without_rebuild() {
  local resolved_output="" resolved_live=""
  resolved_live="$(cd "${PROJECT_ROOT}/apple/EngineArtifacts" && pwd -P)" \
    || die "Live Apple EngineArtifacts directory is missing."
  resolved_output="$(cd "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}" && pwd -P)" \
    || die "Apple engine wrapper output root is missing."
  if [[ "${resolved_output}" == "${resolved_live}" ]]; then
    die "Refusing to hash live apple/EngineArtifacts into Winn v3 provenance without a verified rebuild. Cached Winn archives and dylibs are owner-blocked."
  fi
}

run_winn_provenance_tool() {
  local command="$1"
  shift
  (
    "${PYTHON_BIN}" - "${command}" \
      "${APPLE_WINN_ENGINE_PROVENANCE_FILE}" \
      "${PROJECT_ROOT}" \
      "${WINN_DATAPATH_ARCHIVE_DIR}" \
      "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}" \
      "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinnTunnel.h" \
      "${PROJECT_ROOT}/tools/build_apple_engine_wrappers.sh" \
      "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsWinnPacketEngine.m" \
      "${PROJECT_ROOT}/tools/apple_winn_v3_engine_provenance.schema.json" \
      "${PROJECT_ROOT}/tools/toolchain-pins.json" \
      "${WINN_EXPECTED_MODULE}" \
      "${APPLE_WINN_RELEASE_FACTS:-}" \
      "${CLANG_BIN}" \
      "${STRIP_BIN}" \
      "${NM_BIN}" \
      "${LIPO_BIN}" \
      "${AR_BIN}" \
      "${VTOOL_BIN}" \
      "${FILE_BIN}" \
      "${OTOOL_BIN}" \
      "$@"
  ) <<'PY'

import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile

(
    command,
    provenance_raw,
    project_root_raw,
    archive_root_raw,
    engine_root_raw,
    header_raw,
    wrapper_builder_raw,
    wrapper_source_raw,
    schema_raw,
    pins_raw,
    expected_module,
    release_facts_raw,
    clang_bin,
    strip_bin,
    nm_bin,
    lipo_bin,
    ar_bin,
    vtool_bin,
    file_bin,
    otool_bin,
    *rest,
) = sys.argv[1:]

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
HEADER_RELATIVE = "apple/EngineWrappers/WinnTunnel.h"
WRAPPER_BUILDER_RELATIVE = "tools/build_apple_engine_wrappers.sh"
WRAPPER_SOURCE_RELATIVE = "apple/EngineWrappers/WinsWinnPacketEngine.m"
RELEASE_MANIFEST_CONTRACT = "winsvpn-winn-release-manifest-v1"
TEXT_LIMIT = 2 * 1024 * 1024
ARTIFACT_LIMIT = 64 * 1024 * 1024
TOOL_LIMIT = 512 * 1024 * 1024
PROVENANCE_LIMIT = 1024 * 1024
REBUILD_REQUIRED = (
    "Apple Winn v3 engine provenance is missing, stale, malformed, symbolic, "
    "or not bound to the current release and artifacts. Cached Winn archives "
    "and dylibs are refused until a verified rebuild from a Winn release "
    "directory refreshes provenance."
)
ARCHIVE_SPECS = (
    ("iphoneos_arm64", "libwinn-datapath-ios-arm64.a", "libwinn-datapath-ios-arm64.h", "arm64", "IOS", "datapath-ios-arm64"),
    ("macosx_arm64", "libwinn-datapath-darwin-arm64.a", "libwinn-datapath-darwin-arm64.h", "arm64", "MACOS", "datapath-archive-darwin-arm64"),
    ("macosx_x86_64", "libwinn-datapath-darwin-amd64.a", "libwinn-datapath-darwin-amd64.h", "x86_64", "MACOS", "datapath-archive-darwin-amd64"),
    ("iphonesimulator_arm64", "libwinn-datapath-iossimulator-arm64.a", "libwinn-datapath-iossimulator-arm64.h", "arm64", "IOSSIMULATOR", "datapath-iossimulator-arm64"),
    ("iphonesimulator_x86_64", "libwinn-datapath-iossimulator-amd64.a", "libwinn-datapath-iossimulator-amd64.h", "x86_64", "IOSSIMULATOR", "datapath-iossimulator-amd64"),
)
WRAPPER_SPECS = (
    ("iphoneos", "ios/iphoneos/libWinsWinnPacketEngine.dylib", "IOS", ["arm64"]),
    ("iphonesimulator", "ios/iphonesimulator/libWinsWinnPacketEngine.dylib", "IOSSIMULATOR", ["arm64", "x86_64"]),
    ("macosx", "macos/libWinsWinnPacketEngine.dylib", "MACOS", ["arm64", "x86_64"]),
)
COMMON_SYMBOLS = (
    "WinnTunnelFreeString",
    "WinnTunnelContractVersion",
    "WinnTunnelProtocolVersion",
    "WinnTunnelMaxDatagram",
    "WinnTunnelWriteInbound",
    "WinnTunnelReadOutbound",
    "WinnTunnelStatusJSON",
    "WinnTunnelClose",
)
RELAY_SYMBOLS = ("WinnTunnelCreate", "WinnTunnelCreateWithCarrier")
CORE_SYMBOLS = ("WinnTunnelCreateWinn3",)
ADAPTER_SYMBOLS = (
    "wins_winn_packet_engine_contract_version",
    "wins_winn_packet_engine_create",
    "wins_winn_packet_engine_start",
    "wins_winn_packet_engine_stop",
    "wins_winn_packet_engine_destroy",
    "wins_winn_packet_engine_awg_seam_port",
    "wins_winn_packet_engine_seam_stats",
    "wins_winn_packet_engine_status_json",
)
REQUIRED_WRAPPER_SYMBOLS = COMMON_SYMBOLS + RELAY_SYMBOLS + CORE_SYMBOLS + ADAPTER_SYMBOLS
ROLE_BINDING = {
    "core": {
        "entry_symbol": "WinnTunnelCreateWinn3",
        "payload_class": "ip-packet",
        "required_symbols": list(CORE_SYMBOLS),
    },
    "relay": {
        "entry_symbols": list(RELAY_SYMBOLS),
        "payload_class": "awg-datagram",
        "required_symbols": list(RELAY_SYMBOLS),
    },
}


def fail(message):
    raise SystemExit(message)


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def require_absolute_tool(path, label):
    tool = pathlib.Path(path)
    if not str(tool).startswith("/") or tool.is_symlink() or not tool.is_file() or not os.access(tool, os.X_OK):
        fail(f"{label} must be an absolute regular non-symlink executable: {path}")
    return str(tool)


LIPO = require_absolute_tool(lipo_bin, "lipo")
FILE = require_absolute_tool(file_bin, "file")
OTOOL = require_absolute_tool(otool_bin, "otool")
CLANG = require_absolute_tool(clang_bin, "clang")
STRIP = require_absolute_tool(strip_bin, "strip")
NM = require_absolute_tool(nm_bin, "nm")
AR = require_absolute_tool(ar_bin, "ar")
VTOOL = require_absolute_tool(vtool_bin, "vtool")


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def stable_read(path, label, limit):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        fail("O_NOFOLLOW is required for Apple Winn v3 provenance")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_uid != os.getuid()
        ):
            fail(f"{label} must be a nonempty owner-only single-link regular file: {path}")
        if before.st_size > limit:
            fail(f"{label} exceeds the {limit} byte snapshot limit: {path}")
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            chunks = []
            remaining = opened.st_size
            while remaining > 0:
                block = os.read(fd, min(1024 * 1024, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            finished = os.fstat(fd)
        finally:
            os.close(fd)
        after = path.lstat()
    except OSError as error:
        fail(f"{label} is unreadable: {path} ({error})")
    if identity(before) != identity(opened) or identity(opened) != identity(finished) or identity(finished) != identity(after):
        fail(f"{label} changed while it was snapshotted: {path}")
    payload = b"".join(chunks)
    if not payload:
        fail(f"{label} is empty: {path}")
    return payload


def stable_read_tool(path, label, limit):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        fail("O_NOFOLLOW is required for Apple Winn v3 toolchain identity")
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_uid not in (0, os.getuid())
        ):
            fail(f"{label} must be a nonempty owner regular file: {path}")
        if before.st_size > limit:
            fail(f"{label} exceeds the {limit} byte snapshot limit: {path}")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow)
        try:
            opened = os.fstat(fd)
            chunks = []
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                chunks.append(block)
            finished = os.fstat(fd)
        finally:
            os.close(fd)
        after = path.lstat()
    except OSError as error:
        fail(f"{label} is unreadable: {path} ({error})")
    if identity(before) != identity(opened) or identity(opened) != identity(finished) or identity(finished) != identity(after):
        fail(f"{label} changed while it was snapshotted: {path}")
    payload = b"".join(chunks)
    if not payload:
        fail(f"{label} is empty: {path}")
    return payload


def sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def expect_equal(actual, expected, label):
    if actual != expected:
        fail(f"{label} mismatch: expected {expected!r}, found {actual!r}")


def json_type_name(value):
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if type(value) is str:
        return "string"
    if type(value) is list:
        return "array"
    if type(value) is dict:
        return "object"
    return type(value).__name__


def load_json_object(path, label, limit):
    payload = stable_read(path, label, limit)
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid JSON: {error}")
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    return value


def resolve_schema_node(schema, node):
    ref = node.get("$ref") if type(node) is dict else None
    if not ref:
        return node
    if not ref.startswith("#/$defs/"):
        fail(f"unsupported schema ref {ref}")
    name = ref.split("/")[-1]
    defs = schema.get("$defs")
    if type(defs) is not dict or name not in defs:
        fail(f"schema is missing $defs/{name}")
    return defs[name]


def validate_schema(instance, schema, node, path):
    node = resolve_schema_node(schema, node)
    expected_type = node.get("type")
    if expected_type == "object":
        if type(instance) is not dict:
            fail(f"{path} must be an object, found {json_type_name(instance)}")
        required = node.get("required", [])
        for key in required:
            if key not in instance:
                fail(f"{path} omits required field {key}")
        properties = node.get("properties", {})
        additional = node.get("additionalProperties", True)
        for key, value in instance.items():
            if key in properties:
                validate_schema(value, schema, properties[key], f"{path}.{key}")
            elif additional is False:
                fail(f"{path} has extra field {key}")
    elif expected_type == "array":
        if type(instance) is not list:
            fail(f"{path} must be an array, found {json_type_name(instance)}")
        min_items = node.get("minItems")
        if type(min_items) is int and len(instance) < min_items:
            fail(f"{path} has too few items")
        items = node.get("items")
        if items is not None:
            for index, value in enumerate(instance):
                validate_schema(value, schema, items, f"{path}[{index}]")
    elif expected_type == "string":
        if type(instance) is not str:
            fail(f"{path} must be a string, found {json_type_name(instance)}")
        min_length = node.get("minLength")
        if type(min_length) is int and len(instance) < min_length:
            fail(f"{path} is shorter than {min_length}")
        pattern = node.get("pattern")
        if pattern and re.search(pattern, instance) is None:
            fail(f"{path} does not match {pattern}")
    elif expected_type == "integer":
        if type(instance) is bool or type(instance) is not int:
            fail(f"{path} must be an integer, found {json_type_name(instance)}")
    if "const" in node:
        const = node["const"]
        if instance != const or type(instance) is not type(const) or type(instance) is bool:
            if type(const) is not bool and type(instance) is bool:
                fail(f"{path} rejects bool-as-int / bool-as-const {instance!r}")
            if instance != const:
                fail(f"{path} must be {const!r}, found {instance!r}")
            if type(instance) is not type(const):
                fail(f"{path} has the wrong scalar type for const {const!r}")
    if "enum" in node and instance not in node["enum"]:
        fail(f"{path} is not one of {node['enum']!r}")


def run_absolute(tool, args, label):
    completed = subprocess.run([tool, *args], capture_output=True, check=False)
    if completed.returncode != 0:
        fail(f"{label} failed ({tool})")
    return completed.stdout.decode("utf-8", "replace")


MACHO_PLATFORMS = {
    "1": "MACOS",
    "2": "IOS",
    "7": "IOSSIMULATOR",
    "MACOS": "MACOS",
    "IOS": "IOS",
    "IOSSIMULATOR": "IOSSIMULATOR",
}


def platforms_from_otool(otool_text):
    found = []
    for line in otool_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("platform "):
            continue
        mapped = MACHO_PLATFORMS.get(stripped.split()[1])
        if mapped:
            found.append(mapped)
    return sorted(set(found))


def exported_symbols(path, label, arch=None):
    args = ["-gU"]
    if arch is not None:
        args.extend(["-arch", arch])
    args.append(str(path))
    output = run_absolute(NM, args, f"nm {label}")
    symbols = set()
    for line in output.splitlines():
        fields = line.split()
        if fields:
            symbols.add(fields[-1].lstrip("_"))
    return symbols


EXPECTED_MINOS = {
    ("IOS", "arm64"): "13.0",
    ("IOSSIMULATOR", "arm64"): "14.0",
    ("IOSSIMULATOR", "x86_64"): "13.0",
    ("MACOS", "arm64"): "13.0",
    ("MACOS", "x86_64"): "13.0",
}
INSTALL_NAME = "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine"
ROLE_SYMBOLS = {
    "core": list(CORE_SYMBOLS),
    "relay": list(RELAY_SYMBOLS),
}


def load_command_field(text, field):
    values = []
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == field:
            values.append(parts[1])
    return values


def inspect_dylib_slice(path, arch, expected_platform, required_symbols):
    load_commands = run_absolute(
        OTOOL, ["-arch", arch, "-l", str(path)], f"otool load commands {path} {arch}"
    )
    platforms = platforms_from_otool(load_commands)
    if platforms != [expected_platform]:
        fail(f"{path} {arch} platform {platforms!r} does not match {expected_platform}")
    uuids = load_command_field(load_commands, "uuid")
    if len(uuids) != 1 or re.fullmatch(
        r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
        uuids[0],
    ) is None:
        fail(f"{path} {arch} must contain exactly one valid LC_UUID")
    build_text = run_absolute(
        VTOOL, ["-arch", arch, "-show-build", str(path)], f"vtool {path} {arch}"
    )
    minos_values = load_command_field(build_text, "minos")
    if len(minos_values) != 1:
        fail(f"{path} {arch} must contain exactly one minimum OS value")
    expected_minos = EXPECTED_MINOS.get((expected_platform, arch))
    if expected_minos is None or minos_values[0] != expected_minos:
        fail(
            f"{path} {arch} has minimum OS {minos_values[0]!r}; "
            f"expected {expected_minos!r}"
        )
    header = run_absolute(
        OTOOL, ["-arch", arch, "-hv", str(path)], f"otool header {path} {arch}"
    )
    if re.search(r"\b(MH_DYLIB|DYLIB)\b", header) is None:
        fail(f"{path} {arch} Mach-O filetype is not MH_DYLIB")
    install_output = run_absolute(
        OTOOL, ["-arch", arch, "-D", str(path)], f"otool install name {path} {arch}"
    )
    install_names = [
        line.strip()
        for line in install_output.splitlines()
        if line.strip() and line.strip() != str(path) and not line.endswith(":")
    ]
    if install_names[-1:] != [INSTALL_NAME]:
        fail(f"{path} {arch} has an unexpected install name: {install_names!r}")
    dependency_output = run_absolute(
        OTOOL, ["-arch", arch, "-L", str(path)], f"otool dependencies {path} {arch}"
    )
    dependencies = []
    for line in dependency_output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.endswith(":") or stripped.startswith(str(path)):
            continue
        dependency = stripped.split(" (", 1)[0]
        if dependency == INSTALL_NAME:
            continue
        if not (
            dependency.startswith("/usr/lib/")
            or dependency.startswith("/System/Library/Frameworks/")
        ):
            fail(f"{path} {arch} has a non-system dependency: {dependency}")
        dependencies.append(dependency)
    dependencies = sorted(set(dependencies))
    if not any(item == "/usr/lib/libSystem.B.dylib" for item in dependencies):
        fail(f"{path} {arch} dependency closure omits /usr/lib/libSystem.B.dylib")
    found_symbols = exported_symbols(path, f"{path} {arch}", arch)
    missing = sorted(set(required_symbols) - found_symbols)
    if missing:
        fail(f"{path} {arch} is missing required exported symbols: {missing!r}")
    return {
        "architecture": arch,
        "dependencies": dependencies,
        "filetype": "MH_DYLIB",
        "install_name": INSTALL_NAME,
        "minos": minos_values[0],
        "platform": expected_platform,
        "role_symbols": ROLE_SYMBOLS,
        "uuid": uuids[0].upper(),
    }


def inspect_binary(path, kind, expected_platform, expected_archs=None, required_symbols=()):
    file_text = run_absolute(FILE, ["-b", str(path)], f"file {path}").strip()
    arch_text = run_absolute(LIPO, ["-archs", str(path)], f"lipo {path}").strip()
    architectures = sorted(item for item in arch_text.split() if item)
    if not architectures:
        fail(f"{path} has no inspectable architectures")
    if "universal" in file_text.lower() and expected_archs is not None and len(expected_archs) == 1:
        fail(f"refusing a fat substitute for single-arch {path}: {file_text}")
    platforms = platforms_from_otool(run_absolute(OTOOL, ["-l", str(path)], f"otool {path}"))
    if platforms != [expected_platform]:
        fail(f"{path} platform {platforms!r} does not match {expected_platform}")
    if kind == "dylib":
        if "dynamically linked shared library" not in file_text and "Mach-O" not in file_text:
            fail(f"{path} is not a Mach-O dylib: {file_text}")
        if "current ar archive" in file_text:
            fail(f"{path} is an archive, not a dylib: {file_text}")
        filetype = "mach-o-dylib"
    elif kind == "archive":
        if "current ar archive" in file_text:
            filetype = "ar-archive"
        elif "Mach-O" in file_text:
            filetype = "mach-o-archive"
        else:
            fail(f"{path} is not an archive: {file_text}")
        if "dynamically linked shared library" in file_text:
            fail(f"{path} is a dylib, not an archive: {file_text}")
    else:
        fail(f"unknown binary kind {kind}")
    if expected_archs is not None and architectures != expected_archs:
        fail(f"{path} architectures {architectures!r} do not match {expected_archs!r}")
    strip_state = "not-applicable"
    slices = {}
    if kind == "dylib":
        for arch in architectures:
            symbols = run_absolute(NM, ["-arch", arch, "-m", str(path)], f"nm strip {path} {arch}")
            if not symbols.strip():
                fail(f"{path} {arch} has no inspectable symbols")
            if re.search(r"(^|\s)non-external(\s|$)", symbols):
                fail(f"{path} {arch} is not stripped: non-external symbols remain")
            slices[arch] = inspect_dylib_slice(
                path, arch, expected_platform, required_symbols
            )
        strip_state = "stripped"
    return architectures, expected_platform, filetype, strip_state, slices


def inspect_snapshot(payload, kind, expected_platform, expected_archs, label, required_symbols=()):
    tmp_dir = tempfile.mkdtemp(prefix="wins-winn-inspect-")
    try:
        os.chmod(tmp_dir, 0o700)
        path = pathlib.Path(tmp_dir) / "artifact"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    fail(f"short inspect snapshot write for {label}")
                view = view[written:]
            os.fsync(fd)
            info = os.fstat(fd)
            if info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
                fail(f"{label} inspect snapshot is not a single-link file")
        finally:
            os.close(fd)
        return inspect_binary(path, kind, expected_platform, expected_archs, required_symbols)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def signature_normalized_sha256(payload, label):
    # Staging and Xcode export re-sign the macOS framework after this record
    # is written. Ad hoc re-sign a private copy (replacing any linker, ad hoc
    # or distribution signature), remove the signature, and hash the result:
    # the macOS verifier and the cross-store gate compute the same digest.
    tmp_dir = tempfile.mkdtemp(prefix="wins-winn-normalize-")
    try:
        os.chmod(tmp_dir, 0o700)
        path = pathlib.Path(tmp_dir) / "artifact"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    fail(f"short normalization snapshot write for {label}")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        run_absolute(
            "/usr/bin/codesign",
            ["--force", "--sign", "-", "--timestamp=none", str(path)],
            f"codesign normalization {label}",
        )
        run_absolute(
            "/usr/bin/codesign", ["--remove-signature", str(path)], f"codesign signature removal {label}"
        )
        return sha256_bytes(path.read_bytes())
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def current_apple_toolchain():
    def tool_record(path, label):
        tool_path = pathlib.Path(path)
        payload = stable_read_tool(tool_path, f"Apple tool {label}", TOOL_LIMIT)
        return {"path": str(tool_path), "sha256": sha256_bytes(payload)}

    return {
        "tools": {
            "clang": tool_record(CLANG, "clang"),
            "ar": tool_record(AR, "ar"),
            "file": tool_record(FILE, "file"),
            "lipo": tool_record(LIPO, "lipo"),
            "nm": tool_record(NM, "nm"),
            "otool": tool_record(OTOOL, "otool"),
            "strip": tool_record(STRIP, "strip"),
            "vtool": tool_record(VTOOL, "vtool"),
        }
    }


def exact_keys(value, expected, label):
    if type(value) is not dict or set(value) != set(expected):
        fail(f"{label} keys are not exact")
    return value


def require_sha(value, label):
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} is not an exact SHA-256 value")
    return value


def pinned_go():
    pins = load_json_object(pathlib.Path(pins_raw), "toolchain pins", TEXT_LIMIT)
    tools = pins.get("tools")
    go = tools.get("go") if type(tools) is dict else None
    if type(go) is not dict:
        fail("toolchain pins omit tools.go")
    version = go.get("version")
    if type(version) is not str or not VERSION_RE.fullmatch(version):
        fail("toolchain pins tools.go.version is invalid")
    archives = go.get("archive_sha256")
    if type(archives) is not dict:
        fail("toolchain pins omit tools.go.archive_sha256")
    darwin = {
        archives.get(key)
        for key in ("darwin_arm64", "darwin_amd64")
        if type(archives.get(key)) is str and SHA256_RE.fullmatch(archives.get(key))
    }
    if not darwin:
        fail("toolchain pins omit the official darwin Go archive identities")
    return version, darwin


# The release record is copied from the sealed release manifest by
# acquire_winn_release and is checked here for internal consistency and
# against the pinned toolchain. The signature itself is verified by
# tools/winn_release.py; this record carries the manifest digest and public
# key that verification accepted, so a later reader can re-check the same
# release directory with `verify-winn-provenance --release DIR`.
def validate_release(release):
    exact_keys(
        release,
        {"contract", "go", "manifest_sha256", "producer", "signature_public_key", "signature_state", "source"},
        "Winn release record",
    )
    expect_equal(release["contract"], RELEASE_MANIFEST_CONTRACT, "Winn release manifest contract")
    require_sha(release["manifest_sha256"], "Winn release manifest")
    state = release["signature_state"]
    key = release["signature_public_key"]
    if state == "signed":
        if type(key) is not str or SHA256_RE.fullmatch(key) is None:
            fail("signed Winn release record must carry the 32-byte Ed25519 public key")
    elif state == "unsigned-dev":
        if key != "":
            fail("unsigned-dev Winn release record must not claim a signature public key")
    else:
        fail(f"Winn release signature_state is invalid: {state!r}")
    source = exact_keys(release["source"], {"binding", "commit", "tree_sha256"}, "Winn release source")
    if source["binding"] not in ("git-archive", "export"):
        fail("Winn release source binding is invalid")
    if type(source["commit"]) is not str or COMMIT_RE.fullmatch(source["commit"]) is None:
        fail("Winn release source commit is invalid")
    require_sha(source["tree_sha256"], "Winn release source tree")
    go = exact_keys(
        release["go"],
        {"archive_sha256", "executable_sha256", "install_tree_sha256", "version"},
        "Winn release Go toolchain",
    )
    pinned_version, pinned_archives = pinned_go()
    expect_equal(go["version"], pinned_version, "Winn release Go version")
    if go["archive_sha256"] not in pinned_archives:
        fail("Winn release Go archive is not a pinned official darwin archive")
    require_sha(go["executable_sha256"], "Winn release Go executable")
    require_sha(go["install_tree_sha256"], "Winn release Go install tree")
    producer = exact_keys(
        release["producer"],
        {"builder_sha256", "driver_sha256", "toolchain_pins_sha256"},
        "Winn release producer",
    )
    for field, value in producer.items():
        require_sha(value, f"Winn release producer {field}")
    return release


def load_release_facts():
    if not release_facts_raw:
        fail(
            "Winn provenance can only be written from a verified Winn release "
            "(APPLE_WINN_RELEASE_FACTS is produced by acquire_winn_release)."
        )
    facts = load_json_object(pathlib.Path(release_facts_raw), "Winn release facts", TEXT_LIMIT)
    exact_keys(facts, {"archives", "release"}, "Winn release facts")
    archives = facts["archives"]
    if type(archives) is not dict or set(archives) != {spec[0] for spec in ARCHIVE_SPECS}:
        fail("Winn release facts must describe exactly the five Apple archives")
    for key, archive_name, header_name, _arch, _platform, target in ARCHIVE_SPECS:
        entry = exact_keys(
            archives[key],
            {"build_a_sha256", "build_b_sha256", "header_sha256", "sha256", "target"},
            f"Winn release facts {key}",
        )
        expect_equal(entry["target"], target, f"Winn release facts {key} target")
        for field in ("build_a_sha256", "build_b_sha256", "header_sha256", "sha256"):
            require_sha(entry[field], f"Winn release facts {key} {field}")
    return validate_release(facts["release"]), archives


def current_source():
    wrapper_source = pathlib.Path(wrapper_source_raw)
    wrapper_source_bytes = stable_read(wrapper_source, "Winn Apple wrapper source", TEXT_LIMIT * 4)
    return {
        "module": expected_module,
        "wrapper_path": WRAPPER_SOURCE_RELATIVE,
        "wrapper_sha256": sha256_bytes(wrapper_source_bytes),
    }


def current_bindings(release, release_archives):
    archive_root = pathlib.Path(archive_root_raw)
    engine_root = pathlib.Path(engine_root_raw)
    header_bytes = stable_read(pathlib.Path(header_raw), "Winn wrapper header", TEXT_LIMIT)
    wrapper_builder_bytes = stable_read(
        pathlib.Path(wrapper_builder_raw), "Winn wrapper builder", TEXT_LIMIT * 4
    )
    archives = {}
    for key, archive_name, header_name, expected_arch, expected_platform, target in ARCHIVE_SPECS:
        archive_path = archive_root / archive_name
        header_path = archive_root / header_name
        archive_bytes = stable_read(archive_path, f"Winn archive {key}", ARTIFACT_LIMIT)
        header_bytes_for_slice = stable_read(
            header_path, f"Winn archive header {key}", TEXT_LIMIT
        )
        architectures, platform_name, filetype, _strip_state, _slices = inspect_snapshot(
            archive_bytes, "archive", expected_platform, [expected_arch], f"Winn archive {key}"
        )
        archive_sha = sha256_bytes(archive_bytes)
        header_sha = sha256_bytes(header_bytes_for_slice)
        released = release_archives.get(key) if type(release_archives) is dict else None
        if type(released) is not dict:
            fail(f"Winn release does not describe archive {key}")
        expect_equal(released.get("target"), target, f"Winn release archive {key} target")
        expect_equal(released.get("sha256"), archive_sha, f"Winn release archive {key} SHA-256")
        expect_equal(released.get("header_sha256"), header_sha, f"Winn release header {key} SHA-256")
        # Reproducibility witness: both independent driver builds produced
        # exactly the bytes that are wrapped here.
        expect_equal(released.get("build_a_sha256"), archive_sha, f"Winn release archive {key} build A")
        expect_equal(released.get("build_b_sha256"), archive_sha, f"Winn release archive {key} build B")
        archives[key] = {
            "architectures": architectures,
            "build_a_sha256": archive_sha,
            "build_b_sha256": archive_sha,
            "filetype": filetype,
            "header_path": header_name,
            "header_sha256": header_sha,
            "path": archive_name,
            "platform": platform_name,
            "sha256": archive_sha,
            "target": target,
        }
    wrappers = {}
    for key, relative, expected_platform, expected_archs in WRAPPER_SPECS:
        wrapper_path = engine_root / relative
        wrapper_bytes = stable_read(wrapper_path, f"Winn wrapper {key}", ARTIFACT_LIMIT)
        architectures, platform_name, filetype, strip_state, slices = inspect_snapshot(
            wrapper_bytes,
            "dylib",
            expected_platform,
            expected_archs,
            f"Winn wrapper {key}",
            REQUIRED_WRAPPER_SYMBOLS,
        )
        wrappers[key] = {
            "architectures": architectures,
            "filetype": filetype,
            "path": relative,
            "platform": platform_name,
            "sha256": sha256_bytes(wrapper_bytes),
            "roles": ["core", "relay"],
            "slices": slices,
            "strip_state": strip_state,
        }
        if key == "macosx":
            wrappers[key]["signature_normalized_sha256"] = signature_normalized_sha256(
                wrapper_bytes, f"Winn wrapper {key}"
            )
    return {
        "archives": archives,
        "builders": {
            "wrapper_builder": {
                "path": WRAPPER_BUILDER_RELATIVE,
                "sha256": sha256_bytes(wrapper_builder_bytes),
            },
            "wrapper_header": {
                "path": HEADER_RELATIVE,
                "sha256": sha256_bytes(header_bytes),
            },
        },
        "component": "winn-apple-engine-wrappers",
        "generation": "v3",
        "apple_toolchain": current_apple_toolchain(),
        "release": validate_release(release),
        "role_binding": ROLE_BINDING,
        "schema_version": 5,
        "source": current_source(),
        "wrappers": wrappers,
    }


def load_and_validate_provenance():
    path = pathlib.Path(provenance_raw)
    if path.is_symlink() or not path.is_file():
        fail(f"{REBUILD_REQUIRED} Provenance path: {path}")
    recorded = load_json_object(path, "Apple Winn v3 engine provenance", PROVENANCE_LIMIT)
    schema = load_json_object(pathlib.Path(schema_raw), "Apple Winn v3 provenance schema", TEXT_LIMIT)
    validate_schema(recorded, schema, schema, "$")
    return path, recorded


def verify_provenance():
    _, recorded = load_and_validate_provenance()
    expected = current_bindings(recorded.get("release"), recorded.get("archives"))
    expect_equal(recorded, expected, "Apple Winn v3 engine provenance")
    return expected


def publish_atomic(output, payload):
    if output.is_symlink():
        fail(f"Apple Winn v3 engine provenance path must not be symbolic: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | nofollow
    tmp = output.with_name(f".apple-winn-v3-engine-provenance.{secrets.token_hex(16)}")
    fd = os.open(tmp, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                fail("short Apple Winn v3 provenance write")
            view = view[written:]
        os.fsync(fd)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            fail("Apple Winn v3 provenance temp is not owner-only single-link")
    except Exception:
        os.close(fd)
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    os.close(fd)
    os.replace(tmp, output)
    dest = output.lstat()
    if (
        not stat.S_ISREG(dest.st_mode)
        or dest.st_nlink != 1
        or dest.st_uid != os.getuid()
        or dest.st_size != len(payload)
    ):
        fail("Apple Winn v3 provenance publication is not a single-link owner file")


def write_provenance():
    release, release_archives = load_release_facts()
    manifest = current_bindings(release, release_archives)
    schema = load_json_object(pathlib.Path(schema_raw), "Apple Winn v3 provenance schema", TEXT_LIMIT)
    validate_schema(manifest, schema, schema, "$")
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    publish_atomic(pathlib.Path(provenance_raw), payload)
    verify_provenance()


def archive_is_bound(archive_raw):
    archive = pathlib.Path(archive_raw)
    payload = stable_read(archive, "Winn archive candidate", ARTIFACT_LIMIT)
    _, recorded = load_and_validate_provenance()
    expected = current_bindings(recorded.get("release"), recorded.get("archives"))
    for field in ("source", "release", "builders"):
        if recorded.get(field) != expected[field]:
            sys.exit(1)
    archives = recorded.get("archives")
    if type(archives) is not dict:
        sys.exit(1)
    name = archive.name
    for key, archive_name, header_name, expected_arch, expected_platform, _target in ARCHIVE_SPECS:
        if archive_name != name:
            continue
        entry = archives.get(key)
        if type(entry) is not dict or entry != expected["archives"][key]:
            sys.exit(1)
        if entry.get("sha256") != sha256_bytes(payload):
            sys.exit(1)
        header = archive.with_name(header_name)
        header_bytes = stable_read(header, f"Winn archive header {key}", TEXT_LIMIT)
        if entry.get("header_sha256") != sha256_bytes(header_bytes):
            sys.exit(1)
        architectures, platform_name, filetype, _strip_state, _slices = inspect_snapshot(
            payload, "archive", expected_platform, [expected_arch], "Winn archive candidate"
        )
        if entry.get("architectures") != architectures:
            sys.exit(1)
        if entry.get("platform") != platform_name or entry.get("filetype") != filetype:
            sys.exit(1)
        sys.exit(0)
    sys.exit(1)


# Re-check a published provenance document against a freshly verified copy
# of the release directory it claims to come from.
def release_is_bound():
    recorded = verify_provenance()
    release, release_archives = load_release_facts()
    expect_equal(recorded["release"], release, "Winn release record")
    for key, *_ in ARCHIVE_SPECS:
        entry = recorded["archives"][key]
        for field in ("build_a_sha256", "build_b_sha256", "header_sha256", "sha256", "target"):
            expect_equal(entry[field], release_archives[key][field], f"Winn release archive {key} {field}")


if command == "verify":
    verify_provenance()
elif command == "write":
    write_provenance()
elif command == "release-bound":
    release_is_bound()
elif command == "archive-bound":
    if not rest:
        fail("archive-bound requires an archive path")
    archive_is_bound(rest[0])
else:
    fail(f"Unknown Winn provenance command: {command}")
PY
}

verify_winn_provenance() {
  command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "Python 3 is required."
  run_winn_provenance_tool verify \
    || die "Apple Winn v3 engine provenance verification failed. Cached Winn artifacts are owner-blocked until a verified rebuild refreshes provenance."
  printf 'APPLE WINN V3 ENGINE PROVENANCE: PASS\n'
}

write_winn_provenance() {
  local published_sha=""
  command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "Python 3 is required."
  mkdir -p "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}"
  [[ ! -L "${APPLE_WINN_ENGINE_PROVENANCE_FILE}" ]] \
    || die "Apple Winn v3 engine provenance path must not be symbolic."
  run_winn_provenance_tool write \
    || die "Apple Winn v3 engine provenance could not be refreshed. Incomplete or stale Winn artifacts are rebuild-required."
  published_sha="$(wins_sha256 "${APPLE_WINN_ENGINE_PROVENANCE_FILE}")" \
    || die "Apple Winn v3 engine provenance hash command failed."
  printf 'Apple Winn v3 engine provenance: %s (sha256=%s)\n' \
    "${APPLE_WINN_ENGINE_PROVENANCE_FILE}" \
    "${published_sha}"
}

winn_archive_bound_to_current_provenance() {
  command -v "${PYTHON_BIN}" >/dev/null 2>&1 || return 1
  run_winn_provenance_tool archive-bound "$1"
}

# The five Apple slices of a sealed Winn release, as target:archive-stem.
# The stems are the names the Xcode PacketTunnel targets force_load from
# WINN3_DATAPATH_ARCHIVE_DIR (tools/winn_conformance_build_out) and the names
# tools/verify_winn_abi_conformance.sh and the wrapper pass below read.
WINN_APPLE_RELEASE_SLICES=(
  "datapath-ios-arm64:libwinn-datapath-ios-arm64"
  "datapath-iossimulator-arm64:libwinn-datapath-iossimulator-arm64"
  "datapath-iossimulator-amd64:libwinn-datapath-iossimulator-amd64"
  "datapath-archive-darwin-arm64:libwinn-datapath-darwin-arm64"
  "datapath-archive-darwin-amd64:libwinn-datapath-darwin-amd64"
)

# The Winn datapath c-archives are no longer produced by this script. They
# come from a Winn release directory written by tools/winn_release.py, which
# builds every target twice from a sealed source snapshot with pinned Go,
# refuses any pair that is not byte-identical, and records every output in a
# manifest signed by the owner's release authority key.
#
# acquire_winn_release asks the driver to verify the whole release ONCE and
# print the exact manifest bytes it verified (--print-manifest). Those held
# bytes are the only manifest this function uses: manifest.json and
# manifest.sig.json are never read here. It then snapshots each Apple slice
# with O_NOFOLLOW into OUTPUT_DIR under the canonical archive names, after
# proving that they are the bytes the verified manifest names and that both
# independent builds agreed on them. FACTS receives the release record that
# the provenance document carries: manifest SHA-256, signature public key,
# source, Go toolchain, producer digests, and the per-slice digests.
#
# MODE is "signed" (release use: the driver checks the Ed25519 signature
# against the pinned authority key in tools/winn_release_authority.json, and
# the facts record that same key) or
# "unsigned-dev" (the driver's --allow-unsigned dev path; never accepted in
# release mode). WINS_WINN_TRUST_PUBLIC_KEY replaces the pinned key with a
# test key for fixtures and the offline proof; release mode refuses it.
#
# Exit 3 is passed through when the driver reports TOOLCHAIN-MISSING.
acquire_winn_release() {
  local release_dir="$1" output_dir="$2" facts="$3" mode="$4"
  local slice pairs=()
  for slice in "${WINN_APPLE_RELEASE_SLICES[@]}"; do
    pairs+=("${slice}")
  done
  "${PYTHON_BIN}" - "${release_dir}" "${output_dir}" "${facts}" "${mode}" \
    "${WINN_RELEASE_PYTHON}" "${WINN_RELEASE_DRIVER}" "${WINN_RELEASE_AUTHORITY}" \
    "${WINS_WINN_TRUST_PUBLIC_KEY:-}" "${pairs[@]}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

(
    release_raw,
    output_raw,
    facts_raw,
    mode,
    driver_python,
    driver_raw,
    authority_raw,
    trust_key,
    *pairs,
) = sys.argv[1:]

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
MANIFEST_CONTRACT = "winsvpn-winn-release-manifest-v1"
KEY_BY_TARGET = {
    "datapath-ios-arm64": "iphoneos_arm64",
    "datapath-iossimulator-arm64": "iphonesimulator_arm64",
    "datapath-iossimulator-amd64": "iphonesimulator_x86_64",
    "datapath-archive-darwin-arm64": "macosx_arm64",
    "datapath-archive-darwin-amd64": "macosx_x86_64",
}
TEXT_LIMIT = 4 * 1024 * 1024
ARTIFACT_LIMIT = 256 * 1024 * 1024
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def fail(message, code=1):
    sys.stderr.write(f"Winn release: {message}\n")
    raise SystemExit(code)


if not NOFOLLOW:
    fail("O_NOFOLLOW is required to read a Winn release")
if mode not in ("signed", "unsigned-dev"):
    fail(f"unknown signature mode {mode!r}")


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def stable_read(path, label, limit):
    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_uid not in (0, os.getuid())
        ):
            fail(f"{label} must be a nonempty single-link regular file owned by this user: {path}")
        if before.st_size > limit:
            fail(f"{label} exceeds the {limit} byte limit: {path}")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | NOFOLLOW)
        try:
            opened = os.fstat(fd)
            chunks = []
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                chunks.append(block)
            finished = os.fstat(fd)
        finally:
            os.close(fd)
        after = os.lstat(path)
    except OSError as error:
        fail(f"{label} is unreadable: {path} ({error})")
    if not (identity(before) == identity(opened) == identity(finished) == identity(after)):
        fail(f"{label} changed while it was read: {path}")
    payload = b"".join(chunks)
    if len(payload) != before.st_size:
        fail(f"{label} was short-read: {path}")
    return payload


def strict_json(payload, label):
    def exact_object(items):
        value = {}
        for key, item in items:
            if key in value:
                fail(f"{label} has a duplicate JSON key {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=exact_object,
            parse_constant=lambda token: fail(f"{label} has a non-finite constant {token}"),
        )
    except (UnicodeError, ValueError) as error:
        fail(f"{label} is invalid JSON: {error}")
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    return value


def require_sha(value, label):
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} is not an exact SHA-256 value")
    return value


def write_new(path, payload, mode_bits):
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | NOFOLLOW,
        mode_bits,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                fail(f"short write to {path}")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


release = pathlib.Path(release_raw)
if not release.is_absolute() or release.is_symlink() or not release.is_dir():
    fail(f"release directory must be an absolute non-symbolic directory: {release_raw}")
release = pathlib.Path(os.path.realpath(release))
output = pathlib.Path(output_raw)
if output.is_symlink() or not output.is_dir():
    fail(f"archive output directory is missing or symbolic: {output}")
driver = pathlib.Path(driver_raw)
if driver.is_symlink() or not driver.is_file():
    fail(f"release driver is missing or symbolic: {driver}")

if trust_key and SHA256_RE.fullmatch(trust_key) is None:
    fail("WINS_WINN_TRUST_PUBLIC_KEY must be a 32-byte hexadecimal Ed25519 public key")
public_key = ""
if mode == "signed":
    if trust_key:
        public_key = trust_key
    else:
        authority = strict_json(
            stable_read(pathlib.Path(authority_raw), "release authority pin", TEXT_LIMIT),
            "release authority pin",
        )
        if authority.get("contract") != "winsvpn-winn-release-authority-v1" or authority.get("algorithm") != "ed25519":
            fail("release authority pin contract or algorithm is invalid")
        public_key = require_sha(authority.get("public_key"), "pinned release authority public key")

# One verification. Exit 0 means the Ed25519 signature verified under the
# trusted key (the driver's pin, or the explicit test key) and every artifact
# digest, size and build A/B match held; stdout is the exact manifest bytes
# the signature covers. Everything below is taken from those bytes.
command = [driver_python, "-I", str(driver), "verify", "--release", str(release)]
if mode == "unsigned-dev":
    command.append("--allow-unsigned")
elif trust_key:
    command.extend(["--trust-public-key", trust_key])
command.append("--print-manifest")
try:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=3600,
    )
except (OSError, subprocess.TimeoutExpired) as error:
    fail(f"driver verify could not run: {error}")
sys.stderr.write(completed.stderr.decode("utf-8", "replace"))
if completed.returncode == 3:
    fail("TOOLCHAIN-MISSING while verifying the release", 3)
if completed.returncode != 0:
    fail(f"driver verify rejected the release (exit {completed.returncode})")
manifest_bytes = completed.stdout
if len(manifest_bytes) > TEXT_LIMIT or manifest_bytes.count(b"\n") != 1 or not manifest_bytes.endswith(b"\n"):
    fail("driver verify must print exactly one canonical manifest line")
manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
manifest = strict_json(manifest_bytes, "verified release manifest")
if manifest.get("contract") != MANIFEST_CONTRACT:
    fail("release manifest contract is not " + MANIFEST_CONTRACT)

entries = manifest.get("artifacts")
if type(entries) is not list:
    fail("release manifest artifacts must be a list")
by_target = {}
for entry in entries:
    if type(entry) is not dict or type(entry.get("target")) is not str:
        fail("release manifest artifact entry is malformed")
    if entry["target"] in by_target:
        fail(f"release manifest lists {entry['target']} twice")
    by_target[entry["target"]] = entry


def inside(path, root):
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


archives = {}
for pair in pairs:
    target, stem = pair.split(":", 1)
    key = KEY_BY_TARGET.get(target)
    if key is None:
        fail(f"unexpected Apple slice {target}")
    entry = by_target.get(target)
    if entry is None:
        fail(f"release does not contain the Apple slice {target}")
    artifacts_root = release / "artifacts" / target
    located = {}
    for field, label in (("path", "archive"), ("header_path", "header")):
        recorded = entry.get(field)
        if type(recorded) is not str or recorded.startswith("/") or ".." in pathlib.PurePosixPath(recorded).parts:
            fail(f"verified manifest names no release-relative {label} for {target}")
        candidate = release / recorded
        if os.path.normpath(candidate) != str(candidate) or not inside(candidate, artifacts_root):
            fail(f"verified manifest names a {label} outside artifacts/{target}: {recorded}")
        located[field] = candidate
    archive_path = located["path"]
    header_path = located["header_path"]
    sha256 = require_sha(entry.get("sha256"), f"{target} manifest sha256")
    header_sha256 = require_sha(entry.get("header_sha256"), f"{target} manifest header_sha256")
    build_a = require_sha(entry.get("build_a_sha256"), f"{target} manifest build_a_sha256")
    build_b = require_sha(entry.get("build_b_sha256"), f"{target} manifest build_b_sha256")
    if not (build_a == build_b == sha256):
        fail(f"{target} was not reproduced byte-for-byte by both release builds")
    archive_bytes = stable_read(archive_path, f"{target} archive", ARTIFACT_LIMIT)
    header_bytes = stable_read(header_path, f"{target} header", TEXT_LIMIT)
    if hashlib.sha256(archive_bytes).hexdigest() != sha256:
        fail(f"{target} archive bytes do not match the verified release manifest")
    if hashlib.sha256(header_bytes).hexdigest() != header_sha256:
        fail(f"{target} header bytes do not match the verified release manifest")
    write_new(output / f"{stem}.a", archive_bytes, 0o644)
    write_new(output / f"{stem}.h", header_bytes, 0o644)
    archives[key] = {
        "build_a_sha256": build_a,
        "build_b_sha256": build_b,
        "header_sha256": header_sha256,
        "sha256": sha256,
        "target": target,
    }

if set(archives) != set(KEY_BY_TARGET.values()):
    fail("release acquisition did not produce all five Apple slices")

source = manifest.get("source")
if type(source) is not dict:
    fail("release manifest omits source")
toolchains = manifest.get("toolchains")
go = toolchains.get("go") if type(toolchains) is dict else None
if type(go) is not dict:
    fail("release manifest omits toolchains.go")
producer = manifest.get("producer")
if type(producer) is not dict:
    fail("release manifest omits producer")


# The driver keys producer digests by file name; the interface spec named
# them builder/driver/toolchain_pins. Accept either spelling, never both.
def producer_digest(file_name, spec_name):
    if file_name in producer and spec_name in producer:
        fail(f"release manifest producer names {file_name} twice")
    return producer.get(file_name, producer.get(spec_name))


if type(source.get("commit")) is not str or COMMIT_RE.fullmatch(source["commit"]) is None:
    fail("release manifest source commit is invalid")
if source.get("binding") not in ("git-archive", "export"):
    fail("release manifest source binding is invalid")
facts = {
    "archives": archives,
    "release": {
        "contract": MANIFEST_CONTRACT,
        "go": {
            "archive_sha256": require_sha(go.get("archive_sha256"), "release Go archive"),
            "executable_sha256": require_sha(go.get("executable_sha256"), "release Go executable"),
            "install_tree_sha256": require_sha(go.get("install_tree_sha256"), "release Go install tree"),
            "version": go.get("version") if type(go.get("version")) is str else fail("release Go version is invalid"),
        },
        "manifest_sha256": manifest_sha256,
        "producer": {
            "builder_sha256": require_sha(producer_digest("build_winn_protocol_engine.sh", "builder_sha256"), "release builder"),
            "driver_sha256": require_sha(producer_digest("winn_release.py", "driver_sha256"), "release driver"),
            "toolchain_pins_sha256": require_sha(producer_digest("toolchain-pins.json", "toolchain_pins_sha256"), "release toolchain pins"),
        },
        "signature_public_key": public_key,
        "signature_state": mode,
        "source": {
            "binding": source["binding"],
            "commit": source["commit"],
            "tree_sha256": require_sha(source.get("tree_sha256"), "release source tree"),
        },
    },
}
write_new(
    pathlib.Path(facts_raw),
    (json.dumps(facts, indent=2, sort_keys=True) + "\n").encode("ascii"),
    0o600,
)
print(
    f"Winn release accepted ({mode}): manifest sha256 {manifest_sha256}"
    + (f", public key {public_key}" if public_key else ""),
    file=sys.stderr,
)
PY
}

# Dev only: produce an unsigned Apple release through the driver. The result
# is staged with --allow-unsigned and recorded as signature_state
# "unsigned-dev", which release-mode staging refuses.
build_winn_dev_release() {
  local out="$1" commit="${WINS_WINN_SOURCE_COMMIT:-}" status=0
  if [[ -z "${commit}" ]]; then
    commit="$(/usr/bin/git -C "${PROJECT_ROOT}" rev-parse --verify HEAD)" \
      || die "Could not read the source commit for a dev Winn build; set WINS_WINN_SOURCE_COMMIT."
  fi
  [[ "${commit}" =~ ^[0-9a-f]{7,64}$ ]] \
    || die "WINS_WINN_SOURCE_COMMIT must be a hexadecimal commit id."
  local args=(build --set apple --out "${out}" --source-commit "${commit}")
  if [[ -n "${WINS_WINN_SOURCE_EXPORT:-}" ]]; then
    args+=(--source-export "${WINS_WINN_SOURCE_EXPORT}")
  fi
  if [[ -n "${WINS_WINN_GO_ARCHIVE:-}" ]]; then
    args+=(--go-archive "${WINS_WINN_GO_ARCHIVE}")
  fi
  if [[ -n "${WINS_APPLE_DEVELOPER_DIR:-}" ]]; then
    args+=(--developer-dir "${WINS_APPLE_DEVELOPER_DIR}")
  fi
  if [[ -n "${WINS_WINN_MODULE_PROXY:-}" ]]; then
    args+=(--module-proxy "${WINS_WINN_MODULE_PROXY}")
  fi
  printf 'Winn: UNSIGNED DEV BUILD of the Apple set through %s (source %s)\n' \
    "${WINN_RELEASE_DRIVER}" "${commit}" >&2
  "${WINN_RELEASE_PYTHON}" -I "${WINN_RELEASE_DRIVER}" "${args[@]}" >&2 || status=$?
  if [[ "${status}" -eq 3 ]]; then
    printf 'ERROR: TOOLCHAIN-MISSING: the Winn release driver could not find a pinned toolchain.\n' >&2
    exit 3
  fi
  [[ "${status}" -eq 0 ]] || die "Winn release driver build failed (exit ${status})."
}

winn_archive_for() {
  local platform="$1"
  local arch="$2"
  local archive=""
  case "${platform}:${arch}" in
    iphoneos:arm64) archive=libwinn-datapath-ios-arm64.a ;;
    macosx:arm64) archive=libwinn-datapath-darwin-arm64.a ;;
    macosx:x86_64) archive=libwinn-datapath-darwin-amd64.a ;;
    iphonesimulator:arm64) archive=libwinn-datapath-iossimulator-arm64.a ;;
    iphonesimulator:x86_64) archive=libwinn-datapath-iossimulator-amd64.a ;;
    *) printf '\n'; return 0 ;;
  esac
  [[ -f "${WINN_DATAPATH_ARCHIVE_DIR}/${archive}" && ! -L "${WINN_DATAPATH_ARCHIVE_DIR}/${archive}" \
     && -s "${WINN_DATAPATH_ARCHIVE_DIR}/${archive}" ]] \
    || die "required Apple Winn archive ${archive} was not acquired from the Winn release."
  printf '%s/%s\n' "${WINN_DATAPATH_ARCHIVE_DIR}" "${archive}"
}

# Winn wrapper. Deliberately a separate pass from build_platform so its exact
# release architecture set and provenance transaction remain independently
# fail-closed.
# REFUSE TO LEAVE BEHIND A WRAPPER THIS RUN DID NOT WRITE.
#
# Every gate below runs against a path this script has just produced. That is
# only worth anything if a run which produces NOTHING cannot leave an older,
# ungated wrapper sitting where tools/stage_apple_engine_artifacts.sh will find
# it and copy it into WinsWinnPacketEngine.framework. Both of the early returns
# in build_winn_platform do exactly that today: they skip the build, print a
# reassuring line, and the previous run's dylib stays in EngineArtifacts and
# ships. The wrapper staged on 2026-08-05 11:30 survived every subsequent build
# this way while the winn/3 sources moved 122 files ahead of it.
#
# "Optional" has to mean "this platform produces no wrapper", never "this
# platform produces last week's wrapper". So a skip with no stale artifact
# present is still a clean skip -- a fresh clone, or a host with no Go, keeps
# building the AmneziaWG components that actually ship. A skip with a stale
# artifact present is the trap, and it is fatal. Removing the file is left to
# the operator on purpose: this script does not delete artifacts it cannot
# rebuild, and the deletion is the operator's acknowledgement that the wrapper
# was never validated by this run.
refuse_stale_winn_wrapper() {
  local platform="$1"
  local reason="$2"
  local stale
  stale="$(platform_output_dir "${platform}")/libWinsWinnPacketEngine.dylib"
  [[ -e "${stale}" ]] || return 0
  die "$(printf 'Refusing to leave an unvalidated Winn wrapper in place for %s.\n  %s\n  A wrapper from an earlier run is still at:\n    %s   (last written %s)\n  This run built nothing, so nothing gated it, and staging would ship it anyway.\n  Remove or move that file, then re-run. Do not stage it.' \
    "${platform}" "${reason}" "${stale}" "$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "${stale}" 2>/dev/null || printf 'unknown')")"
}

build_winn_platform() {
  local platform="$1"

  if [[ ! -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsWinnPacketEngine.m" || \
        -L "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsWinnPacketEngine.m" ]]; then
    die "owner-blocked: required Winn wrapper source is unavailable at ${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsWinnPacketEngine.m."
  fi

  local archs
  archs="$(platform_archs "${platform}")"

  local sdk_path
  sdk_path="$(xcrun --sdk "${platform}" --show-sdk-path)"
  local output_dir
  output_dir="$(platform_output_dir "${platform}")"

  local temp_dir
  temp_dir="$("${WINS_MKTEMP_BIN}" -d "${TMPDIR:-/tmp}/wins-winn-wrapper-${platform}.XXXXXX")" \
    || die "Could not create Winn wrapper staging directory."
  local winn_slices=()
  local built_archs=()
  local arch archive snapshot minos target winn_slice

  for arch in ${archs}; do
    archive="$(winn_archive_for "${platform}" "${arch}")"
    [[ -n "${archive}" && -f "${archive}" && ! -L "${archive}" ]] \
      || die "owner-blocked: required Winn archive is unavailable for ${platform}/${arch}."

    snapshot="${temp_dir}/libwinn-datapath-${arch}.a"
    stable_snapshot_file "${archive}" "${snapshot}" \
      || die "Could not snapshot Winn archive ${archive}."

    # Same rule the AmneziaWG path uses: the archive's own LC_BUILD_VERSION
    # decides the deployment target, so the wrapper can never be newer than the
    # Go code it force-loads.
    minos="$(archive_minos "${snapshot}" "${arch}")"
    target="$(target_triple "${platform}" "${minos}" "${arch}")"
    winn_slice="${temp_dir}/libWinsWinnPacketEngine-${arch}.dylib"

    "${CLANG_BIN}" \
      -target "${target}" \
      -isysroot "${sdk_path}" \
      -dynamiclib \
      -fobjc-arc \
      -fvisibility=hidden \
      -framework CoreFoundation \
      -framework Foundation \
      -framework Security \
      -lresolv \
      -Wl,-x \
      -Wl,-S \
      -Wl,-install_name,@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine \
      -Wl,-force_load,"${snapshot}" \
      "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsWinnPacketEngine.m" \
      -o "${winn_slice}"

    strip_and_validate_dylib "${winn_slice}"

    winn_slices+=("${winn_slice}")
    built_archs+=("${arch}")
  done

  [[ "${#winn_slices[@]}" -eq "$(wc -w <<<"${archs}" | tr -d ' ')" ]] \
    || die "owner-blocked: Winn release transaction did not produce every declared ${platform} slice."

  local winn_binary="${output_dir}/libWinsWinnPacketEngine.dylib"

  # GATE THE CANDIDATE IN THE TEMP DIR, INSTALL ONLY WHAT PASSED.
  #
  # This used to assemble straight into EngineArtifacts and gate afterwards.
  # Every require_* below is fatal, so a wrapper that failed one was left in the
  # staging directory by the very run that rejected it -- and the next run to
  # take either early return above would skip the build entirely and stage the
  # rejected file. Gating a path the caller can already see is not a gate; it is
  # a report filed after the artifact escaped.
  #
  # Assembling into ${temp_dir} first also makes the gate's subject unambiguous:
  # this path did not exist before this function ran, so it cannot be anything
  # other than what these slices produced moments ago. The staging directory
  # gets written exactly once, after the last require_* has returned.
  local candidate="${temp_dir}/gated-libWinsWinnPacketEngine.dylib"
  if [[ "${#winn_slices[@]}" -eq 1 ]]; then
    install -m 755 "${winn_slices[0]}" "${candidate}"
  else
    "${LIPO_BIN}" -create -output "${candidate}" "${winn_slices[@]}"
    chmod 755 "${candidate}"
  fi
  [[ -s "${candidate}" ]] \
    || die "Winn wrapper candidate for ${platform} was not written to ${candidate}."

  # Validate the final lipo product as well. This is the byte sequence that is
  # published and hashed, so validating only the thin link products would
  # leave the final output's symbol table outside the gate.
  strip_and_validate_dylib "${candidate}"
  require_platform "${candidate}" "${platform}"
  require_minimum_os "${candidate}" "${platform}"
  require_archs "${candidate}" "${built_archs[*]}"
  require_install_name "${candidate}" \
    "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine"
  require_symbols "${candidate}" "${WINN_COMMON_REQUIRED_SYMBOLS[@]}"
  require_symbols "${candidate}" "${WINN_RELAY_REQUIRED_SYMBOLS[@]}"
  require_symbols "${candidate}" "${WINN_CORE_REQUIRED_SYMBOLS[@]}"
  require_symbols "${candidate}" "${WINN_REQUIRED_SYMBOLS[@]}"

  mkdir -p "${output_dir}"
  install -m 755 "${candidate}" "${winn_binary}"
  rm -rf "${temp_dir}"

  printf 'Built Winn engine wrapper for %s (%s): %s\n' \
    "${platform}" "${built_archs[*]}" "${winn_binary}"
}

publish_winn_transaction_file() {
  local source="$1" destination="$2" mode="$3" temporary=""
  mkdir -p "$(dirname "${destination}")"
  temporary="$(${WINS_MKTEMP_BIN} "$(dirname "${destination}")/.winn-release-transaction.XXXXXX")" \
    || die "Could not reserve a Winn release publication path."
  rm -f "${temporary}"
  stable_snapshot_file "${source}" "${temporary}" \
    || die "Could not retain Winn release transaction output ${source}."
  chmod "${mode}" "${temporary}"
  mv -f "${temporary}" "${destination}"
}

build_winn_release_transaction() (
  local final_engine_root="${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}"
  local final_archive_root="${WINN_DATAPATH_ARCHIVE_DIR}"
  local final_provenance="${APPLE_WINN_ENGINE_PROVENANCE_FILE}"
  local live_wrapper_root="${APPLE_ENGINE_WRAPPER_SOURCE_DIR}"
  local release_dir="${WINS_WINN_RELEASE_DIR}"
  local signature_mode="signed"
  local transaction_wrapper_builder_sha=""
  local transaction=""
  local acquire_status=0
  transaction="$(${WINS_MKTEMP_BIN} -d "${TMPDIR:-/tmp}/wins-apple-winn-release.XXXXXX")" \
    || die "could not create the Apple Winn release transaction."
  cleanup_winn_release_transaction() {
    if [[ -n "${transaction}" && -d "${transaction}" && ! -L "${transaction}" ]]; then
      rm -rf "${transaction}"
    fi
  }
  trap cleanup_winn_release_transaction EXIT
  transaction_wrapper_builder_sha="$(wins_sha256 "${PROJECT_ROOT}/tools/build_apple_engine_wrappers.sh")" \
    || die "Apple Winn wrapper builder could not be retained."
  local transaction_wrappers="${transaction}/wrappers"
  local transaction_archives="${transaction}/archives"
  local transaction_engines="${transaction}/engines"
  local transaction_facts="${transaction}/release-facts.json"

  if [[ -z "${release_dir}" ]]; then
    release_dir="${transaction}/dev-release"
    signature_mode="unsigned-dev"
    build_winn_dev_release "${release_dir}"
  elif [[ "${WINS_WINN_ALLOW_UNSIGNED}" == "1" ]]; then
    signature_mode="unsigned-dev"
  fi

  rm -f "${final_provenance}"
  mkdir -p "${transaction_wrappers}" "${transaction_archives}" "${transaction_engines}"
  local wrapper_input
  for wrapper_input in WinnTunnel.h WinsWinnPacketEngine.m WinnTunnelTestDouble.c; do
    stable_snapshot_file "${live_wrapper_root}/${wrapper_input}" "${transaction_wrappers}/${wrapper_input}" \
      || die "Winn wrapper input ${wrapper_input} could not be retained."
  done

  acquire_winn_release "${release_dir}" "${transaction_archives}" "${transaction_facts}" "${signature_mode}" \
    || acquire_status=$?
  if [[ "${acquire_status}" -eq 3 ]]; then
    printf 'ERROR: TOOLCHAIN-MISSING: the Winn release driver could not verify the release.\n' >&2
    exit 3
  fi
  [[ "${acquire_status}" -eq 0 ]] \
    || die "the Winn release was not accepted; nothing was staged."

  APPLE_ENGINE_WRAPPER_SOURCE_DIR="${transaction_wrappers}"
  WINN_DATAPATH_ARCHIVE_DIR="${transaction_archives}"
  APPLE_ENGINE_WRAPPER_OUTPUT_ROOT="${transaction_engines}"
  APPLE_WINN_ENGINE_PROVENANCE_FILE="${transaction_engines}/apple_winn_v3_engine_provenance.json"
  APPLE_WINN_RELEASE_FACTS="${transaction_facts}"

  # The C ABI and header-semantics gate runs against the exact acquired
  # archive and header bytes before anything is compiled from them.
  verify_winn_abi
  build_winn_platform macosx
  build_winn_platform iphoneos
  build_winn_platform iphonesimulator
  [[ "$(wins_sha256 "${PROJECT_ROOT}/tools/build_apple_engine_wrappers.sh")" == "${transaction_wrapper_builder_sha}" ]] \
    || die "Apple Winn wrapper builder changed during the release transaction."
  write_winn_provenance
  verify_winn_provenance
  [[ "$(wins_sha256 "${PROJECT_ROOT}/tools/build_apple_engine_wrappers.sh")" == "${transaction_wrapper_builder_sha}" ]] \
    || die "Apple Winn wrapper builder changed before release publication."

  APPLE_ENGINE_WRAPPER_SOURCE_DIR="${live_wrapper_root}"
  verify_winn_provenance \
    || die "retained Winn transaction no longer matches the live wrapper sources."
  local archive_name header_name relative stale
  for archive_name in \
    libwinn-datapath-ios-arm64.a \
    libwinn-datapath-darwin-arm64.a \
    libwinn-datapath-darwin-amd64.a \
    libwinn-datapath-iossimulator-arm64.a \
    libwinn-datapath-iossimulator-amd64.a; do
    header_name="${archive_name%.a}.h"
    publish_winn_transaction_file "${transaction_archives}/${archive_name}" "${final_archive_root}/${archive_name}" 0644
    publish_winn_transaction_file "${transaction_archives}/${header_name}" "${final_archive_root}/${header_name}" 0644
    # Receipt sidecars from the retired producer would describe other bytes.
    for stale in custody.json receipt.json ready; do
      rm -f "${final_archive_root}/${archive_name}.${stale}"
    done
  done
  for relative in \
    ios/iphoneos/libWinsWinnPacketEngine.dylib \
    ios/iphonesimulator/libWinsWinnPacketEngine.dylib \
    macos/libWinsWinnPacketEngine.dylib; do
    publish_winn_transaction_file "${transaction_engines}/${relative}" "${final_engine_root}/${relative}" 0755
  done
  publish_winn_transaction_file \
    "${transaction_engines}/apple_winn_v3_engine_provenance.json" \
    "${final_provenance}" 0600

  WINN_DATAPATH_ARCHIVE_DIR="${final_archive_root}"
  APPLE_ENGINE_WRAPPER_OUTPUT_ROOT="${final_engine_root}"
  APPLE_WINN_ENGINE_PROVENANCE_FILE="${final_provenance}"
  if ! verify_winn_provenance; then
    rm -f "${final_provenance}"
    die "published Apple Winn transaction did not reverify against the published bytes."
  fi
  printf 'Winn release staged for Apple (%s): archives in %s, wrappers in %s\n' \
    "${signature_mode}" "${final_archive_root}" "${final_engine_root}"
  rm -rf "${transaction}"
  transaction=""
)

# Check that a release directory is acceptable for the Apple build without
# writing anything outside a scratch directory: every Apple slice verifies
# through the driver and matches the manifest, and both builds agreed.
verify_winn_release_acceptable() (
  local mode="signed" status=0 scratch=""
  if [[ "${WINS_WINN_ALLOW_UNSIGNED}" == "1" ]]; then
    mode="unsigned-dev"
  fi
  scratch="$(${WINS_MKTEMP_BIN} -d "${TMPDIR:-/tmp}/wins-apple-winn-release-check.XXXXXX")" \
    || die "could not create a Winn release check directory."
  trap 'rm -rf "${scratch}"' EXIT
  mkdir -p "${scratch}/archives"
  acquire_winn_release "${WINS_WINN_RELEASE_DIR}" "${scratch}/archives" "${scratch}/facts.json" "${mode}" \
    || status=$?
  if [[ "${status}" -eq 3 ]]; then
    printf 'ERROR: TOOLCHAIN-MISSING: the Winn release driver could not verify the release.\n' >&2
    exit 3
  fi
  [[ "${status}" -eq 0 ]] || die "the Winn release is not acceptable for the Apple build."
  cat "${scratch}/facts.json"
  printf 'APPLE WINN RELEASE: ACCEPTED (%s)\n' "${mode}"
)

# Re-verify a published provenance document against a release directory:
# the driver re-checks the signature (or, for an unsigned-dev record, the
# digests only) and every recorded manifest, signature-key, and per-slice
# digest must match what is published.
verify_winn_release_binding() (
  local release_dir="$1" recorded_state="" mode="signed" status=0 scratch=""
  recorded_state="$("${PYTHON_BIN}" -c 'import json,sys; print(json.load(open(sys.argv[1]))["release"]["signature_state"])' \
    "${APPLE_WINN_ENGINE_PROVENANCE_FILE}")" \
    || die "Apple Winn v3 provenance has no readable release record."
  case "${recorded_state}" in
    signed) mode="signed" ;;
    unsigned-dev)
      [[ "${WINS_APPLE_WINN3_RELEASE:-0}" != "1" ]] \
        || die "Release mode refuses an unsigned-dev Winn release."
      mode="unsigned-dev"
      ;;
    *) die "Apple Winn v3 provenance release signature_state is invalid." ;;
  esac
  scratch="$(${WINS_MKTEMP_BIN} -d "${TMPDIR:-/tmp}/wins-apple-winn-rebind.XXXXXX")" \
    || die "could not create a Winn release re-verification directory."
  trap 'rm -rf "${scratch}"' EXIT
  mkdir -p "${scratch}/archives"
  acquire_winn_release "${release_dir}" "${scratch}/archives" "${scratch}/facts.json" "${mode}" \
    || status=$?
  if [[ "${status}" -eq 3 ]]; then
    printf 'ERROR: TOOLCHAIN-MISSING: the Winn release driver could not verify the release.\n' >&2
    exit 3
  fi
  [[ "${status}" -eq 0 ]] || die "the Winn release was not accepted on re-verification."
  APPLE_WINN_RELEASE_FACTS="${scratch}/facts.json" run_winn_provenance_tool release-bound \
    || die "Apple Winn v3 provenance is not bound to the release at ${release_dir}."
  printf 'APPLE WINN V3 RELEASE BINDING: PASS (%s)\n' "${mode}"
)

build_platform() {
  local platform="$1"
  local archs
  archs="$(platform_archs "${platform}")"
  local bridge_archive="${APPLE_WG_GO_OUTPUT_DIR}/${platform}/libwg-go.a"
  [[ -f "${bridge_archive}" ]] || die "Missing Apple Go bridge archive: ${bridge_archive}"
  require_symbols "${bridge_archive}" "wgGetConfig"

  local sdk_path
  sdk_path="$(xcrun --sdk "${platform}" --show-sdk-path)"
  local output_dir
  output_dir="$(platform_output_dir "${platform}")"
  mkdir -p "${output_dir}"

  local awg_binary="${output_dir}/libWinsAmneziaWGPacketEngine.dylib"
  local xray_binary="${output_dir}/libWinsXrayVlessWsTransport.dylib"
  local temp_dir
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/wins-engine-wrapper-${platform}.XXXXXX")"
  local awg_slices=()
  local xray_slices=()
  local framework_loader_rpath
  case "${platform}" in
    macosx)
      framework_loader_rpath="@loader_path/../../.."
      ;;
    iphoneos|iphonesimulator)
      framework_loader_rpath="@loader_path/.."
      ;;
    *)
      die "Unknown Apple platform '${platform}'."
      ;;
  esac
  local arch

  for arch in ${archs}; do
    local minos
    minos="$(archive_minos "${bridge_archive}" "${arch}")"
    local target
    target="$(target_triple "${platform}" "${minos}" "${arch}")"
    local thin_archive="${temp_dir}/libwg-go-${arch}.a"
    local awg_slice="${temp_dir}/libWinsAmneziaWGPacketEngine-${arch}.dylib"
    local xray_slice="${temp_dir}/libWinsXrayVlessWsTransport-${arch}.dylib"

    "${LIPO_BIN}" "${bridge_archive}" -thin "${arch}" -output "${thin_archive}"

    "${CLANG_BIN}" \
      -target "${target}" \
      -isysroot "${sdk_path}" \
      -dynamiclib \
      -fobjc-arc \
      -fvisibility=hidden \
      -framework Foundation \
      -framework Security \
      -lresolv \
      -Wl,-x \
      -Wl,-install_name,@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine \
      -Wl,-force_load,"${thin_archive}" \
      "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsAmneziaWGPacketEngine.m" \
      -o "${awg_slice}"

    "${CLANG_BIN}" \
      -target "${target}" \
      -isysroot "${sdk_path}" \
      -dynamiclib \
      -fobjc-arc \
      -fvisibility=hidden \
      -framework Foundation \
      -L"${temp_dir}" \
      -lWinsAmneziaWGPacketEngine-${arch} \
      -Wl,-x \
      -Wl,-install_name,@rpath/WinsXrayVlessWsTransport.framework/WinsXrayVlessWsTransport \
      -Wl,-rpath,"${framework_loader_rpath}" \
      "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsXrayVlessWsTransport.m" \
      -o "${xray_slice}"

    awg_slices+=("${awg_slice}")
    xray_slices+=("${xray_slice}")
  done

  if [[ "${#awg_slices[@]}" -eq 1 ]]; then
    install -m 755 "${awg_slices[0]}" "${awg_binary}"
    install -m 755 "${xray_slices[0]}" "${xray_binary}"
  else
    "${LIPO_BIN}" -create -output "${awg_binary}" "${awg_slices[@]}"
    "${LIPO_BIN}" -create -output "${xray_binary}" "${xray_slices[@]}"
    chmod 755 "${awg_binary}" "${xray_binary}"
  fi
  rm -rf "${temp_dir}"

  require_platform "${awg_binary}" "${platform}"
  require_platform "${xray_binary}" "${platform}"
  require_minimum_os "${awg_binary}" "${platform}"
  require_minimum_os "${xray_binary}" "${platform}"
  require_archs "${awg_binary}" "${archs}"
  require_archs "${xray_binary}" "${archs}"
  require_symbols "${awg_binary}" "${AWG_REQUIRED_SYMBOLS[@]}"
  require_symbols "${xray_binary}" "${XRAY_REQUIRED_SYMBOLS[@]}"
  require_undefined_symbols "${xray_binary}" "${XRAY_REQUIRED_UNDEFINED_SYMBOLS[@]}"
  "${OTOOL_BIN}" -L "${xray_binary}" \
    | grep -q '@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine' \
    || die "Xray wrapper must depend on the embedded AWG framework."

  printf 'Built Apple engine wrappers for %s (%s): %s\n' "${platform}" "${archs}" "${output_dir}"
}

# The Winn C ABI conformance guard. This runs BEFORE anything is compiled and a
# failure is fatal, including for the AmneziaWG components.
#
# C carries no arity, so a wrapper calling a Winn entry point with the wrong
# signature links cleanly and then writes through an uninitialised register
# inside Go. That has already happened once in this tree: WinnTunnel.h was
# written against a plan document and disagreed with the real archive on 4 of 5
# entry points, while the test double implemented the same wrong contract so
# every test passed. Nothing about that failure is visible at link time, so it
  # has to be caught here, and it has to be unconditional. An ABI mismatch that
# only fails the optional component is an ABI mismatch someone will ship.
verify_winn_abi() {
  # No Winn header in the tree means no Winn ABI to disagree about.
  [[ -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinnTunnel.h" ]] || return 0
  # But once the header exists the guard is not optional and must not be
  # silently skippable by deleting it.
  #
  # THE TEST IS READABILITY, NOT THE EXECUTABLE BIT, AND THE GUARD IS INVOKED
  # THROUGH bash.
  #
  # This condition was `[[ -x ... ]]` and it took the whole script down on every
  # host in this tree, measured 2026-08-09: the repository sets
  # core.fileMode=false and records tools/verify_winn_abi_conformance.sh as mode
  # 100644, so the file is not executable in any checkout and never can become
  # one without a git mode change. verify_winn_abi runs from main() before the
  # target dispatch, so the failure was total -- `build_apple_engine_wrappers.sh
  # all` and `... winn` both died here, and NO Apple engine wrapper of any kind
  # could be rebuilt. That is the reason the staged Winn dylib still dated from
  # 2026-08-05 11:30 while 122 winn3/*.go files moved past it, and why the
  # AmneziaWG and Xray wrappers beside it date from July.
  #
  # A permission bit git is configured not to track is not a security property.
  # The property that matters is that the guard cannot be skipped by removing
  # the file, and that is preserved exactly: an absent or unreadable guard is
  # still fatal. Running it through bash makes the check independent of a bit
  # this repository cannot carry.
  [[ -f "${PROJECT_ROOT}/tools/verify_winn_abi_conformance.sh" \
     && -r "${PROJECT_ROOT}/tools/verify_winn_abi_conformance.sh" ]] \
    || die "apple/EngineWrappers/WinnTunnel.h exists but tools/verify_winn_abi_conformance.sh is missing or unreadable. The Winn C ABI cannot be built unverified."
  #
  # It now runs inside the Winn release transaction, against the five archives
  # and headers acquired from the release. WINN_ABI_SKIP_BUILD keeps the guard
  # from building substitutes, and the slice list is exactly the Apple set so
  # every acquired archive is checked and nothing else is.
  WINN_DATAPATH_ARCHIVE_DIR="${WINN_DATAPATH_ARCHIVE_DIR}" \
  APPLE_ENGINE_WRAPPER_SOURCE_DIR="${APPLE_ENGINE_WRAPPER_SOURCE_DIR}" \
  WINN_ABI_SKIP_BUILD=1 \
  WINN_ABI_SLICES="macosx:arm64:13.0 macosx:x86_64:13.0 iphoneos:arm64:13.0 iphonesimulator:arm64:14.0 iphonesimulator:x86_64:13.0" \
    bash "${PROJECT_ROOT}/tools/verify_winn_abi_conformance.sh" \
    || die "Winn C ABI conformance failed. The wrapper and the real c-archive disagree; see the compiler output above."
}

usage_die() {
  die "$(printf '%s\n' \
    "Usage: build_apple_engine_wrappers.sh [TARGET] [--release DIR [--allow-unsigned]]" \
    "  TARGET: all (default), awg, winn, verify-awg-provenance, verify-winn-provenance," \
    "          verify-xray-provenance, write-winn-provenance, write-xray-provenance," \
    "          archive-bound-winn-provenance ARCHIVE, verify-winn-release" \
    "  --release DIR      take the five Apple Winn slices from a signed Winn release" \
    "                     directory (also WINS_WINN_RELEASE_DIR). Without it, winn/all" \
    "                     build an UNSIGNED dev release through tools/winn_release.py." \
    "  --allow-unsigned   dev only: accept an unsigned release directory." \
    "  $*")"
}

main() {
  local target="all"
  local archive_argument=""
  if [[ $# -gt 0 && "$1" != --* ]]; then
    target="$1"
    shift
  fi

  case "${target}" in
    all|awg|winn|verify-awg-provenance|verify-winn-provenance|verify-xray-provenance|write-winn-provenance|write-xray-provenance|archive-bound-winn-provenance|verify-winn-release) ;;
    *) usage_die "Unknown target '${target}'." ;;
  esac
  if [[ "${target}" == "archive-bound-winn-provenance" && $# -gt 0 && "$1" != --* ]]; then
    archive_argument="$1"
    shift
  fi
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --release)
        [[ $# -ge 2 && -n "$2" ]] || usage_die "--release requires a directory."
        WINS_WINN_RELEASE_DIR="$2"
        shift 2
        ;;
      --allow-unsigned)
        WINS_WINN_ALLOW_UNSIGNED=1
        shift
        ;;
      *) usage_die "Unknown argument '$1'." ;;
    esac
  done

  if [[ "${target}" == "verify-awg-provenance" ]]; then
    command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "Python 3 is required."
    verify_awg_provenance engine
    verify_xray_provenance
    printf 'APPLE AWG 3.1 ENGINE PROVENANCE: PASS\n'
    return 0
  fi

  if [[ "${target}" == "verify-xray-provenance" ]]; then
    command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "Python 3 is required."
    verify_xray_provenance
    return 0
  fi

  if [[ "${target}" == "write-xray-provenance" ]]; then
    command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "Python 3 is required."
    apple_refuse_live_xray_provenance_hash_without_rebuild
    write_xray_provenance
    return 0
  fi

  if [[ "${target}" == "verify-winn-release" ]]; then
    [[ -n "${WINS_WINN_RELEASE_DIR}" ]] || usage_die "verify-winn-release requires --release DIR."
    apple_require_exact_winn_release_inputs
    verify_winn_release_acceptable
    return 0
  fi

  if [[ "${target}" == "verify-winn-provenance" ]]; then
    ensure_tools
    verify_winn_provenance
    if [[ -n "${WINS_WINN_RELEASE_DIR}" ]]; then
      [[ "${WINS_WINN_RELEASE_DIR}" == /* && -d "${WINS_WINN_RELEASE_DIR}" && ! -L "${WINS_WINN_RELEASE_DIR}" ]] \
        || die "WINS_WINN_RELEASE_DIR must be an absolute non-symbolic directory."
      verify_winn_release_binding "${WINS_WINN_RELEASE_DIR}"
    elif [[ "${WINS_APPLE_WINN3_RELEASE:-0}" == "1" ]]; then
      die "Release mode requires the signed Winn release directory (--release DIR) to re-verify provenance."
    fi
    return 0
  fi

  if [[ "${target}" == "write-winn-provenance" ]]; then
    ensure_tools
    apple_refuse_live_winn_provenance_hash_without_rebuild
    write_winn_provenance
    return 0
  fi

  if [[ "${target}" == "archive-bound-winn-provenance" ]]; then
    ensure_tools
    [[ -n "${archive_argument}" ]] || die "archive-bound-winn-provenance requires an archive path."
    winn_archive_bound_to_current_provenance "${archive_argument}" \
      || die "Winn archive is not bound to current Winn v3 provenance: ${archive_argument}"
    printf 'APPLE WINN V3 ARCHIVE BINDING: PASS\n'
    return 0
  fi

  if [[ "${target}" == "winn" || "${target}" == "all" ]]; then
    apple_require_exact_winn_release_inputs
  fi

  ensure_tools

  mkdir -p "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}"
  [[ ! -L "${APPLE_WINN_ENGINE_PROVENANCE_FILE}" ]] \
    || die "Apple Winn v3 engine provenance path must not be symbolic."
  [[ ! -L "${APPLE_XRAY_ENGINE_PROVENANCE_FILE}" ]] \
    || die "Apple Xray VLESS-WS engine provenance path must not be symbolic."

  if [[ "${target}" == "awg" ]]; then
    [[ -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsAmneziaWGPacketEngine.m" ]] \
      || die "Missing AWG wrapper source."
    [[ -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsXrayVlessWsTransport.m" ]] \
      || die "Missing Xray wrapper source."
    [[ ! -L "${APPLE_AWG_ENGINE_PROVENANCE_FILE}" ]] \
      || die "Apple AWG engine provenance path must not be symbolic."
    rm -f "${APPLE_AWG_ENGINE_PROVENANCE_FILE}"
    rm -f "${APPLE_XRAY_ENGINE_PROVENANCE_FILE}"
    verify_awg_provenance bridge
    build_platform macosx
    build_platform iphoneos
    build_platform iphonesimulator
    write_engine_provenance
    write_xray_provenance
    printf 'Apple AWG/Xray engine wrapper rebuild complete: %s\n' \
      "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}"
    return 0
  fi

  if [[ "${target}" == "winn" ]]; then
    [[ -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsWinnPacketEngine.m" ]] \
      || die "Missing Winn wrapper source."
    build_winn_release_transaction
    printf 'Winn engine wrapper build complete: %s\n' "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}"
    return 0
  fi

  [[ -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsAmneziaWGPacketEngine.m" ]] \
    || die "Missing AWG wrapper source."
  [[ -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsXrayVlessWsTransport.m" ]] \
    || die "Missing Xray wrapper source."
  [[ -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsWinnPacketEngine.m" ]] \
    || die "Missing Winn wrapper source."

  # The Winn transaction runs first so its C ABI conformance gate still
  # precedes every compile in an `all` build, AmneziaWG included.
  build_winn_release_transaction

  mkdir -p "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}"
  [[ ! -L "${APPLE_AWG_ENGINE_PROVENANCE_FILE}" ]] \
    || die "Apple AWG engine provenance path must not be symbolic."
  [[ ! -L "${APPLE_XRAY_ENGINE_PROVENANCE_FILE}" ]] \
    || die "Apple Xray VLESS-WS engine provenance path must not be symbolic."
  rm -f "${APPLE_AWG_ENGINE_PROVENANCE_FILE}"
  rm -f "${APPLE_XRAY_ENGINE_PROVENANCE_FILE}"

  if [[ "${WINS_SKIP_APPLE_WG_GO_BUILD}" != "1" ]]; then
    APPLE_WG_GO_OUTPUT_DIR="${APPLE_WG_GO_OUTPUT_DIR}" \
      /bin/bash "${PROJECT_ROOT}/tools/build_apple_wg_go_bridge.sh"
  fi
  verify_awg_provenance bridge

  build_platform macosx
  build_platform iphoneos
  build_platform iphonesimulator
  write_engine_provenance
  write_xray_provenance

  printf 'Apple engine wrapper build complete: %s\n' "${APPLE_ENGINE_WRAPPER_OUTPUT_ROOT}"
}

main "$@"
