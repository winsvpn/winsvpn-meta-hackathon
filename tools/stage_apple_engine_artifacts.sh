#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
STAGING_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
WINS_REQUIRE_APPLE_ENGINE="${WINS_REQUIRE_APPLE_ENGINE:-0}"
WINS_APPLE_WINN3_RELEASE="${WINS_APPLE_WINN3_RELEASE:-0}"
WINS_STAGE_APPLE_ENGINE_SELFTEST="${WINS_STAGE_APPLE_ENGINE_SELFTEST:-0}"
APPLE_AWG_ENGINE_PROVENANCE_NAME="apple_awg_31_engine_provenance.json"
APPLE_WINN_ENGINE_PROVENANCE_NAME="apple_winn_v3_engine_provenance.json"
APPLE_XRAY_ENGINE_PROVENANCE_NAME="apple_xray_vless_ws_engine_provenance.json"
APPLE_WINN_EXPECTED_MODULE="winsvpn.local/winnprotocol"
APPLE_WINN_EXPECTED_GENERATION="v3"
APPLE_AWG_EXPECTED_REPOSITORY="https://github.com/amnezia-vpn/amneziawg-apple.git"
APPLE_AWG_EXPECTED_TAG="v3.1.20260814"
APPLE_AWG_EXPECTED_COMMIT="fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d"
APPLE_AWG_EXPECTED_TREE="24183de0cc22b957ff9e34ac3494a80f515ac565"
APPLE_AWG_EXPECTED_GENERATION="3.1"
APPLE_AWG_EXPECTED_GO_VERSION="1.27.1"
APPLE_AWG_EXPECTED_GO_MOD_SHA256="790252dad6cad8aa668ccc4dafdfdac4f2fa3d3fbefce16ded750f0a46cabe0d"
APPLE_AWG_EXPECTED_GO_SUM_SHA256="1a806e7973118c0ce8832e15d246fea0c44335a31fc4a0abe36a2ed165fada9d"
# APPLE_AWG_EXPECTED_GO_DARWIN_ARM64_SHA256 and _AMD64_SHA256 are read from
# tools/toolchain-pins.json (tools.go.archive_sha256.darwin_*) once die() exists.
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

ALL_COMPONENTS=(
  "amneziawg_packet_engine"
  "xray_vless_ws_transport"
  "winn_packet_engine"
)

if [[ "${WINS_APPLE_WINN3_RELEASE}" == "1" ]]; then
  REQUIRED_COMPONENTS=(
    "amneziawg_packet_engine"
    "xray_vless_ws_transport"
    "winn_packet_engine"
  )
  OPTIONAL_COMPONENTS=()
else
  if [[ "${WINS_REQUIRE_APPLE_ENGINE}" == "1" ]]; then
    REQUIRED_COMPONENTS=(
      "amneziawg_packet_engine"
      "xray_vless_ws_transport"
      "winn_packet_engine"
    )
    OPTIONAL_COMPONENTS=()
  else
    REQUIRED_COMPONENTS=("amneziawg_packet_engine" "xray_vless_ws_transport")
    OPTIONAL_COMPONENTS=("winn_packet_engine")
  fi
fi

SYMBOL_CONTRACT_VERSION=1

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# The reviewed Go archive digests have one source of truth: the toolchain pin
# file beside this script. A missing, symbolic, or non-64-hex value refuses.
toolchain_go_archive_pin() {
  local key="$1"
  local pins="${STAGING_SCRIPT_DIR}/toolchain-pins.json"
  local value=""
  [[ -f "${pins}" && ! -L "${pins}" ]] || return 1
  value="$(/usr/bin/plutil -extract "tools.go.archive_sha256.${key}" raw -o - "${pins}")" \
    || return 1
  [[ "${value}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${value}"
}

APPLE_AWG_EXPECTED_GO_DARWIN_ARM64_SHA256="$(toolchain_go_archive_pin darwin_arm64)" \
  || die "tools/toolchain-pins.json does not pin a 64-hex tools.go.archive_sha256.darwin_arm64."
APPLE_AWG_EXPECTED_GO_DARWIN_AMD64_SHA256="$(toolchain_go_archive_pin darwin_amd64)" \
  || die "tools/toolchain-pins.json does not pin a 64-hex tools.go.archive_sha256.darwin_amd64."

if [[ "${WINS_APPLE_WINN3_RELEASE}" == "1" ]]; then
  [[ -z "${APPLE_ENGINE_ARTIFACTS_DIR:-}" ]] \
    || die "APPLE_ENGINE_ARTIFACTS_DIR reuse is forbidden in production Apple staging."
  [[ "${WINS_APPLE_ENGINE_TRANSACTION_PROVENANCE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
    || die "Production Apple staging requires the current build transaction provenance receipt."
fi

WINS_SHA256_BIN="/usr/bin/shasum"
WINS_LIPO_BIN="/usr/bin/lipo"
WINS_FILE_BIN="/usr/bin/file"
WINS_OTOOL_BIN="/usr/bin/otool"
WINS_STRIP_BIN="/usr/bin/strip"
WINS_NM_BIN="/usr/bin/nm"


# Bash 3.2 ignores `set -e` for `local x=$(cmd)` and inside `$(function)`.
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

component_candidates() {
  case "$1" in
    amneziawg_packet_engine)
      printf '%s\n' \
        "WinsAmneziaWGPacketEngine.framework" \
        "AmneziaWGPacketEngine.framework" \
        "libWinsAmneziaWGPacketEngine.dylib" \
        "WinsAmneziaWGPacketEngine.dylib" \
        "WinsAmneziaWGPacketEngine" \
        "amneziawg_packet_engine"
      ;;
    xray_vless_ws_transport)
      printf '%s\n' \
        "WinsXrayVlessWsTransport.framework" \
        "XrayVlessWsTransport.framework" \
        "libWinsXrayVlessWsTransport.dylib" \
        "WinsXrayVlessWsTransport.dylib" \
        "WinsXrayVlessWsTransport" \
        "xray_vless_ws_transport"
      ;;
    winn_packet_engine)
      printf '%s\n' \
        "WinsWinnPacketEngine.framework" \
        "WinnPacketEngine.framework" \
        "libWinsWinnPacketEngine.dylib" \
        "WinsWinnPacketEngine.dylib" \
        "WinsWinnPacketEngine" \
        "winn_packet_engine"
      ;;
    *)
      return 1
      ;;
  esac
}

component_required_symbols() {
  case "$1" in
    amneziawg_packet_engine)
      printf '%s\n' \
        "wins_amneziawg_packet_engine_contract_version" \
        "wins_amneziawg_packet_engine_create" \
        "wins_amneziawg_packet_engine_start" \
        "wins_amneziawg_packet_engine_listen_port" \
        "wins_amneziawg_packet_engine_stop" \
        "wins_amneziawg_packet_engine_destroy"
      ;;
    xray_vless_ws_transport)
      printf '%s\n' \
        "wins_xray_vless_ws_transport_contract_version" \
        "wins_xray_vless_ws_transport_configure" \
        "wins_xray_vless_ws_transport_start" \
        "wins_xray_vless_ws_transport_stop"
      ;;
    winn_packet_engine)
      # The five v1 carrier symbols, PLUS the three additive ones. Gating only
      # the v1 five is how a stale engine shipped unnoticed: on 2026-08-05 the
      # staged artifacts were a 2026-08-04 12:20 build exporting six symbols,
      # this phase staged them without complaint, and the appex ran for a full
      # session with no seam accounting at all.
      #
      # All three additive symbols fail SILENTLY when absent, which is why they
      # are gated here and not merely in build_apple_engine_wrappers.sh:
      #   * awg_seam_port    - without it the wrapper loads, starts, and carries
      #                        nothing, because AmneziaWG keeps talking to the
      #                        gateway from its own socket.
      #   * seam_stats       - the only view of the loopback boundary. The seam
      #                        lost 34% of an unpaced burst on 2026-08-04 without
      #                        a single counter moving anywhere in the system.
      #   * status_json      - the Go engine's own view of that same boundary.
      #
      #   * WinnTunnelCreateWinn3 - the create for the STANDALONE winn/3 shape,
      #                        added to this list on 2026-08-09. Its absence is
      #                        the quietest of the four and the only one that has
      #                        already reached the App Store. The eight symbols
      #                        above it all belong to the v1 relay carrier, so a
      #                        dylib built before winn/3 existed satisfies every
      #                        one of them and stages clean. The 2026-08-05 11:30
      #                        wrapper did exactly that, and Runner.app,
      #                        PacketTunnel.appex, WinsWinnPacketEngine.framework
      #                        and the 1.0.14+29 .ipa each shipped with ZERO
      #                        winn3 strings while this phase reported success on
      #                        every build in between. The Apple pump resolves the
      #                        create through dlsym, so there is no link error to
      #                        catch it: dlsym returns NULL and the host reports
      #                        StartError.symbolsUnavailable at connect time.
      #
      # build_apple_engine_wrappers.sh already requires all nine, but it is not
      # in the Xcode build path. This phase IS, so a regression that dropped a
      # symbol would otherwise reach a bundle without ever failing a build.
      printf '%s\n' \
        "wins_winn_packet_engine_contract_version" \
        "wins_winn_packet_engine_create" \
        "wins_winn_packet_engine_start" \
        "wins_winn_packet_engine_stop" \
        "wins_winn_packet_engine_destroy" \
        "wins_winn_packet_engine_awg_seam_port" \
        "wins_winn_packet_engine_expect_awg_port" \
        "wins_winn_packet_engine_seam_stats" \
        "wins_winn_packet_engine_status_json" \
        "WinnTunnelCreateWinn3"
      ;;
    *)
      return 1
      ;;
  esac
}

platform_family() {
  case "${PLATFORM_NAME:-}" in
    iphoneos|iphonesimulator)
      printf 'ios\n'
      ;;
    macosx)
      printf 'macos\n'
      ;;
    *)
      printf 'unknown\n'
      ;;
  esac
}

expected_macho_platform() {
  case "${PLATFORM_NAME:-}" in
    iphoneos)
      printf 'IOS\n'
      ;;
    iphonesimulator)
      printf 'IOSSIMULATOR\n'
      ;;
    macosx)
      printf 'MACOS\n'
      ;;
    *)
      printf 'UNKNOWN\n'
      ;;
  esac
}

source_directories() {
  local family
  family="$(platform_family)"

  if [[ -n "${APPLE_ENGINE_ARTIFACTS_DIR:-}" ]]; then
    printf '%s\n' "${APPLE_ENGINE_ARTIFACTS_DIR}"
  fi

  case "${PLATFORM_NAME:-}" in
    iphoneos|iphonesimulator)
      printf '%s\n' \
        "${PROJECT_ROOT}/apple/EngineArtifacts/${family}/${PLATFORM_NAME}" \
        "${PROJECT_ROOT}/apple/EngineArtifacts/${PLATFORM_NAME}" \
        "${PROJECT_ROOT}/apple/EngineArtifacts/${family}"
      ;;
    macosx)
      printf '%s\n' \
        "${PROJECT_ROOT}/apple/EngineArtifacts/${family}" \
        "${PROJECT_ROOT}/apple/EngineArtifacts/${PLATFORM_NAME}"
      ;;
    *)
      ;;
  esac
}

artifact_executable() {
  local artifact_path="$1"
  if [[ "${artifact_path}" == *.framework ]]; then
    local framework_name
    framework_name="$(basename "${artifact_path}" .framework)"
    if [[ -x "${artifact_path}/${framework_name}" ]]; then
      printf '%s\n' "${artifact_path}/${framework_name}"
      return 0
    fi

    if [[ -f "${artifact_path}/Info.plist" && -x /usr/libexec/PlistBuddy ]]; then
      local plist_executable
      plist_executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "${artifact_path}/Info.plist" 2>/dev/null || true)"
      if [[ -n "${plist_executable}" && -x "${artifact_path}/${plist_executable}" ]]; then
        printf '%s\n' "${artifact_path}/${plist_executable}"
        return 0
      fi
    fi

    local candidate
    for candidate in "${artifact_path}"/*; do
      if [[ -f "${candidate}" && -x "${candidate}" ]]; then
        printf '%s\n' "${candidate}"
        return 0
      fi
    done
    return 1
  fi

  [[ -f "${artifact_path}" ]] || return 1
  printf '%s\n' "${artifact_path}"
}

artifact_platforms() {
  local executable="$1"
  local vtool_bin="vtool"
  if command -v xcrun >/dev/null 2>&1; then
    vtool_bin="$(xcrun -f vtool 2>/dev/null || printf 'vtool')"
  fi

  if command -v "${vtool_bin}" >/dev/null 2>&1 || [[ -x "${vtool_bin}" ]]; then
    "${vtool_bin}" -show-build "${executable}" 2>/dev/null \
      | awk '/^[[:space:]]*platform[[:space:]]+[A-Z0-9_]+[[:space:]]*$/ { print $2 }' \
      | sort -u
    return 0
  fi

  return 1
}

artifact_archs() {
  local executable="$1"
  local archs=""
  [[ -x "${WINS_LIPO_BIN}" && ! -L "${WINS_LIPO_BIN}" ]] \
    || die "Apple engine staging requires absolute /usr/bin/lipo."
  archs="$("${WINS_LIPO_BIN}" -archs "${executable}")" \
    || die "Could not derive architectures from ${executable}."
  [[ -n "${archs// }" ]] || die "No inspectable architectures in ${executable}."
  printf '%s\n' "${archs}"
}

artifact_symbols() {
  # $2 is an OPTIONAL architecture. Pass it. Omitting it is a latent bug on any
  # fat binary: `nm -gU` without -arch reports symbols across slices, so a
  # universal dylib whose x86_64 slice is stale and whose arm64 slice is fresh
  # answers as though every symbol is present in both.
  #
  # Demonstrated 2026-08-05 with a deliberately mixed fat dylib (arm64 with all
  # eight winn symbols, x86_64 with six): this exact pipeline reported 8, while
  # `-arch x86_64` reported 6. Without the per-slice loop in
  # require_component_symbols, this gate would pass the very defect it was
  # written to catch -- one architecture over, shipping a blind engine to Intel
  # Macs and Intel-host simulators. Found by different-family review, not by the
  # author.
  local executable="$1"
  local arch="${2:-}"
  local nm_bin="nm"
  if command -v xcrun >/dev/null 2>&1; then
    nm_bin="$(xcrun -f nm 2>/dev/null || printf 'nm')"
  fi

  if command -v "${nm_bin}" >/dev/null 2>&1 || [[ -x "${nm_bin}" ]]; then
    if [[ -n "${arch}" ]]; then
      "${nm_bin}" -gU -arch "${arch}" "${executable}" 2>/dev/null \
        | awk '{ print $NF }' \
        | sed 's/^_//' \
        | sort -u
    else
      "${nm_bin}" -gU "${executable}" 2>/dev/null \
        | awk '{ print $NF }' \
        | sed 's/^_//' \
        | sort -u
    fi
    return 0
  fi

  return 1
}

artifact_dependencies() {
  local executable="$1"
  local otool_bin="otool"
  if command -v xcrun >/dev/null 2>&1; then
    otool_bin="$(xcrun -f otool 2>/dev/null || printf 'otool')"
  fi

  if command -v "${otool_bin}" >/dev/null 2>&1 || [[ -x "${otool_bin}" ]]; then
    "${otool_bin}" -L "${executable}" 2>/dev/null \
      | awk 'NR > 1 { print $1 }' \
      | sort -u
    return 0
  fi

  return 1
}

require_component_symbols() {
  # EVERY slice must carry the full symbol set, checked independently. A fat
  # binary is only as good as its worst slice: an Intel Mac loads the x86_64
  # slice and nothing else, so "present in arm64" is not present for that user.
  local component="$1"
  local executable="$2"
  local symbols required_symbol missing_symbols=() arch archs=()

  while IFS= read -r arch; do
    [[ -n "${arch}" ]] && archs+=("${arch}")
  done < <(artifact_archs "${executable}" | tr ' ' '\n')

  [[ "${#archs[@]}" -gt 0 ]] \
    || die "Apple engine artifact ${component} has no inspectable architectures."

  for arch in "${archs[@]}"; do
    symbols="$(artifact_symbols "${executable}" "${arch}" | tr '\n' ' ')"
    [[ -n "${symbols// }" ]] \
      || die "Apple engine artifact ${component} has no exported global symbols${arch:+ in slice ${arch}}."

    missing_symbols=()
    while IFS= read -r required_symbol; do
      [[ " ${symbols} " == *" ${required_symbol} "* ]] \
        || missing_symbols+=("${required_symbol}")
    done < <(component_required_symbols "${component}")

    [[ "${#missing_symbols[@]}" -eq 0 ]] \
      || die "Apple engine artifact ${component}${arch:+ slice ${arch}} is missing required Win's VPN C ABI symbols: ${missing_symbols[*]}"
  done
}

require_absolute_bin() {
  local path="$1"
  local label="$2"
  [[ -n "${path}" && "${path}" == /* && -x "${path}" && ! -L "${path}" ]] \
    || die "Apple engine staging requires absolute ${label}."
}

engine_delivery_is_stripped() {
  local executable="$1"
  require_absolute_bin "${WINS_NM_BIN}" "nm"
  require_absolute_bin "${WINS_OTOOL_BIN}" "otool"
  require_absolute_bin "${WINS_LIPO_BIN}" "lipo"
  "${PYTHON_BIN}" - "${executable}" "${STAGING_SCRIPT_DIR}" \
    "${WINS_NM_BIN}" "${WINS_OTOOL_BIN}" "${WINS_LIPO_BIN}" <<'PY'
import pathlib
import subprocess
import sys

executable, tools_dir, nm_bin, otool_bin, lipo_bin = sys.argv[1:]
sys.path.insert(0, tools_dir)
from release_obfuscation_contract import ObfuscationError, reject_unstripped_native_blob

DEBUG_TYPES = {
    "BNSYM",
    "ENSYM",
    "FUN",
    "GSYM",
    "LCSYM",
    "OSO",
    "SLINE",
    "SO",
    "SOL",
    "STSYM",
}


def fail(message):
    raise SystemExit(message)


def run(tool, args, label):
    completed = subprocess.run(
        [tool, *args], capture_output=True, text=True, check=False
    )
    output = f"{completed.stdout}{completed.stderr}"
    if completed.returncode not in (0, 1):
        fail(f"{label} failed with exit {completed.returncode}")
    return completed.returncode, output, completed.stdout


path = pathlib.Path(executable)
if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
    fail(f"Apple engine delivery binary is missing, symbolic, or empty: {path}")
try:
    payload = path.read_bytes()
except OSError as error:
    fail(f"Apple engine delivery binary is unreadable: {path} ({error})")
try:
    reject_unstripped_native_blob(str(path), payload)
except ObfuscationError as error:
    fail(str(error))

code, _combined, arch_text = run(lipo_bin, ["-archs", str(path)], f"lipo {path}")
if code != 0:
    fail(f"Could not derive architectures from {path}")
architectures = [item for item in arch_text.split() if item]
if not architectures:
    fail(f"{path} has no inspectable architectures")

for arch in architectures:
    code, combined, stdout = run(
        nm_bin, ["-a", "-arch", arch, str(path)], f"nm -a {path} {arch}"
    )
    lowered = combined.lower()
    if "truncated" in lowered or "malformed" in lowered:
        fail(f"{path} slice {arch} is not a parseable Mach-O symbol table")
    if code == 1 and "no symbols" in lowered:
        fail(f"{path} slice {arch} has no inspectable symbol table")
    if code != 0:
        fail(f"Mach-O symbol-table inspection failed for {path} slice {arch}")
    for line in stdout.splitlines():
        if DEBUG_TYPES.intersection(line.split()):
            fail(f"{path} slice {arch} retains private or debug symbols")
    _code, _combined, nm_m = run(
        nm_bin, ["-m", "-arch", arch, str(path)], f"nm -m {path} {arch}"
    )
    for line in nm_m.splitlines():
        if "non-external" in line:
            fail(f"{path} slice {arch} retains non-public or local symbols")

_code, _combined, load_commands = run(
    otool_bin, ["-l", str(path)], f"otool -l {path}"
)
for raw_line in load_commands.splitlines():
    line = raw_line.strip()
    if line.startswith("segname ") and "__DWARF" in line.split(None, 1)[-1]:
        fail(f"{path} retains a DWARF debug segment")
    if line.startswith("sectname ") and line.split(None, 1)[-1].startswith("__debug"):
        fail(f"{path} retains a debug section")
    if line.startswith("nlocalsym"):
        count = line.split()[-1]
        if count != "0":
            fail(f"{path} retains local dynamic symbols")
PY
}

require_stripped_engine_binary() {
  local component="$1"
  local executable="$2"
  local output=""
  local status=0
  set +e
  output="$(engine_delivery_is_stripped "${executable}" 2>&1)"
  status=$?
  set -e
  [[ "${status}" -eq 0 ]] \
    || die "Apple engine artifact ${component} retains non-public or local symbols${output:+: ${output}}"
}

# Strip non-public/local symbols before signing. A clean, linker-signed copy
# must not be rewritten: `strip -x` replaces the ad-hoc signature using the
# destination filename, which would break provenance SHA-256 binding. Dirty
# inputs are stripped so they are never signed, then refused so hashes stay
# bound to the reviewed source bytes.
prepare_stripped_engine_delivery() {
  local component="$1"
  local executable="$2"
  if engine_delivery_is_stripped "${executable}"; then
    return 0
  fi
  require_absolute_bin "${WINS_STRIP_BIN}" "strip"
  "${WINS_STRIP_BIN}" -x -no_code_signature_warning "${executable}" \
    || die "Could not strip non-public/local symbols from Apple engine artifact ${component}."
  require_component_symbols "${component}" "${executable}"
  engine_delivery_is_stripped "${executable}" \
    || die "Apple engine artifact ${component} retained non-public or local symbols after strip."
  die "Apple engine artifact ${component} was not stripped before staging; source artifacts must already be stripped of non-public/local symbols so destination hashes stay bound to provenance."
}

require_component_dependencies() {
  local component="$1"
  local executable="$2"

  case "${component}" in
    xray_vless_ws_transport)
      local dependencies
      dependencies="$(artifact_dependencies "${executable}" | tr '\n' ' ')"
      [[ -n "${dependencies// }" ]] \
        || die "Apple engine artifact ${component} has no inspectable dynamic library dependencies."
      [[ " ${dependencies} " == *" @rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine "* ]] \
        || die "Apple engine artifact ${component} must depend on the embedded AWG framework."
      ;;
  esac
}

require_valid_artifact() {
  local component="$1"
  local artifact_path="$2"
  local executable
  executable="$(artifact_executable "${artifact_path}")" \
    || die "Apple engine artifact ${component} has no inspectable Mach-O executable."

  if [[ -L "${artifact_path}" && "${artifact_path}" != *.framework ]]; then
    die "Apple engine artifact ${component} must not be a symbolic link."
  fi
  if [[ "${artifact_path}" == *.framework ]]; then
    local link target
    while IFS= read -r link; do
      target="$(readlink "${link}")"
      [[ -n "${target}" && "${target}" != /* && "${target}" != *".."* ]] \
        || die "Apple engine framework ${component} contains an unsafe symbolic link."
    done < <(find "${artifact_path}" -type l -print 2>/dev/null)
  elif find "${artifact_path}" -type l -print -quit 2>/dev/null | grep -q .; then
    die "Apple engine artifact ${component} must not contain symbolic links."
  fi

  local expected_platform
  expected_platform="$(expected_macho_platform)"
  [[ "${expected_platform}" != "UNKNOWN" ]] \
    || die "Cannot stage Apple engine artifacts for unknown platform '${PLATFORM_NAME:-unset}'."

  local platforms
  platforms="$(artifact_platforms "${executable}" | tr '\n' ' ')"
  [[ -n "${platforms// }" ]] \
    || die "Apple engine artifact ${component} is missing LC_BUILD_VERSION platform metadata."

  local platform
  for platform in ${platforms}; do
    [[ "${platform}" == "${expected_platform}" ]] \
      || die "Apple engine artifact ${component} targets ${platform}; expected ${expected_platform}."
  done

  local archs
  archs="$(artifact_archs "${executable}")"
  [[ -n "${archs// }" ]] \
    || die "Apple engine artifact ${component} has no inspectable architectures."

  local required_archs="${ARCHS:-}"
  if [[ -z "${required_archs// }" ]]; then
    case "${PLATFORM_NAME:-}" in
      iphoneos)
        required_archs="arm64"
        ;;
      iphonesimulator|macosx)
        required_archs="$(uname -m)"
        ;;
    esac
  fi

  local required_arch
  for required_arch in ${required_archs}; do
    if [[ "${required_arch}" == "arm64" && " ${archs} " == *" arm64e "* ]]; then
      continue
    fi
    [[ " ${archs} " == *" ${required_arch} "* ]] \
      || die "Apple engine artifact ${component} is missing architecture ${required_arch}; found ${archs}."
  done

  require_component_symbols "${component}" "${executable}"
  require_stripped_engine_binary "${component}" "${executable}"
  require_component_dependencies "${component}" "${executable}"
}

find_component_artifact() {
  local component="$1"
  local source_dir candidate

  while IFS= read -r source_dir; do
    [[ -d "${source_dir}" ]] || continue
    while IFS= read -r candidate; do
      if [[ -e "${source_dir}/${candidate}" ]]; then
        printf '%s\n' "${source_dir}/${candidate}"
        return 0
      fi
    done < <(component_candidates "${component}")
  done < <(source_directories)

  return 1
}

destination_directory() {
  local target_build_dir="${TARGET_BUILD_DIR:-}"
  local frameworks_path="${FRAMEWORKS_FOLDER_PATH:-}"
  [[ -n "${target_build_dir}" && -n "${frameworks_path}" ]] \
    || die "TARGET_BUILD_DIR and FRAMEWORKS_FOLDER_PATH are required when staging Apple engine artifacts."
  [[ "${frameworks_path}" != *.appex/* ]] \
    || die "Apple engine frameworks must be staged in the containing app, not a nested app extension."
  printf '%s\n' "${target_build_dir}/${frameworks_path}"
}

manifest_directory() {
  local target_build_dir="${TARGET_BUILD_DIR:-}"
  local resources_path="${UNLOCALIZED_RESOURCES_FOLDER_PATH:-}"
  [[ -n "${target_build_dir}" && -n "${resources_path}" ]] \
    || die "TARGET_BUILD_DIR and UNLOCALIZED_RESOURCES_FOLDER_PATH are required when staging Apple engine artifacts."
  printf '%s\n' "${target_build_dir}/${resources_path}"
}

framework_name_for_component() {
  case "$1" in
    amneziawg_packet_engine) printf 'WinsAmneziaWGPacketEngine\n' ;;
    xray_vless_ws_transport) printf 'WinsXrayVlessWsTransport\n' ;;
    winn_packet_engine) printf 'WinsWinnPacketEngine\n' ;;
    *) return 1 ;;
  esac
}

framework_bundle_identifier_for_component() {
  case "$1" in
    amneziawg_packet_engine) printf 'org.winsvpn.engine.amneziawg\n' ;;
    xray_vless_ws_transport) printf 'org.winsvpn.engine.xray-vless-ws\n' ;;
    winn_packet_engine) printf 'org.winsvpn.engine.winn\n' ;;
    *) return 1 ;;
  esac
}

framework_privacy_path() {
  local dest_path="$1"
  local family
  family="$(platform_family)"
  case "${family}" in
    macos)
      printf '%s\n' "${dest_path}/Versions/A/Resources/PrivacyInfo.xcprivacy"
      ;;
    ios)
      printf '%s\n' "${dest_path}/PrivacyInfo.xcprivacy"
      ;;
    *)
      die "Cannot write Apple engine privacy manifests for unknown platform '${PLATFORM_NAME:-unset}'."
      ;;
  esac
}

write_framework_privacy_manifest() {
  local privacy_path="$1"
  local component="$2"
  [[ -n "${privacy_path}" && -n "${component}" ]] \
    || die "Apple engine privacy manifest path and component are required."
  mkdir -p "$(dirname "${privacy_path}")"
  "${PYTHON_BIN}" - "${privacy_path}" "${component}" <<'PY'
import plistlib
import sys

output, component = sys.argv[1:]
allowed = {
    "amneziawg_packet_engine",
    "xray_vless_ws_transport",
    "winn_packet_engine",
}
if component not in allowed:
    raise SystemExit(f"unsupported Apple engine privacy component: {component}")

accessed = [
    {
        "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryFileTimestamp",
        "NSPrivacyAccessedAPITypeReasons": ["C617.1"],
    }
]
if component == "winn_packet_engine":
    accessed.append(
        {
            "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategorySystemBootTime",
            "NSPrivacyAccessedAPITypeReasons": ["35F9.1"],
        }
    )
accessed.sort(key=lambda item: item["NSPrivacyAccessedAPIType"])
for item in accessed:
    item["NSPrivacyAccessedAPITypeReasons"] = sorted(item["NSPrivacyAccessedAPITypeReasons"])

manifest = {
    "NSPrivacyAccessedAPITypes": accessed,
    "NSPrivacyCollectedDataTypes": [],
    "NSPrivacyTracking": False,
    "NSPrivacyTrackingDomains": [],
}
with open(output, "wb") as handle:
    plistlib.dump(manifest, handle, fmt=plistlib.FMT_XML, sort_keys=True)
PY
  [[ -f "${privacy_path}" && ! -L "${privacy_path}" && -s "${privacy_path}" ]] \
    || die "Staged Apple engine privacy manifest is missing, symbolic, or empty: ${privacy_path}"
}

remove_nested_extension_artifacts() {
  local target_build_dir="${TARGET_BUILD_DIR:-}"
  local plugins_path="${PLUGINS_FOLDER_PATH:-}"
  [[ -n "${target_build_dir}" && -n "${plugins_path}" ]] || return 0

  local extension="${target_build_dir}/${plugins_path}/PacketTunnel.appex"
  [[ -d "${extension}" ]] || return 0
  rm -rf \
    "${extension}/Libraries" \
    "${extension}/Contents/Libraries" \
    "${extension}/Contents/Resources/Libraries"
  rm -rf \
    "${extension}/Frameworks/WinsAmneziaWGPacketEngine.framework" \
    "${extension}/Frameworks/WinsXrayVlessWsTransport.framework" \
    "${extension}/Frameworks/WinsWinnPacketEngine.framework" \
    "${extension}/Contents/Frameworks/WinsAmneziaWGPacketEngine.framework" \
    "${extension}/Contents/Frameworks/WinsXrayVlessWsTransport.framework" \
    "${extension}/Contents/Frameworks/WinsWinnPacketEngine.framework"
}

resign_embedded_extension_after_cleanup() {
  local target_build_dir="${TARGET_BUILD_DIR:-}"
  local plugins_path="${PLUGINS_FOLDER_PATH:-}"
  [[ -n "${target_build_dir}" && -n "${plugins_path}" ]] || return 0

  local extension="${target_build_dir}/${plugins_path}/PacketTunnel.appex"
  [[ -d "${extension}" ]] || return 0
  if [[ "${CODE_SIGNING_ALLOWED:-YES}" == "NO" ||
        -z "${EXPANDED_CODE_SIGN_IDENTITY:-}" ||
        "${EXPANDED_CODE_SIGN_IDENTITY}" == "-" ]]; then
    return 0
  fi

  /usr/bin/codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY}" \
    --preserve-metadata=identifier,entitlements,flags \
    --timestamp=none \
    "${extension}"
  /usr/bin/codesign --verify --strict --verbose=2 "${extension}"
  printf 'Re-signed embedded PacketTunnel after removing legacy engine artifacts.\n'
}

remove_stale_artifacts() {
  local dest_dir="$1"
  local component candidate
  mkdir -p "${dest_dir}"
  for component in "${ALL_COMPONENTS[@]}"; do
    while IFS= read -r candidate; do
      rm -rf "${dest_dir}/${candidate}"
    done < <(component_candidates "${component}")
  done
  remove_nested_extension_artifacts
}

stage_artifact() {
  local component="$1"
  local artifact_path="$2"
  local dest_dir="$3"
  local framework_name bundle_identifier source_executable dest_path executable_path info_path privacy_path
  framework_name="$(framework_name_for_component "${component}")"
  bundle_identifier="$(framework_bundle_identifier_for_component "${component}")"
  source_executable="$(artifact_executable "${artifact_path}")" \
    || die "Apple engine artifact ${component} has no executable to stage."
  dest_path="${dest_dir}/${framework_name}.framework"

  rm -rf "${dest_path}"
  if [[ "$(platform_family)" == "macos" ]]; then
    mkdir -p "${dest_path}/Versions/A/Resources"
    executable_path="${dest_path}/Versions/A/${framework_name}"
    info_path="${dest_path}/Versions/A/Resources/Info.plist"
    install -m 755 "${source_executable}" "${executable_path}"
    ln -s A "${dest_path}/Versions/Current"
    ln -s "Versions/Current/${framework_name}" "${dest_path}/${framework_name}"
    ln -s Versions/Current/Resources "${dest_path}/Resources"
  else
    mkdir -p "${dest_path}"
    executable_path="${dest_path}/${framework_name}"
    info_path="${dest_path}/Info.plist"
    install -m 755 "${source_executable}" "${executable_path}"
  fi

  "${PYTHON_BIN}" - "${info_path}" "${framework_name}" "${bundle_identifier}" "${PLATFORM_NAME:-}" "${IPHONEOS_DEPLOYMENT_TARGET:-}" "${MACOSX_DEPLOYMENT_TARGET:-}" <<'PY'
import plistlib
import sys

output, name, identifier, platform, ios_minimum, macos_minimum = sys.argv[1:]
info = {
    "CFBundleDevelopmentRegion": "en",
    "CFBundleExecutable": name,
    "CFBundleIdentifier": identifier,
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": name,
    "CFBundlePackageType": "FMWK",
    "CFBundleShortVersionString": "1.0",
    "CFBundleVersion": "1",
}
if platform in {"iphoneos", "iphonesimulator"}:
    info["CFBundleSupportedPlatforms"] = [
        "iPhoneOS" if platform == "iphoneos" else "iPhoneSimulator"
    ]
    if ios_minimum:
        info["MinimumOSVersion"] = ios_minimum
elif platform == "macosx" and macos_minimum:
    info["LSMinimumSystemVersion"] = macos_minimum
with open(output, "wb") as handle:
    plistlib.dump(info, handle, fmt=plistlib.FMT_BINARY, sort_keys=True)
PY

  privacy_path="$(framework_privacy_path "${dest_path}")"
  write_framework_privacy_manifest "${privacy_path}" "${component}"

  local install_name="@rpath/${framework_name}.framework/${framework_name}"
  local current_id=""
  current_id="$("${WINS_OTOOL_BIN}" -D "${executable_path}")" \
    || die "Could not read install name of staged ${component}."
  current_id="$(printf '%s\n' "${current_id}" | awk 'NR==2 { print $1 }')"
  if [[ "${current_id}" != "${install_name}" ]]; then
    xcrun install_name_tool -id "${install_name}" "${executable_path}"
  fi
  if [[ "${component}" == "xray_vless_ws_transport" ]]; then
    local dependency required_dependency
    required_dependency="@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"
    while IFS= read -r dependency; do
      if [[ "${dependency}" == *WinsAmneziaWGPacketEngine* && "${dependency}" != "${required_dependency}" ]]; then
        xcrun install_name_tool -change "${dependency}" "${required_dependency}" "${executable_path}"
      fi
    done < <(artifact_dependencies "${executable_path}")
    artifact_dependencies "${executable_path}" | grep -qx "${required_dependency}" \
      || die "Staged Xray framework does not depend on the staged AWG framework."
  fi

  # Strict strip contract (raw Mach-O, nm -a stabs, nm -m, nlocalsym). Code
  # signing is not done here: provenance verification and the retained
  # publication below compare the staged bytes to the source bytes, so the
  # frameworks are signed by sign_staged_engine_frameworks afterwards.
  prepare_stripped_engine_delivery "${component}" "${executable_path}"
  require_component_symbols "${component}" "${executable_path}"
  require_stripped_engine_binary "${component}" "${executable_path}"

  printf 'Staged Apple engine artifact component=%s artifact=%s\n' \
    "${component}" "${framework_name}.framework"
}

# Signs each staged framework after its bytes were verified against provenance
# and published. Runs only for a real signing identity, as Xcode supplies it.
sign_staged_engine_frameworks() {
  local dest_dir="$1"
  shift
  local component framework_name
  if [[ "${CODE_SIGNING_ALLOWED:-YES}" == "NO" ||
        -z "${EXPANDED_CODE_SIGN_IDENTITY:-}" ||
        "${EXPANDED_CODE_SIGN_IDENTITY}" == "-" ]]; then
    return 0
  fi
  for component in "$@"; do
    framework_name="$(framework_name_for_component "${component}")" \
      || die "Cannot sign unknown Apple engine component ${component}."
    /usr/bin/codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY}" \
      --timestamp=none \
      "${dest_dir}/${framework_name}.framework" \
      || die "Could not sign staged Apple engine framework ${framework_name}."
  done
}

apple_awg_engine_provenance_path() {
  if [[ -n "${APPLE_ENGINE_ARTIFACTS_DIR:-}" ]]; then
    printf '%s/%s\n' "${APPLE_ENGINE_ARTIFACTS_DIR}" "${APPLE_AWG_ENGINE_PROVENANCE_NAME}"
  else
    printf '%s/apple/EngineArtifacts/%s\n' "${PROJECT_ROOT}" "${APPLE_AWG_ENGINE_PROVENANCE_NAME}"
  fi
}

verify_and_stage_awg_provenance() {
  local manifest_dir="$1"
  local awg_artifact="$2"
  local xray_artifact="$3"
  local source_manifest awg_executable xray_executable copied_manifest expected_paths
  source_manifest="$(apple_awg_engine_provenance_path)"
  awg_executable="$(artifact_executable "${awg_artifact}")" \
    || die "Apple AWG artifact has no executable for provenance verification."
  xray_executable="$(artifact_executable "${xray_artifact}")" \
    || die "Apple Xray artifact has no executable for provenance verification."
  if [[ -n "${APPLE_ENGINE_ARTIFACTS_DIR:-}" ]]; then
    expected_paths=0
  else
    expected_paths=1
  fi

  "${PYTHON_BIN}" - "${source_manifest}" "${PLATFORM_NAME:-}" \
    "${awg_executable}" "${xray_executable}" "${expected_paths}" \
    "${APPLE_AWG_EXPECTED_REPOSITORY}" "${APPLE_AWG_EXPECTED_TAG}" \
    "${APPLE_AWG_EXPECTED_COMMIT}" "${APPLE_AWG_EXPECTED_TREE}" \
    "${APPLE_AWG_EXPECTED_GENERATION}" "${APPLE_AWG_EXPECTED_GO_VERSION}" \
    "${APPLE_AWG_EXPECTED_GO_MOD_SHA256}" "${APPLE_AWG_EXPECTED_GO_SUM_SHA256}" \
    "${APPLE_AWG_EXPECTED_GO_DARWIN_ARM64_SHA256}" \
    "${APPLE_AWG_EXPECTED_GO_DARWIN_AMD64_SHA256}" \
    "${APPLE_AWG_EXPECTED_XRAY_VERSION}" "${APPLE_AWG_EXPECTED_XRAY_COMMIT}" \
    "${APPLE_AWG_EXPECTED_XRAY_SUM}" "${APPLE_AWG_EXPECTED_XRAY_GO_MOD_SUM}" \
    "${APPLE_AWG_EXPECTED_XRAY_ZIP_SHA256}" \
    "${PROJECT_ROOT}/apple/EngineWrappers/WinsAmneziaWGPacketEngine.m" <<'PY' || die "Apple AWG 3.1 engine provenance verification failed. Staging is refused until a verified rebuild."
import hashlib
import json
import pathlib
import re
import sys

(
    manifest_path,
    platform,
    awg_path,
    xray_path,
    enforce_paths,
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


path = pathlib.Path(manifest_path)
if not path.is_file() or path.is_symlink():
    raise SystemExit(
        f"Apple AWG 3.1 engine provenance is missing, non-regular, or symbolic: {path}"
    )
if path.stat().st_size > 1024 * 1024:
    raise SystemExit("Apple AWG 3.1 engine provenance exceeds 1 MiB")
try:
    manifest = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"Apple AWG 3.1 engine provenance is invalid JSON: {error}") from error
if not isinstance(manifest, dict):
    raise SystemExit("Apple AWG 3.1 engine provenance must be a JSON object")

expected_source = {
    "commit": commit,
    "go_mod_sha256": go_mod_sha256,
    "go_sum_sha256": go_sum_sha256,
    "repository": repository,
    "tag": tag,
    "tree": tree,
}
expected_go = {
    "darwin_amd64_archive_sha256": go_darwin_amd64_sha256,
    "darwin_arm64_archive_sha256": go_darwin_arm64_sha256,
    "version": go_version,
}
expected_xray = {
    "commit": xray_commit,
    "go_mod_sum": xray_go_mod_sum,
    "module_sum": xray_sum,
    "replaced_module": "github.com/xtls/xray-core",
    "source_module": "github.com/amnezia-vpn/amnezia-xray-core",
    "version": xray_version,
    "zip_sha256": xray_zip_sha256,
}
source_path = pathlib.Path(awg_wrapper_source)
if not source_path.is_file() or source_path.is_symlink():
    raise SystemExit(
        f"Apple AWG wrapper source is missing, non-regular, or symbolic: {source_path}"
    )
expected_wrapper_source = {
    "path": "apple/EngineWrappers/WinsAmneziaWGPacketEngine.m",
    "sha256": sha256(source_path),
}
checks = (
    (manifest.get("schema_version"), 2, "schema_version"),
    (
        manifest.get("component"),
        "amneziawg-apple-engine-wrappers",
        "component",
    ),
    (manifest.get("generation"), generation, "generation"),
    (manifest.get("source"), expected_source, "source"),
    (manifest.get("go_toolchain"), expected_go, "Go toolchain"),
    (manifest.get("xray_replacement"), expected_xray, "Xray replacement"),
    (manifest.get("awg_wrapper_source"), expected_wrapper_source, "AWG wrapper source"),
)
for actual, expected, label in checks:
    if actual != expected:
        raise SystemExit(
            f"Apple AWG 3.1 engine provenance {label} mismatch: "
            f"expected {expected!r}, found {actual!r}"
        )
bridge_sha = manifest.get("bridge_provenance_sha256")
if not isinstance(bridge_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", bridge_sha):
    raise SystemExit("Apple AWG 3.1 bridge provenance SHA-256 is invalid")

platform_specs = {
    "iphoneos": (
        "iphoneos",
        ["arm64"],
        "ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib",
        "ios/iphoneos/libWinsXrayVlessWsTransport.dylib",
    ),
    "iphonesimulator": (
        "iphonesimulator",
        ["arm64", "x86_64"],
        "ios/iphonesimulator/libWinsAmneziaWGPacketEngine.dylib",
        "ios/iphonesimulator/libWinsXrayVlessWsTransport.dylib",
    ),
    "macosx": (
        "macosx",
        ["arm64", "x86_64"],
        "macos/libWinsAmneziaWGPacketEngine.dylib",
        "macos/libWinsXrayVlessWsTransport.dylib",
    ),
}
if platform not in platform_specs:
    raise SystemExit(f"Unsupported Apple platform for AWG provenance: {platform}")
key, architectures, expected_awg_path, expected_xray_path = platform_specs[platform]
wrappers = manifest.get("wrappers")
if not isinstance(wrappers, dict) or key not in wrappers:
    raise SystemExit(f"Apple AWG engine provenance omits {key}")
components = wrappers[key]
if not isinstance(components, dict):
    raise SystemExit(f"Apple AWG engine provenance {key} entry is invalid")

for component, raw_path, expected_path in (
    ("amneziawg_packet_engine", awg_path, expected_awg_path),
    ("xray_vless_ws_transport", xray_path, expected_xray_path),
):
    entry = components.get(component)
    if not isinstance(entry, dict):
        raise SystemExit(f"Apple AWG engine provenance omits {key}/{component}")
    if entry.get("architectures") != architectures:
        raise SystemExit(
            f"Apple AWG engine provenance architectures mismatch for {key}/{component}"
        )
    if enforce_paths == "1" and entry.get("path") != expected_path:
        raise SystemExit(
            f"Apple AWG engine provenance path mismatch for {key}/{component}"
        )
    artifact = pathlib.Path(raw_path)
    if not artifact.is_file() or artifact.is_symlink():
        raise SystemExit(f"Apple engine artifact is missing or symbolic: {artifact}")
    if entry.get("sha256") != sha256(artifact):
        raise SystemExit(
            f"Apple AWG engine provenance SHA-256 mismatch for {key}/{component}"
        )
PY

  mkdir -p "${manifest_dir}"
  copied_manifest="${manifest_dir}/${APPLE_AWG_ENGINE_PROVENANCE_NAME}"
  rm -f "${copied_manifest}"
  install -m 644 "${source_manifest}" "${copied_manifest}"
  local source_sha copied_sha
  source_sha="$(shasum -a 256 "${source_manifest}" | awk '{print $1}')"
  copied_sha="$(shasum -a 256 "${copied_manifest}" | awk '{print $1}')"
  [[ "${source_sha}" == "${copied_sha}" ]] \
    || die "Staged Apple AWG 3.1 provenance hash mismatch."
  printf '%s\n' "${copied_sha}"
}

apple_xray_engine_provenance_path() {
  if [[ -n "${APPLE_ENGINE_ARTIFACTS_DIR:-}" ]]; then
    printf '%s/%s\n' "${APPLE_ENGINE_ARTIFACTS_DIR}" "${APPLE_XRAY_ENGINE_PROVENANCE_NAME}"
  else
    printf '%s/apple/EngineArtifacts/%s\n' "${PROJECT_ROOT}" "${APPLE_XRAY_ENGINE_PROVENANCE_NAME}"
  fi
}

verify_and_stage_xray_provenance() {
  local manifest_dir="$1"
  local xray_artifact="$2"
  local source_manifest xray_executable dest_executable dest_dir dest_framework
  local copied_manifest source_sha copied_sha dest_sha
  source_manifest="$(apple_xray_engine_provenance_path)"
  xray_executable="$(artifact_executable "${xray_artifact}")" \
    || die "Apple Xray artifact has no executable for provenance verification."
  dest_dir="$(destination_directory)"
  dest_framework="${dest_dir}/WinsXrayVlessWsTransport.framework"
  if [[ "$(platform_family)" == "macos" ]]; then
    dest_executable="${dest_framework}/Versions/A/WinsXrayVlessWsTransport"
  else
    dest_executable="${dest_framework}/WinsXrayVlessWsTransport"
  fi
  [[ -f "${dest_executable}" && ! -L "${dest_executable}" && -s "${dest_executable}" ]] \
    || die "Staged Apple Xray destination executable is missing, symbolic, or empty: ${dest_executable}"
  if [[ -z "${APPLE_ENGINE_ARTIFACTS_DIR:-}" ]]; then
    /bin/bash "${STAGING_SCRIPT_DIR}/build_apple_engine_wrappers.sh" verify-xray-provenance >&2 \
      || die "Apple Xray VLESS-WS engine provenance verification failed. Staging is refused until a verified rebuild."
  fi
  dest_sha="$(wins_sha256 "${dest_executable}")" \
    || die "Apple Xray VLESS-WS destination dylib hash command failed."
  source_sha="$(wins_sha256 "${xray_executable}")" \
    || die "Apple Xray VLESS-WS source dylib hash command failed."
  [[ "${source_sha}" == "${dest_sha}" ]] \
    || die "Staged Apple Xray destination bytes do not match the source artifact."
  "${PYTHON_BIN}" - "${source_manifest}" "${dest_sha}" "${PLATFORM_NAME:-}" <<'PY' || die "Apple Xray VLESS-WS engine provenance destination SHA-256 mismatch. Staging is refused until a verified rebuild."
import json
import pathlib
import sys

manifest_path, dest_digest, platform = sys.argv[1:]
path = pathlib.Path(manifest_path)
if path.is_symlink() or not path.is_file():
    raise SystemExit(f"Apple Xray VLESS-WS engine provenance is missing or symbolic: {path}")
manifest = json.loads(path.read_text(encoding="utf-8"))
if (
    manifest.get("schema_version") != 1
    or manifest.get("component") != "xray-apple-vless-ws-engine-wrappers"
):
    raise SystemExit("Apple Xray VLESS-WS engine provenance identity is not exact")
wrappers = manifest.get("wrappers")
if not isinstance(wrappers, dict) or platform not in wrappers:
    raise SystemExit(f"Apple Xray VLESS-WS engine provenance omits {platform}")
entry = wrappers[platform]
if not isinstance(entry, dict) or entry.get("sha256") != dest_digest:
    raise SystemExit(
        f"Apple Xray VLESS-WS engine provenance SHA-256 mismatch for {platform}"
    )
PY
  mkdir -p "${manifest_dir}"
  copied_manifest="${manifest_dir}/${APPLE_XRAY_ENGINE_PROVENANCE_NAME}"
  rm -f "${copied_manifest}"
  install -m 644 "${source_manifest}" "${copied_manifest}"
  source_sha="$(wins_sha256 "${source_manifest}")" \
    || die "Apple Xray VLESS-WS source provenance hash command failed."
  copied_sha="$(wins_sha256 "${copied_manifest}")" \
    || die "Apple Xray VLESS-WS staged provenance hash command failed."
  [[ "${source_sha}" == "${copied_sha}" ]] \
    || die "Staged Apple Xray VLESS-WS provenance hash mismatch."
  printf '%s\n' "${copied_sha}"
}

apple_winn_engine_provenance_path() {
  if [[ -n "${APPLE_ENGINE_ARTIFACTS_DIR:-}" ]]; then
    printf '%s/%s\n' "${APPLE_ENGINE_ARTIFACTS_DIR}" "${APPLE_WINN_ENGINE_PROVENANCE_NAME}"
  else
    printf '%s/apple/EngineArtifacts/%s\n' "${PROJECT_ROOT}" "${APPLE_WINN_ENGINE_PROVENANCE_NAME}"
  fi
}

verify_and_stage_winn_provenance() {
  local manifest_dir="$1"
  local winn_artifact="$2"
  local source_manifest winn_executable dest_executable dest_dir dest_framework
  local copied_manifest expected_paths archive_root schema_path
  local source_sha copied_sha dest_sha
  source_manifest="$(apple_winn_engine_provenance_path)"
  winn_executable="$(artifact_executable "${winn_artifact}")" \
    || die "Apple Winn artifact has no executable for provenance verification."
  dest_dir="$(destination_directory)"
  dest_framework="${dest_dir}/WinsWinnPacketEngine.framework"
  if [[ "$(platform_family)" == "macos" ]]; then
    dest_executable="${dest_framework}/Versions/A/WinsWinnPacketEngine"
  else
    dest_executable="${dest_framework}/WinsWinnPacketEngine"
  fi
  [[ -f "${dest_executable}" && ! -L "${dest_executable}" && -s "${dest_executable}" ]] \
    || die "Staged Apple Winn destination executable is missing, symbolic, or empty: ${dest_executable}"
  archive_root="${WINN_DATAPATH_ARCHIVE_DIR:-${APPLE_ENGINE_ARTIFACTS_DIR:-${PROJECT_ROOT}/tools/winn_conformance_build_out}}"
  schema_path="${STAGING_SCRIPT_DIR}/apple_winn_v3_engine_provenance.schema.json"
  if [[ -n "${APPLE_ENGINE_ARTIFACTS_DIR:-}" ]]; then
    expected_paths=0
  else
    expected_paths=1
  fi
  # Production staging re-verifies the provenance against the signed Winn
  # release it names: the release driver re-checks the Ed25519 signature
  # with the pinned authority key and every recorded manifest, key, and
  # per-slice digest must match.
  if [[ "${expected_paths}" == "1" && "${WINS_APPLE_WINN3_RELEASE}" == "1" ]]; then
    [[ -n "${WINS_WINN_RELEASE_DIR:-}" ]] \
      || die "Production Apple staging requires WINS_WINN_RELEASE_DIR, the signed Winn release the engines were built from."
    WINS_APPLE_WINN3_RELEASE=1 WINS_WINN_TRUST_PUBLIC_KEY="" \
      /bin/bash "${STAGING_SCRIPT_DIR}/build_apple_engine_wrappers.sh" verify-winn-provenance \
        --release "${WINS_WINN_RELEASE_DIR}" >&2 \
      || die "Apple Winn v3 engine provenance is not bound to the signed Winn release. Staging is refused until a verified rebuild."
  fi

  "${PYTHON_BIN}" - "${source_manifest}" "${PLATFORM_NAME:-}" \
    "${winn_executable}" "${dest_executable}" "${expected_paths}" \
    "${archive_root}" "${schema_path}" \
    "${APPLE_AWG_EXPECTED_GO_VERSION}" \
    "${APPLE_AWG_EXPECTED_GO_DARWIN_ARM64_SHA256}" \
    "${APPLE_AWG_EXPECTED_GO_DARWIN_AMD64_SHA256}" \
    "${APPLE_WINN_EXPECTED_MODULE}" \
    "${APPLE_WINN_EXPECTED_GENERATION}" \
    "${WINS_LIPO_BIN}" "${WINS_FILE_BIN}" "${WINS_OTOOL_BIN}" \
    "${WINS_NM_BIN}" "/usr/bin/vtool" \
    "${WINS_APPLE_ENGINE_TRANSACTION_PROVENANCE_SHA256:-}" \
    "${WINS_APPLE_WINN3_RELEASE}" \
    "${STAGING_SCRIPT_DIR}/winn_release_authority.json" <<'PY' || die "Apple Winn v3 engine provenance verification failed. Staging is refused until a verified rebuild."
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

(
    manifest_path,
    platform,
    source_path,
    dest_path,
    enforce_full,
    archive_root,
    schema_path,
    go_version,
    go_arm64_sha256,
    go_amd64_sha256,
    expected_module,
    generation,
    lipo_bin,
    file_bin,
    otool_bin,
    nm_bin,
    vtool_bin,
    transaction_provenance_sha256,
    release_mode,
    authority_path,
) = sys.argv[1:]

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ARCHIVE_KEYS = (
    "iphoneos_arm64",
    "iphonesimulator_arm64",
    "iphonesimulator_x86_64",
    "macosx_arm64",
    "macosx_x86_64",
)
ARCHIVE_TARGETS = {
    "iphoneos_arm64": "datapath-ios-arm64",
    "iphonesimulator_arm64": "datapath-iossimulator-arm64",
    "iphonesimulator_x86_64": "datapath-iossimulator-amd64",
    "macosx_arm64": "datapath-archive-darwin-arm64",
    "macosx_x86_64": "datapath-archive-darwin-amd64",
}
WRAPPER_KEYS = ("iphoneos", "iphonesimulator", "macosx")
PLATFORM_TO_WRAPPER = {
    "iphoneos": ("iphoneos", "IOS", "ios/iphoneos/libWinsWinnPacketEngine.dylib"),
    "iphonesimulator": (
        "iphonesimulator",
        "IOSSIMULATOR",
        "ios/iphonesimulator/libWinsWinnPacketEngine.dylib",
    ),
    "macosx": ("macosx", "MACOS", "macos/libWinsWinnPacketEngine.dylib"),
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


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def stable_read(path, label, limit, permitted_uids=None):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        fail("O_NOFOLLOW is required for Apple Winn v3 staging")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow
    try:
        before = path.lstat()
        accepted_uids = {os.getuid()} if permitted_uids is None else set(permitted_uids)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_uid not in accepted_uids
        ):
            fail(f"{label} must be a nonempty owner-only single-link regular file: {path}")
        if before.st_size > limit:
            fail(f"{label} exceeds the snapshot limit: {path}")
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


def sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def json_type_name(value):
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is str:
        return "string"
    if type(value) is list:
        return "array"
    if type(value) is dict:
        return "object"
    return type(value).__name__


def resolve_schema_node(schema, node):
    ref = node.get("$ref") if type(node) is dict else None
    if not ref:
        return node
    name = ref.split("/")[-1]
    return schema["$defs"][name]


def validate_schema(instance, schema, node, path):
    node = resolve_schema_node(schema, node)
    for index, subschema in enumerate(node.get("allOf", [])):
        validate_schema(instance, schema, subschema, f"{path}.allOf[{index}]")
    expected_type = node.get("type")
    if expected_type == "object":
        if type(instance) is not dict:
            fail(f"{path} must be an object, found {json_type_name(instance)}")
        for key in node.get("required", []):
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
        if type(node.get("minItems")) is int and len(instance) < node["minItems"]:
            fail(f"{path} has too few items")
        items = node.get("items")
        if items is not None:
            for index, value in enumerate(instance):
                validate_schema(value, schema, items, f"{path}[{index}]")
    elif expected_type == "string":
        if type(instance) is not str:
            fail(f"{path} must be a string, found {json_type_name(instance)}")
        if type(node.get("minLength")) is int and len(instance) < node["minLength"]:
            fail(f"{path} is shorter than {node['minLength']}")
        if node.get("pattern") and re.search(node["pattern"], instance) is None:
            fail(f"{path} does not match {node['pattern']}")
    elif expected_type == "integer":
        if type(instance) is bool or type(instance) is not int:
            fail(f"{path} must be an integer, found {json_type_name(instance)}")
        if type(node.get("minimum")) is int and instance < node["minimum"]:
            fail(f"{path} is less than {node['minimum']}")
    if "const" in node:
        const = node["const"]
        if type(instance) is bool and type(const) is not bool:
            fail(f"{path} rejects bool-as-int {instance!r}")
        if instance != const or type(instance) is not type(const):
            fail(f"{path} must be {const!r}, found {instance!r}")
    if "enum" in node and instance not in node["enum"]:
        fail(f"{path} is not one of {node['enum']!r}")


def load_json_object(path, label, limit):
    payload = stable_read(path, label, limit)
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid JSON: {error}")
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    return value


def require_absolute_tool(path, label):
    tool = pathlib.Path(path)
    if not str(tool).startswith("/") or tool.is_symlink() or not tool.is_file() or not os.access(tool, os.X_OK):
        fail(f"{label} must be an absolute regular non-symlink executable: {path}")
    return str(tool)


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


MACHO_MINOS = {
    ("IOS", "arm64"): "13.0",
    ("IOSSIMULATOR", "arm64"): "14.0",
    ("IOSSIMULATOR", "x86_64"): "13.0",
    ("MACOS", "arm64"): "13.0",
    ("MACOS", "x86_64"): "13.0",
}
INSTALL_NAME = "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine"


def command_values(text, field):
    values = []
    for line in text.splitlines():
        fields = line.strip().split()
        if len(fields) >= 2 and fields[0] == field:
            values.append(fields[1])
    return values


def inspect_dylib_slice(path, arch, expected_platform):
    otool = require_absolute_tool(otool_bin, "otool")
    nm = require_absolute_tool(nm_bin, "nm")
    vtool = require_absolute_tool(vtool_bin, "vtool")
    load_commands = run_absolute(otool, ["-arch", arch, "-l", str(path)], f"otool {path} {arch}")
    platforms = platforms_from_otool(load_commands)
    if platforms != [expected_platform]:
        fail(f"{path} {arch} platform mismatch: {platforms!r}")
    uuids = command_values(load_commands, "uuid")
    if len(uuids) != 1 or re.fullmatch(r"[0-9A-Fa-f-]{36}", uuids[0]) is None:
        fail(f"{path} {arch} must contain exactly one LC_UUID")
    build = run_absolute(vtool, ["-arch", arch, "-show-build", str(path)], f"vtool {path} {arch}")
    minos = command_values(build, "minos")
    if minos != [MACHO_MINOS[(expected_platform, arch)]]:
        fail(f"{path} {arch} minimum OS mismatch: {minos!r}")
    build_version = run_absolute(
        vtool,
        ["-show-build", "-arch", arch, str(path)],
        f"vtool {path} {arch}",
    )
    if platforms_from_otool(build_version) != [expected_platform]:
        fail(f"{path} {arch} vtool platform mismatch")
    if command_values(build_version, "minos") != minos:
        fail(f"{path} {arch} vtool minimum OS mismatch")
    header = run_absolute(otool, ["-arch", arch, "-hv", str(path)], f"otool header {path} {arch}")
    if re.search(r"\b(MH_DYLIB|DYLIB)\b", header) is None:
        fail(f"{path} {arch} Mach-O filetype is not MH_DYLIB")
    install = run_absolute(otool, ["-arch", arch, "-D", str(path)], f"otool install name {path} {arch}")
    install_names = [line.strip() for line in install.splitlines() if line.strip() and not line.endswith(":") and line.strip() != str(path)]
    if install_names[-1:] != [INSTALL_NAME]:
        fail(f"{path} {arch} install name mismatch")
    dependencies_output = run_absolute(otool, ["-arch", arch, "-L", str(path)], f"otool dependencies {path} {arch}")
    dependencies = []
    for line in dependencies_output.splitlines():
        value = line.strip()
        if not value or value.endswith(":") or value.startswith(str(path)):
            continue
        dependency = value.split(" (", 1)[0]
        if dependency == INSTALL_NAME:
            continue
        if not (dependency.startswith("/usr/lib/") or dependency.startswith("/System/Library/Frameworks/")):
            fail(f"{path} {arch} non-system dependency: {dependency}")
        dependencies.append(dependency)
    dependencies = sorted(set(dependencies))
    if "/usr/lib/libSystem.B.dylib" not in dependencies:
        fail(f"{path} {arch} dependency closure omits libSystem")
    symbols_output = run_absolute(nm, ["-arch", arch, "-gU", str(path)], f"nm {path} {arch}")
    symbols = {line.split()[-1].lstrip("_") for line in symbols_output.splitlines() if line.split()}
    role_symbols = {
        "core": ["WinnTunnelCreateWinn3"],
        "relay": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
    }
    missing = sorted({item for values in role_symbols.values() for item in values} - symbols)
    if missing:
        fail(f"{path} {arch} role symbols are missing: {missing!r}")
    return {
        "architecture": arch,
        "dependencies": dependencies,
        "filetype": "MH_DYLIB",
        "install_name": INSTALL_NAME,
        "minos": minos[0],
        "platform": expected_platform,
        "role_symbols": role_symbols,
        "uuid": uuids[0].upper(),
    }


def inspect_dylib(path, expected_platform, expected_architectures):
    lipo = require_absolute_tool(lipo_bin, "lipo")
    file_tool = require_absolute_tool(file_bin, "file")
    otool = require_absolute_tool(otool_bin, "otool")
    file_text = run_absolute(file_tool, ["-b", str(path)], f"file {path}").strip()
    arch_text = run_absolute(lipo, ["-archs", str(path)], f"lipo {path}").strip()
    raw_architectures = [item for item in arch_text.split() if item]
    architectures = sorted(raw_architectures)
    if len(architectures) != len(set(architectures)):
        fail(f"{path} contains duplicate Mach-O architectures")
    if architectures != expected_architectures:
        fail(f"{path} architectures {architectures!r} do not match {expected_architectures!r}; thin engines are refused")
    if "dynamically linked shared library" not in file_text and "Mach-O" not in file_text:
        fail(f"{path} is not a Mach-O dylib: {file_text}")
    slices = {arch: inspect_dylib_slice(path, arch, expected_platform) for arch in architectures}
    return architectures, "mach-o-dylib", expected_platform, slices


schema = load_json_object(pathlib.Path(schema_path), "Apple Winn v3 provenance schema", 2 * 1024 * 1024)
manifest_file = pathlib.Path(manifest_path)
if manifest_file.is_symlink() or not manifest_file.is_file():
    fail(f"Apple Winn v3 engine provenance is missing, non-regular, or symbolic: {manifest_file}")
manifest = load_json_object(
    manifest_file,
    "Apple Winn v3 engine provenance",
    1024 * 1024,
)
manifest_payload = stable_read(manifest_file, "Apple Winn v3 engine provenance", 1024 * 1024)
if enforce_full == "1" and sha256_bytes(manifest_payload) != transaction_provenance_sha256:
    fail("Apple Winn v3 provenance is not the current producer transaction receipt")
validate_schema(manifest, schema, schema, "$")
if type(manifest.get("schema_version")) is bool:
    fail("Apple Winn v3 engine provenance schema_version rejects bool-as-int")
if manifest.get("component") != "winn-apple-engine-wrappers":
    fail("Apple Winn v3 engine provenance component mismatch")
if manifest.get("generation") != generation:
    fail("Apple Winn v3 engine provenance generation mismatch")
release = manifest.get("release")
if type(release) is not dict:
    fail("Apple Winn v3 engine provenance release record is invalid")
release_go = release.get("go")
if type(release_go) is not dict:
    fail("Apple Winn v3 engine provenance release Go toolchain is invalid")
if release_go.get("version") != go_version:
    fail("Apple Winn v3 engine provenance Go version mismatch")
if release_go.get("archive_sha256") not in (go_arm64_sha256, go_amd64_sha256):
    fail("Apple Winn v3 engine provenance Go archive is not a pinned official darwin archive")
for key in ("executable_sha256", "archive_sha256", "install_tree_sha256"):
    value = release_go.get(key)
    if type(value) is not str or not SHA256_RE.fullmatch(value):
        fail(f"Apple Winn v3 engine provenance release Go {key} is invalid")
if type(release.get("manifest_sha256")) is not str or not SHA256_RE.fullmatch(release["manifest_sha256"]):
    fail("Apple Winn v3 engine provenance release manifest digest is invalid")
signature_state = release.get("signature_state")
public_key = release.get("signature_public_key")
if signature_state == "signed":
    if type(public_key) is not str or not SHA256_RE.fullmatch(public_key):
        fail("Apple Winn v3 engine provenance signed release has no Ed25519 public key")
elif signature_state == "unsigned-dev":
    if public_key != "":
        fail("Apple Winn v3 engine provenance unsigned-dev release claims a public key")
else:
    fail("Apple Winn v3 engine provenance release signature_state is invalid")
if release_mode == "1":
    # Release mode never ships an unsigned dev build, and the release must be
    # signed by the pinned owner release authority key, not a test key.
    if signature_state != "signed":
        fail("Apple Winn v3 engine provenance names an unsigned-dev release; release mode requires a signed Winn release")
    authority = load_json_object(pathlib.Path(authority_path), "Winn release authority pin", 64 * 1024)
    if authority.get("contract") != "winsvpn-winn-release-authority-v1" or authority.get("algorithm") != "ed25519":
        fail("Winn release authority pin is malformed")
    if public_key != authority.get("public_key"):
        fail("Apple Winn v3 engine provenance release was not signed by the pinned release authority key")
source = manifest.get("source")
if type(source) is not dict or source.get("module") != expected_module:
    fail("Apple Winn v3 engine provenance source/module is invalid")
archives = manifest.get("archives")
if type(archives) is not dict or set(archives) != set(ARCHIVE_KEYS):
    fail("Apple Winn engine provenance must describe every nonempty archive")
for key in ARCHIVE_KEYS:
    entry = archives[key]
    digest = entry.get("sha256")
    if type(digest) is not str or not SHA256_RE.fullmatch(digest):
        fail(f"Apple Winn archive provenance {key} is empty or invalid")
    if entry.get("target") != ARCHIVE_TARGETS[key]:
        fail(f"Apple Winn archive provenance {key} target mismatch")
    # Both independent release builds must have produced exactly these bytes.
    if not (entry.get("build_a_sha256") == entry.get("build_b_sha256") == digest):
        fail(f"Apple Winn archive provenance {key} is not reproducible across both release builds")
    if archive_root:
        archive_path = pathlib.Path(archive_root) / entry["path"]
        if enforce_full == "1" or archive_path.exists():
            payload = stable_read(archive_path, f"Winn archive {key}", 64 * 1024 * 1024)
            if sha256_bytes(payload) != digest:
                fail(f"Apple Winn archive provenance SHA-256 mismatch for {key}")
            header = stable_read(pathlib.Path(archive_root) / entry["header_path"], f"Winn archive header {key}", 1024 * 1024)
            if sha256_bytes(header) != entry["header_sha256"]:
                fail(f"Apple Winn archive header provenance mismatch for {key}")
wrappers = manifest.get("wrappers")
if type(wrappers) is not dict or set(wrappers) != set(WRAPPER_KEYS):
    fail("Apple Winn engine provenance must describe exactly the three Apple platforms")
if platform not in PLATFORM_TO_WRAPPER:
    fail(f"Unsupported Apple platform for Winn provenance: {platform}")
key, expected_platform, expected_path = PLATFORM_TO_WRAPPER[platform]
entry = wrappers[key]
if enforce_full == "1" and entry.get("path") != expected_path:
    fail(f"Apple Winn engine provenance path mismatch for {key}")
source_bytes = stable_read(pathlib.Path(source_path), "source Winn dylib", 64 * 1024 * 1024)
dest_bytes = stable_read(pathlib.Path(dest_path), "destination Winn dylib", 64 * 1024 * 1024)
source_digest = sha256_bytes(source_bytes)
dest_digest = sha256_bytes(dest_bytes)
if source_digest != dest_digest:
    fail(
        f"Apple Winn engine provenance destination SHA-256 mismatch for {key}: "
        "staged destination bytes do not match the source artifact"
    )
if entry.get("sha256") != dest_digest:
    fail(f"Apple Winn engine provenance SHA-256 mismatch for {key}")
expected_architectures = {
    "iphoneos": ["arm64"],
    "iphonesimulator": ["arm64", "x86_64"],
    "macosx": ["arm64", "x86_64"],
}[platform]
architectures, filetype, platform_name, slices = inspect_dylib(
    pathlib.Path(dest_path), expected_platform, expected_architectures
)
if entry.get("architectures") != architectures:
    fail(f"Apple Winn engine provenance architectures mismatch for {key}")
if entry.get("filetype") != filetype or entry.get("platform") != platform_name:
    fail(f"Apple Winn engine provenance filetype/platform mismatch for {key}")
if entry.get("slices") != slices:
    fail(f"Apple Winn engine provenance per-slice facts mismatch for {key}")
PY

  mkdir -p "${manifest_dir}"
  copied_manifest="${manifest_dir}/${APPLE_WINN_ENGINE_PROVENANCE_NAME}"
  rm -f "${copied_manifest}"
  install -m 644 "${source_manifest}" "${copied_manifest}"
  source_sha="$(wins_sha256 "${source_manifest}")" \
    || die "Apple Winn v3 source provenance hash command failed."
  copied_sha="$(wins_sha256 "${copied_manifest}")" \
    || die "Apple Winn v3 staged provenance hash command failed."
  dest_sha="$(wins_sha256 "${dest_executable}")" \
    || die "Apple Winn v3 destination dylib hash command failed."
  [[ "${source_sha}" == "${copied_sha}" ]] \
    || die "Staged Apple Winn v3 provenance hash mismatch."
  [[ -n "${dest_sha}" ]] \
    || die "Staged Apple Winn v3 destination digest is empty."
  printf '%s\n' "${copied_sha}"
}

publish_engine_artifacts_transaction() {
  local dest_dir="$1"
  local awg_provenance_sha256="$2"
  local xray_provenance_sha256="$3"
  local winn_provenance_sha256="$4"
  local awg_source_executable="$5"
  local xray_source_executable="$6"
  local winn_source_executable="$7"
  local awg_source_provenance="$8"
  local xray_source_provenance="$9"
  local winn_source_provenance="${10}"
  shift 10
  local staged_components=("$@")
  [[ "${WINS_APPLE_WINN3_RELEASE}" =~ ^[01]$ ]] \
    || die "WINS_APPLE_WINN3_RELEASE must be exactly 0 or 1."
  [[ "${WINS_REQUIRE_APPLE_ENGINE}" =~ ^[01]$ ]] \
    || die "WINS_REQUIRE_APPLE_ENGINE must be exactly 0 or 1."
  "${PYTHON_BIN}" - "${dest_dir}/apple_engine_artifacts_manifest.json" "${PLATFORM_NAME:-}" "${SYMBOL_CONTRACT_VERSION}" "${awg_provenance_sha256}" "${xray_provenance_sha256}" "${winn_provenance_sha256}" "${awg_source_executable}" "${xray_source_executable}" "${winn_source_executable}" "${awg_source_provenance}" "${xray_source_provenance}" "${winn_source_provenance}" "${STAGING_SCRIPT_DIR}" "${WINS_APPLE_WINN3_RELEASE}" "${WINS_REQUIRE_APPLE_ENGINE}" "${WINN_DATAPATH_ARCHIVE_DIR:-${APPLE_ENGINE_ARTIFACTS_DIR:-${PROJECT_ROOT}/tools/winn_conformance_build_out}}" "$(destination_directory)" "${staged_components[@]}" <<'PY'
import json
import hashlib
import os
import pathlib
import stat
import sys

output_path = sys.argv[1]
platform_name = sys.argv[2]
symbol_contract_version = int(sys.argv[3])
awg_provenance_sha256 = sys.argv[4]
xray_provenance_sha256 = sys.argv[5]
winn_provenance_sha256 = sys.argv[6]
source_engine_paths = sys.argv[7:10]
source_provenance_paths = sys.argv[10:13]
staging_script_dir = pathlib.Path(sys.argv[13])
release_candidate = sys.argv[14] == "1"
require_complete_engine = sys.argv[15] == "1"
# The Winn archives sit where verify_winn_provenance reads them (the signed
# release copies in tools/winn_conformance_build_out by default), not beside
# the tracked provenance JSON in apple/EngineArtifacts.
winn_archive_root = pathlib.Path(sys.argv[16])
# The engines are staged in FRAMEWORKS_FOLDER_PATH (destination_directory),
# which on macOS is Contents/Frameworks, not a child of the manifest's
# UNLOCALIZED_RESOURCES_FOLDER_PATH (Contents/Resources).
staged_framework_root = pathlib.Path(sys.argv[17])
staged = sys.argv[18:]
all_engines_required = release_candidate or require_complete_engine
manifest = {
    "schema_version": 1,
    "platform_name": platform_name,
    "symbol_contract_version": symbol_contract_version,
    "required_components": ([
        "amneziawg_packet_engine", "xray_vless_ws_transport", "winn_packet_engine"
    ] if all_engines_required else ["amneziawg_packet_engine", "xray_vless_ws_transport"]),
    "optional_components": ([] if all_engines_required else ["winn_packet_engine"]),
    "staged_components": staged,
    "apple_awg_31_provenance_sha256": awg_provenance_sha256 or None,
    "apple_xray_vless_ws_provenance_sha256": xray_provenance_sha256 or None,
    "apple_winn_v3_provenance_sha256": winn_provenance_sha256 or None,
    "secret_material_redacted": True,
}


class Retained:
    def __init__(self, raw_path, label):
        self.path = pathlib.Path(os.path.abspath(os.path.normpath(raw_path)))
        self.label = label
        self.parents = []
        self.fd = -1
        current = pathlib.Path("/")
        current_fd = os.open(
            current,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            for index, name in enumerate(self.path.parts[1:]):
                parent = os.fstat(current_fd)
                child = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                if stat.S_ISLNK(child.st_mode):
                    raise OSError(f"{label} has a symbolic path component")
                self.parents.append((current, current_fd, self.identity(parent), name, self.identity(child)))
                current_fd = -1
                current /= name
                if index == len(self.path.parts[1:]) - 1:
                    if not stat.S_ISREG(child.st_mode) or child.st_nlink != 1 or child.st_size <= 0:
                        raise OSError(f"{label} is not one nonempty regular file")
                    self.fd = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=self.parents[-1][1],
                    )
                    break
                if not stat.S_ISDIR(child.st_mode):
                    raise OSError(f"{label} ancestor is not a directory")
                current_fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=self.parents[-1][1],
                )
            self.verify()
            self.digest = self.sha256()
        except BaseException:
            if current_fd >= 0:
                os.close(current_fd)
            self.close()
            raise

    @staticmethod
    def identity(info):
        stable = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        return stable + ((info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns) if stat.S_ISREG(info.st_mode) else ())

    def verify(self):
        for path, descriptor, identity, child_name, child_identity in self.parents:
            if self.identity(os.fstat(descriptor)) != identity:
                raise OSError(f"{self.label} retained ancestor changed: {path}")
            child = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
            if self.identity(child) != child_identity:
                raise OSError(
                    f"{self.label} pathname substitution/restoration rejected: {path / child_name}"
                )
        if self.identity(os.fstat(self.fd)) != self.parents[-1][4]:
            raise OSError(f"{self.label} retained descriptor changed")

    def bytes(self):
        self.verify()
        size = os.fstat(self.fd).st_size
        payload = os.pread(self.fd, size, 0)
        if len(payload) != size or os.pread(self.fd, 1, size):
            raise OSError(f"{self.label} changed while read")
        self.verify()
        return payload

    def sha256(self):
        return hashlib.sha256(self.bytes()).hexdigest()

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        for _path, descriptor, _identity, _child_name, _child_identity in reversed(self.parents):
            os.close(descriptor)
        self.parents = []


class RetainedDirectory:
    def __init__(self, raw_path, label):
        self.path = pathlib.Path(os.path.abspath(os.path.normpath(raw_path)))
        self.label = label
        self.chain = []
        self.fd = -1
        current = pathlib.Path("/")
        descriptor = os.open(
            current,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            for name in self.path.parts[1:]:
                child = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode):
                    raise OSError(f"{label} has a symbolic or non-directory component")
                self.chain.append(
                    (current, descriptor, Retained.identity(os.fstat(descriptor)), name, Retained.identity(child))
                )
                current /= name
                descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=self.chain[-1][1],
                )
            self.fd = descriptor
            self.verify()
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            self.close()
            raise

    def verify(self):
        for path, descriptor, identity, child_name, child_identity in self.chain:
            if Retained.identity(os.fstat(descriptor)) != identity:
                raise OSError(f"{self.label} retained ancestor changed: {path}")
            child = os.stat(child_name, dir_fd=descriptor, follow_symlinks=False)
            if Retained.identity(child) != child_identity:
                raise OSError(f"{self.label} parent substitution/restoration rejected")
        if Retained.identity(os.fstat(self.fd)) != self.chain[-1][4]:
            raise OSError(f"{self.label} retained directory changed")

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        for _path, descriptor, _identity, _child_name, _child_identity in reversed(self.chain):
            os.close(descriptor)
        self.chain = []


output = pathlib.Path(output_path)
resource_dir = output.parent
framework_root = staged_framework_root
if platform_name == "macosx":
    engine_paths = {
        "amneziawg_packet_engine": framework_root / "WinsAmneziaWGPacketEngine.framework/Versions/A/WinsAmneziaWGPacketEngine",
        "xray_vless_ws_transport": framework_root / "WinsXrayVlessWsTransport.framework/Versions/A/WinsXrayVlessWsTransport",
        "winn_packet_engine": framework_root / "WinsWinnPacketEngine.framework/Versions/A/WinsWinnPacketEngine",
    }
else:
    engine_paths = {
        "amneziawg_packet_engine": framework_root / "WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine",
        "xray_vless_ws_transport": framework_root / "WinsXrayVlessWsTransport.framework/WinsXrayVlessWsTransport",
        "winn_packet_engine": framework_root / "WinsWinnPacketEngine.framework/WinsWinnPacketEngine",
    }
destination_provenance_paths = {
    "AWG provenance": resource_dir / "apple_awg_31_engine_provenance.json",
    "Xray provenance": resource_dir / "apple_xray_vless_ws_engine_provenance.json",
    "Winn provenance": resource_dir / "apple_winn_v3_engine_provenance.json",
}
source_engines = dict(zip(
    ("amneziawg_packet_engine", "xray_vless_ws_transport", "winn_packet_engine"),
    source_engine_paths,
))
source_provenance = dict(zip(
    ("AWG provenance", "Xray provenance", "Winn provenance"),
    source_provenance_paths,
))
retained = []
try:
    engine_bindings = {
        component: Retained(source_engines[component], component + " source engine")
        for component in staged
    }
    retained.extend(engine_bindings.values())
    provenance_bindings = {
        label: Retained(path, label + " source")
        for label, path in source_provenance.items()
    }
    retained.extend(provenance_bindings.values())
    schema_path = staging_script_dir / "apple_winn_v3_engine_provenance.schema.json"
    retained.append(Retained(schema_path, "Winn provenance schema"))
    expected_provenance = {
        "AWG provenance source": awg_provenance_sha256,
        "Xray provenance source": xray_provenance_sha256,
        "Winn provenance source": winn_provenance_sha256,
    }
    for binding in retained:
        expected = expected_provenance.get(binding.label)
        if expected is not None and binding.digest != expected:
            raise OSError(binding.label + " retained hash drifted before publication")
    def strict_json(binding):
        def exact_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate JSON key: " + key)
                value[key] = item
            return value

        return json.loads(
            binding.bytes().decode("ascii"),
            object_pairs_hook=exact_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError("non-finite JSON constant: " + value)
            ),
        )

    provenance_documents = {
        label: strict_json(binding) for label, binding in provenance_bindings.items()
    }
    for archive_key, archive_record in provenance_documents["Winn provenance"]["archives"].items():
        archive_bindings = {
            "archive": Retained(winn_archive_root / archive_record["path"], archive_key + " archive"),
            "header": Retained(winn_archive_root / archive_record["header_path"], archive_key + " header"),
        }
        retained.extend(archive_bindings.values())
        archive_expected = {
            "archive": archive_record["sha256"],
            "header": archive_record["header_sha256"],
        }
        for kind, binding in archive_bindings.items():
            if binding.digest != archive_expected[kind]:
                raise OSError(archive_key + " retained " + kind + " hash drifted")
    awg_record = provenance_documents["AWG provenance"]["wrappers"][platform_name]["amneziawg_packet_engine"]
    xray_record = provenance_documents["Xray provenance"]["wrappers"][platform_name]
    winn_record = provenance_documents["Winn provenance"]["wrappers"][platform_name]
    expected_engines = {
        "amneziawg_packet_engine": awg_record["sha256"],
        "xray_vless_ws_transport": xray_record["sha256"],
        "winn_packet_engine": winn_record["sha256"],
    }
    for component, binding in engine_bindings.items():
        if binding.digest != expected_engines[component]:
            raise OSError(component + " source engine is not bound by retained provenance")

    destination_directories = {
        path: RetainedDirectory(path, "retained staging destination")
        for path in {
            *(engine_paths[component].parent for component in staged),
            resource_dir,
        }
    }

    def committed_bytes(parent_binding, name, label):
        parent_binding.verify()
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_binding.fd,
        )
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0:
                raise OSError(label + " committed inode is not one nonempty regular file")
            payload_bytes = os.pread(descriptor, before.st_size, 0)
            if len(payload_bytes) != before.st_size or os.pread(descriptor, 1, before.st_size):
                raise OSError(label + " committed inode changed while read")
            after = os.fstat(descriptor)
            if Retained.identity(before) != Retained.identity(after):
                raise OSError(label + " committed inode identity changed")
            parent_binding.verify()
            return payload_bytes
        finally:
            os.close(descriptor)

    def copy_held(binding, destination, mode):
        destination = pathlib.Path(destination)
        parent_binding = destination_directories[destination.parent]
        parent_binding.verify()
        parent_fd = parent_binding.fd
        temporary_name = ".retained." + destination.name + "." + str(os.getpid())
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=parent_fd,
        )
        try:
            payload_bytes = binding.bytes()
            offset = 0
            while offset < len(payload_bytes):
                written = os.write(temporary_fd, payload_bytes[offset:])
                if written <= 0:
                    raise OSError(binding.label + " retained copy write failed")
                offset += written
            os.fsync(temporary_fd)
        finally:
            os.close(temporary_fd)
        for current in retained:
            current.verify()
        os.replace(
            temporary_name, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd
        )
        os.fsync(parent_fd)
        parent_binding.verify()
        if hashlib.sha256(
            committed_bytes(parent_binding, destination.name, binding.label)
        ).hexdigest() != binding.digest:
            raise OSError(binding.label + " committed copy digest drifted")
        binding.verify()

    for component, binding in engine_bindings.items():
        copy_held(binding, engine_paths[component], 0o755)
    for label, binding in provenance_bindings.items():
        copy_held(binding, destination_provenance_paths[label], 0o644)
    payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("ascii")
    resource_binding = destination_directories[resource_dir]
    resource_binding.verify()
    resource_fd = resource_binding.fd
    temporary = ".apple-engine-manifest." + str(os.getpid())
    temp_fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o644,
        dir_fd=resource_fd,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(temp_fd, payload[offset:])
            if written <= 0:
                raise OSError("engine manifest retained write failed")
            offset += written
        os.fsync(temp_fd)
    finally:
        os.close(temp_fd)
    for binding in retained:
        binding.verify()
        if binding.sha256() != binding.digest:
            raise OSError(binding.label + " changed immediately before manifest commit")
    os.replace(temporary, output.name, src_dir_fd=resource_fd, dst_dir_fd=resource_fd)
    os.fsync(resource_fd)
    resource_binding.verify()
    for binding in retained:
        binding.verify()
        if binding.sha256() != binding.digest:
            raise OSError(binding.label + " changed immediately after manifest commit")
    if committed_bytes(resource_binding, output.name, "engine manifest") != payload:
        raise OSError("committed engine manifest bytes drifted")
finally:
    for binding in reversed(locals().get("destination_directories", {}).values()):
        binding.close()
    for binding in reversed(retained):
        binding.close()
PY
}

# Xcode Run Script entry (ios and macos Runner targets) and the release
# producers: validate, stage, verify AWG/Xray/Winn provenance against their
# pins (and, for WINS_APPLE_WINN3_RELEASE=1, the signed Winn release), publish
# apple_engine_artifacts_manifest.json, then sign the staged frameworks.
stage_engine_artifacts() {
  if [[ "${WINS_APPLE_WINN3_RELEASE}" == "1" || "${WINS_REQUIRE_APPLE_ENGINE}" == "1" ]]; then
    REQUIRED_COMPONENTS=(
      "amneziawg_packet_engine"
      "xray_vless_ws_transport"
      "winn_packet_engine"
    )
    OPTIONAL_COMPONENTS=()
  else
    REQUIRED_COMPONENTS=("amneziawg_packet_engine" "xray_vless_ws_transport")
    OPTIONAL_COMPONENTS=("winn_packet_engine")
  fi
  local dest_dir manifest_dir
  # `|| die` keeps this fail-closed even when a caller disabled errexit.
  dest_dir="$(destination_directory)" \
    || die "Apple engine staging has no Xcode build destination."
  manifest_dir="$(manifest_directory)" \
    || die "Apple engine staging has no Xcode resources destination."
  remove_stale_artifacts "${dest_dir}"
  resign_embedded_extension_after_cleanup
  rm -f "${manifest_dir}/apple_engine_artifacts_manifest.json"
  rm -f "${manifest_dir}/${APPLE_AWG_ENGINE_PROVENANCE_NAME}"
  rm -f "${manifest_dir}/${APPLE_WINN_ENGINE_PROVENANCE_NAME}"
  rm -f "${manifest_dir}/${APPLE_XRAY_ENGINE_PROVENANCE_NAME}"

  local staged_components=()
  local missing_components=()
  local component artifact_path
  local awg_artifact_path=""
  local xray_artifact_path=""
  local winn_artifact_path=""
  for component in "${REQUIRED_COMPONENTS[@]}"; do
    if artifact_path="$(find_component_artifact "${component}")"; then
      require_valid_artifact "${component}" "${artifact_path}"
      stage_artifact "${component}" "${artifact_path}" "${dest_dir}"
      staged_components+=("${component}")
      case "${component}" in
        amneziawg_packet_engine) awg_artifact_path="${artifact_path}" ;;
        xray_vless_ws_transport) xray_artifact_path="${artifact_path}" ;;
        winn_packet_engine) winn_artifact_path="${artifact_path}" ;;
      esac
    else
      missing_components+=("${component}")
    fi
  done

  # Optional components are validated exactly as strictly as required ones when
  # they are present. They may be absent only on unsigned dry-run builds, where
  # neither WINS_REQUIRE_APPLE_ENGINE nor WINS_APPLE_WINN3_RELEASE is set.
  # macOS still ships Bash 3.2, where expanding an explicitly empty array
  # under `set -u` raises "unbound variable". Word-splitting is safe here
  # because component identifiers are fixed ASCII tokens without whitespace.
  for component in ${OPTIONAL_COMPONENTS[*]-}; do
    if artifact_path="$(find_component_artifact "${component}")"; then
      require_valid_artifact "${component}" "${artifact_path}"
      stage_artifact "${component}" "${artifact_path}" "${dest_dir}"
      staged_components+=("${component}")
      case "${component}" in
        amneziawg_packet_engine) awg_artifact_path="${artifact_path}" ;;
        xray_vless_ws_transport) xray_artifact_path="${artifact_path}" ;;
        winn_packet_engine) winn_artifact_path="${artifact_path}" ;;
      esac
    else
      printf 'Apple engine artifact staging skipped absent optional component: %s\n' "${component}"
    fi
  done

  if [[ "${#missing_components[@]}" -gt 0 ]]; then
    if [[ "${WINS_APPLE_WINN3_RELEASE}" == "1" || "${WINS_REQUIRE_APPLE_ENGINE}" == "1" ]]; then
      die "Missing required Apple engine artifacts: ${missing_components[*]}"
    fi
    printf 'Apple engine artifact staging skipped missing components: %s\n' "${missing_components[*]}"
  fi

  local awg_provenance_sha256=""
  local winn_provenance_sha256=""
  local xray_provenance_sha256=""
  if [[ -n "${awg_artifact_path}" && -n "${xray_artifact_path}" ]]; then
    if ! awg_provenance_sha256="$(verify_and_stage_awg_provenance \
      "${manifest_dir}" "${awg_artifact_path}" "${xray_artifact_path}")"; then
      die "Apple AWG 3.1 engine provenance verification failed. Staging is refused until a verified rebuild."
    fi
    if ! xray_provenance_sha256="$(verify_and_stage_xray_provenance \
      "${manifest_dir}" "${xray_artifact_path}")"; then
      die "Apple Xray VLESS-WS engine provenance verification failed. Staging is refused until a verified rebuild."
    fi
  fi
  if [[ -n "${winn_artifact_path}" ]]; then
    if ! winn_provenance_sha256="$(verify_and_stage_winn_provenance \
      "${manifest_dir}" "${winn_artifact_path}")"; then
      die "Apple Winn v3 engine provenance verification failed. Staging is refused until a verified rebuild."
    fi
  elif [[ "${WINS_APPLE_WINN3_RELEASE}" == "1" || "${WINS_REQUIRE_APPLE_ENGINE}" == "1" ]]; then
    die "Apple Winn v3 engine provenance is required when Winn is a required engine."
  fi

  if [[ "${#staged_components[@]}" -gt 0 ]]; then
    mkdir -p "${manifest_dir}"
    local awg_source_executable xray_source_executable winn_source_executable
    awg_source_executable="$(artifact_executable "${awg_artifact_path}")" \
      || die "Could not bind the AWG source executable for retained publication."
    xray_source_executable="$(artifact_executable "${xray_artifact_path}")" \
      || die "Could not bind the Xray source executable for retained publication."
    winn_source_executable="$(artifact_executable "${winn_artifact_path}")" \
      || die "Could not bind the Winn source executable for retained publication."
    publish_engine_artifacts_transaction \
      "${manifest_dir}" \
      "${awg_provenance_sha256}" \
      "${xray_provenance_sha256}" \
      "${winn_provenance_sha256}" \
      "${awg_source_executable}" \
      "${xray_source_executable}" \
      "${winn_source_executable}" \
      "$(apple_awg_engine_provenance_path)" \
      "$(apple_xray_engine_provenance_path)" \
      "$(apple_winn_engine_provenance_path)" \
      "${staged_components[@]}"
    sign_staged_engine_frameworks "${dest_dir}" "${staged_components[@]}"
  fi

  if [[ "${#staged_components[@]}" -eq 0 ]]; then
    printf 'No Apple engine artifacts staged for %s.\n' "${PLATFORM_NAME:-unknown}"
  else
    printf 'Apple engine artifact staging completed for %s: %s\n' \
      "${PLATFORM_NAME:-unknown}" "${staged_components[*]}"
  fi
}

write_selftest_xray_provenance() {
  local output="$1"
  local xray="$2"
  local platform="$3"
  "${PYTHON_BIN}" - "${output}" "${xray}" "${platform}" <<'PY'
import hashlib
import json
import pathlib
import sys

output, xray_raw, platform = sys.argv[1:]
xray = pathlib.Path(xray_raw)
manifest = {
    "component": "xray-apple-vless-ws-engine-wrappers",
    "schema_version": 1,
    "wrappers": {
        platform: {
            "sha256": hashlib.sha256(xray.read_bytes()).hexdigest(),
        }
    },
}
pathlib.Path(output).write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
}

write_selftest_winn_provenance() {
  local output="$1"
  local winn="$2"
  local archive_root="$3"
  "${PYTHON_BIN}" - "${output}" "${winn}" "${archive_root}" \
    "${APPLE_AWG_EXPECTED_GO_VERSION}" \
    "${APPLE_AWG_EXPECTED_GO_DARWIN_ARM64_SHA256}" \
    "${APPLE_AWG_EXPECTED_GO_DARWIN_AMD64_SHA256}" \
    "${APPLE_WINN_EXPECTED_MODULE}" \
    "${APPLE_WINN_EXPECTED_GENERATION}" \
    "${WINS_LIPO_BIN}" "${WINS_FILE_BIN}" "${WINS_OTOOL_BIN}" \
    "${WINS_NM_BIN}" "/usr/bin/vtool" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    output,
    winn_raw,
    archive_root,
    go_version,
    go_arm64,
    go_amd64,
    module,
    generation,
    lipo_bin,
    file_bin,
    otool_bin,
    nm_bin,
    vtool_bin,
) = sys.argv[1:]
winn = pathlib.Path(winn_raw)
digest = hashlib.sha256(winn.read_bytes()).hexdigest()
archs = sorted(subprocess.check_output([lipo_bin, "-archs", str(winn)], text=True).split())
if archs != ["arm64", "x86_64"]:
    raise SystemExit(f"self-test Winn dylib is not exactly universal arm64+x86_64: {archs!r}")
file_text = subprocess.check_output([file_bin, "-b", str(winn)], text=True)
if "Mach-O" not in file_text:
    raise SystemExit(f"self-test Winn dylib is not Mach-O: {file_text}")
otool_text = subprocess.check_output([otool_bin, "-l", str(winn)], text=True)
names = {
    "1": "MACOS",
    "2": "IOS",
    "7": "IOSSIMULATOR",
    "MACOS": "MACOS",
    "IOS": "IOS",
    "IOSSIMULATOR": "IOSSIMULATOR",
}
platforms = []
for line in otool_text.splitlines():
    stripped = line.strip()
    if stripped.startswith("platform "):
        mapped = names.get(stripped.split()[1])
        if mapped:
            platforms.append(mapped)
if sorted(set(platforms)) != ["MACOS"]:
    raise SystemExit(f"self-test Winn dylib platform {platforms!r} is not MACOS")


def command_values(text, field):
    return [
        parts[1]
        for line in text.splitlines()
        if len(parts := line.strip().split()) >= 2 and parts[0] == field
    ]


def platform_values(text):
    return sorted({
        names.get(parts[1])
        for line in text.splitlines()
        if len(parts := line.strip().split()) >= 2
        and parts[0] == "platform"
        and names.get(parts[1])
    })


def inspect_slice(arch):
    load = subprocess.check_output(
        [otool_bin, "-arch", arch, "-l", str(winn)], text=True
    )
    build = subprocess.check_output(
        [vtool_bin, "-show-build", "-arch", arch, str(winn)], text=True
    )
    if platform_values(load) != ["MACOS"] or platform_values(build) != ["MACOS"]:
        raise SystemExit(f"self-test Winn dylib {arch} platform mismatch")
    minos = command_values(load, "minos")
    if minos != ["13.0"] or command_values(build, "minos") != minos:
        raise SystemExit(f"self-test Winn dylib {arch} minimum OS mismatch")
    uuids = command_values(load, "uuid")
    if len(uuids) != 1:
        raise SystemExit(f"self-test Winn dylib {arch} UUID mismatch")
    header = subprocess.check_output(
        [otool_bin, "-arch", arch, "-hv", str(winn)], text=True
    )
    if "MH_DYLIB" not in header and "DYLIB" not in header:
        raise SystemExit(f"self-test Winn dylib {arch} filetype mismatch")
    install = subprocess.check_output(
        [otool_bin, "-arch", arch, "-D", str(winn)], text=True
    )
    install_names = [
        line.strip()
        for line in install.splitlines()
        if line.strip() and not line.endswith(":") and line.strip() != str(winn)
    ]
    expected_install = "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine"
    if install_names[-1:] != [expected_install]:
        raise SystemExit(f"self-test Winn dylib {arch} install-name mismatch")
    dependencies_output = subprocess.check_output(
        [otool_bin, "-arch", arch, "-L", str(winn)], text=True
    )
    dependencies = []
    for line in dependencies_output.splitlines():
        value = line.strip()
        if not value or value.endswith(":") or value.startswith(str(winn)):
            continue
        dependency = value.split(" (", 1)[0]
        if dependency != expected_install:
            dependencies.append(dependency)
    dependencies = sorted(set(dependencies))
    symbols_output = subprocess.check_output(
        [nm_bin, "-arch", arch, "-gU", str(winn)], text=True
    )
    symbols = {line.split()[-1].lstrip("_") for line in symbols_output.splitlines() if line.split()}
    required = {"WinnTunnelCreate", "WinnTunnelCreateWithCarrier", "WinnTunnelCreateWinn3"}
    if not required.issubset(symbols):
        raise SystemExit(f"self-test Winn dylib {arch} role symbols mismatch")
    return {
        "architecture": arch,
        "dependencies": dependencies,
        "filetype": "MH_DYLIB",
        "install_name": expected_install,
        "minos": minos[0],
        "platform": "MACOS",
        "role_symbols": {
            "core": ["WinnTunnelCreateWinn3"],
            "relay": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
        },
        "uuid": uuids[0].upper(),
    }


macos_slices = {arch: inspect_slice(arch) for arch in archs}
root = pathlib.Path(archive_root)
archives = {}
dummy = "0" * 64
for key, name, header, arch, platform, target in (
    ("iphoneos_arm64", "libwinn-datapath-ios-arm64.a", "libwinn-datapath-ios-arm64.h", "arm64", "IOS", "datapath-ios-arm64"),
    ("macosx_arm64", "libwinn-datapath-darwin-arm64.a", "libwinn-datapath-darwin-arm64.h", "arm64", "MACOS", "datapath-archive-darwin-arm64"),
    ("macosx_x86_64", "libwinn-datapath-darwin-amd64.a", "libwinn-datapath-darwin-amd64.h", "x86_64", "MACOS", "datapath-archive-darwin-amd64"),
    ("iphonesimulator_arm64", "libwinn-datapath-iossimulator-arm64.a", "libwinn-datapath-iossimulator-arm64.h", "arm64", "IOSSIMULATOR", "datapath-iossimulator-arm64"),
    ("iphonesimulator_x86_64", "libwinn-datapath-iossimulator-amd64.a", "libwinn-datapath-iossimulator-amd64.h", "x86_64", "IOSSIMULATOR", "datapath-iossimulator-amd64"),
):
    archive = root / name
    header_path = root / header
    archive.write_bytes(f"selftest-archive:{key}\n".encode("ascii"))
    header_path.write_text(f"/* {name} */\n", encoding="utf-8")
    archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    archives[key] = {
        "architectures": [arch],
        "build_a_sha256": archive_sha,
        "build_b_sha256": archive_sha,
        "filetype": "ar-archive",
        "header_path": header,
        "header_sha256": hashlib.sha256(header_path.read_bytes()).hexdigest(),
        "path": name,
        "platform": platform,
        "sha256": archive_sha,
        "target": target,
    }
def fixture_slice(arch, platform, minos, uuid):
    return {
        "architecture": arch,
        "dependencies": ["/usr/lib/libSystem.B.dylib"],
        "filetype": "MH_DYLIB",
        "install_name": "@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine",
        "minos": minos,
        "platform": platform,
        "role_symbols": {
            "core": ["WinnTunnelCreateWinn3"],
            "relay": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
        },
        "uuid": uuid,
    }


wrappers = {
    "iphoneos": {
        "architectures": ["arm64"],
        "filetype": "mach-o-dylib",
        "path": "ios/iphoneos/libWinsWinnPacketEngine.dylib",
        "platform": "IOS",
        "roles": ["core", "relay"],
        "sha256": dummy,
        "slices": {
            "arm64": fixture_slice(
                "arm64", "IOS", "13.0", "11111111-1111-1111-1111-111111111111"
            )
        },
        "strip_state": "stripped",
    },
    "iphonesimulator": {
        "architectures": ["arm64", "x86_64"],
        "filetype": "mach-o-dylib",
        "path": "ios/iphonesimulator/libWinsWinnPacketEngine.dylib",
        "platform": "IOSSIMULATOR",
        "roles": ["core", "relay"],
        "sha256": dummy,
        "slices": {
            "arm64": fixture_slice(
                "arm64", "IOSSIMULATOR", "14.0", "22222222-2222-2222-2222-222222222222"
            ),
            "x86_64": fixture_slice(
                "x86_64", "IOSSIMULATOR", "13.0", "33333333-3333-3333-3333-333333333333"
            ),
        },
        "strip_state": "stripped",
    },
    "macosx": {
        "architectures": archs,
        "filetype": "mach-o-dylib",
        "path": "macos/libWinsWinnPacketEngine.dylib",
        "platform": "MACOS",
        "roles": ["core", "relay"],
        "sha256": digest,
        "slices": macos_slices,
        "strip_state": "stripped",
    },
}
path_binding = lambda path, sha=dummy: {"path": path, "sha256": sha}
manifest = {
    "apple_toolchain": {
        "tools": {
            name: path_binding(f"/usr/bin/{name}")
            for name in ("ar", "clang", "file", "lipo", "nm", "otool", "strip", "vtool")
        }
    },
    "archives": archives,
    "builders": {
        "wrapper_builder": {"path": "tools/build_apple_engine_wrappers.sh", "sha256": "b" * 64},
        "wrapper_header": {"path": "apple/EngineWrappers/WinnTunnel.h", "sha256": "c" * 64},
    },
    "component": "winn-apple-engine-wrappers",
    "generation": generation,
    "release": {
        "contract": "winsvpn-winn-release-manifest-v1",
        "go": {
            "archive_sha256": go_arm64,
            "executable_sha256": "1" * 64,
            "install_tree_sha256": "2" * 64,
            "version": go_version,
        },
        "manifest_sha256": "3" * 64,
        "producer": {
            "builder_sha256": "4" * 64,
            "driver_sha256": "5" * 64,
            "toolchain_pins_sha256": "6" * 64,
        },
        "signature_public_key": "",
        "signature_state": "unsigned-dev",
        "source": {
            "binding": "export",
            "commit": "260da56",
            "tree_sha256": "7" * 64,
        },
    },
    "role_binding": {
        "core": {
            "entry_symbol": "WinnTunnelCreateWinn3",
            "payload_class": "ip-packet",
            "required_symbols": ["WinnTunnelCreateWinn3"],
        },
        "relay": {
            "entry_symbols": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
            "payload_class": "awg-datagram",
            "required_symbols": ["WinnTunnelCreate", "WinnTunnelCreateWithCarrier"],
        },
    },
    "schema_version": 5,
    "source": {
        "module": module,
        "wrapper_path": "apple/EngineWrappers/WinsWinnPacketEngine.m",
        "wrapper_sha256": "6" * 64,
    },
    "wrappers": wrappers,
}
pathlib.Path(output).write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
}

require_selftest_engine_privacy() {
  local privacy_path="$1"
  local component="$2"
  [[ -f "${privacy_path}" && ! -L "${privacy_path}" && -s "${privacy_path}" ]] \
    || die "Apple engine artifact staging self-test missing privacy manifest for ${component}."
  "${PYTHON_BIN}" - "${privacy_path}" "${component}" <<'PY'
import plistlib
import sys

path, component = sys.argv[1:]
with open(path, "rb") as handle:
    manifest = plistlib.load(handle)
if manifest.get("NSPrivacyTracking") is not False:
    raise SystemExit(f"{component} privacy manifest must disable tracking")
if manifest.get("NSPrivacyTrackingDomains") not in ([], None):
    raise SystemExit(f"{component} privacy tracking domains must be empty")
if manifest.get("NSPrivacyCollectedDataTypes") not in ([], None):
    raise SystemExit(f"{component} privacy manifest should not declare collected data")
expected = {"NSPrivacyAccessedAPICategoryFileTimestamp": {"C617.1"}}
if component == "winn_packet_engine":
    expected["NSPrivacyAccessedAPICategorySystemBootTime"] = {"35F9.1"}
actual = {}
for item in manifest.get("NSPrivacyAccessedAPITypes") or []:
    api_type = item.get("NSPrivacyAccessedAPIType")
    reasons = item.get("NSPrivacyAccessedAPITypeReasons") or []
    if not isinstance(api_type, str) or not api_type:
        raise SystemExit(f"{component} privacy API type must be a string")
    if api_type in actual:
        raise SystemExit(f"{component} duplicate privacy API type {api_type}")
    if not isinstance(reasons, list) or any(not isinstance(reason, str) for reason in reasons):
        raise SystemExit(f"{component} privacy API reasons are malformed")
    actual[api_type] = set(reasons)
if actual != expected:
    raise SystemExit(
        f"{component} privacy API reasons {actual!r}, expected {expected!r}"
    )
PY
}

run_selftest() {
  printf '== Apple Engine Artifact Staging Self-Test ==\n'
  # The fixtures below are unsigned development engines. A release producer
  # exports WINS_APPLE_WINN3_RELEASE=1 and WINS_REQUIRE_APPLE_ENGINE=1 into
  # the readiness gate that runs this self-test; each case sets the mode it
  # tests, so the inherited release mode must not leak into the others.
  WINS_APPLE_WINN3_RELEASE=0
  WINS_REQUIRE_APPLE_ENGINE=0
  local production_output production_status
  set +e
  production_output="$(TARGET_BUILD_DIR="" stage_engine_artifacts 2>&1)"
  production_status=$?
  set -e
  if [[ "${production_status}" -eq 0 || "${production_output}" != *"TARGET_BUILD_DIR and FRAMEWORKS_FOLDER_PATH are required"* ]]; then
    die "Apple engine staging self-test did not fail closed without an Xcode build destination."
  fi
  local tmp_dir
  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/wins-apple-engine-stage.XXXXXX")"
  tmp_dir="$(cd "${tmp_dir}" && pwd -P)"
  trap 'rm -rf "${tmp_dir}"' RETURN

  local ios_privacy macos_privacy sim_privacy output status
  ios_privacy="$(PLATFORM_NAME=iphoneos framework_privacy_path "${tmp_dir}/WinsAmneziaWGPacketEngine.framework")"
  macos_privacy="$(PLATFORM_NAME=macosx framework_privacy_path "${tmp_dir}/WinsAmneziaWGPacketEngine.framework")"
  sim_privacy="$(PLATFORM_NAME=iphonesimulator framework_privacy_path "${tmp_dir}/WinsXrayVlessWsTransport.framework")"
  [[ "${ios_privacy}" == "${tmp_dir}/WinsAmneziaWGPacketEngine.framework/PrivacyInfo.xcprivacy" ]] \
    || die "Apple engine artifact staging self-test iOS privacy path is not the framework root."
  [[ "${macos_privacy}" == "${tmp_dir}/WinsAmneziaWGPacketEngine.framework/Versions/A/Resources/PrivacyInfo.xcprivacy" ]] \
    || die "Apple engine artifact staging self-test macOS privacy path is not Versions/A/Resources."
  [[ "${sim_privacy}" == "${tmp_dir}/WinsXrayVlessWsTransport.framework/PrivacyInfo.xcprivacy" ]] \
    || die "Apple engine artifact staging self-test simulator privacy path is not the framework root."
  set +e
  output="$(PLATFORM_NAME=unknown framework_privacy_path "${tmp_dir}/Foo.framework" 2>&1)"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"unknown platform"* ]]; then
    die "Apple engine artifact staging self-test did not fail on an unknown privacy platform."
  fi

  local privacy_a="${tmp_dir}/privacy-a.xcprivacy"
  local privacy_b="${tmp_dir}/privacy-b.xcprivacy"
  local privacy_c="${tmp_dir}/privacy-c.xcprivacy"
  write_framework_privacy_manifest "${privacy_a}" "winn_packet_engine"
  write_framework_privacy_manifest "${privacy_b}" "winn_packet_engine"
  cmp -s "${privacy_a}" "${privacy_b}" \
    || die "Apple engine artifact staging self-test privacy generation is not deterministic."
  write_framework_privacy_manifest "${privacy_a}" "amneziawg_packet_engine"
  write_framework_privacy_manifest "${privacy_c}" "xray_vless_ws_transport"
  cmp -s "${privacy_a}" "${privacy_c}" \
    || die "Apple engine artifact staging self-test AWG and Xray privacy manifests must match."
  cmp -s "${privacy_a}" "${privacy_b}" \
    && die "Apple engine artifact staging self-test Winn privacy manifest must differ from AWG/Xray."
  require_selftest_engine_privacy "${privacy_a}" "amneziawg_packet_engine"
  require_selftest_engine_privacy "${privacy_c}" "xray_vless_ws_transport"
  require_selftest_engine_privacy "${privacy_b}" "winn_packet_engine"

  mkdir -p "${tmp_dir}/src" "${tmp_dir}/build/PacketTunnel.appex"

  local clang_bin="clang"
  if command -v xcrun >/dev/null 2>&1; then
    clang_bin="$(xcrun -f clang 2>/dev/null || printf 'clang')"
  fi
  command -v "${clang_bin}" >/dev/null 2>&1 || [[ -x "${clang_bin}" ]] \
    || die "Apple engine artifact staging self-test requires clang."

  local sdk_path=""
  if command -v xcrun >/dev/null 2>&1; then
    sdk_path="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
  fi
  local clang_args=(
    -dynamiclib
    -arch arm64
    -arch x86_64
    -mmacosx-version-min=13.0
  )
  if [[ -n "${sdk_path}" ]]; then
    clang_args+=(-isysroot "${sdk_path}")
  fi

  compile_selftest_dylib() {
    local output_path="$1"
    shift
    local source_path="${output_path}.c"
    /bin/cat >"${source_path}"
    "${clang_bin}" "${clang_args[@]}" "$@" "${source_path}" -o "${output_path}"
  }

  compile_selftest_dylib "${tmp_dir}/src/libWinsAmneziaWGPacketEngine.dylib" \
    -Wl,-install_name,@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine \
    -x c <<'C'
int wins_amneziawg_packet_engine_contract_version(void) { return 1; }
void *wins_amneziawg_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)0; }
int wins_amneziawg_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
int wins_amneziawg_packet_engine_listen_port(void *engine) { (void)engine; return 0; }
void wins_amneziawg_packet_engine_stop(void *engine) { (void)engine; }
void wins_amneziawg_packet_engine_destroy(void *engine) { (void)engine; }
C

  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_APPLE_WINN3_RELEASE=0 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"Missing required Apple engine artifacts: xray_vless_ws_transport winn_packet_engine"* ]]; then
    die "Apple engine artifact staging self-test did not fail closed on missing required engines."
  fi

  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build-unsigned-dry-run" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=0 \
    WINS_APPLE_WINN3_RELEASE=0 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${output}" != *"Apple engine artifact staging skipped missing components: xray_vless_ws_transport"* \
        || "${output}" == *"Missing required Apple engine artifacts"* ]]; then
    die "Apple engine artifact staging self-test did not skip missing engines on unsigned dry-run."
  fi

  compile_selftest_dylib "${tmp_dir}/src/libWinsXrayVlessWsTransport.dylib" -x c <<'C'
int wins_xray_vless_ws_transport_contract_version(void) { return 1; }
int wins_xray_vless_ws_transport_configure(const char *config_json) { return config_json == (const char *)0 ? 0 : 1; }
int wins_xray_vless_ws_transport_start(void) { return 1; }
void wins_xray_vless_ws_transport_stop(void) {}
C
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"must depend on the embedded AWG framework"* ]]; then
    die "Apple engine artifact staging self-test did not fail on missing Xray dependency."
  fi

  compile_selftest_dylib "${tmp_dir}/src/libWinsXrayVlessWsTransport.dylib" \
    -L"${tmp_dir}/src" \
    -lWinsAmneziaWGPacketEngine \
    -Wl,-install_name,@rpath/WinsXrayVlessWsTransport.framework/WinsXrayVlessWsTransport \
    -Wl,-rpath,@loader_path/.. \
    -x c <<'C'
extern int wins_amneziawg_packet_engine_contract_version(void);
int wins_xray_vless_ws_transport_contract_version(void) { return 1; }
int wins_xray_vless_ws_transport_configure(const char *config_json) { return config_json == (const char *)0 ? 0 : wins_amneziawg_packet_engine_contract_version(); }
int wins_xray_vless_ws_transport_start(void) { return wins_amneziawg_packet_engine_contract_version(); }
void wins_xray_vless_ws_transport_stop(void) {}
C
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"Missing required Apple engine artifacts: winn_packet_engine"* ]]; then
    die "Apple engine artifact staging self-test did not fail on a missing Winn artifact."
  fi

  # Required Winn component: must be validated and staged like AWG and Xray.
  compile_selftest_dylib "${tmp_dir}/src/libWinsWinnPacketEngine.dylib" \
    -Wl,-install_name,@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine \
    -x c <<'C'
int wins_winn_packet_engine_contract_version(void) { return 1; }
void *wins_winn_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)0; }
int wins_winn_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
void wins_winn_packet_engine_stop(void *engine) { (void)engine; }
void wins_winn_packet_engine_destroy(void *engine) { (void)engine; }
int wins_winn_packet_engine_awg_seam_port(void *engine) { (void)engine; return 0; }
int wins_winn_packet_engine_expect_awg_port(void *engine, int port) { (void)engine; (void)port; return 0; }
int wins_winn_packet_engine_seam_stats(void *engine, char *out, int capacity) { (void)engine; (void)out; (void)capacity; return 0; }
int wins_winn_packet_engine_status_json(void *engine, char *out, int capacity) { (void)engine; (void)out; (void)capacity; return 0; }
const char *WinnTunnelCreateWinn3(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
const char *WinnTunnelCreate(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
const char *WinnTunnelCreateWithCarrier(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
C
  mkdir -p "${tmp_dir}/apple/EngineWrappers"
  install -m 644 \
    "${PROJECT_ROOT}/apple/EngineWrappers/WinsAmneziaWGPacketEngine.m" \
    "${tmp_dir}/apple/EngineWrappers/WinsAmneziaWGPacketEngine.m"
  "${PYTHON_BIN}" - \
    "${tmp_dir}/src/${APPLE_AWG_ENGINE_PROVENANCE_NAME}" \
    "${tmp_dir}/src/libWinsAmneziaWGPacketEngine.dylib" \
    "${tmp_dir}/src/libWinsXrayVlessWsTransport.dylib" \
    "${tmp_dir}/apple/EngineWrappers/WinsAmneziaWGPacketEngine.m" \
    "${APPLE_AWG_EXPECTED_GO_DARWIN_AMD64_SHA256}" \
    "${APPLE_AWG_EXPECTED_GO_DARWIN_ARM64_SHA256}" <<'PY'
import hashlib
import json
import pathlib
import sys

output, awg_raw, xray_raw, awg_source_raw, go_amd64, go_arm64 = sys.argv[1:]
awg = pathlib.Path(awg_raw)
xray = pathlib.Path(xray_raw)
awg_source = pathlib.Path(awg_source_raw)
manifest = {
    "awg_wrapper_source": {
        "path": "apple/EngineWrappers/WinsAmneziaWGPacketEngine.m",
        "sha256": hashlib.sha256(awg_source.read_bytes()).hexdigest(),
    },
    "bridge_provenance_sha256": "0" * 64,
    "component": "amneziawg-apple-engine-wrappers",
    "generation": "3.1",
    "go_toolchain": {
        "darwin_amd64_archive_sha256": go_amd64,
        "darwin_arm64_archive_sha256": go_arm64,
        "version": "1.27.1",
    },
    "schema_version": 2,
    "source": {
        "commit": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",
        "go_mod_sha256": "790252dad6cad8aa668ccc4dafdfdac4f2fa3d3fbefce16ded750f0a46cabe0d",
        "go_sum_sha256": "1a806e7973118c0ce8832e15d246fea0c44335a31fc4a0abe36a2ed165fada9d",
        "repository": "https://github.com/amnezia-vpn/amneziawg-apple.git",
        "tag": "v3.1.20260814",
        "tree": "24183de0cc22b957ff9e34ac3494a80f515ac565",
    },
    "wrappers": {
        "macosx": {
            "amneziawg_packet_engine": {
                "architectures": ["arm64", "x86_64"],
                "path": "selftest/libWinsAmneziaWGPacketEngine.dylib",
                "sha256": hashlib.sha256(awg.read_bytes()).hexdigest(),
            },
            "xray_vless_ws_transport": {
                "architectures": ["arm64", "x86_64"],
                "path": "selftest/libWinsXrayVlessWsTransport.dylib",
                "sha256": hashlib.sha256(xray.read_bytes()).hexdigest(),
            },
        }
    },
    "xray_replacement": {
        "commit": "77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3",
        "go_mod_sum": "h1:VwJOtL3vj2w+8TWa6MZE1q88NsfrWvOXGJ+5wZ2N2ro=",
        "module_sum": "h1:4PniqnMxVxC54OdTx3e73BOMH/GD6jf85iaRyApAwGQ=",
        "replaced_module": "github.com/xtls/xray-core",
        "source_module": "github.com/amnezia-vpn/amnezia-xray-core",
        "version": "v1.260924.0",
        "zip_sha256": "7df5ebc400da6cc4ab13f5578e2fd19b855f98807f1ef1d86a30afc2cd213c40",
    },
}
pathlib.Path(output).write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
  write_selftest_xray_provenance \
    "${tmp_dir}/src/${APPLE_XRAY_ENGINE_PROVENANCE_NAME}" \
    "${tmp_dir}/src/libWinsXrayVlessWsTransport.dylib" \
    "macosx"
  write_selftest_winn_provenance \
    "${tmp_dir}/src/${APPLE_WINN_ENGINE_PROVENANCE_NAME}" \
    "${tmp_dir}/src/libWinsWinnPacketEngine.dylib" \
    "${tmp_dir}/src"
  PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts >/dev/null

  [[ -f "${tmp_dir}/build/Runner.app/Frameworks/WinsAmneziaWGPacketEngine.framework/Versions/A/WinsAmneziaWGPacketEngine" ]] \
    || die "Apple engine artifact staging self-test did not copy AWG artifact."
  [[ -f "${tmp_dir}/build/Runner.app/Frameworks/WinsXrayVlessWsTransport.framework/Versions/A/WinsXrayVlessWsTransport" ]] \
    || die "Apple engine artifact staging self-test did not copy Xray artifact."
  [[ -f "${tmp_dir}/build/Runner.app/Frameworks/WinsWinnPacketEngine.framework/Versions/A/WinsWinnPacketEngine" ]] \
    || die "Apple engine artifact staging self-test did not stage the required Winn artifact."
  [[ -f "${tmp_dir}/build/Runner.app/apple_engine_artifacts_manifest.json" ]] \
    || die "Apple engine artifact staging self-test did not write manifest."
  [[ -f "${tmp_dir}/build/Runner.app/${APPLE_AWG_ENGINE_PROVENANCE_NAME}" ]] \
    || die "Apple engine artifact staging self-test did not copy AWG 3.1 provenance."
  grep -q '"apple_awg_31_provenance_sha256"' "${tmp_dir}/build/Runner.app/apple_engine_artifacts_manifest.json" \
    || die "Apple engine artifact staging self-test manifest omits AWG 3.1 provenance."
  [[ -f "${tmp_dir}/build/Runner.app/${APPLE_XRAY_ENGINE_PROVENANCE_NAME}" ]] \
    || die "Apple engine artifact staging self-test did not copy Xray provenance."
  grep -q '"apple_xray_vless_ws_provenance_sha256"' "${tmp_dir}/build/Runner.app/apple_engine_artifacts_manifest.json" \
    || die "Apple engine artifact staging self-test manifest omits Xray provenance."
  [[ -f "${tmp_dir}/build/Runner.app/${APPLE_WINN_ENGINE_PROVENANCE_NAME}" ]] \
    || die "Apple engine artifact staging self-test did not copy Winn v3 provenance."
  grep -q '"apple_winn_v3_provenance_sha256"' "${tmp_dir}/build/Runner.app/apple_engine_artifacts_manifest.json" \
    || die "Apple engine artifact staging self-test manifest omits Winn v3 provenance."
  grep -q '"staged_components"' "${tmp_dir}/build/Runner.app/apple_engine_artifacts_manifest.json" \
    || die "Apple engine artifact staging self-test manifest omits staged_components."
  grep -q '"winn_packet_engine"' "${tmp_dir}/build/Runner.app/apple_engine_artifacts_manifest.json" \
    || die "Apple engine artifact staging self-test manifest omits the required Winn component."
  "${PYTHON_BIN}" - \
    "${tmp_dir}/build/Runner.app/apple_engine_artifacts_manifest.json" \
    "${tmp_dir}/build/Runner.app/${APPLE_XRAY_ENGINE_PROVENANCE_NAME}" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
provenance = pathlib.Path(sys.argv[2]).read_bytes()
expected = hashlib.sha256(provenance).hexdigest()
if manifest.get("apple_xray_vless_ws_provenance_sha256") != expected:
    raise SystemExit("self-test Xray provenance hash is not bound exactly")
PY

  local awg_framework xray_framework winn_framework
  awg_framework="${tmp_dir}/build/Runner.app/Frameworks/WinsAmneziaWGPacketEngine.framework"
  xray_framework="${tmp_dir}/build/Runner.app/Frameworks/WinsXrayVlessWsTransport.framework"
  winn_framework="${tmp_dir}/build/Runner.app/Frameworks/WinsWinnPacketEngine.framework"
  [[ ! -e "${awg_framework}/PrivacyInfo.xcprivacy" ]] \
    || die "Apple engine artifact staging self-test placed macOS AWG privacy at the iOS framework root."
  [[ ! -e "${xray_framework}/PrivacyInfo.xcprivacy" ]] \
    || die "Apple engine artifact staging self-test placed macOS Xray privacy at the iOS framework root."
  [[ ! -e "${winn_framework}/PrivacyInfo.xcprivacy" ]] \
    || die "Apple engine artifact staging self-test placed macOS Winn privacy at the iOS framework root."
  require_selftest_engine_privacy \
    "${awg_framework}/Versions/A/Resources/PrivacyInfo.xcprivacy" \
    "amneziawg_packet_engine"
  require_selftest_engine_privacy \
    "${xray_framework}/Versions/A/Resources/PrivacyInfo.xcprivacy" \
    "xray_vless_ws_transport"
  require_selftest_engine_privacy \
    "${winn_framework}/Versions/A/Resources/PrivacyInfo.xcprivacy" \
    "winn_packet_engine"

  local src_awg dst_awg src_xray dst_xray src_winn dst_winn
  local src_awg_sha dst_awg_sha src_xray_sha dst_xray_sha src_winn_sha dst_winn_sha
  src_awg="${tmp_dir}/src/libWinsAmneziaWGPacketEngine.dylib"
  dst_awg="${awg_framework}/Versions/A/WinsAmneziaWGPacketEngine"
  src_xray="${tmp_dir}/src/libWinsXrayVlessWsTransport.dylib"
  dst_xray="${xray_framework}/Versions/A/WinsXrayVlessWsTransport"
  src_winn="${tmp_dir}/src/libWinsWinnPacketEngine.dylib"
  dst_winn="${winn_framework}/Versions/A/WinsWinnPacketEngine"
  src_awg_sha="$(wins_sha256 "${src_awg}")" \
    || die "Apple engine artifact staging self-test could not hash the source AWG dylib."
  dst_awg_sha="$(wins_sha256 "${dst_awg}")" \
    || die "Apple engine artifact staging self-test could not hash the staged AWG dylib."
  src_xray_sha="$(wins_sha256 "${src_xray}")" \
    || die "Apple engine artifact staging self-test could not hash the source Xray dylib."
  dst_xray_sha="$(wins_sha256 "${dst_xray}")" \
    || die "Apple engine artifact staging self-test could not hash the staged Xray dylib."
  src_winn_sha="$(wins_sha256 "${src_winn}")" \
    || die "Apple engine artifact staging self-test could not hash the source Winn dylib."
  dst_winn_sha="$(wins_sha256 "${dst_winn}")" \
    || die "Apple engine artifact staging self-test could not hash the staged Winn dylib."
  [[ "${src_awg_sha}" == "${dst_awg_sha}" ]] \
    || die "Apple engine artifact staging self-test AWG destination hash is not bound to the source artifact."
  [[ "${src_xray_sha}" == "${dst_xray_sha}" ]] \
    || die "Apple engine artifact staging self-test Xray destination hash is not bound to the source artifact."
  [[ "${src_winn_sha}" == "${dst_winn_sha}" ]] \
    || die "Apple engine artifact staging self-test Winn destination hash is not bound to the source artifact."
  engine_delivery_is_stripped "${dst_awg}" \
    || die "Apple engine artifact staging self-test staged an unstripped AWG delivery binary."
  engine_delivery_is_stripped "${dst_xray}" \
    || die "Apple engine artifact staging self-test staged an unstripped Xray delivery binary."
  engine_delivery_is_stripped "${dst_winn}" \
    || die "Apple engine artifact staging self-test staged an unstripped Winn delivery binary."
  require_component_symbols "amneziawg_packet_engine" "${dst_awg}"
  require_component_symbols "xray_vless_ws_transport" "${dst_xray}"
  require_component_symbols "winn_packet_engine" "${dst_winn}"

  cp "${src_awg}" "${tmp_dir}/src/libWinsAmneziaWGPacketEngine.dylib.clean"
  compile_selftest_dylib "${tmp_dir}/src/libWinsAmneziaWGPacketEngine.dylib" \
    -Wl,-install_name,@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine \
    -x c <<'C'
static int wins_amneziawg_packet_engine_secret(void) { return 7; }
int wins_amneziawg_packet_engine_contract_version(void) { return wins_amneziawg_packet_engine_secret(); }
void *wins_amneziawg_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)0; }
int wins_amneziawg_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
int wins_amneziawg_packet_engine_listen_port(void *engine) { (void)engine; return 0; }
void wins_amneziawg_packet_engine_stop(void *engine) { (void)engine; }
void wins_amneziawg_packet_engine_destroy(void *engine) { (void)engine; }
C
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"non-public or local symbols"* ]]; then
    die "Apple engine artifact staging self-test did not fail on a delivery dylib with local symbols."
  fi

  compile_selftest_dylib "${tmp_dir}/src/libWinsAmneziaWGPacketEngine.dylib" -g \
    -Wl,-install_name,@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine \
    -x c <<'C'
int wins_amneziawg_packet_engine_contract_version(void) { return 1; }
void *wins_amneziawg_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)0; }
int wins_amneziawg_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
int wins_amneziawg_packet_engine_listen_port(void *engine) { (void)engine; return 0; }
void wins_amneziawg_packet_engine_stop(void *engine) { (void)engine; }
void wins_amneziawg_packet_engine_destroy(void *engine) { (void)engine; }
C
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"non-public or local symbols"* ]]; then
    die "Apple engine artifact staging self-test did not fail on a delivery dylib with debug symbols."
  fi
  cp "${tmp_dir}/src/libWinsAmneziaWGPacketEngine.dylib.clean" \
    "${tmp_dir}/src/libWinsAmneziaWGPacketEngine.dylib"
  rm -f "${tmp_dir}/src/libWinsAmneziaWGPacketEngine.dylib.clean"

  # A symbol-complete substitute must still fail provenance. Rebuilding a
  # required-symbol dylib with a different contract version keeps the C ABI
  # gate green while changing the bytes that provenance binds.
  compile_selftest_dylib "${tmp_dir}/src/libWinsWinnPacketEngine.dylib" \
    -Wl,-install_name,@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine \
    -x c <<'C'
int wins_winn_packet_engine_contract_version(void) { return 2; }
void *wins_winn_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)0; }
int wins_winn_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
void wins_winn_packet_engine_stop(void *engine) { (void)engine; }
void wins_winn_packet_engine_destroy(void *engine) { (void)engine; }
int wins_winn_packet_engine_awg_seam_port(void *engine) { (void)engine; return 0; }
int wins_winn_packet_engine_expect_awg_port(void *engine, int port) { (void)engine; (void)port; return 0; }
int wins_winn_packet_engine_seam_stats(void *engine, char *out, int capacity) { (void)engine; (void)out; (void)capacity; return 0; }
int wins_winn_packet_engine_status_json(void *engine, char *out, int capacity) { (void)engine; (void)out; (void)capacity; return 0; }
const char *WinnTunnelCreateWinn3(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
const char *WinnTunnelCreate(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
const char *WinnTunnelCreateWithCarrier(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
C
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"SHA-256 mismatch"* ]]; then
    die "Apple engine artifact staging self-test did not fail on a symbol-complete Winn dylib substitute."
  fi

  # Restore a matching Winn dylib so later negative ABI cases still reach the
  # symbol gate rather than dying on an unrelated provenance mismatch.
  compile_selftest_dylib "${tmp_dir}/src/libWinsWinnPacketEngine.dylib" \
    -Wl,-install_name,@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine \
    -x c <<'C'
int wins_winn_packet_engine_contract_version(void) { return 1; }
void *wins_winn_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)0; }
int wins_winn_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
void wins_winn_packet_engine_stop(void *engine) { (void)engine; }
void wins_winn_packet_engine_destroy(void *engine) { (void)engine; }
int wins_winn_packet_engine_awg_seam_port(void *engine) { (void)engine; return 0; }
int wins_winn_packet_engine_expect_awg_port(void *engine, int port) { (void)engine; (void)port; return 0; }
int wins_winn_packet_engine_seam_stats(void *engine, char *out, int capacity) { (void)engine; (void)out; (void)capacity; return 0; }
int wins_winn_packet_engine_status_json(void *engine, char *out, int capacity) { (void)engine; (void)out; (void)capacity; return 0; }
const char *WinnTunnelCreateWinn3(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
const char *WinnTunnelCreate(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
const char *WinnTunnelCreateWithCarrier(const char *doc, int fd, char **err) { (void)doc; (void)fd; (void)err; return 0; }
C
  write_selftest_winn_provenance \
    "${tmp_dir}/src/${APPLE_WINN_ENGINE_PROVENANCE_NAME}" \
    "${tmp_dir}/src/libWinsWinnPacketEngine.dylib" \
    "${tmp_dir}/src"
  ln -sf "${APPLE_WINN_ENGINE_PROVENANCE_NAME}" "${tmp_dir}/src/${APPLE_WINN_ENGINE_PROVENANCE_NAME}.real"
  rm -f "${tmp_dir}/src/${APPLE_WINN_ENGINE_PROVENANCE_NAME}"
  ln -s "${APPLE_WINN_ENGINE_PROVENANCE_NAME}.real" "${tmp_dir}/src/${APPLE_WINN_ENGINE_PROVENANCE_NAME}"
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"symbolic"* ]]; then
    die "Apple engine artifact staging self-test did not fail on symbolic Winn provenance."
  fi
  rm -f "${tmp_dir}/src/${APPLE_WINN_ENGINE_PROVENANCE_NAME}" "${tmp_dir}/src/${APPLE_WINN_ENGINE_PROVENANCE_NAME}.real"
  printf '{not json\n' >"${tmp_dir}/src/${APPLE_WINN_ENGINE_PROVENANCE_NAME}"
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"invalid JSON"* ]]; then
    die "Apple engine artifact staging self-test did not fail on malformed Winn provenance."
  fi
  rm -f "${tmp_dir}/src/${APPLE_WINN_ENGINE_PROVENANCE_NAME}"

  # A present Winn artifact that does not honour the C ABI must still fail.
  rm -f "${tmp_dir}/src/libWinsWinnPacketEngine.dylib"
  compile_selftest_dylib "${tmp_dir}/src/libWinsWinnPacketEngine.dylib" \
    -Wl,-install_name,@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine \
    -x c <<'C'
int wins_winn_packet_engine_contract_version(void) { return 1; }
int wins_winn_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
void wins_winn_packet_engine_stop(void *engine) { (void)engine; }
void wins_winn_packet_engine_destroy(void *engine) { (void)engine; }
int wins_winn_packet_engine_awg_seam_port(void *engine) { (void)engine; return 0; }
int wins_winn_packet_engine_expect_awg_port(void *engine, int port) { (void)engine; (void)port; return 0; }
int wins_winn_packet_engine_seam_stats(void *engine, char *out, int capacity) { (void)engine; (void)out; (void)capacity; return 0; }
int wins_winn_packet_engine_status_json(void *engine, char *out, int capacity) { (void)engine; (void)out; (void)capacity; return 0; }
C
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"missing required Win's VPN C ABI symbols: wins_winn_packet_engine_create"* ]]; then
    die "Apple engine artifact staging self-test did not fail on an invalid Winn artifact."
  fi
  rm -f "${tmp_dir}/src/libWinsWinnPacketEngine.dylib"

  # An artifact missing only an ADDITIVE symbol must fail too. Without this case
  # the suite passes even if component_required_symbols() is reverted to the v1
  # five: the fixture above omits `create`, which the old gate already caught, so
  # nothing here pinned the three symbols the gate was widened for. That is the
  # exact regression that shipped on 2026-08-04 -- a six-symbol engine staged in
  # silence -- so it gets its own negative test.
  compile_selftest_dylib "${tmp_dir}/src/libWinsWinnPacketEngine.dylib" \
    -Wl,-install_name,@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine \
    -x c <<'C'
int wins_winn_packet_engine_contract_version(void) { return 1; }
void *wins_winn_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)0; }
int wins_winn_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
void wins_winn_packet_engine_stop(void *engine) { (void)engine; }
void wins_winn_packet_engine_destroy(void *engine) { (void)engine; }
int wins_winn_packet_engine_awg_seam_port(void *engine) { (void)engine; return 0; }
int wins_winn_packet_engine_expect_awg_port(void *engine, int port) { (void)engine; (void)port; return 0; }
C
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 \
        || "${output}" != *"wins_winn_packet_engine_seam_stats"* \
        || "${output}" != *"wins_winn_packet_engine_status_json"* ]]; then
    die "Apple engine artifact staging self-test did not fail on an artifact missing the additive seam-observability symbols."
  fi
  rm -f "${tmp_dir}/src/libWinsWinnPacketEngine.dylib"

  local xray_provenance xray_provenance_saved
  xray_provenance="${tmp_dir}/src/${APPLE_XRAY_ENGINE_PROVENANCE_NAME}"
  xray_provenance_saved="${xray_provenance}.saved"
  mv "${xray_provenance}" "${xray_provenance_saved}"
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=0 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"Xray VLESS-WS engine provenance"* ]]; then
    die "Apple engine artifact staging self-test did not reject missing Xray provenance."
  fi
  install -m 644 "${xray_provenance_saved}" "${xray_provenance}"
  "${PYTHON_BIN}" - "${xray_provenance}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
manifest = json.loads(path.read_text(encoding="utf-8"))
manifest["wrappers"]["macosx"]["sha256"] = "0" * 64
path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=0 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"Xray VLESS-WS engine provenance"* ]]; then
    die "Apple engine artifact staging self-test did not reject drifted Xray provenance."
  fi
  rm -f "${xray_provenance}"
  mv "${xray_provenance_saved}" "${xray_provenance}"

  rm -f "${tmp_dir}/src/libWinsXrayVlessWsTransport.dylib"
  compile_selftest_dylib "${tmp_dir}/src/libWinsXrayVlessWsTransport.dylib" \
    -L"${tmp_dir}/src" \
    -lWinsAmneziaWGPacketEngine \
    -Wl,-install_name,@rpath/WinsXrayVlessWsTransport.framework/WinsXrayVlessWsTransport \
    -Wl,-rpath,@loader_path/.. \
    -x c <<'C'
extern int wins_amneziawg_packet_engine_contract_version(void);
int wins_xray_vless_ws_transport_contract_version(void) { return 1; }
int wins_xray_vless_ws_transport_start(void) { return wins_amneziawg_packet_engine_contract_version(); }
void wins_xray_vless_ws_transport_stop(void) {}
C
  set +e
  output="$(
    PROJECT_ROOT="${tmp_dir}" \
    APPLE_ENGINE_ARTIFACTS_DIR="${tmp_dir}/src" \
    TARGET_BUILD_DIR="${tmp_dir}/build" \
    FRAMEWORKS_FOLDER_PATH="Runner.app/Frameworks" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Runner.app" \
    PLUGINS_FOLDER_PATH="Runner.app/PlugIns" \
    PLATFORM_NAME="macosx" \
    ARCHS="$(uname -m)" \
    WINS_REQUIRE_APPLE_ENGINE=1 \
    WINS_STAGE_APPLE_ENGINE_SELFTEST=0 \
    stage_engine_artifacts 2>&1
  )"
  status=$?
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"missing required Win's VPN C ABI symbols: wins_xray_vless_ws_transport_configure"* ]]; then
    die "Apple engine artifact staging self-test did not fail on missing C ABI symbols."
  fi

  printf 'Apple engine artifact staging self-test passed.\n'
}

if [[ "${WINS_STAGE_APPLE_ENGINE_SELFTEST}" == "1" ]]; then
  run_selftest
  exit 0
fi

stage_engine_artifacts
