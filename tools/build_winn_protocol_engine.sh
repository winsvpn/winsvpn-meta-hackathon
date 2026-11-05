#!/bin/bash -p
# Cross-compile the Winn Protocol v3 client binding for one target.
#
# This deliberately mirrors tools/build_xray_engine.sh: same argument shape
# (<target> <output-path>), same NDK clang resolution for the Android targets,
# same CGO_ENABLED=0 everywhere else. It is a second consumer of an existing
# pattern, not a second native-library strategy.
#
#   ./tools/build_winn_protocol_engine.sh <target> <output-path>
#
#   target: windows-amd64 | windows-arm64 | darwin-amd64 | darwin-arm64
#           linux-amd64   | linux-arm64   | android-arm64 | android-arm | android-amd64
#           ios-arm64
#           server-linux-amd64  | server-linux-arm64   (winn-server, control plane)
#           carrier-linux-amd64 | carrier-linux-arm64  (winn-carrier-server, data plane)
#           winn3-gateway-linux-amd64 | winn3-gateway-linux-arm64
#                                                     (winn3-gateway, v3 responder)
#
# The eight executable targets produce a plain Go binary: winn-clientinfo, a
# single-shot JSON subprocess. That is how Win's VPN already ships Go engines
# (winsvpn_awg_engine.exe on Windows, libxray.so under jniLibs on Android).
#
# ios-arm64 is different and has to be. iOS cannot spawn subprocesses, so the
# target there is -buildmode=c-archive, matching how the reviewed AmneziaWG Go
# bridge reaches iOS as libwg-go.a before an Objective-C wrapper links it. The
# resulting .a plus generated .h is the input to a wrapper, not a drop-in
# artifact.
#
# The client-info targets report versions, capabilities, suites, mode/carrier
# policy, and run the v3 connectivity contract validators. They are not packet
# engines. The separate datapath targets below are the standalone Winn v3
# packet engines consumed by the platform tunnel providers. A release advertises
# winn/3 only when its platform allowlist, descriptor ring, and artifact gates
# all pass.
#
# ---------------------------------------------------------------------------
# DATAPATH TARGETS (added by the datapath lane)
# ---------------------------------------------------------------------------
#
#   datapath-<platform>-<arch>          the framed-duplex subprocess engine
#                                       (cmd/winn-datapath), for the eight
#                                       executable targets
#   datapath-ios-arm64                  the c-archive engine (cdatapath) for iOS
#   datapath-iossimulator-arm64
#   datapath-iossimulator-amd64         the same c-archive for the iOS SIMULATOR.
#                                       Without these nothing Winn could be run
#                                       in a simulator at all, only compiled.
#   datapath-archive-darwin-arm64
#   datapath-archive-darwin-amd64       the same c-archive for macOS, which the
#                                       plan has sharing the Apple wrapper
#
# These targets move standalone Winn v3 packets between the host tunnel seam and
# the authenticated Winn session. They do not require AWG or Xray. Building a
# datapath alone still does not enable winn/3; release producers must also pass
# platform enablement, descriptor-ring, and final-artifact verification gates.
#
# ---------------------------------------------------------------------------
# SERVER TARGETS (added by the deploy lane, 2026-08-04)
# ---------------------------------------------------------------------------
#
#   server-linux-<amd64|arm64>   cmd/winn-server, the control-plane PQ AWG key
#                                controller. See OPERATIONS.md section 4 and
#                                deploy/systemd/winn-server-file.service.
#   carrier-linux-<amd64|arm64>  cmd/winn-carrier-server, the data-plane
#                                obfuscated carrier. See OPERATIONS.md section
#                                4.1 and deploy/systemd/winn-carrier-server.service.
#
# Both are plain Go executables, same build_executable() path as the eight
# original targets above -- nothing server-specific about the compilation
# step. They are named separately from linux-amd64/linux-arm64 because those
# already mean "the winn-clientinfo client binding for Linux"; a second
# meaning on the same target name would silently overwrite whichever the
# caller built second. arm64 is built because the rest of this script treats
# every OS as an amd64/arm64 pair; nothing about deploying to a specific
# arm64 host requires it yet.
#
# ---------------------------------------------------------------------------
# WINN/3 GATEWAY TARGET (added by the v3 deployment lane, 2026-08-09)
# ---------------------------------------------------------------------------
#
#   winn3-gateway-linux-<amd64|arm64>
#                                cmd/winn3-gateway, the reachable multi-session
#                                winn/3 responder. See its package doc and
#                                server/wins_winn3_gateway_install.sh.
#
# This is a DIFFERENT artifact from carrier-linux-*, and the distinction is the
# whole reason it needs its own target rather than a flag on that one:
#
#   - winn-carrier-server speaks the v1 stack. It terminates an authenticated
#     H2/H3 transport and relays outer AmneziaWG datagrams to a local AWG
#     backend, so it is useless without AmneziaWG underneath it.
#   - winn3-gateway speaks winn/3, which is a STANDALONE protocol: its own
#     handshake, its own crypto, no AmneziaWG and no Xray anywhere in the path.
#     It binds one unconnected UDP socket and terminates sessions itself.
#
# Building it does not entitle any client to advertise winn/3, and installing
# it does not change what the control plane serves. The hub's
# resolve_served_winn_protocol() is the only thing that decides that, and this
# script does not touch it.
#
# NOTE ON WHAT THIS BINARY IS. cmd/winn3-gateway supports two explicit modes.
# The default reflector mode is handshake-only and carries no user traffic.
# Production standalone rollout uses -forward with an authenticated peer
# registry, a TUN device, forwarding/NAT rules, and the installer-managed
# privileges and boot ordering. A build alone proves neither mode is deployed;
# release evidence must show the exact unit, registry, firewall, and carriage.

#
# ---------------------------------------------------------------------------
# HOW A RELEASE IS PRODUCED (owner decision, 2026-10-09)
# ---------------------------------------------------------------------------
#
# The retained-producer gate (root-owned authority JSON with a 15 minute
# window, an inode-bound single-use ledger signed after the build, and a
# custody file-descriptor handoff) could never complete and was removed. The
# protections that matter are kept, split between two tools:
#
#   tools/winn_release.py   seals a read-only source snapshot from a clean git
#                           commit, extracts Go from the pinned archive and
#                           checks archive, install tree and bin/go digests,
#                           checks the pinned NDK and Xcode, fills and seals a
#                           private module cache (go.sum pins its bytes), runs
#                           THIS script twice per target from two snapshot
#                           copies, requires byte-identical outputs, writes the
#                           manifest and signs it with the release authority.
#   this script             builds ONE target from those sealed inputs. It
#                           re-checks every input digest before and after the
#                           compile, so a mutated input fails the build.
#
# Called without WINS_WINN_SOURCE_ROOT, this script hands the request to
# `tools/winn_release.py build-one`, which does the whole sealed two-build
# release for that one target and installs the result at <output-path>.
# ---------------------------------------------------------------------------

set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
hash -r 2>/dev/null || true

die() { printf 'WINN BUILD ERROR: %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PIN_MANIFEST="${SCRIPT_DIR}/toolchain-pins.json"
GARBLE_PIN_MANIFEST="${SCRIPT_DIR}/winn_garble_pin.json"
RELEASE_DRIVER="${SCRIPT_DIR}/winn_release.py"
NDK_CLANG_API_LEVEL=24
IOS_DEPLOYMENT_TARGET=13.0
# Go 1.27 requires macOS 13 or later. Keep the c-archive's load commands aligned
# with the app, extension, and wrapper deployment floor so an older target can
# never hide inside an otherwise macOS-13 release artifact.
MACOS_DEPLOYMENT_TARGET=13.0
# The simulator slices tools/verify_winn_abi_conformance.sh already names. arm64
# needs 14.0 because that is the first iOS SDK with an arm64 simulator at all;
# x86_64 matches the device target.
IOS_SIMULATOR_ARM64_DEPLOYMENT_TARGET=14.0
IOS_SIMULATOR_X86_64_DEPLOYMENT_TARGET=13.0

[[ $# -eq 2 ]] \
  || die "Usage: $0 <windows-amd64|windows-arm64|darwin-amd64|darwin-arm64|linux-amd64|linux-arm64|android-arm64|android-arm|android-amd64|ios-arm64|datapath-<same ten>|datapath-iossimulator-arm64|datapath-iossimulator-amd64|datapath-archive-darwin-arm64|datapath-archive-darwin-amd64|server-linux-amd64|server-linux-arm64|carrier-linux-amd64|carrier-linux-arm64|winn3-gateway-linux-amd64|winn3-gateway-linux-arm64|winn3-relay-windows-amd64|winn3-relay-windows-arm64> <output-path>"

TARGET="$1"
OUTPUT_ARG="$2"

case "${TARGET}" in
  windows-amd64|windows-arm64|darwin-amd64|darwin-arm64|linux-amd64|linux-arm64) ;;
  android-arm64|android-arm|android-amd64|ios-arm64) ;;
  datapath-windows-amd64|datapath-windows-arm64|datapath-darwin-amd64|datapath-darwin-arm64) ;;
  datapath-linux-amd64|datapath-linux-arm64) ;;
  datapath-android-arm64|datapath-android-arm|datapath-android-amd64) ;;
  datapath-ios-arm64|datapath-iossimulator-arm64|datapath-iossimulator-amd64) ;;
  datapath-archive-darwin-arm64|datapath-archive-darwin-amd64) ;;
  server-linux-amd64|server-linux-arm64|carrier-linux-amd64|carrier-linux-arm64) ;;
  winn3-gateway-linux-amd64|winn3-gateway-linux-arm64) ;;
  winn3-relay-windows-amd64|winn3-relay-windows-arm64) ;;
  *) die "Unknown target '${TARGET}'." ;;
esac

if [[ -z "${WINS_WINN_SOURCE_ROOT:-}" ]]; then
  exec /usr/bin/python3 -I "${RELEASE_DRIVER}" build-one "${TARGET}" "${OUTPUT_ARG}"
fi
MODULE_DIR="${WINS_WINN_SOURCE_ROOT}"
# go build runs here. It is MODULE_DIR for every target except the Windows
# relay, which is its own module (windows/winn3_engine) replacing the Winn
# module with ../../winn_protocol_experimental.
BUILD_DIR="${MODULE_DIR}"
RELAY_TREE_DIGEST=""

# ---------------------------------------------------------------------------
# OUTPUT PATH RESOLUTION -- the defect that shipped three stale artifacts.
#
# Every build below runs `go build -o` inside a subshell that has `cd`'d to
# ${MODULE_DIR}, while everything else runs in the CALLER's working directory.
# With OUTPUT taken verbatim from "$2", a RELATIVE path once named two
# different files: go wrote one, validation read a stale leftover at the
# other, and the script printed "Validated" over bytes it had not built
# (orphans dated 2026-08-08 15:15 under winn_protocol_experimental/tools/
# winn_conformance_build_out/). OUTPUT is therefore absolutised here, every
# build goes to a private stage directory, and the output path must not exist
# before the build: a script that validates whatever is at a path cannot tell
# a fresh artifact from a fossil.
# ---------------------------------------------------------------------------
OUTPUT_DIR_ARG="${OUTPUT_ARG%/*}"
[[ "${OUTPUT_DIR_ARG}" != "${OUTPUT_ARG}" ]] || OUTPUT_DIR_ARG="."
[[ -n "${OUTPUT_DIR_ARG}" ]] || OUTPUT_DIR_ARG="/"
OUTPUT_BASENAME="${OUTPUT_ARG##*/}"
[[ -n "${OUTPUT_BASENAME}" && "${OUTPUT_BASENAME}" != "." && "${OUTPUT_BASENAME}" != ".." ]] \
  || die "Output path must name a file."
/bin/mkdir -p "${OUTPUT_DIR_ARG}" || die "Cannot create the output directory for '${OUTPUT_ARG}'."
OUTPUT="$(cd "${OUTPUT_DIR_ARG}" && pwd -P)/${OUTPUT_BASENAME}"
OUTPUT_PARENT="${OUTPUT%/*}"
GENERATION_RECEIPT="${OUTPUT}.receipt.json"
EXPECTED_HEADER_PATH=""
[[ "${OUTPUT}" == *.a ]] && EXPECTED_HEADER_PATH="${OUTPUT%.a}.h"
for generation_path in "${OUTPUT}" "${EXPECTED_HEADER_PATH}" "${GENERATION_RECEIPT}"; do
  [[ -z "${generation_path}" || ( ! -e "${generation_path}" && ! -L "${generation_path}" ) ]] \
    || die "Output destination must be fresh and non-symbolic: ${generation_path}"
done

SAFE_TMP_ROOT="$(cd "${TMPDIR:-/tmp}" && pwd -P)" || die "Could not resolve the build temporary root."
STAGE_DIRS=()
NEW_STAGE_DIR=""
BUILT_DIGEST=""
BUILT_HEADER_DIGEST=""
INSTALLED_FILES=()
COMMITTED=0

cleanup_all() {
  local d f
  for d in ${STAGE_DIRS+"${STAGE_DIRS[@]}"}; do
    case "${d}" in
      "${OUTPUT_PARENT}"/.winn-protocol-build.*|"${OUTPUT_PARENT}"/.winn-protocol-apple-inspect.*|"${SAFE_TMP_ROOT}"/winn-protocol-gocache.*|"${SAFE_TMP_ROOT}"/winn-protocol-garblecache.*)
        [[ -d "${d}" && ! -L "${d}" ]] && { /bin/chmod -R u+w "${d}" 2>/dev/null || true; /bin/rm -rf -- "${d}"; }
        ;;
    esac
  done
  if [[ "${COMMITTED}" != 1 ]]; then
    for f in ${INSTALLED_FILES+"${INSTALLED_FILES[@]}"}; do
      [[ -f "${f}" && ! -L "${f}" ]] && /bin/rm -f -- "${f}"
    done
  fi
}
trap cleanup_all EXIT

digest_of() {
  local path="$1" digest
  [[ -f "${path}" && ! -L "${path}" && -s "${path}" ]] || return 1
  digest="$(/usr/bin/shasum -a 256 "${path}" 2>/dev/null || /usr/bin/sha256sum "${path}")" || return 1
  digest="${digest%% *}"
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${digest}"
}

realpath_of() {
  /usr/bin/python3 -I -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"
}

# Same member encoding the source and module-cache digests have always used.
# The digest is refused, not computed, for any tree that can still be written.
sealed_tree_digest() {
  /usr/bin/python3 -I "${RELEASE_DRIVER}" digest --kind sealed "$1"
}

pin_value() {
  /usr/bin/python3 -I - "${PIN_MANIFEST}" "$@" <<'WINS_PIN_EOF'
import json
import sys

path, *keys = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    value = json.load(handle)["tools"]
for key in keys:
    value = value[key] if isinstance(value, dict) else None
if not isinstance(value, str) or not value or "\n" in value:
    raise SystemExit(f"toolchain pin {'.'.join(keys)} is missing; refusing an unpinned toolchain")
print(value)
WINS_PIN_EOF
}

# ---------------------------------------------------------------------------
# Sealed inputs. Each digest is measured here and again after the compile.
# ---------------------------------------------------------------------------
verify_sealed_inputs() {
  local resolved
  [[ "${MODULE_DIR}" == /* && -d "${MODULE_DIR}" && ! -L "${MODULE_DIR}" ]] \
    || die "WINS_WINN_SOURCE_ROOT must be an absolute directory."
  resolved="$(cd "${MODULE_DIR}" && pwd -P)"
  [[ "${resolved}" == "${MODULE_DIR}" ]] || die "WINS_WINN_SOURCE_ROOT must already be canonical."
  [[ -f "${MODULE_DIR}/go.mod" && ! -L "${MODULE_DIR}/go.mod" && -f "${MODULE_DIR}/go.sum" && ! -L "${MODULE_DIR}/go.sum" ]] \
    || die "Sealed Winn source has no regular go.mod and go.sum."
  [[ "${WINS_WINN_SOURCE_TREE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
    || die "WINS_WINN_SOURCE_TREE_SHA256 must name the sealed source digest."
  SOURCE_TREE_DIGEST="$(sealed_tree_digest "${MODULE_DIR}")" \
    || die "Winn source is not a sealed (non-writable, regular-file) tree."
  [[ "${SOURCE_TREE_DIGEST}" == "${WINS_WINN_SOURCE_TREE_SHA256}" ]] \
    || die "Winn source tree ${SOURCE_TREE_DIGEST} does not match the sealed snapshot ${WINS_WINN_SOURCE_TREE_SHA256}."

  [[ "${WINS_STORE_GOMODCACHE:-}" == /* && -d "${WINS_STORE_GOMODCACHE}" && ! -L "${WINS_STORE_GOMODCACHE}" ]] \
    || die "WINS_STORE_GOMODCACHE must name the sealed absolute module cache."
  resolved="$(cd "${WINS_STORE_GOMODCACHE}" && pwd -P)"
  [[ "${resolved}" == "${WINS_STORE_GOMODCACHE}" ]] || die "WINS_STORE_GOMODCACHE must already be canonical."
  [[ "${WINS_STORE_GOMODCACHE_TREE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
    || die "WINS_STORE_GOMODCACHE_TREE_SHA256 must name the sealed module-cache digest."
  MODULE_CACHE_TREE_DIGEST="$(sealed_tree_digest "${WINS_STORE_GOMODCACHE}")" \
    || die "Go module cache is not a sealed (non-writable, regular-file) tree."
  [[ "${MODULE_CACHE_TREE_DIGEST}" == "${WINS_STORE_GOMODCACHE_TREE_SHA256}" ]] \
    || die "Go module cache ${MODULE_CACHE_TREE_DIGEST} does not match the sealed cache ${WINS_STORE_GOMODCACHE_TREE_SHA256}."
}

# The relay module must be sealed too, and its replace directive must land on
# exactly the sealed Winn module this invocation verified, not on some other
# copy of it.
verify_relay_inputs() {
  local resolved replaced
  [[ "${WINS_WINN_RELAY_SOURCE_ROOT:-}" == /* && -d "${WINS_WINN_RELAY_SOURCE_ROOT}" && ! -L "${WINS_WINN_RELAY_SOURCE_ROOT}" ]] \
    || die "WINS_WINN_RELAY_SOURCE_ROOT must name the sealed windows/winn3_engine snapshot for ${TARGET}."
  resolved="$(cd "${WINS_WINN_RELAY_SOURCE_ROOT}" && pwd -P)"
  [[ "${resolved}" == "${WINS_WINN_RELAY_SOURCE_ROOT}" ]] || die "WINS_WINN_RELAY_SOURCE_ROOT must already be canonical."
  [[ "${WINS_WINN_RELAY_SOURCE_TREE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
    || die "WINS_WINN_RELAY_SOURCE_TREE_SHA256 must name the sealed relay digest."
  RELAY_TREE_DIGEST="$(sealed_tree_digest "${WINS_WINN_RELAY_SOURCE_ROOT}")" \
    || die "Relay source is not a sealed (non-writable, regular-file) tree."
  [[ "${RELAY_TREE_DIGEST}" == "${WINS_WINN_RELAY_SOURCE_TREE_SHA256}" ]] \
    || die "Relay source tree ${RELAY_TREE_DIGEST} does not match the sealed snapshot."
  /usr/bin/grep -qx 'replace winsvpn.local/winnprotocol => ../../winn_protocol_experimental' \
    "${WINS_WINN_RELAY_SOURCE_ROOT}/go.mod" \
    || die "Relay go.mod does not replace the Winn module with ../../winn_protocol_experimental."
  replaced="$(cd "${WINS_WINN_RELAY_SOURCE_ROOT}/../../winn_protocol_experimental" 2>/dev/null && pwd -P)" \
    || die "The relay's replaced Winn module is missing."
  [[ "${replaced}" == "${MODULE_DIR}" ]] \
    || die "The relay's replaced Winn module ${replaced} is not the sealed source ${MODULE_DIR}."
  BUILD_DIR="${WINS_WINN_RELAY_SOURCE_ROOT}"
}

reverify_sealed_inputs() {
  local now
  if [[ -n "${RELAY_TREE_DIGEST}" ]]; then
    now="$(sealed_tree_digest "${WINS_WINN_RELAY_SOURCE_ROOT}")" || die "Relay source custody changed during the build."
    [[ "${now}" == "${RELAY_TREE_DIGEST}" ]] || die "Relay source tree mutated during the build."
  fi
  now="$(sealed_tree_digest "${MODULE_DIR}")" || die "Winn source custody changed during the build."
  [[ "${now}" == "${SOURCE_TREE_DIGEST}" ]] || die "Winn source tree mutated during the build."
  now="$(sealed_tree_digest "${WINS_STORE_GOMODCACHE}")" || die "Module cache custody changed during the build."
  [[ "${now}" == "${MODULE_CACHE_TREE_DIGEST}" ]] || die "Go module cache mutated during the build."
  now="$(digest_of "${GO_BIN}")" || die "Reviewed Go executable vanished during the build."
  [[ "${now}" == "${REVIEWED_GO_EXECUTABLE_SHA256}" ]] || die "Reviewed Go executable changed during the build."
  if [[ -n "${PLATFORM_CC_PATH}" ]]; then
    now="$(digest_of "${PLATFORM_CC_PATH}")" || die "Platform compiler vanished during the build."
    [[ "${now}" == "${PLATFORM_CC_SHA256}" ]] || die "Platform compiler changed during the build."
  fi
}

# Go comes only from WINS_RELEASE_GO_ROOT, and only if bin/go is the pinned
# executable reporting the pinned version. PATH go, GOROOT overrides, network
# toolchain switching and module downloads are all off.
select_reviewed_go() {
  local host_os host_arch identity
  REVIEWED_GO_VERSION="$(pin_value go version)" || die "Go version pin is unavailable."
  case "$(/usr/bin/uname -s)" in Darwin) host_os=darwin ;; Linux) host_os=linux ;; *) die "Unsupported build host OS." ;; esac
  case "$(/usr/bin/uname -m)" in arm64|aarch64) host_arch=arm64 ;; x86_64) host_arch=amd64 ;; *) die "Unsupported build host CPU." ;; esac
  HOST_PIN_KEY="${host_os}_${host_arch}"
  # bin/go differs per host platform. tools.go.executable_sha256 is the
  # darwin_arm64 measurement; every other host needs its own
  # executable_sha256_by_platform entry, which wins when present.
  if REVIEWED_GO_EXECUTABLE_SHA256="$(pin_value go executable_sha256_by_platform "${host_os}_${host_arch}" 2>/dev/null)"; then
    :
  elif [[ "${host_os}_${host_arch}" == darwin_arm64 ]]; then
    REVIEWED_GO_EXECUTABLE_SHA256="$(pin_value go executable_sha256)" || die "Go executable pin is unavailable."
  else
    printf 'WINN BUILD ERROR: missing pin: tools.go.executable_sha256_by_platform.%s is absent from tools/toolchain-pins.json; measure it with sha256sum go/bin/go from the pinned go%s.%s-%s.tar.gz and record it there.\n' \
      "${host_os}_${host_arch}" "${REVIEWED_GO_VERSION}" "${host_os}" "${host_arch}" >&2
    exit 65
  fi
  [[ "${REVIEWED_GO_EXECUTABLE_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "Go executable pin for ${host_os}_${host_arch} is not a lowercase SHA-256."
  [[ "${WINS_RELEASE_GO_ROOT:-}" == /* && -d "${WINS_RELEASE_GO_ROOT}" && ! -L "${WINS_RELEASE_GO_ROOT}" ]] \
    || die "WINS_RELEASE_GO_ROOT must name the extracted pinned Go ${REVIEWED_GO_VERSION} root."
  GO_BIN="${WINS_RELEASE_GO_ROOT}/bin/go"
  [[ -f "${GO_BIN}" && -x "${GO_BIN}" && ! -L "${GO_BIN}" ]] || die "No regular executable bin/go under WINS_RELEASE_GO_ROOT."
  [[ "$(digest_of "${GO_BIN}")" == "${REVIEWED_GO_EXECUTABLE_SHA256}" ]] \
    || die "bin/go under WINS_RELEASE_GO_ROOT is not the pinned Go ${REVIEWED_GO_VERSION} executable."

  # tools/winn_release.py gives every build of one variant (A or B) the same
  # private cache, so the standard library is compiled once per platform and
  # variant. A and B never share a cache, so the two-build comparison still
  # sets two independently compiled outputs against each other.
  if [[ -n "${WINS_WINN_VARIANT_GOCACHE:-}" ]]; then
    [[ "${WINS_WINN_VARIANT_GOCACHE}" == /* && -d "${WINS_WINN_VARIANT_GOCACHE}" \
      && ! -L "${WINS_WINN_VARIANT_GOCACHE}" && -O "${WINS_WINN_VARIANT_GOCACHE}" ]] \
      || die "WINS_WINN_VARIANT_GOCACHE must be an absolute directory owned by this user."
    WINS_STORE_GOCACHE="${WINS_WINN_VARIANT_GOCACHE}"
    GO_CACHE_VERIFY=0
  else
    WINS_STORE_GOCACHE="$(/usr/bin/mktemp -d "${SAFE_TMP_ROOT}/winn-protocol-gocache.XXXXXXXX")" \
      || die "Could not create an isolated empty Go build cache."
    STAGE_DIRS+=("${WINS_STORE_GOCACHE}")
    /bin/chmod 0700 "${WINS_STORE_GOCACHE}"
    GO_CACHE_VERIFY=1
  fi

  export GO111MODULE=on GOENV=off GOFLAGS="-mod=readonly" GOPROXY=off GOSUMDB=off GOWORK=off
  export GOTOOLCHAIN=local GOTELEMETRY=off GOPRIVATE="" GONOPROXY="" GONOSUMDB=""
  export GOMODCACHE="${WINS_STORE_GOMODCACHE}" GOCACHE="${WINS_STORE_GOCACHE}"
  export GODEBUG="gocacheverify=${GO_CACHE_VERIFY}"
  # Apple's ranlib stamps the c-archive symbol table member (__.SYMDEF) with
  # the current time unless ZERO_AR_DATE is set. Measured on 2026-10-09: two
  # otherwise identical datapath-archive-darwin-amd64 builds that crossed a
  # second boundary differed only there, and the two-build gate refused them.
  export ZERO_AR_DATE=1
  unset GOAUTH GOBIN GOCACHEPROG GOEXPERIMENT GOFIPS140 GOTOOLDIR GOROOT GOPATH
  unset GO386 GOAMD64 GOARM GOARM64 GOMIPS GOMIPS64 GOPPC64 GORISCV64 GOWASM
  unset CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_FFLAGS CGO_LDFLAGS
  unset CGO_CFLAGS_ALLOW CGO_CFLAGS_DISALLOW CGO_LDFLAGS_ALLOW CGO_LDFLAGS_DISALLOW

  identity="$("${GO_BIN}" version)" || die "Reviewed Go could not report its version."
  [[ "${identity}" == "go version go${REVIEWED_GO_VERSION} ${host_os}/${host_arch}" ]] \
    || die "Reviewed Go identity mismatch: ${identity}"
}

# ---------------------------------------------------------------------------
# Website-engine obfuscation (owner ruling 2026-10-27).
#
# WINS_WINN_OBFUSCATION=garble builds the client engines that ship only from
# winsvpn.org with garble: every identifier and file path is hashed, string
# literals are encrypted (-literals) and position and panic metadata are
# removed (-tiny). Plain go build stays the default, and store, Apple and
# server targets refuse obfuscation. garble also removes the embedded Go
# build info, so the identity check for these outputs is the forbidden-name
# scan and machine check in verify_staged_obfuscated_executable.
#
# The seed is a private owner secret. It is read from an owner-only file,
# handed only to garble, and recorded only as its SHA-256 commitment. Two
# builds with the same seed are byte-identical, which keeps the two-build
# gate in tools/winn_release.py meaningful.
# ---------------------------------------------------------------------------
OBFUSCATION=""
GARBLE_BIN=""
GARBLE_VERSION=""
GARBLE_EXECUTABLE_SHA256=""
GARBLE_SEED=""
GARBLE_SEED_SHA256=""
GARBLE_CACHE_DIR=""
GARBLE_FLAGS=(-literals -tiny)
V3_PACKAGES_LINKED=""

select_obfuscation() {
  local identity seed_file
  case "${WINS_WINN_OBFUSCATION:-}" in
    "") return 0 ;;
    garble) ;;
    *) die "Unknown WINS_WINN_OBFUSCATION '${WINS_WINN_OBFUSCATION}'; only garble is reviewed." ;;
  esac
  case "${TARGET}" in
    datapath-android-*|datapath-linux-*|datapath-windows-*|winn3-relay-windows-*) ;;
    *) die "Obfuscation is limited to the website client engines; ${TARGET} builds plain." ;;
  esac
  GARBLE_VERSION="$(PIN_MANIFEST="${GARBLE_PIN_MANIFEST}" pin_value garble version)" || die "garble version pin is unavailable."
  GARBLE_EXECUTABLE_SHA256="$(PIN_MANIFEST="${GARBLE_PIN_MANIFEST}" pin_value garble executable_sha256_by_platform "${HOST_PIN_KEY}")" \
    || die "garble has no executable pin for ${HOST_PIN_KEY}."
  [[ "${GARBLE_EXECUTABLE_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "garble executable pin is not a lowercase SHA-256."
  GARBLE_BIN="${WINS_GARBLE_BIN:-}"
  [[ "${GARBLE_BIN}" == /* && -f "${GARBLE_BIN}" && -x "${GARBLE_BIN}" && ! -L "${GARBLE_BIN}" ]] \
    || die "WINS_GARBLE_BIN must name the pinned garble ${GARBLE_VERSION} executable."
  [[ "$(digest_of "${GARBLE_BIN}")" == "${GARBLE_EXECUTABLE_SHA256}" ]] \
    || die "WINS_GARBLE_BIN is not the pinned garble ${GARBLE_VERSION} executable."
  identity="$("${GARBLE_BIN}" version 2>/dev/null | /usr/bin/head -n 1)" || die "garble could not report its version."
  [[ "${identity}" == "mvdan.cc/garble ${GARBLE_VERSION}" ]] || die "garble identity mismatch: ${identity}"

  seed_file="${WINS_GARBLE_SEED_FILE:-}"
  # The seed never reaches stdout, stderr, the receipt or the log.
  GARBLE_SEED="$(/usr/bin/python3 -I - "${seed_file}" <<'WINS_SEED_EOF'
import os
import re
import stat
import sys

path = sys.argv[1]
if not path.startswith("/"):
    raise SystemExit("WINS_GARBLE_SEED_FILE must be an absolute path")
# One descriptor, opened without following a final link, is both checked and read.
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit("WINS_GARBLE_SEED_FILE must be a regular single-link file")
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise SystemExit("WINS_GARBLE_SEED_FILE must be owner-only")
    seed = os.read(fd, 256)
finally:
    os.close(fd)
# garble v0.18.0 uses exactly the first 8 bytes of -seed (64 bits) and warns
# about any more, so the seed is exactly 8 bytes: 11 unpadded base64 chars.
if re.fullmatch(rb"[A-Za-z0-9+/]{10}[AEIMQUYcgkosw048]", seed) is None:
    raise SystemExit("WINS_GARBLE_SEED_FILE must hold one unpadded base64 8-byte seed")
sys.stdout.write(seed.decode("ascii"))
WINS_SEED_EOF
)" || die "The garble seed file was refused."
  GARBLE_SEED_SHA256="$(printf '%s' "${GARBLE_SEED}" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')" \
    || die "Could not commit to the garble seed."
  [[ "${GARBLE_SEED_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "garble seed commitment is malformed."

  if [[ -n "${WINS_WINN_VARIANT_GARBLE_CACHE:-}" ]]; then
    [[ "${WINS_WINN_VARIANT_GARBLE_CACHE}" == /* && -d "${WINS_WINN_VARIANT_GARBLE_CACHE}" \
      && ! -L "${WINS_WINN_VARIANT_GARBLE_CACHE}" && -O "${WINS_WINN_VARIANT_GARBLE_CACHE}" ]] \
      || die "WINS_WINN_VARIANT_GARBLE_CACHE must be an absolute directory owned by this user."
    GARBLE_CACHE_DIR="${WINS_WINN_VARIANT_GARBLE_CACHE}"
  else
    GARBLE_CACHE_DIR="$(/usr/bin/mktemp -d "${SAFE_TMP_ROOT}/winn-protocol-garblecache.XXXXXXXX")" \
      || die "Could not create an isolated garble cache."
    STAGE_DIRS+=("${GARBLE_CACHE_DIR}")
    /bin/chmod 0700 "${GARBLE_CACHE_DIR}"
  fi
  OBFUSCATION=garble
}

# garble removes the embedded build info, so GOOS/GOARCH cannot be read back
# from it. Check the machine in the file header instead, require garble's
# "unknown" build-info marker, and refuse any surviving source module path.
verify_staged_obfuscated_executable() {
  local staged="$1" reported
  reported="$("${GO_BIN}" version "${staged}" 2>&1)" || true
  [[ "${reported}" == "${staged}: unknown" ]] \
    || die "Obfuscated output still carries readable Go build info: ${reported##*: }"
  /usr/bin/python3 -I - "${staged}" "${TARGET_GOOS}" "${TARGET_GOARCH}" <<'WINS_OBFUSCATED_EOF' \
    || die "Obfuscated output ${staged} failed its identity scan."
import struct
import sys

path, goos, goarch = sys.argv[1:]
with open(path, "rb") as handle:
    blob = handle.read()
for marker in (b"winsvpn.local/", b"winn_protocol_experimental", b"winn3_engine/",
               b"/Users/", b"/home/", b"\tpath\t"):
    if marker in blob:
        raise SystemExit(f"obfuscated output still names {marker.decode('latin1')!r}")
if goos == "windows":
    if blob[:2] != b"MZ":
        raise SystemExit("obfuscated Windows output is not a PE image")
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[pe:pe + 4] != b"PE\0\0":
        raise SystemExit("obfuscated Windows output has no PE header")
    machine = struct.unpack_from("<H", blob, pe + 4)[0]
    expected = {"amd64": 0x8664, "arm64": 0xAA64}[goarch]
else:
    if blob[:4] != b"\x7fELF":
        raise SystemExit("obfuscated output is not an ELF image")
    machine = struct.unpack_from("<H", blob, 18)[0]
    expected = {"amd64": 0x3E, "arm64": 0xB7, "arm": 0x28}[goarch]
if machine != expected:
    raise SystemExit(f"obfuscated output machine 0x{machine:x} is not {goos}/{goarch}")
WINS_OBFUSCATED_EOF
  # The bytes can no longer show which packages they link, so for a datapath
  # the sealed source proves it: the package built here must link all five
  # winn3 packages for this target. The receipt records the result and the
  # signed manifest carries it to the Android gate.
  V3_PACKAGES_LINKED=""
  if [[ "${ARTIFACT_ROLE}" == datapath ]]; then
    local deps package
    deps="$(cd "${BUILD_DIR}" && "${GO_BIN}" list -deps "${PACKAGE}")" \
      || die "go list -deps failed for ${TARGET}."
    for package in core session carrier tun driver; do
      /usr/bin/grep -qx "winsvpn.local/winnprotocol/winn3/${package}" <<<"${deps}" \
        || die "${TARGET} does not link winsvpn.local/winnprotocol/winn3/${package}."
    done
    V3_PACKAGES_LINKED=1
  fi
}

# ---------------------------------------------------------------------------
# External platform toolchains (only cgo targets need one).
# ---------------------------------------------------------------------------
PLATFORM_CC=""
PLATFORM_CC_PATH=""
PLATFORM_CC_SHA256=""
PLATFORM_NDK_VERSION=""
PLATFORM_SDK=""
PLATFORM_SDK_VERSION=""

resolve_ndk_clang() {
  local arch="$1" triple ndk_home candidate canonical prebuilt
  case "${arch}" in
    arm64) triple="aarch64-linux-android" ;;
    arm) triple="armv7a-linux-androideabi" ;;
    amd64) triple="x86_64-linux-android" ;;
    *) die "Unsupported Android architecture '${arch}'." ;;
  esac
  ndk_home="${WINS_ANDROID_NDK_ROOT}"
  for prebuilt in darwin-x86_64 linux-x86_64; do
    candidate="${ndk_home}/toolchains/llvm/prebuilt/${prebuilt}/bin/${triple}${NDK_CLANG_API_LEVEL}-clang"
    if [[ -x "${candidate}" ]]; then
      canonical="$(realpath_of "${candidate}")" || die "Android clang could not be canonicalized."
      case "${canonical}" in "${ndk_home}"/*) ;; *) die "Android clang escaped the pinned NDK." ;; esac
      [[ -f "${canonical}" && -x "${canonical}" && ! -L "${canonical}" ]] || die "Android clang leaf is unavailable."
      PLATFORM_CC_PATH="${canonical}"
      PLATFORM_CC_SHA256="$(digest_of "${canonical}")" || die "Android clang could not be hashed."
      PLATFORM_CC="${canonical}"
      return 0
    fi
  done
  die "No ${triple}${NDK_CLANG_API_LEVEL}-clang found under ${ndk_home}/toolchains/llvm/prebuilt/{darwin,linux}-x86_64/bin."
}

prepare_target_platform() {
  local root resolved revision pinned sdk tool_root tool
  case "${TARGET}" in
    android-*|datapath-android-*)
      root="${WINS_ANDROID_NDK_ROOT:-}"
      [[ "${root}" == /* && -d "${root}" && ! -L "${root}" ]] \
        || die "Android NDK not found: set WINS_ANDROID_NDK_ROOT to the pinned NDK for ${TARGET}."
      resolved="$(cd "${root}" && pwd -P)"
      [[ "${resolved}" == "${root}" ]] || die "WINS_ANDROID_NDK_ROOT must already be canonical."
      pinned="$(pin_value android_ndk version)" || die "Android NDK version pin is unavailable."
      revision="$(/usr/bin/sed -n 's/^Pkg\.Revision[[:space:]]*=[[:space:]]*//p' "${root}/source.properties" 2>/dev/null || true)"
      revision="${revision%%$'\n'*}"
      [[ "${revision}" == "${pinned}" ]] || die "Android NDK is ${revision:-unknown}; the pin is ${pinned}."
      if [[ -n "${WINS_ANDROID_NDK_TREE_SHA256:-}" ]]; then
        [[ "$(/usr/bin/python3 -I "${RELEASE_DRIVER}" digest --kind platform "${root}")" == "${WINS_ANDROID_NDK_TREE_SHA256}" ]] \
          || die "Android NDK tree does not match WINS_ANDROID_NDK_TREE_SHA256."
      fi
      PLATFORM_NDK_VERSION="${revision}"
      case "${TARGET}" in
        *-arm64) resolve_ndk_clang arm64 ;;
        *-amd64) resolve_ndk_clang amd64 ;;
        *-arm) resolve_ndk_clang arm ;;
      esac
      ;;
    ios-arm64|datapath-ios-arm64|datapath-iossimulator-*|datapath-archive-darwin-*)
      root="${WINS_APPLE_DEVELOPER_DIR:-$(/usr/bin/xcode-select -p 2>/dev/null || true)}"
      [[ "${root}" == /* && -d "${root}" ]] || die "Xcode developer directory not found for ${TARGET}."
      root="$(realpath_of "${root}")"
      export DEVELOPER_DIR="${root}"
      case "${TARGET}" in
        ios-arm64|datapath-ios-arm64) sdk=iphoneos ;;
        datapath-iossimulator-*) sdk=iphonesimulator ;;
        *) sdk=macosx ;;
      esac
      PLATFORM_SDK="$(/usr/bin/xcrun --sdk "${sdk}" --show-sdk-path)" || die "Apple ${sdk} SDK is unavailable."
      PLATFORM_SDK_VERSION="$(/usr/bin/xcrun --sdk "${sdk}" --show-sdk-version)" || die "Apple ${sdk} SDK version is unavailable."
      PLATFORM_CC="$(/usr/bin/xcrun --sdk "${sdk}" -f clang)" || die "Apple clang is unavailable."
      PLATFORM_CC="$(realpath_of "${PLATFORM_CC}")"
      case "${PLATFORM_SDK}" in "${root}"/*) ;; *) die "Apple SDK escaped the selected Xcode." ;; esac
      case "${PLATFORM_CC}" in "${root}"/*) ;; *) die "Apple clang escaped the selected Xcode." ;; esac
      [[ -f "${PLATFORM_CC}" && -x "${PLATFORM_CC}" && ! -L "${PLATFORM_CC}" ]] || die "Apple clang leaf is unavailable."
      PLATFORM_CC_PATH="${PLATFORM_CC}"
      PLATFORM_CC_SHA256="$(digest_of "${PLATFORM_CC}")" || die "Apple clang could not be hashed."
      tool_root="${root}/Toolchains/XcodeDefault.xctoolchain/usr/bin"
      APPLE_LIPO="$(realpath_of "${tool_root}/lipo")"
      APPLE_NM="$(realpath_of "${tool_root}/nm")"
      APPLE_AR="$(realpath_of "${tool_root}/ar")"
      APPLE_VTOOL="$(realpath_of "${tool_root}/vtool")"
      for tool in "${APPLE_LIPO}" "${APPLE_NM}" "${APPLE_AR}" "${APPLE_VTOOL}"; do
        case "${tool}" in "${root}"/*) ;; *) die "Apple tool escaped the selected Xcode: ${tool}" ;; esac
        [[ -f "${tool}" && -x "${tool}" && ! -L "${tool}" ]] || die "Apple tool is unavailable: ${tool}"
      done
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Target selection. PACKAGE is the Go package the current target builds.
#
# The default is the executable one, because eight of the nine original targets
# are executables. That default is WRONG for every c-archive target, and an
# earlier revision of this script let ios-arm64 inherit it: it built a
# c-archive out of ./cmd/winn-clientinfo, a main package that exports none of
# the symbols the archive gate then looks for. ARCHIVE_MODE exists so that
# mistake cannot recur silently.
# ---------------------------------------------------------------------------
PACKAGE="./cmd/winn-clientinfo"
ARTIFACT_LABEL="client binding"
ARTIFACT_ROLE="clientinfo"
ARCHIVE_MODE=0
ARCHIVE_SYMBOLS=""
EXPECTED_MAIN_PATH=""
TARGET_GOOS=""
TARGET_GOARCH=""
TARGET_CGO_ENABLED=""
TARGET_PLATFORM_ID=""

select_clientinfo_archive() {
  PACKAGE="./cshared"
  ARTIFACT_LABEL="client binding (c-archive)"
  ARTIFACT_ROLE="clientinfo"
  ARCHIVE_MODE=1
  ARCHIVE_SYMBOLS="_WinnFacadeVersion _WinnProtocolVersion _WinnTunnelSupported _WinnTunnelBackendJSON _WinnFreeString"
}

select_datapath_engine() {
  PACKAGE="./cmd/winn-datapath"
  ARTIFACT_LABEL="datapath engine (framed duplex subprocess)"
  ARTIFACT_ROLE="datapath"
}

# _WinnTunnelCreateWinn3 is listed beside the relay's _WinnTunnelCreate because
# the two datapaths ship in ONE archive and the appex resolves both by name at
# run time. An archive that silently lost the winn/3 entry point would
# otherwise pass here and fail at dlsym on the device.
select_datapath_archive() {
  PACKAGE="./cdatapath"
  ARTIFACT_LABEL="datapath engine (c-archive)"
  ARTIFACT_ROLE="datapath"
  ARCHIVE_MODE=1
  ARCHIVE_SYMBOLS="_WinnTunnelContractVersion _WinnTunnelProtocolVersion _WinnTunnelMaxDatagram _WinnTunnelCreate _WinnTunnelCreateWinn3 _WinnTunnelWriteInbound _WinnTunnelReadOutbound _WinnTunnelStatusJSON _WinnTunnelClose _WinnTunnelFreeString _WinsWinn3EnqueuePackets _WinsWinn3DequeuePackets"
}

select_server_engine() {
  PACKAGE="./cmd/winn-server"
  ARTIFACT_LABEL="protocol server (control-plane PQ AWG key controller)"
  ARTIFACT_ROLE="control-plane-server"
}

select_carrier_engine() {
  PACKAGE="./cmd/winn-carrier-server"
  ARTIFACT_LABEL="carrier server (data-plane obfuscated transport)"
  ARTIFACT_ROLE="v1-carrier-server"
}

# select_winn3_relay_engine switches this invocation to windows/winn3_engine,
# the Wintun inner-packet relay (winsvpn_winn3_engine.exe) that
# windows/runner/winn3_supervisor.cpp starts. It carries no Winn crypto in its
# default mode; tools/build_windows_winn3_relay.sh explains the boundary.
select_winn3_relay_engine() {
  PACKAGE="."
  EXPECTED_MAIN_PATH="winsvpn.local/winsvpnwinn3engine"
  ARTIFACT_LABEL="winn3 Windows relay (Wintun inner-packet relay)"
  ARTIFACT_ROLE="winn3-relay"
  verify_relay_inputs
}

select_winn3_gateway_engine() {
  PACKAGE="./cmd/winn3-gateway"
  ARTIFACT_LABEL="winn3 gateway (reachable multi-session v3 responder)"
  ARTIFACT_ROLE="winn3-gateway"
}

require_archive_selection() {
  [[ "${ARCHIVE_MODE}" == "1" && -n "${ARCHIVE_SYMBOLS}" ]] \
    || die "Internal error: target '${TARGET}' asked for a c-archive without selecting an archive package."
  [[ "${OUTPUT}" == *.a ]] \
    || die "Archive target '${TARGET}' requires an output path ending in .a; refusing artifact relabel."
}

# ---------------------------------------------------------------------------
# Building. Every build goes to a private stage directory beside OUTPUT and is
# gated there; only then is it linked into place (no-clobber), so a failed
# build can never be mistaken for a successful one.
# ---------------------------------------------------------------------------
go_header_for() {
  local path="$1"
  printf '%s.h\n' "${path%.*}"
}

new_stage_dir() {
  NEW_STAGE_DIR="$(/usr/bin/mktemp -d "${OUTPUT_PARENT}/.winn-protocol-build.XXXXXX")" \
    || die "Could not create a private stage directory beside ${OUTPUT}."
  STAGE_DIRS+=("${NEW_STAGE_DIR}")
}

configure_target_go_environment() {
  local goos="$1" goarch="$2" cgo_enabled="$3" cc="${4:-}"
  export GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED="${cgo_enabled}"
  unset GO386 GOAMD64 GOARM GOARM64 GOMIPS GOMIPS64 GOPPC64 GORISCV64 GOWASM
  unset CC CXX FC PKG_CONFIG
  case "${goarch}" in
    amd64) export GOAMD64=v1 ;;
    arm64) export GOARM64=v8.0 ;;
    arm) export GOARM=7 ;;
    *) die "Internal error: unsupported Go architecture ${goarch}." ;;
  esac
  if [[ "${cgo_enabled}" == "1" ]]; then
    [[ -n "${cc}" ]] || die "Internal error: CGO target ${goos}/${goarch} has no compiler."
    export CC="${cc}"
  fi
}

verify_staged_executable_identity() {
  local staged="$1" metadata="${staged}.buildinfo.json" expected_path
  if [[ -n "${OBFUSCATION}" ]]; then
    verify_staged_obfuscated_executable "${staged}"
    return
  fi
  expected_path="${EXPECTED_MAIN_PATH:-winsvpn.local/winnprotocol/${PACKAGE#./}}"
  "${GO_BIN}" version -m -json "${staged}" >"${metadata}" \
    || die "Could not inspect embedded Go identity in staged output ${staged}."
  /usr/bin/python3 -I - "${metadata}" "${REVIEWED_GO_VERSION}" "${expected_path}" \
    "${TARGET_GOOS}" "${TARGET_GOARCH}" "${TARGET_CGO_ENABLED}" <<'WINS_BUILDINFO_EOF'
import json
import sys

path, version, expected_path, goos, goarch, cgo = sys.argv[1:]

def reject(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate build-info key {key!r}")
        result[key] = value
    return result

with open(path, encoding="utf-8") as source:
    document = json.load(source, object_pairs_hook=reject)
if not isinstance(document, dict):
    raise SystemExit("embedded Go build info is not an object")
if document.get("GoVersion") != f"go{version}":
    raise SystemExit("embedded Go version does not match reviewed Go")
if document.get("Path") != expected_path:
    raise SystemExit("embedded main package does not match selected artifact role")
observed = {}
for item in document.get("Settings") or []:
    if not isinstance(item, dict) or set(item) != {"Key", "Value"} or item["Key"] in observed:
        raise SystemExit("embedded Go build settings are malformed")
    observed[item["Key"]] = item["Value"]
required = {"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": cgo, "-trimpath": "true"}
feature = {"amd64": ("GOAMD64", "v1"), "arm64": ("GOARM64", "v8.0"), "arm": ("GOARM", "7")}[goarch]
required[feature[0]] = feature[1]
wrong = {key: (value, observed.get(key)) for key, value in required.items() if observed.get(key) != value}
if wrong:
    raise SystemExit(f"embedded Go build settings do not match target: {wrong}")
WINS_BUILDINFO_EOF
  /bin/rm -f -- "${metadata}"
}

link_into_place() {
  local source="$1" destination="$2"
  /usr/bin/python3 -I - "${source}" "${destination}" <<'WINS_INSTALL_EOF'
import os
import stat
import sys

source, destination = sys.argv[1:]
info = os.lstat(source)
if not stat.S_ISREG(info.st_mode):
    raise SystemExit("staged output is not one regular file")
os.link(source, destination, follow_symlinks=False)  # fails if destination exists
os.unlink(source)
fd = os.open(destination, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    os.fsync(fd)
finally:
    os.close(fd)
WINS_INSTALL_EOF
  INSTALLED_FILES+=("${destination}")
}

install_staged_output() {
  local staged="$1" staged_header staged_digest
  [[ -s "${staged}" ]] \
    || die "Build produced no output. Expected ${staged##*/} from 'go build -o'; NOTHING at ${OUTPUT} was touched."
  staged_digest="$(digest_of "${staged}")" || die "Hash command failed for staged output ${staged}."
  staged_header="$(go_header_for "${staged}")"
  if [[ "${ARCHIVE_MODE}" == "1" ]]; then
    [[ -s "${staged_header}" ]] || die "c-archive build emitted no generated header."
    BUILT_HEADER_DIGEST="$(digest_of "${staged_header}")" || die "Hash command failed for generated header."
    link_into_place "${staged_header}" "${EXPECTED_HEADER_PATH}"
  fi
  link_into_place "${staged}" "${OUTPUT}"
  BUILT_DIGEST="$(digest_of "${OUTPUT}")" || die "Hash command failed for installed output ${OUTPUT}."
  [[ "${BUILT_DIGEST}" == "${staged_digest}" ]] \
    || die "The artifact at ${OUTPUT} does not match the bytes just built. Something else wrote to that path."
}

# A path is not an identity: before the success line, the file at OUTPUT must
# still hash to the bytes this invocation's go build produced.
require_output_is_our_own_build() {
  [[ -n "${BUILT_DIGEST}" ]] \
    || die "Refusing to validate ${OUTPUT}: no build in this invocation produced it."
  [[ "$(digest_of "${OUTPUT}")" == "${BUILT_DIGEST}" ]] \
    || die "The artifact at ${OUTPUT} changed after it was built."
  if [[ -n "${BUILT_HEADER_DIGEST}" ]]; then
    [[ "$(digest_of "${EXPECTED_HEADER_PATH}")" == "${BUILT_HEADER_DIGEST}" ]] \
      || die "The generated header at ${EXPECTED_HEADER_PATH} changed after it was built."
  fi
}

run_go_build() {
  local staged="$1"
  shift
  # The subshell is the left operand of ||, so errexit does not apply inside
  # it: every step carries its own refusal.
  (
    cd "${BUILD_DIR}" || die "Cannot enter build directory for ${TARGET}."
    "${GO_BIN}" mod verify >/dev/null \
      || die "go mod verify failed for ${TARGET}."
    if [[ -n "${OBFUSCATION}" ]]; then
      # garble runs the go on PATH, so the reviewed Go goes first.
      PATH="${GO_BIN%/*}:${PATH}" GARBLE_CACHE="${GARBLE_CACHE_DIR}" \
        "${GARBLE_BIN}" "${GARBLE_FLAGS[@]}" "-seed=${GARBLE_SEED}" \
        build -mod=readonly -pgo=off -trimpath -buildvcs=false "$@" -o "${staged}" "${PACKAGE}"
    else
      "${GO_BIN}" build -mod=readonly -pgo=off -trimpath -buildvcs=false "$@" -o "${staged}" "${PACKAGE}"
    fi
  ) || die "go build failed for ${TARGET}."
}

build_executable() {
  local goos="$1" goarch="$2" cc="${3:-}" staged
  TARGET_GOOS="${goos}"
  TARGET_GOARCH="${goarch}"
  TARGET_CGO_ENABLED=0
  [[ -n "${cc}" ]] && TARGET_CGO_ENABLED=1
  TARGET_PLATFORM_ID="${goos}"
  [[ "${goos}" == android ]] && TARGET_PLATFORM_ID="android-api-${NDK_CLANG_API_LEVEL}"
  new_stage_dir
  staged="${NEW_STAGE_DIR}/${OUTPUT##*/}"
  configure_target_go_environment "${goos}" "${goarch}" "${TARGET_CGO_ENABLED}" "${cc}"
  run_go_build "${staged}" -ldflags='-s -w -buildid='
  verify_staged_executable_identity "${staged}"
  install_staged_output "${staged}"
}

build_apple_archive() {
  local goos="$1" goarch="$2" platform_id="$3" triple="$4" min_flag="$5" want_arch="$6" want_platform="$7"
  local flags staged
  require_archive_selection
  TARGET_GOOS="${goos}"
  TARGET_GOARCH="${goarch}"
  TARGET_CGO_ENABLED=1
  TARGET_PLATFORM_ID="${platform_id}"
  flags="-target ${triple} -isysroot ${PLATFORM_SDK}${min_flag:+ ${min_flag}}"
  new_stage_dir
  staged="${NEW_STAGE_DIR}/${OUTPUT##*/}"
  configure_target_go_environment "${goos}" "${goarch}" 1 "${PLATFORM_CC} ${flags}"
  export CGO_CFLAGS="${flags}"
  run_go_build "${staged}" -buildmode=c-archive
  unset CGO_CFLAGS
  validate_apple_archive "${staged}" "${want_arch}" "${want_platform}"
  install_staged_output "${staged}"
}

# The same gates tools/build_apple_wg_go_bridge.sh applies to libwg-go.a: one
# exact slice of the requested architecture, built for the requested Mach-O
# platform (device, simulator or macOS), exporting the C ABI a wrapper calls,
# with a generated header declaring that ABI with the reviewed C types.
validate_apple_archive() {
  local archive="$1" want_arch="$2" want_platform="$3" header kind archs platform missing symbols symbol tmp
  header="$(go_header_for "${archive}")"
  [[ -s "${archive}" && -s "${header}" ]] || die "Apple c-archive or its generated header is missing in the stage."
  kind="$(/usr/bin/file -b "${archive}")" || die "Could not inspect ${archive}."
  [[ "${kind}" == *"ar archive"* ]] || die "Staged Apple output is not an ar archive: ${kind}."
  archs="$("${APPLE_LIPO}" -archs "${archive}")" || die "lipo could not read ${archive}."
  [[ "${archs}" == "${want_arch}" ]] || die "Expected one exact ${want_arch} slice, found '${archs}'."
  tmp="$(/usr/bin/mktemp -d "${OUTPUT_PARENT}/.winn-protocol-apple-inspect.XXXXXX")" || die "Could not create an inspection directory."
  STAGE_DIRS+=("${tmp}")
  ( cd "${tmp}" && "${APPLE_AR}" -x "${archive}" go.o ) || die "Could not extract go.o from ${archive}."
  platform="$("${APPLE_VTOOL}" -show-build "${tmp}/go.o" 2>/dev/null | /usr/bin/awk '$1 == "platform" { print $2 }')"
  [[ "${platform}" == "${want_platform}" ]] || die "Expected Mach-O platform ${want_platform}, found '${platform}'."
  symbols="$("${APPLE_NM}" -gU "${archive}" 2>/dev/null | /usr/bin/awk '{print $NF}')" || die "nm could not read ${archive}."
  missing=""
  for symbol in ${ARCHIVE_SYMBOLS}; do
    # A pattern match, not `printf | grep -q`: under pipefail, grep -q exiting
    # at the first match can SIGPIPE printf and turn a present symbol into a
    # "missing" one (seen on 2026-10-09 under load).
    [[ $'\n'"${symbols}"$'\n' == *$'\n'"${symbol}"$'\n'* ]] || missing="${missing} ${symbol}"
  done
  [[ -z "${missing}" ]] || die "Missing exported symbols in ${archive}:${missing}"
  validate_generated_header_semantics "${header}" "${ARTIFACT_ROLE}" \
    || die "Generated archive header failed semantic validation."
  printf 'Validated Apple c-archive: %s (%s, %s, package %s, C ABI present)\n' \
    "${OUTPUT}" "${want_arch}" "${want_platform}" "${PACKAGE}" >&2
}

validate_generated_header_semantics() {
  /usr/bin/python3 -I - "$1" "$2" <<'WINS_HEADER_SEMANTICS_EOF'
import re
import sys

path, role = sys.argv[1:]
with open(path, "rb") as handle:
    payload = handle.read(1024 * 1024 + 1)
if not payload or len(payload) > 1024 * 1024:
    raise SystemExit("generated header size is invalid")
text = payload.decode("ascii", errors="strict")
if "\x00" in text or "#ifndef" not in text or "#define" not in text:
    raise SystemExit("generated header guard is absent or malformed")
signatures = {
    "clientinfo": {
        "WinnFacadeVersion": r"char\s*\*\s*WinnFacadeVersion\s*\(\s*void\s*\)",
        "WinnProtocolVersion": r"char\s*\*\s*WinnProtocolVersion\s*\(\s*void\s*\)",
        "WinnTunnelBackendJSON": r"char\s*\*\s*WinnTunnelBackendJSON\s*\(\s*void\s*\)",
        "WinnFreeString": r"void\s+WinnFreeString\s*\(\s*char\s*\*\s*[A-Za-z_]\w*\s*\)",
    },
    "datapath": {
        "WinnTunnelCreate": (
            r"long\s+long(?:\s+int)?\s+WinnTunnelCreate\s*\(\s*"
            r"char\s*\*\s*[A-Za-z_]\w*\s*,\s*int\s+[A-Za-z_]\w*\s*,\s*"
            r"char\s*\*\s*\*\s*[A-Za-z_]\w*\s*\)"
        ),
        "WinnTunnelWriteInbound": (
            r"int\s+WinnTunnelWriteInbound\s*\(\s*long\s+long(?:\s+int)?\s+"
            r"[A-Za-z_]\w*\s*,\s*char\s*\*\s*[A-Za-z_]\w*\s*,\s*"
            r"int\s+[A-Za-z_]\w*\s*\)"
        ),
        "WinnTunnelStatusJSON": (
            r"char\s*\*\s*WinnTunnelStatusJSON\s*\(\s*long\s+long(?:\s+int)?\s+"
            r"[A-Za-z_]\w*\s*\)"
        ),
    },
}.get(role)
if signatures is None:
    raise SystemExit(f"generated header role has no reviewed C ABI: {role!r}")
for symbol, signature in signatures.items():
    if len(re.findall(rf"(?m)^extern\s+{signature}\s*;\s*$", text)) != 1:
        raise SystemExit(f"generated header does not declare the exact C ABI for {symbol}")
WINS_HEADER_SEMANTICS_EOF
}

build_ios_archive() {
  build_apple_archive ios arm64 ios-device "arm64-apple-ios${IOS_DEPLOYMENT_TARGET}" \
    "-miphoneos-version-min=${IOS_DEPLOYMENT_TARGET}" arm64 IOS
}

# The simulator slice differs from the device slice only in SDK and the
# -simulator triple suffix, which moves the Mach-O platform to IOSSIMULATOR.
build_iossimulator_archive() {
  if [[ "$1" == amd64 ]]; then
    build_apple_archive ios amd64 ios-simulator "x86_64-apple-ios${IOS_SIMULATOR_X86_64_DEPLOYMENT_TARGET}-simulator" "" x86_64 IOSSIMULATOR
  else
    build_apple_archive ios arm64 ios-simulator "arm64-apple-ios${IOS_SIMULATOR_ARM64_DEPLOYMENT_TARGET}-simulator" "" arm64 IOSSIMULATOR
  fi
}

build_macos_archive() {
  if [[ "$1" == amd64 ]]; then
    build_apple_archive darwin amd64 macos "x86_64-apple-macos${MACOS_DEPLOYMENT_TARGET}" \
      "-mmacosx-version-min=${MACOS_DEPLOYMENT_TARGET}" x86_64 MACOS
  else
    build_apple_archive darwin arm64 macos "arm64-apple-macos${MACOS_DEPLOYMENT_TARGET}" \
      "-mmacosx-version-min=${MACOS_DEPLOYMENT_TARGET}" arm64 MACOS
  fi
}

verify_sealed_inputs
select_reviewed_go
select_obfuscation
prepare_target_platform

case "${TARGET}" in
  windows-amd64) build_executable windows amd64 ;;
  windows-arm64) build_executable windows arm64 ;;
  darwin-amd64)  build_executable darwin  amd64 ;;
  darwin-arm64)  build_executable darwin  arm64 ;;
  linux-amd64)   build_executable linux   amd64 ;;
  linux-arm64)   build_executable linux   arm64 ;;
  android-arm64) build_executable android arm64 "${PLATFORM_CC}" ;;
  android-arm)   build_executable android arm "${PLATFORM_CC}" ;;
  android-amd64) build_executable android amd64 "${PLATFORM_CC}" ;;
  ios-arm64)     select_clientinfo_archive; build_ios_archive ;;

  # --- datapath engine: subprocess transport (Android, Windows, desktop) ---
  datapath-windows-amd64) select_datapath_engine; build_executable windows amd64 ;;
  datapath-windows-arm64) select_datapath_engine; build_executable windows arm64 ;;
  datapath-darwin-amd64)  select_datapath_engine; build_executable darwin  amd64 ;;
  datapath-darwin-arm64)  select_datapath_engine; build_executable darwin  arm64 ;;
  datapath-linux-amd64)   select_datapath_engine; build_executable linux   amd64 ;;
  datapath-linux-arm64)   select_datapath_engine; build_executable linux   arm64 ;;
  datapath-android-arm64) select_datapath_engine; build_executable android arm64 "${PLATFORM_CC}" ;;
  datapath-android-arm)   select_datapath_engine; build_executable android arm "${PLATFORM_CC}" ;;
  datapath-android-amd64) select_datapath_engine; build_executable android amd64 "${PLATFORM_CC}" ;;

  # --- datapath engine: c-archive transport (iOS, iOS simulator, macOS) ---
  datapath-ios-arm64)            select_datapath_archive; build_ios_archive ;;
  datapath-iossimulator-arm64)   select_datapath_archive; build_iossimulator_archive arm64 ;;
  datapath-iossimulator-amd64)   select_datapath_archive; build_iossimulator_archive amd64 ;;
  datapath-archive-darwin-arm64) select_datapath_archive; build_macos_archive arm64 ;;
  datapath-archive-darwin-amd64) select_datapath_archive; build_macos_archive amd64 ;;

  # --- server targets: control-plane controller, data-plane carrier ---
  server-linux-amd64)  select_server_engine;  build_executable linux amd64 ;;
  server-linux-arm64)  select_server_engine;  build_executable linux arm64 ;;
  carrier-linux-amd64) select_carrier_engine; build_executable linux amd64 ;;
  carrier-linux-arm64) select_carrier_engine; build_executable linux arm64 ;;

  # --- winn/3 gateway: the standalone v3 responder a client can reach ---
  winn3-gateway-linux-amd64) select_winn3_gateway_engine; build_executable linux amd64 ;;
  winn3-gateway-linux-arm64) select_winn3_gateway_engine; build_executable linux arm64 ;;

  # --- winn/3 Windows relay: its own module, built from the same snapshot ---
  winn3-relay-windows-amd64) select_winn3_relay_engine; build_executable windows amd64 ;;
  winn3-relay-windows-arm64) select_winn3_relay_engine; build_executable windows arm64 ;;
esac

# The success line is a claim about a file and about the inputs that made it.
# Re-prove both immediately before making it.
require_output_is_our_own_build
reverify_sealed_inputs

RECEIPT_PAYLOAD="$(/usr/bin/python3 -I - \
  "${TARGET}" "${ARTIFACT_ROLE}" "${PACKAGE}" "${TARGET_GOOS}" "${TARGET_GOARCH}" \
  "${TARGET_CGO_ENABLED}" "${ARCHIVE_MODE}" "${OUTPUT}" "${BUILT_DIGEST}" \
  "${BUILT_HEADER_DIGEST}" "${SOURCE_TREE_DIGEST}" "${MODULE_CACHE_TREE_DIGEST}" \
  "${REVIEWED_GO_VERSION}" "${REVIEWED_GO_EXECUTABLE_SHA256}" "${TARGET_PLATFORM_ID}" \
  "${PLATFORM_CC_PATH}" "${PLATFORM_CC_SHA256}" "${PLATFORM_NDK_VERSION}" \
  "${PLATFORM_SDK_VERSION}" "${OBFUSCATION}" "${GARBLE_VERSION}" "${GARBLE_EXECUTABLE_SHA256}" \
  "${GARBLE_SEED_SHA256}" "${GARBLE_FLAGS[*]}" "${V3_PACKAGES_LINKED}" <<'WINS_RECEIPT_EOF'
import json
import sys

(
    target, role, package, goos, goarch, cgo, archive_mode, output, artifact_sha,
    header_sha, source_sha, cache_sha, go_version, go_sha, platform_id,
    compiler_path, compiler_sha, ndk_version, sdk_version,
    obfuscation, garble_version, garble_sha, seed_sha, garble_flags, v3_linked,
) = sys.argv[1:]
receipt = {
    "archive_mode": archive_mode == "1",
    "artifact": {"header_sha256": header_sha or None, "output_path": output, "sha256": artifact_sha},
    "contract": "winsvpn-winn-core-build-v4",
    "go": {"executable_sha256": go_sha, "version": go_version},
    "module_cache_tree_sha256": cache_sha,
    "package": package,
    "platform": {
        "compiler_path": compiler_path or None,
        "compiler_sha256": compiler_sha or None,
        "id": platform_id,
        "ndk_version": ndk_version or None,
        "sdk_version": sdk_version or None,
    },
    "role": role,
    "source_tree_sha256": source_sha,
    "target": {"cgo_enabled": cgo == "1", "goarch": goarch, "goos": goos, "id": target},
}
# Plain receipts keep their exact v4 shape; only obfuscated builds add this.
if obfuscation:
    receipt["obfuscation"] = {
        "executable_sha256": garble_sha,
        "flags": garble_flags.split(),
        "seed_sha256": seed_sha,
        "tool": "mvdan.cc/garble",
        "version": garble_version,
    }
    if role == "datapath":
        receipt["v3_packages_linked"] = v3_linked == "1"
payload = json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
if len(payload) > 8192:
    raise SystemExit("Winn build receipt exceeded 8192 bytes")
print(payload)
WINS_RECEIPT_EOF
)" || die "Could not construct the Winn build receipt."
# The receipt is staged in a private mktemp directory and written under
# noclobber, never at a predictable name beside OUTPUT where a planted file or
# link would be overwritten or written through, then linked into place
# (no-clobber), like the artifact.
new_stage_dir
RECEIPT_STAGE="${NEW_STAGE_DIR}/receipt.json"
( set -C; printf '%s\n' "${RECEIPT_PAYLOAD}" >"${RECEIPT_STAGE}" ) \
  || die "Could not stage the Winn build receipt."
link_into_place "${RECEIPT_STAGE}" "${GENERATION_RECEIPT}"
COMMITTED=1
printf 'WINN_BUILD_RECEIPT %s\n' "${RECEIPT_PAYLOAD}"
printf 'Built Winn Protocol %s: %s (%s, sha256 %s)\n' \
  "${ARTIFACT_LABEL}" "${OUTPUT}" "${TARGET}" "${BUILT_DIGEST}"
