#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT}"

PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
# macOS ships realpath only at /bin/realpath (there is no /usr/bin/realpath on
# macOS 27); GNU systems install it at /usr/bin/realpath.
if [[ "$(/usr/bin/uname -s)" == "Darwin" ]]; then
  REALPATH_BIN="/bin/realpath"
else
  REALPATH_BIN="/usr/bin/realpath"
fi

# Resolves a candidate to a real, on-disk regular executable file -- never
# a symlink, shell function, or alias -- so the later exact version+revision
# check is actually binding to one concrete file on disk rather than to
# whatever a compromised `flutter` or `python3` on PATH claims to report.
# `realpath -e` is GNU-only; stock macOS realpath rejects `-e`, so
# the unadorned form is the Darwin fallback. PATH `realpath` is never used:
# if the fixed realpath is missing or itself a symlink, this producer stops.
if [[ ! -x "${REALPATH_BIN}" || -L "${REALPATH_BIN}" || ! -f "${REALPATH_BIN}" ]]; then
  printf 'APPLE RELEASE CANDIDATE BUILD ERROR: %s must be a real regular executable; PATH realpath is refused.\n' "${REALPATH_BIN}" >&2
  exit 65
fi
resolve_real_executable() {
  local candidate="$1" resolved=""
  [[ -n "${candidate}" ]] || return 1
  if [[ "${candidate}" != /* ]]; then
    return 1
  fi
  # GNU realpath -e -- requires the path to exist; Darwin /bin/realpath
  # rejects -e, so the unadorned "${REALPATH_BIN}" -- form is the fallback.
  resolved="$("${REALPATH_BIN}" -e -- "${candidate}" 2>/dev/null \
    || "${REALPATH_BIN}" -- "${candidate}" 2>/dev/null \
    || true)"
  [[ -n "${resolved}" && -f "${resolved}" && -x "${resolved}" && ! -L "${resolved}" ]] || return 1
  printf '%s\n' "${resolved}"
}

if [[ "${PYTHON_BIN}" != /* ]]; then
  PYTHON_BIN="$(command -v "${PYTHON_BIN}" 2>/dev/null || true)"
fi
PYTHON_BIN="$(resolve_real_executable "${PYTHON_BIN}")" \
  || {
    printf 'APPLE RELEASE CANDIDATE BUILD ERROR: Python must be a real regular executable file, not a symlink, alias, or shell function.\n' >&2
    exit 65
  }

# SINGLE SOURCE OF TRUTH: read every toolchain pin from
# tools/toolchain-pins.json at run time instead of a literal. A literal that
# happens to agree today is still a defect -- the next pin bump silently
# desynchronises this producer from every other build. Fail loudly so a
# missing pin file or parser never selects an unreviewed toolchain silently.
read_wins_toolchain_pin() {
  local pin_key="${1:?read_wins_toolchain_pin: missing key}"
  [[ -f "${ROOT}/tools/toolchain-pins.json" ]] || {
    printf 'TOOLCHAIN PIN ERROR: %s does not exist; cannot resolve %s.\n' \
      "${ROOT}/tools/toolchain-pins.json" "${pin_key}" >&2
    exit 65
  }
  "${PYTHON_BIN}" - "${ROOT}/tools/toolchain-pins.json" "${pin_key}" <<'WINS_PIN_EOF'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
sys.stdout.write(str(value))
WINS_PIN_EOF
}

FLUTTER_BIN="${FLUTTER_BIN:-}"
DEPENDENCY_FREEZE="${ROOT}/tools/run_release_dependency_freeze.sh"
APPLE_RUNTIME="${ROOT}/tools/apple_runtime_smoke.sh"
WINN_RELEASE_DRIVER="${ROOT}/tools/winn_release.py"
IOS_ARTIFACT="${ROOT}/build/apple/exports/ios-app-store-local/Win's VPN.ipa"
IOS_ARTIFACT_REL="build/apple/exports/ios-app-store-local/Win's VPN.ipa"
MACOS_ARTIFACT="${ROOT}/build/apple/exports/macos-app-store-local/Win's VPN.pkg"
MACOS_ARTIFACT_REL="build/apple/exports/macos-app-store-local/Win's VPN.pkg"
MACOS_NATIVE_HOST_INSTALLED_PATH="/Library/Application Support/Win's VPN/NativeMessagingHost/wins_bridge_host"
BUILD_LOCK_DIR="${ROOT}/.dart_tool/winsvpn-release-build.lock"
BUILD_LOCK_OWNER="${BUILD_LOCK_DIR}/owner.txt"
BUILD_LOCK_ACQUIRED=0
RELEASE_GO_WORK=""
RELEASE_GO_WORK_PARENT=""
REQUIRED_FLUTTER_VERSION="$(read_wins_toolchain_pin tools.flutter.version)"
REQUIRED_FLUTTER_REVISION="$(read_wins_toolchain_pin tools.flutter.revision)"
REQUIRED_GO_VERSION="$(read_wins_toolchain_pin tools.go.version)"

release_build_lock() {
  [[ "${BUILD_LOCK_ACQUIRED}" == "1" ]] || return 0
  rm -f -- "${BUILD_LOCK_OWNER}"
  rmdir -- "${BUILD_LOCK_DIR}"
  BUILD_LOCK_ACQUIRED=0
}

# Removes only the private pinned-Go extraction this run created. The
# extracted tree is frozen read-only (0500/0400), so owner write permission is
# restored inside that mktemp-owned directory before removal.
release_go_cleanup() {
  [[ -n "${RELEASE_GO_WORK}" ]] || return 0
  case "${RELEASE_GO_WORK}" in
    "${RELEASE_GO_WORK_PARENT:-/nonexistent}"/wins-apple-release-go.*)
      if [[ -d "${RELEASE_GO_WORK}" && ! -L "${RELEASE_GO_WORK}" ]]; then
        /bin/chmod -R u+w "${RELEASE_GO_WORK}" 2>/dev/null || true
        /bin/rm -rf -- "${RELEASE_GO_WORK}"
      fi
      ;;
    *)
      printf 'APPLE RELEASE CANDIDATE BUILD ERROR: refusing to remove an unexpected Go work path: %s\n' \
        "${RELEASE_GO_WORK}" >&2
      ;;
  esac
  RELEASE_GO_WORK=""
}

release_cleanup() {
  local status=$?
  trap - EXIT
  set +e
  release_go_cleanup
  release_build_lock
  exit "${status}"
}
trap release_cleanup EXIT

die() {
  printf 'APPLE RELEASE CANDIDATE BUILD ERROR: %s\n' "$*" >&2
  exit 65
}

# Pinned Go for the AWG/Xray bridge. tools/winn_release.py prepare-go extracts
# the official archive into a new private directory and refuses unless the
# archive SHA-256, the normalized install-tree SHA-256 and the bin/go SHA-256
# all equal tools/toolchain-pins.json for this host. The archive comes from
# WINS_WINN_GO_ARCHIVE, or else from the pins' archive_path. Only the
# extracted root is handed on (WINS_RELEASE_GO_ROOT); the AWG bridge measures
# bin/go and the install tree again itself and never trusts a claimed digest.
prepare_pinned_release_go() {
  local identity go_root canonical parent
  local -a prepare_args
  [[ -f "${WINN_RELEASE_DRIVER}" && ! -L "${WINN_RELEASE_DRIVER}" ]] \
    || die "The Winn release driver is unavailable: ${WINN_RELEASE_DRIVER}"
  [[ -z "${RELEASE_GO_WORK}" ]] || die "Pinned release Go was already prepared."
  parent="${TMPDIR:-/tmp}"
  parent="$(cd "${parent}" && pwd -P)" || die "TMPDIR is not a usable directory."
  RELEASE_GO_WORK_PARENT="${parent}"
  RELEASE_GO_WORK="$(/usr/bin/mktemp -d "${parent}/wins-apple-release-go.XXXXXX")" \
    || die "Could not create a private pinned Go work directory."
  /bin/chmod 0700 "${RELEASE_GO_WORK}"
  prepare_args=(prepare-go --out "${RELEASE_GO_WORK}/go")
  if [[ -n "${WINS_WINN_GO_ARCHIVE:-}" ]]; then
    prepare_args+=(--go-archive "${WINS_WINN_GO_ARCHIVE}")
  fi
  identity="$("${PYTHON_BIN}" -I "${WINN_RELEASE_DRIVER}" "${prepare_args[@]}")" \
    || die "Pinned Go could not be prepared (set WINS_WINN_GO_ARCHIVE to the official pinned archive)."
  go_root="$(printf '%s\n' "${identity}" | "${PYTHON_BIN}" -I -c '
import json
import re
import sys
lines = [line for line in sys.stdin.read().splitlines() if line.strip()]
if len(lines) != 1:
    raise SystemExit("prepare-go must print exactly one JSON line")
value = json.loads(lines[0])
for key in ("archive_sha256", "install_tree_sha256", "executable_sha256"):
    if not re.fullmatch(r"[0-9a-f]{64}", str(value.get(key, ""))):
        raise SystemExit("prepare-go identity lacks " + key)
if value.get("version") != sys.argv[1]:
    raise SystemExit("prepare-go reported Go " + str(value.get("version")))
print(value["go_root"])
' "${REQUIRED_GO_VERSION}")" \
    || die "Pinned Go identity from tools/winn_release.py prepare-go is malformed."
  case "${go_root}" in
    "${RELEASE_GO_WORK}"/go/*) ;;
    *) die "Pinned Go root is outside the private work directory: ${go_root}" ;;
  esac
  [[ -d "${go_root}" && ! -L "${go_root}" ]] || die "Pinned Go root is missing or symbolic."
  canonical="$(cd "${go_root}" && pwd -P)" || die "Pinned Go root cannot be resolved."
  [[ "${canonical}" == "${go_root}" ]] || die "Pinned Go root is not canonical: ${go_root}"
  [[ -f "${go_root}/bin/go" && -x "${go_root}/bin/go" && ! -L "${go_root}/bin/go" ]] \
    || die "Pinned Go root has no regular bin/go."
  WINS_RELEASE_GO_ROOT="${go_root}"
  export WINS_RELEASE_GO_ROOT
}

resolve_reviewed_flutter_bin() {
  local configured="${FLUTTER_BIN}" candidate resolved
  if [[ -n "${configured}" ]]; then
    if [[ "${configured}" == */* ]]; then
      resolved="$(resolve_real_executable "${configured}")" \
        || die "Configured FLUTTER_BIN must be a real regular executable file, not a symlink, alias, or shell function: ${configured}"
      printf '%s\n' "${resolved}"
      return 0
    fi
    candidate="$(command -v "${configured}" 2>/dev/null || true)"
    resolved="$(resolve_real_executable "${candidate}")" \
      || die "Configured FLUTTER_BIN command must resolve to a real regular executable file: ${configured}"
    printf '%s\n' "${resolved}"
    return 0
  fi

  candidate="${HOME}/Library/Application Support/WinsVPN/toolchains/flutter-${REQUIRED_FLUTTER_VERSION}-extract/flutter/bin/flutter"
  resolved="$(resolve_real_executable "${candidate}")" && {
    printf '%s\n' "${resolved}"
    return 0
  }

  candidate="$(command -v flutter 2>/dev/null || true)"
  resolved="$(resolve_real_executable "${candidate}")" && {
    printf '%s\n' "${resolved}"
    return 0
  }

  die "Reviewed Flutter ${REQUIRED_FLUTTER_VERSION} is unavailable. Install it under ~/Library/Application Support/WinsVPN/toolchains or set FLUTTER_BIN explicitly."
}

resolve_repo_file() {
  local value="$1"
  local label="$2"
  local candidate parent resolved
  [[ -n "${value}" ]] || die "${label} is required."
  if [[ "${value}" == /* ]]; then
    candidate="${value}"
  else
    candidate="${ROOT}/${value}"
  fi
  [[ -f "${candidate}" && ! -L "${candidate}" ]] || die "${label} is missing or symbolic."
  parent="$(cd "$(dirname "${candidate}")" && pwd -P)"
  resolved="${parent}/$(basename "${candidate}")"
  case "${resolved}" in
    "${ROOT}"/.artifacts/*/RELEASE_INPUT_INDEX.json) ;;
    *) die "${label} must be a repository .artifacts RELEASE_INPUT_INDEX.json." ;;
  esac
  printf '%s\n' "${resolved}"
}

acquire_release_build_lock() {
  local owner="owner metadata is not available"
  mkdir -p -- "$(dirname "${BUILD_LOCK_DIR}")"
  if ! mkdir -- "${BUILD_LOCK_DIR}" 2>/dev/null; then
    if [[ -s "${BUILD_LOCK_OWNER}" ]]; then
      owner="$(tr '\n' ' ' <"${BUILD_LOCK_OWNER}")"
    fi
    printf 'Another platform release build owns %s. %s. Wait for it to finish; never delete an active lock.\n' \
      "${BUILD_LOCK_DIR}" "${owner}" >&2
    exit 73
  fi
  BUILD_LOCK_ACQUIRED=1
  printf 'platform=apple\npid=%s\nstarted_utc=%s\n' \
    "$$" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" >"${BUILD_LOCK_OWNER}"
}

initialize_receipt_directory() {
  local index_path="$1"
  local requested parent
  requested="${WINS_APPLE_BUILD_RECEIPT_DIR:-}"
  if [[ -z "${requested}" ]]; then
    requested="$(dirname "${index_path}")/apple-build-$(date -u +'%Y%m%dT%H%M%SZ')-$$"
  elif [[ "${requested}" != /* ]]; then
    requested="${ROOT}/${requested}"
  fi
  [[ ! -e "${requested}" && ! -L "${requested}" ]] \
    || die "Apple build receipt directory must be a new immutable path."
  parent="$(cd "$(dirname "${requested}")" && pwd -P)"
  RECEIPT_DIR="${parent}/$(basename "${requested}")"
  case "${RECEIPT_DIR}" in
    "${ROOT}"/.artifacts/*) ;;
    *) die "WINS_APPLE_BUILD_RECEIPT_DIR must stay under repository .artifacts." ;;
  esac
  mkdir -m 0700 -- "${RECEIPT_DIR}"
  IOS_BEGIN="${RECEIPT_DIR}/IOS_BUILD_BEGIN.json"
  MACOS_BEGIN="${RECEIPT_DIR}/MACOS_BUILD_BEGIN.json"
  IOS_RECEIPT="${RECEIPT_DIR}/IOS_BUILD_RECEIPT.json"
  MACOS_RECEIPT="${RECEIPT_DIR}/MACOS_BUILD_RECEIPT.json"
}

begin_receipts() {
  # M-1: fail before any Apple engine artifact is accepted if a committed
  # Xray/AmneziaWG binary embeds a Go runtime with known-fixed stdlib CVEs.
  # This is repo-state-only (no network, no platform build tools), so it is
  # cheap to run unconditionally even on an Apple-only build lane.
  "${PYTHON_BIN}" tools/verify_embedded_engine_runtime_versions.py
  # A scoped (ios,macos) index refuses a full-set verify-index, so every
  # verification names the Apple platform it covers, as the macOS Android
  # producer does.
  /bin/bash "${DEPENDENCY_FREEZE}" verify-index \
    --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform ios
  /bin/bash "${DEPENDENCY_FREEZE}" verify-index \
    --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform macos
  /bin/bash "${DEPENDENCY_FREEZE}" begin-build \
    --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform ios \
    --output "${IOS_BEGIN}"
  /bin/bash "${DEPENDENCY_FREEZE}" begin-build \
    --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform macos \
    --output "${MACOS_BEGIN}"
}

finish_receipt() {
  local platform="$1"
  local begin="$2"
  local artifact="$3"
  local output="$4"
  /bin/bash "${DEPENDENCY_FREEZE}" finish-build \
    --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform "${platform}" \
    --begin "${begin}" --artifact "${artifact}" \
    --producer tools/apple_runtime_smoke.sh \
    --toolchain-name Xcode --toolchain-version "${XCODE_VERSION}" \
    --toolchain-revision "${XCODE_REVISION}" --target app-store-local \
    --output "${output}"
  /bin/bash "${DEPENDENCY_FREEZE}" verify-receipt \
    --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform "${platform}" \
    --receipt "${output}" --artifact "${artifact}"
}

[[ "$(uname -s)" == "Darwin" ]] || die "This producer must run on macOS."
[[ -x "${PYTHON_BIN}" ]] || die "Python is unavailable at ${PYTHON_BIN}."
FLUTTER_BIN="$(resolve_reviewed_flutter_bin)"
export FLUTTER_BIN
XCODEBUILD_PATH="$(command -v xcodebuild 2>/dev/null || true)"
XCODEBUILD_BIN="$(resolve_real_executable "${XCODEBUILD_PATH}")" \
  || die "xcodebuild must resolve to a real regular executable file, not a symlink, alias, or shell function."

RELEASE_INDEX="$(resolve_repo_file "${WINS_RELEASE_INPUT_INDEX:-}" "WINS_RELEASE_INPUT_INDEX")"
acquire_release_build_lock
initialize_receipt_directory "${RELEASE_INDEX}"

XCODE_REPORT="$("${XCODEBUILD_BIN}" -version)"
XCODE_VERSION="$(printf '%s\n' "${XCODE_REPORT}" | sed -n 's/^Xcode //p' | head -n 1)"
XCODE_REVISION="$(printf '%s\n' "${XCODE_REPORT}" | sed -n 's/^Build version //p' | head -n 1)"
[[ "${XCODE_VERSION}" =~ ^[0-9]+([.][0-9]+){1,2}$ ]] \
  || die "xcodebuild reported an invalid Xcode version."
[[ "${XCODE_REVISION}" =~ ^[A-Za-z0-9.]+$ ]] \
  || die "xcodebuild reported an invalid build revision."

read -r FLUTTER_VERSION FLUTTER_REVISION < <(
  "${FLUTTER_BIN}" --version --machine | "${PYTHON_BIN}" -c '
import json
import sys
raw = sys.stdin.read()
start = raw.find("{")
end = raw.rfind("}")
if start < 0 or end < start:
    raise SystemExit("Flutter version JSON was not found")
value = json.loads(raw[start : end + 1])
print(value.get("frameworkVersion", ""), value.get("frameworkRevision", ""))
'
)
[[ "${FLUTTER_VERSION}" == "${REQUIRED_FLUTTER_VERSION}" \
   && "${FLUTTER_REVISION}" == "${REQUIRED_FLUTTER_REVISION}" ]] \
  || die "Apple releases require Flutter ${REQUIRED_FLUTTER_VERSION} (${REQUIRED_FLUTTER_REVISION}); found ${FLUTTER_VERSION} (${FLUTTER_REVISION})."

begin_receipts

[[ -z "${APPLE_ENGINE_ARTIFACTS_DIR:-}" ]] \
  || die "APPLE_ENGINE_ARTIFACTS_DIR reuse is forbidden in production Apple candidate builds."
[[ "${WINS_SKIP_APPLE_ENGINE_WRAPPER_BUILD:-0}" == "0" ]] \
  || die "Preexisting Apple engine artifact reuse is forbidden in production candidate mode."
unset WINS_RELEASE_GO_ROOT
prepare_pinned_release_go

# Build fresh AWG/Xray/Winn engine wrapper artifacts into apple/EngineArtifacts
# before xcodebuild ever archives anything below. tools/apple_runtime_smoke.sh
# only VERIFIES whatever ends up inside the exported .ipa/.app, and the
# ios/macos Xcode projects' Run Script build phase
# (tools/stage_apple_engine_artifacts.sh) only COPIES whatever is already
# sitting in apple/EngineArtifacts -- neither one builds it. Before this call
# existed, nothing in this producer did either: a release either failed
# closed on missing required AWG/Xray artifacts (WINS_REQUIRE_APPLE_ENGINE=1
# below already guarantees that much), or, if apple/EngineArtifacts happened
# to be pre-populated by an earlier, unrelated local run, silently shipped
# whatever was sitting there -- stale AWG/Xray, and/or a stale Winn wrapper,
# with nothing to catch either.
#
# tools/build_apple_engine_wrappers.sh still treats Winn as additive internally,
# so this release producer verifies the resulting iOS and macOS Winn artifacts
# immediately after the build. A skipped or stale-absent Winn build is fatal
# before any archive begins.
# Store candidates take the Winn c-archives only from a signed release
# directory produced by tools/winn_release.py (two byte-identical builds per
# slice, manifest signed by the release authority). WINS_APPLE_WINN3_RELEASE=1
# makes the wrapper builder refuse an unsigned or driver-built dev release.
[[ -n "${WINS_WINN_RELEASE_DIR:-}" ]] \
  || die "Set WINS_WINN_RELEASE_DIR to the signed Winn release directory (tools/winn_release.py build + sign)."
export WINS_WINN_RELEASE_DIR
export WINS_APPLE_WINN3_RELEASE=1
(
  source "${ROOT}/tools/build_apple_engine_wrappers.sh" all
)

# A file-presence check cannot distinguish a current AWG 3.1 wrapper from an
# older dylib left by a previous build. Re-derive every bridge/wrapper SHA-256
# from the immutable Apple source, Go-toolchain, and Xray provenance before an
# archive starts. This is intentionally unconditional, including on the
# explicit reuse path above.
/bin/bash "${ROOT}/tools/build_apple_engine_wrappers.sh" verify-awg-provenance
[[ -f "${ROOT}/apple/EngineArtifacts/apple_awg_31_engine_provenance.json" \
   && ! -L "${ROOT}/apple/EngineArtifacts/apple_awg_31_engine_provenance.json" ]] \
  || die "Apple AWG 3.1 engine provenance is missing or symbolic."

# Winn v3 provenance is required after reuse selection as well as after a
# fresh wrapper build. Cached Winn dylibs that still export a complete symbol
# set are not evidence of current source, archives, or reviewed Go identity.
(
  source "${ROOT}/tools/build_apple_engine_wrappers.sh" verify-winn-provenance
)
[[ -f "${ROOT}/apple/EngineArtifacts/apple_winn_v3_engine_provenance.json" \
   && ! -L "${ROOT}/apple/EngineArtifacts/apple_winn_v3_engine_provenance.json" ]] \
  || die "Apple Winn v3 engine provenance is missing or symbolic. Cached Winn artifacts are owner-blocked until a verified rebuild."
WINS_APPLE_ENGINE_TRANSACTION_PROVENANCE_SHA256="$(
  /usr/bin/shasum -a 256 "${ROOT}/apple/EngineArtifacts/apple_winn_v3_engine_provenance.json"
)" || die "Apple Winn v3 transaction provenance could not be hashed."
WINS_APPLE_ENGINE_TRANSACTION_PROVENANCE_SHA256="${WINS_APPLE_ENGINE_TRANSACTION_PROVENANCE_SHA256%% *}"
[[ "${WINS_APPLE_ENGINE_TRANSACTION_PROVENANCE_SHA256}" =~ ^[0-9a-f]{64}$ ]] \
  || die "Apple Winn v3 transaction provenance digest is malformed."
export WINS_APPLE_ENGINE_TRANSACTION_PROVENANCE_SHA256

# Native standalone v3 is the primary Apple datapath. These artifacts must
# remain on disk as regular files; a missing or symbolic wrapper is a
# release-candidate refusal, not an implicit fallback to v1.
for winn_artifact in \
  "apple/EngineArtifacts/macos/libWinsWinnPacketEngine.dylib" \
  "apple/EngineArtifacts/ios/iphoneos/libWinsWinnPacketEngine.dylib"; do
  [[ -f "${ROOT}/${winn_artifact}" && ! -L "${ROOT}/${winn_artifact}" ]] \
    || die "Standalone v3 release artifact is missing or symbolic: ${winn_artifact}"
done

# Packaged Winn v1 fallbacks stay mandatory beside v3. AWG is attempted
# first; Xray is attempted only after AWG fails. Neither packaged fallback
# may be omitted from a release candidate.
for engine_artifact in \
  "apple/EngineArtifacts/macos/libWinsAmneziaWGPacketEngine.dylib" \
  "apple/EngineArtifacts/macos/libWinsXrayVlessWsTransport.dylib" \
  "apple/EngineArtifacts/macos/libWinsWinnPacketEngine.dylib" \
  "apple/EngineArtifacts/ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib" \
  "apple/EngineArtifacts/ios/iphoneos/libWinsXrayVlessWsTransport.dylib" \
  "apple/EngineArtifacts/ios/iphoneos/libWinsWinnPacketEngine.dylib"; do
  [[ -f "${ROOT}/${engine_artifact}" && ! -L "${ROOT}/${engine_artifact}" ]] \
    || die "Apple release engine artifact is missing or symbolic: ${engine_artifact}"
done

# Browser native-messaging is delivered outside the sandboxed macOS app. The
# App Store PKG architecture cannot include that host, so this producer builds
# the companion binary (arm64 for 1.0.16 and 1.0.17, owner ruling 2026-10-16) and documents the exact product-scope
# incompatibility instead of embedding it in the candidate.
NATIVE_HOST_DIR="${RECEIPT_DIR}/native-messaging"
mkdir -m 0700 -- "${NATIVE_HOST_DIR}"
NATIVE_HOST_BIN="${NATIVE_HOST_DIR}/wins_bridge_host"
FLUTTER_DIR="$(dirname "${FLUTTER_BIN}")"
DART_CANDIDATE="${FLUTTER_DIR}/cache/dart-sdk/bin/dart"
DART_BIN="$(resolve_real_executable "${DART_CANDIDATE}")" \
  || die "Reviewed Dart compiler is unavailable beside Flutter at ${DART_CANDIDATE}."
# Owner ruling 2026-10-16: the 1.0.16 and 1.0.17 companion is Apple silicon only (the
# release Mac cannot build an x86_64 Dart slice); the gate below accepts an
# arm64 host only under that dated ruling.
[[ "$(/usr/bin/uname -m)" == "arm64" ]] \
  || die "The 1.0.16 and 1.0.17 native-messaging companion must be built on Apple silicon (owner ruling 2026-10-16)."
/bin/bash "${ROOT}/tools/native_messaging/build_native_host.sh" \
  --output "${NATIVE_HOST_BIN}" --dart "${DART_BIN}"
"${PYTHON_BIN}" "${ROOT}/tools/apple_cross_store_artifact_gate.py" \
  native-host verify-binary --host "${NATIVE_HOST_BIN}" \
  >"${NATIVE_HOST_DIR}/wins_bridge_host.identity.json"
"${PYTHON_BIN}" "${ROOT}/tools/apple_cross_store_artifact_gate.py" native-host scope \
  >"${NATIVE_HOST_DIR}/macos-app-store-scope.json"
chmod 0600 \
  "${NATIVE_HOST_DIR}/wins_bridge_host.identity.json" \
  "${NATIVE_HOST_DIR}/macos-app-store-scope.json"
"${PYTHON_BIN}" "${ROOT}/tools/native_messaging/render_host_manifest.py" \
  --browser firefox \
  --host-path "${MACOS_NATIVE_HOST_INSTALLED_PATH}" \
  --output "${NATIVE_HOST_DIR}/org.winsvpn.bridge.firefox.json"
CHROME_STATUS=0
CHROME_ID="$("${PYTHON_BIN}" "${ROOT}/tools/native_messaging/native_host_layout.py" recorded-id --browser chrome)" || CHROME_STATUS=$?
NATIVE_HOST_MANIFEST_ARGS=(
  native-host verify-manifests
  --host-path "${MACOS_NATIVE_HOST_INSTALLED_PATH}"
  --firefox "${NATIVE_HOST_DIR}/org.winsvpn.bridge.firefox.json"
)
if [[ "${CHROME_STATUS}" -eq 0 && -n "${CHROME_ID}" ]]; then
  "${PYTHON_BIN}" "${ROOT}/tools/native_messaging/render_host_manifest.py" \
    --browser chrome \
    --host-path "${MACOS_NATIVE_HOST_INSTALLED_PATH}" \
    --output "${NATIVE_HOST_DIR}/org.winsvpn.bridge.chrome.json"
  NATIVE_HOST_MANIFEST_ARGS+=(--chrome "${NATIVE_HOST_DIR}/org.winsvpn.bridge.chrome.json" --owner-chrome-id "${CHROME_ID}")
elif [[ "${CHROME_STATUS}" -eq 78 ]]; then
  printf 'Chrome native-host registration is owner-blocked; no Chrome manifest was generated and no store id was invented.\n' \
    >"${NATIVE_HOST_DIR}/chrome-owner-blocked.txt"
  chmod 0600 "${NATIVE_HOST_DIR}/chrome-owner-blocked.txt"
else
  die "Chrome native-host recorded-id lookup failed (${CHROME_STATUS})."
fi
"${PYTHON_BIN}" "${ROOT}/tools/apple_cross_store_artifact_gate.py" \
  "${NATIVE_HOST_MANIFEST_ARGS[@]}"
printf 'macOS App Store cannot deliver wins_bridge_host; companion host is %s and live registration is tools/native_messaging/install_macos_native_host.sh.\n' \
  "${NATIVE_HOST_BIN}"

# CocoaPods refuses a non-UTF-8 locale (`Unicode Normalization not
# appropriate for ASCII-8BIT`), so both smoke passes run under en_US.UTF-8.
RUN_LOG="${RECEIPT_DIR}/APPLE_ARCHIVE_EXPORT.log"
VERIFICATION_LOG="${RECEIPT_DIR}/APPLE_CANDIDATE_VERIFICATION.log"
: >"${RUN_LOG}"
: >"${VERIFICATION_LOG}"
# macOS chmod treats "--" after the mode as a file name; these paths are absolute.
chmod 0600 "${RUN_LOG}" "${VERIFICATION_LOG}"
# The first pass writes the archive privacy manifest report for the archives it
# exports; the freeze binds it to the IPA and PKG bytes. A report left by an
# earlier run must never stand in for this one.
ARCHIVE_PRIVACY_REPORT="${ROOT}/build/apple/privacy/archive-privacy-manifests.json"
ARCHIVE_PRIVACY_INVENTORY="${RECEIPT_DIR}/APPLE_ARCHIVE_PRIVACY_INVENTORY.json"
/bin/rm -f "${ARCHIVE_PRIVACY_REPORT}" "${ROOT}/build/apple/privacy/archive-privacy-manifests.md"

env \
  FLUTTER_BIN="${FLUTTER_BIN}" \
  LANG=en_US.UTF-8 \
  LC_ALL=en_US.UTF-8 \
  WINS_APPLE_RELEASE_CANDIDATE_REBUILD=1 \
  WINS_APPLE_PRIVACY_ARCHIVE_REPORT=1 \
  APPLE_PRIVACY_REPORT_DIR=build/apple/privacy \
  WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE=1 \
  WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE=1 \
  WINS_REQUIRE_APPLE_ENGINE=1 \
  WINS_APPLE_WINN3_RELEASE=1 \
  WINS_REQUIRE_WINN3_DESCRIPTOR_PUBKEY=1 \
  WINS_APPLE_SIGNING_KEYCHAIN_PROBE_TIMEOUT_SECONDS=120 \
  WINS_APPLE_EXPORT_TIMEOUT_SECONDS=1200 \
  WINS_RELEASE_SHELL_SMOKE=0 \
  WINS_IOS_SIMULATOR_SMOKE=0 \
  WINS_IOS_SIMULATOR_SCREENSHOT_SMOKE=0 \
  WINS_MACOS_LAUNCH_SMOKE=0 \
  WINS_APPLE_LIVE_TUNNEL_SMOKE=0 \
  WINS_IOS_LIVE_TUNNEL_SMOKE=0 \
  WINS_IOS_INSTALL=0 \
  /bin/bash "${APPLE_RUNTIME}" 2>&1 | /usr/bin/tee "${RUN_LOG}"

env \
  FLUTTER_BIN="${FLUTTER_BIN}" \
  LANG=en_US.UTF-8 \
  LC_ALL=en_US.UTF-8 \
  WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH=1 \
  WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY=1 \
  WINS_REQUIRE_APPLE_ENGINE=1 \
  WINS_APPLE_WINN3_RELEASE=1 \
  WINS_RELEASE_SHELL_SMOKE=0 \
  WINS_IOS_SIMULATOR_SMOKE=0 \
  WINS_IOS_SIMULATOR_SCREENSHOT_SMOKE=0 \
  WINS_MACOS_LAUNCH_SMOKE=0 \
  /bin/bash "${APPLE_RUNTIME}" 2>&1 | /usr/bin/tee "${VERIFICATION_LOG}"

"${PYTHON_BIN}" "${ROOT}/tools/verify_standalone_v3_artifact.py" \
  "${IOS_ARTIFACT}" "${MACOS_ARTIFACT}"
"${PYTHON_BIN}" "${ROOT}/tools/verify_winn3_ring_artifact.py" \
  "${WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256:?reviewed Winn3 ring SHA-256 required}" \
  "${IOS_ARTIFACT}" "${MACOS_ARTIFACT}"

# Inspect every embedded Watch device slice from an authenticated snapshot of
# the exact signed IPA. The gate emits verifier identity, canonical output,
# output digest, and IPA digest into the durable verification log that the
# candidate freeze binds. Missing or unsupported Watch payloads stop here.
"${PYTHON_BIN}" "${ROOT}/tools/apple_cross_store_artifact_gate.py" \
  watch-evidence "${IOS_ARTIFACT_REL}" 2>&1 | /usr/bin/tee -a "${VERIFICATION_LOG}"

"${PYTHON_BIN}" "${ROOT}/tools/apple_cross_store_artifact_gate.py" \
  native-host refuse-packaged --artifact "${MACOS_ARTIFACT_REL}"

# Exact IPA/PKG bytes must exist as one owner-signed, single-link regular file
# before receipts or the freeze can treat them as current candidates. Absence,
# a symlink, extra hard links, or an unsigned/ad-hoc/development identity is a
# producer refusal -- freeze must not invent Apple Distribution authority.
require_exact_exported_candidate() {
  local path="$1"
  local label="$2"
  local nlink
  [[ -f "${path}" && ! -L "${path}" ]] \
    || die "${label} owner-signed artifact is absent or symbolic."
  nlink="$(/usr/bin/stat -f '%l' -- "${path}" 2>/dev/null || true)"
  [[ "${nlink}" == "1" ]] \
    || die "${label} owner-signed artifact must be one exact single-link file."
  [[ -s "${path}" ]] || die "${label} owner-signed artifact is empty."
}

require_exact_exported_candidate "${IOS_ARTIFACT}" "iOS App Store IPA"
require_exact_exported_candidate "${MACOS_ARTIFACT}" "macOS App Store PKG"
"${PYTHON_BIN}" "${ROOT}/tools/apple_upload_exact_release_candidates.py" \
  --verify-owner-signed-packaging \
  "${IOS_ARTIFACT}" \
  "${MACOS_ARTIFACT}"

# Xcode creates SwiftPM scaffolding folders world-writable (mode 0777) on every
# archive, whatever the umask: xcshareddata/swiftpm in the Runner workspaces and
# .swiftpm/xcode in the Flutter-generated Swift packages under
# Flutter/ephemeral/Packages. The dependency freeze rightly refuses a writable
# directory. They are untracked and must hold no file; removing the empty
# folders returns the tree to its frozen state. A file inside is refused.
remove_xcode_swiftpm_scaffolding() {
  local path relative tracked
  local -a found=()
  while IFS= read -r -d '' path; do
    found+=("${path}")
  done < <(/usr/bin/find "${ROOT}/ios" "${ROOT}/macos" \
    \( -path '*/xcshareddata/swiftpm' -o -path '*/Flutter/ephemeral/Packages/*/.swiftpm' \) \
    -prune -print0)
  for path in ${found[@]+"${found[@]}"}; do
    relative="${path#"${ROOT}/"}"
    [[ -d "${path}" && ! -L "${path}" ]] \
      || die "Xcode SwiftPM scaffolding is not a plain directory: ${relative}"
    # A command substitution inside [[ ]] hides a failed git (empty output reads
    # as untracked), so the answer is captured and its exit status checked.
    tracked="$(/usr/bin/git -C "${ROOT}" ls-files -- "${relative}")" \
      || die "Xcode SwiftPM scaffolding tracked state could not be read: ${relative}"
    [[ -z "${tracked}" ]] \
      || die "Xcode SwiftPM scaffolding is tracked: ${relative}"
    [[ -z "$(/usr/bin/find "${path}" ! -type d -print -quit)" ]] \
      || die "Xcode SwiftPM scaffolding holds files; refusing to remove: ${relative}"
    /usr/bin/find "${path}" -depth -type d -empty -delete
    [[ ! -e "${path}" ]] || die "Xcode SwiftPM scaffolding was not removed: ${relative}"
  done
}
remove_xcode_swiftpm_scaffolding

/bin/bash "${DEPENDENCY_FREEZE}" verify-index \
  --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform ios
/bin/bash "${DEPENDENCY_FREEZE}" verify-index \
  --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform macos
finish_receipt ios "${IOS_BEGIN}" "${IOS_ARTIFACT}" "${IOS_RECEIPT}"
finish_receipt macos "${MACOS_BEGIN}" "${MACOS_ARTIFACT}" "${MACOS_RECEIPT}"

[[ -f "${ARCHIVE_PRIVACY_REPORT}" && ! -L "${ARCHIVE_PRIVACY_REPORT}" && -s "${ARCHIVE_PRIVACY_REPORT}" ]] \
  || die "The first pass did not write the archive privacy manifest report."
/bin/cp -- "${ARCHIVE_PRIVACY_REPORT}" "${ARCHIVE_PRIVACY_INVENTORY}"
chmod 0600 "${ARCHIVE_PRIVACY_INVENTORY}"

"${PYTHON_BIN}" tools/freeze_apple_release_candidates.py \
  --receipt-directory "${RECEIPT_DIR}" \
  --release-input-index "${RELEASE_INDEX}" \
  --ios-build-receipt "${IOS_RECEIPT}" \
  --macos-build-receipt "${MACOS_RECEIPT}" \
  --archive-export-log "${RUN_LOG}" --verification-log "${VERIFICATION_LOG}" \
  --archive-privacy-inventory "${ARCHIVE_PRIVACY_INVENTORY}"

printf 'APPLE RELEASE CANDIDATE BUILD: PASS\n'
printf 'iOS receipt: %s\n' "${IOS_RECEIPT}"
printf 'macOS receipt: %s\n' "${MACOS_RECEIPT}"
printf 'No upload or App Review mutation occurred.\n'
