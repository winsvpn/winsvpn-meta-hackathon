#!/usr/bin/env bash
set -Eeuo pipefail

# WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1
# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
readonly WINS_RELEASE_DEPENDENCY_NATIVE_HOST=darwin
readonly WINS_RELEASE_DEPENDENCY_NATIVE_RUNTIME=bash-file
readonly WINS_RELEASE_DEPENDENCY_NATIVE_PLATFORM=apple

wins_release_dependency_build_attempt_v2() {
  local attempt_name output output_after output_before output_descriptor output_identity
  local output_size

  exec 1>&- 2>&-
  [[ "$#" -eq 1 && "$1" == "--wins-release-dependency-build-attempt-v2" ]] \
    || exit 64

  for attempt_name in ${!WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_@}; do
    case "${attempt_name}" in
      WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT|\
      WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE|\
      WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT|\
      WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM) ;;
      *) exit 64 ;;
    esac
  done

  [[ "${WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT-}" \
      == "winsvpn-witnessed-build-attempt-v2" ]] || exit 64
  [[ "${WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE-}" \
      =~ ^[0-9a-f]{64}$ ]] || exit 64
  case "${WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM-}" in
    ios|macos) ;;
    *) exit 64 ;;
  esac
  [[ "${OSTYPE}" == darwin* ]] || exit 64

  output="${WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT-}"
  [[ "${#output}" -ge 1 && "${#output}" -le 192 \
      && "${output}" =~ ^[A-Za-z0-9][A-Za-z0-9._+\ -]*$ \
      && -f "${output}" && ! -L "${output}" ]] || exit 64
  output_before="$(/usr/bin/stat -f '%d:%i:%l:%Lp:%z:%u:%HT' "${output}")" \
    || exit 64
  case "${output_before}" in
    *:1:600:0:"${EUID}":Regular\ File) ;;
    *) exit 64 ;;
  esac

  exec 9<> "${output}" || exit 64
  output_descriptor="$(/usr/bin/stat -f '%i:%l:%Lp:%z:%u:%HT' /dev/fd/9)" \
    || exit 64
  [[ "${output_descriptor}" == "${output_before#*:}" ]] || exit 64
  output_after="$(/usr/bin/stat -f '%d:%i:%l:%Lp:%z:%u:%HT' "${output}")" \
    || exit 64
  [[ "${output_after}" == "${output_before}" ]] || exit 64

  printf '%s\n' \
    'WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1' \
    "contract=${WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT}" \
    "nonce=${WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE}" \
    "host=${WINS_RELEASE_DEPENDENCY_NATIVE_HOST}" \
    "runtime=${WINS_RELEASE_DEPENDENCY_NATIVE_RUNTIME}" \
    "platform=${WINS_RELEASE_DEPENDENCY_NATIVE_PLATFORM}" \
    "target=${WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM}" >&9 || exit 64
  [[ -s /dev/fd/9 ]] || exit 64
  output_after="$(/usr/bin/stat -f '%d:%i:%l:%Lp:%z:%u:%HT' "${output}")" \
    || exit 64
  output_identity="${output_before%:0:${EUID}:Regular File}"
  output_size="$(/usr/bin/stat -f '%z' /dev/fd/9)" || exit 64
  output_descriptor="$(/usr/bin/stat -f '%i:%l:%Lp:%z:%u:%HT' /dev/fd/9)" \
    || exit 64
  [[ "${output_size}" =~ ^[1-9][0-9]*$ \
      && "${output_after}" \
        == "${output_identity}:${output_size}:${EUID}:Regular File" \
      && "${output_descriptor}" == "${output_after#*:}" ]] || exit 64
  exec 9>&-
}

if [[ "${1-}" == "--wins-release-dependency-build-attempt-v2" ]]; then
  wins_release_dependency_build_attempt_v2 "$@"
  exit 0
fi

ROOT_DIR="${WINS_PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
FLUTTER_BIN="${FLUTTER_BIN:-}"
POD_BIN="${POD_BIN:-}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# Canonical cross-store verification is deliberately dispatched before any
# Flutter, CocoaPods, Xcode, keychain, device, launch, or upload preflight.
# It inspects only the exact existing artifact named by the runner.
if [[ "${1:-}" == "--verify" ]]; then
  if [[ "$#" -ne 3 || "${2:-}" != "macos-developer-id-app" ]]; then
    printf 'APPLE CROSS-STORE ARTIFACT GATE: FAIL: expected --verify macos-developer-id-app <repo-relative-artifact>\n' >&2
    exit 64
  fi
  exec "${PYTHON_BIN}" "${ROOT_DIR}/tools/validate_apple_submission_package.py" \
    --verify "$2" "$3"
fi

# SINGLE SOURCE OF TRUTH: read every toolchain pin from
# tools/toolchain-pins.json at run time instead of a literal. A literal that
# happens to agree today is still a defect -- the next pin bump silently
# desynchronises this gate from every other build. Fail loudly so a missing
# pin file or parser never selects an unreviewed toolchain silently.
read_wins_toolchain_pin() {
  local pin_key="${1:?read_wins_toolchain_pin: missing key}"
  [[ -f "${ROOT_DIR}/tools/toolchain-pins.json" ]] || {
    printf 'TOOLCHAIN PIN ERROR: %s does not exist; cannot resolve %s.\n' \
      "${ROOT_DIR}/tools/toolchain-pins.json" "${pin_key}" >&2
    exit 65
  }
  "${PYTHON_BIN}" - "${ROOT_DIR}/tools/toolchain-pins.json" "${pin_key}" <<'WINS_PIN_EOF'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
sys.stdout.write(str(value))
WINS_PIN_EOF
}

REQUIRED_FLUTTER_VERSION="$(read_wins_toolchain_pin tools.flutter.version)"
REQUIRED_FLUTTER_REVISION="$(read_wins_toolchain_pin tools.flutter.revision)"
REQUIRED_COCOAPODS_VERSION="$(read_wins_toolchain_pin tools.cocoapods.version)"
WINS_SKIP_IOS_DEVICE="${WINS_SKIP_IOS_DEVICE:-0}"
WINS_REQUIRE_IOS_DEVICE="${WINS_REQUIRE_IOS_DEVICE:-0}"
WINS_PREFLIGHT_ONLY="${WINS_PREFLIGHT_ONLY:-0}"
WINS_PRE_RELEASE_SOURCE_SMOKE="${WINS_PRE_RELEASE_SOURCE_SMOKE:-0}"
WINS_PRE_RELEASE_SOURCE_SMOKE_SELFTEST="${WINS_PRE_RELEASE_SOURCE_SMOKE_SELFTEST:-0}"
WINS_SKIP_APPLE_DEBUG_BUILDS="${WINS_SKIP_APPLE_DEBUG_BUILDS:-0}"
WINS_IOS_INSTALL="${WINS_IOS_INSTALL:-0}"
WINS_IOS_LAUNCH="${WINS_IOS_LAUNCH:-0}"
WINS_IOS_SIGNED_BUILD="${WINS_IOS_SIGNED_BUILD:-0}"
WINS_IOS_LIVE_TUNNEL_SMOKE="${WINS_IOS_LIVE_TUNNEL_SMOKE:-0}"
WINS_IOS_APPROVE_VPN_PERMISSION="${WINS_IOS_APPROVE_VPN_PERMISSION:-0}"
WINS_IOS_APPROVE_VPN_PERMISSION_BEST_EFFORT="${WINS_IOS_APPROVE_VPN_PERMISSION_BEST_EFFORT:-1}"
WINS_IOS_UI_AUTOMATION_TIMEOUT_SECONDS="${WINS_IOS_UI_AUTOMATION_TIMEOUT_SECONDS:-120}"
WINS_IOS_VPN_PERMISSION_SETTLE_SECONDS="${WINS_IOS_VPN_PERMISSION_SETTLE_SECONDS:-5}"
WINS_IOS_SIMULATOR_SMOKE="${WINS_IOS_SIMULATOR_SMOKE:-1}"
WINS_IOS_SIMULATOR_SCREENSHOT_SMOKE="${WINS_IOS_SIMULATOR_SCREENSHOT_SMOKE:-1}"
WINS_MACOS_LAUNCH_SMOKE="${WINS_MACOS_LAUNCH_SMOKE:-1}"
WINS_RELEASE_SHELL_SMOKE="${WINS_RELEASE_SHELL_SMOKE:-1}"
WINS_MACOS_LAUNCH_RELEASE="${WINS_MACOS_LAUNCH_RELEASE:-${WINS_RELEASE_SHELL_SMOKE}}"
WINS_SIGNED_MACOS_BUILD="${WINS_SIGNED_MACOS_BUILD:-0}"
WINS_IOS_ARCHIVE_SMOKE="${WINS_IOS_ARCHIVE_SMOKE:-0}"
WINS_MACOS_ARCHIVE_SMOKE="${WINS_MACOS_ARCHIVE_SMOKE:-0}"
WINS_IOS_DEBUGGING_EXPORT_SMOKE="${WINS_IOS_DEBUGGING_EXPORT_SMOKE:-0}"
WINS_MACOS_DEBUGGING_EXPORT_SMOKE="${WINS_MACOS_DEBUGGING_EXPORT_SMOKE:-0}"
WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE="${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE:-0}"
WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE="${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}"
WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE="${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE:-0}"
WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE="${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}"
WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE="${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}"
WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE="${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}"
WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE="${WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE:-0}"
WINS_MACOS_APP_STORE_PKG_INSTALL_GUI_AUTH="${WINS_MACOS_APP_STORE_PKG_INSTALL_GUI_AUTH:-0}"
WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY="${WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY:-0}"
WINS_MACOS_APP_STORE_PKG_INSTALL_SYSTEM_TARGET="${WINS_MACOS_APP_STORE_PKG_INSTALL_SYSTEM_TARGET:-0}"
WINS_MACOS_APP_STORE_PKG_INSTALL_RUN_AS_USER="${WINS_MACOS_APP_STORE_PKG_INSTALL_RUN_AS_USER:-${SUDO_USER:-}}"
WINS_MACOS_APP_STORE_PKG_INSTALL_IMAGE_SIZE="${WINS_MACOS_APP_STORE_PKG_INSTALL_IMAGE_SIZE:-512m}"
WINS_MACOS_APP_STORE_PKG_ROOT_GATE_REFRESH="${WINS_MACOS_APP_STORE_PKG_ROOT_GATE_REFRESH:-0}"
WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE="${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE:-0}"
WINS_APPLE_EXISTING_EXPORTS_SMOKE="${WINS_APPLE_EXISTING_EXPORTS_SMOKE:-0}"
WINS_APPLE_VERIFY_EXISTING_EXPORTS_ONLY="${WINS_APPLE_VERIFY_EXISTING_EXPORTS_ONLY:-0}"
WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY="${WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY:-0}"
WINS_APPLE_MANUAL_DISTRIBUTION_EXPORTS="${WINS_APPLE_MANUAL_DISTRIBUTION_EXPORTS:-1}"
WINS_APPLE_EXPORT_TIMEOUT_SECONDS="${WINS_APPLE_EXPORT_TIMEOUT_SECONDS:-900}"
WINS_APPLE_SIGNING_KEYCHAIN_PROBE="${WINS_APPLE_SIGNING_KEYCHAIN_PROBE:-0}"
WINS_APPLE_SIGNING_KEYCHAIN_PROBE_TIMEOUT_SECONDS="${WINS_APPLE_SIGNING_KEYCHAIN_PROBE_TIMEOUT_SECONDS:-20}"
WINS_APPLE_AUTOMATION_DIAGNOSTIC_TIMEOUT_SECONDS="${WINS_APPLE_AUTOMATION_DIAGNOSTIC_TIMEOUT_SECONDS:-5}"
WINS_APPLE_AUTHENTICATION_KEY_PATH="${WINS_APPLE_AUTHENTICATION_KEY_PATH:-}"
WINS_APPLE_AUTHENTICATION_KEY_ID="${WINS_APPLE_AUTHENTICATION_KEY_ID:-}"
WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID="${WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID:-}"
WINS_MACOS_DEVELOPMENT_XCCONFIG="${WINS_MACOS_DEVELOPMENT_XCCONFIG:-}"
# The identity create_signed_macos_archive signs the NON-App-Store macOS archive
# with. Added 2026-08-09; it used to be the literal "Apple Development" on the
# xcodebuild command line, which is precedence level 2 and therefore outranked
# the six pbxproj settings AND every default in macos/Runner/Configs/
# Signing.xcconfig. Consequence: a Developer ID archive was unreachable from
# this script no matter what the project said, and the failure was silent -- the
# archive succeeded, signed with a development certificate.
#
# Only WINS_MACOS_DEVELOPMENT_XCCONFIG (-xcconfig, level 1) could beat it, and
# configure_apple_macos_development_signing_args REQUIRES that file to contain
# the exact line "CODE_SIGN_IDENTITY = Apple Development", so that route cannot
# carry a Developer ID identity either. Both doors were shut.
#
# The default preserves the previous behaviour exactly. Set it in the process
# environment to sign the archive with something else, e.g.
#   WINS_APPLE_CODE_SIGN_IDENTITY="Developer ID Application" ...
# Identity NAMES are not secrets; they appear in `codesign -dv` on any shipped
# binary. Never put a password, keystore path or token in this variable.
WINS_APPLE_CODE_SIGN_IDENTITY="${WINS_APPLE_CODE_SIGN_IDENTITY:-Apple Development}"
WINS_APPLE_PRIVACY_ARCHIVE_REPORT="${WINS_APPLE_PRIVACY_ARCHIVE_REPORT:-0}"
WINS_SIGNING_DIAGNOSIS_SELFTEST="${WINS_SIGNING_DIAGNOSIS_SELFTEST:-0}"
WINS_ENGINE_ARTIFACT_SELFTEST="${WINS_ENGINE_ARTIFACT_SELFTEST:-0}"
WINS_LIVE_TUNNEL_RESULT_SELFTEST="${WINS_LIVE_TUNNEL_RESULT_SELFTEST:-0}"
WINS_REQUIRE_APPLE_ENGINE="${WINS_REQUIRE_APPLE_ENGINE:-0}"
WINS_APPLE_LIVE_TUNNEL_SMOKE="${WINS_APPLE_LIVE_TUNNEL_SMOKE:-0}"
WINS_MACOS_LIVE_TUNNEL_APP_PATH="${WINS_MACOS_LIVE_TUNNEL_APP_PATH:-}"
WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS="${WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS:-120}"
WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN="${WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN:-}"
WINS_APPLE_EXTERNAL_LEAK_AUDIT="${WINS_APPLE_EXTERNAL_LEAK_AUDIT:-0}"
WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS="${WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS:-}"
WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS="${WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS:-2}"
WINS_APPLE_FORCE_XRAY="${WINS_APPLE_FORCE_XRAY:-0}"
WINS_APPLE_EXPECT_DOUBLE_VPN="${WINS_APPLE_EXPECT_DOUBLE_VPN:-0}"
case "${WINS_APPLE_EXPECT_DOUBLE_VPN}" in
  0|1) ;;
  *) printf 'WINS_APPLE_EXPECT_DOUBLE_VPN must be 0 or 1.\n' >&2; exit 2 ;;
esac
IOS_BUNDLE_ID="${IOS_BUNDLE_ID:-org.winsvpn.app}"
IOS_DEBUG_BUNDLE_ID="${IOS_DEBUG_BUNDLE_ID:-${IOS_BUNDLE_ID}.debug}"
MACOS_BUNDLE_ID="${MACOS_BUNDLE_ID:-org.winsvpn.app}"
APPLE_BASE_APP_GROUP_ID="${APPLE_BASE_APP_GROUP_ID:-group.org.winsvpn.app}"
APPLE_APP_GROUP_ID="${APPLE_APP_GROUP_ID:-${APPLE_BASE_APP_GROUP_ID}}"
APPLE_MACOS_TEAM_ID="${APPLE_MACOS_TEAM_ID:-5YT8H4U72M}"
APPLE_MACOS_APP_GROUP_ID="${APPLE_MACOS_APP_GROUP_ID:-${APPLE_MACOS_TEAM_ID}.${APPLE_BASE_APP_GROUP_ID}}"
APPLE_ARCHIVE_DIR="${APPLE_ARCHIVE_DIR:-build/apple/archives}"
APPLE_EXPORT_DIR="${APPLE_EXPORT_DIR:-build/apple/exports}"
APPLE_UPLOAD_DIR="${APPLE_UPLOAD_DIR:-build/apple/uploads}"
APPLE_PRIVACY_REPORT_DIR="${APPLE_PRIVACY_REPORT_DIR:-build/apple/privacy}"
APPLE_RELEASE_SYMBOL_ROOT="${APPLE_RELEASE_SYMBOL_ROOT:-${ROOT_DIR}/.artifacts/private-release-symbols/apple}"
RELEASE_OBFUSCATION_CONTRACT="${RELEASE_OBFUSCATION_CONTRACT:-tools/release_obfuscation_contract.py}"
APPLE_SYMBOL_CUSTODY_TOOL="${APPLE_SYMBOL_CUSTODY_TOOL:-tools/apple_release_symbol_custody.py}"
APPLE_SUBMISSION_PACKAGE_VALIDATOR="${APPLE_SUBMISSION_PACKAGE_VALIDATOR:-tools/validate_apple_submission_package.py}"
APPLE_APP_STORE_CONNECT_AUTH_PROBE="${APPLE_APP_STORE_CONNECT_AUTH_PROBE:-tools/apple_app_store_connect_auth_probe.py}"
APPLE_RELEASE_CONTAMINATION_GATE="${APPLE_RELEASE_CONTAMINATION_GATE:-tools/apple_release_contamination_gate.py}"
XCODE_TOOLCHAIN_BIN="/Applications/Xcode.app/Contents/Developer/usr/bin"
WINS_IOS_UI_AUTOMATION_FAILURE_DETECTED=0
WINS_IOS_UI_AUTOMATION_BEST_EFFORT_CONTINUED=0
APPLE_XCODE_AUTH_ARGS=()
APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS=()
MACOS_PKG_QUARANTINED_APP_PATHS=()
MACOS_PKG_QUARANTINE_ROOT=""
PRE_RELEASE_SOURCE_SMOKE_FORBIDDEN_LANES=(
  WINS_IOS_ARCHIVE_SMOKE
  WINS_MACOS_ARCHIVE_SMOKE
  WINS_IOS_DEBUGGING_EXPORT_SMOKE
  WINS_MACOS_DEBUGGING_EXPORT_SMOKE
  WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE
  WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE
  WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE
  WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE
  WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE
  WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE
  WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE
  WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY
  WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE
  WINS_APPLE_VERIFY_EXISTING_EXPORTS_ONLY
  WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY
  WINS_APPLE_PRIVACY_ARCHIVE_REPORT
)

if [[ -x "${XCODE_TOOLCHAIN_BIN}/git" ]]; then
  export PATH="${XCODE_TOOLCHAIN_BIN}:${PATH}"
fi

cd "${ROOT_DIR}"

apple_release_identity() {
  awk '/^version:[[:space:]]*/ {print $2; exit}' pubspec.yaml
}

apple_release_symbol_dir() {
  local platform="$1"
  local identity
  identity="$(apple_release_identity)"
  [[ "${identity}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+$ ]] \
    || die "Could not read version: <semver>+<build> from pubspec.yaml for Apple symbols."
  printf '%s/%s/%s\n' "${APPLE_RELEASE_SYMBOL_ROOT}" "${platform}" "${identity}"
}

prepare_apple_release_symbols() {
  local platform="$1"
  local directory resolved resolved_root private_root
  directory="$(apple_release_symbol_dir "${platform}")"
  resolved="$("${PYTHON_BIN}" - "${directory}" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
  )"
  resolved_root="$("${PYTHON_BIN}" - "${ROOT_DIR}" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
  )"
  private_root="${resolved_root}/.artifacts/private-release-symbols"
  case "${resolved}" in
    "${private_root}"/*) ;;
    "${resolved_root}"/*)
      die "Apple release symbols inside the project must stay under .artifacts/private-release-symbols."
      ;;
  esac
  rm -rf -- "${resolved}"
  mkdir -p -- "${resolved}"
  chmod 700 "${resolved}"
  printf '%s\n' "${resolved}"
}

require_apple_release_symbols() {
  local platform="$1"
  local directory
  directory="$(apple_release_symbol_dir "${platform}")"
  [[ -d "${directory}" ]] \
    || die "Private ${platform} Flutter release-symbol directory is missing: ${directory}"
  # Xcode runs under umask 022 (App Store Connect error 90255), so gen_snapshot writes the
  # private .symbols files readable by others; take that back before anything reads them.
  chmod -R go-rwx "${directory}"
  find "${directory}" -type f -name '*.symbols' -size +63c -print -quit | grep -q . \
    || die "No non-empty private Flutter .symbols file was produced for ${platform}."
}

record_apple_release_obfuscation() {
  local platform="$1"
  local artifact="$2"
  local symbols manifest
  symbols="$(apple_release_symbol_dir "${platform}")"
  manifest="${symbols}/manifest.json"
  require_apple_release_symbols "${platform}"
  "${PYTHON_BIN}" "${RELEASE_OBFUSCATION_CONTRACT}" record \
    --platform "${platform}" \
    --symbols-dir "${symbols}" \
    --manifest "${manifest}" \
    --artifact "${artifact}"
}

record_apple_private_symbol_custody() {
  local platform="$1"
  local artifact="$2"
  local archive="$3"
  local symbols
  symbols="$(apple_release_symbol_dir "${platform}")"
  require_apple_release_symbols "${platform}"
  "${PYTHON_BIN}" "${APPLE_SYMBOL_CUSTODY_TOOL}" collect \
    --platform "${platform}" \
    --artifact "${artifact}" \
    --flutter-symbols "${symbols}" \
    --archive "${archive}" \
    --private-root "${APPLE_RELEASE_SYMBOL_ROOT}"
}

section() {
  printf '\n== %s ==\n' "$*"
}

sanitize_apple_log_output() {
  (
    cd /
    "${PYTHON_BIN}" -c '
import re
import sys

patterns = [
    (re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"), "<uuid>"),
    (re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}\b"), "<device-udid>"),
]

for line in sys.stdin:
    for pattern, replacement in patterns:
        line = pattern.sub(replacement, line)
    line = re.sub(
        r"((?:\"(?:serialNumber|ecid|udid)\"|\b(?:serialNumber|ecid|udid)\b)\s*[:=]\s*)(\"[^\"]*\"|\d+|[^,\s}]+)",
        "\\1\"<redacted>\"",
        line,
        flags=re.IGNORECASE,
    )
    sys.stdout.write(line)
'
  )
}

print_redacted_command() {
  local redact_next=0
  local arg
  local rendered='+'
  for arg in "$@"; do
    if [[ "${redact_next}" == "1" ]]; then
      rendered+=" $(printf '%q' '<redacted>')"
      redact_next=0
      continue
    fi

    case "${arg}" in
      -authenticationKeyPath|-authenticationKeyID|-authenticationKeyIssuerID)
        rendered+=" $(printf '%q' "${arg}")"
        redact_next=1
        ;;
      *)
        rendered+=" $(printf '%q' "${arg}")"
        ;;
    esac
  done
  printf '%s\n' "${rendered}" | sanitize_apple_log_output
}

require_private_apple_auth_key_file() {
  local key_path="$1"
  [[ -f "${key_path}" ]] \
    || die "App Store Connect authentication key file is not readable at WINS_APPLE_AUTHENTICATION_KEY_PATH."

  local resolved_key_path resolved_root_dir
  resolved_key_path="$("${PYTHON_BIN}" - "${key_path}" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
  )"
  resolved_root_dir="$("${PYTHON_BIN}" - "${ROOT_DIR}" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
  )"

  case "${resolved_key_path}" in
    "${resolved_root_dir}"|"${resolved_root_dir}"/*)
      die "App Store Connect authentication key file must live outside the project folder so it cannot be committed accidentally."
      ;;
  esac

  local mode
  mode="$(stat -f '%Lp' "${resolved_key_path}" 2>/dev/null || true)"
  [[ -n "${mode}" ]] || die "Could not inspect permissions for App Store Connect authentication key file."
  if (( 8#${mode} & 8#077 )); then
    die "App Store Connect authentication key file must be private to the current user. Run chmod 600 on the key file, then rerun the Apple export lane."
  fi
}

run() {
  print_redacted_command "$@"
  set +e
  "$@" 2>&1 | sanitize_apple_log_output
  local status="${PIPESTATUS[0]}"
  set -e
  return "${status}"
}

winn3_descriptor_pubkey_define_args() {
  # PUBLIC key only. Hub env is WINN3_ (no WINS_); client dart-define is WINS_ (with prefix) — crossed names are silent no-ops.
  # Reads WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3 and *_FILE, validates base64 32 bytes, emits one --dart-define per slot.
  # Never hardcodes a value; never reads a private key.
  local slot var file_var raw value
  for slot in G1 G2 G3; do
    var="WINS_WINN3_DESCRIPTOR_PUBKEY_${slot}"
    file_var="${var}_FILE"
    raw=""; value=""
    if [[ -n "${!file_var:-}" ]]; then
      if [[ ! -f "${!file_var}" || -L "${!file_var}" ]]; then
        printf 'Winn3 descriptor pubkey file missing or symbolic: %s=%s\n' "${file_var}" "${!file_var}" >&2; return 65
      fi
      raw="$(tr -d '\r\n' < "${!file_var}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      if [[ "${raw}" == --dart-define=* || "${raw}" == WINS_WINN3_DESCRIPTOR_PUBKEY_* || "${raw}" == WINN3_DESCRIPTOR_PUBKEY_* ]]; then
        printf 'Refusing %s that looks like a dart-define or hub key name: %.60s\n' "${file_var}" "${raw}" >&2; return 65
      fi
      value="${raw}"
    elif [[ -n "${!var:-}" ]]; then
      raw="${!var}"
      if [[ "${raw}" == --dart-define=* ]]; then printf 'Refusing %s that already contains --dart-define\n' "${var}" >&2; return 65; fi
      if [[ "${raw}" == WINN3_DESCRIPTOR_PUBKEY_* ]]; then printf 'Refusing %s that looks like a hub key name: %.60s\n' "${var}" "${raw}" >&2; return 65; fi
      value="$(printf '%s' "${raw}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    else
      continue
    fi
    if [[ -z "${value}" ]]; then continue; fi
    if ! printf '%s' "${value}" | python3 -c 'import base64,sys; d=base64.b64decode(sys.stdin.read().strip(),validate=True); assert len(d)==32' 2>/dev/null; then
      printf 'Winn3 descriptor pubkey %s is not valid base64 of 32 bytes: %.20s...\n' "${var}" "${value}" >&2; return 65
    fi
    printf '%s\n' "--dart-define=${var}=${value}"
  done
}

flutter_build_define_args() {
  local target_platform="${1:-}"
  # Winn3 descriptor pubkey defines are ALWAYS considered — they are public material and make a build complete.
  winn3_descriptor_pubkey_define_args || return $?
  if [[ "${WINS_APPLE_WINN3_RELEASE:-0}" == "1" ]]; then
    case "${target_platform}" in
      ios|macos)
        printf '%s\n' "--dart-define=WINS_WINN3_ENABLED_PLATFORMS=${target_platform}"
        # Owner ruling 2026-10-24: the Double VPN ciphertext relay ships on
        # every platform. iOS and macOS release builds advertise it for exactly
        # their own target, next to the standalone enable above and never
        # outside WINS_APPLE_WINN3_RELEASE=1, so local, smoke and debug builds
        # keep the AmneziaWG Double route.
        printf '%s\n' "--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=${target_platform}"
        ;;
      *)
        printf 'WINS_APPLE_WINN3_RELEASE=1 cannot identify Flutter target platform: %s\n' "${target_platform}" >&2
        return 65
        ;;
    esac
  fi
  # The rest is transport selection; kept after pubkey so log order is stable (pubkey first).
  if [[ "${WINS_APPLE_LIVE_TUNNEL_SMOKE}" != "1" \
    && "${WINS_IOS_LIVE_TUNNEL_SMOKE}" != "1" ]]; then
    if [[ "${WINS_APPLE_FORCE_XRAY}" == "1" ]]; then
      printf '%s\n' "--dart-define=WINS_FORCE_XRAY=true"
    fi
    return 0
  fi

  if [[ "${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE}" == "1" \
    || "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
    || "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE}" == "1" \
    || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" \
    || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
    || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" \
    || "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1" ]]; then
    printf 'Apple distribution archives must not compile live-tunnel smoke defines.\n' >&2
    return 65
  fi

  printf '%s\n' \
    "--dart-define=WINS_APPLE_LIVE_TUNNEL_SMOKE=true" \
    "--dart-define=WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS=${WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS}" \
    "--dart-define=WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN=${WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN}" \
    "--dart-define=WINS_APPLE_LIVE_TUNNEL_SMOKE_DOUBLE_VPN=$([[ "${WINS_APPLE_EXPECT_DOUBLE_VPN}" == "1" ]] && printf true || printf false)" \
    "--dart-define=WINS_FORCE_XRAY=$([[ "${WINS_APPLE_FORCE_XRAY}" == "1" ]] && printf true || printf false)" \
    "--dart-define=WINS_APPLE_EXTERNAL_LEAK_AUDIT=$([[ "${WINS_APPLE_EXTERNAL_LEAK_AUDIT}" == "1" ]] && printf true || printf false)" \
    "--dart-define=WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS=${WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS}" \
    "--dart-define=WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS=${WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS}"
}

verify_apple_release_contamination() {
  local platform="$1"
  local artifact="$2"
  [[ -f "${APPLE_RELEASE_CONTAMINATION_GATE}" ]] \
    || die "Apple release contamination gate is missing."
  "${PYTHON_BIN}" "${APPLE_RELEASE_CONTAMINATION_GATE}" \
    --platform "${platform}" "${artifact}" \
    || die "Apple release artifact contains or cannot disprove live-smoke contamination."
}

verify_apple_release_dart_defines() {
  local xcconfig="$1"
  "${PYTHON_BIN}" "${APPLE_RELEASE_CONTAMINATION_GATE}" \
    --verify-xcconfig "${xcconfig}" \
    || die "Apple release build metadata contains or cannot disprove live-smoke contamination."
}

log_winn3_descriptor_pubkey_status_for_defines() {
  local count=0 arg
  for arg in "$@"; do
    [[ "${arg}" == --dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_* ]] && count=$((count+1))
  done
  if [[ "${count}" -gt 0 ]]; then
    printf 'APPLE BUILD: Winn3 descriptor verification ring PRESENT (%s slot(s) compiled in)\n' "${count}"
  else
    printf 'APPLE BUILD WARNING: Winn3 descriptor verification ring ABSENT — no WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3 supplied.\n' >&2
    printf 'APPLE BUILD WARNING: This build will report descriptor-no-verification-keys-compiled and standalone is unavailable.\n' >&2
    printf 'APPLE BUILD WARNING: Set WINS_WINN3_DESCRIPTOR_PUBKEY_G1 from tools/winn3_sign_descriptor.py pubkey to produce a complete build.\n' >&2
    if [[ "${WINS_REQUIRE_WINN3_DESCRIPTOR_PUBKEY:-0}" == "1" ]]; then printf 'Winn3 descriptor pubkey required but missing\n' >&2; return 65; fi
  fi
}

run_flutter_build() {
  local args=("$@")
  local target_platform="${args[1]:-}"
  local define define_output collected=()
  define_output="$(flutter_build_define_args "${target_platform}")" || return $?
  while IFS= read -r define; do
    [[ -n "${define}" ]] && collected+=("${define}")
  done <<< "${define_output}"
  # Bash 3.2 (/bin/bash) treats "${empty[@]}" as unbound under set -u and has
  # no lowercase parameter expansion; the ${name[@]+...} guards and tr keep
  # this function portable.
  log_winn3_descriptor_pubkey_status_for_defines ${collected[@]+"${collected[@]}"} || return $?
  if [[ "${WINS_APPLE_WINN3_RELEASE:-0}" == "1" ]]; then
    local pubkey_defines=() ring_sha256 expected_ring_lower
    for define in ${collected[@]+"${collected[@]}"}; do
      [[ "${define}" == --dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_* ]] && pubkey_defines+=("${define}")
    done
    ring_sha256="$("${PYTHON_BIN}" "${ROOT_DIR}/tools/winn3_descriptor_ring_identity.py" ${pubkey_defines[@]+"${pubkey_defines[@]}"})" || return $?
    local expected_ring_sha256="${WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256:-}"
    expected_ring_lower="$(printf '%s' "${expected_ring_sha256}" | /usr/bin/tr '[:upper:]' '[:lower:]')"
    [[ "${expected_ring_sha256}" =~ ^[0-9a-fA-F]{64}$ &&
       "${expected_ring_lower}" == "${ring_sha256}" ]] || {
      printf 'Reviewed Winn3 descriptor ring identity mismatch. Computed=%s\n' "${ring_sha256}" >&2
      return 65
    }
    collected+=("--dart-define=WINS_WINN3_DESCRIPTOR_RING_SHA256=${ring_sha256}")
  fi
  args+=(${collected[@]+"${collected[@]}"})
  run "${FLUTTER_BIN}" "${args[@]}"
}

force_macos_flutter_assemble() {
  rm -f macos/Flutter/ephemeral/tripwire
  local local_paths=(
    .dart_tool/flutter_build
    build/macos/Build/Products/Debug/App.framework
  )
  if [[ "${WINS_MACOS_LAUNCH_RELEASE}" != "1" ]]; then
    local_paths+=(
      build/macos
      build/macos/Build/Products/Release/App.framework
    )
  fi
  rm -rf "${local_paths[@]}"

  if [[ "${WINS_MACOS_LAUNCH_RELEASE}" == "1" ]]; then
    find "${HOME}/Library/Developer/Xcode/DerivedData" \
      \( -path "*/Build/Products/Debug/Win's VPN.app/Contents/Frameworks/App.framework" \
      -o -path '*/Build/Products/Debug/wins_vpn.app/Contents/Frameworks/App.framework' \) \
      -prune \
      -exec rm -rf {} + 2>/dev/null || true
    find "${HOME}/Library/Developer/Xcode/DerivedData" \
      \( -path "*/Build/Products/Debug/Win's VPN.app" \
      -o -path '*/Build/Products/Debug/wins_vpn.app' \
      -o -path '*/Build/Products/Debug/App.framework' \) \
      -prune \
      -exec rm -rf {} + 2>/dev/null || true
  else
    find "${HOME}/Library/Developer/Xcode/DerivedData" \
      \( -path "*/Build/Products/*/Win's VPN.app/Contents/Frameworks/App.framework" \
      -o -path '*/Build/Products/*/wins_vpn.app/Contents/Frameworks/App.framework' \) \
      -prune \
      -exec rm -rf {} + 2>/dev/null || true
    find "${HOME}/Library/Developer/Xcode/DerivedData" \
      \( -path "*/Build/Products/Debug/Win's VPN.app" \
      -o -path "*/Build/Products/Release/Win's VPN.app" \
      -o -path '*/Build/Products/Debug/wins_vpn.app' \
      -o -path '*/Build/Products/Release/wins_vpn.app' \
      -o -path '*/Build/Products/Debug/App.framework' \
      -o -path '*/Build/Products/Release/App.framework' \) \
      -prune \
      -exec rm -rf {} + 2>/dev/null || true
  fi
}

explain_apple_signing_failure() {
  local log_file="$1"

  if grep -Eiq 'Personal development teams.*Network Extensions capability|do not support the Network Extensions capability' "${log_file}"; then
    printf '\nApple signing diagnosis: the selected Apple team cannot create Network Extension provisioning profiles. Use a paid Apple Developer Program team with Packet Tunnel / Network Extension capability enabled, then create or download matching app and PacketTunnel provisioning profiles.\n' >&2
    return 0
  fi

  if grep -Eiq "Device .+ isn't registered in your developer account|device must be registered in order to be included in a provisioning profile" "${log_file}"; then
    printf '\nApple signing diagnosis: this Mac is not registered in the selected Apple Developer team. Register the Mac provisioning UDID under Certificates, Identifiers & Profiles > Devices, then rerun the signed macOS lane so Xcode can create Mac App Development profiles for the app and PacketTunnel extension.\n' >&2
    return 0
  fi

  if grep -Eiq 'exportArchive No Accounts|No Accounts' "${log_file}"; then
    printf '\nApple signing diagnosis: Xcode could not access an Apple Developer account while exporting the archive. Unlock this Mac if needed, open Xcode > Settings > Accounts, refresh the paid Win'\''s VPN team, or rerun with WINS_APPLE_AUTHENTICATION_KEY_PATH, WINS_APPLE_AUTHENTICATION_KEY_ID, and WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID set to an App Store Connect API key. For release-testing exports, also create/download device-scoped distribution profiles for the host app and PacketTunnel extension.\n' >&2
    return 0
  fi

  if grep -Eiq "No profiles for '.+' were found|couldn't find any .* provisioning profiles|There are no .* provisioning profiles matching|No .* provisioning profiles matching" "${log_file}"; then
    printf '\nApple signing diagnosis: matching provisioning profiles are missing for one or more Win'\''s VPN app or PacketTunnel bundle identifiers. Create the required development and distribution profiles with Packet Tunnel, App Groups, and keychain access groups, refresh Xcode accounts, then rerun the signed lane.\n' >&2
    return 0
  fi

  if grep -Eiq 'requires? signing with a development certificate|No valid Apple code-signing identity' "${log_file}"; then
    printf '\nApple signing diagnosis: a development signing certificate is required for entitlement-bearing Apple targets. Sign in to Xcode and download or create an Apple Development certificate for the selected team.\n' >&2
    return 0
  fi
}

explain_ios_ui_automation_failure() {
  local log_file="$1"

  if grep -Eiq 'Unlock .+ to Continue|device is locked|Run Destination Preflight: The destination is not ready' "${log_file}"; then
    WINS_IOS_UI_AUTOMATION_FAILURE_DETECTED=1
    printf '\niOS UI automation diagnosis: Xcode could not start the Win'\''s VPN UI test runner because the iPhone is locked or not ready for UI automation. Unlock the iPhone, keep it on the home screen, approve any Xcode/device prompts, and rerun with WINS_IOS_APPROVE_VPN_PERMISSION=1.\n' >&2
    return 0
  fi

  if grep -Eiq 'Timed out while enabling automation mode|failed to initialize for UI testing|test runner failed to initialize for UI testing' "${log_file}"; then
    WINS_IOS_UI_AUTOMATION_FAILURE_DETECTED=1
    printf '\niOS UI automation diagnosis: Xcode built and installed the Win'\''s VPN UI test runner, but the iPhone did not enable XCTest automation mode. Keep the iPhone unlocked and approve any device prompt for Xcode UI automation, app data separation, or developer testing, and confirm Settings > Developer > UI Automation is enabled if that toggle is present. If no prompt is visible, reconnect USB and reboot the iPhone before retrying with WINS_IOS_APPROVE_VPN_PERMISSION=1.\n' >&2
    return 0
  fi
}

explain_ios_device_launch_failure() {
  local log_file="$1"

  if grep -Eiq 'Unable to launch .+ because the device was not, or could not be, unlocked|BSErrorCodeDescription = Locked|reason: Locked' "${log_file}"; then
    printf '\niOS device launch diagnosis: the app was installed, but the iPhone is locked so SpringBoard refused to launch it. Unlock the iPhone or use iPhone Mirroring from an unlocked Mac session, then rerun with WINS_IOS_LAUNCH=1.\n' >&2
    return 0
  fi
}

run_with_signing_diagnostics() {
  local log_file
  log_file="$(mktemp "${TMPDIR:-/tmp}/wins-apple-signing.XXXXXX")"
  local timeout_seconds="${WINS_SIGNING_COMMAND_TIMEOUT_SECONDS:-0}"
  local timed_out=0

  print_redacted_command "$@"
  set +e
  local status
  if [[ "${timeout_seconds}" =~ ^[0-9]+$ && "${timeout_seconds}" -gt 0 ]]; then
    "$@" >"${log_file}" 2>&1 &
    local command_pid="$!"
    local start_seconds="${SECONDS}"
    while kill -0 "${command_pid}" >/dev/null 2>&1; do
      if (( SECONDS - start_seconds >= timeout_seconds )); then
        timed_out=1
        kill_process_tree "${command_pid}"
        sleep 2
        if kill -0 "${command_pid}" >/dev/null 2>&1; then
          kill_process_tree "${command_pid}" KILL
        fi
        break
      fi
      sleep 1
    done
    wait "${command_pid}" >/dev/null 2>&1
    status="$?"
    sanitize_apple_log_output < "${log_file}"
  else
    "$@" 2>&1 | tee "${log_file}" | sanitize_apple_log_output
    status="${PIPESTATUS[0]}"
  fi
  set -e

  if [[ "${timed_out}" == "1" ]]; then
    printf '\nApple signing diagnosis: the signing/export command did not finish within %s seconds. If a SecurityAgent or keychain access prompt is waiting, unlock this Mac and choose Always Allow for the Apple signing certificate private key, then rerun the export lane.\n' "${timeout_seconds}" >&2
    print_keychain_prompt_state >&2
    status=124
  fi

  if [[ "${status}" -ne 0 ]]; then
    explain_apple_signing_failure "${log_file}"
  fi

  rm -f "${log_file}"
  return "${status}"
}

kill_process_tree() {
  local pid="$1"
  local signal="${2:-TERM}"
  local child

  while IFS= read -r child; do
    [[ -n "${child}" ]] || continue
    kill_process_tree "${child}" "${signal}"
  done < <(pgrep -P "${pid}" 2>/dev/null || true)

  kill "-${signal}" "${pid}" >/dev/null 2>&1 || true
}

run_with_export_signing_diagnostics() {
  WINS_SIGNING_COMMAND_TIMEOUT_SECONDS="${WINS_APPLE_EXPORT_TIMEOUT_SECONDS}" \
    run_with_signing_diagnostics "$@"
}

run_with_ios_device_launch_diagnostics() {
  local log_file
  log_file="$(mktemp "${TMPDIR:-/tmp}/wins-ios-device-launch.XXXXXX")"

  print_redacted_command "$@"
  set +e
  "$@" 2>&1 | tee "${log_file}" | sanitize_apple_log_output
  local status="${PIPESTATUS[0]}"
  set -e

  if [[ "${status}" -ne 0 ]]; then
    explain_apple_signing_failure "${log_file}"
    explain_ios_device_launch_failure "${log_file}"
  fi

  rm -f "${log_file}"
  return "${status}"
}

run_with_ios_ui_automation_diagnostics() {
  local log_file
  log_file="$(mktemp "${TMPDIR:-/tmp}/wins-ios-ui-automation.XXXXXX")"
  WINS_IOS_UI_AUTOMATION_FAILURE_DETECTED=0

  print_redacted_command "$@"
  set +e
  "$@" >"${log_file}" 2>&1 &
  local command_pid="$!"
  local start_seconds="${SECONDS}"
  local timed_out=0
  while kill -0 "${command_pid}" >/dev/null 2>&1; do
    if (( SECONDS - start_seconds >= WINS_IOS_UI_AUTOMATION_TIMEOUT_SECONDS )); then
      timed_out=1
      kill "${command_pid}" >/dev/null 2>&1 || true
      sleep 2
      if kill -0 "${command_pid}" >/dev/null 2>&1; then
        kill -9 "${command_pid}" >/dev/null 2>&1 || true
      fi
      break
    fi
    sleep 1
  done
  wait "${command_pid}" >/dev/null 2>&1
  local status="$?"
  set -e

  sanitize_apple_log_output < "${log_file}"

  if [[ "${timed_out}" == "1" ]]; then
    WINS_IOS_UI_AUTOMATION_FAILURE_DETECTED=1
    printf '\niOS UI automation diagnosis: Xcode UI automation did not finish within %s seconds. The iPhone is usually locked, waiting for a local prompt, or unable to enter XCTest automation mode. Unlock the iPhone, keep it awake, approve any Xcode/device prompts, and rerun with WINS_IOS_APPROVE_VPN_PERMISSION=1.\n' "${WINS_IOS_UI_AUTOMATION_TIMEOUT_SECONDS}" >&2
    status=124
  fi

  if [[ "${status}" -ne 0 ]]; then
    explain_apple_signing_failure "${log_file}"
    explain_ios_ui_automation_failure "${log_file}"
  fi

  rm -f "${log_file}"
  return "${status}"
}

assert_signing_diagnosis() {
  local log_file="$1"
  local expected="$2"
  local output

  output="$(explain_apple_signing_failure "${log_file}" 2>&1)"
  if [[ "${output}" != *"${expected}"* ]]; then
    die "Apple signing diagnosis self-test expected '${expected}', got '${output}'."
  fi
}

run_signing_diagnostics_selftest() {
  section "Apple Signing Diagnostics Self-Test"

  local log_file
  log_file="$(mktemp "${TMPDIR:-/tmp}/wins-apple-signing-selftest.XXXXXX")"
  trap 'rm -f "${log_file}"' RETURN
  local output

  printf '%s\n' \
    'Error (Xcode): Cannot create a iOS App Development provisioning profile for "org.winsvpn.app". Personal development teams, including "Example", do not support the Network Extensions capability.' \
    > "${log_file}"
  assert_signing_diagnosis "${log_file}" "cannot create Network Extension provisioning profiles"

  printf '%s\n' \
    "Error (Xcode): No profiles for 'org.winsvpn.app.PacketTunnel' were found: Xcode couldn't find any iOS App Development provisioning profiles matching 'org.winsvpn.app.PacketTunnel'." \
    > "${log_file}"
  assert_signing_diagnosis "${log_file}" "matching provisioning profiles are missing"

  printf '%s\n' \
    "/Users/winsvpn/Downloads/wins_vpn/macos/Runner.xcodeproj: error: Device \"Win's's MacBook Pro\" isn't registered in your developer account. The device must be registered in order to be included in a provisioning profile. (in target 'Runner' from project 'Runner')" \
    > "${log_file}"
  assert_signing_diagnosis "${log_file}" "this Mac is not registered"

  printf '%s\n' \
    'error: exportArchive No Accounts' \
    "error: exportArchive No profiles for 'org.winsvpn.app' were found" \
    > "${log_file}"
  assert_signing_diagnosis "${log_file}" "could not access an Apple Developer account"

  printf '%s\n' \
    'error: "Runner" has entitlements that require signing with a development certificate.' \
    > "${log_file}"
  assert_signing_diagnosis "${log_file}" "development signing certificate is required"

  printf '%s\n' \
    'RunnerUITests-Runner encountered an error: Failed to initialize for UI testing: Timed out while enabling automation mode.' \
    > "${log_file}"
  output="$(explain_ios_ui_automation_failure "${log_file}" 2>&1)"
  if [[ "${output}" != *"did not enable XCTest automation mode"* ]]; then
    die "Apple signing diagnosis self-test expected iOS UI automation diagnosis, got '${output}'."
  fi

  printf '%s\n' \
    'Error Domain=com.apple.dt.deviceprep Code=-3 "Unlock Owner’s iPhone to Continue" UserInfo={NSLocalizedRecoverySuggestion=Xcode cannot launch RunnerUITests on Owner’s iPhone because the device is locked.}' \
    > "${log_file}"
  output="$(explain_ios_ui_automation_failure "${log_file}" 2>&1)"
  if [[ "${output}" != *"iPhone is locked or not ready for UI automation"* ]]; then
    die "Apple signing diagnosis self-test expected locked iOS device diagnosis, got '${output}'."
  fi

  printf '%s\n' \
    'Unable to launch org.winsvpn.app because the device was not, or could not be, unlocked.' \
    'BSErrorCodeDescription = Locked' \
    > "${log_file}"
  output="$(explain_ios_device_launch_failure "${log_file}" 2>&1)"
  if [[ "${output}" != *"SpringBoard refused to launch it"* ]]; then
    die "Apple signing diagnosis self-test expected locked iOS launch diagnosis, got '${output}'."
  fi

  printf '%s\n' 'error: unrelated Swift compile failure' > "${log_file}"
  output="$(explain_apple_signing_failure "${log_file}" 2>&1)"
  if [[ -n "${output}" ]]; then
    die "Apple signing diagnosis self-test expected no diagnosis for unrelated output, got '${output}'."
  fi

  output="$(
    print_redacted_command \
      xcodebuild \
      -authenticationKeyPath /tmp/AuthKey_SECRET_PRIVATE.p8 \
      -authenticationKeyID SECRETKEYID \
      -authenticationKeyIssuerID SECRETISSUERID \
      -allowProvisioningUpdates
  )"
  if [[ "${output}" == *"SECRET"* || "${output}" == *"AuthKey_SECRET_PRIVATE.p8"* ]]; then
    die "Apple signing diagnosis self-test leaked App Store Connect authentication key command arguments: ${output}"
  fi
  if [[ "${output}" != *"redacted"* ]]; then
    die "Apple signing diagnosis self-test expected redacted authentication key command arguments, got '${output}'."
  fi

  set +e
  output="$(
    (
      WINS_APPLE_AUTHENTICATION_KEY_PATH="${ROOT_DIR}/tools/apple_runtime_smoke.sh"
      WINS_APPLE_AUTHENTICATION_KEY_ID="SELFTESTKEY"
      WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID="SELFTESTISSUER"
      configure_apple_xcode_auth_args
    ) 2>&1
  )"
  local auth_status="$?"
  set -e
  if [[ "${auth_status}" == "0" || "${output}" != *"outside the project folder"* ]]; then
    die "Apple signing diagnosis self-test expected project-local auth key rejection, status=${auth_status}, output='${output}'."
  fi

  local loose_auth_key
  loose_auth_key="$(mktemp "${TMPDIR:-/tmp}/wins-apple-auth-loose.XXXXXX")"
  printf '%s\n' 'not-a-real-private-key' > "${loose_auth_key}"
  chmod 644 "${loose_auth_key}"
  set +e
  output="$(
    (
      WINS_APPLE_AUTHENTICATION_KEY_PATH="${loose_auth_key}"
      WINS_APPLE_AUTHENTICATION_KEY_ID="SELFTESTKEY"
      WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID="SELFTESTISSUER"
      configure_apple_xcode_auth_args
    ) 2>&1
  )"
  auth_status="$?"
  set -e
  rm -f "${loose_auth_key}"
  if [[ "${auth_status}" == "0" || "${output}" != *"chmod 600"* ]]; then
    die "Apple signing diagnosis self-test expected loose auth key permission rejection, status=${auth_status}, output='${output}'."
  fi

  local private_auth_key
  private_auth_key="$(mktemp "${TMPDIR:-/tmp}/wins-apple-auth-private.XXXXXX")"
  printf '%s\n' 'not-a-real-private-key' > "${private_auth_key}"
  chmod 600 "${private_auth_key}"
  WINS_APPLE_AUTHENTICATION_KEY_PATH="${private_auth_key}" \
  WINS_APPLE_AUTHENTICATION_KEY_ID="SELFTESTKEY" \
  WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID="SELFTESTISSUER" \
    configure_apple_xcode_auth_args
  require_app_store_connect_upload_auth
  rm -f "${private_auth_key}"
  if [[ "${#APPLE_XCODE_AUTH_ARGS[@]}" -ne 6 ]]; then
    die "Apple signing diagnosis self-test expected configured App Store Connect auth args."
  fi
  APPLE_XCODE_AUTH_ARGS=()

  set +e
  output="$(
    (
      WINS_MACOS_DEVELOPMENT_XCCONFIG="${ROOT_DIR}/macos/Flutter/Flutter-Debug.xcconfig"
      configure_apple_macos_development_signing_args
    ) 2>&1
  )"
  local project_xcconfig_status="$?"
  set -e
  if [[ "${project_xcconfig_status}" == "0" || "${output}" != *"outside the project folder"* ]]; then
    die "Apple signing diagnosis self-test expected project-local macOS xcconfig rejection, status=${project_xcconfig_status}, output='${output}'."
  fi

  local private_macos_xcconfig
  private_macos_xcconfig="$(mktemp "${TMPDIR:-/tmp}/wins-macos-signing.XXXXXX.xcconfig")"
  cat > "${private_macos_xcconfig}" <<'XCCONFIG'
CODE_SIGN_STYLE = Manual
DEVELOPMENT_TEAM = 5YT8H4U72M
CODE_SIGN_IDENTITY = Apple Development
WINS_PROFILE_Runner = Test Runner Profile
WINS_PROFILE_PacketTunnel = Test PacketTunnel Profile
PROVISIONING_PROFILE_SPECIFIER = $(WINS_PROFILE_$(TARGET_NAME))
XCCONFIG
  chmod 600 "${private_macos_xcconfig}"
  WINS_MACOS_DEVELOPMENT_XCCONFIG="${private_macos_xcconfig}"
  configure_apple_macos_development_signing_args
  rm -f "${private_macos_xcconfig}"
  if [[ "${#APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS[@]}" -ne 2 \
    || "${APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS[0]}" != "-xcconfig" ]]; then
    die "Apple signing diagnosis self-test expected configured external macOS development xcconfig args."
  fi
  APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS=()
  WINS_MACOS_DEVELOPMENT_XCCONFIG=""

  local app_store_archive_test_dir app_store_archive_options app_store_archive_xcconfig
  app_store_archive_test_dir="$(mktemp -d "${TMPDIR:-/tmp}/wins-macos-app-store-archive-selftest.XXXXXX")"
  app_store_archive_options="${app_store_archive_test_dir}/ExportOptions.plist"
  app_store_archive_xcconfig="${app_store_archive_test_dir}/ArchiveSigning.xcconfig"
  "${PYTHON_BIN}" - "${app_store_archive_options}" <<'PY'
import plistlib
import sys
from pathlib import Path

Path(sys.argv[1]).write_bytes(plistlib.dumps({
    "signingStyle": "manual",
    "signingCertificate": "A" * 40,
    "provisioningProfiles": {
        "org.winsvpn.app": "Win's VPN Mac App Store",
        "org.winsvpn.app.PacketTunnel": "Win's VPN Mac PacketTunnel App Store",
    },
}))
PY
  write_macos_app_store_archive_xcconfig \
    "${app_store_archive_options}" \
    "${app_store_archive_xcconfig}"
  if ! grep -q '^CODE_SIGN_STYLE = Manual$' "${app_store_archive_xcconfig}" \
    || ! grep -q '^CODE_SIGN_IDENTITY = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$' "${app_store_archive_xcconfig}" \
    || ! grep -q '^WINS_PROFILE_Runner = Win'"'"'s VPN Mac App Store$' "${app_store_archive_xcconfig}" \
    || ! grep -q '^WINS_PROFILE_PacketTunnel = Win'"'"'s VPN Mac PacketTunnel App Store$' "${app_store_archive_xcconfig}" \
    || ! grep -q '^PROVISIONING_PROFILE_SPECIFIER = \$(WINS_PROFILE_\$(TARGET_NAME))$' "${app_store_archive_xcconfig}"; then
    rm -rf "${app_store_archive_test_dir}"
    die "Apple signing diagnosis self-test expected a target-aware macOS App Store archive xcconfig."
  fi
  local app_store_archive_mode
  app_store_archive_mode="$(stat -f '%Lp' "${app_store_archive_xcconfig}" 2>/dev/null || true)"
  if [[ "${app_store_archive_mode}" != "600" ]]; then
    rm -rf "${app_store_archive_test_dir}"
    die "Apple signing diagnosis self-test expected mode 600 for the macOS App Store archive xcconfig."
  fi

  "${PYTHON_BIN}" - "${app_store_archive_options}" <<'PY'
import plistlib
import sys
from pathlib import Path

path = Path(sys.argv[1])
options = plistlib.loads(path.read_bytes())
options["provisioningProfiles"]["org.winsvpn.app"] = "Unsafe $(HOME) Profile"
path.write_bytes(plistlib.dumps(options))
PY
  set +e
  output="$(write_macos_app_store_archive_xcconfig \
    "${app_store_archive_options}" \
    "${app_store_archive_xcconfig}" 2>&1)"
  local unsafe_archive_xcconfig_status="$?"
  set -e
  rm -rf "${app_store_archive_test_dir}"
  if [[ "${unsafe_archive_xcconfig_status}" == "0" \
    || "${output}" != *"unsafe xcconfig characters"* ]]; then
    die "Apple signing diagnosis self-test expected unsafe macOS App Store profile-name rejection, status=${unsafe_archive_xcconfig_status}, output='${output}'."
  fi

  set +e
  output="$(require_app_store_connect_upload_auth 2>&1)"
  local upload_auth_status="$?"
  set -e
  if [[ "${upload_auth_status}" == "0" || "${output}" != *"App Store Connect upload lanes require"* ]]; then
    die "Apple signing diagnosis self-test expected missing upload auth rejection, status=${upload_auth_status}, output='${output}'."
  fi

  local validator_probe
  validator_probe="$(mktemp "${TMPDIR:-/tmp}/wins-apple-submission-validator.XXXXXX.py")"
  printf '%s\n' 'print("validator-ok")' > "${validator_probe}"
  set +e
  output="$(APPLE_SUBMISSION_PACKAGE_VALIDATOR="${validator_probe}" require_valid_apple_submission_package_for_upload 2>&1)"
  local package_status="$?"
  set -e
  rm -f "${validator_probe}"
  if [[ "${package_status}" != "0" || "${output}" != *"validator-ok"* ]]; then
    die "Apple signing diagnosis self-test expected upload lanes to run the full Apple submission package validator, status=${package_status}, output='${output}'."
  fi

  if ! (
    WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE=1
    WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE=0
    WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE=0
    app_store_connect_upload_lane_requested
  ); then
    die "Apple signing diagnosis self-test expected iOS internal TestFlight upload lane detection."
  fi

  if ! (
    WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE=0
    WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE=1
    WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE=0
    app_store_connect_upload_lane_requested
  ); then
    die "Apple signing diagnosis self-test expected iOS App Store Connect upload lane detection."
  fi

  if ! (
    WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE=0
    WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE=0
    WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE=1
    app_store_connect_upload_lane_requested
  ); then
    die "Apple signing diagnosis self-test expected macOS App Store Connect upload lane detection."
  fi

  if (
    WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE=0
    WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE=0
    WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE=0
    WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE=1
    WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE=1
    app_store_connect_upload_lane_requested
  ); then
    die "Apple signing diagnosis self-test must not classify local export lanes as App Store Connect upload lanes."
  fi

  if ! (
    WINS_APPLE_PRIVACY_ARCHIVE_REPORT=0
    WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE=1
    WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE=0
    WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE=0
    force_archive_privacy_report_for_app_store_upload
    [[ "${WINS_APPLE_PRIVACY_ARCHIVE_REPORT}" == "1" ]]
  ); then
    die "Apple signing diagnosis self-test expected upload lanes to force the archive privacy report."
  fi

  if (
    WINS_APPLE_PRIVACY_ARCHIVE_REPORT=0
    WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE=0
    WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE=0
    WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE=0
    WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE=1
    WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE=1
    force_archive_privacy_report_for_app_store_upload
    [[ "${WINS_APPLE_PRIVACY_ARCHIVE_REPORT}" == "1" ]]
  ); then
    die "Apple signing diagnosis self-test must not force the archive privacy report for local-only exports."
  fi

  if [[ "$(macos_pkg_install_authorization_mode_for_values 0 0 0)" != "root" ]]; then
    die "Apple signing diagnosis self-test expected macOS package install root authorization mode."
  fi
  if [[ "$(macos_pkg_install_authorization_mode_for_values 501 1 0)" != "sudo" ]]; then
    die "Apple signing diagnosis self-test expected macOS package install sudo authorization mode."
  fi
  if [[ "$(macos_pkg_install_authorization_mode_for_values 501 0 1)" != "gui" ]]; then
    die "Apple signing diagnosis self-test expected macOS package install GUI authorization mode."
  fi
  if [[ "$(macos_pkg_install_authorization_mode_for_values 501 0 0)" != "missing" ]]; then
    die "Apple signing diagnosis self-test expected macOS package install missing authorization mode."
  fi

  local prefs_plist
  prefs_plist="$(mktemp "${TMPDIR:-/tmp}/wins-apple-team-prefs.XXXXXX")"
  "${PYTHON_BIN}" - "${prefs_plist}" <<'PY'
import plistlib
import sys
from pathlib import Path

payload = {
    "IDEProvisioningTeamByIdentifier": {
        "account-id": [
            {
                "teamID": "FREE12345",
                "teamName": "Example (Personal Team)",
                "teamType": "Personal Team",
                "isFreeProvisioningTeam": True,
            },
            {
                "teamID": "PAID12345",
                "teamName": "Example Inc",
                "teamType": "Company/Organization",
                "isFreeProvisioningTeam": False,
            },
        ]
    }
}
Path(sys.argv[1]).write_bytes(plistlib.dumps(payload))
PY
  local free_ids
  free_ids="$(XCODE_TEAM_PREFS_PLIST="${prefs_plist}" xcode_free_provisioning_team_ids)"
  rm -f "${prefs_plist}"
  if [[ "${free_ids}" != "FREE12345" ]]; then
    die "Apple signing diagnosis self-test expected free team FREE12345, got '${free_ids}'."
  fi

  local project_file
  project_file="$(mktemp "${TMPDIR:-/tmp}/wins-apple-team-project.XXXXXX")"
  printf '%s\n' 'DEVELOPMENT_TEAM = FREE12345;' > "${project_file}"
  local project_teams
  project_teams="$(xcode_project_development_team_ids "${project_file}")"
  rm -f "${project_file}"
  if [[ "${project_teams}" != "FREE12345" ]]; then
    die "Apple signing diagnosis self-test expected project team FREE12345, got '${project_teams}'."
  fi

  printf 'Apple signing diagnostics self-test passed.\n'
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

resolve_reviewed_flutter_bin() {
  local configured="${FLUTTER_BIN}" candidate
  if [[ -n "${configured}" ]]; then
    if [[ "${configured}" == */* ]]; then
      [[ -x "${configured}" ]] || return 1
      printf '%s\n' "${configured}"
      return 0
    fi
    candidate="$(command -v "${configured}" 2>/dev/null || true)"
    [[ -n "${candidate}" && -x "${candidate}" ]] || return 1
    printf '%s\n' "${candidate}"
    return 0
  fi

  candidate="${HOME}/Library/Application Support/WinsVPN/toolchains/flutter-${REQUIRED_FLUTTER_VERSION}-extract/flutter/bin/flutter"
  if [[ -x "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
    return 0
  fi

  candidate="$(command -v flutter 2>/dev/null || true)"
  [[ -n "${candidate}" && -x "${candidate}" ]] || return 1
  printf '%s\n' "${candidate}"
}

require_reviewed_flutter_toolchain() {
  local resolved identity flutter_version flutter_revision flutter_dir
  resolved="$(resolve_reviewed_flutter_bin || true)"
  [[ -n "${resolved}" && -x "${resolved}" ]] \
    || die "Reviewed Flutter ${REQUIRED_FLUTTER_VERSION} is unavailable. Install it under ~/Library/Application Support/WinsVPN/toolchains or set FLUTTER_BIN explicitly."
  FLUTTER_BIN="${resolved}"
  export FLUTTER_BIN
  flutter_dir="$(dirname "${FLUTTER_BIN}")"
  case ":${PATH}:" in
    *":${flutter_dir}:"*) ;;
    *) PATH="${flutter_dir}:${PATH}" ;;
  esac
  export PATH
  require_cmd "${PYTHON_BIN}"
  identity="$("${FLUTTER_BIN}" --version --machine 2>/dev/null | "${PYTHON_BIN}" -c '
import json
import sys
raw = sys.stdin.read()
start = raw.find("{")
end = raw.rfind("}")
if start < 0 or end < start:
    raise SystemExit("Flutter version JSON was not found")
value = json.loads(raw[start : end + 1])
print(value.get("frameworkVersion", ""), value.get("frameworkRevision", ""))
')" || die "Unable to read the reviewed Flutter toolchain identity."
  read -r flutter_version flutter_revision <<<"${identity}"
  [[ "${flutter_version}" == "${REQUIRED_FLUTTER_VERSION}" \
    && "${flutter_revision}" == "${REQUIRED_FLUTTER_REVISION}" ]] \
    || die "Apple builds require Flutter ${REQUIRED_FLUTTER_VERSION} (${REQUIRED_FLUTTER_REVISION}); found ${flutter_version:-unknown} (${flutter_revision:-unknown})."
  printf 'Reviewed Flutter toolchain: %s (%s) at %s\n' \
    "${flutter_version}" "${flutter_revision}" "${FLUTTER_BIN}"
}

resolve_reviewed_pod_bin() {
  local configured="${POD_BIN}" candidate ruby_bin gem_user_dir
  if [[ -n "${configured}" ]]; then
    if [[ "${configured}" == */* ]]; then
      [[ -x "${configured}" ]] || return 1
      printf '%s\n' "${configured}"
      return 0
    fi
    candidate="$(command -v "${configured}" 2>/dev/null || true)"
    [[ -n "${candidate}" && -x "${candidate}" ]] || return 1
    printf '%s\n' "${candidate}"
    return 0
  fi

  candidate="$(command -v pod 2>/dev/null || true)"
  if [[ -n "${candidate}" && -x "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
    return 0
  fi

  ruby_bin="$(command -v ruby 2>/dev/null || true)"
  if [[ -n "${ruby_bin}" ]]; then
    gem_user_dir="$("${ruby_bin}" -rrubygems -e 'print Gem.user_dir' 2>/dev/null || true)"
    candidate="${gem_user_dir}/bin/pod"
    if [[ -n "${gem_user_dir}" && -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  fi
  return 1
}

require_reviewed_cocoapods() {
  local resolved pod_version pod_dir
  resolved="$(resolve_reviewed_pod_bin || true)"
  [[ -n "${resolved}" && -x "${resolved}" ]] \
    || die "CocoaPods ${REQUIRED_COCOAPODS_VERSION} is unavailable. Install it in the current user's gem directory or set POD_BIN explicitly."
  pod_version="$("${resolved}" --version 2>/dev/null | awk 'NF { print $1; exit }')"
  [[ "${pod_version}" == "${REQUIRED_COCOAPODS_VERSION}" ]] \
    || die "Apple builds require CocoaPods ${REQUIRED_COCOAPODS_VERSION}; found ${pod_version:-unknown} at ${resolved}."
  POD_BIN="${resolved}"
  export POD_BIN
  pod_dir="$(dirname "${POD_BIN}")"
  case ":${PATH}:" in
    *":${pod_dir}:"*) ;;
    *) PATH="${pod_dir}:${PATH}" ;;
  esac
  export PATH
  export COCOAPODS_DISABLE_STATS=true
  printf 'Reviewed CocoaPods: %s at %s\n' "${pod_version}" "${POD_BIN}"
}

rerun_macos_pkg_install_lane_as_user_if_root() {
  [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY}" == "1" && "${EUID}" -eq 0 ]] \
    || return 0

  local target_user="${WINS_MACOS_APP_STORE_PKG_INSTALL_RUN_AS_USER}" target_uid name
  [[ "${target_user}" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "Root macOS package verification requires WINS_MACOS_APP_STORE_PKG_INSTALL_RUN_AS_USER to name the non-root Mac build user."
  target_uid="$(id -u "${target_user}" 2>/dev/null || true)"
  [[ "${target_uid}" =~ ^[0-9]+$ && "${target_uid}" -gt 0 ]] \
    || die "macOS package verification build user is missing or privileged: ${target_user}."

  local -a preserved_names=(
    WINS_PROJECT_ROOT
    FLUTTER_BIN
    POD_BIN
    PYTHON_BIN
    WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE
    WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY
    WINS_MACOS_APP_STORE_PKG_INSTALL_SYSTEM_TARGET
    WINS_MACOS_APP_STORE_PKG_INSTALL_GUI_AUTH
    WINS_MACOS_APP_STORE_PKG_INSTALL_IMAGE_SIZE
    WINS_MACOS_APP_STORE_PKG_INSTALL_RUN_AS_USER
    WINS_REQUIRE_APPLE_ENGINE
    WINS_APPLE_SIGNING_KEYCHAIN_PROBE
    WINS_APPLE_SIGNING_KEYCHAIN_PROBE_TIMEOUT_SECONDS
  )
  local -a environment=("WINS_PROJECT_ROOT=${ROOT_DIR}")
  for name in "${preserved_names[@]}"; do
    [[ "${name}" == "WINS_PROJECT_ROOT" ]] && continue
    environment+=("${name}=${!name}")
  done

  printf 'Dropping root before Flutter/readiness checks; PackageKit alone will reacquire administrator authorization as needed (user=%s).\n' \
    "${target_user}"
  exec sudo -n -u "${target_user}" -H env "${environment[@]}" /bin/bash "$0" "$@"
}

require_pre_release_source_smoke_safe() {
  local lane_name
  for lane_name in "${PRE_RELEASE_SOURCE_SMOKE_FORBIDDEN_LANES[@]}"; do
    if [[ "${!lane_name}" == "1" ]]; then
      die "WINS_PRE_RELEASE_SOURCE_SMOKE=1 permits development build/install/live-smoke lanes only; ${lane_name}=1 is a release mutation or release-evidence lane."
    fi
  done
}

run_pre_release_source_smoke_selftest() {
  section "Apple Pre-release Source Smoke Safety Self-Test"
  local lane_name reset_name output_file
  for lane_name in "${PRE_RELEASE_SOURCE_SMOKE_FORBIDDEN_LANES[@]}"; do
    output_file="$(mktemp "${TMPDIR:-/tmp}/wins-apple-prerelease-selftest.XXXXXX")"
    if (
      for reset_name in "${PRE_RELEASE_SOURCE_SMOKE_FORBIDDEN_LANES[@]}"; do
        printf -v "${reset_name}" '%s' 0
      done
      printf -v "${lane_name}" '%s' 1
      require_pre_release_source_smoke_safe
    ) >"${output_file}" 2>&1; then
      rm -f "${output_file}"
      die "Pre-release source-smoke safety self-test allowed forbidden lane ${lane_name}."
    fi
    grep -Fq "${lane_name}=1 is a release mutation or release-evidence lane" "${output_file}" \
      || {
        rm -f "${output_file}"
        die "Pre-release source-smoke safety self-test did not identify forbidden lane ${lane_name}."
      }
    rm -f "${output_file}"
  done

  (
    for reset_name in "${PRE_RELEASE_SOURCE_SMOKE_FORBIDDEN_LANES[@]}"; do
      printf -v "${reset_name}" '%s' 0
    done
    require_pre_release_source_smoke_safe
  ) || die "Pre-release source-smoke safety self-test rejected the development-only lane."
  printf 'Apple pre-release source-smoke safety self-test passed: %s forbidden release lanes fail closed.\n' \
    "${#PRE_RELEASE_SOURCE_SMOKE_FORBIDDEN_LANES[@]}"
}

require_file() {
  local path="$1"
  [[ -f "${path}" ]] || die "Missing required file: ${path}"
}

require_cmd() {
  local name="$1"
  command -v "${name}" >/dev/null 2>&1 || die "Missing required command on PATH: ${name}"
}

macos_pkg_install_authorization_mode_for_values() {
  local euid="$1"
  local sudo_available="$2"
  local gui_auth_enabled="${3:-0}"
  if [[ "${euid}" == "0" ]]; then
    printf 'root\n'
  elif [[ "${sudo_available}" == "1" ]]; then
    printf 'sudo\n'
  elif [[ "${gui_auth_enabled}" == "1" ]]; then
    printf 'gui\n'
  else
    printf 'missing\n'
  fi
}

macos_pkg_install_authorization_mode() {
  local sudo_available=0
  if [[ "$(id -u)" != "0" ]] && sudo -n true 2>/dev/null; then
    sudo_available=1
  fi

  local mode
  mode="$(macos_pkg_install_authorization_mode_for_values \
    "$(id -u)" \
    "${sudo_available}" \
    "${WINS_MACOS_APP_STORE_PKG_INSTALL_GUI_AUTH}")"
  case "${mode}" in
    root|sudo|gui)
      printf '%s\n' "${mode}"
      return 0
      ;;
    *)
      die "macOS App Store package install smoke requires root, non-interactive sudo, or WINS_MACOS_APP_STORE_PKG_INSTALL_GUI_AUTH=1 because the package declares auth=root."
      ;;
  esac
}

run_macos_installer_with_gui_authorization() {
  local pkg_path="$1"
  local target_path="$2"
  local authorization_tmp safe_pkg_path status
  if [[ "${pkg_path}" != /* ]]; then
    pkg_path="${ROOT_DIR}/${pkg_path}"
  fi
  require_cmd osascript
  authorization_tmp="$(mktemp -d "${TMPDIR:-/tmp}/wins-authorized-installer.XXXXXX")"
  safe_pkg_path="${authorization_tmp}/WinsVPN.pkg"
  if ! /bin/cp -p "${pkg_path}" "${safe_pkg_path}" \
    || ! /usr/bin/cmp -s "${pkg_path}" "${safe_pkg_path}"; then
    rm -rf "${authorization_tmp}"
    die "Could not create a byte-identical administrator-safe package copy."
  fi
  if ! /usr/sbin/installer -pkginfo -pkg "${safe_pkg_path}" >/dev/null; then
    rm -rf "${authorization_tmp}"
    die "Administrator-safe package copy is not readable by macOS installer."
  fi
  printf 'Administrator-safe macOS package copy verified: byte-identical and installer-readable.\n'
  printf '+ administrator-authorized installer -pkg %q -target %q -verboseR\n' \
    "${pkg_path}" \
    "${target_path}"
  set +e
  /usr/bin/osascript - "${safe_pkg_path}" "${target_path}" <<'APPLESCRIPT'
on run argv
  set packagePath to item 1 of argv
  set targetPath to item 2 of argv
  set installerCommand to "/usr/sbin/installer -pkg " & quoted form of packagePath & " -target " & quoted form of targetPath & " -verboseR"
  return do shell script installerCommand with administrator privileges
end run
APPLESCRIPT
  status="$?"
  set -e
  rm -rf "${authorization_tmp}"
  return "${status}"
}

first_macos_app_with_bundle_id() {
  local applications_dir="$1"
  local expected_bundle_id="$2"
  local app_path bundle_id

  [[ -d "${applications_dir}" ]] || return 0
  while IFS= read -r -d '' app_path; do
    bundle_id="$(
      /usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
        "${app_path}/Contents/Info.plist" 2>/dev/null || true
    )"
    if [[ "${bundle_id}" == "${expected_bundle_id}" ]]; then
      printf '%s\n' "${app_path}"
      return 0
    fi
  done < <(
    find "${applications_dir}" -mindepth 1 -maxdepth 1 -type d \
      -name '*.app' -print0 2>/dev/null
  )
}

require_clean_macos_system_install_target() {
  local existing_app
  existing_app="$(first_macos_app_with_bundle_id /Applications "${MACOS_BUNDLE_ID}")"
  if [[ -n "${existing_app}" ]]; then
    die "System-target package smoke requires no existing ${MACOS_BUNDLE_ID} app bundle under /Applications; found ${existing_app}."
  fi
  if pkgutil --pkg-info "${MACOS_BUNDLE_ID}" >/dev/null 2>&1; then
    die "System-target package smoke requires no existing ${MACOS_BUNDLE_ID} installer receipt."
  fi
}

unregister_project_macos_build_copies_for_package_install() {
  local lsregister app_path bundle_id search_root
  lsregister="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
  [[ -x "${lsregister}" ]] \
    || die "Launch Services registration tool is unavailable: ${lsregister}"

  while IFS= read -r -d '' app_path; do
    case "${app_path}" in
      "${ROOT_DIR}/build/"*|\
      "${HOME}/Library/Developer/Xcode/DerivedData/"*|\
      "${ROOT_DIR}/.artifacts/apple-preinstall-backup/"*)
        ;;
      *)
        die "Refusing to unregister a macOS app outside approved test output: ${app_path}"
        ;;
    esac
    [[ -f "${app_path}/Contents/Info.plist" ]] || continue
    bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
      "${app_path}/Contents/Info.plist" 2>/dev/null || true)"
    [[ "${bundle_id}" == "${MACOS_BUNDLE_ID}" ]] || continue
    "${lsregister}" -u "${app_path}" >/dev/null 2>&1 || true
    printf 'Unregistered test build copy from Launch Services: %s\n' "${app_path}"
  done < <(
    for search_root in \
      "${ROOT_DIR}/build" \
      "${HOME}/Library/Developer/Xcode/DerivedData" \
      "${ROOT_DIR}/.artifacts/apple-preinstall-backup"; do
      [[ -d "${search_root}" ]] || continue
      find "${search_root}" -type d -name '*.app' -prune -print0 2>/dev/null
    done
  )
}

restore_project_macos_build_copies_after_package_install() {
  local app_path quarantined_path index
  for index in "${!MACOS_PKG_QUARANTINED_APP_PATHS[@]}"; do
    app_path="${MACOS_PKG_QUARANTINED_APP_PATHS[${index}]}"
    quarantined_path="${MACOS_PKG_QUARANTINE_ROOT}/bundle-${index}"
    if [[ -e "${app_path}" || ! -e "${quarantined_path}" ]]; then
      printf 'ERROR: Could not safely restore quarantined project app: %s\n' \
        "${app_path}" >&2
      return 1
    fi
    if ! /bin/mv "${quarantined_path}" "${app_path}" 2>/dev/null; then
      sudo -n /bin/mv "${quarantined_path}" "${app_path}" \
        || die "Could not restore administrator-owned test app: ${app_path}"
    fi
    printf 'Restored project build copy after package install: %s\n' "${app_path}"
  done
  MACOS_PKG_QUARANTINED_APP_PATHS=()
  if [[ -n "${MACOS_PKG_QUARANTINE_ROOT}" ]]; then
    /bin/rmdir "${MACOS_PKG_QUARANTINE_ROOT}" \
      || die "Could not remove empty package-install quarantine directory."
  fi
  MACOS_PKG_QUARANTINE_ROOT=""
  trap - EXIT
}

quarantine_project_macos_build_copies_for_package_install() {
  local app_path bundle_id quarantined_path index search_root
  MACOS_PKG_QUARANTINED_APP_PATHS=()
  MACOS_PKG_QUARANTINE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/wins-pkg-quarantine.XXXXXX")"
  trap restore_project_macos_build_copies_after_package_install EXIT
  while IFS= read -r -d '' app_path; do
    case "${app_path}" in
      "${ROOT_DIR}/build/"*|\
      "${HOME}/Library/Developer/Xcode/DerivedData/"*|\
      "${ROOT_DIR}/.artifacts/apple-preinstall-backup/"*)
        ;;
      *)
        die "Refusing to quarantine a macOS app outside approved test output: ${app_path}"
        ;;
    esac
    [[ -f "${app_path}/Contents/Info.plist" ]] || continue
    bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' \
      "${app_path}/Contents/Info.plist" 2>/dev/null || true)"
    [[ "${bundle_id}" == "${MACOS_BUNDLE_ID}" ]] || continue
    index="${#MACOS_PKG_QUARANTINED_APP_PATHS[@]}"
    quarantined_path="${MACOS_PKG_QUARANTINE_ROOT}/bundle-${index}"
    [[ ! -e "${quarantined_path}" ]] \
      || die "Package-install quarantine path already exists: ${quarantined_path}"
    if ! /bin/mv "${app_path}" "${quarantined_path}" 2>/dev/null; then
      sudo -n /bin/mv "${app_path}" "${quarantined_path}" \
        || die "Could not quarantine administrator-owned test app: ${app_path}"
    fi
    MACOS_PKG_QUARANTINED_APP_PATHS+=("${app_path}")
    printf 'Temporarily quarantined test build copy from PackageKit relocation: %s\n' \
      "${app_path}"
  done < <(
    for search_root in \
      "${ROOT_DIR}/build" \
      "${HOME}/Library/Developer/Xcode/DerivedData" \
      "${ROOT_DIR}/.artifacts/apple-preinstall-backup"; do
      [[ -d "${search_root}" ]] || continue
      find "${search_root}" -type d -name '*.app' -prune -print0 2>/dev/null
    done
  )
  if [[ "${#MACOS_PKG_QUARANTINED_APP_PATHS[@]}" == "0" ]]; then
    /bin/rmdir "${MACOS_PKG_QUARANTINE_ROOT}"
    MACOS_PKG_QUARANTINE_ROOT=""
  fi
}

configure_apple_xcode_auth_args() {
  APPLE_XCODE_AUTH_ARGS=()

  local configured_count=0
  [[ -n "${WINS_APPLE_AUTHENTICATION_KEY_PATH}" ]] && configured_count=$((configured_count + 1))
  [[ -n "${WINS_APPLE_AUTHENTICATION_KEY_ID}" ]] && configured_count=$((configured_count + 1))
  [[ -n "${WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID}" ]] && configured_count=$((configured_count + 1))
  if [[ "${configured_count}" == "0" ]]; then
    return
  fi

  if [[ "${configured_count}" != "3" ]]; then
    die "Set WINS_APPLE_AUTHENTICATION_KEY_PATH, WINS_APPLE_AUTHENTICATION_KEY_ID, and WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID together, or leave all three unset."
  fi
  require_private_apple_auth_key_file "${WINS_APPLE_AUTHENTICATION_KEY_PATH}"

  APPLE_XCODE_AUTH_ARGS=(
    -authenticationKeyPath "${WINS_APPLE_AUTHENTICATION_KEY_PATH}"
    -authenticationKeyID "${WINS_APPLE_AUTHENTICATION_KEY_ID}"
    -authenticationKeyIssuerID "${WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID}"
  )
}

configure_apple_macos_development_signing_args() {
  APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS=()
  if [[ -z "${WINS_MACOS_DEVELOPMENT_XCCONFIG}" ]]; then
    return
  fi

  local resolved_xcconfig resolved_root mode
  resolved_xcconfig="$("${PYTHON_BIN}" - "${WINS_MACOS_DEVELOPMENT_XCCONFIG}" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
  )"
  resolved_root="$("${PYTHON_BIN}" - "${ROOT_DIR}" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
  )"
  [[ -f "${resolved_xcconfig}" ]] \
    || die "WINS_MACOS_DEVELOPMENT_XCCONFIG must point to a readable xcconfig file."
  case "${resolved_xcconfig}" in
    "${resolved_root}"|"${resolved_root}"/*)
      die "The macOS development signing xcconfig must live outside the project folder."
      ;;
  esac
  mode="$(stat -f '%Lp' "${resolved_xcconfig}" 2>/dev/null || true)"
  [[ -n "${mode}" ]] || die "Could not inspect macOS development xcconfig permissions."
  if (( 8#${mode} & 8#077 )); then
    die "The macOS development signing xcconfig must be private to the current user. Run chmod 600 on the file, then retry."
  fi
  if ! grep -q '^CODE_SIGN_STYLE = Manual$' "${resolved_xcconfig}" \
    || ! grep -q '^DEVELOPMENT_TEAM = 5YT8H4U72M$' "${resolved_xcconfig}" \
    || ! grep -q '^CODE_SIGN_IDENTITY = Apple Development$' "${resolved_xcconfig}" \
    || ! grep -Eq '^WINS_PROFILE_Runner = .+' "${resolved_xcconfig}" \
    || ! grep -Eq '^WINS_PROFILE_PacketTunnel = .+' "${resolved_xcconfig}" \
    || ! grep -q '^PROVISIONING_PROFILE_SPECIFIER = \$(WINS_PROFILE_\$(TARGET_NAME))$' "${resolved_xcconfig}"; then
    die "The macOS development signing xcconfig is not target-aware. Generate it with tools/apple_profile_manager.py --write-macos-development-xcconfig outside the project folder."
  fi

  APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS=(-xcconfig "${resolved_xcconfig}")
}

run_xcodebuild_with_signing_diagnostics() {
  local -a expanded_args=()
  local arg
  for arg in "$@"; do
    if [[ "${arg}" == "__APPLE_XCODE_AUTH_ARGS__" ]]; then
      if [[ "${#APPLE_XCODE_AUTH_ARGS[@]}" -gt 0 ]]; then
        expanded_args+=("${APPLE_XCODE_AUTH_ARGS[@]}")
      fi
    elif [[ "${arg}" == "__APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS__" ]]; then
      if [[ "${#APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS[@]}" -gt 0 ]]; then
        expanded_args+=("${APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS[@]}")
      fi
    else
      expanded_args+=("${arg}")
    fi
  done
  # Xcode writes the signed bundle (CodeResources, embedded.provisionprofile) with the caller's
  # umask. The release producer runs under umask 077 for its secrets; App Store Connect refuses a
  # package whose payload is readable only by root (error 90255), so Xcode runs under umask 022.
  local saved_umask rc=0
  saved_umask="$(umask)"
  umask 022
  run_with_signing_diagnostics xcodebuild "${expanded_args[@]}" || rc=$?
  umask "${saved_umask}"
  return "${rc}"
}

run_xcodebuild_with_export_signing_diagnostics() {
  local -a expanded_args=()
  local arg
  for arg in "$@"; do
    if [[ "${arg}" == "__APPLE_XCODE_AUTH_ARGS__" ]]; then
      if [[ "${#APPLE_XCODE_AUTH_ARGS[@]}" -gt 0 ]]; then
        expanded_args+=("${APPLE_XCODE_AUTH_ARGS[@]}")
      fi
    else
      expanded_args+=("${arg}")
    fi
  done
  # Same umask rule as run_xcodebuild_with_signing_diagnostics: export re-signs and writes the payload.
  local saved_umask rc=0
  saved_umask="$(umask)"
  umask 022
  run_with_export_signing_diagnostics xcodebuild "${expanded_args[@]}" || rc=$?
  umask "${saved_umask}"
  return "${rc}"
}

run_xcodebuild_with_ios_ui_automation_diagnostics() {
  local -a expanded_args=()
  local arg
  for arg in "$@"; do
    if [[ "${arg}" == "__APPLE_XCODE_AUTH_ARGS__" ]]; then
      if [[ "${#APPLE_XCODE_AUTH_ARGS[@]}" -gt 0 ]]; then
        expanded_args+=("${APPLE_XCODE_AUTH_ARGS[@]}")
      fi
    else
      expanded_args+=("${arg}")
    fi
  done
  run_with_ios_ui_automation_diagnostics env WINS_IOS_APPROVE_VPN_PERMISSION=1 xcrun xcodebuild "${expanded_args[@]}"
}

apple_xcode_auth_state() {
  if [[ "${#APPLE_XCODE_AUTH_ARGS[@]}" -gt 0 ]]; then
    printf 'configured'
  else
    printf 'not configured'
  fi
}

apple_macos_development_signing_state() {
  if [[ "${#APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS[@]}" -gt 0 ]]; then
    printf 'configured (private external xcconfig)'
  else
    printf 'automatic Xcode signing'
  fi
}

optional_cmd_status() {
  local label="$1"
  shift
  printf '%s: ' "${label}"
  if "$@" >/dev/null 2>&1; then
    printf 'ok\n'
  else
    printf 'missing or not usable\n'
  fi
}

codesigning_identity_count() {
  if ! command -v security >/dev/null 2>&1; then
    printf '0\n'
    return 0
  fi

  security find-identity -v -p codesigning 2>/dev/null \
    | awk '/valid identities found/ { print $1; found=1 } END { if (!found) print 0 }'
}

apple_identity_count_matching() {
  local pattern="$1"
  if ! command -v security >/dev/null 2>&1; then
    printf '0\n'
    return 0
  fi

  security find-identity -v -p codesigning 2>/dev/null | grep -E -c "${pattern}" || true
}

first_codesigning_identity_matching() {
  local pattern="$1"
  if ! command -v security >/dev/null 2>&1; then
    return 0
  fi

  security find-identity -v -p codesigning 2>/dev/null \
    | awk -v pattern="${pattern}" '
        match($0, /"[^"]+"/) {
          identity = substr($0, RSTART + 1, RLENGTH - 2)
          if (identity ~ pattern) {
            print identity
            exit
          }
        }
      '
}

first_identity_matching() {
  local pattern="$1"
  if ! command -v security >/dev/null 2>&1; then
    return 0
  fi

  security find-identity -v 2>/dev/null \
    | awk -v pattern="${pattern}" '
        match($0, /"[^"]+"/) {
          identity = substr($0, RSTART + 1, RLENGTH - 2)
          if (identity ~ pattern) {
            print identity
            exit
          }
        }
      '
}

require_valid_codesigning_identity() {
  local identity_count
  identity_count="$(codesigning_identity_count)"
  if [[ "${identity_count}" -lt 1 ]]; then
    die "No valid Apple code-signing identity is installed. Sign in to Xcode with an Apple Developer account and create/download an Apple Development certificate before signed iOS/macOS install tests."
  fi
}

distribution_export_lane_requested() {
  [[ "${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE}" == "1" \
    || "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
    || "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE}" == "1" \
    || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" \
    || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
    || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" \
    || "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1" ]]
}

refuse_direct_app_store_connect_upload() {
  # Xcode's destination=upload export sends the package to Apple without leaving local bytes,
  # so neither the payload-permission gates (App Store Connect error 90255) nor the built-name
  # checks can inspect what is uploaded. Export locally, verify and freeze that artifact, and
  # upload those exact bytes (Transporter) until a reviewed exact-artifact upload path exists.
  die "Direct App Store Connect upload is disabled: Xcode destination=upload transmits the package before the exported IPA or PKG can pass the payload-permission and built-name gates. Export, verify, and freeze a local artifact, then upload those exact bytes (Transporter)."
}

app_store_connect_upload_lane_requested() {
  [[ "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE}" == "1" \
    || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" \
    || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" ]]
}

force_archive_privacy_report_for_app_store_upload() {
  if app_store_connect_upload_lane_requested; then
    WINS_APPLE_PRIVACY_ARCHIVE_REPORT=1
  fi
}

require_app_store_connect_upload_auth() {
  if [[ "${#APPLE_XCODE_AUTH_ARGS[@]}" -eq 0 ]]; then
    die "App Store Connect upload lanes require WINS_APPLE_AUTHENTICATION_KEY_PATH, WINS_APPLE_AUTHENTICATION_KEY_ID, and WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID so uploads can run unattended and key paths stay redacted."
  fi
}

probe_app_store_connect_upload_auth() {
  section "App Store Connect Authentication Probe"
  "${PYTHON_BIN}" "${APPLE_APP_STORE_CONNECT_AUTH_PROBE}"
}

require_owner_signoff_for_app_store_upload() {
  "${PYTHON_BIN}" tools/validate_apple_owner_signoff.py --require-approved
}

require_valid_apple_submission_package_for_upload() {
  section "Apple Submission Package Upload Gate"
  printf 'App Store Connect upload lanes require a valid Apple submission package.\n'
  "${PYTHON_BIN}" "${APPLE_SUBMISSION_PACKAGE_VALIDATOR}" --release-ready
}

development_signing_lane_requested() {
  [[ "${WINS_IOS_INSTALL}" == "1" \
    || "${WINS_IOS_SIGNED_BUILD}" == "1" \
    || "${WINS_SIGNED_MACOS_BUILD}" == "1" \
    || "${WINS_IOS_ARCHIVE_SMOKE}" == "1" \
    || "${WINS_MACOS_ARCHIVE_SMOKE}" == "1" \
    || "${WINS_IOS_DEBUGGING_EXPORT_SMOKE}" == "1" \
    || "${WINS_MACOS_DEBUGGING_EXPORT_SMOKE}" == "1" ]]
}

apple_development_keychain_probe_needed() {
  [[ "${WINS_APPLE_SIGNING_KEYCHAIN_PROBE}" == "1" ]] || development_signing_lane_requested
}

apple_distribution_keychain_probe_needed() {
  [[ "${WINS_APPLE_SIGNING_KEYCHAIN_PROBE}" == "1" \
    || "${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE}" == "1" \
    || "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
    || "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE}" == "1" \
    || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" \
    || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
    || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" ]]
}

developer_id_keychain_probe_needed() {
  [[ "${WINS_APPLE_SIGNING_KEYCHAIN_PROBE}" == "1" \
    || "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1" ]]
}

mac_app_store_installer_keychain_probe_needed() {
  [[ "${WINS_APPLE_SIGNING_KEYCHAIN_PROBE}" == "1" \
    || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
    || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" ]]
}

developer_id_installer_keychain_probe_needed() {
  [[ "${WINS_APPLE_SIGNING_KEYCHAIN_PROBE}" == "1" \
    || "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1" ]]
}

apple_signing_keychain_probe_requested() {
  [[ "${WINS_APPLE_SIGNING_KEYCHAIN_PROBE}" == "1" ]] \
    || development_signing_lane_requested \
    || distribution_export_lane_requested
}

probe_codesign_identity_access() {
  local label="$1"
  local identity_name="$2"
  local timeout_seconds="${WINS_APPLE_SIGNING_KEYCHAIN_PROBE_TIMEOUT_SECONDS}"
  if ! [[ "${timeout_seconds}" =~ ^[0-9]+$ && "${timeout_seconds}" -gt 0 ]]; then
    timeout_seconds=20
  fi

  local tmpdir
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/wins-sign-probe.XXXXXX")"
  local probe_path="${tmpdir}/probe"
  local log_file="${tmpdir}/codesign.log"
  cp /usr/bin/true "${probe_path}"

  printf 'Probing %s private-key access with codesign timeout=%ss.\n' "${label}" "${timeout_seconds}"
  printf '+ codesign --force --sign %s --timestamp=none %s\n' "${identity_name}" "${probe_path}"

  set +e
  /usr/bin/codesign --force --sign "${identity_name}" --timestamp=none "${probe_path}" >"${log_file}" 2>&1 &
  local command_pid="$!"
  local start_seconds="${SECONDS}"
  local sign_status=0
  local timed_out=0

  while kill -0 "${command_pid}" >/dev/null 2>&1; do
    if (( SECONDS - start_seconds >= timeout_seconds )); then
      timed_out=1
      kill_process_tree "${command_pid}"
      sleep 1
      if kill -0 "${command_pid}" >/dev/null 2>&1; then
        kill_process_tree "${command_pid}" KILL
      fi
      break
    fi
    sleep 1
  done

  wait "${command_pid}" >/dev/null 2>&1
  sign_status="$?"
  sanitize_apple_log_output < "${log_file}" 2>/dev/null
  set -e

  if [[ "${timed_out}" == "1" ]]; then
    printf 'Apple signing keychain probe timed out for %s after %s seconds.\n' "${label}" "${timeout_seconds}" >&2
    printf 'Unlock this Mac and choose Always Allow for the %s private key, then rerun this probe or the export lane.\n' "${label}" >&2
    print_keychain_prompt_state >&2
    rm -f "${log_file}" "${probe_path}" >/dev/null 2>&1 || true
    rmdir "${tmpdir}" >/dev/null 2>&1 || true
    return 124
  fi

  if [[ "${sign_status}" -ne 0 ]]; then
    printf 'Apple signing keychain probe failed for %s with exit code %s.\n' "${label}" "${sign_status}" >&2
    print_keychain_prompt_state >&2
    rm -f "${log_file}" "${probe_path}" >/dev/null 2>&1 || true
    rmdir "${tmpdir}" >/dev/null 2>&1 || true
    return "${sign_status}"
  fi

  /usr/bin/codesign --verify --strict --verbose=2 "${probe_path}"
  rm -f "${log_file}" "${probe_path}" >/dev/null 2>&1 || true
  rmdir "${tmpdir}" >/dev/null 2>&1 || true
  printf 'Apple signing keychain probe passed for %s.\n' "${label}"
}

probe_productbuild_identity_access() {
  local label="$1"
  local identity_name="$2"
  local timeout_seconds="${WINS_APPLE_SIGNING_KEYCHAIN_PROBE_TIMEOUT_SECONDS}"
  if ! [[ "${timeout_seconds}" =~ ^[0-9]+$ && "${timeout_seconds}" -gt 0 ]]; then
    timeout_seconds=20
  fi

  local tmpdir
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/wins-installer-sign-probe.XXXXXX")"
  local app_path="${tmpdir}/Probe.app"
  local probe_executable="${app_path}/Contents/MacOS/Probe"
  local info_plist="${app_path}/Contents/Info.plist"
  local pkg_path="${tmpdir}/probe.pkg"
  local log_file="${tmpdir}/productbuild.log"
  mkdir -p "${app_path}/Contents/MacOS"
  cp /usr/bin/true "${probe_executable}"
  /usr/libexec/PlistBuddy \
    -c 'Add :CFBundleExecutable string Probe' \
    -c 'Add :CFBundleIdentifier string org.winsvpn.signingprobe' \
    -c 'Add :CFBundleName string Probe' \
    -c 'Add :CFBundlePackageType string APPL' \
    -c 'Add :CFBundleVersion string 1' \
    -c 'Add :CFBundleShortVersionString string 1.0' \
    "${info_plist}" >/dev/null

  printf 'Probing %s private-key access with productbuild timeout=%ss.\n' "${label}" "${timeout_seconds}"
  printf '+ productbuild --sign %s --component %s /Applications %s\n' "${identity_name}" "${app_path}" "${pkg_path}"

  set +e
  /usr/bin/productbuild \
    --sign "${identity_name}" \
    --component "${app_path}" \
    /Applications \
    "${pkg_path}" >"${log_file}" 2>&1 &
  local command_pid="$!"
  local start_seconds="${SECONDS}"
  local sign_status=0
  local timed_out=0

  while kill -0 "${command_pid}" >/dev/null 2>&1; do
    if (( SECONDS - start_seconds >= timeout_seconds )); then
      timed_out=1
      kill_process_tree "${command_pid}"
      sleep 1
      if kill -0 "${command_pid}" >/dev/null 2>&1; then
        kill_process_tree "${command_pid}" KILL
      fi
      break
    fi
    sleep 1
  done

  wait "${command_pid}" >/dev/null 2>&1
  sign_status="$?"
  sanitize_apple_log_output < "${log_file}" 2>/dev/null
  set -e

  if [[ "${timed_out}" == "1" ]]; then
    printf 'Apple installer keychain probe timed out for %s after %s seconds.\n' "${label}" "${timeout_seconds}" >&2
    printf 'Unlock this Mac, enter the login keychain password, and choose Always Allow for the %s private key, then rerun this probe or the export lane.\n' "${label}" >&2
    print_keychain_prompt_state >&2
    rm -rf "${tmpdir}"
    return 124
  fi

  if [[ "${sign_status}" -ne 0 ]]; then
    printf 'Apple installer keychain probe failed for %s with exit code %s.\n' "${label}" "${sign_status}" >&2
    print_keychain_prompt_state >&2
    rm -rf "${tmpdir}"
    return "${sign_status}"
  fi

  pkgutil --check-signature "${pkg_path}"
  rm -rf "${tmpdir}"
  printf 'Apple installer keychain probe passed for %s.\n' "${label}"
}

apple_signing_keychain_probe() {
  if ! apple_signing_keychain_probe_requested; then
    printf 'Skipping Apple signing keychain probe. Set WINS_APPLE_SIGNING_KEYCHAIN_PROBE=1 or run a distribution export lane to test private-key access.\n'
    return 0
  fi

  section "Apple Signing Keychain Probe"
  require_cmd codesign
  require_cmd productbuild
  require_cmd pkgutil
  require_valid_codesigning_identity

  local identity_name
  if apple_development_keychain_probe_needed; then
    identity_name="$(first_codesigning_identity_matching '^Apple Development:|^iPhone Developer:')"
    if [[ -z "${identity_name}" ]]; then
      if development_signing_lane_requested; then
        die "Signed Apple development lanes need an Apple Development identity, but none is installed."
      fi
      printf 'Skipping Apple Development private-key probe because no Apple Development identity is installed.\n'
    else
      probe_codesign_identity_access "Apple Development" "${identity_name}"
    fi
  fi

  if apple_distribution_keychain_probe_needed; then
    identity_name="$(first_codesigning_identity_matching '^Apple Distribution:|^iPhone Distribution:')"
    if [[ -z "${identity_name}" ]]; then
      die "Apple signing keychain probe needs an Apple Distribution identity, but none is installed."
    fi
    probe_codesign_identity_access "Apple Distribution" "${identity_name}"
  fi

  if developer_id_keychain_probe_needed; then
    identity_name="$(first_codesigning_identity_matching '^Developer ID Application:')"
    if [[ -z "${identity_name}" ]]; then
      if [[ "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1" ]]; then
        die "macOS Developer ID export needs a Developer ID Application identity, but none is installed."
      fi
      printf 'Skipping Developer ID Application private-key probe because no Developer ID Application identity is installed.\n'
    else
      probe_codesign_identity_access "Developer ID Application" "${identity_name}"
    fi
  fi

  if mac_app_store_installer_keychain_probe_needed; then
    identity_name="$(first_identity_matching '^3rd Party Mac Developer Installer:')"
    if [[ -z "${identity_name}" ]]; then
      if [[ "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
          || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" ]]; then
        die "macOS App Store export/upload needs a 3rd Party Mac Developer Installer identity, but none is installed."
      fi
      printf 'Skipping Mac App Store installer private-key probe because no 3rd Party Mac Developer Installer identity is installed.\n'
    else
      probe_productbuild_identity_access "Mac App Store Installer" "${identity_name}"
    fi
  fi

  if developer_id_installer_keychain_probe_needed; then
    identity_name="$(first_identity_matching '^Developer ID Installer:')"
    if [[ -z "${identity_name}" ]]; then
      if [[ "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1" ]]; then
        die "macOS Developer ID export needs a Developer ID Installer identity, but none is installed."
      fi
      printf 'Skipping Developer ID Installer private-key probe because no Developer ID Installer identity is installed.\n'
    else
      probe_productbuild_identity_access "Developer ID Installer" "${identity_name}"
    fi
  fi
}

xcode_project_development_team_count() {
  local project_file="$1"
  [[ -f "${project_file}" ]] || {
    printf '0\n'
    return 0
  }

  "${PYTHON_BIN}" - "${project_file}" <<'PY'
import re
import sys
from pathlib import Path

try:
    text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
except Exception:
    print(0)
    raise SystemExit(0)

teams = set()
for match in re.finditer(r"\bDEVELOPMENT_TEAM(?:\[[^\]]+\])?\s*=\s*([^;]*);", text):
    value = match.group(1).strip().strip('"')
    if value:
        teams.add(value)

print(len(teams))
PY
}

xcode_project_development_team_ids() {
  local project_file="$1"
  [[ -f "${project_file}" ]] || return 0

  "${PYTHON_BIN}" - "${project_file}" <<'PY'
import re
import sys
from pathlib import Path

try:
    text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
except Exception:
    raise SystemExit(0)

teams = set()
for match in re.finditer(r"\bDEVELOPMENT_TEAM(?:\[[^\]]+\])?\s*=\s*([^;]*);", text):
    value = match.group(1).strip().strip('"')
    if value:
        teams.add(value)

for team in sorted(teams):
    print(team)
PY
}

xcode_free_provisioning_team_ids() {
  "${PYTHON_BIN}" <<'PY'
import os
import plistlib
import subprocess
import sys
from pathlib import Path

try:
    prefs_path = os.environ.get("XCODE_TEAM_PREFS_PLIST", "").strip()
    if prefs_path:
        data = plistlib.loads(Path(prefs_path).read_bytes())
    else:
        exported = subprocess.run(
            ["defaults", "export", "com.apple.dt.Xcode", "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if exported.returncode != 0 or not exported.stdout:
            raise SystemExit(0)
        data = plistlib.loads(exported.stdout)
except Exception:
    raise SystemExit(0)

team_groups = data.get("IDEProvisioningTeamByIdentifier") or {}
for teams in team_groups.values():
    if not isinstance(teams, list):
        continue
    for team in teams:
        if not isinstance(team, dict):
            continue
        team_id = str(team.get("teamID") or "").strip()
        if team_id and team.get("isFreeProvisioningTeam") is True:
            print(team_id)
PY
}

print_xcode_provisioning_team_status() {
  "${PYTHON_BIN}" <<'PY'
import plistlib
import subprocess

try:
    exported = subprocess.run(
        ["defaults", "export", "com.apple.dt.Xcode", "-"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    data = plistlib.loads(exported.stdout) if exported.returncode == 0 and exported.stdout else {}
except Exception:
    data = {}

teams = []
for group in (data.get("IDEProvisioningTeamByIdentifier") or {}).values():
    if not isinstance(group, list):
        continue
    for team in group:
        if not isinstance(team, dict):
            continue
        team_id = str(team.get("teamID") or "").strip()
        if not team_id:
            continue
        teams.append({
            "id": team_id,
            "free": team.get("isFreeProvisioningTeam") is True,
            "type": str(team.get("teamType") or "unknown").strip() or "unknown",
        })

free_count = sum(1 for team in teams if team["free"])
paid_count = sum(1 for team in teams if not team["free"])
print(f"Xcode provisioning teams visible: {len(teams)}; paid_or_org={paid_count}; free_personal={free_count}")
if teams:
    team_summaries = ", ".join(
        f"{team['id']}:{'free' if team['free'] else 'paid'}:{team['type']}"
        for team in teams
    )
    print(f"Xcode provisioning team IDs: {team_summaries}")
PY
}

require_project_teams_not_free_for_network_extensions() {
  local label="$1"
  shift

  local team_ids
  team_ids="$(
    for project_file in "$@"; do
      xcode_project_development_team_ids "${project_file}"
    done | sort -u
  )"

  [[ -n "${team_ids//[[:space:]]/}" ]] || return 0

  local free_ids
  free_ids="$(xcode_free_provisioning_team_ids | sort -u)"
  [[ -n "${free_ids//[[:space:]]/}" ]] || return 0

  local team_id
  while IFS= read -r team_id; do
    [[ -n "${team_id}" ]] || continue
    if grep -Fxq "${team_id}" <<<"${free_ids}"; then
      die "${label} is configured for Apple team ${team_id}, which Xcode currently marks as a free Personal Team. Packet Tunnel / Network Extension signing requires a paid Apple Developer Program team. In Xcode > Settings > Accounts, refresh or add the paid team, then set Runner and PacketTunnel Signing & Capabilities to that team."
    fi
  done <<<"${team_ids}"
}

xcode_target_development_team_summary() {
  local project_file="$1"
  local target_name="$2"
  [[ -f "${project_file}" ]] || {
    printf '0 0 0\n'
    return 0
  }

  "${PYTHON_BIN}" - "${project_file}" "${target_name}" <<'PY'
import re
import sys
from pathlib import Path

project_path = Path(sys.argv[1])
target_name = sys.argv[2]

try:
    text = project_path.read_text(encoding="utf-8", errors="replace")
except Exception:
    print("0 0 0")
    raise SystemExit(0)

objects = {}
for match in re.finditer(r"\n\t\t([A-Za-z0-9]+) /\* ([^*]+) \*/ = \{\n(.*?)\n\t\t\};", text, re.S):
    objects[match.group(1)] = {
        "comment": match.group(2),
        "body": match.group(3),
    }

target_config_list_id = ""
for object_id, payload in objects.items():
    body = payload["body"]
    if "isa = PBXNativeTarget;" not in body:
        continue
    name_match = re.search(r"\bname = (?:(?:\"([^\"]+)\")|([^;]+));", body)
    name = (name_match.group(1) or name_match.group(2)).strip() if name_match else payload["comment"]
    if name != target_name:
        continue
    config_list_match = re.search(r"\bbuildConfigurationList = ([A-Za-z0-9]+)", body)
    if config_list_match:
        target_config_list_id = config_list_match.group(1)
    break

if not target_config_list_id or target_config_list_id not in objects:
    print("0 0 0")
    raise SystemExit(0)

config_list_body = objects[target_config_list_id]["body"]
config_section = re.search(r"buildConfigurations = \((.*?)\);", config_list_body, re.S)
if not config_section:
    print("0 0 0")
    raise SystemExit(0)

config_ids = re.findall(r"([A-Za-z0-9]+) /\* [^*]+ \*/", config_section.group(1))
teams = []
configured_count = 0
for config_id in config_ids:
    config = objects.get(config_id)
    if not config or "isa = XCBuildConfiguration;" not in config["body"]:
        continue
    team_match = re.search(
        r"\bDEVELOPMENT_TEAM(?:\[[^\]]+\])?\s*=\s*([^;]*);",
        config["body"],
    )
    if not team_match:
        continue
    team = team_match.group(1).strip().strip('"')
    if not team:
        continue
    configured_count += 1
    teams.append(team)

print(f"{configured_count} {len(config_ids)} {len(set(teams))}")
PY
}

print_target_development_team_status() {
  local label="$1"
  local project_file="$2"
  local target_name="$3"
  local configured_count
  local total_count
  local unique_count

  read -r configured_count total_count unique_count < <(
    xcode_target_development_team_summary "${project_file}" "${target_name}"
  )

  if [[ "${total_count}" -lt 1 ]]; then
    printf '%s development team configured: no (target not found)\n' "${label}"
  elif [[ "${configured_count}" -eq "${total_count}" && "${unique_count}" -eq 1 ]]; then
    printf '%s development team configured: yes (%s/%s configs)\n' \
      "${label}" "${configured_count}" "${total_count}"
  else
    printf '%s development team configured: no (%s/%s configs; %s unique value(s))\n' \
      "${label}" "${configured_count}" "${total_count}" "${unique_count}"
  fi
}

require_target_development_team() {
  local label="$1"
  local project_file="$2"
  local target_name="$3"
  local configured_count
  local total_count
  local unique_count

  read -r configured_count total_count unique_count < <(
    xcode_target_development_team_summary "${project_file}" "${target_name}"
  )

  if [[ "${total_count}" -lt 1 ]]; then
    die "${label} target was not found in ${project_file}."
  fi
  if [[ "${configured_count}" -ne "${total_count}" ]]; then
    die "${label} is missing DEVELOPMENT_TEAM in one or more build configurations (${configured_count}/${total_count}). Select your Apple Developer Team for that target in Xcode Signing & Capabilities."
  fi
  if [[ "${unique_count}" -ne 1 ]]; then
    die "${label} has inconsistent DEVELOPMENT_TEAM values across build configurations. Use one Apple Developer Team for all Debug/Release/Profile configs."
  fi
}

apple_provisioning_profile_report() {
  command -v security >/dev/null 2>&1 || {
    printf 'provisioning profiles: cannot inspect because security is missing\n'
    return 0
  }

  "${PYTHON_BIN}" - \
    "${IOS_BUNDLE_ID}" \
    "${MACOS_BUNDLE_ID}" \
    "${APPLE_APP_GROUP_ID}" \
    "${APPLE_MACOS_APP_GROUP_ID}" <<'PY'
import plistlib
import subprocess
import sys
from pathlib import Path

ios_bundle, macos_bundle, ios_app_group, macos_app_group = sys.argv[1:5]
required = [
    ("iOS app", ios_bundle, ios_app_group, "iOS"),
    ("iOS PacketTunnel", f"{ios_bundle}.PacketTunnel", ios_app_group, "iOS"),
    ("watchOS app", f"{ios_bundle}.watchkitapp", "", "iOS"),
    ("macOS app", macos_bundle, macos_app_group, "OSX"),
    ("macOS PacketTunnel", f"{macos_bundle}.PacketTunnel", macos_app_group, "OSX"),
]

profile_roots = [
    Path.home() / "Library" / "MobileDevice" / "Provisioning Profiles",
    Path.home() / "Library" / "Developer" / "Xcode" / "UserData" / "Provisioning Profiles",
]
profile_paths = []
seen = set()
for root in profile_roots:
    if not root.exists():
        continue
    for suffix in ("*.mobileprovision", "*.provisionprofile"):
        for path in sorted(root.glob(suffix)):
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            profile_paths.append(path)
print(f"provisioning profiles installed: {len(profile_paths)}")

matches = {
    label: {
        "count": 0,
        "development_count": 0,
        "distribution_count": 0,
        "packet_tunnel": False,
        "app_group": False,
        "keychain_group": False,
        "distribution_packet_tunnel": False,
        "distribution_app_group": False,
        "distribution_keychain_group": False,
        "release_testing_count": 0,
        "release_testing_packet_tunnel": False,
        "release_testing_app_group": False,
        "release_testing_keychain_group": False,
    }
    for label, _, _, _ in required
}

def profile_bundle_id(entitlements):
    app_identifier = str(
        entitlements.get("application-identifier")
        or entitlements.get("com.apple.application-identifier")
        or ""
    )
    if "." not in app_identifier:
        return app_identifier
    return app_identifier.split(".", 1)[1]

def profile_matches(profile_id, bundle_id):
    return (
        profile_id == bundle_id
        or profile_id == "*"
        or (profile_id.endswith("*") and bundle_id.startswith(profile_id[:-1]))
    )

def has_expected_app_group(groups, expected_app_group, team_prefix):
    group_values = {str(group) for group in groups}
    if expected_app_group in group_values:
        return True
    if team_prefix and expected_app_group.startswith(f"{team_prefix}."):
        base_group = expected_app_group[len(team_prefix) + 1 :]
        return base_group in group_values and f"{team_prefix}.*" in group_values
    return False

for profile_path in profile_paths:
    decoded = subprocess.run(
        ["security", "cms", "-D", "-i", str(profile_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if decoded.returncode != 0 or not decoded.stdout:
        continue
    try:
        profile = plistlib.loads(decoded.stdout)
    except Exception:
        continue

    entitlements = profile.get("Entitlements") or {}
    app_identifier = str(
        entitlements.get("application-identifier")
        or entitlements.get("com.apple.application-identifier")
        or ""
    )
    team_prefix = app_identifier.split(".", 1)[0] if "." in app_identifier else ""
    profile_id = profile_bundle_id(entitlements)
    platforms = set(profile.get("Platform") or [])
    is_macos_device_scoped_profile = (
        "OSX" in platforms
        and bool(profile.get("ProvisionedDevices"))
        and profile.get("ProvisionsAllDevices") is not True
    )
    is_development_profile = entitlements.get("get-task-allow") is True or is_macos_device_scoped_profile
    is_ios_release_testing_profile = (
        "iOS" in platforms
        and not is_development_profile
        and bool(profile.get("ProvisionedDevices"))
        and profile.get("ProvisionsAllDevices") is not True
    )
    network_extensions = entitlements.get("com.apple.developer.networking.networkextension") or []
    app_groups = entitlements.get("com.apple.security.application-groups") or []
    keychain_groups = entitlements.get("keychain-access-groups") or []

    def has_expected_shared_keychain_group(groups):
        return any(
            str(group) in {"org.winsvpn.shared", f"{team_prefix}.org.winsvpn.shared"}
            or (bool(team_prefix) and str(group) == f"{team_prefix}.*")
            for group in groups
        )

    for label, bundle_id, expected_app_group, expected_platform in required:
        if expected_platform not in platforms or not profile_matches(profile_id, bundle_id):
            continue
        item = matches[label]
        item["count"] += 1
        if is_development_profile:
            item["development_count"] += 1
        else:
            item["distribution_count"] += 1
        item["packet_tunnel"] = item["packet_tunnel"] or "packet-tunnel-provider" in network_extensions
        item["app_group"] = (
            item["app_group"]
            or has_expected_app_group(app_groups, expected_app_group, team_prefix)
        )
        item["keychain_group"] = (
            item["keychain_group"] or has_expected_shared_keychain_group(keychain_groups)
        )
        if not is_development_profile:
            item["distribution_packet_tunnel"] = (
                item["distribution_packet_tunnel"]
                or "packet-tunnel-provider" in network_extensions
            )
            item["distribution_app_group"] = (
                item["distribution_app_group"]
                or has_expected_app_group(app_groups, expected_app_group, team_prefix)
            )
            item["distribution_keychain_group"] = (
                item["distribution_keychain_group"]
                or has_expected_shared_keychain_group(keychain_groups)
            )
        if is_ios_release_testing_profile:
            item["release_testing_count"] += 1
            item["release_testing_packet_tunnel"] = (
                item["release_testing_packet_tunnel"]
                or "packet-tunnel-provider" in network_extensions
            )
            item["release_testing_app_group"] = (
                item["release_testing_app_group"]
                or has_expected_app_group(app_groups, expected_app_group, team_prefix)
            )
            item["release_testing_keychain_group"] = (
                item["release_testing_keychain_group"]
                or has_expected_shared_keychain_group(keychain_groups)
            )

for label, bundle_id, _, _ in required:
    item = matches[label]
    present = "yes" if item["count"] else "no"
    print(
        f"profile for {label} ({bundle_id}): {present}; "
        f"matches={item['count']}; "
        f"development_profiles={item['development_count']}; "
        f"distribution_profiles={item['distribution_count']}; "
        f"packet_tunnel={item['packet_tunnel']}; "
        f"profile_app_group={item['app_group']}; "
        f"keychain_group={item['keychain_group']}; "
        f"distribution_packet_tunnel={item['distribution_packet_tunnel']}; "
        f"distribution_app_group={item['distribution_app_group']}; "
        f"distribution_keychain_group={item['distribution_keychain_group']}"
    )
    if label in {"iOS app", "iOS PacketTunnel", "watchOS app"}:
        release_testing_present = "yes" if item["release_testing_count"] else "no"
        print(
            f"release-testing profile for {label} ({bundle_id}): "
            f"{release_testing_present}; "
            f"release_testing_profiles={item['release_testing_count']}; "
            f"release_testing_packet_tunnel={item['release_testing_packet_tunnel']}; "
            f"release_testing_app_group={item['release_testing_app_group']}; "
            f"release_testing_keychain_group={item['release_testing_keychain_group']}"
        )

missing_distribution = []
incomplete_distribution = []
for label, bundle_id, _, _ in required:
    item = matches[label]
    if item["distribution_count"] < 1:
        missing_distribution.append(f"{label} ({bundle_id})")
        continue
    if label == "watchOS app":
        continue
    missing_capabilities = []
    if not item["distribution_packet_tunnel"]:
        missing_capabilities.append("packet-tunnel-provider")
    if not item["distribution_app_group"]:
        missing_capabilities.append("app-group")
    if not item["distribution_keychain_group"]:
        missing_capabilities.append("keychain-group")
    if missing_capabilities:
        incomplete_distribution.append(
            f"{label} ({bundle_id}) missing {', '.join(missing_capabilities)}"
        )

if missing_distribution or incomplete_distribution:
    print(
        "distribution profile readiness: missing or incomplete; "
        f"missing_profiles={'; '.join(missing_distribution) or 'none'}; "
        f"incomplete_profiles={'; '.join(incomplete_distribution) or 'none'}"
    )
else:
    print("distribution profile readiness: ok")

missing_release_testing = []
incomplete_release_testing = []
for label, bundle_id, _, _ in required:
    if label not in {"iOS app", "iOS PacketTunnel", "watchOS app"}:
        continue
    item = matches[label]
    if item["release_testing_count"] < 1:
        missing_release_testing.append(f"{label} ({bundle_id})")
        continue
    if label == "watchOS app":
        continue
    missing_capabilities = []
    if not item["release_testing_packet_tunnel"]:
        missing_capabilities.append("packet-tunnel-provider")
    if not item["release_testing_app_group"]:
        missing_capabilities.append("app-group")
    if not item["release_testing_keychain_group"]:
        missing_capabilities.append("keychain-group")
    if missing_capabilities:
        incomplete_release_testing.append(
            f"{label} ({bundle_id}) missing {', '.join(missing_capabilities)}"
        )

if missing_release_testing or incomplete_release_testing:
    print(
        "iOS release-testing profile readiness: missing or incomplete; "
        f"missing_profiles={'; '.join(missing_release_testing) or 'none'}; "
        f"incomplete_profiles={'; '.join(incomplete_release_testing) or 'none'}"
    )
else:
    print("iOS release-testing profile readiness: ok")
PY
}

require_distribution_profiles_for() {
  local scope_label="$1"
  shift

  command -v security >/dev/null 2>&1 \
    || die "Cannot inspect Apple provisioning profiles because the security command is missing."

  local output status
  set +e
  output="$("${PYTHON_BIN}" - "${scope_label}" "$@" <<'PY'
import plistlib
import subprocess
import sys
from pathlib import Path

scope_label = sys.argv[1]
args = sys.argv[2:]
if len(args) % 3 != 0:
    raise SystemExit("distribution profile guard received invalid arguments")

required = [
    (args[index], args[index + 1], args[index + 2])
    for index in range(0, len(args), 3)
]

scope_normalized = scope_label.strip().lower()
if scope_normalized.startswith("ios"):
    expected_platform = "iOS"
elif scope_normalized.startswith("macos"):
    expected_platform = "OSX"
else:
    raise SystemExit(f"distribution profile guard has unknown platform scope: {scope_label}")

profile_roots = [
    Path.home() / "Library" / "MobileDevice" / "Provisioning Profiles",
    Path.home() / "Library" / "Developer" / "Xcode" / "UserData" / "Provisioning Profiles",
]
profile_paths = []
seen = set()
for root in profile_roots:
    if not root.exists():
        continue
    for suffix in ("*.mobileprovision", "*.provisionprofile"):
        for path in sorted(root.glob(suffix)):
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            profile_paths.append(path)

matches = {
    bundle_id: {
        "distribution_count": 0,
        "distribution_packet_tunnel": False,
        "distribution_app_group": False,
        "distribution_keychain_group": False,
    }
    for _, bundle_id, _ in required
}

def profile_bundle_id(entitlements):
    app_identifier = str(
        entitlements.get("application-identifier")
        or entitlements.get("com.apple.application-identifier")
        or ""
    )
    if "." not in app_identifier:
        return app_identifier
    return app_identifier.split(".", 1)[1]

def profile_matches(profile_id, bundle_id):
    return (
        profile_id == bundle_id
        or profile_id == "*"
        or (profile_id.endswith("*") and bundle_id.startswith(profile_id[:-1]))
    )

def has_expected_app_group(groups, expected_app_group, team_prefix):
    group_values = {str(group) for group in groups}
    if expected_app_group in group_values:
        return True
    if team_prefix and expected_app_group.startswith(f"{team_prefix}."):
        base_group = expected_app_group[len(team_prefix) + 1 :]
        return base_group in group_values and f"{team_prefix}.*" in group_values
    return False

for profile_path in profile_paths:
    decoded = subprocess.run(
        ["security", "cms", "-D", "-i", str(profile_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if decoded.returncode != 0 or not decoded.stdout:
        continue
    try:
        profile = plistlib.loads(decoded.stdout)
    except Exception:
        continue

    entitlements = profile.get("Entitlements") or {}
    app_identifier = str(
        entitlements.get("application-identifier")
        or entitlements.get("com.apple.application-identifier")
        or ""
    )
    team_prefix = app_identifier.split(".", 1)[0] if "." in app_identifier else ""
    profile_id = profile_bundle_id(entitlements)
    platforms = set(profile.get("Platform") or [])
    if expected_platform not in platforms:
        continue
    is_macos_device_scoped_profile = (
        "OSX" in platforms
        and bool(profile.get("ProvisionedDevices"))
        and profile.get("ProvisionsAllDevices") is not True
    )
    is_development_profile = (
        entitlements.get("get-task-allow") is True
        or is_macos_device_scoped_profile
    )
    if is_development_profile:
        continue

    network_extensions = entitlements.get("com.apple.developer.networking.networkextension") or []
    app_groups = entitlements.get("com.apple.security.application-groups") or []
    keychain_groups = entitlements.get("keychain-access-groups") or []

    def has_expected_shared_keychain_group(groups):
        return any(
            str(group) in {"org.winsvpn.shared", f"{team_prefix}.org.winsvpn.shared"}
            or (bool(team_prefix) and str(group) == f"{team_prefix}.*")
            for group in groups
        )

    for _, bundle_id, expected_app_group in required:
        if not profile_matches(profile_id, bundle_id):
            continue
        item = matches[bundle_id]
        item["distribution_count"] += 1
        item["distribution_packet_tunnel"] = (
            item["distribution_packet_tunnel"]
            or "packet-tunnel-provider" in network_extensions
        )
        item["distribution_app_group"] = (
            item["distribution_app_group"]
            or has_expected_app_group(app_groups, expected_app_group, team_prefix)
        )
        item["distribution_keychain_group"] = (
            item["distribution_keychain_group"]
            or has_expected_shared_keychain_group(keychain_groups)
        )

missing_profiles = []
incomplete_profiles = []
for label, bundle_id, _ in required:
    item = matches[bundle_id]
    if item["distribution_count"] < 1:
        missing_profiles.append(f"{label} ({bundle_id})")
        continue
    if label == "watchOS app":
        continue

    missing_capabilities = []
    if not item["distribution_packet_tunnel"]:
        missing_capabilities.append("packet-tunnel-provider")
    if not item["distribution_app_group"]:
        missing_capabilities.append("app-group")
    if not item["distribution_keychain_group"]:
        missing_capabilities.append("keychain-group")
    if missing_capabilities:
        incomplete_profiles.append(
            f"{label} ({bundle_id}) missing {', '.join(missing_capabilities)}"
        )

if missing_profiles or incomplete_profiles:
    print(
        f"Apple distribution provisioning profiles are not ready for {scope_label}.",
        file=sys.stderr,
    )
    print(
        "missing_profiles=" + ("; ".join(missing_profiles) or "none"),
        file=sys.stderr,
    )
    print(
        "incomplete_profiles=" + ("; ".join(incomplete_profiles) or "none"),
        file=sys.stderr,
    )
    print(
        "Create/download distribution profiles for every listed bundle ID with "
        "Packet Tunnel, App Groups, and shared keychain access before running "
        "this export lane.",
        file=sys.stderr,
    )
    raise SystemExit(78)

print(f"Apple distribution provisioning profiles ready for {scope_label}.")
PY
)"
  status="$?"
  set -e
  if [[ -n "${output}" ]]; then
    printf '%s\n' "${output}"
  fi
  if [[ "${status}" != "0" ]]; then
    die "Distribution profile prerequisites are not met for ${scope_label}."
  fi
}

require_ios_distribution_profiles() {
  require_distribution_profiles_for \
    "iOS distribution export" \
    "iOS app" "${IOS_BUNDLE_ID}" "${APPLE_APP_GROUP_ID}" \
    "iOS PacketTunnel" "${IOS_BUNDLE_ID}.PacketTunnel" "${APPLE_APP_GROUP_ID}" \
    "watchOS app" "${IOS_BUNDLE_ID}.watchkitapp" ""
}

require_ios_release_testing_profiles() {
  local output status
  set +e
  output="$("${PYTHON_BIN}" tools/apple_profile_manager.py --quiet 2>&1)"
  status="$?"
  set -e
  if [[ -n "${output}" ]]; then
    printf '%s\n' "${output}"
  fi
  if [[ "${status}" != "0" ]]; then
    die "iOS release-testing export needs device-scoped release-testing/Ad Hoc Apple Distribution profiles for ${IOS_BUNDLE_ID}, ${IOS_BUNDLE_ID}.PacketTunnel, and ${IOS_BUNDLE_ID}.watchkitapp. Create/download those profiles, run tools/apple_profile_manager.py --source ~/Downloads --install, then rerun WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE=1."
  fi
}

require_macos_distribution_profiles() {
  require_distribution_profiles_for \
    "macOS distribution export" \
    "macOS app" "${MACOS_BUNDLE_ID}" "${APPLE_MACOS_APP_GROUP_ID}" \
    "macOS PacketTunnel" "${MACOS_BUNDLE_ID}.PacketTunnel" "${APPLE_MACOS_APP_GROUP_ID}"
}

manual_distribution_export_options_plist() {
  local lane="$1"
  local base_plist="$2"
  local signing_certificate="$3"
  shift 3

  if [[ "${WINS_APPLE_MANUAL_DISTRIBUTION_EXPORTS}" != "1" ]]; then
    printf '%s\n' "${base_plist}"
    return 0
  fi
  # iOS lanes export with the tracked plists' automatic signing (Xcode-managed
  # App Store profiles). The developer portal holds no manual App Store profile
  # for the Watch app (org.winsvpn.app.watchkitapp), and a manual export refuses
  # an Xcode-managed one ("is Xcode managed, but signing settings require a
  # manually managed profile"). macOS lanes keep their portal profiles.
  case "${lane}" in
    ios-*)
      printf '%s\n' "${base_plist}"
      return 0
      ;;
  esac

  local tmp_dir output_plist
  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/wins-export-options.XXXXXX")"
  output_plist="${tmp_dir}/ExportOptions.plist"

  local resolver_status
  if "${PYTHON_BIN}" - \
    "${lane}" \
    "${base_plist}" \
    "${output_plist}" \
    "${signing_certificate}" \
    "$@" <<'PY'
import plistlib
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

lane, base_plist, output_plist, signing_certificate, *args = sys.argv[1:]
if len(args) % 3 != 0:
    raise SystemExit("manual export profile resolver received invalid arguments")

required = [
    (args[index], args[index + 1], args[index + 2])
    for index in range(0, len(args), 3)
]

profile_roots = [
    Path.home() / "Library" / "MobileDevice" / "Provisioning Profiles",
    Path.home() / "Library" / "Developer" / "Xcode" / "UserData" / "Provisioning Profiles",
]

profile_paths = []
seen = set()
for root in profile_roots:
    if not root.exists():
        continue
    for suffix in ("*.mobileprovision", "*.provisionprofile"):
        for path in sorted(root.glob(suffix)):
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            profile_paths.append(path)

def profile_bundle_id(entitlements):
    app_identifier = str(
        entitlements.get("application-identifier")
        or entitlements.get("com.apple.application-identifier")
        or ""
    )
    if "." not in app_identifier:
        return app_identifier
    return app_identifier.split(".", 1)[1]

def has_expected_shared_keychain_group(groups, team_prefix):
    return any(
        str(group) in {"org.winsvpn.shared", f"{team_prefix}.org.winsvpn.shared"}
        or (bool(team_prefix) and str(group) == f"{team_prefix}.*")
        for group in groups
    )

def has_expected_app_group(groups, expected_app_group, team_prefix):
    group_values = {str(group) for group in groups}
    if expected_app_group in group_values:
        return True
    if team_prefix and expected_app_group.startswith(f"{team_prefix}."):
        base_group = expected_app_group[len(team_prefix) + 1 :]
        return base_group in group_values and f"{team_prefix}.*" in group_values
    return False

def identity_hash_for(name_fragment):
    completed = subprocess.run(
        ["security", "find-identity", "-v"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return ""
    for line in completed.stdout.splitlines():
        if name_fragment not in line or "Win's VPN Inc" not in line:
            continue
        match = re.search(r"\b([0-9A-F]{40})\b", line)
        if match:
            return match.group(1)
    return ""

def lane_matches_profile_shape(profile, entitlements):
    platforms = set(profile.get("Platform") or [])
    provisioned_devices = bool(profile.get("ProvisionedDevices"))
    provisions_all_devices = profile.get("ProvisionsAllDevices") is True

    if lane.startswith("ios-") and "iOS" not in platforms:
        return False
    if lane.startswith("macos-") and "OSX" not in platforms:
        return False

    if lane == "macos-debugging":
        return provisioned_devices and not provisions_all_devices
    if entitlements.get("get-task-allow") is True:
        return False

    if lane == "ios-app-store":
        return not provisioned_devices and not provisions_all_devices
    if lane == "ios-release-testing":
        return provisioned_devices and not provisions_all_devices
    if lane == "macos-app-store":
        return not provisioned_devices and not provisions_all_devices
    if lane == "macos-developer-id":
        return provisions_all_devices

    raise SystemExit(f"unknown manual distribution export lane: {lane}")

def required_network_extension_value():
    if lane == "macos-developer-id":
        return "packet-tunnel-provider-systemextension"
    return "packet-tunnel-provider"

profiles = []
for profile_path in profile_paths:
    decoded = subprocess.run(
        ["security", "cms", "-D", "-i", str(profile_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if decoded.returncode != 0 or not decoded.stdout:
        continue
    try:
        profile = plistlib.loads(decoded.stdout)
    except Exception:
        continue

    entitlements = profile.get("Entitlements") or {}
    app_identifier = str(
        entitlements.get("application-identifier")
        or entitlements.get("com.apple.application-identifier")
        or ""
    )
    team_prefix = app_identifier.split(".", 1)[0] if "." in app_identifier else ""
    profiles.append(
        {
            "path": profile_path,
            "profile": profile,
            "entitlements": entitlements,
            "bundle_id": profile_bundle_id(entitlements),
            "team_prefix": team_prefix,
        }
    )

provisioning_profiles = {}
missing = []
required_ne = required_network_extension_value()
for label, bundle_id, expected_app_group in required:
    candidates = []
    rejected_reasons = []

    for item in profiles:
        profile = item["profile"]
        entitlements = item["entitlements"]
        if item["bundle_id"] != bundle_id:
            continue
        if profile.get("IsXcodeManaged") is True:
            # xcodebuild refuses an Xcode-managed profile in a manual export.
            rejected_reasons.append(f"{profile.get('Name') or profile.get('UUID')} is Xcode managed")
            continue
        if not lane_matches_profile_shape(profile, entitlements):
            rejected_reasons.append(f"{profile.get('Name') or profile.get('UUID')} has the wrong distribution type for {lane}")
            continue

        network_extensions = entitlements.get("com.apple.developer.networking.networkextension") or []
        app_groups = entitlements.get("com.apple.security.application-groups") or []
        keychain_groups = entitlements.get("keychain-access-groups") or []
        if label == "watchOS app":
            candidates.append(item)
            continue
        if required_ne not in network_extensions:
            rejected_reasons.append(f"{profile.get('Name') or profile.get('UUID')} lacks {required_ne}")
            continue
        if expected_app_group and not has_expected_app_group(
            app_groups,
            expected_app_group,
            item["team_prefix"],
        ):
            rejected_reasons.append(f"{profile.get('Name') or profile.get('UUID')} lacks App Group {expected_app_group}")
            continue
        if not has_expected_shared_keychain_group(keychain_groups, item["team_prefix"]):
            rejected_reasons.append(f"{profile.get('Name') or profile.get('UUID')} lacks shared keychain access")
            continue
        candidates.append(item)

    if not candidates:
        detail = "; ".join(rejected_reasons[:4]) if rejected_reasons else "no matching installed profile"
        missing.append(f"{label} ({bundle_id}): {detail}")
        continue

    candidates.sort(
        key=lambda item: (
            item["profile"].get("ExpirationDate") or datetime.min,
            str(item["profile"].get("Name") or ""),
            str(item["profile"].get("UUID") or ""),
        )
    )
    selected = candidates[-1]
    profile = selected["profile"]
    profile_name = str(profile.get("Name") or profile.get("UUID") or "").strip()
    profile_uuid = str(profile.get("UUID") or "").strip()
    if not profile_name:
        missing.append(f"{label} ({bundle_id}): selected profile has no name or UUID")
        continue
    provisioning_profiles[bundle_id] = profile_name
    print(
        f"manual export profile: {label} ({bundle_id}) -> {profile_name}"
        + (f" [{profile_uuid}]" if profile_uuid else ""),
        file=sys.stderr,
    )

if missing:
    print(
        f"Manual export options cannot be generated for {lane}.",
        file=sys.stderr,
    )
    for item in missing:
        print(f"- {item}", file=sys.stderr)
    raise SystemExit(78)

with Path(base_plist).open("rb") as handle:
    options = plistlib.load(handle)

options["signingStyle"] = "manual"
if signing_certificate:
    options["signingCertificate"] = signing_certificate
if lane == "macos-app-store":
    options["signingCertificate"] = (
        identity_hash_for("Apple Distribution:")
        or signing_certificate
        or options.get("signingCertificate", "")
    )
    options["installerSigningCertificate"] = (
        identity_hash_for("3rd Party Mac Developer Installer:")
        or "3rd Party Mac Developer Installer"
    )
options["provisioningProfiles"] = provisioning_profiles

Path(output_plist).write_bytes(plistlib.dumps(options))
PY
  then
    resolver_status=0
  else
    resolver_status="$?"
  fi

  if [[ "${resolver_status}" -ne 0 ]]; then
    rm -rf "${tmp_dir}"
    return "${resolver_status}"
  fi

  printf '%s\n' "${output_plist}"
}

write_macos_app_store_archive_xcconfig() {
  local export_options_plist="$1"
  local output_xcconfig="$2"

  "${PYTHON_BIN}" - \
    "${export_options_plist}" \
    "${output_xcconfig}" \
    "${APPLE_MACOS_TEAM_ID}" \
    "${MACOS_BUNDLE_ID}" \
    "${MACOS_BUNDLE_ID}.PacketTunnel" <<'PY'
import os
import plistlib
import re
import sys
from pathlib import Path

export_options_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
team_id = sys.argv[3]
host_bundle_id = sys.argv[4]
extension_bundle_id = sys.argv[5]

if not re.fullmatch(r"[A-Z0-9]{10}", team_id):
    raise SystemExit("macOS App Store archive team ID is invalid")

with export_options_path.open("rb") as handle:
    options = plistlib.load(handle)

if options.get("signingStyle") != "manual":
    raise SystemExit("macOS App Store archive requires manual signing export options")

identity = str(options.get("signingCertificate") or "").strip()
if not re.fullmatch(r"[0-9A-F]{40}", identity):
    raise SystemExit(
        "macOS App Store archive requires the exact Apple Distribution identity hash"
    )

profiles = options.get("provisioningProfiles")
if not isinstance(profiles, dict):
    raise SystemExit("macOS App Store archive provisioningProfiles are missing")

expected_bundle_ids = {host_bundle_id, extension_bundle_id}
if set(profiles) != expected_bundle_ids:
    raise SystemExit(
        "macOS App Store archive provisioningProfiles must contain exactly the "
        "Runner and PacketTunnel bundle IDs"
    )

def safe_xcconfig_value(bundle_id):
    value = str(profiles.get(bundle_id) or "").strip()
    if not value or len(value) > 255:
        raise SystemExit(f"provisioning profile name is invalid for {bundle_id}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._()'+-]*", value):
        raise SystemExit(
            f"provisioning profile name contains unsafe xcconfig characters for {bundle_id}"
        )
    return value

host_profile = safe_xcconfig_value(host_bundle_id)
extension_profile = safe_xcconfig_value(extension_bundle_id)

lines = [
    "CODE_SIGN_STYLE = Manual",
    f"DEVELOPMENT_TEAM = {team_id}",
    f"CODE_SIGN_IDENTITY = {identity}",
    f"WINS_PROFILE_Runner = {host_profile}",
    f"WINS_PROFILE_PacketTunnel = {extension_profile}",
    "PROVISIONING_PROFILE_SPECIFIER = $(WINS_PROFILE_$(TARGET_NAME))",
]

output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
    handle.write("\n".join(lines) + "\n")
os.chmod(output_path, 0o600)
PY
}

manual_macos_app_store_archive_xcconfig() {
  [[ "${WINS_APPLE_MANUAL_DISTRIBUTION_EXPORTS}" == "1" ]] \
    || die "macOS App Store archive creation requires WINS_APPLE_MANUAL_DISTRIBUTION_EXPORTS=1."

  local export_options_plist output_xcconfig
  export_options_plist="$(
    manual_distribution_export_options_plist \
      macos-app-store \
      apple/ExportOptions/macos-app-store-local.plist \
      "Apple Distribution" \
      "macOS app" "${MACOS_BUNDLE_ID}" "${APPLE_MACOS_APP_GROUP_ID}" \
      "macOS PacketTunnel" "${MACOS_BUNDLE_ID}.PacketTunnel" "${APPLE_MACOS_APP_GROUP_ID}"
  )" || die "Unable to resolve installed profiles for the macOS App Store archive."
  output_xcconfig="$(dirname "${export_options_plist}")/ArchiveSigning.xcconfig"
  write_macos_app_store_archive_xcconfig \
    "${export_options_plist}" \
    "${output_xcconfig}"
  printf '%s\n' "${output_xcconfig}"
}

macos_app_store_archive_signing_requested() {
  [[ "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
    || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" ]]
}

apple_signing_preflight_report() {
  section "Apple Signing Preflight"

  printf 'valid Apple code-signing identities: %s\n' "$(codesigning_identity_count)"
  printf 'Apple Development identities: %s\n' "$(apple_identity_count_matching '"Apple Development:|"iPhone Developer:')"
  printf 'Apple Distribution identities: %s\n' "$(apple_identity_count_matching '"Apple Distribution:|"iPhone Distribution:')"
  printf 'Developer ID Application identities: %s\n' "$(apple_identity_count_matching '"Developer ID Application:')"
  print_keychain_prompt_state

  print_target_development_team_status "iOS Runner" ios/Runner.xcodeproj/project.pbxproj Runner
  print_target_development_team_status "iOS PacketTunnel" ios/Runner.xcodeproj/project.pbxproj PacketTunnel
  print_target_development_team_status "macOS Runner" macos/Runner.xcodeproj/project.pbxproj Runner
  print_target_development_team_status "macOS PacketTunnel" macos/Runner.xcodeproj/project.pbxproj PacketTunnel
  print_xcode_provisioning_team_status

  apple_provisioning_profile_report
}

print_keychain_prompt_state() {
  command -v ps >/dev/null 2>&1 || return 0
  command -v awk >/dev/null 2>&1 || return 0

  local security_agent_processes
  security_agent_processes="$(
    ps -axo pid=,etime=,comm= 2>/dev/null \
      | awk '/SecurityAgent/ {print $1 ":" $2}' \
      | paste -sd ',' - 2>/dev/null || true
  )"

  if [[ -n "${security_agent_processes}" ]]; then
    printf 'Apple keychain prompt state: SecurityAgent running; pid_elapsed=%s\n' "${security_agent_processes}"
    if command -v osascript >/dev/null 2>&1; then
      local prompt_summary
      prompt_summary="$(
        osascript <<'OSA' 2>/dev/null || true
tell application "System Events"
  if not (exists process "SecurityAgent") then return ""
  tell process "SecurityAgent"
    if (count of windows) is 0 then return ""
    set promptItems to {}
    try
      repeat with promptText in static texts of window 1
        set promptValue to value of promptText as text
        if promptValue contains "wants to access key" or promptValue contains "To allow this" then
          set end of promptItems to promptValue
        end if
      end repeat
    end try
    set hasPasswordField to false
    try
      if (count of text fields of window 1) > 0 then set hasPasswordField to true
    end try
    set hasAlwaysAllow to false
    try
      if exists button "Always Allow" of window 1 then set hasAlwaysAllow to true
    end try
    set AppleScript's text item delimiters to " | "
    set promptSummary to promptItems as text
    set AppleScript's text item delimiters to ""
    return "prompt=" & promptSummary & "; password_field=" & hasPasswordField & "; always_allow=" & hasAlwaysAllow
  end tell
end tell
OSA
      )"
      if [[ -n "${prompt_summary}" ]]; then
        printf 'Apple keychain prompt detail: %s\n' "${prompt_summary}"
      fi
    fi
  else
    printf 'Apple keychain prompt state: no SecurityAgent process observed\n'
  fi
}

require_ios_signing_prereqs() {
  section "Signed iOS Build Prerequisites"
  require_valid_codesigning_identity

  local development_identity_count
  development_identity_count="$(apple_identity_count_matching '"Apple Development:|"iPhone Developer:')"
  if [[ "${development_identity_count}" -lt 1 ]]; then
    die "No Apple Development signing identity is installed. Physical iPhone install tests require an Apple Development certificate, not only distribution or Developer ID signing."
  fi

  require_target_development_team "iOS Runner" ios/Runner.xcodeproj/project.pbxproj Runner
  require_target_development_team "iOS PacketTunnel" ios/Runner.xcodeproj/project.pbxproj PacketTunnel
  require_project_teams_not_free_for_network_extensions \
    "Signed iOS build" \
    ios/Runner.xcodeproj/project.pbxproj
}

require_ios_signed_runtime_prereqs() {
  section "Signed iOS Runtime Prerequisites"
  require_ios_signing_prereqs
  require_physical_ios_developer_services
}

require_macos_signing_prereqs() {
  section "Signed macOS Build Prerequisites"
  require_valid_codesigning_identity

  require_target_development_team "macOS Runner" macos/Runner.xcodeproj/project.pbxproj Runner
  require_target_development_team "macOS PacketTunnel" macos/Runner.xcodeproj/project.pbxproj PacketTunnel
  require_project_teams_not_free_for_network_extensions \
    "Signed macOS build" \
    macos/Runner.xcodeproj/project.pbxproj
}

require_macos_developer_id_system_extension_migration_if_requested() {
  if [[ "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" != "1" ]]; then
    return 0
  fi

  section "macOS Developer ID Architecture Prerequisites"
  "${PYTHON_BIN}" - <<'PY'
import plistlib
import sys
from pathlib import Path

info_path = Path("macos/PacketTunnel/Info.plist")
entitlements_path = Path("macos/PacketTunnel/PacketTunnel.entitlements")

with info_path.open("rb") as handle:
    info = plistlib.load(handle)
with entitlements_path.open("rb") as handle:
    entitlements = plistlib.load(handle)

extension_point = (info.get("NSExtension") or {}).get("NSExtensionPointIdentifier")
network_extensions = entitlements.get("com.apple.developer.networking.networkextension") or []

reasons = []
if extension_point == "com.apple.networkextension.packet-tunnel":
    reasons.append(
        "macOS PacketTunnel is still packaged as an app-extension Packet Tunnel"
    )
if "packet-tunnel-provider-systemextension" not in network_extensions:
    reasons.append(
        "macOS PacketTunnel entitlements do not include packet-tunnel-provider-systemextension"
    )

if reasons:
    print(
        "macOS Developer ID export is intentionally disabled for the current "
        "PacketTunnel app-extension architecture.",
        file=sys.stderr,
    )
    for reason in reasons:
        print(f"- {reason}", file=sys.stderr)
    print(
        "Use the Mac App Store export lane for the current app-extension build, "
        "or migrate macOS distribution to a deliberate Network Extension System "
        "Extension target with matching Developer ID provisioning before running "
        "WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE=1.",
        file=sys.stderr,
    )
    raise SystemExit(78)

print("macOS Developer ID architecture prerequisites passed.")
PY
}

require_requested_signed_prereqs() {
  if [[ "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "1" && "${WINS_IOS_INSTALL}" != "1" ]]; then
    die "WINS_IOS_LIVE_TUNNEL_SMOKE=1 requires WINS_IOS_INSTALL=1 so the signed app is built and installed on the physical iPhone first."
  fi

  if [[ ("${WINS_IOS_ARCHIVE_SMOKE}" == "1" \
      || "${WINS_MACOS_ARCHIVE_SMOKE}" == "1" \
      || "${WINS_IOS_DEBUGGING_EXPORT_SMOKE}" == "1" \
      || "${WINS_MACOS_DEBUGGING_EXPORT_SMOKE}" == "1" \
      || "${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE}" == "1" \
      || "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
      || "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE}" == "1" \
      || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" \
      || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
      || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" \
      || "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1" \
      || "${WINS_APPLE_EXISTING_EXPORTS_SMOKE}" == "1" \
      || "${WINS_APPLE_VERIFY_EXISTING_EXPORTS_ONLY}" == "1" \
      || "${WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY}" == "1") \
    && "${WINS_REQUIRE_APPLE_ENGINE}" != "1" \
    && "${WINS_APPLE_WINN3_RELEASE:-0}" != "1" ]]; then
    die "Apple archive/export smoke requires a legacy engine gate or WINS_APPLE_WINN3_RELEASE=1."
  fi

  if [[ "${WINS_IOS_INSTALL}" == "1" ]]; then
    require_ios_signed_runtime_prereqs
    if [[ "${WINS_IOS_LAUNCH}" == "1" \
        || "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "1" \
        || "${WINS_IOS_APPROVE_VPN_PERMISSION}" == "1" ]]; then
      local ios_device_id
      ios_device_id="$(resolve_physical_ios_device_id)"
      [[ -n "${ios_device_id}" ]] || die "Could not resolve physical iOS device id for active-unlock prerequisite."
      require_physical_ios_active_unlock_for_launch \
        "${ios_device_id}" \
        "requested physical iOS launch/UI lane"
    fi
  elif [[ "${WINS_IOS_SIGNED_BUILD}" == "1" \
      || "${WINS_IOS_ARCHIVE_SMOKE}" == "1" \
      || "${WINS_IOS_DEBUGGING_EXPORT_SMOKE}" == "1" \
      || "${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE}" == "1" \
      || "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
      || "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE}" == "1" \
      || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" ]]; then
    require_ios_signing_prereqs
  fi

  if [[ "${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE}" == "1" \
      || "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
      || "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE}" == "1" \
      || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" ]]; then
    require_ios_distribution_profiles
  fi
  if [[ "${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE}" == "1" ]]; then
    require_ios_release_testing_profiles
  fi

  if [[ "${WINS_SIGNED_MACOS_BUILD}" == "1" \
      || "${WINS_MACOS_ARCHIVE_SMOKE}" == "1" \
      || "${WINS_MACOS_DEBUGGING_EXPORT_SMOKE}" == "1" \
      || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
      || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" \
      || "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1" ]]; then
    require_macos_signing_prereqs
  fi

  if [[ "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" \
      || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" == "1" \
      || "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1" ]]; then
    require_macos_distribution_profiles
  fi

  if app_store_connect_upload_lane_requested; then
    require_app_store_connect_upload_auth
  fi
}

physical_ios_device_id_or_empty() {
  [[ -x "${FLUTTER_BIN}" ]] || return 0
  "${FLUTTER_BIN}" devices --machine 2>/dev/null | "${PYTHON_BIN}" -c '
import json
import sys

try:
    devices = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)

for device in devices:
    platform = str(device.get("targetPlatform") or "").lower()
    name = str(device.get("name") or "")
    if platform == "ios" and not device.get("emulator") and ("iphone" in name.lower() or "ipad" in name.lower()):
        print(device.get("id") or "")
        raise SystemExit(0)
'
}

usb_ios_device_hint() {
  usb_ios_device_hint_source_or_empty >/dev/null
}

usb_ios_device_hint_source_or_empty() {
  if command -v system_profiler >/dev/null 2>&1 \
    && system_profiler SPUSBDataType 2>/dev/null | grep -Eiq 'iPhone|iPad|iPod'; then
    printf 'system_profiler\n'
    return 0
  fi

  if command -v ioreg >/dev/null 2>&1 \
    && ioreg -p IOUSB -l -w 0 2>/dev/null \
      | grep -Eiq '"(USB Product Name|kUSBProductString)" = "(iPhone|iPad|iPod)"|"SupportsIPhoneOS" = Yes'; then
    printf 'IORegistry\n'
    return 0
  fi

  return 1
}

devicectl_physical_ios_report() {
  command -v xcrun >/dev/null 2>&1 || return 0
  xcrun -f devicectl >/dev/null 2>&1 || return 0
  [[ -x "${PYTHON_BIN}" || "${PYTHON_BIN}" == "python3" ]] || return 0

  local json_output
  json_output="$(mktemp "${TMPDIR:-/tmp}/wins-devicectl-json.XXXXXX")"
  if ! xcrun devicectl list devices --timeout 5 --json-output "${json_output}" >/dev/null 2>&1; then
    rm -f "${json_output}"
    return 0
  fi

  "${PYTHON_BIN}" - "${json_output}" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text())
except Exception:
    raise SystemExit(0)

devices = payload.get("result", {}).get("devices", [])
for device in devices:
    hardware = device.get("hardwareProperties", {})
    properties = device.get("deviceProperties", {})
    connection = device.get("connectionProperties", {})
    if hardware.get("platform") != "iOS" or hardware.get("reality") != "physical":
        continue
    name = properties.get("name") or "unknown"
    os_version = properties.get("osVersionNumber") or "unknown"
    os_build = properties.get("osBuildUpdate") or "unknown"
    developer_mode = properties.get("developerModeStatus", "unknown")
    ddi = properties.get("ddiServicesAvailable", "unknown")
    pairing = connection.get("pairingState", "unknown")
    transport = connection.get("transportType", "unknown")
    print(
        "physical iOS devicectl: "
        f"name={name}; os={os_version} ({os_build}); "
        f"developerMode={developer_mode}; ddiServicesAvailable={ddi}; "
        f"pairing={pairing}; transport={transport}"
    )
PY
  rm -f "${json_output}"
}

devicectl_ios_lock_state_report() {
  local ios_device_id="$1"

  command -v xcrun >/dev/null 2>&1 || return 0
  xcrun -f devicectl >/dev/null 2>&1 || return 0
  [[ -x "${PYTHON_BIN}" || "${PYTHON_BIN}" == "python3" ]] || return 0

  local json_output
  json_output="$(mktemp "${TMPDIR:-/tmp}/wins-devicectl-lockstate.XXXXXX")"
  if ! xcrun devicectl device info lockState \
    --device "${ios_device_id}" \
    --timeout 10 \
    --json-output "${json_output}" >/dev/null 2>&1; then
    rm -f "${json_output}"
    printf 'physical iOS lock state: unavailable\n'
    return 0
  fi

  "${PYTHON_BIN}" - "${json_output}" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text())
except Exception:
    raise SystemExit(0)

result = payload.get("result", {})

def safe_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "unknown"
    text = str(value)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,48}", text):
        return "present"
    return text

parts = [
    f"passcodeRequired={safe_value(result.get('passcodeRequired'))}",
    f"unlockedSinceBoot={safe_value(result.get('unlockedSinceBoot'))}",
]

for key in ("lockState", "isLocked", "locked"):
    if key in result:
        parts.append(f"{key}={safe_value(result.get(key))}")

print("physical iOS lock state: " + "; ".join(parts))
PY
  rm -f "${json_output}"
}

devicectl_ios_display_report() {
  local ios_device_id="$1"

  command -v xcrun >/dev/null 2>&1 || return 0
  xcrun -f devicectl >/dev/null 2>&1 || return 0
  [[ -x "${PYTHON_BIN}" || "${PYTHON_BIN}" == "python3" ]] || return 0

  local json_output
  json_output="$(mktemp "${TMPDIR:-/tmp}/wins-devicectl-displays.XXXXXX")"
  if ! xcrun devicectl device info displays \
    --device "${ios_device_id}" \
    --timeout 10 \
    --json-output "${json_output}" >/dev/null 2>&1; then
    rm -f "${json_output}"
    printf 'physical iOS display state: unavailable\n'
    return 0
  fi

  "${PYTHON_BIN}" - "${json_output}" <<'PY'
import json
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text())
except Exception:
    raise SystemExit(0)

result = payload.get("result", {})
backlight = str(result.get("backlightState") or "unknown")
orientation = result.get("orientation") or {}
current_orientation = str(orientation.get("currentDeviceOrientation") or "unknown")

display = {}
for item in result.get("displays") or []:
    if isinstance(item, dict) and item.get("primary") is True:
        display = item
        break
if not display and result.get("displays"):
    first = result["displays"][0]
    if isinstance(first, dict):
        display = first

native_size = display.get("nativeSize") if isinstance(display, dict) else None
point_scale = display.get("pointScale") if isinstance(display, dict) else None
if isinstance(native_size, list) and len(native_size) == 2:
    size_summary = f"{native_size[0]}x{native_size[1]}"
else:
    size_summary = "unknown"

print(
    "physical iOS display state: "
    f"backlight={backlight}; orientation={current_orientation}; "
    f"primarySize={size_summary}; pointScale={point_scale or 'unknown'}"
)
PY
  rm -f "${json_output}"
}

physical_ios_active_unlock_blocker_or_empty() {
  local ios_device_id="$1"

  command -v xcrun >/dev/null 2>&1 || return 0
  xcrun -f devicectl >/dev/null 2>&1 || return 0
  [[ -x "${PYTHON_BIN}" || "${PYTHON_BIN}" == "python3" ]] || return 0

  local lock_json display_json lock_status display_status
  lock_json="$(mktemp "${TMPDIR:-/tmp}/wins-devicectl-lockstate.XXXXXX")"
  display_json="$(mktemp "${TMPDIR:-/tmp}/wins-devicectl-displays.XXXXXX")"
  lock_status=0
  display_status=0

  xcrun devicectl device info lockState \
    --device "${ios_device_id}" \
    --timeout 10 \
    --json-output "${lock_json}" >/dev/null 2>&1 || lock_status="$?"
  xcrun devicectl device info displays \
    --device "${ios_device_id}" \
    --timeout 10 \
    --json-output "${display_json}" >/dev/null 2>&1 || display_status="$?"

  "${PYTHON_BIN}" - "${lock_json}" "${lock_status}" "${display_json}" "${display_status}" <<'PY'
import json
import sys
from pathlib import Path

lock_path, lock_status, display_path, display_status = sys.argv[1:5]
reasons = []

def load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return {}

if lock_status == "0":
    result = load_json(lock_path).get("result", {})
    for key in ("locked", "isLocked"):
        value = result.get(key)
        if value is True:
            reasons.append(f"CoreDevice lockState reports {key}=true")
    lock_state = str(result.get("lockState") or "").strip().lower()
    if lock_state in {"locked", "passcode_locked", "device_locked"}:
        reasons.append(f"CoreDevice lockState reports {lock_state}")

if display_status == "0":
    result = load_json(display_path).get("result", {})
    backlight = str(result.get("backlightState") or "").strip().lower()
    if backlight == "off":
        reasons.append("CoreDevice display backlight is off")

if reasons:
    print("; ".join(reasons))
PY

  rm -f "${lock_json}" "${display_json}"
}

require_physical_ios_active_unlock_for_launch() {
  local ios_device_id="$1"
  local lane_label="$2"
  local blocker
  blocker="$(physical_ios_active_unlock_blocker_or_empty "${ios_device_id}" || true)"
  if [[ -z "${blocker}" ]]; then
    printf 'physical iOS active-unlock preflight: no lock/display blocker observed for %s\n' "${lane_label}"
    return 0
  fi

  devicectl_ios_lock_state_report "${ios_device_id}"
  devicectl_ios_display_report "${ios_device_id}"
  ios_screen_viewing_report
  die "Physical iOS active unlock is required before ${lane_label}: ${blocker}. Unlock the iPhone or open a controllable iPhone Mirroring window from an unlocked Mac session, then rerun this lane."
}

ios_screen_viewing_report() {
  command -v xcrun >/dev/null 2>&1 || return 0
  xcrun -f devicectl >/dev/null 2>&1 || return 0
  [[ -x "${PYTHON_BIN}" || "${PYTHON_BIN}" == "python3" ]] || return 0

  local json_output
  json_output="$(mktemp "${TMPDIR:-/tmp}/wins-devicectl-screen.XXXXXX")"
  if xcrun devicectl list devices --timeout 5 --json-output "${json_output}" >/dev/null 2>&1; then
    "${PYTHON_BIN}" - "${json_output}" <<'PY'
import json
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text())
except Exception:
    raise SystemExit(0)

for device in payload.get("result", {}).get("devices", []):
    hardware = device.get("hardwareProperties", {})
    properties = device.get("deviceProperties", {})
    if hardware.get("platform") != "iOS" or hardware.get("reality") != "physical":
        continue
    url = properties.get("screenViewingURL")
    print(
        "physical iOS screen viewing: "
        f"coreDeviceURL={'present' if url else 'absent'}"
    )
    break
PY
  fi
  rm -f "${json_output}"

  command -v osascript >/dev/null 2>&1 || return 0

  local mirroring_state mirroring_output mirroring_pid mirroring_started mirroring_timed_out
  mirroring_output="$(mktemp "${TMPDIR:-/tmp}/wins-iphone-mirroring.XXXXXX")"
  mirroring_timed_out=0
  osascript >"${mirroring_output}" 2>/dev/null <<'APPLESCRIPT' &
tell application "System Events"
  if exists process "iPhone Mirroring" then
    tell process "iPhone Mirroring"
      return "running; windows=" & (count of windows as text)
    end tell
  else
    return "not-running"
  end if
end tell
APPLESCRIPT
  mirroring_pid="$!"
  mirroring_started="${SECONDS}"
  while kill -0 "${mirroring_pid}" >/dev/null 2>&1; do
    if (( SECONDS - mirroring_started >= WINS_APPLE_AUTOMATION_DIAGNOSTIC_TIMEOUT_SECONDS )); then
      mirroring_timed_out=1
      kill "${mirroring_pid}" >/dev/null 2>&1 || true
      break
    fi
    sleep 0.2
  done
  wait "${mirroring_pid}" >/dev/null 2>&1 || true
  mirroring_state="$(cat "${mirroring_output}" 2>/dev/null || true)"
  rm -f "${mirroring_output}"

  if [[ "${mirroring_timed_out}" == "1" ]]; then
    printf 'iPhone Mirroring automation state: unavailable (diagnostic timed out after %ss)\n' \
      "${WINS_APPLE_AUTOMATION_DIAGNOSTIC_TIMEOUT_SECONDS}"
    return 0
  fi
  if [[ -n "${mirroring_state}" ]]; then
    printf 'iPhone Mirroring automation state: %s\n' "${mirroring_state}"
  fi
}

ios_active_unlock_note_if_needed() {
  if [[ "${WINS_IOS_LAUNCH}" != "1" \
    && "${WINS_IOS_LIVE_TUNNEL_SMOKE}" != "1" \
    && "${WINS_IOS_APPROVE_VPN_PERMISSION}" != "1" ]]; then
    return
  fi

  printf 'physical iOS active-unlock note: devicectl lockState reports passcode/unlocked-since-boot only on some iOS versions; launch, live VPN, and permission UI lanes still require the iPhone to be actively unlocked at SpringBoard or through iPhone Mirroring from an unlocked Mac session.\n'
}

require_physical_ios_developer_services() {
  command -v xcrun >/dev/null 2>&1 || die "xcrun is required for physical iOS device readiness checks."
  xcrun -f devicectl >/dev/null 2>&1 || die "devicectl is required for physical iOS device readiness checks."

  local json_output ios_device_id details_output
  json_output="$(mktemp "${TMPDIR:-/tmp}/wins-devicectl-json.XXXXXX")"
  if ! xcrun devicectl list devices --timeout 5 --json-output "${json_output}" >/dev/null 2>&1; then
    rm -f "${json_output}"
    die "devicectl could not list physical iOS devices."
  fi

  # CoreDevice can initially report ddiServicesAvailable=false for a paired,
  # wired, unlocked phone until a command actually opens the developer-service
  # connection. Warm that connection once, then refresh and strictly validate
  # the list result below. The details command is never itself treated as a
  # pass, so a locked, untrusted, or unprepared phone still fails closed.
  ios_device_id="$("${PYTHON_BIN}" - "${json_output}" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
for device in payload.get("result", {}).get("devices", []):
    hardware = device.get("hardwareProperties", {})
    if hardware.get("platform") == "iOS" and hardware.get("reality") == "physical":
        identifier = device.get("identifier")
        if isinstance(identifier, str) and identifier:
            print(identifier)
        break
PY
)"
  if [[ -n "${ios_device_id}" ]]; then
    details_output="$(mktemp "${TMPDIR:-/tmp}/wins-devicectl-details.XXXXXX")"
    xcrun devicectl device info details \
      --device "${ios_device_id}" \
      --timeout 30 \
      --json-output "${details_output}" >/dev/null 2>&1 || true
    rm -f "${details_output}"
    if ! xcrun devicectl list devices --timeout 5 --json-output "${json_output}" >/dev/null 2>&1; then
      rm -f "${json_output}"
      die "devicectl could not refresh physical iOS developer-service state."
    fi
  fi

  if ! "${PYTHON_BIN}" - "${json_output}" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
devices = payload.get("result", {}).get("devices", [])
physical_ios = [
    device for device in devices
    if device.get("hardwareProperties", {}).get("platform") == "iOS"
    and device.get("hardwareProperties", {}).get("reality") == "physical"
]

if not physical_ios:
    print("No physical iOS device is visible to devicectl.")
    raise SystemExit(1)

device = physical_ios[0]
properties = device.get("deviceProperties", {})
connection = device.get("connectionProperties", {})
errors = []

if connection.get("pairingState") != "paired":
    errors.append(f"pairingState={connection.get('pairingState')!r}, expected 'paired'")
if properties.get("developerModeStatus") != "enabled":
    errors.append(
        f"developerModeStatus={properties.get('developerModeStatus')!r}, expected 'enabled'"
    )
if properties.get("ddiServicesAvailable") is not True:
    errors.append(
        f"ddiServicesAvailable={properties.get('ddiServicesAvailable')!r}, expected True"
    )

if errors:
    print("Physical iOS device is not ready for install/launch testing:")
    for error in errors:
        print(f"- {error}")
    print("Enable Developer Mode on the iPhone, reboot/confirm if prompted, keep it unlocked and trusted, then rerun.")
    raise SystemExit(1)

print("Physical iOS device developer services: ok")
PY
  then
    rm -f "${json_output}"
    exit 1
  fi

  rm -f "${json_output}"
}

ios_simulator_id_or_empty() {
  command -v xcrun >/dev/null 2>&1 || return 0
  xcrun simctl list devices available --json 2>/dev/null | "${PYTHON_BIN}" -c '
import json
import sys

try:
    devices_by_runtime = json.load(sys.stdin).get("devices", {})
except Exception:
    raise SystemExit(0)

candidates = []
for runtime, devices in devices_by_runtime.items():
    if "iOS" not in runtime:
        continue
    for device in devices:
        if not device.get("isAvailable", True):
            continue
        name = str(device.get("name") or "")
        if "iPhone" not in name:
            continue
        candidates.append(device)

if not candidates:
    raise SystemExit(0)

booted = [device for device in candidates if device.get("state") == "Booted"]
preferred = booted or [device for device in candidates if "16 Pro Max" in str(device.get("name") or "")] or candidates
print(preferred[0].get("udid") or "")
'
}

latest_macos_debug_app_or_empty() {
  [[ -d "${HOME}/Library/Developer/Xcode/DerivedData" ]] || return 0
  "${PYTHON_BIN}" - <<'PY'
from pathlib import Path

root = Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData"
apps = []
for app_name in ("Win's VPN.app", "wins_vpn.app"):
    apps.extend(path for path in root.glob(f"**/Build/Products/Debug/{app_name}") if path.is_dir())
if apps:
    print(max(apps, key=lambda path: path.stat().st_mtime))
PY
}

latest_macos_release_app_or_empty() {
  "${PYTHON_BIN}" - <<'PY'
from pathlib import Path

derived_data_root = Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData"
project_release_root = Path.cwd() / "build" / "macos" / "Build" / "Products" / "Release"
apps = []
for app_name in ("Win's VPN.app", "wins_vpn.app"):
    project_app = project_release_root / app_name
    if project_app.is_dir():
        apps.append(project_app)
    if derived_data_root.is_dir():
        apps.extend(path for path in derived_data_root.glob(f"**/Build/Products/Release/{app_name}") if path.is_dir())
if apps:
    print(max(apps, key=lambda path: path.stat().st_mtime))
PY
}

latest_macos_launch_app_or_empty() {
  local app_path
  if [[ "${WINS_MACOS_LAUNCH_RELEASE}" == "1" ]]; then
    app_path="$(latest_macos_release_app_or_empty || true)"
    if [[ -n "${app_path}" ]]; then
      printf '%s\n' "${app_path}"
      return 0
    fi
  fi
  app_path="$(latest_macos_debug_app_or_empty || true)"
  if [[ -n "${app_path}" ]]; then
    printf '%s\n' "${app_path}"
    return 0
  fi
  latest_macos_release_app_or_empty || true
}

macos_app_executable_path() {
  local app_path="$1"
  local info_plist="${app_path}/Contents/Info.plist"
  local executable_name
  executable_name="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "${info_plist}" 2>/dev/null || true)"
  [[ -n "${executable_name}" ]] || return 1
  printf '%s\n' "${app_path}/Contents/MacOS/${executable_name}"
}

print_runtime_candidate_binding() {
  local platform="$1"
  "${PYTHON_BIN}" - "${platform}" <<'PY'
import json
import sys
from pathlib import Path

platform = sys.argv[1]
manifest_path = Path("app_store/apple/artifacts/release_candidate.json")
with manifest_path.open(encoding="utf-8") as handle:
    manifest = json.load(handle)

for artifact in manifest.get("artifacts", []):
    if artifact.get("platform") != platform:
        continue
    artifact_hash = str(artifact.get("sha256") or "").strip()
    source_hash = str(artifact.get("source_fingerprint_sha256") or "").strip()
    if len(artifact_hash) != 64 or len(source_hash) != 64:
        raise SystemExit(
            f"{platform} release candidate manifest is missing valid runtime-binding hashes"
        )
    print(f"Runtime candidate artifact SHA-256: {artifact_hash}")
    print(f"Runtime candidate source fingerprint SHA-256: {source_hash}")
    break
else:
    raise SystemExit(f"release candidate manifest does not contain {platform!r}")
PY
}

refresh_macos_app_registration() {
  local app_path="$1"
  local app_icon="${app_path}/Contents/Resources/AppIcon.icns"
  local packet_tunnel_path="${app_path}/Contents/PlugIns/PacketTunnel.appex"
  local bundle_id=""
  local packet_tunnel_registered=0
  local registration_attempt
  local lsregister
  lsregister="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

  bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${app_path}/Contents/Info.plist" 2>/dev/null || true)"
  /usr/bin/touch "${app_path}" "${app_icon}" >/dev/null 2>&1 || true
  if [[ -x "${lsregister}" ]]; then
    if [[ -n "${bundle_id}" ]]; then
      printf 'Refreshing macOS LaunchServices registration for %s (%s)\n' "${bundle_id}" "${app_path}"
    else
      printf 'Refreshing macOS LaunchServices registration for %s\n' "${app_path}"
    fi
    printf '+ %s -u %s\n' "${lsregister}" "${app_path}"
    "${lsregister}" -u "${app_path}" >/dev/null 2>&1 || true
    printf '+ %s -f %s\n' "${lsregister}" "${app_path}"
    "${lsregister}" -f "${app_path}" >/dev/null 2>&1 || true
  fi

  if command -v pluginkit >/dev/null 2>&1 && [[ -d "${packet_tunnel_path}" ]]; then
    printf '+ pluginkit -a %s\n' "${packet_tunnel_path}"
    run pluginkit -a "${packet_tunnel_path}"
    for registration_attempt in {1..20}; do
      if pluginkit -m -A -vv -i "${bundle_id}.PacketTunnel" 2>/dev/null \
        | grep -Fq "${packet_tunnel_path}"; then
        packet_tunnel_registered=1
        break
      fi
      sleep 0.5
    done
    [[ "${packet_tunnel_registered}" == "1" ]] \
      || die "macOS PacketTunnel extension did not register from the current signed app bundle."
    printf 'Registered macOS PacketTunnel extension from current signed app: %s\n' \
      "${packet_tunnel_path}"
  fi
}

verify_ios_simulator_screenshot_transition() {
  local baseline_screenshot="$1"
  local launched_screenshot="$2"
  local bmp_dir
  bmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/wins-ios-sim-bmp.XXXXXX")"

  /usr/bin/sips -s format bmp "${baseline_screenshot}" --out "${bmp_dir}/baseline.bmp" >/dev/null
  /usr/bin/sips -s format bmp "${launched_screenshot}" --out "${bmp_dir}/launched.bmp" >/dev/null

  "${PYTHON_BIN}" - "${bmp_dir}/baseline.bmp" "${bmp_dir}/launched.bmp" <<'PY'
import struct
import sys
from pathlib import Path


def load_bmp(path):
    data = Path(path).read_bytes()
    if data[:2] != b"BM":
        raise SystemExit(f"{path}: not a BMP screenshot")
    offset = struct.unpack_from("<I", data, 10)[0]
    width = struct.unpack_from("<i", data, 18)[0]
    height = struct.unpack_from("<i", data, 22)[0]
    bpp = struct.unpack_from("<H", data, 28)[0]
    if width <= 0 or height == 0:
        raise SystemExit(f"{path}: invalid BMP dimensions {width}x{height}")
    if bpp not in (24, 32):
        raise SystemExit(f"{path}: unsupported BMP bit depth {bpp}")
    absolute_height = abs(height)
    row_stride = ((width * bpp + 31) // 32) * 4
    return {
        "data": data,
        "offset": offset,
        "width": width,
        "height": absolute_height,
        "top_down": height < 0,
        "bytes_per_pixel": bpp // 8,
        "row_stride": row_stride,
    }


def pixel(image, x, y):
    row = y if image["top_down"] else image["height"] - 1 - y
    index = image["offset"] + row * image["row_stride"] + x * image["bytes_per_pixel"]
    return image["data"][index : index + 3]


baseline = load_bmp(sys.argv[1])
launched = load_bmp(sys.argv[2])
if baseline["width"] != launched["width"] or baseline["height"] != launched["height"]:
    raise SystemExit(
        "iOS simulator screenshots have mismatched dimensions: "
        f"{baseline['width']}x{baseline['height']} vs "
        f"{launched['width']}x{launched['height']}"
    )

width = baseline["width"]
height = baseline["height"]
step = max(8, min(width, height) // 80)
sample_count = 0
changed_count = 0
total_channel_delta = 0

for y in range(height // 5, height * 4 // 5, step):
    for x in range(width // 5, width * 4 // 5, step):
        first = pixel(baseline, x, y)
        second = pixel(launched, x, y)
        delta = sum(abs(a - b) for a, b in zip(first, second))
        total_channel_delta += delta
        sample_count += 1
        if delta > 24:
            changed_count += 1

if sample_count == 0:
    raise SystemExit("iOS simulator screenshot verifier sampled no pixels")

mean_channel_delta = total_channel_delta / (sample_count * 3)
changed_fraction = changed_count / sample_count
print(
    "iOS simulator screenshot transition: "
    f"mean_channel_delta={mean_channel_delta:.2f}; "
    f"changed_fraction={changed_fraction:.3f}"
)
if mean_channel_delta < 8 or changed_fraction < 0.08:
    raise SystemExit(
        "iOS simulator launch did not visibly replace the home screen; "
        "the app may be blank, hidden, or stuck before first frame"
    )
PY

  rm -rf "${bmp_dir}"
}

latest_ios_device_debug_app_or_empty() {
  [[ -d "${HOME}/Library/Developer/Xcode/DerivedData" ]] || return 0
  "${PYTHON_BIN}" - <<'PY'
from pathlib import Path

root = Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData"
apps = [path for path in root.glob("**/Build/Products/Debug-iphoneos/Runner.app") if path.is_dir()]
if apps:
    print(max(apps, key=lambda path: path.stat().st_mtime))
PY
}

latest_ios_device_profile_app_or_empty() {
  [[ -d "${HOME}/Library/Developer/Xcode/DerivedData" ]] || return 0
  "${PYTHON_BIN}" - <<'PY'
from pathlib import Path

root = Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData"
apps = [path for path in root.glob("**/Build/Products/Profile-iphoneos/Runner.app") if path.is_dir()]
if apps:
    print(max(apps, key=lambda path: path.stat().st_mtime))
PY
}

latest_ios_device_release_app_or_empty() {
  [[ -d "${HOME}/Library/Developer/Xcode/DerivedData" ]] || return 0
  "${PYTHON_BIN}" - <<'PY'
from pathlib import Path

root = Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData"
apps = [path for path in root.glob("**/Build/Products/Release-iphoneos/Runner.app") if path.is_dir()]
if apps:
    print(max(apps, key=lambda path: path.stat().st_mtime))
PY
}

verify_apple_app_bundle() {
  local label="$1"
  local app_path="$2"
  local expected_app_bundle_id="$3"
  local expected_packet_tunnel_bundle_id="$4"
  local bundle_layout="$5"
  local expected_supported_platform="$6"

  "${PYTHON_BIN}" - \
    "${label}" \
    "${app_path}" \
    "${expected_app_bundle_id}" \
    "${expected_packet_tunnel_bundle_id}" \
    "${bundle_layout}" \
    "${expected_supported_platform}" \
    "${APPLE_APP_GROUP_ID}" \
    "${APPLE_MACOS_APP_GROUP_ID}" <<'PY'
import plistlib
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

(
    label,
    app_path,
    expected_app_bundle_id,
    expected_packet_tunnel_bundle_id,
    bundle_layout,
    expected_supported_platform,
    ios_app_group,
    macos_app_group,
) = sys.argv[1:9]
app = Path(app_path)
require_complete_engine = os.environ.get("WINS_REQUIRE_APPLE_ENGINE") == "1"
require_signed_entitlements = label.startswith("Signed") or label.startswith("Exported")
skip_network_extension_entitlement_contract = expected_supported_platform == "iPhoneSimulator"
expected_app_group = macos_app_group if bundle_layout == "macos" else ios_app_group
# Debug configurations sign with their own keychain group (the iOS Debug
# WINS_KEYCHAIN_ACCESS_GROUP is $(AppIdentifierPrefix)org.winsvpn.shared.debug);
# release bundles must carry org.winsvpn.shared.
expected_keychain_group_suffix = (
    "org.winsvpn.shared.debug"
    if expected_app_bundle_id.endswith(".debug")
    else "org.winsvpn.shared"
)
if not app.is_dir():
    raise SystemExit(f"{label}: app bundle does not exist: {app}")

if bundle_layout == "macos":
    app_info = app / "Contents" / "Info.plist"
    app_privacy = app / "Contents" / "Resources" / "PrivacyInfo.xcprivacy"
    app_executable_root = app / "Contents" / "MacOS"
    extension = app / "Contents" / "PlugIns" / "PacketTunnel.appex"
    info = extension / "Contents" / "Info.plist"
    extension_privacy = extension / "Contents" / "Resources" / "PrivacyInfo.xcprivacy"
    executable = extension / "Contents" / "MacOS" / "PacketTunnel"
else:
    app_info = app / "Info.plist"
    app_privacy = app / "PrivacyInfo.xcprivacy"
    app_executable_root = app
    extension = app / "PlugIns" / "PacketTunnel.appex"
    info = extension / "Info.plist"
    extension_privacy = extension / "PrivacyInfo.xcprivacy"
    executable = extension / "PacketTunnel"
    watch_app = app / "Watch" / "WinsWatch.app"
    watch_info = watch_app / "Info.plist"
    watch_privacy = watch_app / "PrivacyInfo.xcprivacy"
    legacy_watch_extension = watch_app / "PlugIns" / "WinsWatch Extension.appex"

FILE_TIMESTAMP_API = "NSPrivacyAccessedAPICategoryFileTimestamp"
USER_DEFAULTS_API = "NSPrivacyAccessedAPICategoryUserDefaults"
SYSTEM_BOOT_TIME_API = "NSPrivacyAccessedAPICategorySystemBootTime"
APP_FUNCTIONALITY_PURPOSE = "NSPrivacyCollectedDataTypePurposeAppFunctionality"
EXPECTED_HOST_COLLECTED_DATA = {
    "NSPrivacyCollectedDataTypeCoarseLocation",
    "NSPrivacyCollectedDataTypeDeviceID",
    "NSPrivacyCollectedDataTypeUserID",
    "NSPrivacyCollectedDataTypeProductInteraction",
}

def require_supported_platform(candidate, subject, supported_platform=None):
    supported_platform = supported_platform or expected_supported_platform
    platforms = candidate.get("CFBundleSupportedPlatforms")
    if platforms != [supported_platform]:
        raise SystemExit(
            f"{label}: {subject} supported platforms {platforms!r}, expected [{supported_platform!r}]"
        )

def require_privacy_manifest(privacy_path, subject, expected_api_reasons, host=False):
    if not privacy_path.is_file():
        raise SystemExit(f"{label}: {subject} PrivacyInfo.xcprivacy is missing")
    with privacy_path.open("rb") as handle:
        manifest = plistlib.load(handle)
    if manifest.get("NSPrivacyTracking") is not False:
        raise SystemExit(f"{label}: {subject} privacy manifest must disable tracking")
    tracking_domains = manifest.get("NSPrivacyTrackingDomains")
    if tracking_domains not in ([], None):
        raise SystemExit(f"{label}: {subject} privacy tracking domains must be empty")

    api_reasons = {}
    for item in manifest.get("NSPrivacyAccessedAPITypes") or []:
        api_type = item.get("NSPrivacyAccessedAPIType")
        if not isinstance(api_type, str) or not api_type:
            raise SystemExit(f"{label}: {subject} privacy API type must be a string")
        if api_type in api_reasons:
            raise SystemExit(f"{label}: {subject} duplicate privacy API type {api_type}")
        reasons = item.get("NSPrivacyAccessedAPITypeReasons") or []
        if not isinstance(reasons, list) or any(not isinstance(reason, str) for reason in reasons):
            raise SystemExit(f"{label}: {subject} privacy API reasons are malformed")
        if len(reasons) != len(set(reasons)):
            raise SystemExit(f"{label}: {subject} duplicate privacy API reason")
        api_reasons[api_type] = set(reasons)
    if api_reasons != expected_api_reasons:
        raise SystemExit(
            f"{label}: {subject} privacy API reasons {api_reasons!r}, "
            f"expected {expected_api_reasons!r}"
        )

    collected = {}
    for item in manifest.get("NSPrivacyCollectedDataTypes") or []:
        data_type = item.get("NSPrivacyCollectedDataType")
        if not isinstance(data_type, str) or not data_type:
            raise SystemExit(f"{label}: {subject} collected data type must be a string")
        if data_type in collected:
            raise SystemExit(f"{label}: {subject} duplicate collected data type {data_type}")
        collected[data_type] = item
    if host:
        expected = set(EXPECTED_HOST_COLLECTED_DATA)
        if set(collected) != expected:
            raise SystemExit(
                f"{label}: {subject} privacy collected data {sorted(collected)!r}, expected {sorted(expected)!r}"
            )
        for data_type in sorted(expected):
            item = collected[data_type]
            if item.get("NSPrivacyCollectedDataTypeLinked") is not True:
                raise SystemExit(f"{label}: {subject} {data_type} must be linked")
            if item.get("NSPrivacyCollectedDataTypeTracking") is not False:
                raise SystemExit(f"{label}: {subject} {data_type} must not be tracking")
            purposes = set(item.get("NSPrivacyCollectedDataTypePurposes") or [])
            if purposes != {APP_FUNCTIONALITY_PURPOSE}:
                raise SystemExit(f"{label}: {subject} {data_type} missing app functionality purpose")
    elif collected:
        raise SystemExit(
            f"{label}: {subject} privacy manifest should not declare collected data: {sorted(collected)!r}"
        )

def require_empty_privacy_manifest(privacy_path, subject):
    if not privacy_path.is_file():
        raise SystemExit(f"{label}: {subject} PrivacyInfo.xcprivacy is missing")
    with privacy_path.open("rb") as handle:
        manifest = plistlib.load(handle)
    if manifest.get("NSPrivacyTracking") is not False:
        raise SystemExit(f"{label}: {subject} privacy manifest must disable tracking")
    if manifest.get("NSPrivacyTrackingDomains") not in ([], None):
        raise SystemExit(f"{label}: {subject} privacy tracking domains must be empty")
    if manifest.get("NSPrivacyAccessedAPITypes") not in ([], None):
        raise SystemExit(f"{label}: {subject} must not declare unused required-reason APIs")
    if manifest.get("NSPrivacyCollectedDataTypes") not in ([], None):
        raise SystemExit(f"{label}: {subject} must not declare collected data")

def require_macho_platform(executable_path, subject, supported_platform=None):
    supported_platform = supported_platform or expected_supported_platform
    expected_macho_platforms = {
        "iPhoneOS": "IOS",
        "iPhoneSimulator": "IOSSIMULATOR",
        "MacOSX": "MACOS",
        "WatchOS": "WATCHOS",
        "WatchSimulator": "WATCHSIMULATOR",
    }
    expected = expected_macho_platforms.get(supported_platform)
    if expected is None:
        raise SystemExit(
            f"{label}: no expected Mach-O platform mapping for {supported_platform!r}"
        )
    try:
        completed = subprocess.run(
            ["xcrun", "vtool", "-show-build", str(executable_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        stderr = getattr(error, "stderr", "") or ""
        detail = stderr.strip() or str(error)
        raise SystemExit(f"{label}: could not inspect {subject} Mach-O platform: {detail}")
    platforms = re.findall(r"^\s*platform\s+([A-Z0-9_]+)\s*$", completed.stdout, re.MULTILINE)
    if not platforms:
        raise SystemExit(f"{label}: {subject} Mach-O LC_BUILD_VERSION platform is missing")
    unexpected = sorted({platform for platform in platforms if platform != expected})
    if unexpected:
        raise SystemExit(
            f"{label}: {subject} Mach-O platforms {platforms!r}, expected only {expected!r}"
        )

def require_macos_app_icon(icon_path):
    if not icon_path.is_file():
        raise SystemExit(f"{label}: compiled macOS AppIcon.icns is missing")
    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "AppIcon.iconset"
        try:
            subprocess.run(
                ["iconutil", "-c", "iconset", str(icon_path), "-o", str(iconset)],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            stderr = getattr(error, "stderr", "") or ""
            detail = stderr.strip() or str(error)
            raise SystemExit(f"{label}: compiled macOS AppIcon.icns is unreadable: {detail}")
        required_icons = [
            "icon_16x16.png",
            "icon_16x16@2x.png",
            "icon_32x32.png",
            "icon_32x32@2x.png",
            "icon_128x128.png",
            "icon_128x128@2x.png",
            "icon_256x256.png",
            "icon_256x256@2x.png",
            "icon_512x512.png",
            "icon_512x512@2x.png",
        ]
        missing = [name for name in required_icons if not (iconset / name).is_file()]
        if missing:
            raise SystemExit(
                f"{label}: compiled macOS AppIcon.icns is incomplete; "
                f"missing {', '.join(missing)}"
            )
        source_icon = Path("macos/Runner/Assets.xcassets/AppIcon.appiconset/app_icon_1024.png")
        compiled_1024_icon = iconset / "icon_512x512@2x.png"
        if source_icon.is_file():
            source_bmp = Path(tmp) / "source.bmp"
            compiled_bmp = Path(tmp) / "compiled.bmp"
            for input_path, output_path in (
                (source_icon, source_bmp),
                (compiled_1024_icon, compiled_bmp),
            ):
                try:
                    subprocess.run(
                        ["sips", "-s", "format", "bmp", str(input_path), "--out", str(output_path)],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                except (OSError, subprocess.CalledProcessError) as error:
                    stderr = getattr(error, "stderr", "") or ""
                    detail = stderr.strip() or str(error)
                    raise SystemExit(
                        f"{label}: could not normalize macOS icon pixels: {detail}"
                    )
            source_hash = hashlib.sha256(source_bmp.read_bytes()).hexdigest()
            compiled_hash = hashlib.sha256(compiled_bmp.read_bytes()).hexdigest()
            if compiled_hash != source_hash:
                raise SystemExit(
                    f"{label}: compiled macOS AppIcon.icns 1024 slot does not match "
                    f"Win Empire source icon; got sha256 {compiled_hash}, expected {source_hash}"
                )

def require_ios_app_icon_asset_catalog(asset_catalog):
    if not asset_catalog.is_file():
        raise SystemExit(f"{label}: compiled iOS Assets.car is missing")
    try:
        completed = subprocess.run(
            ["xcrun", "assetutil", "--info", str(asset_catalog)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        stderr = getattr(error, "stderr", "") or ""
        detail = stderr.strip() or str(error)
        raise SystemExit(f"{label}: compiled iOS Assets.car is unreadable: {detail}")
    try:
        renditions = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"{label}: compiled iOS Assets.car did not produce JSON: {error}")

    def require_source_marketing_icon():
        source_icon = Path(
            "ios/Runner/Assets.xcassets/AppIcon.appiconset/Icon-App-1024x1024@1x.png"
        )
        if not source_icon.is_file():
            raise SystemExit(f"{label}: iOS source AppIcon marketing icon is missing")
        data = source_icon.read_bytes()
        # Owner ruling 2026-10-16 (calculator disguise kept): reviewed iOS marketing icon source PNG.
        expected_sha256 = "0b8e4f2a0f9c75ba120bba8d7a034477199a7c6ce757f8368a26bcf3dca51e77"
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != expected_sha256:
            raise SystemExit(
                f"{label}: iOS source AppIcon marketing icon changed; "
                f"got sha256 {actual_sha256}, expected {expected_sha256}"
            )
        if len(data) < 26 or data[:8] != b"\x89PNG\r\n\x1a\n":
            raise SystemExit(f"{label}: iOS source AppIcon marketing icon is not a PNG")
        width = int.from_bytes(data[16:20], "big")
        height = int.from_bytes(data[20:24], "big")
        color_type = data[25]
        if (width, height) != (1024, 1024):
            raise SystemExit(
                f"{label}: iOS source AppIcon marketing icon size {width}x{height}, expected 1024x1024"
            )
        if color_type in (4, 6):
            raise SystemExit(f"{label}: iOS source AppIcon marketing icon must be opaque")

    marketing_slot = {
            "idiom": "marketing",
            "width": 1024,
            "height": 1024,
            "scale": 1,
            "rendition": "Icon-App-1024x1024@1x.png",
            # Owner ruling 2026-10-16 (calculator disguise kept): reviewed iOS marketing icon as compiled into Assets.car (Xcode 27.0 27A266a).
            "digest": "3FE5426220052BD3E70D93F319453838AE0F0D9D9D784E6F3662C13B4B227EA8",
    }
    calculator_marketing_slot = {
            "idiom": "marketing",
            "width": 1024,
            "height": 1024,
            "scale": 1,
            "rendition": "Calculator-1024.png",
            "digest": "B831D95142B06ECF20BC38BBC9E005AFD4D6BE7DFBE253BF884BFCB004923903",
    }
    runtime_slots = [
        {
            "idiom": "phone",
            "width": 120,
            "height": 120,
            "scale": 2,
            "rendition": "Icon-App-60x60@2x.png",
        },
        {
            "idiom": "phone",
            "width": 180,
            "height": 180,
            "scale": 3,
            "rendition": "Icon-App-60x60@3x.png",
        },
    ]

    icon_renditions = [
        item for item in renditions
        if item.get("Name") == "AppIcon" and item.get("AssetType") == "Icon Image"
    ]
    if not icon_renditions:
        raise SystemExit(f"{label}: compiled iOS Assets.car does not contain AppIcon images")

    calculator_renditions = [
        item for item in renditions
        if item.get("Name") == "CalculatorIcon" and item.get("AssetType") == "Icon Image"
    ]
    if not calculator_renditions:
        raise SystemExit(
            f"{label}: compiled iOS Assets.car does not contain CalculatorIcon images"
        )

    for item in icon_renditions:
        if item.get("Opaque") is not True:
            raise SystemExit(
                f"{label}: compiled iOS AppIcon rendition {item.get('RenditionName')} must be opaque"
            )
    for item in calculator_renditions:
        if item.get("Opaque") is not True:
            raise SystemExit(
                f"{label}: compiled iOS CalculatorIcon rendition "
                f"{item.get('RenditionName')} must be opaque"
            )

    is_thinned_catalog = any(
        isinstance(item, dict) and item.get("ThinningParameters")
        for item in renditions
    )

    compiled_marketing_matches = [
        item for item in icon_renditions
        if item.get("Idiom") == marketing_slot["idiom"]
        and item.get("PixelWidth") == marketing_slot["width"]
        and item.get("PixelHeight") == marketing_slot["height"]
        and item.get("Scale") == marketing_slot["scale"]
        and item.get("RenditionName") == marketing_slot["rendition"]
    ]
    if len(compiled_marketing_matches) == 1:
        compiled_marketing = compiled_marketing_matches[0]
        if compiled_marketing.get("SHA1Digest") != marketing_slot["digest"]:
            raise SystemExit(
                f"{label}: compiled iOS AppIcon marketing digest changed; "
                f"got {compiled_marketing.get('SHA1Digest')}, expected {marketing_slot['digest']}"
            )
    elif len(compiled_marketing_matches) == 0 and is_thinned_catalog:
        require_source_marketing_icon()
    else:
        raise SystemExit(
            f"{label}: compiled iOS Assets.car expected exactly one AppIcon "
            f"{marketing_slot['idiom']} {marketing_slot['width']}x{marketing_slot['height']}@{marketing_slot['scale']}x "
            f"rendition {marketing_slot['rendition']}, found {len(compiled_marketing_matches)}"
        )

    compiled_calculator_matches = [
        item for item in calculator_renditions
        if item.get("Idiom") == calculator_marketing_slot["idiom"]
        and item.get("PixelWidth") == calculator_marketing_slot["width"]
        and item.get("PixelHeight") == calculator_marketing_slot["height"]
        and item.get("Scale") == calculator_marketing_slot["scale"]
        and item.get("RenditionName") == calculator_marketing_slot["rendition"]
    ]
    if len(compiled_calculator_matches) == 1:
        compiled_calculator = compiled_calculator_matches[0]
        if compiled_calculator.get("SHA1Digest") != calculator_marketing_slot["digest"]:
            raise SystemExit(
                f"{label}: compiled iOS CalculatorIcon marketing digest changed; "
                f"got {compiled_calculator.get('SHA1Digest')}, "
                f"expected {calculator_marketing_slot['digest']}"
            )
    elif len(compiled_calculator_matches) != 0 or not is_thinned_catalog:
        raise SystemExit(
            f"{label}: compiled iOS Assets.car expected exactly one CalculatorIcon "
            f"marketing rendition, found {len(compiled_calculator_matches)}"
        )

    matched_runtime_slots = 0
    for slot in runtime_slots:
        matches = [
            item for item in icon_renditions
            if item.get("Idiom") == slot["idiom"]
            and item.get("PixelWidth") == slot["width"]
            and item.get("PixelHeight") == slot["height"]
            and item.get("Scale") == slot["scale"]
            and item.get("RenditionName") == slot["rendition"]
        ]
        if len(matches) == 1:
            matched_runtime_slots += 1
        elif len(matches) == 0 and is_thinned_catalog:
            continue
        else:
            raise SystemExit(
                f"{label}: compiled iOS Assets.car expected exactly one AppIcon "
                f"{slot['idiom']} {slot['width']}x{slot['height']}@{slot['scale']}x "
                f"rendition {slot['rendition']}, found {len(matches)}"
            )

    if is_thinned_catalog and matched_runtime_slots == 0:
        raise SystemExit(
            f"{label}: thinned compiled iOS Assets.car is missing phone AppIcon runtime renditions"
        )
    print(f"{label}: compiled iOS AppIcon and CalculatorIcon asset catalogs verified")

def signed_entitlements(bundle_path, subject):
    try:
        completed = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(bundle_path)],
            check=False,
            capture_output=True,
        )
    except OSError as error:
        if require_signed_entitlements:
            raise SystemExit(f"{label}: could not inspect signed {subject} entitlements: {error}")
        return None

    if completed.returncode != 0 or not completed.stdout.strip():
        if require_signed_entitlements:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise SystemExit(
                f"{label}: signed {subject} entitlements are missing"
                + (f": {detail}" if detail else "")
            )
        return None

    try:
        return plistlib.loads(completed.stdout)
    except Exception as error:
        raise SystemExit(f"{label}: signed {subject} entitlements are not a plist: {error}")

def require_signed_entitlement_contract(bundle_path, subject):
    if skip_network_extension_entitlement_contract:
        return

    entitlements = signed_entitlements(bundle_path, subject)
    if entitlements is None:
        return

    network_extensions = entitlements.get("com.apple.developer.networking.networkextension") or []
    if "packet-tunnel-provider" not in network_extensions:
        raise SystemExit(
            f"{label}: signed {subject} is missing packet-tunnel-provider entitlement"
        )

    app_groups = entitlements.get("com.apple.security.application-groups") or []
    if expected_app_group not in app_groups:
        raise SystemExit(
            f"{label}: signed {subject} App Group entitlement {app_groups!r}, "
            f"expected {expected_app_group!r}"
        )

    keychain_groups = entitlements.get("keychain-access-groups") or []
    if not any(str(group).endswith("org.winsvpn.shared") for group in keychain_groups):
        raise SystemExit(
            f"{label}: signed {subject} is missing shared keychain access group"
        )

engine_artifact_names_by_component = {
    "amneziawg_packet_engine": [
        "WinsAmneziaWGPacketEngine",
        "AmneziaWGPacketEngine",
        "amneziawg_packet_engine",
    ],
    "xray_vless_ws_transport": [
        "WinsXrayVlessWsTransport",
        "XrayVlessWsTransport",
        "xray_vless_ws_transport",
    ],
    "winn_packet_engine": [
        "WinsWinnPacketEngine",
        "WinnPacketEngine",
        "winn_packet_engine",
    ],
}

engine_required_symbols_by_component = {
    "amneziawg_packet_engine": [
        "wins_amneziawg_packet_engine_contract_version",
        "wins_amneziawg_packet_engine_create",
        "wins_amneziawg_packet_engine_start",
        "wins_amneziawg_packet_engine_stop",
        "wins_amneziawg_packet_engine_destroy",
    ],
    "xray_vless_ws_transport": [
        "wins_xray_vless_ws_transport_contract_version",
        "wins_xray_vless_ws_transport_configure",
        "wins_xray_vless_ws_transport_start",
        "wins_xray_vless_ws_transport_stop",
    ],
    "winn_packet_engine": [
        "wins_winn_packet_engine_contract_version",
        "wins_winn_packet_engine_create",
        "wins_winn_packet_engine_start",
        "wins_winn_packet_engine_stop",
        "wins_winn_packet_engine_destroy",
        "wins_winn_packet_engine_awg_seam_port",
        "wins_winn_packet_engine_seam_stats",
        "wins_winn_packet_engine_status_json",
        "WinnTunnelCreateWinn3",
    ],
}

def engine_search_roots():
    containing_app_frameworks = extension.parent.parent / "Frameworks"
    roots = [
        containing_app_frameworks,
        extension,
        extension / "Frameworks",
        extension / "Libraries",
    ]
    if bundle_layout == "macos":
        roots.extend([
            extension / "Contents",
            extension / "Contents" / "Frameworks",
            extension / "Contents" / "Libraries",
            extension / "Contents" / "Resources" / "Frameworks",
            extension / "Contents" / "Resources" / "Libraries",
            extension / "Contents" / "MacOS",
        ])
    return roots

def framework_executable(framework_path):
    info_path = framework_path / "Info.plist"
    executable_name = framework_path.stem
    if info_path.is_file():
        with info_path.open("rb") as handle:
            framework_plist = plistlib.load(handle)
        executable_name = str(framework_plist.get("CFBundleExecutable") or executable_name)
    executable_path = framework_path / executable_name
    if not executable_path.is_file():
        raise SystemExit(
            f"{label}: engine artifact {framework_path.name} executable is missing"
        )
    return executable_path

def exported_symbols(executable_path, subject):
    try:
        completed = subprocess.run(
            ["xcrun", "nm", "-gU", str(executable_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        stderr = getattr(error, "stderr", "") or ""
        detail = stderr.strip() or str(error)
        raise SystemExit(f"{label}: could not inspect {subject} exported symbols: {detail}")
    symbols = set()
    for line in completed.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        symbol = parts[-1]
        if symbol.startswith("_"):
            symbol = symbol[1:]
        symbols.add(symbol)
    if not symbols:
        raise SystemExit(f"{label}: {subject} has no exported global symbols")
    return symbols

def imported_libraries(executable_path, subject):
    try:
        completed = subprocess.run(
            ["xcrun", "otool", "-L", str(executable_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        stderr = getattr(error, "stderr", "") or ""
        detail = stderr.strip() or str(error)
        raise SystemExit(f"{label}: could not inspect {subject} dynamic library dependencies: {detail}")
    libraries = set()
    for line in completed.stdout.splitlines()[1:]:
        parts = line.split()
        if parts:
            libraries.add(parts[0])
    if not libraries:
        raise SystemExit(f"{label}: {subject} has no inspectable dynamic library dependencies")
    return libraries

def require_engine_symbols(component, executable_path):
    required = engine_required_symbols_by_component[component]
    symbols = exported_symbols(executable_path, f"engine artifact {component}")
    missing = [symbol for symbol in required if symbol not in symbols]
    if missing:
        raise SystemExit(
            f"{label}: engine artifact {component} is missing required Win's VPN C ABI symbols: "
            f"{', '.join(missing)}"
        )

def require_engine_dependencies(component, executable_path):
    if component != "xray_vless_ws_transport":
        return
    libraries = imported_libraries(executable_path, f"engine artifact {component}")
    required_dependency = "@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"
    if required_dependency not in libraries:
        raise SystemExit(
            f"{label}: engine artifact {component} must depend on {required_dependency}"
        )

def candidate_engine_artifacts():
    artifacts = []
    seen = set()
    for component, names in engine_artifact_names_by_component.items():
        for root in engine_search_roots():
            if not root.exists():
                continue
            for name in names:
                for candidate in [
                    root / f"{name}.framework",
                    root / f"lib{name}.dylib",
                    root / f"{name}.dylib",
                    root / name,
                ]:
                    if candidate in seen or not candidate.exists():
                        continue
                    seen.add(candidate)
                    artifacts.append((component, candidate))
    return artifacts

def verify_engine_artifacts():
    if bundle_layout == "ios":
        unsupported_dylibs = []
        for dylib in extension.rglob("*.dylib"):
            is_xcode_debug_image = (
                dylib.name.endswith(".debug.dylib") or dylib.name == "__preview.dylib"
            )
            if (
                ".framework" not in dylib.as_posix()
                and not dylib.name.startswith("libswift")
                and not is_xcode_debug_image
            ):
                unsupported_dylibs.append(dylib)
        if unsupported_dylibs:
            names = ", ".join(path.name for path in unsupported_dylibs)
            raise SystemExit(
                f"{label}: iOS app extensions cannot contain standalone dynamic libraries: {names}"
            )
    artifacts = candidate_engine_artifacts()
    required_components = sorted(engine_artifact_names_by_component)
    if not artifacts:
        if require_complete_engine:
            raise SystemExit(
                f"{label}: missing required Apple engine artifacts: {', '.join(required_components)}"
            )
        print(f"{label}: no Apple AWG/Xray/Winn engine artifacts bundled yet")
        return
    verified_components = []
    for component, artifact in artifacts:
        if artifact.is_symlink():
            raise SystemExit(f"{label}: engine artifact {component} must not be a symlink")
        if artifact.suffix == ".framework":
            if not artifact.is_dir():
                raise SystemExit(f"{label}: engine artifact {component} framework is not a directory")
            artifact_executable = framework_executable(artifact)
            require_macho_platform(
                artifact_executable,
                f"engine artifact {component}",
            )
            require_engine_symbols(component, artifact_executable)
            require_engine_dependencies(component, artifact_executable)
            privacy_path = (
                artifact / "Versions" / "A" / "Resources" / "PrivacyInfo.xcprivacy"
                if bundle_layout == "macos"
                else artifact / "PrivacyInfo.xcprivacy"
            )
            expected_engine_apis = {FILE_TIMESTAMP_API: {"C617.1"}}
            if component == "winn_packet_engine":
                expected_engine_apis[SYSTEM_BOOT_TIME_API] = {"35F9.1"}
            require_privacy_manifest(
                privacy_path,
                f"engine artifact {component}",
                expected_engine_apis,
            )
        elif artifact.is_file():
            require_macho_platform(artifact, f"engine artifact {component}")
            require_engine_symbols(component, artifact)
            require_engine_dependencies(component, artifact)
        else:
            raise SystemExit(f"{label}: engine artifact {component} has unsupported bundle shape")
        verified_components.append(component)
    verified_component_set = set(verified_components)
    missing_components = [
        component for component in required_components
        if component not in verified_component_set
    ]
    if missing_components and require_complete_engine:
        raise SystemExit(
            f"{label}: missing required Apple engine artifacts: {', '.join(missing_components)}"
        )
    verified_summary = ", ".join(sorted(verified_component_set))
    if missing_components:
        print(
            f"{label}: partial Apple engine artifacts verified: "
            f"{verified_summary}; missing: {', '.join(missing_components)}"
        )
        return
    print(f"{label}: verified Apple engine artifacts: {verified_summary}")

if not app_info.is_file():
    raise SystemExit(f"{label}: host app Info.plist is missing")
with app_info.open("rb") as handle:
    app_plist = plistlib.load(handle)

require_supported_platform(app_plist, "host app")
require_privacy_manifest(
    app_privacy,
    "host app",
    {
        FILE_TIMESTAMP_API: {"C617.1"},
        USER_DEFAULTS_API: {"CA92.1"},
        SYSTEM_BOOT_TIME_API: {"35F9.1"},
    },
    host=True,
)

app_bundle_id = app_plist.get("CFBundleIdentifier")
if app_bundle_id != expected_app_bundle_id:
    raise SystemExit(
        f"{label}: host app bundle id {app_bundle_id!r}, expected {expected_app_bundle_id!r}"
    )

expected_host_name = "Win's VPN"
for key, expected in (
    ("CFBundleDisplayName", expected_host_name),
    ("CFBundleName", expected_host_name),
):
    actual = app_plist.get(key)
    if actual != expected:
        raise SystemExit(f"{label}: host app {key} {actual!r}, expected {expected!r}")

host_version_name = str(app_plist.get("CFBundleShortVersionString") or "")
host_build_number = str(app_plist.get("CFBundleVersion") or "")
if not host_version_name or not host_build_number:
    raise SystemExit(f"{label}: host app version or build number is missing")

app_executable_name = str(app_plist.get("CFBundleExecutable") or "")
if not app_executable_name:
    raise SystemExit(f"{label}: host app executable name is missing from Info.plist")
app_executable = app_executable_root / app_executable_name
if not app_executable.is_file():
    raise SystemExit(f"{label}: host app executable is missing")
require_macho_platform(app_executable, "host app executable")

if bundle_layout == "macos":
    if app.name != "Win's VPN.app":
        raise SystemExit(
            f"{label}: macOS app bundle name {app.name!r}, expected \"Win's VPN.app\""
        )
    app_icon_file = str(app_plist.get("CFBundleIconFile") or "")
    app_icon_name = str(app_plist.get("CFBundleIconName") or "")
    if app_icon_file != "AppIcon" or app_icon_name != "AppIcon":
        raise SystemExit(
            f"{label}: macOS app icon metadata file={app_icon_file!r} name={app_icon_name!r}, "
            "expected AppIcon"
        )
    app_category = str(app_plist.get("LSApplicationCategoryType") or "")
    if app_category != "public.app-category.utilities":
        raise SystemExit(
            f"{label}: macOS app category {app_category!r}, expected public.app-category.utilities"
        )
    require_macos_app_icon(app / "Contents" / "Resources" / "AppIcon.icns")
    flutter_app_executable = app / "Contents" / "Frameworks" / "App.framework" / "App"
    main_dart = Path("lib/main.dart")
    if not flutter_app_executable.is_file():
        raise SystemExit(f"{label}: Flutter App.framework executable is missing")
    if main_dart.is_file() and flutter_app_executable.stat().st_mtime + 1 < main_dart.stat().st_mtime:
        raise SystemExit(
            f"{label}: Flutter App.framework is older than lib/main.dart; "
            "the macOS Dart bundle is stale"
        )
else:
    require_ios_app_icon_asset_catalog(app / "Assets.car")

app_keychain_group = str(app_plist.get("WinsAppleSharedKeychainAccessGroup") or "")
if not app_keychain_group.endswith(expected_keychain_group_suffix):
    raise SystemExit(
        f"{label}: host app shared keychain group marker is missing or unexpected"
    )
require_signed_entitlement_contract(app, "host app")

if not extension.is_dir():
    raise SystemExit(f"{label}: PacketTunnel.appex is not embedded")
if not info.is_file():
    raise SystemExit(f"{label}: PacketTunnel Info.plist is missing")
if not executable.is_file():
    raise SystemExit(f"{label}: PacketTunnel executable is missing")
require_macho_platform(executable, "PacketTunnel executable")

with info.open("rb") as handle:
    plist = plistlib.load(handle)

require_supported_platform(plist, "PacketTunnel")
require_privacy_manifest(
    extension_privacy,
    "PacketTunnel",
    {
        FILE_TIMESTAMP_API: {"C617.1"},
        SYSTEM_BOOT_TIME_API: {"35F9.1"},
    },
)

bundle_id = plist.get("CFBundleIdentifier")
if bundle_id != expected_packet_tunnel_bundle_id:
    raise SystemExit(
        f"{label}: PacketTunnel bundle id {bundle_id!r}, expected {expected_packet_tunnel_bundle_id!r}"
    )

for key, expected in (
    ("CFBundleShortVersionString", host_version_name),
    ("CFBundleVersion", host_build_number),
):
    actual = str(plist.get(key) or "")
    if actual != expected:
        raise SystemExit(
            f"{label}: PacketTunnel {key} {actual!r}, expected host value {expected!r}"
        )

extension_info = plist.get("NSExtension") or {}
extension_point = extension_info.get("NSExtensionPointIdentifier")
if extension_point != "com.apple.networkextension.packet-tunnel":
    raise SystemExit(
        f"{label}: PacketTunnel extension point {extension_point!r}, expected packet tunnel"
    )

principal_class = str(extension_info.get("NSExtensionPrincipalClass") or "")
if "PacketTunnelProvider" not in principal_class:
    raise SystemExit(
        f"{label}: PacketTunnel principal class {principal_class!r} does not name PacketTunnelProvider"
    )

keychain_group = str(plist.get("WinsAppleSharedKeychainAccessGroup") or "")
if not keychain_group.endswith(expected_keychain_group_suffix):
    raise SystemExit(
        f"{label}: shared keychain group marker is missing or unexpected"
    )
require_signed_entitlement_contract(extension, "PacketTunnel")

if bundle_layout == "ios":
    if not watch_app.is_dir():
        raise SystemExit(f"{label}: WinsWatch.app is not embedded in the iOS app")
    if not watch_info.is_file():
        raise SystemExit(f"{label}: WinsWatch Info.plist is missing")
    if legacy_watch_extension.exists():
        raise SystemExit(f"{label}: legacy WinsWatch Extension.appex must not be embedded")

    with watch_info.open("rb") as handle:
        watch_plist = plistlib.load(handle)
    watch_supported_platform = (
        "WatchSimulator" if expected_supported_platform == "iPhoneSimulator" else "WatchOS"
    )
    require_supported_platform(watch_plist, "WinsWatch", watch_supported_platform)
    require_empty_privacy_manifest(watch_privacy, "WinsWatch")

    expected_watch_bundle_id = f"{expected_app_bundle_id}.watchkitapp"
    if watch_plist.get("CFBundleIdentifier") != expected_watch_bundle_id:
        raise SystemExit(
            f"{label}: WinsWatch bundle id {watch_plist.get('CFBundleIdentifier')!r}, "
            f"expected {expected_watch_bundle_id!r}"
        )
    if watch_plist.get("WKCompanionAppBundleIdentifier") != expected_app_bundle_id:
        raise SystemExit(
            f"{label}: WinsWatch companion id "
            f"{watch_plist.get('WKCompanionAppBundleIdentifier')!r}, "
            f"expected {expected_app_bundle_id!r}"
        )
    if watch_plist.get("WKRunsIndependentlyOfCompanionApp") is not False:
        raise SystemExit(f"{label}: WinsWatch must be companion-only")
    for subject, candidate in (("WinsWatch", watch_plist),):
        for key, expected in (
            ("CFBundleShortVersionString", host_version_name),
            ("CFBundleVersion", host_build_number),
        ):
            actual = str(candidate.get(key) or "")
            if actual != expected:
                raise SystemExit(
                    f"{label}: {subject} {key} {actual!r}, expected host value {expected!r}"
                )

    watch_executable_name = str(watch_plist.get("CFBundleExecutable") or "")
    watch_executable = watch_app / watch_executable_name
    if not watch_executable.is_file():
        raise SystemExit(f"{label}: watch app executable is missing")
    require_macho_platform(watch_executable, "WinsWatch executable", watch_supported_platform)

if skip_network_extension_entitlement_contract:
    print(
        f"{label}: skipped Network Extension entitlement contract for simulator-only bundle"
    )

verify_engine_artifacts()

watch_summary = " plus watch companion" if bundle_layout == "ios" else ""
print(f"{label}: host app and embedded PacketTunnel{watch_summary} verified ({app_bundle_id} / {bundle_id}; {expected_supported_platform} Mach-O)")
PY
  # Keep the bundle contract's status: callers that run this under set +e (the engine artifact
  # gate self-test) must see its failure, not the status of the iOS-only name check below.
  local bundle_contract_rc=$?
  (( bundle_contract_rc == 0 )) || return "${bundle_contract_rc}"
  if [[ "${bundle_layout}" == "ios" ]]; then
    verify_ios_bundle_names "${label}" "${app_path}"
  fi
}

verify_ios_bundle_names() {
  # Owner ruling 2026-10-25: the built host and Watch apps are named "Win's VPN" and the
  # PacketTunnel extension "Win's VPN Helper". The source plists are checked by the readiness
  # gate; this checks the processed Info.plists inside the archive or exported IPA, so an Xcode
  # build setting that rewrites a name (App Store Connect error ITMS-90129) cannot pass.
  local label="$1"
  local app_path="$2"
  require_cmd "${PYTHON_BIN}"
  "${PYTHON_BIN}" - "${label}" "${app_path}" <<'PY'
import plistlib
import sys
from pathlib import Path

label, app = sys.argv[1], Path(sys.argv[2])
app_name = "Win's VPN"
for subject, info, expected in (
    ("host app", app / "Info.plist", app_name),
    ("WinsWatch", app / "Watch" / "WinsWatch.app" / "Info.plist", app_name),
    ("PacketTunnel", app / "PlugIns" / "PacketTunnel.appex" / "Info.plist", f"{app_name} Helper"),
):
    try:
        with info.open("rb") as handle:
            plist = plistlib.load(handle)
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        raise SystemExit(f"{label}: {subject} Info.plist could not be read to check its name: {exc}")
    for key in ("CFBundleDisplayName", "CFBundleName"):
        if plist.get(key) != expected:
            raise SystemExit(f"{label}: {subject} {key} {plist.get(key)!r}, expected {expected!r}")
print(f"{label}: host, WinsWatch and PacketTunnel bundle names verified ({app_name!r}).")
PY
}

run_engine_artifact_selftest() {
  section "Apple Engine Artifact Gate Self-Test"

  local tmp app extension frameworks awg_framework xray_framework winn_framework output status
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/wins-engine-artifacts.XXXXXX")"
  app="${tmp}/Win's VPN.app"
  extension="${app}/Contents/PlugIns/PacketTunnel.appex"
  frameworks="${app}/Contents/Frameworks"
  awg_framework="${frameworks}/WinsAmneziaWGPacketEngine.framework"
  xray_framework="${frameworks}/WinsXrayVlessWsTransport.framework"
  winn_framework="${frameworks}/WinsWinnPacketEngine.framework"

  mkdir -p \
    "${app}/Contents/MacOS" \
    "${app}/Contents/Resources" \
    "${extension}/Contents/MacOS" \
    "${extension}/Contents/Resources" \
    "${awg_framework}"
  cp /usr/bin/true "${app}/Contents/MacOS/Win's VPN"
  SRCROOT="${ROOT_DIR}/macos" \
    TARGET_BUILD_DIR="${app}/Contents" \
    UNLOCALIZED_RESOURCES_FOLDER_PATH="Resources" \
    DERIVED_FILE_DIR="${tmp}/derived" \
    /bin/bash "${ROOT_DIR}/tools/ensure_macos_app_icon.sh" >/dev/null
  cp /usr/bin/true "${extension}/Contents/MacOS/PacketTunnel"
  mkdir -p "${app}/Contents/Frameworks/App.framework"
  touch "${app}/Contents/Frameworks/App.framework/App"

  local clang_bin="clang"
  if command -v xcrun >/dev/null 2>&1; then
    clang_bin="$(xcrun -f clang 2>/dev/null || printf 'clang')"
  fi
  command -v "${clang_bin}" >/dev/null 2>&1 || [[ -x "${clang_bin}" ]] \
    || die "Apple engine artifact gate self-test requires clang."

  local sdk_path=""
  if command -v xcrun >/dev/null 2>&1; then
    sdk_path="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
  fi
  local clang_args=(-dynamiclib)
  if [[ -n "${sdk_path}" ]]; then
    clang_args+=(-isysroot "${sdk_path}")
  fi

  "${clang_bin}" "${clang_args[@]}" \
    -Wl,-install_name,@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine \
    -x c - -o "${awg_framework}/WinsAmneziaWGPacketEngine" <<'C'
int wins_amneziawg_packet_engine_contract_version(void) { return 1; }
void *wins_amneziawg_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)1; }
int wins_amneziawg_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
void wins_amneziawg_packet_engine_stop(void *engine) { (void)engine; }
void wins_amneziawg_packet_engine_destroy(void *engine) { (void)engine; }
C

  cat > "${app}/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>Win's VPN</string>
  <key>CFBundleDisplayName</key>
  <string>Win's VPN</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIconName</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>org.winsvpn.app</string>
  <key>CFBundleName</key>
  <string>Win's VPN</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.utilities</string>
  <key>CFBundleSupportedPlatforms</key>
  <array>
    <string>MacOSX</string>
  </array>
  <key>WinsAppleSharedKeychainAccessGroup</key>
  <string>TEAMID.org.winsvpn.shared</string>
</dict>
</plist>
PLIST

  cat > "${extension}/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>PacketTunnel</string>
  <key>CFBundleIdentifier</key>
  <string>org.winsvpn.app.PacketTunnel</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>CFBundleSupportedPlatforms</key>
  <array>
    <string>MacOSX</string>
  </array>
  <key>NSExtension</key>
  <dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.networkextension.packet-tunnel</string>
    <key>NSExtensionPrincipalClass</key>
    <string>PacketTunnel.PacketTunnelProvider</string>
  </dict>
  <key>WinsAppleSharedKeychainAccessGroup</key>
  <string>TEAMID.org.winsvpn.shared</string>
</dict>
</plist>
PLIST

  cat > "${app}/Contents/Resources/PrivacyInfo.xcprivacy" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>NSPrivacyAccessedAPITypes</key>
  <array>
    <dict>
      <key>NSPrivacyAccessedAPIType</key>
      <string>NSPrivacyAccessedAPICategoryFileTimestamp</string>
      <key>NSPrivacyAccessedAPITypeReasons</key>
      <array>
        <string>C617.1</string>
      </array>
    </dict>
    <dict>
      <key>NSPrivacyAccessedAPIType</key>
      <string>NSPrivacyAccessedAPICategoryUserDefaults</string>
      <key>NSPrivacyAccessedAPITypeReasons</key>
      <array>
        <string>CA92.1</string>
      </array>
    </dict>
    <dict>
      <key>NSPrivacyAccessedAPIType</key>
      <string>NSPrivacyAccessedAPICategorySystemBootTime</string>
      <key>NSPrivacyAccessedAPITypeReasons</key>
      <array>
        <string>35F9.1</string>
      </array>
    </dict>
  </array>
  <key>NSPrivacyCollectedDataTypes</key>
  <array>
    <dict>
      <key>NSPrivacyCollectedDataType</key>
      <string>NSPrivacyCollectedDataTypeCoarseLocation</string>
      <key>NSPrivacyCollectedDataTypeLinked</key>
      <true/>
      <key>NSPrivacyCollectedDataTypePurposes</key>
      <array>
        <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
      </array>
      <key>NSPrivacyCollectedDataTypeTracking</key>
      <false/>
    </dict>
    <dict>
      <key>NSPrivacyCollectedDataType</key>
      <string>NSPrivacyCollectedDataTypeDeviceID</string>
      <key>NSPrivacyCollectedDataTypeLinked</key>
      <true/>
      <key>NSPrivacyCollectedDataTypePurposes</key>
      <array>
        <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
      </array>
      <key>NSPrivacyCollectedDataTypeTracking</key>
      <false/>
    </dict>
    <dict>
      <key>NSPrivacyCollectedDataType</key>
      <string>NSPrivacyCollectedDataTypeUserID</string>
      <key>NSPrivacyCollectedDataTypeLinked</key>
      <true/>
      <key>NSPrivacyCollectedDataTypePurposes</key>
      <array>
        <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
      </array>
      <key>NSPrivacyCollectedDataTypeTracking</key>
      <false/>
    </dict>
    <dict>
      <key>NSPrivacyCollectedDataType</key>
      <string>NSPrivacyCollectedDataTypeProductInteraction</string>
      <key>NSPrivacyCollectedDataTypeLinked</key>
      <true/>
      <key>NSPrivacyCollectedDataTypePurposes</key>
      <array>
        <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
      </array>
      <key>NSPrivacyCollectedDataTypeTracking</key>
      <false/>
    </dict>
  </array>
  <key>NSPrivacyTracking</key>
  <false/>
  <key>NSPrivacyTrackingDomains</key>
  <array/>
</dict>
</plist>
PLIST

  cat > "${extension}/Contents/Resources/PrivacyInfo.xcprivacy" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>NSPrivacyAccessedAPITypes</key>
  <array>
    <dict>
      <key>NSPrivacyAccessedAPIType</key>
      <string>NSPrivacyAccessedAPICategoryFileTimestamp</string>
      <key>NSPrivacyAccessedAPITypeReasons</key>
      <array>
        <string>C617.1</string>
      </array>
    </dict>
    <dict>
      <key>NSPrivacyAccessedAPIType</key>
      <string>NSPrivacyAccessedAPICategorySystemBootTime</string>
      <key>NSPrivacyAccessedAPITypeReasons</key>
      <array>
        <string>35F9.1</string>
      </array>
    </dict>
  </array>
  <key>NSPrivacyCollectedDataTypes</key>
  <array/>
  <key>NSPrivacyTracking</key>
  <false/>
  <key>NSPrivacyTrackingDomains</key>
  <array/>
</dict>
</plist>
PLIST

  # macOS engine frameworks carry their own manifest at
  # Versions/A/Resources/PrivacyInfo.xcprivacy: FileTimestamp C617.1 for AWG and
  # Xray, plus SystemBootTime 35F9.1 for Winn (verify_engine_artifacts).
  mkdir -p "${awg_framework}/Versions/A/Resources"
  cat > "${awg_framework}/Versions/A/Resources/PrivacyInfo.xcprivacy" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>NSPrivacyAccessedAPITypes</key>
  <array>
    <dict>
      <key>NSPrivacyAccessedAPIType</key>
      <string>NSPrivacyAccessedAPICategoryFileTimestamp</string>
      <key>NSPrivacyAccessedAPITypeReasons</key>
      <array>
        <string>C617.1</string>
      </array>
    </dict>
  </array>
  <key>NSPrivacyCollectedDataTypes</key>
  <array/>
  <key>NSPrivacyTracking</key>
  <false/>
  <key>NSPrivacyTrackingDomains</key>
  <array/>
</dict>
</plist>
PLIST

  set +e
  output="$(
    WINS_REQUIRE_APPLE_ENGINE=0 verify_apple_app_bundle \
      "Exported engine artifact self-test app" \
      "${app}" \
      "org.winsvpn.app" \
      "org.winsvpn.app.PacketTunnel" \
      macos \
      MacOSX 2>&1
  )"
  status="$?"
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"signed host app entitlements are missing"* ]]; then
    rm -rf "${tmp}"
    die "Apple engine artifact gate self-test expected exported unsigned entitlement failure, got status=${status}: ${output}"
  fi

  set +e
  output="$(
    WINS_REQUIRE_APPLE_ENGINE=1 verify_apple_app_bundle \
      "Engine artifact self-test" \
      "${app}" \
      "org.winsvpn.app" \
      "org.winsvpn.app.PacketTunnel" \
      macos \
      MacOSX 2>&1
  )"
  status="$?"
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"missing required Apple engine artifacts: winn_packet_engine, xray_vless_ws_transport"* ]]; then
    rm -rf "${tmp}"
    die "Apple engine artifact gate self-test expected missing Xray failure, got status=${status}: ${output}"
  fi

  mkdir -p "${xray_framework}/Versions/A/Resources"
  cp "${awg_framework}/Versions/A/Resources/PrivacyInfo.xcprivacy" \
    "${xray_framework}/Versions/A/Resources/PrivacyInfo.xcprivacy"
  cp /usr/bin/true "${xray_framework}/WinsXrayVlessWsTransport"
  set +e
  output="$(
    WINS_REQUIRE_APPLE_ENGINE=1 verify_apple_app_bundle \
      "Engine artifact self-test" \
      "${app}" \
      "org.winsvpn.app" \
      "org.winsvpn.app.PacketTunnel" \
      macos \
      MacOSX 2>&1
  )"
  status="$?"
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"engine artifact xray_vless_ws_transport is missing required Win's VPN C ABI symbols"* ]]; then
    rm -rf "${tmp}"
    die "Apple engine artifact gate self-test expected Xray ABI failure, got status=${status}: ${output}"
  fi

  "${clang_bin}" "${clang_args[@]}" -x c - -o "${xray_framework}/WinsXrayVlessWsTransport" <<'C'
int wins_xray_vless_ws_transport_contract_version(void) { return 1; }
int wins_xray_vless_ws_transport_configure(const char *launch_json) { return launch_json == (const char *)0 ? 0 : 1; }
int wins_xray_vless_ws_transport_start(void) { return 1; }
void wins_xray_vless_ws_transport_stop(void) {}
C
  set +e
  output="$(
    WINS_REQUIRE_APPLE_ENGINE=1 verify_apple_app_bundle \
      "Engine artifact self-test" \
      "${app}" \
      "org.winsvpn.app" \
      "org.winsvpn.app.PacketTunnel" \
      macos \
      MacOSX 2>&1
  )"
  status="$?"
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"must depend on @rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"* ]]; then
    rm -rf "${tmp}"
    die "Apple engine artifact gate self-test expected Xray dependency failure, got status=${status}: ${output}"
  fi

  "${clang_bin}" "${clang_args[@]}" \
    -F"${frameworks}" \
    -framework WinsAmneziaWGPacketEngine \
    -Wl,-install_name,@rpath/WinsXrayVlessWsTransport.framework/WinsXrayVlessWsTransport \
    -Wl,-rpath,@loader_path/.. \
    -x c - -o "${xray_framework}/WinsXrayVlessWsTransport" <<'C'
extern int wins_amneziawg_packet_engine_contract_version(void);
int wins_xray_vless_ws_transport_contract_version(void) { return 1; }
int wins_xray_vless_ws_transport_configure(const char *launch_json) { return launch_json == (const char *)0 ? 0 : wins_amneziawg_packet_engine_contract_version(); }
int wins_xray_vless_ws_transport_start(void) { return wins_amneziawg_packet_engine_contract_version(); }
void wins_xray_vless_ws_transport_stop(void) {}
C
  set +e
  output="$(
    WINS_REQUIRE_APPLE_ENGINE=1 verify_apple_app_bundle \
      "Engine artifact self-test" \
      "${app}" \
      "org.winsvpn.app" \
      "org.winsvpn.app.PacketTunnel" \
      macos \
      MacOSX 2>&1
  )"
  status="$?"
  set -e
  if [[ "${status}" -eq 0 || "${output}" != *"missing required Apple engine artifacts: winn_packet_engine"* ]]; then
    rm -rf "${tmp}"
    die "Apple engine artifact gate self-test expected missing Winn failure, got status=${status}: ${output}"
  fi

  mkdir -p "${winn_framework}/Versions/A/Resources"
  cp "${extension}/Contents/Resources/PrivacyInfo.xcprivacy" \
    "${winn_framework}/Versions/A/Resources/PrivacyInfo.xcprivacy"
  "${clang_bin}" "${clang_args[@]}" \
    -Wl,-install_name,@rpath/WinsWinnPacketEngine.framework/WinsWinnPacketEngine \
    -x c - -o "${winn_framework}/WinsWinnPacketEngine" <<'C'
int wins_winn_packet_engine_contract_version(void) { return 1; }
void *wins_winn_packet_engine_create(const char *launch_json, const void *packet_flow) { (void)launch_json; (void)packet_flow; return (void *)1; }
int wins_winn_packet_engine_start(void *engine) { return engine == (void *)0 ? 0 : 1; }
void wins_winn_packet_engine_stop(void *engine) { (void)engine; }
void wins_winn_packet_engine_destroy(void *engine) { (void)engine; }
int wins_winn_packet_engine_awg_seam_port(void *engine) { return engine == (void *)0 ? 0 : 1; }
const char *wins_winn_packet_engine_seam_stats(void *engine) { (void)engine; return "{}"; }
const char *wins_winn_packet_engine_status_json(void *engine) { (void)engine; return "{}"; }
void *WinnTunnelCreateWinn3(const char *launch_json) { (void)launch_json; return (void *)1; }
C
  WINS_REQUIRE_APPLE_ENGINE=1 verify_apple_app_bundle \
    "Engine artifact self-test" \
    "${app}" \
    "org.winsvpn.app" \
    "org.winsvpn.app.PacketTunnel" \
    macos \
    MacOSX >/dev/null

  rm -rf "${tmp}"
  printf 'Apple engine artifact gate self-test passed.\n'
}

runtime_preflight_report() {
  section "Apple Runtime Preflight"

  if command -v xcode-select >/dev/null 2>&1; then
    local developer_dir
    developer_dir="$(xcode-select -p 2>/dev/null || true)"
    printf 'xcode-select: %s\n' "${developer_dir:-unavailable}"
    if [[ "${developer_dir}" == *"/CommandLineTools" ]]; then
      printf 'full Xcode selected: no (Command Line Tools are active)\n'
    elif [[ -n "${developer_dir}" ]]; then
      printf 'full Xcode selected: yes\n'
    fi
  else
    printf 'xcode-select: missing\n'
  fi

  if [[ -d "/Applications/Xcode.app/Contents/Developer" ]]; then
    printf 'Xcode.app: present at /Applications/Xcode.app\n'
  else
    printf 'Xcode.app: not found at /Applications/Xcode.app\n'
  fi

  optional_cmd_status "xcodebuild" xcodebuild -version
  optional_cmd_status "simctl" xcrun -f simctl
  optional_cmd_status "devicectl" xcrun -f devicectl
  printf 'App Store Connect authentication key: %s\n' "$(apple_xcode_auth_state)"
  printf 'macOS development signing: %s\n' "$(apple_macos_development_signing_state)"

  local report_pod_bin
  report_pod_bin="$(resolve_reviewed_pod_bin || true)"
  if [[ -n "${report_pod_bin}" ]]; then
    printf 'CocoaPods: %s (%s)\n' \
      "$("${report_pod_bin}" --version 2>/dev/null || printf 'installed')" \
      "${report_pod_bin}"
  else
    printf 'CocoaPods: missing\n'
  fi
  apple_signing_preflight_report

  if [[ -x "${FLUTTER_BIN}" ]]; then
    printf 'Flutter: %s\n' "$("${FLUTTER_BIN}" --version 2>/dev/null | head -n 1 || true)"
    local ios_device_id
    ios_device_id="$(physical_ios_device_id_or_empty || true)"
    if [[ -n "${ios_device_id}" ]]; then
      printf 'physical iOS device visible to Flutter: yes\n'
    else
      printf 'physical iOS device visible to Flutter: no\n'
    fi
  else
    printf 'Flutter: not executable at %s\n' "${FLUTTER_BIN}"
  fi

  if command -v xcrun >/dev/null 2>&1; then
    local simulator_id
    simulator_id="$(ios_simulator_id_or_empty || true)"
    if [[ -n "${simulator_id}" ]]; then
      printf 'usable iOS simulator: yes (%s)\n' "${simulator_id}"
    else
      printf 'usable iOS simulator: no\n'
    fi
  fi

  devicectl_physical_ios_report
  if [[ -n "${ios_device_id:-}" ]]; then
    devicectl_ios_lock_state_report "${ios_device_id}"
    devicectl_ios_display_report "${ios_device_id}"
    ios_screen_viewing_report
    ios_active_unlock_note_if_needed
  fi

  local usb_hint_source
  if usb_hint_source="$(usb_ios_device_hint_source_or_empty)"; then
    printf 'USB iOS/iPadOS hardware hint: present via %s\n' "${usb_hint_source}"
  else
    printf 'USB iOS/iPadOS hardware hint: not detected\n'
  fi
}

require_full_xcode() {
  section "Full Xcode"
  require_cmd xcode-select

  local developer_dir
  developer_dir="$(xcode-select -p)"
  printf 'xcode-select: %s\n' "${developer_dir}"

  if [[ "${developer_dir}" == *"/CommandLineTools" ]]; then
    die "Full Xcode is not selected. Install Xcode, then run: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"
  fi

  run xcodebuild -version
  run xcrun -f simctl
  run xcrun -f devicectl
  run xcrun simctl list devices available
  run xcrun xctrace list devices
}

resolve_physical_ios_device_id() {
  "${FLUTTER_BIN}" devices --machine | "${PYTHON_BIN}" -c '
import json
import sys

devices = json.load(sys.stdin)
for device in devices:
    platform = str(device.get("targetPlatform") or "").lower()
    name = str(device.get("name") or "")
    if platform == "ios" and not device.get("emulator") and ("iphone" in name.lower() or "ipad" in name.lower()):
        print(device.get("id") or "")
        raise SystemExit(0)
raise SystemExit(1)
'
}

require_flutter_and_device() {
  section "Flutter And Devices"
  [[ -x "${FLUTTER_BIN}" ]] || die "Flutter not found or not executable at ${FLUTTER_BIN}"
  require_cmd "${PYTHON_BIN}"

  run "${FLUTTER_BIN}" --version
  run "${FLUTTER_BIN}" config --enable-macos-desktop
  run "${FLUTTER_BIN}" pub get
  run "${FLUTTER_BIN}" devices -v

  if [[ "${WINS_SKIP_IOS_DEVICE}" == "1" ]]; then
    printf 'Skipping physical iPhone/iPad requirement because WINS_SKIP_IOS_DEVICE=1.\n'
    return
  fi

  if [[ "${WINS_REQUIRE_IOS_DEVICE}" != "1" && "${WINS_IOS_INSTALL}" != "1" ]]; then
    printf 'Physical iPhone/iPad install requirement is not enforced for unsigned simulator/macOS smoke. Set WINS_REQUIRE_IOS_DEVICE=1 or WINS_IOS_INSTALL=1 to require it.\n'
    return
  fi

  local ios_device_id
  if ! ios_device_id="$(resolve_physical_ios_device_id)"; then
    if usb_ios_device_hint; then
      die "An iPhone/iPad appears to be attached over USB, but Flutter cannot use it. Select full Xcode, open Xcode once, trust the device on both sides, and re-run this script."
    fi
    die "No physical iPhone/iPad is visible to Flutter. Connect and trust the device, then re-run this script."
  fi
  [[ -n "${ios_device_id}" ]] || die "Flutter returned an empty physical iOS device id."
  printf 'Physical iOS device: %s\n' "${ios_device_id}"
}

install_pods() {
  section "CocoaPods"
  require_reviewed_cocoapods
  require_file ios/Podfile
  require_file macos/Podfile

  (
    cd ios
    run "${POD_BIN}" install --deployment
  )

  (
    cd macos
    run "${POD_BIN}" install --deployment
  )
}

signed_ios_xcode_destination() {
  if [[ "${WINS_IOS_INSTALL}" == "1" ]]; then
    local ios_device_id
    ios_device_id="$(resolve_physical_ios_device_id)"
    [[ -n "${ios_device_id}" ]] || die "Could not resolve physical iOS device id for signed iOS build."
    printf 'id=%s\n' "${ios_device_id}"
  else
    printf 'generic/platform=iOS\n'
  fi
}

signed_ios_build() {
  local destination
  destination="$(signed_ios_xcode_destination)"

  local flutter_mode="--debug"
  local xcode_configuration="Debug"
  local app_lookup="latest_ios_device_debug_app_or_empty"
  local build_label="Signed iOS debug app"
  local artifact_label="signed iOS debug app"
  if [[ "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "1" || "${WINS_IOS_LAUNCH}" == "1" ]]; then
    flutter_mode="--profile"
    xcode_configuration="Profile"
    app_lookup="latest_ios_device_profile_app_or_empty"
    build_label="Signed iOS profile app"
    artifact_label="signed iOS profile app"
  fi

  run_flutter_build build ios "${flutter_mode}" --config-only
  run_xcodebuild_with_signing_diagnostics \
    -hideShellScriptEnvironment \
    -workspace ios/Runner.xcworkspace \
    -scheme Runner \
    -configuration "${xcode_configuration}" \
    -destination "${destination}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates \
    build
  local app_path
  app_path="$("${app_lookup}" || true)"
  [[ -n "${app_path}" ]] \
    || die "${artifact_label} artifact was not produced under Xcode DerivedData."
  local host_bundle_id="${IOS_BUNDLE_ID}"
  if [[ "${xcode_configuration}" == "Debug" ]]; then
    host_bundle_id="${IOS_DEBUG_BUNDLE_ID}"
  fi
  verify_apple_app_bundle \
    "${build_label}" \
    "${app_path}" \
    "${host_bundle_id}" \
    "${host_bundle_id}.PacketTunnel" \
    ios \
    iPhoneOS
  run codesign --verify --deep --strict --verbose=2 "${app_path}"
}

build_apple_apps() {
  section "Apple Debug Builds"

  if [[ "${WINS_IOS_INSTALL}" == "1" ]]; then
    require_ios_signed_runtime_prereqs
    signed_ios_build
  elif [[ "${WINS_IOS_SIGNED_BUILD}" == "1" ]]; then
    require_ios_signing_prereqs
    signed_ios_build
  else
    run_flutter_build build ios --debug --no-codesign
    find build/ios/iphoneos -maxdepth 1 -name '*.app' -print -quit | grep -q . \
      || die "iOS debug app artifact was not produced under build/ios/iphoneos."
    verify_apple_app_bundle \
      "Unsigned iOS device debug app" \
      build/ios/iphoneos/Runner.app \
      "${IOS_DEBUG_BUNDLE_ID}" \
      "${IOS_DEBUG_BUNDLE_ID}.PacketTunnel" \
      ios \
      iPhoneOS
  fi

  if [[ "${WINS_SIGNED_MACOS_BUILD}" == "1" ]]; then
    require_macos_signing_prereqs
    run_flutter_build build macos --debug --config-only
    force_macos_flutter_assemble
    run_xcodebuild_with_signing_diagnostics \
      -hideShellScriptEnvironment \
      -workspace macos/Runner.xcworkspace \
      -scheme Runner \
      -configuration Debug \
      -destination 'platform=macOS' \
      __APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS__ \
      __APPLE_XCODE_AUTH_ARGS__ \
      -allowProvisioningUpdates \
      build
    local app_path
    app_path="$(latest_macos_debug_app_or_empty || true)"
    [[ -n "${app_path}" ]] \
      || die "macOS debug app artifact was not produced under Xcode DerivedData."
    verify_apple_app_bundle \
      "Signed macOS debug app" \
      "${app_path}" \
      "${MACOS_BUNDLE_ID}" \
      "${MACOS_BUNDLE_ID}.PacketTunnel" \
      macos \
      MacOSX
    run codesign --verify --deep --strict --verbose=2 "${app_path}"
  else
    run_flutter_build build macos --debug --config-only
    force_macos_flutter_assemble
    run xcodebuild \
      -hideShellScriptEnvironment \
      -workspace macos/Runner.xcworkspace \
      -scheme Runner \
      -configuration Debug \
      -destination 'platform=macOS' \
      CODE_SIGNING_ALLOWED=NO \
      CODE_SIGNING_REQUIRED=NO \
      build
    local app_path
    app_path="$(latest_macos_debug_app_or_empty || true)"
    [[ -n "${app_path}" ]] \
      || die "macOS debug app artifact was not produced under Xcode DerivedData."
    verify_apple_app_bundle \
      "Unsigned macOS debug app" \
      "${app_path}" \
      "${MACOS_BUNDLE_ID}" \
      "${MACOS_BUNDLE_ID}.PacketTunnel" \
      macos \
      MacOSX
  fi
}

release_shell_smoke() {
  if [[ "${WINS_RELEASE_SHELL_SMOKE}" != "1" ]]; then
    printf 'Skipping Apple release shell smoke. Set WINS_RELEASE_SHELL_SMOKE=1 to build and verify iOS no-codesign and macOS signed Release bundles.\n'
    return
  fi

  section "Apple Release Shell Smoke"

  local ios_symbols macos_symbols
  ios_symbols="$(prepare_apple_release_symbols ios)"
  run_flutter_build build ios --release --no-codesign --obfuscate --split-debug-info="${ios_symbols}" --extra-gen-snapshot-options=--strip
  require_apple_release_symbols ios
  [[ -d build/ios/iphoneos/Runner.app ]] \
    || die "iOS release app artifact was not produced at build/ios/iphoneos/Runner.app."
  verify_apple_app_bundle \
    "Unsigned iOS device release app" \
    build/ios/iphoneos/Runner.app \
    "${IOS_BUNDLE_ID}" \
    "${IOS_BUNDLE_ID}.PacketTunnel" \
    ios \
    iPhoneOS

  local app_path
  app_path="build/macos/Build/Products/Release/Win's VPN.app"
  macos_symbols="$(prepare_apple_release_symbols macos)"
  run_flutter_build build macos --release --obfuscate --split-debug-info="${macos_symbols}" --extra-gen-snapshot-options=--strip
  require_apple_release_symbols macos
  [[ -d "${app_path}" ]] \
    || die "macOS release app artifact was not produced at ${app_path}."
  verify_apple_app_bundle \
    "Signed macOS release app" \
    "${app_path}" \
    "${MACOS_BUNDLE_ID}" \
    "${MACOS_BUNDLE_ID}.PacketTunnel" \
    macos \
    MacOSX
  run codesign --verify --deep --strict --verbose=2 "${app_path}"
}

signed_ios_archive_path() {
  printf '%s/wins-vpn-ios.xcarchive' "${APPLE_ARCHIVE_DIR}"
}

create_signed_ios_archive() {
  require_ios_signing_prereqs
  mkdir -p "${APPLE_ARCHIVE_DIR}"

  local archive_path symbols
  archive_path="$(signed_ios_archive_path)"
  rm -rf "${archive_path}"

  symbols="$(prepare_apple_release_symbols ios)"
  run_flutter_build build ios --release --config-only --obfuscate --split-debug-info="${symbols}" --extra-gen-snapshot-options=--strip
  verify_apple_release_dart_defines ios/Flutter/Generated.xcconfig
  # Info.plist generation stays off here: a generated Info.plist makes Xcode
  # stamp CFBundleName from PRODUCT_NAME on every target ("BasicCalc" on the
  # host, "WinsWatch" on the Watch app), which undoes the "Win's VPN" app
  # name (owner ruling 2026-10-25). The release markers still reach the host
  # Info.plist: it reads them as $(INFOPLIST_KEY_...) build settings.
  run_xcodebuild_with_signing_diagnostics \
    -hideShellScriptEnvironment \
    -workspace ios/Runner.xcworkspace \
    -scheme Runner \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -archivePath "${archive_path}" \
    DART_OBFUSCATION=true \
    SPLIT_DEBUG_INFO="${symbols}" \
    EXTRA_GEN_SNAPSHOT_OPTIONS=--strip \
    INFOPLIST_KEY_WinsReleaseContaminationContract=apple-release-no-live-smoke-v1 \
    INFOPLIST_KEY_WinsReleaseLiveSmokeCompiled=NO \
    INFOPLIST_KEY_WinsReleaseSmokePinEmbedded=NO \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates \
    archive
  require_apple_release_symbols ios
}

# The iOS app is named by PRODUCT_NAME ("BasicCalc" for the calculator
# disguise; owner ruling 2026-10-16), so archives and IPAs are searched for
# their single .app instead of assuming Runner.app. Zero or several apps refuse.
single_app_bundle_in() {
  local directory="$1"
  local label="$2"
  local candidate count=0 found=""
  for candidate in "${directory}"/*.app; do
    [[ -d "${candidate}" && ! -L "${candidate}" ]] || continue
    count=$((count + 1))
    found="${candidate}"
  done
  [[ "${count}" -eq 1 ]] \
    || die "${label} must contain exactly one .app bundle; found ${count} in ${directory}."
  printf '%s\n' "${found}"
}

verify_signed_ios_archive() {
  local archive_path app_path
  archive_path="$(signed_ios_archive_path)"
  app_path="$(single_app_bundle_in "${archive_path}/Products/Applications" "Signed iOS archive")" \
    || die "Signed iOS archive app was not produced under ${archive_path}/Products/Applications."
  verify_apple_release_contamination ios "${archive_path}"
  require_apple_release_symbols ios
  verify_apple_app_bundle \
    "Signed iOS archive app" \
    "${app_path}" \
    "${IOS_BUNDLE_ID}" \
    "${IOS_BUNDLE_ID}.PacketTunnel" \
    ios \
    iPhoneOS
}

ios_archive_smoke() {
  if [[ "${WINS_IOS_ARCHIVE_SMOKE}" != "1" ]]; then
    printf 'Skipping signed iOS archive smoke. Set WINS_IOS_ARCHIVE_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 to create and verify a local signed iOS archive.\n'
    return
  fi

  section "Signed iOS Archive Smoke"
  create_signed_ios_archive
  verify_signed_ios_archive
}

ios_debugging_export_smoke() {
  if [[ "${WINS_IOS_DEBUGGING_EXPORT_SMOKE}" != "1" ]]; then
    printf 'Skipping iOS debugging export smoke. Set WINS_IOS_DEBUGGING_EXPORT_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 to export and verify a local development-signed IPA.\n'
    return
  fi

  section "iOS Debugging Export Smoke"
  command -v unzip >/dev/null || die "unzip is required to verify exported iOS IPA payloads."

  local archive_path export_path ipa_path
  archive_path="$(signed_ios_archive_path)"
  if [[ "${WINS_IOS_ARCHIVE_SMOKE}" != "1" ]]; then
    create_signed_ios_archive
    verify_signed_ios_archive
  fi
  [[ -d "${archive_path}" ]] || die "Signed iOS archive is required before export: ${archive_path}."

  export_path="${APPLE_EXPORT_DIR}/ios-debugging-local"
  rm -rf "${export_path}"
  mkdir -p "${APPLE_EXPORT_DIR}"
  run_xcodebuild_with_export_signing_diagnostics \
    -hideShellScriptEnvironment \
    -exportArchive \
    -archivePath "${archive_path}" \
    -exportOptionsPlist apple/ExportOptions/ios-debugging-local.plist \
    -exportPath "${export_path}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates

  ipa_path="$(find "${export_path}" -maxdepth 1 -type f -name '*.ipa' -print -quit)"
  [[ -n "${ipa_path}" && -f "${ipa_path}" ]] \
    || die "iOS debugging export did not produce an IPA in ${export_path}."

  verify_ios_ipa_artifact \
    "${ipa_path}" \
    "Exported iOS debugging app" \
    "iOS debugging"
  printf 'Exported iOS debugging IPA: %s\n' "${ipa_path}"
}

ios_release_testing_export_smoke() {
  if [[ "${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE}" != "1" ]]; then
    printf 'Skipping iOS release-testing export smoke. Set WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 to export and verify a local distribution-signed IPA without uploading.\n'
    return
  fi

  section "iOS Release-Testing Export Smoke"
  command -v unzip >/dev/null || die "unzip is required to verify exported iOS IPA payloads."

  local archive_path export_path ipa_path export_options_plist
  archive_path="$(signed_ios_archive_path)"
  export_options_plist="$(
    manual_distribution_export_options_plist \
      ios-release-testing \
      apple/ExportOptions/ios-release-testing.plist \
      "Apple Distribution" \
      "iOS app" "${IOS_BUNDLE_ID}" "${APPLE_APP_GROUP_ID}" \
      "iOS PacketTunnel" "${IOS_BUNDLE_ID}.PacketTunnel" "${APPLE_APP_GROUP_ID}" \
      "watchOS app" "${IOS_BUNDLE_ID}.watchkitapp" ""
  )"
  if [[ "${WINS_IOS_ARCHIVE_SMOKE}" != "1" ]]; then
    create_signed_ios_archive
    verify_signed_ios_archive
  fi
  [[ -d "${archive_path}" ]] || die "Signed iOS archive is required before export: ${archive_path}."

  export_path="${APPLE_EXPORT_DIR}/ios-release-testing"
  rm -rf "${export_path}"
  mkdir -p "${APPLE_EXPORT_DIR}"
  run_xcodebuild_with_export_signing_diagnostics \
    -hideShellScriptEnvironment \
    -exportArchive \
    -archivePath "${archive_path}" \
    -exportOptionsPlist "${export_options_plist}" \
    -exportPath "${export_path}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates

  ipa_path="$(find "${export_path}" -maxdepth 1 -type f -name '*.ipa' -print -quit)"
  [[ -n "${ipa_path}" && -f "${ipa_path}" ]] \
    || die "iOS release-testing export did not produce an IPA in ${export_path}."

  verify_ios_ipa_artifact \
    "${ipa_path}" \
    "Exported iOS release-testing app" \
    "iOS release-testing"
  printf 'Exported iOS release-testing IPA: %s\n' "${ipa_path}"
}

ios_app_store_local_export_smoke() {
  if [[ "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE}" != "1" ]]; then
    printf 'Skipping iOS App Store local export smoke. Set WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 to export and verify a local App Store-signed IPA without uploading.\n'
    return
  fi

  section "iOS App Store Local Export Smoke"
  command -v unzip >/dev/null || die "unzip is required to verify exported iOS IPA payloads."

  local archive_path export_path ipa_path export_options_plist
  archive_path="$(signed_ios_archive_path)"
  if [[ "${WINS_IOS_ARCHIVE_SMOKE}" != "1" ]]; then
    create_signed_ios_archive
    verify_signed_ios_archive
  fi
  [[ -d "${archive_path}" ]] || die "Signed iOS archive is required before export: ${archive_path}."

  export_path="${APPLE_EXPORT_DIR}/ios-app-store-local"
  rm -rf "${export_path}"
  mkdir -p "${APPLE_EXPORT_DIR}"
  export_options_plist="$(
    manual_distribution_export_options_plist \
      ios-app-store \
      apple/ExportOptions/ios-app-store-local.plist \
      "Apple Distribution" \
      "iOS app" "${IOS_BUNDLE_ID}" "${APPLE_APP_GROUP_ID}" \
      "iOS PacketTunnel" "${IOS_BUNDLE_ID}.PacketTunnel" "${APPLE_APP_GROUP_ID}" \
      "watchOS app" "${IOS_BUNDLE_ID}.watchkitapp" ""
  )"
  run_xcodebuild_with_export_signing_diagnostics \
    -hideShellScriptEnvironment \
    -exportArchive \
    -archivePath "${archive_path}" \
    -exportOptionsPlist "${export_options_plist}" \
    -exportPath "${export_path}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates

  ipa_path="$(find "${export_path}" -maxdepth 1 -type f -name '*.ipa' -print -quit)"
  [[ -n "${ipa_path}" && -f "${ipa_path}" ]] \
    || die "iOS App Store local export did not produce an IPA in ${export_path}."

  verify_ios_ipa_artifact \
    "${ipa_path}" \
    "Exported iOS App Store local app" \
    "iOS App Store local"
  record_apple_release_obfuscation ios "${ipa_path}"
  record_apple_private_symbol_custody ios "${ipa_path}" "${archive_path}"
  printf 'Exported iOS App Store local IPA: %s\n' "${ipa_path}"
}

ios_testflight_internal_upload_smoke() {
  if [[ "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE}" != "1" ]]; then
    printf 'Skipping iOS TestFlight internal upload smoke. Set WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 and App Store Connect API-key env vars to upload an internal-TestFlight-only iOS archive.\n'
    return
  fi

  section "iOS TestFlight Internal Upload Smoke"
  refuse_direct_app_store_connect_upload
  require_app_store_connect_upload_auth

  local archive_path upload_path
  archive_path="$(signed_ios_archive_path)"
  if [[ "${WINS_IOS_ARCHIVE_SMOKE}" != "1" ]]; then
    create_signed_ios_archive
    verify_signed_ios_archive
  fi
  [[ -d "${archive_path}" ]] || die "Signed iOS archive is required before upload: ${archive_path}."
  verify_apple_release_contamination ios "${archive_path}"

  upload_path="${APPLE_UPLOAD_DIR}/ios-testflight-internal"
  rm -rf "${upload_path}"
  mkdir -p "${APPLE_UPLOAD_DIR}"
  run_xcodebuild_with_export_signing_diagnostics \
    -hideShellScriptEnvironment \
    -exportArchive \
    -archivePath "${archive_path}" \
    -exportOptionsPlist apple/ExportOptions/ios-testflight-internal.plist \
    -exportPath "${upload_path}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates

  printf 'Uploaded iOS archive to App Store Connect for internal TestFlight processing: %s\n' "${archive_path}"
}

ios_app_store_connect_upload_smoke() {
  if [[ "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" != "1" ]]; then
    printf 'Skipping iOS App Store Connect upload smoke. Set WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 and App Store Connect API-key env vars to upload the iOS archive.\n'
    return
  fi

  section "iOS App Store Connect Upload Smoke"
  refuse_direct_app_store_connect_upload
  require_app_store_connect_upload_auth

  local archive_path upload_path
  archive_path="$(signed_ios_archive_path)"
  if [[ "${WINS_IOS_ARCHIVE_SMOKE}" != "1" ]]; then
    create_signed_ios_archive
    verify_signed_ios_archive
  fi
  [[ -d "${archive_path}" ]] || die "Signed iOS archive is required before upload: ${archive_path}."
  verify_apple_release_contamination ios "${archive_path}"

  upload_path="${APPLE_UPLOAD_DIR}/ios-app-store-connect"
  rm -rf "${upload_path}"
  mkdir -p "${APPLE_UPLOAD_DIR}"
  run_xcodebuild_with_export_signing_diagnostics \
    -hideShellScriptEnvironment \
    -exportArchive \
    -archivePath "${archive_path}" \
    -exportOptionsPlist apple/ExportOptions/ios-app-store-connect.plist \
    -exportPath "${upload_path}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates

  printf 'Uploaded iOS archive to App Store Connect for TestFlight/App Store processing: %s\n' "${archive_path}"
}

signed_macos_archive_path() {
  printf '%s/wins-vpn-macos.xcarchive' "${APPLE_ARCHIVE_DIR}"
}

# Fail closed BEFORE archiving if the requested signing identity is not in the
# keychain. Added 2026-08-09.
#
# The failure this prevents is specific and expensive: with a Developer ID or
# Apple Distribution identity requested but absent, xcodebuild does not
# necessarily stop -- automatic signing falls back to whatever it CAN resolve,
# and the archive is produced signed with the wrong certificate. The operator
# then discovers it at notarisation or at upload, after the whole archive has
# been built, and the natural conclusion is "the new certificate does not
# work". Refusing here costs a second and names the real cause.
#
# The default identity is deliberately exempt from the strict check only in the
# sense that it is what the repository has always used; it is still verified to
# exist, because an expired or revoked development certificate produces exactly
# the same confusing symptom.
require_macos_archive_signing_identity_present() {
  local identity="${WINS_APPLE_CODE_SIGN_IDENTITY}"
  local available

  command -v security >/dev/null 2>&1 \
    || die "security(1) is required to verify the macOS archive signing identity."

  available="$(security find-identity -v -p codesigning 2>/dev/null || true)"

  if [[ -z "${available//[[:space:]]/}" ]] || [[ "${available}" == *"0 valid identities found"* ]]; then
    die "No code signing identities are present in the keychain, so the macOS archive cannot be signed.
Requested identity: '${identity}' (WINS_APPLE_CODE_SIGN_IDENTITY).
Install the certificate and its private key, then retry. Verify with:
    security find-identity -v -p codesigning"
  fi

  # `security find-identity` prints one line per identity as
  #   N) <40-hex SHA1> "Apple Development: Name (XXXXXXXXXX)"
  # so a prefix match of the requested identity against the quoted common name
  # is the same match rule codesign itself applies to an identity string.
  if ! printf '%s\n' "${available}" | grep -Fq "\"${identity}"; then
    die "Requested macOS archive signing identity '${identity}' is not in the keychain.
This is WINS_APPLE_CODE_SIGN_IDENTITY; it defaults to 'Apple Development'.
Identities that ARE available:
$(printf '%s\n' "${available}" | sed 's/^/    /')
Refusing rather than letting automatic signing silently substitute a different
certificate and produce an archive that fails at notarisation or upload."
  fi
}

create_signed_macos_archive() {
  require_macos_signing_prereqs
  mkdir -p "${APPLE_ARCHIVE_DIR}"

  local archive_path symbols archive_xcconfig archive_signing_dir archive_status
  archive_path="$(signed_macos_archive_path)"
  rm -rf "${archive_path}"

  symbols="$(prepare_apple_release_symbols macos)"
  run_flutter_build build macos --release --config-only --obfuscate --split-debug-info="${symbols}" --extra-gen-snapshot-options=--strip
  verify_apple_release_dart_defines macos/Flutter/ephemeral/Flutter-Generated.xcconfig
  force_macos_flutter_assemble

  # Info.plist generation stays off, as on iOS: when it generates the plist,
  # Xcode derives CFBundleShortVersionString and CFBundleVersion from
  # MARKETING_VERSION and CURRENT_PROJECT_VERSION, which the Runner target does
  # not set, and drops both keys (r34). The host plist reads FLUTTER_BUILD_NAME,
  # FLUTTER_BUILD_NUMBER and the $(INFOPLIST_KEY_...) release markers itself.
  if macos_app_store_archive_signing_requested; then
    archive_xcconfig="$(manual_macos_app_store_archive_xcconfig)"
    archive_signing_dir="$(dirname "${archive_xcconfig}")"
    if run_xcodebuild_with_signing_diagnostics \
      -hideShellScriptEnvironment \
      -workspace macos/Runner.xcworkspace \
      -scheme Runner \
      -configuration Release \
      -destination 'generic/platform=macOS' \
      -archivePath "${archive_path}" \
      -xcconfig "${archive_xcconfig}" \
      DART_OBFUSCATION=true \
      SPLIT_DEBUG_INFO="${symbols}" \
      EXTRA_GEN_SNAPSHOT_OPTIONS=--strip \
      INFOPLIST_KEY_WinsReleaseContaminationContract=apple-release-no-live-smoke-v1 \
      INFOPLIST_KEY_WinsReleaseLiveSmokeCompiled=NO \
      INFOPLIST_KEY_WinsReleaseSmokePinEmbedded=NO \
      archive; then
      archive_status=0
    else
      archive_status="$?"
    fi
    rm -rf "${archive_signing_dir}"
    [[ "${archive_status}" == "0" ]] || return "${archive_status}"
  else
    require_macos_archive_signing_identity_present
    run_xcodebuild_with_signing_diagnostics \
      -hideShellScriptEnvironment \
      -workspace macos/Runner.xcworkspace \
      -scheme Runner \
      -configuration Release \
      -destination 'generic/platform=macOS' \
      -archivePath "${archive_path}" \
      DART_OBFUSCATION=true \
      SPLIT_DEBUG_INFO="${symbols}" \
      EXTRA_GEN_SNAPSHOT_OPTIONS=--strip \
      INFOPLIST_KEY_WinsReleaseContaminationContract=apple-release-no-live-smoke-v1 \
      INFOPLIST_KEY_WinsReleaseLiveSmokeCompiled=NO \
      INFOPLIST_KEY_WinsReleaseSmokePinEmbedded=NO \
      __APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS__ \
      __APPLE_XCODE_AUTH_ARGS__ \
      -allowProvisioningUpdates \
      CODE_SIGN_IDENTITY="${WINS_APPLE_CODE_SIGN_IDENTITY}" \
      archive
  fi
  require_apple_release_symbols macos
}

verify_signed_macos_archive() {
  local archive_path app_path
  archive_path="$(signed_macos_archive_path)"
  app_path="${archive_path}/Products/Applications/Win's VPN.app"
  [[ -d "${app_path}" ]] || die "Signed macOS archive app was not produced at ${app_path}."
  verify_apple_release_contamination macos "${archive_path}"
  require_apple_release_symbols macos
  verify_apple_app_bundle \
    "Signed macOS archive app" \
    "${app_path}" \
    "${MACOS_BUNDLE_ID}" \
    "${MACOS_BUNDLE_ID}.PacketTunnel" \
    macos \
    MacOSX
}

macos_archive_smoke() {
  if [[ "${WINS_MACOS_ARCHIVE_SMOKE}" != "1" ]]; then
    printf 'Skipping signed macOS archive smoke. Set WINS_MACOS_ARCHIVE_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 to create and verify a local signed macOS archive.\n'
    return
  fi

  section "Signed macOS Archive Smoke"
  create_signed_macos_archive
  verify_signed_macos_archive
}

apple_privacy_archive_report() {
  section "Apple Archive Privacy Manifest Report"
  mkdir -p "${APPLE_PRIVACY_REPORT_DIR}"

  "${PYTHON_BIN}" - \
    "${APPLE_PRIVACY_REPORT_DIR}" \
    "$(signed_ios_archive_path)" \
    "$(signed_macos_archive_path)" <<'PY'
import json
import hashlib
import plistlib
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_HOST_COLLECTED_DATA = {
    "NSPrivacyCollectedDataTypeCoarseLocation",
    "NSPrivacyCollectedDataTypeDeviceID",
    "NSPrivacyCollectedDataTypeUserID",
    "NSPrivacyCollectedDataTypeProductInteraction",
}
APP_FUNCTIONALITY_PURPOSE = "NSPrivacyCollectedDataTypePurposeAppFunctionality"

report_dir = Path(sys.argv[1])
archives = [Path(value) for value in sys.argv[2:]]


def xcrun_privacyreport_available():
    try:
        subprocess.run(
            ["xcrun", "--find", "privacyreport"],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except Exception:
        return False


def relative_to_archive(path, archive):
    try:
        return str(path.relative_to(archive))
    except ValueError:
        return str(path)


def subject_kind(path):
    text = str(path).replace("\\", "/")
    if "/Watch/" in text or "WinsWatch.app/" in text:
        return "watch"
    if "PacketTunnel.appex/" in text:
        return "packet_tunnel"
    for framework in (
        "WinsAmneziaWGPacketEngine",
        "WinsXrayVlessWsTransport",
        "WinsWinnPacketEngine",
    ):
        if f"{framework}.framework/" in text:
            return framework
    if "Flutter.framework/" in text or "FlutterMacOS.framework/" in text:
        return "flutter"
    if "/Frameworks/" in text or "/PlugIns/" in text:
        raise SystemExit(f"unexpected archive privacy manifest path: {text}")
    # The host app is the only .app on the path (its name follows
    # PRODUCT_NAME, e.g. BasicCalc.app on iOS); nested code returned above.
    app_parts = [part for part in text.split("/") if part.endswith(".app")]
    if len(app_parts) == 1 and (
        text.endswith(f"{app_parts[0]}/PrivacyInfo.xcprivacy")
        or text.endswith(f"{app_parts[0]}/Contents/Resources/PrivacyInfo.xcprivacy")
    ):
        return "runner"
    raise SystemExit(f"unexpected archive privacy manifest path: {text}")


def iso_mtime(path):
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def summarize_manifest(path, archive):
    with path.open("rb") as handle:
        manifest = plistlib.load(handle)

    collected = []
    for item in manifest.get("NSPrivacyCollectedDataTypes") or []:
        collected.append(
            {
                "data_type": item.get("NSPrivacyCollectedDataType"),
                "linked": item.get("NSPrivacyCollectedDataTypeLinked"),
                "tracking": item.get("NSPrivacyCollectedDataTypeTracking"),
                "purposes": sorted(item.get("NSPrivacyCollectedDataTypePurposes") or []),
            }
        )

    accessed = []
    for item in manifest.get("NSPrivacyAccessedAPITypes") or []:
        accessed.append(
            {
                "api_type": item.get("NSPrivacyAccessedAPIType"),
                "reasons": sorted(item.get("NSPrivacyAccessedAPITypeReasons") or []),
            }
        )

    return {
        "archive": archive.name,
        "path": relative_to_archive(path, archive),
        "file_size_bytes": path.stat().st_size,
        "modified_at": iso_mtime(path),
        "sha256": sha256_file(path),
        "subject_kind": subject_kind(path),
        "tracking": manifest.get("NSPrivacyTracking"),
        "tracking_domains": manifest.get("NSPrivacyTrackingDomains") or [],
        "collected_data_types": sorted(collected, key=lambda item: item.get("data_type") or ""),
        "accessed_api_types": sorted(accessed, key=lambda item: item.get("api_type") or ""),
    }


def data_type_map(manifest, label):
    result = {}
    for item in manifest.get("collected_data_types") or []:
        data_type = item.get("data_type")
        if not isinstance(data_type, str) or not data_type:
            raise SystemExit(f"{label}: collected data type must be a string")
        if data_type in result:
            raise SystemExit(f"{label}: duplicate collected data type {data_type}")
        result[data_type] = item
    return result


def api_type_map(manifest, label):
    result = {}
    for item in manifest.get("accessed_api_types") or []:
        api_type = item.get("api_type")
        reasons = item.get("reasons")
        if not isinstance(api_type, str) or not api_type:
            raise SystemExit(f"{label}: accessed API type must be a string")
        if not isinstance(reasons, list) or not reasons:
            raise SystemExit(f"{label}: accessed API reasons must be a non-empty list")
        if any(not isinstance(reason, str) or not reason for reason in reasons):
            raise SystemExit(f"{label}: accessed API reasons must be strings")
        if len(reasons) != len(set(reasons)):
            raise SystemExit(f"{label}: duplicate accessed API reason for {api_type}")
        if api_type in result:
            raise SystemExit(f"{label}: duplicate accessed API type {api_type}")
        result[api_type] = set(reasons)
    return result


def require_archive_manifest_contract(archive_report):
    manifests = archive_report["privacy_manifests"]
    archive_name = archive_report["archive"]
    if "macos" in archive_name:
        required_subjects = [
            "runner",
            "packet_tunnel",
            "flutter",
            "WinsAmneziaWGPacketEngine",
            "WinsXrayVlessWsTransport",
            "WinsWinnPacketEngine",
        ]
    elif "ios" in archive_name:
        required_subjects = [
            "runner",
            "packet_tunnel",
            "watch",
            "flutter",
            "WinsAmneziaWGPacketEngine",
            "WinsXrayVlessWsTransport",
            "WinsWinnPacketEngine",
        ]
    else:
        raise SystemExit(f"{archive_name}: unknown Apple archive privacy contract")
    by_subject = {}
    for manifest in manifests:
        subject = manifest["subject_kind"]
        if subject in by_subject:
            raise SystemExit(f"{archive_name}: duplicate archive privacy manifest for {subject}")
        by_subject[subject] = manifest
        if manifest["tracking"] is not False:
            raise SystemExit(
                f"{archive_report['archive']}: {manifest['path']} must have tracking disabled"
            )
        if manifest["tracking_domains"]:
            raise SystemExit(
                f"{archive_report['archive']}: {manifest['path']} must not declare tracking domains"
            )

    missing = [subject for subject in required_subjects if subject not in by_subject]
    unexpected = sorted(set(by_subject) - set(required_subjects))
    if missing or unexpected or len(manifests) != len(required_subjects):
        raise SystemExit(
            f"{archive_name}: privacy manifest inventory mismatch; "
            f"missing={missing!r} unexpected={unexpected!r} "
            f"count={len(manifests)} expected={len(required_subjects)}"
        )

    host = by_subject["runner"]
    host_label = f"{archive_report['archive']}: archive host privacy manifest"
    host_data = data_type_map(host, host_label)
    expected_host_data = set(EXPECTED_HOST_COLLECTED_DATA)
    if set(host_data) != expected_host_data:
        raise SystemExit(
            f"{archive_report['archive']}: archive host privacy manifest collected data "
            f"{sorted(host_data)!r}, expected {sorted(expected_host_data)!r}"
        )
    for data_type in sorted(expected_host_data):
        item = host_data[data_type]
        if item.get("linked") is not True:
            raise SystemExit(
                f"{archive_report['archive']}: archive host privacy manifest {data_type} "
                "must be linked"
            )
        if item.get("tracking") is not False:
            raise SystemExit(
                f"{archive_report['archive']}: archive host privacy manifest {data_type} "
                "must not be tracking"
            )
        if set(item.get("purposes") or []) != {APP_FUNCTIONALITY_PURPOSE}:
            raise SystemExit(
                f"{archive_report['archive']}: archive host privacy manifest {data_type} "
                "must include app functionality purpose"
            )

    host_apis = api_type_map(host, host_label)
    expected_host_apis = {
        "NSPrivacyAccessedAPICategoryFileTimestamp": {"C617.1"},
        "NSPrivacyAccessedAPICategoryUserDefaults": {"CA92.1"},
        "NSPrivacyAccessedAPICategorySystemBootTime": {"35F9.1"},
    }
    if host_apis != expected_host_apis:
        raise SystemExit(f"{host_label}: accessed API mapping is not exact")

    packet = by_subject["packet_tunnel"]
    if packet.get("collected_data_types"):
        raise SystemExit(
            f"{archive_report['archive']}: archive PacketTunnel privacy manifest must not collect data"
        )
    packet_label = f"{archive_name}: archive PacketTunnel privacy manifest"
    packet_apis = api_type_map(packet, packet_label)
    expected_packet_apis = {
        "NSPrivacyAccessedAPICategoryFileTimestamp": {"C617.1"},
        "NSPrivacyAccessedAPICategorySystemBootTime": {"35F9.1"},
    }
    if packet_apis != expected_packet_apis:
        raise SystemExit(f"{packet_label}: accessed API mapping is not exact")

    expected_framework_apis = {
        "WinsAmneziaWGPacketEngine": {
            "NSPrivacyAccessedAPICategoryFileTimestamp": {"C617.1"},
        },
        "WinsXrayVlessWsTransport": {
            "NSPrivacyAccessedAPICategoryFileTimestamp": {"C617.1"},
        },
        "WinsWinnPacketEngine": {
            "NSPrivacyAccessedAPICategoryFileTimestamp": {"C617.1"},
            "NSPrivacyAccessedAPICategorySystemBootTime": {"35F9.1"},
        },
    }
    for subject in required_subjects:
        if subject == "runner":
            continue
        manifest = by_subject[subject]
        if manifest.get("collected_data_types"):
            raise SystemExit(
                f"{archive_name}: {subject} privacy manifest must not collect data"
            )
        if subject in expected_framework_apis:
            actual = api_type_map(manifest, f"{archive_name}: {subject}")
            if actual != expected_framework_apis[subject]:
                raise SystemExit(f"{archive_name}: {subject} accessed API mapping is not exact")
        elif subject == "watch" and api_type_map(manifest, f"{archive_name}: watch"):
            raise SystemExit(f"{archive_name}: watch accessed API mapping must be empty")
        elif subject == "flutter":
            api_type_map(manifest, f"{archive_name}: flutter")


archive_reports = []
missing_archives = []
for archive in archives:
    if not archive.is_dir():
        missing_archives.append(str(archive))
        continue
    manifests = sorted(archive.glob("Products/Applications/**/PrivacyInfo.xcprivacy"))
    applications = sorted(archive.glob("Products/Applications/*.app"))
    archive_reports.append(
        {
            "archive": archive.name,
            "path": str(archive),
            "modified_at": iso_mtime(archive),
            "application_count": len(applications),
            "privacy_manifest_count": len(manifests),
            "privacy_manifests": [
                summarize_manifest(path, archive)
                for path in manifests
            ],
        }
    )

if not archive_reports:
    raise SystemExit(
        "No Apple archives were available for privacy manifest reporting. "
        f"Missing archives: {', '.join(missing_archives) or 'none'}"
    )

for archive_report in archive_reports:
    require_archive_manifest_contract(archive_report)

report = {
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "report_type": "local_archive_privacy_manifest_inventory",
    "apple_xcrun_privacyreport_available": xcrun_privacyreport_available(),
    "note": (
        "This is a local manifest inventory for archived products. It does not "
        "replace the final App Store Connect/Xcode privacy report."
    ),
    "archives": archive_reports,
}

json_path = report_dir / "archive-privacy-manifests.json"
markdown_path = report_dir / "archive-privacy-manifests.md"
json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

lines = [
    "# Apple Archive Privacy Manifest Inventory",
    "",
    f"Generated at: {report['generated_at']}",
    "",
    f"Xcode privacyreport CLI available: {str(report['apple_xcrun_privacyreport_available']).lower()}",
    "",
    report["note"],
    "",
]
for archive_report in archive_reports:
    lines.extend(
        [
            f"## {archive_report['archive']}",
            "",
            f"Archive modified at: {archive_report['modified_at']}",
            "",
            f"Applications found: {archive_report['application_count']}",
            "",
            f"Privacy manifests found: {archive_report['privacy_manifest_count']}",
            "",
        ]
    )
    for manifest in archive_report["privacy_manifests"]:
        collected = ", ".join(
            item["data_type"] or "unknown"
            for item in manifest["collected_data_types"]
        ) or "none"
        apis = ", ".join(
            item["api_type"] or "unknown"
            for item in manifest["accessed_api_types"]
        ) or "none"
        lines.extend(
            [
                f"- `{manifest['path']}`",
                f"  - kind: {manifest['subject_kind']}",
                f"  - tracking: {manifest['tracking']}",
                f"  - collected data: {collected}",
                f"  - accessed APIs: {apis}",
                f"  - size: {manifest['file_size_bytes']} bytes",
                f"  - sha256: `{manifest['sha256']}`",
            ]
        )
    lines.append("")

markdown_path.write_text("\n".join(lines).rstrip() + "\n")

print(f"Apple archive privacy manifest report written: {json_path}")
print(f"Apple archive privacy manifest report written: {markdown_path}")
if missing_archives:
    print(f"Apple archive privacy manifest report skipped missing archives: {', '.join(missing_archives)}")
PY
}

macos_debugging_export_smoke() {
  if [[ "${WINS_MACOS_DEBUGGING_EXPORT_SMOKE}" != "1" ]]; then
    printf 'Skipping macOS debugging export smoke. Set WINS_MACOS_DEBUGGING_EXPORT_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 to export and verify a local development-signed macOS app.\n'
    return
  fi

  section "macOS Debugging Export Smoke"
  local archive_path export_path app_path export_options_plist
  archive_path="$(signed_macos_archive_path)"
  if [[ "${WINS_MACOS_ARCHIVE_SMOKE}" != "1" ]]; then
    create_signed_macos_archive
    verify_signed_macos_archive
  fi
  [[ -d "${archive_path}" ]] || die "Signed macOS archive is required before export: ${archive_path}."

  export_path="${APPLE_EXPORT_DIR}/macos-debugging-local"
  rm -rf "${export_path}"
  mkdir -p "${APPLE_EXPORT_DIR}"
  export_options_plist="$(manual_distribution_export_options_plist \
    macos-debugging \
    apple/ExportOptions/macos-debugging-local.plist \
    "Apple Development" \
    "macOS app" "${MACOS_BUNDLE_ID}" "${APPLE_MACOS_APP_GROUP_ID}" \
    "macOS PacketTunnel" "${MACOS_BUNDLE_ID}.PacketTunnel" "${APPLE_MACOS_APP_GROUP_ID}")" \
    || die "Unable to generate manual macOS debugging export options."
  run_xcodebuild_with_export_signing_diagnostics \
    -hideShellScriptEnvironment \
    -exportArchive \
    -archivePath "${archive_path}" \
    -exportOptionsPlist "${export_options_plist}" \
    -exportPath "${export_path}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates

  app_path="$(find "${export_path}" -maxdepth 1 -type d -name '*.app' -print -quit)"
  [[ -n "${app_path}" && -d "${app_path}" ]] \
    || die "macOS debugging export did not produce an app bundle in ${export_path}."
  verify_apple_app_bundle \
    "Exported macOS debugging app" \
    "${app_path}" \
    "${MACOS_BUNDLE_ID}" \
    "${MACOS_BUNDLE_ID}.PacketTunnel" \
    macos \
    MacOSX
  run codesign --verify --deep --strict --verbose=2 "${app_path}"
  verify_apple_release_contamination macos "${app_path}"
  printf 'Exported macOS debugging app: %s\n' "${app_path}"
}

macos_app_store_local_export_smoke() {
  if [[ "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" != "1" ]]; then
    printf 'Skipping macOS App Store local export smoke. Set WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 to export and verify a local App Store-signed macOS artifact without uploading.\n'
    return
  fi

  section "macOS App Store Local Export Smoke"
  local archive_path export_path app_path pkg_path export_options_plist
  archive_path="$(signed_macos_archive_path)"
  if [[ "${WINS_MACOS_ARCHIVE_SMOKE}" != "1" ]]; then
    create_signed_macos_archive
    verify_signed_macos_archive
  fi
  [[ -d "${archive_path}" ]] || die "Signed macOS archive is required before export: ${archive_path}."

  export_path="${APPLE_EXPORT_DIR}/macos-app-store-local"
  rm -rf "${export_path}"
  mkdir -p "${APPLE_EXPORT_DIR}"
  export_options_plist="$(
    manual_distribution_export_options_plist \
      macos-app-store \
      apple/ExportOptions/macos-app-store-local.plist \
      "Apple Distribution" \
      "macOS app" "${MACOS_BUNDLE_ID}" "${APPLE_MACOS_APP_GROUP_ID}" \
      "macOS PacketTunnel" "${MACOS_BUNDLE_ID}.PacketTunnel" "${APPLE_MACOS_APP_GROUP_ID}"
  )"
  run_xcodebuild_with_export_signing_diagnostics \
    -hideShellScriptEnvironment \
    -exportArchive \
    -archivePath "${archive_path}" \
    -exportOptionsPlist "${export_options_plist}" \
    -exportPath "${export_path}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates

  app_path="$(find "${export_path}" -maxdepth 2 -type d -name '*.app' -print -quit)"
  if [[ -n "${app_path}" && -d "${app_path}" ]]; then
    verify_apple_app_bundle \
      "Exported macOS App Store local app" \
      "${app_path}" \
      "${MACOS_BUNDLE_ID}" \
      "${MACOS_BUNDLE_ID}.PacketTunnel" \
      macos \
      MacOSX
    run codesign --verify --deep --strict --verbose=2 "${app_path}"
    local app_executable
    app_executable="$(find "${app_path}/Contents/MacOS" -maxdepth 1 -type f -perm -111 -print -quit)"
    [[ -n "${app_executable}" ]] \
      || die "Could not locate the exported macOS executable for obfuscation evidence."
    record_apple_release_obfuscation macos "${app_executable}"
    printf 'Exported macOS App Store local app: %s\n' "${app_path}"
    return
  fi

  pkg_path="$(find "${export_path}" -maxdepth 2 -type f -name '*.pkg' -print -quit)"
  [[ -n "${pkg_path}" && -f "${pkg_path}" ]] \
    || die "macOS App Store local export did not produce an app bundle or installer package in ${export_path}."
  verify_macos_pkg_artifact \
    "${pkg_path}" \
    "Exported macOS App Store local app" \
    "macOS App Store local"
  record_apple_release_obfuscation macos "${pkg_path}"
  record_apple_private_symbol_custody macos "${pkg_path}" "${archive_path}"
  printf 'Exported macOS App Store local package: %s\n' "${pkg_path}"
}

macos_app_store_connect_upload_smoke() {
  if [[ "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}" != "1" ]]; then
    printf 'Skipping macOS App Store Connect upload smoke. Set WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 and App Store Connect API-key env vars to upload the macOS archive.\n'
    return
  fi

  section "macOS App Store Connect Upload Smoke"
  refuse_direct_app_store_connect_upload
  require_app_store_connect_upload_auth

  local archive_path upload_path
  archive_path="$(signed_macos_archive_path)"
  if [[ "${WINS_MACOS_ARCHIVE_SMOKE}" != "1" ]]; then
    create_signed_macos_archive
    verify_signed_macos_archive
  fi
  [[ -d "${archive_path}" ]] || die "Signed macOS archive is required before upload: ${archive_path}."
  verify_apple_release_contamination macos "${archive_path}"

  upload_path="${APPLE_UPLOAD_DIR}/macos-app-store-connect"
  rm -rf "${upload_path}"
  mkdir -p "${APPLE_UPLOAD_DIR}"
  run_xcodebuild_with_export_signing_diagnostics \
    -hideShellScriptEnvironment \
    -exportArchive \
    -archivePath "${archive_path}" \
    -exportOptionsPlist apple/ExportOptions/macos-app-store-connect.plist \
    -exportPath "${upload_path}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates

  printf 'Uploaded macOS archive to App Store Connect for TestFlight/App Store processing: %s\n' "${archive_path}"
}

macos_app_store_pkg_install_smoke() {
  if [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE}" != "1" ]]; then
    printf 'Skipping macOS App Store package install smoke. Set WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 to install the exported package onto a temporary volume and verify the installed app.\n'
    return
  fi

  section "macOS App Store Package Install Smoke"
  require_cmd hdiutil
  require_cmd installer

  local export_path pkg_path tmp dmg_path mount_point installed_app authorization_mode
  export_path="${APPLE_EXPORT_DIR}/macos-app-store-local"
  pkg_path="$(find "${export_path}" -maxdepth 2 -type f -name '*.pkg' -print -quit)"
  [[ -n "${pkg_path}" && -f "${pkg_path}" ]] \
    || die "macOS App Store package install smoke needs an existing package in ${export_path}."

  verify_macos_pkg_artifact \
    "${pkg_path}" \
    "Exported macOS App Store local app" \
    "macOS App Store local"

  authorization_mode="$(macos_pkg_install_authorization_mode)"

  if [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_SYSTEM_TARGET}" == "1" ]]; then
    installed_app="/Applications/Win's VPN.app"
    require_clean_macos_system_install_target
    # PackageKit can otherwise relocate an upgrade into a Launch Services
    # registered Xcode archive under the project instead of /Applications.
    unregister_project_macos_build_copies_for_package_install
    quarantine_project_macos_build_copies_for_package_install
    case "${authorization_mode}" in
      root)
        run installer -pkg "${pkg_path}" -target / -verboseR
        ;;
      sudo)
        run sudo -n installer -pkg "${pkg_path}" -target / -verboseR
        ;;
      gui)
        run_macos_installer_with_gui_authorization "${pkg_path}" / \
          || die "Administrator-authorized macOS package installation failed."
        ;;
      *)
        die "Unexpected macOS package install authorization mode: ${authorization_mode}"
        ;;
    esac
    restore_project_macos_build_copies_after_package_install
    [[ -d "${installed_app}" ]] \
      || die "macOS App Store package install smoke did not install Win's VPN.app into /Applications."
    verify_apple_app_bundle \
      "Installed macOS App Store local app" \
      "${installed_app}" \
      "${MACOS_BUNDLE_ID}" \
      "${MACOS_BUNDLE_ID}.PacketTunnel" \
      macos \
      MacOSX
    run codesign --verify --deep --strict --verbose=2 "${installed_app}"
    printf 'Installed and verified macOS App Store local package on clean system volume: %s\n' "${pkg_path}"
    return
  fi

  tmp="$(mktemp -d "${TMPDIR:-/tmp}/wins-macos-pkg-install.XXXXXX")"
  dmg_path="${tmp}/wins-macos-app-store-install-smoke.dmg"
  mount_point="${tmp}/volume"
  mkdir -p "${mount_point}"

  cleanup_macos_pkg_install_smoke() {
    trap - RETURN
    if mount | grep -Fq "${mount_point}"; then
      if ! hdiutil detach "${mount_point}" -quiet; then
        sleep 1
        hdiutil detach "${mount_point}" -quiet -force || true
      fi
    fi
    rm -rf "${tmp}"
  }
  trap cleanup_macos_pkg_install_smoke RETURN

  run hdiutil create -quiet -size "${WINS_MACOS_APP_STORE_PKG_INSTALL_IMAGE_SIZE:-512m}" -fs APFS -volname WinsPkgSmoke "${dmg_path}"
  run hdiutil attach -quiet -nobrowse -mountpoint "${mount_point}" "${dmg_path}"
  case "${authorization_mode}" in
    root)
      run installer -pkg "${pkg_path}" -target "${mount_point}" -verboseR
      ;;
    sudo)
      run sudo -n installer -pkg "${pkg_path}" -target "${mount_point}" -verboseR
      ;;
    gui)
      if ! run_macos_installer_with_gui_authorization "${pkg_path}" "${mount_point}"; then
        cleanup_macos_pkg_install_smoke
        die "Administrator-authorized macOS package installation failed."
      fi
      ;;
    *)
      die "Unexpected macOS package install authorization mode: ${authorization_mode}"
      ;;
  esac

  installed_app="${mount_point}/Applications/Win's VPN.app"
  [[ -d "${installed_app}" ]] \
    || die "macOS App Store package install smoke did not install Win's VPN.app into the temporary volume."
  verify_apple_app_bundle \
    "Installed macOS App Store local app" \
    "${installed_app}" \
    "${MACOS_BUNDLE_ID}" \
    "${MACOS_BUNDLE_ID}.PacketTunnel" \
    macos \
    MacOSX
  run codesign --verify --deep --strict --verbose=2 "${installed_app}"
  printf 'Installed and verified macOS App Store local package on temporary volume: %s\n' "${pkg_path}"
}

macos_developer_id_export_smoke() {
  if [[ "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" != "1" ]]; then
    printf 'Skipping macOS Developer ID export smoke. Set WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE=1 with WINS_REQUIRE_APPLE_ENGINE=1 to export and verify a local Developer ID artifact without notarizing or uploading.\n'
    return
  fi

  section "macOS Developer ID Export Smoke"
  local archive_path export_path app_path pkg_path export_options_plist
  archive_path="$(signed_macos_archive_path)"
  if [[ "${WINS_MACOS_ARCHIVE_SMOKE}" != "1" ]]; then
    create_signed_macos_archive
    verify_signed_macos_archive
  fi
  [[ -d "${archive_path}" ]] || die "Signed macOS archive is required before export: ${archive_path}."

  export_path="${APPLE_EXPORT_DIR}/macos-developer-id"
  rm -rf "${export_path}"
  mkdir -p "${APPLE_EXPORT_DIR}"
  export_options_plist="$(
    manual_distribution_export_options_plist \
      macos-developer-id \
      apple/ExportOptions/macos-developer-id.plist \
      "Developer ID Application" \
      "macOS app" "${MACOS_BUNDLE_ID}" "${APPLE_MACOS_APP_GROUP_ID}" \
      "macOS PacketTunnel" "${MACOS_BUNDLE_ID}.PacketTunnel" "${APPLE_MACOS_APP_GROUP_ID}"
  )"
  run_xcodebuild_with_export_signing_diagnostics \
    -hideShellScriptEnvironment \
    -exportArchive \
    -archivePath "${archive_path}" \
    -exportOptionsPlist "${export_options_plist}" \
    -exportPath "${export_path}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates

  app_path="$(find "${export_path}" -maxdepth 2 -type d -name '*.app' -print -quit)"
  if [[ -n "${app_path}" && -d "${app_path}" ]]; then
    verify_apple_app_bundle \
      "Exported macOS Developer ID app" \
      "${app_path}" \
      "${MACOS_BUNDLE_ID}" \
      "${MACOS_BUNDLE_ID}.PacketTunnel" \
      macos \
      MacOSX
    run codesign --verify --deep --strict --verbose=2 "${app_path}"
    verify_apple_release_contamination macos "${app_path}"
    printf 'Exported macOS Developer ID app: %s\n' "${app_path}"
    return
  fi

  pkg_path="$(find "${export_path}" -maxdepth 2 -type f -name '*.pkg' -print -quit)"
  [[ -n "${pkg_path}" && -f "${pkg_path}" ]] \
    || die "macOS Developer ID export did not produce an app bundle or installer package in ${export_path}."
  verify_macos_pkg_artifact \
    "${pkg_path}" \
    "Exported macOS Developer ID app" \
    "macOS Developer ID"
  printf 'Exported macOS Developer ID package: %s\n' "${pkg_path}"
}

verify_existing_ios_export_ipa() {
  local export_path="$1"
  local app_label="$2"
  local print_label="$3"
  local expected_certificate_type="$4"
  local expected_export_method="${5:-}"

  command -v unzip >/dev/null || die "unzip is required to verify exported iOS IPA payloads."
  [[ -d "${export_path}" ]] || die "${print_label} export directory is missing: ${export_path}"
  verify_existing_export_metadata \
    "${export_path}" \
    "${print_label}" \
    "${expected_certificate_type}" \
    ".ipa" \
    "${expected_export_method}"

  local ipa_path
  ipa_path="$(find "${export_path}" -maxdepth 1 -type f -name '*.ipa' -print -quit)"
  [[ -n "${ipa_path}" && -f "${ipa_path}" ]] \
    || die "${print_label} IPA is missing in ${export_path}."
  verify_ios_ipa_artifact "${ipa_path}" "${app_label}" "${print_label}"
  printf 'Verified existing %s IPA: %s\n' "${print_label}" "${ipa_path}"
}

verify_ios_ipa_artifact() {
  local ipa_path="$1"
  local app_label="$2"
  local print_label="$3"

  require_cmd unzip

  local extract_dir app_path
  verify_ios_ipa_payload_world_readable "${ipa_path}" "${print_label}"
  extract_dir="$(mktemp -d "${TMPDIR:-/tmp}/wins-existing-ipa.XXXXXX")"
  run unzip -q "${ipa_path}" -d "${extract_dir}"
  app_path="$(single_app_bundle_in "${extract_dir}/Payload" "${print_label} IPA Payload")" || {
    rm -rf "${extract_dir}"
    die "${print_label} IPA did not contain exactly one Payload/*.app."
  }
  verify_apple_app_bundle \
    "${app_label}" \
    "${app_path}" \
    "${IOS_BUNDLE_ID}" \
    "${IOS_BUNDLE_ID}.PacketTunnel" \
    ios \
    iPhoneOS
  run codesign --verify --deep --strict --verbose=2 "${app_path}"
  verify_apple_release_contamination ios "${ipa_path}"
  rm -rf "${extract_dir}"
  printf 'Verified %s IPA payload app: %s\n' "${print_label}" "${ipa_path}"
}

extract_macos_pkg_app_for_verification() {
  local pkg_path="$1"
  local print_label="$2"
  local extract_dir="$3"

  require_cmd ditto

  local expanded_dir root_dir payload_path bom_path app_path
  expanded_dir="${extract_dir}/expanded"
  root_dir="${extract_dir}/root"
  mkdir -p "${root_dir}"

  run pkgutil --expand "${pkg_path}" "${expanded_dir}" >&2
  payload_path="$(find "${expanded_dir}" -path '*/Payload' -type f -print -quit)"
  [[ -n "${payload_path}" && -f "${payload_path}" ]] \
    || die "${print_label} package is missing a component Payload."

  "${PYTHON_BIN}" - \
    "${expanded_dir}" \
    "${print_label}" \
    "${MACOS_BUNDLE_ID}" <<'PY' >&2
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

expanded_dir = Path(sys.argv[1])
print_label = sys.argv[2]
expected_bundle_id = sys.argv[3]

package_infos = sorted(expanded_dir.glob("*.pkg/PackageInfo"))
if len(package_infos) != 1:
    raise SystemExit(
        f"{print_label} package expected exactly one component PackageInfo, found {len(package_infos)}"
    )
package_info = package_infos[0]
component_dir = package_info.parent
component_ref = f"#{component_dir.name}"

package_root = ET.parse(package_info).getroot()
expected_attrs = {
    "identifier": expected_bundle_id,
    "install-location": "/Applications",
    "auth": "root",
    "relocatable": "false",
    "postinstall-action": "none",
    "preserve-xattr": "true",
}
for key, expected in expected_attrs.items():
    actual = package_root.attrib.get(key)
    if actual != expected:
        raise SystemExit(
            f"{print_label} PackageInfo {key}={actual!r}, expected {expected!r}"
        )

package_version = package_root.attrib.get("version")
if not package_version:
    raise SystemExit(f"{print_label} PackageInfo version is missing")

payload = package_root.find("payload")
if payload is None:
    raise SystemExit(f"{print_label} PackageInfo payload metadata is missing")
for key in ("numberOfFiles", "installKBytes"):
    value = payload.attrib.get(key)
    if value is None or not value.isdigit() or int(value) <= 0:
        raise SystemExit(f"{print_label} PackageInfo payload {key} must be positive")

bundle = package_root.find("bundle")
if bundle is None:
    raise SystemExit(f"{print_label} PackageInfo bundle metadata is missing")
if bundle.attrib.get("id") != expected_bundle_id:
    raise SystemExit(
        f"{print_label} PackageInfo bundle id={bundle.attrib.get('id')!r}, "
        f"expected {expected_bundle_id!r}"
    )
if bundle.attrib.get("path") != "./Win's VPN.app":
    raise SystemExit(
        f"{print_label} PackageInfo bundle path={bundle.attrib.get('path')!r}, "
        "expected \"./Win's VPN.app\""
    )
if bundle.attrib.get("CFBundleShortVersionString") != package_version:
    raise SystemExit(
        f"{print_label} PackageInfo bundle version does not match package version"
    )
if not bundle.attrib.get("CFBundleVersion"):
    raise SystemExit(f"{print_label} PackageInfo bundle build number is missing")

distribution_path = expanded_dir / "Distribution"
if not distribution_path.is_file():
    raise SystemExit(f"{print_label} package Distribution metadata is missing")
distribution = ET.parse(distribution_path).getroot()

title = distribution.findtext("title")
if title != "Win's VPN":
    raise SystemExit(f"{print_label} Distribution title={title!r}, expected \"Win's VPN\"")

product = distribution.find("product")
if product is None or product.attrib.get("id") != expected_bundle_id:
    actual = None if product is None else product.attrib.get("id")
    raise SystemExit(
        f"{print_label} Distribution product id={actual!r}, expected {expected_bundle_id!r}"
    )
if product.attrib.get("version") != package_version:
    raise SystemExit(f"{print_label} Distribution product version does not match PackageInfo")

options = distribution.find("options")
if options is None:
    raise SystemExit(f"{print_label} Distribution options metadata is missing")
if options.attrib.get("customize") != "never":
    raise SystemExit(f"{print_label} Distribution must disable installer customization")
if options.attrib.get("require-scripts") != "false":
    raise SystemExit(f"{print_label} Distribution must not require installer scripts")
architectures = set((options.attrib.get("hostArchitectures") or "").split(","))
if not {"arm64", "x86_64"}.issubset(architectures):
    raise SystemExit(
        f"{print_label} Distribution hostArchitectures={sorted(architectures)!r}, "
        "expected arm64 and x86_64"
    )

# The app pkg inherits the Runner MACOSX_DEPLOYMENT_TARGET (13.0 since ee48a2f).
os_version = distribution.find("./volume-check/allowed-os-versions/os-version")
if os_version is None or os_version.attrib.get("min") != "13.0":
    actual = None if os_version is None else os_version.attrib.get("min")
    raise SystemExit(
        f"{print_label} Distribution minimum OS={actual!r}, expected '13.0'"
    )

component_choice = None
for choice in distribution.findall("choice"):
    if choice.attrib.get("id") == expected_bundle_id:
        component_choice = choice
        break
if component_choice is None:
    raise SystemExit(f"{print_label} Distribution component choice is missing")
if component_choice.attrib.get("visible") != "false":
    raise SystemExit(f"{print_label} Distribution component choice must be hidden")
if component_choice.attrib.get("customLocation") != "/Applications":
    raise SystemExit(f"{print_label} Distribution component install location must be /Applications")

matching_pkg_ref = None
for pkg_ref in distribution.findall("pkg-ref"):
    if pkg_ref.attrib.get("id") == expected_bundle_id and (pkg_ref.text or "").strip() == component_ref:
        matching_pkg_ref = pkg_ref
        break
if matching_pkg_ref is None:
    raise SystemExit(f"{print_label} Distribution component pkg-ref is missing")
if matching_pkg_ref.attrib.get("version") != package_version:
    raise SystemExit(f"{print_label} Distribution pkg-ref version does not match PackageInfo")
if matching_pkg_ref.attrib.get("onConclusion") != "none":
    raise SystemExit(f"{print_label} Distribution pkg-ref onConclusion must be none")

print(f"{print_label} package PackageInfo metadata verified: {package_info}")
print(f"{print_label} package Distribution metadata verified: {distribution_path}")
PY

  bom_path="$(dirname "${payload_path}")/Bom"
  if [[ -f "${bom_path}" ]]; then
    run ditto -x --bom "${bom_path}" "${payload_path}" "${root_dir}" >&2
  else
    run ditto -x "${payload_path}" "${root_dir}" >&2
  fi

  app_path="$(find "${root_dir}" -maxdepth 2 -type d -name "Win's VPN.app" -print -quit)"
  [[ -n "${app_path}" && -d "${app_path}" ]] \
    || die "${print_label} package payload did not extract Win's VPN.app."
  printf '%s\n' "${app_path}"
}

verify_macos_pkg_payload_world_readable() {
  # App Store Connect error 90255: every payload entry must be readable by non-root users,
  # and every directory must also be searchable by them.
  local pkg_path="$1"
  local print_label="$2"
  local work_dir="$3"
  local expanded="${work_dir}/payload-bom"
  local listing="${work_dir}/payload-bom.listing"
  local payloads="${work_dir}/payload-bom.payloads"
  local findings="${work_dir}/payload-bom.unreadable"
  local bom payload unreadable payload_count=0
  rm -rf "${expanded}" "${listing}" "${payloads}" "${findings}"
  if ! pkgutil --expand "${pkg_path}" "${expanded}" >/dev/null; then
    rm -rf "${expanded}"
    die "${print_label} package could not be expanded to check payload permissions."
  fi
  : > "${findings}"
  if ! find "${expanded}" -name Payload -type f -print0 > "${payloads}"; then
    rm -rf "${expanded}" "${listing}" "${payloads}" "${findings}"
    die "${print_label} package payloads could not be enumerated to check payload permissions."
  fi
  # Every component payload must carry its own BOM: one checked BOM does not vouch for a
  # sibling component. Each BOM is listed to a file first, so a failing lsbom stops the gate
  # and no pipeline cut short by head can end the script under pipefail without a message.
  while IFS= read -r -d '' payload; do
    payload_count=$((payload_count + 1))
    bom="${payload%/Payload}/Bom"
    if [[ ! -f "${bom}" ]]; then
      rm -rf "${expanded}" "${listing}" "${payloads}" "${findings}"
      die "${print_label} package component has a Payload without a BOM: ${payload#"${expanded}"/}"
    fi
    if ! lsbom -p Mf "${bom}" > "${listing}"; then
      rm -rf "${expanded}" "${listing}" "${payloads}" "${findings}"
      die "${print_label} package BOM could not be listed to check payload permissions: ${bom#"${expanded}"/}"
    fi
    # lsbom prints the symbolic mode first: character 8 is the read bit for others and, on a
    # directory, character 10 is the search bit for others. An entry that does not parse fails.
    # The BOM's own root entry "." carries no file mode in an Xcode-exported package
    # ("?---------"); it is not a payload file. Only that exact entry is skipped.
    awk -F'\t' '
      NF < 2 || length($1) < 10 { print "[unparseable BOM entry: " $0 "]"; next }
      $2 == "." && $1 ~ /^\?-+ *$/ { next }
      substr($1, 8, 1) != "r" || (substr($1, 1, 1) == "d" && substr($1, 10, 1) != "x") { print $2 }
    ' "${listing}" >> "${findings}"
  done < "${payloads}"
  unreadable="$(head -5 "${findings}")"
  rm -rf "${expanded}" "${listing}" "${payloads}" "${findings}"
  (( payload_count > 0 )) \
    || die "${print_label} package has no component payload, so its payload permissions cannot be checked."
  [[ -z "${unreadable}" ]] \
    || die "${print_label} package payload has entries other users cannot read (App Store Connect error 90255): ${unreadable//$'\n'/, }"
}

verify_ios_ipa_payload_world_readable() {
  # The IPA counterpart of error 90255: export writes CodeResources and embedded.mobileprovision
  # with the caller's umask, and the zip keeps those modes. Every Unix entry must be readable by
  # others and every directory searchable by them; an entry made on another system carries no
  # mode and is refused too.
  local ipa_path="$1"
  local print_label="$2"
  require_cmd "${PYTHON_BIN}"
  "${PYTHON_BIN}" - "${ipa_path}" "${print_label}" <<'PY'
import sys
import zipfile

ipa_path, label = sys.argv[1], sys.argv[2]
try:
    with zipfile.ZipFile(ipa_path) as archive:
        entries = archive.infolist()
except (OSError, zipfile.BadZipFile) as exc:
    raise SystemExit(f"{label} IPA could not be read to check payload permissions: {exc}")
if not entries:
    raise SystemExit(f"{label} IPA is empty, so its payload permissions cannot be checked.")
# Files and directories must be readable by others; directories must also be searchable.
unreadable = [
    entry.filename
    for entry in entries
    if entry.create_system != 3
    or not (entry.external_attr >> 16) & 0o004
    or (entry.is_dir() and not (entry.external_attr >> 16) & 0o001)
]
if unreadable:
    raise SystemExit(
        f"{label} IPA has entries other users cannot read (App Store Connect error 90255): "
        + ", ".join(unreadable[:5])
    )
print(f"{label} IPA payload entries are readable by all users ({len(entries)} entries).")
PY
}

verify_macos_pkg_artifact() {
  local pkg_path="$1"
  local app_label="$2"
  local print_label="$3"

  local extract_dir app_path
  extract_dir="$(mktemp -d "${TMPDIR:-/tmp}/wins-existing-pkg.XXXXXX")"
  run pkgutil --check-signature "${pkg_path}"
  pkgutil --payload-files "${pkg_path}" | grep -Fq "Win's VPN.app/Contents/Info.plist" \
    || die "${print_label} package payload does not contain Win's VPN.app."
  verify_macos_pkg_payload_world_readable "${pkg_path}" "${print_label}" "${extract_dir}"
  app_path="$(extract_macos_pkg_app_for_verification "${pkg_path}" "${print_label}" "${extract_dir}")"
  verify_apple_app_bundle \
    "${app_label}" \
    "${app_path}" \
    "${MACOS_BUNDLE_ID}" \
    "${MACOS_BUNDLE_ID}.PacketTunnel" \
    macos \
    MacOSX
  run codesign --verify --deep --strict --verbose=2 "${app_path}"
  verify_apple_release_contamination macos "${pkg_path}"
  rm -rf "${extract_dir}"
  printf 'Verified %s package payload app: %s\n' "${print_label}" "${pkg_path}"
}

verify_existing_export_metadata() {
  local export_path="$1"
  local print_label="$2"
  local expected_certificate_type="$3"
  local expected_artifact_suffix="$4"
  local expected_export_method="${5:-}"

  require_cmd "${PYTHON_BIN}"

  "${PYTHON_BIN}" - \
    "${export_path}" \
    "${print_label}" \
    "${expected_certificate_type}" \
    "${expected_artifact_suffix}" \
    "${expected_export_method}" <<'PY'
import plistlib
import sys
from pathlib import Path

export_path = Path(sys.argv[1])
print_label = sys.argv[2]
expected_certificate_type = sys.argv[3]
expected_artifact_suffix = sys.argv[4]
expected_export_method = sys.argv[5]
options_path = export_path / "ExportOptions.plist"
summary_path = export_path / "DistributionSummary.plist"

if not options_path.is_file():
    raise SystemExit(f"{print_label} export metadata is missing ExportOptions.plist in {export_path}")
if not summary_path.is_file():
    raise SystemExit(f"{print_label} export metadata is missing DistributionSummary.plist in {export_path}")

with options_path.open("rb") as handle:
    options = plistlib.load(handle)
with summary_path.open("rb") as handle:
    summary = plistlib.load(handle)

expected_method = expected_export_method or (
    "debugging" if expected_certificate_type == "Apple Development" else "app-store-connect"
)
if options.get("destination") != "export":
    raise SystemExit(f"{print_label} ExportOptions destination={options.get('destination')!r}, expected 'export'")
if options.get("method") != expected_method:
    raise SystemExit(f"{print_label} ExportOptions method={options.get('method')!r}, expected {expected_method!r}")
if options.get("teamID") != "5YT8H4U72M":
    raise SystemExit(f"{print_label} ExportOptions teamID={options.get('teamID')!r}, expected '5YT8H4U72M'")
if expected_method == "app-store-connect":
    if options.get("uploadSymbols") is not False:
        raise SystemExit(f"{print_label} App Store local export must keep uploadSymbols=false")
    if options.get("testFlightInternalTestingOnly") is True:
        raise SystemExit(f"{print_label} App Store local export must not be internal-TestFlight-only")

if not isinstance(summary, dict) or not summary:
    raise SystemExit(f"{print_label} DistributionSummary.plist is empty or malformed")
artifact_names = [str(name) for name in summary]
if expected_artifact_suffix and not any(name.endswith(expected_artifact_suffix) for name in artifact_names):
    raise SystemExit(
        f"{print_label} DistributionSummary artifacts {artifact_names!r} did not include '*{expected_artifact_suffix}'"
    )

certificate_count = 0
team_count = 0

def walk(value):
    global certificate_count, team_count
    if isinstance(value, dict):
        certificate = value.get("certificate")
        if isinstance(certificate, dict):
            certificate_count += 1
            actual = certificate.get("type")
            if actual != expected_certificate_type:
                raise SystemExit(
                    f"{print_label} DistributionSummary certificate type={actual!r}, "
                    f"expected {expected_certificate_type!r}"
                )
        team = value.get("team")
        if isinstance(team, dict):
            team_count += 1
            actual_team = team.get("id")
            if actual_team != "5YT8H4U72M":
                raise SystemExit(
                    f"{print_label} DistributionSummary team id={actual_team!r}, expected '5YT8H4U72M'"
                )
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)

walk(summary)
if certificate_count < 1:
    raise SystemExit(f"{print_label} DistributionSummary did not include certificate metadata")
if team_count < 1:
    raise SystemExit(f"{print_label} DistributionSummary did not include team metadata")

print(f"Verified existing {print_label} export metadata: {export_path}")
PY
}

verify_existing_macos_export_artifact() {
  local export_path="$1"
  local app_label="$2"
  local print_label="$3"
  local expected_certificate_type="$4"

  [[ -d "${export_path}" ]] || die "${print_label} export directory is missing: ${export_path}"
  verify_existing_export_metadata \
    "${export_path}" \
    "${print_label}" \
    "${expected_certificate_type}" \
    ""

  local app_path pkg_path
  app_path="$(find "${export_path}" -maxdepth 2 -type d -name '*.app' -print -quit)"
  if [[ -n "${app_path}" && -d "${app_path}" ]]; then
    verify_apple_app_bundle \
      "${app_label}" \
      "${app_path}" \
      "${MACOS_BUNDLE_ID}" \
      "${MACOS_BUNDLE_ID}.PacketTunnel" \
      macos \
      MacOSX
    run codesign --verify --deep --strict --verbose=2 "${app_path}"
    printf 'Verified existing %s app: %s\n' "${print_label}" "${app_path}"
    return
  fi

  pkg_path="$(find "${export_path}" -maxdepth 2 -type f -name '*.pkg' -print -quit)"
  [[ -n "${pkg_path}" && -f "${pkg_path}" ]] \
    || die "${print_label} export did not contain an app bundle or installer package in ${export_path}."
  verify_macos_pkg_artifact "${pkg_path}" "${app_label}" "${print_label}"
  printf 'Verified existing %s package: %s\n' "${print_label}" "${pkg_path}"
}

existing_apple_exports_smoke() {
  if [[ "${WINS_APPLE_EXISTING_EXPORTS_SMOKE}" != "1" \
      && "${WINS_APPLE_VERIFY_EXISTING_EXPORTS_ONLY}" != "1" \
      && "${WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY}" != "1" ]]; then
    printf 'Skipping existing Apple exports smoke. Set WINS_APPLE_EXISTING_EXPORTS_SMOKE=1, WINS_APPLE_VERIFY_EXISTING_EXPORTS_ONLY=1, or WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY=1 with WINS_REQUIRE_APPLE_ENGINE=1 to re-verify exported artifacts without rebuilding.\n'
    return
  fi

  section "Existing Apple Export Artifact Smoke"
  if [[ "${WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY}" != "1" ]]; then
    verify_existing_ios_export_ipa \
      "${APPLE_EXPORT_DIR}/ios-debugging-local" \
      "Exported existing iOS debugging app" \
      "iOS debugging" \
      "Apple Development"
    verify_existing_ios_export_ipa \
      "${APPLE_EXPORT_DIR}/ios-release-testing" \
      "Exported existing iOS release-testing app" \
      "iOS release-testing" \
      "Apple Distribution" \
      "release-testing"
  fi
  verify_existing_ios_export_ipa \
    "${APPLE_EXPORT_DIR}/ios-app-store-local" \
    "Exported existing iOS App Store local app" \
    "iOS App Store local" \
    "Apple Distribution"
  if [[ "${WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY}" != "1" ]]; then
    verify_existing_macos_export_artifact \
      "${APPLE_EXPORT_DIR}/macos-debugging-local" \
      "Exported existing macOS debugging app" \
      "macOS debugging" \
      "Apple Development"
  fi

  local macos_app_store_export_path macos_app_store_candidate
  macos_app_store_export_path=""
  for macos_app_store_candidate in \
    "${APPLE_EXPORT_DIR}/macos-app-store-local" \
    "${APPLE_EXPORT_DIR}/macos-app-store-local-direct"; do
    if [[ -d "${macos_app_store_candidate}" ]] \
        && [[ -n "$(find "${macos_app_store_candidate}" -maxdepth 2 \( -type d -name '*.app' -o -type f -name '*.pkg' \) -print -quit)" ]]; then
      macos_app_store_export_path="${macos_app_store_candidate}"
      break
    fi
  done

  if [[ -n "${macos_app_store_export_path}" ]]; then
    verify_existing_macos_export_artifact \
      "${macos_app_store_export_path}" \
      "Exported existing macOS App Store local app" \
      "macOS App Store local" \
      "Apple Distribution"
  else
    printf 'Skipping existing macOS App Store local artifact: no app or pkg is present in %s or %s yet.\n' \
      "${APPLE_EXPORT_DIR}/macos-app-store-local" \
      "${APPLE_EXPORT_DIR}/macos-app-store-local-direct"
  fi
}

ios_simulator_smoke() {
  if [[ "${WINS_IOS_SIMULATOR_SMOKE}" != "1" ]]; then
    printf 'Skipping iOS simulator smoke. Set WINS_IOS_SIMULATOR_SMOKE=1 to build, install, and launch the simulator app.\n'
    return
  fi

  section "iOS Simulator Smoke"
  require_cmd sips
  local simulator_id
  simulator_id="$(ios_simulator_id_or_empty || true)"
  [[ -n "${simulator_id}" ]] || die "No usable iOS simulator is available."

  run_flutter_build build ios --simulator --debug
  [[ -d build/ios/iphonesimulator/Runner.app ]] \
    || die "iOS simulator app artifact was not produced at build/ios/iphonesimulator/Runner.app."
  verify_apple_app_bundle \
    "iOS simulator debug app" \
    build/ios/iphonesimulator/Runner.app \
    "${IOS_DEBUG_BUNDLE_ID}" \
    "${IOS_DEBUG_BUNDLE_ID}.PacketTunnel" \
    ios \
    iPhoneSimulator

  xcrun simctl boot "${simulator_id}" >/dev/null 2>&1 || true
  run xcrun simctl bootstatus "${simulator_id}" -b
  xcrun simctl terminate "${simulator_id}" "${IOS_DEBUG_BUNDLE_ID}" >/dev/null 2>&1 || true
  run xcrun simctl install "${simulator_id}" build/ios/iphonesimulator/Runner.app
  local screenshot_dir baseline_screenshot launched_screenshot
  screenshot_dir=""
  if [[ "${WINS_IOS_SIMULATOR_SCREENSHOT_SMOKE}" == "1" ]]; then
    screenshot_dir="$(mktemp -d "${TMPDIR:-/tmp}/wins-ios-sim-screen.XXXXXX")"
    baseline_screenshot="${screenshot_dir}/before-launch.png"
    launched_screenshot="${screenshot_dir}/after-launch.png"
    run xcrun simctl launch "${simulator_id}" com.apple.springboard
    sleep 1
    run xcrun simctl io "${simulator_id}" screenshot "${baseline_screenshot}"
  fi

  local launch_output launch_status app_pid
  printf '+ xcrun simctl launch %s %s\n' "${simulator_id}" "${IOS_DEBUG_BUNDLE_ID}"
  set +e
  launch_output="$(xcrun simctl launch "${simulator_id}" "${IOS_DEBUG_BUNDLE_ID}" 2>&1)"
  launch_status="$?"
  set -e
  printf '%s\n' "${launch_output}"
  if [[ "${launch_status}" != "0" ]]; then
    xcrun simctl terminate "${simulator_id}" "${IOS_DEBUG_BUNDLE_ID}" >/dev/null 2>&1 || true
    die "iOS simulator app launch failed."
  fi

  app_pid="$(printf '%s\n' "${launch_output}" | awk -F': ' -v bundle="${IOS_DEBUG_BUNDLE_ID}" '$1 == bundle { print $2; exit }')"
  [[ -n "${app_pid}" ]] || die "iOS simulator launch did not report a process id."
  sleep 5
  if ! kill -0 "${app_pid}" >/dev/null 2>&1; then
    xcrun simctl terminate "${simulator_id}" "${IOS_DEBUG_BUNDLE_ID}" >/dev/null 2>&1 || true
    die "iOS simulator app did not stay running after launch."
  fi
  printf 'iOS simulator app process: %s\n' "${app_pid}"
  if [[ "${WINS_IOS_SIMULATOR_SCREENSHOT_SMOKE}" == "1" ]]; then
    run xcrun simctl io "${simulator_id}" screenshot "${launched_screenshot}"
    if ! verify_ios_simulator_screenshot_transition "${baseline_screenshot}" "${launched_screenshot}"; then
      printf 'iOS simulator screenshots preserved for debugging: %s\n' "${screenshot_dir}" >&2
      xcrun simctl terminate "${simulator_id}" "${IOS_DEBUG_BUNDLE_ID}" >/dev/null 2>&1 || true
      return 1
    fi
    rm -rf "${screenshot_dir}"
  fi
  xcrun simctl terminate "${simulator_id}" "${IOS_DEBUG_BUNDLE_ID}" >/dev/null 2>&1 || true
}

macos_launch_smoke() {
  if [[ "${WINS_MACOS_LAUNCH_SMOKE}" != "1" ]]; then
    printf 'Skipping macOS launch smoke. Set WINS_MACOS_LAUNCH_SMOKE=1 to launch and inspect the macOS app shell.\n'
    return
  fi
  if [[ "${WINS_APPLE_LIVE_TUNNEL_SMOKE}" == "1" ]]; then
    printf 'Skipping basic macOS launch smoke because WINS_APPLE_LIVE_TUNNEL_SMOKE=1 will launch and inspect the signed app.\n'
    return
  fi

  section "macOS Launch Smoke"
  require_cmd open
  require_cmd pgrep
  require_cmd xcrun

  local app_path
  app_path="$(latest_macos_launch_app_or_empty || true)"
  [[ -n "${app_path}" ]] || die "No macOS debug or release app was found under Xcode DerivedData."
  [[ -d "${app_path}" ]] || die "macOS launch app path does not exist: ${app_path}"

  local app_executable
  app_executable="$(macos_app_executable_path "${app_path}")" \
    || die "macOS app executable could not be resolved from ${app_path}/Contents/Info.plist."
  pkill -f "${app_executable}" >/dev/null 2>&1 || true
  refresh_macos_app_registration "${app_path}"
  run open -n "${app_path}"
  sleep 5

  local app_pid
  app_pid="$(pgrep -f "${app_executable}" | head -n 1 || true)"
  [[ -n "${app_pid}" ]] || die "macOS app did not stay running after launch."
  printf 'macOS app process: %s\n' "${app_pid}"

  WINS_MACOS_PID="${app_pid}" xcrun swift - <<'SWIFT'
import CoreGraphics
import Foundation

let pid = Int(ProcessInfo.processInfo.environment["WINS_MACOS_PID"] ?? "") ?? -1
let options = CGWindowListOption(arrayLiteral: .optionOnScreenOnly, .excludeDesktopElements)
let windows = CGWindowListCopyWindowInfo(options, kCGNullWindowID) as? [[String: Any]] ?? []

for window in windows {
  let ownerPid = window[kCGWindowOwnerPID as String] as? Int ?? -1
  guard ownerPid == pid else { continue }
  guard (window[kCGWindowLayer as String] as? Int ?? -1) == 0 else { continue }
  guard (window[kCGWindowIsOnscreen as String] as? Int ?? 0) == 1 else { continue }
  guard let bounds = window[kCGWindowBounds as String] as? [String: Any] else { continue }
  let width = bounds["Width"] as? Double ?? 0
  let height = bounds["Height"] as? Double ?? 0
  if width >= 320 && height >= 320 {
    let name = window[kCGWindowName as String] as? String ?? "(untitled)"
    print("macOS app window: \(name) \(Int(width))x\(Int(height))")
    exit(0)
  }
}

print("No visible macOS app window with usable bounds was found for pid \(pid).")
exit(1)
SWIFT

  osascript -e "tell application id \"${MACOS_BUNDLE_ID}\" to quit" >/dev/null 2>&1 &
  local quit_pid="$!"
  local attempt
  for attempt in {1..10}; do
    if ! kill -0 "${quit_pid}" >/dev/null 2>&1; then
      wait "${quit_pid}" || true
      return
    fi
    sleep 1
  done

  kill "${quit_pid}" >/dev/null 2>&1 || true
  wait "${quit_pid}" >/dev/null 2>&1 || true
  kill "${app_pid}" >/dev/null 2>&1 || true
}

optional_ios_install() {
  if [[ "${WINS_IOS_INSTALL}" != "1" ]]; then
    printf 'Skipping physical iOS install. Set WINS_IOS_INSTALL=1 after Apple signing/provisioning is configured.\n'
    return
  fi

  if [[ "${WINS_SKIP_IOS_DEVICE}" == "1" ]]; then
    die "WINS_IOS_INSTALL=1 cannot be used with WINS_SKIP_IOS_DEVICE=1."
  fi

  section "Optional Physical iOS Install"
  require_valid_codesigning_identity
  require_physical_ios_developer_services

  local ios_device_id
  ios_device_id="$(resolve_physical_ios_device_id)"
  [[ -n "${ios_device_id}" ]] || die "Could not resolve physical iOS device id for install."
  if [[ "${WINS_IOS_LAUNCH}" == "1" || "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "1" ]]; then
    require_physical_ios_active_unlock_for_launch \
      "${ios_device_id}" \
      "physical iOS install followed by launch"
  fi

  local app_path
  local app_label="debug"
  if [[ "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "1" || "${WINS_IOS_LAUNCH}" == "1" ]]; then
    app_path="$(latest_ios_device_profile_app_or_empty || true)"
    app_label="profile"
  else
    app_path="$(latest_ios_device_debug_app_or_empty || true)"
  fi
  [[ -n "${app_path}" ]] || die "No signed iOS ${app_label} app was found under Xcode DerivedData."
  [[ -d "${app_path}" ]] || die "Signed iOS ${app_label} app path does not exist: ${app_path}"

  run_with_signing_diagnostics xcrun devicectl device install app --device "${ios_device_id}" "${app_path}"

  if [[ "${WINS_IOS_LAUNCH}" == "1" ]]; then
    require_cmd xcrun
    terminate_ios_app_if_running "${ios_device_id}"
    devicectl_ios_lock_state_report "${ios_device_id}"
    ios_active_unlock_note_if_needed
    local launch_json app_pid running_pid
    launch_json="$(mktemp "${TMPDIR:-/tmp}/wins-ios-launch.XXXXXX")"
    run_with_ios_device_launch_diagnostics xcrun devicectl device process launch \
      --terminate-existing \
      --device "${ios_device_id}" \
      --json-output "${launch_json}" \
      "${IOS_BUNDLE_ID}"
    app_pid="$("${PYTHON_BIN}" - "${launch_json}" <<'PY'
import json
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text())
except Exception:
    raise SystemExit(0)

pid = payload.get("result", {}).get("process", {}).get("processIdentifier")
if isinstance(pid, int) and pid > 0:
    print(pid)
PY
)"
    rm -f "${launch_json}"
    [[ -n "${app_pid}" ]] || die "Physical iOS app did not report a process id after launch."
    printf 'Physical iOS app process: %s\n' "${app_pid}"
    sleep 5
    running_pid="$(wait_for_ios_app_pid "${ios_device_id}" || true)"
    [[ -n "${running_pid}" ]] \
      || die "Physical iOS app did not stay running after launch."
    terminate_ios_app_if_running "${ios_device_id}"
  fi
}

ios_app_pid_or_empty() {
  local ios_device_id="$1"
  local json_output
  json_output="$(mktemp "${TMPDIR:-/tmp}/wins-ios-processes.XXXXXX")"
  if ! xcrun devicectl device info processes \
    --device "${ios_device_id}" \
    --json-output "${json_output}" >/dev/null 2>&1; then
    rm -f "${json_output}"
    return 0
  fi

  "${PYTHON_BIN}" - "${json_output}" <<'PY'
import json
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text())
except Exception:
    raise SystemExit(0)

for process in payload.get("result", {}).get("runningProcesses", []):
    executable = str(process.get("executable") or "")
    if "/Runner.app/Runner" not in executable:
        continue
    pid = process.get("processIdentifier")
    if isinstance(pid, int) and pid > 0:
        print(pid)
        raise SystemExit(0)
PY
  rm -f "${json_output}"
}

wait_for_ios_app_pid() {
  local ios_device_id="$1"
  local attempt pid
  for attempt in {1..20}; do
    pid="$(ios_app_pid_or_empty "${ios_device_id}" || true)"
    if [[ -n "${pid}" ]]; then
      printf '%s\n' "${pid}"
      return 0
    fi
    sleep 0.5
  done
}

terminate_ios_app_if_running() {
  local ios_device_id="$1"
  local pid
  pid="$(ios_app_pid_or_empty "${ios_device_id}" || true)"
  [[ -n "${pid}" ]] || return 0
  xcrun devicectl device process terminate \
    --device "${ios_device_id}" \
    --pid "${pid}" >/dev/null 2>&1 || true
}

ios_vpn_permission_ui_approval() {
  local ios_device_id="$1"
  local app_path="$2"

  if [[ "${WINS_IOS_APPROVE_VPN_PERMISSION}" != "1" ]]; then
    return
  fi

  section "Physical iOS VPN Permission UI Approval"
  require_cmd xcrun

  terminate_ios_app_if_running "${ios_device_id}"
  devicectl_ios_lock_state_report "${ios_device_id}"
  ios_active_unlock_note_if_needed
  local approval_status=0
  run_xcodebuild_with_ios_ui_automation_diagnostics \
    -hideShellScriptEnvironment \
    -workspace ios/Runner.xcworkspace \
    -scheme RunnerPermissionUITests \
    -configuration Profile \
    -destination "id=${ios_device_id}" \
    __APPLE_XCODE_AUTH_ARGS__ \
    -allowProvisioningUpdates \
    -only-testing:RunnerUITests/VpnPermissionUITests/testApprovesVpnConfigurationPermissionIfPresented \
    test || approval_status="$?"

  if [[ "${approval_status:-0}" -ne 0 ]]; then
    if [[ "${WINS_IOS_APPROVE_VPN_PERMISSION_BEST_EFFORT}" == "1" \
      && "${WINS_IOS_UI_AUTOMATION_FAILURE_DETECTED}" == "1" ]]; then
      WINS_IOS_UI_AUTOMATION_BEST_EFFORT_CONTINUED=1
      printf 'Continuing physical iOS live tunnel smoke after XCTest automation-mode failure because WINS_IOS_APPROVE_VPN_PERMISSION_BEST_EFFORT=1. The direct app launch will report whether iOS VPN configuration permission is still pending.\n' >&2
    else
      return "${approval_status}"
    fi
  fi

  if ! [[ "${WINS_IOS_VPN_PERMISSION_SETTLE_SECONDS}" =~ ^[0-9]+$ ]] \
    || (( WINS_IOS_VPN_PERMISSION_SETTLE_SECONDS < 1 \
      || WINS_IOS_VPN_PERMISSION_SETTLE_SECONDS > 120 )); then
    die "WINS_IOS_VPN_PERMISSION_SETTLE_SECONDS must be an integer from 1 through 120."
  fi
  printf 'Waiting %s seconds for the permission-triggering smoke to finish and disconnect before the evidence launch.\n' \
    "${WINS_IOS_VPN_PERMISSION_SETTLE_SECONDS}"
  sleep "${WINS_IOS_VPN_PERMISSION_SETTLE_SECONDS}"

  terminate_ios_app_if_running "${ios_device_id}"
  # The UI-test scheme installs the same current-source Profile app before it
  # requests VPN permission. Reinstalling that app after the user approves the
  # system dialog removes the just-created NETunnelProviderManager preference
  # on physical iOS devices and makes the following live launch report the
  # manager as invalid. Keep the approved installation in place. The path is
  # still validated by the caller before this helper runs.
  [[ -d "${app_path}" ]] \
    || die "Signed iOS profile app path disappeared during VPN permission approval: ${app_path}"
}

read_apple_live_tunnel_smoke_status() {
  local candidate="$1"
  local output_file
  output_file="$(mktemp "${TMPDIR:-/tmp}/wins-live-smoke-status.XXXXXX")"
  "${PYTHON_BIN}" - "${candidate}" >"${output_file}" 2>/dev/null <<'PY' &
import json
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text())
    print(payload.get("status", "") or payload.get("phase", ""))
except Exception:
    print("")
PY
  local read_pid="$!"
  local status=""
  for _ in 1 2 3 4 5 6 7 8; do
    if ! kill -0 "${read_pid}" >/dev/null 2>&1; then
      wait "${read_pid}" >/dev/null 2>&1 || true
      status="$(<"${output_file}")"
      rm -f "${output_file}"
      printf '%s' "${status}"
      return
    fi
    sleep 0.25
  done
  kill "${read_pid}" >/dev/null 2>&1 || true
  wait "${read_pid}" >/dev/null 2>&1 || true
  rm -f "${output_file}"
  printf ''
}

validate_apple_live_tunnel_smoke_result() {
  local result_file="$1"
  local output_file
  output_file="$(mktemp "${TMPDIR:-/tmp}/wins-live-smoke-validate.XXXXXX")"
  "${PYTHON_BIN}" - "${result_file}" >"${output_file}" 2>&1 <<'PY' &
import json
import os
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text())
status = payload.get("status")

def reject(message):
    print(f"Apple live tunnel smoke validator rejected result: {message}")
    raise SystemExit(1)

if payload.get("schema_version") != 1:
    reject("missing or unsupported schema_version")
if payload.get("smoke") != "apple_live_tunnel":
    reject("missing apple_live_tunnel smoke marker")
if payload.get("secret_material_redacted") is not True:
    reject("secret_material_redacted is not true")
if status not in {"running", "passed", "failed"}:
    reject("invalid status")

payload_text = json.dumps(payload, sort_keys=True).lower()
raw_markers = (
    "privatekey",
    "private key",
    "presharedkey",
    "preshared key",
    "endpoint =",
    "client_private_key",
    "client_public_key",
    "/var/",
    "/tmp/",
    "/etc/",
    "/users/",
    "/private/",
    "group containers",
    "file://",
    "http://",
    "https://",
)
if any(marker in payload_text for marker in raw_markers):
    reject("payload contains unredacted secret, path, or URL material")
ipv4_literal_pattern = re.compile(
    r"(?<![0-9])"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}"
    r"(?![0-9])"
)
if ipv4_literal_pattern.search(payload_text):
    reject("payload contains unredacted IPv4 literal")
ipv6_candidate_pattern = re.compile(
    r"(^|[^A-Za-z0-9])((?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4})(?=$|[^A-Za-z0-9])"
)
for match in ipv6_candidate_pattern.finditer(payload_text):
    candidate = match.group(2)
    if "::" in candidate or candidate.count(":") >= 3:
        reject("payload contains unredacted IPv6 literal")
hostname_like_pattern = re.compile(
    r"(^|[^A-Za-z0-9_-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
    r"(?=$|[^A-Za-z0-9_-])"
)
if hostname_like_pattern.search(payload_text):
    reject("payload contains unredacted hostname-like identifier")
uuid_like_pattern = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
if uuid_like_pattern.search(payload_text):
    reject("payload contains unredacted UUID-like identifier")
external_audit_required = os.environ.get("WINS_APPLE_EXTERNAL_LEAK_AUDIT") == "1"
requested_transport_mode = os.environ.get("WINS_APPLE_EXPECTED_TRANSPORT_MODE", "")
double_vpn_required = os.environ.get("WINS_APPLE_EXPECT_DOUBLE_VPN") == "1"

passed = payload.get("passed") is True
probe_ok = payload.get("internet_probe_ok") is True
disconnect_ok = payload.get("disconnect_ok") is True
local_state_restored = payload.get("local_state_restored") is True
if status == "passed" and passed and probe_ok and disconnect_ok:
    required_true_fields = (
        "local_state_restored",
        "readiness_available",
        "ready",
        "connected",
        "active",
        "network_extension_connected",
        "provider_status_available",
        "provider_status_current",
        "provider_ready",
        "provider_engine_ready",
        "provider_network_settings_ready",
        "provider_healthy",
        "provider_message_probe_healthy",
        "provider_message_probe_accepted",
        "provider_message_probe_engine_running",
        "provider_message_probe_transport_mode_supported",
        "provider_message_probe_transport_mode_consistent",
        "provider_message_probe_executable_sha256_matches_expected",
        "transport_mode_verified",
        "internet_probe_available",
        "internet_probe_attempted",
        "leak_protection_config_checked",
        "leak_protection_config_passed",
        "leak_protection_provider_status_current",
        "leak_protection_default_route_enabled",
        "leak_protection_ipv6_enabled",
        "leak_protection_engine_ipv6_enabled",
        "leak_protection_dns_full_tunnel_match_enabled",
        "leak_protection_engine_dns_full_tunnel_match_enabled",
    )
    for field in required_true_fields:
        if payload.get(field) is not True:
            reject(f"passed result is missing required true field {field}")
    required_false_fields = (
        "internet_probe_blocked_by_provider_readiness",
        "internet_probe_blocked_by_leak_protection_config",
    )
    for field in required_false_fields:
        if payload.get(field) is not False:
            reject(f"passed result is missing required false field {field}")
    if payload.get("internet_probe_url_kind") != "public_https":
        reject("passed result did not use the public_https probe kind")
    expected_transport = payload.get("expected_transport_mode")
    observed_transport = payload.get("observed_transport_mode")
    allowed_transports = payload.get("allowed_transport_modes")
    supported_transports = {"amneziawg", "xray_vless_ws_amneziawg"}
    if expected_transport not in {"automatic", *supported_transports}:
        reject("passed result has unsupported expected transport mode")
    if not isinstance(allowed_transports, list) or any(
        not isinstance(item, str) for item in allowed_transports
    ):
        reject("passed result is missing the allowed transport modes")
    if expected_transport == "automatic":
        if allowed_transports != ["amneziawg", "xray_vless_ws_amneziawg"]:
            reject("automatic lane does not preserve direct and Xray fallback order")
    elif allowed_transports != [expected_transport]:
        reject("forced lane does not pin exactly one transport")
    if observed_transport not in allowed_transports:
        reject("passed result did not prove an allowed transport mode")
    if requested_transport_mode and expected_transport != requested_transport_mode:
        reject("compiled app transport does not match the requested live lane")
    provider_transport = payload.get("provider_message_probe_transport_mode")
    if provider_transport != observed_transport:
        reject("passed result provider transport does not match observed transport")
    provider_executable_sha256 = payload.get("provider_message_probe_executable_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", provider_executable_sha256):
        reject("passed result is missing the exact active provider executable hash")
    if double_vpn_required:
        for field in (
            "double_vpn_requested",
            "double_vpn_active",
            "double_vpn_verified",
        ):
            if payload.get(field) is not True:
                reject(f"passed Double VPN result is missing required true field {field}")
        for field in ("double_vpn_core_id", "double_vpn_exit_slug"):
            value = payload.get(field)
            if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,63}", value):
                reject(f"passed Double VPN result is missing safe non-empty field {field}")
    for field in (
        "leak_protection_dns_server_count",
        "leak_protection_engine_dns_server_count",
    ):
        value = payload.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            reject(f"passed result is missing positive integer field {field}")
    if external_audit_required:
        for field in (
            "external_leak_audit_requested",
            "external_leak_audit_attempted",
            "external_leak_audit_passed",
            "external_leak_audit_non_google_cloudflare_only",
        ):
            if payload.get(field) is not True:
                reject(f"passed result is missing required external audit true field {field}")
        if payload.get("external_leak_audit_blocked_by_configuration") is not False:
            reject("passed result reported external audit configuration block")
        if payload.get("external_leak_audit_url_kind") != "public_https_hostname_canary":
            reject("passed result did not use public HTTPS hostname canaries")
        endpoint_count = payload.get("external_leak_audit_endpoint_count")
        minimum_count = payload.get("external_leak_audit_minimum_endpoint_count")
        success_count = payload.get("external_leak_audit_success_count")
        failure_count = payload.get("external_leak_audit_failure_count")
        invalid_count = payload.get("external_leak_audit_invalid_endpoint_count")
        https_count = payload.get("external_leak_audit_https_canary_count")
        dns_count = payload.get("external_leak_audit_dns_canary_count")
        for field_name, value in (
            ("external_leak_audit_endpoint_count", endpoint_count),
            ("external_leak_audit_minimum_endpoint_count", minimum_count),
            ("external_leak_audit_success_count", success_count),
            ("external_leak_audit_https_canary_count", https_count),
            ("external_leak_audit_dns_canary_count", dns_count),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 2:
                reject(f"passed result is missing integer >=2 field {field_name}")
        for field_name, value in (
            ("external_leak_audit_failure_count", failure_count),
            ("external_leak_audit_invalid_endpoint_count", invalid_count),
        ):
            if value != 0:
                reject(f"passed result expected zero {field_name}")
        if success_count != endpoint_count or https_count != endpoint_count or dns_count != endpoint_count:
            reject("passed result external canary counts do not match endpoint count")
    summary = "Apple live VPN connect/probe/disconnect passed."
else:
    summary = payload.get("readiness_summary") or payload.get("error") or "no sanitized summary"
print(f"Apple live tunnel smoke result: status={status} passed={passed} probe_ok={probe_ok} disconnect_ok={disconnect_ok} local_state_restored={local_state_restored}")
print(f"Apple live tunnel smoke summary: {summary}")
platform = payload.get("platform")
permission_pending = (
    platform in ("ios", "macos")
    and (
        payload.get("vpn_configuration_permission_pending") is True
        or payload.get("vpn_manager_invalid_after_config_save") is True
        or "Approve the iOS VPN configuration permission" in summary
        or "Approve the macOS VPN configuration permission" in summary
    )
)
if permission_pending:
    provider_stage = payload.get("provider_stage", "")
    native_status = payload.get("native_tunnel_status", "")
    connected = payload.get("network_extension_connected")
    manager_invalid = payload.get("vpn_manager_invalid_after_config_save")
    vpn_permission = payload.get("vpn_configuration_permission_pending")
    if platform == "macos":
        print("Apple live tunnel smoke blocker: macOS VPN authorization is incomplete; launch Win's VPN in the logged-in GUI session and approve the VPN configuration permission.")
    else:
        print("Apple live tunnel smoke blocker: iOS VPN authorization is incomplete on the device; accept the VPN prompt and complete Face ID or device-passcode authentication.")
    print(
        "Apple live tunnel smoke readiness: "
        f"provider_stage={provider_stage} native_status={native_status} "
        f"network_extension_connected={connected} "
        f"manager_invalid_after_config_save={manager_invalid} "
        f"vpn_permission_pending={vpn_permission}"
    )
leak_protection_blocked = (
    payload.get("internet_probe_blocked_by_leak_protection_config") is True
    or (
        payload.get("leak_protection_config_checked") is True
        and payload.get("leak_protection_config_passed") is False
    )
)
if leak_protection_blocked and status != "passed" and not permission_pending:
    leak_kind = payload.get("leak_protection_config_kind", "")
    default_route = payload.get("leak_protection_default_route_enabled")
    ipv6 = payload.get("leak_protection_ipv6_enabled")
    dns_match = payload.get("leak_protection_dns_full_tunnel_match_enabled")
    print("Apple live tunnel smoke blocker: leak-protection config is incomplete before internet probe.")
    print(
        "Apple live tunnel smoke leak-protection readiness: "
        f"kind={leak_kind} default_route={default_route} "
        f"ipv6={ipv6} dns_full_tunnel_match={dns_match}"
    )
if status != "passed" or not passed or not probe_ok or not disconnect_ok or not local_state_restored:
    raise SystemExit(1)
PY
  local validate_pid="$!"
  local validate_status=0
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if ! kill -0 "${validate_pid}" >/dev/null 2>&1; then
      wait "${validate_pid}" >/dev/null 2>&1 || validate_status="$?"
      cat "${output_file}" || true
      rm -f "${output_file}"
      return "${validate_status}"
    fi
    sleep 0.25
  done
  kill "${validate_pid}" >/dev/null 2>&1 || true
  wait "${validate_pid}" >/dev/null 2>&1 || true
  rm -f "${output_file}"
  printf 'Apple live tunnel smoke result could not be read within 5 seconds: %s\n' "${result_file}" >&2
  return 1
}

read_apple_live_tunnel_smoke_log_status() {
  local log_file="$1"
  local output_file
  output_file="$(mktemp "${TMPDIR:-/tmp}/wins-live-smoke-log-status.XXXXXX")"
  "${PYTHON_BIN}" - "${log_file}" >"${output_file}" 2>/dev/null <<'PY' &
import json
import sys
from pathlib import Path

token = "WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT "
last = None
try:
    for line in Path(sys.argv[1]).read_text(errors="replace").splitlines():
        if token not in line:
            continue
        raw = line.split(token, 1)[1].strip()
        try:
            payload = json.loads(raw)
        except Exception:
            continue
        if isinstance(payload, dict):
            last = payload
    if last is None:
        print("")
    else:
        print(last.get("status", "") or last.get("phase", ""))
except Exception:
    print("")
PY
  local read_pid="$!"
  local status=""
  for _ in 1 2 3 4 5 6 7 8; do
    if ! kill -0 "${read_pid}" >/dev/null 2>&1; then
      wait "${read_pid}" >/dev/null 2>&1 || true
      status="$(<"${output_file}")"
      rm -f "${output_file}"
      printf '%s' "${status}"
      return
    fi
    sleep 0.25
  done
  kill "${read_pid}" >/dev/null 2>&1 || true
  wait "${read_pid}" >/dev/null 2>&1 || true
  rm -f "${output_file}"
  printf ''
}

validate_apple_live_tunnel_smoke_log_result() {
  local log_file="$1"
  local output_file
  output_file="$(mktemp "${TMPDIR:-/tmp}/wins-live-smoke-log-validate.XXXXXX")"
  "${PYTHON_BIN}" - "${log_file}" >"${output_file}" 2>&1 <<'PY' &
import json
import os
import re
import sys
from pathlib import Path

token = "WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT "
payload = None
log_text = Path(sys.argv[1]).read_text(errors="replace")
for line in log_text.splitlines():
    if token not in line:
        continue
    raw = line.split(token, 1)[1].strip()
    try:
        candidate = json.loads(raw)
    except Exception:
        continue
    if isinstance(candidate, dict):
        payload = candidate
if payload is None:
    print("Apple live tunnel smoke stdout did not contain a sanitized result payload.")
    raise SystemExit(1)
status = payload.get("status")

def reject(message):
    print(f"Apple live tunnel smoke validator rejected result: {message}")
    raise SystemExit(1)

if payload.get("schema_version") != 1:
    reject("missing or unsupported schema_version")
if payload.get("smoke") != "apple_live_tunnel":
    reject("missing apple_live_tunnel smoke marker")
if payload.get("secret_material_redacted") is not True:
    reject("secret_material_redacted is not true")
if status not in {"running", "passed", "failed"}:
    reject("invalid status")

payload_text = json.dumps(payload, sort_keys=True).lower()
raw_markers = (
    "privatekey",
    "private key",
    "presharedkey",
    "preshared key",
    "endpoint =",
    "client_private_key",
    "client_public_key",
    "/var/",
    "/tmp/",
    "/etc/",
    "/users/",
    "/private/",
    "group containers",
    "file://",
    "http://",
    "https://",
)
if any(marker in payload_text for marker in raw_markers):
    reject("payload contains unredacted secret, path, or URL material")
ipv4_literal_pattern = re.compile(
    r"(?<![0-9])"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}"
    r"(?![0-9])"
)
if ipv4_literal_pattern.search(payload_text):
    reject("payload contains unredacted IPv4 literal")
ipv6_candidate_pattern = re.compile(
    r"(^|[^A-Za-z0-9])((?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4})(?=$|[^A-Za-z0-9])"
)
for match in ipv6_candidate_pattern.finditer(payload_text):
    candidate = match.group(2)
    if "::" in candidate or candidate.count(":") >= 3:
        reject("payload contains unredacted IPv6 literal")
hostname_like_pattern = re.compile(
    r"(^|[^A-Za-z0-9_-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
    r"(?=$|[^A-Za-z0-9_-])"
)
if hostname_like_pattern.search(payload_text):
    reject("payload contains unredacted hostname-like identifier")
uuid_like_pattern = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
if uuid_like_pattern.search(payload_text):
    reject("payload contains unredacted UUID-like identifier")
external_audit_required = os.environ.get("WINS_APPLE_EXTERNAL_LEAK_AUDIT") == "1"
requested_transport_mode = os.environ.get("WINS_APPLE_EXPECTED_TRANSPORT_MODE", "")
double_vpn_required = os.environ.get("WINS_APPLE_EXPECT_DOUBLE_VPN") == "1"

passed = payload.get("passed") is True
probe_ok = payload.get("internet_probe_ok") is True
disconnect_ok = payload.get("disconnect_ok") is True
local_state_restored = payload.get("local_state_restored") is True
if status == "passed" and passed and probe_ok and disconnect_ok:
    required_true_fields = (
        "local_state_restored",
        "readiness_available",
        "ready",
        "connected",
        "active",
        "network_extension_connected",
        "provider_status_available",
        "provider_status_current",
        "provider_ready",
        "provider_engine_ready",
        "provider_network_settings_ready",
        "provider_healthy",
        "provider_message_probe_healthy",
        "provider_message_probe_accepted",
        "provider_message_probe_engine_running",
        "provider_message_probe_transport_mode_supported",
        "provider_message_probe_transport_mode_consistent",
        "provider_message_probe_executable_sha256_matches_expected",
        "transport_mode_verified",
        "internet_probe_available",
        "internet_probe_attempted",
        "leak_protection_config_checked",
        "leak_protection_config_passed",
        "leak_protection_provider_status_current",
        "leak_protection_default_route_enabled",
        "leak_protection_ipv6_enabled",
        "leak_protection_engine_ipv6_enabled",
        "leak_protection_dns_full_tunnel_match_enabled",
        "leak_protection_engine_dns_full_tunnel_match_enabled",
    )
    for field in required_true_fields:
        if payload.get(field) is not True:
            reject(f"passed result is missing required true field {field}")
    required_false_fields = (
        "internet_probe_blocked_by_provider_readiness",
        "internet_probe_blocked_by_leak_protection_config",
    )
    for field in required_false_fields:
        if payload.get(field) is not False:
            reject(f"passed result is missing required false field {field}")
    if payload.get("internet_probe_url_kind") != "public_https":
        reject("passed result did not use the public_https probe kind")
    expected_transport = payload.get("expected_transport_mode")
    observed_transport = payload.get("observed_transport_mode")
    allowed_transports = payload.get("allowed_transport_modes")
    supported_transports = {"amneziawg", "xray_vless_ws_amneziawg"}
    if expected_transport not in {"automatic", *supported_transports}:
        reject("passed result has unsupported expected transport mode")
    if not isinstance(allowed_transports, list) or any(
        not isinstance(item, str) for item in allowed_transports
    ):
        reject("passed result is missing the allowed transport modes")
    if expected_transport == "automatic":
        if allowed_transports != ["amneziawg", "xray_vless_ws_amneziawg"]:
            reject("automatic lane does not preserve direct and Xray fallback order")
    elif allowed_transports != [expected_transport]:
        reject("forced lane does not pin exactly one transport")
    if observed_transport not in allowed_transports:
        reject("passed result did not prove an allowed transport mode")
    if requested_transport_mode and expected_transport != requested_transport_mode:
        reject("compiled app transport does not match the requested live lane")
    provider_transport = payload.get("provider_message_probe_transport_mode")
    if provider_transport != observed_transport:
        reject("passed result provider transport does not match observed transport")
    provider_executable_sha256 = payload.get("provider_message_probe_executable_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", provider_executable_sha256):
        reject("passed result is missing the exact active provider executable hash")
    if double_vpn_required:
        for field in (
            "double_vpn_requested",
            "double_vpn_active",
            "double_vpn_verified",
        ):
            if payload.get(field) is not True:
                reject(f"passed Double VPN result is missing required true field {field}")
        for field in ("double_vpn_core_id", "double_vpn_exit_slug"):
            value = payload.get(field)
            if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,63}", value):
                reject(f"passed Double VPN result is missing safe non-empty field {field}")
    for field in (
        "leak_protection_dns_server_count",
        "leak_protection_engine_dns_server_count",
    ):
        value = payload.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            reject(f"passed result is missing positive integer field {field}")
    if external_audit_required:
        for field in (
            "external_leak_audit_requested",
            "external_leak_audit_attempted",
            "external_leak_audit_passed",
            "external_leak_audit_non_google_cloudflare_only",
        ):
            if payload.get(field) is not True:
                reject(f"passed result is missing required external audit true field {field}")
        if payload.get("external_leak_audit_blocked_by_configuration") is not False:
            reject("passed result reported external audit configuration block")
        if payload.get("external_leak_audit_url_kind") != "public_https_hostname_canary":
            reject("passed result did not use public HTTPS hostname canaries")
        endpoint_count = payload.get("external_leak_audit_endpoint_count")
        minimum_count = payload.get("external_leak_audit_minimum_endpoint_count")
        success_count = payload.get("external_leak_audit_success_count")
        failure_count = payload.get("external_leak_audit_failure_count")
        invalid_count = payload.get("external_leak_audit_invalid_endpoint_count")
        https_count = payload.get("external_leak_audit_https_canary_count")
        dns_count = payload.get("external_leak_audit_dns_canary_count")
        for field_name, value in (
            ("external_leak_audit_endpoint_count", endpoint_count),
            ("external_leak_audit_minimum_endpoint_count", minimum_count),
            ("external_leak_audit_success_count", success_count),
            ("external_leak_audit_https_canary_count", https_count),
            ("external_leak_audit_dns_canary_count", dns_count),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 2:
                reject(f"passed result is missing integer >=2 field {field_name}")
        for field_name, value in (
            ("external_leak_audit_failure_count", failure_count),
            ("external_leak_audit_invalid_endpoint_count", invalid_count),
        ):
            if value != 0:
                reject(f"passed result expected zero {field_name}")
        if success_count != endpoint_count or https_count != endpoint_count or dns_count != endpoint_count:
            reject("passed result external canary counts do not match endpoint count")
    summary = "Apple live VPN connect/probe/disconnect passed."
else:
    summary = (
        payload.get("readiness_summary")
        or payload.get("error")
        or payload.get("phase")
        or "no sanitized summary"
    )
if "System Maintenance underway" in log_text and status != "passed":
    summary = f"{summary}; hub reported System Maintenance underway"
print(f"Apple live tunnel smoke result: status={status} passed={passed} probe_ok={probe_ok} disconnect_ok={disconnect_ok} local_state_restored={local_state_restored}")
print(f"Apple live tunnel smoke summary: {summary}")
platform = payload.get("platform")
permission_pending = (
    platform in ("ios", "macos")
    and (
        payload.get("vpn_configuration_permission_pending") is True
        or payload.get("vpn_manager_invalid_after_config_save") is True
        or "Approve the iOS VPN configuration permission" in summary
        or "Approve the macOS VPN configuration permission" in summary
    )
)
if permission_pending:
    provider_stage = payload.get("provider_stage", "")
    native_status = payload.get("native_tunnel_status", "")
    connected = payload.get("network_extension_connected")
    manager_invalid = payload.get("vpn_manager_invalid_after_config_save")
    vpn_permission = payload.get("vpn_configuration_permission_pending")
    if platform == "macos":
        print("Apple live tunnel smoke blocker: macOS VPN configuration permission pending in the logged-in GUI session.")
    else:
        print("Apple live tunnel smoke blocker: iOS VPN configuration permission pending on the device.")
    print(
        "Apple live tunnel smoke readiness: "
        f"provider_stage={provider_stage} native_status={native_status} "
        f"network_extension_connected={connected} "
        f"manager_invalid_after_config_save={manager_invalid} "
        f"vpn_permission_pending={vpn_permission}"
    )
leak_protection_blocked = (
    payload.get("internet_probe_blocked_by_leak_protection_config") is True
    or (
        payload.get("leak_protection_config_checked") is True
        and payload.get("leak_protection_config_passed") is False
    )
)
if leak_protection_blocked and status != "passed" and not permission_pending:
    leak_kind = payload.get("leak_protection_config_kind", "")
    default_route = payload.get("leak_protection_default_route_enabled")
    ipv6 = payload.get("leak_protection_ipv6_enabled")
    dns_match = payload.get("leak_protection_dns_full_tunnel_match_enabled")
    print("Apple live tunnel smoke blocker: leak-protection config is incomplete before internet probe.")
    print(
        "Apple live tunnel smoke leak-protection readiness: "
        f"kind={leak_kind} default_route={default_route} "
        f"ipv6={ipv6} dns_full_tunnel_match={dns_match}"
    )
if status != "passed" or not passed or not probe_ok or not disconnect_ok or not local_state_restored:
    raise SystemExit(1)
PY
  local validate_pid="$!"
  local validate_status=0
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if ! kill -0 "${validate_pid}" >/dev/null 2>&1; then
      wait "${validate_pid}" >/dev/null 2>&1 || validate_status="$?"
      cat "${output_file}" || true
      rm -f "${output_file}"
      return "${validate_status}"
    fi
    sleep 0.25
  done
  kill "${validate_pid}" >/dev/null 2>&1 || true
  wait "${validate_pid}" >/dev/null 2>&1 || true
  rm -f "${output_file}"
  printf 'Apple live tunnel smoke stdout result could not be read within 5 seconds: %s\n' "${log_file}" >&2
  return 1
}

run_live_tunnel_result_selftest() {
  section "Apple Live Tunnel Result Validator Self-Test"

  local tmpdir
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/wins-live-smoke-selftest.XXXXXX")"
  local good_json="${tmpdir}/good.json"
  local good_automatic_xray_json="${tmpdir}/good-automatic-xray.json"
  local good_audit_json="${tmpdir}/good-audit.json"
  local weak_audit_json="${tmpdir}/weak-audit.json"
  local good_audit_log="${tmpdir}/good-audit.log"
  local macos_permission_json="${tmpdir}/macos-permission.json"
  local bad_schema_json="${tmpdir}/bad-schema.json"
  local secret_json="${tmpdir}/secret.json"
  local ip_literal_json="${tmpdir}/ip-literal.json"
  local ipv6_literal_json="${tmpdir}/ipv6-literal.json"
  local hostname_json="${tmpdir}/hostname.json"
  local uuid_json="${tmpdir}/uuid.json"
  local weak_pass_json="${tmpdir}/weak-pass.json"
  local weak_double_vpn_json="${tmpdir}/weak-double-vpn.json"
  local good_log="${tmpdir}/good.log"
  local empty_log="${tmpdir}/empty.log"

  cat >"${good_json}" <<'JSON'
{
  "schema_version": 1,
  "smoke": "apple_live_tunnel",
  "status": "passed",
  "platform": "ios",
  "updated_at": "2026-07-09T00:00:00Z",
  "secret_material_redacted": true,
  "passed": true,
  "ready": true,
  "connected": true,
  "active": true,
  "readiness_available": true,
  "network_extension_connected": true,
  "provider_status_available": true,
  "provider_status_current": true,
  "provider_ready": true,
  "provider_engine_ready": true,
  "provider_network_settings_ready": true,
  "provider_healthy": true,
  "provider_message_probe_healthy": true,
  "provider_message_probe_accepted": true,
  "provider_message_probe_engine_running": true,
  "provider_message_probe_transport_mode": "amneziawg",
  "provider_message_probe_transport_mode_supported": true,
  "provider_message_probe_transport_mode_consistent": true,
  "provider_message_probe_executable_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "provider_message_probe_executable_sha256_matches_expected": true,
  "expected_transport_mode": "amneziawg",
  "allowed_transport_modes": ["amneziawg"],
  "observed_transport_mode": "amneziawg",
  "transport_mode_verified": true,
  "double_vpn_requested": true,
  "double_vpn_active": true,
  "double_vpn_verified": true,
  "double_vpn_core_id": "north-america-core",
  "double_vpn_exit_slug": "spain-madrid",
  "internet_probe_available": true,
  "internet_probe_attempted": true,
  "internet_probe_ok": true,
  "internet_probe_blocked_by_provider_readiness": false,
  "internet_probe_blocked_by_leak_protection_config": false,
  "internet_probe_url_kind": "public_https",
  "disconnect_ok": true,
  "local_state_restored": true,
  "leak_protection_config_checked": true,
  "leak_protection_config_passed": true,
  "leak_protection_provider_status_current": true,
  "leak_protection_default_route_enabled": true,
  "leak_protection_ipv6_enabled": true,
  "leak_protection_engine_ipv6_enabled": true,
  "leak_protection_dns_full_tunnel_match_enabled": true,
  "leak_protection_engine_dns_full_tunnel_match_enabled": true,
  "leak_protection_dns_server_count": 2,
  "leak_protection_engine_dns_server_count": 2
}
JSON
  WINS_APPLE_EXTERNAL_LEAK_AUDIT=0 \
    validate_apple_live_tunnel_smoke_result "${good_json}" >/dev/null
  WINS_APPLE_EXTERNAL_LEAK_AUDIT=0 \
    WINS_APPLE_EXPECT_DOUBLE_VPN=1 \
    validate_apple_live_tunnel_smoke_result "${good_json}" >/dev/null
  jq '
    .expected_transport_mode = "automatic"
    | .allowed_transport_modes = ["amneziawg", "xray_vless_ws_amneziawg"]
    | .observed_transport_mode = "xray_vless_ws_amneziawg"
    | .provider_message_probe_transport_mode = "xray_vless_ws_amneziawg"
  ' "${good_json}" >"${good_automatic_xray_json}"
  WINS_APPLE_EXTERNAL_LEAK_AUDIT=0 \
    WINS_APPLE_EXPECTED_TRANSPORT_MODE=automatic \
    validate_apple_live_tunnel_smoke_result "${good_automatic_xray_json}" >/dev/null
  sed 's/"double_vpn_active": true/"double_vpn_active": false/' \
    "${good_json}" >"${weak_double_vpn_json}"
  if WINS_APPLE_EXTERNAL_LEAK_AUDIT=0 \
    WINS_APPLE_EXPECT_DOUBLE_VPN=1 \
    validate_apple_live_tunnel_smoke_result "${weak_double_vpn_json}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test accepted an inactive Double VPN configuration."
  fi
  if WINS_APPLE_EXTERNAL_LEAK_AUDIT=0 \
    WINS_APPLE_EXPECTED_TRANSPORT_MODE=xray_vless_ws_amneziawg \
    validate_apple_live_tunnel_smoke_result "${good_json}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test accepted a reused app compiled for the wrong transport."
  fi

  cat >"${good_audit_json}" <<'JSON'
{
  "schema_version": 1,
  "smoke": "apple_live_tunnel",
  "status": "passed",
  "platform": "ios",
  "updated_at": "2026-07-09T00:00:00Z",
  "secret_material_redacted": true,
  "passed": true,
  "ready": true,
  "connected": true,
  "active": true,
  "readiness_available": true,
  "network_extension_connected": true,
  "provider_status_available": true,
  "provider_status_current": true,
  "provider_ready": true,
  "provider_engine_ready": true,
  "provider_network_settings_ready": true,
  "provider_healthy": true,
  "provider_message_probe_healthy": true,
  "provider_message_probe_accepted": true,
  "provider_message_probe_engine_running": true,
  "provider_message_probe_transport_mode": "amneziawg",
  "provider_message_probe_transport_mode_supported": true,
  "provider_message_probe_transport_mode_consistent": true,
  "provider_message_probe_executable_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "provider_message_probe_executable_sha256_matches_expected": true,
  "expected_transport_mode": "amneziawg",
  "allowed_transport_modes": ["amneziawg"],
  "observed_transport_mode": "amneziawg",
  "transport_mode_verified": true,
  "internet_probe_available": true,
  "internet_probe_attempted": true,
  "internet_probe_ok": true,
  "internet_probe_blocked_by_provider_readiness": false,
  "internet_probe_blocked_by_leak_protection_config": false,
  "internet_probe_url_kind": "public_https",
  "disconnect_ok": true,
  "local_state_restored": true,
  "leak_protection_config_checked": true,
  "leak_protection_config_passed": true,
  "leak_protection_provider_status_current": true,
  "leak_protection_default_route_enabled": true,
  "leak_protection_ipv6_enabled": true,
  "leak_protection_engine_ipv6_enabled": true,
  "leak_protection_dns_full_tunnel_match_enabled": true,
  "leak_protection_engine_dns_full_tunnel_match_enabled": true,
  "leak_protection_dns_server_count": 2,
  "leak_protection_engine_dns_server_count": 2,
  "external_leak_audit_requested": true,
  "external_leak_audit_attempted": true,
  "external_leak_audit_passed": true,
  "external_leak_audit_endpoint_count": 2,
  "external_leak_audit_minimum_endpoint_count": 2,
  "external_leak_audit_invalid_endpoint_count": 0,
  "external_leak_audit_success_count": 2,
  "external_leak_audit_failure_count": 0,
  "external_leak_audit_https_canary_count": 2,
  "external_leak_audit_dns_canary_count": 2,
  "external_leak_audit_non_google_cloudflare_only": true,
  "external_leak_audit_blocked_by_configuration": false,
  "external_leak_audit_url_kind": "public_https_hostname_canary"
}
JSON
  WINS_APPLE_EXTERNAL_LEAK_AUDIT=1 \
    validate_apple_live_tunnel_smoke_result "${good_audit_json}" >/dev/null
  printf 'noise before payload\nWINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT %s\n' \
    "$(tr -d '\n' <"${good_audit_json}")" >"${good_audit_log}"
  WINS_APPLE_EXTERNAL_LEAK_AUDIT=1 \
    validate_apple_live_tunnel_smoke_log_result "${good_audit_log}" >/dev/null

  cat >"${macos_permission_json}" <<'JSON'
{
  "schema_version": 1,
  "smoke": "apple_live_tunnel",
  "status": "failed",
  "platform": "macos",
  "updated_at": "2026-07-16T00:00:00Z",
  "secret_material_redacted": true,
  "passed": false,
  "internet_probe_ok": false,
  "disconnect_ok": true,
  "local_state_restored": true,
  "vpn_configuration_permission_pending": true,
  "provider_stage": "config_saved",
  "native_tunnel_status": "invalid",
  "leak_protection_config_checked": true,
  "leak_protection_config_passed": false,
  "readiness_summary": "Approve the macOS VPN configuration permission for Win's VPN, then try again."
}
JSON
  local macos_permission_output
  local macos_permission_status=0
  set +e
  macos_permission_output="$(
    WINS_APPLE_EXTERNAL_LEAK_AUDIT=1 \
      validate_apple_live_tunnel_smoke_result "${macos_permission_json}" 2>&1
  )"
  macos_permission_status="$?"
  set -e
  if [[ "${macos_permission_status}" -eq 0 ]]; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test expected pending macOS permission to remain a failing release gate."
  fi
  if [[ "${macos_permission_output}" != *"macOS VPN authorization is incomplete"* ]]; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test did not report the pending macOS permission blocker."
  fi
  if [[ "${macos_permission_output}" == *"leak-protection config is incomplete"* ]]; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test misclassified pending macOS permission as a leak-protection blocker."
  fi

  cat >"${weak_audit_json}" <<'JSON'
{
  "schema_version": 1,
  "smoke": "apple_live_tunnel",
  "status": "passed",
  "platform": "ios",
  "updated_at": "2026-07-09T00:00:00Z",
  "secret_material_redacted": true,
  "passed": true,
  "ready": true,
  "connected": true,
  "active": true,
  "readiness_available": true,
  "network_extension_connected": true,
  "provider_status_available": true,
  "provider_status_current": true,
  "provider_ready": true,
  "provider_engine_ready": true,
  "provider_network_settings_ready": true,
  "provider_healthy": true,
  "provider_message_probe_healthy": true,
  "provider_message_probe_accepted": true,
  "provider_message_probe_engine_running": true,
  "internet_probe_available": true,
  "internet_probe_attempted": true,
  "internet_probe_ok": true,
  "internet_probe_blocked_by_provider_readiness": false,
  "internet_probe_blocked_by_leak_protection_config": false,
  "internet_probe_url_kind": "public_https",
  "disconnect_ok": true,
  "local_state_restored": true,
  "leak_protection_config_checked": true,
  "leak_protection_config_passed": true,
  "leak_protection_provider_status_current": true,
  "leak_protection_default_route_enabled": true,
  "leak_protection_ipv6_enabled": true,
  "leak_protection_engine_ipv6_enabled": true,
  "leak_protection_dns_full_tunnel_match_enabled": true,
  "leak_protection_engine_dns_full_tunnel_match_enabled": true,
  "leak_protection_dns_server_count": 2,
  "leak_protection_engine_dns_server_count": 2,
  "external_leak_audit_requested": true,
  "external_leak_audit_attempted": false,
  "external_leak_audit_passed": false,
  "external_leak_audit_endpoint_count": 1,
  "external_leak_audit_minimum_endpoint_count": 2,
  "external_leak_audit_invalid_endpoint_count": 1,
  "external_leak_audit_success_count": 0,
  "external_leak_audit_failure_count": 0,
  "external_leak_audit_https_canary_count": 1,
  "external_leak_audit_dns_canary_count": 1,
  "external_leak_audit_non_google_cloudflare_only": false,
  "external_leak_audit_blocked_by_configuration": true,
  "external_leak_audit_url_kind": "public_https_hostname_canary"
}
JSON
  if WINS_APPLE_EXTERNAL_LEAK_AUDIT=1 \
    validate_apple_live_tunnel_smoke_result "${weak_audit_json}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test expected weak external audit rejection."
  fi

  cat >"${bad_schema_json}" <<'JSON'
{
  "schema_version": 0,
  "smoke": "apple_live_tunnel",
  "status": "passed",
  "platform": "ios",
  "secret_material_redacted": true,
  "passed": true,
  "internet_probe_ok": true,
  "disconnect_ok": true
}
JSON
  if validate_apple_live_tunnel_smoke_result "${bad_schema_json}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test expected bad schema rejection."
  fi

  cat >"${secret_json}" <<'JSON'
{
  "schema_version": 1,
  "smoke": "apple_live_tunnel",
  "status": "passed",
  "platform": "ios",
  "secret_material_redacted": true,
  "passed": true,
  "internet_probe_ok": true,
  "disconnect_ok": true,
  "error": "PrivateKey = should-not-be-here"
}
JSON
  if validate_apple_live_tunnel_smoke_result "${secret_json}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test expected secret payload rejection."
  fi

  cat >"${ip_literal_json}" <<'JSON'
{
  "schema_version": 1,
  "smoke": "apple_live_tunnel",
  "status": "passed",
  "platform": "ios",
  "secret_material_redacted": true,
  "passed": true,
  "internet_probe_ok": true,
  "disconnect_ok": true,
  "error": "provider returned 203.0.113.10"
}
JSON
  if validate_apple_live_tunnel_smoke_result "${ip_literal_json}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test expected IPv4 literal rejection."
  fi

  cat >"${ipv6_literal_json}" <<'JSON'
{
  "schema_version": 1,
  "smoke": "apple_live_tunnel",
  "status": "passed",
  "platform": "ios",
  "secret_material_redacted": true,
  "passed": true,
  "internet_probe_ok": true,
  "disconnect_ok": true,
  "error": "provider returned fd48:6989:709::1"
}
JSON
  if validate_apple_live_tunnel_smoke_result "${ipv6_literal_json}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test expected IPv6 literal rejection."
  fi

  cat >"${hostname_json}" <<'JSON'
{
  "schema_version": 1,
  "smoke": "apple_live_tunnel",
  "status": "passed",
  "platform": "ios",
  "secret_material_redacted": true,
  "passed": true,
  "internet_probe_ok": true,
  "disconnect_ok": true,
  "error": "provider returned api.winsvpn.org"
}
JSON
  if validate_apple_live_tunnel_smoke_result "${hostname_json}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test expected hostname-like identifier rejection."
  fi

  cat >"${uuid_json}" <<'JSON'
{
  "schema_version": 1,
  "smoke": "apple_live_tunnel",
  "status": "passed",
  "platform": "ios",
  "secret_material_redacted": true,
  "passed": true,
  "internet_probe_ok": true,
  "disconnect_ok": true,
  "error": "provider returned 00000000-0000-0000-0000-000000000000"
}
JSON
  if validate_apple_live_tunnel_smoke_result "${uuid_json}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test expected UUID-like identifier rejection."
  fi

  cat >"${weak_pass_json}" <<'JSON'
{
  "schema_version": 1,
  "smoke": "apple_live_tunnel",
  "status": "passed",
  "platform": "ios",
  "secret_material_redacted": true,
  "passed": true,
  "internet_probe_ok": true,
  "disconnect_ok": true
}
JSON
  if validate_apple_live_tunnel_smoke_result "${weak_pass_json}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test expected weak pass rejection."
  fi

  printf 'noise before payload\nWINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT %s\n' \
    "$(tr -d '\n' <"${good_json}")" >"${good_log}"
  WINS_APPLE_EXTERNAL_LEAK_AUDIT=0 \
    validate_apple_live_tunnel_smoke_log_result "${good_log}" >/dev/null
  WINS_APPLE_EXTERNAL_LEAK_AUDIT=0 \
    WINS_APPLE_EXPECT_DOUBLE_VPN=1 \
    validate_apple_live_tunnel_smoke_log_result "${good_log}" >/dev/null

  printf 'noise without payload\n' >"${empty_log}"
  if validate_apple_live_tunnel_smoke_log_result "${empty_log}" >/dev/null 2>&1; then
    rm -rf "${tmpdir}"
    die "Apple live tunnel result self-test expected missing log payload rejection."
  fi

  rm -rf "${tmpdir}"
  printf 'Apple live tunnel result validator self-test passed.\n'
}

macos_live_tunnel_smoke() {
  if [[ "${WINS_APPLE_LIVE_TUNNEL_SMOKE}" != "1" ]]; then
    printf 'Skipping Apple live tunnel smoke. Set WINS_APPLE_LIVE_TUNNEL_SMOKE=1 to run the signed macOS connect/probe/disconnect lane.\n'
    return
  fi

  section "Apple Live Tunnel Smoke"
  require_cmd open
  require_cmd pgrep
  require_cmd osascript
  require_cmd "${PYTHON_BIN}"

  if [[ -z "${WINS_MACOS_LIVE_TUNNEL_APP_PATH}" ]]; then
    [[ "${WINS_SIGNED_MACOS_BUILD}" == "1" ]] \
      || die "WINS_APPLE_LIVE_TUNNEL_SMOKE=1 requires WINS_SIGNED_MACOS_BUILD=1 unless WINS_MACOS_LIVE_TUNNEL_APP_PATH selects a verified signed app."
  fi
  [[ "${WINS_REQUIRE_APPLE_ENGINE}" == "1" ]] \
    || die "WINS_APPLE_LIVE_TUNNEL_SMOKE=1 requires WINS_REQUIRE_APPLE_ENGINE=1 so the bundled AWG/Xray/Winn engine gate is enforced first."

  local app_path
  if [[ -n "${WINS_MACOS_LIVE_TUNNEL_APP_PATH}" ]]; then
    app_path="${WINS_MACOS_LIVE_TUNNEL_APP_PATH}"
    [[ "${app_path}" == /* ]] \
      || die "WINS_MACOS_LIVE_TUNNEL_APP_PATH must be an absolute path."
    [[ -d "${app_path}" ]] \
      || die "Requested macOS live tunnel app path does not exist: ${app_path}"
    verify_apple_app_bundle \
      "Selected macOS live tunnel app" \
      "${app_path}" \
      "${MACOS_BUNDLE_ID}" \
      "${MACOS_BUNDLE_ID}.PacketTunnel" \
      macos \
      MacOSX
    run codesign --verify --deep --strict --verbose=2 "${app_path}"

  else
    app_path="$(latest_macos_debug_app_or_empty || true)"
    [[ -n "${app_path}" ]] || die "No signed macOS debug app was found under Xcode DerivedData."
    [[ -d "${app_path}" ]] || die "Signed macOS debug app path does not exist: ${app_path}"
  fi

  # A clean-install verification may leave an App Store build registered under
  # the same production PacketTunnel identifier. NetworkExtension can then
  # resolve the stale provider even though the current development app is the
  # one being launched. Registration is reversible and the app bundle remains
  # untouched, so make the selected provider identity unambiguous before the
  # live activation gate.
  local selected_packet_tunnel_path
  selected_packet_tunnel_path="${app_path}/Contents/PlugIns/PacketTunnel.appex"
  if command -v pluginkit >/dev/null 2>&1; then
    local registered_packet_tunnel_path
    while IFS= read -r registered_packet_tunnel_path; do
      [[ -n "${registered_packet_tunnel_path}" ]] || continue
      [[ "${registered_packet_tunnel_path}" != "${selected_packet_tunnel_path}" ]] || continue
      printf '+ pluginkit -r %s\n' "${registered_packet_tunnel_path}"
      pluginkit -r "${registered_packet_tunnel_path}" >/dev/null 2>&1 || true
    done < <(
      pluginkit -m -A -v -i "${MACOS_BUNDLE_ID}.PacketTunnel" 2>/dev/null \
        | sed -n 's#^.*\t\(/.*\.appex\)$#\1#p'
    )
  fi

  local result_file_name
  result_file_name="apple_live_tunnel_smoke_$(date +%Y%m%d%H%M%S)_$$.json"
  local result_directory
  result_directory="${HOME}/Library/Group Containers/${APPLE_MACOS_APP_GROUP_ID}/wins_vpn"
  mkdir -p "${result_directory}"
  local result_candidates=(
    "${result_directory}/${result_file_name}"
    "${HOME}/Library/Containers/${MACOS_BUNDLE_ID}/Data/Library/Application Support/wins_vpn/${result_file_name}"
    "${HOME}/Library/Application Support/wins_vpn/${result_file_name}"
  )
  local stdout_log
  stdout_log="$(mktemp "${TMPDIR:-/tmp}/wins-live-smoke-app.XXXXXX")"
  local candidate
  for candidate in "${result_candidates[@]}"; do
    rm -f "${candidate}"
  done
  local app_executable
  app_executable="$(macos_app_executable_path "${app_path}")" \
    || die "Signed macOS app executable could not be resolved from ${app_path}/Contents/Info.plist."
  pkill -f "${app_executable}" >/dev/null 2>&1 || true
  refresh_macos_app_registration "${app_path}"

  local created_at_epoch
  created_at_epoch="$(date +%s)"
  [[ -x "${app_executable}" ]] || die "Signed macOS app executable does not exist: ${app_executable}"
  printf '+ open -W -n --env WINS_APPLE_LIVE_TUNNEL_SMOKE=1 --env WINS_APPLE_LIVE_TUNNEL_SMOKE_REQUEST=1 ... %s\n' "${app_path}"
  /usr/bin/open \
    -W \
    -n \
    --stdout "${stdout_log}" \
    --stderr "${stdout_log}" \
    --env WINS_APPLE_LIVE_TUNNEL_SMOKE=1 \
    --env WINS_APPLE_LIVE_TUNNEL_SMOKE_REQUEST=1 \
    --env "WINS_APPLE_LIVE_TUNNEL_SMOKE_CREATED_AT_EPOCH=${created_at_epoch}" \
    --env "WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS=${WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS}" \
    --env "WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN=${WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN}" \
    --env "WINS_APPLE_LIVE_TUNNEL_SMOKE_DOUBLE_VPN=${WINS_APPLE_EXPECT_DOUBLE_VPN}" \
    --env "WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT_DIRECTORY=${result_directory}" \
    --env "WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT_FILENAME=${result_file_name}" \
    --env "WINS_APPLE_EXTERNAL_LEAK_AUDIT=${WINS_APPLE_EXTERNAL_LEAK_AUDIT}" \
    --env "WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS=${WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS}" \
    --env "WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS=${WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS}" \
    "${app_path}" >/dev/null 2>&1 &
  local launch_pid="$!"
  local app_pid=""
  for _ in {1..40}; do
    app_pid="$(pgrep -f "${app_executable}" | head -n 1 || true)"
    [[ -n "${app_pid}" ]] && break
    sleep 0.25
  done
  [[ -n "${app_pid}" ]] || {
    kill "${launch_pid}" >/dev/null 2>&1 || true
    wait "${launch_pid}" >/dev/null 2>&1 || true
    die "LaunchServices did not keep the signed macOS app running for live tunnel smoke."
  }
  printf 'macOS live tunnel app process: %s\n' "${app_pid}"

  local deadline_seconds=$((WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS + 45))
  local start_seconds="${SECONDS}"
  local result_file=""
  local status=""
  while (( SECONDS - start_seconds < deadline_seconds )); do
    for candidate in "${result_candidates[@]}"; do
      [[ -f "${candidate}" ]] || continue
      result_file="${candidate}"
      status="$(read_apple_live_tunnel_smoke_status "${candidate}")"
      if [[ "${status}" == "passed" || "${status}" == "failed" ]]; then
        break
      fi
    done
    if [[ "${status}" != "passed" && "${status}" != "failed" ]]; then
      status="$(read_apple_live_tunnel_smoke_log_status "${stdout_log}")"
    fi
    if [[ "${status}" == "passed" || "${status}" == "failed" ]]; then
      break
    fi
    sleep 2
  done

  local validation_status=0
  if [[ -n "${result_file}" && -f "${result_file}" ]]; then
    validate_apple_live_tunnel_smoke_result "${result_file}" || validation_status=1
  else
    validate_apple_live_tunnel_smoke_log_result "${stdout_log}" || validation_status=1
  fi

  if [[ "${status}" != "passed" && "${status}" != "failed" && -z "${result_file}" ]]; then
    printf 'Apple live tunnel smoke did not write a result file within %s seconds.\n' "${deadline_seconds}" >&2
    printf 'Checked result paths:\n' >&2
    printf '  %s\n' "${result_candidates[@]}" >&2
    printf 'Checked stdout log: %s\n' "${stdout_log}" >&2
    validation_status=1
  fi

  osascript -e "tell application id \"${MACOS_BUNDLE_ID}\" to quit" >/dev/null 2>&1 &
  local quit_pid="$!"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "${quit_pid}" >/dev/null 2>&1 || break
    sleep 0.5
  done
  if kill -0 "${quit_pid}" >/dev/null 2>&1; then
    kill "${quit_pid}" >/dev/null 2>&1 || true
    wait "${quit_pid}" >/dev/null 2>&1 || true
  else
    wait "${quit_pid}" >/dev/null 2>&1 || true
  fi
  if kill -0 "${launch_pid}" >/dev/null 2>&1; then
    kill "${launch_pid}" >/dev/null 2>&1 || true
    wait "${launch_pid}" >/dev/null 2>&1 || true
  else
    wait "${launch_pid}" >/dev/null 2>&1 || true
  fi
  kill "${app_pid}" >/dev/null 2>&1 || true
  pkill -f "${app_executable}" >/dev/null 2>&1 || true
  scutil --nc stop "Win's VPN" >/dev/null 2>&1 || true

  if [[ "${validation_status}" -ne 0 ]]; then
    if [[ -n "${result_file}" ]]; then
      die "Apple live tunnel smoke failed. Inspect sanitized result: ${result_file}"
    fi
    die "Apple live tunnel smoke failed. Inspect sanitized stdout log: ${stdout_log}"
  fi
  if [[ -n "${result_file}" ]]; then
    printf 'Apple live tunnel smoke sanitized result: %s\n' "${result_file}"
  fi
  printf 'Apple live tunnel smoke sanitized stdout log: %s\n' "${stdout_log}"
}

ios_live_tunnel_smoke() {
  if [[ "${WINS_IOS_LIVE_TUNNEL_SMOKE}" != "1" ]]; then
    printf 'Skipping physical iOS live tunnel smoke. Set WINS_IOS_LIVE_TUNNEL_SMOKE=1 with WINS_IOS_INSTALL=1 to run the signed iPhone connect/probe/disconnect lane.\n'
    return
  fi

  section "Physical iOS Live Tunnel Smoke"
  require_cmd xcrun
  require_cmd "${PYTHON_BIN}"

  [[ "${WINS_IOS_INSTALL}" == "1" ]] \
    || die "WINS_IOS_LIVE_TUNNEL_SMOKE=1 requires WINS_IOS_INSTALL=1 so the signed app is present on the physical iPhone."
  [[ "${WINS_REQUIRE_APPLE_ENGINE}" == "1" ]] \
    || die "WINS_IOS_LIVE_TUNNEL_SMOKE=1 requires WINS_REQUIRE_APPLE_ENGINE=1 so the bundled AWG/Xray/Winn engine gate is enforced first."

  require_physical_ios_developer_services

  local ios_device_id
  ios_device_id="$(resolve_physical_ios_device_id)"
  [[ -n "${ios_device_id}" ]] || die "Could not resolve physical iOS device id for live tunnel smoke."
  require_physical_ios_active_unlock_for_launch \
    "${ios_device_id}" \
    "physical iOS live tunnel smoke"

  local app_path
  app_path="$(latest_ios_device_profile_app_or_empty || true)"
  [[ -n "${app_path}" ]] || die "No signed iOS profile app was found under Xcode DerivedData."
  [[ -d "${app_path}" ]] || die "Signed iOS profile app path does not exist: ${app_path}"

  ios_vpn_permission_ui_approval "${ios_device_id}" "${app_path}"
  terminate_ios_app_if_running "${ios_device_id}"
  devicectl_ios_lock_state_report "${ios_device_id}"
  ios_active_unlock_note_if_needed

  local stdout_log
  stdout_log="$(mktemp "${TMPDIR:-/tmp}/wins-ios-live-smoke-app.XXXXXX")"
  local created_at_epoch
  created_at_epoch="$(date +%s)"

  printf '+ env DEVICECTL_CHILD_WINS_APPLE_LIVE_TUNNEL_SMOKE=1 DEVICECTL_CHILD_WINS_APPLE_LIVE_TUNNEL_SMOKE_REQUEST=1 ... xcrun devicectl device process launch --console --device %s %s\n' \
    "${ios_device_id}" "${IOS_BUNDLE_ID}"
  env \
    DEVICECTL_CHILD_WINS_APPLE_LIVE_TUNNEL_SMOKE=1 \
    DEVICECTL_CHILD_WINS_APPLE_LIVE_TUNNEL_SMOKE_REQUEST=1 \
    "DEVICECTL_CHILD_WINS_APPLE_LIVE_TUNNEL_SMOKE_CREATED_AT_EPOCH=${created_at_epoch}" \
    "DEVICECTL_CHILD_WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS=${WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS}" \
    "DEVICECTL_CHILD_WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN=${WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN}" \
    "DEVICECTL_CHILD_WINS_APPLE_LIVE_TUNNEL_SMOKE_DOUBLE_VPN=${WINS_APPLE_EXPECT_DOUBLE_VPN}" \
    "DEVICECTL_CHILD_WINS_APPLE_EXTERNAL_LEAK_AUDIT=${WINS_APPLE_EXTERNAL_LEAK_AUDIT}" \
    "DEVICECTL_CHILD_WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS=${WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS}" \
    "DEVICECTL_CHILD_WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS=${WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS}" \
    xcrun devicectl device process launch \
      --device "${ios_device_id}" \
      --console \
      "${IOS_BUNDLE_ID}" >"${stdout_log}" 2>&1 &
  local launch_pid="$!"

  local deadline_seconds=$((WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS + 75))
  local start_seconds="${SECONDS}"
  local status=""
  while (( SECONDS - start_seconds < deadline_seconds )); do
    status="$(read_apple_live_tunnel_smoke_log_status "${stdout_log}")"
    if [[ "${status}" == "passed" || "${status}" == "failed" ]]; then
      break
    fi
    if ! kill -0 "${launch_pid}" >/dev/null 2>&1; then
      wait "${launch_pid}" >/dev/null 2>&1 || true
      status="$(read_apple_live_tunnel_smoke_log_status "${stdout_log}")"
      break
    fi
    sleep 2
  done

  local validation_status=0
  validate_apple_live_tunnel_smoke_log_result "${stdout_log}" || validation_status=1

  terminate_ios_app_if_running "${ios_device_id}"
  if kill -0 "${launch_pid}" >/dev/null 2>&1; then
    kill "${launch_pid}" >/dev/null 2>&1 || true
    wait "${launch_pid}" >/dev/null 2>&1 || true
  else
    wait "${launch_pid}" >/dev/null 2>&1 || true
  fi

  if [[ "${status}" != "passed" && "${status}" != "failed" ]]; then
    printf 'Physical iOS live tunnel smoke did not emit a final sanitized result within %s seconds.\n' "${deadline_seconds}" >&2
    printf 'Checked stdout log: %s\n' "${stdout_log}" >&2
    validation_status=1
  fi

  if [[ "${validation_status}" -ne 0 ]]; then
    die "Physical iOS live tunnel smoke failed. If the blocker above reports incomplete iOS VPN authorization, accept the Win's VPN prompt, complete Face ID or device-passcode authentication on the iPhone, and rerun this lane. Inspect sanitized stdout log: ${stdout_log}"
  fi
  printf 'Physical iOS live tunnel smoke sanitized stdout log: %s\n' "${stdout_log}"
}

lane_status() {
  if [[ "$1" == "1" ]]; then
    printf 'passed'
  else
    printf 'skipped'
  fi
}

ios_launch_lane_status() {
  if [[ "${WINS_IOS_INSTALL}" == "1" && "${WINS_IOS_LAUNCH}" == "1" ]]; then
    printf 'passed'
  else
    printf 'skipped'
  fi
}

signed_ios_build_lane_status() {
  if [[ "${WINS_IOS_SIGNED_BUILD}" == "1" || "${WINS_IOS_INSTALL}" == "1" ]]; then
    printf 'passed'
  else
    printf 'skipped'
  fi
}

signed_ios_build_lane_label() {
  if [[ "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "1" || "${WINS_IOS_LAUNCH}" == "1" ]]; then
    printf 'Signed iOS profile build'
  else
    printf 'Signed iOS debug build'
  fi
}

required_engine_lane_status() {
  if [[ "${WINS_REQUIRE_APPLE_ENGINE}" == "1" ]]; then
    printf 'passed'
  else
    printf 'optional'
  fi
}

macos_launch_lane_status() {
  if [[ "${WINS_MACOS_LAUNCH_SMOKE}" != "1" ]]; then
    printf 'skipped'
  elif [[ "${WINS_APPLE_LIVE_TUNNEL_SMOKE}" == "1" ]]; then
    printf 'superseded by live smoke'
  else
    printf 'passed'
  fi
}

apple_live_tunnel_lane_status() {
  if [[ "${WINS_APPLE_LIVE_TUNNEL_SMOKE}" == "1" ]]; then
    printf 'passed'
  else
    printf 'skipped'
  fi
}

ios_live_tunnel_lane_status() {
  if [[ "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "1" ]]; then
    printf 'passed'
  else
    printf 'skipped'
  fi
}

ios_vpn_permission_ui_lane_status() {
  if [[ "${WINS_IOS_APPROVE_VPN_PERMISSION}" != "1" ]]; then
    printf 'skipped'
  elif [[ "${WINS_IOS_UI_AUTOMATION_BEST_EFFORT_CONTINUED}" == "1" ]]; then
    printf 'best-effort-failed'
  else
    printf 'passed'
  fi
}

if [[ "${WINS_PRE_RELEASE_SOURCE_SMOKE_SELFTEST}" == "1" ]]; then
  run_pre_release_source_smoke_selftest
  exit 0
fi

if [[ "${WINS_SIGNING_DIAGNOSIS_SELFTEST}" == "1" ]]; then
  run_signing_diagnostics_selftest
  exit 0
fi

if [[ "${WINS_ENGINE_ARTIFACT_SELFTEST}" == "1" ]]; then
  run_engine_artifact_selftest
  exit 0
fi

if [[ "${WINS_LIVE_TUNNEL_RESULT_SELFTEST}" == "1" ]]; then
  run_live_tunnel_result_selftest
  exit 0
fi

rerun_macos_pkg_install_lane_as_user_if_root "$@"
require_reviewed_flutter_toolchain
require_reviewed_cocoapods
configure_apple_xcode_auth_args
configure_apple_macos_development_signing_args
if [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY}" == "1" \
  && "${WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE}" != "1" ]]; then
  die "WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY=1 requires WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE=1."
fi
if app_store_connect_upload_lane_requested; then
  refuse_direct_app_store_connect_upload
  require_app_store_connect_upload_auth
  probe_app_store_connect_upload_auth
  require_valid_apple_submission_package_for_upload
  require_owner_signoff_for_app_store_upload
fi
force_archive_privacy_report_for_app_store_upload

require_macos_developer_id_system_extension_migration_if_requested
require_requested_signed_prereqs
apple_signing_keychain_probe
runtime_preflight_report
if [[ "${WINS_PREFLIGHT_ONLY}" == "1" ]]; then
  if [[ "${WINS_APPLE_PRIVACY_ARCHIVE_REPORT}" == "1" ]]; then
    apple_privacy_archive_report
  fi
  section "Result"
  printf 'Apple runtime preflight report completed. This diagnostic mode does not build or install the app.\n'
  exit 0
fi

if [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY}" == "1" ]]; then
  if [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_SYSTEM_TARGET}" == "1" ]]; then
    export WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH=1
  else
    export WINS_MACOS_APP_STORE_PKG_ROOT_GATE_REFRESH=1
  fi
fi

if [[ "${WINS_PRE_RELEASE_SOURCE_SMOKE}" == "1" ]]; then
  require_pre_release_source_smoke_safe
  section "Pre-release Source Smoke Gate"
  printf '%s\n' \
    'Testing the next source version without treating the prior processed App Store candidate as current.' \
    'Archives, exports, uploads, App Store package installs, privacy archives, and existing-release verification are disabled in this lane.'
else
  section "Readiness Gate"
  run bash tools/verify_apple_readiness.sh
fi

if [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY}" == "1" ]]; then
  require_full_xcode
  macos_app_store_pkg_install_smoke
  section "Result"
  printf 'Current macOS App Store package clean-install verification completed without rebuilding or inspecting unrelated exports.\n'
  exit 0
fi

if [[ "${WINS_APPLE_VERIFY_EXISTING_EXPORTS_ONLY}" == "1" \
    || "${WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY}" == "1" ]]; then
  require_full_xcode
  existing_apple_exports_smoke
  macos_app_store_pkg_install_smoke
  section "Result"
  if [[ "${WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY}" == "1" ]]; then
    printf 'Current iOS and macOS App Store exported artifacts were re-verified without rebuilding or inspecting historical debug exports.\n'
  else
    printf 'Existing Apple exported artifacts were re-verified without rebuilding or exporting.\n'
  fi
  exit 0
fi

require_full_xcode
require_flutter_and_device
if [[ "${WINS_SKIP_APPLE_DEBUG_BUILDS}" == "1" ]]; then
  [[ "${WINS_APPLE_LIVE_TUNNEL_SMOKE}" == "1" ]] \
    || die "WINS_SKIP_APPLE_DEBUG_BUILDS=1 is restricted to the macOS live tunnel gate."
  [[ -n "${WINS_MACOS_LIVE_TUNNEL_APP_PATH}" ]] \
    || die "WINS_SKIP_APPLE_DEBUG_BUILDS=1 requires WINS_MACOS_LIVE_TUNNEL_APP_PATH."
  [[ "${WINS_IOS_INSTALL}" == "0" \
    && "${WINS_IOS_LAUNCH}" == "0" \
    && "${WINS_IOS_SIGNED_BUILD}" == "0" \
    && "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "0" \
    && "${WINS_SIGNED_MACOS_BUILD}" == "0" ]] \
    || die "WINS_SKIP_APPLE_DEBUG_BUILDS=1 cannot be combined with an Apple build, install, or iOS live lane."
  section "Verified Apple Artifact-Only Gate"
  printf 'Skipping Apple debug builds; the selected signed macOS app will be verified before live activation.\n'
else
  install_pods
  build_apple_apps
  optional_ios_install
fi
release_shell_smoke
ios_archive_smoke
macos_archive_smoke
ios_debugging_export_smoke
macos_debugging_export_smoke
ios_release_testing_export_smoke
ios_app_store_local_export_smoke
ios_testflight_internal_upload_smoke
ios_app_store_connect_upload_smoke
macos_app_store_local_export_smoke
macos_app_store_connect_upload_smoke
# Every function above that can create a signed archive self-heals it when its own
# *_ARCHIVE_SMOKE flag was not set, so the privacy report must run after all of them
# (never before) or it can observe neither archive yet and abort with "No Apple
# archives were available" for an upload-only invocation (e.g. only
# WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE=1 set on its own).
if [[ "${WINS_APPLE_PRIVACY_ARCHIVE_REPORT}" == "1" ]]; then
  apple_privacy_archive_report
fi
macos_app_store_pkg_install_smoke
macos_developer_id_export_smoke
existing_apple_exports_smoke
ios_simulator_smoke
macos_launch_smoke
macos_live_tunnel_smoke
ios_live_tunnel_smoke

section "Result"
printf 'Apple runtime smoke prerequisites and requested build/test lanes completed.\n'
printf 'Unsigned debug builds: passed.\n'
printf 'Release shell smoke: %s.\n' "$(lane_status "${WINS_RELEASE_SHELL_SMOKE}")"
printf '%s: %s.\n' "$(signed_ios_build_lane_label)" "$(signed_ios_build_lane_status)"
printf 'Physical iOS install: %s.\n' "$(lane_status "${WINS_IOS_INSTALL}")"
printf 'Physical iOS launch: %s.\n' "$(ios_launch_lane_status)"
printf 'Signed macOS debug build: %s.\n' "$(lane_status "${WINS_SIGNED_MACOS_BUILD}")"
printf 'Signed iOS archive smoke: %s.\n' "$(lane_status "${WINS_IOS_ARCHIVE_SMOKE}")"
printf 'Signed macOS archive smoke: %s.\n' "$(lane_status "${WINS_MACOS_ARCHIVE_SMOKE}")"
printf 'iOS debugging export smoke: %s.\n' "$(lane_status "${WINS_IOS_DEBUGGING_EXPORT_SMOKE}")"
printf 'macOS debugging export smoke: %s.\n' "$(lane_status "${WINS_MACOS_DEBUGGING_EXPORT_SMOKE}")"
printf 'iOS release-testing export smoke: %s.\n' "$(lane_status "${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE}")"
printf 'iOS App Store local export smoke: %s.\n' "$(lane_status "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE}")"
printf 'iOS TestFlight internal upload smoke: %s.\n' "$(lane_status "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE}")"
printf 'iOS App Store Connect upload smoke: %s.\n' "$(lane_status "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE}")"
printf 'macOS App Store local export smoke: %s.\n' "$(lane_status "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}")"
printf 'macOS App Store Connect upload smoke: %s.\n' "$(lane_status "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE}")"
printf 'macOS App Store package install smoke: %s.\n' "$(lane_status "${WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE}")"
printf 'macOS Developer ID export smoke: %s.\n' "$(lane_status "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}")"
printf 'Existing Apple exports smoke: %s.\n' "$(lane_status "${WINS_APPLE_EXISTING_EXPORTS_SMOKE}")"
printf 'Apple signing keychain probe: %s.\n' "$(lane_status "$(if apple_signing_keychain_probe_requested; then printf '1'; else printf '0'; fi)")"
printf 'Apple archive privacy manifest report: %s.\n' "$(lane_status "${WINS_APPLE_PRIVACY_ARCHIVE_REPORT}")"
printf 'iOS simulator smoke: %s.\n' "$(lane_status "${WINS_IOS_SIMULATOR_SMOKE}")"
printf 'macOS launch smoke: %s.\n' "$(macos_launch_lane_status)"
printf 'Apple live tunnel smoke: %s.\n' "$(apple_live_tunnel_lane_status)"
printf 'Physical iOS VPN permission UI helper: %s.\n' "$(ios_vpn_permission_ui_lane_status)"
printf 'Physical iOS live tunnel smoke: %s.\n' "$(ios_live_tunnel_lane_status)"
printf 'Bundled AWG/Xray engine artifact gate: %s.\n' "$(required_engine_lane_status)"
if [[ "${WINS_APPLE_LIVE_TUNNEL_SMOKE}" == "1" && "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "1" ]]; then
  printf 'Signed macOS and physical iOS live VPN connect/probe/disconnect validation completed.\n'
elif [[ "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "1" ]]; then
  if [[ "${WINS_IOS_UI_AUTOMATION_BEST_EFFORT_CONTINUED}" == "1" ]]; then
    printf 'Physical iOS VPN permission UI helper could not enter XCTest automation mode, but the direct physical iOS live VPN connect/probe/disconnect lane passed.\n'
  fi
  printf 'Physical iOS live VPN connect/probe/disconnect validation completed. Signed macOS live validation is still recommended before release packaging.\n'
elif [[ "${WINS_APPLE_LIVE_TUNNEL_SMOKE}" == "1" ]]; then
  printf 'Signed macOS live VPN connect/probe/disconnect validation completed. Production iOS release still needs the equivalent physical-device live tunnel validation before App Store submission.\n'
elif app_store_connect_upload_lane_requested; then
  printf 'Requested App Store Connect upload lanes completed. Wait for Apple processing, then finish TestFlight/App Store metadata, privacy, and release review checks.\n'
elif [[ "${WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE}" == "1" || "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE}" == "1" || "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1" ]]; then
  printf 'Requested signed Apple distribution export lanes completed and exported artifacts were verified. TestFlight/App Store upload still needs an explicit upload command and final App Store privacy/review checks.\n'
elif [[ "${WINS_IOS_DEBUGGING_EXPORT_SMOKE}" == "1" || "${WINS_MACOS_DEBUGGING_EXPORT_SMOKE}" == "1" ]]; then
  printf 'Requested signed Apple local debugging export lanes completed and exported artifacts were verified. Production readiness still requires distribution export profiles and live VPN validation on every Apple platform before submission.\n'
elif [[ "${WINS_IOS_ARCHIVE_SMOKE}" == "1" || "${WINS_MACOS_ARCHIVE_SMOKE}" == "1" ]]; then
  printf 'Requested signed Apple archive lanes completed and archived app bundles were verified. Production readiness still requires live VPN validation on every Apple platform before submission.\n'
elif [[ "${WINS_REQUIRE_APPLE_ENGINE}" == "1" && ("${WINS_IOS_SIGNED_BUILD}" == "1" || "${WINS_IOS_INSTALL}" == "1" || "${WINS_SIGNED_MACOS_BUILD}" == "1") ]]; then
  printf 'Requested signed Apple provisioning lanes and bundled packet-engine checks completed. Production readiness still requires live VPN tunnel validation against the control hub and data plane.\n'
elif [[ "${WINS_IOS_SIGNED_BUILD}" == "1" || "${WINS_IOS_INSTALL}" == "1" || "${WINS_SIGNED_MACOS_BUILD}" == "1" ]]; then
  printf 'Requested signed Apple provisioning lanes completed. Rerun with WINS_REQUIRE_APPLE_ENGINE=1 to require bundled AWG/Xray/Winn packet-engine artifacts.\n'
else
  if [[ "${WINS_REQUIRE_APPLE_ENGINE}" == "1" ]]; then
    printf 'Requested unsigned/simulator/launch lanes and bundled AWG/Xray/Winn packet-engine checks completed. Production readiness still requires signed Network Extension distribution profiles/exports and live VPN validation on every Apple platform before submission.\n'
  else
    printf 'Requested unsigned/simulator/launch lanes completed. Production readiness still requires WINS_REQUIRE_APPLE_ENGINE=1 packet-engine enforcement, signed Network Extension distribution profiles/exports, and live VPN validation on every Apple platform before submission.\n'
  fi
fi

if [[ "${WINS_APPLE_LIVE_TUNNEL_SMOKE}" == "1" ]]; then
  print_runtime_candidate_binding macos
fi
if [[ "${WINS_IOS_LIVE_TUNNEL_SMOKE}" == "1" ]]; then
  print_runtime_candidate_binding ios
fi
