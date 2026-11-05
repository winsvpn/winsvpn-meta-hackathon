#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
readonly LINUX_SYSTEM_PYTHON="/usr/bin/python3"
unset -f python3 2>/dev/null || true
python3() {
  "${LINUX_SYSTEM_PYTHON}" -I "$@"
}
readonly -f python3
# The privacy validator and the obfuscation contract import their sibling tools
# by plain name (release_obfuscation_contract, release_secret_scan_policy, ...),
# which needs the script directory on sys.path. Isolated mode (-I) drops it, so
# these two scripts run with the same environment and user-site isolation
# (-E -s) and keep Python's script-directory entry. The directory is the
# producer's own frozen tools/ tree.
python3_tool() {
  "${LINUX_SYSTEM_PYTHON}" -E -s "$@"
}
readonly -f python3_tool

if [[ "${1:-}" == "--verify" ]]; then
  [[ "$#" == 3 ]] || {
    echo "canonical cross-store usage is exactly --verify <target-id> <artifact-path>" >&2
    exit 64
  }
  exec python3 "$ROOT/tools/linux_cross_store_artifact_gate.py" "$@"
fi

APP_VERSION="$(awk '/^version:[[:space:]]*/ {gsub(/\r/,""); split($2, parts, "+"); print parts[1]; exit}' "$ROOT/pubspec.yaml")"
BUILD_NUMBER="$(awk '/^version:[[:space:]]*/ {gsub(/\r/,""); split($2, parts, "+"); print parts[2]; exit}' "$ROOT/pubspec.yaml")"
[[ -n "${APP_VERSION}" && "${BUILD_NUMBER}" =~ ^[0-9]+$ ]] \
  || { echo "Could not read version: <semver>+<build> from pubspec.yaml." >&2; exit 65; }
# Bound after detect_linux_release_arch so x64 and arm64 each keep an
# immutable obfuscation symbol directory and cannot overwrite each other.
LINUX_SYMBOL_DIR=""
LINUX_OBFUSCATION_MANIFEST=""
LINUX_NATIVE_SYMBOL_DIR=""

# Xray is no longer fetched as a prebuilt release archive: it is compiled
# from source by tools/build_xray_engine.sh, which pins the exact upstream
# commit/tag and the reviewed Go toolchain used to build it (see that script
# for the actual supply-chain pins). XRAY_VERSION here is a human-readable
# label for log output only.
XRAY_VERSION="26.9.30"
XRAY_LICENSE_SHA256="1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5"
AWG_TOOLS_VERSION="v3.1.20260812"
AWG_TOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
AWG_TOOLS_ARCHIVE_SHA256="919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56"
AWG_TOOLS_SOURCE_SHA256="dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493"
AWG_BINARY_SHA256="23d29323258166183eeeb288c1f9f08b879f3707e54591b1bfb2402413f6d8d8"
AWG_QUICK_SOURCE_SHA256="f4bb0f5d63665ade87f0cb9f2185c43515cff09868637eb311f98f65a318722c"
AWG_QUICK_SHA256="89dca7788242e542cec249af5d062764fbcb3a6a3ef66999c400d5bbe2f446db"
AWG_TOOLS_COPYING_SHA256="8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643"
AWG_GO_TAG="v3.1.20260828"
AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"
AWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"
AWG_GO_BINARY_SHA256="5e8e2e656d77f9f66102660234fa08d8c2ddb99bf32961db8c02ad19c32e872f"
GO_VERSION="1.27.1"
GO_ARCHIVE_SHA256="63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445"

# linux-arm64 AmneziaWG userspace and host Go pins REUSE trust this project
# already extended -- neither is a new supply-chain decision:
#
# GO_ARCHIVE_SHA256_ARM64 is go.dev's own go${GO_VERSION}.linux-arm64.tar.gz,
# same publisher (go.dev), same already-pinned version (${GO_VERSION}) as
# GO_ARCHIVE_SHA256 above, just the other CPU architecture of the identical
# release. Independently downloaded and hashed this value directly from
# go.dev (not copied from any index), and cross-checked the method by
# re-downloading go${GO_VERSION}.linux-amd64.tar.gz the same way -- it
# reproduces GO_ARCHIVE_SHA256 above exactly.
GO_ARCHIVE_SHA256_ARM64="3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec"
#
# AWG_GO_BINARY_SHA256_ARM64 is different in kind: it is not a third-party
# artifact at all, but the expected output of *this script's own* reproducible
# build of the pinned amneziawg-go v3.1.20260828 source (AWG_GO_COMMIT/
# AWG_GO_SOURCE_SHA256 above) with GOARCH=arm64 instead of amd64. Computed
# by actually running that exact recipe (darwin-arm64-hosted go${GO_VERSION}
# cross-compiling) and confirmed reproducible across two independent builds
# on 2026-08-23. Cross-validated against the amd64 leg of the same recipe,
# which produced AWG_GO_BINARY_SHA256 above byte-for-byte. Linux-host
# rebuilds must reconfirm both output hashes before a signed release.
# Re-derive in under a minute with:
#   curl -fsSL https://go.dev/dl/go${GO_VERSION}.<host-os>-<host-arch>.tar.gz | tar -xz
#   (cd amneziawg-go-src && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
#     SOURCE_DATE_EPOCH=1783563753 <go> build -mod=readonly -trimpath \
#     -buildvcs=false -ldflags='-s -w -buildid=' -o out .)
AWG_GO_BINARY_SHA256_ARM64="9083c92dbd16422cd590df8fcf2ebae2c604b43539bdd58dddaede74efd0642a"
# Deterministic Xray outputs from the pinned v26.9.30 source. The digests
# below were measured on 2026-10-07 with tools/build_xray_engine.sh, the
# reviewed Go 1.27.1 toolchain and the v26.9.30 source; two clean builds per
# target were byte-identical (the Go version is embedded in the binary).
# Release production verifies the exact target output before staging.
XRAY_SHA256_AMD64="09e63d5420f26db2bc6144f6d047601909541acf21792878d3859e4fc4980a12"
XRAY_SHA256_ARM64="868fcabbf9a08d1e453bc6dc82dd8ca27cfcf8cdb2b3a8ff31b824361966964b"
# linux-arm64 awg from the already-pinned amneziawg-tools v3.1.20260812 source
# (tools/build_linux_arm64_awg.sh). Upstream never published an arm64 zip;
# this is a from-source rebuild with Debian 12 clang 14.0.6 / binutils 2.40-2.
# Two isolated clean builds were byte-identical. awg-quick is the same bash
# script already pinned as AWG_QUICK_SHA256.
AWG_BINARY_SHA256_ARM64="bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d"
COSIGN_VERSION="v3.1.3"
COSIGN_PATH="/usr/local/bin/cosign"
LINUX_SIGNING_VERIFIER_SHA256="fc5121b35f32c868edd053cf3e2f5a1d37b6d058bf68419c044df08c701f8272"
# SHA-256 of the release Cosign public key (the exact bytes of
# WINS_LINUX_COSIGN_PUBKEY and of the installer trust anchor
# /etc/winsvpn/release-signing/cosign.pub). This value is owner-supplied: the
# key pair is not in the repository. While it is empty, SIGN_LINUX_RELEASE=1
# is refused with a plain message naming this pin; unsigned rehearsals are
# unaffected.
LINUX_COSIGN_PUBLIC_KEY_SHA256="7b66c6fed0f6cc06e09cde6bc0cf89a6b1d07f3084020ecb8d8adb3b41e88144"
# sha256 of the exact RELEASE_INPUT_INDEX.json bytes, set by
# resolve_linux_release_controls before any build step.
LINUX_RELEASE_INDEX_SHA256=""

# SINGLE SOURCE OF TRUTH: read every toolchain pin from
# tools/toolchain-pins.json at run time instead of a literal. A literal that
# happens to agree today is still a defect -- the next pin bump silently
# desynchronises this producer from every other build. Fail loudly so a
# missing pin file or parser never selects an unreviewed toolchain silently.
read_wins_toolchain_pin() {
  local pin_key="${1:?read_wins_toolchain_pin: missing key}"
  if [[ ! -f "${ROOT}/tools/toolchain-pins.json" ]]; then
    printf 'TOOLCHAIN PIN ERROR: %s does not exist; cannot resolve %s.\n' \
      "${ROOT}/tools/toolchain-pins.json" "${pin_key}" >&2
    exit 65
  fi
  "${LINUX_SYSTEM_PYTHON:-${PYTHON_BIN:-python3}}" -I -S - \
    "${ROOT}/tools/toolchain-pins.json" "${pin_key}" <<'WINS_PIN_EOF'
import json, sys

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate toolchain pin key: {key}")
        result[key] = value
    return result

def reject_nonfinite(value):
    raise SystemExit(f"non-finite toolchain pin number: {value}")

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(
        handle,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonfinite,
    )
expected_top = {
    "_declared_divergences_note", "_not_covered", "_purpose",
    "declared_divergences", "discovery_scan_roots", "pending_convergence",
    "schema_version", "sites", "tools",
}  # Exact reviewed top-level schema.
if not isinstance(value, dict) or set(value) != expected_top:
    raise SystemExit("toolchain pin top-level fields are not exact")
for part in sys.argv[2].split("."):
    value = value[part]
sys.stdout.write(str(value))
WINS_PIN_EOF
}

read_optional_wins_toolchain_pin() {
  local pin_key="${1:?read_optional_wins_toolchain_pin: missing key}"
  "${LINUX_SYSTEM_PYTHON}" -I -S - \
    "${ROOT}/tools/toolchain-pins.json" "${pin_key}" <<'WINS_OPTIONAL_PIN_EOF'
import json, sys

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate toolchain pin key: {key}")
        result[key] = value
    return result

def reject_nonfinite(value):
    raise ValueError(f"non-finite toolchain pin number: {value}")

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        value = json.load(
            handle,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    expected_top = {
        "_declared_divergences_note", "_not_covered", "_purpose",
        "declared_divergences", "discovery_scan_roots", "pending_convergence",
        "schema_version", "sites", "tools",
    }
    if not isinstance(value, dict) or set(value) != expected_top:
        raise ValueError("toolchain pin top-level fields are not exact")
    for part in sys.argv[2].split("."):
        value = value[part]
except (OSError, KeyError, TypeError, ValueError):
    value = ""
sys.stdout.write(str(value) if value is not None else "")
WINS_OPTIONAL_PIN_EOF
}

# A real release check failed (missing pin, wrong digest, unsafe input). The
# message names exactly what is missing or wrong; exit status 65 (data error).
release_refused() {
  printf 'RELEASE REFUSED: %s\n' "$*" >&2
  return 65
}

REQUIRED_FLUTTER_VERSION="$(read_wins_toolchain_pin tools.flutter.version)"
REQUIRED_FLUTTER_REVISION="$(read_wins_toolchain_pin tools.flutter.revision)"
REQUIRED_DART_VERSION="$(read_wins_toolchain_pin tools.flutter.dart_version)"

# Canonical JSON SHA-256 over the exact Dart host and Linux registration input
# records produced by write_native_host_source_closure(). The producer itself
# is covered by the immutable Linux release-input index, so this reviewed pin
# makes any host source, lockfile, registration helper, or manifest dependency
# change invalidate the release before compilation. Updating the host requires
# reviewing the changed input set and updating this pin in the same change.
NATIVE_HOST_SOURCE_CLOSURE_SHA256="e83906b015ce9f430272fb6c99aa0032179e591854a96cc9528c4599343451da"

# ---------------------------------------------------------------------------
# Winn3 descriptor verification key wiring: CLIENT side (PUBLIC material).
#
# The client reads --dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_G1 (WITH WINS_
# prefix) via String.fromEnvironment. The hub reads the SAME value under a
# DIFFERENT name WINN3_DESCRIPTOR_PUBKEY_G1 (NO prefix) via os.getenv. Crossing
# the names is a silent no-op at both ends, so this function handles ONLY the
# client name and rejects a hub-named or dart-define-shaped value.
#
# Convention: PUBLIC key is PASSED AT BUILD TIME, never hardcoded into a
# committed file. The operator obtains the base64 raw-32-byte value from
#   tools/winn3_sign_descriptor.py pubkey --key g1.pem --kid g1
# and exports it as WINS_WINN3_DESCRIPTOR_PUBKEY_G1 (or _G2/_G3) before
# invoking any flutter build, or via WINS_WINN3_DESCRIPTOR_PUBKEY_G1_FILE
# pointing at a file containing that single base64 line. G1 is the primary
# slot; G2/G3 are for rotation.
#
# If none are supplied this build will still succeed but the produced client
# will report descriptor-no-verification-keys-compiled and standalone is
# unavailable. It never accepts a descriptor unverified, so this is
# completeness not safety, but it MUST be visible. The caller logs the ring
# status loudly so a missing key cannot be mistaken for a complete build.
# ---------------------------------------------------------------------------
collect_winn3_descriptor_pubkey_defines() {
  local slot var file_var raw value defines
  defines=()
  for slot in G1 G2 G3; do
    var="WINS_WINN3_DESCRIPTOR_PUBKEY_${slot}"
    file_var="${var}_FILE"
    raw=""
    value=""
    if [[ -n "${!file_var:-}" ]]; then
      if [[ ! -f "${!file_var}" || -L "${!file_var}" ]]; then
        printf 'Winn3 descriptor pubkey file missing or symbolic: %s=%s\n' "${file_var}" "${!file_var}" >&2
        return 65
      fi
      raw="$(tr -d '\r\n' < "${!file_var}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      if [[ "${raw}" == --dart-define=* || "${raw}" == WINS_WINN3_DESCRIPTOR_PUBKEY_* || "${raw}" == WINN3_DESCRIPTOR_PUBKEY_* ]]; then
        printf 'Refusing %s that looks like a dart-define or hub key name (crossed names are a silent no-op): %.60s\n' "${file_var}" "${raw}" >&2
        return 65
      fi
      value="${raw}"
    elif [[ -n "${!var:-}" ]]; then
      raw="${!var}"
      if [[ "${raw}" == --dart-define=* ]]; then
        printf 'Refusing %s that already contains --dart-define (pass just the base64 value)\n' "${var}" >&2
        return 65
      fi
      if [[ "${raw}" == WINN3_DESCRIPTOR_PUBKEY_* ]]; then
        printf 'Refusing %s that looks like a hub key name (hub is WINN3_ without WINS_ prefix): %.60s\n' "${var}" "${raw}" >&2
        return 65
      fi
      value="$(printf '%s' "${raw}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    else
      continue
    fi
    if [[ -z "${value}" ]]; then
      continue
    fi
    if ! printf '%s' "${value}" | python3 -c 'import base64,sys; d=base64.b64decode(sys.stdin.read().strip(),validate=True); assert len(d)==32' 2>/dev/null; then
      printf 'Winn3 descriptor pubkey %s is not valid base64 of 32 bytes (raw Ed25519): %.20s...\n' "${var}" "${value}" >&2
      return 65
    fi
    defines+=("--dart-define=${var}=${value}")
  done
  if [[ "${#defines[@]}" -gt 0 ]]; then
    printf '%s\n' "${defines[@]}"
  fi
}

log_winn3_descriptor_pubkey_status() {
  local count="$1"
  if [[ "${count}" -gt 0 ]]; then
    log "Winn3 descriptor verification ring: PRESENT (${count} slot(s) compiled in; standalone v3 can verify descriptors)"
  else
    printf '[LINUX-BUILD] WARNING: Winn3 descriptor verification ring ABSENT: no WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3 supplied.\n' >&2
    printf '[LINUX-BUILD] WARNING: This build will report descriptor-no-verification-keys-compiled and standalone is unavailable.\n' >&2
    printf '[LINUX-BUILD] WARNING: Set WINS_WINN3_DESCRIPTOR_PUBKEY_G1 to the base64 raw-32-byte pubkey from tools/winn3_sign_descriptor.py pubkey --key <pem> --kid g1 to produce a complete build.\n' >&2
    printf '[LINUX-BUILD] WARNING: The PUBLIC key is safe to pass as --dart-define; never pass a private key.\n' >&2
    printf 'Standalone v3 Linux release requires a descriptor verification key.\n' >&2
    return 65
  fi
}

# ---------------------------------------------------------------------------
# WHERE THE RING COMES FROM when the operator exported nothing.
#
# The collector above has existed since the descriptor work landed and was
# never called by this script: `flutter build linux --release` ran with zero
# --dart-define arguments, so every Linux bundle produced so far compiled an
# EMPTY ring and would reject every descriptor it was handed at run time. The
# collector is the consumer; this is the producer that was missing.
#
# tools/winn3_descriptor_ring_defines.py is the single reviewed source for the
# three public keys plus the expected identity. It recomputes the identity from
# the key bytes through tools/winn3_descriptor_ring_identity.py and emits
# nothing at all when the two disagree, so a drifted key cannot reach a build
# through this path. Its base64 values are checked against ^[A-Za-z0-9+/]{43}=$
# before emission, which is why `eval` of its output is safe here.
#
# OPERATOR ENV WINS. Any explicitly exported slot -- value or _FILE -- returns
# immediately and this function contributes nothing, so a rotation ring or a
# deliberately-wrong test ring is still passed in by hand exactly as before.
# ---------------------------------------------------------------------------
load_reviewed_winn3_descriptor_ring() {
  local slot var file_var reviewed_exports
  for slot in G1 G2 G3; do
    var="WINS_WINN3_DESCRIPTOR_PUBKEY_${slot}"
    file_var="${var}_FILE"
    if [[ -n "${!var:-}" || -n "${!file_var:-}" ]]; then
      log "Winn3 descriptor ring: operator-supplied (${var} present); not loading the reviewed ring"
      return 0
    fi
  done
  reviewed_exports="$(python3 "$ROOT/tools/winn3_descriptor_ring_defines.py" sh)" || {
    printf 'Reviewed Winn3 descriptor ring unavailable: tools/winn3_descriptor_ring_defines.py refused to emit.\n' >&2
    return 65
  }
  [[ -n "${reviewed_exports}" ]] || {
    printf 'Reviewed Winn3 descriptor ring unavailable: the ring tool emitted nothing.\n' >&2
    return 65
  }
  eval "${reviewed_exports}"
  log "Winn3 descriptor ring: loaded the reviewed ring from tools/winn3_descriptor_ring_defines.py"
}

# ---------------------------------------------------------------------------
# Collect the ring into an array of --dart-define arguments, attest it against
# the reviewed identity, and append the identity define the client compares
# itself against at run time (Winn3DescriptorKeyRing.attestsExpectedIdentity).
#
# The identity define is DERIVED from the keys that were actually collected,
# never copied from the environment, so it always describes the ring that got
# compiled rather than the ring somebody intended to compile.
#
# Linux release builds enable the standalone Winn v3 host explicitly. The
# native executor is wired through linux_tunnel_backend.cc, while the build
# define keeps non-release/dev builds fail-closed by default. The descriptor
# ring remains an independent requirement: an enabled client must also carry
# the reviewed keys to distinguish a real descriptor from a forged one.
# ---------------------------------------------------------------------------
WINN3_RING_DEFINES=()
WINN3_RING_SHA256=""
resolve_winn3_descriptor_ring_defines() {
  local collected expected normalized line
  # The expected identity is the committed pin REVIEWED_RING_SHA256 in
  # tools/winn3_descriptor_ring_defines.py. Its `identity` format recomputes
  # the identity from the pinned public keys and refuses to print anything if
  # the two disagree, so a caller value can never choose the release ring.
  expected="$(python3 "$ROOT/tools/winn3_descriptor_ring_defines.py" identity)" || {
    release_refused "tools/winn3_descriptor_ring_defines.py did not verify its pinned REVIEWED_RING_SHA256"
    return $?
  }
  [[ "${expected}" =~ ^[0-9a-f]{64}$ ]] || {
    release_refused "tools/winn3_descriptor_ring_defines.py printed a malformed REVIEWED_RING_SHA256"
    return $?
  }
  if [[ -n "${WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256:-}" && \
        "${WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256}" != "${expected}" ]]; then
    release_refused "WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256=${WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256} differs from the pinned REVIEWED_RING_SHA256=${expected}"
    return $?
  fi
  load_reviewed_winn3_descriptor_ring || return 65
  collected="$(collect_winn3_descriptor_pubkey_defines)" || return 65
  WINN3_RING_DEFINES=()
  if [[ -n "${collected}" ]]; then
    while IFS= read -r line; do
      [[ -n "${line}" ]] && WINN3_RING_DEFINES+=("${line}")
    done <<<"${collected}"
  fi
  log_winn3_descriptor_pubkey_status "${#WINN3_RING_DEFINES[@]}" || return 65
  WINN3_RING_SHA256="$(python3 "$ROOT/tools/winn3_descriptor_ring_identity.py" \
    "${WINN3_RING_DEFINES[@]}")" || return 65
  normalized="$(printf '%s' "${expected}" | tr '[:upper:]' '[:lower:]')"
  if [[ ! "${normalized}" =~ ^[0-9a-f]{64}$ || "${normalized}" != "${WINN3_RING_SHA256}" ]]; then
    printf 'Reviewed Winn3 descriptor ring identity mismatch. Computed=%s Expected=%s\n' \
      "${WINN3_RING_SHA256}" "${expected:-<unset>}" >&2
    return 65
  fi
  WINN3_RING_DEFINES+=("--dart-define=WINS_WINN3_DESCRIPTOR_RING_SHA256=${WINN3_RING_SHA256}")
  log "Winn3 descriptor ring identity attested: ${WINN3_RING_SHA256}"
}

# Write the identity the bundle's AOT bytes were SCANNED for, not the identity
# somebody asked for. tools/build_linux_deb.sh refuses to package a bundle
# without this file and refuses one whose identity is not the reviewed value,
# so a bundle built with a different ring cannot be packaged by accident.
write_winn3_descriptor_ring_attestation() {
  local bundle="$1" identity="$2"
  python3 - "${bundle}/winn3-descriptor-ring-attestation.json" "${identity}" <<'WINS_RING_ATTESTATION_EOF'
import json
import re
import sys

path, identity = sys.argv[1], sys.argv[2].lower()
if not re.fullmatch(r"[0-9a-f]{64}", identity):
    raise SystemExit(f"refusing to attest a malformed ring identity: {identity!r}")
with open(path, "w", encoding="utf-8") as handle:
    json.dump(
        {"schema_version": 1, "identity_sha256": identity, "verified_artifact": "lib/libapp.so"},
        handle,
        sort_keys=True,
    )
    handle.write("\n")
WINS_RING_ATTESTATION_EOF
}

# Dual-auth is a release capability, not a generic Linux CMake build mode. The
# canonical producer owns the only accepted define so a raw Flutter Release
# bundle (which omits winn-datapath and receipts) cannot advertise a host it
# does not ship. Keep this as an argv entry, never an operator environment
# switch: Dart's compilation environment is a mapping and duplicate keys are
# not a supported security contract.
WINN3_DUAL_AUTH_DEFINE_NAME="WINS_WINN3_DUAL_AUTH"
WINN3_DUAL_AUTH_DEFINE_ARG="--dart-define=${WINN3_DUAL_AUTH_DEFINE_NAME}=true"
WINN3_DUAL_AUTH_ATTESTATION_NAME="winn3-dual-auth-release-attestation.json"
WINN3_DUAL_AUTH_RELEASE_DEFINES=("${WINN3_DUAL_AUTH_DEFINE_ARG}")
LINUX_WINN3_ENABLED_PLATFORMS_DEFINE_ARG="--dart-define=WINS_WINN3_ENABLED_PLATFORMS=linux"
# Owner ruling 2026-10-24: the Double VPN ciphertext relay ships on every
# platform. Like the dual-auth define, the producer owns the only accepted
# argv entry; linux/flutter/Winn3DescriptorRing.cmake must not carry a second
# copy, and the same argument is what the compiled capability probe measures.
LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG="--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux"
LINUX_WINN3_RELAY_RELEASE_DEFINES=("${LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG}")

assert_linux_winn3_relay_define_argv() {
  local count=0 arg
  for arg in "$@"; do
    case "${arg}" in
      --dart-define-from-file=*)
        echo "Linux release relay define refuses --dart-define-from-file because hidden duplicate keys cannot be audited." >&2
        return 65
        ;;
      "${LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG}")
        count=$((count + 1))
        ;;
      *WINS_WINN3_RELAY_ENABLED_PLATFORMS*)
        printf 'Linux release relay define must be exactly %s; got %s.\n' \
          "${LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG}" "${arg}" >&2
        return 65
        ;;
    esac
  done
  if [[ "${count}" -ne 1 ]]; then
    printf 'Linux release requires exactly one %s; found %s.\n' \
      "${LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG}" "${count}" >&2
    return 65
  fi
}

assert_linux_winn3_dual_auth_define_argv() {
  local count=0 arg entry
  for arg in "$@"; do
    case "${arg}" in
      --dart-define-from-file=*)
        echo "Linux release dual-auth refuses --dart-define-from-file because hidden duplicate keys cannot be audited." >&2
        return 65
        ;;
      --dart-define=*)
        entry="${arg#--dart-define=}"
        if [[ "${entry}" == "${WINN3_DUAL_AUTH_DEFINE_NAME}=true" ]]; then
          count=$((count + 1))
        elif [[ "${entry}" == "${WINN3_DUAL_AUTH_DEFINE_NAME}" || \
                "${entry}" == "${WINN3_DUAL_AUTH_DEFINE_NAME}="* || \
                "${entry}" == "${WINN3_DUAL_AUTH_DEFINE_NAME}"* ]]; then
          printf 'Linux release dual-auth define must be exactly %s; got %s.\n' \
            "${WINN3_DUAL_AUTH_DEFINE_ARG}" "${arg}" >&2
          return 65
        fi
        ;;
      *"${WINN3_DUAL_AUTH_DEFINE_NAME}"*)
        printf 'Malformed Linux release dual-auth argument: %s\n' "${arg}" >&2
        return 65
        ;;
    esac
  done
  if [[ "${count}" -ne 1 ]]; then
    printf 'Linux release requires exactly one %s; found %s.\n' \
      "${WINN3_DUAL_AUTH_DEFINE_ARG}" "${count}" >&2
    return 65
  fi
}

reject_linux_winn3_dual_auth_environment_override() {
  local var raw
  if [[ -n "${WINS_WINN3_DUAL_AUTH+x}" ]]; then
    echo "WINS_WINN3_DUAL_AUTH is producer-owned for Linux release builds; remove the environment override." >&2
    return 65
  fi
  for var in DART_DEFINES EXTRA_FRONT_END_OPTIONS EXTRA_GEN_SNAPSHOT_OPTIONS; do
    raw="${!var:-}"
    if [[ "${raw}" == *"${WINN3_DUAL_AUTH_DEFINE_NAME}"* || \
          "${raw}" == *"V0lOU19XSU5OM19EVUFMX0FVVEg"* ]]; then
      printf '%s carries a duplicate or conflicting Linux dual-auth define.\n' "${var}" >&2
      return 65
    fi
  done
}

# linux/flutter/winn3_tool_backend.sh appends its CMake-provided blob after
# Flutter's incoming DART_DEFINES. A second dual-auth or relay entry there can
# override the producer-owned argv entry. Reject plaintext, valid encoded, and
# malformed encoded attempts before invoking Flutter.
assert_no_secondary_linux_winn3_dual_auth_injection() {
  python3 - \
    "${ROOT}/linux/flutter/Winn3DescriptorRing.cmake" \
    "${ROOT}/linux/flutter/winn3_tool_backend.sh" <<'WINS_DUAL_AUTH_SOURCE_EOF' || return 65
import base64
import binascii
import pathlib
import re
import sys

names = ("WINS_WINN3_DUAL_AUTH", "WINS_WINN3_RELAY_ENABLED_PLATFORMS")

for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"RELEASE REFUSED: Linux dual-auth injection source is missing or symbolic: {path}")
    source = path.read_text(encoding="ascii")
    active = "\n".join(
        line.split("#", 1)[0]
        for line in source.splitlines()
    )
    for name in names:
        if name in active:
            raise SystemExit(f"RELEASE REFUSED: secondary plaintext {name} injection is forbidden: {path}")
        # Complete base64 groups are a stable prefix even when NAME=VALUE
        # changes the encoding of the final bytes of NAME.
        prefix = base64.b64encode(name.encode("ascii")[:len(name) // 3 * 3]).decode("ascii")
        for token in re.findall(r"[A-Za-z0-9+/=]{24,}", active):
            if token.startswith(prefix):
                try:
                    decoded = base64.b64decode(token, validate=True).decode("ascii")
                except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
                    raise SystemExit(
                        f"RELEASE REFUSED: malformed encoded {name} injection is forbidden: {path}"
                    ) from exc
                if decoded == name or decoded.startswith(name + "="):
                    raise SystemExit(f"RELEASE REFUSED: secondary encoded {name} injection is forbidden: {path}")
WINS_DUAL_AUTH_SOURCE_EOF
}

# Compile and run a probe against the shared Winn core with exactly the defines
# the release build passes. The historical evidence table in
# lib/winn_protocol_dispatch.dart (kWinnHostCapabilities) is not the controlling
# fact for a release: WINS_WINN3_ENABLED_PLATFORMS=linux is, so the probe must
# carry it or it measures a different build than the one that ships. The same
# holds for WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux and the relay capability.
prove_linux_winn3_dual_auth_compiled_capability() {
  local probe="${tmp_dir:?}/linux_dual_auth_compiled_capability_test.dart"
  cat >"${probe}" <<'DART'
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn3_cover_fallback.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

void main() {
  test('Linux release advertises the producer-owned dual-auth capability', () {
    expect(kWinn3DualAuthHostSupported, isTrue);
    final flags = winnClientCapabilities(
      operatingSystem: 'linux',
      spaKeyProvisioned: true,
      descriptorRingCarried: true,
    );
    expect(flags[kWinnClientCapabilityDualAuth], isTrue);
  });

  test('Linux release advertises the producer-owned relay capability', () {
    final flags = winnClientCapabilities(
      operatingSystem: 'linux',
      spaKeyProvisioned: true,
      descriptorRingCarried: true,
    );
    expect(
      winnClientRelayCapabilityFlags(
        operatingSystem: 'linux',
        supportsWinn3: flags['supports_winn3'] == true,
        supportsWinn3Descriptor: flags['supports_winn3_descriptor'] == true,
      ),
      <String, bool>{kWinnClientCapabilityRelay: true},
    );
    expect(winn3RelayBuildEnabledPlatforms(), <String>{'linux'});
  });
}
DART
  run_with_reviewed_flutter_pub_custody "${FLUTTER_COMMAND}" test --no-pub \
    "${LINUX_WINN3_ENABLED_PLATFORMS_DEFINE_ARG}" \
    "${LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG}" \
    "${WINN3_DUAL_AUTH_DEFINE_ARG}" \
    "${probe}" || {
      release_refused "the compiled Linux dual-auth capability probe failed with ${LINUX_WINN3_ENABLED_PLATFORMS_DEFINE_ARG} ${LINUX_WINN3_RELAY_ENABLED_PLATFORMS_DEFINE_ARG} ${WINN3_DUAL_AUTH_DEFINE_ARG}"
      return $?
    }
}

assert_userspace_awg_runtime_pin_ready() {
  python3 -I - \
    "${AWG_QUICK_SHA256}" \
    "${ROOT}/linux/packaging/install.sh" \
    "${ROOT}/linux/runner/linux_tunnel_backend.cc" <<'PY' || return 65
import pathlib, sys

digest = sys.argv[1]
missing = []
for raw in sys.argv[2:]:
    path = pathlib.Path(raw)
    source = path.read_text(encoding="utf-8")
    if digest not in source:
        missing.append(path.as_posix())
if missing:
    raise SystemExit(
        "RELEASE REFUSED: AWG_QUICK_SHA256 is not pinned in the shared Linux installer/runtime "
        "for the userspace-only HeaderProtectionKey awg-quick: " + ", ".join(missing)
    )
PY
}

# Contract v2 (2026-10-09): the v1 runtime_report / runtime_report_sha256 /
# runtime challenge fields are gone with the retired final-AOT runtime probe.
# The attestation binds the define, the compiled capability probe that ran
# with the release defines, the capability source, the release index, the
# producer, and the exact runner, libapp.so and winn-datapath bytes.
write_linux_winn3_dual_auth_attestation() {
  local bundle="$1"
  python3 - "${bundle}" "${ROOT}/tools/build_linux_release.sh" \
    "${WINN3_DUAL_AUTH_ATTESTATION_NAME}" \
    "${ROOT}/lib/winn_protocol_dispatch.dart" "${formal_index_path:?}" <<'WINS_DUAL_AUTH_ATTEST_EOF'
import hashlib
import json
import os
import pathlib
import sys

bundle = pathlib.Path(sys.argv[1])
producer = pathlib.Path(sys.argv[2])
attestation_name = sys.argv[3]
capability_source = pathlib.Path(sys.argv[4])
release_index = pathlib.Path(sys.argv[5])
if bundle.is_symlink() or not bundle.is_dir():
    raise SystemExit("Linux dual-auth bundle is missing or symbolic")
if producer.is_symlink() or not producer.is_file():
    raise SystemExit("Linux dual-auth producer is missing or symbolic")
if capability_source.is_symlink() or not capability_source.is_file():
    raise SystemExit("Linux dual-auth capability source is missing or symbolic")
if release_index.is_symlink() or not release_index.is_file():
    raise SystemExit("Linux dual-auth release index is missing or symbolic")

def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

artifact_paths = ("wins_vpn", "lib/libapp.so", "winn-datapath")
artifacts = {}
for relative in artifact_paths:
    path = bundle / relative
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
        raise SystemExit(f"Linux dual-auth artifact is missing or unsafe: {relative}")
    artifacts[relative] = digest(path)

document = {
    "schema_version": 2,
    "contract": "winsvpn-linux-winn3-dual-auth-release-v2",
    "build_mode": "release",
    "dart_define": {
        "name": "WINS_WINN3_DUAL_AUTH",
        "value": "true",
        "occurrences": 1,
        "source": "flutter-cli",
    },
    "native_gates": ["linux_winn3_host_test", "linux_winn_gate_test"],
    "producer": {
        "path": "tools/build_linux_release.sh",
        "sha256": digest(producer),
    },
    "capability_proof": {
        "contract": "winsvpn-linux-compiled-capability-proof-v3",
        "source_path": "lib/winn_protocol_dispatch.dart",
        "source_sha256": digest(capability_source),
        "release_input_index_sha256": digest(release_index),
        "define": "WINS_WINN3_DUAL_AUTH=true",
        "enabled_platforms_define": "WINS_WINN3_ENABLED_PLATFORMS=linux",
        "relay_enabled_platforms_define": "WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux",
        "compiled_test": "linux_dual_auth_compiled_capability_test",
        "verified_artifact": "lib/libapp.so",
        "verified_artifact_sha256": artifacts["lib/libapp.so"],
    },
    "artifacts": artifacts,
}
path = bundle / attestation_name
temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
with temporary.open("x", encoding="ascii") as handle:
    json.dump(document, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(temporary, 0o644)
os.replace(temporary, path)
WINS_DUAL_AUTH_ATTEST_EOF
}

verify_linux_winn3_dual_auth_bundle_attestation() {
  local bundle="$1"
  python3 - "${bundle}" "${ROOT}/tools/build_linux_release.sh" \
    "${WINN3_DUAL_AUTH_ATTESTATION_NAME}" <<'WINS_DUAL_AUTH_VERIFY_EOF'
import hashlib
import json
import os
import pathlib
import re
import sys

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate Linux dual-auth attestation key: {key}")
        result[key] = value
    return result

def reject_nonfinite(value):
    raise SystemExit(f"non-finite Linux dual-auth attestation number: {value}")

bundle = pathlib.Path(sys.argv[1])
producer = pathlib.Path(sys.argv[2])
attestation = bundle / sys.argv[3]
if bundle.is_symlink() or not bundle.is_dir():
    raise SystemExit("Linux dual-auth bundle is missing or symbolic")
if producer.is_symlink() or not producer.is_file():
    raise SystemExit("Linux dual-auth producer is missing or symbolic")
if attestation.is_symlink() or not attestation.is_file():
    raise SystemExit("Linux release bundle lacks the dual-auth attestation")
if attestation.stat().st_size <= 0 or attestation.stat().st_size > 65536:
    raise SystemExit("Linux dual-auth attestation size is invalid")

document = json.loads(
    attestation.read_text(encoding="ascii"),
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_nonfinite,
)
if set(document) != {
    "schema_version", "contract", "build_mode", "dart_define",
    "native_gates", "producer", "capability_proof", "artifacts",
}:
    raise SystemExit("Linux dual-auth attestation fields are not exact")
if document["schema_version"] != 2 or document["contract"] != "winsvpn-linux-winn3-dual-auth-release-v2":
    raise SystemExit("Linux dual-auth attestation contract is invalid")
if document["build_mode"] != "release":
    raise SystemExit("Linux dual-auth attestation is not release-bound")
if document["dart_define"] != {
    "name": "WINS_WINN3_DUAL_AUTH",
    "value": "true",
    "occurrences": 1,
    "source": "flutter-cli",
}:
    raise SystemExit("Linux dual-auth attestation define is missing, false, duplicated, or malformed")
if document["native_gates"] != ["linux_winn3_host_test", "linux_winn_gate_test"]:
    raise SystemExit("Linux dual-auth native gate binding is invalid")

def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

expected_producer = {
    "path": "tools/build_linux_release.sh",
    "sha256": digest(producer),
}
if document["producer"] != expected_producer:
    raise SystemExit("Linux dual-auth attestation producer binding is stale")
required = {"wins_vpn", "lib/libapp.so", "winn-datapath"}
artifacts = document["artifacts"]
if not isinstance(artifacts, dict) or set(artifacts) != required:
    raise SystemExit("Linux dual-auth attestation artifact set is incomplete")
for relative in sorted(required):
    expected = artifacts[relative]
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise SystemExit(f"Linux dual-auth artifact digest is malformed: {relative}")
    path = bundle / relative
    if path.is_symlink() or not path.is_file() or digest(path) != expected:
        raise SystemExit(f"Linux dual-auth artifact binding failed: {relative}")
proof = document["capability_proof"]
if not isinstance(proof, dict) or set(proof) != {
    "contract", "source_path", "source_sha256", "release_input_index_sha256",
    "define", "enabled_platforms_define", "relay_enabled_platforms_define",
    "compiled_test", "verified_artifact", "verified_artifact_sha256",
}:
    raise SystemExit("Linux dual-auth compiled capability proof fields are not exact")
if proof.get("contract") != "winsvpn-linux-compiled-capability-proof-v3" or proof.get("define") != "WINS_WINN3_DUAL_AUTH=true":
    raise SystemExit("Linux dual-auth compiled capability proof contract is invalid")
if proof.get("enabled_platforms_define") != "WINS_WINN3_ENABLED_PLATFORMS=linux":
    raise SystemExit("Linux dual-auth compiled capability proof is not bound to the Linux enabled-platforms define")
if proof.get("relay_enabled_platforms_define") != "WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux":
    raise SystemExit("Linux dual-auth compiled capability proof is not bound to the Linux relay enabled-platforms define")
if proof.get("compiled_test") != "linux_dual_auth_compiled_capability_test":
    raise SystemExit("Linux dual-auth compiled capability test proof is invalid")
if proof.get("source_path") != "lib/winn_protocol_dispatch.dart" or proof.get("verified_artifact") != "lib/libapp.so":
    raise SystemExit("Linux dual-auth compiled capability proof paths are invalid")
for field in ("source_sha256", "release_input_index_sha256", "verified_artifact_sha256"):
    if not isinstance(proof.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", proof[field]) is None:
        raise SystemExit(f"Linux dual-auth compiled capability proof digest is malformed: {field}")
if proof["verified_artifact_sha256"] != artifacts["lib/libapp.so"]:
    raise SystemExit("Linux dual-auth capability proof is not bound to final libapp.so")
WINS_DUAL_AUTH_VERIFY_EOF
}

verify_linux_winn3_dual_auth_bundle() {
  local bundle="$1"
  assert_no_secondary_linux_winn3_dual_auth_injection || return $?
  verify_linux_winn3_dual_auth_bundle_attestation "${bundle}"
}

verify_linux_winn3_dual_auth_archive_attestation() {
  local archive="$1"
  python3 - "${archive}" "${ROOT}/tools/build_linux_release.sh" \
    "${WINN3_DUAL_AUTH_ATTESTATION_NAME}" <<'WINS_DUAL_AUTH_ARCHIVE_EOF'
import hashlib
import json
import pathlib
import re
import sys
import tarfile

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate Linux archive dual-auth attestation key: {key}")
        result[key] = value
    return result

def reject_nonfinite(value):
    raise SystemExit(f"non-finite Linux archive dual-auth attestation number: {value}")

archive = pathlib.Path(sys.argv[1])
producer = pathlib.Path(sys.argv[2])
attestation_name = sys.argv[3]
required = {"wins_vpn", "lib/libapp.so", "winn-datapath"}
if producer.is_symlink() or not producer.is_file():
    raise SystemExit("Linux archive dual-auth producer is missing or symbolic")

with tarfile.open(archive, "r:gz") as bundle:
    members = {}
    for member in bundle.getmembers():
        normalized = member.name.removeprefix("./")
        if normalized in required or normalized == attestation_name:
            if normalized in members or not member.isfile():
                raise SystemExit(f"Linux dual-auth archive member is duplicate or unsafe: {normalized}")
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise SystemExit(f"Linux dual-auth archive member is unreadable: {normalized}")
            members[normalized] = extracted.read()

if set(members) != required | {attestation_name}:
    raise SystemExit("Linux archive omits dual-auth attestation or bound artifacts")
if len(members[attestation_name]) > 65536:
    raise SystemExit("Linux archive dual-auth attestation is oversized")
document = json.loads(
    members[attestation_name].decode("ascii"),
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_nonfinite,
)
if set(document) != {
    "schema_version", "contract", "build_mode", "dart_define",
    "native_gates", "producer", "capability_proof", "artifacts",
}:
    raise SystemExit("Linux archive dual-auth attestation fields are not exact")
if document.get("schema_version") != 2 or document.get("contract") != "winsvpn-linux-winn3-dual-auth-release-v2":
    raise SystemExit("Linux archive dual-auth attestation contract is invalid")
if document.get("build_mode") != "release" or document.get("dart_define") != {
    "name": "WINS_WINN3_DUAL_AUTH",
    "value": "true",
    "occurrences": 1,
    "source": "flutter-cli",
}:
    raise SystemExit("Linux archive dual-auth activation binding is invalid")
if document.get("native_gates") != ["linux_winn3_host_test", "linux_winn_gate_test"]:
    raise SystemExit("Linux archive dual-auth native gate binding is invalid")
producer_binding = document.get("producer")
if producer_binding != {
    "path": "tools/build_linux_release.sh",
    "sha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
}:
    raise SystemExit("Linux archive dual-auth producer binding is stale")
artifacts = document.get("artifacts")
if not isinstance(artifacts, dict) or set(artifacts) != required:
    raise SystemExit("Linux archive dual-auth artifact set is incomplete")
for relative in sorted(required):
    expected = artifacts[relative]
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise SystemExit(f"Linux archive dual-auth digest is malformed: {relative}")
    if hashlib.sha256(members[relative]).hexdigest() != expected:
        raise SystemExit(f"Linux archive dual-auth artifact binding failed: {relative}")
proof = document.get("capability_proof")
if not isinstance(proof, dict) or set(proof) != {
    "contract", "source_path", "source_sha256", "release_input_index_sha256",
    "define", "enabled_platforms_define", "relay_enabled_platforms_define",
    "compiled_test", "verified_artifact", "verified_artifact_sha256",
}:
    raise SystemExit("Linux archive compiled capability proof fields are not exact")
if proof.get("contract") != "winsvpn-linux-compiled-capability-proof-v3" or proof.get("define") != "WINS_WINN3_DUAL_AUTH=true":
    raise SystemExit("Linux archive compiled capability proof contract is invalid")
if proof.get("enabled_platforms_define") != "WINS_WINN3_ENABLED_PLATFORMS=linux":
    raise SystemExit("Linux archive compiled capability proof is not bound to the Linux enabled-platforms define")
if proof.get("relay_enabled_platforms_define") != "WINS_WINN3_RELAY_ENABLED_PLATFORMS=linux":
    raise SystemExit("Linux archive compiled capability proof is not bound to the Linux relay enabled-platforms define")
if proof.get("compiled_test") != "linux_dual_auth_compiled_capability_test":
    raise SystemExit("Linux archive compiled capability test proof is invalid")
if proof.get("source_path") != "lib/winn_protocol_dispatch.dart" or proof.get("verified_artifact") != "lib/libapp.so":
    raise SystemExit("Linux archive compiled capability proof paths are invalid")
for field in ("source_sha256", "release_input_index_sha256", "verified_artifact_sha256"):
    if not isinstance(proof.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", proof[field]) is None:
        raise SystemExit(f"Linux archive compiled capability proof digest is malformed: {field}")
if proof["verified_artifact_sha256"] != artifacts["lib/libapp.so"]:
    raise SystemExit("Linux archive capability proof is not bound to final libapp.so")
WINS_DUAL_AUTH_ARCHIVE_EOF
}

verify_linux_winn3_dual_auth_archive() {
  local archive="$1"
  assert_no_secondary_linux_winn3_dual_auth_injection || return $?
  verify_linux_winn3_dual_auth_archive_attestation "${archive}"
}

verify_linux_archive_release_manifest() {
  python3 -I - "$1" <<'PY'
import hashlib
import pathlib
import re
import tarfile
import sys

archive = pathlib.Path(sys.argv[1])
manifest_name = "release-manifest.sha256"
payloads = {}
with tarfile.open(archive, "r:gz") as bundle:
    for member in bundle.getmembers():
        normalized = member.name.removeprefix("./")
        if normalized in {"", "."} or member.isdir():
            continue
        path = pathlib.PurePosixPath(normalized)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"Linux archive manifest member path is unsafe: {member.name!r}")
        if not member.isfile() or normalized in payloads:
            raise SystemExit(f"Linux archive manifest member is duplicate or unsafe: {normalized}")
        extracted = bundle.extractfile(member)
        if extracted is None:
            raise SystemExit(f"Linux archive manifest member is unreadable: {normalized}")
        payloads[normalized] = extracted.read()

if manifest_name not in payloads:
    raise SystemExit("Linux archive omits release-manifest.sha256")
try:
    text = payloads.pop(manifest_name).decode("ascii")
except UnicodeDecodeError as exc:
    raise SystemExit("Linux archive release-manifest.sha256 is not ASCII") from exc
records = {}
for line in text.splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00\r\n]+)", line)
    if match is None:
        raise SystemExit("Linux archive release-manifest.sha256 contains a malformed record")
    digest, relative = match.groups()
    path = pathlib.PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or relative == manifest_name:
        raise SystemExit(f"Linux archive release manifest path is unsafe: {relative!r}")
    if relative in records:
        raise SystemExit(f"Linux archive release manifest path is duplicated: {relative}")
    records[relative] = digest
if set(records) != set(payloads):
    missing = sorted(set(payloads) - set(records))
    extra = sorted(set(records) - set(payloads))
    raise SystemExit(
        "Linux archive release manifest is not exhaustive and exact; "
        f"missing={missing} extra={extra}"
    )
for relative, payload in payloads.items():
    if hashlib.sha256(payload).hexdigest() != records[relative]:
        raise SystemExit(f"Linux archive release manifest digest mismatch: {relative}")
print(f"LINUX ARCHIVE RELEASE MANIFEST: PASS ({len(records)} payloads)")
PY
}

tmp_dir=""
bundle_tmp=""
pubkey_tmp=""
package_tmp=""
neutral_host_tmp=""
neutral_linux_tmp=""
publication_stage_dir=""
publication_final_dir=""
staged_archive=""
staged_archive_sha=""
staged_bundle=""
staged_installer_bootstrap=""
staged_private_symbols=""
staged_publication_receipt=""
staged_publication_receipt_bundle=""
LINUX_PRIVATE_PUBLICATION_ROOT="${ROOT}/.artifacts/private-release-generations/linux"
publication_committed=0
publication_uncommitted_identity=""
symbol_rollback_active=0
symbol_rollback_had_previous=0
symbol_rollback_target=""
symbol_rollback_stage=""
symbol_rollback_backup=""
native_host_neutral_source=""
native_host_neutral_source_created=0
build_lock_dir="${ROOT}/.dart_tool/winsvpn-release-build.lock"
build_lock_owner_file="${build_lock_dir}/owner.txt"
build_lock_acquired=0
formal_index_path=""
formal_receipt_dir=""
formal_begin_receipt=""
formal_build_receipt=""
OUT_DIR=""
ARCHIVE=""
ARCHIVE_SHA_PATH=""
BUNDLE_PATH=""
FLUTTER_COMMAND=""
publication_custody_active=0
publication_custody_specs=()
publication_custody_next_fd=20
publication_writer_fd=""
publication_custody_test_preopen_swap=0
publication_custody_test_fail_after_rename=0
# Set by detect_linux_release_arch, called once on the Linux path after the
# OS-agnostic --self-test-* dispatches and before the WSL /mnt wrapper, so both
# x64 and arm64 WSL hosts publish matching archive and symbol names.
LINUX_RELEASE_GOARCH=""
LINUX_RELEASE_ARCH_LABEL=""
LINUX_RELEASE_ELF_MACHINE=""
LINUX_RELEASE_HOST_MACHINE=""

release_build_lock() {
  [[ "${build_lock_acquired}" == "1" ]] || return 0
  rm -f -- "${build_lock_owner_file}"
  rmdir -- "${build_lock_dir}"
  build_lock_acquired=0
}

fsync_linux_directories() {
  python3 -I - "$@" <<'PY'
import os, pathlib, stat, sys
seen = set()
for raw in sys.argv[1:]:
    path = pathlib.Path(raw)
    if os.fspath(path) in seen:
        continue
    seen.add(os.fspath(path))
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SystemExit(f"Linux durability directory is unsafe: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
PY
}

publication_custody_digest() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import hashlib, os, pathlib, stat, sys
fd = int(sys.argv[1])
kind = sys.argv[2]
raw_path = pathlib.Path(sys.argv[3])
if kind == "file":
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            break
        digest.update(block)
        offset += len(block)
    print(digest.hexdigest())
elif kind == "directory":
    opened = os.fstat(fd)
    if not stat.S_ISDIR(opened.st_mode):
        raise SystemExit("publication custody directory descriptor is unavailable")
    digest = hashlib.sha256()
    counters = [0, 0]

    def scan(directory_fd, prefix=""):
        for name in sorted(os.listdir(directory_fd)):
            if not name or "/" in name or name in {".", ".."}:
                raise SystemExit("publication custody directory contains an unsafe member name")
            relative = name if not prefix else f"{prefix}/{name}"
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            counters[0] += 1
            if counters[0] > 100000:
                raise SystemExit("publication custody directory has too many members")
            if stat.S_ISDIR(info.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    child = os.fstat(child_fd)
                    if (child.st_dev, child.st_ino) != (info.st_dev, info.st_ino):
                        raise SystemExit("publication custody directory member changed while opened")
                    digest.update(b"d\0" + relative.encode("utf-8") + b"\0")
                    scan(child_fd, relative)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 512 * 1024 * 1024:
                raise SystemExit("publication custody directory contains an unsafe file")
            child_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                child = os.fstat(child_fd)
                if (child.st_dev, child.st_ino, child.st_size) != (
                    info.st_dev, info.st_ino, info.st_size
                ):
                    raise SystemExit("publication custody file changed while opened")
                counters[1] += child.st_size
                if counters[1] > 4 * 1024 * 1024 * 1024:
                    raise SystemExit("publication custody directory exceeds its aggregate byte bound")
                digest.update(b"f\0" + relative.encode("utf-8") + b"\0")
                digest.update(str(child.st_size).encode("ascii") + b"\0")
                offset = 0
                while offset < child.st_size:
                    block = os.pread(child_fd, min(1024 * 1024, child.st_size - offset), offset)
                    if not block:
                        raise SystemExit("publication custody file truncated while retained")
                    digest.update(block)
                    offset += len(block)
            finally:
                os.close(child_fd)

    scan(fd)
    print(digest.hexdigest())
elif kind == "identity":
    print("0" * 64)
else:
    raise SystemExit("publication custody kind is invalid")
PY
}

hold_linux_publication_path() {
  local path="$1" kind="$2" fd digest quoted_path
  fd="${publication_custody_next_fd}"
  publication_custody_next_fd=$((publication_custody_next_fd + 1))
  [[ "${fd}" -lt 200 ]] || return 65
  printf -v quoted_path '%q' "${path}"
  eval "exec ${fd}<${quoted_path}"
  digest="$(publication_custody_digest "${fd}" "${kind}" "${path}")" || return 65
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || return 65
  publication_custody_specs+=("${fd}|${kind}|${digest}|${path}")
}

open_linux_publication_output_under_custody() {
  local path="$1" fd descriptor quoted_path status
  [[ "${publication_custody_active}" == "1" ]] || {
    echo "Linux publication output creation requires active descriptor custody." >&2
    return 65
  }
  [[ -z "${publication_writer_fd}" ]] || {
    echo "A Linux publication writer is already open." >&2
    return 65
  }
  [[ ! -e "${path}" && ! -L "${path}" ]] || {
    echo "Linux publication output unexpectedly exists before producer custody: ${path}" >&2
    return 65
  }
  set -o noclobber
  publication_writer_fd=19
  printf -v quoted_path '%q' "${path}"
  if eval "exec ${publication_writer_fd}<>${quoted_path}"; then
    :
  else
    status=$?
    publication_writer_fd=""
    set +o noclobber
    return "${status}"
  fi
  set +o noclobber
  if [[ "${publication_custody_test_preopen_swap}" == "1" ]]; then
    publication_custody_test_preopen_swap=0
    mv -- "${path}" "${path}.producer-authentic"
    printf 'hostile pre-custody replacement\n' >"${path}"
  fi

  fd="${publication_custody_next_fd}"
  publication_custody_next_fd=$((publication_custody_next_fd + 1))
  [[ "${fd}" -lt 200 ]] || return 65
  if [[ -e "/proc/$$/fd/${publication_writer_fd}" ]]; then
    descriptor="/proc/$$/fd/${publication_writer_fd}"
  elif [[ -e "/dev/fd/${publication_writer_fd}" ]]; then
    descriptor="/dev/fd/${publication_writer_fd}"
  else
    echo "The retained Linux producer descriptor is unavailable." >&2
    return 65
  fi
  printf -v quoted_path '%q' "${descriptor}"
  eval "exec ${fd}<${quoted_path}"
  if python3 -I - "${publication_writer_fd}" "${fd}" "${path}" <<'PY'
import os, pathlib, stat, sys
writer = os.fstat(int(sys.argv[1]))
reader = os.fstat(int(sys.argv[2]))
path = pathlib.Path(sys.argv[3])
current = path.lstat()
identity = (writer.st_dev, writer.st_ino)
if (
    not stat.S_ISREG(writer.st_mode)
    or writer.st_nlink != 1
    or (reader.st_dev, reader.st_ino) != identity
    or (current.st_dev, current.st_ino) != identity
):
    raise SystemExit("Linux producer output changed before retained custody opened")
PY
  then
    :
  else
    status=$?
    eval "exec ${fd}<&-"
    eval "exec ${publication_writer_fd}>&-"
    publication_writer_fd=""
    return "${status}"
  fi
  publication_custody_specs+=("${fd}|pending-file|-|${path}")
}

finalize_linux_publication_output_under_custody() {
  local path="$1" mode="$2" spec rest kind held_path
  local matched=0
  [[ -n "${publication_writer_fd}" ]] || return 65
  python3 -I - "${publication_writer_fd}" "${mode}" <<'PY'
import os, sys
fd = int(sys.argv[1])
mode = int(sys.argv[2], 8)
os.fsync(fd)
os.fchmod(fd, mode)
PY
  for spec in "${publication_custody_specs[@]}"; do
    rest="${spec#*|}"
    kind="${rest%%|*}"
    rest="${rest#*|}"
    held_path="${rest#*|}"
    if [[ "${held_path}" == "${path}" ]]; then
      [[ "${kind}" == "pending-file" ]] || return 65
      matched=$((matched + 1))
    fi
  done
  [[ "${matched}" == "1" ]] || return 65
  seal_linux_publication_custody_path \
    "${path}" file "${publication_writer_fd}" || return $?
  eval "exec ${publication_writer_fd}>&-"
  publication_writer_fd=""
}

seal_linux_publication_custody_path() {
  local requested="$1" requested_kind="${2:-file}"
  local allowed_writer_fd="${3:-}" spec fd_raw rest kind expected path matched=0 status digest
  local -a refreshed=()
  for spec in "${publication_custody_specs[@]}"; do
    fd_raw="${spec%%|*}"
    rest="${spec#*|}"
    kind="${rest%%|*}"
    rest="${rest#*|}"
    expected="${rest%%|*}"
    path="${rest#*|}"
    if [[ "${path}" != "${requested}" ]]; then
      refreshed+=("${spec}")
      continue
    fi
    if [[ "${kind}" != "${requested_kind}" ]]; then
      [[ "${kind}" == "pending-file" && "${requested_kind}" == "file" ]] || return 65
    fi
    # Sealing = every held object is a single-link regular file or a real
    # directory, none is group/other-writable, and (on Linux) no same-UID
    # process holds a writable descriptor to it. The held-descriptor digest
    # recorded below is re-verified at every custody assertion and immediately
    # before and after the no-replace commit, so a later byte change is
    # refused. This replaces the root-only FS_IMMUTABLE_FL attribute.
    if python3 -I - \
        "${fd_raw}" "${requested_kind}" "${requested}" "${allowed_writer_fd}" \
        "${WINS_LINUX_CUSTODY_PORTABLE_TEST:-0}" <<'PY'
import os
import pathlib
import stat
import sys

fd = int(sys.argv[1])
kind = sys.argv[2]
label = pathlib.Path(sys.argv[3])
allowed_writer_raw = sys.argv[4]
allowed_writer_fd = int(allowed_writer_raw) if allowed_writer_raw else -1
portable_test = sys.argv[5] == "1"
if sys.platform != "linux" and not portable_test:
    raise SystemExit(
        "RELEASE REFUSED: Linux /proc is required to prove there is no writable publication alias"
    )
directory_flags = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
)
file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
opened = []
regular_inodes = set()

def collect(current_fd, current_kind, relative=""):
    info = os.fstat(current_fd)
    if current_kind == "file":
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit(f"Linux publication object is not a single-link regular file: {label}")
        regular_inodes.add((info.st_dev, info.st_ino))
        opened.append((current_fd, info, relative or label.name, False))
        return
    if current_kind != "directory" or not stat.S_ISDIR(info.st_mode):
        raise SystemExit(f"Linux publication custody object has the wrong kind: {label}")
    opened.append((current_fd, info, relative or ".", True))
    for name in sorted(os.listdir(current_fd)):
        if not name or "/" in name or name in {".", ".."}:
            raise SystemExit("Linux publication seal found an unsafe member name")
        child_info = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        child_relative = name if not relative else f"{relative}/{name}"
        if stat.S_ISDIR(child_info.st_mode):
            child_fd = os.open(name, directory_flags, dir_fd=current_fd)
            collect(child_fd, "directory", child_relative)
        elif stat.S_ISREG(child_info.st_mode) and child_info.st_nlink == 1:
            child_fd = os.open(name, file_flags, dir_fd=current_fd)
            collect(child_fd, "file", child_relative)
        else:
            raise SystemExit(
                f"Linux publication seal rejected a symlink, hardlink, or special member: {child_relative}"
            )

def seal(current_fd, info, relative, is_directory):
    after = os.fstat(current_fd)
    if (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino):
        raise SystemExit(f"Linux publication object changed while sealed: {relative}")
    if after.st_mode & 0o022:
        raise SystemExit(f"Linux publication object is group/other-writable: {relative}")
    if not is_directory and after.st_nlink != 1:
        raise SystemExit(f"Linux publication object remained multiply linked: {relative}")

def same_uid(pid):
    try:
        text = pathlib.Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    except (FileNotFoundError, ProcessLookupError):
        return False
    for line in text.splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1]) == os.getuid()
    raise SystemExit(f"could not determine Linux process ownership: {pid}")

def reject_writable_aliases():
    if sys.platform != "linux":
        return
    for process in pathlib.Path("/proc").iterdir():
        if not process.name.isdigit() or not same_uid(process.name):
            continue
        descriptor_root = process / "fd"
        try:
            descriptors = list(descriptor_root.iterdir())
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as exc:
            raise SystemExit(
                f"could not prove absence of same-UID writable aliases for pid {process.name}"
            ) from exc
        for descriptor in descriptors:
            try:
                alias = descriptor.stat()
                if (alias.st_dev, alias.st_ino) not in regular_inodes:
                    continue
                fdinfo = (process / "fdinfo" / descriptor.name).read_text(encoding="ascii")
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            flags_line = next((line for line in fdinfo.splitlines() if line.startswith("flags:")), "")
            if not flags_line:
                raise SystemExit("Linux writable-alias proof lacks descriptor flags")
            flags = int(flags_line.split()[1], 8)
            if flags & os.O_ACCMODE != os.O_RDONLY:
                if (
                    int(descriptor.name) == allowed_writer_fd
                    and int(process.name) in {os.getpid(), os.getppid()}
                ):
                    continue
                raise SystemExit(
                    f"Linux publication object retains a same-UID writable descriptor alias: pid={process.name} fd={descriptor.name}"
                )

try:
    collect(fd, kind)
    for current_fd, info, relative, is_directory in sorted(
        opened, key=lambda item: item[2].count("/"), reverse=True
    ):
        seal(current_fd, info, relative, is_directory)
    reject_writable_aliases()
except OSError as exc:
    raise SystemExit(f"RELEASE REFUSED: Linux publication custody failed for {label}: {exc}") from exc
finally:
    for current_fd, _info, _relative, _is_directory in reversed(opened):
        if current_fd != fd:
            os.close(current_fd)
PY
    then
      :
    else
      status=$?
      return "${status}"
    fi
    digest="$(publication_custody_digest \
      "${fd_raw}" "${requested_kind}" "${requested}")" || return 65
    refreshed+=("${fd_raw}|sealed-${requested_kind}|${digest}|${path}")
    matched=1
  done
  [[ "${matched}" == "1" ]] || {
    echo "Linux publication seal target is outside retained custody: ${requested}" >&2
    return 65
  }
  publication_custody_specs=("${refreshed[@]}")
}

# sha256 of a held file, read with pread through its retained descriptor.
# (macOS /dev/fd/N shares the descriptor offset, so a pathname read through it
# is not a reliable view of the retained bytes there; on Linux this equals a
# read of /proc/$$/fd/N.)
publication_held_file_sha256() {
  local requested="$1" spec fd_raw rest path
  for spec in "${publication_custody_specs[@]}"; do
    fd_raw="${spec%%|*}"
    rest="${spec#*|}"
    rest="${rest#*|}"
    path="${rest#*|}"
    if [[ "${path}" == "${requested}" ]]; then
      publication_custody_digest "${fd_raw}" file "${requested}"
      return $?
    fi
  done
  return 65
}

linux_publication_custody_path_for_read() {
  local requested="$1" spec fd_raw rest kind digest path
  if [[ "${publication_custody_active}" != "1" ]]; then
    printf '%s\n' "${requested}"
    return 0
  fi
  for spec in "${publication_custody_specs[@]}"; do
    fd_raw="${spec%%|*}"
    rest="${spec#*|}"
    kind="${rest%%|*}"
    rest="${rest#*|}"
    digest="${rest%%|*}"
    path="${rest#*|}"
    if [[ "${path}" == "${requested}" ]]; then
      if [[ -e "/proc/$$/fd/${fd_raw}" ]]; then
        printf '/proc/%s/fd/%s\n' "$$" "${fd_raw}"
      elif [[ -e "/dev/fd/${fd_raw}" ]]; then
        printf '/dev/fd/%s\n' "${fd_raw}"
      else
        printf 'Signed Linux publication descriptor is unavailable: %s\n' \
          "${requested}" >&2
        return 65
      fi
      return 0
    fi
  done
  printf 'Signed Linux publication path is outside retained custody: %s\n' \
    "${requested}" >&2
  return 65
}

begin_linux_signed_publication_custody() {
  [[ "${publication_custody_active}" == "0" ]] || return 65
  publication_custody_specs=()
  publication_custody_next_fd=20
  hold_linux_publication_path "${staged_installer_bootstrap}" file
  if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
    hold_linux_publication_path "${ROOT}/tools/linux_release_signing.py" file
    hold_linux_publication_path "${COSIGN_PATH}" file
    hold_linux_publication_path "${WINS_LINUX_COSIGN_KEY:?}" file
    hold_linux_publication_path "${WINS_LINUX_COSIGN_PUBKEY:?}" file
    hold_linux_publication_path "${WINS_LINUX_COSIGN_TRUST_ANCHOR:?}" file
  fi
  hold_linux_publication_path "${publication_stage_dir}" identity
  publication_custody_active=1
}

extend_linux_signed_publication_custody() {
  [[ "${publication_custody_active}" == "1" ]] || return 0
  hold_linux_publication_path "$1" "${2:-file}"
}

assert_linux_signed_publication_custody() {
  [[ "${publication_custody_active}" == "1" ]] || {
    echo "Signed Linux publication descriptor custody was not established." >&2
    return 65
  }
  python3 -I - "${publication_custody_specs[@]}" <<'PY'
import hashlib, os, pathlib, stat, sys

def require_sealed(fd, label):
    info = os.fstat(fd)
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise SystemExit(f"sealed publication object gained a hard link: {label}")
    if info.st_mode & 0o022:
        raise SystemExit(f"sealed publication object is group/other-writable: {label}")

for spec in sys.argv[1:]:
    fd_raw, kind, expected, raw_path = spec.split("|", 3)
    fd = int(fd_raw)
    path = pathlib.Path(raw_path)
    held = os.fstat(fd)
    current = path.lstat()
    if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
        raise SystemExit(f"signed publication pathname changed outside held custody: {path}")
    if kind in {"file", "sealed-file"}:
        if kind == "sealed-file":
            require_sealed(fd, path)
        digest = hashlib.sha256()
        offset = 0
        while True:
            block = os.pread(fd, 1024 * 1024, offset)
            if not block:
                break
            digest.update(block)
            offset += len(block)
    elif kind in {"directory", "sealed-directory"}:
        if not stat.S_ISDIR(held.st_mode):
            raise SystemExit("signed publication directory descriptor is unavailable")
        if kind == "sealed-directory":
            require_sealed(fd, path)
        digest = hashlib.sha256()
        counters = [0, 0]

        def scan(directory_fd, prefix=""):
            for name in sorted(os.listdir(directory_fd)):
                if not name or "/" in name or name in {".", ".."}:
                    raise SystemExit("signed publication custody has an unsafe member name")
                relative = name if not prefix else f"{prefix}/{name}"
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                counters[0] += 1
                if counters[0] > 100000:
                    raise SystemExit("signed publication custody has too many members")
                if stat.S_ISDIR(info.st_mode):
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                    try:
                        child = os.fstat(child_fd)
                        if (child.st_dev, child.st_ino) != (info.st_dev, info.st_ino):
                            raise SystemExit("signed publication directory changed while opened")
                        if kind == "sealed-directory":
                            require_sealed(child_fd, relative)
                        digest.update(b"d\0" + relative.encode("utf-8") + b"\0")
                        scan(child_fd, relative)
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 512 * 1024 * 1024:
                    raise SystemExit("signed publication custody contains an unsafe file")
                child_fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    child = os.fstat(child_fd)
                    if (child.st_dev, child.st_ino, child.st_size) != (
                        info.st_dev, info.st_ino, info.st_size
                    ):
                        raise SystemExit("signed publication file changed while opened")
                    if kind == "sealed-directory":
                        require_sealed(child_fd, relative)
                    counters[1] += child.st_size
                    if counters[1] > 4 * 1024 * 1024 * 1024:
                        raise SystemExit("signed publication custody exceeds its aggregate byte bound")
                    digest.update(b"f\0" + relative.encode("utf-8") + b"\0")
                    digest.update(str(child.st_size).encode("ascii") + b"\0")
                    offset = 0
                    while offset < child.st_size:
                        block = os.pread(child_fd, min(1024 * 1024, child.st_size - offset), offset)
                        if not block:
                            raise SystemExit("signed publication file truncated while retained")
                        digest.update(block)
                        offset += len(block)
                finally:
                    os.close(child_fd)

        scan(fd)
    elif kind == "identity":
        digest = hashlib.sha256()
        digest.update(b"")
        if expected != "0" * 64:
            raise SystemExit("signed publication identity descriptor baseline is invalid")
        continue
    else:
        raise SystemExit("signed publication custody kind is invalid")
    if digest.hexdigest() != expected:
        raise SystemExit(f"signed publication held bytes changed: {path}")
PY
}

rebind_linux_signed_publication_custody_paths() {
  local old_root="$1" new_root="$2" spec fd_raw rest kind digest path
  local -a rebound=()
  for spec in "${publication_custody_specs[@]}"; do
    fd_raw="${spec%%|*}"
    rest="${spec#*|}"
    kind="${rest%%|*}"
    rest="${rest#*|}"
    digest="${rest%%|*}"
    path="${rest#*|}"
    case "${path}" in
      "${old_root}") path="${new_root}" ;;
      "${old_root}"/*) path="${new_root}${path#"${old_root}"}" ;;
    esac
    rebound+=("${fd_raw}|${kind}|${digest}|${path}")
  done
  publication_custody_specs=("${rebound[@]}")
}

close_linux_signed_publication_custody() {
  local spec fd_raw
  if [[ -n "${publication_writer_fd}" ]]; then
    eval "exec ${publication_writer_fd}>&-"
    publication_writer_fd=""
  fi
  [[ "${publication_custody_active}" == "1" ]] || return 0
  for spec in "${publication_custody_specs[@]}"; do
    fd_raw="${spec%%|*}"
    eval "exec ${fd_raw}<&-"
  done
  publication_custody_specs=()
  publication_custody_active=0
  publication_custody_next_fd=20
}

remove_uncommitted_linux_generation() {
  local final_path="$1" expected_identity="$2"
  python3 -I - "${final_path}" "${expected_identity}" \
    "${LINUX_PRIVATE_PUBLICATION_ROOT}" <<'PY'
import os
import pathlib
import stat
import sys

final_path = pathlib.Path(sys.argv[1])
expected_raw = sys.argv[2]
private_root = pathlib.Path(sys.argv[3])
try:
    expected_dev, expected_ino = (int(part) for part in expected_raw.split(":", 1))
except (TypeError, ValueError) as exc:
    raise SystemExit("uncommitted Linux generation identity is malformed") from exc
if not final_path.is_absolute() or final_path.parent.parent != private_root:
    raise SystemExit("refusing to roll back a Linux generation outside the private publication root")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
parent_fd = os.open(final_path.parent, flags | os.O_NOFOLLOW)
generation_fd = -1

def remove_members(directory_fd: int, root_dev: int) -> None:
    for name in sorted(os.listdir(directory_fd)):
        if not name or "/" in name or name in {".", ".."}:
            raise SystemExit("uncommitted Linux generation has an unsafe member name")
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child_fd = os.open(name, flags | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or opened.st_dev != root_dev:
                    raise SystemExit("uncommitted Linux generation directory identity changed")
                remove_members(child_fd, root_dev)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)

try:
    try:
        generation_fd = os.open(final_path.name, flags | os.O_NOFOLLOW, dir_fd=parent_fd)
    except FileNotFoundError:
        raise SystemExit(0)
    generation_info = os.fstat(generation_fd)
    if (generation_info.st_dev, generation_info.st_ino) != (expected_dev, expected_ino):
        raise SystemExit("refusing to remove a substituted uncommitted Linux generation")
    remove_members(generation_fd, generation_info.st_dev)
    os.close(generation_fd)
    generation_fd = -1
    os.rmdir(final_path.name, dir_fd=parent_fd)
    os.fsync(parent_fd)
finally:
    if generation_fd >= 0:
        os.close(generation_fd)
    os.close(parent_fd)
PY
}

rollback_linux_publication() {
  local sync_parent="" backup_parent=""
  [[ "${publication_committed}" == "0" ]] || return 0
  if [[ -n "${publication_uncommitted_identity}" && -n "${publication_final_dir}" ]]; then
    remove_uncommitted_linux_generation \
      "${publication_final_dir}" "${publication_uncommitted_identity}" || return 65
    publication_uncommitted_identity=""
    publication_final_dir=""
  fi
  if [[ "${symbol_rollback_active}" == "1" ]]; then
    [[ -z "${symbol_rollback_target}" ]] || rm -rf -- "${symbol_rollback_target}"
    if [[ "${symbol_rollback_had_previous}" == "1" ]]; then
      [[ -d "${symbol_rollback_backup}" && ! -L "${symbol_rollback_backup}" ]] || {
        echo "Linux private-symbol rollback backup is missing or unsafe." >&2
        return 65
      }
      mv -- "${symbol_rollback_backup}" "${symbol_rollback_target}" || return $?
    fi
    [[ -z "${symbol_rollback_stage}" ]] || rm -rf -- "${symbol_rollback_stage}"
    sync_parent="$(dirname "${symbol_rollback_target}")"
    backup_parent="${sync_parent}"
    [[ -z "${symbol_rollback_backup}" ]] || backup_parent="$(dirname "${symbol_rollback_backup}")"
    fsync_linux_directories "${sync_parent}" "${backup_parent}" || return 65
    symbol_rollback_active=0
    symbol_rollback_had_previous=0
    symbol_rollback_target=""
    symbol_rollback_stage=""
    symbol_rollback_backup=""
  fi
  if [[ -n "${publication_stage_dir}" && -d "${publication_stage_dir}" && ! -L "${publication_stage_dir}" ]]; then
    sync_parent="$(dirname "${publication_stage_dir}")"
    rm -rf -- "${publication_stage_dir}"
    publication_stage_dir=""
    fsync_linux_directories "${sync_parent}" || return 65
  fi
  return 0
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  close_linux_signed_publication_custody || true
  rollback_linux_publication || true
  release_build_lock
  if [[ -n "${neutral_linux_tmp}" ]]; then
    chmod -R u+w -- "${neutral_linux_tmp}" 2>/dev/null || true
    rm -rf -- "${neutral_linux_tmp}"
  fi
  if [[ -n "${neutral_host_tmp}" ]]; then
    chmod -R u+w -- "${neutral_host_tmp}" 2>/dev/null || true
    rm -rf -- "${neutral_host_tmp}"
  fi
  if [[ -n "${tmp_dir}" ]]; then
    # Go's module cache deliberately makes downloaded content read-only. The
    # cache lives only inside this mktemp-owned tree, so restore owner write
    # permission before removing it without weakening any shared cache.
    chmod -R u+w -- "${tmp_dir}" 2>/dev/null || true
    rm -rf -- "${tmp_dir}"
  fi
  if [[ "${native_host_neutral_source_created}" == "1" && -n "${native_host_neutral_source}" ]]; then
    case "${native_host_neutral_source}" in
      /tmp/winsvpn-native-host-source-[0-9a-f][0-9a-f]*)
        chmod -R u+w -- "${native_host_neutral_source}" 2>/dev/null || true
        rm -rf -- "${native_host_neutral_source}"
        native_host_neutral_source_created=0
        ;;
      *)
        echo "Refusing to clean an unexpected native-host source path: ${native_host_neutral_source}" >&2
        ;;
    esac
  fi
  [[ -z "${bundle_tmp}" ]] || rm -f -- "${bundle_tmp}"
  [[ -z "${pubkey_tmp}" ]] || rm -f -- "${pubkey_tmp}"
  [[ -z "${package_tmp}" ]] || rm -rf -- "${package_tmp}"
  [[ -z "${publication_stage_dir}" ]] || rm -rf -- "${publication_stage_dir}"
  exit "${status}"
}
trap cleanup EXIT

log() {
  printf '[LINUX-BUILD] %s\n' "$*"
}

# Host architecture, in the two spellings this codebase already uses: Go and
# the Winn/Xray engine builders name it amd64/arm64 (GOARCH), while release
# filenames and Flutter's own build output directory name it x64/arm64
# (packages/flutter_tools/lib/src/build_info.dart's TargetPlatform.simpleName
# in the Flutter SDK: 'x64' for linux_x64, 'arm64' for linux_arm64). Detected
# from the host's trusted /usr/bin/uname exactly once, so this script produces
# the existing
# wins-vpn-linux-x64.tar.gz, byte-for-byte the same as before this existed,
# on an x64 host, and a wins-vpn-linux-arm64.tar.gz on an arm64 host -- no
# cross-compilation of the Flutter UI is attempted anywhere: Flutter's own
# `flutter build linux` hard-refuses an x64-host-to-arm64-target cross-build
# (packages/flutter_tools/lib/src/commands/build_linux.dart in the Flutter
# SDK: BuildLinuxCommand.runCommand throws "Cross-build from Linux x64 host
# to Linux arm64 target is not currently supported", citing
# https://github.com/flutter/flutter/issues/74929), so this only ever builds
# for the architecture the script is actually running on -- an arm64 release
# needs a genuine linux-arm64 Debian 12 host matching tools/linux_apt_pins.json
# (clang 14.0.6 / binutils 2.40-2). Ubuntu 24.04 is an unrecorded distro and
# would fail the apt pin verifier and the linux-arm64 awg clang identity check.
# Never a Flutter UI cross-build from this or any x64 machine.
detect_linux_release_arch() {
  local host_os host_machine
  [[ -f /usr/bin/uname && -x /usr/bin/uname && ! -L /usr/bin/uname ]] || {
    echo "Cannot establish the Linux host identity: /usr/bin/uname is unavailable or unsafe." >&2
    return 64
  }
  host_os="$(/usr/bin/uname -s)" || {
    echo "Cannot establish the Linux host operating system." >&2
    return 64
  }
  [[ "${host_os}" == "Linux" ]] || {
    echo "This producer must run on Linux; detected ${host_os}." >&2
    return 64
  }
  host_machine="$(/usr/bin/uname -m)" || {
    echo "Cannot establish the Linux host architecture." >&2
    return 64
  }
  LINUX_RELEASE_HOST_MACHINE="${host_machine}"
  case "${host_machine}" in
    x86_64)
      LINUX_RELEASE_GOARCH=amd64
      LINUX_RELEASE_ARCH_LABEL=x64
      LINUX_RELEASE_ELF_MACHINE=62
      ;;
    aarch64|arm64)
      LINUX_RELEASE_GOARCH=arm64
      LINUX_RELEASE_ARCH_LABEL=arm64
      LINUX_RELEASE_ELF_MACHINE=183
      ;;
    *)
      echo "Unsupported Linux host architecture: ${host_machine}" >&2
      return 64
      ;;
  esac
}

# Every Linux Winn producer target is constructed from this identity and must
# still match it immediately before compilation. The child Winn builder also
# supports cross-compilation for other products, so a target string alone is
# not evidence that this release is a native matching-host build.
assert_linux_release_matching_host() {
  local actual_os actual_machine expected_goarch expected_label expected_machine
  [[ -f /usr/bin/uname && -x /usr/bin/uname && ! -L /usr/bin/uname ]] || {
    echo "Cannot verify a matching Linux host: /usr/bin/uname is unavailable or unsafe." >&2
    return 65
  }
  actual_os="$(/usr/bin/uname -s)" || return 65
  actual_machine="$(/usr/bin/uname -m)" || return 65
  [[ "${actual_os}" == "Linux" ]] || {
    echo "Winn Linux producer requires a Linux host; detected ${actual_os}." >&2
    return 65
  }
  case "${actual_machine}" in
    x86_64) expected_goarch=amd64; expected_label=x64; expected_machine=62 ;;
    aarch64|arm64) expected_goarch=arm64; expected_label=arm64; expected_machine=183 ;;
    *)
      echo "Unsupported Linux host architecture: ${actual_machine}" >&2
      return 65
      ;;
  esac
  [[ "${LINUX_RELEASE_HOST_MACHINE:-}" == "${actual_machine}" &&
      "${LINUX_RELEASE_GOARCH:-}" == "${expected_goarch}" &&
      "${LINUX_RELEASE_ARCH_LABEL:-}" == "${expected_label}" &&
      "${LINUX_RELEASE_ELF_MACHINE:-}" == "${expected_machine}" ]] || {
    echo "Linux producer architecture identity changed or is not host-matching." >&2
    return 65
  }
}

bind_linux_obfuscation_paths() {
  local arch_label="${1:-}"
  case "${arch_label}" in
    x64|arm64) ;;
    *)
      echo "Linux obfuscation symbol paths require x64 or arm64, not '${arch_label}'." >&2
      return 65
      ;;
  esac
  LINUX_SYMBOL_DIR="${ROOT}/.artifacts/private-release-symbols/linux/${arch_label}/${APP_VERSION}+${BUILD_NUMBER}"
  LINUX_OBFUSCATION_MANIFEST="${LINUX_SYMBOL_DIR}/manifest.json"
  LINUX_NATIVE_SYMBOL_DIR="${LINUX_SYMBOL_DIR}/native"
}

elf_identity_of() {
  python3 -I - "$1" "${2:-executable}" <<'PY'
import os, pathlib, stat, struct, sys

path = pathlib.Path(sys.argv[1])
role = sys.argv[2]
if role not in {"executable", "shared"}:
    raise SystemExit(1)
before = path.lstat()
if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
    raise SystemExit(1)
fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
try:
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino, opened.st_size) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
    ):
        raise SystemExit(1)
    data = bytearray()
    while len(data) < opened.st_size:
        block = os.read(fd, min(1024 * 1024, opened.st_size - len(data)))
        if not block:
            raise SystemExit(1)
        data.extend(block)
finally:
    os.close(fd)
if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
    raise SystemExit(1)
header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
elf_type, machine, version, entry = header[1], header[2], header[3], header[4]
if machine == 183 and entry % 4 != 0:
    raise SystemExit(1)
phoff, ehsize, phentsize, phnum = header[5], header[8], header[9], header[10]
if version != 1 or ehsize != 64 or phentsize != 56 or phnum == 0 or phnum > 4096:
    raise SystemExit(1)
if phoff < ehsize or phoff + phentsize * phnum > len(data):
    raise SystemExit(1)
executable_load = False
readable_load = False
entry_bound = False
entry_file_offset = None
dynamic_segments = []
interpreter_segments = []
loads = []
for index in range(phnum):
    kind, flags, offset, vaddr, _paddr, filesz, memsz, alignment = struct.unpack_from(
        "<IIQQQQQQ", data, phoff + index * phentsize
    )
    if filesz > memsz or offset > len(data) or filesz > len(data) - offset:
        raise SystemExit(1)
    if alignment not in {0, 1} and alignment & (alignment - 1):
        raise SystemExit(1)
    if kind == 1 and alignment not in {0, 1} and (vaddr - offset) % alignment != 0:
        raise SystemExit(1)
    if kind == 1:
        if memsz == 0:
            raise SystemExit(1)
        loads.append((vaddr, vaddr + memsz, offset, offset + filesz, flags))
        readable_load = readable_load or bool(flags & 4)
        if flags & 1:
            if filesz == 0:
                raise SystemExit(1)
            executable_load = True
            if entry != 0 and vaddr <= entry < vaddr + memsz and entry - vaddr < filesz:
                entry_bound = True
                entry_file_offset = offset + (entry - vaddr)
    elif kind == 2:
        dynamic_segments.append((vaddr, vaddr + memsz, offset, offset + filesz))
    elif kind == 3:
        interpreter_segments.append((vaddr, vaddr + memsz, offset, offset + filesz))
if any(loads[index][0] > loads[index + 1][0] for index in range(len(loads) - 1)):
    raise SystemExit(1)
if elf_type not in {2, 3} or not executable_load or not readable_load:
    raise SystemExit(1)
if len(interpreter_segments) > 1:
    raise SystemExit(1)
for _vstart, _vend, start, end in interpreter_segments:
    payload = bytes(data[start:end])
    if not payload or payload[-1:] != b"\0" or b"\0" in payload[:-1]:
        raise SystemExit(1)

def entry_is_defined() -> bool:
    if entry_file_offset is None:
        return False
    code = bytes(data[entry_file_offset:entry_file_offset + 16])
    if not code or code.startswith(b"\0" * min(4, len(code))):
        return False
    if machine == 62:
        return not (code.startswith(b"\xcc") or code.startswith(b"\xf4") or code.startswith(b"\x0f\x0b"))
    if machine == 183 and len(code) >= 4:
        instruction = int.from_bytes(code[:4], "little")
        return instruction != 0 and instruction & 0xFFE0001F not in {0xD4200000, 0xD4400000}
    return False

def dynamic_needed_count() -> int:
    if not dynamic_segments:
        return 0
    if len(dynamic_segments) != 1:
        raise SystemExit(1)
    _vstart, _vend, start, end = dynamic_segments[0]
    if start >= end or (end - start) % 16:
        raise SystemExit(1)
    needed = 0
    terminated = False
    cursor = start
    while cursor + 16 <= end:
        tag, _value = struct.unpack_from("<QQ", data, cursor)
        cursor += 16
        if tag == 0:
            terminated = True
            break
        if tag == 1:
            needed += 1
    if not terminated:
        raise SystemExit(1)
    return needed

if role == "executable":
    if entry == 0 or not entry_bound or not entry_is_defined():
        raise SystemExit(1)
    if elf_type == 3 and len(dynamic_segments) != 1:
        raise SystemExit(1)
    if interpreter_segments and (len(dynamic_segments) != 1 or dynamic_needed_count() == 0):
        raise SystemExit(1)
    if not interpreter_segments and elf_type == 2 and dynamic_segments:
        raise SystemExit(1)
else:
    if elf_type != 3 or entry != 0 or len(dynamic_segments) != 1 or interpreter_segments:
        raise SystemExit(1)
    dynamic_start, dynamic_end, _file_start, _file_end = dynamic_segments[0]
    if not any(
        load_start <= dynamic_start < dynamic_end <= load_end and flags & 4
        for load_start, load_end, _start, _end, flags in loads
    ):
        raise SystemExit(1)
print(f"{elf_type} {machine} {role}")
PY
}

assert_release_elf_machine() {
  local path="$1" expected_machine="$2" label="$3" role="${4:-executable}" elf_type machine measured_role
  IFS=' ' read -r elf_type machine measured_role < <(elf_identity_of "$path" "$role") || {
    echo "${label} is not a supported little-endian ELF64 executable: ${path}" >&2
    return 65
  }
  [[ "$elf_type" == 2 || "$elf_type" == 3 ]] || {
    echo "${label} has unsupported ELF type ${elf_type}: ${path}" >&2
    return 65
  }
  [[ "$machine" == "$expected_machine" ]] || {
    echo "${label} targets ELF machine ${machine}; release target requires ${expected_machine}." >&2
    return 65
  }
}

# Inspect every packaged ELF64 object, not just the named engines. A filename
# or requested architecture is never architecture evidence: libapp.so, the
# Flutter engine, a nested plugin, or the browser host of the other machine
# would otherwise ship inside a correctly named tarball.
assert_packaged_linux_elf_architecture() {
  local root="$1" expected_machine="$2" candidate magic candidate_type candidate_machine
  local candidate_role _candidate_role
  local -a required_program=(
    wins_vpn
    winsvpn-bypass-bpf
    winn-datapath
    xray
    awg
    amneziawg-go
    tools/native_messaging/host/wins_bridge_host
  )
  local -a required_library=(
    lib/libapp.so
    lib/libflutter_linux_gtk.so
  )
  [[ -d "$root" && ! -L "$root" ]] || {
    echo "Linux package root is missing or unsafe: ${root}" >&2
    return 65
  }
  if [[ -e "$root/winn3-gateway" || -L "$root/winn3-gateway" ]]; then
    echo "refusing to package the server-role winn3-gateway in the client release bundle" >&2
    return 65
  fi
  if find "$root" -type l -print -quit | grep -q .; then
    echo "refusing to package a bundle that contains a symbolic link" >&2
    return 65
  fi
  for candidate in "${required_program[@]}"; do
    [[ -f "$root/$candidate" && ! -L "$root/$candidate" && -x "$root/$candidate" ]] || {
      echo "required target ELF is missing or unsafe: $candidate" >&2
      return 65
    }
    assert_release_elf_machine "$root/$candidate" "$expected_machine" "$candidate" executable || return 65
  done
  [[ -f "$root/awg-quick" && ! -L "$root/awg-quick" && -x "$root/awg-quick" ]] || {
    echo "required architecture-independent runtime is missing or unsafe: awg-quick" >&2
    return 65
  }
  for candidate in "${required_library[@]}"; do
    [[ -f "$root/$candidate" && ! -L "$root/$candidate" ]] || {
      echo "required Flutter/runtime ELF is missing or unsafe: $candidate" >&2
      return 65
    }
    assert_release_elf_machine "$root/$candidate" "$expected_machine" "$candidate" shared || return 65
  done
  [[ -f "$root/winn3-descriptor-ring-attestation.json" && ! -L "$root/winn3-descriptor-ring-attestation.json" ]] || {
    echo "required Winn v3 ring attestation is missing or unsafe" >&2
    return 65
  }
  while IFS= read -r -d '' candidate; do
    magic="$(LC_ALL=C od -An -tx1 -N4 -- "$candidate" | tr -d ' \n')"
    [[ "$magic" == "7f454c46" ]] || continue
    candidate_role=executable
    case "${candidate#$root/}" in
      *.so|*.so.*|lib/*) candidate_role=shared ;;
    esac
    IFS=' ' read -r candidate_type candidate_machine _candidate_role < <(elf_identity_of "$candidate" "$candidate_role") || {
      echo "not a supported little-endian ELF64 file: $candidate" >&2
      return 65
    }
    [[ "$candidate_type" == 2 || "$candidate_type" == 3 ]] || {
      echo "refusing to package unsupported ELF type ${candidate_type}: $candidate" >&2
      return 65
    }
    [[ "$candidate_machine" == "$expected_machine" ]] || {
      echo "refusing mixed-architecture bundle: $candidate targets ELF machine $candidate_machine, expected $expected_machine" >&2
      return 65
    }
  done < <(find "$root" -type f -print0)
}

native_host_source_paths() {
  printf '%s\n' \
    tools/native_messaging/host/pubspec.yaml \
    tools/native_messaging/host/pubspec.lock \
    tools/native_messaging/host/bin/wins_bridge_host.dart \
    lib/browser_bridge_app_ipc.dart \
    lib/browser_bridge_framing.dart \
    lib/browser_bridge_protocol.dart \
    lib/browser_bridge_proxy.dart \
    lib/vpn_config_validation.dart \
    lib/windows_system_executable.dart \
    lib/winn_carrier_profile_keys.dart \
    lib/winn_protocol_dispatch.dart \
    tools/native_messaging/install_native_host.sh \
    tools/native_messaging/native_host_layout.py \
    tools/native_messaging/render_host_manifest.py \
    tools/native_messaging/manifests/store_ids.json \
    extension/tools/jsonc.py \
    extension/manifest/firefox.jsonc
}

assert_native_host_source_links() {
  local name
  for name in \
    browser_bridge_app_ipc.dart \
    browser_bridge_framing.dart \
    browser_bridge_protocol.dart \
    browser_bridge_proxy.dart \
    vpn_config_validation.dart \
    windows_system_executable.dart \
    winn_carrier_profile_keys.dart \
    winn_protocol_dispatch.dart; do
    [[ -L "${ROOT}/tools/native_messaging/host/lib/${name}" ]] || {
      echo "Native-host shared source link is missing: ${name}" >&2
      return 65
    }
    [[ "$(readlink "${ROOT}/tools/native_messaging/host/lib/${name}")" == "../../../../lib/${name}" ]] || {
      echo "Native-host shared source link changed target: ${name}" >&2
      return 65
    }
  done
}

write_native_host_source_closure() {
  local output="$1" actual source_path
  local -a source_paths
  assert_native_host_source_links
  source_paths=()
  while IFS= read -r source_path; do
    source_paths+=("${source_path}")
  done < <(native_host_source_paths | LC_ALL=C sort)
  python3 - "${ROOT}" "${output}" "${source_paths[@]}" <<'PY'
import hashlib
import json
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
output = pathlib.Path(sys.argv[2])
paths = sys.argv[3:]
if paths != sorted(set(paths)):
    raise SystemExit("native-host source closure paths must be unique and sorted")
records = []
for relative in paths:
    path = root / pathlib.PurePosixPath(relative)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
        raise SystemExit(f"native-host source input is not one non-empty regular file: {relative}")
    resolved = path.resolve(strict=True)
    resolved.relative_to(root)
    payload = path.read_bytes()
    after = path.lstat()
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SystemExit(f"native-host source input mutated while hashing: {relative}")
    records.append(
        {
            "path": relative,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
    )
encoded = (json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
output.write_bytes(encoded)
PY
  actual="$(sha256sum "${output}" | awk '{print $1}')"
  [[ "${actual}" == "${NATIVE_HOST_SOURCE_CLOSURE_SHA256}" ]] || {
    release_refused "native-host source closure changed: reviewed=${NATIVE_HOST_SOURCE_CLOSURE_SHA256} current=${actual}; review the 17 closure inputs and update NATIVE_HOST_SOURCE_CLOSURE_SHA256 in the same change"
    return $?
  }
}

# Print "<chrome-id> <edge-id>" from the committed store-id record
# (tools/native_messaging/manifests/store_ids.json through
# native_host_layout.py recorded-id). A missing or malformed id is a plain
# refusal (65) that names the id the owner must record.
resolve_linux_native_host_store_ids() {
  local chrome_id edge_id
  chrome_id="$(python3 "${ROOT}/tools/native_messaging/native_host_layout.py" recorded-id --browser chrome)" || {
    release_refused "no Chrome Web Store extension id is recorded in tools/native_messaging/manifests/store_ids.json (key \"chrome\")"
    return $?
  }
  edge_id="$(python3 "${ROOT}/tools/native_messaging/native_host_layout.py" recorded-id --browser edge)" || {
    release_refused "no Microsoft Edge Add-ons extension id is recorded in tools/native_messaging/manifests/store_ids.json (key \"edge\")"
    return $?
  }
  [[ "${chrome_id}" =~ ^[a-p]{32}$ && "${edge_id}" =~ ^[a-p]{32}$ ]] || {
    release_refused "the recorded Chrome or Edge store-listing id is not 32 characters a-p"
    return $?
  }
  [[ "${chrome_id}" != "${edge_id}" ]] || {
    release_refused "the recorded Chrome and Edge store-listing ids must be distinct"
    return $?
  }
  printf '%s %s\n' "${chrome_id}" "${edge_id}"
}

build_and_stage_linux_native_host() {
  local bundle_dir="$1" scratch_dir="$2"
  local native_tools_dir native_host_output private_debug source_closure
  local dart_command dart_identity delivery_sections debug_sections chrome_id edge_id
  local installed_host_path provenance_output neutral_host_dir name

  native_tools_dir="${bundle_dir}/tools/native_messaging"
  native_host_output="${scratch_dir}/wins_bridge_host"
  private_debug="${LINUX_NATIVE_SYMBOL_DIR}/wins_bridge_host.debug"
  source_closure="${scratch_dir}/native-host-source-closure.json"
  installed_host_path="/usr/lib/wins-vpn/wins_bridge_host"
  provenance_output="${native_tools_dir}/linux-release-provenance.json"
  native_host_neutral_source="/tmp/winsvpn-native-host-source-${NATIVE_HOST_SOURCE_CLOSURE_SHA256}"

  write_native_host_source_closure "${source_closure}"

  dart_command="$(dirname "${FLUTTER_COMMAND}")/cache/dart-sdk/bin/dart"
  [[ -f "${dart_command}" && -x "${dart_command}" && ! -L "${dart_command}" ]] || {
    echo "Reviewed Flutter SDK does not contain one regular Dart compiler: ${dart_command}" >&2
    return 65
  }
  dart_identity="$(run_with_reviewed_flutter_pub_custody "${dart_command}" --version 2>&1)"
  [[ "${dart_identity}" == "Dart SDK version: ${REQUIRED_DART_VERSION} "* ]] || {
    echo "Linux native-host release requires Dart ${REQUIRED_DART_VERSION}; found: ${dart_identity}" >&2
    return 65
  }

  [[ ! -e "${native_host_neutral_source}" && ! -L "${native_host_neutral_source}" ]] || {
    echo "Stable native-host source stage already exists; refusing stale or concurrent input: ${native_host_neutral_source}" >&2
    return 73
  }
  neutral_host_dir="${native_host_neutral_source}/tools/native_messaging/host"
  mkdir -m 0700 -- "${native_host_neutral_source}"
  native_host_neutral_source_created=1
  mkdir -p -- "${neutral_host_dir}/bin" "${neutral_host_dir}/lib" "${native_host_neutral_source}/lib"
  install -m 0644 "${ROOT}/tools/native_messaging/host/pubspec.yaml" "${neutral_host_dir}/pubspec.yaml"
  install -m 0644 "${ROOT}/tools/native_messaging/host/pubspec.lock" "${neutral_host_dir}/pubspec.lock"
  install -m 0644 "${ROOT}/tools/native_messaging/host/bin/wins_bridge_host.dart" \
    "${neutral_host_dir}/bin/wins_bridge_host.dart"
  for name in \
    browser_bridge_app_ipc.dart \
    browser_bridge_framing.dart \
    browser_bridge_protocol.dart \
    browser_bridge_proxy.dart \
    vpn_config_validation.dart \
    windows_system_executable.dart \
    winn_carrier_profile_keys.dart \
    winn_protocol_dispatch.dart; do
    install -m 0644 "${ROOT}/lib/${name}" "${native_host_neutral_source}/lib/${name}"
    ln -s "../../../../lib/${name}" "${neutral_host_dir}/lib/${name}"
  done

  log "Building stripped Dart AOT native-messaging host for Linux ${LINUX_RELEASE_ARCH_LABEL}"
  (
    cd "${neutral_host_dir}"
    run_with_reviewed_flutter_pub_custody \
      "${dart_command}" pub get --offline --enforce-lockfile
    run_with_reviewed_flutter_pub_custody \
      "${dart_command}" compile exe \
      --target-os=linux \
      --target-arch="${LINUX_RELEASE_ARCH_LABEL}" \
      --save-debugging-info="${private_debug}" \
      bin/wins_bridge_host.dart \
      -o "${native_host_output}"
  )
  chmod 0755 -- "${native_host_output}"
  chmod 0600 -- "${private_debug}"
  assert_release_elf_machine \
    "${native_host_output}" \
    "${LINUX_RELEASE_ELF_MACHINE}" \
    "Browser native-messaging host"
  "${native_host_output}" --selftest >/dev/null

  delivery_sections="$(readelf -SW "${native_host_output}")"
  debug_sections="$(readelf -SW "${private_debug}")"
  if grep -Eq '[.]symtab|[.]debug_|[.]zdebug_|[.]gnu_debugdata|[.]gdb_index' <<<"${delivery_sections}"; then
    echo "Linux native-messaging host retains private native symbols or debug sections." >&2
    return 65
  fi
  grep -q '[.]debug_info' <<<"${debug_sections}" || {
    echo "Linux native-messaging host private debug companion lacks .debug_info." >&2
    return 65
  }
  scan_owned_binary_paths "${native_host_output}"

  read -r chrome_id edge_id < <(resolve_linux_native_host_store_ids) || return 65
  [[ -n "${chrome_id}" && -n "${edge_id}" ]] || return 65

  install -D -m 0755 "${native_host_output}" \
    "${native_tools_dir}/host/wins_bridge_host"
  install -m 0755 "${ROOT}/tools/native_messaging/install_native_host.sh" \
    "${native_tools_dir}/install_native_host.sh"
  install -m 0644 "${ROOT}/tools/native_messaging/native_host_layout.py" \
    "${native_tools_dir}/native_host_layout.py"
  install -m 0644 "${ROOT}/tools/native_messaging/render_host_manifest.py" \
    "${native_tools_dir}/render_host_manifest.py"
  install -D -m 0644 "${ROOT}/extension/tools/jsonc.py" \
    "${bundle_dir}/extension/tools/jsonc.py"
  install -D -m 0644 "${ROOT}/extension/manifest/firefox.jsonc" \
    "${bundle_dir}/extension/manifest/firefox.jsonc"

  # The recorded store-id file ships byte for byte: it is one of the closure
  # inputs the cross-store gate compares with the packaged copy, so
  # re-serializing it (compact JSON) made every package fail that comparison.
  # resolve_linux_native_host_store_ids has already validated both ids from it.
  install -D -m 0644 "${ROOT}/tools/native_messaging/manifests/store_ids.json" \
    "${native_tools_dir}/manifests/store_ids.json"
  python3 "${ROOT}/tools/native_messaging/render_host_manifest.py" \
    --browser chrome \
    --extension-id "${chrome_id}" \
    --host-path "${installed_host_path}" \
    --output "${native_tools_dir}/manifests/org.winsvpn.bridge.chrome.json"
  python3 "${ROOT}/tools/native_messaging/render_host_manifest.py" \
    --browser edge \
    --extension-id "${edge_id}" \
    --host-path "${installed_host_path}" \
    --output "${native_tools_dir}/manifests/org.winsvpn.bridge.edge.json"
  python3 "${ROOT}/tools/native_messaging/render_host_manifest.py" \
    --browser firefox \
    --extension-id companion@winsvpn.org \
    --host-path "${installed_host_path}" \
    --output "${native_tools_dir}/manifests/org.winsvpn.bridge.firefox.json"
  chmod 0644 -- "${native_tools_dir}/manifests/"*.json

  python3 - \
    "${bundle_dir}" \
    "${provenance_output}" \
    "${source_closure}" \
    "${private_debug}" \
    "${LINUX_RELEASE_ARCH_LABEL}" \
    "${LINUX_RELEASE_ELF_MACHINE}" \
    "${REQUIRED_DART_VERSION}" \
    "${REQUIRED_FLUTTER_VERSION}" \
    "${REQUIRED_FLUTTER_REVISION}" \
    "${NATIVE_HOST_SOURCE_CLOSURE_SHA256}" \
    "${installed_host_path}" <<'PY'
import hashlib
import json
import pathlib
import stat
import sys

(
    bundle_raw,
    output_raw,
    source_closure_raw,
    private_debug_raw,
    architecture,
    elf_machine_raw,
    dart_version,
    flutter_version,
    flutter_revision,
    source_closure_sha256,
    installed_host_path,
) = sys.argv[1:]

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate native-host source-closure key: {key}")
        result[key] = value
    return result

def reject_nonfinite(value):
    raise SystemExit(f"non-finite native-host source-closure number: {value}")

bundle = pathlib.Path(bundle_raw).resolve(strict=True)
output = pathlib.Path(output_raw)
source_inputs = json.loads(
    pathlib.Path(source_closure_raw).read_text(encoding="ascii"),
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_nonfinite,
)
if not isinstance(source_inputs, list):
    raise SystemExit("native-host source closure must be a JSON array")
for record_value in source_inputs:
    if not isinstance(record_value, dict) or set(record_value) != {"path", "sha256", "bytes"}:
        raise SystemExit("native-host source-closure record fields are not exact")
private_debug = pathlib.Path(private_debug_raw)
asset_paths = (
    "extension/manifest/firefox.jsonc",
    "extension/tools/jsonc.py",
    "tools/native_messaging/host/wins_bridge_host",
    "tools/native_messaging/install_native_host.sh",
    "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
    "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json",
    "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json",
    "tools/native_messaging/manifests/store_ids.json",
    "tools/native_messaging/native_host_layout.py",
    "tools/native_messaging/render_host_manifest.py",
)

def record(relative: str) -> dict[str, object]:
    path = bundle / relative
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
        raise SystemExit(f"unsafe native-host package asset: {relative}")
    payload = path.read_bytes()
    return {
        "path": relative,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "mode": stat.S_IMODE(info.st_mode),
    }

debug_payload = private_debug.read_bytes()
document = {
    "schema_version": 1,
    "kind": "winsvpn.linux.native_messaging_host.provenance.v1",
    "architecture": architecture,
    "elf_machine": int(elf_machine_raw),
    "installed_host_path": installed_host_path,
    "hardening": {
        "compile_mode": "dart-aot-product",
        "tree_shaken": True,
        "debug_info_detached": True,
        "delivery_symbols_stripped": True,
        "host_dart_sources_shipped": False,
    },
    "toolchain": {
        "dart_version": dart_version,
        "flutter_version": flutter_version,
        "flutter_revision": flutter_revision,
        "compile_arguments": [
            "compile",
            "exe",
            "--target-os=linux",
            f"--target-arch={architecture}",
            "--save-debugging-info=<private-custody>/wins_bridge_host.debug",
            "bin/wins_bridge_host.dart",
        ],
    },
    "source_closure_sha256": source_closure_sha256,
    "source_inputs": source_inputs,
    "packaged_assets": [record(relative) for relative in asset_paths],
    "private_debug_info": {
        "sha256": hashlib.sha256(debug_payload).hexdigest(),
        "bytes": len(debug_payload),
        "mode": stat.S_IMODE(private_debug.stat().st_mode),
    },
}
output.write_text(
    json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
    encoding="ascii",
)
PY
  chmod 0644 -- "${provenance_output}"
}

# Originally three MANDATORY release components were pinned or implemented for
# amd64 only. linux-arm64 now has from-source pins for all three: Xray
# (tools/build_xray_engine.sh + XRAY_SHA256_ARM64), amneziawg-go (this script's
# existing Go recipe + AWG_GO_BINARY_SHA256_ARM64), and awg (tools/build_linux_arm64_awg.sh
# + AWG_BINARY_SHA256_ARM64). awg-quick is architecture-independent. A missing
# pin is a release refusal, never a silent omit of the Winn v1 fallback.
assert_mandatory_dependencies_available_for_arch() {
  case "${LINUX_RELEASE_GOARCH}" in
    amd64|arm64) return 0 ;;
    *)
      echo "Unsupported Linux host architecture for a release build: ${LINUX_RELEASE_GOARCH:-unset}" >&2
      return 64
      ;;
  esac
}

# Bind a regular file through O_NOFOLLOW and hash the opened descriptor.
winsvpn_sha256_bind_file() {
  python3 -I - "$1" <<'PY'
import hashlib, os, re, stat, sys
path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
if re.fullmatch(r"/proc/[0-9]+/fd/[0-9]+", path) is not None:
    # A held descriptor (exec {fd}<file) is a magic link by design: open follows
    # it to the held inode, and the inode behind it must be a regular file.
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    before = os.stat(path)
else:
    before = os.lstat(path)
if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
    raise SystemExit(f"{path} must be a regular file")
fd = os.open(path, flags)
try:
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino, info.st_size) != (
        before.st_dev, before.st_ino, before.st_size
    ):
        raise SystemExit(f"{path} changed while opened")
    hasher = hashlib.sha256()
    remaining = info.st_size
    while remaining:
        block = os.read(fd, min(1024 * 1024, remaining))
        if not block:
            raise SystemExit(f"{path} ended before its declared size")
        hasher.update(block)
        remaining -= len(block)
    finished = os.fstat(fd)
    if finished.st_mtime_ns != info.st_mtime_ns:
        raise SystemExit(f"{path} changed while hashed")
    sys.stdout.write(hasher.hexdigest() + "\n")
finally:
    os.close(fd)
PY
}

# Hash-bind a compiled engine, then O_NOFOLLOW install and re-hash the destination.
winsvpn_stage_bound_engine() {
  local src="$1"
  local dest="$2"
  local label="$3"
  local expected="$4"
  local digest installed
  digest="$(winsvpn_sha256_bind_file "${src}")" || return 65
  [[ "${digest}" == "${expected}" ]] || {
    echo "${label} SHA-256 verification failed." >&2
    return 65
  }
  installed="$(winsvpn_install_bound_engine "${src}" "${dest}" "${label}")" || return 65
  [[ "${installed}" == "${digest}" ]] || {
    echo "${label} changed while installed." >&2
    return 65
  }
}

# Copy a regular engine payload through O_NOFOLLOW descriptors and hash both ends.
winsvpn_install_bound_engine() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import hashlib, os, stat, sys
src, dest, label = sys.argv[1], sys.argv[2], sys.argv[3]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
write_flags = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
)

def bind(path: str) -> str:
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SystemExit(f"{label} must be a regular file")
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_size) != (
            before.st_dev, before.st_ino, before.st_size
        ):
            raise SystemExit(f"{label} changed while opened")
        hasher = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                raise SystemExit(f"{label} ended before its declared size")
            hasher.update(block)
            remaining -= len(block)
        finished = os.fstat(fd)
        if finished.st_mtime_ns != info.st_mtime_ns:
            raise SystemExit(f"{label} changed while hashed")
        return hasher.hexdigest()
    finally:
        os.close(fd)

digest = bind(src)
if os.path.exists(dest) or os.path.lexists(dest):
    raise SystemExit(f"{label} destination already exists")
src_fd = os.open(src, flags)
try:
    info = os.fstat(src_fd)
    dest_fd = os.open(dest, write_flags, 0o755)
    try:
        remaining = info.st_size
        while remaining:
            block = os.read(src_fd, min(1024 * 1024, remaining))
            if not block:
                raise SystemExit(f"{label} ended while installing")
            written = os.write(dest_fd, block)
            if written != len(block):
                raise SystemExit(f"{label} install write truncated")
            remaining -= len(block)
        os.fchmod(dest_fd, 0o755)
    finally:
        os.close(dest_fd)
finally:
    os.close(src_fd)
installed = bind(dest)
if installed != digest:
    raise SystemExit(f"{label} changed while installed")
sys.stdout.write(installed + "\n")
PY
}

# Fetch URL onto an exclusive descriptor, hash that fd, and copy a 0400 snapshot.
winsvpn_curl_verified_snapshot() {
  local url="$1"
  local expected="$2"
  local snapshot="$3"
  python3 -I - "$url" "$expected" "$snapshot" <<'PY'
import hashlib, os, stat, subprocess, sys
url, expected, snapshot = sys.argv[1], sys.argv[2], sys.argv[3]
download = snapshot + ".download"
if os.path.exists(download) or os.path.lexists(download):
    raise SystemExit("download path already exists")
if os.path.exists(snapshot) or os.path.lexists(snapshot):
    raise SystemExit("snapshot path already exists")
flags = (
    os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
)
snap_flags = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
)
fd = os.open(download, flags, 0o600)
try:
    subprocess.run(
        [
            "curl",
            "--proto",
            "=https",
            "--tlsv1.2",
            "-fsSL",
            "--retry",
            "4",
            "--retry-all-errors",
            url,
        ],
        stdout=fd,
        stdin=subprocess.DEVNULL,
        check=True,
    )
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise SystemExit("download is not a regular file")
    os.lseek(fd, 0, os.SEEK_SET)
    hasher = hashlib.sha256()
    remaining = info.st_size
    while remaining:
        block = os.read(fd, min(1024 * 1024, remaining))
        if not block:
            raise SystemExit("download ended before its declared size")
        hasher.update(block)
        remaining -= len(block)
    if hasher.hexdigest() != expected:
        raise SystemExit("SHA-256 verification failed")
    os.lseek(fd, 0, os.SEEK_SET)
    snap_fd = os.open(snapshot, snap_flags, 0o400)
    try:
        remaining = info.st_size
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                raise SystemExit("download ended while snapshotting")
            written = os.write(snap_fd, block)
            if written != len(block):
                raise SystemExit("snapshot write truncated")
            remaining -= len(block)
        os.fchmod(snap_fd, 0o400)
    finally:
        os.close(snap_fd)
finally:
    os.close(fd)
    try:
        os.unlink(download)
    except OSError:
        pass
PY
}

# Copy a local regular file onto a 0400 snapshot after O_NOFOLLOW hashing.
winsvpn_snapshot_verified_file() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import hashlib, os, stat, sys
src, expected, snapshot = sys.argv[1], sys.argv[2], sys.argv[3]
if os.path.exists(snapshot) or os.path.lexists(snapshot):
    raise SystemExit("snapshot path already exists")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
snap_flags = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
)
before = os.lstat(src)
if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
    raise SystemExit("source must be a regular file")
fd = os.open(src, flags)
try:
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino, info.st_size) != (
        before.st_dev, before.st_ino, before.st_size
    ):
        raise SystemExit("source changed while opened")
    hasher = hashlib.sha256()
    snap_fd = os.open(snapshot, snap_flags, 0o400)
    try:
        remaining = info.st_size
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                raise SystemExit("source ended before its declared size")
            hasher.update(block)
            written = os.write(snap_fd, block)
            if written != len(block):
                raise SystemExit("snapshot write truncated")
            remaining -= len(block)
        if hasher.hexdigest() != expected:
            raise SystemExit("SHA-256 verification failed")
        os.fchmod(snap_fd, 0o400)
    finally:
        os.close(snap_fd)
    finished = os.fstat(fd)
    if finished.st_mtime_ns != info.st_mtime_ns:
        raise SystemExit("source changed while copied")
finally:
    os.close(fd)
PY
}

winsvpn_write_userspace_only_awg_quick() {
  local source="$1"
  local destination="$2"
  local digest
  [[ "$(winsvpn_sha256_bind_file "${source}")" == "${AWG_QUICK_SOURCE_SHA256}" ]] || {
    echo "Authenticated awg-quick source SHA-256 verification failed." >&2
    return 65
  }
  digest="$(python3 -I - "${source}" "${destination}" \
    "${AWG_GO_BINARY_SHA256}" "${AWG_GO_BINARY_SHA256_ARM64}" <<'PY'
import hashlib, os, pathlib, stat, sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
amd64_sha256 = sys.argv[3]
arm64_sha256 = sys.argv[4]
if destination.exists() or destination.is_symlink():
    raise SystemExit("userspace-only awg-quick destination already exists")
raw = source.read_bytes()
marker = b"# ~~ function override insertion point ~~\n"
override = f'''# Wins VPN release override: HPK requires the exact in-bundle reviewed userspace engine.
add_if() {{
\tlocal implementation="${{SELF%/*}}/amneziawg-go"
\tlocal expected_engine_sha256 actual_engine_sha256
\tcase "$(/usr/bin/uname -m)" in
\t\tx86_64|amd64) expected_engine_sha256="{amd64_sha256}" ;;
\t\taarch64|arm64) expected_engine_sha256="{arm64_sha256}" ;;
\t\t*) die "unsupported architecture for the reviewed AmneziaWG userspace engine" ;;
\tesac
\t[[ -f "$implementation" && ! -L "$implementation" && -x "$implementation" ]] || die "reviewed in-bundle AmneziaWG userspace implementation is unavailable"
\tactual_engine_sha256="$(/usr/bin/sha256sum -- "$implementation")" || die "could not hash the reviewed AmneziaWG userspace implementation"
\tactual_engine_sha256="${{actual_engine_sha256%% *}}"
\t[[ "$actual_engine_sha256" == "$expected_engine_sha256" ]] || die "AmneziaWG userspace implementation is not owner-authorized for this architecture"
\techo "[!] HeaderProtectionKey requires the exact reviewed userspace AmneziaWG engine; kernel fast path is disabled until exact kernel proof is pinned." >&2
\tcmd "$implementation" "$INTERFACE"
}}
'''.encode("ascii")
if raw.count(marker) != 1:
    raise SystemExit("awg-quick userspace override insertion point is missing or duplicated")
payload = raw.replace(marker, override)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
fd = os.open(destination, flags, 0o700)
try:
    view = memoryview(payload)
    while view:
        view = view[os.write(fd, view):]
    os.fsync(fd)
    os.fchmod(fd, 0o755)
finally:
    os.close(fd)
print(hashlib.sha256(payload).hexdigest())
PY
)" || return 65
  [[ "${digest}" == "${AWG_QUICK_SHA256}" ]] || {
    echo "Userspace-only awg-quick transformed SHA-256 verification failed: expected=${AWG_QUICK_SHA256} actual=${digest}." >&2
    return 65
  }
}

# Extract a 0400 snapshot through the same O_NOFOLLOW descriptor; never reopen.
# Tar members are written one by one (directories and regular files only, no
# overwrite, no symlink follow), as linux/packaging/store_engine_bind.py does,
# so extraction does not depend on tarfile.data_filter: Debian 12's
# /usr/bin/python3 (3.11.2) has no PEP 706 filter. Optional trailing
# "<member>=<link target>" arguments name reviewed symbolic-link members that
# are left out; each must be present exactly once with exactly that target,
# and every other link member is still refused.
winsvpn_extract_snapshot() {
  python3 -I - "$@" <<'PY'
import os, stat, sys, tarfile, zipfile
snapshot, dest, kind = sys.argv[1], sys.argv[2], sys.argv[3]
skipped_links = {}
for spec in sys.argv[4:]:
    link_name, separator, link_target = spec.partition("=")
    if not separator or not link_name or not link_target or link_name in skipped_links:
        raise SystemExit(f"reviewed archive link exclusion is malformed: {spec}")
    skipped_links[link_name] = link_target
if skipped_links and kind not in {"tar.gz", "tar.xz"}:
    raise SystemExit("reviewed archive link exclusions apply to tar archives only")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
before = os.lstat(snapshot)
if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
    raise SystemExit("snapshot must be a regular file")
os.makedirs(dest, exist_ok=True)
fd = os.open(snapshot, flags)
try:
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino, info.st_size) != (
        before.st_dev, before.st_ino, before.st_size
    ):
        raise SystemExit("snapshot changed while opened")
    handle = os.fdopen(fd, "rb")
    fd = -1

    def reject_member(name: str, member=None) -> None:
        normalized = name.replace("\\", "/")
        parts = [part for part in normalized.split("/") if part]
        if normalized.startswith("/") or any(part == ".." for part in parts):
            raise SystemExit(f"archive member path is unsafe: {name}")
        if member is not None:
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise SystemExit(f"archive member type is unsafe: {name}")
            if member.linkname:
                raise SystemExit(f"archive link target is not allowed: {name}")
            if not (member.isfile() or member.isdir()) or member.sparse is not None:
                raise SystemExit(f"archive member type is unsafe: {name}")

    def make_private_dir(path: str, name: str) -> None:
        try:
            os.mkdir(path, 0o755)
        except FileExistsError:
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise SystemExit(f"archive extraction target is unsafe: {name}")

    def extract_tar_members(archive, members) -> None:
        # Member mtimes are restored as extractall did: tools compare them
        # (Flutter rebuilds its tool when packages/flutter_tools/pubspec.yaml
        # is newer than pubspec.lock).
        directories = []
        for member in members:
            parts = [part for part in member.name.split("/") if part and part != "."]
            if not parts:
                continue
            parent = dest
            for part in parts[:-1]:
                parent = os.path.join(parent, part)
                make_private_dir(parent, member.name)
            target = os.path.join(parent, parts[-1])
            if member.isdir():
                make_private_dir(target, member.name)
                directories.append((target, member.mtime))
                continue
            source = archive.extractfile(member)
            if source is None:
                raise SystemExit(f"archive member is unreadable: {member.name}")
            file_mode = 0o755 if member.mode & 0o111 else 0o644
            try:
                out = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                    file_mode,
                )
            except OSError as suc:
                raise SystemExit(f"archive extraction target is unsafe: {member.name}") from suc
            written_total = 0
            try:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    written_total += len(block)
                    if written_total > member.size:
                        raise SystemExit(f"archive member size is inconsistent: {member.name}")
                    view = memoryview(block)
                    while view:
                        written = os.write(out, view)
                        if written <= 0:
                            raise SystemExit(f"archive member could not be written: {member.name}")
                        view = view[written:]
                if written_total != member.size:
                    raise SystemExit(f"archive member size is inconsistent: {member.name}")
                os.fchmod(out, file_mode)
            finally:
                os.close(out)
            os.utime(target, (member.mtime, member.mtime), follow_symlinks=False)
        for path, mtime in sorted(directories, reverse=True):
            os.utime(path, (mtime, mtime), follow_symlinks=False)

    try:
        if kind in {"tar.gz", "tar.xz"}:
            mode = "r:gz" if kind == "tar.gz" else "r:xz"
            with tarfile.open(fileobj=handle, mode=mode) as archive:
                members = []
                skipped = set()
                for member in archive.getmembers():
                    if member.name in skipped_links:
                        if (
                            member.name in skipped
                            or not member.issym()
                            or member.linkname != skipped_links[member.name]
                        ):
                            raise SystemExit(
                                f"reviewed archive link exclusion does not match: {member.name}"
                            )
                        skipped.add(member.name)
                        continue
                    reject_member(member.name, member)
                    members.append(member)
                if skipped != set(skipped_links):
                    raise SystemExit("reviewed archive link exclusions are not all present")
                extract_tar_members(archive, members)
        elif kind == "zip":
            with zipfile.ZipFile(handle) as archive:
                for name in archive.namelist():
                    reject_member(name)
                archive.extractall(dest)
        else:
            raise SystemExit(f"unsupported snapshot kind: {kind}")
    except SystemExit:
        raise
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as suc:
        raise SystemExit(f"snapshot extraction failed: {suc}")
    handle.close()
finally:
    if fd >= 0:
        os.close(fd)
PY
}

# Execute a compiler while Linux inotify watches every authenticated source or
# toolchain inode. Hash equality alone cannot catch a rename/substitute/restore
# race. The inotify descriptor is private to this supervisor; MOVE_SELF,
# DELETE_SELF, attribute/write events, and queue overflow all fail closed.
# The tree digest is the same encoding as linux_winn3_source_tree_sha256, which
# is the encoding of every tools/toolchain-pins.json install_tree_sha256 pin and
# of WINS_STORE_GOMODCACHE_TREE_SHA256. Symbolic links, hard links and special
# files in a watched tree are refused. WINS_LINUX_CUSTODY_PORTABLE_TEST=1 only
# lets the self-test exercise the digest/link checks on a non-Linux host (no
# inotify there); a release run never reaches this function off Linux.
#
# Optional leading arguments --flutter-sdk-root=<root> and
# --pub-cache-root=<root> name a custody root as the Flutter SDK or the Pub
# cache. Before the compiler runs, such a root must still equal its full pin.
# During and after the run, only the fixed runtime-state paths those tools
# rewrite on every invocation are ignored (inotify events and the post-run
# comparison); every other byte of the SDK and cache stays under custody:
#   Flutter SDK: the same runtime-mutable set tools/build_android_release_macos.sh
#     skips (.git, bin/cache/lockfile, bin/cache/flutter_version_check.stamp,
#     packages/flutter_tools/.dart_tool and the three gradle state dirs), plus
#     what bin/flutter and the tool rewrite each run in Flutter 3.47.6:
#     bin/cache/engine.stamp (written through engine.stamp.tmp.<pid>),
#     bin/cache/engine.realm (bin/internal/update_engine_version.sh),
#     bin/cache/flutter.version.json and the legacy version file
#     (packages/flutter_tools/lib/src/version.dart ensureVersionFile).
#   Pub cache: active_roots, _temp and log (pub's own bookkeeping).
run_with_linux_tree_custody() {
  local portable_test="${WINS_LINUX_CUSTODY_PORTABLE_TEST:-0}"
  if [[ "$(uname -s)" != "Linux" || ! -d /proc/self/fd ]] && [[ "${portable_test}" != "1" ]]; then
    release_refused "compiler tree custody needs Linux inotify and /proc/self/fd"
    return $?
  fi
  # Literal interpreter: this function is exported into child shells
  # (wins_release_go_run, build_xray_engine.sh) where the readonly python3
  # wrapper function does not exist.
  /usr/bin/python3 -I - "${portable_test}" "$@" <<'PY'
import ctypes
import hashlib
import os
import pathlib
import select
import stat
import subprocess
import sys

portable_test = sys.argv[1] == "1"
arguments = sys.argv[2:]
try:
    separator = arguments.index("--")
except ValueError:
    raise SystemExit("Linux tree custody requires -- before the compiler command")
specs = arguments[:separator]
command = arguments[separator + 1:]
FLUTTER_SDK_RUNTIME_STATE = (
    ".git",
    "bin/cache/lockfile",
    "bin/cache/flutter_version_check.stamp",
    "bin/cache/engine.stamp",
    "bin/cache/engine.realm",
    "bin/cache/flutter.version.json",
    "version",
    "packages/flutter_tools/.dart_tool",
    "packages/flutter_tools/gradle/.gradle",
    "packages/flutter_tools/gradle/build",
    "packages/flutter_tools/gradle/.kotlin",
)
FLUTTER_SDK_TRANSIENT_PREFIX = "bin/cache/engine.stamp.tmp."
# The Flutter tool rewrites these two iOS USB artifact stamps on every pub get,
# also on Linux, with the bytes the reviewed SDK already holds (measured round
# R11a). Only their write events are tolerated; they stay stable members, so
# the post-run stable digest still refuses any change of their bytes, and the
# chained digest binds them for the next run. Delete, move and attribute events
# on them, and writes anywhere else, are still refused.
FLUTTER_SDK_REWRITTEN_STAMPS = (
    "bin/cache/libimobiledevice.stamp",
    "bin/cache/libusbmuxd.stamp",
)
PUB_CACHE_RUNTIME_STATE = ("active_roots", "_temp", "log")
runtime_state = {}
publication_directory_roots = set()
chain_dir = None
while specs and specs[0].startswith("--"):
    option, delimiter, option_root = specs.pop(0).partition("=")
    if option == "--chain-state-dir" and delimiter and chain_dir is None:
        chain_dir = option_root
        continue
    if option == "--publication-directory-root" and delimiter:
        if not option_root.startswith("/") or option_root in publication_directory_roots:
            raise SystemExit("publication directory custody root is malformed or repeated")
        publication_directory_roots.add(option_root)
        continue
    if option not in {"--flutter-sdk-root", "--pub-cache-root"} or not delimiter:
        raise SystemExit(f"Linux tree custody option is unknown: {option}")
    if not option_root.startswith("/") or option_root in runtime_state:
        raise SystemExit("Linux tree custody runtime-state root is malformed or repeated")
    runtime_state[option_root] = option
if set(runtime_state) - {spec.partition("=")[2] for spec in specs}:
    raise SystemExit("Linux tree custody runtime-state root is not an authenticated tree")
if publication_directory_roots - {spec.partition("=")[2] for spec in specs}:
    raise SystemExit("publication directory custody root is not an authenticated tree")
if publication_directory_roots & set(runtime_state):
    raise SystemExit("publication directory custody cannot exclude runtime state")
# Digest chaining (L-E B3). A watched run may legitimately rewrite the runtime
# state of a designated Flutter SDK or Pub cache (the first pub get creates
# packages/flutter_tools/.dart_tool and active_roots), so after each run whose
# stable members are unchanged the full post-run digest is recorded in a
# private chain directory, and the next run expects that digest instead of the
# install pin. The first run of a tree still expects the install pin; any
# change between runs, inside or outside the runtime state, is refused.
if chain_dir is not None:
    if not chain_dir.startswith("/"):
        raise SystemExit("Linux tree custody chain directory must be absolute")
    chain_info = os.lstat(chain_dir)
    if (
        not stat.S_ISDIR(chain_info.st_mode)
        or chain_info.st_uid != os.geteuid()
        or stat.S_IMODE(chain_info.st_mode) != 0o700
    ):
        raise SystemExit("Linux tree custody chain directory must be a private 0700 directory")

def chain_path(root: pathlib.Path) -> pathlib.Path:
    name = hashlib.sha256(os.fsencode(root)).hexdigest()[:32]
    return pathlib.Path(chain_dir) / f"tree-{name}.sha256"

def chained_expectation(root: pathlib.Path, install_pin: str) -> str:
    if chain_dir is None:
        return install_pin
    path = chain_path(root)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return install_pin
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size != 65
    ):
        raise SystemExit(f"Linux tree custody chain record is unsafe: {path}")
    text = path.read_text(encoding="ascii")
    if len(text) != 65 or not text.endswith("\n") or any(c not in "0123456789abcdef" for c in text[:64]):
        raise SystemExit(f"Linux tree custody chain record is malformed: {path}")
    return text[:64]

def record_chain(root: pathlib.Path, digest: str) -> None:
    if chain_dir is None:
        return
    path = chain_path(root)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (digest + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)

def is_runtime_state(root: pathlib.Path, relative: str) -> bool:
    kind = runtime_state.get(os.fspath(root))
    if kind is None:
        return False
    if kind == "--flutter-sdk-root":
        names = FLUTTER_SDK_RUNTIME_STATE
        if relative.startswith(FLUTTER_SDK_TRANSIENT_PREFIX) and "/" not in relative[len(FLUTTER_SDK_TRANSIENT_PREFIX):]:
            return True
    else:
        names = PUB_CACHE_RUNTIME_STATE
    return any(relative == name or relative.startswith(name + "/") for name in names)

use_inotify = sys.platform == "linux" and pathlib.Path("/proc/self/fd").is_dir()
if not use_inotify and not portable_test:
    raise SystemExit("Linux compiler tree custody reached an unsupported runtime")
if not specs or not command:
    raise SystemExit("Linux tree custody requires authenticated trees and a compiler command")

watch_fd = -1
if use_inotify:
    libc = ctypes.CDLL(None, use_errno=True)
    inotify_init1 = libc.inotify_init1
    inotify_add_watch = libc.inotify_add_watch
    inotify_init1.argtypes = [ctypes.c_int]
    inotify_init1.restype = ctypes.c_int
    inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    inotify_add_watch.restype = ctypes.c_int
    watch_fd = inotify_init1(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    if watch_fd < 0:
        raise SystemExit(f"could not initialize Linux inotify custody: {os.strerror(ctypes.get_errno())}")

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_MASK_ADD = 0x20000000
MASK = (
    IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO |
    IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT
)
ANCESTOR_MASK = IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT
# A publication directory is authenticated by names and bytes (its digest), so it
# is watched for every event that can change either, but not for attribute
# changes: private_release_symbol_custody.py verify ends by chmod-ing the symbols
# tree and the directories above it to their private modes, which raises
# IN_ATTRIB even when the mode is already right and changes no name or byte.
PUBLICATION_MASK = MASK & ~IN_ATTRIB
PUBLICATION_ANCESTOR_MASK = ANCESTOR_MASK & ~IN_ATTRIB
watched = {}
watch_paths = {}
root_records = []

def add_watch(path: pathlib.Path, mask: int) -> None:
    if watch_fd < 0:
        return
    key = os.fspath(path)
    previous = watched.get(key, 0)
    missing = mask & ~previous
    if not missing:
        return
    requested = missing | (IN_MASK_ADD if previous else 0)
    result = inotify_add_watch(watch_fd, os.fsencode(path), requested)
    if result < 0:
        raise SystemExit(f"could not watch authenticated compiler input {path}: {os.strerror(ctypes.get_errno())}")
    watched[key] = previous | missing
    watch_paths[result] = pathlib.Path(key)

def publication_directory_digest(root: pathlib.Path, *, install_watches: bool) -> str:
    """The sealed-directory digest of publication custody, taken over `root`.

    This is the exact sorted depth-first encoding of publication_custody_digest
    (a directory record, then a file record with its length, its name and its
    bytes), so a directory handed to a tool by its canonical path can be proved
    equal to the sealed copy that publication custody holds, and watched while the
    tool reads it."""
    root_info = root.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise SystemExit(f"publication directory custody root is unsafe: {root}")
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    digest = hashlib.sha256()
    counters = [0, 0]
    root_fd = os.open(root, directory_flags)
    try:
        opened = os.fstat(root_fd)
        if (opened.st_dev, opened.st_ino) != (root_info.st_dev, root_info.st_ino):
            raise SystemExit("publication directory custody root changed while opened")
        if install_watches:
            add_watch(root, PUBLICATION_MASK)
            for ancestor in root.parents:
                add_watch(ancestor, PUBLICATION_ANCESTOR_MASK)

        def scan(directory_fd: int, prefix: str = "") -> None:
            for name in sorted(os.listdir(directory_fd)):
                if not name or "/" in name or name in {".", ".."}:
                    raise SystemExit("publication directory custody has an unsafe member name")
                relative = name if not prefix else f"{prefix}/{name}"
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                counters[0] += 1
                if counters[0] > 100000:
                    raise SystemExit("publication directory custody has too many members")
                if stat.S_ISDIR(info.st_mode):
                    child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                    try:
                        child = os.fstat(child_fd)
                        if (child.st_dev, child.st_ino) != (info.st_dev, info.st_ino):
                            raise SystemExit("publication directory member changed while opened")
                        if install_watches:
                            add_watch(root / relative, PUBLICATION_MASK)
                        digest.update(b"d\0" + relative.encode("utf-8") + b"\0")
                        scan(child_fd, relative)
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 512 * 1024 * 1024:
                    raise SystemExit("publication directory custody has an unsafe file")
                if install_watches:
                    add_watch(root / relative, PUBLICATION_MASK)
                child_fd = os.open(name, file_flags, dir_fd=directory_fd)
                try:
                    child = os.fstat(child_fd)
                    if (child.st_dev, child.st_ino, child.st_size) != (
                        info.st_dev, info.st_ino, info.st_size,
                    ):
                        raise SystemExit("publication directory file changed while opened")
                    counters[1] += child.st_size
                    if counters[1] > 4 * 1024 * 1024 * 1024:
                        raise SystemExit("publication directory custody exceeds its byte bound")
                    digest.update(b"f\0" + relative.encode("utf-8") + b"\0")
                    digest.update(str(child.st_size).encode("ascii") + b"\0")
                    offset = 0
                    while offset < child.st_size:
                        block = os.pread(child_fd, min(1024 * 1024, child.st_size - offset), offset)
                        if not block:
                            raise SystemExit("publication directory file truncated while retained")
                        digest.update(block)
                        offset += len(block)
                finally:
                    os.close(child_fd)

        scan(root_fd)
        return digest.hexdigest()
    finally:
        os.close(root_fd)

def tree_digest(root: pathlib.Path, *, install_watches: bool, include_runtime_state: bool) -> tuple[str, str]:
    """Return (digest of every member, digest without the runtime state).

    With include_runtime_state=False the runtime-state paths are not examined
    at all (after the run they may hold anything the tool wrote there)."""
    if os.fspath(root) in publication_directory_roots:
        value = publication_directory_digest(root, install_watches=install_watches)
        return value, value
    root_info = root.lstat()
    if stat.S_ISREG(root_info.st_mode):
        # A single authenticated file (a staged release archive handed to a named
        # tool): its bytes are the digest, the file itself is watched, and any
        # replacement of the pathname is refused.
        def file_identity(info):
            return (
                info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            )
        if root_info.st_nlink != 1:
            raise SystemExit(f"authenticated file has a hard-link alias: {root}")
        if install_watches:
            add_watch(root, MASK)
            for ancestor in root.parents:
                add_watch(ancestor, ANCESTOR_MASK)
        file_fd = os.open(root, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
        try:
            if file_identity(os.fstat(file_fd)) != file_identity(root_info):
                raise SystemExit(f"authenticated file changed while opened: {root}")
            file_digest = hashlib.sha256()
            offset = 0
            while offset < root_info.st_size:
                block = os.pread(file_fd, min(1024 * 1024, root_info.st_size - offset), offset)
                if not block:
                    raise SystemExit(f"authenticated file was truncated: {root}")
                file_digest.update(block)
                offset += len(block)
            if (
                file_identity(os.fstat(file_fd)) != file_identity(root_info)
                or file_identity(root.lstat()) != file_identity(root_info)
            ):
                raise SystemExit(f"authenticated file changed while read: {root}")
            return file_digest.hexdigest(), file_digest.hexdigest()
        finally:
            os.close(file_fd)
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise SystemExit(f"authenticated compiler tree is missing or unsafe: {root}")
    if install_watches:
        add_watch(root, MASK)
        for ancestor in root.parents:
            add_watch(ancestor, ANCESTOR_MASK)
    members = []
    stable_members = []
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        runtime = is_runtime_state(root, relative)
        if runtime and not include_runtime_state:
            continue
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            raise SystemExit(f"authenticated compiler tree contains a symbolic link: {relative}")
        if stat.S_ISDIR(before.st_mode):
            if install_watches and not runtime:
                add_watch(path, MASK)
            continue
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SystemExit(f"authenticated compiler tree contains a hard link or special member: {relative}")
        if install_watches and not runtime:
            add_watch(path, MASK)
        if len(members) >= 500000:
            raise SystemExit("authenticated compiler tree exceeds the member bound")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
                raise SystemExit(f"authenticated compiler file changed while opened: {relative}")
            total_bytes += opened.st_size
            if total_bytes > 32 * 1024 * 1024 * 1024:
                raise SystemExit("authenticated compiler trees exceed the byte bound")
            file_digest = hashlib.sha256()
            offset = 0
            while offset < opened.st_size:
                block = os.pread(fd, min(1024 * 1024, opened.st_size - offset), offset)
                if not block:
                    raise SystemExit(f"authenticated compiler file truncated: {relative}")
                file_digest.update(block)
                offset += len(block)
        finally:
            os.close(fd)
        # Same member record as linux_winn3_source_tree_sha256.
        record = f"file {opened.st_size} {file_digest.hexdigest()} {relative}\n"
        members.append(record)
        if not runtime:
            stable_members.append(record)
    members.sort()
    stable_members.sort()
    return (
        hashlib.sha256("".join(members).encode("utf-8")).hexdigest(),
        hashlib.sha256("".join(stable_members).encode("utf-8")).hexdigest(),
    )

STAMP_WRITE_MASK = IN_MODIFY | IN_CLOSE_WRITE

def event_is_tolerated_stamp_write(wd: int, name: bytes, mask: int) -> bool:
    if mask & MASK & ~STAMP_WRITE_MASK:
        return False
    watched_path = watch_paths.get(wd)
    if watched_path is None:
        return False
    target = watched_path / os.fsdecode(name) if name else watched_path
    for root, _before, _expected, _stable in root_records:
        if runtime_state.get(os.fspath(root)) != "--flutter-sdk-root":
            continue
        try:
            relative = target.relative_to(root).as_posix()
        except ValueError:
            continue
        return relative in FLUTTER_SDK_REWRITTEN_STAMPS
    return False

def event_is_child_attribute_of_ancestor(wd: int, name: bytes, mask: int) -> bool:
    # An ancestor of a custody root is watched only for changes to the ancestor
    # itself (ANCESTOR_MASK). Linux also raises IN_ATTRIB on a watched directory
    # for every child entry whose attributes change: a chmod of a temporary
    # directory a test created, or of a compiler's output file. Those events
    # carry the child's name and say nothing about the authenticated tree; the
    # next path component toward a root has its own watch and reports its own
    # attribute changes without a name.
    if not name or mask & MASK & ~IN_ATTRIB:
        return False
    watched_path = watch_paths.get(wd)
    return watched_path is not None and watched.get(os.fspath(watched_path)) == ANCESTOR_MASK

def event_is_runtime_state(wd: int, name: bytes) -> bool:
    watched_path = watch_paths.get(wd)
    if watched_path is None:
        return False
    target = watched_path / os.fsdecode(name) if name else watched_path
    for root, _before, _expected, _stable in root_records:
        if target == root:
            return False
        try:
            relative = target.relative_to(root).as_posix()
        except ValueError:
            continue
        return is_runtime_state(root, relative)
    return False

try:
    for spec in specs:
        expected, delimiter, raw_path = spec.partition("=")
        if not delimiter or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise SystemExit("Linux tree custody specification is malformed")
        root = pathlib.Path(raw_path)
        if not root.is_absolute():
            raise SystemExit("Linux tree custody root must be absolute")
        before = root.lstat()
        actual, stable = tree_digest(root, install_watches=True, include_runtime_state=True)
        if actual != chained_expectation(root, expected):
            raise SystemExit(f"authenticated compiler tree digest mismatch: {root}")
        root_records.append((root, before, expected, stable))
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, check=False, close_fds=True)
    events = bytearray()
    if watch_fd >= 0:
        poller = select.poll()
        poller.register(watch_fd, select.POLLIN)
        while poller.poll(0):
            block = os.read(watch_fd, 1024 * 1024)
            if not block:
                break
            events.extend(block)
    offset = 0
    while offset + 16 <= len(events):
        wd = int.from_bytes(events[offset:offset + 4], sys.byteorder, signed=True)
        mask = int.from_bytes(events[offset + 4:offset + 8], sys.byteorder)
        name_len = int.from_bytes(events[offset + 12:offset + 16], sys.byteorder)
        name = bytes(events[offset + 16:offset + 16 + name_len]).split(b"\0", 1)[0]
        offset += 16 + name_len
        if mask & (IN_Q_OVERFLOW | IN_IGNORED):
            raise SystemExit("authenticated compiler tree changed while the compiler was running")
        if (
            mask & MASK
            and not event_is_runtime_state(wd, name)
            and not event_is_tolerated_stamp_write(wd, name, mask)
            and not event_is_child_attribute_of_ancestor(wd, name, mask)
        ):
            raise SystemExit("authenticated compiler tree changed while the compiler was running")
    for root, before, expected, stable in root_records:
        after = root.lstat()
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise SystemExit(f"authenticated compiler tree pathname was replaced: {root}")
        if stat.S_ISREG(before.st_mode) and (
            after.st_mode, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
        ) != (
            before.st_mode, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns,
        ):
            raise SystemExit(f"authenticated file changed during execution: {root}")
        if tree_digest(root, install_watches=False, include_runtime_state=False)[1] != stable:
            raise SystemExit(f"authenticated compiler tree changed after compiler execution: {root}")
    for root, _before, _expected, _stable in root_records:
        if os.fspath(root) in runtime_state:
            record_chain(root, tree_digest(root, install_watches=False, include_runtime_state=True)[0])
    raise SystemExit(completed.returncode)
finally:
    if watch_fd >= 0:
        os.close(watch_fd)
PY
}

run_with_reviewed_flutter_pub_custody() {
  local -a chain=()
  if [[ -n "${WINS_LINUX_TREE_CUSTODY_CHAIN_DIR:-}" ]]; then
    chain=("--chain-state-dir=${WINS_LINUX_TREE_CUSTODY_CHAIN_DIR}")
  fi
  run_with_linux_tree_custody ${chain[@]+"${chain[@]}"} \
    "--flutter-sdk-root=${WINS_LINUX_FLUTTER_TREE_ROOT:?}" \
    "--pub-cache-root=${PUB_CACHE:?}" \
    "${WINS_LINUX_FLUTTER_TREE_SHA256:?}=${WINS_LINUX_FLUTTER_TREE_ROOT:?}" \
    "${WINS_LINUX_PUB_CACHE_TREE_SHA256:?}=${PUB_CACHE:?}" -- "$@"
}

prepare_linux_reviewed_go_for_engines() {
  local go_bin="" go_root archive_name expected_archive go_snapshot archive_path measured_go
  local expected_go_binary expected_go_tree measured_go_tree platform_key
  if declare -F wins_release_go_run >/dev/null 2>&1 || \
     [[ -n "${LINUX_REVIEWED_GO_BIN:-}" || -n "${WINS_RELEASE_GO_SHA256:-}" || \
        -n "${WINS_RELEASE_GO_TREE_SHA256:-}" || -n "${WINS_RELEASE_GO:-}" || \
        -n "${GOROOT+x}" || -n "${GOPATH+x}" || -n "${GOBIN+x}" ]]; then
    echo "Inherited Go custody is forbidden; the Linux producer constructs one authenticated Go environment." >&2
    return 65
  fi
  case "${LINUX_RELEASE_GOARCH}" in
    amd64)
      archive_name="go${GO_VERSION}.linux-amd64.tar.gz"
      expected_archive="${GO_ARCHIVE_SHA256}"
      ;;
    arm64)
      archive_name="go${GO_VERSION}.linux-arm64.tar.gz"
      expected_archive="${GO_ARCHIVE_SHA256_ARM64}"
      ;;
    *)
      echo "No pinned Go SDK archive for Linux ${LINUX_RELEASE_GOARCH}." >&2
      return 65
      ;;
  esac

  if [[ -n "${WINS_ENGINE_SOURCE_ROOT:-}" ]]; then
    [[ -d "${WINS_ENGINE_SOURCE_ROOT}" && ! -L "${WINS_ENGINE_SOURCE_ROOT}" ]] || {
      echo "store engine staging requires declared local source artifacts" >&2
      return 65
    }
    archive_path="${WINS_ENGINE_SOURCE_ROOT}/go-sdk/${archive_name}"
    [[ -f "${archive_path}" && ! -L "${archive_path}" ]] || {
      echo "declared Go SDK archive is missing under ${WINS_ENGINE_SOURCE_ROOT}/go-sdk" >&2
      return 65
    }
    go_snapshot="$tmp_dir/${archive_name}.snap"
    winsvpn_snapshot_verified_file "${archive_path}" "${expected_archive}" "${go_snapshot}" || return 65
  else
    go_snapshot="$tmp_dir/${archive_name}.snap"
    winsvpn_curl_verified_snapshot \
      "https://go.dev/dl/${archive_name}" "${expected_archive}" "${go_snapshot}" || return 65
  fi
  # linux/packaging/store_engine_bind.py already extracted the same archive into
  # "$tmp_dir/go-sdk" in store mode, and the extractor refuses an existing file.
  mkdir -p "$tmp_dir/go-sdk-reviewed"
  winsvpn_extract_snapshot "${go_snapshot}" "$tmp_dir/go-sdk-reviewed" tar.gz || return 65
  go_root="$tmp_dir/go-sdk-reviewed/go"
  go_bin="$go_root/bin/go"
  [[ -x "${go_bin}" && ! -L "${go_bin}" ]] || {
    echo "Pinned Go SDK archive did not produce an executable go binary." >&2
    return 65
  }
  measured_go="$(winsvpn_sha256_bind_file "${go_bin}")" || return 65
  platform_key="linux_${LINUX_RELEASE_GOARCH}"
  expected_go_binary="$(read_optional_wins_toolchain_pin "tools.go.executable_sha256_by_platform.${platform_key}")"
  expected_go_tree="$(read_optional_wins_toolchain_pin "tools.linux.go.install_tree_sha256.${platform_key}")"
  [[ "${expected_go_binary}" =~ ^[0-9a-f]{64}$ && "${measured_go}" == "${expected_go_binary}" ]] || {
    release_refused "tools.go.executable_sha256_by_platform.${platform_key} does not authorize the extracted Go executable (measured ${measured_go}); record the reviewed value in tools/toolchain-pins.json"
    return $?
  }
  [[ "${expected_go_tree}" =~ ^[0-9a-f]{64}$ ]] || {
    release_refused "tools.linux.go.install_tree_sha256.${platform_key} is absent from tools/toolchain-pins.json; measure it with: bash tools/build_linux_release.sh --measure-tree-sha256 <extracted go dir>"
    return $?
  }
  measured_go_tree="$(linux_winn3_source_tree_sha256 "${go_root}")" || return 65
  [[ "${measured_go_tree}" == "${expected_go_tree}" ]] || {
    echo "Extracted Linux Go install tree does not match its reviewed identity." >&2
    return 65
  }
  mkdir -p "$tmp_dir/go-home" "$tmp_dir/go-path" "$tmp_dir/go-bin" \
    "$tmp_dir/go-tmp" "${GOMODCACHE:-$tmp_dir/go-mod-cache}" \
    "${GOCACHE:-$tmp_dir/go-build-cache}"
  LINUX_REVIEWED_GO_BIN="${go_bin}"
  WINS_RELEASE_GO_ROOT="${go_root}"
  WINS_RELEASE_GO_HOME="$tmp_dir/go-home"
  WINS_RELEASE_GO_GOPATH="$tmp_dir/go-path"
  WINS_RELEASE_GO_GOBIN="$tmp_dir/go-bin"
  WINS_RELEASE_GO_TMPDIR="$tmp_dir/go-tmp"
  exec {WINS_RELEASE_GO_FD}<"${go_bin}"
  WINS_RELEASE_GO_HELD_PATH="/proc/$$/fd/${WINS_RELEASE_GO_FD}"
  [[ -r "${WINS_RELEASE_GO_HELD_PATH}" ]] || {
    echo "Linux /proc descriptor binding is required for the reviewed Go executable." >&2
    return 65
  }
  export LINUX_REVIEWED_GO_BIN WINS_RELEASE_GO_ROOT WINS_RELEASE_GO_HOME
  export WINS_RELEASE_GO_GOPATH WINS_RELEASE_GO_GOBIN WINS_RELEASE_GO_TMPDIR
  export WINS_RELEASE_GO_HELD_PATH
  WINS_RELEASE_GO_SHA256="${measured_go}"
  WINS_RELEASE_GO_TREE_SHA256="${measured_go_tree}"
  export WINS_RELEASE_GO_SHA256 WINS_RELEASE_GO_TREE_SHA256
  wins_release_go_verify() {
    local executable_digest tree_digest
    executable_digest="$(winsvpn_sha256_bind_file "${WINS_RELEASE_GO_HELD_PATH:?}")" || return 1
    [[ "${executable_digest}" == "${WINS_RELEASE_GO_SHA256:?}" ]] || return 1
    tree_digest="$(linux_winn3_source_tree_sha256 "${WINS_RELEASE_GO_ROOT:?}")" || return 1
    [[ "${tree_digest}" == "${WINS_RELEASE_GO_TREE_SHA256:?}" ]]
  }
  wins_release_go_run() {
    local variable value
    local module_cache_spec=""
    local -a custody_specs=(
      "${WINS_RELEASE_GO_TREE_SHA256:?}=${WINS_RELEASE_GO_ROOT:?}"
    )
    local -a constructed_env=(
      "HOME=${WINS_RELEASE_GO_HOME:?}"
      "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
      "TMPDIR=${WINS_RELEASE_GO_TMPDIR:?}"
      "GOROOT=${WINS_RELEASE_GO_ROOT:?}"
      "GOPATH=${WINS_RELEASE_GO_GOPATH:?}"
      "GOBIN=${WINS_RELEASE_GO_GOBIN:?}"
      "GOENV=off"
      "GOTOOLCHAIN=local"
      "GOPRIVATE="
      "GONOPROXY="
      "GONOSUMDB="
      "GOAUTH=off"
    )
    for variable in GOPROXY GOSUMDB GOMODCACHE GOCACHE GOFLAGS GOOS GOARCH \
      GOAMD64 GOARM64 CGO_ENABLED SOURCE_DATE_EPOCH; do
      if [[ -n "${!variable+x}" ]]; then
        value="${!variable}"
        constructed_env+=("${variable}=${value}")
      fi
    done
    if [[ -n "${GOMODCACHE:-}" ]]; then
      [[ "${WINS_STORE_GOMODCACHE_TREE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || {
        release_refused "WINS_STORE_GOMODCACHE_TREE_SHA256 must authenticate the offline Linux module cache"
        return $?
      }
      custody_specs+=("${WINS_STORE_GOMODCACHE_TREE_SHA256}=${GOMODCACHE}")
    fi
    run_with_linux_tree_custody "${custody_specs[@]}" -- \
      /usr/bin/env -i "${constructed_env[@]}" "${WINS_RELEASE_GO_HELD_PATH:?}" "$@"
  }
  export -f winsvpn_sha256_bind_file linux_winn3_source_tree_sha256 release_refused
  export -f run_with_linux_tree_custody
  export -f wins_release_go_verify wins_release_go_run
  wins_release_go_verify || {
    echo "Constructed reviewed Go custody failed its first held-descriptor verification." >&2
    return 65
  }
  [[ "$(wins_release_go_run version)" == "go version go${GO_VERSION} linux/${LINUX_RELEASE_GOARCH}" ]] || {
    echo "Constructed reviewed Go toolchain identity mismatch." >&2
    return 65
  }
}

stage_store_awg_from_tools_source() {
  local src_root src build clang_version expected_clang_sha source_before source_after build_source
  local transformed_quick="$tmp_dir/awg-quick-userspace"
  local prebuilt="${WINS_ENGINE_SOURCE_ROOT}/awg-prebuilt/awg"
  local quick_prebuilt="${WINS_ENGINE_SOURCE_ROOT}/awg-prebuilt/awg-quick"
  if [[ -f "${prebuilt}" && ! -L "${prebuilt}" && -f "${quick_prebuilt}" && ! -L "${quick_prebuilt}" ]]; then
    [[ "$(winsvpn_sha256_bind_file "${prebuilt}")" == "${AWG_BINARY_SHA256_ARM64}" ]] || {
      echo "arm64 AWG prebuilt payload SHA-256 verification failed." >&2
      return 65
    }
    [[ "$(winsvpn_sha256_bind_file "${quick_prebuilt}")" == "${AWG_QUICK_SOURCE_SHA256}" ]] || {
      echo "awg-quick prebuilt payload SHA-256 verification failed." >&2
      return 65
    }
    winsvpn_write_userspace_only_awg_quick "${quick_prebuilt}" "${transformed_quick}" || return 65
    winsvpn_install_bound_engine "${prebuilt}" "$tmp_dir/awg" "awg" >/dev/null || return 65
    winsvpn_install_bound_engine "${transformed_quick}" "$tmp_dir/awg-quick" "awg-quick" >/dev/null || return 65
    return 0
  fi
  if [[ -z "${AWG_ARM64_CLANG:-}" ]]; then
    echo "arm64 AWG requires clang 14.0.6/binutils 2.40-2 or a prebuilt authenticated payload." >&2
    return 65
  fi
  # Store AWG must exec the package clang inode, never a PATH alias.
  AWG_ARM64_CLANG="$(
    python3 -I - "${AWG_ARM64_CLANG}" <<'PY'
import os, stat, sys
exported = sys.argv[1]
package = "/usr/bin/clang"
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW

def identity(path: str) -> tuple[int, int, str]:
    current = path
    for _ in range(8):
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(current)
            if os.path.isabs(target):
                current = target
            else:
                current = os.path.join(os.path.dirname(current), target)
            continue
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit("clang must be a regular file")
        fd = os.open(current, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise SystemExit("clang changed while opened")
            return opened.st_dev, opened.st_ino, current
        finally:
            os.close(fd)
    raise SystemExit("clang symlink chain is too long")

try:
    invoked = identity(exported)
    pkg = identity(package)
except OSError:
    raise SystemExit("package clang is unreadable")
if (invoked[0], invoked[1]) != (pkg[0], pkg[1]):
    raise SystemExit("arm64 AWG clang must be the package executable")
sys.stdout.write(pkg[2] + "\n")
PY
  )" || {
    echo "arm64 AWG requires clang 14.0.6/binutils 2.40-2 or a prebuilt authenticated payload." >&2
    return 65
  }
  if [[ -L "${AWG_ARM64_CLANG}" || ! -f "${AWG_ARM64_CLANG}" ]]; then
    echo "arm64 AWG requires clang 14.0.6/binutils 2.40-2 or a prebuilt authenticated payload." >&2
    return 65
  fi
  expected_clang_sha="$(read_optional_wins_toolchain_pin tools.linux.arm64.clang_executable_sha256)"
  [[ "${expected_clang_sha}" =~ ^[0-9a-f]{64}$ ]] || {
    release_refused "tools.linux.arm64.clang_executable_sha256 is absent from tools/toolchain-pins.json; on the arm64 Linux build host record the sha256 of the resolved clang 14.0.6 executable: sha256sum \"\$(readlink -f /usr/bin/clang)\""
    return $?
  }
  [[ "$(winsvpn_sha256_bind_file "${AWG_ARM64_CLANG}")" == "${expected_clang_sha}" ]] || {
    echo "Reviewed arm64 AWG clang executable SHA-256 verification failed." >&2
    return 65
  }
  exec {AWG_ARM64_CLANG_FD}<"${AWG_ARM64_CLANG}"
  AWG_ARM64_CLANG="/proc/$$/fd/${AWG_ARM64_CLANG_FD}"
  [[ -r "${AWG_ARM64_CLANG}" ]] || {
    echo "Linux /proc descriptor binding is required for the arm64 AWG compiler." >&2
    return 65
  }
  clang_version="$("${AWG_ARM64_CLANG}" --version | head -n 1 || true)"
  [[ "${clang_version}" == *"clang version 14.0.6"* ]] || {
    echo "arm64 AWG requires clang 14.0.6/binutils 2.40-2 or a prebuilt authenticated payload; found: ${clang_version:-unknown}." >&2
    return 65
  }
  src_root="${WINS_ENGINE_SOURCE_ROOT}/awg-tools-src"
  [[ -d "${src_root}" && ! -L "${src_root}" ]] || {
    echo "declared amneziawg-tools source is missing." >&2
    return 65
  }
  if [[ -d "${src_root}/src" ]]; then
    src="${src_root}/src"
  else
    src="${src_root}/amneziawg-tools-${AWG_TOOLS_VERSION#v}/src"
  fi
  [[ -f "${src}/version.h" && ! -L "${src}/version.h" ]] || {
    echo "amneziawg-tools source is missing src/version.h." >&2
    return 65
  }
  [[ -f "${src}/wg-quick/linux.bash" && ! -L "${src}/wg-quick/linux.bash" ]] || {
    echo "amneziawg-tools source is missing wg-quick/linux.bash." >&2
    return 65
  }
  grep -Fq 'WIREGUARD_TOOLS_VERSION "3.1.20260812"' "${src}/version.h" || {
    echo "Pinned amneziawg-tools source has an unexpected version.h." >&2
    return 65
  }
  command -v make >/dev/null 2>&1 || {
    echo "make is required to compile linux-arm64 awg from declared source." >&2
    return 65
  }
  [[ "$(winsvpn_sha256_bind_file "${src}/wg-quick/linux.bash")" == "${AWG_QUICK_SOURCE_SHA256}" ]] || {
    echo "Authenticated awg-quick source SHA-256 verification failed." >&2
    return 65
  }
  winsvpn_write_userspace_only_awg_quick \
    "${src}/wg-quick/linux.bash" "${transformed_quick}" || return 65
  source_before="$(linux_winn3_source_tree_sha256 "${src}")" || return 65
  build="$tmp_dir/awg-tools-build/src"
  mkdir -p "${build}"
  cp -a "${src}/." "${build}/"
  source_after="$(linux_winn3_source_tree_sha256 "${src}")" || return 65
  build_source="$(linux_winn3_source_tree_sha256 "${build}")" || return 65
  [[ "${source_before}" == "${source_after}" && "${source_before}" == "${build_source}" ]] || {
    echo "Compiler-consumed amneziawg-tools source does not match the authenticated staging source." >&2
    return 65
  }
  (
    cd "${build}"
    export LC_ALL=C LANG=C TZ=UTC
    export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:?}"
    export CFLAGS="-O3 -ffile-prefix-map=${build}=. -fno-ident -g0 -fPIE"
    export LDFLAGS="-pie -Wl,--build-id=none -Wl,-z,relro,-z,now"
    # make writes its objects into this build copy, so tree custody over it
    # could never pass. The copy was proven equal to the authenticated source
    # above, and the output must equal AWG_BINARY_SHA256_ARM64 when staged.
    make PLATFORM=linux WITH_WGQUICK=no WITH_BASHCOMPLETION=no \
      WITH_SYSTEMDUNITS=no CC="${AWG_ARM64_CLANG}"
    [[ -x wg ]] || {
      echo "make did not produce src/wg." >&2
      return 65
    }
    install -m 0755 wg "$tmp_dir/awg"
    install -m 0755 "${transformed_quick}" "$tmp_dir/awg-quick"
  )
}

linux_winn3_source_tree_sha256() {
  python3 -I - "${1:-${ROOT}/winn_protocol_experimental}" <<'PY'
import hashlib
import os
import stat
import sys

root = sys.argv[1]
root_info = os.lstat(root)
if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
    raise SystemExit("source root is missing or unsafe")
members = []
total_bytes = 0
for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
    current = os.lstat(dirpath)
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
        raise SystemExit("source contains an unsafe directory")
    dirnames.sort()
    filenames.sort()
    for name in dirnames:
        info = os.lstat(os.path.join(dirpath, name))
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SystemExit("source contains an unsafe directory member")
    for name in filenames:
        path = os.path.join(dirpath, name)
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise SystemExit("source contains a non-regular file")
        total_bytes += before.st_size
        if len(members) >= 500000 or total_bytes > 16 * 1024 * 1024 * 1024:
            raise SystemExit("source exceeds the structural custody bound")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev, before.st_ino, before.st_size
            ):
                raise SystemExit("source changed while opened")
            digest = hashlib.sha256()
            remaining = opened.st_size
            while remaining:
                block = os.read(fd, min(1024 * 1024, remaining))
                if not block:
                    raise SystemExit("source member ended before its declared size")
                digest.update(block)
                remaining -= len(block)
            if os.fstat(fd).st_mtime_ns != opened.st_mtime_ns:
                raise SystemExit("source changed while hashed")
        finally:
            os.close(fd)
        relative = os.path.relpath(path, root).replace(os.sep, "/")
        members.append(f"file {opened.st_size} {digest.hexdigest()} {relative}\n")
members.sort()
sys.stdout.write(hashlib.sha256("".join(members).encode("utf-8")).hexdigest())
PY
}

run_with_retained_release_source_tree() {
  local source_root="$1"
  shift
  python3 -I - "${source_root}" "$@" <<'PY'
import hashlib
import os
import pathlib
import stat
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
command = sys.argv[2:]
if not command:
    raise SystemExit("retained source custody requires a compiler command")
held = []
try:
    for path in sorted(root.rglob("*")):
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            raise SystemExit(f"compiler source contains a symbolic link: {path}")
        if stat.S_ISDIR(before.st_mode):
            continue
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(f"compiler source contains an unsupported member: {path}")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
        opened = os.fstat(fd)
        digest = hashlib.sha256()
        offset = 0
        while offset < opened.st_size:
            block = os.pread(fd, min(1024 * 1024, opened.st_size - offset), offset)
            if not block:
                os.close(fd)
                raise SystemExit(f"compiler source ended while retained: {path}")
            digest.update(block)
            offset += len(block)
        held.append((path, fd, opened, digest.hexdigest()))
    completed = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL, check=False)
    for path, fd, opened, expected in held:
        retained = os.fstat(fd)
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (retained.st_dev, retained.st_ino):
            raise SystemExit(f"compiler source pathname was replaced: {path}")
        if retained.st_size != opened.st_size or retained.st_mtime_ns != opened.st_mtime_ns:
            raise SystemExit(f"compiler source metadata changed while retained: {path}")
        digest = hashlib.sha256()
        offset = 0
        while offset < retained.st_size:
            block = os.pread(fd, min(1024 * 1024, retained.st_size - offset), offset)
            if not block:
                raise SystemExit(f"retained compiler source became truncated: {path}")
            digest.update(block)
            offset += len(block)
        if digest.hexdigest() != expected:
            raise SystemExit(f"compiler source bytes changed through the retained descriptor: {path}")
    raise SystemExit(completed.returncode)
finally:
    for _path, fd, _opened, _digest in held:
        os.close(fd)
PY
}

run_with_retained_release_source_custody_at_root() {
  local custody_root="$1"
  local index_path="$2"
  shift 2
  # Every compiler input listed by the immutable release index is held open,
  # digest-checked before the compiler runs, watched with inotify (Linux), and
  # re-read through the held descriptor afterwards. Literal interpreter: this
  # function is exported into a /bin/bash -c child where the readonly python3
  # wrapper does not exist.
  /usr/bin/python3 -I - "${custody_root}" "${index_path}" \
    "${WINS_LINUX_CUSTODY_PORTABLE_TEST:-0}" "$@" <<'PY'
import ctypes
import hashlib
import json
import os
import pathlib
import resource
import select
import signal
import stat
import subprocess
import sys

repo = pathlib.Path(sys.argv[1])
index_path = pathlib.Path(sys.argv[2])
portable_test = sys.argv[3] == "1"
command = sys.argv[4:]
if not command:
    raise SystemExit("retained release source custody requires a compiler command")

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate release source custody key: {key}")
        result[key] = value
    return result

def reject_nonfinite(value):
    raise SystemExit(f"non-finite release source custody number: {value}")

index = json.loads(
    index_path.read_text(encoding="utf-8"),
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_nonfinite,
)
expected_index_keys = {
    "contract", "created_utc", "manifest_set_complete", "platform_manifests",
    "publication_authorized", "release", "schema_version", "sha256_anchor",
    "shared_manifest", "shared_revision",
}
if not isinstance(index, dict) or set(index) != expected_index_keys:
    raise SystemExit("release source-custody index fields are not exact")
if set(index["shared_manifest"]) != {"path", "sha256"}:
    raise SystemExit("release source-custody shared-manifest fields are not exact")
# The complete index carries the seven canonical freeze platforms
# (release_dependency_freeze.CANONICAL_FREEZE_PLATFORMS), not the earlier five.
if not isinstance(index["platform_manifests"], dict) or set(index["platform_manifests"]) != {
    "android", "wear_os", "ios", "macos", "windows", "linux", "extension",
}:
    raise SystemExit("release source-custody platform-manifest set is not exact")
for platform_record in index["platform_manifests"].values():
    if not isinstance(platform_record, dict) or set(platform_record) != {
        "artifact_input_fingerprint_sha256", "path", "sha256",
    }:
        raise SystemExit("release source-custody platform-manifest fields are not exact")
manifest_paths = [index["shared_manifest"]["path"], index["platform_manifests"]["linux"]["path"]]
records = {}
for relative_manifest in manifest_paths:
    manifest = json.loads(
        (index_path.parent / relative_manifest).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonfinite,
    )
    contract = manifest.get("contract") if isinstance(manifest, dict) else None
    if contract == "winsvpn-shared-inputs-v1":
        expected_manifest_keys = {
            "contract", "created_utc", "generated_outputs_excluded", "inputs",
            "publication_authorized", "release", "roots", "schema_version", "shared_revision",
        }
    elif contract == "winsvpn-platform-inputs-v1":
        expected_manifest_keys = {
            "artifact_input_fingerprint_sha256", "contract", "created_utc",
            "generated_outputs_excluded", "native_extra_paths", "native_inputs",
            "native_only_change_invalidates_only_this_platform", "native_roots",
            "platform", "producer_inputs", "producer_paths", "publication_authorized",
            "release", "schema_version", "shared",
        }
    else:
        raise SystemExit("release source manifest contract is invalid")
    if set(manifest) != expected_manifest_keys:
        raise SystemExit("release source manifest fields are not exact")
    for key in ("inputs", "native_inputs", "producer_inputs"):
        collection = manifest.get(key)
        if collection is None:
            continue
        # The freeze controller always writes git_audit (an object, or null in its
        # fixture mode) next to these four fields; this custody reads only "files".
        if not isinstance(collection, dict) or not {
            "file_count", "files", "fingerprint_sha256", "total_bytes",
        } <= set(collection) <= {
            "file_count", "files", "fingerprint_sha256", "git_audit", "total_bytes",
        }:
            raise SystemExit("release source manifest collection fields are not exact")
        if not isinstance(collection.get("git_audit", {}), (dict, type(None))):
            raise SystemExit("release source manifest git audit is not an object")
        for record in collection["files"]:
            if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
                raise SystemExit("release source manifest record fields are not exact")
            relative = record.get("path")
            digest = record.get("sha256")
            size = record.get("size")
            if not isinstance(relative, str) or not isinstance(digest, str) or not isinstance(size, int):
                raise SystemExit("release source manifest contains a malformed compiler input")
            previous = records.setdefault(relative, (digest, size))
            if previous != (digest, size):
                raise SystemExit(f"release source manifests disagree for {relative}")

# Every compiler input stays open until the compiler has finished, so the
# process needs one descriptor per input plus its own few. A default soft limit
# of 1024 (docker, most shells) is far below the roughly 1800 inputs of a real
# release: raise the soft limit to what is needed, never above the hard limit.
descriptors_needed = len(records) + 256
soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
if soft_limit != resource.RLIM_INFINITY and soft_limit < descriptors_needed:
    if hard_limit != resource.RLIM_INFINITY and hard_limit < descriptors_needed:
        raise SystemExit(
            f"retained release source custody needs {descriptors_needed} file descriptors "
            f"but the hard limit is {hard_limit}"
        )
    resource.setrlimit(resource.RLIMIT_NOFILE, (descriptors_needed, hard_limit))

held = []
watch_fd = -1
watched_paths = set()
if sys.platform == "linux":
    libc = ctypes.CDLL(None, use_errno=True)
    watch_fd = libc.inotify_init1(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    if watch_fd < 0:
        raise SystemExit("could not initialize Linux source-custody inotify")
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    libc.inotify_add_watch.restype = ctypes.c_int
elif not portable_test:
    raise SystemExit("RELEASE REFUSED: retained release source custody needs Linux inotify")

FILE_MASK = 0x00000002 | 0x00000004 | 0x00000008 | 0x00000400 | 0x00000800 | 0x00002000
DIR_MASK = 0x00000004 | 0x00000400 | 0x00000800 | 0x00002000

def add_watch(path: pathlib.Path, mask: int) -> None:
    if watch_fd < 0 or os.fspath(path) in watched_paths:
        return
    if libc.inotify_add_watch(watch_fd, os.fsencode(path), mask) < 0:
        raise SystemExit(f"could not watch retained release input: {path}")
    watched_paths.add(os.fspath(path))

def watch_path_and_ancestors(path: pathlib.Path) -> None:
    add_watch(path, FILE_MASK)
    for parent in (path.parent, *path.parents):
        add_watch(parent, DIR_MASK)

# `flutter build` runs the gen_localizations target before it compiles, and that
# target rewrites the three tracked lib/l10n/app_localizations*.dart outputs in
# place on every run; it is skipped only when l10n.yaml is absent (Flutter
# 3.47.6, build_system/targets/localizations.dart canSkip). `flutter pub get`
# has already generated the outputs before this wrapper starts, and the digest
# check below proves they equal the immutable index. The generator
# configuration is therefore set aside for the compile, so that nothing rewrites
# a compiler input: every output stays watched, held and compared like any other
# input. The configuration is put back, same inode, after the checks. One that
# is recreated or replaced meanwhile is refused.
#
# The set-aside is itself under custody. The original is opened, hashed and
# linked to its parked name before it is unlinked, and that descriptor stays open
# until the configuration is back, so the parked bytes are re-proved against the
# digest taken before the compile (identity, ctime and bytes). A second inotify
# instance watches the repository root for the name l10n.yaml and for the parked
# name (create, delete, move in or out) and the parked file itself, so a
# configuration that exists only while the compiler runs is seen even when it is
# gone again at the end. A parked file left by an interrupted run is a recovery
# condition that is checked before anything else, whether or not l10n.yaml
# exists, and the compiler does not run until it is resolved. A SIGTERM or SIGHUP
# with its default disposition unwinds through the finally block below, which
# puts the configuration back; one that was ignored at start stays ignored.
GENERATOR_CONFIG = "l10n.yaml"
PARKED_CONFIG = GENERATOR_CONFIG + ".source-custody-suspended"
CONFIG_NAME_MASK = 0x00000040 | 0x00000080 | 0x00000100 | 0x00000200
suspended_config = None
config_watch_fd = -1

def config_digest(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(descriptor, 1024 * 1024, offset)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        offset += len(block)

def config_identity(info) -> tuple:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )

def check_parked_config() -> None:
    if suspended_config is None:
        return
    _path, parked, descriptor, opened, expected = suspended_config
    try:
        unchanged = (
            config_identity(parked.lstat()) == config_identity(opened)
            and config_identity(os.fstat(descriptor)) == config_identity(opened)
            and config_digest(descriptor) == expected
            and config_identity(os.fstat(descriptor)) == config_identity(opened)
        )
    except FileNotFoundError:
        unchanged = False
    if not unchanged:
        raise SystemExit("release generator configuration changed while it was suspended")

def suspend_generator_config() -> None:
    global suspended_config, config_watch_fd
    path = repo / GENERATOR_CONFIG
    parked = repo / PARKED_CONFIG
    # A parked file left by an interrupted run must be recovered by hand first; it is
    # checked before the live name, so an absent l10n.yaml cannot hide it.
    if os.path.lexists(parked):
        raise SystemExit(
            f"release generator configuration is already suspended ({parked.name}); "
            f"an earlier run was interrupted, so restore it to {GENERATOR_CONFIG} first"
        )
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    if info is not None:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit(
                f"release generator configuration is not a single-link regular file: {GENERATOR_CONFIG}"
            )
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            expected = config_digest(descriptor)
            if (
                config_identity(opened) != config_identity(info)
                or config_identity(os.fstat(descriptor)) != config_identity(info)
            ):
                raise SystemExit("release generator configuration changed while opened")
            os.link(path, parked, follow_symlinks=False)
            suspended_config = (path, parked, descriptor, os.fstat(descriptor), expected)
            check_parked_config()
            current = path.lstat()
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise SystemExit("release generator configuration changed before suspension")
            os.unlink(path)
            suspended_config = (path, parked, descriptor, os.fstat(descriptor), expected)
        finally:
            if suspended_config is None:
                os.close(descriptor)
        check_parked_config()
    if watch_fd >= 0:
        # Started after our own set-aside and before any compiler can see a new name.
        config_watch_fd = libc.inotify_init1(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        if config_watch_fd < 0:
            raise SystemExit("could not initialize generator configuration custody")
        if libc.inotify_add_watch(config_watch_fd, os.fsencode(repo), DIR_MASK | CONFIG_NAME_MASK) < 0:
            raise SystemExit("could not watch the absent generator configuration")
        if suspended_config is not None:
            if libc.inotify_add_watch(config_watch_fd, os.fsencode(parked), FILE_MASK) < 0:
                raise SystemExit("could not watch the suspended generator configuration")
    check_generator_config()

def check_generator_config() -> None:
    if os.path.lexists(repo / GENERATOR_CONFIG):
        raise SystemExit("release generator configuration was recreated while it was suspended")
    if config_watch_fd >= 0:
        names = {os.fsencode(GENERATOR_CONFIG), os.fsencode(PARKED_CONFIG)}
        while True:
            try:
                events = os.read(config_watch_fd, 1024 * 1024)
            except BlockingIOError:
                break
            if not events:
                break
            offset = 0
            while offset + 16 <= len(events):
                mask = int.from_bytes(events[offset + 4:offset + 8], sys.byteorder)
                size = int.from_bytes(events[offset + 12:offset + 16], sys.byteorder)
                name = events[offset + 16:offset + 16 + size].split(b"\0", 1)[0]
                offset += 16 + size
                if (
                    mask & (0x00004000 | 0x00008000)
                    or (not name and mask & (FILE_MASK | DIR_MASK))
                    or (name in names and mask & CONFIG_NAME_MASK)
                ):
                    raise SystemExit("release generator configuration changed while it was suspended")
    check_parked_config()

def restore_generator_config() -> None:
    global suspended_config
    if suspended_config is None:
        return
    path, parked, descriptor, opened, _expected = suspended_config
    check_parked_config()
    try:
        os.link(parked, path, follow_symlinks=False)
    except FileExistsError:
        raise SystemExit("release generator configuration was recreated while it was suspended")
    restored = path.lstat()
    if (restored.st_dev, restored.st_ino) != (opened.st_dev, opened.st_ino):
        raise SystemExit("release generator configuration changed while it was restored")
    os.unlink(parked)
    suspended_config = None
    os.close(descriptor)

def unwind_on_signal(signum, _frame) -> None:
    raise SystemExit(128 + signum)

# A signal that was ignored when this process started stays ignored: a build
# launched with nohup or setsid sets SIGHUP to SIG_IGN on purpose so that it
# survives its terminal, and replacing that with an unwind would end the compile
# when the terminal closes. Only a signal with its default disposition unwinds.
for signal_name in ("SIGTERM", "SIGHUP"):
    if signal.getsignal(getattr(signal, signal_name)) != signal.SIG_IGN:
        signal.signal(getattr(signal, signal_name), unwind_on_signal)

try:
    suspend_generator_config()
    for relative, (expected_digest, expected_size) in sorted(records.items()):
        pure = pathlib.PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            raise SystemExit(f"release compiler input path is unsafe: {relative}")
        path = repo.joinpath(*pure.parts)
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise SystemExit(f"release compiler input is not a regular file: {relative}")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            os.close(fd)
            raise SystemExit(f"release compiler input changed while retained: {relative}")
        digest = hashlib.sha256()
        offset = 0
        while offset < opened.st_size:
            block = os.pread(fd, min(1024 * 1024, opened.st_size - offset), offset)
            if not block:
                os.close(fd)
                raise SystemExit(f"release compiler input ended while retained: {relative}")
            digest.update(block)
            offset += len(block)
        if opened.st_size != expected_size or digest.hexdigest() != expected_digest:
            os.close(fd)
            raise SystemExit(f"release compiler input does not match the immutable index: {relative}")
        watch_path_and_ancestors(path)
        held.append((relative, path, fd, opened, expected_digest))

    completed = subprocess.run(command, cwd=repo, stdin=subprocess.DEVNULL, check=False)
    check_generator_config()
    if watch_fd >= 0:
        poller = select.poll()
        poller.register(watch_fd, select.POLLIN)
        events = bytearray()
        while poller.poll(0):
            block = os.read(watch_fd, 1024 * 1024)
            if not block:
                break
            events.extend(block)
        offset = 0
        while offset + 16 <= len(events):
            mask = int.from_bytes(events[offset + 4:offset + 8], sys.byteorder)
            name_len = int.from_bytes(events[offset + 12:offset + 16], sys.byteorder)
            offset += 16 + name_len
            if mask & (FILE_MASK | DIR_MASK | 0x00004000 | 0x00008000):
                raise SystemExit("retained release input changed while the compiler was running")
    for relative, path, fd, opened, expected_digest in held:
        retained = os.fstat(fd)
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (retained.st_dev, retained.st_ino):
            raise SystemExit(f"release compiler input pathname was replaced: {relative}")
        if (
            retained.st_size != opened.st_size
            or retained.st_mtime_ns != opened.st_mtime_ns
            or retained.st_ctime_ns != opened.st_ctime_ns
        ):
            raise SystemExit(f"release compiler input metadata changed while retained: {relative}")
        digest = hashlib.sha256()
        offset = 0
        while offset < retained.st_size:
            block = os.pread(fd, min(1024 * 1024, retained.st_size - offset), offset)
            if not block:
                raise SystemExit(f"retained release compiler input became truncated: {relative}")
            digest.update(block)
            offset += len(block)
        if digest.hexdigest() != expected_digest:
            raise SystemExit(f"release compiler input bytes changed through the retained descriptor: {relative}")
    restore_generator_config()
    raise SystemExit(completed.returncode)
finally:
    try:
        restore_generator_config()
    except (OSError, SystemExit) as error:
        print(f"release generator configuration was not restored: {error}", file=sys.stderr)
    if suspended_config is not None:
        os.close(suspended_config[2])
    if config_watch_fd >= 0:
        os.close(config_watch_fd)
    for _relative, _path, fd, _opened, _expected in held:
        os.close(fd)
    if watch_fd >= 0:
        os.close(watch_fd)
PY
}

run_with_retained_release_source_custody() {
  local index_path="$1"
  shift
  run_with_retained_release_source_custody_at_root "${ROOT}" "${index_path}" "$@"
}

run_retained_release_source_custody_self_test() {
  local fixture_root index_dir index_path error_path status
  fixture_root="$(mktemp -d)"
  index_dir="${fixture_root}/index"
  index_path="${index_dir}/RELEASE_INPUT_INDEX.json"
  error_path="${fixture_root}/mutation.stderr"
  mkdir -m 0700 -- "${index_dir}"
  printf 'reviewed-compiler-source\n' >"${fixture_root}/source.txt"
  python3 -I - "${fixture_root}" "${index_dir}" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
index_dir = pathlib.Path(sys.argv[2])
payload = (root / "source.txt").read_bytes()
record = {"path": "source.txt", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
def collection(files, git_audit=None):
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {
        "file_count": len(files),
        "files": files,
        "fingerprint_sha256": hashlib.sha256(encoded).hexdigest(),
        "git_audit": git_audit,
        "total_bytes": sum(item["size"] for item in files),
    }
git_audit = {
    "binding_scope": "selected-blobs-semantic-v1",
    "git_executable_sha256": "5" * 64,
    "object_format": "sha1",
    "selected_blobs": [{"mode": "100644", "oid": "6" * 40, "path": "source.txt"}],
}
(index_dir / "SHARED_INPUTS.json").write_text(
    json.dumps({
        "contract": "winsvpn-shared-inputs-v1",
        "created_utc": "2026-08-26T00:00:00Z",
        "generated_outputs_excluded": True,
        "inputs": collection([record], git_audit),
        "publication_authorized": False,
        "release": "self-test",
        "roots": ["."],
        "schema_version": 1,
        "shared_revision": "0" * 40,
    }, sort_keys=True) + "\n", encoding="ascii"
)
(index_dir / "LINUX_INPUTS.json").write_text(
    json.dumps({
        "artifact_input_fingerprint_sha256": "1" * 64,
        "contract": "winsvpn-platform-inputs-v1",
        "created_utc": "2026-08-26T00:00:00Z",
        "generated_outputs_excluded": True,
        "native_extra_paths": [],
        "native_inputs": collection([]),
        "native_only_change_invalidates_only_this_platform": True,
        "native_roots": [],
        "platform": "linux",
        "producer_inputs": collection([]),
        "producer_paths": [],
        "publication_authorized": False,
        "release": "self-test",
        "schema_version": 1,
        "shared": {"path": "SHARED_INPUTS.json", "sha256": "2" * 64},
    }, sort_keys=True) + "\n",
    encoding="ascii",
)
(index_dir / "RELEASE_INPUT_INDEX.json").write_text(
    json.dumps(
        {
            "contract": "winsvpn-release-input-index-v1",
            "created_utc": "2026-08-26T00:00:00Z",
            "manifest_set_complete": True,
            "platform_manifests": {
                name: {
                    "artifact_input_fingerprint_sha256": "3" * 64,
                    "path": "LINUX_INPUTS.json",
                    "sha256": "4" * 64,
                }
                for name in ("android", "wear_os", "ios", "macos", "windows", "linux", "extension")
            },
            "publication_authorized": False,
            "release": "self-test",
            "schema_version": 1,
            "sha256_anchor": "RELEASE_INPUT_INDEX.json.sha256",
            "shared_manifest": {"path": "SHARED_INPUTS.json", "sha256": "2" * 64},
            "shared_revision": "0" * 40,
        },
        sort_keys=True,
    ) + "\n",
    encoding="ascii",
)
PY
  # A non-Linux host has no inotify; WINS_LINUX_CUSTODY_PORTABLE_TEST lets
  # the digest, link and retained-descriptor checks run there. On Linux the
  # inotify watch is always used.
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_retained_release_source_custody_at_root \
      "${fixture_root}" "${index_path}" \
      /bin/sh -c 'cat source.txt >/dev/null' >/dev/null 2>"${error_path}"; then
    :
  else
    sed -n '1,20p' "${error_path}" >&2
    echo "Retained release source custody refused an unmodified compiler input." >&2
    rm -rf -- "${fixture_root}"
    return 1
  fi
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_retained_release_source_custody_at_root \
      "${fixture_root}" "${index_path}" /bin/sh -c 'exit 7' >/dev/null 2>"${error_path}"; then
    status=0
  else
    status=$?
  fi
  [[ "${status}" == 7 ]] || {
    echo "Retained release source custody did not return the compiler exit status (got ${status})." >&2
    rm -rf -- "${fixture_root}"
    return 1
  }
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_retained_release_source_custody_at_root \
      "${fixture_root}" "${index_path}" \
      /bin/sh -c 'chmod u+w source.txt; printf "mutated-compiler-source\n" > source.txt' \
      >/dev/null 2>"${error_path}"; then
    echo "Retained release source custody accepted compiler-time mutation of a release input." >&2
    rm -rf -- "${fixture_root}"
    return 1
  fi
  grep -Eq 'changed through the retained descriptor|metadata changed while retained|changed while the compiler was running' "${error_path}" || {
    sed -n '1,20p' "${error_path}" >&2
    rm -rf -- "${fixture_root}"
    return 1
  }
  # The fixture now differs from the index: the pre-run digest must refuse it.
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_retained_release_source_custody_at_root \
      "${fixture_root}" "${index_path}" /bin/sh -c 'exit 0' >/dev/null 2>"${error_path}"; then
    echo "Retained release source custody accepted an input that does not match the index." >&2
    rm -rf -- "${fixture_root}"
    return 1
  fi
  grep -Fq 'does not match the immutable index' "${error_path}" || {
    sed -n '1,20p' "${error_path}" >&2
    rm -rf -- "${fixture_root}"
    return 1
  }
  printf 'reviewed-compiler-source\n' >"${fixture_root}/elsewhere.txt"
  rm -f -- "${fixture_root}/source.txt"
  ln -s elsewhere.txt "${fixture_root}/source.txt"
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_retained_release_source_custody_at_root \
      "${fixture_root}" "${index_path}" /bin/sh -c 'exit 0' >/dev/null 2>"${error_path}"; then
    echo "Retained release source custody accepted a symlinked compiler input." >&2
    rm -rf -- "${fixture_root}"
    return 1
  fi
  grep -Fq 'is not a regular file' "${error_path}" || {
    sed -n '1,20p' "${error_path}" >&2
    rm -rf -- "${fixture_root}"
    return 1
  }
  rm -rf -- "${fixture_root}"
  printf 'LINUX RETAINED RELEASE SOURCE CUSTODY SELF-TEST: PASS\n'
}

run_linux_tree_custody_self_test() {
  local fixture_root expected status error_path
  fixture_root="$(mktemp -d)"
  error_path="${fixture_root}/custody.stderr"
  mkdir -m 0700 "${fixture_root}/tree" "${fixture_root}/tree/sub"
  printf 'reviewed-toolchain-byte\n' >"${fixture_root}/tree/tool"
  printf 'nested-toolchain-byte\n' >"${fixture_root}/tree/sub/lib"
  # The custody digest must be the pin encoding (linux_winn3_source_tree_sha256).
  expected="$(linux_winn3_source_tree_sha256 "${fixture_root}/tree")"
  if [[ "$(uname -s)" == "Linux" ]]; then :; else
    if run_with_linux_tree_custody "${expected}=${fixture_root}/tree" -- /bin/sh -c 'exit 0' \
        2>"${error_path}"; then
      echo "Compiler tree custody ran without inotify outside the portable self-test." >&2
      rm -rf "${fixture_root}"
      return 1
    else
      status=$?
    fi
    [[ "${status}" == 65 ]] && grep -Fq 'RELEASE REFUSED: compiler tree custody needs Linux inotify' "${error_path}" || {
      cat "${error_path}" >&2
      rm -rf "${fixture_root}"
      return 1
    }
  fi
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${expected}=${fixture_root}/tree" -- \
      /bin/sh -c 'cat "$1/tool" "$1/sub/lib" >/dev/null' sh "${fixture_root}/tree" \
      2>"${error_path}"; then
    :
  else
    cat "${error_path}" >&2
    echo "Compiler tree custody refused an unmodified pinned tree." >&2
    rm -rf "${fixture_root}"
    return 1
  fi
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${expected}=${fixture_root}/tree" -- /bin/sh -c 'exit 7' 2>"${error_path}"; then
    status=0
  else
    status=$?
  fi
  [[ "${status}" == 7 ]] || {
    echo "Compiler tree custody did not return the compiler exit status (got ${status})." >&2
    rm -rf "${fixture_root}"
    return 1
  }
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "$(printf '%064d' 0)=${fixture_root}/tree" -- /bin/sh -c 'exit 0' 2>"${error_path}"; then
    echo "Compiler tree custody accepted a tree that does not match its pin." >&2
    rm -rf "${fixture_root}"
    return 1
  fi
  grep -Fq 'authenticated compiler tree digest mismatch' "${error_path}" || {
    cat "${error_path}" >&2
    rm -rf "${fixture_root}"
    return 1
  }
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${expected}=${fixture_root}/tree" -- \
      /bin/sh -c 'chmod u+w "$1/tool"; printf "substituted-toolchain-byte\n" >"$1/tool"' sh \
      "${fixture_root}/tree" 2>"${error_path}"; then
    rm -rf "${fixture_root}"
    echo "Compiler tree custody accepted a toolchain mutated by the compiler." >&2
    return 1
  fi
  grep -Eq 'changed after compiler execution|changed while the compiler was running' "${error_path}" || {
    cat "${error_path}" >&2
    rm -rf "${fixture_root}"
    return 1
  }
  printf 'reviewed-toolchain-byte\n' >"${fixture_root}/tree/tool"
  ln -s tool "${fixture_root}/tree/alias"
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${expected}=${fixture_root}/tree" -- /bin/sh -c 'exit 0' 2>"${error_path}"; then
    echo "Compiler tree custody accepted a symbolic link in a pinned tree." >&2
    rm -rf "${fixture_root}"
    return 1
  fi
  grep -Fq 'contains a symbolic link' "${error_path}" || {
    cat "${error_path}" >&2
    rm -rf "${fixture_root}"
    return 1
  }
  rm -f -- "${fixture_root}/tree/alias"
  ln -- "${fixture_root}/tree/tool" "${fixture_root}/hardlink"
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${expected}=${fixture_root}/tree" -- /bin/sh -c 'exit 0' 2>"${error_path}"; then
    echo "Compiler tree custody accepted a hard-linked file in a pinned tree." >&2
    rm -rf "${fixture_root}"
    return 1
  fi
  grep -Fq 'contains a hard link or special member' "${error_path}" || {
    cat "${error_path}" >&2
    rm -rf "${fixture_root}"
    return 1
  }
  run_linux_tree_custody_runtime_state_self_test "${fixture_root}" || {
    rm -rf "${fixture_root}"
    return 1
  }
  run_linux_file_custody_self_test "${fixture_root}" || {
    rm -rf "${fixture_root}"
    return 1
  }
  rm -rf "${fixture_root}"
  printf 'LINUX COMPILER TREE CUSTODY SELF-TEST: PASS\n'
}

# One authenticated file (the staged release archive that named tools inspect):
# the tools must see the sealed bytes at the sealed pathname for the whole run.
run_linux_file_custody_self_test() {
  local fixture_root="$1" archive expected error_path
  archive="${fixture_root}/archive.tar.gz"
  error_path="${fixture_root}/file-custody.stderr"
  printf 'sealed-archive-byte\n' >"${archive}"
  chmod 0644 "${archive}"
  expected="$(python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "${archive}")"
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${expected}=${archive}" -- /bin/sh -c 'cat "$1" >/dev/null' sh "${archive}" \
      2>"${error_path}"; then
    :
  else
    cat "${error_path}" >&2
    echo "File custody refused an unmodified sealed file." >&2
    return 1
  fi
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "$(printf '%064d' 0)=${archive}" -- /bin/sh -c 'exit 0' 2>"${error_path}"; then
    echo "File custody accepted a file that does not match its sealed digest." >&2
    return 1
  fi
  grep -Fq 'authenticated compiler tree digest mismatch' "${error_path}" || {
    cat "${error_path}" >&2
    return 1
  }
  # The reported attack: put the held archive aside, show the tool a clean
  # substitute, then put the held archive back before the next assertion.
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${expected}=${archive}" -- /bin/sh -c '
        mv "$1" "$1.aside" &&
        printf "clean-substitute\n" >"$1" &&
        cat "$1" >/dev/null &&
        rm -f "$1" &&
        mv "$1.aside" "$1"' sh "${archive}" 2>"${error_path}"; then
    echo "File custody accepted an archive that was swapped for a substitute and restored." >&2
    return 1
  fi
  grep -Eq 'authenticated file changed during execution|changed while the compiler was running|pathname was replaced' "${error_path}" || {
    cat "${error_path}" >&2
    return 1
  }
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${expected}=${archive}" -- /bin/sh -c 'printf "x" >>"$1"' sh "${archive}" \
      2>"${error_path}"; then
    echo "File custody accepted a file that was appended to." >&2
    return 1
  fi
  printf 'sealed-archive-byte\n' >"${archive}"
  ln -- "${archive}" "${fixture_root}/archive-alias"
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${expected}=${archive}" -- /bin/sh -c 'exit 0' 2>"${error_path}"; then
    echo "File custody accepted a hard-linked file." >&2
    return 1
  fi
  grep -Fq 'hard-link alias' "${error_path}" || {
    cat "${error_path}" >&2
    return 1
  }
  rm -f -- "${fixture_root}/archive-alias"
  rm -f -- "${archive}.link" && ln -s "${archive}" "${archive}.link"
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${expected}=${archive}.link" -- /bin/sh -c 'exit 0' 2>"${error_path}"; then
    echo "File custody accepted a symbolic link." >&2
    return 1
  fi
  rm -f -- "${archive}.link"
}

# The Flutter SDK and Pub cache roots tolerate only their tools' runtime state.
run_linux_tree_custody_runtime_state_self_test() {
  local fixture_root="$1" sdk pub sdk_pin pub_pin error_path
  sdk="${fixture_root}/flutter"
  pub="${fixture_root}/pub-cache"
  error_path="${fixture_root}/runtime-state.stderr"
  mkdir -p "${sdk}/bin/cache" "${sdk}/.git" "${pub}/hosted/pub.dev/pkg" "${pub}/active_roots"
  printf 'flutter-launcher\n' >"${sdk}/bin/flutter"
  : >"${sdk}/bin/cache/lockfile"
  printf 'engine-1\n' >"${sdk}/bin/cache/engine.stamp"
  printf 'ref: refs/heads/stable\n' >"${sdk}/.git/HEAD"
  printf 'package-source\n' >"${pub}/hosted/pub.dev/pkg/lib.dart"
  sdk_pin="$(linux_winn3_source_tree_sha256 "${sdk}")"
  pub_pin="$(linux_winn3_source_tree_sha256 "${pub}")"
  # The bookkeeping writes of bin/flutter, the Flutter tool and pub.
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "--flutter-sdk-root=${sdk}" "--pub-cache-root=${pub}" \
      "${sdk_pin}=${sdk}" "${pub_pin}=${pub}" -- /bin/sh -c '
        printf x >"$1/bin/cache/lockfile"
        printf "engine-2\n" >"$1/bin/cache/engine.stamp.tmp.42"
        mv "$1/bin/cache/engine.stamp.tmp.42" "$1/bin/cache/engine.stamp"
        printf "\n" >"$1/bin/cache/engine.realm"
        printf "{}\n" >"$1/bin/cache/flutter.version.json"
        printf "ref: refs/heads/main\n" >"$1/.git/HEAD"
        mkdir -p "$2/active_roots/ab" "$2/log"
        printf root >"$2/active_roots/ab/cd"
        printf log >"$2/log/pub_log.txt"' sh "${sdk}" "${pub}" 2>"${error_path}"; then
    :
  else
    cat "${error_path}" >&2
    echo "Compiler tree custody refused Flutter/Pub runtime-state writes." >&2
    return 1
  fi
  # The runtime state still had to match the full pin before the run.
  sdk_pin="$(linux_winn3_source_tree_sha256 "${sdk}")"
  pub_pin="$(linux_winn3_source_tree_sha256 "${pub}")"
  printf 'engine-3\n' >"${sdk}/bin/cache/engine.stamp"
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "--flutter-sdk-root=${sdk}" "${sdk_pin}=${sdk}" -- /bin/sh -c 'exit 0' 2>"${error_path}"; then
    echo "Compiler tree custody accepted runtime state that differs from the pin before the run." >&2
    return 1
  fi
  grep -Fq 'authenticated compiler tree digest mismatch' "${error_path}" || { cat "${error_path}" >&2; return 1; }
  printf 'engine-2\n' >"${sdk}/bin/cache/engine.stamp"
  # Without the Flutter SDK designation the same writes are refused.
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${sdk_pin}=${sdk}" -- /bin/sh -c 'printf y >"$1/bin/cache/lockfile"' sh "${sdk}" \
      2>"${error_path}"; then
    echo "Compiler tree custody accepted a lockfile write in an undesignated tree." >&2
    return 1
  fi
  grep -Fq 'changed after compiler execution' "${error_path}" || { cat "${error_path}" >&2; return 1; }
  : >"${sdk}/bin/cache/lockfile"
  sdk_pin="$(linux_winn3_source_tree_sha256 "${sdk}")"
  # The final release build runs through run_with_reviewed_flutter_pub_custody:
  # bin/flutter's engine.stamp.tmp.<pid> create and replace is tolerated there,
  # and the same writes are refused for a Flutter SDK root without the designation.
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 WINS_LINUX_FLUTTER_TREE_ROOT="${sdk}" PUB_CACHE="${pub}" \
      WINS_LINUX_FLUTTER_TREE_SHA256="${sdk_pin}" WINS_LINUX_PUB_CACHE_TREE_SHA256="${pub_pin}" \
      run_with_reviewed_flutter_pub_custody /bin/sh -c '
        printf "engine-4\n" >"$1/bin/cache/engine.stamp.tmp.$$"
        mv "$1/bin/cache/engine.stamp.tmp.$$" "$1/bin/cache/engine.stamp"' sh "${sdk}" 2>"${error_path}"; then
    :
  else
    cat "${error_path}" >&2
    echo "Reviewed Flutter/Pub custody refused the engine.stamp.tmp.<pid> replace." >&2
    return 1
  fi
  sdk_pin="$(linux_winn3_source_tree_sha256 "${sdk}")"
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "${sdk_pin}=${sdk}" "${pub_pin}=${pub}" -- /bin/sh -c '
        printf "engine-5\n" >"$1/bin/cache/engine.stamp.tmp.$$"
        mv "$1/bin/cache/engine.stamp.tmp.$$" "$1/bin/cache/engine.stamp"' sh "${sdk}" 2>"${error_path}"; then
    echo "Compiler tree custody accepted an engine.stamp replace in an undesignated Flutter SDK." >&2
    return 1
  fi
  grep -Fq 'changed after compiler execution' "${error_path}" || { cat "${error_path}" >&2; return 1; }
  printf 'engine-2\n' >"${sdk}/bin/cache/engine.stamp"
  sdk_pin="$(linux_winn3_source_tree_sha256 "${sdk}")"
  # Everything outside the runtime state stays under custody.
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "--flutter-sdk-root=${sdk}" "${sdk_pin}=${sdk}" -- \
      /bin/sh -c 'printf "substituted\n" >"$1/bin/flutter"' sh "${sdk}" 2>"${error_path}"; then
    echo "Compiler tree custody accepted a substituted Flutter launcher." >&2
    return 1
  fi
  grep -Fq 'changed after compiler execution' "${error_path}" || { cat "${error_path}" >&2; return 1; }
  printf 'flutter-launcher\n' >"${sdk}/bin/flutter"
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "--flutter-sdk-root=${sdk}" "${sdk_pin}=${sdk}" -- \
      /bin/sh -c 'mkdir -p "$1/bin/cache/artifacts"; printf "planted\n" >"$1/bin/cache/artifacts/tool"' sh "${sdk}" \
      2>"${error_path}"; then
    echo "Compiler tree custody accepted a new Flutter cache artifact." >&2
    return 1
  fi
  grep -Fq 'changed after compiler execution' "${error_path}" || { cat "${error_path}" >&2; return 1; }
  rm -rf -- "${sdk}/bin/cache/artifacts"
  # Only a plain engine.stamp.tmp.<suffix> file is transient, not a tree under it.
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "--flutter-sdk-root=${sdk}" "${sdk_pin}=${sdk}" -- \
      /bin/sh -c 'mkdir -p "$1/bin/cache/engine.stamp.tmp.42"; printf "planted\n" >"$1/bin/cache/engine.stamp.tmp.42/tool"' sh "${sdk}" \
      2>"${error_path}"; then
    echo "Compiler tree custody accepted a tree planted under a transient engine-stamp name." >&2
    return 1
  fi
  grep -Fq 'changed after compiler execution' "${error_path}" || { cat "${error_path}" >&2; return 1; }
  rm -rf -- "${sdk}/bin/cache/engine.stamp.tmp.42"
  pub_pin="$(linux_winn3_source_tree_sha256 "${pub}")"
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "--pub-cache-root=${pub}" "${pub_pin}=${pub}" -- \
      /bin/sh -c 'printf "changed\n" >"$1/hosted/pub.dev/pkg/lib.dart"' sh "${pub}" 2>"${error_path}"; then
    echo "Compiler tree custody accepted a changed Pub package source." >&2
    return 1
  fi
  grep -Fq 'changed after compiler execution' "${error_path}" || { cat "${error_path}" >&2; return 1; }
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "--flutter-sdk-root=${fixture_root}/elsewhere" "${pub_pin}=${pub}" -- /bin/sh -c 'exit 0' \
      2>"${error_path}"; then
    echo "Compiler tree custody accepted a runtime-state root that is not a custody root." >&2
    return 1
  fi
  grep -Fq 'runtime-state root is not an authenticated tree' "${error_path}" || { cat "${error_path}" >&2; return 1; }
  if WINS_LINUX_CUSTODY_PORTABLE_TEST=1 run_with_linux_tree_custody \
      "--writable-root=${pub}" "${pub_pin}=${pub}" -- /bin/sh -c 'exit 0' 2>"${error_path}"; then
    echo "Compiler tree custody accepted an unknown option." >&2
    return 1
  fi
  grep -Fq 'Linux tree custody option is unknown' "${error_path}" || { cat "${error_path}" >&2; return 1; }
}

verify_linux_winn3_datapath_contract() {
  local binary="$1" expected_goarch="$2" contract_path="$3" error_path="$4"
  [[ -x "${binary}" && ! -L "${binary}" ]] || {
    echo "Winn Protocol v3 datapath role probe requires an executable regular file." >&2
    return 65
  }
  if ! "${binary}" -print-contract >"${contract_path}" 2>"${error_path}"; then
    echo "Winn Protocol v3 datapath role probe failed; refusing an unverified core artifact." >&2
    sed 's/^/  /' "${error_path}" 2>/dev/null || true
    return 65
  fi
  python3 -I - "${contract_path}" "${expected_goarch}" <<'PY'
import json
import pathlib
import sys

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate contract JSON key: {key}")
        result[key] = value
    return result

try:
    document = json.loads(
        pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite contract JSON number: {value}")
        ),
    )
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid Winn Protocol datapath contract: {error}")
if not isinstance(document, dict):
    raise SystemExit("Winn Protocol datapath contract is not an object")
expected = {
    "contract": "winn-datapath/1",
    "protocol_version": "winn/3",
    "wire": "winn-datapath-duplex/1",
    "payloads": ["awg-datagram", "ip-packet"],
    "goos": "linux",
    "goarch": sys.argv[2],
}
# The banner also carries the frame geometry and carrier-seam fields of the
# datapath's Contract struct (cmd/winn-datapath/main.go). The role probe pins the
# identity fields above and the exact field set, so a banner that gains or loses a
# field is refused.
banner_fields = {
    "frame_magic", "frame_version", "frame_header_size", "max_frame_payload",
    "max_datagram", "payload_semantics", "carrier_profile_version", "carriers_buildable",
}
if set(document) != set(expected) | banner_fields:
    raise SystemExit("Winn Protocol datapath contract fields are not exact")
for key, value in expected.items():
    if document.get(key) != value:
        raise SystemExit(
            f"Winn Protocol datapath contract {key!r} is {document.get(key)!r}; "
            f"expected {value!r}"
        )
PY
}

verify_linux_winn3_gateway_role() {
  local binary="$1" keygen_dir="$2" error_path="$3" candidate name
  local -a expected_files=(
    static.key
    static.pub
    admission.key
    client.key
    client.pub
    auth_ed25519.seed
    auth_ed25519.pub
    auth_mldsa65.seed
    auth_mldsa65.pub
  )
  [[ -x "${binary}" && ! -L "${binary}" ]] || {
    echo "Winn Protocol v3 relay role probe requires an executable regular file." >&2
    return 65
  }
  [[ ! -e "${keygen_dir}" && ! -L "${keygen_dir}" ]] || {
    echo "Winn Protocol v3 relay role probe directory is not fresh." >&2
    return 65
  }
  mkdir -m 0700 -- "${keygen_dir}"
  if ! (umask 077; PATH=/usr/bin:/bin:/usr/sbin:/sbin "${binary}" -mode keygen -out "${keygen_dir}") \
      >"${keygen_dir}.stdout" 2>"${error_path}"; then
    echo "Winn Protocol v3 relay role probe failed; refusing an unverified relay artifact." >&2
    sed 's/^/  /' "${error_path}" 2>/dev/null || true
    return 65
  fi
  for name in "${expected_files[@]}"; do
    [[ -f "${keygen_dir}/${name}" && ! -L "${keygen_dir}/${name}" && -s "${keygen_dir}/${name}" ]] || {
      echo "Winn Protocol v3 relay role probe omitted keygen output: ${name}" >&2
      return 65
    }
  done
  python3 -I - "${keygen_dir}" "${expected_files[@]}" <<'PY'
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
expected = set(sys.argv[2:])
entries = list(root.iterdir())
if {entry.name for entry in entries} != expected:
    raise SystemExit("Winn Protocol v3 relay keygen output set is not exact")
for entry in entries:
    info = entry.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"Winn Protocol v3 relay keygen output is not a private regular file: {entry.name}")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size <= 0:
        raise SystemExit(f"Winn Protocol v3 relay keygen output has unsafe custody: {entry.name}")
PY
  while IFS= read -r -d '' candidate; do
    [[ -f "${candidate}" && ! -L "${candidate}" ]] || {
      echo "Winn Protocol v3 relay role probe produced an unsafe keygen entry: ${candidate}" >&2
      return 65
    }
    name="${candidate##*/}"
    case " ${expected_files[*]} " in
      *" ${name} "*) ;;
      *)
        echo "Winn Protocol v3 relay role probe produced an unexpected keygen entry: ${name}" >&2
        return 65
        ;;
    esac
  done < <(find "${keygen_dir}" -mindepth 1 -maxdepth 1 -print0)
}

write_linux_winn3_core_relay_provenance() {
  local output="$1" core_digest="$2" relay_digest="$3" source_digest="$4"
  local input_index_hash="$5" source_custody="$6" core_target="$7" relay_target="$8"
  local go_version="$9" go_executable_sha256="${10}" go_install_tree_sha256="${11}"
  local release_manifest_sha256="${12}"
  python3 -I - "${output}" \
    "${LINUX_RELEASE_ARCH_LABEL}" "${LINUX_RELEASE_GOARCH}" "${LINUX_RELEASE_ELF_MACHINE}" \
    "${core_digest}" "${relay_digest}" "${source_digest}" "${input_index_hash}" \
    "${source_custody}" "${core_target}" "${relay_target}" \
    "${go_executable_sha256:?}" "${go_install_tree_sha256:?}" "${go_version:?}" \
    "${release_manifest_sha256:?}" <<'PY'
import json
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
document = {
    "schema_version": 1,
    "contract": "winsvpn-linux-winn3-core-relay-provenance-v1",
    "host": {
        "os": "Linux",
        "arch_label": sys.argv[2],
        "goarch": sys.argv[3],
        "elf_machine": int(sys.argv[4]),
    },
    "source": {
        "module": "winn_protocol_experimental",
        "tree_sha256": sys.argv[7],
        "custody": sys.argv[9],
        "release_input_index_sha256": sys.argv[8],
        "winn_release_manifest_sha256": sys.argv[15],
    },
    "toolchain": {
        "go_version": sys.argv[14],
        "go_executable_sha256": sys.argv[12],
        "go_install_tree_sha256": sys.argv[13],
    },
    "artifacts": {
        "core": {
            "role": "client-datapath",
            "target": sys.argv[10],
            "sha256": sys.argv[5],
        },
        "relay": {
            "role": "gateway-relay",
            "target": sys.argv[11],
            "sha256": sys.argv[6],
            "custody": "disposable-scratch-only",
        },
    },
}
output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate provenance JSON key: {key}")
        result[key] = value
    return result

checked = json.loads(
    output.read_text(encoding="ascii"),
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=lambda value: (_ for _ in ()).throw(
        ValueError(f"non-finite provenance JSON number: {value}")
    ),
)
if checked != document:
    raise SystemExit("Winn Protocol core/relay provenance changed after writing")
PY
}

# The sealed Winn builder prints one WINN_BUILD_RECEIPT line and one
# "Built Winn Protocol <label>: <path> (<target>, sha256 <hex>)" line. Bind
# both to the exact target and to the bytes this producer is about to gate.
assert_linux_winn_builder_receipt() {
  local build_log="$1" target="$2" output="$3" digest
  digest="$(winsvpn_sha256_bind_file "${output}")" || return 65
  python3 -I - "${build_log}" "${target}" "${output}" "${digest}" <<'PY'
import json
import os
import sys

log_path, target, output, digest = sys.argv[1:5]
with open(log_path, encoding="utf-8", errors="replace") as handle:
    lines = handle.read().splitlines()
receipts = [line for line in lines if line.startswith("WINN_BUILD_RECEIPT ")]
built = [line for line in lines if line.startswith("Built Winn Protocol ")]
if len(receipts) != 1 or len(built) != 1:
    raise SystemExit("Winn builder must print exactly one receipt and one result line")


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate Winn builder receipt key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise SystemExit(f"non-finite Winn builder receipt number: {value}")


try:
    receipt = json.loads(
        receipts[0][len("WINN_BUILD_RECEIPT "):],
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_constant,
    )
except ValueError as error:
    raise SystemExit(f"Winn builder receipt is not JSON: {error}")
if not isinstance(receipt, dict) or receipt.get("contract") != "winsvpn-winn-core-build-v4":
    raise SystemExit("Winn builder receipt does not carry contract winsvpn-winn-core-build-v4")
receipt_target = receipt.get("target")
receipt_artifact = receipt.get("artifact")
if not isinstance(receipt_target, dict) or receipt_target.get("id") != target:
    raise SystemExit(f"Winn builder receipt does not name target {target}")
if not isinstance(receipt_artifact, dict) or receipt_artifact.get("sha256") != digest:
    raise SystemExit(f"Winn builder receipt does not bind {target} to the produced bytes")
# The builder prints its canonical output path.
if not built[0].endswith(f": {os.path.realpath(output)} ({target}, sha256 {digest})"):
    raise SystemExit(f"Winn builder result line does not bind {target} to the produced bytes")
PY
}

resolve_linux_winn_release_dir() {
  local requested="${WINS_WINN_RELEASE_DIR:-}" resolved
  [[ "${requested}" == /* ]] || {
    echo "WINS_WINN_RELEASE_DIR must be an absolute path to a signed Winn release directory." >&2
    return 65
  }
  [[ -d "${requested}" && ! -L "${requested}" ]] || {
    echo "WINS_WINN_RELEASE_DIR must be an existing directory, not a symlink: ${requested}" >&2
    return 65
  }
  resolved="$(cd -- "${requested}" && pwd -P)" || return 65
  [[ "${resolved}" == "${requested%/}" ]] || {
    echo "WINS_WINN_RELEASE_DIR must already be canonical (resolved ${resolved})." >&2
    return 65
  }
  printf '%s\n' "${resolved}"
}

# Signature verification against the pinned release authority. Release staging
# never passes --allow-unsigned or --trust-public-key. stdout_path receives the
# exact manifest bytes the driver verified (--print-manifest); the caller takes
# every expected value from that file and never rereads the release manifest.
run_linux_winn_release_verify() {
  local release_dir="$1" target="$2" stdout_path="$3" stderr_path="$4" status=0
  python3 -I "${ROOT}/tools/winn_release.py" verify --release "${release_dir}" \
    --print-manifest >"${stdout_path}" 2>"${stderr_path}" || status=$?
  if [[ "${status}" != 0 ]]; then
    if [[ "${status}" == 3 ]] && grep -q '^TOOLCHAIN-MISSING:' "${stderr_path}"; then
      echo "Signed Winn release verification for ${target} needs a missing toolchain:" >&2
    else
      echo "Signed Winn release verification failed for ${target} (exit ${status}):" >&2
    fi
    sed 's/^/  /' "${stderr_path}" >&2 || true
    return 65
  fi
  if grep -q '^UNSIGNED:' "${stderr_path}"; then
    echo "Signed Winn release verification for ${target} reported an unsigned release; release staging refuses it." >&2
    return 65
  fi
}

# Verify a signed Winn release once, copy one executable target's bytes into
# private scratch, and bind the copy to the signed manifest entry taken from
# the exact manifest bytes the driver verified (held in private scratch; the
# release directory's manifest.json is never read here). Writes six lines to
# fields_path: artifact sha256, manifest sha256, source tree sha256, Go
# version, Go executable sha256, Go install tree sha256.
stage_linux_winn_release_artifact() {
  local release_dir="$1" target="$2" filename="$3" dest="$4" fields_path="$5"
  run_linux_winn_release_verify "${release_dir}" "${target}" \
    "${dest}.verified-manifest.json" "${dest}.verify.err" || return 65
  python3 -I - "${release_dir}" "${target}" "${filename}" "${dest}.verified-manifest.json" \
    "${dest}" >"${fields_path}" <<'PY' || return 65
import hashlib
import json
import os
import stat
import sys

release, target, filename, verified_manifest_file, dest = sys.argv[1:6]
HEX = frozenset("0123456789abcdef")
READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW


def hex64(value, label):
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= HEX:
        raise SystemExit(f"signed Winn release {label} is not a lowercase SHA-256")
    return value


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate signed Winn manifest key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise SystemExit(f"non-finite signed Winn manifest number: {value}")


def open_regular(path, label):
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SystemExit(f"{label} must be a regular file")
    fd = os.open(path, READ_FLAGS)
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino, info.st_size) != (before.st_dev, before.st_ino, before.st_size):
        os.close(fd)
        raise SystemExit(f"{label} changed while opened")
    return fd, info


expected_path = os.path.join(release, "artifacts", target, filename)

# The driver's stdout: the manifest bytes whose signature it verified.
fd, info = open_regular(verified_manifest_file, "verified Winn manifest")
try:
    if info.st_size > 16 * 1024 * 1024:
        raise SystemExit("signed Winn manifest is too large")
    chunks = []
    remaining = info.st_size
    while remaining:
        block = os.read(fd, min(1024 * 1024, remaining))
        if not block:
            raise SystemExit("signed Winn manifest ended before its declared size")
        chunks.append(block)
        remaining -= len(block)
finally:
    os.close(fd)
manifest_bytes = b"".join(chunks)
if manifest_bytes.count(b"\n") != 1 or not manifest_bytes.endswith(b"\n"):
    raise SystemExit("winn_release.py verify must print exactly one canonical manifest line")
manifest = json.loads(
    manifest_bytes.decode("utf-8"),
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_constant,
)
if not isinstance(manifest, dict) or manifest.get("contract") != "winsvpn-winn-release-manifest-v1":
    raise SystemExit("signed Winn manifest does not carry contract winsvpn-winn-release-manifest-v1")
entries = [
    entry for entry in manifest.get("artifacts", [])
    if isinstance(entry, dict) and entry.get("target") == target
]
if len(entries) != 1:
    raise SystemExit(f"signed Winn manifest must list {target} exactly once")
entry = entries[0]
if entry.get("path") != f"artifacts/{target}/{filename}":
    raise SystemExit(f"signed Winn manifest path for {target} is not artifacts/{target}/{filename}")
if entry.get("header_path") not in (None, "") or entry.get("header_sha256") not in (None, ""):
    raise SystemExit(f"signed Winn manifest lists a header for executable target {target}")
expected = hex64(entry.get("sha256"), f"{target} sha256")
if hex64(entry.get("build_a_sha256"), "build_a_sha256") != expected or \
        hex64(entry.get("build_b_sha256"), "build_b_sha256") != expected:
    raise SystemExit(f"signed Winn manifest does not record two identical builds of {target}")
size = entry.get("size")
if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
    raise SystemExit(f"signed Winn manifest size for {target} is invalid")
source = manifest.get("source")
toolchains = manifest.get("toolchains")
if not isinstance(source, dict) or not isinstance(toolchains, dict):
    raise SystemExit("signed Winn manifest lacks source or toolchain identity")
source_tree = hex64(source.get("tree_sha256"), "source tree_sha256")
go = toolchains.get("go")
if not isinstance(go, dict):
    raise SystemExit("signed Winn manifest lacks the Go toolchain identity")
go_version = go.get("version")
if not isinstance(go_version, str) or not go_version or any(c.isspace() for c in go_version):
    raise SystemExit("signed Winn manifest Go version is invalid")
go_executable = hex64(go.get("executable_sha256"), "Go executable_sha256")
go_tree = hex64(go.get("install_tree_sha256"), "Go install_tree_sha256")

if os.path.lexists(dest):
    raise SystemExit(f"{filename} scratch destination already exists")
src_fd, src_info = open_regular(expected_path, f"signed {target} artifact")
try:
    if src_info.st_size != size:
        raise SystemExit(f"signed {target} artifact size does not match the manifest")
    hasher = hashlib.sha256()
    dest_fd = os.open(dest, WRITE_FLAGS, 0o700)
    try:
        remaining = src_info.st_size
        while remaining:
            block = os.read(src_fd, min(1024 * 1024, remaining))
            if not block:
                raise SystemExit(f"signed {target} artifact ended while copied")
            view = memoryview(block)
            while view:
                view = view[os.write(dest_fd, view):]
            hasher.update(block)
            remaining -= len(block)
        os.fsync(dest_fd)
        os.fchmod(dest_fd, 0o755)
    finally:
        os.close(dest_fd)
    if os.fstat(src_fd).st_mtime_ns != src_info.st_mtime_ns:
        raise SystemExit(f"signed {target} artifact changed while copied")
finally:
    os.close(src_fd)
if hasher.hexdigest() != expected:
    raise SystemExit(f"signed {target} artifact bytes do not match the manifest sha256")
print(expected)
print(hashlib.sha256(manifest_bytes).hexdigest())
print(source_tree)
print(go_version)
print(go_executable)
print(go_tree)
PY
  [[ "$(winsvpn_sha256_bind_file "${dest}")" == "$(sed -n 1p "${fields_path}")" ]] || {
    echo "Staged ${target} bytes do not match the signed Winn release manifest." >&2
    return 65
  }
}

# Stage Winn v3 datapath plus the Winn v1 AWG-then-Xray cover engines into
# dest. Dest is either the complete Linux bundle (release producer) or a
# dedicated store engine-stage directory. This never copies those payloads
# from a Flutter linux bundle: Flutter's install tree does not produce them.
# Store recipes must export WINS_ENGINE_SOURCE_ROOT to declared, already
# verified source artifacts and must not download during build.
stage_linux_engine_payloads() {
  local dest="${1:-}"
  local dest_abs
  local store_sources=0
  local go_bin awg_tools_dir awg_go_source awg_tools_copying expected_xray_sha256
  local expected_awg_go_binary_sha256 winn_target relay_target
  local winn_source_tree_before winn_source_tree_after winn_digest relay_digest installed_winn
  local winn_declared_source winn_bound_source winn_gomodcache winn_release_dir
  local winn_release_manifest_sha256 winn_go_version winn_go_executable_sha256
  local winn_go_install_tree_sha256 winn_source_custody
  local -a winn_builder_env=() winn_core_fields=() winn_relay_fields=()
  local WINS_WINN_SOURCE_ROOT="" WINS_WINN_SOURCE_TREE_SHA256=""
  local source_index_hash source_custody
  [[ -n "${dest}" ]] || {
    echo "Engine staging destination must be an existing regular directory." >&2
    return 65
  }
  if [[ -L "${dest}" ]]; then
    echo "refusing symlink engine destination: ${dest}" >&2
    return 65
  fi
  [[ -d "${dest}" && ! -L "${dest}" ]] || {
    echo "Engine staging destination must be an existing regular directory." >&2
    return 65
  }
  dest_abs="$(cd -- "${dest}" && pwd -P)"
  if [[ -L "${dest_abs}" ]]; then
    echo "refusing symlink engine destination: ${dest_abs}" >&2
    return 65
  fi
  [[ -n "${tmp_dir}" && -d "${tmp_dir}" && ! -L "${tmp_dir}" ]] || {
    echo "Engine staging requires a scratch directory." >&2
    return 65
  }
  assert_linux_release_matching_host || return 65
  assert_mandatory_dependencies_available_for_arch
  export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:?}"
  unset GOROOT GOPATH GOBIN GOOS GOARCH GOAMD64 GOARM64 CGO_ENABLED \
    GOEXPERIMENT GODEBUG GOTOOLDIR GOWORK GOPRIVATE GONOPROXY GONOSUMDB \
    GOINSECURE || true
  if [[ -n "${WINS_ENGINE_SOURCE_ROOT:-}" ]]; then
    store_sources=1
    [[ -d "${WINS_ENGINE_SOURCE_ROOT}" && ! -L "${WINS_ENGINE_SOURCE_ROOT}" ]] || {
      echo "store engine staging requires declared local source artifacts" >&2
      return 65
    }
    python3 -I "${ROOT}/linux/packaging/store_engine_bind.py" prepare \
      --source-root "${WINS_ENGINE_SOURCE_ROOT}" \
      --tmp "${tmp_dir}" \
      --arch "${LINUX_RELEASE_ARCH_LABEL}" \
      --repo "${ROOT}" \
      --out-env "${tmp_dir}/store-engine.env" >/dev/null
    # shellcheck disable=SC1090
    source "${tmp_dir}/store-engine.env"
    # The binder reports the Go custody it measured. prepare_linux_reviewed_go_for_engines
    # below re-derives every one of these from the same archive and refuses a value
    # that is already set, so they must not stay in the environment.
    unset LINUX_REVIEWED_GO_BIN WINS_RELEASE_GO_SHA256 WINS_RELEASE_GO_TREE_SHA256 \
      WINS_RELEASE_GO_INSTALL_TREE_SHA256
    export GOPROXY=off
    export GOSUMDB=off
    export GOMODCACHE="${WINS_STORE_GOMODCACHE:?}"
    export GOCACHE="${WINS_STORE_GOCACHE:?}"
    export GOFLAGS="-mod=readonly"
    export GOENV=off
    export GOTOOLCHAIN=local
    unset GOPATH || true
    if [[ "${GOMODCACHE}" == "${HOME}/go/pkg/mod" ]]; then
      echo "refusing dirty host Go module cache" >&2
      return 65
    fi
    if [[ "${GOCACHE}" == "${HOME}/Library/Caches/go-build" || "${GOCACHE}" == "${HOME}/.cache/go-build" ]]; then
      echo "refusing host Go build cache" >&2
      return 65
    fi
    [[ -d "${GOCACHE}" && ! -L "${GOCACHE}" ]] || {
      echo "isolated Go build cache is missing." >&2
      return 65
    }
  else
    release_refused "WINS_ENGINE_SOURCE_ROOT must name the authenticated offline Linux engine source/store stage"
    return $?
  fi

  prepare_linux_reviewed_go_for_engines || return $?

  winn_target="datapath-linux-${LINUX_RELEASE_GOARCH}"
  relay_target="winn3-gateway-linux-${LINUX_RELEASE_GOARCH}"
  mkdir -p "$tmp_dir/winn"

  # Winn Protocol v3 datapath engine (winn_protocol_experimental/cmd/winn-datapath,
  # produced for the datapath-linux-{amd64,arm64} builder targets).
  # linux/runner/linux_tunnel_backend.cc's FindWinnDatapathExecutable() resolves
  # it at runtime as "winn-datapath" beside the running executable, i.e. this
  # exact bundle directory.
  #
  # It is first-party in-repo Go source, so it is not a vendored SHA-256 pin.
  # The bytes come from one of two places, and both pass the same gates below
  # (ELF machine, datapath contract, relay role, digests):
  #   - WINS_WINN_RELEASE_DIR set: a signed Winn release directory. The
  #     artifacts must verify against the pinned release authority through
  #     tools/winn_release.py verify, and the signed manifest's source tree
  #     digest must equal this checkout's winn_protocol_experimental tree.
  #   - otherwise: tools/build_winn_protocol_engine.sh in sealed mode, fed a
  #     read-only source snapshot, a read-only module cache copy and the
  #     reviewed Go root, all bound by digest. The builder exits nonzero on
  #     any failure.
  #
  # linux/packaging/install.sh requires winn-datapath on every architecture, so
  # a Linux release archive that omits it is uninstallable. A failed Winn build
  # or a refused release directory is therefore a release refusal, not an
  # AmneziaWG/Xray-only fallback.
  #
  # The relay is a different Winn v3 role and is intentionally never copied
  # into the client bundle. It is obtained for the exact matching-host target,
  # then its keygen-only role contract is exercised in the mktemp-owned scratch
  # tree. A datapath binary substituted under the gateway target, or a gateway
  # for the other CPU, is refused before any release payload can be published.
  # The relay custody is disposable-scratch-only and is never a client package
  # input.
  winn_declared_source="${ROOT}/winn_protocol_experimental"
  winn_source_tree_before="$(linux_winn3_source_tree_sha256 "${winn_declared_source}")" || return 65
  if [[ -n "${WINS_WINN_RELEASE_DIR:-}" ]]; then
    winn_release_dir="$(resolve_linux_winn_release_dir)" || return 65
    log "Staging mandatory Winn Protocol v3 engine (core; target ${winn_target}) from signed release ${winn_release_dir}"
    stage_linux_winn_release_artifact "${winn_release_dir}" "${winn_target}" \
      "winn-datapath" "$tmp_dir/winn/winn-datapath" "$tmp_dir/winn/core-release.fields" || {
      echo "Winn Protocol v3 datapath is required for a Linux release; the signed release did not provide it." >&2
      return 65
    }
    log "Staging mandatory Winn Protocol v3 relay (target ${relay_target}; scratch-only) from signed release"
    stage_linux_winn_release_artifact "${winn_release_dir}" "${relay_target}" \
      "winn3-gateway" "$tmp_dir/winn/winn3-gateway" "$tmp_dir/winn/relay-release.fields" || {
      echo "Winn Protocol v3 relay is required for Linux producer integration; the signed release did not provide it." >&2
      return 65
    }
    mapfile -t winn_core_fields <"$tmp_dir/winn/core-release.fields"
    mapfile -t winn_relay_fields <"$tmp_dir/winn/relay-release.fields"
    [[ "${#winn_core_fields[@]}" == 6 && "${#winn_relay_fields[@]}" == 6 && \
       "${winn_core_fields[*]:1}" == "${winn_relay_fields[*]:1}" ]] || {
      echo "Winn Protocol v3 core and relay must come from one signed release manifest." >&2
      return 65
    }
    [[ "${winn_core_fields[2]}" == "${winn_source_tree_before}" ]] || {
      echo "Signed Winn release source tree ${winn_core_fields[2]} does not match this checkout's winn_protocol_experimental tree ${winn_source_tree_before}." >&2
      return 65
    }
    [[ "${winn_core_fields[3]#go}" == "${GO_VERSION}" ]] || {
      echo "Signed Winn release was built with Go ${winn_core_fields[3]}; this release requires Go ${GO_VERSION}." >&2
      return 65
    }
    winn_source_tree_after="$(linux_winn3_source_tree_sha256 "${winn_declared_source}")" || return 65
    [[ "${winn_source_tree_after}" == "${winn_source_tree_before}" ]] || {
      echo "Winn Protocol source changed while the signed core/relay pair was being staged." >&2
      return 65
    }
    winn_release_manifest_sha256="${winn_core_fields[1]}"
    winn_go_version="${winn_core_fields[3]#go}"
    winn_go_executable_sha256="${winn_core_fields[4]}"
    winn_go_install_tree_sha256="${winn_core_fields[5]}"
    winn_source_custody="signed-winn-release"
  else
    mkdir -m 0700 -- "${tmp_dir}/winn-source"
    cp -a -- "${winn_declared_source}/." "${tmp_dir}/winn-source/" || return 65
    chmod -R a-w -- "${tmp_dir}/winn-source" || return 65
    winn_source_tree_after="$(linux_winn3_source_tree_sha256 "${winn_declared_source}")" || return 65
    winn_bound_source="$(linux_winn3_source_tree_sha256 "${tmp_dir}/winn-source")" || return 65
    [[ "${winn_source_tree_before}" == "${winn_source_tree_after}" && \
       "${winn_source_tree_before}" == "${winn_bound_source}" ]] || {
      echo "Winn Protocol source changed while the compiler-consumed snapshot was sealed." >&2
      return 65
    }
    WINS_WINN_SOURCE_ROOT="${tmp_dir}/winn-source"
    WINS_WINN_SOURCE_ROOT="$(cd -- "${WINS_WINN_SOURCE_ROOT}" && pwd -P)" || return 65
    WINS_WINN_SOURCE_TREE_SHA256="${winn_bound_source}"

    # The builder requires a non-writable, digest-bound module cache. The
    # AmneziaWG and Xray builds below keep using WINS_STORE_GOMODCACHE, so the
    # Winn builder gets its own read-only copy instead of a chmod of the shared
    # cache.
    [[ "${WINS_STORE_GOMODCACHE_TREE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || {
      release_refused "WINS_STORE_GOMODCACHE_TREE_SHA256 must authenticate the offline Linux module cache"
      return $?
    }
    mkdir -m 0700 -- "${tmp_dir}/winn-gomodcache"
    cp -a -- "${WINS_STORE_GOMODCACHE:?}/." "${tmp_dir}/winn-gomodcache/" || return 65
    chmod -R a-w -- "${tmp_dir}/winn-gomodcache" || return 65
    winn_gomodcache="$(cd -- "${tmp_dir}/winn-gomodcache" && pwd -P)" || return 65
    [[ "$(linux_winn3_source_tree_sha256 "${winn_gomodcache}")" == "${WINS_STORE_GOMODCACHE_TREE_SHA256}" ]] || {
      echo "Winn builder module cache copy does not match WINS_STORE_GOMODCACHE_TREE_SHA256." >&2
      return 65
    }
    mkdir -m 0700 -- "$tmp_dir/winn/builder-home" "$tmp_dir/winn/builder-tmp"
    # The builder sees only this environment: no inherited Go variables and no
    # exported shell functions (wins_release_go_run is not part of its contract).
    winn_builder_env=(
      "HOME=$tmp_dir/winn/builder-home"
      "TMPDIR=$tmp_dir/winn/builder-tmp"
      "LANG=C"
      "LC_ALL=C"
      "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:?}"
      "WINS_WINN_SOURCE_ROOT=${WINS_WINN_SOURCE_ROOT}"
      "WINS_WINN_SOURCE_TREE_SHA256=${WINS_WINN_SOURCE_TREE_SHA256}"
      "WINS_STORE_GOMODCACHE=${winn_gomodcache}"
      "WINS_STORE_GOMODCACHE_TREE_SHA256=${WINS_STORE_GOMODCACHE_TREE_SHA256}"
      "WINS_RELEASE_GO_ROOT=${WINS_RELEASE_GO_ROOT:?}"
    )

    log "Building mandatory Winn Protocol v3 engine (core; target ${winn_target})"
    if /usr/bin/env -i "${winn_builder_env[@]}" \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin bash "$ROOT/tools/build_winn_protocol_engine.sh" "${winn_target}" \
        "$tmp_dir/winn/winn-datapath" >"$tmp_dir/winn/build.log" 2>&1 \
        && [[ -s "$tmp_dir/winn/winn-datapath" ]] \
        && assert_linux_winn_builder_receipt "$tmp_dir/winn/build.log" "${winn_target}" \
          "$tmp_dir/winn/winn-datapath"; then
      :
    else
      echo "Winn Protocol v3 datapath is required for a Linux release; the engine build failed. Build log:" >&2
      sed 's/^/  /' "$tmp_dir/winn/build.log" 2>/dev/null || true
      return 65
    fi

    log "Building mandatory Winn Protocol v3 relay (target ${relay_target}; scratch-only)"
    if /usr/bin/env -i "${winn_builder_env[@]}" \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin bash "$ROOT/tools/build_winn_protocol_engine.sh" "${relay_target}" \
        "$tmp_dir/winn/winn3-gateway" >"$tmp_dir/winn/relay-build.log" 2>&1 \
        && [[ -s "$tmp_dir/winn/winn3-gateway" ]] \
        && assert_linux_winn_builder_receipt "$tmp_dir/winn/relay-build.log" "${relay_target}" \
          "$tmp_dir/winn/winn3-gateway"; then
      :
    else
      echo "Winn Protocol v3 relay is required for Linux producer integration; the engine build failed. Build log:" >&2
      sed 's/^/  /' "$tmp_dir/winn/relay-build.log" 2>/dev/null || true
      return 65
    fi
    winn_source_tree_after="$(linux_winn3_source_tree_sha256 "${WINS_WINN_SOURCE_ROOT}")" || return 65
    [[ "${winn_source_tree_after}" == "${winn_source_tree_before}" ]] || {
      echo "Winn Protocol source changed while the core/relay pair was being built." >&2
      return 65
    }
    winn_release_manifest_sha256="not-a-signed-release"
    winn_go_version="${GO_VERSION}"
    winn_go_executable_sha256="${WINS_RELEASE_GO_SHA256:?}"
    winn_go_install_tree_sha256="${WINS_RELEASE_GO_TREE_SHA256:?}"
    winn_source_custody=""
  fi

  # Same gates for built and signed-release bytes.
  assert_release_elf_machine \
    "$tmp_dir/winn/winn-datapath" \
    "$LINUX_RELEASE_ELF_MACHINE" \
    "Winn Protocol v3 datapath"
  verify_linux_winn3_datapath_contract \
    "$tmp_dir/winn/winn-datapath" \
    "$LINUX_RELEASE_GOARCH" \
    "$tmp_dir/winn/datapath-contract.json" \
    "$tmp_dir/winn/datapath-contract.stderr" || return 65
  winn_digest="$(winsvpn_sha256_bind_file "$tmp_dir/winn/winn-datapath")" || return 65
  assert_release_elf_machine \
    "$tmp_dir/winn/winn3-gateway" \
    "$LINUX_RELEASE_ELF_MACHINE" \
    "Winn Protocol v3 relay"
  verify_linux_winn3_gateway_role \
    "$tmp_dir/winn/winn3-gateway" \
    "$tmp_dir/winn/relay-keygen" \
    "$tmp_dir/winn/relay-keygen.stderr" || return 65
  relay_digest="$(winsvpn_sha256_bind_file "$tmp_dir/winn/winn3-gateway")" || return 65
  if [[ -n "${WINS_WINN_RELEASE_DIR:-}" ]]; then
    [[ "${winn_digest}" == "${winn_core_fields[0]}" && "${relay_digest}" == "${winn_relay_fields[0]}" ]] || {
      echo "Winn Protocol v3 core/relay bytes changed after signed release verification." >&2
      return 65
    }
  fi
  source_index_hash="not-bound-in-engine-stage"
  source_custody="producer-checkout"
  if [[ -n "${formal_index_path}" ]]; then
    source_index_hash="$(sha256sum "${formal_index_path}" | awk '{print $1}')" || return 65
    [[ "${source_index_hash}" =~ ^[0-9a-f]{64}$ ]] || return 65
    source_custody="immutable-release-input-index"
  elif [[ -n "${WINS_ENGINE_SOURCE_ROOT:-}" ]]; then
    source_custody="declared-engine-stage"
  fi
  [[ -z "${winn_source_custody}" ]] || source_custody="${winn_source_custody}"
  write_linux_winn3_core_relay_provenance \
    "$tmp_dir/winn/winn3-core-relay-provenance.json" \
    "$winn_digest" "$relay_digest" "$winn_source_tree_after" \
    "$source_index_hash" "$source_custody" "$winn_target" "$relay_target" \
    "$winn_go_version" "$winn_go_executable_sha256" "$winn_go_install_tree_sha256" \
    "$winn_release_manifest_sha256" || return 65
  chmod 0400 "$tmp_dir/winn/winn3-core-relay-provenance.json"
  installed_winn="$(winsvpn_install_bound_engine "$tmp_dir/winn/winn-datapath" "$dest_abs/winn-datapath" "winn-datapath")" || return 65
  [[ "${installed_winn}" == "${winn_digest}" ]] || {
    echo "winn-datapath changed while installed." >&2
    return 65
  }
  log "Winn Protocol v3 engine staged: $dest_abs/winn-datapath"
  log "Winn Protocol v3 core/relay roles verified; relay remains scratch-only"

  if [[ "${LINUX_RELEASE_GOARCH}" != "amd64" ]]; then
    log "Building mandatory linux-arm64 AmneziaWG CLI from pinned amneziawg-tools source"
    if [[ "${store_sources}" == "1" ]]; then
      stage_store_awg_from_tools_source || return 65
    else
      arm64_clang_sha="$(read_optional_wins_toolchain_pin tools.linux.arm64.clang_executable_sha256)"
      [[ "${arm64_clang_sha}" =~ ^[0-9a-f]{64}$ ]] || {
        release_refused "tools.linux.arm64.clang_executable_sha256 is absent from tools/toolchain-pins.json; on the arm64 Linux build host record the sha256 of the resolved clang 14.0.6 executable: sha256sum \"\$(readlink -f /usr/bin/clang)\""
        return $?
      }
      env SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:?}" \
        WINS_LINUX_ARM64_CLANG_SHA256="${arm64_clang_sha}" \
        WINS_RELEASE_INPUT_INDEX="${formal_index_path:?}" \
        bash "$ROOT/tools/build_linux_arm64_awg.sh" \
        "$tmp_dir/awg" "$tmp_dir/awg-quick"
    fi
    winsvpn_stage_bound_engine "$tmp_dir/awg" "$dest_abs/awg" "awg" "${AWG_BINARY_SHA256_ARM64}" || return 65
    winsvpn_stage_bound_engine "$tmp_dir/awg-quick" "$dest_abs/awg-quick" "awg-quick" "${AWG_QUICK_SHA256}" || return 65
  else
    log "Bundling pinned AmneziaWG tools ${AWG_TOOLS_VERSION}"
    if [[ "${store_sources}" == "1" ]]; then
      awg_tools_dir=""
      if [[ -f "${WINS_ENGINE_SOURCE_ROOT}/awg-tools/ubuntu-22.04-amneziawg-tools/awg" ]]; then
        awg_tools_dir="${WINS_ENGINE_SOURCE_ROOT}/awg-tools/ubuntu-22.04-amneziawg-tools"
      elif [[ -f "${WINS_ENGINE_SOURCE_ROOT}/awg-tools/awg" ]]; then
        awg_tools_dir="${WINS_ENGINE_SOURCE_ROOT}/awg-tools"
      else
        echo "declared AmneziaWG tools zip payload is missing awg." >&2
        return 65
      fi
    else
      winsvpn_curl_verified_snapshot \
        "https://github.com/amnezia-vpn/amneziawg-tools/releases/download/${AWG_TOOLS_VERSION}/ubuntu-22.04-amneziawg-tools.zip" \
        "${AWG_TOOLS_ARCHIVE_SHA256}" \
        "$tmp_dir/ubuntu-22.04-amneziawg-tools.zip.snap" || return 65
      winsvpn_extract_snapshot \
        "$tmp_dir/ubuntu-22.04-amneziawg-tools.zip.snap" \
        "$tmp_dir/awg-tools" zip || return 65
      awg_tools_dir="$tmp_dir/awg-tools/ubuntu-22.04-amneziawg-tools"
    fi
    [[ -f "$awg_tools_dir/awg" && -f "$awg_tools_dir/awg-quick" ]] || {
      echo "Pinned AmneziaWG tools archive is missing awg or awg-quick." >&2
      return 65
    }
    [[ ! -L "$awg_tools_dir/awg" && ! -L "$awg_tools_dir/awg-quick" ]] || {
      echo "Pinned AmneziaWG tools payload must not be a symlink." >&2
      return 65
    }
    [[ "$(winsvpn_sha256_bind_file "$awg_tools_dir/awg-quick")" == "${AWG_QUICK_SOURCE_SHA256}" ]] || {
      echo "Pinned AmneziaWG tools archive carries an unexpected awg-quick source." >&2
      return 65
    }
    winsvpn_write_userspace_only_awg_quick \
      "$awg_tools_dir/awg-quick" "$tmp_dir/awg-quick-userspace" || return 65
    winsvpn_stage_bound_engine "$awg_tools_dir/awg" "$dest_abs/awg" "awg" "${AWG_BINARY_SHA256}" || return 65
    winsvpn_stage_bound_engine "$tmp_dir/awg-quick-userspace" "$dest_abs/awg-quick" "awg-quick" "${AWG_QUICK_SHA256}" || return 65
  fi

  awg_tools_copying="$tmp_dir/amneziawg-tools-COPYING"
  if [[ "${store_sources}" == "1" ]]; then
    [[ -f "${WINS_ENGINE_SOURCE_ROOT}/amneziawg-tools-COPYING" && ! -L "${WINS_ENGINE_SOURCE_ROOT}/amneziawg-tools-COPYING" ]] || {
      echo "declared AmneziaWG tools COPYING notice is missing." >&2
      return 65
    }
    winsvpn_snapshot_verified_file \
      "${WINS_ENGINE_SOURCE_ROOT}/amneziawg-tools-COPYING" \
      "${AWG_TOOLS_COPYING_SHA256}" \
      "${awg_tools_copying}" || return 65
  else
    winsvpn_curl_verified_snapshot \
      "https://raw.githubusercontent.com/amnezia-vpn/amneziawg-tools/${AWG_TOOLS_VERSION}/COPYING" \
      "${AWG_TOOLS_COPYING_SHA256}" \
      "${awg_tools_copying}" || return 65
  fi
  [[ "$(sha256sum "$awg_tools_copying" | awk '{print $1}')" == "${AWG_TOOLS_COPYING_SHA256}" ]] || {
    echo "Pinned AmneziaWG tools GPL-2.0 notice SHA-256 verification failed." >&2
    return 65
  }
  install -D -m 0644 "$awg_tools_copying" \
    "$dest_abs/share/doc/wins-vpn/licenses/amneziawg-tools-GPL-2.0.txt"

  log "Building pinned AmneziaWG userspace fallback ${AWG_GO_TAG} (${AWG_GO_COMMIT})"
  if [[ -z "${LINUX_REVIEWED_GO_BIN:-}" ]] || ! declare -F wins_release_go_run >/dev/null 2>&1; then
    echo "Reviewed Go binary is required before compiling amneziawg-go." >&2
    return 65
  fi
  go_bin="${LINUX_REVIEWED_GO_BIN:-}"
  if [[ "${store_sources}" == "1" ]]; then
    awg_go_declared_source="${WINS_ENGINE_SOURCE_ROOT}/amneziawg-go"
    [[ -d "${awg_go_declared_source}" && ! -L "${awg_go_declared_source}" ]] || {
      echo "declared amneziawg-go source is missing." >&2
      return 65
    }
    awg_go_source_before="$(linux_winn3_source_tree_sha256 "${awg_go_declared_source}")" || return 65
    awg_go_source="$tmp_dir/amneziawg-go-bound-source"
    mkdir -p "${awg_go_source}"
    cp -a "${awg_go_declared_source}/." "${awg_go_source}/"
    awg_go_source_after="$(linux_winn3_source_tree_sha256 "${awg_go_declared_source}")" || return 65
    awg_go_bound_source="$(linux_winn3_source_tree_sha256 "${awg_go_source}")" || return 65
    [[ "${awg_go_source_before}" == "${awg_go_source_after}" && \
       "${awg_go_source_before}" == "${awg_go_bound_source}" ]] || {
      echo "Compiler-consumed amneziawg-go source does not match the authenticated staging source." >&2
      return 65
    }
  else
    winsvpn_curl_verified_snapshot \
      "https://github.com/amnezia-vpn/amneziawg-go/archive/${AWG_GO_COMMIT}.tar.gz" \
      "${AWG_GO_SOURCE_SHA256}" \
      "$tmp_dir/amneziawg-go-${AWG_GO_COMMIT}.tar.gz.snap" || return 65
    winsvpn_extract_snapshot \
      "$tmp_dir/amneziawg-go-${AWG_GO_COMMIT}.tar.gz.snap" \
      "$tmp_dir" tar.gz || return 65
    awg_go_source="$tmp_dir/amneziawg-go-${AWG_GO_COMMIT}"
  fi
  grep -Fxq 'go 1.25.0' "$awg_go_source/go.mod" || {
    echo "Pinned amneziawg-go source has an unexpected Go language version." >&2
    return 65
  }
  export GOENV=off
  export GOTOOLCHAIN=local
  export GOPRIVATE=
  export GONOPROXY=
  export GONOSUMDB=
  if [[ "${store_sources}" == "1" ]]; then
    export GOMODCACHE="${WINS_STORE_GOMODCACHE:?}"
    [[ "${GOMODCACHE}" != "${HOME}/go/pkg/mod" ]] || {
      echo "refusing dirty host Go module cache" >&2
      return 65
    }
    export GOCACHE="${WINS_STORE_GOCACHE:?}"
  else
    export GOMODCACHE="$tmp_dir/go-mod-cache"
    export GOCACHE="$tmp_dir/go-build-cache"
  fi
  export CGO_ENABLED=0
  export GOOS=linux
  export GOARCH="${LINUX_RELEASE_GOARCH}"
  if [[ "${LINUX_RELEASE_GOARCH}" == "amd64" ]]; then
    export GOAMD64=v1
  else
    unset GOAMD64
  fi
  export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:?}"
  (
    cd "$awg_go_source"
    if [[ "${store_sources}" != "1" ]]; then
      wins_release_go_run mod download
    fi
    wins_release_go_run mod verify
    wins_release_go_run build -mod=readonly -trimpath -buildvcs=false \
      -ldflags='-s -w -buildid=' -o "$tmp_dir/amneziawg-go" .
  )
  case "${LINUX_RELEASE_GOARCH}" in
    amd64) expected_awg_go_binary_sha256="${AWG_GO_BINARY_SHA256}" ;;
    arm64) expected_awg_go_binary_sha256="${AWG_GO_BINARY_SHA256_ARM64}" ;;
    *) echo "No pinned reproducible-build hash for amneziawg-go on Linux ${LINUX_RELEASE_GOARCH}." >&2; return 65 ;;
  esac
  if [[ "${LINUX_RELEASE_GOARCH}" == "arm64" ]]; then
    python3 "$ROOT/tools/test_linux_arm64_fallback_elf.py" verify amneziawg-go \
      "$tmp_dir/amneziawg-go" --sha256 "${expected_awg_go_binary_sha256}"
  fi
  winsvpn_stage_bound_engine "$tmp_dir/amneziawg-go" "$dest_abs/amneziawg-go" "amneziawg-go" "${expected_awg_go_binary_sha256}" || return 65
  install -D -m 0644 "$awg_go_source/LICENSE" \
    "$dest_abs/share/doc/wins-vpn/licenses/amneziawg-go-MIT.txt"

  log "Building mandatory pinned Xray ${XRAY_VERSION} Linux ${LINUX_RELEASE_ARCH_LABEL} binary from source"
  mkdir -p "$tmp_dir/xray"
  if [[ "${store_sources}" == "1" ]]; then
    xray_declared_source="${WINS_ENGINE_SOURCE_ROOT}/xray-core"
    [[ -d "${xray_declared_source}" && ! -L "${xray_declared_source}" ]] || {
      echo "declared Xray source is missing." >&2
      return 65
    }
    xray_source_before="$(linux_winn3_source_tree_sha256 "${xray_declared_source}")" || return 65
    export XRAY_SOURCE_DIR="$tmp_dir/xray-bound-source"
    mkdir -p "${XRAY_SOURCE_DIR}"
    cp -a "${xray_declared_source}/." "${XRAY_SOURCE_DIR}/"
    xray_source_after="$(linux_winn3_source_tree_sha256 "${xray_declared_source}")" || return 65
    xray_bound_source="$(linux_winn3_source_tree_sha256 "${XRAY_SOURCE_DIR}")" || return 65
    [[ "${xray_source_before}" == "${xray_source_after}" && \
       "${xray_source_before}" == "${xray_bound_source}" ]] || {
      echo "Compiler-consumed Xray source does not match the authenticated staging source." >&2
      return 65
    }
  else
    unset XRAY_SOURCE_DIR || true
  fi
  export -f wins_release_go_run
  bash "$ROOT/tools/build_xray_engine.sh" "linux-${LINUX_RELEASE_GOARCH}" \
    "$tmp_dir/xray/xray" "$tmp_dir/xray/LICENSE"
  if [[ ! -x "$tmp_dir/xray/xray" ]]; then
    echo "build_xray_engine.sh did not produce an executable xray binary." >&2
    return 65
  fi
  [[ "$(sha256sum "$tmp_dir/xray/LICENSE" | awk '{print $1}')" == "${XRAY_LICENSE_SHA256}" ]] || {
    echo "Pinned Xray ${XRAY_VERSION} license SHA-256 verification failed." >&2
    return 65
  }
  case "${LINUX_RELEASE_GOARCH}" in
    amd64) expected_xray_sha256="${XRAY_SHA256_AMD64}" ;;
    arm64) expected_xray_sha256="${XRAY_SHA256_ARM64}" ;;
    *) echo "No Xray output pin policy for Linux ${LINUX_RELEASE_GOARCH}." >&2; return 65 ;;
  esac
  if [[ "${LINUX_RELEASE_GOARCH}" == "arm64" ]]; then
    python3 "$ROOT/tools/test_linux_arm64_fallback_elf.py" verify xray \
      "$tmp_dir/xray/xray" --sha256 "${expected_xray_sha256}"
  fi
  winsvpn_stage_bound_engine "$tmp_dir/xray/xray" "$dest_abs/xray" "xray" "${expected_xray_sha256}" || return 65
  install -D -m 0644 "$tmp_dir/xray/LICENSE" \
    "$dest_abs/share/doc/wins-vpn/licenses/Xray-core-MPL-2.0.txt"

  python3 "$ROOT/tools/test_linux_arm64_fallback_elf.py" verify awg-quick \
    "$dest_abs/awg-quick" --sha256 "${AWG_QUICK_SHA256}"
  if [[ "${LINUX_RELEASE_GOARCH}" == "arm64" ]]; then
    python3 "$ROOT/tools/test_linux_arm64_fallback_elf.py" verify-dir "$dest_abs"
  fi
  for required_engine in winn-datapath awg awg-quick amneziawg-go xray; do
    if [[ ! -f "$dest_abs/$required_engine" || -L "$dest_abs/$required_engine" ]]; then
      echo "Engine staging omitted required payload: $required_engine" >&2
      return 65
    fi
  done
}

acquire_build_lock() {
  local owner="owner metadata is not available"
  mkdir -p -- "$(dirname "${build_lock_dir}")"
  if ! mkdir -- "${build_lock_dir}" 2>/dev/null; then
    if [[ -s "${build_lock_owner_file}" ]]; then
      owner="$(tr '\n' ' ' <"${build_lock_owner_file}")"
    fi
    printf 'Another Windows/WSL release build owns %s. %s. Wait for it to finish; never delete an active lock.\n' \
      "${build_lock_dir}" "${owner}" >&2
    return 73
  fi
  build_lock_acquired=1
  printf 'platform=linux\npid=%s\nstarted_utc=%s\n' \
    "$$" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" >"${build_lock_owner_file}"
}

resolve_release_input_index() {
  local index_input="${WINS_RELEASE_INPUT_INDEX:-}"
  local index_path
  [[ -n "${index_input}" ]] || {
    echo "Every Linux release build requires WINS_RELEASE_INPUT_INDEX." >&2
    return 65
  }
  if [[ "${index_input}" == /* ]]; then
    index_path="$(realpath -e -- "${index_input}")"
  else
    index_path="$(realpath -e -- "${ROOT}/${index_input}")"
  fi
  case "${index_path}" in
    "${ROOT}"/.artifacts/*/RELEASE_INPUT_INDEX.json) ;;
    *)
      echo "WINS_RELEASE_INPUT_INDEX must name a repository .artifacts RELEASE_INPUT_INDEX.json." >&2
      return 65
      ;;
  esac
  printf '%s\n' "${index_path}"
}

# Bind this build to the exact RELEASE_INPUT_INDEX.json bytes and derive the
# one reproducible SOURCE_DATE_EPOCH from that index (created_utc, whole
# seconds). The index must be a strict, exact-schema JSON object. A caller
# SOURCE_DATE_EPOCH is accepted only when it equals the derived value, so the
# WSL neutral child (which inherits the parent's export) and any rebuild of the
# same index produce byte-identical archives.
resolve_linux_release_controls() {
  local index_path="$1"
  local -a controls=()
  [[ "${index_path}" == /* ]] || {
    release_refused "the release input index path must be absolute: ${index_path}"
    return $?
  }
  mapfile -t controls < <(python3 -I - "${index_path}" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import stat
import sys

index_path = pathlib.Path(sys.argv[1])

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"RELEASE REFUSED: duplicate release index JSON key: {key}")
        result[key] = value
    return result

def reject_nonfinite(value):
    raise SystemExit(f"RELEASE REFUSED: non-finite release index JSON number: {value}")

try:
    before = index_path.lstat()
except FileNotFoundError as exc:
    raise SystemExit(f"RELEASE REFUSED: release input index is absent: {index_path}") from exc
if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
    raise SystemExit("RELEASE REFUSED: release input index is not a single-link regular file")
if before.st_mode & 0o022:
    raise SystemExit("RELEASE REFUSED: release input index is group/other-writable")
fd = os.open(index_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
try:
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        raise SystemExit("RELEASE REFUSED: release input index changed while opened")
    if opened.st_size <= 0 or opened.st_size > 16 * 1024 * 1024:
        raise SystemExit("RELEASE REFUSED: release input index size is invalid")
    index_bytes = os.pread(fd, opened.st_size, 0)
finally:
    os.close(fd)
if len(index_bytes) != opened.st_size:
    raise SystemExit("RELEASE REFUSED: release input index was truncated while read")
try:
    index = json.loads(
        index_bytes.decode("utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonfinite,
    )
except (UnicodeDecodeError, ValueError) as exc:
    raise SystemExit(f"RELEASE REFUSED: release input index is not strict JSON: {exc}") from exc
expected_index_keys = {
    "contract", "created_utc", "manifest_set_complete", "platform_manifests",
    "publication_authorized", "release", "schema_version", "sha256_anchor",
    "shared_manifest", "shared_revision",
}
if not isinstance(index, dict) or set(index) != expected_index_keys:
    raise SystemExit("RELEASE REFUSED: release index fields are not exact")
if (
    index["contract"] != "winsvpn-release-input-index-v1"
    or type(index["schema_version"]) is not int
    or index["schema_version"] != 1
):
    raise SystemExit("RELEASE REFUSED: release index contract is invalid")
created = index["created_utc"]
if not isinstance(created, str) or not created.endswith("Z"):
    raise SystemExit("RELEASE REFUSED: release index created_utc is not a UTC timestamp")
try:
    moment = datetime.datetime.fromisoformat(created[:-1] + "+00:00")
except ValueError as exc:
    raise SystemExit("RELEASE REFUSED: release index created_utc is not a UTC timestamp") from exc
if moment.utcoffset() != datetime.timedelta(0):
    raise SystemExit("RELEASE REFUSED: release index created_utc is not UTC")
# Whole seconds, floor: the same integer tools/build_linux_arm64_awg.sh
# derives, so the arm64 AWG child accepts the exported value.
epoch = (moment - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)) // datetime.timedelta(seconds=1)
if not 0 < epoch <= 253402300799:
    raise SystemExit("RELEASE REFUSED: release index created_utc is out of range")
print(epoch)
print(hashlib.sha256(index_bytes).hexdigest())
PY
  ) || return 65
  [[ "${#controls[@]}" == 2 && "${controls[0]}" =~ ^[0-9]+$ && \
     "${controls[1]}" =~ ^[0-9a-f]{64}$ ]] || {
    release_refused "the release input index controls were not resolved"
    return $?
  }
  if [[ -n "${SOURCE_DATE_EPOCH+x}" && "${SOURCE_DATE_EPOCH}" != "${controls[0]}" ]]; then
    release_refused "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} differs from the release index created_utc epoch ${controls[0]}; unset it or pass exactly that value"
    return $?
  fi
  SOURCE_DATE_EPOCH="${controls[0]}"
  LINUX_RELEASE_INDEX_SHA256="${controls[1]}"
  export SOURCE_DATE_EPOCH
}

initialize_formal_linux_receipt() {
  local index_path="$1"
  local requested receipt_parent index_hash index_directory namespace cursor part relative
  local -a receipt_components=()
  requested="${WINS_LINUX_BUILD_RECEIPT_DIR:-}"
  if [[ -z "${requested}" ]]; then
    index_hash="$(sha256sum "${index_path}" | awk '{print $1}')"
    [[ "${index_hash}" =~ ^[0-9a-f]{64}$ ]] || {
      echo "Could not derive the immutable release-index identity for Linux receipts." >&2
      return 65
    }
    # Keep per-run evidence out of the immutable release-manifest control set.
    # Each index receives its own private receipt namespace.
    namespace="${ROOT}/.artifacts/release-build-receipts/linux/${index_hash}"
    cursor="${ROOT}/.artifacts"
    [[ -d "${cursor}" && ! -L "${cursor}" ]] || {
      echo "The repository .artifacts directory is missing or unsafe." >&2
      return 65
    }
    for part in release-build-receipts linux "${index_hash}"; do
      cursor="${cursor}/${part}"
      if [[ -e "${cursor}" || -L "${cursor}" ]]; then
        [[ -d "${cursor}" && ! -L "${cursor}" ]] || {
          echo "Linux build receipt namespace is not a regular directory: ${cursor}" >&2
          return 65
        }
      else
        mkdir -m 0700 -- "${cursor}"
      fi
    done
    requested="${namespace}/linux-build-$(date -u +'%Y%m%dT%H%M%S%NZ')-$$-${RANDOM}${RANDOM}"
  elif [[ "${requested}" != /* ]]; then
    requested="${ROOT}/${requested}"
  fi
  formal_receipt_dir="$(realpath -m -s -- "${requested}")"
  index_directory="$(dirname "$(realpath -e -- "${index_path}")")"
  case "${formal_receipt_dir}" in
    "${ROOT}"/.artifacts/*) ;;
    *)
      echo "WINS_LINUX_BUILD_RECEIPT_DIR must stay under the repository .artifacts directory." >&2
      return 65
      ;;
  esac
  relative="${formal_receipt_dir#"${ROOT}/"}"
  cursor="${ROOT}"
  IFS='/' read -r -a receipt_components <<<"${relative}"
  for part in "${receipt_components[@]}"; do
    cursor="${cursor}/${part}"
    if [[ -e "${cursor}" || -L "${cursor}" ]]; then
      [[ ! -L "${cursor}" ]] || {
        echo "Linux build receipt path traverses a symbolic link: ${cursor}" >&2
        return 65
      }
    fi
  done
  case "${formal_receipt_dir}" in
    "${index_directory}"|"${index_directory}"/*)
      echo "Linux build receipts must stay outside the immutable release-manifest directory." >&2
      return 65
      ;;
  esac
  [[ ! -e "${formal_receipt_dir}" && ! -L "${formal_receipt_dir}" ]] || {
    echo "Linux build receipt directory must be a new immutable path: ${formal_receipt_dir}" >&2
    return 65
  }
  receipt_parent="$(dirname "${formal_receipt_dir}")"
  [[ -d "${receipt_parent}" && ! -L "${receipt_parent}" ]] || {
    echo "Linux build receipt parent must be an existing regular directory: ${receipt_parent}" >&2
    return 65
  }
  mkdir -m 0700 -- "${formal_receipt_dir}"
  formal_begin_receipt="${formal_receipt_dir}/LINUX_BUILD_BEGIN.json"
  formal_build_receipt="${formal_receipt_dir}/LINUX_BUILD_RECEIPT.json"
  if linux_remote_attested; then
    # The macOS release host already ran begin-build for this remote run.
    verify_linux_release_inputs_unchanged "${index_path}"
    return $?
  fi
  python3 "${ROOT}/tools/release_dependency_freeze.py" begin-build \
    --repo "${ROOT}" --index "${index_path}" --platform linux \
    --output "${formal_begin_receipt}"
}

complete_formal_linux_receipt() {
  local index_path="$1"
  local archive="$2"
  [[ -n "${formal_begin_receipt}" && -n "${formal_build_receipt}" ]] || {
    echo "Linux formal receipt state was not initialized." >&2
    return 65
  }
  # The formal receipt hashes the exact archive. Revalidate the attestation
  # inside that archive immediately before finish-build so the receipt's
  # artifact digest transitively binds the single true define, capable native
  # gates, producer bytes, runner, AOT payload, and winn-datapath bytes.
  verify_linux_winn3_dual_auth_archive "${archive}" || return $?
  if linux_remote_attested; then
    complete_remote_attested_linux_run "${index_path}" "${archive}"
    return $?
  fi
  python3 "${ROOT}/tools/release_dependency_freeze.py" finish-build \
    --repo "${ROOT}" --index "${index_path}" --platform linux \
    --begin "${formal_begin_receipt}" --artifact "${archive}" \
    --producer tools/build_linux_release.sh \
    --toolchain-name Flutter --toolchain-version "${REQUIRED_FLUTTER_VERSION}" \
    --toolchain-revision "${REQUIRED_FLUTTER_REVISION}" \
    --target "linux-${LINUX_RELEASE_ARCH_LABEL:-x64}" --output "${formal_build_receipt}"
  python3 "${ROOT}/tools/release_dependency_freeze.py" verify-receipt \
    --repo "${ROOT}" --index "${index_path}" --platform linux \
    --receipt "${formal_build_receipt}" --artifact "${archive}"
  log "Formal Linux build receipt verified: ${formal_build_receipt}"
}

# Remote-attested mode (round R11a). The dependency-freeze worker runs only on
# the macOS release host. tools/release_remote_build.py prepare ran begin-build
# there, shipped the frozen source tar and wrote REMOTE_INPUT.json, which
# WINS_REMOTE_ATTESTATION_INPUT names; only that orchestrator sets it. Every
# direct controller call becomes tools/release_remote_attestation_check.py
# verify-inputs (the shipped index, manifests and every manifest file against
# the digests the Mac recorded), and the receipt step writes REMOTE_RUN.json
# next to REMOTE_INPUT.json for finish-build --remote-host on the Mac, which
# validates the copied-back archive bytes against the begin record.
linux_remote_attested() {
  [[ -n "${WINS_REMOTE_ATTESTATION_INPUT:-}" ]]
}

assert_linux_remote_attestation_mode() {
  linux_remote_attested || return 0
  [[ "${WINS_REMOTE_ATTESTATION_INPUT}" == /* && -f "${WINS_REMOTE_ATTESTATION_INPUT}" && \
     ! -L "${WINS_REMOTE_ATTESTATION_INPUT}" ]] || {
    release_refused "WINS_REMOTE_ATTESTATION_INPUT must name an absolute regular REMOTE_INPUT.json"
    return $?
  }
  [[ "${ROOT}" != /mnt/* && "${WINS_LINUX_NEUTRAL_STAGE_ACTIVE:-0}" == "0" ]] || {
    release_refused "remote-attested Linux builds run from a native checkout, not the WSL neutral stage"
    return $?
  }
  [[ ! -e "$(dirname "${WINS_REMOTE_ATTESTATION_INPUT}")/REMOTE_RUN.json" ]] || {
    release_refused "REMOTE_RUN.json already exists for this remote-attested run"
    return $?
  }
  [[ "${SIGN_LINUX_RELEASE:-0}" == "0" ]] || {
    release_refused "remote-attested Linux builds never hold the cosign key; set WINS_LINUX_SIGNING_DEFERRED_TO_ORCHESTRATOR=1 and sign on the macOS release host"
    return $?
  }
}

# Signing deferral (round R11a). The cosign key stays on the macOS release
# host. tools/release_remote_build.py sets WINS_LINUX_SIGNING_DEFERRED_TO_ORCHESTRATOR=1
# together with WINS_REMOTE_ATTESTATION_INPUT: the remote run then stops before
# its signing step, records signing=orchestrator in REMOTE_RUN.json, and the Mac
# signs the copied-back archive with tools/linux_release_signing.py before
# finish-build. Any other run (a normal release on its own host) cannot defer:
# it signs with SIGN_LINUX_RELEASE=1 or is an unsigned rehearsal.
assert_linux_signing_deferral_mode() {
  case "${WINS_LINUX_SIGNING_DEFERRED_TO_ORCHESTRATOR:-0}" in
    0) return 0 ;;
    1) ;;
    *)
      release_refused "WINS_LINUX_SIGNING_DEFERRED_TO_ORCHESTRATOR must be 0 or 1"
      return $?
      ;;
  esac
  linux_remote_attested || {
    release_refused "signing can be deferred only to the macOS orchestrator of a remote-attested run; a normal release run cannot skip signing"
    return $?
  }
  [[ "${SIGN_LINUX_RELEASE:-0}" == "0" ]] || {
    release_refused "a signing-deferred remote run must not sign on the build host"
    return $?
  }
}

linux_remote_signing_mode() {
  if [[ "${WINS_LINUX_SIGNING_DEFERRED_TO_ORCHESTRATOR:-0}" == "1" ]]; then
    printf 'orchestrator\n'
  else
    printf 'unsigned\n'
  fi
}

verify_linux_release_inputs_unchanged() {
  local index_path="$1"
  if linux_remote_attested; then
    python3 "${ROOT}/tools/release_remote_attestation_check.py" verify-inputs \
      --repo "${ROOT}" --input "${WINS_REMOTE_ATTESTATION_INPUT}" --index "${index_path}"
    return $?
  fi
  python3 "${ROOT}/tools/release_dependency_freeze.py" verify-index \
    --repo "${ROOT}" --index "${index_path}"
}

complete_remote_attested_linux_run() {
  local index_path="$1"
  local archive="$2"
  local run_record
  run_record="$(dirname "${WINS_REMOTE_ATTESTATION_INPUT}")/REMOTE_RUN.json"
  verify_linux_release_inputs_unchanged "${index_path}" || return $?
  python3 "${ROOT}/tools/release_remote_attestation_check.py" record-run \
    --repo "${ROOT}" --input "${WINS_REMOTE_ATTESTATION_INPUT}" \
    --artifact "${archive}" \
    --toolchain-name Flutter --toolchain-version "${REQUIRED_FLUTTER_VERSION}" \
    --toolchain-revision "${REQUIRED_FLUTTER_REVISION}" \
    --target "linux-${LINUX_RELEASE_ARCH_LABEL:-x64}" --output "${run_record}" \
    --signing "$(linux_remote_signing_mode)" || return $?
  log "Remote-attested Linux run record written: ${run_record} (finish-build runs on the macOS release host)"
}

reject_unsupported_release_switches() {
  if [[ "${SKIP_XRAY_DOWNLOAD:-0}" != "0" ]]; then
    echo "SKIP_XRAY_DOWNLOAD is not supported for a release build; pinned Xray is mandatory for Single VPN and Double VPN fallback." >&2
    return 65
  fi
}

initialize_linux_output_paths() {
  local index_path="$1"
  local requested lexical index_directory relative current part output
  local -a components=()

  requested="${WINS_LINUX_OUT_DIR:-${ROOT}/web/downloads}"
  [[ "${requested}" != *$'\n'* && "${requested}" != *$'\r'* ]] || {
    echo "WINS_LINUX_OUT_DIR contains an unsafe line break." >&2
    return 65
  }
  if [[ "${requested}" != /* ]]; then
    requested="${ROOT}/${requested}"
  fi
  lexical="$(realpath -m -s -- "${requested}")"
  case "${lexical}" in
    "${ROOT}"/*) ;;
    *)
      echo "WINS_LINUX_OUT_DIR must stay inside the repository." >&2
      return 65
      ;;
  esac
  index_directory="$(dirname "$(realpath -e -- "${index_path}")")"
  case "${lexical}" in
    "${index_directory}"|"${index_directory}"/*)
      echo "Linux release outputs must not be written into the immutable release-manifest directory." >&2
      return 65
      ;;
  esac

  relative="${lexical#"${ROOT}/"}"
  IFS='/' read -r -a components <<<"${relative}"
  current="${ROOT}"
  for part in "${components[@]}"; do
    [[ -n "${part}" && "${part}" != "." && "${part}" != ".." ]] || {
      echo "WINS_LINUX_OUT_DIR contains an unsafe path component." >&2
      return 65
    }
    current="${current}/${part}"
    if [[ -e "${current}" || -L "${current}" ]]; then
      [[ -d "${current}" && ! -L "${current}" ]] || {
        echo "Linux release output path traverses a non-directory or symbolic link: ${current}" >&2
        return 65
      }
    else
      mkdir -m 0755 -- "${current}"
    fi
  done
  OUT_DIR="$(realpath -e -- "${lexical}")"
  [[ "${OUT_DIR}" == "${lexical}" ]] || {
    echo "Linux release output path changed while it was being validated." >&2
    return 65
  }

  ARCHIVE="${OUT_DIR}/wins-vpn-linux-${LINUX_RELEASE_ARCH_LABEL:-x64}.tar.gz"
  ARCHIVE_SHA_PATH="${ARCHIVE}.sha256"
  BUNDLE_PATH="${ARCHIVE}.sigstore.json"
  for output in "${ARCHIVE}" "${ARCHIVE_SHA_PATH}" "${BUNDLE_PATH}"; do
    if [[ -e "${output}" || -L "${output}" ]]; then
      [[ -f "${output}" && ! -L "${output}" ]] || {
        echo "Existing Linux release output is not a regular non-symlink file: ${output}" >&2
        return 65
      }
    fi
  done
}

prepare_linux_publication_stage() {
  local private_stage_root="${LINUX_PRIVATE_PUBLICATION_ROOT}/.staging"
  [[ -n "${OUT_DIR}" && -d "${OUT_DIR}" && ! -L "${OUT_DIR}" ]] || {
    echo "Linux release output directory was not initialized safely." >&2
    return 65
  }
  mkdir -p -- "${private_stage_root}"
  chmod 0700 "$(dirname "${LINUX_PRIVATE_PUBLICATION_ROOT}")" \
    "${LINUX_PRIVATE_PUBLICATION_ROOT}" "${private_stage_root}"
  publication_stage_dir="$(mktemp -d "${private_stage_root}/generation.XXXXXX")"
  chmod 0700 "${publication_stage_dir}"
  staged_archive="${publication_stage_dir}/$(basename "${ARCHIVE}")"
  staged_archive_sha="${publication_stage_dir}/$(basename "${ARCHIVE_SHA_PATH}")"
  staged_bundle="${publication_stage_dir}/$(basename "${BUNDLE_PATH}")"
  staged_installer_bootstrap="${publication_stage_dir}/install-winsvpn-linux.sh"
  staged_publication_receipt="${publication_stage_dir}/LINUX_PUBLICATION_RECEIPT.json"
  staged_publication_receipt_bundle="${publication_stage_dir}/LINUX_PUBLICATION_RECEIPT.json.sigstore.json"
  install -m 0755 -- \
    "${ROOT}/linux/packaging/install-winsvpn-linux.sh" \
    "${staged_installer_bootstrap}"
  staged_private_symbols="${publication_stage_dir}/private-symbols"
}

stage_linux_private_symbols() {
  local source="$1"
  [[ -d "${publication_stage_dir}" && ! -L "${publication_stage_dir}" ]] || {
    echo "Linux publication stage is unavailable for private symbols." >&2
    return 65
  }
  [[ -d "${source}" && ! -L "${source}" ]] || {
    echo "Linux private symbol source is missing or unsafe." >&2
    return 65
  }
  [[ ! -e "${staged_private_symbols}" && ! -L "${staged_private_symbols}" ]] || {
    echo "Linux private symbols were already staged." >&2
    return 65
  }
  python3 -I - "${source}" "${publication_stage_dir}" "$(basename "${staged_private_symbols}")" <<'PY'
import hashlib
import os
import stat
import sys

source_path, destination_parent, destination_name = sys.argv[1:]
directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
source_before = os.lstat(source_path)
if stat.S_ISLNK(source_before.st_mode) or not stat.S_ISDIR(source_before.st_mode):
    raise SystemExit("Linux private symbol source root is unsafe")
source_fd = os.open(source_path, directory_flags)
destination_parent_fd = os.open(destination_parent, directory_flags)
try:
    source_opened = os.fstat(source_fd)
    if (source_opened.st_dev, source_opened.st_ino) != (source_before.st_dev, source_before.st_ino):
        raise SystemExit("Linux private symbol source changed while opened")
    os.mkdir(destination_name, 0o700, dir_fd=destination_parent_fd)
    destination_fd = os.open(destination_name, directory_flags, dir_fd=destination_parent_fd)
    try:
        def copy_directory(src_fd: int, dst_fd: int, relative: str) -> None:
            names = sorted(os.listdir(src_fd))
            for name in names:
                if name in {".", ".."} or "/" in name or "\0" in name:
                    raise SystemExit("Linux private symbol member name is unsafe")
                info = os.stat(name, dir_fd=src_fd, follow_symlinks=False)
                child_relative = f"{relative}/{name}" if relative else name
                if stat.S_ISDIR(info.st_mode):
                    os.mkdir(name, 0o700, dir_fd=dst_fd)
                    child_src = os.open(name, directory_flags, dir_fd=src_fd)
                    child_dst = os.open(name, directory_flags, dir_fd=dst_fd)
                    try:
                        opened = os.fstat(child_src)
                        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                            raise SystemExit(f"Linux private symbol directory changed while opened: {child_relative}")
                        copy_directory(child_src, child_dst, child_relative)
                        os.fsync(child_dst)
                    finally:
                        os.close(child_dst)
                        os.close(child_src)
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise SystemExit(f"Linux private symbol member is not a single-link regular file: {child_relative}")
                src_file = os.open(name, file_flags, dir_fd=src_fd)
                dst_file = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=dst_fd,
                )
                try:
                    opened = os.fstat(src_file)
                    if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
                        raise SystemExit(f"Linux private symbol file changed while opened: {child_relative}")
                    digest = hashlib.sha256()
                    offset = 0
                    while offset < opened.st_size:
                        block = os.pread(src_file, min(1024 * 1024, opened.st_size - offset), offset)
                        if not block:
                            raise SystemExit(f"Linux private symbol file truncated: {child_relative}")
                        digest.update(block)
                        view = memoryview(block)
                        while view:
                            view = view[os.write(dst_file, view):]
                        offset += len(block)
                    os.fsync(dst_file)
                    os.fchmod(dst_file, 0o600)
                    os.lseek(dst_file, 0, os.SEEK_SET)
                finally:
                    os.close(dst_file)
                    os.close(src_file)
            os.fsync(dst_fd)

        copy_directory(source_fd, destination_fd, "")
    finally:
        os.close(destination_fd)
    os.fsync(destination_parent_fd)
finally:
    os.close(destination_parent_fd)
    os.close(source_fd)
PY
}

write_linux_publication_receipt() {
  local mode archive_read checksum_read bootstrap_read bundle_read symbols_read
  if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
    mode=signed
  else
    mode=unsigned-rehearsal
  fi
  archive_read="$(linux_publication_custody_path_for_read "${staged_archive}")" || return $?
  checksum_read="$(linux_publication_custody_path_for_read "${staged_archive_sha}")" || return $?
  bootstrap_read="$(linux_publication_custody_path_for_read "${staged_installer_bootstrap}")" || return $?
  symbols_read="$(linux_publication_custody_path_for_read "${staged_private_symbols}")" || return $?
  if [[ "${mode}" == "signed" ]]; then
    bundle_read="$(linux_publication_custody_path_for_read "${staged_bundle}")" || return $?
  else
    bundle_read="${staged_bundle}"
  fi
  python3 -I - \
    "${staged_publication_receipt}" "${archive_read}" "${bundle_read}" \
    "${checksum_read}" "${bootstrap_read}" "${staged_archive}" \
    "${staged_archive_sha}" "${staged_installer_bootstrap}" \
    "${symbols_read}" "${mode}" "${LINUX_RELEASE_INDEX_SHA256:-}" \
    "${SOURCE_DATE_EPOCH:-}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

(
    output_raw, archive_raw, bundle_raw, checksum_raw, bootstrap_raw,
    archive_name_raw, checksum_name_raw, bootstrap_name_raw, symbols_raw, mode,
    release_index_sha256, source_date_epoch_raw,
) = sys.argv[1:]
output = pathlib.Path(output_raw)
archive = pathlib.Path(archive_raw)
bundle = pathlib.Path(bundle_raw)
checksum = pathlib.Path(checksum_raw)
bootstrap = pathlib.Path(bootstrap_raw)
archive_name = pathlib.Path(archive_name_raw)
checksum_name = pathlib.Path(checksum_name_raw)
bootstrap_name = pathlib.Path(bootstrap_name_raw)
symbols = pathlib.Path(symbols_raw)
if mode not in {"signed", "unsigned-rehearsal"}:
    raise SystemExit("Linux publication receipt mode is invalid")
if re.fullmatch(r"[0-9a-f]{64}", release_index_sha256) is None:
    raise SystemExit("Linux publication receipt control digest is malformed: release_index_sha256")
try:
    source_date_epoch = int(source_date_epoch_raw)
except ValueError as exc:
    raise SystemExit("Linux publication receipt SOURCE_DATE_EPOCH is invalid") from exc

def descriptor_path(raw: str) -> bool:
    return (
        re.fullmatch(r"/proc/[0-9]+/fd/[0-9]+", raw) is not None
        or re.fullmatch(r"/dev/fd/[0-9]+", raw) is not None
    )

def held_fd(raw):
    # The descriptor paths name descriptors this process inherited from the
    # producer shell, so read and stat them directly with pread/fstat.
    return int(raw.rsplit("/", 1)[1]) if descriptor_path(raw) else None

def read_all(path, raw):
    fd = held_fd(raw)
    if fd is None:
        return path.read_bytes()
    chunks = []
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            return b"".join(chunks)
        chunks.append(block)
        offset += len(block)

def digest(path: pathlib.Path, raw: str = "") -> str:
    return hashlib.sha256(read_all(path, raw)).hexdigest()

def regular_record(path: pathlib.Path, raw: str, label: str, expected_mode: int) -> dict[str, object]:
    fd = held_fd(raw)
    info = os.fstat(fd) if fd is not None else path.lstat()
    if (not descriptor_path(raw) and stat.S_ISLNK(info.st_mode)) or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"Linux publication {label} is not a regular retained file")
    if info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != expected_mode or info.st_size <= 0:
        raise SystemExit(f"Linux publication {label} identity is unsafe")
    return {"sha256": digest(path, raw), "bytes": info.st_size, "mode": expected_mode}

archive_record = regular_record(archive, archive_raw, "archive", 0o644)
checksum_record = regular_record(checksum, checksum_raw, "archive checksum", 0o644)
bootstrap_record = regular_record(bootstrap, bootstrap_raw, "installer bootstrap", 0o755)
expected_checksum = f"{archive_record['sha256']}  {archive_name.name}\n".encode("ascii")
if read_all(checksum, checksum_raw) != expected_checksum:
    raise SystemExit("Linux publication archive checksum does not exactly bind the archive")
if checksum_name.name != archive_name.name + ".sha256":
    raise SystemExit("Linux publication archive checksum basename is wrong")
if bootstrap_name.name != "install-winsvpn-linux.sh":
    raise SystemExit("Linux publication installer bootstrap basename is wrong")
if not descriptor_path(symbols_raw) and symbols.is_symlink():
    raise SystemExit("Linux publication receipt symbol root is unsafe")
symbols_fd = (
    os.dup(held_fd(symbols_raw))
    if descriptor_path(symbols_raw)
    else os.open(
        symbols,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
    )
)
if not stat.S_ISDIR(os.fstat(symbols_fd).st_mode):
    os.close(symbols_fd)
    raise SystemExit("Linux publication symbol root is not a directory")
symbol_records = []
symbol_counters = [0, 0]

def collect_symbols(directory_fd, prefix=""):
    for name in sorted(os.listdir(directory_fd)):
        if not name or "/" in name or name in {".", ".."}:
            raise SystemExit("Linux publication symbol name is unsafe")
        relative = name if not prefix else f"{prefix}/{name}"
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        symbol_counters[0] += 1
        if symbol_counters[0] > 100000:
            raise SystemExit("Linux publication symbol inventory has too many members")
        if stat.S_ISDIR(info.st_mode):
            child_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                child = os.fstat(child_fd)
                if (child.st_dev, child.st_ino) != (info.st_dev, info.st_ino):
                    raise SystemExit("Linux publication symbol directory changed while opened")
                collect_symbols(child_fd, relative)
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 512 * 1024 * 1024:
            raise SystemExit(f"Linux publication symbol is unsafe: {relative}")
        child_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            child = os.fstat(child_fd)
            if (child.st_dev, child.st_ino, child.st_size) != (
                info.st_dev, info.st_ino, info.st_size
            ):
                raise SystemExit("Linux publication symbol changed while opened")
            symbol_counters[1] += child.st_size
            if symbol_counters[1] > 4 * 1024 * 1024 * 1024:
                raise SystemExit("Linux publication symbols exceed the aggregate byte bound")
            offset = 0
            digest_value = hashlib.sha256()
            while offset < child.st_size:
                block = os.pread(child_fd, min(1024 * 1024, child.st_size - offset), offset)
                if not block:
                    raise SystemExit("Linux publication symbol truncated while retained")
                digest_value.update(block)
                offset += len(block)
            symbol_records.append({
                "path": relative,
                "sha256": digest_value.hexdigest(),
                "bytes": child.st_size,
                "mode": stat.S_IMODE(child.st_mode),
            })
        finally:
            os.close(child_fd)

try:
    collect_symbols(symbols_fd)
finally:
    os.close(symbols_fd)
symbol_records.sort(key=lambda record: record["path"])
if not symbol_records or not any(record["path"] == "manifest.json" for record in symbol_records):
    raise SystemExit("Linux publication symbol inventory is empty or lacks manifest.json")
bundle_digest = None
if mode == "signed":
    bundle_digest = regular_record(bundle, bundle_raw, "archive Sigstore bundle", 0o644)["sha256"]
elif bundle.exists() or bundle.is_symlink():
    raise SystemExit("unsigned Linux publication receipt unexpectedly has a Sigstore bundle")
# Contract v3 (2026-10-09): the v2 owner_release_control_sha256 and
# owner_release_control_bundle_sha256 fields are removed with the retired
# owner release-control file.
document = {
    "schema_version": 3,
    "contract": "winsvpn-linux-publication-receipt-v3",
    "mode": mode,
    "source_date_epoch": source_date_epoch,
    "release_index_sha256": release_index_sha256,
    "archive": archive_record,
    "archive_checksum": checksum_record,
    "installer_bootstrap": bootstrap_record,
    "archive_sigstore_bundle_sha256": bundle_digest,
    "symbols": symbol_records,
}
encoded = (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
fd = os.open(
    output,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
    0o600,
)
try:
    view = memoryview(encoded)
    while view:
        view = view[os.write(fd, view):]
    os.fsync(fd)
    os.fchmod(fd, 0o600)
finally:
    os.close(fd)
PY
}

verify_linux_publication_receipt() {
  local receipt_read archive_read checksum_read bootstrap_read bundle_read symbols_read
  receipt_read="$(linux_publication_custody_path_for_read "${staged_publication_receipt}")" || return $?
  archive_read="$(linux_publication_custody_path_for_read "${staged_archive}")" || return $?
  checksum_read="$(linux_publication_custody_path_for_read "${staged_archive_sha}")" || return $?
  bootstrap_read="$(linux_publication_custody_path_for_read "${staged_installer_bootstrap}")" || return $?
  symbols_read="$(linux_publication_custody_path_for_read "${staged_private_symbols}")" || return $?
  if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
    bundle_read="$(linux_publication_custody_path_for_read "${staged_bundle}")" || return $?
  else
    bundle_read="${staged_bundle}"
  fi
  python3 -I - \
    "${receipt_read}" "${archive_read}" "${bundle_read}" \
    "${checksum_read}" "${bootstrap_read}" "${staged_archive}" \
    "${staged_archive_sha}" "${staged_installer_bootstrap}" \
    "${symbols_read}" "${SIGN_LINUX_RELEASE:-0}" \
    "${SOURCE_DATE_EPOCH:-}" "${LINUX_RELEASE_INDEX_SHA256:-}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

(
    receipt_path, archive_raw, bundle_raw, checksum_raw, bootstrap_raw,
    archive_name_raw, checksum_name_raw, bootstrap_name_raw, symbols_raw, signed_raw,
    expected_epoch_raw, expected_index,
) = sys.argv[1:]
archive = pathlib.Path(archive_raw)
bundle = pathlib.Path(bundle_raw)
checksum = pathlib.Path(checksum_raw)
bootstrap = pathlib.Path(bootstrap_raw)
archive_name = pathlib.Path(archive_name_raw)
checksum_name = pathlib.Path(checksum_name_raw)
bootstrap_name = pathlib.Path(bootstrap_name_raw)
symbols = pathlib.Path(symbols_raw)

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate Linux publication receipt key: {key}")
        result[key] = value
    return result

def reject_nonfinite(value):
    raise SystemExit(f"non-finite Linux publication receipt number: {value}")

receipt_descriptor = re.fullmatch(r"/(?:proc/[0-9]+|dev)/fd/([0-9]+)", receipt_path)
if receipt_descriptor is None:
    receipt_bytes = pathlib.Path(receipt_path).read_bytes()
else:
    receipt_chunks = []
    receipt_offset = 0
    while True:
        receipt_block = os.pread(int(receipt_descriptor.group(1)), 1024 * 1024, receipt_offset)
        if not receipt_block:
            break
        receipt_chunks.append(receipt_block)
        receipt_offset += len(receipt_block)
    receipt_bytes = b"".join(receipt_chunks)
receipt = json.loads(
    receipt_bytes.decode("ascii"),
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_nonfinite,
)
expected_keys = {
    "schema_version", "contract", "mode", "source_date_epoch",
    "release_index_sha256", "archive",
    "archive_checksum", "installer_bootstrap",
    "archive_sigstore_bundle_sha256", "symbols",
}
if not isinstance(receipt, dict) or set(receipt) != expected_keys:
    raise SystemExit("Linux publication receipt fields are not exact")
if receipt["schema_version"] != 3 or receipt["contract"] != "winsvpn-linux-publication-receipt-v3":
    raise SystemExit("Linux publication receipt contract is invalid")
expected_mode = "signed" if signed_raw == "1" else "unsigned-rehearsal"
if receipt["mode"] != expected_mode:
    raise SystemExit("Linux publication receipt mode is wrong")
try:
    expected_epoch = int(expected_epoch_raw)
except ValueError as exc:
    raise SystemExit("Linux publication verifier SOURCE_DATE_EPOCH is invalid") from exc
if type(receipt["source_date_epoch"]) is not int or receipt["source_date_epoch"] != expected_epoch:
    raise SystemExit("Linux publication receipt epoch binding failed")
for field, expected in (
    ("release_index_sha256", expected_index),
):
    value = receipt[field]
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None or value != expected:
        raise SystemExit(f"Linux publication receipt control binding failed: {field}")

def descriptor_path(raw):
    return (
        re.fullmatch(r"/proc/[0-9]+/fd/[0-9]+", raw) is not None
        or re.fullmatch(r"/dev/fd/[0-9]+", raw) is not None
    )

def held_fd(raw):
    # The descriptor paths name descriptors this process inherited from the
    # producer shell, so read and stat them directly with pread/fstat.
    return int(raw.rsplit("/", 1)[1]) if descriptor_path(raw) else None

def read_all(path, raw):
    fd = held_fd(raw)
    if fd is None:
        return path.read_bytes()
    chunks = []
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            return b"".join(chunks)
        chunks.append(block)
        offset += len(block)

def digest(path, raw=""):
    return hashlib.sha256(read_all(path, raw)).hexdigest()

def regular_record(path, raw, label, expected_mode):
    fd = held_fd(raw)
    info = os.fstat(fd) if fd is not None else path.lstat()
    if (not descriptor_path(raw) and stat.S_ISLNK(info.st_mode)) or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"Linux publication {label} is not a regular retained file")
    if info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != expected_mode or info.st_size <= 0:
        raise SystemExit(f"Linux publication {label} identity is unsafe")
    return {"sha256": digest(path, raw), "bytes": info.st_size, "mode": expected_mode}

if not isinstance(receipt["archive"], dict) or set(receipt["archive"]) != {"sha256", "bytes", "mode"}:
    raise SystemExit("Linux publication archive receipt fields are not exact")
archive_record = regular_record(archive, archive_raw, "archive", 0o644)
checksum_record = regular_record(checksum, checksum_raw, "archive checksum", 0o644)
bootstrap_record = regular_record(bootstrap, bootstrap_raw, "installer bootstrap", 0o755)
if receipt["archive"] != archive_record:
    raise SystemExit("Linux publication receipt archive binding failed")
if receipt["archive_checksum"] != checksum_record:
    raise SystemExit("Linux publication receipt checksum binding failed")
if receipt["installer_bootstrap"] != bootstrap_record:
    raise SystemExit("Linux publication receipt installer-bootstrap binding failed")
expected_checksum = f"{archive_record['sha256']}  {archive_name.name}\n".encode("ascii")
if read_all(checksum, checksum_raw) != expected_checksum or checksum_name.name != archive_name.name + ".sha256":
    raise SystemExit("Linux publication receipt checksum contents are not exact")
if bootstrap_name.name != "install-winsvpn-linux.sh":
    raise SystemExit("Linux publication receipt installer-bootstrap basename is wrong")
expected_bundle_digest = (
    regular_record(bundle, bundle_raw, "archive Sigstore bundle", 0o644)["sha256"]
    if signed_raw == "1" else None
)
if receipt["archive_sigstore_bundle_sha256"] != expected_bundle_digest:
    raise SystemExit("Linux publication receipt archive-bundle binding failed")
symbols_fd = (
    os.dup(held_fd(symbols_raw))
    if descriptor_path(symbols_raw)
    else os.open(
        symbols,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
    )
)
if not stat.S_ISDIR(os.fstat(symbols_fd).st_mode):
    os.close(symbols_fd)
    raise SystemExit("Linux publication symbol root is not a directory")
actual_symbols = []
symbol_counters = [0, 0]

def collect_symbols(directory_fd, prefix=""):
    for name in sorted(os.listdir(directory_fd)):
        if not name or "/" in name or name in {".", ".."}:
            raise SystemExit("Linux publication receipt symbol name is unsafe")
        relative = name if not prefix else f"{prefix}/{name}"
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        symbol_counters[0] += 1
        if symbol_counters[0] > 100000:
            raise SystemExit("Linux publication receipt symbol inventory has too many members")
        if stat.S_ISDIR(info.st_mode):
            child_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                child = os.fstat(child_fd)
                if (child.st_dev, child.st_ino) != (info.st_dev, info.st_ino):
                    raise SystemExit("Linux publication receipt symbol directory changed")
                collect_symbols(child_fd, relative)
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 512 * 1024 * 1024:
            raise SystemExit(f"Linux publication receipt symbol became unsafe: {relative}")
        child_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            child = os.fstat(child_fd)
            if (child.st_dev, child.st_ino, child.st_size) != (
                info.st_dev, info.st_ino, info.st_size
            ):
                raise SystemExit("Linux publication receipt symbol changed while opened")
            symbol_counters[1] += child.st_size
            if symbol_counters[1] > 4 * 1024 * 1024 * 1024:
                raise SystemExit("Linux publication receipt symbols exceed the aggregate byte bound")
            digest_value = hashlib.sha256()
            offset = 0
            while offset < child.st_size:
                block = os.pread(child_fd, min(1024 * 1024, child.st_size - offset), offset)
                if not block:
                    raise SystemExit("Linux publication receipt symbol truncated")
                digest_value.update(block)
                offset += len(block)
            actual_symbols.append({
                "path": relative,
                "sha256": digest_value.hexdigest(),
                "bytes": child.st_size,
                "mode": stat.S_IMODE(child.st_mode),
            })
        finally:
            os.close(child_fd)

try:
    collect_symbols(symbols_fd)
finally:
    os.close(symbols_fd)
actual_symbols.sort(key=lambda record: record["path"])
if receipt["symbols"] != actual_symbols:
    raise SystemExit("Linux publication receipt symbol inventory changed")
for record in receipt["symbols"]:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes", "mode"}:
        raise SystemExit("Linux publication receipt symbol fields are not exact")
    if (
        not isinstance(record["path"], str)
        or type(record["bytes"]) is not int
        or type(record["mode"]) is not int
        or re.fullmatch(r"[0-9a-f]{64}", record["sha256"] if isinstance(record["sha256"], str) else "") is None
    ):
        raise SystemExit("Linux publication receipt symbol digest is malformed")
PY
}

write_staged_archive_checksum() {
  local archive_read digest
  [[ -f "${staged_archive}" && ! -L "${staged_archive}" && -s "${staged_archive}" ]] || {
    echo "The staged Linux release archive is missing or unsafe." >&2
    return 65
  }
  if [[ "${publication_custody_active}" == "1" ]]; then
    # pread through the retained descriptor (never the pathname).
    digest="$(publication_held_file_sha256 "${staged_archive}")" || return 65
  else
    archive_read="${staged_archive}"
    digest="$(sha256sum "${archive_read}" | awk '{print $1}')"
  fi
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "Could not calculate the staged Linux archive SHA-256." >&2
    return 65
  }
  open_linux_publication_output_under_custody "${staged_archive_sha}" || return $?
  printf '%s  %s\n' "${digest}" "$(basename "${ARCHIVE}")" >&${publication_writer_fd}
  finalize_linux_publication_output_under_custody "${staged_archive_sha}" 0644 || return $?
}

atomic_publish_linux_generation() {
  python3 -I - "$1" "$2" "$3" "$4" "${5:-0}" "${@:6}" <<'PY'
import ctypes
import errno
import hashlib
import os
import pathlib
import stat
import sys

stage, generation_root, generation_name, retained_stage_fd_raw, fail_after_rename_raw = sys.argv[1:6]
custody_specs = sys.argv[6:]
retained_stage_fd = int(retained_stage_fd_raw)
if fail_after_rename_raw not in {"0", "1"}:
    raise SystemExit("Linux publication post-rename test control is invalid")
def require_sealed(fd: int, label: str) -> None:
    info = os.fstat(fd)
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise SystemExit(f"Linux publication object gained a hard link: {label}")
    if info.st_mode & 0o022:
        raise SystemExit(f"Linux publication object is group/other-writable: {label}")
stage_path = pathlib.Path(stage)
root_path = pathlib.Path(generation_root)
if not stage_path.is_absolute() or not root_path.is_absolute() or "/" in generation_name:
    raise SystemExit("Linux generation publication paths are not canonical")
stage_path_info = os.lstat(stage_path)
stage_info = os.fstat(retained_stage_fd)
root_info = os.lstat(root_path)
if (
    stat.S_ISLNK(stage_path_info.st_mode)
    or not stat.S_ISDIR(stage_info.st_mode)
    or (stage_path_info.st_dev, stage_path_info.st_ino) != (stage_info.st_dev, stage_info.st_ino)
):
    raise SystemExit("Linux generation stage is not the exact retained directory")
if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
    raise SystemExit("Linux generation root is not a regular directory")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
stage_parent_fd = os.open(stage_path.parent, flags | os.O_NOFOLLOW)
generation_root_fd = os.open(root_path, flags | os.O_NOFOLLOW)
stage_child_fd = -1
try:
    stage_child_fd = os.open(
        stage_path.name, flags | os.O_NOFOLLOW, dir_fd=stage_parent_fd
    )
    opened_child = os.fstat(stage_child_fd)
    if (opened_child.st_dev, opened_child.st_ino) != (stage_info.st_dev, stage_info.st_ino):
        raise SystemExit("Linux publication stage child does not match the retained stage descriptor")
    if os.fstat(stage_parent_fd).st_dev != os.fstat(generation_root_fd).st_dev:
        raise SystemExit("Linux publication stage and generation root are not on one filesystem")

    def retained_digest(fd: int, kind: str) -> str:
        if kind in {"file", "sealed-file"}:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise SystemExit("retained Linux publication file is unsafe at commit")
            if kind == "sealed-file":
                require_sealed(fd, "retained file")
            digest = hashlib.sha256()
            offset = 0
            while True:
                block = os.pread(fd, 1024 * 1024, offset)
                if not block:
                    return digest.hexdigest()
                digest.update(block)
                offset += len(block)
        if kind in {"directory", "sealed-directory"}:
            opened = os.fstat(fd)
            if not stat.S_ISDIR(opened.st_mode):
                raise SystemExit("retained Linux publication directory is unsafe at commit")
            if kind == "sealed-directory":
                require_sealed(fd, "retained directory")
            digest = hashlib.sha256()
            counters = [0, 0]

            def scan(directory_fd: int, prefix: str = "") -> None:
                for name in sorted(os.listdir(directory_fd)):
                    if not name or "/" in name or name in {".", ".."}:
                        raise SystemExit("retained Linux publication has an unsafe member name")
                    relative = name if not prefix else f"{prefix}/{name}"
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    counters[0] += 1
                    if counters[0] > 100000:
                        raise SystemExit("retained Linux publication has too many members")
                    if stat.S_ISDIR(info.st_mode):
                        child_fd = os.open(name, flags | os.O_NOFOLLOW, dir_fd=directory_fd)
                        try:
                            child = os.fstat(child_fd)
                            if (child.st_dev, child.st_ino) != (info.st_dev, info.st_ino):
                                raise SystemExit("retained Linux publication directory changed while opened")
                            if kind == "sealed-directory":
                                require_sealed(child_fd, relative)
                            digest.update(b"d\0" + relative.encode("utf-8") + b"\0")
                            scan(child_fd, relative)
                        finally:
                            os.close(child_fd)
                        continue
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 512 * 1024 * 1024:
                        raise SystemExit("retained Linux publication contains an unsafe file")
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                    try:
                        child = os.fstat(child_fd)
                        if (child.st_dev, child.st_ino, child.st_size) != (
                            info.st_dev, info.st_ino, info.st_size
                        ):
                            raise SystemExit("retained Linux publication file changed while opened")
                        if kind == "sealed-directory":
                            require_sealed(child_fd, relative)
                        counters[1] += child.st_size
                        if counters[1] > 4 * 1024 * 1024 * 1024:
                            raise SystemExit("retained Linux publication exceeds its aggregate byte bound")
                        digest.update(b"f\0" + relative.encode("utf-8") + b"\0")
                        digest.update(str(child.st_size).encode("ascii") + b"\0")
                        offset = 0
                        while offset < child.st_size:
                            block = os.pread(
                                child_fd, min(1024 * 1024, child.st_size - offset), offset
                            )
                            if not block:
                                raise SystemExit("retained Linux publication file was truncated")
                            digest.update(block)
                            offset += len(block)
                    finally:
                        os.close(child_fd)

            scan(fd)
            return digest.hexdigest()
        if kind == "identity":
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                raise SystemExit("retained Linux publication identity is not a directory")
            return "0" * 64
        raise SystemExit("retained Linux publication custody kind is invalid")

    def validate_retained_custody() -> None:
        for spec in custody_specs:
            fd_raw, kind, expected, raw_path = spec.split("|", 3)
            fd = int(fd_raw)
            held = os.fstat(fd)
            if retained_digest(fd, kind) != expected:
                raise SystemExit(f"retained Linux publication bytes changed before commit: {raw_path}")
            path = pathlib.Path(raw_path)
            try:
                relative = path.relative_to(stage_path)
            except ValueError:
                continue
            if not relative.parts:
                current = stage_info
            elif len(relative.parts) == 1:
                current = os.stat(relative.name, dir_fd=stage_child_fd, follow_symlinks=False)
            else:
                raise SystemExit("retained Linux publication member path is not direct")
            if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                raise SystemExit(f"retained Linux publication member was substituted before commit: {raw_path}")

    def fsync_tree_fd(directory_fd: int, relative: str = ".") -> None:
        for name in sorted(os.listdir(directory_fd)):
            if not name or "/" in name or name in {".", ".."}:
                raise SystemExit("Linux publication tree has an unsafe member name")
            child_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                info = os.fstat(child_fd)
                child_relative = name if relative == "." else f"{relative}/{name}"
                if stat.S_ISDIR(info.st_mode):
                    require_sealed(child_fd, child_relative)
                    fsync_tree_fd(child_fd, child_relative)
                elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise SystemExit(
                        f"Linux publication tree contains an unsafe member: {child_relative}"
                    )
                else:
                    require_sealed(child_fd, child_relative)
                os.fsync(child_fd)
            finally:
                os.close(child_fd)

    fsync_tree_fd(stage_child_fd)
    os.fsync(stage_child_fd)
    os.fsync(stage_parent_fd)
    os.fsync(generation_root_fd)
    # This is the final byte assertion and the physical commit boundary. The
    # retained descriptors are re-read in the same process immediately before
    # the no-replace rename, so no later pathname validation can authorize a
    # substituted archive or checksum.
    validate_retained_custody()
    if sys.platform == "linux":
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise SystemExit("Linux renameat2(RENAME_NOREPLACE) is required for atomic publication")
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            stage_parent_fd,
            os.fsencode(stage_path.name),
            generation_root_fd,
            os.fsencode(generation_name),
            1,
        )
        if result != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise SystemExit("Linux publication generation already exists; immutable generations are never replaced")
            raise SystemExit(f"atomic Linux generation publication failed: {os.strerror(error)}")
    else:
        # Test-only portability path. Real release execution rejects non-Linux
        # before publication and therefore always uses RENAME_NOREPLACE.
        destination = root_path / generation_name
        if destination.exists() or destination.is_symlink():
            raise SystemExit("Linux publication generation already exists; immutable generations are never replaced")
        os.rename(stage_path, destination)
    if fail_after_rename_raw == "1":
        raise SystemExit("hostile partial-commit failure after no-replace rename")
    # The retained stage descriptor is already the destination inode after
    # rename. Seal that directory through the descriptor before any pathname
    # result handling, so the committed generation cannot be renamed,
    # unlinked, or populated through an ancestor race.
    require_sealed(retained_stage_fd, "published generation root")
    published_fd = os.open(
        generation_name, flags | os.O_NOFOLLOW, dir_fd=generation_root_fd
    )
    try:
        published_info = os.fstat(published_fd)
        if (published_info.st_dev, published_info.st_ino) != (
            stage_info.st_dev,
            stage_info.st_ino,
        ):
            def remove_substituted_tree(directory_fd: int, root_dev: int) -> None:
                for member_name in sorted(os.listdir(directory_fd)):
                    member_info = os.stat(
                        member_name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if stat.S_ISDIR(member_info.st_mode):
                        member_fd = os.open(
                            member_name, flags | os.O_NOFOLLOW, dir_fd=directory_fd
                        )
                        try:
                            opened_member = os.fstat(member_fd)
                            if (
                                opened_member.st_dev,
                                opened_member.st_ino,
                            ) != (member_info.st_dev, member_info.st_ino) or opened_member.st_dev != root_dev:
                                raise SystemExit("substituted Linux generation directory changed during rollback")
                            remove_substituted_tree(member_fd, root_dev)
                        finally:
                            os.close(member_fd)
                        os.rmdir(member_name, dir_fd=directory_fd)
                    else:
                        os.unlink(member_name, dir_fd=directory_fd)
                os.fsync(directory_fd)

            current_published = os.stat(
                generation_name, dir_fd=generation_root_fd, follow_symlinks=False
            )
            if (current_published.st_dev, current_published.st_ino) != (
                published_info.st_dev,
                published_info.st_ino,
            ):
                raise SystemExit("substituted Linux generation changed before rollback")
            remove_substituted_tree(published_fd, published_info.st_dev)
            os.rmdir(generation_name, dir_fd=generation_root_fd)
            os.fsync(generation_root_fd)
            raise SystemExit("published Linux generation is not the retained stage inode")
        # Read the retained bytes again through the still-open descriptors
        # after rename. This readback is part of the same helper invocation as
        # the physical commit and never reopens an artifact pathname.
        validate_retained_custody()
        os.fsync(published_fd)
    finally:
        os.close(published_fd)
    os.fsync(generation_root_fd)
    os.fsync(stage_parent_fd)
    print(f"{stage_info.st_dev}:{stage_info.st_ino}")
finally:
    if stage_child_fd >= 0:
        os.close(stage_child_fd)
    os.close(generation_root_fd)
    os.close(stage_parent_fd)
PY
}

commit_linux_publication() {
  local digest mode generation_root generation_name committed_stage_path
  local retained_stage_fd publish_identity helper_identity quoted_stage_path
  local -a atomic_publish_args=()
  [[ -d "${publication_stage_dir}" && ! -L "${publication_stage_dir}" ]] || {
    echo "Linux publication staging generation is missing or unsafe." >&2
    return 65
  }
  [[ -f "${staged_archive}" && ! -L "${staged_archive}" && -s "${staged_archive}" ]] || return 65
  [[ -f "${staged_archive_sha}" && ! -L "${staged_archive_sha}" && -s "${staged_archive_sha}" ]] || return 65
  [[ -f "${staged_publication_receipt}" && ! -L "${staged_publication_receipt}" && \
     -s "${staged_publication_receipt}" ]] || {
    echo "Linux publication generation is missing its exact publication receipt." >&2
    return 65
  }
  [[ -f "${staged_installer_bootstrap}" && \
     ! -L "${staged_installer_bootstrap}" && \
     -x "${staged_installer_bootstrap}" ]] || {
    echo "Linux publication generation is missing its verified installer bootstrap." >&2
    return 65
  }
  digest="$(sha256sum "${staged_archive}" | awk '{print $1}')"
  grep -Fxq "${digest}  $(basename "${ARCHIVE}")" "${staged_archive_sha}" || {
    echo "Linux staged checksum does not bind the staged archive." >&2
    return 65
  }
  if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
    [[ -f "${staged_bundle}" && ! -L "${staged_bundle}" && -s "${staged_bundle}" ]] || {
      echo "Signed Linux generation is missing its verified Sigstore bundle." >&2
      return 65
    }
    mode="signed"
    generation_root="${LINUX_PRIVATE_PUBLICATION_ROOT}/signed"
    [[ -f "${staged_publication_receipt_bundle}" && \
       ! -L "${staged_publication_receipt_bundle}" && \
       -s "${staged_publication_receipt_bundle}" ]] || {
      echo "Signed Linux generation is missing its publication-receipt Sigstore bundle." >&2
      return 65
    }
  else
    [[ ! -e "${staged_bundle}" && ! -L "${staged_bundle}" ]] || {
      echo "Unsigned rehearsal unexpectedly carries a Sigstore bundle." >&2
      return 65
    }
    mode="unsigned-rehearsal"
    generation_root="${LINUX_PRIVATE_PUBLICATION_ROOT}/unsigned-rehearsals"
    [[ ! -e "${staged_publication_receipt_bundle}" && \
       ! -L "${staged_publication_receipt_bundle}" ]] || {
      echo "Unsigned rehearsal unexpectedly carries a publication-receipt signature." >&2
      return 65
    }
  fi
  if [[ -e "${generation_root}" || -L "${generation_root}" ]]; then
    [[ -d "${generation_root}" && ! -L "${generation_root}" ]] || {
      echo "Linux generation namespace is not a regular directory." >&2
      return 65
    }
  else
    mkdir -m 0700 -- "${generation_root}"
  fi
  generation_name="linux-${LINUX_RELEASE_ARCH_LABEL:-x64}-${mode}-${digest}"
  publication_final_dir="${generation_root}/${generation_name}"
  [[ ! -e "${publication_final_dir}" && ! -L "${publication_final_dir}" ]] || {
    echo "Linux publication generation already exists; immutable generations are never replaced." >&2
    return 65
  }
  [[ -d "${staged_private_symbols}" && ! -L "${staged_private_symbols}" && \
     -f "${staged_private_symbols}/manifest.json" && \
     ! -L "${staged_private_symbols}/manifest.json" ]] || {
    echo "Linux publication generation is missing its private symbol custody tree." >&2
    return 65
  }
  assert_linux_signed_publication_custody || return $?
  verify_linux_publication_receipt || return $?
  assert_linux_signed_publication_custody || return $?
  if [[ "${mode}" == "signed" ]]; then
    # These are the final cryptographic checks immediately before the atomic
    # generation commit. Literal or merely well-formed bundles cannot pass.
    verify_linux_signature "${staged_archive}" "${staged_bundle}" || return $?
    verify_linux_signature \
      "${staged_publication_receipt}" "${staged_publication_receipt_bundle}" || return $?
  fi
  committed_stage_path="${publication_stage_dir}"
  retained_stage_fd=210
  printf -v quoted_stage_path '%q' "${publication_stage_dir}"
  eval "exec ${retained_stage_fd}<${quoted_stage_path}" || return 65
  publish_identity="$(python3 -I - "${retained_stage_fd}" <<'PY'
import os, sys
info = os.fstat(int(sys.argv[1]))
print(f"{info.st_dev}:{info.st_ino}")
PY
)" || {
    eval "exec ${retained_stage_fd}<&-"
    return 65
  }
  [[ "${publish_identity}" =~ ^[0-9]+:[0-9]+$ ]] || {
    eval "exec ${retained_stage_fd}<&-"
    return 65
  }
  # Record the only generation identity rollback may remove before the helper
  # can rename. A post-rename failure or lost helper result therefore cannot
  # leave an untracked partial generation or authorize pathname-only cleanup.
  publication_uncommitted_identity="${publish_identity}"
  atomic_publish_args=(
    "${publication_stage_dir}" "${generation_root}" "${generation_name}"
    "${retained_stage_fd}" "${publication_custody_test_fail_after_rename}"
  )
  if [[ "${publication_custody_active}" == "1" ]]; then
    atomic_publish_args+=("${publication_custody_specs[@]}")
  fi
  helper_identity="$(atomic_publish_linux_generation "${atomic_publish_args[@]}")" || {
      local status=$?
      eval "exec ${retained_stage_fd}<&-"
      return "${status}"
    }
  eval "exec ${retained_stage_fd}<&-"
  [[ "${helper_identity}" == "${publish_identity}" ]] || {
    echo "Atomic Linux publication did not return the retained stage identity." >&2
    return 65
  }
  # atomic_publish_linux_generation re-read every retained descriptor and
  # performed the no-replace rename in one process. That rename is the commit;
  # do not insert a pathname-based command between its return and this state
  # transition.
  publication_committed=1
  publication_uncommitted_identity=""
  publication_stage_dir=""
  ARCHIVE="${publication_final_dir}/$(basename "${ARCHIVE}")"
  ARCHIVE_SHA_PATH="${publication_final_dir}/$(basename "${ARCHIVE_SHA_PATH}")"
  BUNDLE_PATH="${publication_final_dir}/$(basename "${BUNDLE_PATH}")"
  staged_archive="${ARCHIVE}"
  staged_archive_sha="${ARCHIVE_SHA_PATH}"
  staged_bundle="${BUNDLE_PATH}"
  staged_installer_bootstrap="${publication_final_dir}/install-winsvpn-linux.sh"
  staged_publication_receipt="${publication_final_dir}/LINUX_PUBLICATION_RECEIPT.json"
  staged_publication_receipt_bundle="${publication_final_dir}/LINUX_PUBLICATION_RECEIPT.json.sigstore.json"
  LINUX_SYMBOL_DIR="${publication_final_dir}/private-symbols"
  LINUX_OBFUSCATION_MANIFEST="${LINUX_SYMBOL_DIR}/manifest.json"
  LINUX_NATIVE_SYMBOL_DIR="${LINUX_SYMBOL_DIR}/native"
  staged_private_symbols="${LINUX_SYMBOL_DIR}"
  rebind_linux_signed_publication_custody_paths \
    "${committed_stage_path}" "${publication_final_dir}"
  symbol_rollback_active=0
  symbol_rollback_had_previous=0
  symbol_rollback_target=""
  symbol_rollback_stage=""
  symbol_rollback_backup=""
  log "Atomically published immutable Linux ${mode} generation: ${publication_final_dir}"
}

run_publication_transaction_self_test() {
  local fixture_root receipt_fixture unsigned_dir symbol_source authentic_bootstrap
  local authentic_archive authentic_checksum authentic_bundle authentic_symbol
  local archive_digest bootstrap_digest bundle_digest checksum_digest custody_error
  local retained_stage retained_stage_fd swap_generation_root rollback_generation rollback_identity quoted_stage_path
  fixture_root="$(mktemp -d)"
  OUT_DIR="${fixture_root}/out"
  mkdir -m 0755 -- "${OUT_DIR}"
  LINUX_PRIVATE_PUBLICATION_ROOT="${fixture_root}/private-generations"
  symbol_source="${fixture_root}/symbols-source"
  mkdir -m 0700 -- "${symbol_source}"
  printf 'private-symbols-v1\n' >"${symbol_source}/manifest.json"
  chmod 0600 "${symbol_source}/manifest.json"
  LINUX_RELEASE_ARCH_LABEL=x64
  ARCHIVE="${OUT_DIR}/wins-vpn-linux-x64.tar.gz"
  ARCHIVE_SHA_PATH="${ARCHIVE}.sha256"
  BUNDLE_PATH="${ARCHIVE}.sigstore.json"
  SOURCE_DATE_EPOCH=1783563753
  LINUX_RELEASE_INDEX_SHA256="$(printf release-index | sha256sum | awk '{print $1}')"
  # Off Linux there is no /proc writable-alias proof; the rest of the
  # transaction (held digests, link checks, no-replace commit) runs as is.
  WINS_LINUX_CUSTODY_PORTABLE_TEST=1
  SIGN_LINUX_RELEASE=1
  prepare_linux_publication_stage
  printf 'new archive\n' >"${staged_archive}"
  printf 'new bundle\n' >"${staged_bundle}"
  if python3 "${ROOT}/tools/linux_release_signing.py" validate-bundle \
      --bundle "${staged_bundle}" >/dev/null 2>&1; then
    echo "Linux publication self-test accepted a literal non-cryptographic Sigstore bundle." >&2
    return 1
  fi
  rollback_linux_publication

  SIGN_LINUX_RELEASE=0
  prepare_linux_publication_stage
  begin_linux_signed_publication_custody
  publication_custody_test_preopen_swap=1
  set +e
  open_linux_publication_output_under_custody "${staged_archive}"
  status=$?
  set -e
  if [[ "${status}" == "0" ]]; then
    echo "Linux producer custody accepted a pre-custody archive pathname swap." >&2
    return 1
  fi
  [[ -f "${staged_archive}.producer-authentic" ]] || {
    echo "Linux pre-custody swap control lost the producer-created inode." >&2
    return 1
  }
  rm -f -- "${staged_archive}" "${staged_archive}.producer-authentic"
  close_linux_signed_publication_custody
  rollback_linux_publication

  retained_stage="${fixture_root}/retained-stage"
  swap_generation_root="${fixture_root}/swap-generations"
  mkdir -m 0700 -- "${retained_stage}" "${swap_generation_root}"
  printf 'authentic retained stage\n' >"${retained_stage}/payload"
  retained_stage_fd=211
  printf -v quoted_stage_path '%q' "${retained_stage}"
  eval "exec ${retained_stage_fd}<${quoted_stage_path}"
  mv -- "${retained_stage}" "${retained_stage}.authentic"
  mkdir -m 0700 -- "${retained_stage}"
  printf 'substituted stage\n' >"${retained_stage}/payload"
  if atomic_publish_linux_generation \
      "${retained_stage}" "${swap_generation_root}" candidate \
      "${retained_stage_fd}" 0 >/dev/null 2>&1; then
    echo "Atomic Linux publication accepted a substituted stage pathname." >&2
    return 1
  fi
  eval "exec ${retained_stage_fd}<&-"
  [[ ! -e "${swap_generation_root}/candidate" ]] || {
    echo "Atomic Linux publication committed a substituted stage." >&2
    return 1
  }
  rm -rf -- "${retained_stage}"
  mv -- "${retained_stage}.authentic" "${retained_stage}"

  retained_stage="${LINUX_PRIVATE_PUBLICATION_ROOT}/.staging/partial-commit-fixture"
  rollback_generation="${LINUX_PRIVATE_PUBLICATION_ROOT}/signed/rollback-fixture"
  mkdir -p -m 0700 -- "$(dirname "${retained_stage}")" "$(dirname "${rollback_generation}")" "${retained_stage}"
  printf 'poisoned post-commit fixture\n' >"${retained_stage}/payload"
  rollback_identity="$(python3 -I - "${retained_stage}" <<'PY'
import os, sys
info = os.lstat(sys.argv[1])
print(f"{info.st_dev}:{info.st_ino}")
PY
)"
  publication_uncommitted_identity="${rollback_identity}"
  publication_final_dir="${rollback_generation}"
  publication_stage_dir=""
  mv -- "${retained_stage}" "${rollback_generation}"
  rollback_linux_publication
  [[ ! -e "${rollback_generation}" && ! -L "${rollback_generation}" ]] || {
    echo "Linux publication rollback left an exact partial-commit generation." >&2
    return 1
  }

  publication_committed=0
  ARCHIVE="${OUT_DIR}/wins-vpn-linux-x64.tar.gz"
  ARCHIVE_SHA_PATH="${ARCHIVE}.sha256"
  BUNDLE_PATH="${ARCHIVE}.sigstore.json"
  SIGN_LINUX_RELEASE=1
  prepare_linux_publication_stage
  COSIGN_PATH="${fixture_root}/cosign"
  WINS_LINUX_COSIGN_KEY="${fixture_root}/cosign.key"
  WINS_LINUX_COSIGN_PUBKEY="${fixture_root}/cosign.pub"
  WINS_LINUX_COSIGN_TRUST_ANCHOR="${fixture_root}/cosign.anchor"
  printf '#!/bin/sh\nexit 1\n' >"${COSIGN_PATH}"
  chmod 0755 "${COSIGN_PATH}"
  printf 'key\n' >"${WINS_LINUX_COSIGN_KEY}"
  printf 'pubkey\n' >"${WINS_LINUX_COSIGN_PUBKEY}"
  printf 'anchor\n' >"${WINS_LINUX_COSIGN_TRUST_ANCHOR}"
  begin_linux_signed_publication_custody
  open_linux_publication_output_under_custody "${staged_archive}"
  printf 'retained archive\n' >&${publication_writer_fd}
  finalize_linux_publication_output_under_custody "${staged_archive}" 0644
  custody_error="${fixture_root}/sealed-custody.stderr"
  # A sealed object is not physically immutable, so a same-UID write through
  # the pathname is possible; the held digest must refuse it.
  printf 'hostile during-hash mutation\n' >>"${staged_archive}"
  if assert_linux_signed_publication_custody 2>"${custody_error}"; then
    echo "Linux publication custody accepted mutation through a pathname alias." >&2
    return 1
  fi
  grep -Fq 'signed publication held bytes changed' "${custody_error}" || {
    cat "${custody_error}" >&2
    return 1
  }
  printf 'retained archive\n' >"${staged_archive}"
  assert_linux_signed_publication_custody
  ln -- "${staged_archive}" "${staged_archive}.hardlink"
  if assert_linux_signed_publication_custody 2>"${custody_error}"; then
    echo "Linux publication custody accepted a new hardlink alias." >&2
    return 1
  fi
  grep -Fq 'gained a hard link' "${custody_error}" || {
    cat "${custody_error}" >&2
    return 1
  }
  rm -f -- "${staged_archive}.hardlink"
  chmod 0666 "${staged_archive}"
  if assert_linux_signed_publication_custody 2>"${custody_error}"; then
    echo "Linux publication custody accepted a group/other-writable sealed object." >&2
    return 1
  fi
  grep -Fq 'group/other-writable' "${custody_error}" || {
    cat "${custody_error}" >&2
    return 1
  }
  chmod 0644 "${staged_archive}"
  assert_linux_signed_publication_custody
  write_staged_archive_checksum
  stage_linux_private_symbols "${symbol_source}"
  extend_linux_signed_publication_custody "${staged_private_symbols}" directory
  seal_linux_publication_custody_path "${staged_private_symbols}" directory
  printf 'retained bundle\n' >"${staged_bundle}"
  extend_linux_signed_publication_custody "${staged_bundle}"
  seal_linux_publication_custody_path "${staged_bundle}" file

  archive_digest="$(sha256sum "${staged_archive}" | awk '{print $1}')"
  bootstrap_digest="$(sha256sum "${staged_installer_bootstrap}" | awk '{print $1}')"
  checksum_digest="$(sha256sum "${staged_archive_sha}" | awk '{print $1}')"
  bundle_digest="$(sha256sum "${staged_bundle}" | awk '{print $1}')"
  authentic_bootstrap="${publication_stage_dir}/.authentic-bootstrap"
  authentic_checksum="${publication_stage_dir}/.authentic-checksum"
  mv -- "${staged_installer_bootstrap}" "${authentic_bootstrap}"
  printf '#!/bin/sh\nprintf attacker\n' >"${staged_installer_bootstrap}"
  chmod 0755 "${staged_installer_bootstrap}"
  custody_error="${fixture_root}/bootstrap-custody.stderr"
  if assert_linux_signed_publication_custody 2>"${custody_error}"; then
    echo "Signed Linux publication custody accepted a same-UID bootstrap substitution." >&2
    return 1
  fi
  [[ "$(publication_held_file_sha256 "${staged_installer_bootstrap}")" == "${bootstrap_digest}" ]] || {
    echo "Signed Linux publication verification did not retain the authentic bootstrap descriptor." >&2
    return 1
  }
  rm -f -- "${staged_installer_bootstrap}"
  mv -- "${authentic_bootstrap}" "${staged_installer_bootstrap}"
  authentic_archive="${publication_stage_dir}/.authentic-archive"
  mv -- "${staged_archive_sha}" "${authentic_checksum}"
  mv -- "${staged_archive}" "${authentic_archive}"
  printf 'attacker archive after validation\n' >"${staged_archive}"
  printf '%064d  %s\n' 0 "$(basename "${ARCHIVE}")" >"${staged_archive_sha}"
  if assert_linux_signed_publication_custody 2>"${custody_error}"; then
    echo "Signed Linux publication custody accepted a hostile archive/checksum swap." >&2
    return 1
  fi
  [[ "$(publication_held_file_sha256 "${staged_archive}")" == "${archive_digest}" ]] || {
    echo "Signed Linux publication verification did not retain the authentic archive descriptor." >&2
    return 1
  }
  [[ "$(publication_held_file_sha256 "${staged_archive_sha}")" == "${checksum_digest}" ]] || {
    echo "Signed Linux publication verification did not retain the authentic checksum descriptor." >&2
    return 1
  }
  rm -f -- "${staged_archive}"
  rm -f -- "${staged_archive_sha}"
  mv -- "${authentic_archive}" "${staged_archive}"
  mv -- "${authentic_checksum}" "${staged_archive_sha}"
  authentic_bundle="${publication_stage_dir}/.authentic-bundle"
  mv -- "${staged_bundle}" "${authentic_bundle}"
  printf '{"mediaType":"attacker-after-validation"}\n' >"${staged_bundle}"
  chmod 0644 "${staged_bundle}"
  if assert_linux_signed_publication_custody 2>"${custody_error}"; then
    echo "Signed Linux publication custody accepted a same-UID Sigstore-bundle substitution." >&2
    return 1
  fi
  [[ "$(publication_held_file_sha256 "${staged_bundle}")" == "${bundle_digest}" ]] || {
    echo "Cosign verification did not retain the authentic Sigstore bundle descriptor." >&2
    return 1
  }
  rm -f -- "${staged_bundle}"
  mv -- "${authentic_bundle}" "${staged_bundle}"
  authentic_symbol="${staged_private_symbols}/.authentic-manifest"
  mv -- "${staged_private_symbols}/manifest.json" "${authentic_symbol}"
  printf 'attacker-symbol-substitution\n' >"${staged_private_symbols}/manifest.json"
  chmod 0600 "${staged_private_symbols}/manifest.json"
  if assert_linux_signed_publication_custody 2>"${custody_error}"; then
    echo "Signed Linux publication custody accepted a substituted private-symbol member." >&2
    return 1
  fi
  rm -f -- "${staged_private_symbols}/manifest.json"
  mv -- "${authentic_symbol}" "${staged_private_symbols}/manifest.json"
  assert_linux_signed_publication_custody
  printf 'post-assert attacker mutation\n' >>"${staged_archive}"
  retained_stage_fd=212
  printf -v quoted_stage_path '%q' "${publication_stage_dir}"
  eval "exec ${retained_stage_fd}<${quoted_stage_path}"
  if atomic_publish_linux_generation \
      "${publication_stage_dir}" "${swap_generation_root}" post-assert-mutation \
      "${retained_stage_fd}" 0 "${publication_custody_specs[@]}" >/dev/null 2>&1; then
    echo "Atomic Linux publication committed bytes mutated after the final custody assertion." >&2
    return 1
  fi
  eval "exec ${retained_stage_fd}<&-"
  [[ ! -e "${swap_generation_root}/post-assert-mutation" ]] || {
    echo "Atomic Linux publication left a post-assert mutated generation." >&2
    return 1
  }
  close_linux_signed_publication_custody
  rollback_linux_publication

  publication_committed=0
  ARCHIVE="${OUT_DIR}/wins-vpn-linux-x64.tar.gz"
  ARCHIVE_SHA_PATH="${ARCHIVE}.sha256"
  BUNDLE_PATH="${ARCHIVE}.sigstore.json"
  SIGN_LINUX_RELEASE=0
  prepare_linux_publication_stage
  begin_linux_signed_publication_custody
  open_linux_publication_output_under_custody "${staged_archive}"
  printf 'unsigned rehearsal\n' >&${publication_writer_fd}
  finalize_linux_publication_output_under_custody "${staged_archive}" 0644
  seal_linux_publication_custody_path "${staged_installer_bootstrap}" file
  write_staged_archive_checksum
  stage_linux_private_symbols "${symbol_source}"
  extend_linux_signed_publication_custody "${staged_private_symbols}" directory
  seal_linux_publication_custody_path "${staged_private_symbols}" directory
  write_linux_publication_receipt
  extend_linux_signed_publication_custody "${staged_publication_receipt}"
  seal_linux_publication_custody_path "${staged_publication_receipt}" file
  verify_linux_publication_receipt
  assert_linux_signed_publication_custody
  commit_linux_publication
  close_linux_signed_publication_custody
  unsigned_dir="${publication_final_dir}"
  [[ "${unsigned_dir}" == "${LINUX_PRIVATE_PUBLICATION_ROOT}/unsigned-rehearsals/"* ]] || {
    echo "Unsigned rehearsal did not publish into its private disjoint generation namespace." >&2
    return 1
  }
  [[ "$(<"${unsigned_dir}/private-symbols/manifest.json")" == "private-symbols-v1" ]] || {
    echo "Linux publication self-test did not atomically retain private symbols with each generation." >&2
    return 1
  }
  verify_linux_publication_receipt
  cp -p -- "${staged_installer_bootstrap}" "${fixture_root}/bootstrap.saved"
  printf '#!/bin/sh\nprintf substituted\n' >"${staged_installer_bootstrap}"
  chmod 0755 "${staged_installer_bootstrap}"
  if verify_linux_publication_receipt >/dev/null 2>&1; then
    echo "Linux publication self-test accepted substituted installer-bootstrap bytes." >&2
    return 1
  fi
  cp -p -- "${fixture_root}/bootstrap.saved" "${staged_installer_bootstrap}"
  cp -p -- "${staged_archive_sha}" "${fixture_root}/checksum.saved"
  printf '%064d  %s\n' 0 "$(basename "${ARCHIVE}")" >"${staged_archive_sha}"
  chmod 0644 "${staged_archive_sha}"
  if verify_linux_publication_receipt >/dev/null 2>&1; then
    echo "Linux publication self-test accepted substituted checksum bytes." >&2
    return 1
  fi
  cp -p -- "${fixture_root}/checksum.saved" "${staged_archive_sha}"
  verify_linux_publication_receipt
  receipt_fixture="$(<"${staged_publication_receipt}")"
  printf '{"schema_version":NaN}\n' >"${staged_publication_receipt}"
  if verify_linux_publication_receipt >/dev/null 2>&1; then
    echo "Linux publication self-test accepted a non-finite receipt value." >&2
    return 1
  fi
  printf '{"schema_version":1,"schema_version":1}\n' >"${staged_publication_receipt}"
  if verify_linux_publication_receipt >/dev/null 2>&1; then
    echo "Linux publication self-test accepted a duplicate receipt key." >&2
    return 1
  fi
  printf '%s\n' "${receipt_fixture}" >"${staged_publication_receipt}"
  verify_linux_publication_receipt
  rm -rf -- "${fixture_root}"
  publication_stage_dir=""
  publication_final_dir=""
  OUT_DIR=""
  ARCHIVE=""
  ARCHIVE_SHA_PATH=""
  BUNDLE_PATH=""
  staged_private_symbols=""
  staged_installer_bootstrap=""
  staged_publication_receipt=""
  staged_publication_receipt_bundle=""
  LINUX_RELEASE_INDEX_SHA256=""
  WINS_LINUX_CUSTODY_PORTABLE_TEST=0
  LINUX_PRIVATE_PUBLICATION_ROOT="${ROOT}/.artifacts/private-release-generations/linux"
  printf 'LINUX RELEASE ATOMIC GENERATION PUBLICATION SELF-TEST: PASS\n'
}

assert_neutral_linux_stage() {
  [[ "${ROOT}" == /tmp/winsvpn-linux-neutral.?????? ]] || {
    echo "WINS_LINUX_NEUTRAL_STAGE_ACTIVE is restricted to a producer-owned /tmp stage." >&2
    return 65
  }
  [[ "$(realpath -e -- "${ROOT}")" == "${ROOT}" ]] || {
    echo "The Linux neutral stage must not traverse a symbolic link." >&2
    return 65
  }
  [[ "$(stat -c '%u' -- "${ROOT}")" == "$(id -u)" ]] || {
    echo "The Linux neutral stage is not owned by the current build user." >&2
    return 65
  }
}

run_from_neutral_wsl_stage() {
  local index_path index_directory index_relative
  local reviewed_manifest reviewed_windows powershell_archiver windows_output
  local source_archive source_archive_sha neutral_child_output
  local neutral_archive neutral_archive_sha neutral_bundle neutral_generation neutral_generation_root
  local shared_manifest linux_manifest symbol_source symbol_target
  local -a review_arguments=()

  [[ "${ROOT}" == /mnt/* ]] || return 1
  if [[ "${WINS_LINUX_NEUTRAL_STAGE_ACTIVE:-0}" == "1" ]]; then
    echo "Refusing to bypass neutral staging from a Windows-mounted source tree." >&2
    exit 65
  fi
  command -v powershell.exe >/dev/null 2>&1 || {
    echo "A WSL build from /mnt requires powershell.exe for protected source staging." >&2
    exit 127
  }
  command -v wslpath >/dev/null 2>&1 || {
    echo "A WSL build from /mnt requires wslpath for protected source staging." >&2
    exit 127
  }

  command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required to verify Linux release inputs and receipts." >&2
    exit 127
  }
  index_path="$(resolve_release_input_index)"
  assert_linux_signing_deferral_mode || exit $?
  acquire_build_lock
  # M-1: fail before any Linux archive is accepted if a committed
  # Xray/AmneziaWG binary embeds a Go runtime with known-fixed stdlib CVEs.
  python3 "${ROOT}/tools/verify_embedded_engine_runtime_versions.py"
  python3 "${ROOT}/tools/release_dependency_freeze.py" verify-index \
    --repo "${ROOT}" --index "${index_path}"
  resolve_linux_release_controls "${index_path}"
  assert_linux_release_inputs_ready
  reject_unsupported_release_switches
  initialize_linux_output_paths "${index_path}"
  preflight_linux_signing
  initialize_formal_linux_receipt "${index_path}"

  if [[ -n "$(git -C "${ROOT}" ls-files --others --exclude-standard -- \
      .github android app_store apple assets docs installer ios legal lib linux \
      macos netlify server test tools web windows README_FINAL_DEPLOYMENT.md)" ]]; then
    reviewed_manifest="${WINS_LINUX_REVIEWED_UNTRACKED_MANIFEST:-}"
    [[ -n "${reviewed_manifest}" ]] || {
      echo "Untracked release source exists; WINS_LINUX_REVIEWED_UNTRACKED_MANIFEST is required." >&2
      exit 65
    }
    reviewed_manifest="$(realpath -e -- "${reviewed_manifest}")"
    case "${reviewed_manifest}" in
      "${ROOT}"/*)
        echo "The reviewed-untracked manifest must remain outside the repository." >&2
        exit 65
        ;;
    esac
    reviewed_windows="$(wslpath -w "${reviewed_manifest}")"
    review_arguments=(-ReviewedUntrackedManifest "${reviewed_windows}")
  fi

  neutral_host_tmp="$(mktemp -d "${ROOT}/.artifacts/linux-neutral-source.XXXXXX")"
  neutral_linux_tmp="$(mktemp -d /tmp/winsvpn-linux-neutral.XXXXXX)"
  powershell_archiver="$(wslpath -w "${ROOT}/tools/create_cross_machine_source_archive.ps1")"
  windows_output="$(wslpath -w "${neutral_host_tmp}")"
  log "Creating hash-reviewed neutral Linux source stage"
  env -u PSModulePath powershell.exe -NoProfile -ExecutionPolicy Bypass -File "${powershell_archiver}" \
    -OutputDirectory "${windows_output}" "${review_arguments[@]}"
  source_archive="${neutral_host_tmp}/wins-vpn-current-source.tar.gz"
  source_archive_sha="$(sha256sum "${source_archive}" | awk '{print $1}')"
  bash "${ROOT}/tools/extract_cross_machine_source_archive.sh" \
    "${source_archive}" "${neutral_linux_tmp}" "${source_archive_sha}"

  index_directory="$(dirname "${index_path}")"
  index_relative="${index_directory#"${ROOT}/"}"
  [[ "${index_relative}" != "${index_directory}" ]] || {
    echo "Release input index escaped the repository." >&2
    exit 65
  }
  mkdir -p -- "${neutral_linux_tmp}/${index_relative}"
  cp -- "${index_directory}/"*.json "${index_directory}/"*.sha256 \
    "${neutral_linux_tmp}/${index_relative}/"
  shared_manifest="${neutral_linux_tmp}/${index_relative}/SHARED_INPUTS.json"
  linux_manifest="${neutral_linux_tmp}/${index_relative}/LINUX_INPUTS.json"
  python3 "${neutral_linux_tmp}/tools/release_dependency_freeze.py" verify \
    --repo "${neutral_linux_tmp}" --manifest "${shared_manifest}"
  python3 "${neutral_linux_tmp}/tools/release_dependency_freeze.py" verify \
    --repo "${neutral_linux_tmp}" --manifest "${linux_manifest}"

  neutral_child_output="${neutral_linux_tmp}/web/downloads"
  log "Re-executing the exact producer from ${neutral_linux_tmp}"
  (
    cd "${neutral_linux_tmp}"
    WINS_LINUX_NEUTRAL_STAGE_ACTIVE=1 \
    WINS_RELEASE_INPUT_INDEX="${neutral_linux_tmp}/${index_relative}/RELEASE_INPUT_INDEX.json" \
    WINS_LINUX_OUT_DIR="${neutral_child_output}" \
    WINS_WINN3_DESCRIPTOR_PUBKEY_G1="${WINS_WINN3_DESCRIPTOR_PUBKEY_G1:-}" \
    WINS_WINN3_DESCRIPTOR_PUBKEY_G2="${WINS_WINN3_DESCRIPTOR_PUBKEY_G2:-}" \
    WINS_WINN3_DESCRIPTOR_PUBKEY_G3="${WINS_WINN3_DESCRIPTOR_PUBKEY_G3:-}" \
    WINS_WINN3_DESCRIPTOR_PUBKEY_G1_FILE="${WINS_WINN3_DESCRIPTOR_PUBKEY_G1_FILE:-}" \
    WINS_WINN3_DESCRIPTOR_PUBKEY_G2_FILE="${WINS_WINN3_DESCRIPTOR_PUBKEY_G2_FILE:-}" \
    WINS_WINN3_DESCRIPTOR_PUBKEY_G3_FILE="${WINS_WINN3_DESCRIPTOR_PUBKEY_G3_FILE:-}" \
    WINS_LINUX_FLUTTER_ARCHIVE="${WINS_LINUX_FLUTTER_ARCHIVE:-}" \
    WINS_LINUX_PUB_CACHE_ARCHIVE="${WINS_LINUX_PUB_CACHE_ARCHIVE:-}" \
      bash tools/build_linux_release.sh
  )

  [[ -n "${LINUX_RELEASE_ARCH_LABEL}" ]] || {
    echo "WSL Linux release wrapping requires a detected host architecture." >&2
    exit 65
  }
  if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
    neutral_generation_root="${neutral_linux_tmp}/.artifacts/private-release-generations/linux/signed"
  else
    neutral_generation_root="${neutral_linux_tmp}/.artifacts/private-release-generations/linux/unsigned-rehearsals"
  fi
  mapfile -t neutral_generations < <(find "${neutral_generation_root}" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null)
  [[ "${#neutral_generations[@]}" == 1 ]] || {
    echo "Neutral Linux build did not produce exactly one immutable publication generation." >&2
    exit 65
  }
  neutral_generation="${neutral_generations[0]}"
  neutral_archive="${neutral_generation}/wins-vpn-linux-${LINUX_RELEASE_ARCH_LABEL}.tar.gz"
  neutral_archive_sha="${neutral_archive}.sha256"
  neutral_bundle="${neutral_archive}.sigstore.json"
  [[ -f "${neutral_archive}" && ! -L "${neutral_archive}" && -s "${neutral_archive}" ]] || {
    echo "Neutral Linux build did not produce a safe release archive." >&2
    exit 65
  }
  [[ -f "${neutral_archive_sha}" && ! -L "${neutral_archive_sha}" ]] || {
    echo "Neutral Linux build did not produce its exact archive checksum." >&2
    exit 65
  }
  (cd "${neutral_child_output}" && sha256sum -c "$(basename "${neutral_archive_sha}")")
  if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
    [[ -f "${neutral_bundle}" && ! -L "${neutral_bundle}" && -s "${neutral_bundle}" ]] || {
      echo "Signed neutral Linux build did not produce a safe Sigstore bundle." >&2
      exit 65
    }
    verify_linux_signature "${neutral_archive}" "${neutral_bundle}"
  elif [[ -e "${neutral_bundle}" || -L "${neutral_bundle}" ]]; then
    echo "Unsigned neutral Linux build unexpectedly produced a Sigstore bundle." >&2
    exit 65
  fi
  prepare_linux_publication_stage
  begin_linux_signed_publication_custody
  open_linux_publication_output_under_custody "${staged_archive}"
  dd if="${neutral_archive}" >&${publication_writer_fd} status=none
  finalize_linux_publication_output_under_custody "${staged_archive}" 0644
  seal_linux_publication_custody_path "${staged_installer_bootstrap}" file
  write_staged_archive_checksum
  if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
    cp -- "${neutral_bundle}" "${staged_bundle}"
    chmod 0644 -- "${staged_bundle}"
    extend_linux_signed_publication_custody "${staged_bundle}"
    seal_linux_publication_custody_path "${staged_bundle}" file
  fi

  symbol_source="${neutral_linux_tmp}/.artifacts/private-release-symbols/linux/${LINUX_RELEASE_ARCH_LABEL}/${APP_VERSION}+${BUILD_NUMBER}"
  [[ -d "${symbol_source}" ]] || {
    echo "Neutral Linux build did not retain its private symbols." >&2
    exit 65
  }
  stage_linux_private_symbols "${symbol_source}"
  extend_linux_signed_publication_custody "${staged_private_symbols}" directory
  seal_linux_publication_custody_path "${staged_private_symbols}" directory
  symbol_target="$(linux_publication_custody_path_for_read "${staged_private_symbols}")"

  if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
    verify_linux_signature "${staged_archive}" "${staged_bundle}"
  fi
  python3_tool "${ROOT}/tools/release_obfuscation_contract.py" verify \
    --platform linux --symbols-dir "${symbol_target}" \
    --manifest "${symbol_target}/manifest.json" \
    --target-id "linux-${LINUX_RELEASE_ARCH_LABEL}-package" --artifact "${staged_archive}"
  python3 "${ROOT}/tools/private_release_symbol_custody.py" verify \
    --platform linux --symbols-dir "${symbol_target}" --artifact "${staged_archive}"
  python3 "${ROOT}/tools/release_dependency_freeze.py" verify-index \
    --repo "${ROOT}" --index "${index_path}"
  write_linux_publication_receipt
  extend_linux_signed_publication_custody "${staged_publication_receipt}"
  seal_linux_publication_custody_path "${staged_publication_receipt}" file
  if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
    sign_linux_release \
      "${staged_publication_receipt}" "${staged_publication_receipt_bundle}"
    extend_linux_signed_publication_custody "${staged_publication_receipt_bundle}"
    seal_linux_publication_custody_path "${staged_publication_receipt_bundle}" file
  fi
  verify_linux_publication_receipt
  complete_formal_linux_receipt "${index_path}" "${staged_archive}"
  commit_linux_publication
  log "Neutral WSL release build completed and reverified"
  return 0
}

run_build_lock_self_test() {
  acquire_build_lock
  if mkdir -- "${build_lock_dir}" 2>/dev/null; then
    echo "Build-lock self-test acquired the same lock twice." >&2
    return 1
  fi
  release_build_lock
  [[ ! -e "${build_lock_dir}" ]] || {
    echo "Build-lock self-test left a stale lock directory." >&2
    return 1
  }
  printf 'LINUX RELEASE BUILD LOCK SELF-TEST: PASS\n'
}

scan_owned_binary_paths() {
  python3 - "$@" <<'PY'
import pathlib
import re
import sys

# Match complete user-home prefixes, not benign route fragments such as the
# literal "/users/" that can legitimately occur in an obfuscated Flutter AOT
# image. Keep this expression aligned with LOCAL_USER_HOME_PATH_RE in
# validate_release_artifact_privacy.py.
local_user_home = re.compile(
    rb"(?i)(?:[a-z]:[\\/](?:users|documents and settings)[\\/]"
    rb"[^\\/\x00\r\n]{1,128}[\\/]|/(?:users|home)/"
    rb"[^/\x00\r\n]{1,128}/)"
)
for candidate in map(pathlib.Path, sys.argv[1:]):
    if not candidate.is_file():
        raise SystemExit(f"Owned Linux release binary is missing: {candidate.name}")
    if local_user_home.search(candidate.read_bytes()):
        raise SystemExit(
            f"Owned Linux release binary exposes a local user-home path: {candidate.name}"
        )
print("LINUX OWNED BINARY USER-HOME PATH SCAN: PASS")
PY
}

run_binary_path_scan_self_test() {
  local benign positive fixture
  tmp_dir="$(mktemp -d)"
  benign="${tmp_dir}/benign.bin"
  printf '%s\n' \
    '/users/' \
    '/users/profile' \
    'file:///opt/winsvpn-release/.dart_tool/flutter_build/generated.dart' \
    >"${benign}"
  scan_owned_binary_paths "${benign}"

  for fixture in \
    '/home/alice/project/lib/main.dart' \
    '/Users/alice/project/lib/main.dart' \
    'C:/Users/alice/project/lib/main.dart' \
    'C:\Users\alice\project\lib\main.dart' \
    'C:/Documents and Settings/alice/project/lib/main.dart'; do
    positive="${tmp_dir}/positive.bin"
    printf '%s\n' "${fixture}" >"${positive}"
    if scan_owned_binary_paths "${positive}" >/dev/null 2>&1; then
      echo "Linux binary path scan accepted a local user-home fixture: ${fixture}" >&2
      return 1
    fi
  done
  printf 'LINUX OWNED BINARY USER-HOME PATH SCAN SELF-TEST: PASS\n'
}

# Deterministic archive production depends on GNU tar's --sort=name --mtime
# options. Refuse loudly rather than silently emit an archive whose bytes vary
# with readdir order and the build wall-clock when tar is not GNU (e.g. BSD
# tar, busybox tar) -- the release's own Python gate would also fail it, but a
# specific refusal at the source is the earlier, clearer signal.
assert_gnu_tar() {
  local tar_version tar_bin
  tar_bin="$(command -v tar || true)"
  [[ -n "${tar_bin}" ]] || {
    echo "tar is required to package the Linux release." >&2
    return 127
  }
  tar_version="$("${tar_bin}" --version 2>&1 | head -n 1 || true)"
  [[ "${tar_version}" == *"GNU tar"* ]] || {
    echo "Linux release packaging requires GNU tar (--sort=name, --mtime); found: ${tar_version:-unknown} at ${tar_bin}. Refusing to emit a non-reproducible archive." >&2
    return 65
  }
  [[ "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]] || {
    echo "Deterministic Linux packaging requires SOURCE_DATE_EPOCH to be set to a valid epoch; found: ${SOURCE_DATE_EPOCH:-<unset>}." >&2
    return 65
  }
}

# The Linux Flutter, Pub cache and Go install-tree pins live under tools.linux:
# tools/release_android_toolchain_archive_custody.sh accepts exactly the
# darwin_arm64 key in tools.flutter.* and tools.flutter_pub_cache.*, and
# tools.go.install_tree_sha256 holds the release_go_archive_custody.tree_hash
# encoding that tools/winn_release.py compares, not this producer's
# linux_winn3_source_tree_sha256 encoding. The bin/go digest has no encoding
# and stays in tools.go.executable_sha256_by_platform, which the Winn builders
# read too.
assert_pinned_linux_flutter_pub_metadata() {
  local requested_arch="${1:-all}" key value platform_key
  local -a keys=() missing=()
  case "${requested_arch}" in
    x64)
      platform_key=linux_amd64
      ;;
    arm64)
      platform_key=linux_arm64
      ;;
    all) platform_key=all ;;
    *) return 65 ;;
  esac
  if [[ "${platform_key}" == "all" ]]; then
    keys+=(
      tools.linux.flutter.archive_sha256.linux_amd64
      tools.linux.flutter.archive_sha256.linux_arm64
      tools.linux.flutter.install_tree_sha256.linux_amd64
      tools.linux.flutter.install_tree_sha256.linux_arm64
      tools.linux.flutter_pub_cache.archive_sha256.linux_amd64
      tools.linux.flutter_pub_cache.archive_sha256.linux_arm64
      tools.linux.flutter_pub_cache.install_tree_sha256.linux_amd64
      tools.linux.flutter_pub_cache.install_tree_sha256.linux_arm64
    )
  else
    keys+=(
      "tools.linux.flutter.archive_sha256.${platform_key}"
      "tools.linux.flutter.install_tree_sha256.${platform_key}"
      "tools.linux.flutter_pub_cache.archive_sha256.${platform_key}"
      "tools.linux.flutter_pub_cache.install_tree_sha256.${platform_key}"
    )
  fi
  for key in "${keys[@]}"; do
    value="$(read_optional_wins_toolchain_pin "${key}")"
    [[ "${value}" =~ ^[0-9a-f]{64}$ ]] || missing+=("${key}")
  done
  if [[ "${#missing[@]}" -ne 0 ]]; then
    release_refused "missing exact Linux Flutter/Pub pins: ${missing[*]}; measure them on a Linux host from the reviewed archives (archive_sha256: sha256sum of the Flutter SDK .tar.xz or Pub cache .tar.gz; install_tree_sha256: bash tools/build_linux_release.sh --measure-tree-sha256 <extracted flutter or pub-cache dir>) and record them in tools/toolchain-pins.json"
    return $?
  fi
}

assert_pinned_linux_go_metadata() {
  local key value
  local -a missing=()
  for key in \
    tools.go.executable_sha256_by_platform.linux_amd64 \
    tools.go.executable_sha256_by_platform.linux_arm64 \
    tools.linux.go.install_tree_sha256.linux_amd64 \
    tools.linux.go.install_tree_sha256.linux_arm64; do
    value="$(read_optional_wins_toolchain_pin "${key}")"
    [[ "${value}" =~ ^[0-9a-f]{64}$ ]] || missing+=("${key}")
  done
  if [[ "${#missing[@]}" -ne 0 ]]; then
    release_refused "missing exact Linux Go executable/tree pins: ${missing[*]}; measure them from the pinned go${GO_VERSION}.linux-<arch>.tar.gz (executable_sha256_by_platform: sha256sum go/bin/go; install_tree_sha256: bash tools/build_linux_release.sh --measure-tree-sha256 <extracted go dir>) and record them in tools/toolchain-pins.json"
    return $?
  fi
}

assert_linux_release_inputs_ready() {
  local arch_key clang_sha
  case "${LINUX_RELEASE_ARCH_LABEL}" in
    x64) arch_key=x64 ;;
    arm64) arch_key=arm64 ;;
    *) return 65 ;;
  esac
  assert_pinned_linux_flutter_pub_metadata "${arch_key}" || return $?
  assert_pinned_linux_go_metadata || return $?
  assert_userspace_awg_runtime_pin_ready || return $?
  [[ -n "${WINS_ENGINE_SOURCE_ROOT:-}" && -d "${WINS_ENGINE_SOURCE_ROOT}" && \
     ! -L "${WINS_ENGINE_SOURCE_ROOT}" ]] || {
    release_refused "WINS_ENGINE_SOURCE_ROOT must name the authenticated offline Linux engine source/store stage"
    return $?
  }
  [[ -n "${WINS_STORE_GOMODCACHE:-}" && -d "${WINS_STORE_GOMODCACHE}" && \
     ! -L "${WINS_STORE_GOMODCACHE}" && \
     "${WINS_STORE_GOMODCACHE_TREE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || {
    release_refused "WINS_STORE_GOMODCACHE and WINS_STORE_GOMODCACHE_TREE_SHA256 must bind the authenticated offline Linux module cache"
    return $?
  }
  [[ -n "${WINS_STORE_GOCACHE:-}" && -d "${WINS_STORE_GOCACHE}" && \
     ! -L "${WINS_STORE_GOCACHE}" ]] || {
    release_refused "WINS_STORE_GOCACHE must name the private Linux Go build cache"
    return $?
  }
  if [[ "${arch_key}" == "arm64" ]]; then
    clang_sha="$(read_optional_wins_toolchain_pin tools.linux.arm64.clang_executable_sha256)"
    [[ "${clang_sha}" =~ ^[0-9a-f]{64}$ ]] || {
      release_refused "tools.linux.arm64.clang_executable_sha256 is absent from tools/toolchain-pins.json; on the arm64 Linux build host record the sha256 of the resolved clang 14.0.6 executable: sha256sum \"\$(readlink -f /usr/bin/clang)\""
      return $?
    }
  fi
}

# Both reviewed Flutter 3.47.6 Linux SDK archives carry exactly two in-tree
# relative symbolic links of the git tree that the Linux desktop build never
# reads: the official x64 archive
# (stable/linux/flutter_linux_3.47.6-stable.tar.xz, sha256 f1631b9c... in
# releases_linux.json) and the arm64 archive built from the 3.47.6 git tag
# (tools.linux.flutter.arm64_from_tag). Extraction leaves them out by exact
# member name and target; any other link member is still refused, and
# tools.linux.flutter.install_tree_sha256.linux_* is measured over the tree
# without them.
LINUX_FLUTTER_ARCHIVE_EXCLUDED_LINKS=(
  "flutter/.claude/skills=../.agents/skills"
  "flutter/engine/src/flutter/lib/web_ui/test/ui/paragraph_performance_test.dart=../webparagraph/paragraph_performance_test.dart"
)

prepare_pinned_linux_flutter_and_pub() {
  local arch_key platform_key flutter_pin_key flutter_sha flutter_tree_sha
  local pub_pin_key pub_sha pub_tree_sha measured_tree
  local flutter_archive="${WINS_LINUX_FLUTTER_ARCHIVE:-}"
  local pub_archive="${WINS_LINUX_PUB_CACHE_ARCHIVE:-}"
  local toolchain_root="${tmp_dir:?}/linux-flutter-toolchain"
  case "${LINUX_RELEASE_ARCH_LABEL}" in
    x64) arch_key="x64"; platform_key="linux_amd64" ;;
    arm64) arch_key="arm64"; platform_key="linux_arm64" ;;
    *) return 65 ;;
  esac
  assert_pinned_linux_flutter_pub_metadata "${arch_key}" || return $?
  flutter_pin_key="tools.linux.flutter.archive_sha256.${platform_key}"
  pub_pin_key="tools.linux.flutter_pub_cache.archive_sha256.${platform_key}"
  flutter_sha="$(read_optional_wins_toolchain_pin "${flutter_pin_key}")"
  flutter_tree_sha="$(read_optional_wins_toolchain_pin "tools.linux.flutter.install_tree_sha256.${platform_key}")"
  pub_sha="$(read_optional_wins_toolchain_pin "${pub_pin_key}")"
  pub_tree_sha="$(read_optional_wins_toolchain_pin "tools.linux.flutter_pub_cache.install_tree_sha256.${platform_key}")"
  [[ "${flutter_sha}" =~ ^[0-9a-f]{64}$ ]] || {
    release_refused "${flutter_pin_key} is absent from tools/toolchain-pins.json; record sha256sum of the reviewed Linux Flutter SDK .tar.xz"
    return $?
  }
  [[ "${pub_sha}" =~ ^[0-9a-f]{64}$ ]] || {
    release_refused "${pub_pin_key} is absent from tools/toolchain-pins.json; record sha256sum of the reviewed Linux Pub cache .tar.gz"
    return $?
  }
  [[ -n "${flutter_archive}" && -f "${flutter_archive}" && ! -L "${flutter_archive}" ]] || {
    release_refused "WINS_LINUX_FLUTTER_ARCHIVE must name the reviewed local Linux Flutter SDK tar.xz"
    return $?
  }
  [[ -n "${pub_archive}" && -f "${pub_archive}" && ! -L "${pub_archive}" ]] || {
    release_refused "WINS_LINUX_PUB_CACHE_ARCHIVE must name the reviewed local Pub cache tar.gz"
    return $?
  }
  mkdir -p "${toolchain_root}/flutter" "${toolchain_root}/pub"
  winsvpn_snapshot_verified_file \
    "${flutter_archive}" "${flutter_sha}" "${toolchain_root}/flutter-sdk.tar.xz.snap" || return 65
  winsvpn_extract_snapshot \
    "${toolchain_root}/flutter-sdk.tar.xz.snap" "${toolchain_root}/flutter" tar.xz \
    "${LINUX_FLUTTER_ARCHIVE_EXCLUDED_LINKS[@]}" || return 65
  winsvpn_snapshot_verified_file \
    "${pub_archive}" "${pub_sha}" "${toolchain_root}/pub-cache.tar.gz.snap" || return 65
  winsvpn_extract_snapshot \
    "${toolchain_root}/pub-cache.tar.gz.snap" "${toolchain_root}/pub" tar.gz || return 65
  FLUTTER_COMMAND="${toolchain_root}/flutter/flutter/bin/flutter"
  PUB_CACHE="${toolchain_root}/pub/pub-cache"
  [[ -x "${FLUTTER_COMMAND}" && ! -L "${FLUTTER_COMMAND}" ]] || {
    echo "Pinned Linux Flutter SDK archive did not produce flutter/bin/flutter." >&2
    return 65
  }
  [[ -d "${PUB_CACHE}" && ! -L "${PUB_CACHE}" ]] || {
    echo "Pinned Pub cache archive must contain one pub-cache root directory." >&2
    return 65
  }
  measured_tree="$(linux_winn3_source_tree_sha256 "${toolchain_root}/flutter/flutter")" || return 65
  [[ "${measured_tree}" == "${flutter_tree_sha}" ]] || {
    echo "Extracted Linux Flutter SDK tree does not match its reviewed identity." >&2
    return 65
  }
  measured_tree="$(linux_winn3_source_tree_sha256 "${PUB_CACHE}")" || return 65
  [[ "${measured_tree}" == "${pub_tree_sha}" ]] || {
    echo "Extracted Linux Pub cache tree does not match its reviewed identity." >&2
    return 65
  }
  WINS_LINUX_FLUTTER_TREE_SHA256="${flutter_tree_sha}"
  WINS_LINUX_PUB_CACHE_TREE_SHA256="${pub_tree_sha}"
  WINS_LINUX_FLUTTER_TREE_ROOT="${toolchain_root}/flutter/flutter"
  # Private digest chain for the watched Flutter/Pub runs (see
  # run_with_linux_tree_custody): the first run expects the install pins.
  WINS_LINUX_TREE_CUSTODY_CHAIN_DIR="$(mktemp -d "${toolchain_root}/tree-custody-chain.XXXXXX")" || return 65
  chmod 0700 -- "${WINS_LINUX_TREE_CUSTODY_CHAIN_DIR}"
  export WINS_LINUX_FLUTTER_TREE_SHA256 WINS_LINUX_PUB_CACHE_TREE_SHA256
  export WINS_LINUX_FLUTTER_TREE_ROOT WINS_LINUX_TREE_CUSTODY_CHAIN_DIR
  export PUB_CACHE FLUTTER_SUPPRESS_ANALYTICS=true CI=true
  unset FLUTTER_ROOT DART_SDK DART_DEFINES || true
}

read_linux_signing_mode() {
  local signing_mode error_path
  error_path="$(mktemp "${TMPDIR:-/tmp}/winsvpn-linux-signing-preflight.XXXXXX")" || return 65
  if signing_mode="$(python3 "${ROOT}/tools/linux_release_signing.py" preflight \
      --repo "${ROOT}" 2>"${error_path}")"; then
    rm -f -- "${error_path}"
    printf '%s\n' "${signing_mode}"
    return 0
  fi
  cat -- "${error_path}" >&2
  rm -f -- "${error_path}"
  return 65
}

# The release public key and the installer trust anchor must both be exactly
# the pinned key (LINUX_COSIGN_PUBLIC_KEY_SHA256): regular, single-link, not
# symlinked, not group/other-writable. Ownership by root is not required.
assert_linux_cosign_public_key_custody() {
  local public_path="$1" trust_path="$2" trust_route="$3" pin="$4"
  [[ -n "${pin}" ]] || {
    release_refused "LINUX_COSIGN_PUBLIC_KEY_SHA256 in tools/build_linux_release.sh is empty; the owner must set it to the sha256 of the release cosign.pub before SIGN_LINUX_RELEASE=1"
    return $?
  }
  [[ "${pin}" =~ ^[0-9a-f]{64}$ ]] || {
    release_refused "LINUX_COSIGN_PUBLIC_KEY_SHA256 is not a lowercase sha256: ${pin}"
    return $?
  }
  python3 -I - "${public_path}" "${trust_path}" "${trust_route}" "${pin}" <<'PY' || return 65
import hashlib, os, pathlib, stat, sys

public_path = pathlib.Path(sys.argv[1])
trust_path = pathlib.Path(sys.argv[2])
if os.fspath(trust_path) != sys.argv[3]:
    raise SystemExit("RELEASE REFUSED: Linux installer trust-anchor route is not canonical")
pin = sys.argv[4]

def read_bound(path: pathlib.Path, label: str, *, current_user: bool) -> bytes:
    try:
        before = os.lstat(path)
    except FileNotFoundError as exc:
        raise SystemExit(f"RELEASE REFUSED: {label} is absent at {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SystemExit(f"RELEASE REFUSED: {label} must be a regular non-symlink file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise SystemExit(f"RELEASE REFUSED: {label} changed while opened")
        if opened.st_nlink != 1 or opened.st_mode & 0o022:
            raise SystemExit(f"RELEASE REFUSED: {label} is hard-linked or group/other-writable")
        if current_user and opened.st_uid != os.getuid():
            raise SystemExit(f"RELEASE REFUSED: {label} is not owned by the current user")
        chunks = []
        while True:
            block = os.read(fd, 65536)
            if not block:
                return b"".join(chunks)
            chunks.append(block)
    finally:
        os.close(fd)

public_digest = hashlib.sha256(read_bound(public_path, "release public key", current_user=True)).hexdigest()
trust_digest = hashlib.sha256(read_bound(trust_path, "installed trust anchor", current_user=False)).hexdigest()
if public_digest != pin:
    raise SystemExit(
        f"RELEASE REFUSED: release public key sha256 {public_digest} is not LINUX_COSIGN_PUBLIC_KEY_SHA256 {pin}"
    )
if trust_digest != pin:
    raise SystemExit(
        f"RELEASE REFUSED: installed trust anchor sha256 {trust_digest} is not LINUX_COSIGN_PUBLIC_KEY_SHA256 {pin}"
    )
PY
}

preflight_linux_signing() {
  local signing_mode

  [[ "${SIGN_LINUX_RELEASE:-0}" == "0" || "${SIGN_LINUX_RELEASE:-0}" == "1" ]] || {
    echo "SIGN_LINUX_RELEASE must be 0 or 1." >&2
    return 65
  }
  signing_mode="$(read_linux_signing_mode)" || return $?
  [[ "${signing_mode}" == "unsigned" ]] && return 0
  assert_linux_cosign_public_key_custody \
    "${WINS_LINUX_COSIGN_PUBKEY:?}" "${WINS_LINUX_COSIGN_TRUST_ANCHOR:?}" \
    "/etc/winsvpn/release-signing/cosign.pub" "${LINUX_COSIGN_PUBLIC_KEY_SHA256}" || return $?
  python3 "${ROOT}/tools/linux_release_signing.py" authenticate-cosign \
    --repo "${ROOT}" --cosign "${COSIGN_PATH}" >/dev/null || {
      echo "Signed Linux release production requires the digest-pinned Cosign ${COSIGN_VERSION} at ${COSIGN_PATH}." >&2
      return 65
    }
}

verify_linux_signature() {
  local archive="$1"
  local bundle_path="$2"
  local archive_read bundle_read
  preflight_linux_signing || return $?
  [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]] || return 0
  archive_read="$(linux_publication_custody_path_for_read "${archive}")" || return $?
  bundle_read="$(linux_publication_custody_path_for_read "${bundle_path}")" || return $?
  run_linux_signing_with_held_boundary \
    "$archive_read" "$bundle_read" "" verify-only
}

run_linux_signing_with_held_boundary() {
  python3 -I - \
    "${ROOT}" "${COSIGN_PATH}" "$1" "$2" "$3" "${4:-sign-verify}" \
    "${WINS_LINUX_COSIGN_PUBKEY:?}" "${WINS_LINUX_COSIGN_TRUST_ANCHOR:?}" \
    "${LINUX_SIGNING_VERIFIER_SHA256}" "${LINUX_COSIGN_PUBLIC_KEY_SHA256}" <<'PY'
import hashlib, os, pathlib, stat, subprocess, sys

(
    repo,
    cosign,
    archive_name,
    bundle,
    public_output,
    action,
    public_name,
    trust_name,
    expected_module_digest,
    expected_public_key_digest,
) = sys.argv[1:]
if action not in {"sign-verify", "verify-only"}:
    raise SystemExit("Linux signing boundary action is invalid")
if len(expected_public_key_digest) != 64 or any(c not in "0123456789abcdef" for c in expected_public_key_digest):
    raise SystemExit("RELEASE REFUSED: LINUX_COSIGN_PUBLIC_KEY_SHA256 is not set to the sha256 of the release cosign.pub")
if trust_name != "/etc/winsvpn/release-signing/cosign.pub":
    raise SystemExit("Linux installer trust-anchor route is not canonical")

def open_regular(path_value: str, label: str, *, expected_uid) -> tuple[int, os.stat_result]:
    path = pathlib.Path(path_value)
    if not path.is_absolute():
        raise SystemExit(f"{label} must be absolute")
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SystemExit(f"{label} must be a regular non-symlink file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        os.close(fd)
        raise SystemExit(f"{label} changed while opened")
    if (
        (expected_uid is not None and opened.st_uid != expected_uid)
        or opened.st_nlink != 1
        or opened.st_mode & 0o022
    ):
        os.close(fd)
        raise SystemExit(f"{label} ownership, link count, or mode is unsafe")
    return fd, opened

def open_ancestor_chain(path_value: str, label: str) -> list[tuple[str, int, os.stat_result]]:
    path = pathlib.Path(path_value)
    if not path.is_absolute():
        raise SystemExit(f"{label} path must be absolute")
    chain = []
    current = pathlib.Path(path.anchor)
    parts = [None, *path.parent.parts[1:]]
    for part in parts:
        if part is not None:
            current /= part
        before = os.lstat(current)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise SystemExit(f"{label} ancestor is not a regular directory: {current}")
        fd = os.open(
            current,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
        )
        opened = os.fstat(fd)
        if (
            (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_mode & 0o022
        ):
            os.close(fd)
            raise SystemExit(f"{label} ancestor custody is unsafe: {current}")
        chain.append((os.fspath(current), fd, opened))
    return chain

def digest_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        offset += len(block)

archive_fd, archive_info = open_regular(archive_name, "Linux archive", expected_uid=os.getuid())
module_name = os.fspath(pathlib.Path(repo) / "tools/linux_release_signing.py")
module_fd = cosign_fd = public_fd = trust_fd = proof_fd = bundle_fd = -1
trust_ancestor_fds = []
try:
    module_fd, module_info = open_regular(
        module_name, "Linux signing verifier implementation", expected_uid=os.getuid()
    )
    cosign_fd, cosign_info = open_regular(
        cosign, "reviewed Cosign executable", expected_uid=None
    )
    if not (cosign_info.st_mode & 0o111):
        raise SystemExit("reviewed Cosign executable is not executable")
    module_digest = digest_fd(module_fd)
    cosign_digest = digest_fd(cosign_fd)
    if module_digest != expected_module_digest:
        raise SystemExit("Linux signing verifier implementation is not the reviewed producer-bound source")
    module_source = b""
    offset = 0
    while True:
        block = os.pread(module_fd, 1024 * 1024, offset)
        if not block:
            break
        module_source += block
        offset += len(block)
        if len(module_source) > 1024 * 1024:
            raise SystemExit("Linux signing verifier implementation is oversized")
    reviewed_namespace = {
        "__name__": "winsvpn_linux_release_signing_reviewed_identity",
        "__file__": module_name,
        "__package__": "",
    }
    exec(
        compile(module_source, module_name, "exec", dont_inherit=True),
        reviewed_namespace,
    )
    expected_cosign_digest = reviewed_namespace["expected_cosign_sha256"]()
    if cosign_digest != expected_cosign_digest:
        raise SystemExit("reviewed Cosign executable SHA-256 does not match the held signing verifier")
    cosign_version = subprocess.run(
        [f"/proc/{os.getpid()}/fd/{cosign_fd}", "version"],
        pass_fds=(cosign_fd,),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="strict",
        shell=False,
        check=False,
        timeout=30,
    )
    expected_version = f"GitVersion: {reviewed_namespace['COSIGN_VERSION']}"
    if cosign_version.returncode != 0 or expected_version not in {
        line.strip() for line in cosign_version.stdout.splitlines()
    }:
        raise SystemExit("held Cosign executable does not report the reviewed version")
    public_fd, public_info = open_regular(public_name, "owner public key", expected_uid=os.getuid())
    trust_ancestor_fds = open_ancestor_chain(trust_name, "installed trust anchor")
    trust_fd, trust_info = open_regular(trust_name, "installed trust anchor", expected_uid=None)
    public_digest = digest_fd(public_fd)
    trust_digest = digest_fd(trust_fd)
    if public_digest != expected_public_key_digest or trust_digest != expected_public_key_digest:
        raise SystemExit("RELEASE REFUSED: the release public key or installed trust anchor is not LINUX_COSIGN_PUBLIC_KEY_SHA256")
    archive_digest = digest_fd(archive_fd)
    held_archive = f"/proc/{os.getpid()}/fd/{archive_fd}"
    held_key_driver = r'''
import contextlib
import os
import sys
import types

held_fd = int(sys.argv[1])
module_fd = int(sys.argv[2])
cosign_fd = int(sys.argv[3])
module_path = sys.argv[4]
source = b""
offset = 0
while True:
    block = os.pread(module_fd, 1024 * 1024, offset)
    if not block:
        break
    source += block
    offset += len(block)
module = types.ModuleType("winsvpn_linux_release_signing_held")
module.__file__ = module_path
module.__package__ = ""
exec(compile(source, module_path, "exec", dont_inherit=True), module.__dict__)
original_open_key = module._open_key

def open_held_key(path_value, repo_path, label, *, private):
    if label == "WINS_LINUX_COSIGN_PUBKEY" and not private:
        return os.dup(held_fd)
    return original_open_key(path_value, repo_path, label, private=private)

module._open_key = open_held_key

@contextlib.contextmanager
def open_held_cosign(path_value=module.COSIGN_PATH):
    if os.fspath(path_value) != module.COSIGN_PATH:
        raise module.SigningError("Cosign executable must use the fixed reviewed path")
    duplicate = os.dup(cosign_fd)
    try:
        yield duplicate
    finally:
        os.close(duplicate)

module.open_authenticated_cosign = open_held_cosign
raise SystemExit(module.main(sys.argv[5:]))
'''
    if action == "sign-verify":
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                held_key_driver,
                str(public_fd),
                str(module_fd),
                str(cosign_fd),
                module_name,
                "run-sign-verify",
                "--repo",
                repo,
                "--cosign",
                cosign,
                "--archive",
                held_archive,
                "--bundle",
                bundle,
                "--public-key-output",
                public_output,
            ],
            stdin=subprocess.DEVNULL,
            pass_fds=(archive_fd, public_fd, trust_fd, module_fd, cosign_fd),
            check=False,
        )
        if completed.returncode != 0:
            raise SystemExit(completed.returncode)
    bundle_fd, bundle_info = open_regular(
        bundle, "Sigstore verification bundle", expected_uid=os.getuid()
    )
    bundle_digest = digest_fd(bundle_fd)
    held_bundle = f"/proc/{os.getpid()}/fd/{bundle_fd}"
    trust_verified = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            held_key_driver,
            str(trust_fd),
            str(module_fd),
            str(cosign_fd),
            module_name,
            "run-verify",
            "--repo",
            repo,
            "--cosign",
            cosign,
            "--archive",
            held_archive,
            "--bundle",
            held_bundle,
        ],
        stdin=subprocess.DEVNULL,
        pass_fds=(archive_fd, bundle_fd, trust_fd, module_fd, cosign_fd),
        check=False,
    )
    if trust_verified.returncode != 0:
        raise SystemExit("Linux signature did not verify with the held installer trust descriptor")
    after = os.fstat(archive_fd)
    current = os.lstat(archive_name)
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
        archive_info.st_dev,
        archive_info.st_ino,
        archive_info.st_size,
        archive_info.st_mtime_ns,
        archive_info.st_ctime_ns,
    ):
        raise SystemExit("Linux archive changed across signing and verification")
    if (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino):
        raise SystemExit("Linux archive pathname was swapped across signing and verification")
    if digest_fd(archive_fd) != archive_digest:
        raise SystemExit("Linux archive bytes changed across signing and verification")
    for path_name, held_fd, held_info, label in (
        (module_name, module_fd, module_info, "Linux signing verifier implementation"),
        (cosign, cosign_fd, cosign_info, "reviewed Cosign executable"),
        (public_name, public_fd, public_info, "owner public key"),
        (trust_name, trust_fd, trust_info, "installed trust anchor"),
    ):
        held_after = os.fstat(held_fd)
        current = os.lstat(path_name)
        if (
            held_after.st_dev,
            held_after.st_ino,
            held_after.st_size,
            held_after.st_mtime_ns,
            held_after.st_ctime_ns,
        ) != (
            held_info.st_dev,
            held_info.st_ino,
            held_info.st_size,
            held_info.st_mtime_ns,
            held_info.st_ctime_ns,
        ):
            raise SystemExit(f"{label} changed across signing and verification")
        if (current.st_dev, current.st_ino) != (held_after.st_dev, held_after.st_ino):
            raise SystemExit(f"{label} pathname was swapped across signing and verification")
    if digest_fd(public_fd) != public_digest or digest_fd(trust_fd) != trust_digest:
        raise SystemExit("Linux public-key custody bytes changed across signing and verification")
    if digest_fd(module_fd) != module_digest or digest_fd(cosign_fd) != cosign_digest:
        raise SystemExit("Linux signing implementation bytes changed across signing and verification")
    bundle_after = os.fstat(bundle_fd)
    bundle_current = os.lstat(bundle)
    if (
        bundle_after.st_dev,
        bundle_after.st_ino,
        bundle_after.st_size,
        bundle_after.st_mtime_ns,
        bundle_after.st_ctime_ns,
    ) != (
        bundle_info.st_dev,
        bundle_info.st_ino,
        bundle_info.st_size,
        bundle_info.st_mtime_ns,
        bundle_info.st_ctime_ns,
    ) or (bundle_current.st_dev, bundle_current.st_ino) != (
        bundle_after.st_dev,
        bundle_after.st_ino,
    ) or digest_fd(bundle_fd) != bundle_digest:
        raise SystemExit("Sigstore verification bundle changed outside retained descriptor custody")
    for ancestor_name, ancestor_fd, ancestor_info in trust_ancestor_fds:
        held_ancestor = os.fstat(ancestor_fd)
        current_ancestor = os.lstat(ancestor_name)
        if (
            held_ancestor.st_dev,
            held_ancestor.st_ino,
            held_ancestor.st_mode,
            held_ancestor.st_uid,
        ) != (
            ancestor_info.st_dev,
            ancestor_info.st_ino,
            ancestor_info.st_mode,
            ancestor_info.st_uid,
        ) or (current_ancestor.st_dev, current_ancestor.st_ino) != (
            held_ancestor.st_dev,
            held_ancestor.st_ino,
        ):
            raise SystemExit("installed trust-anchor ancestor changed across signing verification")
    if action == "sign-verify":
        proof_fd, proof_info = open_regular(
            public_output, "signing public-key proof", expected_uid=os.getuid()
        )
        if stat.S_IMODE(proof_info.st_mode) != 0o644:
            raise SystemExit("Linux signing public-key proof mode is not exact")
        if digest_fd(proof_fd) != public_digest or public_digest != trust_digest:
            raise SystemExit("Linux signing public-key proof does not exactly match held public/trust descriptors")
finally:
    for _ancestor_name, ancestor_fd, _ancestor_info in reversed(trust_ancestor_fds):
        os.close(ancestor_fd)
    for fd in (proof_fd, bundle_fd, trust_fd, public_fd, cosign_fd, module_fd, archive_fd):
        if fd >= 0:
            os.close(fd)
PY
}

sign_linux_release() {
  local archive="$1"
  local bundle_path="$2"
  local archive_read signing_mode

  # An unsigned rehearsal must never leave a stale bundle beside a rebuilt
  # archive. Signed artifacts use only the owner-held local key pair.
  preflight_linux_signing || return $?
  [[ ! -e "$bundle_path" && ! -L "$bundle_path" ]] || {
    echo "Canonical Linux Sigstore bundle unexpectedly appeared during publication." >&2
    return 65
  }
  signing_mode="$(read_linux_signing_mode)" || return $?
  if [[ "${signing_mode}" == "unsigned" ]]; then
    log "Unsigned local rehearsal: no Sigstore bundle emitted"
    return 0
  fi
  bundle_tmp="${bundle_path}.tmp.$$"
  pubkey_tmp="${bundle_tmp}.cosign.pub"
  rm -f -- "${bundle_tmp}"
  rm -f -- "${pubkey_tmp}"
  log "Signing and immediately verifying the exact Linux archive with descriptor-bound local keys"
  archive_read="$(linux_publication_custody_path_for_read "${archive}")" || return $?
  run_linux_signing_with_held_boundary \
    "$archive_read" "$bundle_tmp" "$pubkey_tmp" || return $?
  [[ -f "${pubkey_tmp}" && ! -L "${pubkey_tmp}" && -s "${pubkey_tmp}" ]] || {
    echo "Linux signing did not preserve its descriptor-bound public-key custody proof." >&2
    return 65
  }
  rm -f -- "${pubkey_tmp}"
  pubkey_tmp=""
  mv -- "$bundle_tmp" "$bundle_path" || return $?
  bundle_tmp=""
  log "Verified Sigstore bundle ready: $bundle_path"
}

run_signing_self_test() {
  local fake_cosign key_dir key_path pubkey_path signing_mode
  tmp_dir="$(mktemp -d)"
  key_dir="${tmp_dir}/keys"
  mkdir -p "$key_dir"
  key_path="${key_dir}/cosign.key"
  pubkey_path="${key_dir}/cosign.pub"
  printf 'local-private-fixture\n' >"$key_path"
  printf 'local-public-fixture\n' >"$pubkey_path"
  chmod 0600 "$key_path"
  chmod 0644 "$pubkey_path"
  key_path="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$key_path")"
  pubkey_path="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$pubkey_path")"
  export SIGN_LINUX_RELEASE=1
  export WINS_LINUX_COSIGN_KEY="$key_path"
  export WINS_LINUX_COSIGN_PUBKEY="$pubkey_path"
  export WINS_LINUX_COSIGN_TRUST_ANCHOR='/etc/winsvpn/release-signing/cosign.pub'
  unset WINS_LINUX_SIGNER_IDENTITY WINS_LINUX_SIGNER_OIDC_ISSUER
  signing_mode="$(python3 "${ROOT}/tools/linux_release_signing.py" preflight --repo "${ROOT}")"
  [[ "${signing_mode}" == "key" ]] || {
    echo "Linux signing self-test did not accept the complete local-key contract." >&2
    return 1
  }
  export WINS_LINUX_SIGNER_IDENTITY='retired-remote-signer'
  if python3 "${ROOT}/tools/linux_release_signing.py" preflight --repo "${ROOT}" >/dev/null 2>&1; then
    echo "Linux signing self-test accepted retired remote-signing environment input." >&2
    return 1
  fi
  unset WINS_LINUX_SIGNER_IDENTITY
  export WINS_LINUX_COSIGN_KEY="${ROOT}/tools/linux_release_signing.py"
  if python3 "${ROOT}/tools/linux_release_signing.py" preflight --repo "${ROOT}" >/dev/null 2>&1; then
    echo "Linux signing self-test accepted a repository-local signing key." >&2
    return 1
  fi
  export WINS_LINUX_COSIGN_KEY="$key_path"
  fake_cosign="${tmp_dir}/cosign"
  printf '#!/bin/sh\nexit 0\n' >"${fake_cosign}"
  chmod 0755 "${fake_cosign}"
  if python3 "${ROOT}/tools/linux_release_signing.py" authenticate-cosign \
      --repo "${ROOT}" --cosign "${fake_cosign}" >/dev/null 2>&1; then
    echo "Linux signing self-test accepted a cosign executable outside ${COSIGN_PATH}." >&2
    return 1
  fi
  printf 'LINUX SIGSTORE SIGNING SELF-TEST: PASS\n'
}

if [[ "${1:-}" == "--self-test-winn3-dual-auth-defines" ]]; then
  shift
  assert_linux_winn3_dual_auth_define_argv "$@"
  printf 'LINUX WINN3 DUAL-AUTH DEFINE SELF-TEST: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--self-test-winn3-relay-define" ]]; then
  shift
  assert_linux_winn3_relay_define_argv "$@"
  printf 'LINUX WINN3 RELAY DEFINE SELF-TEST: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--self-test-winn3-dual-auth-secondary" ]]; then
  [[ "$#" == 1 ]] || {
    echo "Usage: $0 --self-test-winn3-dual-auth-secondary" >&2
    exit 64
  }
  assert_no_secondary_linux_winn3_dual_auth_injection
  printf 'LINUX WINN3 DUAL-AUTH SECONDARY-INJECTION SELF-TEST: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--verify-winn3-dual-auth-bundle" ]]; then
  [[ "$#" == 2 ]] || {
    echo "Usage: $0 --verify-winn3-dual-auth-bundle <bundle-dir>" >&2
    exit 64
  }
  verify_linux_winn3_dual_auth_bundle "$2"
  printf 'LINUX WINN3 DUAL-AUTH BUNDLE: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--self-test-winn3-dual-auth-attestation" ]]; then
  [[ "$#" == 2 ]] || {
    echo "Usage: $0 --self-test-winn3-dual-auth-attestation <bundle-dir>" >&2
    exit 64
  }
  verify_linux_winn3_dual_auth_bundle_attestation "$2"
  printf 'LINUX WINN3 DUAL-AUTH ATTESTATION SELF-TEST: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--self-test-winn3-dual-auth-archive" ]]; then
  [[ "$#" == 2 ]] || {
    echo "Usage: $0 --self-test-winn3-dual-auth-archive <archive>" >&2
    exit 64
  }
  verify_linux_winn3_dual_auth_archive_attestation "$2"
  printf 'LINUX WINN3 DUAL-AUTH ARCHIVE SELF-TEST: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--self-test-release-archive-manifest" ]]; then
  [[ "$#" == 2 ]] || {
    echo "Usage: $0 --self-test-release-archive-manifest <archive>" >&2
    exit 64
  }
  verify_linux_archive_release_manifest "$2"
  exit 0
fi

if [[ "${1:-}" == "--self-test-native-host-closure" ]]; then
  [[ "$#" == 1 ]] || {
    echo "Usage: $0 --self-test-native-host-closure" >&2
    exit 64
  }
  closure_probe="$(mktemp)"
  if write_native_host_source_closure "${closure_probe}"; then
    rm -f "${closure_probe}"
  else
    status=$?
    rm -f "${closure_probe}"
    exit "${status}"
  fi
  printf 'LINUX NATIVE-HOST SOURCE CLOSURE: PASS (%s)\n' "${NATIVE_HOST_SOURCE_CLOSURE_SHA256}"
  exit 0
fi

if [[ "${1:-}" == "--self-test-native-host-store-ids" ]]; then
  [[ "$#" == 1 ]] || {
    echo "Usage: $0 --self-test-native-host-store-ids" >&2
    exit 64
  }
  read -r self_test_chrome_id self_test_edge_id < <(resolve_linux_native_host_store_ids) || exit 65
  printf 'LINUX NATIVE-HOST STORE IDS: PASS chrome=%s edge=%s\n' \
    "${self_test_chrome_id}" "${self_test_edge_id}"
  exit 0
fi

if [[ "${1:-}" == "--self-test-winn3-ring-identity" ]]; then
  [[ "$#" == 1 ]] || {
    echo "Usage: $0 --self-test-winn3-ring-identity" >&2
    exit 64
  }
  resolve_winn3_descriptor_ring_defines
  printf 'LINUX WINN3 RING IDENTITY: PASS (%s)\n' "${WINN3_RING_SHA256}"
  exit 0
fi

if [[ "${1:-}" == "--self-test-userspace-awg-runtime-pin" ]]; then
  assert_userspace_awg_runtime_pin_ready
  printf 'LINUX USERSPACE AWG RUNTIME PIN: PASS\n'
  exit 0
fi

# Print the install_tree_sha256 pin encoding (linux_winn3_source_tree_sha256)
# of an extracted toolchain tree, for recording a missing Linux pin.
if [[ "${1:-}" == "--measure-tree-sha256" ]]; then
  [[ "$#" == 2 && "$2" == /* ]] || {
    echo "Usage: $0 --measure-tree-sha256 <absolute extracted tree>" >&2
    exit 64
  }
  linux_winn3_source_tree_sha256 "$2" || exit 65
  printf '\n'
  exit 0
fi

if [[ "${1:-}" == "--self-test-linux-flutter-pub-pins" ]]; then
  assert_pinned_linux_flutter_pub_metadata all
  printf 'LINUX FLUTTER/PUB TOOLCHAIN PINS: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--self-test-linux-go-pins" ]]; then
  assert_pinned_linux_go_metadata
  printf 'LINUX GO TOOLCHAIN PINS: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--self-test-retained-release-source-custody" ]]; then
  run_retained_release_source_custody_self_test
  exit 0
fi

if [[ "${1:-}" == "--self-test-linux-tree-custody" ]]; then
  run_linux_tree_custody_self_test
  exit 0
fi

if [[ "${1:-}" == "--self-test-publication" ]]; then
  run_publication_transaction_self_test
  exit 0
fi

if [[ "${1:-}" == "--self-test-signing-public-key-custody" ]]; then
  [[ "$#" == 1 ]] || {
    echo "Usage: $0 --self-test-signing-public-key-custody" >&2
    exit 64
  }
  key_fixture="$(mktemp -d)"
  key_error="${key_fixture}/stderr"
  chmod 0700 "${key_fixture}"
  printf 'release-public-key-fixture\n' >"${key_fixture}/cosign.pub"
  printf 'release-public-key-fixture\n' >"${key_fixture}/trust.pub"
  chmod 0644 "${key_fixture}/cosign.pub" "${key_fixture}/trust.pub"
  key_pin="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "${key_fixture}/cosign.pub")"
  key_custody() {
    assert_linux_cosign_public_key_custody \
      "${key_fixture}/cosign.pub" "${key_fixture}/trust.pub" "${key_fixture}/trust.pub" "$1" \
      2>"${key_error}"
  }
  key_refused() {
    local expected_text="$1"
    shift
    if key_custody "$@"; then
      echo "Cosign public-key custody accepted: ${expected_text}" >&2
      exit 1
    fi
    grep -Fq "${expected_text}" "${key_error}" || {
      cat "${key_error}" >&2
      exit 1
    }
  }
  # A user-owned (not root-owned) trust anchor equal to the pin is accepted.
  key_custody "${key_pin}" || { cat "${key_error}" >&2; exit 1; }
  key_refused "LINUX_COSIGN_PUBLIC_KEY_SHA256 in tools/build_linux_release.sh is empty" ""
  key_refused "is not a lowercase sha256" "not-a-digest"
  key_refused "is not LINUX_COSIGN_PUBLIC_KEY_SHA256" "$(printf '%064d' 0)"
  printf 'substituted-trust-anchor\n' >"${key_fixture}/trust.pub"
  key_refused "installed trust anchor sha256" "${key_pin}"
  printf 'release-public-key-fixture\n' >"${key_fixture}/trust.pub"
  chmod 0664 "${key_fixture}/trust.pub"
  key_refused "hard-linked or group/other-writable" "${key_pin}"
  chmod 0644 "${key_fixture}/trust.pub"
  ln "${key_fixture}/trust.pub" "${key_fixture}/trust.second-link"
  key_refused "hard-linked or group/other-writable" "${key_pin}"
  rm -f "${key_fixture}/trust.second-link"
  mv "${key_fixture}/trust.pub" "${key_fixture}/trust.real"
  ln -s trust.real "${key_fixture}/trust.pub"
  key_refused "must be a regular non-symlink file" "${key_pin}"
  rm -f "${key_fixture}/trust.pub"
  mv "${key_fixture}/trust.real" "${key_fixture}/trust.pub"
  if assert_linux_cosign_public_key_custody \
      "${key_fixture}/cosign.pub" "${key_fixture}/trust.pub" \
      "/etc/winsvpn/release-signing/cosign.pub" "${key_pin}" 2>"${key_error}"; then
    echo "Cosign public-key custody accepted a non-canonical trust-anchor route." >&2
    exit 1
  fi
  grep -Fq 'trust-anchor route is not canonical' "${key_error}" || { cat "${key_error}" >&2; exit 1; }
  key_custody "${key_pin}" || { cat "${key_error}" >&2; exit 1; }
  rm -rf -- "${key_fixture}"
  printf 'LINUX COSIGN PUBLIC-KEY CUSTODY SELF-TEST: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--self-test-signing" ]]; then
  run_signing_self_test
  exit 0
fi

if [[ "${1:-}" == "--self-test-signing-deferral" ]]; then
  # Evaluates only the signing-deferral and remote-attestation mode guards
  # for the caller's environment; builds nothing.
  assert_linux_remote_attestation_mode || exit $?
  assert_linux_signing_deferral_mode || exit $?
  printf 'LINUX SIGNING DEFERRAL MODE: PASS signing=%s remote=%s\n' \
    "$(linux_remote_signing_mode)" "$(linux_remote_attested && echo 1 || echo 0)"
  exit 0
fi

if [[ "${1:-}" == "--self-test-build-lock" ]]; then
  run_build_lock_self_test
  exit 0
fi

if [[ "${1:-}" == "--self-test-path-scan" ]]; then
  run_binary_path_scan_self_test
  exit 0
fi

if [[ "${1:-}" == "--self-test-elf-machine" ]]; then
  [[ -n "${2:-}" && "${3:-}" =~ ^[0-9]+$ ]] || {
    echo "Usage: $0 --self-test-elf-machine <path> <expected-e_machine>" >&2
    exit 64
  }
  assert_release_elf_machine "$2" "$3" "ELF architecture self-test"
  printf 'LINUX ELF ARCHITECTURE SELF-TEST: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--self-test-release-controls" ]]; then
  [[ "$#" == 2 ]] || {
    echo "Usage: $0 --self-test-release-controls <release-index>" >&2
    exit 64
  }
  resolve_linux_release_controls "$2"
  printf 'LINUX RELEASE CONTROLS: PASS SOURCE_DATE_EPOCH=%s RELEASE_INDEX_SHA256=%s\n' \
    "${SOURCE_DATE_EPOCH}" "${LINUX_RELEASE_INDEX_SHA256}"
  exit 0
fi

if [[ "${1:-}" == "--self-test-bundle-architecture" ]]; then
  [[ -n "${2:-}" && -d "${2:-}" ]] || {
    echo "Usage: $0 --self-test-bundle-architecture <bundle-dir> <x64|arm64>" >&2
    exit 64
  }
  case "${3:-}" in
    x64|amd64) expected_self_test_machine=62 ;;
    arm64) expected_self_test_machine=183 ;;
    *)
      echo "Usage: $0 --self-test-bundle-architecture <bundle-dir> <x64|arm64>" >&2
      exit 64
      ;;
  esac
  assert_packaged_linux_elf_architecture "$2" "${expected_self_test_machine}"
  printf 'LINUX TARBALL BUNDLE ARCHITECTURE SELF-TEST: PASS (%s)\n' "$3"
  exit 0
fi

if [[ "${1:-}" == "--stage-engines" ]]; then
  [[ "$#" == 3 ]] || {
    echo "Usage: $0 --stage-engines <dest-dir> <x64|arm64>" >&2
    exit 64
  }
  engine_dest="$2"
  requested_arch="$3"
  case "${requested_arch}" in
    x64|arm64) ;;
    *)
      echo "Usage: $0 --stage-engines <dest-dir> <x64|arm64>" >&2
      exit 64
      ;;
  esac
  if [[ -L "${engine_dest}" ]]; then
    echo "refusing symlink engine destination: ${engine_dest}" >&2
    exit 65
  fi
  detect_linux_release_arch
  assert_linux_release_matching_host
  [[ "${requested_arch}" == "${LINUX_RELEASE_ARCH_LABEL}" ]] || {
    echo "refusing architecture-mismatched engine staging: requested ${requested_arch}, host ${LINUX_RELEASE_ARCH_LABEL}" >&2
    exit 65
  }
  [[ "${ROOT}" != /mnt/* ]] || {
    echo "refusing to stage engines from a /mnt Windows path." >&2
    exit 65
  }
  case "${engine_dest}" in
    */build/linux/*/release/bundle|*/build/linux/*/release/bundle/|*/build/linux/*/release/bundle/*)
      echo "refusing to stage store engines into a Flutter linux bundle." >&2
      exit 65
      ;;
  esac
  if [[ -e "${engine_dest}" ]]; then
    [[ -d "${engine_dest}" && ! -L "${engine_dest}" ]] || {
      echo "refusing symlink engine destination: ${engine_dest}" >&2
      exit 65
    }
  fi
  [[ -n "${WINS_ENGINE_SOURCE_ROOT:-}" && -d "${WINS_ENGINE_SOURCE_ROOT}" && ! -L "${WINS_ENGINE_SOURCE_ROOT}" ]] || {
    echo "store engine staging requires declared local source artifacts" >&2
    exit 65
  }
  mkdir -p -- "${engine_dest}"
  [[ -d "${engine_dest}" && ! -L "${engine_dest}" ]] || {
    echo "refusing symlink engine destination: ${engine_dest}" >&2
    exit 65
  }
  engine_dest_abs="$(cd -- "${engine_dest}" && pwd -P)"
  case "${engine_dest_abs}" in
    */build/linux/*/release/bundle|*/build/linux/*/release/bundle/|*/build/linux/*/release/bundle/*)
      echo "refusing to stage store engines into a Flutter linux bundle." >&2
      exit 65
      ;;
  esac
  tmp_dir="$(mktemp -d)"
  cleanup_engine_stage() {
    if [[ -n "${tmp_dir:-}" && -d "${tmp_dir}" ]]; then
      rm -rf -- "${tmp_dir}"
    fi
  }
  trap cleanup_engine_stage EXIT
  formal_index_path="$(resolve_release_input_index)"
  assert_linux_remote_attestation_mode
  assert_linux_signing_deferral_mode
  verify_linux_release_inputs_unchanged "${formal_index_path}"
  resolve_linux_release_controls "${formal_index_path}"
  assert_linux_release_inputs_ready
  export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:?}"
  stage_linux_engine_payloads "${engine_dest_abs}"
  printf 'LINUX ENGINE STAGE: PASS (%s -> %s)\n' "${LINUX_RELEASE_ARCH_LABEL}" "${engine_dest_abs}"
  exit 0
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script must run on Linux or WSL with Linux desktop build support." >&2
  exit 64
fi

# Detect before the WSL /mnt wrapper so an ARM64 WSL host publishes
# wins-vpn-linux-arm64.tar.gz and its matching private-symbol directory.
# Flutter still refuses x64-host to ARM64-target UI builds; this only names
# the native host architecture that the later child will actually compile.
detect_linux_release_arch
assert_linux_release_matching_host

if [[ "${ROOT}" == /mnt/* ]]; then
  run_from_neutral_wsl_stage
  exit 0
fi

bind_linux_obfuscation_paths "${LINUX_RELEASE_ARCH_LABEL}"
command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required to verify Linux release inputs and receipts." >&2
  exit 127
}
acquire_build_lock
tmp_dir="$(mktemp -d)"
formal_index_path="$(resolve_release_input_index)"
# M-1: fail before any Linux archive is accepted if a committed
# Xray/AmneziaWG binary embeds a Go runtime with known-fixed stdlib CVEs.
python3 "${ROOT}/tools/verify_embedded_engine_runtime_versions.py"
assert_linux_remote_attestation_mode
assert_linux_signing_deferral_mode
verify_linux_release_inputs_unchanged "${formal_index_path}"
resolve_linux_release_controls "${formal_index_path}"
assert_linux_release_inputs_ready
reject_unsupported_release_switches
initialize_linux_output_paths "${formal_index_path}"
preflight_linux_signing
if [[ "${WINS_LINUX_NEUTRAL_STAGE_ACTIVE:-0}" == "1" ]]; then
  assert_neutral_linux_stage
elif [[ "${WINS_LINUX_NEUTRAL_STAGE_ACTIVE:-0}" == "0" ]]; then
  initialize_formal_linux_receipt "${formal_index_path}"
else
  echo "WINS_LINUX_NEUTRAL_STAGE_ACTIVE must be 0 or 1." >&2
  exit 65
fi

if command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  log "Installing Flutter Linux desktop build dependencies"
  linux_build_apt=(
    sudo -n env
    DEBIAN_FRONTEND=noninteractive
    APT_LISTCHANGES_FRONTEND=none
    NEEDRESTART_MODE=a
    apt-get
    -o DPkg::Lock::Timeout=300
    -o Acquire::Retries=3
    -o Dpkg::Use-Pty=0
    -o Dpkg::Options::=--force-confdef
    -o Dpkg::Options::=--force-confold
  )
  "${linux_build_apt[@]}" update
  linux_apt_pin_args="$(python3 "${ROOT}/tools/verify_linux_apt_pins.py" emit-install)"
  read -r -a linux_apt_install_args <<<"${linux_apt_pin_args}"
  "${linux_build_apt[@]}" install -y \
    "${linux_apt_install_args[@]}"
elif command -v apt-get >/dev/null 2>&1; then
  log "Skipping apt dependency install because passwordless sudo is unavailable"
fi

# The pinned apt set is verified against dpkg even when the install step was
# skipped (a pre-provisioned builder image must still satisfy the pins, or the
# release is being produced against a distro drift no one recorded).
python3 "${ROOT}/tools/verify_linux_apt_pins.py" verify

prepare_pinned_linux_flutter_and_pub
command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required to validate the Linux release toolchain and artifacts." >&2
  exit 127
}
for native_tool in objcopy readelf strip; do
  command -v "$native_tool" >/dev/null 2>&1 || {
    echo "binutils tool $native_tool is required for Linux private debug-symbol custody." >&2
    exit 127
  }
done
read -r flutter_version flutter_revision < <(
  run_with_reviewed_flutter_pub_custody "${FLUTTER_COMMAND}" --version --machine | python3 -c '
import json
import sys
raw = sys.stdin.read()
start = raw.find("{")
end = raw.rfind("}")
if start < 0 or end < start:
    raise SystemExit("Flutter version JSON was not found.")
def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate Flutter toolchain identity key: {key}")
        result[key] = value
    return result
def reject_nonfinite(value):
    raise SystemExit(f"non-finite Flutter toolchain identity number: {value}")
identity = json.loads(
    raw[start : end + 1],
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_nonfinite,
)
expected_keys = {
    "frameworkVersion", "channel", "repositoryUrl", "frameworkRevision",
    "frameworkCommitDate", "engineRevision", "engineCommitDate",
    "engineContentHash", "engineBuildDate", "dartSdkVersion", "devToolsVersion",
    "flutterVersion", "flutterRoot",
}
if not isinstance(identity, dict) or set(identity) != expected_keys:
    raise SystemExit("Flutter toolchain identity fields are not exact")
print(identity["frameworkVersion"], identity["frameworkRevision"])
'
)
if [[ "$flutter_version" != "$REQUIRED_FLUTTER_VERSION" || "$flutter_revision" != "$REQUIRED_FLUTTER_REVISION" ]]; then
  echo "Linux release builds require reviewed Flutter ${REQUIRED_FLUTTER_VERSION} (${REQUIRED_FLUTTER_REVISION}); found ${flutter_version} (${flutter_revision})." >&2
  exit 65
fi
log "Verified Flutter ${flutter_version} (${flutter_revision})"

# The reviewed SDK archives ship no packages/flutter_tools/.dart_tool. Without
# it the Flutter tool's pub_dependencies cache step runs an online pub get for
# its own packages before the first pub, analyze, test or build command (it
# hangs without network and otherwise writes Pub's caches). Resolve it offline
# from the reviewed Pub cache; --enforce-lockfile keeps the SDK's
# packages/flutter_tools/pubspec.lock byte- and mtime-identical.
log "Resolving the Flutter tool's own packages offline"
run_with_reviewed_flutter_pub_custody \
  "${WINS_LINUX_FLUTTER_TREE_ROOT:?}/bin/cache/dart-sdk/bin/dart" pub get \
  --suppress-analytics --offline --enforce-lockfile \
  --directory "${WINS_LINUX_FLUTTER_TREE_ROOT:?}/packages/flutter_tools"

log "Enabling Linux desktop target"
run_with_reviewed_flutter_pub_custody \
  "${FLUTTER_COMMAND}" config --enable-linux-desktop

log "Resolving Dart packages"
rm -rf -- \
  "$ROOT/.dart_tool/flutter_build" \
  "$ROOT/build/flutter_assets" \
  "$ROOT/build/native_assets" \
  "$ROOT/build/.last_build_id" \
  "$ROOT/build/linux"
run_with_reviewed_flutter_pub_custody \
  "${FLUTTER_COMMAND}" pub get --offline --enforce-lockfile

log "Running static analysis"
run_with_reviewed_flutter_pub_custody "${FLUTTER_COMMAND}" analyze lib test --no-pub

log "Running tests"
# Tests that shell out run `dart` (and openssl, from the builder image's apt
# keep set): give them the pinned Flutter tree's own Dart SDK, never a host one.
run_with_reviewed_flutter_pub_custody /usr/bin/env \
  "PATH=${WINS_LINUX_FLUTTER_TREE_ROOT:?}/bin/cache/dart-sdk/bin:${PATH}" \
  "${FLUTTER_COMMAND}" test --no-pub
prove_linux_winn3_dual_auth_compiled_capability

log "Building Linux release"
reject_linux_winn3_dual_auth_environment_override
assert_no_secondary_linux_winn3_dual_auth_injection
assert_linux_winn3_dual_auth_define_argv "${WINN3_DUAL_AUTH_RELEASE_DEFINES[@]}"
assert_linux_winn3_relay_define_argv "${LINUX_WINN3_RELAY_RELEASE_DEFINES[@]}"
unset DART_DEFINES EXTRA_FRONT_END_OPTIONS EXTRA_GEN_SNAPSHOT_OPTIONS FLUTTER_TARGET
resolve_winn3_descriptor_ring_defines
[[ -n "${LINUX_SYMBOL_DIR}" && -n "${LINUX_OBFUSCATION_MANIFEST}" ]] || {
  echo "Linux obfuscation symbol paths were not bound to an architecture." >&2
  exit 65
}
rm -rf -- "${LINUX_SYMBOL_DIR}"
mkdir -p -- "${LINUX_SYMBOL_DIR}"
chmod 0700 -- \
  "$ROOT/.artifacts/private-release-symbols" \
  "$ROOT/.artifacts/private-release-symbols/linux" \
  "$(dirname "$LINUX_SYMBOL_DIR")" \
  "${LINUX_SYMBOL_DIR}"
flutter_release_command=(
  "${FLUTTER_COMMAND}" build linux --release --obfuscate --no-pub
  --split-debug-info="${LINUX_SYMBOL_DIR}"
  --extra-gen-snapshot-options=--strip
  --dart-define=WINS_WINN3_ENABLED_PLATFORMS=linux
  "${LINUX_WINN3_RELAY_RELEASE_DEFINES[@]}"
  "${WINN3_DUAL_AUTH_RELEASE_DEFINES[@]}" "${WINN3_RING_DEFINES[@]}"
)
export FLUTTER_ALREADY_LOCKED=true
export -f run_with_retained_release_source_custody_at_root
run_with_reviewed_flutter_pub_custody \
  /bin/bash -c 'run_with_retained_release_source_custody_at_root "$@"' _ \
  "${ROOT}" "${formal_index_path}" "${flutter_release_command[@]}"

BUNDLE_DIR="$ROOT/build/linux/${LINUX_RELEASE_ARCH_LABEL}/release/bundle"
LINUX_CMAKE_BUILD_DIR="$ROOT/build/linux/${LINUX_RELEASE_ARCH_LABEL}/release"

command -v cmake >/dev/null 2>&1 && command -v ctest >/dev/null 2>&1 || {
  echo "cmake and ctest are required for the Linux dual-auth native release gates." >&2
  exit 127
}
log "Running release-linked Winn v3 native host and fallback gates"
cmake --build "${LINUX_CMAKE_BUILD_DIR}" --target linux_winn3_host_test
cmake --build "${LINUX_CMAKE_BUILD_DIR}" --target linux_winn_gate_test
ctest --test-dir "${LINUX_CMAKE_BUILD_DIR}" --output-on-failure \
  -R '^(linux_winn3_host_test|linux_winn_gate_test)$'

# Prove the ring reached the COMPILED bytes, not just the command line. This
# scans lib/libapp.so itself; the verifier refuses a directory or a sidecar on
# purpose, so a receipt can never stand in for the AOT payload. Runs before the
# strip loop below, which touches wins_vpn and winsvpn-bypass-bpf only.
log "Verifying the Linux AOT payload carries the attested Winn3 ring identity"
python3 "$ROOT/tools/verify_winn3_ring_artifact.py" \
  "${WINN3_RING_SHA256}" "${BUNDLE_DIR}/lib/libapp.so"
write_winn3_descriptor_ring_attestation "${BUNDLE_DIR}" "${WINN3_RING_SHA256}"

mkdir -p -- "${LINUX_NATIVE_SYMBOL_DIR}"
chmod 0700 -- "${LINUX_NATIVE_SYMBOL_DIR}"

log "Extracting private native debug companions and stripping delivery binaries"
for owned_name in wins_vpn winsvpn-bypass-bpf; do
  owned_binary="${BUNDLE_DIR}/${owned_name}"
  private_debug="${LINUX_NATIVE_SYMBOL_DIR}/${owned_name}.debug"
  [[ -x "$owned_binary" ]] || {
    echo "Owned Linux ELF target is missing: ${owned_name}" >&2
    exit 65
  }
  objcopy --only-keep-debug "$owned_binary" "$private_debug"
  strip --strip-unneeded "$owned_binary"
  (
    cd "${LINUX_NATIVE_SYMBOL_DIR}"
    objcopy --add-gnu-debuglink="$(basename "$private_debug")" "$owned_binary"
  )
  chmod 0600 -- "$private_debug"

  delivery_sections="$(readelf -SW "$owned_binary")"
  debug_sections="$(readelf -SW "$private_debug" 2>/dev/null)"
  grep -q '[.]gnu_debuglink' <<<"$delivery_sections" || {
    echo "Stripped Linux target lacks .gnu_debuglink: ${owned_name}" >&2
    exit 65
  }
  grep -q '[.]note[.]gnu[.]build-id' <<<"$delivery_sections" || {
    echo "Stripped Linux target lacks a GNU build ID: ${owned_name}" >&2
    exit 65
  }
  if grep -Eq '[.]symtab|[.]debug_' <<<"$delivery_sections"; then
    echo "Delivery Linux target retains private symbols: ${owned_name}" >&2
    exit 65
  fi
  if ! grep -q '[.]symtab' <<<"$debug_sections" || \
     ! grep -q '[.]debug_info' <<<"$debug_sections"; then
    echo "Private Linux debug companion is incomplete: ${owned_name}" >&2
    exit 65
  fi
  delivery_build_id="$(readelf -n "$owned_binary" 2>/dev/null | awk '/Build ID:/ {print $3; exit}')"
  debug_build_id="$(readelf -n "$private_debug" 2>/dev/null | awk '/Build ID:/ {print $3; exit}')"
  [[ -n "$delivery_build_id" && "$delivery_build_id" == "$debug_build_id" ]] || {
    echo "Linux delivery/debug build IDs do not match: ${owned_name}" >&2
    exit 65
  }
done

scan_owned_binary_paths \
  "$BUNDLE_DIR/wins_vpn" \
  "$BUNDLE_DIR/winsvpn-bypass-bpf" \
  "$BUNDLE_DIR/lib/libapp.so"

LINUX_PACKAGING_DIR="$ROOT/linux/packaging"
grep -Fq "<release version=\"${APP_VERSION}\"" \
  "$LINUX_PACKAGING_DIR/org.winsvpn.app.metainfo.xml" || {
    echo "Linux AppStream metadata does not describe current app version ${APP_VERSION}." >&2
    exit 65
  }

assert_mandatory_dependencies_available_for_arch
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:?}"

build_and_stage_linux_native_host "${BUNDLE_DIR}" "${tmp_dir}"

stage_linux_engine_payloads "${BUNDLE_DIR}"

write_linux_winn3_dual_auth_attestation "${BUNDLE_DIR}"
verify_linux_winn3_dual_auth_bundle "${BUNDLE_DIR}"

log "Adding Linux install helper and third-party inventory"
install -m 0755 "$LINUX_PACKAGING_DIR/install.sh" "$BUNDLE_DIR/install.sh"
install -D -m 0644 "$ROOT/docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md" \
  "$BUNDLE_DIR/share/doc/wins-vpn/THIRD_PARTY_NOTICES.md"
# Ships on disk, deliberately. Its subject is a host with no internet and no
# LAN, so a support page on a website is unreadable exactly when it is needed.
install -D -m 0644 "$LINUX_PACKAGING_DIR/RECOVERY.md" \
  "$BUNDLE_DIR/share/doc/wins-vpn/RECOVERY.md"
# The offline recovery script and its boot unit. The unit is staged but never
# enabled; install.sh refuses a release that lacks any of the three files.
install -D -m 0755 "$LINUX_PACKAGING_DIR/winsvpn-recover" \
  "$BUNDLE_DIR/share/wins-vpn/winsvpn-recover"
install -D -m 0644 "$LINUX_PACKAGING_DIR/winsvpn-recover.service" \
  "$BUNDLE_DIR/share/wins-vpn/winsvpn-recover.service"

log "Adding Linux desktop store metadata"
install -D -m 0644 \
  "$LINUX_PACKAGING_DIR/org.winsvpn.app.desktop" \
  "$BUNDLE_DIR/share/applications/org.winsvpn.app.desktop"
install -D -m 0644 \
  "$LINUX_PACKAGING_DIR/org.winsvpn.app.metainfo.xml" \
  "$BUNDLE_DIR/share/metainfo/org.winsvpn.app.metainfo.xml"
install -D -m 0644 \
  "$ROOT/web/icons/Icon-512.png" \
  "$BUNDLE_DIR/share/icons/hicolor/512x512/apps/org.winsvpn.app.png"

# Files produced below /mnt/c in WSL can report mode 0777 even when they are
# ordinary assets. Never publish those host-derived permissions. Stage the
# complete bundle on the Linux filesystem and assign the minimal portable
# modes before creating the archive.
log "Normalizing Linux archive ownership and permissions"
package_tmp="$(mktemp -d)"
PACKAGE_ROOT="${package_tmp}/bundle"
mkdir -p -- "$PACKAGE_ROOT"
cp -a -- "$BUNDLE_DIR/." "$PACKAGE_ROOT/"
find "$PACKAGE_ROOT" -type d -exec chmod 0755 -- {} +
find "$PACKAGE_ROOT" -type f -exec chmod 0644 -- {} +
chmod 0755 -- \
  "$PACKAGE_ROOT/wins_vpn" \
  "$PACKAGE_ROOT/winsvpn-bypass-bpf" \
  "$PACKAGE_ROOT/install.sh" \
  "$PACKAGE_ROOT/share/wins-vpn/winsvpn-recover" \
  "$PACKAGE_ROOT/tools/native_messaging/host/wins_bridge_host" \
  "$PACKAGE_ROOT/tools/native_messaging/install_native_host.sh"
for required_bin in xray awg awg-quick amneziawg-go winn-datapath; do
  if [[ ! -f "$PACKAGE_ROOT/$required_bin" ]]; then
    echo "Linux release bundle is missing required fallback binary: $required_bin" >&2
    exit 65
  fi
  chmod 0755 -- "$PACKAGE_ROOT/$required_bin"
done
assert_packaged_linux_elf_architecture "$PACKAGE_ROOT" "$LINUX_RELEASE_ELF_MACHINE"

# M-2: an unsigned but exhaustive manifest, generated last (after every other
# file in PACKAGE_ROOT has its final bytes/mode) and covering every one of
# them by construction. It does not authenticate the release on its own --
# that comes from cosign-signing the whole archive below via
# sign_linux_release(), which install-winsvpn-linux.sh verifies before ever
# extracting anything -- it exists so install.sh (running inside an already
# cosign-verified, root-owned stage) can still catch accidental corruption or
# local tampering of individual files, matching the path format its own
# verify_release_manifest() expects (relative, no leading "./").
log "Generating exhaustive release manifest"
# Write outside PACKAGE_ROOT first: creating the manifest file directly
# inside the tree that `find .` is still walking risks find() observing its
# own (still being written) output as just another member to hash.
manifest_tmp="${package_tmp}/release-manifest.sha256"
(
  cd "$PACKAGE_ROOT"
  find . -type f -print0 \
    | LC_ALL=C sort -z \
    | sed -z 's|^\./||' \
    | xargs -0 sha256sum \
    > "$manifest_tmp"
)
install -m 0644 -- "$manifest_tmp" "$PACKAGE_ROOT/release-manifest.sha256"

log "Packaging release bundle"
prepare_linux_publication_stage
# Byte-reproducibility of the release archive (measured 2026-08-11,
# bld_reprobuild): BSD tar writes members in readdir order and stamps each
# member (and the gzip header) with the build wall-clock, so two builds of
# identical bytes differ solely on order+timestamps. GNU tar's --sort=name and
# a fixed --mtime, followed by `gzip -n` (mtime 0 header), make the whole
# archive a pure function of the bundle bytes. SOURCE_DATE_EPOCH is the exact
# release-index created_utc epoch resolved before compilation, so one
# release-bound epoch governs every signed artifact. The archive is byte-
# deterministic: verified with a real GNU tar two-build cmp (see
# docs/handoff/BUILD_REPRODUCIBILITY_ASSESSMENT_20260810_ds_reprobuild.md and
# REPRODUCIBLE_RELEASE_ARCHIVE_20260811_bld_reprobuild.md).
assert_gnu_tar
begin_linux_signed_publication_custody
open_linux_publication_output_under_custody "${staged_archive}"
tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
  -C "$PACKAGE_ROOT" -cf - . | gzip -n >&${publication_writer_fd}
finalize_linux_publication_output_under_custody "${staged_archive}" 0644
seal_linux_publication_custody_path "${staged_installer_bootstrap}" file
write_staged_archive_checksum
staged_archive_read="$(linux_publication_custody_path_for_read "${staged_archive}")"

python3 - "$staged_archive_read" "$SOURCE_DATE_EPOCH" "$LINUX_RELEASE_ELF_MACHINE" <<'PY'
import pathlib
import struct
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
try:
    source_date_epoch = int(sys.argv[2])
    expected_machine = int(sys.argv[3])
except (IndexError, ValueError):
    raise SystemExit(
        "Linux archive determinism check requires SOURCE_DATE_EPOCH and the "
        "target ELF e_machine."
    )
if expected_machine not in {62, 183}:
    raise SystemExit(f"Unsupported Linux release ELF machine: {expected_machine}")
executables = {
    "wins_vpn",
    "winsvpn-bypass-bpf",
    "xray",
    "awg",
    "awg-quick",
    "amneziawg-go",
    "winn-datapath",
    "install.sh",
    "share/wins-vpn/winsvpn-recover",
    "tools/native_messaging/host/wins_bridge_host",
    "tools/native_messaging/install_native_host.sh",
}
required_payloads = {
    "lib/libapp.so",
    "lib/libflutter_linux_gtk.so",
    "release-manifest.sha256",
    "winn3-descriptor-ring-attestation.json",
    "winn3-dual-auth-release-attestation.json",
}
with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    if not members:
        raise SystemExit("Linux archive is empty.")
    # Determinism invariants (see ds_reprobuild assessment: two builds of
    # identical bundle bytes must produce byte-identical archives). Namely
    # (1) members are written in sorted name order, and (2) every member mtime
    # is normalized to SOURCE_DATE_EPOCH. A regression that re-introduces a
    # build wall-clock or readdir order must fail here, not silently ship a
    # non-reproducible archive.
    if [m.name for m in members] != sorted(m.name for m in members):
        raise SystemExit("Linux archive members are not in sorted name order; "
                         "rebuild determinism is broken.")
    for member in members:
        if member.name != "." and member.name != "./" and member.mtime != source_date_epoch:
            raise SystemExit(f"Linux archive member mtime is not normalized to "
                             f"SOURCE_DATE_EPOCH={source_date_epoch}: {member.name!r}")
    with archive.open("rb") as raw:
        head = raw.read(10)
    if head[:2] != b"\x1f\x8b":
        raise SystemExit("Linux release archive is not gzip.")
    gzip_mtime = int.from_bytes(head[4:8], "little")
    if gzip_mtime != 0:
        raise SystemExit(f"Linux archive gzip header carries a build time "
                         f"(mtime={gzip_mtime}); use gzip -n for determinism.")
    for member in members:
        normalized = member.name.removeprefix("./")
        if normalized in {"", "."}:
            if not member.isdir() or member.mode != 0o755 or member.uid != 0 or member.gid != 0:
                raise SystemExit("Linux archive root entry has unsafe metadata.")
            continue
        path = pathlib.PurePosixPath(normalized)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"Unsafe Linux archive member path: {member.name!r}")
        if path.suffix.lower() in {".debug", ".symbols", ".pdb"}:
            raise SystemExit(f"Private symbol material entered Linux archive: {member.name!r}")
        if member.uid != 0 or member.gid != 0:
            raise SystemExit(f"Linux archive member is not numerically root-owned: {member.name!r}")
        if member.isdir():
            expected_mode = 0o755
        elif member.isfile():
            expected_mode = 0o755 if normalized in executables else 0o644
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise SystemExit(f"Linux archive member could not be read: {member.name!r}")
            payload = extracted.read()
            if payload.startswith(b"\x7fELF"):
                if len(payload) < 64 or payload[:7] != b"\x7fELF\x02\x01\x01":
                    raise SystemExit(
                        f"Linux archive member is not little-endian ELF64: {normalized}"
                    )
                header = struct.unpack_from("<16sHHIQQQIHHHHHH", payload, 0)
                elf_type, machine, version, entry = header[1], header[2], header[3], header[4]
                if machine == 183 and entry % 4 != 0:
                    raise SystemExit(
                        f"Linux archive AArch64 entry point is not 4-byte aligned: {normalized}"
                    )
                phoff, ehsize, phentsize, phnum = header[5], header[8], header[9], header[10]
                if (
                    elf_type not in {2, 3}
                    or version != 1
                    or ehsize != 64
                    or phentsize != 56
                    or phnum == 0
                    or phnum > 4096
                    or phoff < ehsize
                    or phoff + phentsize * phnum > len(payload)
                ):
                    raise SystemExit(
                        f"Linux archive member has an invalid ELF64 structure: {normalized}"
                    )
                executable_role = normalized in executables
                executable_load = False
                readable_loads = []
                dynamic_segments = []
                interpreter_segments = []
                entry_bound = False
                entry_file_offset = None
                for index in range(phnum):
                    kind, flags, offset, vaddr, _paddr, filesz, memsz, alignment = struct.unpack_from(
                        "<IIQQQQQQ", payload, phoff + index * phentsize
                    )
                    if (
                        filesz > memsz
                        or offset > len(payload)
                        or filesz > len(payload) - offset
                        or (alignment not in {0, 1} and alignment & (alignment - 1))
                        or (
                            kind == 1
                            and alignment not in {0, 1}
                            and (vaddr - offset) % alignment != 0
                        )
                    ):
                        raise SystemExit(
                            f"Linux archive member has an invalid ELF segment: {normalized}"
                        )
                    if kind == 1:
                        if memsz == 0:
                            raise SystemExit(
                                f"Linux archive member has an empty PT_LOAD: {normalized}"
                            )
                        if flags & 4:
                            readable_loads.append((vaddr, vaddr + memsz))
                        if flags & 1:
                            if filesz == 0:
                                raise SystemExit(
                                    f"Linux archive member has an empty executable PT_LOAD: {normalized}"
                                )
                            executable_load = True
                            if entry != 0 and vaddr <= entry < vaddr + memsz and entry - vaddr < filesz:
                                entry_bound = True
                                entry_file_offset = offset + (entry - vaddr)
                    elif kind == 2:
                        dynamic_segments.append((vaddr, vaddr + memsz, offset, offset + filesz))
                    elif kind == 3:
                        interpreter_segments.append((offset, offset + filesz))
                if not executable_load:
                    raise SystemExit(
                        f"Linux archive member is a header-only or non-executable ELF: {normalized}"
                    )
                if executable_role:
                    entry_code = payload[entry_file_offset:entry_file_offset + 16] if entry_file_offset is not None else b""
                    entry_defined = bool(entry_code) and not entry_code.startswith(b"\0" * min(4, len(entry_code)))
                    if machine == 62:
                        entry_defined = entry_defined and not (
                            entry_code.startswith(b"\xcc")
                            or entry_code.startswith(b"\xf4")
                            or entry_code.startswith(b"\x0f\x0b")
                        )
                    elif machine == 183 and len(entry_code) >= 4:
                        instruction = int.from_bytes(entry_code[:4], "little")
                        entry_defined = entry_defined and instruction & 0xFFE0001F not in {
                            0xD4200000, 0xD4400000,
                        }
                    else:
                        entry_defined = False
                    if entry == 0 or not entry_bound or not entry_defined:
                        raise SystemExit(
                            f"Linux archive executable has no loadable entry point or it is undefined/trap-only: {normalized}"
                        )
                    if len(interpreter_segments) > 1 or len(dynamic_segments) > 1:
                        raise SystemExit(f"Linux archive executable has duplicate loader segments: {normalized}")
                    for interp_start, interp_end in interpreter_segments:
                        interp = payload[interp_start:interp_end]
                        if not interp or interp[-1:] != b"\0" or b"\0" in interp[:-1]:
                            raise SystemExit(f"Linux archive executable has an invalid PT_INTERP: {normalized}")
                    if elf_type == 3 and len(dynamic_segments) != 1:
                        raise SystemExit(f"Linux archive ET_DYN executable lacks PT_DYNAMIC: {normalized}")
                    if interpreter_segments and len(dynamic_segments) != 1:
                        raise SystemExit(f"Linux archive dynamic executable lacks PT_DYNAMIC: {normalized}")
                elif (
                    elf_type != 3
                    or entry != 0
                    or len(dynamic_segments) != 1
                    or interpreter_segments
                    or not any(
                        load_start <= dynamic_segments[0][0]
                        < dynamic_segments[0][1] <= load_end
                        for load_start, load_end in readable_loads
                    )
                ):
                    raise SystemExit(
                        f"Linux archive shared object lacks loadable ET_DYN/PT_DYNAMIC semantics: {normalized}"
                    )
                if machine != expected_machine:
                    raise SystemExit(
                        "refusing mixed-architecture archive: "
                        f"{normalized} targets ELF machine {machine}, "
                        f"expected {expected_machine}"
                    )
        else:
            raise SystemExit(f"Unsupported Linux archive member type: {member.name!r}")
        if member.mode != expected_mode:
            raise SystemExit(
                f"Unsafe Linux archive mode {member.mode:#o} for {member.name!r}; "
                f"expected {expected_mode:#o}"
            )
    names = {
        member.name.removeprefix("./")
        for member in members
        if member.isfile()
    }
    required_fallback_missing = sorted(executables - names)
    if required_fallback_missing:
        raise SystemExit(
            "Linux archive is missing required executables: "
            + ", ".join(required_fallback_missing)
        )
    required_payload_missing = sorted(required_payloads - names)
    if required_payload_missing:
        raise SystemExit(
            "Linux archive is missing required Flutter/runtime payloads: "
            + ", ".join(required_payload_missing)
        )
print(f"LINUX ARCHIVE METADATA: PASS ({len(members)} members)")
PY

verify_linux_archive_release_manifest "${staged_archive_read}"
verify_linux_winn3_dual_auth_archive "${staged_archive_read}"

# These tools validate named files (the target type is inferred from the file
# name and the evidence binds the name) and refuse symbolic links, so they cannot
# read the /proc/<pid>/fd held-descriptor path that linux_publication_custody_path_for_read
# returns. They get the real staged path. A pathname can be pointed at another
# archive while the held descriptor still carries the sealed one, and comparing
# identity and bytes before and after a tool cannot see that, so each invocation
# runs under run_with_linux_tree_custody: the staged archive must still carry the
# digest sealed in producer custody when the tool starts, is watched while the tool
# runs, and keeps its identity afterwards.
staged_archive_tree_custody=""
for custody_spec in "${publication_custody_specs[@]}"; do
  IFS='|' read -r custody_fd custody_kind custody_sha256 custody_path <<< "${custody_spec}"
  if [[ "${custody_path}" == "${staged_archive}" && "${custody_kind}" == "sealed-file" &&
        "${custody_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
    staged_archive_tree_custody="${custody_sha256}=${staged_archive}"
  fi
done
[[ -n "${staged_archive_tree_custody}" ]] || {
  echo "The staged Linux archive has no sealed file custody." >&2
  exit 65
}
assert_linux_signed_publication_custody
run_with_linux_tree_custody "${staged_archive_tree_custody}" -- \
  "${LINUX_SYSTEM_PYTHON}" -E -s "$ROOT/tools/validate_release_artifact_privacy.py" --artifacts \
  --target "linux-${LINUX_RELEASE_ARCH_LABEL}-package" \
  --artifact "$staged_archive"
run_with_linux_tree_custody "${staged_archive_tree_custody}" -- \
  "${LINUX_SYSTEM_PYTHON}" -E -s "$ROOT/tools/release_obfuscation_contract.py" record \
  --platform linux \
  --symbols-dir "$LINUX_SYMBOL_DIR" \
  --manifest "$LINUX_OBFUSCATION_MANIFEST" \
  --target-id "linux-${LINUX_RELEASE_ARCH_LABEL}-package" \
  --artifact "$staged_archive"
run_with_linux_tree_custody "${staged_archive_tree_custody}" -- \
  "${LINUX_SYSTEM_PYTHON}" -E -s "$ROOT/tools/release_obfuscation_contract.py" verify \
  --platform linux \
  --symbols-dir "$LINUX_SYMBOL_DIR" \
  --manifest "$LINUX_OBFUSCATION_MANIFEST" \
  --target-id "linux-${LINUX_RELEASE_ARCH_LABEL}-package" \
  --artifact "$staged_archive"
run_with_linux_tree_custody "${staged_archive_tree_custody}" -- \
  "${LINUX_SYSTEM_PYTHON}" -I "$ROOT/tools/private_release_symbol_custody.py" record \
  --platform linux \
  --symbols-dir "$LINUX_SYMBOL_DIR" \
  --artifact "$staged_archive"
run_with_linux_tree_custody "${staged_archive_tree_custody}" -- \
  "${LINUX_SYSTEM_PYTHON}" -I "$ROOT/tools/private_release_symbol_custody.py" verify \
  --platform linux \
  --symbols-dir "$LINUX_SYMBOL_DIR" \
  --artifact "$staged_archive"
assert_linux_signed_publication_custody
stage_linux_private_symbols "$LINUX_SYMBOL_DIR"
extend_linux_signed_publication_custody "${staged_private_symbols}" directory
seal_linux_publication_custody_path "${staged_private_symbols}" directory
# An exact target is bound to its one immutable symbol directory, so the
# obfuscation and custody tools verify that directory, not the staged copy. The
# staged copy is sealed above, and a one-time comparison would let the canonical
# directory be swapped for the comparison and put back for the tools. So both
# final invocations authenticate the canonical directory against the digest sealed
# for the staged copy (the same encoding, length-framed) and watch it while they
# read it: the published symbols are exactly the verified ones.
staged_symbols_tree_custody=""
for custody_spec in "${publication_custody_specs[@]}"; do
  IFS='|' read -r custody_fd custody_kind custody_sha256 custody_path <<< "${custody_spec}"
  if [[ "${custody_path}" == "${staged_private_symbols}" && "${custody_kind}" == "sealed-directory" &&
        "${custody_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
    staged_symbols_tree_custody="${custody_sha256}=${LINUX_SYMBOL_DIR}"
  fi
done
[[ -n "${staged_symbols_tree_custody}" ]] || {
  echo "The staged Linux symbols have no sealed directory custody." >&2
  exit 65
}
diff -rq --no-dereference -- "$LINUX_SYMBOL_DIR" "$staged_private_symbols"
run_with_linux_tree_custody "--publication-directory-root=${LINUX_SYMBOL_DIR}" \
  "${staged_archive_tree_custody}" "${staged_symbols_tree_custody}" -- \
  "${LINUX_SYSTEM_PYTHON}" -E -s "$ROOT/tools/release_obfuscation_contract.py" verify \
  --platform linux \
  --symbols-dir "$LINUX_SYMBOL_DIR" \
  --manifest "$LINUX_OBFUSCATION_MANIFEST" \
  --target-id "linux-${LINUX_RELEASE_ARCH_LABEL}-package" \
  --artifact "$staged_archive"
run_with_linux_tree_custody "--publication-directory-root=${LINUX_SYMBOL_DIR}" \
  "${staged_archive_tree_custody}" "${staged_symbols_tree_custody}" -- \
  "${LINUX_SYSTEM_PYTHON}" -I "$ROOT/tools/private_release_symbol_custody.py" verify \
  --platform linux \
  --symbols-dir "$LINUX_SYMBOL_DIR" \
  --artifact "$staged_archive"
assert_linux_signed_publication_custody

sign_linux_release "$staged_archive" "$staged_bundle"
if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
  [[ -f "${staged_bundle}" && ! -L "${staged_bundle}" && -s "${staged_bundle}" ]] || {
    echo "Linux signing completed without a safe staged Sigstore bundle." >&2
    exit 65
  }
  chmod 0644 -- "${staged_bundle}"
  extend_linux_signed_publication_custody "${staged_bundle}"
  seal_linux_publication_custody_path "${staged_bundle}" file
fi
write_linux_publication_receipt
extend_linux_signed_publication_custody "${staged_publication_receipt}"
seal_linux_publication_custody_path "${staged_publication_receipt}" file
if [[ "${SIGN_LINUX_RELEASE:-0}" == "1" ]]; then
  sign_linux_release \
    "${staged_publication_receipt}" "${staged_publication_receipt_bundle}"
  [[ -f "${staged_publication_receipt_bundle}" && \
     ! -L "${staged_publication_receipt_bundle}" && \
     -s "${staged_publication_receipt_bundle}" ]] || {
    echo "Linux publication receipt signing completed without a safe Sigstore bundle." >&2
    exit 65
  }
  extend_linux_signed_publication_custody "${staged_publication_receipt_bundle}"
  seal_linux_publication_custody_path "${staged_publication_receipt_bundle}" file
fi
verify_linux_publication_receipt
assert_linux_signed_publication_custody

verify_linux_release_inputs_unchanged "$formal_index_path"
if [[ "${WINS_LINUX_NEUTRAL_STAGE_ACTIVE:-0}" == "0" ]]; then
  complete_formal_linux_receipt "$formal_index_path" "$staged_archive"
fi
commit_linux_publication
close_linux_signed_publication_custody

log "Release archive ready: $ARCHIVE"
cat -- "$ARCHIVE_SHA_PATH"

# arm64lane 2026-08-08: was a literal (single-quoted, non-expanding) heredoc
# hardcoding "wins-vpn-linux-x64.tar.gz" here even though the archive-naming
# logic earlier in this script (ARCHIVE=...) already parameterizes by
# LINUX_RELEASE_ARCH_LABEL. Harmless while this script only ever completed on
# amd64, but would have printed a wrong filename in a real arm64 release's
# own install instructions the moment one succeeded. Switched to an
# expanding heredoc; nothing else in this block contains '$' or backticks.
cat <<EOF

Linux runtime notes:
- Verify and install with: ./install-winsvpn-linux.sh wins-vpn-linux-${LINUX_RELEASE_ARCH_LABEL:-x64}.tar.gz wins-vpn-linux-${LINUX_RELEASE_ARCH_LABEL:-x64}.tar.gz.sigstore.json
  This cosign-verifies the exact archive *before* extracting anything. Linux release archives require the owner-provisioned local public key at /etc/winsvpn/release-signing/cosign.pub. Do not extract the archive and run install.sh directly -- it refuses to run outside the stage this bootstrap creates.
- Pinned AmneziaWG tools and a pinned, statically linked userspace fallback are bundled on both x86_64 and arm64. A compatible host kernel module remains the faster first choice.
- Pinned Xray 26.9.30 is bundled on both x86_64 and arm64 for Single VPN and Double VPN fallback.
- Winn Protocol v3 (winn-datapath) is mandatory on every architecture.
- Signed builds emit and immediately verify a Cosign 3.1.3 standardized Sigstore bundle with the owner-held local cosign key pair.
- The app uses PolicyKit pkexec when available, otherwise sudo -n/root, to create and remove the VPN interface.
EOF
