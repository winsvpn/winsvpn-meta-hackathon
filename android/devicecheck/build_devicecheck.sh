#!/usr/bin/env bash
set -Eeuo pipefail

# DEVICECHECK_PRODUCER_DISABLED=immutable-compiler-input-v1
# Fail-closed entrypoint reserved for the future externally authenticated
# DeviceCheck compiler-input transaction. This file deliberately contains no
# SDK, Go, Gradle, signing, artifact-publication, or device execution body.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_DIR="$(cd "${HERE}/.." && pwd)"
PROJECT_ROOT="$(cd "${ANDROID_DIR}/.." && pwd)"
SRC="${ANDROID_DIR}/app/src/main/kotlin/org/winsvpn/app"
DST="${HERE}/app/src/main/kotlin/org/winsvpn/app"
JNI="${HERE}/app/src/main/jniLibs/arm64-v8a"
ENGINE_KIND="${WINN_DEVICECHECK_ENGINE:-real}"
GO_MODULE="${PROJECT_ROOT}/winn_protocol_experimental"
ADB_SERIAL="${WINS_DEVICECHECK_ADB_SERIAL:-ZY22GTV6Z3}"
APP_ID="org.winsvpn.devicecheck"
TARGET_APP_ID="org.winsvpn.app.debug"
REVIEWED_GO_VERSION="1.27.1"
AWG_GO_MODULE="github.com/amnezia-vpn/amneziawg-go/v3"
AWG_GO_VERSION="v3.1.20260828"
AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"
RECEIPT_TOOL="${HERE}/devicecheck_build_receipt.py"
REVIEWED_BUILD_TOOLS_VERSION="36.0.0"
RELEASE_PYTHON="/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3"
SOURCE_AUTHORITY_ROOT="/Library/WinsVPN/ReleaseAndroidSource/devicecheck-v3"
SOURCE_SNAPSHOT_BASE="${SOURCE_AUTHORITY_ROOT}/snapshots/sha256"
SOURCE_MANIFEST_BASE="${SOURCE_AUTHORITY_ROOT}/manifests/sha256"
RELEASE_LOADER="${SOURCE_AUTHORITY_ROOT}/loader.py"
RELEASE_CONTROLLER="${SOURCE_AUTHORITY_ROOT}/controller.py"
OWNER_AUTHORITY="${SOURCE_AUTHORITY_ROOT}.authority.json"
OWNER_SIGNER_CERTIFICATE="/Library/WinsVPN/ReleaseAndroidSigning/devicecheck-owner.x509.pem"
BUILD_WORKSPACE_ROOT="/private/var/winsvpn-devicecheck-build"
BUILD_CACHE_ROOT="/private/var/winsvpn-devicecheck-cache"
SOURCE_CUSTODY_CONTRACT="winsvpn-devicecheck-source-custody-v2"
OWNER_AUTHORITY_CONTRACT="winsvpn-devicecheck-owner-authority-v4"
BUILD_HANDOFF_CONTRACT="winsvpn-devicecheck-private-build-handoff-v1"
ATOMIC_PUBLICATION_CONTRACT="winsvpn-devicecheck-content-addressed-publication-v1"
SOURCE_CONSUMER_STATUS="unintegrated"

# Production builds are launched only by the fixed external owner controller.
# Environment strings are never authorization. The controller must retain the
# root-owned v4 authority, exact ReleasePython/loader/controller/certificate,
# one immutable transaction ticket, its writable monotonic single-use state,
# and the authority-bound workspace receipt tool on fixed descriptors 9
# through 16. The authority selects one manifest and snapshot only by their
# sha256 content-addressed v3 paths and binds the private fresh workspace/cache
# handoff. Environment strings are ignored. No mutable workspace Python
# pathname is executed before the held loader authenticates and consumes the
# transaction.
if [[ -L "${BASH_SOURCE[0]}" || ! -f "${BASH_SOURCE[0]}" ||
      "$(stat -f '%l' "${BASH_SOURCE[0]}")" != "1" ]]; then
  echo "OWNER-BLOCKED: DeviceCheck producer script must be a one-link regular file." >&2
  exit 1
fi
if [[ "$(id -u)" == "0" ]]; then
  echo "OWNER-BLOCKED: DeviceCheck builds require the private non-root build user." >&2
  exit 1
fi
if [[ -L "${PROJECT_ROOT}" || "$(stat -f '%Lp' "${PROJECT_ROOT}")" != "700" ||
      "$(stat -f '%u' "${PROJECT_ROOT}")" != "$(id -u)" ]]; then
  echo "OWNER-BLOCKED: DeviceCheck transaction workspace must be private 0700 and build-user owned." >&2
  exit 1
fi
case "${PROJECT_ROOT}" in
  /private/var/winsvpn-devicecheck-build/*) ;;
  *)
    echo "OWNER-BLOCKED: DeviceCheck transaction workspace is outside the fixed private root." >&2
    exit 1
    ;;
esac

require_held_path_fd() {
  local fd="$1" label="$2" path="$3" expected_uid="$4" expected_mode="$5" immutable="$6"
  local fd_meta path_meta fd_device fd_inode fd_uid fd_mode fd_flags
  local path_device path_inode path_uid path_mode path_flags
  if [[ ! -r "/dev/fd/${fd}" || ! -e "${path}" || -L "${path}" ]]; then
    echo "OWNER-BLOCKED: ${label} held descriptor or fixed path is absent." >&2
    exit 1
  fi
  fd_meta="$(stat -Lf '%d:%i:%u:%Lp:%Sf' "/dev/fd/${fd}")"
  path_meta="$(stat -f '%d:%i:%u:%Lp:%Sf' "${path}")"
  IFS=: read -r fd_device fd_inode fd_uid fd_mode fd_flags <<< "${fd_meta}"
  IFS=: read -r path_device path_inode path_uid path_mode path_flags <<< "${path_meta}"
  if [[ "${fd_device}:${fd_inode}" != "${path_device}:${path_inode}" ||
        "${fd_uid}:${fd_mode}" != "${expected_uid}:${expected_mode}" ||
        "${path_uid}:${path_mode}" != "${expected_uid}:${expected_mode}" ]]; then
    echo "OWNER-BLOCKED: ${label} held/path identity, UID, or mode is invalid." >&2
    exit 1
  fi
  if [[ "${immutable}" == "yes" &&
        ( "${fd_flags}" != *schg* || "${path_flags}" != *schg* ) ]]; then
    echo "OWNER-BLOCKED: ${label} is not system immutable." >&2
    exit 1
  fi
}

require_held_path_fd 9 "transaction ticket" \
  "${PROJECT_ROOT}/.devicecheck-source-transaction.json" 0 400 yes
require_held_path_fd 10 "ReleasePython" "${RELEASE_PYTHON}" 0 555 yes
require_held_path_fd 11 "release loader" "${RELEASE_LOADER}" 0 444 yes
require_held_path_fd 12 "release controller" "${RELEASE_CONTROLLER}" 0 444 yes
if [[ ! -r /dev/fd/13 || ! -w /dev/fd/13 ||
      "$(stat -Lf '%u:%Lp' /dev/fd/13)" != "0:600" ]]; then
  echo "OWNER-BLOCKED: monotonic controller state descriptor is absent or invalid." >&2
  exit 1
fi
require_held_path_fd 14 "owner authority" "${OWNER_AUTHORITY}" 0 444 yes
require_held_path_fd 15 "owner signer certificate" "${OWNER_SIGNER_CERTIFICATE}" 0 444 yes
require_held_path_fd 16 "authority-bound receipt tool" "${RECEIPT_TOOL}" "$(id -u)" 444 no

"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate \
  --repo-root "${PROJECT_ROOT}"

# Parser-only selftest still requires the authenticated gate. It executes the
# held authority-bound receipt tool, then returns before SDK or device work.
if [[ "${WINN_DEVICECHECK_RECEIPT_SELFTEST:-}" == "1" ]]; then
  exec "${RELEASE_PYTHON}" -I -S /dev/fd/16 selftest
fi

# The authenticated gate above proves authority and keeps the parser-only
# selftest available, but this workspace script cannot hand immutable source,
# Gradle layout, SDK, NDK, Go layout, and private cache descriptors to their
# compilers. The source closure digest identifies input bytes only; it is never
# substituted for descriptor custody of either built APK. Production must stay
# stopped until the external controller/loader implements that handoff and
# direct target plus androidTest APK custody.
echo "OWNER-BLOCKED: immutable compiler-input handoff is not implemented by the external controller/loader." >&2
exit 1

# No SDK, Go, Gradle, signing, output-publication, or device command is kept
# in this workspace script. Keeping a dormant mutable build body after the
# blocker would let a hostile shell bootstrap or extracted tail execute it.
# The future external controller must supply the complete descriptor-bound
# compiler-input transaction in separately reviewed, authenticated bytes.
# The following identifiers are inert schema documentation for receipt-parser
# interoperability tests. They are comments, not a producer implementation:
# GRADLE_VARIANT="debug"
# GRADLE_TARGET_TASK=":app:assembleDebug"
# GRADLE_TEST_TASK=":app:assembleDebugAndroidTest"
# GRADLE_VARIANT="release"
# GRADLE_TARGET_TASK=":app:assembleRelease"
# GRADLE_TEST_TASK=":app:assembleReleaseAndroidTest"
# "${RELEASE_PYTHON}" -I -S /dev/fd/16 record
# WINN_DEVICECHECK_PRODUCER_ONLY
