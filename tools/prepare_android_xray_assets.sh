#!/usr/bin/env bash
set -Eeuo pipefail

# Run from your Flutter project root, or pass android/app as the first argument:
#   tools/prepare_android_xray_assets.sh android/app
# The Kotlin service loads Xray from nativeLibraryDir as libxray.so.
#
# M-1 remediation: these libxray.so files used to be downloaded straight from
# XTLS/Xray-core's own GitHub release archives. That upstream release embeds
# go1.26.1, which predates several fixed stdlib CVEs (see
# docs/RELEASE_ENGINE_BINARY_REFRESH.md). This script now instead rebuilds the
# exact same already-reviewed Xray-core source commit itself, using the
# pinned, independently-verified Go 1.27.1 toolchain, via
# tools/build_xray_engine.sh. It intentionally does not bump the Xray-core
# version -- only the Go compiler underneath it changes.
#
# Requires network access (clones Xray-core, downloads the pinned Go
# toolchain) and reviewed Android NDK 30.0.16248370 (ANDROID_NDK_HOME, or a
# standard SDK layout). The producer verifies ABI, Xray/Go provenance, and
# 16 KiB ELF LOAD-segment alignment before any result is installed.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ENGINE="${HERE}/build_xray_engine.sh"
[[ -x "${BUILD_ENGINE}" || -f "${BUILD_ENGINE}" ]] || {
  echo "Missing ${BUILD_ENGINE}." >&2
  exit 1
}

ANDROID_APP_DIR="${1:-android/app}"
JNI_DIR="${ANDROID_APP_DIR}/src/main/jniLibs"
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-xray-android-stage.XXXXXX")"
cleanup() {
  rm -rf -- "${STAGE_DIR}"
  for abi in arm64-v8a armeabi-v7a x86_64; do
    rm -f -- "${JNI_DIR}/${abi}/libxray.so.pending_xray_build"
  done
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${STAGE_DIR}/arm64-v8a" "${STAGE_DIR}/armeabi-v7a" "${STAGE_DIR}/x86_64"

echo "[+] Rebuilding Xray (arm64-v8a) from the pinned reviewed source with Go 1.27.1"
bash "${BUILD_ENGINE}" android-arm64 "${STAGE_DIR}/arm64-v8a/libxray.so"

echo "[+] Rebuilding Xray (armeabi-v7a) from the pinned reviewed source with Go 1.27.1"
bash "${BUILD_ENGINE}" android-arm "${STAGE_DIR}/armeabi-v7a/libxray.so"

echo "[+] Rebuilding Xray (x86_64) from the pinned reviewed source with Go 1.27.1"
bash "${BUILD_ENGINE}" android-amd64 "${STAGE_DIR}/x86_64/libxray.so"

for abi in arm64-v8a armeabi-v7a x86_64; do
  dest_dir="${JNI_DIR}/${abi}"
  pending="${dest_dir}/libxray.so.pending_xray_build"
  mkdir -p "${dest_dir}"
  cp "${STAGE_DIR}/${abi}/libxray.so" "${pending}"
  # Keep the tracked source asset mode stable. AGP installs packaged native
  # libraries with executable permissions in nativeLibraryDir.
  chmod 644 "${pending}"
done
for abi in arm64-v8a armeabi-v7a x86_64; do
  mv "${JNI_DIR}/${abi}/libxray.so.pending_xray_build" "${JNI_DIR}/${abi}/libxray.so"
done

cat <<MSG

Xray Android assets installed:
  ${JNI_DIR}/arm64-v8a/libxray.so
  ${JNI_DIR}/armeabi-v7a/libxray.so
  ${JNI_DIR}/x86_64/libxray.so

Now rebuild the APK. ARM64 phones use arm64-v8a, 32-bit ARM devices use
armeabi-v7a, and the x86_64 copy is for emulators.
Update tools/verify_embedded_engine_runtime_versions.py's expectations if this
ever legitimately needs to change again.
MSG
