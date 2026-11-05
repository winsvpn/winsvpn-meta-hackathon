#!/usr/bin/env bash
# Build libwinn_tun_bulk.so (the bulk tun reader JNI library) for every staged
# Android ABI and place it in EVERY shipping source set's jniLibs (main, debug,
# profile, release), matching how libwinnengine.so and libxray.so are staged
# as prebuilt jniLibs. The release gate in android/app/build.gradle.kts
# (androidReleaseStagedEngines) requires this library beside libwinnengine.so
# for every ABI and reads src/release before src/main, so the copy has to land
# in the source set the release build actually packages.
#
# Uses the NDK pinned by android/app/build.gradle.kts (30.0.16248370).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NDK_VERSION="30.0.16248370"
NDK="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/${NDK_VERSION}}"
SRC="$REPO_ROOT/android/app/src/main/cpp/winn_tun_bulk.cpp"
JNI_ROOT="$REPO_ROOT/android/app/src"
SHIP_VARIANTS=(main debug profile release)
LIB_NAME="libwinn_tun_bulk.so"

if [[ ! -d "$NDK" ]]; then
  echo "NDK not found at $NDK (set ANDROID_NDK_HOME)" >&2
  exit 1
fi
if ! grep -Fqx "Pkg.Revision = ${NDK_VERSION}" "$NDK/source.properties"; then
  echo "Selected NDK does not match ${NDK_VERSION}" >&2
  exit 1
fi
if [[ ! -f "$SRC" ]]; then
  echo "source not found: $SRC" >&2
  exit 1
fi

# The NDK ships one prebuilt LLVM per host. Pick the one that is present
# instead of hardcoding darwin-x86_64, so the macOS, Linux and Windows release
# hosts all produce the library from the same pinned NDK.
HOST_TAG=""
for tag in darwin-x86_64 linux-x86_64 windows-x86_64; do
  if [[ -x "$NDK/toolchains/llvm/prebuilt/$tag/bin/clang" || -f "$NDK/toolchains/llvm/prebuilt/$tag/bin/clang.exe" ]]; then
    HOST_TAG="$tag"
    break
  fi
done
if [[ -z "$HOST_TAG" ]]; then
  echo "no prebuilt LLVM toolchain under $NDK/toolchains/llvm/prebuilt" >&2
  exit 1
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/winn-tun-bulk.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

build_abi() {
  local abi="$1" triple="$2" cxx="$3"
  local out="$STAGE/$abi/$LIB_NAME"
  mkdir -p "$STAGE/$abi"
  "$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin/$cxx" \
    -std=c++17 -O2 -fPIC -shared -fno-exceptions -fno-rtti \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,-z,max-page-size=16384 \
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -s \
    -target "$triple" \
    -o "$out" "$SRC"
  echo "built $out"
}

# API floor: the app's minSdk is 26, and the bulk reader uses only POSIX
# read() and write(), so every supported ABI builds against API 24 as before.
build_abi arm64-v8a  aarch64-linux-android24          clang
build_abi armeabi-v7a armv7a-linux-androideabi24      clang
build_abi x86_64     x86_64-linux-android24           clang

# Every ABI built before any shipping input is touched. Install the same bytes
# into every shipping source set so the release gate's src/release-first read
# and the debug/profile builds all see this run's library.
for variant in "${SHIP_VARIANTS[@]}"; do
  for abi in arm64-v8a armeabi-v7a x86_64; do
    dest_dir="$JNI_ROOT/$variant/jniLibs/$abi"
    mkdir -p "$dest_dir"
    install -m 0755 "$STAGE/$abi/$LIB_NAME" "$dest_dir/$LIB_NAME"
    echo "installed $dest_dir/$LIB_NAME"
  done
done

echo "done"
