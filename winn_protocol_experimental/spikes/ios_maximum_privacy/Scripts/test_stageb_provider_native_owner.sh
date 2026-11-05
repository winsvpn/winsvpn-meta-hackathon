#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
readonly SPIKE_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly SCRATCH_RAW="$(mktemp -d "${TMPDIR:-/tmp}/winn-stageb-owner.XXXXXX")"
readonly SCRATCH="$(cd -- "$SCRATCH_RAW" && pwd -P)"

cleanup() {
  case "$SCRATCH" in
    /private/var/folders/*/winn-stageb-owner.*|/var/folders/*/winn-stageb-owner.*|/private/tmp/winn-stageb-owner.*|/tmp/winn-stageb-owner.*)
      [[ ! -L "$SCRATCH" ]] && rm -rf -- "$SCRATCH"
      ;;
    *)
      printf 'refusing unsafe scratch cleanup\n' >&2
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

readonly COMMON_FLAGS=(
  -DWINN_STAGE_B_PROVIDER_NATIVE_OWNER_TESTING=1
  -std=c11
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
  -Werror
  -I "$SPIKE_ROOT/NativeEngine"
)
readonly SOURCES=(
  "$SPIKE_ROOT/NativeEngine/WinnAWGUAPISanitizer.c"
  "$SPIKE_ROOT/NativeEngine/WinnStageBNativeEngine.c"
  "$SPIKE_ROOT/NativeEngine/WinnStageBDarwinUtun.c"
  "$SPIKE_ROOT/NativeEngine/WinnStageBFrameworkLoader.c"
  "$SPIKE_ROOT/NativeEngine/WinnStageBFrameworkDarwin.c"
  "$SPIKE_ROOT/NativeEngine/WinnStageBProviderNativeOwner.c"
  "$SCRIPT_DIR/test_stageb_provider_native_owner.c"
)

compile_and_run() {
  local lane="$1"
  shift
  local binary="$SCRATCH/test-$lane"
  xcrun clang "${COMMON_FLAGS[@]}" "$@" "${SOURCES[@]}" \
    -framework Security -o "$binary"
  "$binary"
}

compile_and_run normal
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  compile_and_run sanitized \
    -fno-omit-frame-pointer -fsanitize=address,undefined
TSAN_OPTIONS=halt_on_error=1 \
  compile_and_run thread \
    -fno-omit-frame-pointer -fsanitize=thread

xcrun clang --analyze "${COMMON_FLAGS[@]}" \
  -Xanalyzer -analyzer-output=text \
  "$SPIKE_ROOT/NativeEngine/WinnStageBProviderNativeOwner.c"

readonly IOS_SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
readonly IOS_TARGET="$(xcrun --sdk iphoneos --find clang)"
"$IOS_TARGET" \
  -isysroot "$IOS_SDK" \
  -target arm64-apple-ios15.0 \
  "${COMMON_FLAGS[@]}" \
  -fsyntax-only \
  "$SPIKE_ROOT/NativeEngine/WinnStageBProviderNativeOwner.c"

echo "WINN_STAGE_B_PROVIDER_NATIVE_OWNER_ALL_GATES_PASS"
