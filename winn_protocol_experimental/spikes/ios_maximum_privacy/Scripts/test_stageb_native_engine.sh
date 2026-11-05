#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
spike_root="$(CDPATH='' cd -- "${script_dir}/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/winn-stageb-native-engine.XXXXXX")"

cleanup() {
  rm -R "${scratch}"
}
trap cleanup EXIT HUP INT TERM

compile_and_run() {
  lane="$1"
  shift
  binary="${scratch}/test-${lane}"
  xcrun clang \
    -std=c11 \
    -Wall \
    -Wextra \
    -Wpedantic \
    -Wconversion \
    -Wsign-conversion \
    -Werror \
    "$@" \
    -I "${spike_root}/NativeEngine" \
    "${spike_root}/NativeEngine/WinnAWGUAPISanitizer.c" \
    "${spike_root}/NativeEngine/WinnStageBNativeEngine.c" \
    "${script_dir}/test_stageb_native_engine.c" \
    -o "${binary}"
  "${binary}"
}

compile_and_run normal
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  compile_and_run sanitized \
    -fno-omit-frame-pointer \
    -fsanitize=address,undefined

for source in \
  "${spike_root}/NativeEngine/WinnAWGUAPISanitizer.c" \
  "${spike_root}/NativeEngine/WinnStageBNativeEngine.c"
do
  xcrun clang --analyze \
    -std=c11 \
    -Wall \
    -Wextra \
    -Wpedantic \
    -Wconversion \
    -Wsign-conversion \
    -Werror \
    -Xanalyzer -analyzer-output=text \
    -I "${spike_root}/NativeEngine" \
    "${source}"
done

echo "WINN_STAGE_B_NATIVE_ENGINE_STATIC_ANALYSIS_PASS"
