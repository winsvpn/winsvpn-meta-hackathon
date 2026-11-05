#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
spike_root="$(CDPATH='' cd -- "${script_dir}/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/winn-stageb-darwin-utun.XXXXXX")"

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
    -pthread \
    "$@" \
    -I "${spike_root}/NativeEngine" \
    "${spike_root}/NativeEngine/WinnStageBDarwinUtun.c" \
    "${script_dir}/test_stageb_darwin_utun.c" \
    -o "${binary}"
  "${binary}"
}

compile_and_run normal
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  compile_and_run sanitized \
    -fno-omit-frame-pointer \
    -fsanitize=address,undefined

UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  compile_and_run integer \
    -fno-omit-frame-pointer \
    -fsanitize=undefined,integer

TSAN_OPTIONS=halt_on_error=1 \
  compile_and_run threaded \
    -fno-omit-frame-pointer \
    -fsanitize=thread

coverage_binary="${scratch}/test-coverage"
coverage_raw="${scratch}/coverage.profraw"
coverage_data="${scratch}/coverage.profdata"
xcrun clang \
  -std=c11 \
  -Wall \
  -Wextra \
  -Wpedantic \
  -Wconversion \
  -Wsign-conversion \
  -Werror \
  -pthread \
  -fprofile-instr-generate \
  -fcoverage-mapping \
  -I "${spike_root}/NativeEngine" \
  "${spike_root}/NativeEngine/WinnStageBDarwinUtun.c" \
  "${script_dir}/test_stageb_darwin_utun.c" \
  -o "${coverage_binary}"
LLVM_PROFILE_FILE="${coverage_raw}" "${coverage_binary}"
xcrun llvm-profdata merge \
  -sparse \
  "${coverage_raw}" \
  -o "${coverage_data}"
xcrun llvm-cov report \
  "${coverage_binary}" \
  -instr-profile="${coverage_data}" \
  "${spike_root}/NativeEngine/WinnStageBDarwinUtun.c"

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
  "${spike_root}/NativeEngine/WinnStageBDarwinUtun.c"

xcrun --sdk iphoneos clang \
  -arch arm64 \
  -fapplication-extension \
  -std=c11 \
  -Wall \
  -Wextra \
  -Wpedantic \
  -Wconversion \
  -Wsign-conversion \
  -Werror \
  -fsyntax-only \
  -I "${spike_root}/NativeEngine" \
  "${spike_root}/NativeEngine/WinnStageBDarwinUtun.c"

xcrun --sdk iphonesimulator clang \
  -arch arm64 \
  -fapplication-extension \
  -std=c11 \
  -Wall \
  -Wextra \
  -Wpedantic \
  -Wconversion \
  -Wsign-conversion \
  -Werror \
  -fsyntax-only \
  -I "${spike_root}/NativeEngine" \
  "${spike_root}/NativeEngine/WinnStageBDarwinUtun.c"

echo "WINN_STAGE_B_DARWIN_UTUN_STATIC_ANALYSIS_PASS"
echo "WINN_STAGE_B_DARWIN_UTUN_APP_EXTENSION_SYNTAX_PASS"
