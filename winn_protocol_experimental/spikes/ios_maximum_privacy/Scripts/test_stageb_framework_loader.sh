#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
readonly SPIKE_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
readonly REPOSITORY_ROOT="$(cd -- "$SPIKE_ROOT/../../.." && pwd -P)"
readonly LOADER="$SPIKE_ROOT/NativeEngine/WinnStageBFrameworkLoader.c"
readonly DARWIN="$SPIKE_ROOT/NativeEngine/WinnStageBFrameworkDarwin.c"
readonly PUBLIC_HEADER="$SPIKE_ROOT/NativeEngine/WinnStageBFrameworkLoader.h"
readonly TEST_SOURCE="$SCRIPT_DIR/test_stageb_framework_loader.c"
readonly DEVICE_SOURCE="$REPOSITORY_ROOT/apple/EngineArtifacts/ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib"
readonly SIMULATOR_SOURCE="$REPOSITORY_ROOT/apple/EngineArtifacts/ios/iphonesimulator/libWinsAmneziaWGPacketEngine.dylib"
readonly DEVICE_SHA256="e0e810039d0ed43b1a599bb64320b0ee4ab4903cbdfd33e048bf0fb5e7f116cd"
readonly SIMULATOR_SHA256="00a17dfd702dc0490efd4f39bc2259fcc38fa4eed8311885499b5f1611713fa3"
readonly SCRATCH_RAW="$(mktemp -d "${TMPDIR:-/tmp}/winn-stageb-loader.XXXXXX")"
readonly SCRATCH="$(cd -- "$SCRATCH_RAW" && pwd -P)"

cleanup() {
  case "$SCRATCH" in
    /private/var/folders/*/winn-stageb-loader.*|/var/folders/*/winn-stageb-loader.*|/private/tmp/winn-stageb-loader.*|/tmp/winn-stageb-loader.*)
      [[ ! -L "$SCRATCH" ]] && rm -rf -- "$SCRATCH"
      ;;
    *)
      printf 'refusing unsafe scratch cleanup\n' >&2
      ;;
  esac
}
trap cleanup EXIT HUP INT TERM

[[ -f "$DEVICE_SOURCE" ]]
[[ -f "$SIMULATOR_SOURCE" ]]
[[ "$(shasum -a 256 -- "$DEVICE_SOURCE" | awk '{print $1}')" == "$DEVICE_SHA256" ]]
[[ "$(shasum -a 256 -- "$SIMULATOR_SOURCE" | awk '{print $1}')" == "$SIMULATOR_SHA256" ]]

if grep -n 'dlclose' "$LOADER" "$DARWIN" "$PUBLIC_HEADER"; then
  printf 'loader must never unload the Go-bearing image\n' >&2
  exit 1
fi
if grep -En 'FrameworkPins|RuntimeBoundary|DLOpenFn|DLSymFn|make_pins|pins[),]' \
    "$PUBLIC_HEADER"; then
  printf 'public header exposes a caller-controlled loader seam or pin\n' >&2
  exit 1
fi
if grep -En '@executable_path|@loader_path|@rpath' "$LOADER"; then
  printf 'portable loader core contains a dyld-relative load path\n' >&2
  exit 1
fi

readonly COMMON_FLAGS=(
  -DWINN_STAGE_B_FRAMEWORK_TESTING=1
  -std=c11
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
  -Werror
  -I "$SPIKE_ROOT/NativeEngine"
)
readonly CORE_CASES=(
  paths expected-device success concurrency late-cleanup commit-abandon commit-begin
  late-supersede-reuse permanent-failure concurrent-permanent-failure boundary-change
  preflight path source runtime-zero runtime-equals-source identity manifest nofollow
  loader-gate preflight-reserved
  platform architecture macho dlopen symbol postflight symbol-image
  post-path post-retained post-macho post-reserved rebind-hash rebind-inode contract
)

compile_test() {
  local output="$1"
  shift
  xcrun clang "${COMMON_FLAGS[@]}" "$@" \
    "$LOADER" "$DARWIN" "$TEST_SOURCE" -o "$output"
}

run_core_cases() {
  local binary="$1"
  local case_name
  for case_name in "${CORE_CASES[@]}"; do
    "$binary" "$case_name"
  done
}

readonly NORMAL="$SCRATCH/loader-test"
compile_test "$NORMAL"
run_core_cases "$NORMAL"

readonly FAKE_TARGET_HEADER="$SCRATCH/TargetConditionals.h"
printf '%s\n' \
  '#ifndef TARGET_CONDITIONALS_H' \
  '#define TARGET_CONDITIONALS_H' \
  '#undef TARGET_OS_SIMULATOR' \
  '#define TARGET_OS_SIMULATOR 1' \
  '#endif' >"$FAKE_TARGET_HEADER"
readonly SIMULATOR_PIN_TEST="$SCRATCH/loader-test-simulator-pin"
compile_test "$SIMULATOR_PIN_TEST" -I "$SCRATCH"
"$SIMULATOR_PIN_TEST" expected-simulator

readonly SANITIZED="$SCRATCH/loader-test-sanitized"
compile_test "$SANITIZED" \
  -fno-omit-frame-pointer -fsanitize=address,undefined
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  run_core_cases "$SANITIZED"

readonly THREAD_SANITIZED="$SCRATCH/loader-test-thread-sanitized"
compile_test "$THREAD_SANITIZED" \
  -fno-omit-frame-pointer -fsanitize=thread
TSAN_OPTIONS=halt_on_error=1 "$THREAD_SANITIZED" concurrency
TSAN_OPTIONS=halt_on_error=1 "$THREAD_SANITIZED" late-cleanup
TSAN_OPTIONS=halt_on_error=1 "$THREAD_SANITIZED" commit-abandon
TSAN_OPTIONS=halt_on_error=1 "$THREAD_SANITIZED" commit-begin
TSAN_OPTIONS=halt_on_error=1 "$THREAD_SANITIZED" late-supersede-reuse
TSAN_OPTIONS=halt_on_error=1 "$THREAD_SANITIZED" concurrent-permanent-failure

readonly APP_ROOT="$SCRATCH/WCF3.app"
readonly FRAMEWORK="$APP_ROOT/Frameworks/WinsAmneziaWGPacketEngine.framework"
readonly ENGINE="$FRAMEWORK/WinsAmneziaWGPacketEngine"
readonly PROVIDER="$APP_ROOT/PlugIns/PacketTunnel.appex/PacketTunnel"
readonly MANIFEST="$APP_ROOT/WinnStageBEngineRuntimePin.manifest"
mkdir -p -- "$FRAMEWORK" "$(dirname -- "$PROVIDER")"
cp -- "$DEVICE_SOURCE" "$ENGINE"
touch "$PROVIDER"
codesign --force --sign - --timestamp=none "$ENGINE"
readonly RUNTIME_SHA256="$(shasum -a 256 -- "$ENGINE" | awk '{print $1}')"
[[ "$RUNTIME_SHA256" != "$DEVICE_SHA256" ]]

write_manifest() {
  local source_sha="$1"
  local runtime_sha="$2"
  local platform="$3"
  local architectures="$4"
  printf '%s\n' \
    'schema=winn-stageb-engine-runtime-pin/1' \
    "source_binary_sha256=$source_sha" \
    "signed_runtime_binary_sha256=$runtime_sha" \
    'relative_path=Frameworks/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine' \
    "platform=$platform" \
    "architectures=$architectures" \
    'install_name=@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine' \
    >"$MANIFEST"
}

write_manifest "$DEVICE_SHA256" "$RUNTIME_SHA256" iphoneos arm64
"$NORMAL" darwin-macho "$ENGINE" iphoneos arm64 ok
"$NORMAL" darwin-preflight "$PROVIDER" ok

ln "$ENGINE" "$SCRATCH/hard-link"
"$NORMAL" darwin-preflight "$PROVIDER" reject
rm -- "$SCRATCH/hard-link"
"$NORMAL" darwin-preflight "$PROVIDER" ok

mv -- "$ENGINE" "$ENGINE.real"
ln -s -- "$(basename -- "$ENGINE.real")" "$ENGINE"
"$NORMAL" darwin-preflight "$PROVIDER" reject
rm -- "$ENGINE"
mv -- "$ENGINE.real" "$ENGINE"
"$NORMAL" darwin-preflight "$PROVIDER" ok

write_manifest "$DEVICE_SHA256" \
  '0f5ea8c09ab8ab392963e8bef6b707608fc62312c00a09dd94009a4ce607f842' \
  iphoneos arm64
"$NORMAL" darwin-preflight "$PROVIDER" reject
write_manifest \
  'f0e810039d0ed43b1a599bb64320b0ee4ab4903cbdfd33e048bf0fb5e7f116cd' \
  "$RUNTIME_SHA256" iphoneos arm64
"$NORMAL" darwin-preflight "$PROVIDER" reject
write_manifest "$DEVICE_SHA256" "$RUNTIME_SHA256" iphonesimulator arm64
"$NORMAL" darwin-preflight "$PROVIDER" reject
write_manifest "$DEVICE_SHA256" "$RUNTIME_SHA256" iphoneos 'arm64,x86_64'
"$NORMAL" darwin-preflight "$PROVIDER" reject
write_manifest "$DEVICE_SHA256" "$RUNTIME_SHA256" iphoneos arm64
printf 'unknown=forbidden\n' >>"$MANIFEST"
"$NORMAL" darwin-preflight "$PROVIDER" reject
write_manifest "$DEVICE_SHA256" "$RUNTIME_SHA256" iphoneos arm64
"$NORMAL" darwin-preflight "$PROVIDER" ok

"$NORMAL" darwin-macho "$DEVICE_SOURCE" iphoneos arm64 reject
"$NORMAL" darwin-macho "$ENGINE" iphonesimulator arm64 reject
"$NORMAL" darwin-macho "$ENGINE" iphoneos x86_64 reject

readonly BAD_INSTALL="$SCRATCH/bad-install"
readonly BAD_DEPENDENCY="$SCRATCH/bad-dependency"
readonly BAD_EXPORT="$SCRATCH/bad-export"
readonly BAD_WEAK_DEPENDENCY="$SCRATCH/bad-weak-dependency"
readonly DUPLICATE_ARM64_FAT="$SCRATCH/duplicate-arm64-fat"
cp -- "$ENGINE" "$BAD_INSTALL"
cp -- "$ENGINE" "$BAD_DEPENDENCY"
cp -- "$ENGINE" "$BAD_EXPORT"
perl -0pi -e \
  's/\@rpath\/WinsAmneziaWGPacketEngine\.framework\/WinsAmneziaWGPacketEngine/#rpath\/WinsAmneziaWGPacketEngine.framework\/WinsAmneziaWGPacketEngine/' \
  "$BAD_INSTALL"
perl -0pi -e 's/\/usr\/lib\/libresolv\.9\.dylib/\/usr\/lib\/libxesolv.9.dylib/' \
  "$BAD_DEPENDENCY"
perl -0pi -e 's/_wgTurnOn/_xgTurnOn/' "$BAD_EXPORT"
"$NORMAL" darwin-macho "$BAD_INSTALL" iphoneos arm64 reject
"$NORMAL" darwin-macho "$BAD_DEPENDENCY" iphoneos arm64 reject
"$NORMAL" darwin-macho "$BAD_EXPORT" iphoneos arm64 reject

ruby -e '
  input, output = ARGV
  bytes = File.binread(input)
  raise "expected thin 64-bit Mach-O" unless bytes.byteslice(0, 4).unpack1("L<") == 0xfeedfacf
  command_count = bytes.byteslice(16, 4).unpack1("L<")
  offset = 32
  changed = false
  command_count.times do
    command, size = bytes.byteslice(offset, 8).unpack("L<L<")
    raise "invalid load command" if size < 8 || offset + size > bytes.bytesize
    if command == 0x0c
      bytes[offset, 4] = [0x80000018].pack("L<")
      changed = true
      break
    end
    offset += size
  end
  raise "LC_LOAD_DYLIB not found" unless changed
  File.binwrite(output, bytes)
' "$ENGINE" "$BAD_WEAK_DEPENDENCY"
"$NORMAL" darwin-macho "$BAD_WEAK_DEPENDENCY" iphoneos arm64 reject

cp -- "$SIMULATOR_SOURCE" "$DUPLICATE_ARM64_FAT"
printf '\x01\x00\x00\x0c' |
  dd of="$DUPLICATE_ARM64_FAT" bs=1 seek=8 conv=notrunc status=none
"$NORMAL" darwin-macho \
  "$DUPLICATE_ARM64_FAT" iphonesimulator arm64 reject

readonly SIGNED_SIMULATOR="$SCRATCH/signed-simulator-engine"
cp -- "$SIMULATOR_SOURCE" "$SIGNED_SIMULATOR"
codesign --force --sign - --timestamp=none "$SIGNED_SIMULATOR"
"$NORMAL" darwin-macho "$SIGNED_SIMULATOR" iphonesimulator arm64 ok
"$NORMAL" darwin-macho "$SIGNED_SIMULATOR" iphonesimulator x86_64 ok

xcrun clang --analyze "${COMMON_FLAGS[@]}" \
  -Xanalyzer -analyzer-output=text "$LOADER" "$DARWIN"

for sdk in iphoneos iphonesimulator; do
  xcrun --sdk "$sdk" clang -arch arm64 \
    -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror \
    -fsyntax-only -I "$SPIKE_ROOT/NativeEngine" "$LOADER" "$DARWIN"
done

readonly PRODUCTION_LOADER_OBJECT="$SCRATCH/production-loader.o"
readonly PRODUCTION_DARWIN_OBJECT="$SCRATCH/production-darwin.o"
xcrun --sdk iphoneos clang -arch arm64 -std=c11 -I "$SPIKE_ROOT/NativeEngine" \
  -c "$LOADER" -o "$PRODUCTION_LOADER_OBJECT"
xcrun --sdk iphoneos clang -arch arm64 -std=c11 -I "$SPIKE_ROOT/NativeEngine" \
  -c "$DARWIN" -o "$PRODUCTION_DARWIN_OBJECT"
nm -m "$PRODUCTION_LOADER_OBJECT" |
  grep -F 'private external _winn_stage_b_framework_expected'
nm -m "$PRODUCTION_DARWIN_OBJECT" |
  grep -F 'private external _winn_stage_b_framework_darwin_runtime_boundary'
if nm -gU "$PRODUCTION_LOADER_OBJECT" "$PRODUCTION_DARWIN_OBJECT" |
  grep -E 'winn_stage_b_framework_.*for_testing'; then
  printf 'production objects expose a testing seam\n' >&2
  exit 1
fi

printf '%s\n' \
  WINN_STAGE_B_FRAMEWORK_LOADER_CORE_PASS \
  WINN_STAGE_B_FRAMEWORK_LOADER_FAULT_MATRIX_PASS \
  WINN_STAGE_B_FRAMEWORK_LOADER_DARWIN_BOUNDARY_PASS \
  WINN_STAGE_B_FRAMEWORK_LOADER_SANITIZERS_PASS \
  WINN_STAGE_B_FRAMEWORK_LOADER_THREAD_SANITIZER_PASS \
  WINN_STAGE_B_FRAMEWORK_LOADER_STATIC_ANALYSIS_PASS \
  WINN_STAGE_B_FRAMEWORK_LOADER_IOS_SDK_SYNTAX_PASS
