#!/bin/bash
# Deterministically build the fixed ReleasePython owner installer bootstrap.

set -euo pipefail
ulimit -n 1024 2>/dev/null || true

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd -P)" || {
  printf 'ReleasePython owner-bootstrap build: cannot resolve source directory\n' >&2
  exit 1
}
readonly SCRIPT_DIR
readonly BUILD_SCRIPT="$SCRIPT_DIR/build_macos_release_python_owner_bootstrap.sh"
readonly SOURCE="$SCRIPT_DIR/macos_release_python_owner_bootstrap.c"
readonly SUPPORT="$SCRIPT_DIR/macos_release_python_owner_bootstrap_build_support.py"
readonly DEVELOPER=/Applications/Xcode.app/Contents/Developer
readonly EXPECTED_CLANG=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang
readonly EXPECTED_LINKER=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld
readonly CODESIGN=/usr/bin/codesign
readonly SHASUM=/usr/bin/shasum
readonly STAT=/usr/bin/stat
readonly XCRUN=/usr/bin/xcrun
readonly -a BUILD_HELPERS=(
  /bin/bash /bin/cat /bin/chmod /bin/cp /bin/kill /bin/mv /bin/realpath
  /bin/rm /bin/sleep /usr/bin/awk /usr/bin/basename /usr/bin/cmp
  /usr/bin/codesign /usr/bin/dirname /usr/bin/env /usr/bin/mktemp
  /usr/bin/python3 /usr/bin/shasum /usr/bin/sort /usr/bin/stat /usr/bin/xcrun
)

fail() {
  printf 'ReleasePython owner-bootstrap build: %s\n' "$*" >&2
  exit 1
}

sha256() {
  "$SHASUM" -a 256 "$1" | while IFS=' ' read -r digest _rest; do
    printf '%s\n' "$digest"
  done
}

identity() {
  "$STAT" -f '%i:%u:%g:%l:%z:%Fm:%Fc:%Sf' "$1"
}

main() {
  [[ $# -eq 2 ]] || fail "usage: $0 ABSOLUTE_OUTPUT ABSOLUTE_INPUT_CLOSURE_MANIFEST"
  local output="$1" manifest_output="$2" output_parent output_leaf manifest_parent manifest_leaf
  local clang linker sdk source_hash build_hash support_hash compiler_hash linker_hash codesign_hash
  local input_closure_hash bootstrap_hash manifest_hash scratch source_snapshot temporary
  local first second probe sdk_manifest dependency_trace linker_trace diagnostics
  local closure_manifest holder_inputs holder_manifest holder_complete holder_ready holder_release
  local holder_pid helper helper_mode helper_links input
  local source_before source_fd_before build_before build_fd_before support_before support_fd_before
  local compiler_before compiler_fd_before linker_before linker_fd_before codesign_before codesign_fd_before

  [[ "$output" == /* && "$output" != / && "$manifest_output" == /* && "$manifest_output" != / ]] ||
    fail 'output and manifest must be absolute file paths'
  [[ "$output" != "$manifest_output" ]] || fail 'output and manifest paths must differ'
  output_parent="$(/usr/bin/dirname "$output")"
  output_leaf="$(/usr/bin/basename "$output")"
  manifest_parent="$(/usr/bin/dirname "$manifest_output")"
  manifest_leaf="$(/usr/bin/basename "$manifest_output")"
  [[ "$output_parent" == "$manifest_parent" ]] ||
    fail 'output and manifest must share one retained parent directory'
  [[ -d "$output_parent" && ! -L "$output_parent" ]] ||
    fail 'output parent must be an existing real directory'
  for input in "$output_leaf" "$manifest_leaf"; do
    [[ "$input" != . && "$input" != .. && "$input" != */* ]] || fail 'output leaf is unsafe'
    [[ ! "$input" =~ ^[.]winsvpn-owner-bootstrap-build-[0-9a-f]{48}$ ]] ||
      fail 'output leaf uses the reserved build transaction namespace'
  done
  for input in "$output" "$manifest_output"; do
    [[ ! -L "$input" && ( ! -e "$input" || -f "$input" ) ]] ||
      fail 'output or manifest destination has an unsafe existing type'
  done
  [[ -f "$SOURCE" && ! -L "$SOURCE" && -f "$BUILD_SCRIPT" && ! -L "$BUILD_SCRIPT" &&
     -f "$SUPPORT" && ! -L "$SUPPORT" ]] ||
    fail 'reviewed bootstrap source, producer, or support is absent or symbolic'

  clang="$(DEVELOPER_DIR="$DEVELOPER" "$XCRUN" --find clang)" || fail 'reviewed Apple clang is unavailable'
  linker="$(DEVELOPER_DIR="$DEVELOPER" "$XCRUN" --find ld)" || fail 'reviewed Apple linker is unavailable'
  sdk="$(DEVELOPER_DIR="$DEVELOPER" "$XCRUN" --sdk macosx --show-sdk-path)" ||
    fail 'reviewed macOS SDK is unavailable'
  [[ "$clang" == "$EXPECTED_CLANG" && -f "$clang" && ! -L "$clang" ]] ||
    fail 'clang path is not the reviewed Xcode toolchain'
  [[ "$linker" == "$EXPECTED_LINKER" && -f "$linker" && ! -L "$linker" ]] ||
    fail 'linker path is not the reviewed Xcode toolchain'
  [[ "$($STAT -f '%u:%Lp:%l:%HT' "$clang")" == '0:755:1:Regular File' ]] ||
    fail 'reviewed clang custody is invalid'
  [[ "$($STAT -f '%u:%Lp:%l:%HT' "$linker")" == '0:755:1:Regular File' ]] ||
    fail 'reviewed linker custody is invalid'
  [[ "$($STAT -f '%u:%Lp:%l:%HT' "$CODESIGN")" == '0:755:1:Regular File' ]] ||
    fail 'reviewed codesign custody is invalid'
  for helper in "${BUILD_HELPERS[@]}"; do
    [[ -f "$helper" && ! -L "$helper" && "$($STAT -f '%u:%HT' "$helper")" == '0:Regular File' ]] ||
      fail "fixed build helper custody is invalid: $helper"
    helper_mode="$($STAT -f '%Lp' "$helper")"
    helper_links="$($STAT -f '%l' "$helper")"
    [[ "$helper_mode" == 555 || "$helper_mode" == 755 ]] ||
      fail "fixed build helper mode is invalid: $helper"
    [[ "$helper_links" =~ ^[1-9][0-9]*$ ]] ||
      fail "fixed build helper link count is invalid: $helper"
  done

  exec 4<"$SUPPORT"
  exec 5<"$BUILD_SCRIPT"
  exec 6<"$CODESIGN"
  exec 7<"$linker"
  exec 8<"$clang"
  exec 9<"$SOURCE"
  source_before="$(identity "$SOURCE")"
  source_fd_before="$(identity /dev/fd/9)"
  build_before="$(identity "$BUILD_SCRIPT")"
  build_fd_before="$(identity /dev/fd/5)"
  support_before="$(identity "$SUPPORT")"
  support_fd_before="$(identity /dev/fd/4)"
  compiler_before="$(identity "$clang")"
  compiler_fd_before="$(identity /dev/fd/8)"
  linker_before="$(identity "$linker")"
  linker_fd_before="$(identity /dev/fd/7)"
  codesign_before="$(identity "$CODESIGN")"
  codesign_fd_before="$(identity /dev/fd/6)"
  [[ "$source_before" == "$source_fd_before" && "$build_before" == "$build_fd_before" &&
     "$support_before" == "$support_fd_before" && "$compiler_before" == "$compiler_fd_before" &&
     "$linker_before" == "$linker_fd_before" && "$codesign_before" == "$codesign_fd_before" ]] ||
    fail 'source, producer, support, or tool changed before descriptor custody'

  scratch="$(/usr/bin/mktemp -d /private/tmp/winsvpn-releasepython-owner-bootstrap-build.XXXXXX)" ||
    fail 'cannot create exclusive deterministic build scratch'
  [[ -d "$scratch" && ! -L "$scratch" ]] || fail 'build scratch custody is invalid'
  /bin/chmod 0700 "$scratch"
  source_snapshot="$scratch/owner-bootstrap.c"
  temporary="$scratch/owner-installer-bootstrap"
  first="$scratch/owner-installer-bootstrap.one"
  second="$scratch/owner-installer-bootstrap.two"
  probe="$scratch/owner-installer-bootstrap.probe"
  sdk_manifest="$scratch/sdk-inputs"
  closure_manifest="$scratch/bootstrap-input-closure.manifest"
  holder_manifest="$scratch/retained-build-inputs"
  holder_inputs="$scratch/retained-build-input-leaves"
  holder_complete="$scratch/retained-build-inputs.complete"
  holder_ready="$scratch/input-holder.ready"
  holder_release="$scratch/input-holder.release"
  trap 'if [[ -n "${holder_pid:-}" ]]; then /bin/kill "$holder_pid" 2>/dev/null || true; fi; /bin/rm -rf -- "$scratch"' EXIT HUP INT TERM
  (umask 077; /bin/cp /dev/fd/9 "$source_snapshot")
  /bin/chmod 0400 "$source_snapshot"

  source_hash="$(sha256 "$source_snapshot")"
  build_hash="$(sha256 /dev/fd/5)"
  support_hash="$(sha256 /dev/fd/4)"
  compiler_hash="$(sha256 /dev/fd/8)"
  linker_hash="$(sha256 /dev/fd/7)"
  codesign_hash="$(sha256 /dev/fd/6)"

  validate_inputs() {
    [[ "$(identity "$SOURCE")" == "$source_before" && "$(identity /dev/fd/9)" == "$source_fd_before" &&
       "$(sha256 "$SOURCE")" == "$source_hash" ]] || fail 'reviewed source changed during build'
    [[ "$(identity "$BUILD_SCRIPT")" == "$build_before" && "$(identity /dev/fd/5)" == "$build_fd_before" &&
       "$(sha256 "$BUILD_SCRIPT")" == "$build_hash" ]] || fail 'reviewed producer changed during build'
    [[ "$(identity "$SUPPORT")" == "$support_before" && "$(identity /dev/fd/4)" == "$support_fd_before" &&
       "$(sha256 "$SUPPORT")" == "$support_hash" ]] || fail 'reviewed support changed during build'
    [[ "$(identity "$clang")" == "$compiler_before" && "$(identity /dev/fd/8)" == "$compiler_fd_before" &&
       "$(sha256 "$clang")" == "$compiler_hash" ]] || fail 'executed compiler changed during build'
    [[ "$(identity "$linker")" == "$linker_before" && "$(identity /dev/fd/7)" == "$linker_fd_before" &&
       "$(sha256 "$linker")" == "$linker_hash" ]] || fail 'executed linker changed during build'
    [[ "$(identity "$CODESIGN")" == "$codesign_before" && "$(identity /dev/fd/6)" == "$codesign_fd_before" &&
       "$(sha256 "$CODESIGN")" == "$codesign_hash" ]] || fail 'executed codesign changed during build'
    [[ "$(sha256 "$source_snapshot")" == "$source_hash" ]] || fail 'source snapshot changed during build'
  }

  build_once() {
    local destination="$1" tag="$2" closure_hash="$3"
    dependency_trace="$scratch/dependencies.$tag"
    linker_trace="$scratch/linker.$tag"
    diagnostics="$scratch/diagnostics.$tag"
    if ! /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp DEVELOPER_DIR="$DEVELOPER" \
      SOURCE_DATE_EPOCH=0 ZERO_AR_DATE=1 "$clang" \
        -std=c17 -Os -Wall -Wextra -Wpedantic -Werror -isysroot "$sdk" \
        -mmacosx-version-min=13.0 -fno-ident -fvisibility=hidden "--ld-path=$linker" \
        -MD -MF "$dependency_trace" -Wl,-t -Wl,-dead_strip -Wl,-no_adhoc_codesign \
        -Wl,-fatal_warnings -lproc \
        "-DWINS_BUILD_SOURCE_SHA256=\"$source_hash\"" \
        "-DWINS_BUILD_SCRIPT_SHA256=\"$build_hash\"" \
        "-DWINS_BUILD_COMPILER_SHA256=\"$compiler_hash\"" \
        "-DWINS_BUILD_LINKER_SHA256=\"$linker_hash\"" \
        "-DWINS_BUILD_CODESIGN_SHA256=\"$codesign_hash\"" \
        "-DWINS_BUILD_INPUT_CLOSURE_SHA256=\"$closure_hash\"" \
        "$source_snapshot" -o "$temporary" >"$linker_trace" 2>"$diagnostics"; then
      /bin/cat "$diagnostics" >&2
      fail 'warning-clean compiler/linker invocation failed'
    fi
    [[ ! -s "$diagnostics" ]] || fail 'compiler or linker emitted diagnostics'
    {
      /usr/bin/awk '{ sub(/\\$/, ""); for (i = 1; i <= NF; ++i) print $i }' "$dependency_trace"
      /bin/cat "$linker_trace"
    } | while IFS= read -r input; do
      input="${input%:}"
      input="${input%%(*}"
      case "$input" in
        "$sdk"/*|"$DEVELOPER"/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/*)
          [[ -f "$input" || -L "$input" ]] || fail "SDK input is not a file: $input"
          printf '%s\n' "$input"
          if [[ -L "$input" ]]; then /bin/realpath "$input"; fi
          ;;
      esac
    done | /usr/bin/sort -u >"$scratch/sdk-inputs.$tag"
    [[ -s "$scratch/sdk-inputs.$tag" ]] || fail 'compiler/linker SDK closure is empty'
    "$CODESIGN" --force --sign - --timestamp=none \
      --identifier org.winsvpn.releasepython.owner-installer-bootstrap "$temporary"
    /bin/chmod 0555 "$temporary"
    /bin/cp -p "$temporary" "$destination"
    /bin/rm -f -- "$temporary"
    validate_inputs
  }

  build_once "$probe" probe "$(printf '0%.0s' {1..64})"
  /bin/mv "$scratch/sdk-inputs.probe" "$sdk_manifest"
  /bin/rm -f -- "$probe"
  {
    /bin/cat "$sdk_manifest"
    printf '%s\n' "$SOURCE" "$BUILD_SCRIPT" "$SUPPORT" "$clang" "$linker" "${BUILD_HELPERS[@]}"
  } | /usr/bin/sort -u >"$holder_inputs"
  while IFS= read -r input; do
    [[ "$input" == /* && ! "$input" =~ [[:space:]] ]] || fail "retained build input path is unsafe: $input"
  done <"$holder_inputs"
  { /bin/cat "$holder_inputs"; printf '%s\n' "$output_parent"; } | /usr/bin/sort -u >"$holder_manifest"
  while IFS= read -r input; do
    printf '%s\n' "$input"
    while [[ "$input" != / ]]; do
      input="$(/usr/bin/dirname "$input")"
      printf '%s\n' "$input"
    done
  done <"$holder_manifest" | /usr/bin/sort -u >"$holder_complete"
  /bin/mv "$holder_complete" "$holder_manifest"

  /usr/bin/env -i HOME=/private/var/empty PATH=/usr/bin:/bin TMPDIR=/private/tmp \
    /usr/bin/python3 -I -S -c 'import os; os.lseek(4, 0, 0); source = b"".join(iter(lambda: os.read(4, 1048576), b"")); exec(compile(source, "<retained-owner-bootstrap-build-support>", "exec"), {"__name__": "__main__"})' \
      hold "$holder_manifest" "$holder_inputs" \
      "$closure_manifest" "$holder_ready" "$holder_release" &
  holder_pid=$!
  while [[ ! -f "$holder_ready" ]] && /bin/kill -0 "$holder_pid" 2>/dev/null; do /bin/sleep 0.01; done
  [[ -f "$holder_ready" ]] || { wait "$holder_pid"; fail 'input descriptor holder failed before build'; }
  /usr/bin/awk 'NR > 4 { if (NF != 4 || ($4 in seen)) exit 1; seen[$4] = 1; if (previous != "" && $4 < previous) exit 1; previous = $4 }' \
    "$closure_manifest" || fail 'closure manifest records are invalid, duplicate, or unsorted'
  input_closure_hash="$(sha256 "$closure_manifest")"

  build_once "$first" one "$input_closure_hash"
  build_once "$second" two "$input_closure_hash"
  /usr/bin/cmp -s "$sdk_manifest" "$scratch/sdk-inputs.one" || fail 'SDK closure changed in first build'
  /usr/bin/cmp -s "$sdk_manifest" "$scratch/sdk-inputs.two" || fail 'SDK closure changed in second build'
  /usr/bin/cmp -s "$first" "$second" || fail 'two final builds were not byte-identical'
  bootstrap_hash="$(sha256 "$first")"
  manifest_hash="$(sha256 "$closure_manifest")"
  [[ "$manifest_hash" == "$input_closure_hash" ]] || fail 'retained closure changed after compilation'
  /bin/kill -0 "$holder_pid" 2>/dev/null || { wait "$holder_pid"; fail 'input holder exited before publication'; }

  /usr/bin/env -i HOME=/private/var/empty PATH=/usr/bin:/bin TMPDIR=/private/tmp \
    /usr/bin/python3 -I -S -c 'import os; os.lseek(4, 0, 0); source = b"".join(iter(lambda: os.read(4, 1048576), b"")); exec(compile(source, "<retained-owner-bootstrap-build-support>", "exec"), {"__name__": "__main__"})' \
      publish "$output_parent" "$first" \
      "$closure_manifest" "$output_leaf" "$manifest_leaf" "$bootstrap_hash" "$manifest_hash"
  [[ "$(sha256 "$output")" == "$bootstrap_hash" && "$(sha256 "$manifest_output")" == "$manifest_hash" ]] ||
    fail 'published build output digest drifted'
  (umask 077; printf 'release\n' >"$holder_release")
  wait "$holder_pid" || fail 'retained build input changed during deterministic build or publication'
  holder_pid=
  validate_inputs
  [[ "$(sha256 "$closure_manifest")" == "$input_closure_hash" ]] || fail 'closure changed after retained publication'
  /bin/rm -rf -- "$scratch"
  trap - EXIT HUP INT TERM
  exec 4<&-
  exec 5<&-
  exec 6<&-
  exec 7<&-
  exec 8<&-
  exec 9<&-
  printf 'source_sha256=%s\n' "$source_hash"
  printf 'build_script_sha256=%s\n' "$build_hash"
  printf 'build_support_sha256=%s\n' "$support_hash"
  printf 'compiler_sha256=%s\n' "$compiler_hash"
  printf 'linker_sha256=%s\n' "$linker_hash"
  printf 'codesign_sha256=%s\n' "$codesign_hash"
  printf 'input_closure_sha256=%s\n' "$input_closure_hash"
  printf 'bootstrap_sha256=%s\n' "$bootstrap_hash"
  printf 'manifest_sha256=%s\n' "$manifest_hash"
  printf 'manifest_path=%s\n' "$manifest_output"
}

main "$@"
