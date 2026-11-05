#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'test_stageb_engine_artifact: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$TEST_ROOT/$label.stdout" 2>"$TEST_ROOT/$label.stderr"; then
    die "expected failure did not occur: $label"
  fi
}

sha256_file() {
  /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{ print $1 }'
}

plist_value() {
  /usr/libexec/PlistBuddy -c "Print :$2" "$1"
}

assert_required_symbols_by_slice() {
  local binary="$1"
  local architecture
  shift
  for architecture in "$@"; do
    symbols=$(/usr/bin/nm -arch "$architecture" -gUj "$binary")
    for required_symbol in \
      _wgTurnOn \
      _wgTurnOff \
      _wgGetConfig \
      _wgSetConfig \
      _wgBumpSockets \
      _wins_amneziawg_packet_engine_contract_version; do
      printf '%s\n' "$symbols" | /usr/bin/grep -Fqx "$required_symbol" ||
        die "required defined export is absent from $architecture slice"
    done
  done
}

assert_install_name_by_slice() {
  local binary="$1"
  local architecture
  shift
  for architecture in "$@"; do
    install_names=$(
      /usr/bin/otool -arch "$architecture" -D "$binary" |
        /usr/bin/awk '/^@/ { print }'
    )
    [ "$install_names" = "$INSTALL_NAME" ] ||
      die "install name is not exact in $architecture slice"
  done
}

receipt_has_exact_shape() {
  local receipt="$1"
  printf '%s\n' "$receipt" |
    /usr/bin/grep -Eq '^\{"schema":"winn-stageb-engine-artifact-receipt/4","platform":"(iphoneos|iphonesimulator)","supported_platform":"(iPhoneOS|iPhoneSimulator)","minimum_os_version":"[0-9]+\.[0-9]+(\.[0-9]+)?","architectures":\["(arm64|x86_64)"(,"(arm64|x86_64)")?\],"install_name":"@rpath/WinsAmneziaWGPacketEngine\.framework/WinsAmneziaWGPacketEngine","source_binary_sha256":"[0-9a-f]{64}","binary_sha256":"[0-9a-f]{64}","info_plist_sha256":"[0-9a-f]{64}","regular_file_tree_manifest_sha256":"[0-9a-f]{64}","stager_script_sha256":"[0-9a-f]{64}","publisher_source_sha256":"[0-9a-f]{64}","publisher_binary_sha256":"[0-9a-f]{64}","developer_toolchain_selector_sha256":"[0-9a-f]{64}","publication":"atomic-no-replace-non-durable"\}$' ||
    return 1
}

assert_exact_receipt_shape() {
  receipt_has_exact_shape "$1" ||
    die "receipt does not match the exact schema, key, type, and order contract"
}

start_barriered_stage() {
  local label="$1"
  local output_root="$2"
  BARRIER_READY_FIFO="$TEST_ROOT/$label.ready.fifo"
  BARRIER_GO_FIFO="$TEST_ROOT/$label.go.fifo"
  /usr/bin/mkfifo "$BARRIER_READY_FIFO" "$BARRIER_GO_FIFO"
  exec 5<>"$BARRIER_READY_FIFO"
  exec 6<>"$BARRIER_GO_FIFO"
  WINN_STAGEB_TEST_BARRIER=1 "$STAGER" iphoneos "$output_root" \
    >"$TEST_ROOT/$label.stdout" 2>"$TEST_ROOT/$label.stderr" &
  BARRIER_PID=$!
  if ! IFS= read -r -t 30 BARRIER_STAGING_NAME <&5; then
    /bin/kill -TERM "$BARRIER_PID" 2>/dev/null || true
    wait "$BARRIER_PID" 2>/dev/null || true
    die "barriered stager readiness watchdog expired: $label"
  fi
  case "$BARRIER_STAGING_NAME" in
    .winn-stageb-engine.[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) die "barriered stager returned an unsafe staging name: $label" ;;
  esac
}

finish_barriered_stage() {
  local label="$1"
  local expected_status="$2"
  local deadline
  local status
  /usr/bin/printf 'GO\n' >&6
  deadline=$((SECONDS + 30))
  while /bin/kill -0 "$BARRIER_PID" 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      /bin/kill -TERM "$BARRIER_PID" 2>/dev/null || true
      wait "$BARRIER_PID" 2>/dev/null || true
      exec 5>&-
      exec 6>&-
      die "barriered stager completion watchdog expired: $label"
    fi
    /bin/sleep 0.1
  done
  set +e
  wait "$BARRIER_PID"
  status=$?
  set -e
  exec 5>&-
  exec 6>&-
  if [ "$expected_status" = "success" ]; then
    [ "$status" -eq 0 ] || die "barriered stager unexpectedly failed: $label"
  else
    [ "$status" -ne 0 ] || die "barriered mutation was unexpectedly published: $label"
  fi
}

SCRIPT_DIR="$(cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)"
readonly SCRIPT_DIR
readonly STAGER="$SCRIPT_DIR/stage_stageb_engine_artifact.sh"
SPIKE_ROOT="$(cd -- "$SCRIPT_DIR/.." && /bin/pwd -P)"
readonly SPIKE_ROOT
REPOSITORY_ROOT="$(cd -- "$SPIKE_ROOT/../../.." && /bin/pwd -P)"
readonly REPOSITORY_ROOT
readonly DEVICE_SOURCE="$REPOSITORY_ROOT/apple/EngineArtifacts/ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib"
readonly SIMULATOR_SOURCE="$REPOSITORY_ROOT/apple/EngineArtifacts/ios/iphonesimulator/libWinsAmneziaWGPacketEngine.dylib"
readonly DEVICE_SHA256="e0e810039d0ed43b1a599bb64320b0ee4ab4903cbdfd33e048bf0fb5e7f116cd"
readonly SIMULATOR_SHA256="00a17dfd702dc0490efd4f39bc2259fcc38fa4eed8311885499b5f1611713fa3"
readonly INSTALL_NAME="@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"
readonly FRAMEWORK_NAME="WinsAmneziaWGPacketEngine.framework"
readonly BINARY_NAME="WinsAmneziaWGPacketEngine"
STAGER_SHA256="$(sha256_file "$STAGER")"
readonly STAGER_SHA256

raw_test_root=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/winn-stageb-engine-test.XXXXXX")
TEST_ROOT="$(cd -- "$raw_test_root" && /bin/pwd -P)"
readonly TEST_ROOT

cleanup() {
  case "${TEST_ROOT:-}" in
    /private/var/folders/*/winn-stageb-engine-test.*|/private/tmp/winn-stageb-engine-test.*|/tmp/winn-stageb-engine-test.*)
      [ ! -L "$TEST_ROOT" ] && /bin/rm -rf -- "$TEST_ROOT"
      ;;
    *)
      printf 'test_stageb_engine_artifact: refusing unsafe cleanup path\n' >&2
      ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ -x "$STAGER" ] || die "stager is not executable"

/bin/mkdir -m 0700 -- \
  "$TEST_ROOT/device-a" \
  "$TEST_ROOT/device-b" \
  "$TEST_ROOT/simulator-a" \
  "$TEST_ROOT/simulator-b"

device_receipt_a="$("$STAGER" iphoneos "$TEST_ROOT/device-a")"
device_receipt_b="$("$STAGER" iphoneos "$TEST_ROOT/device-b")"
simulator_receipt_a="$("$STAGER" iphonesimulator "$TEST_ROOT/simulator-a")"
simulator_receipt_b="$("$STAGER" iphonesimulator "$TEST_ROOT/simulator-b")"

[ "$device_receipt_a" = "$device_receipt_b" ] ||
  die "device receipt is not deterministic across staging roots"
[ "$simulator_receipt_a" = "$simulator_receipt_b" ] ||
  die "simulator receipt is not deterministic across staging roots"

for receipt in "$device_receipt_a" "$simulator_receipt_a"; do
  assert_exact_receipt_shape "$receipt"
  printf '%s\n' "$receipt" |
    /usr/bin/grep -Fq '"publication":"atomic-no-replace-non-durable"}' ||
    die "receipt does not attest the publication boundary"
  printf '%s\n' "$receipt" |
    /usr/bin/grep -Fq "\"stager_script_sha256\":\"$STAGER_SHA256\"" ||
    die "receipt does not bind the exact stager script bytes"
  printf '%s\n' "$receipt" |
    /usr/bin/grep -Eq '"publisher_source_sha256":"[0-9a-f]{64}","publisher_binary_sha256":"[0-9a-f]{64}","developer_toolchain_selector_sha256":"[0-9a-f]{64}"' ||
    die "receipt does not bind the publisher and selected developer toolchain"
done
printf '%s\n' "$device_receipt_a" |
  /usr/bin/grep -Fq '"platform":"iphoneos","supported_platform":"iPhoneOS","minimum_os_version":"13.0","architectures":["arm64"]' ||
  die "device receipt platform fields are incorrect"
printf '%s\n' "$simulator_receipt_a" |
  /usr/bin/grep -Fq '"platform":"iphonesimulator","supported_platform":"iPhoneSimulator","minimum_os_version":"14.0","architectures":["arm64","x86_64"]' ||
  die "simulator receipt platform fields are incorrect"
printf '%s\n' "$device_receipt_a" |
  /usr/bin/grep -Fq "\"source_binary_sha256\":\"$DEVICE_SHA256\",\"binary_sha256\":\"$DEVICE_SHA256\"" ||
  die "device receipt binary hashes are incorrect"
printf '%s\n' "$simulator_receipt_a" |
  /usr/bin/grep -Fq "\"source_binary_sha256\":\"$SIMULATOR_SHA256\",\"binary_sha256\":\"$SIMULATOR_SHA256\"" ||
  die "simulator receipt binary hashes are incorrect"

receipt_with_extra_key="${device_receipt_a%\}},\"extra\":true}"
receipt_with_duplicate_key="${device_receipt_a%\}},\"platform\":\"iphoneos\"}"
receipt_with_wrong_type="${device_receipt_a/\"minimum_os_version\":\"13.0\"/\"minimum_os_version\":13.0}"
receipt_with_reordered_keys="${device_receipt_a/\"platform\":\"iphoneos\",\"supported_platform\":\"iPhoneOS\"/\"supported_platform\":\"iPhoneOS\",\"platform\":\"iphoneos\"}"
for invalid_receipt in \
  "$receipt_with_extra_key" \
  "$receipt_with_duplicate_key" \
  "$receipt_with_wrong_type" \
  "$receipt_with_reordered_keys"; do
  if receipt_has_exact_shape "$invalid_receipt"; then
    die "exact receipt validator accepted an unknown, duplicate, mistyped, or reordered key"
  fi
done

for platform_root in \
  "$TEST_ROOT/device-a" \
  "$TEST_ROOT/device-b" \
  "$TEST_ROOT/simulator-a" \
  "$TEST_ROOT/simulator-b"; do
  framework="$platform_root/$FRAMEWORK_NAME"
  [ -d "$framework" ] || die "framework directory is absent"
  [ -f "$framework/Info.plist" ] || die "framework Info.plist is absent"
  [ -f "$framework/$BINARY_NAME" ] || die "framework binary is absent"
  [ ! -L "$framework/Info.plist" ] || die "framework Info.plist is a symlink"
  [ ! -L "$framework/$BINARY_NAME" ] || die "framework binary is a symlink"
  [ "$(/usr/bin/stat -f '%Lp' "$framework")" = "755" ] ||
    die "framework directory mode is not deterministic"
  [ "$(/usr/bin/stat -f '%Lp' "$framework/Info.plist")" = "444" ] ||
    die "framework Info.plist mode is not deterministic"
  [ "$(/usr/bin/stat -f '%Lp' "$framework/$BINARY_NAME")" = "555" ] ||
    die "framework binary mode is not deterministic"
  entry_count=$(/usr/bin/find "$framework" -mindepth 1 | /usr/bin/awk 'END { print NR }')
  [ "$entry_count" -eq 2 ] || die "framework contains an unexpected entry"
  file_count=$(/usr/bin/find "$framework" -type f | /usr/bin/awk 'END { print NR }')
  [ "$file_count" -eq 2 ] || die "framework contains an unexpected file"
  /usr/bin/plutil -lint "$framework/Info.plist" >/dev/null ||
    die "framework Info.plist is invalid"
  [ "$(plist_value "$framework/Info.plist" CFBundleInfoDictionaryVersion)" = "6.0" ] ||
    die "framework Info.plist dictionary version is incorrect"
done

device_framework="$TEST_ROOT/device-a/$FRAMEWORK_NAME"
simulator_framework="$TEST_ROOT/simulator-a/$FRAMEWORK_NAME"
device_staged="$device_framework/$BINARY_NAME"
simulator_staged="$simulator_framework/$BINARY_NAME"
[ "$(sha256_file "$device_staged")" = "$DEVICE_SHA256" ] ||
  die "device binary hash was not preserved"
[ "$(sha256_file "$simulator_staged")" = "$SIMULATOR_SHA256" ] ||
  die "simulator binary hash was not preserved"
[ "$(/usr/bin/stat -f '%i' "$DEVICE_SOURCE")" != "$(/usr/bin/stat -f '%i' "$device_staged")" ] ||
  die "device staging created a hard link"
[ "$(/usr/bin/stat -f '%i' "$SIMULATOR_SOURCE")" != "$(/usr/bin/stat -f '%i' "$simulator_staged")" ] ||
  die "simulator staging created a hard link"

[ "$(plist_value "$device_framework/Info.plist" 'CFBundleSupportedPlatforms:0')" = "iPhoneOS" ] ||
  die "device supported platform is incorrect"
[ "$(plist_value "$simulator_framework/Info.plist" 'CFBundleSupportedPlatforms:0')" = "iPhoneSimulator" ] ||
  die "simulator supported platform is incorrect"
[ "$(plist_value "$device_framework/Info.plist" MinimumOSVersion)" = "13.0" ] ||
  die "device minimum OS is incorrect"
[ "$(plist_value "$simulator_framework/Info.plist" MinimumOSVersion)" = "14.0" ] ||
  die "simulator minimum OS is not the maximum required by its slices"
if /usr/bin/cmp -s "$device_framework/Info.plist" "$simulator_framework/Info.plist"; then
  die "platform-specific framework Info.plists unexpectedly match"
fi

assert_required_symbols_by_slice "$device_staged" arm64
assert_required_symbols_by_slice "$simulator_staged" arm64 x86_64
assert_install_name_by_slice "$device_staged" arm64
assert_install_name_by_slice "$simulator_staged" arm64 x86_64

for tuple in \
  "$device_receipt_a|$device_framework" \
  "$simulator_receipt_a|$simulator_framework"; do
  receipt="${tuple%%|*}"
  framework="${tuple#*|}"
  plist_hash=$(sha256_file "$framework/Info.plist")
  binary_hash=$(sha256_file "$framework/$BINARY_NAME")
  manifest="$TEST_ROOT/recomputed.manifest"
  /usr/bin/printf \
    '0444\t%s\tInfo.plist\n0555\t%s\t%s\n' \
    "$plist_hash" "$binary_hash" "$BINARY_NAME" > "$manifest"
  tree_hash=$(sha256_file "$manifest")
  printf '%s\n' "$receipt" |
    /usr/bin/grep -Fq "\"info_plist_sha256\":\"$plist_hash\",\"regular_file_tree_manifest_sha256\":\"$tree_hash\"" ||
    die "receipt tree attestation is incorrect"
done

DEVICE_SOURCE_BEFORE="$(sha256_file "$DEVICE_SOURCE")"
readonly DEVICE_SOURCE_BEFORE
/bin/chmod 0755 "$device_staged"
/usr/bin/printf '\001' >> "$device_staged"
[ "$(sha256_file "$DEVICE_SOURCE")" = "$DEVICE_SOURCE_BEFORE" ] ||
  die "mutating a staged copy changed its pinned source"

expect_failure unsupported-platform "$STAGER" $'bad\nplatform' "$TEST_ROOT"
if /usr/bin/grep -q 'bad' "$TEST_ROOT/unsupported-platform.stderr"; then
  die "unsupported platform diagnostic reflected attacker-controlled input"
fi
expect_failure unsafe-root "$STAGER" iphoneos /
expect_failure unsafe-source-tree "$STAGER" iphoneos "$REPOSITORY_ROOT/apple/EngineArtifacts"

/bin/mkdir -m 0700 -- "$TEST_ROOT/output-link-target"
/bin/ln -s -- "$TEST_ROOT/output-link-target" "$TEST_ROOT/output-link"
expect_failure output-symlink "$STAGER" iphoneos "$TEST_ROOT/output-link"

/bin/mkdir -m 0777 -- "$TEST_ROOT/world-writable-output"
expect_failure world-writable-output "$STAGER" iphoneos "$TEST_ROOT/world-writable-output"
/usr/bin/grep -Fq 'must not be group- or world-writable' "$TEST_ROOT/world-writable-output.stderr" ||
  die "world-writable output did not fail at the mode gate"

/bin/mkdir -m 0700 -- "$TEST_ROOT/occupied-output"
/bin/mkdir -m 0700 -- "$TEST_ROOT/occupied-output/unrelated"
"$STAGER" iphoneos "$TEST_ROOT/occupied-output" >/dev/null
[ -d "$TEST_ROOT/occupied-output/unrelated" ] ||
  die "stager changed an unrelated output-root entry"
expect_failure existing-destination "$STAGER" iphoneos "$TEST_ROOT/occupied-output"

/bin/mkdir -m 0700 -- \
  "$TEST_ROOT/destination-link-output" \
  "$TEST_ROOT/destination-link-target"
/bin/ln -s -- \
  "$TEST_ROOT/destination-link-target" \
  "$TEST_ROOT/destination-link-output/$FRAMEWORK_NAME"
expect_failure destination-symlink \
  "$STAGER" iphoneos "$TEST_ROOT/destination-link-output"
[ -L "$TEST_ROOT/destination-link-output/$FRAMEWORK_NAME" ] ||
  die "stager replaced or removed a preexisting destination symlink"

/bin/mkdir -m 0700 -- "$TEST_ROOT/race-output"
set +e
"$STAGER" iphoneos "$TEST_ROOT/race-output" \
  >"$TEST_ROOT/race-a.stdout" 2>"$TEST_ROOT/race-a.stderr" &
race_a_pid=$!
"$STAGER" iphoneos "$TEST_ROOT/race-output" \
  >"$TEST_ROOT/race-b.stdout" 2>"$TEST_ROOT/race-b.stderr" &
race_b_pid=$!
wait "$race_a_pid"
race_a_status=$?
wait "$race_b_pid"
race_b_status=$?
set -e
if ! { [ "$race_a_status" -eq 0 ] && [ "$race_b_status" -ne 0 ]; } &&
   ! { [ "$race_b_status" -eq 0 ] && [ "$race_a_status" -ne 0 ]; }; then
  die "concurrent publication did not produce exactly one winner"
fi
[ -d "$TEST_ROOT/race-output/$FRAMEWORK_NAME" ] ||
  die "concurrent publication produced no framework"
race_temporary_count=$(
  /usr/bin/find "$TEST_ROOT/race-output" -maxdepth 1 -name '.winn-stageb-engine.*' |
    /usr/bin/awk 'END { print NR }'
)
[ "$race_temporary_count" -eq 0 ] ||
  die "concurrent publication left a staging directory behind"
if ! /usr/bin/grep -Fq 'anchored closed-world framework publication failed' \
     "$TEST_ROOT/race-a.stderr" "$TEST_ROOT/race-b.stderr"; then
  die "concurrent loser did not reach the no-replace publication primitive"
fi

/bin/mkdir -m 0700 -- "$TEST_ROOT/root-rebind-output"
start_barriered_stage root-rebind "$TEST_ROOT/root-rebind-output"
/bin/mv -- "$TEST_ROOT/root-rebind-output" "$TEST_ROOT/root-rebind-original"
/bin/mkdir -m 0700 -- "$TEST_ROOT/root-rebind-target"
/bin/ln -s -- "$TEST_ROOT/root-rebind-target" "$TEST_ROOT/root-rebind-output"
finish_barriered_stage root-rebind success
[ -d "$TEST_ROOT/root-rebind-original/$FRAMEWORK_NAME" ] ||
  die "root-rebind publication did not remain anchored to the opened original root"
[ -z "$(/usr/bin/find "$TEST_ROOT/root-rebind-target" -mindepth 1 -maxdepth 1 -print)" ] ||
  die "root-rebind publication or cleanup touched the rebound symlink target"

/bin/mkdir -m 0700 -- "$TEST_ROOT/post-rename-cleanup-output"
WINN_STAGEB_TEST_POST_RENAME_CLEANUP_FAILURE=1 \
  "$STAGER" iphoneos "$TEST_ROOT/post-rename-cleanup-output" \
  >"$TEST_ROOT/post-rename-cleanup.stdout" \
  2>"$TEST_ROOT/post-rename-cleanup.stderr"
post_rename_receipt="$(/bin/cat "$TEST_ROOT/post-rename-cleanup.stdout")"
assert_exact_receipt_shape "$post_rename_receipt"
printf '%s\n' "$post_rename_receipt" |
  /usr/bin/grep -Fq "\"stager_script_sha256\":\"$STAGER_SHA256\"" ||
  die "post-rename cleanup failure suppressed or altered the receipt"
[ -d "$TEST_ROOT/post-rename-cleanup-output/$FRAMEWORK_NAME" ] ||
  die "post-rename cleanup fault lost the committed framework"
[ "$(
  /usr/bin/grep -Fxc \
    'publisher warning: framework publication committed; post-publication staging cleanup failed at checkpoint 90' \
    "$TEST_ROOT/post-rename-cleanup.stderr"
)" -eq 1 ] || die "post-rename cleanup fault did not emit the exact single warning"
post_rename_temporary_count=$(
  /usr/bin/find "$TEST_ROOT/post-rename-cleanup-output" \
    -mindepth 1 -maxdepth 1 -name '.winn-stageb-engine.*' |
    /usr/bin/awk 'END { print NR }'
)
[ "$post_rename_temporary_count" -eq 1 ] ||
  die "post-rename cleanup fault did not preserve exactly one diagnosable staging directory"
/bin/rm -rf -- "$TEST_ROOT/post-rename-cleanup-output"/.winn-stageb-engine.*

/bin/mkdir -m 0700 -- "$TEST_ROOT/extra-entry-output"
start_barriered_stage extra-entry "$TEST_ROOT/extra-entry-output"
extra_entry_framework="$TEST_ROOT/extra-entry-output/$BARRIER_STAGING_NAME/$FRAMEWORK_NAME"
/bin/chmod 0755 "$extra_entry_framework"
/usr/bin/touch "$extra_entry_framework/unexpected"
finish_barriered_stage extra-entry failure
[ -z "$(/usr/bin/find "$TEST_ROOT/extra-entry-output" -mindepth 1 -maxdepth 1 -print)" ] ||
  die "extra-entry rejection did not clean its descriptor-anchored staging tree"

/bin/mkdir -m 0700 -- "$TEST_ROOT/symlink-replacement-output"
start_barriered_stage symlink-replacement "$TEST_ROOT/symlink-replacement-output"
symlink_framework="$TEST_ROOT/symlink-replacement-output/$BARRIER_STAGING_NAME/$FRAMEWORK_NAME"
/bin/chmod 0755 "$symlink_framework"
/bin/chmod 0755 "$symlink_framework/$BINARY_NAME"
/bin/rm -- "$symlink_framework/$BINARY_NAME"
/bin/ln -s -- "$DEVICE_SOURCE" "$symlink_framework/$BINARY_NAME"
finish_barriered_stage symlink-replacement failure
[ -z "$(/usr/bin/find "$TEST_ROOT/symlink-replacement-output" -mindepth 1 -maxdepth 1 -print)" ] ||
  die "symlink-replacement rejection did not clean its staging tree"

device_source_links_before=$(/usr/bin/stat -f '%l' "$DEVICE_SOURCE")
/bin/mkdir -m 0700 -- "$TEST_ROOT/hardlink-replacement-output"
start_barriered_stage hardlink-replacement "$TEST_ROOT/hardlink-replacement-output"
hardlink_framework="$TEST_ROOT/hardlink-replacement-output/$BARRIER_STAGING_NAME/$FRAMEWORK_NAME"
/bin/chmod 0755 "$hardlink_framework"
/bin/chmod 0755 "$hardlink_framework/$BINARY_NAME"
/bin/rm -- "$hardlink_framework/$BINARY_NAME"
/bin/ln -- "$DEVICE_SOURCE" "$hardlink_framework/$BINARY_NAME"
finish_barriered_stage hardlink-replacement failure
[ "$(/usr/bin/stat -f '%l' "$DEVICE_SOURCE")" = "$device_source_links_before" ] ||
  die "hardlink-replacement cleanup changed source-custody link count"
[ -z "$(/usr/bin/find "$TEST_ROOT/hardlink-replacement-output" -mindepth 1 -maxdepth 1 -print)" ] ||
  die "hardlink-replacement rejection did not clean its staging tree"

valid_dependency='/System/Library/Frameworks/Foundation.framework/Foundation'
"$STAGER" --validate-dependency iphoneos arm64 "$valid_dependency" >/dev/null
expect_failure dependency-empty "$STAGER" --validate-dependency iphoneos arm64 ''
expect_failure dependency-control "$STAGER" --validate-dependency iphoneos arm64 $'/usr/lib/libSystem.B.dylib\nx'
expect_failure dependency-repeat "$STAGER" --validate-dependency iphoneos arm64 '/usr//lib/libSystem.B.dylib'
expect_failure dependency-trailing "$STAGER" --validate-dependency iphoneos arm64 '/usr/lib/'
expect_failure dependency-dot "$STAGER" --validate-dependency iphoneos arm64 '/usr/./lib/libSystem.B.dylib'
expect_failure dependency-dotdot "$STAGER" --validate-dependency iphoneos arm64 '/usr/lib/../lib/libSystem.B.dylib'
expect_failure dependency-relative "$STAGER" --validate-dependency iphoneos arm64 'usr/lib/libSystem.B.dylib'
expect_failure dependency-unpinned "$STAGER" --validate-dependency iphoneos arm64 '/System/Library/Frameworks/UIKit.framework/UIKit'
expect_failure dependency-wrong-arch "$STAGER" --validate-dependency iphoneos x86_64 "$valid_dependency"

valid_otool_line=$'\t/System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 300.0.0, current version 5026.5.4)'
"$STAGER" --parse-otool-dependency-line \
  iphoneos arm64 "$valid_otool_line" "$valid_dependency" >/dev/null
expect_failure otool-missing-tab "$STAGER" --parse-otool-dependency-line \
  iphoneos arm64 "${valid_otool_line#$'\t'}" "$valid_dependency"
expect_failure otool-invalid-version "$STAGER" --parse-otool-dependency-line \
  iphoneos arm64 $'\t/System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 300, current version 5026.5.4)' "$valid_dependency"
expect_failure otool-trailing-data "$STAGER" --parse-otool-dependency-line \
  iphoneos arm64 "$valid_otool_line trailing" "$valid_dependency"
expect_failure otool-control "$STAGER" --parse-otool-dependency-line \
  iphoneos arm64 $'\t/System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 300.0.0, current version 5026.5.4)\r' "$valid_dependency"
expect_failure otool-unpinned "$STAGER" --parse-otool-dependency-line \
  iphoneos arm64 $'\t/System/Library/Frameworks/UIKit.framework/UIKit (compatibility version 1.0.0, current version 1.0.0)' '/System/Library/Frameworks/UIKit.framework/UIKit'

mock_repo="$TEST_ROOT/wrong-hash-repo"
/bin/mkdir -p -- \
  "$mock_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts" \
  "$mock_repo/apple/EngineArtifacts/ios/iphoneos"
/bin/cp -- "$STAGER" "$mock_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts/"
/bin/cp -- "$DEVICE_SOURCE" "$mock_repo/apple/EngineArtifacts/ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib"
/bin/chmod 0700 "$mock_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts/stage_stageb_engine_artifact.sh"
/usr/bin/printf '\001' >> "$mock_repo/apple/EngineArtifacts/ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib"
/bin/mkdir -m 0700 "$TEST_ROOT/wrong-hash-output"
expect_failure wrong-hash \
  "$mock_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts/stage_stageb_engine_artifact.sh" \
  iphoneos \
  "$TEST_ROOT/wrong-hash-output"
/usr/bin/grep -Fq 'SHA-256 mismatch' "$TEST_ROOT/wrong-hash.stderr" ||
  die "wrong-hash fixture did not fail at the hash gate"

symlink_repo="$TEST_ROOT/source-symlink-repo"
/bin/mkdir -p -- \
  "$symlink_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts" \
  "$symlink_repo/apple/EngineArtifacts/ios/iphoneos"
/bin/cp -- "$STAGER" "$symlink_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts/"
/bin/chmod 0700 "$symlink_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts/stage_stageb_engine_artifact.sh"
/bin/ln -s -- "$DEVICE_SOURCE" "$symlink_repo/apple/EngineArtifacts/ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib"
/bin/mkdir -m 0700 "$TEST_ROOT/source-symlink-output"
expect_failure source-symlink \
  "$symlink_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts/stage_stageb_engine_artifact.sh" \
  iphoneos \
  "$TEST_ROOT/source-symlink-output"
/usr/bin/grep -Fq 'symlink path component is forbidden' "$TEST_ROOT/source-symlink.stderr" ||
  die "source-symlink fixture did not fail at the custody gate"

platform_repo="$TEST_ROOT/wrong-platform-repo"
/bin/mkdir -p -- \
  "$platform_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts" \
  "$platform_repo/apple/EngineArtifacts/ios/iphoneos"
/bin/cp -- "$STAGER" "$platform_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts/"
/bin/cp -- "$SIMULATOR_SOURCE" "$platform_repo/apple/EngineArtifacts/ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib"
/bin/chmod 0700 "$platform_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts/stage_stageb_engine_artifact.sh"
/usr/bin/sed -i '' \
  "s/$DEVICE_SHA256/$SIMULATOR_SHA256/" \
  "$platform_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts/stage_stageb_engine_artifact.sh"
/bin/mkdir -m 0700 "$TEST_ROOT/wrong-platform-output"
expect_failure wrong-platform \
  "$platform_repo/winn_protocol_experimental/spikes/ios_maximum_privacy/Scripts/stage_stageb_engine_artifact.sh" \
  iphoneos \
  "$TEST_ROOT/wrong-platform-output"
/usr/bin/grep -Fq 'Mach-O architectures do not match' "$TEST_ROOT/wrong-platform.stderr" ||
  die "wrong-platform fixture did not fail at the platform/architecture gate"

leftover_staging_count=$(
  /usr/bin/find "$TEST_ROOT" -name '.winn-stageb-engine.*' |
    /usr/bin/awk 'END { print NR }'
)
[ "$leftover_staging_count" -eq 0 ] ||
  die "a failed or successful invocation left a temporary staging directory"

printf '%s\n' "WINN_STAGEB_ENGINE_ARTIFACT_TEST_PASS"
