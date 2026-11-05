#!/bin/sh
set -eu

# Deterministic fixtures for the generated Xcode project's Stage B wiring.
#
# Two properties are covered:
#
#   1. The generator's NativeEngine inventory guard. It must refuse a source or
#      header on disk that the literal list does not name, and refuse a name in
#      the literal list that is not on disk. Without both directions a new
#      translation unit could ship uncompiled.
#
#   2. The project wiring gate used by both build lanes. It must refuse a
#      project that fails any of: compiling every NativeEngine .c into the
#      Packet Tunnel, keeping those sources out of the host, keeping the engine
#      framework unlinked by both targets, keeping the extension free of a copy
#      phase for it, and embedding exactly one copy into the app's Frameworks
#      directory with CodeSignOnCopy and RemoveHeadersOnCopy.
#
# Each refusal is paired with a positive control on the same input before the
# single mutation, so a gate that always failed would be caught too. Mutated
# projects are produced by editing a generated project with Xcodeproj, never by
# asking the generator to produce something invalid.
#
# Nothing here runs xcodebuild.

spike_test_script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
spike_test_root="$(CDPATH='' cd -- "${spike_test_script_dir}/.." && pwd)"
spike_test_generator="${spike_test_script_dir}/generate_project.rb"

spike_test_scratch="$(
  CDPATH='' cd -- "$(
    mktemp -d "${TMPDIR:-/tmp}/winn-stageb-project-integration.XXXXXX"
  )" && pwd -P
)"
spike_test_cleanup() {
  chmod -R u+w "${spike_test_scratch}" 2>/dev/null || true
  rm -R "${spike_test_scratch}"
}
trap spike_test_cleanup EXIT HUP INT TERM

spike_test_failures=0
spike_test_checks=0

spike_test_note_failure() {
  echo "FAIL: $1" >&2
  spike_test_failures=$((spike_test_failures + 1))
}

# Load the wiring gate from the real build script.
spike_test_shared="${spike_test_scratch}/shared.sh"
awk '
  /^# BEGIN spike_stageb_engine_shared$/ { emit = 1 }
  emit { print }
  /^# END spike_stageb_engine_shared$/ { emit = 0 }
' "${spike_test_script_dir}/build_device.sh" >"${spike_test_shared}"
test -s "${spike_test_shared}" || {
  echo "FAIL: build_device.sh has no shared engine verifier block." >&2
  exit 1
}
# shellcheck source=/dev/null
. "${spike_test_shared}"

# Builds a throwaway spike root that mirrors the real one closely enough to
# generate a project: the generator only reads NativeEngine's directory
# listing, and file references need not exist on disk.
spike_test_make_root() {
  spike_root_path="$1"
  mkdir -p "${spike_root_path}/Scripts"
  cp -R "${spike_test_root}/NativeEngine" "${spike_root_path}/NativeEngine"
  cp "${spike_test_generator}" "${spike_root_path}/Scripts/generate_project.rb"
}

spike_test_generate() {
  spike_generate_root="$1"
  ( cd "${spike_generate_root}" && ruby Scripts/generate_project.rb )
}

# --- generator determinism -------------------------------------------------
# Two independent generations of the same inputs must produce the same
# UUID-independent object graph and the same shared scheme after normalizing
# only the generated host target UUID.
spike_test_checks=$((spike_test_checks + 1))
spike_test_gen_a="${spike_test_scratch}/gen-a"
spike_test_gen_b="${spike_test_scratch}/gen-b"
spike_test_make_root "${spike_test_gen_a}"
spike_test_make_root "${spike_test_gen_b}"
spike_test_generate "${spike_test_gen_a}" >/dev/null
spike_test_generate "${spike_test_gen_b}" >/dev/null
ruby "${spike_test_generator}" --canonical-manifest \
  "${spike_test_gen_a}/PrivacySpike.xcodeproj" \
  >"${spike_test_scratch}/manifest-a.json"
ruby "${spike_test_generator}" --canonical-manifest \
  "${spike_test_gen_b}/PrivacySpike.xcodeproj" \
  >"${spike_test_scratch}/manifest-b.json"
cmp -s \
  "${spike_test_scratch}/manifest-a.json" \
  "${spike_test_scratch}/manifest-b.json" ||
  spike_test_note_failure "the generator is not deterministic."

spike_test_normalize_scheme() {
  spike_scheme_root="$1"
  spike_scheme_output="$2"
  ruby -rxcodeproj -e '
    root = ARGV.fetch(0)
    project = Xcodeproj::Project.open(
      File.join(root, "PrivacySpike.xcodeproj")
    )
    host = project.targets.find { |target| target.name == "PrivacySpike" }
    abort("scheme host target is absent") unless host
    scheme = File.join(
      root,
      "PrivacySpike.xcodeproj",
      "xcshareddata",
      "xcschemes",
      "PrivacySpike.xcscheme"
    )
    text = File.binread(scheme)
    identifiers = text.scan(
      /BlueprintIdentifier = "([0-9A-F]{24})"/
    ).flatten
    abort("scheme has no generated target UUID") if identifiers.empty?
    unless identifiers.all? { |identifier| identifier == host.uuid }
      abort("scheme does not consistently reference the host target UUID")
    end
    normalized = text.gsub(
      /BlueprintIdentifier = "[0-9A-F]{24}"/,
      %q{BlueprintIdentifier = "NORMALIZED_TARGET_UUID"}
    )
    File.binwrite(ARGV.fetch(1), normalized)
  ' "${spike_scheme_root}" "${spike_scheme_output}"
}

spike_test_checks=$((spike_test_checks + 1))
spike_test_normalize_scheme \
  "${spike_test_gen_a}" \
  "${spike_test_scratch}/scheme-a.xml"
spike_test_normalize_scheme \
  "${spike_test_gen_b}" \
  "${spike_test_scratch}/scheme-b.xml"
cmp -s \
  "${spike_test_scratch}/scheme-a.xml" \
  "${spike_test_scratch}/scheme-b.xml" ||
  spike_test_note_failure "the generated shared scheme is not deterministic."

# The checked-in project must be exactly what the generator produces from the
# real tree. The same comparison covers the checked-in shared scheme after
# normalizing its generated target UUID. This is the no-manual-drift property,
# checked against a root that really contains NativeEngine so the inventory
# guard participates.
spike_test_checks=$((spike_test_checks + 1))
ruby "${spike_test_generator}" --canonical-manifest \
  "${spike_test_root}/PrivacySpike.xcodeproj" \
  >"${spike_test_scratch}/manifest-checked-in.json"
cmp -s \
  "${spike_test_scratch}/manifest-checked-in.json" \
  "${spike_test_scratch}/manifest-a.json" ||
  spike_test_note_failure \
    "the checked-in project differs from a fresh generation; regenerate it."

spike_test_checks=$((spike_test_checks + 1))
spike_test_normalize_scheme \
  "${spike_test_root}" \
  "${spike_test_scratch}/scheme-checked-in.xml"
cmp -s \
  "${spike_test_scratch}/scheme-checked-in.xml" \
  "${spike_test_scratch}/scheme-a.xml" ||
  spike_test_note_failure \
    "the checked-in shared scheme differs from a fresh generation; regenerate it."

# --- generator inventory guard --------------------------------------------
spike_test_expect_generator_refusal() {
  spike_gen_label="$1"
  spike_gen_root="$2"
  spike_gen_expected="$3"
  spike_test_checks=$((spike_test_checks + 1))
  if spike_test_generate "${spike_gen_root}" \
    >"${spike_test_scratch}/gen.out" 2>"${spike_test_scratch}/gen.err"
  then
    spike_test_note_failure \
      "${spike_gen_label}: the generator accepted a mismatched inventory."
    return 0
  fi
  grep -Fq "${spike_gen_expected}" "${spike_test_scratch}/gen.err" || {
    spike_test_note_failure "${spike_gen_label}: wrong refusal reason."
    echo "  expected: ${spike_gen_expected}" >&2
    echo "  actual:   $(head -2 "${spike_test_scratch}/gen.err")" >&2
  }
}

spike_test_unlisted="${spike_test_scratch}/unlisted-source"
spike_test_make_root "${spike_test_unlisted}"
spike_test_checks=$((spike_test_checks + 1))
spike_test_generate "${spike_test_unlisted}" >/dev/null 2>&1 ||
  spike_test_note_failure \
    "unlisted-source precondition: a clean root failed to generate."
rm -R "${spike_test_unlisted}/PrivacySpike.xcodeproj"
printf 'int winn_unlisted(void) { return 0; }\n' \
  >"${spike_test_unlisted}/NativeEngine/WinnUnlisted.c"
spike_test_expect_generator_refusal \
  unlisted-source \
  "${spike_test_unlisted}" \
  'NativeEngine/WinnUnlisted.c is an unlisted source.'

spike_test_unlisted_header="${spike_test_scratch}/unlisted-header"
spike_test_make_root "${spike_test_unlisted_header}"
printf '#pragma once\n' \
  >"${spike_test_unlisted_header}/NativeEngine/WinnUnlisted.h"
spike_test_expect_generator_refusal \
  unlisted-header \
  "${spike_test_unlisted_header}" \
  'NativeEngine/WinnUnlisted.h is an unlisted header.'

spike_test_absent="${spike_test_scratch}/absent-source"
spike_test_make_root "${spike_test_absent}"
rm -f "${spike_test_absent}/NativeEngine/WinnStageBNativeEngine.c"
spike_test_expect_generator_refusal \
  absent-source \
  "${spike_test_absent}" \
  'NativeEngine source(s) referenced by this generator are absent'

# --- project wiring gate ---------------------------------------------------
# Mutates a generated project in place with Xcodeproj, then re-runs the gate.
spike_test_mutate_project() {
  spike_mutate_root="$1"
  spike_mutate_program="$2"
  ruby -e "
    require \"xcodeproj\"
    project = Xcodeproj::Project.open(
      File.join(ARGV.fetch(0), \"PrivacySpike.xcodeproj\")
    )
    provider = project.targets.find { |t| t.name == \"PrivacySpikePacketTunnel\" }
    host = project.targets.find { |t| t.name == \"PrivacySpike\" }
    engine = project.files.find { |f|
      f.path == \"WinsAmneziaWGPacketEngine.framework\"
    }
    ${spike_mutate_program}
    project.save
  " "${spike_mutate_root}"
}

spike_test_expect_wiring_refusal() {
  spike_wiring_label="$1"
  spike_wiring_expected="$2"
  spike_wiring_program="$3"
  spike_wiring_root="${spike_test_scratch}/wiring-${spike_wiring_label}"
  spike_test_make_root "${spike_wiring_root}"
  spike_test_generate "${spike_wiring_root}" >/dev/null

  # Positive control on the unmutated project.
  spike_test_checks=$((spike_test_checks + 1))
  spike_assert_engine_project_wiring "${spike_wiring_root}" \
    >/dev/null 2>"${spike_test_scratch}/wiring.err" ||
    {
      spike_test_note_failure \
        "${spike_wiring_label}: the gate rejected an unmutated project."
      cat "${spike_test_scratch}/wiring.err" >&2
    }

  spike_test_mutate_project "${spike_wiring_root}" "${spike_wiring_program}"

  spike_test_checks=$((spike_test_checks + 1))
  if spike_assert_engine_project_wiring "${spike_wiring_root}" \
    >/dev/null 2>"${spike_test_scratch}/wiring.err"
  then
    spike_test_note_failure \
      "${spike_wiring_label}: the gate accepted a mutated project."
    return 0
  fi
  grep -Fq "${spike_wiring_expected}" "${spike_test_scratch}/wiring.err" || {
    spike_test_note_failure "${spike_wiring_label}: wrong refusal reason."
    echo "  expected: ${spike_wiring_expected}" >&2
    echo "  actual:   $(head -2 "${spike_test_scratch}/wiring.err")" >&2
  }
}

spike_test_expect_wiring_refusal \
  provider-links-engine \
  'the Packet Tunnel links' \
  'build_file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
   build_file.file_ref = engine
   provider.frameworks_build_phase.files << build_file'

spike_test_expect_wiring_refusal \
  extension-local-copy \
  'extension-local copy phase' \
  'phase = provider.new_copy_files_build_phase("Extension Frameworks")
   phase.dst_subfolder_spec = "10"
   build_file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
   build_file.file_ref = engine
   phase.files << build_file'

spike_test_expect_wiring_refusal \
  host-does-not-embed \
  'the host embeds' \
  'host.copy_files_build_phases.each do |phase|
     phase.files.to_a.each do |build_file|
       if build_file.file_ref == engine
         build_file.remove_from_project
       end
     end
   end'

spike_test_expect_wiring_refusal \
  embed-missing-codesign \
  'not marked CodeSignOnCopy' \
  'host.copy_files_build_phases.each do |phase|
     phase.files.each do |build_file|
       if build_file.file_ref == engine
         build_file.settings = { "ATTRIBUTES" => ["RemoveHeadersOnCopy"] }
       end
     end
   end'

spike_test_expect_wiring_refusal \
  embed-missing-remove-headers \
  'not marked RemoveHeadersOnCopy' \
  'host.copy_files_build_phases.each do |phase|
     phase.files.each do |build_file|
       if build_file.file_ref == engine
         build_file.settings = { "ATTRIBUTES" => ["CodeSignOnCopy"] }
       end
     end
   end'

spike_test_expect_wiring_refusal \
  native-source-not-compiled \
  'differ from those compiled into the Packet Tunnel' \
  'provider.source_build_phase.files.to_a.each do |build_file|
     path = build_file.file_ref && build_file.file_ref.path
     if path && path.end_with?("WinnStageBNativeEngine.c")
       build_file.remove_from_project
     end
   end'

spike_test_expect_wiring_refusal \
  host-compiles-native-source \
  'the host target compiles Stage B native sources' \
  'source = provider.source_build_phase.files.find { |build_file|
     path = build_file.file_ref && build_file.file_ref.path
     path && path.end_with?("WinnStageBNativeEngine.c")
   }
   host.source_build_phase.add_file_reference(source.file_ref)'

spike_test_expect_wiring_refusal \
  provider-bridge-setting-missing \
  'bridging header is nil' \
  'provider.build_configurations.each do |configuration|
     configuration.build_settings.delete("SWIFT_OBJC_BRIDGING_HEADER")
   end'

spike_test_expect_wiring_refusal \
  host-imports-provider-bridge \
  'only the Packet Tunnel may import it' \
  'host.build_configurations.each do |configuration|
     configuration.build_settings["SWIFT_OBJC_BRIDGING_HEADER"] =
       "PacketTunnel/StageBProviderNativeBridge.h"
   end'

spike_test_expect_wiring_refusal \
  provider-native-header-path-missing \
  'does not contain the provider-private NativeEngine directory' \
  'provider.build_configurations.each do |configuration|
     configuration.build_settings["HEADER_SEARCH_PATHS"] = "$(inherited)"
   end'

spike_test_expect_wiring_refusal \
  duplicate-provider-bridge-reference \
  'exactly one provider-private bridge is required' \
  'project.main_group.new_file(
     "PacketTunnel/StageBProviderNativeBridge.h"
   )'

spike_test_expect_wiring_refusal \
  embed-not-into-frameworks \
  'is not embedded into the Frameworks directory' \
  'host.copy_files_build_phases.each do |phase|
     if phase.files.any? { |build_file| build_file.file_ref == engine }
       phase.dst_subfolder_spec = "7"
     end
   end'

# --- runtime-pin build phase ----------------------------------------------
# The manifest must be produced after the framework copy and before the app is
# signed. The declared input is what makes XCBuild order the task correctly, so
# removing it, moving the phase earlier, or letting a caller supply the runtime
# digest must each be refused.
spike_test_expect_wiring_refusal \
  pin-phase-missing \
  'phases; exactly one is required' \
  'host.build_phases.to_a.each do |phase|
     if phase.isa == "PBXShellScriptBuildPhase"
       phase.remove_from_project
     end
   end'

spike_test_expect_wiring_refusal \
  pin-phase-before-embed \
  'before the embed phase' \
  'pin = host.build_phases.find { |phase|
     phase.isa == "PBXShellScriptBuildPhase"
   }
   host.build_phases.delete(pin)
   host.build_phases.insert(0, pin)'

spike_test_expect_wiring_refusal \
  pin-phase-input-dropped \
  'the embedded engine must be the declared input' \
  'pin = host.build_phases.find { |phase|
     phase.isa == "PBXShellScriptBuildPhase"
   }
   pin.input_paths = []'

# The $(TARGET_BUILD_DIR) below is literal pbxproj text, not a shell command
# substitution.
# shellcheck disable=SC2016
spike_test_expect_wiring_refusal \
  pin-phase-output-wrong \
  'output paths are' \
  'pin = host.build_phases.find { |phase|
     phase.isa == "PBXShellScriptBuildPhase"
   }
   pin.output_paths = ["$(TARGET_BUILD_DIR)/elsewhere.manifest"]'

spike_test_expect_wiring_refusal \
  pin-phase-supplied-runtime-digest \
  'must measure the embedded bytes' \
  'pin = host.build_phases.find { |phase|
     phase.isa == "PBXShellScriptBuildPhase"
   }
   pin.shell_script =
     "WINN_STAGEB_ENGINE_RUNTIME_SHA256=deadbeef\n" + pin.shell_script'

spike_test_expect_wiring_refusal \
  pin-phase-clobbering-write \
  'atomic O_EXCL create' \
  'pin = host.build_phases.find { |phase|
     phase.isa == "PBXShellScriptBuildPhase"
   }
   pin.shell_script = pin.shell_script.sub("set -C\n", "")'

# --- provider Swift/C bridge fixture --------------------------------------
# Compile the real provider adapter against a deterministic C owner stub.  The
# fixture proves the cross-language ownership rules without loading the real
# Go-bearing framework or claiming a physical data path.
spike_bridge_stub_header="${spike_test_scratch}/StageBBridgeStub.h"
cat >"${spike_bridge_stub_header}" <<'BRIDGE_STUB_HEADER'
#ifndef WINN_STAGE_B_BRIDGE_STUB_H
#define WINN_STAGE_B_BRIDGE_STUB_H

#include "StageBProviderNativeBridge.h"

WinnStageBProviderNativeStart *winn_test_bridge_make_start(uint64_t sequence);
void winn_test_bridge_release_start(WinnStageBProviderNativeStart *start);
void winn_test_bridge_reset(void);
void winn_test_bridge_set_create_failure(int enabled);
void winn_test_bridge_set_block_start(int enabled);
int winn_test_bridge_wait_for_start(void);
void winn_test_bridge_release_blocked_start(void);
void winn_test_bridge_set_corrupt_start_reserved(int enabled);
void winn_test_bridge_set_capture_ordinal(uint64_t ordinal);
void winn_test_bridge_set_capture_identity_mismatch(int enabled);
void winn_test_bridge_set_stop_failure(int enabled);
void winn_test_bridge_set_stop_not_invoked(int enabled);
void winn_test_bridge_set_stop_handle_mismatch(int enabled);
uint64_t winn_test_bridge_secret_release_count(void);
uint64_t winn_test_bridge_abandon_count(void);
uint64_t winn_test_bridge_stop_count(void);
uint64_t winn_test_bridge_destroy_count(void);

#endif
BRIDGE_STUB_HEADER

spike_bridge_stub_c="${spike_test_scratch}/StageBBridgeStub.c"
cat >"${spike_bridge_stub_c}" <<'BRIDGE_STUB_C'
#include "StageBBridgeStub.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t winn_test_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t winn_test_condition = PTHREAD_COND_INITIALIZER;
static int winn_test_create_failure;
static int winn_test_block_start;
static int winn_test_start_entered;
static int winn_test_release_start;
static int winn_test_abandoned;
static int winn_test_corrupt_start_reserved;
static int winn_test_stop_failure;
static int winn_test_stop_not_invoked;
static int winn_test_stop_handle_mismatch;
static int winn_test_capture_identity_mismatch;
static uint64_t winn_test_capture_ordinal;
static uint64_t winn_test_secret_releases;
static uint64_t winn_test_abandons;
static uint64_t winn_test_stops;
static uint64_t winn_test_destroys;
static WinnStageBNativeIdentity winn_test_identity;

static const uint8_t winn_test_peer_sha256[32] = {
  0xde, 0xb0, 0xe3, 0x8c, 0xed, 0x1e, 0x41, 0xde,
  0x6f, 0x92, 0xe7, 0x0e, 0x80, 0xc4, 0x18, 0xd2,
  0xd3, 0x56, 0xaf, 0xaa, 0xa9, 0x9e, 0x26, 0xf5,
  0x93, 0x9d, 0xbc, 0x7d, 0x3e, 0xf4, 0x77, 0x2a
};

static void winn_test_release_secret(
    uint8_t *bytes,
    size_t allocation_size,
    void *context) {
  (void)context;
  memset(bytes, 0, allocation_size);
  free(bytes);
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_secret_releases += 1U;
  pthread_mutex_unlock(&winn_test_mutex);
}

static uint64_t winn_test_read_counter(uint64_t *counter) {
  uint64_t value;
  pthread_mutex_lock(&winn_test_mutex);
  value = *counter;
  pthread_mutex_unlock(&winn_test_mutex);
  return value;
}

void winn_test_bridge_reset(void) {
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_create_failure = 0;
  winn_test_block_start = 0;
  winn_test_start_entered = 0;
  winn_test_release_start = 0;
  winn_test_abandoned = 0;
  winn_test_corrupt_start_reserved = 0;
  winn_test_stop_failure = 0;
  winn_test_stop_not_invoked = 0;
  winn_test_stop_handle_mismatch = 0;
  winn_test_capture_identity_mismatch = 0;
  winn_test_capture_ordinal = 0U;
  winn_test_secret_releases = 0U;
  winn_test_abandons = 0U;
  winn_test_stops = 0U;
  winn_test_destroys = 0U;
  memset(&winn_test_identity, 0, sizeof(winn_test_identity));
  pthread_mutex_unlock(&winn_test_mutex);
}

WinnStageBProviderNativeStart *winn_test_bridge_make_start(
    uint64_t sequence) {
  WinnStageBProviderNativeStart *start =
      calloc(1U, sizeof(*start));
  uint8_t *secret = calloc(16U, 1U);
  size_t index;
  if (start == NULL || secret == NULL) {
    free(start);
    free(secret);
    return NULL;
  }
  for (index = 0U; index < 15U; ++index) {
    secret[index] = (uint8_t)(0x80U + index);
  }
  secret[14] = (uint8_t)'\n';
  secret[15] = 0U;
  memset(start->generation.attempt_nonce, 0x11, 16U);
  start->generation.lifecycle_sequence = sequence;
  start->config.bytes = secret;
  start->config.allocation_size = 16U;
  start->config.buffer_length = 16U;
  start->config.erase_and_release = winn_test_release_secret;
  memset(start->config_sha256, 0x44, 32U);
  memset(start->expected_peer_public_key, 0x33, 32U);
  start->engine_generation = 7U;
  start->path_generation = 8U;
  return start;
}

void winn_test_bridge_release_start(
    WinnStageBProviderNativeStart *start) {
  free(start);
}

void winn_test_bridge_set_create_failure(int enabled) {
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_create_failure = enabled;
  pthread_mutex_unlock(&winn_test_mutex);
}

void winn_test_bridge_set_block_start(int enabled) {
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_block_start = enabled;
  pthread_mutex_unlock(&winn_test_mutex);
}

int winn_test_bridge_wait_for_start(void) {
  struct timespec deadline;
  int result = 0;
  clock_gettime(CLOCK_REALTIME, &deadline);
  deadline.tv_sec += 5;
  pthread_mutex_lock(&winn_test_mutex);
  while (!winn_test_start_entered && result == 0) {
    result = pthread_cond_timedwait(
        &winn_test_condition, &winn_test_mutex, &deadline);
  }
  pthread_mutex_unlock(&winn_test_mutex);
  return result == 0 ? 1 : 0;
}

void winn_test_bridge_release_blocked_start(void) {
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_release_start = 1;
  pthread_cond_broadcast(&winn_test_condition);
  pthread_mutex_unlock(&winn_test_mutex);
}

void winn_test_bridge_set_corrupt_start_reserved(int enabled) {
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_corrupt_start_reserved = enabled;
  pthread_mutex_unlock(&winn_test_mutex);
}

void winn_test_bridge_set_capture_ordinal(uint64_t ordinal) {
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_capture_ordinal = ordinal;
  pthread_mutex_unlock(&winn_test_mutex);
}

void winn_test_bridge_set_capture_identity_mismatch(int enabled) {
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_capture_identity_mismatch = enabled;
  pthread_mutex_unlock(&winn_test_mutex);
}

void winn_test_bridge_set_stop_failure(int enabled) {
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_stop_failure = enabled;
  pthread_mutex_unlock(&winn_test_mutex);
}

void winn_test_bridge_set_stop_not_invoked(int enabled) {
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_stop_not_invoked = enabled;
  pthread_mutex_unlock(&winn_test_mutex);
}

void winn_test_bridge_set_stop_handle_mismatch(int enabled) {
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_stop_handle_mismatch = enabled;
  pthread_mutex_unlock(&winn_test_mutex);
}

uint64_t winn_test_bridge_secret_release_count(void) {
  return winn_test_read_counter(&winn_test_secret_releases);
}
uint64_t winn_test_bridge_abandon_count(void) {
  return winn_test_read_counter(&winn_test_abandons);
}
uint64_t winn_test_bridge_stop_count(void) {
  return winn_test_read_counter(&winn_test_stops);
}
uint64_t winn_test_bridge_destroy_count(void) {
  return winn_test_read_counter(&winn_test_destroys);
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_create(
    WinnStageBProviderNativeOwner *output_owner) {
  int fail;
  pthread_mutex_lock(&winn_test_mutex);
  fail = winn_test_create_failure;
  pthread_mutex_unlock(&winn_test_mutex);
  memset(output_owner, 0, sizeof(*output_owner));
  if (fail) {
    return WINN_STAGE_B_PROVIDER_NATIVE_ENGINE_FAILED;
  }
  output_owner->storage_address = (uintptr_t)0x12340000U;
  output_owner->lifecycle_token = 1U;
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_start(
    const WinnStageBProviderNativeOwner *owner,
    WinnStageBProviderNativeStart *start,
    WinnStageBProviderNativeStartResult *output) {
  WinnStageBProviderOwnedSecretBuffer secret;
  int abandoned;
  (void)owner;
  memset(output, 0, sizeof(*output));
  output->lifecycle_handle = -1;
  secret = start->config;
  memset(&start->config, 0, sizeof(start->config));
  if (secret.bytes != NULL && secret.erase_and_release != NULL) {
    memset(secret.bytes, 0, secret.allocation_size);
    secret.erase_and_release(
        secret.bytes, secret.allocation_size, secret.release_context);
  }
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_start_entered = 1;
  pthread_cond_broadcast(&winn_test_condition);
  while (winn_test_block_start && !winn_test_release_start) {
    pthread_cond_wait(&winn_test_condition, &winn_test_mutex);
  }
  abandoned = winn_test_abandoned;
  pthread_mutex_unlock(&winn_test_mutex);
  if (abandoned) {
    return WINN_STAGE_B_PROVIDER_NATIVE_ABANDONED;
  }
  memset(&winn_test_identity, 0, sizeof(winn_test_identity));
  memset(winn_test_identity.engine_instance_uuid, 0x11, 16U);
  winn_test_identity.engine_instance_uuid[6] = 0x41U;
  winn_test_identity.engine_instance_uuid[8] = 0x81U;
  memset(
      winn_test_identity.winning_interface_token_sha256, 0x22, 32U);
  memcpy(
      winn_test_identity.expected_peer_sha256,
      winn_test_peer_sha256,
      32U);
  memset(winn_test_identity.config_sha256, 0x44, 32U);
  winn_test_identity.engine_generation = 7U;
  winn_test_identity.path_generation = 8U;
  output->identity = winn_test_identity;
  memset(output->signed_runtime_sha256, 0x55, 32U);
  output->lifecycle_handle = 77;
  pthread_mutex_lock(&winn_test_mutex);
  if (winn_test_corrupt_start_reserved) {
    output->reserved[0] = 1U;
  }
  pthread_mutex_unlock(&winn_test_mutex);
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_abandon(
    const WinnStageBProviderNativeOwner *owner,
    const WinnStageBProviderNativeGeneration *generation) {
  (void)owner;
  (void)generation;
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_abandoned = 1;
  winn_test_abandons += 1U;
  pthread_cond_broadcast(&winn_test_condition);
  pthread_mutex_unlock(&winn_test_mutex);
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_capture(
    const WinnStageBProviderNativeOwner *owner,
    const WinnStageBProviderNativeGeneration *generation,
    WinnStageBProviderNativeCapture *output) {
  uint64_t ordinal;
  int identity_mismatch;
  (void)owner;
  (void)generation;
  memset(output, 0, sizeof(*output));
  pthread_mutex_lock(&winn_test_mutex);
  ordinal = winn_test_capture_ordinal;
  identity_mismatch = winn_test_capture_identity_mismatch;
  if (ordinal == 0U) {
    winn_test_capture_ordinal = 1U;
    ordinal = 1U;
  }
  pthread_mutex_unlock(&winn_test_mutex);
  output->capture_ordinal = ordinal;
  output->observation.identity = winn_test_identity;
  if (identity_mismatch) {
    output->observation.identity.path_generation += 1U;
  }
  memset(output->observation.telemetry.peer_public_key, 0x33, 32U);
  output->observation.telemetry.latest_handshake_unix_seconds = 10U;
  output->observation.telemetry.latest_handshake_nanoseconds = 20U;
  output->observation.telemetry.received_bytes = 30U;
  output->observation.telemetry.transmitted_bytes = 40U;
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_stop(
    const WinnStageBProviderNativeOwner *owner,
    const WinnStageBProviderNativeGeneration *generation,
    int32_t expected_handle,
    WinnStageBProviderNativeStopResult *output) {
  int fail;
  int not_invoked;
  int handle_mismatch;
  (void)owner;
  (void)generation;
  memset(output, 0, sizeof(*output));
  output->invocation =
      WINN_STAGE_B_PROVIDER_STOP_VOID_INVOCATION_RETURNED;
  output->lifecycle_handle = expected_handle;
  output->lifecycle_acknowledgement_permitted = 1U;
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_stops += 1U;
  fail = winn_test_stop_failure;
  not_invoked = winn_test_stop_not_invoked;
  handle_mismatch = winn_test_stop_handle_mismatch;
  pthread_mutex_unlock(&winn_test_mutex);
  if (not_invoked) {
    memset(output, 0, sizeof(*output));
    output->lifecycle_handle = -1;
    return WINN_STAGE_B_PROVIDER_NATIVE_STOP_NOT_INVOKED;
  }
  if (handle_mismatch) {
    output->lifecycle_handle = expected_handle + 1;
  }
  if (fail) {
    output->owner_poisoned_after_invocation = 1U;
    return WINN_STAGE_B_PROVIDER_NATIVE_POISONED;
  }
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_state(
    const WinnStageBProviderNativeOwner *owner,
    WinnStageBProviderNativeState *output_state) {
  (void)owner;
  *output_state = WINN_STAGE_B_PROVIDER_NATIVE_STATE_RUNNING;
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}

WinnStageBProviderNativeStatus winn_stage_b_provider_native_owner_destroy(
    WinnStageBProviderNativeOwner *owner) {
  memset(owner, 0, sizeof(*owner));
  pthread_mutex_lock(&winn_test_mutex);
  winn_test_destroys += 1U;
  pthread_mutex_unlock(&winn_test_mutex);
  return WINN_STAGE_B_PROVIDER_NATIVE_OK;
}
BRIDGE_STUB_C

spike_bridge_fixture_swift="${spike_test_scratch}/StageBBridgeFixture.swift"
cat >"${spike_bridge_fixture_swift}" <<'BRIDGE_FIXTURE_SWIFT'
import Foundation
import WinnPrivacyCore
import WinnStageBProviderCore

private final class ResultBox: @unchecked Sendable {
  private let lock = NSLock()
  private var value:
    Result<StageBProviderNativeSession, Error>?

  func set(_ value: Result<StageBProviderNativeSession, Error>) {
    lock.lock()
    self.value = value
    lock.unlock()
  }

  func get() -> Result<StageBProviderNativeSession, Error>? {
    lock.lock()
    defer { lock.unlock() }
    return value
  }
}

private final class Clock: @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64 = 100

  func read() -> UInt64 {
    lock.lock()
    defer { lock.unlock() }
    value += 1
    return value
  }
}

private func makeEnvironment() throws -> StageBProviderEnvironment {
  let clock = Clock()
  return try StageBProviderEnvironment(
    responseReplayCapacity: 8,
    reflectorKey: [UInt8](repeating: 0x66, count: 32),
    monotonicClock: { clock.read() }
  )
}

private let makeBinding:
  @Sendable (StageBAWGEnginePathIdentity) throws
    -> StageBProviderPathBinding = { identity in
  var pathID = [UInt8](repeating: 0x77, count: 16)
  pathID[6] = 0x47
  pathID[8] = 0x87
  return try StageBProviderPathBinding(
    pathID: pathID,
    identity: identity,
    context: WCF3ConnectionContext(
      sessionID: [UInt8](repeating: 0x11, count: 16),
      bindingID: [UInt8](repeating: 0x22, count: 16),
      pskGeneration: 1,
      sequenceEpoch: 1
    )
  )
}

private func awaitStart(
  lifecycle: StageBProviderNativeLifecycle,
  providerQueue: DispatchQueue,
  start: UnsafeMutablePointer<WinnStageBProviderNativeStart>
) throws -> Result<StageBProviderNativeSession, Error> {
  let semaphore = DispatchSemaphore(value: 0)
  let box = ResultBox()
  let environment = try makeEnvironment()
  providerQueue.sync {
    lifecycle.start(
      consumingNativeStart: start,
      environment: environment,
      makeBinding: makeBinding
    ) {
      box.set($0)
      semaphore.signal()
    }
  }
  precondition(
    semaphore.wait(timeout: .now() + 5) == .success,
    "native bridge start timed out"
  )
  return box.get()!
}

private func awaitStop(
  lifecycle: StageBProviderNativeLifecycle,
  providerQueue: DispatchQueue
) {
  let semaphore = DispatchSemaphore(value: 0)
  providerQueue.sync {
    lifecycle.stop {
      semaphore.signal()
    }
  }
  precondition(
    semaphore.wait(timeout: .now() + 5) == .success,
    "native bridge stop timed out"
  )
}

@main
private enum StageBBridgeFixture {
  static func main() throws {
    do {
      winn_test_bridge_reset()
      let queue = DispatchQueue(label: "fixture.provider.success")
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let start = winn_test_bridge_make_start(1)!
      let result = try awaitStart(
        lifecycle: lifecycle,
        providerQueue: queue,
        start: start
      )
      winn_test_bridge_release_start(start)
      guard case let .success(session) = result else {
        preconditionFailure("expected successful native bridge start")
      }
      let sample = try session.capture()
      precondition(sample.peer.receivedBytes == 30)
      precondition(sample.peer.transmittedBytes == 40)
      awaitStop(lifecycle: lifecycle, providerQueue: queue)
      precondition(winn_test_bridge_secret_release_count() == 1)
      precondition(winn_test_bridge_stop_count() == 1)
      precondition(winn_test_bridge_destroy_count() == 1)
    }

    do {
      winn_test_bridge_reset()
      winn_test_bridge_set_create_failure(1)
      let queue = DispatchQueue(label: "fixture.provider.create-fail")
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let start = winn_test_bridge_make_start(2)!
      let result = try awaitStart(
        lifecycle: lifecycle,
        providerQueue: queue,
        start: start
      )
      winn_test_bridge_release_start(start)
      guard case .failure = result else {
        preconditionFailure("owner-create failure was accepted")
      }
      precondition(winn_test_bridge_secret_release_count() == 1)
      precondition(winn_test_bridge_destroy_count() == 0)
    }

    do {
      winn_test_bridge_reset()
      winn_test_bridge_set_corrupt_start_reserved(1)
      let queue = DispatchQueue(label: "fixture.provider.start-invalid")
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let start = winn_test_bridge_make_start(3)!
      let result = try awaitStart(
        lifecycle: lifecycle,
        providerQueue: queue,
        start: start
      )
      winn_test_bridge_release_start(start)
      guard case .failure = result else {
        preconditionFailure("corrupt start reserved byte was accepted")
      }
      precondition(winn_test_bridge_stop_count() == 1)
      precondition(winn_test_bridge_destroy_count() == 1)
    }

    do {
      winn_test_bridge_reset()
      winn_test_bridge_set_block_start(1)
      let queue = DispatchQueue(label: "fixture.provider.abandon")
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let semaphore = DispatchSemaphore(value: 0)
      let box = ResultBox()
      let start = winn_test_bridge_make_start(4)!
      let environment = try makeEnvironment()
      queue.sync {
        lifecycle.start(
          consumingNativeStart: start,
          environment: environment,
          makeBinding: makeBinding
        ) {
          box.set($0)
          semaphore.signal()
        }
      }
      precondition(winn_test_bridge_wait_for_start() == 1)
      queue.sync {
        lifecycle.abandonCurrentStart()
      }
      let abandonDeadline = Date().addingTimeInterval(5)
      while winn_test_bridge_abandon_count() == 0,
            Date() < abandonDeadline {
        Thread.sleep(forTimeInterval: 0.001)
      }
      precondition(winn_test_bridge_abandon_count() == 1)
      winn_test_bridge_release_blocked_start()
      precondition(
        semaphore.wait(timeout: .now() + 5) == .success,
        "native bridge abandon timed out"
      )
      winn_test_bridge_release_start(start)
      guard case .failure = box.get()! else {
        preconditionFailure("abandoned blocking start succeeded")
      }
      precondition(winn_test_bridge_secret_release_count() == 1)
      precondition(winn_test_bridge_destroy_count() == 1)
    }

    do {
      winn_test_bridge_reset()
      winn_test_bridge_set_block_start(1)
      let queue = DispatchQueue(
        label: "fixture.provider.stop-after-publication"
      )
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let startCompletion = DispatchSemaphore(value: 0)
      let stopCompletion = DispatchSemaphore(value: 0)
      let box = ResultBox()
      let start = winn_test_bridge_make_start(40)!
      let environment = try makeEnvironment()
      queue.sync {
        lifecycle.start(
          consumingNativeStart: start,
          environment: environment,
          makeBinding: makeBinding
        ) {
          box.set($0)
          startCompletion.signal()
        }
      }
      precondition(winn_test_bridge_wait_for_start() == 1)
      // Drain the provider queue so Pending is deterministically published
      // before stop invalidates its authority.
      queue.sync {}
      queue.sync {
        lifecycle.stop {
          stopCompletion.signal()
        }
      }
      precondition(
        stopCompletion.wait(timeout: .now() + 0.05) == .timedOut,
        "published-pending stop completed while native start was blocked"
      )
      let abandonDeadline = Date().addingTimeInterval(5)
      while winn_test_bridge_abandon_count() == 0,
            Date() < abandonDeadline {
        Thread.sleep(forTimeInterval: 0.001)
      }
      precondition(winn_test_bridge_abandon_count() == 1)
      winn_test_bridge_release_blocked_start()
      precondition(
        startCompletion.wait(timeout: .now() + 5) == .success,
        "published-pending start completion timed out"
      )
      precondition(
        stopCompletion.wait(timeout: .now() + 5) == .success,
        "published-pending stop cleanup barrier timed out"
      )
      precondition(
        stopCompletion.wait(timeout: .now() + 0.05) == .timedOut,
        "published-pending stop completion was signaled twice"
      )
      winn_test_bridge_release_start(start)
      guard case .failure = box.get()! else {
        preconditionFailure("published-pending stop admitted start")
      }
      precondition(winn_test_bridge_secret_release_count() == 1)
      precondition(winn_test_bridge_stop_count() == 0)
      precondition(winn_test_bridge_destroy_count() == 1)
    }

    do {
      winn_test_bridge_reset()
      winn_test_bridge_set_block_start(1)
      let queue = DispatchQueue(
        label: "fixture.provider.stop-before-publication"
      )
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let startCompletion = DispatchSemaphore(value: 0)
      let stopCompletion = DispatchSemaphore(value: 0)
      let box = ResultBox()
      let start = winn_test_bridge_make_start(41)!
      let environment = try makeEnvironment()
      queue.sync {
        lifecycle.start(
          consumingNativeStart: start,
          environment: environment,
          makeBinding: makeBinding
        ) {
          box.set($0)
          startCompletion.signal()
        }
        lifecycle.stop {
          stopCompletion.signal()
        }
      }
      precondition(winn_test_bridge_wait_for_start() == 1)
      precondition(
        stopCompletion.wait(timeout: .now() + 0.05) == .timedOut,
        "pre-publication stop completed while native start was blocked"
      )
      let abandonDeadline = Date().addingTimeInterval(5)
      while winn_test_bridge_abandon_count() == 0,
            Date() < abandonDeadline {
        Thread.sleep(forTimeInterval: 0.001)
      }
      precondition(winn_test_bridge_abandon_count() == 1)
      winn_test_bridge_release_blocked_start()
      precondition(
        startCompletion.wait(timeout: .now() + 5) == .success,
        "pre-publication start completion timed out"
      )
      precondition(
        stopCompletion.wait(timeout: .now() + 5) == .success,
        "pre-publication stop cleanup barrier timed out"
      )
      precondition(
        stopCompletion.wait(timeout: .now() + 0.05) == .timedOut,
        "pre-publication stop completion was signaled twice"
      )
      winn_test_bridge_release_start(start)
      guard case .failure = box.get()! else {
        preconditionFailure("pre-publication stop admitted start")
      }
      precondition(winn_test_bridge_secret_release_count() == 1)
      precondition(winn_test_bridge_stop_count() == 0)
      precondition(winn_test_bridge_destroy_count() == 1)
    }

    do {
      winn_test_bridge_reset()
      let queue = DispatchQueue(label: "fixture.provider.ordinal")
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let start = winn_test_bridge_make_start(5)!
      let result = try awaitStart(
        lifecycle: lifecycle,
        providerQueue: queue,
        start: start
      )
      winn_test_bridge_release_start(start)
      guard case let .success(session) = result else {
        preconditionFailure("ordinal fixture start failed")
      }
      winn_test_bridge_set_capture_ordinal(2)
      do {
        _ = try session.capture()
        preconditionFailure("wrong capture ordinal was accepted")
      } catch {
        // Expected.
      }
      awaitStop(lifecycle: lifecycle, providerQueue: queue)
      precondition(winn_test_bridge_stop_count() == 1)
    }

    do {
      winn_test_bridge_reset()
      let queue = DispatchQueue(label: "fixture.provider.capture-identity")
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let start = winn_test_bridge_make_start(51)!
      let result = try awaitStart(
        lifecycle: lifecycle,
        providerQueue: queue,
        start: start
      )
      winn_test_bridge_release_start(start)
      guard case let .success(session) = result else {
        preconditionFailure("identity fixture start failed")
      }
      winn_test_bridge_set_capture_identity_mismatch(1)
      do {
        _ = try session.capture()
        preconditionFailure("mismatched native identity was accepted")
      } catch {
        // Expected.
      }
      awaitStop(lifecycle: lifecycle, providerQueue: queue)
      precondition(winn_test_bridge_stop_count() == 1)
    }

    do {
      winn_test_bridge_reset()
      let queue = DispatchQueue(label: "fixture.provider.stop-handle")
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let start = winn_test_bridge_make_start(52)!
      let result = try awaitStart(
        lifecycle: lifecycle,
        providerQueue: queue,
        start: start
      )
      winn_test_bridge_release_start(start)
      guard case .success = result else {
        preconditionFailure("stop-handle fixture start failed")
      }
      winn_test_bridge_set_stop_handle_mismatch(1)
      awaitStop(lifecycle: lifecycle, providerQueue: queue)
      precondition(winn_test_bridge_stop_count() == 1)
      precondition(winn_test_bridge_destroy_count() == 0)
    }

    do {
      winn_test_bridge_reset()
      let queue = DispatchQueue(label: "fixture.provider.stop-fail")
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let start = winn_test_bridge_make_start(6)!
      let result = try awaitStart(
        lifecycle: lifecycle,
        providerQueue: queue,
        start: start
      )
      winn_test_bridge_release_start(start)
      guard case .success = result else {
        preconditionFailure("stop-failure fixture start failed")
      }
      winn_test_bridge_set_stop_failure(1)
      awaitStop(lifecycle: lifecycle, providerQueue: queue)
      precondition(winn_test_bridge_stop_count() == 1)
      precondition(winn_test_bridge_destroy_count() == 0)
    }

    do {
      winn_test_bridge_reset()
      let queue = DispatchQueue(label: "fixture.provider.stop-not-invoked")
      let lifecycle = StageBProviderNativeLifecycle(
        providerQueue: queue
      )
      let start = winn_test_bridge_make_start(7)!
      let result = try awaitStart(
        lifecycle: lifecycle,
        providerQueue: queue,
        start: start
      )
      winn_test_bridge_release_start(start)
      guard case .success = result else {
        preconditionFailure("not-invoked fixture start failed")
      }
      winn_test_bridge_set_stop_not_invoked(1)
      awaitStop(lifecycle: lifecycle, providerQueue: queue)
      precondition(winn_test_bridge_stop_count() == 1)
      precondition(winn_test_bridge_destroy_count() == 0)

      // STOP_NOT_INVOKED deliberately wedges this lifecycle until extension
      // exit.  It must not retry stop, destroy, or admit a replacement owner.
      let replacement = winn_test_bridge_make_start(8)!
      let replacementResult = try awaitStart(
        lifecycle: lifecycle,
        providerQueue: queue,
        start: replacement
      )
      winn_test_bridge_release_start(replacement)
      guard case .failure = replacementResult else {
        preconditionFailure("wedged lifecycle admitted a replacement")
      }
      precondition(winn_test_bridge_stop_count() == 1)
      precondition(winn_test_bridge_destroy_count() == 0)
      precondition(winn_test_bridge_secret_release_count() == 2)
    }

    print("WINN_STAGEB_PROVIDER_NATIVE_BRIDGE_FIXTURE_PASS")
  }
}
BRIDGE_FIXTURE_SWIFT

spike_bridge_module_dir="${spike_test_scratch}/bridge-modules"
mkdir -p "${spike_bridge_module_dir}"
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  -emit-module \
  -emit-library \
  -module-name WinnPrivacyCore \
  "${spike_test_root}"/PrivacyCore/Sources/WinnPrivacyCore/*.swift \
  -emit-module-path \
  "${spike_bridge_module_dir}/WinnPrivacyCore.swiftmodule" \
  -o "${spike_bridge_module_dir}/libWinnPrivacyCore.dylib"
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  -emit-module \
  -emit-library \
  -module-name WinnStageBProviderCore \
  -I "${spike_bridge_module_dir}" \
  -L "${spike_bridge_module_dir}" \
  -lWinnPrivacyCore \
  "${spike_test_root}"/PrivacyCore/Sources/WinnStageBProviderCore/*.swift \
  -emit-module-path \
  "${spike_bridge_module_dir}/WinnStageBProviderCore.swiftmodule" \
  -o "${spike_bridge_module_dir}/libWinnStageBProviderCore.dylib"
xcrun clang \
  -std=c11 \
  -Wall \
  -Wextra \
  -Wpedantic \
  -Werror \
  -I "${spike_test_root}/PacketTunnel" \
  -I "${spike_test_root}/NativeEngine" \
  -I "${spike_test_scratch}" \
  -c "${spike_bridge_stub_c}" \
  -o "${spike_test_scratch}/StageBBridgeStub.o"
xcrun swiftc \
  -swift-version 5 \
  -warnings-as-errors \
  -parse-as-library \
  -I "${spike_bridge_module_dir}" \
  -L "${spike_bridge_module_dir}" \
  -lWinnPrivacyCore \
  -lWinnStageBProviderCore \
  -import-objc-header "${spike_bridge_stub_header}" \
  -Xcc -I"${spike_test_root}/PacketTunnel" \
  -Xcc -I"${spike_test_root}/NativeEngine" \
  -Xcc -I"${spike_test_scratch}" \
  "${spike_test_root}/PacketTunnel/StageBProviderNativeAdapterSeam.swift" \
  "${spike_bridge_fixture_swift}" \
  "${spike_test_scratch}/StageBBridgeStub.o" \
  -Xlinker -rpath \
  -Xlinker "${spike_bridge_module_dir}" \
  -o "${spike_test_scratch}/stageb-provider-native-bridge-fixture"
spike_test_checks=$((spike_test_checks + 1))
"${spike_test_scratch}/stageb-provider-native-bridge-fixture" \
  | grep -Fqx 'WINN_STAGEB_PROVIDER_NATIVE_BRIDGE_FIXTURE_PASS' ||
  spike_test_note_failure "the focused Swift/C bridge fixture failed."

test "${spike_test_failures}" -eq 0 || {
  printf 'FAIL: %s of %s project integration checks failed.\n' \
    "${spike_test_failures}" "${spike_test_checks}" >&2
  exit 1
}
printf 'WINN_STAGEB_ENGINE_BUILD_PROJECT_INTEGRATION_PASS checks=%s\n' \
  "${spike_test_checks}"
