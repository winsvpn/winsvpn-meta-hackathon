#!/bin/sh
set -eu

# Two-build fixture for the Stage B engine runtime-pin phase.
#
# The project, embed, and provenance fixtures never invoke xcodebuild; this one
# must, because the property under test is what Xcode actually does across an
# INCREMENTAL rebuild. Xcode does not promise to delete a script phase's
# declared outputs before rerunning it, so a manifest writer that refuses to
# touch an existing output would build once and then fail every subsequent
# valid build. That is not something to reason about -- it is something to run.
#
# Six builds against one persistent derived-data path:
#
#   1. clean build                      -> manifest created, exact bytes
#   2. rerun after the input changes     -> must still succeed (regression
#                                           guard for the noclobber failure)
#   3. rerun with foreign bytes planted  -> must succeed AND replace them,
#                                           proving the phase adopts nothing
#   4. rerun with a symlink planted      -> must FAIL closed, and must not
#                                           write through the link
#   5. rerun with a directory planted    -> must FAIL closed, leaving its
#                                           contents untouched
#   6. rerun with a hard link planted    -> must replace only the declared
#                                           path, never mutate/adopt its peer
#
# Cases 3 through 6 pin the intended boundary: replace a plain file inside the
# build's own declared output path, refuse anything else, never read what was
# there, and unlink rather than write through a hard-linked regular file.
#
# Signing is disabled here, so this fixture proves nothing about sealing.

spike_test_script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
spike_test_root="$(CDPATH='' cd -- "${spike_test_script_dir}/.." && pwd)"
spike_test_manifest_leaf="WinnStageBEngineRuntimePin.manifest"

spike_test_scratch="$(
  CDPATH='' cd -- "$(
    mktemp -d "${TMPDIR:-/tmp}/winn-stageb-pin-rebuild.XXXXXX"
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

spike_test_derived="${spike_test_scratch}/DerivedData"
mkdir "${spike_test_derived}"
spike_test_engine_dir="${spike_test_scratch}/StageBEngine"
mkdir "${spike_test_engine_dir}"

spike_test_receipt="$(
  "${spike_test_script_dir}/stage_stageb_engine_artifact.sh" \
    iphonesimulator "${spike_test_engine_dir}"
)" || {
  echo "FAIL: the engine stager failed; this fixture cannot run." >&2
  exit 1
}
spike_test_source_sha="$(
  printf '%s' "${spike_test_receipt}" |
    ruby -rjson -e 'puts JSON.parse(STDIN.read).fetch("source_binary_sha256")'
)"
spike_test_staged_engine="${spike_test_engine_dir}/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"
spike_test_app="${spike_test_derived}/Build/Products/Debug-iphonesimulator/WCF3 Privacy Spike.app"
spike_test_manifest="${spike_test_app}/${spike_test_manifest_leaf}"

# Reruns the pin phase by making its declared input newer. Touching the staged
# engine reruns the copy phase, which rewrites the embedded engine, which is
# the phase's declared input.
spike_test_touch_input() {
  touch -m "${spike_test_staged_engine}"
}

spike_test_build() {
  spike_build_log="$1"
  xcodebuild \
    -project "${spike_test_root}/PrivacySpike.xcodeproj" \
    -scheme PrivacySpike \
    -configuration Debug \
    -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "${spike_test_derived}" \
    ARCHS=arm64 \
    ONLY_ACTIVE_ARCH=NO \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_IDENTITY= \
    CODE_SIGN_ENTITLEMENTS= \
    WINN_STAGEB_ENGINE_DIR="${spike_test_engine_dir}" \
    WINN_STAGEB_ENGINE_SOURCE_SHA256="${spike_test_source_sha}" \
    WINN_SPIKE_SOURCE_DIGEST=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    build >"${spike_build_log}" 2>&1
}

# The manifest the phase should have produced, rebuilt here from the embedded
# engine rather than copied from the file under test.
spike_test_expected_manifest() {
  spike_expected_path="$1"
  spike_expected_engine="${spike_test_app}/Frameworks/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"
  spike_expected_runtime="$(
    shasum -a 256 "${spike_expected_engine}" | awk '{ print $1 }'
  )"
  printf '%s\n' \
    'schema=winn-stageb-engine-runtime-pin/1' \
    "source_binary_sha256=${spike_test_source_sha}" \
    "signed_runtime_binary_sha256=${spike_expected_runtime}" \
    'relative_path=Frameworks/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine' \
    'platform=iphonesimulator' \
    'architectures=arm64,x86_64' \
    'install_name=@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine' \
    >"${spike_expected_path}"
}

spike_test_assert_manifest_correct() {
  spike_assert_label="$1"
  spike_test_checks=$((spike_test_checks + 1))
  if test -L "${spike_test_manifest}" || test ! -f "${spike_test_manifest}"
  then
    spike_test_note_failure \
      "${spike_assert_label}: the manifest is not a regular file."
    return 0
  fi
  spike_assert_links="$(stat -f '%l' "${spike_test_manifest}")"
  test "${spike_assert_links}" = "1" ||
    spike_test_note_failure \
      "${spike_assert_label}: the manifest has ${spike_assert_links} hard links."
  spike_test_expected_manifest "${spike_test_scratch}/expected"
  cmp -s "${spike_test_scratch}/expected" "${spike_test_manifest}" || {
    spike_test_note_failure \
      "${spike_assert_label}: the manifest is not the exact expected bytes."
    diff "${spike_test_scratch}/expected" "${spike_test_manifest}" >&2 || true
  }
}

# --- 1. clean build --------------------------------------------------------
spike_test_checks=$((spike_test_checks + 1))
spike_test_build "${spike_test_scratch}/build1.log" || {
  spike_test_note_failure "the clean build failed."
  tail -20 "${spike_test_scratch}/build1.log" >&2
  exit 1
}
spike_test_assert_manifest_correct clean-build

# --- 2. incremental rerun --------------------------------------------------
# This is the regression guard. Before the replacement policy existed, this
# build failed with "cannot overwrite existing file" and exit 65.
spike_test_touch_input
spike_test_checks=$((spike_test_checks + 1))
if spike_test_build "${spike_test_scratch}/build2.log"; then
  spike_test_assert_manifest_correct incremental-rebuild
else
  spike_test_note_failure \
    "the incremental rebuild failed; a stale declared output must not wedge the build."
  grep -F 'cannot overwrite existing file' \
    "${spike_test_scratch}/build2.log" >&2 || true
fi

# --- 3. foreign bytes must be replaced, never adopted ---------------------
rm -f "${spike_test_manifest}"
printf 'schema=winn-stageb-engine-runtime-pin/1\nsource_binary_sha256=%064d\n' 0 \
  >"${spike_test_manifest}"
spike_test_touch_input
spike_test_checks=$((spike_test_checks + 1))
if spike_test_build "${spike_test_scratch}/build3.log"; then
  spike_test_assert_manifest_correct foreign-bytes-replaced
else
  spike_test_note_failure \
    "the build refused to replace a plain file it owns in its own output path."
fi

# --- 4. a planted symlink must fail closed and not be followed -----------
rm -f "${spike_test_manifest}"
: >"${spike_test_scratch}/decoy"
ln -s "${spike_test_scratch}/decoy" "${spike_test_manifest}"
spike_test_touch_input
spike_test_checks=$((spike_test_checks + 1))
if spike_test_build "${spike_test_scratch}/build4.log"; then
  spike_test_note_failure \
    "the build accepted a symlink at the runtime pin path."
else
  grep -Fq 'refusing to replace a non-regular runtime pin' \
    "${spike_test_scratch}/build4.log" ||
    spike_test_note_failure \
      "the symlinked build failed for the wrong reason."
fi
spike_test_checks=$((spike_test_checks + 1))
spike_test_decoy_size="$(stat -f '%z' "${spike_test_scratch}/decoy")"
test "${spike_test_decoy_size}" = "0" ||
  spike_test_note_failure \
    "the phase wrote ${spike_test_decoy_size} bytes through the symlink."

# --- 5. a planted directory must fail closed and remain untouched --------
rm -f "${spike_test_manifest}"
mkdir "${spike_test_manifest}"
printf '%s\n' 'directory-sentinel' \
  >"${spike_test_manifest}/sentinel"
spike_test_touch_input
spike_test_checks=$((spike_test_checks + 1))
if spike_test_build "${spike_test_scratch}/build5.log"; then
  spike_test_note_failure \
    "the build accepted a directory at the runtime pin path."
else
  grep -Fq 'refusing to replace a non-regular runtime pin' \
    "${spike_test_scratch}/build5.log" ||
    spike_test_note_failure \
      "the directory-planted build failed for the wrong reason."
fi
spike_test_checks=$((spike_test_checks + 1))
test "$(cat "${spike_test_manifest}/sentinel")" = 'directory-sentinel' ||
  spike_test_note_failure \
    "the phase changed content inside the planted directory."

# --- 6. a hard-linked regular file is unlinked, never written through ----
rm -R "${spike_test_manifest}"
printf '%s\n' 'hardlink-peer-sentinel' \
  >"${spike_test_scratch}/hardlink-peer"
ln "${spike_test_scratch}/hardlink-peer" "${spike_test_manifest}"
spike_test_touch_input
spike_test_checks=$((spike_test_checks + 1))
if spike_test_build "${spike_test_scratch}/build6.log"; then
  spike_test_assert_manifest_correct hardlink-replaced
else
  spike_test_note_failure \
    "the build failed to replace a hard-linked plain file at its output path."
fi
spike_test_checks=$((spike_test_checks + 1))
test "$(cat "${spike_test_scratch}/hardlink-peer")" = \
  'hardlink-peer-sentinel' ||
  spike_test_note_failure \
    "the phase wrote through the hard link into its peer."
spike_test_checks=$((spike_test_checks + 1))
test "$(stat -f '%l' "${spike_test_scratch}/hardlink-peer")" = "1" ||
  spike_test_note_failure \
    "the replaced manifest remains linked to the planted peer."

test "${spike_test_failures}" -eq 0 || {
  printf 'FAIL: %s of %s runtime pin rebuild checks failed.\n' \
    "${spike_test_failures}" "${spike_test_checks}" >&2
  exit 1
}
printf 'WINN_STAGEB_ENGINE_BUILD_PIN_REBUILD_PASS checks=%s\n' \
  "${spike_test_checks}"
