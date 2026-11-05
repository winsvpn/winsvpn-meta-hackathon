#!/bin/sh
set -eu

# Deterministic negative fixtures for the Stage B engine embed verifier.
#
# The functions under test are extracted verbatim from the real build scripts,
# never reimplemented here. The app trees they run against are built by this
# fixture with mkdir/cp/clang, NOT by the production code. Every negative case
# is paired with a positive control on the same tree before its single
# mutation, so a verifier that always failed would be caught just as surely as
# one that always passed.
#
# Nothing here builds an app, signs anything, or runs anything on a device. It
# does not depend on Xcode having produced a product, on the engine stager
# succeeding, or on any physical hardware.

spike_test_script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
spike_test_device="${spike_test_script_dir}/build_device.sh"
spike_test_simulator="${spike_test_script_dir}/build_simulator.sh"

spike_test_scratch="$(
  CDPATH='' cd -- "$(
    mktemp -d "${TMPDIR:-/tmp}/winn-stageb-embed-faults.XXXXXX"
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

spike_test_extract_shared() {
  awk '
    /^# BEGIN spike_stageb_engine_shared$/ { emit = 1 }
    emit { print }
    /^# END spike_stageb_engine_shared$/ { emit = 0 }
  ' "$1"
}

# ---------------------------------------------------------------------------
# The two build lanes must carry the identical verifier. A fix applied to one
# lane and not the other is exactly the drift this check exists to catch.
# ---------------------------------------------------------------------------
spike_test_extract_shared "${spike_test_device}" \
  >"${spike_test_scratch}/device-shared.sh"
spike_test_extract_shared "${spike_test_simulator}" \
  >"${spike_test_scratch}/simulator-shared.sh"
test -s "${spike_test_scratch}/device-shared.sh" || {
  echo "FAIL: build_device.sh has no shared engine verifier block." >&2
  exit 1
}
test -s "${spike_test_scratch}/simulator-shared.sh" || {
  echo "FAIL: build_simulator.sh has no shared engine verifier block." >&2
  exit 1
}
cmp -s \
  "${spike_test_scratch}/device-shared.sh" \
  "${spike_test_scratch}/simulator-shared.sh" || {
  echo "FAIL: the device and simulator engine verifiers have diverged." >&2
  exit 1
}

# Load the verifier exactly as the build lanes define it.
# shellcheck source=/dev/null
. "${spike_test_scratch}/device-shared.sh"

# ---------------------------------------------------------------------------
# Synthetic Mach-O fixtures. These are real Mach-O files so file(1), lipo,
# vtool, otool and nm have something genuine to read. They are NOT the pinned
# engine artifact and carry no provenance claim.
# ---------------------------------------------------------------------------
cat >"${spike_test_scratch}/engine.c" <<'ENGINE'
int wins_amneziawg_packet_engine_contract_version(void) { return 1; }
ENGINE
cat >"${spike_test_scratch}/engine_alt.c" <<'ENGINE_ALT'
int wins_amneziawg_packet_engine_contract_version(void) { return 1; }
int wins_amneziawg_packet_engine_extra_symbol(void) { return 2; }
ENGINE_ALT
cat >"${spike_test_scratch}/provider.c" <<'PROVIDER'
int main(void) { return 0; }
PROVIDER

# Builds a universal arm64+x86_64 simulator dylib at $1 from source $3 with
# install name $2.
spike_test_build_engine() {
  spike_build_output="$1"
  spike_build_install_name="$2"
  spike_build_source="$3"
  xcrun --sdk iphonesimulator clang \
    -target arm64-apple-ios14.0-simulator -dynamiclib \
    -install_name "${spike_build_install_name}" \
    -o "${spike_build_output}.arm64" "${spike_build_source}"
  xcrun --sdk iphonesimulator clang \
    -target x86_64-apple-ios13.0-simulator -dynamiclib \
    -install_name "${spike_build_install_name}" \
    -o "${spike_build_output}.x86_64" "${spike_build_source}"
  xcrun lipo -create \
    "${spike_build_output}.arm64" "${spike_build_output}.x86_64" \
    -output "${spike_build_output}"
  rm -f "${spike_build_output}.arm64" "${spike_build_output}.x86_64"
}

# A valid app tree: one framework at App.app/Frameworks, a provider executable
# with no engine load command.
spike_test_make_app() {
  spike_make_app="$1"
  mkdir -p \
    "${spike_make_app}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}" \
    "${spike_make_app}/PlugIns/Provider.appex"
  spike_test_build_engine \
    "${spike_make_app}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}/${WINN_ENGINE_BINARY_NAME}" \
    "${WINN_ENGINE_INSTALL_NAME}" \
    "${spike_test_scratch}/engine.c"
  xcrun --sdk iphonesimulator clang \
    -target arm64-apple-ios14.0-simulator \
    -o "${spike_make_app}/PlugIns/Provider.appex/Provider" \
    "${spike_test_scratch}/provider.c"
}

spike_test_embed_check() {
  spike_check_app="$1"
  spike_assert_single_embedded_engine \
    "${spike_check_app}" \
    "${spike_check_app}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}"
}

# Runs $1 (a shell function name) with remaining args, expecting success.
spike_test_expect_pass() {
  spike_pass_label="$1"
  shift
  spike_test_checks=$((spike_test_checks + 1))
  "$@" >"${spike_test_scratch}/pass.out" \
    2>"${spike_test_scratch}/pass.err" || {
    spike_test_note_failure "${spike_pass_label}: a valid input was rejected."
    cat "${spike_test_scratch}/pass.err" >&2
  }
}

# Runs a check expecting refusal with a specific message. A different message
# means the input broke for an unrelated reason and the case proves nothing.
spike_test_expect_refusal() {
  spike_case_label="$1"
  spike_case_expected="$2"
  shift 2
  spike_test_checks=$((spike_test_checks + 1))
  if "$@" >"${spike_test_scratch}/case.out" \
    2>"${spike_test_scratch}/case.err"
  then
    spike_test_note_failure "${spike_case_label}: a mutated input was accepted."
    return 0
  fi
  grep -Fq "${spike_case_expected}" "${spike_test_scratch}/case.err" || {
    spike_test_note_failure "${spike_case_label}: wrong refusal reason."
    echo "  expected: ${spike_case_expected}" >&2
    echo "  actual:   $(head -3 "${spike_test_scratch}/case.err")" >&2
  }
}

# --- single-copy assertions ----------------------------------------------
spike_test_baseline="${spike_test_scratch}/Baseline.app"
spike_test_make_app "${spike_test_baseline}"
spike_test_expect_pass baseline spike_test_embed_check "${spike_test_baseline}"

spike_test_missing="${spike_test_scratch}/Missing.app"
spike_test_make_app "${spike_test_missing}"
spike_test_expect_pass missing-precondition \
  spike_test_embed_check "${spike_test_missing}"
rm -R "${spike_test_missing}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}"
spike_test_expect_refusal missing-framework \
  'FAIL: no embedded engine framework copy was produced.' \
  spike_test_embed_check "${spike_test_missing}"

spike_test_duplicate="${spike_test_scratch}/Duplicate.app"
spike_test_make_app "${spike_test_duplicate}"
spike_test_expect_pass duplicate-precondition \
  spike_test_embed_check "${spike_test_duplicate}"
mkdir -p "${spike_test_duplicate}/PlugIns/Provider.appex/Frameworks"
cp -R \
  "${spike_test_duplicate}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}" \
  "${spike_test_duplicate}/PlugIns/Provider.appex/Frameworks/"
spike_test_expect_refusal extension-local-duplicate \
  'FAIL: 2 embedded engine framework copies exist' \
  spike_test_embed_check "${spike_test_duplicate}"

# Ten copies is the case a "*0" shell glob over a padded count would have
# accepted as zero.
spike_test_ten="${spike_test_scratch}/Ten.app"
spike_test_make_app "${spike_test_ten}"
spike_test_expect_pass ten-precondition \
  spike_test_embed_check "${spike_test_ten}"
spike_test_copy=1
while test "${spike_test_copy}" -le 9; do
  mkdir -p "${spike_test_ten}/Extra${spike_test_copy}"
  cp -R \
    "${spike_test_ten}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}" \
    "${spike_test_ten}/Extra${spike_test_copy}/"
  spike_test_copy=$((spike_test_copy + 1))
done
spike_test_expect_refusal ten-framework-copies \
  'FAIL: 10 embedded engine framework copies exist' \
  spike_test_embed_check "${spike_test_ten}"

spike_test_hollow="${spike_test_scratch}/Hollow.app"
spike_test_make_app "${spike_test_hollow}"
spike_test_expect_pass hollow-precondition \
  spike_test_embed_check "${spike_test_hollow}"
rm -f \
  "${spike_test_hollow}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}/${WINN_ENGINE_BINARY_NAME}"
spike_test_expect_refusal missing-engine-binary \
  'FAIL: no embedded engine executable was produced.' \
  spike_test_embed_check "${spike_test_hollow}"

spike_test_stray="${spike_test_scratch}/Stray.app"
spike_test_make_app "${spike_test_stray}"
spike_test_expect_pass stray-precondition \
  spike_test_embed_check "${spike_test_stray}"
cp \
  "${spike_test_stray}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}/${WINN_ENGINE_BINARY_NAME}" \
  "${spike_test_stray}/PlugIns/Provider.appex/${WINN_ENGINE_BINARY_NAME}"
spike_test_expect_refusal stray-engine-binary \
  'FAIL: 2 embedded engine executables exist' \
  spike_test_embed_check "${spike_test_stray}"

spike_test_link="${spike_test_scratch}/Link.app"
spike_test_make_app "${spike_test_link}"
spike_test_expect_pass symlink-precondition \
  spike_test_embed_check "${spike_test_link}"
ln -s \
  "${spike_test_link}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}" \
  "${spike_test_link}/PlugIns/Provider.appex/${WINN_ENGINE_FRAMEWORK_NAME}"
spike_test_expect_refusal symlink-alias \
  'FAIL: a symlink aliases the embedded engine.' \
  spike_test_embed_check "${spike_test_link}"

# A plain file wearing the bundle name: the -type d search must not count it,
# and the run must still refuse rather than silently accept zero directories.
spike_test_notdir="${spike_test_scratch}/NotDir.app"
spike_test_make_app "${spike_test_notdir}"
spike_test_expect_pass notdir-precondition \
  spike_test_embed_check "${spike_test_notdir}"
rm -R "${spike_test_notdir}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}"
: >"${spike_test_notdir}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}"
spike_test_expect_refusal framework-not-a-directory \
  'FAIL: no embedded engine framework copy was produced.' \
  spike_test_embed_check "${spike_test_notdir}"

# --- no-preload assertions ------------------------------------------------
spike_test_clean_provider="${spike_test_baseline}/PlugIns/Provider.appex/Provider"
spike_test_expect_pass provider-clean \
  spike_assert_no_engine_preload "${spike_test_clean_provider}" "the provider"

spike_test_linked="${spike_test_scratch}/Linked.app"
spike_test_make_app "${spike_test_linked}"
spike_test_expect_pass linked-precondition \
  spike_assert_no_engine_preload \
  "${spike_test_linked}/PlugIns/Provider.appex/Provider" "the provider"
xcrun --sdk iphonesimulator clang \
  -target arm64-apple-ios14.0-simulator \
  -o "${spike_test_linked}/PlugIns/Provider.appex/Provider" \
  "${spike_test_scratch}/provider.c" \
  "${spike_test_linked}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}/${WINN_ENGINE_BINARY_NAME}"
spike_test_expect_refusal provider-links-engine \
  'load-time dependencies naming the engine' \
  spike_assert_no_engine_preload \
  "${spike_test_linked}/PlugIns/Provider.appex/Provider" "the provider"

spike_test_rpath="${spike_test_scratch}/Rpath.app"
spike_test_make_app "${spike_test_rpath}"
xcrun --sdk iphonesimulator clang \
  -target arm64-apple-ios14.0-simulator \
  -o "${spike_test_rpath}/PlugIns/Provider.appex/Provider" \
  "${spike_test_scratch}/provider.c" \
  -Wl,-rpath,'@executable_path/../../Frameworks'
spike_test_expect_refusal provider-has-containing-app-rpath \
  'runpath resolving to the containing app Frameworks directory' \
  spike_assert_no_engine_preload \
  "${spike_test_rpath}/PlugIns/Provider.appex/Provider" "the provider"

# --- identity continuity --------------------------------------------------
spike_test_source_engine="${spike_test_scratch}/source-engine"
spike_test_build_engine "${spike_test_source_engine}" \
  "${WINN_ENGINE_INSTALL_NAME}" "${spike_test_scratch}/engine.c"
spike_test_same_engine="${spike_test_scratch}/same-engine"
spike_test_build_engine "${spike_test_same_engine}" \
  "${WINN_ENGINE_INSTALL_NAME}" "${spike_test_scratch}/engine.c"
spike_test_expect_pass identity-same-inputs \
  spike_assert_engine_identity_continuity \
  "${spike_test_source_engine}" "${spike_test_same_engine}"

spike_test_alt_symbols="${spike_test_scratch}/alt-symbols-engine"
spike_test_build_engine "${spike_test_alt_symbols}" \
  "${WINN_ENGINE_INSTALL_NAME}" "${spike_test_scratch}/engine_alt.c"
spike_test_expect_refusal identity-symbol-set-changed \
  'slice identity differs from the pinned source' \
  spike_assert_engine_identity_continuity \
  "${spike_test_source_engine}" "${spike_test_alt_symbols}"

spike_test_alt_name="${spike_test_scratch}/alt-name-engine"
spike_test_build_engine "${spike_test_alt_name}" \
  '@rpath/Wrong.framework/Wrong' "${spike_test_scratch}/engine.c"
spike_test_expect_refusal identity-install-name-changed \
  'slice identity differs from the pinned source' \
  spike_assert_engine_identity_continuity \
  "${spike_test_source_engine}" "${spike_test_alt_name}"

xcrun lipo "${spike_test_source_engine}" -thin arm64 \
  -output "${spike_test_scratch}/thin-source"
spike_test_expect_refusal identity-runtime-arch-not-in-source \
  'absent from the pinned source' \
  spike_assert_engine_identity_continuity \
  "${spike_test_scratch}/thin-source" "${spike_test_source_engine}"

# --- app-sealed runtime pin manifest --------------------------------------
# The loader parses the manifest with a whole-file sscanf plus %n, so anything
# other than the exact seven LF-terminated lines is rejected on device. These
# cases build a real manifest beside a real embedded engine and mutate one
# thing at a time.
spike_test_pin_app="${spike_test_scratch}/Pin.app"
spike_test_make_app "${spike_test_pin_app}"
spike_test_pin_engine="${spike_test_pin_app}/Frameworks/${WINN_ENGINE_FRAMEWORK_NAME}/${WINN_ENGINE_BINARY_NAME}"
spike_test_pin_manifest="${spike_test_pin_app}/${WINN_ENGINE_RUNTIME_PIN_MANIFEST}"
spike_test_pin_source='00a17dfd702dc0490efd4f39bc2259fcc38fa4eed8311885499b5f1611713fa3'
spike_test_pin_runtime="$(shasum -a 256 "${spike_test_pin_engine}" | awk '{print $1}')"

# Writes a canonical manifest, then applies an optional sed program to mutate
# exactly one aspect of it.
spike_test_write_pin() {
  spike_write_source="$1"
  spike_write_runtime="$2"
  spike_write_platform="$3"
  spike_write_arches="$4"
  rm -f "${spike_test_pin_manifest}"
  printf '%s\n' \
    "schema=${WINN_ENGINE_PIN_SCHEMA}" \
    "source_binary_sha256=${spike_write_source}" \
    "signed_runtime_binary_sha256=${spike_write_runtime}" \
    "relative_path=${WINN_ENGINE_RELATIVE_PATH}" \
    "platform=${spike_write_platform}" \
    "architectures=${spike_write_arches}" \
    "install_name=${WINN_ENGINE_INSTALL_NAME}" \
    >"${spike_test_pin_manifest}"
}

spike_test_pin_check() {
  spike_assert_engine_runtime_pin_manifest \
    "${spike_test_pin_app}" \
    "${spike_test_pin_source}" \
    iphonesimulator \
    arm64,x86_64 \
    "${spike_test_pin_engine}"
}

spike_test_write_pin "${spike_test_pin_source}" "${spike_test_pin_runtime}" \
  iphonesimulator arm64,x86_64
spike_test_expect_pass pin-canonical spike_test_pin_check

# Wrong runtime digest: the verifier re-measures the engine, so a manifest
# that merely agrees with itself must still be refused.
spike_test_write_pin "${spike_test_pin_source}" \
  '0f5ea8c09ab8ab392963e8bef6b707608fc62312c00a09dd94009a4ce607f842' \
  iphonesimulator arm64,x86_64
spike_test_expect_refusal pin-wrong-runtime-hash \
  'not the exact expected bytes' spike_test_pin_check

spike_test_write_pin \
  'f0e810039d0ed43b1a599bb64320b0ee4ab4903cbdfd33e048bf0fb5e7f116cd' \
  "${spike_test_pin_runtime}" iphonesimulator arm64,x86_64
spike_test_expect_refusal pin-wrong-source-hash \
  'not the exact expected bytes' spike_test_pin_check

spike_test_write_pin "${spike_test_pin_source}" "${spike_test_pin_runtime}" \
  iphoneos arm64,x86_64
spike_test_expect_refusal pin-wrong-platform \
  'not the exact expected bytes' spike_test_pin_check

spike_test_write_pin "${spike_test_pin_source}" "${spike_test_pin_runtime}" \
  iphonesimulator arm64
spike_test_expect_refusal pin-wrong-architectures \
  'not the exact expected bytes' spike_test_pin_check

# Structural mutations of an otherwise correct manifest.
spike_test_mutate_pin() {
  spike_mutate_label="$1"
  spike_mutate_expected="$2"
  spike_mutate_program="$3"
  spike_test_write_pin "${spike_test_pin_source}" \
    "${spike_test_pin_runtime}" iphonesimulator arm64,x86_64
  spike_test_expect_pass "${spike_mutate_label}-precondition" \
    spike_test_pin_check
  cp "${spike_test_pin_manifest}" "${spike_test_scratch}/pin-src"
  rm -f "${spike_test_pin_manifest}"
  eval "${spike_mutate_program}" \
    <"${spike_test_scratch}/pin-src" >"${spike_test_pin_manifest}"
  spike_test_expect_refusal "${spike_mutate_label}" \
    "${spike_mutate_expected}" spike_test_pin_check
}

spike_test_mutate_pin pin-missing-line 'not the exact expected bytes' \
  'grep -v "^platform="'
# Hold-space swap of lines 4 and 5. A plain "sed -n '5p;4p'" would NOT
# reorder anything -- sed prints in read order -- and would silently make this
# case a no-op mutation.
spike_test_mutate_pin pin-reordered 'not the exact expected bytes' \
  "sed -n -e '1,3p' -e '4{h;d;}' -e '5{p;x;p;d;}' -e '6,7p'"
spike_test_mutate_pin pin-duplicate-line 'not the exact expected bytes' \
  'awk "{print} /^platform=/{print}"'
spike_test_mutate_pin pin-unknown-line 'not the exact expected bytes' \
  'awk "{print} END{print \"extra=1\"}"'
spike_test_mutate_pin pin-unterminated 'not the exact expected bytes' \
  "perl -0pe 's/\\n\\z//'"
spike_test_mutate_pin pin-wrong-relative-path 'not the exact expected bytes' \
  'sed "s#^relative_path=.*#relative_path=Frameworks/Other.framework/Other#"'
spike_test_mutate_pin pin-wrong-install-name 'not the exact expected bytes' \
  'sed "s#^install_name=.*#install_name=@rpath/Other.framework/Other#"'
spike_test_mutate_pin pin-wrong-schema 'not the exact expected bytes' \
  'sed "s#^schema=.*#schema=winn-stageb-engine-runtime-pin/2#"'

# Missing manifest entirely.
spike_test_write_pin "${spike_test_pin_source}" "${spike_test_pin_runtime}" \
  iphonesimulator arm64,x86_64
spike_test_expect_pass pin-missing-precondition spike_test_pin_check
rm -f "${spike_test_pin_manifest}"
spike_test_expect_refusal pin-missing \
  'engine runtime pin input is not a regular file' spike_test_pin_check

# The loader refuses st_nlink != 1 on both files, so a hard-linked manifest
# would build here and fail on device.
spike_test_write_pin "${spike_test_pin_source}" "${spike_test_pin_runtime}" \
  iphonesimulator arm64,x86_64
spike_test_expect_pass pin-hardlink-precondition spike_test_pin_check
ln "${spike_test_pin_manifest}" "${spike_test_scratch}/pin-hard-link"
spike_test_expect_refusal pin-hard-linked \
  'hard links; the loader requires exactly 1' spike_test_pin_check
rm -f "${spike_test_scratch}/pin-hard-link"

# A symlinked manifest is opened O_NOFOLLOW by the loader.
spike_test_write_pin "${spike_test_pin_source}" "${spike_test_pin_runtime}" \
  iphonesimulator arm64,x86_64
cp "${spike_test_pin_manifest}" "${spike_test_scratch}/pin-real"
rm -f "${spike_test_pin_manifest}"
ln -s "${spike_test_scratch}/pin-real" "${spike_test_pin_manifest}"
spike_test_expect_refusal pin-symlinked \
  'engine runtime pin input is not a regular file' spike_test_pin_check
rm -f "${spike_test_pin_manifest}"

# --- stager receipt field parsing ----------------------------------------
# binary_sha256 is a strict suffix of source_binary_sha256, so a substring
# matcher returns the source digest for both and the two receipt fields
# silently conflate -- the exact failure this lane's naming exists to prevent.
spike_test_receipt='{"schema":"winn-stageb-engine-artifact-receipt/3","source_binary_sha256":"00a17dfd702dc0490efd4f39bc2259fcc38fa4eed8311885499b5f1611713fa3","binary_sha256":"e0e810039d0ed43b1a599bb64320b0ee4ab4903cbdfd33e048bf0fb5e7f116cd"}'

spike_test_checks=$((spike_test_checks + 1))
spike_test_source_field="$(
  spike_engine_receipt_field "${spike_test_receipt}" source_binary_sha256
)"
test "${spike_test_source_field}" = \
  '00a17dfd702dc0490efd4f39bc2259fcc38fa4eed8311885499b5f1611713fa3' ||
  spike_test_note_failure \
    "source_binary_sha256 parsed as ${spike_test_source_field}."

spike_test_checks=$((spike_test_checks + 1))
spike_test_binary_field="$(
  spike_engine_receipt_field "${spike_test_receipt}" binary_sha256
)"
test "${spike_test_binary_field}" = \
  'e0e810039d0ed43b1a599bb64320b0ee4ab4903cbdfd33e048bf0fb5e7f116cd' ||
  spike_test_note_failure \
    "binary_sha256 parsed as ${spike_test_binary_field}; the two receipt digest fields are conflated."

spike_test_checks=$((spike_test_checks + 1))
if spike_engine_receipt_field '{"binary_sha256":"x"}' source_binary_sha256 \
  >/dev/null 2>&1
then
  spike_test_note_failure "a missing stager receipt key was accepted."
fi

# --- count helper exactness ----------------------------------------------
spike_test_checks=$((spike_test_checks + 1))
printf '%s\n' a b c d e f g h i j >"${spike_test_scratch}/ten-lines"
spike_test_ten_count="$(spike_count_lines "${spike_test_scratch}/ten-lines")"
test "${spike_test_ten_count}" = 10 ||
  spike_test_note_failure \
    "spike_count_lines returned ${spike_test_ten_count} for ten lines."

spike_test_checks=$((spike_test_checks + 1))
: >"${spike_test_scratch}/no-lines"
spike_test_zero_count="$(spike_count_lines "${spike_test_scratch}/no-lines")"
test "${spike_test_zero_count}" = 0 ||
  spike_test_note_failure \
    "spike_count_lines returned ${spike_test_zero_count} for an empty file."

test "${spike_test_failures}" -eq 0 || {
  printf 'FAIL: %s of %s engine embed checks failed.\n' \
    "${spike_test_failures}" "${spike_test_checks}" >&2
  exit 1
}
printf 'WINN_STAGEB_ENGINE_BUILD_EMBED_FAULTS_PASS checks=%s\n' \
  "${spike_test_checks}"
