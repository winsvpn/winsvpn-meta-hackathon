#!/bin/sh
set -eu

# Deterministic fail-closed concurrency fixture for build_device.sh provenance.
#
# Each case runs from its own isolated spike copy. build_device.sh first
# re-executes from immutable custody, digests a source snapshot containing the
# custodied builder and generator, and then pauses at a fail-only checkpoint
# before DerivedData or any build tool is created. This fixture mutates one
# live worktree file only after that checkpoint reports the original pinned
# hashes. Continuing must fail for the attributable drift reason, and no build
# receipt may exist.

spike_test_script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
spike_test_root="$(CDPATH='' cd -- "${spike_test_script_dir}/.." && pwd)"
spike_test_scratch="$(
  CDPATH='' cd -- "$(
    mktemp -d "${TMPDIR:-/tmp}/winn-stageb-provenance-race.XXXXXX"
  )" && pwd -P
)"
spike_test_pid=""

spike_test_cleanup() {
  if test -n "${spike_test_pid}"; then
    kill "${spike_test_pid}" 2>/dev/null || true
    wait "${spike_test_pid}" 2>/dev/null || true
  fi
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

spike_test_sha256() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}

spike_test_expected_source_digest() {
  spike_digest_root="$1"
  spike_digest_prefix="$2"
  spike_digest_raw="${spike_digest_prefix}.raw"
  spike_digest_list="${spike_digest_prefix}.list"
  spike_digest_stream="${spike_digest_prefix}.stream"
  (
    cd "${spike_digest_root}"
    find \
      Host \
      PacketTunnel \
      NativeEngine \
      PrivacyCore/Sources \
      PrivacyCore/Package.swift \
      Config/Base.xcconfig \
      Scripts/build_device.sh \
      Scripts/generate_project.rb \
      Scripts/stage_stageb_engine_artifact.sh \
      PrivacySpike.xcodeproj/project.pbxproj \
      PrivacySpike.xcodeproj/xcshareddata/xcschemes/PrivacySpike.xcscheme \
      -type f -print0 >"${spike_digest_raw}"
  )
  ruby -e '
    paths = File.binread(ARGV.fetch(0)).split("\0", -1)
    paths.pop if paths.last == ""
    paths.sort_by!(&:b)
    STDOUT.write(paths.join("\n"))
    STDOUT.write("\n")
  ' "${spike_digest_raw}" >"${spike_digest_list}"
  grep -Fqx 'Scripts/build_device.sh' "${spike_digest_list}"
  grep -Fqx 'Scripts/generate_project.rb' "${spike_digest_list}"
  (
    cd "${spike_digest_root}"
    while IFS= read -r spike_digest_input; do
      printf '%s  %s\n' \
        "$(spike_test_sha256 "${spike_digest_input}")" \
        "${spike_digest_input}"
    done <"${spike_digest_list}"
  ) >"${spike_digest_stream}"
  spike_test_sha256 "${spike_digest_stream}"
}

spike_test_wait_ready() {
  spike_wait_ready_path="$1"
  spike_wait_deadline="$(( $(date +%s) + 30 ))"
  while test ! -f "${spike_wait_ready_path}"; do
    if ! kill -0 "${spike_test_pid}" 2>/dev/null; then
      return 1
    fi
    test "$(date +%s)" -lt "${spike_wait_deadline}" || return 1
    sleep 0.05
  done
}

spike_test_run_mutation() {
  spike_case_label="$1"
  spike_case_relative_target="$2"
  spike_case_expected_error="$3"
  spike_case_dir="${spike_test_scratch}/${spike_case_label}"
  spike_case_root="${spike_case_dir}/ios_maximum_privacy"
  spike_case_hook="${spike_case_dir}/hook"
  mkdir -p "${spike_case_root}" "${spike_case_hook}"
  rsync -a \
    --exclude '.derived' \
    --exclude '.runtime' \
    --exclude 'PrivacyCore/.build' \
    "${spike_test_root}/" "${spike_case_root}/"

  spike_case_builder="${spike_case_root}/Scripts/build_device.sh"
  spike_case_generator="${spike_case_root}/Scripts/generate_project.rb"
  spike_case_builder_sha="$(spike_test_sha256 "${spike_case_builder}")"
  spike_case_generator_sha="$(spike_test_sha256 "${spike_case_generator}")"

  WINN_SPIKE_PROVENANCE_TEST_HOOK_DIR="${spike_case_hook}" \
    /bin/sh "${spike_case_builder}" \
    >"${spike_case_dir}/stdout" 2>"${spike_case_dir}/stderr" &
  spike_test_pid="$!"

  spike_test_checks=$((spike_test_checks + 1))
  if ! spike_test_wait_ready "${spike_case_hook}/ready"; then
    spike_test_note_failure \
      "${spike_case_label}: builder exited before the provenance checkpoint."
    wait "${spike_test_pid}" 2>/dev/null || true
    spike_test_pid=""
    return 0
  fi

  spike_test_checks=$((spike_test_checks + 1))
  grep -Fqx "builderSHA256=${spike_case_builder_sha}" \
    "${spike_case_hook}/ready" ||
    spike_test_note_failure \
      "${spike_case_label}: checkpoint did not report the original builder pin."

  spike_test_checks=$((spike_test_checks + 1))
  grep -Fqx "projectGeneratorSHA256=${spike_case_generator_sha}" \
    "${spike_case_hook}/ready" ||
    spike_test_note_failure \
      "${spike_case_label}: checkpoint did not report the original generator pin."

  spike_case_source_digest="$(
    sed -n 's/^sourceDigest=//p' "${spike_case_hook}/ready"
  )"
  spike_case_expected_source_digest="$(
    spike_test_expected_source_digest \
      "${spike_case_root}" \
      "${spike_case_dir}/expected-source-digest"
  )"
  spike_test_checks=$((spike_test_checks + 1))
  test "${spike_case_source_digest}" = \
    "${spike_case_expected_source_digest}" ||
    spike_test_note_failure \
      "${spike_case_label}: sourceDigest does not bind the exact independently enumerated inputs."

  printf '\n# deterministic concurrent mutation: %s\n' "${spike_case_label}" \
    >>"${spike_case_root}/${spike_case_relative_target}"
  : >"${spike_case_hook}/continue"

  spike_test_checks=$((spike_test_checks + 1))
  if wait "${spike_test_pid}"; then
    spike_test_note_failure \
      "${spike_case_label}: mutated build unexpectedly succeeded."
  else
    grep -Fq "${spike_case_expected_error}" "${spike_case_dir}/stderr" ||
      spike_test_note_failure \
        "${spike_case_label}: build failed for the wrong reason."
  fi
  spike_test_pid=""

  spike_test_checks=$((spike_test_checks + 1))
  if find "${spike_case_dir}" -name WINN_SPIKE_BUILD_RECEIPT.json \
    -print -quit | grep -q .
  then
    spike_test_note_failure \
      "${spike_case_label}: drifted invocation published a build receipt."
  fi
}

spike_test_run_mutation \
  builder-drift \
  Scripts/build_device.sh \
  'live build_device.sh drifted from its immutable pre-build pin'

spike_test_run_mutation \
  generator-drift \
  Scripts/generate_project.rb \
  'live generate_project.rb drifted from its immutable pre-build pin'

# macOS' default TMPDIR can be spelled through /var even though Xcodeproj's
# `real_path` reports /private/var. Reproduce that topology with a logical
# symlink, then drive the real builder through the post-snapshot project-wiring
# checkpoint. Reaching `ready` proves the immutable snapshot and every exact
# project/reference comparison completed without invoking xcodebuild or
# touching a device.
spike_test_run_logical_tmpdir_preflight() {
  spike_case_label="logical-tmpdir-preflight"
  spike_case_dir="${spike_test_scratch}/${spike_case_label}"
  spike_case_root="${spike_case_dir}/ios_maximum_privacy"
  spike_case_hook="${spike_case_dir}/hook"
  spike_case_physical_tmp="${spike_case_dir}/private-var"
  spike_case_logical_tmp="${spike_case_dir}/var"
  mkdir -p \
    "${spike_case_root}" \
    "${spike_case_hook}" \
    "${spike_case_physical_tmp}"
  ln -s "${spike_case_physical_tmp}" "${spike_case_logical_tmp}"
  rsync -a \
    --exclude '.derived' \
    --exclude '.runtime' \
    --exclude 'PrivacyCore/.build' \
    "${spike_test_root}/" "${spike_case_root}/"

  spike_test_checks=$((spike_test_checks + 1))
  test "${spike_case_logical_tmp}" != "$(
    CDPATH='' cd -- "${spike_case_logical_tmp}" && pwd -P
  )" || spike_test_note_failure \
    "${spike_case_label}: fixture TMPDIR did not have distinct logical and physical spellings."

  TMPDIR="${spike_case_logical_tmp}" \
    WINN_SPIKE_PROVENANCE_TEST_HOOK_DIR="${spike_case_hook}" \
    WINN_SPIKE_DEVICE_UDID=<DEVICE_UDID> \
    /bin/sh "${spike_case_root}/Scripts/build_device.sh" \
    >"${spike_case_dir}/stdout" 2>"${spike_case_dir}/stderr" &
  spike_test_pid="$!"

  spike_test_checks=$((spike_test_checks + 1))
  if ! spike_test_wait_ready "${spike_case_hook}/ready"; then
    spike_test_note_failure \
      "${spike_case_label}: builder did not reach the post-project-validation checkpoint."
    wait "${spike_test_pid}" 2>/dev/null || true
    spike_test_pid=""
    return 0
  fi

  spike_case_snapshot="$(
    find "${spike_case_physical_tmp}" \
      -maxdepth 1 -type d -name 'winn-ios-spike-source.*' -print
  )"
  spike_test_checks=$((spike_test_checks + 1))
  test -n "${spike_case_snapshot}" &&
    test "$(printf '%s\n' "${spike_case_snapshot}" | wc -l | tr -d ' ')" -eq 1 ||
    spike_test_note_failure \
      "${spike_case_label}: expected one physical immutable snapshot."

  : >"${spike_case_hook}/continue"
  spike_test_checks=$((spike_test_checks + 1))
  if wait "${spike_test_pid}"; then
    spike_test_note_failure \
      "${spike_case_label}: fail-only preflight unexpectedly continued."
  else
    grep -Fq \
      'provenance test checkpoint intentionally stops before build execution' \
      "${spike_case_dir}/stderr" ||
      spike_test_note_failure \
        "${spike_case_label}: preflight failed before the intended safe stop."
  fi
  spike_test_pid=""

  spike_test_checks=$((spike_test_checks + 1))
  if find "${spike_case_dir}" -name WINN_SPIKE_BUILD_RECEIPT.json \
    -print -quit | grep -q .
  then
    spike_test_note_failure \
      "${spike_case_label}: no-device preflight published a build receipt."
  fi
}

spike_test_run_logical_tmpdir_preflight

# Exercise the real receipt publisher with distinct synthetic digests. This
# does not claim a device build; it proves that the final JSON and its returned
# hash carry the already-pinned builder/generator identities rather than
# re-reading either live file.
spike_test_receipt_functions="$(
  awk '
    BEGIN { emit = 0 }
    /^spike_write_input_list\(\)/ { emit = 1 }
    /^spike_write_input_list "\$\{spike_root\}"/ { exit }
    emit { print }
  ' "${spike_test_script_dir}/build_device.sh"
)"
eval "${spike_test_receipt_functions}"
spike_test_receipt_dir="${spike_test_scratch}/receipt"
mkdir "${spike_test_receipt_dir}"
spike_test_receipt="${spike_test_receipt_dir}/WINN_SPIKE_BUILD_RECEIPT.json"
spike_source_digest="$(printf '%064d' 1)"
spike_app_executable_sha="$(printf '%064d' 2)"
spike_provider_executable_sha="$(printf '%064d' 3)"
spike_engine_source_binary_sha="$(printf '%064d' 4)"
spike_engine_embedded_runtime_binary_sha="$(printf '%064d' 5)"
spike_evidence_verifier_sha="$(printf '%064d' 6)"
spike_matrix_verifier_sha="$(printf '%064d' 7)"
spike_engine_runtime_pin_manifest_sha="$(printf '%064d' 8)"
spike_builder_sha="$(printf '%064d' 9)"
spike_generator_sha="$(printf '%064d' 10)"
spike_stager_sha="$(printf '%064d' 11)"
spike_engine_embedded_relative_path="Frameworks/test.framework/test"
export \
  spike_source_digest \
  spike_app_executable_sha \
  spike_provider_executable_sha \
  spike_engine_source_binary_sha \
  spike_engine_embedded_runtime_binary_sha \
  spike_evidence_verifier_sha \
  spike_matrix_verifier_sha \
  spike_engine_runtime_pin_manifest_sha \
  spike_builder_sha \
  spike_generator_sha \
  spike_stager_sha \
  spike_engine_embedded_relative_path
spike_test_receipt_sha="$(
  spike_publish_build_receipt "${spike_test_receipt}"
)"

spike_test_checks=$((spike_test_checks + 1))
ruby -rjson -e '
  document = JSON.parse(File.binread(ARGV.fetch(0)))
  abort("builder receipt pin mismatch") unless
    document.fetch("builderSHA256") == ARGV.fetch(1)
  abort("generator receipt pin mismatch") unless
    document.fetch("projectGeneratorSHA256") == ARGV.fetch(2)
' \
  "${spike_test_receipt}" \
  "${spike_builder_sha}" \
  "${spike_generator_sha}" ||
  spike_test_note_failure \
    "receipt did not carry the pre-pinned builder/generator identities."

spike_test_checks=$((spike_test_checks + 1))
test "${spike_test_receipt_sha}" = \
  "$(spike_test_sha256 "${spike_test_receipt}")" ||
  spike_test_note_failure \
    "receipt publisher returned a hash different from the finished JSON."

test "${spike_test_failures}" -eq 0 || {
  printf 'FAIL: %s of %s build provenance concurrency checks failed.\n' \
    "${spike_test_failures}" "${spike_test_checks}" >&2
  exit 1
}
printf 'WINN_STAGEB_BUILD_PROVENANCE_CONCURRENCY_PASS checks=%s\n' \
  "${spike_test_checks}"
