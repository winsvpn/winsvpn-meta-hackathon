#!/bin/sh
set -eu

spike_test_script_dir="$(
  CDPATH='' cd -- "$(dirname -- "$0")" && pwd
)"
spike_test_builder="${spike_test_script_dir}/build_device.sh"

spike_expect_hash_failure() {
  spike_test_fixture="$1"
  spike_test_expected="$2"
  spike_test_stdout="$(
    mktemp "${TMPDIR:-/tmp}/winn-build-hash-stdout.XXXXXX"
  )"
  spike_test_stderr="$(
    mktemp "${TMPDIR:-/tmp}/winn-build-hash-stderr.XXXXXX"
  )"
  if PATH="${spike_test_script_dir}/test-fixtures/${spike_test_fixture}:${PATH}" \
    "${spike_test_builder}" \
    >"${spike_test_stdout}" 2>"${spike_test_stderr}"
  then
    echo "FAIL: ${spike_test_fixture} shasum produced build success." >&2
    rm -f "${spike_test_stdout}" "${spike_test_stderr}"
    return 1
  fi
  if grep -F 'PASS:' "${spike_test_stdout}" >/dev/null ||
    grep -F 'build_receipt=' "${spike_test_stdout}" >/dev/null
  then
    echo "FAIL: failed hashing emitted PASS or a build receipt." >&2
    rm -f "${spike_test_stdout}" "${spike_test_stderr}"
    return 1
  fi
  grep -F "${spike_test_expected}" "${spike_test_stderr}" >/dev/null || {
    echo "FAIL: ${spike_test_fixture} did not report its hash failure." >&2
    rm -f "${spike_test_stdout}" "${spike_test_stderr}"
    return 1
  }
  rm -f "${spike_test_stdout}" "${spike_test_stderr}"
}

spike_expect_hash_failure \
  failing-shasum \
  'FAIL: shasum failed for'
spike_expect_hash_failure \
  malformed-shasum \
  'FAIL: shasum output is not a lowercase SHA-256'

winn_builder_functions="$(
  awk '
    BEGIN { emit = 0 }
    /^spike_write_input_list\(\)/ { emit = 1 }
    /^spike_write_input_list "\$\{spike_root\}"/ { exit }
    emit { print }
  ' "${spike_test_builder}"
)"
eval "${winn_builder_functions}"

spike_test_receipt_root="$(
  mktemp -d "${TMPDIR:-/tmp}/winn-build-receipt-fault.XXXXXX"
)"
spike_test_receipt="${spike_test_receipt_root}/WINN_SPIKE_BUILD_RECEIPT.json"
trap 'chmod -R u+w "${spike_test_receipt_root}" 2>/dev/null || true
rm -R "${spike_test_receipt_root}"' EXIT HUP INT TERM

spike_source_digest="$(
  printf '%064d' 1
)"
spike_app_executable_sha="$(
  printf '%064d' 2
)"
spike_provider_executable_sha="$(
  printf '%064d' 3
)"
spike_evidence_verifier_sha="$(
  printf '%064d' 4
)"
spike_matrix_verifier_sha="$(
  printf '%064d' 5
)"

spike_expect_receipt_hash_failure() {
  spike_test_mode="$1"
  if (
    if test "${spike_test_mode}" = failed; then
      shasum() { return 17; }
    else
      shasum() {
        printf '%s\n' 'not-a-sha256  injected-build-receipt'
      }
    fi
    spike_publish_build_receipt "${spike_test_receipt}" >/dev/null 2>&1
  ); then
    echo "FAIL: late ${spike_test_mode} receipt hash published." >&2
    return 1
  fi
  test ! -e "${spike_test_receipt}" || {
    echo "FAIL: late hash failure left a final build receipt." >&2
    return 1
  }
  test -z "$(
    find "${spike_test_receipt_root}" -mindepth 1 -print -quit
  )" || {
    echo "FAIL: late hash failure left a staging receipt." >&2
    return 1
  }
}

spike_expect_receipt_hash_failure failed
spike_expect_receipt_hash_failure malformed

printf '%s\n' \
  'PASS: physical build fails closed on early and final-receipt hash faults.'
