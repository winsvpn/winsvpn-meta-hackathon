#!/bin/sh
set -eu

spike_script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
spike_root="$(CDPATH='' cd -- "${spike_script_dir}/.." && pwd)"
experiment_root="$(CDPATH='' cd -- "${spike_root}/../.." && pwd)"
spike_swift_scratch_root_logical="$(
  mktemp -d "${TMPDIR:-/tmp}/winn-ios-spike-verify.XXXXXX"
)"
# macOS commonly exposes /var as a symlink to /private/var. Resolve the
# freshly-created private scratch root once so the physical-evidence verifier
# receives a symlink-free root path, as required by its secure-root contract.
spike_swift_scratch_root="$(
  CDPATH='' cd -- "${spike_swift_scratch_root_logical}" && pwd -P
)"
spike_tools_staging="${spike_swift_scratch_root}/tools-staging"
spike_tools="${spike_swift_scratch_root}/tools"

spike_cleanup() {
  chmod -R u+w "${spike_swift_scratch_root}" 2>/dev/null || true
  rm -R "${spike_swift_scratch_root}"
}
trap spike_cleanup EXIT HUP INT TERM

mkdir -p "${spike_tools_staging}"

"${spike_root}/Scripts/test_awg_uapi_sanitizer.sh"
"${spike_root}/Scripts/test_stageb_native_engine.sh"
"${spike_root}/Scripts/test_stageb_darwin_utun.sh"
"${spike_root}/Scripts/test_stageb_provider_native_owner.sh"
"${spike_root}/Scripts/test_stageb_engine_build_project_integration.sh"

(
  cd "${experiment_root}"
  CGO_ENABLED=0 go build \
    -trimpath \
    -buildvcs=false \
    -o "${spike_tools_staging}/evidenceverify" \
    ./spikes/ios_maximum_privacy/evidenceverify
  CGO_ENABLED=0 go build \
    -trimpath \
    -buildvcs=false \
    -o "${spike_tools_staging}/matrixverify" \
    ./spikes/ios_maximum_privacy/matrixverify
  CGO_ENABLED=0 go build \
    -trimpath \
    -buildvcs=false \
    -o "${spike_tools_staging}/stagebphysicalverify" \
    ./spikes/ios_maximum_privacy/stagebphysicalverify
)
chmod 500 \
  "${spike_tools_staging}/evidenceverify" \
  "${spike_tools_staging}/matrixverify" \
  "${spike_tools_staging}/stagebphysicalverify"
(
  cd "${spike_tools_staging}"
  shasum -a 256 evidenceverify >evidenceverify.sha256
  shasum -a 256 matrixverify >matrixverify.sha256
  shasum -a 256 stagebphysicalverify >stagebphysicalverify.sha256
  chmod 400 \
    evidenceverify.sha256 \
    matrixverify.sha256 \
    stagebphysicalverify.sha256
)
# The directory rename publishes each binary and its digest as one private
# pinned set. Nothing under a pre-existing .derived/tools directory is read.
mv "${spike_tools_staging}" "${spike_tools}"
chmod 500 "${spike_tools}"
spike_evidence_verifier="${spike_tools}/evidenceverify"
spike_matrix_verifier="${spike_tools}/matrixverify"
spike_physical_verifier="${spike_tools}/stagebphysicalverify"
spike_evidence_verifier_sha="$(
  awk '{print $1}' "${spike_tools}/evidenceverify.sha256"
)"
spike_physical_verifier_sha="$(
  awk '{print $1}' "${spike_tools}/stagebphysicalverify.sha256"
)"
(
  cd "${spike_tools}"
  shasum -a 256 -c evidenceverify.sha256
  shasum -a 256 -c matrixverify.sha256
  shasum -a 256 -c stagebphysicalverify.sha256
)

# Use fresh, isolated SwiftPM state for each lane. Reusing PrivacyCore/.build
# can inherit a stale SQLite journal from an interrupted build, and running the
# plain and sanitizer lanes against one build database lets the two
# configurations contaminate each other.
swift test \
  --package-path "${spike_root}/PrivacyCore" \
  --scratch-path "${spike_swift_scratch_root}/plain" \
  --disable-swift-testing

# Xcode 26's SwiftPM testing helper loads the test bundle dynamically. Without
# preloading the AddressSanitizer runtime, the bundle can initialize ASan after
# the helper has already started and abort with "interceptors not installed".
# Ask the selected Xcode clang for its runtime instead of hard-coding an Xcode
# or clang version.
spike_asan_runtime="$(
  xcrun clang --print-file-name=libclang_rt.asan_osx_dynamic.dylib
)"
test -f "${spike_asan_runtime}" || {
  echo "FAIL: Xcode AddressSanitizer runtime is unavailable." >&2
  exit 1
}
DYLD_INSERT_LIBRARIES="${spike_asan_runtime}" \
  swift test \
    --package-path "${spike_root}/PrivacyCore" \
    --scratch-path "${spike_swift_scratch_root}/asan" \
    --disable-swift-testing \
    --sanitize=address

plutil -lint \
  "${spike_root}/Host/Info.plist" \
  "${spike_root}/Host/Host.entitlements" \
  "${spike_root}/PacketTunnel/Info.plist" \
  "${spike_root}/PacketTunnel/PacketTunnel.entitlements"

test -x "${spike_root}/Scripts/build_device.sh" || {
  echo "FAIL: Scripts/build_device.sh must be executable." >&2
  exit 1
}
test -x "${spike_root}/Scripts/build_simulator.sh" || {
  echo "FAIL: Scripts/build_simulator.sh must be executable." >&2
  exit 1
}
test -x "${spike_root}/Scripts/collect_device_evidence.sh" || {
  echo "FAIL: Scripts/collect_device_evidence.sh must be executable." >&2
  exit 1
}
test -x "${spike_root}/Scripts/test_build_device_hash_failure.sh" || {
  echo "FAIL: build-device hash fault fixture must be executable." >&2
  exit 1
}
"${spike_root}/Scripts/test_build_device_hash_failure.sh"

# The host and the Packet Tunnel provider must declare the same source-digest
# build setting. The receipt binds the provider's value, and the host refuses
# an attestation whose digest differs from its own, so a drift here would only
# be discovered on a physical device.
spike_host_digest_setting="$(
  plutil -extract WinnSpikeSourceDigest raw -o - "${spike_root}/Host/Info.plist"
)"
spike_provider_digest_setting="$(
  plutil -extract WinnSpikeSourceDigest raw -o - \
    "${spike_root}/PacketTunnel/Info.plist"
)"
# shellcheck disable=SC2016 # the xcconfig substitution is intentionally literal
test "${spike_host_digest_setting}" = '$(WINN_SPIKE_SOURCE_DIGEST)' || {
  echo "FAIL: Host WinnSpikeSourceDigest is not the build setting." >&2
  exit 1
}
test "${spike_provider_digest_setting}" = "${spike_host_digest_setting}" || {
  echo "FAIL: host and provider WinnSpikeSourceDigest disagree." >&2
  exit 1
}

spike_typecheck_dir="${spike_swift_scratch_root}/typecheck"
spike_iphone_sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
mkdir -p "${spike_typecheck_dir}"
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  -emit-module \
  -module-name WinnPrivacyCore \
  -sdk "${spike_iphone_sdk}" \
  -target arm64-apple-ios17.0 \
  "${spike_root}"/PrivacyCore/Sources/WinnPrivacyCore/*.swift \
  -emit-module-path \
  "${spike_typecheck_dir}/WinnPrivacyCore.swiftmodule"
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  -emit-module \
  -module-name WinnStageBProviderCore \
  -sdk "${spike_iphone_sdk}" \
  -target arm64-apple-ios17.0 \
  -I "${spike_typecheck_dir}" \
  "${spike_root}"/PrivacyCore/Sources/WinnStageBProviderCore/*.swift \
  -emit-module-path \
  "${spike_typecheck_dir}/WinnStageBProviderCore.swiftmodule"
xcrun swiftc \
  -swift-version 5 \
  -typecheck \
  -sdk "${spike_iphone_sdk}" \
  -target arm64-apple-ios17.0 \
  -I "${spike_typecheck_dir}" \
  "${spike_root}"/Host/*.swift
xcrun swiftc \
  -swift-version 5 \
  -typecheck \
  -sdk "${spike_iphone_sdk}" \
  -target arm64-apple-ios17.0 \
  -I "${spike_typecheck_dir}" \
  -import-objc-header \
  "${spike_root}/PacketTunnel/StageBProviderNativeBridge.h" \
  -Xcc -I"${spike_root}/NativeEngine" \
  "${spike_root}"/PacketTunnel/*.swift

grep -q 'productName = WinnStageBProviderCore' \
  "${spike_root}/PrivacySpike.xcodeproj/project.pbxproj" || {
  echo "FAIL: Packet Tunnel target does not link WinnStageBProviderCore." >&2
  exit 1
}
grep -q 'StageBProviderNativeAdapterSeam.swift in Sources' \
  "${spike_root}/PrivacySpike.xcodeproj/project.pbxproj" || {
  echo "FAIL: Packet Tunnel target does not compile the Stage B adapter seam." >&2
  exit 1
}
grep -q 'StageBProviderNativeBridge.h' \
  "${spike_root}/PrivacySpike.xcodeproj/project.pbxproj" || {
  echo "FAIL: Packet Tunnel native bridge header is absent." >&2
  exit 1
}
grep -q 'SWIFT_OBJC_BRIDGING_HEADER = PacketTunnel/StageBProviderNativeBridge.h' \
  "${spike_root}/PrivacySpike.xcodeproj/project.pbxproj" || {
  echo "FAIL: Packet Tunnel does not import its provider-private bridge." >&2
  exit 1
}

# The host receipt is published exactly once, and the publish path is not
# reachable from the Swift package tests, so it is exercised on its own here.
receipt_store_fixture="${spike_typecheck_dir}/receipt-store-fixture"
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  "${spike_root}/Host/ImmutableReceiptStore.swift" \
  "${spike_root}/Scripts/immutable_receipt_store_fixture.swift" \
  -o "${receipt_store_fixture}"
"${receipt_store_fixture}"

swift_evidence_fixture="${spike_typecheck_dir}/swift-evidence-fixture"
# The receipt binds `<runID>.jsonl`, so the fixture must use that name.
swift_evidence_run_id="01234567-89ab-cdef-0123-456789abcdef"
swift_evidence_jsonl="$(
  printf '%s/%s.jsonl' "${spike_typecheck_dir}" "${swift_evidence_run_id}"
)"
swift_start_receipt="$(
  printf '%s/%s.start-receipt.json' \
    "${spike_typecheck_dir}" "${swift_evidence_run_id}"
)"
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  "${spike_root}"/PrivacyCore/Sources/WinnPrivacyCore/*.swift \
  "${spike_root}/Scripts/emit_swift_evidence_fixture.swift" \
  -o "${swift_evidence_fixture}"
"${swift_evidence_fixture}" \
  "${swift_evidence_jsonl}" \
  "${swift_start_receipt}"
host_evidence_validator_fixture="$(
  printf '%s/host-evidence-validator-fixture' "${spike_typecheck_dir}"
)"
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  "${spike_root}/Host/CollectedEvidenceValidator.swift" \
  "${spike_root}/Scripts/validate_collected_evidence_fixture.swift" \
  -o "${host_evidence_validator_fixture}"
"${host_evidence_validator_fixture}" "${swift_evidence_jsonl}"
(
  cd "${experiment_root}"
  go test \
    ./spikes/ios_maximum_privacy/evidenceverify \
    ./spikes/ios_maximum_privacy/matrixverify \
    ./spikes/ios_maximum_privacy/stagebphysicalverify \
    ./spikes/ios_maximum_privacy/stagebreflector
  go vet \
    ./spikes/ios_maximum_privacy/stagebphysicalverify \
    ./spikes/ios_maximum_privacy/stagebreflector
  go test -race -count=1 \
    ./spikes/ios_maximum_privacy/stagebphysicalverify \
    ./spikes/ios_maximum_privacy/stagebreflector

  spike_physical_fixture="${spike_swift_scratch_root}/stageb-physical-fixture"
  cp -R \
    "${spike_root}/stagebphysicalverify/testdata/canonical" \
    "${spike_physical_fixture}"
  chmod -R u+w "${spike_physical_fixture}"
  spike_physical_manifest="${spike_physical_fixture}/manifest.json"
  spike_physical_attempt="${spike_physical_fixture}/evidence/attempt.json"
  spike_fixture_contract_sha="$(
    shasum -a 256 "${spike_root}/STAGE_B_PHYSICAL_EVIDENCE_CONTRACT.md" |
      awk '{print $1}'
  )"
  spike_fixture_source_sha="$(
    find \
      "${spike_root}/stagebphysicalverify" \
      -type f \
      -name '*.go' \
      -exec shasum -a 256 {} \; |
      LC_ALL=C sort |
      shasum -a 256 |
      awk '{print $1}'
  )"
  spike_checked_contract_sha="$(
    printf '%064d' 0 | tr 0 1
  )"
  spike_checked_source_sha="$(
    printf '%064d' 0 | tr 0 2
  )"
  spike_checked_verifier_sha="$(
    printf '%064d' 0 | tr 0 9
  )"
  spike_checked_evidence_sha="$(
    shasum -a 256 "${spike_physical_attempt}" | awk '{print $1}'
  )"
  spike_replace_digest() {
    spike_replace_from="$1"
    spike_replace_to="$2"
    spike_replace_file="$3"
    sed \
      "s|${spike_replace_from}|${spike_replace_to}|g" \
      "${spike_replace_file}" >"${spike_replace_file}.next"
    mv "${spike_replace_file}.next" "${spike_replace_file}"
  }
  spike_replace_digest \
    "${spike_checked_contract_sha}" \
    "${spike_fixture_contract_sha}" \
    "${spike_physical_attempt}"
  spike_replace_digest \
    "${spike_checked_contract_sha}" \
    "${spike_fixture_contract_sha}" \
    "${spike_physical_manifest}"
  spike_replace_digest \
    "${spike_checked_verifier_sha}" \
    "${spike_physical_verifier_sha}" \
    "${spike_physical_attempt}"
  spike_replace_digest \
    "${spike_checked_verifier_sha}" \
    "${spike_physical_verifier_sha}" \
    "${spike_physical_manifest}"
  spike_replace_digest \
    "${spike_checked_source_sha}" \
    "${spike_fixture_source_sha}" \
    "${spike_physical_attempt}"
  spike_replace_digest \
    "${spike_checked_source_sha}" \
    "${spike_fixture_source_sha}" \
    "${spike_physical_manifest}"
  spike_runtime_evidence_sha="$(
    shasum -a 256 "${spike_physical_attempt}" | awk '{print $1}'
  )"
  spike_replace_digest \
    "${spike_checked_evidence_sha}" \
    "${spike_runtime_evidence_sha}" \
    "${spike_physical_manifest}"
  spike_runtime_manifest_sha="$(
    shasum -a 256 "${spike_physical_manifest}" | awk '{print $1}'
  )"
  spike_run_physical_verifier() {
    "${spike_physical_verifier}" \
      -manifest "${spike_physical_manifest}" \
      -expected-manifest-sha256 "${spike_runtime_manifest_sha}" \
      -expected-contract-sha256 "${spike_fixture_contract_sha}" \
      -expected-source-sha256 "${spike_fixture_source_sha}" \
      -expected-verifier-sha256 "${spike_physical_verifier_sha}" \
      "$@"
  }
  spike_expect_physical_rejection() {
    spike_rejection_name="$1"
    shift
    if spike_run_physical_verifier "$@" >/dev/null 2>&1
    then
      echo "FAIL: Stage B physical verifier accepted ${spike_rejection_name}." >&2
      exit 1
    fi
  }
  (
    cd "${spike_tools}"
    shasum -a 256 -c stagebphysicalverify.sha256
  )
  spike_run_physical_verifier
  spike_wrong_pin="$(
    printf '%064d' 0 | tr 0 a
  )"
  spike_expect_physical_rejection \
    "a mutated external manifest pin" \
    -expected-manifest-sha256 "${spike_wrong_pin}"
  spike_expect_physical_rejection \
    "a mutated external contract pin" \
    -expected-contract-sha256 "${spike_wrong_pin}"
  spike_expect_physical_rejection \
    "a mutated external source pin" \
    -expected-source-sha256 "${spike_wrong_pin}"
  spike_expect_physical_rejection \
    "a mutated external verifier pin" \
    -expected-verifier-sha256 "${spike_wrong_pin}"

  cp "${spike_physical_attempt}" "${spike_physical_attempt}.saved"
  sed \
    's/"radio":"wifi"/"radio":"cellular"/' \
    "${spike_physical_attempt}.saved" >"${spike_physical_attempt}"
  cmp -s "${spike_physical_attempt}.saved" "${spike_physical_attempt}" && {
    echo "FAIL: Stage B attempt mutation did not change fixture bytes." >&2
    exit 1
  }
  spike_expect_physical_rejection "mutated attempt bytes"
  mv "${spike_physical_attempt}.saved" "${spike_physical_attempt}"

  cp "${spike_physical_manifest}" "${spike_physical_manifest}.saved"
  sed \
    's|"protocolVersion":"winn/3"|"protocolVersion":"winn/4"|' \
    "${spike_physical_manifest}.saved" >"${spike_physical_manifest}"
  cmp -s "${spike_physical_manifest}.saved" "${spike_physical_manifest}" && {
    echo "FAIL: Stage B manifest mutation did not change fixture bytes." >&2
    exit 1
  }
  spike_expect_physical_rejection "mutated manifest bytes"
  mv "${spike_physical_manifest}.saved" "${spike_physical_manifest}"

  "${spike_evidence_verifier}" \
    -evidence "${swift_evidence_jsonl}" \
    -start-receipt "${swift_start_receipt}" \
    -expected-source-digest \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    -expected-artifact-digest \
      bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    -expected-mode maximum-privacy \
    -expected-profile low \
    -expected-cover continuousWhileConnected \
    -expected-rotation protocol-15m \
    -expected-condition foreground-wifi \
    -expected-pair-id 01234567-89ab-cdef-0123-456789abcdef \
    -expected-os-version fixture-ios \
    -expected-hardware-model fixture-iphone \
    -expected-low-power-mode off \
    -expected-start-thermal nominal \
    -expected-duration-seconds 60 \
    -require-energy \
    -require-wakeups
)

# Cross-language mutation check. Swift computed the first-record digest over
# the exact bytes INCLUDING the trailing line feed; Go recomputes it from the
# emitted file. Altering one byte of that record must therefore be refused. A
# verifier that hashed the stripped line, or did not hash at all, would pass
# this file unchanged and is caught here.
spike_mutated_evidence="${spike_typecheck_dir}/mutated"
mkdir -p "${spike_mutated_evidence}"
spike_mutated_jsonl="$(
  printf '%s/%s.jsonl' "${spike_mutated_evidence}" "${swift_evidence_run_id}"
)"
sed 's/2026-07-24T00:00:00.000Z/2026-07-24T00:00:01.000Z/' \
  "${swift_evidence_jsonl}" >"${spike_mutated_jsonl}"
cmp -s "${swift_evidence_jsonl}" "${spike_mutated_jsonl}" && {
  echo "FAIL: the mutation check did not change the first record." >&2
  exit 1
}
(
  cd "${experiment_root}"
  if "${spike_evidence_verifier}" \
    -evidence "${spike_mutated_jsonl}" \
    -start-receipt "${swift_start_receipt}" \
    -expected-source-digest \
      aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    -expected-artifact-digest \
      bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    -expected-mode maximum-privacy \
    -expected-profile low \
    -expected-cover continuousWhileConnected \
    -expected-rotation protocol-15m \
    -expected-condition foreground-wifi \
    -expected-pair-id 01234567-89ab-cdef-0123-456789abcdef \
    -expected-os-version fixture-ios \
    -expected-hardware-model fixture-iphone \
    -expected-low-power-mode off \
    -expected-start-thermal nominal \
    -expected-duration-seconds 60 \
    -require-energy \
    -require-wakeups >/dev/null 2>&1
  then
    echo "FAIL: a mutated first record was accepted." >&2
    exit 1
  fi
)

# Exercise matrixverify with the real freshly built evidenceverify. The
# one-run manifest is intentionally incomplete: reaching the exact pair
# coverage failure proves matrixverify first invoked and accepted the real
# single-run verifier. A fake unconditional PASS program cannot satisfy this
# integration gate because its pinned digest is the fresh Go build above.
spike_matrix_manifest="${spike_typecheck_dir}/real-verifier-matrix.json"
spike_evidence_sha="$(
  shasum -a 256 "${swift_evidence_jsonl}" | awk '{print $1}'
)"
spike_start_receipt_sha="$(
  shasum -a 256 "${swift_start_receipt}" | awk '{print $1}'
)"
spike_matrix_evidence_name="$(basename "${swift_evidence_jsonl}")"
spike_matrix_start_name="$(basename "${swift_start_receipt}")"
{
  printf '{\n'
  printf '  "schema":"winn-ios-privacy-matrix/1",\n'
  printf '  "protocolVersion":"winn/3",\n'
  printf '  "sourceDigest":"%s",\n' \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  printf '  "artifactDigest":"%s",\n' \
    bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  printf '  "osVersion":"fixture-ios",\n'
  printf '  "hardwareModel":"fixture-iphone",\n'
  printf '  "runs":[{\n'
  printf '    "evidence":"%s",\n' "${spike_matrix_evidence_name}"
  printf '    "evidenceSHA256":"%s",\n' "${spike_evidence_sha}"
  printf '    "mode":"maximum-privacy",\n'
  printf '    "trafficProfile":"low",\n'
  printf '    "coverSemantics":"continuousWhileConnected",\n'
  printf '    "rotationCadence":"protocol-15m",\n'
  printf '    "testCondition":"foreground-wifi",\n'
  printf '    "pairID":"01234567-89ab-cdef-0123-456789abcdef",\n'
  printf '    "repeat":1,\n'
  printf '    "durationSeconds":60,\n'
  printf '    "expectedTerminal":"completed",\n'
  printf '    "lowPowerMode":"off",\n'
  printf '    "startThermal":"nominal",\n'
  printf '    "unplugged":true,\n'
  printf '    "startReceipt":"%s",\n' "${spike_matrix_start_name}"
  printf '    "startReceiptSHA256":"%s"\n' "${spike_start_receipt_sha}"
  printf '  }]\n'
  printf '}\n'
} >"${spike_matrix_manifest}"
spike_matrix_stdout="${spike_typecheck_dir}/matrix.stdout"
spike_matrix_stderr="${spike_typecheck_dir}/matrix.stderr"
if "${spike_matrix_verifier}" \
  -manifest "${spike_matrix_manifest}" \
  -evidence-verifier "${spike_evidence_verifier}" \
  -expected-evidence-verifier-sha256 "${spike_evidence_verifier_sha}" \
  >"${spike_matrix_stdout}" 2>"${spike_matrix_stderr}"
then
  echo "FAIL: intentionally incomplete real-verifier matrix passed." >&2
  exit 1
fi
test ! -s "${spike_matrix_stdout}" || {
  echo "FAIL: failed matrix verification wrote stdout." >&2
  exit 1
}
grep -Fqx \
  'IOS_SPIKE_MATRIX_VERIFY_FAIL: pair 01234567-89ab-cdef-0123-456789abcdef has 1 runs, want 2' \
  "${spike_matrix_stderr}" || {
    echo "FAIL: real evidence-verifier integration did not reach coverage." >&2
    cat "${spike_matrix_stderr}" >&2
    exit 1
  }

# Re-check the exact pinned bytes after every invocation. Any drift is a hard
# refusal, not a warning and not an invitation to use a stale cached tool.
(
  cd "${spike_tools}"
  shasum -a 256 -c evidenceverify.sha256
  shasum -a 256 -c matrixverify.sha256
  shasum -a 256 -c stagebphysicalverify.sha256
)

fixture_first="$(
  cd "${experiment_root}"
  go run ./spikes/ios_maximum_privacy/fixturegen
)"
fixture_second="$(
  cd "${experiment_root}"
  go run ./spikes/ios_maximum_privacy/fixturegen
)"
test "${fixture_first}" = "${fixture_second}" || {
  echo "FAIL: Go WCF3 fixture output is nondeterministic." >&2
  exit 1
}
case "${fixture_first}" in
  *'"sha256": "d1dd7981e67dbcf896b5fbccc44b8d440f6685e62120dd96a8d5c61467ce7f80"'*) ;;
  *)
    echo "FAIL: Go WCF3 fixture digest changed." >&2
    exit 1
    ;;
esac

# The checked-in Xcode project and shared scheme are generated artifacts.
# Regenerate them from scratch, then compare UUID-independent canonical graph
# manifests and the scheme XML with only its generated Blueprint IDs masked.
spike_project_scratch="${spike_swift_scratch_root}/project-regeneration"
mkdir -p "${spike_project_scratch}/Scripts"
cp "${spike_root}/Scripts/generate_project.rb" \
  "${spike_project_scratch}/Scripts/generate_project.rb"
(
  cd "${spike_project_scratch}"
  ruby Scripts/generate_project.rb >/dev/null
)
ruby "${spike_root}/Scripts/generate_project.rb" \
  --canonical-manifest "${spike_root}/PrivacySpike.xcodeproj" \
  >"${spike_project_scratch}/checked-in-project.json"
ruby "${spike_root}/Scripts/generate_project.rb" \
  --canonical-manifest "${spike_project_scratch}/PrivacySpike.xcodeproj" \
  >"${spike_project_scratch}/regenerated-project.json"
cmp \
  "${spike_project_scratch}/checked-in-project.json" \
  "${spike_project_scratch}/regenerated-project.json"
sed -E \
  's/BlueprintIdentifier = "[0-9A-F]{24}"/BlueprintIdentifier = "<UUID>"/' \
  "${spike_root}/PrivacySpike.xcodeproj/xcshareddata/xcschemes/PrivacySpike.xcscheme" \
  >"${spike_project_scratch}/checked-in-scheme.xml"
sed -E \
  's/BlueprintIdentifier = "[0-9A-F]{24}"/BlueprintIdentifier = "<UUID>"/' \
  "${spike_project_scratch}/PrivacySpike.xcodeproj/xcshareddata/xcschemes/PrivacySpike.xcscheme" \
  >"${spike_project_scratch}/regenerated-scheme.xml"
cmp \
  "${spike_project_scratch}/checked-in-scheme.xml" \
  "${spike_project_scratch}/regenerated-scheme.xml"

echo "PASS: Swift tests (plain and AddressSanitizer), plist/entitlement lint, host/provider source-digest agreement, iOS WinnPrivacyCore/WinnStageBProviderCore/provider seam typecheck and target-link gate, immutable start-receipt publish behaviour, freshly built and atomically pinned Go verifiers, Swift-to-Go evidence and activation-receipt verification including a first-record mutation, real-verifier matrix integration, scratch-regenerated canonical Xcode project/scheme comparison, and deterministic Go WCF3 fixture."
