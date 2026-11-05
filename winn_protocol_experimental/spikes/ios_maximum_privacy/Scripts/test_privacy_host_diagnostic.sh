#!/bin/sh
set -eu

# Host-only, non-production diagnostic smoke. It builds a fresh macOS
# executable that depends only on WinnPrivacyCore, runs every profile serially,
# and refuses any activation/network symbol or noncanonical result envelope.
# It never builds, installs, launches, or messages a Network Extension.

spike_script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
spike_root="$(CDPATH='' cd -- "${spike_script_dir}/.." && pwd -P)"
spike_package="${spike_root}/PrivacyCore"
spike_scratch="$(
  CDPATH='' cd -- "$(
    mktemp -d "${TMPDIR:-/tmp}/winn-privacy-host-diagnostic.XXXXXX"
  )" && pwd -P
)"

spike_cleanup() {
  chmod -R u+w "${spike_scratch}" 2>/dev/null || true
  rm -R "${spike_scratch}"
}
trap spike_cleanup EXIT HUP INT TERM

spike_sha256() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}

spike_build_path="${spike_scratch}/build"
swift build \
  --package-path "${spike_package}" \
  --scratch-path "${spike_build_path}" \
  --configuration release \
  --product WinnPrivacyHostDiagnostic >/dev/null
spike_bin_dir="$(
  swift build \
    --package-path "${spike_package}" \
    --scratch-path "${spike_build_path}" \
    --configuration release \
    --show-bin-path
)"
spike_binary="${spike_bin_dir}/WinnPrivacyHostDiagnostic"
test -x "${spike_binary}" || {
  echo "FAIL: host diagnostic binary is absent." >&2
  exit 1
}

spike_source_paths="${spike_scratch}/source-paths"
spike_source_manifest="${spike_scratch}/source.sha256"
(
  cd "${spike_package}"
  {
    printf '%s\n' Package.swift
    find Sources/WinnPrivacyStageACore Sources/WinnPrivacyHostDiagnostic \
      -type f -name '*.swift' -print
  } | LC_ALL=C sort -u
) >"${spike_source_paths}"
(
  cd "${spike_package}"
  while IFS= read -r spike_source; do
    test -f "${spike_source}" && test ! -L "${spike_source}" || {
      echo "FAIL: unsafe diagnostic source input." >&2
      exit 1
    }
    printf '%s  %s\n' \
      "$(spike_sha256 "${spike_source}")" \
      "${spike_source}"
  done <"${spike_source_paths}"
) >"${spike_source_manifest}"
spike_source_sha="$(spike_sha256 "${spike_source_manifest}")"
spike_binary_sha="$(spike_sha256 "${spike_binary}")"
spike_toolchain="$(swift --version | sed -n '1p')"

spike_source_scan="$(
  grep -ER --include='*.swift' \
    'StageB|WinnStageB|import CryptoKit|import NetworkExtension|import Network$|NEPacketTunnelProvider|packetFlow|group\.org\.|NEDNS|NEIPv[46]Route|Darwin\.socket|Darwin\.connect|Darwin\.sendto|Darwin\.recvfrom' \
    "${spike_package}/Sources/WinnPrivacyStageACore" \
    "${spike_package}/Sources/WinnPrivacyHostDiagnostic" ||
    test "$?" -eq 1
)" || {
  echo "FAIL: diagnostic source scan could not complete." >&2
  exit 1
}
if test -n "${spike_source_scan}"; then
  echo "FAIL: diagnostic source contains an activation/network API." >&2
  exit 1
fi

spike_symbols="${spike_scratch}/symbols.txt"
nm "${spike_binary}" >"${spike_symbols}" || {
  echo "FAIL: diagnostic symbol extraction could not complete." >&2
  exit 1
}
spike_symbol_scan="$(
  grep -E \
    'StageB|WinnStageB|CryptoKit|NetworkExtension|_socket$|_connect$|_sendto$|_recvfrom$' \
    "${spike_symbols}" || test "$?" -eq 1
)" || {
  echo "FAIL: diagnostic symbol scan could not complete." >&2
  exit 1
}
if test -n "${spike_symbol_scan}"; then
  echo "FAIL: diagnostic binary imports an activation/network symbol." >&2
  exit 1
fi
spike_strings="${spike_scratch}/binary-strings.txt"
strings -a "${spike_binary}" >"${spike_strings}" || {
  echo "FAIL: diagnostic string extraction could not complete." >&2
  exit 1
}
spike_string_scan="$(
  grep -E \
    'StageB|WinnStageB|CryptoKit|NEPacketTunnelProvider|NetworkExtension|group\.org\.winsvpn|NEDNS|NEIPv[46]Route|packetFlow|startVPNTunnel' \
    "${spike_strings}" || test "$?" -eq 1
)" || {
  echo "FAIL: diagnostic string scan could not complete." >&2
  exit 1
}
if test -n "${spike_string_scan}"; then
  echo "FAIL: diagnostic binary carries a forbidden activation/network surface." >&2
  exit 1
fi

spike_dylibs="${spike_scratch}/dylibs.txt"
otool -L "${spike_binary}" >"${spike_dylibs}" || {
  echo "FAIL: diagnostic dylib extraction could not complete." >&2
  exit 1
}
spike_dylib_scan="$(
  grep -E \
    '/(CryptoKit|Network|NetworkExtension)\.framework/' \
    "${spike_dylibs}" || test "$?" -eq 1
)" || {
  echo "FAIL: diagnostic dylib scan could not complete." >&2
  exit 1
}
if test -n "${spike_dylib_scan}"; then
  echo "FAIL: diagnostic binary links a forbidden framework." >&2
  exit 1
fi

spike_run() {
  spike_mode="$1"
  spike_profile="$2"
  spike_rotation="$3"
  spike_duration="$4"
  spike_output="${spike_scratch}/${spike_mode}-${spike_profile}-${spike_rotation}.json"
  "${spike_binary}" \
    --mode "${spike_mode}" \
    --profile "${spike_profile}" \
    --rotation "${spike_rotation}" \
    --duration-ms "${spike_duration}" \
    --source-sha256 "${spike_source_sha}" \
    --binary-sha256 "${spike_binary_sha}" \
    --toolchain "${spike_toolchain}" \
    >"${spike_output}"
  ruby -rjson -e '
    raw = File.binread(ARGV.fetch(0))
    abort("record must end in exactly one LF") unless
      raw.end_with?("\n") && !raw.delete_suffix("\n").include?("\n")
    document = JSON.parse(raw)
    expected = %w[
      allocatedPrivacyCellBytes binarySHA256 coverDeadlinesMissed
      coverPairsAccepted coverPairsEmitted droppedCells durationMilliseconds
      hardwareModel inboundHighWatermark inboundQueueDepth
      interruptWakeupDelta maximumTimerLatenessNanoseconds mode
      networkExtensionActivated outboundHighWatermark outboundQueueDepth
      physicalEvidenceEligible physicalFootprintEndBytes
      physicalFootprintPeakBytes physicalFootprintStartBytes platform
      platformIdleWakeupDelta profile residentEndBytes residentPeakBytes
      residentStartBytes rotationCadence rotationCount
      rotationStandbyPresentAtStop samples schema sourceSHA256
      stageBActivated stopLatencyNanoseconds systemCPUDeltaNanoseconds
      terminalReason timerCallbacks toolchain userCPUDeltaNanoseconds
      workChangedAfterStop worstThermalProxy
    ].sort
    abort("unknown/missing top-level member") unless document.keys.sort == expected
    abort("JSON keys are not canonical") unless document.keys == expected
    abort("wrong schema") unless
      document.fetch("schema") == "winn-ios-privacy-host-diagnostic/1"
    abort("physical claim") unless
      document.fetch("physicalEvidenceEligible") == false &&
      document.fetch("networkExtensionActivated") == false &&
      document.fetch("stageBActivated") == false
    abort("wrong provenance") unless
      document.fetch("sourceSHA256") == ARGV.fetch(1) &&
      document.fetch("binarySHA256") == ARGV.fetch(2)
    abort("wrong requested mode/profile") unless
      document.fetch("mode") == ARGV.fetch(3) &&
      document.fetch("profile") == ARGV.fetch(4)
    abort("no samples") unless document.fetch("samples") > 0
    abort("work after stop") unless
      document.fetch("workChangedAfterStop") == false
    expected_allocation =
      ARGV.fetch(3) == "maximum-privacy" ? 2_097_152 : 0
    abort("allocation mismatch") unless
      document.fetch("allocatedPrivacyCellBytes") == expected_allocation
  ' \
    "${spike_output}" \
    "${spike_source_sha}" \
    "${spike_binary_sha}" \
    "${spike_mode}" \
    "${spike_profile}"
}

# Strict argument/refusal surface.
if "${spike_binary}" --unknown value >/dev/null 2>&1; then
  echo "FAIL: diagnostic accepted an unknown argument." >&2
  exit 1
fi
if "${spike_binary}" \
  --mode core-baseline \
  --profile idle \
  --rotation protocol-15m \
  --duration-ms 100 \
  --source-sha256 "${spike_source_sha}" \
  --binary-sha256 "${spike_binary_sha}" \
  --toolchain "${spike_toolchain}" >/dev/null 2>&1
then
  echo "FAIL: diagnostic accepted an out-of-range duration." >&2
  exit 1
fi
if "${spike_binary}" \
  --mode core-baseline \
  --profile idle \
  --rotation protocol-15m \
  --duration-ms 200 \
  --source-sha256 "$(printf '%064d' 0)" \
  --binary-sha256 "${spike_binary_sha}" \
  --toolchain "${spike_toolchain}" >/dev/null 2>&1
then
  echo "FAIL: diagnostic accepted an all-zero source hash." >&2
  exit 1
fi

# Short, serial smoke only. This is deliberately not the 45/75-minute matrix.
for spike_mode in core-baseline maximum-privacy; do
  for spike_profile in idle low medium saturated; do
    spike_run \
      "${spike_mode}" \
      "${spike_profile}" \
      protocol-15m \
      1200
  done
done
spike_run maximum-privacy idle accelerated-allocation 1200

printf '%s\n' \
  "WINN_PRIVACY_HOST_DIAGNOSTIC_PASS runs=9 sourceSHA256=${spike_source_sha} binarySHA256=${spike_binary_sha}"
