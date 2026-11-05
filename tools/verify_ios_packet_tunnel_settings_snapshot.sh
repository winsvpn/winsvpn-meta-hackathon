#!/bin/bash
# iOS Packet Tunnel network-settings SNAPSHOT + PRODUCTION-EQUIVALENCE proof.
#
# WHAT THIS ANSWERS
#
# "Did adding dev containment to ios/PacketTunnel/PacketTunnelProvider.swift
# change what a PRODUCTION session installs?" -- answered by executing the real
# settings-construction code and diffing a complete description of the resulting
# NEPacketTunnelNetworkSettings object, not by reading the diff and reasoning.
#
# It runs the real `makeNetworkSettings` from the real provider source against
# shipping config fixtures, in four shapes:
#
#   current x {RELEASE, DEBUG}   and   baseline x {RELEASE, DEBUG}
#
# and requires the PRODUCTION fixtures to be byte-identical across all four.
# A contained dev config is included as a POSITIVE CONTROL: it MUST differ, or
# the snapshot is not sensitive enough to prove anything.
#
# WHY IT EXISTS AS A COMMITTED TOOL
#
# The previous iOS memory numbers survived only as tables in a handoff document
# with the harness uncommitted -- the same provenance failure as the unmeasured
# figure they replaced. A proof that cannot be re-run is a claim.
#
# USAGE
#
#   tools/verify_ios_packet_tunnel_settings_snapshot.sh [baseline-provider.swift]
#
# With no argument it snapshots the current provider in both build shapes and
# checks the invariants that do not need a baseline. Given a baseline copy of
# PacketTunnelProvider.swift (e.g. from a backup or `git show <ref>:<path>`) it
# additionally diffs production behaviour against it.
#
# NO DEVICE, NO SESSION, NO TUNNEL. This builds command-line binaries on this
# Mac and runs them. It never starts a VPN session.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

HARNESS_DIR="tools/ios_packet_tunnel_snapshot"
PROVIDER="ios/PacketTunnel/PacketTunnelProvider.swift"
BASELINE="${1:-}"

XCODE_SWIFTC="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc"
XCODE_MACOS_SDK="/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
SWIFTC_BIN="${SWIFTC_BIN:-${XCODE_SWIFTC}}"
SWIFTC_SDK="${SWIFTC_SDK:-${XCODE_MACOS_SDK}}"
SWIFTC_ARGS=()
if [[ -n "${SWIFTC_SDK}" && -d "${SWIFTC_SDK}" ]]; then
  export SDKROOT="${SWIFTC_SDK}"
  SWIFTC_ARGS=(-sdk "${SWIFTC_SDK}")
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# NEPacketTunnelProvider cannot be instantiated outside an extension host -- a
# plain CLI segfaults on `NEPacketTunnelProvider()`. So the provider source is
# copied with exactly TWO mechanical rewrites, both printed here so a reader can
# audit that neither touches the code under test:
#
#   1. superclass  NEPacketTunnelProvider -> WinsHarnessProviderBase (declared in
#      snapshot_main.swift, with only the members the provider overrides/calls)
#   2. `private func makeNetworkSettings` -> `func makeNetworkSettings`, so the
#      harness can call it.
#
# `makeNetworkSettings` touches no member of either superclass, so rewrite 1
# cannot change its behaviour; rewrite 2 changes visibility only.
prepare_source() {
  local src="$1" dest="$2"
  sed -e 's/^final class PacketTunnelProvider: NEPacketTunnelProvider {$/final class PacketTunnelProvider: WinsHarnessProviderBase {/' \
      -e 's/^  private func makeNetworkSettings($/  func makeNetworkSettings(/' \
      -e 's/^  private func makeNetworkSettings(from config: WinsTunnelConfig) throws -> NEPacketTunnelNetworkSettings {$/  func makeNetworkSettings(from config: WinsTunnelConfig) throws -> NEPacketTunnelNetworkSettings {/' \
      "$src" > "$dest"
  grep -q 'class PacketTunnelProvider: WinsHarnessProviderBase' "$dest" || {
    printf 'FATAL: superclass rewrite did not apply to %s.\n' "$src" >&2; exit 1; }
  grep -qE '^  func makeNetworkSettings\(' "$dest" || {
    printf 'FATAL: visibility rewrite did not apply to %s.\n' "$src" >&2; exit 1; }
}

# Which shim: the current provider returns (settings, statusFields); a baseline
# from before this lane returns a bare NEPacketTunnelNetworkSettings.
pick_shim() {
  if grep -q 'throws -> (settings: NEPacketTunnelNetworkSettings, statusFields: \[String: Any\])' "$1"; then
    printf '%s/shim_current.swift' "${HARNESS_DIR}"
  else
    printf '%s/shim_legacy_single_return.swift' "${HARNESS_DIR}"
  fi
}

snapshot() {
  local src="$1" label="$2" extra="${3:-}"
  local dir="${WORK}/${label}"
  mkdir -p "${dir}"
  prepare_source "$src" "${dir}/PacketTunnelProvider.swift"
  local shim
  shim="$(pick_shim "$src")"
  # Swift permits top-level code only in a file literally named main.swift, so
  # the harness is copied under that name. Its repo name stays descriptive.
  cp "${HARNESS_DIR}/snapshot_main.swift" "${dir}/main.swift"
  # shellcheck disable=SC2086
  "${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" ${extra} \
    apple/WinsTunnelCore/*.swift \
    "${dir}/PacketTunnelProvider.swift" \
    "${shim}" "${dir}/main.swift" \
    -o "${dir}/snapshot"
  "${dir}/snapshot" > "${WORK}/${label}.txt"
}

# Only the PRODUCTION fixtures; the contained control is compared separately.
production_only() {
  awk '/^### /{keep = ($0 ~ /^### PRODUCTION/)} keep' "$1"
}

printf '== snapshotting current provider ==\n'
snapshot "${PROVIDER}" current_release ""
snapshot "${PROVIDER}" current_debug "-D DEBUG"

printf '== invariant: production settings identical in both build shapes ==\n'
production_only "${WORK}/current_release.txt" > "${WORK}/prod_current_release.txt"
production_only "${WORK}/current_debug.txt" > "${WORK}/prod_current_debug.txt"
if ! diff -u "${WORK}/prod_current_release.txt" "${WORK}/prod_current_debug.txt"; then
  printf 'FATAL: production network settings differ between RELEASE and DEBUG shapes.\n' >&2
  exit 1
fi
printf '   OK\n'

printf '== invariant: every production fixture installs full-tunnel leak protection ==\n'
"${PYTHON_BIN:-python3}" - "${WORK}/prod_current_release.txt" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
blocks = [b for b in re.split(r'\n(?=### )', text) if b.startswith('### PRODUCTION')]
if len(blocks) < 4:
    sys.stderr.write('FATAL: expected at least 4 production fixtures, found %d.\n' % len(blocks))
    raise SystemExit(1)
bad = []
for block in blocks:
    name = block.splitlines()[0]
    # The split-tunnel fixture deliberately has no IPv4 default route; every
    # other production fixture must have one. All of them must keep IPv6 leak
    # protection and full-tunnel DNS.
    if 'ipv6Settings = present' not in block:
        bad.append((name, 'ipv6Settings missing'))
    if 'dnsSettings = present' not in block:
        bad.append((name, 'dnsSettings missing'))
    if 'dns.matchDomains = ""' not in block:
        bad.append((name, 'DNS match domains are not the full-tunnel [""]'))
    if 'ipv6.includedRoutes = [::/0]' not in block:
        bad.append((name, 'IPv6 default route missing'))
    if 'config.devContainmentRequested = false' not in block:
        bad.append((name, 'a production fixture requested containment'))
    if 'statusFields.count = 0' not in block:
        bad.append((name, 'a production start emitted containment status fields'))
if bad:
    for name, why in bad:
        sys.stderr.write('FATAL: %s -> %s\n' % (name, why))
    raise SystemExit(1)
print('   OK (%d production fixtures)' % len(blocks))
PY

printf '== positive control: the contained fixture MUST differ ==\n'
if diff -q <(production_only "${WORK}/current_debug.txt") \
           <(awk '/^### /{keep = ($0 ~ /^### CONTROL/)} keep' "${WORK}/current_debug.txt") \
           >/dev/null 2>&1; then
  printf 'FATAL: the control and production sections are indistinguishable.\n' >&2
  exit 1
fi
grep -q 'ipv4.hasDefaultRoute = false' "${WORK}/current_debug.txt" || {
  printf 'FATAL: no contained fixture produced a settings object without a default route.\n' >&2
  exit 1; }
grep -q 'dev_containment_observed_contained = true' "${WORK}/current_debug.txt" || {
  printf 'FATAL: the contained fixture did not report an OBSERVED containment.\n' >&2
  exit 1; }
# Fail-closed: in the RELEASE shape the same marker must be REFUSED, not widened.
grep -q 'error.code = 1016' "${WORK}/current_release.txt" || {
  printf 'FATAL: a RELEASE-shaped build did not refuse a containment-marked config.\n' >&2
  printf '       It must throw rather than install full-tunnel settings.\n' >&2
  exit 1; }
if grep -A6 '^### CONTROL contained dev session (marker, derived' "${WORK}/current_release.txt" \
   | grep -q 'RESULT = settings'; then
  printf 'FATAL: a RELEASE-shaped build produced SETTINGS for a contained config.\n' >&2
  exit 1
fi
printf '   OK\n'

if [[ -n "${BASELINE}" ]]; then
  printf '== equivalence against baseline %s ==\n' "${BASELINE}"
  [[ -f "${BASELINE}" ]] || { printf 'FATAL: no such baseline file.\n' >&2; exit 1; }
  snapshot "${BASELINE}" baseline_release ""
  snapshot "${BASELINE}" baseline_debug "-D DEBUG"
  production_only "${WORK}/baseline_release.txt" > "${WORK}/prod_baseline_release.txt"
  production_only "${WORK}/baseline_debug.txt" > "${WORK}/prod_baseline_debug.txt"
  if ! diff -u "${WORK}/prod_baseline_release.txt" "${WORK}/prod_current_release.txt"; then
    printf 'FATAL: production settings changed vs baseline (RELEASE shape).\n' >&2
    exit 1
  fi
  if ! diff -u "${WORK}/prod_baseline_debug.txt" "${WORK}/prod_current_debug.txt"; then
    printf 'FATAL: production settings changed vs baseline (DEBUG shape).\n' >&2
    exit 1
  fi
  printf '   OK: production network settings are byte-identical to the baseline\n'
  printf '       in both build shapes, across every production fixture.\n'
fi

printf '\nAll iOS packet tunnel settings snapshot checks passed.\n'
