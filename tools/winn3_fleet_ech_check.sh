#!/usr/bin/env bash
# Read-only fleet check: are the data planes' ECH key files per node yet?
#
#   tools/winn3_fleet_ech_check.sh [--expect-distinct] <ssh-alias>...
#
# Round GK OI-GK-3 step 1 (2026-09-26) replaces the one ech-keys.json that all
# eight data planes shared with a per-node two-entry file. This script reports,
# per node, the SHA-256 of that file and, when winn-ech-keygen is installed
# there, the entry count and the first entry's public-key digest. It then
# counts distinct values.
#
# READ-ONLY, and the static test tools/test_winn3_ech_provisioning_static.py
# holds it to that: the remote command hashes the file and runs
# `winn-ech-keygen -describe`, which prints public fields only. Nothing on a
# node is written, restarted or copied, and no key byte leaves a node; a
# digest of a key file is not the key.
#
# Output names nodes by the alias given, never by address.
#
# --expect-distinct exits 1 unless every node reports a file and all file
# digests and all first-entry public-key digests are pairwise distinct.
# Without it the exit status is 0 whenever every node answered.

set -euo pipefail

CRED_DIR="${WINN_CREDENTIALS_DIR:-/etc/winn/credentials}"
ECH_PATH="${CRED_DIR}/ech-keys.json"
ECH_KEYGEN_BIN="${WINN3_ECH_KEYGEN_INSTALL_PATH:-/usr/local/libexec/winn/winn-ech-keygen}"

expect_distinct=0
if [[ "${1:-}" == "--expect-distinct" ]]; then
  expect_distinct=1
  shift
fi
[[ $# -gt 0 ]] || { echo "usage: $0 [--expect-distinct] <ssh-alias>..." >&2; exit 2; }

# Single-quoted: expanded on the node, not here. Paths are the only inputs.
# shellcheck disable=SC2016
REMOTE='f="$1"; bin="$2"
if [ -f "$f" ]; then echo "file_sha256 $(sha256sum < "$f" | cut -d" " -f1)"; else echo "file_sha256 ABSENT"; fi
if [ -f "$f" ] && [ -x "$bin" ]; then "$bin" -describe "$f" | grep -E "^(entries|ech_public_key_sha256) " || true; fi'

printf '%-17s %-14s %-8s %s\n' node file_sha256 entries ech_public_key_sha256
files=()
publics=()
failed=0
for node in "$@"; do
  if ! out="$(ssh -o BatchMode=yes -o ConnectTimeout=15 "${node}" \
        "bash -s -- '${ECH_PATH}' '${ECH_KEYGEN_BIN}'" <<<"${REMOTE}" 2>/dev/null)"; then
    printf '%-17s %s\n' "${node}" "UNREACHABLE"
    failed=1
    continue
  fi
  file_sha="$(awk '$1=="file_sha256" {print $2; exit}' <<<"${out}")"
  entries="$(awk '$1=="entries" {print $2; exit}' <<<"${out}")"
  public_sha="$(awk '$1=="ech_public_key_sha256" {print $2; exit}' <<<"${out}")"
  printf '%-17s %-14s %-8s %s\n' "${node}" "${file_sha:0:12}" "${entries:--}" "${public_sha:0:12}"
  [[ -n "${file_sha}" && "${file_sha}" != "ABSENT" ]] || failed=1
  files+=("${file_sha}")
  [[ -z "${public_sha}" ]] || publics+=("${public_sha}")
done

count_distinct() { [[ $# -eq 0 ]] && { echo 0; return; }; printf '%s\n' "$@" | sort -u | wc -l | tr -d ' '; }
distinct_files="$(count_distinct "${files[@]+"${files[@]}"}")"
distinct_publics="$(count_distinct "${publics[@]+"${publics[@]}"}")"
echo "nodes=$# answered=${#files[@]} distinct_file_sha256=${distinct_files} described=${#publics[@]} distinct_ech_public_key_sha256=${distinct_publics}"

[[ "${failed}" -eq 0 ]] || exit 1
if [[ "${expect_distinct}" -eq 1 ]]; then
  [[ "${distinct_files}" -eq $# && "${#publics[@]}" -eq $# && "${distinct_publics}" -eq $# ]] || exit 1
fi
exit 0
