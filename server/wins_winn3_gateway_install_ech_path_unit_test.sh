#!/usr/bin/env bash
# Round GK OI-GK-3 step 1 (2026-09-26): per-node ECH keys change the CONTENT of
# a node's ECH key file (one shared entry becomes a per-node two-entry file),
# never the installer. This proves emit_unit_text references only the ECH key
# path it was configured with: two nodes configured with two distinct ECH key
# files get units that each name their own file, exactly once, and neither
# names the other's. Pure text: emit_unit_text is sourced and called; nothing
# is installed, started or written outside a private scratch directory.
#
# Controls:
#   node A path / node B path     each unit names only its own file   must PASS
#   M1 installer hardcodes a path                                     must FAIL
#
# Usage:
#   bash wins_winn3_gateway_install_ech_path_unit_test.sh [/path/to/wins_winn3_gateway_install.sh]
set -euo pipefail

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}")"
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-${HERE}/testdata/winn3_gateway_meminfo/large}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/winn3-ech-path-unit.XXXXXXXX")"
trap 'rm -rf "${WORKDIR}"' EXIT

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }

emit_for() {
  local script="$1" ech="$2" out="$3"
  env \
    WINN3_GATEWAY_PATH_MTU=1450 \
    WINN3_GATEWAY_PLAN=udp \
    WINN3_GATEWAY_INNER_V4=10.10.0.1 \
    WINN3_GATEWAY_COVER_CERT=/etc/winn/credentials/cover.pem \
    WINN3_GATEWAY_COVER_KEY=/etc/winn/credentials/cover-key.pem \
    WINN3_GATEWAY_ECH_KEYS="${ech}" \
    WINN3_GATEWAY_WINN_CERT=/etc/winn/credentials/winn-leaf.pem \
    WINN3_GATEWAY_WINN_KEY=/etc/winn/credentials/winn-leaf-key.pem \
    bash -c 'set -euo pipefail; source "$1"; emit_unit_text' _ "${script}" >"${out}" 2>"${out}.err"
}

# Returns 0 when the unit names $2 as its only ECH key file.
names_only() {
  local unit="$1" mine="$2" other="$3"
  [[ "$(grep -c "^LoadCredential=ech-keys.json:" "${unit}")" == 1 ]] || return 1
  grep -qxF "LoadCredential=ech-keys.json:${mine}" "${unit}" || return 1
  ! grep -qF "${other}" "${unit}" || return 1
  grep -qF -- "-ech-keys /run/winn3-gateway/ech-keys.json" "${unit}"
}

run_case() {
  local label="$1" script="$2" expect="$3"
  local a=/etc/winn/credentials/node-a/ech-keys.json
  local b=/etc/winn/credentials/node-b/ech-keys.json
  local ok=1
  emit_for "${script}" "${a}" "${WORKDIR}/${label}-a.service" || ok=0
  emit_for "${script}" "${b}" "${WORKDIR}/${label}-b.service" || ok=0
  if [[ "${ok}" -eq 1 ]]; then
    names_only "${WORKDIR}/${label}-a.service" "${a}" "${b}" || ok=0
    names_only "${WORKDIR}/${label}-b.service" "${b}" "${a}" || ok=0
  fi
  if [[ "${ok}" -eq 1 && "${expect}" == pass ]] || [[ "${ok}" -eq 0 && "${expect}" == fail ]]; then
    pass "${label} (expected ${expect})"
  else
    fail "${label} (expected ${expect}, got $([[ ${ok} -eq 1 ]] && echo pass || echo fail))"
  fi
}

run_case live "${INSTALL}" pass

# M1: a private copy that ignores the configured path and hardcodes one.
cp "${INSTALL}" "${WORKDIR}/m1.sh"
sed -i.bak 's|^LoadCredential=ech-keys.json:\${WINN3_GATEWAY_ECH_KEYS}$|LoadCredential=ech-keys.json:/etc/winn/credentials/ech-keys.json|' "${WORKDIR}/m1.sh"
if cmp -s "${INSTALL}" "${WORKDIR}/m1.sh"; then
  fail "M1 mutation did not apply (the anchor line moved)"
else
  run_case M1-hardcoded "${WORKDIR}/m1.sh" fail
fi

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
