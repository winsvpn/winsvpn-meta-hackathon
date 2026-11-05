#!/usr/bin/env bash
# Lane L54 / L51 C1: the data-plane installer must render the same runtime
# firewall whether or not winn3gw0 exists at install time, and v3 must never be
# placed under the AWG abuse policy (WINVPN-FORWARD / WINVPN-MANGLE-FORWARD).
# Owner ruling 2026-09-26: v3 stays under WINN3GW-FORWARD only.
#
# Method (lane L49 rev2 render harness): execute only the transaction-building
# part of write_runtime_vpn_firewall_unit with `ip` and `install` stubbed, then
# apply the installer's three @...@ substitutions to the verbatim script
# heredoc. Nothing touches the host firewall.
#
# The rendered wins-vpn-firewall is compared with the certified live fleet
# script (lane L49 rev2 FW converge, VERIFY PASS 2026-09-26): fixtures
# tools/fixtures/certified_runtime_fw/wins-vpn-firewall.{ens3,eth0}. The repo
# script additionally carries the transaction-guarded discovery block from
# 480b459 (certified); the comparison removes exactly that block and requires
# the remainder to be byte-identical, and separately proves the block is inert
# (the transaction has no winn3gw0 rule for its grep to find).
#
# usage: tools/test_runtime_fw_render_winn3_absent_policy.sh [installer]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INST="${1:-${ROOT}/server/wins_data_plane_setup_ONETOUCH.sh}"
FIX="${ROOT}/tools/fixtures/certified_runtime_fw"
declare -A FIX_SHA=(
  [ens3]=d82185487b5af15361a5bed17fc3d6acf9cc80ea2269fe2ae95ea09d45f05dd0
  [eth0]=e767e69945ee958b77831a3c54d4efac1d0e72a6a33a38520b009ef12d467f94
)

WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT
failures=0
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; failures=$((failures + 1)); }
sha() { shasum -a 256 "$1" | awk '{print $1}'; }

render() { # render <outdir> <wan_if> "<devices present>" ["<VPN_INTERFACES>"]
  local out="$1" wan="$2" present="$3" vpn_ifaces="${4:-awg0 amn0}" start txn_install hd_start hd_end fn
  mkdir -p "${out}"
  start="$(grep -n '^write_runtime_vpn_firewall_unit() {$' "${INST}" | cut -d: -f1)"
  [[ -n "${start}" ]] || return 1
  txn_install="$(awk -v s="${start}" 'NR>s && /install -m 600 -o root -g root "\$\{transaction_tmp\}" \/root\/wins-forward-nat.transaction/ {print NR; exit}' "${INST}")"
  hd_start="$(awk -v s="${start}" 'NR>s && /cat > "\$\{script_tmp\}" <<.WINS_VPN_FW_EOF./ {print NR; exit}' "${INST}")"
  hd_end="$(awk -v s="${hd_start:-0}" 'NR>s && /^WINS_VPN_FW_EOF$/ {print NR; exit}' "${INST}")"
  [[ -n "${txn_install}" && -n "${hd_start}" && -n "${hd_end}" ]] || return 1
  fn="${out}/fn.sh"
  {
    sed -n "${start},$((txn_install - 1))p" "${INST}"
    echo '  cp "${transaction_tmp}" "${L54_OUT}/wins-forward-nat.transaction"; rm -f -- "${transaction_tmp}"'
    echo '  printf "%s\n" "${ifaces[*]}" > "${L54_OUT}/ifaces"; printf "%s\n" "${vpn_cidr}" > "${L54_OUT}/vpn_cidr"'
    echo '}'
  } > "${fn}"
  L54_OUT="${out}" L54_PRESENT="${present}" WAN_IF="${wan}" VPN_INTERFACES="${vpn_ifaces}" bash -c '
    set -uo pipefail
    ip() { if [[ "$1" == link && "$2" == show ]]; then [[ " ${L54_PRESENT} " == *" $3 "* ]]; return; fi; return 1; }
    log() { :; }; warn() { :; }; err() { :; }
    source "$1"
    write_runtime_vpn_firewall_unit
  ' _ "${fn}" || return 1
  sed -n "$((hd_start + 1)),$((hd_end - 1))p" "${INST}" \
    | IF="$(cat "${out}/ifaces")" W="${wan}" C="$(cat "${out}/vpn_cidr")" \
      perl -pe 's/\@WINVPN_FW_IFACES\@/$ENV{IF}/g; s/\@WINVPN_FW_WAN_IF\@/$ENV{W}/g; s/\@WINVPN_FW_VPN_CIDR\@/$ENV{C}/g' \
    > "${out}/wins-vpn-firewall"
  ! grep -q '@WINVPN_FW_[A-Z_]*@' "${out}/wins-vpn-firewall"
}

# Repo-only blocks not yet on the certified live script: the 480b459
# transaction-guarded discovery block and the SPFW-I1 "2b" foreign-jump prune
# (its text is pinned below by SPFW_BLOCK_SHA; the strip removes the block and
# the single blank line that follows its closing `fi`).
SPFW_BLOCK_SHA=7b870aa84564cb8c93a618d9921155f73b7b09114dac9ddac2d868fe7b7fd166
# Design v17 2.2 item 1 (slice S3): the shared firewall lock block, from its
# comment through the `fi` of `if ! wins_fw_lock`, pinned by LOCK_BLOCK_SHA.
# The block also carries the Cloudflare fetch, moved ahead of the lock
# (S3-PERF-2); the comparison drops that one line from the fixture as well.
CF_FETCH_LINE='WINVPN_FW_CF="$("${CURL_BIN}" -fsS --max-time 10 "${WINVPN_FW_CF_URL}" 2>/dev/null | tr '"'"'\n'"'"' '"'"' '"'"')" || WINVPN_FW_CF=""'
LOCK_BLOCK_SHA=bf5a5ff74a2a0e7cd0462ba451074ea00bc4482286bf94bd0d339b5e809a5c51
# Audit L04-dp F-2: the stealth chain builder replaces the referenced chain in
# one iptables-restore commit instead of flush-then-append. The repo block,
# from its comment through the function's closing brace, is pinned by
# STEALTH_BLOCK_SHA; the certified fixture's older flush-based builder is
# stripped from the fixture side of the comparison.
STEALTH_BLOCK_SHA=c4170b336487f18419f7606999a075bc3b002fd57c4dee846c50524be4359e47
strip_guard() { # remove the 480b459 guard block, the SPFW-I1 2b block, the S3 lock block and the F-2 stealth builder
  awk '
    /^# A device that appeared after install/ { skip = 1 }
    skip == 1 && /^done$/ { skip = 0; next }
    /^# 2b\. Round SPFW \(SPFW-I1\)/ { skip = 2 }
    skip == 2 && /^fi$/ { skip = 3; next }
    /^# Design v17 2\.2 item 1: everything below rewrites live chains/ { skip = 4 }
    skip == 4 && /^fi$/ { skip = 3; next }
    skip == 3 { skip = 0; if ($0 == "") next }
    /^# Atomically replace the entire referenced chain\./ { skip = 5 }
    skip == 5 && /^}$/ { skip = 0; next }
    !skip { print }
  ' "$1"
}
strip_fixture_stealth() { # remove the certified flush-based stealth builder from the fixture
  awk '
    /^# Rebuild the chain so that it is never LESS closed than its final state/ { skip = 1 }
    skip == 1 && /^}$/ { skip = 0; next }
    !skip { print }
  ' "$1"
}
stealth_block() { # print the F-2 stealth builder, first comment line through its closing brace
  awk '
    /^# Atomically replace the entire referenced chain\./ { on = 1 }
    on { print }
    on && /^}$/ { exit }
  ' "$1"
}
lock_block() { # print the S3 lock block, first line through the `fi` of `if ! wins_fw_lock`
  awk '
    /^# Design v17 2\.2 item 1: everything below rewrites live chains/ { on = 1 }
    on { print }
    on && /^fi$/ { exit }
  ' "$1"
}
spfw_block() { # print the SPFW-I1 2b block, first line through its closing `fi`
  awk '
    /^# 2b\. Round SPFW \(SPFW-I1\)/ { on = 1 }
    on { print }
    on && /^fi$/ { exit }
  ' "$1"
}

[[ -f "${INST}" ]] || { echo "installer not found: ${INST}" >&2; exit 2; }

# The edge generator (wins-edge-hardening heredoc) must build its list from
# VPN_INTERFACES only: no install-time device discovery, no winn3gw0 default.
gen="${WORK}/wins-edge-hardening"
awk '/cat > \/usr\/local\/bin\/wins-edge-hardening <<.WINS_EDGE_EOF./ {on=1; next} on && /^WINS_EDGE_EOF$/ {exit} on {print}' "${INST}" > "${gen}"
if [[ ! -s "${gen}" ]]; then
  fail "generator heredoc not found"
else
  if grep -nE '^[[:space:]]*for [a-z_]+ in [^;]*winn3gw0' "${gen}" >/dev/null; then
    fail "generator iterates a list naming winn3gw0: $(grep -nE '^[[:space:]]*for [a-z_]+ in [^;]*winn3gw0' "${gen}" | tr '\n' ' ')"
  else
    pass "generator has no interface loop naming winn3gw0"
  fi
fi

for wan in ens3 eth0; do
  absent="${WORK}/absent_${wan}"; present="${WORK}/present_${wan}"; override="${WORK}/override_${wan}"
  if ! render "${absent}" "${wan}" "awg0 amn0 ${wan}" \
      || ! render "${present}" "${wan}" "awg0 amn0 winn3gw0 ${wan}" \
      || ! render "${override}" "${wan}" "awg0 amn0 winn3gw0 ${wan}" "awg0 amn0 winn3gw0"; then
    fail "${wan}: render failed (installer markers moved?)"
    continue
  fi
  # override: an operator VPN_INTERFACES that names winn3gw0 must not move v3
  # under the WINVPN chains either.
  for case_dir in "${absent}" "${present}" "${override}"; do
    label="${wan}/$(basename "${case_dir}" | cut -d_ -f1)"
    ifs="$(cat "${case_dir}/ifaces")"
    [[ "${ifs}" == "awg0 amn0" ]] && pass "${label}: interface list is 'awg0 amn0'" \
      || fail "${label}: interface list is '${ifs}', want 'awg0 amn0'"
    grep -qx 'WINVPN_FW_IFACES="${WINVPN_FW_IFACES:-awg0 amn0}"' "${case_dir}/wins-vpn-firewall" \
      && pass "${label}: script WINVPN_FW_IFACES is awg0 amn0" \
      || fail "${label}: script WINVPN_FW_IFACES is $(grep '^WINVPN_FW_IFACES=' "${case_dir}/wins-vpn-firewall")"
    n="$(grep -cE '^-A WINVPN-(MANGLE-)?FORWARD .*-[io] winn3gw0' "${case_dir}/wins-forward-nat.transaction")"
    [[ "${n}" == 0 ]] && pass "${label}: no winn3gw0 rule in WINVPN-FORWARD / WINVPN-MANGLE-FORWARD" \
      || fail "${label}: ${n} winn3gw0 rule(s) in WINVPN-FORWARD / WINVPN-MANGLE-FORWARD"
    n="$(grep -c 'winn3gw0' "${case_dir}/wins-forward-nat.transaction")"
    [[ "${n}" == 0 ]] && pass "${label}: transaction never names winn3gw0" \
      || fail "${label}: transaction names winn3gw0 ${n} time(s)"
  done
  cmp -s "${absent}/wins-forward-nat.transaction" "${present}/wins-forward-nat.transaction" \
    && pass "${wan}: transaction independent of install order ($(sha "${absent}/wins-forward-nat.transaction" | cut -c1-12))" \
    || fail "${wan}: transaction differs with winn3gw0 present ($(sha "${absent}/wins-forward-nat.transaction" | cut -c1-12) vs $(sha "${present}/wins-forward-nat.transaction" | cut -c1-12))"
  cmp -s "${absent}/wins-vpn-firewall" "${present}/wins-vpn-firewall" \
    && pass "${wan}: runtime script independent of install order" \
    || fail "${wan}: runtime script differs with winn3gw0 present"
  cmp -s "${absent}/wins-forward-nat.transaction" "${override}/wins-forward-nat.transaction" \
    && cmp -s "${absent}/wins-vpn-firewall" "${override}/wins-vpn-firewall" \
    && pass "${wan}: VPN_INTERFACES naming winn3gw0 renders the same pair" \
    || fail "${wan}: VPN_INTERFACES naming winn3gw0 changes the rendered pair"
  fixture="${FIX}/wins-vpn-firewall.${wan}"
  if [[ "$(sha "${fixture}")" != "${FIX_SHA[${wan}]}" ]]; then
    fail "${wan}: certified fixture hash changed ($(sha "${fixture}"))"
    continue
  fi
  n="$(grep -c '^# 2b\. Round SPFW (SPFW-I1)' "${present}/wins-vpn-firewall")"
  [[ "${n}" == 1 ]] && pass "${wan}: SPFW-I1 2b block present exactly once" \
    || fail "${wan}: SPFW-I1 2b block present ${n} time(s), want 1"
  block_sha="$(spfw_block "${present}/wins-vpn-firewall" | shasum -a 256 | awk '{print $1}')"
  [[ "${block_sha}" == "${SPFW_BLOCK_SHA}" ]] && pass "${wan}: SPFW-I1 2b block is the certified text ${SPFW_BLOCK_SHA:0:8}" \
    || fail "${wan}: SPFW-I1 2b block text changed (${block_sha:0:12}); re-certify SPFW-I1 before changing SPFW_BLOCK_SHA"
  n="$(grep -c '^# Design v17 2\.2 item 1: everything below rewrites live chains' "${present}/wins-vpn-firewall")"
  [[ "${n}" == 1 ]] && pass "${wan}: S3 lock block present exactly once" \
    || fail "${wan}: S3 lock block present ${n} time(s), want 1"
  block_sha="$(lock_block "${present}/wins-vpn-firewall" | shasum -a 256 | awk '{print $1}')"
  [[ "${block_sha}" == "${LOCK_BLOCK_SHA}" ]] && pass "${wan}: S3 lock block is the reviewed text ${LOCK_BLOCK_SHA:0:8}" \
    || fail "${wan}: S3 lock block text changed (${block_sha:0:12}); review it before changing LOCK_BLOCK_SHA"
  n="$(grep -cxF -- "${CF_FETCH_LINE}" "${fixture}")"
  [[ "${n}" == 1 ]] || fail "${wan}: certified fixture carries the Cloudflare fetch ${n} time(s), want 1"
  n="$(grep -cxF -- "${CF_FETCH_LINE}" "${present}/wins-vpn-firewall")"
  [[ "${n}" == 1 ]] || fail "${wan}: rendered script carries the Cloudflare fetch ${n} time(s), want 1"
  n="$(grep -c '^# Atomically replace the entire referenced chain\.' "${present}/wins-vpn-firewall")"
  [[ "${n}" == 1 ]] && pass "${wan}: F-2 stealth builder present exactly once" \
    || fail "${wan}: F-2 stealth builder present ${n} time(s), want 1"
  block_sha="$(stealth_block "${present}/wins-vpn-firewall" | shasum -a 256 | awk '{print $1}')"
  [[ "${block_sha}" == "${STEALTH_BLOCK_SHA}" ]] && pass "${wan}: F-2 stealth builder is the reviewed text ${STEALTH_BLOCK_SHA:0:8}" \
    || fail "${wan}: F-2 stealth builder text changed (${block_sha:0:12}); review it before changing STEALTH_BLOCK_SHA"
  if strip_guard "${present}/wins-vpn-firewall" | cmp -s - <(grep -vxF -- "${CF_FETCH_LINE}" "${fixture}" | strip_fixture_stealth /dev/stdin); then
    pass "${wan}: rendered script equals the certified live script ${FIX_SHA[${wan}]:0:8} apart from the 480b459 guard block, the SPFW-I1 2b block, the S3 lock block and the F-2 stealth builder"
  else
    fail "${wan}: rendered script differs from the certified live script ${FIX_SHA[${wan}]:0:8} beyond the guard, 2b, S3 lock and F-2 stealth builder blocks"
    strip_guard "${present}/wins-vpn-firewall" | diff - <(grep -vxF -- "${CF_FETCH_LINE}" "${fixture}" | strip_fixture_stealth /dev/stdin) | head -20
  fi
  if grep -q -- '^-A WINVPN-FORWARD -i winn3gw0 -o ' "${present}/wins-forward-nat.transaction"; then
    fail "${wan}: guard block would adopt winn3gw0 (transaction carries its egress rule)"
  else
    pass "${wan}: guard block is inert for winn3gw0 (no egress rule for its grep)"
  fi
done

if (( failures > 0 )); then
  printf '%d check(s) failed\n' "${failures}"
  exit 1
fi
echo "all checks passed"
