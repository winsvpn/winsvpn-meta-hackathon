#!/usr/bin/env bash
# Lane L54 / L51 C4: every installer writes /etc/winsvpn/owned-paths.<role>
# (the Wins-named paths its own source names) and its postflight reports each
# Wins-named path that no manifest lists. Report only: nothing is ever deleted.
#
# Runs the installers' own functions against a synthetic root (WINS_OWNED_ROOT)
# populated with a canada-shaped file set from lane L51's fleet inventory:
# files the installers write plus the hand-made extras L51 found there.
#
# usage: tools/test_installer_owned_paths_manifest.sh [repo_root]
set -uo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
S="${ROOT}/server"
DP="${S}/wins_data_plane_setup_ONETOUCH.sh"
# Slice S6: wins_winn3_gateway_install.sh is a tombstone and writes no manifest.
# The gateway's paths are named by the data-plane installer's block (design
# v17 2.2), so DP's manifest lists them.
CORE="${S}/wins_core_server_setup_ONETOUCH.sh"
HUB="${S}/wins_control_plane_setup_ONETOUCH.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT
failures=0
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; failures=$((failures + 1)); }

block() { # Compare shared definitions, excluding gateway provenance helpers.
  python3 -B - "${ROOT}/tools" "$1" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from winn3_gateway_block import segment
lines = Path(sys.argv[2]).read_text(encoding="utf-8").split("\n")
names = {"WINS_OWNED_PATHS_DIRS", "wins_owned_paths_from_source",
         "write_owned_paths_manifest", "report_unknown_owned_paths"}
found = set()
for item in segment(lines):
    if item["kind"] in ("assign", "func") and item["name"] in names:
        if item["name"] in found:
            raise SystemExit("duplicate owned-paths definition: " + item["name"])
        found.add(item["name"])
        body = "\n".join(lines[item["start"]:item["end"] + 1])
        # These two shell forms have identical behavior. G's spelling avoided
        # the former rulings scanner's treatment of /* as a block comment.
        body = body.replace('[[ "${path:0:1}" == / ]]', '[[ "${path}" == /* ]]')
        body = body.replace('"${root}${dir}/"*win[sn]*', '"${root}${dir}"/*win[sn]*')
        print(body)
if found != names:
    raise SystemExit("missing owned-paths definitions: " + ", ".join(sorted(names - found)))
PY
}

declare -A ROLE=([${DP}]=data-plane [${CORE}]=core [${HUB}]=control-plane)
if ! ref="$(block "${DP}")"; then
  fail "data-plane owned-paths definitions cannot be extracted"
  exit 1
fi
for inst in "${DP}" "${CORE}" "${HUB}"; do
  name="$(basename "${inst}")"
  if ! b="$(block "${inst}")"; then
    fail "${name}: owned-paths definitions cannot be extracted"
    continue
  fi
  if [[ -z "${b}" ]]; then
    fail "${name}: owned-paths block missing"
    continue
  fi
  [[ "${b}" == "${ref}" ]] && pass "${name}: owned-paths block identical to the data-plane copy" \
    || fail "${name}: owned-paths block differs from the data-plane copy"
  grep -qx "  write_owned_paths_manifest ${ROLE[${inst}]}" "${inst}" \
    && grep -qx '  report_unknown_owned_paths' "${inst}" \
    && pass "${name}: writes owned-paths.${ROLE[${inst}]} and reports unknown paths" \
    || fail "${name}: does not call write_owned_paths_manifest ${ROLE[${inst}]} / report_unknown_owned_paths"
done

[[ -n "${ref}" ]] || { printf '%d check(s) failed\n' "${failures}"; exit 1; }

HARNESS="${WORK}/harness.sh"
{
  echo 'set -euo pipefail'
  echo 'log() { echo "LOG $*"; }; warn() { echo "WARN $*"; }'
  printf '%s\n' "${ref}"
  echo '"$@"'
} > "${HARNESS}"

R="${WORK}/root"
# Present on canada per lane L51 (CONFORM/behind files the installers write).
OWNED=(
  /etc/fail2ban/jail.d/winsvpn-sshd.conf
  /etc/modprobe.d/winsvpn-awg-kmod-nodebug.conf
  /etc/modules-load.d/winsvpn-conntrack.conf
  /etc/sysctl.d/99-winsvpn-node.conf
  /etc/sysctl.d/99-winsvpn-edge.conf
  /etc/sysctl.d/60-winn3-gateway-forward.conf
  /etc/sysctl.d/60-winn3-gateway-udp-buffers.conf
  /etc/systemd/system/winn3-gateway.service
  /etc/systemd/system/winn3-gateway-firewall.service
  /etc/systemd/system/wins-vpn-firewall.service
  /etc/systemd/system/wins-node-management-tunnel.service
  /usr/local/bin/wins-edge-hardening
  /usr/local/sbin/wins-vpn-firewall
  /usr/local/sbin/winn3-gateway-firewall
  /usr/local/libexec/winn/winn3-gateway
)
# Slice S6: the retired standalone installer's own backup timer and script. Its
# maintenance was merged into the data plane's backup (design v17 2.1 E), so no
# installer names these two any more; they stay on old gateway nodes, reported
# and never removed.
RETIRED=(
  /etc/systemd/system/wins-gateway-backup.timer
  /usr/local/bin/wins-gateway-backup
)
# Hand-made on canada per lane L51 (class d EXTRA): no installer names them.
EXTRA=(
  /etc/modules-load.d/wins-bbr.conf
  /etc/sysctl.d/60-winn3-gateway-pps.conf
  /etc/sysctl.d/60-winn3-gateway-wire-speed.conf
  /etc/sysctl.d/99-wins-network.conf
  /etc/systemd/system/winn-qdisc.service
  /etc/systemd/system/wins-network-tune.service
  /usr/local/libexec/winn/winn3-gateway.bak
  /usr/local/libexec/winn/winn3-gateway.old
  /usr/local/libexec/winn/winn3-gateway.rv39
  /usr/local/sbin/winn-install-qdisc
  /usr/local/sbin/wins-network-tune
)
# Not Wins-named, or outside the scanned directories: never reported.
IGNORED=(/etc/sysctl.d/10-network-security.conf /usr/local/etc/xray/config.json.bak /etc/winn/winn3-peers.json.bak)
for p in "${OWNED[@]}" "${RETIRED[@]}" "${EXTRA[@]}" "${IGNORED[@]}"; do
  mkdir -p "${R}$(dirname "${p}")"; printf 'x\n' > "${R}${p}"
done
before="$(cd "${R}" && find . -type f -not -path './etc/winsvpn/*' | LC_ALL=C sort | shasum -a 256)"

WINS_OWNED_ROOT="${R}" bash "${HARNESS}" write_owned_paths_manifest data-plane "${DP}" > "${WORK}/w1" 2>&1 \
  && pass "manifest written for data-plane" || fail "manifest write failed: $(tr '\n' ' ' < "${WORK}/w1")"
m="${R}/etc/winsvpn/owned-paths.data-plane"
if [[ -f "${m}" ]]; then
  mode="$(stat -f '%Lp' "${m}" 2>/dev/null || stat -c '%a' "${m}")"
  [[ "${mode}" == 644 ]] && pass "manifest mode 644" || fail "manifest mode ${mode}"
  first="$(shasum -a 256 < "${m}")"
  WINS_OWNED_ROOT="${R}" bash "${HARNESS}" write_owned_paths_manifest data-plane "${DP}" > /dev/null 2>&1
  [[ "$(shasum -a 256 < "${m}")" == "${first}" ]] && pass "manifest is deterministic" || fail "manifest changes between runs"
  grep -qx '/etc/systemd/system/wins-node-management-tunnel.service' "${m}" \
    && pass "a path named through a variable assignment is listed (wins-node-management-tunnel.service)" \
    || fail "wins-node-management-tunnel.service missing from the data-plane manifest"
fi

WINS_OWNED_ROOT="${R}" bash "${HARNESS}" report_unknown_owned_paths > "${WORK}/rep" 2>&1
rc=$?
[[ "${rc}" == 0 ]] && pass "report returns 0 (report only)" || fail "report returned ${rc}"
got="$(sed -n 's/^WARN Unknown Wins-named path (no installer manifest lists it; reported, not removed): //p' "${WORK}/rep" | LC_ALL=C sort)"
want="$(printf '%s\n' "${EXTRA[@]}" "${RETIRED[@]}" | LC_ALL=C sort)"
if [[ "${got}" == "${want}" ]]; then
  pass "reports exactly the $((${#EXTRA[@]} + ${#RETIRED[@]})) hand-made extras and retired standalone paths"
else
  fail "reported set differs"
  diff <(printf '%s\n' "${want}") <(printf '%s\n' "${got}") | sed 's/^/  /'
fi
grep -q "Owned-paths check: $((${#EXTRA[@]} + ${#RETIRED[@]})) unknown Wins-named path(s) against 1 manifest(s)." "${WORK}/rep" \
  && pass "summary line counts extras and manifests" || fail "summary line wrong: $(tail -1 "${WORK}/rep")"
after="$(cd "${R}" && find . -type f -not -path './etc/winsvpn/*' | LC_ALL=C sort | shasum -a 256)"
[[ "${after}" == "${before}" && -e "${R}/usr/local/libexec/winn/winn3-gateway.bak" ]] \
  && pass "nothing was deleted or changed outside /etc/winsvpn" || fail "files changed during the report"

if (( failures > 0 )); then
  printf '%d check(s) failed\n' "${failures}"
  exit 1
fi
echo "all checks passed"
