#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "${WORK_DIR}"' EXIT

extract_function() {
  local source="$1" name="$2"
  awk -v name="${name}" '
    $0 == name "() {" { capture=1 }
    capture { print }
    capture && $0 == "}" { exit }
  ' "${source}"
}

for role in control core data; do
  case "${role}" in
    control) source="${ROOT_DIR}/server/wins_control_plane_setup_ONETOUCH.sh" ;;
    core) source="${ROOT_DIR}/server/wins_core_server_setup_ONETOUCH.sh" ;;
    data) source="${ROOT_DIR}/server/wins_data_plane_setup_ONETOUCH.sh" ;;
  esac
  harness="${WORK_DIR}/${role}-package-retry.sh"
  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
    extract_function "${source}" recover_package_state_for_retry
    extract_function "${source}" apt_retry
    cat <<'EOF'
events=()
original_attempts=0
configure_attempts=0
wait_for_package_manager() { events+=("wait"); }
warn() { events+=("warn:$*"); }
err() { events+=("err:$*"); }
sleep() { events+=("sleep:$1"); }
dpkg() {
  events+=("dpkg:$*")
  configure_attempts=$((configure_attempts + 1))
  ((configure_attempts > 1))
}
fake_apt() {
  events+=("apt:$*")
  if [[ "$*" == "install package-under-test" ]]; then
    original_attempts=$((original_attempts + 1))
    ((original_attempts > 1))
    return
  fi
  [[ "$*" == "-f install -y" ]]
}
APT_GET=(fake_apt)
apt_retry fake_apt install package-under-test
[[ "${original_attempts}" == "2" ]]
[[ "${configure_attempts}" == "2" ]]
[[ "${events[*]}" == *"apt:-f install -y"* ]]
[[ "${events[*]}" != *"attempt 2/3"* ]]
EOF
  } > "${harness}"
  bash -n "${harness}"
  bash "${harness}"
  echo "PASS ${role} repairs interrupted dpkg state before a bounded APT retry"
done

for source in \
  "${ROOT_DIR}/server/wins_control_plane_setup_ONETOUCH.sh" \
  "${ROOT_DIR}/server/wins_data_plane_setup_ONETOUCH.sh"; do
  grep -Fq "cloudflared tunnel run --help 2>&1 | grep -F -- '--token-file'" "${source}"
done
grep -Fq "\"\${install_path}\" tunnel run --help 2>&1 | grep -F -- '--token-file'" \
  "${ROOT_DIR}/server/wins_core_server_setup_ONETOUCH.sh"
echo "PASS every hidden-origin role verifies cloudflared token-file support before service cutover"

grep -Fq 'chown root:xray /usr/local/etc/xray /usr/local/etc/xray/config.json' \
  "${ROOT_DIR}/server/wins_data_plane_setup_ONETOUCH.sh"
grep -Fq 'chmod 640 /usr/local/etc/xray/config.json' \
  "${ROOT_DIR}/server/wins_data_plane_setup_ONETOUCH.sh"
grep -Fq 'install -d -m 750 -o root -g xray /usr/local/etc/xray' \
  "${ROOT_DIR}/server/wins_core_server_setup_ONETOUCH.sh"
grep -Fq 'chown root:xray /usr/local/etc/xray/config.json' \
  "${ROOT_DIR}/server/wins_core_server_setup_ONETOUCH.sh"
grep -Fq 'chmod 640 /usr/local/etc/xray/config.json' \
  "${ROOT_DIR}/server/wins_core_server_setup_ONETOUCH.sh"
echo "PASS data/Core Xray UUID-bearing configurations are root-owned and service-readable only"

python3 - \
  "${ROOT_DIR}/server/wins_control_plane_setup_ONETOUCH.sh" \
  "${ROOT_DIR}/server/wins_data_plane_setup_ONETOUCH.sh" \
  "${ROOT_DIR}/server/wins_core_server_setup_ONETOUCH.sh" <<'PYEOF'
from pathlib import Path
import re
import sys

control, data, core = (Path(path).read_text(encoding="utf-8") for path in sys.argv[1:])

if "88ed1862-be98-fb28-8d17-f1c64495c219" in control:
    raise SystemExit("control app still contains the legacy shared Xray UUID")
if 'XRAY_UUID = os.getenv("XRAY_UUID") or os.getenv("XRAYUUID") or ""' not in control:
    raise SystemExit("control app no longer fails empty instead of using a shared Xray UUID")

for role, source, setup_gate, bootstrap, first_listener in (
    ("data", data, "configure_node_management_tunnel", "apply_bootstrap_firewall", "install_awg"),
    ("core", core, "verify_hub_core_management", "apply_bootstrap_firewall", "install_awg_ingress"),
):
    main = source[source.rfind("\nmain() {"):]
    positions = []
    for name in (setup_gate, bootstrap, first_listener):
        # Match the *call site* in main(), not the first mention anywhere:
        # main() comments document the flow and name the same functions a
        # plain find() used to pick up (e.g. the data main() header comment
        # "calls install_awg() directly"), which made the ordering check
        # read the comment position instead of the call position.
        match = re.search(r"^  " + re.escape(name) + r"\s*$", main, flags=re.MULTILINE)
        positions.append(-1 if match is None else match.start())
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise SystemExit(
            f"{role} does not close the host firewall after management setup "
            f"and before its first public listener: {positions}"
        )

data_bootstrap = data[data.index("apply_bootstrap_firewall() {"):data.index("\n}\n\nsshd_effective_value_is()")]
for bootstrap_guard in (
    "set_public_vpn_ingress_admission 0",
    "PUBLIC_VPN_INGRESS_ADMISSION=0",
    "INSTALL_DATA_IDS_IPS=0",
):
    if bootstrap_guard not in data_bootstrap:
        raise SystemExit(
            f"data bootstrap firewall can admit public traffic before Suricata exists: {bootstrap_guard}"
        )
for recovery_guard in (
    'deployment_source="${SSH_CONNECTION:-}"',
    'deployment_source="${deployment_source%% *}"',
    'IONOS_HUB_IP="${deployment_source}"',
):
    if recovery_guard not in data:
        raise SystemExit(f"data bootstrap firewall loses its deployment-session recovery path: {recovery_guard}")
if not re.search(r"apply_bootstrap_firewall\(\).*?write_firewall 0 0", core, re.S):
    raise SystemExit("Core bootstrap firewall can enqueue traffic before Suricata exists")
write_firewall = core[core.find("write_firewall() {"):core.find("\n}\n\napply_bootstrap_firewall()")]
if write_firewall.count('[[ "${install_core_ids_ips}" == "1" ]]') != 2:
    raise SystemExit("Core firewall no longer keys its two IDS/IPS-on blocks (Suricata queue-0 health precheck, NFQUEUE queue rules) on the explicit mode")
if '&& "${install_core_ids_ips}" != "1"' not in write_firewall:
    raise SystemExit("Core public admission no longer refused when inline Suricata IDS/IPS is off")
if '&& "${public_vpn_ingress_admission}" == "1"' not in write_firewall:
    raise SystemExit("Core public listener accepts are not gated by explicit final admission")
data_edge_start = data.index("cat > /usr/local/bin/wins-edge-hardening")
data_edge = data[data_edge_start:data.index("\nWINS_EDGE_EOF\n", data_edge_start)]
# Since 45e7224 encrypted AmneziaWG UDP is accepted directly, before any
# NFQUEUE rule, and is never queued: Suricata cannot inspect it and queueing
# it cost drops and latency. Assert that property instead of the retired
# queue-then-accept pair.
def awg_udp_queue_problem(edge):
    rules = [line.strip() for line in edge.splitlines()
             if line.strip().startswith(("ipt -A WINVPN-INPUT", "append_filter -A WINVPN-INPUT"))]
    awg_accept = 'ipt -A WINVPN-INPUT -p udp --dport "${WG_PORT}" -j ACCEPT'
    queued = [i for i, rule in enumerate(rules) if '"${nfqueue_target[@]}"' in rule]
    if rules.count(awg_accept) != 1:
        return f"expected one AmneziaWG UDP ACCEPT, found {rules.count(awg_accept)}"
    if not queued:
        return "no NFQUEUE rule found; the ordering check would be vacuous"
    if rules.index(awg_accept) > queued[0]:
        return "AmneziaWG UDP ACCEPT sits below an NFQUEUE rule"
    for i in queued:
        if '"${WG_PORT}"' in rules[i] or "-p udp" in rules[i]:
            return f"a UDP or AmneziaWG port is queued to NFQUEUE: {rules[i]}"
    return None
problem = awg_udp_queue_problem(data_edge)
if problem:
    raise SystemExit(f"data public AWG UDP must be accepted before NFQUEUE and never queued: {problem}")
retired_queue = 'ipt -A WINVPN-INPUT -p udp --dport "${WG_PORT}" "${nfqueue_target[@]}"'
awg_accept_line = 'ipt -A WINVPN-INPUT -p udp --dport "${WG_PORT}" -j ACCEPT'
for mutant in (
    data_edge.replace(awg_accept_line, retired_queue + "\n    " + awg_accept_line, 1),
    data_edge.replace(awg_accept_line, "", 1) + "\n  " + awg_accept_line + "\n",
):
    if awg_udp_queue_problem(mutant) is None:
        raise SystemExit("AWG UDP never-queued check accepted a mutant; the check is vacuous")
if data_edge.count('if [[ "${PUBLIC_VPN_INGRESS_ADMISSION}" == "1" ]]') < 3:
    raise SystemExit("data public VPN/Xray/Nginx paths are not admission-gated")
PYEOF
echo "PASS data/Core bootstrap closes public admission and final ACCEPTs follow healthy NFQUEUE rules"
echo "PASS control no longer embeds a shared fallback Xray UUID"
