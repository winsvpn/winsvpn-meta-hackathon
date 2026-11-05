#!/usr/bin/env bash
set -Eeuo pipefail

[[ "$(id -u)" == 0 ]] || {
  echo "Linux live tunnel assertions must run as root." >&2
  exit 77
}

bundle=/opt/wins-vpn
config=/run/wins-vpn-xray/client.json
state=/run/wins-vpn
[[ -x "$bundle/xray" && -x "$bundle/awg" && -s "$config" ]]
ip link show winsvpn >/dev/null

# One invocation proves exactly one advertised Xray port/security route.  The
# release collector must invoke this assertion once for every route in the
# hub-advertised manifest; accepting an implicit port here previously made a
# TCP/80 run look like proof of the complete fallback matrix.
expected_xray_port="${WINS_EXPECT_XRAY_PORT:-}"
expected_xray_security="${WINS_EXPECT_XRAY_SECURITY:-}"
expected_awg_destination_port="${WINS_EXPECT_AWG_DESTINATION_PORT:-9110}"
if [[ ! "${expected_xray_port}" =~ ^[1-9][0-9]{0,4}$ ]] \
  || (( 10#${expected_xray_port} > 65535 )); then
  echo "WINS_EXPECT_XRAY_PORT must name the exact advertised route under test." >&2
  exit 64
fi
case "${expected_xray_security}" in
  none|tls) ;;
  *)
    echo "WINS_EXPECT_XRAY_SECURITY must be none or tls for the exact advertised route under test." >&2
    exit 64
    ;;
esac
if [[ ! "${expected_awg_destination_port}" =~ ^[1-9][0-9]{0,4}$ ]] \
  || (( 10#${expected_awg_destination_port} > 65535 )); then
  echo "WINS_EXPECT_AWG_DESTINATION_PORT must name the exact runtime AWG destination." >&2
  exit 64
fi

python3 - "$config" "${expected_xray_port}" "${expected_xray_security}" \
  "${expected_awg_destination_port}" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
expected_port = int(sys.argv[2])
expected_security = sys.argv[3]
expected_awg_port = int(sys.argv[4])
outbounds = data.get("outbounds") or []
assert 1 <= len(outbounds) <= 16
ports = set()
security = set()
tags = set()
for outbound in outbounds:
    assert outbound["protocol"] == "vless"
    vnext = outbound["settings"]["vnext"]
    assert len(vnext) == 1
    ports.add(vnext[0]["port"])
    stream = outbound["streamSettings"]
    security.add(stream["security"])
    ws = stream["wsSettings"]
    assert ws["host"]
    assert ws["headers"]["Host"] == ws["host"]
    tag = outbound["tag"]
    assert tag and tag not in tags
    tags.add(tag)
assert ports == {expected_port}
assert security == {expected_security}
inbound = data["inbounds"][0]
assert inbound["listen"] in {"127.0.0.1", "::1", "localhost"}
assert inbound["settings"]["port"] == expected_awg_port
print(f"XRAY_ROUTE_PORT={expected_port}")
print(f"XRAY_ROUTE_SECURITY={expected_security}")
print(f"XRAY_EDGE_OUTBOUND_COUNT={len(outbounds)}")
print("XRAY_EXACT_ADVERTISED_ROUTE=PASS")
print("XRAY_CURRENT_AND_COMPAT_HOST_FIELDS=PASS")
print(f"XRAY_AWG_DESTINATION_PORT={expected_awg_port}")
print("XRAY_DYNAMIC_AWG_DESTINATION=PASS")
PY

xray_runtime_ready() {
  local xray_uid xray_pid
  xray_uid="$(id -u winsvpn-xray 2>/dev/null || true)"
  [[ "$xray_uid" =~ ^[1-9][0-9]*$ \
    && "$xray_uid" -lt 1000 && "$xray_uid" -ne 999 ]] || return 1
  xray_pid="$(cat /run/wins-vpn-xray/xray.pid 2>/dev/null || true)"
  [[ "$xray_pid" =~ ^[1-9][0-9]*$ && -e "/proc/$xray_pid/exe" ]] || return 1
  [[ "$(readlink -f "/proc/$xray_pid/exe" 2>/dev/null || true)" == "$bundle/xray" ]] || return 1
  [[ "$(awk '/^Uid:/ {print $2}' "/proc/$xray_pid/status" 2>/dev/null || true)" == "$xray_uid" ]] || return 1
  grep -Fq 'Xray 26.9.30 started' /run/wins-vpn-xray/xray.log 2>/dev/null || return 1
  grep -Eq "accepted udp:(127\\.0\\.0\\.1|\\[::1\\]):${expected_awg_destination_port}" \
    /run/wins-vpn-xray/xray.log 2>/dev/null || return 1
}
xray_ready=0
for _ in {1..20}; do
  if xray_runtime_ready; then
    xray_ready=1
    break
  fi
  sleep 1
done
[[ "$xray_ready" == 1 ]] || {
  echo "The locked Xray runtime did not settle within 20 seconds." >&2
  exit 1
}
xray_uid="$(id -u winsvpn-xray)"
[[ "$xray_uid" =~ ^[1-9][0-9]*$ && "$xray_uid" -lt 1000 ]]
echo "XRAY_LOCKED_IDENTITY_RUNTIME=PASS"

endpoint="$($bundle/awg show winsvpn endpoints | cut -f2)"
[[ "$endpoint" == 127.0.0.1:* || "$endpoint" == '[::1]:'* ]]
handshake="$($bundle/awg show winsvpn latest-handshakes | cut -f2)"
[[ "$handshake" =~ ^[1-9][0-9]*$ ]]
(( $(date +%s) - handshake <= 180 ))
read -r rx_bytes tx_bytes < <($bundle/awg show winsvpn transfer | cut -f2,3)
[[ "$rx_bytes" =~ ^[1-9][0-9]*$ && "$tx_bytes" =~ ^[1-9][0-9]*$ ]]
echo "AWG_XRAY_LOOPBACK_CARRIER=PASS"
echo "AWG_RECENT_HANDSHAKE_AND_TRAFFIC=PASS"

ip -4 route get 1.1.1.1 | grep -Eq ' dev winsvpn( |$)'
xray_mark="$(cat "$state/xray-mark")"
if ip -4 route get 1.1.1.1 mark "$xray_mark" uid "$xray_uid" |
  grep -Eq ' dev winsvpn( |$)'; then
  echo "Xray outer packets recurse into the VPN route." >&2
  exit 1
fi
iptables -t mangle -C OUTPUT -m owner --uid-owner "$xray_uid" \
  -m comment --comment winsvpn-xray-bypass -j MARK --set-mark "$xray_mark"
echo "ORDINARY_ROUTE_PROTECTED=PASS"
echo "XRAY_OUTER_ROUTE_NON_RECURSIVE=PASS"

resolvectl status winsvpn | grep -Fq 'DNS Servers: 10.8.1.1'
getent ahostsv4 example.com >/dev/null
echo "TUNNEL_DNS_RESOLUTION=PASS"

declare -a canaries=(
  'https://api.ipify.org'
  'https://ifconfig.me/ip'
  'https://icanhazip.com'
)
declare -a values=()
for url in "${canaries[@]}"; do
  value="$(curl --proto '=https' --tlsv1.2 -4fsS --interface winsvpn \
    --max-time 12 "$url" | tr -d '[:space:]')"
  [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]
  values+=("$value")
done
[[ "${values[0]}" == "${values[1]}" && "${values[0]}" == "${values[2]}" ]]
printf 'PROTECTED_EGRESS_SHA256=%s\n' \
  "$(printf '%s' "${values[0]}" | sha256sum | cut -d' ' -f1)"
echo "PROTECTED_EGRESS_CANARIES_AGREE=PASS"

if curl --proto '=https' --tlsv1.2 -6fsS --max-time 5 \
  https://api64.ipify.org >/dev/null 2>&1; then
  echo "Unexpected public IPv6 path while the IPv4-only tunnel is active." >&2
  exit 1
fi
echo "PUBLIC_IPV6_LEAK_BLOCKED=PASS"
