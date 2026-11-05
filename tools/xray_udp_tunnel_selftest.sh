#!/usr/bin/env bash
set -euo pipefail

xray_binary="${XRAY_BINARY:-/usr/local/bin/xray}"
source_config="${XRAY_SOURCE_CONFIG:-/usr/local/etc/xray/config.json}"
xudp_mode="${XRAY_SELFTEST_XUDP:-0}"
[[ "${xudp_mode}" == "0" || "${xudp_mode}" == "1" ]] || {
  echo "XRAY_SELFTEST_XUDP must be 0 or 1." >&2
  exit 2
}
work_dir="$(mktemp -d)"
server_pid=""
client_pid=""
receiver_pid=""

cleanup() {
  [[ -z "${client_pid}" ]] || kill "${client_pid}" >/dev/null 2>&1 || true
  [[ -z "${server_pid}" ]] || kill "${server_pid}" >/dev/null 2>&1 || true
  [[ -z "${receiver_pid}" ]] || kill "${receiver_pid}" >/dev/null 2>&1 || true
  rm -rf "${work_dir}"
}
trap cleanup EXIT

uuid="$(python3 - "${source_config}" <<'PY'
import json
import sys

config = json.load(open(sys.argv[1], encoding="utf-8"))
for inbound in config.get("inbounds", []):
    if inbound.get("protocol") != "vless":
        continue
    for client in (inbound.get("settings") or {}).get("clients") or []:
        if client.get("id"):
            print(client["id"])
            raise SystemExit(0)
raise SystemExit("No VLESS client identity is present")
PY
)"

if [[ "${xudp_mode}" == "1" ]]; then
  mux_config='{"enabled":true,"concurrency":-1,"xudpConcurrency":16,"xudpProxyUDP443":"allow"}'
else
  mux_config='{"enabled":false}'
fi

cat >"${work_dir}/server.json" <<EOF
{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "tag": "selftest-server-in",
    "listen": "127.0.0.1",
    "port": 12110,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "${uuid}", "flow": ""}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": {"path": "/wins-core-selftest"}
    }
  }],
  "outbounds": [{
    "tag": "selftest-forward",
    "protocol": "freedom",
    "settings": {
      "redirect": "127.0.0.1:12111",
      "domainStrategy": "UseIPv4",
      "finalRules": [
        {"action": "allow", "network": "udp", "ip": ["127.0.0.1"], "port": "12111"}
      ]
    }
  }],
  "routing": {"rules": [{
    "type": "field",
    "inboundTag": ["selftest-server-in"],
    "outboundTag": "selftest-forward"
  }]}
}
EOF

cat >"${work_dir}/client.json" <<EOF
{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "tag": "selftest-client-in",
    "listen": "127.0.0.1",
    "port": 42111,
    "protocol": "tunnel",
    "settings": {
      "network": "udp",
      "address": "127.0.0.1",
      "port": 9210,
      "followRedirect": false,
      "userLevel": 0
    }
  }],
  "outbounds": [{
    "tag": "selftest-vless-out",
    "protocol": "vless",
    "settings": {"vnext": [{
      "address": "127.0.0.1",
      "port": 12110,
      "users": [{"id": "${uuid}", "encryption": "none", "level": 0}]
    }]},
    "streamSettings": {
      "network": "ws",
      "security": "none",
      "wsSettings": {
        "path": "/wins-core-selftest",
        "headers": {"Host": "localhost"}
      }
    },
    "mux": ${mux_config}
  }],
  "routing": {"rules": [{
    "type": "field",
    "inboundTag": ["selftest-client-in"],
    "outboundTag": "selftest-vless-out"
  }]}
}
EOF

"${xray_binary}" run -test -config "${work_dir}/server.json" >/dev/null 2>&1
"${xray_binary}" run -test -config "${work_dir}/client.json" >/dev/null 2>&1

python3 - "${work_dir}/received" <<'PY' &
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(8)
sock.bind(("127.0.0.1", 12111))
try:
    payload, source = sock.recvfrom(1024)
    if payload == b"wins-xray-udp-selftest":
        sock.sendto(payload, source)
        open(sys.argv[1], "w", encoding="utf-8").write("pass\n")
finally:
    sock.close()
PY
receiver_pid=$!

"${xray_binary}" run -config "${work_dir}/server.json" >"${work_dir}/server.log" 2>&1 &
server_pid=$!
"${xray_binary}" run -config "${work_dir}/client.json" >"${work_dir}/client.log" 2>&1 &
client_pid=$!
sleep 1

python3 - "${work_dir}/roundtrip" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(8)
try:
    payload = b"wins-xray-udp-selftest"
    sock.sendto(payload, ("127.0.0.1", 42111))
    reply, _ = sock.recvfrom(1024)
    if reply == payload:
        open(sys.argv[1], "w", encoding="utf-8").write("pass\n")
finally:
    sock.close()
PY

for _ in $(seq 1 40); do
  if [[ -s "${work_dir}/received" && -s "${work_dir}/roundtrip" ]]; then
    echo "XRAY_UDP_TUNNEL_SELFTEST=PASS xudp=${xudp_mode} roundtrip=PASS"
    exit 0
  fi
  sleep 0.2
done

echo XRAY_UDP_TUNNEL_SELFTEST=FAIL
printf '%s\n' '--- sanitized server log ---'
sed -E 's/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}/<uuid>/g' "${work_dir}/server.log" | tail -n 30
printf '%s\n' '--- sanitized client log ---'
sed -E 's/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}/<uuid>/g' "${work_dir}/client.log" | tail -n 30
exit 1
