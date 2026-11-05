#!/usr/bin/env bash
set -u

printf '%s\n' '=== services ==='
systemctl is-active xray 2>/dev/null || true
systemctl is-active wins-core-sync.timer 2>/dev/null || true
systemctl is-active nginx 2>/dev/null || true

printf '%s\n' '=== xray unit ==='
systemctl show xray -p FragmentPath -p ExecStart -p User --no-pager 2>/dev/null || true

printf '%s\n' '=== sanitized xray config ==='
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

path = Path("/usr/local/etc/xray/config.json")
print("path=", path, "exists=", path.exists())
if not path.exists():
    raise SystemExit(0)

config = json.loads(path.read_text())
for index, inbound in enumerate(config.get("inbounds", [])):
    stream = inbound.get("streamSettings") or {}
    websocket = stream.get("wsSettings") or {}
    clients = (inbound.get("settings") or {}).get("clients") or []
    hashes = [
        hashlib.sha256(str(client.get("id", "")).encode()).hexdigest()[:12]
        for client in clients
        if client.get("id")
    ]
    print(
        "inbound", index,
        "tag=", inbound.get("tag"),
        "protocol=", inbound.get("protocol"),
        "listen=", inbound.get("listen"),
        "port=", inbound.get("port"),
        "network=", stream.get("network"),
        "security=", stream.get("security"),
        "path=", websocket.get("path"),
        "clients=", len(clients),
        "id_hashes=", ",".join(hashes),
    )
for index, outbound in enumerate(config.get("outbounds", [])):
    print(
        "outbound", index,
        "tag=", outbound.get("tag"),
        "protocol=", outbound.get("protocol"),
    )
print("routing_rules=", len((config.get("routing") or {}).get("rules") or []))
print("log=", config.get("log"))
PY

printf '%s\n' '=== xray validation/version ==='
/usr/local/bin/xray version 2>/dev/null | head -n 2 || xray version 2>/dev/null | head -n 2 || true
/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json 2>&1 \
    | sed -E 's/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}/<uuid>/g' || true

printf '%s\n' '=== listening ports ==='
ss -lntup 2>/dev/null \
    | awk 'NR==1 || /:80 |:80$|:443 |:443$|:9210 |:9210$|:1808[01] |:1808[01]$|:10000 |:10000$/' || true

printf '%s\n' '=== core0 peer state ==='
if command -v awg >/dev/null 2>&1; then
    vpn_tool=awg
elif command -v wg >/dev/null 2>&1; then
    vpn_tool=wg
else
    vpn_tool=
fi
if [[ -n "$vpn_tool" ]]; then
    "$vpn_tool" show core0 allowed-ips 2>/dev/null | awk '{print "allowed_ip=" $2}' || true
    "$vpn_tool" show core0 latest-handshakes 2>/dev/null \
        | awk '{print "peer_index=" NR, "handshake_epoch=" $2}' || true
    "$vpn_tool" show core0 transfer 2>/dev/null \
        | awk '{print "peer_index=" NR, "rx=" $2, "tx=" $3}' || true
else
    echo no_awg_or_wg_command
fi

printf '%s\n' '=== interfaces/routes ==='
ip -br addr show core0 corex3 2>/dev/null || true
ip route show table all 2>/dev/null | grep -E '10\.9\.1\.|core0|corex3' | head -n 40 || true

printf '%s\n' '=== reverse proxy hints ==='
nginx -T 2>/dev/null \
    | grep -E 'listen |location |proxy_pass|wins-core-tunnel|server_name' \
    | head -n 80 || true

printf '%s\n' '=== recent xray journal ==='
journalctl -u xray --since '-30 minutes' --no-pager -n 100 2>/dev/null \
    | sed -E 's/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}/<uuid>/g' || true

printf '%s\n' '=== sync units ==='
systemctl show wins-core-sync.service -p FragmentPath -p ExecStart -p User --no-pager 2>/dev/null || true
systemctl show wins-core-sync.timer -p FragmentPath -p NextElapseUSecRealtime -p LastTriggerUSec --no-pager 2>/dev/null || true
