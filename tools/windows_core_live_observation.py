#!/usr/bin/env python3
"""Sanitized, read-only live Double VPN observation relayed through the hub."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import stat
import subprocess
import sys


TARGET = r'''import base64,glob,hashlib,json,pathlib,re,subprocess,time
ctx=json.loads(base64.b64decode(__import__("os").environ["WINS_CORE_OBSERVE_B64"],validate=True))
duration=max(20,min(180,int(ctx["duration_seconds"])))
def run(args,timeout=15):
 try:return subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
 except Exception:return type("R",(),{"returncode":255,"stdout":"","stderr":""})()
def interfaces():
 p=run(["ip","-j","addr","show"]);matches=[]
 if p.returncode==0:
  for item in json.loads(p.stdout):
   for address in item.get("addr_info") or []:
    if address.get("family")=="inet" and str(address.get("local") or "")==ctx["gateway"]:matches.append(str(item.get("ifname") or ""))
 return matches
def stats(name):
 root=pathlib.Path("/sys/class/net")/name/"statistics";out={}
 for key in ("rx_bytes","tx_bytes","rx_packets","tx_packets","rx_dropped","tx_dropped","rx_errors","tx_errors"):
  try:out[key]=int((root/key).read_text().strip())
  except Exception:out[key]=0
 return out
def listeners():
 p=run(["ss","-H","-lunt"]);ports=set()
 for line in p.stdout.splitlines():
  fields=line.split()
  if len(fields)>4:
   value=fields[4]
   try:ports.add(int(value.rsplit(":",1)[1]))
   except Exception:pass
 return ports
def peer_snapshot():
 p=run(["docker","exec","wins-core-ingress","awg","show","core0","dump"]);matches=[]
 if p.returncode==0:
  for line in p.stdout.splitlines()[1:]:
   fields=line.split("\t")
   if len(fields)<7 or fields[0]!=ctx["client_public_key"]:continue
   allowed=[value.strip() for value in fields[3].split(",") if value.strip()]
   matches.append({"allowed_exact":allowed==[ctx["client_ip"]+"/32"],"allowed_digest":hashlib.sha256(",".join(sorted(allowed)).encode()).hexdigest().upper(),"handshake":int(fields[4] or 0),"rx":int(fields[5] or 0),"tx":int(fields[6] or 0)})
 return matches
def exit_peer_snapshot():
 p=run(["docker","exec","wins-core-exit-"+ctx["exit_iface"],"awg","show",ctx["exit_iface"],"dump"]);matches=[]
 if p.returncode==0:
  for line in p.stdout.splitlines()[1:]:
   fields=line.split("\t")
   if len(fields)<7:continue
   matches.append({"endpoint":str(fields[2] or ""),"handshake":int(fields[4] or 0),"rx":int(fields[5] or 0),"tx":int(fields[6] or 0)})
 return matches
def xray_exit_config():
 path=pathlib.Path("/usr/local/etc/xray/core-exits")/(ctx["exit_iface"]+".json")
 expected_port=43000+int(ctx["exit_iface"].replace("corex","",1));unit=run(["systemctl","show","--property=ExecStart","--value","wins-core-xray-exit@"+ctx["exit_iface"]+".service"]);unit_matches=unit.returncode==0 and str(path) in unit.stdout and "xray" in unit.stdout
 try:
  document=json.loads(path.read_text())
  inbound=[item for item in document.get("inbounds",[]) if item.get("tag")=="awg-local-in"]
  outbound=[item for item in document.get("outbounds",[]) if item.get("tag")=="vless-ws-out"]
  if len(inbound)!=1 or len(outbound)!=1:return {"read":True,"valid":False,"local_port":expected_port,"unit_matches":unit_matches}
  item=inbound[0];settings=item.get("settings") or {};stream=outbound[0].get("streamSettings") or {}
  valid=(item.get("listen")=="127.0.0.1" and item.get("protocol")=="tunnel" and settings.get("network")=="udp" and settings.get("address")=="127.0.0.1" and isinstance(item.get("port"),int) and 1<=item.get("port")<=65535 and outbound[0].get("protocol")=="vless" and stream.get("network")=="ws" and stream.get("security") in ("none","tls"))
  return {"read":True,"valid":bool(valid),"local_port":int(item.get("port") or 0),"unit_matches":unit_matches}
 except Exception:return {"read":False,"valid":False,"local_port":expected_port,"unit_matches":unit_matches}
def routing_snapshot():
 route=run(["ip","-4","route","get","1.1.1.1","from",ctx["client_ip"]])
 rule=run(["ip","-4","rule","show","priority",str(ctx["rule_priority"])])
 default=run(["ip","-4","route","show","default"])
 route_text=route.stdout.strip();rule_text=rule.stdout.strip();default_text=default.stdout.strip()
 return {"route_readable":route.returncode==0,"route_uses_exit_iface":bool(re.search(r"(?:^|\s)dev\s+"+re.escape(ctx["exit_iface"])+r"(?:\s|$)",route_text)),"rule_uses_expected_table":bool(re.search(r"(?:^|\s)lookup\s+"+str(ctx["table_id"])+r"(?:\s|$)",rule_text)),"default_wan_iface_digest":hashlib.sha256(default_text.encode()).hexdigest().upper(),"unexpected_direct_egress_route":route.returncode!=0 or not bool(re.search(r"(?:^|\s)dev\s+"+re.escape(ctx["exit_iface"])+r"(?:\s|$)",route_text))}
ingress=interfaces();exit_name=ctx["exit_iface"];xray_config=xray_exit_config()
before_in=stats(ingress[0]) if len(ingress)==1 else {};before_out=stats(exit_name);peer_before=peer_snapshot();exit_peer_before=exit_peer_snapshot();routing_before=routing_snapshot()
ports_before=listeners();start=int(time.time());deadline=time.time()+duration
while time.time()<deadline:time.sleep(min(1,max(0,deadline-time.time())))
after_in=stats(ingress[0]) if len(ingress)==1 else {};after_out=stats(exit_name);ports_after=listeners();peer_after=peer_snapshot();exit_peer_after=exit_peer_snapshot();routing_after=routing_snapshot()
def delta(after,before,key):return max(0,after.get(key,0)-before.get(key,0))
services={name:run(["systemctl","is-active",name]).stdout.strip()=="active" for name in ("docker.service","nginx.service","xray.service","wins-core-management-tunnel.service")}
services["assigned_exit_xray_service"]=run(["systemctl","is-active","wins-core-xray-exit@"+exit_name+".service"]).stdout.strip()=="active"
services["tcpdump_runnable_unprivileged"]=run(["timeout","1","tcpdump","-i","any","-nn","-c","1","tcp port 80"],timeout=3).returncode in (0,124)
transport="unknown"
ruleset=hashlib.sha256()
for rule_path in sorted(glob.glob("/var/lib/suricata/rules/*.rules")+glob.glob("/etc/suricata/rules/*.rules")):
 try:ruleset.update(rule_path.encode()+b"\0"+pathlib.Path(rule_path).read_bytes()+b"\0")
 except OSError:pass
try:
 value=pathlib.Path(ctx["transport_state_path"]).read_text()
 if "mode=direct" in value:transport="direct"
 elif "mode=stealth" in value:transport="stealth"
except Exception:pass
base_peer=peer_before[0] if len(peer_before)==1 else {};last_peer=peer_after[0] if len(peer_after)==1 else {};base_exit_peer=exit_peer_before[0] if len(exit_peer_before)==1 else {};last_exit_peer=exit_peer_after[0] if len(exit_peer_after)==1 else {};expected_loopback="127.0.0.1:"+str(xray_config.get("local_port") or 0)
if transport=="unknown" and last_exit_peer:transport="stealth" if last_exit_peer.get("endpoint")==expected_loopback else "direct"
print(json.dumps({"contract":"winsvpn-windows-core-live-observation-v1","duration_seconds":duration,"observation_window_nonce":ctx["observation_window_nonce"],"ingress_interface_match_count":len(ingress),"exit_interface_present":pathlib.Path('/sys/class/net',exit_name).exists(),"exact_ingress_peer_match_count_before":len(peer_before),"exact_ingress_peer_match_count_after":len(peer_after),"exact_ingress_allowed_ip":bool(last_peer.get("allowed_exact")),"exact_ingress_handshake_advanced":bool(base_peer and last_peer and last_peer.get("handshake",0)>base_peer.get("handshake",0)),"exact_ingress_peer_rx_delta":max(0,last_peer.get("rx",0)-base_peer.get("rx",0)),"exact_ingress_peer_tx_delta":max(0,last_peer.get("tx",0)-base_peer.get("tx",0)),"client_policy_rule_matches":routing_after["rule_uses_expected_table"],"client_route_uses_corex":routing_after["route_uses_exit_iface"],"unexpected_core_direct_egress":routing_after["unexpected_direct_egress_route"],"routing_stable":routing_before==routing_after,"default_wan_iface_digest":routing_after["default_wan_iface_digest"],"udp9210_listener_before":ctx["direct_port"] in ports_before,"udp9210_listener_after":ctx["direct_port"] in ports_after,"tcp80_listener_before":ctx["xray_port"] in ports_before,"tcp80_listener_after":ctx["xray_port"] in ports_after,"ingress_rx_bytes_delta":delta(after_in,before_in,"rx_bytes"),"ingress_tx_bytes_delta":delta(after_in,before_in,"tx_bytes"),"ingress_rx_packets_delta":delta(after_in,before_in,"rx_packets"),"ingress_tx_packets_delta":delta(after_in,before_in,"tx_packets"),"ingress_rx_drop_delta":delta(after_in,before_in,"rx_dropped"),"ingress_tx_drop_delta":delta(after_in,before_in,"tx_dropped"),"exit_rx_bytes_delta":delta(after_out,before_out,"rx_bytes"),"exit_tx_bytes_delta":delta(after_out,before_out,"tx_bytes"),"exit_rx_packets_delta":delta(after_out,before_out,"rx_packets"),"exit_tx_packets_delta":delta(after_out,before_out,"tx_packets"),"exit_rx_drop_delta":delta(after_out,before_out,"rx_dropped"),"exit_tx_drop_delta":delta(after_out,before_out,"tx_dropped"),"exit_peer_match_count_before":len(exit_peer_before),"exit_peer_match_count_after":len(exit_peer_after),"exit_peer_endpoint_loopback_matches_xray":bool(last_exit_peer and last_exit_peer.get("endpoint")==expected_loopback),"exit_peer_handshake_advanced":bool(base_exit_peer and last_exit_peer and last_exit_peer.get("handshake",0)>base_exit_peer.get("handshake",0)),"exit_peer_handshake_fresh_after":bool(last_exit_peer and 0<int(last_exit_peer.get("handshake",0)) and int(time.time())-int(last_exit_peer.get("handshake",0))<=150),"exit_peer_rx_delta":max(0,last_exit_peer.get("rx",0)-base_exit_peer.get("rx",0)),"exit_peer_tx_delta":max(0,last_exit_peer.get("tx",0)-base_exit_peer.get("tx",0)),"xray_exit_config_read":bool(xray_config.get("read")),"xray_exit_local_inbound_valid":bool(xray_config.get("valid")),"xray_exit_unit_matches_config_path":bool(xray_config.get("unit_matches")),"transport_mode":transport,"services":services,"peer_public_key_digest":ctx["peer_public_key_digest"],"allowed_ip_set_digest":ctx["allowed_ip_set_digest"],"observed_allowed_ip_set_digest":str(last_peer.get("allowed_digest") or ""),"entry_counter_before_digest":hashlib.sha256(json.dumps({"iface":before_in,"peer":peer_before},sort_keys=True,separators=(",",":")).encode()).hexdigest().upper(),"entry_counter_after_digest":hashlib.sha256(json.dumps({"iface":after_in,"peer":peer_after},sort_keys=True,separators=(",",":")).encode()).hexdigest().upper(),"exit_counter_before_digest":hashlib.sha256(json.dumps({"iface":before_out,"peer":exit_peer_before},sort_keys=True,separators=(",",":")).encode()).hexdigest().upper(),"exit_counter_after_digest":hashlib.sha256(json.dumps({"iface":after_out,"peer":exit_peer_after},sort_keys=True,separators=(",",":")).encode()).hexdigest().upper(),"suricata_ruleset_digest":ruleset.hexdigest().upper(),"expected_exit_identity_digest":ctx["expected_exit_identity_digest"],"observation_started_epoch":start,"observation_finished_epoch":int(time.time())},separators=(",",":"),sort_keys=True))'''


def sha(value: object) -> str:
    return hashlib.sha256(str(value or "").encode()).hexdigest().upper()


def owner_env(path: pathlib.Path) -> dict[str, str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        return {}
    result = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
            result[key] = value
    return result


def main() -> int:
    sudo_mode = os.getenv("WINS_CORE_SUDO_STDIN", "0") == "1"
    sudo_password = sys.stdin.readline(512).rstrip("\r\n") if sudo_mode else ""
    if sudo_mode and (not sudo_password or len(sudo_password) > 256 or "\x00" in sudo_password):
        raise SystemExit("invalid Core observer sudo credential")
    expected = {key: os.environ[key].strip().upper() for key in (
        "WINS_ACCOUNT_DIGEST", "WINS_DEVICE_DIGEST", "WINS_PUBLIC_KEY_DIGEST", "WINS_NODE_SLUG_DIGEST",
    )}
    if not all(re.fullmatch(r"[0-9A-F]{64}", value) for value in expected.values()):
        raise SystemExit("invalid observation digest contract")
    observation_nonce = os.environ["WINS_OBSERVATION_NONCE"].strip().lower()
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        observation_nonce,
    ):
        raise SystemExit("invalid observation nonce contract")
    duration = max(20, min(180, int(os.getenv("WINS_OBSERVE_SECONDS", "90"))))
    connection = sqlite3.connect("file:/root/vpn_auth/vpn_users.db?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        """select a.*,e.iface,e.table_id,c.management_host,c.management_user,c.tunnel_gateway_ipv4,
                         c.last_heartbeat,c.runtime_checked_at
           from double_vpn_assignments a
           join core_exit_peers e on e.core_id=a.core_id and e.exit_slug=a.exit_slug
           join core_servers c on c.core_id=a.core_id
           where a.status='active' and c.status='online' and c.management_status='ok' and c.runtime_ready=1"""
    ).fetchall()
    matches = [dict(row) for row in rows if
        sha(row["account_number"]) == expected["WINS_ACCOUNT_DIGEST"] and
        sha(row["device_id"]) == expected["WINS_DEVICE_DIGEST"] and
        sha(row["client_public_key"]) == expected["WINS_PUBLIC_KEY_DIGEST"] and
        sha(row["exit_slug"]) == expected["WINS_NODE_SLUG_DIGEST"]]
    connection.close()
    if len(matches) != 1:
        raise SystemExit("Double assignment digest match is not unique")
    row = matches[0]
    host = str(row["management_host"] or "").strip().lower()
    user = str(row["management_user"] or "ubuntu").strip().lower()
    iface = str(row["iface"] or "")
    gateway = str(row["tunnel_gateway_ipv4"] or "")
    if not re.fullmatch(r"corex[0-9]+", iface) or not gateway:
        raise SystemExit("Double runtime identifiers are invalid")
    known = pathlib.Path("/root/vpn_auth/managed_known_hosts")
    if not any(line.split(None, 1)[0] == host for line in known.read_text().splitlines() if line.strip()):
        raise SystemExit("pinned Core target unavailable")
    context = {
        "duration_seconds": duration, "gateway": gateway, "exit_iface": iface,
        "client_public_key": str(row["client_public_key"] or ""),
        "client_ip": str(row["client_ip"] or ""),
        "table_id": int(row["table_id"] or 0),
        "rule_priority": 11000 + int(row["table_id"] or 0) - 52000,
        "transport_state_path": f"/etc/amnezia/wins-core/{iface}.transport",
        "direct_port": int(os.getenv("WINS_CORE_DIRECT_PORT", "9210")),
        "xray_port": int(os.getenv("WINS_CORE_XRAY_PORT", "80")),
        "peer_public_key_digest": expected["WINS_PUBLIC_KEY_DIGEST"],
        "allowed_ip_set_digest": sha(str(row["client_ip"]) + "/32"),
        "expected_exit_identity_digest": expected["WINS_NODE_SLUG_DIGEST"],
        "observation_window_nonce": observation_nonce,
    }
    command = ["ssh", "-i", "/root/.ssh/id_rsa", "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
        "-o", "ConnectionAttempts=1", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no"]
    if not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", host):
        command.extend(["-o", "ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h"])
    encoded_context = base64.b64encode(
        json.dumps(context, separators=(",", ":")).encode()
    ).decode()
    remote_command = "WINS_CORE_OBSERVE_B64=" + encoded_context + " python3 -"
    input_text = TARGET
    if sudo_mode:
        remote_command = (
            "sudo -S -p '' -- env WINS_CORE_OBSERVE_B64="
            + encoded_context + " python3 -"
        )
        input_text = sudo_password + "\n" + TARGET
    command.extend([f"{user}@{host}", remote_command])
    environment = os.environ.copy(); environment.update(owner_env(pathlib.Path("/root/vpn_auth/.env")))
    completed = subprocess.run(command, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=duration+60, check=False)
    if completed.returncode != 0:
        print(json.dumps({"ok": False, "error_type": "core_observation_failed"}, separators=(",", ":")))
        return 1
    result = json.loads(completed.stdout)
    if result.get("contract") != "winsvpn-windows-core-live-observation-v1":
        raise SystemExit("Core observation contract mismatch")
    pinned_lines = sorted(
        line.strip() for line in known.read_text().splitlines()
        if line.strip() and line.split(None, 1)[0] == host
    )
    result["observer_host_key_digest"] = sha("\n".join(pinned_lines))
    result["observer_identity_digest"] = sha(user + "@" + host)
    result["observer_authenticated"] = True
    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(seconds=180)).isoformat()
    result["assignment_revision_present"] = bool(
        re.fullmatch(r"[0-9a-f]{64}", str(row.get("applied_revision") or ""))
    )
    result["assignment_runtime_validated_fresh"] = bool(
        str(row.get("runtime_validated_at") or "") >= cutoff
    )
    result["core_registration_fresh"] = bool(
        str(row.get("last_heartbeat") or "") >= cutoff
        and str(row.get("runtime_checked_at") or "") >= cutoff
    )
    result["assignment_revision_ready"] = bool(
        result["assignment_revision_present"]
        and result["assignment_runtime_validated_fresh"]
        and result["core_registration_fresh"]
    )
    result["observation_window_nonce"] = observation_nonce
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
