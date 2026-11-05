#!/usr/bin/env python3
"""Observe the active Core-to-exit AWG canary without exposing tunnel material.

Run ephemerally on the Control Hub.  The first stdin line is the Core sudo
password; it is forwarded only to sudo on the pinned managed Core connection.
The result contains booleans and counters, never keys, addresses, or endpoints.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys


def fail(kind: str) -> int:
    print(json.dumps({"ok": False, "error_type": kind}, separators=(",", ":")))
    return 1


def main() -> int:
    if os.geteuid() != 0:
        return fail("hub_root_required")
    password = sys.stdin.readline(512).rstrip("\r\n")
    if not password or len(password) > 256 or "\x00" in password:
        return fail("invalid_sudo_credential")

    database = pathlib.Path("/root/vpn_auth/vpn_users.db")
    known_hosts = pathlib.Path("/root/vpn_auth/managed_known_hosts")
    identity = pathlib.Path("/root/.ssh/id_rsa")
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT c.management_host AS host,
                   COALESCE(NULLIF(c.management_user,''),'ubuntu') AS user,
                   e.iface, n.wg_port
            FROM core_servers c
            JOIN core_exit_peers e ON e.core_id=c.core_id
            JOIN nodes n ON n.slug=e.exit_slug
            WHERE c.status='online' AND c.management_status='ok'
              AND n.slug='spain-madrid'
            ORDER BY c.core_id
            """
        ).fetchall()
        connection.close()
    except Exception:
        return fail("database_query_failed")
    if len(rows) != 1:
        return fail("managed_core_exit_not_unique")
    host = str(rows[0]["host"] or "").strip().lower()
    user = str(rows[0]["user"] or "").strip().lower()
    iface = str(rows[0]["iface"] or "").strip()
    port = int(rows[0]["wg_port"] or 0)
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        return fail("invalid_management_user")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
        return fail("invalid_management_host")
    if not re.fullmatch(r"corex[0-9]{1,3}", iface) or not (1 <= port <= 65535):
        return fail("invalid_exit_contract")
    if (
        not known_hosts.is_file()
        or known_hosts.is_symlink()
        or known_hosts.stat().st_mode & 0o077
        or not identity.is_file()
    ):
        return fail("unsafe_management_prerequisite")
    if not any(
        line.split(None, 1)[0] == host
        for line in known_hosts.read_text(encoding="utf-8", errors="strict").splitlines()
        if line.strip()
    ):
        return fail("pinned_host_key_missing")

    target = r'''import json,subprocess,time,os,re,pathlib
iface=os.environ["WINS_EXIT_IFACE"]
expected_port=int(os.environ["WINS_EXIT_PORT"])
def run(args,timeout=15):
 r=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,check=False)
 return r.returncode,r.stdout.strip()
def recovery_timing_metrics(journal_text):
 attempts=[]; pending={}; samples=[]
 start_pattern=re.compile(r"(?:^|\s)exit=(corex[0-9]{1,3}) recovering stale stealth handshake(?:\s|$)")
 recovered_pattern=re.compile(r"(?:^|\s)exit=(corex[0-9]{1,3}) stale stealth handshake recovered(?:\s|$)")
 for raw in journal_text.splitlines()[:1000]:
  try: item=json.loads(raw)
  except (ValueError,TypeError): continue
  message=item.get("MESSAGE")
  stamp=item.get("__REALTIME_TIMESTAMP")
  if not isinstance(message,str) or not str(stamp).isdigit(): continue
  micros=int(stamp)
  started=start_pattern.search(message)
  if started:
   attempts.append({"start":micros,"recovered":False})
   pending[started.group(1)]=len(attempts)-1
   continue
  recovered=recovered_pattern.search(message)
  if not recovered: continue
  index=pending.pop(recovered.group(1),None)
  if index is None or micros<attempts[index]["start"]: continue
  attempts[index]["recovered"]=True
  seconds=min(1800,max(0,(micros-attempts[index]["start"]+999999)//1000000))
  samples.append(seconds)
 return {
  "recovery_sample_count":min(500,len(samples)),
  "latest_recovery_seconds":samples[-1] if samples else 0,
  "max_recovery_seconds":max(samples or [0]),
  "latest_attempt_unrecovered":bool(attempts and not attempts[-1]["recovered"])
 }
rc,names=run(["docker","ps","--format","{{.Names}}"])
containers=[x for x in names.splitlines() if x.startswith("wins-core-exit-")]
dump=""; owner=""
for container in containers:
 code,text=run(["docker","exec",container,"awg","show",iface,"dump"])
 if code==0 and text:
  dump=text; owner=container; break
lines=dump.splitlines()
peers=[line.split("\t") for line in lines[1:] if line.strip()]
now=int(time.time())
endpoint_present=False; endpoint_port_ok=False; allowed_default=False
endpoint_loopback=False
handshakes=[]; rx=[]; tx=[]; keepalives=[]
for fields in peers:
 if len(fields)<8: continue
 endpoint=fields[2]
 endpoint_present=endpoint_present or bool(endpoint and endpoint!="(none)")
 endpoint_loopback=endpoint_loopback or endpoint.startswith("127.0.0.1:")
 m=re.search(r":([0-9]{1,5})$",endpoint)
 endpoint_port_ok=endpoint_port_ok or bool(m and int(m.group(1))==expected_port)
 allowed_default=allowed_default or fields[3]=="0.0.0.0/0"
 handshakes.append(int(fields[4] or 0)); rx.append(int(fields[5] or 0)); tx.append(int(fields[6] or 0)); keepalives.append(int(fields[7] or 0))
latest=max(handshakes or [0])
state_path="/etc/amnezia/wins-core/"+iface+".transport"
try: state=open(state_path,encoding="utf-8").read()
except OSError: state=""
xray_config_path="/usr/local/etc/xray/core-exits/"+iface+".json"
try:
 with open(xray_config_path,encoding="utf-8") as handle: xray_config=json.load(handle)
except (OSError,ValueError,TypeError): xray_config={}
inbounds=xray_config.get("inbounds") if isinstance(xray_config,dict) else []
outbounds=xray_config.get("outbounds") if isinstance(xray_config,dict) else []
inbounds=inbounds if isinstance(inbounds,list) else []
outbounds=outbounds if isinstance(outbounds,list) else []
udp_tunnel=any(isinstance(item,dict) and item.get("protocol")=="tunnel" and isinstance(item.get("settings"),dict) and item["settings"].get("network")=="udp" for item in inbounds)
vless=next((item for item in outbounds if isinstance(item,dict) and item.get("tag")=="vless-ws-out" and item.get("protocol")=="vless"),{})
mux=vless.get("mux") if isinstance(vless,dict) else {}
mux=mux if isinstance(mux,dict) else {}
native_mux=udp_tunnel and mux.get("enabled") is False and type(mux.get("concurrency")) is int and mux.get("concurrency")==0 and type(mux.get("xudpConcurrency")) is int and mux.get("xudpConcurrency")==0 and mux.get("xudpProxyUDP443")=="skip"
legacy_mux=udp_tunnel and mux.get("enabled") is True and type(mux.get("concurrency")) is int and mux.get("concurrency")==-1 and type(mux.get("xudpConcurrency")) is int and mux.get("xudpConcurrency")==16 and mux.get("xudpProxyUDP443")=="allow"
xray_unit_active=run(["systemctl","is-active","--quiet","wins-core-xray-exit@"+iface+".service"])[0]==0
xray_config_valid=bool(xray_config) and run(["xray","-test","-config",xray_config_path],15)[0]==0
listener_port=next((item.get("port") for item in inbounds if isinstance(item,dict) and item.get("listen")=="127.0.0.1" and item.get("protocol")=="tunnel" and type(item.get("port")) is int and 1<=item.get("port")<=65535),None)
_,udp_listeners=run(["ss","-H","-l","-u","-n"],8)
loopback_udp_listener=bool(listener_port and re.search(r"(?:^|\\s)127\\.0\\.0\\.1:"+re.escape(str(listener_port))+r"(?:\\s|$)",udp_listeners,re.MULTILINE))
try:
 with open("/usr/local/bin/wins-core-sync",encoding="utf-8") as handle: sync_agent=handle.read(262145)
except OSError: sync_agent=""
native_agent='mux:{enabled:false,concurrency:0,xudpConcurrency:0,xudpProxyUDP443:"skip"}'
legacy_agent='mux:{enabled:true,concurrency:-1,xudpConcurrency:16,xudpProxyUDP443:"allow"}'
if not sync_agent or len(sync_agent)>262144: sync_agent_contract="unreadable"
elif native_agent in sync_agent and legacy_agent not in sync_agent: sync_agent_contract="native_udp"
elif legacy_agent in sync_agent and native_agent not in sync_agent: sync_agent_contract="legacy_xudp"
else: sync_agent_contract="other"
_,sync_journal=run(["journalctl","-u","wins-core-sync.service","--since","-30 minutes","--no-pager","-o","json","-n","1000"],30)
recovery_metrics=recovery_timing_metrics(sync_journal)
ingress_rc,ingress_port=run(["docker","exec","wins-core-ingress","awg","show","core0","listen-port"])
suricata_active=run(["systemctl","is-active","--quiet","suricata.service"])[0]==0
suricata_exec=run(["systemctl","show","suricata.service","-p","ExecStart","--value"])[1]
suricata_queue0=bool(re.search(r"(?:^|\s)-q\s+0(?:\s|$)",suricata_exec))
suricata_control=run(["suricatasc","-c","uptime"])[0]==0
suricata_nfq="nfq" in run(["suricata","--build-info"])[1].lower()
iptables_save_ok=run(["sh","-lc","iptables-save >/dev/null"])[0]==0
_,rules_text=run(["iptables-save"])
nfqueue_rule_count=sum(1 for line in rules_text.splitlines() if "--queue-num 0" in line)
queue_bypass="--queue-bypass" in rules_text
ipv6_disabled=run(["sysctl","-n","net.ipv6.conf.all.disable_ipv6"])[1]=="1"
management_active=run(["systemctl","is-active","--quiet","wins-core-management-tunnel.service"])[0]==0
ssh_active=run(["systemctl","is-active","--quiet","ssh.service"])[0]==0 or run(["systemctl","is-active","--quiet","sshd.service"])[0]==0
xray_active=run(["systemctl","is-active","--quiet","xray.service"])[0]==0
nginx_active=run(["systemctl","is-active","--quiet","nginx.service"])[0]==0
config_test=subprocess.run(["suricata","-T","-c","/etc/suricata/suricata.yaml"],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90,check=False)
rollback_manifest=pathlib.Path("/root/winsvpn-live-remediation-core-20260721T010026Z/files.before.sha256")
try:
 manifest_text=rollback_manifest.read_text(encoding="utf-8",errors="strict")
 rollback_suricata_file_count=sum(1 for line in manifest_text.splitlines() if "  etc/suricata/" in line)
except OSError: rollback_suricata_file_count=-1
config_errors=[]
for line in config_test.stdout.splitlines():
 if any(word in line.lower() for word in ("error","failed","fatal","invalid")):
  clean=re.sub(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}","[ip]",line)
  clean=re.sub(r"[A-Za-z0-9+/=_-]{40,}","[redacted]",clean)
  config_errors.append(clean[-240:])
_,suricata_props=run(["systemctl","show","suricata.service","-p","ActiveState","-p","SubState","-p","Result","-p","ExecMainStatus","-p","NRestarts"])
props={}
for line in suricata_props.splitlines():
 if "=" in line: props[line.split("=",1)[0]]=line.split("=",1)[1]
_,suricata_log=run(["journalctl","-u","suricata.service","--no-pager","-n","120","-o","cat"],30)
suricata_failure="none"
sl=suricata_log.lower()
if "out of memory" in sl or "oom" in sl or "status=9/kill" in sl: suricata_failure="resource_kill"
elif "configuration provided was invalid" in sl or "failed to parse" in sl: suricata_failure="configuration"
elif "already running" in sl or "pid file" in sl: suricata_failure="pid_state"
elif "failed with result" in sl or "failed to start" in sl: suricata_failure="service_failure"
error_lines=[]
for line in suricata_log.splitlines():
 if any(word in line.lower() for word in ("error","failed","fatal","pid")):
  clean=re.sub(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}","[ip]",line)
  clean=re.sub(r"[A-Za-z0-9+/=_-]{40,}","[redacted]",clean)
  error_lines.append(clean[-240:])
print(json.dumps({
 "role":"core","ok":bool(dump),"interface_present":bool(dump),
 "exit_container_present":bool(owner),"peer_count":len(peers),
 "endpoint_present":endpoint_present,"endpoint_port_expected":endpoint_port_ok,
 "endpoint_loopback":endpoint_loopback,
 "transport_state_stealth":"mode=stealth" in state.splitlines(),
 "native_udp_mux_disabled_configs_count":int(native_mux),
 "legacy_xudp_enabled_configs_count":int(legacy_mux),
 "other_mux_configs_count":int(not native_mux and not legacy_mux),
 "installed_sync_agent_contract":sync_agent_contract,
 "exit_xray_unit_active":xray_unit_active,"xray_unit_active_count":int(xray_unit_active),
 "exit_xray_config_valid":xray_config_valid,"xray_config_valid_count":int(xray_config_valid),
 "exit_loopback_udp_listener":loopback_udp_listener,"loopback_udp_listener_count":int(loopback_udp_listener),
 "recovery_sample_count":recovery_metrics["recovery_sample_count"],
 "latest_recovery_seconds":recovery_metrics["latest_recovery_seconds"],
 "max_recovery_seconds":recovery_metrics["max_recovery_seconds"],
 "latest_attempt_unrecovered":recovery_metrics["latest_attempt_unrecovered"],
 "allowed_default_route":allowed_default,"persistent_keepalive_25":25 in keepalives,
 "handshake_count":sum(1 for value in handshakes if value>0),
 "fresh_within_300s":bool(latest and now-latest<=300),
 "handshake_age_seconds":now-latest if latest else -1,
 "rx_positive":any(value>0 for value in rx),"tx_positive":any(value>0 for value in tx),
 "udp_9210_listener":ingress_rc==0 and ingress_port.strip()=="9210"
 ,"suricata_active":suricata_active,"suricata_queue0":suricata_queue0,
 "suricata_control":suricata_control,"suricata_nfq":suricata_nfq,
 "iptables_save_ok":iptables_save_ok,"suricata_state":props.get("ActiveState","unknown"),
 "nfqueue_rule_count":nfqueue_rule_count,"queue_bypass":queue_bypass,
 "ipv6_disabled":ipv6_disabled,"management_active":management_active,"ssh_active":ssh_active,
 "xray_active":xray_active,"nginx_active":nginx_active,
 "suricata_config_test_ok":config_test.returncode==0,"suricata_config_errors":config_errors[-6:],
 "rollback_suricata_file_count":rollback_suricata_file_count,
 "suricata_substate":props.get("SubState","unknown"),"suricata_result":props.get("Result","unknown"),
 "suricata_exec_status":props.get("ExecMainStatus","unknown"),"suricata_restarts":props.get("NRestarts","unknown"),
 "suricata_failure":suricata_failure
 ,"suricata_error_tail":error_lines[-6:]
},sort_keys=True,separators=(",",":")))'''
    encoded = base64.b64encode(target.encode()).decode()
    remote = (
        f"sudo -S -p '' -- env WINS_EXIT_IFACE={iface} WINS_EXIT_PORT={port} "
        f"WINS_CORE_OBSERVE_B64={encoded} python3 -c "
        "'import base64,os;exec(base64.b64decode(os.environ[\"WINS_CORE_OBSERVE_B64\"]))'"
    )
    command = [
        "ssh", "-i", str(identity), "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
        "-o", "ConnectionAttempts=1", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no", "-o", "ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h",
        f"{user}@{host}", remote,
    ]
    environment = os.environ.copy()
    env_path = pathlib.Path("/root/vpn_auth/.env")
    if env_path.is_file() and not env_path.is_symlink() and not env_path.stat().st_mode & 0o077:
        for line in env_path.read_text(encoding="utf-8", errors="strict").splitlines():
            if "=" in line and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", line.split("=", 1)[0]):
                environment[line.split("=", 1)[0]] = line.split("=", 1)[1]
    completed = subprocess.run(
        command, input=(password + "\n").encode(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=environment, timeout=60, check=False,
    )
    if completed.returncode != 0:
        return fail("remote_privileged_probe_failed")
    try:
        result = json.loads(completed.stdout.decode("utf-8", errors="strict"))
    except Exception:
        return fail("remote_probe_invalid")
    if result.get("role") != "core":
        return fail("remote_probe_contract_failed")
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
