#!/usr/bin/env python3
"""Run a bounded, sanitized Windows-to-Spain transport observation via hub.

This script is intended to run on the control hub.  It selects the one online
data plane from the hub database, proves the requested account/device/key/node
digests without emitting their raw values, and relays a read-only observation
program over the pinned management SSH path.  The target program records only
counts, deltas, booleans, rule SIDs, and error classes; it never returns peer
keys, tunnel addresses, public addresses, UUIDs, request bodies, or tokens.
"""

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
import urllib.parse


TARGET = r'''import base64,glob,hashlib,ipaddress,json,os,pathlib,re,select,socket,subprocess,threading,time
ctx=json.loads(base64.b64decode(os.environ["WINS_OBSERVE_CONTEXT_B64"],validate=True))
duration=max(20,min(180,int(ctx["duration_seconds"])))
def run(args,timeout=20):
 try:return subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
 except Exception as exc:return type("R",(),{"returncode":255,"stdout":"","stderr":type(exc).__name__})()
def peer_snapshot():
 p=run(["docker","exec","amnezia-awg2","awg","show","awg0","dump"])
 matches=[];total=0
 if p.returncode==0:
  for line in p.stdout.splitlines()[1:]:
   fields=line.split("\t")
   if len(fields)<7:continue
   total+=1
   if hashlib.sha256(fields[0].encode()).hexdigest().upper()!=ctx["public_key_digest"]:continue
   allowed=[x.strip() for x in fields[3].split(",") if x.strip()]
   psk="" if fields[1] in {"","(none)","off"} else fields[1]
   matches.append({"allowed_ipv4_32":len(allowed)==1 and bool(re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/32",allowed[0])),"allowed_ip_set_digest":hashlib.sha256(",".join(sorted(allowed)).encode()).hexdigest().upper(),"psk_digest":hashlib.sha256(psk.encode()).hexdigest().upper(),"handshake":int(fields[4] or 0),"rx":int(fields[5] or 0),"tx":int(fields[6] or 0)})
 return {"matches":matches,"peer_count":total,"command_ok":p.returncode==0}
def firewall_counters():
 p=run(["iptables-save","-c"]);out={"udp9110_packets":0,"udp9110_bytes":0,"tcp80_packets":0,"tcp80_bytes":0,"nfqueue_packets":0,"nfqueue_bytes":0}
 if p.returncode!=0:return out
 for line in p.stdout.splitlines():
  m=re.match(r"^\[([0-9]+):([0-9]+)\]\s+(.*)$",line)
  if not m:continue
  packets,bytes_,rule=int(m.group(1)),int(m.group(2)),m.group(3)
  if "9110" in rule and ("--dport" in rule or "--sport" in rule):out["udp9110_packets"]+=packets;out["udp9110_bytes"]+=bytes_
  if re.search(r"(?:--dport|--sport)\s+"+str(ctx["target_xray_port"])+r"(?:\s|$)",rule) and "-p tcp" in rule:out["tcp80_packets"]+=packets;out["tcp80_bytes"]+=bytes_
  if "NFQUEUE" in rule or "--queue-num 0" in rule:out["nfqueue_packets"]+=packets;out["nfqueue_bytes"]+=bytes_
 return out
def forwarding_snapshot():
 p=run(["iptables-save","-c"]);text=p.stdout if p.returncode==0 else ""
 def packets(pattern):
  total=0
  for line in text.splitlines():
   match=re.match(r"^\[([0-9]+):[0-9]+\]\s+(.*)$",line)
   if match and re.search(pattern,match.group(2)):total+=int(match.group(1))
  return total
 ip_forward=run(["sysctl","-n","net.ipv4.ip_forward"]).stdout.strip()=="1"
 default_route=run(["ip","-j","route","show","default"])
 try:default_ok=default_route.returncode==0 and bool(json.loads(default_route.stdout))
 except Exception:default_ok=False
 return {"inspection_complete":p.returncode==0,"ipv4_forward":ip_forward,"default_route_present":default_ok,"awg0_present":run(["ip","link","show","dev","awg0"]).returncode==0,"forward_jump_in":bool(re.search(r"-A FORWARD\b[^\n]*-i awg0\b[^\n]*-j WINVPN-FORWARD\b",text)),"forward_jump_out":bool(re.search(r"-A FORWARD\b[^\n]*-o awg0\b[^\n]*-j WINVPN-FORWARD\b",text)),"vpn_to_wan_accept":bool(re.search(r"-A WINVPN-FORWARD\b[^\n]*-i awg0\b[^\n]*-o \S+\b[^\n]*-j ACCEPT\b",text)),"return_established_accept":bool(re.search(r"-A WINVPN-FORWARD\b[^\n]*--ctstate (?:RELATED,ESTABLISHED|ESTABLISHED,RELATED)\b[^\n]*-j ACCEPT\b",text)),"masquerade_present":bool(re.search(r"-A WINVPN-NAT-POSTROUTING\b[^\n]*-s \S+\b[^\n]*-o \S+\b[^\n]*-j MASQUERADE\b",text)),"forward_in_packets":packets(r"-A WINVPN-FORWARD\b.*-i awg0\b.*-j ACCEPT\b"),"forward_return_packets":packets(r"-A WINVPN-FORWARD\b.*--ctstate (?:RELATED,ESTABLISHED|ESTABLISHED,RELATED)\b.*-j ACCEPT\b"),"masquerade_packets":packets(r"-A WINVPN-NAT-POSTROUTING\b.*-j MASQUERADE\b")}
def log_offsets():
 out={}
 for pattern in ("/var/log/nginx/*.log","/var/log/xray/*.log","/var/log/suricata/eve.json","/var/log/suricata/fast.log"):
  for value in glob.glob(pattern):
   p=pathlib.Path(value)
   try:
    if p.is_file() and not p.is_symlink():out[str(p)]=p.stat().st_size
   except OSError:pass
 return out
def new_logs(offsets):
 chunks=[]
 for value,offset in offsets.items():
  p=pathlib.Path(value)
  try:
   with p.open("rb") as f:f.seek(offset);chunks.append((value,f.read(8*1024*1024).decode("utf-8",errors="replace")))
  except OSError:pass
 return chunks
def source_class(raw):
 value=raw.strip("[]")
 if value.count(".")>=4:value=value.rsplit(".",1)[0]
 try:
  addr=ipaddress.ip_address(value)
  if hashlib.sha256(str(addr).encode()).hexdigest().upper()==ctx["client_egress_digest"]:return "expected"
  if addr.is_loopback:return "loopback"
  if addr.is_private:return "private"
  if addr.is_global:return "global"
  return "other"
 except ValueError:return "unknown"
def private_awg_gateway():
 p=run(["ip","-j","addr","show","dev","awg0"])
 if p.returncode!=0:return None
 try:items=json.loads(p.stdout)
 except Exception:return None
 candidates=[]
 for item in items if isinstance(items,list) else []:
  for address in item.get("addr_info",[]) if isinstance(item,dict) else []:
   if not isinstance(address,dict) or address.get("family")!="inet":continue
   try:value=ipaddress.ip_address(str(address.get("local") or ""))
   except ValueError:continue
   if value.version==4 and value.is_private and not value.is_loopback:candidates.append(str(value))
 candidates=sorted(set(candidates))
 return candidates[0] if len(candidates)==1 else None
baseline=peer_snapshot();fw0=firewall_counters();forward0=forwarding_snapshot();offsets=log_offsets();started=int(time.time())
echo_gateway="127.0.0.1" if ctx["probe_echo_bind"]=="loopback" else private_awg_gateway();echo_gateway_matches=bool(echo_gateway and hashlib.sha256(echo_gateway.encode()).hexdigest().upper()==ctx["probe_gateway_digest"])
echo_stats={"payload_matches":0,"replies_sent":0};echo_socket=None;echo_thread=None;echo_stop=threading.Event()
if ctx["probe_echo_port"] and echo_gateway_matches:
 echo_socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);echo_socket.bind((echo_gateway,ctx["probe_echo_port"]));echo_socket.settimeout(0.2)
 expected_echo=ctx["probe_payload_nonce"].encode("ascii")
 def echo_loop():
  while not echo_stop.is_set():
   try:payload,address=echo_socket.recvfrom(65535)
   except socket.timeout:continue
   except OSError:break
   if payload!=expected_echo:continue
   echo_stats["payload_matches"]+=1
   try:echo_socket.sendto(payload,address);echo_stats["replies_sent"]+=1
   except OSError:break
 echo_thread=threading.Thread(target=echo_loop,daemon=True);echo_thread.start()
ruleset=hashlib.sha256()
for rule_path in sorted(glob.glob("/var/lib/suricata/rules/*.rules")+glob.glob("/etc/suricata/rules/*.rules")):
 try:ruleset.update(rule_path.encode()+b"\0"+pathlib.Path(rule_path).read_bytes()+b"\0")
 except OSError:pass
suricata_ruleset_digest=ruleset.hexdigest().upper()
tcpdump=run(["sh","-c","command -v tcpdump"])
proc=None;counts={"udp9110_inbound":0,"udp9110_outbound":0,"tcp80_inbound":0,"tcp80_outbound":0,"probe_payload_matches":0,"udp9110_inbound_lengths":{},"udp9110_outbound_lengths":{},"udp9110_source_class":{"expected":0,"global":0,"private":0,"loopback":0,"other":0,"unknown":0},"tcp80_source_class":{"expected":0,"global":0,"private":0,"loopback":0,"other":0,"unknown":0}}
if tcpdump.returncode==0:
 tcpdump_args=["tcpdump","-i","any","-nn","-l"]
 if ctx["probe_payload_nonce"]:tcpdump_args.extend(["-A","-s","0"])
 tcpdump_args.append("(udp port 9110) or (tcp port "+str(ctx["target_xray_port"])+")")
 proc=subprocess.Popen(tcpdump_args,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
deadline=time.time()+duration
samples=[]
while time.time()<deadline:
 if proc and proc.stdout:
  ready,_,_=select.select([proc.stdout],[],[],0.2)
  if ready:
   line=proc.stdout.readline()
   if ctx["probe_payload_nonce"] and ctx["probe_payload_nonce"] in line:counts["probe_payload_matches"]+=line.count(ctx["probe_payload_nonce"])
   m=re.search(r"\bIP6?\s+(\S+)\s+>\s+(\S+):",line)
   if m:
    src,dst=m.group(1),m.group(2)
    is_udp9110=dst.endswith(".9110") or dst.endswith(":9110") or src.endswith(".9110") or src.endswith(":9110")
    suffix="9110" if is_udp9110 else str(ctx["target_xray_port"])
    inbound=dst.endswith("."+suffix) or dst.endswith(":"+suffix)
    counts[("udp9110" if is_udp9110 else "tcp80")+("_inbound" if inbound else "_outbound")]+=1
    if is_udp9110:
     length_match=re.search(r"\blength\s+(\d+)\b",line)
     if length_match:
      length_key=length_match.group(1)
      histogram=counts["udp9110_"+("inbound" if inbound else "outbound")+"_lengths"]
      histogram[length_key]=histogram.get(length_key,0)+1
    if inbound:counts[("udp9110" if is_udp9110 else "tcp80")+"_source_class"][source_class(src)]+=1
 else:time.sleep(0.2)
 if not samples or time.time()-samples[-1][0]>=1:
  snap=peer_snapshot();matches=snap["matches"]
  if len(matches)==1:samples.append((time.time(),matches[0]))
if proc:
 proc.terminate()
 try:proc.wait(timeout=3)
 except Exception:proc.kill()
if echo_socket:
 echo_stop.set();echo_socket.close()
 if echo_thread:echo_thread.join(timeout=2)
final=peer_snapshot();fw1=firewall_counters();forward1=forwarding_snapshot();chunks=new_logs(offsets)
joined="\n".join(text for _,text in chunks)
eve=[]
for name,text in chunks:
 if name.endswith("eve.json"):
  for line in text.splitlines():
   try:item=json.loads(line)
   except Exception:continue
   if item.get("event_type")=="alert":eve.append(item.get("alert") or {})
drop_sids=sorted({int(x.get("signature_id")) for x in eve if str(x.get("action") or "").lower() in {"blocked","drop"} and str(x.get("signature_id") or "").isdigit()})
config_ok=False;path_ok=False;uuid_ok=False;inbound_port_ok=False;redirect_ok=False
try:
 cfg=json.loads(pathlib.Path("/usr/local/etc/xray/config.json").read_text())
 raw=json.dumps(cfg,separators=(",",":"))
 path_ok=ctx["xray_path"] in raw;uuid_ok=ctx["xray_uuid"] in raw;inbound_port_ok=any(int(item.get("port") or 0)==ctx["xray_inbound_port"] for item in cfg.get("inbounds",[]) if isinstance(item,dict));redirect_ok=any(item.get("protocol")=="freedom" and item.get("tag")=="forward-to-amneziawg" and (item.get("settings") or {}).get("redirect")=="127.0.0.1:9110" for item in cfg.get("outbounds",[]) if isinstance(item,dict));config_ok=True
except Exception:pass
obfs_keys=("Jc","Jmin","Jmax","S1","S2","S3","S4","H1","H2","H3","H4")
runtime_obfs={}
try:
 for line in pathlib.Path("/etc/amnezia/amneziawg/awg0.conf").read_text().splitlines():
  if "=" not in line:continue
  key,value=[part.strip() for part in line.split("=",1)]
  if key in obfs_keys:runtime_obfs[key]=int(value)
except Exception:pass
runtime_obfs_digest=hashlib.sha256(json.dumps(runtime_obfs,sort_keys=True,separators=(",",":")).encode()).hexdigest().upper()
runtime_cli_obfs={}
for key in obfs_keys:
 value=run(["docker","exec","amnezia-awg2","awg","show","awg0",key.lower()])
 if value.returncode==0 and re.fullmatch(r"-?[0-9]+",value.stdout.strip()):runtime_cli_obfs[key]=int(value.stdout.strip())
runtime_cli_obfs_digest=hashlib.sha256(json.dumps(runtime_cli_obfs,sort_keys=True,separators=(",",":")).encode()).hexdigest().upper()
runtime_listen_port=run(["docker","exec","amnezia-awg2","awg","show","awg0","listen-port"])
runtime_listen_port_matches=runtime_listen_port.returncode==0 and runtime_listen_port.stdout.strip()=="9110"
release_awg_image="amneziavpn/amneziawg-go@sha256:acef5ae84808a9568448e9d8c7a96f640a5ccc590b0f8dfbc2df9f9dc0e848c9"
container_image=run(["docker","inspect","--format","{{.Config.Image}}","amnezia-awg2"])
container_image_ref=container_image.stdout.strip() if container_image.returncode==0 else ""
image_repo_digests=run(["docker","image","inspect","--format","{{join .RepoDigests \"\\n\"}}",container_image_ref]) if container_image_ref else run(["false"])
release_awg_image_matches=container_image_ref==release_awg_image or release_awg_image in image_repo_digests.stdout.splitlines()
container_image_id=run(["docker","inspect","--format","{{.Image}}","amnezia-awg2"])
container_image_id_digest=hashlib.sha256(container_image_id.stdout.strip().encode()).hexdigest().upper() if container_image_id.returncode==0 else ""
awg_tools_version=run(["docker","exec","amnezia-awg2","awg","--version"])
awg_tools_version_digest=hashlib.sha256(awg_tools_version.stdout.strip().encode()).hexdigest().upper() if awg_tools_version.returncode==0 else ""
listeners=run(["ss","-H","-ltnp"]);listener_lines=[line for line in listeners.stdout.splitlines() if re.search(r"(?:\]:|:)"+str(ctx["target_xray_port"])+r"\s",line)]
processes=run(["ps","-eo","comm="])
iface_key=run(["docker","exec","amnezia-awg2","awg","show","awg0","public-key"])
iface_key_matches=iface_key.returncode==0 and hashlib.sha256(iface_key.stdout.strip().encode()).hexdigest().upper()==ctx["node_public_key_digest"]
nginx=run(["nginx","-T"]);listen_lines=[line for line in nginx.stdout.splitlines() if re.search(r"(?:^|[\s:])"+str(ctx["xray_public_port"])+r"(?:\s|;)",line) and line.strip().startswith("listen ")];nginx_public_port=bool(listen_lines);nginx_security=(any(" ssl" in line for line in listen_lines) if ctx["xray_security"]=="tls" else any(" ssl" not in line for line in listen_lines));nginx_host=ctx["xray_host"] in nginx.stdout;nginx_path=ctx["xray_path"] in nginx.stdout
def delta(key):return max(0,fw1[key]-fw0[key])
def forward_delta(key):return max(0,forward1[key]-forward0[key])
base=baseline["matches"][0] if len(baseline["matches"])==1 else None
last=final["matches"][0] if len(final["matches"])==1 else None
error_categories={name:len(re.findall(pattern,joined,re.I)) for name,pattern in {"connection_refused":r"connection refused","connection_reset":r"connection reset","invalid_user":r"invalid user|invalid account","invalid_request":r"invalid request|bad request","websocket":r"websocket|web socket","context_canceled":r"context canceled|context cancelled","unexpected_eof":r"unexpected eof|\beof\b","closed_connection":r"closed network connection|broken pipe"}.items()}
result={"contract":"winsvpn-windows-spain-live-observation-v1","duration_seconds":duration,"hub_device_match_count":ctx["hub_device_match_count"],"hub_assignment_match_count":ctx["hub_assignment_match_count"],"node_digest_match":ctx["node_digest_match"],"peer_match_count_before":len(baseline["matches"]),"peer_match_count_after":len(final["matches"]),"peer_allowed_ipv4_32":bool(last and last["allowed_ipv4_32"]),"peer_count":final["peer_count"],"max_peers":ctx["max_peers"],"below_capacity":final["peer_count"]<ctx["max_peers"],"handshake_advanced":bool(base and last and last["handshake"]>base["handshake"]),"rx_delta":max(0,(last or {}).get("rx",0)-(base or {}).get("rx",0)),"tx_delta":max(0,(last or {}).get("tx",0)-(base or {}).get("tx",0)),"probe_echo_bind_mode":ctx["probe_echo_bind"],"probe_gateway_digest_matches":echo_gateway_matches,"probe_echo_bound_expected_address":bool(echo_socket),"probe_echo_bound_private_ipv4":bool(echo_socket and ctx["probe_echo_bind"]=="awg_gateway"),"probe_echo_payload_matches":echo_stats["payload_matches"],"probe_echo_replies_sent":echo_stats["replies_sent"],"tcpdump_available":tcpdump.returncode==0,"probe_payload_matches":counts["probe_payload_matches"],"udp9110_inbound_packets":counts["udp9110_inbound"],"udp9110_outbound_packets":counts["udp9110_outbound"],"udp9110_inbound_length_histogram":counts["udp9110_inbound_lengths"],"udp9110_outbound_length_histogram":counts["udp9110_outbound_lengths"],"expected_client_udp9110_inbound_packets":counts["udp9110_source_class"]["expected"],"udp9110_source_classes":counts["udp9110_source_class"],"tcp80_inbound_packets":counts["tcp80_inbound"],"tcp80_outbound_packets":counts["tcp80_outbound"],"expected_client_tcp80_inbound_packets":counts["tcp80_source_class"]["expected"],"tcp80_source_classes":counts["tcp80_source_class"],"tcp80_listener_present":bool(listener_lines),"tcp80_listener_nginx":any("nginx" in line for line in listener_lines),"nginx_process_running":"nginx" in processes.stdout.split(),"xray_process_running":"xray" in processes.stdout.split(),"firewall_udp9110_packet_delta":delta("udp9110_packets"),"firewall_tcp80_packet_delta":delta("tcp80_packets"),"firewall_nfqueue_packet_delta":delta("nfqueue_packets"),"suricata_new_alert_count":len(eve),"suricata_new_drop_sids":drop_sids,"xray_config_read":config_ok,"xray_path_matches_registration":path_ok,"xray_uuid_matches_registration":uuid_ok,"xray_inbound_port_matches_registration":inbound_port_ok,"xray_redirects_all_vless_udp_to_awg9110":redirect_ok,"awg_obfuscation_matches_registration":runtime_obfs_digest==ctx["node_obfuscation_digest"],"awg_runtime_obfuscation_matches_registration":runtime_cli_obfs_digest==ctx["node_obfuscation_digest"],"awg_runtime_listen_port_matches_registration":runtime_listen_port_matches,"nginx_ws_path_mentions":joined.count(ctx["xray_path"]),"nginx_http_101_mentions":len(re.findall(r"\s101\s",joined)),"xray_error_mentions":len(re.findall(r"(?i)\b(error|failed|invalid|rejected)\b",joined)),"xray_error_categories":error_categories,"observation_started_epoch":started,"observation_finished_epoch":int(time.time())}
result.update({"forwarding_inspection_complete":forward1["inspection_complete"],"ipv4_forward_enabled":forward1["ipv4_forward"],"default_route_present":forward1["default_route_present"],"awg0_present":forward1["awg0_present"],"forward_jump_in_present":forward1["forward_jump_in"],"forward_jump_out_present":forward1["forward_jump_out"],"vpn_to_wan_accept_present":forward1["vpn_to_wan_accept"],"return_established_accept_present":forward1["return_established_accept"],"masquerade_present":forward1["masquerade_present"],"forward_in_packet_delta":forward_delta("forward_in_packets"),"forward_return_packet_delta":forward_delta("forward_return_packets"),"masquerade_packet_delta":forward_delta("masquerade_packets")})
result.update({"observation_mode":ctx["observation_mode"],"observation_window_nonce":ctx["observation_window_nonce"],"peer_public_key_digest":ctx["public_key_digest"],"allowed_ip_set_digest":str((last or {}).get("allowed_ip_set_digest") or ""),"entry_counter_before_digest":hashlib.sha256(json.dumps({"peer":baseline,"firewall":fw0,"forwarding":forward0},sort_keys=True,separators=(",",":")).encode()).hexdigest().upper(),"entry_counter_after_digest":hashlib.sha256(json.dumps({"peer":final,"firewall":fw1,"forwarding":forward1},sort_keys=True,separators=(",",":")).encode()).hexdigest().upper(),"exit_counter_before_digest":hashlib.sha256(json.dumps({"firewall":fw0,"forwarding":forward0},sort_keys=True,separators=(",",":")).encode()).hexdigest().upper(),"exit_counter_after_digest":hashlib.sha256(json.dumps({"firewall":fw1,"forwarding":forward1},sort_keys=True,separators=(",",":")).encode()).hexdigest().upper(),"suricata_ruleset_digest":suricata_ruleset_digest,"expected_exit_identity_digest":ctx["expected_exit_identity_digest"],"peer_psk_matches_registration":bool(last and last["psk_digest"]==ctx["peer_psk_digest"]),"node_public_key_matches_runtime":iface_key_matches,"client_registration_digests_supplied":ctx["client_registration_digests_supplied"],"client_preshared_key_matches_registration":ctx["client_preshared_key_matches_registration"],"client_server_public_key_matches_registration":ctx["client_server_public_key_matches_registration"],"client_obfuscation_matches_registration":ctx["client_obfuscation_matches_registration"],"nginx_public_port_matches_registration":nginx_public_port,"nginx_security_matches_registration":nginx_security,"nginx_host_matches_registration":nginx_host,"nginx_path_matches_registration":nginx_path,"awg_container_name_matches":container_image.returncode==0,"awg_container_image_ref":container_image_ref,"awg_container_image_id_digest":container_image_id_digest,"awg_container_image_matches_release_pin":release_awg_image_matches,"awg_tools_version_command_ok":awg_tools_version.returncode==0,"awg_tools_version_digest":awg_tools_version_digest})
print(json.dumps(result,separators=(",",":"),sort_keys=True))'''


def sha(value: object) -> str:
    return hashlib.sha256(str(value or "").encode()).hexdigest().upper()


def owner_env(path: pathlib.Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        return {}
    result = {}
    for line in path.read_text(errors="strict").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
            result[key] = value
    return result


def main() -> int:
    mode = os.getenv("WINS_OBSERVE_MODE", "direct").strip().lower()
    if mode not in {"direct", "double_exit"}:
        raise SystemExit("invalid observation mode")
    expected = {
        key: os.environ[key].strip().upper()
        for key in (
            "WINS_ACCOUNT_DIGEST",
            "WINS_DEVICE_DIGEST",
            "WINS_PUBLIC_KEY_DIGEST",
            "WINS_NODE_SLUG_DIGEST",
            "WINS_CLIENT_EGRESS_DIGEST",
        )
    }
    if not all(re.fullmatch(r"[0-9A-F]{64}", value) for value in expected.values()):
        raise SystemExit("invalid observation digest contract")
    registration_keys = (
        "WINS_CLIENT_PSK_DIGEST",
        "WINS_CLIENT_SERVER_KEY_DIGEST",
        "WINS_CLIENT_OBFUSCATION_DIGEST",
    )
    registration_values = {
        key: os.getenv(key, "").strip().upper() for key in registration_keys
    }
    if any(registration_values.values()) and not all(
        re.fullmatch(r"[0-9A-F]{64}", value)
        for value in registration_values.values()
    ):
        raise SystemExit("invalid client registration digest contract")
    registration_supplied = all(registration_values.values())
    duration = max(20, min(180, int(os.getenv("WINS_OBSERVE_SECONDS", "90"))))
    probe_payload_nonce = os.getenv("WINS_PROBE_PAYLOAD_NONCE", "").strip().upper()
    if probe_payload_nonce and not re.fullmatch(r"WINSXRAY[0-9A-F]{32}", probe_payload_nonce):
        raise SystemExit("invalid probe payload nonce contract")
    probe_echo_port = int(os.getenv("WINS_PROBE_ECHO_PORT", "0"))
    if probe_echo_port not in {0, 49152} or (probe_echo_port and not probe_payload_nonce):
        raise SystemExit("invalid probe echo contract")
    probe_gateway_digest = os.getenv("WINS_PROBE_GATEWAY_DIGEST", "").strip().upper()
    if probe_echo_port and not re.fullmatch(r"[0-9A-F]{64}", probe_gateway_digest):
        raise SystemExit("invalid probe gateway digest contract")
    probe_echo_bind = os.getenv("WINS_PROBE_ECHO_BIND", "awg_gateway").strip().lower()
    if probe_echo_bind not in {"awg_gateway", "loopback"} or (
        not probe_echo_port and probe_echo_bind != "awg_gateway"
    ):
        raise SystemExit("invalid probe echo bind contract")
    db = pathlib.Path("/root/vpn_auth/vpn_users.db")
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    nodes = [dict(row) for row in connection.execute("select * from nodes")]
    matches = [row for row in nodes if sha(row.get("slug")) == expected["WINS_NODE_SLUG_DIGEST"]]
    if len(matches) != 1 or matches[0].get("status") != "online" or matches[0].get("management_status") != "ok":
        raise SystemExit("observed node is not uniquely online and managed")
    node = matches[0]
    try:
        node_obfuscation = json.loads(str(node.get("obfuscation_json") or "{}"))
    except json.JSONDecodeError as exc:
        raise SystemExit("registered node obfuscation is invalid") from exc
    if not isinstance(node_obfuscation, dict):
        raise SystemExit("registered node obfuscation is invalid")
    devices = [
        dict(row)
        for row in connection.execute(
            "select account_number,device_id,client_public_key,preshared_key,location_slug from devices"
        )
    ]
    device_matches = [
        row
        for row in devices
        if sha(row.get("account_number")) == expected["WINS_ACCOUNT_DIGEST"]
        and sha(row.get("device_id")) == expected["WINS_DEVICE_DIGEST"]
        and sha(row.get("client_public_key")) == expected["WINS_PUBLIC_KEY_DIGEST"]
        and sha(row.get("location_slug")) == expected["WINS_NODE_SLUG_DIGEST"]
    ]
    assignments = [
        dict(row)
        for row in connection.execute(
            "select account_number,device_id,core_id,exit_slug,status from double_vpn_assignments"
        )
    ]
    assignment_matches = [
        row
        for row in assignments
        if sha(row.get("account_number")) == expected["WINS_ACCOUNT_DIGEST"]
        and sha(row.get("device_id")) == expected["WINS_DEVICE_DIGEST"]
        and sha(row.get("exit_slug")) == expected["WINS_NODE_SLUG_DIGEST"]
    ]
    assignment_matches = [row for row in assignment_matches if row.get("status") == "active"]
    target_public_key_digest = expected["WINS_PUBLIC_KEY_DIGEST"]
    target_psk_digest = sha(device_matches[0].get("preshared_key")) if len(device_matches) == 1 else ""
    direct_registration = mode == "direct" and len(device_matches) == 1
    client_psk_matches = (
        sha(device_matches[0].get("preshared_key"))
        == registration_values["WINS_CLIENT_PSK_DIGEST"]
        if registration_supplied and direct_registration
        else None
    )
    client_server_key_matches = (
        sha(node.get("public_key"))
        == registration_values["WINS_CLIENT_SERVER_KEY_DIGEST"]
        if registration_supplied and direct_registration
        else None
    )
    client_obfuscation_matches = (
        sha(json.dumps(node_obfuscation, sort_keys=True, separators=(",", ":")))
        == registration_values["WINS_CLIENT_OBFUSCATION_DIGEST"]
        if registration_supplied and direct_registration
        else None
    )
    if mode == "double_exit":
        if len(assignment_matches) != 1:
            connection.close()
            raise SystemExit("hub Double assignment digest match is not unique")
        core_id = str(assignment_matches[0].get("core_id") or "")
        core = connection.execute(
            "select exit_public_key from core_servers where core_id=? and status='online' and runtime_ready=1",
            (core_id,),
        ).fetchone()
        if core is None or not str(core[0] or ""):
            connection.close()
            raise SystemExit("hub Double Core exit identity is unavailable")
        target_public_key_digest = sha(core[0])
        target_psk_digest = sha("")
    connection.close()
    if len(device_matches) != 1:
        raise SystemExit("hub device digest match is not unique")
    observation_nonce = os.environ["WINS_OBSERVATION_NONCE"].strip().lower()
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        observation_nonce,
    ):
        raise SystemExit("invalid observation nonce contract")
    context = {
        "duration_seconds": duration,
        "public_key_digest": target_public_key_digest,
        "peer_psk_digest": target_psk_digest,
        "node_public_key_digest": sha(node.get("public_key")),
        "node_obfuscation_digest": sha(
            json.dumps(node_obfuscation, sort_keys=True, separators=(",", ":"))
        ),
        "client_egress_digest": expected["WINS_CLIENT_EGRESS_DIGEST"],
        "observation_mode": mode,
        "expected_exit_identity_digest": expected["WINS_NODE_SLUG_DIGEST"],
        "hub_device_match_count": len(device_matches),
        "hub_assignment_match_count": len(assignment_matches),
        "node_digest_match": True,
        "max_peers": max(1, int(node.get("max_peers") or 0)),
        "xray_path": str(node.get("xray_path") or ""),
        "xray_uuid": str(node.get("xray_uuid") or ""),
        "xray_host": (str(node.get("xray_sni") or "").strip().lower() or (urllib.parse.urlsplit("//" + str(node.get("stealth_endpoint") or "")).hostname or "").lower()),
        "xray_public_port": int(node.get("stealth_public_port") or 80),
        "target_xray_port": max(
            1, min(65535, int(os.getenv("WINS_TARGET_XRAY_PORT", "80")))
        ),
        "xray_inbound_port": max(
            1, min(65535, int(node.get("xray_inbound_port") or 10085))
        ),
        "observation_window_nonce": observation_nonce,
        "xray_security": str(node.get("xray_security") or "none").strip().lower(),
        "probe_payload_nonce": probe_payload_nonce,
        "probe_echo_port": probe_echo_port,
        "probe_gateway_digest": probe_gateway_digest,
        "probe_echo_bind": probe_echo_bind,
        "client_registration_digests_supplied": registration_supplied,
        "client_preshared_key_matches_registration": client_psk_matches,
        "client_server_public_key_matches_registration": client_server_key_matches,
        "client_obfuscation_matches_registration": client_obfuscation_matches,
    }
    host = str(node.get("ssh_host") or "").strip().lower()
    known_hosts = pathlib.Path("/root/vpn_auth/managed_known_hosts")
    identity = pathlib.Path("/root/.ssh/id_rsa")
    if not host or not any(
        line.split(None, 1)[0] == host
        for line in known_hosts.read_text(errors="strict").splitlines()
        if line.strip()
    ):
        raise SystemExit("pinned data-plane target is unavailable")
    command = [
        "ssh", "-i", str(identity), "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
        "-o", "ConnectionAttempts=1",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
    ]
    if not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", host):
        command.extend(["-o", "ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h"])
    command.extend([
        f"root@{host}",
        "WINS_OBSERVE_CONTEXT_B64=" + base64.b64encode(json.dumps(context, separators=(",", ":")).encode()).decode() + " python3 -",
    ])
    environment = os.environ.copy()
    environment.update(owner_env(pathlib.Path("/root/vpn_auth/.env")))
    try:
        completed = subprocess.run(
            command, input=TARGET, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment, timeout=duration + 60, check=False,
        )
    except subprocess.TimeoutExpired:
        print(json.dumps({"ok": False, "error_type": "remote_observation_timeout"}, separators=(",", ":")))
        return 1
    if completed.returncode != 0:
        stderr = completed.stderr.lower()
        if "host key verification failed" in stderr:
            error_type = "remote_host_key_rejected"
        elif "permission denied" in stderr:
            error_type = "remote_authentication_rejected"
        elif "connection timed out" in stderr or "operation timed out" in stderr:
            error_type = "remote_connection_timeout"
        elif "connection refused" in stderr:
            error_type = "remote_connection_refused"
        elif "no route to host" in stderr or "network is unreachable" in stderr:
            error_type = "remote_network_unreachable"
        elif "traceback" in stderr:
            error_type = "remote_observer_exception"
        else:
            error_type = "remote_observation_failed"
        print(json.dumps({
            "ok": False,
            "error_type": error_type,
            "return_code": int(completed.returncode),
        }, separators=(",", ":")))
        return 1
    result = json.loads(completed.stdout)
    if result.get("contract") != "winsvpn-windows-spain-live-observation-v1":
        raise SystemExit("observation contract mismatch")
    pinned_lines = sorted(
        line.strip() for line in known_hosts.read_text(errors="strict").splitlines()
        if line.strip() and line.split(None, 1)[0] == host
    )
    result["observer_host_key_digest"] = sha("\n".join(pinned_lines))
    result["observer_identity_digest"] = sha("root@" + host)
    result["observer_authenticated"] = True
    result["observation_window_nonce"] = observation_nonce
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
