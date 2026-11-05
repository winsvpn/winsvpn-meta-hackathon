#!/usr/bin/env python3
"""Capture only redacted HTTP/WebSocket fingerprints for a bounded Spain test."""

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


TARGET = r'''import base64,collections,datetime as dt,hashlib,json,os,pathlib,re,socket,subprocess,time
ctx=json.loads(base64.b64decode(os.environ["WINS_HTTP_OBSERVE_B64"],validate=True));duration=max(20,min(120,int(ctx["duration_seconds"])))
def run(args,timeout=20):
 try:return subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
 except Exception:return type("R",(),{"returncode":255,"stdout":"","stderr":""})()
tcp=run(["timeout",str(duration),"tcpdump","-i","any","-nn","-s0","-A","tcp port 80"],timeout=duration+10)
raw=tcp.stdout;requests=[];responses=collections.Counter()
packet_starts=list(re.finditer(r"(?m)^\d{2}:\d{2}:\d{2}[^\n]*\sIP6?\s+(\S+)\s+>\s+(\S+):",raw))
packets=[]
for index,header in enumerate(packet_starts):
 end=packet_starts[index+1].start() if index+1<len(packet_starts) else len(raw);packets.append((header.group(1),header.group(2),raw[header.start():end]))
for source,destination,packet in packets:
 match=re.search(r"(?:^|[^A-Z])(GET|POST|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/1\.[01]\r?\n((?:[^\r\n]+\r?\n){1,80})",packet,re.M)
 if not match:continue
 method,path,block=match.groups();headers={}
 for line in block.splitlines():
  if ":" in line:
   key,value=line.split(":",1);headers[key.strip().lower()]=value.strip()
 host=headers.get("host","").split(":",1)[0].lower()
 requests.append({"source_flow_sha256":hashlib.sha256(source.encode()).hexdigest(),"method":method,"path_sha256":hashlib.sha256(path.encode()).hexdigest(),"path_matches_expected":path==ctx["path"],"host_sha256":hashlib.sha256(host.encode()).hexdigest(),"host_matches_expected":host==ctx["host"],"upgrade_websocket":headers.get("upgrade","").lower()=="websocket","connection_upgrade":"upgrade" in headers.get("connection","").lower(),"sec_websocket_key_present":bool(headers.get("sec-websocket-key")),"sec_websocket_version_present":bool(headers.get("sec-websocket-version")),"authorization_header_present":"authorization" in headers})
for status in re.findall(r"HTTP/1\.[01]\s+([0-9]{3})",raw):responses[status]+=1
ng=run(["nginx","-T"]);nginx_host_present=ctx["host"] in ng.stdout;nginx_path_present=ctx["path"] in ng.stdout
probe_status=0
try:
 request=(f"GET {ctx['path']} HTTP/1.1\r\nHost: {ctx['host']}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
 with socket.create_connection(("127.0.0.1",80),timeout=4) as sock:
  sock.sendall(request);first=sock.recv(256).split(b"\r\n",1)[0];m=re.match(rb"HTTP/1\.[01] ([0-9]{3})",first);probe_status=int(m.group(1)) if m else 0
except Exception:pass
cutoff=dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=duration+30);eve=pathlib.Path('/var/log/suricata/eve.json');alerts=collections.Counter()
try:
 with eve.open('rb') as handle:
  handle.seek(max(0,eve.stat().st_size-16*1024*1024));handle.readline() if handle.tell() else None
  for line in handle.read().decode(errors='replace').splitlines():
   try:item=json.loads(line);timestamp=dt.datetime.fromisoformat(str(item.get('timestamp') or '').replace('Z','+00:00'))
   except Exception:continue
   if item.get('event_type')!='alert' or timestamp.astimezone(dt.timezone.utc)<cutoff:continue
   alert=item.get('alert') or {};key=(int(alert.get('signature_id') or 0),str(alert.get('action') or 'unknown').lower(),str(alert.get('signature') or '')[:160]);alerts[key]+=1
except Exception:pass
print(json.dumps({"contract":"winsvpn-spain-http-fingerprint-observation-v1","duration_seconds":duration,"tcpdump_ok":tcp.returncode in (0,124),"request_count":len(requests),"requests":requests,"response_status_counts":dict(responses),"nginx_host_present":nginx_host_present,"nginx_path_present":nginx_path_present,"local_same_host_path_probe_status":probe_status,"suricata_alerts":[{"sid":k[0],"action":k[1],"message":k[2],"count":v} for k,v in sorted(alerts.items())]},separators=(",",":"),sort_keys=True))'''


def sha(value: object) -> str:
    return hashlib.sha256(str(value or "").encode()).hexdigest().upper()


def env_file(path: pathlib.Path) -> dict[str, str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        return {}
    result = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key): result[key] = value
    return result


def main() -> int:
    node_digest = os.environ["WINS_NODE_SLUG_DIGEST"].strip().upper()
    if not re.fullmatch(r"[0-9A-F]{64}", node_digest): raise SystemExit("invalid node digest")
    duration = max(20, min(120, int(os.getenv("WINS_OBSERVE_SECONDS", "60"))))
    connection = sqlite3.connect("file:/root/vpn_auth/vpn_users.db?mode=ro", uri=True, timeout=5);connection.row_factory=sqlite3.Row
    rows=[dict(row) for row in connection.execute("select * from nodes where status='online' and management_status='ok'")];connection.close()
    matches=[row for row in rows if sha(row.get("slug"))==node_digest]
    if len(matches)!=1: raise SystemExit("node digest match is not unique")
    node=matches[0];parsed=urllib.parse.urlsplit("//"+str(node.get("stealth_endpoint") or ""))
    host=(str(node.get("xray_sni") or "") or parsed.hostname or "").lower();path=str(node.get("xray_path") or "")
    if not host or not path.startswith("/"): raise SystemExit("expected HTTP fingerprint unavailable")
    context={"duration_seconds":duration,"host":host,"path":path};target=str(node.get("ssh_host") or "").strip().lower();known=pathlib.Path('/root/vpn_auth/managed_known_hosts')
    command=['ssh','-i','/root/.ssh/id_rsa','-o','BatchMode=yes','-o','ConnectTimeout=12','-o','ConnectionAttempts=1','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={known}','-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no']
    if not re.fullmatch(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}',target):command.extend(['-o','ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h'])
    command.extend([f'root@{target}','WINS_HTTP_OBSERVE_B64='+base64.b64encode(json.dumps(context,separators=(',',':')).encode()).decode()+' python3 -'])
    environment=os.environ.copy();environment.update(env_file(pathlib.Path('/root/vpn_auth/.env')))
    completed=subprocess.run(command,input=TARGET,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment,timeout=duration+60,check=False)
    if completed.returncode!=0:
        print(json.dumps({'ok':False,'error_type':'http_observation_failed'},separators=(',',':')));return 1
    result=json.loads(completed.stdout)
    if result.get('contract')!='winsvpn-spain-http-fingerprint-observation-v1':raise SystemExit('HTTP observation contract mismatch')
    print(json.dumps(result,separators=(',',':'),sort_keys=True));return 0


if __name__ == '__main__': raise SystemExit(main())
