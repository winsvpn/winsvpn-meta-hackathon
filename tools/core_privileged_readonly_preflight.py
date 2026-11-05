#!/usr/bin/env python3
"""Sanitized privileged Core parity probe, executed ephemerally on the hub."""

from __future__ import annotations

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
    db = pathlib.Path("/root/vpn_auth/vpn_users.db")
    known_hosts = pathlib.Path("/root/vpn_auth/managed_known_hosts")
    identity = pathlib.Path("/root/.ssh/id_rsa")
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        """SELECT management_host AS host,
                  COALESCE(NULLIF(management_user,''),'ubuntu') AS user
           FROM core_servers
           WHERE status='online' AND management_status='ok'
           ORDER BY core_id"""
    ).fetchall()
    connection.close()
    if len(rows) != 1:
        return fail("managed_core_not_unique")
    host = str(rows[0]["host"] or "").strip().lower()
    user = str(rows[0]["user"] or "").strip().lower()
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
        return fail("invalid_management_identity")
    if not known_hosts.is_file() or known_hosts.is_symlink() or known_hosts.stat().st_mode & 0o077 or not identity.is_file():
        return fail("unsafe_management_prerequisite")
    if not any(line.split(None, 1)[0] == host for line in known_hosts.read_text(encoding="utf-8").splitlines() if line.strip()):
        return fail("pinned_host_key_missing")
    remote = r'''import hashlib,json,pathlib,subprocess
p=pathlib.Path("/usr/local/bin/wins-core-sync")
def run(args):
 r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=15,check=False)
 return r.returncode,r.stdout.strip()
timer_rc,timer=run(["systemctl","is-active","wins-core-sync.timer"])
enabled_rc,enabled=run(["systemctl","is-enabled","wins-core-sync.timer"])
result_rc,result=run(["systemctl","show","wins-core-sync.service","-p","Result","--value"])
status_rc,status=run(["systemctl","show","wins-core-sync.service","-p","ExecMainStatus","--value"])
timer_text=pathlib.Path("/etc/systemd/system/wins-core-sync.timer").read_text(encoding="utf-8",errors="strict")
interval_match=__import__("re").search(r"(?m)^OnUnitActiveSec=(\S+)$",timer_text)
interval=interval_match.group(1) if interval_match else ""
deps_rc,_=run(["bash","-lc","systemctl is-active --quiet nginx xray docker && docker ps --format '{{.Names}}' | grep -qx wins-core-ingress"])
text=p.read_text(encoding="utf-8",errors="strict")
transactions=sorted(pathlib.Path("/root").glob("winsvpn-core-sync-*") ,key=lambda item:item.name)
transaction=transactions[-1] if transactions else None
commit=transaction/"commit.json" if transaction else None
agent_preimage=transaction/"wins-core-sync.preimage" if transaction else None
timer_preimage=transaction/"wins-core-sync.timer.preimage" if transaction else None
print(json.dumps({"role":"core","ok":True,"sync_sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"sync_mode":oct(p.stat().st_mode&0o777),"timer_active":timer_rc==0 and timer=="active","timer_enabled":enabled_rc==0 and enabled=="enabled","timer_interval":interval,"last_result":result if result_rc==0 else "","last_status":status if status_rc==0 else "","runtime_dependencies_active":deps_rc==0,"has_batched_ack": "/api/v1/core/assignments/ack" in text,"rollback_transaction_present":bool(transaction and transaction.is_dir()),"commit_receipt_present":bool(commit and commit.is_file()),"agent_preimage_present":bool(agent_preimage and agent_preimage.is_file()),"timer_preimage_present":bool(timer_preimage and timer_preimage.is_file()),"rollback_owner_only":bool(transaction and transaction.stat().st_mode&0o077==0)},separators=(",",":"),sort_keys=True))'''
    command = [
        "ssh", "-i", str(identity), "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
        "-o", "ConnectionAttempts=1", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no", "-o", "ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h",
        f"{user}@{host}", "sudo -S -p '' -- python3 -",
    ]
    environment = os.environ.copy()
    env_path = pathlib.Path("/root/vpn_auth/.env")
    if env_path.is_file() and not env_path.is_symlink() and not env_path.stat().st_mode & 0o077:
        for line in env_path.read_text(encoding="utf-8", errors="strict").splitlines():
            if "=" in line and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", line.split("=", 1)[0]):
                environment[line.split("=", 1)[0]] = line.split("=", 1)[1]
    completed = subprocess.run(
        command,
        input=(password + "\n" + remote).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", errors="replace").lower()
        if "sorry, try again" in error or "incorrect password" in error:
            return fail("sudo_authentication_failed")
        if "password is required" in error:
            return fail("sudo_password_required")
        if "cloudflared" in error or "proxycommand" in error:
            return fail("management_proxy_failed")
        return fail(f"remote_privileged_probe_failed_{completed.returncode}")
    try:
        result = json.loads(completed.stdout.decode("utf-8", errors="strict"))
    except Exception:
        return fail("remote_probe_invalid")
    if result.get("role") != "core" or result.get("ok") is not True:
        return fail("remote_probe_contract_failed")
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
