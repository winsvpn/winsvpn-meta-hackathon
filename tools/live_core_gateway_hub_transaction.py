#!/usr/bin/env python3
"""Transactionally populate the live Core gateway and install an exact hub main.

Run as root on the control hub after copying the generated candidate to the
owner-only path supplied by WINS_CANDIDATE_PATH.  The gateway is discovered
from the pinned outbound management SSH path and is never printed.  A SQLite
online backup, the exact main.py preimage, the exact Core row preimage, and a
SHA-256 manifest are retained before either live value is changed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import urllib.request


CONTRACT = "winsvpn-core-gateway-main-transaction-v1"
DB = pathlib.Path("/root/vpn_auth/vpn_users.db")
MAIN = pathlib.Path("/root/vpn_auth/main.py")
KNOWN_HOSTS = pathlib.Path("/root/vpn_auth/managed_known_hosts")
IDENTITY = pathlib.Path("/root/.ssh/id_rsa")
ROLLBACK_ROOT = pathlib.Path("/root/vpn_auth/rollback-live-hotfixes")


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def fail(message: str) -> None:
    raise RuntimeError(message)


def secure_regular(path: pathlib.Path, *, owner_only: bool = True) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
        fail(f"unsafe_{path.name}")
    if owner_only and stat.S_IMODE(info.st_mode) & 0o077:
        fail(f"overpermissive_{path.name}")


def owner_environment(path: pathlib.Path) -> dict[str, str]:
    secure_regular(path)
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
            result[key] = value
    return result


def atomic_json(path: pathlib.Path, value: object) -> None:
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        pathlib.Path(name).unlink(missing_ok=True)
        raise


def discover_gateway(host: str, user: str) -> tuple[str, int]:
    target = r'''import ipaddress,json,re,subprocess,sys
p=subprocess.run(["ip","-j","addr","show"],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
if p.returncode: raise SystemExit(21)
items=json.loads(p.stdout); candidates=[]
for item in items:
 name=str(item.get("ifname") or "")
 if not re.fullmatch(r"core[a-z0-9_.-]{1,15}",name) or "UP" not in (item.get("flags") or []): continue
 for address in item.get("addr_info") or []:
  if address.get("family")!="inet" or address.get("scope")!="global": continue
  if bool(address.get("secondary")): continue
  candidate=ipaddress.ip_address(address.get("local") or "")
  if candidate.version==4 and candidate.is_private and not candidate.is_loopback:
   candidates.append((str(candidate),int(address.get("prefixlen") or 0),name))
preferred=set()
for name in sorted({item[2] for item in candidates}):
 route=subprocess.run(["ip","-j","route","show","dev",name],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
 if route.returncode==0:
  for entry in json.loads(route.stdout or "[]"):
   value=str(entry.get("prefsrc") or "")
   if value: preferred.add(value)
selected=[item for item in candidates if item[0] in preferred]
s=subprocess.run(["ss","-H","-lun"],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
listener=s.returncode==0 and any(re.search(r"(?:^|[.:])9210$",field) for line in s.stdout.splitlines() for field in line.split()[3:4])
if len(selected)!=1 or not listener:
 print(json.dumps({"candidate_count":len(candidates),"selected_count":len(selected),"listener":listener},separators=(",",":")),file=sys.stderr);raise SystemExit(22)
print(json.dumps({"gateway":selected[0][0],"prefix":selected[0][1]},separators=(",",":")))'''
    command = [
        "ssh", "-i", str(IDENTITY), "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=12", "-o", "ConnectionAttempts=1",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
    ]
    if not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", host):
        command.extend(["-o", "ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h"])
    command.extend([f"{user}@{host}", "python3 -"])
    environment = os.environ.copy()
    environment.update(owner_environment(pathlib.Path("/root/vpn_auth/.env")))
    completed = subprocess.run(
        command, input=target, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=environment, timeout=45, check=False,
    )
    if completed.returncode != 0:
        if completed.returncode == 22:
            try:
                diagnostic = json.loads(completed.stderr.splitlines()[-1])
                candidate_count = int(diagnostic.get("candidate_count", -1))
                selected_count = int(diagnostic.get("selected_count", -1))
                listener = bool(diagnostic.get("listener"))
            except Exception:
                candidate_count, selected_count, listener = -1, -1, False
            fail(f"authoritative_gateway_probe_failed_22_c{candidate_count}_s{selected_count}_l{int(listener)}")
        fail(f"authoritative_gateway_probe_failed_{completed.returncode}")
    try:
        result = json.loads(completed.stdout)
        gateway = str(result["gateway"])
        prefix = int(result["prefix"])
        address = ipaddress.ip_address(gateway)
    except Exception as exc:
        raise RuntimeError("authoritative_gateway_probe_invalid") from exc
    if address.version != 4 or not address.is_private or address.is_loopback:
        fail("authoritative_gateway_not_rfc1918")
    network = ipaddress.ip_network(f"{gateway}/{prefix}", strict=False)
    if address in {network.network_address, network.broadcast_address}:
        fail("authoritative_gateway_not_usable")
    return gateway, prefix


def health_ok() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=4) as response:
            return response.status == 200
    except Exception:
        return False


def main() -> int:
    if os.geteuid() != 0:
        fail("root_required")
    candidate = pathlib.Path(os.environ["WINS_CANDIDATE_PATH"])
    expected_candidate = os.environ["WINS_CANDIDATE_SHA256"].strip().lower()
    expected_preimage = os.environ["WINS_MAIN_PREIMAGE_SHA256"].strip().lower()
    if not all(
        re.fullmatch(r"[0-9a-f]{64}", value)
        for value in (expected_candidate, expected_preimage)
    ):
        fail("invalid_hash_contract")
    for path in (DB, MAIN, KNOWN_HOSTS, IDENTITY, candidate):
        secure_regular(path)
    if digest(candidate) != expected_candidate or digest(MAIN) != expected_preimage:
        fail("source_preimage_hash_mismatch")
    compile_result = subprocess.run(
        ["/root/vpn_auth/venv/bin/python", "-m", "py_compile", str(candidate)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False,
    )
    if compile_result.returncode != 0:
        fail("candidate_compile_failed")

    connection = sqlite3.connect(DB, timeout=15)
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        """SELECT * FROM core_servers WHERE status='online' AND management_status='ok'
           AND runtime_ready=1 ORDER BY core_id"""
    ).fetchall()
    if len(rows) != 1:
        connection.close()
        fail("authoritative_core_not_unique")
    row = dict(rows[0])
    core_id = str(row.get("core_id") or "")
    host = str(row.get("management_host") or "").strip().lower()
    user = str(row.get("management_user") or "ubuntu").strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,39}", core_id):
        connection.close(); fail("invalid_core_id")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        connection.close(); fail("invalid_management_user")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
        connection.close(); fail("invalid_management_host")
    if not any(
        line.split(None, 1)[0] == host
        for line in KNOWN_HOSTS.read_text(encoding="utf-8", errors="strict").splitlines()
        if line.strip()
    ):
        connection.close(); fail("pinned_core_host_missing")
    if str(row.get("tunnel_gateway_ipv4") or "").strip():
        connection.close(); fail("core_gateway_preimage_not_blank")
    gateway, prefix = discover_gateway(host, user)

    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    rollback = ROLLBACK_ROOT / f"core-gateway-main.{timestamp}"
    rollback.mkdir(parents=True, mode=0o700)
    os.chmod(rollback, 0o700)
    main_backup = rollback / "main.py.preimage"
    shutil.copy2(MAIN, main_backup)
    os.chmod(main_backup, 0o600)
    row_backup = rollback / "core-row.preimage.json"
    atomic_json(row_backup, row)
    db_backup = rollback / "vpn_users.db.preimage"
    backup_connection = sqlite3.connect(db_backup)
    connection.backup(backup_connection)
    backup_connection.close()
    os.chmod(db_backup, 0o600)
    manifest_path = rollback / "manifest.json"
    manifest = {
        "contract": CONTRACT,
        "created_utc": timestamp,
        "result": "prepared",
        "main_preimage_sha256": digest(main_backup),
        "candidate_sha256": expected_candidate,
        "db_preimage_sha256": digest(db_backup),
        "row_preimage_sha256": digest(row_backup),
        "gateway_preimage_blank": True,
        "gateway_sha256": hashlib.sha256(gateway.encode()).hexdigest(),
        "gateway_prefix": prefix,
    }
    atomic_json(manifest_path, manifest)

    gateway_changed = False
    main_changed = False
    stage = "gateway_update"
    try:
        connection.execute("BEGIN IMMEDIATE")
        current = connection.execute(
            "SELECT tunnel_gateway_ipv4 FROM core_servers WHERE core_id=?", (core_id,)
        ).fetchone()
        if current is None or str(current[0] or "").strip():
            fail("core_gateway_concurrent_change")
        updated = connection.execute(
            "UPDATE core_servers SET tunnel_gateway_ipv4=? WHERE core_id=? AND COALESCE(tunnel_gateway_ipv4,'')=''",
            (gateway, core_id),
        )
        if updated.rowcount != 1:
            fail("core_gateway_update_rejected")
        connection.commit()
        gateway_changed = True

        stage = "main_install"
        main_info = MAIN.stat()
        os.chown(candidate, main_info.st_uid, main_info.st_gid)
        os.chmod(candidate, stat.S_IMODE(main_info.st_mode))
        os.replace(candidate, MAIN)
        main_changed = True
        if digest(MAIN) != expected_candidate:
            fail("installed_main_hash_mismatch")

        stage = "service_restart"
        restarted = subprocess.run(
            ["systemctl", "restart", "wins-hub.service"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45, check=False,
        )
        if restarted.returncode != 0:
            fail("hub_restart_failed")
        for _ in range(20):
            active = subprocess.run(
                ["systemctl", "is-active", "--quiet", "wins-hub.service"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            ).returncode == 0
            if active and health_ok():
                break
            time.sleep(1)
        else:
            fail("hub_health_failed")
        check = connection.execute(
            "SELECT tunnel_gateway_ipv4 FROM core_servers WHERE core_id=?", (core_id,)
        ).fetchone()
        if check is None or str(check[0] or "") != gateway:
            fail("gateway_postcondition_failed")
        manifest.update({"result": "committed", "finished_utc": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())})
        atomic_json(manifest_path, manifest)
        print(json.dumps({
            "ok": True,
            "contract": CONTRACT,
            "result": "committed",
            "candidate_sha256": expected_candidate,
            "gateway_sha256": manifest["gateway_sha256"],
            "gateway_prefix": prefix,
            "rollback_manifest_sha256": digest(manifest_path),
        }, separators=(",", ":"), sort_keys=True))
        return 0
    except Exception as exc:
        error_type = str(exc) if re.fullmatch(r"[a-z0-9_]+", str(exc)) else type(exc).__name__
        if main_changed:
            restore_tmp = MAIN.with_name(f".{MAIN.name}.rollback.{os.getpid()}")
            shutil.copy2(main_backup, restore_tmp)
            os.replace(restore_tmp, MAIN)
            subprocess.run(
                ["systemctl", "restart", "wins-hub.service"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45, check=False,
            )
        if gateway_changed:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE core_servers SET tunnel_gateway_ipv4=? WHERE core_id=?",
                (str(row.get("tunnel_gateway_ipv4") or ""), core_id),
            )
            connection.commit()
        manifest.update({
            "result": "rolled_back",
            "error_stage": stage,
            "error_type": error_type,
            "finished_utc": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
        })
        atomic_json(manifest_path, manifest)
        print(json.dumps({
            "ok": False,
            "contract": CONTRACT,
            "result": "rolled_back",
            "error_stage": stage,
            "error_type": error_type,
            "rollback_manifest_sha256": digest(manifest_path),
        }, separators=(",", ":"), sort_keys=True))
        return 1
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        message = str(exc)
        error_type = message if re.fullmatch(r"[a-z0-9_]+", message) else type(exc).__name__
        print(json.dumps({
            "ok": False,
            "contract": CONTRACT,
            "result": "not_started",
            "error_type": error_type,
        }, separators=(",", ":"), sort_keys=True))
        raise SystemExit(1)
