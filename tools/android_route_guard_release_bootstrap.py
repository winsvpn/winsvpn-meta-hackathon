#!/usr/bin/env python3
"""Provision and preflight the release-only Android route observer.

The workflow is intentionally fail closed:

* management access and release access are key-only;
* the dedicated account is locked and its authorized key has one forced command;
* sudo permits only the root-owned route guard actions;
* inventory is derived read-only from the hub database and expires after one hour;
* no firewall, VPN, application, or provider-edge setting is changed here.

Private keys are never accepted on stdin, argv, or in an inventory.  The only
key accepted by ``provision-target`` is an OpenSSH Ed25519 public key.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shlex
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
from typing import Any


CONTRACT = "winsvpn-android-route-inventory-v1"
BOOTSTRAP_CONTRACT = "winsvpn-android-route-guard-bootstrap-v1"
ACCOUNT = "winsroute"
ALIASES = {"node": "node-release", "core": "core-release"}
# These paths are serialized into Python that executes on Linux. PurePosixPath
# prevents a Windows release controller from emitting backslash paths.
GUARD_PATH = pathlib.PurePosixPath("/usr/local/sbin/winsvpn-android-route-guard")
DISPATCH_PATH = pathlib.PurePosixPath("/usr/local/sbin/winsvpn-android-route-dispatch")
SUDOERS_PATH = pathlib.PurePosixPath("/etc/sudoers.d/winsvpn-android-route-guard")
HOME_PATH = pathlib.PurePosixPath("/var/lib/winsvpn-route-release")
DB_PATH = pathlib.Path("/root/vpn_auth/vpn_users.db")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SAFE_COMMENT_RE = re.compile(r"^[A-Za-z0-9_.@+-]{0,80}$")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class BootstrapError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def validate_public_key(value: str) -> str:
    line = value.strip()
    parts = line.split()
    if len(parts) not in {2, 3} or parts[0] != "ssh-ed25519":
        raise BootstrapError("release key must be one unoptioned OpenSSH Ed25519 public key")
    if len(parts) == 3 and not SAFE_COMMENT_RE.fullmatch(parts[2]):
        raise BootstrapError("release public-key comment is unsafe")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except Exception as exc:
        raise BootstrapError("release public key is not valid base64") from exc
    try:
        kind_len = struct.unpack(">I", raw[:4])[0]
        kind = raw[4 : 4 + kind_len]
        offset = 4 + kind_len
        key_len = struct.unpack(">I", raw[offset : offset + 4])[0]
        key = raw[offset + 4 :]
    except (IndexError, struct.error) as exc:
        raise BootstrapError("release public key blob is malformed") from exc
    if kind != b"ssh-ed25519" or key_len != 32 or len(key) != 32:
        raise BootstrapError("release public key is not a 32-byte Ed25519 key")
    return " ".join(parts)


def parse_port(endpoint: str, label: str) -> int:
    value = str(endpoint or "").strip()
    if value.startswith("["):
        match = re.fullmatch(r"\[[0-9A-Fa-f:]+\]:(\d{1,5})", value)
    else:
        match = re.fullmatch(r"[^\s/:]+:(\d{1,5})", value)
    if not match:
        raise BootstrapError(f"{label} endpoint is missing an explicit safe port")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise BootstrapError(f"{label} endpoint port is invalid")
    return port


def parse_routes(raw: Any, default_port: int, default_security: str, label: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as exc:
        raise BootstrapError(f"{label} transports are invalid JSON") from exc
    if not value:
        value = [{"port": default_port, "security": default_security}]
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise BootstrapError(f"{label} transports are empty or excessive")
    routes: list[dict[str, Any]] = []
    seen: set[int] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) - {"port", "security", "protocol"}:
            raise BootstrapError(f"{label} transport fields are invalid")
        port = item.get("port")
        security = str(item.get("security", "none")).lower()
        protocol = str(item.get("protocol", "tcp")).lower()
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
            or protocol != "tcp"
            or security not in {"none", "tls"}
            or port in seen
        ):
            raise BootstrapError(f"{label} transport is invalid or duplicated")
        seen.add(port)
        routes.append({"protocol": "tcp", "port": port, "security": security})
    return sorted(routes, key=lambda item: (item["port"], item["security"]))


def inventory_from_database(database: pathlib.Path) -> dict[str, Any]:
    database = database.absolute()
    if not database.is_file() or database.is_symlink():
        raise BootstrapError("hub database is missing or unsafe")
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT n.slug, n.endpoint, n.wg_port,
                   n.stealth_public_port AS node_stealth_port,
                   n.xray_security AS node_xray_security,
                   n.stealth_transports AS node_transports,
                   c.core_id, c.ingress_endpoint,
                   c.stealth_endpoint AS core_stealth_endpoint,
                   c.xray_security AS core_xray_security,
                   c.stealth_transports AS core_transports
              FROM core_exit_peers e
              JOIN nodes n ON n.slug = e.exit_slug
              JOIN core_servers c ON c.core_id = e.core_id
             WHERE n.status = 'online'
               AND n.management_status = 'ok'
               AND n.free_access_enabled = 1
               AND n.direct_awg_enabled = 1
               AND c.status = 'online'
               AND c.management_status = 'ok'
               AND c.runtime_ready = 1
             ORDER BY LOWER(n.slug), LOWER(c.core_id)
            """
        ).fetchall()
        connection.close()
    except sqlite3.Error as exc:
        raise BootstrapError("hub inventory read-only query failed") from exc
    if len(rows) != 1:
        raise BootstrapError("hub must expose exactly one eligible free exit/Core pair for release evidence")
    row = dict(rows[0])
    node_port = int(row.get("wg_port") or parse_port(row.get("endpoint"), "node"))
    core_port = parse_port(row.get("ingress_endpoint"), "Core")
    if node_port != 9110:
        raise BootstrapError("public node release route must be UDP/9110")
    node_routes = parse_routes(
        row.get("node_transports"), int(row.get("node_stealth_port") or 80),
        str(row.get("node_xray_security") or "none").lower(), "node",
    )
    core_default_port = parse_port(row.get("core_stealth_endpoint"), "Core stealth")
    core_routes = parse_routes(
        row.get("core_transports"), core_default_port,
        str(row.get("core_xray_security") or "none").lower(), "Core",
    )
    core_id = str(row.get("core_id") or "").strip()
    exit_slug = str(row.get("slug") or "").strip()
    if not core_id or not exit_slug:
        raise BootstrapError("hub release pair identity is incomplete")
    return {
        "schema_version": 1,
        "contract": CONTRACT,
        "captured_at_utc": utc_now(),
        "node": {
            "direct": {"protocol": "udp", "port": node_port, "ssh_alias": ALIASES["node"]},
            "advertised_xray_routes": [
                {**route, "ssh_alias": ALIASES["node"]} for route in node_routes
            ],
            "core_id_sha256": EMPTY_SHA256,
            "exit_slug_sha256": EMPTY_SHA256,
        },
        "double_vpn": {
            "direct": {"protocol": "udp", "port": core_port, "ssh_alias": ALIASES["core"]},
            "advertised_xray_routes": [
                {**route, "ssh_alias": ALIASES["core"]} for route in core_routes
            ],
            "core_id_sha256": sha256_text(core_id),
            "exit_slug_sha256": sha256_text(exit_slug),
        },
        "secret_material_redacted": True,
    }


DISPATCHER = r'''#!/usr/bin/env bash
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset BASH_ENV ENV CDPATH GLOBIGNORE
readonly original=${SSH_ORIGINAL_COMMAND:-}
readonly action_pattern='^sudo -n /usr/local/sbin/winsvpn-android-route-guard (apply|observe|restore) ([0-9a-f]{32})$'
if [[ ${original} == 'sudo -n /usr/local/sbin/winsvpn-android-route-guard snapshot' ]]; then
  exec /usr/bin/sudo -n /usr/local/sbin/winsvpn-android-route-guard snapshot
fi
if [[ ${original} =~ ${action_pattern} ]]; then
  exec /usr/bin/sudo -n /usr/local/sbin/winsvpn-android-route-guard "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
fi
printf '%s\n' 'ANDROID ROUTE DISPATCH: denied' >&2
exit 126
'''


def target_program(public_key: str, role: str, guard: bytes) -> str:
    if role not in ALIASES:
        raise BootstrapError("target role must be node or core")
    payload = {
        "contract": BOOTSTRAP_CONTRACT,
        "role": role,
        "account": ACCOUNT,
        "public_key": validate_public_key(public_key),
        "guard_b64": base64.b64encode(guard).decode("ascii"),
        "guard_sha256": sha256_bytes(guard),
        "dispatcher_b64": base64.b64encode(DISPATCHER.encode()).decode("ascii"),
        "dispatcher_sha256": sha256_text(DISPATCHER),
    }
    encoded = base64.b64encode(json.dumps(payload, sort_keys=True).encode()).decode("ascii")
    # This program is streamed over an already-authorized management channel.
    # It contains only public-key and public source material, never a private key.
    return f'''#!/usr/bin/env python3
import base64, hashlib, json, os, pathlib, pwd, re, shutil, subprocess, sys, tempfile
payload=json.loads(base64.b64decode({encoded!r}, validate=True))
def fail(message):
    print(json.dumps({{"ok":False,"contract":{BOOTSTRAP_CONTRACT!r},"error":message,"secret_material_redacted":True}}, separators=(",",":")))
    raise SystemExit(1)
if os.geteuid()!=0: fail("root_required")
if payload.get("contract")!={BOOTSTRAP_CONTRACT!r} or payload.get("role") not in ("node","core") or payload.get("account")!={ACCOUNT!r}: fail("payload_invalid")
guard=base64.b64decode(payload["guard_b64"],validate=True)
dispatcher=base64.b64decode(payload["dispatcher_b64"],validate=True)
if hashlib.sha256(guard).hexdigest()!=payload["guard_sha256"] or hashlib.sha256(dispatcher).hexdigest()!=payload["dispatcher_sha256"]: fail("source_digest_mismatch")
for command in ("python3","iptables","iptables-restore","sha256sum","conntrack","flock","systemd-run","systemctl","stat","dd","sudo","visudo","useradd","usermod"):
    if shutil.which(command) is None: fail("missing_required_command_"+command.replace("-","_"))
account={ACCOUNT!r}; home=pathlib.Path({str(HOME_PATH)!r}); ssh_dir=home/".ssh"; authorized=ssh_dir/"authorized_keys"
try:
    existing=pwd.getpwnam(account)
    if existing.pw_uid==0 or existing.pw_dir!=str(home) or existing.pw_shell!="/bin/sh": fail("existing_account_contract_mismatch")
    created=False
except KeyError:
    account_create=subprocess.run(["useradd","--system","--home-dir",str(home),"--shell","/bin/sh","--create-home",account],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    if account_create.returncode!=0:
        reason=account_create.stderr.lower()
        if "cannot lock" in reason: fail("account_create_database_locked")
        if "already exists" in reason: fail("account_create_name_collision")
        if "cannot create directory" in reason: fail("account_create_home_failed")
        if "permission denied" in reason: fail("account_create_permission_denied")
        if "invalid user name" in reason: fail("account_create_invalid_user_name")
        if "configuration error" in reason or "unknown item" in reason: fail("account_create_login_defs_invalid")
        if "invalid shell" in reason: fail("account_create_invalid_shell")
        if "invalid" in reason: fail("account_create_invalid_configuration")
        if "not found" in reason: fail("account_create_dependency_not_found")
        fail("account_create_failed")
    created=True
account_lock=subprocess.run(["usermod","--lock",account],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if account_lock.returncode!=0: fail("account_lock_failed")
existing=pwd.getpwnam(account)
if existing.pw_uid==0 or existing.pw_dir!=str(home) or existing.pw_shell!="/bin/sh": fail("account_contract_invalid")
def atomic(path,data,mode):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=".winsvpn-route-",dir=str(path.parent))
    try:
        with os.fdopen(fd,"wb") as handle: handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.chown(name,0,0); os.chmod(name,mode); os.replace(name,path)
    finally:
        try: os.unlink(name)
        except FileNotFoundError: pass
atomic(pathlib.Path({str(GUARD_PATH)!r}),guard,0o755)
atomic(pathlib.Path({str(DISPATCH_PATH)!r}),dispatcher,0o755)
home.mkdir(parents=True,exist_ok=True); ssh_dir.mkdir(parents=True,exist_ok=True)
os.chown(home,0,0); os.chmod(home,0o755); os.chown(ssh_dir,0,0); os.chmod(ssh_dir,0o755)
key_line=('command="/usr/local/sbin/winsvpn-android-route-dispatch",restrict '+payload["public_key"]+'\\n').encode()
atomic(authorized,key_line,0o644)
sudoers=("Cmnd_Alias WINSVPN_ANDROID_ROUTE_GUARD = /usr/local/sbin/winsvpn-android-route-guard snapshot, /usr/local/sbin/winsvpn-android-route-guard apply *, /usr/local/sbin/winsvpn-android-route-guard observe *, /usr/local/sbin/winsvpn-android-route-guard restore *\\n"+account+" ALL=(root) NOPASSWD: WINSVPN_ANDROID_ROUTE_GUARD\\n").encode()
candidate=pathlib.Path("/etc/sudoers.d/.winsvpn-android-route-guard.candidate")
atomic(candidate,sudoers,0o440)
check=subprocess.run(["visudo","-cf",str(candidate)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if check.returncode!=0: candidate.unlink(missing_ok=True); fail("sudoers_validation_failed")
os.replace(candidate,pathlib.Path({str(SUDOERS_PATH)!r}))
result={{"ok":True,"contract":{BOOTSTRAP_CONTRACT!r},"role":payload["role"],"account":account,"guard_sha256":payload["guard_sha256"],"dispatcher_sha256":payload["dispatcher_sha256"],"forced_command":True,"password_locked":True,"secret_material_redacted":True}}
print(json.dumps(result,sort_keys=True,separators=(",",":")))
'''


def ssh_base(alias: str, config: pathlib.Path | None = None) -> list[str]:
    if not ALIAS_RE.fullmatch(alias):
        raise BootstrapError("SSH alias is unsafe")
    command = [
        "ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
        "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15",
    ]
    if config is not None:
        config = config.absolute()
        if not config.is_file() or config.is_symlink():
            raise BootstrapError("release SSH config is missing or unsafe")
        command.extend(["-F", str(config)])
    command.append(alias)
    return command


def provision_target(management_alias: str, role: str, public_key_path: pathlib.Path) -> dict[str, Any]:
    if not public_key_path.is_file() or public_key_path.is_symlink():
        raise BootstrapError("release public-key file is missing or unsafe")
    public_key = validate_public_key(public_key_path.read_text(encoding="utf-8"))
    guard_path = pathlib.Path(__file__).resolve().parent / "android_remote_route_guard.sh"
    guard = guard_path.read_bytes()
    program = target_program(public_key, role, guard)
    completed = subprocess.run(
        [*ssh_base(management_alias), "sudo", "-n", "python3", "-"],
        input=program, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=180, check=False,
    )
    if completed.returncode != 0:
        raise BootstrapError("authorized target bootstrap failed; remote detail withheld")
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise BootstrapError("target bootstrap returned an invalid record count")
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise BootstrapError("target bootstrap returned invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or value.get("ok") is not True
        or value.get("contract") != BOOTSTRAP_CONTRACT
        or value.get("role") != role
        or value.get("account") != ACCOUNT
        or value.get("secret_material_redacted") is not True
        or value.get("guard_sha256") != sha256_bytes(guard)
    ):
        raise BootstrapError("target bootstrap attestation is invalid")
    return value


def hub_data_relay_program(
    *, action: str, target_input: str = "", operation_id: str = "",
) -> str:
    if action not in {"bootstrap", "snapshot", "apply", "observe", "restore"}:
        raise BootstrapError("hub data relay action is invalid")
    if action in {"apply", "observe", "restore"} and not re.fullmatch(r"[0-9a-f]{32}", operation_id):
        raise BootstrapError("hub data relay operation ID is invalid")
    if action in {"bootstrap", "apply"} and not target_input:
        raise BootstrapError("hub data relay input is required")
    if len(target_input.encode("utf-8")) > 512 * 1024:
        raise BootstrapError("hub data relay input is excessive")
    payload = base64.b64encode(target_input.encode("utf-8")).decode("ascii")
    # The streamed relay selects the single current release node from the hub
    # database in read-only mode and uses only the hub's already-pinned key and
    # Cloudflare Access transport. It never emits the management hostname.
    return f'''#!/usr/bin/env python3
import base64, json, os, pathlib, re, sqlite3, subprocess, sys
action={action!r}; operation_id={operation_id!r}; target_input=base64.b64decode({payload!r},validate=True)
def fail(kind):
    print(json.dumps({{"ok":False,"contract":"winsvpn-android-hub-data-relay-v1","error_type":kind,"secret_material_redacted":True}},separators=(",",":")))
    raise SystemExit(1)
if os.geteuid()!=0: fail("root_required")
database=pathlib.Path("/root/vpn_auth/vpn_users.db"); known=pathlib.Path("/root/vpn_auth/managed_known_hosts"); identity=pathlib.Path("/root/.ssh/id_rsa")
if not database.is_file() or not known.is_file() or known.is_symlink() or known.stat().st_mode&0o077 or not identity.is_file() or identity.is_symlink() or identity.stat().st_mode&0o077: fail("management_prerequisite_missing")
try:
    connection=sqlite3.connect(f"file:{{database}}?mode=ro",uri=True,timeout=5); connection.row_factory=sqlite3.Row
    rows=connection.execute("SELECT ssh_host AS host, 'root' AS user FROM nodes WHERE status='online' AND management_status='ok' AND free_access_enabled=1 AND direct_awg_enabled=1 ORDER BY slug").fetchall(); connection.close()
except Exception: fail("database_query_failed")
if len(rows)!=1: fail("eligible_node_ambiguous")
host=str(rows[0]["host"] or "").strip().lower(); user=str(rows[0]["user"] or "").strip().lower()
if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{{0,251}}[a-z0-9])?",host) or user!="root": fail("management_target_invalid")
if not any(line.split(None,1)[0]==host for line in known.read_text(encoding="utf-8",errors="strict").splitlines() if line.strip()): fail("pinned_host_key_missing")
environment=os.environ.copy(); owner_env=pathlib.Path("/root/vpn_auth/.env")
if owner_env.is_file() and not owner_env.is_symlink() and not owner_env.stat().st_mode&0o077:
    for line in owner_env.read_text(encoding="utf-8",errors="strict").splitlines():
        item=line.strip()
        if not item or item.startswith("#") or "=" not in item: continue
        key,raw=item.split("=",1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{{0,127}}",key): environment[key]=raw
command=["ssh","-i",str(identity),"-o","BatchMode=yes","-o","PasswordAuthentication=no","-o","KbdInteractiveAuthentication=no","-o","PreferredAuthentications=publickey","-o","ConnectTimeout=15","-o","ConnectionAttempts=1","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={{known}}","-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no","-o","ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h",f"{{user}}@{{host}}"]
if action=="bootstrap": command += ["sudo","-n","python3","-"]
else:
    command += ["sudo","-n","/usr/local/sbin/winsvpn-android-route-guard",action]
    if operation_id: command.append(operation_id)
try:
    completed=subprocess.run(command,input=target_input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment,timeout=180,check=False)
except Exception: fail("managed_call_failed")
if completed.returncode!=0:
    try:
        rejected=json.loads(completed.stdout.decode("utf-8",errors="strict").strip())
        candidate=str(rejected.get("error",rejected.get("error_type","")))
        if rejected.get("secret_material_redacted") is True and re.fullmatch(r"[a-z][a-z0-9_]*",candidate): fail("target_"+candidate[:56])
    except Exception: pass
    diagnostic="managed_call_rejected_rc_"+str(completed.returncode) if 0 < completed.returncode < 256 else "managed_call_rejected"
    stderr=completed.stderr.decode("utf-8",errors="replace").lower()
    if "password is required" in stderr: diagnostic="target_sudo_password_required"
    elif "not found" in stderr: diagnostic="target_command_not_found"
    elif "syntaxerror" in stderr: diagnostic="target_python_syntax_error"
    elif "permission denied" in stderr: diagnostic="target_permission_denied"
    elif "connection timed out" in stderr or "operation timed out" in stderr: diagnostic="target_connection_timeout"
    fail(diagnostic)
lines=[line for line in completed.stdout.decode("utf-8",errors="strict").splitlines() if line.strip()]
if len(lines)!=1: fail("managed_result_count_invalid")
try: value=json.loads(lines[0])
except Exception: fail("managed_result_invalid_json")
if not isinstance(value,dict) or value.get("secret_material_redacted") is not True: fail("managed_result_contract_invalid")
print(json.dumps(value,sort_keys=True,separators=(",",":")))
'''


def hub_direct_ssh(host: str, identity: pathlib.Path) -> list[str]:
    if not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
        raise BootstrapError("hub host is invalid")
    identity = identity.absolute()
    if not identity.is_file() or identity.is_symlink():
        raise BootstrapError("hub identity is missing or unsafe")
    return [
        "ssh", "-i", str(identity), "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "PreferredAuthentications=publickey", "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=15", f"root@{host}", "python3", "-",
    ]


def hub_data_call(
    hub_host: str, hub_identity: pathlib.Path, *, action: str,
    target_input: str = "", operation_id: str = "",
) -> dict[str, Any]:
    program = hub_data_relay_program(
        action=action, target_input=target_input, operation_id=operation_id,
    )
    completed = subprocess.run(
        hub_direct_ssh(hub_host, hub_identity), input=program, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=210, check=False,
    )
    if completed.returncode != 0:
        diagnostic = "unknown"
        try:
            failure = json.loads(completed.stdout.strip())
            candidate = str(failure.get("error_type", ""))
            if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", candidate):
                diagnostic = candidate
        except (json.JSONDecodeError, AttributeError):
            pass
        raise BootstrapError(
            f"hub-mediated data-node call failed ({diagnostic}); remote detail withheld"
        )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise BootstrapError("hub-mediated data-node call returned an invalid record count")
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise BootstrapError("hub-mediated data-node call returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("secret_material_redacted") is not True:
        raise BootstrapError("hub-mediated data-node attestation is invalid")
    return value


def provision_data_via_hub(
    hub_host: str, hub_identity: pathlib.Path, public_key_path: pathlib.Path,
) -> dict[str, Any]:
    if not public_key_path.is_file() or public_key_path.is_symlink():
        raise BootstrapError("release public-key file is missing or unsafe")
    public_key = validate_public_key(public_key_path.read_text(encoding="utf-8"))
    guard_path = pathlib.Path(__file__).resolve().parent / "android_remote_route_guard.sh"
    guard = guard_path.read_bytes()
    target = target_program(public_key, "node", guard)
    value = hub_data_call(
        hub_host, hub_identity, action="bootstrap", target_input=target,
    )
    if (
        value.get("ok") is not True
        or value.get("contract") != BOOTSTRAP_CONTRACT
        or value.get("role") != "node"
        or value.get("account") != ACCOUNT
        or value.get("guard_sha256") != sha256_bytes(guard)
    ):
        raise BootstrapError("hub-mediated data-node bootstrap attestation is invalid")
    return value


def ssh_effective(alias: str) -> dict[str, list[str]]:
    completed = subprocess.run(
        ["ssh", "-G", alias], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30, check=False,
    )
    if completed.returncode != 0:
        raise BootstrapError(f"management alias {alias} cannot be resolved")
    result: dict[str, list[str]] = {}
    for line in completed.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key and value:
            result.setdefault(key.lower(), []).append(value.strip())
    return result


def one(config: dict[str, list[str]], key: str, default: str = "") -> str:
    values = config.get(key, [])
    return values[0] if values else default


def render_release_alias(alias: str, management_alias: str, identity: pathlib.Path) -> str:
    config = ssh_effective(management_alias)
    hostname = one(config, "hostname")
    port = one(config, "port", "22")
    if not hostname or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise BootstrapError(f"management alias {management_alias} has unsafe host metadata")
    known = one(config, "userknownhostsfile")
    if not known or known.lower() == "none":
        raise BootstrapError(f"management alias {management_alias} lacks a pinned known-hosts file")
    identity_value = identity.absolute().as_posix()
    if any(character.isspace() for character in identity_value):
        raise BootstrapError("release identity path cannot contain whitespace")
    fields = [
        f"Host {alias}", f"  HostName {hostname}", f"  Port {port}", f"  User {ACCOUNT}",
        f"  IdentityFile {identity_value}", "  IdentitiesOnly yes", "  BatchMode yes",
        "  PasswordAuthentication no", "  KbdInteractiveAuthentication no",
        "  PreferredAuthentications publickey", "  StrictHostKeyChecking yes",
        f"  UserKnownHostsFile {known}", "  GlobalKnownHostsFile /dev/null",
        f"  HostKeyAlias {one(config, 'hostkeyalias', hostname)}", "  RequestTTY no",
        "  ClearAllForwardings yes",
    ]
    proxy = one(config, "proxycommand")
    if proxy and proxy.lower() != "none":
        if "\n" in proxy or "\r" in proxy:
            raise BootstrapError("management ProxyCommand is unsafe")
        fields.append(f"  ProxyCommand {proxy}")
    return "\n".join(fields) + "\n"


def validate_release_alias_policy(alias: str, config_path: pathlib.Path) -> None:
    if not ALIAS_RE.fullmatch(alias):
        raise BootstrapError("release alias is unsafe")
    completed = subprocess.run(
        ["ssh", "-G", "-F", str(config_path.absolute()), alias], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
    )
    if completed.returncode != 0:
        raise BootstrapError(f"release alias {alias} cannot be resolved")
    effective: dict[str, list[str]] = {}
    for line in completed.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key and value:
            effective.setdefault(key.lower(), []).append(value.strip())
    required = {
        "user": ACCOUNT,
        "batchmode": "yes",
        "passwordauthentication": "no",
        "kbdinteractiveauthentication": "no",
        "preferredauthentications": "publickey",
        "identitiesonly": "yes",
        "stricthostkeychecking": "true",
        "requesttty": "false",
        "clearallforwardings": "yes",
    }
    for key, expected in required.items():
        actual = one(effective, key).lower()
        # OpenSSH -G normalizes yes/no differently for these two enums.
        if key == "stricthostkeychecking" and actual == "yes":
            actual = "true"
        if key == "requesttty" and actual == "no":
            actual = "false"
        if actual != expected:
            raise BootstrapError(f"release alias {alias} violates {key} policy")
    identity_files = effective.get("identityfile", [])
    if len(identity_files) != 1:
        raise BootstrapError(f"release alias {alias} must expose exactly one identity")
    known = one(effective, "userknownhostsfile")
    if not known or known.lower() == "none":
        raise BootstrapError(f"release alias {alias} lacks pinned known hosts")
    lookup = one(effective, "hostkeyalias", one(effective, "hostname"))
    pinned = False
    for raw_path in known.split():
        candidate = pathlib.Path(raw_path.strip('"')).expanduser()
        if not candidate.is_file() or candidate.is_symlink():
            continue
        check = subprocess.run(
            ["ssh-keygen", "-F", lookup, "-f", str(candidate)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
        )
        if check.returncode == 0 and check.stdout:
            pinned = True
            break
    if not pinned:
        raise BootstrapError(f"release alias {alias} has no matching pinned host key")


def atomic_private_text(path: pathlib.Path, value: str) -> None:
    path = path.absolute()
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise BootstrapError("output path is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".winsvpn-route-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def secure_windows_path(path: pathlib.Path, recursive: bool = False) -> None:
    who = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
    )
    match = re.search(r'"(S-1-[0-9-]+)"', who.stdout)
    if who.returncode != 0 or not match:
        raise BootstrapError("current Windows SID is unavailable for key ACL")
    sid = match.group(1)
    grant = f"*{sid}:(OI)(CI)F" if path.is_dir() else f"*{sid}:F"
    system = "*S-1-5-18:(OI)(CI)F" if path.is_dir() else "*S-1-5-18:F"
    command = ["icacls", str(path), "/inheritance:r", "/grant:r", grant, system]
    if recursive:
        command.extend(["/t", "/c"])
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60, check=False,
    )
    if result.returncode != 0:
        raise BootstrapError("release-key ACL could not be restricted")


def init_release_key(identity: pathlib.Path) -> dict[str, Any]:
    repo = pathlib.Path(__file__).resolve().parent.parent
    identity = identity.absolute()
    try:
        relative = identity.relative_to(repo)
    except ValueError as exc:
        raise BootstrapError("release identity must stay inside the repository") from exc
    if len(relative.parts) < 3 or relative.parts[0] != ".artifacts" or "private" not in relative.parts[1].lower():
        raise BootstrapError("release identity must stay under a private .artifacts directory")
    public = pathlib.Path(str(identity) + ".pub")
    if identity.exists() or identity.is_symlink() or public.exists() or public.is_symlink():
        raise BootstrapError("refusing to replace an existing release identity")
    identity.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "winsvpn-route-release", "-f", str(identity)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
    )
    if completed.returncode != 0 or not identity.is_file() or not public.is_file():
        raise BootstrapError("Ed25519 release identity generation failed")
    validate_public_key(public.read_text(encoding="utf-8"))
    if os.name == "nt":
        secure_windows_path(identity.parent, recursive=True)
    else:
        os.chmod(identity.parent, 0o700)
        os.chmod(identity, 0o600)
        os.chmod(public, 0o644)
    fingerprint = subprocess.run(
        ["ssh-keygen", "-lf", str(public), "-E", "sha256"], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
    )
    if fingerprint.returncode != 0 or "SHA256:" not in fingerprint.stdout:
        raise BootstrapError("release public-key fingerprint failed")
    match = re.search(r"SHA256:[A-Za-z0-9+/]+", fingerprint.stdout)
    if not match:
        raise BootstrapError("release public-key fingerprint is malformed")
    return {
        "ok": True,
        "identity_path": str(identity),
        "public_key_path": str(public),
        "public_key_fingerprint": match.group(0),
        "private_key_printed": False,
        "secret_material_redacted": True,
    }


def fetch_inventory(hub_alias: str, output: pathlib.Path) -> dict[str, Any]:
    source = pathlib.Path(__file__).read_text(encoding="utf-8")
    completed = subprocess.run(
        [*ssh_base(hub_alias), "sudo", "-n", "env", "WINSVPN_ROUTE_BOOTSTRAP_STREAMED=1", "python3", "-", "emit-inventory", "--database", str(DB_PATH)],
        input=source, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=90, check=False,
    )
    if completed.returncode != 0:
        raise BootstrapError("authorized hub inventory query failed; remote detail withheld")
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise BootstrapError("hub inventory query returned an invalid record count")
    try:
        inventory = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise BootstrapError("hub inventory query returned invalid JSON") from exc
    validate_inventory_shape(inventory)
    atomic_private_text(output, json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    return inventory


def validate_inventory_shape(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "contract", "captured_at_utc", "node", "double_vpn", "secret_material_redacted"
    }:
        raise BootstrapError("route inventory top-level contract is invalid")
    if value["schema_version"] != 1 or value["contract"] != CONTRACT or value["secret_material_redacted"] is not True:
        raise BootstrapError("route inventory contract marker is invalid")
    try:
        captured = dt.datetime.fromisoformat(str(value["captured_at_utc"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise BootstrapError("route inventory timestamp is invalid") from exc
    if captured.tzinfo is None or abs(dt.datetime.now(dt.timezone.utc) - captured.astimezone(dt.timezone.utc)) > dt.timedelta(hours=1):
        raise BootstrapError("route inventory is stale or future-dated")
    for mode, alias in (("node", ALIASES["node"]), ("double_vpn", ALIASES["core"])):
        item = value.get(mode)
        if not isinstance(item, dict) or set(item) != {"direct", "advertised_xray_routes", "core_id_sha256", "exit_slug_sha256"}:
            raise BootstrapError(f"{mode} inventory is invalid")
        direct = item["direct"]
        if not isinstance(direct, dict) or direct.get("protocol") != "udp" or direct.get("ssh_alias") != alias:
            raise BootstrapError(f"{mode} direct route is invalid")
        routes = item["advertised_xray_routes"]
        if not isinstance(routes, list) or not routes:
            raise BootstrapError(f"{mode} Xray routes are empty")
        parse_routes(
            [{key: route[key] for key in ("protocol", "port", "security")} for route in routes],
            80, "none", mode,
        )
        if any(route.get("ssh_alias") != alias for route in routes):
            raise BootstrapError(f"{mode} Xray alias is invalid")
        for digest in (item["core_id_sha256"], item["exit_slug_sha256"]):
            if not isinstance(digest, str) or not SHA_RE.fullmatch(digest):
                raise BootstrapError(f"{mode} identity digest is invalid")
    if value["node"]["direct"]["port"] != 9110:
        raise BootstrapError("node direct route must be UDP/9110")
    if value["node"]["core_id_sha256"] != EMPTY_SHA256 or value["node"]["exit_slug_sha256"] != EMPTY_SHA256:
        raise BootstrapError("single-hop identity digests must be empty digests")
    if value["double_vpn"]["core_id_sha256"] in {EMPTY_SHA256, "0" * 64} or value["double_vpn"]["exit_slug_sha256"] in {EMPTY_SHA256, "0" * 64}:
        raise BootstrapError("Double VPN identity digests are sentinels")


def self_test() -> None:
    key_blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"K" * 32
    public = "ssh-ed25519 " + base64.b64encode(key_blob).decode() + " winsvpn-release"
    if validate_public_key(public) != public:
        raise BootstrapError("public-key self-test failed")
    program = target_program(public, "node", b"#!/usr/bin/env bash\nexit 0\n")
    compile(program, "<target-bootstrap>", "exec")
    compile(
        hub_data_relay_program(action="snapshot"),
        "<hub-data-relay>", "exec",
    )
    shell_check = subprocess.run(
        ["bash", "-n"], input=DISPATCHER.encode("utf-8"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=15,
    )
    if shell_check.returncode != 0:
        raise BootstrapError("forced-command dispatcher syntax self-test failed")
    if "SSH_ORIGINAL_COMMAND" not in DISPATCHER or "restrict" not in target_program(public, "core", b"x"):
        raise BootstrapError("forced-command self-test failed")
    now = utc_now()
    sample = {
        "schema_version": 1, "contract": CONTRACT, "captured_at_utc": now,
        "node": {
            "direct": {"protocol": "udp", "port": 9110, "ssh_alias": "node-release"},
            "advertised_xray_routes": [{"protocol": "tcp", "port": 80, "security": "none", "ssh_alias": "node-release"}],
            "core_id_sha256": EMPTY_SHA256, "exit_slug_sha256": EMPTY_SHA256,
        },
        "double_vpn": {
            "direct": {"protocol": "udp", "port": 9210, "ssh_alias": "core-release"},
            "advertised_xray_routes": [{"protocol": "tcp", "port": 443, "security": "tls", "ssh_alias": "core-release"}],
            "core_id_sha256": sha256_text("core"), "exit_slug_sha256": sha256_text("exit"),
        },
        "secret_material_redacted": True,
    }
    validate_inventory_shape(sample)
    print("ANDROID ROUTE GUARD RELEASE BOOTSTRAP SELF-TEST: PASS")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Release-only Android route-guard bootstrap and preflight")
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("self-test")
    init_key = sub.add_parser("init-key")
    init_key.add_argument("--identity", required=True)
    emit = sub.add_parser("emit-inventory")
    emit.add_argument("--database", default=str(DB_PATH))
    fetch = sub.add_parser("fetch-inventory")
    fetch.add_argument("--hub-alias", required=True)
    fetch.add_argument("--output", required=True)
    provision = sub.add_parser("provision-target")
    provision.add_argument("--management-alias", required=True)
    provision.add_argument("--role", choices=sorted(ALIASES), required=True)
    provision.add_argument("--public-key", required=True)
    provision_hub = sub.add_parser("provision-data-via-hub")
    provision_hub.add_argument("--hub-host", required=True)
    provision_hub.add_argument("--hub-identity", required=True)
    provision_hub.add_argument("--public-key", required=True)
    hub_call = sub.add_parser("data-call-via-hub")
    hub_call.add_argument("--hub-host", required=True)
    hub_call.add_argument("--hub-identity", required=True)
    hub_call.add_argument("--action", choices=("snapshot", "apply", "observe", "restore"), required=True)
    hub_call.add_argument("--operation-id", default="")
    hub_call.add_argument("--input", default="")
    aliases = sub.add_parser("render-alias-config")
    aliases.add_argument("--node-management-alias", required=True)
    aliases.add_argument("--core-management-alias", required=True)
    aliases.add_argument("--identity", required=True)
    aliases.add_argument("--output", required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--inventory", required=True)
    preflight.add_argument("--ssh-config", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "self-test":
        self_test()
    elif args.command == "init-key":
        print(json.dumps(init_release_key(pathlib.Path(args.identity)), sort_keys=True, separators=(",", ":")))
    elif args.command == "emit-inventory":
        value = inventory_from_database(pathlib.Path(args.database))
        validate_inventory_shape(value)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    elif args.command == "fetch-inventory":
        value = fetch_inventory(args.hub_alias, pathlib.Path(args.output))
        print(json.dumps({"ok": True, "inventory_sha256": sha256_text(json.dumps(value, indent=2, sort_keys=True) + "\n"), "secret_material_redacted": True}, sort_keys=True, separators=(",", ":")))
    elif args.command == "provision-target":
        value = provision_target(args.management_alias, args.role, pathlib.Path(args.public_key))
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    elif args.command == "provision-data-via-hub":
        value = provision_data_via_hub(
            args.hub_host, pathlib.Path(args.hub_identity), pathlib.Path(args.public_key),
        )
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    elif args.command == "data-call-via-hub":
        target_input = ""
        if args.input:
            input_path = pathlib.Path(args.input).absolute()
            if not input_path.is_file() or input_path.is_symlink() or input_path.stat().st_size > 64 * 1024:
                raise BootstrapError("hub data-call input is missing or unsafe")
            target_input = input_path.read_text(encoding="utf-8")
        value = hub_data_call(
            args.hub_host, pathlib.Path(args.hub_identity), action=args.action,
            target_input=target_input, operation_id=args.operation_id,
        )
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    elif args.command == "render-alias-config":
        identity = pathlib.Path(args.identity).absolute()
        if not identity.is_file() or identity.is_symlink():
            raise BootstrapError("release private-key path is missing or unsafe")
        text = render_release_alias(ALIASES["node"], args.node_management_alias, identity)
        text += "\n" + render_release_alias(ALIASES["core"], args.core_management_alias, identity)
        atomic_private_text(pathlib.Path(args.output), text)
        print(json.dumps({"ok": True, "config_sha256": sha256_text(text), "secret_material_redacted": True}, sort_keys=True, separators=(",", ":")))
    else:
        inventory = pathlib.Path(args.inventory).absolute()
        config = pathlib.Path(args.ssh_config).absolute()
        validate_inventory_shape(json.loads(inventory.read_text(encoding="utf-8")))
        if not config.is_file() or config.is_symlink():
            raise BootstrapError("release SSH config is missing or unsafe")
        for alias in (ALIASES["node"], ALIASES["core"]):
            validate_release_alias_policy(alias, config)
        environment = os.environ.copy()
        environment["WINSVPN_ANDROID_SSH_CONFIG"] = str(config)
        controller = pathlib.Path(__file__).resolve().parent / "android_remote_route_control.py"
        completed = subprocess.run(
            [sys.executable, str(controller), "snapshot", "--inventory", str(inventory)],
            env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=90, check=False,
        )
        if completed.returncode != 0:
            raise BootstrapError("release route-control preflight failed; remote detail withheld")
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            raise BootstrapError("release route-control preflight returned invalid output")
        value = json.loads(lines[0])
        if value.get("passed") is not True or value.get("active_operation_count") != 0 or value.get("secret_material_redacted") is not True:
            raise BootstrapError("release route-control preflight attestation is invalid")
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BootstrapError, OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"ANDROID ROUTE GUARD RELEASE BOOTSTRAP: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
