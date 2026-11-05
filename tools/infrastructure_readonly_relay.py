#!/usr/bin/env python3
"""Relay the sanitized infrastructure probe through the hidden control hub.

Run this script on the hub with WINS_RELAY_ROLE=data|core and the local probe
bytes in WINS_PROBE_B64. Set WINS_RELAY_SUDO=1 only when the pinned management
account has reviewed passwordless sudo and a privileged read-only parity result
is required. It selects the saved management hostname from the
SQLite database in read-only mode, uses the existing pinned known-hosts file,
existing SSH key, and outbound Cloudflare Access proxy, and makes no database,
known-hosts, service, firewall, or remote-host change.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import sqlite3
import subprocess


def fail(kind: str) -> int:
    print(json.dumps({"ok": False, "error_type": kind}, separators=(",", ":")))
    return 1


def fail_remote(returncode: int, stderr: bytes) -> int:
    """Return only an allow-listed diagnostic class, never remote stderr."""
    diagnostic = "unknown"
    text = stderr.decode("utf-8", errors="replace")
    for candidate in (
        "PermissionError",
        "FileNotFoundError",
        "TimeoutExpired",
        "JSONDecodeError",
        "OperationalError",
        "ValueError",
        "KeyError",
        "TypeError",
    ):
        if candidate in text:
            diagnostic = candidate
            break
    if diagnostic == "unknown" and "role marker is invalid" in text:
        diagnostic = "invalid_role_marker"
    if diagnostic == "unknown" and "a password is required" in text.lower():
        diagnostic = "sudo_password_required"
    if diagnostic == "unknown" and (
        "not allowed to run sudo" in text.lower()
        or ("sudoers" in text.lower() and "not" in text.lower())
    ):
        diagnostic = "sudo_not_permitted"
    if diagnostic == "unknown" and "sudo: not found" in text.lower():
        diagnostic = "sudo_unavailable"
    print(
        json.dumps(
            {
                "ok": False,
                "error_type": "remote_probe_failed",
                "returncode": returncode,
                "diagnostic": diagnostic,
            },
            separators=(",", ":"),
        )
    )
    return 1


def load_owner_env(path: pathlib.Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        value = line.strip()
        if not value or value.startswith("#") or "=" not in value:
            continue
        key, raw = value.split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
            values[key] = raw
    return values


def build_remote_probe_command(role: str, use_sudo: bool) -> str:
    """Return a constant-shape command from the already allow-listed role."""
    command = f"env WINS_PROBE_ROLE_OVERRIDE={role} python3 -"
    return f"sudo -n {command}" if use_sudo else command


def main() -> int:
    role = os.getenv("WINS_RELAY_ROLE", "")
    if role not in {"data", "core"}:
        return fail("invalid_role")
    sudo_mode = os.getenv("WINS_RELAY_SUDO", "0")
    if sudo_mode not in {"0", "1"}:
        return fail("invalid_sudo_mode")
    try:
        probe = base64.b64decode(os.environ["WINS_PROBE_B64"], validate=True)
    except Exception:
        return fail("invalid_probe")
    if not probe.startswith(b"#!/usr/bin/env python3\n") or len(probe) > 256 * 1024:
        return fail("invalid_probe_contract")

    database = pathlib.Path("/root/vpn_auth/vpn_users.db")
    known_hosts = pathlib.Path("/root/vpn_auth/managed_known_hosts")
    identity = pathlib.Path("/root/.ssh/id_rsa")
    if (
        not database.is_file()
        or not known_hosts.is_file()
        or known_hosts.is_symlink()
        or known_hosts.stat().st_mode & 0o077
        or not identity.is_file()
    ):
        return fail("management_prerequisite_missing")
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        if role == "data":
            row = connection.execute(
                """
                SELECT ssh_host AS host, 'root' AS user
                FROM nodes
                WHERE status='online' AND management_status='ok'
                ORDER BY slug LIMIT 1
                """
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT management_host AS host,
                       COALESCE(NULLIF(management_user,''),'ubuntu') AS user
                FROM core_servers
                WHERE status='online' AND management_status='ok'
                ORDER BY core_id LIMIT 1
                """
            ).fetchone()
        connection.close()
    except Exception:
        return fail("database_query_failed")
    if not row:
        return fail("managed_target_unavailable")
    host = str(row["host"] or "").strip().lower()
    user = str(row["user"] or "").strip().lower()
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        return fail("invalid_management_user")
    if not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
        host,
    ):
        return fail("invalid_management_host")
    if not any(
        line.split(None, 1)[0] == host
        for line in known_hosts.read_text(encoding="utf-8", errors="strict").splitlines()
        if line.strip()
    ):
        return fail("pinned_host_key_missing")

    environment = os.environ.copy()
    environment.update(load_owner_env(pathlib.Path("/root/vpn_auth/.env")))
    command = [
        "ssh",
        "-i",
        str(identity),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=12",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "UpdateHostKeys=no",
    ]
    if not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", host):
        command.extend(
            ["-o", "ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h"]
        )
    remote_probe_command = build_remote_probe_command(role, sudo_mode == "1")
    command.extend([f"{user}@{host}", remote_probe_command])
    try:
        completed = subprocess.run(
            command,
            input=probe,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=180,
            check=False,
        )
    except Exception as exc:
        return fail(f"relay_{type(exc).__name__}")
    if completed.returncode != 0:
        return fail_remote(completed.returncode, completed.stderr)
    try:
        result = json.loads(completed.stdout.decode("utf-8", errors="strict"))
    except Exception:
        return fail("remote_probe_invalid_json")
    if result.get("role") != role:
        return fail("remote_role_mismatch")
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
