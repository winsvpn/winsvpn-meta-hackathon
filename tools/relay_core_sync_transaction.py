#!/usr/bin/env python3
"""Relay a staged Core sync transaction through the hidden Control Hub."""

from __future__ import annotations

import argparse
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


def classify_apply_failure(stdout: bytes, stderr: bytes) -> str:
    text = (stdout + b"\n" + stderr).decode("utf-8", errors="replace").lower()
    if "sorry, try again" in text or "incorrect password" in text:
        return "sudo_authentication_failed"
    if "transaction failed; restoring" in text:
        return "remote_transaction_rolled_back"
    if "unexpected staging contract" in text or "staged core sync agent" in text:
        return "remote_stage_validation_failed"
    if "timed out" in text or "timeout" in text:
        return "remote_service_timeout"
    if "failed to start" in text or "job for wins-core-sync.service failed" in text:
        return "remote_sync_service_failed"
    return "remote_transaction_failed"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True)
    parser.add_argument("--apply", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        return fail("root_required")
    stage = pathlib.Path(args.stage).resolve(strict=True)
    apply = pathlib.Path(args.apply).resolve(strict=True)
    if not stage.is_dir() or stage.is_symlink() or not apply.is_file() or apply.is_symlink():
        return fail("invalid_local_stage")
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
            """SELECT management_host AS host,
                      COALESCE(NULLIF(management_user,''),'ubuntu') AS user
               FROM core_servers
               WHERE status='online' AND management_status='ok'
               ORDER BY core_id"""
        ).fetchall()
        connection.close()
    except Exception:
        return fail("database_query_failed")
    if len(rows) != 1:
        return fail("managed_core_is_not_unique")
    host = str(rows[0]["host"] or "").strip().lower()
    user = str(rows[0]["user"] or "").strip().lower()
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        return fail("invalid_management_user")
    if not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|(?:[0-9]{1,3}\.){3}[0-9]{1,3}", host
    ):
        return fail("invalid_management_host")
    if not known_hosts.is_file() or known_hosts.is_symlink() or known_hosts.stat().st_mode & 0o077:
        return fail("unsafe_known_hosts")
    if not identity.is_file():
        return fail("identity_missing")
    if not any(
        line.split(None, 1)[0] == host
        for line in known_hosts.read_text(encoding="utf-8", errors="strict").splitlines()
        if line.strip()
    ):
        return fail("pinned_host_key_missing")

    manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    digest = str(manifest.get("files", [{}])[0].get("sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return fail("invalid_stage_manifest")
    remote_dir = f"/tmp/winsvpn-core-sync-stage-{digest[:16]}"
    destination = f"{user}@{host}"
    ssh_base = [
        "ssh", "-i", str(identity), "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
        "-o", "ConnectionAttempts=1", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no",
    ]
    scp_base = [
        "scp", "-i", str(identity), "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
        "-o", "ConnectionAttempts=1", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UpdateHostKeys=no",
    ]
    if not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", host):
        proxy = "ProxyCommand=/usr/bin/cloudflared access ssh --hostname %h"
        ssh_base += ["-o", proxy]
        scp_base += ["-o", proxy]
    environment = os.environ.copy()
    for line in pathlib.Path("/root/vpn_auth/.env").read_text(encoding="utf-8", errors="strict").splitlines():
        if "=" in line and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", line.split("=", 1)[0]):
            environment[line.split("=", 1)[0]] = line.split("=", 1)[1]

    def invoke(command: list[str], *, input_bytes: bytes | None = None, timeout: int = 180):
        return subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=timeout,
            check=False,
        )

    create = invoke(ssh_base + [destination, f"install -d -m 0700 -- {remote_dir}"])
    if create.returncode != 0:
        return fail("remote_stage_create_failed")
    try:
        sudo_preflight = invoke(
            ssh_base + [destination, "sudo -S -p '' -- true"],
            input_bytes=(password + "\n").encode("utf-8"),
            timeout=30,
        )
        if sudo_preflight.returncode != 0:
            return fail("sudo_preflight_failed")
        files = [stage / "wins-core-sync", stage / "wins-core-sync.timer", stage / "manifest.json", apply]
        copied = invoke(scp_base + [*(str(path) for path in files), f"{destination}:{remote_dir}/"])
        if copied.returncode != 0:
            return fail("remote_stage_copy_failed")
        remote_apply = f"{remote_dir}/{apply.name}"
        remote_command = (
            f"chmod 0700 -- {remote_apply}; chmod 0600 -- {remote_dir}/wins-core-sync "
            f"{remote_dir}/wins-core-sync.timer {remote_dir}/manifest.json; "
            f"sudo -S -p '' -- {remote_apply} {remote_dir} /root"
        )
        applied = invoke(
            ssh_base + [destination, remote_command],
            input_bytes=(password + "\n").encode("utf-8"),
            timeout=240,
        )
        if applied.returncode != 0:
            return fail(classify_apply_failure(applied.stdout, applied.stderr))
        stdout = applied.stdout.decode("utf-8", errors="replace")
        match = re.search(r"Committed Core sync transaction: (/root/winsvpn-core-sync-[0-9TZ]+)", stdout)
        if not match:
            return fail("remote_commit_receipt_missing")
        print(json.dumps({"ok": True, "transaction_dir": match.group(1)}, separators=(",", ":")))
        return 0
    finally:
        cleanup = (
            f"test \"$(readlink -f -- {remote_dir})\" = {remote_dir} && "
            f"find {remote_dir} -xdev -depth -delete"
        )
        invoke(ssh_base + [destination, cleanup], timeout=30)


if __name__ == "__main__":
    raise SystemExit(main())
