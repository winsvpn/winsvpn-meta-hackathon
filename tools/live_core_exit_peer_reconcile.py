#!/usr/bin/env python3
"""Safely reconcile missing Core-to-exit peers through the hub management path.

Run only on the Control Hub.  The tool imports the installed hub application so
it reuses its pinned SSH host keys, Cloudflare Access path, capacity checks,
AmneziaWG container discovery, and serialized peer mutation.  Output and the
rollback receipt contain counts and digests only, never keys or endpoints.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


APP_DIR = pathlib.Path("/root/vpn_auth")
ENV_FILES = (pathlib.Path("/root/vpn_auth.env"), APP_DIR / ".env")
ROLLBACK_ROOT = APP_DIR / "rollback-live-hotfixes"
CONTRACT = "winsvpn-core-exit-peer-reconcile-v1"


def fail(kind: str) -> int:
    print(
        json.dumps(
            {"contract": CONTRACT, "ok": False, "error_type": kind},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 1


def load_owner_environment(path: pathlib.Path) -> None:
    if not path.exists():
        return
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RuntimeError("unsafe_owner_environment")
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        # Both deployment environment files use systemd/shell-compatible
        # quoting.  Parse that quoting instead of retaining literal quote
        # characters (which would make integer settings such as DEVICE_LIMIT
        # invalid when the installed application is imported).
        fields = shlex.split(line, comments=False, posix=True)
        if len(fields) != 1 or "=" not in fields[0]:
            continue
        key, value = fields[0].split("=", 1)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
            os.environ[key] = value


def atomic_json(path: pathlib.Path, value: object) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        pathlib.Path(temporary).unlink(missing_ok=True)
        raise


def target_digest(row: Any) -> str:
    canonical = "|".join(
        str(row[name] or "")
        for name in ("core_id", "slug", "client_public_key", "vpn_internal_ip")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def serialized_remote_awg(app: Any, command: str) -> str:
    wrapped = app.remote_awg_exec_command(command)
    # --close: flock's file form hands the locked descriptor (fd 3) to the
    # command, and it survives exec, so the command AND anything it spawns hold
    # the lock. Measured: a child left behind by this form kept fd 3 on the lock
    # and the hub's next peer sync -- which takes the same lock on fd 9 -- blocked
    # the full `flock -w 10` and returned 503 at Connect. --close closes that
    # descriptor in the child before exec while the flock process itself keeps
    # the lock for the command's lifetime, so serialization is unchanged.
    return (
        "install -d -m 0755 /run/lock; "
        "flock -w 20 --close /run/lock/winsvpn-awg-peer.lock "
        f"sh -lc {shlex.quote(wrapped)}"
    )


def remote_peer_state(app: Any, row: Any) -> str:
    peer = shlex.quote(str(row["client_public_key"]))
    allowed = shlex.quote(str(row["vpn_internal_ip"]) + "/32")
    command = (
        f"peer={peer}; expected={allowed}; "
        "if ! awg show awg0 peers 2>/dev/null | tr ' ' '\\n' | "
        "awk -v peer=\"$peer\" '$0==peer {found=1} END {exit(found ? 0 : 1)}'; "
        "then exit 23; fi; "
        "actual=$(awg show awg0 allowed-ips 2>/dev/null | "
        "awk -v peer=\"$peer\" '$1==peer {print $2; exit}'); "
        "[ \"$actual\" = \"$expected\" ] || exit 24; "
        "psk=$(awg show awg0 preshared-keys 2>/dev/null | "
        "awk -v peer=\"$peer\" '$1==peer {print $2; exit}'); "
        "[ -z \"$psk\" ] || [ \"$psk\" = '(none)' ] || exit 25"
    )
    wrapped = serialized_remote_awg(app, command)
    node_host = row["ssh_host"] or app.extract_node_host(row["endpoint"] or "")
    completed = subprocess.run(
        app.node_ssh_command(node_host, wrapped, connect_timeout=5, multiplex=False),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if completed.returncode == 0:
        return "valid"
    if completed.returncode == 23:
        return "missing"
    if completed.returncode in {24, 25}:
        return "invalid"
    return "unreachable"


def remove_peer(app: Any, row: Any) -> bool:
    peer = shlex.quote(str(row["client_public_key"]))
    wrapped = serialized_remote_awg(app, f"awg set awg0 peer {peer} remove")
    node_host = row["ssh_host"] or app.extract_node_host(row["endpoint"] or "")
    completed = subprocess.run(
        app.node_ssh_command(node_host, wrapped, connect_timeout=5, multiplex=False),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    return completed.returncode == 0


def add_core_peer(app: Any, row: Any) -> bool:
    peer = shlex.quote(str(row["client_public_key"]))
    allowed = shlex.quote(str(row["vpn_internal_ip"]) + "/32")
    customer_limit = app.normalized_node_max_peers(row["max_peers"])
    runtime_limit = customer_limit + app.NODE_RUNTIME_PEER_RESERVE
    command = (
        f"peer={peer}; allowed={allowed}; runtime_limit={runtime_limit}; "
        "peer_count=$(awg show awg0 peers 2>/dev/null | wc -w); "
        "if ! awg show awg0 peers 2>/dev/null | tr ' ' '\\n' | "
        "awk -v peer=\"$peer\" '$0==peer {found=1} END {exit(found ? 0 : 1)}'; "
        "then [ \"$peer_count\" -lt \"$runtime_limit\" ] || exit 75; fi; "
        "awg set awg0 peer \"$peer\" remove 2>/dev/null || true; "
        "awg set awg0 peer \"$peer\" allowed-ips \"$allowed\"; "
        "actual=$(awg show awg0 allowed-ips 2>/dev/null | "
        "awk -v peer=\"$peer\" '$1==peer {print $2; exit}'); "
        "[ \"$actual\" = \"$allowed\" ] || exit 24; "
        "psk=$(awg show awg0 preshared-keys 2>/dev/null | "
        "awk -v peer=\"$peer\" '$1==peer {print $2; exit}'); "
        "[ -z \"$psk\" ] || [ \"$psk\" = '(none)' ] || exit 25"
    )
    wrapped = serialized_remote_awg(app, command)
    node_host = row["ssh_host"] or app.extract_node_host(row["endpoint"] or "")
    completed = subprocess.run(
        app.node_ssh_command(node_host, wrapped, connect_timeout=5, multiplex=False),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    return completed.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--node-slug", default="")
    args = parser.parse_args()
    requested_slug = args.node_slug.strip().lower()
    if requested_slug and not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", requested_slug):
        return fail("invalid_node_slug")
    if os.geteuid() != 0:
        return fail("root_required")
    stage = "load_environment"
    try:
        for path in ENV_FILES:
            load_owner_environment(path)
        stage = "import_app"
        os.chdir(APP_DIR)
        sys.path.insert(0, str(APP_DIR))
        import main as app  # type: ignore[import-not-found]

        stage = "query_targets"
        with app.get_db() as connection:
            app.ensure_schema(connection)
            rows = connection.execute(
                """
                SELECT DISTINCT
                    c.core_id, c.exit_public_key AS client_public_key,
                    e.core_exit_ip AS vpn_internal_ip,
                    n.slug, n.endpoint, n.ssh_host, n.status, n.max_peers,
                    u.expiration_date
                FROM double_vpn_assignments a
                JOIN devices d
                  ON d.device_id=a.device_id AND d.account_number=a.account_number
                JOIN users u ON u.account_number=a.account_number
                JOIN core_exit_peers e
                  ON e.core_id=a.core_id AND e.exit_slug=a.exit_slug
                JOIN core_servers c ON c.core_id=e.core_id
                JOIN nodes n ON n.slug=e.exit_slug
                WHERE a.status='active' AND u.status='active' AND c.status='online'
                  AND c.exit_public_key IS NOT NULL AND c.exit_public_key!=''
                  AND e.core_exit_ip IS NOT NULL AND e.core_exit_ip!=''
                  AND (?='' OR n.slug=?)
                """,
                (requested_slug, requested_slug),
            ).fetchall()
        now = app.utcnow()
        targets: dict[str, Any] = {}
        skipped = 0
        for row in rows:
            expiry = app.parse_iso_datetime(row["expiration_date"])
            if expiry and expiry < now:
                skipped += 1
                continue
            if (row["status"] or "") in {"offline", "maintenance"}:
                skipped += 1
                continue
            targets.setdefault(target_digest(row), row)

        stage = "read_remote_state"
        states = {digest: remote_peer_state(app, row) for digest, row in targets.items()}
        counts = {name: sum(value == name for value in states.values()) for name in ("valid", "missing", "invalid", "unreachable")}
        receipt = None
        applied = 0
        rolled_back = 0
        failed = counts["invalid"] + counts["unreachable"]
        if args.apply:
            stage = "apply_preflight"
            if failed:
                return fail("unsafe_preflight_state")
            timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            receipt_dir = ROLLBACK_ROOT / f"core-exit-peer-resync.{timestamp}"
            receipt_dir.mkdir(parents=True, mode=0o700)
            os.chmod(receipt_dir, 0o700)
            receipt = receipt_dir / "manifest.json"
            manifest = {
                "contract": CONTRACT,
                "created_utc": timestamp,
                "result": "prepared",
                "target_digests": sorted(targets),
                "prestate": {digest: states[digest] for digest in sorted(states)},
            }
            atomic_json(receipt, manifest)
            for digest, row in targets.items():
                if states[digest] != "missing":
                    continue
                ok = add_core_peer(app, row)
                after = remote_peer_state(app, row)
                if ok and after == "valid":
                    applied += 1
                    continue
                if remove_peer(app, row):
                    rolled_back += 1
                failed += 1
            manifest.update(
                {
                    "finished_utc": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
                    "result": "committed" if failed == 0 else "rolled_back",
                    "applied": applied,
                    "rolled_back": rolled_back,
                    "failed": failed,
                }
            )
            atomic_json(receipt, manifest)

        stage = "emit_result"
        payload = {
            "contract": CONTRACT,
            "ok": failed == 0,
            "apply": bool(args.apply),
            "target_count": len(targets),
            "skipped": skipped,
            **{f"{name}_count": count for name, count in counts.items()},
            "applied": applied,
            "rolled_back": rolled_back,
            "failed": failed,
            "receipt_sha256": (
                hashlib.sha256(receipt.read_bytes()).hexdigest() if receipt else ""
            ),
        }
        print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return 0 if payload["ok"] else 1
    except Exception as exc:
        detail = str(exc)
        location = ""
        traceback_cursor = exc.__traceback__
        while traceback_cursor and traceback_cursor.tb_next:
            traceback_cursor = traceback_cursor.tb_next
        if traceback_cursor is not None:
            filename = pathlib.Path(traceback_cursor.tb_frame.f_code.co_filename).name
            location = f"_{re.sub(r'[^a-zA-Z0-9]+', '_', filename)}_{traceback_cursor.tb_lineno}"
        kind = (
            detail
            if re.fullmatch(r"[a-z0-9_]+", detail)
            else f"{stage}_{type(exc).__name__}{location}"
        )
        return fail(kind)


if __name__ == "__main__":
    raise SystemExit(main())
