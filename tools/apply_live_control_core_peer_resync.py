#!/usr/bin/env python3
"""Transactionally install only the tested Core-peer resync function on a hub."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request


MAIN = pathlib.Path("/root/vpn_auth/main.py")
ROLLBACK_ROOT = pathlib.Path("/root/vpn_auth/rollback-live-hotfixes")
CONTRACT = "winsvpn-control-core-peer-resync-hotfix-v1"
HEREDOC_HEADER = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: pathlib.Path) -> str:
    return digest_bytes(path.read_bytes())


def secure_regular(path: pathlib.Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError(f"unsafe_{path.name}")


def embedded_main(source: str) -> str:
    lines = source.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.strip() == HEREDOC_HEADER]
    if len(starts) != 1:
        raise RuntimeError("embedded_main_header_not_unique")
    start = starts[0] + 1
    ends = [index for index in range(start, len(lines)) if lines[index].strip() == "PYEOF"]
    if not ends:
        raise RuntimeError("embedded_main_terminator_missing")
    return "".join(lines[start : ends[0]])


def function_bounds(source: str, name: str) -> tuple[int, int, str]:
    tree = ast.parse(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if len(matches) != 1 or matches[0].end_lineno is None:
        raise RuntimeError("target_function_not_unique")
    node = matches[0]
    lines = source.splitlines(keepends=True)
    return node.lineno - 1, node.end_lineno, "".join(lines[node.lineno - 1 : node.end_lineno])


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


def health_ok() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=4) as response:
            return response.status == 200
    except Exception:
        return False


def restart_and_verify() -> bool:
    restarted = subprocess.run(
        ["systemctl", "restart", "wins-hub.service"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=45,
        check=False,
    )
    if restarted.returncode != 0:
        return False
    for _ in range(20):
        active = subprocess.run(
            ["systemctl", "is-active", "--quiet", "wins-hub.service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
        if active and health_ok():
            return True
        time.sleep(1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--expected-preimage", required=True)
    args = parser.parse_args()
    source_path = pathlib.Path(args.source)
    expected = args.expected_preimage.strip().lower()
    if os.geteuid() != 0:
        raise RuntimeError("root_required")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RuntimeError("invalid_preimage_hash")
    secure_regular(MAIN)
    secure_regular(source_path)
    if digest(MAIN) != expected:
        raise RuntimeError("live_preimage_changed")

    source_main = embedded_main(source_path.read_text(encoding="utf-8", errors="strict"))
    _, _, replacement = function_bounds(source_main, "resync_active_peers_to_node")
    required = (
        '"core_attempted": 0',
        "FROM double_vpn_assignments a",
        "JOIN core_exit_peers e",
        "c.exit_public_key AS client_public_key",
        '"Double VPN Core exit peer resync failed"',
    )
    if any(marker not in replacement for marker in required):
        raise RuntimeError("replacement_contract_incomplete")

    live = MAIN.read_text(encoding="utf-8", errors="strict")
    start, end, preimage_function = function_bounds(live, "resync_active_peers_to_node")
    lines = live.splitlines(keepends=True)
    candidate = "".join(lines[:start]) + replacement + "".join(lines[end:])
    compile(candidate, str(MAIN), "exec")
    candidate_function = function_bounds(candidate, "resync_active_peers_to_node")[2]
    if candidate_function != replacement:
        raise RuntimeError("candidate_function_mismatch")

    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    rollback = ROLLBACK_ROOT / f"control-core-peer-resync.{timestamp}"
    rollback.mkdir(parents=True, mode=0o700)
    os.chmod(rollback, 0o700)
    preimage = rollback / "main.py.preimage"
    shutil.copy2(MAIN, preimage)
    os.chmod(preimage, 0o600)
    manifest_path = rollback / "manifest.json"
    manifest = {
        "contract": CONTRACT,
        "created_utc": timestamp,
        "result": "prepared",
        "main_preimage_sha256": digest(preimage),
        "function_preimage_sha256": digest_bytes(preimage_function.encode()),
        "function_candidate_sha256": digest_bytes(replacement.encode()),
    }
    atomic_json(manifest_path, manifest)

    installed = False
    try:
        info = MAIN.stat()
        descriptor, temporary = tempfile.mkstemp(prefix=".main.py.core-resync.", dir=MAIN.parent)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(candidate)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, info.st_uid, info.st_gid)
        os.chmod(temporary, stat.S_IMODE(info.st_mode))
        os.replace(temporary, MAIN)
        installed = True
        if function_bounds(MAIN.read_text(encoding="utf-8"), "resync_active_peers_to_node")[2] != replacement:
            raise RuntimeError("installed_function_mismatch")
        if not restart_and_verify():
            raise RuntimeError("hub_health_failed")
        manifest.update(
            {
                "result": "committed",
                "finished_utc": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
                "main_candidate_sha256": digest(MAIN),
            }
        )
        atomic_json(manifest_path, manifest)
        print(
            json.dumps(
                {
                    "contract": CONTRACT,
                    "ok": True,
                    "result": "committed",
                    "main_candidate_sha256": digest(MAIN),
                    "function_candidate_sha256": manifest["function_candidate_sha256"],
                    "receipt_sha256": digest(manifest_path),
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:
        if installed:
            restore = MAIN.with_name(f".main.py.rollback.{os.getpid()}")
            shutil.copy2(preimage, restore)
            os.replace(restore, MAIN)
            restart_and_verify()
        error = str(exc) if re.fullmatch(r"[a-z0-9_]+", str(exc)) else type(exc).__name__
        manifest.update(
            {
                "result": "rolled_back",
                "error_type": error,
                "finished_utc": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
            }
        )
        atomic_json(manifest_path, manifest)
        print(
            json.dumps(
                {
                    "contract": CONTRACT,
                    "ok": False,
                    "result": "rolled_back",
                    "error_type": error,
                    "receipt_sha256": digest(manifest_path),
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        detail = str(exc)
        error = detail if re.fullmatch(r"[a-z0-9_]+", detail) else type(exc).__name__
        print(json.dumps({"contract": CONTRACT, "ok": False, "result": "not_started", "error_type": error}, separators=(",", ":"), sort_keys=True))
        raise SystemExit(1)
