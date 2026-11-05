#!/usr/bin/env python3
"""Install a staged hub readiness patch with an armed delayed rollback."""

from __future__ import annotations

import argparse
import ast
import hashlib
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


MAIN = pathlib.Path("/root/vpn_auth/main.py")
DB = pathlib.Path("/root/vpn_auth/vpn_users.db")
ROLLBACK_ROOT = pathlib.Path("/root/vpn_auth/rollback-live-hotfixes")
CONTRACT = "winsvpn-control-core-readiness-live-v1"
STAGE_CONTRACT = "winsvpn-control-core-readiness-stage-v1"
SEMANTIC_CONTRACT = "core-registration-snapshot-v5"
REQUIRED_CHANGED_REGIONS = {
    "core_runtime_snapshot_registration",
    "assignment_preparation_retry_headers",
    "assignment_reactivation_ack_invalidation",
    "core_promotion_latch",
}


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path: pathlib.Path, value: object) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        pathlib.Path(temporary).unlink(missing_ok=True)
        raise


def secure_regular(path: pathlib.Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError(f"unsafe_{path.name}")


def top_level_text(source: str, name: str) -> str:
    tree = ast.parse(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if len(matches) != 1 or matches[0].end_lineno is None:
        raise RuntimeError("candidate_semantic_contract_failed")
    node = matches[0]
    first = min((item.lineno for item in node.decorator_list), default=node.lineno)
    return "".join(source.splitlines(keepends=True)[first - 1 : int(node.end_lineno)])


def validate_candidate_contract(source: str) -> None:
    helper = top_level_text(source, "apply_core_registration_runtime_state")
    required_helper = (
        "UPDATE core_servers SET runtime_ready=? WHERE core_id=?",
        "if not runtime_ready:",
        "UPDATE double_vpn_assignments SET runtime_validated_at=NULL WHERE core_id=?",
        "for device_id, revision in reported_revisions.items():",
        'hmac.compare_digest(expected_revisions.get(device_id, ""), revision)',
    )
    forbidden_helper = (
        "validated_assignment_count",
        "runtime_ready = runtime_ready and",
        "runtime_ready = bool(expected_revisions)",
    )
    registration = top_level_text(source, "register_core")
    if (
        any(marker not in helper for marker in required_helper)
        or any(marker in helper for marker in forbidden_helper)
        or "runtime_ready = bool(payload.runtime_ready)" not in registration
        or "acknowledged_count = apply_core_registration_runtime_state(" not in registration
        or "runtime_ready=runtime_ready" not in registration
        or '"promoted": promoted' not in registration
        or '"pending_promotion_id": str(promoted_row["pending_promotion_id"] or "")'
        not in registration
        or '"active_promotion_id": str(promoted_row["active_promotion_id"] or "")'
        not in registration
        or "excluded.promoted" in registration
    ):
        raise RuntimeError("candidate_semantic_contract_failed")
    selector = top_level_text(source, "select_double_vpn_core")
    schema = top_level_text(source, "ensure_schema")
    promotion = top_level_text(source, "admin_promote_core")
    acknowledgement = top_level_text(source, "acknowledge_core_promotion")
    withdrawal = top_level_text(source, "admin_withdraw_core")

    tree = ast.parse(source)
    has_close = any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "close_core_promotion"
        for node in tree.body
    )
    has_sync = any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_verify_account_sync"
        for node in tree.body
    )

    withdrawal_ok = False
    if has_close:
        close_promo = top_level_text(source, "close_core_promotion")
        if (
            'require_admin_token(x_admin_token, request, "withdraw Double VPN Core")'
            in withdrawal
            and "close_core_promotion(" in withdrawal
            and "SET promoted=0, runtime_ready=0" in close_promo
            and "active_promotion_id=NULL" in close_promo
            and "SET status='inactive', applied_revision=NULL, runtime_validated_at=NULL"
            in close_promo
        ):
            withdrawal_ok = True
    elif (
        'require_admin_token(x_admin_token, request, "withdraw Double VPN Core")'
        in withdrawal
        and "SET promoted=0, runtime_ready=0" in withdrawal
        and "active_promotion_id=NULL" in withdrawal
        and "SET status='inactive', applied_revision=NULL, runtime_validated_at=NULL"
        in withdrawal
    ):
        withdrawal_ok = True

    if (
        "AND promoted = 1" not in selector
        or "AND active_promotion_id IS NOT NULL" not in selector
        or "CORE_SELF_READY_SQL" not in selector
        or "AND COALESCE(n.operator_enabled, 0) = 1" not in selector
        or "AND n.retired_at IS NULL" not in selector
        or 'add_column_if_missing(conn, "core_servers", "promoted", "INTEGER NOT NULL DEFAULT 0")'
        not in schema
        or "create_core_promotion_events_table(conn)" not in schema
        or 'add_column_if_missing(conn, "core_servers", "pending_promotion_id", "TEXT")'
        not in schema
        or 'add_column_if_missing(conn, "core_servers", "active_promotion_id", "TEXT")'
        not in schema
        or 'require_admin_token(x_admin_token, request, "promote Double VPN Core")'
        not in promotion
        or "BEGIN IMMEDIATE" not in promotion
        or "pending_promotion_id=?" not in promotion
        or '"promoted": False' not in promotion
        or "CORE_SELF_READY_SQL" not in promotion
        or 'require_core_token(conn, core_id, x_core_token, request, "Core promotion acknowledgement")'
        not in acknowledgement
        or "BEGIN IMMEDIATE" not in acknowledgement
        or "SET promoted=1, active_promotion_id=?" not in acknowledgement
        or "INSERT INTO core_promotion_events" not in acknowledgement
        or "CORE_SELF_READY_SQL" not in acknowledgement
        or not withdrawal_ok
    ):
        raise RuntimeError("candidate_semantic_contract_failed")
    verification_target = "_verify_account_sync" if has_sync else "verify_account"
    verification = top_level_text(source, verification_target)
    required_reactivation_markers = (
        "applied_revision=CASE",
        "runtime_validated_at=CASE",
        "WHEN double_vpn_assignments.status='active'",
        "THEN double_vpn_assignments.applied_revision",
        "THEN double_vpn_assignments.runtime_validated_at",
    )
    inactive_update = (
        "SET status='inactive', applied_revision=NULL, "
        "runtime_validated_at=NULL, updated_at=?"
    )
    if (
        any(marker not in verification for marker in required_reactivation_markers)
        or verification.count(inactive_update) != 2
    ):
        raise RuntimeError("candidate_semantic_contract_failed")
    # M-8: the per-device logout invalidation moved into the shared
    # perform_authenticated_device_logout helper that logout_device and
    # free_logout_device now call (auth runs before any state change). Assert
    # the invalidation on the helper and confirm logout_device delegates to
    # it -- the invariant (a logout invalidates that device's assignment
    # exactly once) is unchanged.
    logout_helper = top_level_text(source, "perform_authenticated_device_logout")
    if logout_helper.count(inactive_update) != 1:
        raise RuntimeError("candidate_semantic_contract_failed")
    logout = top_level_text(source, "logout_device")
    has_logout_sync = any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "logout_device_sync"
        for node in tree.body
    )
    logout_sync = top_level_text(source, "logout_device_sync") if has_logout_sync else ""
    if (
        "perform_authenticated_device_logout" not in logout
        and "perform_authenticated_device_logout" not in logout_sync
    ):
        raise RuntimeError("candidate_semantic_contract_failed")
    verification_tree = ast.parse(verification)
    preparation_errors = []
    preparation_error_code_uses = sum(
        1
        for node in ast.walk(verification_tree)
        if isinstance(node, ast.Constant)
        and node.value == "double_vpn_assignment_preparing"
    )
    for node in ast.walk(verification_tree):
        if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
            continue
        call = node.exc
        if not isinstance(call.func, ast.Name) or call.func.id != "HTTPException":
            continue
        keywords = {item.arg: item.value for item in call.keywords if item.arg}
        try:
            detail = ast.literal_eval(keywords["detail"])
        except (KeyError, ValueError):
            continue
        if detail == "Double VPN Core assignment is still being prepared. Please try again.":
            preparation_errors.append(keywords)
    try:
        status_code = ast.literal_eval(preparation_errors[0]["status_code"])
        headers = ast.literal_eval(preparation_errors[0]["headers"])
    except (IndexError, KeyError, ValueError) as exc:
        raise RuntimeError("candidate_semantic_contract_failed") from exc
    if (
        len(preparation_errors) != 1
        or status_code != 503
        or headers != {
            "X-Wins-Error-Code": "double_vpn_assignment_preparing",
            "Retry-After": "5",
        }
        or preparation_error_code_uses != 1
    ):
        raise RuntimeError("candidate_semantic_contract_failed")


def run(args: list[str], timeout: int = 45) -> bool:
    return subprocess.run(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    ).returncode == 0


def health_ok() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=4) as response:
            return response.status == 200
    except Exception:
        return False


def restart_and_verify() -> bool:
    if not run(["systemctl", "restart", "wins-hub.service"]):
        return False
    for _ in range(20):
        if run(["systemctl", "is-active", "--quiet", "wins-hub.service"], 5) and health_ok():
            return True
        time.sleep(1)
    return False


def cancel_watchdog(unit: str) -> None:
    if re.fullmatch(r"winsvpn-core-readiness-rollback-[0-9]{8}t[0-9]{6}z", unit):
        run(["systemctl", "stop", f"{unit}.timer", f"{unit}.service"], 15)


def commit(transaction: pathlib.Path) -> int:
    transaction = transaction.resolve(strict=True)
    root = ROLLBACK_ROOT.resolve(strict=True)
    if transaction.parent != root or transaction.is_symlink():
        raise RuntimeError("unsafe_transaction_path")
    manifest_path = transaction / "manifest.json"
    secure_regular(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("contract") != CONTRACT or manifest.get("result") != "armed":
        raise RuntimeError("transaction_not_armed")
    if digest(MAIN) != manifest.get("candidate_sha256") or not health_ok():
        raise RuntimeError("commit_postcondition_failed")
    validate_candidate_contract(MAIN.read_text(encoding="utf-8", errors="strict"))
    (transaction / "COMMITTED").touch(mode=0o600, exist_ok=False)
    cancel_watchdog(str(manifest.get("watchdog_unit") or ""))
    manifest.update({"result": "committed", "committed_utc": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())})
    atomic_json(manifest_path, manifest)
    print(json.dumps({"ok": True, "result": "committed", "transaction_dir": str(transaction), "receipt_sha256": digest(manifest_path)}, separators=(",", ":"), sort_keys=True))
    return 0


def apply(stage: pathlib.Path) -> int:
    if os.geteuid() != 0:
        raise RuntimeError("root_required")
    stage = stage.resolve(strict=True)
    candidate = stage / "main.py"
    stage_manifest = stage / "manifest.json"
    for path in (MAIN, DB, candidate, stage_manifest):
        secure_regular(path)
    manifest = json.loads(stage_manifest.read_text(encoding="utf-8"))
    if (
        manifest.get("schema_version") != 2
        or manifest.get("contract") != STAGE_CONTRACT
        or manifest.get("semantic_contract") != SEMANTIC_CONTRACT
        or not REQUIRED_CHANGED_REGIONS <= set(manifest.get("changed_regions") or [])
    ):
        raise RuntimeError("unexpected_stage_contract")
    if manifest.get("secret_material_present") is not False or manifest.get("publication_authorized") is not False:
        raise RuntimeError("unsafe_stage_manifest")
    if digest(MAIN) != manifest.get("preimage_sha256") or digest(candidate) != manifest.get("candidate_sha256"):
        raise RuntimeError("stage_hash_mismatch")
    candidate_text = candidate.read_text(encoding="utf-8", errors="strict")
    compile(candidate_text, str(candidate), "exec")
    validate_candidate_contract(candidate_text)
    if not health_ok() or not run(["systemctl", "is-active", "--quiet", "wins-hub.service"], 5):
        raise RuntimeError("hub_preflight_failed")
    connection = sqlite3.connect(DB, timeout=15)
    if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        connection.close()
        raise RuntimeError("database_integrity_failed")
    core_rows = connection.execute("SELECT COUNT(*) FROM core_servers WHERE status='online' AND management_status='ok'").fetchone()[0]
    if core_rows != 1:
        connection.close()
        raise RuntimeError("managed_core_not_unique")

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    transaction = ROLLBACK_ROOT / f"control-core-readiness.{stamp}"
    transaction.mkdir(mode=0o700)
    preimage = transaction / "main.py.preimage"
    shutil.copy2(MAIN, preimage)
    os.chmod(preimage, 0o600)
    db_preimage = transaction / "vpn_users.db.preimage"
    backup = sqlite3.connect(db_preimage)
    connection.backup(backup)
    backup.close()
    connection.close()
    os.chmod(db_preimage, 0o600)
    watchdog_unit = f"winsvpn-core-readiness-rollback-{stamp.lower()}"
    rollback_script = transaction / "rollback.sh"
    rollback_script.write_text(
        "#!/usr/bin/env bash\nset -Eeuo pipefail\n"
        f"test ! -e {transaction}/COMMITTED || exit 0\n"
        "systemctl stop wins-hub.service\n"
        f"install -o root -g root -m 0600 -- {preimage} /root/vpn_auth/.main.py.readiness-rollback\n"
        "mv -f -- /root/vpn_auth/.main.py.readiness-rollback /root/vpn_auth/main.py\n"
        "systemctl restart wins-hub.service\n"
        f"printf '%s\\n' watchdog-rolled-back > {transaction}/watchdog.result\n",
        encoding="utf-8",
    )
    os.chmod(rollback_script, 0o700)
    live_manifest = {
        "contract": CONTRACT,
        "created_utc": stamp,
        "result": "prepared",
        "preimage_sha256": digest(preimage),
        "candidate_sha256": digest(candidate),
        "database_preimage_sha256": digest(db_preimage),
        "stage_manifest_sha256": digest(stage_manifest),
        "semantic_contract": SEMANTIC_CONTRACT,
        "watchdog_unit": watchdog_unit,
        "watchdog_seconds": 180,
        "database_changes": "additive_schema_only",
    }
    live_manifest_path = transaction / "manifest.json"
    atomic_json(live_manifest_path, live_manifest)
    installed = False
    armed = False
    try:
        if not run([
            "systemd-run", "--quiet", "--unit", watchdog_unit, "--on-active=180s",
            "--timer-property=AccuracySec=1s", str(rollback_script),
        ], 20):
            raise RuntimeError("watchdog_arm_failed")
        armed = True
        info = MAIN.stat()
        temporary = MAIN.with_name(f".main.py.readiness.{os.getpid()}")
        shutil.copy2(candidate, temporary)
        os.chown(temporary, info.st_uid, info.st_gid)
        os.chmod(temporary, stat.S_IMODE(info.st_mode))
        os.replace(temporary, MAIN)
        installed = True
        if digest(MAIN) != live_manifest["candidate_sha256"] or not restart_and_verify():
            raise RuntimeError("hub_install_postflight_failed")
        connection = sqlite3.connect(DB, timeout=15)
        core_columns = {row[1] for row in connection.execute("PRAGMA table_info(core_servers)")}
        assignment_columns = {row[1] for row in connection.execute("PRAGMA table_info(double_vpn_assignments)")}
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        connection.close()
        if not {"regional_aliases", "direct_awg_enabled"} <= core_columns or not {"applied_revision", "runtime_validated_at"} <= assignment_columns or integrity != "ok":
            raise RuntimeError("schema_postflight_failed")
        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/openapi.json", timeout=5) as response:
                openapi = json.loads(response.read())
        except Exception as exc:
            raise RuntimeError("openapi_postflight_failed") from exc
        if "/api/v1/core/assignments/ack" not in openapi.get("paths", {}):
            raise RuntimeError("ack_endpoint_missing")
        live_manifest.update({"result": "armed", "armed_utc": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())})
        atomic_json(live_manifest_path, live_manifest)
        print(json.dumps({"ok": True, "result": "armed", "transaction_dir": str(transaction), "watchdog_unit": watchdog_unit, "candidate_sha256": digest(MAIN), "receipt_sha256": digest(live_manifest_path)}, separators=(",", ":"), sort_keys=True))
        return 0
    except Exception:
        if installed:
            restore = MAIN.with_name(f".main.py.readiness-rollback.{os.getpid()}")
            shutil.copy2(preimage, restore)
            os.replace(restore, MAIN)
            restart_and_verify()
        if armed:
            cancel_watchdog(watchdog_unit)
        live_manifest.update({"result": "rolled_back", "finished_utc": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())})
        atomic_json(live_manifest_path, live_manifest)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--stage")
    group.add_argument("--commit")
    args = parser.parse_args()
    return commit(pathlib.Path(args.commit)) if args.commit else apply(pathlib.Path(args.stage))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        value = str(exc)
        error = value if re.fullmatch(r"[a-z0-9_]+", value) else type(exc).__name__
        print(json.dumps({"ok": False, "result": "not_committed", "error_type": error}, separators=(",", ":"), sort_keys=True))
        raise SystemExit(1)
