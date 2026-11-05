#!/usr/bin/env python3
"""Build a readiness-only hub candidate from an exact live main.py preimage."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import pathlib
import re


HEADER = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''
FUNCTIONS = (
    "create_core_servers_table",
    "create_double_vpn_assignments_table",
    "select_double_vpn_core",
    "mark_stale_nodes_offline",
    "verify_account",
    "logout_device",
    "register_core",
    "core_assignments",
)
REGIONS = (
    "bounded_readiness_timeout",
    "core_registration_models",
    "core_metadata_schema",
    "assignment_revision_helpers",
    "core_runtime_snapshot_registration",
    "assignment_preparation_retry_headers",
    "login_readiness_wait_and_first_hop_metadata",
    "batched_acknowledgement_endpoint",
    "ready_registration_gate",
    "assignment_revision_feed",
    "assignment_reactivation_ack_invalidation",
    "core_promotion_latch",
)
SEMANTIC_CONTRACT = "core-registration-snapshot-v5"


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def embedded_main(source: str) -> str:
    lines = source.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == HEADER]
    if len(starts) != 1:
        raise RuntimeError("embedded_main_header_not_unique")
    start = starts[0] + 1
    ends = [i for i in range(start, len(lines)) if lines[i].strip() == "PYEOF"]
    if not ends:
        raise RuntimeError("embedded_main_terminator_missing")
    return "".join(lines[start : ends[0]])


def top_level(source: str, name: str) -> ast.AST:
    matches = [
        node
        for node in ast.parse(source).body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    if len(matches) != 1 or matches[0].end_lineno is None:
        raise RuntimeError(f"top_level_{name}_not_unique")
    return matches[0]


def span(source: str, name: str, *, decorators: bool = True) -> tuple[int, int, str]:
    node = top_level(source, name)
    first = node.lineno
    if decorators and getattr(node, "decorator_list", None):
        first = min(item.lineno for item in node.decorator_list)
    lines = source.splitlines(keepends=True)
    return first - 1, int(node.end_lineno), "".join(lines[first - 1 : int(node.end_lineno)])


def replace_top_level(live: str, canonical: str, name: str) -> str:
    start, end, _ = span(live, name)
    _, _, replacement = span(canonical, name)
    lines = live.splitlines(keepends=True)
    return "".join(lines[:start]) + replacement + "".join(lines[end:])


def has_top_level(source: str, name: str) -> bool:
    return any(
        isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
        for node in ast.parse(source).body
    )


def assignment_span(source: str, name: str) -> tuple[int, int, str]:
    matches = []
    for node in ast.parse(source).body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            matches.append(node)
    if len(matches) != 1 or matches[0].end_lineno is None:
        raise RuntimeError(f"top_level_assignment_{name}_not_unique")
    node = matches[0]
    lines = source.splitlines(keepends=True)
    return node.lineno - 1, int(node.end_lineno), "".join(
        lines[node.lineno - 1 : int(node.end_lineno)]
    )


def replace_top_level_assignment(live: str, canonical: str, name: str) -> str:
    start, end, _ = assignment_span(live, name)
    _, _, replacement = assignment_span(canonical, name)
    lines = live.splitlines(keepends=True)
    return "".join(lines[:start]) + replacement + "".join(lines[end:])


def function_text(source: str, name: str) -> str:
    return span(source, name)[2]


def validate_candidate_contract(source: str) -> None:
    helper = function_text(source, "apply_core_registration_runtime_state")
    for marker in (
        "UPDATE core_servers SET runtime_ready=? WHERE core_id=?",
        "if not runtime_ready:",
        "UPDATE double_vpn_assignments SET runtime_validated_at=NULL WHERE core_id=?",
        "for device_id, revision in reported_revisions.items():",
        'hmac.compare_digest(expected_revisions.get(device_id, ""), revision)',
    ):
        if marker not in helper:
            raise RuntimeError("runtime_snapshot_semantics_incomplete")
    for forbidden in (
        "validated_assignment_count",
        "runtime_ready = runtime_ready and",
        "runtime_ready = bool(expected_revisions)",
    ):
        if forbidden in helper:
            raise RuntimeError("runtime_snapshot_semantics_stale")

    registration = function_text(source, "register_core")
    for marker in (
        "runtime_ready = bool(payload.runtime_ready)",
        "acknowledged_count = apply_core_registration_runtime_state(",
        "runtime_ready=runtime_ready",
        '"promoted": promoted',
        '"pending_promotion_id": str(promoted_row["pending_promotion_id"] or "")',
        '"active_promotion_id": str(promoted_row["active_promotion_id"] or "")',
    ):
        if marker not in registration:
            raise RuntimeError("runtime_registration_semantics_incomplete")
    if "excluded.promoted" in registration:
        raise RuntimeError("core_promotion_registration_bypass")

    selector = function_text(source, "select_double_vpn_core")
    if (
        "AND promoted = 1" not in selector
        or "AND active_promotion_id IS NOT NULL" not in selector
        or "CORE_SELF_READY_SQL" not in selector
        or "AND COALESCE(n.operator_enabled, 0) = 1" not in selector
        or "AND n.retired_at IS NULL" not in selector
    ):
        raise RuntimeError("core_promotion_selection_gate_incomplete")
    schema = function_text(source, "ensure_schema")
    if (
        'add_column_if_missing(conn, "core_servers", "promoted", "INTEGER NOT NULL DEFAULT 0")'
        not in schema
        or "create_core_promotion_events_table(conn)" not in schema
        or 'add_column_if_missing(conn, "core_servers", "pending_promotion_id", "TEXT")'
        not in schema
        or 'add_column_if_missing(conn, "core_servers", "active_promotion_id", "TEXT")'
        not in schema
    ):
        raise RuntimeError("core_promotion_schema_incomplete")
    promotion = function_text(source, "admin_promote_core")
    acknowledgement = function_text(source, "acknowledge_core_promotion")
    withdrawal = function_text(source, "admin_withdraw_core")
    withdrawal_ok = False
    if has_top_level(source, "close_core_promotion"):
        close_promo = function_text(source, "close_core_promotion")
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
        'require_admin_token(x_admin_token, request, "promote Double VPN Core")'
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
        raise RuntimeError("core_promotion_admin_contract_incomplete")

    verification_target = (
        "_verify_account_sync"
        if has_top_level(source, "_verify_account_sync")
        else "verify_account"
    )
    verification = function_text(source, verification_target)
    tree = ast.parse(verification)
    preparation_errors = []
    preparation_error_code_uses = sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and node.value == "double_vpn_assignment_preparing"
    )
    for node in ast.walk(tree):
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
    if len(preparation_errors) != 1:
        raise RuntimeError("assignment_preparation_error_not_unique")
    try:
        status_code = ast.literal_eval(preparation_errors[0]["status_code"])
        headers = ast.literal_eval(preparation_errors[0]["headers"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError("assignment_preparation_headers_incomplete") from exc
    if status_code != 503 or headers != {
        "X-Wins-Error-Code": "double_vpn_assignment_preparing",
        "Retry-After": "5",
    }:
        raise RuntimeError("assignment_preparation_headers_incomplete")
    if preparation_error_code_uses != 1:
        raise RuntimeError("assignment_preparation_headers_not_scoped")
    for marker in (
        "applied_revision=CASE",
        "runtime_validated_at=CASE",
        "WHEN double_vpn_assignments.status='active'",
        "THEN double_vpn_assignments.applied_revision",
        "THEN double_vpn_assignments.runtime_validated_at",
    ):
        if marker not in verification:
            raise RuntimeError("assignment_reactivation_invalidation_incomplete")
    inactive_update = (
        "SET status='inactive', applied_revision=NULL, "
        "runtime_validated_at=NULL, updated_at=?"
    )
    if verification.count(inactive_update) != 2:
        raise RuntimeError("assignment_deactivation_invalidation_incomplete")
    # M-8: the per-device logout invalidation moved into the shared
    # perform_authenticated_device_logout helper that both logout_device and
    # free_logout_device now call (authentication runs before any state
    # change). The invariant is unchanged -- a logout must invalidate that
    # device's assignment exactly once -- so assert it on the helper and
    # confirm logout_device delegates to it.
    logout_helper = function_text(source, "perform_authenticated_device_logout")
    if logout_helper.count(inactive_update) != 1:
        raise RuntimeError("assignment_logout_invalidation_incomplete")
    logout = function_text(source, "logout_device")
    logout_sync = (
        function_text(source, "logout_device_sync")
        if has_top_level(source, "logout_device_sync")
        else ""
    )
    if (
        "perform_authenticated_device_logout" not in logout
        and "perform_authenticated_device_logout" not in logout_sync
    ):
        raise RuntimeError("assignment_logout_invalidation_incomplete")


def canonical_block(source: str, start_marker: str, end_marker: str) -> str:
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


def build(live: str, canonical: str) -> str:
    if "DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS" not in live:
        marker = 'DOUBLE_VPN_CORE_STALE_SECONDS = max(60, int(os.getenv("DOUBLE_VPN_CORE_STALE_SECONDS", "180")))\n'
        addition = canonical_block(
            canonical,
            "DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS = min(\n",
            "WELCOME_MESSAGE_DEFAULT =",
        )
        if live.count(marker) != 1:
            raise RuntimeError("readiness_timeout_anchor_not_unique")
        live = live.replace(marker, marker + addition, 1)

    live = replace_top_level(live, canonical, "CoreRegistration")
    if "class CoreAssignmentAcknowledgementBatch" not in live:
        _, class_end, _ = span(live, "CoreRegistration", decorators=False)
        _, _, batch = span(canonical, "CoreAssignmentAcknowledgementBatch", decorators=False)
        lines = live.splitlines(keepends=True)
        live = "".join(lines[:class_end]) + "\n" + batch + "".join(lines[class_end:])
    if "class CorePromotionAcknowledgement" not in live:
        _, class_end, _ = span(
            live, "CoreAssignmentAcknowledgementBatch", decorators=False
        )
        _, _, acknowledgement_model = span(
            canonical, "CorePromotionAcknowledgement", decorators=False
        )
        lines = live.splitlines(keepends=True)
        live = (
            "".join(lines[:class_end])
            + "\n"
            + acknowledgement_model
            + "".join(lines[class_end:])
        )

    for name in FUNCTIONS:
        live = replace_top_level(live, canonical, name)

    for helper_name in (
        "_verify_account_impl",
        "_verify_account_sync",
        "free_logout_device_sync",
        "logout_device_sync",
    ):
        if has_top_level(canonical, helper_name):
            if has_top_level(live, helper_name):
                live = replace_top_level(live, canonical, helper_name)
            else:
                insert_at, _, _ = span(live, "logout_device", decorators=False)
                _, _, helper_code = span(canonical, helper_name, decorators=False)
                lines = live.splitlines(keepends=True)
                live = "".join(lines[:insert_at]) + helper_code + "\n\n" + "".join(lines[insert_at:])

    if has_top_level(canonical, "close_core_promotion"):
        if has_top_level(live, "close_core_promotion"):
            live = replace_top_level(live, canonical, "close_core_promotion")
        else:
            insert_at, _, _ = span(live, "select_double_vpn_core", decorators=False)
            _, _, helper = span(canonical, "close_core_promotion", decorators=False)
            lines = live.splitlines(keepends=True)
            live = "".join(lines[:insert_at]) + helper + "\n\n" + "".join(lines[insert_at:])

    if has_top_level(canonical, "_wait_for_core_assignment_ready_sync"):
        if has_top_level(live, "_wait_for_core_assignment_ready_sync"):
            live = replace_top_level(live, canonical, "_wait_for_core_assignment_ready_sync")
        elif has_top_level(live, "wait_for_core_assignment_ready"):
            _, end_pos, _ = span(live, "wait_for_core_assignment_ready")
            _, _, helper = span(canonical, "_wait_for_core_assignment_ready_sync", decorators=False)
            lines = live.splitlines(keepends=True)
            live = "".join(lines[:end_pos]) + "\n\n" + helper + "".join(lines[end_pos:])

    if has_top_level(live, "create_core_promotion_events_table"):
        live = replace_top_level(live, canonical, "create_core_promotion_events_table")
    else:
        insert_at, _, _ = span(live, "create_core_servers_table", decorators=False)
        _, _, event_table = span(
            canonical, "create_core_promotion_events_table", decorators=False
        )
        lines = live.splitlines(keepends=True)
        live = "".join(lines[:insert_at]) + event_table + "\n" + "".join(lines[insert_at:])

    canonical_core_sql = assignment_span(canonical, "CORE_SELF_READY_SQL")[2]
    try:
        assignment_span(live, "CORE_SELF_READY_SQL")
    except RuntimeError:
        insert_at, _, _ = span(live, "select_double_vpn_core", decorators=False)
        lines = live.splitlines(keepends=True)
        live = "".join(lines[:insert_at]) + canonical_core_sql + "\n" + "".join(lines[insert_at:])
    else:
        live = replace_top_level_assignment(live, canonical, "CORE_SELF_READY_SQL")

    if has_top_level(live, "core_promotion_readiness_failures"):
        live = replace_top_level(live, canonical, "core_promotion_readiness_failures")
    else:
        insert_at, _, _ = span(live, "select_double_vpn_core", decorators=False)
        _, _, helper = span(
            canonical, "core_promotion_readiness_failures", decorators=False
        )
        lines = live.splitlines(keepends=True)
        live = "".join(lines[:insert_at]) + helper + "\n" + "".join(lines[insert_at:])

    for name in (
        "admin_promote_core",
        "acknowledge_core_promotion",
        "admin_withdraw_core",
        "admin_list_core_promotions",
    ):
        if has_top_level(live, name):
            live = replace_top_level(live, canonical, name)
            continue
        insert_at, _, _ = span(live, "register_site_ai_tunnel_key")
        _, _, handler = span(canonical, name)
        lines = live.splitlines(keepends=True)
        live = "".join(lines[:insert_at]) + handler + "\n\n" + "".join(lines[insert_at:])

    if "CORE_ASSIGNMENT_REVISION_FIELDS = (" not in live:
        helpers = canonical_block(
            canonical,
            "CORE_ASSIGNMENT_REVISION_FIELDS = (\n",
            "def cleanup_stale_devices(",
        )
        cleanup_start, _, _ = span(live, "cleanup_stale_devices", decorators=False)
        lines = live.splitlines(keepends=True)
        live = "".join(lines[:cleanup_start]) + helpers + "".join(lines[cleanup_start:])

    if "def parse_core_assignment_acknowledgements(" not in live:
        acknowledgements = canonical_block(
            canonical,
            "def parse_core_assignment_acknowledgements(\n",
            '@app.post("/api/v1/core/register")',
        )
        register_start, _, _ = span(live, "register_core")
        lines = live.splitlines(keepends=True)
        live = "".join(lines[:register_start]) + acknowledgements + "".join(lines[register_start:])

    # This helper is deliberately replaced even when the live host already has
    # the earlier readiness schema. The previous implementation derived global
    # Core readiness from all assignments visible after a stale sync snapshot,
    # which is the race this hotfix must remove. A partially deployed older
    # readiness patch may have the surrounding revision helpers but not this
    # function, so insert it exactly once in that case.
    helper_nodes = [
        node
        for node in ast.parse(live).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "apply_core_registration_runtime_state"
    ]
    if len(helper_nodes) > 1:
        raise RuntimeError("top_level_apply_core_registration_runtime_state_not_unique")
    if helper_nodes:
        live = replace_top_level(
            live, canonical, "apply_core_registration_runtime_state"
        )
    else:
        register_start, _, _ = span(live, "register_core")
        _, _, helper = span(
            canonical, "apply_core_registration_runtime_state", decorators=False
        )
        lines = live.splitlines(keepends=True)
        live = "".join(lines[:register_start]) + helper + "\n" + "".join(lines[register_start:])

    required = [
        "DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS = min(",
        "class CoreAssignmentAcknowledgementBatch(BaseModel):",
        "applied_revision TEXT",
        "runtime_validated_at TEXT",
        "def core_assignment_revision(",
        "async def wait_for_core_assignment_ready(",
        '@app.post("/api/v1/core/assignments/ack")',
        "payload.acknowledgements, maximum=1024",
        'regional_aliases = parse_aliases(core["regional_aliases"] or "[]")',
        '"direct_awg_enabled": config_direct_awg_enabled',
        'assignments = active_core_assignment_payloads(conn, requested_core)',
        '"promoted": promoted',
        "AND promoted = 1",
        "CORE_SELF_READY_SQL",
        '@app.post("/admin/core/promote")',
        '@app.post("/admin/core/withdraw")',
        "def create_core_promotion_events_table(",
    ]
    missing = [marker for marker in required if marker not in live]
    if "_wait_for_core_assignment_ready_sync(" not in live and "await wait_for_core_assignment_ready(" not in live:
        missing.append("wait_for_core_assignment_ready_call")
    if missing:
        raise RuntimeError(f"readiness_candidate_incomplete_{len(missing)}")
    if 'subprocess.run(["ssh"' in live or "shell=True" in live:
        raise RuntimeError("unsafe_remote_execution_added")
    compile(live, "main.py", "exec")
    validate_candidate_contract(live)
    return live


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--live", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    source = pathlib.Path(args.source).resolve(strict=True)
    preimage = pathlib.Path(args.live).resolve(strict=True)
    output = pathlib.Path(args.output)
    if output.exists():
        if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
            raise RuntimeError("output_not_empty")
    else:
        output.mkdir(parents=True, mode=0o700)
    canonical = embedded_main(source.read_text(encoding="utf-8", errors="strict"))
    live = preimage.read_text(encoding="utf-8", errors="strict")
    candidate_text = build(live, canonical)
    candidate = output / "main.py"
    fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
        stream.write(candidate_text)
        stream.flush()
        os.fsync(stream.fileno())
    manifest = {
        "schema_version": 2,
        "contract": "winsvpn-control-core-readiness-stage-v1",
        "semantic_contract": SEMANTIC_CONTRACT,
        "source_sha256": sha256(source),
        "preimage_sha256": sha256(preimage),
        "candidate_sha256": sha256(candidate),
        "changed_regions": list(REGIONS),
        "unrelated_live_regions_preserved": True,
        "publication_authorized": False,
        "secret_material_present": False,
    }
    manifest_path = output / "manifest.json"
    fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({**manifest, "manifest_sha256": sha256(manifest_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
