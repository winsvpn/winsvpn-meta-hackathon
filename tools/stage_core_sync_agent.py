#!/usr/bin/env python3
"""Stage the exact Core sync agent emitted by the one-touch installer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys

TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from validate_deployment_scripts import parse_heredocs


HEADER = 'cat > "${sync_tmp}" <<\'EOF\''
NAME = "wins-core-sync"
MODE = 0o700
TIMER_HEADER = "cat > /etc/systemd/system/wins-core-sync.timer <<'EOF'"
TIMER_NAME = "wins-core-sync.timer"
TIMER_MODE = 0o644
REQUIRED_MARKERS = (
    "class=assignment_payload_invalid",
    "class=exit_interface_setup_failed",
    "class=ingress_peer_update_failed",
    "class=client_policy_rule_update_failed",
    "class=exit_metadata_invalid",
    "class=exit_state_directory_failed",
    "class=exit_local_port_invalid",
    "class=exit_xray_selection_failed",
    "existing_stealth_transport_is_healthy",
    "class=healthy_stealth_preserved",
    "class=direct_fallback_persisted",
    "class=exit_transport_state_write_failed",
    "class=exit_config_staging_failed",
    "class=exit_container_replace_failed",
    "class=exit_config_install_failed",
    "class=exit_image_unavailable",
    "class=exit_container_start_failed",
    "class=exit_interface_restart_failed",
    "class=exit_interface_missing_after_restart",
    "class=exit_route_update_failed",
    "class=assignment_identity_invalid",
    "class=assignment_routing_metadata_invalid",
    "class=assignment_revision_invalid",
    "class=ingress_peer_missing",
    "class=ingress_allowed_ip_mismatch",
    "class=ingress_psk_mismatch",
    "class=client_policy_rule_mismatch",
    "class=exit_default_route_mismatch",
    "class=ingress_container_down",
    "class=ingress_key_mismatch",
    "class=ingress_stale_peer_present",
    "class=exit_interface_invalid",
    "class=exit_container_down",
    "class=exit_key_mismatch",
    "class=exit_transport_state_invalid",
    "class=exit_stealth_config_missing",
    "class=exit_stealth_config_invalid",
    "class=exit_stealth_service_inactive",
    "class=exit_handshake_stale",
    "class=exit_handshake_recovery_failed",
    "class=exit_handshake_recovery_non_stealth",
    "class=exit_handshake_recovery_cooldown",
    "class=exit_handshake_recovery_stamp_create_failed",
    "class=exit_handshake_recovery_stamp_write_failed",
    "class=exit_handshake_recovery_stamp_permissions_failed",
    "class=exit_handshake_recovery_stamp_install_failed",
    "class=exit_handshake_recovery_xray_restart_failed",
    "class=exit_handshake_recovery_xray_inactive",
    "class=exit_handshake_recovery_container_restart_failed",
    "class=exit_handshake_recovery_interface_missing_after_restart",
    "class=exit_handshake_recovery_route_metadata_invalid",
    "class=exit_handshake_recovery_route_restore_failed",
    "class=exit_handshake_recovery_timeout",
    "class=forwarding_firewall_rule_missing",
    "class=nat_firewall_rule_missing",
    "class=assignment_runtime_invalid",
)
TRANSPORT_REQUIRED_MARKERS = (
    'mux:{enabled:false,concurrency:0,xudpConcurrency:0,xudpProxyUDP443:"skip"}',
    'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-90}"',
)


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(source: pathlib.Path, output: pathlib.Path) -> dict[str, object]:
    source = source.resolve(strict=True)
    if not source.is_file() or source.is_symlink():
        raise ValueError("Core source must be a regular non-symlink file.")
    if output.exists():
        if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
            raise ValueError("Staging output must be absent or an empty non-symlink directory.")
    else:
        output.mkdir(parents=True, mode=0o700)
    output = output.resolve(strict=True)

    bodies = [block.body for block in parse_heredocs(source) if block.header.strip() == HEADER]
    if len(bodies) != 1:
        raise ValueError(f"Expected exactly one Core sync heredoc, found {len(bodies)}.")
    body = bodies[0]
    if 'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-45}"' in body:
        raise ValueError("Core sync candidate regressed to the undersized 45-second handshake timeout.")
    required = (
        '#!/usr/bin/env bash',
        'CORE_INGRESS_ADDR="${CORE_INGRESS_ADDR:-10.9.1.1/16}"',
        'CORE_SYNC_LOCK_FILE="${CORE_SYNC_LOCK_FILE:-/run/wins-core-sync.lock}"',
        'CORE_SYNC_LOCK_WAIT_SECONDS="${CORE_SYNC_LOCK_WAIT_SECONDS:-120}"',
        'CORE_SYNC_BUSY_EXIT_CODE="${CORE_SYNC_BUSY_EXIT_CODE:-0}"',
        "acquire_core_sync_lock() {",
        'flock -w "${CORE_SYNC_LOCK_WAIT_SECONDS}" 9',
        "return 75",
        "concurrent synchronization invocation skipped; active lock owner remains authoritative",
        "register_core false || true",
        "register_core true",
        "trap - EXIT",
        'CORE_SYNC_FAILURE_STAGE="ready-registration"',
        'Core sync failed during stage=${CORE_SYNC_FAILURE_STAGE}',
        "verify_management_runtime",
        "validate_synced_runtime",
        'CORE_ADVERTISED_STATE_FILE="${CORE_ADVERTISED_STATE_FILE:-/var/lib/winsvpn/core-promotion-state.json}"',
        "persist_core_advertised_state() {",
        '(.promoted | type == "boolean")',
        "winsvpn-core-advertised-state-v2",
        '(.pending_promotion_id | type == "string")',
        'CORE_BUILD_EXCLUSION_LOCK="${CORE_BUILD_EXCLUSION_LOCK:-${CORE_ADVERTISED_STATE_LOCK}.build}"',
        "acknowledge_core_promotion() (",
        'flock -w "${CORE_PROMOTION_ACK_DRAIN_WAIT_SECONDS}" 7',
        "/api/v1/core/promotion/ack",
        'CORE_SYNC_FAILURE_STAGE="promotion-acknowledgement"',
        'persist_core_advertised_state "${response}" "${runtime_ready}"',
        "--cgroup-parent=wins-core.slice",
    ) + REQUIRED_MARKERS + TRANSPORT_REQUIRED_MARKERS
    if 'mux:{enabled:true,concurrency:-1,xudpConcurrency:16,xudpProxyUDP443:"allow"}' in body:
        raise ValueError("Core sync candidate re-enables incompatible XUDP aggregation.")
    missing = [marker for marker in required if marker not in body]
    if missing:
        raise ValueError(f"Core sync readiness contract is incomplete: {missing}")
    if re.search(r"^\s*register_core false\s*$", body, re.MULTILINE):
        raise ValueError("Core sync candidate contains the transient-unready race.")
    if body.index("if acquire_core_sync_lock; then") > body.index(
        'trap \'rc=$?; trap - EXIT; if ((rc != 0)); then warn "Core sync failed during stage=${CORE_SYNC_FAILURE_STAGE}"'
    ):
        raise ValueError("Core sync lock is acquired after the unready failure trap.")
    if "\x00" in body or not body.endswith("\n"):
        raise ValueError("Core sync heredoc is not canonical UTF-8 text.")

    timer_bodies = [block.body for block in parse_heredocs(source) if block.header.strip() == TIMER_HEADER]
    if len(timer_bodies) != 1:
        raise ValueError(f"Expected exactly one Core sync timer heredoc, found {len(timer_bodies)}.")
    timer_body = timer_bodies[0]
    if (
        "OnBootSec=3s" not in timer_body
        or "OnUnitActiveSec=1s" not in timer_body
        or "AccuracySec=100ms" not in timer_body
    ):
        raise ValueError("Core sync timer does not satisfy the bounded readiness interval.")
    entries = []
    for name, mode, content in (
        (NAME, MODE, body),
        (TIMER_NAME, TIMER_MODE, timer_body),
    ):
        candidate = output / name
        descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(candidate, mode)
        entries.append({
            "name": name,
            "sha256": sha256(candidate),
            "size_bytes": candidate.stat().st_size,
            "mode": f"{mode:04o}",
        })
    manifest = {
        "schema_version": 1,
        "contract": "winsvpn-core-sync-staging-v1",
        "source_sha256": sha256(source),
        "files": entries,
        "readiness_transaction": "preserve-until-failure",
        "secret_material_present": False,
        "publication_authorized": False,
    }
    manifest_path = output / "manifest.json"
    descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {**manifest, "manifest_sha256": sha256(manifest_path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(json.dumps(stage(pathlib.Path(args.source), pathlib.Path(args.output)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
