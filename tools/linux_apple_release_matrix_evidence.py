#!/usr/bin/env python3
"""Compile strict Linux/macOS/iOS machine observations into native smoke v2.

This compiler is deliberately fail closed.  It converts hash-bound receipts
from live harnesses into the small public transcript accepted by the release
producer; a hand-written collection of pass booleans is not accepted.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile
import uuid
from typing import Any

from public_release_live_smoke_common import (
    build_receipt_binding,
    producer_contract_hash,
    release_input_binding,
)


MACHINE_CONTRACT = "winsvpn-linux-apple-release-machine-evidence-v1"
NATIVE_CONTRACT = "winsvpn-native-live-smoke-v2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MIN_TRAFFIC_BYTES = 96
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
INVALID_OBSERVATION_DIGESTS = {EMPTY_SHA256, "0" * 64}
APPLE_SPLIT_SCOPE = "destination-consumer-mdm-per-app-only"
LINUX_SPLIT_SCOPE = "launcher-cgroup-v2"
LINUX_PUBLIC_PRODUCER = "tools/linux_public_release_live_smoke.sh"
APPLE_PUBLIC_PRODUCER = "tools/apple_public_release_live_smoke.sh"


class MatrixError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise MatrixError(f"{label} fields are invalid: {actual}")
    return value


def true(value: Any, label: str) -> None:
    if value is not True:
        raise MatrixError(f"{label} must be true")


def false(value: Any, label: str) -> None:
    if value is not False:
        raise MatrixError(f"{label} must be false")


def sha256(value: Any, label: str) -> str:
    text = str(value)
    if not SHA256_RE.fullmatch(text):
        raise MatrixError(f"{label} must be a lowercase SHA-256 digest")
    return text


def parse_utc(value: Any, label: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise MatrixError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise MatrixError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def evidence_file(
    root: pathlib.Path, relative_value: Any, expected_sha256: Any, label: str
) -> pathlib.Path:
    relative = pathlib.Path(str(relative_value))
    if relative.is_absolute() or ".." in relative.parts:
        raise MatrixError(f"{label} path must be relative to the evidence directory")
    resolved_root = root.resolve()
    candidate = resolved_root / relative
    current = resolved_root
    for part in relative.parts:
        current = current / part
        if not current.exists() and not current.is_symlink():
            raise MatrixError(f"{label} does not exist")
        info = current.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag):
            raise MatrixError(f"{label} must not traverse a symlink/reparse point")
    path = candidate.resolve()
    try:
        path.relative_to(resolved_root)
    except ValueError as exc:
        raise MatrixError(f"{label} escaped the evidence directory") from exc
    if not path.is_file() or path.is_symlink():
        raise MatrixError(f"{label} must be a regular file")
    expected = sha256(expected_sha256, f"{label} SHA-256")
    if sha256_file(path) != expected:
        raise MatrixError(f"{label} SHA-256 mismatch")
    return path


def receipt(
    root: pathlib.Path,
    path_value: Any,
    hash_value: Any,
    contract: str,
    fields: set[str],
    label: str,
) -> dict[str, Any]:
    path = evidence_file(root, path_value, hash_value, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MatrixError(f"{label} must be UTF-8 JSON") from exc
    result = exact(value, fields, label)
    if result["schema_version"] != 1 or result["contract"] != contract:
        raise MatrixError(f"{label} contract/version is invalid")
    true(result["secret_material_redacted"], f"{label} redaction")
    parse_utc(result["captured_at_utc"], f"{label} captured_at_utc")
    return result


def validate_binding(
    machine: dict[str, Any],
    artifact: pathlib.Path,
    binding: dict[str, str | int],
) -> None:
    artifact_hash = sha256(machine["artifact_sha256"], "artifact")
    if artifact_hash != sha256_file(artifact):
        raise MatrixError("machine evidence does not match the exact artifact")
    if machine["artifact_size_bytes"] != artifact.stat().st_size:
        raise MatrixError("machine evidence artifact size is wrong")
    for field in (
        "release_input_index_sha256",
        "platform_manifest_sha256",
        "artifact_input_fingerprint_sha256",
        "build_receipt_sha256",
    ):
        if sha256(machine[field], field) != binding[field]:
            raise MatrixError(f"machine evidence does not match {field}")
    field = "producer_contract_sha256"
    if sha256(machine[field], field) != binding.get(field):
        raise MatrixError("machine evidence does not match the producer contract")


def validate_install(
    machine: dict[str, Any], root: pathlib.Path, artifact_hash: str
) -> None:
    platform = machine["platform"]
    install = exact(
        machine["install"],
        {
            "source_artifact_sha256",
            "clean_remove_passed",
            "install_passed",
            "installed_identity_sha256",
            "exact_install_source_verified",
            "receipt_path",
            "receipt_sha256",
        },
        "install observation",
    )
    if sha256(install["source_artifact_sha256"], "install source") != artifact_hash:
        raise MatrixError("install source does not match the tested artifact")
    sha256(install["installed_identity_sha256"], "installed identity")
    for field in ("clean_remove_passed", "install_passed", "exact_install_source_verified"):
        true(install[field], f"install {field}")
    install_receipt_fields = {
        "schema_version",
        "contract",
        "platform",
        "source_artifact_sha256",
        "installed_identity_sha256",
        "app_version",
        "build_number",
        "exact_install_source_verified",
        "captured_at_utc",
        "secret_material_redacted",
    }
    if platform in {"macos", "ios"}:
        install_receipt_fields.update(
            {
                "install_method",
                "installed_bundle_id",
                "installed_team_id",
                "installed_designated_requirement_sha256",
                "install_session_sha256",
            }
        )
    observed = receipt(
        root,
        install["receipt_path"],
        install["receipt_sha256"],
        "winsvpn-install-receipt-v1",
        install_receipt_fields,
        "install receipt",
    )
    if (
        observed["platform"] != platform
        or observed["source_artifact_sha256"] != artifact_hash
        or observed["installed_identity_sha256"] != install["installed_identity_sha256"]
        or observed["app_version"] != machine["app_version"]
        or observed["build_number"] != machine["build_number"]
    ):
        raise MatrixError("install receipt contradicts machine evidence")
    true(observed["exact_install_source_verified"], "install receipt source binding")
    if platform in {"macos", "ios"}:
        expected_method = (
            "macos-signed-package"
            if platform == "macos"
            else "xcode-devicectl-exact-ipa"
        )
        if observed["install_method"] != expected_method:
            raise MatrixError("Apple install receipt method is invalid")
        if observed["installed_bundle_id"] != "org.winsvpn.app":
            raise MatrixError("Apple installed bundle identity is invalid")
        if not re.fullmatch(r"[A-Z0-9]{10}", str(observed["installed_team_id"])):
            raise MatrixError("Apple installed team identity is invalid")
        sha256(
            observed["installed_designated_requirement_sha256"],
            "Apple installed designated requirement",
        )
        sha256(observed["install_session_sha256"], "Apple install session")
    if platform == "linux":
        payload = exact(
            machine["installed_payload"],
            {"path", "sha256", "installed_payload_manifest_sha256"},
            "Linux installed payload",
        )
        report_path = evidence_file(root, payload["path"], payload["sha256"], "Linux installed payload report")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report = exact(
            report,
            {
                "schema_version",
                "contract",
                "platform",
                "artifact_sha256",
                "installed_payload_manifest_sha256",
                "member_count",
                "exact_archive_payload_installed",
                "secret_material_redacted",
            },
            "Linux installed payload report",
        )
        if (
            report["schema_version"] != 1
            or report["contract"] != "winsvpn-linux-installed-payload-v1"
            or report["platform"] != "linux"
            or report["artifact_sha256"] != artifact_hash
            or report["installed_payload_manifest_sha256"]
            != sha256(payload["installed_payload_manifest_sha256"], "installed payload manifest")
            or not isinstance(report["member_count"], int)
            or isinstance(report["member_count"], bool)
            or report["member_count"] < 10
        ):
            raise MatrixError("Linux installed payload report is invalid")
        true(report["exact_archive_payload_installed"], "Linux exact payload")
        true(report["secret_material_redacted"], "Linux payload report redaction")


def route_key(value: dict[str, Any]) -> tuple[str, int, str]:
    protocol = value.get("protocol")
    port = value.get("port")
    security = value.get("security")
    if protocol != "tcp" or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise MatrixError("Xray route protocol/port is invalid")
    if security not in {"none", "tls"}:
        raise MatrixError("Xray route security is invalid")
    return protocol, port, security


def validate_routes(machine: dict[str, Any], root: pathlib.Path) -> list[dict[str, Any]]:
    def route_set(field: str, label: str) -> tuple[set[tuple[str, int, str]], list[dict[str, Any]]]:
        advertised = machine[field]
        if not isinstance(advertised, list) or not 1 <= len(advertised) <= 32:
            raise MatrixError(f"{label} route list is invalid")
        keys: set[tuple[str, int, str]] = set()
        sanitized_routes: list[dict[str, Any]] = []
        for value in advertised:
            route = exact(value, {"protocol", "port", "security"}, label)
            key = route_key(route)
            if key in keys:
                raise MatrixError(f"{label} is duplicated")
            keys.add(key)
            sanitized_routes.append(dict(route))
        return keys, sanitized_routes

    advertised_keys, sanitized = route_set("advertised_xray_routes", "advertised node Xray route")
    double_advertised_keys, double_sanitized = route_set(
        "double_vpn_advertised_xray_routes", "advertised Double VPN Xray route"
    )
    def route_manifest_hash(routes: list[dict[str, Any]]) -> str:
        canonical = json.dumps(
            sorted(routes, key=lambda item: (item["port"], item["security"])),
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(canonical).hexdigest()

    advertised_hash = route_manifest_hash(sanitized)
    double_advertised_hash = route_manifest_hash(double_sanitized)
    direct_port = machine["direct_awg_port"]
    double_direct_port = machine["double_vpn_direct_port"]
    for value, label in ((direct_port, "direct AWG port"), (double_direct_port, "Double VPN direct port")):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise MatrixError(f"{label} is invalid")

    lanes = machine["lanes"]
    if not isinstance(lanes, list) or not lanes:
        raise MatrixError("route lanes are missing")
    lane_ids: set[str] = set()
    direct_count = 0
    double_direct_count = 0
    tested_xray: set[tuple[str, int, str]] = set()
    tested_double_xray: set[tuple[str, int, str]] = set()
    protected_egress_digests: set[str] = set()
    for value in lanes:
        lane_fields = {
            "lane_id",
            "kind",
            "protocol",
            "port",
            "security",
            "runtime_direct_port",
            "advertised_xray_routes_sha256",
            "forcing_blocked_udp_port",
            "connected_passed",
            "double_vpn_active",
            "rx_delta_bytes",
            "tx_delta_bytes",
            "protected_egress_sha256",
            "provider_executable_sha256",
            "control_state_before_sha256",
            "control_state_after_sha256",
            "forcing_applied",
            "forcing_restored",
            "double_vpn_core_id_sha256",
            "double_vpn_exit_slug_sha256",
            "receipt_path",
            "receipt_sha256",
        }
        lane = exact(
            value,
            lane_fields,
            "route lane",
        )
        lane_id = str(lane["lane_id"])
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,79}", lane_id):
            raise MatrixError("route lane ID is invalid")
        if lane_id in lane_ids:
            raise MatrixError("route lane ID is duplicated")
        lane_ids.add(lane_id)
        kind = lane["kind"]
        if kind not in {"direct_awg", "xray", "double_vpn_direct", "double_vpn_xray"}:
            raise MatrixError(f"route lane kind is invalid: {kind}")
        is_xray = kind in {"xray", "double_vpn_xray"}
        is_double = kind in {"double_vpn_direct", "double_vpn_xray"}
        expected_direct_port = double_direct_port if is_double else direct_port
        expected_routes_hash = double_advertised_hash if is_double else advertised_hash
        if lane["runtime_direct_port"] != expected_direct_port:
            raise MatrixError(f"{lane_id} runtime direct port contradicts its mode baseline")
        if sha256(lane["advertised_xray_routes_sha256"], f"{lane_id} advertised route manifest") != expected_routes_hash:
            raise MatrixError(f"{lane_id} advertised route manifest contradicts its mode baseline")
        if lane["double_vpn_active"] is not is_double:
            raise MatrixError(f"{lane_id} Double VPN state is inconsistent")
        if is_xray:
            key = route_key(lane)
            target = tested_double_xray if is_double else tested_xray
            if key in target:
                raise MatrixError(f"{lane_id} duplicates an already tested Xray route")
            target.add(key)
        else:
            if lane["protocol"] != "udp" or lane["port"] != expected_direct_port or lane["security"] != "none":
                raise MatrixError(f"{lane_id} direct AWG port does not match its machine-observed runtime config")
            if is_double:
                double_direct_count += 1
            else:
                direct_count += 1
        true(lane["connected_passed"], f"{lane_id} connection")
        for field in ("rx_delta_bytes", "tx_delta_bytes"):
            if isinstance(lane[field], bool) or not isinstance(lane[field], int) or lane[field] < MIN_TRAFFIC_BYTES:
                raise MatrixError(f"{lane_id} lacks bidirectional traffic proof")
        for field in (
            "protected_egress_sha256",
            "provider_executable_sha256",
            "control_state_before_sha256",
            "control_state_after_sha256",
        ):
            digest = sha256(lane[field], f"{lane_id} {field}")
            if field in {"protected_egress_sha256", "provider_executable_sha256"} and digest in INVALID_OBSERVATION_DIGESTS:
                raise MatrixError(f"{lane_id} {field} is an empty/sentinel observation")
        protected_egress_digests.add(str(lane["protected_egress_sha256"]))
        if lane["control_state_before_sha256"] != lane["control_state_after_sha256"]:
            raise MatrixError(f"{lane_id} did not restore pre-test control state")
        if is_xray:
            true(lane["forcing_applied"], f"{lane_id} forcing apply")
            if lane["forcing_blocked_udp_port"] != expected_direct_port:
                raise MatrixError(f"{lane_id} forcing did not block its mode direct port")
        elif lane["forcing_applied"] is not False:
            raise MatrixError(f"{lane_id} unexpected route forcing")
        elif lane["forcing_blocked_udp_port"] is not None:
            raise MatrixError(f"{lane_id} unexpectedly reports a forced UDP port")
        true(lane["forcing_restored"], f"{lane_id} forcing restore")
        empty_digest = EMPTY_SHA256
        core_digest = sha256(
            lane["double_vpn_core_id_sha256"],
            f"{lane_id} Double VPN Core identity",
        )
        exit_digest = sha256(
            lane["double_vpn_exit_slug_sha256"],
            f"{lane_id} Double VPN exit identity",
        )
        if is_double:
            if core_digest in INVALID_OBSERVATION_DIGESTS or exit_digest in INVALID_OBSERVATION_DIGESTS:
                raise MatrixError(f"{lane_id} lacks real Double VPN Core/exit identity")
        elif core_digest != empty_digest or exit_digest != empty_digest:
            raise MatrixError(f"{lane_id} unexpectedly reports Double VPN identity")
        route_receipt_fields = {
            "schema_version",
            "contract",
            "platform",
            "lane_id",
            "kind",
            "protocol",
            "port",
            "security",
            "runtime_direct_port",
            "advertised_xray_routes_sha256",
            "forcing_blocked_udp_port",
            "double_vpn_active",
            "provider_executable_sha256",
            "connected_observed",
            "rx_delta_bytes",
            "tx_delta_bytes",
            "protected_egress_sha256",
            "control_state_before_sha256",
            "control_state_after_sha256",
            "forcing_applied",
            "forcing_restored",
            "double_vpn_core_id_sha256",
            "double_vpn_exit_slug_sha256",
            "captured_at_utc",
            "secret_material_redacted",
        }
        observed = receipt(
            root,
            lane["receipt_path"],
            lane["receipt_sha256"],
            "winsvpn-route-observation-v1",
            route_receipt_fields,
            f"{lane_id} route receipt",
        )
        receipt_comparison_fields = {
            "platform",
            "lane_id",
            "kind",
            "protocol",
            "port",
            "security",
            "runtime_direct_port",
            "advertised_xray_routes_sha256",
            "forcing_blocked_udp_port",
            "double_vpn_active",
            "provider_executable_sha256",
            "rx_delta_bytes",
            "tx_delta_bytes",
            "protected_egress_sha256",
            "control_state_before_sha256",
            "control_state_after_sha256",
            "forcing_applied",
            "forcing_restored",
            "double_vpn_core_id_sha256",
            "double_vpn_exit_slug_sha256",
        }
        for field in receipt_comparison_fields:
            expected = machine["platform"] if field == "platform" else lane[field]
            if observed[field] != expected:
                raise MatrixError(f"{lane_id} route receipt contradicts {field}")
        true(observed["connected_observed"], f"{lane_id} route observation")
    if direct_count != 1:
        raise MatrixError("exactly one direct AWG lane is required")
    if tested_xray != advertised_keys:
        raise MatrixError("normal Xray lanes do not exactly cover every advertised route")
    if double_direct_count != 1:
        raise MatrixError("exactly one Double VPN direct lane is required")
    if tested_double_xray != double_advertised_keys:
        raise MatrixError(
            "Double VPN Xray lanes do not exactly cover every advertised route"
        )
    if len(protected_egress_digests) != 1:
        raise MatrixError(
            "direct, Xray, and Double VPN lanes did not use one selected exit"
        )
    return sorted(sanitized, key=lambda item: (item["port"], item["security"]))


def validate_matrix_check(
    root: pathlib.Path,
    value: Any,
    name: str,
    contract: str,
    required_fields: set[str],
) -> dict[str, Any]:
    fields = {"receipt_path", "receipt_sha256", *required_fields}
    check = exact(value, fields, name)
    observed = receipt(
        root,
        check["receipt_path"],
        check["receipt_sha256"],
        contract,
        {
            "schema_version",
            "contract",
            *required_fields,
            "captured_at_utc",
            "secret_material_redacted",
        },
        f"{name} receipt",
    )
    for field in required_fields:
        if observed[field] != check[field]:
            raise MatrixError(f"{name} receipt contradicts {field}")
    return check


def validate_behavior(machine: dict[str, Any], root: pathlib.Path) -> None:
    platform = machine["platform"]
    split = validate_matrix_check(
        root,
        machine["split_scope"],
        "split scope",
        "winsvpn-split-observation-v1",
        {
            "scope",
            "consumer_per_app_available",
            "mdm_per_app_only",
            "selection_applied_by_harness",
            "selected_scope_bypassed",
            "ordinary_scope_protected",
        },
    )
    if platform == "linux":
        if split["scope"] != LINUX_SPLIT_SCOPE:
            raise MatrixError("Linux split evidence is not launcher/cgroup scoped")
        true(split["consumer_per_app_available"], "Linux consumer per-app scope")
        false(split["mdm_per_app_only"], "Linux MDM-only split")
    else:
        if split["scope"] != APPLE_SPLIT_SCOPE:
            raise MatrixError("Apple split evidence does not state its consumer limitation")
        false(split["consumer_per_app_available"], "Apple consumer per-app scope")
        true(split["mdm_per_app_only"], "Apple MDM-only split")
    for field in ("selection_applied_by_harness", "selected_scope_bypassed", "ordinary_scope_protected"):
        true(split[field], f"split {field}")

    leak = validate_matrix_check(
        root,
        machine["leak"],
        "leak",
        "winsvpn-leak-observation-v1",
        {"dns_protected", "ipv4_protected", "ipv6_escape_blocked", "public_canaries_agree"},
    )
    for field in ("dns_protected", "ipv4_protected", "ipv6_escape_blocked", "public_canaries_agree"):
        true(leak[field], f"leak {field}")

    change = validate_matrix_check(
        root,
        machine["network_change"],
        "network change",
        "winsvpn-network-change-observation-v1",
        {
            "change_triggered_by_harness",
            "pre_change_protected",
            "post_change_recovered",
            "post_change_protected",
        },
    )
    for field in ("change_triggered_by_harness", "pre_change_protected", "post_change_recovered", "post_change_protected"):
        true(change[field], f"network change {field}")

    teardown = validate_matrix_check(
        root,
        machine["teardown"],
        "teardown",
        "winsvpn-teardown-observation-v1",
        {
            "disconnect_requested_by_harness",
            "provider_absent",
            "protected_routes_absent",
            "transient_state_absent",
        },
    )
    for field in ("disconnect_requested_by_harness", "provider_absent", "protected_routes_absent", "transient_state_absent"):
        true(teardown[field], f"teardown {field}")

    rollback = validate_matrix_check(
        root,
        machine["rollback"],
        "rollback",
        "winsvpn-rollback-observation-v1",
        {
            "failure_injected_by_harness",
            "prior_state_sha256",
            "restored_state_sha256",
            "recovery_connect_passed",
        },
    )
    sha256(rollback["prior_state_sha256"], "rollback prior state")
    sha256(rollback["restored_state_sha256"], "rollback restored state")
    if rollback["prior_state_sha256"] != rollback["restored_state_sha256"]:
        raise MatrixError("rollback did not restore the exact prior state")
    true(rollback["failure_injected_by_harness"], "rollback failure injection")
    true(rollback["recovery_connect_passed"], "rollback recovery connect")


def validate_map(
    machine: dict[str, Any], root: pathlib.Path, map_screenshot: pathlib.Path
) -> dict[str, Any]:
    visual = exact(
        machine["map_visual"],
        {
            "screenshot_sha256",
            "capture_method",
            "radius_label_50_miles_detected",
            "surrounding_city_label_count",
            "target_marker_detected",
            "viewport_not_world_zoom",
            "receipt_path",
            "receipt_sha256",
        },
        "map visual",
    )
    screenshot_hash = sha256(visual["screenshot_sha256"], "map screenshot")
    if sha256_file(map_screenshot) != screenshot_hash:
        raise MatrixError("map screenshot does not match machine evidence")
    if visual["capture_method"] not in {"linux-window-capture", "macos-window-capture", "xcode-device-ui-capture"}:
        raise MatrixError("map capture method is not machine controlled")
    for field in ("radius_label_50_miles_detected", "target_marker_detected", "viewport_not_world_zoom"):
        true(visual[field], f"map {field}")
    if isinstance(visual["surrounding_city_label_count"], bool) or not isinstance(visual["surrounding_city_label_count"], int) or visual["surrounding_city_label_count"] < 2:
        raise MatrixError("map capture lacks at least two surrounding city labels")
    observed = receipt(
        root,
        visual["receipt_path"],
        visual["receipt_sha256"],
        "winsvpn-map-capture-observation-v1",
        {
            "schema_version",
            "contract",
            "platform",
            "screenshot_sha256",
            "capture_method",
            "radius_label_50_miles_detected",
            "surrounding_city_label_count",
            "target_marker_detected",
            "viewport_not_world_zoom",
            "captured_at_utc",
            "secret_material_redacted",
        },
        "map capture receipt",
    )
    for field in (
        "screenshot_sha256",
        "capture_method",
        "radius_label_50_miles_detected",
        "surrounding_city_label_count",
        "target_marker_detected",
        "viewport_not_world_zoom",
    ):
        if observed[field] != visual[field]:
            raise MatrixError(f"map receipt contradicts {field}")
    if observed["platform"] != machine["platform"]:
        raise MatrixError("map receipt platform is wrong")
    return visual


def compile_evidence(
    machine: dict[str, Any],
    root: pathlib.Path,
    artifact: pathlib.Path,
    map_screenshot: pathlib.Path,
    binding: dict[str, str | int],
    evidence_bundle_index_sha256: str | None = None,
) -> dict[str, Any]:
    top_fields = {
        "schema_version",
        "contract",
        "platform",
        "app_version",
        "build_number",
        "artifact_sha256",
        "artifact_size_bytes",
        "release_input_index_sha256",
        "platform_manifest_sha256",
        "artifact_input_fingerprint_sha256",
        "build_receipt_sha256",
        "run_id",
        "captured_at_utc",
        "secret_material_redacted",
        "install",
        "advertised_xray_routes",
        "double_vpn_advertised_xray_routes",
        "direct_awg_port",
        "double_vpn_direct_port",
        "lanes",
        "split_scope",
        "leak",
        "network_change",
        "teardown",
        "rollback",
        "map_visual",
    }
    platform = machine.get("platform")
    if platform == "linux":
        top_fields.update({"installed_payload"})
    top_fields.update({"producer_contract_sha256"})
    evidence = exact(machine, top_fields, "machine evidence")
    if evidence["schema_version"] != 1 or evidence["contract"] != MACHINE_CONTRACT:
        raise MatrixError("machine evidence contract/version is invalid")
    if platform not in {"linux", "ios", "macos"}:
        raise MatrixError("machine evidence platform is invalid")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(evidence["app_version"])):
        raise MatrixError("app version is invalid")
    if not isinstance(evidence["build_number"], str) or not evidence["build_number"].isdigit():
        raise MatrixError("build number is invalid")
    try:
        parsed_run_id = uuid.UUID(str(evidence["run_id"]))
    except ValueError as exc:
        raise MatrixError("run ID is invalid") from exc
    if parsed_run_id.int == 0:
        raise MatrixError("run ID must not be empty")
    parse_utc(evidence["captured_at_utc"], "captured_at_utc")
    true(evidence["secret_material_redacted"], "machine evidence redaction")
    validate_binding(evidence, artifact, binding)
    artifact_hash = sha256(evidence["artifact_sha256"], "artifact")
    validate_install(evidence, root, artifact_hash)
    routes = validate_routes(evidence, root)
    validate_behavior(evidence, root)
    visual = validate_map(evidence, root, map_screenshot)
    result = {
        "schema_version": 2,
        "contract": NATIVE_CONTRACT,
        "platform": platform,
        "app_version": evidence["app_version"],
        "build_number": evidence["build_number"],
        "artifact_sha256": artifact_hash,
        "run_id": str(parsed_run_id),
        "captured_at_utc": evidence["captured_at_utc"],
        "secret_material_redacted": True,
        "checks": {
            "artifact_signature": True,
            "clean_install": True,
            "ip_map_50_mile_city_context": True,
            "split_tunneling_contract": True,
            "double_vpn": True,
            "leak_test": True,
        },
        "map_visual": {
            "screenshot_sha256": visual["screenshot_sha256"],
            "radius_miles": 50,
            "city_labels_visible": True,
            "target_marker_visible": True,
            "viewport_not_world_zoom": True,
        },
        "direct_awg": {
            "protocol": "udp",
            "port": evidence["direct_awg_port"],
            "passed": True,
        },
        "advertised_xray_routes": routes,
        "tested_xray_routes": [{**route, "passed": True} for route in routes],
    }
    if evidence_bundle_index_sha256 is not None:
        result["evidence_bundle_index_sha256"] = sha256(
            evidence_bundle_index_sha256, "evidence bundle index"
        )
    return result


def atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, indent=2) + "\n")
    os.replace(temporary, path)


def write_receipt(root: pathlib.Path, name: str, value: dict[str, Any]) -> tuple[str, str]:
    path = root / name
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    return name, sha256_file(path)


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="wins-linux-apple-matrix-") as name:
        root = pathlib.Path(name)
        artifact = root / "artifact.bin"
        artifact.write_bytes(b"exact-artifact")
        screenshot = root / "map.png"
        screenshot.write_bytes(b"machine-map-screenshot")
        artifact_hash = sha256_file(artifact)
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        binding = {
            "release_input_index_sha256": "1" * 64,
            "platform_manifest_sha256": "2" * 64,
            "artifact_input_fingerprint_sha256": "3" * 64,
            "build_receipt_sha256": "4" * 64,
            "producer_contract_sha256": "a" * 64,
        }

        def make_receipt(name: str, contract: str, fields: dict[str, Any]) -> dict[str, str]:
            path, digest = write_receipt(
                root,
                name,
                {
                    "schema_version": 1,
                    "contract": contract,
                    **fields,
                    "captured_at_utc": now,
                    "secret_material_redacted": True,
                },
            )
            return {"receipt_path": path, "receipt_sha256": digest}

        install_fields = {
            "platform": "macos",
            "source_artifact_sha256": artifact_hash,
            "installed_identity_sha256": "5" * 64,
            "app_version": "1.0.14",
            "build_number": "29",
            "exact_install_source_verified": True,
            "install_method": "macos-signed-package",
            "installed_bundle_id": "org.winsvpn.app",
            "installed_team_id": "5YT8H4U72M",
            "installed_designated_requirement_sha256": "d" * 64,
            "install_session_sha256": "e" * 64,
        }
        base: dict[str, Any] = {
            "schema_version": 1,
            "contract": MACHINE_CONTRACT,
            "platform": "macos",
            "app_version": "1.0.14",
            "build_number": "29",
            "artifact_sha256": artifact_hash,
            "artifact_size_bytes": artifact.stat().st_size,
            **binding,
            "run_id": str(uuid.uuid4()),
            "captured_at_utc": now,
            "secret_material_redacted": True,
            "install": {
                "source_artifact_sha256": artifact_hash,
                "clean_remove_passed": True,
                "install_passed": True,
                "installed_identity_sha256": "5" * 64,
                "exact_install_source_verified": True,
                **make_receipt("install.json", "winsvpn-install-receipt-v1", install_fields),
            },
            "advertised_xray_routes": [
                {"protocol": "tcp", "port": 80, "security": "none"},
                {"protocol": "tcp", "port": 443, "security": "tls"},
            ],
            "double_vpn_advertised_xray_routes": [
                {"protocol": "tcp", "port": 8080, "security": "none"},
                {"protocol": "tcp", "port": 8443, "security": "tls"},
            ],
            "direct_awg_port": 9110,
            "double_vpn_direct_port": 9210,
            "lanes": [],
            "split_scope": {},
            "leak": {},
            "network_change": {},
            "teardown": {},
            "rollback": {},
            "map_visual": {},
        }

        def lane(lane_id: str, kind: str, protocol: str, port: int, security: str, double: bool) -> dict[str, Any]:
            core_digest = hashlib.sha256(
                b"north-america-core" if double else b""
            ).hexdigest()
            exit_digest = hashlib.sha256(b"spain" if double else b"").hexdigest()
            runtime_direct_port = base[
                "double_vpn_direct_port" if double else "direct_awg_port"
            ]
            mode_routes = base[
                "double_vpn_advertised_xray_routes"
                if double else "advertised_xray_routes"
            ]
            routes_hash = hashlib.sha256(
                json.dumps(
                    mode_routes, separators=(",", ":"), sort_keys=True
                ).encode()
            ).hexdigest()
            is_xray = kind in {"xray", "double_vpn_xray"}
            fields = {
                "platform": "macos",
                "lane_id": lane_id,
                "kind": kind,
                "protocol": protocol,
                "port": port,
                "security": security,
                "runtime_direct_port": runtime_direct_port,
                "advertised_xray_routes_sha256": routes_hash,
                "forcing_blocked_udp_port": runtime_direct_port if is_xray else None,
                "double_vpn_active": double,
                "provider_executable_sha256": "6" * 64,
                "connected_observed": True,
                "rx_delta_bytes": 256,
                "tx_delta_bytes": 512,
                "protected_egress_sha256": "7" * 64,
                "control_state_before_sha256": "8" * 64,
                "control_state_after_sha256": "8" * 64,
                "forcing_applied": is_xray,
                "forcing_restored": True,
                "double_vpn_core_id_sha256": core_digest,
                "double_vpn_exit_slug_sha256": exit_digest,
            }
            return {
                "lane_id": lane_id,
                "kind": kind,
                "protocol": protocol,
                "port": port,
                "security": security,
                "runtime_direct_port": runtime_direct_port,
                "advertised_xray_routes_sha256": routes_hash,
                "forcing_blocked_udp_port": runtime_direct_port if is_xray else None,
                "connected_passed": True,
                "double_vpn_active": double,
                "rx_delta_bytes": 256,
                "tx_delta_bytes": 512,
                "protected_egress_sha256": "7" * 64,
                "provider_executable_sha256": "6" * 64,
                "control_state_before_sha256": "8" * 64,
                "control_state_after_sha256": "8" * 64,
                "forcing_applied": is_xray,
                "forcing_restored": True,
                "double_vpn_core_id_sha256": core_digest,
                "double_vpn_exit_slug_sha256": exit_digest,
                **make_receipt(f"{lane_id}.json", "winsvpn-route-observation-v1", fields),
            }

        base["lanes"] = [
            lane("direct-awg", "direct_awg", "udp", 9110, "none", False),
            lane("xray-80-none", "xray", "tcp", 80, "none", False),
            lane("xray-443-tls", "xray", "tcp", 443, "tls", False),
            lane("double-direct", "double_vpn_direct", "udp", 9210, "none", True),
            lane("double-xray-8080-none", "double_vpn_xray", "tcp", 8080, "none", True),
            lane("double-xray-8443-tls", "double_vpn_xray", "tcp", 8443, "tls", True),
        ]

        split_fields = {
            "scope": APPLE_SPLIT_SCOPE,
            "consumer_per_app_available": False,
            "mdm_per_app_only": True,
            "selection_applied_by_harness": True,
            "selected_scope_bypassed": True,
            "ordinary_scope_protected": True,
        }
        base["split_scope"] = {
            **split_fields,
            **make_receipt("split.json", "winsvpn-split-observation-v1", split_fields),
        }
        check_specs = {
            "leak": (
                "winsvpn-leak-observation-v1",
                {"dns_protected": True, "ipv4_protected": True, "ipv6_escape_blocked": True, "public_canaries_agree": True},
            ),
            "network_change": (
                "winsvpn-network-change-observation-v1",
                {"change_triggered_by_harness": True, "pre_change_protected": True, "post_change_recovered": True, "post_change_protected": True},
            ),
            "teardown": (
                "winsvpn-teardown-observation-v1",
                {"disconnect_requested_by_harness": True, "provider_absent": True, "protected_routes_absent": True, "transient_state_absent": True},
            ),
            "rollback": (
                "winsvpn-rollback-observation-v1",
                {"failure_injected_by_harness": True, "prior_state_sha256": "9" * 64, "restored_state_sha256": "9" * 64, "recovery_connect_passed": True},
            ),
        }
        for field, (contract, values) in check_specs.items():
            base[field] = {**values, **make_receipt(f"{field}.json", contract, values)}
        map_fields = {
            "platform": "macos",
            "screenshot_sha256": sha256_file(screenshot),
            "capture_method": "macos-window-capture",
            "radius_label_50_miles_detected": True,
            "surrounding_city_label_count": 3,
            "target_marker_detected": True,
            "viewport_not_world_zoom": True,
        }
        base["map_visual"] = {
            **{key: value for key, value in map_fields.items() if key != "platform"},
            **make_receipt("map.json", "winsvpn-map-capture-observation-v1", map_fields),
        }
        native = compile_evidence(base, root, artifact, screenshot, binding)
        if native["direct_awg"]["port"] != 9110 or len(native["tested_xray_routes"]) != 2:
            raise MatrixError("positive machine-evidence self-test failed")

        linux_install_fields = {
            key: value
            for key, value in install_fields.items()
            if key
            not in {
                "install_method",
                "installed_bundle_id",
                "installed_team_id",
                "installed_designated_requirement_sha256",
                "install_session_sha256",
            }
        }
        linux_install_fields["platform"] = "linux"
        linux_payload = {
            "schema_version": 1,
            "contract": "winsvpn-linux-installed-payload-v1",
            "platform": "linux",
            "artifact_sha256": artifact_hash,
            "installed_payload_manifest_sha256": "b" * 64,
            "member_count": 12,
            "exact_archive_payload_installed": True,
            "secret_material_redacted": True,
        }
        payload_path, payload_hash = write_receipt(
            root, "linux-installed-payload.json", linux_payload
        )
        linux_machine = {
            "platform": "linux",
            "app_version": "1.0.14",
            "build_number": "29",
            "install": {
                "source_artifact_sha256": artifact_hash,
                "clean_remove_passed": True,
                "install_passed": True,
                "installed_identity_sha256": "5" * 64,
                "exact_install_source_verified": True,
                **make_receipt(
                    "linux-install.json",
                    "winsvpn-install-receipt-v1",
                    linux_install_fields,
                ),
            },
            "installed_payload": {
                "path": payload_path,
                "sha256": payload_hash,
                "installed_payload_manifest_sha256": "b" * 64,
            },
        }
        validate_install(linux_machine, root, artifact_hash)
        bad_linux_machine = copy.deepcopy(linux_machine)
        bad_linux_machine["installed_payload"]["installed_payload_manifest_sha256"] = "c" * 64
        try:
            validate_install(bad_linux_machine, root, artifact_hash)
        except MatrixError:
            pass
        else:
            raise MatrixError("changed Linux installed-payload identity was accepted")

        mutations: list[dict[str, Any]] = []
        bad = copy.deepcopy(base)
        bad["lanes"] = [lane for lane in bad["lanes"] if lane["port"] != 443]
        mutations.append(bad)
        bad = copy.deepcopy(base)
        bad["split_scope"]["consumer_per_app_available"] = True
        mutations.append(bad)
        bad = copy.deepcopy(base)
        bad["network_change"]["change_triggered_by_harness"] = False
        mutations.append(bad)
        bad = copy.deepcopy(base)
        bad["rollback"]["restored_state_sha256"] = "a" * 64
        mutations.append(bad)
        bad = copy.deepcopy(base)
        bad["map_visual"]["surrounding_city_label_count"] = 1
        mutations.append(bad)
        for invalid in mutations:
            try:
                compile_evidence(invalid, root, artifact, screenshot, binding)
            except MatrixError:
                continue
            raise MatrixError("negative machine-evidence self-test was accepted")
    print("LINUX/APPLE RELEASE MATRIX EVIDENCE SELF-TEST: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--machine-evidence")
    parser.add_argument("--artifact")
    parser.add_argument("--map-screenshot")
    parser.add_argument("--release-input-index")
    parser.add_argument("--build-receipt")
    parser.add_argument("--evidence-bundle-index-sha256")
    parser.add_argument("--output")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    required = (
        args.machine_evidence,
        args.artifact,
        args.map_screenshot,
        args.release_input_index,
        args.build_receipt,
        args.output,
    )
    if any(not value for value in required):
        parser.error("machine evidence, artifact, map screenshot, release input index, build receipt, and output are required")
    machine_path = pathlib.Path(args.machine_evidence).expanduser().resolve()
    artifact = pathlib.Path(args.artifact).expanduser().resolve()
    map_screenshot = pathlib.Path(args.map_screenshot).expanduser().resolve()
    if not machine_path.is_file() or not artifact.is_file() or not map_screenshot.is_file():
        raise MatrixError("machine evidence, artifact, or map screenshot is missing")
    try:
        machine = json.loads(machine_path.read_text(encoding="utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MatrixError("machine evidence must be UTF-8 JSON") from exc
    platform = str(machine.get("platform", ""))
    if platform not in {"linux", "ios", "macos"}:
        raise MatrixError("machine evidence platform is invalid")
    if not args.evidence_bundle_index_sha256:
        raise MatrixError("machine evidence requires its private evidence-bundle index hash")
    repo = pathlib.Path(__file__).resolve().parent.parent
    input_binding = release_input_binding(repo, platform, args.release_input_index)
    build_binding = build_receipt_binding(
        repo, platform, args.release_input_index, args.build_receipt, artifact
    )
    binding: dict[str, str | int] = {
        "release_input_index_sha256": input_binding.index_sha256,
        "platform_manifest_sha256": input_binding.platform_manifest_sha256,
        "artifact_input_fingerprint_sha256": input_binding.artifact_input_fingerprint_sha256,
        "build_receipt_sha256": build_binding.sha256,
    }
    binding["producer_contract_sha256"] = producer_contract_hash(
        repo,
        LINUX_PUBLIC_PRODUCER if platform == "linux" else APPLE_PUBLIC_PRODUCER,
    )
    native = compile_evidence(
        machine,
        machine_path.parent,
        artifact,
        map_screenshot,
        binding,
        args.evidence_bundle_index_sha256,
    )
    atomic_json(pathlib.Path(args.output).expanduser().resolve(), native)
    print("LINUX/APPLE RELEASE MATRIX EVIDENCE: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MatrixError as error:
        print(f"LINUX/APPLE RELEASE MATRIX EVIDENCE: FAIL: {error}", file=os.sys.stderr)
        raise SystemExit(1)
