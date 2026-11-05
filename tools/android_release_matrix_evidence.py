#!/usr/bin/env python3
"""Compile strict Android physical-test machine evidence into native schema v2.

This compiler never drives a live device or changes route controls. The live
PowerShell harness writes the machine facts and receipts; this module verifies
their hashes, exact route coverage, transactional rollback, split-browser
egress, leak checks, and map binding before producing the only Android native
transcript accepted by the public-release wrapper.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import uuid
from typing import Any

from public_release_live_smoke_common import (
    build_receipt_binding,
    producer_contract_hash,
    release_input_binding,
)


MACHINE_CONTRACT = "winsvpn-android-release-machine-evidence-v2"
INDEX_CONTRACT = "winsvpn-android-evidence-bundle-index-v1"
NATIVE_CONTRACT = "winsvpn-native-live-smoke-v2"
EXPECTED_SIGNER_SHA256 = (
    "4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee"
)
SHA256_LENGTH = 64
MIN_TUN_BYTES = 96
ANDROID_PUBLIC_PRODUCER = "tools/android_public_release_live_smoke.ps1"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
ZERO_SHA256 = "0" * SHA256_LENGTH
MAX_INDEX_AGE = dt.timedelta(hours=72)
MAX_RECEIPT_SKEW = dt.timedelta(hours=12)
EXPECTED_APPLICATION_ID = "org.winsvpn.app"
OWNER_BLOCKED_ABSENT_PACKAGES = (
    "OWNER-BLOCKED: produced Android AAB/APK bytes are absent"
)
OWNER_BLOCKED_MAPPING = (
    "OWNER-BLOCKED: private R8 mapping custody is absent"
)
OWNER_BLOCKED_LISTING = "OWNER-BLOCKED: ABSENT"
PRODUCED_ARTIFACT_CONTRACT = "winsvpn-android-produced-artifact-receipt-v1"
RUNTIME_CONTRACT = "winsvpn-android-form-factor-runtime-receipt-v1"
WEAR_RUNTIME_CONTRACT = "winsvpn-android-wear-runtime-receipt-v1"
WINN_PRIMARY_TRANSPORT = "winn_v3"
WINN_FALLBACK_TRANSPORTS = ["winn_v1_awg", "winn_v1_xray"]
FORM_FACTORS = ("phone", "tv", "wear")
FORM_FACTOR_CANDIDATES = {
    "phone": "android-phone-tablet",
    "tv": "android-tv",
    "wear": "wear-os",
}
CANONICAL_PACKAGE_PATHS = {
    ("phone", "apk"): "build/app/outputs/flutter-apk/app-release.apk",
    ("phone", "aab"): "build/app/outputs/bundle/release/app-release.aab",
    ("tv", "apk"): "build/app/outputs/flutter-apk/app-tv-release.apk",
    ("tv", "aab"): "build/app/outputs/bundle/tvRelease/app-tv-release.aab",
    ("wear", "aab"): "wear_os/app/build/outputs/bundle/release/app-release.aab",
}
PHONE_CANDIDATE_ALIASES = {
    "apk": "build/app/outputs/flutter-apk/app-phone-release.apk",
    "aab": "build/app/outputs/bundle/phoneRelease/app-phone-release.aab",
}
SCALAR_PACKAGE_FIELDS = {
    ("phone", "aab"): ("phone_aab_sha256", "phone_aab_size_bytes"),
    ("tv", "apk"): ("tv_apk_sha256", "tv_apk_size_bytes"),
    ("tv", "aab"): ("tv_aab_sha256", "tv_aab_size_bytes"),
    ("wear", "aab"): ("wear_aab_sha256", "wear_aab_size_bytes"),
}
MAPPING_ROLES = (
    "android-apk",
    "android-aab",
    "android-tv-apk",
    "android-tv-aab",
    "wear-os",
)
PUBLIC_MAPPING_NAMES = {
    "mapping.txt",
    "proguard-mapping.txt",
    "proguard.map",
}
HELPER_PATHS = {
    "collector": "tools/android_final_evidence_collector.py",
    "driver": "tools/android_release_ui_driver.py",
    "remote_control": "tools/android_remote_route_control.py",
    "remote_guard": "tools/android_remote_route_guard.sh",
}
_INDEXED_FILE_BYTES: dict[pathlib.Path, bytes] = {}
_INDEXED_FILE_JSON: dict[pathlib.Path, Any] = {}


class EvidenceError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    cached = _INDEXED_FILE_BYTES.get(path.resolve())
    if cached is not None:
        return hashlib.sha256(cached).hexdigest()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def json_from_indexed_file(path: pathlib.Path, label: str) -> Any:
    resolved = path.resolve()
    if resolved in _INDEXED_FILE_JSON:
        return _INDEXED_FILE_JSON[resolved]
    raw = _INDEXED_FILE_BYTES.get(resolved)
    try:
        value = json.loads(
            raw.decode("utf-8-sig") if raw is not None else path.read_text(encoding="utf-8-sig")
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} must be valid UTF-8 JSON.") from exc
    if raw is not None:
        _INDEXED_FILE_JSON[resolved] = value
    return value


def require_sha256(value: Any, label: str) -> str:
    text = str(value)
    if len(text) != SHA256_LENGTH or any(ch not in "0123456789abcdef" for ch in text):
        raise EvidenceError(f"{label} must be a lowercase SHA-256 digest.")
    return text


def require_observed_sha256(value: Any, label: str) -> str:
    digest = require_sha256(value, label)
    if digest in {EMPTY_SHA256, ZERO_SHA256}:
        raise EvidenceError(f"{label} must not be an empty or zero sentinel digest.")
    return digest


def require_exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise EvidenceError(f"{label} fields are invalid: {actual}")
    return value


def require_true(value: Any, label: str) -> None:
    if value is not True:
        raise EvidenceError(f"{label} must be true.")


def require_false(value: Any, label: str) -> None:
    if value is not False:
        raise EvidenceError(f"{label} must be false.")


def require_positive_int(value: Any, label: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceError(f"{label} must be an integer >= {minimum}.")
    return value


def require_fresh(captured: dt.datetime, label: str) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    if captured < now - MAX_INDEX_AGE or captured > now + dt.timedelta(minutes=5):
        raise EvidenceError(f"{label} is stale or from the future.")


def require_receipt_skew(captured: dt.datetime, machine_captured: dt.datetime, label: str) -> None:
    require_fresh(captured, label)
    if captured > machine_captured + dt.timedelta(minutes=5):
        raise EvidenceError(f"{label} is newer than the machine evidence run.")
    if captured < machine_captured - MAX_RECEIPT_SKEW:
        raise EvidenceError(f"{label} is mixed from an older evidence run.")


def sha256_repo_file(path: pathlib.Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(OWNER_BLOCKED_ABSENT_PACKAGES)
    info = path.stat()
    if info.st_nlink != 1 or info.st_size <= 0:
        raise EvidenceError(OWNER_BLOCKED_ABSENT_PACKAGES)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def produced_package_bytes(
    repo: pathlib.Path,
    relative: str,
    expected_sha256: str,
    expected_size: int,
    label: str,
) -> None:
    raw = pathlib.Path(relative)
    if raw.is_absolute() or ".." in raw.parts:
        raise EvidenceError(f"{label} path must be a canonical repository-relative produced package.")
    path = repo / raw
    actual = sha256_repo_file(path, label)
    if actual != expected_sha256:
        raise EvidenceError(f"{label} hash does not match the produced package bytes.")
    if path.stat().st_size != expected_size:
        raise EvidenceError(f"{label} size does not match the produced package bytes.")


def parse_utc(value: Any) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("captured_at_utc must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise EvidenceError("captured_at_utc must include a timezone.")
    return parsed.astimezone(dt.timezone.utc)


def evidence_file(
    evidence_root: pathlib.Path,
    relative_value: Any,
    expected_sha256: Any,
    label: str,
) -> pathlib.Path:
    raw = pathlib.Path(str(relative_value))
    if raw.is_absolute() or ".." in raw.parts:
        raise EvidenceError(f"{label} path must be relative to the machine-evidence directory.")
    root = evidence_root.resolve()
    candidate = root / raw
    if candidate.is_symlink():
        raise EvidenceError(f"{label} must not be a symlink.")
    path = candidate.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise EvidenceError(f"{label} escaped the machine-evidence directory.") from exc
    if not path.is_file() or path.is_symlink():
        raise EvidenceError(f"{label} must be a regular evidence file.")
    expected = require_sha256(expected_sha256, f"{label} SHA-256")
    actual = sha256_file(path)
    if actual != expected:
        raise EvidenceError(f"{label} hash mismatch: expected={expected} actual={actual}")
    return path


def evidence_json(
    evidence_root: pathlib.Path,
    relative_value: Any,
    expected_sha256: Any,
    fields: set[str],
    contract: str,
    label: str,
) -> dict[str, Any]:
    path = evidence_file(evidence_root, relative_value, expected_sha256, label)
    raw = json_from_indexed_file(path, label)
    value = require_exact(raw, fields, label)
    if value["schema_version"] != 1 or value["contract"] != contract:
        raise EvidenceError(f"{label} contract/version is invalid.")
    require_true(value["secret_material_redacted"], f"{label} secret redaction")
    parse_utc(value["captured_at_utc"])
    return value


def load_evidence_bundle(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    artifact: pathlib.Path,
    binding: dict[str, Any],
    *,
    expected_index_sha256: str,
    expected_run_id: str,
) -> tuple[dict[str, Any], pathlib.Path, str, pathlib.Path]:
    global _INDEXED_FILE_BYTES, _INDEXED_FILE_JSON
    _INDEXED_FILE_BYTES = {}
    _INDEXED_FILE_JSON = {}
    index_path = index_path.absolute()
    if index_path.is_symlink():
        raise EvidenceError("Android evidence index must not be a symlink.")
    cursor = index_path.parent
    repo_absolute = repo.absolute()
    while True:
        if cursor.is_symlink():
            raise EvidenceError("Android evidence index path must not traverse a symlink.")
        if cursor == repo_absolute or cursor == cursor.parent:
            break
        cursor = cursor.parent
    index_path = index_path.resolve()
    if (
        index_path.name != "EVIDENCE_INDEX.json"
        or not index_path.is_file()
        or index_path.stat().st_nlink != 1
    ):
        raise EvidenceError("--evidence-index must name a regular EVIDENCE_INDEX.json file.")
    try:
        index_path.relative_to((repo / ".artifacts").resolve())
    except ValueError as exc:
        raise EvidenceError("Android evidence index must stay under repository .artifacts.") from exc
    index_bytes = index_path.read_bytes()
    index_sha256 = hashlib.sha256(index_bytes).hexdigest()
    if require_sha256(expected_index_sha256, "Expected evidence index") != index_sha256:
        raise EvidenceError("Android evidence index changed after physical collection.")
    try:
        raw_index = json.loads(index_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("Android evidence index must be canonical UTF-8 JSON.") from exc
    index = require_exact(
        raw_index,
        {
            "schema_version", "contract", "run_id", "created_at_utc",
            "machine_evidence_path", "map_screenshot_path", "files", "binding",
            "helpers", "secret_material_redacted",
        },
        "Android evidence index",
    )
    if index["schema_version"] != 1 or index["contract"] != INDEX_CONTRACT:
        raise EvidenceError("Android evidence index contract/version is invalid.")
    require_true(index["secret_material_redacted"], "Android evidence index redaction")
    try:
        run_id = uuid.UUID(str(index["run_id"]))
        expected_uuid = uuid.UUID(str(expected_run_id))
    except ValueError as exc:
        raise EvidenceError("Android evidence index run ID is invalid.") from exc
    if run_id.int == 0 or run_id != expected_uuid:
        raise EvidenceError("Android evidence index run ID changed after physical collection.")
    if index_path.parent.name != str(run_id):
        raise EvidenceError("Android evidence bundle directory does not match its run ID.")
    created = parse_utc(index["created_at_utc"])
    now = dt.datetime.now(dt.timezone.utc)
    if created < now - MAX_INDEX_AGE or created > now + dt.timedelta(minutes=5):
        raise EvidenceError("Android evidence index is stale or from the future.")

    bundle_binding = require_exact(
        index["binding"],
        {"artifact", "release_inputs", "build_receipt", "producer"},
        "Android evidence index binding",
    )
    artifact_binding = require_exact(
        bundle_binding["artifact"], {"path", "sha256", "size_bytes"}, "Bundle artifact binding"
    )
    try:
        expected_artifact_path = artifact.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError as exc:
        raise EvidenceError("Android staged APK must stay inside the repository.") from exc
    if artifact_binding["path"] != expected_artifact_path:
        raise EvidenceError("Android evidence bundle artifact path is inconsistent.")
    if require_sha256(artifact_binding["sha256"], "Bundle artifact") != sha256_file(artifact):
        raise EvidenceError("Android evidence bundle is bound to another APK.")
    if artifact_binding["size_bytes"] != artifact.stat().st_size:
        raise EvidenceError("Android evidence bundle APK size is inconsistent.")
    release_binding = require_exact(
        bundle_binding["release_inputs"],
        {
            "path", "sha256", "platform_manifest_sha256",
            "artifact_input_fingerprint_sha256", "shared_revision",
        },
        "Bundle release-input binding",
    )
    if release_binding["path"] != binding["release_input_index_path"]:
        raise EvidenceError("Android evidence bundle release-input path is inconsistent.")
    for index_field, binding_field in (
        ("sha256", "release_input_index_sha256"),
        ("platform_manifest_sha256", "platform_manifest_sha256"),
        ("artifact_input_fingerprint_sha256", "artifact_input_fingerprint_sha256"),
    ):
        if require_sha256(release_binding[index_field], f"Bundle {binding_field}") != binding[binding_field]:
            raise EvidenceError(f"Android evidence bundle does not match {binding_field}.")
    if release_binding["shared_revision"] != binding["shared_revision"]:
        raise EvidenceError("Android evidence bundle does not match the shared revision.")
    build_binding = require_exact(
        bundle_binding["build_receipt"], {"path", "sha256"}, "Bundle build-receipt binding"
    )
    if build_binding["path"] != binding["build_receipt_path"]:
        raise EvidenceError("Android evidence bundle build-receipt path is inconsistent.")
    if require_sha256(build_binding["sha256"], "Bundle build receipt") != binding["build_receipt_sha256"]:
        raise EvidenceError("Android evidence bundle does not match build_receipt_sha256.")
    producer_binding = require_exact(
        bundle_binding["producer"], {"path", "closure_sha256"}, "Bundle producer binding"
    )
    if producer_binding["path"] != ANDROID_PUBLIC_PRODUCER:
        raise EvidenceError("Android evidence bundle producer path is inconsistent.")
    if (
        require_sha256(producer_binding["closure_sha256"], "Bundle producer closure")
        != binding["producer_contract_sha256"]
    ):
        raise EvidenceError("Android evidence bundle does not match producer_contract_sha256.")
    helpers = require_exact(index["helpers"], set(HELPER_PATHS), "Android evidence helper binding")
    for name, relative in HELPER_PATHS.items():
        helper = require_exact(helpers[name], {"path", "sha256"}, f"Android {name} helper")
        if helper["path"] != relative:
            raise EvidenceError(f"Android {name} helper path is invalid.")
        current = sha256_file(repo / pathlib.PurePosixPath(relative))
        if require_sha256(helper["sha256"], f"Android {name} helper") != current:
            raise EvidenceError(f"Android {name} helper changed after physical collection.")

    files = index["files"]
    if not isinstance(files, list) or not files or len(files) > 128:
        raise EvidenceError("Android evidence index file list is invalid.")
    root = index_path.parent
    indexed_names: list[str] = []
    contracts: dict[str, str] = {}
    for item in files:
        entry = require_exact(item, {"path", "sha256", "size_bytes", "contract"}, "Android indexed file")
        raw_path = pathlib.Path(str(entry["path"]))
        if raw_path.is_absolute() or len(raw_path.parts) != 1 or raw_path.name.startswith(".") or raw_path.suffix.lower() == ".tmp":
            raise EvidenceError("Android indexed file path is unsafe.")
        if raw_path.name in indexed_names:
            raise EvidenceError("Android evidence index contains a duplicate path.")
        path = root / raw_path.name
        if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
            raise EvidenceError(f"Android indexed file is unsafe: {raw_path.name}")
        content = path.read_bytes()
        if entry["size_bytes"] != len(content):
            raise EvidenceError(f"Android indexed file size mismatch: {raw_path.name}")
        if require_sha256(entry["sha256"], f"{raw_path.name} index") != hashlib.sha256(content).hexdigest():
            raise EvidenceError(f"Android indexed file hash mismatch: {raw_path.name}")
        if not isinstance(entry["contract"], str) or not entry["contract"].startswith("winsvpn-"):
            raise EvidenceError(f"Android indexed file contract is invalid: {raw_path.name}")
        indexed_names.append(raw_path.name)
        contracts[raw_path.name] = entry["contract"]
        _INDEXED_FILE_BYTES[path.resolve()] = content
        if raw_path.suffix.lower() == ".json":
            value = json_from_indexed_file(path, f"Android indexed file {raw_path.name}")
            if (
                not isinstance(value, dict)
                or value.get("contract") != entry["contract"]
                or value.get("secret_material_redacted") is not True
            ):
                raise EvidenceError(f"Android indexed JSON contract/redaction mismatch: {raw_path.name}")
    if indexed_names != sorted(indexed_names):
        raise EvidenceError("Android evidence index file list must be sorted.")
    actual: set[str] = set()
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file():
            raise EvidenceError("Android evidence bundle contains an unsafe extra entry.")
        actual.add(path.name)
    if actual != set(indexed_names) | {index_path.name}:
        raise EvidenceError("Android evidence bundle contains unindexed, missing, or temporary files.")

    machine_name = str(index["machine_evidence_path"])
    map_name = str(index["map_screenshot_path"])
    if contracts.get(machine_name) != MACHINE_CONTRACT:
        raise EvidenceError("Android evidence index does not bind the machine-evidence contract.")
    if contracts.get(map_name) != "winsvpn-android-map-screenshot-v1":
        raise EvidenceError("Android evidence index does not bind the map screenshot contract.")
    machine_path = root / machine_name
    machine = json_from_indexed_file(machine_path, "Android machine evidence")
    if not isinstance(machine, dict) or machine.get("run_id") != str(run_id):
        raise EvidenceError("Android machine evidence run ID contradicts its bundle index.")
    return machine, root, index_sha256, root / map_name


def validate_forcing(root: pathlib.Path, value: Any, lane: dict[str, Any]) -> None:
    label = str(lane["lane_id"])
    forcing = require_exact(
        value,
        {
            "required",
            "blocked_udp_port",
            "apply_passed",
            "restore_passed",
            "before_state_sha256",
            "after_state_sha256",
            "apply_receipt_path",
            "apply_receipt_sha256",
            "restore_receipt_path",
            "restore_receipt_sha256",
        },
        f"{label} forcing",
    )
    if not isinstance(forcing["required"], bool):
        raise EvidenceError(f"{label} forcing.required must be boolean.")
    blocked_udp_port = forcing["blocked_udp_port"]
    if (
        isinstance(blocked_udp_port, bool)
        or not isinstance(blocked_udp_port, int)
        or blocked_udp_port != lane["direct_first_hop_port"]
    ):
        raise EvidenceError(f"{label} forcing is not bound to its observed direct first-hop UDP port.")
    before = require_sha256(forcing["before_state_sha256"], f"{label} before state")
    after = require_sha256(forcing["after_state_sha256"], f"{label} after state")
    if before != after:
        raise EvidenceError(f"{label} did not restore the exact pre-test control state.")
    require_true(forcing["restore_passed"], f"{label} forcing restore")
    restore_receipt = evidence_json(
        root,
        forcing["restore_receipt_path"],
        forcing["restore_receipt_sha256"],
        {
            "schema_version", "contract", "phase", "operation_id", "lane_id",
            "blocked_udp_port",
            "before_state_sha256", "after_state_sha256", "passed",
            "captured_at_utc", "secret_material_redacted",
        },
        "winsvpn-android-forcing-receipt-v1",
        f"{label} restore receipt",
    )
    if (
        restore_receipt["phase"] != "restore"
        or restore_receipt["lane_id"] != label
        or restore_receipt["blocked_udp_port"] != blocked_udp_port
        or restore_receipt["before_state_sha256"] != before
        or restore_receipt["after_state_sha256"] != after
    ):
        raise EvidenceError(f"{label} restore receipt contradicts the forcing transaction.")
    try:
        operation_id = uuid.UUID(str(restore_receipt["operation_id"]))
    except ValueError as exc:
        raise EvidenceError(f"{label} forcing operation_id must be a UUID.") from exc
    if operation_id.int == 0:
        raise EvidenceError(f"{label} forcing operation_id must not be zero.")
    require_true(restore_receipt["passed"], f"{label} restore receipt")
    if forcing["required"]:
        require_true(forcing["apply_passed"], f"{label} forcing apply")
        apply_receipt = evidence_json(
            root,
            forcing["apply_receipt_path"],
            forcing["apply_receipt_sha256"],
            {
                "schema_version", "contract", "phase", "operation_id", "lane_id",
                "blocked_udp_port",
                "before_state_sha256", "applied_state_sha256", "passed",
                "captured_at_utc", "secret_material_redacted",
            },
            "winsvpn-android-forcing-receipt-v1",
            f"{label} apply receipt",
        )
        if (
            apply_receipt["phase"] != "apply"
            or apply_receipt["lane_id"] != label
            or apply_receipt["blocked_udp_port"] != blocked_udp_port
            or apply_receipt["before_state_sha256"] != before
            or apply_receipt["operation_id"] != restore_receipt["operation_id"]
        ):
            raise EvidenceError(f"{label} apply receipt contradicts the forcing transaction.")
        require_sha256(apply_receipt["applied_state_sha256"], f"{label} applied state")
        require_true(apply_receipt["passed"], f"{label} apply receipt")
    elif forcing["apply_passed"] is not False:
        raise EvidenceError(f"{label} non-forced lane must record apply_passed=false.")


def validate_residue(value: Any, label: str) -> None:
    residue = require_exact(
        value,
        {"tun_absent", "vpn_service_absent", "xray_absent", "passed"},
        f"{label} residue",
    )
    for field in residue:
        require_true(residue[field], f"{label} residue {field}")


def route_manifest_sha256(routes: list[dict[str, Any]]) -> str:
    canonical = "".join(
        f"tcp|{route['port']}|{route['security']}\n"
        for route in sorted(routes, key=lambda item: (item["port"], item["security"]))
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_lane(
    root: pathlib.Path,
    value: Any,
    *,
    direct_awg_port: int,
    double_vpn_direct_port: int,
) -> dict[str, Any]:
    lane = require_exact(
        value,
        {
            "lane_id",
            "kind",
            "protocol",
            "port",
            "direct_first_hop_port",
            "security",
            "double_vpn",
            "connected_passed",
            "tunnel_validated",
            "tun_rx_delta",
            "tun_tx_delta",
            "protected_egress_sha256",
            "double_vpn_core_id_sha256",
            "double_vpn_exit_slug_sha256",
            "route_inventory_sha256",
            "mode_xray_manifest_sha256",
            "remote_observation_path",
            "remote_observation_sha256",
            "xray_process_observed",
            "route_receipt_path",
            "route_receipt_sha256",
            "forcing",
            "residue",
        },
        "Android route lane",
    )
    lane_id = str(lane["lane_id"])
    if not lane_id or len(lane_id) > 80:
        raise EvidenceError("Android route lane_id is invalid.")
    kind = str(lane["kind"])
    allowed_kinds = {"direct_awg", "xray", "double_vpn_direct", "double_vpn_xray"}
    if kind not in allowed_kinds:
        raise EvidenceError(f"Unsupported Android route lane kind: {kind}")
    is_xray = kind in {"xray", "double_vpn_xray"}
    is_double = kind in {"double_vpn_direct", "double_vpn_xray"}
    if lane["double_vpn"] is not is_double:
        raise EvidenceError(f"{lane_id} has inconsistent Double VPN state.")
    expected_protocol = "tcp" if is_xray else "udp"
    expected_direct_port = double_vpn_direct_port if is_double else direct_awg_port
    if lane["protocol"] != expected_protocol:
        raise EvidenceError(f"{lane_id} protocol does not match its lane kind.")
    if isinstance(lane["port"], bool) or not isinstance(lane["port"], int):
        raise EvidenceError(f"{lane_id} port must be an integer.")
    if not 1 <= lane["port"] <= 65535:
        raise EvidenceError(f"{lane_id} route port is invalid.")
    if (
        isinstance(lane["direct_first_hop_port"], bool)
        or not isinstance(lane["direct_first_hop_port"], int)
        or lane["direct_first_hop_port"] != expected_direct_port
    ):
        raise EvidenceError(f"{lane_id} is not bound to the observed mode-specific direct first-hop port.")
    if not is_xray and lane["port"] != expected_direct_port:
        raise EvidenceError(f"{lane_id} direct route does not match its observed first-hop UDP port.")
    if lane["security"] not in ({"none", "tls"} if is_xray else {"none"}):
        raise EvidenceError(f"{lane_id} security value is invalid.")
    if lane["xray_process_observed"] is not is_xray:
        raise EvidenceError(f"{lane_id} Xray process observation contradicts its lane kind.")
    require_true(lane["connected_passed"], f"{lane_id} connected")
    require_true(lane["tunnel_validated"], f"{lane_id} tunnel validation")
    for counter in ("tun_rx_delta", "tun_tx_delta"):
        if isinstance(lane[counter], bool) or not isinstance(lane[counter], int) or lane[counter] < MIN_TUN_BYTES:
            raise EvidenceError(f"{lane_id} {counter} lacks bidirectional traffic proof.")
    require_observed_sha256(lane["protected_egress_sha256"], f"{lane_id} protected egress")
    core_digest = require_sha256(
        lane["double_vpn_core_id_sha256"], f"{lane_id} Double VPN Core identity"
    )
    exit_digest = require_sha256(
        lane["double_vpn_exit_slug_sha256"], f"{lane_id} Double VPN exit identity"
    )
    if is_double:
        if core_digest in {EMPTY_SHA256, ZERO_SHA256} or exit_digest in {EMPTY_SHA256, ZERO_SHA256}:
            raise EvidenceError(f"{lane_id} lacks real Double VPN Core/exit identity.")
    elif core_digest != EMPTY_SHA256 or exit_digest != EMPTY_SHA256:
        raise EvidenceError(f"{lane_id} unexpectedly reports Double VPN identity.")
    inventory_digest = require_observed_sha256(
        lane["route_inventory_sha256"], f"{lane_id} route inventory"
    )
    manifest_digest = require_observed_sha256(
        lane["mode_xray_manifest_sha256"], f"{lane_id} mode Xray manifest"
    )
    remote_observation = evidence_json(
        root,
        lane["remote_observation_path"],
        lane["remote_observation_sha256"],
        {
            "schema_version", "contract", "mode", "lane_kind",
            "selected_protocol", "selected_port", "selected_security",
            "direct_first_hop_port", "selected_packets", "selected_bytes",
            "direct_packets", "direct_bytes", "direct_block_packets",
            "route_inventory_sha256", "mode_xray_manifest_sha256", "passed",
            "captured_at_utc", "secret_material_redacted",
        },
        "winsvpn-android-remote-route-observation-v1",
        f"{lane_id} remote route observation",
    )
    if (
        remote_observation["mode"] != ("double_vpn" if is_double else "node")
        or remote_observation["lane_kind"] != ("xray" if is_xray else "direct")
        or remote_observation["selected_protocol"] != lane["protocol"]
        or remote_observation["selected_port"] != lane["port"]
        or remote_observation["selected_security"] != lane["security"]
        or remote_observation["direct_first_hop_port"] != lane["direct_first_hop_port"]
        or remote_observation["route_inventory_sha256"] != inventory_digest
        or remote_observation["mode_xray_manifest_sha256"] != manifest_digest
    ):
        raise EvidenceError(f"{lane_id} remote route observation contradicts the lane.")
    for counter in ("selected_packets", "selected_bytes"):
        if isinstance(remote_observation[counter], bool) or not isinstance(remote_observation[counter], int) or remote_observation[counter] <= 0:
            raise EvidenceError(f"{lane_id} remote selected-route counter is empty.")
    if is_xray:
        if isinstance(remote_observation["direct_block_packets"], bool) or remote_observation["direct_block_packets"] <= 0:
            raise EvidenceError(f"{lane_id} did not observe the blocked direct fallback attempt.")
    elif remote_observation["direct_block_packets"] != 0:
        raise EvidenceError(f"{lane_id} unexpectedly blocked its direct first hop.")
    require_true(remote_observation["passed"], f"{lane_id} remote route observation")
    route_receipt = evidence_json(
        root,
        lane["route_receipt_path"],
        lane["route_receipt_sha256"],
        {
            "schema_version", "contract", "lane_id", "protocol", "port",
            "direct_first_hop_port", "security", "double_vpn", "connected_observed", "captured_at_utc",
            "double_vpn_core_id_sha256", "double_vpn_exit_slug_sha256",
            "route_inventory_sha256", "mode_xray_manifest_sha256",
            "remote_observation_sha256",
            "secret_material_redacted",
        },
        "winsvpn-android-route-receipt-v1",
        f"{lane_id} route receipt",
    )
    if (
        route_receipt["lane_id"] != lane_id
        or route_receipt["protocol"] != lane["protocol"]
        or route_receipt["port"] != lane["port"]
        or route_receipt["direct_first_hop_port"] != lane["direct_first_hop_port"]
        or route_receipt["security"] != lane["security"]
        or route_receipt["double_vpn"] is not lane["double_vpn"]
        or route_receipt["double_vpn_core_id_sha256"] != core_digest
        or route_receipt["double_vpn_exit_slug_sha256"] != exit_digest
        or route_receipt["route_inventory_sha256"] != inventory_digest
        or route_receipt["mode_xray_manifest_sha256"] != manifest_digest
        or route_receipt["remote_observation_sha256"] != lane["remote_observation_sha256"]
    ):
        raise EvidenceError(f"{lane_id} route receipt contradicts the lane.")
    require_true(route_receipt["connected_observed"], f"{lane_id} route receipt")
    validate_forcing(root, lane["forcing"], lane)
    if is_xray and lane["forcing"]["required"] is not True:
        raise EvidenceError(f"{lane_id} must use a fail-closed forced-route transaction.")
    validate_residue(lane["residue"], lane_id)
    return lane


def validate_machine_binding(machine: dict[str, Any], binding: dict[str, str]) -> None:
    for field in (
        "release_input_index_sha256",
        "platform_manifest_sha256",
        "artifact_input_fingerprint_sha256",
        "build_receipt_sha256",
        "producer_contract_sha256",
    ):
        if require_sha256(machine[field], field) != binding[field]:
            raise EvidenceError(f"Android machine evidence does not match {field}.")


def validate_listing_inventory(value: Any) -> None:
    listing = require_exact(value, set(FORM_FACTORS), "Android listing inventory")
    for form in FORM_FACTORS:
        if listing[form] != OWNER_BLOCKED_LISTING:
            raise EvidenceError(
                f"{form} listing/screenshot inventory must remain {OWNER_BLOCKED_LISTING}."
            )


def validate_mapping_custody(
    repo: pathlib.Path,
    root: pathlib.Path,
    value: Any,
    *,
    owner_blocked: Any,
    app_version: str,
    phone_version_code: int,
    wear_version_code: int,
) -> None:
    require_true(owner_blocked, "Android mapping_owner_blocked")
    for path in root.iterdir():
        name = path.name.lower()
        if name in PUBLIC_MAPPING_NAMES or name.endswith(".map"):
            raise EvidenceError("Android R8 mapping files must remain owner-blocked private custody.")
    mapping = require_exact(value, set(MAPPING_ROLES), "Android private symbol mapping")
    seen: set[str] = set()
    for role in MAPPING_ROLES:
        digest = require_observed_sha256(mapping[role], f"{role} mapping")
        if digest in seen:
            raise EvidenceError("Android private mapping hashes are duplicated across form factors.")
        seen.add(digest)
        stamp = (
            f"{app_version}+{wear_version_code}"
            if role == "wear-os"
            else f"{app_version}+{phone_version_code}"
        )
        role_root = repo / ".artifacts" / "private-release-symbols" / role / stamp
        if role_root.is_symlink() or not role_root.is_dir():
            raise EvidenceError(OWNER_BLOCKED_MAPPING)
        matched = False
        for path in sorted(role_root.rglob("*")):
            if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
                continue
            if path.name in PUBLIC_MAPPING_NAMES:
                if sha256_repo_file(path, f"{role} mapping") != digest:
                    raise EvidenceError(f"{role} mapping hash does not match private custody.")
                matched = True
        if not matched:
            raise EvidenceError(OWNER_BLOCKED_MAPPING)


def validate_produced_package(
    root: pathlib.Path,
    repo: pathlib.Path,
    value: Any,
    *,
    form: str,
    role: str,
    candidate_id: str,
    version_name: str,
    version_code: int,
    machine_captured: dt.datetime,
    used_receipts: set[str],
    used_hashes: dict[str, tuple[str, str]],
) -> tuple[str, int]:
    package = require_exact(
        value,
        {"role", "path", "sha256", "size_bytes", "receipt_path", "receipt_sha256"},
        f"{form} {role} produced package",
    )
    if package["role"] != role:
        raise EvidenceError(f"{form} {role} produced package role is mixed.")
    expected_path = CANONICAL_PACKAGE_PATHS[(form, role)]
    if package["path"] != expected_path:
        raise EvidenceError(f"{form} {role} produced package path is not the exact candidate.")
    digest = require_observed_sha256(package["sha256"], f"{form} {role} produced package")
    size = require_positive_int(package["size_bytes"], f"{form} {role} produced package size")
    owner = used_hashes.get(digest)
    if owner is not None and owner != (form, role):
        raise EvidenceError("Android produced-artifact hashes are duplicated or mixed across form factors.")
    used_hashes[digest] = (form, role)
    receipt_name = str(package["receipt_path"])
    if receipt_name in used_receipts:
        raise EvidenceError("Android produced-artifact receipts are duplicated across form factors.")
    used_receipts.add(receipt_name)
    receipt = evidence_json(
        root,
        package["receipt_path"],
        package["receipt_sha256"],
        {
            "schema_version", "contract", "form_factor", "role", "candidate_id",
            "path", "sha256", "size_bytes", "version_name", "version_code",
            "captured_at_utc", "secret_material_redacted",
        },
        PRODUCED_ARTIFACT_CONTRACT,
        f"{form} {role} produced-artifact receipt",
    )
    require_receipt_skew(
        parse_utc(receipt["captured_at_utc"]),
        machine_captured,
        f"{form} {role} produced-artifact receipt",
    )
    if (
        receipt["form_factor"] != form
        or receipt["role"] != role
        or receipt["candidate_id"] != candidate_id
        or receipt["path"] != expected_path
        or receipt["sha256"] != digest
        or receipt["size_bytes"] != size
        or receipt["version_name"] != version_name
        or receipt["version_code"] != version_code
    ):
        raise EvidenceError(f"{form} {role} produced-artifact receipt contradicts the matrix.")
    produced_package_bytes(repo, expected_path, digest, size, f"{form} {role} produced package")
    return digest, size


def validate_vpn_runtime(
    root: pathlib.Path,
    value: Any,
    *,
    form: str,
    candidate_id: str,
    version_name: str,
    version_code: int,
    artifact_sha256: str,
    machine_captured: dt.datetime,
    used_receipts: set[str],
) -> None:
    runtime = require_exact(
        value,
        {
            "kind", "artifact_sha256", "source_only", "receipt_path",
            "receipt_sha256", "passed",
        },
        f"{form} runtime evidence",
    )
    if runtime["kind"] != "live_vpn":
        raise EvidenceError(f"{form} runtime evidence kind must be live_vpn.")
    require_false(runtime["source_only"], f"{form} runtime source_only")
    require_true(runtime["passed"], f"{form} runtime")
    if require_observed_sha256(runtime["artifact_sha256"], f"{form} runtime artifact") != artifact_sha256:
        raise EvidenceError(f"{form} runtime evidence is not bound to its produced candidate.")
    receipt_name = str(runtime["receipt_path"])
    if receipt_name in used_receipts:
        raise EvidenceError("Android runtime receipts are duplicated or mixed across form factors.")
    used_receipts.add(receipt_name)
    receipt = evidence_json(
        root,
        runtime["receipt_path"],
        runtime["receipt_sha256"],
        {
            "schema_version", "contract", "form_factor", "kind", "candidate_id",
            "artifact_sha256", "version_name", "version_code",
            "primary_transport", "fallback_transports", "winn_v3_session_observed",
            "source_only", "passed", "captured_at_utc", "secret_material_redacted",
        },
        RUNTIME_CONTRACT,
        f"{form} runtime receipt",
    )
    require_receipt_skew(
        parse_utc(receipt["captured_at_utc"]),
        machine_captured,
        f"{form} runtime receipt",
    )
    if (
        receipt["form_factor"] != form
        or receipt["kind"] != "live_vpn"
        or receipt["candidate_id"] != candidate_id
        or receipt["artifact_sha256"] != artifact_sha256
        or receipt["version_name"] != version_name
        or receipt["version_code"] != version_code
        or receipt["primary_transport"] != WINN_PRIMARY_TRANSPORT
        or receipt["fallback_transports"] != WINN_FALLBACK_TRANSPORTS
    ):
        raise EvidenceError(f"{form} runtime receipt contradicts the exact candidate binding.")
    require_true(receipt["winn_v3_session_observed"], f"{form} Winn v3 session")
    require_false(receipt["source_only"], f"{form} runtime receipt source_only")
    require_true(receipt["passed"], f"{form} runtime receipt")


def validate_wear_runtime(
    root: pathlib.Path,
    value: Any,
    *,
    candidate_id: str,
    version_name: str,
    version_code: int,
    artifact_sha256: str,
    phone_apk_sha256: str,
    machine_captured: dt.datetime,
    used_receipts: set[str],
) -> None:
    runtime = require_exact(
        value,
        {
            "kind", "artifact_sha256", "source_only", "receipt_path",
            "receipt_sha256", "passed",
        },
        "wear runtime evidence",
    )
    if runtime["kind"] != "pairing_runtime":
        raise EvidenceError("Wear runtime evidence kind must be pairing_runtime, not VPN.")
    require_false(runtime["source_only"], "wear runtime source_only")
    require_true(runtime["passed"], "wear runtime")
    if require_observed_sha256(runtime["artifact_sha256"], "wear runtime artifact") != artifact_sha256:
        raise EvidenceError("Wear runtime evidence is not bound to the Wear AAB candidate.")
    receipt_name = str(runtime["receipt_path"])
    if receipt_name in used_receipts:
        raise EvidenceError("Android runtime receipts are duplicated or mixed across form factors.")
    used_receipts.add(receipt_name)
    receipt = evidence_json(
        root,
        runtime["receipt_path"],
        runtime["receipt_sha256"],
        {
            "schema_version", "contract", "form_factor", "kind", "candidate_id",
            "artifact_sha256", "version_name", "version_code",
            "companion_phone_artifact_sha256", "pairing_observed",
            "source_only", "passed", "captured_at_utc", "secret_material_redacted",
        },
        WEAR_RUNTIME_CONTRACT,
        "wear runtime receipt",
    )
    require_receipt_skew(
        parse_utc(receipt["captured_at_utc"]),
        machine_captured,
        "wear runtime receipt",
    )
    if (
        receipt["form_factor"] != "wear"
        or receipt["kind"] != "pairing_runtime"
        or receipt["candidate_id"] != candidate_id
        or receipt["artifact_sha256"] != artifact_sha256
        or receipt["version_name"] != version_name
        or receipt["version_code"] != version_code
        or receipt["companion_phone_artifact_sha256"] != phone_apk_sha256
    ):
        raise EvidenceError("Wear runtime receipt contradicts the exact candidate binding.")
    require_true(receipt["pairing_observed"], "wear pairing observation")
    require_false(receipt["source_only"], "wear runtime receipt source_only")
    require_true(receipt["passed"], "wear runtime receipt")


def validate_form_factor_matrix(
    machine: dict[str, Any],
    root: pathlib.Path,
    repo: pathlib.Path,
    artifact: pathlib.Path,
    artifact_hash: str,
    machine_captured: dt.datetime,
) -> None:
    if machine["application_id"] != EXPECTED_APPLICATION_ID:
        raise EvidenceError("Android application_id is not the exact release package.")
    matrix = require_exact(machine["form_factor_matrix"], set(FORM_FACTORS), "Android form-factor matrix")
    used_receipts: set[str] = set()
    used_hashes: dict[str, tuple[str, str]] = {}
    package_digests: dict[tuple[str, str], tuple[str, int]] = {}
    version_codes: dict[str, int] = {}
    for form in FORM_FACTORS:
        roles = ("apk", "aab") if form in {"phone", "tv"} else ("aab",)
        row = require_exact(
            matrix[form],
            {"form_factor", "candidate_id", "version_name", "version_code", "packages", "runtime"},
            f"{form} form-factor row",
        )
        if row["form_factor"] != form:
            raise EvidenceError(f"{form} form-factor row is mixed with another form factor.")
        if row["candidate_id"] != FORM_FACTOR_CANDIDATES[form]:
            raise EvidenceError(f"{form} candidate_id is not the exact release candidate.")
        if row["version_name"] != machine["app_version"]:
            raise EvidenceError(f"{form} version_name is not bound to the machine app_version.")
        version_code = require_positive_int(row["version_code"], f"{form} version_code")
        if form == "phone" and str(version_code) != machine["build_number"]:
            raise EvidenceError("phone version_code is not bound to the machine build_number.")
        version_codes[form] = version_code
        packages = require_exact(row["packages"], set(roles), f"{form} produced packages")
        for role in roles:
            digest, size = validate_produced_package(
                root,
                repo,
                packages[role],
                form=form,
                role=role,
                candidate_id=row["candidate_id"],
                version_name=row["version_name"],
                version_code=version_code,
                machine_captured=machine_captured,
                used_receipts=used_receipts,
                used_hashes=used_hashes,
            )
            package_digests[(form, role)] = (digest, size)
            scalar = SCALAR_PACKAGE_FIELDS.get((form, role))
            if scalar is not None:
                scalar_hash, scalar_size = scalar
                if require_sha256(machine[scalar_hash], scalar_hash) != digest:
                    raise EvidenceError(f"{scalar_hash} contradicts the {form} {role} candidate.")
                if machine[scalar_size] != size:
                    raise EvidenceError(f"{scalar_size} contradicts the {form} {role} candidate.")
    if len(set(version_codes.values())) != len(version_codes):
        raise EvidenceError("Android form-factor version_codes are mixed or duplicated.")
    phone_apk, phone_size = package_digests[("phone", "apk")]
    if phone_apk != artifact_hash or phone_size != artifact.stat().st_size:
        raise EvidenceError("phone APK candidate is not the exact staged live-smoke artifact.")
    if phone_apk != require_sha256(machine["artifact_sha256"], "Artifact"):
        raise EvidenceError("phone APK candidate contradicts artifact_sha256.")
    for role, relative in PHONE_CANDIDATE_ALIASES.items():
        digest, size = package_digests[("phone", role)]
        produced_package_bytes(repo, relative, digest, size, f"phone flavored {role} candidate")
    validate_vpn_runtime(
        root,
        matrix["phone"]["runtime"],
        form="phone",
        candidate_id=FORM_FACTOR_CANDIDATES["phone"],
        version_name=str(machine["app_version"]),
        version_code=version_codes["phone"],
        artifact_sha256=phone_apk,
        machine_captured=machine_captured,
        used_receipts=used_receipts,
    )
    validate_vpn_runtime(
        root,
        matrix["tv"]["runtime"],
        form="tv",
        candidate_id=FORM_FACTOR_CANDIDATES["tv"],
        version_name=str(machine["app_version"]),
        version_code=version_codes["tv"],
        artifact_sha256=package_digests[("tv", "apk")][0],
        machine_captured=machine_captured,
        used_receipts=used_receipts,
    )
    validate_wear_runtime(
        root,
        matrix["wear"]["runtime"],
        candidate_id=FORM_FACTOR_CANDIDATES["wear"],
        version_name=str(machine["app_version"]),
        version_code=version_codes["wear"],
        artifact_sha256=package_digests[("wear", "aab")][0],
        phone_apk_sha256=phone_apk,
        machine_captured=machine_captured,
        used_receipts=used_receipts,
    )
    validate_mapping_custody(
        repo,
        root,
        machine["private_symbol_mapping_sha256"],
        owner_blocked=machine["mapping_owner_blocked"],
        app_version=str(machine["app_version"]),
        phone_version_code=version_codes["phone"],
        wear_version_code=version_codes["wear"],
    )
    validate_listing_inventory(machine["listing_inventory"])


def validate_network_change(root: pathlib.Path, value: Any) -> None:
    fields = {
        "before_underlying_transport", "after_underlying_transport",
        "vpn_continuously_present", "tun_rx_delta", "tun_tx_delta",
        "protected_egress_sha256", "dns_servers", "dns_leak_passed",
        "ipv4_leak_passed", "ipv6_leak_passed", "wifi_state_restored",
        "mobile_data_state_restored", "receipt_path", "receipt_sha256", "passed",
    }
    network = require_exact(value, fields, "Android network-change evidence")
    pair = (network["before_underlying_transport"], network["after_underlying_transport"])
    if pair not in {("wifi", "cellular"), ("cellular", "wifi")}:
        raise EvidenceError("Android network change must exercise Wi-Fi and cellular in different directions.")
    for counter in ("tun_rx_delta", "tun_tx_delta"):
        if isinstance(network[counter], bool) or not isinstance(network[counter], int) or network[counter] < MIN_TUN_BYTES:
            raise EvidenceError(f"Android network change {counter} lacks traffic proof.")
    require_observed_sha256(network["protected_egress_sha256"], "Network-change protected egress")
    if network["dns_servers"] != ["10.8.1.1"]:
        raise EvidenceError("Android network-change tunnel DNS must be exactly 10.8.1.1.")
    for field in (
        "vpn_continuously_present", "dns_leak_passed", "ipv4_leak_passed",
        "ipv6_leak_passed", "wifi_state_restored", "mobile_data_state_restored", "passed",
    ):
        require_true(network[field], f"Android network change {field}")
    receipt_value = evidence_json(
        root,
        network["receipt_path"],
        network["receipt_sha256"],
        {
            "schema_version", "contract", "before_underlying_transport",
            "after_underlying_transport", "vpn_continuously_present", "tun_rx_delta",
            "tun_tx_delta", "protected_egress_sha256", "dns_servers",
            "dns_leak_passed", "ipv4_leak_passed", "ipv6_leak_passed",
            "wifi_state_restored", "mobile_data_state_restored", "passed",
            "captured_at_utc", "secret_material_redacted",
        },
        "winsvpn-android-network-change-receipt-v1",
        "Android network-change receipt",
    )
    for field in fields - {"receipt_path", "receipt_sha256"}:
        if receipt_value[field] != network[field]:
            raise EvidenceError(f"Android network-change receipt contradicts {field}.")


def validate_global_teardown(root: pathlib.Path, value: Any) -> None:
    fields = {
        "tun_absent", "vpn_service_absent", "xray_absent", "wifi_state_restored",
        "mobile_data_state_restored", "receipt_path", "receipt_sha256", "passed",
    }
    teardown = require_exact(value, fields, "Android global teardown evidence")
    for field in fields - {"receipt_path", "receipt_sha256"}:
        require_true(teardown[field], f"Android global teardown {field}")
    observed = evidence_json(
        root,
        teardown["receipt_path"],
        teardown["receipt_sha256"],
        {
            "schema_version", "contract", "tun_absent", "vpn_service_absent",
            "xray_absent", "wifi_state_restored", "mobile_data_state_restored",
            "passed", "captured_at_utc", "secret_material_redacted",
        },
        "winsvpn-android-global-teardown-receipt-v1",
        "Android global teardown receipt",
    )
    for field in fields - {"receipt_path", "receipt_sha256"}:
        if observed[field] != teardown[field]:
            raise EvidenceError(f"Android global teardown receipt contradicts {field}.")


def validate_global_rollback(root: pathlib.Path, value: Any) -> None:
    fields = {
        "before_state_sha256", "after_state_sha256", "remote_forcing_absent",
        "network_state_restored", "split_state_restored", "double_vpn_state_restored",
        "receipt_path", "receipt_sha256", "passed",
    }
    rollback = require_exact(value, fields, "Android global rollback evidence")
    before = require_observed_sha256(rollback["before_state_sha256"], "Rollback before state")
    after = require_observed_sha256(rollback["after_state_sha256"], "Rollback after state")
    if before != after:
        raise EvidenceError("Android final control state was not restored exactly.")
    for field in (
        "remote_forcing_absent", "network_state_restored", "split_state_restored",
        "double_vpn_state_restored", "passed",
    ):
        require_true(rollback[field], f"Android global rollback {field}")
    observed = evidence_json(
        root,
        rollback["receipt_path"],
        rollback["receipt_sha256"],
        {
            "schema_version", "contract", "before_state_sha256", "after_state_sha256",
            "remote_forcing_absent", "network_state_restored", "split_state_restored",
            "double_vpn_state_restored", "passed", "captured_at_utc",
            "secret_material_redacted",
        },
        "winsvpn-android-global-rollback-receipt-v1",
        "Android global rollback receipt",
    )
    for field in fields - {"receipt_path", "receipt_sha256"}:
        if observed[field] != rollback[field]:
            raise EvidenceError(f"Android global rollback receipt contradicts {field}.")


def compile_evidence(
    machine: dict[str, Any],
    root: pathlib.Path,
    artifact: pathlib.Path,
    binding: dict[str, str],
    evidence_bundle_index_sha256: str,
    repo: pathlib.Path,
) -> dict[str, Any]:
    top = require_exact(
        machine,
        {
            "schema_version",
            "contract",
            "platform",
            "app_version",
            "build_number",
            "artifact_sha256",
            "artifact_size_bytes",
            "application_id",
            "phone_aab_sha256",
            "phone_aab_size_bytes",
            "tv_apk_sha256",
            "tv_apk_size_bytes",
            "tv_aab_sha256",
            "tv_aab_size_bytes",
            "wear_aab_sha256",
            "wear_aab_size_bytes",
            "private_symbol_mapping_sha256",
            "mapping_owner_blocked",
            "listing_inventory",
            "form_factor_matrix",
            "release_input_index_sha256",
            "platform_manifest_sha256",
            "artifact_input_fingerprint_sha256",
            "build_receipt_sha256",
            "producer_contract_sha256",
            "artifact_signer_sha256",
            "installed_base_apk_sha256",
            "installed_base_apk_size_bytes",
            "installed_signer_sha256",
            "artifact_signature_receipt_path",
            "artifact_signature_receipt_sha256",
            "clean_uninstall_passed",
            "install_passed",
            "run_id",
            "captured_at_utc",
            "secret_material_redacted",
            "startup",
            "direct_awg_port",
            "double_vpn_direct_port",
            "advertised_xray_routes",
            "double_vpn_advertised_xray_routes",
            "lanes",
            "split_browser",
            "leak",
            "map_visual",
            "network_change",
            "teardown",
            "rollback",
        },
        "Android machine evidence",
    )
    if top["schema_version"] != 2 or top["contract"] != MACHINE_CONTRACT or top["platform"] != "android":
        raise EvidenceError("Android machine-evidence contract/version/platform is invalid.")
    if not isinstance(top["build_number"], str) or not top["build_number"].isdigit():
        raise EvidenceError("Android build_number must be a decimal string.")
    artifact_hash = require_sha256(top["artifact_sha256"], "Artifact")
    if sha256_file(artifact) != artifact_hash:
        raise EvidenceError("Machine evidence is not bound to the exact staged APK.")
    if top["artifact_size_bytes"] != artifact.stat().st_size:
        raise EvidenceError("Machine artifact size does not match the staged APK.")
    validate_machine_binding(top, binding)
    if top["installed_base_apk_size_bytes"] != top["artifact_size_bytes"]:
        raise EvidenceError("Installed base APK size does not match the staged APK.")
    if require_sha256(top["installed_base_apk_sha256"], "Installed APK") != artifact_hash:
        raise EvidenceError("Installed base APK hash does not match the staged APK.")
    for field in ("artifact_signer_sha256", "installed_signer_sha256"):
        if require_sha256(top[field], field) != EXPECTED_SIGNER_SHA256:
            raise EvidenceError(f"{field} is not the pinned Android upload signer.")
    signature_receipt = evidence_json(
        root,
        top["artifact_signature_receipt_path"],
        top["artifact_signature_receipt_sha256"],
        {
            "schema_version", "contract", "artifact_sha256", "artifact_size_bytes",
            "installed_base_apk_sha256", "installed_base_apk_size_bytes",
            "artifact_signer_sha256", "installed_signer_sha256",
            "apksigner_verified", "captured_at_utc", "secret_material_redacted",
        },
        "winsvpn-android-apk-signature-receipt-v1",
        "APK signature receipt",
    )
    signature_expected = {
        "artifact_sha256": artifact_hash,
        "artifact_size_bytes": top["artifact_size_bytes"],
        "installed_base_apk_sha256": artifact_hash,
        "installed_base_apk_size_bytes": top["artifact_size_bytes"],
        "artifact_signer_sha256": EXPECTED_SIGNER_SHA256,
        "installed_signer_sha256": EXPECTED_SIGNER_SHA256,
    }
    for field, expected in signature_expected.items():
        if signature_receipt[field] != expected:
            raise EvidenceError(f"APK signature receipt {field} contradicts machine evidence.")
    require_true(signature_receipt["apksigner_verified"], "APK signature receipt verification")
    require_true(top["clean_uninstall_passed"], "Clean uninstall")
    require_true(top["install_passed"], "Exact APK install")
    require_true(top["secret_material_redacted"], "Secret redaction")
    try:
        run_id = uuid.UUID(str(top["run_id"]))
    except ValueError as exc:
        raise EvidenceError("Android machine-evidence run_id must be a UUID.") from exc
    if run_id.int == 0:
        raise EvidenceError("Android machine-evidence run_id must not be zero.")
    captured = parse_utc(top["captured_at_utc"])
    require_fresh(captured, "Android machine evidence captured_at_utc")
    validate_form_factor_matrix(top, root, repo, artifact, artifact_hash, captured)

    startup = require_exact(
        top["startup"],
        {"pid", "logcat_path", "logcat_sha256", "fatal_scan_passed"},
        "Android startup evidence",
    )
    if isinstance(startup["pid"], bool) or not isinstance(startup["pid"], int) or startup["pid"] <= 0:
        raise EvidenceError("Android startup PID is invalid.")
    require_true(startup["fatal_scan_passed"], "Startup fatal scan")
    evidence_file(root, startup["logcat_path"], startup["logcat_sha256"], "PID-scoped startup logcat")

    direct_awg_port = top["direct_awg_port"]
    double_vpn_direct_port = top["double_vpn_direct_port"]
    for value, label in (
        (direct_awg_port, "direct_awg_port"),
        (double_vpn_direct_port, "double_vpn_direct_port"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise EvidenceError(f"{label} must be a valid machine-observed UDP port.")
    if direct_awg_port != 9110:
        raise EvidenceError("The public data-plane direct AWG route must use UDP 9110.")

    def normalize_advertised(value: Any, label: str) -> tuple[list[dict[str, Any]], set[tuple[int, str]]]:
        if not isinstance(value, list) or not value:
            raise EvidenceError(f"At least one {label} is required.")
        normalized: list[dict[str, Any]] = []
        keys: set[tuple[int, str]] = set()
        for raw in value:
            route = require_exact(raw, {"protocol", "port", "security"}, label)
            if route["protocol"] != "tcp" or isinstance(route["port"], bool) or not isinstance(route["port"], int):
                raise EvidenceError(f"{label} protocol/port is invalid.")
            if not 1 <= route["port"] <= 65535 or route["security"] not in {"none", "tls"}:
                raise EvidenceError(f"{label} port/security is invalid.")
            key = (route["port"], route["security"])
            if key in keys:
                raise EvidenceError(f"Duplicate {label.lower()} values are forbidden.")
            keys.add(key)
            normalized.append({"protocol": "tcp", "port": key[0], "security": key[1]})
        return normalized, keys

    advertised, advertised_keys = normalize_advertised(
        top["advertised_xray_routes"], "advertised node Xray route"
    )
    double_advertised, double_advertised_keys = normalize_advertised(
        top["double_vpn_advertised_xray_routes"], "advertised Double VPN Xray route"
    )

    if not isinstance(top["lanes"], list):
        raise EvidenceError("Android route lanes must be a list.")
    lanes = [
        validate_lane(
            root,
            lane,
            direct_awg_port=direct_awg_port,
            double_vpn_direct_port=double_vpn_direct_port,
        )
        for lane in top["lanes"]
    ]
    ids = [str(lane["lane_id"]) for lane in lanes]
    if len(ids) != len(set(ids)):
        raise EvidenceError("Android route lane IDs must be unique.")
    inventory_digests = {lane["route_inventory_sha256"] for lane in lanes}
    if len(inventory_digests) != 1:
        raise EvidenceError("Android route lanes are not bound to one exact live route inventory.")
    node_manifest = route_manifest_sha256(advertised)
    double_manifest = route_manifest_sha256(double_advertised)
    for lane in lanes:
        expected_manifest = double_manifest if lane["double_vpn"] else node_manifest
        if lane["mode_xray_manifest_sha256"] != expected_manifest:
            raise EvidenceError(f"{lane['lane_id']} is not bound to its advertised mode-specific Xray set.")
    kinds = [lane["kind"] for lane in lanes]
    for required_kind in ("direct_awg", "double_vpn_direct"):
        if kinds.count(required_kind) != 1:
            raise EvidenceError(f"Exactly one {required_kind} lane is required.")
    tested_xray_keys = {
        (lane["port"], lane["security"]) for lane in lanes if lane["kind"] == "xray"
    }
    if tested_xray_keys != advertised_keys or kinds.count("xray") != len(advertised_keys):
        raise EvidenceError("Every advertised Xray port/security route must have exactly one single-hop live lane.")
    tested_double_xray_keys = {
        (lane["port"], lane["security"])
        for lane in lanes
        if lane["kind"] == "double_vpn_xray"
    }
    if (
        tested_double_xray_keys != double_advertised_keys
        or kinds.count("double_vpn_xray") != len(double_advertised_keys)
    ):
        raise EvidenceError("Every advertised Double VPN Xray port/security route must have exactly one live lane.")

    direct_egress = next(lane["protected_egress_sha256"] for lane in lanes if lane["kind"] == "direct_awg")
    split = require_exact(
        top["split_browser"],
        {
            "excluded_package",
            "protected_package",
            "baseline_egress_sha256",
            "excluded_egress_sha256",
            "protected_egress_sha256",
            "selection_receipt_path",
            "selection_receipt_sha256",
            "passed",
        },
        "Android split-browser evidence",
    )
    if split["excluded_package"] != "com.android.chrome" or split["protected_package"] != "com.sec.android.app.sbrowser":
        raise EvidenceError("Android split proof must use excluded Chrome and protected Samsung Internet.")
    baseline = require_observed_sha256(split["baseline_egress_sha256"], "Split baseline egress")
    excluded = require_observed_sha256(split["excluded_egress_sha256"], "Split excluded egress")
    protected = require_observed_sha256(split["protected_egress_sha256"], "Split protected egress")
    if excluded != baseline or protected != direct_egress or protected == baseline:
        raise EvidenceError("Android split-browser egress does not prove excluded-versus-protected routing.")
    require_true(split["passed"], "Android split-browser test")
    split_receipt = evidence_json(
        root,
        split["selection_receipt_path"],
        split["selection_receipt_sha256"],
        {
            "schema_version", "contract", "excluded_package", "protected_package",
            "baseline_egress_sha256", "excluded_egress_sha256",
            "protected_egress_sha256", "selection_ui_sha256", "passed",
            "captured_at_utc", "secret_material_redacted",
        },
        "winsvpn-android-split-browser-receipt-v1",
        "Split selection receipt",
    )
    for field in (
        "excluded_package", "protected_package", "baseline_egress_sha256",
        "excluded_egress_sha256", "protected_egress_sha256",
    ):
        if split_receipt[field] != split[field]:
            raise EvidenceError(f"Split selection receipt {field} contradicts machine evidence.")
    require_sha256(split_receipt["selection_ui_sha256"], "Split selection UI")
    require_true(split_receipt["passed"], "Split selection receipt")

    leak = require_exact(
        top["leak"],
        {
            "dns_servers",
            "protected_canary_count",
            "dns_leak_passed",
            "ipv4_leak_passed",
            "ipv6_leak_passed",
            "receipt_path",
            "receipt_sha256",
        },
        "Android leak evidence",
    )
    if leak["dns_servers"] != ["10.8.1.1"]:
        raise EvidenceError("Android tunnel DNS must be exactly 10.8.1.1.")
    if isinstance(leak["protected_canary_count"], bool) or leak["protected_canary_count"] < 2:
        raise EvidenceError("Android leak proof requires two independent protected canaries.")
    for field in ("dns_leak_passed", "ipv4_leak_passed", "ipv6_leak_passed"):
        require_true(leak[field], f"Android {field}")
    leak_receipt = evidence_json(
        root,
        leak["receipt_path"],
        leak["receipt_sha256"],
        {
            "schema_version", "contract", "dns_servers", "protected_canary_count",
            "dns_leak_passed", "ipv4_leak_passed", "ipv6_leak_passed",
            "captured_at_utc", "secret_material_redacted",
        },
        "winsvpn-android-leak-receipt-v1",
        "Leak receipt",
    )
    for field in (
        "dns_servers", "protected_canary_count", "dns_leak_passed",
        "ipv4_leak_passed", "ipv6_leak_passed",
    ):
        if leak_receipt[field] != leak[field]:
            raise EvidenceError(f"Leak receipt {field} contradicts machine evidence.")

    map_visual = require_exact(
        top["map_visual"],
        {
            "screenshot_path",
            "screenshot_sha256",
            "radius_miles",
            "city_labels_visible",
            "target_marker_visible",
            "viewport_not_world_zoom",
        },
        "Android map evidence",
    )
    screenshot = evidence_file(
        root,
        map_visual["screenshot_path"],
        map_visual["screenshot_sha256"],
        "Android map screenshot",
    )
    if screenshot.stat().st_size < 1024:
        raise EvidenceError("Android map screenshot is implausibly small.")
    if map_visual["radius_miles"] != 50:
        raise EvidenceError("Android map radius must be exactly 50 miles.")
    for field in ("city_labels_visible", "target_marker_visible", "viewport_not_world_zoom"):
        require_true(map_visual[field], f"Android map {field}")

    validate_network_change(root, top["network_change"])
    validate_global_teardown(root, top["teardown"])
    validate_global_rollback(root, top["rollback"])

    tested_routes = [
        {"protocol": "tcp", "port": port, "security": security, "passed": True}
        for port, security in sorted(tested_xray_keys)
    ]
    return {
        "schema_version": 2,
        "contract": NATIVE_CONTRACT,
        "platform": "android",
        "app_version": str(top["app_version"]),
        "build_number": str(top["build_number"]),
        "artifact_sha256": artifact_hash,
        "evidence_bundle_index_sha256": require_observed_sha256(
            evidence_bundle_index_sha256, "Android evidence bundle index"
        ),
        "run_id": str(run_id),
        "captured_at_utc": captured.isoformat().replace("+00:00", "Z"),
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
            "screenshot_sha256": map_visual["screenshot_sha256"],
            "radius_miles": 50,
            "city_labels_visible": True,
            "target_marker_visible": True,
            "viewport_not_world_zoom": True,
        },
        "direct_awg": {"protocol": "udp", "port": direct_awg_port, "passed": True},
        "advertised_xray_routes": sorted(advertised, key=lambda item: (item["port"], item["security"])),
        "tested_xray_routes": tested_routes,
    }


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_self_test() -> None:
    # Unit tests exercise complete positive/negative fixtures. Keep CLI
    # self-test small so the public producer can prove this exact compiler is
    # callable without manufacturing a live transcript.
    require_sha256("0" * 64, "self-test")
    try:
        require_sha256("A" * 64, "self-test")
    except EvidenceError:
        pass
    else:
        raise EvidenceError("Compiler self-test accepted a non-lowercase digest.")
    print("ANDROID RELEASE MATRIX EVIDENCE COMPILER SELF-TEST: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-index")
    parser.add_argument("--expected-evidence-index-sha256")
    parser.add_argument("--expected-run-id")
    parser.add_argument("--artifact")
    parser.add_argument("--release-input-index")
    parser.add_argument("--build-receipt")
    parser.add_argument("--output")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if not all((
        args.evidence_index, args.expected_evidence_index_sha256, args.expected_run_id,
        args.artifact, args.release_input_index, args.build_receipt, args.output,
    )):
        raise EvidenceError(
            "--evidence-index, its expected digest/run ID, --artifact, --release-input-index, "
            "--build-receipt, and --output are required."
        )
    evidence_index = pathlib.Path(args.evidence_index).absolute()
    artifact = pathlib.Path(args.artifact).resolve()
    output = pathlib.Path(args.output).resolve()
    if not evidence_index.is_file() or not artifact.is_file():
        raise EvidenceError("Evidence index and staged APK must exist.")
    repo = pathlib.Path(__file__).resolve().parent.parent
    try:
        inputs = release_input_binding(repo, "android", args.release_input_index)
        build = build_receipt_binding(
            repo, "android", args.release_input_index, args.build_receipt, artifact
        )
        binding = {
            "release_input_index_sha256": inputs.index_sha256,
            "platform_manifest_sha256": inputs.platform_manifest_sha256,
            "artifact_input_fingerprint_sha256": inputs.artifact_input_fingerprint_sha256,
            "shared_revision": inputs.shared_revision,
            "release_input_index_path": pathlib.Path(args.release_input_index).expanduser().resolve().relative_to(repo.resolve()).as_posix(),
            "build_receipt_sha256": build.sha256,
            "build_receipt_path": build.path,
            "producer_contract_sha256": producer_contract_hash(repo, ANDROID_PUBLIC_PRODUCER),
        }
    except Exception as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError(f"Android release input/build binding failed: {exc}") from exc
    machine, bundle_root, bundle_index_sha256, map_path = load_evidence_bundle(
        repo,
        evidence_index,
        artifact,
        binding,
        expected_index_sha256=args.expected_evidence_index_sha256,
        expected_run_id=args.expected_run_id,
    )
    transcript = compile_evidence(
        machine, bundle_root, artifact, binding, bundle_index_sha256, repo
    )
    write_json(output, transcript)
    print("ANDROID RELEASE MATRIX EVIDENCE: PASS")
    print(f"EVIDENCE_RUN_ID={machine['run_id']}")
    print(f"EVIDENCE_INDEX_SHA256={bundle_index_sha256}")
    print(f"EVIDENCE_MAP_SCREENSHOT_PATH={map_path}")
    print(f"Native transcript: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        print(f"ANDROID RELEASE MATRIX EVIDENCE: FAIL: {exc}")
        raise SystemExit(1)
