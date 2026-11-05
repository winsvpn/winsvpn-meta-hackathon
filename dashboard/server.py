#!/usr/bin/env python3
"""Local, fail-closed release-readiness dashboard for Win's VPN."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import shutil
import stat
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "dashboard" / "state.json"
DEFAULT_EVIDENCE_ROOT = REPO_ROOT / ".artifacts" / "dashboard" / "evidence"
DEFAULT_SNAPSHOT = REPO_ROOT / ".artifacts" / "dashboard" / "state.snapshot.json"
DEFAULT_CROSS_STORE_CACHE = (
    REPO_ROOT / ".artifacts" / "dashboard" / "cross-store-cache.json"
)
DASHBOARD_INDEX = REPO_ROOT / "dashboard" / "index.html"
STATIC_DIR = REPO_ROOT / "dashboard" / "static"
INDEX = STATIC_DIR / "index.html"
APP_JS = STATIC_DIR / "app.js"
SECURITY_CSP = (
    "default-src 'self'; style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)
LOCAL_BIND = "127.0.0.1"
DEFAULT_PORT = 4210
ALLOWED_GET_TARGETS = frozenset({"/", "/index.html", "/api/state", "/app.js"})
CROSS_STORE_CACHE_SCHEMA_VERSION = 1
CROSS_STORE_RECEIPT_STATUSES = (
    "verified",
    "missing",
    "invalid",
    "stale",
    "unavailable",
)
MAX_JSON_BYTES = 1024 * 1024
FUTURE_SKEW = timedelta(minutes=5)
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
PRODUCER_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SAFE_RELATIVE_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SECRET_LIKE_PRODUCER_PREFIXES = (
    "akia",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "hf_",
    "sk_",
)
RELEASE_IDENTITY = "1.0.17+34"
DASHBOARD_SCHEMA_VERSION = 8
DASHBOARD_RECEIPT_SCHEMA_VERSION = 4
CROSS_STORE_RECEIPT_SCHEMA_VERSION = 2
CROSS_STORE_RECEIPT_CONTRACT = "winsvpn-upload-target-receipt-v2"
DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY = ".artifacts/upload-receipts"
DEFAULT_RELEASE_INPUT_INDEX = ".artifacts/release-inputs/RELEASE_INPUT_INDEX.json"
REQUIRED_UPLOAD_TARGET_IDS = (
    "android-phone-tablet-aab",
    "android-tv-aab",
    "wear-os-aab",
    "ios-app-store-ipa",
    "macos-app-store-pkg",
    "windows-x64-installer",
    "windows-x64-partner-center",
    "windows-arm64-installer",
    "windows-arm64-partner-center",
    "linux-x64-package",
    "linux-arm64-package",
    "linux-flathub-manifest",
    "linux-snap-manifest",
    "chrome-extension-package",
    "edge-extension-package",
    "firefox-extension-package",
)
OPTIONAL_UPLOAD_TARGET_IDS = ("macos-developer-id-app",)
KNOWN_CROSS_STORE_TARGET_IDS = REQUIRED_UPLOAD_TARGET_IDS + OPTIONAL_UPLOAD_TARGET_IDS

# Store surfaces represented by each dashboard card. Shared/universal artifacts
# intentionally appear on more than one card; every required upload target must
# be named at least once so TV, Edge, and secondary package surfaces cannot vanish.
DASHBOARD_UPLOAD_TARGET_MAP = {
    "windows-x86": ("windows-x64-installer", "windows-x64-partner-center"),
    "windows-arm64": ("windows-arm64-installer", "windows-arm64-partner-center"),
    "macos-x86": ("macos-app-store-pkg",),
    "macos-arm64": ("macos-app-store-pkg",),
    "linux-x86": ("linux-x64-package", "linux-flathub-manifest", "linux-snap-manifest"),
    "linux-arm64": ("linux-arm64-package", "linux-flathub-manifest", "linux-snap-manifest"),
    "ios": ("ios-app-store-ipa",),
    "android": ("android-phone-tablet-aab", "android-tv-aab"),
    "chrome-extension": ("chrome-extension-package", "edge-extension-package"),
    "firefox-extension": ("firefox-extension-package",),
    "watch-wear-os": ("wear-os-aab",),
    "apple-watch-watchos": ("ios-app-store-ipa",),
    "control-hub": (),
    "data-plane": (),
    "core-double-vpn": (),
    "smart-router": (),
    "gcp-three-server-proof": (),
    "signing-store-metadata": (),
    "winn-v3": (),
    "winn-v1-awg-xray": (),
}
DASHBOARD_OPTIONAL_UPLOAD_TARGET_MAP = {
    target_id: (
        ("macos-developer-id-app",)
        if target_id in {"macos-x86", "macos-arm64"}
        else ()
    )
    for target_id in DASHBOARD_UPLOAD_TARGET_MAP
}

if set(REQUIRED_UPLOAD_TARGET_IDS) != {
    upload_target
    for upload_targets in DASHBOARD_UPLOAD_TARGET_MAP.values()
    for upload_target in upload_targets
}:
    raise RuntimeError("dashboard upload-target map does not cover the required matrix")
if set(OPTIONAL_UPLOAD_TARGET_IDS) != {
    upload_target
    for upload_targets in DASHBOARD_OPTIONAL_UPLOAD_TARGET_MAP.values()
    for upload_target in upload_targets
}:
    raise RuntimeError("dashboard optional upload-target map is invalid")
if set(REQUIRED_UPLOAD_TARGET_IDS).intersection(OPTIONAL_UPLOAD_TARGET_IDS):
    raise RuntimeError("required and optional upload-target matrices overlap")
if len(KNOWN_CROSS_STORE_TARGET_IDS) != len(set(KNOWN_CROSS_STORE_TARGET_IDS)):
    raise RuntimeError("cross-store upload-target matrices contain duplicate ids")

# Operator visibility is a display split of the scored Chrome card. Scoring
# still maps chrome-extension to both Chrome and Edge receipts. The operator
# view must show Edge as its own store surface so Edge upload state cannot
# hide under Chrome while Chrome remains a first-class card.
OPERATOR_EDGE_TARGET_ID = "edge-extension"
OPERATOR_EDGE_LABEL = "Edge extension"
OPERATOR_UPLOAD_TARGET_MAP = {
    **{
        target_id: (
            ("chrome-extension-package",)
            if target_id == "chrome-extension"
            else upload_targets
        )
        for target_id, upload_targets in DASHBOARD_UPLOAD_TARGET_MAP.items()
    },
    OPERATOR_EDGE_TARGET_ID: ("edge-extension-package",),
}
OPERATOR_OPTIONAL_UPLOAD_TARGET_MAP = {
    **DASHBOARD_OPTIONAL_UPLOAD_TARGET_MAP,
    OPERATOR_EDGE_TARGET_ID: (),
}
if set(REQUIRED_UPLOAD_TARGET_IDS) != {
    upload_target
    for upload_targets in OPERATOR_UPLOAD_TARGET_MAP.values()
    for upload_target in upload_targets
}:
    raise RuntimeError("operator upload-target map does not cover the required matrix")
if OPERATOR_UPLOAD_TARGET_MAP["chrome-extension"] != ("chrome-extension-package",):
    raise RuntimeError("Chrome operator card must map only the Chrome upload target")
if OPERATOR_UPLOAD_TARGET_MAP[OPERATOR_EDGE_TARGET_ID] != ("edge-extension-package",):
    raise RuntimeError("Edge operator card must map only the Edge upload target")
if "edge-extension-package" in OPERATOR_UPLOAD_TARGET_MAP["chrome-extension"]:
    raise RuntimeError("Chrome operator card must not hide Edge upload state")
if OPERATOR_EDGE_TARGET_ID in DASHBOARD_UPLOAD_TARGET_MAP:
    raise RuntimeError("scored target contract must not gain a separate Edge card")
if set(OPERATOR_OPTIONAL_UPLOAD_TARGET_MAP) != set(OPERATOR_UPLOAD_TARGET_MAP):
    raise RuntimeError("operator optional upload-target map is incomplete")
if len(REQUIRED_UPLOAD_TARGET_IDS) == len(OPERATOR_UPLOAD_TARGET_MAP):
    raise RuntimeError("store-upload denominator must not equal operator/blocker card count")
if len(REQUIRED_UPLOAD_TARGET_IDS) != 16:
    raise RuntimeError("strict store-upload denominator must remain 16")

PUBLICATION_HOLD = "DO-NOT-UPLOAD"
GCP_PROOF_SUMMARY_CODE = "gcp_proof_acceptance"
GCP_PROOF_RECEIPT_NAME = "acceptance-receipt.json"
GCP_PROOF_FRESHNESS = timedelta(hours=6)
GCP_PROOF_TARGET_ID = "gcp-three-server-proof"
AGP_MIGRATION_SUMMARY_CODE = "agp_migration_complete"
MACOS_PYTHON_SUMMARY_CODE = "macos_release_python_runtime"
CURRENT_POSTURE_CATEGORY_IDS = (
    "publication_hold",
    "missing_upload_receipts",
    "gcp_proof",
    "agp_migration",
    "macos_release_python",
    "undisclosed_blocker_audits",
    "owner_blockers",
    "external_blockers",
)

REQUIRED_TARGETS = {
    "windows-x86": "Windows x64",
    "windows-arm64": "Windows arm64",
    "macos-x86": "macOS x86",
    "macos-arm64": "macOS arm64",
    "linux-x86": "Linux x64",
    "linux-arm64": "Linux arm64",
    "ios": "iOS",
    "android": "Android",
    "chrome-extension": "Chrome extension",
    "firefox-extension": "Firefox extension",
    "watch-wear-os": "Wear OS",
    "apple-watch-watchos": "Apple Watch/watchOS",
    "control-hub": "control hub",
    "data-plane": "data plane",
    "core-double-vpn": "core/double-VPN",
    "smart-router": "Smart Router",
    "gcp-three-server-proof": "Three-server GCP proof",
    "signing-store-metadata": "Signing and store metadata",
    "winn-v3": "Winn v3",
    "winn-v1-awg-xray": "Winn v1 AWG/Xray",
}
if len(REQUIRED_TARGETS) != 20:
    raise RuntimeError("engineering/operator scored target count must remain 20")
if len(REQUIRED_TARGETS) == len(OPERATOR_UPLOAD_TARGET_MAP):
    raise RuntimeError("engineering target count must stay distinct from operator Chrome/Edge split")

REQUIRED_DIMENSIONS = {
    "engineering": "Engineering verification",
    "artifact": "Release artifact",
    "signing": "Signing verification",
    "store_metadata": "Store metadata",
    "runtime_proof": "Runtime proof",
}
BLOCKER_KINDS = {"owner", "external"}
DIMENSION_EVIDENCE_CONTRACT = {
    "engineering": ("engineering_verification", "engineering_gate"),
    "artifact": ("release_artifact_verification", "artifact_gate"),
    "signing": ("signature_verification", "signature_gate"),
    "store_metadata": ("store_metadata_verification", "store_metadata_gate"),
    "runtime_proof": ("runtime_verification", "runtime_gate"),
}
BLOCKER_AUDIT_CONTRACT = ("release_blocker_audit", "blocker_gate")
OPEN_BLOCKER_CONTRACT = ("open_release_blocker", "blocker_gate")
ENGINEERING_DIMENSION_IDS = frozenset({"engineering", "runtime_proof"})
STORE_DIMENSION_IDS = frozenset({"artifact", "signing", "store_metadata"})
FORBIDDEN_EVIDENCE_PATH_PARTS = frozenset(
    {
        "handoff",
        "handoffs",
        "blueprint",
        "blueprints",
        "plan",
        "plans",
        "docs",
        "test",
        "tests",
        "testing",
        "testdata",
        "test-data",
        "unittest",
        "unittests",
        "pytest",
        "coverage",
        "upload-receipts",
        "release-inputs",
    }
)
FORBIDDEN_EVIDENCE_NAME_MARKERS = (
    "handoff",
    "blueprint",
    "unittest",
    "unit-test",
    "unit_test",
    "pytest",
    "test_report",
    "coverage",
    "progress.json",
    "continue.md",
    "lane_report",
)
FORBIDDEN_EVIDENCE_SUFFIXES = {".md", ".rst", ".arb"}
if ENGINEERING_DIMENSION_IDS | STORE_DIMENSION_IDS != frozenset(REQUIRED_DIMENSIONS):
    raise RuntimeError("engineering/store dimension split does not cover the contract")
if ENGINEERING_DIMENSION_IDS & STORE_DIMENSION_IDS:
    raise RuntimeError("engineering and store dimension sets overlap")

_hash_cache: dict[Path, tuple[int, int, int, int, int, str]] = {}
_hash_cache_lock = threading.Lock()
_cross_store_module: Any | None = None
_cross_store_module_lock = threading.Lock()
_gcp_proof_module: Any | None = None
_gcp_proof_module_lock = threading.Lock()


class DashboardError(ValueError):
    """Raised when configuration or evidence is not safe to use."""


class CrossStoreReceiptMissing(DashboardError):
    """Raised when one required canonical upload-target receipt is absent."""


def require_exact_fields(value: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = set(value) - allowed
    missing = allowed - set(value)
    if unknown or missing:
        details = []
        if unknown:
            details.append("unknown " + ", ".join(sorted(unknown)))
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        raise DashboardError(f"{context} fields are invalid: " + "; ".join(details))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DashboardError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise DashboardError(f"cannot read {path.name}: {exc.strerror or exc}") from exc
    try:
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise DashboardError(f"{path.name} must be a regular file")
            if opened.st_size > MAX_JSON_BYTES:
                raise DashboardError(f"{path.name} exceeds {MAX_JSON_BYTES} bytes")
            payload = handle.read(MAX_JSON_BYTES + 1)
            if len(payload) > MAX_JSON_BYTES:
                raise DashboardError(f"{path.name} exceeds {MAX_JSON_BYTES} bytes")
            if _stat_key(os.fstat(handle.fileno())) != _stat_key(opened):
                raise DashboardError(f"{path.name} changed while being read")
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, DashboardError) as exc:
        raise DashboardError(f"invalid JSON in {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise DashboardError(f"{path.name} must contain a JSON object")
    return value


def parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise DashboardError(f"{field} must be a UTC timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise DashboardError(f"{field} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise DashboardError(f"{field} must include UTC offset Z or +00:00")
    return parsed.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _validate_dimension_list(dimensions: Any) -> list[dict[str, Any]]:
    if not isinstance(dimensions, list) or not dimensions:
        raise DashboardError("dimensions must be a non-empty array")
    seen: set[str] = set()
    total = 0
    validated: list[dict[str, Any]] = []
    for dimension in dimensions:
        if not isinstance(dimension, dict):
            raise DashboardError("dimensions contains a non-object entry")
        require_exact_fields(dimension, {"id", "label", "weight"}, "dimension")
        dimension_id = dimension.get("id")
        label = dimension.get("label")
        weight = dimension.get("weight")
        if dimension_id not in REQUIRED_DIMENSIONS:
            raise DashboardError("dimensions contains an unknown id")
        if dimension_id in seen:
            raise DashboardError(f"dimensions repeats {dimension_id}")
        if label != REQUIRED_DIMENSIONS[dimension_id]:
            raise DashboardError(f"dimension {dimension_id} has an unexpected label")
        if not isinstance(label, str) or not label.strip():
            raise DashboardError(f"dimension {dimension_id} must have a label")
        if isinstance(weight, bool) or not isinstance(weight, int) or weight <= 0:
            raise DashboardError(f"dimension {dimension_id} must have a positive integer weight")
        seen.add(dimension_id)
        total += weight
        validated.append({"id": dimension_id, "label": label.strip(), "weight": weight})
    if total != 100:
        raise DashboardError(f"dimension weights total {total}, not 100")
    if seen != set(REQUIRED_DIMENSIONS):
        raise DashboardError("dimension set does not match release-readiness contract")
    return validated


def _validate_cross_store_relative_path(
    value: Any, field: str, *, expected_name: str | None = None
) -> str:
    if not isinstance(value, str) or not value or len(value) > 500:
        raise DashboardError(f"{field} must be a non-empty repository-relative path")
    if "\\" in value or any(ord(character) < 32 for character in value):
        raise DashboardError(f"{field} contains unsafe path characters")
    relative = Path(value)
    if relative.is_absolute() or any(
        part in {"", ".", ".."}
        or re.fullmatch(r"[A-Za-z0-9._-]+", part) is None
        for part in relative.parts
    ):
        raise DashboardError(f"{field} must be a safe repository-relative path")
    if not relative.parts or relative.parts[0] != ".artifacts":
        raise DashboardError(f"{field} must stay under .artifacts")
    if expected_name is not None and relative.name != expected_name:
        raise DashboardError(f"{field} must name {expected_name}")
    return relative.as_posix()


def _validate_cross_store_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DashboardError("cross_store must be an object")
    require_exact_fields(
        value,
        {
            "receipt_schema_version",
            "release_input_index",
            "receipt_directory",
            "required_upload_targets",
            "optional_upload_targets",
        },
        "cross_store",
    )
    if value.get("receipt_schema_version") != CROSS_STORE_RECEIPT_SCHEMA_VERSION:
        raise DashboardError(
            f"cross_store receipt_schema_version must be {CROSS_STORE_RECEIPT_SCHEMA_VERSION}"
        )
    required_upload_targets = value.get("required_upload_targets")
    if required_upload_targets != list(REQUIRED_UPLOAD_TARGET_IDS):
        raise DashboardError("cross_store required upload-target matrix is invalid")
    optional_upload_targets = value.get("optional_upload_targets")
    if optional_upload_targets != list(OPTIONAL_UPLOAD_TARGET_IDS):
        raise DashboardError("cross_store optional upload-target matrix is invalid")
    release_input_index = _validate_cross_store_relative_path(
        value.get("release_input_index"),
        "cross_store release_input_index",
        expected_name="RELEASE_INPUT_INDEX.json",
    )
    receipt_directory = _validate_cross_store_relative_path(
        value.get("receipt_directory"),
        "cross_store receipt_directory",
    )
    if Path(receipt_directory).suffix:
        raise DashboardError("cross_store receipt_directory must be a directory path")
    return {
        "receipt_schema_version": CROSS_STORE_RECEIPT_SCHEMA_VERSION,
        "release_input_index": release_input_index,
        "receipt_directory": receipt_directory,
        "required_upload_targets": list(REQUIRED_UPLOAD_TARGET_IDS),
        "optional_upload_targets": list(OPTIONAL_UPLOAD_TARGET_IDS),
    }


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    require_exact_fields(
        config,
        {
            "schema_version",
            "release",
            "refresh_seconds",
            "max_evidence_age_seconds",
            "cross_store",
            "dimensions",
            "targets",
        },
        "state",
    )
    if config.get("schema_version") != DASHBOARD_SCHEMA_VERSION:
        raise DashboardError(
            f"state schema_version must be {DASHBOARD_SCHEMA_VERSION}"
        )
    if config.get("release") != RELEASE_IDENTITY:
        raise DashboardError(f"state release must be {RELEASE_IDENTITY}")
    refresh_seconds = config.get("refresh_seconds")
    if (
        isinstance(refresh_seconds, bool)
        or not isinstance(refresh_seconds, int)
        or not 2 <= refresh_seconds <= 60
    ):
        raise DashboardError("refresh_seconds must be an integer from 2 to 60")
    max_age = config.get("max_evidence_age_seconds")
    if (
        isinstance(max_age, bool)
        or not isinstance(max_age, int)
        or not 60 <= max_age <= 31 * 24 * 60 * 60
    ):
        raise DashboardError("max_evidence_age_seconds must be 60 seconds to 31 days")

    cross_store = _validate_cross_store_config(config.get("cross_store"))
    dimensions = _validate_dimension_list(config.get("dimensions"))

    targets = config.get("targets")
    if not isinstance(targets, list):
        raise DashboardError("targets must be an array")
    forbidden = {"readiness", "progress", "status", "blockers", "complete", "profile"}
    seen_targets: set[str] = set()
    validated_targets: list[dict[str, Any]] = []
    for target in targets:
        if not isinstance(target, dict):
            raise DashboardError("every target must be an object")
        require_exact_fields(
            target,
            {"id", "label", "group", "upload_targets", "optional_upload_targets"},
            "target",
        )
        forbidden_found = forbidden.intersection(target)
        if forbidden_found:
            raise DashboardError(
                f"target {target.get('id', '?')} contains manual result fields: "
                + ", ".join(sorted(forbidden_found))
            )
        target_id = target.get("id")
        label = target.get("label")
        group = target.get("group")
        upload_targets = target.get("upload_targets")
        optional_upload_targets = target.get("optional_upload_targets")
        if target_id not in REQUIRED_TARGETS:
            raise DashboardError(f"unexpected target id: {target_id}")
        if target_id in seen_targets:
            raise DashboardError(f"duplicate target id: {target_id}")
        if label != REQUIRED_TARGETS[target_id]:
            raise DashboardError(f"target {target_id} label must be {REQUIRED_TARGETS[target_id]}")
        if not isinstance(group, str) or not group.strip():
            raise DashboardError(f"target {target_id} must have a group")
        if upload_targets != list(DASHBOARD_UPLOAD_TARGET_MAP[target_id]):
            raise DashboardError(f"target {target_id} upload target mapping is invalid")
        if optional_upload_targets != list(
            DASHBOARD_OPTIONAL_UPLOAD_TARGET_MAP[target_id]
        ):
            raise DashboardError(
                f"target {target_id} optional upload target mapping is invalid"
            )
        seen_targets.add(target_id)
        validated_targets.append(
            {
                "id": target_id,
                "label": label,
                "group": group.strip(),
                "upload_targets": upload_targets,
                "optional_upload_targets": optional_upload_targets,
            }
        )
    missing = set(REQUIRED_TARGETS) - seen_targets
    extra = seen_targets - set(REQUIRED_TARGETS)
    if missing or extra or len(targets) != len(REQUIRED_TARGETS):
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if extra:
            details.append("extra " + ", ".join(sorted(extra)))
        raise DashboardError("target set mismatch: " + "; ".join(details))

    return {
        "schema_version": DASHBOARD_SCHEMA_VERSION,
        "release": RELEASE_IDENTITY,
        "refresh_seconds": refresh_seconds,
        "max_evidence_age_seconds": max_age,
        "cross_store": cross_store,
        "dimensions": dimensions,
        "targets": validated_targets,
    }


def load_config(path: Path = DEFAULT_CONFIG) -> dict[str, Any]:
    return validate_config(read_json(path))


def config_contract_sha256(config: dict[str, Any]) -> str:
    """Return the hash of the validated, canonical dashboard contract."""
    canonical = json.dumps(
        config,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _stat_key(stat_result: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        stat_result.st_dev,
        stat_result.st_ino,
        stat_result.st_size,
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
    )


def _require_private_local_owner(stat_result: os.stat_result, context: str) -> None:
    if stat_result.st_uid != os.geteuid():
        raise DashboardError(f"{context} must be owned by the dashboard user")
    if stat_result.st_mode & 0o022:
        raise DashboardError(f"{context} must not be group- or other-writable")


def sha256_file(path: Path, stat_result: os.stat_result) -> str:
    cache_key = _stat_key(stat_result)
    with _hash_cache_lock:
        cached = _hash_cache.get(path)
        if cached and cached[:5] == cache_key:
            return cached[5]
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if _stat_key(opened) != cache_key:
            raise DashboardError("artifact changed before hashing")
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
        if _stat_key(os.fstat(handle.fileno())) != cache_key:
            raise DashboardError("artifact changed while hashing")
    value = digest.hexdigest()
    with _hash_cache_lock:
        _hash_cache[path] = (*cache_key, value)
    return value


def _resolve_contained_without_symlinks(
    base: Path, relative: Path, context: str
) -> Path:
    def inspect_components() -> Path:
        try:
            base_stat = base.lstat()
        except OSError as exc:
            raise DashboardError(f"{context} root is missing or unreadable") from exc
        if stat.S_ISLNK(base_stat.st_mode):
            raise DashboardError(f"{context} root must not be a symbolic link")
        if not stat.S_ISDIR(base_stat.st_mode):
            raise DashboardError(f"{context} root must be a directory")
        _require_private_local_owner(base_stat, f"{context} root")

        current = base
        for index, part in enumerate(relative.parts):
            current = current / part
            try:
                component_stat = current.lstat()
            except OSError as exc:
                raise DashboardError(f"{context} path is missing or unreadable") from exc
            if stat.S_ISLNK(component_stat.st_mode):
                raise DashboardError(f"{context} path contains a symbolic link")
            _require_private_local_owner(component_stat, f"{context} path")
            if index < len(relative.parts) - 1 and not stat.S_ISDIR(
                component_stat.st_mode
            ):
                raise DashboardError(f"{context} path has a non-directory component")
        return current

    unresolved = inspect_components()
    try:
        resolved_base = base.resolve(strict=True)
        resolved = unresolved.resolve(strict=True)
        resolved.relative_to(resolved_base)
    except (OSError, ValueError) as exc:
        raise DashboardError(f"{context} path escapes its root") from exc

    confirmed = inspect_components()
    try:
        confirmed_base = base.resolve(strict=True)
        confirmed_resolved = confirmed.resolve(strict=True)
        confirmed_resolved.relative_to(confirmed_base)
    except (OSError, ValueError) as exc:
        raise DashboardError(f"{context} path escapes its root") from exc
    if confirmed_base != resolved_base or confirmed_resolved != resolved:
        raise DashboardError(f"{context} path changed during validation")
    return confirmed_resolved


def _artifact_path(
    artifact: dict[str, Any], evidence_root: Path
) -> tuple[Path, str, str]:
    root_name = artifact.get("root", "evidence")
    raw_path = artifact.get("path")
    if root_name not in {"repo", "evidence"}:
        raise DashboardError("artifact root must be repo or evidence")
    if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 500:
        raise DashboardError("artifact path must be a non-empty relative path")
    if any(ord(char) < 32 for char in raw_path):
        raise DashboardError("artifact path contains control characters")
    relative = Path(raw_path)
    if relative.is_absolute() or "\\" in raw_path or any(
        part in {"", ".", ".."} or not SAFE_RELATIVE_PART_RE.fullmatch(part)
        for part in relative.parts
    ):
        raise DashboardError("absolute artifact paths are not accepted")
    _reject_non_evidence_path(relative)
    if any(
        marker in part.lower()
        for part in relative.parts
        for marker in ("secret", "credential", "keystore", "private", "token", "password")
    ):
        raise DashboardError("artifact path may expose sensitive material")
    base = REPO_ROOT if root_name == "repo" else evidence_root
    resolved = _resolve_contained_without_symlinks(
        base, relative, f"artifact {root_name}"
    )
    return resolved, root_name, relative.as_posix()


def validate_artifact(artifact: Any, evidence_root: Path) -> dict[str, Any]:
    if not isinstance(artifact, dict):
        raise DashboardError("artifact entry must be an object")
    require_exact_fields(artifact, {"root", "path", "sha256"}, "artifact")
    expected_hash = artifact.get("sha256")
    if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
        raise DashboardError("artifact sha256 must contain 64 hexadecimal characters")
    resolved, root_name, relative_path = _artifact_path(artifact, evidence_root)
    try:
        stat_result = resolved.stat()
    except OSError as exc:
        raise DashboardError("artifact is not readable") from exc
    if not stat.S_ISREG(stat_result.st_mode) or stat_result.st_size <= 0:
        raise DashboardError("artifact must be a non-empty regular file")
    if stat_result.st_nlink != 1:
        raise DashboardError("artifact must not be hard-linked")
    _require_private_local_owner(stat_result, "artifact")
    actual_hash = sha256_file(resolved, stat_result)
    if actual_hash != expected_hash.lower():
        raise DashboardError("artifact SHA-256 mismatch")
    return {
        "root": root_name,
        "path": relative_path,
        "sha256": actual_hash,
        "bytes": stat_result.st_size,
        "modified_at": iso_utc(datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)),
    }


def _reject_non_evidence_path(relative: Path) -> None:
    lowered_parts = [part.lower() for part in relative.parts]
    lowered_name = relative.name.lower()
    if any(part in {"handoff", "handoffs", "blueprint", "blueprints"} for part in lowered_parts):
        raise DashboardError("handoff and blueprint claims are not release evidence")
    if "handoff" in lowered_name:
        raise DashboardError("handoff claims are not release evidence")
    if any(part in {"plan", "plans"} for part in lowered_parts):
        raise DashboardError("plan documents are not release evidence")
    if any(
        part
        in {
            "test",
            "tests",
            "testing",
            "testdata",
            "test-data",
            "unittest",
            "unittests",
            "pytest",
            "coverage",
        }
        for part in lowered_parts
    ):
        raise DashboardError("unit-test output is not release evidence")
    if "docs" in lowered_parts:
        raise DashboardError("documentation is not release evidence")
    if any(part in {"upload-receipts", "release-inputs"} for part in lowered_parts):
        raise DashboardError("cross-store receipts are not dashboard dimension evidence")
    if any(part in FORBIDDEN_EVIDENCE_PATH_PARTS for part in lowered_parts):
        raise DashboardError("path is not release evidence")
    if any(marker in lowered_name for marker in FORBIDDEN_EVIDENCE_NAME_MARKERS):
        raise DashboardError("plans, handoffs, and unit-test files are not release evidence")
    if lowered_name.startswith("test_") or lowered_name.endswith("_test.py"):
        raise DashboardError("unit-test output is not release evidence")
    if relative.suffix.lower() in FORBIDDEN_EVIDENCE_SUFFIXES:
        raise DashboardError("documentation is not release evidence")


def _claim_artifact_hash(
    claims: dict[str, tuple[str, str]],
    digest: str,
    target_id: str,
    dimension_id: str,
) -> None:
    owner = claims.get(digest)
    if owner is not None and owner != (target_id, dimension_id):
        raise DashboardError(
            "artifact hash is reused across targets or evidence dimensions"
        )
    claims[digest] = (target_id, dimension_id)


def _store_dimensions_verified(dimensions: list[dict[str, Any]]) -> bool:
    store_items = [
        dimension
        for dimension in dimensions
        if dimension.get("id") in STORE_DIMENSION_IDS
    ]
    return len(store_items) == len(STORE_DIMENSION_IDS) and all(
        dimension.get("status") == "verified" for dimension in store_items
    )


def _dimension_score(dimensions: list[dict[str, Any]], dimension_ids: frozenset[str]) -> int:
    return sum(
        int(dimension["weight"])
        for dimension in dimensions
        if dimension.get("id") in dimension_ids and dimension.get("status") == "verified"
    )


def _dimension_result(
    dimension: dict[str, Any],
    raw_check: Any,
    evidence_contract: tuple[str, str],
    evidence_root: Path,
    now: datetime,
    max_age: timedelta,
    receipt_generated_at: datetime | None,
    target_id: str,
    artifact_claims: dict[str, tuple[str, str]],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": dimension["id"],
        "label": dimension["label"],
        "weight": dimension["weight"],
        "status": "missing",
        "reason": "no evidence check supplied",
        "observed_at": None,
        "producer": None,
        "evidence_type": evidence_contract[0],
        "summary_code": None,
        "artifacts": [],
    }
    if raw_check is None:
        return result
    try:
        if not isinstance(raw_check, dict):
            raise DashboardError("check must be an object")
        require_exact_fields(
            raw_check,
            {
                "status",
                "observed_at",
                "producer",
                "evidence_type",
                "summary_code",
                "artifacts",
            },
            "check",
        )
        check_status = raw_check.get("status")
        if check_status not in {"pass", "fail"}:
            raise DashboardError("check status must be pass or fail")
        producer = raw_check.get("producer")
        if (
            not isinstance(producer, str)
            or not PRODUCER_RE.fullmatch(producer)
            or producer.startswith(SECRET_LIKE_PRODUCER_PREFIXES)
        ):
            raise DashboardError(
                "check producer must be a safe lowercase identifier up to 32 characters"
            )
        expected_evidence_type, expected_producer = evidence_contract
        if raw_check.get("evidence_type") != expected_evidence_type:
            raise DashboardError(
                f"check evidence_type must be {expected_evidence_type}"
            )
        if producer != expected_producer:
            raise DashboardError(f"check producer must be {expected_producer}")
        observed = parse_utc(raw_check.get("observed_at"), "check observed_at")
        if observed > now + FUTURE_SKEW:
            raise DashboardError("check observed_at is in the future")
        if receipt_generated_at is not None and observed > receipt_generated_at + FUTURE_SKEW:
            raise DashboardError("check observed_at is later than receipt generation")
        summary_code = raw_check.get("summary_code")
        if not isinstance(summary_code, str) or not ID_RE.fullmatch(summary_code):
            raise DashboardError("check summary_code must be a safe identifier")
        artifacts = raw_check.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise DashboardError("check must reference at least one artifact")
        validated_artifacts = [
            validate_artifact(artifact, evidence_root) for artifact in artifacts
        ]
        artifact_times = [
            parse_utc(artifact["modified_at"], "artifact modified_at")
            for artifact in validated_artifacts
        ]
        if any(modified > now + FUTURE_SKEW for modified in artifact_times):
            raise DashboardError("artifact modified_at is in the future")
        if any(modified > observed + FUTURE_SKEW for modified in artifact_times):
            raise DashboardError("artifact changed after evidence observation")
        claimed: set[str] = set()
        for artifact in validated_artifacts:
            digest = str(artifact["sha256"]).lower()
            if digest in claimed:
                raise DashboardError("check repeats an artifact hash")
            claimed.add(digest)
            _claim_artifact_hash(
                artifact_claims,
                digest,
                target_id,
                str(dimension["id"]),
            )
        result.update(
            {
                "observed_at": iso_utc(observed),
                "producer": producer,
                "evidence_type": expected_evidence_type,
                "summary_code": summary_code,
                "artifacts": validated_artifacts,
            }
        )
        if now - observed > max_age or any(
            now - modified > max_age for modified in artifact_times
        ):
            result.update(
                status="stale",
                reason="evidence observation or referenced artifact is older than the freshness window",
            )
        elif check_status == "fail":
            result.update(status="failed", reason="evidence producer reported failure")
        else:
            result.update(status="verified", reason="fresh evidence and artifact hashes verified")
    except DashboardError as exc:
        result.update(status="invalid", reason=str(exc))
    return result


def _blocker_result(
    raw_blocker: Any,
    evidence_root: Path,
    now: datetime,
    max_age: timedelta,
    receipt_generated_at: datetime | None,
    target_id: str,
    artifact_claims: dict[str, tuple[str, str]],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": "invalid",
        "kind": "external",
        "status": "invalid",
        "reason": "invalid blocker evidence",
        "observed_at": None,
        "producer": None,
        "evidence_type": OPEN_BLOCKER_CONTRACT[0],
        "summary_code": None,
        "artifacts": [],
    }
    try:
        if not isinstance(raw_blocker, dict):
            raise DashboardError("blocker must be an object")
        require_exact_fields(
            raw_blocker,
            {
                "id",
                "kind",
                "status",
                "observed_at",
                "producer",
                "evidence_type",
                "summary_code",
                "artifacts",
            },
            "blocker",
        )
        blocker_id = raw_blocker.get("id")
        kind = raw_blocker.get("kind")
        if not isinstance(blocker_id, str) or not ID_RE.fullmatch(blocker_id):
            raise DashboardError("blocker id must be a safe identifier")
        if kind not in BLOCKER_KINDS:
            raise DashboardError("blocker kind must be owner or external")
        result.update(id=blocker_id, kind=kind)
        check = _dimension_result(
            {"id": blocker_id, "label": blocker_id, "weight": 0},
            {
                key: raw_blocker[key]
                for key in (
                    "status",
                    "observed_at",
                    "producer",
                    "evidence_type",
                    "summary_code",
                    "artifacts",
                )
            },
            OPEN_BLOCKER_CONTRACT,
            evidence_root,
            now,
            max_age,
            receipt_generated_at,
            target_id,
            artifact_claims,
        )
        result.update(
            status=check["status"],
            reason=check["reason"],
            observed_at=check["observed_at"],
            producer=check["producer"],
            evidence_type=check["evidence_type"],
            summary_code=check.get("summary_code"),
            artifacts=check["artifacts"],
        )
        if check["status"] == "verified":
            result["status"] = "open"
            result["reason"] = "fresh blocker evidence is open"
    except DashboardError as exc:
        result["reason"] = str(exc)
    return result


def _cross_store_receipt_role(target_id: str) -> str:
    return "optional" if target_id in OPTIONAL_UPLOAD_TARGET_IDS else "required"


def _cross_store_snapshot_receipt(
    target_id: str,
    receipt_relative: str,
    *,
    status: str,
    reason: str,
    verified_at: str | None = None,
    receipt_sha256: str | None = None,
    artifact_sha256: str | None = None,
) -> dict[str, Any]:
    if status not in CROSS_STORE_RECEIPT_STATUSES:
        raise DashboardError(f"{target_id} cross-store status is not in the contract")
    return {
        "target_id": target_id,
        "receipt": receipt_relative,
        "receipt_schema_version": CROSS_STORE_RECEIPT_SCHEMA_VERSION,
        "release": RELEASE_IDENTITY,
        "status": status,
        "verified_at": verified_at,
        "receipt_sha256": receipt_sha256,
        "artifact_sha256": artifact_sha256,
        "reason": reason,
    }


def _cross_store_status_counts(receipts: list[dict[str, Any]]) -> dict[str, int]:
    counts = {status: 0 for status in CROSS_STORE_RECEIPT_STATUSES}
    for receipt in receipts:
        status = receipt.get("status")
        if status not in counts:
            raise DashboardError("cross-store receipt status is outside the contract")
        counts[str(status)] += 1
    if sum(counts.values()) != len(receipts):
        raise DashboardError("cross-store status counts do not cover every receipt")
    return counts


def _upload_receipt_present(receipt_path: Path) -> bool:
    try:
        receipt_path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise DashboardError("upload receipt is unreadable") from exc
    return True


def _load_cross_store_module() -> Any:
    global _cross_store_module
    with _cross_store_module_lock:
        if _cross_store_module is None:
            tools_root = REPO_ROOT / "tools"
            tools_root_string = str(tools_root)
            if tools_root_string not in sys.path:
                sys.path.insert(0, tools_root_string)
            try:
                module = importlib.import_module("cross_store_upload_readiness")
                module._assert_target_contract()
            except Exception as exc:
                raise DashboardError(
                    "authoritative cross-store verifier is unavailable"
                ) from exc
            module_required_target_ids = tuple(
                target.target_id for target in module.REQUIRED_UPLOAD_TARGETS
            )
            module_optional_target_ids = tuple(
                target.target_id for target in module.OPTIONAL_UPLOAD_TARGETS
            )
            if (
                module.TARGET_RECEIPT_SCHEMA_VERSION
                != CROSS_STORE_RECEIPT_SCHEMA_VERSION
                or module.TARGET_RECEIPT_CONTRACT != CROSS_STORE_RECEIPT_CONTRACT
                or module_required_target_ids != REQUIRED_UPLOAD_TARGET_IDS
                or module_optional_target_ids != OPTIONAL_UPLOAD_TARGET_IDS
                or set(module.TARGET_BY_ID) != set(KNOWN_CROSS_STORE_TARGET_IDS)
            ):
                raise DashboardError(
                    "authoritative cross-store verifier contract does not match the dashboard"
                )
            _cross_store_module = module
        return _cross_store_module


def run_live_cross_store_verification(
    repo_root: Path,
    release_input_index: Path,
    target_id: str,
    receipt_path: Path,
    now: datetime,
    evidence_dir: Path,
) -> dict[str, Any]:
    """Sync-phase only: execute current custody/signing gates into evidence_dir."""

    if target_id not in KNOWN_CROSS_STORE_TARGET_IDS:
        raise DashboardError(f"unexpected cross-store upload target: {target_id}")
    receipt_role = _cross_store_receipt_role(target_id)
    try:
        receipt_path.lstat()
    except FileNotFoundError as exc:
        raise CrossStoreReceiptMissing(
            f"{receipt_role} {target_id} schema-v2 receipt is missing"
        ) from exc
    except OSError as exc:
        raise DashboardError(
            f"{receipt_role} {target_id} receipt is unreadable"
        ) from exc

    module = _load_cross_store_module()
    try:
        verified = module.verify_target_receipt_current(
            repo_root,
            release_input_index,
            target_id,
            receipt_path,
            now=now,
            evidence_dir=evidence_dir,
        )
    except Exception as exc:
        reason = str(exc).replace(str(repo_root), "<repo>")
        raise DashboardError(
            f"{target_id} schema-v2 receipt verification failed: {reason}"
        ) from exc
    if not isinstance(verified, dict):
        raise DashboardError(f"{target_id} verifier returned malformed evidence")
    expected_receipt = receipt_path.relative_to(repo_root).as_posix()
    verified_at = parse_utc(
        verified.get("verified_utc"), f"{target_id} cross-store verified_utc"
    )
    receipt_sha256 = verified.get("receipt_sha256")
    artifact = verified.get("artifact")
    if (
        verified.get("release") != RELEASE_IDENTITY
        or verified.get("receipt_path") != expected_receipt
        or not isinstance(receipt_sha256, str)
        or SHA256_RE.fullmatch(receipt_sha256) is None
        or not isinstance(artifact, dict)
        or not isinstance(artifact.get("sha256"), str)
        or SHA256_RE.fullmatch(str(artifact.get("sha256"))) is None
    ):
        raise DashboardError(
            f"{target_id} verified receipt binding does not match the canonical release"
        )
    return _cross_store_snapshot_receipt(
        target_id,
        expected_receipt,
        status="verified",
        reason="authoritative schema-v2 receipt and current artifact gates verified",
        verified_at=iso_utc(verified_at),
        receipt_sha256=receipt_sha256.lower(),
        artifact_sha256=str(artifact["sha256"]).lower(),
    )


def _reverify_cached_cross_store_evidence(
    repo_root: Path,
    release_input_index: Path,
    target_id: str,
    receipt_path: Path,
    now: datetime,
    expected_receipt: str,
    expected_receipt_sha256: str,
    expected_artifact_sha256: str,
) -> None:
    """Rehash bound cache evidence. Never executes live custody/signing gates."""

    if not _upload_receipt_present(receipt_path):
        raise CrossStoreReceiptMissing(
            f"{_cross_store_receipt_role(target_id)} {target_id} "
            "schema-v2 receipt is missing"
        )
    module = _load_cross_store_module()
    try:
        live_receipt_sha = module._stable_identity(
            receipt_path, f"{target_id} upload receipt"
        )[2]
    except DashboardError:
        raise
    except Exception as exc:
        reason = str(exc).replace(str(repo_root), "<repo>")
        raise DashboardError(
            f"{target_id} cached receipt could not be rehashed: {reason}"
        ) from exc
    if (
        not isinstance(live_receipt_sha, str)
        or SHA256_RE.fullmatch(live_receipt_sha) is None
        or live_receipt_sha.lower() != expected_receipt_sha256.lower()
    ):
        raise DashboardError(
            f"{target_id} cached receipt hash does not match current file"
        )
    try:
        payload = module._load_json(receipt_path, f"{target_id} upload receipt")
        artifact = payload.get("artifact")
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            raise DashboardError(
                f"{target_id} cached receipt does not bind an artifact"
            )
        freeze_mod = getattr(module, "freeze", None)
        secure_repo_path = getattr(freeze_mod, "secure_repo_path", None)
        if not callable(secure_repo_path):
            raise DashboardError(
                "authoritative cross-store path primitive is unavailable"
            )
        artifact_path = secure_repo_path(
            repo_root,
            Path(str(artifact["path"])),
            f"{target_id} artifact",
            must_exist=True,
        )
        live_artifact_sha = module._stable_identity(
            artifact_path, f"{target_id} artifact"
        )[2]
    except DashboardError:
        raise
    except Exception as exc:
        reason = str(exc).replace(str(repo_root), "<repo>")
        raise DashboardError(
            f"{target_id} cached artifact could not be rehashed: {reason}"
        ) from exc
    if (
        not isinstance(live_artifact_sha, str)
        or SHA256_RE.fullmatch(live_artifact_sha) is None
        or live_artifact_sha.lower() != expected_artifact_sha256.lower()
    ):
        raise DashboardError(
            f"{target_id} cached artifact hash does not match current file"
        )
    try:
        verified = module._verify_target_receipt(
            repo_root,
            release_input_index,
            target_id,
            receipt_path,
            now=now,
        )
    except DashboardError:
        raise
    except Exception as exc:
        reason = str(exc).replace(str(repo_root), "<repo>")
        raise DashboardError(
            f"{target_id} cached verification did not reverify: {reason}"
        ) from exc
    if not isinstance(verified, dict):
        raise DashboardError(f"{target_id} verifier returned malformed evidence")
    receipt_sha256 = verified.get("receipt_sha256")
    artifact_binding = verified.get("artifact")
    if (
        verified.get("release") != RELEASE_IDENTITY
        or verified.get("receipt_path") != expected_receipt
        or not isinstance(receipt_sha256, str)
        or SHA256_RE.fullmatch(receipt_sha256) is None
        or receipt_sha256.lower() != expected_receipt_sha256.lower()
        or not isinstance(artifact_binding, dict)
        or not isinstance(artifact_binding.get("sha256"), str)
        or SHA256_RE.fullmatch(str(artifact_binding.get("sha256"))) is None
        or str(artifact_binding.get("sha256")).lower()
        != expected_artifact_sha256.lower()
    ):
        raise DashboardError(
            f"{target_id} cached verification binding does not match current files"
        )


def _snapshot_receipt_from_cache_record(
    target_id: str,
    receipt_relative: str,
    record: Any,
    now: datetime,
    max_age: timedelta,
    repo_root: Path,
    release_input_index: str,
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise DashboardError(f"{target_id} cached verification record is malformed")
    require_exact_fields(
        record,
        {
            "target_id",
            "receipt",
            "receipt_schema_version",
            "release",
            "status",
            "verified_at",
            "receipt_sha256",
            "artifact_sha256",
            "reason",
        },
        f"{target_id} cached verification",
    )
    if (
        record.get("target_id") != target_id
        or record.get("receipt") != receipt_relative
        or record.get("receipt_schema_version") != CROSS_STORE_RECEIPT_SCHEMA_VERSION
        or record.get("release") != RELEASE_IDENTITY
        or record.get("status") not in CROSS_STORE_RECEIPT_STATUSES
        or not isinstance(record.get("reason"), str)
        or not record.get("reason")
    ):
        raise DashboardError(
            f"{target_id} cached verification binding does not match the canonical release"
        )
    status = str(record["status"])
    if status in {"verified", "stale"}:
        if (
            not isinstance(record.get("receipt_sha256"), str)
            or SHA256_RE.fullmatch(str(record.get("receipt_sha256"))) is None
            or not isinstance(record.get("artifact_sha256"), str)
            or SHA256_RE.fullmatch(str(record.get("artifact_sha256"))) is None
        ):
            raise DashboardError(f"{target_id} cached verification hashes are invalid")
        try:
            _reverify_cached_cross_store_evidence(
                repo_root,
                repo_root / release_input_index,
                target_id,
                repo_root / receipt_relative,
                now,
                receipt_relative,
                str(record["receipt_sha256"]),
                str(record["artifact_sha256"]),
            )
        except CrossStoreReceiptMissing as suc:
            return _cross_store_snapshot_receipt(
                target_id,
                receipt_relative,
                status="missing",
                reason=str(suc),
            )
        except DashboardError as suc:
            return _cross_store_snapshot_receipt(
                target_id,
                receipt_relative,
                status="invalid",
                reason=str(suc).replace(str(repo_root), "<repo>"),
            )
        verified_at = parse_utc(
            record.get("verified_at"), f"{target_id} cached verified_at"
        )
        if verified_at > now + FUTURE_SKEW:
            return _cross_store_snapshot_receipt(
                target_id,
                receipt_relative,
                status="invalid",
                reason="cross-store receipt is future-dated",
            )
        if now - verified_at > max_age or status == "stale":
            return _cross_store_snapshot_receipt(
                target_id,
                receipt_relative,
                status="stale",
                reason="cross-store receipt is older than the dashboard freshness window",
                verified_at=iso_utc(verified_at),
                receipt_sha256=str(record["receipt_sha256"]).lower(),
                artifact_sha256=str(record["artifact_sha256"]).lower(),
            )
        return _cross_store_snapshot_receipt(
            target_id,
            receipt_relative,
            status="verified",
            reason=str(record["reason"]),
            verified_at=iso_utc(verified_at),
            receipt_sha256=str(record["receipt_sha256"]).lower(),
            artifact_sha256=str(record["artifact_sha256"]).lower(),
        )
    if record.get("verified_at") is not None or record.get("receipt_sha256") is not None:
        raise DashboardError(f"{target_id} cached non-verified record is not fail-closed")
    if record.get("artifact_sha256") is not None:
        raise DashboardError(f"{target_id} cached non-verified record is not fail-closed")
    return _cross_store_snapshot_receipt(
        target_id,
        receipt_relative,
        status=status if status != "unavailable" else "invalid",
        reason=str(record["reason"]),
    )


def _read_cross_store_cache(
    cache_path: Path,
    now: datetime,
    max_age: timedelta,
    receipt_directory: str,
    release_input_index: str,
    repo_root: Path,
) -> dict[str, dict[str, Any]] | None:
    """Read bounded immutable cached evidence. Never creates the cache path.

    Verified and stale records must still rehash the bound receipt and artifact
    through the authoritative verifier primitives. Live gates are never executed.
    """

    try:
        cache_stat = cache_path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DashboardError("cached cross-store evidence is unreadable") from exc
    if stat.S_ISLNK(cache_stat.st_mode):
        raise DashboardError("cached cross-store evidence must not be a symbolic link")
    if not stat.S_ISREG(cache_stat.st_mode):
        raise DashboardError("cached cross-store evidence must be a regular file")
    if cache_stat.st_nlink != 1:
        raise DashboardError("cached cross-store evidence must not be hard-linked")
    _require_private_local_owner(cache_stat, "cached cross-store evidence")
    record = read_json(cache_path)
    require_exact_fields(
        record,
        {
            "schema_version",
            "release",
            "generated_at",
            "receipt_directory",
            "release_input_index",
            "receipts",
        },
        "cached cross-store evidence",
    )
    generated_at = parse_utc(record.get("generated_at"), "cached cross-store generated_at")
    receipts = record.get("receipts")
    if (
        record.get("schema_version") != CROSS_STORE_CACHE_SCHEMA_VERSION
        or record.get("release") != RELEASE_IDENTITY
        or record.get("receipt_directory") != receipt_directory
        or record.get("release_input_index") != release_input_index
        or not isinstance(receipts, dict)
        or set(receipts) != set(KNOWN_CROSS_STORE_TARGET_IDS)
    ):
        raise DashboardError("cached cross-store evidence contract is invalid")
    if generated_at > now + FUTURE_SKEW:
        raise DashboardError("cached cross-store evidence is future-dated")
    if now - generated_at > max_age:
        raise DashboardError("cached cross-store evidence is stale")
    loaded: dict[str, dict[str, Any]] = {}
    for target_id in KNOWN_CROSS_STORE_TARGET_IDS:
        receipt_relative = f"{receipt_directory}/{target_id}.json"
        loaded[target_id] = _snapshot_receipt_from_cache_record(
            target_id,
            receipt_relative,
            receipts[target_id],
            now,
            max_age,
            repo_root,
            release_input_index,
        )
    return loaded


def materialize_cross_store_cache(
    repo_root: Path,
    cache_path: Path,
    cross_store: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Sync-phase only. Execute gates and write bounded immutable cached evidence."""

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise DashboardError("cache time must be timezone-aware")
    current = current.astimezone(timezone.utc)
    receipt_directory = cross_store["receipt_directory"]
    release_input_index = Path(cross_store["release_input_index"])
    index_path = repo_root / release_input_index
    gate_root = repo_root / ".artifacts" / "dashboard" / "cross-store-gate-tmp"
    if gate_root.exists() or gate_root.is_symlink():
        shutil.rmtree(gate_root, ignore_errors=False)
    receipts: dict[str, dict[str, Any]] = {}
    try:
        for target_id in KNOWN_CROSS_STORE_TARGET_IDS:
            receipt_relative = f"{receipt_directory}/{target_id}.json"
            receipt_path = repo_root / receipt_relative
            if not _upload_receipt_present(receipt_path):
                receipts[target_id] = _cross_store_snapshot_receipt(
                    target_id,
                    receipt_relative,
                    status="missing",
                    reason=(
                        f"{_cross_store_receipt_role(target_id)} {target_id} "
                        "schema-v2 receipt is missing"
                    ),
                )
                continue
            evidence_dir = gate_root / target_id
            try:
                receipts[target_id] = run_live_cross_store_verification(
                    repo_root,
                    index_path,
                    target_id,
                    receipt_path,
                    current,
                    evidence_dir,
                )
            except CrossStoreReceiptMissing as exc:
                receipts[target_id] = _cross_store_snapshot_receipt(
                    target_id,
                    receipt_relative,
                    status="missing",
                    reason=str(exc),
                )
            except DashboardError as exc:
                receipts[target_id] = _cross_store_snapshot_receipt(
                    target_id,
                    receipt_relative,
                    status="invalid",
                    reason=str(exc).replace(str(repo_root), "<repo>"),
                )
    finally:
        if gate_root.exists() or gate_root.is_symlink():
            shutil.rmtree(gate_root, ignore_errors=True)
    payload = {
        "schema_version": CROSS_STORE_CACHE_SCHEMA_VERSION,
        "release": RELEASE_IDENTITY,
        "generated_at": iso_utc(current),
        "receipt_directory": receipt_directory,
        "release_input_index": cross_store["release_input_index"],
        "receipts": receipts,
    }
    write_json_atomic(cache_path, payload)
    cache_path.chmod(0o400)
    return payload


def verify_cross_store_upload_receipt(
    repo_root: Path,
    release_input_index: Path,
    target_id: str,
    receipt_path: Path,
    now: datetime,
) -> dict[str, Any]:
    """Read-only cached-evidence consumer. Never executes gates or creates directories.

    Snapshot rendering and HTTP GET use this path. Live custody/signing execution
    belongs to materialize_cross_store_cache during an explicit local sync.
    """

    del release_input_index
    del now
    if target_id not in KNOWN_CROSS_STORE_TARGET_IDS:
        raise DashboardError(f"unexpected cross-store upload target: {target_id}")
    receipt_role = _cross_store_receipt_role(target_id)
    if not _upload_receipt_present(receipt_path):
        raise CrossStoreReceiptMissing(
            f"{receipt_role} {target_id} schema-v2 receipt is missing"
        )
    raise DashboardError(f"{target_id} cached verification evidence is missing")


def _apply_cross_store_freshness(
    result: dict[str, Any],
    target_id: str,
    receipt_relative: str,
    now: datetime,
    max_age: timedelta,
) -> dict[str, Any]:
    if result.get("status") != "verified":
        return result
    verified_at = parse_utc(
        result.get("verified_at"), f"{target_id} cross-store verified_at"
    )
    if verified_at > now + FUTURE_SKEW:
        return _cross_store_snapshot_receipt(
            target_id,
            receipt_relative,
            status="invalid",
            reason="cross-store receipt is future-dated",
        )
    if now - verified_at > max_age:
        return {
            **result,
            "status": "stale",
            "reason": "cross-store receipt is older than the dashboard freshness window",
        }
    return result


def _cross_store_receipt_result(
    target_id: str,
    cross_store: dict[str, Any],
    repo_root: Path,
    now: datetime,
    max_age: timedelta,
    cache: dict[str, dict[str, Any]],
    cached_receipts: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if target_id in cache:
        return dict(cache[target_id])
    receipt_relative = (
        Path(cross_store["receipt_directory"]) / f"{target_id}.json"
    ).as_posix()
    receipt_path = repo_root / receipt_relative
    index_path = repo_root / cross_store["release_input_index"]
    try:
        if cached_receipts is not None and target_id in cached_receipts:
            result = dict(cached_receipts[target_id])
        else:
            result = verify_cross_store_upload_receipt(
                repo_root,
                index_path,
                target_id,
                receipt_path,
                now,
            )
        result = _apply_cross_store_freshness(
            result, target_id, receipt_relative, now, max_age
        )
    except CrossStoreReceiptMissing as exc:
        result = _cross_store_snapshot_receipt(
            target_id,
            receipt_relative,
            status="missing",
            reason=str(exc),
        )
    except DashboardError as exc:
        result = _cross_store_snapshot_receipt(
            target_id,
            receipt_relative,
            status="invalid",
            reason=str(exc).replace(str(repo_root), "<repo>"),
        )
    cache[target_id] = dict(result)
    return result


def _unavailable_cross_store_receipt(
    target_id: str, receipt_relative: str, reason: str, status: str
) -> dict[str, Any]:
    return {
        "target_id": target_id,
        "receipt": receipt_relative,
        "receipt_schema_version": CROSS_STORE_RECEIPT_SCHEMA_VERSION,
        "release": RELEASE_IDENTITY,
        "status": status,
        "verified_at": None,
        "receipt_sha256": None,
        "artifact_sha256": None,
        "reason": reason,
    }


def _reject_reused_cross_store_receipts(cache: dict[str, dict[str, Any]]) -> None:
    receipt_owners: dict[str, list[str]] = {}
    artifact_owners: dict[str, list[str]] = {}
    for target_id, receipt in cache.items():
        if receipt.get("status") not in {"verified", "stale"}:
            continue
        receipt_sha = receipt.get("receipt_sha256")
        artifact_sha = receipt.get("artifact_sha256")
        if isinstance(receipt_sha, str) and SHA256_RE.fullmatch(receipt_sha):
            receipt_owners.setdefault(receipt_sha.lower(), []).append(target_id)
        if isinstance(artifact_sha, str) and SHA256_RE.fullmatch(artifact_sha):
            artifact_owners.setdefault(artifact_sha.lower(), []).append(target_id)
    reused_ids: set[str] = set()
    for owners in (*receipt_owners.values(), *artifact_owners.values()):
        if len(set(owners)) > 1:
            reused_ids.update(owners)
    for target_id in reused_ids:
        current = cache[target_id]
        cache[target_id] = _unavailable_cross_store_receipt(
            target_id,
            str(current["receipt"]),
            "cross-store receipt or artifact hash is reused across upload targets",
            "invalid",
        )


def _cross_store_target_result(
    target: dict[str, Any],
    cross_store: dict[str, Any],
    repo_root: Path,
    now: datetime,
    max_age: timedelta,
    cache: dict[str, dict[str, Any]],
    cached_receipts: dict[str, dict[str, Any]] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    upload_targets = target["upload_targets"]
    if not upload_targets:
        return "not_applicable", []
    receipts = [
        _cross_store_receipt_result(
            target_id,
            cross_store,
            repo_root,
            now,
            max_age,
            cache,
            cached_receipts,
        )
        for target_id in upload_targets
    ]
    statuses = [receipt["status"] for receipt in receipts]
    if statuses and all(status == "verified" for status in statuses):
        return "verified", receipts
    if any(status == "invalid" for status in statuses):
        return "invalid", receipts
    if any(status == "stale" for status in statuses):
        return "stale", receipts
    if any(status == "verified" for status in statuses):
        return "partial", receipts
    return "missing", receipts


def _operator_cross_store_status(receipts: list[dict[str, Any]], applies: bool) -> str:
    if not applies:
        return "not_applicable"
    statuses = [receipt["status"] for receipt in receipts]
    if statuses and all(status == "unavailable" for status in statuses):
        return "unavailable"
    if statuses and all(status == "verified" for status in statuses):
        return "verified"
    if any(status == "invalid" for status in statuses):
        return "invalid"
    if any(status == "stale" for status in statuses):
        return "stale"
    if any(status == "verified" for status in statuses):
        return "partial"
    if any(status == "unavailable" for status in statuses):
        return "unavailable"
    return "missing"


def _derive_status_and_readiness(
    technical_readiness: int,
    dimension_statuses: set[str],
    blocker_audit_status: str,
    blocker_results: list[dict[str, Any]],
    cross_store_status: str,
    store_dimensions_verified: bool,
) -> tuple[int, str]:
    cross_store_verified = cross_store_status in {"verified", "not_applicable"}
    readiness = (
        technical_readiness
        if blocker_audit_status == "verified"
        and not blocker_results
        and cross_store_verified
        and store_dimensions_verified
        else 0
    )
    if (
        technical_readiness == 100
        and dimension_statuses == {"verified"}
        and blocker_audit_status == "verified"
        and not blocker_results
        and cross_store_verified
    ):
        status = "ready"
    elif blocker_results:
        status = "blocked"
    elif blocker_audit_status == "invalid":
        status = "invalid"
    elif blocker_audit_status == "failed":
        status = "blocked"
    elif blocker_audit_status == "stale":
        status = "stale"
    elif cross_store_status == "invalid":
        status = "invalid"
    elif cross_store_status == "stale":
        status = "stale"
    elif "invalid" in dimension_statuses:
        status = "invalid"
    elif "failed" in dimension_statuses:
        status = "blocked"
    elif "stale" in dimension_statuses:
        status = "stale"
    elif cross_store_status == "partial":
        status = "partial"
    elif cross_store_status == "missing" and technical_readiness > 0:
        status = "partial"
    elif readiness > 0:
        status = "partial"
    else:
        status = "unverified"
    return readiness, status


def _operator_card(
    target: dict[str, Any],
    target_id: str,
    label: str,
    upload_targets: tuple[str, ...],
    receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    cross_store_status = _operator_cross_store_status(
        receipts, bool(upload_targets)
    )
    if target["status"] == "unavailable":
        readiness, status = 0, "unavailable"
    else:
        readiness, status = _derive_status_and_readiness(
            target["technical_readiness"],
            {dimension["status"] for dimension in target["dimensions"]},
            target["blocker_audit"]["status"],
            target["blockers"],
            cross_store_status,
            _store_dimensions_verified(list(target["dimensions"])),
        )
    return {
        **target,
        "id": target_id,
        "label": label,
        "upload_targets": list(upload_targets),
        "optional_upload_targets": list(
            OPERATOR_OPTIONAL_UPLOAD_TARGET_MAP[target_id]
        ),
        "cross_store_status": cross_store_status,
        "cross_store_receipts": receipts,
        "readiness": readiness,
        "status": status,
    }


def _split_operator_targets(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    operator_targets: list[dict[str, Any]] = []
    for target in targets:
        if target["id"] != "chrome-extension":
            operator_targets.append(target)
            continue
        receipts_by_id = {
            receipt["target_id"]: receipt for receipt in target["cross_store_receipts"]
        }
        chrome_ids = OPERATOR_UPLOAD_TARGET_MAP["chrome-extension"]
        edge_ids = OPERATOR_UPLOAD_TARGET_MAP[OPERATOR_EDGE_TARGET_ID]
        try:
            chrome_receipts = [receipts_by_id[target_id] for target_id in chrome_ids]
            edge_receipts = [receipts_by_id[target_id] for target_id in edge_ids]
        except KeyError as exc:
            raise DashboardError(
                "Chrome scored card is missing a mapped Chrome or Edge receipt"
            ) from exc
        operator_targets.append(
            _operator_card(
                target,
                "chrome-extension",
                REQUIRED_TARGETS["chrome-extension"],
                chrome_ids,
                chrome_receipts,
            )
        )
        operator_targets.append(
            _operator_card(
                target,
                OPERATOR_EDGE_TARGET_ID,
                OPERATOR_EDGE_LABEL,
                edge_ids,
                edge_receipts,
            )
        )
    represented = {
        upload_target
        for target in operator_targets
        for upload_target in target["upload_targets"]
    }
    if represented != set(REQUIRED_UPLOAD_TARGET_IDS):
        raise DashboardError(
            "operator view does not represent every required upload target"
        )
    if len(operator_targets) != len(REQUIRED_TARGETS) + 1:
        raise DashboardError("operator view must add a distinct Edge card")
    if len(operator_targets) == len(REQUIRED_UPLOAD_TARGET_IDS):
        raise DashboardError(
            "store-upload denominator must not use operator/blocker card count"
        )
    chrome = next(
        target for target in operator_targets if target["id"] == "chrome-extension"
    )
    edge = next(
        target for target in operator_targets if target["id"] == OPERATOR_EDGE_TARGET_ID
    )
    if chrome["upload_targets"] != ["chrome-extension-package"]:
        raise DashboardError("Chrome operator card mapping is invalid")
    if edge["upload_targets"] != ["edge-extension-package"]:
        raise DashboardError("Edge operator card mapping is invalid")
    if (
        edge["engineering_readiness"] != chrome["engineering_readiness"]
        or edge["technical_readiness"] != chrome["technical_readiness"]
        or edge["store_evidence_readiness"] != chrome["store_evidence_readiness"]
        or edge["dimensions"] != chrome["dimensions"]
        or edge["blockers"] != chrome["blockers"]
        or edge["blocker_audit"] != chrome["blocker_audit"]
    ):
        raise DashboardError("Edge operator card must inherit Chrome engineering evidence")
    if chrome["engineering_readiness"] > 40 or edge["engineering_readiness"] > 40:
        raise DashboardError("engineering readiness cannot exceed 40")
    if chrome["store_evidence_readiness"] > 60 or edge["store_evidence_readiness"] > 60:
        raise DashboardError("store evidence readiness cannot exceed 60")
    return operator_targets


def _blocker_summary(operator_targets: list[dict[str, Any]]) -> dict[str, Any]:
    items: list[dict[str, str]] = []
    for target in operator_targets:
        audit = target.get("blocker_audit") or {}
        audit_status = audit.get("status") or "missing"
        if audit_status != "verified":
            items.append(
                {
                    "target_id": target["id"],
                    "blocker_id": "blocker_audit",
                    "kind": "undisclosed",
                    "status": str(audit_status),
                }
            )
        for blocker in target.get("blockers") or []:
            kind = blocker.get("kind")
            if kind not in BLOCKER_KINDS:
                continue
            items.append(
                {
                    "target_id": target["id"],
                    "blocker_id": str(blocker.get("id") or "invalid"),
                    "kind": kind,
                    "status": str(blocker.get("status") or "invalid"),
                }
            )
    owner = sum(item["kind"] == "owner" for item in items)
    external = sum(item["kind"] == "external" for item in items)
    undisclosed = sum(item["kind"] == "undisclosed" for item in items)
    return {
        "owner": owner,
        "external": external,
        "undisclosed_audits": undisclosed,
        "count": owner + external + undisclosed,
        "items": items,
    }


def _target_by_id(
    targets: list[dict[str, Any]], target_id: str
) -> dict[str, Any] | None:
    for target in targets:
        if target.get("id") == target_id:
            return target
    return None


def _verified_summary(
    target: dict[str, Any] | None, dimension_id: str, summary_code: str
) -> bool:
    if target is None:
        return False
    return any(
        item.get("id") == dimension_id
        and item.get("status") == "verified"
        and item.get("summary_code") == summary_code
        for item in target.get("dimensions") or []
    )


def _load_gcp_proof_module() -> Any:
    global _gcp_proof_module
    with _gcp_proof_module_lock:
        if _gcp_proof_module is None:
            tools_root = REPO_ROOT / "tools"
            tools_root_string = str(tools_root)
            if tools_root_string not in sys.path:
                sys.path.insert(0, tools_root_string)
            try:
                module = importlib.import_module("gcp_proof_fleet")
            except Exception as suc:
                raise DashboardError(
                    "canonical GCP acceptance-receipt verifier is unavailable"
                ) from suc
            if (
                getattr(module, "MAX_EVIDENCE_AGE", None) != GCP_PROOF_FRESHNESS
                or getattr(module, "RECEIPT_NAME", None) != GCP_PROOF_RECEIPT_NAME
            ):
                raise DashboardError(
                    "canonical GCP acceptance-receipt verifier contract is invalid"
                )
            _gcp_proof_module = module
        return _gcp_proof_module


def verify_gcp_proof_acceptance_receipt_for_release(
    receipt_path: Path,
    *,
    repo_root: Path,
    release_input_index: Path,
) -> dict[str, Any]:
    """Call the fleet acceptance-receipt verifier. Executes no cloud command."""

    module = _load_gcp_proof_module()
    try:
        verified = module.verify_acceptance_receipt_for_release(
            receipt_path,
            repo_root=repo_root,
            release_input_index=release_input_index,
        )
    except Exception as suc:
        raise DashboardError(
            "GCP acceptance receipt did not reverify against the current freeze"
        ) from suc
    if not isinstance(verified, dict) or verified.get("verified") is not True:
        raise DashboardError("GCP acceptance receipt did not reverify")
    return verified


def _current_freeze_index_binding(
    repo_root: Path, release_input_index: str
) -> dict[str, Any]:
    relative = Path(release_input_index)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise DashboardError("release input index path is unsafe")
    index_path = repo_root / relative
    try:
        info = index_path.lstat()
    except OSError as suc:
        raise DashboardError("current freeze index is missing") from suc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise DashboardError("current freeze index must be a regular file")
    digest = hashlib.sha256(index_path.read_bytes()).hexdigest()
    return {
        "path": str(index_path.absolute()),
        "sha256": digest,
        "bytes": info.st_size,
    }


def _gcp_acceptance_receipt_path(
    dimensions: list[dict[str, Any]],
    evidence_root: Path,
    repo_root: Path,
) -> Path | None:
    found: Path | None = None
    for item in dimensions:
        if item.get("id") != "runtime_proof":
            continue
        artifacts = item.get("artifacts") or []
        if not isinstance(artifacts, list):
            raise DashboardError("GCP runtime proof artifacts are malformed")
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise DashboardError("GCP runtime proof artifact is malformed")
            relative = Path(str(artifact.get("path") or ""))
            if relative.name != GCP_PROOF_RECEIPT_NAME:
                continue
            if found is not None:
                raise DashboardError("GCP proof repeats an acceptance receipt")
            root = artifact.get("root")
            if root == "repo":
                base = repo_root
            elif root == "evidence":
                base = evidence_root
            else:
                raise DashboardError("GCP acceptance receipt root is invalid")
            if relative.is_absolute() or any(
                part in {"", ".", ".."} for part in relative.parts
            ):
                raise DashboardError("GCP acceptance receipt path is unsafe")
            found = base / relative
    return found


def _unverified_gcp_proof(status: str) -> dict[str, Any]:
    if status not in {"missing", "invalid", "stale", "unavailable"}:
        status = "invalid"
    return {
        "status": status,
        "fresh": False,
        "reason": "no valid fresh GCP proof",
    }


def _canonical_gcp_acceptance(
    dimensions: list[dict[str, Any]],
    *,
    repo_root: Path | None,
    release_input_index: str | None,
    now: datetime | None,
    evidence_root: Path | None,
) -> dict[str, Any]:
    """Reverify the fleet receipt against the current candidate freeze.

    Named dashboard status is not acceptance. The canonical verifier, the
    6-hour window, and the freeze index path+digest must all match.
    """

    if (
        repo_root is None
        or release_input_index is None
        or now is None
        or evidence_root is None
    ):
        return _unverified_gcp_proof("missing")
    try:
        receipt_path = _gcp_acceptance_receipt_path(
            dimensions, evidence_root, repo_root
        )
        if receipt_path is None:
            return _unverified_gcp_proof("missing")
        freeze_binding = _current_freeze_index_binding(
            repo_root, release_input_index
        )
        index_path = Path(freeze_binding["path"])
        verified = verify_gcp_proof_acceptance_receipt_for_release(
            receipt_path,
            repo_root=repo_root,
            release_input_index=index_path,
        )
        if verified.get("publication_authorized") is not False:
            return _unverified_gcp_proof("invalid")
        if verified.get("release") != RELEASE_IDENTITY:
            return _unverified_gcp_proof("invalid")
        index_ref = verified.get("release_input_index")
        if not isinstance(index_ref, dict):
            return _unverified_gcp_proof("invalid")
        got_path = Path(str(index_ref.get("path") or ""))
        if (
            got_path.absolute() != index_path.absolute()
            or index_ref.get("sha256") != freeze_binding["sha256"]
        ):
            return _unverified_gcp_proof("invalid")
        created = parse_utc(
            verified.get("receipt_created_utc"),
            "GCP acceptance receipt creation",
        )
        if created > now + FUTURE_SKEW:
            return _unverified_gcp_proof("invalid")
        if now - created > GCP_PROOF_FRESHNESS:
            return _unverified_gcp_proof("stale")
        return {
            "status": "verified",
            "fresh": True,
            "reason": "current GCP proof acceptance evidence verified",
        }
    except DashboardError:
        return _unverified_gcp_proof("invalid")


def _bind_gcp_runtime_proof(
    target_id: str,
    dimension_results: list[dict[str, Any]],
    *,
    repo_root: Path,
    release_input_index: str,
    now: datetime,
    evidence_root: Path,
) -> None:
    if target_id != GCP_PROOF_TARGET_ID:
        return
    for item in dimension_results:
        if item.get("id") != "runtime_proof":
            continue
        if (
            item.get("status") != "verified"
            or item.get("summary_code") != GCP_PROOF_SUMMARY_CODE
        ):
            return
        bound = _canonical_gcp_acceptance(
            dimension_results,
            repo_root=repo_root,
            release_input_index=release_input_index,
            now=now,
            evidence_root=evidence_root,
        )
        if bound["status"] == "verified" and bound["fresh"] is True:
            return
        status = bound["status"]
        if status not in {"stale", "invalid", "unavailable"}:
            status = "invalid"
        item["status"] = status
        item["reason"] = bound["reason"]
        return


def _gcp_proof_posture(
    targets: list[dict[str, Any]],
    *,
    repo_root: Path | None = None,
    release_input_index: str | None = None,
    now: datetime | None = None,
    evidence_root: Path | None = None,
) -> dict[str, Any]:
    """GCP proof is the canonical acceptance receipt, never named status alone.

    Source files, proof-client binaries, worker pid files, and generic
    dashboard receipts are not a valid fresh GCP proof.
    """

    target = _target_by_id(targets, GCP_PROOF_TARGET_ID)
    dimensions = list(target.get("dimensions") or []) if target is not None else []
    named = _verified_summary(target, "runtime_proof", GCP_PROOF_SUMMARY_CODE)
    canonical = _canonical_gcp_acceptance(
        dimensions,
        repo_root=repo_root,
        release_input_index=release_input_index,
        now=now,
        evidence_root=evidence_root,
    )
    if named and canonical["status"] == "verified" and canonical["fresh"] is True:
        return canonical
    status = "missing"
    if target is not None:
        runtime_statuses = {
            item.get("status")
            for item in dimensions
            if item.get("id") == "runtime_proof"
        }
        target_status = str(target.get("status") or "unverified")
        if target_status == "unavailable" or "unavailable" in runtime_statuses:
            status = "unavailable"
        elif target_status == "invalid" or "invalid" in runtime_statuses:
            status = "invalid"
        elif target_status == "stale" or "stale" in runtime_statuses:
            status = "stale"
    if canonical["status"] in {"stale", "invalid", "unavailable"}:
        status = str(canonical["status"])
    return _unverified_gcp_proof(status)


def _agp_migration_posture(targets: list[dict[str, Any]]) -> dict[str, Any]:
    """AGP completion cannot be inferred from a Gradle pin or source tree."""

    android = _target_by_id(targets, "android")
    wear = _target_by_id(targets, "watch-wear-os")
    if _verified_summary(
        android, "artifact", AGP_MIGRATION_SUMMARY_CODE
    ) and _verified_summary(wear, "artifact", AGP_MIGRATION_SUMMARY_CODE):
        return {
            "status": "complete",
            "reason": "AGP migration completion evidence verified",
        }
    return {
        "status": "in_progress",
        "reason": "AGP migration in progress; source pin is not completion evidence",
    }


def _macos_release_python_posture(targets: list[dict[str, Any]]) -> dict[str, Any]:
    """Owner Python custody cannot be inferred from schema source files."""

    for target_id in ("macos-arm64", "macos-x86", "signing-store-metadata"):
        if _verified_summary(
            _target_by_id(targets, target_id),
            "engineering",
            MACOS_PYTHON_SUMMARY_CODE,
        ):
            return {
                "status": "authenticated",
                "reason": "owner-provisioned macOS release Python runtime evidence verified",
            }
    return {
        "status": "owner_prompt_pending",
        "reason": "macOS release Python owner prompt pending",
    }


def _upload_receipt_posture(coverage: dict[str, Any]) -> dict[str, Any]:
    store = coverage["store_upload"]
    verified = int(store["verified"])
    required = int(store["required_receipts"])
    unavailable = int(store["unavailable"])
    if required != len(REQUIRED_UPLOAD_TARGET_IDS):
        raise DashboardError("current posture upload denominator is invalid")
    if unavailable == required:
        status = "unavailable"
    elif verified <= 0:
        status = "pending"
    elif verified < required:
        status = "incomplete"
    else:
        status = "complete"
    return {
        "verified": verified,
        "required": required,
        "status": status,
    }


def _current_posture(
    targets: list[dict[str, Any]],
    coverage: dict[str, Any],
    blocker_summary: dict[str, Any],
    *,
    repo_root: Path | None = None,
    release_input_index: str | None = None,
    now: datetime | None = None,
    evidence_root: Path | None = None,
) -> dict[str, Any]:
    """Operator facts derived from evidence, never from workers or source presence."""

    upload_receipts = _upload_receipt_posture(coverage)
    gcp_proof = _gcp_proof_posture(
        targets,
        repo_root=repo_root,
        release_input_index=release_input_index,
        now=now,
        evidence_root=evidence_root,
    )
    agp_migration = _agp_migration_posture(targets)
    macos_release_python = _macos_release_python_posture(targets)
    categories: list[dict[str, str]] = [
        {
            "id": "publication_hold",
            "status": "open",
            "detail": PUBLICATION_HOLD,
        }
    ]
    if upload_receipts["verified"] != upload_receipts["required"]:
        categories.append(
            {
                "id": "missing_upload_receipts",
                "status": "open",
                "detail": (
                    f"{upload_receipts['verified']}/{upload_receipts['required']}"
                ),
            }
        )
    if not gcp_proof["fresh"] or gcp_proof["status"] != "verified":
        categories.append(
            {
                "id": "gcp_proof",
                "status": "open",
                "detail": "no valid fresh GCP proof",
            }
        )
    if agp_migration["status"] != "complete":
        categories.append(
            {
                "id": "agp_migration",
                "status": "open",
                "detail": "in progress",
            }
        )
    if macos_release_python["status"] != "authenticated":
        categories.append(
            {
                "id": "macos_release_python",
                "status": "open",
                "detail": "owner prompt pending",
            }
        )
    undisclosed = int(blocker_summary.get("undisclosed_audits") or 0)
    owner = int(blocker_summary.get("owner") or 0)
    external = int(blocker_summary.get("external") or 0)
    if undisclosed > 0:
        categories.append(
            {
                "id": "undisclosed_blocker_audits",
                "status": "open",
                "detail": str(undisclosed),
            }
        )
    if owner > 0:
        categories.append(
            {
                "id": "owner_blockers",
                "status": "open",
                "detail": str(owner),
            }
        )
    if external > 0:
        categories.append(
            {
                "id": "external_blockers",
                "status": "open",
                "detail": str(external),
            }
        )
    known = {item["id"] for item in categories}
    if not known <= set(CURRENT_POSTURE_CATEGORY_IDS):
        raise DashboardError("current posture contains an unknown blocker category")
    if categories[0]["id"] != "publication_hold":
        raise DashboardError("publication hold must remain the first blocker category")
    return {
        "publication_hold": PUBLICATION_HOLD,
        "store_upload_authorized": False,
        "upload_receipts": upload_receipts,
        "gcp_proof": gcp_proof,
        "agp_migration": agp_migration,
        "macos_release_python": macos_release_python,
        "active_blocker_categories": categories,
    }


SCORED_COVERAGE_KEYS = (
    "ready",
    "pending",
    "failed",
    "stale",
    "partial",
    "unavailable",
)
ENGINEERING_COVERAGE_KEYS = (
    "verified",
    "pending",
    "failed",
    "stale",
    "unavailable",
)
RECEIPT_COVERAGE_KEYS = (
    "verified",
    "pending",
    "failed",
    "stale",
    "unavailable",
)


def _rounded_percent(verified: int, required: int) -> int:
    if required <= 0 or verified <= 0:
        return 0
    if verified >= required:
        return 100
    return int((verified * 100 / required) + 0.5)


def _count_outcomes(outcomes: list[str], keys: tuple[str, ...]) -> dict[str, int]:
    return {key: sum(item == key for item in outcomes) for key in keys}


def _scored_target_outcome(status: str) -> str:
    if status == "ready":
        return "ready"
    if status == "partial":
        return "partial"
    if status == "stale":
        return "stale"
    if status == "unverified":
        return "pending"
    if status == "unavailable":
        return "unavailable"
    return "failed"


def _receipt_outcome(status: str) -> str:
    if status == "verified":
        return "verified"
    if status == "missing":
        return "pending"
    if status == "stale":
        return "stale"
    if status == "unavailable":
        return "unavailable"
    return "failed"


def _engineering_target_outcome(target: dict[str, Any]) -> str:
    dimensions = [
        item
        for item in target.get("dimensions") or []
        if item.get("id") in ENGINEERING_DIMENSION_IDS
    ]
    if len(dimensions) != len(ENGINEERING_DIMENSION_IDS):
        return "unavailable"
    statuses = {item.get("status") for item in dimensions}
    if statuses <= {"verified"}:
        return "verified"
    if statuses & {"failed", "invalid"}:
        return "failed"
    if "stale" in statuses:
        return "stale"
    if "missing" in statuses:
        return "pending"
    return "failed"


def _iso_extreme(timestamps: list[Any], *, newest: bool) -> str | None:
    parsed: list[datetime] = []
    for value in timestamps:
        if not isinstance(value, str) or not value:
            continue
        try:
            parsed.append(parse_utc(value, "coverage timestamp"))
        except DashboardError:
            continue
    if not parsed:
        return None
    chosen = max(parsed) if newest else min(parsed)
    return iso_utc(chosen)


def _coverage_and_freshness(
    targets: list[dict[str, Any]],
    required_receipts: list[dict[str, Any]],
    optional_receipts: list[dict[str, Any]],
    max_age_seconds: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(targets) != len(REQUIRED_TARGETS):
        raise DashboardError("coverage requires the complete scored target set")
    if len(required_receipts) != len(REQUIRED_UPLOAD_TARGET_IDS):
        raise DashboardError("coverage requires the complete required upload-target set")
    if len(optional_receipts) != len(OPTIONAL_UPLOAD_TARGET_IDS):
        raise DashboardError("coverage requires the complete optional upload-target set")

    scored = _count_outcomes(
        [
            _scored_target_outcome(str(target.get("status") or "unavailable"))
            for target in targets
        ],
        SCORED_COVERAGE_KEYS,
    )
    scored["required"] = len(REQUIRED_TARGETS)
    if sum(scored[key] for key in SCORED_COVERAGE_KEYS) != scored["required"]:
        raise DashboardError("scored-target coverage counts do not cover every target")

    engineering_counts = _count_outcomes(
        [_engineering_target_outcome(target) for target in targets],
        ENGINEERING_COVERAGE_KEYS,
    )
    engineering_dimensions = [
        item
        for target in targets
        for item in target.get("dimensions") or []
        if item.get("id") in ENGINEERING_DIMENSION_IDS
    ]
    required_engineering_dimensions = len(REQUIRED_TARGETS) * len(
        ENGINEERING_DIMENSION_IDS
    )
    verified_engineering_dimensions = sum(
        item.get("status") == "verified" for item in engineering_dimensions
    )
    pending_engineering_dimensions = sum(
        item.get("status") == "missing" for item in engineering_dimensions
    )
    failed_engineering_dimensions = sum(
        item.get("status") in {"failed", "invalid"} for item in engineering_dimensions
    )
    stale_engineering_dimensions = sum(
        item.get("status") == "stale" for item in engineering_dimensions
    )
    engineering_percent = _rounded_percent(
        verified_engineering_dimensions, required_engineering_dimensions
    )
    if (
        engineering_percent == 100
        and verified_engineering_dimensions != required_engineering_dimensions
    ):
        raise DashboardError(
            "engineering coverage cannot report 100 from missing evidence"
        )

    store = _count_outcomes(
        [
            _receipt_outcome(str(receipt.get("status") or "unavailable"))
            for receipt in required_receipts
        ],
        RECEIPT_COVERAGE_KEYS,
    )
    store["required_receipts"] = len(REQUIRED_UPLOAD_TARGET_IDS)
    if sum(store[key] for key in RECEIPT_COVERAGE_KEYS) != store["required_receipts"]:
        raise DashboardError(
            "store-upload coverage counts do not cover every required receipt"
        )
    store["percent"] = _rounded_percent(store["verified"], store["required_receipts"])
    if store["percent"] == 100 and store["verified"] != store["required_receipts"]:
        raise DashboardError(
            "store-upload coverage cannot report 100 from missing receipts"
        )
    optional = _count_outcomes(
        [
            _receipt_outcome(str(receipt.get("status") or "unavailable"))
            for receipt in optional_receipts
        ],
        RECEIPT_COVERAGE_KEYS,
    )
    store["optional_receipts"] = len(OPTIONAL_UPLOAD_TARGET_IDS)
    store["optional_verified"] = optional["verified"]
    store["optional_pending"] = optional["pending"]
    store["optional_failed"] = optional["failed"]
    store["optional_stale"] = optional["stale"]
    store["optional_unavailable"] = optional["unavailable"]

    all_dimensions = [
        item
        for target in targets
        for item in target.get("dimensions") or []
    ]
    timestamps = [target.get("last_evidence_at") for target in targets]
    timestamps.extend(receipt.get("verified_at") for receipt in required_receipts)
    timestamps.extend(receipt.get("verified_at") for receipt in optional_receipts)
    verified_timestamps = [
        item.get("observed_at")
        for item in all_dimensions
        if item.get("status") == "verified"
    ]
    verified_timestamps.extend(
        receipt.get("verified_at")
        for receipt in required_receipts
        if receipt.get("status") == "verified"
    )

    coverage = {
        "scored_targets": scored,
        "engineering": {
            "required_targets": len(REQUIRED_TARGETS),
            "required_dimensions": required_engineering_dimensions,
            "verified_targets": engineering_counts["verified"],
            "pending_targets": engineering_counts["pending"],
            "failed_targets": engineering_counts["failed"],
            "stale_targets": engineering_counts["stale"],
            "unavailable_targets": engineering_counts["unavailable"],
            "verified_dimensions": verified_engineering_dimensions,
            "pending_dimensions": pending_engineering_dimensions,
            "failed_dimensions": failed_engineering_dimensions,
            "stale_dimensions": stale_engineering_dimensions,
            "percent": engineering_percent,
        },
        "store_upload": store,
    }
    freshness = {
        "max_age_seconds": max_age_seconds,
        "stale_targets": scored["stale"],
        "stale_dimensions": sum(
            item.get("status") == "stale" for item in all_dimensions
        ),
        "stale_upload_receipts": store["stale"],
        "newest_evidence_at": _iso_extreme(timestamps, newest=True),
        "oldest_verified_evidence_at": _iso_extreme(
            verified_timestamps, newest=False
        ),
    }
    return coverage, freshness


def evaluate_target(
    target: dict[str, Any],
    dimensions: list[dict[str, Any]],
    evidence_root: Path,
    now: datetime,
    max_age: timedelta,
    cross_store: dict[str, Any],
    repo_root: Path,
    cross_store_cache: dict[str, dict[str, Any]],
    artifact_claims: dict[str, tuple[str, str]],
    cached_receipts: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    receipt_name = f"{target['id']}.json"
    receipt_path = evidence_root / receipt_name
    checks: dict[str, Any] = {}
    raw_blockers: list[Any] = []
    raw_blocker_audit: Any = None
    receipt_error: str | None = None
    receipt_generated_at: str | None = None
    receipt_generated: datetime | None = None
    receipt_present = False
    try:
        receipt_path.lstat()
        receipt_present = True
    except FileNotFoundError:
        pass
    except OSError:
        receipt_error = "receipt is not readable"
    if receipt_present:
        try:
            resolved_receipt = _resolve_contained_without_symlinks(
                evidence_root, Path(receipt_name), "receipt"
            )
            receipt_stat = resolved_receipt.stat()
            if not stat.S_ISREG(receipt_stat.st_mode):
                raise DashboardError("receipt must be a regular file")
            if receipt_stat.st_nlink != 1:
                raise DashboardError("receipt must not be hard-linked")
            _require_private_local_owner(receipt_stat, "receipt")
            receipt = read_json(resolved_receipt)
            require_exact_fields(
                receipt,
                {
                    "schema_version",
                    "release",
                    "target",
                    "generated_at",
                    "dimensions",
                    "blocker_audit",
                    "blockers",
                },
                "receipt",
            )
            if receipt.get("schema_version") != 4:
                raise DashboardError("receipt schema_version must be 4")
            if receipt.get("release") != RELEASE_IDENTITY:
                raise DashboardError("receipt release does not match current release")
            if receipt.get("target") != target["id"]:
                raise DashboardError("receipt target does not match card")
            receipt_generated = parse_utc(receipt.get("generated_at"), "receipt generated_at")
            if receipt_generated > now + FUTURE_SKEW:
                raise DashboardError("receipt generated_at is in the future")
            receipt_modified = datetime.fromtimestamp(
                receipt_stat.st_mtime, timezone.utc
            )
            if receipt_modified > now + FUTURE_SKEW:
                raise DashboardError("receipt modified_at is in the future")
            if abs(receipt_modified - receipt_generated) > FUTURE_SKEW:
                raise DashboardError(
                    "receipt file time does not match receipt generation"
                )
            receipt_generated_at = iso_utc(receipt_generated)
            raw_checks = receipt.get("dimensions")
            if not isinstance(raw_checks, dict):
                raise DashboardError("receipt dimensions must be an object")
            expected = {dimension["id"] for dimension in dimensions}
            unknown = set(raw_checks) - expected
            missing = expected - set(raw_checks)
            if unknown or missing:
                details = []
                if unknown:
                    details.append("unknown " + ", ".join(sorted(unknown)))
                if missing:
                    details.append("missing " + ", ".join(sorted(missing)))
                raise DashboardError("receipt dimension set mismatch: " + "; ".join(details))
            supplied_blockers = receipt.get("blockers")
            if not isinstance(supplied_blockers, list):
                raise DashboardError("receipt blockers must be an array, even when empty")
            raw_blocker_audit = receipt.get("blocker_audit")
            raw_blockers = supplied_blockers
            checks = raw_checks
        except DashboardError as exc:
            receipt_error = str(exc)

    if receipt_error:
        dimension_results = [
            {
                "id": dimension["id"],
                "label": dimension["label"],
                "weight": dimension["weight"],
                "status": "invalid",
                "reason": receipt_error,
                "observed_at": None,
                "producer": None,
                "evidence_type": DIMENSION_EVIDENCE_CONTRACT[dimension["id"]][0],
                "summary_code": None,
                "artifacts": [],
            }
            for dimension in dimensions
        ]
        blocker_results = []
        blocker_audit = {
            "id": "blocker_audit",
            "label": "Owner and external blocker audit",
            "weight": 0,
            "status": "invalid",
            "reason": receipt_error,
            "observed_at": None,
            "producer": None,
            "evidence_type": BLOCKER_AUDIT_CONTRACT[0],
            "summary_code": None,
            "artifacts": [],
        }
    else:
        dimension_results = [
            _dimension_result(
                dimension,
                checks.get(dimension["id"]),
                DIMENSION_EVIDENCE_CONTRACT[dimension["id"]],
                evidence_root,
                now,
                max_age,
                receipt_generated,
                target["id"],
                artifact_claims,
            )
            for dimension in dimensions
        ]
        _bind_gcp_runtime_proof(
            target["id"],
            dimension_results,
            repo_root=repo_root,
            release_input_index=cross_store["release_input_index"],
            now=now,
            evidence_root=evidence_root,
        )
        blocker_audit = _dimension_result(
            {
                "id": "blocker_audit",
                "label": "Owner and external blocker audit",
                "weight": 0,
            },
            raw_blocker_audit,
            BLOCKER_AUDIT_CONTRACT,
            evidence_root,
            now,
            max_age,
            receipt_generated,
            target["id"],
            artifact_claims,
        )
        blocker_results = [
            _blocker_result(
                raw_blocker,
                evidence_root,
                now,
                max_age,
                receipt_generated,
                target["id"],
                artifact_claims,
            )
            for raw_blocker in raw_blockers
        ]
        if len({blocker["id"] for blocker in blocker_results}) != len(blocker_results):
            blocker_results = [
                {
                    **blocker,
                    "status": "invalid",
                    "reason": "receipt repeats a blocker id",
                }
                for blocker in blocker_results
            ]

    technical_readiness = sum(
        dimension["weight"]
        for dimension in dimension_results
        if dimension["status"] == "verified"
    )
    cross_store_status, cross_store_receipts = _cross_store_target_result(
        target,
        cross_store,
        repo_root,
        now,
        max_age,
        cross_store_cache,
        cached_receipts,
    )
    optional_cross_store_status, optional_cross_store_receipts = (
        _cross_store_target_result(
            {"upload_targets": target["optional_upload_targets"]},
            cross_store,
            repo_root,
            now,
            max_age,
            cross_store_cache,
            cached_receipts,
        )
    )
    statuses = {dimension["status"] for dimension in dimension_results}
    blocker_audit_status = blocker_audit["status"]
    engineering_readiness = _dimension_score(
        dimension_results, ENGINEERING_DIMENSION_IDS
    )
    store_evidence_readiness = _dimension_score(
        dimension_results, STORE_DIMENSION_IDS
    )
    store_verified = _store_dimensions_verified(dimension_results)
    readiness, status = _derive_status_and_readiness(
        technical_readiness,
        statuses,
        blocker_audit_status,
        blocker_results,
        cross_store_status,
        store_verified,
    )
    timestamps = [
        dimension["observed_at"]
        for dimension in dimension_results
        if dimension["observed_at"] is not None
    ]
    timestamps.extend(
        blocker["observed_at"]
        for blocker in blocker_results
        if blocker["observed_at"] is not None
    )
    if blocker_audit["observed_at"] is not None:
        timestamps.append(blocker_audit["observed_at"])
    return {
        **target,
        "readiness": readiness,
        "technical_readiness": technical_readiness,
        "engineering_readiness": engineering_readiness,
        "store_evidence_readiness": store_evidence_readiness,
        "status": status,
        "receipt": receipt_name,
        "receipt_generated_at": receipt_generated_at,
        "last_evidence_at": max(timestamps) if timestamps else None,
        "cross_store_status": cross_store_status,
        "cross_store_receipts": cross_store_receipts,
        "optional_cross_store_status": optional_cross_store_status,
        "optional_cross_store_receipts": optional_cross_store_receipts,
        "dimensions": dimension_results,
        "blocker_audit": blocker_audit,
        "blockers": blocker_results,
    }


def build_snapshot(
    config_path: Path = DEFAULT_CONFIG,
    evidence_root: Path = DEFAULT_EVIDENCE_ROOT,
    now: datetime | None = None,
    repo_root: Path = REPO_ROOT,
    cache_path: Path | None = None,
) -> dict[str, Any]:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise DashboardError("snapshot time must be timezone-aware")
    current = current.astimezone(timezone.utc)
    config = load_config(config_path)
    max_age = timedelta(seconds=config["max_evidence_age_seconds"])
    resolved_cache = cache_path if cache_path is not None else DEFAULT_CROSS_STORE_CACHE
    cached_receipts = _read_cross_store_cache(
        resolved_cache,
        current,
        max_age,
        config["cross_store"]["receipt_directory"],
        config["cross_store"]["release_input_index"],
        repo_root,
    )
    cross_store_cache: dict[str, dict[str, Any]] = {}
    for upload_target in KNOWN_CROSS_STORE_TARGET_IDS:
        _cross_store_receipt_result(
            upload_target,
            config["cross_store"],
            repo_root,
            current,
            max_age,
            cross_store_cache,
            cached_receipts,
        )
    _reject_reused_cross_store_receipts(cross_store_cache)
    artifact_claims: dict[str, tuple[str, str]] = {}
    targets = [
        evaluate_target(
            target,
            config["dimensions"],
            evidence_root,
            current,
            max_age,
            config["cross_store"],
            repo_root,
            cross_store_cache,
            artifact_claims,
            cached_receipts,
        )
        for target in config["targets"]
    ]
    if set(cross_store_cache) != set(KNOWN_CROSS_STORE_TARGET_IDS):
        raise DashboardError(
            "snapshot did not evaluate the complete canonical cross-store matrix"
        )
    cross_store_receipts = [
        cross_store_cache[target_id] for target_id in REQUIRED_UPLOAD_TARGET_IDS
    ]
    cross_store_status_counts = _cross_store_status_counts(cross_store_receipts)
    optional_cross_store_receipts = [
        cross_store_cache[target_id] for target_id in OPTIONAL_UPLOAD_TARGET_IDS
    ]
    optional_cross_store_status_counts = _cross_store_status_counts(
        optional_cross_store_receipts
    )
    overall = int((sum(target["readiness"] for target in targets) / len(targets)) + 0.5)
    required_receipts_complete = all(
        receipt["status"] == "verified" for receipt in cross_store_receipts
    )
    if not required_receipts_complete and overall == 100:
        raise DashboardError(
            "upload readiness cannot be claimed while a required receipt is missing"
        )
    operator_targets = _split_operator_targets(targets)
    coverage, freshness = _coverage_and_freshness(
        targets,
        cross_store_receipts,
        optional_cross_store_receipts,
        config["max_evidence_age_seconds"],
    )
    if (
        coverage["store_upload"]["verified"] != len(REQUIRED_UPLOAD_TARGET_IDS)
        and (
            overall == 100
            or coverage["store_upload"]["percent"] == 100
        )
    ):
        raise DashboardError(
            "store-upload coverage cannot claim completion while a required receipt is missing"
        )
    if (
        coverage["engineering"]["verified_dimensions"]
        != coverage["engineering"]["required_dimensions"]
        and coverage["engineering"]["percent"] == 100
    ):
        raise DashboardError(
            "engineering coverage cannot claim completion from missing evidence"
        )
    for target in operator_targets:
        mapped_receipts = target["cross_store_receipts"]
        if mapped_receipts and any(
            receipt["status"] != "verified" for receipt in mapped_receipts
        ):
            if target["status"] == "ready" or target["readiness"] > 0:
                raise DashboardError(
                    f"{target['id']} cannot claim upload readiness from missing receipts"
                )
        if target["status"] == "ready" and not _store_dimensions_verified(
            list(target.get("dimensions") or [])
        ):
            raise DashboardError(
                f"{target['id']} cannot be ready from engineering or test evidence alone"
            )
        if target["readiness"] == 100 and target.get("store_evidence_readiness", 0) < 60:
            raise DashboardError(
                f"{target['id']} cannot report 100 percent without signed-artifact and store evidence"
            )
    blocker_summary = _blocker_summary(operator_targets)
    current_posture = _current_posture(
        targets,
        coverage,
        blocker_summary,
        repo_root=repo_root,
        release_input_index=config["cross_store"]["release_input_index"],
        now=current,
        evidence_root=evidence_root,
    )
    if (
        current_posture["publication_hold"] != PUBLICATION_HOLD
        or current_posture["store_upload_authorized"] is not False
    ):
        raise DashboardError("dashboard cannot authorize store upload")
    if (
        current_posture["upload_receipts"]["verified"]
        != coverage["store_upload"]["verified"]
        or current_posture["upload_receipts"]["required"]
        != len(REQUIRED_UPLOAD_TARGET_IDS)
    ):
        raise DashboardError("current posture upload counts drifted from coverage")
    snapshot_expires = current + timedelta(
        seconds=max(10, config["refresh_seconds"] * 3)
    )
    return {
        "schema_version": DASHBOARD_SCHEMA_VERSION,
        "receipt_schema_version": DASHBOARD_RECEIPT_SCHEMA_VERSION,
        "cross_store_receipt_schema_version": CROSS_STORE_RECEIPT_SCHEMA_VERSION,
        "release": RELEASE_IDENTITY,
        "generated_at": iso_utc(current),
        "snapshot_expires_at": iso_utc(snapshot_expires),
        "source": "verified-local-evidence",
        "local_only": True,
        "contract_sha256": config_contract_sha256(config),
        "refresh_seconds": config["refresh_seconds"],
        "max_evidence_age_seconds": config["max_evidence_age_seconds"],
        "evidence_directory": "local hash-verified evidence",
        "cross_store": {
            "release": RELEASE_IDENTITY,
            "receipt_schema_version": CROSS_STORE_RECEIPT_SCHEMA_VERSION,
            "release_input_index": config["cross_store"]["release_input_index"],
            "receipt_directory": config["cross_store"]["receipt_directory"],
            "required_upload_target_count": len(REQUIRED_UPLOAD_TARGET_IDS),
            "required_upload_targets": list(REQUIRED_UPLOAD_TARGET_IDS),
            "status_counts": cross_store_status_counts,
            "receipts": cross_store_receipts,
            "optional_upload_target_count": len(OPTIONAL_UPLOAD_TARGET_IDS),
            "optional_upload_targets": list(OPTIONAL_UPLOAD_TARGET_IDS),
            "optional_status_counts": optional_cross_store_status_counts,
            "optional_receipts": optional_cross_store_receipts,
        },
        "overall_readiness": overall,
        "overall_technical_readiness": int(
            (sum(target["technical_readiness"] for target in targets) / len(targets))
            + 0.5
        ),
        "overall_engineering_readiness": int(
            (sum(target["engineering_readiness"] for target in targets) / len(targets))
            + 0.5
        ),
        "overall_store_evidence_readiness": int(
            (
                sum(target["store_evidence_readiness"] for target in targets)
                / len(targets)
            )
            + 0.5
        ),
        "ready_targets": sum(target["status"] == "ready" for target in targets),
        "target_count": len(targets),
        "targets": targets,
        "operator_targets": operator_targets,
        "blocker_summary": blocker_summary,
        "current_posture": current_posture,
        "coverage": coverage,
        "freshness": freshness,
    }


def build_failure_snapshot(now: datetime | None = None) -> dict[str, Any]:
    """Build an explicit non-evidence state when a sync cannot evaluate inputs.

    This contains no receipt-derived fields. It prevents a prior successful snapshot
    from looking current after configuration or evidence validation fails.
    """
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise DashboardError("snapshot time must be timezone-aware")
    generated_at = iso_utc(current.astimezone(timezone.utc))
    targets = [
        {
            "id": target_id,
            "label": label,
            "group": "evidence unavailable",
            "readiness": 0,
            "technical_readiness": 0,
            "engineering_readiness": 0,
            "store_evidence_readiness": 0,
            "status": "unavailable",
            "receipt": f"{target_id}.json",
            "receipt_generated_at": None,
            "last_evidence_at": None,
            "upload_targets": list(DASHBOARD_UPLOAD_TARGET_MAP[target_id]),
            "optional_upload_targets": list(
                DASHBOARD_OPTIONAL_UPLOAD_TARGET_MAP[target_id]
            ),
            "cross_store_status": (
                "unavailable"
                if DASHBOARD_UPLOAD_TARGET_MAP[target_id]
                else "not_applicable"
            ),
            "cross_store_receipts": [
                {
                    "target_id": upload_target,
                    "receipt": (
                        f"{DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY}/{upload_target}.json"
                    ),
                    "receipt_schema_version": CROSS_STORE_RECEIPT_SCHEMA_VERSION,
                    "release": RELEASE_IDENTITY,
                    "status": "unavailable",
                    "verified_at": None,
                    "receipt_sha256": None,
                    "artifact_sha256": None,
                    "reason": "local evidence validation failed",
                }
                for upload_target in DASHBOARD_UPLOAD_TARGET_MAP[target_id]
            ],
            "optional_cross_store_status": (
                "unavailable"
                if DASHBOARD_OPTIONAL_UPLOAD_TARGET_MAP[target_id]
                else "not_applicable"
            ),
            "optional_cross_store_receipts": [
                {
                    "target_id": upload_target,
                    "receipt": (
                        f"{DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY}/{upload_target}.json"
                    ),
                    "receipt_schema_version": CROSS_STORE_RECEIPT_SCHEMA_VERSION,
                    "release": RELEASE_IDENTITY,
                    "status": "unavailable",
                    "verified_at": None,
                    "receipt_sha256": None,
                    "artifact_sha256": None,
                    "reason": "local evidence validation failed",
                }
                for upload_target in DASHBOARD_OPTIONAL_UPLOAD_TARGET_MAP[target_id]
            ],
            "dimensions": [],
            "blocker_audit": {
                "id": "blocker_audit",
                "label": "Owner and external blocker audit",
                "weight": 0,
                "status": "unavailable",
                "reason": "local evidence validation failed",
                "observed_at": None,
                "producer": None,
                "evidence_type": BLOCKER_AUDIT_CONTRACT[0],
                "summary_code": None,
                "artifacts": [],
            },
            "blockers": [],
        }
        for target_id, label in REQUIRED_TARGETS.items()
    ]
    operator_targets = _split_operator_targets(targets)
    blocker_summary = _blocker_summary(operator_targets)
    required_receipts = [
        _unavailable_cross_store_receipt(
            upload_target,
            f"{DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY}/{upload_target}.json",
            "local evidence validation failed",
            "unavailable",
        )
        for upload_target in REQUIRED_UPLOAD_TARGET_IDS
    ]
    optional_receipts = [
        _unavailable_cross_store_receipt(
            upload_target,
            f"{DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY}/{upload_target}.json",
            "local evidence validation failed",
            "unavailable",
        )
        for upload_target in OPTIONAL_UPLOAD_TARGET_IDS
    ]
    coverage, freshness = _coverage_and_freshness(
        targets, required_receipts, optional_receipts, 0
    )
    current_posture = _current_posture(targets, coverage, blocker_summary)
    return {
        "schema_version": DASHBOARD_SCHEMA_VERSION,
        "receipt_schema_version": DASHBOARD_RECEIPT_SCHEMA_VERSION,
        "cross_store_receipt_schema_version": CROSS_STORE_RECEIPT_SCHEMA_VERSION,
        "release": RELEASE_IDENTITY,
        "generated_at": generated_at,
        "snapshot_expires_at": iso_utc(
            current.astimezone(timezone.utc) + timedelta(seconds=15)
        ),
        "source": "invalid-local-evidence",
        "local_only": True,
        "contract_sha256": None,
        "refresh_seconds": 5,
        "max_evidence_age_seconds": 0,
        "evidence_directory": "local evidence validation failed",
        "cross_store": {
            "release": RELEASE_IDENTITY,
            "receipt_schema_version": CROSS_STORE_RECEIPT_SCHEMA_VERSION,
            "release_input_index": DEFAULT_RELEASE_INPUT_INDEX,
            "receipt_directory": DEFAULT_CROSS_STORE_RECEIPT_DIRECTORY,
            "required_upload_target_count": len(REQUIRED_UPLOAD_TARGET_IDS),
            "required_upload_targets": list(REQUIRED_UPLOAD_TARGET_IDS),
            "status_counts": _cross_store_status_counts(required_receipts),
            "receipts": required_receipts,
            "optional_upload_target_count": len(OPTIONAL_UPLOAD_TARGET_IDS),
            "optional_upload_targets": list(OPTIONAL_UPLOAD_TARGET_IDS),
            "optional_status_counts": _cross_store_status_counts(optional_receipts),
            "optional_receipts": optional_receipts,
        },
        "overall_readiness": 0,
        "overall_technical_readiness": 0,
        "overall_engineering_readiness": 0,
        "overall_store_evidence_readiness": 0,
        "ready_targets": 0,
        "target_count": len(targets),
        "targets": targets,
        "operator_targets": operator_targets,
        "blocker_summary": blocker_summary,
        "current_posture": current_posture,
        "coverage": coverage,
        "freshness": freshness,
    }


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "WinsVpnLocalDashboard/1"
    sys_version = ""
    config_path = DEFAULT_CONFIG
    evidence_root = DEFAULT_EVIDENCE_ROOT
    repo_root = REPO_ROOT
    cache_path = DEFAULT_CROSS_STORE_CACHE
    snapshot_path = DEFAULT_SNAPSHOT

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Content-Security-Policy", SECURITY_CSP)
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _accept_local_origin_form(self) -> bool:
        host_values = self.headers.get_all("Host", [])
        port = self.server.server_port
        allowed_hosts = {
            "localhost",
            "127.0.0.1",
            f"localhost:{port}",
            f"127.0.0.1:{port}",
        }
        if (
            len(host_values) != 1
            or host_values[0] != host_values[0].strip()
            or host_values[0].lower() not in allowed_hosts
        ):
            self._send(400, b"invalid host\n", "text/plain; charset=utf-8")
            return False
        # The Host check stops DNS rebinding, but a page on another origin can
        # still make the operator's browser send a no-cors GET here, and each
        # one runs a full evidence snapshot. Browsers label those requests;
        # the dashboard's own page sends same-origin, a typed URL sends none.
        fetch_sites = self.headers.get_all("Sec-Fetch-Site", [])
        origins = self.headers.get_all("Origin", [])
        allowed_origins = {
            "http://localhost",
            "http://127.0.0.1",
            f"http://localhost:{port}",
            f"http://127.0.0.1:{port}",
        }
        if (
            len(fetch_sites) > 1
            or (fetch_sites and fetch_sites[0].strip().lower() not in {"same-origin", "none"})
            or len(origins) > 1
            or (origins and origins[0].strip().lower() not in allowed_origins)
        ):
            self._send(403, b"cross-origin request rejected\n", "text/plain; charset=utf-8")
            return False
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            self._send(400, b"invalid request target\n", "text/plain; charset=utf-8")
            return False
        if (
            not self.path.startswith("/")
            or self.path.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
            or self.path != parsed.path
        ):
            self._send(400, b"invalid request target\n", "text/plain; charset=utf-8")
            return False
        return True

    def _read_only_snapshot(self) -> dict[str, Any]:
        try:
            return build_snapshot(
                self.config_path,
                self.evidence_root,
                repo_root=self.repo_root,
                cache_path=self.cache_path,
            )
        except DashboardError:
            return build_failure_snapshot()

    def do_GET(self) -> None:
        if not self._accept_local_origin_form():
            return
        path = self.path
        if path not in ALLOWED_GET_TARGETS:
            self._send(404, b"not found\n", "text/plain; charset=utf-8")
            return
        if path == "/api/state":
            body = json.dumps(
                self._read_only_snapshot(),
                separators=(",", ":"),
            ).encode("utf-8")
            self._send(200, body, "application/json; charset=utf-8")
            return
        if path in {"/", "/index.html"}:
            try:
                body = DASHBOARD_INDEX.read_bytes()
            except OSError:
                self._send(500, b"dashboard unavailable\n", "text/plain; charset=utf-8")
                return
            self._send(200, body, "text/html; charset=utf-8")
            return
        try:
            body = APP_JS.read_bytes()
        except OSError:
            self._send(500, b"dashboard unavailable\n", "text/plain; charset=utf-8")
            return
        self._send(200, body, "application/javascript; charset=utf-8")

    def _reject_method(self) -> None:
        if not self._accept_local_origin_form():
            return
        if self.path not in ALLOWED_GET_TARGETS:
            self._send(404, b"not found\n", "text/plain; charset=utf-8")
            return
        self._send(
            405,
            b"method not allowed\n",
            "text/plain; charset=utf-8",
            (("Allow", "GET"),),
        )

    def do_HEAD(self) -> None:
        self._reject_method()

    def do_POST(self) -> None:
        self._reject_method()

    def do_PUT(self) -> None:
        self._reject_method()

    def do_PATCH(self) -> None:
        self._reject_method()

    def do_DELETE(self) -> None:
        self._reject_method()

    def do_OPTIONS(self) -> None:
        self._reject_method()

    def do_TRACE(self) -> None:
        self._reject_method()

    def log_message(self, format_string: str, *args: Any) -> None:
        return


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CROSS_STORE_CACHE)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--snapshot",
        nargs="?",
        const=DEFAULT_SNAPSHOT,
        type=Path,
        help="write one atomic JSON snapshot instead of starting the server",
    )
    parser.add_argument(
        "--failure-snapshot",
        type=Path,
        help="replace a prior snapshot with an explicit zero-evidence failure state",
    )
    parser.add_argument(
        "--refresh-cross-store-cache",
        action="store_true",
        help="sync-phase only: execute custody/signing gates into immutable cached evidence",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="validate configuration and current evidence without serving",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not 1 <= args.port <= 65535:
        raise DashboardError("port must be from 1 to 65535")
    if args.failure_snapshot is not None:
        write_json_atomic(args.failure_snapshot, build_failure_snapshot())
        print(
            json.dumps(
                {
                    "snapshot": str(args.failure_snapshot),
                    "source": "invalid-local-evidence",
                    "overall_readiness": 0,
                    "target_count": len(REQUIRED_TARGETS),
                },
                separators=(",", ":"),
            )
        )
        return 0
    if args.refresh_cross_store_cache:
        config = load_config(args.config)
        materialize_cross_store_cache(
            args.repo_root,
            args.cache,
            config["cross_store"],
        )
        if args.snapshot is None and not args.validate:
            print(
                json.dumps(
                    {
                        "cache": str(args.cache),
                        "release": RELEASE_IDENTITY,
                    },
                    separators=(",", ":"),
                )
            )
            return 0
    if args.snapshot is not None or args.validate:
        snapshot = build_snapshot(
            args.config,
            args.evidence_root,
            repo_root=args.repo_root,
            cache_path=args.cache,
        )
        if args.snapshot is not None:
            write_json_atomic(args.snapshot, snapshot)
            print(
                json.dumps(
                    {
                        "snapshot": str(args.snapshot),
                        "generated_at": snapshot["generated_at"],
                        "overall_readiness": snapshot["overall_readiness"],
                        "ready_targets": snapshot["ready_targets"],
                        "target_count": snapshot["target_count"],
                    },
                    separators=(",", ":"),
                )
            )
            return 0
        print(
            json.dumps(
                {
                    "valid": True,
                    "generated_at": snapshot["generated_at"],
                    "overall_readiness": snapshot["overall_readiness"],
                    "ready_targets": snapshot["ready_targets"],
                    "target_count": snapshot["target_count"],
                },
                separators=(",", ":"),
            )
        )
        return 0

    DashboardHandler.config_path = args.config
    DashboardHandler.evidence_root = args.evidence_root
    DashboardHandler.repo_root = args.repo_root
    DashboardHandler.cache_path = args.cache
    DashboardHandler.snapshot_path = DEFAULT_SNAPSHOT
    server = ThreadingHTTPServer((LOCAL_BIND, args.port), DashboardHandler)
    print(f"local release dashboard: http://{LOCAL_BIND}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
