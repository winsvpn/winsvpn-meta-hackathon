#!/usr/bin/env python3
"""Compile strict Windows physical-test receipts into native schema v2.

This module is deliberately a compiler, not a device simulator.  It accepts
only exact-field, SHA-256-bound receipts emitted by the interactive Windows
driver and server observers.  Missing routes, mismatched installed payloads,
unrestored forcing transactions, or an incomplete teardown fail closed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import stat
import sys
import uuid
from typing import Any


MACHINE_CONTRACT = "winsvpn-windows-release-machine-evidence-v1"
NATIVE_CONTRACT = "winsvpn-native-live-smoke-v2"
SHA256_LENGTH = 64
MIN_TRAFFIC_BYTES = 96
MAX_RECEIPT_SKEW = dt.timedelta(hours=12)
BINDING_FIELDS = {
    "release_input_index_sha256",
    "platform_manifest_sha256",
    "artifact_input_fingerprint_sha256",
    "build_receipt_sha256",
    "producer_contract_sha256",
}
RECEIPT_BINDING_FIELDS = BINDING_FIELDS | {
    "collector_closure_sha256",
    "artifact_sha256",
    "step_nonce",
    "sequence",
    "started_at_utc",
    "finished_at_utc",
}
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_EVIDENCE_AGE = dt.timedelta(hours=72)
MAX_FUTURE_SKEW = dt.timedelta(minutes=5)
PE_MACHINE_X64 = 0x8664
PE_MACHINE_ARM64 = 0xAA64
PE_MACHINE_X86 = 0x014C
PE_MACHINE_NAMES = {PE_MACHINE_X64: "x64", PE_MACHINE_ARM64: "arm64"}
PE_OS_ARCHITECTURE = {"x64": "X64", "arm64": "Arm64"}
IDENTITY_CONTRACT = "winsvpn-windows-machine-identity-v1"
PAYLOAD_CONTRACT = "winsvpn-windows-payload-receipt-v1"
RUNTIME_CONTRACT = "winsvpn-windows-runtime-receipt-v1"
RUNTIME_CONTEXT_CONTRACT = "winsvpn-windows-release-runtime-context-v1"
WINN_V3_CONTRACT = "winsvpn-windows-winn-v3-receipt-v1"
WINN_V1_AWG_CONTRACT = "winsvpn-windows-winn-v1-awg-receipt-v1"
WINN_V1_XRAY_CONTRACT = "winsvpn-windows-winn-v1-xray-receipt-v1"
ARCHITECTURE_FIELDS = (
    "architecture",
    "pe_machine",
    "native_architecture",
    "os_architecture",
    "process_wow64",
)
ARCHITECTURE_RECEIPT_FIELDS = ARCHITECTURE_FIELDS + (
    "source_only",
    "release_identity",
)
ARCHITECTURE_BOUND_CONTRACTS = {
    "winsvpn-windows-signature-receipt-v1",
    "winsvpn-windows-install-receipt-v1",
    PAYLOAD_CONTRACT,
    RUNTIME_CONTRACT,
    RUNTIME_CONTEXT_CONTRACT,
    "winsvpn-windows-teardown-rollback-receipt-v1",
    IDENTITY_CONTRACT,
    WINN_V3_CONTRACT,
    WINN_V1_AWG_CONTRACT,
    WINN_V1_XRAY_CONTRACT,
}
REQUIRED_BUNDLE_CONTRACTS = (
    IDENTITY_CONTRACT,
    PAYLOAD_CONTRACT,
    RUNTIME_CONTRACT,
    WINN_V3_CONTRACT,
    WINN_V1_AWG_CONTRACT,
    WINN_V1_XRAY_CONTRACT,
)
SINGLETON_CONTRACTS = {
    MACHINE_CONTRACT,
    IDENTITY_CONTRACT,
    "winsvpn-windows-signature-receipt-v1",
    "winsvpn-windows-install-receipt-v1",
    PAYLOAD_CONTRACT,
    RUNTIME_CONTRACT,
    RUNTIME_CONTEXT_CONTRACT,
    "winsvpn-windows-route-advertisement-receipt-v1",
    "winsvpn-windows-rapid-cancel-receipt-v1",
    "winsvpn-windows-split-tunnel-receipt-v1",
    "winsvpn-windows-network-change-receipt-v1",
    "winsvpn-windows-leak-receipt-v1",
    "winsvpn-windows-release-watchdog-receipt-v1",
    "winsvpn-windows-teardown-rollback-receipt-v1",
    WINN_V3_CONTRACT,
    WINN_V1_AWG_CONTRACT,
    WINN_V1_XRAY_CONTRACT,
    "winsvpn-windows-map-receipt-v1",
}
_SECURE_BYTES: dict[pathlib.Path, bytes] = {}
_SECURE_IDENTITY: dict[pathlib.Path, tuple[int, int, int, int]] = {}
_RECEIPT_CONTEXT: dict[str, Any] | None = None
BUNDLE_CONTRACT = "winsvpn-windows-release-bundle-index-v1"


class EvidenceError(RuntimeError):
    pass


def _reject_reparse_walk(path: pathlib.Path) -> pathlib.Path:
    raw = pathlib.Path(path)
    if ".." in raw.parts:
        raise EvidenceError("Secure evidence paths may not contain parent traversal.")
    absolute = pathlib.Path(os.path.abspath(raw))
    inspected = absolute
    # macOS exposes /var as an immutable root-owned alias to /private/var.
    # Accept only that exact OS alias for cross-platform compiler tests, then
    # inspect the canonical path. Caller-controlled nested links remain fatal.
    if sys.platform == "darwin" and len(absolute.parts) > 1 and absolute.parts[1] == "var":
        alias = pathlib.Path("/var")
        alias_info = alias.lstat()
        if stat.S_ISLNK(alias_info.st_mode):
            if alias_info.st_uid != 0 or os.readlink(alias) != "private/var":
                raise EvidenceError("Secure evidence path traverses an untrusted system alias: /var")
            inspected = pathlib.Path("/private/var").joinpath(*absolute.parts[2:])
    current = pathlib.Path(inspected.anchor)
    for component in inspected.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise EvidenceError(f"Secure evidence path component is unavailable: {current}") from exc
        attributes = getattr(info, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(info.st_mode) or attributes & reparse_flag:
            raise EvidenceError(f"Secure evidence path contains a reparse point: {current}")
    return inspected


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _clear_secure_cache() -> None:
    _SECURE_BYTES.clear()
    _SECURE_IDENTITY.clear()


def _open_unreparsed_descriptor(path: pathlib.Path, label: str) -> int:
    if os.name == "nt":
        import ctypes
        import msvcrt

        class _ByHandleFileInformation(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", ctypes.c_uint32),
                ("ftCreationTimeLow", ctypes.c_uint32),
                ("ftCreationTimeHigh", ctypes.c_uint32),
                ("ftLastAccessTimeLow", ctypes.c_uint32),
                ("ftLastAccessTimeHigh", ctypes.c_uint32),
                ("ftLastWriteTimeLow", ctypes.c_uint32),
                ("ftLastWriteTimeHigh", ctypes.c_uint32),
                ("dwVolumeSerialNumber", ctypes.c_uint32),
                ("nFileSizeHigh", ctypes.c_uint32),
                ("nFileSizeLow", ctypes.c_uint32),
                ("nNumberOfLinks", ctypes.c_uint32),
                ("nFileIndexHigh", ctypes.c_uint32),
                ("nFileIndexLow", ctypes.c_uint32),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        get_info = kernel32.GetFileInformationByHandle
        get_info.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ByHandleFileInformation)]
        get_info.restype = ctypes.c_bool
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_bool
        handle = create_file(
            str(path),
            0x80000000,
            0,
            None,
            3,
            0x00200000,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in (None, invalid):
            raise EvidenceError(f"{label} could not be opened with write/delete sharing denied.")
        info = _ByHandleFileInformation()
        if not get_info(handle, ctypes.byref(info)):
            close_handle(ctypes.c_void_p(handle))
            raise EvidenceError(f"{label} handle identity is unavailable.")
        if info.dwFileAttributes & 0x400:
            close_handle(ctypes.c_void_p(handle))
            raise EvidenceError(f"{label} descriptor opened a reparse point.")
        try:
            return msvcrt.open_osfhandle(
                int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
        except OSError as exc:
            close_handle(ctypes.c_void_p(handle))
            raise EvidenceError(f"{label} descriptor could not be bound.") from exc
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"{label} could not be opened without following links.") from exc


def secure_read_once(path: pathlib.Path, *, maximum: int, label: str) -> bytes:
    inspected = _reject_reparse_walk(path)
    try:
        path_before = os.lstat(inspected)
    except OSError as exc:
        raise EvidenceError(f"{label} path is unavailable.") from exc
    cached = _SECURE_BYTES.get(inspected)
    if cached is not None:
        try:
            current = os.lstat(inspected)
        except OSError as exc:
            raise EvidenceError(f"{label} path disappeared after the first secure read.") from exc
        if _file_identity(current) != _SECURE_IDENTITY.get(inspected):
            raise EvidenceError(f"{label} changed after the first secure read.")
        return cached
    descriptor = _open_unreparsed_descriptor(inspected, label)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > maximum:
            raise EvidenceError(f"{label} is not a bounded regular file.")
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (path_before.st_dev, path_before.st_ino, path_before.st_size)
        ):
            raise EvidenceError(f"{label} descriptor does not match the unreparsed path.")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise EvidenceError(f"{label} changed while it was being read.")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise EvidenceError(f"{label} grew while it was being read.")
        after = os.fstat(descriptor)
        identity_before = _file_identity(before)
        identity_after = _file_identity(after)
        if identity_before != identity_after:
            raise EvidenceError(f"{label} identity changed while open.")
    finally:
        os.close(descriptor)
    path_after = os.lstat(inspected)
    if _file_identity(path_after) != identity_after:
        raise EvidenceError(f"{label} path identity changed after the secure read.")
    data = b"".join(chunks)
    _SECURE_BYTES[inspected] = data
    _SECURE_IDENTITY[inspected] = identity_after
    return data


def sha256_file(path: pathlib.Path) -> str:
    inspected = _reject_reparse_walk(path)
    data = _SECURE_BYTES.get(inspected)
    if data is None:
        data = secure_read_once(path, maximum=MAX_ARTIFACT_BYTES, label=str(path))
    return hashlib.sha256(data).hexdigest()


def secure_size(path: pathlib.Path) -> int:
    inspected = _reject_reparse_walk(path)
    data = _SECURE_BYTES.get(inspected)
    if data is None:
        data = secure_read_once(path, maximum=MAX_ARTIFACT_BYTES, label=str(path))
    return len(data)


def require_sha256(value: Any, label: str) -> str:
    text = str(value)
    if len(text) != SHA256_LENGTH or any(ch not in "0123456789abcdef" for ch in text):
        raise EvidenceError(f"{label} must be a lowercase SHA-256 digest.")
    return text


def require_exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise EvidenceError(f"{label} fields are invalid: {actual}")
    return value


def require_true(value: Any, label: str) -> None:
    if value is not True:
        raise EvidenceError(f"{label} must be true.")


def require_positive_int(value: Any, label: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceError(f"{label} must be an integer >= {minimum}.")
    return value


def require_port(value: Any, label: str) -> int:
    port = require_positive_int(value, label)
    if port > 65535:
        raise EvidenceError(f"{label} must be <= 65535.")
    return port


def parse_utc(value: Any, label: str = "captured_at_utc") -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{label} must be an ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"{label} must include a timezone.")
    return parsed.astimezone(dt.timezone.utc)


def require_fresh(value: dt.datetime, label: str, *, now: dt.datetime | None = None) -> None:
    current = now or dt.datetime.now(dt.timezone.utc)
    if value < current - MAX_EVIDENCE_AGE:
        raise EvidenceError(f"{label} is older than the 72-hour live-evidence window.")
    if value > current + MAX_FUTURE_SKEW:
        raise EvidenceError(f"{label} is in the future.")


def pe_architecture(data: bytes, label: str) -> str:
    if len(data) < 64 or data[:2] != b"MZ":
        raise EvidenceError(f"{label} is not a PE image.")
    pe = int.from_bytes(data[60:64], "little")
    if pe < 64 or pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        raise EvidenceError(f"{label} is not a PE32+ image.")
    machine = int.from_bytes(data[pe + 4 : pe + 6], "little")
    optional_size = int.from_bytes(data[pe + 20 : pe + 22], "little")
    optional = pe + 24
    if optional + optional_size > len(data) or optional_size < 152:
        raise EvidenceError(f"{label} has a truncated PE optional header.")
    magic = int.from_bytes(data[optional : optional + 2], "little")
    name = PE_MACHINE_NAMES.get(machine)
    if name is None or magic != 0x20B:
        raise EvidenceError(f"{label} is not PE32+ x64 or arm64.")
    directory_count = int.from_bytes(data[optional + 108 : optional + 112], "little")
    directory_base = optional + 112
    if directory_count < 5 or directory_base + 40 > optional + optional_size:
        raise EvidenceError(f"{label} lacks an Authenticode data directory.")
    cert_offset = int.from_bytes(data[directory_base + 32 : directory_base + 36], "little")
    cert_size = int.from_bytes(data[directory_base + 36 : directory_base + 40], "little")
    if cert_offset < 1 or cert_size < 8 or cert_offset + cert_size > len(data):
        raise EvidenceError(f"{label} lacks an embedded Authenticode certificate table.")
    length = int.from_bytes(data[cert_offset : cert_offset + 4], "little")
    revision = int.from_bytes(data[cert_offset + 4 : cert_offset + 6], "little")
    cert_type = int.from_bytes(data[cert_offset + 6 : cert_offset + 8], "little")
    if length < 8 or length > cert_size or revision != 0x0200 or cert_type != 0x0002:
        raise EvidenceError(f"{label} Authenticode certificate table is invalid.")
    return name


def architecture_binding_for(name: str) -> dict[str, Any]:
    if name not in PE_OS_ARCHITECTURE:
        raise EvidenceError(f"Unsupported Windows PE architecture: {name}")
    machine = next(
        value for value, label in PE_MACHINE_NAMES.items() if label == name
    )
    return {
        "architecture": name,
        "pe_machine": machine,
        "native_architecture": name,
        "os_architecture": PE_OS_ARCHITECTURE[name],
        "process_wow64": False,
    }


def require_architecture_binding(
    record: dict[str, Any],
    label: str,
    expected: dict[str, Any],
) -> None:
    if not isinstance(record, dict):
        raise EvidenceError(f"{label} omitted architecture binding.")
    if record.get("source_only") is True:
        raise EvidenceError(
            f"{label} is source-only; refusing non-physical substitution."
        )
    if any(field not in record for field in ARCHITECTURE_FIELDS):
        raise EvidenceError(f"{label} omitted architecture binding.")
    architecture = record["architecture"]
    native = record["native_architecture"]
    os_architecture = record["os_architecture"]
    pe_machine = record["pe_machine"]
    wow64 = record["process_wow64"]
    if architecture == "x86" or pe_machine == PE_MACHINE_X86:
        raise EvidenceError(f"{label} is x86/stub; refusing non-native architecture.")
    if wow64 is not False:
        raise EvidenceError(f"{label} is WOW64; refusing non-native architecture.")
    if architecture not in PE_OS_ARCHITECTURE:
        raise EvidenceError(f"{label} is not PE32+ x64 or arm64.")
    expected_machine = expected["pe_machine"]
    if (
        native != architecture
        or os_architecture != PE_OS_ARCHITECTURE[architecture]
        or isinstance(pe_machine, bool)
        or not isinstance(pe_machine, int)
        or pe_machine != next(
            value for value, label in PE_MACHINE_NAMES.items() if label == architecture
        )
    ):
        raise EvidenceError(
            f"{label} architecture is mixed, WOW64, omitted, or unsupported."
        )
    if (
        architecture != expected["architecture"]
        or native != expected["native_architecture"]
        or os_architecture != expected["os_architecture"]
        or pe_machine != expected_machine
        or wow64 is not False
    ):
        raise EvidenceError(
            f"{label} architecture is cross-candidate or inconsistent with the exact tested installer."
        )


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
    path = (root / raw).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise EvidenceError(f"{label} escaped the machine-evidence directory.") from exc
    data = secure_read_once(path, maximum=MAX_ARTIFACT_BYTES, label=label)
    expected = require_sha256(expected_sha256, f"{label} SHA-256")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise EvidenceError(f"{label} hash mismatch: expected={expected} actual={actual}")
    return path


def evidence_ref(value: Any, label: str) -> dict[str, Any]:
    return require_exact(value, {"path", "sha256"}, f"{label} reference")


def read_json_file(path: pathlib.Path, label: str) -> Any:
    try:
        data = secure_read_once(path, maximum=MAX_JSON_BYTES, label=label)
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} must be valid UTF-8 JSON.") from exc


def referenced_json(root: pathlib.Path, value: Any, label: str) -> dict[str, Any]:
    ref = evidence_ref(value, label)
    path = evidence_file(root, ref["path"], ref["sha256"], label)
    raw = read_json_file(path, label)
    if not isinstance(raw, dict):
        raise EvidenceError(f"{label} must contain one JSON object.")
    return raw


def receipt(
    root: pathlib.Path,
    value: Any,
    *,
    fields: set[str],
    contract: str,
    label: str,
    run_id: str,
    captured: dt.datetime,
) -> dict[str, Any]:
    if _RECEIPT_CONTEXT is None:
        raise EvidenceError("Receipt verification context was not initialized.")
    architecture_bound = contract in ARCHITECTURE_BOUND_CONTRACTS
    required_fields = fields | {
        "schema_version",
        "contract",
        "run_id",
        "captured_at_utc",
        "secret_material_redacted",
        "step_nonce",
        "sequence",
        "started_at_utc",
        "finished_at_utc",
        *RECEIPT_BINDING_FIELDS,
    }
    if architecture_bound:
        required_fields |= set(ARCHITECTURE_RECEIPT_FIELDS)
    raw = require_exact(
        referenced_json(root, value, label),
        required_fields,
        label,
    )
    if raw["schema_version"] != 1 or raw["contract"] != contract:
        raise EvidenceError(f"{label} contract/version is invalid.")
    if raw["run_id"] != run_id:
        raise EvidenceError(f"{label} belongs to a different live run.")
    for field in sorted(BINDING_FIELDS | {"collector_closure_sha256", "artifact_sha256"}):
        if require_sha256(raw[field], f"{label} {field}") != _RECEIPT_CONTEXT[field]:
            raise EvidenceError(f"{label} has a stale or mismatched {field}.")
    if architecture_bound:
        require_architecture_binding(
            raw, label, _RECEIPT_CONTEXT["architecture_binding"]
        )
        if raw["release_identity"] != _RECEIPT_CONTEXT["release_identity"]:
            raise EvidenceError(f"{label} release identity is stale or mixed.")
        if raw["source_only"] is not False:
            raise EvidenceError(
                f"{label} is source-only; refusing non-physical substitution."
            )
    try:
        step_nonce = uuid.UUID(str(raw["step_nonce"]))
    except ValueError as exc:
        raise EvidenceError(f"{label} step_nonce must be a UUID.") from exc
    if step_nonce.int == 0:
        raise EvidenceError(f"{label} step_nonce must not be zero.")
    require_positive_int(raw["sequence"], f"{label} sequence")
    require_true(raw["secret_material_redacted"], f"{label} secret redaction")
    timestamp = parse_utc(raw["captured_at_utc"], f"{label} captured_at_utc")
    started = parse_utc(raw["started_at_utc"], f"{label} started_at_utc")
    finished = parse_utc(raw["finished_at_utc"], f"{label} finished_at_utc")
    if finished < started or timestamp != finished:
        raise EvidenceError(f"{label} step timestamp ordering is invalid.")
    if abs(timestamp - captured) > MAX_RECEIPT_SKEW:
        raise EvidenceError(f"{label} timestamp is outside the bounded live-run window.")
    require_fresh(started, f"{label} started_at_utc")
    require_fresh(finished, f"{label} finished_at_utc")
    require_fresh(timestamp, f"{label} captured_at_utc")
    return raw


def normalize_routes(value: Any, label: str) -> tuple[list[dict[str, Any]], set[tuple[int, str]]]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise EvidenceError(f"{label} must contain between 1 and 32 routes.")
    normalized: list[dict[str, Any]] = []
    keys: set[tuple[int, str]] = set()
    for raw in value:
        route = require_exact(raw, {"protocol", "port", "security"}, label)
        if route["protocol"] != "tcp":
            raise EvidenceError(f"Every {label} must use TCP.")
        port = require_port(route["port"], f"{label} port")
        security = str(route["security"])
        if security not in {"none", "tls"}:
            raise EvidenceError(f"Every {label} security value must be none or tls.")
        key = (port, security)
        if key in keys:
            raise EvidenceError(f"Duplicate {label} values are forbidden.")
        keys.add(key)
        normalized.append({"protocol": "tcp", "port": port, "security": security})
    return normalized, keys


def validate_candidate_manifest(
    root: pathlib.Path,
    reference: Any,
    *,
    version: str,
    build: str,
    artifact_hash: str,
    artifact_size: int,
    gui_hash: str,
    gui_size: int,
    service_hash: str,
    service_size: int,
    awg_engine_hash: str,
    awg_engine_size: int,
) -> str:
    ref = evidence_ref(reference, "Candidate artifact manifest")
    path = evidence_file(root, ref["path"], ref["sha256"], "Candidate artifact manifest")
    manifest = require_exact(
        read_json_file(path, "Candidate artifact manifest"),
        {
            "schema_version",
            "created_utc",
            "release_identity",
            "internal_candidate",
            "publication_authorized",
            "stage",
            "shared_revision",
            "shared_fingerprint_sha256",
            "native_fingerprint_sha256",
            "producer_fingerprint_sha256",
            "artifact_input_fingerprint_sha256",
            "source_archive_sha256",
            "artifacts",
            "payload_entry_count",
            "payload_all_present_and_matching",
            "authenticode_status",
            "unsigned_local_candidate",
        },
        "Candidate artifact manifest",
    )
    if manifest["schema_version"] != 1 or manifest["release_identity"] != f"{version}+{build}":
        raise EvidenceError("Candidate manifest release identity is invalid.")
    parse_utc(manifest["created_utc"], "Candidate manifest created_utc")
    for field in (
        "shared_fingerprint_sha256",
        "native_fingerprint_sha256",
        "producer_fingerprint_sha256",
        "artifact_input_fingerprint_sha256",
        "source_archive_sha256",
    ):
        require_sha256(manifest[field], f"Candidate manifest {field}")
    require_true(manifest["payload_all_present_and_matching"], "Candidate payload manifest")
    require_positive_int(manifest["payload_entry_count"], "Candidate payload entry count")
    if manifest["authenticode_status"] != "Valid" or manifest["unsigned_local_candidate"] is not False:
        raise EvidenceError("Candidate manifest is not a signed Windows release candidate.")
    if not isinstance(manifest["publication_authorized"], bool):
        raise EvidenceError("Candidate manifest publication_authorized must be boolean.")
    if not isinstance(manifest["artifacts"], list) or not manifest["artifacts"]:
        raise EvidenceError("Candidate artifact list is empty.")
    artifacts: dict[str, tuple[str, int]] = {}
    for raw in manifest["artifacts"]:
        item = require_exact(raw, {"name", "sha256", "size"}, "Candidate artifact entry")
        name = str(item["name"])
        if not name or name in artifacts:
            raise EvidenceError("Candidate artifact names must be nonempty and unique.")
        artifacts[name] = (
            require_sha256(item["sha256"], f"Candidate artifact {name}"),
            require_positive_int(item["size"], f"Candidate artifact {name} size"),
        )
    expected = {
        "WinsVPN-Setup.exe": (artifact_hash, artifact_size),
        "wins_vpn.exe": (gui_hash, gui_size),
        "wins_vpn_tunnel_service.exe": (service_hash, service_size),
        "winsvpn_awg_engine.exe": (awg_engine_hash, awg_engine_size),
    }
    for name, details in expected.items():
        if artifacts.get(name) != details:
            raise EvidenceError(f"Candidate manifest {name} does not match the exact tested payload.")
    payloads = [name for name in artifacts if name.endswith(".payload-manifest.json")]
    if len(payloads) != 1:
        raise EvidenceError("Candidate manifest must bind one installer payload manifest.")
    return require_sha256(ref["sha256"], "Candidate manifest reference")


def validate_forcing(
    root: pathlib.Path,
    reference: Any,
    *,
    lane_id: str,
    required: bool,
    direct_port: int,
    run_id: str,
    captured: dt.datetime,
) -> None:
    value = receipt(
        root,
        reference,
        fields={
            "lane_id",
            "required",
            "blocked_udp_port",
            "operation_id",
            "before_state_sha256",
            "applied_state_sha256",
            "after_state_sha256",
            "apply_passed",
            "restore_passed",
            "passed",
        },
        contract="winsvpn-windows-forcing-receipt-v1",
        label=f"{lane_id} forcing receipt",
        run_id=run_id,
        captured=captured,
    )
    if value["lane_id"] != lane_id or value["required"] is not required:
        raise EvidenceError(f"{lane_id} forcing receipt contradicts its lane.")
    if require_port(value["blocked_udp_port"], f"{lane_id} blocked UDP port") != direct_port:
        raise EvidenceError(f"{lane_id} forcing did not target its mode-specific direct first hop.")
    try:
        operation = uuid.UUID(str(value["operation_id"]))
    except ValueError as exc:
        raise EvidenceError(f"{lane_id} forcing operation_id must be a UUID.") from exc
    if operation.int == 0:
        raise EvidenceError(f"{lane_id} forcing operation_id must not be zero.")
    before = require_sha256(value["before_state_sha256"], f"{lane_id} forcing before state")
    applied = require_sha256(value["applied_state_sha256"], f"{lane_id} forcing applied state")
    after = require_sha256(value["after_state_sha256"], f"{lane_id} forcing after state")
    if before != after:
        raise EvidenceError(f"{lane_id} forcing transaction did not restore exact pre-test state.")
    require_true(value["restore_passed"], f"{lane_id} forcing restore")
    require_true(value["passed"], f"{lane_id} forcing transaction")
    if required:
        require_true(value["apply_passed"], f"{lane_id} forcing apply")
        if applied == before:
            raise EvidenceError(f"{lane_id} forcing apply did not change control state.")
    elif value["apply_passed"] is not False or applied != before:
        raise EvidenceError(f"{lane_id} direct lane must not mutate forcing controls.")


def validate_lane(
    root: pathlib.Path,
    raw: Any,
    *,
    node_direct_port: int,
    core_direct_port: int,
    run_id: str,
    captured: dt.datetime,
) -> dict[str, Any]:
    lane = require_exact(
        raw,
        {
            "lane_id",
            "kind",
            "protocol",
            "port",
            "direct_first_hop_port",
            "security",
            "client_receipt",
            "server_receipt",
            "forcing_receipt",
        },
        "Windows route lane",
    )
    lane_id = str(lane["lane_id"])
    if not lane_id or len(lane_id) > 80:
        raise EvidenceError("Windows route lane_id is invalid.")
    kind = str(lane["kind"])
    if kind not in {"node_direct_awg", "node_xray", "core_direct_awg", "core_xray"}:
        raise EvidenceError(f"Unsupported Windows lane kind: {kind}")
    core = kind.startswith("core_")
    xray = kind.endswith("_xray")
    direct_port = core_direct_port if core else node_direct_port
    protocol = "tcp" if xray else "udp"
    if lane["protocol"] != protocol:
        raise EvidenceError(f"{lane_id} protocol contradicts its lane kind.")
    port = require_port(lane["port"], f"{lane_id} port")
    first_hop = require_port(lane["direct_first_hop_port"], f"{lane_id} direct first hop")
    if first_hop != direct_port or (not xray and port != direct_port):
        raise EvidenceError(f"{lane_id} is not bound to its observed mode-specific direct UDP port.")
    security = str(lane["security"])
    if security not in ({"none", "tls"} if xray else {"none"}):
        raise EvidenceError(f"{lane_id} security value is invalid.")

    client = receipt(
        root,
        lane["client_receipt"],
        fields={
            "lane_id",
            "kind",
            "protocol",
            "port",
            "direct_first_hop_port",
            "security",
            "connect_label",
            "connect_role",
            "disconnect_label",
            "disconnect_role",
            "native_active_observed",
            "manager_running",
            "awg_engine_running",
            "legacy_tunnel_service_absent",
            "adapter_up",
            "protected_route_present",
            "xray_process_observed",
            "rx_bytes_delta",
            "tx_bytes_delta",
            "protected_egress_sha256",
            "normal_teardown_proven",
            "residual_awg_engine_absent",
            "residual_legacy_service_absent",
            "residual_adapter_absent",
            "residual_xray_absent",
            "residual_routes_absent",
            "passed",
        },
        contract="winsvpn-windows-client-route-receipt-v1",
        label=f"{lane_id} client route receipt",
        run_id=run_id,
        captured=captured,
    )
    for field in ("lane_id", "kind", "protocol", "port", "direct_first_hop_port", "security"):
        if client[field] != lane[field]:
            raise EvidenceError(f"{lane_id} client receipt {field} contradicts the lane.")
    if (
        client["connect_label"] != "Connect VPN"
        or client["connect_role"] != 43
        or client["disconnect_label"] != "Disconnect VPN"
        or client["disconnect_role"] != 43
    ):
        raise EvidenceError(f"{lane_id} lacks exact semantic Connect/Disconnect UI proof.")
    for field in (
        "native_active_observed",
        "manager_running",
        "awg_engine_running",
        "legacy_tunnel_service_absent",
        "adapter_up",
        "protected_route_present",
        "normal_teardown_proven",
        "residual_awg_engine_absent",
        "residual_legacy_service_absent",
        "residual_adapter_absent",
        "residual_xray_absent",
        "residual_routes_absent",
        "passed",
    ):
        require_true(client[field], f"{lane_id} client {field}")
    if client["xray_process_observed"] is not xray:
        raise EvidenceError(f"{lane_id} Xray process observation contradicts its route kind.")
    for field in ("rx_bytes_delta", "tx_bytes_delta"):
        require_positive_int(client[field], f"{lane_id} client {field}", MIN_TRAFFIC_BYTES)
    require_sha256(client["protected_egress_sha256"], f"{lane_id} protected egress")

    server = receipt(
        root,
        lane["server_receipt"],
        fields={
            "lane_id",
            "scope",
            "protocol",
            "port",
            "direct_first_hop_port",
            "security",
            "entry_ingress_packets",
            "exit_egress_packets",
            "handshake_advanced",
            "rx_bytes_delta",
            "tx_bytes_delta",
            "xray_upgrade_observed",
            "suricata_drop_count",
            "observer_identity_sha256",
            "observer_host_key_sha256",
            "peer_public_key_sha256",
            "allowed_ip_set_sha256",
            "observation_window_nonce",
            "entry_counter_before_sha256",
            "entry_counter_after_sha256",
            "exit_counter_before_sha256",
            "exit_counter_after_sha256",
            "suricata_ruleset_sha256",
            "expected_exit_identity_sha256",
            "observer_authenticated",
            "peer_bound",
            "expected_exit_observed",
            "passed",
        },
        contract="winsvpn-windows-server-route-receipt-v1",
        label=f"{lane_id} server route receipt",
        run_id=run_id,
        captured=captured,
    )
    expected_scope = "core" if core else "node"
    expected_server = {
        "lane_id": lane_id,
        "scope": expected_scope,
        "protocol": protocol,
        "port": port,
        "direct_first_hop_port": direct_port,
        "security": security,
    }
    for field, expected in expected_server.items():
        if server[field] != expected:
            raise EvidenceError(f"{lane_id} server receipt {field} contradicts the lane.")
    require_positive_int(server["entry_ingress_packets"], f"{lane_id} entry packets")
    require_positive_int(server["exit_egress_packets"], f"{lane_id} exit packets")
    require_true(server["handshake_advanced"], f"{lane_id} server handshake")
    require_positive_int(server["rx_bytes_delta"], f"{lane_id} server RX", MIN_TRAFFIC_BYTES)
    require_positive_int(server["tx_bytes_delta"], f"{lane_id} server TX", MIN_TRAFFIC_BYTES)
    if server["xray_upgrade_observed"] is not xray:
        raise EvidenceError(f"{lane_id} server Xray upgrade observation contradicts route kind.")
    if server["suricata_drop_count"] != 0:
        raise EvidenceError(f"{lane_id} recorded a Suricata drop during the valid route test.")
    for field in (
        "observer_identity_sha256",
        "observer_host_key_sha256",
        "peer_public_key_sha256",
        "allowed_ip_set_sha256",
        "entry_counter_before_sha256",
        "entry_counter_after_sha256",
        "exit_counter_before_sha256",
        "exit_counter_after_sha256",
        "suricata_ruleset_sha256",
        "expected_exit_identity_sha256",
    ):
        require_sha256(server[field], f"{lane_id} server {field}")
    try:
        window_nonce = uuid.UUID(str(server["observation_window_nonce"]))
    except ValueError as exc:
        raise EvidenceError(f"{lane_id} server observation window nonce must be a UUID.") from exc
    if window_nonce.int == 0:
        raise EvidenceError(f"{lane_id} server observation window nonce must not be zero.")
    if (
        server["entry_counter_before_sha256"] == server["entry_counter_after_sha256"]
        or server["exit_counter_before_sha256"] == server["exit_counter_after_sha256"]
    ):
        raise EvidenceError(f"{lane_id} server counter window did not change.")
    for field in ("observer_authenticated", "peer_bound", "expected_exit_observed"):
        require_true(server[field], f"{lane_id} server {field}")
    require_true(server["passed"], f"{lane_id} server route")
    validate_forcing(
        root,
        lane["forcing_receipt"],
        lane_id=lane_id,
        required=xray,
        direct_port=direct_port,
        run_id=run_id,
        captured=captured,
    )
    return lane


def compile_evidence(
    machine: dict[str, Any],
    root: pathlib.Path,
    artifact: pathlib.Path,
    map_screenshot: pathlib.Path | None = None,
    expected_bindings: dict[str, str] | None = None,
) -> dict[str, Any]:
    top = require_exact(
        machine,
        {
            "schema_version",
            "contract",
            "platform",
            "app_version",
            "build_number",
            "run_id",
            "captured_at_utc",
            "secret_material_redacted",
            "step_nonce",
            "sequence",
            "started_at_utc",
            "finished_at_utc",
            *BINDING_FIELDS,
            "collector_closure_sha256",
            "artifact_sha256",
            "artifact_size_bytes",
            "installed_gui_sha256",
            "installed_gui_size_bytes",
            "installed_service_sha256",
            "installed_service_size_bytes",
            "installed_awg_engine_sha256",
            "installed_awg_engine_size_bytes",
            "architecture",
            "pe_machine",
            "native_architecture",
            "os_architecture",
            "process_wow64",
            "candidate_manifest",
            "signature_receipt",
            "install_receipt",
            "payload_receipt",
            "runtime_receipt",
            "route_advertisement_receipt",
            "node_direct_awg_port",
            "core_direct_awg_port",
            "node_advertised_xray_routes",
            "core_advertised_xray_routes",
            "lanes",
            "rapid_cancel_receipt",
            "split_tunnel_receipt",
            "network_change_receipt",
            "leak_receipt",
            "watchdog_receipt",
            "teardown_rollback_receipt",
            "map_receipt",
        },
        "Windows machine evidence",
    )
    if top["schema_version"] != 1 or top["contract"] != MACHINE_CONTRACT or top["platform"] != "windows":
        raise EvidenceError("Windows machine-evidence contract/version/platform is invalid.")
    version = str(top["app_version"])
    if not version or any(not part.isdigit() for part in version.split(".")) or len(version.split(".")) != 3:
        raise EvidenceError("Windows app_version must use numeric major.minor.patch format.")
    build = str(top["build_number"])
    if not build.isdigit():
        raise EvidenceError("Windows build_number must be a decimal string.")
    try:
        run_uuid = uuid.UUID(str(top["run_id"]))
    except ValueError as exc:
        raise EvidenceError("Windows machine-evidence run_id must be a UUID.") from exc
    if run_uuid.int == 0:
        raise EvidenceError("Windows machine-evidence run_id must not be zero.")
    run_id = str(run_uuid)
    captured = parse_utc(top["captured_at_utc"])
    try:
        machine_nonce = uuid.UUID(str(top["step_nonce"]))
    except ValueError as exc:
        raise EvidenceError("Windows machine-evidence step_nonce must be a UUID.") from exc
    if machine_nonce.int == 0:
        raise EvidenceError("Windows machine-evidence step_nonce must not be zero.")
    require_positive_int(top["sequence"], "Windows machine-evidence sequence")
    started = parse_utc(top["started_at_utc"], "Windows machine-evidence started_at_utc")
    finished = parse_utc(top["finished_at_utc"], "Windows machine-evidence finished_at_utc")
    if finished < started or captured != finished:
        raise EvidenceError("Windows machine-evidence timestamp ordering is invalid.")
    require_fresh(started, "Windows machine-evidence started_at_utc")
    require_fresh(finished, "Windows machine-evidence finished_at_utc")
    require_fresh(captured, "Windows machine-evidence captured_at_utc")
    require_true(top["secret_material_redacted"], "Windows machine secret redaction")
    if expected_bindings is None or set(expected_bindings) != BINDING_FIELDS:
        raise EvidenceError("Independent release/build/producer bindings are required.")
    for field in sorted(BINDING_FIELDS):
        machine_digest = require_sha256(top[field], f"Windows machine {field}")
        expected_digest = require_sha256(expected_bindings[field], f"Expected {field}")
        if machine_digest != expected_digest:
            raise EvidenceError(f"Windows machine evidence has stale or mismatched {field}.")
    collector_closure = require_sha256(
        top["collector_closure_sha256"], "Windows collector closure"
    )

    artifact_bytes = secure_read_once(
        artifact, maximum=MAX_ARTIFACT_BYTES, label="Exact Windows installer"
    )
    artifact_hash = require_sha256(top["artifact_sha256"], "Windows installer")
    artifact_size = require_positive_int(top["artifact_size_bytes"], "Windows installer size")
    if sha256_file(artifact) != artifact_hash or secure_size(artifact) != artifact_size:
        raise EvidenceError("Machine evidence is not bound to the exact Windows installer.")
    artifact_architecture = pe_architecture(artifact_bytes, "Exact Windows installer")
    architecture_binding = architecture_binding_for(artifact_architecture)
    require_architecture_binding(
        top, "Windows machine evidence", architecture_binding
    )
    global _RECEIPT_CONTEXT
    _RECEIPT_CONTEXT = {
        **{field: require_sha256(top[field], f"Windows machine {field}") for field in BINDING_FIELDS},
        "collector_closure_sha256": collector_closure,
        "artifact_sha256": artifact_hash,
        "architecture": artifact_architecture,
        "architecture_binding": architecture_binding,
        "release_identity": f"{version}+{build}",
    }
    gui_hash = require_sha256(top["installed_gui_sha256"], "Installed GUI")
    gui_size = require_positive_int(top["installed_gui_size_bytes"], "Installed GUI size")
    service_hash = require_sha256(top["installed_service_sha256"], "Installed service")
    service_size = require_positive_int(top["installed_service_size_bytes"], "Installed service size")
    awg_engine_hash = require_sha256(
        top["installed_awg_engine_sha256"], "Installed AWG engine"
    )
    awg_engine_size = require_positive_int(
        top["installed_awg_engine_size_bytes"], "Installed AWG engine size"
    )
    manifest_hash = validate_candidate_manifest(
        root,
        top["candidate_manifest"],
        version=version,
        build=build,
        artifact_hash=artifact_hash,
        artifact_size=artifact_size,
        gui_hash=gui_hash,
        gui_size=gui_size,
        service_hash=service_hash,
        service_size=service_size,
        awg_engine_hash=awg_engine_hash,
        awg_engine_size=awg_engine_size,
    )

    signature = receipt(
        root,
        top["signature_receipt"],
        fields={
            "artifact_sha256",
            "artifact_size_bytes",
            "authenticode_status",
            "signer_certificate_sha256",
            "timestamp_certificate_sha256",
            "signature_verified",
            "timestamp_verified",
        },
        contract="winsvpn-windows-signature-receipt-v1",
        label="Windows signature receipt",
        run_id=run_id,
        captured=captured,
    )
    if signature["artifact_sha256"] != artifact_hash or signature["artifact_size_bytes"] != artifact_size:
        raise EvidenceError("Windows signature receipt does not match the exact installer.")
    if signature["authenticode_status"] != "Valid":
        raise EvidenceError("Windows signature receipt is not Valid.")
    require_sha256(signature["signer_certificate_sha256"], "Windows signer certificate")
    require_sha256(signature["timestamp_certificate_sha256"], "Windows timestamp certificate")
    require_true(signature["signature_verified"], "Windows signature verification")
    require_true(signature["timestamp_verified"], "Windows timestamp verification")

    install = receipt(
        root,
        top["install_receipt"],
        fields={
            "artifact_sha256",
            "candidate_manifest_sha256",
            "previous_version_uninstalled",
            "install_exit_code",
            "installed_gui_sha256",
            "installed_gui_size_bytes",
            "installed_service_sha256",
            "installed_service_size_bytes",
            "installed_awg_engine_sha256",
            "installed_awg_engine_size_bytes",
            "manager_service_running",
            "gui_launched",
            "passed",
        },
        contract="winsvpn-windows-install-receipt-v1",
        label="Windows clean-install receipt",
        run_id=run_id,
        captured=captured,
    )
    install_expected = {
        "artifact_sha256": artifact_hash,
        "candidate_manifest_sha256": manifest_hash,
        "installed_gui_sha256": gui_hash,
        "installed_gui_size_bytes": gui_size,
        "installed_service_sha256": service_hash,
        "installed_service_size_bytes": service_size,
        "installed_awg_engine_sha256": awg_engine_hash,
        "installed_awg_engine_size_bytes": awg_engine_size,
    }
    for field, expected in install_expected.items():
        if install[field] != expected:
            raise EvidenceError(f"Windows install receipt {field} contradicts machine evidence.")
    require_true(install["previous_version_uninstalled"], "Windows clean uninstall")
    if install["install_exit_code"] != 0:
        raise EvidenceError("Windows installer did not return exit code zero.")
    for field in ("manager_service_running", "gui_launched", "passed"):
        require_true(install[field], f"Windows install {field}")

    payload = receipt(
        root,
        top["payload_receipt"],
        fields={
            "candidate_payload_manifest_sha256",
            "payload_snapshot_index_sha256",
            "payload_entry_count",
            "payload_pe_count",
            "payload_pe_verified",
            "mixed_architecture",
            "passed",
        },
        contract=PAYLOAD_CONTRACT,
        label="Windows payload receipt",
        run_id=run_id,
        captured=captured,
    )
    require_sha256(
        payload["candidate_payload_manifest_sha256"],
        "Windows payload manifest",
    )
    require_sha256(
        payload["payload_snapshot_index_sha256"],
        "Windows payload snapshot index",
    )
    require_positive_int(payload["payload_entry_count"], "Windows payload entry count")
    require_positive_int(payload["payload_pe_count"], "Windows payload PE count")
    if payload["payload_pe_count"] > payload["payload_entry_count"]:
        raise EvidenceError("Windows payload PE count exceeds the payload entry count.")
    require_true(payload["payload_pe_verified"], "Windows payload PE verification")
    if payload["mixed_architecture"] is not False:
        raise EvidenceError("Windows payload receipt architecture is mixed.")
    require_true(payload["passed"], "Windows payload receipt")

    runtime = receipt(
        root,
        top["runtime_receipt"],
        fields={"runtime_observed", "passed"},
        contract=RUNTIME_CONTRACT,
        label="Windows runtime receipt",
        run_id=run_id,
        captured=captured,
    )
    require_true(runtime["runtime_observed"], "Windows runtime observation")
    require_true(runtime["passed"], "Windows runtime receipt")

    node_port = require_port(top["node_direct_awg_port"], "Node direct AWG port")
    core_port = require_port(top["core_direct_awg_port"], "Core direct AWG port")
    if node_port != 9110:
        raise EvidenceError("The public node direct AWG route must use UDP 9110.")
    if core_port == node_port:
        raise EvidenceError("The machine-observed Core first hop must remain distinct from node UDP 9110.")
    node_routes, node_keys = normalize_routes(top["node_advertised_xray_routes"], "node advertised Xray route")
    _, core_keys = normalize_routes(top["core_advertised_xray_routes"], "Core advertised Xray route")
    required_xray_routes = {(80, "none"), (443, "tls")}
    if not required_xray_routes.issubset(node_keys) or not required_xray_routes.issubset(core_keys):
        raise EvidenceError(
            "Node and Core advertisements must each include TCP 80/none and TCP 443/tls."
        )
    advertisement = receipt(
        root,
        top["route_advertisement_receipt"],
        fields={
            "node_direct_awg_port",
            "core_direct_awg_port",
            "node_advertised_xray_routes",
            "core_advertised_xray_routes",
            "node_registration_sha256",
            "core_assignment_sha256",
            "api_response_sha256",
            "passed",
        },
        contract="winsvpn-windows-route-advertisement-receipt-v1",
        label="Windows route-advertisement receipt",
        run_id=run_id,
        captured=captured,
    )
    if (
        advertisement["node_direct_awg_port"] != node_port
        or advertisement["core_direct_awg_port"] != core_port
        or advertisement["node_advertised_xray_routes"] != top["node_advertised_xray_routes"]
        or advertisement["core_advertised_xray_routes"] != top["core_advertised_xray_routes"]
    ):
        raise EvidenceError("Route-advertisement receipt contradicts machine route inputs.")
    for field in ("node_registration_sha256", "core_assignment_sha256", "api_response_sha256"):
        require_sha256(advertisement[field], f"Advertisement {field}")
    require_true(advertisement["passed"], "Route advertisement")

    if not isinstance(top["lanes"], list):
        raise EvidenceError("Windows route lanes must be a list.")
    lanes = [
        validate_lane(
            root,
            lane,
            node_direct_port=node_port,
            core_direct_port=core_port,
            run_id=run_id,
            captured=captured,
        )
        for lane in top["lanes"]
    ]
    lane_ids = [str(lane["lane_id"]) for lane in lanes]
    if len(lane_ids) != len(set(lane_ids)):
        raise EvidenceError("Windows route lane IDs must be unique.")
    kinds = [str(lane["kind"]) for lane in lanes]
    for direct_kind in ("node_direct_awg", "core_direct_awg"):
        if kinds.count(direct_kind) != 1:
            raise EvidenceError(f"Exactly one {direct_kind} lane is required.")
    tested_node = {(lane["port"], lane["security"]) for lane in lanes if lane["kind"] == "node_xray"}
    tested_core = {(lane["port"], lane["security"]) for lane in lanes if lane["kind"] == "core_xray"}
    if tested_node != node_keys or kinds.count("node_xray") != len(node_keys):
        raise EvidenceError("Every node-advertised Xray route must have exactly one live lane.")
    if tested_core != core_keys or kinds.count("core_xray") != len(core_keys):
        raise EvidenceError("Every Core-advertised Xray route must have exactly one live lane.")
    observer_scope: dict[str, dict[str, str]] = {}
    for lane in top["lanes"]:
        server_raw = referenced_json(root, lane["server_receipt"], "Bound server receipt")
        scope = str(server_raw["scope"])
        coherent = {
            field: str(server_raw[field])
            for field in (
                "observer_identity_sha256",
                "observer_host_key_sha256",
                "peer_public_key_sha256",
                "allowed_ip_set_sha256",
                "suricata_ruleset_sha256",
                "expected_exit_identity_sha256",
            )
        }
        if scope in observer_scope and observer_scope[scope] != coherent:
            raise EvidenceError(
                f"Windows {scope} lanes do not share one pinned observer/peer/exit identity."
            )
        observer_scope[scope] = coherent

    rapid = receipt(
        root,
        top["rapid_cancel_receipt"],
        fields={
            "connect_label",
            "connect_role",
            "cancel_label",
            "cancel_role",
            "cancel_before_native_active",
            "late_restart_absent",
            "reconnect_passed",
            "disconnect_label",
            "disconnect_role",
            "clean_state_proven",
            "passed",
        },
        contract="winsvpn-windows-rapid-cancel-receipt-v1",
        label="Windows rapid-cancel receipt",
        run_id=run_id,
        captured=captured,
    )
    semantic_expected = {
        "connect_label": "Connect VPN",
        "connect_role": 43,
        "cancel_label": "Cancel VPN connection",
        "cancel_role": 43,
        "disconnect_label": "Disconnect VPN",
        "disconnect_role": 43,
    }
    for field, expected in semantic_expected.items():
        if rapid[field] != expected:
            raise EvidenceError(f"Rapid-cancel semantic field {field} is invalid.")
    for field in (
        "cancel_before_native_active",
        "late_restart_absent",
        "reconnect_passed",
        "clean_state_proven",
        "passed",
    ):
        require_true(rapid[field], f"Rapid-cancel {field}")

    split = receipt(
        root,
        top["split_tunnel_receipt"],
        fields={
            "excluded_executable_sha256",
            "protected_executable_sha256",
            "baseline_egress_sha256",
            "excluded_egress_sha256",
            "protected_egress_sha256",
            "selection_ui_sha256",
            "wfp_service_running",
            "process_rule_observed",
            "rollback_clean",
            "passed",
        },
        contract="winsvpn-windows-split-tunnel-receipt-v1",
        label="Windows split-tunnel receipt",
        run_id=run_id,
        captured=captured,
    )
    for field in (
        "excluded_executable_sha256",
        "protected_executable_sha256",
        "baseline_egress_sha256",
        "excluded_egress_sha256",
        "protected_egress_sha256",
        "selection_ui_sha256",
    ):
        require_sha256(split[field], f"Split {field}")
    if split["excluded_executable_sha256"] == split["protected_executable_sha256"]:
        raise EvidenceError("Split proof must use distinct excluded and protected executables.")
    if (
        split["excluded_egress_sha256"] != split["baseline_egress_sha256"]
        or split["protected_egress_sha256"] == split["baseline_egress_sha256"]
    ):
        raise EvidenceError("Windows split egress does not prove bypass-versus-protected routing.")
    for field in ("wfp_service_running", "process_rule_observed", "rollback_clean", "passed"):
        require_true(split[field], f"Split {field}")

    network = receipt(
        root,
        top["network_change_receipt"],
        fields={"profiles", "final_route_restored", "final_dns_restored", "passed"},
        contract="winsvpn-windows-network-change-receipt-v1",
        label="Windows network-change receipt",
        run_id=run_id,
        captured=captured,
    )
    expected_profiles = {"wifi_to_ethernet", "ethernet_to_wifi", "dhcp_renew", "ipv6_recovery"}
    if not isinstance(network["profiles"], list) or len(network["profiles"]) != len(expected_profiles):
        raise EvidenceError("Windows network-change receipt must contain the four mandatory profiles.")
    seen_profiles: set[str] = set()
    for raw_profile in network["profiles"]:
        profile = require_exact(
            raw_profile,
            {"name", "transition_observed", "protected_egress_sha256", "dns_protected", "passed"},
            "Windows network-change profile",
        )
        name = str(profile["name"])
        if name in seen_profiles:
            raise EvidenceError("Windows network-change profiles must be unique.")
        seen_profiles.add(name)
        require_sha256(profile["protected_egress_sha256"], f"Network profile {name} egress")
        for field in ("transition_observed", "dns_protected", "passed"):
            require_true(profile[field], f"Network profile {name} {field}")
    if seen_profiles != expected_profiles:
        raise EvidenceError("Windows network-change profile set is incomplete.")
    for field in ("final_route_restored", "final_dns_restored", "passed"):
        require_true(network[field], f"Network change {field}")

    leak = receipt(
        root,
        top["leak_receipt"],
        fields={
            "tunnel_dns_sha256",
            "protected_canary_count",
            "dns_leak_passed",
            "ipv4_leak_passed",
            "ipv6_leak_passed",
            "kill_switch_passed",
            "passed",
        },
        contract="winsvpn-windows-leak-receipt-v1",
        label="Windows leak receipt",
        run_id=run_id,
        captured=captured,
    )
    require_sha256(leak["tunnel_dns_sha256"], "Windows tunnel DNS")
    require_positive_int(leak["protected_canary_count"], "Windows protected canary count", 2)
    for field in ("dns_leak_passed", "ipv4_leak_passed", "ipv6_leak_passed", "kill_switch_passed", "passed"):
        require_true(leak[field], f"Windows leak {field}")

    watchdog = receipt(
        root,
        top["watchdog_receipt"],
        fields={
            "normal_teardown_proven",
            "fail_safe_triggered",
            "baseline_state_sha256",
            "final_state_sha256",
            "dns_restored",
            "lan_management_restored",
            "egress_restored",
            "pass",
        },
        contract="winsvpn-windows-release-watchdog-receipt-v1",
        label="Windows fixed watchdog receipt",
        run_id=run_id,
        captured=captured,
    )
    if (
        watchdog["baseline_state_sha256"]
        != watchdog["final_state_sha256"]
        or watchdog["fail_safe_triggered"] is not False
    ):
        raise EvidenceError("Windows watchdog used emergency cleanup or did not restore exact state.")
    for field in (
        "normal_teardown_proven",
        "dns_restored",
        "lan_management_restored",
        "egress_restored",
        "pass",
    ):
        require_true(watchdog[field], f"Windows watchdog {field}")
    for field in ("baseline_state_sha256", "final_state_sha256"):
        require_sha256(watchdog[field], f"Windows watchdog {field}")

    teardown = receipt(
        root,
        top["teardown_rollback_receipt"],
        fields={
            "baseline_route_sha256",
            "final_route_sha256",
            "baseline_egress_sha256",
            "final_egress_sha256",
            "manager_running",
            "legacy_tunnel_service_absent",
            "awg_engine_absent",
            "split_service_absent",
            "adapter_absent_or_down",
            "xray_absent",
            "protected_routes_absent",
            "rollback_artifact_path",
            "rollback_artifact_sha256",
            "previous_release_record_path",
            "previous_release_record_sha256",
            "previous_payload_manifest_path",
            "previous_payload_manifest_sha256",
            "previous_signer_certificate_sha256",
            "rollback_signature_verified",
            "rollback_payload_verified",
            "rollback_owner_authorization_verified",
            "rollback_install_passed",
            "candidate_reinstall_passed",
            "final_installed_gui_sha256",
            "final_installed_service_sha256",
            "final_installed_awg_engine_sha256",
            "passed",
        },
        contract="winsvpn-windows-teardown-rollback-receipt-v1",
        label="Windows teardown/rollback receipt",
        run_id=run_id,
        captured=captured,
    )
    baseline_route = require_sha256(teardown["baseline_route_sha256"], "Baseline route state")
    final_route = require_sha256(teardown["final_route_sha256"], "Final route state")
    baseline_egress = require_sha256(teardown["baseline_egress_sha256"], "Baseline public egress")
    final_egress = require_sha256(teardown["final_egress_sha256"], "Final public egress")
    if baseline_route != final_route or baseline_egress != final_egress:
        raise EvidenceError("Windows teardown did not restore exact route and egress state.")
    rollback_path = evidence_file(
        root,
        teardown["rollback_artifact_path"],
        teardown["rollback_artifact_sha256"],
        "Preserved Windows rollback artifact",
    )
    if secure_size(rollback_path) < 1024:
        raise EvidenceError("Preserved Windows rollback artifact is implausibly small.")
    rollback_architecture = pe_architecture(
        secure_read_once(
            rollback_path,
            maximum=MAX_ARTIFACT_BYTES,
            label="Preserved Windows rollback artifact",
        ),
        "Preserved Windows rollback artifact",
    )
    if rollback_architecture != artifact_architecture:
        raise EvidenceError(
            "Windows rollback artifact architecture does not match the exact tested installer."
        )
    previous_record = require_exact(
        referenced_json(
            root,
            {
                "path": teardown["previous_release_record_path"],
                "sha256": teardown["previous_release_record_sha256"],
            },
            "Protected previous-release record",
        ),
        {
            "schema_version",
            "contract",
            "release_identity",
            "artifact_sha256",
            "artifact_size_bytes",
            "payload_manifest_sha256",
            "signer_certificate_sha256",
            "owner_authorization_content_sha256",
            "owner_authorization_cms_sha256",
        },
        "Protected previous-release record",
    )
    if (
        previous_record["schema_version"] != 1
        or previous_record["contract"] != "winsvpn-windows-previous-release-record-v1"
        or not str(previous_record["release_identity"])
        or require_sha256(previous_record["artifact_sha256"], "Previous artifact hash")
        != teardown["rollback_artifact_sha256"]
        or require_positive_int(previous_record["artifact_size_bytes"], "Previous artifact size")
        != secure_size(rollback_path)
        or require_sha256(
            previous_record["signer_certificate_sha256"], "Previous signer certificate"
        )
        != require_sha256(
            teardown["previous_signer_certificate_sha256"], "Rollback signer certificate"
        )
    ):
        raise EvidenceError("Protected previous-release record does not bind the rollback artifact.")
    for field in (
        "payload_manifest_sha256",
        "owner_authorization_content_sha256",
        "owner_authorization_cms_sha256",
    ):
        require_sha256(previous_record[field], f"Previous-release record {field}")
    previous_payload_path = evidence_file(
        root,
        teardown["previous_payload_manifest_path"],
        teardown["previous_payload_manifest_sha256"],
        "Previous payload manifest",
    )
    previous_payload = read_json_file(previous_payload_path, "Previous payload manifest")
    if (
        require_sha256(
            teardown["previous_payload_manifest_sha256"],
            "Previous payload manifest reference",
        )
        != previous_record["payload_manifest_sha256"]
        or not isinstance(previous_payload, dict)
        or previous_payload.get("schema_version") != 2
        or not isinstance(previous_payload.get("installer"), dict)
        or require_sha256(
            previous_payload["installer"].get("sha256"),
            "Previous payload installer",
        )
        != teardown["rollback_artifact_sha256"]
        or require_positive_int(
            previous_payload["installer"].get("size"),
            "Previous payload installer size",
        )
        != secure_size(rollback_path)
        or not isinstance(previous_payload.get("payload"), list)
        or not previous_payload["payload"]
    ):
        raise EvidenceError("Previous payload manifest does not bind the rollback installer.")
    if (
        teardown["final_installed_gui_sha256"] != gui_hash
        or teardown["final_installed_service_sha256"] != service_hash
        or teardown["final_installed_awg_engine_sha256"] != awg_engine_hash
    ):
        raise EvidenceError("Windows rollback test did not finish on the exact candidate payload.")
    for field in (
        "manager_running",
        "legacy_tunnel_service_absent",
        "awg_engine_absent",
        "split_service_absent",
        "adapter_absent_or_down",
        "xray_absent",
        "protected_routes_absent",
        "rollback_install_passed",
        "candidate_reinstall_passed",
        "rollback_signature_verified",
        "rollback_payload_verified",
        "rollback_owner_authorization_verified",
        "passed",
    ):
        require_true(teardown[field], f"Windows teardown {field}")

    map_value = receipt(
        root,
        top["map_receipt"],
        fields={
            "screenshot_path",
            "screenshot_sha256",
            "radius_miles",
            "city_labels_visible",
            "target_marker_visible",
            "viewport_not_world_zoom",
            "passed",
        },
        contract="winsvpn-windows-map-receipt-v1",
        label="Windows map receipt",
        run_id=run_id,
        captured=captured,
    )
    screenshot = evidence_file(root, map_value["screenshot_path"], map_value["screenshot_sha256"], "Windows map screenshot")
    if secure_size(screenshot) < 1024:
        raise EvidenceError("Windows map screenshot is implausibly small.")
    if map_screenshot is not None and map_screenshot.resolve() != screenshot.resolve():
        raise EvidenceError("Public wrapper map screenshot is not the exact receipt-bound map file.")
    if map_value["radius_miles"] != 50:
        raise EvidenceError("Windows map radius must be exactly 50 miles.")
    for field in ("city_labels_visible", "target_marker_visible", "viewport_not_world_zoom", "passed"):
        require_true(map_value[field], f"Windows map {field}")

    tested_node_routes = [
        {"protocol": "tcp", "port": port, "security": security, "passed": True}
        for port, security in sorted(node_keys)
    ]
    return {
        "schema_version": 2,
        "contract": NATIVE_CONTRACT,
        "platform": "windows",
        "app_version": version,
        "build_number": build,
        "artifact_sha256": artifact_hash,
        "run_id": run_id,
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
            "screenshot_sha256": map_value["screenshot_sha256"],
            "radius_miles": 50,
            "city_labels_visible": True,
            "target_marker_visible": True,
            "viewport_not_world_zoom": True,
        },
        "direct_awg": {"protocol": "udp", "port": node_port, "passed": True},
        "advertised_xray_routes": sorted(node_routes, key=lambda item: (item["port"], item["security"])),
        "tested_xray_routes": tested_node_routes,
        "windows_matrix": {
            "rapid_connect_cancel_no_late_restart": True,
            "reconnect_after_cancel": True,
            "dynamic_xray_awg_fallback": True,
            "per_app_split_tunneling": True,
            "wifi_ethernet_dhcp_ipv6_recovery": True,
            "leak_protection": True,
            "disconnect_teardown": True,
            "rollback": True,
        },
    }


def _deny_sensitive_json(value: Any, label: str, key_path: str = "") -> None:
    denied_keys = re.compile(
        r"(?:^|_)(?:password|passphrase|token|secret|private_key|preshared_key|"
        r"ssh_host|hub_ip|control_hub|xray_uuid|xray_path|raw_host)(?:$|_)",
        re.IGNORECASE,
    )
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key)
            if len(name) > 128 or (
                name != "secret_material_redacted" and denied_keys.search(name)
            ):
                raise EvidenceError(f"{label} contains a forbidden sensitive field: {key_path}{name}")
            _deny_sensitive_json(child, label, f"{key_path}{name}.")
    elif isinstance(value, list):
        if len(value) > 2048:
            raise EvidenceError(f"{label} contains an oversized list.")
        for index, child in enumerate(value):
            _deny_sensitive_json(child, label, f"{key_path}{index}.")
    elif isinstance(value, str):
        if len(value) > 8192:
            raise EvidenceError(f"{label} contains an oversized string.")
        for candidate in re.findall(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", value):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if address.is_global:
                raise EvidenceError(f"{label} contains a forbidden public IP address.")
        if re.search(r"https?://|ssh://", value, re.IGNORECASE):
            raise EvidenceError(f"{label} contains a forbidden raw network URL.")


def _validate_machine_identity(
    identity: dict[str, Any],
    artifact_hash: str,
    architecture_binding: dict[str, Any],
    closure: str,
    run_id: str,
    release_identity: str,
) -> None:
    if identity.get("source_only") is not False:
        raise EvidenceError(
            "Windows machine-identity is source-only; refusing non-physical substitution."
        )
    if (
        identity.get("run_id") != run_id
        or identity.get("collector_closure_sha256") != closure
        or identity.get("artifact_sha256") != artifact_hash
        or identity.get("release_identity") != release_identity
    ):
        raise EvidenceError(
            "Windows machine-identity does not bind this live x64/arm64 host and artifact."
        )
    require_architecture_binding(
        identity, "Windows machine-identity", architecture_binding
    )
    require_sha256(identity.get("machine_guid_sha256"), "Windows machine GUID")
    require_true(identity.get("secret_material_redacted"), "Windows machine-identity redaction")
    require_fresh(
        parse_utc(identity.get("captured_at_utc"), "Windows machine-identity captured_at_utc"),
        "Windows machine-identity captured_at_utc",
    )


def _unique_contract(
    loaded_json: dict[str, dict[str, Any]],
    contract: str,
    label: str,
) -> dict[str, Any]:
    matches = [
        value for value in loaded_json.values() if value.get("contract") == contract
    ]
    if len(matches) != 1:
        raise EvidenceError(f"Windows bundle lacks exactly one {label}.")
    return matches[0]


def _validate_winn_physical_order(loaded_json: dict[str, dict[str, Any]]) -> None:
    v3 = _unique_contract(loaded_json, WINN_V3_CONTRACT, "Winn v3 primary receipt")
    awg = _unique_contract(loaded_json, WINN_V1_AWG_CONTRACT, "Winn v1 AWG receipt")
    xray = _unique_contract(loaded_json, WINN_V1_XRAY_CONTRACT, "Winn v1 Xray fallback receipt")
    fallback = v3.get("fallback_transports")
    if (
        v3.get("primary_transport") != "winn_v3"
        or v3.get("winn_v3_session_observed") is not True
        or not isinstance(fallback, list)
        or fallback != ["winn_v1_awg", "winn_v1_xray"]
        or v3.get("source_only") is True
    ):
        raise EvidenceError(
            "Windows Winn v3 primary receipt is source-only or has mixed fallback order."
        )
    if awg.get("transport") != "winn_v1_awg" or awg.get("observed") is not True:
        raise EvidenceError("Windows Winn v1 AWG receipt is source-only or unobserved.")
    if xray.get("transport") != "winn_v1_xray" or xray.get("observed") is not True:
        raise EvidenceError(
            "Windows Winn v1 Xray fallback receipt is source-only or unobserved."
        )
    try:
        awg_sequence = int(awg["sequence"])
        xray_sequence = int(xray["sequence"])
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceError("Windows Winn physical-order sequences are invalid.") from exc
    if awg_sequence >= xray_sequence:
        raise EvidenceError("Windows Winn v1 Xray fallback is not after AWG.")


def compile_bundle(
    index_path: pathlib.Path,
    artifact: pathlib.Path,
    map_screenshot: pathlib.Path,
    *,
    expected_bindings: dict[str, str],
    expected_collector_closure: str,
) -> dict[str, Any]:
    _clear_secure_cache()
    index_bytes = secure_read_once(
        index_path, maximum=MAX_INDEX_BYTES, label="Windows evidence bundle index"
    )
    try:
        index_raw = json.loads(index_bytes.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("Windows evidence bundle index must be valid UTF-8 JSON.") from exc
    index = require_exact(
        index_raw,
        {
            "schema_version",
            "contract",
            "run_id",
            "created_at_utc",
            "secret_material_redacted",
            "collector_closure_sha256",
            *BINDING_FIELDS,
            "artifact_sha256",
            "machine_evidence_path",
            "machine_evidence_sha256",
            "entries",
            "publication_authorized",
            "sealed",
        },
        "Windows evidence bundle index",
    )
    if index["schema_version"] != 1 or index["contract"] != BUNDLE_CONTRACT:
        raise EvidenceError("Windows evidence bundle index contract/version is invalid.")
    try:
        bundle_run = uuid.UUID(str(index["run_id"]))
    except ValueError as exc:
        raise EvidenceError("Windows evidence bundle run_id must be a UUID.") from exc
    if bundle_run.int == 0:
        raise EvidenceError("Windows evidence bundle run_id must not be zero.")
    if str(index["run_id"]) != str(bundle_run):
        raise EvidenceError("Windows evidence bundle run_id must use canonical lowercase UUID form.")
    bundle_created = parse_utc(index["created_at_utc"], "Windows evidence bundle created_at_utc")
    require_fresh(bundle_created, "Windows evidence bundle created_at_utc")
    require_true(index["secret_material_redacted"], "Windows evidence bundle redaction")
    require_true(index["sealed"], "Windows evidence bundle seal")
    if index["publication_authorized"] is not False:
        raise EvidenceError("A Windows evidence bundle never authorizes publication.")
    closure = require_sha256(index["collector_closure_sha256"], "Bundle collector closure")
    if closure != require_sha256(expected_collector_closure, "Expected collector closure"):
        raise EvidenceError("Windows evidence bundle was not produced by the fixed collector closure.")
    if set(expected_bindings) != BINDING_FIELDS:
        raise EvidenceError("All five independent release bindings are required for the bundle.")
    for field in sorted(BINDING_FIELDS):
        if require_sha256(index[field], f"Bundle {field}") != require_sha256(
            expected_bindings[field], f"Expected {field}"
        ):
            raise EvidenceError(f"Windows evidence bundle has stale {field}.")
    artifact_hash = require_sha256(index["artifact_sha256"], "Bundle artifact")
    if sha256_file(artifact) != artifact_hash:
        raise EvidenceError("Windows evidence bundle does not match the exact publication artifact.")
    entries = index["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 512:
        raise EvidenceError("Windows evidence bundle entry count is invalid.")
    bundle_root = _reject_reparse_walk(index_path).parent
    if bundle_root.name != str(bundle_run):
        raise EvidenceError("Windows evidence bundle directory must equal its index run UUID.")
    artifact_architecture = pe_architecture(
        secure_read_once(artifact, maximum=MAX_ARTIFACT_BYTES, label="Exact Windows installer"),
        "Exact Windows installer",
    )
    architecture_binding = architecture_binding_for(artifact_architecture)
    paths: set[str] = set()
    sequences: set[int] = set()
    nonce_values: set[str] = set()
    loaded_json: dict[str, dict[str, Any]] = {}
    contracts: dict[str, int] = {}
    for raw_entry in entries:
        entry = require_exact(
            raw_entry,
            {"path", "sha256", "size_bytes", "contract", "sequence", "step_nonce"},
            "Windows evidence bundle entry",
        )
        relative = pathlib.PurePosixPath(str(entry["path"]))
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise EvidenceError("Windows evidence bundle entry path is unsafe.")
        relative_text = relative.as_posix()
        if len(relative_text) > 240 or relative_text in paths:
            raise EvidenceError("Windows evidence bundle entry paths must be short and unique.")
        paths.add(relative_text)
        sequence = require_positive_int(entry["sequence"], "Bundle entry sequence")
        if sequence in sequences:
            raise EvidenceError("Windows evidence bundle entry sequences must be unique.")
        sequences.add(sequence)
        try:
            nonce = uuid.UUID(str(entry["step_nonce"]))
        except ValueError as exc:
            raise EvidenceError("Windows evidence bundle entry step_nonce must be a UUID.") from exc
        if nonce.int == 0 or str(nonce) in nonce_values:
            raise EvidenceError("Windows evidence bundle step nonces must be nonzero and unique.")
        nonce_values.add(str(nonce))
        entry_path = bundle_root.joinpath(*relative.parts)
        maximum = MAX_JSON_BYTES if str(entry["contract"]) else MAX_ARTIFACT_BYTES
        data = secure_read_once(entry_path, maximum=maximum, label=f"Bundle entry {relative_text}")
        if len(data) != require_positive_int(entry["size_bytes"], f"Bundle entry {relative_text} size"):
            raise EvidenceError(f"Bundle entry {relative_text} size changed.")
        if hashlib.sha256(data).hexdigest() != require_sha256(
            entry["sha256"], f"Bundle entry {relative_text} SHA-256"
        ):
            raise EvidenceError(f"Bundle entry {relative_text} hash changed.")
        if data[:2] == b"MZ":
            entry_architecture = pe_architecture(data, f"Bundle entry {relative_text}")
            if entry_architecture != artifact_architecture:
                raise EvidenceError(
                    "Windows evidence bundle mixes x64 and arm64 PE images."
                )
        contract = str(entry["contract"])
        if contract:
            if len(contract) > 96 or not re.fullmatch(r"winsvpn-[a-z0-9-]+-v[0-9]+", contract):
                raise EvidenceError(f"Bundle entry {relative_text} contract is invalid.")
            contracts[contract] = contracts.get(contract, 0) + 1
            try:
                parsed = json.loads(data.decode("utf-8-sig"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise EvidenceError(f"Bundle entry {relative_text} must be UTF-8 JSON.") from exc
            if not isinstance(parsed, dict) or parsed.get("contract") != contract:
                raise EvidenceError(f"Bundle entry {relative_text} contract does not match its index.")
            if parsed.get("run_id") != str(bundle_run):
                raise EvidenceError(f"Bundle entry {relative_text} run_id does not match its index.")
            if parsed.get("sequence") != sequence or parsed.get("step_nonce") != str(nonce):
                raise EvidenceError(f"Bundle entry {relative_text} sequence/nonce does not match its index.")
            if parsed.get("collector_closure_sha256") != closure:
                raise EvidenceError(f"Bundle entry {relative_text} collector closure does not match its index.")
            _deny_sensitive_json(parsed, f"Bundle entry {relative_text}")
            loaded_json[relative_text] = parsed
    if sequences != set(range(1, len(entries) + 1)):
        raise EvidenceError("Windows evidence bundle sequences must be consecutive from one.")
    for contract, count in contracts.items():
        if contract in SINGLETON_CONTRACTS and count != 1:
            raise EvidenceError(f"Windows evidence bundle has duplicate {contract} evidence.")
    for required in REQUIRED_BUNDLE_CONTRACTS:
        if contracts.get(required, 0) != 1:
            raise EvidenceError(f"Windows bundle lacks exactly one {required} evidence.")
    for relative_text, parsed in loaded_json.items():
        contract = str(parsed.get("contract") or "")
        if contract in ARCHITECTURE_BOUND_CONTRACTS:
            require_architecture_binding(
                parsed,
                f"Bundle {contract}",
                architecture_binding,
            )
    machine_path = str(index["machine_evidence_path"])
    if machine_path not in loaded_json or loaded_json[machine_path].get("contract") != MACHINE_CONTRACT:
        raise EvidenceError("Windows bundle lacks its indexed machine-evidence record.")
    machine_bytes = secure_read_once(
        bundle_root / pathlib.PurePosixPath(machine_path),
        maximum=MAX_JSON_BYTES,
        label="Windows machine evidence",
    )
    if require_sha256(index["machine_evidence_sha256"], "Machine evidence index hash") != hashlib.sha256(
        machine_bytes
    ).hexdigest():
        raise EvidenceError("Windows machine-evidence index hash is stale.")
    machine = loaded_json[machine_path]
    if machine.get("artifact_sha256") != artifact_hash:
        raise EvidenceError("Windows machine evidence artifact does not match the bundle.")
    require_architecture_binding(
        machine, "Windows machine evidence", architecture_binding
    )
    identity = _unique_contract(
        loaded_json, IDENTITY_CONTRACT, "machine-identity record"
    )
    _validate_machine_identity(
        identity,
        artifact_hash,
        architecture_binding,
        closure,
        str(bundle_run),
        f"{machine.get('app_version')}+{machine.get('build_number')}",
    )
    _validate_winn_physical_order(loaded_json)
    transcript = compile_evidence(
        machine,
        bundle_root,
        artifact,
        map_screenshot,
        expected_bindings,
    )
    transcript["evidence_bundle_index_sha256"] = hashlib.sha256(index_bytes).hexdigest()
    return transcript


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_self_test() -> None:
    try:
        require_sha256("A" * 64, "uppercase digest")
    except EvidenceError:
        pass
    else:
        raise EvidenceError("Compiler self-test accepted a noncanonical digest.")
    try:
        normalize_routes([], "self-test routes")
    except EvidenceError:
        pass
    else:
        raise EvidenceError("Compiler self-test accepted an empty advertised route set.")
    try:
        pe_architecture(b"MZ" + b"\x00" * 512, "self-test installer")
    except EvidenceError:
        pass
    else:
        raise EvidenceError("Compiler self-test accepted a non-PE installer.")
    try:
        require_architecture_binding(
            {
                "architecture": "x64",
                "pe_machine": PE_MACHINE_X64,
                "native_architecture": "x64",
                "os_architecture": "X64",
                "process_wow64": True,
            },
            "self-test wow64",
            architecture_binding_for("x64"),
        )
    except EvidenceError:
        pass
    else:
        raise EvidenceError("Compiler self-test accepted WOW64 architecture binding.")
    try:
        require_architecture_binding(
            {
                "architecture": "x86",
                "pe_machine": PE_MACHINE_X86,
                "native_architecture": "x86",
                "os_architecture": "X86",
                "process_wow64": False,
            },
            "self-test x86",
            architecture_binding_for("x64"),
        )
    except EvidenceError:
        pass
    else:
        raise EvidenceError("Compiler self-test accepted an x86/stub architecture binding.")
    print("WINDOWS RELEASE MATRIX COMPILER SELF-TEST: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-index")
    parser.add_argument("--artifact")
    parser.add_argument("--map-screenshot")
    parser.add_argument("--output")
    parser.add_argument("--release-input-index-sha256")
    parser.add_argument("--platform-manifest-sha256")
    parser.add_argument("--artifact-input-fingerprint-sha256")
    parser.add_argument("--build-receipt-sha256")
    parser.add_argument("--producer-contract-sha256")
    parser.add_argument("--collector-closure-sha256")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        run_self_test()
        return 0
    required = (
        args.bundle_index,
        args.artifact,
        args.map_screenshot,
        args.output,
        args.release_input_index_sha256,
        args.platform_manifest_sha256,
        args.artifact_input_fingerprint_sha256,
        args.build_receipt_sha256,
        args.producer_contract_sha256,
        args.collector_closure_sha256,
    )
    if not all(required):
        parser.error("bundle index, artifact, map, output, collector closure, and all five release bindings are required")
    transcript = compile_bundle(
        pathlib.Path(args.bundle_index),
        pathlib.Path(args.artifact).resolve(),
        pathlib.Path(args.map_screenshot).resolve(),
        expected_bindings={
            "release_input_index_sha256": args.release_input_index_sha256,
            "platform_manifest_sha256": args.platform_manifest_sha256,
            "artifact_input_fingerprint_sha256": args.artifact_input_fingerprint_sha256,
            "build_receipt_sha256": args.build_receipt_sha256,
            "producer_contract_sha256": args.producer_contract_sha256,
        },
        expected_collector_closure=args.collector_closure_sha256,
    )
    write_json(pathlib.Path(args.output).resolve(), transcript)
    print("WINDOWS RELEASE MATRIX EVIDENCE: PASS")
    print(f"Native transcript: {pathlib.Path(args.output).resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        raise SystemExit(f"WINDOWS RELEASE MATRIX EVIDENCE: FAIL: {exc}") from exc
