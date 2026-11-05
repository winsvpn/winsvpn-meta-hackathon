#!/usr/bin/env python3
"""Fail-closed exact-artifact public-release live-smoke evidence producer.

Platform wrappers call this file after a native live run has written the small,
sanitized transcript contract validated below.  The wrapper and this helper are
hashed together so changing either invalidates previously assembled evidence.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import zipfile

from validate_release_artifact_privacy import PrivacyError as ArtifactPrivacyError
from validate_release_artifact_privacy import validate_artifacts
from release_obfuscation_contract import ObfuscationError
from release_obfuscation_contract import verify as verify_obfuscation_evidence
from release_dependency_freeze import (
    DependencyFreezeError,
    secure_repo_path,
    verify_build_receipt,
    verify_release_index,
)


CONTRACT = "winsvpn-native-live-smoke-v2"
PRODUCER_CONTRACT = "winsvpn-public-release-live-smoke-v3"
COMMON_PATH = "tools/public_release_live_smoke_common.py"
PRIVACY_PATH = "tools/validate_release_artifact_privacy.py"
OBFUSCATION_PATH = "tools/release_obfuscation_contract.py"
DEPENDENCY_FREEZE_PATH = "tools/release_dependency_freeze.py"
RELEASE_INPUT_INDEX_NAME = "RELEASE_INPUT_INDEX.json"
RAW_EVIDENCE_MAX_AGE = dt.timedelta(hours=72)
APPROVED_PRODUCERS = {
    "android": "tools/android_public_release_live_smoke.ps1",
    "windows": "tools/windows_public_release_live_smoke.ps1",
    "linux": "tools/linux_public_release_live_smoke.sh",
    "ios": "tools/apple_public_release_live_smoke.sh",
    "macos": "tools/apple_public_release_live_smoke.sh",
}
PRODUCER_EXTRA_DEPENDENCIES = {
    "tools/android_public_release_live_smoke.ps1": (
        "tools/android_final_evidence_collector.py",
        "tools/android_release_matrix_evidence.py",
        "tools/android_release_ui_driver.py",
        "tools/android_remote_route_control.py",
        "tools/android_remote_route_guard.sh",
        "tools/android_fresh_release_regression.ps1",
        "tools/android_exact_installed_live_cycle.ps1",
    ),
    "tools/windows_public_release_live_smoke.ps1": (
        "tools/windows_release_matrix_driver.ps1",
        "tools/windows_release_matrix_evidence.py",
        "tools/windows_invoke_vpn_power.ps1",
        "tools/windows_semantic_transition_probe.ps1",
        "tools/windows_test_failsafe_watchdog.ps1",
    ),
    "tools/linux_public_release_live_smoke.sh": (
        "tools/linux_final_evidence_collector.py",
        "tools/linux_release_ui_driver.py",
        "tools/install_linux_release_ui_driver.sh",
        "tools/linux_split_tunnel_live_canary.sh",
        "tools/linux_apple_release_matrix_evidence.py",
        "tools/linux_installed_artifact_manifest.py",
        "tools/linux_live_tunnel_assertions.sh",
        "tools/linux_live_split_assertions.sh",
        "tools/linux_live_tunnel_teardown_assertions.sh",
    ),
    "tools/apple_public_release_live_smoke.sh": (
        "tools/apple_final_evidence_collector.py",
        "tools/apple_release_ui_driver.py",
        "tools/apple_map_semantic_observer.swift",
        "tools/install_apple_release_ui_driver.sh",
        "tools/android_remote_route_control.py",
        "ios/RunnerUITests/VpnPermissionUITests.swift",
        "ios/RunnerUITests/RunnerUITests.entitlements",
        "ios/Runner.xcodeproj/project.pbxproj",
        "ios/Runner.xcodeproj/xcshareddata/xcschemes/Runner.xcscheme",
        "tools/linux_apple_release_matrix_evidence.py",
        "tools/apple_runtime_smoke.sh",
    ),
}
ROOT_FIELDS = {
    "schema_version",
    "contract",
    "platform",
    "app_version",
    "build_number",
    "artifact_sha256",
    "evidence_bundle_index_sha256",
    "run_id",
    "captured_at_utc",
    "secret_material_redacted",
    "checks",
    "map_visual",
    "direct_awg",
    "advertised_xray_routes",
    "tested_xray_routes",
}
CHECK_FIELDS = {
    "artifact_signature",
    "clean_install",
    "ip_map_50_mile_city_context",
    "split_tunneling_contract",
    "double_vpn",
    "leak_test",
}
WINDOWS_MATRIX_FIELDS = {
    "rapid_connect_cancel_no_late_restart",
    "reconnect_after_cancel",
    "dynamic_xray_awg_fallback",
    "per_app_split_tunneling",
    "wifi_ethernet_dhcp_ipv6_recovery",
    "leak_protection",
    "disconnect_teardown",
    "rollback",
}
MAP_VISUAL_FIELDS = {
    "screenshot_sha256",
    "radius_miles",
    "city_labels_visible",
    "target_marker_visible",
    "viewport_not_world_zoom",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LINUX_COSIGN_VERSION = "v3.1.3"
LINUX_COSIGN_PATH = pathlib.Path("/usr/local/bin/cosign")
LINUX_COSIGN_TRUST_ANCHOR = pathlib.Path(
    "/etc/winsvpn/release-signing/cosign.pub"
)
LINUX_COSIGN_SHA256_BY_MACHINE = {
    "x86_64": "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
    "amd64": "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
    "aarch64": "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a",
    "arm64": "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a",
}
LINUX_STANDARD_BUNDLE_MEDIA_TYPE = (
    "application/vnd.dev.sigstore.bundle.v0.3+json"
)
LINUX_BUNDLE_MAX_BYTES = 16 * 1024 * 1024
RETIRED_LINUX_SIGNER_ENV = (
    "WINS_LINUX_SIGNER_IDENTITY",
    "WINS_LINUX_SIGNER_OIDC_ISSUER",
)


class EvidenceError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class ReleaseInputBinding:
    index_sha256: str
    platform_manifest_sha256: str
    shared_revision: str
    artifact_input_fingerprint_sha256: str
    evidence_not_before_utc: dt.datetime


@dataclasses.dataclass(frozen=True)
class BuildReceiptBinding:
    path: str
    sha256: str
    artifact_size_bytes: int
    finished_utc: dt.datetime


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_exact_fields(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be a JSON object.")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise EvidenceError(f"{label} fields are not exact (missing={missing}, extra={extra}).")
    return value


def parse_utc(value: object, label: str = "captured_at_utc") -> dt.datetime:
    if not isinstance(value, str):
        raise EvidenceError(f"{label} must be an ISO-8601 string.")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{label} is not valid ISO-8601.") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"{label} must include a UTC offset.")
    return parsed.astimezone(dt.timezone.utc)


def pubspec_version(repo: pathlib.Path) -> tuple[str, str]:
    text = (repo / "pubspec.yaml").read_text(encoding="utf-8")
    match = re.search(r"(?m)^version:\s*([^+\s]+)\+(\d+)\s*$", text)
    if not match:
        raise EvidenceError("pubspec.yaml must contain version: <semver>+<integer>.")
    return match.group(1), match.group(2)


def verify_release_obfuscation(
    repo: pathlib.Path,
    platform: str,
    version: str,
    build: str,
    artifact: pathlib.Path,
) -> None:
    obfuscation_platform, relative = {
        "android": ("android-apk", pathlib.Path("android-apk")),
        "windows": ("windows", pathlib.Path("windows")),
        "linux": ("linux", pathlib.Path("linux")),
        "ios": ("ios", pathlib.Path("apple") / "ios"),
        "macos": ("macos", pathlib.Path("apple") / "macos"),
    }[platform]
    symbols = repo / ".artifacts" / "private-release-symbols" / relative / f"{version}+{build}"
    verify_obfuscation_evidence(
        obfuscation_platform, symbols / "manifest.json", symbols, [artifact]
    )


def release_input_binding(
    repo: pathlib.Path, platform: str, index_value: str
) -> ReleaseInputBinding:
    index_path = pathlib.Path(index_value).expanduser()
    try:
        index_path = secure_repo_path(
            repo, index_path, "Release input index", must_exist=True
        )
    except DependencyFreezeError as exc:
        raise EvidenceError(str(exc)) from exc
    if index_path.name != RELEASE_INPUT_INDEX_NAME or not index_path.is_file():
        raise EvidenceError(
            f"--release-input-index must name an existing {RELEASE_INPUT_INDEX_NAME}."
        )
    try:
        verified = verify_release_index(repo, index_path)
    except DependencyFreezeError as exc:
        raise EvidenceError(str(exc)) from exc
    if verified.get("platforms", {}).get(platform) is None:
        raise EvidenceError(f"Release input index does not verify {platform}.")
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
        reference = index["platform_manifests"][platform]
        manifest_path = index_path.parent / reference["path"]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError("Verified release input metadata is unreadable.") from exc
    index_sha256 = sha256_file(index_path)
    manifest_sha256 = sha256_file(manifest_path)
    fingerprint = str(verified["platforms"][platform])
    shared_revision = str(verified.get("shared_revision", ""))
    if (
        not SHA256_RE.fullmatch(index_sha256)
        or manifest_sha256 != reference.get("sha256")
        or fingerprint != reference.get("artifact_input_fingerprint_sha256")
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", shared_revision)
    ):
        raise EvidenceError("Release input binding is malformed or inconsistent.")
    not_before = max(
        parse_utc(index.get("created_utc"), "release input index created_utc"),
        parse_utc(manifest.get("created_utc"), f"{platform} manifest created_utc"),
    )
    return ReleaseInputBinding(
        index_sha256=index_sha256,
        platform_manifest_sha256=manifest_sha256,
        shared_revision=shared_revision,
        artifact_input_fingerprint_sha256=fingerprint,
        evidence_not_before_utc=not_before,
    )


def build_receipt_binding(
    repo: pathlib.Path,
    platform: str,
    index_value: str,
    receipt_value: str,
    artifact: pathlib.Path,
) -> BuildReceiptBinding:
    try:
        receipt_path = secure_repo_path(
            repo, pathlib.Path(receipt_value).expanduser(), "Build receipt", must_exist=True
        )
        receipt_relative = receipt_path.relative_to(repo.resolve())
        if not receipt_relative.parts or receipt_relative.parts[0] != ".artifacts":
            raise EvidenceError("Build receipt must stay under .artifacts/.")
        result = verify_build_receipt(
            repo,
            pathlib.Path(index_value).expanduser(),
            platform,
            receipt_path,
            artifact,
        )
    except DependencyFreezeError as exc:
        raise EvidenceError(str(exc)) from exc
    return BuildReceiptBinding(
        path=receipt_relative.as_posix(),
        sha256=str(result["receipt_sha256"]),
        artifact_size_bytes=int(result["artifact_size_bytes"]),
        finished_utc=parse_utc(result["finished_utc"], "build receipt finished_utc"),
    )


def producer_contract_hash(repo: pathlib.Path, producer: str) -> str:
    digest = hashlib.sha256()
    dependencies = (
        producer,
        *PRODUCER_EXTRA_DEPENDENCIES.get(producer, ()),
        COMMON_PATH,
        PRIVACY_PATH,
        OBFUSCATION_PATH,
        DEPENDENCY_FREEZE_PATH,
    )
    for relative in dict.fromkeys(dependencies):
        path = repo / relative
        if not path.is_file():
            raise EvidenceError(f"Approved producer dependency is missing: {relative}")
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def route_key(route: dict) -> tuple[int, str]:
    return int(route["port"]), str(route["security"])


def validate_route(route: object, *, tested: bool) -> dict:
    fields = {"protocol", "port", "security", "passed"} if tested else {"protocol", "port", "security"}
    value = require_exact_fields(route, fields, "Xray route")
    if value["protocol"] != "tcp":
        raise EvidenceError("Every Xray route must use TCP.")
    if isinstance(value["port"], bool) or not isinstance(value["port"], int) or not 1 <= value["port"] <= 65535:
        raise EvidenceError("Every Xray route must have a valid integer port.")
    if value["security"] not in {"none", "tls"}:
        raise EvidenceError("Every Xray route security value must be none or tls.")
    if tested and value["passed"] is not True:
        raise EvidenceError("Every tested Xray route must pass.")
    return {"protocol": "tcp", "port": value["port"], "security": value["security"]}


def xray_manifest_sha256(routes: list[dict]) -> str:
    canonical = "".join(
        f"tcp|{route['port']}|{route['security']}\n"
        for route in sorted(routes, key=route_key)
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_native_transcript(
    raw: object,
    *,
    platform: str,
    version: str,
    build: str,
    artifact_sha256: str,
    evidence_not_before_utc: dt.datetime,
) -> tuple[dict, dt.datetime, uuid.UUID, list[dict], str]:
    expected_root_fields = ROOT_FIELDS | ({"windows_matrix"} if platform == "windows" else set())
    root = require_exact_fields(raw, expected_root_fields, "Native transcript")
    if isinstance(root["schema_version"], bool) or root["schema_version"] != 2 or root["contract"] != CONTRACT:
        raise EvidenceError("Native transcript contract/version is unsupported.")
    if (
        root["platform"] != platform
        or root["app_version"] != version
        or not isinstance(root["build_number"], str)
        or root["build_number"] != build
    ):
        raise EvidenceError("Native transcript platform/version/build does not match current source.")
    if root["artifact_sha256"] != artifact_sha256 or not SHA256_RE.fullmatch(str(root["artifact_sha256"])):
        raise EvidenceError("Native transcript is not bound to the exact lowercase artifact SHA-256.")
    evidence_bundle_index_sha256 = str(root["evidence_bundle_index_sha256"])
    if (
        not SHA256_RE.fullmatch(evidence_bundle_index_sha256)
        or evidence_bundle_index_sha256 == "0" * 64
    ):
        raise EvidenceError(
            "Native transcript is not bound to a real immutable evidence-bundle index SHA-256."
        )
    if root["secret_material_redacted"] is not True:
        raise EvidenceError("Native transcript must explicitly state secret_material_redacted=true.")
    try:
        run_id = uuid.UUID(str(root["run_id"]))
    except (ValueError, AttributeError) as exc:
        raise EvidenceError("Native transcript run_id must be a UUID.") from exc
    if run_id.int == 0:
        raise EvidenceError("Native transcript run_id must not be the zero UUID.")
    captured = parse_utc(root["captured_at_utc"])
    now = dt.datetime.now(dt.timezone.utc)
    if captured < now - RAW_EVIDENCE_MAX_AGE:
        raise EvidenceError("Native transcript is older than the 72-hour evidence limit.")
    if captured < evidence_not_before_utc or captured > now + dt.timedelta(minutes=5):
        raise EvidenceError(
            "Native transcript predates its immutable platform release-input binding or is in the future."
        )

    checks = require_exact_fields(root["checks"], CHECK_FIELDS, "Native checks")
    failed = sorted(name for name, result in checks.items() if result is not True)
    if failed:
        raise EvidenceError(f"Native live checks did not all pass: {failed}")

    if platform == "windows":
        windows_matrix = require_exact_fields(
            root["windows_matrix"], WINDOWS_MATRIX_FIELDS, "Windows mandatory matrix"
        )
        failed_windows = sorted(
            name for name, result in windows_matrix.items() if result is not True
        )
        if failed_windows:
            raise EvidenceError(
                f"Windows mandatory live checks did not all pass: {failed_windows}"
            )

    map_visual = require_exact_fields(root["map_visual"], MAP_VISUAL_FIELDS, "Map visual")
    if (
        not SHA256_RE.fullmatch(str(map_visual["screenshot_sha256"]))
        or isinstance(map_visual["radius_miles"], bool)
        or map_visual["radius_miles"] != 50
        or map_visual["city_labels_visible"] is not True
        or map_visual["target_marker_visible"] is not True
        or map_visual["viewport_not_world_zoom"] is not True
    ):
        raise EvidenceError(
            "Map visual must prove a 50-mile radius, surrounding city labels, "
            "the target marker, and a local rather than world-scale viewport."
        )

    direct = require_exact_fields(root["direct_awg"], {"protocol", "port", "passed"}, "Direct AWG check")
    if (
        direct["protocol"] != "udp"
        or isinstance(direct["port"], bool)
        or direct["port"] != 9110
        or direct["passed"] is not True
    ):
        raise EvidenceError("Direct AWG must pass over UDP 9110.")

    advertised_raw = root["advertised_xray_routes"]
    tested_raw = root["tested_xray_routes"]
    if not isinstance(advertised_raw, list) or not isinstance(tested_raw, list) or not advertised_raw:
        raise EvidenceError("At least one advertised and tested Xray route is required.")
    if len(advertised_raw) > 32 or len(tested_raw) > 32:
        raise EvidenceError("Xray route evidence exceeds the supported maximum of 32 routes.")
    advertised = [validate_route(route, tested=False) for route in advertised_raw]
    tested = [validate_route(route, tested=True) for route in tested_raw]
    advertised_keys = [route_key(route) for route in advertised]
    tested_keys = [route_key(route) for route in tested]
    if len(set(advertised_keys)) != len(advertised_keys) or len(set(tested_keys)) != len(tested_keys):
        raise EvidenceError("Duplicate Xray routes are forbidden.")
    if set(advertised_keys) != set(tested_keys) or len(advertised_keys) != len(tested_keys):
        raise EvidenceError("Every advertised Xray route must be tested exactly once.")
    routes = [
        {"protocol": "tcp", "port": route["port"], "security": route["security"], "passed": True}
        for route in sorted(tested, key=route_key)
    ]
    manifest = xray_manifest_sha256(routes)
    sanitized = {
        "schema_version": 2,
        "contract": CONTRACT,
        "platform": platform,
        "app_version": version,
        "build_number": build,
        "artifact_sha256": artifact_sha256,
        "evidence_bundle_index_sha256": evidence_bundle_index_sha256,
        "run_id": str(run_id),
        "captured_at_utc": captured.isoformat().replace("+00:00", "Z"),
        "secret_material_redacted": True,
        "checks": {name: True for name in sorted(CHECK_FIELDS)},
        "map_visual": {
            "screenshot_sha256": str(map_visual["screenshot_sha256"]),
            "radius_miles": 50,
            "city_labels_visible": True,
            "target_marker_visible": True,
            "viewport_not_world_zoom": True,
        },
        "direct_awg": {"protocol": "udp", "port": 9110, "passed": True},
        "advertised_xray_routes": [
            {"protocol": "tcp", "port": route["port"], "security": route["security"]}
            for route in sorted(advertised, key=route_key)
        ],
        "tested_xray_routes": routes,
    }
    if platform == "windows":
        sanitized["windows_matrix"] = {
            name: True for name in sorted(WINDOWS_MATRIX_FIELDS)
        }
    return sanitized, captured, run_id, routes, manifest


def image_dimensions(path: pathlib.Path) -> tuple[int, int]:
    data = path.read_bytes()[:64 * 1024]
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    if data.startswith(b"\xff\xd8"):
        offset = 2
        while offset + 9 < len(data):
            if data[offset] != 0xFF:
                offset += 1
                continue
            marker = data[offset + 1]
            offset += 2
            if marker in {0xD8, 0xD9}:
                continue
            if offset + 2 > len(data):
                break
            length = int.from_bytes(data[offset : offset + 2], "big")
            if length < 2 or offset + length > len(data):
                break
            if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                return int.from_bytes(data[offset + 5 : offset + 7], "big"), int.from_bytes(data[offset + 3 : offset + 5], "big")
            offset += length
    raise EvidenceError("Map screenshot must be a readable PNG or JPEG image.")


def verify_map_screenshot(path: pathlib.Path, expected_sha256: str) -> None:
    if not path.is_file() or path.suffix.lower() not in {".png", ".jpg", ".jpeg"}:
        raise EvidenceError("Map screenshot must be an existing PNG or JPEG file.")
    size = path.stat().st_size
    if size < 10_000 or size > 25 * 1024 * 1024:
        raise EvidenceError("Map screenshot size must be between 10 KiB and 25 MiB.")
    if sha256_file(path) != expected_sha256:
        raise EvidenceError("Map screenshot SHA-256 does not match the native transcript.")
    width, height = image_dimensions(path)
    if width < 600 or height < 600:
        raise EvidenceError("Map screenshot must be at least 600 by 600 pixels.")


def find_android_tool(name: str) -> pathlib.Path | None:
    found = shutil.which(name)
    if found:
        return pathlib.Path(found)
    roots = [os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME")]
    if os.name == "nt":
        roots.append(str(pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk"))
    candidates: list[pathlib.Path] = []
    for raw_root in roots:
        if not raw_root:
            continue
        build_tools = pathlib.Path(raw_root) / "build-tools"
        if build_tools.is_dir():
            candidates.extend(build_tools.glob(f"*/{name}*"))
    return sorted((path for path in candidates if path.is_file()), reverse=True)[0] if candidates else None


def run_checked(command: list[str], label: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise EvidenceError(f"{label} failed with exit code {result.returncode}.")
    return result


def verify_android_signature(artifact: pathlib.Path) -> None:
    tool = find_android_tool("apksigner")
    if not tool:
        raise EvidenceError("apksigner is required to verify the Android release artifact.")
    if tool.suffix.lower() in {".bat", ".cmd"}:
        jar = tool.parent / "lib" / "apksigner.jar"
        java = shutil.which("java")
        if not jar.is_file() or not java:
            raise EvidenceError("apksigner.jar and Java are required for Android signature verification.")
        command = [java, "-jar", str(jar), "verify", "--verbose", "--print-certs", str(artifact)]
    else:
        command = [str(tool), "verify", "--verbose", "--print-certs", str(artifact)]
    result = run_checked(command, "Android APK signature verification")
    output = result.stdout + result.stderr
    if "Signer #1 certificate SHA-256 digest:" not in output or not re.search(
        r"Verified using v[23] scheme .*:\s*true", output
    ):
        raise EvidenceError("Android APK lacks a verified v2/v3 signer certificate.")


def verify_windows_signature(artifact: pathlib.Path) -> None:
    subject_regex = os.environ.get("WINS_WINDOWS_SIGNER_SUBJECT_REGEX", "").strip()
    if not subject_regex or subject_regex in {".*", ".+", "^.*$", "^.+$"} or len(subject_regex) < 8:
        raise EvidenceError("WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required for Windows release verification.")
    try:
        re.compile(subject_regex)
    except re.error as exc:
        raise EvidenceError("WINS_WINDOWS_SIGNER_SUBJECT_REGEX is invalid.") from exc
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        raise EvidenceError("Windows PowerShell is required for Authenticode verification.")
    command = (
        "$s=Get-AuthenticodeSignature -LiteralPath $args[0];"
        "[ordered]@{status=[string]$s.Status;signer=[string]$s.SignerCertificate.Subject;"
        "timestamp=[string]$s.TimeStamperCertificate.Subject}|ConvertTo-Json -Compress"
    )
    result = run_checked([powershell, "-NoProfile", "-Command", command, str(artifact)], "Authenticode verification")
    try:
        details = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise EvidenceError("Authenticode verification returned invalid status data.") from exc
    if details.get("status") != "Valid" or not re.search(subject_regex, details.get("signer", "")):
        raise EvidenceError("Windows artifact does not have the required valid Authenticode signer.")
    if not details.get("timestamp", "").strip():
        raise EvidenceError("Windows Authenticode signature lacks a trusted timestamp certificate.")


def _linux_root_path_components(path: pathlib.Path) -> list[pathlib.Path]:
    current = pathlib.Path(path.anchor)
    components = [current]
    for part in path.parts[1:]:
        current /= part
        components.append(current)
    return components


@contextlib.contextmanager
def _open_linux_root_file(
    path: pathlib.Path, label: str, *, executable: bool
):
    if not path.is_absolute():
        raise EvidenceError(f"{label} must use an absolute path.")
    components = _linux_root_path_components(path)
    for index, component in enumerate(components):
        try:
            info = os.lstat(component)
        except OSError as exc:
            raise EvidenceError(f"{label} path component is unavailable: {component}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise EvidenceError(f"{label} path must not contain symbolic links.")
        if info.st_uid != 0:
            raise EvidenceError(f"{label} path must be owned by root.")
        if info.st_mode & 0o022:
            raise EvidenceError(f"{label} path must not be writable by group or other.")
        if index < len(components) - 1 and not stat.S_ISDIR(info.st_mode):
            raise EvidenceError(f"{label} parent path must contain only directories.")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"{label} could not be opened without following links.") from exc
    try:
        opened = os.fstat(fd)
        current = os.lstat(path)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise EvidenceError(f"{label} changed while it was opened.")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size <= 0:
            raise EvidenceError(f"{label} must be one nonempty regular file without hardlinks.")
        if executable and not opened.st_mode & 0o111:
            raise EvidenceError(f"{label} must be executable.")
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def _open_linux_input_file(path: pathlib.Path, label: str):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise EvidenceError(f"{label} must be an existing non-symlink file.") from exc
    try:
        opened = os.fstat(fd)
        current = os.lstat(path)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise EvidenceError(f"{label} changed while it was opened.")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size <= 0:
            raise EvidenceError(f"{label} must be one nonempty regular file without hardlinks.")
        yield fd
    finally:
        os.close(fd)


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        offset += len(block)


def _linux_fd_path(fd: int) -> str:
    if not pathlib.Path("/proc/self/fd").is_dir():
        raise EvidenceError("Linux signature verification requires /proc/self/fd binding.")
    return f"/proc/self/fd/{fd}"


def _strict_linux_bundle_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"Linux Sigstore bundle contains duplicate key {key!r}.")
        result[key] = value
    return result


def _validate_linux_standard_bundle_fd(fd: int) -> None:
    size = os.fstat(fd).st_size
    if size > LINUX_BUNDLE_MAX_BYTES:
        raise EvidenceError("Linux Sigstore bundle exceeds the 16 MiB limit.")
    raw = os.pread(fd, size + 1, 0)
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_linux_bundle_object,
        )
    except EvidenceError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("Linux Sigstore bundle must be strict UTF-8 JSON.") from exc
    if not isinstance(payload, dict):
        raise EvidenceError("Linux Sigstore bundle root must be an object.")
    if payload.get("mediaType") != LINUX_STANDARD_BUNDLE_MEDIA_TYPE:
        raise EvidenceError("Linux live smoke refuses legacy Sigstore bundle formats.")
    if not isinstance(payload.get("verificationMaterial"), dict):
        raise EvidenceError("Linux Sigstore bundle lacks verificationMaterial.")
    content = [
        field
        for field in ("messageSignature", "dsseEnvelope")
        if isinstance(payload.get(field), dict)
    ]
    if len(content) != 1:
        raise EvidenceError("Linux Sigstore bundle must contain one signature content type.")


def _run_linux_cosign(
    argv: list[str], pass_fds: tuple[int, ...], label: str
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            argv,
            pass_fds=pass_fds,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="strict",
            shell=False,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise EvidenceError(f"{label} could not execute safely.") from exc
    if completed.returncode != 0:
        raise EvidenceError(f"{label} failed with exit code {completed.returncode}.")
    return completed


def verify_linux_signature(
    artifact: pathlib.Path,
    args: argparse.Namespace,
    expected_artifact_sha256: str = "",
) -> None:
    retired = [name for name in RETIRED_LINUX_SIGNER_ENV if os.environ.get(name, "").strip()]
    if retired:
        raise EvidenceError(
            "GitHub/OIDC Linux signer settings are retired and must be unset: "
            + ", ".join(retired)
        )
    if sys.platform != "linux":
        raise EvidenceError("Linux release signatures must be verified on Linux.")
    machine = platform.machine().lower()
    expected_cosign_sha256 = LINUX_COSIGN_SHA256_BY_MACHINE.get(machine)
    if not expected_cosign_sha256:
        raise EvidenceError(f"No reviewed Cosign digest exists for Linux architecture {machine!r}.")
    if not args.linux_bundle:
        raise EvidenceError("Linux release evidence requires a separate Sigstore v3 bundle.")
    bundle = pathlib.Path(os.path.abspath(os.path.expanduser(args.linux_bundle)))
    artifact = pathlib.Path(os.path.abspath(artifact))
    if bundle == artifact:
        raise EvidenceError("Linux artifact and Sigstore bundle must be separate files.")

    with _open_linux_root_file(
        LINUX_COSIGN_PATH, "Linux Cosign executable", executable=True
    ) as cosign_fd, _open_linux_root_file(
        LINUX_COSIGN_TRUST_ANCHOR, "Linux Cosign trust anchor", executable=False
    ) as trust_fd, _open_linux_input_file(
        artifact, "Linux release artifact"
    ) as artifact_fd, _open_linux_input_file(
        bundle, "Linux Sigstore bundle"
    ) as bundle_fd:
        initial = {
            "cosign": _sha256_fd(cosign_fd),
            "trust": _sha256_fd(trust_fd),
            "artifact": _sha256_fd(artifact_fd),
            "bundle": _sha256_fd(bundle_fd),
        }
        if initial["cosign"] != expected_cosign_sha256:
            raise EvidenceError("Fixed Linux Cosign SHA-256 does not match the reviewed digest.")
        if expected_artifact_sha256 and initial["artifact"] != expected_artifact_sha256:
            raise EvidenceError("Linux artifact changed between hashing and signature verification.")
        _validate_linux_standard_bundle_fd(bundle_fd)

        cosign = _linux_fd_path(cosign_fd)
        trust = _linux_fd_path(trust_fd)
        version = _run_linux_cosign(
            [cosign, "version"], (cosign_fd,), "Linux Cosign version verification"
        )
        expected_version_line = f"GitVersion: {LINUX_COSIGN_VERSION}"
        if expected_version_line not in [line.strip() for line in version.stdout.splitlines()]:
            raise EvidenceError(f"Expected exact Linux Cosign {LINUX_COSIGN_VERSION}.")
        _run_linux_cosign(
            [
                cosign,
                "verify-blob",
                _linux_fd_path(artifact_fd),
                "--key",
                trust,
                "--bundle",
                _linux_fd_path(bundle_fd),
                "--offline",
                "--insecure-ignore-tlog",
            ],
            (cosign_fd, trust_fd, artifact_fd, bundle_fd),
            "Linux local-key Sigstore bundle verification",
        )
        final = {
            "cosign": _sha256_fd(cosign_fd),
            "trust": _sha256_fd(trust_fd),
            "artifact": _sha256_fd(artifact_fd),
            "bundle": _sha256_fd(bundle_fd),
        }
        if final != initial:
            raise EvidenceError("Linux signature inputs changed during verification.")


def codesign_details(app: pathlib.Path) -> str:
    result = run_checked(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)], "Apple codesign verification")
    details = run_checked(["codesign", "-d", "--verbose=4", str(app)], "Apple codesign identity inspection")
    return result.stdout + result.stderr + details.stdout + details.stderr


def apple_team_id(repo: pathlib.Path) -> str:
    candidates: set[str] = set()
    for relative in (
        "ios/Runner.xcodeproj/project.pbxproj",
        "macos/Runner.xcodeproj/project.pbxproj",
    ):
        path = repo / relative
        if path.is_file():
            candidates.update(re.findall(r"DEVELOPMENT_TEAM\s*=\s*([A-Z0-9]{10});", path.read_text(encoding="utf-8")))
    if len(candidates) != 1:
        raise EvidenceError("Apple project files must pin one consistent 10-character Team ID.")
    return next(iter(candidates))


def verify_apple_signature(artifact: pathlib.Path, platform: str, repo: pathlib.Path) -> None:
    if sys.platform != "darwin":
        raise EvidenceError("Apple release signatures must be verified on macOS.")
    team_id = apple_team_id(repo)
    if platform == "macos" and artifact.suffix.lower() == ".pkg":
        result = run_checked(["pkgutil", "--check-signature", str(artifact)], "macOS package signature verification")
        output = result.stdout + result.stderr
        if "Status: signed by a certificate trusted by macOS" not in output or not re.search(
            r"(Developer ID Installer|3rd Party Mac Developer Installer)", output
        ) or f"({team_id})" not in output:
            raise EvidenceError("macOS package lacks a trusted distribution installer signature.")
        if "Developer ID Installer" in output:
            run_checked(["spctl", "-a", "-vv", "-t", "install", str(artifact)], "macOS Gatekeeper verification")
        return
    with tempfile.TemporaryDirectory(prefix="wins-apple-signature-") as temp_dir:
        if artifact.suffix.lower() == ".ipa":
            with zipfile.ZipFile(artifact) as archive:
                archive.extractall(temp_dir)
            apps = list((pathlib.Path(temp_dir) / "Payload").glob("*.app"))
            if len(apps) != 1:
                raise EvidenceError("iOS IPA must contain exactly one Payload application.")
            app = apps[0]
        elif artifact.suffix.lower() == ".app" and artifact.is_dir():
            app = artifact
        else:
            raise EvidenceError("Apple artifact must be an iOS IPA, macOS app, or signed macOS pkg.")
        output = codesign_details(app)
        if f"TeamIdentifier={team_id}" not in output:
            raise EvidenceError("Apple artifact Team ID does not match the project signing team.")
        if platform == "ios":
            if not re.search(r"Authority=(Apple Distribution|iPhone Distribution)", output):
                raise EvidenceError("iOS artifact is not distribution signed.")
            provision = app / "embedded.mobileprovision"
            if not provision.is_file():
                raise EvidenceError("iOS artifact lacks an embedded distribution profile.")
            decoded = run_checked(["security", "cms", "-D", "-i", str(provision)], "iOS profile verification")
            profile = plistlib.loads(decoded.stdout.encode("utf-8"))
            if profile.get("Entitlements", {}).get("get-task-allow") is not False:
                raise EvidenceError("iOS release profile permits debugging.")
            if team_id not in profile.get("TeamIdentifier", []):
                raise EvidenceError("iOS release profile Team ID does not match the project signing team.")
            expiration = profile.get("ExpirationDate")
            if not isinstance(expiration, dt.datetime) or expiration.replace(tzinfo=dt.timezone.utc) <= dt.datetime.now(dt.timezone.utc):
                raise EvidenceError("iOS release profile is missing an unexpired expiration date.")
        else:
            if not re.search(r"Authority=(Developer ID Application|3rd Party Mac Developer Application)", output):
                raise EvidenceError("macOS app is not distribution signed.")


def verify_platform_signature(
    artifact: pathlib.Path,
    platform: str,
    args: argparse.Namespace,
    repo: pathlib.Path,
    expected_artifact_sha256: str = "",
) -> None:
    if platform == "android":
        verify_android_signature(artifact)
    elif platform == "windows":
        verify_windows_signature(artifact)
    elif platform == "linux":
        verify_linux_signature(artifact, args, expected_artifact_sha256)
    else:
        verify_apple_signature(artifact, platform, repo)


def atomic_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=False) + "\n")
    os.replace(temporary, path)


def run_self_test(repo: pathlib.Path, platform: str) -> None:
    version, build = pubspec_version(repo)
    if not re.fullmatch(r"[A-Z0-9]{10}", apple_team_id(repo)):
        raise EvidenceError("Apple Team ID source pin self-test failed.")
    producer_hash = producer_contract_hash(repo, APPROVED_PRODUCERS[platform])
    if (
        not SHA256_RE.fullmatch(producer_hash)
        or producer_hash == sha256_file(repo / APPROVED_PRODUCERS[platform])
    ):
        raise EvidenceError("Producer hash does not bind its dependency-scoped validator closure.")
    try:
        release_input_binding(repo, platform, "missing/RELEASE_INPUT_INDEX.json")
    except EvidenceError:
        pass
    else:
        raise EvidenceError("Missing release input index was accepted.")
    evidence_not_before = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
    now = dt.datetime.now(dt.timezone.utc)
    artifact_hash = hashlib.sha256(b"fixture").hexdigest()
    with tempfile.TemporaryDirectory(prefix="wins-map-visual-") as map_temp:
        map_fixture = pathlib.Path(map_temp) / "map.png"
        png_header = (
            b"\x89PNG\r\n\x1a\n"
            + (13).to_bytes(4, "big")
            + b"IHDR"
            + (1280).to_bytes(4, "big")
            + (720).to_bytes(4, "big")
            + b"\x08\x06\x00\x00\x00"
        )
        map_fixture.write_bytes(png_header + b"\x00" * (10_240 - len(png_header)))
        map_hash = sha256_file(map_fixture)
        verify_map_screenshot(map_fixture, map_hash)
    base = {
        "schema_version": 2,
        "contract": CONTRACT,
        "platform": "android",
        "app_version": version,
        "build_number": build,
        "artifact_sha256": artifact_hash,
        "evidence_bundle_index_sha256": "d" * 64,
        "run_id": str(uuid.uuid4()),
        "captured_at_utc": now.isoformat(),
        "secret_material_redacted": True,
        "checks": {name: True for name in CHECK_FIELDS},
        "map_visual": {
            "screenshot_sha256": map_hash,
            "radius_miles": 50,
            "city_labels_visible": True,
            "target_marker_visible": True,
            "viewport_not_world_zoom": True,
        },
        "direct_awg": {"protocol": "udp", "port": 9110, "passed": True},
        "advertised_xray_routes": [
            {"protocol": "tcp", "port": 80, "security": "none"},
            {"protocol": "tcp", "port": 443, "security": "tls"},
        ],
        "tested_xray_routes": [
            {"protocol": "tcp", "port": 443, "security": "tls", "passed": True},
            {"protocol": "tcp", "port": 80, "security": "none", "passed": True},
        ],
    }
    _, _, _, routes, manifest = validate_native_transcript(
        base,
        platform="android",
        version=version,
        build=build,
        artifact_sha256=artifact_hash,
        evidence_not_before_utc=evidence_not_before,
    )
    if len(routes) != 2 or not SHA256_RE.fullmatch(manifest):
        raise EvidenceError("Positive live-smoke transcript self-test failed.")

    negative_mutations = []
    bad = copy.deepcopy(base)
    bad["direct_awg"]["port"] = 80
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["checks"]["leak_test"] = False
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["map_visual"]["radius_miles"] = 500
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["map_visual"]["city_labels_visible"] = False
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["advertised_xray_routes"].append(copy.deepcopy(bad["advertised_xray_routes"][0]))
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["tested_xray_routes"][0]["endpoint"] = "forbidden.example"
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["tested_xray_routes"].pop()
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["artifact_sha256"] = artifact_hash.upper()
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    del bad["evidence_bundle_index_sha256"]
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["evidence_bundle_index_sha256"] = "D" * 64
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["evidence_bundle_index_sha256"] = "0" * 64
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["schema_version"] = True
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["build_number"] = int(build)
    negative_mutations.append(bad)
    bad = copy.deepcopy(base)
    bad["direct_awg"]["passed"] = 1
    negative_mutations.append(bad)
    for index, invalid in enumerate(negative_mutations, start=1):
        try:
            validate_native_transcript(
                invalid,
                platform="android",
                version=version,
                build=build,
                artifact_sha256=artifact_hash,
                evidence_not_before_utc=evidence_not_before,
            )
        except EvidenceError:
            continue
        raise EvidenceError(f"Negative live-smoke transcript self-test {index} was accepted.")

    windows_base = copy.deepcopy(base)
    windows_base["platform"] = "windows"
    windows_base["windows_matrix"] = {
        name: True for name in WINDOWS_MATRIX_FIELDS
    }
    validate_native_transcript(
        windows_base,
        platform="windows",
        version=version,
        build=build,
        artifact_sha256=artifact_hash,
        evidence_not_before_utc=evidence_not_before,
    )
    missing_windows_matrix = copy.deepcopy(windows_base)
    del missing_windows_matrix["windows_matrix"]
    failed_windows_matrix = copy.deepcopy(windows_base)
    failed_windows_matrix["windows_matrix"]["rapid_connect_cancel_no_late_restart"] = False
    android_with_windows_matrix = copy.deepcopy(base)
    android_with_windows_matrix["windows_matrix"] = {
        name: True for name in WINDOWS_MATRIX_FIELDS
    }
    for invalid, invalid_platform in (
        (missing_windows_matrix, "windows"),
        (failed_windows_matrix, "windows"),
        (android_with_windows_matrix, "android"),
    ):
        try:
            validate_native_transcript(
                invalid,
                platform=invalid_platform,
                version=version,
                build=build,
                artifact_sha256=artifact_hash,
                evidence_not_before_utc=evidence_not_before,
            )
        except EvidenceError:
            continue
        raise EvidenceError("Invalid platform-scoped Windows matrix was accepted.")

    stale = copy.deepcopy(base)
    stale["captured_at_utc"] = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=73)
    ).isoformat()
    try:
        validate_native_transcript(
            stale,
            platform="android",
            version=version,
            build=build,
            artifact_sha256=artifact_hash,
            evidence_not_before_utc=dt.datetime.now(dt.timezone.utc)
            - dt.timedelta(hours=80),
        )
    except EvidenceError:
        pass
    else:
        raise EvidenceError("A transcript older than 72 hours was accepted.")

    if platform == "linux":
        with tempfile.TemporaryDirectory() as temp_name:
            temp = pathlib.Path(temp_name)
            artifact = temp / "artifact.tar.gz"
            bundle = temp / "artifact.tar.gz.sigstore.json"
            artifact.write_bytes(b"signed-linux-fixture")
            bundle.write_text("{}\n", encoding="utf-8")
            fake_marker = temp / "path-selected-cosign-ran"
            fake_cosign = temp / "cosign"
            fake_cosign.write_text(
                "#!/bin/sh\n"
                f"touch {str(fake_marker)!r}\n"
                "exit 0\n",
                encoding="utf-8",
            )
            fake_cosign.chmod(0o755)
            original_path = os.environ.get("PATH", "")
            os.environ["PATH"] = str(temp) + os.pathsep + original_path
            try:
                try:
                    verify_linux_signature(
                        artifact, argparse.Namespace(linux_bundle=str(bundle))
                    )
                except EvidenceError:
                    pass
                else:
                    raise EvidenceError("PATH-selected fake Cosign was accepted.")
            finally:
                os.environ["PATH"] = original_path
            if fake_marker.exists():
                raise EvidenceError("Linux verification executed a PATH-selected Cosign.")

            retired_name = RETIRED_LINUX_SIGNER_ENV[0]
            original_retired = os.environ.get(retired_name)
            os.environ[retired_name] = "retired-github-identity"
            try:
                try:
                    verify_linux_signature(
                        artifact, argparse.Namespace(linux_bundle=str(bundle))
                    )
                except EvidenceError:
                    pass
                else:
                    raise EvidenceError("Retired GitHub signer input was accepted.")
            finally:
                if original_retired is None:
                    os.environ.pop(retired_name, None)
                else:
                    os.environ[retired_name] = original_retired
    print("PUBLIC RELEASE LIVE-SMOKE PRODUCER SELF-TEST: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=sorted(APPROVED_PRODUCERS), required=True)
    parser.add_argument("--producer", required=True)
    parser.add_argument("--artifact")
    parser.add_argument("--native-transcript")
    parser.add_argument("--map-screenshot")
    parser.add_argument("--release-input-index")
    parser.add_argument("--build-receipt")
    parser.add_argument("--output-root", default=".artifacts/release-evidence")
    parser.add_argument("--linux-bundle", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    repo = pathlib.Path(__file__).resolve().parent.parent
    expected_producer = APPROVED_PRODUCERS[args.platform]
    producer = args.producer.replace("\\", "/")
    if producer != expected_producer:
        raise EvidenceError(f"{args.platform} must use {expected_producer}.")
    if args.self_test:
        run_self_test(repo, args.platform)
        return 0
    if (
        not args.artifact
        or not args.native_transcript
        or not args.map_screenshot
        or not args.release_input_index
        or not args.build_receipt
    ):
        raise EvidenceError(
            "--artifact, --native-transcript, --map-screenshot, --release-input-index, and --build-receipt are required."
        )

    try:
        artifact = secure_repo_path(
            repo, pathlib.Path(args.artifact).expanduser(), "Built artifact", must_exist=True
        )
    except DependencyFreezeError as exc:
        raise EvidenceError(str(exc)) from exc
    transcript_path = pathlib.Path(args.native_transcript).expanduser().resolve()
    map_screenshot = pathlib.Path(args.map_screenshot).expanduser().resolve()
    if not artifact.is_file() or not transcript_path.is_file() or not map_screenshot.is_file():
        raise EvidenceError("Artifact, native transcript, and map screenshot must be existing files.")
    version, build = pubspec_version(repo)
    release_inputs = release_input_binding(repo, args.platform, args.release_input_index)
    artifact_hash = sha256_file(artifact)
    receipt = build_receipt_binding(
        repo,
        args.platform,
        args.release_input_index,
        args.build_receipt,
        artifact,
    )
    try:
        native_raw = json.loads(transcript_path.read_text(encoding="utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("Native transcript must be valid UTF-8 JSON.") from exc
    sanitized, captured, run_id, routes, manifest = validate_native_transcript(
        native_raw,
        platform=args.platform,
        version=version,
        build=build,
        artifact_sha256=artifact_hash,
        evidence_not_before_utc=max(
            release_inputs.evidence_not_before_utc, receipt.finished_utc
        ),
    )
    verify_map_screenshot(
        map_screenshot, str(sanitized["map_visual"]["screenshot_sha256"])
    )
    try:
        validate_artifacts((artifact,), {})
    except ArtifactPrivacyError as exc:
        raise EvidenceError(f"Exact artifact failed client privacy validation: {exc}") from exc
    try:
        verify_release_obfuscation(repo, args.platform, version, build, artifact)
    except ObfuscationError as exc:
        raise EvidenceError(f"Exact artifact failed release obfuscation validation: {exc}") from exc
    verify_platform_signature(
        artifact, args.platform, args, repo, expected_artifact_sha256=artifact_hash
    )

    output_root = pathlib.Path(args.output_root)
    try:
        output_root = secure_repo_path(
            repo, output_root, "Evidence output root", must_exist=False
        )
        required_root = secure_repo_path(
            repo,
            pathlib.Path(".artifacts/release-evidence"),
            "Evidence root",
            must_exist=False,
        )
        output_root.relative_to(required_root)
    except (DependencyFreezeError, ValueError) as exc:
        raise EvidenceError("Output root must stay under .artifacts/release-evidence.") from exc
    run_dir = output_root / args.platform / str(run_id)
    try:
        secure_repo_path(repo, run_dir, "Evidence run output", must_exist=False)
    except DependencyFreezeError as exc:
        raise EvidenceError(str(exc)) from exc
    if run_dir.exists():
        raise EvidenceError("Run ID already exists; live evidence runs must be unique and immutable.")
    run_dir.mkdir(parents=True, exist_ok=False)
    sanitized_path = run_dir / "transcript.json"
    raw_path = run_dir / "run.json"
    stored_map_screenshot = run_dir / f"map-screenshot{map_screenshot.suffix.lower()}"
    shutil.copyfile(map_screenshot, stored_map_screenshot)
    atomic_json(sanitized_path, sanitized)
    transcript_relative = sanitized_path.relative_to(repo).as_posix()
    map_relative = stored_map_screenshot.relative_to(repo).as_posix()
    raw = {
        "schema_version": 3,
        "platform": args.platform,
        "app_version": version,
        "build_number": build,
        "release_input_index_sha256": release_inputs.index_sha256,
        "platform_manifest_sha256": release_inputs.platform_manifest_sha256,
        "shared_revision": release_inputs.shared_revision,
        "artifact_input_fingerprint_sha256": release_inputs.artifact_input_fingerprint_sha256,
        "artifact_sha256": artifact_hash,
        "evidence_bundle_index_sha256": sanitized["evidence_bundle_index_sha256"],
        "artifact_size_bytes": receipt.artifact_size_bytes,
        "build_receipt": {"path": receipt.path, "sha256": receipt.sha256},
        "run_id": str(run_id),
        "tested_at_utc": captured.isoformat().replace("+00:00", "Z"),
        "secret_material_redacted": True,
        "producer": {
            "contract": PRODUCER_CONTRACT,
            "path": producer,
            "sha256": producer_contract_hash(repo, producer),
        },
        "transcript": {"path": transcript_relative, "sha256": sha256_file(sanitized_path)},
        "artifact_signature_passed": True,
        "clean_install_passed": True,
        "ip_map_50_mile_city_context_passed": True,
        "direct_awg_passed": True,
        "xray_all_backup_routes_passed": True,
        "split_tunneling_contract_passed": True,
        "double_vpn_passed": True,
        "leak_test_passed": True,
        "map_screenshot": {
            "path": map_relative,
            "sha256": sha256_file(stored_map_screenshot),
        },
        "route_matrix": {
            "direct_awg": {"protocol": "udp", "port": 9110, "passed": True},
            "xray": {
                "advertised_route_count": len(routes),
                "tested_route_count": len(routes),
                "manifest_sha256": manifest,
                "routes": routes,
            },
        },
    }
    if args.platform == "windows":
        raw["windows_matrix_passed"] = True
    atomic_json(raw_path, raw)
    print("PUBLIC RELEASE LIVE-SMOKE EVIDENCE: PASS")
    print(f"Platform: {args.platform}")
    print(f"Raw evidence: {raw_path}")
    print(f"Artifact SHA-256: {artifact_hash}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        print(f"PUBLIC RELEASE LIVE-SMOKE EVIDENCE: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
