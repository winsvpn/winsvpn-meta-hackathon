#!/usr/bin/env python3
"""Collect exact physical Android release evidence on a Windows ADB host.

The collector composes the existing clean-install/onboarding regression with
the UIAutomator driver and remote first-hop kernel observer. It writes the
strict v2 machine contract only after all route, split, handoff, leak, map,
teardown, and rollback facts have been observed and restored.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from typing import Any

import android_remote_route_control as _route_control_module
from android_release_ui_driver import (
    AndroidDriver,
    CHROME,
    DriverError,
    PACKAGE,
    SAMSUNG_BROWSER,
    sha256_file,
    sha256_text,
)
from android_remote_route_control import (
    RouteControlError,
    apply as route_apply,
    load_inventory,
    observe as route_observe,
    restore as route_restore,
    snapshot as route_snapshot,
)
from public_release_live_smoke_common import (
    build_receipt_binding,
    producer_contract_hash,
    release_input_binding,
)


CONTRACT = "winsvpn-android-release-machine-evidence-v2"
INDEX_CONTRACT = "winsvpn-android-evidence-bundle-index-v1"
PRODUCER = "tools/android_public_release_live_smoke.ps1"
EXPECTED_SIGNER = "4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee"
EXPECTED_APPLICATION_ID = PACKAGE
OWNER_BLOCKED_ABSENT_PACKAGES = (
    "OWNER-BLOCKED: produced Android AAB/APK bytes are absent"
)
OWNER_BLOCKED_RUNTIME_RECEIPTS = (
    "OWNER-BLOCKED: exact indexed phone, TV, and Wear evidence manifest is required"
)
OWNER_BLOCKED_LISTING = "OWNER-BLOCKED: ABSENT"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
ZIP_LOCAL_FILE_MAGIC = b"PK\x03\x04"
JAR_SIGNATURE_SUFFIXES = (".RSA", ".DSA", ".EC")
OWNER_BLOCKED_PACKAGE_VERIFIER = (
    "OWNER-BLOCKED: fixed owner-authorized APK and AAB verifier identities are not provisioned"
)
PACKAGE_VERIFIER_OUTPUT_CONTRACT = "winsvpn-android-package-verifier-output-v1"
MAX_PACKAGE_VERIFIER_OUTPUT_BYTES = 1024 * 1024
MAX_PACKAGE_VERIFIER_TOOL_BYTES = 512 * 1024 * 1024
PACKAGE_VERIFIER_TIMEOUT_SECONDS = 120
# These values must be issued and reviewed by the owner before production can run.
# Caller-provided paths or hashes are intentionally not accepted as trust anchors.
OWNER_AUTHORIZED_PACKAGE_VERIFIER_CUSTODY: dict[str, dict[str, str | int]] = {}
PRODUCED_ARTIFACT_CONTRACT = "winsvpn-android-produced-artifact-receipt-v1"
RUNTIME_CONTRACT = "winsvpn-android-form-factor-runtime-receipt-v1"
WEAR_RUNTIME_CONTRACT = "winsvpn-android-wear-runtime-receipt-v1"
WINN_PRIMARY_TRANSPORT = "winn_v3"
WINN_FALLBACK_TRANSPORTS = ["winn_v1_awg", "winn_v1_xray"]
MAX_RUNTIME_RECEIPT_BYTES = 64 * 1024
MAX_RUNTIME_RECEIPT_SKEW = dt.timedelta(hours=12)
MAX_FORM_FACTOR_MANIFEST_BYTES = 256 * 1024
MAX_SOURCE_INDEX_BYTES = 256 * 1024
MAX_SOURCE_MEMBER_BYTES = 8 * 1024 * 1024
MAX_SOURCE_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_PRODUCED_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024
FORM_FACTOR_MANIFEST_CONTRACT = "winsvpn-android-form-factor-evidence-manifest-v1"
FORM_FACTOR_SOURCE_INDEX_CONTRACT = "winsvpn-android-form-factor-source-index-v1"
FORM_FACTOR_OWNER_AUTHORITY_CONTRACT = (
    "winsvpn-android-form-factor-evidence-owner-authority-v1"
)
FORM_FACTOR_OWNER_AUTHORIZATION_CONTRACT = (
    "winsvpn-android-form-factor-evidence-owner-authorization-v2"
)
FORM_FACTOR_OWNER_AUTHORITY_RELATIVE = (
    "android/release/form_factor_evidence_owner_authority.json"
)
FORM_FACTOR_OWNER_SIGNATURE_DOMAIN = (
    b"WINSVPN-ANDROID-FORM-FACTOR-EVIDENCE-OWNER-AUTHORIZATION-V2\0"
)
MAX_OWNER_AUTHORITY_BYTES = 16 * 1024
MAX_OWNER_AUTHORIZATION_BYTES = 256 * 1024
MAX_OWNER_AUTHORIZATION_WINDOW = dt.timedelta(hours=24)
MAX_NATIVE_TOOL_BYTES = 512 * 1024 * 1024
MAX_ADB_SUPPORT_TREE_BYTES = 4 * 1024 * 1024 * 1024
MAX_ADB_SUPPORT_TREE_FILES = 4096
MAX_TESSERACT_SUPPORT_TREE_BYTES = 4 * 1024 * 1024 * 1024
MAX_TESSERACT_SUPPORT_TREE_FILES = 4096
MAX_ROUTE_AUTHORITY_BYTES = 1024 * 1024
MAX_DEVICE_ATTESTATION_BYTES = 64 * 1024
MAX_DEVICECHECK_BUILD_RECEIPT_BYTES = 2 * 1024 * 1024
DEVICECHECK_BUILD_RECEIPT_CONTRACT = "winsvpn-devicecheck-build-receipt-v2"
DEVICECHECK_BUILD_RECEIPT_RELATIVE = (
    "android/devicecheck/app/build/outputs/devicecheck-receipts/release/"
    "DEVICECHECK_BUILD_RECEIPT.json"
)
DEVICECHECK_BUILD_RECEIPT_SIDECAR_RELATIVE = (
    DEVICECHECK_BUILD_RECEIPT_RELATIVE + ".sha256"
)
DEVICECHECK_BUILD_TOOLS_VERSION = "36.0.0"
DEVICECHECK_SEALED_JAVA_ROOT = "/Library/WinsVPN/ReleaseAndroidToolchains/jdk-17.0.20.1"
DEVICECHECK_SEALED_JAVA_RELATIVE = "bin/java"
DEVICECHECK_SOURCE_CUSTODY_CONTRACT = "winsvpn-devicecheck-source-custody-v2"
DEVICECHECK_SOURCE_AUTHORITY_CONTRACT = "winsvpn-devicecheck-owner-authority-v4"
DEVICECHECK_SOURCE_SNAPSHOT_PREFIX = (
    "/Library/WinsVPN/ReleaseAndroidSource/devicecheck-v3/snapshots/sha256/"
)
DEVICECHECK_SOURCE_CONSUMER_STATUS = "integrated"
DEVICE_ATTESTATION_CONTRACT = "winsvpn-android-physical-device-attestation-v3"
DEVICE_ATTESTATION_PACKAGE = "org.winsvpn.devicecheck"
DEVICE_ATTESTATION_RUNNER = (
    "org.winsvpn.devicecheck.test/androidx.test.runner.AndroidJUnitRunner"
)
DEVICE_ATTESTATION_PROOF_CLASS = (
    "org.winsvpn.devicecheck.LiveHardwareAttestationProofTest"
)
DEVICE_ATTESTATION_TEST_METHOD = "provePossessionOfOwnerAttestedKey"
DEVICE_ATTESTATION_REPORT_SCHEMA = (
    "winsvpn-android-live-hardware-attestation-evidence-v4"
)
DEVICE_ATTESTATION_PROOF_DOMAIN = (
    b"WINSVPN-ANDROID-LIVE-HARDWARE-ATTESTATION-EVIDENCE-V4\0"
)
DEVICE_ATTESTATION_NONCE_HASH_DOMAIN = (
    b"WINSVPN-ANDROID-ATTESTATION-NONCE-SALTED-HASH-V2\0"
)
DEVICE_ATTESTATION_TEST_PACKAGE = "org.winsvpn.devicecheck.test"
DEVICE_ATTESTATION_VERSION_NAME = "devicecheck"
DEVICE_ATTESTATION_VERSION_CODE = 1
DEVICE_ATTESTATION_BUILD_HASH_LABELS = (
    "board",
    "bootloader",
    "brand",
    "device",
    "display",
    "fingerprint",
    "hardware",
    "host",
    "id",
    "manufacturer",
    "model",
    "product",
    "soc_manufacturer",
    "soc_model",
    "supported_abis",
    "tags",
    "type",
    "user",
    "version_incremental",
    "version_release",
)
DEVICE_ATTESTATION_REPORT_FIELDS = (
    "schema",
    "host_session_nonce",
    "transcript_context_sha256",
    "persistent_key_id",
    "target_package_id",
    "target_version_name_utf8_hex",
    "target_version_code",
    "target_signer_sha256",
    "target_base_apk_sha256",
    "target_base_apk_bytes",
    "target_installing_package",
    "target_initiating_package",
    "target_originating_package",
    "test_apk_package_id",
    "test_apk_version_name_utf8_hex",
    "test_apk_version_code",
    "test_apk_signer_sha256",
    "test_apk_sha256",
    "test_apk_bytes",
    "test_apk_installing_package",
    "test_apk_initiating_package",
    "test_apk_originating_package",
    "key_origin",
    "key_purposes",
    "key_digests",
    "key_signature_paddings",
    "key_security_level",
    "key_rsa_modulus_bits",
    "key_rsa_public_exponent",
    "attestation_leaf_certificate_sha256",
    "attestation_extension_sha256",
    "attestation_version",
    "attestation_security_level",
    "keymint_version",
    "keymint_security_level",
    "attestation_challenge_sha256",
    "attested_verified_boot_key_sha256",
    "attested_verified_boot_hash_sha256",
    "attested_device_locked",
    "attested_verified_boot_state",
    "current_verified_boot_state",
    "current_flash_locked",
    "current_vbmeta_device_state",
    "user_device_secure",
    "user_unlocked",
    "device_provisioned",
    "boot_count",
    "android_sdk",
    "android_security_patch",
    *(f"build_{label}_nonce_sha256" for label in DEVICE_ATTESTATION_BUILD_HASH_LABELS),
    "display_count",
    "display_id",
    "display_name_nonce_sha256",
    "display_flags",
    "display_state",
    "display_rotation",
    "display_mode_id",
    "display_physical_width_pixels",
    "display_physical_height_pixels",
    "display_refresh_millihertz",
    "display_current_width_pixels",
    "display_current_height_pixels",
    "display_maximum_width_pixels",
    "display_maximum_height_pixels",
    "display_density_dpi",
    "runtime_process_name_utf8_hex",
    "runtime_process_id",
    "runtime_process_uid",
    "runtime_elapsed_realtime_millis",
    "runtime_uptime_millis",
    "runtime_wall_clock_millis",
    "network_count",
    "active_network_handle",
    "active_network_transports",
    "active_network_validated",
    "active_network_internet",
    "active_interface_name_utf8_hex",
    "active_link_address_count",
    "active_route_count",
    "active_dns_server_count",
    "active_network_mtu",
    "active_endpoint_nonce_sha256",
    "vpn_present",
    "vpn_network_handle",
    "vpn_interface_name_utf8_hex",
    "vpn_link_address_count",
    "vpn_route_count",
    "vpn_dns_server_count",
    "vpn_network_mtu",
    "vpn_endpoint_nonce_sha256",
)
DEVICE_ATTESTATION_REPORT_STATUS_KEYS = {
    "winsvpn_attestation_report_b64",
    "winsvpn_attestation_signature_hex",
    "winsvpn_attestation_key_id",
    "winsvpn_attestation_schema",
}
DEVICE_ATTESTATION_RUNNER_STATUS_KEYS = {
    "class",
    "current",
    "id",
    "numtests",
    "stream",
    "test",
}
DEVICE_ATTESTATION_RUNNER_FAILURE_KEYS = {"longMsg", "shortMsg", "stack"}
DEVICE_ATTESTATION_RUNNER_RESULT_KEYS = {"stream"}
MAX_DEVICE_ATTESTATION_REPORT_BYTES = 16 * 1024
MAX_DEVICE_ATTESTATION_REPORT_B64_CHARS = 21_848
MAX_DEVICE_ATTESTATION_STATUS_BUNDLE_BYTES = 24 * 1024
MAX_DEVICE_ATTESTATION_TRANSCRIPT_BYTES = 256 * 1024
DEVICE_ATTESTATION_FINAL_PROOF_CONTRACT = (
    "winsvpn-android-final-attestation-transcript-proof-v1"
)
MAX_SUBPROCESS_STDOUT_BYTES = 4 * 1024 * 1024
MAX_SUBPROCESS_STDERR_BYTES = 1024 * 1024
MAX_EVIDENCE_JSON_BYTES = 8 * 1024 * 1024
# OWNER-BLOCKED until the owner provisions the final public authority and a
# reviewed change replaces this sentinel in both this collector and its source-
# frozen PowerShell wrapper. Release inputs can bind a key, but cannot select
# their own root of trust.
EXPECTED_FORM_FACTOR_OWNER_AUTHORITY_SHA256 = "0" * 64
NATIVE_TOOL_ROLES = (
    "adb",
    "tesseract",
    "powershell",
    "ssh",
    "whoami",
    "icacls",
    "taskkill",
)
ROUTE_AUTHORITY_ROLES = (
    "route_inventory",
    "ssh_config",
    "ssh_identity",
    "ssh_known_hosts",
)
_WINDOWS_WHOAMI: pathlib.Path | None = None
_WINDOWS_ICACLS: pathlib.Path | None = None
_WINDOWS_TASKKILL: pathlib.Path | None = None
_EVIDENCE_HOLDS: dict[str, dict[str, Any]] = {}
FORM_FACTOR_CANDIDATES = {
    "phone": "android-phone-tablet",
    "tv": "android-tv",
    "wear": "wear-os",
}
CANONICAL_PRODUCED_PACKAGES = (
    ("phone_apk", "build/app/outputs/flutter-apk/app-release.apk"),
    ("phone_aab", "build/app/outputs/bundle/release/app-release.aab"),
    ("tv_apk", "build/app/outputs/flutter-apk/app-tv-release.apk"),
    ("tv_aab", "build/app/outputs/bundle/tvRelease/app-tv-release.aab"),
    ("wear_aab", "wear_os/app/build/outputs/bundle/release/app-release.aab"),
)
PHONE_CANDIDATE_ALIASES = {
    "phone_apk": "build/app/outputs/flutter-apk/app-phone-release.apk",
    "phone_aab": "build/app/outputs/bundle/phoneRelease/app-phone-release.aab",
}
FORM_FACTOR_PACKAGE_KEYS = {
    "phone": {"apk": "phone_apk", "aab": "phone_aab"},
    "tv": {"apk": "tv_apk", "aab": "tv_aab"},
    "wear": {"aab": "wear_aab"},
}
FORM_FACTOR_DESCRIPTOR_IDS = (
    "phone-apk-produced",
    "phone-aab-produced",
    "tv-apk-produced",
    "tv-aab-produced",
    "wear-aab-produced",
    "phone-runtime",
    "tv-runtime",
    "wear-runtime",
)
DESCRIPTOR_PACKAGE_KEYS = {
    "phone-apk-produced": ("phone", "apk", "phone_apk"),
    "phone-aab-produced": ("phone", "aab", "phone_aab"),
    "tv-apk-produced": ("tv", "apk", "tv_apk"),
    "tv-aab-produced": ("tv", "aab", "tv_aab"),
    "wear-aab-produced": ("wear", "aab", "wear_aab"),
}
FIXED_IMPORTED_BASENAMES = {
    descriptor_id: f"{descriptor_id}.json" for descriptor_id in FORM_FACTOR_DESCRIPTOR_IDS
}
CANONICAL_SYMBOL_ROLES = (
    "android-apk",
    "android-aab",
    "android-tv-apk",
    "android-tv-aab",
    "wear-os",
)
HELPER_PATHS = {
    "collector": "tools/android_final_evidence_collector.py",
    "driver": "tools/android_release_ui_driver.py",
    "remote_control": "tools/android_remote_route_control.py",
    "remote_guard": "tools/android_remote_route_guard.sh",
}


class CollectorError(RuntimeError):
    pass


def expected_android_identity(repo: pathlib.Path) -> tuple[str, str]:
    text = (repo / "pubspec.yaml").read_text(encoding="utf-8")
    match = re.search(r"(?m)^version:\s*([^+\s]+)\+(\d+)\s*$", text)
    if match is None:
        raise CollectorError("pubspec.yaml does not contain an exact Android version identity")
    return match.group(1), match.group(2)


def _assert_package_container_bytes(path: pathlib.Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise CollectorError(OWNER_BLOCKED_ABSENT_PACKAGES) from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
    ):
        raise CollectorError(OWNER_BLOCKED_ABSENT_PACKAGES)
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic != ZIP_LOCAL_FILE_MAGIC:
        raise CollectorError(f"produced Android package is not a signed ZIP: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            names = [member.filename.upper() for member in members]
    except zipfile.BadZipFile as exc:
        raise CollectorError(f"produced Android package is not a readable ZIP: {path}") from exc
    if len(names) != len(set(names)):
        raise CollectorError(f"produced Android package has colliding ZIP members: {path}")


def _descriptor_safe_execution_supported() -> bool:
    proc_fds = pathlib.Path("/proc/self/fd")
    return (
        os.name == "posix"
        and sys.platform.startswith("linux")
        and proc_fds.is_dir()
        and os.access(proc_fds, os.R_OK | os.X_OK)
    )


def _open_held_external_file(
    path: pathlib.Path,
    label: str,
    *,
    max_bytes: int,
    executable: bool = False,
) -> dict[str, Any]:
    lexical = pathlib.Path(os.path.abspath(os.fspath(path)))
    if os.name != "nt":
        lexical = lexical.parent.resolve(strict=True) / lexical.name
    current = pathlib.Path(lexical.anchor)
    ancestors: list[dict[str, Any]] = []
    descriptor = -1
    try:
        for part in lexical.parts[1:-1]:
            current /= part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise CollectorError(f"{label} traverses an unsafe ancestor")
            directory_flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                directory_flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                directory_flags |= os.O_NOFOLLOW
            ancestor_descriptor = os.open(current, directory_flags)
            ancestor_opened = os.fstat(ancestor_descriptor)
            if _directory_identity(ancestor_opened) != _directory_identity(info):
                os.close(ancestor_descriptor)
                raise CollectorError(f"{label} ancestor changed while it was opened")
            ancestors.append(
                {
                    "path": str(current),
                    "identity": _directory_identity(info),
                    "change_identity": (
                        _stat_identity(ancestor_opened)
                        if current == lexical.parent
                        else None
                    ),
                    "descriptor": ancestor_descriptor,
                }
            )
        before = lexical.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > max_bytes
            or executable and before.st_mode & 0o111 == 0
        ):
            raise CollectorError(
                f"OWNER-BLOCKED: {label} must be one bounded single-link "
                f"{'executable' if executable else 'file'}"
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lexical, flags)
        opened = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(before):
            raise CollectorError(f"{label} changed while its descriptor was opened")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        os.lseek(descriptor, 0, os.SEEK_SET)
        after = os.fstat(descriptor)
        path_after = lexical.lstat()
        if (
            _stat_identity(after) != _stat_identity(before)
            or _stat_identity(path_after) != _stat_identity(before)
        ):
            raise CollectorError(f"{label} changed while its descriptor was bound")
        return {
            "path": str(lexical),
            "sha256": digest.hexdigest(),
            "identity": _stat_identity(before),
            "size_bytes": before.st_size,
            "descriptor": descriptor,
            "ancestors": ancestors,
        }
    except (OSError, CollectorError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        for ancestor in ancestors:
            os.close(ancestor["descriptor"])
        if isinstance(exc, CollectorError):
            raise
        raise CollectorError(f"OWNER-BLOCKED: {label} could not be held") from exc


def _revalidate_held_external_file(hold: dict[str, Any], label: str) -> None:
    descriptor = hold.get("descriptor")
    if not isinstance(descriptor, int) or descriptor < 0:
        raise CollectorError(f"{label} retained descriptor is invalid")
    try:
        opened = os.fstat(descriptor)
        path_info = pathlib.Path(hold["path"]).lstat()
        position = os.lseek(descriptor, 0, os.SEEK_CUR)
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        os.lseek(descriptor, position, os.SEEK_SET)
        for ancestor in hold["ancestors"]:
            descriptor_info = os.fstat(ancestor["descriptor"])
            ancestor_path_info = pathlib.Path(ancestor["path"]).lstat()
            descriptor_identity = _directory_identity(descriptor_info)
            path_identity = _directory_identity(ancestor_path_info)
            if (
                descriptor_identity != ancestor["identity"]
                or path_identity != ancestor["identity"]
                or ancestor["change_identity"] is not None
                and (
                    _stat_identity(descriptor_info) != ancestor["change_identity"]
                    or _stat_identity(ancestor_path_info)
                    != ancestor["change_identity"]
                )
            ):
                raise CollectorError(f"{label} ancestor identity changed after execution")
    except OSError as exc:
        raise CollectorError(f"{label} descriptor or path disappeared after execution") from exc
    if (
        _stat_identity(opened) != hold["identity"]
        or _stat_identity(path_info) != hold["identity"]
        or opened.st_size != hold["size_bytes"]
        or digest.hexdigest() != hold["sha256"]
    ):
        raise CollectorError(f"{label} descriptor or path identity changed after execution")


def _close_held_external_files(holds: dict[str, dict[str, Any]]) -> None:
    for hold in holds.values():
        descriptor = hold.get("descriptor")
        if isinstance(descriptor, int) and descriptor >= 0:
            os.close(descriptor)
            hold["descriptor"] = -1
        for ancestor in hold.get("ancestors", []):
            ancestor_descriptor = ancestor.get("descriptor")
            if isinstance(ancestor_descriptor, int) and ancestor_descriptor >= 0:
                os.close(ancestor_descriptor)
                ancestor["descriptor"] = -1


def _package_verifier_custody_hold(
    custody: dict[str, dict[str, str | int]],
) -> dict[str, dict[str, Any]]:
    required_roles = {"java", "apksigner_jar", "aab_verifier_jar"}
    if set(custody) != required_roles:
        raise CollectorError(OWNER_BLOCKED_PACKAGE_VERIFIER)
    holds: dict[str, dict[str, Any]] = {}
    inode_keys: set[tuple[int, int]] = set()
    hashes: set[str] = set()
    try:
        for role in sorted(required_roles):
            record = custody[role]
            if not isinstance(record, dict) or set(record) != {
                "expected_path",
                "path",
                "sha256",
                "size_bytes",
            }:
                raise CollectorError(OWNER_BLOCKED_PACKAGE_VERIFIER)
            expected_path = record["expected_path"]
            path_value = record["path"]
            digest = record["sha256"]
            size_bytes = record["size_bytes"]
            if (
                not isinstance(expected_path, str)
                or not isinstance(path_value, str)
                or not pathlib.Path(expected_path).is_absolute()
                or not pathlib.Path(path_value).is_absolute()
                or pathlib.Path(path_value) != pathlib.Path(expected_path)
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or digest in {"0" * 64, EMPTY_SHA256}
                or not isinstance(size_bytes, int)
                or isinstance(size_bytes, bool)
                or size_bytes <= 0
                or size_bytes > MAX_PACKAGE_VERIFIER_TOOL_BYTES
            ):
                raise CollectorError(OWNER_BLOCKED_PACKAGE_VERIFIER)
            hold = _open_held_external_file(
                pathlib.Path(path_value),
                f"Android package verifier {role}",
                max_bytes=MAX_PACKAGE_VERIFIER_TOOL_BYTES,
                executable=role == "java",
            )
            if hold["sha256"] != digest or hold["size_bytes"] != size_bytes:
                raise CollectorError(OWNER_BLOCKED_PACKAGE_VERIFIER)
            inode_key = hold["identity"][:2]
            if inode_key in inode_keys or digest in hashes:
                raise CollectorError("Android package verifier custody reuses tool bytes")
            inode_keys.add(inode_key)
            hashes.add(digest)
            holds[role] = hold
        return holds
    except BaseException:
        _close_held_external_files(holds)
        raise


def _package_verifier_output(
    completed: subprocess.CompletedProcess,
    *,
    role: str,
    package_sha256: str,
    package_size: int,
    expected_format: str,
    tool_snapshots: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(completed, subprocess.CompletedProcess):
        raise CollectorError(f"{role} verifier parser accepts only process output")
    stdout = completed.stdout
    stderr = completed.stderr
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8")
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8")
    if (
        not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or len(stdout) > MAX_PACKAGE_VERIFIER_OUTPUT_BYTES
        or len(stderr) > MAX_PACKAGE_VERIFIER_OUTPUT_BYTES
        or completed.returncode != 0
    ):
        raise CollectorError(f"{role} cryptographic package verification failed")
    output_sha256 = hashlib.sha256(stdout + b"\0" + stderr).hexdigest()
    if expected_format == "apk-signing-block":
        try:
            text = stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CollectorError(f"{role} apksigner output is not strict UTF-8") from exc
        scheme_values = re.findall(
            r"(?m)^Verified using v([234]) scheme(?: \([^\r\n]+\))?: (true|false)\r?$",
            text,
        )
        certificate_values = re.findall(
            r"(?mi)^Signer #\d+ certificate SHA-256 digest: ([0-9a-f:]+)\r?$",
            text,
        )
        normalized_certificates = [
            value.replace(":", "").lower() for value in certificate_values
        ]
        if (
            re.search(r"(?m)^Verifies\r?$", text) is None
            or not any(
                version in {"2", "3"} and value == "true"
                for version, value in scheme_values
            )
            or normalized_certificates != [EXPECTED_SIGNER]
        ):
            raise CollectorError(f"{role} APK signing-block verification failed")
        proof: dict[str, Any] = {
            "schema_version": 1,
            "contract": PACKAGE_VERIFIER_OUTPUT_CONTRACT,
            "artifact_sha256": package_sha256,
            "artifact_size_bytes": package_size,
            "cryptographic_verified": True,
            "format": expected_format,
            "signer_certificate_sha256": EXPECTED_SIGNER,
            "signed_payload_entries": 1,
            "unsigned_payload_entries": [],
        }
    else:
        try:
            proof = _strict_json_bytes(stdout, f"{role} AAB verifier output")
        except CollectorError as exc:
            raise CollectorError(f"{role} AAB JAR verification output is invalid") from exc
    required = {
        "schema_version",
        "contract",
        "artifact_sha256",
        "artifact_size_bytes",
        "cryptographic_verified",
        "format",
        "signer_certificate_sha256",
        "signed_payload_entries",
        "unsigned_payload_entries",
    }
    signer = proof.get("signer_certificate_sha256") if isinstance(proof, dict) else None
    if (
        not isinstance(proof, dict)
        or set(proof) != required
        or proof["schema_version"] != 1
        or proof["contract"] != PACKAGE_VERIFIER_OUTPUT_CONTRACT
        or proof["artifact_sha256"] != package_sha256
        or proof["artifact_size_bytes"] != package_size
        or proof["cryptographic_verified"] is not True
        or proof["format"] != expected_format
        or not isinstance(signer, str)
        or re.fullmatch(r"[0-9a-f]{64}", signer) is None
        or signer != EXPECTED_SIGNER
        or not isinstance(proof["signed_payload_entries"], int)
        or isinstance(proof["signed_payload_entries"], bool)
        or proof["signed_payload_entries"] <= 0
        or proof["unsigned_payload_entries"] != []
    ):
        raise CollectorError(f"{role} cryptographic verifier did not bind exact held bytes")
    tool_roles = (
        ("java", "apksigner_jar")
        if expected_format == "apk-signing-block"
        else ("java", "aab_verifier_jar")
    )
    tool_binding = hashlib.sha256()
    for tool_role in tool_roles:
        snapshot = tool_snapshots[tool_role]
        tool_binding.update(tool_role.encode("ascii") + b"\0")
        tool_binding.update(snapshot["sha256"].encode("ascii") + b"\0")
        tool_binding.update(str(snapshot["size_bytes"]).encode("ascii") + b"\0")
    return {
        **proof,
        "output_sha256": output_sha256,
        "tool_binding_sha256": tool_binding.hexdigest(),
    }


def _run_held_package_verifier(
    *,
    artifact_hold: dict[str, Any],
    expected_format: str,
    tool_holds: dict[str, dict[str, Any]],
) -> subprocess.CompletedProcess:
    if not _descriptor_safe_execution_supported():
        raise CollectorError(
            "OWNER-BLOCKED: this platform cannot execute Java and verifier inputs from "
            "retained descriptors"
        )
    verifier_role = (
        "apksigner_jar"
        if expected_format == "apk-signing-block"
        else "aab_verifier_jar"
    )
    java_fd = tool_holds["java"]["descriptor"]
    verifier_fd = tool_holds[verifier_role]["descriptor"]
    artifact_fd = artifact_hold["descriptor"]
    descriptor_paths = {
        descriptor: f"/proc/self/fd/{descriptor}"
        for descriptor in (java_fd, verifier_fd, artifact_fd)
    }
    if any(not pathlib.Path(path).exists() for path in descriptor_paths.values()):
        raise CollectorError(
            "OWNER-BLOCKED: retained package-verifier descriptors are not addressable"
        )
    if expected_format == "apk-signing-block":
        command = [
            descriptor_paths[java_fd],
            "-jar",
            descriptor_paths[verifier_fd],
            "verify",
            "--verbose",
            "--print-certs",
            descriptor_paths[artifact_fd],
        ]
    else:
        command = [
            descriptor_paths[java_fd],
            "-jar",
            descriptor_paths[verifier_fd],
            "--strict-json",
            descriptor_paths[artifact_fd],
        ]
    try:
        return _bounded_subprocess_run(
            command,
            timeout=PACKAGE_VERIFIER_TIMEOUT_SECONDS,
            check=False,
            pass_fds=(java_fd, verifier_fd, artifact_fd),
            stdout_limit=MAX_PACKAGE_VERIFIER_OUTPUT_BYTES,
            stderr_limit=MAX_PACKAGE_VERIFIER_OUTPUT_BYTES,
        )
    except CollectorError as exc:
        raise CollectorError(
            "OWNER-BLOCKED: retained-descriptor Java execution is unavailable"
        ) from exc


def _assert_held_java_descriptor_execution(
    tool_holds: dict[str, dict[str, Any]],
) -> None:
    if not _descriptor_safe_execution_supported():
        raise CollectorError(
            "OWNER-BLOCKED: this platform cannot execute Java from a retained descriptor"
        )
    java_fd = tool_holds["java"]["descriptor"]
    java_path = f"/proc/self/fd/{java_fd}"
    if not pathlib.Path(java_path).exists():
        raise CollectorError("OWNER-BLOCKED: retained Java descriptor is not addressable")
    try:
        completed = _bounded_subprocess_run(
            [java_path, "-version"],
            timeout=30,
            check=False,
            pass_fds=(java_fd,),
            stdout_limit=64 * 1024,
            stderr_limit=64 * 1024,
        )
    except CollectorError as exc:
        raise CollectorError(
            "OWNER-BLOCKED: Java cannot execute from its retained descriptor"
        ) from exc
    if completed.returncode != 0:
        raise CollectorError(
            "OWNER-BLOCKED: Java cannot execute from its retained descriptor"
        )
    _revalidate_held_external_file(
        tool_holds["java"], "Android package verifier java"
    )


def _assert_held_package_container(hold: dict[str, Any]) -> None:
    descriptor = hold["descriptor"]
    position = os.lseek(descriptor, 0, os.SEEK_CUR)
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.read(descriptor, 4) != ZIP_LOCAL_FILE_MAGIC:
            raise CollectorError("held Android package is not a signed ZIP")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            with zipfile.ZipFile(stream) as archive:
                names = [member.filename.upper() for member in archive.infolist()]
    except (OSError, zipfile.BadZipFile) as exc:
        raise CollectorError("held Android package is not a readable ZIP") from exc
    finally:
        os.lseek(descriptor, position, os.SEEK_SET)
    if len(names) != len(set(names)):
        raise CollectorError("held Android package has colliding ZIP members")


def assert_held_produced_packages(
    repo: pathlib.Path,
    apk: pathlib.Path,
) -> dict[str, dict[str, str | int]]:
    for _role, relative in CANONICAL_PRODUCED_PACKAGES:
        _assert_package_container_bytes(repo / pathlib.PurePosixPath(relative))
    if not _descriptor_safe_execution_supported():
        raise CollectorError(
            "OWNER-BLOCKED: this platform cannot execute Java from a retained descriptor"
        )
    tool_holds = _package_verifier_custody_hold(
        OWNER_AUTHORIZED_PACKAGE_VERIFIER_CUSTODY
    )
    records: dict[str, dict[str, str | int]] = {}
    try:
        _assert_held_java_descriptor_execution(tool_holds)
        for role, relative in CANONICAL_PRODUCED_PACKAGES:
            path = repo / pathlib.PurePosixPath(relative)
            artifact_hold = _open_held_external_file(
                path,
                f"{role} held package",
                max_bytes=MAX_PRODUCED_PACKAGE_BYTES,
            )
            try:
                _assert_held_package_container(artifact_hold)
                package_sha256 = artifact_hold["sha256"]
                package_size = artifact_hold["size_bytes"]
                expected_format = (
                    "apk-signing-block" if role.endswith("_apk") else "aab-jar"
                )
                try:
                    completed = _run_held_package_verifier(
                        artifact_hold=artifact_hold,
                        expected_format=expected_format,
                        tool_holds=tool_holds,
                    )
                    proof = _package_verifier_output(
                        completed,
                        role=role,
                        package_sha256=package_sha256,
                        package_size=package_size,
                        expected_format=expected_format,
                        tool_snapshots=tool_holds,
                    )
                finally:
                    _revalidate_held_external_file(
                        artifact_hold, f"{role} held package"
                    )
                    for tool_role, tool_hold in tool_holds.items():
                        _revalidate_held_external_file(
                            tool_hold, f"Android package verifier {tool_role}"
                        )
                records[role] = {
                    "path": pathlib.PurePosixPath(relative).as_posix(),
                    "sha256": package_sha256,
                    "size_bytes": package_size,
                    "signer_certificate_sha256": proof["signer_certificate_sha256"],
                    "cryptographic_signature_verified": True,
                    "signature_format": proof["format"],
                    "signature_verifier_output_sha256": proof["output_sha256"],
                    "signature_verifier_tool_binding_sha256": proof["tool_binding_sha256"],
                }
            finally:
                _close_held_external_files({"artifact": artifact_hold})
    finally:
        _close_held_external_files(tool_holds)
    if len({str(record["sha256"]) for record in records.values()}) != len(records):
        raise CollectorError("produced Android package hashes are duplicated across form factors")
    for role, relative in PHONE_CANDIDATE_ALIASES.items():
        alias = repo / pathlib.PurePosixPath(relative)
        _assert_package_container_bytes(alias)
        if (
            sha256_file(alias) != records[role]["sha256"]
            or alias.stat().st_size != records[role]["size_bytes"]
        ):
            raise CollectorError("phone flavored package does not match its canonical held bytes")
    canonical_apk = repo / pathlib.PurePosixPath(CANONICAL_PRODUCED_PACKAGES[0][1])
    if apk.resolve() != canonical_apk.resolve():
        raise CollectorError("collector APK is not the canonical published phone APK")
    if records["phone_apk"]["sha256"] != sha256_file(apk):
        raise CollectorError("collector APK bytes are not the held current phone APK")
    return records


def assert_obfuscation_symbol_evidence(
    repo: pathlib.Path,
    app_version: str,
    phone_version_code: int,
    wear_version_code: int,
    bound_files: dict[str, dict[str, Any]] | None = None,
) -> dict[str, str]:
    mapping_names = {"mapping.txt", "proguard-mapping.txt"}
    evidence: dict[str, str] = {}
    for role in CANONICAL_SYMBOL_ROLES:
        version_code = wear_version_code if role == "wear-os" else phone_version_code
        version_identity = f"{app_version}+{version_code}"
        root = repo / ".artifacts" / "private-release-symbols" / role / version_identity
        if root.is_symlink() or not root.is_dir():
            raise CollectorError(
                f"Android private-symbol evidence is missing for {role}/{version_identity}"
            )
        mapping_found = False
        symbols_found = False
        mapping_sha = ""
        for path in sorted(root.rglob("*")):
            if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
                continue
            if path.name in mapping_names:
                mapping_found = True
                mapping_sha = sha256_file(path)
            if path.name.endswith(".symbols"):
                symbols_found = True
            if path.name in mapping_names or path.name.endswith(".symbols"):
                snapshot = _bound_file_snapshot(
                    repo,
                    path,
                    f"{role} private symbol evidence",
                    max_bytes=MAX_PRODUCED_PACKAGE_BYTES,
                    require_artifacts=True,
                    retain_raw=False,
                )
                if bound_files is not None:
                    prior = bound_files.get(str(snapshot["path"]))
                    if prior is not None and prior != snapshot:
                        raise CollectorError(
                            f"{role} private symbol evidence changed during preflight"
                        )
                    bound_files[str(snapshot["path"])] = snapshot
        if not mapping_found or not symbols_found:
            raise CollectorError(
                f"Android private R8 mapping or Flutter .symbols evidence is missing for {role}"
            )
        evidence[role] = mapping_sha
    if len(set(evidence.values())) != len(evidence):
        raise CollectorError("Android private mapping hashes are duplicated across form factors")
    return evidence


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _external_file_snapshot(
    path: pathlib.Path,
    label: str,
    *,
    max_bytes: int,
    retain_raw: bool = False,
    kind: str = "file",
) -> dict[str, Any]:
    lexical = pathlib.Path(os.path.abspath(os.fspath(path)))
    if os.name != "nt":
        lexical = lexical.parent.resolve(strict=True) / lexical.name
    current = pathlib.Path(lexical.anchor)
    try:
        for part in lexical.parts[1:-1]:
            current /= part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise CollectorError(f"{label} traverses an unsafe ancestor")
        before = lexical.lstat()
    except OSError as exc:
        raise CollectorError(f"OWNER-BLOCKED: {label} is missing or unreadable") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > max_bytes
    ):
        raise CollectorError(
            f"OWNER-BLOCKED: {label} must be one bounded single-link {kind}"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lexical, flags)
        try:
            opened = os.fstat(descriptor)
            if _stat_identity(opened) != _stat_identity(before):
                raise CollectorError(f"{label} changed while it was opened")
            digest = hashlib.sha256()
            chunks: list[bytes] = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                if retain_raw:
                    chunks.append(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise CollectorError(f"OWNER-BLOCKED: {label} could not be bound") from exc
    if _stat_identity(after) != _stat_identity(before):
        raise CollectorError(f"{label} changed while it was hashed")
    return {
        "path": str(lexical),
        "sha256": digest.hexdigest(),
        "identity": _stat_identity(before),
        "size_bytes": before.st_size,
        "raw": b"".join(chunks) if retain_raw else None,
    }


def _external_executable_snapshot(path: pathlib.Path, label: str) -> dict[str, Any]:
    return _external_file_snapshot(
        path,
        label,
        max_bytes=MAX_NATIVE_TOOL_BYTES,
        kind="executable",
    )


def _reaudit_native_tools(snapshots: dict[str, dict[str, Any]]) -> None:
    if set(snapshots) != set(NATIVE_TOOL_ROLES):
        raise CollectorError("Android native-tool custody is incomplete")
    for role in NATIVE_TOOL_ROLES:
        expected = snapshots[role]
        current = _external_executable_snapshot(
            pathlib.Path(expected["path"]), f"Android {role} executable"
        )
        if current != expected:
            raise CollectorError(f"Android {role} executable changed after preflight")


def _adb_support_tree_snapshot(root: pathlib.Path) -> dict[str, Any]:
    lexical = pathlib.Path(os.path.abspath(os.fspath(root)))
    if os.name != "nt":
        lexical = lexical.resolve(strict=True)
    try:
        root_info = lexical.lstat()
    except OSError as exc:
        raise CollectorError("OWNER-BLOCKED: reviewed ADB support tree is missing") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise CollectorError("OWNER-BLOCKED: reviewed ADB support tree is unsafe")
    files: list[dict[str, Any]] = []
    inode_keys: set[tuple[int, int]] = set()
    total_bytes = 0
    for directory, dirnames, filenames in os.walk(lexical, followlinks=False):
        dirnames.sort()
        filenames.sort()
        directory_path = pathlib.Path(directory)
        for dirname in dirnames:
            child = directory_path / dirname
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise CollectorError("reviewed ADB support tree contains an unsafe directory")
        for filename in filenames:
            path = directory_path / filename
            relative = path.relative_to(lexical).as_posix()
            snapshot = _external_file_snapshot(
                path,
                f"ADB support file {relative}",
                max_bytes=MAX_NATIVE_TOOL_BYTES,
            )
            inode_key = snapshot["identity"][:2]
            total_bytes += int(snapshot["size_bytes"])
            if inode_key in inode_keys:
                raise CollectorError("reviewed ADB support tree contains a hardlink")
            if (
                len(files) >= MAX_ADB_SUPPORT_TREE_FILES
                or total_bytes > MAX_ADB_SUPPORT_TREE_BYTES
            ):
                raise CollectorError("reviewed ADB support tree exceeds its custody limits")
            inode_keys.add(inode_key)
            files.append({"relative": relative, **snapshot})
    basenames = {pathlib.PurePosixPath(item["relative"]).name.casefold() for item in files}
    if not {"adb.exe", "adbwinapi.dll", "adbwinusbapi.dll"}.issubset(basenames):
        raise CollectorError(
            "OWNER-BLOCKED: reviewed ADB support tree lacks its Windows runtime closure"
        )
    digest = hashlib.sha256()
    for item in files:
        digest.update(item["relative"].encode("utf-8") + b"\0")
        digest.update(item["sha256"].encode("ascii") + b"\0")
        digest.update(str(item["size_bytes"]).encode("ascii") + b"\0")
    return {
        "root": str(lexical),
        "root_identity": _stat_identity(root_info),
        "tree_sha256": digest.hexdigest(),
        "total_bytes": total_bytes,
        "files": files,
    }


def _reaudit_adb_support_tree(expected: dict[str, Any]) -> None:
    current = _adb_support_tree_snapshot(pathlib.Path(expected["root"]))
    if current != expected:
        raise CollectorError("ADB support tree changed after preflight")


def _tesseract_support_tree_snapshot(root: pathlib.Path) -> dict[str, Any]:
    lexical = pathlib.Path(os.path.abspath(os.fspath(root)))
    if os.name != "nt":
        lexical = lexical.resolve(strict=True)
    try:
        root_info = lexical.lstat()
    except OSError as exc:
        raise CollectorError(
            "OWNER-BLOCKED: reviewed Tesseract support tree is missing"
        ) from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise CollectorError("OWNER-BLOCKED: reviewed Tesseract support tree is unsafe")
    files: list[dict[str, Any]] = []
    inode_keys: set[tuple[int, int]] = set()
    total_bytes = 0
    for directory, dirnames, filenames in os.walk(lexical, followlinks=False):
        dirnames.sort()
        filenames.sort()
        directory_path = pathlib.Path(directory)
        for dirname in dirnames:
            child = directory_path / dirname
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise CollectorError(
                    "reviewed Tesseract support tree contains an unsafe directory"
                )
        for filename in filenames:
            path = directory_path / filename
            relative = path.relative_to(lexical).as_posix()
            snapshot = _external_file_snapshot(
                path,
                f"Tesseract support file {relative}",
                max_bytes=MAX_NATIVE_TOOL_BYTES,
            )
            inode_key = snapshot["identity"][:2]
            total_bytes += int(snapshot["size_bytes"])
            if inode_key in inode_keys:
                raise CollectorError("reviewed Tesseract support tree contains a hardlink")
            if (
                len(files) >= MAX_TESSERACT_SUPPORT_TREE_FILES
                or total_bytes > MAX_TESSERACT_SUPPORT_TREE_BYTES
            ):
                raise CollectorError(
                    "reviewed Tesseract support tree exceeds its custody limits"
                )
            inode_keys.add(inode_key)
            files.append({"relative": relative, **snapshot})
    relative_names = {item["relative"].casefold() for item in files}
    if "tesseract.exe" not in relative_names or "tessdata/eng.traineddata" not in relative_names:
        raise CollectorError(
            "OWNER-BLOCKED: reviewed Tesseract support tree lacks executable or English tessdata"
        )
    digest = hashlib.sha256()
    for item in files:
        digest.update(item["relative"].encode("utf-8") + b"\0")
        digest.update(item["sha256"].encode("ascii") + b"\0")
        digest.update(str(item["size_bytes"]).encode("ascii") + b"\0")
    return {
        "root": str(lexical),
        "root_identity": _stat_identity(root_info),
        "tree_sha256": digest.hexdigest(),
        "total_bytes": total_bytes,
        "files": files,
    }


def _reaudit_tesseract_support_tree(expected: dict[str, Any]) -> None:
    current = _tesseract_support_tree_snapshot(pathlib.Path(expected["root"]))
    if current != expected:
        raise CollectorError("Tesseract support tree changed after preflight")


def _reaudit_route_authority(snapshots: dict[str, dict[str, Any]]) -> None:
    if set(snapshots) != set(ROUTE_AUTHORITY_ROLES):
        raise CollectorError("Android remote-route authority is incomplete")
    for role in ROUTE_AUTHORITY_ROLES:
        expected = snapshots[role]
        current = _external_file_snapshot(
            pathlib.Path(expected["path"]),
            f"Android {role.replace('_', ' ')}",
            max_bytes=MAX_ROUTE_AUTHORITY_BYTES,
            retain_raw=expected["raw"] is not None,
        )
        if current != expected:
            raise CollectorError(
                f"Android {role.replace('_', ' ')} changed after preflight"
            )


def _normalized_map_city_labels(values: list[str]) -> list[str]:
    labels: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise CollectorError("Android map city labels must be strings")
        label = value.strip()
        if (
            len(label) < 2
            or len(label) > 80
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .'-]*", label) is None
        ):
            raise CollectorError("Android map city label is unsafe")
        labels.append(label)
    if len(labels) < 2 or len(labels) > 8:
        raise CollectorError("Android map evidence requires two to eight city labels")
    if len({label.casefold() for label in labels}) != len(labels):
        raise CollectorError("Android map city labels are duplicated")
    return sorted(labels, key=lambda label: (label.casefold(), label))


def _route_inventory_aliases(inventory: dict[str, Any]) -> set[str]:
    aliases: set[str] = set()
    for mode in ("node", "double_vpn"):
        value = inventory.get(mode)
        if not isinstance(value, dict):
            raise CollectorError("Android route inventory modes are incomplete")
        direct = value.get("direct")
        advertised = value.get("advertised_xray_routes")
        if not isinstance(direct, dict) or not isinstance(advertised, list):
            raise CollectorError("Android route inventory routes are incomplete")
        candidates = [direct, *advertised]
        for candidate in candidates:
            alias = candidate.get("ssh_alias") if isinstance(candidate, dict) else None
            if not isinstance(alias, str) or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", alias) is None:
                raise CollectorError("Android route inventory contains an unsafe SSH alias")
            aliases.add(alias)
    if not aliases:
        raise CollectorError("Android route inventory contains no SSH aliases")
    return aliases


def _validate_release_ssh_config(raw: bytes, aliases: set[str]) -> None:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CollectorError("Android release SSH config must be ASCII") from exc
    parsed: dict[str, dict[str, str]] = {}
    current_alias: str | None = None
    for line_number, original in enumerate(text.splitlines(), start=1):
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].rstrip()
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise CollectorError(
                f"Android release SSH config line {line_number} is malformed"
            )
        keyword, value = parts[0].casefold(), parts[1].strip()
        if keyword == "host":
            host_patterns = value.split()
            if (
                len(host_patterns) != 1
                or host_patterns[0] not in aliases
                or any(marker in host_patterns[0] for marker in ("*", "!", "?"))
                or host_patterns[0] in parsed
            ):
                raise CollectorError("Android release SSH config Host blocks are not exact")
            current_alias = host_patterns[0]
            parsed[current_alias] = {}
            continue
        if current_alias is None or keyword not in {"hostname", "user", "port"}:
            raise CollectorError(
                "Android release SSH config permits only Host, HostName, User, and Port"
            )
        if keyword in parsed[current_alias]:
            raise CollectorError("Android release SSH config contains duplicate options")
        parsed[current_alias][keyword] = value
    if set(parsed) != aliases:
        raise CollectorError("Android release SSH config does not bind every route alias")
    for alias, options in parsed.items():
        if set(options) != {"hostname", "user", "port"}:
            raise CollectorError(f"Android release SSH config block is incomplete: {alias}")
        host = options["hostname"]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if (
                len(host) > 253
                or re.fullmatch(
                    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
                    host,
                )
                is None
            ):
                raise CollectorError("Android release SSH config HostName is unsafe")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", options["user"]) is None:
            raise CollectorError("Android release SSH config User is unsafe")
        if not options["port"].isdigit() or not 1 <= int(options["port"]) <= 65535:
            raise CollectorError("Android release SSH config Port is unsafe")


def _validate_adb_server_environment(expected_socket: str) -> None:
    if re.fullmatch(r"tcp:127\.0\.0\.1:[1-9][0-9]{0,4}", expected_socket or "") is None:
        raise CollectorError("Android evidence requires one dedicated loopback ADB server")
    if int(expected_socket.rsplit(":", 1)[1]) > 65535:
        raise CollectorError("Android evidence ADB server port is invalid")
    if os.environ.get("ADB_SERVER_SOCKET") != expected_socket:
        raise CollectorError("Android evidence ADB server socket is not exact")
    if os.environ.get("ADB_LIBUSB") != "1":
        raise CollectorError(
            "Android evidence requires the reviewed Windows libusb ADB backend"
        )
    for name in ("ANDROID_ADB_SERVER_ADDRESS", "ANDROID_ADB_SERVER_PORT"):
        if os.environ.get(name):
            raise CollectorError(f"Android evidence rejects {name} overrides")


def _device_attestation_challenge(
    *,
    manifest_sha256: str,
    app_version: str,
    phone_build_number: str,
    serial_sha256: str,
) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(
            {
                "application_id": EXPECTED_APPLICATION_ID,
                "app_version": app_version,
                "form_factor_manifest_sha256": manifest_sha256,
                "phone_build_number": phone_build_number,
                "serial_sha256": serial_sha256,
            },
            "Android device-attestation challenge",
        )
    ).hexdigest()


def _attested_key_id(modulus_hex: str, exponent: int) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(
            {
                "algorithm": "rsa",
                "exponent": exponent,
                "modulus_hex": modulus_hex,
            },
            "Android attested public key",
        )
    ).hexdigest()


def _device_attestation_receipt(
    repo: pathlib.Path,
    path: pathlib.Path,
    *,
    manifest_sha256: str,
    app_version: str,
    phone_build_number: str,
    serial: str,
    bound_files: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if (
        re.fullmatch(r"[A-Za-z0-9._-]{4,128}", serial or "") is None
        or serial.casefold().startswith("emulator-")
    ):
        raise CollectorError("Android physical evidence requires an exact hardware serial")
    snapshot = _bound_file_snapshot(
        repo,
        path,
        "Android physical-device attestation receipt",
        max_bytes=MAX_DEVICE_ATTESTATION_BYTES,
        require_artifacts=True,
    )
    value = _strict_json_bytes(
        snapshot["raw"], "Android physical-device attestation receipt"
    )
    fields = {
        "schema_version",
        "contract",
        "application_id",
        "app_version",
        "phone_build_number",
        "serial_sha256",
        "transport",
        "hardware_identity_sha256",
        "attestation_challenge_sha256",
        "key_attestation_verified",
        "attestation_chain_verified",
        "attestation_security_level",
        "attestation_certificate_chain_sha256",
        "attestation_leaf_certificate_sha256",
        "attestation_application_id",
        "attestation_app_signer_sha256",
        "hardware_enforced_key_authorization",
        "attested_public_key_algorithm",
        "attested_rsa_modulus_hex",
        "attested_rsa_public_exponent",
        "attested_key_id",
        "live_proof_signature_algorithm",
        "verified_boot_state",
        "device_locked",
        "captured_at_utc",
        "passed",
        "secret_material_redacted",
    }
    serial_sha256 = sha256_text(serial)
    modulus_hex = value.get("attested_rsa_modulus_hex")
    exponent = value.get("attested_rsa_public_exponent")
    modulus = (
        int(modulus_hex, 16)
        if isinstance(modulus_hex, str)
        and re.fullmatch(r"[0-9a-f]{512,1024}", modulus_hex) is not None
        else 0
    )
    key_authorization = value.get("hardware_enforced_key_authorization")
    if (
        set(value) != fields
        or value["schema_version"] != 1
        or value["contract"] != DEVICE_ATTESTATION_CONTRACT
        or value["application_id"] != EXPECTED_APPLICATION_ID
        or value["app_version"] != app_version
        or value["phone_build_number"] != phone_build_number
        or value["serial_sha256"] != serial_sha256
        or value["transport"] != "usb"
        or re.fullmatch(r"[0-9a-f]{64}", str(value["hardware_identity_sha256"]))
        is None
        or value["attestation_challenge_sha256"]
        != _device_attestation_challenge(
            manifest_sha256=manifest_sha256,
            app_version=app_version,
            phone_build_number=phone_build_number,
            serial_sha256=serial_sha256,
        )
        or value["key_attestation_verified"] is not True
        or value["attestation_chain_verified"] is not True
        or value["attestation_security_level"] not in {"tee", "strongbox"}
        or re.fullmatch(
            r"[0-9a-f]{64}", str(value["attestation_certificate_chain_sha256"])
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", str(value["attestation_leaf_certificate_sha256"])
        )
        is None
        or value["attestation_certificate_chain_sha256"] in {"0" * 64, EMPTY_SHA256}
        or value["attestation_leaf_certificate_sha256"] in {"0" * 64, EMPTY_SHA256}
        or value["attestation_application_id"] != DEVICE_ATTESTATION_PACKAGE
        or value["attestation_app_signer_sha256"] != EXPECTED_SIGNER
        or not isinstance(key_authorization, dict)
        or set(key_authorization)
        != {
            "keymint_security_level",
            "origin",
            "purposes",
            "digests",
            "signature_paddings",
        }
        or key_authorization["keymint_security_level"]
        != value["attestation_security_level"]
        or key_authorization["origin"] != "generated"
        or key_authorization["purposes"] != ["sign"]
        or key_authorization["digests"] != ["sha256"]
        or key_authorization["signature_paddings"]
        != ["rsa-pkcs1-v1_5-sign"]
        or value["attested_public_key_algorithm"] != "rsa"
        or not isinstance(exponent, int)
        or isinstance(exponent, bool)
        or exponent != 65537
        or modulus.bit_length() not in {2048, 3072, 4096}
        or modulus_hex != format(modulus, "x")
        or len(modulus_hex) != modulus.bit_length() // 4
        or modulus % 2 == 0
        or value["attested_key_id"] != _attested_key_id(modulus_hex, exponent)
        or value["live_proof_signature_algorithm"]
        != "rsa-pkcs1-v1_5-sha256"
        or value["verified_boot_state"] != "green"
        or value["device_locked"] is not True
        or value["passed"] is not True
        or value["secret_material_redacted"] is not True
    ):
        raise CollectorError("Android physical-device attestation receipt is invalid")
    captured = _parse_receipt_time(
        value["captured_at_utc"], "Android physical-device attestation receipt"
    )
    now = dt.datetime.now(dt.timezone.utc)
    if captured < now - MAX_RUNTIME_RECEIPT_SKEW or captured > now + dt.timedelta(minutes=5):
        raise CollectorError("Android physical-device attestation receipt is stale")
    bound_files[str(snapshot["path"])] = snapshot
    return {"snapshot": snapshot, "value": value}


def _devicecheck_evidence_record(
    value: Any,
    label: str,
    *,
    expected_path: str | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"bytes", "path", "sha256"}
        or not isinstance(value["bytes"], int)
        or isinstance(value["bytes"], bool)
        or value["bytes"] <= 0
        or not isinstance(value["path"], str)
        or not value["path"]
        or re.fullmatch(r"[0-9a-f]{64}", str(value["sha256"])) is None
        or value["sha256"] in {"0" * 64, EMPTY_SHA256}
        or (expected_path is not None and value["path"] != expected_path)
    ):
        raise CollectorError(f"{label} evidence record is invalid")
    return value


def _devicecheck_owner_pinned_bytes(value: str, label: str) -> int:
    if re.fullmatch(r"[1-9][0-9]{0,9}", value or "") is None:
        raise CollectorError(f"{label} owner-pinned byte count is invalid")
    parsed = int(value)
    if parsed > 512 * 1024 * 1024:
        raise CollectorError(f"{label} owner-pinned byte count is out of range")
    return parsed


def _devicecheck_artifact_record(
    value: Any,
    label: str,
    *,
    expected_path: str,
    expected_package_id: str,
) -> dict[str, Any]:
    fields = {
        "bytes",
        "identity",
        "package_id",
        "path",
        "sha256",
        "signer_sha256",
        "version_code",
        "version_name",
        "version_name_utf8_hex",
    }
    identity_fields = {
        "ctime_ns",
        "device",
        "flags",
        "gid",
        "inode",
        "mode",
        "mtime_ns",
        "nlink",
        "size",
        "uid",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise CollectorError(f"{label} artifact fields are invalid")
    identity = value["identity"]
    if (
        not isinstance(identity, dict)
        or set(identity) != identity_fields
        or any(
            not isinstance(identity[field], int) or isinstance(identity[field], bool)
            for field in identity_fields
        )
        or any(identity[field] < 0 for field in identity_fields - {"mode"})
        or identity["mode"] < 0
        or identity["mode"] > 0o7777
        or identity["nlink"] != 1
        or identity["size"] != value["bytes"]
        or not isinstance(value["bytes"], int)
        or isinstance(value["bytes"], bool)
        or value["bytes"] <= 0
        or value["bytes"] > MAX_DEVICECHECK_BUILD_RECEIPT_BYTES * 1024
        or value["path"] != expected_path
        or value["package_id"] != expected_package_id
        or value["version_name"] != DEVICE_ATTESTATION_VERSION_NAME
        or value["version_name_utf8_hex"]
        != DEVICE_ATTESTATION_VERSION_NAME.encode("utf-8").hex()
        or value["version_code"] != DEVICE_ATTESTATION_VERSION_CODE
        or re.fullmatch(r"[0-9a-f]{64}", str(value["sha256"])) is None
        or value["sha256"] in {"0" * 64, EMPTY_SHA256}
        or value["signer_sha256"] != EXPECTED_SIGNER
    ):
        raise CollectorError(f"{label} artifact identity is invalid")
    return value


def _devicecheck_build_receipt(
    repo: pathlib.Path,
    path: pathlib.Path,
    expected_sha256: str,
    bound_files: dict[str, dict[str, Any]],
    *,
    expected_target_apk_sha256: str,
    expected_target_apk_bytes: int,
    expected_android_test_apk_sha256: str,
    expected_android_test_apk_bytes: int,
    expected_source_inventory_sha256: str,
) -> dict[str, Any]:
    expected_path = repo / DEVICECHECK_BUILD_RECEIPT_RELATIVE
    if path != expected_path:
        raise CollectorError(
            "OWNER-BLOCKED: exact release DeviceCheck build receipt path is required"
        )
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or "") is None:
        raise CollectorError(
            "OWNER-BLOCKED: exact DeviceCheck build receipt hash is required"
        )
    snapshot = _bound_file_snapshot(
        repo,
        path,
        "DeviceCheck target and androidTest build receipt",
        max_bytes=MAX_DEVICECHECK_BUILD_RECEIPT_BYTES,
        require_artifacts=False,
    )
    if snapshot["sha256"] != expected_sha256:
        raise CollectorError("DeviceCheck build receipt changed")
    sidecar = _bound_file_snapshot(
        repo,
        repo / DEVICECHECK_BUILD_RECEIPT_SIDECAR_RELATIVE,
        "DeviceCheck build receipt sidecar",
        max_bytes=1024,
        require_artifacts=False,
    )
    expected_sidecar = (
        f"{expected_sha256}  DEVICECHECK_BUILD_RECEIPT.json\n".encode("ascii")
    )
    if sidecar["raw"] != expected_sidecar:
        raise CollectorError("DeviceCheck build receipt sidecar is invalid")
    value = _strict_json_bytes(snapshot["raw"], "DeviceCheck build receipt")
    top_fields = {
        "artifacts",
        "build",
        "consumer_status",
        "contract",
        "gradle_custody",
        "owner_signer",
        "parity",
        "producer",
        "receipt_storage",
        "schema_version",
        "source_closure",
        "source_transaction",
        "toolchain",
    }
    if (
        set(value) != top_fields
        or value["schema_version"] != 2
        or value["contract"] != DEVICECHECK_BUILD_RECEIPT_CONTRACT
    ):
        raise CollectorError("DeviceCheck build receipt contract is invalid")
    if value["consumer_status"] != DEVICECHECK_SOURCE_CONSUMER_STATUS:
        raise CollectorError(
            "OWNER-BLOCKED: DeviceCheck source-custody consumer is not integrated"
        )
    build = value["build"]
    target_path = (
        "android/devicecheck/app/build/outputs/apk/release/app-release.apk"
    )
    test_path = (
        "android/devicecheck/app/build/outputs/apk/androidTest/release/"
        "app-release-androidTest.apk"
    )
    if build != {
        "android_test_output": test_path,
        "android_test_task": ":app:assembleReleaseAndroidTest",
        "min_sdk": 24,
        "target_output": target_path,
        "target_task": ":app:assembleRelease",
        "variant": "release",
    }:
        raise CollectorError("DeviceCheck build receipt is not the exact release variant")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {"android_test", "target"}:
        raise CollectorError("DeviceCheck build receipt artifact set is invalid")
    target = _devicecheck_artifact_record(
        artifacts["target"],
        "DeviceCheck target APK",
        expected_path=target_path,
        expected_package_id=DEVICE_ATTESTATION_PACKAGE,
    )
    android_test = _devicecheck_artifact_record(
        artifacts["android_test"],
        "DeviceCheck androidTest APK",
        expected_path=test_path,
        expected_package_id=DEVICE_ATTESTATION_TEST_PACKAGE,
    )
    if (
        target["sha256"] == android_test["sha256"]
        or target["identity"]["device"] == android_test["identity"]["device"]
        and target["identity"]["inode"] == android_test["identity"]["inode"]
    ):
        raise CollectorError("DeviceCheck build receipt reuses one APK")
    expected_artifacts = (
        (target, expected_target_apk_sha256, expected_target_apk_bytes),
        (android_test, expected_android_test_apk_sha256, expected_android_test_apk_bytes),
    )
    if any(
        re.fullmatch(r"[0-9a-f]{64}", expected_digest or "") is None
        or expected_digest in {"0" * 64, EMPTY_SHA256}
        or not isinstance(expected_bytes, int)
        or isinstance(expected_bytes, bool)
        or expected_bytes <= 0
        or record["sha256"] != expected_digest
        or record["bytes"] != expected_bytes
        for record, expected_digest, expected_bytes in expected_artifacts
    ):
        raise CollectorError("DeviceCheck APK producer receipt contradicts owner custody")
    if (
        re.fullmatch(r"[0-9a-f]{64}", expected_source_inventory_sha256 or "")
        is None
        or expected_source_inventory_sha256 in {"0" * 64, EMPTY_SHA256}
    ):
        raise CollectorError("DeviceCheck source-inventory owner pin is invalid")
    parity = value["parity"]
    if parity != {
        "android_test_package_id": DEVICE_ATTESTATION_TEST_PACKAGE,
        "package_relation": "target_package_id + .test",
        "passed": True,
        "signer_sha256": EXPECTED_SIGNER,
        "version_code": DEVICE_ATTESTATION_VERSION_CODE,
        "version_name_utf8_hex": DEVICE_ATTESTATION_VERSION_NAME.encode("utf-8").hex(),
    }:
        raise CollectorError("DeviceCheck target/androidTest parity is invalid")
    source_closure = value["source_closure"]
    inventory = source_closure.get("inventory") if isinstance(source_closure, dict) else None
    if (
        not isinstance(source_closure, dict)
        or set(source_closure) != {"inventory", "inventory_sha256"}
        or not isinstance(inventory, list)
        or not inventory
        or len(inventory) > 4096
        or source_closure["inventory_sha256"]
        != hashlib.sha256(
            _canonical_json_bytes(inventory, "DeviceCheck source inventory") + b"\n"
        ).hexdigest()
    ):
        raise CollectorError("DeviceCheck source closure is invalid")
    if source_closure["inventory_sha256"] != expected_source_inventory_sha256:
        raise CollectorError("DeviceCheck source inventory contradicts owner custody")

    owner_signer = value["owner_signer"]
    if owner_signer != {
        "certificate_sha256": EXPECTED_SIGNER,
        "identity_source": "reviewed-source-pin",
    }:
        raise CollectorError("DeviceCheck owner signer identity is invalid")
    source_transaction = value["source_transaction"]
    source_transaction_fields = {
        "authority_sha256",
        "expires_unix_ns",
        "monotonic_sequence",
        "nonce",
        "prebuild_source_inventory_sha256",
        "source_snapshot",
        "transaction_sha256",
        "workspace",
    }
    workspace = (
        source_transaction.get("workspace")
        if isinstance(source_transaction, dict)
        else None
    )
    workspace_fields = {"device", "inode", "mode", "path", "uid"}
    if (
        not isinstance(source_transaction, dict)
        or set(source_transaction) != source_transaction_fields
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(source_transaction[field])) is None
            or source_transaction[field] in {"0" * 64, EMPTY_SHA256}
            for field in ("authority_sha256", "nonce", "transaction_sha256")
        )
        or source_transaction["prebuild_source_inventory_sha256"]
        != source_closure["inventory_sha256"]
        or not isinstance(source_transaction["expires_unix_ns"], int)
        or isinstance(source_transaction["expires_unix_ns"], bool)
        or source_transaction["expires_unix_ns"] <= 0
        or not isinstance(source_transaction["monotonic_sequence"], int)
        or isinstance(source_transaction["monotonic_sequence"], bool)
        or source_transaction["monotonic_sequence"] <= 0
        or not isinstance(workspace, dict)
        or set(workspace) != workspace_fields
        or any(
            not isinstance(workspace[field], int) or isinstance(workspace[field], bool)
            for field in workspace_fields - {"path"}
        )
        or workspace["device"] <= 0
        or workspace["inode"] <= 0
        or workspace["mode"] != 0o700
        or workspace["uid"] <= 0
        or not isinstance(workspace["path"], str)
        or not (
            pathlib.PurePosixPath(workspace["path"]).is_absolute()
            or pathlib.PureWindowsPath(workspace["path"]).is_absolute()
        )
    ):
        raise CollectorError("DeviceCheck source transaction identity is invalid")
    expected_source_snapshot = (
        DEVICECHECK_SOURCE_SNAPSHOT_PREFIX
        + source_transaction["prebuild_source_inventory_sha256"]
    )
    if source_transaction["source_snapshot"] != expected_source_snapshot:
        raise CollectorError(
            "OWNER-BLOCKED: DeviceCheck source transaction is not bound to the "
            "current content-addressed source custody"
        )

    artifact_snapshots: dict[str, dict[str, Any]] = {}
    for role, record in (("target", target), ("android_test", android_test)):
        current = _bound_file_snapshot(
            repo,
            repo / pathlib.PurePosixPath(record["path"]),
            f"DeviceCheck {role.replace('_', ' ')} APK",
            max_bytes=512 * 1024 * 1024,
            require_artifacts=False,
            retain_raw=False,
        )
        if (
            current["sha256"] != record["sha256"]
            or current["size_bytes"] != record["bytes"]
        ):
            raise CollectorError(
                "locally held DeviceCheck APK contradicts producer custody"
            )
        bound_files[str(current["path"])] = current
        artifact_snapshots[role] = current
    source_records: dict[str, dict[str, Any]] = {}
    total_source_bytes = 0
    for item in inventory:
        record = _devicecheck_evidence_record(item, "DeviceCheck source closure")
        relative = pathlib.PurePosixPath(record["path"])
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or record["path"] in source_records
        ):
            raise CollectorError("DeviceCheck source closure path is unsafe or duplicated")
        current = _bound_file_snapshot(
            repo,
            repo / relative,
            f"DeviceCheck source closure {record['path']}",
            max_bytes=4 * 1024 * 1024,
            require_artifacts=False,
        )
        total_source_bytes += current["size_bytes"]
        if (
            total_source_bytes > 64 * 1024 * 1024
            or current["sha256"] != record["sha256"]
            or current["size_bytes"] != record["bytes"]
        ):
            raise CollectorError("DeviceCheck source closure changed")
        source_records[record["path"]] = record
        bound_files[str(current["path"])] = current
    if list(source_records) != sorted(source_records):
        raise CollectorError("DeviceCheck source closure is not canonically ordered")
    required_sources = {
        "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/HardwareAttestationTest.kt",
        "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/LiveHardwareAttestationProofTest.kt",
        "android/devicecheck/build_devicecheck.sh",
        "android/devicecheck/devicecheck_build_receipt.py",
        "android/devicecheck/devicecheck_source_custody.py",
        "android/devicecheck/test_devicecheck_build_receipt.py",
        "android/devicecheck/test_devicecheck_source_custody.py",
        "android/devicecheck/test_live_hardware_attestation_proof.py",
        "android/devicecheck/test_shipping_source_closure.py",
        "android/devicecheck/gradle/dependency-locking/app.lockfile",
        "android/devicecheck/gradle/verification-metadata.xml",
    }
    if not required_sources.issubset(source_records):
        raise CollectorError("DeviceCheck source closure omits a required producer input")
    source_custody_snapshot = bound_files[
        str(repo / "android/devicecheck/devicecheck_source_custody.py")
    ]
    required_source_custody_fragments = (
        f'CONTRACT = "{DEVICECHECK_SOURCE_CUSTODY_CONTRACT}"'.encode("ascii"),
        f'OWNER_AUTHORITY_CONTRACT = "{DEVICECHECK_SOURCE_AUTHORITY_CONTRACT}"'.encode(
            "ascii"
        ),
        b'SOURCE_AUTHORITY_RELATIVE = "ReleaseAndroidSource/devicecheck-v3"',
        f'CONSUMER_STATUS = "{DEVICECHECK_SOURCE_CONSUMER_STATUS}"'.encode("ascii"),
    )
    if any(
        source_custody_snapshot["raw"].count(fragment) != 1
        for fragment in required_source_custody_fragments
    ):
        raise CollectorError(
            "DeviceCheck source closure does not contain the current content-addressed "
            "source-custody contract"
        )
    producer = value["producer"]
    producer_paths = {
        "build_script": "android/devicecheck/build_devicecheck.sh",
        "companion_source_contract_test": "android/devicecheck/test_live_hardware_attestation_proof.py",
        "hardware_attestation_test": "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/HardwareAttestationTest.kt",
        "live_hardware_attestation_proof_test": "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/LiveHardwareAttestationProofTest.kt",
        "receipt_tool": "android/devicecheck/devicecheck_build_receipt.py",
        "source_custody": "android/devicecheck/devicecheck_source_custody.py",
        "source_custody_contract_test": "android/devicecheck/test_devicecheck_source_custody.py",
        "shipping_source_closure_test": "android/devicecheck/test_shipping_source_closure.py",
    }
    if not isinstance(producer, dict) or set(producer) != set(producer_paths):
        raise CollectorError("DeviceCheck producer closure is invalid")
    for role, relative in producer_paths.items():
        if producer[role] != source_records[relative]:
            raise CollectorError("DeviceCheck producer closure contradicts its inventory")
    gradle = value["gradle_custody"]
    if (
        not isinstance(gradle, dict)
        or set(gradle)
        != {
            "agp_version",
            "dependency_lock",
            "gradle_version",
            "ndk_version",
            "verification_metadata",
        }
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", str(gradle["agp_version"])) is None
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", str(gradle["gradle_version"])) is None
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", str(gradle["ndk_version"])) is None
        or gradle["dependency_lock"]
        != source_records["android/devicecheck/gradle/dependency-locking/app.lockfile"]
        or gradle["verification_metadata"]
        != source_records["android/devicecheck/gradle/verification-metadata.xml"]
    ):
        raise CollectorError("DeviceCheck Gradle custody is invalid")
    storage = value["receipt_storage"]
    if storage != {
        "publication": "descriptor-relative-no-replace",
        "receipt_name": "DEVICECHECK_BUILD_RECEIPT.json",
        "sidecar_name": "DEVICECHECK_BUILD_RECEIPT.json.sha256",
    }:
        raise CollectorError("DeviceCheck receipt publication contract is invalid")
    toolchain = value["toolchain"]
    expected_tool_paths = {
        "aapt": f"build-tools/{DEVICECHECK_BUILD_TOOLS_VERSION}/aapt",
        "apksigner": f"build-tools/{DEVICECHECK_BUILD_TOOLS_VERSION}/apksigner",
        "apksigner_jar": (
            f"build-tools/{DEVICECHECK_BUILD_TOOLS_VERSION}/lib/apksigner.jar"
        ),
    }
    if (
        not isinstance(toolchain, dict)
        or set(toolchain)
        != {
            *expected_tool_paths,
            "android_build_tools_version",
            "execution",
            "java",
            "java_root",
        }
        or toolchain["android_build_tools_version"] != DEVICECHECK_BUILD_TOOLS_VERSION
        or toolchain["java_root"] != DEVICECHECK_SEALED_JAVA_ROOT
        or toolchain["execution"]
        != {
            "aapt": "held-path-with-ancestor-custody",
            "apksigner": "sealed-java-held-jar-descriptor",
            "environment": "explicit-allowlist",
        }
    ):
        raise CollectorError("DeviceCheck reviewed Build Tools custody is invalid")
    tool_hashes: set[str] = set()
    for role, relative in expected_tool_paths.items():
        record = _devicecheck_evidence_record(
            toolchain[role], f"DeviceCheck {role}", expected_path=relative
        )
        tool_hashes.add(record["sha256"])
    java = _devicecheck_evidence_record(
        toolchain["java"],
        "DeviceCheck sealed Java",
        expected_path=DEVICECHECK_SEALED_JAVA_RELATIVE,
    )
    tool_hashes.add(java["sha256"])
    if len(tool_hashes) != len(expected_tool_paths) + 1:
        raise CollectorError("DeviceCheck reviewed Build Tools inputs are duplicated")
    bound_files[str(snapshot["path"])] = snapshot
    bound_files[str(sidecar["path"])] = sidecar
    return {
        "snapshot": snapshot,
        "sidecar": sidecar,
        "value": value,
        "target": target,
        "android_test": android_test,
        "artifact_snapshots": artifact_snapshots,
    }


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt" and process.poll() is None and _WINDOWS_TASKKILL is not None:
        try:
            killer = subprocess.Popen(
                [
                    str(_WINDOWS_TASKKILL),
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            killer.wait(timeout=15)
        except (OSError, subprocess.SubprocessError):
            pass
    elif os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    if process.poll() is None:
        try:
            process.kill()
        except (OSError, ProcessLookupError):
            pass


def _bounded_subprocess_run(
    command: list[str],
    *,
    input: str | bytes | None = None,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    text: bool = False,
    timeout: float,
    check: bool = False,
    pass_fds: tuple[int, ...] = (),
    stdout_limit: int = MAX_SUBPROCESS_STDOUT_BYTES,
    stderr_limit: int = MAX_SUBPROCESS_STDERR_BYTES,
) -> subprocess.CompletedProcess:
    if (
        not command
        or any(not isinstance(item, int) or item < 3 for item in pass_fds)
        or len(set(pass_fds)) != len(pass_fds)
        or os.name == "nt" and pass_fds
        or stdout_limit <= 0
        or stderr_limit <= 0
        or timeout <= 0
    ):
        raise CollectorError("bounded Android subprocess parameters are invalid")
    try:
        for descriptor in pass_fds:
            os.fstat(descriptor)
    except OSError as exc:
        raise CollectorError("bounded Android subprocess inherited descriptor is invalid") from exc
    stdin_bytes = (
        input.encode("utf-8") if isinstance(input, str) else input
    )
    if stdin_bytes is not None and len(stdin_bytes) > 1024 * 1024:
        raise CollectorError("bounded Android subprocess input is too large")
    popen_options: dict[str, Any] = {
        "stdin": subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": False,
        "close_fds": True,
    }
    if env is not None:
        popen_options["env"] = env
    if cwd is not None:
        popen_options["cwd"] = str(cwd)
    if os.name == "nt":
        popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_options["start_new_session"] = True
        popen_options["pass_fds"] = pass_fds
    try:
        process = subprocess.Popen(command, **popen_options)
    except OSError as exc:
        raise CollectorError("bounded Android subprocess could not start") from exc
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    overflow = threading.Event()
    read_error: list[BaseException] = []

    def drain(stream: Any, target: bytearray, limit: int) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                remaining = limit - len(target)
                if len(chunk) > remaining:
                    if remaining > 0:
                        target.extend(chunk[:remaining])
                    overflow.set()
                    _terminate_process_tree(process)
                    return
                target.extend(chunk)
        except BaseException as exc:  # pragma: no cover - platform pipe failure
            read_error.append(exc)
            _terminate_process_tree(process)

    stdout_thread = threading.Thread(
        target=drain,
        args=(process.stdout, stdout_buffer, stdout_limit),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain,
        args=(process.stderr, stderr_buffer, stderr_limit),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        if process.stdin is not None:
            try:
                process.stdin.write(stdin_bytes or b"")
                process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                process.stdin.close()
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if overflow.is_set() or read_error:
                _terminate_process_tree(process)
                break
            if time.monotonic() >= deadline:
                _terminate_process_tree(process)
                raise CollectorError("bounded Android subprocess timed out")
            time.sleep(0.01)
        process.wait(timeout=15)
    finally:
        _terminate_process_tree(process)
        stdout_thread.join(timeout=15)
        stderr_thread.join(timeout=15)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
    if stdout_thread.is_alive() or stderr_thread.is_alive() or read_error:
        raise CollectorError("bounded Android subprocess pipe cleanup failed")
    if overflow.is_set():
        raise CollectorError("bounded Android subprocess exceeded its output limit")
    stdout: str | bytes = bytes(stdout_buffer)
    stderr: str | bytes = bytes(stderr_buffer)
    if text:
        try:
            stdout = stdout.decode("utf-8", errors="strict")
            stderr = stderr.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CollectorError("bounded Android subprocess returned invalid UTF-8") from exc
    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, command, output=stdout, stderr=stderr
        )
    return result


def _adb_transport_binding(
    adb: pathlib.Path,
    serial: str,
    expected_transport_id: str | None = None,
) -> dict[str, str]:
    completed = _bounded_subprocess_run(
        [str(adb), "devices", "-l"],
        text=True,
        timeout=30,
        check=False,
        stdout_limit=64 * 1024,
        stderr_limit=64 * 1024,
    )
    if completed.returncode != 0:
        raise CollectorError("Android USB transport inventory failed")
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if lines.count("List of devices attached") != 1:
        raise CollectorError("Android ADB transport inventory is malformed")
    rows = [line.split() for line in lines if line != "List of devices attached"]
    if len(rows) != 1 or len(rows[0]) < 4:
        raise CollectorError("Android evidence requires exactly one ADB transport")
    row = rows[0]
    if row[0] != serial or row[1] != "device":
        raise CollectorError("Android physical device is not uniquely online")
    usb_values = [token[4:] for token in row[2:] if token.startswith("usb:")]
    transport_ids = [
        token[len("transport_id:") :]
        for token in row[2:]
        if token.startswith("transport_id:")
    ]
    if (
        len(usb_values) > 1
        or (
            len(usb_values) == 1
            and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", usb_values[0] or "")
            is None
        )
        or len(transport_ids) != 1
        or re.fullmatch(r"[1-9][0-9]{0,9}", transport_ids[0] or "") is None
        or int(transport_ids[0]) > 2147483647
        or (
            expected_transport_id is not None
            and transport_ids[0] != expected_transport_id
        )
    ):
        raise CollectorError("Android evidence requires one stable physical USB transport")
    return {
        "listed_usb": usb_values[0] if usb_values else "",
        "transport_id": transport_ids[0],
    }


def _adb_libusb_device_path(adb: pathlib.Path, transport_id: str) -> str:
    features = _bounded_subprocess_run(
        [str(adb), "host-features"],
        text=True,
        timeout=30,
        check=False,
        stdout_limit=64 * 1024,
        stderr_limit=64 * 1024,
    )
    feature_set = {
        item.strip() for item in features.stdout.strip().split(",") if item.strip()
    }
    if features.returncode != 0 or "libusb" not in feature_set:
        raise CollectorError("Android evidence requires an active libusb ADB server")
    device_path = _adb_text(adb, transport_id, ["get-devpath"])
    if re.fullmatch(r"usb:[A-Za-z0-9._:-]{1,128}", device_path or "") is None:
        raise CollectorError("Android ADB transport is not a physical USB device path")
    return device_path


def _adb_text(adb: pathlib.Path, transport_id: str, arguments: list[str]) -> str:
    completed = _bounded_subprocess_run(
        [str(adb), "-t", transport_id, *arguments],
        text=True,
        timeout=30,
        check=False,
        stdout_limit=64 * 1024,
        stderr_limit=64 * 1024,
    )
    if completed.returncode != 0:
        raise CollectorError("Android physical-device identity query failed")
    return completed.stdout.strip()


def _rsa_pkcs1_v1_5_sha256_verify(
    modulus_hex: str, exponent: int, message: bytes, signature_hex: str
) -> bool:
    try:
        modulus = int(modulus_hex, 16)
        signature = bytes.fromhex(signature_hex)
    except (TypeError, ValueError):
        return False
    width = (modulus.bit_length() + 7) // 8
    if len(signature) != width or int.from_bytes(signature, "big") >= modulus:
        return False
    encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(
        width, "big"
    )
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    tail = digest_info + hashlib.sha256(message).digest()
    padding_length = width - len(tail) - 3
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + tail
    return secrets.compare_digest(encoded, expected)


def _device_report_uint(
    report: dict[str, str], name: str, minimum: int, maximum: int
) -> int:
    value = report[name]
    if (
        re.fullmatch(r"0|[1-9][0-9]*", value) is None
        or len(value) > 20
    ):
        raise CollectorError(f"Android device semantic report {name} is invalid")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise CollectorError(f"Android device semantic report {name} is out of range")
    return parsed


def _device_report_bool(report: dict[str, str], name: str) -> bool:
    value = report[name]
    if value not in {"true", "false"}:
        raise CollectorError(f"Android device semantic report {name} is invalid")
    return value == "true"


def _device_report_utf8_hex(
    report: dict[str, str], name: str, *, maximum_bytes: int
) -> str:
    value = report[name]
    if (
        len(value) % 2 != 0
        or len(value) > maximum_bytes * 2
        or re.fullmatch(r"[0-9a-f]+", value) is None
    ):
        raise CollectorError(f"Android device semantic report {name} is invalid")
    try:
        raw = bytes.fromhex(value)
        decoded = raw.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise CollectorError(
            f"Android device semantic report {name} is not canonical UTF-8"
        ) from exc
    if not raw or decoded.encode("utf-8") != raw:
        raise CollectorError(
            f"Android device semantic report {name} is not canonical UTF-8"
        )
    return decoded


def _parse_device_semantic_report(raw: bytes) -> dict[str, str]:
    if (
        not raw
        or len(raw) > MAX_DEVICE_ATTESTATION_REPORT_BYTES
        or not raw.endswith(b"\n")
        or any(byte < 0x20 or byte > 0x7E for byte in raw if byte != 0x0A)
    ):
        raise CollectorError("Android device semantic report is not bounded ASCII")
    lines = raw[:-1].split(b"\n")
    if len(lines) != len(DEVICE_ATTESTATION_REPORT_FIELDS):
        raise CollectorError("Android device semantic report field count is invalid")
    report: dict[str, str] = {}
    for expected_name, line in zip(DEVICE_ATTESTATION_REPORT_FIELDS, lines):
        try:
            text = line.decode("ascii")
        except UnicodeError as exc:
            raise CollectorError("Android device semantic report is not ASCII") from exc
        match = re.fullmatch(
            r"([a-z][a-z0-9_]{0,95})=([A-Za-z0-9._,:+\-]{1,2048})",
            text,
        )
        if match is None or match.group(1) != expected_name:
            raise CollectorError("Android device semantic report order is invalid")
        if expected_name in report:
            raise CollectorError("Android device semantic report has duplicate fields")
        report[expected_name] = match.group(2)
    return report


def _nonce_salted_device_report_hash(nonce: bytes, label: str, value: str) -> str:
    if (
        len(nonce) != 32
        or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", label) is None
        or not value
        or len(value.encode("utf-8")) > 16 * 1024
    ):
        raise CollectorError("Android device report nonce-hash input is invalid")
    return hashlib.sha256(
        DEVICE_ATTESTATION_NONCE_HASH_DOMAIN
        + nonce
        + b"\0"
        + label.encode("ascii")
        + b"\0"
        + value.encode("utf-8")
    ).hexdigest()


def _validate_device_semantic_report(
    report: dict[str, str],
    nonce: bytes,
    attestation: dict[str, Any],
    context_sha256: str,
) -> None:
    receipt = attestation["value"]
    package_name = DEVICE_ATTESTATION_PACKAGE
    package_version_hex = DEVICE_ATTESTATION_VERSION_NAME.encode("utf-8").hex()
    package_source_pattern = re.compile(
        r"none|[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+"
    )
    expected_fixed = {
        "schema": DEVICE_ATTESTATION_REPORT_SCHEMA,
        "host_session_nonce": nonce.hex(),
        "transcript_context_sha256": context_sha256,
        "persistent_key_id": receipt["attested_key_id"],
        "target_package_id": package_name,
        "target_version_name_utf8_hex": package_version_hex,
        "target_version_code": str(DEVICE_ATTESTATION_VERSION_CODE),
        "target_signer_sha256": receipt["attestation_app_signer_sha256"],
        "test_apk_package_id": DEVICE_ATTESTATION_TEST_PACKAGE,
        "test_apk_version_name_utf8_hex": package_version_hex,
        "test_apk_version_code": str(DEVICE_ATTESTATION_VERSION_CODE),
        "test_apk_signer_sha256": receipt["attestation_app_signer_sha256"],
        "key_origin": "generated",
        "key_purposes": "sign",
        "key_digests": "sha256",
        "key_signature_paddings": "rsa-pkcs1-v1_5-sign",
        "key_security_level": receipt["attestation_security_level"],
        "key_rsa_modulus_bits": str(
            int(receipt["attested_rsa_modulus_hex"], 16).bit_length()
        ),
        "key_rsa_public_exponent": str(receipt["attested_rsa_public_exponent"]),
        "attestation_leaf_certificate_sha256": receipt[
            "attestation_leaf_certificate_sha256"
        ],
        "attestation_security_level": receipt["attestation_security_level"],
        "keymint_security_level": receipt["attestation_security_level"],
        "attestation_challenge_sha256": receipt["attestation_challenge_sha256"],
        "attested_device_locked": "true",
        "attested_verified_boot_state": "green",
        "current_verified_boot_state": "green",
        "current_flash_locked": "1",
        "current_vbmeta_device_state": "locked",
        "user_device_secure": "true",
        "user_unlocked": "true",
        "device_provisioned": "true",
        "android_sdk": report["android_sdk"],
    }
    if any(report[name] != value for name, value in expected_fixed.items()):
        raise CollectorError("Android device semantic report contradicts its receipt")

    apk_digests = (
        report["target_base_apk_sha256"],
        report["test_apk_sha256"],
    )
    if (
        any(
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or digest in {"0" * 64, EMPTY_SHA256}
            for digest in apk_digests
        )
        or apk_digests[0] == apk_digests[1]
    ):
        raise CollectorError("Android device semantic report APK identity is invalid")
    _device_report_uint(report, "target_base_apk_bytes", 1, 512 * 1024 * 1024)
    _device_report_uint(report, "test_apk_bytes", 1, 512 * 1024 * 1024)

    for prefix in ("target", "test_apk"):
        sources = [
            report[f"{prefix}_installing_package"],
            report[f"{prefix}_initiating_package"],
            report[f"{prefix}_originating_package"],
        ]
        if (
            all(value == "none" for value in sources)
            or any(package_source_pattern.fullmatch(value) is None for value in sources)
        ):
            raise CollectorError("Android device semantic report install source is invalid")

    for name in (
        "attestation_extension_sha256",
        "attested_verified_boot_key_sha256",
        "attested_verified_boot_hash_sha256",
        "display_name_nonce_sha256",
        "active_endpoint_nonce_sha256",
        "vpn_endpoint_nonce_sha256",
        *(f"build_{label}_nonce_sha256" for label in DEVICE_ATTESTATION_BUILD_HASH_LABELS),
    ):
        if (
            re.fullmatch(r"[0-9a-f]{64}", report[name]) is None
            or report[name] in {"0" * 64, EMPTY_SHA256}
        ):
            raise CollectorError(f"Android device semantic report {name} is invalid")

    if _device_report_uint(report, "attestation_version", 1, 500) not in {
        3,
        4,
        100,
        200,
        300,
        400,
        500,
    }:
        raise CollectorError("Android device semantic report attestation version is invalid")
    _device_report_uint(report, "keymint_version", 1, 500)
    _device_report_uint(report, "boot_count", 0, 2**31 - 1)
    _device_report_uint(report, "android_sdk", 31, 100)
    try:
        security_patch = dt.date.fromisoformat(report["android_security_patch"])
    except ValueError as exc:
        raise CollectorError(
            "Android device semantic report security patch is invalid"
        ) from exc
    if security_patch.year < 2020 or security_patch > dt.datetime.now(dt.timezone.utc).date():
        raise CollectorError("Android device semantic report security patch is invalid")

    _device_report_uint(report, "display_count", 1, 1)
    _device_report_uint(report, "display_id", 0, 0)
    _device_report_uint(report, "display_flags", 0, 2**31 - 1)
    _device_report_uint(report, "display_state", 2, 2)
    _device_report_uint(report, "display_rotation", 0, 3)
    _device_report_uint(report, "display_mode_id", 1, 2**31 - 1)
    for name in (
        "display_physical_width_pixels",
        "display_physical_height_pixels",
        "display_current_width_pixels",
        "display_current_height_pixels",
        "display_maximum_width_pixels",
        "display_maximum_height_pixels",
    ):
        _device_report_uint(report, name, 240, 16_384)
    _device_report_uint(report, "display_refresh_millihertz", 10_000, 1_000_000)
    _device_report_uint(report, "display_density_dpi", 72, 2_000)

    if _device_report_utf8_hex(
        report, "runtime_process_name_utf8_hex", maximum_bytes=256
    ) != DEVICE_ATTESTATION_PACKAGE:
        raise CollectorError("Android device semantic report process is invalid")
    _device_report_uint(report, "runtime_process_id", 1, 2**31 - 1)
    _device_report_uint(report, "runtime_process_uid", 1, 2**31 - 1)
    elapsed = _device_report_uint(
        report, "runtime_elapsed_realtime_millis", 1, 2**63 - 1
    )
    uptime = _device_report_uint(report, "runtime_uptime_millis", 1, 2**63 - 1)
    wall_clock = _device_report_uint(
        report, "runtime_wall_clock_millis", 1_577_836_800_000, 2**63 - 1
    )
    if elapsed < uptime or abs(wall_clock - int(time.time() * 1000)) > 15 * 60 * 1000:
        raise CollectorError("Android device semantic report runtime clocks are invalid")

    network_count = _device_report_uint(report, "network_count", 1, 32)
    active_handle = _device_report_uint(
        report, "active_network_handle", 1, 2**63 - 1
    )
    transports = report["active_network_transports"].split(",")
    allowed_transports = (
        "cellular",
        "wifi",
        "bluetooth",
        "ethernet",
        "vpn",
        "wifi_aware",
        "lowpan",
    )
    if (
        not transports
        or len(set(transports)) != len(transports)
        or transports != [name for name in allowed_transports if name in transports]
    ):
        raise CollectorError("Android device semantic report transports are invalid")
    if not _device_report_bool(report, "active_network_validated") or not _device_report_bool(
        report, "active_network_internet"
    ):
        raise CollectorError("Android device semantic report network is not validated")
    _device_report_utf8_hex(report, "active_interface_name_utf8_hex", maximum_bytes=128)
    _device_report_uint(report, "active_link_address_count", 1, 64)
    _device_report_uint(report, "active_route_count", 1, 256)
    _device_report_uint(report, "active_dns_server_count", 0, 32)
    _device_report_uint(report, "active_network_mtu", 0, 65_535)
    vpn_present = _device_report_bool(report, "vpn_present")
    vpn_handle = _device_report_uint(
        report, "vpn_network_handle", 0, 2**63 - 1
    )
    vpn_interface = _device_report_utf8_hex(
        report, "vpn_interface_name_utf8_hex", maximum_bytes=128
    )
    vpn_links = _device_report_uint(report, "vpn_link_address_count", 0, 64)
    vpn_routes = _device_report_uint(report, "vpn_route_count", 0, 256)
    vpn_dns = _device_report_uint(report, "vpn_dns_server_count", 0, 32)
    vpn_mtu = _device_report_uint(report, "vpn_network_mtu", 0, 65_535)
    if vpn_present:
        if (
            "vpn" not in transports
            or vpn_handle != active_handle
            or vpn_interface == "none"
            or vpn_interface
            != _device_report_utf8_hex(
                report, "active_interface_name_utf8_hex", maximum_bytes=128
            )
            or vpn_links < 1
            or vpn_routes < 1
            or vpn_links != _device_report_uint(
                report, "active_link_address_count", 1, 64
            )
            or vpn_routes != _device_report_uint(
                report, "active_route_count", 1, 256
            )
            or vpn_dns != _device_report_uint(
                report, "active_dns_server_count", 0, 32
            )
            or vpn_mtu != _device_report_uint(
                report, "active_network_mtu", 0, 65_535
            )
            or report["vpn_endpoint_nonce_sha256"]
            == report["active_endpoint_nonce_sha256"]
            or report["vpn_endpoint_nonce_sha256"]
            == _nonce_salted_device_report_hash(
                nonce, "vpn_network_endpoint", "none"
            )
        ):
            raise CollectorError("Android device semantic report VPN endpoint is invalid")
    elif (
        "vpn" in transports
        or vpn_handle != 0
        or vpn_interface != "none"
        or any(value != 0 for value in (vpn_links, vpn_routes, vpn_dns, vpn_mtu))
        or report["vpn_endpoint_nonce_sha256"]
        != _nonce_salted_device_report_hash(nonce, "vpn_network_endpoint", "none")
    ):
        raise CollectorError("Android device semantic report absent VPN endpoint is invalid")
    if network_count < (2 if vpn_present else 1):
        raise CollectorError("Android device semantic report network inventory is invalid")


def _instrumentation_attestation_status(stdout: str) -> dict[str, str]:
    try:
        encoded_stdout = stdout.encode("ascii")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise CollectorError(
            "Android hardware-attestation transcript is not bounded ASCII"
        ) from exc
    if (
        not encoded_stdout
        or len(encoded_stdout) > MAX_DEVICE_ATTESTATION_TRANSCRIPT_BYTES
        or b"\r" in encoded_stdout
        or not encoded_stdout.endswith(b"\n")
    ):
        raise CollectorError(
            "Android hardware-attestation transcript is not bounded ASCII"
        )
    blocks: list[tuple[dict[str, str], int]] = []
    pending: dict[str, str] = {}
    results: dict[str, str] = {}
    final_codes: list[int] = []
    result_phase = False
    final_phase = False
    for line in stdout.splitlines():
        if line.startswith("INSTRUMENTATION_STATUS: "):
            if result_phase or final_phase:
                raise CollectorError("Android hardware-attestation status is ambiguous")
            match = re.fullmatch(
                r"INSTRUMENTATION_STATUS: ([A-Za-z][A-Za-z0-9_.-]{0,127})=(.*)",
                line,
            )
            if (
                match is None
                or match.group(1) in pending
                or len(match.group(2)) > 64 * 1024
            ):
                raise CollectorError("Android hardware-attestation status is ambiguous")
            pending[match.group(1)] = match.group(2)
            continue
        code_match = re.fullmatch(
            r"INSTRUMENTATION_STATUS_CODE:\s*(-?[0-9]{1,3})\s*", line
        )
        if code_match is not None:
            if not pending or result_phase or final_phase:
                raise CollectorError("Android hardware-attestation status is ambiguous")
            blocks.append((pending, int(code_match.group(1))))
            pending = {}
            continue
        if line.startswith(("INSTRUMENTATION_FAILED:", "INSTRUMENTATION_ABORTED:")):
            raise CollectorError("Android hardware-attestation runner reported failure")
        if line.startswith("INSTRUMENTATION_RESULT"):
            if pending or len(blocks) != 3 or final_phase:
                raise CollectorError("Android hardware-attestation runner lifecycle is invalid")
            result_phase = True
            result_match = re.fullmatch(
                r"INSTRUMENTATION_RESULT: ([A-Za-z][A-Za-z0-9_.-]{0,127})=(.*)",
                line,
            )
            if (
                result_match is None
                or result_match.group(1) in results
                or result_match.group(1) not in DEVICE_ATTESTATION_RUNNER_RESULT_KEYS
                or result_match.group(1) in DEVICE_ATTESTATION_RUNNER_FAILURE_KEYS
            ):
                raise CollectorError("Android hardware-attestation runner reported failure")
            results[result_match.group(1)] = result_match.group(2)
            continue
        final_match = re.fullmatch(r"INSTRUMENTATION_CODE:\s*(-?[0-9]{1,3})\s*", line)
        if final_match is not None:
            if pending or len(blocks) != 3 or set(results) != DEVICE_ATTESTATION_RUNNER_RESULT_KEYS:
                raise CollectorError("Android hardware-attestation final result is out of order")
            final_phase = True
            final_codes.append(int(final_match.group(1)))
            continue
        if line.startswith("INSTRUMENTATION_"):
            raise CollectorError("Android hardware-attestation runner output is ambiguous")
        if line:
            raise CollectorError("Android hardware-attestation runner output is ambiguous")
    if pending:
        raise CollectorError("Android hardware-attestation status is ambiguous")

    if len(blocks) != 3:
        raise CollectorError("Android hardware-attestation status is ambiguous")
    start, custom, finish = blocks
    start_values, start_code = start
    values, status_code = custom
    finish_values, finish_code = finish
    custom_bundle_bytes = sum(
        len(name.encode("ascii")) + len(value.encode("ascii")) + 2
        for name, value in values.items()
    )
    if (
        start_code != 1
        or finish_code != 0
        or set(start_values) != DEVICE_ATTESTATION_RUNNER_STATUS_KEYS
        or set(finish_values) != DEVICE_ATTESTATION_RUNNER_STATUS_KEYS
    ):
        raise CollectorError("Android hardware-attestation runner lifecycle is invalid")
    if (
        status_code != 0
        or custom_bundle_bytes > MAX_DEVICE_ATTESTATION_STATUS_BUNDLE_BYTES
        or set(values) != DEVICE_ATTESTATION_REPORT_STATUS_KEYS
        or any(
            name.startswith("winsvpn_attestation_")
            for name in (*start_values, *finish_values)
        )
    ):
        raise CollectorError("Android hardware-attestation status schema is invalid")
    for block in (start_values, finish_values):
        if (
            set(block) & DEVICE_ATTESTATION_RUNNER_FAILURE_KEYS
            or block.get("class") != DEVICE_ATTESTATION_PROOF_CLASS
            or block.get("test") != DEVICE_ATTESTATION_TEST_METHOD
            or block.get("current") != "1"
            or block.get("numtests") != "1"
            or block.get("id") != "AndroidJUnitRunner"
        ):
            raise CollectorError("Android hardware-attestation runner lifecycle is invalid")

    if (
        set(results) != DEVICE_ATTESTATION_RUNNER_RESULT_KEYS
        or final_codes != [-1]
    ):
        raise CollectorError(
            "Android physical device did not prove possession of its attested key"
        )
    return values


def _devicecheck_custody_context(
    devicecheck_build_receipt: dict[str, Any],
) -> dict[str, str | int]:
    try:
        snapshot_sha256 = devicecheck_build_receipt["snapshot"]["sha256"]
        consumer_status = devicecheck_build_receipt["value"]["consumer_status"]
        source_inventory_sha256 = devicecheck_build_receipt["value"][
            "source_closure"
        ]["inventory_sha256"]
        target = devicecheck_build_receipt["target"]
        android_test = devicecheck_build_receipt["android_test"]
        context: dict[str, str | int] = {
            "build_receipt_sha256": snapshot_sha256,
            "consumer_status": consumer_status,
            "source_inventory_sha256": source_inventory_sha256,
            "target_apk_sha256": target["sha256"],
            "target_apk_bytes": target["bytes"],
            "android_test_apk_sha256": android_test["sha256"],
            "android_test_apk_bytes": android_test["bytes"],
        }
    except (KeyError, TypeError) as exc:
        raise CollectorError("DeviceCheck producer custody context is incomplete") from exc
    if (
        any(
            re.fullmatch(r"[0-9a-f]{64}", str(context[name])) is None
            or context[name] in {"0" * 64, EMPTY_SHA256}
            for name in (
                "build_receipt_sha256",
                "source_inventory_sha256",
                "target_apk_sha256",
                "android_test_apk_sha256",
            )
        )
        or any(
            not isinstance(context[name], int)
            or isinstance(context[name], bool)
            or context[name] <= 0
            for name in ("target_apk_bytes", "android_test_apk_bytes")
        )
        or context["target_apk_sha256"] == context["android_test_apk_sha256"]
        or context["consumer_status"] != DEVICECHECK_SOURCE_CONSUMER_STATUS
    ):
        raise CollectorError("DeviceCheck producer custody context is invalid")
    return context


def _assert_devicecheck_proof_matches_custody(
    proof: dict[str, str], devicecheck_build_receipt: dict[str, Any]
) -> None:
    custody = _devicecheck_custody_context(devicecheck_build_receipt)
    try:
        observed_target_bytes = int(proof["target_base_apk_bytes"])
        observed_test_bytes = int(proof["test_apk_bytes"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CollectorError(
            "device-signed installed DeviceCheck APK descriptors are invalid"
        ) from exc
    if (
        proof.get("target_base_apk_sha256") != custody["target_apk_sha256"]
        or observed_target_bytes != custody["target_apk_bytes"]
        or proof.get("test_apk_sha256") != custody["android_test_apk_sha256"]
        or observed_test_bytes != custody["android_test_apk_bytes"]
    ):
        raise CollectorError(
            "device-signed installed DeviceCheck APKs contradict producer custody"
        )


def _live_device_attestation_proof(
    adb: pathlib.Path,
    transport_id: str,
    attestation: dict[str, Any],
    *,
    phase: str,
    context_sha256: str,
) -> dict[str, str]:
    if phase not in {"initial", "final"} or re.fullmatch(
        r"[0-9a-f]{64}", context_sha256 or ""
    ) is None:
        raise CollectorError("Android live attestation proof context is invalid")
    nonce = secrets.token_bytes(32)
    receipt = attestation["value"]
    result = _bounded_subprocess_run(
        [
            str(adb),
            "-t",
            transport_id,
            "shell",
            "am",
            "instrument",
            "-w",
            "-r",
            "-e",
            "class",
            DEVICE_ATTESTATION_PROOF_CLASS,
            "-e",
            "winsvpn_attestation_session_nonce",
            nonce.hex(),
            "-e",
            "winsvpn_attestation_key_id",
            receipt["attested_key_id"],
            "-e",
            "winsvpn_attestation_transcript_context_sha256",
            context_sha256,
            DEVICE_ATTESTATION_RUNNER,
        ],
        text=True,
        timeout=120,
        check=False,
        stdout_limit=256 * 1024,
        stderr_limit=64 * 1024,
    )
    if result.returncode != 0:
        raise CollectorError(
            "OWNER-BLOCKED: live hardware-attestation proof runner is unavailable"
        )
    statuses = _instrumentation_attestation_status(result.stdout)
    report_b64 = statuses["winsvpn_attestation_report_b64"]
    if (
        len(report_b64) > MAX_DEVICE_ATTESTATION_REPORT_B64_CHARS
        or statuses["winsvpn_attestation_schema"]
        != DEVICE_ATTESTATION_REPORT_SCHEMA
        or statuses["winsvpn_attestation_key_id"] != receipt["attested_key_id"]
    ):
        raise CollectorError(
            "Android physical device did not prove possession of its attested key"
        )
    try:
        report_raw = base64.b64decode(report_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CollectorError("Android device semantic report encoding is invalid") from exc
    if base64.b64encode(report_raw).decode("ascii") != report_b64:
        raise CollectorError("Android device semantic report encoding is noncanonical")
    report = _parse_device_semantic_report(report_raw)
    _validate_device_semantic_report(report, nonce, attestation, context_sha256)
    signature = statuses["winsvpn_attestation_signature_hex"]
    signature_length = int(receipt["attested_rsa_modulus_hex"], 16).bit_length() // 4
    if (
        re.fullmatch(rf"[0-9a-f]{{{signature_length}}}", signature) is None
        or not _rsa_pkcs1_v1_5_sha256_verify(
            receipt["attested_rsa_modulus_hex"],
            receipt["attested_rsa_public_exponent"],
            DEVICE_ATTESTATION_PROOF_DOMAIN + nonce + report_raw,
            signature,
        )
    ):
        raise CollectorError(
            "Android physical device did not prove possession of its attested key"
        )
    return {
        "phase": phase,
        "transport_id": transport_id,
        "transcript_context_sha256": context_sha256,
        "nonce_sha256": hashlib.sha256(nonce).hexdigest(),
        "report_schema": DEVICE_ATTESTATION_REPORT_SCHEMA,
        "report_sha256": hashlib.sha256(report_raw).hexdigest(),
        "report_b64": report_b64,
        "target_base_apk_sha256": report["target_base_apk_sha256"],
        "target_base_apk_bytes": report["target_base_apk_bytes"],
        "test_apk_sha256": report["test_apk_sha256"],
        "test_apk_bytes": report["test_apk_bytes"],
        "attested_key_id": receipt["attested_key_id"],
        "signature_hex": signature,
    }


def _verify_physical_usb_device(
    adb: pathlib.Path,
    serial: str,
    attestation: dict[str, Any],
    devicecheck_build_receipt: dict[str, Any],
) -> dict[str, str]:
    if serial.casefold().startswith("emulator-"):
        raise CollectorError("Android evidence refuses emulator transports")
    binding = _adb_transport_binding(adb, serial)
    transport_id = binding["transport_id"]
    usb_device_path = _adb_libusb_device_path(adb, transport_id)
    if (
        binding["listed_usb"]
        and usb_device_path.removeprefix("usb:") != binding["listed_usb"]
    ):
        raise CollectorError("Android ADB USB device path contradicts its inventory")
    if _adb_text(adb, transport_id, ["get-serialno"]) != serial:
        raise CollectorError("Android ADB serial identity changed")
    properties = {
        "serial": serial,
        "usb": usb_device_path,
        "product": _adb_text(adb, transport_id, ["shell", "getprop", "ro.product.name"]),
        "model": _adb_text(adb, transport_id, ["shell", "getprop", "ro.product.model"]),
        "device": _adb_text(adb, transport_id, ["shell", "getprop", "ro.product.device"]),
        "boot_serial": _adb_text(adb, transport_id, ["shell", "getprop", "ro.boot.serialno"]),
    }
    for key, value in properties.items():
        if not value or len(value) > 256 or any(ord(character) < 0x20 for character in value):
            raise CollectorError(f"Android physical-device {key} identity is invalid")
    hardware_sha256 = hashlib.sha256(
        _canonical_json_bytes(properties, "Android physical-device identity")
    ).hexdigest()
    value = attestation["value"]
    if (
        hardware_sha256 != value["hardware_identity_sha256"]
        or _adb_text(adb, transport_id, ["shell", "getprop", "ro.boot.verifiedbootstate"])
        != "green"
        or _adb_text(adb, transport_id, ["shell", "getprop", "ro.boot.flash.locked"])
        != "1"
    ):
        raise CollectorError("Android physical-device identity or verified boot changed")
    initial_context = hashlib.sha256(
        _canonical_json_bytes(
            {
                "hardware_identity_sha256": hardware_sha256,
                "serial_sha256": sha256_text(serial),
                "transport_id": transport_id,
                "devicecheck_custody": _devicecheck_custody_context(
                    devicecheck_build_receipt
                ),
            },
            "Android initial attestation context",
        )
    ).hexdigest()
    proof = _live_device_attestation_proof(
        adb,
        transport_id,
        attestation,
        phase="initial",
        context_sha256=initial_context,
    )
    _assert_devicecheck_proof_matches_custody(proof, devicecheck_build_receipt)
    _adb_transport_binding(adb, serial, transport_id)
    return {
        "serial_sha256": sha256_text(serial),
        "hardware_identity_sha256": hardware_sha256,
        "transport": "usb",
        "usb": usb_device_path,
        "transport_id": transport_id,
    }


class _TransportBoundAndroidDriver(AndroidDriver):
    def __init__(
        self,
        adb: pathlib.Path,
        serial: str,
        transport_id: str,
        pin: str,
        tesseract_support_root: pathlib.Path,
        package: str = PACKAGE,
    ) -> None:
        if not adb.is_file() or adb.is_symlink():
            raise DriverError("adb must be a regular executable")
        if not serial or ":" in serial:
            raise DriverError("the final Android route matrix requires USB ADB")
        if re.fullmatch(r"[1-9][0-9]{0,9}", transport_id or "") is None:
            raise DriverError("Android ADB transport ID is invalid")
        if not re.fullmatch(r"\d{4}", pin):
            raise DriverError("camouflage PIN must contain exactly four digits")
        self.adb = str(adb.resolve())
        self.serial = serial
        self.transport_id = transport_id
        self.pin = pin
        self.package = package
        self.tesseract_support_root = tesseract_support_root.resolve(strict=True)
        self.width = 0
        self.height = 0
        self.preflight()

    def adb_run(
        self, args: list[str], *, timeout: int = 45, check: bool = True
    ) -> str:
        _adb_transport_binding(
            pathlib.Path(self.adb), self.serial, self.transport_id
        )
        result = _bounded_subprocess_run(
            [self.adb, "-t", self.transport_id, *args],
            text=True,
            timeout=timeout,
            check=False,
            stdout_limit=MAX_SUBPROCESS_STDOUT_BYTES,
            stderr_limit=MAX_SUBPROCESS_STDERR_BYTES,
        )
        if check and result.returncode != 0:
            tail = (result.stderr or result.stdout).strip().splitlines()[-1:] or [
                "adb command failed"
            ]
            raise DriverError(f"adb action failed: {tail[0][:240]}")
        return result.stdout

    def preflight(self) -> None:
        _adb_transport_binding(
            pathlib.Path(self.adb), self.serial, self.transport_id
        )
        size = self.adb_run(["shell", "wm", "size"])
        matches_size = re.findall(r"(?:Physical|Override) size:\s*(\d+)x(\d+)", size)
        if not matches_size:
            raise DriverError("Android display size is unavailable")
        self.width, self.height = map(int, matches_size[-1])
        if self.width < 320 or self.height < 480:
            raise DriverError("Android display size is implausible")
        trust = self.adb_run(["shell", "dumpsys", "trust"])
        window = self.adb_run(["shell", "dumpsys", "window"])
        if re.search(r"deviceLocked=1", trust) or re.search(
            r"mDreamingLockscreen=true|mShowingLockscreen=true|mKeyguardShowing=true|isStatusBarKeyguard=true",
            window,
        ):
            raise DriverError("Android device must be awake and unlocked")

    def map_observation(
        self,
        output: pathlib.Path,
        tesseract: pathlib.Path,
        expected_cities: list[str],
    ) -> dict[str, Any]:
        if tesseract.parent.resolve(strict=True) != self.tesseract_support_root:
            raise DriverError("Tesseract escaped its reviewed support tree")
        tessdata = self.tesseract_support_root / "tessdata"
        if not tesseract.is_file() or tesseract.is_symlink() or not tessdata.is_dir():
            raise DriverError("reviewed Tesseract runtime is unavailable")
        if len({city.strip().casefold() for city in expected_cities if city.strip()}) < 2:
            raise DriverError("at least two expected nearby city labels are required")
        self.launch()
        if self.runtime().tun_present:
            raise DriverError("map observation must occur while disconnected")
        explore = self.find("Explore map")
        if explore is not None:
            self.tap(explore)
            time.sleep(4)
        xml = self.xml_text()
        labels = [self.label(node) for node in ET.fromstring(xml).iter("node")]
        if not any("Approximate IP location" in label for label in labels):
            raise DriverError("map does not expose the approximate-IP-location label")
        if not any("Your approximate network location" in label for label in labels):
            raise DriverError("map target marker semantics are absent")
        output.parent.mkdir(parents=True, exist_ok=True)
        raw = _bounded_subprocess_run(
            [self.adb, "-t", self.transport_id, "exec-out", "screencap", "-p"],
            text=False,
            timeout=30,
            check=False,
            stdout_limit=128 * 1024 * 1024,
            stderr_limit=64 * 1024,
        )
        if raw.returncode != 0 or len(raw.stdout) < 1024:
            raise DriverError("Android map screenshot capture failed")
        output.write_bytes(raw.stdout)
        tesseract_env = {
            name: os.environ[name]
            for name in ("SystemRoot", "WINDIR", "TEMP", "TMP", "PATHEXT")
            if os.environ.get(name)
        }
        tesseract_env["TESSDATA_PREFIX"] = str(tessdata)
        trusted_path = [str(self.tesseract_support_root)]
        system_root = os.environ.get("SystemRoot")
        if system_root:
            trusted_path.append(str(pathlib.Path(system_root) / "System32"))
        tesseract_env["PATH"] = os.pathsep.join(trusted_path)
        tesseract_env["NoDefaultCurrentDirectoryInExePath"] = "1"
        tesseract_env["OMP_TOOL"] = "disabled"
        tesseract_env["OMP_NUM_THREADS"] = "1"
        tesseract_env["OMP_DYNAMIC"] = "FALSE"
        ocr = _bounded_subprocess_run(
            [
                str(tesseract),
                str(output.resolve()),
                "stdout",
                "--tessdata-dir",
                str(tessdata),
                "-l",
                "eng",
                "--psm",
                "11",
            ],
            cwd=self.tesseract_support_root,
            env=tesseract_env,
            text=True,
            timeout=60,
            check=False,
            stdout_limit=8 * 1024 * 1024,
            stderr_limit=1024 * 1024,
        )
        if ocr.returncode != 0:
            raise DriverError("map OCR failed")
        normalized = re.sub(r"\s+", " ", ocr.stdout).casefold()
        matched = sorted(
            {
                city.strip()
                for city in expected_cities
                if city.strip() and city.strip().casefold() in normalized
            }
        )
        if len(matched) < 2:
            raise DriverError(
                "map OCR did not observe at least two expected nearby city labels"
            )
        return {
            "screenshot_path": str(output),
            "screenshot_sha256": sha256_file(output),
            "radius_miles": 50,
            "city_labels_visible": True,
            "target_marker_visible": True,
            "viewport_not_world_zoom": True,
            "observed_city_label_count": len(matched),
            "ocr_sha256": sha256_text(ocr.stdout),
        }


class _PinnedRouteSubprocess:
    PIPE = subprocess.PIPE

    def __init__(
        self,
        ssh: pathlib.Path,
        config: pathlib.Path,
        identity: pathlib.Path,
        known_hosts: pathlib.Path,
        aliases: set[str],
    ) -> None:
        self._ssh = str(ssh)
        self._config = str(config)
        self._identity = str(identity)
        self._known_hosts = str(known_hosts)
        self._aliases = set(aliases)

    def run(self, command: list[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        if args:
            raise RouteControlError("remote route controller used positional subprocess options")
        if not command or command[0] != "ssh":
            raise RouteControlError("remote route controller attempted an unpinned executable")
        if command.count("-F") != 1:
            raise RouteControlError("remote route controller did not bind one SSH config")
        config_index = command.index("-F")
        if config_index + 1 >= len(command) or command[config_index + 1] != self._config:
            raise RouteControlError("remote route controller used the wrong SSH config")
        try:
            sudo_index = command.index("sudo")
        except ValueError as exc:
            raise RouteControlError("remote route controller omitted its fixed helper") from exc
        if sudo_index < 2 or command[sudo_index - 1] not in self._aliases:
            raise RouteControlError("remote route controller used an unauthorized SSH alias")
        alias = command[sudo_index - 1]
        prefix = command[1:config_index] + command[config_index + 2 : sudo_index - 1]
        strict_options = [
            "-F", self._config,
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", f"IdentityFile={self._identity}",
            "-o", f"UserKnownHostsFile={self._known_hosts}",
            "-o", "GlobalKnownHostsFile=none",
            "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "CanonicalizeHostname=no",
            "-o", "PermitLocalCommand=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
        ]
        for stream_name in ("stdout", "stderr"):
            stream = kwargs.pop(stream_name, subprocess.PIPE)
            if stream is not subprocess.PIPE:
                raise RouteControlError(
                    "remote route controller attempted unbounded subprocess output"
                )
        allowed = {"input", "text", "timeout", "check"}
        if set(kwargs) - allowed:
            raise RouteControlError("remote route controller used unsupported subprocess options")
        return _bounded_subprocess_run(
            [self._ssh, *prefix, *strict_options, alias, *command[sudo_index:]],
            input=kwargs.get("input"),
            text=bool(kwargs.get("text", False)),
            timeout=float(kwargs.get("timeout", 45)),
            check=bool(kwargs.get("check", False)),
            stdout_limit=256 * 1024,
            stderr_limit=64 * 1024,
        )


def atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise CollectorError(f"refusing to overwrite evidence: {path}")
    try:
        encoded = (
            json.dumps(
                value,
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CollectorError(f"evidence JSON is not canonical ASCII: {path.name}") from exc
    _write_exact_bytes(path, encoded)


def _apply_private_windows_acl(path: pathlib.Path, *, recursive: bool) -> None:
    if _WINDOWS_WHOAMI is None or _WINDOWS_ICACLS is None:
        raise CollectorError("authenticated Windows ACL tools are not configured")
    who = _bounded_subprocess_run(
        [str(_WINDOWS_WHOAMI), "/user", "/fo", "csv", "/nh"], text=True,
        check=False, timeout=15, stdout_limit=64 * 1024, stderr_limit=64 * 1024,
    )
    match = re.search(r'"S-1-[0-9-]+"', who.stdout)
    if who.returncode != 0 or not match:
        raise CollectorError("current Windows SID is unavailable for evidence ACL")
    sid = match.group(0).strip('"')
    command = [
        str(_WINDOWS_ICACLS), str(path), "/inheritance:r", "/grant:r",
        f"*{sid}:(OI)(CI)F" if path.is_dir() else f"*{sid}:F",
        "*S-1-5-18:(OI)(CI)F" if path.is_dir() else "*S-1-5-18:F",
    ]
    if recursive:
        command.extend(["/t", "/c"])
    acl = _bounded_subprocess_run(
        command, text=True,
        check=False, timeout=60, stdout_limit=256 * 1024, stderr_limit=64 * 1024,
    )
    if acl.returncode != 0:
        raise CollectorError("owner-only Android evidence ACL could not be applied")


def seal_evidence_bundle(root: pathlib.Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise CollectorError("Android evidence bundle root became unsafe")
    files = list(root.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise CollectorError("Android evidence bundle contains an unsafe entry")
    if os.name == "nt":
        _apply_private_windows_acl(root, recursive=True)
    else:
        os.chmod(root, 0o700)
        for path in files:
            os.chmod(path, 0o600)


def secure_evidence_root(repo: pathlib.Path, output_root: pathlib.Path) -> tuple[pathlib.Path, uuid.UUID]:
    repo = repo.resolve()
    output_root = output_root.absolute()
    try:
        relative = output_root.relative_to(repo)
    except ValueError as exc:
        raise CollectorError("Android evidence bundle root must stay inside the repository") from exc
    if not relative.parts or relative.parts[0] != ".artifacts":
        raise CollectorError("Android evidence bundles must stay under .artifacts")
    current = repo
    for part in relative.parts:
        current = current / part
        if (current.exists() or current.is_symlink()) and current.is_symlink():
            raise CollectorError("Android evidence bundle path must not traverse a symlink")
    output_root.mkdir(parents=True, exist_ok=True)
    if output_root.is_symlink() or not output_root.is_dir():
        raise CollectorError("Android evidence bundle parent must be a non-symlink directory")
    try:
        output_root.resolve().relative_to(repo)
    except ValueError as exc:
        raise CollectorError("Android evidence bundle parent escaped the repository") from exc
    run_id = uuid.uuid4()
    root = output_root / str(run_id)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    if os.name == "nt":
        _apply_private_windows_acl(root, recursive=False)
    else:
        os.chmod(root, 0o700)
    return root, run_id


def receipt(
    root: pathlib.Path,
    name: str,
    contract: str,
    facts: dict[str, Any],
    *,
    captured_at_utc: str | None = None,
) -> tuple[str, str]:
    path = root / name
    value = {
        "schema_version": 1,
        "contract": contract,
        **facts,
        "captured_at_utc": captured_at_utc or utc_now(),
        "secret_material_redacted": True,
    }
    atomic_json(path, value)
    return path.name, _held_evidence_record(path)["sha256"]


def _strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite constant {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise CollectorError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CollectorError(f"{label} must be a JSON object")
    return value


def _parse_receipt_time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise CollectorError(f"{label} captured_at_utc is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CollectorError(f"{label} captured_at_utc is invalid") from exc
    if parsed.tzinfo is None:
        raise CollectorError(f"{label} captured_at_utc lacks a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _relative_input_path(base: pathlib.Path, value: Any, label: str) -> pathlib.Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise CollectorError(f"{label} must be a relative POSIX path")
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise CollectorError(f"{label} must be a descriptor-safe relative path")
    return base.joinpath(*relative.parts)


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        getattr(info, "st_flags", 0),
        getattr(info, "st_file_attributes", 0),
        getattr(info, "st_reparse_tag", 0),
    )


def _evidence_hold_key(path: pathlib.Path) -> str:
    return str(pathlib.Path(os.path.abspath(os.fspath(path))))


def _register_evidence_file(
    path: pathlib.Path,
    *,
    expected_sha256: str,
    expected_size: int,
    max_bytes: int,
) -> dict[str, Any]:
    key = _evidence_hold_key(path)
    if key in _EVIDENCE_HOLDS:
        raise CollectorError(f"evidence file was registered twice: {path.name}")
    if (
        re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or "") is None
        or expected_size <= 0
        or expected_size > max_bytes
    ):
        raise CollectorError(f"evidence file expectation is invalid: {path.name}")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        lexical = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != expected_size
            or _stat_identity(opened) != _stat_identity(lexical)
        ):
            raise CollectorError(f"evidence file identity is unsafe: {path.name}")
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise CollectorError(f"evidence file was truncated: {path.name}")
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise CollectorError(f"evidence file grew while it was bound: {path.name}")
        after = os.fstat(descriptor)
        if (
            _stat_identity(after) != _stat_identity(opened)
            or digest.hexdigest() != expected_sha256
        ):
            raise CollectorError(f"evidence file changed while it was bound: {path.name}")
        record = {
            "descriptor": descriptor,
            "path": pathlib.Path(key),
            "identity": _stat_identity(opened),
            "sha256": expected_sha256,
            "size_bytes": expected_size,
        }
        _EVIDENCE_HOLDS[key] = record
        descriptor = -1
        return record
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _held_evidence_record(path: pathlib.Path) -> dict[str, Any]:
    record = _EVIDENCE_HOLDS.get(_evidence_hold_key(path))
    if record is None:
        raise CollectorError(f"evidence file is not descriptor-bound: {path.name}")
    return record


def _held_evidence_bytes(path: pathlib.Path, *, max_bytes: int) -> bytes:
    record = _held_evidence_record(path)
    if record["size_bytes"] > max_bytes:
        raise CollectorError(f"held evidence is too large to parse: {path.name}")
    descriptor = record["descriptor"]
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = bytearray()
    while len(raw) < record["size_bytes"]:
        block = os.read(descriptor, min(1024 * 1024, record["size_bytes"] - len(raw)))
        if not block:
            raise CollectorError(f"held evidence was truncated: {path.name}")
        raw.extend(block)
    return bytes(raw)


def _reaudit_evidence_holds(root: pathlib.Path) -> set[str]:
    records = {
        pathlib.Path(record["path"]).name: record
        for record in _EVIDENCE_HOLDS.values()
        if pathlib.Path(record["path"]).parent == root
    }
    if len(records) != sum(
        1
        for record in _EVIDENCE_HOLDS.values()
        if pathlib.Path(record["path"]).parent == root
    ):
        raise CollectorError("evidence bundle has duplicate held basenames")
    for name, record in records.items():
        path = root / name
        try:
            lexical = path.lstat()
            opened = os.fstat(record["descriptor"])
        except OSError as exc:
            raise CollectorError(f"held evidence pathname disappeared: {name}") from exc
        if (
            _stat_identity(lexical) != record["identity"]
            or _stat_identity(opened) != record["identity"]
        ):
            raise CollectorError(f"held evidence identity changed: {name}")
        digest = hashlib.sha256(_held_evidence_bytes(path, max_bytes=record["size_bytes"])).hexdigest()
        if digest != record["sha256"]:
            raise CollectorError(f"held evidence bytes changed: {name}")
    return set(records)


def _close_evidence_holds(root: pathlib.Path) -> None:
    keys = [
        key
        for key, record in _EVIDENCE_HOLDS.items()
        if pathlib.Path(record["path"]).parent == root
    ]
    for key in keys:
        record = _EVIDENCE_HOLDS.pop(key)
        os.close(record["descriptor"])


def _bound_file_snapshot(
    repo: pathlib.Path,
    path: pathlib.Path,
    label: str,
    *,
    max_bytes: int,
    require_artifacts: bool,
    retain_raw: bool = True,
) -> dict[str, Any]:
    repo = pathlib.Path(os.path.abspath(os.fspath(repo)))
    lexical = pathlib.Path(os.path.abspath(os.fspath(path)))
    try:
        relative = lexical.relative_to(repo)
    except ValueError as exc:
        raise CollectorError(f"{label} must stay inside the repository") from exc
    if require_artifacts and (not relative.parts or relative.parts[0] != ".artifacts"):
        raise CollectorError(f"{label} must stay under .artifacts")
    if not relative.parts:
        raise CollectorError(f"{label} must name a file inside the repository")
    try:
        repo_info = repo.lstat()
    except OSError as exc:
        raise CollectorError(f"{label} repository root is unreadable") from exc
    if stat.S_ISLNK(repo_info.st_mode) or not stat.S_ISDIR(repo_info.st_mode):
        raise CollectorError(f"{label} repository root must be a real directory")

    use_dir_fd = (
        os.name != "nt"
        and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
    )
    parent_descriptor: int | None = None
    ancestor_before: list[tuple[pathlib.Path, tuple[int, ...]]] = []
    try:
        if use_dir_fd:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                directory_flags |= os.O_NOFOLLOW
            parent_descriptor = os.open(repo, directory_flags)
            for part in relative.parts[:-1]:
                child = os.open(part, directory_flags, dir_fd=parent_descriptor)
                child_info = os.fstat(child)
                if not stat.S_ISDIR(child_info.st_mode):
                    os.close(child)
                    raise CollectorError(f"{label} ancestor is not a directory")
                os.close(parent_descriptor)
                parent_descriptor = child
            before = os.stat(
                relative.parts[-1], dir_fd=parent_descriptor, follow_symlinks=False
            )
        else:
            current = repo
            for part in relative.parts[:-1]:
                current /= part
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise CollectorError(f"{label} path traverses an unsafe ancestor")
                ancestor_before.append((current, _directory_identity(info)))
            before = lexical.lstat()
    except FileNotFoundError as exc:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise CollectorError(OWNER_BLOCKED_RUNTIME_RECEIPTS) from exc
    except OSError as exc:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise CollectorError(f"{label} path could not be bound safely") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > max_bytes
    ):
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise CollectorError(f"{label} is not a bounded single-link regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        if use_dir_fd:
            assert parent_descriptor is not None
            descriptor = os.open(relative.parts[-1], flags, dir_fd=parent_descriptor)
        else:
            descriptor = os.open(lexical, flags)
    except OSError as exc:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise CollectorError(f"{label} could not be opened safely") from exc
    try:
        try:
            opened = os.fstat(descriptor)
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, min(65536, max_bytes + 1 - total))
                if not chunk:
                    break
                if retain_raw:
                    chunks.append(chunk)
                digest.update(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise CollectorError(f"{label} exceeds its byte limit")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        raise
    try:
        try:
            if use_dir_fd:
                assert parent_descriptor is not None
                pathname_after = os.stat(
                    relative.parts[-1], dir_fd=parent_descriptor, follow_symlinks=False
                )
            else:
                pathname_after = lexical.lstat()
                for ancestor, expected_identity in ancestor_before:
                    current = ancestor.lstat()
                    if _directory_identity(current) != expected_identity:
                        raise CollectorError(f"{label} ancestor changed while it was read")
        except OSError as exc:
            raise CollectorError(f"{label} pathname changed while it was read") from exc
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    identity = _stat_identity(before)
    opened_identity = _stat_identity(opened)
    after_identity = _stat_identity(after)
    pathname_identity = _stat_identity(pathname_after)
    raw = b"".join(chunks) if retain_raw else None
    if (
        identity != opened_identity
        or identity != after_identity
        or identity != pathname_identity
        or total != before.st_size
    ):
        raise CollectorError(f"{label} changed while it was read")
    return {
        "path": lexical,
        "relative": relative.as_posix(),
        "raw": raw,
        "sha256": digest.hexdigest(),
        "size_bytes": total,
        "identity": identity,
    }


_ED25519_P = 2**255 - 19
_ED25519_L = 2**252 + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_I = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)


def _ed25519_recover_x(y: int, sign: int) -> int | None:
    if y >= _ED25519_P:
        return None
    xx = (y * y - 1) * pow(
        _ED25519_D * y * y + 1, _ED25519_P - 2, _ED25519_P
    )
    x = pow(xx % _ED25519_P, (_ED25519_P + 3) // 8, _ED25519_P)
    if (x * x - xx) % _ED25519_P != 0:
        x = x * _ED25519_I % _ED25519_P
    if (x * x - xx) % _ED25519_P != 0 or (x == 0 and sign == 1):
        return None
    if x & 1 != sign:
        x = _ED25519_P - x
    return x


def _ed25519_decode_point(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    x = _ed25519_recover_x(y, value >> 255)
    if x is None:
        return None
    return (x, y, 1, x * y % _ED25519_P)


def _ed25519_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _ED25519_P
    b = (y1 + x1) * (y2 + x2) % _ED25519_P
    c = 2 * t1 * t2 * _ED25519_D % _ED25519_P
    d = 2 * z1 * z2 % _ED25519_P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (
        e * f % _ED25519_P,
        g * h % _ED25519_P,
        f * g % _ED25519_P,
        e * h % _ED25519_P,
    )


def _ed25519_mul(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    current = point
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, current)
        current = _ed25519_add(current, current)
        scalar >>= 1
    return result


_ED25519_BASE_Y = 4 * pow(5, _ED25519_P - 2, _ED25519_P) % _ED25519_P
_ED25519_BASE_X = _ed25519_recover_x(_ED25519_BASE_Y, 0)
if _ED25519_BASE_X is None:
    raise RuntimeError("Ed25519 base point construction failed")
_ED25519_BASE = (
    _ED25519_BASE_X,
    _ED25519_BASE_Y,
    1,
    _ED25519_BASE_X * _ED25519_BASE_Y % _ED25519_P,
)


def _ed25519_equal(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> bool:
    return (
        (left[0] * right[2] - right[0] * left[2]) % _ED25519_P == 0
        and (left[1] * right[2] - right[1] * left[2]) % _ED25519_P == 0
    )


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    public_point = _ed25519_decode_point(public_key)
    signature_point = _ed25519_decode_point(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    neutral = (0, 1, 1, 0)
    if public_point is None or signature_point is None or scalar >= _ED25519_L:
        return False
    if (
        _ed25519_equal(public_point, neutral)
        or _ed25519_equal(signature_point, neutral)
        or not _ed25519_equal(_ed25519_mul(public_point, _ED25519_L), neutral)
        or not _ed25519_equal(_ed25519_mul(signature_point, _ED25519_L), neutral)
    ):
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _ED25519_L
    return _ed25519_equal(
        _ed25519_mul(_ED25519_BASE, scalar),
        _ed25519_add(
            signature_point, _ed25519_mul(public_point, challenge)
        ),
    )


def _canonical_json_bytes(value: Any, label: str) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CollectorError(f"{label} is not canonical ASCII JSON") from exc


def _release_input_owner_authority(
    repo: pathlib.Path,
    release_input_index_path: pathlib.Path,
    expected_release_input_index_sha256: str,
    bound_files: dict[str, dict[str, Any]],
) -> tuple[str, bytes]:
    if (
        re.fullmatch(
            r"[0-9a-f]{64}", EXPECTED_FORM_FACTOR_OWNER_AUTHORITY_SHA256
        )
        is None
        or EXPECTED_FORM_FACTOR_OWNER_AUTHORITY_SHA256
        in {"0" * 64, EMPTY_SHA256}
    ):
        raise CollectorError(
            "OWNER-BLOCKED: reviewed Android owner authority is not provisioned"
        )
    index_snapshot = _bound_file_snapshot(
        repo,
        release_input_index_path,
        "trusted Android release-input index",
        max_bytes=MAX_FORM_FACTOR_MANIFEST_BYTES,
        require_artifacts=True,
    )
    if index_snapshot["sha256"] != expected_release_input_index_sha256:
        raise CollectorError("trusted Android release-input index changed")
    index = _strict_json_bytes(index_snapshot["raw"], "trusted Android release-input index")
    platforms = index.get("platform_manifests")
    android_reference = platforms.get("android") if isinstance(platforms, dict) else None
    if (
        index.get("contract") != "winsvpn-release-input-index-v1"
        or not isinstance(android_reference, dict)
        or set(android_reference) != {
            "artifact_input_fingerprint_sha256",
            "path",
            "sha256",
        }
    ):
        raise CollectorError("trusted Android release-input index is malformed")
    platform_path = _relative_input_path(
        pathlib.Path(index_snapshot["path"]).parent,
        android_reference["path"],
        "trusted Android input manifest",
    )
    platform_snapshot = _bound_file_snapshot(
        repo,
        platform_path,
        "trusted Android input manifest",
        max_bytes=8 * 1024 * 1024,
        require_artifacts=True,
    )
    if platform_snapshot["sha256"] != android_reference["sha256"]:
        raise CollectorError("trusted Android input manifest changed")
    platform = _strict_json_bytes(
        platform_snapshot["raw"], "trusted Android input manifest"
    )
    native = platform.get("native_inputs")
    files = native.get("files") if isinstance(native, dict) else None
    if not isinstance(files, list):
        raise CollectorError("trusted Android native-input inventory is malformed")
    authority_entries = [
        item
        for item in files
        if isinstance(item, dict)
        and item.get("path") == FORM_FACTOR_OWNER_AUTHORITY_RELATIVE
    ]
    if len(authority_entries) != 1 or set(authority_entries[0]) != {
        "path",
        "sha256",
        "size",
    }:
        raise CollectorError(
            "OWNER-BLOCKED: Android form-factor owner authority is absent from trusted release inputs"
        )
    authority_snapshot = _bound_file_snapshot(
        repo,
        repo / FORM_FACTOR_OWNER_AUTHORITY_RELATIVE,
        "Android form-factor owner authority",
        max_bytes=MAX_OWNER_AUTHORITY_BYTES,
        require_artifacts=False,
    )
    entry = authority_entries[0]
    if (
        authority_snapshot["sha256"]
        != EXPECTED_FORM_FACTOR_OWNER_AUTHORITY_SHA256
        or entry["sha256"] != EXPECTED_FORM_FACTOR_OWNER_AUTHORITY_SHA256
        or
        entry["sha256"] != authority_snapshot["sha256"]
        or entry["size"] != authority_snapshot["size_bytes"]
    ):
        raise CollectorError("Android form-factor owner authority changed")
    authority = _strict_json_bytes(
        authority_snapshot["raw"], "Android form-factor owner authority"
    )
    if set(authority) != {
        "schema_version",
        "contract",
        "algorithm",
        "key_id",
        "public_key_hex",
        "secret_material_redacted",
    }:
        raise CollectorError("Android form-factor owner authority fields are invalid")
    public_key_hex = authority["public_key_hex"]
    if (
        authority["schema_version"] != 1
        or authority["contract"] != FORM_FACTOR_OWNER_AUTHORITY_CONTRACT
        or authority["algorithm"] != "ed25519"
        or authority["secret_material_redacted"] is not True
        or not isinstance(public_key_hex, str)
        or re.fullmatch(r"[0-9a-f]{64}", public_key_hex) is None
    ):
        raise CollectorError("Android form-factor owner authority is invalid")
    public_key = bytes.fromhex(public_key_hex)
    key_id = hashlib.sha256(public_key).hexdigest()
    if authority["key_id"] != key_id:
        raise CollectorError("Android form-factor owner authority key ID is invalid")
    for snapshot in (index_snapshot, platform_snapshot, authority_snapshot):
        bound_files[str(snapshot["path"])] = snapshot
    return key_id, public_key


def _verify_form_factor_owner_authorization(
    repo: pathlib.Path,
    authorization_path: pathlib.Path,
    expected_authorization_sha256: str,
    *,
    key_id: str,
    public_key: bytes,
    manifest_sha256: str,
    app_version: str,
    phone_build_number: str,
    release_input_index_sha256: str,
    build_receipt_sha256: str,
    packages: dict[str, dict[str, str | int]],
    native_tool_snapshots: dict[str, dict[str, Any]],
    adb_support_tree_snapshot: dict[str, Any],
    tesseract_support_tree_snapshot: dict[str, Any],
    route_authority_snapshots: dict[str, dict[str, Any]],
    expected_map_city_labels: list[str],
    device_attestation: dict[str, Any],
    devicecheck_build_receipt: dict[str, Any],
    approved_producers: list[dict[str, str]],
    bound_files: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{64}", expected_authorization_sha256 or "") is None:
        raise CollectorError("OWNER-BLOCKED: exact owner authorization hash is required")
    snapshot = _bound_file_snapshot(
        repo,
        authorization_path,
        "Android form-factor owner authorization",
        max_bytes=MAX_OWNER_AUTHORIZATION_BYTES,
        require_artifacts=True,
    )
    if snapshot["sha256"] != expected_authorization_sha256:
        raise CollectorError("Android form-factor owner authorization changed")
    authorization = _strict_json_bytes(
        snapshot["raw"], "Android form-factor owner authorization"
    )
    signed_fields = {
        "schema_version",
        "contract",
        "algorithm",
        "key_id",
        "application_id",
        "app_version",
        "phone_build_number",
        "release_input_index_sha256",
        "build_receipt_sha256",
        "form_factor_manifest_sha256",
        "candidate_ids",
        "package_sha256s",
        "package_signer_sha256s",
        "cryptographic_package_signatures_verified",
        "native_tool_sha256s",
        "adb_support_tree_sha256",
        "tesseract_support_tree_sha256",
        "route_authority_sha256s",
        "expected_map_city_labels",
        "physical_device",
        "devicecheck_build_receipt",
        "approved_producers",
        "issued_at_utc",
        "expires_at_utc",
        "secret_material_redacted",
    }
    if set(authorization) != signed_fields | {"signature_hex"}:
        raise CollectorError("Android form-factor owner authorization fields are invalid")
    signed = {field: authorization[field] for field in signed_fields}
    expected_packages = {
        role: packages[role]["sha256"]
        for role, _relative in CANONICAL_PRODUCED_PACKAGES
    }
    expected_signers = {
        role: packages[role].get("signer_certificate_sha256")
        for role, _relative in CANONICAL_PRODUCED_PACKAGES
    }
    expected_signature_verification = {
        role: packages[role].get("cryptographic_signature_verified")
        for role, _relative in CANONICAL_PRODUCED_PACKAGES
    }
    if (
        any(
            not isinstance(value, str)
            or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in expected_signers.values()
        )
        or any(value is not True for value in expected_signature_verification.values())
    ):
        raise CollectorError(OWNER_BLOCKED_PACKAGE_VERIFIER)
    expected_native_tools = {
        role: native_tool_snapshots[role]["sha256"] for role in NATIVE_TOOL_ROLES
    }
    expected_route_authority = {
        role: route_authority_snapshots[role]["sha256"]
        for role in ROUTE_AUTHORITY_ROLES
    }
    expected_physical_device = {
        "serial_sha256": device_attestation["value"]["serial_sha256"],
        "transport": "usb",
        "hardware_identity_sha256": device_attestation["value"]
        ["hardware_identity_sha256"],
        "attestation_receipt_sha256": device_attestation["snapshot"]["sha256"],
        "attested_key_id": device_attestation["value"]["attested_key_id"],
        "hardware_enforced_key_authorization": device_attestation["value"]
        ["hardware_enforced_key_authorization"],
        "attestation_certificate_chain_sha256": device_attestation["value"]
        ["attestation_certificate_chain_sha256"],
    }
    expected_devicecheck_build_receipt = {
        "receipt_sha256": devicecheck_build_receipt["snapshot"]["sha256"],
        "contract": DEVICECHECK_BUILD_RECEIPT_CONTRACT,
        "consumer_status": devicecheck_build_receipt["value"]["consumer_status"],
        "variant": "release",
        "target_apk_sha256": devicecheck_build_receipt["target"]["sha256"],
        "target_apk_bytes": devicecheck_build_receipt["target"]["bytes"],
        "android_test_apk_sha256": devicecheck_build_receipt["android_test"]
        ["sha256"],
        "android_test_apk_bytes": devicecheck_build_receipt["android_test"]
        ["bytes"],
        "signer_sha256": devicecheck_build_receipt["target"]["signer_sha256"],
        "source_inventory_sha256": devicecheck_build_receipt["value"]
        ["source_closure"]["inventory_sha256"],
    }
    if (
        signed["schema_version"] != 2
        or signed["contract"] != FORM_FACTOR_OWNER_AUTHORIZATION_CONTRACT
        or signed["algorithm"] != "ed25519"
        or signed["key_id"] != key_id
        or signed["application_id"] != EXPECTED_APPLICATION_ID
        or signed["app_version"] != app_version
        or signed["phone_build_number"] != phone_build_number
        or signed["release_input_index_sha256"] != release_input_index_sha256
        or signed["build_receipt_sha256"] != build_receipt_sha256
        or signed["form_factor_manifest_sha256"] != manifest_sha256
        or signed["candidate_ids"] != FORM_FACTOR_CANDIDATES
        or signed["package_sha256s"] != expected_packages
        or signed["package_signer_sha256s"] != expected_signers
        or signed["cryptographic_package_signatures_verified"]
        != expected_signature_verification
        or signed["native_tool_sha256s"] != expected_native_tools
        or signed["adb_support_tree_sha256"]
        != adb_support_tree_snapshot["tree_sha256"]
        or signed["tesseract_support_tree_sha256"]
        != tesseract_support_tree_snapshot["tree_sha256"]
        or signed["route_authority_sha256s"] != expected_route_authority
        or signed["expected_map_city_labels"] != expected_map_city_labels
        or signed["physical_device"] != expected_physical_device
        or signed["devicecheck_build_receipt"]
        != expected_devicecheck_build_receipt
        or signed["approved_producers"] != approved_producers
        or signed["secret_material_redacted"] is not True
    ):
        raise CollectorError(
            "Android form-factor owner authorization contradicts the exact candidate"
        )
    issued = _parse_receipt_time(signed["issued_at_utc"], "owner authorization")
    expires = _parse_receipt_time(signed["expires_at_utc"], "owner authorization")
    now = dt.datetime.now(dt.timezone.utc)
    if (
        expires <= issued
        or expires - issued > MAX_OWNER_AUTHORIZATION_WINDOW
        or issued > now + dt.timedelta(minutes=5)
        or expires < now
    ):
        raise CollectorError("Android form-factor owner authorization is stale or expired")
    signature_hex = authorization["signature_hex"]
    if (
        not isinstance(signature_hex, str)
        or re.fullmatch(r"[0-9a-f]{128}", signature_hex) is None
        or not _verify_ed25519(
            public_key,
            FORM_FACTOR_OWNER_SIGNATURE_DOMAIN
            + _canonical_json_bytes(signed, "Android form-factor owner authorization"),
            bytes.fromhex(signature_hex),
        )
    ):
        raise CollectorError("Android form-factor owner authorization signature is invalid")
    bound_files[str(snapshot["path"])] = snapshot
    return {"snapshot": snapshot, "value": authorization}


def _producer_closure(
    repo: pathlib.Path,
    producer: dict[str, Any],
    label: str,
    bound_files: dict[str, dict[str, Any]],
) -> str:
    if set(producer) != {"path", "closure_sha256", "files"}:
        raise CollectorError(f"{label} producer fields are invalid")
    primary = producer["path"]
    files = producer["files"]
    if (
        not isinstance(primary, str)
        or not primary.startswith(("tools/", "wear_os/tools/"))
        or not isinstance(files, list)
        or not 1 <= len(files) <= 32
    ):
        raise CollectorError(f"{label} producer closure is invalid")
    relative_paths: list[str] = []
    digest = hashlib.sha256()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise CollectorError(f"{label} producer file descriptor is invalid")
        relative = item["path"]
        path = _relative_input_path(repo, relative, f"{label} producer file")
        snapshot = _bound_file_snapshot(
            repo,
            path,
            f"{label} producer file",
            max_bytes=4 * 1024 * 1024,
            require_artifacts=False,
        )
        if item["sha256"] != snapshot["sha256"]:
            raise CollectorError(f"{label} producer file hash changed")
        if relative in relative_paths:
            raise CollectorError(f"{label} producer closure repeats a file")
        relative_paths.append(relative)
        digest.update(relative.encode("ascii") + b"\0")
        digest.update(snapshot["raw"])
        digest.update(b"\0")
        prior = bound_files.get(str(snapshot["path"]))
        if prior is not None and (
            prior["identity"] != snapshot["identity"]
            or prior["sha256"] != snapshot["sha256"]
            or prior["raw"] != snapshot["raw"]
        ):
            raise CollectorError(f"{label} producer file changed across descriptors")
        bound_files[str(snapshot["path"])] = snapshot
    if relative_paths != sorted(relative_paths) or primary not in relative_paths:
        raise CollectorError(f"{label} producer file closure is not canonical")
    closure = digest.hexdigest()
    if producer["closure_sha256"] != closure:
        raise CollectorError(f"{label} producer closure hash changed")
    return closure


def _validate_runtime_receipt(
    value: dict[str, Any],
    *,
    form: str,
    packages: dict[str, dict[str, str | int]],
    app_version: str,
    version_code: int,
    machine_captured: dt.datetime,
) -> None:
    common = {
        "schema_version",
        "contract",
        "form_factor",
        "kind",
        "candidate_id",
        "artifact_sha256",
        "version_name",
        "version_code",
        "source_only",
        "passed",
        "captured_at_utc",
        "secret_material_redacted",
    }
    if form == "wear":
        fields = common | {"companion_phone_artifact_sha256", "pairing_observed"}
        contract = WEAR_RUNTIME_CONTRACT
        kind = "pairing_runtime"
        artifact = packages["wear_aab"]["sha256"]
    else:
        fields = common | {
            "primary_transport",
            "fallback_transports",
            "winn_v3_session_observed",
        }
        contract = RUNTIME_CONTRACT
        kind = "live_vpn"
        artifact = packages[f"{form}_apk"]["sha256"]
    if set(value) != fields:
        raise CollectorError(f"{form} runtime receipt fields are invalid")
    captured = _parse_receipt_time(value["captured_at_utc"], f"{form} runtime receipt")
    now = dt.datetime.now(dt.timezone.utc)
    if (
        captured < machine_captured - MAX_RUNTIME_RECEIPT_SKEW
        or captured > machine_captured + dt.timedelta(minutes=5)
        or captured > now + dt.timedelta(minutes=5)
    ):
        raise CollectorError(f"{form} runtime receipt is stale or from another run")
    if (
        value["schema_version"] != 1
        or value["contract"] != contract
        or value["form_factor"] != form
        or value["kind"] != kind
        or value["candidate_id"] != FORM_FACTOR_CANDIDATES[form]
        or value["artifact_sha256"] != artifact
        or value["version_name"] != app_version
        or value["version_code"] != version_code
        or value["source_only"] is not False
        or value["passed"] is not True
        or value["secret_material_redacted"] is not True
    ):
        raise CollectorError(f"{form} runtime receipt contradicts the exact candidate")
    if form == "wear":
        if (
            value["companion_phone_artifact_sha256"] != packages["phone_apk"]["sha256"]
            or value["pairing_observed"] is not True
        ):
            raise CollectorError("Wear runtime receipt is not exact pairing evidence")
    elif (
        value["primary_transport"] != WINN_PRIMARY_TRANSPORT
        or value["fallback_transports"] != WINN_FALLBACK_TRANSPORTS
        or value["winn_v3_session_observed"] is not True
    ):
        raise CollectorError(
            f"{form} runtime receipt does not prove Winn v3 then Winn v1 AWG then Xray"
        )


def _validate_produced_receipt(
    value: dict[str, Any],
    *,
    form: str,
    role: str,
    record: dict[str, str | int],
    app_version: str,
) -> int:
    fields = {
        "schema_version",
        "contract",
        "form_factor",
        "role",
        "candidate_id",
        "path",
        "sha256",
        "size_bytes",
        "version_name",
        "version_code",
        "captured_at_utc",
        "secret_material_redacted",
    }
    version_code = value.get("version_code")
    if (
        set(value) != fields
        or value["schema_version"] != 1
        or value["contract"] != PRODUCED_ARTIFACT_CONTRACT
        or value["form_factor"] != form
        or value["role"] != role
        or value["candidate_id"] != FORM_FACTOR_CANDIDATES[form]
        or value["path"] != record["path"]
        or value["sha256"] != record["sha256"]
        or value["size_bytes"] != record["size_bytes"]
        or value["version_name"] != app_version
        or isinstance(version_code, bool)
        or not isinstance(version_code, int)
        or version_code <= 0
        or value["secret_material_redacted"] is not True
    ):
        raise CollectorError(f"{form} {role} produced receipt contradicts the exact package")
    _parse_receipt_time(value["captured_at_utc"], f"{form} {role} produced receipt")
    return version_code


def _write_exact_bytes(path: pathlib.Path, raw: bytes) -> None:
    if not raw:
        raise CollectorError(f"refusing empty evidence bytes: {path}")
    if path.exists() or path.is_symlink():
        raise CollectorError(f"refusing to overwrite evidence: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CollectorError(f"could not write exact evidence bytes: {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)
    _register_evidence_file(
        path,
        expected_sha256=hashlib.sha256(raw).hexdigest(),
        expected_size=len(raw),
        max_bytes=max(len(raw), 1),
    )


def preflight_form_factor_evidence(
    repo: pathlib.Path,
    manifest_path: pathlib.Path,
    expected_manifest_sha256: str,
    owner_authorization_path: pathlib.Path,
    expected_owner_authorization_sha256: str,
    release_input_index_path: pathlib.Path,
    packages: dict[str, dict[str, str | int]],
    app_version: str,
    phone_build_number: str,
    release_input_index_sha256: str,
    build_receipt_sha256: str,
    native_tool_paths: dict[str, pathlib.Path],
    adb_support_root: pathlib.Path,
    tesseract_support_root: pathlib.Path,
    route_authority_paths: dict[str, pathlib.Path],
    route_inventory: dict[str, Any],
    route_inventory_sha256: str,
    expected_map_city_labels: list[str],
    device_attestation_path: pathlib.Path,
    devicecheck_build_receipt_path: pathlib.Path,
    expected_devicecheck_build_receipt_sha256: str,
    expected_devicecheck_target_apk_sha256: str,
    expected_devicecheck_target_apk_bytes: int,
    expected_devicecheck_android_test_apk_sha256: str,
    expected_devicecheck_android_test_apk_bytes: int,
    expected_devicecheck_source_inventory_sha256: str,
    serial: str,
) -> dict[str, Any]:
    if set(packages) != {role for role, _relative in CANONICAL_PRODUCED_PACKAGES}:
        raise CollectorError("Android produced package closure is incomplete")
    if re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256 or "") is None:
        raise CollectorError(OWNER_BLOCKED_RUNTIME_RECEIPTS)
    if set(native_tool_paths) != set(NATIVE_TOOL_ROLES):
        raise CollectorError("OWNER-BLOCKED: exact Android native-tool closure is required")
    if set(route_authority_paths) != set(ROUTE_AUTHORITY_ROLES):
        raise CollectorError("OWNER-BLOCKED: exact Android remote-route authority is required")
    normalized_city_labels = _normalized_map_city_labels(expected_map_city_labels)
    native_tool_snapshots = {
        role: _external_executable_snapshot(
            native_tool_paths[role], f"Android {role} executable"
        )
        for role in NATIVE_TOOL_ROLES
    }
    adb_support_snapshot = _adb_support_tree_snapshot(adb_support_root)
    adb_path = pathlib.Path(native_tool_snapshots["adb"]["path"])
    if adb_path.parent != pathlib.Path(adb_support_snapshot["root"]):
        raise CollectorError("Android ADB executable is outside its reviewed support tree")
    adb_members = {
        item["relative"]: item for item in adb_support_snapshot["files"]
    }
    adb_member = adb_members.get(adb_path.name)
    if (
        adb_member is None
        or adb_member["sha256"] != native_tool_snapshots["adb"]["sha256"]
        or adb_member["identity"] != native_tool_snapshots["adb"]["identity"]
    ):
        raise CollectorError("Android ADB executable is not bound by its support tree")
    if len({item["sha256"] for item in native_tool_snapshots.values()}) != len(
        native_tool_snapshots
    ):
        raise CollectorError("Android native-tool executable hashes must be distinct")
    tesseract_support_snapshot = _tesseract_support_tree_snapshot(
        tesseract_support_root
    )
    tesseract_path = pathlib.Path(native_tool_snapshots["tesseract"]["path"])
    if tesseract_path.parent != pathlib.Path(tesseract_support_snapshot["root"]):
        raise CollectorError(
            "Android Tesseract executable is outside its reviewed support tree"
        )
    tesseract_members = {
        item["relative"]: item for item in tesseract_support_snapshot["files"]
    }
    tesseract_member = tesseract_members.get(tesseract_path.name)
    if (
        tesseract_member is None
        or tesseract_member["sha256"]
        != native_tool_snapshots["tesseract"]["sha256"]
        or tesseract_member["identity"]
        != native_tool_snapshots["tesseract"]["identity"]
    ):
        raise CollectorError(
            "Android Tesseract executable is not bound by its support tree"
        )
    route_authority_snapshots = {
        role: _external_file_snapshot(
            route_authority_paths[role],
            f"Android {role.replace('_', ' ')}",
            max_bytes=MAX_ROUTE_AUTHORITY_BYTES,
            retain_raw=role in {"route_inventory", "ssh_config"},
        )
        for role in ROUTE_AUTHORITY_ROLES
    }
    if route_authority_snapshots["route_inventory"]["sha256"] != route_inventory_sha256:
        raise CollectorError("Android route inventory changed before preflight")
    route_aliases = _route_inventory_aliases(route_inventory)
    _validate_release_ssh_config(
        route_authority_snapshots["ssh_config"]["raw"], route_aliases
    )
    bound_files: dict[str, dict[str, Any]] = {}
    for package_role, _relative in CANONICAL_PRODUCED_PACKAGES:
        package = packages[package_role]
        snapshot = _bound_file_snapshot(
            repo,
            repo / pathlib.PurePosixPath(str(package["path"])),
            f"{package_role} produced package",
            max_bytes=MAX_PRODUCED_PACKAGE_BYTES,
            require_artifacts=False,
            retain_raw=False,
        )
        if (
            snapshot["sha256"] != package["sha256"]
            or snapshot["size_bytes"] != package["size_bytes"]
        ):
            raise CollectorError(f"{package_role} produced package changed before preflight")
        bound_files[str(snapshot["path"])] = snapshot
    authority_key_id, authority_public_key = _release_input_owner_authority(
        repo,
        release_input_index_path,
        release_input_index_sha256,
        bound_files,
    )
    manifest_snapshot = _bound_file_snapshot(
        repo,
        manifest_path,
        "Android form-factor evidence manifest",
        max_bytes=MAX_FORM_FACTOR_MANIFEST_BYTES,
        require_artifacts=True,
    )
    if manifest_snapshot["sha256"] != expected_manifest_sha256:
        raise CollectorError("Android form-factor evidence manifest hash changed")
    manifest = _strict_json_bytes(manifest_snapshot["raw"], "Android form-factor evidence manifest")
    fields = {
        "schema_version",
        "contract",
        "application_id",
        "app_version",
        "phone_build_number",
        "release_input_index_sha256",
        "build_receipt_sha256",
        "captured_at_utc",
        "descriptors",
        "secret_material_redacted",
    }
    if (
        set(manifest) != fields
        or manifest["schema_version"] != 1
        or manifest["contract"] != FORM_FACTOR_MANIFEST_CONTRACT
        or manifest["application_id"] != EXPECTED_APPLICATION_ID
        or manifest["app_version"] != app_version
        or manifest["phone_build_number"] != phone_build_number
        or manifest["release_input_index_sha256"] != release_input_index_sha256
        or manifest["build_receipt_sha256"] != build_receipt_sha256
        or manifest["secret_material_redacted"] is not True
    ):
        raise CollectorError("Android form-factor evidence manifest binding is invalid")
    manifest_captured = _parse_receipt_time(
        manifest["captured_at_utc"], "Android form-factor evidence manifest"
    )
    now = dt.datetime.now(dt.timezone.utc)
    if manifest_captured < now - MAX_RUNTIME_RECEIPT_SKEW or manifest_captured > now + dt.timedelta(minutes=5):
        raise CollectorError("Android form-factor evidence manifest is stale or from the future")
    device_attestation = _device_attestation_receipt(
        repo,
        device_attestation_path,
        manifest_sha256=manifest_snapshot["sha256"],
        app_version=app_version,
        phone_build_number=phone_build_number,
        serial=serial,
        bound_files=bound_files,
    )
    devicecheck_build_receipt = _devicecheck_build_receipt(
        repo,
        devicecheck_build_receipt_path,
        expected_devicecheck_build_receipt_sha256,
        bound_files,
        expected_target_apk_sha256=expected_devicecheck_target_apk_sha256,
        expected_target_apk_bytes=expected_devicecheck_target_apk_bytes,
        expected_android_test_apk_sha256=expected_devicecheck_android_test_apk_sha256,
        expected_android_test_apk_bytes=expected_devicecheck_android_test_apk_bytes,
        expected_source_inventory_sha256=expected_devicecheck_source_inventory_sha256,
    )
    descriptors = manifest["descriptors"]
    if not isinstance(descriptors, list) or [item.get("id") if isinstance(item, dict) else None for item in descriptors] != list(FORM_FACTOR_DESCRIPTOR_IDS):
        raise CollectorError("Android form-factor evidence manifest must bind exactly eight descriptors")
    seen_receipt_paths: set[str] = set()
    seen_receipt_inodes: set[tuple[int, int]] = set()
    seen_receipt_hashes: set[str] = set()
    seen_index_paths: set[str] = set()
    seen_index_inodes: set[tuple[int, int]] = set()
    seen_index_hashes: set[str] = set()
    imported: dict[str, dict[str, Any]] = {}
    version_codes: dict[str, int] = {}
    manifest_dir = pathlib.Path(manifest_snapshot["path"]).parent
    for descriptor in descriptors:
        descriptor_id = descriptor["id"]
        if set(descriptor) != {
            "id",
            "receipt_path",
            "receipt_sha256",
            "source_index_path",
            "source_index_sha256",
            "producer_closure_sha256",
        }:
            raise CollectorError(f"{descriptor_id} descriptor fields are invalid")
        receipt_path = _relative_input_path(
            manifest_dir, descriptor["receipt_path"], f"{descriptor_id} receipt"
        )
        index_path = _relative_input_path(
            manifest_dir, descriptor["source_index_path"], f"{descriptor_id} source index"
        )
        receipt_snapshot = _bound_file_snapshot(
            repo,
            receipt_path,
            f"{descriptor_id} receipt",
            max_bytes=MAX_RUNTIME_RECEIPT_BYTES,
            require_artifacts=True,
        )
        index_snapshot = _bound_file_snapshot(
            repo,
            index_path,
            f"{descriptor_id} source index",
            max_bytes=MAX_SOURCE_INDEX_BYTES,
            require_artifacts=True,
        )
        receipt_path_identity = str(receipt_snapshot["path"])
        receipt_inode = receipt_snapshot["identity"][:2]
        receipt_hash = receipt_snapshot["sha256"]
        index_path_identity = str(index_snapshot["path"])
        index_inode = index_snapshot["identity"][:2]
        index_hash = index_snapshot["sha256"]
        if (
            receipt_path_identity in seen_receipt_paths
            or receipt_inode in seen_receipt_inodes
            or receipt_hash in seen_receipt_hashes
            or index_path_identity in seen_index_paths
            or index_inode in seen_index_inodes
            or index_hash in seen_index_hashes
        ):
            raise CollectorError("Android descriptor receipts or source indexes are duplicated")
        seen_receipt_paths.add(receipt_path_identity)
        seen_receipt_inodes.add(receipt_inode)
        seen_receipt_hashes.add(receipt_hash)
        seen_index_paths.add(index_path_identity)
        seen_index_inodes.add(index_inode)
        seen_index_hashes.add(index_hash)
        if (
            descriptor["receipt_sha256"] != receipt_snapshot["sha256"]
            or descriptor["source_index_sha256"] != index_snapshot["sha256"]
        ):
            raise CollectorError(f"{descriptor_id} descriptor hash changed")
        index = _strict_json_bytes(index_snapshot["raw"], f"{descriptor_id} source index")
        if set(index) != {
            "schema_version",
            "contract",
            "created_at_utc",
            "producer",
            "files",
            "sealed",
            "secret_material_redacted",
        } or index["schema_version"] != 1 or index["contract"] != FORM_FACTOR_SOURCE_INDEX_CONTRACT or index["sealed"] is not True or index["secret_material_redacted"] is not True:
            raise CollectorError(f"{descriptor_id} source index contract is invalid")
        index_captured = _parse_receipt_time(
            index["created_at_utc"], f"{descriptor_id} source index"
        )
        if (
            index_captured < manifest_captured - MAX_RUNTIME_RECEIPT_SKEW
            or index_captured > manifest_captured + dt.timedelta(minutes=5)
        ):
            raise CollectorError(f"{descriptor_id} source index is stale or from another run")
        closure = _producer_closure(
            repo, index["producer"], f"{descriptor_id} source index", bound_files
        )
        if descriptor["producer_closure_sha256"] != closure:
            raise CollectorError(f"{descriptor_id} producer closure changed")
        files = index["files"]
        if not isinstance(files, list) or len(files) != 1:
            raise CollectorError(
                f"{descriptor_id} source index must contain only its exact receipt"
            )
        indexed_paths: list[str] = []
        indexed_inodes: set[tuple[int, int]] = set()
        indexed_hashes: set[str] = set()
        indexed_bytes = 0
        matched_item: dict[str, Any] | None = None
        source_members: list[dict[str, Any]] = []
        for item in files:
            if not isinstance(item, dict) or set(item) != {"path", "sha256", "size_bytes", "contract"}:
                raise CollectorError(f"{descriptor_id} source index file descriptor is invalid")
            original_source = pathlib.PurePosixPath(str(item["path"]))
            original_name = original_source.name.lower()
            source_contract = str(item["contract"]).lower()
            if (
                original_name in {
                    "mapping.txt",
                    "proguard-mapping.txt",
                    "proguard.map",
                }
                or original_name.endswith((".map", ".symbols"))
                or any(
                    marker in source_contract
                    for marker in ("mapping", "proguard", "private-symbol")
                )
            ):
                raise CollectorError(
                    "Android private mapping/symbol material cannot enter public source evidence"
                )
            indexed_path = _relative_input_path(
                pathlib.Path(index_snapshot["path"]).parent,
                item["path"],
                f"{descriptor_id} indexed file",
            )
            indexed_snapshot = _bound_file_snapshot(
                repo,
                indexed_path,
                f"{descriptor_id} indexed file",
                max_bytes=MAX_SOURCE_MEMBER_BYTES,
                require_artifacts=True,
            )
            indexed_paths.append(item["path"])
            indexed_inode = indexed_snapshot["identity"][:2]
            indexed_hash = indexed_snapshot["sha256"]
            indexed_bytes += len(indexed_snapshot["raw"])
            if (
                indexed_inode in indexed_inodes
                or indexed_hash in indexed_hashes
                or indexed_bytes > MAX_SOURCE_INVENTORY_BYTES
                or item["sha256"] != indexed_hash
                or item["size_bytes"] != len(indexed_snapshot["raw"])
                or not isinstance(item["contract"], str)
                or not item["contract"].startswith("winsvpn-")
            ):
                raise CollectorError(f"{descriptor_id} source-index inventory is not exact")
            indexed_inodes.add(indexed_inode)
            indexed_hashes.add(indexed_hash)
            if indexed_path.suffix.lower() == ".json":
                indexed_value = _strict_json_bytes(
                    indexed_snapshot["raw"], f"{descriptor_id} indexed JSON"
                )
                if (
                    indexed_value.get("contract") != item["contract"]
                    or indexed_value.get("secret_material_redacted") is not True
                ):
                    raise CollectorError(f"{descriptor_id} indexed JSON contract is invalid")
            prior = bound_files.get(str(indexed_snapshot["path"]))
            if prior is not None and (
                prior["identity"] != indexed_snapshot["identity"]
                or prior["sha256"] != indexed_snapshot["sha256"]
                or prior["raw"] != indexed_snapshot["raw"]
            ):
                raise CollectorError(f"{descriptor_id} indexed file changed across descriptors")
            bound_files[str(indexed_snapshot["path"])] = indexed_snapshot
            source_members.append({"item": dict(item), "snapshot": indexed_snapshot})
            if indexed_path == receipt_snapshot["path"]:
                if (
                    item["sha256"] != receipt_snapshot["sha256"]
                    or item["size_bytes"] != len(receipt_snapshot["raw"])
                    or indexed_snapshot["identity"] != receipt_snapshot["identity"]
                    or indexed_snapshot["raw"] != receipt_snapshot["raw"]
                ):
                    raise CollectorError(f"{descriptor_id} source-index membership changed")
                matched_item = item
        if indexed_paths != sorted(set(indexed_paths)) or matched_item is None:
            raise CollectorError(f"{descriptor_id} receipt is not uniquely indexed")
        receipt_value = _strict_json_bytes(receipt_snapshot["raw"], f"{descriptor_id} receipt")
        receipt_contract = receipt_value.get("contract")
        if receipt_contract not in {
            PRODUCED_ARTIFACT_CONTRACT,
            RUNTIME_CONTRACT,
            WEAR_RUNTIME_CONTRACT,
        } or matched_item["contract"] != receipt_contract:
            raise CollectorError(f"{descriptor_id} receipt contract is invalid")
        imported[descriptor_id] = {
            "descriptor": descriptor,
            "receipt": receipt_snapshot,
            "source_index": index_snapshot,
            "producer_path": index["producer"]["path"],
            "producer_closure_sha256": closure,
            "source_members": source_members,
            "value": receipt_value,
        }
        bound_files[str(receipt_snapshot["path"])] = receipt_snapshot
        bound_files[str(index_snapshot["path"])] = index_snapshot

    if sum(len(item["source_members"]) for item in imported.values()) > 32:
        raise CollectorError("Android imported source evidence exceeds the bundle file limit")
    for descriptor_id, (form, role, package_key) in DESCRIPTOR_PACKAGE_KEYS.items():
        code = _validate_produced_receipt(
            imported[descriptor_id]["value"],
            form=form,
            role=role,
            record=packages[package_key],
            app_version=app_version,
        )
        prior = version_codes.get(form)
        if prior is not None and prior != code:
            raise CollectorError(f"{form} produced receipts disagree on version_code")
        version_codes[form] = code
    if (
        set(version_codes) != set(FORM_FACTOR_CANDIDATES)
        or version_codes["phone"] != int(phone_build_number)
        or len(set(version_codes.values())) != 3
    ):
        raise CollectorError("Android form-factor version codes are not distinct issued identities")
    runtime_time = manifest_captured
    for form in FORM_FACTOR_CANDIDATES:
        _validate_runtime_receipt(
            imported[f"{form}-runtime"]["value"],
            form=form,
            packages=packages,
            app_version=app_version,
            version_code=version_codes[form],
            machine_captured=runtime_time,
        )
    approved_producers = [
        {
            "descriptor_id": descriptor_id,
            "path": imported[descriptor_id]["producer_path"],
            "closure_sha256": imported[descriptor_id]["producer_closure_sha256"],
        }
        for descriptor_id in FORM_FACTOR_DESCRIPTOR_IDS
    ]
    owner_authorization = _verify_form_factor_owner_authorization(
        repo,
        owner_authorization_path,
        expected_owner_authorization_sha256,
        key_id=authority_key_id,
        public_key=authority_public_key,
        manifest_sha256=manifest_snapshot["sha256"],
        app_version=app_version,
        phone_build_number=phone_build_number,
        release_input_index_sha256=release_input_index_sha256,
        build_receipt_sha256=build_receipt_sha256,
        packages=packages,
        native_tool_snapshots=native_tool_snapshots,
        adb_support_tree_snapshot=adb_support_snapshot,
        tesseract_support_tree_snapshot=tesseract_support_snapshot,
        route_authority_snapshots=route_authority_snapshots,
        expected_map_city_labels=normalized_city_labels,
        device_attestation=device_attestation,
        devicecheck_build_receipt=devicecheck_build_receipt,
        approved_producers=approved_producers,
        bound_files=bound_files,
    )
    bound_files[str(manifest_snapshot["path"])] = manifest_snapshot
    return {
        "manifest": manifest_snapshot,
        "owner_authorization": owner_authorization,
        "imported": imported,
        "version_codes": version_codes,
        "native_tool_snapshots": native_tool_snapshots,
        "adb_support_tree_snapshot": adb_support_snapshot,
        "tesseract_support_tree_snapshot": tesseract_support_snapshot,
        "route_authority_snapshots": route_authority_snapshots,
        "route_aliases": route_aliases,
        "expected_map_city_labels": normalized_city_labels,
        "device_attestation": device_attestation,
        "devicecheck_build_receipt": devicecheck_build_receipt,
        "bound_files": bound_files,
    }


def _reaudit_form_factor_snapshots(repo: pathlib.Path, preflight: dict[str, Any]) -> None:
    for expected in preflight["bound_files"].values():
        try:
            current = _bound_file_snapshot(
                repo,
                expected["path"],
                "preflight-bound form-factor evidence",
                max_bytes=max(int(expected["size_bytes"]), 1),
                require_artifacts=expected["relative"].startswith(".artifacts/"),
                retain_raw=expected["raw"] is not None,
            )
        except CollectorError as exc:
            raise CollectorError("form-factor evidence changed after preflight") from exc
        if (
            current["identity"] != expected["identity"]
            or current["sha256"] != expected["sha256"]
            or (
                expected["raw"] is not None
                and current["raw"] != expected["raw"]
            )
        ):
            raise CollectorError("form-factor evidence changed after preflight")


def _import_descriptor_source_closure(
    root: pathlib.Path,
    descriptor_id: str,
    imported: dict[str, Any],
) -> dict[str, str]:
    receipt_target = root / FIXED_IMPORTED_BASENAMES[descriptor_id]
    index_target = root / f"{descriptor_id}-source-index.json"
    _write_exact_bytes(receipt_target, imported["receipt"]["raw"])
    _write_exact_bytes(index_target, imported["source_index"]["raw"])
    relocation_files: list[dict[str, Any]] = []
    source_ordinal = 0
    for member in imported["source_members"]:
        item = member["item"]
        snapshot = member["snapshot"]
        if snapshot["identity"] == imported["receipt"]["identity"]:
            target = receipt_target
        else:
            suffix = pathlib.PurePosixPath(item["path"]).suffix.lower()
            if re.fullmatch(r"\.[a-z0-9]{1,8}", suffix or "") is None:
                suffix = ".bin"
            target = root / f"{descriptor_id}-source-{source_ordinal:02d}{suffix}"
            source_ordinal += 1
            _write_exact_bytes(target, snapshot["raw"])
        relocation_files.append({
            "source_path": item["path"],
            "source_sha256": snapshot["sha256"],
            "source_size_bytes": snapshot["size_bytes"],
            "source_contract": item["contract"],
            "imported_path": target.name,
            "imported_sha256": _held_evidence_record(target)["sha256"],
            "imported_size_bytes": _held_evidence_record(target)["size_bytes"],
        })
    relocation = {
        "schema_version": 1,
        "contract": "winsvpn-android-form-factor-source-relocation-v1",
        "descriptor_id": descriptor_id,
        "source_index_path": index_target.name,
        "source_index_sha256": _held_evidence_record(index_target)["sha256"],
        "producer_path": imported["producer_path"],
        "producer_closure_sha256": imported["producer_closure_sha256"],
        "files": relocation_files,
        "secret_material_redacted": True,
    }
    relocation_target = root / f"{descriptor_id}-source-relocation.json"
    _write_exact_bytes(
        relocation_target,
        json.dumps(
            relocation,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii") + b"\n",
    )
    return {
        "receipt_path": receipt_target.name,
        "receipt_sha256": _held_evidence_record(receipt_target)["sha256"],
        "source_index_path": index_target.name,
        "source_relocation_path": relocation_target.name,
    }


def build_form_factor_closure(
    repo: pathlib.Path,
    root: pathlib.Path,
    packages: dict[str, dict[str, str | int]],
    symbol_evidence: dict[str, str],
    app_version: str,
    preflight: dict[str, Any],
    captured_at_utc: str,
) -> dict[str, Any]:
    if set(symbol_evidence) != set(CANONICAL_SYMBOL_ROLES):
        raise CollectorError("Android private mapping closure is incomplete")
    machine_captured = _parse_receipt_time(captured_at_utc, "Android machine evidence")
    _reaudit_form_factor_snapshots(repo, preflight)
    _reaudit_native_tools(preflight["native_tool_snapshots"])
    _reaudit_adb_support_tree(preflight["adb_support_tree_snapshot"])
    _reaudit_tesseract_support_tree(preflight["tesseract_support_tree_snapshot"])
    _reaudit_route_authority(preflight["route_authority_snapshots"])
    for path in root.iterdir():
        lowered = path.name.lower()
        if lowered in {"mapping.txt", "proguard-mapping.txt", "proguard.map"} or lowered.endswith(".map"):
            raise CollectorError("Android R8 mapping must remain in private owner custody")
    manifest_target = root / "form-factor-evidence-manifest.json"
    _write_exact_bytes(manifest_target, preflight["manifest"]["raw"])
    authorization_target = root / "form-factor-owner-authorization.json"
    _write_exact_bytes(
        authorization_target,
        preflight["owner_authorization"]["snapshot"]["raw"],
    )
    _write_exact_bytes(
        root / "physical-device-attestation.json",
        preflight["device_attestation"]["snapshot"]["raw"],
    )
    devicecheck = preflight["devicecheck_build_receipt"]
    devicecheck_custody_path, devicecheck_custody_sha256 = receipt(
        root,
        "devicecheck-build-custody.json",
        "winsvpn-devicecheck-build-custody-v1",
        {
            "build_receipt_contract": DEVICECHECK_BUILD_RECEIPT_CONTRACT,
            "build_receipt_sha256": devicecheck["snapshot"]["sha256"],
            "build_receipt_sidecar_sha256": devicecheck["sidecar"]["sha256"],
            "consumer_status": devicecheck["value"]["consumer_status"],
            "variant": "release",
            "target_apk_sha256": devicecheck["target"]["sha256"],
            "target_apk_bytes": devicecheck["target"]["bytes"],
            "android_test_apk_sha256": devicecheck["android_test"]["sha256"],
            "android_test_apk_bytes": devicecheck["android_test"]["bytes"],
            "signer_sha256": devicecheck["target"]["signer_sha256"],
            "source_inventory_sha256": devicecheck["value"]["source_closure"]
            ["inventory_sha256"],
            "passed": True,
        },
    )
    imported_sources = {
        descriptor_id: _import_descriptor_source_closure(
            root, descriptor_id, preflight["imported"][descriptor_id]
        )
        for descriptor_id in FORM_FACTOR_DESCRIPTOR_IDS
    }
    matrix: dict[str, Any] = {}
    for form, roles in FORM_FACTOR_PACKAGE_KEYS.items():
        matrix_packages: dict[str, Any] = {}
        for role, package_key in roles.items():
            descriptor_id = f"{form}-{role}-produced"
            imported = preflight["imported"][descriptor_id]
            receipt_value = imported["value"]
            receipt_time = _parse_receipt_time(
                receipt_value["captured_at_utc"], f"{descriptor_id} receipt"
            )
            if (
                receipt_time < machine_captured - MAX_RUNTIME_RECEIPT_SKEW
                or receipt_time > machine_captured + dt.timedelta(minutes=5)
            ):
                raise CollectorError(f"{descriptor_id} receipt is stale or from another run")
            record = packages[package_key]
            matrix_packages[role] = {
                "role": role,
                "path": record["path"],
                "sha256": record["sha256"],
                "size_bytes": record["size_bytes"],
                "receipt_path": imported_sources[descriptor_id]["receipt_path"],
                "receipt_sha256": imported_sources[descriptor_id]["receipt_sha256"],
            }
        runtime_id = f"{form}-runtime"
        runtime_imported = preflight["imported"][runtime_id]
        runtime_value = runtime_imported["value"]
        _validate_runtime_receipt(
            runtime_value,
            form=form,
            packages=packages,
            app_version=app_version,
            version_code=preflight["version_codes"][form],
            machine_captured=machine_captured,
        )
        artifact_key = "wear_aab" if form == "wear" else f"{form}_apk"
        matrix[form] = {
            "form_factor": form,
            "candidate_id": FORM_FACTOR_CANDIDATES[form],
            "version_name": app_version,
            "version_code": preflight["version_codes"][form],
            "packages": matrix_packages,
            "runtime": {
                "kind": "pairing_runtime" if form == "wear" else "live_vpn",
                "artifact_sha256": packages[artifact_key]["sha256"],
                "source_only": False,
                "receipt_path": imported_sources[runtime_id]["receipt_path"],
                "receipt_sha256": imported_sources[runtime_id]["receipt_sha256"],
                "passed": True,
            },
        }
    for path in root.iterdir():
        lowered = path.name.lower()
        if lowered in {"mapping.txt", "proguard-mapping.txt", "proguard.map"} or lowered.endswith(".map"):
            raise CollectorError("Android R8 mapping must remain in private owner custody")
    return {
        "application_id": EXPECTED_APPLICATION_ID,
        "phone_aab_sha256": packages["phone_aab"]["sha256"],
        "phone_aab_size_bytes": packages["phone_aab"]["size_bytes"],
        "tv_apk_sha256": packages["tv_apk"]["sha256"],
        "tv_apk_size_bytes": packages["tv_apk"]["size_bytes"],
        "tv_aab_sha256": packages["tv_aab"]["sha256"],
        "tv_aab_size_bytes": packages["tv_aab"]["size_bytes"],
        "wear_aab_sha256": packages["wear_aab"]["sha256"],
        "wear_aab_size_bytes": packages["wear_aab"]["size_bytes"],
        "private_symbol_mapping_sha256": symbol_evidence,
        "devicecheck_build_custody_path": devicecheck_custody_path,
        "devicecheck_build_custody_sha256": devicecheck_custody_sha256,
        "mapping_owner_blocked": True,
        "listing_inventory": {
            "phone": OWNER_BLOCKED_LISTING,
            "tv": OWNER_BLOCKED_LISTING,
            "wear": OWNER_BLOCKED_LISTING,
        },
        "form_factor_matrix": matrix,
    }


def copy_evidence(source: pathlib.Path, root: pathlib.Path, name: str) -> tuple[str, str]:
    if not source.is_file() or source.is_symlink() or source.stat().st_nlink != 1:
        raise CollectorError(f"upstream evidence is not a regular file: {source}")
    target = root / name
    if target.exists() or target.is_symlink():
        raise CollectorError(f"refusing to overwrite copied evidence: {target}")
    snapshot = _external_file_snapshot(
        source,
        f"upstream Android evidence {name}",
        max_bytes=128 * 1024 * 1024,
        retain_raw=True,
    )
    _write_exact_bytes(target, snapshot["raw"])
    return target.name, _held_evidence_record(target)["sha256"]


def evidence_contract(path: pathlib.Path, raw: bytes | None = None) -> str:
    if path.name == "map-50-mile.png":
        return "winsvpn-android-map-screenshot-v1"
    if path.name == "startup-logcat.txt":
        return "winsvpn-android-startup-logcat-v1"
    if path.suffix.lower() != ".json" and re.fullmatch(
        r"(?:phone|tv|wear)-(?:apk-produced|aab-produced|runtime)-source-\d{2}\.[a-z0-9]{1,8}",
        path.name,
    ):
        return "winsvpn-android-form-factor-imported-source-member-v1"
    if path.suffix.lower() != ".json":
        raise CollectorError(f"unrecognized evidence file type: {path.name}")
    try:
        if raw is None:
            raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CollectorError(f"evidence JSON is invalid: {path.name}") from exc
    contract = value.get("contract") if isinstance(value, dict) else None
    if not isinstance(contract, str) or not contract.startswith("winsvpn-"):
        raise CollectorError(f"evidence contract is invalid: {path.name}")
    if value.get("secret_material_redacted") is not True:
        raise CollectorError(f"evidence redaction marker is missing: {path.name}")
    return contract


def _finalize_device_transcript_proof(
    root: pathlib.Path,
    adb: pathlib.Path,
    serial: str,
    physical_device: dict[str, str],
    attestation: dict[str, Any],
    devicecheck_build_receipt: dict[str, Any],
) -> tuple[str, str]:
    binding = _adb_transport_binding(
        adb, serial, physical_device["transport_id"]
    )
    if (
        binding["listed_usb"]
        and physical_device["usb"].removeprefix("usb:")
        != binding["listed_usb"]
    ):
        raise CollectorError("Android USB endpoint changed before final proof")
    names = _reaudit_evidence_holds(root)
    files = [
        {
            "path": name,
            "sha256": _held_evidence_record(root / name)["sha256"],
            "size_bytes": _held_evidence_record(root / name)["size_bytes"],
        }
        for name in sorted(names)
    ]
    transcript = {
        "contract": "winsvpn-android-device-evidence-transcript-v1",
        "serial_sha256": physical_device["serial_sha256"],
        "hardware_identity_sha256": physical_device["hardware_identity_sha256"],
        "transport": physical_device["transport"],
        "usb": physical_device["usb"],
        "transport_id": physical_device["transport_id"],
        "devicecheck_custody": _devicecheck_custody_context(
            devicecheck_build_receipt
        ),
        "files": files,
    }
    transcript_sha256 = hashlib.sha256(
        _canonical_json_bytes(transcript, "Android device evidence transcript")
    ).hexdigest()
    proof = _live_device_attestation_proof(
        adb,
        physical_device["transport_id"],
        attestation,
        phase="final",
        context_sha256=transcript_sha256,
    )
    _assert_devicecheck_proof_matches_custody(proof, devicecheck_build_receipt)
    _adb_transport_binding(adb, serial, physical_device["transport_id"])
    return receipt(
        root,
        "physical-device-final-proof.json",
        DEVICE_ATTESTATION_FINAL_PROOF_CONTRACT,
        {
            "serial_sha256": physical_device["serial_sha256"],
            "hardware_identity_sha256": physical_device["hardware_identity_sha256"],
            "transport": physical_device["transport"],
            "usb": physical_device["usb"],
            "transport_id": physical_device["transport_id"],
            "attestation_receipt_sha256": attestation["snapshot"]["sha256"],
            "devicecheck_build_receipt_sha256": devicecheck_build_receipt
            ["snapshot"]["sha256"],
            "transcript_sha256": transcript_sha256,
            "transcript_context_sha256": transcript_sha256,
            "transcript_file_count": len(files),
            "nonce_sha256": proof["nonce_sha256"],
            "semantic_report_schema": proof["report_schema"],
            "semantic_report_sha256": proof["report_sha256"],
            "semantic_report_b64": proof["report_b64"],
            "target_base_apk_sha256": proof["target_base_apk_sha256"],
            "target_base_apk_bytes": int(proof["target_base_apk_bytes"]),
            "test_apk_sha256": proof["test_apk_sha256"],
            "test_apk_bytes": int(proof["test_apk_bytes"]),
            "attested_key_id": proof["attested_key_id"],
            "signature_hex": proof["signature_hex"],
            "passed": True,
        },
    )


def create_evidence_index(
    repo: pathlib.Path,
    root: pathlib.Path,
    run_id: uuid.UUID,
    machine_path: pathlib.Path,
    map_path: pathlib.Path,
    *,
    artifact_path: pathlib.Path,
    release_input_index_path: pathlib.Path,
    inputs: Any,
    build: Any,
    producer_sha256: str,
) -> tuple[pathlib.Path, str]:
    index_path = root / "EVIDENCE_INDEX.json"
    if index_path.exists() or index_path.is_symlink():
        raise CollectorError("evidence index already exists")
    held_paths = _reaudit_evidence_holds(root)
    actual_paths = {
        path.name
        for path in root.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if actual_paths != held_paths:
        raise CollectorError("evidence bundle contains an unheld or missing file")
    mandatory_paths = {
        machine_path.name,
        map_path.name,
        "apk-signature-receipt.json",
        "startup-logcat.txt",
        "form-factor-evidence-manifest.json",
        "form-factor-owner-authorization.json",
        "physical-device-attestation.json",
        "physical-device-final-proof.json",
    }
    for descriptor_id in FORM_FACTOR_DESCRIPTOR_IDS:
        mandatory_paths.update(
            {
                FIXED_IMPORTED_BASENAMES[descriptor_id],
                f"{descriptor_id}-source-index.json",
                f"{descriptor_id}-source-relocation.json",
            }
        )
    if not mandatory_paths.issubset(held_paths):
        missing = sorted(mandatory_paths - held_paths)
        raise CollectorError(
            f"evidence bundle mandatory closure is incomplete: {','.join(missing)}"
        )
    entries: list[dict[str, Any]] = []
    for name in sorted(held_paths):
        path = root / name
        if path.name.startswith(".") or path.suffix.lower() == ".tmp":
            raise CollectorError("temporary evidence files are forbidden at seal time")
        record = _held_evidence_record(path)
        raw = (
            _held_evidence_bytes(path, max_bytes=MAX_EVIDENCE_JSON_BYTES)
            if path.suffix.lower() == ".json"
            else None
        )
        entries.append({
            "path": path.name,
            "sha256": record["sha256"],
            "size_bytes": record["size_bytes"],
            "contract": evidence_contract(path, raw),
        })
    paths = {entry["path"] for entry in entries}
    if machine_path.name not in paths or map_path.name not in paths:
        raise CollectorError("machine evidence or map screenshot is absent from the bundle")
    helpers = {
        name: {
            "path": relative,
            "sha256": sha256_file(repo / pathlib.PurePosixPath(relative)),
        }
        for name, relative in HELPER_PATHS.items()
    }
    try:
        artifact_relative = artifact_path.resolve().relative_to(repo.resolve()).as_posix()
        input_index_relative = release_input_index_path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError as exc:
        raise CollectorError("artifact and release-input index must stay inside the repository") from exc
    value = {
        "schema_version": 1,
        "contract": INDEX_CONTRACT,
        "run_id": str(run_id),
        "created_at_utc": utc_now(),
        "machine_evidence_path": machine_path.name,
        "map_screenshot_path": map_path.name,
        "files": entries,
        "binding": {
            "artifact": {
                "path": artifact_relative,
                "sha256": sha256_file(artifact_path),
                "size_bytes": artifact_path.stat().st_size,
            },
            "release_inputs": {
                "path": input_index_relative,
                "sha256": inputs.index_sha256,
                "platform_manifest_sha256": inputs.platform_manifest_sha256,
                "artifact_input_fingerprint_sha256": inputs.artifact_input_fingerprint_sha256,
                "shared_revision": inputs.shared_revision,
            },
            "build_receipt": {"path": build.path, "sha256": build.sha256},
            "producer": {"path": PRODUCER, "closure_sha256": producer_sha256},
        },
        "helpers": helpers,
        "secret_material_redacted": True,
    }
    atomic_json(index_path, value)
    seal_evidence_bundle(root)
    indexed_sha256 = _held_evidence_record(index_path)["sha256"]
    final_held_paths = _reaudit_evidence_holds(root)
    actual = {path.name for path in root.iterdir() if path.is_file() and not path.is_symlink()}
    if (
        actual != paths | {index_path.name}
        or final_held_paths != actual
    ):
        raise CollectorError("evidence bundle changed while the index was sealed")
    return index_path, indexed_sha256


FRESH_REGRESSION_REQUIRED_MARKERS = frozenset(
    {
        "ANDROID_FRESH_RELEASE_REGRESSION",
        "ANDROID_MACHINE_EVIDENCE_ROOT",
        "ANDROID_MACHINE_EVIDENCE_RUN_ID",
        "APK_ARTIFACT_SIGNER_SHA256",
        "APK_INSTALLED_SIGNER_SHA256",
        "APK_SHA256",
        "APK_SIGNATURE_RECEIPT_PATH",
        "APK_SIGNATURE_RECEIPT_SHA256",
        "APK_SIZE_BYTES",
        "BATTERY_PRE_TUNNEL_PROMPT",
        "CALCULATOR_KEYS_VISIBLE",
        "CLEAN_UNINSTALL",
        "DECOY_TO_REAL_TOP",
        "DEVICE_SERIAL",
        "DEVICE_UNLOCK_PRECHECK",
        "DISPLAY_SIZE",
        "DOUBLE_AFTER_RESTART",
        "DOUBLE_BEFORE_RESTART",
        "EXACT_INSTALL",
        "INSTALLED_BASE_APK_SHA256",
        "INSTALLED_BASE_APK_SIZE_BYTES",
        "ONBOARDING_TOP",
        "PLUGGED_IN_STAY_AWAKE_RESTORED",
        "PRIVACY_CONSENT_ACTION",
        "REAL_TO_DECOY_TOP",
        "SCREEN_TIMEOUT_RESTORED_MS",
        "STARTUP_LOGCAT_FATAL_SCAN",
        "STARTUP_LOGCAT_PATH",
        "STARTUP_LOGCAT_SHA256",
        "STARTUP_PID",
        "TEMPORARY_PLUGGED_IN_STAY_AWAKE",
        "TEMPORARY_SCREEN_TIMEOUT_MS",
    }
)
FRESH_REGRESSION_OPTIONAL_MARKERS = frozenset(
    {
        "PREEXISTING_PACKAGE",
        "THIRD_PARTY_SECURITY_SHEET",
    }
)
FRESH_REGRESSION_MARKERS = (
    FRESH_REGRESSION_REQUIRED_MARKERS | FRESH_REGRESSION_OPTIONAL_MARKERS
)


def parse_markers(text: str, allowed_keys: frozenset[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line.strip())
        if match is None:
            continue
        key = match.group(1)
        if key not in allowed_keys:
            raise CollectorError(f"fresh regression emitted unexpected marker: {key}")
        if key in values:
            raise CollectorError(f"fresh regression emitted duplicate marker: {key}")
        values[key] = match.group(2).strip()
    return values


def run_fresh_regression(
    repo: pathlib.Path, powershell: str, apk: pathlib.Path, adb: pathlib.Path,
    serial: str, transport_id: str, pin: str, acknowledge_security_sheet: bool,
) -> dict[str, str]:
    _adb_transport_binding(adb, serial, transport_id)
    command = [
        powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(repo / "tools" / "android_fresh_release_regression.ps1"),
        "-Apk", str(apk), "-Adb", str(adb), "-Serial", serial, "-Pin", pin,
    ]
    if acknowledge_security_sheet:
        command.append("-AcknowledgeThirdPartySecuritySheet")
    result = _bounded_subprocess_run(
        command, text=True,
        timeout=900, check=False,
        stdout_limit=MAX_SUBPROCESS_STDOUT_BYTES,
        stderr_limit=MAX_SUBPROCESS_STDERR_BYTES,
    )
    _adb_transport_binding(adb, serial, transport_id)
    if result.returncode != 0:
        tail = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["fresh regression failed"]
        raise CollectorError(f"exact clean-install regression failed: {tail[0][:300]}")
    markers = parse_markers(result.stdout, FRESH_REGRESSION_MARKERS)
    missing = sorted(FRESH_REGRESSION_REQUIRED_MARKERS - markers.keys())
    if missing:
        raise CollectorError(
            "fresh regression omitted required markers: " + ", ".join(missing)
        )
    required = {
        "ANDROID_FRESH_RELEASE_REGRESSION": "PASS",
        "CLEAN_UNINSTALL": "PASS",
        "EXACT_INSTALL": "PASS",
        "STARTUP_LOGCAT_FATAL_SCAN": "PASS",
    }
    for key, expected in required.items():
        if markers.get(key) != expected:
            raise CollectorError(f"fresh regression required marker failed: {key}")
    for key in (
        "APK_SHA256", "INSTALLED_BASE_APK_SHA256", "APK_SIGNATURE_RECEIPT_PATH",
        "APK_SIGNATURE_RECEIPT_SHA256", "APK_ARTIFACT_SIGNER_SHA256",
        "APK_INSTALLED_SIGNER_SHA256", "APK_SIZE_BYTES", "INSTALLED_BASE_APK_SIZE_BYTES",
        "STARTUP_PID", "STARTUP_LOGCAT_PATH", "STARTUP_LOGCAT_SHA256",
    ):
        if key not in markers:
            raise CollectorError(f"fresh regression omitted exact-install fact: {key}")
    return markers


def package_version(
    driver: AndroidDriver, expected_name: str, expected_code: str
) -> tuple[str, str]:
    dump = driver.adb_run(["shell", "dumpsys", "package", PACKAGE], timeout=60)
    names = set(re.findall(r"(?m)^\s*versionName=([^\s]+)\s*$", dump))
    codes = set(re.findall(r"(?m)^\s*versionCode=(\d+)\b", dump))
    if len(names) != 1 or len(codes) != 1:
        raise CollectorError("installed Android versionName/versionCode is ambiguous")
    name = names.pop()
    code = codes.pop()
    if name != expected_name or code != expected_code:
        raise CollectorError(
            "installed Android package version does not match the exact release identity"
        )
    return name, code


def xray_manifest(routes: list[dict[str, Any]]) -> str:
    canonical = "".join(
        f"tcp|{item['port']}|{item['security']}\n"
        for item in sorted(routes, key=lambda item: (item["port"], item["security"]))
    )
    return sha256_text(canonical)


def control_state(
    remote_sha: str, radio: dict[str, bool], double_vpn: bool,
    chrome_excluded: bool, samsung_excluded: bool,
) -> str:
    return sha256_text(json.dumps({
        "remote_state_sha256": remote_sha,
        "radio": radio,
        "double_vpn": double_vpn,
        "split": {CHROME: chrome_excluded, SAMSUNG_BROWSER: samsung_excluded},
    }, sort_keys=True, separators=(",", ":")))


def _map_bounds(value: Any, label: str) -> tuple[int, int, int, int]:
    if (
        not isinstance(value, list)
        or len(value) != 4
        or any(isinstance(item, bool) or not isinstance(item, int) for item in value)
    ):
        raise CollectorError(f"Android map {label} must contain four integer pixels")
    left, top, right, bottom = value
    if left < 0 or top < 0 or right <= left or bottom <= top:
        raise CollectorError(f"Android map {label} is invalid")
    return left, top, right, bottom


def _validated_map_visual(
    raw: dict[str, Any], authorized_city_labels: list[str]
) -> dict[str, Any]:
    expected_fields = {
        "measurement_contract",
        "screenshot_path",
        "screenshot_sha256",
        "observed_city_labels",
        "viewport_bounds_px",
        "radius_circle_bounds_px",
        "target_marker_bounds_px",
        "target_marker_semantic_observed",
    }
    if not isinstance(raw, dict) or set(raw) != expected_fields:
        raise CollectorError(
            "OWNER-BLOCKED: authenticated Android map geometry measurement is required"
        )
    if raw["measurement_contract"] != "winsvpn-android-map-geometry-observation-v1":
        raise CollectorError("Android map geometry measurement contract is invalid")
    if (
        not isinstance(raw["screenshot_path"], str)
        or re.fullmatch(r"[0-9a-f]{64}", str(raw["screenshot_sha256"])) is None
        or raw["target_marker_semantic_observed"] is not True
    ):
        raise CollectorError("Android map screenshot or marker observation is invalid")
    observed_labels = _normalized_map_city_labels(raw["observed_city_labels"])
    if observed_labels != authorized_city_labels:
        raise CollectorError("Android map city labels are not owner-authorized")
    viewport = _map_bounds(raw["viewport_bounds_px"], "viewport bounds")
    radius = _map_bounds(raw["radius_circle_bounds_px"], "radius-circle bounds")
    marker = _map_bounds(raw["target_marker_bounds_px"], "target-marker bounds")
    viewport_width = viewport[2] - viewport[0]
    viewport_height = viewport[3] - viewport[1]
    shortest = min(viewport_width, viewport_height)
    radius_width = radius[2] - radius[0]
    radius_height = radius[3] - radius[1]
    marker_width = marker[2] - marker[0]
    marker_height = marker[3] - marker[1]
    if shortest < 200:
        raise CollectorError("Android map viewport is too small for radius measurement")
    if (
        abs(radius_width - radius_height) > max(4, shortest // 20)
        or radius_width < int(shortest * 0.90)
        or radius_width > int(shortest * 1.10)
        or marker_width > int(shortest * 0.15)
        or marker_height > int(shortest * 0.15)
    ):
        raise CollectorError("Android map geometry does not prove the 50-mile viewport")
    radius_center = ((radius[0] + radius[2]) / 2, (radius[1] + radius[3]) / 2)
    marker_center = ((marker[0] + marker[2]) / 2, (marker[1] + marker[3]) / 2)
    tolerance = max(4.0, shortest * 0.02)
    if (
        abs(radius_center[0] - marker_center[0]) > tolerance
        or abs(radius_center[1] - marker_center[1]) > tolerance
        or radius[0] < viewport[0]
        or radius[1] < viewport[1]
        or radius[2] > viewport[2]
        or radius[3] > viewport[3]
        or marker[0] < viewport[0]
        or marker[1] < viewport[1]
        or marker[2] > viewport[2]
        or marker[3] > viewport[3]
    ):
        raise CollectorError("Android map marker and radius geometry are inconsistent")
    return {
        "screenshot_path": raw["screenshot_path"],
        "screenshot_sha256": raw["screenshot_sha256"],
        "radius_miles": 50,
        "city_labels_visible": True,
        "target_marker_visible": True,
        "viewport_not_world_zoom": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk")
    parser.add_argument("--adb")
    parser.add_argument("--adb-support-root")
    parser.add_argument("--serial")
    parser.add_argument("--pin", default="1357")
    parser.add_argument("--route-inventory")
    parser.add_argument("--ssh-config")
    parser.add_argument("--ssh-identity")
    parser.add_argument("--ssh-known-hosts")
    parser.add_argument("--expected-adb-server-socket")
    parser.add_argument("--device-attestation-receipt")
    parser.add_argument("--devicecheck-build-receipt")
    parser.add_argument("--expected-devicecheck-build-receipt-sha256")
    parser.add_argument("--expected-devicecheck-target-apk-sha256")
    parser.add_argument("--expected-devicecheck-target-apk-bytes")
    parser.add_argument("--expected-devicecheck-android-test-apk-sha256")
    parser.add_argument("--expected-devicecheck-android-test-apk-bytes")
    parser.add_argument("--expected-devicecheck-source-inventory-sha256")
    parser.add_argument("--release-input-index")
    parser.add_argument("--build-receipt")
    parser.add_argument("--form-factor-evidence-manifest")
    parser.add_argument("--expected-form-factor-evidence-manifest-sha256")
    parser.add_argument("--form-factor-owner-authorization")
    parser.add_argument("--expected-form-factor-owner-authorization-sha256")
    parser.add_argument("--tesseract")
    parser.add_argument("--tesseract-support-root")
    parser.add_argument("--ssh")
    parser.add_argument("--whoami")
    parser.add_argument("--icacls")
    parser.add_argument("--taskkill")
    parser.add_argument("--expected-map-city", action="append", default=[])
    parser.add_argument("--output-root")
    parser.add_argument("--powershell")
    parser.add_argument("--acknowledge-third-party-security-sheet", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if xray_manifest([{"port": 443, "security": "tls"}, {"port": 80, "security": "none"}]) != sha256_text("tcp|80|none\ntcp|443|tls\n"):
            raise CollectorError("Xray manifest self-test failed")
        rfc8032_public_key = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a"
            "0ee172f3daa62325af021a68f707511a"
        )
        rfc8032_signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        )
        if not _verify_ed25519(rfc8032_public_key, b"", rfc8032_signature):
            raise CollectorError("Ed25519 RFC 8032 self-test failed")
        print("ANDROID FINAL EVIDENCE COLLECTOR SELF-TEST: PASS")
        return 0
    required = (
        args.apk, args.adb, args.adb_support_root, args.serial, args.route_inventory,
        args.ssh_config, args.ssh_identity, args.ssh_known_hosts,
        args.expected_adb_server_socket,
        args.device_attestation_receipt,
        args.devicecheck_build_receipt,
        args.expected_devicecheck_build_receipt_sha256,
        args.expected_devicecheck_target_apk_sha256,
        args.expected_devicecheck_target_apk_bytes,
        args.expected_devicecheck_android_test_apk_sha256,
        args.expected_devicecheck_android_test_apk_bytes,
        args.expected_devicecheck_source_inventory_sha256,
        args.release_input_index, args.build_receipt, args.tesseract,
        args.tesseract_support_root, args.output_root,
        args.powershell, args.ssh, args.whoami, args.icacls, args.taskkill,
        args.form_factor_evidence_manifest,
        args.expected_form_factor_evidence_manifest_sha256,
        args.form_factor_owner_authorization,
        args.expected_form_factor_owner_authorization_sha256,
    )
    if any(not value for value in required):
        raise CollectorError(
            "APK, dedicated ADB server, serial, route/SSH authority, frozen inputs, build receipts, "
            "hash-pinned form-factor evidence manifest, owner-signed authorization, "
            "Tesseract, and output are required"
        )
    expected_devicecheck_target_apk_bytes = _devicecheck_owner_pinned_bytes(
        args.expected_devicecheck_target_apk_bytes,
        "DeviceCheck target APK",
    )
    expected_devicecheck_android_test_apk_bytes = _devicecheck_owner_pinned_bytes(
        args.expected_devicecheck_android_test_apk_bytes,
        "DeviceCheck androidTest APK",
    )

    repo = pathlib.Path(__file__).resolve().parent.parent
    apk = pathlib.Path(args.apk).expanduser().resolve()
    adb = pathlib.Path(args.adb).expanduser().resolve()
    native_tool_paths = {
        "adb": adb,
        "tesseract": pathlib.Path(args.tesseract).expanduser().absolute(),
        "powershell": pathlib.Path(args.powershell).expanduser().absolute(),
        "ssh": pathlib.Path(args.ssh).expanduser().absolute(),
        "whoami": pathlib.Path(args.whoami).expanduser().absolute(),
        "icacls": pathlib.Path(args.icacls).expanduser().absolute(),
        "taskkill": pathlib.Path(args.taskkill).expanduser().absolute(),
    }
    expected_name, expected_code = expected_android_identity(repo)
    packages = assert_held_produced_packages(repo, apk)
    route_inventory_path = pathlib.Path(args.route_inventory).expanduser().absolute()
    ssh_config_path = pathlib.Path(args.ssh_config).expanduser().absolute()
    ssh_identity_path = pathlib.Path(args.ssh_identity).expanduser().absolute()
    ssh_known_hosts_path = pathlib.Path(args.ssh_known_hosts).expanduser().absolute()
    inventory, inventory_sha = load_inventory(route_inventory_path)
    route_authority_paths = {
        "route_inventory": route_inventory_path,
        "ssh_config": ssh_config_path,
        "ssh_identity": ssh_identity_path,
        "ssh_known_hosts": ssh_known_hosts_path,
    }
    _validate_adb_server_environment(args.expected_adb_server_socket)
    inputs = release_input_binding(repo, "android", args.release_input_index)
    build = build_receipt_binding(repo, "android", args.release_input_index, args.build_receipt, apk)
    producer_sha = producer_contract_hash(repo, PRODUCER)
    form_factor_preflight = preflight_form_factor_evidence(
        repo,
        pathlib.Path(args.form_factor_evidence_manifest).expanduser().absolute(),
        args.expected_form_factor_evidence_manifest_sha256,
        pathlib.Path(args.form_factor_owner_authorization).expanduser().absolute(),
        args.expected_form_factor_owner_authorization_sha256,
        pathlib.Path(args.release_input_index).expanduser().absolute(),
        packages,
        expected_name,
        expected_code,
        inputs.index_sha256,
        build.sha256,
        native_tool_paths,
        pathlib.Path(args.adb_support_root).expanduser().absolute(),
        pathlib.Path(args.tesseract_support_root).expanduser().absolute(),
        route_authority_paths,
        inventory,
        inventory_sha,
        args.expected_map_city,
        pathlib.Path(args.device_attestation_receipt).expanduser().absolute(),
        pathlib.Path(args.devicecheck_build_receipt).expanduser().absolute(),
        args.expected_devicecheck_build_receipt_sha256,
        args.expected_devicecheck_target_apk_sha256,
        expected_devicecheck_target_apk_bytes,
        args.expected_devicecheck_android_test_apk_sha256,
        expected_devicecheck_android_test_apk_bytes,
        args.expected_devicecheck_source_inventory_sha256,
        args.serial,
    )
    global _WINDOWS_WHOAMI, _WINDOWS_ICACLS, _WINDOWS_TASKKILL
    _WINDOWS_WHOAMI = native_tool_paths["whoami"]
    _WINDOWS_ICACLS = native_tool_paths["icacls"]
    _WINDOWS_TASKKILL = native_tool_paths["taskkill"]
    os.environ["WINSVPN_ANDROID_SSH_CONFIG"] = str(ssh_config_path)
    _route_control_module.subprocess = _PinnedRouteSubprocess(
        native_tool_paths["ssh"],
        ssh_config_path,
        ssh_identity_path,
        ssh_known_hosts_path,
        form_factor_preflight["route_aliases"],
    )
    symbol_evidence = assert_obfuscation_symbol_evidence(
        repo,
        expected_name,
        form_factor_preflight["version_codes"]["phone"],
        form_factor_preflight["version_codes"]["wear"],
        form_factor_preflight["bound_files"],
    )
    root, run_id = secure_evidence_root(
        repo, pathlib.Path(args.output_root).expanduser().absolute()
    )
    output = root / "machine-evidence.json"

    physical_device = _verify_physical_usb_device(
        adb,
        args.serial,
        form_factor_preflight["device_attestation"],
        form_factor_preflight["devicecheck_build_receipt"],
    )
    authorized_device = form_factor_preflight["owner_authorization"]["value"][
        "physical_device"
    ]
    if any(
        physical_device[field] != authorized_device[field]
        for field in ("serial_sha256", "hardware_identity_sha256", "transport")
    ):
        raise CollectorError("live Android physical device is not owner-authorized")

    markers = run_fresh_regression(
        repo, str(native_tool_paths["powershell"]), apk, adb, args.serial,
        physical_device["transport_id"], args.pin,
        args.acknowledge_third_party_security_sheet,
    )
    artifact_sha = sha256_file(apk)
    if markers["APK_SHA256"].lower() != artifact_sha or markers["INSTALLED_BASE_APK_SHA256"].lower() != artifact_sha:
        raise CollectorError("fresh regression APK identity contradicts the exact artifact")
    if markers["APK_ARTIFACT_SIGNER_SHA256"] != EXPECTED_SIGNER or markers["APK_INSTALLED_SIGNER_SHA256"] != EXPECTED_SIGNER:
        raise CollectorError("fresh regression signer does not match the pinned upload identity")
    signature_name, signature_sha = copy_evidence(
        pathlib.Path(markers["APK_SIGNATURE_RECEIPT_PATH"]), root, "apk-signature-receipt.json"
    )
    if signature_sha != markers["APK_SIGNATURE_RECEIPT_SHA256"].lower():
        raise CollectorError("copied APK signature receipt changed")
    startup_name, startup_sha = copy_evidence(
        pathlib.Path(markers["STARTUP_LOGCAT_PATH"]), root, "startup-logcat.txt"
    )
    if startup_sha != markers["STARTUP_LOGCAT_SHA256"].lower():
        raise CollectorError("copied startup logcat changed")

    driver = _TransportBoundAndroidDriver(
        adb,
        args.serial,
        physical_device["transport_id"],
        args.pin,
        pathlib.Path(args.tesseract_support_root).expanduser().absolute(),
    )
    app_version, build_number = package_version(driver, expected_name, expected_code)
    if driver.package != EXPECTED_APPLICATION_ID:
        raise CollectorError("installed Android application id is not the exact release package")
    remote_before = route_snapshot(inventory)
    original_radio = driver.radio_state()
    driver.launch()
    original_double = driver.switch_state("Double VPN")
    original_chrome = driver.split_state(CHROME)
    original_samsung = driver.split_state(SAMSUNG_BROWSER)
    before_control_sha = control_state(
        remote_before["state_sha256"], original_radio, original_double,
        original_chrome, original_samsung,
    )

    active_route: tuple[str, str, int, str, str] | None = None
    lanes: list[dict[str, Any]] = []
    split_evidence: dict[str, Any] | None = None
    leak_evidence: dict[str, Any] | None = None
    network_evidence: dict[str, Any] | None = None
    map_evidence: dict[str, Any] | None = None
    final_teardown: dict[str, Any] | None = None
    route_radio = {"wifi_enabled": False, "mobile_data_enabled": True}
    try:
        # Map evidence is pre-VPN and OCR-derived, never a caller-supplied pass flag.
        map_raw = driver.map_observation(
            root / "map-50-mile.png", native_tool_paths["tesseract"], args.expected_map_city
        )
        map_evidence = _validated_map_visual(
            map_raw, form_factor_preflight["expected_map_city_labels"]
        )
        map_path = pathlib.Path(map_evidence["screenshot_path"]).expanduser().absolute()
        expected_map_path = root / "map-50-mile.png"
        try:
            if map_path.resolve(strict=True) != expected_map_path.resolve(strict=True):
                raise CollectorError("Android map screenshot escaped its exact output path")
            map_size = map_path.stat().st_size
        except OSError as exc:
            raise CollectorError("Android map screenshot is missing") from exc
        _register_evidence_file(
            expected_map_path,
            expected_sha256=map_evidence["screenshot_sha256"],
            expected_size=map_size,
            max_bytes=128 * 1024 * 1024,
        )
        map_evidence["screenshot_path"] = pathlib.Path(map_evidence["screenshot_path"]).name

        chrome_state, split_ui_sha = driver.set_split_package(CHROME, True)
        samsung_state, _ = driver.set_split_package(SAMSUNG_BROWSER, False)
        if not chrome_state or samsung_state:
            raise CollectorError("split selection is not Chrome excluded / Samsung protected")
        driver.set_radio_state(route_radio)
        baseline_ip = driver.browser_public_ip(CHROME, "https://api.ipify.org")
        baseline_digest = sha256_text(baseline_ip)
        if baseline_digest in {EMPTY_SHA256, "0" * 64}:
            raise CollectorError("phone baseline egress identity is a sentinel")

        for mode_name, double_enabled, kind_prefix in (
            ("node", False, ""),
            ("double_vpn", True, "double_vpn_"),
        ):
            mode = inventory[mode_name]
            route_specs = [
                ("direct", mode["direct"]["port"], "none"),
                *[("xray", item["port"], item["security"]) for item in mode["advertised_xray_routes"]],
            ]
            for route_kind, selected_port, security in route_specs:
                driver.launch()
                driver.set_double_vpn(double_enabled)
                source_ip = driver.browser_public_ip(SAMSUNG_BROWSER, "https://api.ipify.org")
                operation_id = uuid.uuid4().hex
                lane_id = (
                    f"{kind_prefix}direct-{selected_port}" if route_kind == "direct"
                    else f"{kind_prefix}xray-{selected_port}-{security}"
                )
                apply_value = route_apply(
                    inventory, mode_name, route_kind, selected_port, security,
                    operation_id, source_ip,
                )
                active_route = (mode_name, route_kind, selected_port, security, operation_id)
                connected = False
                try:
                    driver.connect()
                    connected = True
                    live = driver.observe_connected(expect_xray=route_kind == "xray")
                    remote = route_observe(
                        inventory, mode_name, route_kind, selected_port, security, operation_id
                    )
                    remote_path, remote_sha = receipt(
                        root, f"{lane_id}-remote-observation.json",
                        "winsvpn-android-remote-route-observation-v1",
                        {
                            **{key: remote[key] for key in (
                                "mode", "lane_kind", "selected_protocol", "selected_port",
                                "selected_security", "direct_first_hop_port", "selected_packets",
                                "selected_bytes", "direct_packets", "direct_bytes",
                                "direct_block_packets",
                            )},
                            "route_inventory_sha256": inventory_sha,
                            "mode_xray_manifest_sha256": xray_manifest(mode["advertised_xray_routes"]),
                            "passed": True,
                        },
                    )
                    excluded_digest = None
                    if mode_name == "node" and route_kind == "direct":
                        excluded_ip = driver.browser_public_ip(CHROME, "https://api.ipify.org")
                        excluded_digest = sha256_text(excluded_ip)
                        driver.launch()
                    route_receipt_path, route_receipt_sha = receipt(
                        root, f"{lane_id}-route.json", "winsvpn-android-route-receipt-v1",
                        {
                            "lane_id": lane_id,
                            "protocol": "tcp" if route_kind == "xray" else "udp",
                            "port": selected_port,
                            "direct_first_hop_port": mode["direct"]["port"],
                            "security": security,
                            "double_vpn": double_enabled,
                            "double_vpn_core_id_sha256": mode["core_id_sha256"],
                            "double_vpn_exit_slug_sha256": mode["exit_slug_sha256"],
                            "route_inventory_sha256": inventory_sha,
                            "mode_xray_manifest_sha256": xray_manifest(mode["advertised_xray_routes"]),
                            "remote_observation_sha256": remote_sha,
                            "connected_observed": True,
                        },
                    )
                finally:
                    if connected:
                        residue = driver.disconnect()
                    else:
                        runtime = driver.runtime()
                        if runtime.tun_present or runtime.vpn_service_present:
                            try:
                                residue = driver.disconnect()
                            except Exception:
                                residue = {"tun_absent": False, "vpn_service_absent": False, "xray_absent": False, "passed": False}
                        else:
                            residue = {
                                "tun_absent": True, "vpn_service_absent": True,
                                "xray_absent": not runtime.xray_present, "passed": not runtime.xray_present,
                            }
                    restore_value = route_restore(
                        inventory, mode_name, route_kind, selected_port, security, operation_id
                    )
                    active_route = None
                if restore_value["passed"] is not True or restore_value["before_state_sha256"] != apply_value["before_state_sha256"] or restore_value["after_state_sha256"] != apply_value["before_state_sha256"]:
                    raise CollectorError(f"remote route state did not restore for {lane_id}")
                restore_path, restore_sha = receipt(
                    root, f"{lane_id}-forcing-restore.json",
                    "winsvpn-android-forcing-receipt-v1",
                    {
                        "phase": "restore", "operation_id": str(uuid.UUID(hex=operation_id)),
                        "lane_id": lane_id, "blocked_udp_port": mode["direct"]["port"],
                        "before_state_sha256": apply_value["before_state_sha256"],
                        "after_state_sha256": restore_value["after_state_sha256"],
                        "passed": True,
                    },
                )
                if route_kind == "xray":
                    apply_path, apply_sha = receipt(
                        root, f"{lane_id}-forcing-apply.json",
                        "winsvpn-android-forcing-receipt-v1",
                        {
                            "phase": "apply", "operation_id": str(uuid.UUID(hex=operation_id)),
                            "lane_id": lane_id, "blocked_udp_port": mode["direct"]["port"],
                            "before_state_sha256": apply_value["before_state_sha256"],
                            "applied_state_sha256": apply_value["applied_state_sha256"],
                            "passed": True,
                        },
                    )
                else:
                    apply_path, apply_sha = "", ""
                lane = {
                    "lane_id": lane_id,
                    "kind": (
                        "double_vpn_xray" if double_enabled and route_kind == "xray" else
                        "double_vpn_direct" if double_enabled else route_kind if route_kind == "xray" else "direct_awg"
                    ),
                    "protocol": "tcp" if route_kind == "xray" else "udp",
                    "port": selected_port,
                    "direct_first_hop_port": mode["direct"]["port"],
                    "security": security,
                    "double_vpn": double_enabled,
                    "double_vpn_core_id_sha256": mode["core_id_sha256"],
                    "double_vpn_exit_slug_sha256": mode["exit_slug_sha256"],
                    "route_inventory_sha256": inventory_sha,
                    "mode_xray_manifest_sha256": xray_manifest(mode["advertised_xray_routes"]),
                    "remote_observation_path": remote_path,
                    "remote_observation_sha256": remote_sha,
                    "connected_passed": True,
                    "tunnel_validated": True,
                    "tun_rx_delta": live["tun_rx_delta"],
                    "tun_tx_delta": live["tun_tx_delta"],
                    "protected_egress_sha256": live["protected_egress_sha256"],
                    "xray_process_observed": live["xray_process_observed"],
                    "route_receipt_path": route_receipt_path,
                    "route_receipt_sha256": route_receipt_sha,
                    "forcing": {
                        "required": route_kind == "xray",
                        "blocked_udp_port": mode["direct"]["port"],
                        "apply_passed": route_kind == "xray",
                        "restore_passed": True,
                        "before_state_sha256": apply_value["before_state_sha256"],
                        "after_state_sha256": restore_value["after_state_sha256"],
                        "apply_receipt_path": apply_path,
                        "apply_receipt_sha256": apply_sha,
                        "restore_receipt_path": restore_path,
                        "restore_receipt_sha256": restore_sha,
                    },
                    "residue": residue,
                }
                lanes.append(lane)
                if mode_name == "node" and route_kind == "direct":
                    if excluded_digest != baseline_digest or live["protected_egress_sha256"] == baseline_digest:
                        raise CollectorError("Chrome/Samsung split egress did not diverge truthfully")
                    split_path, split_sha = receipt(
                        root, "split-browser.json", "winsvpn-android-split-browser-receipt-v1",
                        {
                            "excluded_package": CHROME,
                            "protected_package": SAMSUNG_BROWSER,
                            "baseline_egress_sha256": baseline_digest,
                            "excluded_egress_sha256": excluded_digest,
                            "protected_egress_sha256": live["protected_egress_sha256"],
                            "selection_ui_sha256": split_ui_sha,
                            "passed": True,
                        },
                    )
                    split_evidence = {
                        "excluded_package": CHROME, "protected_package": SAMSUNG_BROWSER,
                        "baseline_egress_sha256": baseline_digest,
                        "excluded_egress_sha256": excluded_digest,
                        "protected_egress_sha256": live["protected_egress_sha256"],
                        "selection_receipt_path": split_path,
                        "selection_receipt_sha256": split_sha, "passed": True,
                    }
                    leak_path, leak_sha = receipt(
                        root, "leak.json", "winsvpn-android-leak-receipt-v1",
                        {
                            "dns_servers": live["dns_servers"],
                            "protected_canary_count": live["protected_canary_count"],
                            "dns_leak_passed": live["dns_leak_passed"],
                            "ipv4_leak_passed": live["ipv4_leak_passed"],
                            "ipv6_leak_passed": live["ipv6_leak_passed"],
                        },
                    )
                    leak_evidence = {
                        "dns_servers": live["dns_servers"],
                        "protected_canary_count": live["protected_canary_count"],
                        "dns_leak_passed": live["dns_leak_passed"],
                        "ipv4_leak_passed": live["ipv4_leak_passed"],
                        "ipv6_leak_passed": live["ipv6_leak_passed"],
                        "receipt_path": leak_path, "receipt_sha256": leak_sha,
                    }

        # Network handoff is run without any remote forcing state.
        driver.set_radio_state(original_radio)
        driver.launch(); driver.set_double_vpn(False); driver.connect()
        try:
            network = driver.network_change()
        finally:
            final_teardown = driver.disconnect()
        network["wifi_state_restored"] = driver.radio_state()["wifi_enabled"] == original_radio["wifi_enabled"]
        network["mobile_data_state_restored"] = driver.radio_state()["mobile_data_enabled"] == original_radio["mobile_data_enabled"]
        network["passed"] = all((network["wifi_state_restored"], network["mobile_data_state_restored"]))
        network_path, network_sha = receipt(
            root, "network-change.json", "winsvpn-android-network-change-receipt-v1", network
        )
        network_evidence = {**network, "receipt_path": network_path, "receipt_sha256": network_sha}
    finally:
        if active_route is not None:
            mode_name, route_kind, port, security, operation_id = active_route
            try:
                runtime = driver.runtime()
                if runtime.tun_present or runtime.vpn_service_present:
                    driver.disconnect()
            finally:
                try:
                    route_restore(inventory, mode_name, route_kind, port, security, operation_id)
                except Exception:
                    pass
        try:
            runtime = driver.runtime()
            if runtime.tun_present or runtime.vpn_service_present:
                driver.disconnect()
            driver.set_radio_state(original_radio)
            driver.launch()
            driver.set_split_package(CHROME, original_chrome)
            driver.set_split_package(SAMSUNG_BROWSER, original_samsung)
            driver.set_double_vpn(original_double)
        except Exception as exc:
            raise CollectorError(f"Android test controls failed to restore: {exc}") from exc

    if any(value is None for value in (split_evidence, leak_evidence, network_evidence, map_evidence, final_teardown)):
        raise CollectorError("Android final matrix did not produce every mandatory evidence class")
    remote_after = route_snapshot(inventory)
    after_radio = driver.radio_state()
    driver.launch()
    after_double = driver.switch_state("Double VPN")
    after_chrome = driver.split_state(CHROME)
    after_samsung = driver.split_state(SAMSUNG_BROWSER)
    after_control_sha = control_state(
        remote_after["state_sha256"], after_radio, after_double, after_chrome, after_samsung
    )
    if before_control_sha != after_control_sha:
        raise CollectorError("Android whole-run control state was not restored exactly")
    runtime = driver.runtime()
    teardown_facts = {
        "tun_absent": not runtime.tun_present,
        "vpn_service_absent": not runtime.vpn_service_present,
        "xray_absent": not runtime.xray_present,
        "wifi_state_restored": after_radio["wifi_enabled"] == original_radio["wifi_enabled"],
        "mobile_data_state_restored": after_radio["mobile_data_enabled"] == original_radio["mobile_data_enabled"],
    }
    teardown_facts["passed"] = all(teardown_facts.values())
    teardown_path, teardown_sha = receipt(
        root, "global-teardown.json", "winsvpn-android-global-teardown-receipt-v1", teardown_facts
    )
    rollback_facts = {
        "before_state_sha256": before_control_sha,
        "after_state_sha256": after_control_sha,
        "remote_forcing_absent": remote_after["active_operation_count"] == 0,
        "network_state_restored": after_radio == original_radio,
        "split_state_restored": after_chrome == original_chrome and after_samsung == original_samsung,
        "double_vpn_state_restored": after_double == original_double,
    }
    rollback_facts["passed"] = all(
        value for key, value in rollback_facts.items() if key not in {"before_state_sha256", "after_state_sha256"}
    )
    rollback_path, rollback_sha = receipt(
        root, "global-rollback.json", "winsvpn-android-global-rollback-receipt-v1", rollback_facts
    )

    captured_at_utc = utc_now()
    form_factor_closure = build_form_factor_closure(
        repo,
        root,
        packages,
        symbol_evidence,
        app_version,
        form_factor_preflight,
        captured_at_utc,
    )
    machine = {
        "schema_version": 2, "contract": CONTRACT, "platform": "android",
        "app_version": app_version, "build_number": build_number,
        "artifact_sha256": artifact_sha, "artifact_size_bytes": apk.stat().st_size,
        **form_factor_closure,
        "release_input_index_sha256": inputs.index_sha256,
        "platform_manifest_sha256": inputs.platform_manifest_sha256,
        "artifact_input_fingerprint_sha256": inputs.artifact_input_fingerprint_sha256,
        "build_receipt_sha256": build.sha256,
        "producer_contract_sha256": producer_sha,
        "artifact_signer_sha256": EXPECTED_SIGNER,
        "installed_base_apk_sha256": artifact_sha,
        "installed_base_apk_size_bytes": int(markers["INSTALLED_BASE_APK_SIZE_BYTES"]),
        "installed_signer_sha256": EXPECTED_SIGNER,
        "artifact_signature_receipt_path": signature_name,
        "artifact_signature_receipt_sha256": signature_sha,
        "clean_uninstall_passed": True, "install_passed": True,
        "run_id": str(run_id), "captured_at_utc": captured_at_utc,
        "secret_material_redacted": True,
        "startup": {
            "pid": int(markers["STARTUP_PID"]), "logcat_path": startup_name,
            "logcat_sha256": startup_sha, "fatal_scan_passed": True,
        },
        "direct_awg_port": inventory["node"]["direct"]["port"],
        "double_vpn_direct_port": inventory["double_vpn"]["direct"]["port"],
        "advertised_xray_routes": [
            {key: item[key] for key in ("protocol", "port", "security")}
            for item in inventory["node"]["advertised_xray_routes"]
        ],
        "double_vpn_advertised_xray_routes": [
            {key: item[key] for key in ("protocol", "port", "security")}
            for item in inventory["double_vpn"]["advertised_xray_routes"]
        ],
        "lanes": lanes,
        "split_browser": split_evidence,
        "leak": leak_evidence,
        "map_visual": map_evidence,
        "network_change": network_evidence,
        "teardown": {**teardown_facts, "receipt_path": teardown_path, "receipt_sha256": teardown_sha},
        "rollback": {**rollback_facts, "receipt_path": rollback_path, "receipt_sha256": rollback_sha},
    }
    atomic_json(output, machine)
    _finalize_device_transcript_proof(
        root,
        adb,
        args.serial,
        physical_device,
        form_factor_preflight["device_attestation"],
        form_factor_preflight["devicecheck_build_receipt"],
    )
    index_path, index_sha = create_evidence_index(
        repo,
        root,
        run_id,
        output,
        root / "map-50-mile.png",
        artifact_path=apk,
        release_input_index_path=pathlib.Path(args.release_input_index).expanduser().resolve(),
        inputs=inputs,
        build=build,
        producer_sha256=producer_sha,
    )
    print("ANDROID FINAL EVIDENCE COLLECTOR: PASS")
    print(f"EVIDENCE_RUN_ID={run_id}")
    print(f"EVIDENCE_INDEX_PATH={index_path}")
    print(f"EVIDENCE_INDEX_SHA256={index_sha}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CollectorError, DriverError, RouteControlError) as exc:
        print(f"ANDROID FINAL EVIDENCE COLLECTOR: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
