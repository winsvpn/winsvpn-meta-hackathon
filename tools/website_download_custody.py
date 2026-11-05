#!/usr/bin/env python3
"""Fail-closed custody for public website download publication.

authenticated:true and unkeyed SHA-256 are not authentication. Available
downloads must consume existing platform-gate cryptographic outputs through a
repository-pinned verifier boundary. PENDING and partial platform coverage
exit nonzero and never report PASS. Absent owner or publication evidence stays
PENDING.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
MANIFEST_RELATIVE = Path("web") / "releases" / "downloads.json"
CUSTODY_RELATIVE = Path("web") / "releases" / "download-custody.json"
OWNER_EVIDENCE_RELATIVE = Path("web") / "releases" / "owner-publication-evidence.json"
DOWNLOADS_RELATIVE = Path("web") / "downloads"
REPLAY_RELATIVE = Path("web") / "releases" / "download-custody-consumed.jsonl"
CHALLENGE_RELATIVE = Path("web") / "releases" / "download-custody-challenge.json"
UNSIGNED_WAIVER_RELATIVE = Path("web") / "releases" / "download-unsigned-waiver.json"

MANIFEST_SCHEMA = "winsvpn-download-manifest-v2"
CUSTODY_SCHEMA = "winsvpn-website-download-custody-v1"
OWNER_EVIDENCE_SCHEMA = "winsvpn-website-download-owner-evidence-v1"
PUBLICATION_RECEIPT_SCHEMA = "winsvpn-website-download-publication-receipt-v1"
PUBLICATION_RECEIPT_KIND = "website_download_publication_receipt_v1"
CHALLENGE_SCHEMA = "winsvpn-website-download-custody-challenge-v1"
REPLAY_RECORD_SCHEMA = "winsvpn-website-download-custody-replay-v2"
UNSIGNED_WAIVER_SCHEMA = "winsvpn-website-download-unsigned-waiver-v1"

CANONICAL_RELEASE = "1.0.16+33"
CANONICAL_WEBSITE_RELEASE_ID = "v1.0.16+33"
CANONICAL_VERSION = "1.0.16"
PUBLIC_PACKAGE_IDENTITY = "org.winsvpn.app"
PENDING_STATUS = "verification_pending"
AVAILABLE_STATUS = "available"
# Store-delivered entries (macOS, iOS) that wait for App Store review. They
# carry no URL or artifact metadata, exactly like verification_pending.
STORE_PENDING_STATUS = "store_pending"
FAILED_STATUS = "failed"
PRODUCTION_ORIGIN = "https://winsvpn.org"

MAX_RECEIPT_AGE = timedelta(hours=24)
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_JSON_BYTES = 65536
MAX_SIDECAR_BYTES = 4096
MAX_CHALLENGE_BYTES = 4096
MAX_REPLAY_BYTES = 1_048_576
MAX_VERIFIER_BYTES = 2_000_000
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
# The 1.0.16+33 Linux tarballs inflate to about 96 MiB (x64 100945920 bytes,
# arm64 95744000 bytes). 256 MiB keeps a hard decompression bound with headroom.
MAX_LINUX_UNCOMPRESSED = 256 * 1024 * 1024
MAX_TAR_MEMBERS = 4096
READ_CHUNK = 1024 * 1024

GZIP_MAGIC = b"\x1f\x8b"
ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
ZIP_MAGIC = b"PK\x03\x04"
EM_X86_64 = 62
EM_AARCH64 = 183
PE_AMD64 = 0x8664
PE_ARM64 = 0xAA64
PE32_PLUS_MAGIC = 0x20B
# Inno Setup 7.1.0 ships x86 and x64 setup loaders only. installer/windows/
# winsvpn.iss pins SetupArchitecture=x64, so BOTH website installers are a
# PE32+ x64 loader. The ARM64 installer is that x64 loader around an ARM64
# payload (MinVersion 10.0.22000, ArchitecturesAllowed=arm64); its payload
# architecture is enforced by the producer's Assert-StagedReleasePeMachines
# gate and bound here through the release receipt's toolchain target.
WINDOWS_INSTALLER_LOADER_MACHINE = PE_AMD64

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ISSUANCE_ID = re.compile(r"[0-9a-f]{32}\Z")
FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+()-]{0,180}\Z")
DEBUG_NAME_RE = re.compile(r"(?i)debug")

STALE_ANDROID_DEBUG_PACKAGE = "com.example.wins_vpn"
STALE_ANDROID_DEBUG_SHA256 = (
    "89e8ba316dd2a041bde8d019fd407aebf6250a1840a73c98f053e0b6b4621d0f"
)
STALE_WINDOWS_UNSIGNED_SHA256 = (
    "25cfc27fabf67a937c52704fc3a288f105aa74d99cdd7a23e850389ef83261d3"
)
ANDROID_PUBLIC_SIGNER_SHA256 = (
    "4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee"
)
HISTORICAL_RELEASE_IDS = frozenset(
    {"v1.0.0", "1.0.0", "v1.0.14+29", "1.0.14+29"}
)
WINN_PRIMARY = "winn/3"
WINN_FALLBACK = "winn/1"
WINN_FALLBACK_ORDER = ["awg", "xray"]
WINN_PROVENANCE_KIND = "website_download_winn_provenance_receipt_v1"
WINN_PROVENANCE_SCHEMA = "winsvpn-website-download-winn-provenance-v1"
PRIVACY_RECEIPT_KIND = "release_artifact_privacy_receipt_v1"
PRIVACY_RECEIPT_SCHEMA = "winsvpn-web-download-privacy-receipt-v1"
RELEASE_RECEIPT_KIND = "release_publication_receipt_v1"
RELEASE_RECEIPT_SCHEMA = "winsvpn-web-download-release-receipt-v1"
STALE_ARCHITECTURE_LABELS = {
    "windows": frozenset(
        {"x86", "x86_64", "amd64", "i386", "i686", "aarch64", "arm", "win32", "ia32"}
    ),
    "android": frozenset(
        {"armeabi", "x86", "mips", "mips64", "arm64", "armv7", "armv8"}
    ),
    "linux": frozenset(
        {
            "x86_64",
            "amd64",
            "aarch64",
            "i386",
            "i686",
            "armhf",
            "armv7",
            "arm64-v8a",
        }
    ),
    "macos": frozenset({"x64", "amd64", "aarch64", "x86", "i386"}),
    "ios": frozenset({"x86_64", "x64", "armv7", "arm64e", "i386"}),
}

# One manifest entry per architecture (owner ruling 2026-10-25). Each tuple is
# (entry id, public label, delivery kind). The entry id names the platform and,
# for Windows and Linux, the single architecture that entry may publish.
PLATFORM_CONTRACT = (
    ("windows-x64", "Windows x64", "direct"),
    ("windows-arm64", "Windows ARM64", "direct"),
    ("android", "Android", "direct"),
    ("linux-x64", "Linux x64", "direct"),
    ("linux-arm64", "Linux ARM64", "direct"),
    ("macos", "MacBook (macOS)", "store"),
    ("ios", "iPhone (iOS)", "store"),
)
PLATFORM_IDS = tuple(item[0] for item in PLATFORM_CONTRACT)
PLATFORM_TARGETS = {
    "windows-x64": "windows",
    "windows-arm64": "windows",
    "android": "android",
    "linux-x64": "linux",
    "linux-arm64": "linux",
    "macos": "macos",
    "ios": "ios",
}
ENTRY_ARCHITECTURES = {
    "windows-x64": "x64",
    "windows-arm64": "arm64",
    "linux-x64": "x64",
    "linux-arm64": "arm64",
}
PLATFORM_ARCHITECTURES = {
    "windows": frozenset({"x64", "arm64"}),
    "android": frozenset({"arm64-v8a", "armeabi-v7a", "x86_64"}),
    "linux": frozenset({"x64", "arm64"}),
    "macos": frozenset({"arm64", "x86_64"}),
    "ios": frozenset({"arm64"}),
}
CANONICAL_FILENAMES = {
    "windows-x64": "WinsVPN-Setup.exe",
    "windows-arm64": "WinsVPN-Setup-arm64.exe",
    "android": "wins-vpn-android.apk",
    "linux-x64": "wins-vpn-linux-x64.tar.gz",
    "linux-arm64": "wins-vpn-linux-arm64.tar.gz",
}
# Owner ruling 2026-10-21 "Ship unsigned": the 1.0.16+33 Windows installers ship
# without Authenticode. They are published under the producer's own unsigned
# output names (installer/windows/winsvpn.iss, AllowUnsignedLocal branch), so the
# filename itself says UNSIGNED and is never renamed to a signed-release name.
UNSIGNED_CANONICAL_FILENAMES = {
    "windows-x64": "WinsVPN-UNSIGNED-LOCAL-Setup.exe",
    "windows-arm64": "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe",
}
UNSIGNED_SIGNATURE_KIND = "unsigned_owner_waiver"
UNSIGNED_PUBLIC_LABEL = "Unsigned"
UNSIGNED_WAIVER_PLATFORM = "windows"
UNSIGNED_WAIVER_ARCHITECTURES = ["x64", "arm64"]
UNSIGNED_WAIVER_RULING_MARKER = 'Windows: "Ship unsigned"'
UNSIGNED_WAIVER_PUBLIC_REFERENCE = "unsigned-windows-v1.0.16+33"
UNSIGNED_PUBLIC_RULING_KEYS = frozenset({"reference"})
UNSIGNED_WAIVER_KEYS = frozenset({"label", "waiver_filename", "waiver_sha256"})
UNSIGNED_WAIVER_DOCUMENT_KEYS = frozenset(
    {
        "schema",
        "release_id",
        "canonical_release",
        "platform",
        "entries",
        "architectures",
        "public_label",
        "user_notice",
        "owner_ruling",
    }
)
OWNER_RULING_KEYS = frozenset({"record", "record_sha256", "lines"})
# Large direct artifacts are served from Cloudflare R2 through the Worker's
# manifest gate under an immutable content-addressed key.
R2_OBJECT_PREFIX = "downloads/sha256/"
# Owner update 2026-10-25: the account is on Workers Free, so for 1.0.16+33 the
# desktop binaries are hosted as assets of one pinned public GitHub release.
# Git allows "+" in a tag, but "+" in a URL path is decoded as a space by some
# handlers and GitHub links then need %2B, so the tag uses "-33" instead of
# "+33". Only this exact owner/repo/tag prefix is publication authority; every
# other GitHub URL stays backup-only.
GITHUB_RELEASE_OWNER_REPO = "winsvpn/winsvpn-downloads"
GITHUB_RELEASE_TAG = "v1.0.16-33"
GITHUB_RELEASE_PREFIX = (
    f"https://github.com/{GITHUB_RELEASE_OWNER_REPO}/releases/download/{GITHUB_RELEASE_TAG}/"
)
GITHUB_RELEASE_ENTRIES = frozenset({"windows-x64", "windows-arm64", "linux-x64", "linux-arm64"})
GITHUB_HOSTING_RULING_MARKER = GITHUB_RELEASE_OWNER_REPO


def github_release_url(filename: str) -> str:
    return f"{GITHUB_RELEASE_PREFIX}{filename}"

PENDING_BLOCKERS = (
    "Windows x64 artifact absent: https://winsvpn.org/downloads/WinsVPN-Setup.exe with WinVerifyTrust receipt WinsVPN-Setup.exe.authenticode.json, production signer, SHA-256 sidecar, and privacy/release/winn/publication receipts, or the owner-waived unsigned https://winsvpn.org/downloads/WinsVPN-UNSIGNED-LOCAL-Setup.exe labelled Unsigned by download-unsigned-waiver.json",
    "Windows arm64 artifact absent: https://winsvpn.org/downloads/WinsVPN-Setup-arm64.exe with matching Authenticode signer/hash/provenance receipts, or the owner-waived unsigned https://winsvpn.org/downloads/WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe labelled Unsigned",
    (
        "Android artifact absent: https://winsvpn.org/downloads/wins-vpn-android.apk "
        "signed by production upload certificate "
        f"{ANDROID_PUBLIC_SIGNER_SHA256} for org.winsvpn.app 1.0.16+33; "
        "forbidden debug package com.example.wins_vpn digest "
        f"{STALE_ANDROID_DEBUG_SHA256}"
    ),
    "Linux x64 artifact absent: https://winsvpn.org/downloads/wins-vpn-linux-x64.tar.gz with Cosign/sigstore and privacy/release/winn/publication receipts",
    "Linux arm64 artifact absent: https://winsvpn.org/downloads/wins-vpn-linux-arm64.tar.gz with Cosign/sigstore and privacy/release/winn/publication receipts",
    "macOS store URL absent: production apps.apple.com listing after the Apple cross-store gate; no direct unsigned package (store_pending)",
    "iOS store URL absent: production apps.apple.com listing after the Apple cross-store gate; no direct unsigned package (store_pending)",
    "owner-publication-evidence.json and verifier-issued one-use challenge absent",
    "Worker download redirect table must stay empty; GitHub and placeholder 302s are not publication authority",
)
DIRECT_FILENAME_ARCH = {
    "WinsVPN-Setup.exe": ("windows", "x64"),
    "WinsVPN-Setup-arm64.exe": ("windows", "arm64"),
    "WinsVPN-UNSIGNED-LOCAL-Setup.exe": ("windows", "x64"),
    "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe": ("windows", "arm64"),
    "wins-vpn-android.apk": ("android", None),
    "wins-vpn-linux-x64.tar.gz": ("linux", "x64"),
    "wins-vpn-linux-arm64.tar.gz": ("linux", "arm64"),
}
SIGNATURE_KINDS = {
    "windows": "authenticode_signer_certificate_sha256",
    "android": "apk_signer_certificate_sha256",
    "linux": "publication_signature_sha256",
    "macos": "publication_signature_sha256",
    "ios": "publication_signature_sha256",
}
WEBSITE_AUDIT_RELATIVE = "tools/website_security_audit.py"
LINUX_GATE_RELATIVE = "tools/linux_cross_store_artifact_gate.py"
WINDOWS_GATE_RELATIVE = "tools/windows_cross_store_artifact_gate.py"
APPLE_GATE_RELATIVE = "tools/apple_cross_store_artifact_gate.py"
LINUX_SIGNING_RELATIVE = "tools/linux_release_signing.py"
TRUSTED_COSIGN_KEY_RELATIVE = "linux/packaging/release-signing/cosign.pub"
VERIFIER_FILES = (
    WEBSITE_AUDIT_RELATIVE,
    LINUX_GATE_RELATIVE,
    WINDOWS_GATE_RELATIVE,
    APPLE_GATE_RELATIVE,
    LINUX_SIGNING_RELATIVE,
)

MANIFEST_ROOT_KEYS = frozenset({"schema", "release_id", "artifacts"})
MANIFEST_ENTRY_KEYS = frozenset({"id", "label", "status", "delivery", "artifact"})
DELIVERY_KEYS = frozenset({"kind", "url"})
PENDING_ARTIFACT_KEYS = frozenset({"filename", "sha256", "bytes"})
AVAILABLE_ARTIFACT_KEYS = frozenset(
    {
        "filename",
        "sha256",
        "bytes",
        "canonical_release",
        "package_identity",
        "version",
        "architecture",
        "signature",
        "winn_provenance",
        "privacy",
        "release_receipt",
        "publication_receipt",
    }
)
SIGNATURE_KEYS = frozenset({"kind", "sha256"})
RECEIPT_BINDING_KEYS = frozenset({"kind", "receipt_filename", "receipt_sha256"})
WINDOWS_VERIFICATION_KEYS = frozenset(
    {
        "kind",
        "receipt_filename",
        "receipt_sha256",
        "approved_signer_subject",
        "approved_signer_certificate_sha256",
    }
)
WINN_BINDING_KEYS = frozenset(
    {
        "kind",
        "receipt_filename",
        "receipt_sha256",
        "primary",
        "fallback",
        "fallback_order",
    }
)
# Every hosted receipt carries one evidence object derived from the real build
# records (see tools/website_download_publication.py). The identity keys alone
# only restate the artifact; the evidence keys say which record proved what.
PRIVACY_EVIDENCE_KEY = "scan"
RELEASE_EVIDENCE_KEY = "build"
WINN_EVIDENCE_KEY = "engine_release"
PRIVACY_SCAN_KEYS = frozenset(
    {
        "contract",
        "record_filename",
        "record_sha256",
        "result",
        "matched_labels",
        "inventory_revision",
        "inventory_sha256",
        "label_count",
        "target_id",
    }
)
PRIVACY_SCAN_CONTRACTS = frozenset(
    {
        "winsvpn-release-host-secret-scan-v2",
        "winsvpn-release-artifact-privacy-scan-text-v1",
    }
)
RELEASE_BUILD_KEYS = frozenset(
    {
        "receipt_contract",
        "receipt_filename",
        "receipt_sha256",
        "shared_revision",
        "producer_path",
        "producer_sha256",
        "toolchain_target",
        "signing",
        "remote_machine",
        "source_artifact_name",
        "finished_utc",
    }
)
BUILD_RECEIPT_CONTRACT = "winsvpn-build-receipt-v1"
WINN_ENGINE_KEYS = frozenset(
    {
        "manifest_sha256",
        "signature_public_key",
        "verified_by",
        "source_commit",
        "tree_sha256",
        "targets",
        "binding",
    }
)
WINN_RELEASE_VERIFIER = "tools/winn_release.py verify"
WINN_AUTHORITY_RELATIVE = "tools/winn_release_authority.json"
WINN_MEASURED_BINDING_KEYS = frozenset({"kind", "member", "sha256", "target"})
WINN_LOG_BINDING_KEYS = frozenset({"kind", "log_filename", "log_sha256", "line"})
GOARCH_BY_ARCH = {"x64": "amd64", "arm64": "arm64"}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HOSTED_IDENTITY_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "kind",
        "canonical_release",
        "platform_id",
        "artifact_filename",
        "artifact_sha256",
        "artifact_bytes",
        "package_identity",
        "architecture",
        "version",
    }
)
PRIVACY_RECEIPT_KEYS = HOSTED_IDENTITY_RECEIPT_KEYS | frozenset({PRIVACY_EVIDENCE_KEY})
RELEASE_RECEIPT_KEYS = HOSTED_IDENTITY_RECEIPT_KEYS | frozenset({RELEASE_EVIDENCE_KEY})
WINN_RECEIPT_KEYS = HOSTED_IDENTITY_RECEIPT_KEYS | frozenset(
    {"primary", "fallback", "fallback_order", WINN_EVIDENCE_KEY}
)
CUSTODY_KEYS = frozenset(
    {
        "schema",
        "release_id",
        "canonical_release",
        "package_identity",
        "status",
        "owner_evidence_filename",
        "platforms",
        "forbidden_android_debug_package",
        "forbidden_android_debug_sha256",
        "forbidden_windows_unsigned_sha256",
        "winn_primary",
        "winn_fallback",
        "winn_fallback_order",
        "production_origin",
        "canonical_filenames",
        "unsigned_canonical_filenames",
        "unsigned_waiver_filename",
        "r2_object_prefix",
        "github_release_prefix",
        "verifier_boundary",
        "replay_log_filename",
        "challenge_filename",
    }
)
OWNER_EVIDENCE_KEYS = frozenset(
    {
        "schema",
        "issued_utc",
        "issuance_id",
        "canonical_release",
        "package_identity",
        "challenge_nonce",
        "owner_ruling",
        "platforms",
    }
)
OWNER_PUBLICATION_RULING_MARKER = 'Website downloads: "Publish now"'
OWNER_PLATFORM_KEYS = frozenset(
    {
        "id",
        "target",
        "version",
        "architecture",
        "artifact_filename",
        "artifact_sha256",
        "artifact_bytes",
        "signature_kind",
        "signature_sha256",
        "nonce",
        "receipt_filename",
    }
)
PUBLICATION_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "kind",
        "issuance_id",
        "issued_utc",
        "nonce",
        "canonical_release",
        "package_identity",
        "platform_id",
        "target",
        "version",
        "architecture",
        "artifact_filename",
        "artifact_sha256",
        "artifact_bytes",
        "signature_kind",
        "signature_sha256",
        "challenge_nonce",
        "owner_evidence_sha256",
    }
)
CHALLENGE_KEYS = frozenset(
    {
        "schema",
        "nonce",
        "issued_utc",
        "canonical_release",
        "package_identity",
    }
)
REPLAY_RECORD_KEYS = frozenset(
    {
        "schema",
        "issuance_id",
        "nonce",
        "challenge_nonce",
        "owner_evidence_sha256",
        "artifact_sha256",
        "consumed_utc",
    }
)
REPLAY_RECORD_KEYS_V1 = REPLAY_RECORD_KEYS - {"owner_evidence_sha256"}

_PINNED_MODULES: dict[str, Any] = {}

# Durable owner-controlled release ledger (Arbiter decision 2026-10-25, review
# DLP-04 / Argon F-2): a fixed path outside every clone that records each
# consumed challenge, issuance and owner evidence digest, so a challenge copied
# into another clone cannot publish twice. Tests may point it elsewhere only
# through WINS_RELEASE_LEDGER.
RELEASE_LEDGER_DEFAULT = Path(
    "/Users/owner/.winsvpn-release-ledger/download-custody-consumed.jsonl"
)
RELEASE_LEDGER_ENV = "WINS_RELEASE_LEDGER"
RELEASE_LEDGER_SCHEMA = "winsvpn-website-download-release-ledger-v1"
RELEASE_LEDGER_KEYS = frozenset(
    {
        "schema",
        "canonical_release",
        "issuance_id",
        "challenge_nonce",
        "owner_evidence_sha256",
        "nonces",
        "artifact_sha256s",
        "consumed_utc",
    }
)
MAX_RELEASE_LEDGER_BYTES = 4 * 1024 * 1024


class WebsiteDownloadCustodyError(RuntimeError):
    """Fail-closed website download custody refusal."""


class CustodyReport:
    def __init__(
        self, ok: bool, status: str, summary: str, findings: tuple[str, ...]
    ) -> None:
        self.ok = ok
        self.status = status
        self.summary = summary
        self.findings = findings


class OpenedRelative:
    """An already-open regular file plus the bytes read from that descriptor."""

    def __init__(self, fd: int, data: bytes, info: os.stat_result) -> None:
        self.fd = fd
        self.data = data
        self.info = info

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def parse_utc(value: object, label: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise WebsiteDownloadCustodyError(f"{label} timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise WebsiteDownloadCustodyError(f"{label} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise WebsiteDownloadCustodyError(f"{label} timestamp is invalid")
    return parsed.astimezone(timezone.utc)


def require_fresh(created: datetime, label: str, *, now: datetime) -> None:
    if created.year < 2026:
        raise WebsiteDownloadCustodyError(f"{label} is stale")
    if created > now + MAX_CLOCK_SKEW or now - created > MAX_RECEIPT_AGE:
        raise WebsiteDownloadCustodyError(f"{label} is stale or future-dated")


def require_hex64(value: object, label: str) -> str:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        raise WebsiteDownloadCustodyError(f"{label} must be 64 lowercase hex characters")
    return value


def require_issuance_id(value: object, label: str) -> str:
    if type(value) is not str or ISSUANCE_ID.fullmatch(value) is None:
        raise WebsiteDownloadCustodyError(f"{label} must be 32 lowercase hex characters")
    return value


def require_filename(value: object, label: str) -> str:
    if type(value) is not str or FILENAME_RE.fullmatch(value) is None:
        raise WebsiteDownloadCustodyError(f"{label} is invalid")
    if "/" in value or "\\" in value or ".." in value:
        raise WebsiteDownloadCustodyError(f"{label} escapes the downloads directory")
    if DEBUG_NAME_RE.search(value):
        raise WebsiteDownloadCustodyError(f"{label} names a debug artifact")
    return value


def require_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise WebsiteDownloadCustodyError(f"{label} must be a JSON integer")
    if value < 1:
        raise WebsiteDownloadCustodyError(f"{label} must be a positive byte count")
    return value


def require_exact_keys(payload: dict[str, Any], keys: frozenset[str], label: str) -> None:
    if set(payload) != keys:
        raise WebsiteDownloadCustodyError(f"{label} does not have its exact schema")


def refuse_self_asserted_authenticated(payload: dict[str, Any], label: str) -> None:
    if "authenticated" in payload:
        raise WebsiteDownloadCustodyError(
            f"{label} self-asserted authenticated:true is not cryptographic authentication"
        )


def require_nofollow() -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC"):
        raise WebsiteDownloadCustodyError(
            "descriptor-anchored O_NOFOLLOW reads are required"
        )
    if not hasattr(os, "O_DIRECTORY"):
        raise WebsiteDownloadCustodyError(
            "descriptor-anchored O_DIRECTORY reads are required"
        )


def require_replay_locking() -> None:
    require_nofollow()
    if not hasattr(fcntl, "flock") or not hasattr(fcntl, "LOCK_EX"):
        raise WebsiteDownloadCustodyError("interprocess replay locking is required")


def _dir_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
    )


def _inode_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid)


def _open_flags(*, directory: bool = False) -> int:
    require_nofollow()
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def _relative_parts(relative: str, label: str) -> tuple[str, ...]:
    parts = Path(relative).parts
    if Path(relative).is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise WebsiteDownloadCustodyError(f"{label} path is not a canonical relative path")
    if any("/" in part or "\\" in part or "\x00" in part for part in parts):
        raise WebsiteDownloadCustodyError(f"{label} path is not a canonical relative path")
    return parts


def _require_root_owned(
    info: os.stat_result,
    root_info: os.stat_result,
    label: str,
    *,
    directory: bool,
) -> None:
    if info.st_uid != root_info.st_uid:
        raise WebsiteDownloadCustodyError(f"{label} is not root-owned")
    if info.st_mode & 0o022:
        raise WebsiteDownloadCustodyError(f"{label} is group/other-writable")
    if directory:
        return
    if stat.S_IMODE(info.st_mode) & 0o177:
        raise WebsiteDownloadCustodyError(f"{label} must use mode 0600 or stricter")


def _pread_exact(fd: int, size: int, label: str) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        block = os.pread(fd, min(READ_CHUNK, size - offset), offset)
        if not block:
            break
        chunks.append(block)
        offset += len(block)
    data = b"".join(chunks)
    if len(data) != size:
        raise WebsiteDownloadCustodyError(f"{label} was replaced during descriptor read")
    return data


def _write_all(fd: int, data: bytes, label: str) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise WebsiteDownloadCustodyError(f"{label} write was truncated")
        view = view[written:]


def immutable_descriptor_path(fd: int, label: str) -> str:
    if fd < 0:
        raise WebsiteDownloadCustodyError(f"{label} descriptor is closed")
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode):
        raise WebsiteDownloadCustodyError(f"{label} descriptor is not a regular file")
    if Path("/proc/self/fd").is_dir():
        path = f"/proc/self/fd/{fd}"
    elif Path("/dev/fd").exists():
        path = f"/dev/fd/{fd}"
    else:
        raise WebsiteDownloadCustodyError(
            f"{label} requires an immutable descriptor path"
        )
    probe = -1
    try:
        probe = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        probed = os.fstat(probe)
        if (probed.st_dev, probed.st_ino) != (opened.st_dev, opened.st_ino):
            raise WebsiteDownloadCustodyError(
                f"{label} immutable descriptor path does not match the open file"
            )
    except OSError as exc:
        raise WebsiteDownloadCustodyError(
            f"{label} immutable descriptor path is unavailable"
        ) from exc
    finally:
        if probe >= 0:
            os.close(probe)
    return path


def _open_root_fd(root: Path, label: str) -> tuple[int, os.stat_result]:
    require_nofollow()
    try:
        root_before = os.lstat(root)
    except OSError as exc:
        raise WebsiteDownloadCustodyError(f"{label} root is missing") from exc
    if stat.S_ISLNK(root_before.st_mode):
        raise WebsiteDownloadCustodyError(f"{label} root is a symlink")
    if not stat.S_ISDIR(root_before.st_mode):
        raise WebsiteDownloadCustodyError(f"{label} root is missing")
    root_fd = os.open(root, _open_flags(directory=True))
    try:
        root_after = os.fstat(root_fd)
        if _dir_identity(root_before) != _dir_identity(root_after):
            raise WebsiteDownloadCustodyError(f"{label} root was replaced")
        return root_fd, root_after
    except Exception:
        os.close(root_fd)
        raise


def _open_child(
    parent_fd: int,
    name: str,
    flags: int,
    label: str,
    *,
    directory: bool,
) -> tuple[int, os.stat_result]:
    if name in {"", ".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise WebsiteDownloadCustodyError(f"{label} path is not a canonical relative path")
    try:
        child = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise WebsiteDownloadCustodyError(f"{label} is missing") from exc
    if stat.S_ISLNK(child.st_mode):
        raise WebsiteDownloadCustodyError(f"{label} is a symlink")
    if directory:
        if not stat.S_ISDIR(child.st_mode):
            raise WebsiteDownloadCustodyError(f"{label} is missing")
    else:
        if not stat.S_ISREG(child.st_mode):
            raise WebsiteDownloadCustodyError(f"{label} is a symlink")
        if child.st_nlink != 1:
            raise WebsiteDownloadCustodyError(
                f"{label} must have exactly one filesystem link"
            )
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise WebsiteDownloadCustodyError(f"{label} is missing") from exc
    try:
        opened = os.fstat(fd)
        if directory:
            if _dir_identity(child) != _dir_identity(opened):
                raise WebsiteDownloadCustodyError(f"{label} path was replaced")
        else:
            if _file_identity(child) != _file_identity(opened):
                raise WebsiteDownloadCustodyError(f"{label} was replaced")
            if opened.st_nlink != 1:
                raise WebsiteDownloadCustodyError(
                    f"{label} must have exactly one filesystem link"
                )
        return fd, opened
    except Exception:
        os.close(fd)
        raise


def _reject_duplicate_keys(pairs: list[tuple[str, object]], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WebsiteDownloadCustodyError(f"{label} has a duplicate JSON key")
        result[key] = value
    return result


def decode_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WebsiteDownloadCustodyError(f"{label} is not ASCII JSON") from exc
    try:
        payload = json.loads(
            text,
            object_pairs_hook=lambda pairs: _reject_duplicate_keys(pairs, label),
        )
    except json.JSONDecodeError as exc:
        raise WebsiteDownloadCustodyError(f"{label} is invalid JSON: {exc}") from exc
    if type(payload) is not dict:
        raise WebsiteDownloadCustodyError(f"{label} must be a JSON object")
    refuse_self_asserted_authenticated(payload, label)
    return payload


def open_nofollow_file(
    root: Path, relative: str, label: str, *, max_bytes: int
) -> OpenedRelative:
    parts = _relative_parts(relative, label)
    current_fd = -1
    file_fd = -1
    try:
        current_fd, _root_info = _open_root_fd(root, label)
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            if last:
                child_fd, opened = _open_child(
                    current_fd, part, _open_flags(), label, directory=False
                )
                file_fd = child_fd
                if opened.st_size > max_bytes:
                    raise WebsiteDownloadCustodyError(f"{label} exceeds {max_bytes} bytes")
                data = _pread_exact(file_fd, opened.st_size, label)
                final = os.fstat(file_fd)
                if _file_identity(opened) != _file_identity(final) or len(data) != opened.st_size:
                    raise WebsiteDownloadCustodyError(
                        f"{label} was replaced during descriptor read"
                    )
                owned = OpenedRelative(file_fd, data, final)
                file_fd = -1
                return owned
            next_fd, _next_info = _open_child(
                current_fd, part, _open_flags(directory=True), label, directory=True
            )
            os.close(current_fd)
            current_fd = next_fd
        raise WebsiteDownloadCustodyError(f"{label} is missing")
    except Exception:
        if file_fd >= 0:
            os.close(file_fd)
        raise
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def read_nofollow_relative(
    root: Path, relative: str, label: str, *, max_bytes: int
) -> bytes:
    opened = open_nofollow_file(root, relative, label, max_bytes=max_bytes)
    try:
        return opened.data
    finally:
        opened.close()


def read_nofollow_optional(
    root: Path, relative: str, label: str, *, max_bytes: int
) -> bytes | None:
    try:
        return read_nofollow_relative(root, relative, label, max_bytes=max_bytes)
    except WebsiteDownloadCustodyError as exc:
        message = str(exc)
        if message.endswith(" is missing") or message.endswith(" root is missing"):
            return None
        raise


def load_json_object(
    root: Path, relative: str, label: str, *, max_bytes: int = MAX_JSON_BYTES
) -> dict[str, Any]:
    raw = read_nofollow_relative(root, relative, label, max_bytes=max_bytes)
    return decode_json_object(raw, label)


def pinned_verifier_digests() -> dict[str, str]:
    pins: dict[str, str] = {}
    for relative in VERIFIER_FILES:
        data = read_nofollow_relative(
            ROOT, relative, relative, max_bytes=MAX_VERIFIER_BYTES
        )
        pins[relative] = sha256_bytes(data)
    return pins


def pending_custody_document() -> dict[str, Any]:
    return {
        "schema": CUSTODY_SCHEMA,
        "release_id": CANONICAL_WEBSITE_RELEASE_ID,
        "canonical_release": CANONICAL_RELEASE,
        "package_identity": PUBLIC_PACKAGE_IDENTITY,
        "status": PENDING_STATUS,
        "owner_evidence_filename": None,
        "platforms": list(PLATFORM_IDS),
        "forbidden_android_debug_package": STALE_ANDROID_DEBUG_PACKAGE,
        "forbidden_android_debug_sha256": STALE_ANDROID_DEBUG_SHA256,
        "forbidden_windows_unsigned_sha256": STALE_WINDOWS_UNSIGNED_SHA256,
        "winn_primary": WINN_PRIMARY,
        "winn_fallback": WINN_FALLBACK,
        "winn_fallback_order": list(WINN_FALLBACK_ORDER),
        "production_origin": PRODUCTION_ORIGIN,
        "canonical_filenames": dict(CANONICAL_FILENAMES),
        "unsigned_canonical_filenames": dict(UNSIGNED_CANONICAL_FILENAMES),
        "unsigned_waiver_filename": UNSIGNED_WAIVER_RELATIVE.name,
        "r2_object_prefix": R2_OBJECT_PREFIX,
        "github_release_prefix": GITHUB_RELEASE_PREFIX,
        "verifier_boundary": list(VERIFIER_FILES),
        "replay_log_filename": REPLAY_RELATIVE.name,
        "challenge_filename": CHALLENGE_RELATIVE.name,
    }


def load_pinned_module(relative: str, expected_digest: str) -> Any:
    cached = _PINNED_MODULES.get(relative)
    if cached is not None:
        return cached
    data = read_nofollow_relative(
        ROOT, relative, relative, max_bytes=MAX_VERIFIER_BYTES
    )
    digest = sha256_bytes(data)
    if digest != expected_digest:
        raise WebsiteDownloadCustodyError(
            f"{relative} does not match the pinned verifier boundary"
        )
    origin = (ROOT / relative).resolve(strict=True)
    module_name = "winsvpn_website_pin_" + relative.replace("/", "_").replace(".", "_")
    spec = importlib.util.spec_from_file_location(module_name, origin)
    if spec is None or spec.loader is None:
        raise WebsiteDownloadCustodyError(f"{relative} could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    loaded = Path(getattr(module, "__file__", "")).resolve()
    if loaded != origin:
        raise WebsiteDownloadCustodyError(f"{relative} loaded from an unexpected path")
    again = read_nofollow_relative(
        ROOT, relative, relative, max_bytes=MAX_VERIFIER_BYTES
    )
    if sha256_bytes(again) != expected_digest:
        raise WebsiteDownloadCustodyError(f"{relative} was replaced after the pin check")
    _PINNED_MODULES[relative] = module
    return module


def production_direct_url(filename: str) -> str:
    return f"{PRODUCTION_ORIGIN}/downloads/{filename}"


def architecture_errors(platform_id: str, architecture: object, label: str) -> list[str]:
    allowed = PLATFORM_ARCHITECTURES[platform_id]
    if type(architecture) is not list or not architecture:
        return [f"{label} architecture is missing"]
    if any(type(item) is not str for item in architecture):
        return [f"{label} architecture is invalid"]
    if len(architecture) != len(set(architecture)):
        return [f"{label} architecture contains duplicates"]
    stale = STALE_ARCHITECTURE_LABELS[platform_id]
    if any(item in stale for item in architecture):
        return [f"{label} pins a stale architecture artifact"]
    if any(item not in allowed for item in architecture):
        return [f"{label} architecture is not an allowed {platform_id} architecture"]
    if platform_id == "android" and set(architecture) != allowed:
        return [f"{label} architecture inventory is not the exact current Android ABI set"]
    if platform_id == "windows" and len(architecture) != 1:
        return [f"{label} architecture must bind exactly one current Windows installer architecture"]
    if platform_id == "linux" and len(architecture) != 1:
        return [f"{label} architecture must bind exactly one current Linux architecture"]
    if platform_id == "macos" and set(architecture) != allowed:
        return [f"{label} architecture inventory is not the exact current macOS set"]
    if platform_id == "ios" and architecture != ["arm64"]:
        return [f"{label} architecture inventory is not the exact current iOS set"]
    return []


def entry_architecture_errors(entry_id: str, architecture: object, label: str) -> list[str]:
    platform_id = PLATFORM_TARGETS[entry_id]
    errors = architecture_errors(platform_id, architecture, label)
    if errors:
        return errors
    expected = ENTRY_ARCHITECTURES.get(entry_id)
    if expected is not None and architecture != [expected]:
        return [f"{label} architecture does not match its {entry_id} manifest entry"]
    return []


def refuse_forbidden_identity(
    *,
    digest: str,
    package_identity: object,
    canonical_release: object,
    signature_sha256: object,
    prefix: str,
) -> list[str]:
    errors: list[str] = []
    if digest == STALE_ANDROID_DEBUG_SHA256:
        errors.append(f"{prefix} pins the stale Android debug APK digest")
    if digest == STALE_WINDOWS_UNSIGNED_SHA256:
        errors.append(f"{prefix} pins the stale unsigned Windows installer digest")
    if package_identity == STALE_ANDROID_DEBUG_PACKAGE:
        errors.append(f"{prefix} uses the stale Android debug application ID")
    if canonical_release in HISTORICAL_RELEASE_IDS:
        errors.append(f"{prefix} substitutes a historical release identity")
    if signature_sha256 in {STALE_ANDROID_DEBUG_SHA256, STALE_WINDOWS_UNSIGNED_SHA256}:
        errors.append(f"{prefix} substitutes a stale unsigned or debug signature")
    if type(signature_sha256) is str and signature_sha256 == digest:
        errors.append(
            f"{prefix} unkeyed artifact digest is not cryptographic authentication"
        )
    return errors


def pending_entry_errors(
    entry: dict[str, Any],
    platform_id: str,
    label: str,
    status: str = PENDING_STATUS,
) -> list[str]:
    delivery = entry.get("delivery")
    artifact = entry.get("artifact")
    if type(delivery) is not dict or type(artifact) is not dict:
        return [f"{label} delivery/artifact metadata missing"]
    errors: list[str] = []
    if set(delivery) != DELIVERY_KEYS:
        errors.append(f"{label} pending delivery is outside the closed JSON schema")
    expected_kind = next(kind for item, _name, kind in PLATFORM_CONTRACT if item == platform_id)
    if status == STORE_PENDING_STATUS and expected_kind != "store":
        errors.append(f"{label} store_pending is valid only for an app-store entry")
    if delivery.get("kind") == "github_release":
        errors.append(
            f"{label} GitHub is backup-only and is not website publication authority"
        )
    elif delivery.get("kind") != expected_kind:
        errors.append(f"{label} pending delivery kind is invalid")
    if delivery.get("url") is not None:
        errors.append(f"{label} pending entry contains release metadata")
    url = delivery.get("url")
    if type(url) is str and (
        "/releases/latest/" in url or "/releases/download/latest/" in url
    ):
        errors.append(f"{label} delivery URL is a mutable latest-release route")
    if set(artifact) != PENDING_ARTIFACT_KEYS:
        errors.append(f"{label} pending artifact is outside the closed JSON schema")
        return errors
    if any(artifact.get(field) is not None for field in ("filename", "sha256", "bytes")):
        errors.append(f"{label} pending entry contains release metadata")
    return errors


def canonical_filename_for(
    entry_id: str, architecture: object, *, unsigned: bool = False
) -> str | None:
    if entry_id not in PLATFORM_TARGETS:
        return None
    if entry_id == "android":
        return None if unsigned else CANONICAL_FILENAMES["android"]
    if entry_id in {"macos", "ios"}:
        return None
    expected_arch = ENTRY_ARCHITECTURES.get(entry_id)
    if type(architecture) is not list or architecture != [expected_arch]:
        return None
    if unsigned:
        return UNSIGNED_CANONICAL_FILENAMES.get(entry_id)
    return CANONICAL_FILENAMES.get(entry_id)


def artifact_is_unsigned_waiver(artifact: dict[str, Any]) -> bool:
    signature = artifact.get("signature")
    return type(signature) is dict and signature.get("kind") == UNSIGNED_SIGNATURE_KIND


def expected_available_artifact_keys(entry_id: str, *, unsigned: bool = False) -> frozenset[str]:
    keys = set(AVAILABLE_ARTIFACT_KEYS)
    if PLATFORM_TARGETS.get(entry_id) == "windows":
        keys.add("unsigned_waiver" if unsigned else "windows_verification")
    return frozenset(keys)


def unsigned_waiver_binding_errors(
    artifact: dict[str, Any], prefix: str
) -> list[str]:
    binding = artifact.get("unsigned_waiver")
    if type(binding) is not dict or set(binding) != UNSIGNED_WAIVER_KEYS:
        return [f"{prefix} unsigned Windows download requires a manifest-bound owner waiver"]
    errors: list[str] = []
    if binding.get("label") != UNSIGNED_PUBLIC_LABEL:
        errors.append(f"{prefix} unsigned Windows download must be labelled Unsigned")
    if binding.get("waiver_filename") != UNSIGNED_WAIVER_RELATIVE.name:
        errors.append(f"{prefix} unsigned waiver filename is not the release waiver")
    try:
        waiver_sha256 = require_hex64(
            binding.get("waiver_sha256"), f"{prefix} unsigned waiver SHA-256"
        )
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
        return errors
    signature = artifact.get("signature")
    if type(signature) is not dict or signature.get("sha256") != waiver_sha256:
        errors.append(f"{prefix} unsigned signature is not bound to the owner waiver")
    return errors


def load_unsigned_waiver(root: Path) -> tuple[dict[str, Any], str]:
    raw = read_nofollow_relative(
        root,
        UNSIGNED_WAIVER_RELATIVE.as_posix(),
        "unsigned Windows owner waiver",
        max_bytes=MAX_JSON_BYTES,
    )
    payload = decode_json_object(raw, "unsigned Windows owner waiver")
    require_exact_keys(payload, UNSIGNED_WAIVER_DOCUMENT_KEYS, "unsigned Windows owner waiver")
    if payload.get("schema") != UNSIGNED_WAIVER_SCHEMA:
        raise WebsiteDownloadCustodyError("unsupported unsigned Windows owner waiver schema")
    if (
        payload.get("release_id") != CANONICAL_WEBSITE_RELEASE_ID
        or payload.get("canonical_release") != CANONICAL_RELEASE
    ):
        raise WebsiteDownloadCustodyError(
            "unsigned Windows owner waiver is not scoped to the current 1.0.16+33 release"
        )
    if payload.get("platform") != UNSIGNED_WAIVER_PLATFORM:
        raise WebsiteDownloadCustodyError("unsigned owner waiver covers only Windows")
    entries = payload.get("entries")
    if type(entries) is not list or not entries or any(
        entry not in UNSIGNED_CANONICAL_FILENAMES for entry in entries
    ) or len(set(entries)) != len(entries):
        raise WebsiteDownloadCustodyError("unsigned owner waiver entries are invalid")
    if payload.get("architectures") != [ENTRY_ARCHITECTURES[entry] for entry in entries]:
        raise WebsiteDownloadCustodyError(
            "unsigned owner waiver architectures do not match its entries"
        )
    if payload.get("public_label") != UNSIGNED_PUBLIC_LABEL:
        raise WebsiteDownloadCustodyError("unsigned owner waiver public label must be Unsigned")
    notice = payload.get("user_notice")
    if type(notice) is not str or "unsigned" not in notice.lower() or len(notice) > 512:
        raise WebsiteDownloadCustodyError("unsigned owner waiver user notice is invalid")
    ruling = payload.get("owner_ruling")
    if type(ruling) is not dict or set(ruling) != UNSIGNED_PUBLIC_RULING_KEYS:
        raise WebsiteDownloadCustodyError("unsigned owner waiver ruling reference is invalid")
    if ruling.get("reference") != UNSIGNED_WAIVER_PUBLIC_REFERENCE:
        raise WebsiteDownloadCustodyError("unsigned owner waiver lacks the public waiver reference")
    return payload, sha256_bytes(raw)


def owner_ruling_errors(
    ruling: object, label: str, *, required_marker: str
) -> list[str]:
    if type(ruling) is not dict or set(ruling) != OWNER_RULING_KEYS:
        return [f"{label} does not cite its recorded owner ruling"]
    record = ruling.get("record")
    if type(record) is not str or not record.endswith(".md") or "/" in record or len(record) > 200:
        return [f"{label} owner ruling record name is invalid"]
    if type(ruling.get("record_sha256")) is not str or HEX64.fullmatch(
        ruling.get("record_sha256")
    ) is None:
        return [f"{label} owner ruling record SHA-256 is invalid"]
    lines = ruling.get("lines")
    if (
        type(lines) is not list
        or not lines
        or len(lines) > 8
        or any(type(line) is not str or not line or len(line) > 1024 for line in lines)
    ):
        return [f"{label} owner ruling lines are invalid"]
    if not any(required_marker in line for line in lines):
        return [f"{label} does not quote the owner ruling {required_marker}"]
    return []


def windows_verification_binding_errors(
    artifact: dict[str, Any], filename: str, prefix: str
) -> list[str]:
    verification = artifact.get("windows_verification")
    if type(verification) is not dict or set(verification) != WINDOWS_VERIFICATION_KEYS:
        return [f"{prefix} requires a manifest-bound WinVerifyTrust receipt"]
    errors: list[str] = []
    if verification.get("kind") != "winverifytrust_receipt_v1":
        errors.append(f"{prefix} WinVerifyTrust receipt kind is invalid")
    if verification.get("receipt_filename") != f"{filename}.authenticode.json":
        errors.append(
            f"{prefix} WinVerifyTrust receipt filename is not bound to the artifact"
        )
    try:
        require_hex64(
            verification.get("receipt_sha256"),
            f"{prefix} WinVerifyTrust receipt SHA-256",
        )
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
    subject = verification.get("approved_signer_subject")
    if type(subject) is not str or not subject.strip() or len(subject) > 512:
        errors.append(f"{prefix} WinVerifyTrust approved signer subject is invalid")
    try:
        approved = require_hex64(
            verification.get("approved_signer_certificate_sha256"),
            f"{prefix} WinVerifyTrust approved signer SHA-256",
        )
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
        return errors
    signature = artifact.get("signature")
    if type(signature) is dict and signature.get("sha256") != approved:
        errors.append(f"{prefix} signature does not match the WinVerifyTrust signer")
    return errors


def available_artifact_schema_errors(
    entry_id: str, artifact: dict[str, Any], prefix: str
) -> list[str]:
    errors: list[str] = []
    platform_id = PLATFORM_TARGETS[entry_id]
    unsigned = artifact_is_unsigned_waiver(artifact)
    digest = artifact.get("sha256") if type(artifact.get("sha256")) is str else ""
    signature = artifact.get("signature") if type(artifact.get("signature")) is dict else {}
    errors.extend(
        refuse_forbidden_identity(
            digest=digest.lower() if type(digest) is str else "",
            package_identity=artifact.get("package_identity"),
            canonical_release=artifact.get("canonical_release"),
            signature_sha256=signature.get("sha256") if type(signature) is dict else None,
            prefix=prefix,
        )
    )
    if unsigned and platform_id != UNSIGNED_WAIVER_PLATFORM:
        errors.append(f"{prefix} only Windows may ship under the unsigned owner waiver")
        return errors
    if set(artifact) != expected_available_artifact_keys(entry_id, unsigned=unsigned):
        errors.append(
            f"{prefix} available artifact is missing current signed-release custody metadata"
        )
        return errors
    try:
        filename = require_filename(artifact.get("filename"), f"{prefix} filename")
        digest = require_hex64(artifact.get("sha256"), f"{prefix} SHA-256")
        require_int(artifact.get("bytes"), f"{prefix} byte count")
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
        filename = artifact.get("filename") if type(artifact.get("filename")) is str else ""
        digest = artifact.get("sha256") if type(artifact.get("sha256")) is str else ""
    if artifact.get("canonical_release") != CANONICAL_RELEASE:
        errors.append(f"{prefix} is not bound to the current 1.0.16+33 release")
    if artifact.get("package_identity") != PUBLIC_PACKAGE_IDENTITY:
        errors.append(f"{prefix} package identity is not the production org.winsvpn.app identity")
    if artifact.get("version") != CANONICAL_VERSION:
        errors.append(f"{prefix} version is not the current 1.0.16 identity")
    errors.extend(entry_architecture_errors(entry_id, artifact.get("architecture"), prefix))
    expected_name = canonical_filename_for(
        entry_id, artifact.get("architecture"), unsigned=unsigned
    )
    if expected_name is None:
        errors.append(f"{prefix} canonical target filename cannot be derived")
    elif filename != expected_name:
        errors.append(f"{prefix} filename is not the exact canonical target filename")
    bound = DIRECT_FILENAME_ARCH.get(filename) if filename else None
    if bound is not None and bound[0] != platform_id:
        errors.append(f"{prefix} canonical filename belongs to another platform")
    if bound is not None and bound[1] is not None:
        architecture = artifact.get("architecture")
        if type(architecture) is list and architecture != [bound[1]]:
            errors.append(f"{prefix} architecture label does not match the canonical filename")
    signature = artifact.get("signature")
    if type(signature) is not dict or set(signature) != SIGNATURE_KEYS:
        errors.append(f"{prefix} signature binding is incomplete")
        return errors
    expected_kind = UNSIGNED_SIGNATURE_KIND if unsigned else SIGNATURE_KINDS[platform_id]
    try:
        signer = require_hex64(signature.get("sha256"), f"{prefix} signature SHA-256")
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
        return errors
    if signature.get("kind") != expected_kind:
        errors.append(f"{prefix} signature kind is not the current signed-release kind")
    if type(digest) is str and signer == digest:
        errors.append(
            f"{prefix} unkeyed artifact digest is not cryptographic authentication"
        )
    errors.extend(
        hosted_receipt_binding_errors(
            artifact.get("privacy"),
            filename,
            PRIVACY_RECEIPT_KIND,
            ".privacy.json",
            prefix,
            "privacy",
        )
    )
    errors.extend(
        hosted_receipt_binding_errors(
            artifact.get("release_receipt"),
            filename,
            RELEASE_RECEIPT_KIND,
            ".release.json",
            prefix,
            "release",
        )
    )
    errors.extend(winn_provenance_binding_errors(artifact.get("winn_provenance"), filename, prefix))
    if platform_id == "windows":
        if unsigned:
            errors.extend(unsigned_waiver_binding_errors(artifact, prefix))
        else:
            errors.extend(windows_verification_binding_errors(artifact, filename, prefix))
    receipt = artifact.get("publication_receipt")
    if type(receipt) is not dict or set(receipt) != RECEIPT_BINDING_KEYS:
        errors.append(f"{prefix} requires a manifest-bound publication receipt")
        return errors
    if receipt.get("kind") != PUBLICATION_RECEIPT_KIND:
        errors.append(f"{prefix} publication receipt kind is invalid")
    expected_receipt_name = f"{filename}.publication.json" if filename else ""
    if receipt.get("receipt_filename") != expected_receipt_name:
        errors.append(f"{prefix} publication receipt filename is not bound to the artifact")
    try:
        require_hex64(receipt.get("receipt_sha256"), f"{prefix} publication receipt SHA-256")
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
    return errors


def hosted_receipt_binding_errors(
    binding: object,
    filename: str,
    expected_kind: str,
    suffix: str,
    prefix: str,
    label: str,
) -> list[str]:
    if type(binding) is not dict or set(binding) != RECEIPT_BINDING_KEYS:
        return [f"{prefix} requires a manifest-bound {label} receipt"]
    if binding.get("kind") != expected_kind:
        return [f"{prefix} {label} receipt kind is invalid"]
    if binding.get("receipt_filename") != f"{filename}{suffix}":
        return [f"{prefix} {label} receipt filename is not bound to the artifact"]
    try:
        require_hex64(binding.get("receipt_sha256"), f"{prefix} {label} receipt SHA-256")
    except WebsiteDownloadCustodyError as exc:
        return [str(exc)]
    return []


def winn_provenance_binding_errors(binding: object, filename: str, prefix: str) -> list[str]:
    if type(binding) is not dict or set(binding) != WINN_BINDING_KEYS:
        return [f"{prefix} requires a manifest-bound Winn provenance receipt"]
    errors: list[str] = []
    if binding.get("kind") != WINN_PROVENANCE_KIND:
        errors.append(f"{prefix} Winn provenance receipt kind is invalid")
    if binding.get("primary") != WINN_PRIMARY:
        errors.append(f"{prefix} Winn primary is not winn/3")
    if binding.get("fallback") != WINN_FALLBACK:
        errors.append(f"{prefix} Winn fallback is not winn/1")
    if binding.get("fallback_order") != WINN_FALLBACK_ORDER:
        errors.append(f"{prefix} Winn v1 fallback order is not AWG then Xray")
    if binding.get("receipt_filename") != f"{filename}.winn.json":
        errors.append(f"{prefix} Winn provenance receipt filename is not bound to the artifact")
    try:
        require_hex64(binding.get("receipt_sha256"), f"{prefix} Winn provenance receipt SHA-256")
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
    return errors


def load_manifest(root: Path) -> dict[str, Any]:
    payload = load_json_object(root, MANIFEST_RELATIVE.as_posix(), "download manifest")
    require_exact_keys(payload, MANIFEST_ROOT_KEYS, "download manifest")
    if payload.get("schema") != MANIFEST_SCHEMA:
        raise WebsiteDownloadCustodyError("unsupported download manifest schema")
    release_id = payload.get("release_id")
    if release_id in HISTORICAL_RELEASE_IDS:
        raise WebsiteDownloadCustodyError(
            "download manifest substitutes a historical release identity"
        )
    if release_id != CANONICAL_WEBSITE_RELEASE_ID:
        raise WebsiteDownloadCustodyError(
            "release_id is not the current 1.0.16+33 website release"
        )
    entries = payload.get("artifacts")
    if type(entries) is not list or len(entries) != len(PLATFORM_CONTRACT):
        raise WebsiteDownloadCustodyError(
            f"manifest must contain exactly {len(PLATFORM_CONTRACT)} per-architecture artifacts"
        )
    return payload


def load_custody_metadata(root: Path) -> dict[str, Any]:
    payload = load_json_object(
        root, CUSTODY_RELATIVE.as_posix(), "website download custody metadata"
    )
    require_exact_keys(payload, CUSTODY_KEYS, "website download custody metadata")
    if payload.get("schema") != CUSTODY_SCHEMA:
        raise WebsiteDownloadCustodyError("unsupported website download custody schema")
    if payload.get("release_id") != CANONICAL_WEBSITE_RELEASE_ID:
        raise WebsiteDownloadCustodyError(
            "custody metadata release_id is not the current 1.0.16+33 website release"
        )
    if payload.get("canonical_release") != CANONICAL_RELEASE:
        raise WebsiteDownloadCustodyError(
            "custody metadata is not bound to the current 1.0.16+33 release"
        )
    if payload.get("package_identity") != PUBLIC_PACKAGE_IDENTITY:
        raise WebsiteDownloadCustodyError(
            "custody metadata package identity is not org.winsvpn.app"
        )
    if payload.get("platforms") != list(PLATFORM_IDS):
        raise WebsiteDownloadCustodyError("custody metadata platform order is invalid")
    if payload.get("forbidden_android_debug_package") != STALE_ANDROID_DEBUG_PACKAGE:
        raise WebsiteDownloadCustodyError("custody metadata dropped the debug package refusal")
    if payload.get("forbidden_android_debug_sha256") != STALE_ANDROID_DEBUG_SHA256:
        raise WebsiteDownloadCustodyError("custody metadata dropped the debug APK digest refusal")
    if payload.get("forbidden_windows_unsigned_sha256") != STALE_WINDOWS_UNSIGNED_SHA256:
        raise WebsiteDownloadCustodyError(
            "custody metadata dropped the unsigned Windows digest refusal"
        )
    if payload.get("winn_primary") != WINN_PRIMARY:
        raise WebsiteDownloadCustodyError(
            "custody metadata dropped the Winn v3 primary pin"
        )
    if payload.get("winn_fallback") != WINN_FALLBACK:
        raise WebsiteDownloadCustodyError(
            "custody metadata dropped the Winn v1 fallback pin"
        )
    if payload.get("winn_fallback_order") != WINN_FALLBACK_ORDER:
        raise WebsiteDownloadCustodyError(
            "custody metadata dropped the Winn v1 AWG-then-Xray fallback order"
        )
    if payload.get("production_origin") != PRODUCTION_ORIGIN:
        raise WebsiteDownloadCustodyError(
            "custody metadata production origin is not the exact winsvpn.org origin"
        )
    if payload.get("canonical_filenames") != CANONICAL_FILENAMES:
        raise WebsiteDownloadCustodyError(
            "custody metadata canonical filenames are not the exact target names"
        )
    if payload.get("unsigned_canonical_filenames") != UNSIGNED_CANONICAL_FILENAMES:
        raise WebsiteDownloadCustodyError(
            "custody metadata unsigned filenames are not the exact producer names"
        )
    if payload.get("unsigned_waiver_filename") != UNSIGNED_WAIVER_RELATIVE.name:
        raise WebsiteDownloadCustodyError(
            "custody metadata unsigned waiver filename is invalid"
        )
    if payload.get("r2_object_prefix") != R2_OBJECT_PREFIX:
        raise WebsiteDownloadCustodyError(
            "custody metadata R2 object prefix is not the content-addressed prefix"
        )
    if payload.get("github_release_prefix") != GITHUB_RELEASE_PREFIX:
        raise WebsiteDownloadCustodyError(
            "custody metadata GitHub release prefix is not the pinned v1.0.16-33 release"
        )
    pins = payload.get("verifier_boundary")
    if pins != list(VERIFIER_FILES):
        raise WebsiteDownloadCustodyError(
            "custody metadata verifier boundary is not the repository-pinned verifier set"
        )
    status = payload.get("status")
    if status not in {PENDING_STATUS, AVAILABLE_STATUS}:
        raise WebsiteDownloadCustodyError("custody metadata status is invalid")
    owner_name = payload.get("owner_evidence_filename")
    if status == PENDING_STATUS:
        if owner_name is not None:
            raise WebsiteDownloadCustodyError(
                "pending custody metadata must not name owner publication evidence"
            )
    elif owner_name != OWNER_EVIDENCE_RELATIVE.name:
        raise WebsiteDownloadCustodyError(
            "available custody metadata must name owner-publication-evidence.json"
        )
    if payload.get("replay_log_filename") != REPLAY_RELATIVE.name:
        raise WebsiteDownloadCustodyError("custody metadata replay log filename is invalid")
    if payload.get("challenge_filename") != CHALLENGE_RELATIVE.name:
        raise WebsiteDownloadCustodyError("custody metadata challenge filename is invalid")
    return payload


def load_challenge(root: Path, *, now: datetime) -> dict[str, Any]:
    payload = load_json_object(
        root,
        CHALLENGE_RELATIVE.as_posix(),
        "verifier-issued one-use challenge",
        max_bytes=MAX_CHALLENGE_BYTES,
    )
    require_exact_keys(payload, CHALLENGE_KEYS, "verifier-issued one-use challenge")
    if payload.get("schema") != CHALLENGE_SCHEMA:
        raise WebsiteDownloadCustodyError("unsupported verifier challenge schema")
    issued = parse_utc(payload.get("issued_utc"), "verifier challenge issued_utc")
    require_fresh(issued, "verifier challenge issued_utc", now=now)
    require_issuance_id(payload.get("nonce"), "verifier challenge nonce")
    if payload.get("canonical_release") != CANONICAL_RELEASE:
        raise WebsiteDownloadCustodyError("verifier challenge is not the current release")
    if payload.get("package_identity") != PUBLIC_PACKAGE_IDENTITY:
        raise WebsiteDownloadCustodyError("verifier challenge package identity is invalid")
    return payload


def _parse_replay_records(raw: bytes) -> dict[tuple[str, str, str], dict[str, Any]]:
    records: dict[tuple[str, str, str], dict[str, Any]] = {}
    challenge_owners: dict[str, tuple[str, str]] = {}
    if not raw:
        return records
    if not raw.endswith(b"\n"):
        raise WebsiteDownloadCustodyError("download custody replay log is truncated")
    for line in raw.split(b"\n"):
        if not line:
            continue
        record = decode_json_object(line, "download custody replay record")
        schema = record.get("schema")
        if schema == "winsvpn-website-download-custody-replay-v1":
            require_exact_keys(record, REPLAY_RECORD_KEYS_V1, "download custody replay record")
            owner_digest = None
        elif schema == REPLAY_RECORD_SCHEMA:
            require_exact_keys(record, REPLAY_RECORD_KEYS, "download custody replay record")
            owner_digest = require_hex64(
                record.get("owner_evidence_sha256"), "replay owner evidence SHA-256"
            )
        else:
            raise WebsiteDownloadCustodyError("unsupported download custody replay record")
        issuance_id = require_issuance_id(
            record.get("issuance_id"), "replay issuance_id"
        )
        nonce = require_issuance_id(record.get("nonce"), "replay nonce")
        challenge_nonce = require_issuance_id(
            record.get("challenge_nonce"), "replay challenge nonce"
        )
        require_hex64(record.get("artifact_sha256"), "replay artifact SHA-256")
        owner_key = (issuance_id, owner_digest)
        if challenge_nonce in challenge_owners and challenge_owners[challenge_nonce] != owner_key:
            raise WebsiteDownloadCustodyError("download custody challenge was reused by another issuance")
        challenge_owners[challenge_nonce] = owner_key
        key = (issuance_id, nonce, challenge_nonce)
        if key in records:
            raise WebsiteDownloadCustodyError("download custody replay log contains a replay")
        records[key] = record
    return records


def load_replay_log(root: Path) -> dict[tuple[str, str, str], dict[str, Any]]:
    raw = read_nofollow_optional(
        root,
        REPLAY_RELATIVE.as_posix(),
        "download custody replay log",
        max_bytes=MAX_REPLAY_BYTES,
    )
    if raw is None:
        return {}
    return _parse_replay_records(raw)


def _require_replay_file(info: os.stat_result, root_info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise WebsiteDownloadCustodyError("download custody replay log is not a regular file")
    _require_root_owned(info, root_info, "download custody replay log", directory=False)


def _open_replay_journal(root: Path) -> tuple[int, int, int, os.stat_result, os.stat_result]:
    require_replay_locking()
    parts = _relative_parts(REPLAY_RELATIVE.as_posix(), "download custody replay log")
    if len(parts) < 2:
        raise WebsiteDownloadCustodyError(
            "download custody replay log path is not a canonical relative path"
        )
    dir_parts = parts[:-1]
    journal_name = parts[-1]
    root_fd = -1
    parent_fd = -1
    journal_fd = -1
    try:
        root_fd, root_info = _open_root_fd(root, "download custody replay log")
        _require_root_owned(
            root_info, root_info, "download custody replay log root", directory=True
        )
        parent_fd = os.dup(root_fd)
        for part in dir_parts:
            child_fd, child_info = _open_child(
                parent_fd,
                part,
                _open_flags(directory=True),
                "download custody replay log",
                directory=True,
            )
            _require_root_owned(
                child_info, root_info, "download custody replay log", directory=True
            )
            os.close(parent_fd)
            parent_fd = child_fd
        parent_info = os.fstat(parent_fd)
        _require_root_owned(
            parent_info, root_info, "download custody replay log", directory=True
        )
        create_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            journal_fd = os.open(journal_name, create_flags, 0o600, dir_fd=parent_fd)
            os.fchmod(journal_fd, 0o600)
            os.fsync(journal_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            journal_fd = os.open(
                journal_name,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        info = os.fstat(journal_fd)
        named = os.stat(journal_name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or info.st_nlink != 1
            or _inode_identity(info) != (named.st_dev, named.st_ino, named.st_uid)
        ):
            raise WebsiteDownloadCustodyError(
                "download custody replay log is not a regular file"
            )
        _require_replay_file(info, root_info)
        owned_journal = journal_fd
        owned_parent = parent_fd
        owned_root = root_fd
        journal_fd = -1
        parent_fd = -1
        root_fd = -1
        return owned_journal, owned_parent, owned_root, root_info, parent_info
    except OSError as exc:
        raise WebsiteDownloadCustodyError(
            f"download custody replay log could not be consumed: {exc}"
        ) from exc
    finally:
        if journal_fd >= 0:
            os.close(journal_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        if root_fd >= 0:
            os.close(root_fd)


def release_ledger_path() -> Path:
    override = os.environ.get(RELEASE_LEDGER_ENV, "")
    return Path(override) if override else RELEASE_LEDGER_DEFAULT


def _inside_git_work_tree(directory: Path) -> bool:
    for candidate in (directory, *directory.parents):
        try:
            os.lstat(candidate / ".git")
            return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def _open_release_ledger(*, create: bool) -> tuple[int, Path] | None:
    """Open (and on first use create) the ledger with its custody checks."""
    require_replay_locking()
    path = release_ledger_path()
    if not path.is_absolute() or path.name != "download-custody-consumed.jsonl":
        raise WebsiteDownloadCustodyError("release ledger path is not an absolute ledger file")
    directory = path.parent
    try:
        directory_info = os.lstat(directory)
    except FileNotFoundError:
        if not create:
            return None
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise WebsiteDownloadCustodyError(f"release ledger directory cannot be created: {exc}") from exc
        directory_info = os.lstat(directory)
    if stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(directory_info.st_mode):
        raise WebsiteDownloadCustodyError("release ledger directory is a symlink or not a directory")
    if stat.S_IMODE(directory_info.st_mode) != 0o700 or directory_info.st_uid != os.getuid():
        raise WebsiteDownloadCustodyError("release ledger directory must be owner-only mode 0700")
    if _inside_git_work_tree(Path(os.path.realpath(directory))):
        raise WebsiteDownloadCustodyError("release ledger must live outside every git work tree")
    dir_fd = os.open(directory, _open_flags(directory=True))
    try:
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_APPEND
        try:
            fd = os.open(path.name, flags, dir_fd=dir_fd)
        except FileNotFoundError:
            if not create:
                return None
            try:
                fd = os.open(path.name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=dir_fd)
                os.fsync(fd)
                os.fsync(dir_fd)
            except FileExistsError:
                fd = os.open(path.name, flags, dir_fd=dir_fd)
        info = os.fstat(fd)
        named = os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid()
        ):
            os.close(fd)
            raise WebsiteDownloadCustodyError(
                "release ledger must be one owner-only regular file (mode 0600)"
            )
        return fd, path
    except OSError as exc:
        raise WebsiteDownloadCustodyError(f"release ledger cannot be opened: {exc}") from exc
    finally:
        os.close(dir_fd)


def _parse_release_ledger(raw: bytes) -> list[dict[str, Any]]:
    if raw and not raw.endswith(b"\n"):
        raise WebsiteDownloadCustodyError("release ledger is truncated")
    records: list[dict[str, Any]] = []
    for line in raw.split(b"\n"):
        if not line:
            continue
        record = decode_json_object(line, "release ledger record")
        require_exact_keys(record, RELEASE_LEDGER_KEYS, "release ledger record")
        if record.get("schema") != RELEASE_LEDGER_SCHEMA:
            raise WebsiteDownloadCustodyError("unsupported release ledger record")
        require_issuance_id(record.get("issuance_id"), "release ledger issuance_id")
        require_issuance_id(record.get("challenge_nonce"), "release ledger challenge nonce")
        require_hex64(record.get("owner_evidence_sha256"), "release ledger owner evidence SHA-256")
        nonces = record.get("nonces")
        digests = record.get("artifact_sha256s")
        if type(nonces) is not list or type(digests) is not list or not nonces:
            raise WebsiteDownloadCustodyError("release ledger record lists are invalid")
        for nonce in nonces:
            require_issuance_id(nonce, "release ledger nonce")
        for digest in digests:
            require_hex64(digest, "release ledger artifact SHA-256")
        records.append(record)
    return records


def release_ledger_records() -> list[dict[str, Any]]:
    """Read the ledger without creating it; a parse error always refuses."""
    opened = _open_release_ledger(create=False)
    if opened is None:
        return []
    fd, _path = opened
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        size = os.fstat(fd).st_size
        if size > MAX_RELEASE_LEDGER_BYTES:
            raise WebsiteDownloadCustodyError("release ledger exceeds its size bound")
        return _parse_release_ledger(_pread_exact(fd, size, "release ledger") if size else b"")
    finally:
        os.close(fd)


def release_ledger_conflict(records: list[dict[str, Any]], *, challenge_nonce: str, issuance_id: str, nonces: list[str]) -> bool:
    for record in records:
        if record["challenge_nonce"] == challenge_nonce or record["issuance_id"] == issuance_id:
            return True
        if set(record["nonces"]) & set(nonces):
            return True
    return False


def consume_release_ledger(
    *,
    issuance_id: str,
    challenge_nonce: str,
    owner_evidence_sha256: str,
    nonces: list[str],
    artifact_sha256s: list[str],
    now: datetime,
) -> None:
    """Lock the durable ledger across the check and the fsync'd append."""
    opened = _open_release_ledger(create=True)
    if opened is None:
        raise WebsiteDownloadCustodyError("release ledger could not be created")
    fd, _path = opened
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        size = os.fstat(fd).st_size
        if size > MAX_RELEASE_LEDGER_BYTES:
            raise WebsiteDownloadCustodyError("release ledger exceeds its size bound")
        records = _parse_release_ledger(_pread_exact(fd, size, "release ledger") if size else b"")
        if release_ledger_conflict(
            records, challenge_nonce=challenge_nonce, issuance_id=issuance_id, nonces=nonces
        ):
            raise WebsiteDownloadCustodyError(
                "owner publication evidence nonce or challenge was already consumed "
                "(durable release ledger)"
            )
        record = {
            "schema": RELEASE_LEDGER_SCHEMA,
            "canonical_release": CANONICAL_RELEASE,
            "issuance_id": issuance_id,
            "challenge_nonce": challenge_nonce,
            "owner_evidence_sha256": owner_evidence_sha256,
            "nonces": list(nonces),
            "artifact_sha256s": list(artifact_sha256s),
            "consumed_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        line = canonical_json(record) + b"\n"
        try:
            _write_all(fd, line, "release ledger")
            os.fsync(fd)
        except Exception:
            try:
                os.ftruncate(fd, size)
                os.fsync(fd)
            except OSError:
                pass
            raise
        after = os.fstat(fd).st_size
        again = _parse_release_ledger(_pread_exact(fd, after, "release ledger"))
        if not any(item["challenge_nonce"] == challenge_nonce for item in again):
            raise WebsiteDownloadCustodyError("release ledger consumption did not persist")
    except OSError as exc:
        raise WebsiteDownloadCustodyError(f"release ledger could not be consumed: {exc}") from exc
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def consume_replay(
    root: Path,
    *,
    issuance_id: str,
    nonce: str,
    challenge_nonce: str,
    owner_evidence_sha256: str,
    artifact_sha256: str,
    now: datetime,
) -> None:
    key = (issuance_id, nonce, challenge_nonce)
    record = {
        "schema": REPLAY_RECORD_SCHEMA,
        "issuance_id": issuance_id,
        "nonce": nonce,
        "challenge_nonce": challenge_nonce,
        "owner_evidence_sha256": owner_evidence_sha256,
        "artifact_sha256": artifact_sha256,
        "consumed_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    line = canonical_json(record) + b"\n"
    journal_fd = -1
    parent_fd = -1
    root_fd = -1
    locked = False
    try:
        journal_fd, parent_fd, root_fd, root_info, parent_info = _open_replay_journal(root)
        fcntl.flock(journal_fd, fcntl.LOCK_EX)
        locked = True
        root_after = os.fstat(root_fd)
        parent_after = os.fstat(parent_fd)
        if _dir_identity(root_after) != _dir_identity(root_info):
            raise WebsiteDownloadCustodyError("download custody replay log root was replaced")
        if _dir_identity(parent_after) != _dir_identity(parent_info):
            raise WebsiteDownloadCustodyError("download custody replay log path was replaced")
        info = os.fstat(journal_fd)
        named = os.stat(REPLAY_RELATIVE.name, dir_fd=parent_fd, follow_symlinks=False)
        if _inode_identity(info) != (named.st_dev, named.st_ino, named.st_uid):
            raise WebsiteDownloadCustodyError("download custody replay log was replaced")
        _require_replay_file(info, root_info)
        if info.st_size > MAX_REPLAY_BYTES:
            raise WebsiteDownloadCustodyError(
                f"download custody replay log exceeds {MAX_REPLAY_BYTES} bytes"
            )
        raw = _pread_exact(journal_fd, info.st_size, "download custody replay log") if info.st_size else b""
        records = _parse_replay_records(raw)
        # One challenge serves exactly one owner evidence document (Sol DLP-04,
        # Argon F-2); a nonce or issuance never reappears under another key.
        if key in records or any(
            (
                item["challenge_nonce"] == challenge_nonce and (
                    item["schema"] != REPLAY_RECORD_SCHEMA or
                    item["issuance_id"] != issuance_id or
                    item["owner_evidence_sha256"] != owner_evidence_sha256
                )
            )
            or item["nonce"] == nonce
            or (item["issuance_id"] == issuance_id and item["challenge_nonce"] != challenge_nonce)
            for item in records.values()
        ):
            raise WebsiteDownloadCustodyError(
                "owner publication evidence nonce or challenge was already consumed"
            )
        start = info.st_size
        os.lseek(journal_fd, 0, os.SEEK_END)
        try:
            _write_all(journal_fd, line, "download custody replay log")
            os.fsync(journal_fd)
            os.fsync(parent_fd)
        except Exception:
            try:
                os.ftruncate(journal_fd, start)
                os.fsync(journal_fd)
            except OSError:
                pass
            raise
        after = os.fstat(journal_fd)
        if _inode_identity(after) != _inode_identity(info):
            raise WebsiteDownloadCustodyError("download custody replay log was replaced")
        _require_replay_file(after, root_info)
        if after.st_size > MAX_REPLAY_BYTES:
            raise WebsiteDownloadCustodyError(
                f"download custody replay log exceeds {MAX_REPLAY_BYTES} bytes"
            )
        again_raw = _pread_exact(journal_fd, after.st_size, "download custody replay log")
        again = _parse_replay_records(again_raw)
        if key not in again:
            raise WebsiteDownloadCustodyError("download custody replay consumption did not persist")
        if list(again).count(key) != 1:
            raise WebsiteDownloadCustodyError(
                "owner publication evidence nonce or challenge was already consumed"
            )
    except WebsiteDownloadCustodyError:
        raise
    except OSError as exc:
        raise WebsiteDownloadCustodyError(
            f"download custody replay log could not be consumed: {exc}"
        ) from exc
    finally:
        if locked and journal_fd >= 0:
            try:
                fcntl.flock(journal_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        if journal_fd >= 0:
            os.close(journal_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        if root_fd >= 0:
            os.close(root_fd)


def load_owner_evidence(root: Path, *, now: datetime) -> tuple[dict[str, Any], str]:
    raw = read_nofollow_relative(
        root,
        OWNER_EVIDENCE_RELATIVE.as_posix(),
        "owner publication evidence",
        max_bytes=MAX_JSON_BYTES,
    )
    payload = decode_json_object(raw, "owner publication evidence")
    require_exact_keys(payload, OWNER_EVIDENCE_KEYS, "owner publication evidence")
    if payload.get("schema") != OWNER_EVIDENCE_SCHEMA:
        raise WebsiteDownloadCustodyError("unsupported owner publication evidence schema")
    issued = parse_utc(payload.get("issued_utc"), "owner publication evidence issued_utc")
    require_fresh(issued, "owner publication evidence issued_utc", now=now)
    require_issuance_id(payload.get("issuance_id"), "owner publication evidence issuance_id")
    require_issuance_id(
        payload.get("challenge_nonce"), "owner publication evidence challenge nonce"
    )
    if payload.get("canonical_release") != CANONICAL_RELEASE:
        raise WebsiteDownloadCustodyError(
            "owner publication evidence is not bound to the current 1.0.16+33 release"
        )
    if payload.get("package_identity") != PUBLIC_PACKAGE_IDENTITY:
        raise WebsiteDownloadCustodyError(
            "owner publication evidence package identity is not org.winsvpn.app"
        )
    ruling_errors = owner_ruling_errors(
        payload.get("owner_ruling"),
        "owner publication evidence",
        required_marker=OWNER_PUBLICATION_RULING_MARKER,
    )
    if ruling_errors:
        raise WebsiteDownloadCustodyError(ruling_errors[0])
    platforms = payload.get("platforms")
    if type(platforms) is not list or not platforms:
        raise WebsiteDownloadCustodyError("owner publication evidence platforms are missing")
    seen_ids: set[str] = set()
    seen_nonces: set[str] = set()
    for item in platforms:
        if type(item) is not dict:
            raise WebsiteDownloadCustodyError("owner publication evidence platform must be an object")
        refuse_self_asserted_authenticated(item, "owner publication evidence platform")
        require_exact_keys(item, OWNER_PLATFORM_KEYS, "owner publication evidence platform")
        platform_id = item.get("id")
        if platform_id not in PLATFORM_TARGETS or platform_id in seen_ids:
            raise WebsiteDownloadCustodyError(
                "owner publication evidence platform id is invalid or duplicated"
            )
        seen_ids.add(platform_id)
        if item.get("target") != PLATFORM_TARGETS[platform_id]:
            raise WebsiteDownloadCustodyError(
                f"owner publication evidence {platform_id} target is invalid"
            )
        if item.get("version") != CANONICAL_VERSION:
            raise WebsiteDownloadCustodyError(
                f"owner publication evidence {platform_id} version is not 1.0.16"
            )
        arch_errors = entry_architecture_errors(
            platform_id, item.get("architecture"), f"owner publication evidence {platform_id}"
        )
        if arch_errors:
            raise WebsiteDownloadCustodyError(arch_errors[0])
        filename = require_filename(
            item.get("artifact_filename"),
            f"owner publication evidence {platform_id} artifact filename",
        )
        unsigned_item = item.get("signature_kind") == UNSIGNED_SIGNATURE_KIND
        if unsigned_item and PLATFORM_TARGETS[platform_id] != UNSIGNED_WAIVER_PLATFORM:
            raise WebsiteDownloadCustodyError(
                f"owner publication evidence {platform_id} cannot use the Windows unsigned waiver"
            )
        expected_name = canonical_filename_for(
            platform_id, item.get("architecture"), unsigned=unsigned_item
        )
        if expected_name is None or filename != expected_name:
            raise WebsiteDownloadCustodyError(
                f"owner publication evidence {platform_id} filename is not canonical"
            )
        digest = require_hex64(
            item.get("artifact_sha256"),
            f"owner publication evidence {platform_id} artifact SHA-256",
        )
        require_int(
            item.get("artifact_bytes"),
            f"owner publication evidence {platform_id} artifact bytes",
        )
        identity_errors = refuse_forbidden_identity(
            digest=digest,
            package_identity=payload.get("package_identity"),
            canonical_release=payload.get("canonical_release"),
            signature_sha256=item.get("signature_sha256"),
            prefix=f"owner publication evidence {platform_id}",
        )
        if identity_errors:
            raise WebsiteDownloadCustodyError(identity_errors[0])
        expected_signature_kind = (
            UNSIGNED_SIGNATURE_KIND
            if unsigned_item
            else SIGNATURE_KINDS[PLATFORM_TARGETS[platform_id]]
        )
        if item.get("signature_kind") != expected_signature_kind:
            raise WebsiteDownloadCustodyError(
                f"owner publication evidence {platform_id} signature kind is unsigned or invalid"
            )
        signer = require_hex64(
            item.get("signature_sha256"),
            f"owner publication evidence {platform_id} signature SHA-256",
        )
        if signer == digest:
            raise WebsiteDownloadCustodyError(
                f"owner publication evidence {platform_id} unkeyed artifact digest is not cryptographic authentication"
            )
        if platform_id == "android" and signer != ANDROID_PUBLIC_SIGNER_SHA256:
            raise WebsiteDownloadCustodyError(
                f"owner publication evidence {platform_id} is not the reviewed production signer"
            )
        nonce = require_issuance_id(
            item.get("nonce"), f"owner publication evidence {platform_id} nonce"
        )
        if nonce in seen_nonces:
            raise WebsiteDownloadCustodyError(
                f"owner publication evidence {platform_id} nonce is a replay"
            )
        seen_nonces.add(nonce)
        if nonce in {payload.get("issuance_id"), payload.get("challenge_nonce")}:
            raise WebsiteDownloadCustodyError(
                f"owner publication evidence {platform_id} nonce replays the issuance or challenge"
            )
        expected_receipt = f"{filename}.publication.json"
        if item.get("receipt_filename") != expected_receipt:
            raise WebsiteDownloadCustodyError(
                f"owner publication evidence {platform_id} receipt filename is not bound"
            )
    return payload, sha256_bytes(raw)


def publication_receipt_errors(
    receipt: dict[str, Any],
    *,
    platform_id: str,
    artifact: dict[str, Any],
    owner: dict[str, Any],
    owner_sha256: str,
    owner_platform: dict[str, Any],
    challenge: dict[str, Any],
    now: datetime,
    prefix: str,
) -> list[str]:
    refuse_self_asserted_authenticated(receipt, f"{prefix} publication receipt")
    try:
        require_exact_keys(receipt, PUBLICATION_RECEIPT_KEYS, f"{prefix} publication receipt")
    except WebsiteDownloadCustodyError as exc:
        return [str(exc)]
    errors: list[str] = []
    if receipt.get("schema") != PUBLICATION_RECEIPT_SCHEMA:
        errors.append(f"{prefix} publication receipt schema is invalid")
    if receipt.get("kind") != PUBLICATION_RECEIPT_KIND:
        errors.append(f"{prefix} publication receipt kind is invalid")
    try:
        issued = parse_utc(receipt.get("issued_utc"), f"{prefix} publication receipt issued_utc")
        require_fresh(issued, f"{prefix} publication receipt issued_utc", now=now)
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
    if receipt.get("issuance_id") != owner.get("issuance_id"):
        errors.append(f"{prefix} publication receipt issuance_id is not the owner issuance")
    if receipt.get("issued_utc") != owner.get("issued_utc"):
        errors.append(
            f"{prefix} publication receipt issued_utc does not match owner evidence"
        )
    if receipt.get("nonce") != owner_platform.get("nonce"):
        errors.append(f"{prefix} publication receipt nonce is not the owner nonce")
    if receipt.get("challenge_nonce") != challenge.get("nonce"):
        errors.append(f"{prefix} publication receipt does not consume the verifier challenge")
    if receipt.get("canonical_release") != CANONICAL_RELEASE:
        errors.append(f"{prefix} publication receipt is not the current 1.0.16+33 release")
    if receipt.get("package_identity") != PUBLIC_PACKAGE_IDENTITY:
        errors.append(f"{prefix} publication receipt package identity is invalid")
    if receipt.get("platform_id") != platform_id:
        errors.append(f"{prefix} publication receipt platform does not match the artifact")
    if receipt.get("target") != PLATFORM_TARGETS[platform_id]:
        errors.append(f"{prefix} publication receipt target is invalid")
    if receipt.get("version") != CANONICAL_VERSION:
        errors.append(f"{prefix} publication receipt version is not 1.0.16")
    if receipt.get("architecture") != artifact.get("architecture"):
        errors.append(f"{prefix} publication receipt architecture does not match the artifact")
    if receipt.get("artifact_filename") != artifact.get("filename"):
        errors.append(f"{prefix} publication receipt filename does not match the artifact")
    if receipt.get("artifact_sha256") != artifact.get("sha256"):
        errors.append(f"{prefix} publication receipt SHA-256 does not match the artifact")
    if receipt.get("artifact_bytes") != artifact.get("bytes"):
        errors.append(f"{prefix} publication receipt byte count does not match the artifact")
    if receipt.get("signature_kind") != artifact.get("signature", {}).get("kind"):
        errors.append(f"{prefix} publication receipt is unsigned or has the wrong signature kind")
    if receipt.get("signature_sha256") != artifact.get("signature", {}).get("sha256"):
        errors.append(f"{prefix} publication receipt signature does not match the artifact")
    if receipt.get("signature_sha256") == artifact.get("sha256"):
        errors.append(
            f"{prefix} publication receipt unkeyed artifact digest is not cryptographic authentication"
        )
    if receipt.get("owner_evidence_sha256") != owner_sha256:
        errors.append(f"{prefix} publication receipt is not bound to current owner evidence")
    return errors


def hosted_identity_receipt_file_errors(
    root: Path,
    binding: object,
    artifact: dict[str, Any],
    platform_id: str,
    prefix: str,
    label: str,
    schema: str,
    kind: str,
    *,
    required_keys: frozenset[str],
    extra_expected: dict[str, Any] | None = None,
    evidence_errors: Any = None,
) -> list[str]:
    if type(binding) is not dict:
        return [f"{prefix} requires a hosted {label} receipt"]
    receipt_name = binding.get("receipt_filename")
    receipt_sha256 = binding.get("receipt_sha256")
    if type(receipt_name) is not str or type(receipt_sha256) is not str:
        return [f"{prefix} {label} receipt binding is incomplete"]
    relative = (DOWNLOADS_RELATIVE / receipt_name).as_posix()
    try:
        receipt_bytes = read_nofollow_relative(
            root, relative, f"{prefix} {label} receipt", max_bytes=MAX_JSON_BYTES
        )
    except WebsiteDownloadCustodyError as exc:
        return [str(exc)]
    if sha256_bytes(receipt_bytes) != receipt_sha256:
        return [f"{prefix} {label} receipt hash mismatch"]
    try:
        receipt = decode_json_object(receipt_bytes, f"{prefix} {label} receipt")
    except WebsiteDownloadCustodyError as exc:
        return [str(exc)]
    try:
        require_exact_keys(receipt, required_keys, f"{prefix} {label} receipt")
    except WebsiteDownloadCustodyError as exc:
        return [str(exc)]
    errors: list[str] = []
    if (
        receipt.get("schema") != schema
        or receipt.get("kind") != kind
        or receipt.get("canonical_release") != CANONICAL_RELEASE
        or receipt.get("platform_id") != platform_id
        or receipt.get("artifact_filename") != artifact.get("filename")
        or receipt.get("artifact_sha256") != artifact.get("sha256")
        or receipt.get("artifact_bytes") != artifact.get("bytes")
        or receipt.get("package_identity") != artifact.get("package_identity")
        or receipt.get("architecture") != artifact.get("architecture")
        or receipt.get("version") != CANONICAL_VERSION
    ):
        errors.append(
            f"{prefix} {label} receipt does not bind the exact 1.0.16+33 artifact"
        )
    if extra_expected:
        for key, expected in extra_expected.items():
            if receipt.get(key) != expected:
                errors.append(
                    f"{prefix} {label} receipt does not bind {key} to the current policy"
                )
    if evidence_errors is not None:
        errors.extend(evidence_errors(receipt))
    return errors


def expected_scan_target(entry_id: str) -> str | None:
    platform_id = PLATFORM_TARGETS[entry_id]
    arch = ENTRY_ARCHITECTURES.get(entry_id)
    if platform_id == "windows" and arch:
        return f"windows-{arch}-installer"
    if platform_id == "linux" and arch:
        return f"linux-{arch}-package"
    return None


def privacy_scan_errors(entry_id: str, receipt: dict[str, Any], prefix: str) -> list[str]:
    scan = receipt.get(PRIVACY_EVIDENCE_KEY)
    label = f"{prefix} privacy receipt scan evidence"
    if type(scan) is not dict or set(scan) != PRIVACY_SCAN_KEYS:
        return [f"{label} does not have its exact schema"]
    errors: list[str] = []
    if scan.get("contract") not in PRIVACY_SCAN_CONTRACTS:
        errors.append(f"{label} contract is not a reviewed release privacy scan")
    try:
        require_filename(scan.get("record_filename"), f"{label} record filename")
        require_hex64(scan.get("record_sha256"), f"{label} record SHA-256")
        require_hex64(scan.get("inventory_sha256"), f"{label} inventory SHA-256")
        require_int(scan.get("label_count"), f"{label} label count")
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
    if scan.get("result") != "pass" or scan.get("matched_labels") != []:
        errors.append(f"{label} is not a passing scan with zero matched secret labels")
    revision = scan.get("inventory_revision")
    if type(revision) is not str or not revision or len(revision) > 128:
        errors.append(f"{label} inventory revision is invalid")
    expected_target = expected_scan_target(entry_id)
    target = scan.get("target_id")
    if expected_target is not None and target != expected_target:
        errors.append(f"{label} scanned a different target than {expected_target}")
    if type(target) is not str or not target:
        errors.append(f"{label} target is missing")
    return errors


def release_build_errors(
    entry_id: str, receipt: dict[str, Any], artifact: dict[str, Any], prefix: str
) -> list[str]:
    build = receipt.get(RELEASE_EVIDENCE_KEY)
    label = f"{prefix} release receipt build evidence"
    if type(build) is not dict or set(build) != RELEASE_BUILD_KEYS:
        return [f"{label} does not have its exact schema"]
    errors: list[str] = []
    if build.get("receipt_contract") != BUILD_RECEIPT_CONTRACT:
        errors.append(f"{label} is not a winsvpn-build-receipt-v1 record")
    if build.get("receipt_filename") != "BUILD_RECEIPT.json":
        errors.append(f"{label} does not name BUILD_RECEIPT.json")
    try:
        require_hex64(build.get("receipt_sha256"), f"{label} receipt SHA-256")
        require_hex64(build.get("producer_sha256"), f"{label} producer SHA-256")
        parse_utc(build.get("finished_utc"), f"{label} finished_utc")
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
    revision = build.get("shared_revision")
    if type(revision) is not str or HEX40.fullmatch(revision) is None:
        errors.append(f"{label} shared revision is not a 40-hex commit")
    for key in ("producer_path", "remote_machine", "signing"):
        value = build.get(key)
        if type(value) is not str or not value or len(value) > 256:
            errors.append(f"{label} {key} is invalid")
    if build.get("source_artifact_name") != artifact.get("filename"):
        errors.append(
            f"{label} built a differently named artifact; published bytes are never renamed"
        )
    platform_id = PLATFORM_TARGETS[entry_id]
    arch = ENTRY_ARCHITECTURES.get(entry_id)
    target = build.get("toolchain_target")
    unsigned = artifact_is_unsigned_waiver(artifact)
    if platform_id == "windows":
        if unsigned:
            if target != f"windows-{arch}-inno-unsigned":
                errors.append(f"{label} toolchain target is not windows-{arch}-inno-unsigned")
            if build.get("signing") != "unsigned":
                errors.append(f"{label} unsigned label disagrees with the build signing record")
        else:
            if type(target) is not str or not target.startswith(f"windows-{arch}-inno"):
                errors.append(f"{label} toolchain target is not a windows-{arch} installer")
            if build.get("signing") == "unsigned":
                errors.append(f"{label} records an unsigned build for a signed download")
    elif platform_id == "linux":
        if target != f"linux-{arch}":
            errors.append(f"{label} toolchain target is not linux-{arch}")
        if build.get("signing") == "unsigned":
            errors.append(f"{label} records an unsigned Linux build")
    elif type(target) is not str or not target.startswith(platform_id):
        errors.append(f"{label} toolchain target is not a {platform_id} target")
    return errors


def pinned_winn_authority_key() -> str:
    payload = load_json_object(ROOT, WINN_AUTHORITY_RELATIVE, "Winn release authority")
    key = payload.get("public_key")
    return require_hex64(key, "Winn release authority public key")


def expected_winn_targets(entry_id: str) -> list[str] | None:
    platform_id = PLATFORM_TARGETS[entry_id]
    goarch = GOARCH_BY_ARCH.get(ENTRY_ARCHITECTURES.get(entry_id) or "")
    if goarch is None:
        return None
    if platform_id == "windows":
        return [f"datapath-windows-{goarch}", f"winn3-relay-windows-{goarch}"]
    if platform_id == "linux":
        return [f"datapath-linux-{goarch}"]
    return None


def winn_engine_errors(entry_id: str, receipt: dict[str, Any], prefix: str) -> list[str]:
    engine = receipt.get(WINN_EVIDENCE_KEY)
    label = f"{prefix} Winn provenance engine release evidence"
    if type(engine) is not dict or set(engine) != WINN_ENGINE_KEYS:
        return [f"{label} does not have its exact schema"]
    errors: list[str] = []
    try:
        require_hex64(engine.get("manifest_sha256"), f"{label} manifest SHA-256")
        require_hex64(engine.get("tree_sha256"), f"{label} tree SHA-256")
        if engine.get("signature_public_key") != pinned_winn_authority_key():
            errors.append(f"{label} is not signed by the pinned Winn release authority")
    except WebsiteDownloadCustodyError as exc:
        errors.append(str(exc))
    if engine.get("verified_by") != WINN_RELEASE_VERIFIER:
        errors.append(f"{label} was not verified by {WINN_RELEASE_VERIFIER}")
    commit = engine.get("source_commit")
    if type(commit) is not str or HEX40.fullmatch(commit) is None:
        errors.append(f"{label} source commit is not a 40-hex commit")
    targets = engine.get("targets")
    expected_targets = expected_winn_targets(entry_id)
    if type(targets) is not list or not targets or any(type(t) is not str for t in targets):
        errors.append(f"{label} targets are invalid")
    elif expected_targets is not None and targets != expected_targets:
        errors.append(f"{label} targets are not the {entry_id} engines {expected_targets}")
    binding = engine.get("binding")
    platform_id = PLATFORM_TARGETS[entry_id]
    arch = ENTRY_ARCHITECTURES.get(entry_id)
    if type(binding) is not dict:
        errors.append(f"{label} binding is missing")
        return errors
    if binding.get("kind") == "measured_member_sha256":
        if set(binding) != WINN_MEASURED_BINDING_KEYS:
            errors.append(f"{label} measured binding does not have its exact schema")
        elif (
            type(binding.get("member")) is not str
            or not binding.get("member")
            or type(binding.get("sha256")) is not str
            or HEX64.fullmatch(binding.get("sha256")) is None
            or type(targets) is not list
            or binding.get("target") not in targets
        ):
            errors.append(f"{label} measured binding is invalid")
    elif binding.get("kind") == "producer_log":
        if platform_id != "windows":
            errors.append(f"{label} producer-log binding is accepted only for Windows")
        if set(binding) != WINN_LOG_BINDING_KEYS:
            errors.append(f"{label} producer-log binding does not have its exact schema")
        else:
            expected_line = (
                "Staged the release-verified, role-checked Winn Protocol v3 "
                f"datapath and relay for {arch}."
            )
            if binding.get("line") != expected_line:
                errors.append(f"{label} producer log does not stage the {arch} Winn engines")
            if type(binding.get("log_sha256")) is not str or HEX64.fullmatch(
                binding.get("log_sha256")
            ) is None:
                errors.append(f"{label} producer log SHA-256 is invalid")
            try:
                require_filename(binding.get("log_filename"), f"{label} producer log")
            except WebsiteDownloadCustodyError as exc:
                errors.append(str(exc))
    else:
        errors.append(f"{label} binding kind is invalid")
    if platform_id == "linux" and binding.get("kind") != "measured_member_sha256":
        errors.append(f"{label} Linux engines must be measured inside the tarball")
    return errors


def artifact_hosted_receipt_file_errors(
    root: Path, platform_id: str, artifact: dict[str, Any], prefix: str
) -> list[str]:
    errors: list[str] = []
    errors.extend(
        hosted_identity_receipt_file_errors(
            root,
            artifact.get("privacy"),
            artifact,
            platform_id,
            prefix,
            "privacy",
            PRIVACY_RECEIPT_SCHEMA,
            PRIVACY_RECEIPT_KIND,
            required_keys=PRIVACY_RECEIPT_KEYS,
            evidence_errors=lambda receipt: privacy_scan_errors(platform_id, receipt, prefix),
        )
    )
    errors.extend(
        hosted_identity_receipt_file_errors(
            root,
            artifact.get("release_receipt"),
            artifact,
            platform_id,
            prefix,
            "release",
            RELEASE_RECEIPT_SCHEMA,
            RELEASE_RECEIPT_KIND,
            required_keys=RELEASE_RECEIPT_KEYS,
            evidence_errors=lambda receipt: release_build_errors(
                platform_id, receipt, artifact, prefix
            ),
        )
    )
    errors.extend(
        hosted_identity_receipt_file_errors(
            root,
            artifact.get("winn_provenance"),
            artifact,
            platform_id,
            prefix,
            "Winn provenance",
            WINN_PROVENANCE_SCHEMA,
            WINN_PROVENANCE_KIND,
            required_keys=WINN_RECEIPT_KEYS,
            extra_expected={
                "primary": WINN_PRIMARY,
                "fallback": WINN_FALLBACK,
                "fallback_order": WINN_FALLBACK_ORDER,
            },
            evidence_errors=lambda receipt: winn_engine_errors(platform_id, receipt, prefix),
        )
    )
    return errors


def sidecar_errors(root: Path, filename: str, digest: str, prefix: str) -> list[str]:
    relative = (DOWNLOADS_RELATIVE / f"{filename}.sha256").as_posix()
    try:
        body = read_nofollow_relative(
            root, relative, f"{prefix} SHA-256 sidecar", max_bytes=MAX_SIDECAR_BYTES
        )
    except WebsiteDownloadCustodyError as exc:
        return [str(exc)]
    expected = f"{digest}  {filename}\n".encode("ascii")
    if body != expected:
        return [f"{prefix} SHA-256 sidecar does not exactly bind {filename}"]
    return []


def present_download_names(root: Path) -> set[str]:
    downloads = root / DOWNLOADS_RELATIVE
    try:
        info = os.lstat(downloads)
    except OSError:
        return set()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise WebsiteDownloadCustodyError("downloads directory is missing or is a symlink")
    names: set[str] = set()
    require_nofollow()
    dir_fd = os.open(downloads, _open_flags(directory=True))
    try:
        after = os.fstat(dir_fd)
        if _dir_identity(info) != _dir_identity(after):
            raise WebsiteDownloadCustodyError("downloads directory was replaced")
        for entry in os.listdir(dir_fd):
            child = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(child.st_mode):
                raise WebsiteDownloadCustodyError(
                    f"downloads directory contains a symlink: {entry}"
                )
            if stat.S_ISDIR(child.st_mode):
                raise WebsiteDownloadCustodyError(
                    f"downloads directory contains a nested directory: {entry}"
                )
            if stat.S_ISREG(child.st_mode):
                names.add(entry)
    finally:
        os.close(dir_fd)
    return names


def parse_pe_machine(data: bytes) -> int | None:
    if len(data) < 64 or data[:2] != PE_MAGIC:
        return None
    pe_offset = struct.unpack_from("<I", data, 60)[0]
    if pe_offset + 6 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    return int(struct.unpack_from("<H", data, pe_offset + 4)[0])


def parse_elf_machine(data: bytes) -> int | None:
    if not data.startswith(ELF_MAGIC) or len(data) < 20:
        return None
    return int(struct.unpack_from("<H", data, 18)[0])


def gunzip_limited(data: bytes, max_bytes: int) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        block = decoder.decompress(view[offset : offset + READ_CHUNK], max_bytes - len(output) + 1)
        output.extend(block)
        if len(output) > max_bytes:
            raise WebsiteDownloadCustodyError(
                "Linux artifact uncompressed size exceeds the inspect bound"
            )
        offset += READ_CHUNK
        if decoder.eof:
            break
    return bytes(output)


def linux_type_errors(data: bytes, expected_arch: str, prefix: str) -> list[str]:
    if not data.startswith(GZIP_MAGIC):
        return [f"{prefix} Linux artifact is not a gzip tar"]
    try:
        raw = gunzip_limited(data, MAX_LINUX_UNCOMPRESSED)
    except WebsiteDownloadCustodyError as exc:
        return [str(exc)]
    except OSError as exc:
        return [f"{prefix} Linux artifact gzip is invalid: {exc}"]
    expected_machine = EM_X86_64 if expected_arch == "x64" else EM_AARCH64
    machines: set[int] = set()
    identity_version: str | None = None
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for index, member in enumerate(archive.getmembers()):
                if index >= MAX_TAR_MEMBERS:
                    return [f"{prefix} Linux artifact tar member count is unbounded"]
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                payload = extracted.read(min(member.size, 2 * 1024 * 1024))
                machine = parse_elf_machine(payload)
                if machine is not None:
                    machines.add(machine)
                if member.name.endswith("org.winsvpn.app.metainfo.xml"):
                    try:
                        text = payload.decode("utf-8")
                    except UnicodeDecodeError:
                        return [f"{prefix} Linux AppStream metadata is not UTF-8"]
                    if f'version="{CANONICAL_VERSION}"' in text:
                        identity_version = CANONICAL_VERSION
                    if "org.winsvpn.app" not in text:
                        return [f"{prefix} Linux package identity is not org.winsvpn.app"]
    except tarfile.TarError as exc:
        return [f"{prefix} Linux artifact is not a tar archive: {exc}"]
    if not machines:
        return [f"{prefix} Linux artifact does not contain a measured ELF image"]
    if machines != {expected_machine}:
        return [f"{prefix} Linux ELF machine does not match the canonical architecture"]
    if identity_version != CANONICAL_VERSION:
        return [f"{prefix} Linux version is not proven by package metadata"]
    return []


def android_type_errors(data: bytes, prefix: str) -> list[str]:
    if not data.startswith(ZIP_MAGIC):
        return [f"{prefix} Android artifact is not an APK"]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
    except zipfile.BadZipFile as exc:
        return [f"{prefix} Android artifact is not a ZIP/APK: {exc}"]
    if "AndroidManifest.xml" not in names:
        return [f"{prefix} Android artifact is missing AndroidManifest.xml"]
    abis = {
        part
        for name in names
        if name.startswith("lib/")
        for part in [name.split("/")[1] if name.count("/") >= 2 else ""]
        if part in PLATFORM_ARCHITECTURES["android"]
    }
    if abis != PLATFORM_ARCHITECTURES["android"]:
        return [f"{prefix} Android ABI inventory is not proven by the APK contents"]
    return []


def parse_pe_optional_magic(data: bytes) -> int | None:
    if len(data) < 64 or data[:2] != PE_MAGIC:
        return None
    pe_offset = struct.unpack_from("<I", data, 60)[0]
    if pe_offset + 26 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    return int(struct.unpack_from("<H", data, pe_offset + 24)[0])


def windows_type_errors(data: bytes, expected_arch: str, prefix: str) -> list[str]:
    """Check the website installer's outer PE loader.

    Both installers are Inno Setup 7.1.0 PE32+ x64 loaders (SetupArchitecture=x64;
    Inno has no ARM64 loader). Requiring 0xAA64 on the ARM64 installer would
    refuse every real ARM64 installer, and accepting any machine would let an x86
    loader through. The payload architecture is not visible in the LZMA2 solid
    stream, so it is bound through the release receipt's toolchain target, which
    custody checks separately (release_build_errors).
    """
    if expected_arch not in {"x64", "arm64"}:
        return [f"{prefix} Windows architecture is not x64 or arm64"]
    machine = parse_pe_machine(data)
    if machine is None:
        return [f"{prefix} Windows artifact is not a PE image"]
    if (
        machine != WINDOWS_INSTALLER_LOADER_MACHINE
        or parse_pe_optional_magic(data) != PE32_PLUS_MAGIC
    ):
        return [
            f"{prefix} Windows installer loader is not the reviewed PE32+ x64 Inno loader"
        ]
    return []


def windows_unsigned_errors(
    data: bytes, filename: str, pins: dict[str, str], prefix: str
) -> list[str]:
    """An Unsigned label must be true, and the VERSIONINFO must be 1.0.16.33."""
    try:
        windows = load_pinned_module(WINDOWS_GATE_RELATIVE, pins[WINDOWS_GATE_RELATIVE])
        parsed = windows._parse_pe_image(
            filename,
            data,
            expected_machine=WINDOWS_INSTALLER_LOADER_MACHINE,
            require_certificate=False,
        )
        versions = windows.pe_version_info(filename, data, require_certificate=False)
    except Exception as exc:
        return [f"{prefix} unsigned Windows installer is not a readable PE32+ image: {exc}"]
    errors: list[str] = []
    if parsed.get("cert_size") != 0:
        errors.append(
            f"{prefix} carries an Authenticode certificate table but is labelled Unsigned; "
            "publish it through the signed WinVerifyTrust path instead"
        )
    if (
        versions.get("ProductVersion") != CANONICAL_VERSION
        or versions.get("FileVersion") != f"{CANONICAL_VERSION}.33"
        or versions.get("ProductName") != "Win's VPN"
    ):
        errors.append(f"{prefix} installer VERSIONINFO is not Win's VPN 1.0.16.33")
    return errors


def linux_winn_member_errors(
    root: Path, artifact: dict[str, Any], data: bytes, prefix: str
) -> list[str]:
    """Measure the Winn engine inside the tarball against the signed release digest."""
    binding = artifact.get("winn_provenance")
    if type(binding) is not dict:
        return [f"{prefix} Winn provenance receipt is missing"]
    relative = (DOWNLOADS_RELATIVE / str(binding.get("receipt_filename"))).as_posix()
    try:
        receipt_bytes = read_nofollow_relative(
            root, relative, f"{prefix} Winn provenance receipt", max_bytes=MAX_JSON_BYTES
        )
    except WebsiteDownloadCustodyError as exc:
        return [str(exc)]
    if sha256_bytes(receipt_bytes) != binding.get("receipt_sha256"):
        return [f"{prefix} Winn provenance receipt hash mismatch"]
    try:
        receipt = decode_json_object(receipt_bytes, f"{prefix} Winn provenance receipt")
    except WebsiteDownloadCustodyError as exc:
        return [str(exc)]
    engine = receipt.get(WINN_EVIDENCE_KEY)
    measured = engine.get("binding") if type(engine) is dict else None
    if type(measured) is not dict or measured.get("kind") != "measured_member_sha256":
        return [f"{prefix} Linux Winn engine is not measured inside the tarball"]
    member_name = measured.get("member")
    try:
        raw = gunzip_limited(data, MAX_LINUX_UNCOMPRESSED)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            member = archive.getmember(str(member_name))
            if not member.isfile() or member.size > MAX_LINUX_UNCOMPRESSED:
                return [f"{prefix} Linux Winn engine member is not a regular file"]
            extracted = archive.extractfile(member)
            payload = extracted.read() if extracted is not None else b""
    except (KeyError, tarfile.TarError, OSError, WebsiteDownloadCustodyError) as exc:
        return [f"{prefix} Linux Winn engine member cannot be measured: {exc}"]
    if sha256_bytes(payload) != measured.get("sha256"):
        return [
            f"{prefix} Linux Winn engine bytes do not match the signed engine release digest"
        ]
    return []


def open_trusted_cosign_key(label: str) -> OpenedRelative:
    return open_nofollow_file(
        ROOT, TRUSTED_COSIGN_KEY_RELATIVE, label, max_bytes=MAX_JSON_BYTES
    )


def _immutable_apk_from_fd(artifact_fd: int, prefix: str) -> tuple[Path, Path, int]:
    info = os.fstat(artifact_fd)
    if not stat.S_ISREG(info.st_mode):
        raise WebsiteDownloadCustodyError(f"{prefix} Android artifact descriptor is invalid")
    data = _pread_exact(artifact_fd, info.st_size, f"{prefix} Android artifact")
    tmp = Path(tempfile.mkdtemp(prefix="winsvpn-android-verify-"))
    snapshot_fd = -1
    dir_fd = -1
    try:
        os.chmod(tmp, 0o700)
        dir_fd = os.open(tmp, _open_flags(directory=True))
        dest_name = "wins-vpn-android.apk"
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        snapshot_fd = os.open(dest_name, flags, 0o400, dir_fd=dir_fd)
        os.fchmod(snapshot_fd, 0o400)
        _write_all(snapshot_fd, data, f"{prefix} Android snapshot")
        os.fsync(snapshot_fd)
        copied = _pread_exact(snapshot_fd, len(data), f"{prefix} Android snapshot")
        if copied != data:
            raise WebsiteDownloadCustodyError(
                f"{prefix} Android snapshot does not match the open descriptor"
            )
        owned = snapshot_fd
        snapshot_fd = -1
        return tmp, tmp / dest_name, owned
    except Exception:
        if snapshot_fd >= 0:
            os.close(snapshot_fd)
            snapshot_fd = -1
        if dir_fd >= 0:
            try:
                os.unlink("wins-vpn-android.apk", dir_fd=dir_fd)
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass
        raise
    finally:
        if dir_fd >= 0:
            os.close(dir_fd)


def _darwin_cosign_snapshots(
    artifact: bytes, key: bytes, bundle: bytes, prefix: str
) -> tuple[Path, str, str, str]:
    tmp = Path(tempfile.mkdtemp(prefix="winsvpn-cosign-verify-"))
    os.chmod(tmp, 0o700)
    refs: list[str] = []
    for name, payload in (
        ("artifact.tar.gz", artifact),
        ("cosign.pub", key),
        ("bundle.sigstore.json", bundle),
    ):
        path = tmp / name
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400
        )
        try:
            _write_all(fd, payload, f"{prefix} Cosign snapshot")
            os.fsync(fd)
        finally:
            os.close(fd)
        refs.append(str(path))
    return tmp, refs[0], refs[1], refs[2]


def linux_signature_errors(
    root: Path,
    filename: str,
    data: bytes,
    pins: dict[str, str],
    prefix: str,
    *,
    artifact_fd: int,
) -> list[str]:
    _ = data
    if artifact_fd < 0:
        return [
            f"{prefix} Linux Cosign verification requires the already-open artifact descriptor"
        ]
    try:
        artifact_info = os.fstat(artifact_fd)
        if not stat.S_ISREG(artifact_info.st_mode):
            return [f"{prefix} Linux artifact descriptor is invalid"]
        measured = _pread_exact(artifact_fd, artifact_info.st_size, f"{prefix} Linux artifact")
        if measured != data:
            return [f"{prefix} Linux artifact descriptor does not match the hashed bytes"]
    except OSError as exc:
        return [f"{prefix} Linux artifact descriptor is invalid: {exc}"]
    bundle_relative = (DOWNLOADS_RELATIVE / f"{filename}.sigstore.json").as_posix()
    bundle: OpenedRelative | None = None
    key: OpenedRelative | None = None
    try:
        try:
            bundle = open_nofollow_file(
                root,
                bundle_relative,
                f"{prefix} Linux Sigstore bundle",
                max_bytes=MAX_JSON_BYTES,
            )
        except WebsiteDownloadCustodyError:
            return [
                f"{prefix} Linux Cosign/sigstore publication signature is missing; "
                "unkeyed digest is not authentication"
            ]
        try:
            key = open_trusted_cosign_key(f"{prefix} Linux Cosign canonical trusted key")
        except WebsiteDownloadCustodyError:
            return [
                f"{prefix} Linux Cosign canonical trusted key is missing; "
                "unkeyed digest is not authentication"
            ]
        try:
            signing = load_pinned_module(LINUX_SIGNING_RELATIVE, pins[LINUX_SIGNING_RELATIVE])
            signing.validate_standard_bundle(
                immutable_descriptor_path(bundle.fd, f"{prefix} Linux Sigstore bundle")
            )
        except Exception as exc:
            return [
                f"{prefix} Linux Sigstore bundle is not a Cosign standard bundle: {exc}"
            ]
        snapshot_dir: Path | None = None
        try:
            if sys.platform == "darwin":
                # macOS /dev/fd/N duplicates the descriptor and shares its file
                # offset, so Cosign's second read of the bundle sees EOF. Verify
                # private 0400 snapshots of the exact held bytes instead.
                snapshot_dir, artifact_ref, key_ref, bundle_ref = _darwin_cosign_snapshots(
                    data, key.data, bundle.data, prefix
                )
            else:
                artifact_ref = immutable_descriptor_path(
                    artifact_fd, f"{prefix} Linux artifact"
                )
                key_ref = immutable_descriptor_path(
                    key.fd, f"{prefix} Linux Cosign canonical trusted key"
                )
                bundle_ref = immutable_descriptor_path(
                    bundle.fd, f"{prefix} Linux Sigstore bundle"
                )
            with signing.open_authenticated_cosign(*cosign_path_arguments(signing)) as cosign_fd:
                # _cosign_executable rehashes the authenticated descriptor and
                # returns /proc/self/fd/N on Linux (the previous behaviour) or
                # the authenticated path on macOS, which cannot exec /dev/fd/N.
                executable = signing._cosign_executable(cosign_fd, "Cosign execution")
                completed = subprocess.run(
                    [
                        executable,
                        "verify-blob",
                        artifact_ref,
                        "--key",
                        key_ref,
                        "--bundle",
                        bundle_ref,
                        "--offline",
                        "--insecure-ignore-tlog",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    pass_fds=(cosign_fd, artifact_fd, key.fd, bundle.fd),
                )
            if snapshot_dir is not None:
                for ref, expected in (
                    (artifact_ref, data),
                    (key_ref, key.data),
                    (bundle_ref, bundle.data),
                ):
                    if Path(ref).read_bytes() != expected:
                        return [f"{prefix} Linux Cosign snapshot changed during verification"]
        except Exception as exc:
            return [
                f"{prefix} Linux Cosign verification failed; unkeyed digest is not authentication: {exc}"
            ]
        finally:
            if snapshot_dir is not None:
                for child in snapshot_dir.iterdir():
                    try:
                        child.unlink()
                    except OSError:
                        pass
                try:
                    snapshot_dir.rmdir()
                except OSError:
                    pass
        if completed.returncode != 0:
            return [
                f"{prefix} Linux Cosign verification failed; unkeyed digest is not authentication"
            ]
        return []
    finally:
        if key is not None:
            key.close()
        if bundle is not None:
            bundle.close()


def cosign_path_arguments(signing: Any) -> tuple[str, ...]:
    """macOS only: WINS_RELEASE_COSIGN names the digest-pinned Cosign binary.

    linux_release_signing authenticates the bytes against its darwin pin, so a
    wrong path fails closed. On Linux the reviewed fixed path is always used.
    """
    override = os.environ.get("WINS_RELEASE_COSIGN", "")
    if sys.platform == "darwin" and override:
        return (override,)
    return ()


def windows_signature_errors(
    data: bytes,
    filename: str,
    pins: dict[str, str],
    prefix: str,
    *,
    policy_leaf_sha256: str,
) -> list[str]:
    try:
        windows = load_pinned_module(WINDOWS_GATE_RELATIVE, pins[WINDOWS_GATE_RELATIVE])
        leaf = windows.authenticode_leaf_identity(filename, data)
    except Exception as exc:
        return [
            f"{prefix} Windows Authenticode is not proven by the pinned Windows gate: {exc}"
        ]
    if type(leaf) is not dict:
        return [f"{prefix} Windows Authenticode leaf identity is missing"]
    leaf_sha256 = leaf.get("sha256")
    try:
        measured = require_hex64(leaf_sha256, f"{prefix} Windows Authenticode leaf SHA-256")
        expected = require_hex64(
            policy_leaf_sha256, f"{prefix} Windows Authenticode policy SHA-256"
        )
    except WebsiteDownloadCustodyError as exc:
        return [str(exc)]
    if measured != expected:
        return [
            f"{prefix} Windows Authenticode leaf SHA-256 is not bound to policy"
        ]
    try:
        windows.authenticode_custody_policy(filename, data, leaf)
    except Exception as exc:
        return [
            f"{prefix} Windows Authenticode custody policy is not proven by the pinned Windows gate: {exc}"
        ]
    return []


def android_signature_errors(artifact_fd: int, pins: dict[str, str], prefix: str) -> list[str]:
    snapshot_dir: Path | None = None
    snapshot_fd = -1
    try:
        snapshot_dir, snapshot_path, snapshot_fd = _immutable_apk_from_fd(artifact_fd, prefix)
        audit = load_pinned_module(WEBSITE_AUDIT_RELATIVE, pins[WEBSITE_AUDIT_RELATIVE])
        errors = audit.public_binary_identity_errors("android", snapshot_path)
        final = os.fstat(snapshot_fd)
        if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
            return [f"{prefix} Android snapshot was replaced"]
        copied = _pread_exact(snapshot_fd, final.st_size, f"{prefix} Android snapshot")
        original_info = os.fstat(artifact_fd)
        original = _pread_exact(
            artifact_fd, original_info.st_size, f"{prefix} Android artifact"
        )
        try:
            named_bytes = snapshot_path.read_bytes()
        except OSError as exc:
            return [f"{prefix} Android snapshot was replaced: {exc}"]
        if named_bytes != copied or copied != original:
            return [f"{prefix} Android snapshot does not match the open descriptor"]
        return [f"{prefix} {item}" for item in errors]
    except Exception as exc:
        return [
            f"{prefix} Android production signature is not proven by the pinned website audit: {exc}"
        ]
    finally:
        if snapshot_fd >= 0:
            os.close(snapshot_fd)
        if snapshot_dir is not None:
            snapshot_file = snapshot_dir / "wins-vpn-android.apk"
            try:
                snapshot_file.unlink()
            except OSError:
                pass
            try:
                snapshot_dir.rmdir()
            except OSError:
                pass


def apple_store_errors(platform_id: str, prefix: str) -> list[str]:
    _ = platform_id
    return [
        f"{prefix} production store URL and Apple gate output are absent; "
        "keep verification_pending"
    ]


def measured_artifact_errors(
    root: Path,
    platform_id: str,
    artifact: dict[str, Any],
    pins: dict[str, str],
    prefix: str,
) -> list[str]:
    filename = artifact.get("filename")
    digest = artifact.get("sha256")
    byte_count = artifact.get("bytes")
    architecture = artifact.get("architecture")
    entry_id = platform_id
    platform_id = PLATFORM_TARGETS.get(entry_id, entry_id)
    if type(filename) is not str or type(digest) is not str or type(byte_count) is not int:
        return []
    relative = (DOWNLOADS_RELATIVE / filename).as_posix()
    opened: OpenedRelative | None = None
    try:
        try:
            opened = open_nofollow_file(
                root, relative, f"{prefix} file", max_bytes=MAX_ARTIFACT_BYTES
            )
        except WebsiteDownloadCustodyError as exc:
            return [str(exc)]
        data = opened.data
        if len(data) != byte_count:
            return [
                f"{prefix} byte count mismatch for {filename}: expected {byte_count}, got {len(data)}"
            ]
        if sha256_bytes(data) != digest:
            return [f"{prefix} SHA-256 mismatch for {filename}"]
        held = os.fstat(opened.fd)
        if _file_identity(opened.info) != _file_identity(held):
            return [f"{prefix} was replaced during descriptor read"]
        errors: list[str] = []
        errors.extend(sidecar_errors(root, filename, digest, prefix))
        if platform_id == "linux":
            expected_arch = architecture[0] if type(architecture) is list and architecture else ""
            errors.extend(linux_type_errors(data, expected_arch, prefix))
            if not errors:
                errors.extend(
                    linux_signature_errors(
                        root, filename, data, pins, prefix, artifact_fd=opened.fd
                    )
                )
            if not errors:
                errors.extend(linux_winn_member_errors(root, artifact, data, prefix))
        elif platform_id == "windows":
            expected_arch = architecture[0] if type(architecture) is list and architecture else ""
            errors.extend(windows_type_errors(data, expected_arch, prefix))
            signature = artifact.get("signature")
            policy_leaf = (
                signature.get("sha256") if type(signature) is dict else ""
            )
            if not errors and artifact_is_unsigned_waiver(artifact):
                errors.extend(windows_unsigned_errors(data, filename, pins, prefix))
            elif not errors:
                errors.extend(
                    windows_signature_errors(
                        data,
                        filename,
                        pins,
                        prefix,
                        policy_leaf_sha256=policy_leaf if type(policy_leaf) is str else "",
                    )
                )
        elif platform_id == "android":
            errors.extend(android_type_errors(data, prefix))
            if not errors:
                errors.extend(android_signature_errors(opened.fd, pins, prefix))
        elif platform_id in {"macos", "ios"}:
            errors.extend(apple_store_errors(platform_id, prefix))
        return errors
    finally:
        if opened is not None:
            opened.close()


def evaluate_tree(root: Path, *, now: datetime | None = None) -> CustodyReport:
    checked_at = now or utc_now()
    findings: list[str] = []
    try:
        manifest = load_manifest(root)
        custody = load_custody_metadata(root)
        pins = pinned_verifier_digests()
        if type(pins) is not dict or set(pins) != set(VERIFIER_FILES):
            raise WebsiteDownloadCustodyError("repository-pinned verifier boundary is incomplete")
        present = present_download_names(root)
        owner_raw = read_nofollow_optional(
            root,
            OWNER_EVIDENCE_RELATIVE.as_posix(),
            "owner publication evidence",
            max_bytes=MAX_JSON_BYTES,
        )
        challenge_raw = read_nofollow_optional(
            root,
            CHALLENGE_RELATIVE.as_posix(),
            "verifier-issued one-use challenge",
            max_bytes=MAX_CHALLENGE_BYTES,
        )
        replay_records = load_replay_log(root)
    except WebsiteDownloadCustodyError as exc:
        return CustodyReport(False, FAILED_STATUS, f"FAIL {exc}", (str(exc),))

    entries = manifest["artifacts"]
    available_ids: list[str] = []
    github_ids: list[str] = []
    bound_names: set[str] = set()
    for index, (platform_id, platform_label, expected_kind) in enumerate(PLATFORM_CONTRACT):
        prefix = f"artifact {platform_id}"
        entry = entries[index]
        if type(entry) is not dict:
            findings.append(f"{prefix} must be an object")
            continue
        refuse_self_asserted_authenticated(entry, prefix)
        if set(entry) != MANIFEST_ENTRY_KEYS:
            findings.append(f"{prefix} does not have its exact schema")
            continue
        if entry.get("id") != platform_id or entry.get("label") != platform_label:
            findings.append(f"{prefix} id/label/order mismatch")
            continue
        status = entry.get("status")
        if status in {PENDING_STATUS, STORE_PENDING_STATUS}:
            findings.extend(pending_entry_errors(entry, platform_id, prefix, status))
            continue
        if status != AVAILABLE_STATUS:
            findings.append(f"{prefix} has an invalid status")
            continue
        if platform_id not in {"windows-x64", "windows-arm64", "linux-x64", "linux-arm64"}:
            findings.append(f"{prefix} is outside the owner-authorized 1.0.16+33 desktop launch")
        candidate_artifact = entry.get("artifact")
        if platform_id.startswith("windows-") and (
            type(candidate_artifact) is not dict or not artifact_is_unsigned_waiver(candidate_artifact)
        ):
            findings.append(f"{prefix} must use the recorded Unsigned owner waiver")
        available_ids.append(platform_id)
        delivery = entry.get("delivery")
        artifact = entry.get("artifact")
        if type(delivery) is not dict or type(artifact) is not dict:
            findings.append(f"{prefix} delivery/artifact metadata missing")
            continue
        refuse_self_asserted_authenticated(delivery, prefix)
        refuse_self_asserted_authenticated(artifact, prefix)
        if set(delivery) != DELIVERY_KEYS:
            findings.append(f"{prefix} delivery is outside the closed JSON schema")
            continue
        if expected_kind == "store":
            findings.extend(apple_store_errors(platform_id, prefix))
            continue
        github = delivery.get("kind") == "github_release"
        if github and (platform_id not in GITHUB_RELEASE_ENTRIES or expected_kind != "direct"):
            findings.append(
                f"{prefix} GitHub is backup-only and is not website publication authority"
            )
            continue
        if not github and (delivery.get("kind") != "direct" or expected_kind != "direct"):
            findings.append(
                f"{prefix} available website downloads must be locally bound direct artifacts"
            )
            continue
        filename = artifact.get("filename") if type(artifact.get("filename")) is str else ""
        delivery_url = str(delivery.get("url") or "")
        if "/releases/latest/" in delivery_url or "/releases/download/latest/" in delivery_url:
            findings.append(f"{prefix} delivery URL is a mutable latest-release route")
        parsed = urlparse(delivery_url)
        if github:
            github_ids.append(platform_id)
            if not filename or delivery.get("url") != github_release_url(filename) or (
                parsed.scheme != "https"
                or parsed.netloc != "github.com"
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path
                != f"/{GITHUB_RELEASE_OWNER_REPO}/releases/download/{GITHUB_RELEASE_TAG}/{filename}"
            ):
                findings.append(
                    f"{prefix} GitHub is backup-only and is not website publication authority "
                    f"unless the URL is exactly {GITHUB_RELEASE_PREFIX}<filename>"
                )
        else:
            expected_url = production_direct_url(filename) if filename else ""
            if delivery.get("url") != expected_url:
                findings.append(
                    f"{prefix} direct URL is not the exact production origin binding"
                )
            if (
                parsed.scheme != "https"
                or parsed.netloc != "winsvpn.org"
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path != f"/downloads/{filename}"
            ):
                findings.append(f"{prefix} direct URL left the exact production origin")
        findings.extend(available_artifact_schema_errors(platform_id, artifact, prefix))
        findings.extend(
            artifact_hosted_receipt_file_errors(root, platform_id, artifact, prefix)
        )
        target_platform = PLATFORM_TARGETS[platform_id]
        if target_platform == "windows" and filename and artifact_is_unsigned_waiver(artifact):
            try:
                waiver, waiver_sha256 = load_unsigned_waiver(root)
                if platform_id not in waiver.get("entries", []):
                    findings.append(f"{prefix} is not covered by the unsigned owner waiver")
                signature = artifact.get("signature")
                if type(signature) is not dict or signature.get("sha256") != waiver_sha256:
                    findings.append(f"{prefix} unsigned waiver SHA-256 does not match the waiver file")
            except WebsiteDownloadCustodyError as exc:
                findings.append(f"{prefix} {exc}")
        elif target_platform == "windows" and filename:
            try:
                audit = load_pinned_module(
                    WEBSITE_AUDIT_RELATIVE, pins[WEBSITE_AUDIT_RELATIVE]
                )
                findings.extend(
                    f"{prefix} {message}"
                    for message in audit.windows_winverifytrust_receipt_errors(
                        root / DOWNLOADS_RELATIVE / filename,
                        artifact,
                        root / DOWNLOADS_RELATIVE,
                    )
                )
            except WebsiteDownloadCustodyError as exc:
                findings.append(str(exc))
        if filename:
            bound_names.add(filename)
            bound_names.add(f"{filename}.sha256")
            if target_platform == "linux":
                bound_names.add(f"{filename}.sigstore.json")
            for field in (
                "privacy",
                "release_receipt",
                "publication_receipt",
                "winn_provenance",
                "windows_verification",
            ):
                binding = artifact.get(field)
                if type(binding) is dict:
                    receipt_name = binding.get("receipt_filename")
                    if type(receipt_name) is str and receipt_name:
                        bound_names.add(receipt_name)

    owner_exists = owner_raw is not None
    challenge_exists = challenge_raw is not None
    # Per-platform launch (owner ruling 2026-10-25): any subset of entries may be
    # available while the rest stay verification_pending or store_pending. Each
    # available entry still needs its own measured custody and owner evidence.
    if available_ids:
        if custody.get("status") != AVAILABLE_STATUS:
            findings.append(
                "custody metadata must be available when a public download is bound"
            )
        if not owner_exists:
            findings.append(
                "available downloads require owner publication evidence; "
                "self-asserted authenticated:true is not enough"
            )
        if not challenge_exists:
            findings.append(
                "available downloads require a verifier-issued one-use challenge"
            )
    else:
        if custody.get("status") != PENDING_STATUS:
            findings.append(
                "custody metadata must stay verification_pending while artifacts are absent"
            )
        if owner_exists:
            findings.append(
                "owner publication evidence is present while every download is still pending"
            )
        if challenge_exists:
            findings.append(
                "verifier challenge is present while every download is still pending"
            )
        if present:
            findings.append(
                "pending downloads directory contains files that would substitute missing artifacts"
            )

    owner = None
    owner_sha256 = None
    owner_by_id: dict[str, dict[str, Any]] = {}
    challenge = None
    if available_ids and challenge_exists:
        try:
            challenge = load_challenge(root, now=checked_at)
        except WebsiteDownloadCustodyError as exc:
            findings.append(str(exc))
    if available_ids and owner_exists:
        try:
            owner, owner_sha256 = load_owner_evidence(root, now=checked_at)
            owner_platforms = owner.get("platforms")
            if type(owner_platforms) is not list:
                raise WebsiteDownloadCustodyError("owner publication evidence platforms are missing")
            owner_ids = [item.get("id") for item in owner_platforms if type(item) is dict]
            if owner_ids != available_ids:
                raise WebsiteDownloadCustodyError(
                    "owner publication evidence platforms are not exactly the available downloads"
                )
            if challenge is not None and owner.get("challenge_nonce") != challenge.get("nonce"):
                raise WebsiteDownloadCustodyError(
                    "owner publication evidence does not consume the verifier-issued challenge"
                )
            owner_by_id = {
                item["id"]: item for item in owner_platforms if type(item) is dict
            }
            if github_ids:
                ruling = owner.get("owner_ruling")
                lines = ruling.get("lines") if type(ruling) is dict else None
                if type(lines) is not list or not any(
                    type(line) is str and GITHUB_HOSTING_RULING_MARKER in line for line in lines
                ):
                    raise WebsiteDownloadCustodyError(
                        "GitHub-hosted downloads require owner evidence quoting the recorded "
                        f"ruling that names {GITHUB_HOSTING_RULING_MARKER}"
                    )
            replay_key = (
                str(owner.get("issuance_id")),
                str(owner_by_id[available_ids[0]]["nonce"]) if available_ids[0] in owner_by_id else "",
                str(owner.get("challenge_nonce")),
            )
            if replay_key[1] and replay_key in replay_records:
                raise WebsiteDownloadCustodyError(
                    "owner publication evidence nonce or challenge was already consumed"
                )
            if release_ledger_conflict(
                release_ledger_records(),
                challenge_nonce=str(owner.get("challenge_nonce")),
                issuance_id=str(owner.get("issuance_id")),
                nonces=[str(item.get("nonce")) for item in owner_platforms if type(item) is dict],
            ):
                raise WebsiteDownloadCustodyError(
                    "owner publication evidence nonce or challenge was already consumed "
                    "(durable release ledger)"
                )
            if any(
                record.get("challenge_nonce") == owner.get("challenge_nonce")
                or record.get("issuance_id") == owner.get("issuance_id")
                for record in replay_records.values()
            ):
                raise WebsiteDownloadCustodyError(
                    "owner publication evidence nonce or challenge was already consumed"
                )
            for item in owner_platforms:
                if type(item) is not dict:
                    continue
                item_key = (
                    str(owner.get("issuance_id")),
                    str(item.get("nonce")),
                    str(owner.get("challenge_nonce")),
                )
                if item_key in replay_records:
                    raise WebsiteDownloadCustodyError(
                        "owner publication evidence nonce or challenge was already consumed"
                    )
        except WebsiteDownloadCustodyError as exc:
            findings.append(str(exc))

    if available_ids and owner is not None and owner_sha256 is not None and challenge is not None:
        for index, (platform_id, _label, expected_kind) in enumerate(PLATFORM_CONTRACT):
            if platform_id not in available_ids:
                continue
            prefix = f"artifact {platform_id}"
            entry = entries[index]
            artifact = entry.get("artifact")
            if type(artifact) is not dict:
                continue
            if expected_kind == "direct":
                findings.extend(
                    measured_artifact_errors(root, platform_id, artifact, pins, prefix)
                )
            owner_platform = owner_by_id.get(platform_id)
            if owner_platform is None:
                findings.append(f"{prefix} is missing from owner publication evidence")
                continue
            if owner_platform.get("artifact_filename") != artifact.get("filename"):
                findings.append(f"{prefix} filename does not match owner publication evidence")
            if owner_platform.get("artifact_sha256") != artifact.get("sha256"):
                findings.append(f"{prefix} SHA-256 does not match owner publication evidence")
            if owner_platform.get("artifact_bytes") != artifact.get("bytes"):
                findings.append(f"{prefix} byte count does not match owner publication evidence")
            if owner_platform.get("architecture") != artifact.get("architecture"):
                findings.append(f"{prefix} architecture does not match owner publication evidence")
            if owner_platform.get("target") != PLATFORM_TARGETS[platform_id]:
                findings.append(f"{prefix} target does not match owner publication evidence")
            if owner_platform.get("version") != CANONICAL_VERSION:
                findings.append(f"{prefix} version does not match owner publication evidence")
            signature = artifact.get("signature")
            if type(signature) is dict:
                if owner_platform.get("signature_kind") != signature.get("kind"):
                    findings.append(f"{prefix} signature kind does not match owner evidence")
                if owner_platform.get("signature_sha256") != signature.get("sha256"):
                    findings.append(f"{prefix} signature does not match owner evidence")
            receipt_binding = artifact.get("publication_receipt")
            if type(receipt_binding) is not dict:
                continue
            receipt_name = receipt_binding.get("receipt_filename")
            receipt_sha256 = receipt_binding.get("receipt_sha256")
            if type(receipt_name) is not str or type(receipt_sha256) is not str:
                continue
            relative = (DOWNLOADS_RELATIVE / receipt_name).as_posix()
            try:
                receipt_bytes = read_nofollow_relative(
                    root, relative, f"{prefix} publication receipt", max_bytes=MAX_JSON_BYTES
                )
            except WebsiteDownloadCustodyError as exc:
                findings.append(str(exc))
                continue
            if sha256_bytes(receipt_bytes) != receipt_sha256:
                findings.append(f"{prefix} publication receipt hash mismatch")
                continue
            try:
                receipt = decode_json_object(receipt_bytes, f"{prefix} publication receipt")
            except WebsiteDownloadCustodyError as exc:
                findings.append(str(exc))
                continue
            findings.extend(
                publication_receipt_errors(
                    receipt,
                    platform_id=platform_id,
                    artifact=artifact,
                    owner=owner,
                    owner_sha256=owner_sha256,
                    owner_platform=owner_platform,
                    challenge=challenge,
                    now=checked_at,
                    prefix=prefix,
                )
            )

    unbound = sorted(present - bound_names)
    if unbound and available_ids:
        preview = ", ".join(unbound[:8])
        extra = f" (+{len(unbound) - 8} more)" if len(unbound) > 8 else ""
        findings.append(
            "downloads directory contains manifest-unbound files that must not substitute "
            f"current artifacts: {preview}{extra}"
        )
    missing = sorted(name for name in bound_names if name not in present)
    if missing:
        findings.append(
            "manifest-bound direct artifacts or receipts are absent: " + ", ".join(missing)
        )

    if findings:
        return CustodyReport(
            False,
            FAILED_STATUS,
            "FAIL website download custody: " + "; ".join(findings),
            tuple(findings),
        )
    if available_ids:
        if owner is None or challenge is None:
            summary = "FAIL available downloads lack trusted cryptographic custody"
            return CustodyReport(False, FAILED_STATUS, summary, (summary,))
        try:
            # Durable ledger first: once it records the challenge, no other
            # clone can publish with it, even if the local journal step fails.
            consume_release_ledger(
                issuance_id=str(owner.get("issuance_id")),
                challenge_nonce=str(owner.get("challenge_nonce")),
                owner_evidence_sha256=owner_sha256,
                nonces=[str(owner_by_id[item].get("nonce")) for item in available_ids],
                artifact_sha256s=[str(owner_by_id[item].get("artifact_sha256")) for item in available_ids],
                now=checked_at,
            )
            for platform_id in available_ids:
                owner_platform = owner_by_id[platform_id]
                consume_replay(
                    root,
                    issuance_id=str(owner.get("issuance_id")),
                    nonce=str(owner_platform.get("nonce")),
                    challenge_nonce=str(owner.get("challenge_nonce")),
                    owner_evidence_sha256=owner_sha256,
                    artifact_sha256=str(owner_platform.get("artifact_sha256")),
                    now=checked_at,
                )
        except WebsiteDownloadCustodyError as exc:
            return CustodyReport(False, FAILED_STATUS, f"FAIL {exc}", (str(exc),))
        not_available = [item for item in PLATFORM_IDS if item not in available_ids]
        summary = (
            f"PASS {len(available_ids)} public download(s) bound to current "
            f"{CANONICAL_RELEASE} artifacts: {', '.join(available_ids)}; "
            f"not published: {', '.join(not_available) or 'none'}"
        )
        return CustodyReport(True, AVAILABLE_STATUS, summary, ())
    summary = (
        f"PENDING {len(PLATFORM_IDS)} platforms; signed release artifacts and "
        "owner publication evidence are absent; blockers: "
        + "; ".join(PENDING_BLOCKERS)
    )
    return CustodyReport(False, PENDING_STATUS, summary, PENDING_BLOCKERS)


def evaluate_repository(*, now: datetime | None = None) -> CustodyReport:
    return evaluate_tree(ROOT, now=now)


def main() -> int:
    report = evaluate_repository()
    print(report.summary)
    if report.ok and report.status == AVAILABLE_STATUS and report.summary.startswith("PASS "):
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
