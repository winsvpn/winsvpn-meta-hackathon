#!/usr/bin/env python3
"""Fail-closed legal-bundle verifier for exact produced release packages.

The verifier accepts a ZIP-family package (APK, AAB, IPA, MSIX, browser ZIP),
a tar archive, or an already extracted package directory. It never extracts an
archive. Every archive member name and type is validated before selected bytes
are read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = Path("legal/release/LEGAL_BUNDLE_MANIFEST.json")
CONTRACT_NAME = "winsvpn-release-legal-bundle-v1"
RECEIPT_NAME = "winsvpn-release-legal-compliance-receipt-v1"
SCHEMA_VERSION = 1
OWNER_BLOCKED = "OWNER-BLOCKED: ABSENT"
STORE_RELEASE_LEGAL_COMPLIANCE_BLOCKED = "BLOCKED"
DESIGNATED_SOURCE_ARCHIVE_URL = "https://downloads.winsvpn.org/source/wins-vpn-1.0.17.tar.gz"
INVENTORY_PATH = "docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md"
PROVENANCE_PATH = "docs/AMNEZIAWG_ENGINE_PROVENANCE.md"
PUBSPEC_LOCK_PATH = "pubspec.lock"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_LEGAL_FILE_BYTES = 8 * 1024 * 1024
MAX_NOTICES_COMPRESSED_BYTES = 32 * 1024 * 1024
MAX_NOTICES_TEXT_BYTES = 64 * 1024 * 1024
MAX_AOT_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
MAX_PATH_BYTES = 2048
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"\b[0-9a-f]{40}\b")
HEX64_RE = re.compile(r"\b[0-9a-f]{64}\b")
WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
MIT_COMPLETE_MARKERS = (
    "Copyright",
    "Permission is hereby granted, free of charge",
    "The above copyright notice and this permission notice shall be included",
    'THE SOFTWARE IS PROVIDED "AS IS"',
    "WITHOUT WARRANTY OF ANY KIND",
)
LICENSE_COMPLETE_MARKERS = {
    "licenses/AGPL-3.0-or-later.txt": (
        "GNU AFFERO GENERAL PUBLIC LICENSE",
        "Version 3, 19 November 2007",
        "13. Remote Network Interaction; Use with the GNU General Public License.",
        "END OF TERMS AND CONDITIONS",
        "How to Apply These Terms to Your New Programs",
    ),
    "licenses/Apache-2.0.txt": (
        "Apache License",
        "Version 2.0, January 2004",
        "1. Definitions.",
        "2. Grant of Copyright License.",
        "3. Grant of Patent License.",
        "4. Redistribution.",
        "5. Submission of Contributions.",
        "6. Trademarks.",
        "7. Disclaimer of Warranty.",
        "8. Limitation of Liability.",
        "9. Accepting Warranty or Additional Liability.",
        "END OF TERMS AND CONDITIONS",
    ),
    "licenses/GPL-2.0-amneziawg-tools.txt": (
        "GNU GENERAL PUBLIC LICENSE",
        "Version 2, June 1991",
        "END OF TERMS AND CONDITIONS",
        "How to Apply These Terms to Your New Programs",
        "Ty Coon, President of Vice",
    ),
    "licenses/MIT-amnezia-libxray.txt": MIT_COMPLETE_MARKERS,
    "licenses/MIT-amneziawg-apple.txt": MIT_COMPLETE_MARKERS,
    "licenses/MIT-amneziawg-go.txt": MIT_COMPLETE_MARKERS,
    "licenses/MPL-2.0.txt": (
        "Mozilla Public License Version 2.0",
        "1. Definitions",
        "Exhibit A - Source Code Form License Notice",
        'Exhibit B - "Incompatible With Secondary Licenses" Notice',
    ),
    "licenses/Wintun-Prebuilt-Binaries-License.txt": (
        "Prebuilt Binaries License",
        "LICENSE GRANT",
        "LIMITATION OF LIABILITY",
        "RESERVATION OF RIGHTS",
        "reverse engineer",
    ),
}
LICENSE_MIN_BYTES = {
    "licenses/AGPL-3.0-or-later.txt": 30000,
    "licenses/Apache-2.0.txt": 8000,
    "licenses/GPL-2.0-amneziawg-tools.txt": 15000,
    "licenses/MIT-amnezia-libxray.txt": 800,
    "licenses/MIT-amneziawg-apple.txt": 800,
    "licenses/MIT-amneziawg-go.txt": 800,
    "licenses/MPL-2.0.txt": 15000,
    "licenses/Wintun-Prebuilt-Binaries-License.txt": 4000,
}


class LegalComplianceError(RuntimeError):
    """A release package or canonical legal contract is not acceptable."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LegalComplianceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> Any:
    raise LegalComplianceError(f"non-finite JSON constant is forbidden: {value}")


def _load_json(payload: bytes, label: str) -> Any:
    if len(payload) > MAX_JSON_BYTES:
        raise LegalComplianceError(f"{label} exceeds {MAX_JSON_BYTES} bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegalComplianceError(f"{label} is not UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite_constant,
        )
    except LegalComplianceError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise LegalComplianceError(f"{label} is not valid JSON: {exc}") from exc


def _canonical_json(document: Any) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LegalComplianceError(f"{label} must be a JSON object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        raise LegalComplianceError(f"{label} keys differ: missing={missing} extra={extra}")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise LegalComplianceError(f"{label} must be a non-empty trimmed string")
    return value


def _string_list(value: Any, label: str, *, sorted_required: bool = True) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise LegalComplianceError(f"{label} must be a list of non-empty strings")
    if len(value) != len(set(value)):
        raise LegalComplianceError(f"{label} contains duplicate values")
    if sorted_required and value != sorted(value):
        raise LegalComplianceError(f"{label} must be sorted")
    return value


def _safe_relative_name(raw: str, label: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise LegalComplianceError(f"{label} is empty")
    if "\\" in raw or "\x00" in raw or raw.startswith("/") or WINDOWS_DRIVE_RE.match(raw):
        raise LegalComplianceError(f"{label} is not a safe POSIX relative path: {raw!r}")
    if unicodedata.normalize("NFC", raw) != raw:
        raise LegalComplianceError(f"{label} is not NFC-normalized: {raw!r}")
    if len(raw.encode("utf-8")) > MAX_PATH_BYTES:
        raise LegalComplianceError(f"{label} is too long")
    parts = PurePosixPath(raw).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise LegalComplianceError(f"{label} contains an unsafe path segment: {raw!r}")
    if any(any(ord(character) < 32 for character in part) for part in parts):
        raise LegalComplianceError(f"{label} contains a control character")
    return PurePosixPath(*parts).as_posix()


def _repo_regular_file(repo_root: Path, relative: str, label: str) -> Path:
    safe = _safe_relative_name(relative, label)
    root = repo_root.resolve(strict=True)
    current = root
    for part in PurePosixPath(safe).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise LegalComplianceError(f"{label} is missing: {safe}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise LegalComplianceError(f"{label} traverses a symbolic link: {safe}")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise LegalComplianceError(f"{label} escapes repository root: {safe}") from exc
    if not stat.S_ISREG(resolved.lstat().st_mode):
        raise LegalComplianceError(f"{label} is not a regular file: {safe}")
    return resolved


def _require_contains(haystack: str, needle: str, label: str) -> None:
    if needle not in haystack:
        raise LegalComplianceError(f"{label} omits required marker: {needle}")


def _require_blocked(value: Any, label: str) -> str:
    text = _string(value, label)
    if text != OWNER_BLOCKED:
        raise LegalComplianceError(
            f"{label} must remain {OWNER_BLOCKED} without owner/legal repository evidence"
        )
    return text


def assert_complete_license_text(relative: str, payload: bytes) -> None:
    markers = LICENSE_COMPLETE_MARKERS.get(relative)
    if markers is None:
        return
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegalComplianceError(f"{relative} is not UTF-8 license text") from exc
    minimum = LICENSE_MIN_BYTES.get(relative, 1)
    if len(payload) < minimum:
        raise LegalComplianceError(f"{relative} is truncated below {minimum} bytes")
    for marker in markers:
        if marker not in text:
            raise LegalComplianceError(f"{relative} is missing required license text: {marker}")


def _direct_hosted_runtime_packages(lock_text: str) -> dict[str, str]:
    packages: dict[str, str] = {}
    current: str | None = None
    dependency: str | None = None
    source: str | None = None
    version: str | None = None

    def commit() -> None:
        if current and dependency == "direct main" and source == "hosted" and version:
            packages[current] = version

    for line in lock_text.splitlines():
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            commit()
            current = line.strip()[:-1]
            dependency = None
            source = None
            version = None
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("dependency:"):
            dependency = stripped.split(":", 1)[1].strip().strip('"')
        elif stripped.startswith("source:"):
            source = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("version:"):
            version = stripped.split(":", 1)[1].strip().strip('"')
    commit()
    if not packages:
        raise LegalComplianceError("pubspec.lock has no direct hosted runtime packages")
    return packages


def _inventory_version(text: str) -> str:
    match = re.search(r"(?m)^Version:\s*(\S+)\s*$", text)
    if match is None:
        raise LegalComplianceError("component inventory is missing a Version line")
    return match.group(1)


def _tools_source_tarball(provenance: str) -> tuple[str, str]:
    match = re.search(
        r"amneziawg-tools GitHub source tarball\s+`([^`]+)`\s+- sha256 `([0-9a-f]{64})`",
        provenance,
    )
    if match is None:
        raise LegalComplianceError(
            "engine provenance is missing the amneziawg-tools source tarball digest"
        )
    return match.group(1), match.group(2)


def _tools_linux_archive_hash(inventory: str) -> str:
    match = re.search(
        r"AmneziaWG tools[\s\S]*?release archive SHA-256 `([0-9a-f]{64})`",
        inventory,
    )
    if match is None:
        raise LegalComplianceError("component inventory is missing the amneziawg-tools archive digest")
    return match.group(1)


@dataclass(frozen=True)
class Contract:
    document: dict[str, Any]
    raw: bytes
    files: dict[str, dict[str, str]]
    platforms: dict[str, dict[str, Any]]
    components: dict[str, dict[str, Any]]


def load_contract(repo_root: Path = REPO_ROOT) -> Contract:
    path = _repo_regular_file(repo_root, CONTRACT_PATH.as_posix(), "legal contract")
    raw = path.read_bytes()
    document = _load_json(raw, "legal contract")
    top = _exact_keys(
        document,
        {
            "app_release",
            "bundle_path",
            "components",
            "contract",
            "files",
            "flutter_notice_markers",
            "owner_legal_approval",
            "platforms",
            "publication_evidence",
            "schema_version",
        },
        "legal contract",
    )
    if top["contract"] != CONTRACT_NAME or top["schema_version"] != SCHEMA_VERSION:
        raise LegalComplianceError("legal contract identity or schema version is unsupported")
    release = _string(top["app_release"], "app_release")
    pubspec = _repo_regular_file(repo_root, "pubspec.yaml", "pubspec").read_text("utf-8")
    match = re.search(r"(?m)^version:\s*([^\s]+)\s*$", pubspec)
    if match is None or match.group(1) != release:
        raise LegalComplianceError("legal contract app_release differs from pubspec.yaml")
    if top["bundle_path"] != CONTRACT_PATH.as_posix():
        raise LegalComplianceError("legal contract bundle_path is not canonical")

    files = top["files"]
    if not isinstance(files, dict) or not files:
        raise LegalComplianceError("legal contract files must be a non-empty object")
    if list(files) != sorted(files):
        raise LegalComplianceError("legal contract file keys must be sorted")
    for package_path, raw_record in files.items():
        _safe_relative_name(package_path, "legal package path")
        record = _exact_keys(raw_record, {"repository_source", "sha256"}, package_path)
        source_name = _string(record["repository_source"], f"{package_path} source")
        expected = _string(record["sha256"], f"{package_path} sha256")
        if SHA256_RE.fullmatch(expected) is None:
            raise LegalComplianceError(f"{package_path} sha256 is malformed")
        source = _repo_regular_file(repo_root, source_name, f"{package_path} source")
        payload = source.read_bytes()
        actual = _sha256(payload)
        if actual != expected:
            raise LegalComplianceError(
                f"canonical legal source changed without contract refresh: {source_name}"
            )
        assert_complete_license_text(package_path, payload)

    platforms = top["platforms"]
    components = top["components"]
    if not isinstance(platforms, dict) or not platforms or list(platforms) != sorted(platforms):
        raise LegalComplianceError("platform contracts must be a non-empty sorted object")
    if not isinstance(components, dict) or not components or list(components) != sorted(components):
        raise LegalComplianceError("component contracts must be a non-empty sorted object")
    platform_names = set(platforms)
    for component_name, raw_record in components.items():
        record = _exact_keys(raw_record, {"identity", "license", "platforms", "repository"}, component_name)
        _string(record["identity"], f"{component_name} identity")
        _string(record["license"], f"{component_name} license")
        _string(record["repository"], f"{component_name} repository")
        declared = _string_list(record["platforms"], f"{component_name} platforms")
        if not set(declared) <= platform_names:
            raise LegalComplianceError(f"{component_name} declares an unknown platform")

    for platform, raw_record in platforms.items():
        record = _exact_keys(
            raw_record,
            {
                "forbidden_components",
                "forbidden_in_app_markers",
                "in_app_markers",
                "required_components",
                "required_files",
                "requires_flutter_notices",
            },
            platform,
        )
        forbidden = set(_string_list(record["forbidden_components"], f"{platform} forbidden_components"))
        _string_list(
            record["forbidden_in_app_markers"],
            f"{platform} forbidden_in_app_markers",
            sorted_required=False,
        )
        required = set(_string_list(record["required_components"], f"{platform} required_components"))
        required_files = set(_string_list(record["required_files"], f"{platform} required_files"))
        _string_list(record["in_app_markers"], f"{platform} in_app_markers", sorted_required=False)
        if not isinstance(record["requires_flutter_notices"], bool):
            raise LegalComplianceError(f"{platform} requires_flutter_notices must be Boolean")
        if forbidden & required:
            raise LegalComplianceError(f"{platform} both requires and forbids a component")
        if not required <= set(components) or not forbidden <= set(components):
            raise LegalComplianceError(f"{platform} references an unknown component")
        if not required_files <= set(files):
            raise LegalComplianceError(f"{platform} references an unknown legal file")
        for component_name in required:
            if platform not in components[component_name]["platforms"]:
                raise LegalComplianceError(
                    f"{platform} requires {component_name}, but component platform map disagrees"
                )
        for component_name in forbidden:
            if platform in components[component_name]["platforms"]:
                raise LegalComplianceError(
                    f"{platform} forbids {component_name}, but component platform map claims it"
                )

    markers = _string_list(top["flutter_notice_markers"], "flutter_notice_markers")
    if "flutter-dart-runtime" not in components:
        raise LegalComplianceError("flutter-dart-runtime component is missing")
    lock_path = _repo_regular_file(repo_root, PUBSPEC_LOCK_PATH, "pubspec.lock")
    lock_bytes = lock_path.read_bytes()
    lock_hash = _sha256(lock_bytes)
    flutter_identity = _string(
        components["flutter-dart-runtime"]["identity"], "flutter-dart-runtime identity"
    )
    lock_match = re.fullmatch(
        r"pubspec.lock sha256 ([0-9a-f]{64}) plus package NOTICES.Z",
        flutter_identity,
    )
    if lock_match is None:
        raise LegalComplianceError("flutter-dart-runtime identity is not bound to pubspec.lock")
    if lock_match.group(1) != lock_hash:
        raise LegalComplianceError("flutter-dart-runtime identity does not match pubspec.lock")
    try:
        lock_text = lock_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegalComplianceError("pubspec.lock is not UTF-8") from exc
    direct_packages = _direct_hosted_runtime_packages(lock_text)
    expected_markers = sorted(direct_packages)
    if markers != expected_markers:
        raise LegalComplianceError(
            "flutter_notice_markers must be the exact sorted direct hosted runtime packages: "
            f"{expected_markers}"
        )

    owner = _exact_keys(
        top["owner_legal_approval"],
        {
            "company_rights_chain",
            "copyleft_license_election",
            "proprietary_license",
            "status",
        },
        "owner_legal_approval",
    )
    for key, value in owner.items():
        _require_blocked(value, f"owner_legal_approval.{key}")
    publication = _exact_keys(
        top["publication_evidence"],
        {
            "live_source_archive",
            "source_archive_sha256",
            "source_archive_url",
            "status",
        },
        "publication_evidence",
    )
    for key in ("live_source_archive", "source_archive_sha256", "status"):
        _require_blocked(publication[key], f"publication_evidence.{key}")
    archive_url = _string(publication["source_archive_url"], "publication_evidence.source_archive_url")
    if archive_url != DESIGNATED_SOURCE_ARCHIVE_URL:
        raise LegalComplianceError("publication_evidence.source_archive_url is not the designated archive")

    inventory_text = _repo_regular_file(repo_root, INVENTORY_PATH, "component inventory").read_text("utf-8")
    inventory_version = _inventory_version(inventory_text)
    provenance_text = _repo_regular_file(repo_root, PROVENANCE_PATH, "engine provenance").read_text("utf-8")
    tools_url, tools_hash = _tools_source_tarball(provenance_text)
    linux_tools_hash = _tools_linux_archive_hash(inventory_text)
    notices = _repo_regular_file(
        repo_root, "legal/release/THIRD_PARTY_RUNTIME_NOTICES.txt", "runtime notices"
    ).read_text("utf-8")
    proprietary_license = _repo_regular_file(
        repo_root, "legal/release/WINS_VPN_SOFTWARE_LICENSE.txt", "proprietary software license"
    ).read_text("utf-8")
    source_offer = _repo_regular_file(repo_root, "legal/release/SOURCE_OFFER.txt", "source offer").read_text(
        "utf-8"
    )
    evidence_text = inventory_text + "\n" + provenance_text
    for marker in (inventory_version, release, OWNER_BLOCKED, lock_hash, linux_tools_hash, "v26.9.30"):
        _require_contains(notices, marker, "runtime notices")
    for package_name, package_version in direct_packages.items():
        _require_contains(notices, f"{package_name} {package_version}", "runtime notices")
    for component_name, raw_record in components.items():
        identity = raw_record["identity"]
        for commit in COMMIT_RE.findall(identity):
            _require_contains(evidence_text, commit, "component inventory or engine provenance")
            _require_contains(notices, commit, "runtime notices")
    _require_contains(proprietary_license, OWNER_BLOCKED, "proprietary software license")
    _require_contains(proprietary_license, "Win Empire LLC", "proprietary software license")
    normalized_offer = " ".join(source_offer.split())
    for marker in (
        "AGPL-3.0",
        "three years",
        "any third party",
        "MPL-2.0",
        archive_url,
        "77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3",
        OWNER_BLOCKED,
        inventory_version,
        release,
        tools_url,
        tools_hash,
    ):
        if marker not in normalized_offer:
            raise LegalComplianceError(f"canonical source offer omits required marker: {marker}")
    for phrase in ("is available without charge at",):
        if phrase in normalized_offer:
            raise LegalComplianceError(
                f"source offer asserts unpublished archive as live: {phrase}"
            )
    extra_digests = set(HEX64_RE.findall(source_offer.casefold())) - {tools_hash}
    if extra_digests:
        raise LegalComplianceError(
            "source offer records a source digest without publication evidence: "
            f"{sorted(extra_digests)}"
        )
    return Contract(document, raw, files, platforms, components)


class ArtifactView:
    kind: str
    names: tuple[str, ...]

    def read(self, name: str, maximum: int) -> bytes:
        raise NotImplementedError

    def identity(self) -> tuple[str, int]:
        raise NotImplementedError

    def close(self) -> None:
        pass


def _validate_member_names(raw_names: list[str]) -> tuple[str, ...]:
    if len(raw_names) > MAX_ARCHIVE_MEMBERS:
        raise LegalComplianceError("artifact contains too many members")
    exact: set[str] = set()
    aliases: set[str] = set()
    normalized: list[str] = []
    for raw in raw_names:
        candidate = raw[:-1] if raw.endswith("/") else raw
        if not candidate:
            continue
        safe = _safe_relative_name(candidate, "artifact member")
        alias = safe.casefold()
        if safe in exact or alias in aliases:
            raise LegalComplianceError(f"artifact contains duplicate or aliased member: {safe}")
        exact.add(safe)
        aliases.add(alias)
        normalized.append(safe)
    return tuple(sorted(normalized))


class ZipArtifactView(ArtifactView):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.kind = "zip"
        self.archive = zipfile.ZipFile(path)
        infos: dict[str, zipfile.ZipInfo] = {}
        raw_names: list[str] = []
        total = 0
        for info in self.archive.infolist():
            raw_names.append(info.filename)
            total += info.file_size
            if total > MAX_ARCHIVE_TOTAL_BYTES:
                raise LegalComplianceError("ZIP declared uncompressed size is excessive")
            if info.flag_bits & 0x1:
                raise LegalComplianceError(f"encrypted ZIP member is forbidden: {info.filename}")
            mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise LegalComplianceError(f"ZIP link or special member is forbidden: {info.filename}")
            safe = _safe_relative_name(info.filename[:-1] if info.filename.endswith("/") else info.filename, "ZIP member") if info.filename.rstrip("/") else ""
            if safe and not info.is_dir():
                infos[safe] = info
        _validate_member_names(raw_names)
        self.names = tuple(sorted(infos))
        self.infos = infos

    def read(self, name: str, maximum: int) -> bytes:
        info = self.infos.get(name)
        if info is None or info.is_dir():
            raise LegalComplianceError(f"artifact member is missing: {name}")
        if info.file_size > maximum:
            raise LegalComplianceError(f"artifact member exceeds size limit: {name}")
        payload = self.archive.read(info)
        if len(payload) != info.file_size:
            raise LegalComplianceError(f"artifact member size changed while reading: {name}")
        return payload

    def identity(self) -> tuple[str, int]:
        return _sha256_file(self.path), self.path.stat().st_size

    def close(self) -> None:
        self.archive.close()


class TarArtifactView(ArtifactView):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.kind = "tar"
        self.archive = tarfile.open(path, "r:*")
        members: dict[str, tarfile.TarInfo] = {}
        raw_names: list[str] = []
        total = 0
        for member in self.archive.getmembers():
            raw_names.append(member.name + ("/" if member.isdir() else ""))
            if not member.isfile() and not member.isdir():
                raise LegalComplianceError(f"tar link or special member is forbidden: {member.name}")
            total += member.size
            if total > MAX_ARCHIVE_TOTAL_BYTES:
                raise LegalComplianceError("tar declared uncompressed size is excessive")
            safe = _safe_relative_name(member.name, "tar member")
            if member.isfile():
                members[safe] = member
        _validate_member_names(raw_names)
        self.names = tuple(sorted(members))
        self.members = members

    def read(self, name: str, maximum: int) -> bytes:
        member = self.members.get(name)
        if member is None or member.size > maximum:
            raise LegalComplianceError(f"artifact member is missing or too large: {name}")
        stream = self.archive.extractfile(member)
        if stream is None:
            raise LegalComplianceError(f"artifact member cannot be read: {name}")
        payload = stream.read(maximum + 1)
        if len(payload) != member.size or len(payload) > maximum:
            raise LegalComplianceError(f"artifact member size is invalid: {name}")
        return payload

    def identity(self) -> tuple[str, int]:
        return _sha256_file(self.path), self.path.stat().st_size

    def close(self) -> None:
        self.archive.close()


class DirectoryArtifactView(ArtifactView):
    def __init__(self, path: Path) -> None:
        self.path = path.resolve(strict=True)
        self.kind = "directory"
        files: dict[str, Path] = {}
        raw_names: list[str] = []
        stack = [self.path]
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    metadata = entry.stat(follow_symlinks=False)
                    item = Path(entry.path)
                    relative = item.relative_to(self.path).as_posix()
                    if stat.S_ISLNK(metadata.st_mode):
                        raise LegalComplianceError(f"package directory contains a symbolic link: {relative}")
                    if stat.S_ISDIR(metadata.st_mode):
                        raw_names.append(relative + "/")
                        stack.append(item)
                    elif stat.S_ISREG(metadata.st_mode):
                        raw_names.append(relative)
                        files[_safe_relative_name(relative, "directory member")] = item
                    else:
                        raise LegalComplianceError(f"package directory contains a special file: {relative}")
        _validate_member_names(raw_names)
        self.names = tuple(sorted(files))
        self.files = files

    def read(self, name: str, maximum: int) -> bytes:
        path = self.files.get(name)
        if path is None:
            raise LegalComplianceError(f"artifact member is missing: {name}")
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise LegalComplianceError(f"artifact member is not a bounded regular file: {name}")
        payload = path.read_bytes()
        after = path.lstat()
        if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
            raise LegalComplianceError(f"artifact member changed while reading: {name}")
        return payload

    def identity(self) -> tuple[str, int]:
        digest = hashlib.sha256()
        total = 0
        for name in sorted(self.files):
            payload = self.read(name, MAX_AOT_MEMBER_BYTES)
            encoded = name.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)
            total += len(payload)
        return digest.hexdigest(), total


def open_artifact(path: Path) -> ArtifactView:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise LegalComplianceError(f"artifact is missing: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise LegalComplianceError("artifact path must not be a symbolic link")
    if stat.S_ISDIR(metadata.st_mode):
        return DirectoryArtifactView(path)
    if not stat.S_ISREG(metadata.st_mode):
        raise LegalComplianceError("artifact must be a regular file or directory")
    if zipfile.is_zipfile(path):
        return ZipArtifactView(path)
    if tarfile.is_tarfile(path):
        return TarArtifactView(path)
    raise LegalComplianceError("artifact is not a supported ZIP, tar, or directory package")


def _one_suffix(names: tuple[str, ...], suffix: str, label: str) -> str:
    matches = [name for name in names if name == suffix or name.endswith("/" + suffix)]
    if len(matches) != 1:
        raise LegalComplianceError(f"artifact must contain exactly one {label}; found {len(matches)}")
    return matches[0]


def _gunzip_notices(payload: bytes) -> str:
    if len(payload) > MAX_NOTICES_COMPRESSED_BYTES:
        raise LegalComplianceError("Flutter NOTICES.Z is too large")
    try:
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decompressed = inflater.decompress(payload, MAX_NOTICES_TEXT_BYTES + 1)
        if inflater.unconsumed_tail or len(decompressed) > MAX_NOTICES_TEXT_BYTES:
            raise LegalComplianceError("Flutter NOTICES.Z expands beyond the limit")
        decompressed += inflater.flush(MAX_NOTICES_TEXT_BYTES + 1 - len(decompressed))
    except zlib.error as exc:
        raise LegalComplianceError("Flutter NOTICES.Z is not valid gzip") from exc
    if (
        len(decompressed) > MAX_NOTICES_TEXT_BYTES
        or not inflater.eof
        or inflater.unused_data
    ):
        raise LegalComplianceError("Flutter NOTICES.Z expands beyond the limit")
    try:
        return decompressed.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegalComplianceError("Flutter NOTICES.Z does not contain UTF-8 notices") from exc


def _verify_flutter_notice_blocks(notices_text: str, markers: list[str]) -> None:
    separator = "\n--------------------------------------------------------------------------------\n"
    blocks = notices_text.split(separator)
    for marker in markers:
        matches: list[str] = []
        for block in blocks:
            header, delimiter, body = block.partition("\n\n")
            if delimiter and marker in header.splitlines():
                matches.append(body)
        if len(matches) != 1:
            raise LegalComplianceError(
                f"Flutter NOTICES.Z must contain exactly one license block for {marker}; found {len(matches)}"
            )
        body = matches[0]
        if len(body.encode("utf-8")) < 256 or "Copyright" not in body:
            raise LegalComplianceError(f"Flutter NOTICES.Z has a truncated license block for {marker}")
        if not any(
            phrase in body
            for phrase in (
                "Apache License",
                "Permission is hereby granted",
                "Redistribution and use in source and binary forms",
            )
        ):
            raise LegalComplianceError(f"Flutter NOTICES.Z has no recognized license grant for {marker}")


def _aot_candidates(names: tuple[str, ...]) -> list[str]:
    candidates: list[str] = []
    for name in names:
        lowered = name.casefold()
        if (
            lowered.endswith("/libapp.so")
            or lowered.endswith("/app.so")
            or lowered.endswith("/app.framework/app")
            or lowered.endswith("/app.framework/versions/a/app")
        ):
            candidates.append(name)
    return candidates


def build_receipt(
    artifact: Path,
    platform: str,
    *,
    repo_root: Path = REPO_ROOT,
    verifier_path: Path | None = None,
) -> dict[str, Any]:
    contract = load_contract(repo_root)
    if platform not in contract.platforms:
        raise LegalComplianceError(f"unsupported platform: {platform}")
    selected = contract.platforms[platform]
    view = open_artifact(artifact)
    try:
        manifest_member = _one_suffix(
            view.names, contract.document["bundle_path"], "canonical legal bundle manifest"
        )
        embedded_manifest = view.read(manifest_member, MAX_JSON_BYTES)
        _load_json(embedded_manifest, "embedded legal bundle manifest")
        if embedded_manifest != contract.raw:
            raise LegalComplianceError("embedded legal bundle manifest is stale or substituted")
        bundle_prefix = manifest_member[: -len("LEGAL_BUNDLE_MANIFEST.json")]
        required_files = selected["required_files"]
        expected_bundle = {bundle_prefix + "LEGAL_BUNDLE_MANIFEST.json"}
        expected_bundle.update(bundle_prefix + relative for relative in required_files)
        actual_bundle = {
            name for name in view.names if name.startswith(bundle_prefix) and name != bundle_prefix.rstrip("/")
        }
        if actual_bundle != expected_bundle:
            missing = sorted(expected_bundle - actual_bundle)
            extra = sorted(actual_bundle - expected_bundle)
            raise LegalComplianceError(
                f"platform legal bundle file set differs: missing={missing} extra={extra}"
            )

        file_receipts: list[dict[str, Any]] = []
        for relative in required_files:
            member = bundle_prefix + relative
            payload = view.read(member, MAX_LEGAL_FILE_BYTES)
            expected_hash = contract.files[relative]["sha256"]
            actual_hash = _sha256(payload)
            if actual_hash != expected_hash:
                raise LegalComplianceError(f"legal file is stale or substituted: {relative}")
            file_receipts.append(
                {
                    "bytes": len(payload),
                    "member": member,
                    "path": relative,
                    "sha256": actual_hash,
                }
            )

        notices_receipt: dict[str, Any] | None = None
        if selected["requires_flutter_notices"]:
            notices_member = _one_suffix(view.names, "flutter_assets/NOTICES.Z", "Flutter NOTICES.Z")
            notices_payload = view.read(notices_member, MAX_NOTICES_COMPRESSED_BYTES)
            notices_text = _gunzip_notices(notices_payload)
            _verify_flutter_notice_blocks(
                notices_text, contract.document["flutter_notice_markers"]
            )
            notices_receipt = {
                "bytes": len(notices_payload),
                "member": notices_member,
                "sha256": _sha256(notices_payload),
                "text_sha256": _sha256(notices_text.encode("utf-8")),
            }
        else:
            notice_matches = [
                name
                for name in view.names
                if name == "flutter_assets/NOTICES.Z" or name.endswith("/flutter_assets/NOTICES.Z")
            ]
            if notice_matches:
                raise LegalComplianceError(
                    f"{platform} package unexpectedly contains Flutter NOTICES.Z and is not the declared narrow companion"
                )

        markers = selected["in_app_markers"]
        marker_receipt: list[str] = []
        forbidden_marker_receipt: list[str] = []
        if markers:
            candidates = _aot_candidates(view.names)
            if not candidates:
                raise LegalComplianceError("Flutter package has no identifiable AOT payload for in-app notice checks")
            payloads = [(name, view.read(name, MAX_AOT_MEMBER_BYTES)) for name in candidates]
            for marker in markers:
                encoded = marker.encode("utf-8")
                missing_from = [name for name, payload in payloads if encoded not in payload]
                if missing_from:
                    raise LegalComplianceError(
                        f"compiled in-app notice marker is missing from {missing_from}: {marker}"
                    )
                marker_receipt.append(marker)
            for marker in selected["forbidden_in_app_markers"]:
                encoded = marker.encode("utf-8")
                present_in = [name for name, payload in payloads if encoded in payload]
                if present_in:
                    raise LegalComplianceError(
                        f"compiled in-app notice falsely claims absent component in {present_in}: {marker}"
                    )
                forbidden_marker_receipt.append(marker)

        artifact_hash, artifact_bytes = view.identity()
        verifier = verifier_path or Path(__file__).resolve()
        verifier_hash = _sha256_file(verifier)
        required_components = {
            name: contract.components[name] for name in selected["required_components"]
        }
        receipt: dict[str, Any] = {
            "artifact": {
                "bytes": artifact_bytes,
                "kind": view.kind,
                "sha256": artifact_hash,
            },
            "bundle": {
                "files": file_receipts,
                "flutter_notices": notices_receipt,
                "forbidden_in_app_markers_absent": forbidden_marker_receipt,
                "in_app_markers": marker_receipt,
                "manifest_member": manifest_member,
                "manifest_sha256": _sha256(contract.raw),
            },
            "components": required_components,
            "contract": RECEIPT_NAME,
            "owner_legal_approval": contract.document["owner_legal_approval"],
            "platform": platform,
            "publication_evidence": contract.document["publication_evidence"],
            "schema_version": SCHEMA_VERSION,
            "store_release_legal_compliance": STORE_RELEASE_LEGAL_COMPLIANCE_BLOCKED,
            "verifier": {
                "contract_manifest_sha256": _sha256(contract.raw),
                "path": "tools/verify_release_legal_compliance.py",
                "sha256": verifier_hash,
            },
        }
        return receipt
    finally:
        view.close()


def verify_receipt(
    artifact: Path,
    platform: str,
    receipt_path: Path,
    *,
    repo_root: Path = REPO_ROOT,
    verifier_path: Path | None = None,
) -> dict[str, Any]:
    receipt_file = _repo_independent_regular_file(receipt_path, "receipt")
    payload = receipt_file.read_bytes()
    document = _load_json(payload, "receipt")
    if payload != _canonical_json(document):
        raise LegalComplianceError("receipt JSON is not canonical")
    expected = build_receipt(
        artifact, platform, repo_root=repo_root, verifier_path=verifier_path
    )
    if document != expected:
        raise LegalComplianceError("receipt does not bind the exact current artifact and legal files")
    return expected


def _repo_independent_regular_file(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise LegalComplianceError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise LegalComplianceError(f"{label} must be a regular non-symbolic file")
    return path


def write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise LegalComplianceError(f"refusing to overwrite receipt path: {path}")
    parent = path.parent
    try:
        metadata = parent.lstat()
    except FileNotFoundError as exc:
        raise LegalComplianceError(f"receipt parent directory is missing: {parent}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise LegalComplianceError("receipt parent must be a real directory")
    payload = _canonical_json(receipt)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _report_blocked_gates(contract: Contract) -> None:
    print(f"owner/legal approval: {contract.document['owner_legal_approval']['status']}")
    print(f"publication evidence: {contract.document['publication_evidence']['status']}")
    print(f"store-release legal compliance: {STORE_RELEASE_LEGAL_COMPLIANCE_BLOCKED}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--platform")
    parser.add_argument("--check-contract", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write-receipt", type=Path)
    group.add_argument("--verify-receipt", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        contract = load_contract()
        if args.check_contract:
            if args.artifact is not None or args.platform is not None or args.write_receipt or args.verify_receipt:
                raise LegalComplianceError("--check-contract cannot be combined with artifact options")
            print(
                f"release legal contract mechanical PASS: {len(contract.files)} files, "
                f"{len(contract.components)} components, {len(contract.platforms)} platforms"
            )
            _report_blocked_gates(contract)
            return 0
        if args.artifact is None or args.platform is None:
            raise LegalComplianceError("--artifact and --platform are required")
        if args.verify_receipt is not None:
            receipt = verify_receipt(args.artifact, args.platform, args.verify_receipt)
        else:
            receipt = build_receipt(args.artifact, args.platform)
            if args.write_receipt is not None:
                write_receipt(args.write_receipt, receipt)
        if args.write_receipt is None and args.verify_receipt is None:
            sys.stdout.buffer.write(_canonical_json(receipt))
        else:
            print(
                f"release legal package mechanical PASS: platform={args.platform} "
                f"sha256={receipt['artifact']['sha256']}"
            )
            _report_blocked_gates(contract)
        return 0
    except (LegalComplianceError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"release legal package FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
