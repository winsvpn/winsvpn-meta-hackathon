#!/usr/bin/env python3
"""Permission-frozen Wear AAB receipt, signer identity, and release gates.

Wear OS is a separate Play form factor of org.winsvpn.app. This tool records
and verifies one exact signed AAB without uploading it. Validation is performed
against private descriptor-stable copies and includes:

  * one complete JAR signer matching the reviewed Android upload certificate
  * a bundletool-decoded Wear manifest and an exact native-library allowlist
  * R8 mapping custody cryptographically bound to the embedded AAB proguard.map
  * exact hashes for the producer, gate tools, pins, and relevant Wear sources

The receipt files are made read-only. That is a permission freeze, not an OS or
external append-only immutability guarantee, and the JSON states that plainly.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, NamedTuple


CONTRACT = "winsvpn-wear-os-signed-aab-receipt-v2"
SCHEMA_VERSION = 2
RECEIPT_NAME = "WEAR_OS_SIGNED_AAB_RECEIPT.json"
SIDECAR_NAME = "WEAR_OS_SIGNED_AAB_RECEIPT.json.sha256"
DEFAULT_REPO = Path(__file__).resolve().parents[2]
UPLOAD_PIN_SOURCE = "tools/build_android_release_macos.sh"
UPLOAD_PIN_VARIABLE = "EXPECTED_UPLOAD_CERTIFICATE_SHA256"
RELEASE_IDENTITY_RELATIVE = "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
PAGE_ALIGNMENT_TOOL = "tools/verify_android_aab_page_alignment.py"
CREATE_RECEIPT_TOOL = "wear_os/tools/create_signed_aab_receipt.py"
PROVENANCE_PATHS = (
    "wear_os/app/build.gradle.kts",
    "wear_os/build.gradle.kts",
    "wear_os/settings.gradle.kts",
    "wear_os/gradle.properties",
    "wear_os/gradle/wrapper/gradle-wrapper.properties",
    "wear_os/gradle/wrapper/gradle-wrapper.jar",
    "wear_os/gradle/dependency-locking/app.lockfile",
    "wear_os/gradle/verification-metadata.xml",
    "wear_os/app/src/main/AndroidManifest.xml",
    "wear_os/app/proguard-rules.pro",
    "wear_os/tools/prepare_release.sh",
    "wear_os/tools/assert_release_aab.py",
    "wear_os/tools/signed_aab_receipt.py",
    CREATE_RECEIPT_TOOL,
    UPLOAD_PIN_SOURCE,
    "tools/private_release_symbol_custody.py",
    "tools/validate_release_artifact_privacy.py",
    "tools/verify_android_aab_signers.py",
    PAGE_ALIGNMENT_TOOL,
    "tools/toolchain-pins.json",
    RELEASE_IDENTITY_RELATIVE,
    "pubspec.yaml",
    "app_store/android/wear/README.md",
    "app_store/android/wear/metadata/en-US/title.txt",
    "app_store/android/wear/metadata/en-US/short_description.txt",
    "app_store/android/wear/metadata/en-US/full_description.txt",
    "app_store/android/wear/metadata/en-US/whats_new.txt",
    "app_store/android/wear/review/play_console_notes.txt",
    "app_store/android/wear/review/data_safety.md",
    "app_store/android/wear/review/privacy_label_manifest.json",
    "app_store/android/wear/review/owner_signoff.json",
    "app_store/android/wear/artifacts/release_candidate.json",
)

PRIVACY_MANIFEST_RELATIVE = "app_store/android/wear/review/privacy_label_manifest.json"
OWNER_SIGNOFF_RELATIVE = "app_store/android/wear/review/owner_signoff.json"
RELEASE_CANDIDATE_RELATIVE = "app_store/android/wear/artifacts/release_candidate.json"
STORE_METADATA_FILES = (
    "app_store/android/wear/README.md",
    "app_store/android/wear/metadata/en-US/title.txt",
    "app_store/android/wear/metadata/en-US/short_description.txt",
    "app_store/android/wear/metadata/en-US/full_description.txt",
    "app_store/android/wear/metadata/en-US/whats_new.txt",
    "app_store/android/wear/review/play_console_notes.txt",
    "app_store/android/wear/review/data_safety.md",
    PRIVACY_MANIFEST_RELATIVE,
    OWNER_SIGNOFF_RELATIVE,
    RELEASE_CANDIDATE_RELATIVE,
)
WEAR_AAB_PATH = "wear_os/app/build/outputs/bundle/release/app-release.aab"

BUILD_ATTEMPT_SWITCH = "--wins-release-dependency-build-attempt-v2"
BUILD_ATTEMPT_CONTRACT = "winsvpn-witnessed-build-attempt-v2"
BUILD_ATTEMPT_ENV_PLATFORM = "wear_os"
BUILD_ATTEMPT_ENV_PREFIX = "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_"
BUILD_ATTEMPT_REQUIRED_ENV = (
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT",
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE",
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT",
    "WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM",
)
BUILD_ATTEMPT_NONCE = re.compile(r"[0-9a-f]{64}\Z")
BUILD_ATTEMPT_OUTPUT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")


class ReceiptError(RuntimeError):
    pass


def _run_native_build_witness(raw_argv: list[str]) -> int:
    """Refuse release-controller adoption until a real AAB builder is bound.

    The ordinary receipt CLI below verifies an already-built AAB. It is not a
    Gradle producer. Writing a JSON witness into an inode named ``*.aab`` would
    therefore relabel metadata as an artifact. The special controller switch
    stays silent and fail-closed until an externally authenticated builder can
    bind frozen inputs, toolchain, signing identity, and the exact AAB bytes.
    """

    try:
        if raw_argv != [BUILD_ATTEMPT_SWITCH]:
            raise ReceiptError("invalid witnessed build-attempt arguments")
        if not sys.flags.isolated or not sys.flags.no_site:
            raise ReceiptError("witnessed build attempt requires isolated Python")

        environment_names = tuple(
            name
            for name in os.environ
            if isinstance(name, str) and name.startswith(BUILD_ATTEMPT_ENV_PREFIX)
        )
        if (
            len(environment_names) != len(set(environment_names))
            or set(environment_names) != set(BUILD_ATTEMPT_REQUIRED_ENV)
        ):
            raise ReceiptError("invalid witnessed build-attempt environment")

        contract = os.environ.get(BUILD_ATTEMPT_REQUIRED_ENV[0])
        nonce = os.environ.get(BUILD_ATTEMPT_REQUIRED_ENV[1])
        output_name = os.environ.get(BUILD_ATTEMPT_REQUIRED_ENV[2])
        platform = os.environ.get(BUILD_ATTEMPT_REQUIRED_ENV[3])
        if contract != BUILD_ATTEMPT_CONTRACT:
            raise ReceiptError("invalid witnessed build-attempt contract")
        if not isinstance(nonce, str) or not BUILD_ATTEMPT_NONCE.fullmatch(nonce):
            raise ReceiptError("invalid witnessed build-attempt nonce")
        if platform != BUILD_ATTEMPT_ENV_PLATFORM:
            raise ReceiptError("invalid witnessed build-attempt platform")
        if (
            not isinstance(output_name, str)
            or not BUILD_ATTEMPT_OUTPUT.fullmatch(output_name)
            or output_name in {".", ".."}
            or os.path.basename(output_name) != output_name
            or "/" in output_name
            or "\\" in output_name
        ):
            raise ReceiptError("invalid witnessed build-attempt output")
    except BaseException:
        return 1
    return 1


CANONICAL_CROSS_STORE_TARGET = "wear-os-aab"
CANONICAL_RELEASE = "1.0.16+33"
CANONICAL_VERSION_NAME = "1.0.16"
CANONICAL_BUILD_NUMBER = 33
WEAR_VERSION_CODE = 3301
EXPECTED_APPLICATION_ID = "org.winsvpn.app"
STALE_TV_PACKAGE = "org.winsvpn.app.tv"
STALE_DEBUG_PACKAGE = "com.example.wins_vpn"
WEAR_RECEIPT_ROOT = ".artifacts/release-build-receipts/wear-os"
OWNER_BUILD_SYSTEM_BLOCKER = "owner/build-system blocker"
OWNER_BLOCKED = "OWNER-BLOCKED"
OPENSSL_ENV = "WINS_RELEASE_OPENSSL"
KEYTOOL_ENV = "WINS_RELEASE_KEYTOOL"
JARSIGNER_ENV = "WINS_RELEASE_JARSIGNER"
SECRET_INVENTORY_ENV = "WINS_RELEASE_SECRET_INVENTORY"
AUTHENTICATED_INVENTORY_SWITCH = "--authenticated-inventory"
DEBUG_SIGNER_MARKER = "android debug"
EXPECTED_MIN_SDK = 30
EXPECTED_TARGET_SDK = 37


class _ExactReleaseTool(NamedTuple):
    """One open, content-bound executable supplied by release custody.

    The narrow contract accepts only an exact absolute path from the named
    environment variable. Tool-path variables and unrelated inherited values
    are never forwarded to child processes.
    """

    environment_name: str
    label: str
    path: Path
    descriptor: int
    identity: tuple[int, int, int, int, int, int, int, int]
    sha256: str


def _tool_stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        stat.S_IMODE(value.st_mode),
        value.st_uid,
        value.st_gid,
    )


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    pread = getattr(os, "pread", None)
    if pread is not None:
        offset = 0
        while True:
            chunk = pread(descriptor, 1024 * 1024, offset)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
            offset += len(chunk)
    original_offset = os.lseek(descriptor, 0, os.SEEK_CUR)
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
    finally:
        os.lseek(descriptor, original_offset, os.SEEK_SET)


def _assert_exact_release_tool(tool: _ExactReleaseTool) -> None:
    if os.environ.get(tool.environment_name) != str(tool.path):
        raise ReceiptError(f"{tool.label} release-custody path was substituted")
    try:
        path_state = os.lstat(tool.path)
    except OSError as error:
        raise ReceiptError(f"{tool.label} release-custody path disappeared") from error
    if stat.S_ISLNK(path_state.st_mode) or not stat.S_ISREG(path_state.st_mode):
        raise ReceiptError(f"{tool.label} release-custody path was substituted")
    if _tool_stat_identity(path_state) != tool.identity:
        raise ReceiptError(f"{tool.label} release-custody identity changed")
    if _sha256_descriptor(tool.descriptor) != tool.sha256:
        raise ReceiptError(f"{tool.label} release-custody executable changed")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        current_descriptor = os.open(tool.path, flags)
    except OSError as error:
        raise ReceiptError(f"{tool.label} release-custody path was substituted") from error
    try:
        current_state = os.fstat(current_descriptor)
        if _tool_stat_identity(current_state) != tool.identity:
            raise ReceiptError(f"{tool.label} release-custody identity changed")
        if _sha256_descriptor(current_descriptor) != tool.sha256:
            raise ReceiptError(f"{tool.label} release-custody executable changed")
    finally:
        os.close(current_descriptor)


@contextmanager
def _exact_release_tool(environment_name: str, label: str) -> Iterator[_ExactReleaseTool]:
    raw_path = os.environ.get(environment_name)
    if not raw_path:
        raise ReceiptError(f"{environment_name} is required for exact {label} custody")
    if raw_path != raw_path.strip():
        raise ReceiptError(f"{environment_name} must be one exact absolute path")
    path = Path(raw_path)
    if not path.is_absolute() or os.path.normpath(raw_path) != raw_path:
        raise ReceiptError(f"{environment_name} must be one exact absolute path")
    try:
        path_state = os.lstat(path)
    except OSError as error:
        raise ReceiptError(f"{label} must be an existing regular executable") from error
    if stat.S_ISLNK(path_state.st_mode) or not stat.S_ISREG(path_state.st_mode):
        raise ReceiptError(f"{label} must be a regular non-symlink executable")
    if not stat.S_IMODE(path_state.st_mode) & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise ReceiptError(f"{label} must be executable")
    if not os.access(path, os.X_OK):
        raise ReceiptError(f"{label} is not executable by the release user")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReceiptError(f"{label} must be a readable regular non-symlink executable") from error
    try:
        opened_state = os.fstat(descriptor)
        if not stat.S_ISREG(opened_state.st_mode):
            raise ReceiptError(f"{label} must be a regular executable")
        if (opened_state.st_dev, opened_state.st_ino) != (path_state.st_dev, path_state.st_ino):
            raise ReceiptError(f"{label} changed while release custody opened it")
        tool = _ExactReleaseTool(
            environment_name=environment_name,
            label=label,
            path=path,
            descriptor=descriptor,
            identity=_tool_stat_identity(opened_state),
            sha256=_sha256_descriptor(descriptor),
        )
        _assert_exact_release_tool(tool)
        yield tool
        _assert_exact_release_tool(tool)
    finally:
        os.close(descriptor)


def _run_exact_release_tool(
    tool: _ExactReleaseTool,
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    _assert_exact_release_tool(tool)
    options: dict[str, Any] = {
        "capture_output": True,
        "check": False,
        "timeout": timeout,
        "env": _safe_gate_environment(),
    }
    if input_bytes is None:
        options["stdin"] = subprocess.DEVNULL
    else:
        options["input"] = input_bytes
    try:
        return subprocess.run([str(tool.path), *arguments], **options)
    finally:
        _assert_exact_release_tool(tool)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _writable(path: Path) -> bool:
    return bool(_mode(path) & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def _same_identity(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )


def _copy_open_file(source_fd: int, destination_fd: int) -> None:
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            view = view[written:]


def _copy_regular_snapshot(source: Path, destination: Path, label: str) -> os.stat_result:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
    except OSError as error:
        raise ReceiptError(f"{label} must be a readable regular non-symlink file: {source}") from error
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ReceiptError(f"{label} must be a regular file: {source}")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            _copy_open_file(source_fd, destination_fd)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        try:
            after = os.lstat(source)
        except OSError as error:
            raise ReceiptError(f"{label} source path disappeared during private staging") from error
        if not _same_identity(before, after):
            raise ReceiptError(f"{label} source path changed during private staging")
        return before
    finally:
        os.close(source_fd)


@contextmanager
def _private_input_snapshots(aab: Path, mapping: Path) -> Iterator[tuple[Path, Path]]:
    with tempfile.TemporaryDirectory(prefix="winsvpn-wear-receipt-") as directory:
        root = Path(directory)
        # The artifact privacy validator accepts a Wear bundle only under its
        # canonical file name and below a wear_os path component, so the private
        # copy carries both.
        staged_directory = root / "wear_os"
        staged_directory.mkdir(mode=0o700)
        staged_aab = staged_directory / "app-release.aab"
        staged_mapping = root / "mapping.txt"
        _copy_regular_snapshot(aab, staged_aab, "Wear AAB")
        _copy_regular_snapshot(mapping, staged_mapping, "R8 mapping")
        yield staged_aab, staged_mapping


def _stable_bytes(path: Path, label: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="winsvpn-wear-evidence-") as directory:
        snapshot = Path(directory) / "evidence"
        _copy_regular_snapshot(path, snapshot, label)
        return snapshot.read_bytes()


def _stable_file_evidence(path: Path, label: str) -> dict[str, Any]:
    data = _stable_bytes(path, label)
    return {
        "name": path.name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _load_py(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ReceiptError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _reviewed_upload_certificate_sha256(repo: Path) -> str:
    source = _stable_bytes(repo / UPLOAD_PIN_SOURCE, "Android upload certificate pin source")
    pattern = re.compile(
        rb'^' + re.escape(UPLOAD_PIN_VARIABLE.encode("ascii")) + rb'="([0-9a-f]{64})"$',
        re.MULTILINE,
    )
    matches = pattern.findall(source)
    if len(matches) != 1:
        raise ReceiptError(
            f"{UPLOAD_PIN_SOURCE} must define exactly one lowercase {UPLOAD_PIN_VARIABLE}"
        )
    return matches[0].decode("ascii")


def _owner_blocked(message: str) -> ReceiptError:
    text = message if message.startswith(f"{OWNER_BLOCKED}:") else f"{OWNER_BLOCKED}: {message}"
    if OWNER_BUILD_SYSTEM_BLOCKER not in text:
        text = f"{text} ({OWNER_BUILD_SYSTEM_BLOCKER})"
    return ReceiptError(text)


def _canonical_release_identity(repo: Path) -> dict[str, Any]:
    try:
        identity = json.loads(
            _stable_bytes(repo / RELEASE_IDENTITY_RELATIVE, "release identity").decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError("Wear release identity map is unreadable") from error
    mappings = identity.get("platform_mappings") if isinstance(identity, dict) else None
    reviewed = mappings.get("wear_os") if isinstance(mappings, dict) else None
    if (
        not isinstance(identity, dict)
        or identity.get("canonical_release") != CANONICAL_RELEASE
        or identity.get("marketing_version") != CANONICAL_VERSION_NAME
        or identity.get("build_number") != CANONICAL_BUILD_NUMBER
        or not isinstance(reviewed, dict)
        or reviewed.get("package") != EXPECTED_APPLICATION_ID
        or reviewed.get("version_name") != CANONICAL_VERSION_NAME
        or reviewed.get("version_code") != WEAR_VERSION_CODE
    ):
        raise ReceiptError("Wear release identity is not the canonical 1.0.16+33 identity.")
    return {
        "canonical_release": CANONICAL_RELEASE,
        "package": EXPECTED_APPLICATION_ID,
        "version_name": CANONICAL_VERSION_NAME,
        "version_code": WEAR_VERSION_CODE,
    }


def _load_json_object(repo: Path, relative: str, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(_stable_bytes(repo / relative, label).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{label} is unreadable") from error
    if not isinstance(payload, dict):
        raise ReceiptError(f"{label} must be one JSON object")
    return payload


def _companion_protocol_claims() -> dict[str, Any]:
    inspector = _load_py(
        Path(__file__).resolve().with_name("assert_release_aab.py"),
        "wear_assert_release_aab_contract",
    )
    contract = inspector.companion_protocol_contract()
    engines = contract.get("forbidden_local_engines")
    if (
        not isinstance(contract, dict)
        or contract.get("executed_on") != "paired-phone"
        or contract.get("local_wear_inclusion") is not False
        or contract.get("local_tunnel") is not False
        or contract.get("primary") != "winn-v3"
        or contract.get("fallback") != ["awg", "xray"]
        or not isinstance(engines, list)
        or "libwinnengine.so" not in engines
        or "libam-go.so" not in engines
        or "libxray.so" not in engines
    ):
        raise ReceiptError("Wear companion protocol contract is malformed")
    return contract


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


def _hold_aab_bytes(path: Path) -> tuple[bytes, tuple[int, int, int, int], str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(path, flags)
    except OSError as error:
        raise ReceiptError(
            f"Wear AAB must be a readable regular non-symlink file: {path}"
        ) from error
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ReceiptError(f"Wear AAB must be a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        if len(data) != before.st_size or not data:
            raise ReceiptError("Wear AAB current bytes could not be held")
        return data, _file_identity(before), hashlib.sha256(data).hexdigest()
    finally:
        os.close(source_fd)


def _revalidate_held_aab(
    path: Path, identity: tuple[int, int, int, int], digest: str
) -> None:
    try:
        after = os.lstat(path)
    except OSError as error:
        raise ReceiptError("Wear AAB origin disappeared during verification") from error
    if _file_identity(after) != identity:
        raise ReceiptError("Wear AAB current bytes changed during inspection")
    held, held_identity, held_digest = _hold_aab_bytes(path)
    if held_identity != identity or held_digest != digest or hashlib.sha256(held).hexdigest() != digest:
        raise ReceiptError("Wear AAB current bytes changed during inspection")


def _signing_claims(
    pins: dict[str, Any],
    certificate_sha256: str,
    expected_certificate: str,
) -> dict[str, Any]:
    return {
        "signer_count": 1,
        "certificate_sha256": certificate_sha256,
        "expected_android_upload_certificate_sha256": expected_certificate,
        "identity_match": True,
        "digest": "SHA-256",
        "package": pins["application_id"],
        "version_name": pins["version_name"],
        "version_code": pins["version_code"],
        "min_sdk": EXPECTED_MIN_SDK,
        "target_sdk": EXPECTED_TARGET_SDK,
    }


def _require_listing_protocol(text: str, label: str) -> None:
    folded = " ".join(text.split())
    if "Winn v3" not in text:
        raise ReceiptError(f"{label} must name Winn v3 as the primary protocol")
    if "AWG then Xray" not in folded and "AWG first" not in folded:
        raise ReceiptError(f"{label} must name Winn v1 AWG then Xray fallback")


def _ascii_text(repo: Path, relative: str, label: str) -> str:
    payload = _stable_bytes(repo / relative, label)
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReceiptError(f"{relative} must be ASCII") from error


def _reviewed_store_metadata(repo: Path) -> dict[str, Any]:
    privacy = _load_json_object(repo, PRIVACY_MANIFEST_RELATIVE, "Wear privacy label")
    signoff = _load_json_object(repo, OWNER_SIGNOFF_RELATIVE, "Wear owner signoff")
    candidate = _load_json_object(repo, RELEASE_CANDIDATE_RELATIVE, "Wear release candidate")
    protocol = _companion_protocol_claims()
    privacy_protocol = privacy.get("phone_tunnel_protocol")
    candidate_protocol = candidate.get("phone_tunnel_protocol")
    title = _ascii_text(
        repo, "app_store/android/wear/metadata/en-US/title.txt", "Wear title"
    ).strip()
    short = _ascii_text(
        repo,
        "app_store/android/wear/metadata/en-US/short_description.txt",
        "Wear short description",
    ).strip()
    listing = _ascii_text(
        repo,
        "app_store/android/wear/metadata/en-US/full_description.txt",
        "Wear listing",
    )
    whats_new = _ascii_text(
        repo,
        "app_store/android/wear/metadata/en-US/whats_new.txt",
        "Wear what's new",
    ).strip()
    notes = _ascii_text(
        repo, "app_store/android/wear/review/play_console_notes.txt", "Wear Play notes"
    )
    safety = _ascii_text(
        repo, "app_store/android/wear/review/data_safety.md", "Wear data safety"
    )
    _require_listing_protocol(listing, "Wear listing")
    _require_listing_protocol(notes, "Wear Play notes")
    _require_listing_protocol(safety, "Wear data safety")
    _require_listing_protocol(whats_new, "Wear what's new")
    if "Winn v3" not in short or "AWG then Xray" not in short:
        raise ReceiptError("Wear short description must name the release protocol")
    if title != "Win's VPN":
        raise ReceiptError("Wear Play listing title is not Win's VPN")
    if len(short) > 80:
        raise ReceiptError("Wear short description exceeds Play's 80-character limit")
    if len(whats_new) > 500:
        raise ReceiptError("Wear what's new exceeds Play's 500-character limit")
    if "https://www.winsvpn.org/privacy/" not in listing:
        raise ReceiptError("Wear listing must name the privacy policy URL")
    if (
        privacy.get("schema_version") != 1
        or privacy.get("contract") != "winsvpn-wear-os-privacy-label-v1"
        or privacy.get("canonical_release") != CANONICAL_RELEASE
        or privacy.get("application_id") != EXPECTED_APPLICATION_ID
        or privacy.get("version_name") != CANONICAL_VERSION_NAME
        or privacy.get("version_code") != WEAR_VERSION_CODE
        or privacy.get("standalone") is not False
        or privacy.get("data_collected") is not False
        or privacy.get("data_shared") is not False
        or privacy.get("off_device_collection") is not False
        or privacy.get("tracking") is not False
        or privacy.get("internet_permission") is not False
        or privacy.get("vpn_service") is not False
        or privacy.get("query_all_packages") is not False
        or privacy.get("account_or_keys_on_watch") is not False
        or privacy.get("pairing") != "wearable-data-layer"
        or privacy.get("watch_launcher_label") != "Calculator"
        or privacy.get("play_listing_name") != "Win's VPN"
        or privacy.get("privacy_policy_url") != "https://www.winsvpn.org/privacy/"
        or privacy.get("listing_screenshot_inventory") != "owner-blocked"
        or not isinstance(privacy_protocol, dict)
        or privacy_protocol.get("executed_on") != protocol["executed_on"]
        or privacy_protocol.get("local_wear_inclusion") is not False
        or privacy_protocol.get("primary") != protocol["primary"]
        or privacy_protocol.get("fallback") != protocol["fallback"]
        or privacy_protocol.get("forbidden_local_engines") != protocol["forbidden_local_engines"]
    ):
        raise ReceiptError("Wear privacy label is not the canonical 1.0.16+33 companion contract.")
    if (
        signoff.get("schema_version") != 1
        or signoff.get("contract") != "winsvpn-wear-os-owner-signoff-v1"
        or signoff.get("canonical_release") != CANONICAL_RELEASE
        or signoff.get("application_id") != EXPECTED_APPLICATION_ID
        or signoff.get("version_name") != CANONICAL_VERSION_NAME
        or signoff.get("version_code") != WEAR_VERSION_CODE
        or signoff.get("form_factor") != "wear-os"
        or signoff.get("standalone") is not False
        or signoff.get("submission_approved") is not False
        or signoff.get("upload_authorized") is not False
        or signoff.get("listing_screenshot_inventory") != "owner-blocked"
    ):
        raise ReceiptError("Wear owner signoff is not the canonical 1.0.16+33 companion contract.")
    artifact = candidate.get("artifact")
    if (
        candidate.get("schema_version") != 1
        or candidate.get("contract") != "winsvpn-wear-os-release-candidate-v1"
        or candidate.get("canonical_release") != CANONICAL_RELEASE
        or candidate.get("target_id") != CANONICAL_CROSS_STORE_TARGET
        or candidate.get("package") != EXPECTED_APPLICATION_ID
        or candidate.get("version_name") != CANONICAL_VERSION_NAME
        or candidate.get("version_code") != WEAR_VERSION_CODE
        or candidate.get("standalone") is not False
        or not isinstance(artifact, dict)
        or artifact.get("path") != WEAR_AAB_PATH
        or artifact.get("build_variant") != "release"
        or artifact.get("obfuscated") is not True
        or artifact.get("debug_artifact_allowed") is not False
        or artifact.get("owner_signing_required") is not True
        or artifact.get("produced") is not False
        or artifact.get("upload_performed") is not False
        or artifact.get("publication_authorized") is not False
        or not isinstance(candidate_protocol, dict)
        or candidate_protocol.get("executed_on") != protocol["executed_on"]
        or candidate_protocol.get("local_wear_inclusion") is not False
        or candidate_protocol.get("primary") != protocol["primary"]
        or candidate_protocol.get("fallback") != protocol["fallback"]
        or candidate_protocol.get("forbidden_local_engines") != protocol["forbidden_local_engines"]
    ):
        raise ReceiptError("Wear release candidate is not the canonical 1.0.16+33 companion contract.")
    files: dict[str, str] = {}
    for relative in STORE_METADATA_FILES:
        payload = _stable_bytes(repo / relative, f"Wear store metadata {relative}")
        try:
            payload.decode("ascii")
        except UnicodeDecodeError as error:
            raise ReceiptError(f"{relative} must be ASCII") from error
        files[relative] = str(
            _stable_file_evidence(repo / relative, f"Wear store metadata {relative}")["sha256"]
        )
    payload = {
        "canonical_release": CANONICAL_RELEASE,
        "application_id": EXPECTED_APPLICATION_ID,
        "version_name": CANONICAL_VERSION_NAME,
        "version_code": WEAR_VERSION_CODE,
        "standalone": False,
        "submission_approved": False,
        "upload_authorized": False,
        "listing_screenshot_inventory": "owner-blocked",
        "companion_protocol": protocol,
        "files": files,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    payload["sha256"] = hashlib.sha256(encoded).hexdigest()
    return payload


def _open_source_identity(path: Path, label: str) -> os.stat_result:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReceiptError(f"{label} must be a readable regular non-symlink file: {path}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ReceiptError(f"{label} must be a regular file: {path}")
        return info
    finally:
        os.close(descriptor)


def _reject_origin_swap(path: Path, before: os.stat_result, label: str) -> None:
    try:
        after = os.lstat(path)
    except OSError as error:
        raise ReceiptError(f"{label} origin disappeared during verification") from error
    if not _same_identity(before, after):
        raise ReceiptError(f"{label} origin was swapped or restored during verification")


def _verify_aab_page_alignment(repo: Path, aab: Path) -> None:
    inspector = _load_py(repo / PAGE_ALIGNMENT_TOOL, "wear_aab_page_alignment")
    try:
        inspector.verify_aab(aab)
    except inspector.AlignmentError as error:
        raise ReceiptError(f"Wear AAB 16 KiB page alignment failed: {error}") from error


def _discover_wear_receipts(repo: Path) -> list[Path]:
    root = repo / WEAR_RECEIPT_ROOT
    if root.is_symlink():
        raise ReceiptError("Wear receipt root must not be a symbolic link")
    if not root.exists():
        return []
    if not root.is_dir():
        raise ReceiptError("Wear receipt root is not a real directory")
    discovered: list[Path] = []
    for child in sorted(root.iterdir()):
        if child.is_symlink() or not child.is_dir():
            continue
        receipt = child / RECEIPT_NAME
        if receipt.is_symlink() or not receipt.is_file():
            continue
        discovered.append(child)
    return discovered


def _reject_receipt_reuse(
    repo: Path, digest: str, *, ignore_dir: Path | None = None
) -> None:
    matching: list[Path] = []
    ignore = ignore_dir.resolve() if ignore_dir is not None else None
    for receipt_dir in _discover_wear_receipts(repo):
        receipt_path = receipt_dir / RECEIPT_NAME
        try:
            info = receipt_path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        if info.st_nlink != 1:
            matching.append(receipt_dir)
            continue
        try:
            payload = _load_receipt(receipt_dir)
        except ReceiptError:
            continue
        artifact = payload.get("artifact")
        if not isinstance(artifact, dict) or artifact.get("sha256") != digest:
            continue
        if ignore is not None and receipt_dir.resolve() == ignore:
            continue
        matching.append(receipt_dir)
    if matching:
        raise ReceiptError(
            "Wear receipt reuse is refused; multiple receipts bind the artifact."
        )


def _receipt_binds_candidate(
    payload: dict[str, Any],
    aab: Path,
    digest: str,
    size: int,
    pins: dict[str, Any],
) -> bool:
    artifact = payload.get("artifact")
    if not isinstance(artifact, dict):
        return False
    if artifact.get("sha256") != digest:
        return False
    if (
        artifact.get("name") != aab.name
        or artifact.get("size_bytes") != size
        or payload.get("canonical_release") != CANONICAL_RELEASE
        or payload.get("application_id") != pins["application_id"]
        or payload.get("version_name") != pins["version_name"]
        or payload.get("version_code") != pins["version_code"]
        or payload.get("platform") != "wear-os"
        or payload.get("play_track") != "wear-os"
        or payload.get("publication_authorized") is not False
        or payload.get("upload_performed") is not False
    ):
        raise ReceiptError(
            "Wear receipt identity does not bind the canonical 1.0.16+33 candidate."
        )
    return True


def _verify_source_closure(repo: Path, payload: dict[str, Any], receipt_dir: Path) -> None:
    source = payload.get("source_freeze")
    dependency = payload.get("dependency_freeze")
    if not isinstance(source, dict) or not isinstance(dependency, dict):
        raise _owner_blocked("Wear source closure does not bind the artifact")
    index_path = dependency.get("index_path")
    if not isinstance(index_path, str) or not index_path or Path(index_path).is_absolute():
        raise _owner_blocked("Wear dependency freeze index is missing")
    try:
        creator = _load_py(
            repo / CREATE_RECEIPT_TOOL,
            "wear_create_signed_aab_receipt_gate",
        )
    except (OSError, ImportError) as error:
        raise ReceiptError("Wear source closure verifier is unavailable") from error
    try:
        creator._reject_self_authorized(source, receipt_dir)
        current_source = creator._bind_source_freeze(repo)
        current_dependency = creator._bind_dependency_freeze(repo, repo / index_path)
    except creator.ReceiptError as error:
        message = str(error)
        if (
            message.startswith("owner-blocked")
            or message.startswith(OWNER_BLOCKED)
            or OWNER_BUILD_SYSTEM_BLOCKER in message
        ):
            raise _owner_blocked(message) from error
        raise ReceiptError(message) from error
    if source != current_source or dependency != current_dependency:
        raise ReceiptError("Wear source closure changed after receipt creation")
    producer = payload.get("producer")
    if not isinstance(producer, dict) or not producer:
        raise _owner_blocked("Wear producer/verifier closure is absent")
    current_producer = creator._producer_bytes(repo, sys.modules[__name__])
    if producer != current_producer:
        raise ReceiptError("Wear producer/verifier closure changed after receipt creation")


def _bind_unique_wear_receipt(
    repo: Path,
    aab: Path,
    digest: str,
    size: int,
    pins: dict[str, Any],
) -> Path:
    matching: list[tuple[Path, dict[str, Any]]] = []
    for receipt_dir in _discover_wear_receipts(repo):
        receipt_path = receipt_dir / RECEIPT_NAME
        try:
            info = receipt_path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        if info.st_nlink != 1:
            raise ReceiptError(
                "Wear receipt reuse is refused; multiple receipts bind the artifact."
            )
        try:
            payload = _load_receipt(receipt_dir)
        except ReceiptError:
            continue
        if not _receipt_binds_candidate(payload, aab, digest, size, pins):
            continue
        matching.append((receipt_dir, payload))
    if not matching:
        raise _owner_blocked(
            "no immutable Wear signed-AAB receipt binds the artifact"
        )
    if len(matching) != 1:
        raise ReceiptError(
            "Wear receipt reuse is refused; multiple receipts bind the artifact."
        )
    receipt_dir, payload = matching[0]
    _verify_source_closure(repo, payload, receipt_dir)
    return receipt_dir


def _require_pin_alignment(repo: Path) -> dict[str, Any]:
    pins = json.loads(_stable_bytes(repo / "tools/toolchain-pins.json", "toolchain pins"))
    tools = pins["tools"]
    gradle = tools["gradle"]["distribution_version"]
    agp = tools["android_gradle_plugin"]["version"]
    kotlin = tools["kotlin"]["version"]
    wrapper = _stable_bytes(
        repo / "wear_os/gradle/wrapper/gradle-wrapper.properties",
        "Wear Gradle wrapper properties",
    ).decode("utf-8")
    if f"gradle-{gradle}-all.zip" not in wrapper:
        raise ReceiptError("Wear Gradle wrapper does not match tools/toolchain-pins.json")
    root_gradle = _stable_bytes(repo / "wear_os/build.gradle.kts", "Wear root Gradle").decode("utf-8")
    if f'id("com.android.application") version "{agp}"' not in root_gradle:
        raise ReceiptError("Wear AGP pin does not match tools/toolchain-pins.json")
    if f'id("org.jetbrains.kotlin.plugin.compose") version "{kotlin}"' not in root_gradle:
        raise ReceiptError("Wear Kotlin pin does not match tools/toolchain-pins.json")
    pubspec = _stable_bytes(repo / "pubspec.yaml", "pubspec").decode("utf-8")
    match = re.search(r"^version:\s*([^+\s]+)\+(\d+)\s*$", pubspec, re.MULTILINE)
    if match is None:
        raise ReceiptError("pubspec.yaml is missing version: <name>+<build>")
    version_name, build = match.group(1), int(match.group(2))
    if (
        version_name != CANONICAL_VERSION_NAME
        or build != CANONICAL_BUILD_NUMBER
        or f"{version_name}+{build}" != CANONICAL_RELEASE
    ):
        raise ReceiptError("Wear pubspec is not the canonical 1.0.16+33 identity.")
    version_code = build * 100 + 1
    if version_code != WEAR_VERSION_CODE:
        raise ReceiptError("Wear versionCode is not the canonical 1.0.16+33 watch identity.")
    reviewed = _canonical_release_identity(repo)
    app_gradle = _stable_bytes(repo / "wear_os/app/build.gradle.kts", "Wear app Gradle").decode("utf-8")
    if f"versionCode = {version_code}" not in app_gradle:
        raise ReceiptError("Wear versionCode does not follow the pubspec watch scheme")
    if f'versionName = "{version_name}"' not in app_gradle:
        raise ReceiptError("Wear versionName does not match pubspec.yaml")
    if f'applicationId = "{EXPECTED_APPLICATION_ID}"' not in app_gradle:
        raise ReceiptError("Wear applicationId is not org.winsvpn.app")
    if re.search(r"applicationIdSuffix\s*=", app_gradle):
        raise ReceiptError("Wear applicationIdSuffix would contaminate the shared Play package")
    if "compileSdk = 37" not in app_gradle or "targetSdk = 37" not in app_gradle:
        raise ReceiptError("Wear compile/target SDK is not the ruled API 37 identity")
    if "minSdk = 30" not in app_gradle:
        raise ReceiptError("Wear minSdk is not the ruled Wear OS 3 identity")
    if "wearReleaseSigningIsOwnerUploadKey" not in app_gradle:
        raise ReceiptError("Wear Gradle is missing the owner-upload-key signing refusal")
    if "OWNER-BLOCKED: missing Android upload keystore" not in app_gradle:
        raise ReceiptError("Wear Gradle does not fail closed as OWNER-BLOCKED without the upload keystore")
    if "debug or test key" not in app_gradle:
        raise ReceiptError("Wear Gradle does not refuse debug or test release keys")
    if 'ndkVersion = "30.0.16248370"' not in app_gradle:
        raise ReceiptError("Wear ndkVersion is not the ruled NDK r30 identity")
    if "isMinifyEnabled = true" not in app_gradle or "isShrinkResources = true" not in app_gradle:
        raise ReceiptError("Wear release R8 minify/resource shrinking is not enabled")
    if (
        f'applicationId = "{STALE_TV_PACKAGE}"' in app_gradle
        or f'applicationId = "{STALE_DEBUG_PACKAGE}"' in app_gradle
    ):
        raise ReceiptError("Wear Gradle contains a contaminated or stale application ID")
    manifest = _stable_bytes(
        repo / "wear_os/app/src/main/AndroidManifest.xml", "Wear source manifest"
    ).decode("utf-8")
    if 'android:name="android.hardware.type.watch"' not in manifest:
        raise ReceiptError("Wear source manifest is missing android.hardware.type.watch")
    if 'android:required="true"' not in manifest:
        raise ReceiptError("Wear source manifest must require android.hardware.type.watch")
    if 'android:name="com.google.android.wearable.standalone"' not in manifest:
        raise ReceiptError("Wear source manifest is missing standalone metadata")
    if 'android:value="false"' not in manifest:
        raise ReceiptError("Wear source manifest must declare a non-standalone companion")
    if "android.permission.INTERNET" in manifest:
        raise ReceiptError("Wear source manifest must not request INTERNET")
    if "QUERY_ALL_PACKAGES" in manifest:
        raise ReceiptError("Wear source manifest must not request QUERY_ALL_PACKAGES")
    if "BIND_VPN_SERVICE" in manifest:
        raise ReceiptError("Wear source manifest must not declare a VPN service")
    if "wearCompanionMustNotPackagePhoneVpnEngines" not in app_gradle:
        raise ReceiptError("Wear Gradle is missing the phone VPN engine packaging refusal")
    return {
        "gradle": gradle,
        "agp": agp,
        "kotlin": kotlin,
        "canonical_release": reviewed["canonical_release"],
        "version_name": version_name,
        "version_code": version_code,
        "application_id": EXPECTED_APPLICATION_ID,
        "standalone": False,
    }


def _provenance(repo: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in PROVENANCE_PATHS:
        evidence = _stable_file_evidence(repo / relative, f"Provenance input {relative}")
        hashes[relative] = str(evidence["sha256"])
    return hashes


def _certificate(aab: Path) -> tuple[str, str]:
    with _exact_release_tool(OPENSSL_ENV, "OpenSSL") as openssl:
        with zipfile.ZipFile(aab) as archive:
            names = archive.namelist()
            blocks = [
                name
                for name in names
                if name.upper().startswith("META-INF/")
                and name.upper().endswith((".RSA", ".DSA", ".EC"))
            ]
            signature_files = [
                name
                for name in names
                if name.upper().startswith("META-INF/") and name.upper().endswith(".SF")
            ]
            if len(blocks) != 1:
                raise ReceiptError("Wear AAB must contain exactly one PKCS#7 signature block")
            if len(signature_files) != 1:
                raise ReceiptError("Wear AAB must contain exactly one signer .SF file")
            if blocks[0].rsplit(".", 1)[0].casefold() != signature_files[0].rsplit(".", 1)[0].casefold():
                raise ReceiptError("Wear AAB signature block and .SF signer names do not match")
            der = archive.read(blocks[0])
            signature_bytes = archive.read(signature_files[0])
        with tempfile.TemporaryDirectory(prefix="winsvpn-wear-signer-") as directory:
            root = Path(directory)
            block_path = root / "signature.der"
            signature_path = root / "signature.sf"
            signer_path = root / "actual-signer.pem"
            verified_path = root / "verified-signature.sf"
            block_path.write_bytes(der)
            signature_path.write_bytes(signature_bytes)
            os.chmod(block_path, 0o600)
            os.chmod(signature_path, 0o600)
            verified = _run_exact_release_tool(
                openssl,
                [
                    "smime",
                    "-verify",
                    "-inform",
                    "DER",
                    "-in",
                    str(block_path),
                    "-content",
                    str(signature_path),
                    "-noverify",
                    "-signer",
                    str(signer_path),
                    "-out",
                    str(verified_path),
                ],
            )
            if verified.returncode != 0 or not signer_path.is_file():
                raise ReceiptError("unable to verify the Wear AAB PKCS#7 signer")
            signer_pem = signer_path.read_bytes()
        if signer_pem.count(b"-----BEGIN CERTIFICATE-----") != 1:
            raise ReceiptError("Wear AAB PKCS#7 block must identify exactly one signing certificate")
        fingerprint = _run_exact_release_tool(
            openssl,
            ["x509", "-noout", "-fingerprint", "-sha256"],
            input_bytes=signer_pem,
        )
        subject = _run_exact_release_tool(
            openssl,
            ["x509", "-noout", "-subject"],
            input_bytes=signer_pem,
        )
        if fingerprint.returncode != 0 or subject.returncode != 0:
            raise ReceiptError("unable to fingerprint Wear AAB signing certificate")
        raw = fingerprint.stdout.decode("ascii", errors="replace")
        if "=" not in raw:
            raise ReceiptError("openssl fingerprint output is unusable")
        digest = raw.split("=", 1)[1].replace(":", "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ReceiptError("Wear AAB certificate SHA-256 is malformed")
        subject_text = subject.stdout.decode("utf-8", errors="replace").strip()
        if DEBUG_SIGNER_MARKER in subject_text.casefold():
            raise ReceiptError("Wear AAB is signed by the Android debug signer")
        return digest, subject_text


def _verify_jar_signature(aab: Path) -> None:
    with _exact_release_tool(JARSIGNER_ENV, "jarsigner") as jarsigner:
        completed = _run_exact_release_tool(jarsigner, ["-verify", str(aab)])
    output = (completed.stdout + completed.stderr).lower()
    if completed.returncode != 0 or b"jar is unsigned" in output or b"jar verified" not in output:
        raise ReceiptError("jarsigner rejected the Wear AAB signature")


def _verify_android_signer_module(signer: Any, aab: Path) -> None:
    with _exact_release_tool(KEYTOOL_ENV, "keytool") as keytool, _exact_release_tool(
        JARSIGNER_ENV, "jarsigner"
    ) as jarsigner:
        # The reviewed signer module (tools/verify_android_aab_signers.py) runs a
        # structural single-signer verification that needs no external tool, so it
        # does not expose the duck-typed `_required_tool` seam. Only patch that
        # seam when the supplied signer actually defines it, and always bind the
        # exact custody keytool/jarsigner paths in its place so verification never
        # falls back to ambient discovery.
        patched_required_tool = hasattr(signer, "_required_tool")
        original_required_tool = getattr(signer, "_required_tool", None)
        original_safe_environment = getattr(signer, "_safe_tool_environment", None)

        def exact_required_tool(name: str) -> str:
            if name == "keytool":
                _assert_exact_release_tool(keytool)
                return str(keytool.path)
            if name == "jarsigner":
                _assert_exact_release_tool(jarsigner)
                return str(jarsigner.path)
            raise ReceiptError(f"unsupported Android signer tool requested: {name}")

        if patched_required_tool:
            signer._required_tool = exact_required_tool
            signer._safe_tool_environment = _safe_gate_environment
        try:
            signer.verify(aab)
        finally:
            if patched_required_tool:
                signer._required_tool = original_required_tool
                signer._safe_tool_environment = original_safe_environment


def _bind_staged_r8_mapping(repo: Path, staged_aab: Path, staged_mapping: Path) -> dict[str, Any]:
    inspector = _load_py(repo / "wear_os/tools/assert_release_aab.py", "wear_assert_release_aab")
    try:
        embedded = inspector.read_embedded_proguard_map(staged_aab)
        external = staged_mapping.read_bytes()
        return inspector.bind_r8_mapping_bytes(external, embedded)
    except inspector.InspectionError as error:
        raise ReceiptError(str(error)) from error


def _custody_claims(mapping: Path, binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "mapping": {
            "name": mapping.name,
            "size_bytes": binding["external_size_bytes"],
            "sha256": binding["external_sha256"],
        },
        "embedded_proguard_map": {
            "path": binding["embedded_path"],
            "size_bytes": binding["embedded_size_bytes"],
            "sha256": binding["embedded_sha256"],
        },
        "binding": {
            "exact_bytes": binding["exact_bytes"],
            "canonicalization": binding["canonicalization"],
            "canonical_sha256": binding["canonical_sha256"],
        },
    }


def _assert_wear_signed_aab(repo: Path, aab: Path) -> dict[str, Any]:
    inspector = _load_py(repo / "wear_os/tools/assert_release_aab.py", "wear_assert_release_aab")
    inspected = inspector.inspect(aab)
    if not inspected.get("ok"):
        raise ReceiptError(
            "Wear form-factor inspector rejected the AAB: "
            + "; ".join(inspected.get("failures") or ["unknown"])
        )
    signer = _load_py(repo / "tools/verify_android_aab_signers.py", "verify_android_aab_signers")
    try:
        _verify_android_signer_module(signer, aab)
    except Exception as error:
        raise ReceiptError(
            f"Wear AAB is not a single complete JAR-signed bundle: {error}"
        ) from error
    _verify_jar_signature(aab)
    return inspected


def _safe_gate_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _gate_environment(arguments: list[str]) -> dict[str, str]:
    environment = _safe_gate_environment()
    if AUTHENTICATED_INVENTORY_SWITCH in arguments:
        # The privacy validator's authenticated exact secret scan reads the
        # inventory this variable names and refuses to run without it. Only the
        # absolute path crosses, never the inventory contents, and no other gate
        # receives it.
        inventory = os.environ.get(SECRET_INVENTORY_ENV, "")
        if inventory:
            environment[SECRET_INVENTORY_ENV] = inventory
    return environment


def _run_gate(arguments: list[str], label: str) -> None:
    completed = subprocess.run(
        arguments,
        capture_output=True,
        check=False,
        timeout=180,
        env=_gate_environment(arguments),
    )
    if completed.returncode != 0:
        raise ReceiptError(f"{label} failed closed")


def _verify_release_gates(repo: Path, aab: Path, symbols_dir: Path) -> dict[str, Any]:
    privacy_tool = repo / "tools/validate_release_artifact_privacy.py"
    custody_tool = repo / "tools/private_release_symbol_custody.py"
    _run_gate(
        [
            sys.executable,
            str(privacy_tool),
            AUTHENTICATED_INVENTORY_SWITCH,
            "--artifact",
            str(aab),
            "--target",
            CANONICAL_CROSS_STORE_TARGET,
        ],
        "Wear release artifact privacy gate",
    )
    _run_gate(
        [
            sys.executable,
            str(custody_tool),
            "verify",
            "--platform",
            "wear-os",
            "--symbols-dir",
            str(symbols_dir),
            "--artifact",
            str(aab),
        ],
        "Wear private symbol custody gate",
    )
    custody_manifest = _stable_file_evidence(
        symbols_dir / "custody-manifest.json", "Wear custody manifest"
    )
    custody_sidecar = _stable_file_evidence(
        symbols_dir / "custody-manifest.sha256", "Wear custody manifest sidecar"
    )
    return {
        "artifact_privacy": {
            "passed": True,
            "artifact_sha256": _sha256_file(aab),
        },
        "private_symbol_custody": {
            "passed": True,
            "manifest_sha256": custody_manifest["sha256"],
            "sidecar_sha256": custody_sidecar["sha256"],
        },
    }


def _write_permission_frozen(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o444,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o444)
    if _writable(path) or path.is_symlink():
        raise ReceiptError(f"failed to permission-freeze receipt file: {path}")


def _gate_claims(
    inspected: dict[str, Any],
    expected_certificate: str,
    external_gates: dict[str, Any],
    mapping_binding: dict[str, Any],
) -> dict[str, Any]:
    decoder = inspected.get("manifest_decoder")
    native = inspected.get("native_libraries")
    if not isinstance(decoder, dict) or not isinstance(native, list):
        raise ReceiptError("Wear inspector did not return structured gate evidence")
    if mapping_binding.get("bound") is not True:
        raise ReceiptError("Wear R8 mapping is not bound to the embedded AAB proguard.map")
    manifest = inspected.get("manifest")
    if (
        not isinstance(manifest, dict)
        or manifest.get("package") != EXPECTED_APPLICATION_ID
        or manifest.get("version_name") != CANONICAL_VERSION_NAME
        or manifest.get("version_code") != WEAR_VERSION_CODE
        or manifest.get("min_sdk") != EXPECTED_MIN_SDK
        or manifest.get("target_sdk") != EXPECTED_TARGET_SDK
        or manifest.get("minify_enabled") is not True
    ):
        raise ReceiptError(
            "Wear AAB identity does not bind the canonical 1.0.16+33 watch identity"
        )
    protocol = _companion_protocol_claims()
    observed = inspected.get("companion_protocol")
    if isinstance(observed, dict) and observed != protocol:
        raise ReceiptError("Wear companion protocol evidence drifted from the reviewed contract")
    forbidden = {str(name).casefold() for name in protocol.get("forbidden_local_engines") or []}
    for item in native:
        if not isinstance(item, dict):
            raise ReceiptError("Wear inspector native evidence is malformed")
        basename = str(item.get("path") or "").replace("\\", "/").rsplit("/", 1)[-1]
        if basename.casefold() in forbidden:
            raise ReceiptError(
                f"Wear AAB receipt cannot bind phone VPN engine {basename}"
            )
    return {
        "structured_wear_manifest": {"passed": True, **decoder},
        "native_library_allowlist": {
            "passed": True,
            "approved_count": inspected.get("approved_native_library_count"),
            "observed_count": len(native),
        },
        "companion_protocol": {"passed": True, **protocol},
        "phone_vpn_engines_absent": True,
        "single_complete_jar_signer": True,
        "package_identity": {
            "passed": True,
            "package": EXPECTED_APPLICATION_ID,
            "version_name": CANONICAL_VERSION_NAME,
            "version_code": WEAR_VERSION_CODE,
            "min_sdk": EXPECTED_MIN_SDK,
            "target_sdk": EXPECTED_TARGET_SDK,
            "minify_enabled": True,
        },
        "reviewed_android_upload_certificate": {
            "passed": True,
            "expected_sha256": expected_certificate,
        },
        "artifact_privacy": external_gates["artifact_privacy"],
        "private_symbol_custody": external_gates["private_symbol_custody"],
        "r8_mapping_bound": {
            "passed": True,
            "external_sha256": mapping_binding["external_sha256"],
            "embedded_sha256": mapping_binding["embedded_sha256"],
            "exact_bytes": mapping_binding["exact_bytes"],
            "canonicalization": mapping_binding["canonicalization"],
            "canonical_sha256": mapping_binding["canonical_sha256"],
        },
        "publication_authorized": False,
    }


def record(repo: Path, aab: Path, mapping: Path, receipt_dir: Path) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    aab = aab.expanduser()
    mapping = mapping.expanduser()
    if aab.suffix.lower() != ".aab":
        raise ReceiptError(f"Wear release artifact must be a .aab: {aab}")
    if receipt_dir.exists() or receipt_dir.is_symlink():
        raise ReceiptError(f"Wear receipt directory must be a new path: {receipt_dir}")
    pins = _require_pin_alignment(repo)
    expected_certificate = _reviewed_upload_certificate_sha256(repo)
    store_metadata = _reviewed_store_metadata(repo)
    _held, held_identity, held_digest = _hold_aab_bytes(aab)
    with _private_input_snapshots(aab, mapping) as (staged_aab, staged_mapping):
        mapping_binding = _bind_staged_r8_mapping(repo, staged_aab, staged_mapping)
        _verify_aab_page_alignment(repo, staged_aab)
        inspected = _assert_wear_signed_aab(repo, staged_aab)
        certificate_sha256, _subject = _certificate(staged_aab)
        if certificate_sha256 != expected_certificate:
            raise ReceiptError("Wear AAB signer does not match the reviewed Android upload certificate")
        external_gates = _verify_release_gates(repo, staged_aab, mapping.parent)
        artifact_evidence = {
            "name": aab.name,
            "size_bytes": staged_aab.stat().st_size,
            "sha256": _sha256_file(staged_aab),
        }
        if artifact_evidence["sha256"] != held_digest:
            raise ReceiptError("Wear AAB current bytes changed during inspection")
        _reject_receipt_reuse(repo, str(artifact_evidence["sha256"]))
        payload = {
            "schema_version": SCHEMA_VERSION,
            "contract": CONTRACT,
            "canonical_release": CANONICAL_RELEASE,
            "platform": "wear-os",
            "play_track": "wear-os",
            "publication_authorized": False,
            "upload_performed": False,
            "application_id": pins["application_id"],
            "version_name": pins["version_name"],
            "version_code": pins["version_code"],
            "standalone": pins["standalone"],
            "artifact": artifact_evidence,
            "signing": _signing_claims(pins, certificate_sha256, expected_certificate),
            "store_metadata": store_metadata,
            "custody": _custody_claims(mapping, mapping_binding),
            "provenance": {
                "gradle": pins["gradle"],
                "agp": pins["agp"],
                "kotlin": pins["kotlin"],
                "files": _provenance(repo),
            },
            "gates": _gate_claims(inspected, expected_certificate, external_gates, mapping_binding),
            "receipt_storage": {
                "protection": "permission-frozen",
                "os_immutability_claimed": False,
                "external_append_only_store_claimed": False,
            },
        }
    _revalidate_held_aab(aab, held_identity, held_digest)
    receipt_dir.mkdir(mode=0o700, parents=False)
    serialized = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_permission_frozen(receipt_dir / RECEIPT_NAME, serialized)
    sidecar = f"{hashlib.sha256(serialized).hexdigest()}  {RECEIPT_NAME}\n".encode("ascii")
    _write_permission_frozen(receipt_dir / SIDECAR_NAME, sidecar)
    os.chmod(receipt_dir, 0o555)
    if _writable(receipt_dir):
        raise ReceiptError("failed to permission-freeze Wear receipt directory")
    return {
        "ok": True,
        "contract": CONTRACT,
        "receipt": str(receipt_dir / RECEIPT_NAME),
        "artifact_sha256": payload["artifact"]["sha256"],
        "certificate_sha256": certificate_sha256,
        "receipt_protection": "permission-frozen",
        "publication_authorized": False,
        "upload_performed": False,
    }


def _load_receipt(receipt_dir: Path) -> dict[str, Any]:
    if receipt_dir.is_symlink() or not receipt_dir.is_dir():
        raise ReceiptError(f"Wear receipt directory is not a real directory: {receipt_dir}")
    if _writable(receipt_dir):
        raise ReceiptError("Wear receipt directory is writable and not permission-frozen")
    receipt_path = receipt_dir / RECEIPT_NAME
    sidecar_path = receipt_dir / SIDECAR_NAME
    for path, label in (
        (receipt_path, "Wear receipt"),
        (sidecar_path, "Wear receipt sidecar"),
    ):
        if path.is_symlink() or not path.is_file():
            raise ReceiptError(f"{label} must be a regular non-symlink file: {path}")
    if _writable(receipt_path) or _writable(sidecar_path):
        raise ReceiptError("Wear receipt files are writable and not permission-frozen")
    serialized = _stable_bytes(receipt_path, "Wear receipt")
    sidecar = _stable_bytes(sidecar_path, "Wear receipt sidecar")
    expected = f"{hashlib.sha256(serialized).hexdigest()}  {RECEIPT_NAME}"
    try:
        observed_sidecar = sidecar.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ReceiptError("Wear receipt sidecar is not ASCII") from error
    if observed_sidecar != expected:
        raise ReceiptError("Wear receipt sidecar does not match receipt bytes")
    try:
        payload = json.loads(serialized.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError(f"Wear receipt is not valid UTF-8 JSON: {error}") from error
    if not isinstance(payload, dict):
        raise ReceiptError("Wear receipt JSON must be an object")
    return payload


def verify(repo: Path, aab: Path, mapping: Path, receipt_dir: Path) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    aab = aab.expanduser()
    mapping = mapping.expanduser()
    payload = _load_receipt(receipt_dir.expanduser())
    if payload.get("contract") != CONTRACT or payload.get("schema_version") != SCHEMA_VERSION:
        raise ReceiptError("Wear receipt contract is unsupported")
    if payload.get("canonical_release") != CANONICAL_RELEASE:
        raise ReceiptError("Wear receipt is not bound to the canonical 1.0.16+33 identity.")
    if payload.get("platform") != "wear-os" or payload.get("play_track") != "wear-os":
        raise ReceiptError("Wear receipt is not bound to the Wear OS Play track")
    if payload.get("publication_authorized") is not False:
        raise ReceiptError("Wear receipt must not authorize Play publication")
    if payload.get("upload_performed") is not False:
        raise ReceiptError("Wear receipt claims an upload; this gate never uploads")
    expected_storage = {
        "protection": "permission-frozen",
        "os_immutability_claimed": False,
        "external_append_only_store_claimed": False,
    }
    if payload.get("receipt_storage") != expected_storage:
        raise ReceiptError("Wear receipt storage claim is unsupported")
    pins = _require_pin_alignment(repo)
    for key in ("application_id", "version_name", "version_code", "standalone"):
        if payload.get(key) != pins[key]:
            raise ReceiptError(f"Wear receipt {key} does not match current source")
    expected_certificate = _reviewed_upload_certificate_sha256(repo)
    store_metadata = _reviewed_store_metadata(repo)
    if payload.get("store_metadata") != store_metadata:
        raise ReceiptError("Wear store metadata changed after receipt creation")
    origin = _open_source_identity(aab, "Wear AAB")
    _held, held_identity, held_digest = _hold_aab_bytes(aab)
    with _private_input_snapshots(aab, mapping) as (staged_aab, staged_mapping):
        artifact = payload.get("artifact")
        if not isinstance(artifact, dict):
            raise ReceiptError("Wear receipt artifact block is missing")
        if artifact != {
            "name": aab.name,
            "size_bytes": staged_aab.stat().st_size,
            "sha256": _sha256_file(staged_aab),
        }:
            raise ReceiptError("Wear AAB no longer matches its permission-frozen receipt")
        if artifact["sha256"] != held_digest:
            raise ReceiptError("Wear AAB current bytes changed during inspection")
        mapping_binding = _bind_staged_r8_mapping(repo, staged_aab, staged_mapping)
        if payload.get("custody") != _custody_claims(mapping, mapping_binding):
            raise ReceiptError("Wear R8 mapping no longer matches its permission-frozen receipt")
        _verify_aab_page_alignment(repo, staged_aab)
        inspected = _assert_wear_signed_aab(repo, staged_aab)
        certificate_sha256, _subject = _certificate(staged_aab)
        if certificate_sha256 != expected_certificate:
            raise ReceiptError("Wear AAB signer does not match the reviewed Android upload certificate")
        signing = payload.get("signing")
        if signing != _signing_claims(pins, certificate_sha256, expected_certificate):
            raise ReceiptError("Wear AAB signing evidence does not match the reviewed identity")
        external_gates = _verify_release_gates(repo, staged_aab, mapping.parent)
        expected_gates = _gate_claims(
            inspected, expected_certificate, external_gates, mapping_binding
        )
        if payload.get("gates") != expected_gates:
            raise ReceiptError("Wear release gate evidence changed after receipt creation")
        _reject_receipt_reuse(repo, str(artifact["sha256"]), ignore_dir=receipt_dir.expanduser())
    _reject_origin_swap(aab, origin, "Wear AAB")
    _revalidate_held_aab(aab, held_identity, held_digest)
    provenance = payload.get("provenance")
    if not isinstance(provenance, dict):
        raise ReceiptError("Wear receipt is missing provenance")
    for key in ("gradle", "agp", "kotlin"):
        if provenance.get(key) != pins[key]:
            raise ReceiptError(f"Wear receipt toolchain {key} drifted from current pins")
    if provenance.get("files") != _provenance(repo):
        raise ReceiptError("Wear source or gate-tool provenance changed after receipt creation")
    return {
        "ok": True,
        "contract": CONTRACT,
        "receipt": str(receipt_dir / RECEIPT_NAME),
        "artifact_sha256": payload["artifact"]["sha256"],
        "certificate_sha256": expected_certificate,
        "receipt_protection": "permission-frozen",
        "publication_authorized": False,
        "upload_performed": False,
    }


def _canonical_gate_artifact(repo: Path, target_id: str, raw_path: str) -> Path:
    if target_id != CANONICAL_CROSS_STORE_TARGET:
        raise ReceiptError(f"unsupported exact Wear upload target: {target_id}")
    relative = Path(raw_path)
    if not raw_path or relative.is_absolute() or ".." in relative.parts:
        raise ReceiptError("cross-store Wear AAB path must be repository-relative and contained")
    candidate = repo / relative
    if candidate.is_symlink():
        raise ReceiptError("cross-store Wear AAB must not be a symbolic link")
    if not candidate.exists():
        raise _owner_blocked("missing Wear signed AAB")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(repo.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ReceiptError("cross-store Wear AAB path is missing or escapes the repository") from error
    if not resolved.is_file() or resolved.suffix.lower() != ".aab" or resolved.stat().st_size == 0:
        raise _owner_blocked("missing Wear signed AAB")
    if _writable(resolved):
        raise ReceiptError("Wear signed AAB is writable and not permission-frozen")
    return resolved


def canonical_gate_verify(repo: Path, target_id: str, raw_path: str) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    aab = _canonical_gate_artifact(repo, target_id, raw_path)
    pins = _require_pin_alignment(repo)
    store_metadata = _reviewed_store_metadata(repo)
    _held, held_identity, held_digest = _hold_aab_bytes(aab)
    origin = _open_source_identity(aab, "Wear AAB")
    symbols_dir = (
        repo
        / ".artifacts/private-release-symbols/wear-os"
        / f"{pins['version_name']}+{pins['version_code']}"
    )
    mapping = symbols_dir / "mapping.txt"
    if mapping.is_symlink() or not mapping.is_file():
        raise _owner_blocked("Wear R8 mapping receipt is absent")
    with _private_input_snapshots(aab, mapping) as (staged_aab, staged_mapping):
        mapping_binding = _bind_staged_r8_mapping(repo, staged_aab, staged_mapping)
        _verify_aab_page_alignment(repo, staged_aab)
        inspected = _assert_wear_signed_aab(repo, staged_aab)
        expected_certificate = _reviewed_upload_certificate_sha256(repo)
        certificate_sha256, _subject = _certificate(staged_aab)
        if certificate_sha256 != expected_certificate:
            raise ReceiptError(
                "Wear AAB signer does not match the reviewed Android upload certificate"
            )
        external_gates = _verify_release_gates(repo, staged_aab, symbols_dir)
        claims = _gate_claims(inspected, expected_certificate, external_gates, mapping_binding)
        digest = _sha256_file(staged_aab)
        size = staged_aab.stat().st_size
        if digest != held_digest:
            raise ReceiptError("Wear AAB current bytes changed during inspection")
    _reject_origin_swap(aab, origin, "Wear AAB")
    _revalidate_held_aab(aab, held_identity, held_digest)
    bound_receipt = _bind_unique_wear_receipt(repo, aab, digest, size, pins)
    _reject_origin_swap(aab, origin, "Wear AAB")
    _revalidate_held_aab(aab, held_identity, held_digest)
    return {
        "ok": True,
        "pending": True,
        "target_id": target_id,
        "artifact": raw_path,
        "artifact_sha256": digest,
        "certificate_sha256": expected_certificate,
        "canonical_release": CANONICAL_RELEASE,
        "application_id": pins["application_id"],
        "version_name": pins["version_name"],
        "version_code": pins["version_code"],
        "min_sdk": EXPECTED_MIN_SDK,
        "target_sdk": EXPECTED_TARGET_SDK,
        "receipt": str(bound_receipt / RECEIPT_NAME),
        "gates": claims,
        "store_metadata": store_metadata,
        "publication_authorized": False,
        "upload_performed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("record", "verify"):
        command = subparsers.add_parser(name)
        command.add_argument("--aab", type=Path, required=True)
        command.add_argument("--mapping", type=Path, required=True)
        command.add_argument("--receipt-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if BUILD_ATTEMPT_SWITCH in raw_argv:
        return _run_native_build_witness(raw_argv)
    try:
        if raw_argv[:1] == ["--verify"]:
            if len(raw_argv) != 3:
                raise ReceiptError(
                    "canonical cross-store usage is exactly --verify <target-id> <artifact-path>"
                )
            result = canonical_gate_verify(DEFAULT_REPO, raw_argv[1], raw_argv[2])
            print(json.dumps(result, sort_keys=True))
            return 0
        args = _parser().parse_args(raw_argv)
        if args.command == "record":
            result = record(args.repo, args.aab, args.mapping, args.receipt_dir)
        else:
            result = verify(args.repo, args.aab, args.mapping, args.receipt_dir)
    except ReceiptError as error:
        print(f"WEAR OS SIGNED AAB RECEIPT: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
