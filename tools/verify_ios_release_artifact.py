#!/usr/bin/env python3
"""Fail-closed verification for the exact iOS xcarchive and exported IPA.

This gate verifies produced bytes. It does not create signing identities,
provisioning profiles, archives, exports, or release receipts.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import fnmatch
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Callable, Iterator, Sequence
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPECTED_APP_BUNDLE_ID = "org.winsvpn.app"
EXPECTED_EXTENSION_BUNDLE_ID = "org.winsvpn.app.PacketTunnel"
EXPECTED_APP_NAME = "Win's VPN"
EXPECTED_EXTENSION_NAME = "Win's VPN Helper"
EXPECTED_WATCH_BUNDLE_ID = "org.winsvpn.app.watchkitapp"
EXPECTED_WATCH_EXECUTABLE = "WinsWatch"
EXPECTED_TEAM_ID = "5YT8H4U72M"
EXPECTED_APP_GROUP = "group.org.winsvpn.app"
EXPECTED_KEYCHAIN_SUFFIX = "org.winsvpn.shared"
EXPECTED_MINIMUM_IOS = "15.0"
EXPECTED_MINIMUM_WATCHOS = "9.0"
# Exact LC_BUILD_VERSION minimum per Watch slice. arm64_32 carries the project's
# WATCHOS_DEPLOYMENT_TARGET; Xcode 27 builds the 64-bit arm64 slice with watchOS
# 26.0 as its floor whatever the deployment target says (vtool, 1.0.16 Watch app).
EXPECTED_MINIMUM_WATCHOS_BY_ARCH = {
    "arm64_32": EXPECTED_MINIMUM_WATCHOS,
    "arm64": "26.0",
}
ARTIFACT_CONTRACT = "winsvpn-ios-release-artifact-v1"
OBFUSCATION_CONTRACT = "winsvpn-release-obfuscation-and-secret-free-v2"
SYMBOL_CUSTODY_CONTRACT = "winsvpn-apple-private-symbol-custody-v1"

MAX_IPA_BYTES = 4 * 1024 * 1024 * 1024
MAX_ZIP_MEMBERS = 20_000
MAX_ZIP_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_ZIP_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024

REQUIRED_WINN3_SYMBOLS = frozenset(
    {
        "WinnTunnelContractVersion",
        "WinnTunnelProtocolVersion",
        "WinnTunnelMaxDatagram",
        "WinnTunnelCreate",
        "WinnTunnelCreateWinn3",
        "WinnTunnelCreateWithCarrier",
        "WinnTunnelWriteInbound",
        "WinnTunnelReadOutbound",
        "WinnTunnelStatusJSON",
        "WinnTunnelClose",
        "WinnTunnelFreeString",
    }
)
REQUIRED_WINN3_BINARY_MARKERS = (
    b"winn-datapath/1+winn3",
    b"winn3_datapath_proof_",
    b"winn3_gate_state",
)
FORBIDDEN_ENTITLEMENTS = frozenset(
    {
        "get-task-allow",
        "com.apple.security.get-task-allow",
        "task_for_pid-allow",
        "dynamic-codesigning",
        "com.apple.private.cs.debugger",
        "com.apple.security.cs.debugger",
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
    }
)
DISTRIBUTION_SIGNING_AUTHORITY = "Apple Distribution:"
# Xcode 27 refuses to archive with Apple Distribution under automatic signing, so the
# xcarchive is signed for development and the App Store export re-signs it. Only the
# exported IPA proves distribution signing; the archive proves the same identity, UUIDs
# and dSYM coverage, and may carry nothing debug-only beyond get-task-allow.
ARCHIVE_SIGNING_AUTHORITY = "Apple Development:"
ARCHIVE_ALLOWED_DEBUG_ENTITLEMENTS = frozenset({"get-task-allow"})
EXPECTED_OBFUSCATION_VERIFICATION = {
    "inspected_artifact_symbol_files_absent": True,
    "inspected_blobs_long_lived_credentials_absent": True,
    "inspected_blobs_sensitive_internal_identifiers_absent": True,
    "inspected_native_debug_sections_absent": True,
    "flutter_obfuscation_flag_required": True,
    "private_flutter_symbols_verified": True,
    "producer_static_contract_verified": True,
    "split_debug_info_flag_required": True,
    "obfuscation_is_not_secret_protection": True,
    "durable_secrets_remain_server_side": True,
    "authenticated_receipt_required": True,
    "apple_dsym_separated": True,
    "apple_strip_style_all_required": True,
}


class VerificationError(RuntimeError):
    """The supplied produced artifact is present but invalid."""


class BlockedError(RuntimeError):
    """Owner-controlled or externally produced material is absent."""


CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]]


def default_command_runner(arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise BlockedError(f"Required native tool is unavailable: {arguments[0]}") from exc


def _run(
    runner: CommandRunner,
    arguments: Sequence[str],
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    completed = runner(arguments)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        ).strip()
        raise VerificationError(
            f"{label} failed" + (f": {detail}" if detail else "")
        )
    return completed


def _sha256_fd(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    os.lseek(descriptor, 0, os.SEEK_SET)
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            raise VerificationError("IPA changed or truncated while it was read")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise VerificationError("IPA grew while it was read")
    return digest.hexdigest()


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclasses.dataclass(frozen=True)
class BoundIPA:
    original: pathlib.Path
    snapshot: pathlib.Path
    size: int
    sha256: str


@contextlib.contextmanager
def bind_ipa(path: pathlib.Path) -> Iterator[BoundIPA]:
    candidate = path.expanduser()
    try:
        before = os.lstat(candidate)
    except FileNotFoundError as exc:
        raise BlockedError(f"Produced iOS IPA is missing: {candidate}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_IPA_BYTES
    ):
        raise VerificationError(
            "IPA must be one bounded regular non-symlink file with no hardlink aliases"
        )
    if candidate.suffix.lower() != ".ipa":
        raise VerificationError(f"Produced iOS artifact must end in .ipa: {candidate}")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if not hasattr(os, "O_NOFOLLOW"):
        raise BlockedError("O_NOFOLLOW is required to bind the exact IPA")
    flags |= os.O_NOFOLLOW
    descriptor = os.open(candidate, flags)
    temporary_root = pathlib.Path(tempfile.mkdtemp(prefix="wins-ios-ipa-bind."))
    snapshot = temporary_root / "artifact.ipa"
    try:
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        expected = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if identity != expected:
            raise VerificationError("IPA was replaced before descriptor binding")
        digest = _sha256_fd(descriptor, opened.st_size)
        os.lseek(descriptor, 0, os.SEEK_SET)
        with snapshot.open("xb") as output:
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise VerificationError("IPA changed while its safe snapshot was copied")
                output.write(chunk)
                remaining -= len(chunk)
            output.flush()
            os.fsync(output.fileno())
        if _sha256_file(snapshot) != digest:
            raise VerificationError("Safe IPA snapshot hash does not match the bound IPA")
        bound = BoundIPA(candidate.resolve(strict=True), snapshot, opened.st_size, digest)
        yield bound
        after = os.lstat(candidate)
        rebound = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if rebound != identity or _sha256_fd(descriptor, opened.st_size) != digest:
            raise VerificationError("IPA changed, moved, or was aliased during verification")
    finally:
        os.close(descriptor)
        shutil.rmtree(temporary_root, ignore_errors=True)


def _safe_zip_name(name: str) -> pathlib.PurePosixPath:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise VerificationError(f"IPA contains an unsafe member name: {name!r}")
    path = pathlib.PurePosixPath(name)
    if any(part in ("", ".", "..") for part in path.parts):
        raise VerificationError(f"IPA contains a non-canonical member name: {name!r}")
    return path


@contextlib.contextmanager
def extract_ipa(snapshot: pathlib.Path) -> Iterator[pathlib.Path]:
    root = pathlib.Path(tempfile.mkdtemp(prefix="wins-ios-ipa-extract."))
    try:
        try:
            archive = zipfile.ZipFile(snapshot)
        except (OSError, zipfile.BadZipFile) as exc:
            raise VerificationError("Produced IPA is not a readable ZIP archive") from exc
        with archive:
            entries = archive.infolist()
            if not entries or len(entries) > MAX_ZIP_MEMBERS:
                raise VerificationError("IPA member count is empty or exceeds the safety bound")
            total = 0
            folded_names: set[str] = set()
            validated: list[tuple[zipfile.ZipInfo, pathlib.PurePosixPath, int]] = []
            for info in entries:
                member = _safe_zip_name(info.filename.rstrip("/") or info.filename)
                folded = member.as_posix().casefold()
                if folded in folded_names:
                    raise VerificationError(
                        f"IPA contains duplicate or case-colliding member: {info.filename}"
                    )
                folded_names.add(folded)
                if info.flag_bits & 0x1:
                    raise VerificationError(f"IPA member is encrypted: {info.filename}")
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if kind == stat.S_IFLNK or kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise VerificationError(
                        f"IPA contains a symlink or special member: {info.filename}"
                    )
                if info.is_dir() and kind == stat.S_IFREG:
                    raise VerificationError(
                        f"IPA directory has a regular-file mode: {info.filename}"
                    )
                if not info.is_dir() and kind == stat.S_IFDIR:
                    raise VerificationError(
                        f"IPA file has a directory mode: {info.filename}"
                    )
                # App Store Connect error 90255: every member must be readable by all users
                # and every directory searchable by them. A member without Unix modes is
                # refused, since its permissions cannot be checked.
                if (
                    info.create_system != 3
                    or not mode & 0o004
                    or (info.is_dir() and not mode & 0o001)
                ):
                    raise VerificationError(
                        "IPA member is not readable by all users "
                        f"(App Store Connect error 90255): {info.filename}"
                    )
                if info.file_size < 0 or info.file_size > MAX_ZIP_MEMBER_BYTES:
                    raise VerificationError(f"IPA member exceeds the size bound: {info.filename}")
                total += info.file_size
                if total > MAX_ZIP_EXPANDED_BYTES:
                    raise VerificationError("IPA expanded size exceeds the safety bound")
                validated.append((info, member, mode))
            for info, member, mode in validated:
                target = root.joinpath(*member.parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                if mode & 0o777:
                    target.chmod(mode & 0o777)
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _safe_tree(root: pathlib.Path, label: str) -> None:
    count = 0
    total = 0
    for path in root.rglob("*"):
        count += 1
        if count > MAX_ZIP_MEMBERS:
            raise VerificationError(f"{label} exceeds the file-count safety bound")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise VerificationError(f"{label} contains a symlink: {path}")
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise VerificationError(f"{label} contains a hardlinked file: {path}")
            total += info.st_size
            if total > MAX_ZIP_EXPANDED_BYTES:
                raise VerificationError(f"{label} exceeds the size safety bound")
        elif not stat.S_ISDIR(info.st_mode):
            raise VerificationError(f"{label} contains a special file: {path}")


def _load_plist(path: pathlib.Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise VerificationError(f"{label} is missing or unsafe: {path}")
    try:
        with path.open("rb") as handle:
            value = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        raise VerificationError(f"{label} is not a valid property list") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{label} root must be a dictionary")
    return value


def _load_json(path: pathlib.Path, label: str, blocked_if_missing: bool) -> dict[str, Any]:
    if not path.exists():
        error = BlockedError if blocked_if_missing else VerificationError
        raise error(f"{label} is missing: {path}")
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise VerificationError(f"{label} must be one regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{label} root must be an object")
    return value


def _codesign_entitlements(
    path: pathlib.Path, label: str, runner: CommandRunner
) -> dict[str, Any]:
    completed = _run(
        runner,
        ["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(path)],
        f"{label} signed-entitlement inspection",
    )
    try:
        value = plistlib.loads(completed.stdout)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise VerificationError(f"{label} signed entitlements are not a plist") from exc
    if not isinstance(value, dict) or not value:
        raise VerificationError(f"{label} signed entitlements are empty")
    return value


def _codesign_identity(
    path: pathlib.Path,
    label: str,
    runner: CommandRunner,
    authority: str = DISTRIBUTION_SIGNING_AUTHORITY,
) -> str:
    completed = _run(
        runner,
        ["/usr/bin/codesign", "--display", "--verbose=4", str(path)],
        f"{label} signing identity inspection",
    )
    text = (completed.stderr + b"\n" + completed.stdout).decode(
        "utf-8", errors="replace"
    )
    authorities = re.findall(r"^Authority=(.+)$", text, re.MULTILINE)
    if not any(value.startswith(authority) for value in authorities):
        raise VerificationError(f"{label} is not signed by {authority.rstrip(':')}")
    teams = re.findall(r"^TeamIdentifier=(.+)$", text, re.MULTILINE)
    if teams != [EXPECTED_TEAM_ID]:
        raise VerificationError(
            f"{label} signing TeamIdentifier {teams!r}, expected {EXPECTED_TEAM_ID!r}"
        )
    return teams[0]


def _profile(path: pathlib.Path, label: str, runner: CommandRunner) -> dict[str, Any]:
    if not path.is_file():
        raise VerificationError(f"{label} embedded.mobileprovision is missing")
    completed = _run(
        runner,
        ["/usr/bin/security", "cms", "-D", "-i", str(path)],
        f"{label} provisioning-profile decode",
    )
    try:
        value = plistlib.loads(completed.stdout)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise VerificationError(f"{label} provisioning profile is not a plist") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{label} provisioning profile root must be a dictionary")
    return value


def _truthy_entitlement(value: object) -> bool:
    return value not in (None, False, "", [], {})


def _reject_debug_entitlements(
    entitlements: dict[str, Any],
    label: str,
    allowed: frozenset[str] = frozenset(),
) -> None:
    forbidden = sorted(
        key
        for key, value in entitlements.items()
        if key not in allowed
        and (
            key in FORBIDDEN_ENTITLEMENTS
            or key.startswith("com.apple.private.")
        )
        and _truthy_entitlement(value)
    )
    if forbidden:
        raise VerificationError(
            f"{label} contains forbidden debug, profiling, or private entitlements: "
            + ", ".join(forbidden)
        )
    if entitlements.get("aps-environment") == "development":
        raise VerificationError(f"{label} contains the development APNs entitlement")
    if entitlements.get("com.apple.developer.icloud-container-environment") == "Development":
        raise VerificationError(f"{label} contains the development iCloud entitlement")


def _matches_profile_value(allowed: object, claimed: str) -> bool:
    if isinstance(allowed, str):
        return fnmatch.fnmatchcase(claimed, allowed)
    if isinstance(allowed, list):
        return any(isinstance(item, str) and fnmatch.fnmatchcase(claimed, item) for item in allowed)
    return False


def _require_release_entitlements(
    entitlements: dict[str, Any],
    profile: dict[str, Any],
    bundle_id: str,
    label: str,
    *,
    distribution: bool = True,
) -> str:
    allowed = frozenset() if distribution else ARCHIVE_ALLOWED_DEBUG_ENTITLEMENTS
    _reject_debug_entitlements(entitlements, f"signed {label}", allowed)
    profile_entitlements = profile.get("Entitlements")
    if not isinstance(profile_entitlements, dict):
        raise VerificationError(f"{label} profile Entitlements dictionary is missing")
    _reject_debug_entitlements(profile_entitlements, f"{label} profile", allowed)
    if distribution and profile.get("ProvisionedDevices") not in (None, []):
        raise VerificationError(f"{label} uses a development or ad hoc provisioning profile")
    if profile.get("ProvisionsAllDevices") is True:
        raise VerificationError(f"{label} uses an enterprise provisioning profile")
    expires = profile.get("ExpirationDate")
    if not isinstance(expires, dt.datetime):
        raise VerificationError(f"{label} profile ExpirationDate is missing")
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=dt.timezone.utc)
    if expires <= dt.datetime.now(dt.timezone.utc):
        raise VerificationError(f"{label} provisioning profile is expired")
    if distribution and profile_entitlements.get("beta-reports-active") is not True:
        raise VerificationError(f"{label} profile is not an App Store distribution profile")

    teams = profile.get("TeamIdentifier")
    if teams != [EXPECTED_TEAM_ID]:
        raise VerificationError(
            f"{label} profile TeamIdentifier {teams!r}, expected [{EXPECTED_TEAM_ID!r}]"
        )
    if entitlements.get("com.apple.developer.team-identifier") != EXPECTED_TEAM_ID:
        raise VerificationError(f"signed {label} team entitlement is invalid")
    application_identifier = entitlements.get("application-identifier")
    if not isinstance(application_identifier, str) or not application_identifier.endswith(
        "." + bundle_id
    ):
        raise VerificationError(f"signed {label} application-identifier is invalid")
    prefix = application_identifier[: -(len(bundle_id) + 1)]
    if not re.fullmatch(r"[A-Z0-9]{10}", prefix):
        raise VerificationError(f"signed {label} application-identifier prefix is invalid")
    prefixes = profile.get("ApplicationIdentifierPrefix")
    if not isinstance(prefixes, list) or prefix not in prefixes:
        raise VerificationError(f"{label} profile does not authorize the App ID prefix")
    if not _matches_profile_value(
        profile_entitlements.get("application-identifier"), application_identifier
    ):
        raise VerificationError(f"{label} profile does not authorize application-identifier")

    network = entitlements.get("com.apple.developer.networking.networkextension")
    if network != ["packet-tunnel-provider"]:
        raise VerificationError(f"signed {label} Network Extension entitlement is not exact")
    profile_network = profile_entitlements.get(
        "com.apple.developer.networking.networkextension"
    )
    if not isinstance(profile_network, list) or "packet-tunnel-provider" not in profile_network:
        raise VerificationError(f"{label} profile does not authorize packet-tunnel-provider")

    app_groups = entitlements.get("com.apple.security.application-groups")
    if app_groups != [EXPECTED_APP_GROUP]:
        raise VerificationError(f"signed {label} App Group entitlement is not exact")
    profile_groups = profile_entitlements.get("com.apple.security.application-groups")
    if not isinstance(profile_groups, list) or EXPECTED_APP_GROUP not in profile_groups:
        raise VerificationError(f"{label} profile does not authorize the App Group")

    expected_keychain_group = f"{prefix}.{EXPECTED_KEYCHAIN_SUFFIX}"
    keychain_groups = entitlements.get("keychain-access-groups")
    if keychain_groups != [expected_keychain_group]:
        raise VerificationError(f"signed {label} keychain access group is not exact")
    allowed_keychain_groups = profile_entitlements.get("keychain-access-groups")
    if not _matches_profile_value(allowed_keychain_groups, expected_keychain_group):
        raise VerificationError(f"{label} profile does not authorize the keychain group")
    return prefix


def _require_watch_release_entitlements(
    entitlements: dict[str, Any],
    profile: dict[str, Any],
    label: str,
    *,
    distribution: bool = True,
) -> str:
    allowed = frozenset() if distribution else ARCHIVE_ALLOWED_DEBUG_ENTITLEMENTS
    _reject_debug_entitlements(entitlements, f"signed {label}", allowed)
    profile_entitlements = profile.get("Entitlements")
    if not isinstance(profile_entitlements, dict):
        raise VerificationError(f"{label} profile Entitlements dictionary is missing")
    _reject_debug_entitlements(profile_entitlements, f"{label} profile", allowed)
    if distribution and profile.get("ProvisionedDevices") not in (None, []):
        raise VerificationError(f"{label} uses a development or ad hoc provisioning profile")
    if profile.get("ProvisionsAllDevices") is True:
        raise VerificationError(f"{label} uses an enterprise provisioning profile")
    expires = profile.get("ExpirationDate")
    if not isinstance(expires, dt.datetime):
        raise VerificationError(f"{label} profile ExpirationDate is missing")
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=dt.timezone.utc)
    if expires <= dt.datetime.now(dt.timezone.utc):
        raise VerificationError(f"{label} provisioning profile is expired")
    if distribution and profile_entitlements.get("beta-reports-active") is not True:
        raise VerificationError(f"{label} profile is not an App Store distribution profile")

    teams = profile.get("TeamIdentifier")
    if teams != [EXPECTED_TEAM_ID]:
        raise VerificationError(
            f"{label} profile TeamIdentifier {teams!r}, expected [{EXPECTED_TEAM_ID!r}]"
        )
    if entitlements.get("com.apple.developer.team-identifier") != EXPECTED_TEAM_ID:
        raise VerificationError(f"signed {label} team entitlement is invalid")
    expected_identifier = f"{EXPECTED_TEAM_ID}.{EXPECTED_WATCH_BUNDLE_ID}"
    application_identifier = entitlements.get("application-identifier")
    if application_identifier != expected_identifier:
        raise VerificationError(f"signed {label} application-identifier is invalid")
    prefixes = profile.get("ApplicationIdentifierPrefix")
    if prefixes != [EXPECTED_TEAM_ID]:
        raise VerificationError(f"{label} profile App ID prefix is invalid")
    profile_identifier = profile_entitlements.get("application-identifier")
    # Development signing may use the team wildcard profile (TEAM.*); the App Store
    # profile must name the Watch App ID exactly.
    if (
        profile_identifier != expected_identifier
        if distribution
        else not _matches_profile_value(profile_identifier, expected_identifier)
    ):
        raise VerificationError(f"{label} profile does not authorize application-identifier")

    allowed_signed_keys = {
        "application-identifier",
        "com.apple.developer.team-identifier",
        "get-task-allow",
        # App Store distribution signing copies the profile's TestFlight flag
        # into the binary; the profile check above already requires it.
        "beta-reports-active",
    }
    unexpected = sorted(
        key
        for key, value in entitlements.items()
        if key not in allowed_signed_keys and _truthy_entitlement(value)
    )
    if unexpected:
        raise VerificationError(
            f"signed {label} has unexpected entitlements: {', '.join(unexpected)}"
        )
    return EXPECTED_TEAM_ID


def _version_tuple(value: str) -> tuple[int, ...]:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", value):
        raise VerificationError(f"Invalid deployment version: {value!r}")
    return tuple(int(part) for part in value.split("."))


def _macho_evidence(
    executable: pathlib.Path,
    label: str,
    runner: CommandRunner,
    expected_platform: str = "IOS",
    expected_minimum: str | dict[str, str] = EXPECTED_MINIMUM_IOS,
) -> tuple[frozenset[str], frozenset[str]]:
    build = _run(
        runner,
        ["/usr/bin/xcrun", "vtool", "-show-build", str(executable)],
        f"{label} Mach-O build-version inspection",
    ).stdout.decode("utf-8", errors="replace")
    pattern = r"\bplatform\s+([A-Z0-9_]+).*?\bminos\s+([0-9]+(?:\.[0-9]+){1,2})"
    sections = re.split(r"\(architecture ([A-Za-z0-9_]+)\):", build)
    if len(sections) > 1:
        records = []
        for arch, body in zip(sections[1::2], sections[2::2]):
            slice_records = re.findall(pattern, body, re.DOTALL)
            if not slice_records:
                raise VerificationError(
                    f"{label} architecture slice {arch!r} has no LC_BUILD_VERSION platform/minos record"
                )
            records.extend((arch, platform, minimum) for platform, minimum in slice_records)
    else:
        records = [(None, platform, minimum) for platform, minimum in re.findall(pattern, build, re.DOTALL)]
    if not records:
        raise VerificationError(f"{label} has no LC_BUILD_VERSION platform/minos record")
    for arch, platform, minimum in records:
        if isinstance(expected_minimum, dict):
            if arch not in expected_minimum:
                raise VerificationError(
                    f"{label} has an unreviewed architecture slice: {arch!r}"
                )
            wanted = expected_minimum[arch]
        else:
            wanted = expected_minimum
        if platform != expected_platform or _version_tuple(minimum) != _version_tuple(wanted):
            raise VerificationError(
                f"{label} Mach-O platform/minos {(platform, minimum)!r}"
                + (f" for {arch}" if arch else "")
                + f", expected ({expected_platform!r}, {wanted!r})"
            )
    if isinstance(expected_minimum, dict):
        # Every reviewed slice must be present exactly once: a universal
        # binary that drops one (or repeats one) is not the reviewed Watch app.
        seen = [arch for arch, _platform, _minimum in records]
        if sorted(seen) != sorted(expected_minimum):
            raise VerificationError(
                f"{label} architecture slices {sorted(seen)!r}, "
                f"expected exactly {sorted(expected_minimum)!r}"
            )
    uuid_text = _run(
        runner,
        ["/usr/bin/xcrun", "dwarfdump", "--uuid", str(executable)],
        f"{label} UUID inspection",
    ).stdout.decode("utf-8", errors="replace")
    uuids = frozenset(value.lower() for value in re.findall(r"UUID:\s+([0-9A-Fa-f-]{36})", uuid_text))
    if not uuids:
        raise VerificationError(f"{label} has no Mach-O UUID")
    return frozenset(minimum for _, _, minimum in records), uuids


def _verify_winn3_runtime(
    executable: pathlib.Path, label: str, runner: CommandRunner
) -> None:
    nm = _run(
        runner,
        ["/usr/bin/xcrun", "nm", "-gU", str(executable)],
        f"{label} Winn v3 symbol inspection",
    ).stdout.decode("utf-8", errors="replace")
    symbols = {parts[-1].lstrip("_") for line in nm.splitlines() if (parts := line.split())}
    missing = sorted(REQUIRED_WINN3_SYMBOLS - symbols)
    if missing:
        raise VerificationError(
            f"{label} is missing required v3-primary runtime symbols: {', '.join(missing)}"
        )
    data = executable.read_bytes()
    missing_markers = [marker.decode("ascii") for marker in REQUIRED_WINN3_BINARY_MARKERS if marker not in data]
    if missing_markers:
        raise VerificationError(
            f"{label} is missing required v3-primary runtime markers: "
            + ", ".join(missing_markers)
        )


def _verify_privacy_manifest(
    produced: pathlib.Path, source: pathlib.Path, label: str
) -> None:
    actual = _load_plist(produced, f"produced {label} PrivacyInfo.xcprivacy")
    expected = _load_plist(source, f"source {label} PrivacyInfo.xcprivacy")
    allowed_keys = {
        "NSPrivacyTracking",
        "NSPrivacyTrackingDomains",
        "NSPrivacyCollectedDataTypes",
        "NSPrivacyAccessedAPITypes",
    }
    if set(actual) - allowed_keys:
        raise VerificationError(f"produced {label} privacy manifest has unexpected keys")
    if actual != expected:
        raise VerificationError(
            f"produced {label} privacy manifest does not match the reviewed source manifest"
        )


@dataclasses.dataclass(frozen=True)
class BundleEvidence:
    app_version: str
    build_number: str
    app_prefix: str
    app_uuids: frozenset[str]
    extension_uuids: frozenset[str]
    watch_uuids: frozenset[str]


def verify_app_bundle(
    app: pathlib.Path,
    label: str,
    runner: CommandRunner = default_command_runner,
    *,
    distribution: bool = True,
) -> BundleEvidence:
    authority = (
        DISTRIBUTION_SIGNING_AUTHORITY if distribution else ARCHIVE_SIGNING_AUTHORITY
    )
    _safe_tree(app, label)
    app_info = _load_plist(app / "Info.plist", f"{label} host Info.plist")
    if app_info.get("CFBundleIdentifier") != EXPECTED_APP_BUNDLE_ID:
        raise VerificationError(f"{label} host bundle identifier is invalid")
    if app_info.get("CFBundlePackageType") != "APPL":
        raise VerificationError(f"{label} host CFBundlePackageType is not APPL")
    if app_info.get("MinimumOSVersion") != EXPECTED_MINIMUM_IOS:
        raise VerificationError(f"{label} host MinimumOSVersion is not {EXPECTED_MINIMUM_IOS}")
    version = str(app_info.get("CFBundleShortVersionString") or "")
    build_number = str(app_info.get("CFBundleVersion") or "")
    if not version or not build_number:
        raise VerificationError(f"{label} host version/build is missing")
    # Owner ruling 2026-10-25: host and Watch apps are named "Win's VPN", the extension
    # "Win's VPN Helper" (the "Calculator" name was refused with ITMS-90129).
    for key in ("CFBundleDisplayName", "CFBundleName"):
        if app_info.get(key) != EXPECTED_APP_NAME:
            raise VerificationError(
                f"{label} host {key}={app_info.get(key)!r}, expected {EXPECTED_APP_NAME!r}"
            )

    expected_watch = app / "Watch/WinsWatch.app"
    watch_apps = sorted(app.rglob("*.app"))
    if watch_apps != [expected_watch]:
        raise VerificationError(
            f"{label} must contain exactly Watch/WinsWatch.app, found {watch_apps!r}"
        )
    watch_info = _load_plist(expected_watch / "Info.plist", f"{label} Watch Info.plist")
    expected_watch_info = {
        "CFBundleIdentifier": EXPECTED_WATCH_BUNDLE_ID,
        "CFBundlePackageType": "APPL",
        "CFBundleExecutable": EXPECTED_WATCH_EXECUTABLE,
        "WKApplication": True,
        "WKCompanionAppBundleIdentifier": EXPECTED_APP_BUNDLE_ID,
        "WKRunsIndependentlyOfCompanionApp": False,
        "CFBundleDisplayName": EXPECTED_APP_NAME,
        "CFBundleName": EXPECTED_APP_NAME,
    }
    for key, expected in expected_watch_info.items():
        if watch_info.get(key) != expected:
            raise VerificationError(
                f"{label} Watch {key}={watch_info.get(key)!r}, expected {expected!r}"
            )
    if str(watch_info.get("CFBundleShortVersionString") or "") != version:
        raise VerificationError(f"{label} Watch version does not match the host")
    if str(watch_info.get("CFBundleVersion") or "") != build_number:
        raise VerificationError(f"{label} Watch build does not match the host")

    plug_ins = app / "PlugIns"
    expected_extension = plug_ins / "PacketTunnel.appex"
    extensions = sorted(app.rglob("*.appex"))
    if extensions != [expected_extension]:
        raise VerificationError(
            f"{label} must contain exactly PlugIns/PacketTunnel.appex, found {extensions!r}"
        )
    extension_info = _load_plist(
        expected_extension / "Info.plist", f"{label} PacketTunnel Info.plist"
    )
    if extension_info.get("CFBundleIdentifier") != EXPECTED_EXTENSION_BUNDLE_ID:
        raise VerificationError(f"{label} PacketTunnel bundle identifier is invalid")
    if not EXPECTED_EXTENSION_BUNDLE_ID.startswith(EXPECTED_APP_BUNDLE_ID + "."):
        raise VerificationError("Expected extension identifier is not contained by the host ID")
    if extension_info.get("CFBundlePackageType") != "XPC!":
        raise VerificationError(f"{label} PacketTunnel CFBundlePackageType is not XPC!")
    for key in ("CFBundleDisplayName", "CFBundleName"):
        if extension_info.get(key) != EXPECTED_EXTENSION_NAME:
            raise VerificationError(
                f"{label} PacketTunnel {key}={extension_info.get(key)!r}, "
                f"expected {EXPECTED_EXTENSION_NAME!r}"
            )
    if extension_info.get("MinimumOSVersion") != EXPECTED_MINIMUM_IOS:
        raise VerificationError(
            f"{label} PacketTunnel MinimumOSVersion is not {EXPECTED_MINIMUM_IOS}"
        )
    if extension_info.get("WinsReleaseArtifactVerifierContract") != ARTIFACT_CONTRACT:
        raise VerificationError(f"{label} PacketTunnel verifier contract marker is missing")
    if str(extension_info.get("CFBundleShortVersionString") or "") != version:
        raise VerificationError(f"{label} PacketTunnel version does not match the host")
    if str(extension_info.get("CFBundleVersion") or "") != build_number:
        raise VerificationError(f"{label} PacketTunnel build does not match the host")
    extension_point = extension_info.get("NSExtension")
    if not isinstance(extension_point, dict):
        raise VerificationError(f"{label} PacketTunnel NSExtension dictionary is missing")
    if extension_point.get("NSExtensionPointIdentifier") != "com.apple.networkextension.packet-tunnel":
        raise VerificationError(f"{label} PacketTunnel extension point is invalid")
    principal = str(extension_point.get("NSExtensionPrincipalClass") or "")
    if not principal.endswith(".PacketTunnelProvider"):
        raise VerificationError(f"{label} PacketTunnel principal class is invalid")

    _verify_privacy_manifest(
        app / "PrivacyInfo.xcprivacy",
        ROOT / "ios/Runner/PrivacyInfo.xcprivacy",
        "host",
    )
    _verify_privacy_manifest(
        expected_extension / "PrivacyInfo.xcprivacy",
        ROOT / "ios/PacketTunnel/PrivacyInfo.xcprivacy",
        "PacketTunnel",
    )
    _verify_privacy_manifest(
        expected_watch / "PrivacyInfo.xcprivacy",
        ROOT / "ios/WinsWatch Watch App/PrivacyInfo.xcprivacy",
        "Watch",
    )

    app_executable_name = str(app_info.get("CFBundleExecutable") or "")
    extension_executable_name = str(extension_info.get("CFBundleExecutable") or "")
    app_executable = app / app_executable_name
    extension_executable = expected_extension / extension_executable_name
    watch_executable = expected_watch / EXPECTED_WATCH_EXECUTABLE
    for executable, subject in (
        (app_executable, "host executable"),
        (extension_executable, "PacketTunnel executable"),
        (watch_executable, "Watch executable"),
    ):
        if not executable.is_file() or executable.is_symlink():
            raise VerificationError(f"{label} {subject} is missing or unsafe")

    _run(
        runner,
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(expected_extension)],
        f"{label} PacketTunnel signature verification",
    )
    _run(
        runner,
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(expected_watch)],
        f"{label} Watch signature verification",
    )
    _run(
        runner,
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)],
        f"{label} host signature verification",
    )
    _codesign_identity(app, f"{label} host", runner, authority)
    _codesign_identity(expected_extension, f"{label} PacketTunnel", runner, authority)
    _codesign_identity(expected_watch, f"{label} Watch", runner, authority)
    app_entitlements = _codesign_entitlements(app, f"{label} host", runner)
    extension_entitlements = _codesign_entitlements(
        expected_extension, f"{label} PacketTunnel", runner
    )
    watch_entitlements = _codesign_entitlements(expected_watch, f"{label} Watch", runner)
    app_profile = _profile(app / "embedded.mobileprovision", f"{label} host", runner)
    extension_profile = _profile(
        expected_extension / "embedded.mobileprovision", f"{label} PacketTunnel", runner
    )
    watch_profile = _profile(
        expected_watch / "embedded.mobileprovision", f"{label} Watch", runner
    )
    app_prefix = _require_release_entitlements(
        app_entitlements,
        app_profile,
        EXPECTED_APP_BUNDLE_ID,
        f"{label} host",
        distribution=distribution,
    )
    extension_prefix = _require_release_entitlements(
        extension_entitlements,
        extension_profile,
        EXPECTED_EXTENSION_BUNDLE_ID,
        f"{label} PacketTunnel",
        distribution=distribution,
    )
    if extension_prefix != app_prefix:
        raise VerificationError(f"{label} host and PacketTunnel App ID prefixes differ")
    watch_prefix = _require_watch_release_entitlements(
        watch_entitlements, watch_profile, f"{label} Watch", distribution=distribution
    )
    if watch_prefix != app_prefix:
        raise VerificationError(f"{label} host and Watch App ID prefixes differ")

    _, app_uuids = _macho_evidence(app_executable, f"{label} host executable", runner)
    _, extension_uuids = _macho_evidence(
        extension_executable, f"{label} PacketTunnel executable", runner
    )
    _, watch_uuids = _macho_evidence(
        watch_executable,
        f"{label} Watch executable",
        runner,
        "WATCHOS",
        EXPECTED_MINIMUM_WATCHOS_BY_ARCH,
    )
    _verify_winn3_runtime(extension_executable, f"{label} PacketTunnel executable", runner)
    return BundleEvidence(
        version, build_number, app_prefix, app_uuids, extension_uuids, watch_uuids
    )


def _archive_app(archive: pathlib.Path) -> pathlib.Path:
    try:
        info = archive.lstat()
    except FileNotFoundError as exc:
        raise BlockedError(f"Produced iOS xcarchive is missing: {archive}") from exc
    if archive.suffix != ".xcarchive" or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise VerificationError("iOS archive must be a real non-symlink .xcarchive directory")
    _safe_tree(archive, "iOS xcarchive")
    applications = archive / "Products/Applications"
    apps = sorted(applications.glob("*.app"))
    if len(apps) != 1:
        raise VerificationError(f"xcarchive must contain exactly one iOS app, found {apps!r}")
    metadata = _load_plist(archive / "Info.plist", "xcarchive Info.plist")
    if metadata.get("ArchiveVersion") != 2:
        raise VerificationError("xcarchive ArchiveVersion is not 2")
    properties = metadata.get("ApplicationProperties")
    if not isinstance(properties, dict):
        raise VerificationError("xcarchive ApplicationProperties dictionary is missing")
    expected_path = f"Applications/{apps[0].name}"
    expected_metadata = {
        "ApplicationPath": expected_path,
        "CFBundleIdentifier": EXPECTED_APP_BUNDLE_ID,
        "Team": EXPECTED_TEAM_ID,
    }
    for key, expected in expected_metadata.items():
        if properties.get(key) != expected:
            raise VerificationError(
                f"xcarchive ApplicationProperties {key}={properties.get(key)!r}, expected {expected!r}"
            )
    if not str(properties.get("SigningIdentity") or "").startswith(ARCHIVE_SIGNING_AUTHORITY):
        raise VerificationError("xcarchive SigningIdentity is not Apple Development")
    return apps[0]


def _archive_dsym_uuids(
    archive: pathlib.Path, runner: CommandRunner
) -> frozenset[str]:
    dsyms = sorted((archive / "dSYMs").glob("*.dSYM"))
    if len(dsyms) < 3:
        raise VerificationError("xcarchive must contain host, PacketTunnel, and Watch dSYM bundles")
    uuids: set[str] = set()
    for dsym in dsyms:
        output = _run(
            runner,
            ["/usr/bin/xcrun", "dwarfdump", "--uuid", str(dsym)],
            f"xcarchive dSYM UUID inspection for {dsym.name}",
        ).stdout.decode("utf-8", errors="replace")
        uuids.update(value.lower() for value in re.findall(r"UUID:\s+([0-9A-Fa-f-]{36})", output))
    if not uuids:
        raise VerificationError("xcarchive dSYMs contain no Mach-O UUIDs")
    return frozenset(uuids)


def _artifact_record_path(path: pathlib.Path) -> str:
    resolved = path.resolve(strict=True)
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def _inventory(root: pathlib.Path) -> list[dict[str, object]]:
    if not root.is_dir() or root.is_symlink():
        raise VerificationError(f"Private receipt directory is missing or unsafe: {root}")
    records: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise VerificationError(f"Private receipt inventory contains a symlink: {path}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
            raise VerificationError(f"Private receipt inventory contains an unsafe file: {path}")
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": info.st_size,
                "sha256": _sha256_file(path),
            }
        )
    return records


def verify_obfuscation_receipt(
    receipt: pathlib.Path,
    ipa: BoundIPA,
    evidence: BundleEvidence,
    runner: CommandRunner,
) -> None:
    payload = _load_json(receipt, "iOS obfuscation receipt", True)
    required_keys = {
        "schema_version",
        "contract",
        "contract_sha256",
        "platform",
        "app_version",
        "build_number",
        "created_at_utc",
        "private_symbols_not_packaged",
        "verification",
        "artifacts",
        "symbols",
    }
    if set(payload) != required_keys or payload.get("schema_version") != 2:
        raise VerificationError("iOS obfuscation receipt schema is invalid")
    if payload.get("contract") != OBFUSCATION_CONTRACT or payload.get("platform") != "ios":
        raise VerificationError("iOS obfuscation receipt contract/platform is invalid")
    contract_tool = ROOT / "tools/release_obfuscation_contract.py"
    if payload.get("contract_sha256") != _sha256_file(contract_tool):
        raise VerificationError("iOS obfuscation receipt binds another contract source")
    if payload.get("app_version") != evidence.app_version or str(payload.get("build_number")) != evidence.build_number:
        raise VerificationError("iOS obfuscation receipt version/build does not match the IPA")
    if payload.get("private_symbols_not_packaged") is not True:
        raise VerificationError("iOS obfuscation receipt does not assert symbol separation")
    if payload.get("verification") != EXPECTED_OBFUSCATION_VERIFICATION:
        raise VerificationError("iOS obfuscation receipt verification claims are incomplete")
    expected_artifact = {
        "path": _artifact_record_path(ipa.original),
        "size": ipa.size,
        "sha256": ipa.sha256,
    }
    if payload.get("artifacts") != [expected_artifact]:
        raise VerificationError("iOS obfuscation receipt is not bound to the exact IPA")
    expected_symbols = _inventory(receipt.parent)
    expected_symbols = [item for item in expected_symbols if str(item["path"]).endswith(".symbols")]
    if not expected_symbols or payload.get("symbols") != expected_symbols:
        raise VerificationError("iOS obfuscation receipt private symbols do not match")
    if not any(item["path"] == "app.ios-arm64.symbols" for item in expected_symbols):
        raise VerificationError("iOS arm64 Flutter symbol receipt is missing")
    _run(
        runner,
        [
            sys.executable,
            str(contract_tool),
            "verify",
            "--platform",
            "ios",
            "--symbols-dir",
            str(receipt.parent),
            "--manifest",
            str(receipt),
            "--artifact",
            str(ipa.original),
        ],
        "canonical iOS obfuscation receipt verification",
    )


def verify_symbol_custody_receipt(
    receipt: pathlib.Path,
    ipa: BoundIPA,
    evidence: BundleEvidence,
    runner: CommandRunner,
    archive_path: pathlib.Path,
) -> None:
    payload = _load_json(receipt, "iOS symbol-custody receipt", True)
    required_keys = {
        "schema_version",
        "contract",
        "platform",
        "app_version",
        "build_number",
        "created_at_utc",
        "private_symbols_not_packaged",
        "artifact",
        "flutter_symbols",
        "xcarchive_dsyms",
    }
    if set(payload) != required_keys or payload.get("schema_version") != 1:
        raise VerificationError("iOS symbol-custody receipt schema is invalid")
    if payload.get("contract") != SYMBOL_CUSTODY_CONTRACT or payload.get("platform") != "ios":
        raise VerificationError("iOS symbol-custody receipt contract/platform is invalid")
    if payload.get("app_version") != evidence.app_version or str(payload.get("build_number")) != evidence.build_number:
        raise VerificationError("iOS symbol-custody receipt version/build does not match the IPA")
    if payload.get("private_symbols_not_packaged") is not True:
        raise VerificationError("iOS symbol-custody receipt does not assert symbol separation")
    expected_artifact = {
        "filename": ipa.original.name,
        "size": ipa.size,
        "sha256": ipa.sha256,
    }
    if payload.get("artifact") != expected_artifact or receipt.parent.name != ipa.sha256:
        raise VerificationError("iOS symbol-custody receipt is not keyed to the exact IPA")
    flutter_inventory = _inventory(receipt.parent / "flutter")
    dsym_inventory = _inventory(receipt.parent / "dSYMs")
    if payload.get("flutter_symbols") != flutter_inventory:
        raise VerificationError("iOS symbol-custody Flutter inventory does not match")
    if payload.get("xcarchive_dsyms") != dsym_inventory:
        raise VerificationError("iOS symbol-custody dSYM inventory does not match")
    if not any(str(item["path"]).endswith(".symbols") for item in flutter_inventory):
        raise VerificationError("iOS symbol-custody receipt contains no Flutter symbols")
    dwarf_records = [item for item in dsym_inventory if "/DWARF/" in str(item["path"])]
    if len(dwarf_records) < 2 or not any("PacketTunnel" in str(item["path"]) for item in dwarf_records):
        raise VerificationError("iOS symbol-custody receipt lacks host/PacketTunnel DWARF bytes")
    try:
        private_root = receipt.parent.parents[3]
    except IndexError as exc:
        raise VerificationError("iOS symbol-custody receipt path layout is invalid") from exc
    _run(
        runner,
        [
            sys.executable,
            str(ROOT / "tools/apple_release_symbol_custody.py"),
            "verify",
            "--platform",
            "ios",
            "--artifact",
            str(ipa.original),
            # The custody closure binds this xcarchive's inventory; check it.
            "--archive",
            str(archive_path),
            "--private-root",
            str(private_root),
        ],
        "canonical iOS symbol-custody receipt verification",
    )


def verify_release_pair(
    ipa_path: pathlib.Path,
    archive_path: pathlib.Path,
    obfuscation_receipt: pathlib.Path,
    symbol_custody_receipt: pathlib.Path,
    runner: CommandRunner = default_command_runner,
) -> None:
    with bind_ipa(ipa_path) as ipa, extract_ipa(ipa.snapshot) as extracted:
        payload = extracted / "Payload"
        apps = sorted(path for path in payload.glob("*.app") if path.is_dir())
        if len(apps) != 1:
            raise VerificationError(f"IPA must contain exactly one Payload app, found {apps!r}")
        ipa_evidence = verify_app_bundle(apps[0], "exported IPA", runner)
        archive_app = _archive_app(archive_path)
        archive_evidence = verify_app_bundle(
            archive_app, "produced xcarchive", runner, distribution=False
        )
        if ipa_evidence != archive_evidence:
            raise VerificationError("IPA and xcarchive app identity, UUID, or version evidence differs")
        dsym_uuids = _archive_dsym_uuids(archive_path, runner)
        required_uuids = (
            ipa_evidence.app_uuids
            | ipa_evidence.extension_uuids
            | ipa_evidence.watch_uuids
        )
        if not required_uuids.issubset(dsym_uuids):
            raise VerificationError(
                "xcarchive dSYM UUIDs do not cover the host, PacketTunnel, and Watch"
            )
        verify_obfuscation_receipt(obfuscation_receipt, ipa, ipa_evidence, runner)
        verify_symbol_custody_receipt(
            symbol_custody_receipt, ipa, ipa_evidence, runner, archive_path
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an exact produced iOS xcarchive/IPA pair and private receipts."
    )
    parser.add_argument("--ipa", required=True, type=pathlib.Path)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--obfuscation-receipt", required=True, type=pathlib.Path)
    parser.add_argument("--symbol-custody-receipt", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        verify_release_pair(
            args.ipa,
            args.archive,
            args.obfuscation_receipt,
            args.symbol_custody_receipt,
        )
    except BlockedError as exc:
        print(f"IOS RELEASE ARTIFACT: BLOCKED: {exc}", file=sys.stderr)
        return 2
    except VerificationError as exc:
        print(f"IOS RELEASE ARTIFACT: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "IOS RELEASE ARTIFACT: PASS "
        f"app={EXPECTED_APP_BUNDLE_ID} extension={EXPECTED_EXTENSION_BUNDLE_ID} "
        f"team={EXPECTED_TEAM_ID} minimum_ios={EXPECTED_MINIMUM_IOS}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
