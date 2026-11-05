#!/usr/bin/env python3
"""Inspect and optionally install Win's VPN Apple provisioning profiles."""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import hashlib
import os
import plistlib
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence


IOS_BUNDLE_ID = "org.winsvpn.app"
IOS_PACKET_TUNNEL_BUNDLE_ID = f"{IOS_BUNDLE_ID}.PacketTunnel"
WATCHOS_BUNDLE_ID = f"{IOS_BUNDLE_ID}.watchkitapp"
IOS_APP_GROUP_ID = "group.org.winsvpn.app"
MACOS_BUNDLE_ID = IOS_BUNDLE_ID
MACOS_PACKET_TUNNEL_BUNDLE_ID = IOS_PACKET_TUNNEL_BUNDLE_ID
SHARED_KEYCHAIN_SUFFIX = "org.winsvpn.shared"
DEFAULT_TEAM_ID = "5YT8H4U72M"

# Canonical Apple provisioning-profile UUID: 8-4-4-4-12 hex digits. Enforced
# before the value is used to build an install destination filename, since
# `UUID` is attacker-controlled plist content from an arbitrary local
# `.mobileprovision`/`.provisionprofile` file, not a value this tool derives
# itself.
PROVISIONING_PROFILE_UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$"
)
# Fallback filename stem (see installed_profile_path) is always a prefix of a
# hashlib.sha256(...).hexdigest() value computed by this tool, so it is
# already guaranteed to be safe hex, but it is still checked defensively in
# case that invariant ever changes.
PROFILE_SHA256_STEM_RE = re.compile(r"^[0-9a-f]{12}$")
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9 ._()'&+,:/@-]{1,160}$")
BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
IDENTITY_RE = re.compile(
    r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"([^"\r\n]+)"\s*$'
)
IDENTITY_NAME_RE = re.compile(
    r"^(Apple Development|Apple Distribution): "
    r"([^\x00-\x1f\x7f]{1,120}) \(([A-Z0-9]{10})\)$"
)
IGNORED_IDENTITY_NAME_RE = re.compile(
    r"^(Developer ID Application|Developer ID Installer|Mac App Distribution|"
    r"Mac Installer Distribution|3rd Party Mac Developer Application|"
    r"3rd Party Mac Developer Installer): [^\x00-\x1f\x7f]{1,120} "
    r"\([A-Z0-9]{10}\)$"
)
CERTIFICATE_COMMON_NAME_RE = re.compile(
    r"(?:^subject=|[,/])\s*CN\s*=\s*"
    r"(Apple Development|Apple Distribution):\s*([^,\r\n/]+)"
)
MAX_PROFILE_BYTES = 4 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_CERTIFICATE_BYTES = 128 * 1024
MAX_PLIST_DATA_BYTES = 2 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 15
VALID_PLATFORMS = frozenset({"iOS", "OSX"})


class ProfileError(ValueError):
    """A profile or signing-identity boundary failed closed."""


class StrictPlistDict(dict):
    def __setitem__(self, key: object, value: object) -> None:
        if key in self:
            raise ProfileError(f"duplicate property-list key: {key!r}")
        super().__setitem__(key, value)


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int


@dataclass(frozen=True)
class SigningIdentity:
    sha1: str
    name: str
    kind: str
    team_id: str


@dataclass(frozen=True)
class Profile:
    path: Path
    uuid: str
    name: str
    bundle_id: str
    team_prefix: str
    platforms: tuple[str, ...]
    is_development: bool
    is_ios_release_testing: bool
    provisioned_device_count: int
    provisions_all_devices: bool
    has_packet_tunnel: bool
    has_ios_app_group: bool
    has_shared_keychain_group: bool
    has_apple_development_cert: bool
    has_apple_distribution_cert: bool
    distribution_class: str
    creation: str
    expiration: str
    sha256: str
    certificate_sha1s: tuple[str, ...] = ()
    source_identity: FileIdentity | None = None
    content: bytes = field(default=b"", repr=False, compare=False)


def _file_identity(info: os.stat_result) -> FileIdentity:
    return FileIdentity(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _bounded_run(
    argv: Sequence[str],
    *,
    input_data: bytes | None = None,
    timeout: int = TOOL_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ProfileError("invalid tool invocation")
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            account_home = pwd.getpwuid(os.geteuid()).pw_dir
        except (KeyError, OSError) as error:
            raise ProfileError("cannot resolve the current account for Apple tooling") from error
        tool_environment = {
            "HOME": account_home,
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        }
        try:
            completed = subprocess.run(
                list(argv),
                input=input_data,
                stdout=stdout_file,
                stderr=stderr_file,
                check=False,
                timeout=timeout,
                close_fds=True,
                env=tool_environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ProfileError(f"tool execution failed: {argv[0]}") from error
        stdout_size = os.fstat(stdout_file.fileno()).st_size
        stderr_size = os.fstat(stderr_file.fileno()).st_size
        if stdout_size > MAX_TOOL_OUTPUT_BYTES or stderr_size > MAX_TOOL_OUTPUT_BYTES:
            raise ProfileError(f"tool output exceeded limit: {argv[0]}")
        stdout_file.seek(0)
        stderr_file.seek(0)
        return subprocess.CompletedProcess(
            list(argv),
            completed.returncode,
            stdout_file.read(MAX_TOOL_OUTPUT_BYTES + 1),
            stderr_file.read(MAX_TOOL_OUTPUT_BYTES + 1),
        )


def _safe_absolute_path(path: Path) -> Path:
    value = os.fspath(path.expanduser())
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ProfileError("profile path is empty or contains control characters")
    return Path(os.path.abspath(value))


def _read_regular_snapshot(path: Path, *, max_bytes: int = MAX_PROFILE_BYTES) -> tuple[Path, bytes, FileIdentity]:
    absolute = _safe_absolute_path(path)
    try:
        named_before = os.lstat(absolute)
    except OSError as error:
        raise ProfileError(f"cannot inspect profile: {absolute}") from error
    if not stat.S_ISREG(named_before.st_mode):
        raise ProfileError(f"profile is not a regular file: {absolute}")
    if named_before.st_nlink != 1:
        raise ProfileError(f"profile must have exactly one hard link: {absolute}")
    if named_before.st_uid != os.geteuid():
        raise ProfileError(f"profile is not owned by the current user: {absolute}")
    if named_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ProfileError(f"profile is group/world writable: {absolute}")
    if named_before.st_size <= 0 or named_before.st_size > max_bytes:
        raise ProfileError(f"profile size is outside the accepted range: {absolute}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ProfileError(f"cannot safely open profile: {absolute}") from error
    try:
        opened_before = os.fstat(descriptor)
        if _file_identity(opened_before) != _file_identity(named_before):
            raise ProfileError(f"profile changed while opening: {absolute}")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if not content or len(content) > max_bytes:
            raise ProfileError(f"profile size is outside the accepted range: {absolute}")
        opened_after = os.fstat(descriptor)
        if _file_identity(opened_after) != _file_identity(opened_before):
            raise ProfileError(f"profile changed while reading: {absolute}")
        try:
            named_after = os.lstat(absolute)
        except OSError as error:
            raise ProfileError(f"profile disappeared while reading: {absolute}") from error
        if _file_identity(named_after) != _file_identity(opened_before):
            raise ProfileError(f"profile pathname changed while reading: {absolute}")
        return absolute, content, _file_identity(opened_before)
    finally:
        os.close(descriptor)


def run_security_decode(content: bytes) -> dict:
    if not isinstance(content, bytes) or not content or len(content) > MAX_PROFILE_BYTES:
        raise ProfileError("profile CMS content is outside the accepted range")
    with tempfile.TemporaryDirectory(prefix="wins-profile-decode-") as directory:
        snapshot = Path(directory) / "profile.cms"
        descriptor = os.open(
            snapshot,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        completed = _bounded_run(["/usr/bin/security", "cms", "-D", "-i", str(snapshot)])
    if completed.returncode != 0 or not completed.stdout:
        raise ProfileError("security cms rejected the provisioning profile")
    try:
        decoded = plistlib.loads(completed.stdout, dict_type=StrictPlistDict)
    except Exception as error:
        if isinstance(error, ProfileError):
            raise
        raise ProfileError("security cms returned a malformed property list") from error
    if not isinstance(decoded, dict):
        raise ProfileError("provisioning profile payload is not a dictionary")
    _validate_plist_tree(decoded)
    return decoded


def _validate_plist_tree(value: object, *, depth: int = 0, counter: list[int] | None = None) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > 4096 or depth > 16:
        raise ProfileError("provisioning profile property list is too complex")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or not key or len(key) > 256:
                raise ProfileError("provisioning profile contains an invalid property-list key")
            _validate_plist_tree(child, depth=depth + 1, counter=counter)
        return
    if isinstance(value, list):
        if len(value) > 1024:
            raise ProfileError("provisioning profile property-list array is too large")
        for child in value:
            _validate_plist_tree(child, depth=depth + 1, counter=counter)
        return
    if isinstance(value, str):
        if len(value) > MAX_PROFILE_BYTES:
            raise ProfileError("provisioning profile string is oversized")
        return
    if isinstance(value, bytes):
        if len(value) > MAX_PLIST_DATA_BYTES:
            raise ProfileError("provisioning profile data value is oversized")
        return
    if isinstance(value, (bool, int, dt.datetime)) or value is None:
        return
    raise ProfileError("provisioning profile contains an unsupported property-list value")


def cert_subject(cert_der: bytes) -> str:
    if not isinstance(cert_der, bytes) or not 64 <= len(cert_der) <= MAX_CERTIFICATE_BYTES:
        raise ProfileError("profile contains an invalid developer certificate")
    completed = _bounded_run(
        ["/usr/bin/openssl", "x509", "-inform", "DER", "-noout", "-subject"],
        input_data=cert_der,
    )
    if completed.returncode != 0 or not completed.stdout:
        raise ProfileError("profile developer certificate could not be decoded")
    try:
        subject = completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise ProfileError("profile developer certificate subject is not UTF-8") from error
    if not subject or len(subject) > 1024 or any(ord(character) < 32 for character in subject):
        raise ProfileError("profile developer certificate subject is invalid")
    validity = _bounded_run(
        ["/usr/bin/openssl", "x509", "-inform", "DER", "-noout", "-dates"],
        input_data=cert_der,
    )
    if validity.returncode != 0:
        raise ProfileError("profile developer certificate validity could not be decoded")
    try:
        validity_text = validity.stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ProfileError("profile developer certificate validity is malformed") from error
    values: dict[str, dt.datetime] = {}
    for line in validity_text.splitlines():
        if "=" not in line:
            raise ProfileError("profile developer certificate validity is malformed")
        key, raw_value = line.split("=", 1)
        if key not in {"notBefore", "notAfter"} or key in values:
            raise ProfileError("profile developer certificate validity is ambiguous")
        try:
            parsed = email.utils.parsedate_to_datetime(raw_value)
        except (TypeError, ValueError) as error:
            raise ProfileError("profile developer certificate validity is malformed") from error
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        values[key] = parsed.astimezone(dt.timezone.utc)
    if set(values) != {"notBefore", "notAfter"}:
        raise ProfileError("profile developer certificate validity is incomplete")
    current_time = dt.datetime.now(dt.timezone.utc)
    if not values["notBefore"] <= current_time < values["notAfter"]:
        raise ProfileError("profile developer certificate is not currently valid")
    return subject


def certificate_kind(subject: str, expected_team_id: str) -> str:
    matches = CERTIFICATE_COMMON_NAME_RE.findall(subject)
    if len(matches) != 1:
        raise ProfileError("profile developer certificate common name is ambiguous")
    kind, common_name = matches[0]
    team_match = re.search(r"\(([A-Z0-9]{10})\)\s*$", common_name)
    if team_match is None or team_match.group(1) != expected_team_id:
        raise ProfileError("profile developer certificate belongs to the wrong team")
    return kind


def profile_bundle_id(entitlements: dict) -> str:
    app_identifier = str(
        entitlements.get("application-identifier")
        or entitlements.get("com.apple.application-identifier")
        or ""
    )
    if "." not in app_identifier:
        return app_identifier
    return app_identifier.split(".", 1)[1]


def profile_team_prefix(entitlements: dict) -> str:
    app_identifier = str(
        entitlements.get("application-identifier")
        or entitlements.get("com.apple.application-identifier")
        or ""
    )
    if "." not in app_identifier:
        return ""
    return app_identifier.split(".", 1)[0]


def has_expected_app_group(groups: Iterable[object], expected: str, team_prefix: str) -> bool:
    group_values = {str(group) for group in groups}
    return expected in group_values and not any("*" in group for group in group_values)


def has_expected_keychain_group(groups: Iterable[object], team_prefix: str) -> bool:
    expected = f"{team_prefix}.{SHARED_KEYCHAIN_SUFFIX}" if team_prefix else SHARED_KEYCHAIN_SUFFIX
    group_values = {str(group) for group in groups}
    return expected in group_values and not any("*" in group for group in group_values)


def is_device_scoped_ios_release_testing_profile(
    platforms: Iterable[str],
    *,
    is_development: bool,
    provisioned_device_count: int,
    provisions_all_devices: bool,
) -> bool:
    return (
        "iOS" in set(platforms)
        and not is_development
        and provisioned_device_count > 0
        and not provisions_all_devices
    )


def is_development_profile(
    entitlements: dict,
    *,
    provisioned_device_count: int,
    provisions_all_devices: bool,
    has_development_cert: bool,
    has_distribution_cert: bool,
) -> bool:
    if entitlements.get("get-task-allow") is True:
        return True
    if entitlements.get("com.apple.security.get-task-allow") is True:
        return True
    return (
        has_development_cert
        and not has_distribution_cert
        and provisioned_device_count > 0
        and not provisions_all_devices
    )


def _single_string_list(value: object, label: str) -> str:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], str):
        raise ProfileError(f"profile {label} must contain exactly one string")
    result = value[0]
    if not result or len(result) > 160 or any(ord(character) < 32 for character in result):
        raise ProfileError(f"profile {label} is invalid")
    return result


def _profile_datetime(value: object, label: str) -> dt.datetime:
    if not isinstance(value, dt.datetime):
        raise ProfileError(f"profile {label} is missing or invalid")
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def _strict_string_list(value: object, label: str, *, maximum: int = 256) -> tuple[str, ...]:
    if not isinstance(value, list) or not 0 <= len(value) <= maximum:
        raise ProfileError(f"profile {label} is invalid")
    if not all(isinstance(item, str) and 0 < len(item) <= 256 for item in value):
        raise ProfileError(f"profile {label} contains an invalid value")
    result = tuple(value)
    if len(set(result)) != len(result):
        raise ProfileError(f"profile {label} contains duplicate values")
    return result


def _distribution_class(
    *,
    platforms: tuple[str, ...],
    is_development: bool,
    provisioned_device_count: int,
    provisions_all_devices: bool,
    has_development_cert: bool,
    has_distribution_cert: bool,
) -> str:
    if provisions_all_devices:
        return "enterprise-or-developer-id"
    if is_development:
        return "development"
    if provisioned_device_count:
        return "ad-hoc"
    if has_distribution_cert and set(platforms).issubset(VALID_PLATFORMS):
        return "app-store"
    return "unknown"


def parse_profile(path: Path, *, now: dt.datetime | None = None) -> Profile:
    absolute, content, source_identity = _read_regular_snapshot(path)
    profile = run_security_decode(content)
    if len(profile) > 128:
        raise ProfileError("provisioning profile has too many top-level fields")

    uuid = profile.get("UUID")
    name = profile.get("Name")
    if not isinstance(uuid, str) or not PROVISIONING_PROFILE_UUID_RE.fullmatch(uuid):
        raise ProfileError("profile UUID is missing or non-canonical")
    if not isinstance(name, str) or not PROFILE_NAME_RE.fullmatch(name):
        raise ProfileError("profile name is missing or unsafe")

    entitlements = profile.get("Entitlements")
    if not isinstance(entitlements, dict) or len(entitlements) > 256:
        raise ProfileError("profile entitlements are missing or invalid")
    team_identifier = _single_string_list(profile.get("TeamIdentifier"), "TeamIdentifier")
    app_prefix = _single_string_list(
        profile.get("ApplicationIdentifierPrefix"), "ApplicationIdentifierPrefix"
    )
    if not TEAM_ID_RE.fullmatch(team_identifier) or app_prefix != team_identifier:
        raise ProfileError("profile team and application-identifier prefix do not match")

    app_identifier_keys = [
        key
        for key in ("application-identifier", "com.apple.application-identifier")
        if key in entitlements
    ]
    if len(app_identifier_keys) != 1:
        raise ProfileError("profile application identifier is missing or ambiguous")
    app_identifier = entitlements[app_identifier_keys[0]]
    if not isinstance(app_identifier, str) or not app_identifier:
        raise ProfileError("profile application identifier is invalid")
    if not app_identifier.startswith(team_identifier + "."):
        raise ProfileError("profile application identifier has the wrong team prefix")
    bundle_id = app_identifier[len(team_identifier) + 1 :]
    if not BUNDLE_ID_RE.fullmatch(bundle_id) or "*" in bundle_id:
        raise ProfileError("profile requires an exact bundle identifier")
    entitlement_team = entitlements.get("com.apple.developer.team-identifier")
    if entitlement_team != team_identifier:
        raise ProfileError("profile entitlement team identifier does not match")

    raw_platforms = profile.get("Platform")
    platforms = _strict_string_list(raw_platforms, "Platform", maximum=4)
    if len(platforms) != 1 or not set(platforms).issubset(VALID_PLATFORMS):
        raise ProfileError("profile platform is missing or unsupported")
    provisioned_devices_value = profile.get("ProvisionedDevices", [])
    provisioned_devices = _strict_string_list(
        provisioned_devices_value, "ProvisionedDevices", maximum=512
    )
    provisioned_device_count = len(provisioned_devices)
    raw_all_devices = profile.get("ProvisionsAllDevices", False)
    if not isinstance(raw_all_devices, bool):
        raise ProfileError("profile ProvisionsAllDevices is invalid")
    provisions_all_devices = raw_all_devices
    if provisioned_device_count and provisions_all_devices:
        raise ProfileError("profile mixes device and all-device distribution")
    for task_allow_key in ("get-task-allow", "com.apple.security.get-task-allow"):
        if task_allow_key in entitlements and not isinstance(entitlements[task_allow_key], bool):
            raise ProfileError(f"profile {task_allow_key} entitlement is invalid")

    certs = profile.get("DeveloperCertificates")
    if not isinstance(certs, list) or not 1 <= len(certs) <= 16:
        raise ProfileError("profile DeveloperCertificates is missing or invalid")
    cert_bytes: list[bytes] = []
    for cert in certs:
        if not isinstance(cert, bytes):
            raise ProfileError("profile developer certificate is not DER data")
        if not 64 <= len(cert) <= MAX_CERTIFICATE_BYTES:
            raise ProfileError("profile developer certificate has an invalid size")
        cert_bytes.append(cert)
    certificate_sha1s = tuple(hashlib.sha1(cert).hexdigest().upper() for cert in cert_bytes)
    if len(set(certificate_sha1s)) != len(certificate_sha1s):
        raise ProfileError("profile contains duplicate developer certificates")
    cert_subjects = [cert_subject(cert) for cert in cert_bytes]
    certificate_kinds = [
        certificate_kind(subject, team_identifier) for subject in cert_subjects
    ]
    has_development_cert = "Apple Development" in certificate_kinds
    has_distribution_cert = "Apple Distribution" in certificate_kinds
    is_development = is_development_profile(
        entitlements,
        provisioned_device_count=provisioned_device_count,
        provisions_all_devices=provisions_all_devices,
        has_development_cert=has_development_cert,
        has_distribution_cert=has_distribution_cert,
    )
    if has_development_cert == has_distribution_cert:
        raise ProfileError("profile certificate class is missing or ambiguous")
    if is_development != has_development_cert:
        raise ProfileError("profile entitlements and certificate class do not match")
    is_ios_release_testing = is_device_scoped_ios_release_testing_profile(
        platforms,
        is_development=is_development,
        provisioned_device_count=provisioned_device_count,
        provisions_all_devices=provisions_all_devices,
    )
    network_extensions = _strict_string_list(
        entitlements.get("com.apple.developer.networking.networkextension", []),
        "network-extension entitlements",
        maximum=32,
    )
    app_groups = _strict_string_list(
        entitlements.get("com.apple.security.application-groups", []),
        "application groups",
        maximum=32,
    )
    keychain_groups = _strict_string_list(
        entitlements.get("keychain-access-groups", []),
        "keychain groups",
        maximum=32,
    )
    creation_value = _profile_datetime(profile.get("CreationDate"), "CreationDate")
    expiration_value = _profile_datetime(profile.get("ExpirationDate"), "ExpirationDate")
    current_time = now or dt.datetime.now(dt.timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=dt.timezone.utc)
    else:
        current_time = current_time.astimezone(dt.timezone.utc)
    if creation_value > current_time + dt.timedelta(minutes=5):
        raise ProfileError("profile creation date is in the future")
    if expiration_value <= current_time:
        raise ProfileError("profile is expired")
    if expiration_value <= creation_value:
        raise ProfileError("profile validity interval is invalid")
    distribution_class = _distribution_class(
        platforms=platforms,
        is_development=is_development,
        provisioned_device_count=provisioned_device_count,
        provisions_all_devices=provisions_all_devices,
        has_development_cert=has_development_cert,
        has_distribution_cert=has_distribution_cert,
    )
    if distribution_class in {"enterprise-or-developer-id", "unknown"}:
        raise ProfileError(f"profile distribution class is unsupported: {distribution_class}")

    final_path, final_content, final_identity = _read_regular_snapshot(absolute)
    if (
        final_path != absolute
        or final_identity != source_identity
        or final_content != content
    ):
        raise ProfileError(f"profile changed during validation: {absolute}")

    return Profile(
        path=absolute,
        uuid=uuid,
        name=name,
        bundle_id=bundle_id,
        team_prefix=team_identifier,
        platforms=platforms,
        is_development=is_development,
        is_ios_release_testing=is_ios_release_testing,
        provisioned_device_count=provisioned_device_count,
        provisions_all_devices=provisions_all_devices,
        has_packet_tunnel="packet-tunnel-provider" in network_extensions,
        has_ios_app_group=has_expected_app_group(app_groups, IOS_APP_GROUP_ID, team_identifier),
        has_shared_keychain_group=has_expected_keychain_group(keychain_groups, team_identifier),
        has_apple_development_cert=has_development_cert,
        has_apple_distribution_cert=has_distribution_cert,
        distribution_class=distribution_class,
        creation=creation_value.isoformat(),
        expiration=expiration_value.isoformat(),
        sha256=hashlib.sha256(content).hexdigest(),
        certificate_sha1s=certificate_sha1s,
        source_identity=source_identity,
        content=content,
    )


def discover_profiles(paths: Iterable[Path]) -> list[Profile]:
    candidates: list[Path] = []
    seen: set[Path] = set()
    for source in paths:
        expanded = _safe_absolute_path(source)
        try:
            source_info = os.lstat(expanded)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ProfileError(f"cannot inspect profile source: {expanded}") from error
        if stat.S_ISREG(source_info.st_mode) and expanded.suffix in {".mobileprovision", ".provisionprofile"}:
            candidate_paths = [expanded]
        elif stat.S_ISDIR(source_info.st_mode):
            if source_info.st_uid != os.geteuid() or source_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ProfileError(f"profile source directory is not owner-safe: {expanded}")
            candidate_paths = sorted(expanded.glob("*.mobileprovision")) + sorted(
                expanded.glob("*.provisionprofile")
            )
        else:
            raise ProfileError(f"profile source is not a regular profile or safe directory: {expanded}")
        for candidate in candidate_paths:
            absolute = _safe_absolute_path(candidate)
            if absolute in seen:
                continue
            seen.add(absolute)
            candidates.append(absolute)

    profiles: list[Profile] = []
    for candidate in candidates:
        profiles.append(parse_profile(candidate))
    uuids: dict[str, Profile] = {}
    names: dict[tuple[str, str, tuple[str, ...]], Profile] = {}
    hashes: dict[str, Profile] = {}
    for profile in profiles:
        if profile.uuid in uuids:
            raise ProfileError(f"duplicate provisioning profile UUID: {profile.uuid}")
        uuids[profile.uuid] = profile
        name_key = (profile.name, profile.bundle_id, profile.platforms)
        if name_key in names:
            raise ProfileError(f"ambiguous provisioning profile name: {profile.name}")
        names[name_key] = profile
        if profile.sha256 in hashes:
            raise ProfileError(f"duplicate provisioning profile content: {profile.sha256}")
        hashes[profile.sha256] = profile
    return profiles


def parse_codesigning_identities(output: bytes) -> list[SigningIdentity]:
    if not isinstance(output, bytes) or len(output) > MAX_TOOL_OUTPUT_BYTES:
        raise ProfileError("codesigning identity output is invalid or oversized")
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ProfileError("codesigning identity output is not UTF-8") from error
    identities: list[SigningIdentity] = []
    seen_hashes: set[str] = set()
    seen_names: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or re.fullmatch(r"\d+ valid identities found", line):
            continue
        match = IDENTITY_RE.fullmatch(raw_line)
        if match is None:
            raise ProfileError("security find-identity returned an unrecognized line")
        sha1 = match.group(1).upper()
        name = match.group(2)
        name_match = IDENTITY_NAME_RE.fullmatch(name)
        if name_match is None:
            if IGNORED_IDENTITY_NAME_RE.fullmatch(name):
                continue
            raise ProfileError("security find-identity returned an unsupported identity name")
        if sha1 in seen_hashes or name in seen_names:
            raise ProfileError("security find-identity returned a duplicate identity")
        seen_hashes.add(sha1)
        seen_names.add(name)
        identities.append(
            SigningIdentity(
                sha1=sha1,
                name=name,
                kind=name_match.group(1),
                team_id=name_match.group(3),
            )
        )
    return identities


def list_codesigning_identities() -> list[SigningIdentity]:
    completed = _bounded_run(
        ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"]
    )
    if completed.returncode != 0:
        raise ProfileError("security find-identity failed")
    return parse_codesigning_identities(completed.stdout)


def select_signing_identity(
    profile: Profile,
    identities: Iterable[SigningIdentity],
) -> SigningIdentity:
    expected_kinds = (
        {"Apple Development"}
        if profile.distribution_class == "development"
        else {"Apple Distribution"}
    )
    certificate_hashes = set(profile.certificate_sha1s)
    if not certificate_hashes:
        raise ProfileError(f"profile has no certificate fingerprints: {profile.name}")
    matches = [
        identity
        for identity in identities
        if identity.team_id == profile.team_prefix
        and identity.kind in expected_kinds
        and identity.sha1 in certificate_hashes
    ]
    if len(matches) != 1:
        raise ProfileError(
            f"profile requires exactly one matching codesigning identity: {profile.name}"
        )
    return matches[0]


def readiness_for(
    profiles: list[Profile],
    bundle_id: str,
    *,
    require_vpn_capabilities: bool = True,
) -> tuple[bool, str, list[Profile]]:
    bundle_matches = [profile for profile in profiles if profile.bundle_id == bundle_id]
    matches = [
        profile
        for profile in bundle_matches
        if profile.is_ios_release_testing and profile.distribution_class == "ad-hoc"
    ]
    if not matches:
        has_non_device_scoped_distribution = any(
            "iOS" in profile.platforms
            and not profile.is_development
            and profile.provisioned_device_count == 0
            for profile in bundle_matches
        )
        if has_non_device_scoped_distribution:
            return False, "missing device-scoped release-testing profile", []
        return False, "missing release-testing profile", []

    usable = [
        profile
        for profile in matches
        if (not require_vpn_capabilities or profile.has_packet_tunnel)
        and (not require_vpn_capabilities or profile.has_ios_app_group)
        and (not require_vpn_capabilities or profile.has_shared_keychain_group)
        and profile.has_apple_distribution_cert
        and profile.team_prefix == DEFAULT_TEAM_ID
    ]
    if len(usable) > 1:
        return False, f"ambiguous release-testing profiles ({len(usable)} matches)", usable
    if usable:
        return True, "ok", usable

    reasons: list[str] = []
    for profile in matches:
        missing = []
        if profile.team_prefix != DEFAULT_TEAM_ID:
            missing.append("team")
        if require_vpn_capabilities and not profile.has_packet_tunnel:
            missing.append("packet-tunnel")
        if require_vpn_capabilities and not profile.has_ios_app_group:
            missing.append("app-group")
        if require_vpn_capabilities and not profile.has_shared_keychain_group:
            missing.append("keychain-group")
        if not profile.has_apple_distribution_cert:
            missing.append("apple-distribution-cert")
        reasons.append(f"{profile.name or profile.uuid}: missing {','.join(missing) or 'unknown'}")
    return False, "; ".join(reasons), matches


def macos_readiness_for(
    profiles: list[Profile],
    bundle_id: str,
    *,
    development: bool,
) -> tuple[bool, str, list[Profile]]:
    profile_kind = "development" if development else "app-store"
    bundle_matches = [
        profile
        for profile in profiles
        if profile.bundle_id == bundle_id and "OSX" in profile.platforms
    ]
    if development:
        matches = [
            profile
            for profile in bundle_matches
            if profile.distribution_class == "development"
            and profile.provisioned_device_count > 0
            and not profile.provisions_all_devices
        ]
    else:
        matches = [
            profile
            for profile in bundle_matches
            if profile.distribution_class == "app-store"
            and profile.provisioned_device_count == 0
            and not profile.provisions_all_devices
        ]
    if not matches:
        return False, f"missing macOS {profile_kind} profile", []

    usable: list[Profile] = []
    reasons: list[str] = []
    for profile in matches:
        missing: list[str] = []
        if profile.team_prefix != DEFAULT_TEAM_ID:
            missing.append("team")
        if not profile.has_packet_tunnel:
            missing.append("packet-tunnel")
        if not profile.has_ios_app_group:
            missing.append("app-group")
        if not profile.has_shared_keychain_group:
            missing.append("keychain-group")
        if development and not profile.has_apple_development_cert:
            missing.append("apple-development-cert")
        if not development and not profile.has_apple_distribution_cert:
            missing.append("apple-distribution-cert")
        if missing:
            reasons.append(f"{profile.name or profile.uuid}: missing {','.join(missing)}")
        else:
            usable.append(profile)
    if len(usable) > 1:
        return False, f"ambiguous macOS {profile_kind} profiles ({len(usable)} matches)", usable
    if usable:
        return True, "ok", usable
    return False, "; ".join(reasons), matches


def installed_profile_path(profile: Profile, install_dir: Path) -> Path:
    suffix = ".mobileprovision" if "iOS" in profile.platforms else ".provisionprofile"

    raw_uuid = (profile.uuid or "").strip()
    if raw_uuid:
        if not PROVISIONING_PROFILE_UUID_RE.fullmatch(raw_uuid):
            raise ValueError(f"Non-canonical provisioning profile UUID: {raw_uuid!r}")
        stem = raw_uuid
    else:
        stem = profile.sha256[:12]
        if not PROFILE_SHA256_STEM_RE.fullmatch(stem):
            raise ValueError("Provisioning profile has neither a canonical UUID nor a usable content hash")

    root = _safe_absolute_path(install_dir)
    destination = root / f"{stem}{suffix}"
    if destination.parent != root:
        raise ValueError("Provisioning profile destination escaped the install directory")
    return destination


def print_profile(profile: Profile) -> None:
    release_testing = "yes" if profile.is_ios_release_testing else "no"
    print(
        f"- {profile.name or '(unnamed)'} [{profile.bundle_id}] "
        f"path={profile.path} release_testing={release_testing} "
        f"devices={profile.provisioned_device_count} all_devices={profile.provisions_all_devices} "
        f"packet_tunnel={profile.has_packet_tunnel} app_group={profile.has_ios_app_group} "
        f"keychain_group={profile.has_shared_keychain_group} "
        f"apple_development_cert={profile.has_apple_development_cert} "
        f"apple_distribution_cert={profile.has_apple_distribution_cert} "
        f"expires={profile.expiration}"
    )


def _safe_directory_fd(directory: Path) -> tuple[Path, int]:
    absolute = _safe_absolute_path(directory)
    try:
        named = os.lstat(absolute)
    except OSError as error:
        raise ProfileError(f"cannot inspect destination directory: {absolute}") from error
    if not stat.S_ISDIR(named.st_mode) or named.st_uid != os.geteuid():
        raise ProfileError(f"destination directory is not owner-safe: {absolute}")
    if named.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ProfileError(f"destination directory is group/world writable: {absolute}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ProfileError(f"cannot safely open destination directory: {absolute}") from error
    opened = os.fstat(descriptor)
    if _file_identity(opened) != _file_identity(named):
        os.close(descriptor)
        raise ProfileError(f"destination directory changed while opening: {absolute}")
    return absolute, descriptor


def _read_named_file_at(directory_fd: int, name: str, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise ProfileError("existing destination is not an owner-safe regular file")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ProfileError("existing destination is group/world writable")
        if info.st_size < 0 or info.st_size > max_bytes:
            raise ProfileError("existing destination is oversized")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > max_bytes or _file_identity(os.fstat(descriptor)) != _file_identity(info):
            raise ProfileError("existing destination changed while reading")
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _file_identity(named) != _file_identity(info):
            raise ProfileError("existing destination pathname changed while reading")
        return content
    finally:
        os.close(descriptor)


def _atomic_create_file(directory: Path, name: str, content: bytes, *, mode: int) -> bool:
    if not isinstance(content, bytes) or not content or len(content) > MAX_PROFILE_BYTES:
        raise ProfileError("destination content is empty or oversized")
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise ProfileError("unsafe destination filename")
    _absolute, directory_fd = _safe_directory_fd(directory)
    temp_name = f".{name}.wins-{secrets.token_hex(8)}.tmp"
    temp_inode: tuple[int, int] | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temp_name, flags, mode, dir_fd=directory_fd)
        try:
            opened = os.fstat(descriptor)
            temp_inode = (opened.st_dev, opened.st_ino)
            os.fchmod(descriptor, mode)
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise ProfileError("short write while creating destination")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(
                temp_name,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = _read_named_file_at(directory_fd, name, max_bytes=max(len(content), 1))
            if existing != content:
                raise ProfileError("refusing to replace a different existing destination")
            return False
        linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            temp_inode is None
            or (linked.st_dev, linked.st_ino) != temp_inode
            or not stat.S_ISREG(linked.st_mode)
        ):
            raise ProfileError("destination was substituted during atomic installation")
        os.fsync(directory_fd)
        return True
    finally:
        if temp_inode is not None:
            try:
                current = os.stat(temp_name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if (
                    (current.st_dev, current.st_ino) != temp_inode
                    or not stat.S_ISREG(current.st_mode)
                    or current.st_uid != os.geteuid()
                ):
                    raise ProfileError("temporary destination was substituted during cleanup")
                os.unlink(temp_name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        os.close(directory_fd)


def install_profiles(
    profiles: Iterable[Profile],
    *,
    install_dir: Path | None = None,
) -> list[str]:
    destination_dir = install_dir or (
        Path.home() / "Library" / "MobileDevice" / "Provisioning Profiles"
    )
    destination_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    messages: list[str] = []
    for profile in profiles:
        source_path, source_content, source_identity = _read_regular_snapshot(profile.path)
        if (
            profile.source_identity is None
            or source_identity != profile.source_identity
            or source_content != profile.content
            or hashlib.sha256(source_content).hexdigest() != profile.sha256
        ):
            raise ProfileError(f"profile changed after validation: {profile.path}")
        destination = installed_profile_path(profile, destination_dir)
        if source_path == destination:
            _directory, directory_fd = _safe_directory_fd(destination.parent)
            os.close(directory_fd)
            messages.append(f"already installed: {destination}")
            continue
        created = _atomic_create_file(
            destination.parent,
            destination.name,
            source_content,
            mode=0o600,
        )
        action = "installed" if created else "already installed"
        messages.append(f"{action}: {profile.path} -> {destination}")
    return messages


def macos_development_xcconfig_text(profiles: list[Profile]) -> str:
    selected: dict[str, Profile] = {}
    for target_name, bundle_id in (
        ("Runner", MACOS_BUNDLE_ID),
        ("PacketTunnel", MACOS_PACKET_TUNNEL_BUNDLE_ID),
    ):
        ready, reason, usable = macos_readiness_for(
            profiles,
            bundle_id,
            development=True,
        )
        if not ready or not usable:
            raise ValueError(f"{target_name}: {reason}")
        selected[target_name] = max(
            usable,
            key=lambda profile: (profile.expiration, profile.name, profile.uuid),
        )

    profile_names: dict[str, str] = {}
    for target_name, profile in selected.items():
        name = profile.name.strip()
        if not name or not re.fullmatch(r"[A-Za-z0-9 ._()'&+:-]+", name):
            raise ValueError(f"{target_name}: selected profile has an unsafe xcconfig name")
        profile_names[target_name] = name

    return "\n".join(
        (
            "CODE_SIGN_STYLE = Manual",
            f"DEVELOPMENT_TEAM = {DEFAULT_TEAM_ID}",
            "CODE_SIGN_IDENTITY = Apple Development",
            f"WINS_PROFILE_Runner = {profile_names['Runner']}",
            f"WINS_PROFILE_PacketTunnel = {profile_names['PacketTunnel']}",
            "PROVISIONING_PROFILE_SPECIFIER = $(WINS_PROFILE_$(TARGET_NAME))",
            "",
        )
    )


def write_private_xcconfig(path: Path, contents: str) -> Path:
    project_root = Path(__file__).resolve().parents[1]
    requested = path.expanduser()
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    if not requested.name or requested.name in {".", ".."}:
        raise ValueError("macOS development xcconfig filename is invalid")
    target = requested.parent.resolve(strict=True) / requested.name
    try:
        target.relative_to(project_root)
    except ValueError:
        pass
    else:
        raise ValueError("macOS development xcconfig must live outside the project folder")
    if not target.parent.is_dir():
        raise ValueError("xcconfig parent directory does not exist")
    try:
        encoded = contents.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError("macOS development xcconfig is not UTF-8") from error
    _atomic_create_file(target.parent, target.name, encoded, mode=0o600)
    return target


def check_profiles(
    sources: Iterable[Path],
    *,
    install: bool,
    quiet: bool,
    require_macos: bool,
    require_signing_identity: bool = True,
) -> bool:
    if install and not require_signing_identity:
        raise ProfileError("profile installation cannot bypass codesigning identity custody")
    profiles = discover_profiles(sources)
    relevant = [
        profile
        for profile in profiles
        if profile.bundle_id in {IOS_BUNDLE_ID, IOS_PACKET_TUNNEL_BUNDLE_ID, WATCHOS_BUNDLE_ID}
    ]

    if not quiet:
        print(f"Scanned profiles: {len(profiles)}")
        print(f"Relevant Win's VPN profiles: {len(relevant)}")
        for profile in relevant:
            print_profile(profile)

    app_ok, app_reason, app_usable = readiness_for(relevant, IOS_BUNDLE_ID)
    extension_ok, extension_reason, extension_usable = readiness_for(relevant, IOS_PACKET_TUNNEL_BUNDLE_ID)
    watch_ok, watch_reason, watch_usable = readiness_for(
        relevant,
        WATCHOS_BUNDLE_ID,
        require_vpn_capabilities=False,
    )
    ios_readiness = app_ok and extension_ok and watch_ok
    print(
        "iOS release-testing profile readiness: "
        f"{'ok' if ios_readiness else 'missing or incomplete'}; "
        f"app={app_reason}; packet_tunnel={extension_reason}; watch_app={watch_reason}"
    )

    mac_dev_app_ok, mac_dev_app_reason, mac_dev_app_usable = macos_readiness_for(
        relevant,
        MACOS_BUNDLE_ID,
        development=True,
    )
    mac_dev_extension_ok, mac_dev_extension_reason, mac_dev_extension_usable = macos_readiness_for(
        relevant,
        MACOS_PACKET_TUNNEL_BUNDLE_ID,
        development=True,
    )
    mac_store_app_ok, mac_store_app_reason, mac_store_app_usable = macos_readiness_for(
        relevant,
        MACOS_BUNDLE_ID,
        development=False,
    )
    mac_store_extension_ok, mac_store_extension_reason, mac_store_extension_usable = macos_readiness_for(
        relevant,
        MACOS_PACKET_TUNNEL_BUNDLE_ID,
        development=False,
    )
    macos_readiness = all(
        (
            mac_dev_app_ok,
            mac_dev_extension_ok,
            mac_store_app_ok,
            mac_store_extension_ok,
        )
    )
    print(
        "macOS universal profile readiness: "
        f"{'ok' if macos_readiness else 'missing or incomplete'}; "
        f"development_app={mac_dev_app_reason}; "
        f"development_packet_tunnel={mac_dev_extension_reason}; "
        f"app_store_app={mac_store_app_reason}; "
        f"app_store_packet_tunnel={mac_store_extension_reason}"
    )

    identities_ok = True
    profiles_requiring_identity = app_usable + extension_usable + watch_usable
    if require_macos or install:
        profiles_requiring_identity += mac_dev_app_usable + mac_dev_extension_usable
        profiles_requiring_identity += mac_store_app_usable + mac_store_extension_usable
    if require_signing_identity and profiles_requiring_identity:
        try:
            identities = list_codesigning_identities()
            selected_names: list[str] = []
            for profile in profiles_requiring_identity:
                selected = select_signing_identity(profile, identities)
                selected_names.append(f"{profile.bundle_id}={selected.sha1}")
        except ProfileError as error:
            identities_ok = False
            print(f"Apple codesigning identity readiness: missing or ambiguous; {error}")
        else:
            print(
                "Apple codesigning identity readiness: ok; "
                + ", ".join(selected_names)
            )

    install_requires_macos = require_macos or any(
        "OSX" in profile.platforms for profile in relevant
    )
    overall_ready = (
        ios_readiness
        and identities_ok
        and (macos_readiness or not install_requires_macos)
    )
    if install and not overall_ready:
        print(
            "Refusing to install provisioning profiles before the exact profile and "
            "codesigning-identity set is complete.",
            file=sys.stderr,
        )
        return False

    if install:
        usable_profiles = app_usable + extension_usable + watch_usable
        usable_profiles += mac_dev_app_usable + mac_dev_extension_usable
        usable_profiles += mac_store_app_usable + mac_store_extension_usable
        try:
            for message in install_profiles(usable_profiles):
                print(message)
        except ValueError as error:
            print(f"Refusing to install provisioning profile: {error}", file=sys.stderr)
            return False

    return ios_readiness and (macos_readiness or not require_macos) and identities_ok


def guarded_check_profiles(
    sources: Iterable[Path],
    *,
    install: bool,
    quiet: bool,
    require_macos: bool,
) -> bool:
    try:
        return check_profiles(
            sources,
            install=install,
            quiet=quiet,
            require_macos=require_macos,
        )
    except (OSError, ProfileError) as error:
        print(f"Apple profile custody check failed: {error}", file=sys.stderr)
        return False


def make_fake_profile(
    *,
    bundle_id: str,
    name: str = "Fake Profile",
    team_prefix: str = DEFAULT_TEAM_ID,
    platforms: tuple[str, ...] = ("iOS",),
    is_development: bool = False,
    provisioned_device_count: int = 1,
    provisions_all_devices: bool = False,
    has_packet_tunnel: bool = True,
    has_ios_app_group: bool = True,
    has_shared_keychain_group: bool = True,
    has_apple_development_cert: bool = False,
    has_apple_distribution_cert: bool = True,
) -> Profile:
    digest = hashlib.sha256(name.encode("ascii", errors="strict")).hexdigest()
    distribution_class = _distribution_class(
        platforms=platforms,
        is_development=is_development,
        provisioned_device_count=provisioned_device_count,
        provisions_all_devices=provisions_all_devices,
        has_development_cert=has_apple_development_cert,
        has_distribution_cert=has_apple_distribution_cert,
    )
    return Profile(
        path=Path(f"/tmp/{name.replace(' ', '_')}.mobileprovision"),
        uuid=(
            f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-"
            f"{digest[16:20]}-{digest[20:32]}"
        ).upper(),
        name=name,
        bundle_id=bundle_id,
        team_prefix=team_prefix,
        platforms=platforms,
        is_development=is_development,
        is_ios_release_testing=is_device_scoped_ios_release_testing_profile(
            platforms,
            is_development=is_development,
            provisioned_device_count=provisioned_device_count,
            provisions_all_devices=provisions_all_devices,
        ),
        provisioned_device_count=provisioned_device_count,
        provisions_all_devices=provisions_all_devices,
        has_packet_tunnel=has_packet_tunnel,
        has_ios_app_group=has_ios_app_group,
        has_shared_keychain_group=has_shared_keychain_group,
        has_apple_development_cert=has_apple_development_cert,
        has_apple_distribution_cert=has_apple_distribution_cert,
        distribution_class=distribution_class,
        creation="2026-01-01T00:00:00+00:00",
        expiration="2099-01-01T00:00:00",
        sha256="0" * 64,
        certificate_sha1s=("A" * 40,),
    )


def require_selftest(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_selftest() -> int:
    require_selftest(
        is_development_profile(
            {},
            provisioned_device_count=2,
            provisions_all_devices=False,
            has_development_cert=True,
            has_distribution_cert=False,
        ),
        "device-scoped Apple Development profile should be accepted without get-task-allow",
    )
    require_selftest(
        not is_development_profile(
            {},
            provisioned_device_count=1,
            provisions_all_devices=False,
            has_development_cert=False,
            has_distribution_cert=True,
        ),
        "device-scoped distribution profile must not be classified as development",
    )
    require_selftest(
        is_device_scoped_ios_release_testing_profile(
            ("iOS",),
            is_development=False,
            provisioned_device_count=1,
            provisions_all_devices=False,
        ),
        "device-scoped iOS distribution profile should be accepted",
    )
    require_selftest(
        not is_device_scoped_ios_release_testing_profile(
            ("iOS",),
            is_development=False,
            provisioned_device_count=0,
            provisions_all_devices=True,
        ),
        "all-devices iOS distribution profile must not satisfy release-testing",
    )
    require_selftest(
        not is_device_scoped_ios_release_testing_profile(
            ("iOS",),
            is_development=True,
            provisioned_device_count=1,
            provisions_all_devices=False,
        ),
        "development profile must not satisfy release-testing",
    )

    valid_profiles = [
        make_fake_profile(bundle_id=IOS_BUNDLE_ID, name="Valid App Profile"),
        make_fake_profile(bundle_id=IOS_PACKET_TUNNEL_BUNDLE_ID, name="Valid PacketTunnel Profile"),
    ]
    app_ok, app_reason, _ = readiness_for(valid_profiles, IOS_BUNDLE_ID)
    extension_ok, extension_reason, _ = readiness_for(valid_profiles, IOS_PACKET_TUNNEL_BUNDLE_ID)
    require_selftest(app_ok and extension_ok, f"valid profiles should pass: {app_reason}; {extension_reason}")

    watch_profiles = [
        make_fake_profile(
            bundle_id=WATCHOS_BUNDLE_ID,
            name="Valid Watch Profile",
            has_packet_tunnel=False,
            has_ios_app_group=False,
            has_shared_keychain_group=False,
        ),
    ]
    watch_ok, watch_reason, _ = readiness_for(
        watch_profiles,
        WATCHOS_BUNDLE_ID,
        require_vpn_capabilities=False,
    )
    require_selftest(watch_ok, f"plain watch profile should pass: {watch_reason}")

    all_devices_profiles = [
        make_fake_profile(
            bundle_id=IOS_BUNDLE_ID,
            name="All Devices App Profile",
            provisioned_device_count=0,
            provisions_all_devices=True,
        ),
        make_fake_profile(bundle_id=IOS_PACKET_TUNNEL_BUNDLE_ID, name="Valid PacketTunnel Profile"),
    ]
    app_ok, app_reason, _ = readiness_for(all_devices_profiles, IOS_BUNDLE_ID)
    require_selftest(not app_ok and "device-scoped" in app_reason, "all-devices profile should fail clearly")

    missing_capability_profiles = [
        make_fake_profile(bundle_id=IOS_BUNDLE_ID, name="Missing Keychain", has_shared_keychain_group=False),
    ]
    app_ok, app_reason, _ = readiness_for(missing_capability_profiles, IOS_BUNDLE_ID)
    require_selftest(not app_ok and "keychain-group" in app_reason, "missing keychain should be reported")

    wrong_team_profiles = [
        make_fake_profile(bundle_id=IOS_BUNDLE_ID, name="Wrong Team", team_prefix="WRONGTEAM"),
    ]
    app_ok, app_reason, _ = readiness_for(wrong_team_profiles, IOS_BUNDLE_ID)
    require_selftest(not app_ok and "team" in app_reason, "wrong team should be reported")

    valid_macos_profiles = [
        make_fake_profile(
            bundle_id=MACOS_BUNDLE_ID,
            name="Valid Mac Development App",
            platforms=("OSX",),
            is_development=True,
            provisioned_device_count=1,
            has_apple_development_cert=True,
            has_apple_distribution_cert=False,
        ),
        make_fake_profile(
            bundle_id=MACOS_PACKET_TUNNEL_BUNDLE_ID,
            name="Valid Mac Development PacketTunnel",
            platforms=("OSX",),
            is_development=True,
            provisioned_device_count=1,
            has_apple_development_cert=True,
            has_apple_distribution_cert=False,
        ),
        make_fake_profile(
            bundle_id=MACOS_BUNDLE_ID,
            name="Valid Mac App Store App",
            platforms=("OSX",),
            provisioned_device_count=0,
        ),
        make_fake_profile(
            bundle_id=MACOS_PACKET_TUNNEL_BUNDLE_ID,
            name="Valid Mac App Store PacketTunnel",
            platforms=("OSX",),
            provisioned_device_count=0,
        ),
    ]
    for bundle_id in (MACOS_BUNDLE_ID, MACOS_PACKET_TUNNEL_BUNDLE_ID):
        dev_ok, dev_reason, _ = macos_readiness_for(
            valid_macos_profiles,
            bundle_id,
            development=True,
        )
        store_ok, store_reason, _ = macos_readiness_for(
            valid_macos_profiles,
            bundle_id,
            development=False,
        )
        require_selftest(
            dev_ok and store_ok,
            f"valid macOS profiles should pass for {bundle_id}: {dev_reason}; {store_reason}",
        )

    xcconfig = macos_development_xcconfig_text(valid_macos_profiles)
    require_selftest(
        "WINS_PROFILE_Runner = Valid Mac Development App" in xcconfig
        and "WINS_PROFILE_PacketTunnel = Valid Mac Development PacketTunnel" in xcconfig
        and "PROVISIONING_PROFILE_SPECIFIER = $(WINS_PROFILE_$(TARGET_NAME))" in xcconfig,
        "macOS development xcconfig should bind one validated profile per target",
    )

    developer_id_profile = make_fake_profile(
        bundle_id=MACOS_BUNDLE_ID,
        name="Developer ID Is Not App Store",
        platforms=("OSX",),
        provisioned_device_count=0,
        provisions_all_devices=True,
        has_apple_distribution_cert=False,
    )
    store_ok, store_reason, _ = macos_readiness_for(
        [developer_id_profile],
        MACOS_BUNDLE_ID,
        development=False,
    )
    require_selftest(
        not store_ok and "missing macOS app-store" in store_reason,
        "Developer ID profile must not satisfy Mac App Store readiness",
    )

    duplicate_ready, duplicate_reason, _ = readiness_for(
        [
            make_fake_profile(bundle_id=IOS_BUNDLE_ID, name="Duplicate One"),
            make_fake_profile(bundle_id=IOS_BUNDLE_ID, name="Duplicate Two"),
        ],
        IOS_BUNDLE_ID,
    )
    require_selftest(
        not duplicate_ready and "ambiguous" in duplicate_reason,
        "multiple usable release-testing profiles must fail closed",
    )

    identity_output = (
        b'  1) AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "Apple Distribution: '
        b"Win's VPN Inc (5YT8H4U72M)" b'"\n     1 valid identities found\n'
    )
    identities = parse_codesigning_identities(identity_output)
    selected = select_signing_identity(
        make_fake_profile(bundle_id=IOS_BUNDLE_ID, name="Identity Bound"),
        identities,
    )
    require_selftest(
        selected.sha1 == "A" * 40 and selected.team_id == DEFAULT_TEAM_ID,
        "codesigning identity must bind the profile certificate and team",
    )

    print("Apple profile manager self-test passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect and optionally install Win's VPN iOS release-testing and macOS universal-purchase profiles."
    )
    parser.add_argument(
        "--source",
        action="append",
        type=Path,
        default=[],
        help="Profile file or directory to scan. Defaults to Downloads and installed profile directories.",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Copy usable iOS and macOS profiles into ~/Library/MobileDevice/Provisioning Profiles/.",
    )
    parser.add_argument(
        "--require-macos",
        action="store_true",
        help="Fail unless macOS development and App Store profiles exist for the shared host and PacketTunnel IDs.",
    )
    parser.add_argument(
        "--write-macos-development-xcconfig",
        type=Path,
        help="Write a private target-aware manual-signing xcconfig outside the project folder.",
    )
    parser.add_argument(
        "--watch-seconds",
        type=int,
        default=0,
        help="Keep rescanning for this many seconds, useful while downloading profiles from Apple Developer.",
    )
    parser.add_argument(
        "--watch-interval",
        type=int,
        default=5,
        help="Seconds between scans when --watch-seconds is set.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print only readiness summary.",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="Run synthetic release-testing profile readiness checks and exit.",
    )
    args = parser.parse_args()
    if args.selftest:
        return run_selftest()

    sources = args.source or [
        Path.home() / "Downloads",
        Path.home() / "Library" / "MobileDevice" / "Provisioning Profiles",
        Path.home() / "Library" / "Developer" / "Xcode" / "UserData" / "Provisioning Profiles",
    ]
    if args.watch_seconds < 0:
        parser.error("--watch-seconds must be zero or greater")
    if args.watch_interval <= 0:
        parser.error("--watch-interval must be greater than zero")
    if args.write_macos_development_xcconfig is not None:
        if args.watch_seconds != 0:
            parser.error("--write-macos-development-xcconfig cannot be combined with --watch-seconds")
        try:
            profiles = discover_profiles(sources)
            relevant = [
                profile
                for profile in profiles
                if profile.bundle_id in {MACOS_BUNDLE_ID, MACOS_PACKET_TUNNEL_BUNDLE_ID}
            ]
            identities = list_codesigning_identities()
            for bundle_id in (MACOS_BUNDLE_ID, MACOS_PACKET_TUNNEL_BUNDLE_ID):
                ready, reason, usable = macos_readiness_for(
                    relevant,
                    bundle_id,
                    development=True,
                )
                if not ready or len(usable) != 1:
                    raise ProfileError(f"macOS development profile: {reason}")
                select_signing_identity(usable[0], identities)
            contents = macos_development_xcconfig_text(relevant)
            output = write_private_xcconfig(
                args.write_macos_development_xcconfig,
                contents,
            )
        except (OSError, ValueError) as error:
            print(f"Could not write macOS development xcconfig: {error}", file=sys.stderr)
            return 1
        print(f"Wrote private macOS development signing xcconfig: {output}")
        return 0

    if args.watch_seconds == 0:
        return 0 if guarded_check_profiles(
            sources,
            install=args.install,
            quiet=args.quiet,
            require_macos=args.require_macos,
        ) else 1

    deadline = time.monotonic() + args.watch_seconds
    attempt = 1
    while True:
        if not args.quiet:
            print(f"Profile scan attempt {attempt}")
        if guarded_check_profiles(
            sources,
            install=args.install,
            quiet=True,
            require_macos=args.require_macos,
        ):
            return 0
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(
                f"Timed out after {args.watch_seconds}s waiting for required Apple profiles.",
                file=sys.stderr,
            )
            return 1
        time.sleep(min(args.watch_interval, remaining))
        attempt += 1


if __name__ == "__main__":
    raise SystemExit(main())
