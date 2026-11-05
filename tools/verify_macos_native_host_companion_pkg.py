#!/usr/bin/env python3
"""Fail-closed verifier for the macOS native-messaging companion PKG.

The Mac App Store app cannot deliver an out-of-sandbox Chrome, Edge, or
Firefox native host. The consumer artifact is a separate Developer ID
Installer product PKG. This verifier never invents a Chrome or Edge store
id, team id, or certificate, and it never prints PASS for an unsigned,
unstapled, or incomplete package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import stat
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


ORIGIN_ROOT = pathlib.Path(__file__).resolve().parents[1]
TEAM_ID = "5YT8H4U72M"
OWNER_BLOCK_EXIT = 78
PACKAGE_IDENTIFIER = "org.winsvpn.bridge.nativemessaginghost"
HOST_NAME = "org.winsvpn.bridge"
HOST_DESCRIPTION = "Win's VPN browser bridge"
FIREFOX_EXTENSION_ID = "companion@winsvpn.org"
INSTALLED_HOST_PATH = (
    "/Library/Application Support/Win's VPN/NativeMessagingHost/wins_bridge_host"
)
INSTALLED_HOST_DIR = (
    "/Library/Application Support/Win's VPN/NativeMessagingHost"
)
FIREFOX_MANIFEST_PATH = (
    "/Library/Application Support/Mozilla/NativeMessagingHosts/"
    f"{HOST_NAME}.json"
)
CHROME_MANIFEST_PATH = (
    f"/Library/Google/Chrome/NativeMessagingHosts/{HOST_NAME}.json"
)
EDGE_MANIFEST_PATH = (
    f"/Library/Microsoft/Edge/NativeMessagingHosts/{HOST_NAME}.json"
)
RECEIPT_PATH = (
    f"{INSTALLED_HOST_DIR}/macos-native-host-companion-receipt.json"
)
UNINSTALL_PATH = f"{INSTALLED_HOST_DIR}/uninstall-winsvpn-native-host.sh"
INCOMING_RELATIVE = (
    "Library/Application Support/Win's VPN/NativeMessagingHost/Incoming"
)
RECEIPT_CONTRACT = "winsvpn-macos-native-host-companion-pkg-receipt-v1"
RECEIPT_SCHEMA_VERSION = 2
CHROMIUM_EXTENSION_ID = re.compile(r"^[a-p]{32}$")
PLACEHOLDER = re.compile(r"placeholder", re.IGNORECASE)
PYTHON_HINT = re.compile(
    r"(?i)python3(?:\.\d+)?|/usr/bin/python\b|/bin/python\b|PYTHON_BIN|"
    r"native_host_layout|render_host_manifest|install_macos_native_host"
)
REPO_HINT = re.compile(r"(?i)tools/native_messaging/")
MH_EXECUTE = 0x2
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
REQUIRED_ARCHITECTURES = frozenset({"arm64", "x86_64"})
# Owner ruling 2026-10-16: for release lines 1.0.16 and 1.0.17 the macOS native-messaging
# companion ships for Apple silicon only. The release Mac has an arm64-only
# Dart SDK, Dart cannot cross-compile a macos_x64 executable, and Rosetta is
# not installed, so no x86_64 slice can be built there. The exception names
# this one release line (the version the receipt, Distribution, and
# PackageInfo bind); every other release still requires the universal
# arm64+x86_64 executable. The ruling carries over to release line 1.0.17
# (relayed by the coordinator 2026-11-02). Mirrors
# tools/apple_cross_store_artifact_gate.py.
ARM64_ONLY_OWNER_RULING_DATE = "2026-10-16"
ARM64_ONLY_RELEASE_LINES = frozenset({"1.0.16", "1.0.17"})
ARM64_ONLY_ARCHITECTURES = frozenset({"arm64"})
LC_VERSION_MIN_MACOSX = 0x24
LC_BUILD_VERSION = 0x32
PLATFORM_MACOS = 1
# The host is a bundle-less Dart AOT executable launched by the browser. Its
# Developer ID signature carries exactly these entitlements:
# - the team App Group the sandboxed App Store app writes its IPC discovery
#   file into (lib/browser_bridge_app_ipc.dart resolves it through
#   FileManager; macOS 15 grants the container without a prompt only to an
#   entitled process of the same team);
# - allow-unsigned-executable-memory, because the Dart AOT runtime executes
#   its snapshot from pages the kernel does not see as signed. Under hardened
#   runtime without it the host is SIGKILLed with CODESIGNING "Invalid Page"
#   (observed 2026-11-02 on Dart 3.13.5). allow-jit does not cover it.
# Anything else (get-task-allow, disable-library-validation, allow-jit,
# app-sandbox, ...) is refused.
APP_GROUP_IDENTIFIER = f"{TEAM_ID}.group.org.winsvpn.app"
REQUIRED_HOST_ENTITLEMENTS = {
    "com.apple.security.application-groups": [APP_GROUP_IDENTIFIER],
    "com.apple.security.cs.allow-unsigned-executable-memory": True,
}
# Owner-installed browser-bridge trust root read by both the sandboxed app and
# the host (lib/browser_bridge_app_ipc.dart defaultBrowserBridgeAppIpcTrustFile).
# The postinstall issues it once per machine and keeps a valid one.
IDENTITY_RECEIPT_PATH = (
    "/Library/Application Support/wins_vpn/browser_bridge.identity"
)
FAT_ENDIAN = {
    b"\xca\xfe\xba\xbe": ">",
    b"\xca\xfe\xba\xbf": ">",
    b"\xbe\xba\xfe\xca": "<",
    b"\xbf\xba\xfe\xca": "<",
}
FAT_64 = {b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
REVIEWED_SUBPROCESS_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
REVIEWED_TOOLS = frozenset(
    {
        "/usr/bin/codesign",
        "/usr/sbin/pkgutil",
        "/usr/sbin/spctl",
        "/usr/bin/stapler",
        "/usr/bin/lipo",
        "/usr/bin/lsbom",
    }
)
INCOMING_FILES = (
    "wins_bridge_host",
    "firefox.json",
    "chrome.json",
    "edge.json",
    "receipt.json",
    "uninstall.sh",
)
SOURCE_CLOSURE_PATHS = (
    "pubspec.yaml",
    "tools/build_macos_native_host_companion_pkg.sh",
    "tools/verify_macos_native_host_companion_pkg.py",
    "tools/native_messaging/README-macos-companion-pkg.md",
    "tools/native_messaging/build_native_host.sh",
    "tools/native_messaging/sign_macos_native_host.sh",
    "tools/native_messaging/macos_native_host.entitlements",
    "tools/native_messaging/host/bin/wins_bridge_host.dart",
    "tools/native_messaging/host/pubspec.yaml",
    "tools/native_messaging/host/pubspec.lock",
    # The host package compiles these app sources through relative symlinks in
    # tools/native_messaging/host/lib; bind the resolved bytes, not the links.
    "lib/browser_bridge_app_ipc.dart",
    "lib/browser_bridge_framing.dart",
    "lib/browser_bridge_protocol.dart",
    "lib/browser_bridge_proxy.dart",
    "lib/vpn_config_validation.dart",
    "lib/windows_system_executable.dart",
    "lib/winn_carrier_profile_keys.dart",
    "lib/winn_protocol_dispatch.dart",
)
WRITABLE_MASK = stat.S_IWGRP | stat.S_IWOTH
REQUIRED_SCRIPT_NEEDLES = (
    INSTALLED_HOST_PATH,
    FIREFOX_MANIFEST_PATH,
    CHROME_MANIFEST_PATH,
    EDGE_MANIFEST_PATH,
    FIREFOX_EXTENSION_ID,
    "restore_rollback",
    ".winsvpn-native-host-rollback",
    ".new",
    "/bin/mv -h",
    "root:wheel",
    "fail before mutation",
    "must be distinct",
    "chrome_extension_id",
    "edge_extension_id",
    "refusing symlink parent",
    "refusing symlink native-host path",
    "refusing special native-host path",
    "refusing hardlinked native-host path",
    "changed while it was bound",
    "duplicate JSON key",
    "inner_files",
    "receipt inner_files is not exact",
    '[ "${firefox_ext_type}" = "array" ]',
    '[ "${chrome_origin_type}" = "array" ]',
    '[ "${edge_origin_type}" = "array" ]',
    '[ "${inner_type}" = "array" ]',
    '[ "${inner_len}" = "5" ]',
    '[ "${seen_host}" = "0" ]',
    '[ "${seen_firefox}" = "0" ]',
    '[ "${seen_chrome}" = "0" ]',
    '[ "${seen_edge}" = "0" ]',
    '[ "${seen_uninstall}" = "0" ]',
    '/usr/bin/stat -f %z',
    '[ "${actual_bytes}" = "${bytes}" ]',
    "receipt-bound inner bytes do not match",
    ".mutated",
    "rollback could not restore",
    "exec 3<>",
    "/dev/fd/3",
    "cleanup_install_temps",
    "bind_rollback_dir",
    "held_stage_replace",
    "stat -f %i /dev/fd/3",
    "stat -f %HT /dev/fd/3",
    "stat -f %l /dev/fd/3",
    "/bin/sync",
    "conv=notrunc,fsync",
    "durably before any live",
    IDENTITY_RECEIPT_PATH,
    "identity_preflight",
    "issue_identity_receipt",
    "identity_receipt_valid",
    "/dev/urandom",
    "/bin/chmod 0444",
    'json_require_keys "${identity_flat}" "v secret"',
)
REQUIRED_POSTINSTALL_ACTIVE_LINES = (
    '[ "${firefox_ext_type}" = "array" ] || fail "Firefox native-host manifest is not exact"',
    '[ "${chrome_origin_type}" = "array" ] || fail "Chrome native-host manifest is not exact"',
    '[ "${edge_origin_type}" = "array" ] || fail "Edge native-host manifest is not exact"',
    '[ "${inner_type}" = "array" ] || fail "receipt inner_files is not exact"',
    '[ "${inner_len}" = "5" ] || fail "receipt inner_files is not exact"',
    '[ "${seen_host}" = "0" ] || fail "receipt inner_files is not exact"',
    '[ "${seen_firefox}" = "0" ] || fail "receipt inner_files is not exact"',
    '[ "${seen_chrome}" = "0" ] || fail "receipt inner_files is not exact"',
    '[ "${seen_edge}" = "0" ] || fail "receipt inner_files is not exact"',
    '[ "${seen_uninstall}" = "0" ] || fail "receipt inner_files is not exact"',
    'actual_bytes="$(/usr/bin/stat -f %z "${target}")"',
    '[ "${actual_bytes}" = "${bytes}" ] || fail "receipt-bound inner bytes do not match"',
)
FORBIDDEN_POSTINSTALL_NEEDLES = (
    (
        'json_has "${receipt_flat}" "inner_files.length"',
        "postinstall treats receipt inner_files as optional",
    ),
    (
        '[ "${inner_len}" -ge 1 ]',
        "postinstall treats receipt inner_files length as a minimum, not exact",
    ),
    (
        '/bin/mv -f "${tmp}" "${dest}"',
        "postinstall moves onto a mutable dest pathname that can be a symlink to a directory",
    ),
    (
        '/bin/mv -f "${ROLLBACK}/${name}" "${dest}"',
        "postinstall restores onto a mutable dest pathname that can be a symlink to a directory",
    ),
    (
        '/bin/cp "${source}" "${tmp}"',
        "postinstall copies onto a mutable staging pathname that can be a symlink to a directory",
    ),
    (
        '/bin/cat "${source}" > "${tmp}"',
        "postinstall copies onto a mutable staging pathname that can be a symlink to a directory",
    ),
    (
        'printf \'mutated\\n\' > "${ROLLBACK}/${name}.mutated"',
        "postinstall records mutation state through a mutable rollback pathname",
    ),
    (
        '"${HOST_DIR}"/.winsvpn-stage.*',
        "postinstall cleanup glob follows a swapped parent",
    ),
    (
        '$(/usr/bin/dirname "${CHROME_PATH}")"/.winsvpn-stage.*',
        "postinstall cleanup glob follows a swapped Chrome parent",
    ),
    (
        '${HOST_DIR}/.winsvpn-json',
        "postinstall leaks JSON parse scratch into the host directory",
    ),
    (
        "stat -f '%d:%i' /dev/fd/3",
        "postinstall compares Darwin fdesc device ids against the held temp pathname",
    ),
)
REQUIRED_UNINSTALL_NEEDLES = (
    INSTALLED_HOST_PATH,
    FIREFOX_MANIFEST_PATH,
    CHROME_MANIFEST_PATH,
    EDGE_MANIFEST_PATH,
    RECEIPT_PATH,
    UNINSTALL_PATH,
    PACKAGE_IDENTIFIER,
    "explicit",
    "bind_dest_parent",
    "uninstall could not remove every exact file",
    "remove_held_leaf",
    "./.winsvpn-stage.*",
    IDENTITY_RECEIPT_PATH,
)
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 1024 * 1024
MAX_SCRIPT_BYTES = 256 * 1024
MAX_HOST_BYTES = 128 * 1024 * 1024
MAX_PKG_BYTES = 512 * 1024 * 1024
TOOL_TIMEOUT_SEC = 60
PACKAGE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
RECEIPT_KEYS = frozenset(
    {
        "contract",
        "schema_version",
        "team_id",
        "installer_authority",
        "application_authority",
        "package_identifier",
        "package_version",
        "installed_host_path",
        "firefox_extension_id",
        "chrome_extension_id",
        "edge_extension_id",
        "host_name",
        "inner_files",
        "scripts",
        "source_closure",
        "source_closure_sha256",
    }
)


class CompanionPkgError(RuntimeError):
    """Fail-closed companion PKG refusal."""


class OwnerBlocked(CompanionPkgError):
    """Missing owner-held identity, certificate, or receipt input."""


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _stat_token(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    )


def _bind_pkg_snapshot(source: pathlib.Path, destination: pathlib.Path) -> dict[str, object]:
    """Copy one stable regular PKG byte view into private verifier custody."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
    except OSError as exc:
        raise CompanionPkgError("companion PKG cannot be opened without following links") from exc
    digest = hashlib.sha256()
    copied = 0
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise CompanionPkgError("companion PKG must be one unaliased regular file")
        if before.st_size <= 0 or before.st_size > MAX_PKG_BYTES:
            raise CompanionPkgError("companion PKG is empty or exceeds the reviewed size ceiling")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o400,
        )
        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            copied += len(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise CompanionPkgError("companion PKG custody copy made no progress")
                view = view[written:]
        after = os.fstat(source_fd)
        if _stat_token(before) != _stat_token(after) or copied != before.st_size:
            raise CompanionPkgError("companion PKG changed while its bytes were being bound")
        os.fchmod(destination_fd, 0o400)
        os.fsync(destination_fd)
    except OSError as exc:
        raise CompanionPkgError("companion PKG custody copy failed") from exc
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)
    try:
        parent_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        raise CompanionPkgError("companion PKG custody directory could not be synchronized") from exc
    snapshot = destination.lstat()
    if (
        not stat.S_ISREG(snapshot.st_mode)
        or snapshot.st_nlink != 1
        or stat.S_IMODE(snapshot.st_mode) != 0o400
        or snapshot.st_size != copied
    ):
        raise CompanionPkgError("companion PKG custody snapshot is not immutable-by-mode")
    return {
        "sha256": digest.hexdigest(),
        "bytes": copied,
        "stat": _stat_token(snapshot),
    }


def _assert_pkg_snapshot(path: pathlib.Path, custody: dict[str, object]) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise CompanionPkgError("companion PKG custody snapshot disappeared") from exc
    if (
        _stat_token(info) != custody.get("stat")
        or not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o400
        or _sha256_file(path) != custody.get("sha256")
    ):
        raise CompanionPkgError("companion PKG custody snapshot changed during verification")


def _tool_env() -> dict[str, str]:
    return {
        "PATH": REVIEWED_SUBPROCESS_PATH,
        "HOME": "/var/empty",
        "TMPDIR": "/tmp",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _run(argv: list[str], *, timeout: int = TOOL_TIMEOUT_SEC) -> subprocess.CompletedProcess[str]:
    if not argv or argv[0] not in REVIEWED_TOOLS:
        raise CompanionPkgError(f"unreviewed inspection tool: {argv[:1]!r}")
    try:
        return subprocess.run(
            argv,
            cwd="/",
            env=_tool_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CompanionPkgError(f"{argv[0]} failed to start or timed out") from exc


def _read_regular_text(path: pathlib.Path, label: str, limit: int) -> str:
    if path.is_symlink() or not path.is_file():
        raise CompanionPkgError(f"{label} must be one regular file")
    data = path.read_bytes()
    if not data or len(data) > limit:
        raise CompanionPkgError(f"{label} is empty or exceeds the reviewed size ceiling")
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CompanionPkgError(f"{label} is not ASCII") from exc


def _read_regular_bytes(path: pathlib.Path, label: str, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise CompanionPkgError(f"{label} must be one regular file")
    data = path.read_bytes()
    if not data or len(data) > limit:
        raise CompanionPkgError(f"{label} is empty or exceeds the reviewed size ceiling")
    return data


def _reject_duplicate_keys(pairs: list[tuple[str, object]], label: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CompanionPkgError(f"{label} has a duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_object(path: pathlib.Path, label: str) -> dict[str, object]:
    payload = _read_regular_bytes(path, label, MAX_JSON_BYTES)
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=lambda pairs: _reject_duplicate_keys(pairs, label),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CompanionPkgError(f"{label} is not JSON") from exc
    if type(document) is not dict:
        raise CompanionPkgError(f"{label} must be one JSON object")
    encoded = json.dumps(document, ensure_ascii=True)
    if PLACEHOLDER.search(encoded):
        raise CompanionPkgError(f"{label} still contains a placeholder")
    return document


def _cpu_architecture(cputype: int) -> str:
    if cputype == CPU_TYPE_ARM64:
        return "arm64"
    if cputype == CPU_TYPE_X86_64:
        return "x86_64"
    raise CompanionPkgError(f"native-host CPU type is not allowed: {cputype}")


def _thin_macho_slice(data: bytes) -> tuple[str, int]:
    if len(data) < 32:
        raise CompanionPkgError("native-host Mach-O header is truncated")
    magic = data[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        endian = "<"
    elif magic == b"\xfe\xed\xfa\xcf":
        endian = ">"
    else:
        raise CompanionPkgError("native-host slice is not a 64-bit Mach-O image")
    cputype = struct.unpack_from(endian + "I", data, 4)[0]
    filetype = struct.unpack_from(endian + "I", data, 12)[0]
    return _cpu_architecture(cputype), filetype


def macho_slices(data: bytes) -> list[tuple[str, int]]:
    if len(data) < 8:
        raise CompanionPkgError("native-host Mach-O image is truncated")
    magic = data[:4]
    if magic not in FAT_ENDIAN:
        return [_thin_macho_slice(data)]
    endian = FAT_ENDIAN[magic]
    is_64 = magic in FAT_64
    count = struct.unpack_from(endian + "I", data, 4)[0]
    entry_size = 32 if is_64 else 20
    if count <= 0 or count > 8 or 8 + count * entry_size > len(data):
        raise CompanionPkgError("native-host fat Mach-O header is malformed")
    slices: list[tuple[str, int]] = []
    seen: set[str] = set()
    for index in range(count):
        entry = 8 + index * entry_size
        cputype = struct.unpack_from(endian + "I", data, entry)[0]
        if is_64:
            offset = struct.unpack_from(endian + "Q", data, entry + 8)[0]
            size = struct.unpack_from(endian + "Q", data, entry + 16)[0]
        else:
            offset = struct.unpack_from(endian + "I", data, entry + 8)[0]
            size = struct.unpack_from(endian + "I", data, entry + 12)[0]
        if offset < 0 or size < 32 or offset + size > len(data):
            raise CompanionPkgError("native-host fat Mach-O slice is truncated")
        arch, filetype = _thin_macho_slice(data[offset : offset + size])
        if arch in seen:
            raise CompanionPkgError("native-host Mach-O contains a duplicate architecture")
        seen.add(arch)
        if _cpu_architecture(cputype) != arch:
            raise CompanionPkgError("native-host fat architecture table is inconsistent")
        slices.append((arch, filetype))
    return slices


def accepted_architecture_sets(package_version: str | None) -> list[frozenset[str]]:
    accepted = [REQUIRED_ARCHITECTURES]
    if package_version in ARM64_ONLY_RELEASE_LINES:
        accepted.append(ARM64_ONLY_ARCHITECTURES)
    return accepted


def verify_universal_execute(
    data: bytes, *, package_version: str | None = None
) -> tuple[str, ...]:
    slices = macho_slices(data)
    archs = tuple(arch for arch, _filetype in slices)
    filetypes = {filetype for _arch, filetype in slices}
    if filetypes != {MH_EXECUTE}:
        raise CompanionPkgError("native-host Mach-O filetype must be MH_EXECUTE")
    accepted = accepted_architecture_sets(package_version)
    if set(archs) not in accepted:
        raise CompanionPkgError(
            "native-host must be a universal x86_64+arm64 Mach-O executable"
            + (
                " or, under the owner ruling of "
                + ARM64_ONLY_OWNER_RULING_DATE
                + " for release line "
                + str(package_version)
                + ", an arm64 executable"
                if len(accepted) > 1
                else ""
            )
        )
    return archs


def _decode_macos_version(encoded: int) -> tuple[int, int, int]:
    return (encoded >> 16, (encoded >> 8) & 0xFF, encoded & 0xFF)


def _thin_minimum_macos(data: bytes) -> tuple[int, int, int] | None:
    endian = "<" if data[:4] == b"\xcf\xfa\xed\xfe" else ">"
    ncmds, sizeofcmds = struct.unpack_from(endian + "II", data, 16)
    offset = 32
    end = offset + sizeofcmds
    if end > len(data) or ncmds > 4096:
        raise CompanionPkgError("native-host Mach-O load commands are truncated")
    found: tuple[int, int, int] | None = None
    for _index in range(ncmds):
        if offset + 8 > end:
            raise CompanionPkgError("native-host Mach-O load commands are truncated")
        cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        if cmdsize < 8 or offset + cmdsize > end:
            raise CompanionPkgError("native-host Mach-O load command is malformed")
        if cmd == LC_BUILD_VERSION:
            if cmdsize < 24:
                raise CompanionPkgError("native-host LC_BUILD_VERSION is malformed")
            platform, minos = struct.unpack_from(endian + "II", data, offset + 8)
            if platform != PLATFORM_MACOS:
                raise CompanionPkgError("native-host Mach-O is not built for macOS")
            version = _decode_macos_version(minos)
            if found is not None and found != version:
                raise CompanionPkgError("native-host Mach-O declares conflicting minimum macOS")
            found = version
        elif cmd == LC_VERSION_MIN_MACOSX:
            if cmdsize < 16:
                raise CompanionPkgError("native-host LC_VERSION_MIN_MACOSX is malformed")
            (minos,) = struct.unpack_from(endian + "I", data, offset + 8)
            version = _decode_macos_version(minos)
            if found is not None and found != version:
                raise CompanionPkgError("native-host Mach-O declares conflicting minimum macOS")
            found = version
        offset += cmdsize
    return found


def macho_minimum_macos(data: bytes) -> tuple[int, int, int] | None:
    """Highest minimum macOS any slice declares, or None when none declares one."""

    if len(data) < 32:
        raise CompanionPkgError("native-host Mach-O image is truncated")
    magic = data[:4]
    images: list[bytes] = []
    if magic in FAT_ENDIAN:
        endian = FAT_ENDIAN[magic]
        is_64 = magic in FAT_64
        count = struct.unpack_from(endian + "I", data, 4)[0]
        entry_size = 32 if is_64 else 20
        if count <= 0 or count > 8 or 8 + count * entry_size > len(data):
            raise CompanionPkgError("native-host fat Mach-O header is malformed")
        for index in range(count):
            entry = 8 + index * entry_size
            if is_64:
                offset = struct.unpack_from(endian + "Q", data, entry + 8)[0]
                size = struct.unpack_from(endian + "Q", data, entry + 16)[0]
            else:
                offset = struct.unpack_from(endian + "I", data, entry + 8)[0]
                size = struct.unpack_from(endian + "I", data, entry + 12)[0]
            if size < 32 or offset + size > len(data):
                raise CompanionPkgError("native-host fat Mach-O slice is truncated")
            images.append(data[offset : offset + size])
    else:
        images.append(data)
    versions = [v for v in (_thin_minimum_macos(image) for image in images) if v is not None]
    return max(versions) if versions else None


def format_macos_version(version: tuple[int, int, int]) -> str:
    major, minor, patch = version
    return f"{major}.{minor}" if patch == 0 else f"{major}.{minor}.{patch}"


def parse_macos_version(text: str) -> tuple[int, int, int]:
    if re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}", text or "") is None:
        raise CompanionPkgError("companion Distribution minimum macOS is not exact")
    parts = [int(part) for part in text.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2])


def distribution_host_architectures(archs: tuple[str, ...] | list[str]) -> str:
    return ",".join(sorted(set(archs)))


def _walk_no_follow(root: pathlib.Path) -> list[pathlib.Path]:
    found: list[pathlib.Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            raise CompanionPkgError(f"payload directory is unreadable: {current}") from exc
        for entry in entries:
            path = pathlib.Path(entry.path)
            found.append(path)
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_symlink = entry.is_symlink()
            except OSError as exc:
                raise CompanionPkgError(f"payload entry is unreadable: {path}") from exc
            if is_symlink:
                continue
            if is_dir:
                stack.append(path)
    found.sort()
    return found


def reject_symlinks(root: pathlib.Path) -> None:
    for path in _walk_no_follow(root):
        if path.is_symlink():
            raise CompanionPkgError(f"symlink payload is refused: {path}")


def reject_writable(path: pathlib.Path, label: str) -> None:
    if path.is_symlink():
        raise CompanionPkgError(f"{label} is a symlink")
    try:
        info = path.lstat()
    except OSError as exc:
        raise CompanionPkgError(f"{label} is unreadable") from exc
    if stat.S_IMODE(info.st_mode) & WRITABLE_MASK:
        raise CompanionPkgError(f"{label} is group/other-writable")


def parse_codesign_output(output: str) -> dict[str, object]:
    text = output or ""
    lowered = text.lower()
    authorities = [
        line.split("=", 1)[1].strip()
        for line in text.splitlines()
        if line.startswith("Authority=")
    ]
    teams = [
        line.split("=", 1)[1].strip()
        for line in text.splitlines()
        if line.startswith("TeamIdentifier=")
    ]
    team = teams[0] if len(teams) == 1 else ""
    leaf = authorities[0] if authorities else ""
    signed = bool(authorities) and "Signature=adhoc" not in text
    return {
        "signed": signed,
        "team_id": team,
        "developer_id_application": leaf.startswith("Developer ID Application:"),
        "app_store": (
            "Authority=Apple Distribution:" in text
            or "3rd party mac developer" in lowered
        ),
        "runtime": "(runtime)" in lowered or "flags=" in lowered and "runtime" in lowered,
        "raw": text,
    }


def require_developer_id_application(info: dict[str, object]) -> None:
    if info.get("app_store") is True:
        raise CompanionPkgError(
            "App Store signing cannot cover a native-messaging host outside "
            "the sandboxed app"
        )
    if info.get("signed") is not True:
        raise CompanionPkgError("native-host Application signature is missing")
    if info.get("developer_id_application") is not True:
        raise CompanionPkgError(
            "native-host signer must be Developer ID Application for team "
            f"{TEAM_ID}"
        )
    if info.get("team_id") != TEAM_ID:
        raise CompanionPkgError("native-host team identity is not release-valid")
    if info.get("runtime") is not True:
        raise CompanionPkgError(
            "native-host Application signature is not notarizable (hardened runtime is missing)"
        )


def inspect_host_signature(path: pathlib.Path) -> dict[str, object]:
    verified = _run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=4", "--", str(path)]
    )
    if verified.returncode != 0:
        raise CompanionPkgError("native-host Application signature is cryptographically invalid")
    details = _run(["/usr/bin/codesign", "-d", "--verbose=4", "--", str(path)])
    output = details.stdout + details.stderr
    if details.returncode != 0:
        raise CompanionPkgError("native-host Application signature is missing")
    info = parse_codesign_output(output)
    require_developer_id_application(info)
    entitlements = _run(
        [
            "/usr/bin/codesign",
            "-d",
            "--entitlements",
            "-",
            "--xml",
            "--",
            str(path),
        ]
    )
    if entitlements.returncode != 0:
        raise CompanionPkgError("native-host entitlements are unreadable")
    require_host_entitlements(entitlements.stdout)
    info["entitlements"] = dict(REQUIRED_HOST_ENTITLEMENTS)
    return info


def require_host_entitlements(xml_text: str) -> None:
    payload = (xml_text or "").strip().encode("utf-8")
    if not payload:
        raise CompanionPkgError(
            "native-host signature carries no entitlements; the App Group and "
            "Dart AOT executable-memory entitlements are required"
        )
    upper = payload.upper()
    if b"<!ENTITY" in upper:
        raise CompanionPkgError("native-host entitlements contain a forbidden declaration")
    try:
        document = plistlib.loads(payload)
    except Exception as exc:  # plistlib raises several unrelated types
        raise CompanionPkgError("native-host entitlements are not an exact plist") from exc
    if type(document) is not dict:
        raise CompanionPkgError("native-host entitlements are not an exact plist")
    if document != REQUIRED_HOST_ENTITLEMENTS:
        raise CompanionPkgError(
            "native-host entitlements are not exact: require only "
            + ", ".join(sorted(REQUIRED_HOST_ENTITLEMENTS))
        )


def require_developer_id_installer(output: str, returncode: int) -> None:
    text = output or ""
    lowered = text.lower()
    if returncode != 0 or "status: no signature" in lowered or "status: signed by a certificate that has since" in lowered:
        raise CompanionPkgError("companion PKG is unsigned")
    if "3rd party mac developer installer" in lowered:
        raise CompanionPkgError(
            "companion PKG signer must be Developer ID Installer; "
            "App Store installer signing cannot deliver this host"
        )
    leaf_matches = re.findall(
        r"(?m)^\s*1\.\s+(Developer ID Installer:[^\r\n]+)\s*$", text
    )
    if len(leaf_matches) != 1 or not leaf_matches[0].endswith(f"({TEAM_ID})"):
        raise CompanionPkgError(
            f"companion PKG must be signed by Developer ID Installer team {TEAM_ID}"
        )
    if "status: signed by a developer certificate issued by apple for distribution" not in lowered:
        if "status: signed by a developer id certificate" not in lowered:
            raise CompanionPkgError("companion PKG installer signature is not release-valid")


def require_stapled_ticket(output: str, returncode: int) -> None:
    text = output or ""
    if returncode != 0 or "the validate action worked" not in text.lower():
        raise CompanionPkgError("companion PKG notarization ticket is not stapled")


def require_notarized_install(output: str, returncode: int) -> None:
    text = output or ""
    if returncode != 0 or "source=Notarized Developer ID" not in text:
        raise CompanionPkgError(
            "companion PKG lacks a locally assessable notarized Developer ID ticket"
        )


def verify_pkg_identity(pkg: pathlib.Path) -> dict[str, str]:
    if pkg.is_symlink() or not pkg.is_file():
        raise CompanionPkgError("companion PKG must be one regular file")
    signature = _run(["/usr/sbin/pkgutil", "--check-signature", str(pkg)])
    require_developer_id_installer(
        signature.stdout + signature.stderr, signature.returncode
    )
    stapler = _run(["/usr/bin/stapler", "validate", str(pkg)])
    require_stapled_ticket(stapler.stdout + stapler.stderr, stapler.returncode)
    spctl = _run(
        ["/usr/sbin/spctl", "--assess", "--verbose=4", "--type", "install", str(pkg)]
    )
    require_notarized_install(spctl.stdout + spctl.stderr, spctl.returncode)
    return {"team_id": TEAM_ID, "installer": "Developer ID Installer"}


def _active_script_lines(body: str) -> frozenset[str]:
    lines: set[str] = set()
    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.add(stripped)
    return frozenset(lines)


def verify_scripts(preinstall: str, postinstall: str, uninstall: str) -> None:
    for label, body in (
        ("preinstall", preinstall),
        ("postinstall", postinstall),
        ("uninstall", uninstall),
    ):
        if not body.startswith("#!/bin/sh\n"):
            raise CompanionPkgError(f"{label} must be a static POSIX /bin/sh script")
        if PYTHON_HINT.search(body):
            raise CompanionPkgError(f"{label} is Python-dependent and cannot ship to consumers")
        if REPO_HINT.search(body):
            raise CompanionPkgError(f"{label} depends on the repository")
        if PLACEHOLDER.search(body):
            raise CompanionPkgError(f"{label} still contains a placeholder")
    combined = preinstall + "\n" + postinstall
    for needle in REQUIRED_SCRIPT_NEEDLES:
        if needle not in combined:
            raise CompanionPkgError(
                f"companion scripts omit required install contract: {needle}"
            )
    if "restore_rollback" not in postinstall or "rollback" not in preinstall:
        raise CompanionPkgError("companion scripts omit rollback")
    if "verify_incoming" not in postinstall:
        raise CompanionPkgError("companion scripts omit fail-before-mutation incoming verification")
    if "/usr/bin/grep -F" in postinstall:
        raise CompanionPkgError("postinstall origin checks must parse JSON, not substring grep")
    if "json_flatten" not in postinstall or "duplicate JSON key" not in postinstall:
        raise CompanionPkgError("postinstall omits strict duplicate-key-free JSON parsing")
    if "inner_files" not in postinstall:
        raise CompanionPkgError("postinstall omits receipt inner file hash binding")
    active_postinstall = _active_script_lines(postinstall)
    for line in REQUIRED_POSTINSTALL_ACTIVE_LINES:
        if line not in active_postinstall:
            raise CompanionPkgError(
                f"postinstall omits required exact install contract line: {line}"
            )
    for needle, message in FORBIDDEN_POSTINSTALL_NEEDLES:
        if needle in postinstall:
            raise CompanionPkgError(message)
    if "receipt inner_files is not exact" not in postinstall:
        raise CompanionPkgError("postinstall omits mandatory receipt inner_files array check")
    if ".mutated" not in postinstall:
        raise CompanionPkgError("postinstall omits per-target mutation tracking")
    if "rollback could not restore" not in postinstall:
        raise CompanionPkgError("postinstall omits rollback failure signaling")
    for needle in REQUIRED_UNINSTALL_NEEDLES:
        if needle not in uninstall:
            raise CompanionPkgError(
                f"uninstall helper omits required exact path or identifier: {needle}"
            )
    if "rm -rf /" in uninstall or "rm -rf /*" in uninstall:
        raise CompanionPkgError("uninstall helper is not a safe exact-path helper")
    if '/bin/rm -f "${path}"' in uninstall:
        raise CompanionPkgError("uninstall removes by mutable pathname")
    if "bind_dest_parent" not in uninstall:
        raise CompanionPkgError("uninstall omits descriptor-bound parent binding")
    if "./.winsvpn-stage.*" not in uninstall:
        raise CompanionPkgError(
            "uninstall omits leftover stage cleanup in bound rollback directories"
        )
    if "${ROLLBACK}/.winsvpn-stage." in uninstall or '"${HOST_DIR}"/.winsvpn-stage.' in uninstall:
        raise CompanionPkgError("uninstall cleanup glob follows a swapped parent")
    atomic_start = postinstall.find("atomic_install() {")
    verify_call = postinstall.find("verify_incoming || exit 1")
    if atomic_start < 0 or verify_call < 0 or atomic_start > verify_call:
        raise CompanionPkgError("postinstall omits atomic install")
    atomic = postinstall[atomic_start:verify_call]
    mark_at = atomic.find('mark_mutated "${name}"')
    replace_at = atomic.find('held_stage_replace "${leaf}"')
    if mark_at < 0 or replace_at < 0 or mark_at > replace_at:
        raise CompanionPkgError(
            "postinstall journals mutation state after live replace"
        )
    mark_fn_start = postinstall.find("mark_mutated() {")
    restore_one_start = postinstall.find("restore_one() {")
    if mark_fn_start < 0 or restore_one_start < 0 or mark_fn_start > restore_one_start:
        raise CompanionPkgError("postinstall omits per-target mutation tracking")
    mark_fn = postinstall[mark_fn_start:restore_one_start]
    if "/bin/sync" not in mark_fn:
        raise CompanionPkgError("postinstall omits durable mutation journal sync")
    if "conv=notrunc,fsync" not in postinstall:
        raise CompanionPkgError("postinstall omits descriptor-bound durable staging sync")


def shared_manifest(host_path: str) -> dict[str, object]:
    if host_path != INSTALLED_HOST_PATH:
        raise CompanionPkgError("native-host manifest path is not the exact installed path")
    return {
        "name": HOST_NAME,
        "description": HOST_DESCRIPTION,
        "path": host_path,
        "type": "stdio",
    }


def verify_manifests(
    *,
    firefox: dict[str, object],
    chrome: dict[str, object],
    edge: dict[str, object],
    chrome_id: str,
    edge_id: str,
) -> None:
    if not chrome_id or PLACEHOLDER.search(chrome_id):
        raise CompanionPkgError("Chrome store-listing id is missing")
    if CHROMIUM_EXTENSION_ID.fullmatch(chrome_id) is None:
        raise CompanionPkgError("Chrome store-listing id is not a reviewed 32-letter identity")
    if not edge_id or PLACEHOLDER.search(edge_id):
        raise CompanionPkgError("Edge store-listing id is missing")
    if CHROMIUM_EXTENSION_ID.fullmatch(edge_id) is None:
        raise CompanionPkgError("Edge store-listing id is not a reviewed 32-letter identity")
    if chrome_id == edge_id:
        raise CompanionPkgError(
            "Chrome and Edge store-listing ids must be distinct"
        )
    shared = shared_manifest(INSTALLED_HOST_PATH)
    if firefox != {**shared, "allowed_extensions": [FIREFOX_EXTENSION_ID]}:
        raise CompanionPkgError("Firefox native-host manifest is not exact")
    chrome_origin = f"chrome-extension://{chrome_id}/"
    edge_origin = f"chrome-extension://{edge_id}/"
    if chrome.get("allowed_origins") == [edge_origin]:
        raise CompanionPkgError("Chrome native-host manifest reuses the Edge identity")
    if edge.get("allowed_origins") == [chrome_origin]:
        raise CompanionPkgError("Edge native-host manifest reuses the Chrome identity")
    expected_chrome = {
        **shared,
        "allowed_origins": [chrome_origin],
    }
    if chrome != expected_chrome:
        raise CompanionPkgError("Chrome native-host manifest is not exact")
    expected_edge = {
        **shared,
        "allowed_origins": [edge_origin],
    }
    if edge != expected_edge:
        raise CompanionPkgError("Edge native-host manifest is not exact")


def compute_source_closure(
    *, repo: pathlib.Path | None = None
) -> tuple[str, list[dict[str, object]]]:
    root = ORIGIN_ROOT if repo is None else repo
    records: list[dict[str, object]] = []
    for relative in SOURCE_CLOSURE_PATHS:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise OwnerBlocked(
                f"companion PKG source closure is missing regular file {relative}"
            )
        payload = path.read_bytes()
        if not payload:
            raise OwnerBlocked(f"companion PKG source closure file is empty: {relative}")
        records.append(
            {
                "path": relative,
                "sha256": _sha256_bytes(payload),
                "bytes": len(payload),
            }
        )
    encoded = (
        json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    return _sha256_bytes(encoded), records


def release_version(*, repo: pathlib.Path | None = None) -> str:
    root = ORIGIN_ROOT if repo is None else repo
    path = root / "pubspec.yaml"
    text = _read_regular_text(path, "pubspec release version", MAX_JSON_BYTES)
    matches = re.findall(r"(?m)^version:\s*([^\s+]+)(?:\+[^\s]+)?\s*$", text)
    if len(matches) != 1 or PACKAGE_VERSION.fullmatch(matches[0]) is None:
        raise OwnerBlocked("companion PKG release version is not exact in pubspec.yaml")
    return matches[0]


def canonical_receipt_bytes(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


def build_receipt(
    *,
    payload_root: pathlib.Path,
    scripts_dir: pathlib.Path,
    chrome_id: str,
    edge_id: str,
    repo: pathlib.Path | None = None,
) -> dict[str, object]:
    if CHROMIUM_EXTENSION_ID.fullmatch(chrome_id) is None:
        raise OwnerBlocked(
            "Chrome store-listing id is owner-blocked; refusing to invent one"
        )
    if not edge_id or PLACEHOLDER.search(edge_id) or CHROMIUM_EXTENSION_ID.fullmatch(edge_id) is None:
        raise OwnerBlocked(
            "Edge store-listing id is owner-blocked; refusing to invent one"
        )
    if chrome_id == edge_id:
        raise OwnerBlocked(
            "Chrome and Edge store-listing ids must be distinct; refusing to reuse one identity"
        )
    incoming = payload_root.joinpath(*pathlib.PurePosixPath(INCOMING_RELATIVE).parts)
    inner_files: list[dict[str, object]] = []
    for name in INCOMING_FILES:
        if name == "receipt.json":
            continue
        path = incoming / name
        if path.is_symlink() or not path.is_file():
            raise CompanionPkgError(f"incoming payload file is missing: {name}")
        inner_files.append(
            {
                "path": f"{INCOMING_RELATIVE}/{name}",
                "sha256": _sha256_file(path),
                "bytes": path.stat().st_size,
                "mode": oct(stat.S_IMODE(path.stat().st_mode)),
            }
        )
    scripts = []
    for name in ("preinstall", "postinstall"):
        path = scripts_dir / name
        if path.is_symlink() or not path.is_file():
            raise CompanionPkgError(f"companion {name} script is missing")
        scripts.append(
            {
                "path": name,
                "sha256": _sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    digest, records = compute_source_closure(repo=repo)
    package_version = release_version(repo=repo)
    document: dict[str, object] = {
        "contract": RECEIPT_CONTRACT,
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "team_id": TEAM_ID,
        "installer_authority": "Developer ID Installer",
        "application_authority": "Developer ID Application",
        "package_identifier": PACKAGE_IDENTIFIER,
        "package_version": package_version,
        "installed_host_path": INSTALLED_HOST_PATH,
        "firefox_extension_id": FIREFOX_EXTENSION_ID,
        "chrome_extension_id": chrome_id,
        "edge_extension_id": edge_id,
        "host_name": HOST_NAME,
        "inner_files": inner_files,
        "scripts": scripts,
        "source_closure": records,
        "source_closure_sha256": digest,
    }
    return document


def write_receipt(
    *,
    payload_root: pathlib.Path,
    scripts_dir: pathlib.Path,
    chrome_id: str,
    edge_id: str,
    output: pathlib.Path,
    repo: pathlib.Path | None = None,
) -> dict[str, object]:
    document = build_receipt(
        payload_root=payload_root,
        scripts_dir=scripts_dir,
        chrome_id=chrome_id,
        edge_id=edge_id,
        repo=repo,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_receipt_bytes(document)
    output.write_bytes(payload)
    os.chmod(output, 0o644)
    return document


def _one_named(root: pathlib.Path, name: str, *, kind: str) -> pathlib.Path:
    matches: list[pathlib.Path] = []
    for path in _walk_no_follow(root):
        if path.is_symlink():
            raise CompanionPkgError(f"symlink payload is refused: {path}")
        if path.name == name:
            is_dir = path.is_dir()
            if kind == "dir" and is_dir:
                matches.append(path)
            if kind == "file" and path.is_file():
                matches.append(path)
    if len(matches) != 1:
        raise CompanionPkgError(f"companion PKG must contain exactly one {name}")
    return matches[0]


def _relative_posix(path: pathlib.Path, root: pathlib.Path) -> str:
    return path.relative_to(root).as_posix()


def _payload_root_for_incoming(incoming: pathlib.Path) -> pathlib.Path:
    current = incoming
    for part in reversed(pathlib.PurePosixPath(INCOMING_RELATIVE).parts):
        if current.name != part:
            raise CompanionPkgError(
                "incoming payload is not at the exact system Incoming path"
            )
        current = current.parent
    return current


def verify_receipt(
    receipt: dict[str, object],
    *,
    scripts_dir: pathlib.Path,
    chrome_id: str,
    edge_id: str,
    payload_root: pathlib.Path,
) -> None:
    if set(receipt) != RECEIPT_KEYS:
        raise CompanionPkgError("companion receipt field set is not exact")
    if receipt.get("contract") != RECEIPT_CONTRACT:
        raise CompanionPkgError("companion receipt contract is not exact")
    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise CompanionPkgError("companion receipt schema is not exact")
    if receipt.get("team_id") != TEAM_ID:
        raise CompanionPkgError("companion receipt team is not release-valid")
    if receipt.get("installer_authority") != "Developer ID Installer":
        raise CompanionPkgError("companion receipt installer authority is not exact")
    if receipt.get("application_authority") != "Developer ID Application":
        raise CompanionPkgError("companion receipt application authority is not exact")
    if receipt.get("package_identifier") != PACKAGE_IDENTIFIER:
        raise CompanionPkgError("companion receipt package identifier is not exact")
    package_version = receipt.get("package_version")
    if type(package_version) is not str or PACKAGE_VERSION.fullmatch(package_version) is None:
        raise CompanionPkgError("companion receipt package version is not exact")
    if receipt.get("installed_host_path") != INSTALLED_HOST_PATH:
        raise CompanionPkgError("companion receipt host path is not exact")
    if receipt.get("firefox_extension_id") != FIREFOX_EXTENSION_ID:
        raise CompanionPkgError("companion receipt Firefox id is not exact")
    if receipt.get("chrome_extension_id") != chrome_id:
        raise CompanionPkgError("companion receipt Chrome id is not exact")
    if receipt.get("edge_extension_id") != edge_id:
        raise CompanionPkgError("companion receipt Edge id is not exact")
    inner = receipt.get("inner_files")
    if type(inner) is not list or not inner:
        raise CompanionPkgError("companion receipt does not bind inner files")
    expected_paths = {f"{INCOMING_RELATIVE}/{name}" for name in INCOMING_FILES if name != "receipt.json"}
    seen: set[str] = set()
    for item in inner:
        if type(item) is not dict:
            raise CompanionPkgError("companion receipt inner file record is invalid")
        relative = item.get("path")
        digest = item.get("sha256")
        size = item.get("bytes")
        if type(relative) is not str or type(digest) is not str or type(size) is not int:
            raise CompanionPkgError("companion receipt inner file record is incomplete")
        if relative in seen:
            raise CompanionPkgError("companion receipt inner file record is duplicated")
        seen.add(relative)
        if not SHA256_HEX.fullmatch(digest):
            raise CompanionPkgError("companion receipt inner digest is not SHA-256")
        path = payload_root.joinpath(*pathlib.PurePosixPath(relative).parts)
        if _relative_posix(path, payload_root) != relative:
            raise CompanionPkgError("companion receipt inner path escapes the payload")
        if path.is_symlink() or not path.is_file():
            raise CompanionPkgError(f"receipt-bound inner file is missing: {relative}")
        if _sha256_file(path) != digest:
            raise CompanionPkgError(f"receipt-bound inner digest does not match: {relative}")
        if path.stat().st_size != size:
            raise CompanionPkgError(f"receipt-bound inner bytes do not match: {relative}")
    if seen != expected_paths:
        raise CompanionPkgError("companion receipt does not bind every inner payload file")
    scripts = receipt.get("scripts")
    if type(scripts) is not list or len(scripts) != 2:
        raise CompanionPkgError("companion receipt does not bind install scripts")
    for item in scripts:
        if type(item) is not dict:
            raise CompanionPkgError("companion receipt script record is invalid")
        name = item.get("path")
        digest = item.get("sha256")
        if name not in {"preinstall", "postinstall"} or type(digest) is not str:
            raise CompanionPkgError("companion receipt script record is incomplete")
        path = scripts_dir / str(name)
        if path.is_symlink() or not path.is_file():
            raise CompanionPkgError(f"receipt-bound script is missing: {name}")
        if _sha256_file(path) != digest:
            raise CompanionPkgError(f"receipt-bound script digest does not match: {name}")
    closure = receipt.get("source_closure")
    digest = receipt.get("source_closure_sha256")
    if type(closure) is not list or type(digest) is not str or not SHA256_HEX.fullmatch(digest):
        raise CompanionPkgError("companion receipt source closure is missing")
    encoded = (
        json.dumps(closure, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if _sha256_bytes(encoded) != digest:
        raise CompanionPkgError("companion receipt source closure digest does not match")
    bound_paths = []
    for item in closure:
        if type(item) is not dict:
            raise CompanionPkgError("companion receipt source record is invalid")
        relative = item.get("path")
        file_digest = item.get("sha256")
        if type(relative) is not str or type(file_digest) is not str:
            raise CompanionPkgError("companion receipt source record is incomplete")
        if not SHA256_HEX.fullmatch(file_digest):
            raise CompanionPkgError("companion receipt source digest is not SHA-256")
        bound_paths.append(relative)
    if tuple(bound_paths) != SOURCE_CLOSURE_PATHS:
        raise CompanionPkgError("companion receipt source closure is not the reviewed set")


def _parse_safe_xml(path: pathlib.Path, label: str) -> ET.Element:
    payload = _read_regular_bytes(path, label, MAX_JSON_BYTES)
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise CompanionPkgError(f"{label} contains a forbidden declaration")
    try:
        return ET.fromstring(payload)
    except ET.ParseError as exc:
        raise CompanionPkgError(f"{label} is not exact XML") from exc


def verify_package_metadata(
    *,
    root: pathlib.Path,
    component: pathlib.Path,
    package_version: str,
    architectures: tuple[str, ...],
    minimum_macos: tuple[int, int, int] | None,
) -> None:
    top_level = {path.name for path in root.iterdir() if not path.name.startswith(".")}
    if top_level != {"Distribution", f"{PACKAGE_IDENTIFIER}.pkg"}:
        raise CompanionPkgError("companion product PKG top-level identity is not exact")
    distribution = _parse_safe_xml(root / "Distribution", "companion Distribution")
    if distribution.tag != "installer-gui-script":
        raise CompanionPkgError("companion Distribution root is not exact")
    choices = distribution.findall("./choice")
    if len(choices) != 1 or choices[0].get("id") != PACKAGE_IDENTIFIER:
        raise CompanionPkgError("companion Distribution choice identity is not exact")
    refs = distribution.findall(".//pkg-ref")
    if not refs or any(ref.get("id") != PACKAGE_IDENTIFIER for ref in refs):
        raise CompanionPkgError("companion Distribution package identity is not exact")
    payload_refs = [ref for ref in refs if (ref.text or "").strip()]
    if len(payload_refs) != 1:
        raise CompanionPkgError("companion Distribution package payload is not exact")
    payload_ref = payload_refs[0]
    # productbuild rewrites an embedded component reference to the in-archive
    # form "#<component>.pkg"; the hand-written distribution names it bare.
    if (
        (payload_ref.text or "").strip()
        not in {f"{PACKAGE_IDENTIFIER}.pkg", f"#{PACKAGE_IDENTIFIER}.pkg"}
        or payload_ref.get("version") != package_version
        or payload_ref.get("onConclusion") != "none"
    ):
        raise CompanionPkgError("companion Distribution version or payload is not exact")
    options = distribution.findall("./options")
    if len(options) != 1:
        raise CompanionPkgError("companion Distribution options are not exact")
    if options[0].get("hostArchitectures") != distribution_host_architectures(architectures):
        raise CompanionPkgError(
            "companion Distribution hostArchitectures does not match the host slices"
        )
    os_versions = distribution.findall("./volume-check/allowed-os-versions/os-version")
    if len(os_versions) != 1:
        raise CompanionPkgError("companion Distribution minimum macOS is not exact")
    declared = parse_macos_version(os_versions[0].get("min") or "")
    if minimum_macos is not None and declared < minimum_macos:
        raise CompanionPkgError(
            "companion Distribution allows macOS older than the host's minimum "
            + format_macos_version(minimum_macos)
        )
    package_info = _parse_safe_xml(component / "PackageInfo", "component PackageInfo")
    if (
        package_info.tag != "pkg-info"
        or package_info.get("identifier") != PACKAGE_IDENTIFIER
        or package_info.get("version") != package_version
        or package_info.get("auth") != "root"
    ):
        raise CompanionPkgError("component PackageInfo identity is not exact")


def verify_component_bom(component: pathlib.Path) -> int:
    """Every archived entry is root:wheel, no directory or file is group/other
    writable, the payload root and every directory are exactly 0755, and the
    only AppleDouble entries are empty metadata shadows.

    pkgbuild archives extended attributes as "._" AppleDouble entries. On a
    build host that stamps com.apple.provenance it cannot read that attribute
    ("write: Permission denied") and archives a zero-byte shadow, which
    expansion drops. A non-empty one would carry real metadata onto system
    directories and is refused.
    """

    bom = component / "Bom"
    if bom.is_symlink() or not bom.is_file():
        raise CompanionPkgError("companion component Bom is missing")
    listed = _run(["/usr/bin/lsbom", "-p", "fmugs", str(bom)])
    if listed.returncode != 0:
        raise CompanionPkgError("companion component Bom is unreadable")
    entries = 0
    saw_root = False
    for line in listed.stdout.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) == 4:
            fields.append("")
        if len(fields) != 5:
            raise CompanionPkgError("companion component Bom entry is not exact")
        name, mode_text, uid, gid, size = fields
        entries += 1
        if uid != "0" or gid != "0":
            raise CompanionPkgError(f"companion payload entry is not root:wheel: {name}")
        try:
            mode = int(mode_text, 8)
        except ValueError as exc:
            raise CompanionPkgError("companion component Bom mode is not exact") from exc
        if mode & WRITABLE_MASK:
            raise CompanionPkgError(f"companion payload entry is group/other-writable: {name}")
        if name == ".":
            saw_root = True
        leaf = name.rsplit("/", 1)[-1]
        if leaf.startswith("._"):
            if size not in {"", "0"}:
                raise CompanionPkgError(
                    f"companion payload carries AppleDouble metadata: {name}"
                )
            continue
        if stat.S_ISDIR(mode) and stat.S_IMODE(mode) != 0o755:
            raise CompanionPkgError(f"companion payload directory is not 0755: {name}")
    if not saw_root or entries == 0:
        raise CompanionPkgError("companion component Bom has no payload root")
    return entries


def verify_expanded_root(root: pathlib.Path) -> dict[str, object]:
    if root.is_symlink() or not root.is_dir():
        raise CompanionPkgError("expanded companion PKG root must be a directory")
    reject_symlinks(root)
    component = root / f"{PACKAGE_IDENTIFIER}.pkg"
    if component.is_symlink() or not component.is_dir():
        raise CompanionPkgError("companion component package identity is not exact")
    verify_component_bom(component)
    incoming = _one_named(component, "Incoming", kind="dir")
    scripts_dir = _one_named(component, "Scripts", kind="dir")
    payload_root = _payload_root_for_incoming(incoming)
    if incoming.relative_to(payload_root).as_posix() != INCOMING_RELATIVE:
        raise CompanionPkgError("incoming payload is not at the exact system Incoming path")
    names = sorted(path.name for path in incoming.iterdir() if not path.name.startswith("."))
    if set(names) != set(INCOMING_FILES):
        raise CompanionPkgError("incoming payload file set is not exact")
    for name in INCOMING_FILES:
        path = incoming / name
        reject_writable(path, f"incoming {name}")
        if path.is_symlink() or not path.is_file():
            raise CompanionPkgError(f"incoming {name} must be a regular file")
    host = incoming / "wins_bridge_host"
    host_bytes = _read_regular_bytes(host, "incoming host", MAX_HOST_BYTES)
    receipt = _load_json_object(incoming / "receipt.json", "companion receipt")
    bound_version = receipt.get("package_version")
    archs = verify_universal_execute(
        host_bytes,
        package_version=bound_version if type(bound_version) is str else None,
    )
    minimum_macos = macho_minimum_macos(host_bytes)
    if not os.access(host, os.X_OK):
        raise CompanionPkgError("incoming host is not executable")
    signature = inspect_host_signature(host)
    firefox = _load_json_object(incoming / "firefox.json", "Firefox native-host manifest")
    chrome = _load_json_object(incoming / "chrome.json", "Chrome native-host manifest")
    edge = _load_json_object(incoming / "edge.json", "Edge native-host manifest")
    chrome_id = receipt.get("chrome_extension_id")
    edge_id = receipt.get("edge_extension_id")
    if type(chrome_id) is not str:
        raise CompanionPkgError("companion receipt does not bind a Chrome store-listing id")
    if type(edge_id) is not str:
        raise CompanionPkgError("companion receipt does not bind an Edge store-listing id")
    package_version = receipt.get("package_version")
    if type(package_version) is not str:
        raise CompanionPkgError("companion receipt does not bind a package version")
    verify_package_metadata(
        root=root,
        component=component,
        package_version=package_version,
        architectures=archs,
        minimum_macos=minimum_macos,
    )
    verify_manifests(
        firefox=firefox,
        chrome=chrome,
        edge=edge,
        chrome_id=chrome_id,
        edge_id=edge_id,
    )
    preinstall = _read_regular_text(scripts_dir / "preinstall", "preinstall", MAX_SCRIPT_BYTES)
    postinstall = _read_regular_text(scripts_dir / "postinstall", "postinstall", MAX_SCRIPT_BYTES)
    uninstall = _read_regular_text(incoming / "uninstall.sh", "uninstall helper", MAX_SCRIPT_BYTES)
    verify_scripts(preinstall, postinstall, uninstall)
    verify_receipt(
        receipt,
        scripts_dir=scripts_dir,
        chrome_id=chrome_id,
        edge_id=edge_id,
        payload_root=payload_root,
    )
    return {
        "architectures": sorted(archs),
        "chrome_extension_id": chrome_id,
        "edge_extension_id": edge_id,
        "firefox_extension_id": FIREFOX_EXTENSION_ID,
        "installed_host_path": INSTALLED_HOST_PATH,
        "team_id": TEAM_ID,
        "application_authority": "Developer ID Application",
        "host_sha256": _sha256_bytes(host_bytes),
        "package_identifier": PACKAGE_IDENTIFIER,
        "package_version": package_version,
        "runtime": bool(signature.get("runtime")),
        "minimum_macos": (
            format_macos_version(minimum_macos) if minimum_macos is not None else None
        ),
    }


def expand_pkg(pkg: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    if destination.exists() or destination.is_symlink():
        raise CompanionPkgError("companion PKG expansion destination already exists")
    completed = _run(
        ["/usr/sbin/pkgutil", "--expand-full", str(pkg), str(destination)]
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise CompanionPkgError(f"companion PKG expansion failed: {detail}")
    return destination


def verify_companion_pkg(pkg: pathlib.Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="winsvpn-macos-native-host-pkg-") as raw:
        custody_root = pathlib.Path(raw)
        os.chmod(custody_root, 0o700)
        snapshot = custody_root / "companion.pkg"
        custody = _bind_pkg_snapshot(pkg, snapshot)
        identity = verify_pkg_identity(snapshot)
        expanded = expand_pkg(snapshot, custody_root / "expanded")
        inner = verify_expanded_root(expanded)
        _assert_pkg_snapshot(snapshot, custody)
    inner.update(identity)
    inner["package_sha256"] = custody["sha256"]
    inner["package_bytes"] = custody["bytes"]
    return inner


def _print_pass(record: dict[str, object]) -> None:
    print(
        "MACOS NATIVE-HOST COMPANION PKG: PASS "
        f"team={record['team_id']} "
        f"installer=Developer ID Installer "
        f"version={record['package_version']} "
        f"sha256={record['package_sha256']} "
        f"host={record['installed_host_path']}"
    )


def _bind_receipt_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="bind-receipt")
    parser.add_argument("--payload", required=True, type=pathlib.Path)
    parser.add_argument("--scripts", required=True, type=pathlib.Path)
    parser.add_argument("--chrome-id", required=True)
    parser.add_argument("--edge-id", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--repo", type=pathlib.Path, default=ORIGIN_ROOT)
    args = parser.parse_args(argv)
    document = write_receipt(
        payload_root=args.payload,
        scripts_dir=args.scripts,
        chrome_id=args.chrome_id,
        edge_id=args.edge_id,
        output=args.output,
        repo=args.repo,
    )
    sys.stdout.write(canonical_receipt_bytes(document).decode("ascii"))
    return 0


def _host_facts_main(argv: list[str]) -> int:
    """Producer pre-flight: architecture policy, minimum macOS, signature."""

    parser = argparse.ArgumentParser(prog="host-facts")
    parser.add_argument("--host", required=True, type=pathlib.Path)
    parser.add_argument("--package-version", required=True)
    args = parser.parse_args(argv)
    if PACKAGE_VERSION.fullmatch(args.package_version) is None:
        raise CompanionPkgError("host-facts package version is not exact")
    host_bytes = _read_regular_bytes(args.host, "prebuilt host", MAX_HOST_BYTES)
    archs = verify_universal_execute(host_bytes, package_version=args.package_version)
    minimum = macho_minimum_macos(host_bytes)
    if minimum is None:
        raise CompanionPkgError("prebuilt host declares no minimum macOS")
    inspect_host_signature(args.host)
    print(f"host_architectures {distribution_host_architectures(archs)}")
    print(f"minimum_macos {format_macos_version(minimum)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args[:1] == ["print-source-closure"]:
            digest, records = compute_source_closure()
            document = {"source_closure_sha256": digest, "source_closure": records}
            sys.stdout.write(
                json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
            )
            return 0
        if args[:1] == ["bind-receipt"]:
            return _bind_receipt_main(args[1:])
        if args[:1] == ["host-facts"]:
            return _host_facts_main(args[1:])
        if len(args) != 1 or args[0].startswith("-"):
            raise CompanionPkgError(
                "usage: verify_macos_native_host_companion_pkg.py PKG"
            )
        record = verify_companion_pkg(pathlib.Path(args[0]))
        _print_pass(record)
        return 0
    except OwnerBlocked as error:
        print(f"macos native-host companion PKG owner gate: {error}", file=sys.stderr)
        return OWNER_BLOCK_EXIT
    except CompanionPkgError as error:
        print(f"macos native-host companion PKG: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
