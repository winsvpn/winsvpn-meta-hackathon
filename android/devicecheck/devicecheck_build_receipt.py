#!/usr/bin/env python3
"""Fail-closed producer custody for the DeviceCheck target and androidTest APKs.

The build script owns variant selection and Gradle invocation. This module accepts
only that fixed variant and the pinned SDK root, then derives every receipt field
from descriptor-held files. It never accepts a caller-supplied receipt payload.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import re
import ssl
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Iterator, Sequence


SCHEMA_VERSION = 3
CONTRACT = "winsvpn-devicecheck-build-receipt-v3"
BUILD_TOOLS_VERSION = "36.0.0"
EXPECTED_OWNER_SIGNER_SHA256 = "0" * 64
EXPECTED_SOURCE_AUTHORITY_SHA256 = "0" * 64
SEALED_JAVA_ROOT = pathlib.Path(
    "/Library/WinsVPN/ReleaseAndroidToolchains/jdk-17.0.20.1"
)
SEALED_JAVA_RELATIVE = "bin/java"
SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)
RECEIPT_BASE = "android/devicecheck/app/build/outputs/devicecheck-receipts"
RECEIPT_NAME = "DEVICECHECK_BUILD_RECEIPT.json"
SIDECAR_NAME = "DEVICECHECK_BUILD_RECEIPT.json.sha256"
SOURCE_TRANSACTION_RELATIVE = ".devicecheck-source-transaction.json"
SOURCE_TRANSACTION_CONTRACT = "winsvpn-devicecheck-source-build-transaction-v4"
CONTROLLER_STATE_CONTRACT = "winsvpn-devicecheck-controller-state-v1"
OWNER_AUTHORITY_CONTRACT = "winsvpn-devicecheck-owner-authority-v4"
SOURCE_CUSTODY_CONTRACT = "winsvpn-devicecheck-source-custody-v2"
BUILD_HANDOFF_CONTRACT = "winsvpn-devicecheck-private-build-handoff-v1"
ATOMIC_PUBLICATION_CONTRACT = "winsvpn-devicecheck-content-addressed-publication-v1"
CONSUMER_STATUS = "integrated"
SOURCE_AUTHORITY_ROOT = pathlib.Path(
    "/Library/WinsVPN/ReleaseAndroidSource/devicecheck-v3"
)
SOURCE_SNAPSHOT_BASE = SOURCE_AUTHORITY_ROOT / "snapshots/sha256"
SOURCE_MANIFEST_BASE = SOURCE_AUTHORITY_ROOT / "manifests/sha256"
OWNER_AUTHORITY_PATH = pathlib.Path(
    "/Library/WinsVPN/ReleaseAndroidSource/devicecheck-v3.authority.json"
)
RELEASE_PYTHON_PATH = pathlib.Path(
    "/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3"
)
LOADER_PATH = SOURCE_AUTHORITY_ROOT / "loader.py"
CONTROLLER_PATH = SOURCE_AUTHORITY_ROOT / "controller.py"
OWNER_SIGNER_CERTIFICATE_PATH = pathlib.Path(
    "/Library/WinsVPN/ReleaseAndroidSigning/devicecheck-owner.x509.pem"
)
CONTROLLER_STATE_ROOT = pathlib.Path("/private/var/winsvpn-devicecheck-state")
BUILD_WORKSPACE_ROOT = pathlib.Path("/private/var/winsvpn-devicecheck-build")
BUILD_CACHE_ROOT = pathlib.Path("/private/var/winsvpn-devicecheck-cache")
TRANSACTION_FD = 9
RELEASE_PYTHON_FD = 10
LOADER_FD = 11
CONTROLLER_FD = 12
CONTROLLER_STATE_FD = 13
OWNER_AUTHORITY_FD = 14
OWNER_SIGNER_CERTIFICATE_FD = 15
RECEIPT_TOOL_FD = 16
MAX_TRANSACTION_LIFETIME_NS = 15 * 60 * 1_000_000_000
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_APK_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOOL_BYTES = 256 * 1024 * 1024
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
CHUNK_BYTES = 128 * 1024
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
VERSION_CODE_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")


class ReceiptError(RuntimeError):
    """A receipt cannot be created or verified safely."""


def _fail(message: str) -> None:
    raise ReceiptError(message)


def _require_no_follow() -> int:
    value = getattr(os, "O_NOFOLLOW", None)
    if value is None:
        _fail("platform lacks O_NOFOLLOW; descriptor custody is unavailable")
    return value


def _regular_open_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | _require_no_follow()


def _directory_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if directory == 0:
        _fail("platform lacks O_DIRECTORY; descriptor custody is unavailable")
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | _require_no_follow() | directory


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    mode: int
    nlink: int
    uid: int
    gid: int
    flags: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileIdentity":
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
            mode=stat.S_IMODE(value.st_mode),
            nlink=value.st_nlink,
            uid=value.st_uid,
            gid=value.st_gid,
            flags=int(getattr(value, "st_flags", 0)),
        )

    def receipt_value(self) -> dict[str, int]:
        return {
            "ctime_ns": self.ctime_ns,
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "mtime_ns": self.mtime_ns,
            "nlink": self.nlink,
            "size": self.size,
            "uid": self.uid,
            "gid": self.gid,
            "flags": self.flags,
        }


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return FileIdentity.from_stat(left) == FileIdentity.from_stat(right)


def _relative_parts(relative: str | pathlib.PurePath) -> tuple[str, ...]:
    raw = pathlib.PurePosixPath(str(relative))
    if raw.is_absolute() or not raw.parts:
        _fail(f"path must be a non-empty repository-relative path: {relative}")
    parts = raw.parts
    if any(part in {"", ".", ".."} for part in parts):
        _fail(f"unsafe repository-relative path: {relative}")
    return parts


def _absolute_path(path: pathlib.Path) -> pathlib.Path:
    return path.expanduser().absolute()


def _require_regular_one_link(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        _fail(f"{label} is not a regular file")
    if metadata.st_nlink != 1:
        _fail(f"{label} is not a one-link file")
    if stat.S_IMODE(metadata.st_mode) & 0o6000:
        _fail(f"{label} has forbidden setuid or setgid mode bits")


def _require_directory(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{label} is not a real directory")
    if stat.S_IMODE(metadata.st_mode) & 0o6000:
        _fail(f"{label} has forbidden setuid or setgid mode bits")


def _require_sealed_execution_path(
    root: pathlib.Path,
    relative: str,
    label: str,
) -> None:
    """Require one root-owned SF_IMMUTABLE execution path on macOS."""
    if sys.platform != "darwin" or not SF_IMMUTABLE:
        _fail(f"{label} requires macOS SF_IMMUTABLE custody")
    root = _absolute_path(root)
    if not root.is_absolute():
        _fail(f"{label} root must be absolute")
    current = pathlib.Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        info = os.lstat(current)
        _require_directory(info, f"{label} ancestor {current}")
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            _fail(f"{label} ancestor is not root-owned and non-writable: {current}")
    for index, part in enumerate(_relative_parts(relative)):
        current /= part
        info = os.lstat(current)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            _fail(f"{label} path is not root-owned and non-writable: {current}")
        if not int(getattr(info, "st_flags", 0)) & SF_IMMUTABLE:
            _fail(f"{label} path lacks SF_IMMUTABLE: {current}")
        if index + 1 < len(_relative_parts(relative)):
            _require_directory(info, f"{label} directory {current}")
        else:
            _require_regular_one_link(info, label)


def _open_root(root: pathlib.Path, label: str) -> tuple[pathlib.Path, int, FileIdentity]:
    root = _absolute_path(root)
    before = os.lstat(root)
    _require_directory(before, label)
    descriptor = os.open(root, _directory_open_flags())
    try:
        opened = os.fstat(descriptor)
        after = os.lstat(root)
        if not _same_identity(before, opened) or not _same_identity(before, after):
            _fail(f"{label} changed while its descriptor was opened")
        return root, descriptor, FileIdentity.from_stat(opened)
    except BaseException:
        os.close(descriptor)
        raise


@dataclass
class _DirectoryChain:
    root: pathlib.Path
    root_descriptor: int
    root_identity: FileIdentity
    directories: list[tuple[int, str, int, FileIdentity]]

    @property
    def parent_descriptor(self) -> int:
        return self.directories[-1][2] if self.directories else self.root_descriptor

    def revalidate(self, label: str) -> None:
        current_root = os.lstat(self.root)
        if FileIdentity.from_stat(current_root) != self.root_identity:
            _fail(f"{label} repository root changed during descriptor custody")
        for parent_descriptor, name, child_descriptor, expected in self.directories:
            current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            opened = os.fstat(child_descriptor)
            if FileIdentity.from_stat(current) != expected or FileIdentity.from_stat(opened) != expected:
                _fail(f"{label} ancestor changed during descriptor custody: {name}")

    def close(self) -> None:
        for _parent, _name, descriptor, _identity in reversed(self.directories):
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            os.close(self.root_descriptor)


def _open_relative_chain(root: pathlib.Path, parts: tuple[str, ...], label: str) -> _DirectoryChain:
    root_path, root_descriptor, root_identity = _open_root(root, f"{label} root")
    chain = _DirectoryChain(root_path, root_descriptor, root_identity, [])
    try:
        parent_descriptor = root_descriptor
        for name in parts[:-1]:
            try:
                before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise ReceiptError(f"{label} ancestor is missing: {name}") from exc
            _require_directory(before, f"{label} ancestor {name}")
            try:
                child_descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_descriptor)
            except OSError as exc:
                raise ReceiptError(f"{label} ancestor could not be opened safely: {name}") from exc
            opened = os.fstat(child_descriptor)
            if not _same_identity(before, opened):
                os.close(child_descriptor)
                _fail(f"{label} ancestor changed while opened: {name}")
            identity = FileIdentity.from_stat(opened)
            chain.directories.append((parent_descriptor, name, child_descriptor, identity))
            parent_descriptor = child_descriptor
        return chain
    except BaseException:
        chain.close()
        raise


def _require_relative_directory(root: pathlib.Path, relative: str, label: str) -> None:
    """Open every directory component below a held root without following one."""
    parts = _relative_parts(relative)
    chain = _open_relative_chain(root, parts + ("directory-sentinel",), label)
    try:
        chain.revalidate(label)
    finally:
        chain.close()


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            _fail("short write while creating custody data")
        offset += written


@dataclass
class HeldFile:
    label: str
    path: pathlib.Path
    root: pathlib.Path | None
    relative: str | None
    max_bytes: int
    identity: FileIdentity
    sha256: str
    raw: bytes | None
    ancestor_identities: tuple[FileIdentity, ...]

    @property
    def bytes_count(self) -> int:
        return self.identity.size

    def revalidate(self) -> None:
        if self.root is None or self.relative is None:
            current = hold_absolute_file(
                self.path,
                self.label,
                max_bytes=self.max_bytes,
                capture=False,
            )
        else:
            current = hold_relative_file(
                self.root,
                self.relative,
                self.label,
                max_bytes=self.max_bytes,
                capture=False,
            )
        if (
            current.identity != self.identity
            or current.sha256 != self.sha256
            or current.ancestor_identities != self.ancestor_identities
        ):
            _fail(f"{self.label} drifted after it was held")

    def evidence(self, relative_to: pathlib.Path | None = None) -> dict[str, Any]:
        if relative_to is None:
            path_value = str(self.path)
        else:
            try:
                path_value = self.path.relative_to(relative_to).as_posix()
            except ValueError as exc:
                raise ReceiptError(f"{self.label} escapes the expected root") from exc
        return {
            "bytes": self.bytes_count,
            "path": path_value,
            "sha256": self.sha256,
        }


def _read_descriptor(
    descriptor: int,
    *,
    before: os.stat_result,
    label: str,
    max_bytes: int,
    capture: bool,
    sink: BinaryIO | None,
) -> tuple[FileIdentity, str, bytes | None]:
    if before.st_size <= 0 or before.st_size > max_bytes:
        _fail(f"{label} size is outside its custody bound")
    digest = hashlib.sha256()
    captured = bytearray() if capture else None
    count = 0
    while True:
        chunk = os.read(descriptor, CHUNK_BYTES)
        if not chunk:
            break
        count += len(chunk)
        if count > max_bytes:
            _fail(f"{label} exceeds its custody bound")
        digest.update(chunk)
        if captured is not None:
            captured.extend(chunk)
        if sink is not None:
            sink.write(chunk)
    after = os.fstat(descriptor)
    if not _same_identity(before, after) or count != before.st_size:
        _fail(f"{label} changed while descriptor-held bytes were read")
    raw = bytes(captured) if captured is not None else None
    return FileIdentity.from_stat(after), digest.hexdigest(), raw


def hold_relative_file(
    root: pathlib.Path,
    relative: str | pathlib.PurePath,
    label: str,
    *,
    max_bytes: int,
    capture: bool,
    sink: BinaryIO | None = None,
) -> HeldFile:
    parts = _relative_parts(relative)
    chain = _open_relative_chain(root, parts, label)
    descriptor: int | None = None
    try:
        parent_descriptor = chain.parent_descriptor
        try:
            before = os.stat(parts[-1], dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise ReceiptError(f"{label} is missing") from exc
        _require_regular_one_link(before, label)
        try:
            descriptor = os.open(parts[-1], _regular_open_flags(), dir_fd=parent_descriptor)
        except OSError as exc:
            raise ReceiptError(f"{label} could not be opened safely") from exc
        opened = os.fstat(descriptor)
        if not _same_identity(before, opened):
            _fail(f"{label} changed while its descriptor was opened")
        identity, digest, raw = _read_descriptor(
            descriptor,
            before=opened,
            label=label,
            max_bytes=max_bytes,
            capture=capture,
            sink=sink,
        )
        path_after = os.stat(parts[-1], dir_fd=parent_descriptor, follow_symlinks=False)
        if FileIdentity.from_stat(path_after) != identity:
            _fail(f"{label} path changed after descriptor-held read")
        chain.revalidate(label)
        ancestor_identities = (
            chain.root_identity,
            *(item[3] for item in chain.directories),
        )
        root_path = chain.root
        absolute = root_path.joinpath(*parts)
        return HeldFile(
            label=label,
            path=absolute,
            root=root_path,
            relative="/".join(parts),
            max_bytes=max_bytes,
            identity=identity,
            sha256=digest,
            raw=raw,
            ancestor_identities=ancestor_identities,
        )
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        chain.close()


def hold_absolute_file(
    path: pathlib.Path,
    label: str,
    *,
    max_bytes: int,
    capture: bool,
    sink: BinaryIO | None = None,
) -> HeldFile:
    absolute = _absolute_path(path)
    parts = absolute.parts[1:]
    if not parts:
        _fail(f"{label} must name a file below the filesystem root")
    return hold_relative_file(
        pathlib.Path(absolute.anchor),
        pathlib.PurePosixPath(*parts),
        label,
        max_bytes=max_bytes,
        capture=capture,
        sink=sink,
    )


@contextlib.contextmanager
def held_descriptor(held: HeldFile) -> Iterator[int]:
    """Hold the exact APK descriptor open for pathname-only SDK tools.

    Android's apksigner and aapt accept a /dev/fd/N pathname. The child inherits
    this exact descriptor via pass_fds, so a same-user pathname swap cannot make
    either tool inspect substitute bytes between our authenticated read and its
    own open.
    """
    descriptor: int | None = None
    chain: _DirectoryChain | None = None
    try:
        if held.root is None or held.relative is None:
            before = os.lstat(held.path)
            _require_regular_one_link(before, held.label)
            descriptor = os.open(held.path, _regular_open_flags())
            opened = os.fstat(descriptor)
            if FileIdentity.from_stat(opened) != held.identity:
                _fail(f"{held.label} changed before SDK descriptor custody")
        else:
            parts = _relative_parts(held.relative)
            chain = _open_relative_chain(held.root, parts, held.label)
            parent = chain.parent_descriptor
            before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            _require_regular_one_link(before, held.label)
            descriptor = os.open(parts[-1], _regular_open_flags(), dir_fd=parent)
            opened = os.fstat(descriptor)
            if FileIdentity.from_stat(opened) != held.identity:
                _fail(f"{held.label} changed before SDK descriptor custody")
            current_ancestors = (
                chain.root_identity,
                *(item[3] for item in chain.directories),
            )
            if current_ancestors != held.ancestor_identities:
                _fail(f"{held.label} ancestor changed before SDK descriptor custody")
        yield descriptor
        if FileIdentity.from_stat(os.fstat(descriptor)) != held.identity:
            _fail(f"{held.label} changed during SDK descriptor custody")
        if chain is not None:
            chain.revalidate(held.label)
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if chain is not None:
            chain.close()
    held.revalidate()


def _safe_tree_files(repo: pathlib.Path, base_relative: str, label: str) -> tuple[str, ...]:
    parts = _relative_parts(base_relative)
    base = _absolute_path(repo).joinpath(*parts)
    _require_relative_directory(repo, base_relative, label)
    base_info = os.lstat(base)
    _require_directory(base_info, label)
    files: list[str] = []
    for current_text, directory_names, file_names in os.walk(base, topdown=True, followlinks=False):
        current = pathlib.Path(current_text)
        current_info = os.lstat(current)
        _require_directory(current_info, label)
        for name in sorted(directory_names):
            candidate = current / name
            info = os.lstat(candidate)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                _fail(f"{label} contains an unsafe directory entry: {candidate}")
        directory_names[:] = sorted(directory_names)
        for name in sorted(file_names):
            candidate = current / name
            info = os.lstat(candidate)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                _fail(f"{label} contains an unsafe file entry: {candidate}")
            relative = candidate.relative_to(_absolute_path(repo)).as_posix()
            files.append(relative)
    return tuple(sorted(files))


EXPLICIT_CLOSURE_PATHS = (
    "android/app/build.gradle.kts",
    "android/gradle/wrapper/gradle-wrapper.jar",
    "android/gradle/wrapper/gradle-wrapper.properties",
    "android/gradlew",
    "android/devicecheck/app/build.gradle.kts",
    "android/devicecheck/build.gradle.kts",
    "android/devicecheck/build_devicecheck.sh",
    "android/devicecheck/devicecheck_build_receipt.py",
    "android/devicecheck/gradle.properties",
    "android/devicecheck/gradlew",
    "android/devicecheck/gradlew.bat",
    "android/devicecheck/local.properties",
    "android/devicecheck/settings.gradle.kts",
)
TREE_CLOSURE_ROOTS = (
    "android/devicecheck/app/src",
    "android/devicecheck/awgresponder",
    "android/devicecheck/engine",
    "android/devicecheck/gradle",
)
REQUIRED_CLOSURE_PATHS = (
    "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/HardwareAttestationTest.kt",
    "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/LiveHardwareAttestationProofTest.kt",
    "android/devicecheck/build_devicecheck.sh",
    "android/devicecheck/devicecheck_build_receipt.py",
    "android/devicecheck/test_live_hardware_attestation_proof.py",
    "android/devicecheck/test_shipping_source_closure.py",
)


def closure_paths(repo: pathlib.Path) -> tuple[str, ...]:
    root = _absolute_path(repo)
    paths = set(EXPLICIT_CLOSURE_PATHS)
    for base in TREE_CLOSURE_ROOTS:
        paths.update(_safe_tree_files(root, base, f"DeviceCheck closure {base}"))
    tests_dir = root / "android/devicecheck"
    _require_relative_directory(root, "android/devicecheck", "DeviceCheck test root")
    for candidate in sorted(tests_dir.glob("test_*.py")):
        info = os.lstat(candidate)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            _fail(f"DeviceCheck test closure contains an unsafe entry: {candidate}")
        paths.add(candidate.relative_to(root).as_posix())
    missing = sorted(set(REQUIRED_CLOSURE_PATHS) - paths)
    if missing:
        _fail("DeviceCheck source/test closure omits required inputs: " + ", ".join(missing))
    return tuple(sorted(paths))


@dataclass
class SourceClosure:
    repo: pathlib.Path
    paths: tuple[str, ...]
    held: dict[str, HeldFile]

    def text(self, relative: str) -> str:
        item = self.held.get(relative)
        if item is None or item.raw is None:
            _fail(f"source closure did not hold text input: {relative}")
        try:
            return item.raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReceiptError(f"source closure input is not UTF-8: {relative}") from exc

    def revalidate(self) -> None:
        if closure_paths(self.repo) != self.paths:
            _fail("DeviceCheck source/test/build/Gradle closure changed after it was held")
        for relative in self.paths:
            self.held[relative].revalidate()

    def inventory(self) -> list[dict[str, Any]]:
        return [self.held[relative].evidence(self.repo) for relative in self.paths]


def hold_source_closure(repo: pathlib.Path) -> SourceClosure:
    repo = _absolute_path(repo)
    before = closure_paths(repo)
    held = {
        relative: hold_relative_file(
            repo,
            relative,
            f"DeviceCheck closure input {relative}",
            max_bytes=MAX_SOURCE_BYTES,
            capture=True,
        )
        for relative in before
    }
    result = SourceClosure(repo=repo, paths=before, held=held)
    result.revalidate()
    return result


def _unique_match(pattern: str, text: str, label: str) -> str:
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        _fail(f"{label} must occur exactly once")
    return matches[0]


@dataclass(frozen=True)
class BuildFacts:
    agp_version: str
    compile_sdk: int
    gradle_version: str
    min_sdk: int
    ndk_version: str
    target_sdk: int


def build_facts(closure: SourceClosure) -> BuildFacts:
    settings = closure.text("android/devicecheck/settings.gradle.kts")
    wrapper = closure.text("android/devicecheck/gradle/wrapper/gradle-wrapper.properties")
    app_gradle = closure.text("android/devicecheck/app/build.gradle.kts")
    shipping_gradle = closure.text("android/app/build.gradle.kts")
    agp = _unique_match(
        r'^\s*id\("com\.android\.application"\)\s+version\s+"([0-9.]+)"\s+apply\s+false\s*$',
        settings,
        "DeviceCheck AGP pin",
    )
    gradle = _unique_match(
        r"gradle-([0-9.]+)-all\.zip",
        wrapper,
        "DeviceCheck Gradle wrapper pin",
    )
    min_sdk_text = _unique_match(
        r"^\s*minSdk\s*=\s*([0-9]+)\s*$",
        app_gradle,
        "DeviceCheck minSdk",
    )
    compile_sdk_text = _unique_match(
        r"^\s*compileSdk\s*=\s*([0-9]+)\s*$",
        app_gradle,
        "DeviceCheck compileSdk",
    )
    target_sdk_text = _unique_match(
        r"^\s*targetSdk\s*=\s*([0-9]+)\s*$",
        app_gradle,
        "DeviceCheck targetSdk",
    )
    device_ndk = _unique_match(
        r'^\s*ndkVersion\s*=\s*"([0-9.]+)"\s*$',
        app_gradle,
        "DeviceCheck ndkVersion",
    )
    shipping_ndk = _unique_match(
        r'^\s*ndkVersion\s*=\s*"([0-9.]+)"\s*$',
        shipping_gradle,
        "shipping ndkVersion",
    )
    if device_ndk != shipping_ndk:
        _fail("DeviceCheck and shipping ndkVersion values differ")
    return BuildFacts(
        agp_version=agp,
        compile_sdk=int(compile_sdk_text),
        gradle_version=gradle,
        min_sdk=int(min_sdk_text),
        ndk_version=device_ndk,
        target_sdk=int(target_sdk_text),
    )


@dataclass(frozen=True)
class VariantPolicy:
    name: str
    target_task: str
    android_test_task: str
    target_apk: str
    android_test_apk: str
    target_output_dir: str
    android_test_output_dir: str


VARIANT_POLICIES: dict[str, VariantPolicy] = {
    "debug": VariantPolicy(
        name="debug",
        target_task=":app:assembleDebug",
        android_test_task=":app:assembleDebugAndroidTest",
        target_apk="android/devicecheck/app/build/outputs/apk/debug/app-debug.apk",
        android_test_apk="android/devicecheck/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk",
        target_output_dir="android/devicecheck/app/build/outputs/apk/debug",
        android_test_output_dir="android/devicecheck/app/build/outputs/apk/androidTest/debug",
    ),
    "release": VariantPolicy(
        name="release",
        target_task=":app:assembleRelease",
        android_test_task=":app:assembleReleaseAndroidTest",
        target_apk="android/devicecheck/app/build/outputs/apk/release/app-release.apk",
        android_test_apk="android/devicecheck/app/build/outputs/apk/androidTest/release/app-release-androidTest.apk",
        target_output_dir="android/devicecheck/app/build/outputs/apk/release",
        android_test_output_dir="android/devicecheck/app/build/outputs/apk/androidTest/release",
    ),
}


def selected_policy(variant: str) -> VariantPolicy:
    try:
        return VARIANT_POLICIES[variant]
    except KeyError as exc:
        raise ReceiptError(f"unsupported DeviceCheck evidence variant: {variant}") from exc


def _validate_build_script_policy(
    closure: SourceClosure,
    policy: VariantPolicy,
    *,
    schema_fixture: bool,
) -> None:
    build_script = closure.text("android/devicecheck/build_devicecheck.sh")
    disabled_marker = "# DEVICECHECK_PRODUCER_DISABLED=immutable-compiler-input-v1"
    if disabled_marker in build_script and not schema_fixture:
        _fail(
            "OWNER-BLOCKED: DeviceCheck build producer is intentionally disabled "
            "until the external immutable compiler-input transaction exists"
        )
    required = (
        f'GRADLE_VARIANT="{policy.name}"',
        f'GRADLE_TARGET_TASK="{policy.target_task}"',
        f'GRADLE_TEST_TASK="{policy.android_test_task}"',
        '"${RELEASE_PYTHON}" -I -S /dev/fd/16 record',
        'WINN_DEVICECHECK_PRODUCER_ONLY',
        'WINN_DEVICECHECK_RECEIPT_SELFTEST',
    )
    missing = [token for token in required if token not in build_script]
    if missing:
        _fail(
            "DeviceCheck producer script does not enforce target plus androidTest "
            "receipt custody: "
            + ", ".join(missing)
        )


@dataclass
class Toolchain:
    sdk_root: pathlib.Path
    inputs: dict[str, HeldFile]
    java: HeldFile

    @property
    def apksigner(self) -> pathlib.Path:
        return self.inputs["apksigner"].path

    @property
    def aapt(self) -> pathlib.Path:
        return self.inputs["aapt"].path

    def revalidate(self) -> None:
        for value in self.inputs.values():
            value.revalidate()
        self.java.revalidate()

    def receipt_value(self) -> dict[str, Any]:
        sdk_identity = self.inputs["aapt"].ancestor_identities[0]
        return {
            "aapt": self.inputs["aapt"].evidence(self.sdk_root),
            "apksigner": self.inputs["apksigner"].evidence(self.sdk_root),
            "apksigner_jar": self.inputs["apksigner_jar"].evidence(self.sdk_root),
            "android_build_tools_version": BUILD_TOOLS_VERSION,
            "execution": {
                "aapt": "held-path-with-ancestor-custody",
                "apksigner": "sealed-java-held-jar-descriptor",
                "environment": "explicit-allowlist",
            },
            "java": self.java.evidence(SEALED_JAVA_ROOT),
            "java_root": str(SEALED_JAVA_ROOT),
            "sdk_root": str(self.sdk_root),
            "sdk_root_identity": sdk_identity.receipt_value(),
        }


def hold_toolchain(
    sdk_root: pathlib.Path,
    *,
    require_sealed_execution: bool,
) -> Toolchain:
    sdk_root = _absolute_path(sdk_root)
    expected = {
        "aapt": f"build-tools/{BUILD_TOOLS_VERSION}/aapt",
        "apksigner": f"build-tools/{BUILD_TOOLS_VERSION}/apksigner",
        "apksigner_jar": f"build-tools/{BUILD_TOOLS_VERSION}/lib/apksigner.jar",
    }
    held = {
        name: hold_relative_file(
            sdk_root,
            relative,
            f"reviewed Android SDK {name}",
            max_bytes=MAX_TOOL_BYTES,
            capture=False,
        )
        for name, relative in expected.items()
    }
    for name in ("aapt", "apksigner"):
        if not (held[name].identity.mode & 0o111):
            _fail(f"reviewed Android SDK {name} is not executable")
    java = hold_relative_file(
        SEALED_JAVA_ROOT,
        SEALED_JAVA_RELATIVE,
        "owner-sealed Android release Java",
        max_bytes=MAX_TOOL_BYTES,
        capture=False,
    )
    if not (java.identity.mode & 0o111):
        _fail("owner-sealed Android release Java is not executable")
    if require_sealed_execution:
        for name, relative in expected.items():
            _require_sealed_execution_path(
                sdk_root,
                relative,
                f"reviewed Android SDK {name}",
            )
        _require_sealed_execution_path(
            SEALED_JAVA_ROOT,
            SEALED_JAVA_RELATIVE,
            "owner-sealed Android release Java",
        )
    result = Toolchain(sdk_root=sdk_root, inputs=held, java=java)
    result.revalidate()
    return result


def _apk_outputs_under(repo: pathlib.Path, output_relative: str, label: str) -> tuple[str, ...]:
    all_files = _safe_tree_files(repo, output_relative, label)
    return tuple(path for path in all_files if path.lower().endswith(".apk"))


def _require_exact_output_set(repo: pathlib.Path, policy: VariantPolicy) -> None:
    checks = (
        (policy.target_output_dir, policy.target_apk, "DeviceCheck target APK"),
        (policy.android_test_output_dir, policy.android_test_apk, "DeviceCheck androidTest APK"),
    )
    for output_dir, expected, label in checks:
        found = _apk_outputs_under(repo, output_dir, label)
        if found != (expected,):
            if not found:
                _fail(f"{label} is missing; expected exactly {expected}")
            _fail(
                f"{label} output is split, extra, or ambiguous: expected {expected}; "
                f"found {', '.join(found)}"
            )


def _canonical_json(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ReceiptError("receipt value is not canonical JSON") from exc
    try:
        return (encoded + "\n").encode("ascii")
    except UnicodeEncodeError as exc:
        raise ReceiptError("receipt serialization is not ASCII") from exc


def _duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReceiptError(f"{label} is not ASCII JSON") from exc
    try:
        value = json.loads(text, object_pairs_hook=_duplicate_safe_object)
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        _fail(f"{label} must be a JSON object")
    if _canonical_json(value) != raw:
        _fail(f"{label} is not canonical ASCII JSON")
    return value


def _directory_identity(path: pathlib.Path, label: str) -> dict[str, Any]:
    path = _absolute_path(path)
    info = os.lstat(path)
    _require_directory(info, label)
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "mode": stat.S_IMODE(info.st_mode),
        "path": str(path),
        "gid": int(info.st_gid),
        "uid": int(info.st_uid),
    }


def _workspace_identity(repo: pathlib.Path) -> dict[str, Any]:
    return _directory_identity(repo, "DeviceCheck transaction workspace")


def _certificate_der_sha256(raw: bytes, label: str) -> str:
    try:
        der = ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReceiptError(f"{label} is not one PEM X.509 certificate") from exc
    return hashlib.sha256(der).hexdigest()


def _read_inherited_file(
    descriptor: int,
    path: pathlib.Path,
    label: str,
    *,
    expected_mode: int,
    require_immutable: bool,
    max_bytes: int,
    expected_uid: int = 0,
) -> tuple[FileIdentity, str, bytes]:
    try:
        before = os.fstat(descriptor)
        _require_regular_one_link(before, label)
        if before.st_uid != expected_uid or stat.S_IMODE(before.st_mode) != expected_mode:
            _fail(
                f"OWNER-BLOCKED: {label} is not UID {expected_uid} exact mode "
                f"{expected_mode:04o}"
            )
        if require_immutable and not int(getattr(before, "st_flags", 0)) & SF_IMMUTABLE:
            _fail(f"OWNER-BLOCKED: {label} lacks SF_IMMUTABLE custody")
        path_info = os.lstat(path)
        if not _same_identity(before, path_info):
            _fail(f"OWNER-BLOCKED: {label} held-path mismatch")
        os.lseek(descriptor, 0, os.SEEK_SET)
        identity, digest, raw = _read_descriptor(
            descriptor,
            before=before,
            label=label,
            max_bytes=max_bytes,
            capture=True,
            sink=None,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as exc:
        raise ReceiptError(f"OWNER-BLOCKED: {label} descriptor is absent or invalid") from exc
    if raw is None:
        _fail(f"OWNER-BLOCKED: {label} bytes were not held")
    return identity, digest, raw


def _authority_record(
    authority: dict[str, Any],
    name: str,
    expected_path: pathlib.Path | None,
) -> dict[str, Any]:
    value = authority.get(name)
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size_bytes"}:
        _fail(f"OWNER-BLOCKED: owner authority {name} record is malformed")
    if (
        (expected_path is not None and value["path"] != str(expected_path))
        or not isinstance(value["path"], str)
        or not isinstance(value["sha256"], str)
        or HEX_64_RE.fullmatch(value["sha256"]) is None
        or value["sha256"] in {"0" * 64, hashlib.sha256(b"").hexdigest()}
        or type(value["size_bytes"]) is not int
        or value["size_bytes"] <= 0
    ):
        _fail(f"OWNER-BLOCKED: owner authority {name} record is not fixed and bounded")
    return value


def _validate_owner_authority_bytes(raw: bytes, digest: str) -> dict[str, Any]:
    authority = _strict_json(raw, "DeviceCheck owner authority")
    required = {
        "schema_version",
        "contract",
        "release_python",
        "loader",
        "controller",
        "source_manifest",
        "source_snapshot",
        "build",
        "owner_signer_certificate",
        "owner_signer_sha256",
        "authorization",
        "consumer",
        "secret_material_redacted",
    }
    if set(authority) != required:
        _fail("OWNER-BLOCKED: DeviceCheck owner authority fields are invalid")
    if (
        authority["schema_version"] != 4
        or authority["contract"] != OWNER_AUTHORITY_CONTRACT
        or authority["secret_material_redacted"] is not True
        or digest != EXPECTED_SOURCE_AUTHORITY_SHA256
    ):
        _fail("OWNER-BLOCKED: DeviceCheck owner authority is not the reviewed content address")
    _authority_record(authority, "release_python", RELEASE_PYTHON_PATH)
    _authority_record(authority, "loader", LOADER_PATH)
    _authority_record(authority, "controller", CONTROLLER_PATH)
    _authority_record(authority, "owner_signer_certificate", OWNER_SIGNER_CERTIFICATE_PATH)
    source_manifest = _authority_record(authority, "source_manifest", None)
    if pathlib.Path(source_manifest["path"]) != (
        SOURCE_MANIFEST_BASE / f"{source_manifest['sha256']}.json"
    ):
        _fail("OWNER-BLOCKED: source index is not at its exact content-addressed path")
    source_snapshot = authority["source_snapshot"]
    if (
        not isinstance(source_snapshot, dict)
        or set(source_snapshot) != {"closure_sha256", "path"}
        or not isinstance(source_snapshot["closure_sha256"], str)
        or HEX_64_RE.fullmatch(source_snapshot["closure_sha256"]) is None
        or pathlib.Path(source_snapshot["path"])
        != SOURCE_SNAPSHOT_BASE / source_snapshot["closure_sha256"]
    ):
        _fail("OWNER-BLOCKED: source snapshot is not the exact content-addressed closure")
    build = authority["build"]
    if (
        not isinstance(build, dict)
        or set(build)
        != {
            "atomic_publication_contract",
            "build_gid",
            "build_uid",
            "cache_mode",
            "cache_root",
            "fresh_workspace_required",
            "handoff_contract",
            "workspace_mode",
            "workspace_root",
        }
        or type(build["build_uid"]) is not int
        or build["build_uid"] <= 0
        or type(build["build_gid"]) is not int
        or build["build_gid"] <= 0
        or build["workspace_root"] != str(BUILD_WORKSPACE_ROOT)
        or build["cache_root"] != str(BUILD_CACHE_ROOT)
        or build["workspace_mode"] != "0700"
        or build["cache_mode"] != "0700"
        or build["fresh_workspace_required"] is not True
        or build["handoff_contract"] != BUILD_HANDOFF_CONTRACT
        or build["atomic_publication_contract"] != ATOMIC_PUBLICATION_CONTRACT
    ):
        _fail("OWNER-BLOCKED: private build workspace/cache authority is malformed")
    authorization = authority["authorization"]
    if (
        not isinstance(authorization, dict)
        or set(authorization) != {"authorization_id", "nonce", "sequence"}
        or not isinstance(authorization["authorization_id"], str)
        or HEX_64_RE.fullmatch(authorization["authorization_id"]) is None
        or authorization["authorization_id"] in {"0" * 64, hashlib.sha256(b"").hexdigest()}
        or not isinstance(authorization["nonce"], str)
        or NONCE_RE.fullmatch(authorization["nonce"]) is None
        or authorization["nonce"] in {"0" * 64, hashlib.sha256(b"").hexdigest()}
        or type(authorization["sequence"]) is not int
        or authorization["sequence"] <= 0
    ):
        _fail("OWNER-BLOCKED: owner authorization identity is malformed")
    if authority["consumer"] != {
        "contract": BUILD_HANDOFF_CONTRACT,
        "status": CONSUMER_STATUS,
    }:
        _fail("OWNER-BLOCKED: DeviceCheck receipt consumer is not integrated")
    signer = authority["owner_signer_sha256"]
    if (
        not isinstance(signer, str)
        or HEX_64_RE.fullmatch(signer) is None
        or signer in {"0" * 64, hashlib.sha256(b"").hexdigest()}
    ):
        _fail("OWNER-BLOCKED: owner signer identity is malformed")
    return authority


def _validate_transaction_value(
    value: dict[str, Any],
    repo: pathlib.Path,
    closure: SourceClosure,
) -> None:
    expected_fields = {
        "schema_version",
        "contract",
        "authority_sha256",
        "authorization_id",
        "source_closure_sha256",
        "producer_source_sha256",
        "source_index_path",
        "source_index_sha256",
        "build_script_sha256",
        "receipt_tool_sha256",
        "release_python_sha256",
        "loader_sha256",
        "controller_sha256",
        "owner_signer_sha256",
        "owner_signer_certificate_sha256",
        "workspace",
        "cache",
        "source_snapshot",
        "handoff_contract",
        "atomic_publication_contract",
        "consumer_status",
        "nonce",
        "issued_unix_ns",
        "expires_unix_ns",
        "monotonic_sequence",
        "controller_state_path",
        "sealed",
    }
    if set(value) != expected_fields:
        _fail("DeviceCheck source transaction fields are invalid")
    integers = ("issued_unix_ns", "expires_unix_ns", "monotonic_sequence")
    if any(type(value[name]) is not int for name in integers):
        _fail("DeviceCheck source transaction time/sequence fields are malformed")
    now = time.time_ns()
    issued = value["issued_unix_ns"]
    expires = value["expires_unix_ns"]
    nonce = value["nonce"]
    expected_state_path = CONTROLLER_STATE_ROOT / f"{value['monotonic_sequence']}-{nonce}.json"
    if (
        value["schema_version"] != 4
        or value["contract"] != SOURCE_TRANSACTION_CONTRACT
        or not isinstance(nonce, str)
        or NONCE_RE.fullmatch(nonce) is None
        or value["monotonic_sequence"] <= 0
        or issued <= 0
        or expires <= issued
        or expires - issued > MAX_TRANSACTION_LIFETIME_NS
        or now < issued
        or now >= expires
        or value["controller_state_path"] != str(expected_state_path)
        or value["workspace"] != _workspace_identity(repo)
        or value["handoff_contract"] != BUILD_HANDOFF_CONTRACT
        or value["atomic_publication_contract"] != ATOMIC_PUBLICATION_CONTRACT
        or value["consumer_status"] != CONSUMER_STATUS
        or value["sealed"] is not True
    ):
        _fail("DeviceCheck source transaction nonce, expiry, sequence, or workspace binding is invalid")
    expected_inventory = _inventory_sha256(closure.inventory())
    hash_fields = (
        "authority_sha256",
        "authorization_id",
        "source_closure_sha256",
        "producer_source_sha256",
        "source_index_sha256",
        "build_script_sha256",
        "receipt_tool_sha256",
        "release_python_sha256",
        "loader_sha256",
        "controller_sha256",
        "owner_signer_sha256",
        "owner_signer_certificate_sha256",
    )
    if any(
        not isinstance(value[name], str) or HEX_64_RE.fullmatch(value[name]) is None
        for name in hash_fields
    ):
        _fail("DeviceCheck source transaction contains malformed content addresses")
    if (
        EXPECTED_SOURCE_AUTHORITY_SHA256 in {"0" * 64, hashlib.sha256(b"").hexdigest()}
        or value["authority_sha256"] != EXPECTED_SOURCE_AUTHORITY_SHA256
        or value["producer_source_sha256"] != expected_inventory
        or value["source_index_path"]
        != str(SOURCE_MANIFEST_BASE / f"{value['source_index_sha256']}.json")
        or value["source_snapshot"]
        != str(SOURCE_SNAPSHOT_BASE / value["source_closure_sha256"])
        or value["build_script_sha256"]
        != closure.held["android/devicecheck/build_devicecheck.sh"].sha256
        or value["receipt_tool_sha256"]
        != closure.held["android/devicecheck/devicecheck_build_receipt.py"].sha256
    ):
        if EXPECTED_SOURCE_AUTHORITY_SHA256 in {"0" * 64, hashlib.sha256(b"").hexdigest()}:
            _fail("OWNER-BLOCKED: reviewed DeviceCheck source authority is not provisioned")
        _fail("DeviceCheck source transaction does not bind the immutable pre-build authenticated snapshot")
    cache = value["cache"]
    if not isinstance(cache, dict):
        _fail("DeviceCheck source transaction cache identity is malformed")
    expected_cache = BUILD_CACHE_ROOT / value["authorization_id"]
    if cache != _directory_identity(expected_cache, "DeviceCheck transaction cache"):
        _fail("DeviceCheck source transaction does not bind its private cache")
    if pathlib.Path(repo) != BUILD_WORKSPACE_ROOT / value["authorization_id"]:
        _fail("DeviceCheck source transaction does not bind its fresh candidate workspace")
    workspace = value["workspace"]
    if (
        workspace["mode"] != 0o700
        or cache["mode"] != 0o700
        or workspace["uid"] != os.getuid()
        or cache["uid"] != os.getuid()
        or workspace["gid"] != os.getgid()
        or cache["gid"] != os.getgid()
    ):
        _fail("DeviceCheck transaction workspace/cache is not private build-user custody")


def _production_transaction_custody(
    repo: pathlib.Path,
    value: dict[str, Any],
    held: HeldFile,
    closure: SourceClosure,
) -> None:
    if sys.platform != "darwin" or not SF_IMMUTABLE:
        _fail("OWNER-BLOCKED: DeviceCheck external transaction custody requires macOS SF_IMMUTABLE")
    workspace = _workspace_identity(repo)
    private_root = BUILD_WORKSPACE_ROOT
    try:
        repo.relative_to(private_root)
    except ValueError as exc:
        raise ReceiptError(
            "OWNER-BLOCKED: DeviceCheck workspace is outside the private build-user root"
        ) from exc
    if os.getuid() == 0 or workspace["uid"] != os.getuid() or workspace["mode"] != 0o700:
        _fail("OWNER-BLOCKED: DeviceCheck workspace is not private 0700 build-user custody")
    ticket_identity, ticket_digest, ticket_raw = _read_inherited_file(
        TRANSACTION_FD,
        held.path,
        "DeviceCheck authenticated transaction ticket",
        expected_mode=0o400,
        require_immutable=True,
        max_bytes=64 * 1024,
    )
    if ticket_raw != held.raw or ticket_digest != held.sha256 or ticket_identity != held.identity:
        _fail("DeviceCheck held/path source transaction mismatch")
    authority_identity, authority_digest, authority_raw = _read_inherited_file(
        OWNER_AUTHORITY_FD,
        OWNER_AUTHORITY_PATH,
        "DeviceCheck owner authority",
        expected_mode=0o444,
        require_immutable=True,
        max_bytes=MAX_SOURCE_BYTES,
    )
    del authority_identity
    authority = _validate_owner_authority_bytes(authority_raw, authority_digest)
    workspace = value["workspace"]
    cache = value["cache"]
    if (
        workspace["uid"] != authority["build"]["build_uid"]
        or workspace["gid"] != authority["build"]["build_gid"]
        or cache["uid"] != authority["build"]["build_uid"]
        or cache["gid"] != authority["build"]["build_gid"]
        or workspace["mode"] != 0o700
        or cache["mode"] != 0o700
    ):
        _fail("OWNER-BLOCKED: workspace/cache identity disagrees with owner authority")
    if (
        value["authorization_id"] != authority["authorization"]["authorization_id"]
        or value["nonce"] != authority["authorization"]["nonce"]
        or value["monotonic_sequence"] != authority["authorization"]["sequence"]
        or value["source_index_sha256"] != authority["source_manifest"]["sha256"]
        or value["source_index_path"] != authority["source_manifest"]["path"]
        or value["source_closure_sha256"]
        != authority["source_snapshot"]["closure_sha256"]
        or value["source_snapshot"] != authority["source_snapshot"]["path"]
    ):
        _fail("OWNER-BLOCKED: transaction does not bind the v4 source authority")
    source_index = hold_absolute_file(
        pathlib.Path(authority["source_manifest"]["path"]),
        "DeviceCheck content-addressed source index",
        max_bytes=MAX_SOURCE_BYTES,
        capture=True,
    )
    if (
        source_index.sha256 != authority["source_manifest"]["sha256"]
        or source_index.bytes_count != authority["source_manifest"]["size_bytes"]
        or source_index.identity.mode != 0o444
    ):
        _fail("OWNER-BLOCKED: held source index does not match the owner authority")
    source_index.revalidate()
    inputs = (
        ("release_python", RELEASE_PYTHON_FD, RELEASE_PYTHON_PATH, 0o555),
        ("loader", LOADER_FD, LOADER_PATH, 0o444),
        ("controller", CONTROLLER_FD, CONTROLLER_PATH, 0o444),
        (
            "owner_signer_certificate",
            OWNER_SIGNER_CERTIFICATE_FD,
            OWNER_SIGNER_CERTIFICATE_PATH,
            0o444,
        ),
    )
    held_raw: dict[str, bytes] = {}
    for name, descriptor, path, mode in inputs:
        _identity, digest, raw = _read_inherited_file(
            descriptor,
            path,
            f"DeviceCheck held {name.replace('_', ' ')}",
            expected_mode=mode,
            require_immutable=True,
            max_bytes=MAX_TOOL_BYTES,
        )
        record = _authority_record(authority, name, path)
        if digest != record["sha256"] or len(raw) != record["size_bytes"]:
            _fail(f"OWNER-BLOCKED: held {name} does not match the owner authority")
        if value[f"{name}_sha256"] != digest:
            _fail(f"OWNER-BLOCKED: transaction does not bind held {name}")
        held_raw[name] = raw
    if (
        value["authority_sha256"] != authority_digest
        or value["owner_signer_sha256"] != authority["owner_signer_sha256"]
        or _certificate_der_sha256(
            held_raw["owner_signer_certificate"],
            "DeviceCheck owner signer certificate",
        )
        != value["owner_signer_sha256"]
    ):
        _fail("OWNER-BLOCKED: owner authority, transaction, and signer certificate disagree")
    receipt_tool = closure.held["android/devicecheck/devicecheck_build_receipt.py"]
    receipt_identity, receipt_digest, receipt_raw = _read_inherited_file(
        RECEIPT_TOOL_FD,
        receipt_tool.path,
        "DeviceCheck authority-bound receipt tool",
        expected_mode=0o444,
        require_immutable=False,
        max_bytes=MAX_SOURCE_BYTES,
        expected_uid=os.getuid(),
    )
    if (
        receipt_identity != receipt_tool.identity
        or receipt_digest != receipt_tool.sha256
        or receipt_raw != receipt_tool.raw
        or receipt_digest != value["receipt_tool_sha256"]
    ):
        _fail("OWNER-BLOCKED: held receipt-tool descriptor does not bind the reviewed producer")
    state_path = pathlib.Path(value["controller_state_path"])
    _read_inherited_file(
        CONTROLLER_STATE_FD,
        state_path,
        "DeviceCheck monotonic controller state",
        expected_mode=0o600,
        require_immutable=False,
        max_bytes=64 * 1024,
    )


def _source_transaction(
    repo: pathlib.Path,
    closure: SourceClosure,
    *,
    require_inherited_descriptor: bool,
) -> tuple[dict[str, Any], HeldFile]:
    held = hold_relative_file(
        repo,
        SOURCE_TRANSACTION_RELATIVE,
        "DeviceCheck authenticated source transaction",
        max_bytes=64 * 1024,
        capture=True,
    )
    if held.raw is None:
        _fail("DeviceCheck source transaction bytes were not held")
    value = _strict_json(held.raw, "DeviceCheck source transaction")
    _validate_transaction_value(value, repo, closure)
    if require_inherited_descriptor:
        _production_transaction_custody(repo, value, held, closure)
    held.revalidate()
    return value, held


def _validate_controller_state_value(
    state: dict[str, Any],
    transaction: dict[str, Any],
    transaction_sha256: str,
    allowed_phases: frozenset[str],
) -> None:
    if set(state) != {
        "schema_version",
        "contract",
        "authority_sha256",
        "nonce",
        "monotonic_sequence",
        "phase",
        "transaction_sha256",
        "receipt_sha256",
    }:
        _fail("OWNER-BLOCKED: monotonic controller state fields are invalid")
    receipt_digest = state["receipt_sha256"]
    if (
        state["schema_version"] != 1
        or state["contract"] != CONTROLLER_STATE_CONTRACT
        or state["authority_sha256"] != transaction["authority_sha256"]
        or state["nonce"] != transaction["nonce"]
        or state["monotonic_sequence"] != transaction["monotonic_sequence"]
        or state["transaction_sha256"] != transaction_sha256
        or state["phase"] not in allowed_phases
        or (
            receipt_digest is not None
            and (
                not isinstance(receipt_digest, str)
                or HEX_64_RE.fullmatch(receipt_digest) is None
            )
        )
        or (state["phase"] != "consumed" and receipt_digest is not None)
        or (state["phase"] == "consumed" and receipt_digest is None)
    ):
        _fail("OWNER-BLOCKED: transaction nonce was forged, replayed, expired, or consumed")


def _read_controller_state_locked(
    transaction: dict[str, Any],
    transaction_sha256: str,
    allowed_phases: frozenset[str],
) -> dict[str, Any]:
    state_path = pathlib.Path(transaction["controller_state_path"])
    _identity, _digest, raw = _read_inherited_file(
        CONTROLLER_STATE_FD,
        state_path,
        "DeviceCheck monotonic controller state",
        expected_mode=0o600,
        require_immutable=False,
        max_bytes=64 * 1024,
    )
    state = _strict_json(raw, "DeviceCheck monotonic controller state")
    _validate_controller_state_value(
        state,
        transaction,
        transaction_sha256,
        allowed_phases,
    )
    return state


def _validate_controller_state(
    transaction: dict[str, Any],
    transaction_sha256: str,
    allowed_phases: frozenset[str],
) -> dict[str, Any]:
    try:
        fcntl.flock(CONTROLLER_STATE_FD, fcntl.LOCK_EX)
        return _read_controller_state_locked(
            transaction,
            transaction_sha256,
            allowed_phases,
        )
    except OSError as exc:
        raise ReceiptError("OWNER-BLOCKED: monotonic controller state lock failed") from exc
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(CONTROLLER_STATE_FD, fcntl.LOCK_UN)


def _transition_controller_state(
    transaction: dict[str, Any],
    transaction_sha256: str,
    *,
    expected_phase: str,
    next_phase: str,
    receipt_sha256: str | None,
) -> None:
    try:
        fcntl.flock(CONTROLLER_STATE_FD, fcntl.LOCK_EX)
        state = _read_controller_state_locked(
            transaction,
            transaction_sha256,
            frozenset({expected_phase}),
        )
        state["phase"] = next_phase
        state["receipt_sha256"] = receipt_sha256
        raw = _canonical_json(state)
        os.lseek(CONTROLLER_STATE_FD, 0, os.SEEK_SET)
        os.ftruncate(CONTROLLER_STATE_FD, 0)
        _write_all(CONTROLLER_STATE_FD, raw)
        os.fsync(CONTROLLER_STATE_FD)
        os.lseek(CONTROLLER_STATE_FD, 0, os.SEEK_SET)
    except OSError as exc:
        raise ReceiptError("OWNER-BLOCKED: monotonic controller state transition failed") from exc
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(CONTROLLER_STATE_FD, fcntl.LOCK_UN)


def authenticate_build_gate(repo: pathlib.Path) -> dict[str, Any]:
    """Consume one owner-issued nonce before any build output may be written."""
    repo = _absolute_path(repo)
    closure = hold_source_closure(repo)
    transaction, held = _source_transaction(
        repo,
        closure,
        require_inherited_descriptor=True,
    )
    _transition_controller_state(
        transaction,
        held.sha256,
        expected_phase="issued",
        next_phase="building",
        receipt_sha256=None,
    )
    closure.revalidate()
    held.revalidate()
    return {
        "authority_sha256": transaction["authority_sha256"],
        "contract": SOURCE_TRANSACTION_CONTRACT,
        "nonce": transaction["nonce"],
        "ok": True,
        "sequence": transaction["monotonic_sequence"],
        "workspace": str(repo),
    }


def _tool_environment() -> dict[str, str]:
    return {
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": "/private/tmp",
    }


def _run_checked(command: Sequence[str], *, pass_fds: tuple[int, ...] = ()) -> str:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            env=_tool_environment(),
            errors="strict",
            pass_fds=pass_fds,
            cwd="/private/tmp",
            close_fds=True,
        )
    except (OSError, UnicodeError) as exc:
        raise ReceiptError(f"failed to execute reviewed SDK tool {command[0]}") from exc
    if completed.returncode != 0:
        _fail(
            f"reviewed SDK tool failed for {pathlib.Path(command[-1]).name}: "
            f"exit={completed.returncode}"
        )
    return completed.stdout


ToolRunner = Callable[[Sequence[str]], str]


def _run_held_tool(
    command: Sequence[str],
    descriptors: tuple[int, ...],
    runner: ToolRunner | None,
) -> str:
    if runner is None:
        return _run_checked(command, pass_fds=descriptors)
    return runner(command)


def _parse_signer_digest(output: str, label: str) -> str:
    verified = re.findall(
        r"(?im)^Verified using v(?:2|3(?:\.1)?) scheme.*:\s*true\s*$",
        output,
    )
    if not verified:
        _fail(f"{label} is not verified with APK Signature Scheme v2 or v3")
    raw_digests = re.findall(
        r"(?im)^.*certificate SHA-256 digest:\s*([0-9A-Fa-f:]+)\s*$",
        output,
    )
    digests = {value.replace(":", "").lower() for value in raw_digests}
    if len(digests) != 1:
        _fail(f"{label} has zero, ambiguous, or multiple signer certificate digests")
    digest = next(iter(digests))
    if HEX_64_RE.fullmatch(digest) is None:
        _fail(f"{label} signer SHA-256 is malformed")
    signer_numbers = {
        int(value)
        for value in re.findall(
            r"(?im)^(?:[A-Za-z0-9_.-]+\s+)*Signer\s+#([0-9]+)\s+certificate SHA-256 digest:",
            output,
        )
    }
    if signer_numbers != {1}:
        _fail(f"{label} must have exactly one APK signer")
    return digest


def _required_owner_signer_sha256() -> str:
    value = EXPECTED_OWNER_SIGNER_SHA256
    if HEX_64_RE.fullmatch(value) is None or value in {"0" * 64, hashlib.sha256(b"").hexdigest()}:
        _fail("OWNER-BLOCKED: reviewed DeviceCheck owner signer identity is not provisioned")
    return value


def _parse_aapt_package(output: str, label: str) -> tuple[str, str, int]:
    package_lines = re.findall(r"(?m)^package:\s*(.+)$", output)
    if len(package_lines) != 1:
        _fail(f"{label} has zero or ambiguous aapt package records")
    pairs = re.findall(r"([A-Za-z][A-Za-z0-9_]*)='([^']*)'", package_lines[0])
    fields: dict[str, str] = {}
    for key, value in pairs:
        if key in fields:
            _fail(f"{label} aapt package record has duplicate field {key}")
        fields[key] = value
    required = ("name", "versionCode", "versionName")
    if any(key not in fields for key in required):
        _fail(f"{label} aapt package record omits package/version identity")
    package_id = fields["name"]
    version_name = fields["versionName"]
    version_code_text = fields["versionCode"]
    if PACKAGE_ID_RE.fullmatch(package_id) is None:
        _fail(f"{label} has malformed package id")
    if VERSION_CODE_RE.fullmatch(version_code_text) is None:
        _fail(f"{label} has malformed version code")
    if int(version_code_text) > 2_147_483_647:
        _fail(f"{label} version code exceeds Android signed-int range")
    try:
        encoded_name = version_name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ReceiptError(f"{label} version name is not UTF-8") from exc
    if not encoded_name or len(encoded_name) > 1024 or any(ord(ch) < 32 for ch in version_name):
        _fail(f"{label} version name is malformed")
    return package_id, version_name, int(version_code_text)


def inspect_apk(
    held: HeldFile,
    toolchain: Toolchain,
    min_sdk: int,
    runner: ToolRunner | None,
) -> dict[str, Any]:
    with held_descriptor(held) as descriptor:
        descriptor_path = f"/dev/fd/{descriptor}"
        with held_descriptor(toolchain.java) as java_descriptor, held_descriptor(
            toolchain.inputs["apksigner_jar"]
        ) as jar_descriptor:
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.lseek(jar_descriptor, 0, os.SEEK_SET)
            signer_output = _run_held_tool(
                (
                    f"/dev/fd/{java_descriptor}",
                    "-jar",
                    f"/dev/fd/{jar_descriptor}",
                    "verify",
                    "--verbose",
                    "--print-certs",
                    "-Werr",
                    "--min-sdk-version",
                    str(min_sdk),
                    descriptor_path,
                ),
                (descriptor, java_descriptor, jar_descriptor),
                runner,
            )
        signer_sha256 = _parse_signer_digest(signer_output, held.label)
        with held_descriptor(toolchain.inputs["aapt"]) as aapt_descriptor:
            os.lseek(descriptor, 0, os.SEEK_SET)
            aapt_output = _run_held_tool(
                (f"/dev/fd/{aapt_descriptor}", "dump", "badging", descriptor_path),
                (descriptor, aapt_descriptor),
                runner,
            )
        package_id, version_name, version_code = _parse_aapt_package(aapt_output, held.label)
    return {
        "bytes": held.bytes_count,
        "identity": held.identity.receipt_value(),
        "package_id": package_id,
        "path": held.relative if held.relative is not None else str(held.path),
        "sha256": held.sha256,
        "signer_sha256": signer_sha256,
        "version_code": version_code,
        "version_name": version_name,
        "version_name_utf8_hex": version_name.encode("utf-8").hex(),
    }


def _require_distinct_artifacts(
    target: HeldFile,
    android_test: HeldFile,
    target_record: dict[str, Any],
    test_record: dict[str, Any],
) -> None:
    if target.relative == android_test.relative or target.path == android_test.path:
        _fail("target and androidTest APK paths are reused")
    if (target.identity.device, target.identity.inode) == (
        android_test.identity.device,
        android_test.identity.inode,
    ):
        _fail("target and androidTest APKs reuse one inode")
    if target.sha256 == android_test.sha256:
        _fail("target and androidTest APKs reuse one SHA-256")
    if target_record["package_id"] + ".test" != test_record["package_id"]:
        _fail("androidTest package id does not exactly bind to the target package id")
    for key in ("version_name", "version_name_utf8_hex", "version_code", "signer_sha256"):
        if target_record[key] != test_record[key]:
            _fail(f"target and androidTest APK {key} values do not match")


def _inventory_sha256(inventory: list[dict[str, Any]]) -> str:
    return hashlib.sha256(_canonical_json(inventory)).hexdigest()


def _closure_evidence(closure: SourceClosure, path: str) -> dict[str, Any]:
    item = closure.held.get(path)
    if item is None:
        _fail(f"DeviceCheck closure omitted required evidence input: {path}")
    return item.evidence(closure.repo)


@dataclass
class DerivedReceipt:
    payload: dict[str, Any]
    closure: SourceClosure
    toolchain: Toolchain
    target: HeldFile
    android_test: HeldFile
    policy: VariantPolicy
    source_transaction: HeldFile
    source_transaction_value: dict[str, Any]

    def revalidate(self) -> None:
        self.closure.revalidate()
        _validate_transaction_value(
            self.source_transaction_value,
            self.closure.repo,
            self.closure,
        )
        self.toolchain.revalidate()
        self.target.revalidate()
        self.android_test.revalidate()
        self.source_transaction.revalidate()
        _require_exact_output_set(self.closure.repo, self.policy)


def derive_receipt(
    repo: pathlib.Path,
    sdk_root: pathlib.Path,
    variant: str,
    *,
    runner: ToolRunner | None = None,
    _allowed_state_phases: frozenset[str] = frozenset({"building"}),
) -> DerivedReceipt:
    repo = _absolute_path(repo)
    policy = selected_policy(variant)
    closure = hold_source_closure(repo)
    source_transaction, source_transaction_held = _source_transaction(
        repo,
        closure,
        require_inherited_descriptor=runner is None,
    )
    if runner is None:
        _validate_controller_state(
            source_transaction,
            source_transaction_held.sha256,
            _allowed_state_phases,
        )
    _validate_build_script_policy(closure, policy, schema_fixture=runner is not None)
    facts = build_facts(closure)
    toolchain = hold_toolchain(
        sdk_root,
        require_sealed_execution=runner is None,
    )
    _require_exact_output_set(repo, policy)
    target = hold_relative_file(
        repo,
        policy.target_apk,
        "DeviceCheck target APK",
        max_bytes=MAX_APK_BYTES,
        capture=False,
    )
    android_test = hold_relative_file(
        repo,
        policy.android_test_apk,
        "DeviceCheck androidTest APK",
        max_bytes=MAX_APK_BYTES,
        capture=False,
    )
    target_record = inspect_apk(target, toolchain, facts.min_sdk, runner)
    test_record = inspect_apk(android_test, toolchain, facts.min_sdk, runner)
    _require_distinct_artifacts(target, android_test, target_record, test_record)
    owner_signer_sha256 = _required_owner_signer_sha256()
    if source_transaction["owner_signer_sha256"] != owner_signer_sha256:
        _fail("DeviceCheck transaction signer drifted from the reviewed owner certificate")
    if (
        target_record["signer_sha256"] != owner_signer_sha256
        or test_record["signer_sha256"] != owner_signer_sha256
    ):
        _fail("DeviceCheck APK signer drifted from the reviewed owner signer identity")
    inventory = closure.inventory()
    payload: dict[str, Any] = {
        "artifacts": {
            "android_test": test_record,
            "target": target_record,
        },
        "build": {
            "android_test_task": policy.android_test_task,
            "android_test_output": policy.android_test_apk,
            "compile_sdk": facts.compile_sdk,
            "min_sdk": facts.min_sdk,
            "target_sdk": facts.target_sdk,
            "target_output": policy.target_apk,
            "target_task": policy.target_task,
            "variant": policy.name,
        },
        "contract": CONTRACT,
        "gradle_custody": {
            "agp_version": facts.agp_version,
            "dependency_lock": _closure_evidence(
                closure,
                "android/devicecheck/gradle/dependency-locking/app.lockfile",
            ),
            "gradle_version": facts.gradle_version,
            "ndk_version": facts.ndk_version,
            "verification_metadata": _closure_evidence(
                closure,
                "android/devicecheck/gradle/verification-metadata.xml",
            ),
        },
        "parity": {
            "android_test_package_id": test_record["package_id"],
            "package_relation": "target_package_id + .test",
            "passed": True,
            "signer_sha256": target_record["signer_sha256"],
            "version_code": target_record["version_code"],
            "version_name_utf8_hex": target_record["version_name_utf8_hex"],
        },
        "owner_signer": {
            "certificate_sha256": owner_signer_sha256,
            "identity_source": "reviewed-source-pin",
        },
        "producer": {
            "build_script": _closure_evidence(closure, "android/devicecheck/build_devicecheck.sh"),
            "companion_source_contract_test": _closure_evidence(
                closure,
                "android/devicecheck/test_live_hardware_attestation_proof.py",
            ),
            "hardware_attestation_test": _closure_evidence(
                closure,
                "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/HardwareAttestationTest.kt",
            ),
            "live_hardware_attestation_proof_test": _closure_evidence(
                closure,
                "android/devicecheck/app/src/androidTest/kotlin/org/winsvpn/devicecheck/LiveHardwareAttestationProofTest.kt",
            ),
            "receipt_tool": _closure_evidence(closure, "android/devicecheck/devicecheck_build_receipt.py"),
            "shipping_source_closure_test": _closure_evidence(
                closure,
                "android/devicecheck/test_shipping_source_closure.py",
            ),
            "source_inventory_sha256": source_transaction["producer_source_sha256"],
        },
        "receipt_storage": {
            "atomic_publication_contract": ATOMIC_PUBLICATION_CONTRACT,
            "publication": "descriptor-relative-exclusive-atomic-directory-rename",
            "receipt_name": RECEIPT_NAME,
            "sidecar_name": SIDECAR_NAME,
        },
        "schema_version": SCHEMA_VERSION,
        "source_transaction": {
            "authority_sha256": source_transaction["authority_sha256"],
            "authorization_id": source_transaction["authorization_id"],
            "atomic_publication_contract": source_transaction[
                "atomic_publication_contract"
            ],
            "cache": source_transaction["cache"],
            "consumer_status": source_transaction["consumer_status"],
            "expires_unix_ns": source_transaction["expires_unix_ns"],
            "handoff_contract": source_transaction["handoff_contract"],
            "monotonic_sequence": source_transaction["monotonic_sequence"],
            "nonce": source_transaction["nonce"],
            "prebuild_source_inventory_sha256": source_transaction[
                "producer_source_sha256"
            ],
            "source_closure_sha256": source_transaction["source_closure_sha256"],
            "source_index_path": source_transaction["source_index_path"],
            "source_index_sha256": source_transaction["source_index_sha256"],
            "source_snapshot": source_transaction["source_snapshot"],
            "transaction_sha256": source_transaction_held.sha256,
            "workspace": source_transaction["workspace"],
        },
        "source_closure": {
            "inventory": inventory,
            "inventory_sha256": _inventory_sha256(inventory),
        },
        "toolchain": toolchain.receipt_value(),
    }
    derived = DerivedReceipt(
        payload,
        closure,
        toolchain,
        target,
        android_test,
        policy,
        source_transaction_held,
        source_transaction,
    )
    derived.revalidate()
    return derived


def receipt_directory_relative(variant: str) -> str:
    selected_policy(variant)
    return f"{RECEIPT_BASE}/{variant}"


def receipt_relative(variant: str) -> str:
    return f"{receipt_directory_relative(variant)}/{RECEIPT_NAME}"


def sidecar_relative(variant: str) -> str:
    return f"{receipt_directory_relative(variant)}/{SIDECAR_NAME}"


def _open_or_create_directory(parent_descriptor: int, name: str, label: str) -> int:
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    _require_directory(before, label)
    descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_descriptor)
    opened = os.fstat(descriptor)
    if not _same_identity(before, opened):
        os.close(descriptor)
        _fail(f"{label} changed while opened")
    return descriptor


def _write_new_file(
    directory_descriptor: int,
    name: str,
    data: bytes,
    label: str,
) -> FileIdentity:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | _require_no_follow()
    )
    descriptor = os.open(name, flags, 0o400, dir_fd=directory_descriptor)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        _require_regular_one_link(opened, label)
        if opened.st_size != len(data):
            _fail(f"{label} changed while published")
        os.fchmod(descriptor, 0o400)
        return FileIdentity.from_stat(os.fstat(descriptor))
    finally:
        os.close(descriptor)


@dataclass
class PublishedReceipt:
    root_path: pathlib.Path
    root_descriptor: int
    root_identity: FileIdentity
    owned_directories: list[int]
    directory_links: list[tuple[int, str, int, FileIdentity]]
    parent_descriptor: int
    receipt_descriptor: int
    variant: str
    receipt_identity: FileIdentity | None
    sidecar_identity: FileIdentity | None

    def revalidate_ancestors(self) -> None:
        if not _same_directory_binding(
            FileIdentity.from_stat(os.lstat(self.root_path)),
            self.root_identity,
        ):
            _fail("DeviceCheck receipt repository changed during publication")
        for parent, name, child, identity in self.directory_links:
            path_identity = FileIdentity.from_stat(
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            )
            descriptor_identity = FileIdentity.from_stat(os.fstat(child))
            if not _same_directory_binding(path_identity, identity) or not _same_directory_binding(
                descriptor_identity,
                identity,
            ):
                _fail("DeviceCheck receipt ancestor changed during publication")

    def close(self) -> None:
        for descriptor in reversed(self.owned_directories):
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            os.close(self.root_descriptor)
        self.owned_directories.clear()

    def _remove_owned_file(self, name: str, identity: FileIdentity | None) -> None:
        if identity is None:
            return
        try:
            current = os.stat(name, dir_fd=self.receipt_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        if FileIdentity.from_stat(current) != identity:
            return
        with contextlib.suppress(OSError):
            os.unlink(name, dir_fd=self.receipt_descriptor)

    def rollback(self) -> None:
        with contextlib.suppress(OSError):
            os.fchmod(self.receipt_descriptor, 0o700)
        self._remove_owned_file(SIDECAR_NAME, self.sidecar_identity)
        self._remove_owned_file(RECEIPT_NAME, self.receipt_identity)
        with contextlib.suppress(OSError):
            os.rmdir(self.variant, dir_fd=self.parent_descriptor)
        self.close()


def _same_directory_binding(left: FileIdentity, right: FileIdentity) -> bool:
    return (
        left.device,
        left.inode,
        left.mode,
        left.uid,
        left.gid,
        left.flags,
    ) == (
        right.device,
        right.inode,
        right.mode,
        right.uid,
        right.gid,
        right.flags,
    )


def _rename_exclusive(
    directory_descriptor: int,
    source_name: str,
    target_name: str,
) -> None:
    if sys.platform != "darwin":
        _fail("OWNER-BLOCKED: atomic exclusive receipt publication requires macOS")
    renameatx = ctypes.CDLL(None, use_errno=True).renameatx_np
    renameatx.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameatx.restype = ctypes.c_int
    rename_excl = 0x00000004
    result = renameatx(
        directory_descriptor,
        os.fsencode(source_name),
        directory_descriptor,
        os.fsencode(target_name),
        rename_excl,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise ReceiptError(
            "DeviceCheck receipt directory already exists; no-replace publication refused"
        )
    raise OSError(error, os.strerror(error), target_name)


def publish_receipt(repo: pathlib.Path, variant: str, payload: dict[str, Any]) -> PublishedReceipt:
    receipt_data = _canonical_json(payload)
    receipt_digest = hashlib.sha256(receipt_data).hexdigest()
    sidecar_data = (
        f"{receipt_digest}  {RECEIPT_NAME}\n".encode("ascii")
    )
    parts = _relative_parts(receipt_directory_relative(variant))
    root, root_descriptor, root_identity = _open_root(repo, "DeviceCheck receipt repository")
    owned_directories: list[int] = []
    directory_links: list[tuple[int, str, int, FileIdentity]] = []
    parent_descriptor = root_descriptor
    receipt_descriptor: int | None = None
    publication: PublishedReceipt | None = None
    try:
        for name in parts[:-1]:
            child = _open_or_create_directory(
                parent_descriptor,
                name,
                f"DeviceCheck receipt parent {name}",
            )
            child_identity = FileIdentity.from_stat(os.fstat(child))
            directory_links.append((parent_descriptor, name, child, child_identity))
            owned_directories.append(child)
            parent_descriptor = child
        staging_name = f".{parts[-1]}.{receipt_digest}.tmp"
        try:
            os.mkdir(staging_name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError as exc:
            raise ReceiptError(
                "DeviceCheck receipt staging directory already exists; publication refused"
            ) from exc
        receipt_descriptor = os.open(
            staging_name,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
        publication = PublishedReceipt(
            root_path=root,
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            owned_directories=owned_directories,
            directory_links=directory_links,
            parent_descriptor=parent_descriptor,
            receipt_descriptor=receipt_descriptor,
            variant=staging_name,
            receipt_identity=None,
            sidecar_identity=None,
        )
        publication.receipt_identity = _write_new_file(
            receipt_descriptor,
            RECEIPT_NAME,
            receipt_data,
            "DeviceCheck receipt",
        )
        publication.sidecar_identity = _write_new_file(
            receipt_descriptor,
            SIDECAR_NAME,
            sidecar_data,
            "DeviceCheck receipt sidecar",
        )
        os.fsync(receipt_descriptor)
        os.fchmod(receipt_descriptor, 0o500)
        publication.revalidate_ancestors()
        _rename_exclusive(parent_descriptor, staging_name, parts[-1])
        publication.variant = parts[-1]
        os.fsync(parent_descriptor)
        publication.revalidate_ancestors()
        return publication
    except BaseException:
        if publication is not None:
            publication.rollback()
        else:
            if receipt_descriptor is not None:
                with contextlib.suppress(OSError):
                    os.close(receipt_descriptor)
            for descriptor in reversed(owned_directories):
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            with contextlib.suppress(OSError):
                os.close(root_descriptor)
        raise


def _receipt_entries(repo: pathlib.Path, variant: str) -> tuple[str, ...]:
    parts = _relative_parts(receipt_directory_relative(variant))
    chain = _open_relative_chain(repo, (*parts, "held-entry"), "DeviceCheck receipt directory")
    try:
        entries = tuple(sorted(os.listdir(chain.parent_descriptor)))
        chain.revalidate("DeviceCheck receipt directory")
    except OSError as exc:
        raise ReceiptError("DeviceCheck receipt directory cannot be read") from exc
    finally:
        chain.close()
    expected = (RECEIPT_NAME, SIDECAR_NAME)
    if entries != expected:
        _fail("DeviceCheck receipt directory has partial or unexpected publication entries")
    return entries


def load_receipt(repo: pathlib.Path, variant: str) -> tuple[dict[str, Any], str]:
    _receipt_entries(repo, variant)
    receipt = hold_relative_file(
        repo,
        receipt_relative(variant),
        "DeviceCheck receipt",
        max_bytes=MAX_RECEIPT_BYTES,
        capture=True,
    )
    sidecar = hold_relative_file(
        repo,
        sidecar_relative(variant),
        "DeviceCheck receipt sidecar",
        max_bytes=1024,
        capture=True,
    )
    if receipt.raw is None or sidecar.raw is None:
        _fail("DeviceCheck receipt bytes were not held")
    payload = _strict_json(receipt.raw, "DeviceCheck receipt")
    expected_sidecar = f"{receipt.sha256}  {RECEIPT_NAME}\n".encode("ascii")
    if sidecar.raw != expected_sidecar:
        _fail("DeviceCheck receipt sidecar does not match canonical receipt bytes")
    receipt.revalidate()
    sidecar.revalidate()
    return payload, receipt.sha256


def verify(
    repo: pathlib.Path,
    sdk_root: pathlib.Path,
    variant: str,
    *,
    runner: ToolRunner | None = None,
    _recording: bool = False,
) -> dict[str, Any]:
    repo = _absolute_path(repo)
    payload, receipt_sha256 = load_receipt(repo, variant)
    allowed_phases = (
        frozenset({"building"}) if _recording else frozenset({"consumed"})
    )
    derived = derive_receipt(
        repo,
        sdk_root,
        variant,
        runner=runner,
        _allowed_state_phases=allowed_phases,
    )
    if payload != derived.payload:
        _fail("DeviceCheck receipt contains forged, stale, or caller-authored fields")
    derived.revalidate()
    payload_after, receipt_sha256_after = load_receipt(repo, variant)
    if payload_after != payload or receipt_sha256_after != receipt_sha256:
        _fail("DeviceCheck receipt drifted while it was revalidated")
    if runner is None:
        state = _validate_controller_state(
            derived.source_transaction_value,
            derived.source_transaction.sha256,
            allowed_phases,
        )
        if not _recording and state["receipt_sha256"] != receipt_sha256:
            _fail("OWNER-BLOCKED: consumed controller state binds a different receipt")
    return {
        "android_test_sha256": derived.payload["artifacts"]["android_test"]["sha256"],
        "contract": CONTRACT,
        "ok": True,
        "receipt": receipt_relative(variant),
        "receipt_sha256": receipt_sha256,
        "sidecar": sidecar_relative(variant),
        "target_sha256": derived.payload["artifacts"]["target"]["sha256"],
        "variant": variant,
    }


def record(
    repo: pathlib.Path,
    sdk_root: pathlib.Path,
    variant: str,
    *,
    runner: ToolRunner | None = None,
) -> dict[str, Any]:
    repo = _absolute_path(repo)
    derived = derive_receipt(repo, sdk_root, variant, runner=runner)
    derived.revalidate()
    publication = publish_receipt(repo, variant, derived.payload)
    try:
        result = verify(repo, sdk_root, variant, runner=runner, _recording=True)
    except BaseException:
        publication.rollback()
        raise
    if runner is None:
        try:
            _transition_controller_state(
                derived.source_transaction_value,
                derived.source_transaction.sha256,
                expected_phase="building",
                next_phase="consumed",
                receipt_sha256=result["receipt_sha256"],
            )
        except BaseException:
            publication.rollback()
            raise
    publication.close()
    return result


def selftest() -> dict[str, Any]:
    """Exercise parser invariants without an APK, SDK invocation, or device action."""
    signer = _parse_signer_digest(
        "Verified using v2 scheme (APK Signature Scheme v2): true\n"
        "Signer #1 certificate SHA-256 digest: " + "a" * 64 + "\n",
        "selftest APK",
    )
    package_id, version_name, version_code = _parse_aapt_package(
        "package: name='org.winsvpn.devicecheck' versionCode='1' versionName='devicecheck'\n",
        "selftest APK",
    )
    try:
        _strict_json(b'{"x":1,"x":2}\n', "selftest duplicate JSON")
    except ReceiptError:
        pass
    else:
        _fail("selftest duplicate JSON rejection failed")
    if signer != "a" * 64 or (package_id, version_name, version_code) != (
        "org.winsvpn.devicecheck",
        "devicecheck",
        1,
    ):
        _fail("selftest parser invariant failed")
    return {"contract": CONTRACT, "device_actions": False, "ok": True}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in ("record", "verify"):
        command = subcommands.add_parser(name)
        command.add_argument("--repo-root", required=True, type=pathlib.Path)
        command.add_argument("--sdk-dir", required=True, type=pathlib.Path)
        command.add_argument("--variant", required=True, choices=tuple(sorted(VARIANT_POLICIES)))
    gate = subcommands.add_parser("gate")
    gate.add_argument("--repo-root", required=True, type=pathlib.Path)
    subcommands.add_parser("selftest")
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        if arguments.command == "selftest":
            result = selftest()
        elif arguments.command == "gate":
            result = authenticate_build_gate(arguments.repo_root)
        elif arguments.command == "record":
            result = record(arguments.repo_root, arguments.sdk_dir, arguments.variant)
        else:
            result = verify(arguments.repo_root, arguments.sdk_dir, arguments.variant)
    except ReceiptError as exc:
        print(f"REFUSING: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(_canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
