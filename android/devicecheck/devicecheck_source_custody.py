#!/usr/bin/env python3
"""Authenticated source custody for the DeviceCheck release producer.

This verification-only module is intentionally independent of the build
driver.  It discovers a bounded, content-addressed closure, binds it to a
reviewed Git commit, and validates an externally installed snapshot under the
fixed ``/Library/WinsVPN`` authority.  It does not provision that authority or
hand immutable compiler inputs to Gradle or Go.  It never invokes sudo, reads a
sudo password, downloads anything, or signs anything.

The filesystem code uses descriptor-relative traversal with O_NOFOLLOW.  A
pathname is never trusted merely because it was checked before it was opened:
the open descriptor, all retained ancestor identities, and the path entry are
checked together before and after every read.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import select
import ssl
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Sequence


CONTRACT = "winsvpn-devicecheck-source-custody-v2"
SCHEMA_VERSION = 2
AUTHORITY_ROOT = Path("/Library/WinsVPN")
SOURCE_AUTHORITY_RELATIVE = "ReleaseAndroidSource/devicecheck-v3"
SNAPSHOT_BASE_RELATIVE = f"{SOURCE_AUTHORITY_RELATIVE}/snapshots/sha256"
MANIFEST_BASE_RELATIVE = f"{SOURCE_AUTHORITY_RELATIVE}/manifests/sha256"
DEFAULT_SNAPSHOT = AUTHORITY_ROOT / SNAPSHOT_BASE_RELATIVE
DEFAULT_MANIFEST = AUTHORITY_ROOT / MANIFEST_BASE_RELATIVE
OWNER_AUTHORITY_CONTRACT = "winsvpn-devicecheck-owner-authority-v4"
OWNER_AUTHORITY_PATH = AUTHORITY_ROOT / f"{SOURCE_AUTHORITY_RELATIVE}.authority.json"
EXPECTED_OWNER_AUTHORITY_SHA256 = "0" * 64
RELEASE_PYTHON_PATH = AUTHORITY_ROOT / "ReleasePython/3.14.7/launcher/python3"
LOADER_PATH = AUTHORITY_ROOT / SOURCE_AUTHORITY_RELATIVE / "loader.py"
CONTROLLER_PATH = AUTHORITY_ROOT / SOURCE_AUTHORITY_RELATIVE / "controller.py"
OWNER_SIGNER_CERTIFICATE_PATH = (
    AUTHORITY_ROOT / "ReleaseAndroidSigning/devicecheck-owner.x509.pem"
)
BUILD_WORKSPACE_ROOT = Path("/private/var/winsvpn-devicecheck-build")
BUILD_CACHE_ROOT = Path("/private/var/winsvpn-devicecheck-cache")
BUILD_HANDOFF_CONTRACT = "winsvpn-devicecheck-private-build-handoff-v1"
ATOMIC_PUBLICATION_CONTRACT = "winsvpn-devicecheck-content-addressed-publication-v1"
CONSUMER_STATUS = "unintegrated"
GIT_EXECUTABLE = Path("/usr/bin/git")

SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)
UF_IMMUTABLE = getattr(stat, "UF_IMMUTABLE", 0x00000002)
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_GIT_METADATA_FILE_BYTES = 384 * 1024 * 1024
MAX_GIT_METADATA_TOTAL_BYTES = 768 * 1024 * 1024
MAX_FILE_COUNT = 100_000
MAX_DIRECTORY_COUNT = 100_000
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_GIT_STDOUT_BYTES = 64 * 1024 * 1024
MAX_GIT_STDERR_BYTES = 1024 * 1024
READ_CHUNK = 128 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40,64}$")

# These are the build's control inputs.  Generated output directories and the
# machine-local local.properties file are deliberately outside this closure.
DEVICECHECK_CONTROL_FILES = (
    "android/devicecheck/app/build.gradle.kts",
    "android/devicecheck/build.gradle.kts",
    "android/devicecheck/build_devicecheck.sh",
    "android/devicecheck/devicecheck_build_receipt.py",
    "android/devicecheck/devicecheck_source_custody.py",
    "android/devicecheck/gradle.properties",
    "android/devicecheck/gradlew",
    "android/devicecheck/gradlew.bat",
    "android/devicecheck/settings.gradle.kts",
)
ANDROID_CONTROL_FILES = (
    "android/app/build.gradle.kts",
    "android/gradlew",
    "android/gradle/wrapper/gradle-wrapper.jar",
    "android/gradle/wrapper/gradle-wrapper.properties",
    "android/gradle/dependency-locking/app.lockfile",
    "android/gradle/dependency-locking/jni.lockfile",
    "android/gradle/dependency-locking/jni_flutter.lockfile",
    "android/gradle/verification-metadata.xml",
    "android/app/libs/amneziawg.aar",
)
DEVICECHECK_TREE_ROOTS = (
    "android/devicecheck/app/src/androidTest",
    "android/devicecheck/app/src/main/kotlin/org/winsvpn/devicecheck",
    "android/devicecheck/awgresponder",
    "android/devicecheck/engine",
    "android/devicecheck/gradle",
    "winn_protocol_experimental",
)
DEVICECHECK_EXPLICIT_SOURCE_FILES = (
    "android/devicecheck/app/src/main/AndroidManifest.xml",
)
SHIPPING_APP_SOURCE_FILES = (
    "WinnAndroidEngineHost.kt",
    "WinnAwgLoopbackSeam.kt",
    "WinnCarrierProfile.kt",
    "WinnCarrierProfileKeys.kt",
    "WinnEngineConfig.kt",
    "WinnEngineTransport.kt",
    "WinnProtocolFraming.kt",
    "WinnTunnelBridge.kt",
    "WinnV3AndroidTun.kt",
    "WinnV3Bridge.kt",
    "WinnV3Host.kt",
    "WinnV3Keys.kt",
    "WinnV3Posture.kt",
    "WinnV3PromotionProbe.kt",
    "WinnV3SessionPlan.kt",
    "WinnV3StagedStart.kt",
)
GO_SUM_FILES = (
    "winn_protocol_experimental/go.sum",
    "android/devicecheck/awgresponder/go.sum",
)
EXCLUDED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".gradle",
        ".dart_tool",
        "__pycache__",
        "build",
        "dist",
        "target",
        "testdata",
    }
)
FORBIDDEN_NAME_PARTS = frozenset(
    {
        ".env",
        ".pem",
        ".p12",
        ".pfx",
        ".key",
        "id_rsa",
        "id_ed25519",
        ".jks",
        ".keystore",
    }
)


class CustodyError(ValueError):
    """Raised for any source, manifest, or installed-snapshot violation."""


def _fail(message: str) -> None:
    raise CustodyError(message)


def _nofollow() -> int:
    flag = getattr(os, "O_NOFOLLOW", 0)
    if not flag:
        _fail("O_NOFOLLOW is required for DeviceCheck source custody")
    return flag


def _directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if not directory:
        _fail("O_DIRECTORY is required for DeviceCheck source custody")
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | directory | _nofollow()


def _file_flags(read_only: bool = True) -> int:
    access = os.O_RDONLY if read_only else os.O_WRONLY
    return access | getattr(os, "O_CLOEXEC", 0) | _nofollow()


def _relative_parts(value: str | Path) -> tuple[str, ...]:
    text = str(value)
    if not text or "\\" in text:
        _fail(f"unsafe relative path: {value}")
    path = Path(text)
    if path.is_absolute() or not path.parts:
        _fail(f"path is not repository-relative: {value}")
    if path.as_posix() != text:
        _fail(f"relative path is not canonical: {value}")
    if any(part in {"", ".", ".."} for part in path.parts):
        _fail(f"unsafe relative path: {value}")
    encoded = os.fsencode(text)
    if len(encoded) > MAX_PATH_BYTES:
        _fail(f"path exceeds custody bound: {value}")
    return tuple(path.parts)


def _relative_text(parts: Sequence[str]) -> str:
    return "/".join(parts)


def _absolute(path: Path) -> Path:
    value = Path(path)
    if not value.is_absolute():
        _fail(f"absolute path required: {path}")
    return value


def _canonical_system_alias(path: Path) -> Path:
    """Expand only Apple's fixed root aliases without pathname resolution."""
    path = _absolute(path)
    parts = path.parts
    if len(parts) < 2 or parts[1] not in {"tmp", "var"}:
        return path
    alias = Path(path.anchor) / parts[1]
    expected = f"private/{parts[1]}"
    info = os.lstat(alias)
    if (
        not stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or os.readlink(alias) != expected
    ):
        _fail(f"fixed system alias identity changed: {alias}")
    return Path(path.anchor) / "private" / parts[1] / Path(*parts[2:])


def _reject_symlink_components(path: Path) -> None:
    path = _canonical_system_alias(path)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError as exc:
            raise CustodyError(f"missing path component: {current}") from exc
        if stat.S_ISLNK(info.st_mode):
            _fail(f"symlink path component rejected: {current}")


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int
    flags: int

    @classmethod
    def from_stat(cls, info: os.stat_result) -> "FileIdentity":
        return cls(
            device=int(info.st_dev),
            inode=int(info.st_ino),
            uid=int(info.st_uid),
            gid=int(info.st_gid),
            mode=stat.S_IMODE(info.st_mode),
            nlink=int(info.st_nlink),
            size=int(info.st_size),
            mtime_ns=int(info.st_mtime_ns),
            ctime_ns=int(info.st_ctime_ns),
            flags=int(getattr(info, "st_flags", 0)),
        )

    def document(self) -> dict[str, int]:
        return {
            "ctime_ns": self.ctime_ns,
            "device": self.device,
            "flags": self.flags,
            "gid": self.gid,
            "inode": self.inode,
            "mode": self.mode,
            "mtime_ns": self.mtime_ns,
            "nlink": self.nlink,
            "size": self.size,
            "uid": self.uid,
        }


def _same_identity(left: os.stat_result | FileIdentity, right: os.stat_result | FileIdentity) -> bool:
    lhs = left if isinstance(left, FileIdentity) else FileIdentity.from_stat(left)
    rhs = right if isinstance(right, FileIdentity) else FileIdentity.from_stat(right)
    return lhs == rhs


_STABLE_DIRECTORY_IDENTITY_FIELDS = (
    "device",
    "inode",
    "uid",
    "gid",
    "mode",
    "nlink",
    "flags",
)

_DIRECTORY_WATCH_FFLAGS = (
    select.KQ_NOTE_DELETE
    | select.KQ_NOTE_RENAME
    | select.KQ_NOTE_REVOKE
)
_DIRECTORY_NAMESPACE_WATCH_FFLAGS = _DIRECTORY_WATCH_FFLAGS | select.KQ_NOTE_WRITE
_FILE_WATCH_FFLAGS = (
    _DIRECTORY_WATCH_FFLAGS
    | select.KQ_NOTE_WRITE
    | select.KQ_NOTE_EXTEND
    | select.KQ_NOTE_ATTRIB
)


def _same_directory_identity(
    left: os.stat_result | FileIdentity,
    right: os.stat_result | FileIdentity,
) -> bool:
    lhs = left if isinstance(left, FileIdentity) else FileIdentity.from_stat(left)
    rhs = right if isinstance(right, FileIdentity) else FileIdentity.from_stat(right)
    return all(
        getattr(lhs, field) == getattr(rhs, field)
        for field in _STABLE_DIRECTORY_IDENTITY_FIELDS
    )


def _register_directory_watch(
    watcher: Any,
    fd: int,
    label: str,
    *,
    namespace: bool = True,
) -> None:
    try:
        watcher.control(
            [
                select.kevent(
                    fd,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=(
                        _DIRECTORY_NAMESPACE_WATCH_FFLAGS
                        if namespace
                        else _DIRECTORY_WATCH_FFLAGS
                    ),
                )
            ],
            0,
            0,
        )
    except OSError as exc:
        raise CustodyError(f"{label} could not be registered for directory custody") from exc


def _retain_directory_identity_watch(watcher: Any, fd: int, label: str) -> None:
    _register_directory_watch(watcher, fd, label, namespace=False)


def _register_file_watch(watcher: Any, fd: int, label: str) -> None:
    try:
        watcher.control(
            [
                select.kevent(
                    fd,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=_FILE_WATCH_FFLAGS,
                )
            ],
            0,
            0,
        )
    except OSError as exc:
        raise CustodyError(f"{label} could not be registered for file custody") from exc


def _remove_file_watch(watcher: Any, fd: int) -> None:
    with contextlib.suppress(OSError):
        watcher.control(
            [
                select.kevent(
                    fd,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_DELETE,
                )
            ],
            0,
            0,
        )


def _reject_directory_watch_events(
    watcher: Any,
    label: str,
    *,
    initializing_fds: Iterable[int] = (),
) -> None:
    try:
        events = watcher.control(None, MAX_DIRECTORY_COUNT, 0)
    except OSError as exc:
        raise CustodyError(f"{label} directory custody could not be checked") from exc
    initializing = set(initializing_fds)
    for event in events:
        if int(event.ident) in initializing:
            continue
        if int(event.fflags) & _DIRECTORY_NAMESPACE_WATCH_FFLAGS:
            _fail(f"{label} detected ancestor namespace or identity change")


def _require_directory(info: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(info.st_mode):
        _fail(f"{label} is not a directory")
    if stat.S_IMODE(info.st_mode) & 0o6000:
        _fail(f"{label} has forbidden setuid or setgid mode bits")


def _require_one_link_regular(info: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(info.st_mode):
        _fail(f"{label} is not a regular file")
    if info.st_nlink != 1:
        _fail(f"{label} is not a one-link regular file")
    if stat.S_IMODE(info.st_mode) & 0o6000:
        _fail(f"{label} has forbidden setuid or setgid mode bits")


@dataclass
class _HeldAncestor:
    fd: int
    path: Path
    name: str | None
    parent_fd: int | None
    identity: FileIdentity


@dataclass
class _HeldDirectory:
    fd: int
    path: Path
    name: str | None
    parent_fd: int | None
    identity: FileIdentity
    ancestors: tuple[_HeldAncestor, ...] = ()
    owns_ancestors: bool = False
    watcher: Any | None = None


def _open_root(path: Path, label: str) -> _HeldDirectory:
    path = _canonical_system_alias(path)
    opened: list[_HeldAncestor] = []
    current_fd: int | None = None
    watcher: Any | None = None
    try:
        if not hasattr(select, "kqueue"):
            _fail("kqueue rename custody is required for DeviceCheck source authority")
        watcher = select.kqueue()
        root_before = os.lstat(path.anchor)
        _require_directory(root_before, f"{label} filesystem root")
        root_fd = os.open(path.anchor, _directory_flags())
        root_opened = os.fstat(root_fd)
        if not _same_identity(root_before, root_opened):
            os.close(root_fd)
            _fail(f"{label} filesystem root changed while it was opened")
        path_parts = path.parts[1:]
        _register_directory_watch(
            watcher,
            root_fd,
            f"{label} filesystem root",
            namespace=len(path_parts) > 2,
        )
        root_after = os.lstat(path.anchor)
        if not (
            _same_identity(root_before, root_after)
            and _same_identity(root_after, os.fstat(root_fd))
        ):
            os.close(root_fd)
            _fail(f"{label} filesystem root changed before custody was established")
        _reject_directory_watch_events(
            watcher,
            f"{label} filesystem root",
            initializing_fds=(root_fd,),
        )
        current_fd = root_fd
        current_path = Path(path.anchor)
        current_name: str | None = None
        current_parent_fd: int | None = None
        current_identity = FileIdentity.from_stat(root_opened)
        for part_index, part in enumerate(path_parts):
            _reject_directory_watch_events(watcher, f"{label} ancestor {current_path}")
            parent_fd = current_fd
            opened.append(
                _HeldAncestor(
                    parent_fd,
                    current_path,
                    current_name,
                    current_parent_fd,
                    current_identity,
                )
            )
            before = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
            _require_directory(before, f"{label} ancestor {current_path / part}")
            try:
                child_fd = os.open(part, _directory_flags(), dir_fd=parent_fd)
            except OSError as exc:
                raise CustodyError(
                    f"{label} ancestor could not be opened with O_NOFOLLOW: "
                    f"{current_path / part}"
                ) from exc
            current_fd = child_fd
            child_opened = os.fstat(child_fd)
            same_opened = (
                _same_identity
                if part_index >= len(path_parts) - 2
                else _same_directory_identity
            )
            if not same_opened(before, child_opened):
                _fail(f"{label} ancestor changed while it was opened: {current_path / part}")
            _register_directory_watch(
                watcher,
                child_fd,
                f"{label} ancestor {current_path / part}",
                namespace=part_index < len(path_parts) - 3,
            )
            _reject_directory_watch_events(
                watcher,
                f"{label} ancestor {current_path / part}",
                initializing_fds=(child_fd,),
            )
            child_after = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
            child_held = os.fstat(child_fd)
            if not (
                same_opened(before, child_after)
                and same_opened(child_after, child_held)
            ):
                _fail(
                    f"{label} ancestor changed before custody was established: "
                    f"{current_path / part}"
                )
            _retain_directory_identity_watch(
                watcher,
                parent_fd,
                f"{label} ancestor {current_path}",
            )
            current_parent_fd = parent_fd
            current_name = part
            current_path /= part
            current_identity = FileIdentity.from_stat(child_held)
        return _HeldDirectory(
            current_fd,
            path,
            current_name,
            current_parent_fd,
            current_identity,
            tuple(opened),
            True,
            watcher,
        )
    except BaseException:
        close_fds = [] if current_fd is None else [current_fd]
        close_fds.extend(item.fd for item in reversed(opened))
        for fd in dict.fromkeys(close_fds):
            with contextlib.suppress(OSError):
                os.close(fd)
        if watcher is not None:
            with contextlib.suppress(OSError):
                watcher.close()
        raise


def _open_directory_at(
    parent: _HeldDirectory,
    name: str,
    label: str,
    *,
    expected: FileIdentity | None = None,
) -> _HeldDirectory:
    if parent.watcher is None:
        _fail(f"{label} parent has no progressive directory custody")
    _reject_directory_watch_events(parent.watcher, f"{label} parent")
    try:
        before = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise CustodyError(f"{label} is missing: {name}") from exc
    _require_directory(before, label)
    if expected is not None and not _same_identity(before, expected):
        _fail(f"{label} changed after its directory inventory was captured")
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent.fd)
    except OSError as exc:
        raise CustodyError(f"{label} could not be opened with O_NOFOLLOW") from exc
    opened = os.fstat(fd)
    if not _same_directory_identity(before, opened):
        os.close(fd)
        _fail(f"{label} changed while its descriptor was opened")
    _register_directory_watch(parent.watcher, fd, label, namespace=False)
    _reject_directory_watch_events(
        parent.watcher,
        label,
        initializing_fds=(fd,),
    )
    after = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    held = os.fstat(fd)
    if not (
        _same_directory_identity(before, after)
        and _same_directory_identity(after, held)
    ):
        os.close(fd)
        _fail(f"{label} changed before progressive custody was established")
    _retain_directory_identity_watch(parent.watcher, parent.fd, f"{label} parent")
    return _HeldDirectory(
        fd,
        parent.path / name,
        name,
        parent.fd,
        FileIdentity.from_stat(held),
        watcher=parent.watcher,
    )


def _revalidate_directory_stack(stack: Sequence[_HeldDirectory], label: str) -> None:
    if stack:
        watcher = stack[0].watcher
        if watcher is not None:
            _reject_directory_watch_events(watcher, label)
        absolute_ancestors = stack[0].ancestors
        for index, current in enumerate(absolute_ancestors):
            if index == 0:
                latest = os.lstat(current.path)
            else:
                if current.parent_fd is None or current.name is None:
                    _fail(f"{label} has an invalid retained absolute ancestor")
                latest = os.stat(
                    current.name,
                    dir_fd=current.parent_fd,
                    follow_symlinks=False,
                )
            opened = os.fstat(current.fd)
            same_retained = (
                _same_identity
                if index == len(absolute_ancestors) - 1
                else _same_directory_identity
            )
            if not (
                same_retained(latest, opened)
                and same_retained(opened, current.identity)
            ):
                _fail(f"{label} absolute ancestor identity changed: {current.path}")
    for index, current in enumerate(stack):
        if index == 0 and current.parent_fd is None:
            latest = os.lstat(current.path)
        else:
            if current.parent_fd is None or current.name is None:
                _fail(f"{label} has an invalid retained ancestor")
            latest = os.stat(current.name, dir_fd=current.parent_fd, follow_symlinks=False)
        opened = os.fstat(current.fd)
        if not (_same_identity(latest, opened) and _same_identity(opened, current.identity)):
            _fail(f"{label} ancestor identity changed: {current.path}")


def _close_stack(stack: Sequence[_HeldDirectory]) -> None:
    if stack and stack[0].watcher is not None:
        with contextlib.suppress(OSError):
            stack[0].watcher.close()
    for item in reversed(stack):
        with contextlib.suppress(OSError):
            os.close(item.fd)
    if stack and stack[0].owns_ancestors:
        for item in reversed(stack[0].ancestors):
            with contextlib.suppress(OSError):
                os.close(item.fd)


def _read_file_at(
    parent: _HeldDirectory,
    name: str,
    label: str,
    *,
    expected: FileIdentity | None = None,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> tuple[FileIdentity, str, bytes]:
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str) or HEX64.fullmatch(expected_sha256) is None
    ):
        _fail(f"{label} authenticated SHA-256 is malformed")
    if expected_size is not None and (
        type(expected_size) is not int or expected_size < 0 or expected_size > MAX_FILE_BYTES
    ):
        _fail(f"{label} authenticated byte count is malformed")
    before = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        _fail(f"{label} is a symlink")
    _require_one_link_regular(before, label)
    if before.st_size > MAX_FILE_BYTES:
        _fail(f"{label} exceeds the per-file bound")
    if expected is not None and not _same_identity(before, expected):
        _fail(f"{label} identity does not match its authenticated manifest")
    try:
        fd = os.open(name, _file_flags(), dir_fd=parent.fd)
    except OSError as exc:
        raise CustodyError(f"{label} could not be opened with O_NOFOLLOW") from exc
    try:
        file_watch_registered = False
        opened = os.fstat(fd)
        _require_one_link_regular(opened, label)
        if not _same_identity(before, opened):
            _fail(f"{label} changed while its descriptor was opened")
        if parent.watcher is None:
            _fail(f"{label} parent has no progressive file custody")
        _register_file_watch(parent.watcher, fd, label)
        file_watch_registered = True
        _reject_directory_watch_events(parent.watcher, label)
        digest = hashlib.sha256()
        data = bytearray()
        while True:
            block = os.read(fd, READ_CHUNK)
            if not block:
                break
            data.extend(block)
            if len(data) > MAX_FILE_BYTES:
                _fail(f"{label} exceeds the per-file bound")
            digest.update(block)
        after = os.fstat(fd)
        path_after = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        _reject_directory_watch_events(parent.watcher, label)
        if not (_same_identity(opened, after) and _same_identity(after, path_after)):
            _fail(f"{label} changed while descriptor-held bytes were read")
        actual_sha256 = digest.hexdigest()
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            _fail(f"{label} bytes do not match their authenticated SHA-256")
        if expected_size is not None and len(data) != expected_size:
            _fail(f"{label} byte count does not match its authenticated authority")
        return FileIdentity.from_stat(after), actual_sha256, bytes(data)
    finally:
        if file_watch_registered and parent.watcher is not None:
            _remove_file_watch(parent.watcher, fd)
        os.close(fd)


@dataclass(frozen=True)
class _CapturedFile:
    path: str
    identity: FileIdentity
    sha256: str
    data: bytes

    def document(self) -> dict[str, Any]:
        header = f"blob {len(self.data)}\0".encode("ascii")
        return {
            "blob_sha1": hashlib.sha1(header + self.data).hexdigest(),
            "blob_sha256": hashlib.sha256(header + self.data).hexdigest(),
            "bytes": len(self.data),
            "identity": self.identity.document(),
            "path": self.path,
            "sha256": self.sha256,
        }


def _capture_tree(root: Path, virtual_root: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = _absolute(root)
    prefix = _relative_text(_relative_parts(virtual_root))
    held_root = _open_root(root, f"closure root {virtual_root}")
    files: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = [
        {"identity": held_root.identity.document(), "path": prefix}
    ]
    stack: list[_HeldDirectory] = [held_root]

    def visit(current: _HeldDirectory, relative: str) -> None:
        try:
            names = sorted(os.listdir(current.fd), key=os.fsencode)
        except OSError as exc:
            _fail(f"cannot enumerate closure directory: {current.path}: {exc}")
        inventory = {
            name: os.stat(name, dir_fd=current.fd, follow_symlinks=False)
            for name in names
        }
        for name in names:
            if not name or "/" in name or "\\" in name or name in {".", ".."}:
                _fail(f"unsafe directory entry: {current.path / name}")
            info = inventory[name]
            child_relative = f"{relative}/{name}"
            if name in EXCLUDED_DIRECTORY_NAMES and not virtual_root.startswith(
                "module-cache/"
            ):
                _fail(f"ignored or generated entry appeared in source closure: {child_relative}")
            if stat.S_ISLNK(info.st_mode):
                _fail(f"symlink in source closure: {child_relative}")
            if stat.S_ISDIR(info.st_mode):
                child = _open_directory_at(
                    current,
                    name,
                    f"closure directory {child_relative}",
                    expected=FileIdentity.from_stat(info),
                )
                stack.append(child)
                directories.append(
                    {"identity": child.identity.document(), "path": child_relative}
                )
                try:
                    visit(child, child_relative)
                    _revalidate_directory_stack(stack, f"closure {child_relative}")
                finally:
                    stack.pop()
                    os.close(child.fd)
                continue
            if stat.S_ISREG(info.st_mode):
                identity, digest, data = _read_file_at(
                    current,
                    name,
                    f"closure file {child_relative}",
                    expected=FileIdentity.from_stat(info),
                )
                _reject_secret_material(child_relative, data)
                files.append(_CapturedFile(child_relative, identity, digest, data).document())
                _revalidate_directory_stack(stack, f"closure file {child_relative}")
                continue
            _fail(f"special file in source closure: {child_relative}")

    try:
        visit(held_root, prefix)
        _revalidate_directory_stack(stack, f"closure root {virtual_root}")
    finally:
        _close_stack(stack)
    return files, directories


def _inventory_git_metadata_file(
    parent: _HeldDirectory,
    name: str,
    label: str,
    *,
    expected: FileIdentity | None = None,
) -> dict[str, Any]:
    before = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        _fail(f"{label} is a symlink")
    _require_one_link_regular(before, label)
    if expected is not None and not _same_identity(before, expected):
        _fail(f"{label} changed after its directory inventory was captured")
    if before.st_size > MAX_GIT_METADATA_FILE_BYTES:
        _fail(f"{label} exceeds the Git metadata per-file bound")
    try:
        fd = os.open(name, _file_flags(), dir_fd=parent.fd)
    except OSError as exc:
        raise CustodyError(f"{label} could not be opened with O_NOFOLLOW") from exc
    try:
        file_watch_registered = False
        opened = os.fstat(fd)
        _require_one_link_regular(opened, label)
        if not _same_identity(before, opened):
            _fail(f"{label} changed while its descriptor was opened")
        if parent.watcher is None:
            _fail(f"{label} parent has no progressive file custody")
        _register_file_watch(parent.watcher, fd, label)
        file_watch_registered = True
        _reject_directory_watch_events(parent.watcher, label)
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(fd, READ_CHUNK)
            if not block:
                break
            size += len(block)
            if size > MAX_GIT_METADATA_FILE_BYTES:
                _fail(f"{label} exceeds the Git metadata per-file bound")
            digest.update(block)
        after = os.fstat(fd)
        path_after = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        _reject_directory_watch_events(parent.watcher, label)
        if not (_same_identity(opened, after) and _same_identity(after, path_after)):
            _fail(f"{label} changed while descriptor-held bytes were hashed")
        if size != after.st_size:
            _fail(f"{label} size changed while descriptor-held bytes were hashed")
        return {
            "bytes": size,
            "identity": FileIdentity.from_stat(after).document(),
            "sha256": digest.hexdigest(),
        }
    finally:
        if file_watch_registered and parent.watcher is not None:
            _remove_file_watch(parent.watcher, fd)
        os.close(fd)


def _capture_git_metadata_tree(
    root: Path,
    virtual_root: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = _absolute(root)
    prefix = _relative_text(_relative_parts(virtual_root))
    held_root = _open_root(root, f"Git metadata root {virtual_root}")
    files: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = [
        {"identity": held_root.identity.document(), "path": prefix}
    ]
    stack: list[_HeldDirectory] = [held_root]
    total_bytes = 0

    def visit(current: _HeldDirectory, relative: str) -> None:
        nonlocal total_bytes
        try:
            names = sorted(os.listdir(current.fd), key=os.fsencode)
        except OSError as exc:
            _fail(f"cannot enumerate Git metadata directory: {current.path}: {exc}")
        inventory = {
            name: os.stat(name, dir_fd=current.fd, follow_symlinks=False)
            for name in names
        }
        for name in names:
            if not name or "/" in name or "\\" in name or name in {".", ".."}:
                _fail(f"unsafe Git metadata directory entry: {current.path / name}")
            info = inventory[name]
            child_relative = f"{relative}/{name}"
            if stat.S_ISLNK(info.st_mode):
                _fail(f"symlink in reviewed Git metadata: {child_relative}")
            if stat.S_ISDIR(info.st_mode):
                if len(directories) >= MAX_DIRECTORY_COUNT:
                    _fail("reviewed Git metadata exceeds its directory count bound")
                child = _open_directory_at(
                    current,
                    name,
                    f"Git metadata directory {child_relative}",
                    expected=FileIdentity.from_stat(info),
                )
                stack.append(child)
                directories.append(
                    {"identity": child.identity.document(), "path": child_relative}
                )
                try:
                    visit(child, child_relative)
                    _revalidate_directory_stack(stack, f"Git metadata {child_relative}")
                finally:
                    stack.pop()
                    os.close(child.fd)
                continue
            if stat.S_ISREG(info.st_mode):
                if len(files) >= MAX_FILE_COUNT:
                    _fail("reviewed Git metadata exceeds its file count bound")
                record = _inventory_git_metadata_file(
                    current,
                    name,
                    f"Git metadata file {child_relative}",
                    expected=FileIdentity.from_stat(info),
                )
                total_bytes += int(record["bytes"])
                if total_bytes > MAX_GIT_METADATA_TOTAL_BYTES:
                    _fail("reviewed Git metadata exceeds its aggregate byte bound")
                files.append({"path": child_relative, **record})
                _revalidate_directory_stack(stack, f"Git metadata file {child_relative}")
                continue
            _fail(f"special file in reviewed Git metadata: {child_relative}")

    try:
        visit(held_root, prefix)
        _revalidate_directory_stack(stack, f"Git metadata root {virtual_root}")
    finally:
        _close_stack(stack)
    return files, directories


def _open_relative_chain(root: Path, relative: str, label: str) -> tuple[list[_HeldDirectory], str]:
    parts = _relative_parts(relative)
    stack = [_open_root(_absolute(root), f"{label} root")]
    try:
        current = stack[0]
        for name in parts[:-1]:
            current = _open_directory_at(current, name, f"{label} ancestor {name}")
            stack.append(current)
        return stack, parts[-1]
    except BaseException:
        _close_stack(stack)
        raise


def _capture_file_with_directories(
    root: Path,
    relative: str,
    virtual: str,
    *,
    expected: FileIdentity | None = None,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> tuple[_CapturedFile, list[dict[str, Any]]]:
    stack, leaf = _open_relative_chain(root, relative, f"closure file {relative}")
    try:
        acquired = FileIdentity.from_stat(
            os.stat(leaf, dir_fd=stack[-1].fd, follow_symlinks=False)
        )
        if expected is not None and not _same_identity(acquired, expected):
            _fail(f"closure file {relative} identity changed before acquisition")
        identity, digest, data = _read_file_at(
            stack[-1],
            leaf,
            f"closure file {relative}",
            expected=acquired,
            expected_sha256=expected_sha256,
            expected_size=expected_size,
        )
        _revalidate_directory_stack(stack, f"closure file {relative}")
        source_parts = _relative_parts(relative)
        virtual_parts = _relative_parts(virtual)
        if len(virtual_parts) < len(source_parts) or tuple(virtual_parts[-len(source_parts):]) != source_parts:
            _fail(f"source and virtual paths do not share a safe suffix: {virtual}")
        prefix = virtual_parts[:-len(source_parts)]
        directories: list[dict[str, Any]] = []
        for index, directory in enumerate(stack):
            directory_parts = prefix + source_parts[:index]
            if not directory_parts:
                continue
            directories.append(
                {
                    "identity": directory.identity.document(),
                    "path": _relative_text(directory_parts),
                }
            )
        return _CapturedFile(virtual, identity, digest, data), directories
    finally:
        _close_stack(stack)


def capture_file(
    root: Path,
    relative: str,
    *,
    expected: FileIdentity | None = None,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> _CapturedFile:
    if expected is None and expected_sha256 is None:
        _fail("descriptor capture requires an authenticated identity or SHA-256")
    captured, _directories = _capture_file_with_directories(
        root,
        relative,
        relative,
        expected=expected,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
    )
    return captured


def _read_small_repo_file(repo: Path, relative: str) -> bytes:
    captured, _directories = _capture_file_with_directories(repo, relative, relative)
    if len(captured.data) > MAX_FILE_BYTES:
        _fail(f"control input is too large: {relative}")
    return captured.data


def _credential_name(path: str) -> bool:
    lowered = path.lower()
    basename = lowered.rsplit("/", 1)[-1]
    if basename in {".env", "credentials.json", "secrets.json", "keystore.jks"}:
        return True
    if basename.startswith(".env."):
        return True
    return basename in {"id_rsa", "id_ed25519"} or basename.endswith(
        (".p12", ".pfx", ".jks", ".keystore")
    )


def _reject_secret_material(path: str, data: bytes) -> None:
    if _credential_name(path):
        _fail(f"credential-like source material rejected: {path}")
    # Do not scan arbitrary executable or archive bytes for English marker
    # strings.  Binary build inputs such as the shipping AAR and native .so
    # files can contain those byte sequences coincidentally.
    if b"\x00" in data[:4096]:
        return
    upper = data.upper()
    if b"-----BEGIN" in upper and b"PRIVATE KEY-----" in upper:
        _fail(f"private-key source material rejected: {path}")


def _escape_module_path(module: str) -> str:
    result: list[str] = []
    for char in module:
        if char == "!":
            result.append("!!")
        elif "A" <= char <= "Z":
            result.extend(("!", char.lower()))
        else:
            result.append(char)
    return "".join(result)


def _module_versions(repo: Path) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    source_found: set[tuple[str, str]] = set()
    all_found: set[tuple[str, str]] = set()
    for relative in GO_SUM_FILES:
        data = _read_small_repo_file(repo, relative)
        for raw_line in data.decode("utf-8").splitlines():
            fields = raw_line.split()
            if len(fields) < 2 or fields[0].startswith("//"):
                continue
            module = fields[0]
            version = fields[1]
            source_row = not version.endswith("/go.mod")
            if not source_row:
                version = version[:-7]
            if module.startswith("winsvpn.local/"):
                continue
            if not module or not version.startswith("v"):
                _fail(f"invalid Go module checksum row in {relative}")
            all_found.add((module, version))
            if source_row:
                source_found.add((module, version))
    return tuple(sorted(source_found)), tuple(sorted(all_found))


def _gomodcache_root() -> Path:
    try:
        output = subprocess.check_output(
            ["go", "env", "GOMODCACHE"],
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        ).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise CustodyError("Go GOMODCACHE could not be discovered without network access") from exc
    if not output:
        _fail("Go GOMODCACHE is empty")
    return _absolute(Path(output))


def _module_cache_inputs(
    module_cache: Path,
    source_modules: Iterable[tuple[str, str]],
    all_modules: Iterable[tuple[str, str]],
) -> tuple[tuple[Path, str], ...]:
    module_cache = _absolute(module_cache)
    _reject_symlink_components(module_cache)
    paths: list[tuple[Path, str]] = []
    source_set = set(source_modules)
    for module, version in all_modules:
        escaped = _escape_module_path(module)
        download = module_cache / "cache" / "download" / escaped / "@v"
        suffixes = ("mod", "info", "zip", "ziphash")
        if (module, version) in source_set:
            source = module_cache / f"{escaped}@{version}"
            if not source.is_dir() or source.is_symlink():
                _fail(f"required Go module source is missing or substituted: {source}")
            paths.append((source, f"module-cache/{escaped}@{version}"))
        for suffix in suffixes:
            candidate = download / f"{version}.{suffix}"
            if candidate.is_symlink():
                _fail(f"required Go module cache metadata is missing or substituted: {candidate}")
            if candidate.is_file():
                paths.append((candidate, f"module-cache/cache/download/{escaped}/@v/{version}.{suffix}"))
            elif suffix == "mod":
                _fail(f"required Go module cache metadata is missing: {candidate}")
    return tuple(paths)


def closure_paths(repo: Path, *, module_cache: Path | None = None) -> tuple[tuple[Path, str], ...]:
    """Return the intended source and cache roots for external producer integration."""
    repo = _absolute(repo)
    opened_repo = _open_root(repo, "source repository")
    _close_stack([opened_repo])
    result: list[tuple[Path, str]] = []
    explicit = list(
        DEVICECHECK_CONTROL_FILES
        + ANDROID_CONTROL_FILES
        + DEVICECHECK_EXPLICIT_SOURCE_FILES
    )
    for name in SHIPPING_APP_SOURCE_FILES:
        explicit.append(f"android/app/src/main/kotlin/org/winsvpn/app/{name}")
    for relative in sorted(set(explicit)):
        if _credential_name(relative):
            _fail(f"credential-like closure input rejected: {relative}")
        result.append((repo / Path(*_relative_parts(relative)), relative))
    for relative in DEVICECHECK_TREE_ROOTS:
        path = repo / Path(*_relative_parts(relative))
        result.append((path, relative))
    if module_cache is None:
        module_cache = _gomodcache_root()
    source_modules, all_modules = _module_versions(repo)
    result.extend(_module_cache_inputs(module_cache, source_modules, all_modules))
    paths = [relative for _path, relative in result]
    if len(paths) != len(set(paths)):
        _fail("source closure contains duplicate virtual paths")
    return tuple(sorted(result, key=lambda item: item[1].encode("utf-8")))


def _capture_path(
    path: Path,
    virtual: str,
    allowed_roots: Sequence[Path],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if path.is_dir() and not path.is_symlink():
        return _capture_tree(path, virtual)
    if path.is_symlink():
        _fail(f"source closure path is a symlink: {virtual}")
    for root in allowed_roots:
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            continue
        captured, directories = _capture_file_with_directories(root, relative, virtual)
        return [captured.document()], directories
    _fail(f"source closure input is outside the allowed source tree: {virtual}")


def _capture_closure(
    repo: Path,
    inputs: Sequence[tuple[Path, str]],
    *,
    allowed_roots: Sequence[Path] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    files: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []
    roots = tuple(allowed_roots or (repo,))
    for path, virtual in inputs:
        if not path.exists() and not path.is_symlink():
            _fail(f"source closure input is missing: {virtual}")
        captured_files, captured_directories = _capture_path(path, virtual, roots)
        files.extend(captured_files)
        directories.extend(captured_directories)
    files.sort(key=lambda item: item["path"].encode("utf-8"))
    merged_directories: dict[str, dict[str, Any]] = {}
    for directory in directories:
        previous = merged_directories.get(directory["path"])
        if previous is not None and previous != directory:
            _fail(f"source closure ancestor identity changed: {directory['path']}")
        merged_directories[directory["path"]] = directory
    directories = list(merged_directories.values())
    directories.sort(key=lambda item: item["path"].encode("utf-8"))
    if len(files) > MAX_FILE_COUNT or len(directories) > MAX_DIRECTORY_COUNT:
        _fail("source closure exceeds its count bound")
    total = sum(int(item["bytes"]) for item in files)
    if total > MAX_TOTAL_BYTES:
        _fail("source closure exceeds its aggregate byte bound")
    if [item["path"] for item in files] != sorted({item["path"] for item in files}, key=lambda item: item.encode("utf-8")):
        _fail("source closure file paths are not unique and sorted")
    if [item["path"] for item in directories] != sorted({item["path"] for item in directories}, key=lambda item: item.encode("utf-8")):
        _fail("source closure directory paths are not unique and sorted")
    return files, directories


def _feed(digest: "hashlib._Hash", *parts: object) -> None:
    for part in parts:
        raw = str(part).encode("utf-8", "surrogateescape")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)


def closure_digest(files: Sequence[dict[str, Any]], directories: Sequence[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for directory in directories:
        _feed(digest, "D", directory["path"])
    for item in files:
        _feed(
            digest,
            "F",
            item["path"],
            item["bytes"],
            item["blob_sha1"],
            item["blob_sha256"],
            item["sha256"],
        )
    return digest.hexdigest()


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, 15)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, 9)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1)


def _git_executable_is_os_custodied() -> None:
    held = _open_root(GIT_EXECUTABLE.parent, "reviewed Git executable parent")
    try:
        for item in (*held.ancestors, held):
            if item.identity.uid != 0 or item.identity.mode & 0o022:
                _fail("reviewed Git executable ancestor is writable or not root-owned")
        before = os.stat(GIT_EXECUTABLE.name, dir_fd=held.fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0:
            _fail("reviewed Git executable is not a root-owned regular file")
        mode = stat.S_IMODE(before.st_mode)
        if mode & 0o022 or not mode & 0o111:
            _fail("reviewed Git executable is writable or not executable")
        fd = os.open(GIT_EXECUTABLE.name, _file_flags(), dir_fd=held.fd)
        try:
            opened = os.fstat(fd)
            after = os.stat(
                GIT_EXECUTABLE.name,
                dir_fd=held.fd,
                follow_symlinks=False,
            )
            if not (_same_identity(before, opened) and _same_identity(opened, after)):
                _fail("reviewed Git executable changed while it was authenticated")
        finally:
            os.close(fd)
        _revalidate_directory_stack([held], "reviewed Git executable parent")
    finally:
        _close_stack([held])


def _git_command(repo: Path, *args: str) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    try:
        process = subprocess.Popen(
            [str(GIT_EXECUTABLE), *args],
            cwd=str(repo),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise CustodyError(f"Git source binding failed to start: {' '.join(args)}") from exc
    if process.stdout is None or process.stderr is None:
        _terminate_process_group(process)
        _fail("Git source binding did not create bounded output pipes")
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    streams = {stdout_fd: (process.stdout, MAX_GIT_STDOUT_BYTES), stderr_fd: (process.stderr, MAX_GIT_STDERR_BYTES)}
    outputs = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    selector = selectors.DefaultSelector()
    for descriptor, (stream, _limit) in streams.items():
        os.set_blocking(descriptor, False)
        selector.register(stream, selectors.EVENT_READ, descriptor)
    deadline = time.monotonic() + 15.0
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_group(process)
                _fail("Git source binding exceeded its deadline")
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _mask in events:
                descriptor = key.data
                try:
                    block = os.read(descriptor, READ_CHUNK)
                except BlockingIOError:
                    continue
                if not block:
                    with contextlib.suppress(Exception):
                        selector.unregister(key.fileobj)
                    continue
                output = outputs[descriptor]
                output.extend(block)
                if len(output) > streams[descriptor][1]:
                    _terminate_process_group(process)
                    _fail("Git source binding output exceeded its bound")
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except (OSError, subprocess.SubprocessError) as exc:
        _terminate_process_group(process)
        raise CustodyError(f"Git source binding failed: {' '.join(args)}") from exc
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    stderr = bytes(outputs[stderr_fd])
    if return_code != 0:
        detail = stderr.decode("utf-8", "replace").strip()[:512]
        _fail(f"Git source binding failed: {' '.join(args)}: {detail}")
    return bytes(outputs[stdout_fd])


def _parse_git_tree(raw: bytes, object_length: int) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            path = encoded_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise CustodyError("reviewed Git tree output is malformed") from exc
        _relative_parts(path)
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            _fail(f"unsupported reviewed Git entry: {path}")
        if len(object_id) != object_length or re.fullmatch(r"[0-9a-f]+", object_id) is None:
            _fail(f"reviewed Git object id is malformed: {path}")
        if path in result:
            _fail(f"duplicate reviewed Git path: {path}")
        result[path] = {"mode": mode, "object": object_id, "path": path}
    return result


def reviewed_git_binding(
    repo: Path,
    reviewed_commit: str,
    *,
    required_paths: Iterable[str] | None = None,
) -> dict[str, Any]:
    if not COMMIT.fullmatch(reviewed_commit):
        _fail("reviewed commit must be a full hexadecimal Git object id")
    repo = _absolute(repo)
    _git_executable_is_os_custodied()
    held_repo = _open_root(repo, "reviewed Git repository")
    held_git = _open_directory_at(held_repo, ".git", "reviewed Git metadata")
    stack = [held_repo, held_git]
    try:
        before_files, before_dirs = _capture_git_metadata_tree(
            repo / ".git",
            "git-metadata",
        )
        forbidden_git_redirects = {
            "git-metadata/commondir",
            "git-metadata/info/grafts",
            "git-metadata/objects/info/alternates",
        }
        present_git_paths = {item["path"] for item in before_files}
        redirected = sorted(present_git_paths & forbidden_git_redirects, key=os.fsencode)
        if redirected:
            _fail(f"reviewed Git metadata redirects outside its held object store: {redirected[0]}")

        def run(*args: str) -> bytes:
            output = _git_command(repo, *args)
            _revalidate_directory_stack(stack, "reviewed Git transaction")
            return output

        common_dir = run("rev-parse", "--git-common-dir").decode("ascii").strip()
        held_git_path = os.stat(".git", dir_fd=held_repo.fd, follow_symlinks=False)
        if common_dir != ".git" or not _same_identity(held_git_path, held_git.identity):
            _fail("reviewed Git common directory escapes its retained metadata custody")

        actual = run("rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
        if actual != reviewed_commit:
            _fail(f"reviewed commit mismatch: expected {reviewed_commit}, got {actual}")
        tree = run("rev-parse", "--verify", f"{reviewed_commit}^{{tree}}").decode("ascii").strip()
        if len(tree) != len(reviewed_commit) or re.fullmatch(r"[0-9a-f]+", tree) is None:
            _fail("reviewed Git tree id is invalid")
        inventory = _parse_git_tree(
            run("ls-tree", "-rz", "--full-tree", reviewed_commit),
            len(reviewed_commit),
        )
        wanted = set(inventory) if required_paths is None else set(required_paths)
        if any(path == "module-cache" or path.startswith("module-cache/") for path in wanted):
            _fail("module-cache paths cannot be represented as reviewed Git files")
        missing = sorted(wanted - set(inventory), key=os.fsencode)
        if missing:
            _fail(f"source closure contains untracked or ignored input: {missing[0]}")
        selected = [inventory[path] for path in sorted(wanted, key=os.fsencode)]
        after_files, after_dirs = _capture_git_metadata_tree(
            repo / ".git",
            "git-metadata",
        )
        if before_files != after_files or before_dirs != after_dirs:
            _fail("reviewed Git metadata changed during source binding")
        _revalidate_directory_stack(stack, "reviewed Git transaction")
        return {"commit": actual, "files": selected, "tree": tree}
    finally:
        _close_stack(stack)


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def parse_manifest(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_MANIFEST_BYTES:
        _fail("source custody manifest exceeds its size bound")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: _fail(
                f"non-finite JSON value rejected: {value}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CustodyError("source custody manifest is not strict JSON") from exc
    if not isinstance(value, dict):
        _fail("source custody manifest must be an object")
    return value


def _snapshot_relative_for_digest(digest: str) -> str:
    if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
        _fail("source snapshot content address is malformed")
    return f"{SNAPSHOT_BASE_RELATIVE}/{digest}"


def _manifest_path_for_digest(digest: str) -> Path:
    if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
        _fail("source manifest content address is malformed")
    return AUTHORITY_ROOT / MANIFEST_BASE_RELATIVE / f"{digest}.json"


def _identity_from_document(value: Any, label: str) -> FileIdentity:
    if not isinstance(value, dict):
        _fail(f"{label} identity is not an object")
    expected = {"ctime_ns", "device", "flags", "gid", "inode", "mode", "mtime_ns", "nlink", "size", "uid"}
    if set(value) != expected or any(type(item) is not int for item in value.values()):
        _fail(f"{label} identity is malformed")
    return FileIdentity(**{key: value[key] for key in expected})


def validate_manifest(document: dict[str, Any]) -> dict[str, Any]:
    required = {"authority", "closure", "contract", "reviewed", "schema_version"}
    if set(document) != required:
        _fail("source custody manifest has unexpected or missing top-level fields")
    if document["contract"] != CONTRACT or document["schema_version"] != SCHEMA_VERSION:
        _fail("source custody manifest contract mismatch")
    authority = document["authority"]
    if not isinstance(authority, dict) or set(authority) != {"root", "snapshot"}:
        _fail("source custody authority fields are invalid")
    if authority["root"] != str(AUTHORITY_ROOT):
        _fail("source custody authority is not the fixed /Library/WinsVPN authority")
    reviewed = document["reviewed"]
    if not isinstance(reviewed, dict) or set(reviewed) != {"commit", "files", "tree"}:
        _fail("reviewed Git binding is malformed")
    if (
        not isinstance(reviewed.get("commit"), str)
        or not isinstance(reviewed.get("tree"), str)
        or not COMMIT.fullmatch(reviewed["commit"])
        or not re.fullmatch(r"[0-9a-f]{40,64}", reviewed["tree"])
    ):
        _fail("reviewed Git binding has invalid object ids")
    git_files = reviewed["files"]
    if not isinstance(git_files, list):
        _fail("reviewed Git file inventory is malformed")
    git_by_path: dict[str, dict[str, str]] = {}
    for item in git_files:
        if not isinstance(item, dict) or set(item) != {"mode", "object", "path"}:
            _fail("reviewed Git file record is malformed")
        path = item["path"]
        if not isinstance(path, str) or path in git_by_path:
            _fail("reviewed Git file path is unsafe or duplicated")
        _relative_parts(path)
        if item["mode"] not in {"100644", "100755"}:
            _fail(f"reviewed Git file mode is unsupported: {path}")
        if (
            not isinstance(item["object"], str)
            or len(item["object"]) != len(reviewed["commit"])
            or re.fullmatch(r"[0-9a-f]+", item["object"]) is None
        ):
            _fail(f"reviewed Git file object is malformed: {path}")
        git_by_path[path] = item
    if [item["path"] for item in git_files] != sorted(git_by_path, key=os.fsencode):
        _fail("reviewed Git file inventory is not canonically ordered")
    closure = document["closure"]
    if not isinstance(closure, dict) or set(closure) != {"directories", "files", "sha256", "total_bytes"}:
        _fail("source closure document is malformed")
    files = closure["files"]
    directories = closure["directories"]
    if not isinstance(files, list) or not isinstance(directories, list):
        _fail("source closure inventories must be lists")
    if len(files) > MAX_FILE_COUNT or len(directories) > MAX_DIRECTORY_COUNT:
        _fail("source closure inventory exceeds its count bound")
    seen_files: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "blob_sha1",
            "blob_sha256",
            "bytes",
            "identity",
            "path",
            "sha256",
        }:
            _fail("source closure file record is malformed")
        path = item["path"]
        if not isinstance(path, str) or path in seen_files or _relative_parts(path) != tuple(Path(path).parts):
            _fail("source closure file paths are unsafe or duplicated")
        if _credential_name(path):
            _fail(f"credential-like source material rejected: {path}")
        seen_files.add(path)
        if type(item["bytes"]) is not int or item["bytes"] < 0 or item["bytes"] > MAX_FILE_BYTES:
            _fail(f"source closure file size is outside bounds: {path}")
        if not isinstance(item["sha256"], str) or not HEX64.fullmatch(item["sha256"]):
            _fail(f"source closure file digest is malformed: {path}")
        if (
            not isinstance(item["blob_sha1"], str)
            or re.fullmatch(r"[0-9a-f]{40}", item["blob_sha1"]) is None
            or not isinstance(item["blob_sha256"], str)
            or HEX64.fullmatch(item["blob_sha256"]) is None
        ):
            _fail(f"source closure Git blob digest is malformed: {path}")
        identity = _identity_from_document(item["identity"], f"source closure file {path}")
        if path.startswith("module-cache/"):
            if path in git_by_path:
                _fail(f"module-cache input cannot claim reviewed Git identity: {path}")
        else:
            git_item = git_by_path.get(path)
            if git_item is None:
                _fail(f"source closure input is not bound to a reviewed Git blob: {path}")
            expected_mode = 0o755 if git_item["mode"] == "100755" else 0o644
            if identity.mode != expected_mode:
                _fail(f"source mode differs from reviewed Git mode: {path}")
            blob_key = "blob_sha1" if len(git_item["object"]) == 40 else "blob_sha256"
            if item[blob_key] != git_item["object"]:
                _fail(f"source bytes differ from reviewed Git blob: {path}")
    seen_dirs: set[str] = set()
    for item in directories:
        if not isinstance(item, dict) or set(item) != {"identity", "path"}:
            _fail("source closure directory record is malformed")
        path = item["path"]
        if not isinstance(path, str) or path in seen_dirs:
            _fail("source closure directory paths are unsafe or duplicated")
        _relative_parts(path)
        seen_dirs.add(path)
        _identity_from_document(item["identity"], f"source closure directory {path}")
    if [item["path"] for item in files] != sorted(seen_files, key=lambda item: item.encode("utf-8")):
        _fail("source closure file inventory is not canonically ordered")
    if [item["path"] for item in directories] != sorted(seen_dirs, key=lambda item: item.encode("utf-8")):
        _fail("source closure directory inventory is not canonically ordered")
    if type(closure.get("total_bytes")) is not int:
        _fail("source closure total byte count is invalid")
    total = sum(item["bytes"] for item in files)
    if total != closure["total_bytes"] or total > MAX_TOTAL_BYTES:
        _fail("source closure total byte count is invalid")
    if (
        not isinstance(closure.get("sha256"), str)
        or not HEX64.fullmatch(closure["sha256"])
        or closure["sha256"] != closure_digest(files, directories)
    ):
        _fail("source closure content address is invalid")
    if authority["snapshot"] != _snapshot_relative_for_digest(closure["sha256"]):
        _fail("source snapshot is not the exact content-addressed closure path")
    expected_git_paths = {path for path in seen_files if not path.startswith("module-cache/")}
    if set(git_by_path) != expected_git_paths:
        _fail("reviewed Git inventory does not exactly match repository source inputs")
    return document


def build_manifest(
    repo: Path,
    reviewed_commit: str,
    *,
    module_cache: Path | None = None,
) -> dict[str, Any]:
    """Capture the fixed production closure and return its manifest document."""
    repo = _absolute(repo)
    resolved_module_cache = (
        _absolute(module_cache) if module_cache is not None else _gomodcache_root()
    )
    configured = closure_paths(repo, module_cache=resolved_module_cache)
    roots = (repo, resolved_module_cache)
    first_files, first_dirs = _capture_closure(repo, configured, allowed_roots=roots)
    repository_paths = [
        item["path"] for item in first_files if not item["path"].startswith("module-cache/")
    ]
    git_binding = reviewed_git_binding(
        repo,
        reviewed_commit,
        required_paths=repository_paths,
    )
    second_files, second_dirs = _capture_closure(repo, configured, allowed_roots=roots)
    if first_files != second_files or first_dirs != second_dirs:
        _fail("source closure changed between authenticated passes")
    if reviewed_git_binding(
        repo,
        reviewed_commit,
        required_paths=repository_paths,
    ) != git_binding:
        _fail("reviewed Git source binding changed during closure capture")
    content_address = closure_digest(first_files, first_dirs)
    document = {
        "authority": {
            "root": str(AUTHORITY_ROOT),
            "snapshot": _snapshot_relative_for_digest(content_address),
        },
        "closure": {
            "directories": first_dirs,
            "files": first_files,
            "sha256": content_address,
            "total_bytes": sum(item["bytes"] for item in first_files),
        },
        "contract": CONTRACT,
        "reviewed": git_binding,
        "schema_version": SCHEMA_VERSION,
    }
    return validate_manifest(document)


def manifest_bytes(document: dict[str, Any]) -> bytes:
    return _canonical_bytes(validate_manifest(document))


def manifest_sha256(document: dict[str, Any]) -> str:
    return hashlib.sha256(manifest_bytes(document)).hexdigest()


def _authority_file_record(
    value: Any,
    label: str,
    expected_path: Path | None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size_bytes"}:
        _fail(f"{label} authority record is malformed")
    if expected_path is not None and value["path"] != str(expected_path):
        _fail(f"{label} authority path is not the fixed reviewed path")
    if not isinstance(value["sha256"], str) or HEX64.fullmatch(value["sha256"]) is None:
        _fail(f"{label} authority digest is malformed")
    if type(value["size_bytes"]) is not int or not 0 < value["size_bytes"] <= MAX_FILE_BYTES:
        _fail(f"{label} authority size is outside its bound")
    return value


def _certificate_der_sha256(raw: bytes, label: str) -> str:
    try:
        text = raw.decode("ascii")
        der = ssl.PEM_cert_to_DER_cert(text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise CustodyError(f"{label} is not one PEM X.509 certificate") from exc
    return hashlib.sha256(der).hexdigest()


def validate_owner_authority(document: dict[str, Any]) -> dict[str, Any]:
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
    if set(document) != required:
        _fail("DeviceCheck owner authority fields are invalid")
    if (
        document["schema_version"] != 4
        or document["contract"] != OWNER_AUTHORITY_CONTRACT
        or document["secret_material_redacted"] is not True
    ):
        _fail("DeviceCheck owner authority contract is invalid")
    _authority_file_record(document["release_python"], "ReleasePython", RELEASE_PYTHON_PATH)
    _authority_file_record(document["loader"], "loader", LOADER_PATH)
    _authority_file_record(document["controller"], "controller", CONTROLLER_PATH)
    manifest_record = _authority_file_record(
        document["source_manifest"],
        "source manifest",
        None,
    )
    if Path(manifest_record["path"]) != _manifest_path_for_digest(
        manifest_record["sha256"]
    ):
        _fail("source manifest is not at its exact content-addressed path")
    _authority_file_record(
        document["owner_signer_certificate"],
        "owner signer certificate",
        OWNER_SIGNER_CERTIFICATE_PATH,
    )
    snapshot = document["source_snapshot"]
    if (
        not isinstance(snapshot, dict)
        or set(snapshot) != {"path", "closure_sha256"}
        or not isinstance(snapshot["closure_sha256"], str)
        or HEX64.fullmatch(snapshot["closure_sha256"]) is None
    ):
        _fail("source snapshot authority record is malformed")
    expected_snapshot = AUTHORITY_ROOT / _snapshot_relative_for_digest(
        snapshot["closure_sha256"]
    )
    if Path(snapshot["path"]) != expected_snapshot:
        _fail("source snapshot is not at its exact content-addressed path")
    build = document["build"]
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
        _fail("private DeviceCheck build-user/workspace authority is malformed")
    authorization = document["authorization"]
    if (
        not isinstance(authorization, dict)
        or set(authorization) != {"authorization_id", "nonce", "sequence"}
        or not isinstance(authorization["authorization_id"], str)
        or HEX64.fullmatch(authorization["authorization_id"]) is None
        or not isinstance(authorization["nonce"], str)
        or HEX64.fullmatch(authorization["nonce"]) is None
        or authorization["nonce"] in {"0" * 64, hashlib.sha256(b"").hexdigest()}
        or type(authorization["sequence"]) is not int
        or authorization["sequence"] <= 0
    ):
        _fail("DeviceCheck owner authorization identity is malformed")
    consumer = document["consumer"]
    if consumer != {
        "contract": BUILD_HANDOFF_CONTRACT,
        "status": CONSUMER_STATUS,
    }:
        _fail("DeviceCheck external consumer integration state is invalid")
    signer = document["owner_signer_sha256"]
    if (
        not isinstance(signer, str)
        or HEX64.fullmatch(signer) is None
        or signer in {"0" * 64, hashlib.sha256(b"").hexdigest()}
    ):
        _fail("OWNER-BLOCKED: reviewed DeviceCheck owner signer identity is absent")
    return document


def _read_fixed_authority_file(
    path: Path,
    label: str,
    expected: dict[str, Any],
    *,
    expected_mode: int,
    require_owner_custody: bool,
) -> bytes:
    _reject_symlink_components(path.parent)
    captured = capture_file(
        path.parent,
        path.name,
        expected_sha256=expected["sha256"],
        expected_size=expected["size_bytes"],
    )
    if captured.identity.mode != expected_mode:
        _fail(f"{label} does not have exact data-only/executable mode {expected_mode:04o}")
    if require_owner_custody:
        _require_sealed_identity(captured.identity, label)
        _require_sealed_ancestor(path.parent)
    return captured.data


def _load_owner_authority_at(
    path: Path,
    expected_sha256: str,
    *,
    require_owner_custody: bool,
) -> dict[str, Any]:
    path = _absolute(path)
    if path != OWNER_AUTHORITY_PATH:
        _fail("OWNER-BLOCKED: DeviceCheck owner authority path is fixed")
    if not isinstance(expected_sha256, str) or HEX64.fullmatch(expected_sha256) is None:
        _fail("OWNER-BLOCKED: reviewed DeviceCheck owner-authority digest is absent")
    if expected_sha256 in {"0" * 64, hashlib.sha256(b"").hexdigest()}:
        _fail("OWNER-BLOCKED: reviewed DeviceCheck owner authority is not provisioned")
    _reject_symlink_components(path.parent)
    captured = capture_file(
        path.parent,
        path.name,
        expected_sha256=expected_sha256,
    )
    if captured.identity.mode != 0o444:
        _fail("OWNER-BLOCKED: DeviceCheck owner authority is not exact data-only mode 0444")
    if require_owner_custody:
        _require_sealed_identity(captured.identity, "DeviceCheck owner authority")
        _require_sealed_ancestor(path.parent)
    authority = validate_owner_authority(parse_manifest(captured.data))
    fixed_modes = {
        "release_python": 0o555,
        "loader": 0o444,
        "controller": 0o444,
        "owner_signer_certificate": 0o444,
    }
    held_bytes = {
        key: _read_fixed_authority_file(
            Path(authority[key]["path"]),
            f"DeviceCheck {key.replace('_', ' ')}",
            authority[key],
            expected_mode=mode,
            require_owner_custody=require_owner_custody,
        )
        for key, mode in fixed_modes.items()
    }
    manifest_path = Path(authority["source_manifest"]["path"])
    manifest_raw = _read_fixed_authority_file(
        manifest_path,
        "DeviceCheck source manifest",
        authority["source_manifest"],
        expected_mode=0o444,
        require_owner_custody=require_owner_custody,
    )
    manifest = validate_manifest(parse_manifest(manifest_raw))
    if manifest["closure"]["sha256"] != authority["source_snapshot"]["closure_sha256"]:
        _fail("DeviceCheck source authority and manifest closure disagree")
    if manifest["authority"]["snapshot"] != _snapshot_relative_for_digest(
        authority["source_snapshot"]["closure_sha256"]
    ):
        _fail("DeviceCheck manifest and owner authority snapshot paths disagree")
    if (
        _certificate_der_sha256(
            held_bytes["owner_signer_certificate"],
            "DeviceCheck owner signer certificate",
        )
        != authority["owner_signer_sha256"]
    ):
        _fail("DeviceCheck owner signer certificate does not match its reviewed identity")
    verified = verify_snapshot(
        manifest,
        Path(authority["source_snapshot"]["path"]),
        require_sealed=require_owner_custody,
    )
    return {
        "authority_sha256": captured.sha256,
        "build_uid": authority["build"]["build_uid"],
        "build_gid": authority["build"]["build_gid"],
        "cache_root": authority["build"]["cache_root"],
        "consumer_handoff": authority["consumer"]["status"],
        "controller_sha256": authority["controller"]["sha256"],
        "loader_sha256": authority["loader"]["sha256"],
        "manifest_sha256": authority["source_manifest"]["sha256"],
        "owner_signer_sha256": authority["owner_signer_sha256"],
        "owner_signer_certificate_sha256": authority["owner_signer_certificate"]["sha256"],
        "release_python_sha256": authority["release_python"]["sha256"],
        "source_closure_sha256": verified["closure_sha256"],
        "source_snapshot": verified["snapshot"],
        "workspace_root": authority["build"]["workspace_root"],
        "production_ready": False,
    }


def authenticate_owner_authority() -> dict[str, Any]:
    """Audit fixed owner inputs, then refuse until a sealed consumer exists."""
    _load_owner_authority_at(
        OWNER_AUTHORITY_PATH,
        EXPECTED_OWNER_AUTHORITY_SHA256,
        require_owner_custody=True,
    )
    _fail(
        "OWNER-BLOCKED: the external authenticated DeviceCheck controller has not "
        "consumed the sealed snapshot in a private fresh build workspace/cache"
    )


def write_manifest(path: Path, document: dict[str, Any]) -> str:
    del path, document
    _fail(
        "OWNER-BLOCKED: DeviceCheck source custody is verification-only; "
        "the external owner authority must issue the manifest"
    )


def load_manifest(path: Path) -> dict[str, Any]:
    del path
    _fail(
        "OWNER-BLOCKED: caller-selected manifests are not release authority; "
        "use the fixed externally authenticated owner authority"
    )


def _snapshot_path(document: dict[str, Any], snapshot: Path | None) -> Path:
    validate_manifest(document)
    expected = AUTHORITY_ROOT / document["authority"]["snapshot"]
    value = expected if snapshot is None else _absolute(snapshot)
    if value != expected:
        _fail("DeviceCheck snapshot path is fixed by its content-addressed owner authority")
    return value


def _require_sealed_ancestor(path: Path) -> None:
    path = _absolute(path)
    _reject_symlink_components(path)
    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current /= part
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode):
            _fail(f"installed snapshot ancestor is not a directory: {current}")
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o222:
            _fail(f"installed snapshot ancestor is writable or not root-owned: {current}")
        if index >= len(parts) - 1 and not (int(getattr(info, "st_flags", 0)) & SF_IMMUTABLE):
            _fail(f"installed snapshot authority is not SF_IMMUTABLE: {current}")


def _require_sealed_identity(info: FileIdentity, label: str) -> None:
    if info.uid != 0 or info.mode & 0o222:
        _fail(f"{label} is writable or not root-owned")
    flags = info.flags
    if flags & UF_IMMUTABLE and not flags & SF_IMMUTABLE:
        _fail(f"{label} uses UF_IMMUTABLE without SF_IMMUTABLE")
    if not flags & SF_IMMUTABLE:
        _fail(f"{label} is not SF_IMMUTABLE")


def _snapshot_expected(document: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], set[str]]:
    closure = document["closure"]
    files = {item["path"]: item for item in closure["files"]}
    directories = {item["path"] for item in closure["directories"]}
    for path in (*files, *tuple(directories)):
        parts = _relative_parts(path)
        for index in range(1, len(parts)):
            directories.add(_relative_text(parts[:index]))
    return files, directories


def verify_snapshot(
    document: dict[str, Any],
    snapshot: Path | None = None,
    *,
    require_sealed: bool | None = None,
) -> dict[str, Any]:
    """Verify exact snapshot bytes, identities, bounds, and no extra entries."""
    validate_manifest(document)
    destination = _snapshot_path(document, snapshot)
    snapshot_relative = document["authority"]["snapshot"]
    if require_sealed is None:
        require_sealed = AUTHORITY_ROOT == Path("/Library/WinsVPN")
    production_authority = AUTHORITY_ROOT == Path("/Library/WinsVPN")
    if production_authority and not require_sealed:
        _fail("the fixed DeviceCheck authority always requires SF_IMMUTABLE custody")
    if require_sealed and not production_authority:
        _fail("SF_IMMUTABLE custody is restricted to the production DeviceCheck authority")
    if require_sealed:
        if sys.platform != "darwin" or not SF_IMMUTABLE:
            _fail("SF_IMMUTABLE installed snapshot custody requires macOS")
        _require_sealed_ancestor(destination)
    expected_files, expected_dirs = _snapshot_expected(document)
    actual_files, actual_dirs = _capture_tree(destination, snapshot_relative)
    actual_by_path = {item["path"]: item for item in actual_files}
    actual_dir_paths = {item["path"] for item in actual_dirs}
    expected_file_paths = {f"{snapshot_relative}/{path}": item for path, item in expected_files.items()}
    expected_dir_paths = {f"{snapshot_relative}/{path}" for path in expected_dirs}
    if set(actual_by_path) != set(expected_file_paths):
        _fail("installed source snapshot file set does not match the manifest")
    expected_dir_paths.add(snapshot_relative)
    if actual_dir_paths != expected_dir_paths:
        _fail("installed source snapshot directory set does not match the manifest")
    for item in actual_dirs:
        info = _identity_from_document(item["identity"], f"installed snapshot directory {item['path']}")
        if info.mode != 0o555:
            _fail(f"installed snapshot directory is not exact data-only mode 0555: {item['path']}")
        if require_sealed:
            if info.uid != 0:
                _fail(f"installed snapshot directory is not root-owned: {item['path']}")
            if info.flags & UF_IMMUTABLE and not info.flags & SF_IMMUTABLE:
                _fail(f"installed snapshot directory uses UF_IMMUTABLE without SF_IMMUTABLE: {item['path']}")
            if not info.flags & SF_IMMUTABLE:
                _fail(f"installed snapshot directory is not SF_IMMUTABLE: {item['path']}")
    for path, actual in actual_by_path.items():
        source_path = path[len(snapshot_relative) + 1 :]
        expected = expected_files[source_path]
        if actual["bytes"] != expected["bytes"] or actual["sha256"] != expected["sha256"]:
            _fail(f"installed source snapshot bytes changed: {source_path}")
        info = _identity_from_document(actual["identity"], f"installed snapshot {source_path}")
        if info.nlink != 1:
            _fail(f"installed source snapshot hardlink rejected: {source_path}")
        if info.mode != 0o444:
            _fail(f"installed source snapshot file is not exact data-only mode 0444: {source_path}")
        if require_sealed:
            _require_sealed_identity(info, f"installed snapshot {source_path}")
    return {
        "closure_sha256": document["closure"]["sha256"],
        "file_count": len(actual_files),
        "snapshot": str(destination),
        "total_bytes": document["closure"]["total_bytes"],
    }


def provision_snapshot(
    document: dict[str, Any],
    repo: Path,
    *,
    snapshot: Path | None = None,
    module_cache: Path | None = None,
    require_sealed: bool | None = None,
) -> None:
    del document, repo, snapshot, module_cache, require_sealed
    _fail(
        "OWNER-BLOCKED: DeviceCheck source custody never provisions snapshots; "
        "an external owner-controlled transaction must supply one"
    )


def owner_provision_command(
    manifest: Path,
    *,
    repo: Path | None = None,
    module_cache: Path | None = None,
    helper: Path | None = None,
) -> str:
    del manifest, repo, module_cache, helper
    _fail(
        "OWNER-BLOCKED: no root-helper command exists; owner provisioning is external"
    )


def verify_source_against_manifest(
    repo: Path,
    document: dict[str, Any],
    *,
    module_cache: Path | None = None,
) -> dict[str, Any]:
    """Rebind source bytes and identities to the manifest without installing."""
    validate_manifest(document)
    expected = {item["path"]: item for item in document["closure"]["files"]}
    repo = _absolute(repo)
    roots: list[Path] = [repo]
    inputs: list[tuple[Path, str]] = []
    for path in expected:
        if path == "module-cache" or path.startswith("module-cache/"):
            if module_cache is None:
                _fail(f"module-cache source root is required for: {path}")
            source_root = _absolute(module_cache)
            roots.append(source_root)
            source_relative = path.removeprefix("module-cache/")
            inputs.append((source_root / Path(*_relative_parts(source_relative)), path))
        else:
            inputs.append((repo / Path(*_relative_parts(path)), path))
    files, directories = _capture_closure(repo, inputs, allowed_roots=tuple(roots))
    if files != document["closure"]["files"]:
        _fail("current source closure does not match the reviewed manifest")
    if closure_digest(files, directories) != document["closure"]["sha256"]:
        _fail("current source closure content address changed")
    repository_paths = [
        item["path"] for item in files if not item["path"].startswith("module-cache/")
    ]
    current_git = reviewed_git_binding(
        repo,
        document["reviewed"]["commit"],
        required_paths=repository_paths,
    )
    if current_git != document["reviewed"]:
        _fail("current reviewed Git blob/mode/HEAD closure changed")
    return {"closure_sha256": document["closure"]["sha256"], "file_count": len(files)}


def _cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify-authority")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _cli().parse_args(argv)
    try:
        if args.command == "verify-authority":
            print(json.dumps(authenticate_owner_authority(), sort_keys=True))
            return 0
        _fail("unknown command")
    except CustodyError as exc:
        print(f"REFUSING: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
