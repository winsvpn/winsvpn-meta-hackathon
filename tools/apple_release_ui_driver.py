#!/usr/bin/env python3
"""Root-installed physical Apple UI/network observation driver.

The driver owns UI actions and observations.  It never accepts pass/fail facts.
macOS actions use Accessibility semantics plus independent route/interface/DNS/
process observations. iOS uses a physical XCUITest action channel plus a
source-scoped, watchdog-restored first-hop route guard; both are bound to the
exact installed IPA and frozen producer closure.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import os
import pathlib
import plistlib
import re
import select
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from typing import Any


CONTRACT = "winsvpn-apple-final-evidence-driver-v1"
BUNDLE_ID = "org.winsvpn.app"
MACOS_RECEIPT_ID = "org.winsvpn.app"
MACOS_INSTALL_PATH = pathlib.Path("/Applications/Win's VPN.app")
TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
SSH_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
STATE_ROOT = pathlib.Path("/var/db/winsvpn-release-evidence")
MACOS_INSTALL_ROLLBACK_ROOT = STATE_ROOT / "macos-install-rollback"
# /etc/pf.conf invokes the com.apple/* wildcard anchor. A standalone custom
# anchor is inert unless the root ruleset references it, so the release harness
# uses a dedicated child of that existing wildcard and restores it byte-for-byte.
PF_ANCHOR = "com.apple/winsvpn-release-evidence"
MAP_OBSERVER = pathlib.Path("/usr/local/libexec/winsvpn-apple-map-observer")
IOS_ROUTE_CONTROLLER = pathlib.Path("/usr/local/libexec/winsvpn-apple-route-controller.py")
IOS_RUNTIME_ROOT = pathlib.Path("/usr/local/libexec/winsvpn-ios-xctest-runtime")
IOS_BINDING = STATE_ROOT / "ios-exact-install-binding.json"
IOS_ROUTE_INVENTORY = STATE_ROOT / "ios-route-inventory.json"
IOS_SSH_CONFIG = STATE_ROOT / "ios-route-ssh-config"
IOS_XCTEST_MARKER = "WINS_IOS_RELEASE_EVIDENCE_B64:"
IOS_XCTEST_CONTRACT = "winsvpn-ios-xcuitest-observation-v1"
PROCESS_OUTPUT_LIMIT_BYTES = 1_048_576
PROCESS_READ_CHUNK_BYTES = 65_536
TREE_READ_CHUNK_BYTES = 1_048_576
MAX_XCTEST_TREE_ENTRIES = 32_768
MAX_XCTEST_TREE_BYTES = 2 * 1024 * 1024 * 1024
MAX_XCTEST_FILE_BYTES = 512 * 1024 * 1024
MACOS_NO_FORK_BOUNDARY = pathlib.Path("/usr/bin/sandbox-exec")
MACOS_NO_FORK_PROFILE = "(version 1)(allow default)(deny process-fork)"
MACOS_RESTRICTED_FLAG = 0x00080000
INSTALLED_DRIVER = pathlib.Path(
    "/usr/local/libexec/winsvpn-apple-release-ui-driver.py"
)
IOS_XCTEST_SOURCE_INPUTS = (
    ".dart_tool",
    ".flutter-plugins-dependencies",
    ".metadata",
    "analysis_options.yaml",
    "assets",
    "ios",
    "l10n.yaml",
    "lib",
    "localization",
    "pubspec.lock",
    "pubspec.yaml",
)
_DESCRIPTOR_PATH_RE = re.compile(r"^/(?:dev/fd|proc/self/fd)/([0-9]+)$")


class DriverError(RuntimeError):
    pass


def _owner_blocked(message: str) -> DriverError:
    return DriverError(f"OWNER-BLOCKED: {message}")


def _full_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory_anchor_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        value.st_mode,
    )


def _directory_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if directory == 0 or nofollow == 0:
        raise _owner_blocked("descriptor-relative no-follow directory custody is unavailable")
    return os.O_RDONLY | directory | nofollow | cloexec


def _file_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise _owner_blocked("descriptor-relative no-follow file custody is unavailable")
    return os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)


def _safe_component(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise DriverError("XCTest custody path contains an unsafe component")


@contextlib.contextmanager
def _held_absolute_directory(
    path: pathlib.Path,
    label: str,
    *,
    watch_mutation: bool = True,
):
    absolute = pathlib.Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute() or absolute.anchor != "/":
        raise DriverError(f"{label} must use an absolute path")
    identity = _full_identity if watch_mutation else _directory_anchor_identity
    descriptors: list[int] = [os.open("/", _directory_open_flags())]
    identities: list[tuple[int, ...]] = [identity(os.fstat(descriptors[0]))]
    names: list[pathlib.Path] = [pathlib.Path("/")]
    watch: Any = None
    try:
        current = pathlib.Path("/")
        for part in absolute.parts[1:]:
            _safe_component(part)
            descriptor = os.open(part, _directory_open_flags(), dir_fd=descriptors[-1])
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                os.close(descriptor)
                raise DriverError(f"{label} traverses a non-directory")
            descriptors.append(descriptor)
            identities.append(identity(info))
            current /= part
            names.append(current)
        if watch_mutation:
            if not hasattr(select, "kqueue"):
                raise _owner_blocked(
                    f"{label} requires retained vnode mutation observation"
                )
            watch = select.kqueue()
            flags = 0
            for flag_name in (
                "KQ_NOTE_WRITE",
                "KQ_NOTE_RENAME",
                "KQ_NOTE_DELETE",
                "KQ_NOTE_ATTRIB",
                "KQ_NOTE_REVOKE",
            ):
                flags |= int(getattr(select, flag_name, 0))
            watched_descriptors = descriptors[-2:] if len(descriptors) > 1 else descriptors
            events = [
                select.kevent(
                    descriptor,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=flags,
                )
                for descriptor in watched_descriptors
            ]
            watch.control(events, 0, 0)
        yield descriptors[-1], tuple(zip(descriptors, identities))
        if watch is not None and watch.control(None, 16, 0):
            raise DriverError(f"{label} ancestry changed during retained custody")
        for descriptor, expected, named_path in zip(descriptors, identities, names):
            if identity(os.fstat(descriptor)) != expected:
                raise DriverError(f"{label} ancestry changed during retained custody")
            if identity(named_path.lstat()) != expected:
                raise DriverError(f"{label} named ancestry changed during retained custody")
    finally:
        if watch is not None:
            watch.close()
        for descriptor in reversed(descriptors):
            os.close(descriptor)


class _TreeBudget:
    def __init__(self) -> None:
        self.entries = 0
        self.bytes = 0

    def add(self, size: int) -> None:
        self.entries += 1
        self.bytes += size
        if self.entries > MAX_XCTEST_TREE_ENTRIES:
            raise DriverError("XCTest tree exceeded the entry safety limit")
        if self.bytes > MAX_XCTEST_TREE_BYTES:
            raise DriverError("XCTest tree exceeded the byte safety limit")


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise DriverError("descriptor-relative XCTest copy write failed")
        view = view[written:]


def _copy_regular_at(
    source_directory: int,
    destination_directory: int,
    name: str,
    *,
    expected_uid: int,
    budget: _TreeBudget,
    relative: str,
) -> tuple[str, int]:
    source = os.open(name, _file_open_flags(), dir_fd=source_directory)
    destination: int | None = None
    try:
        before = os.fstat(source)
        named = os.stat(name, dir_fd=source_directory, follow_symlinks=False)
        if (
            _full_identity(before) != _full_identity(named)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != expected_uid
            or before.st_mode & 0o7000
            or before.st_size < 0
            or before.st_size > MAX_XCTEST_FILE_BYTES
        ):
            raise DriverError("XCTest source file identity is unsafe")
        budget.add(before.st_size)
        mode = 0o500 if before.st_mode & 0o111 else 0o400
        destination = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            mode,
            dir_fd=destination_directory,
        )
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            block = os.pread(source, min(TREE_READ_CHUNK_BYTES, before.st_size - offset), offset)
            if not block:
                raise DriverError("XCTest source file ended during retained copy")
            digest.update(block)
            _write_all(destination, block)
            offset += len(block)
        if os.pread(source, 1, offset):
            raise DriverError("XCTest source file grew during retained copy")
        os.fsync(destination)
        after = os.fstat(source)
        if _full_identity(after) != _full_identity(before):
            raise DriverError("XCTest source file changed during retained copy")
        copied = os.fstat(destination)
        if (
            not stat.S_ISREG(copied.st_mode)
            or copied.st_nlink != 1
            or copied.st_size != before.st_size
            or stat.S_IMODE(copied.st_mode) != mode
        ):
            raise DriverError("XCTest destination file identity is unsafe")
        os.chown(
            name,
            os.geteuid(),
            os.getegid(),
            dir_fd=destination_directory,
            follow_symlinks=False,
        )
        return f"F {relative} {mode:o} {before.st_size} {digest.hexdigest()}", before.st_size
    finally:
        if destination is not None:
            os.close(destination)
        os.close(source)


def _copy_directory_contents(
    source_directory: int,
    destination_directory: int,
    *,
    expected_uid: int,
    budget: _TreeBudget,
    prefix: str,
    inventory: list[str],
) -> None:
    before = os.fstat(source_directory)
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_uid != expected_uid
        or before.st_mode & 0o7000
    ):
        raise DriverError("XCTest source directory identity is unsafe")
    names = sorted(os.listdir(source_directory))
    budget.add(0)
    inventory.append(f"D {prefix or '.'} 500")
    for name in names:
        _safe_component(name)
        info = os.stat(name, dir_fd=source_directory, follow_symlinks=False)
        relative = f"{prefix}/{name}" if prefix else name
        if stat.S_ISLNK(info.st_mode):
            raise DriverError("XCTest source tree must not contain symlinks")
        if stat.S_ISDIR(info.st_mode):
            if info.st_uid != expected_uid or info.st_mode & 0o7000:
                raise DriverError("XCTest source directory ownership or mode is unsafe")
            os.mkdir(name, 0o700, dir_fd=destination_directory)
            child_source = os.open(name, _directory_open_flags(), dir_fd=source_directory)
            child_destination = os.open(name, _directory_open_flags(), dir_fd=destination_directory)
            try:
                _copy_directory_contents(
                    child_source,
                    child_destination,
                    expected_uid=expected_uid,
                    budget=budget,
                    prefix=relative,
                    inventory=inventory,
                )
                os.fsync(child_destination)
            finally:
                os.close(child_destination)
                os.close(child_source)
            os.chown(
                name,
                os.geteuid(),
                os.getegid(),
                dir_fd=destination_directory,
                follow_symlinks=False,
            )
            os.chmod(
                name,
                0o500,
                dir_fd=destination_directory,
                follow_symlinks=False,
            )
        elif stat.S_ISREG(info.st_mode):
            entry, _size = _copy_regular_at(
                source_directory,
                destination_directory,
                name,
                expected_uid=expected_uid,
                budget=budget,
                relative=relative,
            )
            inventory.append(entry)
        else:
            raise DriverError("XCTest source tree contains a special file")
    if sorted(os.listdir(source_directory)) != names or _full_identity(os.fstat(source_directory)) != _full_identity(before):
        raise DriverError("XCTest source directory changed during retained copy")


def _copy_tree_no_follow(
    source: pathlib.Path,
    destination: pathlib.Path,
    *,
    expected_uid: int,
    label: str,
) -> tuple[str, int, int]:
    destination_parent = destination.parent
    created = False
    try:
        with _held_absolute_directory(source, label) as (source_fd, _source_chain):
            with _held_absolute_directory(
                destination_parent,
                f"{label} destination",
                watch_mutation=False,
            ) as (
                destination_parent_fd,
                _destination_chain,
            ):
                _safe_component(destination.name)
                os.mkdir(destination.name, 0o700, dir_fd=destination_parent_fd)
                created = True
                destination_fd = os.open(
                    destination.name,
                    _directory_open_flags(),
                    dir_fd=destination_parent_fd,
                )
                try:
                    inventory: list[str] = []
                    budget = _TreeBudget()
                    _copy_directory_contents(
                        source_fd,
                        destination_fd,
                        expected_uid=expected_uid,
                        budget=budget,
                        prefix="",
                        inventory=inventory,
                    )
                    os.fsync(destination_fd)
                    digest = hashlib.sha256(
                        ("\n".join(inventory) + "\n").encode("utf-8")
                    ).hexdigest()
                finally:
                    os.close(destination_fd)
                os.chown(
                    destination.name,
                    os.geteuid(),
                    os.getegid(),
                    dir_fd=destination_parent_fd,
                    follow_symlinks=False,
                )
                os.chmod(
                    destination.name,
                    0o500,
                    dir_fd=destination_parent_fd,
                    follow_symlinks=False,
                )
                os.fsync(destination_parent_fd)
        return digest, budget.entries, budget.bytes
    except BaseException:
        if created and destination.exists() and not destination.is_symlink():
            _relax_sealed_tree_for_cleanup(destination)
            _remove_private_tree(destination)
        raise


def _inventory_directory(
    directory: int,
    *,
    expected_uid: int,
    budget: _TreeBudget,
    prefix: str,
    inventory: list[str],
) -> None:
    before = os.fstat(directory)
    if (
        not stat.S_ISDIR(before.st_mode)
        or before.st_uid != expected_uid
        or stat.S_IMODE(before.st_mode) != 0o555
    ):
        raise DriverError("bound XCTest directory identity is unsafe")
    names = sorted(os.listdir(directory))
    budget.add(0)
    inventory.append(f"D {prefix or '.'} 555")
    for name in names:
        _safe_component(name)
        relative = f"{prefix}/{name}" if prefix else name
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            raise DriverError("bound XCTest tree contains a symlink")
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, _directory_open_flags(), dir_fd=directory)
            try:
                _inventory_directory(
                    child,
                    expected_uid=expected_uid,
                    budget=budget,
                    prefix=relative,
                    inventory=inventory,
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            descriptor = os.open(name, _file_open_flags(), dir_fd=directory)
            try:
                before_file = os.fstat(descriptor)
                if (
                    _full_identity(before_file) != _full_identity(info)
                    or before_file.st_uid != expected_uid
                    or before_file.st_nlink != 1
                    or stat.S_IMODE(before_file.st_mode) not in {0o444, 0o555}
                    or before_file.st_size < 0
                    or before_file.st_size > MAX_XCTEST_FILE_BYTES
                ):
                    raise DriverError("bound XCTest file identity is unsafe")
                budget.add(before_file.st_size)
                digest = hashlib.sha256()
                offset = 0
                while offset < before_file.st_size:
                    block = os.pread(
                        descriptor,
                        min(TREE_READ_CHUNK_BYTES, before_file.st_size - offset),
                        offset,
                    )
                    if not block:
                        raise DriverError("bound XCTest file ended during hashing")
                    digest.update(block)
                    offset += len(block)
                if os.pread(descriptor, 1, offset):
                    raise DriverError("bound XCTest file grew during hashing")
                if _full_identity(os.fstat(descriptor)) != _full_identity(before_file):
                    raise DriverError("bound XCTest file changed during hashing")
                inventory.append(
                    f"F {relative} {stat.S_IMODE(before_file.st_mode):o} "
                    f"{before_file.st_size} {digest.hexdigest()}"
                )
            finally:
                os.close(descriptor)
        else:
            raise DriverError("bound XCTest tree contains a special file")
    if sorted(os.listdir(directory)) != names or _full_identity(os.fstat(directory)) != _full_identity(before):
        raise DriverError("bound XCTest directory changed during hashing")


def _tree_binding(root: pathlib.Path, *, expected_uid: int, label: str) -> tuple[str, int, int]:
    with _held_absolute_directory(root, label) as (root_fd, _chain):
        budget = _TreeBudget()
        inventory: list[str] = []
        _inventory_directory(
            root_fd,
            expected_uid=expected_uid,
            budget=budget,
            prefix="",
            inventory=inventory,
        )
    digest = hashlib.sha256(("\n".join(inventory) + "\n").encode("utf-8")).hexdigest()
    return digest, budget.entries, budget.bytes


def _copy_source_inputs(
    repo: pathlib.Path,
    destination: pathlib.Path,
    *,
    expected_uid: int,
) -> tuple[str, int, int]:
    destination.mkdir(mode=0o700)
    with _held_absolute_directory(repo, "iOS XCTest repository source") as (
        repo_fd,
        _repo_chain,
    ):
        with _held_absolute_directory(
            destination,
            "iOS XCTest source snapshot",
            watch_mutation=False,
        ) as (
            destination_fd,
            _destination_chain,
        ):
            inventory = ["D . 500"]
            budget = _TreeBudget()
            budget.add(0)
            for name in IOS_XCTEST_SOURCE_INPUTS:
                _safe_component(name)
                try:
                    info = os.stat(name, dir_fd=repo_fd, follow_symlinks=False)
                except OSError as exc:
                    raise DriverError(f"required iOS XCTest source input is absent: {name}") from exc
                if stat.S_ISLNK(info.st_mode):
                    raise DriverError("iOS XCTest source input must not be a symlink")
                if stat.S_ISDIR(info.st_mode):
                    os.mkdir(name, 0o700, dir_fd=destination_fd)
                    source_child = os.open(name, _directory_open_flags(), dir_fd=repo_fd)
                    destination_child = os.open(name, _directory_open_flags(), dir_fd=destination_fd)
                    try:
                        _copy_directory_contents(
                            source_child,
                            destination_child,
                            expected_uid=expected_uid,
                            budget=budget,
                            prefix=name,
                            inventory=inventory,
                        )
                        os.fsync(destination_child)
                    finally:
                        os.close(destination_child)
                        os.close(source_child)
                    os.chmod(
                        name,
                        0o500,
                        dir_fd=destination_fd,
                        follow_symlinks=False,
                    )
                elif stat.S_ISREG(info.st_mode):
                    entry, _size = _copy_regular_at(
                        repo_fd,
                        destination_fd,
                        name,
                        expected_uid=expected_uid,
                        budget=budget,
                        relative=name,
                    )
                    inventory.append(entry)
                else:
                    raise DriverError("iOS XCTest source input has an unsafe type")
            os.fsync(destination_fd)
    os.chmod(destination, 0o500)
    digest = hashlib.sha256(("\n".join(inventory) + "\n").encode("utf-8")).hexdigest()
    return digest, budget.entries, budget.bytes


def _remove_private_tree(root: pathlib.Path) -> None:
    if not root.exists() and not root.is_symlink():
        return
    if root.is_symlink() or not root.is_dir():
        raise DriverError("private XCTest cleanup root is unsafe")
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        raise _owner_blocked("descriptor-safe private XCTest cleanup is unavailable")
    shutil.rmtree(root)


def _create_console_build_root(
    private_parent: pathlib.Path,
    console_uid: int,
) -> pathlib.Path:
    parent_info = private_parent.lstat()
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or stat.S_IMODE(parent_info.st_mode) != 0o700
        or type(console_uid) is not int
        or console_uid <= 0
    ):
        raise DriverError("private Xcode build parent identity is unsafe")
    build_root = private_parent / "Build"
    build_root.mkdir(mode=0o700)
    os.chown(build_root, console_uid, -1)
    os.chmod(build_root, 0o700)
    os.chmod(private_parent, 0o711)
    build_info = build_root.lstat()
    sealed_parent = private_parent.lstat()
    if (
        not stat.S_ISDIR(build_info.st_mode)
        or stat.S_ISLNK(build_info.st_mode)
        or build_info.st_uid != console_uid
        or stat.S_IMODE(build_info.st_mode) != 0o700
        or sealed_parent.st_uid != os.geteuid()
        or stat.S_IMODE(sealed_parent.st_mode) != 0o711
    ):
        raise DriverError("console-user Xcode build root custody is invalid")
    return build_root


def _relax_sealed_tree_for_cleanup(root: pathlib.Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    for directory, child_directories, _files in os.walk(root, topdown=True, followlinks=False):
        path = pathlib.Path(directory)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise DriverError("sealed XCTest cleanup tree changed type")
        os.chmod(path, 0o700, follow_symlinks=False)
        child_directories[:] = [
            name
            for name in child_directories
            if not (path / name).is_symlink()
        ]


def _authenticated_no_fork_boundary() -> str:
    if sys.platform != "darwin":
        raise _owner_blocked("the macOS no-fork execution boundary is unavailable")
    path = MACOS_NO_FORK_BOUNDARY
    try:
        info = path.lstat()
    except OSError as exc:
        raise _owner_blocked("the macOS no-fork execution boundary is absent") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o755
        or not (getattr(info, "st_flags", 0) & MACOS_RESTRICTED_FLAG)
    ):
        raise _owner_blocked("the macOS no-fork execution boundary is not authenticated SSV evidence")
    return os.fspath(path)


def _descriptor_path_fd(value: str) -> int | None:
    match = _DESCRIPTOR_PATH_RE.fullmatch(value)
    if match is None:
        return None
    descriptor = int(match.group(1), 10)
    if descriptor < 3:
        raise DriverError("standard-stream descriptor paths are not release artifacts")
    return descriptor


def _descriptor_identity(descriptor: int) -> tuple[int, int, int, int, int, int, int, str]:
    try:
        before = os.fstat(descriptor)
    except OSError as exc:
        raise DriverError("retained release artifact descriptor is unavailable") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_mode & 0o022
    ):
        raise DriverError("retained release artifact descriptor is unsafe")
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        if not block:
            raise DriverError("retained release artifact descriptor ended early")
        digest.update(block)
        offset += len(block)
    after = os.fstat(descriptor)
    fields = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if fields(before) != fields(after):
        raise DriverError("retained release artifact changed while it was read")
    return (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        digest.hexdigest(),
    )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass
    deadline = time.monotonic() + 2
    while True:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        except OSError:
            return
        if time.monotonic() >= deadline:
            raise DriverError("machine command descendant process group survived cleanup")
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        time.sleep(0.02)


def _spawn_bounded(
    args: list[str],
    *,
    stdin: int,
    environment: dict[str, str],
    pass_fds: tuple[int, ...],
    deadline: float,
) -> subprocess.Popen[bytes]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DriverError("machine command exceeded the time bound before launch")
    previous_handler: Any = None
    timer_armed = False
    try:
        if threading.current_thread() is threading.main_thread() and hasattr(signal, "setitimer"):
            def timeout_handler(_signum: int, _frame: Any) -> None:
                raise TimeoutError("process launch deadline expired")

            previous_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.setitimer(signal.ITIMER_REAL, remaining)
            timer_armed = True
        boundary = _authenticated_no_fork_boundary()
        return subprocess.Popen(
            [boundary, "-p", MACOS_NO_FORK_PROFILE, *args],
            cwd="/",
            env=environment,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
        )
    except (OSError, TimeoutError) as exc:
        raise DriverError("machine command could not start within its time bound") from exc
    finally:
        if timer_armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)


def run(
    args: list[str],
    *,
    input_text: str | None = None,
    timeout: int = 120,
    check: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    if (
        not args
        or any(type(item) is not str or not item or "\x00" in item for item in args)
        or type(timeout) is not int
        or timeout <= 0
    ):
        raise DriverError("machine command contract is invalid")
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": "/var/empty",
        "TMPDIR": "/private/tmp",
    }
    if extra_env:
        for key, value in extra_env.items():
            if (
                not re.fullmatch(r"WINSVPN_[A-Z0-9_]+", key)
                or type(value) is not str
                or "\x00" in value
            ):
                raise DriverError("machine command environment extension is unsafe")
            environment[key] = value
    descriptors = sorted(
        {
            descriptor
            for argument in args
            if (descriptor := _descriptor_path_fd(argument)) is not None
        }
    )
    snapshots = {descriptor: _descriptor_identity(descriptor) for descriptor in descriptors}
    input_bytes = None if input_text is None else input_text.encode("utf-8")
    if input_bytes is not None and len(input_bytes) > PROCESS_OUTPUT_LIMIT_BYTES:
        raise DriverError("machine command input exceeded the safety limit")
    deadline = time.monotonic() + timeout
    process: subprocess.Popen[bytes] | None = None
    streams: dict[int, tuple[Any, bytearray, str]] = {}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    input_descriptor: int | None = None
    input_offset = 0
    try:
        process = _spawn_bounded(
            args,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            environment=environment,
            pass_fds=tuple(descriptors),
            deadline=deadline,
        )
        if input_bytes is not None:
            assert process.stdin is not None
            if input_bytes:
                input_descriptor = process.stdin.fileno()
                os.set_blocking(input_descriptor, False)
            else:
                process.stdin.close()
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            assert stream is not None
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            streams[descriptor] = (stream, captured[label], label)
        while streams or input_descriptor is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DriverError("machine command exceeded the time bound")
            readable, writable, _exceptional = select.select(
                list(streams),
                [] if input_descriptor is None else [input_descriptor],
                [],
                min(0.1, remaining),
            )
            if input_descriptor is not None and input_descriptor in writable:
                try:
                    written = os.write(input_descriptor, input_bytes[input_offset:])
                except BlockingIOError:
                    written = 0
                except BrokenPipeError as exc:
                    raise DriverError("machine command closed stdin before consuming its input") from exc
                if written < 0:
                    raise DriverError("machine command input write failed")
                input_offset += written
                if input_offset == len(input_bytes):
                    assert process.stdin is not None
                    process.stdin.close()
                    input_descriptor = None
            for descriptor in readable:
                stream, payload, label = streams[descriptor]
                try:
                    chunk = os.read(
                        descriptor,
                        max(1, min(
                            PROCESS_READ_CHUNK_BYTES,
                            PROCESS_OUTPUT_LIMIT_BYTES + 1 - len(payload),
                        )),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    stream.close()
                    del streams[descriptor]
                    continue
                payload.extend(chunk)
                if len(payload) > PROCESS_OUTPUT_LIMIT_BYTES:
                    raise DriverError(f"machine command {label} exceeded the safety limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DriverError("machine command exceeded the time bound")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise DriverError("machine command exceeded the time bound") from exc
        for descriptor, snapshot in snapshots.items():
            if _descriptor_identity(descriptor) != snapshot:
                raise DriverError("retained release artifact changed during machine command")
        try:
            stdout = bytes(captured["stdout"]).decode("utf-8", "strict")
            stderr = bytes(captured["stderr"]).decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise DriverError("machine command returned invalid UTF-8") from exc
        result = subprocess.CompletedProcess(args, returncode, stdout, stderr)
        if check and result.returncode != 0:
            summary = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["command failed"]
            raise DriverError(f"machine command failed: {args[0]}: {summary[0][:240]}")
        return result
    finally:
        cleanup_error: DriverError | None = None
        if process is not None:
            try:
                _kill_process_group(process)
            except DriverError as exc:
                cleanup_error = exc
        for stream, _payload, _label in list(streams.values()):
            try:
                stream.close()
            except OSError:
                pass
        if process is not None and process.stdin is not None and not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass
        if cleanup_error is not None:
            raise cleanup_error


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def output(action: str, **fields: Any) -> None:
    payload = {
        "schema_version": 1,
        "contract": CONTRACT,
        "action": action,
        "passed": True,
        "secret_material_redacted": True,
        **fields,
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def require_darwin_root() -> None:
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise DriverError("Apple release UI driver must run as root on macOS")
    if STATE_ROOT.exists() or STATE_ROOT.is_symlink():
        info = STATE_ROOT.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise DriverError("Apple release evidence state directory is unsafe")
    else:
        STATE_ROOT.mkdir(mode=0o700, parents=False)
    os.chown(STATE_ROOT, 0, 0)
    os.chmod(STATE_ROOT, 0o700)


def console_identity() -> tuple[str, int, pathlib.Path]:
    result = run(["/usr/bin/stat", "-f", "%Su:%u", "/dev/console"])
    name, raw_uid = result.stdout.strip().split(":", 1)
    if name in {"", "root", "loginwindow"} or not raw_uid.isdigit():
        raise DriverError("No unlocked GUI console user is available")
    home = pathlib.Path(run(["/usr/bin/dscl", ".", "-read", f"/Users/{name}", "NFSHomeDirectory"]).stdout.split()[-1])
    return name, int(raw_uid), home


def as_console(args: list[str], *, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess[str]:
    del args, timeout, check
    raise _owner_blocked(
        "console-user execution requires an authenticated whole-job supervisor; "
        "process-group cleanup cannot contain setsid descendants"
    )


def safe_regular(path: pathlib.Path, label: str) -> pathlib.Path:
    absolute = pathlib.Path(os.path.abspath(os.fspath(path.expanduser())))
    inspected = absolute
    # macOS exposes three immutable root aliases as root-owned links into
    # /private. tempfile normally returns /var/folders/... through that system
    # alias. Accept only those exact Apple aliases, then inspect every component
    # of the canonical /private path. All caller-controlled links remain fatal.
    if sys.platform == "darwin" and len(absolute.parts) > 1:
        alias_name = absolute.parts[1]
        expected_aliases = {
            "etc": "private/etc",
            "tmp": "private/tmp",
            "var": "private/var",
        }
        if alias_name in expected_aliases:
            alias = pathlib.Path(absolute.anchor) / alias_name
            alias_info = alias.lstat()
            if stat.S_ISLNK(alias_info.st_mode):
                if (
                    alias_info.st_uid != 0
                    or os.readlink(alias) != expected_aliases[alias_name]
                ):
                    raise DriverError(f"{label} traverses an untrusted system alias")
                inspected = pathlib.Path("/private") / alias_name
                inspected = inspected.joinpath(*absolute.parts[2:])

    current = pathlib.Path(inspected.anchor)
    for part in inspected.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise DriverError(f"{label} must not traverse a symlink")
    info = inspected.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise DriverError(f"{label} must be a regular file")
    return inspected


def runtime_config_path() -> pathlib.Path:
    _, uid, home = console_identity()
    candidates = (
        home / "Library/Application Support/wins_vpn/vpn_config.txt",
        home / f"Library/Containers/{BUNDLE_ID}/Data/Library/Application Support/wins_vpn/vpn_config.txt",
        home / f"Library/Containers/{BUNDLE_ID}/Data/Documents/vpn_config.txt",
    )
    existing: set[pathlib.Path] = set()
    home_resolved = home.resolve(strict=True)
    for path in candidates:
        if not path.is_file() or path.is_symlink():
            continue
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(home_resolved)
        except ValueError as exc:
            raise DriverError("Installed-app VPN configuration escaped the console user's home") from exc
        info = resolved.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise DriverError("Installed-app VPN configuration ownership or mode is unsafe")
        existing.add(resolved)
    if len(existing) != 1:
        raise DriverError("Expected exactly one installed-app VPN configuration")
    return next(iter(existing))


def runtime_config() -> dict[str, Any]:
    path = runtime_config_path()
    if path.stat().st_size > 256 * 1024:
        raise DriverError("Installed-app VPN configuration is unexpectedly large")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise DriverError("Installed-app VPN configuration is invalid")
    return value


def advertised_routes(config: dict[str, Any]) -> list[dict[str, Any]]:
    xray = config.get("xray") if isinstance(config.get("xray"), dict) else {}
    raw = xray.get("transports") or xray.get("stealth_transports") or []
    if not raw:
        raw = [{"port": xray.get("port"), "security": xray.get("security")}]
    result: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise DriverError("Advertised Xray transport is malformed")
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError) as exc:
            raise DriverError("Advertised Xray port is invalid") from exc
        security = str(item.get("security", "")).strip().lower()
        if not 1 <= port <= 65535 or security not in {"none", "tls"} or (port, security) in seen:
            raise DriverError("Advertised Xray transport is invalid or duplicated")
        seen.add((port, security))
        result.append({"protocol": "tcp", "port": port, "security": security})
    if not result:
        raise DriverError("No advertised Xray transports are available")
    return result


def runtime_direct_port(config: dict[str, Any]) -> int:
    endpoint = str(config.get("server_endpoint") or config.get("serverendpoint") or "").strip()
    match = re.search(r":([0-9]{1,5})$", endpoint)
    if not match:
        raise DriverError("Runtime AWG endpoint has no explicit port")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise DriverError("Runtime AWG endpoint port is invalid")
    xray = config.get("xray") if isinstance(config.get("xray"), dict) else {}
    remote = xray.get("remote_awg_port") or xray.get("remoteawgport")
    if remote is not None and int(remote) != port:
        raise DriverError("Runtime direct port disagrees with Xray remote AWG port")
    return port


def baseline_path(double: bool) -> pathlib.Path:
    return STATE_ROOT / ("double-baseline.json" if double else "node-baseline.json")


def save_baseline(double: bool, config: dict[str, Any]) -> None:
    direct_addresses, xray_addresses = forcing_endpoint_addresses(config)
    value = {
        "schema_version": 1,
        "direct_port": runtime_direct_port(config),
        "xray_routes": advertised_routes(config),
        "direct_addresses": [list(item) for item in direct_addresses],
        "xray_addresses": [list(item) for item in xray_addresses],
    }
    path = baseline_path(double)
    temporary = path.with_suffix(f".tmp.{os.getpid()}")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600); os.replace(temporary, path)


def load_baseline(
    double: bool,
) -> tuple[int, list[dict[str, Any]], list[tuple[int, str]], list[tuple[int, str]]]:
    path = baseline_path(double)
    if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0 or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise DriverError("Mode-specific direct baseline is missing or unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "direct_port", "xray_routes", "direct_addresses", "xray_addresses"
    } or value["schema_version"] != 1:
        raise DriverError("Mode-specific direct baseline is invalid")
    routes = advertised_routes({"xray": {"transports": value["xray_routes"]}})
    port = value["direct_port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise DriverError("Mode-specific direct baseline port is invalid")
    def addresses(field: str) -> list[tuple[int, str]]:
        raw = value[field]
        if not isinstance(raw, list) or not raw or len(raw) > 64:
            raise DriverError("Mode-specific forcing address baseline is invalid")
        result: set[tuple[int, str]] = set()
        for item in raw:
            if not isinstance(item, list) or len(item) != 2 or item[0] not in {4, 6}:
                raise DriverError("Mode-specific forcing address baseline is invalid")
            try:
                parsed = ipaddress.ip_address(str(item[1]))
            except ValueError as exc:
                raise DriverError("Mode-specific forcing address baseline is invalid") from exc
            if parsed.version != item[0]:
                raise DriverError("Mode-specific forcing address family is inconsistent")
            result.add((parsed.version, str(parsed)))
        if len(result) != len(raw):
            raise DriverError("Mode-specific forcing address baseline is duplicated")
        return sorted(result)
    return port, routes, addresses("direct_addresses"), addresses("xray_addresses")


AX_SCRIPT = r'''
on run argv
  set wanted to item 1 of argv
  set operation to item 2 of argv
  tell application "System Events"
    set matches to application processes whose bundle identifier is "org.winsvpn.app"
    if (count of matches) is not 1 then error "Win's VPN AX process is unavailable"
    tell item 1 of matches
      set frontmost to true
      set candidates to entire contents of front window
      repeat with e in candidates
        set labels to {}
        try
          set end of labels to (name of e as text)
        end try
        try
          set end of labels to (description of e as text)
        end try
        try
          set end of labels to (help of e as text)
        end try
        if labels contains wanted then
          if operation is "exists" then return "found"
          try
            perform action "AXPress" of e
            return "pressed"
          on error
            try
              click e
              return "clicked"
            end try
          end try
        end if
      end repeat
    end tell
  end tell
  error "AX semantic element not found: " & wanted
end run
'''

AX_SET_VALUE_SCRIPT = r'''
on run argv
  set wanted to item 1 of argv
  set replacement to item 2 of argv
  tell application "System Events"
    set matches to application processes whose bundle identifier is "org.winsvpn.app"
    if (count of matches) is not 1 then error "Win's VPN AX process is unavailable"
    tell item 1 of matches
      set frontmost to true
      repeat with e in (entire contents of front window)
        set labels to {}
        try
          set end of labels to (name of e as text)
        end try
        try
          set end of labels to (description of e as text)
        end try
        if labels contains wanted then
          try
            set value of e to replacement
            return "set"
          end try
        end if
      end repeat
    end tell
  end tell
  error "AX semantic text field not found: " & wanted
end run
'''


def ax(label: str, operation: str = "click", *, timeout: int = 20) -> str:
    result = as_console(["/usr/bin/osascript", "-e", AX_SCRIPT, label, operation], timeout=timeout)
    return result.stdout.strip()


def ax_set_value(label: str, value: str) -> None:
    result = as_console(["/usr/bin/osascript", "-e", AX_SET_VALUE_SCRIPT, label, value])
    if result.stdout.strip() != "set":
        raise DriverError(f"AX text field did not accept value: {label}")


def wait_ax(label: str, timeout: int = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if ax(label, "exists", timeout=5) == "found":
                return
        except DriverError:
            pass
        time.sleep(1)
    raise DriverError(f"Timed out waiting for AX semantic state: {label}")


def launch_macos_app() -> None:
    as_console(["/usr/bin/open", "-b", BUNDLE_ID])
    wait_ax("Connect VPN", 30)


def settings_path() -> pathlib.Path:
    return runtime_config_path().with_name("vpn_settings.txt")


def settings_snapshot() -> tuple[bytes, int, int, int] | None:
    path = settings_path()
    if path.is_symlink(): raise DriverError("VPN settings must not be a symlink")
    if not path.is_file():
        return None
    info = path.lstat()
    _, uid, _ = console_identity()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise DriverError("VPN settings ownership or mode is unsafe")
    return path.read_bytes(), info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)


def restore_settings(snapshot: tuple[bytes, int, int, int] | None) -> None:
    path = settings_path()
    if path.is_symlink(): raise DriverError("VPN settings must not be a symlink")
    if snapshot is None:
        path.unlink(missing_ok=True)
        return
    data, uid, gid, mode = snapshot
    temporary = path.with_name(f".{path.name}.release-restore.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def control_state_hash() -> str:
    settings = settings_path()
    settings_hash = sha256_file(settings) if settings.is_file() and not settings.is_symlink() else sha256_text("")
    anchor = run(["/sbin/pfctl", "-a", PF_ANCHOR, "-sr"], check=False).stdout
    return sha256_text(settings_hash + "\n" + anchor)


def pf_enabled() -> bool:
    return "Status: Enabled" in run(["/sbin/pfctl", "-s", "info"], check=False).stdout


def require_active_pf_anchor_hook() -> None:
    root_rules = run(["/sbin/pfctl", "-sr"], check=False).stdout
    if not re.search(r'anchor\s+"com\.apple/\*"', root_rules):
        raise DriverError("macOS root PF rules do not invoke the required com.apple wildcard anchor")


def endpoint_host(endpoint: str) -> str:
    value = endpoint.strip()
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)](?::[0-9]{1,5})?", value)
        return match.group(1) if match else ""
    if ":" in value:
        return value.rsplit(":", 1)[0].strip()
    return value


def resolve_endpoint_addresses(hosts: list[str]) -> list[tuple[int, str]]:
    addresses: set[tuple[int, str]] = set()
    for raw in hosts:
        host = endpoint_host(raw)
        if not host:
            continue
        try:
            parsed = ipaddress.ip_address(host)
            addresses.add((parsed.version, str(parsed)))
            continue
        except ValueError:
            pass
        try:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise DriverError("Release forcing could not resolve a configured transport host") from exc
        for family, _, _, _, sockaddr in records:
            if family in {socket.AF_INET, socket.AF_INET6}:
                parsed = ipaddress.ip_address(sockaddr[0])
                addresses.add((parsed.version, str(parsed)))
    if not addresses or len(addresses) > 64:
        raise DriverError("Release forcing transport address set is empty or excessive")
    return sorted(addresses)


def forcing_endpoint_addresses(config: dict[str, Any]) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    direct = resolve_endpoint_addresses(
        [str(config.get("server_endpoint") or config.get("serverendpoint") or "")]
    )
    xray = config.get("xray") if isinstance(config.get("xray"), dict) else {}
    hosts = [str(xray.get("host") or ""), str(xray.get("server_name") or xray.get("servername") or "")]
    for value in (
        xray.get("fallback_hosts"), xray.get("fallbackhosts"),
        config.get("regional_aliases"), config.get("regionalaliases"),
    ):
        if isinstance(value, list):
            hosts.extend(str(item) for item in value)
    return direct, resolve_endpoint_addresses(hosts)


def forcing_pf_rules(
    config: dict[str, Any],
    routes: list[dict[str, Any]],
    selected_port: int,
    direct_port: int,
) -> list[str]:
    direct_addresses, xray_addresses = forcing_endpoint_addresses(config)
    return forcing_pf_rules_from_addresses(
        direct_addresses, xray_addresses, routes, selected_port, direct_port
    )


def forcing_pf_rules_from_addresses(
    direct_addresses: list[tuple[int, str]],
    xray_addresses: list[tuple[int, str]],
    routes: list[dict[str, Any]],
    selected_port: int,
    direct_port: int,
) -> list[str]:
    rules = [
        f"block drop out quick {'inet6' if version == 6 else 'inet'} "
        f"proto udp to {address} port = {direct_port}"
        for version, address in direct_addresses
    ]
    for route in routes:
        if route["port"] != selected_port:
            for version, address in xray_addresses:
                rules.append(
                    f"block drop out quick {'inet6' if version == 6 else 'inet'} "
                    f"proto tcp to {address} port = {route['port']}"
                )
    return rules


def apply_forcing(
    kind: str,
    port: int | None,
    routes: list[dict[str, Any]],
    direct_port: int | None,
    direct_addresses: list[tuple[int, str]],
    xray_addresses: list[tuple[int, str]],
) -> tuple[bool, str, bool]:
    before = run(["/sbin/pfctl", "-a", PF_ANCHOR, "-sr"], check=False).stdout
    was_enabled = pf_enabled()
    rules: list[str] = []
    if kind in {"xray", "double_vpn_xray"}:
        if direct_port is None or not 1 <= direct_port <= 65535 or port is None:
            raise DriverError("Route forcing requires the machine-observed direct first-hop port")
        same_port = [route for route in routes if route["port"] == port]
        if len(same_port) != 1:
            raise DriverError("Requested Xray route cannot be uniquely forced by TCP port")
        rules.extend(forcing_pf_rules_from_addresses(
            direct_addresses, xray_addresses, routes, port, direct_port
        ))
    if not rules:
        return False, before, was_enabled
    if not was_enabled:
        run(["/sbin/pfctl", "-E"])
    try:
        require_active_pf_anchor_hook()
        run(["/sbin/pfctl", "-a", PF_ANCHOR, "-f", "-"], input_text="\n".join(rules) + "\n")
    except Exception:
        if not was_enabled:
            run(["/sbin/pfctl", "-d"], check=False)
        raise
    return bool(rules), before, was_enabled


def restore_forcing(before: str, was_enabled: bool) -> None:
    run(["/sbin/pfctl", "-a", PF_ANCHOR, "-f", "-"], input_text=before)
    if not was_enabled:
        run(["/sbin/pfctl", "-d"])


def utun_counters() -> tuple[str, int, int]:
    text = run(["/usr/sbin/netstat", "-ibn"]).stdout
    totals: dict[str, list[int]] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or not parts[0].startswith("utun"):
            continue
        numbers = [int(value) for value in parts[1:] if value.isdigit()]
        if len(numbers) >= 4:
            current = totals.setdefault(parts[0], [0, 0])
            current[0] = max(current[0], numbers[-4])
            current[1] = max(current[1], numbers[-1])
    if not totals:
        raise DriverError("No active utun interface was observed")
    name, values = max(totals.items(), key=lambda item: sum(item[1]))
    return name, values[0], values[1]


def public_egress_digest() -> str:
    values = []
    for url in ("https://api.ipify.org", "https://icanhazip.com"):
        result = run(["/usr/bin/curl", "--fail", "--silent", "--show-error", "--max-time", "15", url])
        value = result.stdout.strip()
        if not value:
            raise DriverError("Public egress canary returned no identity")
        values.append(value)
    if len(set(values)) != 1:
        raise DriverError("Public egress canaries disagree")
    return sha256_text(values[0])


def public_egress_value(url: str = "https://api.ipify.org") -> str:
    value = run(["/usr/bin/curl", "--fail", "--silent", "--show-error", "--max-time", "15", url]).stdout.strip()
    if not value:
        raise DriverError("Public egress canary returned no identity")
    return value


def resolve_ipv4(host: str) -> str:
    text = run(["/usr/bin/dscacheutil", "-q", "host", "-a", "name", host]).stdout
    addresses = re.findall(r"^ip_address:\s*([0-9.]+)$", text, re.MULTILINE)
    if not addresses:
        raise DriverError("Split canary hostname has no IPv4 address")
    return addresses[0]


def provider_executable_hash() -> str:
    result = run(["/usr/bin/pgrep", "-f", "org.winsvpn.app.*PacketTunnel"], check=False)
    for pid in result.stdout.split():
        opened = run(["/usr/sbin/lsof", "-a", "-p", pid, "-d", "txt", "-Fn"], check=False).stdout
        for line in opened.splitlines():
            if not line.startswith("n"):
                continue
            candidate = pathlib.Path(line[1:])
            if candidate.is_file() and not candidate.is_symlink() and "PacketTunnel" in candidate.name:
                return sha256_file(candidate)
    raise DriverError("Active PacketTunnel provider executable was not observed")


def set_double(enabled: bool) -> None:
    path = settings_path()
    settings: dict[str, Any] = {}
    if path.is_file() and not path.is_symlink():
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict): settings = value
    current = bool(settings.get("double_vpn_requested"))
    if current != enabled:
        ax("Double VPN")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            value = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
            if isinstance(value, dict) and bool(value.get("double_vpn_requested")) == enabled:
                return
            time.sleep(0.5)
        raise DriverError("Double VPN UI toggle did not persist requested state")


def double_requested() -> bool:
    path = settings_path()
    if not path.is_file() or path.is_symlink():
        return False
    value = json.loads(path.read_text(encoding="utf-8"))
    return isinstance(value, dict) and bool(value.get("double_vpn_requested"))


def connect_ui() -> None:
    ax("Connect VPN")
    wait_ax("Disconnect VPN", 120)


def disconnect_ui() -> None:
    ax("Disconnect VPN")
    wait_ax("Connect VPN", 60)


def bundle_manifest(root: pathlib.Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            lines.append(f"l|{relative}|{os.readlink(path)}")
        elif stat.S_ISREG(info.st_mode):
            lines.append(f"f|{relative}|{stat.S_IMODE(info.st_mode):04o}|{sha256_file(path)}")
        elif stat.S_ISDIR(info.st_mode):
            lines.append(f"d|{relative}|{stat.S_IMODE(info.st_mode):04o}")
        else:
            raise DriverError("Apple bundle contains unsupported filesystem object")
    return sha256_text("\n".join(lines) + "\n")


def codesign_identity(app: pathlib.Path) -> tuple[str, str]:
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
    detail = run(["/usr/bin/codesign", "-d", "--verbose=4", str(app)], check=False).stderr
    team = next((line.split("=", 1)[1].strip() for line in detail.splitlines() if line.startswith("TeamIdentifier=")), "")
    if not TEAM_ID_RE.fullmatch(team):
        raise DriverError("Installed Apple app has no valid TeamIdentifier")
    requirement = run(["/usr/bin/codesign", "-d", "-r-", str(app)], check=False).stderr
    return team, sha256_text(requirement)


def plist_identity(app: pathlib.Path) -> tuple[str, str]:
    with (app / "Contents/Info.plist" if (app / "Contents/Info.plist").is_file() else app / "Info.plist").open("rb") as handle:
        value = plistlib.load(handle)
    if value.get("CFBundleIdentifier") != BUNDLE_ID:
        raise DriverError("Installed Apple bundle identifier is wrong")
    version, build = str(value.get("CFBundleShortVersionString", "")), str(value.get("CFBundleVersion", ""))
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not build.isdigit():
        raise DriverError("Installed Apple version/build is invalid")
    return version, build


def find_one_app(root: pathlib.Path) -> pathlib.Path:
    apps = [path for path in root.rglob("*.app") if path.is_dir() and not path.is_symlink()]
    matches = []
    for app in apps:
        try:
            plist_identity(app)
            matches.append(app)
        except DriverError:
            continue
    if len(matches) != 1:
        raise DriverError("Artifact must contain exactly one Win's VPN app")
    return matches[0]


def app_bundle_identifier(app: pathlib.Path) -> str:
    info = app / "Contents/Info.plist"
    if not info.is_file():
        info = app / "Info.plist"
    try:
        with info.open("rb") as handle:
            value = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        return ""
    return str(value.get("CFBundleIdentifier", "")).strip()


def matching_macos_apps(roots: list[pathlib.Path]) -> list[pathlib.Path]:
    """Return real, non-nested host apps PackageKit could relocate into."""
    matches: set[pathlib.Path] = set()
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            continue
        for app in root.rglob("*.app"):
            try:
                resolved = app.resolve(strict=True)
            except OSError:
                continue
            if resolved.is_symlink() or not resolved.is_dir():
                continue
            # PacketTunnel.appex may contain nested helper apps in future; only
            # quarantine the universal host bundle itself.
            if app_bundle_identifier(resolved) == BUNDLE_ID:
                matches.add(resolved)
    return sorted(matches, key=lambda value: str(value))


def macos_relocation_roots(
    users_root: pathlib.Path = pathlib.Path("/Users"),
    *,
    minimum_user_uid: int = 500,
) -> list[pathlib.Path]:
    """Return bounded relocation roots for root and real macOS user homes.

    The collector runs as root, so Path.home() alone is /var/root rather than
    the interactive developer's home. Never scan an entire home; PackageKit's
    known LaunchServices candidates live only in these app/build subtrees.
    """
    homes = {pathlib.Path.home().resolve()}
    if users_root.is_dir() and not users_root.is_symlink():
        for candidate in users_root.iterdir():
            try:
                resolved = candidate.resolve(strict=True)
                info = resolved.stat()
            except OSError:
                continue
            if (
                resolved.parent == users_root.resolve()
                and resolved.is_dir()
                and not resolved.is_symlink()
                and info.st_uid >= minimum_user_uid
            ):
                homes.add(resolved)
    roots = [pathlib.Path("/Applications")]
    for home in sorted(homes, key=lambda value: str(value)):
        roots.extend(
            [
                home / "Applications",
                home / "Library/Developer/Xcode/DerivedData",
                # Frozen exact-candidate worktrees contain signed Debug/Profile
                # app bundles registered by Xcode with LaunchServices.
                home / ".winsvpn-release-candidates",
                home / "Downloads/wins_vpn/build",
            ]
        )
    return roots


def macos_relocation_candidates() -> list[pathlib.Path]:
    roots = macos_relocation_roots()
    matches = set(matching_macos_apps(roots))
    # LaunchServices is the source PackageKit uses for relocatable component
    # packages. Include its current result, but still validate every returned
    # bundle before moving it.
    query = run(
        [
            "/usr/bin/mdfind",
            f"kMDItemCFBundleIdentifier == '{BUNDLE_ID}'",
        ],
        check=False,
    )
    for raw in query.stdout.splitlines():
        candidate = pathlib.Path(raw.strip())
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if (
            resolved.suffix == ".app"
            and resolved.is_dir()
            and not resolved.is_symlink()
            and app_bundle_identifier(resolved) == BUNDLE_ID
        ):
            matches.add(resolved)
    return sorted(matches, key=lambda value: str(value))


def receipt_files(receipt_id: str = MACOS_RECEIPT_ID) -> list[pathlib.Path]:
    receipt_root = pathlib.Path("/var/db/receipts")
    return sorted(
        path
        for path in receipt_root.glob(f"{receipt_id}.*")
        if path.is_file() and not path.is_symlink()
    )


def restore_file_with_metadata(source: pathlib.Path, target: pathlib.Path) -> None:
    info = source.stat()
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target, follow_symlinks=False)
    os.chown(target, info.st_uid, info.st_gid)
    os.chmod(target, stat.S_IMODE(info.st_mode))


def persist_macos_install_rollback(
    prior_apps: list[tuple[pathlib.Path, pathlib.Path, bool]],
    prior_receipts: list[tuple[pathlib.Path, pathlib.Path]],
) -> None:
    """Persist pre-install state until the collector's mandatory finalization."""
    if MACOS_INSTALL_ROLLBACK_ROOT.exists() or MACOS_INSTALL_ROLLBACK_ROOT.is_symlink():
        raise DriverError("A prior macOS install rollback snapshot still exists")
    pending = STATE_ROOT / f"macos-install-rollback.pending.{os.getpid()}"
    if pending.exists() or pending.is_symlink():
        raise DriverError("macOS install rollback staging path is unsafe")
    pending.mkdir(mode=0o700)
    try:
        installed_backups = [backup for _, backup, was_installed in prior_apps if was_installed]
        if len(installed_backups) > 1:
            raise DriverError("Multiple prior /Applications bundles were quarantined")
        if installed_backups:
            shutil.copytree(
                installed_backups[0], pending / "prior-app", symlinks=True
            )
        receipt_names: list[str] = []
        receipt_root = pending / "receipts"
        receipt_root.mkdir(mode=0o700)
        for original, backup in prior_receipts:
            if original.parent != pathlib.Path("/var/db/receipts"):
                raise DriverError("Prior package receipt escaped the receipt database")
            receipt_names.append(original.name)
            restore_file_with_metadata(backup, receipt_root / original.name)
        manifest = {
            "schema_version": 1,
            "prior_app_present": bool(installed_backups),
            "prior_receipts": sorted(receipt_names),
        }
        manifest_path = pending / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.chown(manifest_path, 0, 0)
        os.chmod(manifest_path, 0o600)
        os.replace(pending, MACOS_INSTALL_ROLLBACK_ROOT)
    except Exception:
        if pending.exists() and not pending.is_symlink():
            shutil.rmtree(pending)
        raise


def restore_macos_install_rollback() -> bool:
    """Restore exact pre-install app/receipts, preserving state on any error."""
    root = MACOS_INSTALL_ROLLBACK_ROOT
    if not root.exists() and not root.is_symlink():
        return False
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise DriverError("macOS install rollback snapshot is unsafe")
    manifest_path = root / "manifest.json"
    if (
        not manifest_path.is_file()
        or manifest_path.is_symlink()
        or manifest_path.stat().st_uid != 0
        or stat.S_IMODE(manifest_path.stat().st_mode) != 0o600
    ):
        raise DriverError("macOS install rollback manifest is unsafe")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DriverError("macOS install rollback manifest is invalid") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "prior_app_present", "prior_receipts"}
        or manifest["schema_version"] != 1
        or not isinstance(manifest["prior_app_present"], bool)
        or not isinstance(manifest["prior_receipts"], list)
        or any(
            not isinstance(name, str)
            or pathlib.Path(name).name != name
            or not name.startswith(f"{MACOS_RECEIPT_ID}.")
            for name in manifest["prior_receipts"]
        )
        or len(set(manifest["prior_receipts"])) != len(manifest["prior_receipts"])
    ):
        raise DriverError("macOS install rollback manifest contract is invalid")
    prior_app = root / "prior-app"
    if manifest["prior_app_present"] != (
        prior_app.is_dir() and not prior_app.is_symlink()
    ):
        raise DriverError("macOS install rollback app state is inconsistent")
    receipt_root = root / "receipts"
    expected_receipts = {receipt_root / name for name in manifest["prior_receipts"]}
    if any(not path.is_file() or path.is_symlink() for path in expected_receipts):
        raise DriverError("macOS install rollback receipt state is incomplete")

    if MACOS_INSTALL_PATH.exists() or MACOS_INSTALL_PATH.is_symlink():
        unregister_app(MACOS_INSTALL_PATH)
        if MACOS_INSTALL_PATH.is_dir() and not MACOS_INSTALL_PATH.is_symlink():
            shutil.rmtree(MACOS_INSTALL_PATH)
        else:
            MACOS_INSTALL_PATH.unlink()
    run(["/usr/sbin/pkgutil", "--forget", MACOS_RECEIPT_ID], check=False)
    for current in receipt_files():
        current.unlink()
    if manifest["prior_app_present"]:
        shutil.copytree(prior_app, MACOS_INSTALL_PATH, symlinks=True)
        register_app(MACOS_INSTALL_PATH)
    for backup in sorted(expected_receipts, key=lambda value: value.name):
        restore_file_with_metadata(
            backup, pathlib.Path("/var/db/receipts") / backup.name
        )
    shutil.rmtree(root)
    return True


def unregister_app(app: pathlib.Path) -> None:
    registrar = pathlib.Path(
        "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/"
        "LaunchServices.framework/Versions/A/Support/lsregister"
    )
    if registrar.is_file():
        run([str(registrar), "-u", str(app)], check=False)


def register_app(app: pathlib.Path) -> None:
    registrar = pathlib.Path(
        "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/"
        "LaunchServices.framework/Versions/A/Support/lsregister"
    )
    if registrar.is_file():
        run([str(registrar), "-f", str(app)], check=False)


def install_macos_package_exact(
    artifact: pathlib.Path,
    source_app: pathlib.Path,
    temp: pathlib.Path,
) -> tuple[subprocess.CompletedProcess[str], str]:
    """Install at /Applications while preserving every pre-install byte.

    Xcode App Store component packages are relocatable. PackageKit can silently
    redirect an upgrade into a DerivedData copy registered by LaunchServices.
    Quarantine all validated host-bundle matches, forget only this package's
    receipt, and restore development copies and prior receipts on every exit.
    """
    source_manifest = bundle_manifest(source_app)
    quarantine = temp / "relocation-quarantine"
    quarantine.mkdir(mode=0o700)
    receipt_backup = temp / "receipt-backup"
    receipt_backup.mkdir(mode=0o700)

    prior_apps: list[tuple[pathlib.Path, pathlib.Path, bool]] = []
    for index, app in enumerate(macos_relocation_candidates()):
        destination = quarantine / f"app-{index}"
        unregister_app(app)
        shutil.move(str(app), str(destination))
        prior_apps.append((app, destination, app == MACOS_INSTALL_PATH))

    prior_receipts: list[tuple[pathlib.Path, pathlib.Path]] = []
    for index, receipt in enumerate(receipt_files()):
        destination = receipt_backup / f"receipt-{index}"
        shutil.copy2(receipt, destination, follow_symlinks=False)
        prior_receipts.append((receipt, destination))

    install_succeeded = False
    session: subprocess.CompletedProcess[str] | None = None
    try:
        run(["/usr/sbin/pkgutil", "--forget", MACOS_RECEIPT_ID], check=False)
        session = run(
            ["/usr/sbin/installer", "-pkg", str(artifact), "-target", "/"],
            timeout=300,
        )
        installed = MACOS_INSTALL_PATH
        if not installed.is_dir() or installed.is_symlink():
            raise DriverError("PackageKit did not install Win's VPN at /Applications")
        if bundle_manifest(installed) != source_manifest:
            raise DriverError("Installed macOS app does not match signed package payload")
        persist_macos_install_rollback(prior_apps, prior_receipts)
        install_succeeded = True
        return session, source_manifest
    finally:
        cleanup_errors: list[str] = []
        if not install_succeeded:
            try:
                if MACOS_INSTALL_PATH.exists():
                    shutil.rmtree(MACOS_INSTALL_PATH)
                run(["/usr/sbin/pkgutil", "--forget", MACOS_RECEIPT_ID], check=False)
                for original, backup in prior_receipts:
                    restore_file_with_metadata(backup, original)
            except (OSError, DriverError) as error:
                cleanup_errors.append(f"receipt rollback: {type(error).__name__}")
        for original, backup, was_installed in prior_apps:
            if install_succeeded and was_installed:
                continue
            try:
                if original.exists():
                    if original.is_dir() and not original.is_symlink():
                        shutil.rmtree(original)
                    else:
                        original.unlink()
                original.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(backup), str(original))
                register_app(original)
            except OSError as error:
                cleanup_errors.append(f"app rollback: {type(error).__name__}")
        if install_succeeded:
            register_app(MACOS_INSTALL_PATH)
        if cleanup_errors:
            raise DriverError(
                "macOS exact package install rollback failed closed: "
                + ", ".join(cleanup_errors)
            )


def clean_install(
    platform: str,
    artifact: pathlib.Path,
    route_inventory: pathlib.Path | None = None,
    ssh_config: pathlib.Path | None = None,
) -> dict[str, Any]:
    artifact_descriptor = _descriptor_path_fd(os.fspath(artifact))
    if artifact_descriptor is None:
        raise DriverError(
            "exact Apple clean install requires an inherited retained artifact descriptor"
        )
    artifact_snapshot = _descriptor_identity(artifact_descriptor)
    artifact_hash = artifact_snapshot[-1]
    with tempfile.TemporaryDirectory(prefix="wins-apple-install-") as name:
        temp = pathlib.Path(name)
        if platform == "macos":
            expanded = temp / "expanded"
            run(["/usr/sbin/pkgutil", "--expand-full", str(artifact), str(expanded)])
            source_app = find_one_app(expanded)
            session, source_manifest = install_macos_package_exact(
                artifact, source_app, temp
            )
            installed = MACOS_INSTALL_PATH
            version, build = plist_identity(installed)
            team, requirement = codesign_identity(installed)
            install_method = "macos-signed-package"
            session_hash = sha256_text(artifact_hash + "\n" + source_manifest + "\n" + session.stdout)
            identity_hash = source_manifest
        else:
            if route_inventory is None:
                raise DriverError("iOS exact clean install requires a fresh hash-bound route inventory")
            if ssh_config is None:
                raise DriverError("iOS exact clean install requires a root-owned pinned SSH config")
            with os.fdopen(os.dup(artifact_descriptor), "rb") as artifact_stream:
                artifact_stream.seek(0)
                with zipfile.ZipFile(artifact_stream) as archive:
                    for info in archive.infolist():
                        path = pathlib.PurePosixPath(info.filename)
                        if path.is_absolute() or ".." in path.parts:
                            raise DriverError("IPA contains an unsafe path")
                    archive.extractall(temp / "ipa")
            source_app = find_one_app(temp / "ipa")
            source_manifest = bundle_manifest(source_app)
            device = ios_device_id()
            run(["/usr/bin/xcrun", "devicectl", "device", "uninstall", "app", "--device", device, BUNDLE_ID], check=False, timeout=120)
            session = run(["/usr/bin/xcrun", "devicectl", "device", "install", "app", "--device", device, str(source_app)], timeout=300)
            version, build = plist_identity(source_app)
            team, requirement = codesign_identity(source_app)
            installed_record_hash = ios_installed_record(device, version, build)
            prepare_ios_xctest_runtime(
                source_app, artifact, route_inventory, ssh_config, device, version, build,
                team, requirement, installed_record_hash,
            )
            install_method = "xcode-devicectl-exact-ipa"
            session_hash = sha256_text(artifact_hash + "\n" + source_manifest + "\n" + session.stdout)
            identity_hash = sha256_text(source_manifest + "\n" + team + "\n" + version + "\n" + build + "\n" + installed_record_hash)
        if _descriptor_identity(artifact_descriptor) != artifact_snapshot:
            raise DriverError("retained Apple release artifact changed during clean install")
        return {
            "source_artifact_sha256": artifact_hash,
            "clean_remove_passed": True,
            "install_passed": True,
            "installed_identity_sha256": identity_hash,
            "exact_install_source_verified": True,
            "app_version": version,
            "build_number": build,
            "install_method": install_method,
            "installed_bundle_id": BUNDLE_ID,
            "installed_team_id": team,
            "installed_designated_requirement_sha256": requirement,
            "install_session_sha256": session_hash,
        }


def ios_device_id() -> str:
    with tempfile.NamedTemporaryFile(suffix=".json") as handle:
        run(["/usr/bin/xcrun", "devicectl", "list", "devices", "--timeout", "10", "--json-output", handle.name])
        value = json.loads(pathlib.Path(handle.name).read_text(encoding="utf-8"))
    devices = value.get("result", {}).get("devices", []) if isinstance(value, dict) else []
    identifiers = sorted({
        str(device.get("identifier"))
        for device in devices
        if isinstance(device, dict)
        and device.get("hardwareProperties", {}).get("platform") == "iOS"
        and device.get("hardwareProperties", {}).get("reality") == "physical"
        and isinstance(device.get("identifier"), str)
        and device.get("identifier")
    })
    if len(identifiers) != 1:
        raise DriverError("Exactly one unlocked physical iOS device must be available")
    return identifiers[0]


def ios_installed_record(device: str, version: str, build: str) -> str:
    with tempfile.NamedTemporaryFile(suffix=".json") as handle:
        run(["/usr/bin/xcrun", "devicectl", "device", "info", "apps", "--device", device, "--json-output", handle.name], timeout=120)
        value = json.loads(pathlib.Path(handle.name).read_text(encoding="utf-8"))
    matches: list[dict[str, Any]] = []
    def walk(node: Any) -> None:
        if isinstance(node, dict):
            identifiers = [node.get(key) for key in ("bundleIdentifier", "bundleID", "identifier")]
            if BUNDLE_ID in identifiers:
                matches.append(node)
            for child in node.values(): walk(child)
        elif isinstance(node, list):
            for child in node: walk(child)
    walk(value)
    if len(matches) != 1:
        raise DriverError("devicectl did not report exactly one installed Win's VPN app")
    record = matches[0]
    versions = {str(record.get(key, "")) for key in ("version", "shortVersion", "bundleShortVersion")}
    builds = {str(record.get(key, "")) for key in ("buildVersion", "bundleVersion", "build")}
    if version not in versions or build not in builds:
        raise DriverError("devicectl installed version/build does not match exact IPA")
    sanitized = {"bundle_id": BUNDLE_ID, "version": version, "build": build}
    return sha256_text(json.dumps(sanitized, sort_keys=True))


def _secure_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_secure_json(path: pathlib.Path, fields: set[str], label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise DriverError(f"{label} is missing or unsafe")
    info = path.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 256 * 1024:
        raise DriverError(f"{label} ownership, mode, or size is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != fields:
        raise DriverError(f"{label} contract is invalid")
    return value


def validate_ios_route_inventory(path: pathlib.Path) -> tuple[dict[str, Any], str]:
    path = safe_regular(path, "iOS route inventory")
    if path.stat().st_size > 128 * 1024:
        raise DriverError("iOS route inventory is unexpectedly large")
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "contract", "captured_at_utc", "node", "double_vpn",
        "secret_material_redacted",
    }:
        raise DriverError("iOS route inventory fields are invalid")
    if value["schema_version"] != 1 or value["contract"] != "winsvpn-android-route-inventory-v1" or value["secret_material_redacted"] is not True:
        raise DriverError("iOS route inventory contract is invalid")
    try:
        captured = dt.datetime.fromisoformat(
            str(value["captured_at_utc"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise DriverError("iOS route inventory timestamp is invalid") from exc
    if (
        captured.tzinfo is None
        or abs(dt.datetime.now(dt.timezone.utc) - captured.astimezone(dt.timezone.utc))
        > dt.timedelta(hours=1)
    ):
        raise DriverError("iOS route inventory is stale or future-dated")
    for mode_name in ("node", "double_vpn"):
        mode = value[mode_name]
        if not isinstance(mode, dict) or set(mode) != {
            "direct", "advertised_xray_routes", "core_id_sha256", "exit_slug_sha256"
        }:
            raise DriverError("iOS route inventory mode is invalid")
        direct = mode["direct"]
        if not isinstance(direct, dict) or set(direct) != {"protocol", "port", "ssh_alias"} or direct["protocol"] != "udp":
            raise DriverError("iOS direct route inventory is invalid")
        port = direct["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise DriverError("iOS direct route port is invalid")
        if not isinstance(direct["ssh_alias"], str) or not SSH_ALIAS_RE.fullmatch(direct["ssh_alias"]):
            raise DriverError("iOS direct route SSH alias is invalid")
        routes = mode["advertised_xray_routes"]
        if not isinstance(routes, list) or not routes or len(routes) > 16:
            raise DriverError("iOS advertised Xray route inventory is invalid")
        keys: set[tuple[int, str]] = set()
        ports: set[int] = set()
        for route in routes:
            if not isinstance(route, dict) or set(route) != {"protocol", "port", "security", "ssh_alias"}:
                raise DriverError("iOS advertised Xray route is invalid")
            key = (route["port"], route["security"])
            if route["protocol"] != "tcp" or route["security"] not in {"none", "tls"} or isinstance(route["port"], bool) or not isinstance(route["port"], int) or not 1 <= route["port"] <= 65535 or key in keys or route["port"] in ports:
                raise DriverError("iOS Xray routes must be valid and uniquely forceable by port")
            if not isinstance(route["ssh_alias"], str) or not SSH_ALIAS_RE.fullmatch(route["ssh_alias"]):
                raise DriverError("iOS Xray route SSH alias is invalid")
            keys.add(key); ports.add(route["port"])
        for field in ("core_id_sha256", "exit_slug_sha256"):
            digest = str(mode[field])
            if not SHA_RE.fullmatch(digest):
                raise DriverError("iOS route inventory identity digest is invalid")
            empty = sha256_text("")
            if (mode_name == "node" and digest != empty) or (mode_name == "double_vpn" and digest in {empty, "0" * 64}):
                raise DriverError("iOS route inventory Double VPN identity is inconsistent")
    if value["node"]["direct"]["port"] != 9110:
        raise DriverError("iOS public node direct AWG must use UDP 9110")
    return value, sha256_file(path)


def _harden_tree(root: pathlib.Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            raise DriverError("iOS XCTest runtime must not contain symlinks")
        os.chown(path, os.geteuid(), os.getegid())
        os.chmod(path, 0o555 if path.is_dir() or os.access(path, os.X_OK) else 0o444)
    os.chown(root, os.geteuid(), os.getegid()); os.chmod(root, 0o555)


def _exact_ui_test_executable(products: pathlib.Path) -> pathlib.Path:
    candidates = [
        path
        for path in products.rglob("RunnerUITests")
        if path.parent.name == "RunnerUITests.xctest"
        and path.is_file()
        and not path.is_symlink()
    ]
    if len(candidates) != 1:
        raise DriverError("Xcode Products must contain exactly one RunnerUITests executable")
    return candidates[0]


def _rewrite_xctestrun(value: Any, old_products: str, new_products: str, exact_app: str) -> Any:
    if isinstance(value, dict):
        rewritten = {key: _rewrite_xctestrun(item, old_products, new_products, exact_app) for key, item in value.items()}
        if rewritten.get("IsUITestBundle") is True:
            rewritten["UITargetAppPath"] = exact_app
            rewritten["UITargetAppBundleIdentifier"] = BUNDLE_ID
            dependencies = rewritten.get("DependentProductPaths")
            if isinstance(dependencies, list):
                rewritten["DependentProductPaths"] = [
                    exact_app if isinstance(item, str) and item.endswith("/Runner.app") else item
                    for item in dependencies
                ]
        return rewritten
    if isinstance(value, list):
        return [_rewrite_xctestrun(item, old_products, new_products, exact_app) for item in value]
    if isinstance(value, str):
        return value.replace(old_products, new_products)
    return value


def _inject_xctest_environment(value: Any, environment: dict[str, str]) -> int:
    """Inject only UI-test targets, including modern nested xctestrun layouts."""
    found = 0
    if isinstance(value, dict):
        if value.get("IsUITestBundle") is True:
            value["EnvironmentVariables"] = dict(environment)
            found += 1
        for item in value.values():
            found += _inject_xctest_environment(item, environment)
    elif isinstance(value, list):
        for item in value:
            found += _inject_xctest_environment(item, environment)
    return found


def prepare_ios_xctest_runtime(
    source_app: pathlib.Path,
    artifact: pathlib.Path,
    route_inventory: pathlib.Path,
    ssh_config: pathlib.Path,
    device: str,
    version: str,
    build: str,
    team: str,
    requirement: str,
    installed_record: str,
) -> None:
    artifact_descriptor = _descriptor_path_fd(os.fspath(artifact))
    if artifact_descriptor is None:
        raise DriverError("iOS XCTest runtime requires a retained IPA descriptor")
    artifact_snapshot = _descriptor_identity(artifact_descriptor)
    inventory, inventory_sha = validate_ios_route_inventory(route_inventory)
    ssh_config = safe_regular(ssh_config, "iOS release SSH config")
    if ssh_config.stat().st_uid != 0 or stat.S_IMODE(ssh_config.stat().st_mode) != 0o600:
        raise DriverError("iOS release SSH config must be root-owned mode 0600")
    ssh_config_sha = sha256_file(ssh_config)
    repo = pathlib.Path.cwd().resolve(strict=True)
    if IOS_RUNTIME_ROOT.exists() or IOS_RUNTIME_ROOT.is_symlink():
        raise DriverError("A prior iOS XCTest runtime remains; finalize it before a new install")
    name, uid, home = console_identity()
    if repo.lstat().st_uid != uid:
        raise DriverError("iOS XCTest repository must be owned by the console build user")
    private_parent = pathlib.Path(
        tempfile.mkdtemp(prefix="wins-ios-xctest-build-", dir="/private/tmp")
    )
    os.chown(private_parent, 0, 0)
    os.chmod(private_parent, 0o700)
    source_snapshot = private_parent / "Source"
    source_snapshot_sha, source_snapshot_entries, source_snapshot_bytes = _copy_source_inputs(
        repo,
        source_snapshot,
        expected_uid=uid,
    )
    _harden_tree(source_snapshot)
    rebound_source = _tree_binding(
        source_snapshot,
        expected_uid=0,
        label="immutable iOS XCTest source snapshot",
    )
    source_snapshot_sha, source_snapshot_entries, source_snapshot_bytes = rebound_source
    workspace = source_snapshot / "ios/Runner.xcworkspace"
    test_source = source_snapshot / "ios/RunnerUITests/VpnPermissionUITests.swift"
    entitlements = source_snapshot / "ios/RunnerUITests/RunnerUITests.entitlements"
    project = source_snapshot / "ios/Runner.xcodeproj/project.pbxproj"
    scheme = source_snapshot / "ios/Runner.xcodeproj/xcshareddata/xcschemes/Runner.xcscheme"
    if not workspace.is_dir() or workspace.is_symlink() or any(
        not path.is_file() or path.is_symlink()
        for path in (test_source, entitlements, project, scheme)
    ):
        raise DriverError("immutable iOS XCTest source snapshot is incomplete")
    build_root = _create_console_build_root(private_parent, uid)
    pending: pathlib.Path | None = None
    try:
        command = [
            "/usr/bin/xcrun", "xcodebuild", "build-for-testing",
            "-workspace", str(workspace), "-scheme", "Runner", "-configuration", "Release",
            "-destination", f"id={device}", "-derivedDataPath", str(build_root),
            "-only-testing:RunnerUITests/VpnPermissionUITests/testPhysicalReleaseEvidenceAction",
        ]
        as_console(command, timeout=900)
        if _tree_binding(
            source_snapshot,
            expected_uid=0,
            label="immutable iOS XCTest source snapshot",
        ) != rebound_source:
            raise DriverError("immutable iOS XCTest source snapshot changed during compilation")
        pending = IOS_RUNTIME_ROOT.with_name(f"{IOS_RUNTIME_ROOT.name}.pending.{os.getpid()}")
        if pending.exists() or pending.is_symlink():
            raise DriverError("A stale pending iOS XCTest runtime remains")
        pending.mkdir(mode=0o700)
        products = pending / "Products"
        _copy_tree_no_follow(
            build_root,
            products,
            expected_uid=uid,
            label="console-user Xcode Products",
        )
        _harden_tree(products)
        products_binding = _tree_binding(
            products,
            expected_uid=0,
            label="bound Xcode Products",
        )
        candidates = [
            path
            for path in products.rglob("*.xctestrun")
            if path.is_file() and not path.is_symlink()
        ]
        if len(candidates) != 1:
            raise DriverError("Xcode did not produce exactly one iOS XCTest run specification")
        exact_app = pending / "Exact/Runner.app"
        exact_app.parent.mkdir(mode=0o700)
        _copy_tree_no_follow(
            source_app,
            exact_app,
            expected_uid=os.geteuid(),
            label="extracted exact IPA application",
        )
        _harden_tree(exact_app)
        exact_ipa = pending / "exact-candidate.ipa"
        exact_ipa_descriptor = os.open(
            exact_ipa,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            offset = 0
            while offset < artifact_snapshot[4]:
                block = os.pread(
                    artifact_descriptor,
                    min(1024 * 1024, artifact_snapshot[4] - offset),
                    offset,
                )
                if not block:
                    raise DriverError("retained IPA ended while its runtime copy was made")
                view = memoryview(block)
                while view:
                    written = os.write(exact_ipa_descriptor, view)
                    if written <= 0:
                        raise DriverError("retained IPA runtime copy write failed")
                    view = view[written:]
                offset += len(block)
            os.fsync(exact_ipa_descriptor)
        finally:
            os.close(exact_ipa_descriptor)
        if sha256_file(exact_ipa) != artifact_snapshot[-1]:
            raise DriverError("retained IPA runtime copy does not match the held candidate")
        raw = plistlib.loads(candidates[0].read_bytes())
        patched = _rewrite_xctestrun(raw, str(build_root), str(products), str(exact_app))
        patched_path = pending / "winsvpn-ios.xctestrun"
        patched_path.write_bytes(plistlib.dumps(patched, fmt=plistlib.FMT_XML, sort_keys=True))
        provider_apps = [path for path in exact_app.rglob("*.appex") if app_bundle_identifier(path) == f"{BUNDLE_ID}.PacketTunnel"]
        if len(provider_apps) != 1:
            raise DriverError("Exact IPA does not contain exactly one PacketTunnel provider")
        provider_executable = provider_apps[0] / "PacketTunnel"
        if not provider_executable.is_file() or provider_executable.is_symlink():
            raise DriverError("Exact IPA PacketTunnel executable is missing or unsafe")
        ui_test_executable = _exact_ui_test_executable(products)
        ui_test_relative = ui_test_executable.relative_to(products).as_posix()
        manifest = {
            "schema_version": 2,
            "contract": "winsvpn-ios-xctest-runtime-v2",
            "artifact_path": str(IOS_RUNTIME_ROOT / "exact-candidate.ipa"),
            "artifact_sha256": artifact_snapshot[-1],
            "source_app_manifest_sha256": bundle_manifest(exact_app),
            "provider_executable_sha256": sha256_file(provider_executable),
            "xctestrun_sha256": sha256_file(patched_path),
            "products_tree_sha256": products_binding[0],
            "products_tree_entries": products_binding[1],
            "products_tree_bytes": products_binding[2],
            "ui_test_executable_relative_path": ui_test_relative,
            "ui_test_executable_sha256": sha256_file(ui_test_executable),
            "ui_test_executable_bytes": ui_test_executable.stat().st_size,
            "source_snapshot_sha256": source_snapshot_sha,
            "source_snapshot_entries": source_snapshot_entries,
            "source_snapshot_bytes": source_snapshot_bytes,
            "test_source_sha256": sha256_file(test_source),
            "entitlements_sha256": sha256_file(entitlements),
            "project_sha256": sha256_file(project),
            "scheme_sha256": sha256_file(scheme),
            "route_inventory_sha256": inventory_sha,
            "ssh_config_sha256": ssh_config_sha,
            "device_sha256": sha256_text(device),
            "version": version, "build": build, "team": team,
            "requirement_sha256": requirement,
            "installed_record_sha256": installed_record,
            "secret_material_redacted": True,
        }
        (pending / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
        _harden_tree(pending)
        if _tree_binding(
            products,
            expected_uid=0,
            label="bound Xcode Products",
        ) != products_binding:
            raise DriverError("bound Xcode Products changed before runtime publication")
        if _descriptor_identity(artifact_descriptor) != artifact_snapshot:
            raise DriverError("retained IPA changed while the XCTest runtime was prepared")
        os.replace(pending, IOS_RUNTIME_ROOT)
        shutil.copy2(route_inventory, IOS_ROUTE_INVENTORY)
        os.chown(IOS_ROUTE_INVENTORY, 0, 0); os.chmod(IOS_ROUTE_INVENTORY, 0o600)
        shutil.copy2(ssh_config, IOS_SSH_CONFIG)
        os.chown(IOS_SSH_CONFIG, 0, 0); os.chmod(IOS_SSH_CONFIG, 0o600)
        _secure_json(IOS_BINDING, manifest)
    finally:
        if pending is not None and pending.exists() and not pending.is_symlink():
            _relax_sealed_tree_for_cleanup(pending)
            _remove_private_tree(pending)
        _relax_sealed_tree_for_cleanup(source_snapshot)
        _remove_private_tree(private_parent)


IOS_BINDING_FIELDS = {
    "schema_version", "contract", "artifact_path", "artifact_sha256",
    "source_app_manifest_sha256", "provider_executable_sha256", "xctestrun_sha256",
    "products_tree_sha256", "products_tree_entries", "products_tree_bytes",
    "ui_test_executable_relative_path", "ui_test_executable_sha256",
    "ui_test_executable_bytes", "source_snapshot_sha256",
    "source_snapshot_entries", "source_snapshot_bytes",
    "test_source_sha256", "entitlements_sha256", "route_inventory_sha256",
    "project_sha256", "scheme_sha256",
    "ssh_config_sha256",
    "device_sha256", "version", "build", "team", "requirement_sha256",
    "installed_record_sha256", "secret_material_redacted",
}


def ios_runtime_binding() -> tuple[dict[str, Any], dict[str, Any]]:
    binding = _read_secure_json(IOS_BINDING, IOS_BINDING_FIELDS, "iOS exact-install binding")
    if binding["schema_version"] != 2 or binding["contract"] != "winsvpn-ios-xctest-runtime-v2" or binding["secret_material_redacted"] is not True:
        raise DriverError("iOS exact-install binding contract is invalid")
    artifact = safe_regular(pathlib.Path(binding["artifact_path"]), "bound exact IPA")
    xctestrun = safe_regular(
        IOS_RUNTIME_ROOT / "winsvpn-ios.xctestrun", "bound iOS XCTest run specification"
    )
    exact_app = IOS_RUNTIME_ROOT / "Exact/Runner.app"
    products = IOS_RUNTIME_ROOT / "Products"
    relative_ui_test = binding["ui_test_executable_relative_path"]
    if (
        type(relative_ui_test) is not str
        or not relative_ui_test
        or pathlib.PurePosixPath(relative_ui_test).is_absolute()
        or ".." in pathlib.PurePosixPath(relative_ui_test).parts
    ):
        raise DriverError("bound iOS UI-test executable path is invalid")
    ui_test_executable = safe_regular(
        products.joinpath(*pathlib.PurePosixPath(relative_ui_test).parts),
        "bound iOS UI-test executable",
    )
    test_source = safe_regular(
        pathlib.Path.cwd().resolve() / "ios/RunnerUITests/VpnPermissionUITests.swift",
        "frozen iOS UI test source",
    )
    entitlements = safe_regular(
        pathlib.Path.cwd().resolve() / "ios/RunnerUITests/RunnerUITests.entitlements",
        "frozen iOS UI test entitlements",
    )
    project = safe_regular(
        pathlib.Path.cwd().resolve() / "ios/Runner.xcodeproj/project.pbxproj",
        "frozen iOS Xcode project",
    )
    scheme = safe_regular(
        pathlib.Path.cwd().resolve() / "ios/Runner.xcodeproj/xcshareddata/xcschemes/Runner.xcscheme",
        "frozen iOS Xcode scheme",
    )
    if (
        not IOS_RUNTIME_ROOT.is_dir()
        or IOS_RUNTIME_ROOT.is_symlink()
        or IOS_RUNTIME_ROOT.stat().st_uid != 0
        or not exact_app.is_dir()
        or exact_app.is_symlink()
    ):
        raise DriverError("Bound iOS XCTest runtime is missing or unsafe")
    products_binding = _tree_binding(
        products,
        expected_uid=0,
        label="bound Xcode Products",
    )
    comparisons = {
        "artifact_sha256": sha256_file(artifact),
        "source_app_manifest_sha256": bundle_manifest(exact_app),
        "xctestrun_sha256": sha256_file(xctestrun),
        "products_tree_sha256": products_binding[0],
        "ui_test_executable_sha256": sha256_file(ui_test_executable),
        "test_source_sha256": sha256_file(test_source),
        "entitlements_sha256": sha256_file(entitlements),
        "project_sha256": sha256_file(project),
        "scheme_sha256": sha256_file(scheme),
        "route_inventory_sha256": sha256_file(IOS_ROUTE_INVENTORY),
        "ssh_config_sha256": sha256_file(
            safe_regular(IOS_SSH_CONFIG, "bound iOS release SSH config")
        ),
    }
    for field, actual in comparisons.items():
        if binding[field] != actual:
            raise DriverError(f"iOS exact XCTest binding changed: {field}")
    for field, actual in (
        ("products_tree_entries", products_binding[1]),
        ("products_tree_bytes", products_binding[2]),
        ("ui_test_executable_bytes", ui_test_executable.stat().st_size),
    ):
        if type(binding[field]) is not int or binding[field] != actual:
            raise DriverError(f"iOS exact XCTest binding changed: {field}")
    for field in ("source_snapshot_sha256",):
        if type(binding[field]) is not str or SHA_RE.fullmatch(binding[field]) is None:
            raise DriverError(f"iOS exact XCTest binding field is invalid: {field}")
    for field in ("source_snapshot_entries", "source_snapshot_bytes"):
        if type(binding[field]) is not int or binding[field] <= 0:
            raise DriverError(f"iOS exact XCTest binding field is invalid: {field}")
    inventory, inventory_sha = validate_ios_route_inventory(IOS_ROUTE_INVENTORY)
    if inventory_sha != binding["route_inventory_sha256"]:
        raise DriverError("iOS route inventory binding changed")
    device = ios_device_id()
    if sha256_text(device) != binding["device_sha256"]:
        raise DriverError("A different physical iOS device is connected")
    if ios_installed_record(device, binding["version"], binding["build"]) != binding["installed_record_sha256"]:
        raise DriverError("Installed iOS app no longer matches the exact-install session")
    return binding, inventory


def _redacted_failure(text: str) -> str:
    value = re.sub(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", "[ip-redacted]", text)
    value = re.sub(rf"{re.escape(IOS_XCTEST_MARKER)}[A-Za-z0-9+/=]+", f"{IOS_XCTEST_MARKER}[redacted]", value)
    return value[-300:]


def run_ios_xctest(action: str, fields: dict[str, str] | None = None, *, keep_result: bool = False) -> tuple[dict[str, Any], pathlib.Path | None]:
    binding, _ = ios_runtime_binding()
    device = ios_device_id()
    base = plistlib.loads((IOS_RUNTIME_ROOT / "winsvpn-ios.xctestrun").read_bytes())
    environment = {"WINS_IOS_RELEASE_EVIDENCE": "1", "WINS_IOS_RELEASE_ACTION": action, **(fields or {})}
    found = _inject_xctest_environment(base, environment)
    if found != 1:
        raise DriverError("Patched iOS XCTest run specification lacks one UI-test target")
    _, uid, home = console_identity()
    temp = home / f"Library/Caches/winsvpn-ios-evidence-{uuid.uuid4().hex}"
    temp.mkdir(mode=0o700, parents=True)
    run_spec = temp / "action.xctestrun"
    run_spec.write_bytes(plistlib.dumps(base, fmt=plistlib.FMT_XML, sort_keys=True))
    result_bundle = temp / "result.xcresult"
    try:
        result = as_console([
            "/usr/bin/xcrun", "xcodebuild", "test-without-building",
            "-xctestrun", str(run_spec), "-destination", f"id={device}",
            "-only-testing:RunnerUITests/VpnPermissionUITests/testPhysicalReleaseEvidenceAction",
            "-resultBundlePath", str(result_bundle),
        ], timeout=420, check=False)
        if result.returncode != 0:
            raise DriverError(f"Physical iOS XCTest action failed: {_redacted_failure(result.stderr or result.stdout)}")
        encoded = re.findall(
            rf"{re.escape(IOS_XCTEST_MARKER)}([A-Za-z0-9+/=]+)",
            "\n".join((result.stdout, result.stderr)),
        )
        if len(encoded) != 1:
            raise DriverError("Physical iOS XCTest did not emit exactly one observation")
        try:
            observation = json.loads(base64.b64decode(encoded[0], validate=True))
        except (ValueError, json.JSONDecodeError) as exc:
            raise DriverError("Physical iOS XCTest observation is malformed") from exc
        if not isinstance(observation, dict) or observation.get("schema_version") != 1 or observation.get("contract") != IOS_XCTEST_CONTRACT or observation.get("secret_material_redacted") is not True or observation.get("action") not in {action, "rollback_probe"}:
            raise DriverError("Physical iOS XCTest observation contract is invalid")
        raw = json.dumps(observation, sort_keys=True).lower()
        if any(token in raw for token in ("privatekey", "presharedkey", "endpoint =", "http://", "https://")):
            raise DriverError("Physical iOS XCTest observation contains forbidden material")
        # xcodebuild may reinstall the exact app named by UITargetAppPath. Bind
        # the post-test device record again so a debug host app cannot pass.
        if ios_installed_record(device, binding["version"], binding["build"]) != binding["installed_record_sha256"]:
            raise DriverError("XCTest replaced the exact installed iOS candidate")
        if keep_result:
            retained = IOS_RUNTIME_ROOT / f"result-{uuid.uuid4().hex}.xcresult"
            shutil.move(result_bundle, retained)
            _harden_tree(retained)
            return observation, retained
        return observation, None
    finally:
        if temp.exists() and not temp.is_symlink():
            shutil.rmtree(temp)


def _exact_ios_observation(
    observation: dict[str, Any], action: str, fields: set[str]
) -> dict[str, Any]:
    expected = {
        "schema_version", "contract", "action", "secret_material_redacted", *fields
    }
    if set(observation) != expected or observation.get("action") != action:
        raise DriverError(f"Physical iOS {action} observation fields are invalid")
    return observation


def ios_route_call(action: str, *, mode: str | None = None, kind: str | None = None, port: int | None = None, security: str = "none", operation: str | None = None, source_ip: str | None = None) -> dict[str, Any]:
    if not IOS_ROUTE_CONTROLLER.is_file() or IOS_ROUTE_CONTROLLER.is_symlink():
        raise DriverError("The root-installed iOS route controller is missing or unsafe")
    command = [str(IOS_ROUTE_CONTROLLER), action, "--inventory", str(IOS_ROUTE_INVENTORY)]
    if action != "snapshot":
        if None in (mode, kind, port, operation):
            raise DriverError("iOS route operation arguments are incomplete")
        command += ["--mode", str(mode), "--lane-kind", str(kind), "--selected-port", str(port), "--security", security, "--operation-id", str(operation)]
    input_text = json.dumps({"source_public_ipv4": source_ip}) if action == "apply" else None
    result = run(
        command,
        input_text=input_text,
        timeout=90,
        check=False,
        extra_env={"WINSVPN_ANDROID_SSH_CONFIG": str(IOS_SSH_CONFIG)},
    )
    if result.returncode != 0:
        raise DriverError(f"iOS first-hop route control failed: {_redacted_failure(result.stderr or result.stdout)}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DriverError("iOS first-hop route controller returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("passed") is not True or value.get("secret_material_redacted") is not True:
        raise DriverError("iOS first-hop route controller failed closed")
    return value


def _route_controller_module() -> Any:
    source = pathlib.Path.cwd().resolve() / "tools/android_remote_route_control.py"
    if not source.is_file() or source.is_symlink() or sha256_file(source) != sha256_file(IOS_ROUTE_CONTROLLER):
        raise DriverError("Installed iOS route controller differs from frozen source")
    specification = importlib.util.spec_from_file_location("winsvpn_ios_route_controller", source)
    if specification is None or specification.loader is None:
        raise DriverError("iOS route controller module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    os.environ["WINSVPN_ANDROID_SSH_CONFIG"] = str(IOS_SSH_CONFIG)
    return module


def ios_failure_guard_apply(source_ip: str, operation: str) -> tuple[Any, dict[str, Any], list[tuple[str, str]]]:
    module = _route_controller_module()
    inventory, _ = module.load_inventory(IOS_ROUTE_INVENTORY)
    aliases: dict[str, list[dict[str, Any]]] = {}
    for mode_name in ("node", "double_vpn"):
        direct = inventory[mode_name]["direct"]
        aliases.setdefault(direct["ssh_alias"], []).append({"protocol": "udp", "port": direct["port"]})
        for route in inventory[mode_name]["advertised_xray_routes"]:
            aliases.setdefault(route["ssh_alias"], []).append({"protocol": "tcp", "port": route["port"]})
    applied: list[tuple[str, str]] = []
    before: dict[str, str] = {}
    try:
        for alias in sorted(aliases):
            remote_id = module.remote_operation_id(operation, alias)
            blocks = sorted({(item["protocol"], item["port"]) for item in aliases[alias]})
            result = module.ssh_call(alias, "apply", remote_id, {
                "schema_version": 1,
                "contract": "winsvpn-android-route-control-apply-v1",
                "source_ipv4": source_ip,
                "watchdog_seconds": 180,
                "observations": [],
                "blocks": [{"protocol": protocol, "port": port} for protocol, port in blocks],
            })
            if result.get("watchdog_armed") is not True or result.get("shared_nat_ambiguity_absent") is not True:
                raise DriverError("iOS rollback failure guard did not arm safely")
            applied.append((alias, remote_id))
            before[alias] = str(result["before_state_sha256"])
    except Exception:
        for alias, remote_id in reversed(applied):
            try: module.ssh_call(alias, "restore", remote_id)
            except Exception: pass
        raise
    return module, {"before_state_sha256": module.combined_state(before)}, applied


def ios_failure_guard_restore(module: Any, applied: list[tuple[str, str]], expected: str) -> None:
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    failures: list[str] = []
    for alias, remote_id in reversed(applied):
        try:
            result = module.ssh_call(alias, "restore", remote_id)
            before[alias] = str(result["before_state_sha256"])
            after[alias] = str(result["after_state_sha256"])
        except Exception:
            failures.append(alias)
    if failures or module.combined_state(before) != expected or module.combined_state(after) != expected:
        raise DriverError("iOS rollback failure guard did not restore exact remote state")


def ios_lane(lane_id: str, kind: str, port: int | None, security: str | None, expected_direct_port: int | None) -> dict[str, Any]:
    binding, inventory = ios_runtime_binding()
    desired_double = kind in {"double_vpn_direct", "double_vpn_xray"}
    is_xray = kind in {"xray", "double_vpn_xray"}
    mode_name = "double_vpn" if desired_double else "node"
    mode = inventory[mode_name]
    direct_port = mode["direct"]["port"]
    routes = [
        {key: item[key] for key in ("protocol", "port", "security")}
        for item in mode["advertised_xray_routes"]
    ]
    if is_xray:
        if expected_direct_port != direct_port or port is None or security is None:
            raise DriverError("iOS Xray lane does not match its mode-specific direct baseline")
        if {"protocol": "tcp", "port": port, "security": security} not in routes:
            raise DriverError("iOS Xray lane is not in the advertised route inventory")
        selected_port, selected_security, route_kind = port, security, "xray"
    else:
        selected_port, selected_security, route_kind = direct_port, "none", "direct"
    physical, _ = run_ios_xctest("physical_egress")
    _exact_ios_observation(physical, "physical_egress", {"source_public_ipv4"})
    source_ip = str(physical.get("source_public_ipv4", ""))
    try:
        parsed_source = ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise DriverError("Physical iOS XCTest returned an invalid transient source identity") from exc
    if parsed_source.version != 4 or parsed_source.is_private or parsed_source.is_loopback:
        raise DriverError("Physical iOS source identity is not a public IPv4 address")
    operation = uuid.uuid4().hex
    applied = ios_route_call(
        "apply", mode=mode_name, kind=route_kind, port=selected_port,
        security=selected_security, operation=operation, source_ip=source_ip,
    )
    observation: dict[str, Any] | None = None
    remote: dict[str, Any] | None = None
    restore: dict[str, Any] | None = None
    try:
        observation, _ = run_ios_xctest("lane", {
            "WINS_IOS_EXPECT_DOUBLE_VPN": "1" if desired_double else "0",
            "WINS_IOS_EXPECT_TRANSPORT_MODE": "xray_vless_ws_amneziawg" if is_xray else "amneziawg",
            "WINS_IOS_EXPECT_XRAY_SECURITY": selected_security,
            "WINS_IOS_EXPECT_XRAY_PORT": str(selected_port),
        })
        _exact_ios_observation(
            observation,
            "lane",
            {
                "double_vpn_active", "transport_mode", "rx_delta_bytes",
                "tx_delta_bytes", "protected_egress_sha256", "provider_healthy",
                "dns_count", "dns_full_tunnel_match_enabled",
                "ipv6_leak_protection_enabled",
            },
        )
        remote = ios_route_call(
            "observe", mode=mode_name, kind=route_kind, port=selected_port,
            security=selected_security, operation=operation,
        )
    finally:
        restore = ios_route_call(
            "restore", mode=mode_name, kind=route_kind, port=selected_port,
            security=selected_security, operation=operation,
        )
    if observation is None or remote is None or restore is None:
        raise DriverError("iOS route lane did not produce complete observations")
    if restore.get("after_state_sha256") != applied.get("before_state_sha256") or restore.get("before_state_sha256") != applied.get("before_state_sha256"):
        raise DriverError("iOS first-hop route forcing did not restore exact state")
    if remote.get("selected_port") != selected_port or remote.get("selected_security") != selected_security or remote.get("selected_bytes", 0) < 96:
        raise DriverError("iOS selected first-hop route lacks kernel-counter proof")
    if is_xray and (remote.get("direct_block_packets", 0) <= 0 or applied.get("watchdog_armed") is not True):
        raise DriverError("iOS forced Xray lane lacks blocked direct-attempt proof")
    rx = observation.get("rx_delta_bytes")
    tx = observation.get("tx_delta_bytes")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 96 for value in (rx, tx)):
        raise DriverError("iOS XCTest lacks bidirectional tunnel traffic counters")
    egress = str(observation.get("protected_egress_sha256", ""))
    if not SHA_RE.fullmatch(egress) or egress in {sha256_text(""), "0" * 64}:
        raise DriverError("iOS protected egress observation is invalid")
    if observation.get("provider_healthy") is not True:
        raise DriverError("iOS PacketTunnel provider was not healthy")
    expected_mode = "xray_vless_ws_amneziawg" if is_xray else "amneziawg"
    if (
        observation.get("double_vpn_active") is not desired_double
        or observation.get("transport_mode") != expected_mode
        or isinstance(observation.get("dns_count"), bool)
        or not isinstance(observation.get("dns_count"), int)
        or observation.get("dns_count", 0) <= 0
        or observation.get("dns_full_tunnel_match_enabled") is not True
        or observation.get("ipv6_leak_protection_enabled") is not True
    ):
        raise DriverError("iOS provider observation contradicts the requested lane")
    state = str(applied["before_state_sha256"])
    state_hash = sha256_text(state + "\n" + binding["artifact_sha256"] + "\n" + binding["installed_record_sha256"])
    core = mode["core_id_sha256"]
    exit_slug = mode["exit_slug_sha256"]
    return {
        "lane_id": lane_id, "kind": kind,
        "protocol": "tcp" if is_xray else "udp", "port": selected_port,
        "security": selected_security, "actual_direct_port": direct_port,
        "advertised_xray_routes": routes,
        "forcing_blocked_udp_port": direct_port if is_xray else None,
        "ui_connect_invoked": True, "ui_disconnect_invoked": True,
        "connected_observed": True, "double_vpn_active": desired_double,
        "rx_delta_bytes": rx, "tx_delta_bytes": tx,
        "protected_egress_sha256": egress,
        "provider_executable_sha256": binding["provider_executable_sha256"],
        "control_state_before_sha256": state_hash,
        "control_state_after_sha256": state_hash,
        "forcing_applied": is_xray, "forcing_restored": True,
        "double_vpn_core_id_sha256": core,
        "double_vpn_exit_slug_sha256": exit_slug,
    }


def lane(platform: str, lane_id: str, kind: str, port: int | None, security: str | None, expected_direct_port: int | None) -> dict[str, Any]:
    if platform == "ios":
        return ios_lane(lane_id, kind, port, security, expected_direct_port)
    launch_macos_app()
    desired_double = kind in {"double_vpn_direct", "double_vpn_xray"}
    saved_settings = settings_snapshot()
    state_before = control_state_hash()
    original_double = double_requested()
    connected = False
    prior_rules = ""; prior_enabled = pf_enabled(); applied = False
    try:
        set_double(desired_double)
        is_xray = kind in {"xray", "double_vpn_xray"}
        if is_xray:
            if port is None or security is None or expected_direct_port is None:
                raise DriverError("Xray lane requires a baseline-bound route and direct port")
            mode_direct_port, mode_routes, direct_addresses, xray_addresses = load_baseline(desired_double)
            if mode_direct_port != expected_direct_port:
                raise DriverError("Runtime direct first-hop port changed since baseline")
            if {"protocol": "tcp", "port": port, "security": security} not in mode_routes:
                raise DriverError("Requested Xray route was not observed in the mode baseline")
        else:
            mode_routes = []
            mode_direct_port = None
            direct_addresses, xray_addresses = [], []
            port, security = None, "none"
        applied, prior_rules, prior_enabled = apply_forcing(
            kind, port, mode_routes, mode_direct_port, direct_addresses, xray_addresses
        )
        connect_ui(); connected = True
        time.sleep(3)
        name, rx0, tx0 = utun_counters()
        egress = public_egress_digest()
        time.sleep(1)
        name2, rx1, tx1 = utun_counters()
        if name2 != name or rx1 - rx0 < 96 or tx1 - tx0 < 96:
            raise DriverError("Active Apple tunnel lacks bidirectional traffic proof")
        provider_hash = provider_executable_hash()
        active = runtime_config()
        actual_direct_port = runtime_direct_port(active)
        active_routes = advertised_routes(active)
        double_flag = active.get("double_vpn_active")
        if double_flag is None:
            double_flag = active.get("doublevpnactive")
        if not isinstance(double_flag, bool) or double_flag is not desired_double:
            raise DriverError("Live Apple Double VPN state contradicts the requested mode")
        if not is_xray:
            port = actual_direct_port
            save_baseline(desired_double, active)
        else:
            if actual_direct_port != mode_direct_port or active_routes != mode_routes:
                raise DriverError("Live Xray config differs from its machine-observed direct baseline")
        xray = active.get("xray") if isinstance(active.get("xray"), dict) else {}
        stealth = bool(active.get("stealth_active") or active.get("stealthactive"))
        if kind in {"xray", "double_vpn_xray"} and (not stealth or int(xray.get("port", 0)) != port or str(xray.get("security", "")).lower() != security):
            raise DriverError("Observed Xray route does not match requested advertised route")
        if kind in {"direct_awg", "double_vpn_direct"} and stealth:
            raise DriverError("Direct AWG lane unexpectedly used Xray")
        core = str(active.get("double_vpn_core_id") or active.get("doublevpncoreid") or "")
        exit_slug = str(active.get("double_vpn_exit_slug") or active.get("doublevpnexitslug") or "")
        return {
            "lane_id": lane_id, "kind": kind,
            "protocol": "tcp" if "xray" in kind else "udp", "port": port, "security": security,
            "actual_direct_port": actual_direct_port,
            "advertised_xray_routes": active_routes,
            "forcing_blocked_udp_port": actual_direct_port if is_xray else None,
            "ui_connect_invoked": True, "ui_disconnect_invoked": True, "connected_observed": True,
            "double_vpn_active": desired_double,
            "rx_delta_bytes": rx1 - rx0, "tx_delta_bytes": tx1 - tx0,
            "protected_egress_sha256": egress, "provider_executable_sha256": provider_hash,
            "control_state_before_sha256": state_before, "control_state_after_sha256": state_before,
            "forcing_applied": applied, "forcing_restored": True,
            "double_vpn_core_id_sha256": sha256_text(core),
            "double_vpn_exit_slug_sha256": sha256_text(exit_slug),
        }
    finally:
        cleanup_error: DriverError | None = None
        if connected:
            try: disconnect_ui()
            except DriverError as exc: cleanup_error = exc
        try: set_double(original_double)
        finally:
            restore_settings(saved_settings)
            if applied or prior_rules or pf_enabled() != prior_enabled:
                restore_forcing(prior_rules, prior_enabled)
        if control_state_hash() != state_before:
            raise DriverError("Apple lane did not restore exact control state")
        if cleanup_error is not None:
            raise DriverError("Apple lane failed deterministic UI disconnect") from cleanup_error


def simple_action(action: str, platform: str) -> dict[str, Any]:
    if platform == "ios":
        if action in {"split", "leak", "network_change", "teardown"}:
            observed, _ = run_ios_xctest(action)
            expected_fields = {
                "split": {"scope", "consumer_per_app_available", "mdm_per_app_only", "selection_applied_by_harness", "selected_scope_bypassed", "ordinary_scope_protected"},
                "leak": {"dns_protected", "ipv4_protected", "ipv6_escape_blocked", "public_canaries_agree"},
                "network_change": {"change_triggered_by_harness", "pre_change_protected", "post_change_recovered", "post_change_protected"},
                "teardown": {"disconnect_requested_by_harness", "provider_absent", "protected_routes_absent", "transient_state_absent"},
            }[action]
            _exact_ios_observation(observed, action, expected_fields)
            return {key: value for key, value in observed.items() if key not in {"action", "schema_version", "contract", "secret_material_redacted"}}
        if action == "rollback":
            physical, _ = run_ios_xctest("physical_egress")
            _exact_ios_observation(physical, "physical_egress", {"source_public_ipv4"})
            source = str(physical.get("source_public_ipv4", ""))
            try:
                parsed = ipaddress.ip_address(source)
            except ValueError as exc:
                raise DriverError("iOS rollback source identity is invalid") from exc
            if parsed.version != 4 or parsed.is_private or parsed.is_loopback:
                raise DriverError("iOS rollback requires a public source identity")
            operation = uuid.uuid4().hex
            module, before, applied = ios_failure_guard_apply(source, operation)
            probe: dict[str, Any] | None = None
            try:
                probe, _ = run_ios_xctest("rollback")
            finally:
                ios_failure_guard_restore(module, applied, before["before_state_sha256"])
            if probe is None or set(probe) != {
                "schema_version", "contract", "secret_material_redacted", "action",
                "failure_injected_by_harness", "prior_state_sha256", "restored_state_sha256",
            } or probe.get("failure_injected_by_harness") is not True or probe.get("prior_state_sha256") != probe.get("restored_state_sha256"):
                raise DriverError("iOS rollback failure probe is invalid")
            # Recovery is an independent post-restore direct connection, not a
            # boolean supplied by the failure probe.
            recovery, _ = run_ios_xctest("lane", {
                "WINS_IOS_EXPECT_DOUBLE_VPN": "0",
                "WINS_IOS_EXPECT_TRANSPORT_MODE": "amneziawg",
                "WINS_IOS_EXPECT_XRAY_SECURITY": "none",
                "WINS_IOS_EXPECT_XRAY_PORT": "9110",
            })
            if recovery.get("provider_healthy") is not True:
                raise DriverError("iOS rollback recovery connection did not pass")
            state_hash = sha256_text(before["before_state_sha256"] + "\n" + str(probe["prior_state_sha256"]))
            return {"failure_injected_by_harness": True, "prior_state_sha256": state_hash, "restored_state_sha256": state_hash, "recovery_connect_passed": True}
        raise DriverError("Unknown physical iOS observation action")
    if action == "split":
        launch_macos_app(); saved_settings = settings_snapshot(); before = control_state_hash(); physical = public_egress_value()
        canary_ip = resolve_ipv4("api.ipify.org")
        field_label = "Example: 192.168.0.0/16, 203.0.113.9"
        limitation = "Destination-based split tunneling is available. Apple permits per-app VPN only for MDM-managed apps and profiles, so it is not presented as a consumer feature."
        connected = False
        cleanup_error: DriverError | None = None
        try:
            ax("Split Tunneling"); time.sleep(1)
            ax(limitation, "exists")
            ax_set_value(field_label, f"{canary_ip}/32"); ax("Apply bypass destinations"); time.sleep(2)
            connect_ui(); connected = True
            bypass = public_egress_value("https://api.ipify.org")
            ordinary = public_egress_value("https://icanhazip.com")
            if bypass != physical or ordinary == physical:
                raise DriverError("Destination split did not bypass only the selected canary")
        finally:
            if connected:
                try: disconnect_ui()
                except DriverError as exc: cleanup_error = exc
            try:
                ax_set_value(field_label, ""); ax("Apply bypass destinations"); time.sleep(2)
            except DriverError as exc:
                if cleanup_error is None: cleanup_error = exc
            restore_settings(saved_settings)
        if control_state_hash() != before:
            raise DriverError("Destination split test did not restore exact settings")
        if cleanup_error is not None:
            raise DriverError("Destination split test failed deterministic UI cleanup") from cleanup_error
        return {"scope": "destination-consumer-mdm-per-app-only", "consumer_per_app_available": False, "mdm_per_app_only": True, "selection_applied_by_harness": True, "selected_scope_bypassed": True, "ordinary_scope_protected": True}
    if action == "leak":
        launch_macos_app(); physical4 = public_egress_value()
        physical6 = run(["/usr/bin/curl", "-6", "--fail", "--silent", "--max-time", "8", "https://api64.ipify.org"], check=False).stdout.strip()
        connect_ui()
        try:
            protected4 = public_egress_value()
            if protected4 == physical4: raise DriverError("IPv4 public egress remained physical")
            public_egress_digest()
            dns = run(["/usr/sbin/scutil", "--dns"]).stdout
            config = runtime_config()
            raw_dns = config.get("dns") or config.get("dns_servers") or config.get("dnsservers")
            if isinstance(raw_dns, list):
                configured_dns = [str(value).strip() for value in raw_dns if str(value).strip()]
            elif isinstance(raw_dns, str):
                configured_dns = raw_dns.replace(",", " ").split()
            else:
                configured_dns = []
            if not configured_dns or not all(value in dns for value in configured_dns):
                raise DriverError("Configured protected DNS resolvers were not observed")
            v6 = run(["/usr/bin/curl", "-6", "--fail", "--silent", "--max-time", "8", "https://api64.ipify.org"], check=False)
            ipv6_safe = v6.returncode != 0 or (bool(v6.stdout.strip()) and v6.stdout.strip() != physical6)
            if not ipv6_safe: raise DriverError("Public IPv6 escaped through the physical route")
            return {"dns_protected": True, "ipv4_protected": True, "ipv6_escape_blocked": True, "public_canaries_agree": True}
        finally: disconnect_ui()
    if action == "network_change":
        launch_macos_app(); connect_ui()
        try:
            public_egress_digest()
            service = run(["/usr/sbin/networksetup", "-listallhardwareports"]).stdout
            match = re.search(r"Hardware Port: Wi-Fi\nDevice: (\S+)", service)
            if not match: raise DriverError("No Wi-Fi device is available for transition test")
            device = match.group(1)
            run(["/usr/sbin/ipconfig", "set", device, "DHCP"])
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                try: public_egress_digest(); break
                except DriverError: time.sleep(2)
            else: raise DriverError("Tunnel did not recover after DHCP transition")
            return {"change_triggered_by_harness": True, "pre_change_protected": True, "post_change_recovered": True, "post_change_protected": True}
        finally: disconnect_ui()
    if action == "teardown":
        launch_macos_app()
        try: ax("Disconnect VPN"); wait_ax("Connect VPN", 60)
        except DriverError: wait_ax("Connect VPN", 10)
        default = run(["/sbin/route", "-n", "get", "1.1.1.1"], check=False).stdout
        provider = run(["/usr/bin/pgrep", "-f", "org.winsvpn.app.*PacketTunnel"], check=False)
        return {"disconnect_requested_by_harness": True, "provider_absent": provider.returncode != 0, "protected_routes_absent": "utun" not in default, "transient_state_absent": run(["/sbin/pfctl", "-a", PF_ANCHOR, "-sr"], check=False).stdout.strip() == ""}
    if action == "rollback":
        launch_macos_app(); before = control_state_hash()
        node_port, node_routes, _, _ = load_baseline(False)
        double_port, double_routes, _, _ = load_baseline(True)
        lines = [
            *(f"block drop out quick proto udp to any port = {port}" for port in sorted({node_port, double_port})),
            *(f"block drop out quick proto tcp to any port = {port}" for port in sorted({route['port'] for route in node_routes + double_routes})),
        ]
        rules = "\n".join(lines) + "\n"
        old = run(["/sbin/pfctl", "-a", PF_ANCHOR, "-sr"], check=False).stdout; enabled = pf_enabled()
        try:
            if not enabled: run(["/sbin/pfctl", "-E"])
            require_active_pf_anchor_hook()
            run(["/sbin/pfctl", "-a", PF_ANCHOR, "-f", "-"], input_text=rules)
            ax("Connect VPN")
            failed = False
            try: wait_ax("Connect VPN", 45); failed = True
            except DriverError: pass
            if not failed: raise DriverError("Injected transport failure did not fail connection")
        finally: restore_forcing(old, enabled)
        connect_ui(); public_egress_digest(); disconnect_ui()
        after = control_state_hash()
        if before != after: raise DriverError("Rollback did not restore exact state")
        return {"failure_injected_by_harness": True, "prior_state_sha256": before, "restored_state_sha256": after, "recovery_connect_passed": True}
    raise DriverError("Unknown simple Apple observation action")


def capture_map(platform: str, target: pathlib.Path) -> dict[str, Any]:
    if platform == "ios":
        observed, result_bundle = run_ios_xctest("capture_map", keep_result=True)
        if result_bundle is None or observed.get("map_target_semantic_present") is not True:
            raise DriverError("Physical iOS map XCTest did not retain a semantic screenshot")
        _, _, home = console_identity()
        export = home / f"Library/Caches/winsvpn-ios-map-export-{uuid.uuid4().hex}"
        try:
            as_console([
                "/usr/bin/xcrun", "xcresulttool", "export", "attachments",
                "--path", str(result_bundle), "--output-path", str(export),
            ], timeout=120)
            screenshots = [
                path for path in export.rglob("*")
                if path.is_file() and not path.is_symlink() and path.suffix.lower() in {".png", ".heic", ".jpg", ".jpeg"}
            ]
            if len(screenshots) != 1:
                raise DriverError("iOS XCTest result did not contain exactly one map screenshot")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                raise DriverError("Refusing to overwrite an existing iOS map screenshot")
            shutil.copy2(screenshots[0], target)
            os.chown(target, 0, 0); os.chmod(target, 0o600)
            semantic = json.loads(run([str(MAP_OBSERVER), str(target)]).stdout)
            expected = {"schema_version", "contract", "screenshot_sha256", "radius_label_50_miles_detected", "surrounding_city_labels", "viewport_not_world_zoom", "secret_material_redacted"}
            if not isinstance(semantic, dict) or set(semantic) != expected or semantic["contract"] != "winsvpn-apple-map-semantic-observer-v1" or semantic["secret_material_redacted"] is not True:
                raise DriverError("iOS map semantic observer output is invalid")
            cities = semantic["surrounding_city_labels"]
            if semantic["radius_label_50_miles_detected"] is not True or semantic["viewport_not_world_zoom"] is not True or not isinstance(cities, list) or len({str(city).strip().casefold() for city in cities if str(city).strip()}) < 2:
                raise DriverError("iOS map lacks the visible 50-mile/local-city viewport contract")
            return {"capture_method": "xcode-device-ui-capture", "screenshot_sha256": semantic["screenshot_sha256"], "radius_label_50_miles_detected": True, "surrounding_city_labels": cities, "target_marker_detected": True, "viewport_not_world_zoom": True}
        finally:
            if result_bundle.exists() and not result_bundle.is_symlink(): shutil.rmtree(result_bundle)
            if export.exists() and not export.is_symlink(): shutil.rmtree(export)
    launch_macos_app(); ax("Explore map"); time.sleep(3)
    window_script = 'tell application "System Events" to tell first application process whose bundle identifier is "org.winsvpn.app" to return value of attribute "AXWindowNumber" of front window'
    window_id = as_console(["/usr/bin/osascript", "-e", window_script]).stdout.strip()
    if not window_id.isdigit(): raise DriverError("macOS app window number is unavailable")
    target.parent.mkdir(parents=True, exist_ok=True)
    run(["/usr/sbin/screencapture", "-x", "-l", window_id, str(target)])
    ax("Your approximate network location", "exists")
    observed = json.loads(run([str(MAP_OBSERVER), str(target)]).stdout)
    expected = {"schema_version", "contract", "screenshot_sha256", "radius_label_50_miles_detected", "surrounding_city_labels", "viewport_not_world_zoom", "secret_material_redacted"}
    if not isinstance(observed, dict) or set(observed) != expected or observed["contract"] != "winsvpn-apple-map-semantic-observer-v1" or observed["secret_material_redacted"] is not True:
        raise DriverError("Map semantic observer output is invalid")
    ax("Close map")
    return {"capture_method": "macos-window-capture", "screenshot_sha256": observed["screenshot_sha256"], "radius_label_50_miles_detected": observed["radius_label_50_miles_detected"], "surrounding_city_labels": observed["surrounding_city_labels"], "target_marker_detected": True, "viewport_not_world_zoom": observed["viewport_not_world_zoom"]}


def finalize(platform: str) -> dict[str, Any]:
    if platform == "macos":
        residual = run(["/sbin/pfctl", "-a", PF_ANCHOR, "-sr"], check=False).stdout.strip()
        if residual:
            raise DriverError("Apple release forcing rules remain active at finalization")
        restore_macos_install_rollback()
    if platform == "ios":
        # Remote guards are individually watchdog-restored; a fresh snapshot
        # must prove none remain before local bindings are removed.
        if IOS_ROUTE_INVENTORY.exists():
            snapshot = ios_route_call("snapshot")
            if snapshot.get("active_operation_count") != 0:
                raise DriverError("iOS route-control state remains active at finalization")
        if IOS_RUNTIME_ROOT.exists() or IOS_RUNTIME_ROOT.is_symlink():
            if not IOS_RUNTIME_ROOT.is_dir() or IOS_RUNTIME_ROOT.is_symlink() or IOS_RUNTIME_ROOT.stat().st_uid != 0:
                raise DriverError("iOS XCTest runtime is unsafe at finalization")
            shutil.rmtree(IOS_RUNTIME_ROOT)
        for path in (IOS_BINDING, IOS_ROUTE_INVENTORY, IOS_SSH_CONFIG):
            if path.exists() or path.is_symlink():
                if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0:
                    raise DriverError("iOS release binding is unsafe at finalization")
                path.unlink()
    for double in (False, True):
        path = baseline_path(double)
        if path.exists() or path.is_symlink():
            if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0:
                raise DriverError("Apple release baseline is unsafe at finalization")
            path.unlink()
    return {"restored": True, "baseline_state_removed": True}


def self_test() -> None:
    assert advertised_routes({"xray": {"transports": [{"port": 80, "security": "none"}, {"port": 443, "security": "tls"}]}})[1]["port"] == 443
    try: advertised_routes({"xray": {"transports": [{"port": 80, "security": "none"}] * 2}})
    except DriverError: pass
    else: raise DriverError("duplicate route self-test failed")
    assert IOS_XCTEST_MARKER.endswith(":")
    assert IOS_XCTEST_CONTRACT.startswith("winsvpn-ios-")
    print("APPLE RELEASE UI DRIVER SELF-TEST: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["clean_install", "lane", "split", "leak", "network_change", "teardown", "rollback", "capture_map", "finalize", "self_test"])
    parser.add_argument("--platform", choices=["macos", "ios"])
    parser.add_argument("--artifact")
    parser.add_argument("--route-inventory")
    parser.add_argument("--ssh-config")
    parser.add_argument("--output")
    parser.add_argument("--lane-id")
    parser.add_argument("--kind", choices=["direct_awg", "xray", "double_vpn_direct", "double_vpn_xray"])
    parser.add_argument("--port", type=int)
    parser.add_argument("--security", choices=["none", "tls"])
    parser.add_argument("--direct-port", type=int)
    args = parser.parse_args()
    if args.action == "self_test": self_test(); return 0
    require_darwin_root()
    if not args.platform: raise DriverError("--platform is required")
    if args.action == "clean_install":
        if not args.artifact: raise DriverError("--artifact is required")
        inventory = pathlib.Path(args.route_inventory) if args.route_inventory else None
        ssh_config = pathlib.Path(args.ssh_config) if args.ssh_config else None
        output("clean_install", **clean_install(args.platform, pathlib.Path(args.artifact), inventory, ssh_config)); return 0
    if args.action == "lane":
        if not all((args.lane_id, args.kind)): raise DriverError("lane identity arguments are required")
        output("lane", **lane(args.platform, args.lane_id, args.kind, args.port, args.security, args.direct_port)); return 0
    if args.action == "capture_map":
        if not args.output: raise DriverError("--output is required")
        output("capture_map", **capture_map(args.platform, pathlib.Path(args.output))); return 0
    if args.action == "finalize":
        output("finalize", **finalize(args.platform)); return 0
    output(args.action, **simple_action(args.action, args.platform)); return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (DriverError, json.JSONDecodeError, OSError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        print(f"APPLE RELEASE UI DRIVER: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
