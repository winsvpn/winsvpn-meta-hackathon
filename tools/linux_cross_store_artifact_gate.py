#!/usr/bin/env python3
"""Offline, artifact-only verification for exact Linux upload packages."""

from __future__ import annotations

import sys as _bootstrap_sys


_EXECUTING_GATE_CODE = _bootstrap_sys._getframe().f_code
_BOOTSTRAP_SITE_MODULES = frozenset(
    name
    for name in ("site", "sitecustomize", "usercustomize", "runpy")
    if name in _bootstrap_sys.modules
)

import contextlib
import datetime
import errno
import fcntl
import functools
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import selectors
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zlib
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping, Sequence
from types import MappingProxyType, ModuleType


ORIGIN_ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS_DIR = pathlib.Path(__file__).resolve().parent
ROOT = ORIGIN_ROOT
_MONOTONIC = time.monotonic
_SLEEP = time.sleep
READ_CHUNK = 1024 * 1024
TEST_ONLY = False
CANONICAL_RELEASE = "1.0.17+34"
CANONICAL_PRODUCT_VERSION = "1.0.17"
CANONICAL_DEBIAN_VERSION = "1.0.17-34"
EXPECTED_PRODUCT_NAME = "Win's VPN"
ELF_MAGIC = b"\x7fELF"
ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PF_X = 1
PF_R = 4
ELF64_HEADER_STRUCT = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_PHDR_STRUCT = struct.Struct("<IIQQQQQQ")
ELF64_SHDR_STRUCT = struct.Struct("<IIQQQQIIQQ")
MAX_PHNUM = 128
MAX_SHNUM = 4096
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_COMPRESSION_RATIO = 64
MAX_ARCHIVE_DEPTH = 1
MAX_SUBPROCESS_STREAM_BYTES = 1024 * 1024
SUBPROCESS_DEADLINE_SECONDS = 90.0
SUBPROCESS_TERMINATE_SECONDS = 1.0
PROCESS_CGROUP_ROOT = pathlib.Path("/sys/fs/cgroup/winsvpn-release-gate-v1")
PROCESS_CGROUP_PREFIX = "job-"
PROCESS_CGROUP_DRAIN_SECONDS = 2.0
PROCESS_CGROUP_MAX_ORPHANS = 32
PROCESS_NAMESPACE_UNSHARE = pathlib.Path("/usr/bin/unshare")
PROCESS_NAMESPACE_SHELL = pathlib.Path("/bin/sh")
PROCESS_NAMESPACE_MOUNT = pathlib.Path("/usr/bin/mount")
PROCESS_NAMESPACE_HANDSHAKE = b"winsvpn-linux-process-namespace-v1\n"
HELD_ARTIFACT_CONTRACT = "winsvpn-linux-held-release-artifact-v1"
RUNTIME_PROTOCOL_ORDER_PATH = "share/winsvpn/runtime-protocol-order.json"
RUNTIME_PROTOCOL_ORDER_CONTRACT = "winsvpn-linux-runtime-protocol-order-v1"
SQUASHFS_MAGIC = b"hsqs"
REVIEWED_SUBPROCESS_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
REVIEWED_STORE_TOOLS = {
    "Flatpak": "/usr/bin/flatpak",
    "Snap": "/usr/bin/unsquashfs",
}
REQUIRED_MODULE_FILES = (
    ("release_secret_scan_policy.py", "release_secret_scan_policy"),
    ("release_secret_inventory.py", "release_secret_inventory"),
    ("release_obfuscation_contract.py", "release_obfuscation_contract"),
    ("validate_release_artifact_privacy.py", "validate_release_artifact_privacy"),
    ("linux_release_signing.py", "linux_release_signing"),
    ("release_source_freeze.py", "release_source_freeze"),
    ("release_dependency_freeze.py", "release_dependency_freeze"),
)
MODULE_CUSTODY_PREFIX = "winsvpn-linux-gate-modules-v1-"
MODULE_CUSTODY_MAX_ORPHANS = 32
MODULE_CUSTODY_MAX_FILES = 16
MODULE_CUSTODY_MAX_BYTES = 16 * 1024 * 1024
MODULE_CUSTODY_STALE_SECONDS = 300
ARTIFACT_SNAPSHOT_PREFIX = "winsvpn-linux-gate-art-v2-"
ARTIFACT_SNAPSHOT_LEASE = ".snapshot-lease"
ARTIFACT_SNAPSHOT_CONTRACT = "winsvpn-linux-artifact-snapshot-v2"
ARTIFACT_SNAPSHOT_MAX_ORPHANS = 32
ARTIFACT_SNAPSHOT_MAX_ENTRIES = MAX_ARCHIVE_MEMBERS + 8
ARTIFACT_SNAPSHOT_MAX_BYTES = MAX_UNCOMPRESSED_BYTES + MAX_ARCHIVE_BYTES
ARTIFACT_SNAPSHOT_MAX_DEPTH = 64
ARTIFACT_SNAPSHOT_STALE_SECONDS = 300


class LinuxArtifactGateError(RuntimeError):
    """Fail-closed Linux cross-store artifact refusal."""


def _alias_canonical_gate_module() -> None:
    self = sys.modules[__name__]
    origin = pathlib.Path(__file__).resolve()
    for name in ("tools.linux_cross_store_artifact_gate", "linux_cross_store_artifact_gate"):
        other = sys.modules.get(name)
        if other is None:
            sys.modules[name] = self
            continue
        if other is self:
            continue
        other_file = getattr(other, "__file__", None)
        if other_file and pathlib.Path(other_file).resolve() == origin:
            raise LinuxArtifactGateError(
                "imported-call bypass refused: linux cross-store gate loaded "
                "under a second module identity."
            )
        raise LinuxArtifactGateError(
            "imported-call bypass refused: linux cross-store gate module identity is poisoned."
        )


_alias_canonical_gate_module()
DESCRIPTOR_RELATIVE = "tools/linux_cross_store_artifact_gate.py"
OBFUSCATION_PRIVACY_RELATIVE = "tools/release_obfuscation_contract.py"
UNIQUE_UPLOAD_RECEIPT_DIGEST_FIELDS = ("artifact", "build_receipt")
SHARED_UPLOAD_RECEIPT_PATH_FIELDS = (
    "producer",
    "descriptor",
    "source_freeze",
    "obfuscation_privacy",
)


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))


def _require_readonly_fd(fd: int, label: str) -> None:
    if type(fd) is not int or fd < 0:
        raise LinuxArtifactGateError(f"{label} descriptor is invalid.")
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError as exc:
        raise LinuxArtifactGateError(f"{label} descriptor flags are unavailable.") from exc
    if flags & os.O_ACCMODE != os.O_RDONLY:
        raise LinuxArtifactGateError(
            f"{label} descriptor must be opened O_RDONLY."
        )


def _require_unique_casefold_name(parent_fd: int, name: str, label: str) -> None:
    try:
        matches = sorted(
            entry for entry in os.listdir(parent_fd) if entry.casefold() == name.casefold()
        )
    except OSError as exc:
        raise LinuxArtifactGateError(f"{label} parent could not be enumerated.") from exc
    if matches != [name]:
        raise LinuxArtifactGateError(
            f"{label} has a missing or ambiguous case-folded filename."
        )


def _open_flags(*, write: bool = False, exclusive: bool = False) -> int:
    flags = os.O_CLOEXEC | os.O_NOFOLLOW
    if write:
        flags |= os.O_RDWR | os.O_CREAT
        if exclusive:
            flags |= os.O_EXCL
        return flags
    return flags | os.O_RDONLY


def _dir_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if directory == 0:
        raise LinuxArtifactGateError("Linux gate requires O_DIRECTORY.")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | directory


def _is_symlink_stat(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode)


def _openat_child(parent_fd: int, name: str, flags: int, *, label: str) -> int:
    if name in {"", ".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise LinuxArtifactGateError(f"{label} path component is unsafe.")
    directory = bool(flags & getattr(os, "O_DIRECTORY", 0))
    try:
        info = os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            raise LinuxArtifactGateError(f"{label} is missing.") from exc
        raise LinuxArtifactGateError(f"{label} is not a bound regular file.") from exc
    if _is_symlink_stat(info):
        if directory:
            raise LinuxArtifactGateError(f"{label} traverses a symlink ancestor.")
        raise LinuxArtifactGateError(f"{label} traverses a symbolic link.")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise LinuxArtifactGateError(f"{label} traverses a non-directory.")
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        errno_value = getattr(exc, "errno", None)
        if errno_value in {errno.ELOOP, errno.ENOTDIR}:
            if directory:
                raise LinuxArtifactGateError(
                    f"{label} traverses a symlink ancestor."
                ) from exc
            raise LinuxArtifactGateError(
                f"{label} traverses a symbolic link."
            ) from exc
        if errno_value == errno.ENOENT:
            raise LinuxArtifactGateError(f"{label} is missing.") from exc
        raise LinuxArtifactGateError(f"{label} is not a bound regular file.") from exc
    try:
        opened = os.fstat(fd)
        after = os.lstat(name, dir_fd=parent_fd)
        identity = _directory_identity if directory else _file_identity
        if identity(opened) != identity(info) or identity(opened) != identity(after):
            raise LinuxArtifactGateError(f"{label} parent path was swapped.")
        if directory and not stat.S_ISDIR(opened.st_mode):
            raise LinuxArtifactGateError(f"{label} traverses a non-directory.")
        if not directory and _is_symlink_stat(opened):
            raise LinuxArtifactGateError(f"{label} traverses a symbolic link.")
        return fd
    except Exception:
        os.close(fd)
        raise


def _lexical_parts_under(
    root: pathlib.Path, path: pathlib.Path
) -> tuple[str, ...] | None:
    try:
        root_resolved = pathlib.Path(root).resolve(strict=True)
    except OSError:
        return None
    path_obj = pathlib.Path(path)
    attempts = (
        (os.path.abspath(os.fspath(path_obj)), os.path.abspath(os.fspath(root))),
        (os.path.abspath(os.fspath(path_obj)), os.fspath(root_resolved)),
    )
    for path_abs, root_abs in attempts:
        try:
            relative = os.path.relpath(path_abs, root_abs)
        except ValueError:
            continue
        if relative.startswith("..") or os.path.isabs(relative):
            continue
        if relative in {".", ""}:
            return ()
        posix = relative.replace("\\", "/")
        parts = tuple(pathlib.PurePosixPath(posix).parts)
        if any(
            part in {"", ".", ".."} or "/" in part or "\\" in part or "\x00" in part
            for part in parts
        ):
            return None
        return parts
    return None


def _openat_from_root(
    root: pathlib.Path,
    parts: tuple[str, ...],
    *,
    last_directory: bool,
    label: str,
) -> int:
    if any(
        part in {"", ".", ".."} or "/" in part or "\\" in part or "\x00" in part
        for part in parts
    ):
        raise LinuxArtifactGateError(
            f"{label} must be one canonical repository-relative path."
        )
    if not parts and not last_directory:
        raise LinuxArtifactGateError(
            f"{label} must be one canonical repository-relative path."
        )
    try:
        fd = os.open(root, _dir_open_flags())
    except OSError as exc:
        errno_value = getattr(exc, "errno", None)
        if errno_value in {errno.ELOOP, errno.ENOTDIR}:
            raise LinuxArtifactGateError(
                f"{label} traverses a symlink ancestor."
            ) from exc
        raise LinuxArtifactGateError(f"{label} is missing.") from exc
    try:
        root_info = os.fstat(fd)
        if (
            _file_identity(root_info) != _file_identity(root.lstat())
            or not stat.S_ISDIR(root_info.st_mode)
        ):
            raise LinuxArtifactGateError(
                f"{label} repository root changed while it was bound."
            )
        if not parts:
            return fd
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            flags = _dir_open_flags() if (not last or last_directory) else _open_flags()
            child = _openat_child(fd, part, flags, label=label)
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def _bind_file_under_root(
    root_path: pathlib.Path, path: pathlib.Path, label: str
) -> int:
    root = root_path.resolve(strict=True)
    parts = _lexical_parts_under(root_path, path)
    if parts is None or not parts:
        raise LinuxArtifactGateError(
            f"{label} is outside the bound Linux gate root."
        )
    return _openat_from_root(root, parts, last_directory=False, label=label)


def _bind_repo_file(path: pathlib.Path, label: str) -> int:
    return _bind_file_under_root(ROOT, path, label)


class _RetainedDirectoryChain:
    """Retain every directory descriptor from the filesystem root to one parent."""

    def __init__(
        self,
        entries: tuple[tuple[int, str | None, tuple[int, int, int, int]], ...],
        label: str,
    ) -> None:
        if not entries:
            raise LinuxArtifactGateError(f"{label} ancestor custody is empty.")
        self._entries = entries
        self._label = label

    @property
    def leaf_fd(self) -> int:
        return self._entries[-1][0]

    @property
    def parent_fd(self) -> int:
        if len(self._entries) < 2:
            raise LinuxArtifactGateError(
                f"{self._label} has no retained parent directory."
            )
        return self._entries[-2][0]

    @property
    def leaf_name(self) -> str:
        if len(self._entries) < 2 or self._entries[-1][1] is None:
            raise LinuxArtifactGateError(
                f"{self._label} has no retained leaf name."
            )
        return str(self._entries[-1][1])

    @property
    def leaf_identity(self) -> tuple[int, int, int, int]:
        return self._entries[-1][2]

    def revalidate(self) -> None:
        for index, (fd, name, identity) in enumerate(self._entries):
            if fd < 0:
                raise LinuxArtifactGateError(
                    f"{self._label} ancestor descriptor custody is closed."
                )
            _require_readonly_fd(fd, f"{self._label} ancestor")
            current = os.fstat(fd)
            if not stat.S_ISDIR(current.st_mode) or _directory_identity(current) != identity:
                raise LinuxArtifactGateError(
                    f"{self._label} retained ancestor identity changed."
                )
            if index == 0:
                continue
            parent_fd = self._entries[index - 1][0]
            try:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as exc:
                raise LinuxArtifactGateError(
                    f"{self._label} ancestor was replaced or removed."
                ) from exc
            if _directory_identity(named) != identity:
                raise LinuxArtifactGateError(
                    f"{self._label} ancestor was substituted or restored."
                )

    def close(self) -> None:
        entries = self._entries
        self._entries = ()
        for fd, _name, _identity in reversed(entries):
            if fd >= 0:
                os.close(fd)

    def __copy__(self):
        raise LinuxArtifactGateError("retained ancestor custody cannot be copied.")

    def __deepcopy__(self, memo):
        raise LinuxArtifactGateError("retained ancestor custody cannot be deep-copied.")

    def __reduce_ex__(self, protocol):
        raise LinuxArtifactGateError("retained ancestor custody cannot be serialized.")


def _retain_complete_directory_chain(
    directory: pathlib.Path, label: str
) -> _RetainedDirectoryChain:
    try:
        absolute = directory.resolve(strict=True)
    except OSError as exc:
        raise LinuxArtifactGateError(f"{label} ancestor path is unavailable.") from exc
    if not absolute.is_absolute():
        raise LinuxArtifactGateError(f"{label} ancestor path is not absolute.")
    entries: list[tuple[int, str | None, tuple[int, int, int, int]]] = []
    current_fd = -1
    try:
        current_fd = os.open(os.sep, _dir_open_flags())
        root_info = os.fstat(current_fd)
        entries.append((current_fd, None, _directory_identity(root_info)))
        current_fd = -1
        for part in absolute.parts[1:]:
            parent_fd = entries[-1][0]
            child_fd = _openat_child(
                parent_fd,
                part,
                _dir_open_flags(),
                label=f"{label} ancestor",
            )
            child_info = os.fstat(child_fd)
            entries.append((child_fd, part, _directory_identity(child_info)))
        custody = _RetainedDirectoryChain(tuple(entries), label)
        entries = []
        custody.revalidate()
        return custody
    except Exception:
        if current_fd >= 0:
            os.close(current_fd)
        for fd, _name, _identity in reversed(entries):
            os.close(fd)
        raise


def _strict_object_pairs(pairs: list[tuple[str, object]], label: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LinuxArtifactGateError(f"{label} has a duplicate JSON key.")
        result[key] = value
    return result


def _reject_json_constant(value: str, label: str) -> object:
    raise LinuxArtifactGateError(
        f"{label} contains a non-finite JSON number: {value}."
    )


def _strict_json_object(payload: bytes, label: str) -> dict[str, object]:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=lambda pairs: _strict_object_pairs(pairs, label),
            parse_constant=lambda value: _reject_json_constant(value, label),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LinuxArtifactGateError(f"{label} is not canonical JSON.") from exc
    if type(document) is not dict:
        raise LinuxArtifactGateError(f"{label} must be one JSON object.")
    return document


def _require_exact_keys(
    document: dict[str, object], keys: set[str], label: str
) -> None:
    if set(document) != keys:
        raise LinuxArtifactGateError(
            f"{label} fields are incomplete or unexpected."
        )


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, READ_CHUNK, offset)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        offset += len(block)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _module_file_digest(module: ModuleType) -> str | None:
    path = getattr(module, "__file__", None)
    if not isinstance(path, str) or not path:
        return None
    fd = -1
    try:
        fd = os.open(path, _open_flags())
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
            return None
        return _sha256_fd(fd)
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _reject_module_poison(public_name: str, expected_digest: str) -> None:
    existing = sys.modules.get(public_name)
    if existing is None:
        return
    actual = _module_file_digest(existing)
    if actual != expected_digest:
        raise LinuxArtifactGateError(
            f"required module {public_name} is poisoned via PYTHONPATH, "
            "sitecustomize, or sys.modules substitution."
        )


class _BoundModuleSource:
    """Retained exact source bytes and descriptor for one reviewed module."""

    def __init__(
        self,
        *,
        path: pathlib.Path,
        public_name: str,
        package: str,
        aliases: tuple[str, ...],
        source_root: pathlib.Path,
        fd: int,
        identity: tuple[int, ...],
        digest: str,
        payload: bytes,
    ) -> None:
        self.path = path
        self.public_name = public_name
        self.package = package
        self.aliases = aliases
        self.source_root = source_root
        self.fd = fd
        self.identity = identity
        self.digest = digest
        self.payload = payload
        self.module: ModuleType | None = None

    def revalidate(self) -> None:
        if self.fd < 0:
            raise LinuxArtifactGateError(
                f"required module {self.public_name} descriptor custody is closed."
            )
        _require_readonly_fd(
            self.fd, f"required module {self.public_name} source"
        )
        try:
            retained = os.fstat(self.fd)
            named = self.path.lstat()
        except OSError as exc:
            raise LinuxArtifactGateError(
                f"required module {self.public_name} was removed or replaced."
            ) from exc
        if (
            _file_identity(retained) != self.identity
            or _file_identity(named) != self.identity
            or _sha256_fd(self.fd) != self.digest
            or _sha256_bytes(self.payload) != self.digest
        ):
            raise LinuxArtifactGateError(
                f"required module {self.public_name} changed during authenticated use."
            )
        if self.module is not None:
            for alias in self.aliases:
                if sys.modules.get(alias) is not self.module:
                    raise LinuxArtifactGateError(
                        f"required module {self.public_name} sys.modules identity was poisoned."
                    )

    def validate_runtime_paths(self) -> None:
        if self.module is None:
            raise LinuxArtifactGateError(
                f"required module {self.public_name} was not executed."
            )
        expected_source = self.path.resolve(strict=True)
        expected_root = self.source_root.resolve(strict=True)
        expected_values = {
            "__file__": expected_source,
            "_EXECUTING_SOURCE_PATH": expected_source,
            "_EXECUTING_CODE_PATH": expected_source,
            "CONTRACT_PATH": expected_source,
            "ROOT": expected_root,
            "HERE": expected_source.parent,
            "REPO_ROOT": expected_root,
            "_EXT_TOOLS": expected_root / "extension" / "tools",
        }
        for field, expected in expected_values.items():
            if not hasattr(self.module, field):
                continue
            try:
                actual = pathlib.Path(getattr(self.module, field)).resolve(strict=True)
                reviewed = expected.resolve(strict=True)
            except OSError as exc:
                raise LinuxArtifactGateError(
                    f"required module {self.public_name} runtime path {field} is unavailable."
                ) from exc
            if actual != reviewed:
                raise LinuxArtifactGateError(
                    f"required module {self.public_name} runtime path {field} is poisoned."
                )

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class _GateSourceCustody:
    """Retain the exact gate source and every ancestor for the process lifetime."""

    def __init__(self) -> None:
        self.path = pathlib.Path(__file__).resolve(strict=True)
        self.ancestor_chain = _retain_complete_directory_chain(
            self.path.parent, "Linux cross-store gate source"
        )
        self.fd = -1
        try:
            self.fd = _bind_file_under_root(
                ORIGIN_ROOT, self.path, "Linux cross-store gate source"
            )
            info = os.fstat(self.fd)
            payload = os.pread(self.fd, info.st_size, 0)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size <= 0
                or len(payload) != info.st_size
            ):
                raise LinuxArtifactGateError(
                    "Linux cross-store gate source is not one exact regular file."
                )
            reviewed = compile(
                payload,
                _EXECUTING_GATE_CODE.co_filename,
                "exec",
                dont_inherit=True,
                optimize=sys.flags.optimize,
            )
            if reviewed != _EXECUTING_GATE_CODE:
                raise LinuxArtifactGateError(
                    "Linux cross-store gate executing code differs from held source."
                )
            self.identity = _file_identity(info)
            self.payload = payload
            self.digest = _sha256_bytes(payload)
            self.revalidate()
        except BaseException:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1
            self.ancestor_chain.close()
            raise

    def revalidate(self) -> None:
        if self.fd < 0:
            raise LinuxArtifactGateError(
                "Linux cross-store gate source custody is closed."
            )
        self.ancestor_chain.revalidate()
        _require_readonly_fd(self.fd, "Linux cross-store gate source")
        try:
            retained = os.fstat(self.fd)
            named = self.path.lstat()
        except OSError as exc:
            raise LinuxArtifactGateError(
                "Linux cross-store gate source was replaced or removed."
            ) from exc
        if (
            _file_identity(retained) != self.identity
            or _file_identity(named) != self.identity
            or _sha256_fd(self.fd) != self.digest
            or _sha256_bytes(self.payload) != self.digest
        ):
            raise LinuxArtifactGateError(
                "Linux cross-store gate source changed during authenticated use."
            )


def _compiled_code_index(payload: bytes, filename: str) -> dict[str, tuple[object, ...]]:
    root = compile(
        payload,
        filename,
        "exec",
        dont_inherit=True,
        optimize=sys.flags.optimize,
    )
    collected: dict[str, list[object]] = {}
    pending = [root]
    while pending:
        code = pending.pop()
        collected.setdefault(code.co_qualname, []).append(code)
        pending.extend(
            value for value in code.co_consts if type(value) is type(code)
        )
    return {name: tuple(values) for name, values in collected.items()}


def _require_source_derived_attribute(
    module: ModuleType,
    attribute: str,
    indexed: Mapping[str, tuple[object, ...]],
    public_name: str,
) -> None:
    value = getattr(module, attribute, None)
    if type(value).__name__ == "function":
        expected = indexed.get(attribute, ())
        source_function = getattr(value, "__wrapped__", value)
        if (
            source_function.__code__ not in expected
            or source_function.__globals__ is not module.__dict__
        ):
            raise LinuxArtifactGateError(
                f"authenticated runtime module {public_name}.{attribute} "
                "is not derived from its held source."
            )
        return
    if type(value) is type:
        if value.__module__ != module.__name__:
            raise LinuxArtifactGateError(
                f"authenticated runtime module {public_name}.{attribute} "
                "has a substituted class origin."
            )
        expected_methods = {
            name: codes
            for name, codes in indexed.items()
            if name.startswith(attribute + ".")
            and ".<locals>." not in name
            and name.count(".") == 1
        }
        all_expected = tuple(
            code for codes in expected_methods.values() for code in codes
        )
        checked = 0
        for method_name, descriptor in value.__dict__.items():
            if isinstance(descriptor, (staticmethod, classmethod)):
                descriptor = descriptor.__func__
            if type(descriptor).__name__ != "function":
                continue
            checked += 1
            expected = expected_methods.get(
                f"{attribute}.{method_name}", ()
            )
            source_function = getattr(descriptor, "__wrapped__", descriptor)
            if (
                source_function.__code__ not in expected
                and source_function.__code__ not in all_expected
                or source_function.__globals__ is not module.__dict__
            ):
                raise LinuxArtifactGateError(
                    f"authenticated runtime module {public_name}.{attribute}."
                    f"{method_name} is not derived from held source."
                )
        if checked == 0:
            raise LinuxArtifactGateError(
                f"authenticated runtime module {public_name}.{attribute} "
                "has no held source-derived methods."
            )
        return
    raise LinuxArtifactGateError(
        f"authenticated runtime module {public_name}.{attribute} "
        "has no source-derived behavior boundary."
    )


def _module_custody_temp_root() -> pathlib.Path:
    try:
        root = pathlib.Path(tempfile.gettempdir()).resolve(strict=True)
        repository = ROOT.resolve(strict=True)
    except OSError as exc:
        raise LinuxArtifactGateError(
            "private module custody temp root could not be authenticated."
        ) from exc
    try:
        root.relative_to(repository)
    except ValueError:
        pass
    else:
        raise LinuxArtifactGateError(
            "private module custody must remain outside the repository."
        )
    return root


def _open_module_custody_root() -> tuple[pathlib.Path, int]:
    root = _module_custody_temp_root()
    try:
        fd = os.open(root, _dir_open_flags())
    except OSError as exc:
        raise LinuxArtifactGateError(
            "private module custody temp root could not be opened."
        ) from exc
    try:
        retained = os.fstat(fd)
        named = root.lstat()
        if (
            not stat.S_ISDIR(retained.st_mode)
            or _module_custody_child_identity(retained)
            != _module_custody_child_identity(named)
        ):
            raise LinuxArtifactGateError(
                "private module custody temp root identity is not stable."
            )
        return root, fd
    except Exception:
        os.close(fd)
        raise


def _module_custody_child_name() -> str:
    return MODULE_CUSTODY_PREFIX + secrets.token_hex(16)


def _module_custody_child_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))


def _remove_module_custody_child(
    root_fd: int,
    name: str,
    child_fd: int,
    child_identity: tuple[int, int, int, int],
) -> None:
    entries = sorted(os.listdir(child_fd))
    if len(entries) > MODULE_CUSTODY_MAX_FILES:
        raise LinuxArtifactGateError(
            "private module custody directory exceeds the file ceiling."
        )
    aggregate = 0
    for entry in entries:
        if (
            not re.fullmatch(r"[0-9]{2}-[a-z0-9_]+\.py", entry)
            or entry in {".", ".."}
        ):
            raise LinuxArtifactGateError(
                "private module custody directory contains an unexpected entry."
            )
        info = os.stat(entry, dir_fd=child_fd, follow_symlinks=False)
        aggregate += info.st_size
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o400
            or info.st_size <= 0
            or aggregate > MODULE_CUSTODY_MAX_BYTES
        ):
            raise LinuxArtifactGateError(
                "private module custody file identity is invalid."
            )
    for entry in entries:
        os.unlink(entry, dir_fd=child_fd)
    os.fsync(child_fd)
    current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    if _module_custody_child_identity(current) != child_identity:
        raise LinuxArtifactGateError(
            "private module custody directory was replaced during cleanup."
        )
    os.rmdir(name, dir_fd=root_fd)
    os.fsync(root_fd)


def _recover_module_custody_orphans(root_fd: int) -> None:
    now_ns = time.time_ns()
    candidates: list[tuple[str, os.stat_result]] = []
    for name in sorted(os.listdir(root_fd)):
        if re.fullmatch(MODULE_CUSTODY_PREFIX + r"[0-9a-f]{32}", name) is None:
            continue
        info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            continue
        if now_ns - info.st_mtime_ns < MODULE_CUSTODY_STALE_SECONDS * 1_000_000_000:
            continue
        candidates.append((name, info))
    if len(candidates) > MODULE_CUSTODY_MAX_ORPHANS:
        raise LinuxArtifactGateError(
            "private module custody orphan count exceeds the reviewed ceiling."
        )
    for name, before in candidates:
        child_fd = _openat_child(
            root_fd,
            name,
            _dir_open_flags(),
            label="private module custody orphan",
        )
        try:
            retained = os.fstat(child_fd)
            if (
                _module_custody_child_identity(retained)
                != _module_custody_child_identity(before)
            ):
                raise LinuxArtifactGateError(
                    "private module custody orphan identity changed."
                )
            _remove_module_custody_child(
                root_fd,
                name,
                child_fd,
                _module_custody_child_identity(retained),
            )
        finally:
            os.close(child_fd)


@contextlib.contextmanager
def _private_module_custody(
    sources: tuple[_BoundModuleSource, ...],
) -> Iterable[dict[str, tuple[int, bytes]]]:
    _root, root_fd = _open_module_custody_root()
    name = _module_custody_child_name()
    child_fd = -1
    staged_fds: list[int] = []
    try:
        _recover_module_custody_orphans(root_fd)
        os.mkdir(name, 0o700, dir_fd=root_fd)
        child_fd = _openat_child(
            root_fd,
            name,
            _dir_open_flags(),
            label="private module custody directory",
        )
        child_info = os.fstat(child_fd)
        if (
            child_info.st_uid != os.geteuid()
            or stat.S_IMODE(child_info.st_mode) != 0o700
        ):
            raise LinuxArtifactGateError(
                "private module custody directory mode or owner is invalid."
            )
        staged: dict[str, tuple[int, bytes]] = {}
        for index, source in enumerate(sources):
            staged_name = f"{index:02d}-{source.public_name}.py"
            copied = _copy_exclusive_pread(
                source.fd,
                dir_fd=child_fd,
                name=staged_name,
                size=len(source.payload),
            )
            staged_fd = _openat_child(
                child_fd,
                staged_name,
                _open_flags(),
                label=f"private module custody {source.public_name}",
            )
            staged_fds.append(staged_fd)
            info = os.fstat(staged_fd)
            payload = os.pread(staged_fd, info.st_size, 0)
            if (
                info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o400
                or copied != source.digest
                or payload != source.payload
                or _sha256_fd(staged_fd) != source.digest
            ):
                raise LinuxArtifactGateError(
                    f"private module custody {source.public_name} is not exact."
                )
            staged[source.public_name] = (staged_fd, payload)
        os.fsync(child_fd)
        yield staged
        for source in sources:
            source.revalidate()
            staged_fd, payload = staged[source.public_name]
            if (
                os.pread(staged_fd, len(payload) + 1, 0) != payload
                or _sha256_fd(staged_fd) != source.digest
            ):
                raise LinuxArtifactGateError(
                    f"private module custody {source.public_name} changed."
                )
    finally:
        cleanup_error: BaseException | None = None
        for source in sources:
            try:
                source.revalidate()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        for staged_fd in reversed(staged_fds):
            try:
                os.close(staged_fd)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if child_fd >= 0:
            try:
                retained = os.fstat(child_fd)
                _remove_module_custody_child(
                    root_fd,
                    name,
                    child_fd,
                    _module_custody_child_identity(retained),
                )
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
            finally:
                os.close(child_fd)
        os.close(root_fd)
        if cleanup_error is not None:
            raise cleanup_error


def _bind_module_source(
    path: pathlib.Path,
    public_name: str,
    *,
    package: str,
    aliases: tuple[str, ...],
    source_root: pathlib.Path,
) -> _BoundModuleSource:
    fd = _bind_file_under_root(
        source_root, path, f"required module {public_name}"
    )
    try:
        info = os.fstat(fd)
        named = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > MODULE_CUSTODY_MAX_BYTES
            or _file_identity(info) != _file_identity(named)
        ):
            raise LinuxArtifactGateError(
                f"required module {public_name} must be one bounded single-link file."
            )
        payload = os.pread(fd, info.st_size, 0)
        if len(payload) != info.st_size:
            raise LinuxArtifactGateError(
                f"required module {public_name} was truncated while binding."
            )
        digest = _sha256_bytes(payload)
        if _sha256_fd(fd) != digest:
            raise LinuxArtifactGateError(
                f"required module {public_name} changed while binding."
            )
        source = _BoundModuleSource(
            path=path,
            public_name=public_name,
            package=package,
            aliases=aliases,
            source_root=source_root,
            fd=fd,
            identity=_file_identity(info),
            digest=digest,
            payload=payload,
        )
        source.revalidate()
        return source
    except Exception:
        os.close(fd)
        raise


def _reviewed_stdlib_import_path() -> list[str]:
    try:
        base = pathlib.Path(sys.base_prefix).resolve(strict=True)
    except OSError as exc:
        raise LinuxArtifactGateError(
            "required module standard-library root is unavailable."
        ) from exc
    reviewed: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        candidate = pathlib.Path(entry)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(base)
        except (OSError, ValueError):
            continue
        if "site-packages" in resolved.parts or "dist-packages" in resolved.parts:
            continue
        value = os.fspath(resolved)
        if value not in reviewed:
            reviewed.append(value)
    if not reviewed:
        raise LinuxArtifactGateError(
            "required module standard-library import path is empty."
        )
    return reviewed


def _require_pristine_meta_path() -> None:
    sys.meta_path[:] = [
        finder
        for finder in sys.meta_path
        if getattr(finder, "__module__", "") != "_distutils_hack"
    ]
    frozen = sys.modules.get("_frozen_importlib")
    external = sys.modules.get("_frozen_importlib_external")
    expected = (
        getattr(frozen, "BuiltinImporter", None),
        getattr(frozen, "FrozenImporter", None),
        getattr(external, "PathFinder", None),
    )
    if None in expected or tuple(sys.meta_path) != expected:
        raise LinuxArtifactGateError(
            "required module import boundary is poisoned."
        )


@contextlib.contextmanager
def _isolated_module_import_path(
    source: _BoundModuleSource,
) -> Iterable[None]:
    _require_pristine_meta_path()
    original_object = sys.path
    original_values = list(sys.path)
    reviewed = _reviewed_stdlib_import_path()
    sys.path = list(reviewed)
    try:
        yield
        allowed = list(reviewed)
        if source.public_name == "render_host_manifest":
            allowed.insert(0, os.fspath(source.source_root / "extension" / "tools"))
        if sys.path != allowed:
            raise LinuxArtifactGateError(
                f"required module {source.public_name} changed the isolated import path."
            )
        _require_pristine_meta_path()
    finally:
        sys.path = original_object
        original_object[:] = original_values


def _copy_exclusive(
    source_fd: int,
    destination: pathlib.Path,
    size: int,
    *,
    dir_fd: int | None = None,
    name: str | None = None,
) -> str:
    os.lseek(source_fd, 0, os.SEEK_SET)
    if dir_fd is not None:
        if (
            name is None
            or name in {"", ".", ".."}
            or "/" in name
            or "\\" in name
            or "\x00" in name
        ):
            raise LinuxArtifactGateError("authenticated snapshot destination is unsafe.")
        dest_fd = os.open(
            name, _open_flags(write=True, exclusive=True), 0o400, dir_fd=dir_fd
        )
    else:
        dest_fd = os.open(destination, _open_flags(write=True, exclusive=True), 0o400)
    try:
        os.fchmod(dest_fd, 0o400)
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            block = os.read(source_fd, min(READ_CHUNK, remaining))
            if not block:
                raise LinuxArtifactGateError("authenticated snapshot source truncated.")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(dest_fd, view)
                if written <= 0:
                    raise LinuxArtifactGateError("authenticated snapshot write truncated.")
                view = view[written:]
            remaining -= len(block)
        extra = os.read(source_fd, 1)
        if extra:
            raise LinuxArtifactGateError("authenticated snapshot source mutated while copying.")
        os.fsync(dest_fd)
        return digest.hexdigest()
    finally:
        os.close(dest_fd)


def _copy_exclusive_pread(
    source_fd: int,
    *,
    dir_fd: int,
    name: str,
    size: int,
) -> str:
    if (
        name in {"", ".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
    ):
        raise LinuxArtifactGateError("held artifact snapshot destination is unsafe.")
    dest_fd = os.open(
        name,
        _open_flags(write=True, exclusive=True),
        0o400,
        dir_fd=dir_fd,
    )
    try:
        os.fchmod(dest_fd, 0o400)
        digest = hashlib.sha256()
        offset = 0
        while offset < size:
            block = os.pread(source_fd, min(READ_CHUNK, size - offset), offset)
            if not block:
                raise LinuxArtifactGateError("held artifact source truncated.")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(dest_fd, view)
                if written <= 0:
                    raise LinuxArtifactGateError(
                        "held artifact snapshot write truncated."
                    )
                view = view[written:]
            offset += len(block)
        if os.pread(source_fd, 1, size):
            raise LinuxArtifactGateError("held artifact source exceeded its bound size.")
        os.fsync(dest_fd)
        return digest.hexdigest()
    finally:
        os.close(dest_fd)


def _load_module_closure(
    specifications: tuple[
        tuple[pathlib.Path, str, str, tuple[str, ...]], ...
    ],
    *,
    source_root: pathlib.Path = ORIGIN_ROOT,
) -> tuple[dict[str, ModuleType], tuple[_BoundModuleSource, ...]]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise LinuxArtifactGateError("Linux gate requires O_NOFOLLOW.")
    if not hasattr(os, "O_DIRECTORY"):
        raise LinuxArtifactGateError("Linux gate requires O_DIRECTORY.")
    token = secrets.token_hex(16)
    sources: list[_BoundModuleSource] = []
    loaded: dict[str, ModuleType] = {}
    installed_aliases: list[str] = []
    private_names: list[str] = []
    try:
        aggregate = 0
        for path, public_name, package, aliases in specifications:
            source = _bind_module_source(
                path,
                public_name,
                package=package,
                aliases=aliases,
                source_root=source_root,
            )
            aggregate += len(source.payload)
            if aggregate > MODULE_CUSTODY_MAX_BYTES:
                source.close()
                raise LinuxArtifactGateError(
                    "required module closure exceeds the reviewed byte ceiling."
                )
            for alias in aliases:
                _reject_module_poison(alias, source.digest)
            sources.append(source)
        frozen_sources = tuple(sources)
        with _private_module_custody(frozen_sources) as staged:
            for source in frozen_sources:
                source.revalidate()
                private_name = (
                    f"_winsvpn_linux_gate_{source.public_name}_{token}"
                )
                if private_name in sys.modules:
                    raise LinuxArtifactGateError(
                        f"private module identity collided: {private_name}"
                    )
                staged_fd, staged_payload = staged[source.public_name]
                if (
                    staged_payload != source.payload
                    or _sha256_fd(staged_fd) != source.digest
                ):
                    raise LinuxArtifactGateError(
                        f"required module {source.public_name} staged bytes changed."
                    )
                module = ModuleType(private_name)
                module.__file__ = os.fspath(source.path)
                module.__package__ = source.package
                module.__loader__ = None
                module.__spec__ = None
                source.module = module
                sys.modules[private_name] = module
                private_names.append(private_name)
                for alias in source.aliases:
                    sys.modules[alias] = module
                    installed_aliases.append(alias)
                parent = sys.modules.get(source.package)
                if parent is not None and "." not in source.public_name:
                    setattr(parent, source.public_name, module)
                with _isolated_module_import_path(source):
                    code = compile(
                        staged_payload,
                        os.fspath(source.path),
                        "exec",
                        dont_inherit=True,
                        optimize=0,
                    )
                    exec(code, module.__dict__, module.__dict__)
                source.revalidate()
                source.validate_runtime_paths()
                loaded[source.public_name] = module
            for source in frozen_sources:
                source.revalidate()
                source.validate_runtime_paths()
        return loaded, frozen_sources
    except BaseException:
        for alias in reversed(installed_aliases):
            module = sys.modules.get(alias)
            if any(source.module is module for source in sources):
                sys.modules.pop(alias, None)
        for private_name in reversed(private_names):
            sys.modules.pop(private_name, None)
        for source in reversed(sources):
            source.close()
        raise


def _load_required_modules() -> tuple[
    dict[str, ModuleType], tuple[_BoundModuleSource, ...]
]:
    specifications = tuple(
        (
            TOOLS_DIR / filename,
            public_name,
            "tools",
            (public_name, f"tools.{public_name}"),
        )
        for filename, public_name in REQUIRED_MODULE_FILES
    )
    return _load_module_closure(specifications)


def _verify_module_custody(
    sources: tuple[_BoundModuleSource, ...] | None = None,
) -> None:
    bound = _MODULE_CUSTODY if sources is None else sources
    for source in bound:
        source.revalidate()
        if source.module is not None:
            source.validate_runtime_paths()


def _verify_all_module_custody() -> None:
    runtime_custody = globals().get("_RUNTIME_MODULE_CUSTODY", ())
    if runtime_custody:
        _require_authenticated_runtime_boundary()
    gate_source = globals().get("_GATE_SOURCE_CUSTODY")
    if gate_source is not None:
        gate_source.revalidate()
    for binding in runtime_custody:
        binding.require_objects()
    for binding in runtime_custody:
        binding.revalidate()
    _verify_module_custody()
    renderer_custody = globals().get("_NATIVE_HOST_MODULE_CUSTODY", ())
    if renderer_custody:
        _verify_module_custody(renderer_custody)
    for name, expected in globals().get("_GATE_SUPPORT_OBJECTS", {}).items():
        if globals().get(name) is not expected:
            raise LinuxArtifactGateError(
                f"authenticated Linux gate support edge {name} was poisoned."
            )


def _module_custody_guard(function):
    @functools.wraps(function)
    def guarded(*args, **kwargs):
        _verify_all_module_custody()
        try:
            return function(*args, **kwargs)
        finally:
            _verify_all_module_custody()

    return guarded


_GATE_SOURCE_CUSTODY = _GateSourceCustody()
_MODULES, _MODULE_CUSTODY = _load_required_modules()
linux_release_signing = _MODULES["linux_release_signing"]
source_freeze = _MODULES["release_source_freeze"]
freeze = _MODULES["release_dependency_freeze"]
obfuscation = _MODULES["release_obfuscation_contract"]
privacy = _MODULES["validate_release_artifact_privacy"]
inspect_native_debug_sections = obfuscation.inspect_native_debug_sections
reject_packaged_private_symbols = obfuscation.reject_packaged_private_symbols
reject_sensitive_internal_identifiers = obfuscation.reject_sensitive_internal_identifiers
ObfuscationError = obfuscation.ObfuscationError
PrivacyError = privacy.PrivacyError
check_blob = privacy.check_blob
reject_local_build_paths = privacy.reject_local_build_paths
reject_unstripped_native_library = privacy.reject_unstripped_native_library
validate_tar_metadata = privacy.validate_tar_metadata
_GATE_SUPPORT_OBJECTS = MappingProxyType(
    {
        "linux_release_signing": linux_release_signing,
        "source_freeze": source_freeze,
        "freeze": freeze,
        "obfuscation": obfuscation,
        "privacy": privacy,
        "inspect_native_debug_sections": inspect_native_debug_sections,
        "reject_packaged_private_symbols": reject_packaged_private_symbols,
        "reject_sensitive_internal_identifiers": reject_sensitive_internal_identifiers,
        "check_blob": check_blob,
        "reject_local_build_paths": reject_local_build_paths,
        "reject_unstripped_native_library": reject_unstripped_native_library,
        "validate_tar_metadata": validate_tar_metadata,
        "_MONOTONIC": _MONOTONIC,
        "_SLEEP": _SLEEP,
        "PROCESS_CGROUP_ROOT": PROCESS_CGROUP_ROOT,
        "PROCESS_CGROUP_PREFIX": PROCESS_CGROUP_PREFIX,
        "PROCESS_CGROUP_DRAIN_SECONDS": PROCESS_CGROUP_DRAIN_SECONDS,
    }
)


def _reviewed_stdlib_module(module: ModuleType, name: str) -> ModuleType:
    if sys.modules.get(name) is not module:
        raise LinuxArtifactGateError(
            f"reviewed archive module {name} identity is poisoned."
        )
    source = getattr(module, "__file__", None)
    if not isinstance(source, str) or not source:
        raise LinuxArtifactGateError(
            f"reviewed archive module {name} has no authenticated origin."
        )
    try:
        origin = pathlib.Path(source).resolve(strict=True)
        base = pathlib.Path(sys.base_prefix).resolve(strict=True)
        origin.relative_to(base)
    except (OSError, ValueError) as exc:
        raise LinuxArtifactGateError(
            f"reviewed archive module {name} origin is outside the standard library."
        ) from exc
    if "site-packages" in origin.parts or "dist-packages" in origin.parts:
        raise LinuxArtifactGateError(
            f"reviewed archive module {name} origin is package-path poisoned."
        )
    return module


def _load_reviewed_zstd() -> ModuleType:
    source = next(
        item
        for item in _MODULE_CUSTODY
        if item.public_name == "validate_release_artifact_privacy"
    )
    with _isolated_module_import_path(source):
        module = __import__("compression.zstd", fromlist=("zstd",))
    parent = sys.modules.get("compression")
    if not isinstance(parent, ModuleType):
        raise LinuxArtifactGateError(
            "reviewed archive module compression identity is poisoned."
        )
    _reviewed_stdlib_module(parent, "compression")
    return _reviewed_stdlib_module(module, "compression.zstd")


REVIEWED_ZIPFILE = _reviewed_stdlib_module(privacy.zipfile, "zipfile")
REVIEWED_TARFILE = _reviewed_stdlib_module(privacy.tarfile, "tarfile")
REVIEWED_ZSTD = _load_reviewed_zstd()
REVIEWED_COMPRESSION = sys.modules["compression"]
REVIEWED_FCNTL = _reviewed_stdlib_module(fcntl, "fcntl")


def _runtime_constant_fingerprint(value: object) -> object:
    if isinstance(value, Mapping):
        return (
            "mapping",
            tuple(
                sorted(
                    (
                        _runtime_constant_fingerprint(key),
                        _runtime_constant_fingerprint(item),
                    )
                    for key, item in value.items()
                )
            ),
        )
    if isinstance(value, (tuple, list)):
        return (
            type(value).__name__,
            tuple(_runtime_constant_fingerprint(item) for item in value),
        )
    if isinstance(value, (set, frozenset)):
        return (
            type(value).__name__,
            tuple(
                sorted(
                    (_runtime_constant_fingerprint(item) for item in value),
                    key=repr,
                )
            ),
        )
    if isinstance(value, (str, int, float, bool, bytes, type(None))):
        return (type(value).__name__, value)
    raise LinuxArtifactGateError(
        f"authenticated runtime constant has unsupported type {type(value).__name__}."
    )


class _RuntimeModuleBinding:
    """Retained module source plus exact security-sensitive runtime objects."""

    def __init__(
        self,
        public_name: str,
        module: ModuleType,
        attributes: tuple[str, ...],
        *,
        private: bool = False,
        source_derived: tuple[str, ...] = (),
        constants: tuple[str, ...] = (),
    ) -> None:
        if type(module) is not ModuleType:
            raise LinuxArtifactGateError(
                f"authenticated runtime module {public_name} is not one exact module."
            )
        if not private:
            if sys.modules.get(public_name) is not module:
                raise LinuxArtifactGateError(
                    f"authenticated runtime module {public_name} identity is poisoned."
                )
            spec = getattr(module, "__spec__", None)
            if spec is None or getattr(spec, "name", None) != public_name:
                raise LinuxArtifactGateError(
                    f"authenticated runtime module {public_name} spec is poisoned."
                )
        source = getattr(module, "__file__", None)
        if not isinstance(source, str) or not source:
            raise LinuxArtifactGateError(
                f"authenticated runtime module {public_name} has no exact source."
            )
        try:
            path = pathlib.Path(source).resolve(strict=True)
            fd = os.open(path, _open_flags())
            info = os.fstat(fd)
        except OSError as exc:
            raise LinuxArtifactGateError(
                f"authenticated runtime module {public_name} source is unavailable."
            ) from exc
        try:
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size <= 0
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise LinuxArtifactGateError(
                    f"authenticated runtime module {public_name} source is unsafe."
                )
            values: dict[str, object] = {}
            for attribute in attributes:
                value = getattr(module, attribute, None)
                if value is None:
                    raise LinuxArtifactGateError(
                        f"authenticated runtime module {public_name}.{attribute} is missing."
                    )
                values[attribute] = value
            indexed: dict[str, tuple[object, ...]] = {}
            if source_derived:
                payload = os.pread(fd, info.st_size, 0)
                if len(payload) != info.st_size:
                    raise LinuxArtifactGateError(
                        f"authenticated runtime module {public_name} source was truncated."
                    )
                indexed = _compiled_code_index(payload, source)
                for attribute in source_derived:
                    _require_source_derived_attribute(
                        module, attribute, indexed, public_name
                    )
            self.public_name = public_name
            self.module = module
            self.private = private
            self.path = path
            self.fd = fd
            self.identity = _file_identity(info)
            self.digest = _sha256_fd(fd)
            self.values = MappingProxyType(values)
            self.source_derived = source_derived
            self.constant_fingerprints = MappingProxyType(
                {
                    attribute: _runtime_constant_fingerprint(values[attribute])
                    for attribute in constants
                }
            )
            self.indexed_code = MappingProxyType(indexed)
            fd = -1
        finally:
            if fd >= 0:
                os.close(fd)

    def require_objects(self) -> None:
        if not self.private and sys.modules.get(self.public_name) is not self.module:
            raise LinuxArtifactGateError(
                f"authenticated runtime module {self.public_name} identity is poisoned."
            )
        for attribute, expected in self.values.items():
            if getattr(self.module, attribute, None) is not expected:
                raise LinuxArtifactGateError(
                    f"authenticated runtime module {self.public_name}.{attribute} was poisoned."
                )
        for attribute in self.source_derived:
            _require_source_derived_attribute(
                self.module,
                attribute,
                self.indexed_code,
                self.public_name,
            )
        for attribute, expected in self.constant_fingerprints.items():
            if _runtime_constant_fingerprint(
                getattr(self.module, attribute, None)
            ) != expected:
                raise LinuxArtifactGateError(
                    f"authenticated runtime module {self.public_name}.{attribute} "
                    "constant was poisoned."
                )

    def revalidate(self) -> None:
        self.require_objects()
        if self.fd < 0:
            raise LinuxArtifactGateError(
                f"authenticated runtime module {self.public_name} custody is closed."
            )
        _require_readonly_fd(
            self.fd, f"authenticated runtime module {self.public_name} source"
        )
        try:
            retained = os.fstat(self.fd)
            named = self.path.lstat()
        except OSError as exc:
            raise LinuxArtifactGateError(
                f"authenticated runtime module {self.public_name} source changed."
            ) from exc
        if (
            _file_identity(retained) != self.identity
            or _file_identity(named) != self.identity
            or _sha256_fd(self.fd) != self.digest
        ):
            raise LinuxArtifactGateError(
                f"authenticated runtime module {self.public_name} source changed."
            )


_RUNTIME_MODULE_CUSTODY = (
    _RuntimeModuleBinding(
        "os",
        os,
        (
            "open", "close", "dup", "fstat", "stat", "lstat", "pread",
            "read", "write", "fsync", "listdir", "chmod", "fchmod", "mkdir",
            "rmdir",
            "unlink", "rename", "replace", "set_inheritable", "set_blocking",
            "killpg",
        ),
    ),
    _RuntimeModuleBinding(
        "fcntl",
        fcntl,
        ("fcntl", "flock", "LOCK_EX", "LOCK_NB"),
        constants=("LOCK_EX", "LOCK_NB"),
    ),
    _RuntimeModuleBinding(
        "stat", stat, ("S_ISREG", "S_ISDIR", "S_ISLNK", "S_IMODE")
    ),
    _RuntimeModuleBinding(
        "zipfile", REVIEWED_ZIPFILE, ("ZipFile", "ZipInfo", "is_zipfile")
    ),
    _RuntimeModuleBinding(
        "tarfile", REVIEWED_TARFILE, ("open", "TarInfo", "is_tarfile")
    ),
    _RuntimeModuleBinding(
        "subprocess",
        subprocess,
        ("run", "Popen", "PIPE", "DEVNULL", "TimeoutExpired"),
        source_derived=("run", "Popen"),
    ),
    _RuntimeModuleBinding(
        "selectors", selectors, ("DefaultSelector", "EVENT_READ")
    ),
    _RuntimeModuleBinding("shlex", shlex, ("split",), source_derived=("split",)),
    _RuntimeModuleBinding("signal", signal, ("SIGTERM", "SIGKILL")),
    _RuntimeModuleBinding(
        "validate_release_artifact_privacy",
        privacy,
        (
            "check_blob", "reject_local_build_paths",
            "reject_unstripped_native_library", "validate_tar_metadata",
            "validate_zip_metadata", "_tar_open_mode", "PrivacyError",
            "zipfile", "tarfile", "io",
        ),
        private=True,
        source_derived=(
            "check_blob",
            "reject_local_build_paths",
            "reject_unstripped_native_library",
            "validate_tar_metadata",
            "validate_zip_metadata",
            "_tar_open_mode",
        ),
    ),
    _RuntimeModuleBinding(
        "linux_release_signing",
        linux_release_signing,
        (
            "_proc_fd_path", "open_authenticated_cosign", "SigningError",
            "STANDARD_BUNDLE_MEDIA_TYPE",
        ),
        private=True,
        source_derived=("_proc_fd_path", "open_authenticated_cosign"),
        constants=("STANDARD_BUNDLE_MEDIA_TYPE",),
    ),
    _RuntimeModuleBinding(
        "release_source_freeze",
        source_freeze,
        (
            "verified_release_source_state", "SourceFreezeError",
            "SOURCE_SYMLINK_ALIASES", "SOURCE_PATHS_NATIVE_HOST",
        ),
        private=True,
        source_derived=("verified_release_source_state",),
        constants=(
            "SOURCE_SYMLINK_ALIASES", "SOURCE_PATHS_NATIVE_HOST",
        ),
    ),
    _RuntimeModuleBinding(
        "release_dependency_freeze",
        freeze,
        (
            "verify_build_receipt", "DependencyFreezeError",
            "PLATFORM_ALLOWED_TARGETS", "PLATFORM_BUILD_PRODUCERS",
            "CUSTODY_BINDING_KEYS", "SOURCE_FREEZE_RECEIPT_KEYS",
        ),
        private=True,
        source_derived=("verify_build_receipt",),
        constants=(
            "PLATFORM_ALLOWED_TARGETS", "PLATFORM_BUILD_PRODUCERS",
            "CUSTODY_BINDING_KEYS", "SOURCE_FREEZE_RECEIPT_KEYS",
        ),
    ),
    _RuntimeModuleBinding(
        "release_obfuscation_contract",
        obfuscation,
        (
            "inspect_native_debug_sections",
            "reject_packaged_private_symbols",
            "reject_sensitive_internal_identifiers",
            "ObfuscationError",
        ),
        private=True,
        source_derived=(
            "inspect_native_debug_sections",
            "reject_packaged_private_symbols",
            "reject_sensitive_internal_identifiers",
        ),
    ),
)


def _require_authenticated_runtime_boundary() -> None:
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or not sys.flags.safe_path
        or _BOOTSTRAP_SITE_MODULES
        or any(
            name in sys.modules
            for name in ("sitecustomize", "usercustomize")
        )
    ):
        raise LinuxArtifactGateError(
            "Linux cross-store gate requires a pristine -I -S worker; "
            "PYTHONPATH, sitecustomize, and reconstructed startup are refused."
        )
    _require_pristine_meta_path()
    for binding in _RUNTIME_MODULE_CUSTODY:
        binding.require_objects()
    for binding in _RUNTIME_MODULE_CUSTODY:
        binding.revalidate()


def _require_reviewed_archive_modules() -> None:
    _require_authenticated_runtime_boundary()
    _reviewed_stdlib_module(REVIEWED_ZIPFILE, "zipfile")
    _reviewed_stdlib_module(REVIEWED_TARFILE, "tarfile")
    _reviewed_stdlib_module(REVIEWED_COMPRESSION, "compression")
    _reviewed_stdlib_module(REVIEWED_ZSTD, "compression.zstd")
    _reviewed_stdlib_module(REVIEWED_FCNTL, "fcntl")


def _load_toolchain_pins() -> dict[str, object]:
    path = TOOLS_DIR / "toolchain-pins.json"
    fd = os.open(path, _open_flags())
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
            raise LinuxArtifactGateError("toolchain pins must be one single-link file.")
        payload = os.pread(fd, info.st_size, 0)
        if len(payload) != info.st_size:
            raise LinuxArtifactGateError("toolchain pins mutated while they were read.")
    finally:
        os.close(fd)
    document = _strict_json_object(payload, "toolchain pins")
    _require_exact_keys(
        document,
        {
            "schema_version", "_purpose", "tools", "pending_convergence",
            "_declared_divergences_note", "declared_divergences", "sites",
            "discovery_scan_roots", "_not_covered",
        },
        "toolchain pins",
    )
    tools = document.get("tools")
    if type(tools) is not dict:
        raise LinuxArtifactGateError("toolchain pins tools schema is invalid.")
    _require_exact_keys(
        tools,
        {
            "python", "node", "browser", "openssl", "google_cloud_cli",
            "flutter", "flutter_pub_cache", "java", "cocoapods", "go",
            "gradle", "android_gradle_plugin", "kotlin", "xcode", "android_ndk",
            "linux",
        },
        "toolchain pins tools",
    )
    flutter = tools.get("flutter")
    if type(flutter) is not dict:
        raise LinuxArtifactGateError("toolchain pins Flutter schema is invalid.")
    _require_exact_keys(
        flutter,
        {
            "version", "revision", "dart_version", "archive_path",
            "archive_sha256", "install_tree_sha256", "installed_tree_sha256",
            "installed_tree_note", "channel_note",
            "review_status", "review_note", "host_provisioning",
        },
        "toolchain pins Flutter",
    )
    return flutter


def _load_reviewed_winn3_descriptor_ring_sha256() -> str:
    path = TOOLS_DIR / "winn3_descriptor_ring_defines.py"
    fd = os.open(path, _open_flags())
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
            raise LinuxArtifactGateError(
                "Winn3 descriptor ring defines must be one single-link file."
            )
        payload = os.pread(fd, info.st_size, 0)
        if len(payload) != info.st_size:
            raise LinuxArtifactGateError(
                "Winn3 descriptor ring defines mutated while they were read."
            )
    finally:
        os.close(fd)
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise LinuxArtifactGateError(
            "Winn3 descriptor ring defines are not UTF-8."
        ) from exc
    matches = re.findall(
        r'^REVIEWED_RING_SHA256 = \(\n    "([0-9a-f]{64})"\n\)$',
        text,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise LinuxArtifactGateError(
            "Winn3 descriptor ring defines do not bind exactly one reviewed ring identity."
        )
    return matches[0]


_FLUTTER_TOOLCHAIN = _load_toolchain_pins()
REQUIRED_DART_VERSION = _FLUTTER_TOOLCHAIN["dart_version"]
REQUIRED_FLUTTER_VERSION = _FLUTTER_TOOLCHAIN["version"]
REQUIRED_FLUTTER_REVISION = _FLUTTER_TOOLCHAIN["revision"]
REVIEWED_WINN3_DESCRIPTOR_RING_SHA256 = _load_reviewed_winn3_descriptor_ring_sha256()
WINN3_DESCRIPTOR_RING_ATTESTATION_NAME = "winn3-descriptor-ring-attestation.json"
WINN3_DESCRIPTOR_RING_ATTESTATION_MODE = 0o644
WINN3_DESCRIPTOR_RING_ATTESTATION_SCHEMA_VERSION = 1
WINN3_DESCRIPTOR_RING_VERIFIED_ARTIFACT = "lib/libapp.so"
WINN3_DESCRIPTOR_RING_ATTESTATION_KEYS = frozenset(
    {
        "schema_version",
        "identity_sha256",
        "verified_artifact",
    }
)
STORE_WINN3_DESCRIPTOR_RING_ATTESTATION_RELATIVE = (
    "share/winsvpn/" + WINN3_DESCRIPTOR_RING_ATTESTATION_NAME
)
TARGETS = {
    "linux-x64-package": ("x64", 62),
    "linux-arm64-package": ("arm64", 183),
}
REQUIRED_FILES = frozenset(
    {
        "wins_vpn",
        "winsvpn-bypass-bpf",
        "xray",
        "awg",
        "awg-quick",
        "amneziawg-go",
        "winn-datapath",
        "install.sh",
        "release-manifest.sha256",
        "winn3-descriptor-ring-attestation.json",
        "lib/libapp.so",
        "lib/libflutter_linux_gtk.so",
        "data/icudtl.dat",
        "data/flutter_assets/AssetManifest.bin",
        "data/flutter_assets/FontManifest.json",
        "share/applications/org.winsvpn.app.desktop",
        "share/metainfo/org.winsvpn.app.metainfo.xml",
        "share/icons/hicolor/512x512/apps/org.winsvpn.app.png",
        "share/doc/wins-vpn/THIRD_PARTY_NOTICES.md",
        "share/doc/wins-vpn/RECOVERY.md",
        "extension/manifest/firefox.jsonc",
        "extension/tools/jsonc.py",
        "tools/native_messaging/host/wins_bridge_host",
        "tools/native_messaging/install_native_host.sh",
        "tools/native_messaging/linux-release-provenance.json",
        "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
        "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json",
        "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json",
        "tools/native_messaging/manifests/store_ids.json",
        "tools/native_messaging/native_host_layout.py",
        "tools/native_messaging/render_host_manifest.py",
    }
)
REQUIRED_PROGRAM_ELFS = frozenset(
    {
        "wins_vpn",
        "winsvpn-bypass-bpf",
        "xray",
        "awg",
        "amneziawg-go",
        "winn-datapath",
        "tools/native_messaging/host/wins_bridge_host",
    }
)
REQUIRED_LIBRARY_ELFS = frozenset(
    {
        "lib/libapp.so",
        "lib/libflutter_linux_gtk.so",
    }
)
FLUTTER_PAYLOAD_FILES = {
    "lib/libapp.so": "elf",
    "lib/libflutter_linux_gtk.so": "elf",
    "data/icudtl.dat": "data",
    "data/flutter_assets/AssetManifest.bin": "data",
    "data/flutter_assets/FontManifest.json": "data",
    "winsvpn-bypass-bpf": "elf",
}
NATIVE_HOST_PATH = "tools/native_messaging/host/wins_bridge_host"
NATIVE_HOST_PROVENANCE_PATH = "tools/native_messaging/linux-release-provenance.json"
NATIVE_HOST_INSTALLED_PATH = "/usr/lib/wins-vpn/wins_bridge_host"
NATIVE_HOST_SOURCE_PATHS = (
    "extension/manifest/firefox.jsonc",
    "extension/tools/jsonc.py",
    "lib/browser_bridge_app_ipc.dart",
    "lib/browser_bridge_framing.dart",
    "lib/browser_bridge_protocol.dart",
    "lib/browser_bridge_proxy.dart",
    "lib/vpn_config_validation.dart",
    "lib/windows_system_executable.dart",
    "lib/winn_carrier_profile_keys.dart",
    "lib/winn_protocol_dispatch.dart",
    "tools/native_messaging/host/bin/wins_bridge_host.dart",
    "tools/native_messaging/host/pubspec.lock",
    "tools/native_messaging/host/pubspec.yaml",
    "tools/native_messaging/install_native_host.sh",
    "tools/native_messaging/manifests/store_ids.json",
    "tools/native_messaging/native_host_layout.py",
    "tools/native_messaging/render_host_manifest.py",
)
NATIVE_HOST_PACKAGED_IDENTITY_INPUTS = frozenset(
    {
        "extension/manifest/firefox.jsonc",
        "extension/tools/jsonc.py",
        "tools/native_messaging/manifests/store_ids.json",
    }
)
NATIVE_HOST_PACKAGED_ASSETS = frozenset(
    {
        "extension/manifest/firefox.jsonc",
        "extension/tools/jsonc.py",
        NATIVE_HOST_PATH,
        "tools/native_messaging/install_native_host.sh",
        "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
        "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json",
        "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json",
        "tools/native_messaging/manifests/store_ids.json",
        "tools/native_messaging/native_host_layout.py",
        "tools/native_messaging/render_host_manifest.py",
    }
)
NATIVE_HOST_EXECUTABLES = frozenset(
    {
        NATIVE_HOST_PATH,
        "tools/native_messaging/install_native_host.sh",
    }
)
TRUSTED_LOCAL_COSIGN_KEY = pathlib.Path("linux/packaging/release-signing/cosign.pub")
OWNER_BLOCKED = "OWNER-BLOCKED: ABSENT"
OWNER_COSIGN_TRUST_ANCHOR_SHA256 = (
    # Linux release cosign key, ceremony 2026-10-16 (owner ruling 2026-10-15): sha256 of
    # linux/packaging/release-signing/cosign.pub.
    "7b66c6fed0f6cc06e09cde6bc0cf89a6b1d07f3084020ecb8d8adb3b41e88144"
)
OWNER_UPLOAD_RECEIPT_TRUST_SHA256 = (
    # Linux release cosign key, ceremony 2026-10-16 (owner ruling 2026-10-15): sha256 of
    # linux/packaging/release-signing/cosign.pub.
    "7b66c6fed0f6cc06e09cde6bc0cf89a6b1d07f3084020ecb8d8adb3b41e88144"
)
OWNER_STORE_TOOL_SHA256 = {
    "Flatpak": OWNER_BLOCKED,
    "Snap": OWNER_BLOCKED,
}
RELEASE_IDENTITY_PATH = "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
STORE_METADATA_ROOT = "app_store/linux"
METAINFO_RELATIVE = "linux/packaging/org.winsvpn.app.metainfo.xml"
DESKTOP_ENTRY_RELATIVE = "linux/packaging/org.winsvpn.app.desktop"
LINUX_APPIMAGE_FILENAME = "wins-vpn-1.0.17-x86_64.AppImage"
LINUX_DEB_FILENAME = "wins-vpn_1.0.17-34_amd64.deb"
LINUX_DEB_PATH = "build/linux-deb/wins-vpn_1.0.17-34_amd64.deb"
LINUX_TARBALL_PATH = "web/downloads/wins-vpn-linux-x64.tar.gz"
LINUX_APPIMAGE_UPLOAD_TARGET = False
LINUX_TITLE_MAX = 50
LINUX_SHORT_DESCRIPTION_MAX = 200
LINUX_FULL_DESCRIPTION_MAX = 10000
LINUX_WHATS_NEW_MAX = 1500
LINUX_FEATURE_MAX_COUNT = 20
LINUX_FEATURE_MAX_CHARS = 200
LINUX_SEARCH_TERM_MAX_COUNT = 7
LINUX_SEARCH_TERM_MAX_CHARS = 30
LINUX_COPYRIGHT = "Copyright (C) 2026 Win's VPN Inc. All rights reserved."
LINUX_PRIVACY_POLICY_URL = "https://www.winsvpn.org/privacy/"
LINUX_SUPPORT_URL = "https://www.winsvpn.org/support/"
LINUX_WEBSITE_URL = "https://winsvpn.org"
LINUX_STORE_FILES = (
    "README.md",
    "metadata/en-US/title.txt",
    "metadata/en-US/short_description.txt",
    "metadata/en-US/full_description.txt",
    "metadata/en-US/whats_new.txt",
    "metadata/en-US/features.txt",
    "metadata/en-US/search_terms.txt",
    "metadata/en-US/copyright.txt",
    "metadata/en-US/support_url.txt",
    "metadata/en-US/privacy_url.txt",
    "metadata/en-US/website_url.txt",
    "review/distribution_notes.txt",
    "review/privacy_label_manifest.json",
    "review/owner_signoff.json",
    "artifacts/release_candidate.json",
)
LINUX_OWNER_SIGNOFF_BLOCKERS = [
    "Linux listing/screenshot inventory is owner-blocked",
    "Local cosign/Sigstore identity remains owner-held",
    "No current signed x64 tarball, Debian, Flathub, or Snap receipt for 1.0.17+34",
    "Website tarball, Debian, Flathub, and Snap upload remain owner-authorized only",
    "AppImage is not a 1.0.17+34 upload target",
    "Private Flutter symbols and per-surface obfuscation receipts remain unpublished",
    "Native ARM64 remains pending-owner-evidence",
]
LINUX_TUNNEL_PROTOCOL = {
    "executed_on": "local-device",
    "primary": "winn-v3",
    "fallback": ["awg", "xray"],
    "required_local_engines": [
        "winn-datapath",
        "awg",
        "awg-quick",
        "amneziawg-go",
        "xray",
        "winsvpn-bypass-bpf",
    ],
    "required_native_host": "tools/native_messaging/host/wins_bridge_host",
}
LINUX_COLLECTED_CATEGORIES = [
    "device_or_other_ids",
    "user_ids",
    "email_address",
    "approximate_location",
    "purchase_history",
    "app_info",
    "diagnostics_if_sdk_report_proves",
]
LINUX_NOT_COLLECTED_CATEGORIES = [
    "browsing_history",
    "dns_query_history",
    "traffic_content",
    "raw_vpn_traffic",
    "destination_activity",
]
LINUX_X64_CANDIDATE_TARGETS = (
    "linux-x64-package",
    "linux-flathub-manifest",
    "linux-snap-manifest",
)
STORE_MANIFEST_TARGETS = {
    "linux-flathub-manifest": {
        "kind": "Flatpak",
        "store_kind": "flathub",
        "recipe_name": "org.winsvpn.app.json",
        "package_name": "org.winsvpn.app.flatpak",
        "payload_prefix": "files/",
        "recipe_markers": (
            "--obfuscate",
            "--split-debug-info=",
            "--extra-gen-snapshot-options=--strip",
            "winn-datapath",
            "xray",
            "awg",
            "amneziawg-go",
            "winn3-descriptor-ring-attestation.json",
            "FLATPAK_ARCH",
            "x86_64",
            "aarch64",
        ),
        "flutter": {
            "libapp": "lib/winsvpn/libapp.so",
            "libflutter": "lib/winsvpn/libflutter_linux_gtk.so",
            "icu": "data/icudtl.dat",
            "asset_manifest": "data/flutter_assets/AssetManifest.bin",
            "font_manifest": "data/flutter_assets/FontManifest.json",
            "bypass": "bin/winsvpn-bypass-bpf",
        },
    },
    "linux-snap-manifest": {
        "kind": "Snap",
        "store_kind": "snap",
        "recipe_name": "snapcraft.yaml",
        "package_name": "wins-vpn.snap",
        "payload_prefix": "",
        "recipe_markers": (
            "--obfuscate",
            "--split-debug-info=",
            "--extra-gen-snapshot-options=--strip",
            "winn-datapath",
            "xray",
            "awg",
            "amneziawg-go",
            "winn3-descriptor-ring-attestation.json",
            "CRAFT_ARCH_BUILD_FOR",
            "amd64",
            "arm64",
        ),
        "flutter": {
            "libapp": "lib/libapp.so",
            "libflutter": "lib/libflutter_linux_gtk.so",
            "icu": "data/icudtl.dat",
            "asset_manifest": "data/flutter_assets/AssetManifest.bin",
            "font_manifest": "data/flutter_assets/FontManifest.json",
            "bypass": "bin/winsvpn-bypass-bpf",
        },
    },
}
STORE_PACKAGE_ARCHITECTURES = {
    "x64": 62,
    "arm64": 183,
}
STORE_PACKAGE_PAYLOADS = (
    "wins_vpn",
    "winn-datapath",
    "xray",
    "awg",
    "awg-quick",
    "amneziawg-go",
    "winsvpn-bypass-bpf",
)
STORE_PACKAGE_ELFS = (
    "wins_vpn",
    "winn-datapath",
    "xray",
    "awg",
    "amneziawg-go",
    "winsvpn-bypass-bpf",
)
STORE_PACKAGE_EXECUTABLES = frozenset(STORE_PACKAGE_PAYLOADS)
PRIVATE_STORE_SYMBOL_ROOT = pathlib.Path(".artifacts/private-release-symbols/linux")
PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION = 2
PACKAGE_UPLOAD_RECEIPT_CONTRACT = "winsvpn-linux-package-upload-receipt-v2"
OWNER_AUTHORIZATION_CONTRACT = "winsvpn-linux-owner-authorization-v2"
UPLOAD_AUTHORIZATION_SCHEMA_VERSION = 1
UPLOAD_AUTHORIZATION_CONTRACT = "winsvpn-linux-upload-receipt-authorization-v1"
UPLOAD_AUTHORIZATION_ROOT = pathlib.Path(
    ".artifacts/linux/upload-receipt-authorizations"
)
REQUIRED_LINUX_UPLOAD_TARGETS = (
    "linux-x64-package",
    "linux-arm64-package",
    "linux-flathub-manifest",
    "linux-snap-manifest",
)
PACKAGE_UPLOAD_RECEIPT_KEYS = frozenset(
    {
        "ok",
        "schema_version",
        "contract",
        "release",
        "target_id",
        "platform",
        "artifact",
        "build_receipt",
        "producer",
        "package_identity",
        "architectures",
        "signing",
        "store_evidence",
        "descriptor",
        "source_freeze",
        "obfuscation_privacy",
        "winn3_descriptor_ring_attestation",
        "publication_authorized",
        "upload_attempted",
        "owner_authorization",
        "authentication",
    }
)
UPLOAD_RECEIPT_ISSUER = "winsvpn-linux-package-upload-receipt"
UPLOAD_RECEIPT_AUTH_KEYS = frozenset(
    {
        "contract",
        "schema_version",
        "authority_receipt_path",
        "authority_receipt_sha256",
    }
)
UPLOAD_AUTHORIZATION_KEYS = frozenset(
    {
        "contract",
        "schema_version",
        "issuer",
        "authorization_id",
        "nonce",
        "issued_at",
        "expires_at",
        "target_id",
        "architectures",
        "release",
        "artifact_sha256",
        "artifact_bytes",
        "upload_receipt_binding_sha256",
        "publication_authorized",
        "upload_attempted",
    }
)
UPLOAD_RECEIPT_PLACEHOLDER_TRUST_MARKERS = (
    "placeholder",
    "ed25519privatekey",
    "ed25519publickey",
)
RECEIPT_UNAUTHENTICATED_ERROR = (
    "Linux package/upload receipt is not authenticated by the trusted issuer"
)
RECEIPT_PLACEHOLDER_TRUST_ERROR = (
    "Linux package/upload receipt trust key is a placeholder"
)
WINN3_DESCRIPTOR_RING_ATTESTATION_RECEIPT_KEYS = frozenset(
    {
        "path",
        "mode",
        "sha256",
        "identity_sha256",
        "architectures",
        "verified_artifact",
    }
)
LINUX_PACKAGE_UPLOAD_TARGETS = {
    "linux-x64-package": {
        "kind": "DEB",
        "store_kind": "debian",
        "platform": "linux",
        "required": True,
        "architectures": ("x64",),
        "artifact_suffixes": (".tar.gz",),
        "artifact_name": "wins-vpn-linux-x64.tar.gz",
        "package_name": "wins-vpn",
        "signing_contract": "linux-local-key-sigstore",
        "signing_status": "required",
        "trust_anchor": TRUSTED_LOCAL_COSIGN_KEY.as_posix(),
        "store_surface": "website-tarball",
        "producer": "tools/build_linux_release.sh",
        "build_receipt_target": "linux-x64",
        "elf_machine": 62,
        "identity_keys": frozenset(
            {"name", "appstream_version", "debian_version", "elf_machine"}
        ),
    },
    "linux-arm64-package": {
        "kind": "DEB",
        "store_kind": "debian",
        "platform": "linux",
        "required": True,
        "architectures": ("arm64",),
        "artifact_suffixes": (".tar.gz",),
        "artifact_name": "wins-vpn-linux-arm64.tar.gz",
        "package_name": "wins-vpn",
        "signing_contract": "linux-local-key-sigstore",
        "signing_status": "required",
        "trust_anchor": TRUSTED_LOCAL_COSIGN_KEY.as_posix(),
        "store_surface": "website-tarball",
        "producer": "tools/build_linux_release.sh",
        "build_receipt_target": "linux-arm64",
        "elf_machine": 183,
        "identity_keys": frozenset(
            {"name", "appstream_version", "debian_version", "elf_machine"}
        ),
    },
    "linux-flathub-manifest": {
        "kind": "Flatpak",
        "store_kind": "flathub",
        "platform": "linux",
        "required": True,
        "architectures": ("x64", "arm64"),
        "artifact_suffixes": (".json",),
        "artifact_name": "org.winsvpn.app.json",
        "package_name": "org.winsvpn.app",
        "signing_contract": "flathub-ostree",
        "signing_status": "not_present",
        "trust_anchor": None,
        "store_surface": "flathub-separate-manifest",
        "producer": "linux/packaging/flathub/manifest_artifact.py",
        "build_receipt_target": "linux-flathub-manifest",
        "elf_machines": {"x64": 62, "arm64": 183},
        "identity_keys": frozenset(
            {"name", "appstream_version", "debian_version", "elf_machines"}
        ),
    },
    "linux-snap-manifest": {
        "kind": "Snap",
        "store_kind": "snap",
        "platform": "linux",
        "required": True,
        "architectures": ("x64", "arm64"),
        "artifact_suffixes": (".yaml", ".yml"),
        "artifact_name": "snapcraft.yaml",
        "package_name": "wins-vpn",
        "signing_contract": "snap-store",
        "signing_status": "not_present",
        "trust_anchor": None,
        "store_surface": "snap-separate-manifest",
        "producer": "linux/packaging/snap/manifest_artifact.py",
        "build_receipt_target": "linux-snap-manifest",
        "elf_machines": {"x64": 62, "arm64": 183},
        "identity_keys": frozenset(
            {"name", "appstream_version", "debian_version", "elf_machines"}
        ),
    },
}


class AuthenticatedSnapshot:
    def __init__(
        self,
        origin: pathlib.Path,
        path: pathlib.Path,
        fd: int,
        origin_identity: tuple[int, ...],
        identity: tuple[int, ...],
        digest: str,
        size: int,
        root: pathlib.Path,
        origin_fd: int | None = None,
        origin_ancestor_chain: _RetainedDirectoryChain | None = None,
        snapshot_ancestor_chain: _RetainedDirectoryChain | None = None,
        lease_fd: int | None = None,
    ) -> None:
        self.origin = origin
        self.path = path
        self.fd = fd
        self.origin_identity = origin_identity
        self.identity = identity
        self.digest = digest
        self.size = size
        self.root = root
        self.origin_fd = origin_fd
        self.origin_ancestor_chain = origin_ancestor_chain
        self.snapshot_ancestor_chain = snapshot_ancestor_chain
        self.lease_fd = lease_fd
        self._result_owner: object | None = None

    def claim_result_owner(self, owner: object) -> None:
        if self._result_owner is not None:
            raise LinuxArtifactGateError(
                "authenticated artifact snapshot already belongs to another result."
            )
        self._result_owner = owner

    def require_result_owner(self, owner: object) -> None:
        if self._result_owner is not owner:
            raise LinuxArtifactGateError(
                "authenticated artifact snapshot result ownership changed."
            )

    def __copy__(self):
        raise LinuxArtifactGateError("authenticated artifact custody cannot be copied.")

    def __deepcopy__(self, memo):
        raise LinuxArtifactGateError(
            "authenticated artifact custody cannot be deep-copied."
        )

    def __reduce_ex__(self, protocol):
        raise LinuxArtifactGateError(
            "authenticated artifact custody cannot be serialized."
        )

    def ensure_bound(self) -> None:
        if self.fd < 0:
            raise LinuxArtifactGateError("authenticated artifact snapshot is closed.")
        _require_readonly_fd(self.fd, "authenticated artifact snapshot")
        if self.snapshot_ancestor_chain is None:
            raise LinuxArtifactGateError(
                "authenticated artifact snapshot ancestor custody is missing."
            )
        self.snapshot_ancestor_chain.revalidate()
        current = os.fstat(self.fd)
        latest = self.path.lstat()
        if _file_identity(current) != self.identity or _file_identity(latest) != self.identity:
            raise LinuxArtifactGateError("authenticated artifact snapshot identity changed.")
        if self.origin_fd is not None:
            if self.origin_fd < 0:
                raise LinuxArtifactGateError(
                    "authenticated artifact source custody is closed."
                )
            _require_readonly_fd(self.origin_fd, "authenticated artifact source")
            if self.origin_ancestor_chain is None:
                raise LinuxArtifactGateError(
                    "authenticated artifact source ancestor custody is missing."
                )
            self.origin_ancestor_chain.revalidate()
            source = os.fstat(self.origin_fd)
            try:
                named = self.origin.lstat()
            except OSError as exc:
                raise LinuxArtifactGateError(
                    "authenticated artifact source was replaced or removed."
                ) from exc
            if (
                _file_identity(source) != self.origin_identity
                or _file_identity(named) != self.origin_identity
            ):
                raise LinuxArtifactGateError(
                    "authenticated artifact source was swapped or restored; identity changed."
                )

    def reject_origin_swap(self) -> None:
        if self.origin_ancestor_chain is None:
            raise LinuxArtifactGateError(
                "artifact origin ancestor custody is missing."
            )
        self.origin_ancestor_chain.revalidate()
        try:
            latest = self.origin.lstat()
        except OSError as exc:
            raise LinuxArtifactGateError(
                "artifact origin was replaced or restored during verification."
            ) from exc
        if _file_identity(latest) != self.origin_identity:
            raise LinuxArtifactGateError(
                "artifact origin was swapped or restored during verification."
            )

    def header(self, size: int = 512) -> bytes:
        self.ensure_bound()
        return os.pread(self.fd, size, 0)

    def rehash(self) -> str:
        self.ensure_bound()
        digest = _sha256_fd(self.fd)
        if digest != self.digest:
            raise LinuxArtifactGateError("authenticated artifact snapshot digest changed.")
        if self.origin_fd is not None and _sha256_fd(self.origin_fd) != self.digest:
            raise LinuxArtifactGateError("authenticated artifact source digest changed.")
        self.ensure_bound()
        return digest

    def close(self) -> None:
        failure: BaseException | None = None
        try:
            if (
                self.lease_fd is not None
                and self.lease_fd >= 0
                and self.snapshot_ancestor_chain is not None
            ):
                if self.fd < 0:
                    raise LinuxArtifactGateError(
                        "authenticated artifact snapshot cleanup descriptor is closed."
                    )
                _require_readonly_fd(
                    self.fd, "authenticated artifact snapshot cleanup"
                )
                self.snapshot_ancestor_chain.revalidate()
                retained = os.fstat(self.fd)
                named = self.path.lstat()
                if (
                    _file_identity(retained) != self.identity
                    or _file_identity(named) != self.identity
                ):
                    raise LinuxArtifactGateError(
                        "authenticated artifact snapshot cleanup identity changed."
                    )
                _remove_retained_artifact_snapshot_root(
                    self.snapshot_ancestor_chain, self.lease_fd
                )
        except BaseException as exc:
            failure = exc
        finally:
            if self.origin_fd is not None and self.origin_fd >= 0:
                os.close(self.origin_fd)
                self.origin_fd = -1
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1
            if self.origin_ancestor_chain is not None:
                self.origin_ancestor_chain.close()
                self.origin_ancestor_chain = None
            if self.snapshot_ancestor_chain is not None:
                self.snapshot_ancestor_chain.close()
                self.snapshot_ancestor_chain = None
            if self.lease_fd is not None and self.lease_fd >= 0:
                os.close(self.lease_fd)
                self.lease_fd = -1
        if failure is not None:
            raise failure


class HeldArtifactSnapshot(AuthenticatedSnapshot):
    """Private snapshot retaining the authoritative source and parent FDs."""

    def __init__(
        self,
        *,
        origin: pathlib.Path,
        path: pathlib.Path,
        fd: int,
        source_fd: int,
        source_parent_fd: int,
        source_name: str,
        source_identity: tuple[int, ...],
        parent_identity: tuple[int, ...],
        ancestor_chain: _RetainedDirectoryChain,
        identity: tuple[int, ...],
        digest: str,
        size: int,
        root: pathlib.Path,
    ) -> None:
        super().__init__(
            origin=origin,
            path=path,
            fd=fd,
            origin_identity=source_identity,
            identity=identity,
            digest=digest,
            size=size,
            root=root,
            origin_ancestor_chain=ancestor_chain,
            snapshot_ancestor_chain=_retain_complete_directory_chain(
                path.parent, "Held Linux artifact private snapshot"
            ),
        )
        self.source_fd = source_fd
        self.source_parent_fd = source_parent_fd
        self.source_name = source_name
        self.source_identity = source_identity
        self.parent_identity = parent_identity
        self.ancestor_chain = ancestor_chain

    def ensure_bound(self) -> None:
        super().ensure_bound()
        if self.source_fd < 0 or self.source_parent_fd < 0:
            raise LinuxArtifactGateError("held Linux artifact custody is closed.")
        self.ancestor_chain.revalidate()
        _require_readonly_fd(self.source_fd, "held Linux artifact source")
        _require_readonly_fd(self.source_parent_fd, "held Linux artifact parent")
        source = os.fstat(self.source_fd)
        parent = os.fstat(self.source_parent_fd)
        try:
            named = os.stat(
                self.source_name,
                dir_fd=self.source_parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise LinuxArtifactGateError(
                "held Linux artifact name was replaced or removed."
            ) from exc
        _require_unique_casefold_name(
            self.source_parent_fd,
            self.source_name,
            "Held Linux release artifact",
        )
        if (
            _file_identity(source) != self.source_identity
            or _file_identity(named) != self.source_identity
            or _file_identity(parent) != self.parent_identity
            or _file_identity(parent)
            != _file_identity(os.fstat(self.ancestor_chain.leaf_fd))
        ):
            raise LinuxArtifactGateError(
                "held Linux artifact or retained parent identity changed."
            )

    def reject_origin_swap(self) -> None:
        self.ensure_bound()

    def rehash(self) -> str:
        self.ensure_bound()
        source_digest = _sha256_fd(self.source_fd)
        snapshot_digest = _sha256_fd(self.fd)
        if source_digest != self.digest or snapshot_digest != self.digest:
            raise LinuxArtifactGateError(
                "held Linux artifact or private snapshot digest changed."
            )
        self.ensure_bound()
        return self.digest

    def close(self) -> None:
        if self.source_fd >= 0:
            os.close(self.source_fd)
            self.source_fd = -1
        if self.source_parent_fd >= 0:
            os.close(self.source_parent_fd)
            self.source_parent_fd = -1
        super().close()


def _deep_freeze(value: object) -> object:
    if type(value) is dict:
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if type(value) is list:
        return tuple(_deep_freeze(item) for item in value)
    if type(value) is tuple:
        return tuple(_deep_freeze(item) for item in value)
    if type(value) is set:
        return frozenset(_deep_freeze(item) for item in value)
    if type(value) is float and not math.isfinite(value):
        raise LinuxArtifactGateError(
            "verification result contains a non-finite number."
        )
    if isinstance(value, (str, int, float, bool, bytes, type(None))):
        return value
    raise LinuxArtifactGateError(
        f"verification result contains unsupported mutable state: {type(value).__name__}."
    )


def _deep_thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _deep_thaw(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_deep_thaw(item) for item in value]
    if isinstance(value, frozenset):
        return sorted((_deep_thaw(item) for item in value), key=repr)
    return value


class _CustodyIterator:
    def __init__(self, owner: VerificationResult, values: tuple[object, ...]) -> None:
        self._owner = owner
        self._values = values
        self._index = 0

    def __iter__(self):
        return self

    def __next__(self) -> object:
        self._owner.revalidate()
        if self._index >= len(self._values):
            raise StopIteration
        value = self._values[self._index]
        self._index += 1
        self._owner.revalidate()
        return value


def _custody_view(value: object, owner: VerificationResult) -> object:
    if isinstance(value, Mapping):
        return _CustodyMapping(owner, value)
    if type(value) is tuple:
        return _CustodySequence(owner, value)
    return value


class _CustodyMapping(Mapping[str, object]):
    def __init__(self, owner: VerificationResult, value: Mapping[str, object]) -> None:
        self._owner = owner
        self._value = value

    def __getitem__(self, key: str) -> object:
        self._owner.revalidate()
        value = _custody_view(self._value[key], self._owner)
        self._owner.revalidate()
        return value

    def __iter__(self):
        self._owner.revalidate()
        iterator = _CustodyIterator(self._owner, tuple(self._value))
        self._owner.revalidate()
        return iterator

    def __len__(self) -> int:
        self._owner.revalidate()
        length = len(self._value)
        self._owner.revalidate()
        return length


class _CustodySequence(Sequence[object]):
    def __init__(self, owner: VerificationResult, value: tuple[object, ...]) -> None:
        self._owner = owner
        self._value = value

    def __getitem__(self, index):
        self._owner.revalidate()
        value = self._value[index]
        if type(index) is slice:
            result = tuple(_custody_view(item, self._owner) for item in value)
        else:
            result = _custody_view(value, self._owner)
        self._owner.revalidate()
        return result

    def __iter__(self):
        self._owner.revalidate()
        iterator = _CustodyIterator(
            self._owner,
            tuple(_custody_view(item, self._owner) for item in self._value),
        )
        self._owner.revalidate()
        return iterator

    def __len__(self) -> int:
        self._owner.revalidate()
        length = len(self._value)
        self._owner.revalidate()
        return length

    def __eq__(self, other: object) -> bool:
        self._owner.revalidate()
        try:
            return tuple(self) == tuple(other)
        except TypeError:
            return False

    def __repr__(self) -> str:
        self._owner.revalidate()
        return repr(tuple(self))


class VerificationResult(Mapping[str, object]):
    """A successful result retaining all evidence until final consumption."""

    def __init__(
        self,
        payload: dict[str, object],
        snapshots: tuple[AuthenticatedSnapshot, ...],
    ) -> None:
        if not snapshots or len({id(snapshot) for snapshot in snapshots}) != len(
            snapshots
        ):
            raise LinuxArtifactGateError(
                "verification result evidence custody is incomplete or duplicated."
            )
        self._owner_token = object()
        claimed: list[AuthenticatedSnapshot] = []
        try:
            for snapshot in snapshots:
                snapshot.claim_result_owner(self._owner_token)
                claimed.append(snapshot)
            self._payload = _deep_freeze(payload)
            if not isinstance(self._payload, Mapping):
                raise LinuxArtifactGateError(
                    "verification result payload must be one mapping."
                )
            self._snapshots = snapshots
            self._closed = False
            self.revalidate()
        except BaseException:
            for snapshot in claimed:
                if snapshot._result_owner is self._owner_token:
                    snapshot._result_owner = None
            self._snapshots = ()
            self._closed = True
            raise

    @property
    def closed(self) -> bool:
        return self._closed

    def revalidate(self) -> None:
        if self._closed:
            raise LinuxArtifactGateError("verification result custody is closed.")
        _verify_all_module_custody()
        for snapshot in self._snapshots:
            snapshot.require_result_owner(self._owner_token)
            snapshot.reject_origin_swap()
            snapshot.rehash()

    def publication_payload(self) -> dict[str, object]:
        self.revalidate()
        payload = _deep_thaw(self._payload)
        if not isinstance(payload, dict):
            raise LinuxArtifactGateError("verification result payload thaw failed.")
        self.revalidate()
        return payload

    def _require_open(self) -> None:
        if self._closed:
            raise LinuxArtifactGateError("verification result custody is closed.")

    def __getitem__(self, key: str) -> object:
        self.revalidate()
        value = _custody_view(self._payload[key], self)
        self.revalidate()
        return value

    def __iter__(self):
        self.revalidate()
        iterator = _CustodyIterator(self, tuple(self._payload))
        self.revalidate()
        return iterator

    def __len__(self) -> int:
        self.revalidate()
        length = len(self._payload)
        self.revalidate()
        return length

    def __enter__(self) -> VerificationResult:
        self.revalidate()
        return self

    def __copy__(self):
        raise LinuxArtifactGateError("verification result custody cannot be copied.")

    def __deepcopy__(self, memo):
        raise LinuxArtifactGateError(
            "verification result custody cannot be deep-copied."
        )

    def __reduce__(self):
        raise LinuxArtifactGateError("verification result custody cannot be serialized.")

    def __reduce_ex__(self, protocol):
        raise LinuxArtifactGateError("verification result custody cannot be serialized.")

    def __getstate__(self):
        raise LinuxArtifactGateError("verification result custody cannot be serialized.")

    def close(self) -> None:
        if self._closed:
            return
        failure: BaseException | None = None
        try:
            self.revalidate()
        except BaseException as exc:
            failure = exc
        finally:
            for snapshot in reversed(self._snapshots):
                try:
                    snapshot.require_result_owner(self._owner_token)
                    snapshot.close()
                except BaseException as exc:
                    if failure is None:
                        failure = exc
            self._closed = True
        if failure is not None:
            raise failure

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            self.close()
        except BaseException as cleanup_error:
            if exc_value is None:
                raise
            if hasattr(exc_value, "add_note"):
                exc_value.add_note(
                    "verification result custody cleanup also failed: "
                    + str(cleanup_error)
                )
        return False

    def __del__(self) -> None:
        if getattr(self, "_closed", True):
            return
        for snapshot in reversed(getattr(self, "_snapshots", ())):
            try:
                snapshot.require_result_owner(self._owner_token)
                snapshot.close()
            except BaseException:
                pass
        self._closed = True


def _exact_json(payload: bytes, label: str) -> dict[str, object]:
    return _strict_json_object(payload, label)


def _valid_file_record(record: object, label: str, *, include_mode: bool) -> dict[str, object]:
    if not isinstance(record, dict):
        raise LinuxArtifactGateError(f"{label} is not an object.")
    keys = {"path", "sha256", "bytes", "mode"} if include_mode else {"path", "sha256", "bytes"}
    _require_exact_keys(record, keys, label)
    path = record.get("path")
    digest = record.get("sha256")
    byte_count = record.get("bytes")
    if (
        not isinstance(path, str)
        or not path
        or pathlib.PurePosixPath(path).is_absolute()
        or "\\" in path
        or any(part in {"", ".", ".."} for part in pathlib.PurePosixPath(path).parts)
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or byte_count <= 0
    ):
        raise LinuxArtifactGateError(f"{label} identity is invalid.")
    if include_mode:
        mode = record.get("mode")
        if not isinstance(mode, int) or isinstance(mode, bool) or mode not in {0o644, 0o755}:
            raise LinuxArtifactGateError(f"{label} mode is invalid.")
    return record


def _posix_normalize(parts: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    for part in parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not out:
                raise LinuxArtifactGateError("native-host source path escapes the repository.")
            out.pop()
            continue
        out.append(part)
    return tuple(out)


def native_host_source_paths() -> tuple[str, ...]:
    declared = tuple(NATIVE_HOST_SOURCE_PATHS)
    if declared != tuple(sorted(set(declared))):
        raise LinuxArtifactGateError(
            "native-host source closure paths must be unique and sorted."
        )
    for alias, target in source_freeze.SOURCE_SYMLINK_ALIASES:
        resolved = pathlib.PurePosixPath(alias).parent.joinpath(target)
        resolved_path = pathlib.PurePosixPath(*_posix_normalize(resolved.parts)).as_posix()
        if resolved_path not in declared:
            raise LinuxArtifactGateError(
                "native-host shared source alias does not resolve into the source closure: "
                + alias
            )
    shipping = set(source_freeze.SOURCE_PATHS_NATIVE_HOST) - {
        "tools/native_messaging/manifests/store_ids.json"
    }
    missing_shipping = sorted(shipping - set(declared))
    if missing_shipping:
        raise LinuxArtifactGateError(
            "native-host source closure omitted freeze-bound host inputs: "
            + ", ".join(missing_shipping)
        )
    missing_identity = sorted(
        path
        for path in (
            "extension/manifest/firefox.jsonc",
            "extension/tools/jsonc.py",
        )
        if path not in declared
    )
    if missing_identity:
        raise LinuxArtifactGateError(
            "native-host source closure omitted store-identity inputs: "
            + ", ".join(missing_identity)
        )
    return declared


def _read_origin_regular(relative: str, label: str) -> bytes:
    relative_path = pathlib.PurePosixPath(relative)
    if (
        not relative
        or "\\" in relative
        or relative_path.is_absolute()
        or any(part in {"", ".", ".."} for part in relative_path.parts)
    ):
        raise LinuxArtifactGateError(
            f"{label} must be one canonical repository-relative path."
        )
    root = ORIGIN_ROOT.resolve(strict=True)
    fd = _openat_from_root(
        root, relative_path.parts, last_directory=False, label=label
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
        ):
            raise LinuxArtifactGateError(f"{label} must be one non-empty, single-link file.")
        payload = os.pread(fd, info.st_size, 0)
        after = os.fstat(fd)
        if len(payload) != info.st_size or _file_identity(after) != _file_identity(info):
            raise LinuxArtifactGateError(f"{label} mutated while it was read.")
        return payload
    finally:
        os.close(fd)


def compute_native_host_source_closure() -> tuple[str, list[dict[str, object]]]:
    records: list[dict[str, object]] = []
    for relative in native_host_source_paths():
        payload = _read_origin_regular(relative, f"native-host source {relative}")
        records.append(
            {
                "path": relative,
                "sha256": _sha256_bytes(payload),
                "bytes": len(payload),
            }
        )
    encoded = (
        json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")
    return _sha256_bytes(encoded), records


_NATIVE_HOST_RENDERER: ModuleType | None = None
_NATIVE_HOST_MODULE_CUSTODY: tuple[_BoundModuleSource, ...] = ()


def _native_host_renderer() -> ModuleType:
    global _NATIVE_HOST_RENDERER, _NATIVE_HOST_MODULE_CUSTODY
    if _NATIVE_HOST_RENDERER is not None:
        _verify_module_custody(_NATIVE_HOST_MODULE_CUSTODY)
        return _NATIVE_HOST_RENDERER
    loaded, custody = _load_module_closure(
        (
            (
                ORIGIN_ROOT / "extension" / "tools" / "jsonc.py",
                "jsonc",
                "extension.tools",
                ("jsonc", "extension.tools.jsonc"),
            ),
            (
                ORIGIN_ROOT / "tools" / "native_messaging" / "render_host_manifest.py",
                "render_host_manifest",
                "tools.native_messaging",
                (
                    "render_host_manifest",
                    "tools.native_messaging.render_host_manifest",
                ),
            ),
        )
    )
    _NATIVE_HOST_MODULE_CUSTODY = custody
    _NATIVE_HOST_RENDERER = loaded["render_host_manifest"]
    _verify_module_custody(_NATIVE_HOST_MODULE_CUSTODY)
    return _NATIVE_HOST_RENDERER


def _owner_issued_chromium_ids() -> dict[str, str]:
    renderer = _native_host_renderer()
    try:
        return renderer.owner_issued_chromium_ids()
    except renderer.OwnerIdentityBlocked as exc:
        raise _owner_environment_blocker(str(exc)) from exc
    except renderer.OwnerIdentityInvalid as exc:
        raise LinuxArtifactGateError(str(exc)) from exc
    finally:
        _verify_module_custody(_NATIVE_HOST_MODULE_CUSTODY)


def _bind_native_host_source_freeze_custody() -> tuple[str, AuthenticatedSnapshot]:
    try:
        state = source_freeze.verified_release_source_state(ORIGIN_ROOT)
    except source_freeze.SourceFreezeError as exc:
        raise LinuxArtifactGateError(
            "native-host source closure is not bound to a current authenticated "
            f"source-freeze receipt: {exc}"
        ) from exc
    lock_path = _secure_regular_repo_path(
        state.lock_path, "native-host source-freeze receipt"
    )
    custody = _snapshot_artifact(
        lock_path, "native-host source-freeze receipt"
    )
    try:
        digest, _records = compute_native_host_source_closure()
        custody.reject_origin_swap()
        custody.rehash()
        return digest, custody
    except BaseException:
        private = custody.root
        custody.close()
        shutil.rmtree(private, ignore_errors=True)
        raise


def bind_native_host_source_freeze() -> str:
    digest, custody = _bind_native_host_source_freeze_custody()
    private = custody.root
    try:
        custody.reject_origin_swap()
        custody.rehash()
        return digest
    finally:
        custody.close()
        shutil.rmtree(private, ignore_errors=True)


def _verify_native_host_contract(
    payloads: dict[str, bytes],
    modes: dict[str, int],
    expected_arch: str,
    expected_machine: int,
    expected_closure: str,
) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", expected_closure) is None:
        raise LinuxArtifactGateError(
            "native-host source-freeze custody digest is invalid."
        )
    _require_executable_elf(
        payloads[NATIVE_HOST_PATH], NATIVE_HOST_PATH, expected_machine, require_entry=True
    )
    for name in NATIVE_HOST_PACKAGED_ASSETS | {NATIVE_HOST_PROVENANCE_PATH}:
        expected_mode = 0o755 if name in NATIVE_HOST_EXECUTABLES else 0o644
        if modes.get(name) != expected_mode:
            raise LinuxArtifactGateError(f"native-host package asset has unsafe mode: {name}")

    owner_ids = _owner_issued_chromium_ids()
    store_ids = _exact_json(
        payloads["tools/native_messaging/manifests/store_ids.json"], "native-host store id record"
    )
    _require_exact_keys(store_ids, {"chrome", "edge"}, "native-host store id record")
    chrome_id = store_ids.get("chrome")
    edge_id = store_ids.get("edge")
    if chrome_id != owner_ids["chrome"] or edge_id != owner_ids["edge"]:
        raise LinuxArtifactGateError(
            "native-host packaged store ids do not match the owner-issued Chrome and Edge identity."
        )
    missing_identity = sorted(NATIVE_HOST_PACKAGED_IDENTITY_INPUTS - payloads.keys())
    if missing_identity:
        raise LinuxArtifactGateError(
            "native-host package omitted store-identity inputs: " + ", ".join(missing_identity)
        )

    chrome = _exact_json(
        payloads["tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json"],
        "Chrome native-host manifest",
    )
    edge = _exact_json(
        payloads["tools/native_messaging/manifests/org.winsvpn.bridge.edge.json"],
        "Edge native-host manifest",
    )
    firefox = _exact_json(
        payloads["tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json"],
        "Firefox native-host manifest",
    )
    shared = {
        "name": "org.winsvpn.bridge",
        "description": "Win's VPN browser bridge",
        "path": NATIVE_HOST_INSTALLED_PATH,
        "type": "stdio",
    }
    if chrome != {
        **shared,
        "allowed_origins": [f"chrome-extension://{owner_ids['chrome']}/"],
    }:
        raise LinuxArtifactGateError("Chrome native-host manifest is not exact.")
    if edge != {
        **shared,
        "allowed_origins": [f"chrome-extension://{owner_ids['edge']}/"],
    }:
        raise LinuxArtifactGateError("Edge native-host manifest is not exact.")
    if firefox != {**shared, "allowed_extensions": ["companion@winsvpn.org"]}:
        raise LinuxArtifactGateError("Firefox native-host manifest is not exact.")
    for name in (
        "tools/native_messaging/manifests/store_ids.json",
        "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
        "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json",
        "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json",
    ):
        if b"placeholder" in payloads[name].lower():
            raise LinuxArtifactGateError(f"native-host registration asset contains a placeholder: {name}")

    provenance = _exact_json(payloads[NATIVE_HOST_PROVENANCE_PATH], "native-host provenance")
    _require_exact_keys(
        provenance,
        {
            "schema_version",
            "kind",
            "architecture",
            "elf_machine",
            "installed_host_path",
            "hardening",
            "toolchain",
            "source_closure_sha256",
            "source_inputs",
            "packaged_assets",
            "private_debug_info",
        },
        "native-host provenance",
    )
    if (
        provenance.get("schema_version") != 1
        or provenance.get("kind") != "winsvpn.linux.native_messaging_host.provenance.v1"
        or provenance.get("architecture") != expected_arch
        or provenance.get("elf_machine") != expected_machine
        or provenance.get("installed_host_path") != NATIVE_HOST_INSTALLED_PATH
        or provenance.get("source_closure_sha256") != expected_closure
    ):
        raise LinuxArtifactGateError("native-host provenance identity is invalid.")
    hardening = provenance.get("hardening")
    if hardening != {
        "compile_mode": "dart-aot-product",
        "tree_shaken": True,
        "debug_info_detached": True,
        "delivery_symbols_stripped": True,
        "host_dart_sources_shipped": False,
    }:
        raise LinuxArtifactGateError("native-host hardening provenance is invalid.")

    source_inputs = provenance.get("source_inputs")
    if not isinstance(source_inputs, list) or not source_inputs:
        raise LinuxArtifactGateError("native-host source closure is missing.")
    checked_sources = [
        _valid_file_record(record, f"native-host source input {index}", include_mode=False)
        for index, record in enumerate(source_inputs)
    ]
    source_paths = [str(record["path"]) for record in checked_sources]
    if source_paths != sorted(set(source_paths)):
        raise LinuxArtifactGateError("native-host source closure paths are not unique and sorted.")
    encoded_sources = (
        json.dumps(checked_sources, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")
    if _sha256_bytes(encoded_sources) != expected_closure:
        raise LinuxArtifactGateError(
            "native-host source closure does not match the current source-freeze receipt."
        )
    live_records = {
        record["path"]: record for record in compute_native_host_source_closure()[1]
    }
    if [record["path"] for record in checked_sources] != list(live_records):
        raise LinuxArtifactGateError(
            "native-host source closure is not the current freeze-bound source set."
        )
    for record in checked_sources:
        live = live_records[str(record["path"])]
        if record["sha256"] != live["sha256"] or record["bytes"] != live["bytes"]:
            raise LinuxArtifactGateError(
                "native-host source closure does not match current freeze-bound bytes."
            )
    overlapping = sorted(set(native_host_source_paths()) & set(NATIVE_HOST_PACKAGED_ASSETS))
    for relative in overlapping:
        live = live_records[relative]
        if (
            live["sha256"] != _sha256_bytes(payloads[relative])
            or live["bytes"] != len(payloads[relative])
        ):
            raise LinuxArtifactGateError(
                "packaged native-host identity input does not match the source closure: "
                + relative
            )

    packaged_assets = provenance.get("packaged_assets")
    if not isinstance(packaged_assets, list):
        raise LinuxArtifactGateError("native-host packaged asset provenance is missing.")
    checked_assets = [
        _valid_file_record(record, f"native-host packaged asset {index}", include_mode=True)
        for index, record in enumerate(packaged_assets)
    ]
    asset_paths = [str(record["path"]) for record in checked_assets]
    if asset_paths != sorted(NATIVE_HOST_PACKAGED_ASSETS):
        raise LinuxArtifactGateError("native-host packaged asset provenance is not exhaustive and sorted.")
    for record in checked_assets:
        name = str(record["path"])
        if (
            record["sha256"] != _sha256_bytes(payloads[name])
            or record["bytes"] != len(payloads[name])
            or record["mode"] != modes[name]
        ):
            raise LinuxArtifactGateError(f"native-host provenance does not bind packaged asset: {name}")

    private_debug = provenance.get("private_debug_info")
    if not isinstance(private_debug, dict):
        raise LinuxArtifactGateError("native-host private debug provenance is missing.")
    _require_exact_keys(private_debug, {"sha256", "bytes", "mode"}, "native-host private debug")
    if (
        not isinstance(private_debug.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(private_debug.get("sha256"))) is None
        or not isinstance(private_debug.get("bytes"), int)
        or isinstance(private_debug.get("bytes"), bool)
        or int(private_debug.get("bytes", 0)) <= 0
        or private_debug.get("mode") != 0o600
    ):
        raise LinuxArtifactGateError("native-host private debug provenance is invalid.")

    toolchain = provenance.get("toolchain")
    if not isinstance(toolchain, dict):
        raise LinuxArtifactGateError("native-host toolchain provenance is missing.")
    _require_exact_keys(
        toolchain,
        {"dart_version", "flutter_version", "flutter_revision", "compile_arguments"},
        "native-host toolchain provenance",
    )
    expected_arguments = [
        "compile",
        "exe",
        "--target-os=linux",
        f"--target-arch={expected_arch}",
        "--save-debugging-info=<private-custody>/wins_bridge_host.debug",
        "bin/wins_bridge_host.dart",
    ]
    if (
        toolchain.get("dart_version") != REQUIRED_DART_VERSION
        or toolchain.get("flutter_version") != REQUIRED_FLUTTER_VERSION
        or toolchain.get("flutter_revision") != REQUIRED_FLUTTER_REVISION
        or toolchain.get("compile_arguments") != expected_arguments
    ):
        raise LinuxArtifactGateError("native-host toolchain provenance does not match reviewed pins.")


def _secure_regular_repo_path(raw_path: str, label: str) -> pathlib.Path:
    relative = pathlib.PurePosixPath(raw_path)
    if (
        not raw_path
        or "\\" in raw_path
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise LinuxArtifactGateError(f"{label} must be one canonical repository-relative path.")
    root = ROOT.resolve(strict=True)
    fd = _openat_from_root(root, relative.parts, last_directory=False, label=label)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
        ):
            raise LinuxArtifactGateError(
                f"{label} must be one non-empty, non-linked regular file."
            )
        path = root.joinpath(*relative.parts)
        path.relative_to(root)
        return path
    finally:
        os.close(fd)


def _artifact_snapshot_parent() -> pathlib.Path:
    root = ROOT.resolve(strict=True)
    artifacts = root / ".artifacts"
    if artifacts.is_dir() and not artifacts.is_symlink():
        return artifacts
    try:
        return pathlib.Path(tempfile.gettempdir()).resolve(strict=True)
    except OSError as exc:
        raise LinuxArtifactGateError(
            "private artifact snapshot parent is unavailable."
        ) from exc


def _artifact_snapshot_lease_payload(name: str) -> bytes:
    if re.fullmatch(ARTIFACT_SNAPSHOT_PREFIX + r"[0-9a-f]{32}", name) is None:
        raise LinuxArtifactGateError("private artifact snapshot name is invalid.")
    return (
        f"contract={ARTIFACT_SNAPSHOT_CONTRACT}\n"
        f"name={name}\n"
        f"uid={os.geteuid()}\n"
    ).encode("ascii")


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise LinuxArtifactGateError("descriptor write made no progress.")
        offset += written


def _remove_artifact_snapshot_tree(
    directory_fd: int,
    *,
    depth: int,
    counters: list[int],
    preserve: frozenset[str] = frozenset(),
) -> None:
    if depth > ARTIFACT_SNAPSHOT_MAX_DEPTH:
        raise LinuxArtifactGateError(
            "private artifact snapshot orphan exceeds the depth ceiling."
        )
    for name in sorted(os.listdir(directory_fd)):
        if depth == 0 and name in preserve:
            continue
        if name in {"", ".", ".."} or "/" in name or "\\" in name or "\x00" in name:
            raise LinuxArtifactGateError(
                "private artifact snapshot orphan has an unsafe entry."
            )
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        counters[0] += 1
        counters[1] += max(0, int(info.st_size))
        if (
            counters[0] > ARTIFACT_SNAPSHOT_MAX_ENTRIES
            or counters[1] > ARTIFACT_SNAPSHOT_MAX_BYTES
            or info.st_uid != os.geteuid()
        ):
            raise LinuxArtifactGateError(
                "private artifact snapshot orphan exceeds its authenticated bounds."
            )
        if stat.S_ISDIR(info.st_mode):
            child_fd = _openat_child(
                directory_fd,
                name,
                _dir_open_flags(),
                label="private artifact snapshot orphan directory",
            )
            identity = _directory_identity(os.fstat(child_fd))
            try:
                _remove_artifact_snapshot_tree(
                    child_fd, depth=depth + 1, counters=counters
                )
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if _directory_identity(named) != identity:
                    raise LinuxArtifactGateError(
                        "private artifact snapshot orphan directory was replaced."
                    )
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
            continue
        os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def _remove_retained_artifact_snapshot_root(
    chain: _RetainedDirectoryChain, lease_fd: int
) -> None:
    """Delete one private snapshot only through retained FDs while lease-locked."""
    if lease_fd < 0:
        raise LinuxArtifactGateError(
            "private artifact snapshot cleanup lease is closed."
        )
    chain.revalidate()
    lease_info = os.fstat(lease_fd)
    if (
        not stat.S_ISREG(lease_info.st_mode)
        or lease_info.st_uid != os.geteuid()
        or lease_info.st_nlink != 1
        or stat.S_IMODE(lease_info.st_mode) != 0o400
    ):
        raise LinuxArtifactGateError(
            "private artifact snapshot cleanup lease identity is invalid."
        )
    try:
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise LinuxArtifactGateError(
            "private artifact snapshot cleanup lease is not exclusively retained."
        ) from exc
    retained_identity = _directory_identity(os.fstat(chain.leaf_fd))
    if retained_identity != chain.leaf_identity:
        raise LinuxArtifactGateError(
            "private artifact snapshot cleanup directory identity changed."
        )
    _remove_artifact_snapshot_tree(
        chain.leaf_fd,
        depth=0,
        counters=[0, 0],
        preserve=frozenset({ARTIFACT_SNAPSHOT_LEASE}),
    )
    named_lease = os.stat(
        ARTIFACT_SNAPSHOT_LEASE,
        dir_fd=chain.leaf_fd,
        follow_symlinks=False,
    )
    if _file_identity(named_lease) != _file_identity(lease_info):
        raise LinuxArtifactGateError(
            "private artifact snapshot cleanup lease was replaced."
        )
    os.unlink(ARTIFACT_SNAPSHOT_LEASE, dir_fd=chain.leaf_fd)
    os.fsync(chain.leaf_fd)
    named = os.stat(
        chain.leaf_name, dir_fd=chain.parent_fd, follow_symlinks=False
    )
    if _directory_identity(named) != retained_identity:
        raise LinuxArtifactGateError(
            "private artifact snapshot cleanup directory was replaced."
        )
    os.rmdir(chain.leaf_name, dir_fd=chain.parent_fd)
    os.fsync(chain.parent_fd)


def _recover_artifact_snapshot_orphans(parent_fd: int) -> None:
    candidates = [
        name
        for name in sorted(os.listdir(parent_fd))
        if re.fullmatch(ARTIFACT_SNAPSHOT_PREFIX + r"[0-9a-f]{32}", name)
    ]
    if len(candidates) > ARTIFACT_SNAPSHOT_MAX_ORPHANS:
        raise LinuxArtifactGateError(
            "private artifact snapshot orphan count exceeds the reviewed ceiling."
        )
    now_ns = time.time_ns()
    for name in candidates:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o700
        ):
            raise LinuxArtifactGateError(
                "private artifact snapshot orphan identity is invalid."
            )
        if now_ns - before.st_mtime_ns < ARTIFACT_SNAPSHOT_STALE_SECONDS * 1_000_000_000:
            continue
        child_fd = _openat_child(
            parent_fd,
            name,
            _dir_open_flags(),
            label="private artifact snapshot orphan",
        )
        lease_fd = -1
        try:
            entries = sorted(os.listdir(child_fd))
            if not entries:
                identity = _directory_identity(os.fstat(child_fd))
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _directory_identity(named) != identity:
                    raise LinuxArtifactGateError(
                        "empty artifact snapshot orphan was replaced."
                    )
                os.rmdir(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
                continue
            if ARTIFACT_SNAPSHOT_LEASE not in entries or any(
                entry not in {ARTIFACT_SNAPSHOT_LEASE, "artifact.bin", "extracted"}
                for entry in entries
            ):
                raise LinuxArtifactGateError(
                    "private artifact snapshot orphan schema is invalid."
                )
            if "extracted" in entries and sys.platform == "linux":
                _recover_linux_process_orphans()
            lease_fd = _openat_child(
                child_fd,
                ARTIFACT_SNAPSHOT_LEASE,
                _open_flags(),
                label="private artifact snapshot orphan lease",
            )
            lease_info = os.fstat(lease_fd)
            expected_lease = _artifact_snapshot_lease_payload(name)
            if (
                not stat.S_ISREG(lease_info.st_mode)
                or lease_info.st_uid != os.geteuid()
                or lease_info.st_nlink != 1
                or stat.S_IMODE(lease_info.st_mode) != 0o400
                or lease_info.st_size != len(expected_lease)
            ):
                raise LinuxArtifactGateError(
                    "private artifact snapshot orphan lease is invalid."
                )
            lease_payload = os.pread(lease_fd, len(expected_lease) + 1, 0)
            lease_after = os.fstat(lease_fd)
            if (
                lease_payload != expected_lease
                or _file_identity(lease_after) != _file_identity(lease_info)
            ):
                raise LinuxArtifactGateError(
                    "private artifact snapshot orphan lease is invalid."
                )
            try:
                fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue
            retained_identity = _directory_identity(os.fstat(child_fd))
            _remove_artifact_snapshot_tree(child_fd, depth=0, counters=[0, 0])
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if _directory_identity(named) != retained_identity:
                raise LinuxArtifactGateError(
                    "private artifact snapshot orphan was replaced during cleanup."
                )
            os.rmdir(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if lease_fd >= 0:
                os.close(lease_fd)
            os.close(child_fd)


def _create_artifact_snapshot_root() -> tuple[pathlib.Path, int]:
    parent = _artifact_snapshot_parent()
    parent_fd = os.open(parent, _dir_open_flags())
    child_fd = -1
    lease_fd = -1
    name = ARTIFACT_SNAPSHOT_PREFIX + secrets.token_hex(16)
    try:
        _recover_artifact_snapshot_orphans(parent_fd)
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        child_fd = _openat_child(
            parent_fd,
            name,
            _dir_open_flags(),
            label="private artifact snapshot directory",
        )
        child_info = os.fstat(child_fd)
        if (
            child_info.st_uid != os.geteuid()
            or stat.S_IMODE(child_info.st_mode) != 0o700
        ):
            raise LinuxArtifactGateError(
                "private artifact snapshot directory identity is invalid."
            )
        lease_payload = _artifact_snapshot_lease_payload(name)
        writer = os.open(
            ARTIFACT_SNAPSHOT_LEASE,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=child_fd,
        )
        try:
            _write_all(writer, lease_payload)
            os.fsync(writer)
            os.fchmod(writer, 0o400)
        finally:
            os.close(writer)
        os.fsync(child_fd)
        lease_fd = _openat_child(
            child_fd,
            ARTIFACT_SNAPSHOT_LEASE,
            _open_flags(),
            label="private artifact snapshot lease",
        )
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return parent / name, lease_fd
    except BaseException:
        if lease_fd >= 0:
            os.close(lease_fd)
        raise
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        os.close(parent_fd)


def _snapshot_artifact(
    origin: pathlib.Path,
    label: str,
    *,
    allow_absolute_external: bool = False,
) -> AuthenticatedSnapshot:
    root = ROOT.resolve(strict=True)
    if allow_absolute_external:
        if not origin.is_absolute() or any(
            part in {"", ".", ".."} for part in origin.parts[1:]
        ):
            raise LinuxArtifactGateError(
                f"{label} must be one canonical absolute path."
            )
        try:
            origin = origin.parent.resolve(strict=True) / origin.name
        except OSError as exc:
            raise LinuxArtifactGateError(f"{label} path is unavailable.") from exc
    private, lease_fd = _create_artifact_snapshot_root()
    snapshot_path = private / "artifact.bin"
    dest_fd = -1
    origin_fd = -1
    private_fd = -1
    origin_chain: _RetainedDirectoryChain | None = None
    snapshot_chain: _RetainedDirectoryChain | None = None
    try:
        origin_chain = _retain_complete_directory_chain(origin.parent, label)
        origin_fd = (
            _openat_child(
                origin_chain.leaf_fd,
                origin.name,
                _open_flags(),
                label=label,
            )
            if allow_absolute_external
            else _bind_repo_file(origin, label)
        )
        private_fd = os.open(private, _dir_open_flags())
        snapshot_chain = _retain_complete_directory_chain(private, label)
        before = os.fstat(origin_fd)
        try:
            path_before = origin.lstat()
        except OSError as exc:
            raise LinuxArtifactGateError(f"{label} is not a bound regular file.") from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_ARCHIVE_BYTES
            or _file_identity(before) != _file_identity(path_before)
        ):
            raise LinuxArtifactGateError(
                f"{label} must be one non-empty, single-link regular file within the size ceiling."
            )
        copied = _copy_exclusive(
            origin_fd,
            snapshot_path,
            before.st_size,
            dir_fd=private_fd,
            name="artifact.bin",
        )
        dest_fd = _openat_child(private_fd, "artifact.bin", _open_flags(), label=label)
        dest_info = os.fstat(dest_fd)
        if copied != _sha256_fd(dest_fd) or dest_info.st_nlink != 1:
            raise LinuxArtifactGateError(
                f"{label} snapshot digest or link identity is invalid."
            )
        after = os.fstat(origin_fd)
        try:
            path_after = origin.lstat()
        except OSError as exc:
            raise LinuxArtifactGateError(
                f"{label} mutated during authenticated snapshot."
            ) from exc
        if _file_identity(before) != _file_identity(after) or _file_identity(
            before
        ) != _file_identity(path_after):
            raise LinuxArtifactGateError(f"{label} mutated during authenticated snapshot.")
        snapshot = AuthenticatedSnapshot(
            origin=origin,
            path=snapshot_path,
            fd=dest_fd,
            origin_identity=_file_identity(before),
            identity=_file_identity(dest_info),
            digest=copied,
            size=before.st_size,
            root=private,
            origin_fd=origin_fd,
            origin_ancestor_chain=origin_chain,
            snapshot_ancestor_chain=snapshot_chain,
            lease_fd=lease_fd,
        )
        dest_fd = -1
        origin_fd = -1
        origin_chain = None
        snapshot_chain = None
        lease_fd = -1
        try:
            snapshot.rehash()
        except BaseException:
            snapshot.close()
            raise
        return snapshot
    except LinuxArtifactGateError as original:
        cleanup_error: BaseException | None = None
        if snapshot_chain is not None and lease_fd >= 0:
            try:
                _remove_retained_artifact_snapshot_root(snapshot_chain, lease_fd)
            except BaseException as exc:
                cleanup_error = exc
        if lease_fd >= 0:
            os.close(lease_fd)
            lease_fd = -1
        if dest_fd >= 0:
            os.close(dest_fd)
            dest_fd = -1
        if cleanup_error is not None:
            if hasattr(original, "add_note"):
                original.add_note(
                    "private snapshot descriptor cleanup also failed: "
                    + str(cleanup_error)
                )
        raise
    except OSError as exc:
        cleanup_error = None
        if snapshot_chain is not None and lease_fd >= 0:
            try:
                _remove_retained_artifact_snapshot_root(snapshot_chain, lease_fd)
            except BaseException as cleanup_exc:
                cleanup_error = cleanup_exc
        if lease_fd >= 0:
            os.close(lease_fd)
            lease_fd = -1
        if dest_fd >= 0:
            os.close(dest_fd)
            dest_fd = -1
        wrapped = LinuxArtifactGateError(f"{label} is not a bound regular file.")
        if cleanup_error is not None and hasattr(wrapped, "add_note"):
            wrapped.add_note(
                "private snapshot descriptor cleanup also failed: "
                + str(cleanup_error)
            )
        raise wrapped from exc
    finally:
        if origin_fd >= 0:
            os.close(origin_fd)
        if private_fd >= 0:
            os.close(private_fd)
        if origin_chain is not None:
            origin_chain.close()
        if snapshot_chain is not None:
            snapshot_chain.close()


def _snapshot_held_artifact(
    *,
    source_fd: int,
    source_parent_fd: int,
    source_name: str,
    source_relative_path: str,
    expected_identity: tuple[int, ...],
    expected_size: int,
    expected_sha256: str,
) -> HeldArtifactSnapshot:
    label = "Held Linux release artifact"
    if (
        type(source_fd) is not int
        or source_fd < 0
        or type(source_parent_fd) is not int
        or source_parent_fd < 0
        or type(source_name) is not str
        or source_name in {"", ".", ".."}
        or "/" in source_name
        or "\\" in source_name
        or "\x00" in source_name
        or type(expected_identity) is not tuple
        or len(expected_identity) != 8
        or any(type(value) is not int for value in expected_identity)
        or type(expected_size) is not int
        or isinstance(expected_size, bool)
        or expected_size <= 0
        or expected_size > MAX_ARCHIVE_BYTES
        or type(expected_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise LinuxArtifactGateError("held Linux artifact binding is invalid.")
    if type(source_relative_path) is not str or not source_relative_path:
        raise LinuxArtifactGateError(
            "held Linux artifact path must be canonical and match its retained name."
        )
    _require_readonly_fd(source_fd, "held Linux artifact source")
    _require_readonly_fd(source_parent_fd, "held Linux artifact parent")
    relative = pathlib.PurePosixPath(source_relative_path)
    if (
        not source_relative_path
        or relative.is_absolute()
        or "\\" in source_relative_path
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.name != source_name
    ):
        raise LinuxArtifactGateError(
            "held Linux artifact path must be canonical and match its retained name."
        )

    root = ROOT.resolve(strict=True)
    origin = root.joinpath(*relative.parts)
    canonical_fd = -1
    canonical_parent_fd = -1
    held_source_fd = -1
    held_parent_fd = -1
    private_fd = -1
    snapshot_fd = -1
    ancestor_chain: _RetainedDirectoryChain | None = None
    private: pathlib.Path | None = None
    keep_private = False
    try:
        canonical_fd = _bind_repo_file(origin, label)
        canonical_parent_fd = _openat_from_root(
            root,
            relative.parts[:-1],
            last_directory=True,
            label="Held Linux release artifact parent",
        )
        ancestor_chain = _retain_complete_directory_chain(
            origin.parent,
            "Held Linux release artifact",
        )
        source_info = os.fstat(source_fd)
        source_named = os.stat(
            source_name, dir_fd=source_parent_fd, follow_symlinks=False
        )
        _require_unique_casefold_name(source_parent_fd, source_name, label)
        canonical_info = os.fstat(canonical_fd)
        parent_info = os.fstat(source_parent_fd)
        canonical_parent_info = os.fstat(canonical_parent_fd)
        if (
            not stat.S_ISREG(source_info.st_mode)
            or source_info.st_nlink != 1
            or stat.S_IMODE(source_info.st_mode) not in {0o400, 0o600, 0o644}
            or _file_identity(source_info) != expected_identity
            or _file_identity(source_named) != expected_identity
            or _file_identity(canonical_info) != expected_identity
            or _file_identity(parent_info) != _file_identity(canonical_parent_info)
            or _file_identity(parent_info)
            != _file_identity(os.fstat(ancestor_chain.leaf_fd))
            or source_info.st_size != expected_size
        ):
            raise LinuxArtifactGateError(
                "held Linux artifact descriptor, name, path, mode, size, or parent is not exact."
            )
        if _sha256_fd(source_fd) != expected_sha256:
            raise LinuxArtifactGateError(
                "held Linux artifact SHA-256 does not match the frozen candidate."
            )

        held_source_fd = os.dup(source_fd)
        held_parent_fd = os.dup(source_parent_fd)
        os.set_inheritable(held_source_fd, False)
        os.set_inheritable(held_parent_fd, False)
        artifacts = root / ".artifacts"
        if artifacts.is_dir() and not artifacts.is_symlink():
            private = pathlib.Path(
                tempfile.mkdtemp(prefix="winsvpn-linux-held-", dir=str(artifacts))
            )
        else:
            private = pathlib.Path(tempfile.mkdtemp(prefix="winsvpn-linux-held-"))
        os.chmod(private, 0o700)
        private_fd = os.open(private, _dir_open_flags())
        copied = _copy_exclusive_pread(
            held_source_fd,
            dir_fd=private_fd,
            name="artifact.bin",
            size=expected_size,
        )
        snapshot_path = private / "artifact.bin"
        snapshot_fd = _openat_child(
            private_fd, "artifact.bin", _open_flags(), label=label
        )
        snapshot_info = os.fstat(snapshot_fd)
        if (
            copied != expected_sha256
            or _sha256_fd(snapshot_fd) != expected_sha256
            or not stat.S_ISREG(snapshot_info.st_mode)
            or snapshot_info.st_nlink != 1
            or snapshot_info.st_size != expected_size
            or stat.S_IMODE(snapshot_info.st_mode) != 0o400
        ):
            raise LinuxArtifactGateError(
                "held Linux artifact private snapshot is not exact."
            )
        result = HeldArtifactSnapshot(
            origin=origin,
            path=snapshot_path,
            fd=snapshot_fd,
            source_fd=held_source_fd,
            source_parent_fd=held_parent_fd,
            source_name=source_name,
            source_identity=expected_identity,
            parent_identity=_file_identity(parent_info),
            ancestor_chain=ancestor_chain,
            identity=_file_identity(snapshot_info),
            digest=expected_sha256,
            size=expected_size,
            root=private,
        )
        snapshot_fd = -1
        held_source_fd = -1
        held_parent_fd = -1
        ancestor_chain = None
        try:
            result.rehash()
        except Exception:
            result.close()
            raise
        keep_private = True
        return result
    except LinuxArtifactGateError:
        raise
    except OSError as exc:
        raise LinuxArtifactGateError(
            "held Linux artifact could not be bound descriptor-relatively."
        ) from exc
    finally:
        for descriptor in (
            snapshot_fd,
            held_source_fd,
            held_parent_fd,
            canonical_fd,
            canonical_parent_fd,
            private_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)
        if not keep_private and private is not None:
            shutil.rmtree(private, ignore_errors=True)
        if ancestor_chain is not None:
            ancestor_chain.close()


def _canonical_linux_versions() -> tuple[str, str]:
    identity_path = _secure_regular_repo_path(
        RELEASE_IDENTITY_PATH, "Release identity ruling"
    )
    snapshot = _snapshot_artifact(identity_path, "Release identity ruling")
    try:
        snapshot.reject_origin_swap()
        payload = os.pread(snapshot.fd, snapshot.size, 0)
        if len(payload) != snapshot.size or snapshot.rehash() != snapshot.digest:
            raise LinuxArtifactGateError(
                "Release identity ruling mutated while it was read."
            )
        snapshot.reject_origin_swap()
    finally:
        snapshot.close()
    identity = _exact_json(payload, "Release identity ruling")
    _require_exact_keys(
        identity,
        {
            "schema_version",
            "canonical_release",
            "marketing_version",
            "build_number",
            "platform_mappings",
        },
        "Release identity ruling",
    )
    mappings = identity.get("platform_mappings")
    if not isinstance(mappings, dict):
        raise LinuxArtifactGateError(
            "Release identity platform mappings are invalid."
        )
    linux = mappings.get("linux")
    if not isinstance(linux, dict):
        raise LinuxArtifactGateError("Linux release identity mapping is missing.")
    _require_exact_keys(
        linux,
        {"appstream_version", "debian_version"},
        "Linux release identity mapping",
    )
    marketing = identity.get("marketing_version")
    build = identity.get("build_number")
    appstream = linux.get("appstream_version")
    debian = linux.get("debian_version")
    if (
        identity.get("schema_version") != 2
        or not isinstance(marketing, str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", marketing) is None
        or not isinstance(build, int)
        or isinstance(build, bool)
        or build < 1
        or identity.get("canonical_release") != CANONICAL_RELEASE
        or identity.get("canonical_release") != f"{marketing}+{build}"
        or appstream != marketing
        or debian != f"{marketing}-{build}"
    ):
        raise LinuxArtifactGateError(
            "Linux AppStream/Debian release identity mapping is inconsistent."
        )
    return marketing, str(debian)


def _normalized_member_name(name: str) -> str:
    normalized = name.removeprefix("./")
    path = pathlib.PurePosixPath(normalized)
    if (
        not normalized
        or normalized == "."
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise LinuxArtifactGateError(f"unsafe or ambiguous tar member path: {name!r}")
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LinuxArtifactGateError(
            f"tar member paths must use canonical ASCII: {name!r}"
        ) from exc
    return path.as_posix()


def _looks_like_nested_archive(payload: bytes) -> bool:
    if payload.startswith(
        (
            b"PK\x03\x04",
            b"PK\x05\x06",
            b"PK\x07\x08",
            b"\x1f\x8b",
            b"BZh",
            b"\xfd7zXZ",
            b"(\xb5/\xfd",
        )
    ):
        return True
    return len(payload) >= 262 and payload[257:262] == b"ustar"


def _is_gzip_tar_surrogate(header: bytes) -> bool:
    if header.startswith(b"\x1f\x8b"):
        return True
    if header.startswith(b"BZh") or header.startswith(b"\xfd7zXZ"):
        return True
    return len(header) >= 262 and header[257:262] == b"ustar"


def _parse_elf64_le(payload: bytes, label: str) -> dict[str, object]:
    if not payload.startswith(ELF_MAGIC):
        raise LinuxArtifactGateError(f"{label} is not an ELF image.")
    if len(payload) <= 64:
        raise LinuxArtifactGateError(f"{label} is a truncated 64-byte ELF header, not an executable.")
    ident = payload[:16]
    if ident[4] != 2 or ident[5] != 1 or ident[6] != 1 or ident[7] not in {0, 3}:
        raise LinuxArtifactGateError(f"{label} is not little-endian ELF64 System V/Linux.")
    if len(payload) < ELF64_HEADER_STRUCT.size:
        raise LinuxArtifactGateError(f"{label} ELF header is truncated.")
    (
        _ident,
        elf_type,
        machine,
        version,
        entry,
        phoff,
        shoff,
        _flags,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    ) = ELF64_HEADER_STRUCT.unpack_from(payload, 0)
    if (
        version != 1
        or ehsize != 64
        or elf_type not in {ET_EXEC, ET_DYN}
        or phentsize != 56
        or phnum < 1
        or phnum > MAX_PHNUM
        or phoff < 64
        or phoff + (phnum * 56) > len(payload)
        or shentsize != 64
        or shnum < 1
        or shnum > MAX_SHNUM
        or shoff < 64
        or shoff + (shnum * 64) > len(payload)
        or shstrndx >= shnum
    ):
        raise LinuxArtifactGateError(
            f"{label} ELF program/section tables are missing, unbounded, or invalid."
        )
    executable_load = False
    for index in range(phnum):
        kind, flags, offset, _vaddr, _paddr, filesz, memsz, _align = ELF64_PHDR_STRUCT.unpack_from(
            payload, phoff + (index * 56)
        )
        if offset + filesz > len(payload) or memsz < filesz:
            raise LinuxArtifactGateError(f"{label} has an invalid program header.")
        if kind == PT_LOAD and flags & PF_X:
            if filesz == 0:
                raise LinuxArtifactGateError(f"{label} executable load segment is empty.")
            executable_load = True
    if not executable_load:
        raise LinuxArtifactGateError(f"{label} has no executable PT_LOAD segment.")
    str_hdr = shoff + (shstrndx * 64)
    _name, _stype, _flags, _addr, str_off, str_size, _link, _info, _align, _entsize = (
        ELF64_SHDR_STRUCT.unpack_from(payload, str_hdr)
    )
    if str_off + str_size > len(payload):
        raise LinuxArtifactGateError(f"{label} ELF section string table is invalid.")
    return {
        "machine": machine,
        "elf_type": elf_type,
        "entry": entry,
        "sha256": _sha256_bytes(payload),
    }


# The pinned awg CLI ships with its ELF symbol table (.symtab, no DWARF). This
# gate runs as a pristine -I -S worker and cannot import the privacy scanner, so
# it carries its own copy of the two reviewed digests; a test binds this set to
# APPROVED_VENDOR_DEBUG_METADATA_SHA256["awg"] in
# tools/validate_release_artifact_privacy.py and to the producer's pins.
APPROVED_AWG_SYMBOL_TABLE_SHA256 = frozenset(
    {
        "23d29323258166183eeeb288c1f9f08b879f3707e54591b1bfb2402413f6d8d8",  # linux x64 (upstream)
        "bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d",  # linux arm64 (from source)
    }
)


def _require_executable_elf(
    payload: bytes, label: str, expected_machine: int, *, require_entry: bool
) -> dict[str, object]:
    parsed = _parse_elf64_le(payload, label)
    if parsed["machine"] != expected_machine:
        raise LinuxArtifactGateError(
            f"{label} targets ELF machine {parsed['machine']}; expected {expected_machine}."
        )
    if require_entry and parsed["entry"] == 0:
        raise LinuxArtifactGateError(f"{label} executable entry point is zero.")
    try:
        inspected = inspect_native_debug_sections(payload)
    except ObfuscationError as exc:
        raise LinuxArtifactGateError(f"{label} ELF is malformed: {exc}") from exc
    if inspected is None or inspected[0] != "elf":
        raise LinuxArtifactGateError(f"{label} is not a parseable ELF.")
    approved_awg_symbols = (
        pathlib.PurePosixPath(label).name == "awg"
        and tuple(inspected[1]) == (".symtab",)
        and parsed["sha256"] in APPROVED_AWG_SYMBOL_TABLE_SHA256
    )
    if inspected[1] and not approved_awg_symbols:
        raise LinuxArtifactGateError(
            f"{label} retains private debug sections: " + ", ".join(inspected[1])
        )
    return parsed


def _payload_identity(
    name: str, payload: bytes, kind: str, expected_machine: int
) -> dict[str, object]:
    if kind == "elf":
        parsed = _require_executable_elf(
            payload,
            name,
            expected_machine,
            require_entry=name in REQUIRED_PROGRAM_ELFS or name.endswith("winsvpn-bypass-bpf"),
        )
        return {
            "path": name,
            "type": "elf64-le",
            "sha256": parsed["sha256"],
            "elf_machine": parsed["machine"],
            "elf_type": parsed["elf_type"],
        }
    if payload.startswith(ELF_MAGIC):
        raise LinuxArtifactGateError(f"{name} must be Flutter/runtime data, not an ELF.")
    if not payload:
        raise LinuxArtifactGateError(f"{name} Flutter/runtime payload is empty.")
    return {
        "path": name,
        "type": "data",
        "sha256": _sha256_bytes(payload),
        "bytes": len(payload),
    }


def _reject_extra_elf_payloads(
    payloads: dict[str, bytes], allowed: set[str], label: str
) -> None:
    extra = sorted(
        name
        for name, payload in payloads.items()
        if payload.startswith(ELF_MAGIC) and name not in allowed
    )
    if extra:
        raise LinuxArtifactGateError(
            f"{label} contains extra ELF payloads: " + ", ".join(extra)
        )


def _scan_elf_payloads(
    payloads: dict[str, bytes], expected_machine: int
) -> None:
    for name, payload in payloads.items():
        if not payload.startswith(ELF_MAGIC):
            continue
        parsed = _parse_elf64_le(payload, name)
        if parsed["machine"] != expected_machine:
            raise LinuxArtifactGateError(
                f"{name} targets ELF machine {parsed['machine']}; expected {expected_machine}."
            )


def _require_flutter_payload(
    payloads: dict[str, bytes], expected_machine: int
) -> dict[str, dict[str, object]]:
    identities: dict[str, dict[str, object]] = {}
    for name, kind in FLUTTER_PAYLOAD_FILES.items():
        if name not in payloads:
            raise LinuxArtifactGateError(
                "Linux package is missing Flutter/runtime payload: " + name
            )
        identities[name] = _payload_identity(name, payloads[name], kind, expected_machine)
    libapp = identities["lib/libapp.so"]
    libflutter = identities["lib/libflutter_linux_gtk.so"]
    bypass = identities["winsvpn-bypass-bpf"]
    if len({libapp["sha256"], libflutter["sha256"], bypass["sha256"]}) != 3:
        raise LinuxArtifactGateError(
            "Flutter/runtime payload identities must be distinct by digest."
        )
    return identities


class _ByteSource:
    def __init__(self, fd: int, start: int, end: int) -> None:
        self.fd = fd
        self.offset = start
        self.end = end

    def read(self, count: int) -> bytes:
        remaining = self.end - self.offset
        if count <= 0 or remaining <= 0:
            return b""
        block = os.pread(self.fd, min(count, remaining), self.offset)
        self.offset += len(block)
        return block


class _ArchiveBudget:
    """One fail-closed expansion budget shared by the outer tar and all children."""

    def __init__(self) -> None:
        self.entries = 0
        self.expanded_bytes = 0

    def reserve(
        self,
        expanded: int,
        *,
        compressed: int | None = None,
        label: str,
    ) -> None:
        if type(expanded) is not int or expanded < 0:
            raise LinuxArtifactGateError(f"{label} reports an invalid expanded size.")
        if expanded > MAX_MEMBER_BYTES:
            raise LinuxArtifactGateError(f"{label} exceeds the member size ceiling.")
        if compressed is not None:
            if type(compressed) is not int or compressed < 0:
                raise LinuxArtifactGateError(
                    f"{label} reports an invalid compressed size."
                )
            if expanded and compressed == 0:
                raise LinuxArtifactGateError(
                    f"{label} has expanded bytes without compressed custody."
                )
            if compressed and expanded > compressed * MAX_COMPRESSION_RATIO:
                raise LinuxArtifactGateError(
                    f"{label} compression ratio exceeds the reviewed limit."
                )
        if self.entries >= MAX_ARCHIVE_MEMBERS:
            raise LinuxArtifactGateError(
                "Linux package has too many recursively expanded archive members."
            )
        if self.expanded_bytes + expanded > MAX_UNCOMPRESSED_BYTES:
            raise LinuxArtifactGateError(
                "Linux package exceeds the aggregate recursively expanded size ceiling."
            )
        self.entries += 1
        self.expanded_bytes += expanded


class _InflatingReader:
    def __init__(self, raw: _ByteSource) -> None:
        self._raw = raw
        self._inflater = zlib.decompressobj(-15)
        self._buffer = bytearray()
        self.uncompressed = 0
        self.crc32 = 0
        self._eof = False

    def _fill(self, needed: int) -> None:
        while len(self._buffer) < needed and not self._eof:
            compressed = self._raw.read(65536)
            if compressed:
                produced = self._inflater.decompress(compressed)
            else:
                produced = self._inflater.flush()
                self._eof = True
            if produced:
                self.uncompressed += len(produced)
                self.crc32 = zlib.crc32(produced, self.crc32)
                if self.uncompressed > MAX_UNCOMPRESSED_BYTES:
                    raise LinuxArtifactGateError("Linux package exceeds the uncompressed size ceiling.")
                compressed_used = max(self._raw.offset - 10, 1)
                if self.uncompressed / compressed_used > MAX_COMPRESSION_RATIO:
                    raise LinuxArtifactGateError("Linux package compression ratio exceeds the reviewed limit.")
                self._buffer.extend(produced)
            elif not compressed:
                break

    def read(self, count: int) -> bytes:
        self._fill(count)
        block = bytes(self._buffer[:count])
        del self._buffer[:count]
        return block

    def require_exact_stream_end(self) -> None:
        while True:
            block = self.read(65536)
            if not block:
                break
        if (
            not self._inflater.eof
            or self._inflater.unused_data
            or self._inflater.unconsumed_tail
            or self._raw.offset != self._raw.end
        ):
            raise LinuxArtifactGateError(
                "Linux package contains a truncated or concatenated gzip stream."
            )


def _read_gzip_tar_snapshot(snapshot: AuthenticatedSnapshot) -> tuple[
    list[tarfile.TarInfo], dict[str, bytes], dict[str, int], _ArchiveBudget
]:
    snapshot.ensure_bound()
    if snapshot.size > MAX_ARCHIVE_BYTES:
        raise LinuxArtifactGateError("Linux package archive exceeds the reviewed size ceiling.")
    header = snapshot.header(10)
    if (
        snapshot.size < 18
        or len(header) != 10
        or header[:4] != b"\x1f\x8b\x08\x00"
        or header[4:8] != b"\x00" * 4
    ):
        raise LinuxArtifactGateError("Linux package is not a deterministic gzip -n archive.")
    source = _ByteSource(snapshot.fd, 10, snapshot.size - 8)
    inflater = _InflatingReader(source)
    members: list[tarfile.TarInfo] = []
    payloads: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    seen: set[str] = set()
    aggregate = 0
    budget = _ArchiveBudget()
    zero_block = b"\x00" * 512
    while True:
        hdr = inflater.read(512)
        if len(hdr) != 512:
            raise LinuxArtifactGateError(
                "Linux package tar end marker is missing or truncated."
            )
        if hdr == zero_block:
            second = inflater.read(512)
            if len(second) != 512 or second != zero_block:
                raise LinuxArtifactGateError(
                    "Linux package tar requires exactly two zero end blocks."
                )
            trailing = 0
            while True:
                leftover = inflater.read(65536)
                if not leftover:
                    break
                trailing += len(leftover)
                if any(leftover):
                    raise LinuxArtifactGateError(
                        "Linux package tar has nonzero unmanifested trailing payload."
                    )
            if trailing % 512 != 0:
                raise LinuxArtifactGateError(
                    "Linux package tar has malformed noncanonical zero padding."
                )
            break
        try:
            member = tarfile.TarInfo.frombuf(hdr, encoding="ascii", errors="strict")
        except tarfile.TarError as exc:
            raise LinuxArtifactGateError(f"Linux package archive is unsafe: {exc}") from exc
        members.append(member)
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise LinuxArtifactGateError("Linux package has too many archive members.")
        if member.size < 0 or member.size > MAX_MEMBER_BYTES:
            raise LinuxArtifactGateError("Linux package has an oversized archive member.")
        budget.reserve(member.size, label=f"archive member {member.name}")
        aggregate += member.size
        if aggregate > MAX_UNCOMPRESSED_BYTES:
            raise LinuxArtifactGateError("Linux package exceeds the uncompressed size ceiling.")
        padded = (member.size + 511) // 512 * 512
        if member.name in {".", "./"}:
            if padded and len(inflater.read(padded)) < member.size:
                raise LinuxArtifactGateError(f"cannot skip archive member: {member.name}")
            continue
        name = _normalized_member_name(member.name)
        folded = name.casefold()
        if folded in seen:
            raise LinuxArtifactGateError(
                f"archive has duplicate or case-colliding member: {name}"
            )
        seen.add(folded)
        if member.isdir():
            if padded and len(inflater.read(padded)) < member.size:
                raise LinuxArtifactGateError(f"cannot skip archive member: {name}")
            continue
        if not member.isfile():
            raise LinuxArtifactGateError(f"unsafe archive member type: {name}")
        data = inflater.read(padded) if padded else b""
        if len(data) < member.size:
            raise LinuxArtifactGateError(f"cannot read archive member: {name}")
        payload = data[: member.size]
        payloads[name] = payload
        modes[name] = member.mode & 0o7777
    inflater.require_exact_stream_end()
    if inflater.uncompressed <= 0:
        raise LinuxArtifactGateError("Linux package archive is empty.")
    trailer = os.pread(snapshot.fd, 8, snapshot.size - 8)
    if len(trailer) != 8:
        raise LinuxArtifactGateError("Linux package gzip trailer is truncated.")
    crc32_expected = int.from_bytes(trailer[:4], "little")
    isize = int.from_bytes(trailer[4:], "little")
    if crc32_expected != (inflater.crc32 & 0xFFFFFFFF):
        raise LinuxArtifactGateError(
            "Linux package gzip CRC does not match uncompressed bytes."
        )
    if isize != (inflater.uncompressed & 0xFFFFFFFF):
        raise LinuxArtifactGateError(
            "Linux package gzip ISIZE does not match uncompressed bytes."
        )
    return members, payloads, modes, budget


def _parse_release_manifest(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise LinuxArtifactGateError("release-manifest.sha256 is not UTF-8.") from exc
    records: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00\r\n]+)", line)
        if not match:
            raise LinuxArtifactGateError("release-manifest.sha256 has malformed records.")
        name = _normalized_member_name(match.group(2))
        folded = name.casefold()
        if any(existing.casefold() == folded for existing in records):
            raise LinuxArtifactGateError("release-manifest.sha256 has duplicate paths.")
        records[name] = match.group(1)
    if not records:
        raise LinuxArtifactGateError("release-manifest.sha256 is empty.")
    return records


def _canonical_winn3_descriptor_ring_attestation(identity: str) -> bytes:
    if re.fullmatch(r"[0-9a-f]{64}", identity) is None:
        raise LinuxArtifactGateError("Winn3 descriptor ring identity is invalid.")
    return (
        json.dumps(
            {
                "identity_sha256": identity,
                "schema_version": WINN3_DESCRIPTOR_RING_ATTESTATION_SCHEMA_VERSION,
                "verified_artifact": WINN3_DESCRIPTOR_RING_VERIFIED_ARTIFACT,
            },
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _winn3_descriptor_ring_attestation_members(
    payloads: Mapping[str, bytes],
) -> list[str]:
    expected = WINN3_DESCRIPTOR_RING_ATTESTATION_NAME.casefold()
    return sorted(
        name
        for name in payloads
        if pathlib.PurePosixPath(name).name.casefold() == expected
    )


def _verify_winn3_descriptor_ring_attestation(
    payloads: dict[str, bytes],
    modes: dict[str, int],
    *,
    attestation_name: str,
    verified_artifact_name: str,
    expected_machine: int,
    label: str,
) -> None:
    members = _winn3_descriptor_ring_attestation_members(payloads)
    if attestation_name not in payloads:
        raise LinuxArtifactGateError(
            f"{label} is incomplete: {WINN3_DESCRIPTOR_RING_ATTESTATION_NAME}"
        )
    extra = [name for name in members if name != attestation_name]
    if extra:
        raise LinuxArtifactGateError(
            f"{label} contains extra Winn3 descriptor ring attestation: "
            + ", ".join(extra)
        )
    payload = payloads[attestation_name]
    if not payload:
        raise LinuxArtifactGateError(
            f"{attestation_name} must be one non-empty Winn3 descriptor ring attestation."
        )
    if payload.startswith(ELF_MAGIC):
        raise LinuxArtifactGateError(
            f"{attestation_name} must be Winn3 descriptor ring attestation JSON, not an ELF."
        )
    mode = modes.get(attestation_name)
    if mode != WINN3_DESCRIPTOR_RING_ATTESTATION_MODE:
        raise LinuxArtifactGateError(
            f"{attestation_name} has unsafe mode; expected "
            f"{WINN3_DESCRIPTOR_RING_ATTESTATION_MODE:04o}."
        )
    document = _exact_json(payload, "Winn3 descriptor ring attestation")
    _require_exact_keys(
        document,
        set(WINN3_DESCRIPTOR_RING_ATTESTATION_KEYS),
        "Winn3 descriptor ring attestation",
    )
    schema_version = document.get("schema_version")
    identity = document.get("identity_sha256")
    verified_artifact = document.get("verified_artifact")
    if type(schema_version) is not int or isinstance(schema_version, bool):
        raise LinuxArtifactGateError(
            "Winn3 descriptor ring attestation schema_version is invalid."
        )
    if (
        schema_version != WINN3_DESCRIPTOR_RING_ATTESTATION_SCHEMA_VERSION
        or type(identity) is not str
        or re.fullmatch(r"[0-9a-f]{64}", identity) is None
        or identity != REVIEWED_WINN3_DESCRIPTOR_RING_SHA256
        or verified_artifact != WINN3_DESCRIPTOR_RING_VERIFIED_ARTIFACT
    ):
        raise LinuxArtifactGateError(
            "Winn3 descriptor ring attestation is stale or unbound."
        )
    expected_bytes = _canonical_winn3_descriptor_ring_attestation(identity)
    if payload != expected_bytes:
        raise LinuxArtifactGateError(
            "Winn3 descriptor ring attestation is not the exact canonical document."
        )
    if verified_artifact_name not in payloads:
        raise LinuxArtifactGateError(
            "Winn3 descriptor ring attestation verified artifact is missing."
        )
    artifact_payload = payloads[verified_artifact_name]
    _require_executable_elf(
        artifact_payload,
        verified_artifact_name,
        expected_machine,
        require_entry=False,
    )
    if identity.encode("ascii") not in artifact_payload:
        raise LinuxArtifactGateError(
            "Winn3 descriptor ring attestation does not bind the verified artifact hash."
        )


def _canonical_runtime_protocol_order() -> bytes:
    document = {
        "contract": RUNTIME_PROTOCOL_ORDER_CONTRACT,
        "ordered_protocols": [
            {
                "engines": ["winn-datapath"],
                "protocol": "winn-v3",
            },
            {
                "engines": ["awg", "awg-quick", "amneziawg-go", "xray"],
                "protocol": "winn-v1",
            },
        ],
        "schema_version": 1,
    }
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _elf_section_names(payload: bytes, label: str) -> set[str]:
    (
        _ident,
        _elf_type,
        _machine,
        _version,
        _entry,
        _phoff,
        shoff,
        _flags,
        _ehsize,
        _phentsize,
        _phnum,
        shentsize,
        shnum,
        shstrndx,
    ) = ELF64_HEADER_STRUCT.unpack_from(payload, 0)
    if shentsize != ELF64_SHDR_STRUCT.size or shstrndx >= shnum:
        raise LinuxArtifactGateError(f"{label} ELF section table is invalid.")
    str_header = ELF64_SHDR_STRUCT.unpack_from(
        payload, shoff + (shstrndx * shentsize)
    )
    string_offset = int(str_header[4])
    string_size = int(str_header[5])
    if string_size <= 1 or string_offset + string_size > len(payload):
        raise LinuxArtifactGateError(f"{label} ELF section string table is invalid.")
    strings = payload[string_offset : string_offset + string_size]
    names: set[str] = set()
    for index in range(shnum):
        header = ELF64_SHDR_STRUCT.unpack_from(payload, shoff + (index * shentsize))
        name_offset = int(header[0])
        section_offset = int(header[4])
        section_size = int(header[5])
        if name_offset >= len(strings) or section_offset + section_size > len(payload):
            raise LinuxArtifactGateError(f"{label} ELF section is out of bounds.")
        terminator = strings.find(b"\0", name_offset)
        if terminator < 0:
            raise LinuxArtifactGateError(f"{label} ELF section name is unterminated.")
        try:
            name = strings[name_offset:terminator].decode("ascii")
        except UnicodeError as exc:
            raise LinuxArtifactGateError(
                f"{label} ELF section name is not canonical ASCII."
            ) from exc
        if name in names and name:
            raise LinuxArtifactGateError(f"{label} ELF has duplicate section names.")
        names.add(name)
    return names


def _elf_section_metadata(
    payload: bytes, label: str
) -> dict[str, tuple[int, int, int, int, int, int, int]]:
    """Return name -> (index, type, offset, size, link, info, entsize) metadata."""
    _elf_section_names(payload, label)
    header = ELF64_HEADER_STRUCT.unpack_from(payload, 0)
    shoff = int(header[6])
    shentsize = int(header[11])
    shnum = int(header[12])
    shstrndx = int(header[13])
    str_header = ELF64_SHDR_STRUCT.unpack_from(
        payload, shoff + (shstrndx * shentsize)
    )
    strings_offset = int(str_header[4])
    strings_size = int(str_header[5])
    strings = payload[strings_offset : strings_offset + strings_size]
    result: dict[str, tuple[int, int, int, int, int, int]] = {}
    for index in range(shnum):
        section = ELF64_SHDR_STRUCT.unpack_from(payload, shoff + (index * shentsize))
        name_offset = int(section[0])
        terminator = strings.find(b"\0", name_offset)
        name = strings[name_offset:terminator].decode("ascii")
        if name:
            result[name] = (
                index,
                int(section[1]),
                int(section[4]),
                int(section[5]),
                int(section[6]),
                int(section[7]),
                int(section[9]),
            )
    return result


def _elf_gnu_build_id(payload: bytes, label: str) -> str:
    if len(payload) < ELF64_HEADER_STRUCT.size:
        raise LinuxArtifactGateError(f"{label} ELF header is truncated.")
    header = ELF64_HEADER_STRUCT.unpack_from(payload, 0)
    ident = header[0]
    shoff = int(header[6])
    shentsize = int(header[11])
    shnum = int(header[12])
    shstrndx = int(header[13])
    if (
        ident[:4] != ELF_MAGIC
        or ident[4] != 2
        or ident[5] != 1
        or shentsize != ELF64_SHDR_STRUCT.size
        or shnum <= 1
        or shnum > MAX_SHNUM
        or shstrndx >= shnum
        or shoff > len(payload)
        or shnum * shentsize > len(payload) - shoff
    ):
        raise LinuxArtifactGateError(f"{label} ELF section table is invalid.")
    str_header = ELF64_SHDR_STRUCT.unpack_from(
        payload, shoff + shstrndx * shentsize
    )
    strings_offset = int(str_header[4])
    strings_size = int(str_header[5])
    if strings_size <= 1 or strings_offset > len(payload) or strings_size > len(payload) - strings_offset:
        raise LinuxArtifactGateError(f"{label} ELF section string table is invalid.")
    strings = payload[strings_offset : strings_offset + strings_size]
    matches: list[str] = []
    for index in range(shnum):
        section = ELF64_SHDR_STRUCT.unpack_from(payload, shoff + index * shentsize)
        name_offset = int(section[0])
        section_type = int(section[1])
        section_offset = int(section[4])
        section_size = int(section[5])
        if name_offset >= len(strings) or section_offset > len(payload) or section_size > len(payload) - section_offset:
            raise LinuxArtifactGateError(f"{label} ELF section is out of bounds.")
        terminator = strings.find(b"\0", name_offset)
        if terminator < 0:
            raise LinuxArtifactGateError(f"{label} ELF section name is unterminated.")
        name = strings[name_offset:terminator]
        if name != b".note.gnu.build-id":
            continue
        if section_type != 7:
            raise LinuxArtifactGateError(f"{label} GNU build-ID section type is invalid.")
        note = payload[section_offset : section_offset + section_size]
        if len(note) < 12:
            raise LinuxArtifactGateError(f"{label} GNU build-ID note is truncated.")
        namesz, descsz, note_type = struct.unpack_from("<III", note, 0)
        name_end = 12 + namesz
        desc_offset = (name_end + 3) & ~3
        desc_end = desc_offset + descsz
        padded_end = (desc_end + 3) & ~3
        if (
            namesz != 4
            or note_type != 3
            or note[12:name_end] != b"GNU\0"
            or descsz < 16
            or descsz > 64
            or padded_end != len(note)
        ):
            raise LinuxArtifactGateError(f"{label} GNU build-ID note is malformed.")
        matches.append(note[desc_offset:desc_end].hex())
    if len(matches) != 1:
        raise LinuxArtifactGateError(f"{label} must contain exactly one GNU build ID.")
    return matches[0]


def _require_loadable_held_elf(
    payload: bytes,
    label: str,
    expected_machine: int,
    *,
    executable_role: bool,
) -> dict[str, object]:
    parsed = _require_executable_elf(
        payload,
        label,
        expected_machine,
        require_entry=executable_role,
    )
    (
        _ident,
        elf_type,
        _machine,
        _version,
        entry,
        phoff,
        _shoff,
        _flags,
        _ehsize,
        phentsize,
        phnum,
        _shentsize,
        _shnum,
        _shstrndx,
    ) = ELF64_HEADER_STRUCT.unpack_from(payload, 0)
    executable_loads: list[tuple[int, int, int, int]] = []
    readable_loads: list[tuple[int, int]] = []
    dynamic_segments: list[tuple[int, int, int, int]] = []
    interpreter_segments: list[tuple[int, int]] = []
    for index in range(phnum):
        kind, flags, offset, vaddr, _paddr, filesz, memsz, alignment = (
            ELF64_PHDR_STRUCT.unpack_from(payload, phoff + (index * phentsize))
        )
        if (
            filesz > memsz
            or offset > len(payload)
            or filesz > len(payload) - offset
            or (alignment not in {0, 1} and alignment & (alignment - 1))
            or (
                kind == PT_LOAD
                and alignment not in {0, 1}
                and (vaddr - offset) % alignment != 0
            )
        ):
            raise LinuxArtifactGateError(f"{label} has an invalid loadable ELF segment.")
        if kind == PT_LOAD:
            if memsz == 0:
                raise LinuxArtifactGateError(f"{label} has an empty PT_LOAD segment.")
            if flags & PF_R:
                readable_loads.append((vaddr, vaddr + memsz))
            if flags & PF_X:
                if filesz == 0:
                    raise LinuxArtifactGateError(
                        f"{label} has an empty executable PT_LOAD segment."
                    )
                executable_loads.append((vaddr, vaddr + memsz, offset, filesz))
        elif kind == PT_DYNAMIC:
            dynamic_segments.append((vaddr, vaddr + memsz, offset, filesz))
        elif kind == PT_INTERP:
            interpreter_segments.append((offset, filesz))
    if not executable_loads:
        raise LinuxArtifactGateError(
            f"{label} is header-only or lacks a loadable executable segment."
        )
    section_names = _elf_section_names(payload, label)
    if ".text" not in section_names:
        raise LinuxArtifactGateError(f"{label} ELF lacks a bounded .text section.")

    if executable_role:
        entry_offsets = [
            offset + (entry - start)
            for start, end, offset, filesz in executable_loads
            if start <= entry < end and entry - start < filesz
        ]
        if len(entry_offsets) != 1:
            raise LinuxArtifactGateError(
                f"{label} executable entry point is not bound to one file-backed PT_LOAD."
            )
        entry_code = payload[entry_offsets[0] : entry_offsets[0] + 16]
        if not entry_code or entry_code.startswith(b"\0" * min(4, len(entry_code))):
            raise LinuxArtifactGateError(
                f"{label} executable entry point is empty or undefined."
            )
        if expected_machine == 62 and (
            entry_code.startswith(b"\xcc")
            or entry_code.startswith(b"\xf4")
            or entry_code.startswith(b"\x0f\x0b")
        ):
            raise LinuxArtifactGateError(
                f"{label} executable entry point is trap-only."
            )
        if expected_machine == 183 and len(entry_code) >= 4:
            instruction = int.from_bytes(entry_code[:4], "little")
            if instruction & 0xFFE0001F in {0xD4200000, 0xD4400000}:
                raise LinuxArtifactGateError(
                    f"{label} executable entry point is trap-only."
                )
        if len(interpreter_segments) > 1 or len(dynamic_segments) > 1:
            raise LinuxArtifactGateError(f"{label} has duplicate loader segments.")
        for offset, size in interpreter_segments:
            interpreter = payload[offset : offset + size]
            if not interpreter or interpreter[-1:] != b"\0" or b"\0" in interpreter[:-1]:
                raise LinuxArtifactGateError(f"{label} has an invalid PT_INTERP.")
        if elf_type == ET_DYN and len(dynamic_segments) != 1:
            raise LinuxArtifactGateError(
                f"{label} ET_DYN executable lacks exactly one PT_DYNAMIC."
            )
    else:
        if (
            elf_type != ET_DYN
            or entry != 0
            or len(dynamic_segments) != 1
            or interpreter_segments
        ):
            raise LinuxArtifactGateError(
                f"{label} shared object lacks loadable ET_DYN/PT_DYNAMIC semantics."
            )

    for start, end, offset, size in dynamic_segments:
        if size < 16 or size % 16 != 0:
            raise LinuxArtifactGateError(f"{label} PT_DYNAMIC is malformed.")
        if not any(load_start <= start < end <= load_end for load_start, load_end in readable_loads):
            raise LinuxArtifactGateError(
                f"{label} PT_DYNAMIC is not contained in a readable PT_LOAD."
            )
        tags: list[int] = []
        for item_offset in range(offset, offset + size, 16):
            tag, _value = struct.unpack_from("<QQ", payload, item_offset)
            tags.append(tag)
            if tag == 0:
                break
        if not tags or tags[-1] != 0:
            raise LinuxArtifactGateError(f"{label} PT_DYNAMIC lacks DT_NULL termination.")
        if not executable_role and not {5, 6}.issubset(tags):
            raise LinuxArtifactGateError(
                f"{label} shared object lacks bounded DT_STRTAB/DT_SYMTAB metadata."
            )
    if dynamic_segments and not {".dynamic", ".dynstr", ".dynsym"}.issubset(section_names):
        raise LinuxArtifactGateError(
            f"{label} dynamic ELF lacks required loader sections."
        )
    return parsed


def _verify_held_runtime_closure(
    payloads: Mapping[str, bytes], expected_machine: int
) -> None:
    runtime = payloads.get(RUNTIME_PROTOCOL_ORDER_PATH)
    if runtime is None:
        raise LinuxArtifactGateError(
            "held Linux package is missing its v3-then-v1 runtime protocol manifest."
        )
    if runtime != _canonical_runtime_protocol_order():
        raise LinuxArtifactGateError(
            "held Linux package runtime protocol order is not exact Winn v3 then "
            "Winn v1 over AWG/Xray."
        )
    for name in sorted(REQUIRED_PROGRAM_ELFS):
        _require_loadable_held_elf(
            payloads[name],
            name,
            expected_machine,
            executable_role=True,
        )
    for name in sorted(REQUIRED_LIBRARY_ELFS):
        _require_loadable_held_elf(
            payloads[name],
            name,
            expected_machine,
            executable_role=False,
        )


def _inspect_archive(
    snapshot: AuthenticatedSnapshot,
    expected_arch: str,
    expected_machine: int,
    expected_appstream_version: str,
    expected_source_closure: str,
    *,
    held_strict: bool = False,
) -> dict[str, object]:
    snapshot.reject_origin_swap()
    try:
        members, payloads, modes, archive_budget = _read_gzip_tar_snapshot(snapshot)
        names = [member.name for member in members]
        if names != sorted(names):
            raise LinuxArtifactGateError("Linux package members are not deterministically sorted.")
        mtimes = {member.mtime for member in members}
        if len(mtimes) != 1:
            raise LinuxArtifactGateError("Linux package member timestamps are not deterministic.")
        validate_tar_metadata(snapshot.path, members)
    except (OSError, tarfile.TarError, PrivacyError) as exc:
        raise LinuxArtifactGateError(f"Linux package archive is unsafe: {exc}") from exc
    snapshot.reject_origin_swap()

    missing = sorted(REQUIRED_FILES - payloads.keys())
    if missing:
        raise LinuxArtifactGateError("Linux package is incomplete: " + ", ".join(missing))
    _reject_extra_elf_payloads(
        payloads, set(REQUIRED_PROGRAM_ELFS) | set(REQUIRED_LIBRARY_ELFS), "Linux package"
    )
    _scan_elf_payloads(payloads, expected_machine)
    for required_elf in REQUIRED_PROGRAM_ELFS:
        _require_executable_elf(payloads[required_elf], required_elf, expected_machine, require_entry=True)
    for required_lib in REQUIRED_LIBRARY_ELFS:
        _require_executable_elf(payloads[required_lib], required_lib, expected_machine, require_entry=False)
    flutter_identities = _require_flutter_payload(payloads, expected_machine)
    _verify_native_host_contract(
        payloads,
        modes,
        expected_arch,
        expected_machine,
        expected_source_closure,
    )
    _verify_winn3_descriptor_ring_attestation(
        payloads,
        modes,
        attestation_name=WINN3_DESCRIPTOR_RING_ATTESTATION_NAME,
        verified_artifact_name=WINN3_DESCRIPTOR_RING_VERIFIED_ARTIFACT,
        expected_machine=expected_machine,
        label="Linux package",
    )
    if held_strict:
        _verify_held_runtime_closure(payloads, expected_machine)

    manifest = _parse_release_manifest(payloads["release-manifest.sha256"])
    expected_manifest = {
        name: _sha256_bytes(payload)
        for name, payload in payloads.items()
        if name != "release-manifest.sha256"
    }
    if manifest != expected_manifest:
        raise LinuxArtifactGateError("release-manifest.sha256 is not exhaustive and exact.")

    try:
        desktop = payloads["share/applications/org.winsvpn.app.desktop"].decode("utf-8")
        metainfo = payloads["share/metainfo/org.winsvpn.app.metainfo.xml"].decode("utf-8")
    except UnicodeError as exc:
        raise LinuxArtifactGateError("Linux package identity metadata is not UTF-8.") from exc
    if not re.search(r"(?m)^Exec=wins_vpn(?:\s|$)", desktop):
        raise LinuxArtifactGateError("desktop identity does not launch wins_vpn.")
    if "<!DOCTYPE" in metainfo.upper() or "<!ENTITY" in metainfo.upper():
        raise LinuxArtifactGateError(
            "AppStream metainfo must not contain a document type or entity declaration."
        )
    try:
        component = ET.fromstring(metainfo)
    except ET.ParseError as exc:
        raise LinuxArtifactGateError("AppStream metainfo is malformed XML.") from exc
    component_id = component.find("id")
    if (
        component.tag != "component"
        or component_id is None
        or component_id.text != "org.winsvpn.app"
    ):
        raise LinuxArtifactGateError("metainfo identity is not org.winsvpn.app.")
    releases = component.findall("./releases/release")
    versions = [release.get("version") for release in releases]
    if (
        not versions
        or versions[0] != expected_appstream_version
        or any(
            not isinstance(version, str)
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None
            for version in versions
        )
        or len(versions) != len(set(versions))
    ):
        raise LinuxArtifactGateError(
            "AppStream metainfo does not lead with the canonical release version."
        )
    _scan_store_package_payloads(payloads, budget=archive_budget)
    return {
        "files": len(payloads),
        "elf_machine": expected_machine,
        "appstream_version": expected_appstream_version,
        "flutter_identities": flutter_identities,
    }


def _verify_checksum(origin: pathlib.Path, digest: str) -> AuthenticatedSnapshot:
    sidecar_raw = origin.relative_to(ROOT.resolve(strict=True)).as_posix() + ".sha256"
    try:
        sidecar = _secure_regular_repo_path(sidecar_raw, "Linux archive checksum")
    except LinuxArtifactGateError as suc:
        if "is missing" in str(suc):
            raise _owner_build_system_blocker(
                "no exact local Linux archive checksum is bound to the package"
            ) from suc
        raise
    sidecar_snapshot = _snapshot_artifact(sidecar, "Linux archive checksum")
    try:
        sidecar_snapshot.reject_origin_swap()
        actual = os.pread(sidecar_snapshot.fd, sidecar_snapshot.size, 0)
        expected = f"{digest}  {origin.name}\n".encode("ascii")
        if actual != expected:
            raise LinuxArtifactGateError("Linux archive checksum does not bind the exact artifact.")
        sidecar_snapshot.reject_origin_swap()
        sidecar_snapshot.rehash()
        return sidecar_snapshot
    except BaseException:
        sidecar_snapshot.close()
        raise


def _subprocess_env() -> dict[str, str]:
    return {
        "PATH": REVIEWED_SUBPROCESS_PATH,
        "HOME": "/var/empty",
        "TMPDIR": "/tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "COSIGN_YES": "false",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _validate_standard_bundle_snapshot(snapshot: AuthenticatedSnapshot) -> None:
    snapshot.ensure_bound()
    payload = os.pread(snapshot.fd, snapshot.size, 0)
    if len(payload) != snapshot.size:
        raise LinuxArtifactGateError("Sigstore bundle snapshot read was truncated.")
    document = _exact_json(payload, "Sigstore bundle")
    expected_media_type = linux_release_signing.STANDARD_BUNDLE_MEDIA_TYPE
    if document.get("mediaType") != expected_media_type:
        raise LinuxArtifactGateError(
            "Sigstore bundle is legacy or does not use the reviewed media type."
        )
    if type(document.get("verificationMaterial")) is not dict:
        raise LinuxArtifactGateError("Sigstore bundle lacks verificationMaterial.")
    content_fields = [
        name
        for name in ("messageSignature", "dsseEnvelope")
        if type(document.get(name)) is dict
    ]
    if len(content_fields) != 1:
        raise LinuxArtifactGateError(
            "Sigstore bundle must contain exactly one signature content type."
        )
    _require_exact_keys(
        document,
        {"mediaType", "verificationMaterial", content_fields[0]},
        "Sigstore bundle",
    )
    snapshot.rehash()


def _terminate_subprocess_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the isolated child process group, including descendants."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            raise LinuxArtifactGateError(
                "authenticated subprocess group could not be terminated."
            ) from exc
    if process.poll() is None:
        try:
            process.wait(timeout=SUBPROCESS_TERMINATE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            raise LinuxArtifactGateError(
                "authenticated subprocess group could not be killed."
            ) from exc
    if process.poll() is None:
        try:
            process.wait(timeout=SUBPROCESS_TERMINATE_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise LinuxArtifactGateError(
                "authenticated subprocess did not terminate after SIGKILL."
            ) from exc


def _isolated_process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        raise LinuxArtifactGateError(
            "authenticated subprocess group state is unavailable."
        ) from exc
    return True


class _LinuxCgroupContainment:
    """One cgroup-v2 job hidden behind a fresh user/PID/cgroup namespace."""

    def __init__(self) -> None:
        if sys.platform != "linux":
            raise _owner_environment_blocker(
                "Linux release subprocess containment remains OWNER-BLOCKED: "
                "cgroup v2 is unavailable on this host."
            )
        try:
            if len(os.listdir("/proc/self/task")) != 1:
                raise LinuxArtifactGateError(
                    "authenticated subprocess launch requires a single-threaded controller."
                )
        except OSError as exc:
            raise LinuxArtifactGateError(
                "authenticated subprocess thread state is unavailable."
            ) from exc
        self._chain = _retain_complete_directory_chain(
            PROCESS_CGROUP_ROOT, "reviewed Linux release cgroup"
        )
        self._name = PROCESS_CGROUP_PREFIX + secrets.token_hex(16)
        self._job_fd = -1
        self._procs_fd = -1
        self._kill_fd = -1
        self._events_fd = -1
        self._created = False
        self._namespace_files: list[
            tuple[pathlib.Path, int, tuple[int, ...], str, _RetainedDirectoryChain]
        ] = []
        try:
            root_info = os.fstat(self._chain.leaf_fd)
            if (
                root_info.st_uid != os.geteuid()
                or stat.S_IMODE(root_info.st_mode) != 0o700
            ):
                raise _owner_environment_blocker(
                    "Linux release subprocess containment remains OWNER-BLOCKED: "
                    "the fixed cgroup root is not exclusively delegated to this release UID."
                )
            self._recover_orphan_jobs()
            self._namespace_files.append(
                self._authenticate_namespace_executable(
                    PROCESS_NAMESPACE_UNSHARE,
                    "Linux release namespace supervisor",
                )
            )
            self._namespace_files.append(
                self._authenticate_namespace_executable(
                    PROCESS_NAMESPACE_SHELL,
                    "Linux release namespace bootstrap shell",
                )
            )
            self._namespace_files.append(
                self._authenticate_namespace_executable(
                    PROCESS_NAMESPACE_MOUNT,
                    "Linux release cgroup namespace mount tool",
                )
            )
            os.mkdir(self._name, 0o700, dir_fd=self._chain.leaf_fd)
            self._created = True
            self._job_fd = _openat_child(
                self._chain.leaf_fd,
                self._name,
                _dir_open_flags(),
                label="Linux release subprocess cgroup",
            )
            self._procs_fd = os.open(
                "cgroup.procs", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=self._job_fd,
            )
            self._kill_fd = os.open(
                "cgroup.kill", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=self._job_fd,
            )
            self._events_fd = os.open(
                "cgroup.events", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=self._job_fd,
            )
            self._chain.revalidate()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _authenticate_namespace_executable(
        path: pathlib.Path, label: str
    ) -> tuple[pathlib.Path, int, tuple[int, ...], str, _RetainedDirectoryChain]:
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise _owner_environment_blocker(
                f"{label} remains OWNER-BLOCKED: {path} is unavailable."
            ) from exc
        chain = _retain_complete_directory_chain(resolved.parent, label)
        fd = -1
        try:
            fd = os.open(resolved, _open_flags())
            info = os.fstat(fd)
            named = resolved.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_nlink != 1
                or not info.st_mode & 0o111
                or stat.S_IMODE(info.st_mode) & 0o022
                or _file_identity(info) != _file_identity(named)
            ):
                raise _owner_environment_blocker(
                    f"{label} remains OWNER-BLOCKED: its system executable custody is unsafe."
                )
            digest = _sha256_fd(fd)
            chain.revalidate()
            result = (resolved, fd, _file_identity(info), digest, chain)
            fd = -1
            return result
        except BaseException:
            chain.close()
            raise
        finally:
            if fd >= 0:
                os.close(fd)

    @staticmethod
    def _events_populated(events_fd: int) -> bool:
        raw = os.pread(events_fd, 4096, 0)
        if len(raw) == 4096:
            raise LinuxArtifactGateError(
                "Linux release cgroup events exceed the byte ceiling."
            )
        values: dict[str, str] = {}
        try:
            for line in raw.decode("ascii", "strict").splitlines():
                key, value = line.split(" ", 1)
                if key in values:
                    raise ValueError("duplicate cgroup event")
                values[key] = value
        except (UnicodeError, ValueError) as exc:
            raise LinuxArtifactGateError(
                "Linux release cgroup events are malformed."
            ) from exc
        if values.get("populated") not in {"0", "1"}:
            raise LinuxArtifactGateError(
                "Linux release cgroup population state is missing."
            )
        return values["populated"] == "1"

    @classmethod
    def _kill_job_descriptors(cls, kill_fd: int, events_fd: int) -> None:
        if cls._events_populated(events_fd):
            _write_all(kill_fd, b"1\n")
        deadline = _MONOTONIC() + PROCESS_CGROUP_DRAIN_SECONDS
        while cls._events_populated(events_fd):
            if _MONOTONIC() >= deadline:
                raise LinuxArtifactGateError(
                    "Linux release subprocess cgroup did not drain after kill."
                )
            _SLEEP(0.01)

    @classmethod
    def _recover_orphan_jobs_in(cls, chain: _RetainedDirectoryChain) -> None:
        names = [
            name
            for name in sorted(os.listdir(chain.leaf_fd))
            if re.fullmatch(PROCESS_CGROUP_PREFIX + r"[0-9a-f]{32}", name)
        ]
        if len(names) > PROCESS_CGROUP_MAX_ORPHANS:
            raise LinuxArtifactGateError(
                "Linux release subprocess orphan count exceeds the reviewed ceiling."
            )
        for name in names:
            job_fd = -1
            kill_fd = -1
            events_fd = -1
            try:
                before = os.stat(
                    name, dir_fd=chain.leaf_fd, follow_symlinks=False
                )
                if (
                    not stat.S_ISDIR(before.st_mode)
                    or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o700
                ):
                    raise LinuxArtifactGateError(
                        "Linux release subprocess orphan identity is invalid."
                    )
                job_fd = _openat_child(
                    chain.leaf_fd,
                    name,
                    _dir_open_flags(),
                    label="Linux release subprocess orphan cgroup",
                )
                identity = _directory_identity(os.fstat(job_fd))
                kill_fd = os.open(
                    "cgroup.kill",
                    os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=job_fd,
                )
                events_fd = os.open(
                    "cgroup.events",
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=job_fd,
                )
                cls._kill_job_descriptors(kill_fd, events_fd)
                named = os.stat(
                    name, dir_fd=chain.leaf_fd, follow_symlinks=False
                )
                if _directory_identity(named) != identity:
                    raise LinuxArtifactGateError(
                        "Linux release subprocess orphan was replaced during recovery."
                    )
            except OSError as exc:
                raise LinuxArtifactGateError(
                    "Linux release subprocess orphan recovery failed closed."
                ) from exc
            finally:
                for fd in (events_fd, kill_fd, job_fd):
                    if fd >= 0:
                        os.close(fd)
            os.rmdir(name, dir_fd=chain.leaf_fd)

    def _recover_orphan_jobs(self) -> None:
        self._recover_orphan_jobs_in(self._chain)

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return (self._procs_fd,) + tuple(
            fd for _path, fd, _identity, _digest, _chain in self._namespace_files
        )

    @property
    def requires_namespace_handshake(self) -> bool:
        return True

    def enter_child(self) -> None:
        _write_all(self._procs_fd, b"0\n")
        os.close(self._procs_fd)

    def wrap_argv(self, argv: list[str], handshake_fd: int) -> list[str]:
        if handshake_fd < 0 or len(self._namespace_files) != 3:
            raise LinuxArtifactGateError(
                "Linux release namespace handshake custody is unavailable."
            )
        unshare_fd = self._namespace_files[0][1]
        shell_fd = self._namespace_files[1][1]
        mount_fd = self._namespace_files[2][1]
        unshare = f"/proc/self/fd/{unshare_fd}"
        shell = f"/proc/self/fd/{shell_fd}"
        mount = f"/proc/self/fd/{mount_fd}"
        handshake = PROCESS_NAMESPACE_HANDSHAKE.decode("ascii")
        bootstrap = (
            "set -eu\n"
            f"{shlex.quote(mount)} -t cgroup2 -o nosuid,nodev,noexec "
            "cgroup2 /sys/fs/cgroup\n"
            "winsvpn_cgroup=''\n"
            "winsvpn_cgroup_count=0\n"
            "while IFS= read -r winsvpn_cgroup_line; do\n"
            "  winsvpn_cgroup=$winsvpn_cgroup_line\n"
            "  winsvpn_cgroup_count=$((winsvpn_cgroup_count + 1))\n"
            "done < /proc/self/cgroup\n"
            "[ \"$winsvpn_cgroup_count\" -eq 1 ]\n"
            "[ \"$winsvpn_cgroup\" = '0::/' ]\n"
            "[ -r /sys/fs/cgroup/cgroup.procs ]\n"
            f"printf '%s' {shlex.quote(handshake)} >&{handshake_fd}\n"
            f"exec {handshake_fd}>&-\n"
            f"exec {unshare_fd}>&-\n"
            f"exec {shell_fd}>&-\n"
            f"exec {mount_fd}>&-\n"
            'exec "$@"\n'
        )
        return [
            unshare,
            "--user",
            "--map-root-user",
            "--setgroups=deny",
            "--mount",
            "--propagation=private",
            "--pid",
            "--cgroup",
            "--fork",
            "--kill-child=KILL",
            "--mount-proc=/proc",
            "--",
            shell,
            "-c",
            bootstrap,
            "winsvpn-linux-namespace-v1",
            *argv,
        ]

    def revalidate_namespace_boundary(self) -> None:
        for path, fd, identity, digest, chain in self._namespace_files:
            chain.revalidate()
            current = os.fstat(fd)
            named = path.lstat()
            if (
                _file_identity(current) != identity
                or _file_identity(named) != identity
                or _sha256_fd(fd) != digest
            ):
                raise LinuxArtifactGateError(
                    "Linux release namespace boundary changed during execution."
                )

    def populated(self) -> bool:
        return self._events_populated(self._events_fd)

    def kill_all(self) -> None:
        _write_all(self._kill_fd, b"1\n")

    def wait_empty(self) -> None:
        self._kill_job_descriptors(self._kill_fd, self._events_fd)

    def close(self) -> None:
        failure: BaseException | None = None
        if self._job_fd >= 0:
            try:
                if self._events_fd >= 0 and self.populated():
                    self.kill_all()
                    self.wait_empty()
            except BaseException as exc:
                failure = exc
        for name in ("_events_fd", "_kill_fd", "_procs_fd", "_job_fd"):
            fd = getattr(self, name, -1)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)
        chain = getattr(self, "_chain", None)
        if chain is not None:
            try:
                if self._created:
                    os.rmdir(self._name, dir_fd=chain.leaf_fd)
                    self._created = False
                chain.revalidate()
            except BaseException as exc:
                if failure is None:
                    failure = exc
            finally:
                chain.close()
                self._chain = None
        for _path, fd, _identity, _digest, namespace_chain in reversed(
            self._namespace_files
        ):
            os.close(fd)
            namespace_chain.close()
        self._namespace_files = []
        if failure is not None:
            raise failure


def _open_process_containment() -> _LinuxCgroupContainment:
    return _LinuxCgroupContainment()


def _recover_linux_process_orphans() -> None:
    """Kill authenticated stale extraction jobs before snapshot orphan deletion."""
    if sys.platform != "linux":
        return
    try:
        chain = _retain_complete_directory_chain(
            PROCESS_CGROUP_ROOT, "reviewed Linux release cgroup recovery"
        )
    except LinuxArtifactGateError as exc:
        raise _owner_environment_blocker(
            "Linux release subprocess recovery remains OWNER-BLOCKED: "
            "the fixed cgroup-v2 root is unavailable."
        ) from exc
    try:
        root_info = os.fstat(chain.leaf_fd)
        if (
            root_info.st_uid != os.geteuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise _owner_environment_blocker(
                "Linux release subprocess recovery remains OWNER-BLOCKED: "
                "the fixed cgroup root is not exclusively delegated to this release UID."
            )
        _LinuxCgroupContainment._recover_orphan_jobs_in(chain)
        chain.revalidate()
    finally:
        chain.close()


def _run_bounded_subprocess(
    argv: list[str],
    *,
    cwd: pathlib.Path | str,
    pass_fds: tuple[int, ...],
    label: str,
) -> subprocess.CompletedProcess[str]:
    """Run an isolated child while concurrently draining bounded byte streams."""
    if not argv or any(type(value) is not str or not value for value in argv):
        raise LinuxArtifactGateError(f"{label} argv is invalid.")
    process: subprocess.Popen[bytes] | None = None
    containment = _open_process_containment()
    selector = selectors.DefaultSelector()
    streams: dict[int, tuple[str, bytearray]] = {}
    handshake_read = -1
    handshake_write = -1
    deadline = _MONOTONIC() + SUBPROCESS_DEADLINE_SECONDS
    try:
        launch_argv = argv
        launch_fds = pass_fds + containment.pass_fds
        requires_handshake = bool(
            getattr(containment, "requires_namespace_handshake", False)
        )
        if requires_handshake:
            handshake_read, handshake_write = os.pipe2(os.O_CLOEXEC)
            launch_argv = containment.wrap_argv(argv, handshake_write)
            launch_fds += (handshake_write,)
        try:
            process = subprocess.Popen(
                launch_argv,
                cwd=cwd,
                env=_subprocess_env(),
                pass_fds=tuple(dict.fromkeys(launch_fds)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                shell=False,
                close_fds=True,
                start_new_session=True,
                preexec_fn=containment.enter_child,
                bufsize=0,
            )
        except subprocess.SubprocessError as exc:
            raise LinuxArtifactGateError(
                f"{label} pre-exec containment failed closed."
            ) from exc
        if handshake_write >= 0:
            os.close(handshake_write)
            handshake_write = -1
        if process.stdout is None or process.stderr is None:
            raise LinuxArtifactGateError(f"{label} pipe custody is unavailable.")
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            fd = stream.fileno()
            os.set_blocking(fd, False)
            streams[fd] = (name, bytearray())
            selector.register(fd, selectors.EVENT_READ)
        if handshake_read >= 0:
            os.set_blocking(handshake_read, False)
            streams[handshake_read] = ("namespace", bytearray())
            selector.register(handshake_read, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - _MONOTONIC()
            if remaining <= 0:
                raise LinuxArtifactGateError(f"{label} exceeded its execution deadline.")
            events = selector.select(timeout=min(remaining, 0.25))
            for key, _mask in events:
                fd = int(key.fd)
                name, captured = streams[fd]
                try:
                    chunk = os.read(fd, min(64 * 1024, MAX_SUBPROCESS_STREAM_BYTES - len(captured) + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(fd)
                    continue
                captured.extend(chunk)
                ceiling = (
                    len(PROCESS_NAMESPACE_HANDSHAKE)
                    if name == "namespace"
                    else MAX_SUBPROCESS_STREAM_BYTES
                )
                if len(captured) > ceiling:
                    raise LinuxArtifactGateError(
                        f"{label} {name} exceeded the reviewed byte ceiling."
                    )
        remaining = deadline - _MONOTONIC()
        if remaining <= 0:
            raise LinuxArtifactGateError(f"{label} exceeded its execution deadline.")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise LinuxArtifactGateError(
                f"{label} exceeded its execution deadline."
            ) from exc
        if containment.populated() or _isolated_process_group_exists(process.pid):
            _terminate_subprocess_group(process)
            containment.kill_all()
            containment.wait_empty()
            raise LinuxArtifactGateError(
                f"{label} left a descendant process running."
            )
        if requires_handshake:
            namespace_payload = bytes(
                next(
                    value
                    for name, value in streams.values()
                    if name == "namespace"
                )
            )
            if namespace_payload != PROCESS_NAMESPACE_HANDSHAKE:
                raise _owner_environment_blocker(
                    f"{label} namespace boundary remains OWNER-BLOCKED: "
                    "the reviewed user/PID/cgroup namespace could not start."
                )
            containment.revalidate_namespace_boundary()
        try:
            stdout = bytes(next(value for name, value in streams.values() if name == "stdout")).decode("utf-8", "strict")
            stderr = bytes(next(value for name, value in streams.values() if name == "stderr")).decode("utf-8", "strict")
        except UnicodeError as exc:
            raise LinuxArtifactGateError(
                f"{label} emitted non-UTF-8 diagnostic output."
            ) from exc
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)
    except BaseException:
        if process is not None:
            _terminate_subprocess_group(process)
        containment.kill_all()
        containment.wait_empty()
        raise
    finally:
        selector.close()
        if handshake_read >= 0:
            os.close(handshake_read)
        if handshake_write >= 0:
            os.close(handshake_write)
        if process is not None:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        containment.close()


def _run_cosign(snapshot: AuthenticatedSnapshot, bundle_snapshot: AuthenticatedSnapshot) -> None:
    public_key_raw = snapshot.origin.relative_to(ROOT.resolve(strict=True)).as_posix() + ".cosign.pub"
    public_key_candidate = ROOT.resolve(strict=True) / public_key_raw
    try:
        trusted_public_key = _secure_regular_repo_path(
            TRUSTED_LOCAL_COSIGN_KEY.as_posix(), "reviewed Linux cosign trust anchor"
        )
    except LinuxArtifactGateError as suc:
        if "is missing" in str(suc):
            raise _owner_environment_blocker(
                "reviewed Linux cosign trust anchor remains OWNER-BLOCKED: ABSENT"
            ) from suc
        raise
    key_snapshot = _snapshot_artifact(trusted_public_key, "reviewed Linux cosign trust anchor")
    try:
        try:
            adjacent = public_key_candidate.lstat()
        except OSError:
            adjacent = None
        if adjacent is not None:
            if stat.S_ISLNK(adjacent.st_mode):
                raise LinuxArtifactGateError(
                    "artifact cosign public key traverses a symbolic link."
                )
            artifact_public_key = _secure_regular_repo_path(
                public_key_raw, "Linux artifact cosign public key"
            )
            adjacent_snapshot = _snapshot_artifact(
                artifact_public_key, "Linux artifact cosign public key"
            )
            try:
                if adjacent_snapshot.digest != key_snapshot.digest:
                    raise LinuxArtifactGateError(
                        "artifact cosign public key does not match the reviewed trust anchor."
                    )
            finally:
                adjacent_snapshot.close()
        snapshot.ensure_bound()
        bundle_snapshot.ensure_bound()
        key_snapshot.ensure_bound()
        _require_owner_cosign_trust_anchor()
        if key_snapshot.digest != OWNER_COSIGN_TRUST_ANCHOR_SHA256:
            raise LinuxArtifactGateError(
                "artifact cosign public key does not match the reviewed trust anchor."
            )
        try:
            with linux_release_signing.open_authenticated_cosign() as cosign_fd:
                executable = linux_release_signing._proc_fd_path(cosign_fd, "Cosign execution")
                artifact_reference = linux_release_signing._proc_fd_path(
                    snapshot.fd, "Linux artifact verification"
                )
                key_reference = linux_release_signing._proc_fd_path(
                    key_snapshot.fd, "Linux trust-anchor verification"
                )
                bundle_reference = linux_release_signing._proc_fd_path(
                    bundle_snapshot.fd, "Linux Sigstore bundle verification"
                )
                completed = _run_bounded_subprocess(
                    [
                        executable,
                        "verify-blob",
                        artifact_reference,
                        "--key",
                        key_reference,
                        "--bundle",
                        bundle_reference,
                        "--offline",
                        "--insecure-ignore-tlog",
                    ],
                    cwd=ROOT,
                    pass_fds=(
                        cosign_fd,
                        snapshot.fd,
                        key_snapshot.fd,
                        bundle_snapshot.fd,
                    ),
                    label="local-key Sigstore verification",
                )
        except linux_release_signing.SigningError as exc:
            raise _wrap_signing_error(exc) from exc
        key_snapshot.reject_origin_swap()
        key_snapshot.rehash()
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise LinuxArtifactGateError(f"local-key Sigstore verification failed: {detail}")
    finally:
        try:
            snapshot.rehash()
            bundle_snapshot.rehash()
            bundle_snapshot.reject_origin_swap()
            key_snapshot.rehash()
            key_snapshot.reject_origin_swap()
        finally:
            key_snapshot.close()


def _verify_signature(snapshot: AuthenticatedSnapshot) -> AuthenticatedSnapshot:
    _require_owner_cosign_trust_anchor()
    root = ROOT.resolve(strict=True)
    bundle_raw = snapshot.origin.relative_to(root).as_posix() + ".sigstore.json"
    try:
        bundle = _secure_regular_repo_path(bundle_raw, "Linux Sigstore bundle")
    except LinuxArtifactGateError as exc:
        if "is missing" in str(exc):
            raise _owner_environment_blocker(
                "no owner-issued Sigstore bundle is bound to the exact Linux package"
            ) from exc
        raise
    bundle_snapshot = _snapshot_artifact(bundle, "Linux Sigstore bundle")
    try:
        _validate_standard_bundle_snapshot(bundle_snapshot)
        _run_cosign(snapshot, bundle_snapshot)
        return bundle_snapshot
    except BaseException:
        try:
            snapshot.rehash()
            bundle_snapshot.rehash()
            bundle_snapshot.reject_origin_swap()
        finally:
            bundle_snapshot.close()
        raise


def _retain_evidence_snapshot(
    value: object, label: str
) -> AuthenticatedSnapshot:
    if isinstance(value, AuthenticatedSnapshot):
        try:
            value.reject_origin_swap()
            value.rehash()
            return value
        except BaseException:
            value.close()
            raise
    if isinstance(value, pathlib.Path):
        try:
            resolved = value.resolve(strict=True)
        except OSError as exc:
            raise LinuxArtifactGateError(f"{label} is unavailable for custody.") from exc
        retained = _snapshot_artifact(resolved, label)
        try:
            retained.reject_origin_swap()
            retained.rehash()
            return retained
        except BaseException:
            retained.close()
            raise
    raise LinuxArtifactGateError(
        f"{label} verifier did not return descriptor-bound evidence custody."
    )


class _BuildProvenanceCustody(tuple):
    def __new__(
        cls,
        receipt: AuthenticatedSnapshot,
        source_freeze_receipt: AuthenticatedSnapshot,
    ):
        custody = super().__new__(cls, (receipt, source_freeze_receipt))
        custody._transferred = False
        custody._closed = False
        return custody

    def _revalidate(self) -> None:
        if self._closed or self._transferred:
            raise LinuxArtifactGateError("build provenance custody is unavailable.")
        for snapshot in self:
            snapshot.reject_origin_swap()
            snapshot.rehash()

    def transfer(self) -> tuple[AuthenticatedSnapshot, ...]:
        self._revalidate()
        self._transferred = True
        return tuple(self)

    def resolve(self) -> pathlib.Path:
        self._revalidate()
        return self[0].origin.resolve(strict=True)

    def close(self) -> None:
        if self._closed or self._transferred:
            return
        self._closed = True
        _close_retained_snapshots(tuple(self))

    def __copy__(self):
        raise LinuxArtifactGateError("build provenance custody cannot be copied.")

    def __deepcopy__(self, memo):
        raise LinuxArtifactGateError(
            "build provenance custody cannot be deep-copied."
        )

    def __reduce_ex__(self, protocol):
        raise LinuxArtifactGateError(
            "build provenance custody cannot be serialized."
        )

    def __del__(self) -> None:
        if getattr(self, "_closed", True) or getattr(self, "_transferred", True):
            return
        try:
            self.close()
        except BaseException:
            pass


def _retain_build_provenance_evidence(
    value: object, label: str
) -> tuple[AuthenticatedSnapshot, ...]:
    if isinstance(value, _BuildProvenanceCustody):
        if len(value) != 2 or any(
            not isinstance(item, AuthenticatedSnapshot) for item in value
        ):
            raise LinuxArtifactGateError(
                f"{label} verifier returned incomplete descriptor custody."
            )
        return value.transfer()
    return (_retain_evidence_snapshot(value, label),)


def _close_retained_snapshots(
    snapshots: Iterable[AuthenticatedSnapshot],
) -> None:
    failure: BaseException | None = None
    for snapshot in reversed(tuple(snapshots)):
        try:
            snapshot.reject_origin_swap()
            snapshot.rehash()
        except BaseException as exc:
            if failure is None:
                failure = exc
        try:
            snapshot.close()
        except BaseException as exc:
            if failure is None:
                failure = exc
    if failure is not None:
        raise failure


def _candidate_build_receipts() -> Iterable[pathlib.Path]:
    root = ROOT.resolve(strict=True) / ".artifacts/release-build-receipts/linux"
    if not root.is_dir() or root.is_symlink():
        return ()
    candidates: list[pathlib.Path] = []
    for directory, names, files in os.walk(root, followlinks=False):
        directory_path = pathlib.Path(directory)
        names[:] = [
            name
            for name in names
            if not (directory_path / name).is_symlink()
        ]
        if "LINUX_BUILD_RECEIPT.json" in files:
            candidate = directory_path / "LINUX_BUILD_RECEIPT.json"
            try:
                info = candidate.lstat()
            except OSError:
                continue
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
            ):
                continue
            candidates.append(candidate)
    return tuple(sorted(candidates))


def _remote_attestation_field(record: object) -> set[str]:
    # A remote-attested receipt (tools/release_remote_build.py finish) carries one
    # more block, remote_attestation. freeze.verify_build_receipt requires it exactly
    # when the producer ran remotely, so this key check only has to admit it.
    if type(record) is dict and "remote_attestation" in record:
        return {"remote_attestation"}
    return set()


def _load_receipt_record(path: pathlib.Path) -> dict[str, object] | None:
    fd = -1
    try:
        fd = _bind_repo_file(path, "Linux build receipt")
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
        ):
            return None
        payload = os.pread(fd, info.st_size, 0)
        if len(payload) != info.st_size:
            return None
        try:
            record = _exact_json(payload, "Linux build receipt")
            _require_exact_keys(
                record,
                {
                    "schema_version", "contract", "release", "platform",
                    "begun_utc", "finished_utc", "build_begin_receipt",
                    "build_attempt", "release_input_index", "platform_manifest",
                    "shared_revision", "producer", "toolchain", "source_freeze",
                    "toolchain_custody", "artifact", "sha256_anchor",
                    "publication_authorized",
                }
                | _remote_attestation_field(record),
                "Linux build receipt",
            )
        except LinuxArtifactGateError as exc:
            raise LinuxArtifactGateError(
                f"Linux build receipt does not bind the artifact: {exc}"
            ) from exc
    except LinuxArtifactGateError as exc:
        message = str(exc)
        if "duplicate JSON key" in message:
            raise
        if any(
            marker in message
            for marker in (
                "does not bind the artifact",
                "symlink ancestor",
                "symbolic link",
                "parent path was swapped",
                "was replaced",
                "outside the bound Linux gate root",
            )
        ):
            raise
        return None
    except (OSError, ValueError, UnicodeError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(record, dict):
        return None
    return record


def _snapshot_origin_path(snapshot: AuthenticatedSnapshot) -> pathlib.Path:
    origin = getattr(snapshot, "origin", None)
    if not isinstance(origin, pathlib.Path):
        raise LinuxArtifactGateError(
            "descriptor-bound immutable artifact snapshot origin is required "
            "for receipt verification."
        )
    snapshot.ensure_bound()
    snapshot.reject_origin_swap()
    return origin


def _receipt_matches_snapshot_identity(
    record: object, snapshot: AuthenticatedSnapshot, target: str
) -> bool:
    if not isinstance(record, dict):
        return False
    artifact = record.get("artifact")
    toolchain = record.get("toolchain")
    index = record.get("release_input_index")
    origin = snapshot.origin
    if (
        not isinstance(origin, pathlib.Path)
        or not isinstance(artifact, dict)
        or not isinstance(toolchain, dict)
        or not isinstance(index, dict)
    ):
        return False
    return (
        artifact.get("name") == origin.name
        and artifact.get("size_bytes") == snapshot.size
        and artifact.get("modified_time_ns") == snapshot.origin_identity[6]
        and artifact.get("sha256") == snapshot.digest
        and record.get("release") == CANONICAL_RELEASE
        and record.get("platform") == "linux"
        and toolchain.get("target") == target
    )


def _require_receipt_transaction_binding(
    snapshot: AuthenticatedSnapshot,
    target: str,
    record: dict[str, object],
    result: object,
) -> None:
    if not isinstance(result, dict):
        raise LinuxArtifactGateError(
            "Linux build receipt verifier did not return a binding result."
        )
    expected_release = _linux_release_stamp()
    producer = record.get("producer")
    source_freeze_ref = record.get("source_freeze")
    toolchain_custody = record.get("toolchain_custody")
    begin_ref = record.get("build_begin_receipt")
    toolchain = record.get("toolchain")
    allowed_targets = freeze.PLATFORM_ALLOWED_TARGETS.get("linux", ())
    if (
        result.get("ok") is not True
        or result.get("kind") != "build-receipt"
        or result.get("platform") != "linux"
        or result.get("release") != CANONICAL_RELEASE
        or result.get("release") != expected_release
        or result.get("release") != record.get("release")
        or record.get("release") != CANONICAL_RELEASE
        or result.get("artifact_sha256") != snapshot.digest
        or result.get("artifact_size_bytes") != snapshot.size
        or result.get("begun_utc") != record.get("begun_utc")
        or result.get("finished_utc") != record.get("finished_utc")
        or not isinstance(result.get("receipt_sha256"), str)
        or not isinstance(result.get("shared_revision"), str)
        or not isinstance(result.get("platform_manifest_sha256"), str)
        or not isinstance(result.get("artifact_input_fingerprint_sha256"), str)
        or record.get("platform") != "linux"
        or record.get("publication_authorized") is not False
        or not isinstance(toolchain, dict)
        or toolchain.get("target") != target
        or target not in allowed_targets
        or not isinstance(producer, dict)
        or producer.get("path") != freeze.PLATFORM_BUILD_PRODUCERS["linux"]
        or not isinstance(producer.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(producer.get("sha256"))) is None
        or not isinstance(source_freeze_ref, dict)
        or set(source_freeze_ref) != freeze.CUSTODY_BINDING_KEYS
        or not isinstance(toolchain_custody, dict)
        or set(toolchain_custody) != freeze.CUSTODY_BINDING_KEYS
        or not isinstance(begin_ref, dict)
        or set(begin_ref) != {"path", "sha256"}
        or not isinstance(begin_ref.get("path"), str)
        or not str(begin_ref.get("path")).startswith(".artifacts/")
        or not isinstance(begin_ref.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(begin_ref.get("sha256"))) is None
    ):
        raise LinuxArtifactGateError(
            "Linux build receipt does not bind exact artifact digest, architecture, "
            "release, producer, source-freeze, dependency/toolchain custody, and "
            "transaction continuity."
        )


def _verify_build_provenance(
    snapshot: AuthenticatedSnapshot, target: str
) -> _BuildProvenanceCustody:
    allowed_targets = freeze.PLATFORM_ALLOWED_TARGETS.get("linux", ())
    if target not in allowed_targets:
        raise LinuxArtifactGateError(
            f"unsupported exact Linux receipt architecture target: {target}"
        )
    root = ROOT.resolve(strict=True)
    origin = _snapshot_origin_path(snapshot)
    valid: list[tuple[AuthenticatedSnapshot, AuthenticatedSnapshot]] = []
    for receipt in _candidate_build_receipts():
        record = _load_receipt_record(receipt)
        if record is None or not _receipt_matches_snapshot_identity(
            record, snapshot, target
        ):
            continue
        receipt_snapshot: AuthenticatedSnapshot | None = None
        source_freeze_snapshot: AuthenticatedSnapshot | None = None
        try:
            receipt_snapshot = _snapshot_artifact(receipt, "Linux build receipt")
            rebound = _exact_json(
                os.pread(receipt_snapshot.fd, receipt_snapshot.size, 0),
                "Linux build receipt",
            )
            _require_exact_keys(
                rebound,
                {
                    "schema_version", "contract", "release", "platform",
                    "begun_utc", "finished_utc", "build_begin_receipt",
                    "build_attempt", "release_input_index", "platform_manifest",
                    "shared_revision", "producer", "toolchain", "source_freeze",
                    "toolchain_custody", "artifact", "sha256_anchor",
                    "publication_authorized",
                }
                | _remote_attestation_field(rebound),
                "Linux build receipt",
            )
            if not _receipt_matches_snapshot_identity(
                rebound, snapshot, target
            ):
                raise LinuxArtifactGateError(
                    "Linux build receipt changed while descriptor custody was bound."
                )
            record = rebound
            source_freeze_ref = record.get("source_freeze")
            if type(source_freeze_ref) is not dict:
                raise LinuxArtifactGateError(
                    "Linux build receipt is missing source-freeze custody."
                )
            _require_exact_keys(
                source_freeze_ref,
                set(freeze.CUSTODY_BINDING_KEYS),
                "Linux build receipt source-freeze custody",
            )
            source_reference = source_freeze_ref.get("path")
            if type(source_reference) is not str or not source_reference:
                raise LinuxArtifactGateError(
                    "Linux build receipt source-freeze custody path is invalid."
                )
            source_candidate = pathlib.Path(source_reference)
            external_source = source_candidate.is_absolute()
            if external_source:
                if (
                    "\\" in source_reference
                    or "\x00" in source_reference
                    or any(part in {"", ".", ".."} for part in source_candidate.parts[1:])
                ):
                    raise LinuxArtifactGateError(
                        "Linux build receipt source-freeze custody absolute path is not canonical."
                    )
                source_path = source_candidate
            else:
                source_relative = _require_canonical_relative_path(
                    source_reference,
                    "Linux build receipt source-freeze custody",
                )
                if pathlib.PurePosixPath(source_relative).parts[0] != ".artifacts":
                    raise LinuxArtifactGateError(
                        "Linux build receipt source-freeze custody must stay under .artifacts/."
                    )
                source_path = _secure_regular_repo_path(
                    source_relative, "Linux build receipt source-freeze custody"
                )
            source_freeze_snapshot = _snapshot_artifact(
                source_path,
                "Linux build receipt source-freeze custody",
                allow_absolute_external=external_source,
            )
            if source_freeze_snapshot.digest != source_freeze_ref.get("sha256"):
                raise LinuxArtifactGateError(
                    "Linux build receipt source-freeze custody digest changed."
                )
            index = record.get("release_input_index")
            if not isinstance(index, dict):
                raise LinuxArtifactGateError(
                    "Linux build receipt is missing its release-input index binding."
                )
            index_path = pathlib.Path(str(index.get("path", "")))
            result = freeze.verify_build_receipt(
                root, index_path, "linux", receipt_snapshot.origin, origin
            )
            receipt_snapshot.reject_origin_swap()
            receipt_snapshot.rehash()
            source_freeze_snapshot.reject_origin_swap()
            source_freeze_snapshot.rehash()
        except freeze.DependencyFreezeError as exc:
            _close_retained_snapshots(
                tuple(
                    item
                    for item in (receipt_snapshot, source_freeze_snapshot)
                    if item is not None
                )
            )
            raise LinuxArtifactGateError(
                f"Linux build receipt does not bind the artifact: {exc}"
            ) from exc
        except (OSError, TypeError, ValueError) as exc:
            _close_retained_snapshots(
                tuple(
                    item
                    for item in (receipt_snapshot, source_freeze_snapshot)
                    if item is not None
                )
            )
            raise LinuxArtifactGateError(
                f"Linux build receipt does not bind the artifact: {exc}"
            ) from exc
        except BaseException:
            _close_retained_snapshots(
                tuple(
                    item
                    for item in (receipt_snapshot, source_freeze_snapshot)
                    if item is not None
                )
            )
            raise
        try:
            _require_receipt_transaction_binding(snapshot, target, record, result)
            if receipt_snapshot is None or source_freeze_snapshot is None:
                raise LinuxArtifactGateError(
                    "Linux build receipt descriptor custody is incomplete."
                )
            valid.append((receipt_snapshot, source_freeze_snapshot))
            receipt_snapshot = None
            source_freeze_snapshot = None
        finally:
            pending = tuple(
                item
                for item in (receipt_snapshot, source_freeze_snapshot)
                if item is not None
            )
            if pending:
                _close_retained_snapshots(pending)
    snapshot.reject_origin_swap()
    snapshot.rehash()
    if not valid:
        raise _owner_build_system_blocker(
            "no immutable source/dependency closure binds the exact local Linux package"
        )
    if len(valid) != 1:
        for evidence in valid:
            _close_retained_snapshots(evidence)
        raise LinuxArtifactGateError(
            "Linux build receipt reuse is refused; multiple receipts bind the artifact."
        )
    return _BuildProvenanceCustody(*valid[0])


def _linux_release_stamp() -> str:
    marketing, debian = _canonical_linux_versions()
    stamp = f"{marketing}+{debian.rsplit('-', 1)[-1]}"
    if stamp != CANONICAL_RELEASE:
        raise LinuxArtifactGateError(
            "Linux release stamp is not the canonical 1.0.17+34 identity."
        )
    return stamp


def _owner_build_system_blocker(message: str) -> LinuxArtifactGateError:
    if OWNER_BLOCKED in message:
        return LinuxArtifactGateError(f"owner/build-system blocker: {message}")
    return LinuxArtifactGateError(
        f"owner/build-system blocker: {OWNER_BLOCKED} {message}"
    )


def _owner_environment_blocker(message: str) -> LinuxArtifactGateError:
    if OWNER_BLOCKED in message:
        return LinuxArtifactGateError(f"owner/environment blocker: {message}")
    return LinuxArtifactGateError(
        f"owner/environment blocker: {OWNER_BLOCKED} {message}"
    )


def _owner_pin_blocked(pin: object) -> bool:
    return (
        type(pin) is not str
        or pin == OWNER_BLOCKED
        or re.fullmatch(r"[0-9a-f]{64}", pin) is None
    )


def owner_cosign_trust_anchor_blocked() -> bool:
    return _owner_pin_blocked(OWNER_COSIGN_TRUST_ANCHOR_SHA256)


def owner_upload_receipt_trust_blocked() -> bool:
    return _owner_pin_blocked(OWNER_UPLOAD_RECEIPT_TRUST_SHA256)


def owner_store_tool_pin_blocked(kind: str) -> bool:
    return _owner_pin_blocked(OWNER_STORE_TOOL_SHA256.get(kind))


def _require_owner_cosign_trust_anchor() -> None:
    if owner_cosign_trust_anchor_blocked():
        raise _owner_environment_blocker(
            "reviewed Linux cosign trust anchor remains OWNER-BLOCKED: ABSENT"
        )


def _require_owner_upload_receipt_trust() -> None:
    if (
        owner_upload_receipt_trust_blocked()
        or owner_cosign_trust_anchor_blocked()
        or OWNER_UPLOAD_RECEIPT_TRUST_SHA256 != OWNER_COSIGN_TRUST_ANCHOR_SHA256
    ):
        raise _owner_environment_blocker(
            "Linux owner/upload receipt trust remains OWNER-BLOCKED: ABSENT or "
            "does not equal the reviewed external Sigstore public-key digest"
        )


def _require_owner_store_tool_pins() -> None:
    missing = [
        kind
        for kind in REVIEWED_STORE_TOOLS
        if owner_store_tool_pin_blocked(kind)
    ]
    if missing:
        raise _owner_environment_blocker(
            "authenticated exact Linux store tool pins remain OWNER-BLOCKED: ABSENT: "
            + ", ".join(missing)
        )


def _wrap_signing_error(exc: Exception) -> LinuxArtifactGateError:
    message = str(exc)
    if "owner/environment blocker" in message or "owner/build-system blocker" in message:
        return LinuxArtifactGateError(message)
    if OWNER_BLOCKED in message or "is absent at" in message:
        return _owner_environment_blocker(message)
    return LinuxArtifactGateError(message)


def _load_store_json(relative: str, label: str) -> dict[str, object]:
    _digest, _size, payload = _hash_live_repo_file(relative, label)
    del _digest, _size
    try:
        payload.decode("ascii")
    except UnicodeError as suc:
        raise LinuxArtifactGateError(f"{relative} must be ASCII") from suc
    return _exact_json(payload, label)


def _require_listing_protocol(text: str, label: str) -> None:
    if "Winn v3" not in text or "AWG then Xray" not in text:
        raise LinuxArtifactGateError(
            f"{label} must name Winn v3 primary and Winn v1 AWG then Xray fallback."
        )


def obfuscation_receipt_relative(target_id: str) -> str:
    spec = _package_upload_target(target_id)
    architecture = spec["architectures"][0]
    surface = spec["store_surface"]
    return (
        f".artifacts/private-release-symbols/linux/{architecture}/"
        f"{CANONICAL_RELEASE}/manifest-{surface}.json"
    )


def _ascii_listing_text(relative: str, label: str) -> str:
    payload = _hash_live_repo_file(relative, label)[2]
    try:
        return payload.decode("ascii")
    except UnicodeError as suc:
        raise LinuxArtifactGateError(f"{relative} must be ASCII") from suc


def _require_single_line(text: str, label: str) -> str:
    stripped = text.strip()
    if not stripped or "\n" in stripped or "\r" in stripped:
        raise LinuxArtifactGateError(f"{label} must be one ASCII line.")
    return stripped


def _require_bounded_text(text: str, maximum: int, label: str) -> str:
    if len(text) == 0 or len(text) > maximum:
        raise LinuxArtifactGateError(
            f"{label} must stay within the {maximum}-character Linux listing limit."
        )
    return text


def _require_listing_lines(
    text: str, *, maximum_count: int, maximum_chars: int, label: str
) -> list[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or len(lines) > maximum_count:
        raise LinuxArtifactGateError(
            f"{label} must contain 1 to {maximum_count} ASCII lines."
        )
    for line in lines:
        if len(line) > maximum_chars:
            raise LinuxArtifactGateError(
                f"{label} entries must stay within {maximum_chars} characters."
            )
    if len(set(lines)) != len(lines):
        raise LinuxArtifactGateError(f"{label} entries must be unique.")
    return lines


def _reviewed_store_metadata(target_id: str | None = None) -> dict[str, object]:
    if target_id is not None and target_id not in LINUX_PACKAGE_UPLOAD_TARGETS:
        raise LinuxArtifactGateError(
            f"unsupported exact Linux package/upload target: {target_id}"
        )
    files: dict[str, str] = {}
    for name in LINUX_STORE_FILES:
        relative = f"{STORE_METADATA_ROOT}/{name}"
        digest, _size, payload = _hash_live_repo_file(relative, "Linux store metadata")
        try:
            payload.decode("ascii")
        except UnicodeError as suc:
            raise LinuxArtifactGateError(f"{relative} must be ASCII") from suc
        files[relative] = digest
    for relative, label in (
        (METAINFO_RELATIVE, "Linux AppStream metainfo"),
        (DESKTOP_ENTRY_RELATIVE, "Linux desktop entry"),
    ):
        digest, _size, payload = _hash_live_repo_file(relative, label)
        try:
            payload.decode("ascii")
        except UnicodeError as suc:
            raise LinuxArtifactGateError(f"{relative} must be ASCII") from suc
        files[relative] = digest
    privacy = _load_store_json(
        f"{STORE_METADATA_ROOT}/review/privacy_label_manifest.json",
        "Linux privacy label",
    )
    signoff = _load_store_json(
        f"{STORE_METADATA_ROOT}/review/owner_signoff.json",
        "Linux owner signoff",
    )
    candidate = _load_store_json(
        f"{STORE_METADATA_ROOT}/artifacts/release_candidate.json",
        "Linux release candidate",
    )
    _require_exact_keys(
        privacy,
        {
            "schema_version", "contract", "canonical_release",
            "appstream_version", "debian_version", "application_label",
            "store_listing_name", "privacy_policy_url", "form_factor",
            "camouflage", "tracking", "data_collected", "data_shared",
            "listing_screenshot_inventory", "private_symbols_uploaded",
            "appimage_upload_target", "collected_categories", "not_collected",
            "tunnel_protocol",
        },
        "Linux privacy label",
    )
    _require_exact_keys(
        signoff,
        {
            "schema_version", "contract", "canonical_release",
            "appstream_version", "debian_version", "form_factor",
            "submission_approved", "upload_authorized",
            "appimage_upload_authorized", "listing_screenshot_inventory",
            "blockers",
        },
        "Linux owner signoff",
    )
    _require_exact_keys(
        candidate,
        {
            "schema_version", "contract", "canonical_release",
            "appstream_version", "debian_version", "form_factor",
            "candidate_set_status", "arm64_targets_status",
            "required_artifact_kinds", "targets", "pending_required_targets",
            "deb", "appimage", "private_symbols", "obfuscation_receipts",
            "required_upload_targets", "tunnel_protocol",
        },
        "Linux release candidate",
    )
    listing = _ascii_listing_text(
        f"{STORE_METADATA_ROOT}/metadata/en-US/full_description.txt",
        "Linux listing",
    )
    notes = _ascii_listing_text(
        f"{STORE_METADATA_ROOT}/review/distribution_notes.txt",
        "Linux distribution notes",
    )
    title = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/title.txt",
            "Linux title",
        ),
        "Linux title",
    )
    short = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/short_description.txt",
            "Linux short description",
        ),
        "Linux short description",
    )
    whats_new = _ascii_listing_text(
        f"{STORE_METADATA_ROOT}/metadata/en-US/whats_new.txt",
        "Linux what's new",
    )
    features = _require_listing_lines(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/features.txt",
            "Linux features",
        ),
        maximum_count=LINUX_FEATURE_MAX_COUNT,
        maximum_chars=LINUX_FEATURE_MAX_CHARS,
        label="Linux features",
    )
    search_terms = _require_listing_lines(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/search_terms.txt",
            "Linux search terms",
        ),
        maximum_count=LINUX_SEARCH_TERM_MAX_COUNT,
        maximum_chars=LINUX_SEARCH_TERM_MAX_CHARS,
        label="Linux search terms",
    )
    copyright_line = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/copyright.txt",
            "Linux copyright",
        ),
        "Linux copyright",
    )
    support_url = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/support_url.txt",
            "Linux support URL",
        ),
        "Linux support URL",
    )
    privacy_url = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/privacy_url.txt",
            "Linux privacy URL",
        ),
        "Linux privacy URL",
    )
    website_url = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/website_url.txt",
            "Linux website URL",
        ),
        "Linux website URL",
    )
    metainfo = _ascii_listing_text(METAINFO_RELATIVE, "Linux AppStream metainfo")
    desktop = _ascii_listing_text(DESKTOP_ENTRY_RELATIVE, "Linux desktop entry")
    _require_listing_protocol(listing, "Linux listing")
    _require_listing_protocol(notes, "Linux distribution notes")
    _require_listing_protocol(short, "Linux short description")
    _require_listing_protocol(whats_new, "Linux what's new")
    _require_listing_protocol("\n".join(features), "Linux features")
    _require_listing_protocol(metainfo, "Linux AppStream metainfo")
    _require_bounded_text(title, LINUX_TITLE_MAX, "Linux title")
    _require_bounded_text(short, LINUX_SHORT_DESCRIPTION_MAX, "Linux short description")
    _require_bounded_text(listing, LINUX_FULL_DESCRIPTION_MAX, "Linux listing")
    _require_bounded_text(whats_new, LINUX_WHATS_NEW_MAX, "Linux what's new")
    if title != EXPECTED_PRODUCT_NAME:
        raise LinuxArtifactGateError("Linux listing title is not Win's VPN")
    if "AppImage" not in listing or "not an AppImage" not in listing:
        raise LinuxArtifactGateError(
            "Linux listing must name that AppImage is not a current upload target."
        )
    if copyright_line != LINUX_COPYRIGHT:
        raise LinuxArtifactGateError("Linux copyright is not the canonical 1.0.17+34 line.")
    if (
        privacy_url != LINUX_PRIVACY_POLICY_URL
        or support_url != LINUX_SUPPORT_URL
        or website_url != LINUX_WEBSITE_URL
    ):
        raise LinuxArtifactGateError(
            "Linux listing URLs are not the canonical privacy, support, and website values."
        )
    if EXPECTED_PRODUCT_NAME.casefold() in " ".join(search_terms).casefold():
        raise LinuxArtifactGateError(
            "Linux search terms must not repeat the product name."
        )
    if (
        f'<release version="{CANONICAL_PRODUCT_VERSION}"' not in metainfo
        or CANONICAL_DEBIAN_VERSION not in metainfo
        or 'id>org.winsvpn.app</id>' not in metainfo
    ):
        raise LinuxArtifactGateError(
            "Linux AppStream metadata is not the canonical 1.0.17+34 identity."
        )
    if f"Name={EXPECTED_PRODUCT_NAME}" not in desktop:
        raise LinuxArtifactGateError("Linux desktop entry name is not Win's VPN")
    protocol = privacy.get("tunnel_protocol")
    candidate_protocol = candidate.get("tunnel_protocol")
    symbols = candidate.get("private_symbols")
    targets = candidate.get("targets")
    deb = candidate.get("deb")
    appimage = candidate.get("appimage")
    obfuscation_receipts = candidate.get("obfuscation_receipts")
    expected_obfuscation = {
        target: obfuscation_receipt_relative(target)
        for target in REQUIRED_LINUX_UPLOAD_TARGETS
    }
    if (
        privacy.get("schema_version") != 1
        or privacy.get("contract") != "winsvpn-linux-privacy-label-v1"
        or privacy.get("canonical_release") != CANONICAL_RELEASE
        or privacy.get("appstream_version") != CANONICAL_PRODUCT_VERSION
        or privacy.get("debian_version") != CANONICAL_DEBIAN_VERSION
        or privacy.get("application_label") != EXPECTED_PRODUCT_NAME
        or privacy.get("store_listing_name") != EXPECTED_PRODUCT_NAME
        or privacy.get("privacy_policy_url") != LINUX_PRIVACY_POLICY_URL
        or privacy.get("form_factor") != "linux-x64"
        or privacy.get("camouflage") is not False
        or privacy.get("tracking") is not False
        or privacy.get("data_collected") is not True
        or privacy.get("data_shared") is not False
        or privacy.get("listing_screenshot_inventory") != "owner-blocked"
        or privacy.get("private_symbols_uploaded") is not False
        or privacy.get("appimage_upload_target") is not False
        or privacy.get("collected_categories") != LINUX_COLLECTED_CATEGORIES
        or privacy.get("not_collected") != LINUX_NOT_COLLECTED_CATEGORIES
        or type(protocol) is not dict
        or protocol.get("executed_on") != LINUX_TUNNEL_PROTOCOL["executed_on"]
        or protocol.get("primary") != LINUX_TUNNEL_PROTOCOL["primary"]
        or protocol.get("fallback") != LINUX_TUNNEL_PROTOCOL["fallback"]
        or protocol.get("required_local_engines")
        != LINUX_TUNNEL_PROTOCOL["required_local_engines"]
        or protocol.get("required_native_host")
        != LINUX_TUNNEL_PROTOCOL["required_native_host"]
    ):
        raise LinuxArtifactGateError(
            "Linux privacy label is not the canonical 1.0.17+34 contract."
        )
    if (
        signoff.get("schema_version") != 1
        or signoff.get("contract") != "winsvpn-linux-owner-signoff-v1"
        or signoff.get("canonical_release") != CANONICAL_RELEASE
        or signoff.get("appstream_version") != CANONICAL_PRODUCT_VERSION
        or signoff.get("debian_version") != CANONICAL_DEBIAN_VERSION
        or signoff.get("form_factor") != "linux-x64"
        or signoff.get("submission_approved") is not False
        or signoff.get("upload_authorized") is not False
        or signoff.get("appimage_upload_authorized") is not False
        or signoff.get("listing_screenshot_inventory") != "owner-blocked"
        or signoff.get("blockers") != LINUX_OWNER_SIGNOFF_BLOCKERS
    ):
        raise LinuxArtifactGateError(
            "Linux owner signoff is not the canonical 1.0.17+34 contract."
        )
    if (
        candidate.get("schema_version") != 1
        or candidate.get("contract") != "winsvpn-linux-release-candidate-v1"
        or candidate.get("canonical_release") != CANONICAL_RELEASE
        or candidate.get("appstream_version") != CANONICAL_PRODUCT_VERSION
        or candidate.get("debian_version") != CANONICAL_DEBIAN_VERSION
        or candidate.get("form_factor") != "linux-x64"
        or candidate.get("candidate_set_status") != "no_current_candidate"
        or candidate.get("arm64_targets_status") != "pending-owner-evidence"
        or type(targets) is not dict
        or set(targets) != set(LINUX_X64_CANDIDATE_TARGETS)
        or type(symbols) is not dict
        or symbols.get("x64")
        != ".artifacts/private-release-symbols/linux/x64/1.0.17+34"
        or symbols.get("arm64")
        != ".artifacts/private-release-symbols/linux/arm64/1.0.17+34"
        or symbols.get("uploaded") is not False
        or type(deb) is not dict
        or deb.get("upload_target") is not False
        or deb.get("separate_cross_store_target") is not False
        or deb.get("derived_from") != "linux-x64-package"
        or deb.get("canonical_release") != CANONICAL_RELEASE
        or deb.get("debian_version") != CANONICAL_DEBIAN_VERSION
        or deb.get("architecture") != "amd64"
        or deb.get("filename") != LINUX_DEB_FILENAME
        or deb.get("path") != LINUX_DEB_PATH
        or deb.get("produced") is not False
        or deb.get("upload_performed") is not False
        or deb.get("publication_authorized") is not False
        or type(appimage) is not dict
        or appimage.get("upload_target") is not False
        or appimage.get("production_allowed") is not False
        or appimage.get("canonical_release") != CANONICAL_RELEASE
        or appimage.get("architecture") != "x64"
        or appimage.get("filename") != LINUX_APPIMAGE_FILENAME
        or LINUX_APPIMAGE_UPLOAD_TARGET is not False
        or type(obfuscation_receipts) is not dict
        or obfuscation_receipts != expected_obfuscation
        or type(candidate_protocol) is not dict
        or candidate_protocol.get("executed_on") != LINUX_TUNNEL_PROTOCOL["executed_on"]
        or candidate_protocol.get("primary") != LINUX_TUNNEL_PROTOCOL["primary"]
        or candidate_protocol.get("fallback") != LINUX_TUNNEL_PROTOCOL["fallback"]
    ):
        raise LinuxArtifactGateError(
            "Linux release candidate is not the canonical 1.0.17+34 contract."
        )
    for candidate_target, expected_name, expected_arch, expected_surface, expected_path in (
        (
            "linux-x64-package",
            "wins-vpn-linux-x64.tar.gz",
            "x64",
            "website-tarball",
            LINUX_TARBALL_PATH,
        ),
        (
            "linux-flathub-manifest",
            "org.winsvpn.app.json",
            "x64",
            "flathub-separate-manifest",
            ".artifacts/linux/org.winsvpn.app.json",
        ),
        (
            "linux-snap-manifest",
            "snapcraft.yaml",
            "x64",
            "snap-separate-manifest",
            ".artifacts/linux/snapcraft.yaml",
        ),
    ):
        record = targets.get(candidate_target)
        if (
            type(record) is not dict
            or record.get("filename") != expected_name
            or record.get("architecture") != expected_arch
            or record.get("surface") != expected_surface
            or record.get("path") != expected_path
            or record.get("produced") is not False
            or record.get("upload_performed") is not False
            or record.get("publication_authorized") is not False
        ):
            raise LinuxArtifactGateError(
                "Linux release candidate is not the canonical 1.0.17+34 contract."
            )
    if "winn-datapath" not in notes or LINUX_TUNNEL_PROTOCOL["required_native_host"] not in notes:
        raise LinuxArtifactGateError(
            "Linux distribution notes omit the native tunnel host or browser host."
        )
    if LINUX_APPIMAGE_FILENAME not in notes or LINUX_DEB_FILENAME not in notes:
        raise LinuxArtifactGateError(
            "Linux distribution notes omit the AppImage or Debian 1.0.17+34 identity."
        )
    payload = {
        "canonical_release": CANONICAL_RELEASE,
        "appstream_version": CANONICAL_PRODUCT_VERSION,
        "debian_version": CANONICAL_DEBIAN_VERSION,
        "form": "linux-x64",
        "submission_approved": False,
        "upload_authorized": False,
        "appimage_upload_target": False,
        "listing_screenshot_inventory": "owner-blocked",
        "private_symbols_uploaded": False,
        "obfuscation_receipts": expected_obfuscation,
        "tunnel_protocol": LINUX_TUNNEL_PROTOCOL,
        "files": files,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    payload["sha256"] = _sha256_bytes(encoded)
    return payload


def _bind_obfuscation_receipt(
    target_id: str,
    reviewed: Mapping[str, object],
    *,
    artifact_sha256: str,
    artifact_bytes: int,
    artifact_name: str,
) -> None:
    receipts = reviewed.get("obfuscation_receipts")
    if type(receipts) is not dict:
        raise LinuxArtifactGateError(
            f"{target_id} store metadata is missing obfuscation receipt paths."
        )
    relative = receipts.get(target_id)
    expected = obfuscation_receipt_relative(target_id)
    if relative != expected:
        raise LinuxArtifactGateError(
            f"{target_id} obfuscation receipt path is not the current 1.0.17+34 layout."
        )
    _require_canonical_relative_path(relative, f"{target_id} obfuscation receipt")
    if pathlib.PurePosixPath(str(relative)).parts[0] != ".artifacts":
        raise LinuxArtifactGateError(
            f"{target_id} obfuscation receipt path must stay under .artifacts/."
        )
    _digest, size, payload = _hash_live_repo_file(
        str(relative), f"{target_id} obfuscation receipt"
    )
    del _digest
    record = _exact_json(payload, f"{target_id} obfuscation receipt")
    _require_exact_keys(
        record,
        {
            "schema_version", "contract", "contract_sha256", "platform",
            "app_version", "build_number", "created_at_utc",
            "private_symbols_not_packaged", "verification", "artifacts",
            "symbols", "target_id",
        },
        f"{target_id} obfuscation receipt",
    )
    artifacts = record.get("artifacts")
    if (
        record.get("schema_version") != 2
        or record.get("contract") != "winsvpn-release-obfuscation-and-secret-free-v2"
        or record.get("platform") != "linux"
        or record.get("app_version") != CANONICAL_PRODUCT_VERSION
        or record.get("build_number") != "34"
        or record.get("target_id") != target_id
        or record.get("private_symbols_not_packaged") is not True
        or type(artifacts) is not list
        or len(artifacts) != 1
        or type(artifacts[0]) is not dict
    ):
        raise LinuxArtifactGateError(
            f"{target_id} obfuscation receipt is not the current 1.0.17+34 Linux identity."
        )
    bound = artifacts[0]
    _require_exact_keys(
        bound,
        {"path", "size", "sha256"},
        f"{target_id} obfuscation artifact",
    )
    path = bound.get("path")
    if (
        type(path) is not str
        or pathlib.PurePosixPath(path).name != artifact_name
        or bound.get("sha256") != artifact_sha256
        or bound.get("size") != artifact_bytes
        or type(bound.get("size")) is not int
        or isinstance(bound.get("size"), bool)
        or size <= 0
    ):
        raise LinuxArtifactGateError(
            f"{target_id} obfuscation receipt was swapped or does not bind the exact candidate bytes."
        )


def _receipt_hex64(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise LinuxArtifactGateError(f"{label} digest is invalid.")
    return value


def _receipt_exact_mapping(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise LinuxArtifactGateError(f"{label} schema fields are invalid.")
    return value


def _receipt_exact_str(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise LinuxArtifactGateError(f"{label} is not exact.")
    return value


def _package_upload_target(target_id: str) -> dict[str, object]:
    spec = LINUX_PACKAGE_UPLOAD_TARGETS.get(target_id)
    if spec is None:
        raise LinuxArtifactGateError(
            f"unsupported exact Linux package/upload target: {target_id}"
        )
    return spec


def _receipt_document(record: object, label: str) -> dict[str, object]:
    if type(record) is bytes:
        return _exact_json(record, label)
    if type(record) is dict:
        _require_finite_json_tree(record, label)
        return dict(record)
    raise LinuxArtifactGateError(f"{label} must be exact JSON bytes or one JSON object.")


def _require_finite_json_tree(value: object, label: str) -> None:
    if type(value) is float and not math.isfinite(value):
        raise LinuxArtifactGateError(f"{label} contains a non-finite number.")
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise LinuxArtifactGateError(f"{label} contains a non-string key.")
        for item in value.values():
            _require_finite_json_tree(item, label)
    elif type(value) in {list, tuple}:
        for item in value:
            _require_finite_json_tree(item, label)


def _require_canonical_relative_path(path: object, label: str) -> str:
    if type(path) is not str or not path or "\\" in path:
        raise LinuxArtifactGateError(
            f"{label} must be one canonical repository-relative path."
        )
    relative = pathlib.PurePosixPath(path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise LinuxArtifactGateError(
            f"{label} must be one canonical repository-relative path."
        )
    return path


def _bound_receipt_digest_pairs(
    target_id: str, record: Mapping[str, object]
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    artifact = record.get("artifact")
    build_receipt = record.get("build_receipt")
    producer = record.get("producer")
    descriptor = record.get("descriptor")
    source = record.get("source_freeze")
    hardening = record.get("obfuscation_privacy")
    attestation = record.get("winn3_descriptor_ring_attestation")
    if type(artifact) is dict:
        pairs.append(
            (
                f"{target_id}.artifact",
                _receipt_hex64(artifact.get("sha256"), f"{target_id} artifact"),
            )
        )
    if type(build_receipt) is dict:
        pairs.append(
            (
                f"{target_id}.build_receipt",
                _receipt_hex64(build_receipt.get("sha256"), f"{target_id} build receipt"),
            )
        )
    if type(producer) is dict:
        pairs.append(
            (
                f"{target_id}.producer",
                _receipt_hex64(producer.get("sha256"), f"{target_id} producer"),
            )
        )
    if type(descriptor) is dict:
        pairs.append(
            (
                f"{target_id}.descriptor",
                _receipt_hex64(descriptor.get("sha256"), f"{target_id} descriptor"),
            )
        )
    if type(source) is dict:
        pairs.append(
            (
                f"{target_id}.source_freeze",
                _receipt_hex64(source.get("sha256"), f"{target_id} source freeze"),
            )
        )
    if type(hardening) is dict:
        pairs.append(
            (
                f"{target_id}.obfuscation_privacy",
                _receipt_hex64(
                    hardening.get("sha256"), f"{target_id} obfuscation/privacy"
                ),
            )
        )
    if type(attestation) is dict:
        pairs.append(
            (
                f"{target_id}.winn3_descriptor_ring_attestation",
                _receipt_hex64(
                    attestation.get("sha256"),
                    f"{target_id} Winn3 descriptor ring attestation",
                ),
            )
        )
    return pairs


def _unique_receipt_digest_pairs(
    target_id: str, record: Mapping[str, object]
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for field in UNIQUE_UPLOAD_RECEIPT_DIGEST_FIELDS:
        value = record.get(field)
        if type(value) is dict:
            pairs.append(
                (
                    f"{target_id}.{field}",
                    _receipt_hex64(value.get("sha256"), f"{target_id} {field}"),
                )
            )
    return pairs


def _bind_shared_upload_paths(
    shared: dict[str, tuple[str, str]], target_id: str, record: Mapping[str, object]
) -> None:
    for field in SHARED_UPLOAD_RECEIPT_PATH_FIELDS:
        value = record.get(field)
        if type(value) is not dict:
            continue
        path = value.get("path")
        digest = _receipt_hex64(value.get("sha256"), f"{target_id} {field}")
        path = _require_canonical_relative_path(path, f"{target_id} {field}")
        previous = shared.get(path)
        if previous is not None and previous[0] != digest:
            raise LinuxArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
            )
        for other_path, (other_digest, other_label) in shared.items():
            if other_digest == digest and other_path != path:
                raise LinuxArtifactGateError(
                    f"receipt reuse is refused: {target_id}.{field} reuses {other_label}"
                )
        shared[path] = (digest, f"{target_id}.{field}")


def _reject_receipt_digest_reuse(pairs: list[tuple[str, str]]) -> None:
    seen: dict[str, str] = {}
    for label, digest in pairs:
        previous = seen.get(digest)
        if previous is not None:
            raise LinuxArtifactGateError(
                f"receipt reuse is refused: {label} reuses {previous}"
            )
        seen[digest] = label


def _hash_live_repo_file(relative: str, label: str) -> tuple[str, int, bytes]:
    try:
        path = _secure_regular_repo_path(relative, label)
    except LinuxArtifactGateError as exc:
        if "is missing" in str(exc):
            raise _owner_environment_blocker(
                "Linux package/upload receipts remain pending without owner evidence: "
                + relative
            ) from exc
        raise
    snapshot = _snapshot_artifact(path, label)
    try:
        snapshot.reject_origin_swap()
        payload = os.pread(snapshot.fd, snapshot.size, 0)
        if len(payload) != snapshot.size or snapshot.rehash() != snapshot.digest:
            raise LinuxArtifactGateError(f"{label} mutated while it was read.")
        snapshot.reject_origin_swap()
        return snapshot.digest, snapshot.size, payload
    finally:
        snapshot.close()


def _require_live_upload_bindings(
    target_id: str, receipt: dict[str, object], spec: dict[str, object]
) -> None:
    artifact = receipt["artifact"]
    artifact_path = str(artifact["path"])
    live_digest, live_size, _payload = _hash_live_repo_file(
        artifact_path, f"{target_id} artifact"
    )
    if live_digest != artifact["sha256"] or live_size != artifact["bytes"]:
        raise LinuxArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
        )
    if spec["kind"] == "DEB":
        sidecar_rel = artifact_path + ".sha256"
        _sidecar_digest, _sidecar_size, sidecar_payload = _hash_live_repo_file(
            sidecar_rel, f"{target_id} checksum sidecar"
        )
        expected_sidecar = f"{live_digest}  {spec['artifact_name']}\n".encode("ascii")
        if sidecar_payload != expected_sidecar:
            raise LinuxArtifactGateError(
                f"{target_id} checksum sidecar does not bind the exact artifact."
            )
    exact_paths = {
        "producer": str(spec["producer"]),
        "descriptor": DESCRIPTOR_RELATIVE,
        "obfuscation_privacy": OBFUSCATION_PRIVACY_RELATIVE,
    }
    for field, expected_path in exact_paths.items():
        record = receipt[field]
        path = str(record["path"])
        if path != expected_path:
            raise LinuxArtifactGateError(f"{target_id} {field} path is not exact.")
        live_digest, _live_size, _payload = _hash_live_repo_file(
            path, f"{target_id} {field}"
        )
        if live_digest != record["sha256"]:
            raise LinuxArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
            )
    for field in ("build_receipt", "source_freeze"):
        record = receipt[field]
        path = str(record["path"])
        if pathlib.PurePosixPath(path).parts[0] != ".artifacts":
            raise LinuxArtifactGateError(
                f"{target_id} {field} path must stay under .artifacts/."
            )
        live_digest, _live_size, payload = _hash_live_repo_file(
            path, f"{target_id} {field}"
        )
        if live_digest != record["sha256"]:
            raise LinuxArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
            )
        if field == "build_receipt":
            build_document = _exact_json(payload, f"{target_id} build receipt")
            _require_exact_keys(
                build_document,
                {
                    "schema_version", "contract", "release", "platform",
                    "begun_utc", "finished_utc", "build_begin_receipt",
                    "build_attempt", "release_input_index", "platform_manifest",
                    "shared_revision", "producer", "toolchain", "source_freeze",
                    "toolchain_custody", "artifact", "sha256_anchor",
                    "publication_authorized",
                },
                f"{target_id} build receipt",
            )
        else:
            source_document = _exact_json(payload, f"{target_id} source freeze")
            _require_exact_keys(
                source_document,
                set(freeze.SOURCE_FREEZE_RECEIPT_KEYS),
                f"{target_id} source freeze",
            )


def _require_required_upload_signatures(receipts: dict[str, dict[str, object]]) -> None:
    for target_id, receipt in receipts.items():
        spec = LINUX_PACKAGE_UPLOAD_TARGETS[target_id]
        if spec["signing_status"] != "required":
            continue
        relative = str(receipt["artifact"]["path"])
        try:
            origin = _secure_regular_repo_path(relative, f"{target_id} signed artifact")
        except LinuxArtifactGateError as exc:
            if "is missing" in str(exc):
                raise _owner_environment_blocker(
                    "Linux package/upload receipts remain pending without owner evidence: "
                    + relative
                ) from exc
            raise
        snapshot = _snapshot_artifact(origin, f"{target_id} signed artifact")
        retained = [snapshot]
        try:
            bundle_snapshot = _retain_evidence_snapshot(
                _verify_signature(snapshot),
                f"{target_id} Linux Sigstore bundle",
            )
            retained.append(bundle_snapshot)
        finally:
            _close_retained_snapshots(retained)


def _winn3_descriptor_ring_attestation_receipt_binding(
    target_id: str, spec: Mapping[str, object] | None = None
) -> dict[str, object]:
    bound = spec if spec is not None else _package_upload_target(target_id)
    identity = REVIEWED_WINN3_DESCRIPTOR_RING_SHA256
    payload = _canonical_winn3_descriptor_ring_attestation(identity)
    kind = bound.get("kind")
    architectures = bound.get("architectures")
    if type(architectures) is not tuple or not architectures:
        raise LinuxArtifactGateError(
            f"{target_id} architecture inventory is not exact."
        )
    if kind == "DEB":
        packaged_path = WINN3_DESCRIPTOR_RING_ATTESTATION_NAME
        verified_artifact = WINN3_DESCRIPTOR_RING_VERIFIED_ARTIFACT
    else:
        store = STORE_MANIFEST_TARGETS.get(target_id)
        if store is None:
            raise LinuxArtifactGateError(
                f"{target_id} Winn3 descriptor ring attestation path is not exact."
            )
        prefix = str(store["payload_prefix"])
        packaged_path = _store_prefixed(
            prefix, STORE_WINN3_DESCRIPTOR_RING_ATTESTATION_RELATIVE
        )
        verified_artifact = _store_prefixed(prefix, str(store["flutter"]["libapp"]))
    return {
        "path": packaged_path,
        "mode": WINN3_DESCRIPTOR_RING_ATTESTATION_MODE,
        "sha256": _sha256_bytes(payload),
        "identity_sha256": identity,
        "architectures": list(architectures),
        "verified_artifact": verified_artifact,
    }


def _bind_winn3_descriptor_ring_attestation_receipt(
    target_id: str, receipt: Mapping[str, object], spec: Mapping[str, object]
) -> None:
    record = _receipt_exact_mapping(
        receipt.get("winn3_descriptor_ring_attestation"),
        set(WINN3_DESCRIPTOR_RING_ATTESTATION_RECEIPT_KEYS),
        f"{target_id} Winn3 descriptor ring attestation",
    )
    expected = _winn3_descriptor_ring_attestation_receipt_binding(target_id, spec)
    path = _require_canonical_relative_path(
        record.get("path"), f"{target_id} Winn3 descriptor ring attestation"
    )
    mode = record.get("mode")
    if type(mode) is not int or isinstance(mode, bool) or mode != expected["mode"]:
        raise LinuxArtifactGateError(
            f"{target_id} Winn3 descriptor ring attestation mode is not exact."
        )
    digest = _receipt_hex64(
        record.get("sha256"), f"{target_id} Winn3 descriptor ring attestation"
    )
    identity = _receipt_hex64(
        record.get("identity_sha256"),
        f"{target_id} reviewed Winn3 descriptor ring identity",
    )
    architectures = record.get("architectures")
    if (
        type(architectures) is not list
        or architectures != expected["architectures"]
        or tuple(architectures) != spec["architectures"]
        or len(architectures) != len(set(architectures))
    ):
        raise LinuxArtifactGateError(
            f"{target_id} Winn3 descriptor ring attestation architecture inventory is not exact."
        )
    verified = _require_canonical_relative_path(
        record.get("verified_artifact"),
        f"{target_id} Winn3 descriptor ring verified artifact",
    )
    if path != expected["path"] or verified != expected["verified_artifact"]:
        raise LinuxArtifactGateError(
            f"{target_id} Winn3 descriptor ring attestation path is not exact."
        )
    if (
        digest != expected["sha256"]
        or identity != expected["identity_sha256"]
        or identity != REVIEWED_WINN3_DESCRIPTOR_RING_SHA256
    ):
        raise LinuxArtifactGateError(
            f"{target_id} Winn3 descriptor ring attestation is stale or unbound."
        )


def _bind_package_identity(
    identity: dict[str, object], spec: dict[str, object], target_id: str
) -> None:
    marketing, debian = _canonical_linux_versions()
    if (
        identity.get("name") != spec["package_name"]
        or identity.get("appstream_version") != marketing
        or identity.get("debian_version") != debian
    ):
        raise LinuxArtifactGateError(
            f"{target_id} package identity is not the current 1.0.17+34 Linux identity."
        )
    if "elf_machine" in spec["identity_keys"]:
        machine = identity.get("elf_machine")
        if type(machine) is not int or isinstance(machine, bool) or machine != spec["elf_machine"]:
            raise LinuxArtifactGateError(
                f"{target_id} architecture inventory is not exact."
            )
    if "elf_machines" in spec["identity_keys"]:
        machines = identity.get("elf_machines")
        expected = spec["elf_machines"]
        if type(machines) is not dict or machines != expected:
            raise LinuxArtifactGateError(
                f"{target_id} architecture inventory is not exact."
            )
        for arch, machine in expected.items():
            actual = machines.get(arch)
            if type(actual) is not int or isinstance(actual, bool) or actual != machine:
                raise LinuxArtifactGateError(
                    f"{target_id} architecture inventory is not exact."
                )



def _receipt_hex128(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{128}", value) is None:
        raise LinuxArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    return value


def _require_utc_timestamp(value: object, label: str) -> datetime.datetime:
    if type(value) is not str or not value:
        raise LinuxArtifactGateError(f"{label} is not an RFC3339 UTC timestamp")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise LinuxArtifactGateError(f"{label} is not an RFC3339 UTC timestamp") from error
    if parsed.tzinfo is None:
        raise LinuxArtifactGateError(f"{label} is not an RFC3339 UTC timestamp")
    return parsed.astimezone(datetime.timezone.utc)


def _canonical_upload_receipt_binding(receipt: Mapping[str, object]) -> str:
    if type(receipt) is not dict or "authentication" not in receipt:
        raise LinuxArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    unsigned = dict(receipt)
    del unsigned["authentication"]
    try:
        payload = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise LinuxArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR) from exc
    return _sha256_bytes(payload)


def _upload_authorization_relative(target_id: str) -> str:
    if target_id not in LINUX_PACKAGE_UPLOAD_TARGETS:
        raise LinuxArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    return (UPLOAD_AUTHORIZATION_ROOT / f"{target_id}.json").as_posix()


def _reject_placeholder_trust_material(material: object) -> None:
    if type(material) is dict:
        for key, value in material.items():
            folded = str(key).casefold()
            if folded in {
                "public_key",
                "issuer_public_key",
                "trust_root",
                "signature",
                "ed25519",
            }:
                raise LinuxArtifactGateError(RECEIPT_PLACEHOLDER_TRUST_ERROR)
            if type(value) is str and folded.endswith("public_key"):
                if (
                    re.fullmatch(r"[0-9a-f]{64}", value) is not None
                    and any(
                        value[:width] * (len(value) // width) == value
                        for width in (2, 4, 8, 16, 32)
                    )
                ):
                    raise LinuxArtifactGateError(RECEIPT_PLACEHOLDER_TRUST_ERROR)
    try:
        dumped = json.dumps(material, ensure_ascii=True).casefold()
    except (TypeError, ValueError) as error:
        raise LinuxArtifactGateError(RECEIPT_PLACEHOLDER_TRUST_ERROR) from error
    for marker in UPLOAD_RECEIPT_PLACEHOLDER_TRUST_MARKERS:
        if marker in dumped:
            raise LinuxArtifactGateError(RECEIPT_PLACEHOLDER_TRUST_ERROR)


def _bind_upload_receipt_authentication(
    target_id: str,
    receipt: Mapping[str, object],
    *,
    artifact_sha256: str,
    artifact_bytes: int,
    architectures: tuple[str, ...],
    release: str,
) -> None:
    raw_auth = receipt.get("authentication")
    _reject_placeholder_trust_material(raw_auth)
    auth = _receipt_exact_mapping(
        raw_auth,
        set(UPLOAD_RECEIPT_AUTH_KEYS),
        f"{target_id} upload authentication",
    )
    if (
        auth.get("contract") != UPLOAD_AUTHORIZATION_CONTRACT
        or auth.get("schema_version") != UPLOAD_AUTHORIZATION_SCHEMA_VERSION
    ):
        raise LinuxArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    relative = _upload_authorization_relative(target_id)
    if auth.get("authority_receipt_path") != relative:
        raise LinuxArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    expected_authority_digest = _receipt_hex64(
        auth.get("authority_receipt_sha256"),
        f"{target_id} upload authority receipt",
    )
    _require_owner_upload_receipt_trust()
    _require_owner_cosign_trust_anchor()
    authority_path = _secure_regular_repo_path(
        relative, f"{target_id} externally authorized upload receipt"
    )
    authority_snapshot = _snapshot_artifact(
        authority_path, f"{target_id} externally authorized upload receipt"
    )
    retained: list[AuthenticatedSnapshot] = [authority_snapshot]
    try:
        if authority_snapshot.digest != expected_authority_digest:
            raise LinuxArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
        authority = _strict_json_object(
            os.pread(authority_snapshot.fd, authority_snapshot.size, 0),
            f"{target_id} externally authorized upload receipt",
        )
        _require_exact_keys(
            authority,
            set(UPLOAD_AUTHORIZATION_KEYS),
            f"{target_id} externally authorized upload receipt",
        )
        issued = _require_utc_timestamp(
            authority.get("issued_at"), f"{target_id} upload issued_at"
        )
        expires = _require_utc_timestamp(
            authority.get("expires_at"), f"{target_id} upload expires_at"
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        if (
            issued > now + datetime.timedelta(seconds=60)
            or expires <= now
            or expires <= issued
            or expires - issued > datetime.timedelta(minutes=15)
        ):
            raise LinuxArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
        authority_architectures = authority.get("architectures")
        if (
            authority.get("contract") != UPLOAD_AUTHORIZATION_CONTRACT
            or authority.get("schema_version") != UPLOAD_AUTHORIZATION_SCHEMA_VERSION
            or authority.get("issuer") != UPLOAD_RECEIPT_ISSUER
            or re.fullmatch(r"[0-9a-f]{64}", str(authority.get("authorization_id"))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(authority.get("nonce"))) is None
            or authority.get("target_id") != target_id
            or type(authority_architectures) is not list
            or tuple(authority_architectures) != architectures
            or authority.get("release") != release
            or authority.get("artifact_sha256") != artifact_sha256
            or type(authority.get("artifact_bytes")) is not int
            or isinstance(authority.get("artifact_bytes"), bool)
            or int(authority.get("artifact_bytes")) != artifact_bytes
            or authority.get("upload_receipt_binding_sha256")
            != _canonical_upload_receipt_binding(receipt)
            or authority.get("publication_authorized") is not False
            or authority.get("upload_attempted") is not False
        ):
            raise LinuxArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
        bundle = _retain_evidence_snapshot(
            _verify_signature(authority_snapshot),
            f"{target_id} upload authorization Sigstore bundle",
        )
        retained.append(bundle)
        authority_snapshot.reject_origin_swap()
        authority_snapshot.rehash()
    except LinuxArtifactGateError:
        raise
    except BaseException as exc:
        raise LinuxArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR) from exc
    finally:
        _close_retained_snapshots(retained)


def bind_package_upload_receipt(
    target_id: str,
    record: Mapping[str, object] | bytes,
    *,
    artifact_sha256: str,
    artifact_bytes: int,
) -> dict[str, object]:
    """Bind one Linux DEB/Snap/Flathub upload receipt to exact 1.0.17+34 bytes."""

    spec = _package_upload_target(target_id)
    receipt = _receipt_exact_mapping(
        _receipt_document(record, f"{target_id} upload receipt"),
        set(PACKAGE_UPLOAD_RECEIPT_KEYS),
        f"{target_id} upload receipt",
    )
    release = _linux_release_stamp()
    if (
        receipt.get("ok") is not True
        or receipt.get("schema_version") != PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION
        or receipt.get("contract") != PACKAGE_UPLOAD_RECEIPT_CONTRACT
        or receipt.get("release") != release
        or receipt.get("target_id") != target_id
        or receipt.get("platform") != spec["platform"]
        or receipt.get("publication_authorized") is not False
        or receipt.get("upload_attempted") is not False
    ):
        raise LinuxArtifactGateError(
            f"{target_id} receipt binding is invalid or changed."
        )
    artifact = _receipt_exact_mapping(
        receipt.get("artifact"), {"path", "sha256", "bytes"}, f"{target_id} artifact"
    )
    path = _require_canonical_relative_path(artifact.get("path"), f"{target_id} artifact")
    filename = pathlib.PurePosixPath(path).name
    suffixes = spec["artifact_suffixes"]
    if filename != spec["artifact_name"] or not any(
        filename.endswith(suffix) for suffix in suffixes
    ):
        raise LinuxArtifactGateError(f"{target_id} artifact type is not allowed.")
    bound_digest = _receipt_hex64(artifact_sha256, f"{target_id} candidate bytes")
    if (
        artifact.get("sha256") != bound_digest
        or type(artifact.get("bytes")) is not int
        or isinstance(artifact.get("bytes"), bool)
        or int(artifact.get("bytes")) != artifact_bytes
        or int(artifact.get("bytes")) <= 0
    ):
        raise LinuxArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
        )
    build_receipt = _receipt_exact_mapping(
        receipt.get("build_receipt"),
        {"path", "sha256", "target"},
        f"{target_id} build receipt",
    )
    _receipt_exact_str(
        build_receipt.get("target"),
        str(spec["build_receipt_target"]),
        f"{target_id} build receipt target",
    )
    _receipt_hex64(build_receipt.get("sha256"), f"{target_id} build receipt")
    producer = _receipt_exact_mapping(
        receipt.get("producer"), {"id", "path", "sha256"}, f"{target_id} producer"
    )
    producer_id = producer.get("id")
    if (
        type(producer_id) is not str
        or producer_id != spec["producer"]
        or producer.get("path") != producer_id
    ):
        raise LinuxArtifactGateError(f"{target_id} producer id is not allowed.")
    _receipt_hex64(producer.get("sha256"), f"{target_id} producer")
    identity = _receipt_exact_mapping(
        receipt.get("package_identity"),
        set(spec["identity_keys"]),
        f"{target_id} package identity",
    )
    _bind_package_identity(identity, spec, target_id)
    architectures = receipt.get("architectures")
    if (
        type(architectures) is not list
        or tuple(architectures) != spec["architectures"]
        or len(architectures) != len(set(architectures))
    ):
        raise LinuxArtifactGateError(
            f"{target_id} architecture inventory is not exact."
        )
    _bind_winn3_descriptor_ring_attestation_receipt(target_id, receipt, spec)
    signing = _receipt_exact_mapping(
        receipt.get("signing"),
        {"contract", "trust_anchor", "status"},
        f"{target_id} signing evidence",
    )
    if (
        signing.get("contract") != spec["signing_contract"]
        or signing.get("status") != spec["signing_status"]
        or signing.get("trust_anchor") != spec["trust_anchor"]
    ):
        raise LinuxArtifactGateError(
            f"{target_id} signing evidence is not release-valid."
        )
    store = _receipt_exact_mapping(
        receipt.get("store_evidence"),
        {"surface", "status", "metadata_sha256"},
        f"{target_id} store evidence",
    )
    reviewed = _reviewed_store_metadata(target_id)
    if (
        store.get("surface") != spec["store_surface"]
        or store.get("status") != "not_uploaded"
        or store.get("metadata_sha256") != reviewed["sha256"]
    ):
        raise LinuxArtifactGateError(f"{target_id} store evidence is not exact.")
    descriptor = _receipt_exact_mapping(
        receipt.get("descriptor"),
        {"path", "sha256"},
        f"{target_id} descriptor binding",
    )
    source = _receipt_exact_mapping(
        receipt.get("source_freeze"),
        {"path", "sha256"},
        f"{target_id} source-freeze binding",
    )
    hardening = _receipt_exact_mapping(
        receipt.get("obfuscation_privacy"),
        {"path", "sha256"},
        f"{target_id} obfuscation/privacy binding",
    )
    for label, relative in (
        ("descriptor", descriptor.get("path")),
        ("source freeze", source.get("path")),
        ("obfuscation/privacy", hardening.get("path")),
        ("build receipt", build_receipt.get("path")),
        ("producer", producer.get("path")),
    ):
        _require_canonical_relative_path(relative, f"{target_id} {label}")
    if descriptor.get("path") != DESCRIPTOR_RELATIVE:
        raise LinuxArtifactGateError(f"{target_id} descriptor path is not exact.")
    if hardening.get("path") != OBFUSCATION_PRIVACY_RELATIVE:
        raise LinuxArtifactGateError(
            f"{target_id} obfuscation/privacy path is not exact."
        )
    _bind_obfuscation_receipt(
        target_id,
        reviewed,
        artifact_sha256=bound_digest,
        artifact_bytes=int(artifact.get("bytes")),
        artifact_name=str(spec["artifact_name"]),
    )
    if pathlib.PurePosixPath(str(source.get("path"))).parts[0] != ".artifacts":
        raise LinuxArtifactGateError(
            f"{target_id} source freeze path must stay under .artifacts/."
        )
    if pathlib.PurePosixPath(str(build_receipt.get("path"))).parts[0] != ".artifacts":
        raise LinuxArtifactGateError(
            f"{target_id} build receipt path must stay under .artifacts/."
        )
    owner = _receipt_exact_mapping(
        receipt.get("owner_authorization"),
        {
            "contract",
            "schema_version",
            "status",
            "credentials_authorized",
            "upload_authorized",
        },
        f"{target_id} owner authorization",
    )
    if (
        owner.get("contract") != OWNER_AUTHORIZATION_CONTRACT
        or owner.get("schema_version") != PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION
        or owner.get("status") != "pending"
        or owner.get("credentials_authorized") is not False
        or owner.get("upload_authorized") is not False
    ):
        raise LinuxArtifactGateError(
            f"{target_id} owner authorization must remain pending without owner evidence."
        )
    _reject_receipt_digest_reuse(_bound_receipt_digest_pairs(target_id, receipt))
    _require_live_upload_bindings(target_id, receipt, spec)
    _bind_upload_receipt_authentication(
        target_id,
        receipt,
        artifact_sha256=bound_digest,
        artifact_bytes=int(artifact.get("bytes")),
        architectures=spec["architectures"],
        release=release,
    )
    return {
        "ok": True,
        "target_id": target_id,
        "release": release,
        "kind": spec["kind"],
        "artifact_sha256": bound_digest,
        "publication_authorized": False,
        "upload_attempted": False,
        "owner_authorization": "pending",
    }


def bind_linux_package_upload_receipts(
    records: Mapping[str, object],
    artifacts: Mapping[str, tuple[str, int]],
) -> dict[str, object]:
    """Bind required DEB, Snap, and Flathub receipts, refusing reuse or approval."""

    if type(records) is not dict or type(artifacts) is not dict:
        raise LinuxArtifactGateError("Linux package/upload receipt set is invalid.")
    parsed: dict[str, dict[str, object]] = {}
    for target_id, record in records.items():
        parsed[str(target_id)] = _receipt_document(
            record, f"{target_id} upload receipt"
        )
    unexpected = set(parsed) - set(LINUX_PACKAGE_UPLOAD_TARGETS)
    if unexpected:
        raise LinuxArtifactGateError(
            "unexpected Linux package/upload receipt target: "
            + ", ".join(sorted(unexpected))
        )
    missing = [
        target_id
        for target_id in REQUIRED_LINUX_UPLOAD_TARGETS
        if target_id not in parsed
    ]
    if missing:
        raise _owner_environment_blocker(
            "Linux package/upload receipts remain pending without owner evidence: "
            + ", ".join(missing)
        )
    bound: dict[str, object] = {}
    unique_pairs: list[tuple[str, str]] = []
    shared: dict[str, tuple[str, str]] = {}
    for target_id, record in parsed.items():
        unique_pairs.extend(_unique_receipt_digest_pairs(target_id, record))
        _bind_shared_upload_paths(shared, target_id, record)
    _reject_receipt_digest_reuse(unique_pairs)
    for target_id, record in parsed.items():
        artifact = artifacts.get(target_id)
        if artifact is None or len(artifact) != 2:
            raise LinuxArtifactGateError(
                f"{target_id} exact candidate bytes are missing."
            )
        digest, size = artifact
        bound[target_id] = bind_package_upload_receipt(
            target_id,
            record,
            artifact_sha256=str(digest),
            artifact_bytes=int(size),
        )
    _require_required_upload_signatures(parsed)
    return {
        "ok": True,
        "release": CANONICAL_RELEASE,
        "required_targets": list(REQUIRED_LINUX_UPLOAD_TARGETS),
        "bound_targets": sorted(bound),
        "publication_authorized": False,
        "upload_attempted": False,
        "owner_authorization": "pending",
        "receipts": bound,
    }


def _reject_test_only_production_pass() -> None:
    if TEST_ONLY is True:
        raise LinuxArtifactGateError(
            "TEST_ONLY Linux gate cannot emit a production pass."
        )


def _store_prefixed(prefix: str, relative: str) -> str:
    return f"{prefix}{relative}"


def _parse_snap_recipe(recipe: bytes) -> tuple[dict[tuple[str, ...], str], dict[tuple[str, ...], str]]:
    try:
        text = recipe.decode("utf-8")
    except UnicodeError as exc:
        raise LinuxArtifactGateError("Snap store recipe is not UTF-8.") from exc
    if "\t" in text or "\r" in text or "\x00" in text:
        raise LinuxArtifactGateError("Snap store recipe is not canonical YAML.")
    mappings: dict[tuple[str, ...], str] = {}
    blocks: dict[tuple[str, ...], str] = {}
    stack: list[tuple[int, tuple[str, ...]]] = [(-1, ())]
    block_path: tuple[str, ...] | None = None
    block_indent = -1
    block_lines: list[str] = []

    def finish_block() -> None:
        nonlocal block_path, block_indent, block_lines
        if block_path is not None:
            if not block_lines:
                raise LinuxArtifactGateError("Snap store recipe has an empty block scalar.")
            blocks[block_path] = "\n".join(block_lines) + "\n"
        block_path = None
        block_indent = -1
        block_lines = []

    for line_number, raw in enumerate(text.splitlines(), 1):
        if raw.rstrip(" ") != raw:
            raise LinuxArtifactGateError("Snap store recipe has trailing YAML whitespace.")
        if block_path is not None:
            indent = len(raw) - len(raw.lstrip(" "))
            if not raw.strip() or indent > block_indent:
                if raw.strip():
                    if indent < block_indent + 2:
                        raise LinuxArtifactGateError("Snap store recipe block indentation is invalid.")
                    block_lines.append(raw[block_indent + 2 :])
                else:
                    block_lines.append("")
                continue
            finish_block()
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in {"---", "..."} or stripped.startswith(("%", "!", "&", "*")):
            raise LinuxArtifactGateError("Snap store recipe uses unsupported YAML authority features.")
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2:
            raise LinuxArtifactGateError("Snap store recipe indentation is not canonical.")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            raise LinuxArtifactGateError("Snap store recipe indentation is invalid.")
        parent = stack[-1][1]
        if stripped.startswith("- "):
            if not parent:
                raise LinuxArtifactGateError("Snap store recipe has a root sequence.")
            value = stripped[2:].strip()
            if not value or value.startswith(("&", "*", "!")) or "<<:" in value:
                raise LinuxArtifactGateError("Snap store recipe sequence is unsafe.")
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+):(?:[ ](.*))?", stripped)
        if match is None:
            raise LinuxArtifactGateError(
                f"Snap store recipe has unsupported YAML syntax at line {line_number}."
            )
        key, value = match.groups()
        path = parent + (key,)
        if path in mappings:
            raise LinuxArtifactGateError("Snap store recipe has a duplicate YAML key.")
        value = "" if value is None else value
        if value.startswith(("&", "*", "!")) or "<<:" in value:
            raise LinuxArtifactGateError("Snap store recipe uses unsupported YAML authority features.")
        mappings[path] = value
        if value in {"|", "|-", "|+", ">", ">-", ">+"}:
            block_path = path
            block_indent = indent
            block_lines = []
        elif value == "":
            stack.append((indent, path))
    finish_block()
    if not mappings:
        raise LinuxArtifactGateError("Snap store recipe is empty.")
    return mappings, blocks


def _semantic_shell_recipe_markers(script: str, kind: str) -> frozenset[str]:
    """Extract declarations only from reachable, successful top-level paths."""
    if "\x00" in script or "\r" in script:
        raise LinuxArtifactGateError(f"{kind} store recipe shell is not canonical.")
    declared: set[str] = set()
    required_engines = {"winn-datapath", "xray", "awg", "amneziawg-go"}
    expected_env = "FLATPAK_ARCH" if kind == "Flatpak" else "CRAFT_ARCH_BUILD_FOR"
    expected_arches = (
        {"x86_64": "x64", "aarch64": "arm64"}
        if kind == "Flatpak"
        else {"amd64": "x64", "arm64": "arm64"}
    )
    saw_case = False
    saw_strict_set = False
    heredoc_terminator: str | None = None
    conditional_depth = 0
    case_stack: list[str] = []
    forbidden_control = {
        "alias", "eval", "exec", "source", ".", "trap", "return", "while", "until", "select",
    }
    for line_number, line in enumerate(script.splitlines(), 1):
        if heredoc_terminator is not None:
            if line == heredoc_terminator:
                heredoc_terminator = None
            continue
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise LinuxArtifactGateError(
                f"{kind} store recipe shell is malformed at line {line_number}."
            ) from exc
        if not tokens:
            continue
        stripped = line.strip()
        if re.match(
            r"^(?:function[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*(?:\(\))?[ \t]*\{",
            stripped,
        ):
            raise LinuxArtifactGateError(
                f"{kind} store recipe shell uses an unaudited function at line {line_number}."
            )
        if tokens[0] == "set":
            if tokens != ["set", "-eu"] or saw_strict_set or case_stack or conditional_depth:
                raise LinuxArtifactGateError(
                    f"{kind} store recipe shell changes strict execution mode at line {line_number}."
                )
            saw_strict_set = True
            continue
        if not saw_strict_set and any(token == "exit" for token in tokens):
            raise LinuxArtifactGateError(
                f"{kind} store recipe shell has a successful or dynamic early exit "
                f"at line {line_number}."
            )
        if not saw_strict_set:
            raise LinuxArtifactGateError(
                f"{kind} store recipe does not declare the exact hardening/payload recipe: "
                "the shell does not begin with exact set -eu."
            )
        if tokens[0] == "case":
            exact_architecture_case = tokens[:3] in (
                ["case", f"${{{expected_env}}}", "in"],
                ["case", f"${expected_env}", "in"],
            )
            derived_architecture_case = tokens[:3] in (
                ["case", "${flutter_arch}", "in"],
                ["case", "$flutter_arch", "in"],
            )
            if not exact_architecture_case and not derived_architecture_case:
                raise LinuxArtifactGateError(
                    f"{kind} store recipe shell uses an unaudited case authority "
                    f"at line {line_number}."
                )
            case_stack.append(
                "release-architecture"
                if exact_architecture_case
                else "derived-architecture"
            )
            if exact_architecture_case:
                if saw_case:
                    raise LinuxArtifactGateError(
                        f"{kind} store recipe repeats its architecture authority."
                    )
                saw_case = True
                declared.add(expected_env)
            continue
        if tokens[0] == "esac":
            if not case_stack:
                raise LinuxArtifactGateError(
                    f"{kind} store recipe shell has an unmatched esac at line {line_number}."
                )
            case_stack.pop()
            continue
        if case_stack:
            if any(token == "exit" for token in tokens):
                exit_index = tokens.index("exit")
                status = (
                    tokens[exit_index + 1]
                    if exit_index + 1 < len(tokens)
                    else "0"
                )
                if re.fullmatch(r"[1-9][0-9]*;?", status) is None:
                    raise LinuxArtifactGateError(
                        f"{kind} store recipe shell has a successful or dynamic early exit "
                        f"at line {line_number}."
                    )
            if case_stack[-1] == "release-architecture":
                branch = tokens[0][:-1] if tokens[0].endswith(")") else ""
                if (
                    branch in expected_arches
                    and len(tokens) == 3
                    and tokens[1] == f"flutter_arch={expected_arches[branch]}"
                    and tokens[2] == ";;"
                ):
                    declared.add(branch)
            continue
        if any(token == "exit" for token in tokens):
            exit_index = tokens.index("exit")
            status = tokens[exit_index + 1] if exit_index + 1 < len(tokens) else "0"
            if re.fullmatch(r"[1-9][0-9]*;?", status) is None:
                raise LinuxArtifactGateError(
                    f"{kind} store recipe shell has a successful or dynamic early exit "
                    f"at line {line_number}."
                )
            if conditional_depth == 0:
                raise LinuxArtifactGateError(
                    f"{kind} store recipe shell has an unconditional early exit "
                    f"at line {line_number}."
                )
        if tokens[0] in forbidden_control:
            raise LinuxArtifactGateError(
                f"{kind} store recipe shell uses unsupported control flow at line {line_number}."
            )
        if tokens[0].startswith(("$", "${")) and tokens[0] not in {
            "$flutter_sdk",
            "${flutter_sdk}",
            "$engine_stage",
            "${engine_stage}",
        }:
            raise LinuxArtifactGateError(
                f"{kind} store recipe shell uses an unaudited dynamic command "
                f"at line {line_number}."
            )
        if tokens[0] == "if":
            conditional_depth += 1
            continue
        if tokens[0] == "fi":
            if conditional_depth <= 0:
                raise LinuxArtifactGateError(
                    f"{kind} store recipe shell has an unmatched fi at line {line_number}."
                )
            conditional_depth -= 1
            continue
        if conditional_depth:
            continue
        heredocs = [token[2:] for token in tokens if token.startswith("<<")]
        if len(heredocs) > 1 or any(
            not value or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None
            for value in heredocs
        ):
            raise LinuxArtifactGateError(
                f"{kind} store recipe shell has an unsafe heredoc at line {line_number}."
            )
        if heredocs:
            heredoc_terminator = heredocs[0]
        executable = pathlib.PurePosixPath(tokens[0]).name
        if (
            executable in {"$flutter_sdk", "${flutter_sdk}", "flutter"}
            and len(tokens) >= 4
            and tokens[1:3] == ["build", "linux"]
        ):
            if "--obfuscate" in tokens[3:]:
                declared.add("--obfuscate")
            if any(token.startswith("--split-debug-info=") for token in tokens[3:]):
                declared.add("--split-debug-info=")
            if "--extra-gen-snapshot-options=--strip" in tokens[3:]:
                declared.add("--extra-gen-snapshot-options=--strip")
            continue
        if tokens[:3] == ["for", "engine", "in"] and tokens[-1] == "do":
            engine_tokens = {
                token.rstrip(";") for token in tokens[3:-1] if token.rstrip(";")
            }
            if required_engines.issubset(engine_tokens):
                declared.update(required_engines)
            continue
        if executable == "install" and "-Dm0644" in tokens[1:]:
            attestation = "winn3-descriptor-ring-attestation.json"
            path_arguments = [
                token for token in tokens[1:] if pathlib.PurePosixPath(token).name == attestation
            ]
            if len(path_arguments) == 2:
                declared.add(attestation)
    if heredoc_terminator is not None:
        raise LinuxArtifactGateError(f"{kind} store recipe shell has an unterminated heredoc.")
    if conditional_depth:
        raise LinuxArtifactGateError(f"{kind} store recipe shell has an unterminated if.")
    if case_stack:
        raise LinuxArtifactGateError(f"{kind} store recipe shell has an unterminated case.")
    if not saw_strict_set or not saw_case or not set(expected_arches).issubset(declared):
        raise LinuxArtifactGateError(
            f"{kind} store recipe does not declare the exact hardening/payload recipe: "
            "reachable architecture branches are incomplete."
        )
    return frozenset(declared)


def _require_recipe_markers(recipe: bytes, markers: tuple[str, ...], kind: str) -> None:
    if kind == "Flatpak":
        document = _strict_json_object(recipe, "Flatpak store recipe")
        modules = document.get("modules")
        finish_args = document.get("finish-args")
        if (
            document.get("id") != "org.winsvpn.app"
            or document.get("command") != "wins_vpn"
            or type(document.get("runtime")) is not str
            or type(document.get("runtime-version")) is not str
            or type(document.get("sdk")) is not str
            or type(finish_args) is not list
            or not finish_args
            or type(modules) is not list
            or len(modules) != 1
            or type(modules[0]) is not dict
        ):
            raise LinuxArtifactGateError("Flatpak store recipe schema is invalid.")
        module = modules[0]
        commands = module.get("build-commands")
        sources = module.get("sources")
        if (
            module.get("name") != "winsvpn"
            or module.get("buildsystem") != "simple"
            or type(commands) is not list
            or len(commands) != 1
            or any(type(command) is not str or not command for command in commands)
            or type(sources) is not list
            or len(sources) < 3
            or any(type(source) is not dict for source in sources)
        ):
            raise LinuxArtifactGateError("Flatpak store recipe module schema is invalid.")
        source_arches = {
            tuple(source.get("only-arches", ()))
            for source in sources
            if "only-arches" in source
        }
        if {("x86_64",), ("aarch64",)} - source_arches:
            raise LinuxArtifactGateError("Flatpak store recipe architecture schema is invalid.")
        script = "\n".join(commands) + "\n"
    elif kind == "Snap":
        mappings, blocks = _parse_snap_recipe(recipe)
        required = {
            ("name",): "wins-vpn",
            ("grade",): "stable",
            ("confinement",): "classic",
            ("apps", "wins-vpn", "command"): "bin/wins_vpn",
        }
        if any(mappings.get(path) != value for path, value in required.items()):
            raise LinuxArtifactGateError("Snap store recipe schema is invalid.")
        required_paths = {
            ("version",),
            ("platforms", "amd64"),
            ("platforms", "arm64"),
            ("parts", "winsvpn", "override-build"),
        }
        if not required_paths.issubset(mappings):
            raise LinuxArtifactGateError("Snap store recipe schema is incomplete.")
        script_path = ("parts", "winsvpn", "override-build")
        if script_path not in blocks:
            raise LinuxArtifactGateError("Snap store recipe has no parsed override-build script.")
        script = blocks[script_path]
    else:
        raise LinuxArtifactGateError(f"unsupported Linux store recipe kind: {kind}")
    declarations = _semantic_shell_recipe_markers(script, kind)
    missing = [marker for marker in markers if marker not in declarations]
    if missing:
        raise LinuxArtifactGateError(
            f"{kind} store recipe does not declare the exact hardening/payload recipe: "
            + ", ".join(missing)
        )


def _discover_store_package(
    recipe: pathlib.Path, arch: str, filename: str, kind: str, target_id: str
) -> pathlib.Path:
    root = ROOT.resolve(strict=True)
    relative = (recipe.parent.relative_to(root) / arch / filename).as_posix()
    try:
        return _secure_regular_repo_path(relative, f"{kind} package ({arch})")
    except LinuxArtifactGateError as exc:
        if "is missing" in str(exc):
            raise _owner_build_system_blocker(
                f"no exact local {kind} package is bound to {target_id} for architecture {arch}"
            ) from exc
        raise


class _AuthenticatedStoreTool:
    """Retained exact executable and complete ancestor custody."""

    def __init__(
        self,
        *,
        kind: str,
        path: pathlib.Path,
        fd: int,
        identity: tuple[int, ...],
        digest: str,
        ancestors: _RetainedDirectoryChain,
    ) -> None:
        self.kind = kind
        self.path = path
        self.fd = fd
        self.identity = identity
        self.digest = digest
        self.ancestors = ancestors

    def revalidate(self) -> None:
        if self.fd < 0:
            raise LinuxArtifactGateError(
                f"authenticated exact {self.kind} tool custody is closed."
            )
        _require_readonly_fd(self.fd, f"authenticated exact {self.kind} tool")
        self.ancestors.revalidate()
        current = os.fstat(self.fd)
        try:
            named = self.path.lstat()
        except OSError as exc:
            raise LinuxArtifactGateError(
                f"authenticated exact {self.kind} tool was removed."
            ) from exc
        if (
            _file_identity(current) != self.identity
            or _file_identity(named) != self.identity
            or _sha256_fd(self.fd) != self.digest
        ):
            raise LinuxArtifactGateError(
                f"authenticated exact {self.kind} tool changed during execution."
            )

    def executable_reference(self) -> str:
        self.revalidate()
        try:
            return linux_release_signing._proc_fd_path(
                self.fd, f"{self.kind} store tool execution"
            )
        except linux_release_signing.SigningError as exc:
            raise _wrap_signing_error(exc) from exc

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        self.ancestors.close()


class _RetainedExtractionDirectory:
    """Exact extraction directory retained beneath the snapshot root."""

    def __init__(
        self,
        *,
        path: pathlib.Path,
        name: str,
        fd: int,
        identity: tuple[int, int, int, int],
        parent_generation: tuple[int, int],
        parent_chain: _RetainedDirectoryChain,
    ) -> None:
        self.path = path
        self.name = name
        self.fd = fd
        self.identity = identity
        self.parent_generation = parent_generation
        self.parent_chain = parent_chain

    def revalidate(self) -> None:
        if self.fd < 0:
            raise LinuxArtifactGateError("store extraction directory custody is closed.")
        _require_readonly_fd(self.fd, "store extraction directory")
        self.parent_chain.revalidate()
        current = os.fstat(self.fd)
        parent = os.fstat(self.parent_chain.leaf_fd)
        try:
            named = os.stat(
                self.name,
                dir_fd=self.parent_chain.leaf_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise LinuxArtifactGateError(
                "store extraction directory was replaced or removed."
            ) from exc
        if (
            not stat.S_ISDIR(current.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or _directory_identity(current) != self.identity
            or _directory_identity(named) != self.identity
            or (parent.st_mtime_ns, parent.st_ctime_ns) != self.parent_generation
        ):
            raise LinuxArtifactGateError(
                "store extraction directory was substituted or restored."
            )

    def process_reference(self) -> str:
        self.revalidate()
        try:
            return linux_release_signing._proc_fd_path(
                self.fd, "store extraction directory"
            )
        except linux_release_signing.SigningError as exc:
            raise _wrap_signing_error(exc) from exc

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def _create_retained_extraction_directory(
    snapshot: AuthenticatedSnapshot,
) -> _RetainedExtractionDirectory:
    snapshot.ensure_bound()
    parent_chain = snapshot.snapshot_ancestor_chain
    if parent_chain is None:
        raise LinuxArtifactGateError(
            "authenticated artifact snapshot ancestor custody is missing."
        )
    parent_chain.revalidate()
    name = "extracted"
    try:
        os.mkdir(name, 0o700, dir_fd=parent_chain.leaf_fd)
    except OSError as exc:
        raise LinuxArtifactGateError(
            "store extraction directory could not be created exclusively."
        ) from exc
    fd = -1
    try:
        fd = _openat_child(
            parent_chain.leaf_fd,
            name,
            _dir_open_flags(),
            label="store extraction directory",
        )
        info = os.fstat(fd)
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise LinuxArtifactGateError(
                "store extraction directory mode is not private."
            )
        retained = _RetainedExtractionDirectory(
            path=snapshot.root / name,
            name=name,
            fd=fd,
            identity=_directory_identity(info),
            parent_generation=(
                os.fstat(parent_chain.leaf_fd).st_mtime_ns,
                os.fstat(parent_chain.leaf_fd).st_ctime_ns,
            ),
            parent_chain=parent_chain,
        )
        fd = -1
        retained.revalidate()
        return retained
    finally:
        if fd >= 0:
            os.close(fd)


def _authenticate_store_tool(kind: str) -> _AuthenticatedStoreTool:
    if owner_store_tool_pin_blocked(kind):
        raise _owner_environment_blocker(
            f"authenticated exact {kind} tool pin remains OWNER-BLOCKED: ABSENT"
        )
    path = pathlib.Path(REVIEWED_STORE_TOOLS[kind])
    ancestors = _retain_complete_directory_chain(
        path.parent, f"authenticated exact {kind} tool"
    )
    fd = -1
    try:
        fd = os.open(path, _open_flags())
    except OSError as exc:
        ancestors.close()
        raise _owner_environment_blocker(
            f"no authenticated exact {kind} tool is available at {path}"
        ) from exc
    try:
        info = os.fstat(fd)
        path_info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not info.st_mode & 0o111
            or _file_identity(info) != _file_identity(path_info)
        ):
            raise _owner_environment_blocker(
                f"authenticated exact {kind} tool at {path} is not a regular executable"
            )
        digest = _sha256_fd(fd)
        expected = OWNER_STORE_TOOL_SHA256[kind]
        if digest != expected:
            raise _owner_environment_blocker(
                f"authenticated exact {kind} tool SHA-256 mismatch at {path}"
            )
        custody = _AuthenticatedStoreTool(
            kind=kind,
            path=path,
            fd=fd,
            identity=_file_identity(info),
            digest=digest,
            ancestors=ancestors,
        )
        fd = -1
        custody.revalidate()
        return custody
    except BaseException:
        ancestors.close()
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def _run_store_tool(
    kind: str,
    tool: _AuthenticatedStoreTool,
    snapshot: AuthenticatedSnapshot,
    output: _RetainedExtractionDirectory,
) -> None:
    snapshot.ensure_bound()
    output.revalidate()
    executable = tool.executable_reference()
    output_reference = output.process_reference()
    try:
        artifact_reference = linux_release_signing._proc_fd_path(
            snapshot.fd, f"{kind} package inspection"
        )
    except linux_release_signing.SigningError as exc:
        raise _wrap_signing_error(exc) from exc
    if kind == "Snap":
        argv = [executable, "-d", output_reference, "-f", artifact_reference]
    else:
        argv = [executable, "build-import-bundle", "--ostree-verbose", artifact_reference]
    try:
        completed = _run_bounded_subprocess(
            argv,
            cwd=output_reference,
            pass_fds=(tool.fd, snapshot.fd, output.fd),
            label=f"authenticated exact {kind} tool",
        )
    except OSError as exc:
        raise _owner_environment_blocker(
            f"authenticated exact {kind} tool could not be executed: {exc}"
        ) from exc
    if completed.returncode != 0:
        raise LinuxArtifactGateError(
            f"native {kind} verification failed: {(completed.stderr or completed.stdout).strip()}"
        )
    tool.revalidate()
    snapshot.rehash()
    output.revalidate()


def _walk_extracted_payloads(
    root: _RetainedExtractionDirectory,
) -> tuple[dict[str, bytes], dict[str, int]]:
    payloads: dict[str, bytes] = {}
    modes: dict[str, int] = {}

    def walk(directory_fd: int, parts: tuple[str, ...]) -> None:
        before = os.fstat(directory_fd)
        if not stat.S_ISDIR(before.st_mode):
            raise LinuxArtifactGateError("store package extract directory is invalid.")
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as exc:
            raise LinuxArtifactGateError(
                "store package extract directory could not be enumerated."
            ) from exc
        for name in names:
            _require_unique_casefold_name(
                directory_fd, name, "store package extract member"
            )
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise LinuxArtifactGateError(
                    f"store package extract has an unsafe member: {'/'.join(parts + (name,))}"
                ) from exc
            relative_parts = parts + (name,)
            relative = pathlib.PurePosixPath(*relative_parts).as_posix()
            if stat.S_ISLNK(info.st_mode):
                raise LinuxArtifactGateError(
                    f"store package extract has a symlink member: {relative}"
                )
            if stat.S_ISDIR(info.st_mode):
                child_fd = _openat_child(
                    directory_fd,
                    name,
                    _dir_open_flags(),
                    label=f"store package extract directory {relative}",
                )
                child_identity = _directory_identity(os.fstat(child_fd))
                try:
                    walk(child_fd, relative_parts)
                    named_after = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if _directory_identity(named_after) != child_identity:
                        raise LinuxArtifactGateError(
                            f"store package extract directory was substituted: {relative}"
                        )
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise LinuxArtifactGateError(
                    f"store package extract has an unsafe member: {relative}"
                )
            if info.st_size > MAX_MEMBER_BYTES:
                raise LinuxArtifactGateError("store package has an oversized extracted member.")
            fd = -1
            try:
                fd = _openat_child(
                    directory_fd,
                    name,
                    _open_flags(),
                    label=f"store package extract member {relative}",
                )
                opened = os.fstat(fd)
                if (
                    _file_identity(opened) != _file_identity(info)
                    or not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                ):
                    raise LinuxArtifactGateError(
                        f"store package extract member was swapped: {relative}"
                    )
                payload = os.pread(fd, opened.st_size, 0)
                after = os.fstat(fd)
                if len(payload) != opened.st_size or _file_identity(after) != _file_identity(opened):
                    raise LinuxArtifactGateError(
                        f"store package extract member mutated while it was read: {relative}"
                    )
            except OSError as exc:
                raise LinuxArtifactGateError(
                    f"store package extract has an unsafe member: {relative}"
                ) from exc
            finally:
                if fd >= 0:
                    os.close(fd)
            payloads[relative] = payload
            modes[relative] = stat.S_IMODE(opened.st_mode)
        after = os.fstat(directory_fd)
        if _directory_identity(after) != _directory_identity(before):
            raise LinuxArtifactGateError(
                "store package extract directory changed during traversal."
            )

    root.revalidate()
    walk(root.fd, ())
    root.revalidate()
    return payloads, modes


def _validate_store_package_files(
    payloads: dict[str, bytes],
    modes: dict[str, int],
    *,
    prefix: str,
    expected_machine: int,
    expected_appstream_version: str,
    recipe_name: str,
    recipe_sha256: str,
    flutter: dict[str, str],
) -> dict[str, object]:
    required = {_store_prefixed(prefix, f"bin/{name}") for name in STORE_PACKAGE_PAYLOADS}
    required.update(
        {
            _store_prefixed(prefix, "share/applications/org.winsvpn.app.desktop"),
            _store_prefixed(prefix, "share/metainfo/org.winsvpn.app.metainfo.xml"),
            _store_prefixed(prefix, STORE_WINN3_DESCRIPTOR_RING_ATTESTATION_RELATIVE),
            _store_prefixed(prefix, "share/winsvpn/store-recipe.sha256"),
            _store_prefixed(prefix, "share/winsvpn/release-manifest.sha256"),
        }
    )
    for relative in flutter.values():
        required.add(_store_prefixed(prefix, relative))
    missing = sorted(required - payloads.keys())
    if missing:
        raise LinuxArtifactGateError(
            "store package is incomplete or substituted: " + ", ".join(missing)
        )
    allowed_elfs = {_store_prefixed(prefix, f"bin/{name}") for name in STORE_PACKAGE_ELFS}
    allowed_elfs.add(_store_prefixed(prefix, flutter["libapp"]))
    allowed_elfs.add(_store_prefixed(prefix, flutter["libflutter"]))
    allowed_elfs.add(_store_prefixed(prefix, flutter["bypass"]))
    _reject_extra_elf_payloads(payloads, allowed_elfs, "store package")
    stamp = payloads[_store_prefixed(prefix, "share/winsvpn/store-recipe.sha256")]
    expected_stamp = f"{recipe_sha256}  {recipe_name}\n".encode("ascii")
    if stamp != expected_stamp:
        raise LinuxArtifactGateError(
            "store package does not bind the exact store submission recipe."
        )
    _scan_elf_payloads(payloads, expected_machine)
    payload_identities: dict[str, str] = {}
    for basename in STORE_PACKAGE_ELFS:
        member = _store_prefixed(prefix, f"bin/{basename}")
        require_entry = basename != "awg-quick"
        _require_executable_elf(payloads[member], member, expected_machine, require_entry=require_entry)
        payload_identities[basename] = _sha256_bytes(payloads[member])
    for key in ("libapp", "libflutter"):
        member = _store_prefixed(prefix, flutter[key])
        parsed = _require_executable_elf(payloads[member], member, expected_machine, require_entry=False)
        payload_identities[key] = str(parsed["sha256"])
    libapp_member = _store_prefixed(prefix, flutter["libapp"])
    libapp_build_id = _elf_gnu_build_id(payloads[libapp_member], libapp_member)
    bypass = _store_prefixed(prefix, flutter["bypass"])
    payload_identities["bypass"] = _sha256_bytes(payloads[bypass])
    for key in ("icu", "asset_manifest", "font_manifest"):
        member = _store_prefixed(prefix, flutter[key])
        payload_identities[key] = _payload_identity(
            member, payloads[member], "data", expected_machine
        )["sha256"]
    if len({payload_identities["libapp"], payload_identities["libflutter"], payload_identities["bypass"]}) != 3:
        raise LinuxArtifactGateError("store Flutter/runtime payload identities must be distinct.")
    _verify_winn3_descriptor_ring_attestation(
        payloads,
        modes,
        attestation_name=_store_prefixed(
            prefix, STORE_WINN3_DESCRIPTOR_RING_ATTESTATION_RELATIVE
        ),
        verified_artifact_name=_store_prefixed(prefix, flutter["libapp"]),
        expected_machine=expected_machine,
        label="store package",
    )
    manifest_name = _store_prefixed(prefix, "share/winsvpn/release-manifest.sha256")
    recorded = _parse_release_manifest(payloads[manifest_name])
    expected_manifest = {
        name: _sha256_bytes(payload)
        for name, payload in payloads.items()
        if name != manifest_name
    }
    if recorded != expected_manifest:
        raise LinuxArtifactGateError(
            "store package release-manifest.sha256 is not exhaustive and exact."
        )
    try:
        desktop = payloads[
            _store_prefixed(prefix, "share/applications/org.winsvpn.app.desktop")
        ].decode("utf-8")
        metainfo = payloads[
            _store_prefixed(prefix, "share/metainfo/org.winsvpn.app.metainfo.xml")
        ].decode("utf-8")
    except UnicodeError as exc:
        raise LinuxArtifactGateError("store package identity metadata is not UTF-8.") from exc
    if not re.search(r"(?m)^Exec=wins_vpn(?:\s|$)", desktop):
        raise LinuxArtifactGateError("store package desktop identity does not launch wins_vpn.")
    if "<!DOCTYPE" in metainfo.upper() or "<!ENTITY" in metainfo.upper():
        raise LinuxArtifactGateError(
            "store package AppStream metainfo must not contain a document type or entity declaration."
        )
    try:
        component = ET.fromstring(metainfo)
    except ET.ParseError as exc:
        raise LinuxArtifactGateError("store package AppStream metainfo is malformed XML.") from exc
    component_id = component.find("id")
    if (
        component.tag != "component"
        or component_id is None
        or component_id.text != "org.winsvpn.app"
    ):
        raise LinuxArtifactGateError("store package metainfo identity is not org.winsvpn.app.")
    versions = [release.get("version") for release in component.findall("./releases/release")]
    if not versions or versions[0] != expected_appstream_version:
        raise LinuxArtifactGateError(
            "store package AppStream metainfo does not lead with the canonical release version."
        )
    _scan_store_package_payloads(payloads)
    return {
        "files": len(payloads),
        "elf_machine": expected_machine,
        "payload_identities": payload_identities,
        "libapp_build_id": libapp_build_id,
    }


def _scan_payload_bytes(name: str, payload: bytes) -> None:
    try:
        reject_local_build_paths(name, payload)
        check_blob(name, payload, {})
        reject_unstripped_native_library(name, payload)
    except PrivacyError as exc:
        raise LinuxArtifactGateError(f"package privacy scan failed: {exc}") from exc
    try:
        reject_packaged_private_symbols("linux", name, payload)
        reject_sensitive_internal_identifiers("linux", name, payload)
    except ObfuscationError as exc:
        raise LinuxArtifactGateError(
            f"package obfuscation evidence failed: {exc}"
        ) from exc


def _nested_archive_kind(payload: bytes) -> str | None:
    if payload.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if payload.startswith(b"(\xb5/\xfd"):
        return "zstd"
    if payload.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ")):
        return "tar"
    if len(payload) >= 262 and payload[257:262] == b"ustar":
        return "tar"
    try:
        if REVIEWED_TARFILE.is_tarfile(privacy.io.BytesIO(payload)):
            return "tar"
    except Exception:
        return None
    return None


def _nested_label(parent: str, child: str) -> str:
    try:
        child.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LinuxArtifactGateError(
            f"nested archive member path is not canonical ASCII: {child!r}"
        ) from exc
    return f"{parent}!/{child}"


def _read_nested_member(handle, expected: int, label: str) -> bytes:
    output = bytearray()
    while len(output) < expected:
        block = handle.read(min(65536, expected - len(output)))
        if not block:
            raise LinuxArtifactGateError(f"{label} expansion was truncated.")
        output.extend(block)
    if handle.read(1):
        raise LinuxArtifactGateError(f"{label} expanded beyond its declared size.")
    return bytes(output)


def _decompress_zstd_exact(
    name: str, payload: bytes, budget: _ArchiveBudget
) -> bytes:
    try:
        frame = REVIEWED_ZSTD.get_frame_info(payload)
    except Exception as exc:
        raise LinuxArtifactGateError(f"{name} zstd frame is malformed.") from exc
    expanded = getattr(frame, "decompressed_size", None)
    if type(expanded) is not int or expanded <= 0:
        raise LinuxArtifactGateError(
            f"{name} zstd frame must declare one positive expanded size."
        )
    budget.reserve(expanded, compressed=len(payload), label=f"{name} zstd member")
    try:
        decompressor = REVIEWED_ZSTD.ZstdDecompressor()
        output = bytearray(
            decompressor.decompress(payload, max_length=expanded + 1)
        )
        while not decompressor.eof and not decompressor.needs_input:
            output.extend(
                decompressor.decompress(
                    b"", max_length=max(expanded + 1 - len(output), 0)
                )
            )
            if len(output) > expanded:
                break
    except Exception as exc:
        raise LinuxArtifactGateError(f"{name} zstd expansion failed closed.") from exc
    if (
        len(output) != expanded
        or not decompressor.eof
        or decompressor.unused_data
    ):
        raise LinuxArtifactGateError(
            f"{name} zstd frame is truncated, concatenated, or size-inconsistent."
        )
    return bytes(output)


def _scan_nested_zip(
    name: str,
    payload: bytes,
    budget: _ArchiveBudget,
    depth: int,
) -> None:
    try:
        with REVIEWED_ZIPFILE.ZipFile(privacy.io.BytesIO(payload)) as archive:
            members = archive.infolist()
            privacy.validate_zip_metadata(pathlib.Path("archive"), members)
            files = [member for member in members if not member.is_dir()]
            total = sum(member.file_size for member in files)
            if total > len(payload) * MAX_COMPRESSION_RATIO:
                raise LinuxArtifactGateError(
                    f"{name} aggregate ZIP compression ratio exceeds the reviewed limit."
                )
            for member in members:
                budget.reserve(
                    member.file_size,
                    compressed=member.compress_size,
                    label=f"{name} ZIP member {member.filename}",
                )
            for member in files:
                child_name = _nested_label(name, member.filename)
                with archive.open(member, "r") as handle:
                    child = _read_nested_member(handle, member.file_size, child_name)
                _scan_recursive_payload(child_name, child, budget, depth)
    except LinuxArtifactGateError:
        raise
    except PrivacyError as exc:
        raise LinuxArtifactGateError(f"package privacy scan failed: {exc}") from exc
    except Exception as exc:
        raise LinuxArtifactGateError(f"{name} ZIP archive is malformed.") from exc


def _scan_nested_tar(
    name: str,
    payload: bytes,
    budget: _ArchiveBudget,
    depth: int,
) -> None:
    try:
        mode = privacy._tar_open_mode(payload)
        with REVIEWED_TARFILE.open(
            fileobj=privacy.io.BytesIO(payload), mode=mode
        ) as archive:
            members = list(archive)
            privacy.validate_tar_metadata(pathlib.Path("archive"), members)
            files = [member for member in members if member.isfile()]
            total = sum(member.size for member in files)
            if total > len(payload) * MAX_COMPRESSION_RATIO:
                raise LinuxArtifactGateError(
                    f"{name} aggregate tar compression ratio exceeds the reviewed limit."
                )
            for member in members:
                budget.reserve(member.size, label=f"{name} tar member {member.name}")
            for member in files:
                child_name = _nested_label(name, member.name.removeprefix("./"))
                handle = archive.extractfile(member)
                if handle is None:
                    raise LinuxArtifactGateError(
                        f"{child_name} could not be expanded."
                    )
                with handle:
                    child = _read_nested_member(handle, member.size, child_name)
                _scan_recursive_payload(child_name, child, budget, depth)
    except LinuxArtifactGateError:
        raise
    except PrivacyError as exc:
        raise LinuxArtifactGateError(f"package privacy scan failed: {exc}") from exc
    except Exception as exc:
        raise LinuxArtifactGateError(f"{name} nested tar archive is malformed.") from exc


def _scan_recursive_payload(
    name: str,
    payload: bytes,
    budget: _ArchiveBudget,
    depth: int,
) -> None:
    _scan_payload_bytes(name, payload)
    kind = _nested_archive_kind(payload)
    if kind is None:
        return
    if depth >= MAX_ARCHIVE_DEPTH:
        raise LinuxArtifactGateError(
            f"archive member exceeds the reviewed nesting depth: {name}"
        )
    child_depth = depth + 1
    if kind == "zip":
        _scan_nested_zip(name, payload, budget, child_depth)
        return
    if payload.startswith(b"\x1f\x8b"):
        # A gzip stream is not necessarily a tarball: every Flutter release ships
        # assets/flutter_assets/NOTICES.Z, one gzip-compressed text. Expand it
        # under the privacy scanner's own bounds and scan the expanded bytes. A
        # stream that does not expand, or that expands to a tarball, keeps the
        # tar scan and its fail-closed errors.
        try:
            gunzipped = privacy._gunzip_bounded(payload)
        except PrivacyError:
            gunzipped = None
        if gunzipped is not None and not privacy._is_plain_tar(gunzipped):
            budget.reserve(
                len(gunzipped), compressed=len(payload), label=f"{name} gzip member"
            )
            _scan_recursive_payload(
                _nested_label(name, "gunzip-expanded"), gunzipped, budget, child_depth
            )
            return
    if kind == "zstd":
        expanded = _decompress_zstd_exact(name, payload, budget)
        _scan_recursive_payload(
            _nested_label(name, "zstd-expanded"),
            expanded,
            budget,
            child_depth,
        )
        return
    _scan_nested_tar(name, payload, budget, child_depth)


def _scan_store_package_payloads(
    payloads: dict[str, bytes], *, budget: _ArchiveBudget | None = None
) -> None:
    _require_reviewed_archive_modules()
    shared = _ArchiveBudget() if budget is None else budget
    if budget is None:
        for name, payload in payloads.items():
            shared.reserve(len(payload), label=f"package payload {name}")
    for name, payload in payloads.items():
        _scan_recursive_payload(name, payload, shared, 0)


def _inspect_native_store_package(
    snapshot: AuthenticatedSnapshot,
    *,
    kind: str,
    prefix: str,
    expected_machine: int,
    expected_appstream_version: str,
    recipe_name: str,
    recipe_sha256: str,
    flutter: dict[str, str],
) -> dict[str, object]:
    snapshot.reject_origin_swap()
    header = snapshot.header(512)
    if _is_gzip_tar_surrogate(header):
        raise LinuxArtifactGateError(
            f"gzip-tar surrogate is not a native {kind} package."
        )
    if kind == "Snap" and not header.startswith(SQUASHFS_MAGIC):
        raise LinuxArtifactGateError("store package is not a native Snap squashfs image.")
    tool = _authenticate_store_tool(kind)
    extracted: _RetainedExtractionDirectory | None = None
    try:
        extracted = _create_retained_extraction_directory(snapshot)
        _run_store_tool(kind, tool, snapshot, extracted)
        snapshot.reject_origin_swap()
        payloads, modes = _walk_extracted_payloads(extracted)
        result = _validate_store_package_files(
            payloads,
            modes,
            prefix=prefix,
            expected_machine=expected_machine,
            expected_appstream_version=expected_appstream_version,
            recipe_name=recipe_name,
            recipe_sha256=recipe_sha256,
            flutter=flutter,
        )
        tool.revalidate()
        return result
    finally:
        if extracted is not None:
            extracted.close()
        tool.close()


def _require_split_debug_symbols(
    store_kind: str,
    arch: str,
    kind: str,
    *,
    expected_machine: int,
    expected_build_id: str,
) -> tuple[AuthenticatedSnapshot, AuthenticatedSnapshot]:
    relative = (
        PRIVATE_STORE_SYMBOL_ROOT / store_kind / arch / _linux_release_stamp() / "app.symbols"
    ).as_posix()
    try:
        path = _secure_regular_repo_path(relative, "Flutter split-debug symbols")
    except LinuxArtifactGateError as exc:
        if "is missing" in str(exc):
            raise _owner_build_system_blocker(
                f"no Flutter obfuscation split-debug symbols are bound to the exact local "
                f"{kind} package for architecture {arch}"
            ) from exc
        raise
    snapshot = _snapshot_artifact(path, f"{kind} Flutter split-debug symbols ({arch})")
    retained: list[AuthenticatedSnapshot] = [snapshot]
    try:
        payload = os.pread(snapshot.fd, snapshot.size, 0)
        if len(payload) != snapshot.size or not payload.startswith(ELF_MAGIC):
            raise LinuxArtifactGateError(
                f"{kind} Flutter split-debug symbols ({arch}) are not an ELF debug companion."
            )
        header = ELF64_HEADER_STRUCT.unpack_from(payload, 0)
        if int(header[2]) != expected_machine:
            raise LinuxArtifactGateError(
                f"{kind} Flutter split-debug symbols ({arch}) target the wrong ELF machine."
            )
        label = f"{kind} Flutter split-debug symbols ({arch})"
        sections = _elf_section_metadata(payload, label)
        if not {".symtab", ".strtab", ".debug_info", ".note.gnu.build-id"}.issubset(
            sections
        ):
            raise LinuxArtifactGateError(
                f"{kind} Flutter split-debug symbols ({arch}) are incomplete."
            )
        (
            _debug_index,
            debug_type,
            _debug_offset,
            debug_size,
            _debug_link,
            _debug_info,
            debug_entsize,
        ) = sections[".debug_info"]
        if debug_type != 1 or debug_size == 0 or debug_entsize != 0:
            raise LinuxArtifactGateError(
                f"{kind} Flutter split-debug symbols ({arch}) have invalid debug information."
            )
        (
            sym_index,
            sym_type,
            _sym_offset,
            sym_size,
            sym_link,
            sym_info,
            sym_entsize,
        ) = sections[".symtab"]
        (
            str_index,
            str_type,
            _str_offset,
            str_size,
            _str_link,
            _str_info,
            str_entsize,
        ) = sections[".strtab"]
        symbol_count = sym_size // 24 if sym_entsize == 24 else 0
        if (
            sym_index == 0
            or sym_type != 2
            or sym_size < 48
            or sym_size % 24 != 0
            or sym_entsize != 24
            or sym_link != str_index
            or sym_info <= 0
            or sym_info > symbol_count
            or str_type != 3
            or str_size <= 1
            or str_entsize != 0
        ):
            raise LinuxArtifactGateError(
                f"{kind} Flutter split-debug symbols ({arch}) have an invalid symbol table."
            )
        if _elf_gnu_build_id(payload, f"{kind} Flutter split-debug symbols ({arch})") != expected_build_id:
            raise LinuxArtifactGateError(
                f"{kind} Flutter split-debug symbols ({arch}) do not match the exact libapp build ID."
            )
        bundle = _retain_evidence_snapshot(
            _verify_signature(snapshot),
            f"{kind} Flutter split-debug symbols signature ({arch})",
        )
        retained.append(bundle)
        snapshot.reject_origin_swap()
        snapshot.rehash()
        return snapshot, bundle
    except BaseException:
        _close_retained_snapshots(retained)
        raise


def _verify_store_package_closure(
    snapshot: AuthenticatedSnapshot, arch: str, kind: str
) -> object:
    try:
        return _verify_build_provenance(snapshot, f"linux-{arch}")
    except LinuxArtifactGateError as exc:
        if "owner/build-system blocker" in str(exc):
            raise
        if (
            "exactly one current immutable Linux build receipt must bind the artifact"
            in str(exc)
            or "no immutable source/dependency closure binds"
            in str(exc)
        ):
            raise _owner_build_system_blocker(
                f"no immutable source/dependency closure binds the exact local {kind} "
                f"package for architecture {arch}"
            ) from exc
        raise


@_module_custody_guard
def verify_store_packages(target_id: str, raw_path: str) -> VerificationResult:
    _reject_test_only_production_pass()
    spec = STORE_MANIFEST_TARGETS.get(target_id)
    if spec is None:
        raise LinuxArtifactGateError(f"unsupported exact Linux store manifest target: {target_id}")
    appstream_version, _debian_version = _canonical_linux_versions()
    recipe = _secure_regular_repo_path(raw_path, f"{spec['kind']} store recipe")
    if recipe.name != spec["recipe_name"]:
        raise LinuxArtifactGateError(
            f"{spec['kind']} recipe filename belongs to another exact target."
        )
    recipe_snapshot = _snapshot_artifact(recipe, f"{spec['kind']} store recipe")
    retained: list[AuthenticatedSnapshot] = [recipe_snapshot]
    packages: dict[str, object] = {}
    package_digests: dict[str, str] = {}
    payload_identities: dict[str, dict[str, str]] = {}
    root = ROOT.resolve(strict=True)
    try:
        recipe_snapshot.reject_origin_swap()
        recipe_bytes = os.pread(recipe_snapshot.fd, recipe_snapshot.size, 0)
        _require_recipe_markers(recipe_bytes, spec["recipe_markers"], spec["kind"])
        recipe_sha256 = recipe_snapshot.digest
        for arch, machine in STORE_PACKAGE_ARCHITECTURES.items():
            package = _discover_store_package(
                recipe, arch, spec["package_name"], spec["kind"], target_id
            )
            package_snapshot = _snapshot_artifact(package, f"{spec['kind']} package ({arch})")
            retained.append(package_snapshot)
            inspected = _inspect_native_store_package(
                package_snapshot,
                kind=spec["kind"],
                prefix=spec["payload_prefix"],
                expected_machine=machine,
                expected_appstream_version=appstream_version,
                recipe_name=spec["recipe_name"],
                recipe_sha256=recipe_sha256,
                flutter=spec["flutter"],
            )
            bundle_snapshot = _retain_evidence_snapshot(
                _verify_signature(package_snapshot),
                f"{spec['kind']} Sigstore bundle ({arch})",
            )
            retained.append(bundle_snapshot)
            receipt_evidence = _retain_build_provenance_evidence(
                _verify_store_package_closure(
                    package_snapshot, arch, spec["kind"]
                ),
                f"{spec['kind']} build receipt ({arch})",
            )
            retained.extend(receipt_evidence)
            receipt_snapshot = receipt_evidence[0]
            symbols_evidence = _require_split_debug_symbols(
                spec["store_kind"],
                arch,
                spec["kind"],
                expected_machine=machine,
                expected_build_id=str(inspected["libapp_build_id"]),
            )
            retained.extend(symbols_evidence)
            symbols_snapshot, symbols_bundle_snapshot = symbols_evidence
            package_snapshot.reject_origin_swap()
            package_snapshot.rehash()
            package_digests[arch] = package_snapshot.digest
            payload_identities[arch] = inspected["payload_identities"]
            packages[arch] = {
                "artifact": package.resolve(strict=True).relative_to(root).as_posix(),
                "sha256": package_snapshot.digest,
                "bytes": package_snapshot.size,
                "elf_machine": machine,
                "files": inspected["files"],
                "split_debug_symbols": symbols_snapshot.origin.relative_to(root).as_posix(),
                "split_debug_symbols_sha256": symbols_snapshot.digest,
                "split_debug_symbols_bytes": symbols_snapshot.size,
                "split_debug_symbols_sigstore_bundle": symbols_bundle_snapshot.origin.relative_to(root).as_posix(),
                "libapp_sha256": inspected["payload_identities"]["libapp"],
                "libapp_build_id": inspected["libapp_build_id"],
                "build_receipt": receipt_snapshot.origin.relative_to(root).as_posix(),
                "sigstore_bundle": bundle_snapshot.origin.relative_to(root).as_posix(),
                "payload_identities": inspected["payload_identities"],
            }
        if package_digests["x64"] == package_digests["arm64"]:
            raise LinuxArtifactGateError(
                "x64/arm64 store package evidence cannot cross-bind; architectures must be distinct."
            )
        if payload_identities["x64"] == payload_identities["arm64"]:
            raise LinuxArtifactGateError(
                "x64/arm64 Winn payload identities cannot cross-bind; architectures must be distinct."
            )
        recipe_snapshot.reject_origin_swap()
        recipe_snapshot.rehash()
        _reject_test_only_production_pass()
        _require_owner_cosign_trust_anchor()
        _require_owner_store_tool_pins()
        result = {
            "ok": True,
            "target_id": target_id,
            "artifact": recipe.resolve(strict=True).relative_to(root).as_posix(),
            "sha256": recipe_snapshot.digest,
            "bytes": recipe_snapshot.size,
            "packages": packages,
            "manifest_only": False,
            "network_accessed": False,
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": "pending",
        }
        custody = VerificationResult(result, tuple(retained))
        retained = []
        return custody
    finally:
        _close_retained_snapshots(retained)


@_module_custody_guard
def verify_package(target_id: str, raw_path: str) -> VerificationResult:
    _reject_test_only_production_pass()
    target = TARGETS.get(target_id)
    if target is None:
        raise LinuxArtifactGateError(f"unsupported exact Linux package target: {target_id}")
    arch_label, elf_machine = target
    appstream_version, debian_version = _canonical_linux_versions()
    raw_name = pathlib.PurePosixPath(raw_path).name
    if raw_name.lower().endswith(".appimage"):
        raise LinuxArtifactGateError(
            "AppImage is not a 1.0.17+34 Linux upload target."
        )
    try:
        path = _secure_regular_repo_path(raw_path, "Linux package artifact")
    except LinuxArtifactGateError as suc:
        if "is missing" in str(suc):
            raise _owner_build_system_blocker(
                f"no exact local Linux package is bound to {target_id}"
            ) from suc
        raise
    if path.name != f"wins-vpn-linux-{arch_label}.tar.gz":
        raise LinuxArtifactGateError("Linux package filename belongs to another exact target.")
    snapshot = _snapshot_artifact(path, "Linux package artifact")
    retained: list[AuthenticatedSnapshot] = [snapshot]
    try:
        source_closure, source_freeze_snapshot = (
            _bind_native_host_source_freeze_custody()
        )
        retained.append(source_freeze_snapshot)
        archive = _inspect_archive(
            snapshot,
            arch_label,
            elf_machine,
            appstream_version,
            source_closure,
        )
        checksum_snapshot = _retain_evidence_snapshot(
            _verify_checksum(path, snapshot.digest), "Linux archive checksum"
        )
        retained.append(checksum_snapshot)
        bundle_snapshot = _retain_evidence_snapshot(
            _verify_signature(snapshot), "Linux Sigstore bundle"
        )
        retained.append(bundle_snapshot)
        receipt_evidence = _retain_build_provenance_evidence(
            _verify_build_provenance(snapshot, f"linux-{arch_label}"),
            "Linux build receipt",
        )
        retained.extend(receipt_evidence)
        receipt_snapshot = receipt_evidence[0]
        snapshot.reject_origin_swap()
        snapshot.rehash()
        _reject_test_only_production_pass()
        _require_owner_cosign_trust_anchor()
        root = ROOT.resolve(strict=True)
        result = {
            "ok": True,
            "target_id": target_id,
            "artifact": path.relative_to(root).as_posix(),
            "sha256": snapshot.digest,
            "bytes": snapshot.size,
            "files": archive["files"],
            "elf_machine": elf_machine,
            "appstream_version": archive["appstream_version"],
            "debian_version": debian_version,
            "checksum": checksum_snapshot.origin.relative_to(root).as_posix(),
            "sigstore_bundle": bundle_snapshot.origin.relative_to(root).as_posix(),
            "build_receipt": receipt_snapshot.origin.relative_to(root).as_posix(),
            "flutter_identities": archive["flutter_identities"],
            "network_accessed": False,
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": "pending",
        }
        custody = VerificationResult(result, tuple(retained))
        retained = []
        return custody
    finally:
        _close_retained_snapshots(retained)


@_module_custody_guard
def verify_held_release_artifact(
    *,
    target_id: str,
    source_fd: int,
    source_parent_fd: int,
    source_name: str,
    source_relative_path: str,
    expected_identity: tuple[int, ...],
    expected_size: int,
    expected_sha256: str,
    frozen_release: str,
) -> VerificationResult:
    """Verify the exact retained Linux release artifact before publication."""

    _reject_test_only_production_pass()
    target = TARGETS.get(target_id)
    if target is None or target_id not in {
        "linux-x64-package",
        "linux-arm64-package",
    }:
        raise LinuxArtifactGateError(
            f"unsupported exact held Linux package target: {target_id}"
        )
    if type(frozen_release) is not str or frozen_release != CANONICAL_RELEASE:
        raise LinuxArtifactGateError(
            "held Linux artifact release does not match the frozen canonical release."
        )
    arch_label, elf_machine = target
    expected_name = str(LINUX_PACKAGE_UPLOAD_TARGETS[target_id]["artifact_name"])
    if source_name != expected_name:
        raise LinuxArtifactGateError(
            "held Linux artifact filename belongs to another target or release."
        )
    appstream_version, debian_version = _canonical_linux_versions()
    if frozen_release != _linux_release_stamp():
        raise LinuxArtifactGateError(
            "held Linux artifact release identity is not current."
        )

    retained: list[AuthenticatedSnapshot] = []
    try:
        snapshot = _snapshot_held_artifact(
            source_fd=source_fd,
            source_parent_fd=source_parent_fd,
            source_name=source_name,
            source_relative_path=source_relative_path,
            expected_identity=expected_identity,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        )
        retained.append(snapshot)
        source_closure, source_freeze_snapshot = (
            _bind_native_host_source_freeze_custody()
        )
        retained.append(source_freeze_snapshot)
        archive = _inspect_archive(
            snapshot,
            arch_label,
            elf_machine,
            appstream_version,
            source_closure,
            held_strict=True,
        )
        checksum_snapshot = _retain_evidence_snapshot(
            _verify_checksum(snapshot.origin, snapshot.digest),
            "Linux archive checksum",
        )
        retained.append(checksum_snapshot)
        bundle_snapshot = _retain_evidence_snapshot(
            _verify_signature(snapshot), "Linux Sigstore bundle"
        )
        retained.append(bundle_snapshot)
        receipt_evidence = _retain_build_provenance_evidence(
            _verify_build_provenance(snapshot, f"linux-{arch_label}"),
            "Held Linux build receipt",
        )
        retained.extend(receipt_evidence)
        receipt_snapshot = receipt_evidence[0]
        snapshot.rehash()
        _reject_test_only_production_pass()
        _require_owner_cosign_trust_anchor()
        root = ROOT.resolve(strict=True)
        result = {
            "ok": True,
            "contract": HELD_ARTIFACT_CONTRACT,
            "target_id": target_id,
            "release": frozen_release,
            "artifact_name": source_name,
            "artifact_sha256": snapshot.digest,
            "artifact_bytes": snapshot.size,
            "artifact_identity": list(expected_identity),
            "elf_machine": elf_machine,
            "files": archive["files"],
            "appstream_version": archive["appstream_version"],
            "debian_version": debian_version,
            "runtime_protocol_order": ["winn-v3", "winn-v1"],
            "winn_v1_engines": ["awg", "awg-quick", "amneziawg-go", "xray"],
            "checksum": checksum_snapshot.origin.relative_to(root).as_posix(),
            "sigstore_bundle": bundle_snapshot.origin.relative_to(root).as_posix(),
            "build_receipt": receipt_snapshot.origin.relative_to(root).as_posix(),
            "signing_contract": LINUX_PACKAGE_UPLOAD_TARGETS[target_id][
                "signing_contract"
            ],
            "trust_anchor": TRUSTED_LOCAL_COSIGN_KEY.as_posix(),
            "network_accessed": False,
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": "pending",
        }
        custody = VerificationResult(result, tuple(retained))
        retained = []
        return custody
    finally:
        _close_retained_snapshots(retained)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) == 4 and arguments[0] == "--bind-upload-receipt":
        target_id, receipt_raw, artifact_raw = arguments[1:]
        receipt_path = _secure_regular_repo_path(
            receipt_raw, f"{target_id} upload receipt"
        )
        artifact_path = _secure_regular_repo_path(
            artifact_raw, f"{target_id} upload candidate"
        )
        receipt_snapshot = _snapshot_artifact(
            receipt_path, f"{target_id} upload receipt"
        )
        artifact_snapshot = _snapshot_artifact(
            artifact_path, f"{target_id} upload candidate"
        )
        retained = [receipt_snapshot, artifact_snapshot]
        try:
            receipt = _strict_json_object(
                os.pread(receipt_snapshot.fd, receipt_snapshot.size, 0),
                f"{target_id} upload receipt",
            )
            artifact_record = receipt.get("artifact")
            if (
                type(artifact_record) is not dict
                or artifact_record.get("path") != artifact_raw
            ):
                raise LinuxArtifactGateError(
                    f"{target_id} upload receipt does not name the exact CLI candidate."
                )
            result = bind_package_upload_receipt(
                target_id,
                receipt,
                artifact_sha256=artifact_snapshot.digest,
                artifact_bytes=artifact_snapshot.size,
            )
            receipt_snapshot.rehash()
            artifact_snapshot.rehash()
            print(json.dumps(result, sort_keys=True, allow_nan=False))
            return 0
        finally:
            _close_retained_snapshots(retained)
    if len(arguments) != 3 or arguments[0] != "--verify":
        raise LinuxArtifactGateError(
            "canonical cross-store usage is exactly --verify <target-id> <artifact-path> "
            "or --bind-upload-receipt <target-id> <receipt-path> <artifact-path>"
        )
    if arguments[1] in STORE_MANIFEST_TARGETS:
        result = verify_store_packages(arguments[1], arguments[2])
    else:
        result = verify_package(arguments[1], arguments[2])
    with result:
        print(
            json.dumps(
                result.publication_payload(), sort_keys=True, allow_nan=False
            )
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LinuxArtifactGateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
