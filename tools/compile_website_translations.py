#!/usr/bin/env python3
"""Compile contract-bound website locale sources without translating content.

Production invocation requires the reviewed contract and validator bytes pinned
below. The caller must explicitly choose read-only verification or creation of
an absent canonical aggregate. Existing output is never overwritten directly.
"""

from __future__ import annotations

import argparse
import _posixsubprocess
import ctypes
import errno
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import select
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any


PRODUCTION_CONTRACT_PATH = "localization/website/contract.json"
PRODUCTION_CONTRACT_SHA256 = (
    "9ec1a8a461fb17ada914b0626a2561c3d85a1dc6a20585ffaac2ddb454b45b45"
)
PRODUCTION_VALIDATOR_PATH = "tools/website_localization_contract.py"
PRODUCTION_VALIDATOR_SHA256 = (
    "9a70d57928e534da00f117ac168fb5bfacc5e321c6180be1c2346540e36e6172"
)
PRODUCTION_AUDIT_SHA256 = (
    "556cd4026cb0b50616c8382d2e83da97c96151c7fad5835d538a02599e106b70"
)
PRODUCTION_AUDIT_PATH = "tools/audit_website_translations.py"
PRODUCTION_COMPILER_PATH = "tools/compile_website_translations.py"
EXPECTED_OUTPUT_PATH = "web/i18n/major.json"
EXPECTED_LOCALE_DIRECTORY = "localization/website/locales"
RELEASE_PYTHON_LAUNCHER = "/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3"
RELEASE_PYTHON_EXECUTABLE = (
    "/Library/WinsVPN/ReleasePython/3.14.7/Python.framework/Versions/3.14/"
    "bin/python3.14"
)
RELEASE_PYTHON_BASE_EXECUTABLE = RELEASE_PYTHON_EXECUTABLE
RELEASE_PYTHON_PREFIX = (
    "/Library/WinsVPN/ReleasePython/3.14.7/Python.framework/Versions/3.14"
)
RELEASE_PYTHON_PATH = (
    f"{RELEASE_PYTHON_PREFIX}/lib/python314.zip",
    f"{RELEASE_PYTHON_PREFIX}/lib/python3.14",
    f"{RELEASE_PYTHON_PREFIX}/lib/python3.14/lib-dynload",
)
WORKER_PROTOCOL = "winsvpn-website-translation-worker-v1"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
MAX_CONTROL_BYTES = 128 * 1024
WORKER_TIMEOUT_SECONDS = 120


class WebsiteTranslationCompilerError(RuntimeError):
    """Raised when compilation crosses a bound filesystem or data contract."""


@dataclass(frozen=True)
class ContractBinding:
    contract_path: str
    contract_sha256: str
    validator_path: str
    validator_sha256: str


PRODUCTION_BINDING = ContractBinding(
    contract_path=PRODUCTION_CONTRACT_PATH,
    contract_sha256=PRODUCTION_CONTRACT_SHA256,
    validator_path=PRODUCTION_VALIDATOR_PATH,
    validator_sha256=PRODUCTION_VALIDATOR_SHA256,
)


@dataclass(frozen=True)
class CompilationResult:
    mode: str
    output_path: str
    locale_count: int
    key_count: int
    payload_sha256: str
    payload_size: int


@dataclass
class _DirectoryHandle:
    relative_path: str
    fd: int
    identity: tuple[int, int]
    parent_path: str | None
    name: str | None


@dataclass
class _AncestorHandle:
    absolute_path: str
    fd: int
    identity: tuple[int, int]
    fingerprint: tuple[int, ...]
    parent_index: int | None
    name: str | None


@dataclass
class _FileHandle:
    relative_path: str
    fd: int
    identity: tuple[int, int]
    fingerprint: tuple[int, ...]
    parent_path: str
    name: str
    payload: bytes


@dataclass(frozen=True)
class _InvokedCompilerBinding:
    fd: int
    fingerprint: tuple[int, ...]
    payload: bytes
    executed_from_descriptor: bool


@dataclass(frozen=True)
class _SynthesizedContract:
    document: dict[str, object]
    audit_path: str
    audit_sha256: str


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _retain_invoked_compiler() -> _InvokedCompilerBinding:
    descriptor_prefix = "/dev/fd/"
    executed_from_descriptor = (
        __file__.startswith(descriptor_prefix)
        and __file__[len(descriptor_prefix):].isdigit()
    )
    descriptor = -1
    try:
        if executed_from_descriptor:
            descriptor = int(__file__[len(descriptor_prefix):], 10)
        else:
            nofollow = getattr(os, "O_NOFOLLOW", None)
            if nofollow is None:
                raise WebsiteTranslationCompilerError(
                    "externally invoked compiler descriptor custody is unavailable"
                )
            descriptor = os.open(
                __file__,
                os.O_RDONLY
                | nofollow
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_INPUT_BYTES
        ):
            raise WebsiteTranslationCompilerError(
                "externally invoked compiler descriptor is invalid"
            )
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(
                descriptor,
                min(READ_CHUNK_BYTES, before.st_size - offset),
                offset,
            )
            if not chunk:
                raise WebsiteTranslationCompilerError(
                    "externally invoked compiler descriptor ended early"
                )
            chunks.append(chunk)
            offset += len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if _file_fingerprint(before) != _file_fingerprint(after):
            raise WebsiteTranslationCompilerError(
                "externally invoked compiler descriptor changed during binding"
            )
        if not executed_from_descriptor:
            entry = os.stat(__file__, follow_symlinks=False)
            if _file_fingerprint(entry) != _file_fingerprint(after):
                raise WebsiteTranslationCompilerError(
                    "externally invoked compiler path changed during binding"
                )
    except WebsiteTranslationCompilerError:
        if descriptor >= 0 and not executed_from_descriptor:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0 and not executed_from_descriptor:
            os.close(descriptor)
        raise WebsiteTranslationCompilerError(
            "unable to bind the externally invoked compiler bytes"
        ) from exc
    if not payload or len(payload) > MAX_INPUT_BYTES:
        raise WebsiteTranslationCompilerError(
            "externally invoked compiler bytes are invalid"
        )
    return _InvokedCompilerBinding(
        fd=descriptor,
        fingerprint=_file_fingerprint(after),
        payload=payload,
        executed_from_descriptor=executed_from_descriptor,
    )


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return (metadata.st_dev, metadata.st_ino)


def _file_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


INVOKED_COMPILER = _retain_invoked_compiler()
INVOKED_COMPILER_SHA256 = _sha256(INVOKED_COMPILER.payload)
_BOUND_POPEN = subprocess.Popen
_BOUND_POPEN_INIT = subprocess.Popen.__init__
_BOUND_POPEN_EXECUTE_CHILD = subprocess.Popen._execute_child
_BOUND_POPEN_POSIX_SPAWN = subprocess.Popen._posix_spawn
_BOUND_FORK_EXEC = subprocess._fork_exec


def _safe_relative_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise WebsiteTranslationCompilerError(f"{label} is not a safe relative path")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or parsed.as_posix() != value
        or not parsed.parts
        or any(part in ("", ".", "..") for part in parsed.parts)
    ):
        raise WebsiteTranslationCompilerError(f"{label} is not a safe relative path")
    return value


def _require_sha256(value: str, *, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise WebsiteTranslationCompilerError(f"{label} is not lowercase SHA-256")


class _SecureRepository:
    """Retain descriptor custody for every path used by one compilation."""

    def __init__(self, repo: Path) -> None:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise WebsiteTranslationCompilerError(
                "this platform cannot enforce no-follow repository access"
            )
        self._nofollow = nofollow
        self._directory = directory
        self._cloexec = getattr(os, "O_CLOEXEC", 0)
        self._nonblock = getattr(os, "O_NONBLOCK", 0)
        directory_flags = (
            os.O_RDONLY
            | self._nofollow
            | self._directory
            | self._cloexec
            | self._nonblock
        )
        try:
            raw_repo = os.fspath(repo)
        except TypeError as exc:
            raise WebsiteTranslationCompilerError(
                "repository root is not a filesystem path"
            ) from exc
        if not isinstance(raw_repo, str) or not raw_repo or "\x00" in raw_repo:
            raise WebsiteTranslationCompilerError(
                "repository root is not a safe text path"
            )

        opened: list[int] = []
        cwd_guard: tuple[int, tuple[int, int], tuple[int, ...]] | None = None
        try:
            if raw_repo.startswith("/"):
                absolute_path = raw_repo
                cwd_parts: tuple[str, ...] | None = None
            else:
                cwd_fd = os.open(".", directory_flags)
                opened.append(cwd_fd)
                cwd_metadata = os.fstat(cwd_fd)
                if not stat.S_ISDIR(cwd_metadata.st_mode):
                    raise WebsiteTranslationCompilerError(
                        "current directory custody is not a directory"
                    )
                cwd_guard = (
                    cwd_fd,
                    _identity(cwd_metadata),
                    _file_fingerprint(cwd_metadata),
                )
                cwd_path = os.getcwd()
                cwd_parts = tuple(part for part in cwd_path.split("/") if part)
                relative_parts = () if raw_repo == "." else tuple(raw_repo.split("/"))
                if any(part in ("", ".", "..") for part in relative_parts):
                    raise WebsiteTranslationCompilerError(
                        "repository root must be a canonical relative path"
                    )
                absolute_parts = cwd_parts + relative_parts
                absolute_path = "/" + "/".join(absolute_parts)

            if absolute_path == "/" or not absolute_path.startswith("/"):
                raise WebsiteTranslationCompilerError(
                    "repository root must be a non-root absolute directory"
                )
            absolute_parts = tuple(absolute_path[1:].split("/"))
            if (
                not absolute_parts
                or any(part in ("", ".", "..") for part in absolute_parts)
                or absolute_path != "/" + "/".join(absolute_parts)
            ):
                raise WebsiteTranslationCompilerError(
                    "repository root must be a canonical absolute path"
                )

            slash_fd = os.open("/", directory_flags)
            opened.append(slash_fd)
            slash_metadata = os.fstat(slash_fd)
            if not stat.S_ISDIR(slash_metadata.st_mode):
                raise WebsiteTranslationCompilerError(
                    "filesystem root custody is not a directory"
                )
            ancestors = [
                _AncestorHandle(
                    absolute_path="/",
                    fd=slash_fd,
                    identity=_identity(slash_metadata),
                    fingerprint=_file_fingerprint(slash_metadata),
                    parent_index=None,
                    name=None,
                )
            ]
            parent_fd = slash_fd
            current_path = ""
            for component in absolute_parts:
                descriptor = os.open(component, directory_flags, dir_fd=parent_fd)
                opened.append(descriptor)
                metadata = os.fstat(descriptor)
                entry = os.stat(
                    component,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or not stat.S_ISDIR(entry.st_mode)
                    or _identity(metadata) != _identity(entry)
                ):
                    raise WebsiteTranslationCompilerError(
                        "repository ancestor identity is unsafe"
                    )
                current_path = f"{current_path}/{component}"
                ancestors.append(
                    _AncestorHandle(
                        absolute_path=current_path,
                        fd=descriptor,
                        identity=_identity(metadata),
                        fingerprint=_file_fingerprint(metadata),
                        parent_index=len(ancestors) - 1,
                        name=component,
                    )
                )
                parent_fd = descriptor

            if cwd_guard is not None:
                assert cwd_parts is not None
                cwd_ancestor = ancestors[len(cwd_parts)]
                if cwd_ancestor.identity != cwd_guard[1]:
                    raise WebsiteTranslationCompilerError(
                        "current directory changed during repository selection"
                    )
            root_fd = ancestors[-1].fd
            root_metadata = os.fstat(root_fd)
        except WebsiteTranslationCompilerError:
            for descriptor in reversed(tuple(dict.fromkeys(opened))):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        except OSError as exc:
            for descriptor in reversed(tuple(dict.fromkeys(opened))):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise WebsiteTranslationCompilerError(
                "repository root or ancestor is unsafe or unavailable"
            ) from exc

        self.root_path = absolute_path
        self._ancestors = ancestors
        self._cwd_guard = cwd_guard
        self._directories: dict[str, _DirectoryHandle] = {
            "": _DirectoryHandle(
                relative_path="",
                fd=root_fd,
                identity=_identity(root_metadata),
                parent_path=None,
                name=None,
            )
        }
        self._files: list[_FileHandle] = []
        self._retained_outputs: list[
            tuple[int, int, str, tuple[int, int], bytes]
        ] = []
        self._inventories: dict[
            str,
            tuple[tuple[str, ...], tuple[int, ...]],
        ] = {}
        self._locked_directories: set[str] = set()
        self._owns_locks = True
        self._closed = False

    def __enter__(self) -> _SecureRepository:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for handle in reversed(self._files):
            try:
                os.close(handle.fd)
            except OSError:
                pass
        for descriptor, _, _, _, _ in reversed(self._retained_outputs):
            try:
                os.close(descriptor)
            except OSError:
                pass
        for handle in self._directories.values():
            try:
                if (
                    self._owns_locks
                    and handle.relative_path in self._locked_directories
                ):
                    fcntl.flock(handle.fd, fcntl.LOCK_UN)
            except OSError:
                pass
        descriptors = [handle.fd for handle in self._directories.values()]
        descriptors.extend(handle.fd for handle in self._ancestors)
        if self._cwd_guard is not None:
            descriptors.append(self._cwd_guard[0])
        for descriptor in reversed(tuple(dict.fromkeys(descriptors))):
            try:
                os.close(descriptor)
            except OSError:
                pass

    def export_custody(self) -> dict[str, object]:
        if self._closed:
            raise WebsiteTranslationCompilerError(
                "cannot export closed repository custody"
            )
        cwd_guard: dict[str, object] | None = None
        if self._cwd_guard is not None:
            cwd_guard = {
                "fd": self._cwd_guard[0],
                "identity": list(self._cwd_guard[1]),
                "fingerprint": list(self._cwd_guard[2]),
            }
        return {
            "root_path": self.root_path,
            "ancestors": [
                {
                    "absolute_path": handle.absolute_path,
                    "fd": handle.fd,
                    "identity": list(handle.identity),
                    "fingerprint": list(handle.fingerprint),
                    "parent_index": handle.parent_index,
                    "name": handle.name,
                }
                for handle in self._ancestors
            ],
            "cwd_guard": cwd_guard,
            "directories": [
                {
                    "relative_path": handle.relative_path,
                    "fd": handle.fd,
                    "identity": list(handle.identity),
                    "parent_path": handle.parent_path,
                    "name": handle.name,
                }
                for handle in self._directories.values()
            ],
            "locked_directories": sorted(self._locked_directories),
        }

    def inherited_descriptors(self) -> tuple[int, ...]:
        descriptors = [handle.fd for handle in self._ancestors]
        descriptors.extend(handle.fd for handle in self._directories.values())
        descriptors.extend(handle.fd for handle in self._files)
        if self._cwd_guard is not None:
            descriptors.append(self._cwd_guard[0])
        return tuple(dict.fromkeys(descriptors))

    def retain_output_until_close(
        self,
        fd: int,
        directory_fd: int,
        name: str,
        identity: tuple[int, int],
        expected_payload: bytes,
    ) -> None:
        if (
            self._closed
            or fd < 0
            or any(item[0] == fd for item in self._retained_outputs)
        ):
            raise WebsiteTranslationCompilerError(
                "compiler output descriptor cannot be retained"
            )
        self._retained_outputs.append(
            (fd, directory_fd, name, identity, expected_payload)
        )

    def verify_retained_outputs(self) -> None:
        for fd, directory_fd, name, identity, expected_payload in (
            self._retained_outputs
        ):
            _assert_retained_output_exact(
                self,
                directory_fd,
                name,
                fd,
                identity,
                expected_payload,
            )

    def cleanup_retained_outputs(self) -> None:
        retained = self._retained_outputs
        self._retained_outputs = []
        for fd, directory_fd, name, identity, _ in retained:
            try:
                cleaned = _capture_and_unlink_owned_entry(
                    directory_fd,
                    name,
                    fd,
                    identity,
                    output_name=PurePosixPath(EXPECTED_OUTPUT_PATH).name,
                )
                if cleaned:
                    os.fsync(directory_fd)
            except OSError as exc:
                raise WebsiteTranslationCompilerError(
                    "unable to durably clean unacknowledged compiler output"
                ) from exc
            finally:
                os.close(fd)

    @staticmethod
    def export_file_handle(handle: _FileHandle) -> dict[str, object]:
        return {
            "relative_path": handle.relative_path,
            "fd": handle.fd,
            "identity": list(handle.identity),
            "fingerprint": list(handle.fingerprint),
            "parent_path": handle.parent_path,
            "name": handle.name,
        }

    @staticmethod
    def _pair(value: object, *, label: str) -> tuple[int, int]:
        if (
            not isinstance(value, list)
            or len(value) != 2
            or any(type(item) is not int or item < 0 for item in value)
        ):
            raise WebsiteTranslationCompilerError(
                f"isolated worker {label} is invalid"
            )
        return (value[0], value[1])

    @staticmethod
    def _fingerprint(value: object, *, label: str) -> tuple[int, ...]:
        if (
            not isinstance(value, list)
            or len(value) != 9
            or any(type(item) is not int for item in value)
        ):
            raise WebsiteTranslationCompilerError(
                f"isolated worker {label} is invalid"
            )
        return tuple(value)

    @classmethod
    def from_custody(cls, document: object) -> _SecureRepository:
        if not isinstance(document, dict) or tuple(document) != (
            "root_path",
            "ancestors",
            "cwd_guard",
            "directories",
            "locked_directories",
        ):
            raise WebsiteTranslationCompilerError(
                "isolated worker repository custody is malformed"
            )
        instance = object.__new__(cls)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise WebsiteTranslationCompilerError(
                "this platform cannot enforce inherited repository custody"
            )
        root_path = document["root_path"]
        if not isinstance(root_path, str) or not root_path.startswith("/"):
            raise WebsiteTranslationCompilerError(
                "isolated worker repository root is invalid"
            )
        ancestor_documents = document["ancestors"]
        if not isinstance(ancestor_documents, list) or not ancestor_documents:
            raise WebsiteTranslationCompilerError(
                "isolated worker ancestor custody is empty"
            )
        ancestors: list[_AncestorHandle] = []
        for index, item in enumerate(ancestor_documents):
            if not isinstance(item, dict) or tuple(item) != (
                "absolute_path",
                "fd",
                "identity",
                "fingerprint",
                "parent_index",
                "name",
            ):
                raise WebsiteTranslationCompilerError(
                    "isolated worker ancestor custody is malformed"
                )
            fd = item["fd"]
            parent_index = item["parent_index"]
            name = item["name"]
            absolute_path = item["absolute_path"]
            if (
                type(fd) is not int
                or fd < 0
                or not isinstance(absolute_path, str)
                or (
                    index == 0
                    and (parent_index is not None or name is not None)
                )
                or (
                    index > 0
                    and (
                        parent_index != index - 1
                        or not isinstance(name, str)
                        or name in ("", ".", "..")
                        or "/" in name
                    )
                )
            ):
                raise WebsiteTranslationCompilerError(
                    "isolated worker ancestor custody values are invalid"
                )
            ancestors.append(
                _AncestorHandle(
                    absolute_path=absolute_path,
                    fd=fd,
                    identity=cls._pair(item["identity"], label="ancestor identity"),
                    fingerprint=cls._fingerprint(
                        item["fingerprint"],
                        label="ancestor fingerprint",
                    ),
                    parent_index=parent_index,
                    name=name,
                )
            )
        if ancestors[-1].absolute_path != root_path:
            raise WebsiteTranslationCompilerError(
                "isolated worker root does not match ancestor custody"
            )

        directory_documents = document["directories"]
        if not isinstance(directory_documents, list) or not directory_documents:
            raise WebsiteTranslationCompilerError(
                "isolated worker directory custody is empty"
            )
        directories: dict[str, _DirectoryHandle] = {}
        for item in directory_documents:
            if not isinstance(item, dict) or tuple(item) != (
                "relative_path",
                "fd",
                "identity",
                "parent_path",
                "name",
            ):
                raise WebsiteTranslationCompilerError(
                    "isolated worker directory custody is malformed"
                )
            relative_path = item["relative_path"]
            fd = item["fd"]
            parent_path = item["parent_path"]
            name = item["name"]
            if (
                not isinstance(relative_path, str)
                or type(fd) is not int
                or fd < 0
                or relative_path in directories
                or (
                    relative_path == ""
                    and (parent_path is not None or name is not None)
                )
                or (
                    relative_path != ""
                    and (
                        not isinstance(parent_path, str)
                        or parent_path not in directories
                        or not isinstance(name, str)
                    )
                )
            ):
                raise WebsiteTranslationCompilerError(
                    "isolated worker directory custody values are invalid"
                )
            directories[relative_path] = _DirectoryHandle(
                relative_path=relative_path,
                fd=fd,
                identity=cls._pair(item["identity"], label="directory identity"),
                parent_path=parent_path,
                name=name,
            )
        if directories[""].fd != ancestors[-1].fd:
            raise WebsiteTranslationCompilerError(
                "isolated worker root descriptor is inconsistent"
            )

        cwd_document = document["cwd_guard"]
        cwd_guard: tuple[int, tuple[int, int], tuple[int, ...]] | None = None
        if cwd_document is not None:
            if not isinstance(cwd_document, dict) or tuple(cwd_document) != (
                "fd",
                "identity",
                "fingerprint",
            ):
                raise WebsiteTranslationCompilerError(
                    "isolated worker current-directory custody is malformed"
                )
            cwd_fd = cwd_document["fd"]
            if type(cwd_fd) is not int or cwd_fd < 0:
                raise WebsiteTranslationCompilerError(
                    "isolated worker current-directory descriptor is invalid"
                )
            cwd_guard = (
                cwd_fd,
                cls._pair(cwd_document["identity"], label="cwd identity"),
                cls._fingerprint(
                    cwd_document["fingerprint"],
                    label="cwd fingerprint",
                ),
            )
        locked = document["locked_directories"]
        if (
            not isinstance(locked, list)
            or any(not isinstance(item, str) or item not in directories for item in locked)
        ):
            raise WebsiteTranslationCompilerError(
                "isolated worker directory locks are malformed"
            )

        instance._nofollow = nofollow
        instance._directory = directory
        instance._cloexec = getattr(os, "O_CLOEXEC", 0)
        instance._nonblock = getattr(os, "O_NONBLOCK", 0)
        instance.root_path = root_path
        instance._ancestors = ancestors
        instance._cwd_guard = cwd_guard
        instance._directories = directories
        instance._files = []
        instance._retained_outputs = []
        instance._inventories = {}
        instance._locked_directories = set(locked)
        instance._owns_locks = False
        instance._closed = False
        instance.assert_stable()
        return instance

    def adopt_file(self, document: object, *, expected_path: str) -> _FileHandle:
        if not isinstance(document, dict) or tuple(document) != (
            "relative_path",
            "fd",
            "identity",
            "fingerprint",
            "parent_path",
            "name",
        ):
            raise WebsiteTranslationCompilerError(
                "isolated worker file custody is malformed"
            )
        relative_path = document["relative_path"]
        fd = document["fd"]
        parent_path = document["parent_path"]
        name = document["name"]
        if (
            relative_path != expected_path
            or type(fd) is not int
            or fd < 0
            or not isinstance(parent_path, str)
            or parent_path not in self._directories
            or not isinstance(name, str)
            or PurePosixPath(expected_path).name != name
        ):
            raise WebsiteTranslationCompilerError(
                "isolated worker file custody values are invalid"
            )
        identity = self._pair(document["identity"], label="file identity")
        fingerprint = self._fingerprint(
            document["fingerprint"],
            label="file fingerprint",
        )
        parent = self._directories[parent_path]
        try:
            before = os.fstat(fd)
            entry = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                f"inherited repository file is unavailable: {expected_path}"
            ) from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _identity(before) != identity
            or _identity(entry) != identity
            or _file_fingerprint(before) != fingerprint
            or _file_fingerprint(entry) != fingerprint
        ):
            raise WebsiteTranslationCompilerError(
                f"inherited repository file changed: {expected_path}"
            )
        payload = self._read_descriptor(
            fd,
            maximum=MAX_INPUT_BYTES,
            label=expected_path,
        )
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            len(payload) != after.st_size
            or _file_fingerprint(after) != fingerprint
            or _file_fingerprint(current) != fingerprint
        ):
            raise WebsiteTranslationCompilerError(
                f"inherited repository file changed while read: {expected_path}"
            )
        handle = _FileHandle(
            relative_path=expected_path,
            fd=fd,
            identity=identity,
            fingerprint=fingerprint,
            parent_path=parent_path,
            name=name,
            payload=payload,
        )
        self._files.append(handle)
        self._assert_inventories_stable()
        return handle

    def open_directory(self, relative_path: str) -> _DirectoryHandle:
        relative = _safe_relative_path(relative_path, label="repository directory")
        current_path = ""
        for component in PurePosixPath(relative).parts:
            child_path = f"{current_path}/{component}" if current_path else component
            if child_path in self._directories:
                current_path = child_path
                continue
            parent = self._directories[current_path]
            descriptor = -1
            try:
                descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | self._nofollow
                    | self._directory
                    | self._cloexec
                    | self._nonblock,
                    dir_fd=parent.fd,
                )
                metadata = os.fstat(descriptor)
                entry = os.stat(component, dir_fd=parent.fd, follow_symlinks=False)
            except OSError as exc:
                if descriptor >= 0:
                    os.close(descriptor)
                raise WebsiteTranslationCompilerError(
                    f"repository directory is unsafe or unavailable: {child_path}"
                ) from exc
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or not stat.S_ISDIR(entry.st_mode)
                or _identity(metadata) != _identity(entry)
            ):
                os.close(descriptor)
                raise WebsiteTranslationCompilerError(
                    f"repository directory identity is unsafe: {child_path}"
                )
            self._directories[child_path] = _DirectoryHandle(
                relative_path=child_path,
                fd=descriptor,
                identity=_identity(metadata),
                parent_path=current_path,
                name=component,
            )
            current_path = child_path
        return self._directories[relative]

    def lock_directory(self, relative_path: str) -> _DirectoryHandle:
        handle = self.open_directory(relative_path)
        if relative_path not in self._locked_directories:
            try:
                fcntl.flock(handle.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise WebsiteTranslationCompilerError(
                    f"another compiler owns repository directory: {relative_path}"
                ) from exc
            self._locked_directories.add(relative_path)
        return handle

    @staticmethod
    def _read_descriptor(fd: int, *, maximum: int, label: str) -> bytes:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(READ_CHUNK_BYTES, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    raise WebsiteTranslationCompilerError(
                        f"repository file is too large: {label}"
                    )
            return b"".join(chunks)
        except WebsiteTranslationCompilerError:
            raise
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                f"unable to read descriptor-bound file: {label}"
            ) from exc

    def open_file(
        self,
        relative_path: str,
        *,
        maximum: int = MAX_INPUT_BYTES,
    ) -> _FileHandle:
        relative = _safe_relative_path(relative_path, label="repository file")
        parsed = PurePosixPath(relative)
        parent_path = parsed.parent.as_posix()
        if parent_path == ".":
            parent_path = ""
        parent = (
            self._directories[""]
            if not parent_path
            else self.open_directory(parent_path)
        )
        name = parsed.name
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | self._nofollow
                | self._cloexec
                | self._nonblock,
                dir_fd=parent.fd,
            )
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise WebsiteTranslationCompilerError(
                    f"repository file identity is unsafe: {relative}"
                )
            entry = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        except WebsiteTranslationCompilerError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise WebsiteTranslationCompilerError(
                f"repository file is unsafe or unavailable: {relative}"
            ) from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(entry.st_mode)
            or before.st_nlink != 1
            or _identity(before) != _identity(entry)
            or before.st_size < 0
            or before.st_size > maximum
        ):
            os.close(descriptor)
            raise WebsiteTranslationCompilerError(
                f"repository file identity is unsafe: {relative}"
            )
        try:
            payload = self._read_descriptor(descriptor, maximum=maximum, label=relative)
            after = os.fstat(descriptor)
            current_entry = os.stat(
                name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
        except Exception:
            os.close(descriptor)
            raise
        if (
            _file_fingerprint(before) != _file_fingerprint(after)
            or _file_fingerprint(before) != _file_fingerprint(current_entry)
            or not stat.S_ISREG(current_entry.st_mode)
            or current_entry.st_nlink != 1
            or len(payload) != after.st_size
        ):
            os.close(descriptor)
            raise WebsiteTranslationCompilerError(
                f"repository file changed while read: {relative}"
            )
        handle = _FileHandle(
            relative_path=relative,
            fd=descriptor,
            identity=_identity(after),
            fingerprint=_file_fingerprint(after),
            parent_path=parent_path,
            name=name,
            payload=payload,
        )
        self._files.append(handle)
        self._assert_inventories_stable()
        return handle

    def bind_exact_inventory(
        self,
        relative_path: str,
        expected_names: set[str],
    ) -> _DirectoryHandle:
        directory = self.open_directory(relative_path)
        try:
            before = os.fstat(directory.fd)
            actual = tuple(sorted(os.listdir(directory.fd)))
            after = os.fstat(directory.fd)
            self._assert_directory_stable(directory)
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                f"unable to enumerate locale source directory: {relative_path}"
            ) from exc
        if _file_fingerprint(before) != _file_fingerprint(after):
            raise WebsiteTranslationCompilerError(
                f"locale source inventory changed while listed: {relative_path}"
            )
        expected = tuple(sorted(expected_names))
        if actual != expected:
            missing = sorted(expected_names - set(actual))
            extra = sorted(set(actual) - expected_names)
            raise WebsiteTranslationCompilerError(
                "locale source inventory mismatch: "
                f"missing={missing!r} extra={extra!r}"
            )
        self._inventories[relative_path] = (
            expected,
            _file_fingerprint(after),
        )
        return directory

    def _assert_ancestor_stable(self, handle: _AncestorHandle) -> None:
        try:
            descriptor_metadata = os.fstat(handle.fd)
            if handle.parent_index is None:
                entry = descriptor_metadata
            else:
                parent = self._ancestors[handle.parent_index]
                entry = os.stat(
                    handle.name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                f"repository ancestor changed during compilation: {handle.absolute_path}"
            ) from exc
        # Entries elsewhere in a shared ancestor legitimately change its
        # timestamps. They cannot redirect descriptor-relative repository
        # access. Retain exact identity custody for those ancestors and reserve
        # the mutation fingerprint for the repository root, where it detects a
        # swap-and-restore of the selected repository itself.
        require_fingerprint = handle is self._ancestors[-1]
        if (
            not stat.S_ISDIR(descriptor_metadata.st_mode)
            or not stat.S_ISDIR(entry.st_mode)
            or _identity(descriptor_metadata) != handle.identity
            or _identity(entry) != handle.identity
            or (
                require_fingerprint
                and (
                    _file_fingerprint(descriptor_metadata) != handle.fingerprint
                    or _file_fingerprint(entry) != handle.fingerprint
                )
            )
        ):
            raise WebsiteTranslationCompilerError(
                f"repository ancestor changed during compilation: {handle.absolute_path}"
            )

    def _assert_cwd_guard_stable(self) -> None:
        if self._cwd_guard is None:
            return
        descriptor, identity, fingerprint = self._cwd_guard
        try:
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                "current directory custody changed during compilation"
            ) from exc
        require_fingerprint = identity == self._ancestors[-1].identity
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or _identity(metadata) != identity
            or (
                require_fingerprint
                and _file_fingerprint(metadata) != fingerprint
            )
        ):
            raise WebsiteTranslationCompilerError(
                "current directory custody changed during compilation"
            )

    def _assert_directory_stable(self, handle: _DirectoryHandle) -> None:
        try:
            descriptor_metadata = os.fstat(handle.fd)
            if handle.parent_path is None:
                entry = descriptor_metadata
            else:
                parent = self._directories[handle.parent_path]
                entry = os.stat(
                    handle.name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
        except OSError as exc:
            label = handle.relative_path or "."
            raise WebsiteTranslationCompilerError(
                f"repository directory changed during compilation: {label}"
            ) from exc
        if (
            not stat.S_ISDIR(descriptor_metadata.st_mode)
            or not stat.S_ISDIR(entry.st_mode)
            or _identity(descriptor_metadata) != handle.identity
            or _identity(entry) != handle.identity
        ):
            label = handle.relative_path or "."
            raise WebsiteTranslationCompilerError(
                f"repository directory changed during compilation: {label}"
            )

    def _assert_inventory_stable(self, relative_path: str) -> None:
        expected, fingerprint = self._inventories[relative_path]
        directory = self._directories[relative_path]
        try:
            before = os.fstat(directory.fd)
            actual = tuple(sorted(os.listdir(directory.fd)))
            after = os.fstat(directory.fd)
            self._assert_directory_stable(directory)
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                f"locale source inventory changed: {relative_path}"
            ) from exc
        if (
            actual != expected
            or _file_fingerprint(before) != fingerprint
            or _file_fingerprint(after) != fingerprint
        ):
            raise WebsiteTranslationCompilerError(
                f"locale source inventory changed: {relative_path}"
            )

    def _assert_inventories_stable(self) -> None:
        for relative_path in self._inventories:
            self._assert_inventory_stable(relative_path)

    def _assert_file_snapshot(self, handle: _FileHandle) -> None:
        parent = self._directories[handle.parent_path]
        try:
            descriptor_metadata = os.fstat(handle.fd)
            entry = os.stat(
                handle.name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                f"repository file changed during compilation: {handle.relative_path}"
            ) from exc
        if (
            not stat.S_ISREG(descriptor_metadata.st_mode)
            or not stat.S_ISREG(entry.st_mode)
            or descriptor_metadata.st_nlink != 1
            or entry.st_nlink != 1
            or _identity(descriptor_metadata) != handle.identity
            or _identity(entry) != handle.identity
            or _file_fingerprint(descriptor_metadata) != handle.fingerprint
            or _file_fingerprint(entry) != handle.fingerprint
        ):
            raise WebsiteTranslationCompilerError(
                f"repository file changed during compilation: {handle.relative_path}"
            )

    def _assert_file_stable(self, handle: _FileHandle) -> None:
        self._assert_file_snapshot(handle)
        current_payload = self._read_descriptor(
            handle.fd,
            maximum=max(len(handle.payload), 1),
            label=handle.relative_path,
        )
        self._assert_file_snapshot(handle)
        self._assert_inventories_stable()
        if current_payload != handle.payload:
            raise WebsiteTranslationCompilerError(
                f"repository file bytes changed during compilation: {handle.relative_path}"
            )

    def assert_stable(self) -> None:
        self._assert_cwd_guard_stable()
        for handle in self._ancestors:
            self._assert_ancestor_stable(handle)
        for handle in sorted(
            self._directories.values(),
            key=lambda item: len(PurePosixPath(item.relative_path).parts),
        ):
            self._assert_directory_stable(handle)
        self._assert_inventories_stable()
        for handle in self._files:
            self._assert_file_stable(handle)
        self._assert_inventories_stable()
        for handle in self._ancestors:
            self._assert_ancestor_stable(handle)
        self._assert_cwd_guard_stable()


def _validate_binding(binding: ContractBinding) -> None:
    if binding.contract_path != PRODUCTION_CONTRACT_PATH:
        raise WebsiteTranslationCompilerError("contract path is not authoritative")
    if binding.validator_path != PRODUCTION_VALIDATOR_PATH:
        raise WebsiteTranslationCompilerError("validator path is not authoritative")
    _require_sha256(binding.contract_sha256, label="contract binding")
    _require_sha256(binding.validator_sha256, label="validator binding")


def _load_bound_validator(handle: _FileHandle, binding: ContractBinding) -> ModuleType:
    actual = _sha256(handle.payload)
    if actual != binding.validator_sha256:
        raise WebsiteTranslationCompilerError(
            "website localization validator binding mismatch: "
            f"got {actual} expected {binding.validator_sha256}"
        )
    module = ModuleType("_winsvpn_bound_website_localization_contract")
    module.__file__ = str(handle.relative_path)
    module.__package__ = ""
    try:
        code = compile(
            handle.payload,
            handle.relative_path,
            "exec",
            dont_inherit=True,
        )
        exec(code, module.__dict__)
    except Exception as exc:
        raise WebsiteTranslationCompilerError(
            "unable to load the bound website localization validator"
        ) from exc
    required_api = (
        "AGGREGATE_PATH",
        "AUDIT_PATH",
        "CONTRACT_SCHEMA",
        "INDEX_PATH",
        "INSTANT_LOCALE_RE",
        "LANGUAGES_PATH",
        "LOCALE_DOCUMENT_KEYS",
        "LOCALE_SOURCE_DIRECTORY",
        "LOCALE_SOURCE_SCHEMA",
        "WebsiteLocalizationContractError",
        "canonical_json_bytes",
        "canonical_value_sha256",
        "extract_audit_nontranslatable_keys",
        "extract_runtime_nontranslatable_keys",
        "extract_static_keys",
        "sha256_bytes",
        "strict_json_loads",
        "validate_compiler_output_document",
        "validate_contract_document",
        "validate_locale_document",
    )
    if any(not hasattr(module, name) for name in required_api):
        raise WebsiteTranslationCompilerError(
            "bound website localization validator API is incomplete"
        )
    if (
        module.AGGREGATE_PATH != EXPECTED_OUTPUT_PATH
        or module.LOCALE_SOURCE_DIRECTORY != EXPECTED_LOCALE_DIRECTORY
        or module.DEFAULT_CONTRACT_PATH != PRODUCTION_CONTRACT_PATH
    ):
        raise WebsiteTranslationCompilerError(
            "bound website localization validator paths are not authoritative"
        )
    return module


def _parse_instant_locales(
    validator: ModuleType,
    payload: bytes,
) -> list[dict[str, object]]:
    document = validator.strict_json_loads(payload, label=validator.LANGUAGES_PATH)
    if not isinstance(document, list):
        raise WebsiteTranslationCompilerError(
            f"{validator.LANGUAGES_PATH} root must be an array"
        )
    seen: set[str] = set()
    instant: list[dict[str, object]] = []
    for index, item in enumerate(document):
        if not isinstance(item, dict) or tuple(item.keys()) != (
            "code",
            "name",
            "instant",
        ):
            raise WebsiteTranslationCompilerError(
                f"{validator.LANGUAGES_PATH}[{index}] keys or order are invalid"
            )
        code = item["code"]
        name = item["name"]
        enabled = item["instant"]
        if not isinstance(code, str) or not code:
            raise WebsiteTranslationCompilerError(
                f"locale code at index {index} must be a string"
            )
        if code in seen:
            raise WebsiteTranslationCompilerError(
                f"duplicate locale inventory code: {code}"
            )
        seen.add(code)
        if not isinstance(name, str) or not name or name != name.strip():
            raise WebsiteTranslationCompilerError(
                f"locale inventory name is invalid: {code}"
            )
        if type(enabled) is not bool:
            raise WebsiteTranslationCompilerError(
                f"locale inventory instant flag must be boolean: {code}"
            )
        if enabled:
            if validator.INSTANT_LOCALE_RE.fullmatch(code) is None:
                raise WebsiteTranslationCompilerError(
                    f"unsupported instant locale syntax: {code}"
                )
            instant.append({"code": code, "name": name})
    if not instant or instant[0]["code"] != "en":
        raise WebsiteTranslationCompilerError(
            "English must be the first supported instant locale"
        )
    if any(locale["code"] == "en" for locale in instant[1:]):
        raise WebsiteTranslationCompilerError(
            "English occurs more than once in the instant locale inventory"
        )
    return instant


def _serialization_contract(*, ensure_ascii: bool) -> dict[str, object]:
    return {
        "encoding": "UTF-8",
        "ensure_ascii": ensure_ascii,
        "indent": 2,
        "line_endings": "LF",
        "trailing_newline": True,
    }


def _build_expected_contract_from_bytes(
    validator: ModuleType,
    *,
    index_payload: bytes,
    audit_path: str,
    audit_payload: bytes,
    languages_payload: bytes,
) -> _SynthesizedContract:
    if audit_path != PRODUCTION_AUDIT_PATH:
        raise WebsiteTranslationCompilerError(
            "synthesized contract audit source path is not authoritative"
        )
    locales = _parse_instant_locales(validator, languages_payload)
    translatable_context, translate_no_context = validator.extract_static_keys(
        index_payload
    )
    runtime_nontranslatable = validator.extract_runtime_nontranslatable_keys(
        index_payload
    )
    audit_nontranslatable = validator.extract_audit_nontranslatable_keys(
        audit_payload
    )
    explicit_nontranslatable = runtime_nontranslatable | audit_nontranslatable

    translatable_keys = sorted(translatable_context - explicit_nontranslatable)
    nontranslatable_keys = sorted(translatable_context & explicit_nontranslatable)
    translate_no_only_keys = sorted(translate_no_context - translatable_context)
    mixed_context_keys = sorted(translate_no_context & translatable_context)
    visible_keys = translatable_context | translate_no_context
    drift_keys = sorted(
        (runtime_nontranslatable ^ audit_nontranslatable) & visible_keys
    )

    translatable_hash = validator.canonical_value_sha256(translatable_keys)
    nontranslatable_hash = validator.canonical_value_sha256(nontranslatable_keys)
    translate_no_hash = validator.canonical_value_sha256(translate_no_only_keys)
    mixed_hash = validator.canonical_value_sha256(mixed_context_keys)
    drift_hash = validator.canonical_value_sha256(drift_keys)
    index_hash = validator.sha256_bytes(index_payload)
    english_identity = validator.canonical_value_sha256(
        {
            "file_sha256": index_hash,
            "path": validator.INDEX_PATH,
            "translatable_static_keys_sha256": translatable_hash,
        }
    )
    inventory_identity = validator.canonical_value_sha256(locales)
    locale_codes = [str(item["code"]) for item in locales]
    targets = [
        {
            "locale": code,
            "path": f"{validator.LOCALE_SOURCE_DIRECTORY}/{code}.json",
        }
        for code in locale_codes
        if code != "en"
    ]
    document = {
        "schema": validator.CONTRACT_SCHEMA,
        "english_source": {
            "path": validator.INDEX_PATH,
            "file_sha256": index_hash,
            "translatable_static_keys_sha256": translatable_hash,
            "identity_sha256": english_identity,
        },
        "instant_locale_inventory": {
            "path": validator.LANGUAGES_PATH,
            "file_sha256": validator.sha256_bytes(languages_payload),
            "locales": locales,
            "identity_sha256": inventory_identity,
        },
        "key_classification": {
            "normalization": (
                "html-character-references-decoded-whitespace-collapsed-v1"
            ),
            "translatable_static_keys": translatable_keys,
            "translatable_static_keys_sha256": translatable_hash,
            "nontranslatable_static_keys": nontranslatable_keys,
            "nontranslatable_static_keys_sha256": nontranslatable_hash,
            "inherited_translate_no_only_keys": translate_no_only_keys,
            "inherited_translate_no_only_keys_sha256": translate_no_hash,
            "mixed_translate_context_keys": mixed_context_keys,
            "mixed_translate_context_keys_sha256": mixed_hash,
            "runtime_audit_nontranslatable_drift": {
                "classification": "nontranslatable",
                "keys": drift_keys,
                "keys_sha256": drift_hash,
            },
        },
        "locale_sources": {
            "schema": validator.LOCALE_SOURCE_SCHEMA,
            "document_keys": list(validator.LOCALE_DOCUMENT_KEYS),
            "targets": targets,
            "translation_key_order": "translatable_static_keys",
            "translation_values": "nonempty-trimmed-non-english-strings",
            "serialization": _serialization_contract(ensure_ascii=False),
        },
        "compiler_output": {
            "path": validator.AGGREGATE_PATH,
            "locale_order": locale_codes,
            "mapping_key_order": "translatable_static_keys",
            "english_values": "source-key-identity",
            "target_values": "validated-locale-source-values",
            "serialization": _serialization_contract(ensure_ascii=False),
            "write_strategy": (
                "single-owner-same-directory-temp-fsync-replace-directory-fsync"
            ),
        },
    }
    return _SynthesizedContract(
        document=document,
        audit_path=audit_path,
        audit_sha256=validator.sha256_bytes(audit_payload),
    )


def _first_difference(actual: object, expected: object, location: str = "$") -> str | None:
    if type(actual) is not type(expected):
        return location
    if isinstance(expected, dict):
        if tuple(actual.keys()) != tuple(expected.keys()):
            return location
        for key in expected:
            difference = _first_difference(actual[key], expected[key], f"{location}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(expected, list):
        if len(actual) != len(expected):
            return location
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            difference = _first_difference(
                actual_item,
                expected_item,
                f"{location}[{index}]",
            )
            if difference is not None:
                return difference
        return None
    return None if actual == expected else location


def _validator_call(
    validator: ModuleType,
    operation: Any,
    *args: object,
    **kwargs: object,
) -> Any:
    try:
        return operation(*args, **kwargs)
    except validator.WebsiteLocalizationContractError as exc:
        raise WebsiteTranslationCompilerError(str(exc)) from exc


def _load_bound_contract(
    secure: _SecureRepository,
    validator: ModuleType,
    binding: ContractBinding,
    contract_handle: _FileHandle | None = None,
) -> dict[str, Any]:
    if contract_handle is None:
        contract_handle = secure.open_file(binding.contract_path)
    elif contract_handle.relative_path != binding.contract_path:
        raise WebsiteTranslationCompilerError(
            "inherited website localization contract path is not authoritative"
        )
    actual_hash = _sha256(contract_handle.payload)
    if actual_hash != binding.contract_sha256:
        raise WebsiteTranslationCompilerError(
            "website localization contract binding mismatch: "
            f"got {actual_hash} expected {binding.contract_sha256}"
        )
    document = _validator_call(
        validator,
        validator.strict_json_loads,
        contract_handle.payload,
        label=binding.contract_path,
    )
    contract = _validator_call(
        validator,
        validator.validate_contract_document,
        document,
    )
    canonical_contract = _validator_call(
        validator,
        validator.canonical_json_bytes,
        contract,
        ensure_ascii=True,
    )
    if contract_handle.payload != canonical_contract:
        raise WebsiteTranslationCompilerError(
            "contract JSON is not in canonical ASCII/LF order"
        )

    index_handle = secure.open_file(validator.INDEX_PATH)
    if validator.AUDIT_PATH != PRODUCTION_AUDIT_PATH:
        raise WebsiteTranslationCompilerError(
            "website localization audit source path is not authoritative"
        )
    audit_handle = secure.open_file(PRODUCTION_AUDIT_PATH)
    languages_handle = secure.open_file(validator.LANGUAGES_PATH)
    actual_audit_hash = _sha256(audit_handle.payload)
    if actual_audit_hash != PRODUCTION_AUDIT_SHA256:
        raise WebsiteTranslationCompilerError(
            "website localization audit source binding mismatch: "
            f"got {actual_audit_hash} expected {PRODUCTION_AUDIT_SHA256}"
        )
    synthesized = _validator_call(
        validator,
        _build_expected_contract_from_bytes,
        validator,
        index_payload=index_handle.payload,
        audit_path=PRODUCTION_AUDIT_PATH,
        audit_payload=audit_handle.payload,
        languages_payload=languages_handle.payload,
    )
    if (
        synthesized.audit_path != PRODUCTION_AUDIT_PATH
        or synthesized.audit_sha256 != PRODUCTION_AUDIT_SHA256
    ):
        raise WebsiteTranslationCompilerError(
            "synthesized contract audit source binding mismatch"
        )
    difference = _first_difference(contract, synthesized.document)
    if difference is not None:
        raise WebsiteTranslationCompilerError(
            f"contract does not match descriptor-bound source bytes at {difference}"
        )
    if contract["compiler_output"]["path"] != EXPECTED_OUTPUT_PATH:
        raise WebsiteTranslationCompilerError("compiler output path is not authoritative")
    return contract


def _load_locale_sources(
    secure: _SecureRepository,
    validator: ModuleType,
    contract: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    targets = contract["locale_sources"]["targets"]
    expected_names = {f"{target['locale']}.json" for target in targets}
    if len(expected_names) != len(targets):
        raise WebsiteTranslationCompilerError("duplicate locale source target")
    try:
        secure.bind_exact_inventory(EXPECTED_LOCALE_DIRECTORY, expected_names)
    except WebsiteTranslationCompilerError as exc:
        locale_path = PurePosixPath(EXPECTED_LOCALE_DIRECTORY)
        parent_path = locale_path.parent.as_posix()
        parent = secure.open_directory(parent_path)
        try:
            os.stat(
                locale_path.name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            raise WebsiteTranslationCompilerError(
                "OWNER-BLOCKED: localization/website/locales is absent"
            ) from exc
        except OSError:
            pass
        raise

    locale_sources: dict[str, dict[str, Any]] = {}
    for target in targets:
        locale = target["locale"]
        relative_path = target["path"]
        expected_path = f"{EXPECTED_LOCALE_DIRECTORY}/{locale}.json"
        if relative_path != expected_path:
            raise WebsiteTranslationCompilerError(
                f"locale source path is not authoritative: {locale}"
            )
        handle = secure.open_file(relative_path)
        document = _validator_call(
            validator,
            validator.strict_json_loads,
            handle.payload,
            label=relative_path,
        )
        source = _validator_call(
            validator,
            validator.validate_locale_document,
            document,
            expected_locale=locale,
            contract=contract,
        )
        canonical_source = _validator_call(
            validator,
            validator.canonical_json_bytes,
            source,
            ensure_ascii=False,
        )
        if handle.payload != canonical_source:
            raise WebsiteTranslationCompilerError(
                f"locale source is not canonical UTF-8/LF JSON: {locale}"
            )
        locale_sources[locale] = source
    if list(locale_sources) != [target["locale"] for target in targets]:
        raise WebsiteTranslationCompilerError("locale source order is nondeterministic")
    return locale_sources


def _canonical_output_bytes(
    validator: ModuleType,
    document: dict[str, dict[str, str]],
) -> bytes:
    return _validator_call(
        validator,
        validator.canonical_json_bytes,
        document,
        ensure_ascii=False,
    )


def _build_compiler_output(
    validator: ModuleType,
    contract: dict[str, Any],
    locale_sources: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, str]], bytes]:
    source_keys = contract["key_classification"]["translatable_static_keys"]
    output: dict[str, dict[str, str]] = {}
    for locale in contract["compiler_output"]["locale_order"]:
        if locale == "en":
            output[locale] = {key: key for key in source_keys}
        else:
            source = locale_sources.get(locale)
            if source is None:
                raise WebsiteTranslationCompilerError(
                    f"missing validated locale source: {locale}"
                )
            output[locale] = dict(source["translations"])
    _validator_call(
        validator,
        validator.validate_compiler_output_document,
        output,
        contract=contract,
        locale_sources=locale_sources,
    )
    first = _canonical_output_bytes(validator, output)
    second = _canonical_output_bytes(validator, output)
    if first != second:
        raise WebsiteTranslationCompilerError(
            "compiler output serialization is nondeterministic"
        )
    if not first or len(first) > MAX_OUTPUT_BYTES:
        raise WebsiteTranslationCompilerError("compiler output size is unsafe")
    round_trip = _validator_call(
        validator,
        validator.strict_json_loads,
        first,
        label="compiler output",
    )
    _validator_call(
        validator,
        validator.validate_compiler_output_document,
        round_trip,
        contract=contract,
        locale_sources=locale_sources,
    )
    if round_trip != output:
        raise WebsiteTranslationCompilerError("compiler output round trip changed data")
    return output, first


def _verify_existing_output(
    secure: _SecureRepository,
    validator: ModuleType,
    contract: dict[str, Any],
    locale_sources: dict[str, dict[str, Any]],
    expected_payload: bytes,
) -> None:
    handle = secure.open_file(EXPECTED_OUTPUT_PATH, maximum=MAX_OUTPUT_BYTES)
    document = _validator_call(
        validator,
        validator.strict_json_loads,
        handle.payload,
        label=EXPECTED_OUTPUT_PATH,
    )
    validated = _validator_call(
        validator,
        validator.validate_compiler_output_document,
        document,
        contract=contract,
        locale_sources=locale_sources,
    )
    canonical = _canonical_output_bytes(validator, validated)
    if handle.payload != canonical:
        raise WebsiteTranslationCompilerError(
            "compiler output is not canonical UTF-8/LF JSON"
        )
    if handle.payload != expected_payload:
        raise WebsiteTranslationCompilerError(
            "canonical compiler output does not match validated locale sources"
        )


def _new_private_basename(output_name: str, purpose: str) -> str:
    return f".{output_name}.{purpose}.{os.getpid()}.{secrets.token_hex(16)}"


def _validate_private_basename(
    name: str,
    *,
    output_name: str,
    purpose: str,
) -> None:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if (
        not name
        or len(name.encode("ascii", errors="ignore")) != len(name)
        or len(name) > 240
        or name in (".", "..", output_name)
        or not name.startswith(f".{output_name}.{purpose}.")
        or any(character not in allowed for character in name)
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or PurePosixPath(name).name != name
    ):
        raise WebsiteTranslationCompilerError("temporary output name is unsafe")


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                "unable to write compiler output temporary"
            ) from exc
        if written <= 0:
            raise WebsiteTranslationCompilerError(
                "compiler output temporary write made no progress"
            )
        offset += written


def _rename_exclusive(directory_fd: int, source: str, destination: str) -> None:
    if sys.platform != "darwin":
        raise WebsiteTranslationCompilerError(
            "exclusive compiler output publication is unsupported on this platform"
        )
    renameatx_np = ctypes.CDLL(None, use_errno=True).renameatx_np
    renameatx_np.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameatx_np.restype = ctypes.c_int
    result = renameatx_np(
        directory_fd,
        source.encode("utf-8", errors="strict"),
        directory_fd,
        destination.encode("utf-8", errors="strict"),
        0x00000004,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(error, os.strerror(error), destination)
    raise OSError(error, os.strerror(error), destination)


def _capture_and_unlink_owned_entry(
    directory_fd: int,
    name: str,
    fd: int,
    identity: tuple[int, int] | None,
    *,
    output_name: str,
) -> bool:
    if fd < 0:
        return False
    try:
        held = os.fstat(fd)
    except OSError as exc:
        raise WebsiteTranslationCompilerError(
            "unable to identify owned compiler output during cleanup"
        ) from exc
    owned_identity = _identity(held)
    if identity is not None and identity != owned_identity:
        raise WebsiteTranslationCompilerError(
            "compiler output cleanup identity changed"
        )
    quarantine = _new_private_basename(output_name, "cleanup")
    _validate_private_basename(
        quarantine,
        output_name=output_name,
        purpose="cleanup",
    )
    try:
        # RENAME_EXCL first captures the public entry without deleting it. Only
        # the unguessable captured name can be unlinked, and a substituted
        # capture is restored to its original name without deletion.
        _rename_exclusive(directory_fd, name, quarantine)
    except FileNotFoundError:
        if os.fstat(fd).st_nlink == 0:
            return True
        raise WebsiteTranslationCompilerError(
            "owned compiler output disappeared before cleanup"
        )
    except OSError as exc:
        raise WebsiteTranslationCompilerError(
            "unable to capture owned compiler output for cleanup"
        ) from exc
    try:
        captured = os.stat(
            quarantine,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        held = os.fstat(fd)
    except OSError as exc:
        raise WebsiteTranslationCompilerError(
            "captured compiler output cleanup identity is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(captured.st_mode)
        or not stat.S_ISREG(held.st_mode)
        or _identity(captured) != owned_identity
        or _identity(held) != owned_identity
    ):
        try:
            _rename_exclusive(directory_fd, quarantine, name)
        except OSError as restore_exc:
            raise WebsiteTranslationCompilerError(
                "cleanup substitution was quarantined and could not be restored"
            ) from restore_exc
        raise WebsiteTranslationCompilerError(
            "compiler output cleanup substitution was preserved"
        )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.unlink(quarantine, dir_fd=directory_fd)
        after = os.fstat(fd)
    except OSError as exc:
        raise WebsiteTranslationCompilerError(
            "unable to unlink captured owned compiler output"
        ) from exc
    if after.st_nlink != 0:
        raise WebsiteTranslationCompilerError(
            "owned compiler output cleanup did not remove its retained inode"
        )
    return True


def _require_created_entry(
    directory_fd: int,
    name: str,
    fd: int,
    *,
    expected_mode: int,
    expected_size: int | None = None,
    label: str,
) -> tuple[int, int]:
    try:
        descriptor_metadata = os.fstat(fd)
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise WebsiteTranslationCompilerError(
            f"{label} identity is unavailable"
        ) from exc
    identity = _identity(descriptor_metadata)
    if (
        not stat.S_ISREG(descriptor_metadata.st_mode)
        or not stat.S_ISREG(entry.st_mode)
        or descriptor_metadata.st_nlink != 1
        or entry.st_nlink != 1
        or _identity(entry) != identity
        or stat.S_IMODE(descriptor_metadata.st_mode) != expected_mode
        or stat.S_IMODE(entry.st_mode) != expected_mode
        or (
            expected_size is not None
            and (
                descriptor_metadata.st_size != expected_size
                or entry.st_size != expected_size
            )
        )
    ):
        raise WebsiteTranslationCompilerError(f"{label} identity is unsafe")
    return identity


def _assert_retained_output_exact(
    secure: _SecureRepository,
    directory_fd: int,
    name: str,
    fd: int,
    identity: tuple[int, int],
    expected_payload: bytes,
) -> None:
    _require_created_entry(
        directory_fd,
        name,
        fd,
        expected_mode=0o644,
        expected_size=len(expected_payload),
        label="published compiler output",
    )
    before = os.fstat(fd)
    payload = _SecureRepository._read_descriptor(
        fd,
        maximum=MAX_OUTPUT_BYTES,
        label=EXPECTED_OUTPUT_PATH,
    )
    after = os.fstat(fd)
    final_identity = _require_created_entry(
        directory_fd,
        name,
        fd,
        expected_mode=0o644,
        expected_size=len(expected_payload),
        label="published compiler output",
    )
    secure._assert_inventories_stable()
    terminal = os.fstat(fd)
    terminal_entry = os.stat(
        name,
        dir_fd=directory_fd,
        follow_symlinks=False,
    )
    if (
        final_identity != identity
        or payload != expected_payload
        or _file_fingerprint(before) != _file_fingerprint(after)
        or _file_fingerprint(after) != _file_fingerprint(terminal)
        or _file_fingerprint(terminal) != _file_fingerprint(terminal_entry)
    ):
        raise WebsiteTranslationCompilerError(
            "published compiler output bytes, size, or identity changed"
        )


def _publish_new_output(
    secure: _SecureRepository,
    expected_payload: bytes,
) -> None:
    if sys.platform != "darwin":
        raise WebsiteTranslationCompilerError(
            "exclusive compiler output publication is unsupported on this platform"
        )
    output = PurePosixPath(EXPECTED_OUTPUT_PATH)
    parent_path = output.parent.as_posix()
    output_name = output.name
    parent = secure.lock_directory(parent_path)
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    temporary_fd = -1
    temporary_name: str | None = None
    temporary_identity: tuple[int, int] | None = None
    published = False
    publication_complete = False
    operation_error: BaseException | None = None
    try:
        temporary_name = _new_private_basename(output_name, "compile")
        _validate_private_basename(
            temporary_name,
            output_name=output_name,
            purpose="compile",
        )
        try:
            temporary_fd = os.open(temporary_name, flags, 0o600, dir_fd=parent.fd)
        except FileExistsError as exc:
            raise WebsiteTranslationCompilerError(
                "compiler output temporary name collided"
            ) from exc
        temporary_identity = _identity(os.fstat(temporary_fd))
        temporary_identity = _require_created_entry(
            parent.fd,
            temporary_name,
            temporary_fd,
            expected_mode=0o600,
            expected_size=0,
            label="compiler output temporary",
        )
        _write_all(temporary_fd, expected_payload)
        try:
            os.fchmod(temporary_fd, 0o644)
            os.fsync(temporary_fd)
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                "unable to seal compiler output temporary"
            ) from exc
        temporary_identity = _require_created_entry(
            parent.fd,
            temporary_name,
            temporary_fd,
            expected_mode=0o644,
            expected_size=len(expected_payload),
            label="sealed compiler output temporary",
        )
        written_payload = _SecureRepository._read_descriptor(
            temporary_fd,
            maximum=MAX_OUTPUT_BYTES,
            label="compiler output temporary",
        )
        if written_payload != expected_payload:
            raise WebsiteTranslationCompilerError(
                "compiler output temporary read-back mismatch"
            )
        _require_created_entry(
            parent.fd,
            temporary_name,
            temporary_fd,
            expected_mode=0o644,
            expected_size=len(expected_payload),
            label="sealed compiler output temporary",
        )
        secure._assert_inventories_stable()
        secure.assert_stable()
        try:
            _rename_exclusive(
                parent.fd,
                temporary_name,
                output_name,
            )
        except FileExistsError as exc:
            raise WebsiteTranslationCompilerError(
                "create mode refuses to overwrite existing compiler output"
            ) from exc
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                "unable to publish compiler output atomically without replacement"
            ) from exc
        published = True
        temporary_name = None

        final_identity = _require_created_entry(
            parent.fd,
            output_name,
            temporary_fd,
            expected_mode=0o644,
            label="published compiler output",
        )
        if final_identity != temporary_identity:
            raise WebsiteTranslationCompilerError(
                "published compiler output identity changed"
            )
        try:
            os.fsync(parent.fd)
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                "unable to fsync compiler output directory"
            ) from exc
        secure.assert_stable()
        _assert_retained_output_exact(
            secure,
            parent.fd,
            output_name,
            temporary_fd,
            temporary_identity,
            expected_payload,
        )
        secure.retain_output_until_close(
            temporary_fd,
            parent.fd,
            output_name,
            temporary_identity,
            expected_payload,
        )
        publication_complete = True
        temporary_fd = -1
    except BaseException as exc:
        operation_error = exc
    finally:
        cleanup_error: BaseException | None = None
        cleaned = False
        cleanup_name = output_name if published else temporary_name
        if not publication_complete and cleanup_name is not None:
            try:
                cleaned = _capture_and_unlink_owned_entry(
                    parent.fd,
                    cleanup_name,
                    temporary_fd,
                    temporary_identity,
                    output_name=output_name,
                )
            except BaseException as exc:
                cleanup_error = exc
        if cleaned:
            try:
                os.fsync(parent.fd)
            except OSError as exc:
                cleanup_error = WebsiteTranslationCompilerError(
                    "unable to fsync compiler output cleanup"
                )
                cleanup_error.__cause__ = exc
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = WebsiteTranslationCompilerError(
                        "unable to close retained compiler output"
                    )
                    cleanup_error.__cause__ = exc
        if cleanup_error is not None:
            if operation_error is not None:
                raise cleanup_error from operation_error
            raise cleanup_error
    if operation_error is not None:
        raise operation_error.with_traceback(operation_error.__traceback__)


def _compile_with_secure_repository(
    secure: _SecureRepository,
    *,
    mode: str,
    binding: ContractBinding,
    validator_handle: _FileHandle | None = None,
    contract_handle: _FileHandle | None = None,
) -> CompilationResult:
    if mode not in ("verify", "create"):
        raise WebsiteTranslationCompilerError(
            "compiler mode must be explicitly 'verify' or 'create'"
        )
    _validate_binding(binding)
    output_parent = PurePosixPath(EXPECTED_OUTPUT_PATH).parent.as_posix()
    secure.lock_directory(output_parent)
    if validator_handle is None:
        validator_handle = secure.open_file(binding.validator_path)
    elif validator_handle.relative_path != binding.validator_path:
        raise WebsiteTranslationCompilerError(
            "inherited website localization validator path is not authoritative"
        )
    validator = _load_bound_validator(validator_handle, binding)
    contract = _load_bound_contract(
        secure,
        validator,
        binding,
        contract_handle=contract_handle,
    )
    locale_sources = _load_locale_sources(
        secure,
        validator,
        contract,
    )
    output, expected_payload = _build_compiler_output(
        validator,
        contract,
        locale_sources,
    )
    secure.assert_stable()
    if mode == "verify":
        _verify_existing_output(
            secure,
            validator,
            contract,
            locale_sources,
            expected_payload,
        )
        secure.assert_stable()
    else:
        _publish_new_output(secure, expected_payload)
    return CompilationResult(
        mode=mode,
        output_path=EXPECTED_OUTPUT_PATH,
        locale_count=len(output),
        key_count=len(contract["key_classification"]["translatable_static_keys"]),
        payload_sha256=_sha256(expected_payload),
        payload_size=len(expected_payload),
    )


def _compile_repository_with_binding(
    repo: Path,
    *,
    mode: str,
    binding: ContractBinding,
) -> CompilationResult:
    """Run the non-authoritative in-process core for isolated fixture tests."""

    try:
        with _SecureRepository(repo) as secure:
            return _compile_with_secure_repository(
                secure,
                mode=mode,
                binding=binding,
            )
    except WebsiteTranslationCompilerError:
        raise
    except OSError as exc:
        raise WebsiteTranslationCompilerError(
            f"compiler filesystem operation failed: {exc}"
        ) from exc


def compile_repository(repo: Path, *, mode: str) -> CompilationResult:
    """Reject imported library mode, which cannot emit production authority."""

    del repo, mode
    raise WebsiteTranslationCompilerError(
        "imported library mode cannot emit website compiler production authority"
    )


def _write_protocol_bytes(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(fd, payload[offset:])
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                "isolated worker protocol write failed"
            ) from exc
        if written <= 0:
            raise WebsiteTranslationCompilerError(
                "isolated worker protocol write made no progress"
            )
        offset += written


def _read_protocol_bytes(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = os.read(fd, remaining)
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                "isolated worker protocol read failed"
            ) from exc
        if not chunk:
            raise WebsiteTranslationCompilerError(
                "isolated worker protocol ended early"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_protocol_frame(fd: int, payload: bytes) -> None:
    if not payload or len(payload) > MAX_CONTROL_BYTES:
        raise WebsiteTranslationCompilerError(
            "isolated worker protocol payload size is invalid"
        )
    _write_protocol_bytes(fd, len(payload).to_bytes(8, "big") + payload)


def _read_protocol_frame(fd: int) -> bytes:
    size = int.from_bytes(_read_protocol_bytes(fd, 8), "big")
    if size <= 0 or size > MAX_CONTROL_BYTES:
        raise WebsiteTranslationCompilerError(
            "isolated worker protocol frame size is invalid"
        )
    return _read_protocol_bytes(fd, size)


def _read_protocol_bytes_until(fd: int, size: int, deadline: float) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            raise WebsiteTranslationCompilerError(
                "isolated worker protocol timed out"
            )
        try:
            readable, _, _ = select.select((fd,), (), (), timeout)
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                "isolated worker protocol wait failed"
            ) from exc
        if not readable:
            raise WebsiteTranslationCompilerError(
                "isolated worker protocol timed out"
            )
        try:
            chunk = os.read(fd, remaining)
        except OSError as exc:
            raise WebsiteTranslationCompilerError(
                "isolated worker protocol read failed"
            ) from exc
        if not chunk:
            raise WebsiteTranslationCompilerError(
                "isolated worker protocol ended early"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_protocol_frame_until(fd: int, deadline: float) -> bytes:
    size = int.from_bytes(_read_protocol_bytes_until(fd, 8, deadline), "big")
    if size <= 0 or size > MAX_CONTROL_BYTES:
        raise WebsiteTranslationCompilerError(
            "isolated worker protocol frame size is invalid"
        )
    return _read_protocol_bytes_until(fd, size, deadline)


def _protocol_json_bytes(document: object) -> bytes:
    try:
        return json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WebsiteTranslationCompilerError(
            "isolated worker protocol serialization failed"
        ) from exc


def _reject_protocol_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise WebsiteTranslationCompilerError(
                f"isolated worker protocol has duplicate key: {key!r}"
            )
        output[key] = value
    return output


def _protocol_json_loads(payload: bytes) -> object:
    try:
        text = payload.decode("ascii", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_reject_protocol_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                WebsiteTranslationCompilerError(
                    f"isolated worker protocol has non-finite value: {value}"
                )
            ),
        )
    except WebsiteTranslationCompilerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebsiteTranslationCompilerError(
            "isolated worker protocol JSON is malformed"
        ) from exc


def _assert_invoked_compiler_binding() -> None:
    try:
        before = os.fstat(INVOKED_COMPILER.fd)
        if _file_fingerprint(before) != INVOKED_COMPILER.fingerprint:
            raise WebsiteTranslationCompilerError(
                "externally invoked compiler descriptor custody changed"
            )
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(
                INVOKED_COMPILER.fd,
                min(READ_CHUNK_BYTES, before.st_size - offset),
                offset,
            )
            if not chunk:
                raise WebsiteTranslationCompilerError(
                    "externally invoked compiler descriptor ended early"
                )
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(INVOKED_COMPILER.fd)
    except WebsiteTranslationCompilerError:
        raise
    except OSError as exc:
        raise WebsiteTranslationCompilerError(
            "externally invoked compiler descriptor custody is unavailable"
        ) from exc
    if (
        _file_fingerprint(after) != INVOKED_COMPILER.fingerprint
        or b"".join(chunks) != INVOKED_COMPILER.payload
    ):
        raise WebsiteTranslationCompilerError(
            "externally invoked compiler bytes changed through the retained descriptor"
        )


def _attest_subprocess_launch_hooks() -> None:
    expected_path = f"{RELEASE_PYTHON_PREFIX}/lib/python3.14/subprocess.py"
    popen_methods = (
        subprocess.Popen.__init__,
        subprocess.Popen._execute_child,
        subprocess.Popen._posix_spawn,
    )
    posix_module = sys.modules.get("posix")
    if (
        sys.modules.get("subprocess") is not subprocess
        or sys.modules.get("_posixsubprocess") is not _posixsubprocess
        or getattr(subprocess, "__file__", None) != expected_path
        or getattr(subprocess, "__spec__", None) is None
        or subprocess.__spec__.origin != expected_path
        or subprocess.Popen is not _BOUND_POPEN
        or subprocess.Popen.__init__ is not _BOUND_POPEN_INIT
        or subprocess.Popen._execute_child is not _BOUND_POPEN_EXECUTE_CHILD
        or subprocess.Popen._posix_spawn is not _BOUND_POPEN_POSIX_SPAWN
        or subprocess._fork_exec is not _BOUND_FORK_EXEC
        or subprocess._fork_exec is not _posixsubprocess.fork_exec
        or posix_module is None
        or os.posix_spawn is not posix_module.posix_spawn
        or os.posix_spawnp is not posix_module.posix_spawnp
        or any(
            getattr(method, "__module__", None) != "subprocess"
            or getattr(getattr(method, "__code__", None), "co_filename", None)
            != expected_path
            for method in popen_methods
        )
    ):
        raise WebsiteTranslationCompilerError(
            "production authority rejects rebound subprocess launch hooks"
        )


def _attest_release_runtime() -> int:
    version = sys.version_info
    flags = sys.flags
    if (
        sys.platform != "darwin"
        or tuple(version[:3]) != (3, 14, 7)
        or version.releaselevel != "final"
        or version.serial != 0
        or flags.isolated != 1
        or flags.no_site != 1
        or flags.ignore_environment != 1
        or not flags.safe_path
        or sys.executable != RELEASE_PYTHON_EXECUTABLE
        or getattr(sys, "_base_executable", None) != RELEASE_PYTHON_BASE_EXECUTABLE
        or sys.prefix != RELEASE_PYTHON_PREFIX
        or sys.base_prefix != RELEASE_PYTHON_PREFIX
        or tuple(sys.path) != RELEASE_PYTHON_PATH
    ):
        raise WebsiteTranslationCompilerError(
            "production authority requires exact ReleasePython 3.14.7 with -I -S"
        )
    if sys.argv[0] not in sys.orig_argv:
        raise WebsiteTranslationCompilerError(
            "production authority requires direct script execution"
        )
    script_index = sys.orig_argv.index(sys.argv[0])
    interpreter_arguments = sys.orig_argv[:script_index]
    if (
        "-c" in interpreter_arguments
        or "-m" in interpreter_arguments
        or "-I" not in interpreter_arguments
        or "-S" not in interpreter_arguments
    ):
        raise WebsiteTranslationCompilerError(
            "production authority rejects wrapper or ambient module execution"
        )

    builtins_module = sys.modules.get("builtins")
    expected_meta_path = (
        ("_frozen_importlib", "BuiltinImporter"),
        ("_frozen_importlib", "FrozenImporter"),
        ("_frozen_importlib_external", "PathFinder"),
    )
    actual_meta_path = tuple(
        (getattr(item, "__module__", None), getattr(item, "__qualname__", None))
        for item in sys.meta_path
    )
    expected_module_paths = {
        "os": f"{RELEASE_PYTHON_PREFIX}/lib/python3.14/os.py",
        "json": f"{RELEASE_PYTHON_PREFIX}/lib/python3.14/json/__init__.py",
        "ctypes": f"{RELEASE_PYTHON_PREFIX}/lib/python3.14/ctypes/__init__.py",
    }
    if (
        builtins_module is None
        or getattr(builtins_module, "__import__", None) is None
        or type(builtins_module.__import__) is not type(os.open)
        or builtins_module.__import__.__module__ != "builtins"
        or builtins_module.__import__.__name__ != "__import__"
        or actual_meta_path != expected_meta_path
        or sys.modules.get("os") is not os
        or sys.modules.get("json") is not json
        or sys.modules.get("ctypes") is not ctypes
        or sys.modules.get("posix") is None
        or os.open is not sys.modules["posix"].open
        or os.stat is not sys.modules["posix"].stat
        or os.execve is not sys.modules["posix"].execve
        or os.set_inheritable is not sys.modules["posix"].set_inheritable
        or getattr(json.loads, "__module__", None) != "json"
        or getattr(json.dumps, "__module__", None) != "json"
        or not isinstance(ctypes.CDLL, type)
        or ctypes.CDLL.__module__ != "ctypes"
        or ctypes.CDLL.__qualname__ != "CDLL"
        or getattr(os, "__file__", None) != expected_module_paths["os"]
        or getattr(json, "__file__", None) != expected_module_paths["json"]
        or getattr(ctypes, "__file__", None) != expected_module_paths["ctypes"]
        or getattr(os, "__spec__", None) is None
        or os.__spec__.origin != "frozen"
    ):
        raise WebsiteTranslationCompilerError(
            "production authority rejects rebound modules or import machinery"
        )
    _attest_subprocess_launch_hooks()

    runtime_fd = -1
    try:
        runtime_fd = os.open(
            RELEASE_PYTHON_EXECUTABLE,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        retained = os.fstat(runtime_fd)
        executable_entry = os.stat(
            RELEASE_PYTHON_EXECUTABLE,
            follow_symlinks=False,
        )
        launcher_entry = os.stat(RELEASE_PYTHON_LAUNCHER, follow_symlinks=True)
    except OSError as exc:
        if runtime_fd >= 0:
            os.close(runtime_fd)
        raise WebsiteTranslationCompilerError(
            "exact ReleasePython executable custody is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(retained.st_mode)
        or retained.st_nlink != 1
        or _identity(retained) != _identity(executable_entry)
        or _file_fingerprint(retained) != _file_fingerprint(executable_entry)
        or not stat.S_ISREG(launcher_entry.st_mode)
        or launcher_entry.st_nlink != 1
        or stat.S_IMODE(launcher_entry.st_mode) & 0o111 == 0
    ):
        os.close(runtime_fd)
        raise WebsiteTranslationCompilerError(
            "exact ReleasePython executable identity is unsafe"
        )
    sys.dont_write_bytecode = True
    os.environ.clear()
    os.environ["LC_ALL"] = "C"
    os.environ["LANG"] = "C"
    return runtime_fd


def _reexec_from_retained_compiler(arguments: list[str]) -> None:
    if INVOKED_COMPILER.executed_from_descriptor:
        return
    runtime_fd = _attest_release_runtime()
    try:
        _assert_invoked_compiler_binding()
        os.set_inheritable(INVOKED_COMPILER.fd, True)
        os.execve(
            RELEASE_PYTHON_LAUNCHER,
            (
                RELEASE_PYTHON_LAUNCHER,
                "-I",
                "-S",
                f"/dev/fd/{INVOKED_COMPILER.fd}",
                *arguments,
            ),
            {"LC_ALL": "C", "LANG": "C"},
        )
    except WebsiteTranslationCompilerError:
        raise
    except OSError as exc:
        raise WebsiteTranslationCompilerError(
            "unable to re-execute the retained compiler descriptor"
        ) from exc
    finally:
        os.close(runtime_fd)
        try:
            os.set_inheritable(INVOKED_COMPILER.fd, False)
        except OSError:
            pass


def _authenticated_response_bytes(
    nonce: bytes,
    document: dict[str, object],
) -> bytes:
    body = _protocol_json_bytes(document)
    digest = hmac.new(nonce, body, hashlib.sha256).hexdigest().encode("ascii")
    return digest + b"\n" + body


def _decode_authenticated_response(
    nonce: bytes,
    payload: bytes,
) -> dict[str, object]:
    digest, separator, body = payload.partition(b"\n")
    expected = hmac.new(nonce, body, hashlib.sha256).hexdigest().encode("ascii")
    if (
        separator != b"\n"
        or len(digest) != 64
        or not hmac.compare_digest(digest, expected)
    ):
        raise WebsiteTranslationCompilerError(
            "isolated worker response authentication failed"
        )
    document = _protocol_json_loads(body)
    if not isinstance(document, dict) or tuple(document) != (
        "ok",
        "error",
        "result",
    ):
        raise WebsiteTranslationCompilerError(
            "isolated worker response envelope is malformed"
        )
    return document


def _result_document(result: CompilationResult) -> dict[str, object]:
    return {
        "mode": result.mode,
        "output_path": result.output_path,
        "locale_count": result.locale_count,
        "key_count": result.key_count,
        "payload_sha256": result.payload_sha256,
        "payload_size": result.payload_size,
    }


def _result_from_document(document: object, *, expected_mode: str) -> CompilationResult:
    if not isinstance(document, dict) or tuple(document) != (
        "mode",
        "output_path",
        "locale_count",
        "key_count",
        "payload_sha256",
        "payload_size",
    ):
        raise WebsiteTranslationCompilerError(
            "isolated worker result is malformed"
        )
    if (
        document["mode"] != expected_mode
        or document["output_path"] != EXPECTED_OUTPUT_PATH
        or type(document["locale_count"]) is not int
        or document["locale_count"] <= 0
        or type(document["key_count"]) is not int
        or document["key_count"] <= 0
        or not isinstance(document["payload_sha256"], str)
        or type(document["payload_size"]) is not int
        or document["payload_size"] <= 0
        or document["payload_size"] > MAX_OUTPUT_BYTES
    ):
        raise WebsiteTranslationCompilerError(
            "isolated worker result values are invalid"
        )
    _require_sha256(document["payload_sha256"], label="worker payload")
    return CompilationResult(
        mode=document["mode"],
        output_path=document["output_path"],
        locale_count=document["locale_count"],
        key_count=document["key_count"],
        payload_sha256=document["payload_sha256"],
        payload_size=document["payload_size"],
    )


def _run_isolated_worker(control_fd: int, result_fd: int) -> int:
    runtime_fd = _attest_release_runtime()
    _assert_invoked_compiler_binding()
    secure: _SecureRepository | None = None
    nonce: bytes | None = None
    try:
        manifest = _protocol_json_loads(_read_protocol_frame(control_fd))
        if not isinstance(manifest, dict) or tuple(manifest) != (
            "protocol",
            "nonce",
            "mode",
            "runtime_fd",
            "compiler_sha256",
            "custody",
            "compiler",
            "validator",
            "contract",
        ):
            raise WebsiteTranslationCompilerError(
                "isolated worker manifest is malformed"
            )
        nonce_hex = manifest["nonce"]
        mode = manifest["mode"]
        inherited_runtime_fd = manifest["runtime_fd"]
        reviewed_compiler_sha256 = manifest["compiler_sha256"]
        if (
            manifest["protocol"] != WORKER_PROTOCOL
            or not isinstance(nonce_hex, str)
            or len(nonce_hex) != 64
            or any(character not in "0123456789abcdef" for character in nonce_hex)
            or mode not in ("verify", "create")
            or type(inherited_runtime_fd) is not int
            or inherited_runtime_fd < 0
            or not isinstance(reviewed_compiler_sha256, str)
        ):
            raise WebsiteTranslationCompilerError(
                "isolated worker manifest values are invalid"
            )
        _require_sha256(
            reviewed_compiler_sha256,
            label="reviewed compiler manifest binding",
        )
        if INVOKED_COMPILER_SHA256 != reviewed_compiler_sha256:
            raise WebsiteTranslationCompilerError(
                "isolated worker executed compiler bytes do not match the "
                "externally reviewed binding"
            )
        nonce = bytes.fromhex(nonce_hex)
        if (
            _file_fingerprint(os.fstat(runtime_fd))
            != _file_fingerprint(os.fstat(inherited_runtime_fd))
        ):
            raise WebsiteTranslationCompilerError(
                "isolated worker ReleasePython custody changed"
            )
        compiler_document = manifest["compiler"]
        if not isinstance(compiler_document, dict):
            raise WebsiteTranslationCompilerError(
                "isolated worker compiler custody is malformed"
            )
        compiler_fd = compiler_document.get("fd")
        if (
            type(compiler_fd) is not int
            or compiler_fd != INVOKED_COMPILER.fd
            or sys.argv[0] != f"/dev/fd/{compiler_fd}"
        ):
            raise WebsiteTranslationCompilerError(
                "isolated worker did not execute the retained compiler bytes"
            )

        secure = _SecureRepository.from_custody(manifest["custody"])
        compiler_handle = secure.adopt_file(
            compiler_document,
            expected_path=PRODUCTION_COMPILER_PATH,
        )
        if _sha256(compiler_handle.payload) != reviewed_compiler_sha256:
            raise WebsiteTranslationCompilerError(
                "isolated worker compiler descriptor does not match the "
                "externally reviewed binding"
            )
        validator_handle = secure.adopt_file(
            manifest["validator"],
            expected_path=PRODUCTION_VALIDATOR_PATH,
        )
        contract_handle = secure.adopt_file(
            manifest["contract"],
            expected_path=PRODUCTION_CONTRACT_PATH,
        )
        if _sha256(validator_handle.payload) != PRODUCTION_VALIDATOR_SHA256:
            raise WebsiteTranslationCompilerError(
                "website localization validator binding mismatch"
            )
        if _sha256(contract_handle.payload) != PRODUCTION_CONTRACT_SHA256:
            raise WebsiteTranslationCompilerError(
                "website localization contract binding mismatch"
            )
        secure.assert_stable()
        result = _compile_with_secure_repository(
            secure,
            mode=mode,
            binding=PRODUCTION_BINDING,
            validator_handle=validator_handle,
            contract_handle=contract_handle,
        )
        response = {
            "ok": True,
            "error": None,
            "result": _result_document(result),
        }
    except WebsiteTranslationCompilerError as exc:
        if nonce is None:
            return 2
        response = {
            "ok": False,
            "error": str(exc),
            "result": None,
        }
    except Exception:
        if nonce is None:
            return 2
        response = {
            "ok": False,
            "error": "isolated worker failed closed on an unexpected exception",
            "result": None,
        }
    response_is_success = response["ok"] is True
    try:
        _write_protocol_frame(
            result_fd,
            _authenticated_response_bytes(nonce, response),
        )
        acknowledgement = _read_protocol_bytes(control_fd, 1)
        if response_is_success and acknowledgement == b"\x01":
            if secure is None:
                raise WebsiteTranslationCompilerError(
                    "isolated worker lost repository custody before success"
                )
            secure.assert_stable()
            secure.verify_retained_outputs()
        elif not response_is_success and acknowledgement == b"\x00":
            pass
        else:
            raise WebsiteTranslationCompilerError(
                "isolated worker acknowledgement is invalid"
            )
    except WebsiteTranslationCompilerError:
        if response_is_success and secure is not None:
            secure.cleanup_retained_outputs()
        return 3
    finally:
        if secure is not None:
            secure.close()
        os.close(runtime_fd)
    return 0


def _production_subprocess(repo: Path, *, mode: str) -> CompilationResult:
    if __name__ != "__main__":
        raise WebsiteTranslationCompilerError(
            "imported library mode cannot establish production authority"
        )
    runtime_fd = _attest_release_runtime()
    _assert_invoked_compiler_binding()
    control_read = -1
    control_write = -1
    result_read = -1
    result_write = -1
    process: subprocess.Popen[bytes] | None = None
    try:
        with _SecureRepository(repo) as secure:
            output_parent = PurePosixPath(EXPECTED_OUTPUT_PATH).parent.as_posix()
            secure.lock_directory(output_parent)
            compiler_handle = secure.open_file(PRODUCTION_COMPILER_PATH)
            validator_handle = secure.open_file(PRODUCTION_VALIDATOR_PATH)
            contract_handle = secure.open_file(PRODUCTION_CONTRACT_PATH)
            compiler_sha256 = _sha256(compiler_handle.payload)
            if compiler_sha256 != INVOKED_COMPILER_SHA256:
                raise WebsiteTranslationCompilerError(
                    "repository compiler does not match the externally reviewed "
                    "compiler bytes"
                )
            if _sha256(validator_handle.payload) != PRODUCTION_VALIDATOR_SHA256:
                raise WebsiteTranslationCompilerError(
                    "website localization validator binding mismatch"
                )
            if _sha256(contract_handle.payload) != PRODUCTION_CONTRACT_SHA256:
                raise WebsiteTranslationCompilerError(
                    "website localization contract binding mismatch"
                )
            secure.assert_stable()
            nonce = secrets.token_bytes(32)
            manifest = {
                "protocol": WORKER_PROTOCOL,
                "nonce": nonce.hex(),
                "mode": mode,
                "runtime_fd": runtime_fd,
                "compiler_sha256": compiler_sha256,
                "custody": secure.export_custody(),
                "compiler": secure.export_file_handle(compiler_handle),
                "validator": secure.export_file_handle(validator_handle),
                "contract": secure.export_file_handle(contract_handle),
            }
            control_read, control_write = os.pipe()
            result_read, result_write = os.pipe()
            pass_fds = tuple(
                dict.fromkeys(
                    secure.inherited_descriptors()
                    + (runtime_fd, control_read, result_write)
                )
            )
            os.lseek(compiler_handle.fd, 0, os.SEEK_SET)
            _attest_subprocess_launch_hooks()
            process = _BOUND_POPEN(
                (
                    RELEASE_PYTHON_LAUNCHER,
                    "-I",
                    "-S",
                    f"/dev/fd/{compiler_handle.fd}",
                    "--isolated-worker",
                    str(control_read),
                    str(result_write),
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=pass_fds,
                cwd="/",
                env={"LC_ALL": "C", "LANG": "C"},
            )
            _attest_subprocess_launch_hooks()
            os.close(control_read)
            control_read = -1
            os.close(result_write)
            result_write = -1
            _write_protocol_frame(control_write, _protocol_json_bytes(manifest))
            try:
                response_payload = _read_protocol_frame_until(
                    result_read,
                    time.monotonic() + WORKER_TIMEOUT_SECONDS,
                )
                response = _decode_authenticated_response(nonce, response_payload)
                secure.assert_stable()
                worker_error: str | None
                worker_result: CompilationResult | None
                if response["ok"] is True:
                    if response["error"] is not None:
                        raise WebsiteTranslationCompilerError(
                            "isolated worker returned contradictory authority"
                        )
                    worker_result = _result_from_document(
                        response["result"],
                        expected_mode=mode,
                    )
                    worker_error = None
                    acknowledgement = b"\x01"
                else:
                    error = response["error"]
                    if (
                        response["ok"] is not False
                        or not isinstance(error, str)
                        or not error
                        or response["result"] is not None
                    ):
                        raise WebsiteTranslationCompilerError(
                            "isolated worker returned an invalid failure"
                        )
                    worker_result = None
                    worker_error = error
                    acknowledgement = b"\x00"
                _write_protocol_bytes(control_write, acknowledgement)
            except BaseException:
                try:
                    _write_protocol_bytes(control_write, b"\x00")
                except WebsiteTranslationCompilerError:
                    pass
                os.close(control_write)
                control_write = -1
                try:
                    process.communicate(timeout=WORKER_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                raise
            os.close(control_write)
            control_write = -1
            try:
                stdout, stderr = process.communicate(timeout=WORKER_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.communicate()
                raise WebsiteTranslationCompilerError(
                    "isolated website compiler worker timed out after acknowledgement"
                ) from exc
            os.close(result_read)
            result_read = -1
            if process.returncode != 0 or stdout or stderr:
                raise WebsiteTranslationCompilerError(
                    "isolated website compiler worker failed closed"
                )
            if worker_error is not None:
                raise WebsiteTranslationCompilerError(worker_error)
            if worker_result is None:
                raise WebsiteTranslationCompilerError(
                    "isolated worker omitted its authenticated result"
                )
            return worker_result
    except WebsiteTranslationCompilerError:
        raise
    except OSError as exc:
        raise WebsiteTranslationCompilerError(
            "unable to establish isolated website compiler worker"
        ) from exc
    finally:
        for descriptor in (control_read, control_write, result_read, result_write):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        os.close(runtime_fd)


def _command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    for mode, help_text in (
        ("verify", "Verify canonical output without writing any file."),
        ("create", "Create canonical output only when it is absent."),
    ):
        command = commands.add_parser(mode, help=help_text)
        command.add_argument("--repo", type=Path, default=Path("."))
    return parser


def main(argv: list[str] | None = None) -> int:
    if __name__ != "__main__":
        raise WebsiteTranslationCompilerError(
            "imported library mode cannot invoke the production command boundary"
        )
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["--isolated-worker"]:
        if not INVOKED_COMPILER.executed_from_descriptor:
            return 2
        if len(arguments) != 3:
            return 2
        try:
            control_fd = int(arguments[1], 10)
            result_fd = int(arguments[2], 10)
        except ValueError:
            return 2
        if control_fd < 0 or result_fd < 0 or control_fd == result_fd:
            return 2
        return _run_isolated_worker(control_fd, result_fd)
    try:
        _reexec_from_retained_compiler(arguments)
        args = _command_parser().parse_args(arguments)
        result = _production_subprocess(args.repo, mode=args.mode)
    except WebsiteTranslationCompilerError as exc:
        print(f"website-translation-compiler: {exc}", file=sys.stderr)
        return 1
    action = "verified" if result.mode == "verify" else "created"
    print(
        f"compiler_output_{action} path={result.output_path} "
        f"locales={result.locale_count} keys={result.key_count} "
        f"bytes={result.payload_size} sha256={result.payload_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
