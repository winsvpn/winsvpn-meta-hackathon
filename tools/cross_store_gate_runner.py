#!/usr/bin/env python3
"""Shell-disabled process runner for cross-store release gates."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import select
import stat
import struct
import subprocess
import sys
from collections.abc import Sequence
from typing import Protocol


@dataclasses.dataclass(frozen=True)
class GateProcessResult:
    """Raw result returned only after an attempted process execution."""

    argv: tuple[str, ...]
    stdout: str
    stderr: str
    exit_code: int
    executed: bool
    runner_id: str
    shell_enabled: bool
    environment_overrides: tuple[tuple[str, str], ...] = (
        ("PYTHONDONTWRITEBYTECODE", "1"),
    )


class ExplicitArgvRunner(Protocol):
    """Injectable runner contract used by the evidence collector."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: pathlib.Path,
    ) -> GateProcessResult:
        """Execute one exact argv vector without a command shell."""


class SubprocessExplicitArgvRunner:
    """Production runner. It never accepts or invokes a shell command string."""

    RUNNER_ID = "python-subprocess-explicit-argv-v1"
    ENVIRONMENT_OVERRIDES = (("PYTHONDONTWRITEBYTECODE", "1"),)

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: pathlib.Path,
    ) -> GateProcessResult:
        exact_argv = tuple(argv)
        environment = os.environ.copy()
        environment.update(dict(self.ENVIRONMENT_OVERRIDES))
        completed = subprocess.run(
            exact_argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            shell=False,
            check=False,
            env=environment,
        )
        return GateProcessResult(
            argv=exact_argv,
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            executed=True,
            runner_id=self.RUNNER_ID,
            shell_enabled=False,
            environment_overrides=self.ENVIRONMENT_OVERRIDES,
        )


class ExactProducerExecutionError(RuntimeError):
    """Raised when exact producer-byte execution cannot be proven."""


class ExactSnapshotError(RuntimeError):
    """Raised when a bound byte snapshot cannot be proven or cleaned up."""


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _is_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def _assert_plain_path(path: pathlib.Path, root: pathlib.Path) -> None:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise ExactProducerExecutionError(
            f"Unable to inspect repository execution root: {exc}"
        ) from exc
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or _is_reparse(root_info)
    ):
        raise ExactProducerExecutionError(
            "Repository execution root is not a plain directory."
        )
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ExactProducerExecutionError(
            "Producer execution path escapes the repository."
        ) from exc
    current = root
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise ExactProducerExecutionError(
                f"Unable to inspect producer execution path: {exc}"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise ExactProducerExecutionError(
                "Producer execution path contains a symlink or reparse point."
            )


def _stable_file(path: pathlib.Path) -> tuple[tuple[int, ...], str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        path_before = path.lstat()
        if not stat.S_ISREG(path_before.st_mode) or _is_reparse(path_before):
            raise ExactProducerExecutionError(
                "Producer execution path is not a plain regular file."
            )
        descriptor = os.open(path, flags)
        descriptor_before = os.fstat(descriptor)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        descriptor_after = os.fstat(descriptor)
        path_after = path.lstat()
    except OSError as exc:
        raise ExactProducerExecutionError(
            f"Unable to bind producer execution bytes: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identities = tuple(
        _identity(info)
        for info in (path_before, descriptor_before, descriptor_after, path_after)
    )
    if len(set(identities)) != 1 or path_after.st_size <= 0:
        raise ExactProducerExecutionError(
            "Producer changed while its execution bytes were being bound."
        )
    return identities[0], digest.hexdigest()


def snapshot_path_for(producer: pathlib.Path, sha256: str) -> pathlib.Path:
    """Return the deterministic same-directory snapshot path for a producer."""

    return _kind_snapshot_path(producer, sha256, "gate")


def artifact_snapshot_path_for(artifact: pathlib.Path, sha256: str) -> pathlib.Path:
    """Return the exact-basename path inside a private transaction directory."""

    if len(sha256) != 64 or any(
        character not in "0123456789abcdef" for character in sha256
    ):
        raise ExactSnapshotError("Artifact snapshot hash is not canonical SHA-256.")
    basename = artifact.name
    if (
        not basename
        or basename in {".", ".."}
        or pathlib.Path(basename).name != basename
    ):
        raise ExactSnapshotError("Artifact snapshot basename is unsafe.")
    basename_digest = hashlib.sha256(os.fsencode(basename)).hexdigest()[:16]
    transaction_directory = artifact.parent / (
        f".winsvpn-art-{sha256}-{basename_digest}"
    )
    return transaction_directory / basename


def extension_source_snapshot_path_for(
    source: pathlib.Path, sha256: str
) -> pathlib.Path:
    """Return the deterministic same-directory snapshot path for extension source."""

    return _kind_snapshot_path(source, sha256, "ext")


def _kind_snapshot_path(path: pathlib.Path, sha256: str, kind: str) -> pathlib.Path:
    suffix = path.suffix
    stem = path.name[: -len(suffix)] if suffix else path.name
    return path.with_name(f".{stem}.winsvpn-{kind}-{sha256}{suffix}")


def exclusive_copy_file(source: pathlib.Path, destination: pathlib.Path) -> str:
    """Copy one regular file to an exclusive destination and return its digest."""

    flags_in = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags_out = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    in_fd = -1
    out_fd = -1
    created = False
    complete = False
    try:
        in_fd = os.open(source, flags_in)
        source_info = os.fstat(in_fd)
        if not stat.S_ISREG(source_info.st_mode) or source_info.st_size <= 0:
            raise ExactSnapshotError("Snapshot source is not a non-empty regular file.")
        out_fd = os.open(destination, flags_out, 0o600)
        created = True
        digest = hashlib.sha256()
        while True:
            chunk = os.read(in_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(out_fd, view)
                if written <= 0:
                    raise ExactSnapshotError("Snapshot copy wrote no bytes.")
                view = view[written:]
        os.fsync(out_fd)
        complete = True
        return digest.hexdigest()
    except FileExistsError as exc:
        raise ExactSnapshotError(
            "Snapshot collision or concurrent execution detected."
        ) from exc
    except OSError as exc:
        raise ExactSnapshotError(f"Unable to create exclusive byte snapshot: {exc}") from exc
    finally:
        if in_fd >= 0:
            os.close(in_fd)
        if out_fd >= 0:
            os.close(out_fd)
        if created and not complete:
            try:
                os.unlink(destination)
            except OSError:
                pass


def _private_snapshot_directory_identity(path: pathlib.Path) -> tuple[int, ...]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ExactSnapshotError(
            f"Unable to inspect artifact snapshot directory: {exc}"
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or _is_reparse(info)
    ):
        raise ExactSnapshotError(
            "Artifact snapshot transaction path is not a plain directory."
        )
    if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o700:
        raise ExactSnapshotError(
            "Artifact snapshot transaction directory is not mode 0700."
        )
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ExactSnapshotError(
            "Artifact snapshot transaction directory is not owner-controlled."
        )
    return _directory_identity(info)


def _private_snapshot_file(
    path: pathlib.Path,
) -> tuple[tuple[int, ...], str]:
    try:
        identity, digest = _stable_file(path)
        info = path.lstat()
    except ExactProducerExecutionError as exc:
        raise ExactSnapshotError(str(exc)) from exc
    if identity != _identity(info):
        raise ExactSnapshotError("Artifact snapshot path identity is unstable.")
    if info.st_nlink != 1:
        raise ExactSnapshotError("Artifact snapshot is hardlinked.")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise ExactSnapshotError("Artifact snapshot is not owner-private.")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ExactSnapshotError("Artifact snapshot is not owner-controlled.")
    return identity, digest


def _same_file_object(info: os.stat_result, identity: tuple[int, ...]) -> bool:
    return (
        info.st_dev == identity[0]
        and info.st_ino == identity[1]
        and stat.S_IFMT(info.st_mode) == stat.S_IFMT(identity[2])
    )


def _hash_open_descriptor(descriptor: int) -> tuple[tuple[int, ...], str]:
    """Hash one retained regular-file descriptor without losing its offset."""

    try:
        original_offset = os.lseek(descriptor, 0, os.SEEK_CUR)
        os.lseek(descriptor, 0, os.SEEK_SET)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            raise ExactSnapshotError(
                "Retained artifact descriptor is not a non-empty regular file."
            )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        os.lseek(descriptor, original_offset, os.SEEK_SET)
    except OSError as exc:
        raise ExactSnapshotError(
            f"Unable to hash retained artifact descriptor: {exc}"
        ) from exc
    if _identity(before) != _identity(after):
        raise ExactSnapshotError(
            "Retained artifact descriptor changed while it was hashed."
        )
    return _identity(after), digest.hexdigest()


def _identity_closure_sha256(
    records: Sequence[tuple[str, tuple[int, ...]]],
) -> str:
    payload = [
        {"path": path, "identity": list(identity)}
        for path, identity in records
    ]
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class _KqueueMutationMonitor:
    """Detect transient mutation of retained macOS/BSD vnode descriptors."""

    STRATEGY = "posix-retained-descriptors-kqueue-v1"

    def __init__(self, entries: Sequence[tuple[int, str, bool]]) -> None:
        if not hasattr(select, "kqueue") or not hasattr(select, "kevent"):
            raise ExactSnapshotError(
                "This POSIX host has no reviewed kernel vnode monitor."
            )
        self._labels = {descriptor: label for descriptor, label, _ in entries}
        self._queue = select.kqueue()
        changes = []
        directory_notes = (
            getattr(select, "KQ_NOTE_DELETE", 0)
            | getattr(select, "KQ_NOTE_RENAME", 0)
            | getattr(select, "KQ_NOTE_REVOKE", 0)
        )
        file_notes = (
            directory_notes
            | getattr(select, "KQ_NOTE_WRITE", 0)
            | getattr(select, "KQ_NOTE_EXTEND", 0)
            | getattr(select, "KQ_NOTE_LINK", 0)
        )
        if directory_notes == 0 or file_notes == 0:
            self._queue.close()
            raise ExactSnapshotError(
                "This POSIX host lacks the reviewed vnode mutation flags."
            )
        for descriptor, _label, is_directory in entries:
            changes.append(
                select.kevent(
                    descriptor,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=directory_notes if is_directory else file_notes,
                )
            )
        try:
            self._queue.control(changes, 0, 0)
        except OSError as exc:
            self._queue.close()
            raise ExactSnapshotError(
                f"Unable to arm retained-vnode monitoring: {exc}"
            ) from exc
        self._maximum_events = max(1, len(changes) * 2)

    def assert_quiet(self) -> None:
        try:
            events = self._queue.control(None, self._maximum_events, 0)
        except OSError as exc:
            raise ExactSnapshotError(
                f"Unable to poll retained-vnode monitoring: {exc}"
            ) from exc
        if events:
            details = ", ".join(
                f"{self._labels.get(int(event.ident), 'unknown')}:{int(event.fflags)}"
                for event in events[:8]
            )
            raise ExactSnapshotError(
                "Kernel monitoring observed artifact path mutation during gate "
                f"execution ({details})."
            )

    def close(self) -> None:
        self._queue.close()


class _InotifyMutationMonitor:
    """Detect transient mutation of retained Linux inode descriptors."""

    STRATEGY = "posix-retained-descriptors-inotify-v1"
    _IN_MODIFY = 0x00000002
    _IN_CLOSE_WRITE = 0x00000008
    _IN_DELETE_SELF = 0x00000400
    _IN_MOVE_SELF = 0x00000800
    _IN_UNMOUNT = 0x00002000
    _IN_Q_OVERFLOW = 0x00004000
    _IN_IGNORED = 0x00008000
    _IN_ONLYDIR = 0x01000000
    _EVENT = struct.Struct("iIII")

    def __init__(self, entries: Sequence[tuple[int, str, bool]]) -> None:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        initialize = getattr(libc, "inotify_init1", None)
        add_watch = getattr(libc, "inotify_add_watch", None)
        if initialize is None or add_watch is None:
            raise ExactSnapshotError(
                "This Linux host has no reviewed inotify descriptor monitor."
            )
        initialize.argtypes = [ctypes.c_int]
        initialize.restype = ctypes.c_int
        add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add_watch.restype = ctypes.c_int
        flags = getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = initialize(flags)
        if descriptor < 0:
            error = ctypes.get_errno()
            raise ExactSnapshotError(
                f"Unable to initialize retained-inode monitoring: errno {error}."
            )
        self._descriptor = descriptor
        self._labels: dict[int, str] = {}
        try:
            for held, label, is_directory in entries:
                mask = (
                    self._IN_DELETE_SELF
                    | self._IN_MOVE_SELF
                    | self._IN_UNMOUNT
                    | self._IN_IGNORED
                )
                if is_directory:
                    mask |= self._IN_ONLYDIR
                else:
                    mask |= self._IN_MODIFY | self._IN_CLOSE_WRITE
                proc_path = os.fsencode(f"/proc/self/fd/{held}")
                watch = add_watch(descriptor, proc_path, mask)
                if watch < 0:
                    error = ctypes.get_errno()
                    raise ExactSnapshotError(
                        "Unable to arm retained-inode monitoring for "
                        f"{label}: errno {error}."
                    )
                self._labels[watch] = label
        except Exception:
            os.close(descriptor)
            self._descriptor = -1
            raise

    def assert_quiet(self) -> None:
        violations: list[str] = []
        while True:
            try:
                payload = os.read(self._descriptor, 64 * 1024)
            except BlockingIOError:
                break
            except OSError as exc:
                raise ExactSnapshotError(
                    f"Unable to poll retained-inode monitoring: {exc}"
                ) from exc
            if not payload:
                break
            offset = 0
            while offset + self._EVENT.size <= len(payload):
                watch, mask, _cookie, name_size = self._EVENT.unpack_from(
                    payload, offset
                )
                offset += self._EVENT.size + name_size
                label = self._labels.get(watch, "kernel-queue")
                if mask & self._IN_Q_OVERFLOW:
                    label = "kernel-queue-overflow"
                violations.append(f"{label}:{mask}")
            if offset != len(payload):
                raise ExactSnapshotError(
                    "Retained-inode monitor returned a malformed event stream."
                )
        if violations:
            raise ExactSnapshotError(
                "Kernel monitoring observed artifact path mutation during gate "
                f"execution ({', '.join(violations[:8])})."
            )

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1


def _posix_mutation_monitor(entries: Sequence[tuple[int, str, bool]]):
    if sys.platform.startswith("linux"):
        return _InotifyMutationMonitor(entries)
    return _KqueueMutationMonitor(entries)


@dataclasses.dataclass(frozen=True)
class _RetainedDirectory:
    relative_path: str
    name: str | None
    descriptor: int
    identity: tuple[int, ...]
    parent_descriptor: int | None


class _PosixArtifactCustody:
    """Retain and monitor every path component used by a gate artifact."""

    def __init__(
        self,
        cwd: pathlib.Path,
        source_path: pathlib.Path,
        snapshot_path: pathlib.Path,
        expected_sha256: str,
    ) -> None:
        required_dirfd = (os.open, os.stat, os.mkdir, os.unlink, os.rmdir)
        if any(function not in os.supports_dir_fd for function in required_dirfd):
            raise ExactSnapshotError(
                "This POSIX host lacks the reviewed descriptor-relative filesystem API."
            )
        self.cwd = cwd
        self.source_path = source_path
        self.snapshot_path = snapshot_path
        self.expected_sha256 = expected_sha256
        self.directories: list[_RetainedDirectory] = []
        self.source_descriptor = -1
        self.snapshot_directory_descriptor = -1
        self.snapshot_descriptor = -1
        self.snapshot_created = False
        self.snapshot_directory_created = False
        self.monitor = None
        self.generation = 0
        self.cleanup_complete = False
        self.source_identity: tuple[int, ...] = ()
        self.snapshot_identity: tuple[int, ...] = ()
        self.snapshot_directory_identity: tuple[int, ...] = ()
        self.source_parent_identity: tuple[int, ...] = ()
        try:
            self._bind_and_copy()
        except Exception:
            self._cleanup_partial()
            raise

    @staticmethod
    def _directory_flags() -> int:
        return (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

    @staticmethod
    def _file_flags() -> int:
        return (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )

    def _open_directory(
        self,
        path_or_name: pathlib.Path | str,
        *,
        parent_descriptor: int | None,
        relative_path: str,
    ) -> int:
        try:
            if parent_descriptor is None:
                descriptor = os.open(path_or_name, self._directory_flags())
                path_info = pathlib.Path(path_or_name).lstat()
            else:
                descriptor = os.open(
                    path_or_name,
                    self._directory_flags(),
                    dir_fd=parent_descriptor,
                )
                path_info = os.stat(
                    path_or_name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            descriptor_info = os.fstat(descriptor)
        except OSError as exc:
            raise ExactSnapshotError(
                f"Unable to retain artifact directory {relative_path}: {exc}"
            ) from exc
        if (
            not stat.S_ISDIR(descriptor_info.st_mode)
            or _identity(path_info) != _identity(descriptor_info)
            or _is_reparse(path_info)
        ):
            os.close(descriptor)
            raise ExactSnapshotError(
                f"Artifact directory {relative_path} is not a stable plain directory."
            )
        return descriptor

    def _bind_and_copy(self) -> None:
        relative_source = self.source_path.relative_to(self.cwd)
        if not relative_source.parts or any(
            part in {"", ".", ".."} for part in relative_source.parts
        ):
            raise ExactSnapshotError("Artifact source path is not a contained path.")
        root_descriptor = self._open_directory(
            self.cwd,
            parent_descriptor=None,
            relative_path=".",
        )
        root_identity = _identity(os.fstat(root_descriptor))
        self.directories.append(
            _RetainedDirectory(".", None, root_descriptor, root_identity, None)
        )
        current_descriptor = root_descriptor
        relative_parts: list[str] = []
        for part in relative_source.parts[:-1]:
            relative_parts.append(part)
            relative = "/".join(relative_parts)
            descriptor = self._open_directory(
                part,
                parent_descriptor=current_descriptor,
                relative_path=relative,
            )
            identity = _identity(os.fstat(descriptor))
            self.directories.append(
                _RetainedDirectory(
                    relative,
                    part,
                    descriptor,
                    identity,
                    current_descriptor,
                )
            )
            current_descriptor = descriptor
        source_name = relative_source.parts[-1]
        try:
            self.source_descriptor = os.open(
                source_name,
                self._file_flags(),
                dir_fd=current_descriptor,
            )
            source_path_info = os.stat(
                source_name,
                dir_fd=current_descriptor,
                follow_symlinks=False,
            )
            source_info = os.fstat(self.source_descriptor)
        except OSError as exc:
            raise ExactSnapshotError(
                f"Unable to retain canonical artifact descriptor: {exc}"
            ) from exc
        self.source_identity, source_digest = _hash_open_descriptor(
            self.source_descriptor
        )
        if (
            _identity(source_path_info) != self.source_identity
            or _identity(source_info) != self.source_identity
            or source_info.st_nlink != 1
            or _is_reparse(source_path_info)
            or source_digest != self.expected_sha256
        ):
            raise ExactSnapshotError(
                "Canonical artifact descriptor is not the exact single-link source bytes."
            )
        self.source_parent_identity = _identity(os.fstat(current_descriptor))
        if (
            self.snapshot_path.parent.parent != self.source_path.parent
            or self.snapshot_path.name != self.source_path.name
        ):
            raise ExactSnapshotError("Artifact snapshot layout is not canonical.")
        snapshot_directory_name = self.snapshot_path.parent.name
        try:
            os.mkdir(snapshot_directory_name, 0o700, dir_fd=current_descriptor)
            self.snapshot_directory_created = True
        except FileExistsError as exc:
            raise ExactSnapshotError(
                "Artifact snapshot collision or concurrent execution detected."
            ) from exc
        except OSError as exc:
            raise ExactSnapshotError(
                f"Unable to create descriptor-bound snapshot directory: {exc}"
            ) from exc
        self.snapshot_directory_descriptor = self._open_directory(
            snapshot_directory_name,
            parent_descriptor=current_descriptor,
            relative_path=self.snapshot_path.parent.relative_to(self.cwd).as_posix(),
        )
        snapshot_directory_info = os.fstat(self.snapshot_directory_descriptor)
        if (
            stat.S_IMODE(snapshot_directory_info.st_mode) != 0o700
            or (
                hasattr(os, "getuid")
                and snapshot_directory_info.st_uid != os.getuid()
            )
        ):
            raise ExactSnapshotError(
                "Artifact snapshot directory is not private and owner-controlled."
            )
        self.snapshot_directory_identity = _identity(snapshot_directory_info)
        output_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        output_descriptor = -1
        try:
            output_descriptor = os.open(
                self.snapshot_path.name,
                output_flags,
                0o600,
                dir_fd=self.snapshot_directory_descriptor,
            )
            self.snapshot_created = True
            self.snapshot_identity = _identity(os.fstat(output_descriptor))
            os.lseek(self.source_descriptor, 0, os.SEEK_SET)
            copied = hashlib.sha256()
            while True:
                chunk = os.read(self.source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                copied.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(output_descriptor, view)
                    if written <= 0:
                        raise ExactSnapshotError(
                            "Descriptor-bound snapshot copy wrote no bytes."
                        )
                    view = view[written:]
            os.fsync(output_descriptor)
            self.snapshot_identity = _identity(os.fstat(output_descriptor))
            if copied.hexdigest() != self.expected_sha256:
                raise ExactSnapshotError(
                    "Canonical artifact changed during descriptor-bound copy."
                )
        finally:
            if output_descriptor >= 0:
                os.close(output_descriptor)
        try:
            os.fsync(self.snapshot_directory_descriptor)
            self.snapshot_descriptor = os.open(
                self.snapshot_path.name,
                self._file_flags(),
                dir_fd=self.snapshot_directory_descriptor,
            )
            snapshot_path_info = os.stat(
                self.snapshot_path.name,
                dir_fd=self.snapshot_directory_descriptor,
                follow_symlinks=False,
            )
            snapshot_info = os.fstat(self.snapshot_descriptor)
        except OSError as exc:
            raise ExactSnapshotError(
                f"Unable to retain artifact snapshot descriptor: {exc}"
            ) from exc
        self.snapshot_identity, snapshot_digest = _hash_open_descriptor(
            self.snapshot_descriptor
        )
        if (
            _identity(snapshot_path_info) != self.snapshot_identity
            or _identity(snapshot_info) != self.snapshot_identity
            or snapshot_info.st_nlink != 1
            or stat.S_IMODE(snapshot_info.st_mode) & 0o077
            or snapshot_digest != self.expected_sha256
            or snapshot_info.st_size != source_info.st_size
        ):
            raise ExactSnapshotError(
                "Artifact snapshot descriptor is not the exact private copy."
            )
        self._refresh_directory_identities_after_snapshot_creation()
        monitor_entries = [
            (binding.descriptor, binding.relative_path, True)
            for binding in self.directories
        ]
        monitor_entries.extend(
            (
                (
                    self.snapshot_directory_descriptor,
                    self.snapshot_path.parent.relative_to(self.cwd).as_posix(),
                    True,
                ),
                (
                    self.source_descriptor,
                    relative_source.as_posix(),
                    False,
                ),
                (
                    self.snapshot_descriptor,
                    self.snapshot_path.relative_to(self.cwd).as_posix(),
                    False,
                ),
            )
        )
        self.monitor = _posix_mutation_monitor(monitor_entries)
        self.verify()

    def _refresh_directory_identities_after_snapshot_creation(self) -> None:
        """Freeze directory identities after this transaction's own writes."""

        refreshed: list[_RetainedDirectory] = []
        for binding in self.directories:
            try:
                descriptor_info = os.fstat(binding.descriptor)
                if binding.parent_descriptor is None:
                    path_info = self.cwd.lstat()
                else:
                    path_info = os.stat(
                        binding.name,
                        dir_fd=binding.parent_descriptor,
                        follow_symlinks=False,
                    )
            except OSError as exc:
                raise ExactSnapshotError(
                    "Artifact ancestor changed while the private snapshot was created: "
                    f"{exc}"
                ) from exc
            identity = _identity(descriptor_info)
            if _identity(path_info) != identity:
                raise ExactSnapshotError(
                    "Artifact ancestor changed while the private snapshot was created."
                )
            refreshed.append(dataclasses.replace(binding, identity=identity))
        self.directories = refreshed
        self.source_parent_identity = self.directories[-1].identity
        try:
            snapshot_directory_path_info = os.stat(
                self.snapshot_path.parent.name,
                dir_fd=self.directories[-1].descriptor,
                follow_symlinks=False,
            )
            snapshot_directory_info = os.fstat(
                self.snapshot_directory_descriptor
            )
        except OSError as exc:
            raise ExactSnapshotError(
                "Artifact snapshot directory changed during setup."
            ) from exc
        self.snapshot_directory_identity = _identity(snapshot_directory_info)
        if _identity(snapshot_directory_path_info) != self.snapshot_directory_identity:
            raise ExactSnapshotError(
                "Artifact snapshot directory changed during setup."
            )

    def verify(self) -> dict[str, object]:
        if self.monitor is None:
            raise ExactSnapshotError("Artifact custody monitor is not armed.")
        self.monitor.assert_quiet()
        try:
            root_path_info = self.cwd.lstat()
        except OSError as exc:
            raise ExactSnapshotError(
                f"Unable to rebind repository root during gate execution: {exc}"
            ) from exc
        root = self.directories[0]
        if (
            _identity(root_path_info) != root.identity
            or _identity(os.fstat(root.descriptor)) != root.identity
        ):
            raise ExactSnapshotError(
                "Repository root identity changed during artifact execution."
            )
        for binding in self.directories[1:]:
            try:
                path_info = os.stat(
                    binding.name,
                    dir_fd=binding.parent_descriptor,
                    follow_symlinks=False,
                )
                descriptor_info = os.fstat(binding.descriptor)
            except OSError as exc:
                raise ExactSnapshotError(
                    "Artifact ancestor identity became unavailable during gate "
                    f"execution: {exc}"
                ) from exc
            if (
                _identity(path_info) != binding.identity
                or _identity(descriptor_info) != binding.identity
            ):
                raise ExactSnapshotError(
                    "Artifact ancestor identity changed during gate execution: "
                    f"{binding.relative_path}."
                )
        source_parent_descriptor = self.directories[-1].descriptor
        try:
            source_path_info = os.stat(
                self.source_path.name,
                dir_fd=source_parent_descriptor,
                follow_symlinks=False,
            )
            snapshot_directory_path_info = os.stat(
                self.snapshot_path.parent.name,
                dir_fd=source_parent_descriptor,
                follow_symlinks=False,
            )
            snapshot_path_info = os.stat(
                self.snapshot_path.name,
                dir_fd=self.snapshot_directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ExactSnapshotError(
                f"Artifact descriptor rebinding failed during gate execution: {exc}"
            ) from exc
        source_identity, source_digest = _hash_open_descriptor(
            self.source_descriptor
        )
        snapshot_identity, snapshot_digest = _hash_open_descriptor(
            self.snapshot_descriptor
        )
        if (
            _identity(source_path_info) != self.source_identity
            or source_identity != self.source_identity
            or _identity(snapshot_directory_path_info)
            != self.snapshot_directory_identity
            or _identity(os.fstat(self.snapshot_directory_descriptor))
            != self.snapshot_directory_identity
            or _identity(snapshot_path_info) != self.snapshot_identity
            or snapshot_identity != self.snapshot_identity
            or source_digest != self.expected_sha256
            or snapshot_digest != self.expected_sha256
        ):
            raise ExactSnapshotError(
                "Retained artifact or snapshot identity changed during gate execution."
            )
        self.monitor.assert_quiet()
        self.generation += 1
        records = [
            (binding.relative_path, binding.identity)
            for binding in self.directories
        ]
        records.extend(
            (
                (
                    self.source_path.relative_to(self.cwd).as_posix(),
                    self.source_identity,
                ),
                (
                    self.snapshot_path.parent.relative_to(self.cwd).as_posix(),
                    self.snapshot_directory_identity,
                ),
                (
                    self.snapshot_path.relative_to(self.cwd).as_posix(),
                    self.snapshot_identity,
                ),
            )
        )
        return {
            "strategy": self.monitor.STRATEGY,
            "ancestor_closure_sha256": _identity_closure_sha256(records),
            "retained_object_count": len(records),
            "retained_objects": [
                {"path": path, "identity": list(identity)}
                for path, identity in records
            ],
            "source_identity": list(self.source_identity),
            "snapshot_identity": list(self.snapshot_identity),
            "source_sha256": source_digest,
            "snapshot_sha256": snapshot_digest,
            "bytes": self.source_identity[4],
            "verification_generation": self.generation,
            "kernel_mutation_events_observed": False,
            "windows_delete_write_sharing_denied": False,
        }

    def close(self) -> None:
        cleanup_error: Exception | None = None
        if self.monitor is not None:
            try:
                self.monitor.close()
            except Exception as exc:
                cleanup_error = exc
            self.monitor = None
        if self.snapshot_created and self.snapshot_directory_descriptor >= 0:
            try:
                path_info = os.stat(
                    self.snapshot_path.name,
                    dir_fd=self.snapshot_directory_descriptor,
                    follow_symlinks=False,
                )
                if _identity(path_info) != self.snapshot_identity:
                    raise ExactSnapshotError(
                        "Artifact cleanup refused a substituted snapshot entry."
                    )
                os.unlink(
                    self.snapshot_path.name,
                    dir_fd=self.snapshot_directory_descriptor,
                )
                if (
                    self.snapshot_descriptor >= 0
                    and os.fstat(self.snapshot_descriptor).st_nlink != 0
                ):
                    raise ExactSnapshotError(
                        "Artifact cleanup did not unlink the retained snapshot."
                    )
                self.snapshot_created = False
            except Exception as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if self.snapshot_descriptor >= 0:
            os.close(self.snapshot_descriptor)
            self.snapshot_descriptor = -1
        if self.snapshot_directory_created and self.directories:
            try:
                parent_descriptor = self.directories[-1].descriptor
                path_info = os.stat(
                    self.snapshot_path.parent.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    self.snapshot_created
                    or not _same_file_object(
                        path_info, self.snapshot_directory_identity
                    )
                    or not _same_file_object(
                        os.fstat(self.snapshot_directory_descriptor),
                        self.snapshot_directory_identity,
                    )
                ):
                    raise ExactSnapshotError(
                        "Artifact cleanup refused a substituted snapshot directory."
                    )
                os.rmdir(
                    self.snapshot_path.parent.name,
                    dir_fd=parent_descriptor,
                )
                self.snapshot_directory_created = False
            except Exception as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if self.snapshot_directory_descriptor >= 0:
            os.close(self.snapshot_directory_descriptor)
            self.snapshot_directory_descriptor = -1
        if self.source_descriptor >= 0:
            os.close(self.source_descriptor)
            self.source_descriptor = -1
        for binding in reversed(self.directories):
            os.close(binding.descriptor)
        self.directories.clear()
        if cleanup_error is not None:
            raise ExactSnapshotError(
                f"Descriptor-bound artifact cleanup failed: {cleanup_error}"
            ) from cleanup_error
        self.cleanup_complete = True

    def _cleanup_partial(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class _WindowsArtifactCustody:
    """Deny write/delete sharing on every Windows path component and artifact."""

    STRATEGY = "windows-retained-deny-write-delete-handles-v1"

    def __init__(
        self,
        cwd: pathlib.Path,
        source_path: pathlib.Path,
        expected_sha256: str,
    ) -> None:
        if os.name != "nt":
            raise ExactSnapshotError("Windows artifact custody used on a non-Windows host.")
        import ctypes
        from ctypes import wintypes

        class ByHandleFileInformation(ctypes.Structure):
            _fields_ = (
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTimeLow", wintypes.DWORD),
                ("ftCreationTimeHigh", wintypes.DWORD),
                ("ftLastAccessTimeLow", wintypes.DWORD),
                ("ftLastAccessTimeHigh", wintypes.DWORD),
                ("ftLastWriteTimeLow", wintypes.DWORD),
                ("ftLastWriteTimeHigh", wintypes.DWORD),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            )

        self._ctypes = ctypes
        self._info_type = ByHandleFileInformation
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        self._kernel32.CreateFileW.restype = wintypes.HANDLE
        self._kernel32.GetFileInformationByHandle.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(ByHandleFileInformation),
        )
        self._kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self.cwd = cwd
        self.source_path = source_path
        self.expected_sha256 = expected_sha256
        self.handles: list[tuple[str, int, tuple[int, ...], bool]] = []
        self.generation = 0
        self.cleanup_complete = False
        self.source_identity: tuple[int, ...] = ()
        self.source_parent_identity: tuple[int, ...] = ()
        try:
            self._bind()
        except Exception:
            self.close(suppress_errors=True)
            raise

    def _handle_identity(self, handle: int) -> tuple[int, ...]:
        info = self._info_type()
        if not self._kernel32.GetFileInformationByHandle(handle, self._ctypes.byref(info)):
            error = self._ctypes.get_last_error()
            raise ExactSnapshotError(
                f"Unable to inspect retained Windows handle: error {error}."
            )
        if info.dwFileAttributes & 0x400:
            raise ExactSnapshotError(
                "Retained Windows artifact path uses a reparse point."
            )
        return (
            int(info.dwVolumeSerialNumber),
            int(info.nFileIndexHigh),
            int(info.nFileIndexLow),
            int(info.dwFileAttributes),
            int(info.nNumberOfLinks),
            int(info.nFileSizeHigh),
            int(info.nFileSizeLow),
            int(info.ftLastWriteTimeHigh),
            int(info.ftLastWriteTimeLow),
        )

    def _open_locked(self, path: pathlib.Path, *, directory: bool) -> int:
        desired_access = 0x00000080 | 0x00100000 if directory else 0x80000000
        share_mode = 0x00000001
        flags = 0x00200000 | (0x02000000 if directory else 0x08000000)
        handle = self._kernel32.CreateFileW(
            str(path),
            desired_access,
            share_mode,
            None,
            3,
            flags,
            None,
        )
        invalid = self._ctypes.c_void_p(-1).value
        if handle in (None, invalid):
            error = self._ctypes.get_last_error()
            raise ExactSnapshotError(
                f"Unable to retain Windows artifact path {path}: error {error}."
            )
        return int(handle)

    def _bind(self) -> None:
        relative = self.source_path.relative_to(self.cwd)
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise ExactSnapshotError("Windows artifact path is not contained.")
        current = self.cwd
        directory_paths = [current]
        for part in relative.parts[:-1]:
            current = current / part
            directory_paths.append(current)
        for path in directory_paths:
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or _is_reparse(info):
                raise ExactSnapshotError(
                    "Windows artifact ancestor is not a plain directory."
                )
            handle = self._open_locked(path, directory=True)
            identity = self._handle_identity(handle)
            self.handles.append(
                (path.relative_to(self.cwd).as_posix() or ".", handle, identity, True)
            )
        source_info = self.source_path.lstat()
        if (
            not stat.S_ISREG(source_info.st_mode)
            or source_info.st_nlink != 1
            or _is_reparse(source_info)
        ):
            raise ExactSnapshotError(
                "Windows artifact is not a plain single-link regular file."
            )
        source_handle = self._open_locked(self.source_path, directory=False)
        handle_identity = self._handle_identity(source_handle)
        self.handles.append(
            (
                self.source_path.relative_to(self.cwd).as_posix(),
                source_handle,
                handle_identity,
                False,
            )
        )
        self.source_identity, digest = _stable_file(self.source_path)
        self.source_parent_identity = _identity(self.source_path.parent.lstat())
        if digest != self.expected_sha256:
            raise ExactSnapshotError(
                "Windows artifact hash changed before retained-handle execution."
            )
        self.verify()

    def verify(self) -> dict[str, object]:
        records: list[tuple[str, tuple[int, ...]]] = []
        for label, handle, expected, _is_directory in self.handles:
            current = self._handle_identity(handle)
            if current != expected:
                raise ExactSnapshotError(
                    "Retained Windows artifact handle identity changed."
                )
            records.append((label, current))
        source_identity, digest = _stable_file(self.source_path)
        if source_identity != self.source_identity or digest != self.expected_sha256:
            raise ExactSnapshotError(
                "Windows artifact changed during retained-handle execution."
            )
        self.generation += 1
        return {
            "strategy": self.STRATEGY,
            "ancestor_closure_sha256": _identity_closure_sha256(records),
            "retained_object_count": len(records),
            "retained_objects": [
                {"path": path, "identity": list(identity)}
                for path, identity in records
            ],
            "source_identity": list(self.source_identity),
            "snapshot_identity": list(self.source_identity),
            "source_sha256": digest,
            "snapshot_sha256": digest,
            "bytes": self.source_identity[4],
            "verification_generation": self.generation,
            "kernel_mutation_events_observed": False,
            "windows_delete_write_sharing_denied": True,
        }

    def close(self, *, suppress_errors: bool = False) -> None:
        errors: list[int] = []
        for _label, handle, _identity_value, _is_directory in reversed(self.handles):
            if not self._kernel32.CloseHandle(handle):
                errors.append(self._ctypes.get_last_error())
        self.handles.clear()
        if errors and not suppress_errors:
            raise ExactSnapshotError(
                f"Unable to close retained Windows artifact handles: {errors}."
            )
        self.cleanup_complete = not errors


@dataclasses.dataclass
class ExactArtifactSnapshot:
    """Bind gate execution to retained artifact and ancestor filesystem objects."""

    source_path: pathlib.Path
    cwd: pathlib.Path
    expected_sha256: str
    snapshot_path: pathlib.Path = dataclasses.field(init=False)
    snapshot_directory: pathlib.Path = dataclasses.field(init=False)
    snapshot_relative_path: str = dataclasses.field(init=False)
    source_identity_before: tuple[int, ...] = dataclasses.field(init=False)
    source_parent_identity_before: tuple[int, ...] = dataclasses.field(init=False)
    snapshot_identity_before: tuple[int, ...] = dataclasses.field(init=False)
    snapshot_directory_identity_before: tuple[int, ...] = dataclasses.field(
        init=False
    )
    cleanup_complete: bool = dataclasses.field(init=False, default=False)
    _created: bool = dataclasses.field(init=False, default=False)
    _directory_created: bool = dataclasses.field(init=False, default=False)
    _custody: object = dataclasses.field(init=False, repr=False)
    _last_custody_evidence: dict[str, object] = dataclasses.field(
        init=False, default_factory=dict, repr=False
    )

    def executed_artifact_arg(self, requested_arg: str) -> str:
        if pathlib.Path(requested_arg).is_absolute():
            return str(self.snapshot_path)
        return self.snapshot_relative_path

    def __enter__(self) -> "ExactArtifactSnapshot":
        self.cwd = pathlib.Path(os.path.abspath(self.cwd))
        self.source_path = pathlib.Path(
            os.path.abspath(
                self.source_path
                if self.source_path.is_absolute()
                else self.cwd / self.source_path
            )
        )
        try:
            self.source_path.relative_to(self.cwd)
            _assert_plain_path(self.source_path, self.cwd)
        except ExactProducerExecutionError as exc:
            raise ExactSnapshotError(str(exc)) from exc
        except ValueError as exc:
            raise ExactSnapshotError(
                "Artifact execution source escapes the repository root."
            ) from exc
        if os.name == "nt":
            custody = _WindowsArtifactCustody(
                self.cwd,
                self.source_path,
                self.expected_sha256,
            )
            self.snapshot_path = self.source_path
            self.snapshot_directory = self.source_path.parent
            self.source_identity_before = custody.source_identity
            self.source_parent_identity_before = custody.source_parent_identity
            self.snapshot_identity_before = custody.source_identity
            self.snapshot_directory_identity_before = custody.source_parent_identity
        else:
            self.snapshot_path = artifact_snapshot_path_for(
                self.source_path, self.expected_sha256
            )
            self.snapshot_directory = self.snapshot_path.parent
            custody = _PosixArtifactCustody(
                self.cwd,
                self.source_path,
                self.snapshot_path,
                self.expected_sha256,
            )
            self.source_identity_before = custody.source_identity
            self.source_parent_identity_before = custody.source_parent_identity
            self.snapshot_identity_before = custody.snapshot_identity
            self.snapshot_directory_identity_before = (
                custody.snapshot_directory_identity
            )
            self._created = custody.snapshot_created
            self._directory_created = custody.snapshot_directory_created
        self._custody = custody
        self.snapshot_relative_path = self.snapshot_path.relative_to(
            self.cwd
        ).as_posix()
        self._last_custody_evidence = self.verify_execution_boundary()
        return self

    def verify_execution_boundary(self) -> dict[str, object]:
        """Revalidate retained objects and reject every queued transient mutation."""

        evidence = dict(self._custody.verify())
        evidence.update(
            {
                "source_path": self.source_path.relative_to(self.cwd).as_posix(),
                "execution_path": self.snapshot_relative_path,
            }
        )
        self._last_custody_evidence = evidence
        return dict(evidence)

    def custody_evidence(self) -> dict[str, object]:
        if not self._last_custody_evidence:
            raise ExactSnapshotError("Artifact custody has not been verified.")
        return dict(self._last_custody_evidence)

    def _cleanup(self) -> None:
        self._custody.close()
        self._created = False
        self._directory_created = False
        self.cleanup_complete = self._custody.cleanup_complete
        if not self.cleanup_complete:
            raise ExactSnapshotError("Artifact custody cleanup did not complete.")

    def __exit__(self, exc_type, exc, traceback) -> bool:
        verification_error: Exception | None = None
        cleanup_error: Exception | None = None
        try:
            self.verify_execution_boundary()
        except Exception as caught:
            verification_error = caught
        try:
            self._cleanup()
        except Exception as caught:
            cleanup_error = caught
        if cleanup_error is not None:
            raise cleanup_error
        if verification_error is not None:
            if exc is None:
                raise verification_error
            if hasattr(exc, "add_note"):
                exc.add_note(
                    "Artifact custody also failed during exception cleanup: "
                    f"{verification_error}"
                )
        return False


@dataclasses.dataclass
class ExactProducerExecution:
    """Bind execution to a checked same-directory hardlink snapshot.

    The parent directory identity closes transient rename/replace/restore races;
    the shared inode identity and digest close in-place mutation races. The
    deterministic O_EXCL-like hardlink name makes concurrent execution fail
    closed instead of silently sharing a snapshot.
    """

    requested_argv: tuple[str, ...]
    cwd: pathlib.Path
    producer_arg_index: int
    producer_path: pathlib.Path
    expected_sha256: str
    executed_argv: tuple[str, ...] = dataclasses.field(init=False)
    snapshot_path: pathlib.Path = dataclasses.field(init=False)
    snapshot_relative_path: str = dataclasses.field(init=False)
    producer_identity_before: tuple[int, ...] = dataclasses.field(init=False)
    producer_identity_after: tuple[int, ...] = dataclasses.field(init=False)
    snapshot_identity_before: tuple[int, ...] = dataclasses.field(init=False)
    snapshot_identity_after: tuple[int, ...] = dataclasses.field(init=False)
    parent_identity_before: tuple[int, ...] = dataclasses.field(init=False)
    parent_identity_after: tuple[int, ...] = dataclasses.field(init=False)
    cleanup_complete: bool = dataclasses.field(init=False, default=False)
    _created: bool = dataclasses.field(init=False, default=False)

    def __enter__(self) -> "ExactProducerExecution":
        self.cwd = pathlib.Path(os.path.abspath(self.cwd))
        self.producer_path = pathlib.Path(
            os.path.abspath(
                self.producer_path
                if self.producer_path.is_absolute()
                else self.cwd / self.producer_path
            )
        )
        _assert_plain_path(self.producer_path, self.cwd)
        initial_identity, initial_sha256 = _stable_file(self.producer_path)
        if initial_sha256 != self.expected_sha256:
            raise ExactProducerExecutionError(
                "Canonical producer hash changed before snapshot creation."
            )
        self.snapshot_path = snapshot_path_for(
            self.producer_path, self.expected_sha256
        )
        if os.path.lexists(self.snapshot_path):
            raise ExactProducerExecutionError(
                "Producer snapshot collision or concurrent execution detected."
            )
        try:
            try:
                os.link(
                    self.producer_path,
                    self.snapshot_path,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise ExactProducerExecutionError(
                    "Producer snapshot collision or concurrent execution detected."
                ) from exc
            except OSError as exc:
                raise ExactProducerExecutionError(
                    f"Unable to create exact producer hardlink snapshot: {exc}"
                ) from exc
            self._created = True
            _assert_plain_path(self.snapshot_path, self.cwd)
            self.producer_identity_before, producer_sha256 = _stable_file(
                self.producer_path
            )
            self.snapshot_identity_before, snapshot_sha256 = _stable_file(
                self.snapshot_path
            )
            if (
                producer_sha256 != self.expected_sha256
                or snapshot_sha256 != self.expected_sha256
                or self.producer_identity_before != self.snapshot_identity_before
                or self.producer_identity_before[0:2] != initial_identity[0:2]
                or self.producer_identity_before[3] < 2
            ):
                raise ExactProducerExecutionError(
                    "Producer snapshot is not the exact bound source inode."
                )
            self.parent_identity_before = _directory_identity(
                self.producer_path.parent.stat()
            )
            self.snapshot_relative_path = self.snapshot_path.relative_to(
                self.cwd
            ).as_posix()
            replacement = (
                str(self.snapshot_path)
                if pathlib.Path(self.requested_argv[self.producer_arg_index]).is_absolute()
                else self.snapshot_relative_path
            )
            actual = list(self.requested_argv)
            actual[self.producer_arg_index] = replacement
            self.executed_argv = tuple(actual)
            return self
        except Exception:
            self._cleanup()
            raise

    def _validate_after_execution(self) -> None:
        self.producer_identity_after, producer_sha256 = _stable_file(
            self.producer_path
        )
        self.snapshot_identity_after, snapshot_sha256 = _stable_file(
            self.snapshot_path
        )
        self.parent_identity_after = _directory_identity(
            self.producer_path.parent.stat()
        )
        if (
            producer_sha256 != self.expected_sha256
            or snapshot_sha256 != self.expected_sha256
            or self.producer_identity_after != self.producer_identity_before
            or self.snapshot_identity_after != self.snapshot_identity_before
            or self.parent_identity_after != self.parent_identity_before
        ):
            raise ExactProducerExecutionError(
                "Producer or snapshot changed during exact-byte execution."
            )

    def _cleanup(self) -> None:
        if not self._created:
            return
        descriptor = -1
        try:
            if os.name == "nt":
                unlink_identity, unlink_sha256 = _stable_file(self.snapshot_path)
                if (
                    unlink_identity != self.snapshot_identity_before
                    or unlink_sha256 != self.expected_sha256
                ):
                    raise ExactProducerExecutionError(
                        "Producer snapshot identity changed before cleanup."
                    )
                os.unlink(self.snapshot_path)
                unlink_before = unlink_after = None
            else:
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(self.snapshot_path, flags)
                unlink_before = os.fstat(descriptor)
                if _identity(unlink_before) != self.snapshot_identity_before:
                    raise ExactProducerExecutionError(
                        "Producer snapshot identity changed before cleanup."
                    )
                os.unlink(self.snapshot_path)
                unlink_after = os.fstat(descriptor)
        except OSError as exc:
            raise ExactProducerExecutionError(
                f"Producer snapshot cleanup failed: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        self._created = False
        if os.path.lexists(self.snapshot_path):
            raise ExactProducerExecutionError(
                "Producer snapshot cleanup did not remove the execution path."
            )
        if unlink_before is not None and unlink_after is not None:
            before_identity = _identity(unlink_before)
            after_identity = _identity(unlink_after)
            if (
                after_identity[0:3] != before_identity[0:3]
                or after_identity[4:6] != before_identity[4:6]
                or after_identity[3] != before_identity[3] - 1
            ):
                raise ExactProducerExecutionError(
                    "Producer snapshot cleanup unlinked a different file identity."
                )
        if hasattr(self, "producer_identity_before"):
            final_identity, final_sha256 = _stable_file(self.producer_path)
            if (
                final_sha256 != self.expected_sha256
                or final_identity[0:3] != self.producer_identity_before[0:3]
                or final_identity[4:6] != self.producer_identity_before[4:6]
                or final_identity[3] != self.producer_identity_before[3] - 1
            ):
                raise ExactProducerExecutionError(
                    "Canonical producer identity changed during snapshot cleanup."
                )
        self.cleanup_complete = True

    def __exit__(self, exc_type, exc, traceback) -> bool:
        boundary_error: Exception | None = None
        try:
            self._validate_after_execution()
        except Exception as caught:
            boundary_error = caught
        try:
            self._cleanup()
        except Exception as caught:
            boundary_error = caught
        if boundary_error is not None:
            raise boundary_error
        return False

    def evidence(self) -> dict[str, object]:
        if not self.cleanup_complete:
            raise ExactProducerExecutionError(
                "Producer execution evidence requested before verified cleanup."
            )
        return {
            "snapshot_path": self.snapshot_relative_path,
            "snapshot_sha256": self.expected_sha256,
            "hardlink_same_inode": True,
            "producer_identity_before": list(self.producer_identity_before),
            "producer_identity_after": list(self.producer_identity_after),
            "snapshot_identity_before": list(self.snapshot_identity_before),
            "snapshot_identity_after": list(self.snapshot_identity_after),
            "parent_identity_before": list(self.parent_identity_before),
            "parent_identity_after": list(self.parent_identity_after),
            "cleanup_complete": self.cleanup_complete,
        }
