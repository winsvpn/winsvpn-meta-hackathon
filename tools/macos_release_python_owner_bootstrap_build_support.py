#!/usr/bin/env python3
"""Descriptor holder and exclusive publisher for the native owner bootstrap."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
from pathlib import Path
import resource
import select
import stat
import sys
import time


BLOCK_SIZE = 1024 * 1024
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_SYMLINK = 0x00200000
RENAME_EXCL = 0x00000004
STAGE_PREFIX = ".winsvpn-owner-bootstrap-build-"
HEADER = (
    "contract=winsvpn-macos-release-python-owner-bootstrap-build-closure-v1\n"
    "schema_version=1\n"
    "minimum_macos=13.0\n"
    "codesign_identifier=org.winsvpn.releasepython.owner-installer-bootstrap\n"
)


def digest_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(descriptor, BLOCK_SIZE, offset)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        offset += len(block)


def write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise RuntimeError("short write while creating retained build evidence")
        offset += written


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        getattr(info, "st_flags", 0),
    )


def directory_identity(info: os.stat_result) -> tuple[int, ...]:
    # Directory entry churn is expected while a held output parent is used for
    # bounded stage publication. Its own identity and custody, not st_nlink,
    # are the invariant retained through release.
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        getattr(info, "st_flags", 0),
    )


def read_paths(path: str) -> list[str]:
    values = Path(path).read_text(encoding="utf-8").splitlines()
    if not values or len(values) != len(set(values)):
        raise RuntimeError("retained input list is empty or contains duplicates")
    if any(not value.startswith("/") or any(char.isspace() for char in value) for value in values):
        raise RuntimeError("retained input list contains an unsafe path")
    return values


def hold_inputs(
    manifest_path: str,
    input_manifest_path: str,
    closure_path: str,
    ready_path: str,
    release_path: str,
) -> None:
    paths = read_paths(manifest_path)
    descriptor_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if descriptor_limit != resource.RLIM_INFINITY and len(paths) + 8 >= descriptor_limit:
        raise RuntimeError(
            "retained input count exceeds descriptor-limit headroom: "
            f"{len(paths)} inputs for limit {descriptor_limit}"
        )
    record_paths = set(read_paths(input_manifest_path))
    records: list[str] = []
    held: list[tuple[str, int, str, tuple[int, ...], str | None]] = []
    queue = select.kqueue()
    watched: dict[int, str] = {}
    all_notes = (
        select.KQ_NOTE_DELETE
        | select.KQ_NOTE_WRITE
        | select.KQ_NOTE_EXTEND
        | select.KQ_NOTE_LINK
        | select.KQ_NOTE_RENAME
        | select.KQ_NOTE_REVOKE
    )
    # NOTE_WRITE/NOTE_LINK are intentionally absent: the held output parent
    # gains and loses only descriptor-verified publication-stage entries.
    directory_notes = (
        select.KQ_NOTE_DELETE
        | select.KQ_NOTE_ATTRIB
        | select.KQ_NOTE_RENAME
        | select.KQ_NOTE_REVOKE
    )

    def watch(descriptor: int, path: str, directory: bool = False) -> None:
        watched[descriptor] = path
        queue.control(
            [
                select.kevent(
                    descriptor,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=directory_notes if directory else all_notes,
                )
            ],
            0,
            0,
        )

    def check_events(timeout: float) -> None:
        events = queue.control(None, 256, timeout)
        if events:
            raise RuntimeError(
                "retained build input vnode event: "
                + watched.get(events[0].ident, "unknown")
            )

    for path in paths:
        named = os.lstat(path)
        if stat.S_ISLNK(named.st_mode):
            descriptor = os.open(path, os.O_RDONLY | O_SYMLINK | O_CLOEXEC)
            retained = os.fstat(descriptor)
            target = os.readlink(path)
            if not stat.S_ISLNK(retained.st_mode) or identity(named) != identity(retained):
                raise RuntimeError("retained symlink identity changed")
            held.append((path, descriptor, "L", identity(retained), target))
            watch(descriptor, path)
            if path in record_paths:
                if any(char.isspace() for char in target):
                    raise RuntimeError("retained symlink target contains whitespace")
                records.append(f"L - {target} {path}")
        elif stat.S_ISDIR(named.st_mode):
            descriptor = os.open(
                path, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
            retained = os.fstat(descriptor)
            if directory_identity(named) != directory_identity(retained):
                raise RuntimeError("retained directory identity changed")
            held.append((path, descriptor, "D", directory_identity(retained), None))
            watch(descriptor, path, directory=True)
        elif stat.S_ISREG(named.st_mode):
            descriptor = os.open(path, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            retained = os.fstat(descriptor)
            file_digest = digest_fd(descriptor)
            if identity(named) != identity(retained):
                raise RuntimeError("retained file identity changed")
            held.append((path, descriptor, "F", identity(retained), file_digest))
            watch(descriptor, path)
            if path in record_paths:
                records.append(f"F {file_digest} {retained.st_size} {path}")
        else:
            raise RuntimeError(f"unsupported retained input: {path}")

    if len(records) != len(record_paths):
        raise RuntimeError("retained manifest record count mismatch")
    records.sort(key=lambda value: value.rsplit(" ", 1)[1])
    closure_data = (HEADER + "\n".join(records) + "\n").encode("ascii")
    closure_fd = os.open(
        closure_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o400
    )
    write_all(closure_fd, closure_data)
    os.fchmod(closure_fd, 0o400)
    os.fsync(closure_fd)
    closure_info = os.fstat(closure_fd)
    closure_digest = digest_fd(closure_fd)
    held.append((closure_path, closure_fd, "F", identity(closure_info), closure_digest))
    watch(closure_fd, closure_path)

    marker = os.open(
        ready_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o400
    )
    write_all(marker, b"ready\n")
    os.fsync(marker)
    os.close(marker)

    while not os.path.exists(release_path):
        check_events(0.05)
        time.sleep(0.01)
    check_events(0.0)
    for path, descriptor, kind, expected, expected_value in held:
        named = os.lstat(path)
        retained = os.fstat(descriptor)
        current_named = directory_identity(named) if kind == "D" else identity(named)
        current_retained = directory_identity(retained) if kind == "D" else identity(retained)
        if current_named != expected or current_retained != expected:
            raise RuntimeError(f"retained build input identity changed: {path}")
        if kind == "L":
            if os.readlink(path) != expected_value:
                raise RuntimeError(f"retained symlink target changed: {path}")
        elif kind == "F" and digest_fd(descriptor) != expected_value:
            raise RuntimeError(f"retained build input bytes changed: {path}")


def open_exact_at(
    parent_fd: int, name: str, expected_digest: str, expected_mode: int
) -> tuple[int, os.stat_result] | None:
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    descriptor = os.open(name, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC, dir_fd=parent_fd)
    retained = os.fstat(descriptor)
    parent_group = os.fstat(parent_fd).st_gid
    if (
        identity(named) != identity(retained)
        or not stat.S_ISREG(retained.st_mode)
        or retained.st_uid != os.getuid()
        or retained.st_gid != parent_group
        or retained.st_nlink != 1
        or stat.S_IMODE(retained.st_mode) != expected_mode
        or getattr(retained, "st_flags", 0) != 0
        or digest_fd(descriptor) != expected_digest
    ):
        os.close(descriptor)
        raise RuntimeError(f"existing build leaf is not an exact retry: {name}")
    return descriptor, retained


def safe_unlink_at(parent_fd: int, name: str, descriptor: int) -> None:
    retained = os.fstat(descriptor)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if identity(retained) != identity(named):
        raise RuntimeError(f"cleanup identity changed: {name}")
    os.unlink(name, dir_fd=parent_fd)


def publish_outputs(
    parent: str,
    binary_path: str,
    closure_path: str,
    binary_name: str,
    closure_name: str,
    binary_digest: str,
    closure_digest: str,
) -> None:
    parent_fd = os.open(parent, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    parent_info = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_info.st_mode):
        raise RuntimeError("output parent is not a directory")

    def held(path: str, wanted: str) -> tuple[int, os.stat_result]:
        descriptor = os.open(path, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or getattr(info, "st_flags", 0) != 0
            or digest_fd(descriptor) != wanted
        ):
            raise RuntimeError("held build output is not exact")
        return descriptor, info

    binary, _binary_info = held(binary_path, binary_digest)
    closure, _closure_info = held(closure_path, closure_digest)
    public_binary = open_exact_at(parent_fd, binary_name, binary_digest, 0o555)
    public_closure = open_exact_at(parent_fd, closure_name, closure_digest, 0o444)
    if public_binary is not None and public_closure is not None:
        os.close(public_binary[0])
        os.close(public_closure[0])
        os.close(binary)
        os.close(closure)
        os.close(parent_fd)
        return

    transaction = hashlib.sha256(
        (binary_digest + closure_digest).encode("ascii")
    ).hexdigest()[:48]
    stage_name = f"{STAGE_PREFIX}{transaction}"
    try:
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    stage_fd = os.open(
        stage_name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=parent_fd
    )
    stage_info = os.fstat(stage_fd)
    if (
        not stat.S_ISDIR(stage_info.st_mode)
        or stage_info.st_uid != os.getuid()
        or stage_info.st_gid != parent_info.st_gid
        or stat.S_IMODE(stage_info.st_mode) != 0o700
        or getattr(stage_info, "st_flags", 0) != 0
    ):
        raise RuntimeError("build publication stage custody is invalid")
    entries = set(os.listdir(stage_fd))
    if not entries.issubset({binary_name, closure_name}):
        raise RuntimeError("build publication stage has an unexpected entry")

    def copy_to_stage(
        source: int, name: str, wanted: str, mode: int
    ) -> tuple[int, os.stat_result]:
        existing = open_exact_at(stage_fd, name, wanted, mode)
        if existing is not None:
            return existing
        target = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600,
            dir_fd=stage_fd,
        )
        offset = 0
        while True:
            block = os.pread(source, BLOCK_SIZE, offset)
            if not block:
                break
            cursor = 0
            while cursor < len(block):
                written = os.pwrite(target, block[cursor:], offset + cursor)
                if written <= 0:
                    raise RuntimeError("short write while staging build output")
                cursor += written
            offset += len(block)
        os.fchmod(target, mode)
        os.fsync(target)
        exact = open_exact_at(stage_fd, name, wanted, mode)
        if exact is None:
            raise RuntimeError("staged build output disappeared")
        os.close(target)
        return exact

    binary_stage = (
        copy_to_stage(binary, binary_name, binary_digest, 0o555)
        if public_binary is None
        else open_exact_at(stage_fd, binary_name, binary_digest, 0o555)
    )
    closure_stage = (
        copy_to_stage(closure, closure_name, closure_digest, 0o444)
        if public_closure is None
        else open_exact_at(stage_fd, closure_name, closure_digest, 0o444)
    )
    if public_binary is None and binary_stage is None:
        raise RuntimeError("binary stage is absent")
    if public_closure is None and closure_stage is None:
        raise RuntimeError("manifest stage is absent")
    if digest_fd(binary) != binary_digest or digest_fd(closure) != closure_digest:
        raise RuntimeError("held build output changed during staging")

    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameatx_np
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int

    def publish_one(name: str, staged: tuple[int, os.stat_result], wanted: str, mode: int) -> bool:
        if rename(stage_fd, os.fsencode(name), parent_fd, os.fsencode(name), RENAME_EXCL) == 0:
            exact = open_exact_at(parent_fd, name, wanted, mode)
            if exact is None or identity(exact[1]) != identity(os.fstat(staged[0])):
                raise RuntimeError(f"published build identity changed: {name}")
            os.close(exact[0])
            return True
        saved_errno = ctypes.get_errno()
        if saved_errno == errno.EEXIST:
            exact = open_exact_at(parent_fd, name, wanted, mode)
            if exact is not None:
                os.close(exact[0])
                return False
        raise OSError(saved_errno, os.strerror(saved_errno))

    binary_created = False
    try:
        if public_binary is None:
            binary_created = publish_one(binary_name, binary_stage, binary_digest, 0o555)
        if public_closure is None:
            publish_one(closure_name, closure_stage, closure_digest, 0o444)
    except BaseException:
        if binary_created:
            safe_unlink_at(parent_fd, binary_name, binary_stage[0])
        os.fsync(parent_fd)
        raise

    final_binary = open_exact_at(parent_fd, binary_name, binary_digest, 0o555)
    final_closure = open_exact_at(parent_fd, closure_name, closure_digest, 0o444)
    if final_binary is None or final_closure is None:
        raise RuntimeError("published build pair is incomplete")
    os.fsync(parent_fd)

    for name, staged in ((binary_name, binary_stage), (closure_name, closure_stage)):
        if staged is not None:
            try:
                safe_unlink_at(stage_fd, name, staged[0])
            except FileNotFoundError:
                pass
            os.close(staged[0])
    named_stage = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
    if identity(named_stage) != identity(os.fstat(stage_fd)):
        raise RuntimeError("build publication stage identity changed")
    os.rmdir(stage_name, dir_fd=parent_fd)
    os.fsync(parent_fd)
    for descriptor in (
        final_binary[0],
        final_closure[0],
        binary,
        closure,
        stage_fd,
        parent_fd,
    ):
        os.close(descriptor)
    if public_binary is not None:
        os.close(public_binary[0])
    if public_closure is not None:
        os.close(public_closure[0])


def main(argv: list[str]) -> int:
    if len(argv) == 7 and argv[1] == "hold":
        hold_inputs(*argv[2:])
        return 0
    if len(argv) == 9 and argv[1] == "publish":
        publish_outputs(*argv[2:])
        return 0
    raise SystemExit(
        "usage: build_support.py hold MANIFEST INPUTS CLOSURE READY RELEASE | "
        "publish PARENT BINARY CLOSURE BINARY_NAME CLOSURE_NAME BINARY_SHA256 CLOSURE_SHA256"
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
