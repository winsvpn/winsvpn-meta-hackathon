#!/usr/bin/env python3
"""Updater-specific entrypoint for retained native build support."""

from __future__ import annotations

import fcntl
import os
import re
import stat
import sys


BASE_SUPPORT_FD = 10
BLOCK_SIZE = 1024 * 1024
UPDATER_HEADER = (
    "contract=winsvpn-macos-release-python-owner-updater-build-closure-v1\n"
    "schema_version=1\n"
    "minimum_macos=13.0\n"
    "codesign_identifier=org.winsvpn.releasepython.owner-updater\n"
)
UPDATER_STAGE_PREFIX = ".winsvpn-owner-updater-build-"
UPDATER_STAGE_PATTERN = re.compile(r"^[.]winsvpn-owner-updater-build-[0-9a-f]{48}$")
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
MAX_ABANDONED_STAGES = 16


def retained_base_source() -> bytes:
    blocks: list[bytes] = []
    offset = 0
    while True:
        block = os.pread(BASE_SUPPORT_FD, BLOCK_SIZE, offset)
        if not block:
            return b"".join(blocks)
        blocks.append(block)
        offset += len(block)


def leaf_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        getattr(info, "st_flags", 0),
    )


def reap_abandoned_stages(parent: str, binary_name: str, closure_name: str) -> None:
    parent_fd = os.open(parent, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    try:
        parent_info = os.fstat(parent_fd)
        stages = sorted(name for name in os.listdir(parent_fd) if UPDATER_STAGE_PATTERN.fullmatch(name))
        if len(stages) > MAX_ABANDONED_STAGES:
            raise RuntimeError("too many abandoned updater build stages")
        for stage in stages:
            stage_fd = os.open(
                stage, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=parent_fd
            )
            try:
                named_stage = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
                retained_stage = os.fstat(stage_fd)
                if (
                    leaf_identity(named_stage) != leaf_identity(retained_stage)
                    or not stat.S_ISDIR(retained_stage.st_mode)
                    or retained_stage.st_uid != os.getuid()
                    or retained_stage.st_gid != parent_info.st_gid
                    or stat.S_IMODE(retained_stage.st_mode) != 0o700
                    or getattr(retained_stage, "st_flags", 0) != 0
                ):
                    raise RuntimeError(f"abandoned updater build stage custody is invalid: {stage}")
                children = os.listdir(stage_fd)
                if len(children) > 2:
                    raise RuntimeError(f"abandoned updater build stage has too many entries: {stage}")
                if not set(children).issubset({binary_name, closure_name}):
                    raise RuntimeError(f"abandoned updater build stage has an unexpected entry: {stage}")
                for child in children:
                    if child in {".", ".."} or "/" in child:
                        raise RuntimeError(f"abandoned updater build stage entry is unsafe: {stage}")
                    descriptor = os.open(
                        child, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC, dir_fd=stage_fd
                    )
                    try:
                        named = os.stat(child, dir_fd=stage_fd, follow_symlinks=False)
                        retained = os.fstat(descriptor)
                        if (
                            leaf_identity(named) != leaf_identity(retained)
                            or not stat.S_ISREG(retained.st_mode)
                            or retained.st_uid != os.getuid()
                            or retained.st_gid != parent_info.st_gid
                            or retained.st_nlink != 1
                            or stat.S_IMODE(retained.st_mode) not in {0o444, 0o555}
                            or getattr(retained, "st_flags", 0) != 0
                        ):
                            raise RuntimeError(
                                f"abandoned updater build stage leaf custody is invalid: {stage}/{child}"
                            )
                        os.unlink(child, dir_fd=stage_fd)
                    finally:
                        os.close(descriptor)
                named_stage = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
                if leaf_identity(named_stage) != leaf_identity(os.fstat(stage_fd)):
                    raise RuntimeError(f"abandoned updater build stage identity changed: {stage}")
                os.rmdir(stage, dir_fd=parent_fd)
            finally:
                os.close(stage_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def main() -> int:
    source = retained_base_source()
    if not source:
        raise RuntimeError("retained bootstrap build support is empty")
    namespace: dict[str, object] = {"__name__": "retained_updater_build_support"}
    exec(compile(source, "<retained-owner-build-support>", "exec"), namespace)
    namespace["HEADER"] = UPDATER_HEADER
    namespace["STAGE_PREFIX"] = UPDATER_STAGE_PREFIX
    entrypoint = namespace.get("main")
    if not callable(entrypoint):
        raise RuntimeError("retained bootstrap build support has no entrypoint")
    if len(sys.argv) == 8 and sys.argv[1] == "hold":
        output_parent = sys.argv[7]
        lock_fd = os.open(
            output_parent, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return int(entrypoint(sys.argv[:7]))
        finally:
            os.close(lock_fd)
    if len(sys.argv) == 5 and sys.argv[1] == "reap":
        reap_abandoned_stages(sys.argv[2], sys.argv[3], sys.argv[4])
        return 0
    return int(entrypoint(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())
