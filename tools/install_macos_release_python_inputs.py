#!/usr/bin/env python3
"""Preflight or install the fixed ReleasePython content-addressed inputs.

The non-root ``preflight`` action is safe to run from the repository. The
``install`` action is owner-only: run a separately reviewed, root-owned copy
with both its own SHA-256 and the manifest SHA-256 supplied explicitly.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


CONTRACT = "winsvpn-release-python-input-custody-v1"
DESTINATION_ROOT = Path("/Library/WinsVPN/ReleasePythonInputs/sha256")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_ARTIFACT = 256 * 1024 * 1024
SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)


class Refused(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_held(path: Path, maximum: int) -> tuple[int, bytes, os.stat_result]:
    if not path.is_absolute() or path.is_symlink():
        raise Refused(f"unsafe input path: {path}")
    before = path.lstat()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size < 1
            or opened.st_size > maximum
            or identity(before) != identity(opened)
        ):
            raise Refused(f"input is not one bounded regular file: {path}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise Refused(f"input was truncated while retained: {path}")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise Refused(f"input grew while retained: {path}")
        if not (
            identity(opened)
            == identity(os.fstat(descriptor))
            == identity(path.lstat())
        ):
            raise Refused(f"input identity changed while retained: {path}")
        return descriptor, b"".join(chunks), opened
    except BaseException:
        os.close(descriptor)
        raise


def load_manifest(path: Path) -> tuple[bytes, list[dict[str, str]]]:
    descriptor, data, _info = read_held(path, 1024 * 1024)
    os.close(descriptor)
    try:
        document = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refused(f"custody manifest is invalid: {exc}") from exc
    expected_keys = {
        "artifact_count",
        "artifacts",
        "contract",
        "destination_root",
        "pin_manifest_sha256",
        "schema_version",
    }
    if type(document) is not dict or set(document) != expected_keys:
        raise Refused("custody manifest keys are not exact")
    if (
        document["contract"] != CONTRACT
        or document["schema_version"] != 1
        or type(document["schema_version"]) is not int
        or document["destination_root"] != str(DESTINATION_ROOT)
        or type(document["artifacts"]) is not list
        or document["artifact_count"] != 34
        or len(document["artifacts"]) != 34
        or not isinstance(document["pin_manifest_sha256"], str)
        or HEX64.fullmatch(document["pin_manifest_sha256"]) is None
    ):
        raise Refused("custody manifest contract is not exact")
    artifacts: list[dict[str, str]] = []
    kind_counts: dict[str, int] = {}
    for index, record in enumerate(document["artifacts"]):
        if type(record) is not dict or set(record) != {
            "kind", "leaf", "mode", "path", "sha256"
        }:
            raise Refused(f"custody artifact {index} keys are not exact")
        if not all(type(record[key]) is str for key in record):
            raise Refused(f"custody artifact {index} values are not strings")
        kind = record["kind"]
        leaf = record["leaf"]
        digest = record["sha256"]
        mode = record["mode"]
        path_value = Path(record["path"])
        expected_mode = "0555" if kind == "sigstore-verifier" else "0444"
        if (
            kind not in {
                "package",
                "sigstore-bundle",
                "source-archive",
                "source-sigstore-bundle",
                "sigstore-trusted-root",
                "sigstore-verifier",
                "wheel",
            }
            or leaf != Path(leaf).name
            or leaf in {"", ".", ".."}
            or HEX64.fullmatch(digest) is None
            or mode != expected_mode
            or path_value != DESTINATION_ROOT / digest / leaf
        ):
            raise Refused(f"custody artifact {index} is not exact")
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        artifacts.append(record)
    if kind_counts != {
        "package": 1,
        "sigstore-bundle": 1,
        "source-archive": 1,
        "source-sigstore-bundle": 1,
        "sigstore-trusted-root": 1,
        "sigstore-verifier": 1,
        "wheel": 28,
    } or len({record["path"] for record in artifacts}) != 34:
        raise Refused("custody artifact inventory is not exact")
    return data, artifacts


def verify_sources(source: Path, artifacts: list[dict[str, str]]) -> list[tuple[dict[str, str], int, bytes]]:
    if not source.is_absolute() or source.is_symlink() or not source.is_dir():
        raise Refused("source directory must be one absolute non-symlink directory")
    held: list[tuple[dict[str, str], int, bytes]] = []
    try:
        for record in artifacts:
            descriptor, data, _info = read_held(source / record["leaf"], MAX_ARTIFACT)
            if sha256_bytes(data) != record["sha256"]:
                os.close(descriptor)
                raise Refused(f"source digest mismatch: {record['leaf']}")
            held.append((record, descriptor, data))
        if {path.name for path in source.iterdir()} != {record["leaf"] for record in artifacts}:
            raise Refused("source directory has missing or additional leaves")
        return held
    except BaseException:
        for _record, descriptor, _data in held:
            os.close(descriptor)
        raise


def verify_installed(path: Path, record: dict[str, str]) -> None:
    info = path.lstat()
    mode = int(record["mode"], 8)
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != grp.getgrnam("wheel").gr_gid
        or stat.S_IMODE(info.st_mode) != mode
        or info.st_nlink != 1
        or not (int(getattr(info, "st_flags", 0)) & SF_IMMUTABLE)
    ):
        raise Refused(f"installed custody metadata is invalid: {path}")
    descriptor, data, _opened = read_held(path, MAX_ARTIFACT)
    os.close(descriptor)
    if sha256_bytes(data) != record["sha256"]:
        raise Refused(f"installed custody digest is invalid: {path}")


def install(held: list[tuple[dict[str, str], int, bytes]]) -> None:
    if os.geteuid() != 0:
        raise Refused("install requires a visible owner-controlled root shell")
    wheel_gid = grp.getgrnam("wheel").gr_gid
    if DESTINATION_ROOT.exists():
        for record, _descriptor, _data in held:
            verify_installed(Path(record["path"]), record)
        return
    parent = DESTINATION_ROOT.parents[1]
    parent_info = parent.lstat()
    if (
        parent.is_symlink()
        or not parent.is_dir()
        or parent_info.st_uid != 0
        or stat.S_IMODE(parent_info.st_mode) & 0o022
    ):
        raise Refused("/Library/WinsVPN is not a trusted root-owned parent")
    inputs_root = DESTINATION_ROOT.parent
    os.mkdir(inputs_root, 0o700)
    os.chown(inputs_root, 0, wheel_gid)
    os.mkdir(DESTINATION_ROOT, 0o700)
    os.chown(DESTINATION_ROOT, 0, wheel_gid)
    try:
        for record, descriptor, data in held:
            digest_dir = Path(record["path"]).parent
            os.mkdir(digest_dir, 0o700)
            os.chown(digest_dir, 0, wheel_gid)
            target = Path(record["path"])
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            destination_fd = os.open(target, flags, 0o600)
            try:
                view = memoryview(data)
                offset = 0
                while offset < len(view):
                    offset += os.write(destination_fd, view[offset:])
                os.fchmod(destination_fd, int(record["mode"], 8))
                os.fchown(destination_fd, 0, wheel_gid)
                os.fsync(destination_fd)
            finally:
                os.close(destination_fd)
            os.chflags(target, SF_IMMUTABLE, follow_symlinks=False)
            os.chmod(digest_dir, 0o555)
            os.chflags(digest_dir, SF_IMMUTABLE, follow_symlinks=False)
        for directory in (DESTINATION_ROOT, inputs_root):
            os.chmod(directory, 0o555)
            os.chflags(directory, SF_IMMUTABLE, follow_symlinks=False)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException as exc:
        raise Refused(
            "partial input installation requires independent owner recovery; "
            "this installer never clears schg"
        ) from exc
    for record, _descriptor, _data in held:
        verify_installed(Path(record["path"]), record)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "install"))
    parser.add_argument("source", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--reviewed-script-sha256", default="")
    parser.add_argument("--reviewed-manifest-sha256", default="")
    args = parser.parse_args()
    try:
        manifest_data, artifacts = load_manifest(args.manifest)
        held = verify_sources(args.source, artifacts)
        try:
            if args.action == "install":
                script_digest = sha256_bytes(Path(__file__).read_bytes())
                if (
                    HEX64.fullmatch(args.reviewed_script_sha256) is None
                    or args.reviewed_script_sha256 != script_digest
                    or HEX64.fullmatch(args.reviewed_manifest_sha256) is None
                    or args.reviewed_manifest_sha256 != sha256_bytes(manifest_data)
                ):
                    raise Refused("reviewed installer or manifest digest is not exact")
                install(held)
            elif os.geteuid() == 0:
                raise Refused("repository preflight refuses euid 0")
        finally:
            for _record, descriptor, _data in held:
                os.close(descriptor)
        print(f"ReleasePython input custody {args.action}: PASS ({len(artifacts)} artifacts)")
        return 0
    except (OSError, Refused) as exc:
        print(f"ReleasePython input custody: FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
