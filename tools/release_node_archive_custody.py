#!/usr/bin/env python3
"""Prepare, verify, run, and clean a private Node.js release runtime.

The future ``tools.node`` pin binds ``version``, ``platform``, ``architecture``,
``archive_format``, ``top_level_root``, ``executable``, and
``executable_sha256``. Platform-keyed ``archive_path``, ``archive_sha256``, and
``install_tree_sha256`` objects must each contain ``darwin_arm64``.
"""

from __future__ import annotations

import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unicodedata


MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_EXPANDED = 768 * 1024 * 1024
MAX_MEMBER = 384 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_RATIO = 250
MAX_DECODE_CHUNK = 8 * 1024 * 1024
MAX_DECODER_MEMORY = 256 * 1024 * 1024
BLOCK = 512
ARM64_CPU_TYPE = 0x0100000C
VERSION_RE = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")


class Refused(ValueError):
    """A fail-closed custody refusal."""


def fail(message: str) -> None:
    raise Refused(message)


def _identity(info: os.stat_result) -> tuple[int, ...]:
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


def digest_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        while block := os.read(fd, 1024 * 1024):
            digest.update(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    latest = path.lstat()
    if not (_identity(before) == _identity(after) == _identity(latest)):
        fail(f"file changed while it was hashed: {path}")
    return digest.hexdigest()


def _safe_path_components(path: Path) -> None:
    if not path.is_absolute():
        fail(f"path is not absolute: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part in {"", ".", ".."}:
            fail(f"unsafe path component: {path}")
        current /= part
        info = current.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            fail(f"symbolic path component rejected: {current}")
        if info.st_uid not in {0, os.getuid()}:
            fail(f"foreign-owned path component rejected: {current}")
        if mode & 0o022 and not (
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and mode & stat.S_ISVTX
        ):
            fail(f"unsafe writable path component rejected: {current}")


def require_safe_input(path: Path, expected_name: str) -> None:
    if path.name != expected_name:
        fail("Node archive basename does not match its release identity")
    _safe_path_components(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        fail("Node archive must be one owner-controlled regular file")
    if stat.S_IMODE(info.st_mode) != 0o444:
        fail("Node archive must have immutable mode 0444")


def _read_stable_file(path: Path) -> bytes:
    _safe_path_components(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail("pin manifest must be one regular non-hardlinked file")
        if before.st_size <= 0 or before.st_size > MAX_MANIFEST:
            fail("Node pin manifest size is outside the accepted range")
        chunks: list[bytes] = []
        while block := os.read(fd, 1024 * 1024):
            chunks.append(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    latest = path.lstat()
    if not (_identity(before) == _identity(after) == _identity(latest)):
        fail("Node pin manifest changed while it was read")
    return b"".join(chunks)


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"Node pin field must be an object: {label}")
    return value


def _text(mapping: dict[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        fail(f"Node pin field must be one non-empty string: {key}")
    return value


def load_pin(manifest: Path) -> dict[str, str]:
    try:
        document = json.loads(_read_stable_file(manifest), object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        fail(f"Node pin manifest is not UTF-8: {exc}")
    root = _mapping(document, "document")
    tools = _mapping(root.get("tools"), "tools")
    node = _mapping(tools.get("node"), "tools.node")
    paths = _mapping(node.get("archive_path"), "archive_path")
    archive_hashes = _mapping(node.get("archive_sha256"), "archive_sha256")
    tree_hashes = _mapping(node.get("install_tree_sha256"), "install_tree_sha256")
    result = {
        "version": _text(node, "version"),
        "platform": _text(node, "platform"),
        "architecture": _text(node, "architecture"),
        "archive_format": _text(node, "archive_format"),
        "archive": _text(paths, "darwin_arm64"),
        "archive_sha": _text(archive_hashes, "darwin_arm64"),
        "tree_sha": _text(tree_hashes, "darwin_arm64"),
        "root": _text(node, "top_level_root"),
        "executable": _text(node, "executable"),
        "executable_sha": _text(node, "executable_sha256"),
    }
    match = VERSION_RE.fullmatch(result["version"])
    if match is None:
        fail("Node version pin must be an exact stable semantic version")
    normalized_version = result["version"] if result["version"].startswith("v") else f"v{result['version']}"
    expected_root = f"node-{normalized_version}-darwin-arm64"
    if result["platform"] != "darwin-arm64" or result["architecture"] != "arm64":
        fail("Node platform or architecture pin mismatch")
    if result["archive_format"] != "tar.xz":
        fail("only exact official Node tar.xz archives are accepted")
    if result["root"] != expected_root or result["executable"] != "bin/node":
        fail("Node archive layout pin mismatch")
    for key in ("archive_sha", "tree_sha", "executable_sha"):
        if HEX_RE.fullmatch(result[key]) is None:
            fail(f"invalid Node digest pin: {key}")
    result["normalized_version"] = normalized_version
    return result


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            fail("short write while copying the Node archive")
        view = view[written:]


def copy_stable(source: Path, destination: Path, expected_sha: str) -> None:
    before = source.lstat()
    if digest_file(source) != expected_sha:
        fail("Node archive SHA-256 mismatch")
    source_fd = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        while block := os.read(source_fd, 1024 * 1024):
            _write_all(destination_fd, block)
        os.fsync(destination_fd)
    finally:
        os.close(source_fd)
        os.close(destination_fd)
    if _identity(before) != _identity(source.lstat()) or digest_file(destination) != expected_sha:
        fail("Node archive changed during authenticated copying")


def decompress_exact_xz(archive: Path, output: Path) -> int:
    compressed_size = archive.stat().st_size
    if compressed_size <= 0 or compressed_size > MAX_ARCHIVE:
        fail("Node archive size is outside the accepted range")
    decoder = lzma.LZMADecompressor(
        format=lzma.FORMAT_XZ, memlimit=MAX_DECODER_MEMORY
    )
    total = 0
    with archive.open("rb") as source, output.open("xb") as target:
        while block := source.read(1024 * 1024):
            pending = block
            while pending or not decoder.needs_input:
                remaining = min(
                    MAX_EXPANDED - total + 1,
                    compressed_size * MAX_RATIO - total + 1,
                    MAX_DECODE_CHUNK,
                )
                if remaining <= 0:
                    fail("Node archive expansion limit exceeded")
                try:
                    expanded = decoder.decompress(pending, max_length=remaining)
                except lzma.LZMAError as exc:
                    fail(f"invalid Node XZ stream: {exc}")
                pending = b""
                total += len(expanded)
                if total > MAX_EXPANDED or total > compressed_size * MAX_RATIO:
                    fail("Node archive expansion limit exceeded")
                target.write(expanded)
                if decoder.eof:
                    if decoder.unused_data or source.read(1):
                        fail("Node XZ concatenated streams or trailing data are forbidden")
                    break
                if decoder.needs_input:
                    break
                if not expanded:
                    fail("Node XZ decoder made no progress")
            if decoder.eof:
                break
        if not decoder.eof:
            fail("Node XZ stream is truncated")
        target.flush()
        os.fsync(target.fileno())
    if total < BLOCK * 3 or total % BLOCK:
        fail("Node TAR framing is malformed")
    return total


def _tar_text(field: bytes, label: str) -> str:
    value, separator, padding = field.partition(b"\0")
    if separator and any(padding):
        fail(f"non-zero TAR padding in {label}")
    try:
        text = value.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        fail(f"non-UTF-8 TAR {label}: {exc}")
    if "\x00" in text:
        fail(f"embedded NUL in TAR {label}")
    return text


def _tar_number(field: bytes, label: str) -> int:
    if field and field[0] & 0x80:
        fail(f"base-256 TAR number rejected: {label}")
    value = field.strip(b" \0")
    if not value:
        return 0
    if any(byte not in b"01234567" for byte in value):
        fail(f"invalid TAR octal number: {label}")
    return int(value, 8)


def _member_path(name: str, expected_root: str) -> str:
    normalized = unicodedata.normalize("NFC", name)
    if normalized != name or not name or name.startswith("/") or "\\" in name:
        fail("unsafe or non-canonical Node TAR member path")
    pure = PurePosixPath(name.rstrip("/"))
    if not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        fail("Node TAR path traversal rejected")
    canonical = pure.as_posix()
    if len(canonical.encode("utf-8")) > 1024:
        fail("Node TAR member path is too long")
    if pure.parts[0] != expected_root:
        fail("Node TAR member escaped its pinned top-level root")
    return canonical


def _symlink_target(member: str, target: str, expected_root: str) -> str:
    normalized = unicodedata.normalize("NFC", target)
    if normalized != target or not target or target.startswith("/") or "\\" in target:
        fail("unsafe or non-canonical Node TAR symbolic-link target")
    parts = list(PurePosixPath(member).parent.parts)
    for part in PurePosixPath(target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if len(parts) <= 1:
                fail("Node TAR symbolic link escaped its pinned top-level root")
            parts.pop()
        else:
            parts.append(part)
    if not parts or parts[0] != expected_root:
        fail("Node TAR symbolic link escaped its pinned top-level root")
    resolved = PurePosixPath(*parts).as_posix()
    if len(target.encode("utf-8")) > 1024 or len(resolved.encode("utf-8")) > 1024:
        fail("Node TAR symbolic-link target is too long")
    return resolved


def _validate_header(
    header: bytes, offset: int, expected_root: str
) -> tuple[str, str, int, str]:
    stored = _tar_number(header[148:156], "checksum")
    calculated = sum(header[:148]) + (8 * 32) + sum(header[156:])
    if stored != calculated:
        fail(f"Node TAR header checksum mismatch at offset {offset}")
    if header[257:263] != b"ustar\0" or header[263:265] != b"00":
        fail("only strict POSIX ustar Node archives are accepted")
    _tar_number(header[100:108], "mode")
    _tar_number(header[108:116], "uid")
    _tar_number(header[116:124], "gid")
    _tar_number(header[136:148], "mtime")
    if _tar_number(header[329:337], "device major") or _tar_number(
        header[337:345], "device minor"
    ):
        fail("Node TAR device metadata is forbidden")
    if any(header[500:512]):
        fail("Node TAR header padding is non-zero")
    name = _tar_text(header[0:100], "name")
    prefix = _tar_text(header[345:500], "prefix")
    full_name = f"{prefix}/{name}" if prefix else name
    canonical = _member_path(full_name, expected_root)
    kind_byte = header[156:157]
    if kind_byte in {b"\0", b"0"}:
        kind = "file"
    elif kind_byte == b"5":
        kind = "dir"
    elif kind_byte == b"2":
        kind = "symlink"
    else:
        fail("Node TAR hardlinks, special files, and extension records are forbidden")
    link_target = _tar_text(header[157:257], "link target")
    if kind == "symlink":
        resolved_target = _symlink_target(canonical, link_target, expected_root)
    elif link_target:
        fail("Node TAR link target metadata is forbidden")
    else:
        resolved_target = ""
    size = _tar_number(header[124:136], "size")
    if kind in {"dir", "symlink"} and size != 0:
        fail("Node TAR directory or symbolic link has non-zero content")
    if size > MAX_MEMBER:
        fail("Node TAR member exceeds the size limit")
    return canonical, kind, size, resolved_target


def scan_tar(
    tar_path: Path, expected_root: str
) -> list[tuple[str, str, int, int, str]]:
    members: list[tuple[str, str, int, int, str]] = []
    seen: set[str] = set()
    folded: set[str] = set()
    declared_dirs: set[str] = set()
    total_files = 0
    offset = 0
    archive_size = tar_path.stat().st_size
    with tar_path.open("rb") as stream:
        while True:
            stream.seek(offset)
            header = stream.read(BLOCK)
            if len(header) != BLOCK:
                fail("Node TAR ended before its required trailer")
            if header == b"\0" * BLOCK:
                second = stream.read(BLOCK)
                if second != b"\0" * BLOCK:
                    fail("Node TAR requires two zero trailer blocks")
                while trailer := stream.read(1024 * 1024):
                    if any(trailer):
                        fail("Node TAR comments or non-zero trailing data are forbidden")
                break
            if len(members) >= MAX_MEMBERS:
                fail("Node TAR member-count limit exceeded")
            canonical, kind, size, link_target = _validate_header(
                header, offset, expected_root
            )
            collision = canonical.casefold()
            if canonical in seen or collision in folded:
                fail("Node TAR duplicate, Unicode, or case-fold collision rejected")
            parent = PurePosixPath(canonical).parent
            if canonical != expected_root and parent.as_posix() not in declared_dirs:
                fail("Node TAR member parent directory was not declared first")
            if canonical == expected_root and kind != "dir":
                fail("Node TAR top-level root must be a directory")
            seen.add(canonical)
            folded.add(collision)
            if kind == "dir":
                declared_dirs.add(canonical)
            else:
                total_files += size
                if total_files > MAX_EXPANDED:
                    fail("Node TAR expanded file-size limit exceeded")
            data_offset = offset + BLOCK
            padded = ((size + BLOCK - 1) // BLOCK) * BLOCK
            next_offset = data_offset + padded
            if next_offset > archive_size:
                fail("Node TAR member extends beyond the archive")
            if padded > size:
                stream.seek(data_offset + size)
                if any(stream.read(padded - size)):
                    fail("Node TAR member has non-zero data padding")
            members.append((canonical, kind, size, data_offset, link_target))
            offset = next_offset
    if expected_root not in declared_dirs:
        fail("Node TAR pinned top-level root is absent")
    if not members:
        fail("empty Node TAR rejected")
    return members


def safe_extract(archive: Path, destination: Path, expected_root: str) -> Path:
    if destination.exists() or destination.is_symlink():
        fail("Node extraction destination already exists")
    tar_path = destination.parent / f".{destination.name}.authenticated.tar"
    try:
        decompress_exact_xz(archive, tar_path)
        members = scan_tar(tar_path, expected_root)
        destination.mkdir(mode=0o700)
        with tar_path.open("rb") as stream:
            for canonical, kind, size, data_offset, _link_target in members:
                target = destination.joinpath(*PurePosixPath(canonical).parts)
                if kind == "dir":
                    target.mkdir(mode=0o700)
                    continue
                if kind == "symlink":
                    continue
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
                try:
                    stream.seek(data_offset)
                    remaining = size
                    while remaining:
                        block = stream.read(min(1024 * 1024, remaining))
                        if not block:
                            fail("Node TAR member was truncated during extraction")
                        _write_all(fd, block)
                        remaining -= len(block)
                    os.fsync(fd)
                finally:
                    os.close(fd)
        for canonical, kind, _size, _data_offset, resolved_target in members:
            if kind != "symlink":
                continue
            target = destination.joinpath(*PurePosixPath(canonical).parts)
            resolved_parts = PurePosixPath(resolved_target).parts
            resolved = destination
            for index, part in enumerate(resolved_parts):
                resolved /= part
                info = resolved.lstat()
                if stat.S_ISLNK(info.st_mode):
                    fail("Node TAR symbolic link target traverses another symbolic link")
                if index < len(resolved_parts) - 1 and not stat.S_ISDIR(info.st_mode):
                    fail("Node TAR symbolic link target parent is not a directory")
            if not stat.S_ISREG(resolved.lstat().st_mode):
                fail("Node TAR symbolic link target is absent or not a regular file")
            relative_target = os.path.relpath(resolved, start=target.parent)
            if relative_target.startswith("/"):
                fail("Node TAR symbolic link target became absolute")
            os.symlink(relative_target, target)
    finally:
        if tar_path.exists() and not tar_path.is_symlink():
            tar_path.unlink()
    root = destination / expected_root
    binary = root / "bin/node"
    if not binary.is_file() or binary.is_symlink():
        fail("pinned Node executable is absent")
    binary.chmod(0o500)
    for path in destination.rglob("*"):
        if path.is_symlink():
            continue
        if path.is_file() and path != binary:
            path.chmod(0o400)
    for directory in sorted((path for path in destination.rglob("*") if path.is_dir()), reverse=True):
        directory.chmod(0o500)
    destination.chmod(0o500)
    return root


def tree_hash(root: Path) -> str:
    if root.is_symlink():
        fail("Node root symbolic link rejected")
    root = root.resolve(strict=True)
    root_info = root.lstat()
    if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o500:
        fail("Node root is not owner-controlled and frozen")
    digest = hashlib.sha256()

    def feed(*parts: object) -> None:
        for part in parts:
            value = str(part).encode("utf-8", "surrogateescape")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    def walk(directory: Path) -> None:
        with os.scandir(directory) as scan:
            entries = sorted(scan, key=lambda item: os.fsencode(item.name))
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            info = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid != os.getuid():
                fail(f"unsafe Node tree ownership or mode: {relative}")
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                resolved_relative = _symlink_target(
                    f"root/{relative}", target, "root"
                )
                resolved = root
                target_parts = PurePosixPath(resolved_relative).parts[1:]
                for index, part in enumerate(target_parts):
                    resolved /= part
                    resolved_info = resolved.lstat()
                    if stat.S_ISLNK(resolved_info.st_mode):
                        fail(f"unsafe Node symbolic-link target: {relative}")
                    if index < len(target_parts) - 1 and not stat.S_ISDIR(
                        resolved_info.st_mode
                    ):
                        fail(f"unsafe Node symbolic-link target: {relative}")
                if not stat.S_ISREG(resolved.lstat().st_mode):
                    fail(f"unsafe Node symbolic-link target: {relative}")
                feed("L", relative, target)
            elif mode & 0o022:
                fail(f"unsafe Node tree ownership or mode: {relative}")
            elif stat.S_ISDIR(info.st_mode):
                if mode != 0o500:
                    fail(f"Node directory is not frozen: {relative}")
                feed("D", relative, mode)
                walk(path)
            elif stat.S_ISREG(info.st_mode):
                expected_mode = 0o500 if relative == "bin/node" else 0o400
                if info.st_nlink != 1 or mode != expected_mode:
                    fail(f"Node file mode or hardlink rejected: {relative}")
                feed("F", relative, mode, info.st_size, digest_file(path))
            else:
                fail(f"unsupported Node tree entry: {relative}")

    walk(root)
    return digest.hexdigest()


def runtime_identity(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        fail("Node runtime is not one private owner-controlled directory")
    return ":".join(
        str(value)
        for value in (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_mode,
            info.st_nlink,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    )


def _require_private_state(runtime: Path) -> None:
    for relative in ("state", "state/home", "state/tmp"):
        path = runtime / relative
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            fail(f"unsafe Node runtime state directory: {relative}")
        if stat.S_IMODE(info.st_mode) != 0o700:
            fail(f"Node runtime state directory mode changed: {relative}")


def macho_architectures(binary: Path) -> set[str]:
    with binary.open("rb") as stream:
        header = stream.read(4096)
    if len(header) < 8:
        fail("Node executable is too small to be Mach-O")
    magic = header[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        cpu_type = struct.unpack_from("<I", header, 4)[0]
        return {"arm64" if cpu_type == ARM64_CPU_TYPE else f"cpu-{cpu_type}"}
    if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}:
        is_64 = magic == b"\xca\xfe\xba\xbf"
        count = struct.unpack_from(">I", header, 4)[0]
        entry_size = 32 if is_64 else 20
        if count == 0 or count > 32 or 8 + count * entry_size > len(header):
            fail("Node universal Mach-O header is malformed")
        result: set[str] = set()
        for index in range(count):
            cpu_type = struct.unpack_from(">I", header, 8 + index * entry_size)[0]
            result.add("arm64" if cpu_type == ARM64_CPU_TYPE else f"cpu-{cpu_type}")
        return result
    fail("Node executable is not a supported Mach-O binary")


def _minimal_environment(runtime: Path, binary: Path) -> dict[str, str]:
    return {
        "HOME": str(runtime / "state/home"),
        "TMPDIR": str(runtime / "state/tmp"),
        "PATH": f"{binary.parent}:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _run_node(binary: Path, runtime: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), *arguments],
        env=_minimal_environment(runtime, binary),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def check_node_identity(binary: Path, runtime: Path, version: str, architecture: str) -> None:
    if macho_architectures(binary) != {architecture}:
        fail("Node Mach-O architecture does not match the exact pin")
    version_result = _run_node(binary, runtime, ["--version"])
    expected_version = version if version.startswith("v") else f"v{version}"
    if version_result.returncode != 0 or version_result.stdout.strip() != expected_version or version_result.stderr:
        fail("Node runtime version probe mismatch")
    platform_result = _run_node(binary, runtime, ["-p", "process.platform + '|' + process.arch"])
    if platform_result.returncode != 0 or platform_result.stdout.strip() != f"darwin|{architecture}" or platform_result.stderr:
        fail("Node runtime platform or architecture probe mismatch")


def _runtime_parts(arguments: list[str]) -> tuple[Path, str, Path, str, Path, str]:
    if len(arguments) != 6:
        fail("Node runtime verification arguments are malformed")
    runtime_text, expected_id, root_text, expected_tree, binary_text, expected_binary = arguments
    if HEX_RE.fullmatch(expected_tree) is None or HEX_RE.fullmatch(expected_binary) is None:
        fail("Node runtime digest arguments are malformed")
    runtime = Path(runtime_text)
    root = Path(root_text)
    binary = Path(binary_text)
    return runtime, expected_id, root, expected_tree, binary, expected_binary


def verify_runtime(arguments: list[str]) -> tuple[Path, Path]:
    runtime, expected_id, root, expected_tree, binary, expected_binary = _runtime_parts(arguments)
    if runtime_identity(runtime) != expected_id:
        fail("Node runtime identity changed")
    if runtime.parent != Path("/private/tmp") or not runtime.name.startswith("wins-release-node."):
        fail("Node runtime pointer escaped its private prefix")
    expected_root_prefix = runtime / "extracted"
    if root.parent != expected_root_prefix or binary != root / "bin/node":
        fail("Node runtime pointers changed")
    _require_private_state(runtime)
    if tree_hash(root) != expected_tree or digest_file(binary) != expected_binary:
        fail("Node runtime tree or executable content changed")
    return runtime, binary


def _destroy_runtime(runtime: Path) -> None:
    if runtime.parent != Path("/private/tmp") or not runtime.name.startswith("wins-release-node."):
        fail("refusing Node cleanup outside the private runtime prefix")
    if runtime.is_symlink() or not runtime.is_dir():
        fail("refusing cleanup of a substituted Node runtime")
    for base, directories, files in os.walk(runtime, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files:
            path = base_path / name
            if path.is_symlink():
                continue
            if not path.is_file():
                fail("refusing cleanup of an unsupported Node runtime entry")
            path.chmod(0o600)
        for name in directories:
            path = base_path / name
            if path.is_symlink() or not path.is_dir():
                fail("refusing cleanup of an unsupported Node runtime directory")
            path.chmod(0o700)
        base_path.chmod(0o700)
    shutil.rmtree(runtime)


def prepare(manifest_text: str) -> None:
    manifest = Path(manifest_text)
    pin = load_pin(manifest)
    archive = Path(pin["archive"])
    expected_name = f"{pin['root']}.tar.xz"
    require_safe_input(archive, expected_name)
    runtime = Path(tempfile.mkdtemp(prefix="wins-release-node.", dir="/private/tmp"))
    runtime.chmod(0o700)
    try:
        incoming = runtime / "incoming.tar.xz"
        extracted = runtime / "extracted"
        state = runtime / "state"
        state.mkdir(mode=0o700)
        (state / "home").mkdir(mode=0o700)
        (state / "tmp").mkdir(mode=0o700)
        copy_stable(archive, incoming, pin["archive_sha"])
        root = safe_extract(incoming, extracted, pin["root"])
        binary = root / pin["executable"]
        if tree_hash(root) != pin["tree_sha"] or digest_file(binary) != pin["executable_sha"]:
            fail("Node extracted tree or executable digest mismatch")
        check_node_identity(binary, runtime, pin["version"], pin["architecture"])
        if tree_hash(root) != pin["tree_sha"] or digest_file(binary) != pin["executable_sha"]:
            fail("Node runtime changed during identity validation")
        print(f"RUNTIME|{runtime}")
        print(f"RUNTIME_ID|{runtime_identity(runtime)}")
        print(f"ROOT|{root}")
        print(f"TREE_SHA256|{pin['tree_sha']}")
        print(f"BINARY|{binary}")
        print(f"BINARY_SHA256|{pin['executable_sha']}")
    except BaseException:
        try:
            _destroy_runtime(runtime)
        except (OSError, Refused):
            pass
        raise


def cleanup(runtime_text: str, expected_id: str) -> None:
    runtime = Path(runtime_text)
    if runtime_identity(runtime) != expected_id:
        fail("refusing cleanup of a replaced Node runtime")
    _destroy_runtime(runtime)


def run_action(arguments: list[str]) -> int:
    try:
        separator = arguments.index("--")
    except ValueError:
        fail("Node run action requires an argument separator")
    verification = arguments[:separator]
    command = arguments[separator + 1 :]
    runtime, binary = verify_runtime(verification)
    try:
        completed = subprocess.run(
            [str(binary), *command],
            env=_minimal_environment(runtime, binary),
            timeout=300,
            check=False,
        )
    except BaseException:
        verify_runtime(verification)
        raise
    verify_runtime(verification)
    return completed.returncode


def main() -> int:
    try:
        if len(sys.argv) < 2:
            fail("missing Node custody action")
        action = sys.argv[1]
        if action == "prepare" and len(sys.argv) == 3:
            prepare(sys.argv[2])
        elif action == "verify":
            verify_runtime(sys.argv[2:])
        elif action == "run":
            return run_action(sys.argv[2:])
        elif action == "cleanup" and len(sys.argv) == 4:
            cleanup(sys.argv[2], sys.argv[3])
        else:
            fail("unknown or malformed Node custody action")
    except (
        Refused,
        OSError,
        KeyError,
        json.JSONDecodeError,
        lzma.LZMAError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"release-node custody: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
