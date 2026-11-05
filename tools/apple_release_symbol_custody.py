#!/usr/bin/env python3
"""Privately retain Flutter symbols and xcarchive dSYMs for exact Apple artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import fnmatch
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_PRIVATE_ROOT = ROOT / ".artifacts" / "private-release-symbols" / "apple"
CONTRACT = "winsvpn-apple-private-symbol-custody-v1"
CLOSURE_CONTRACT = "winsvpn-apple-private-symbol-custody-closure-v1"
CLOSURE_FILENAME = ".custody-closure.json"
IOS_VERIFIER_PATH = ROOT / "tools" / "verify_ios_release_artifact.py"
READ_CHUNK = 1024 * 1024
STABLE_STAT_FIELDS = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


class CustodyError(RuntimeError):
    pass


def _original_path(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _require_nofollow() -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC") or not hasattr(os, "O_DIRECTORY"):
        raise CustodyError("Apple symbol custody requires O_NOFOLLOW descriptor binding")


def _file_read_flags() -> int:
    _require_nofollow()
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    return flags


def _file_create_flags() -> int:
    _require_nofollow()
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    return flags


def _dir_flags() -> int:
    _require_nofollow()
    return os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _same_stable_file(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, field) == getattr(right, field) for field in STABLE_STAT_FIELDS)


def _reject_component_name(name: str) -> None:
    if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise CustodyError(f"Private symbol path component is unsafe: {name!r}")


def _raise_open_error(exc: OSError, label: str, path: pathlib.Path | str) -> None:
    err = getattr(exc, "errno", None)
    if err in {errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP)}:
        raise CustodyError(f"{label} is unsafe or a symlink: {path}") from exc
    if err == errno.ENOENT:
        raise CustodyError(f"{label} does not exist: {path}") from exc
    raise CustodyError(f"{label} is unsafe or a symlink: {path}") from exc


def _open_named(
    name: str | pathlib.Path,
    flags: int,
    *,
    label: str,
    error_path: pathlib.Path | str,
    dir_fd: int | None = None,
    mode: int | None = None,
) -> int:
    kwargs: dict[str, object] = {}
    if dir_fd is not None:
        kwargs["dir_fd"] = dir_fd
    try:
        if flags & os.O_CREAT:
            return os.open(name, flags, 0o600 if mode is None else mode, **kwargs)
        return os.open(name, flags, **kwargs)
    except OSError as exc:
        _raise_open_error(exc, label, error_path)
        raise AssertionError("unreachable") from exc


def _read_fd(fd: int, size: int, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    offset = 0
    while remaining:
        block = os.pread(fd, min(READ_CHUNK, remaining), offset)
        if not block:
            raise CustodyError(f"{label} changed while it was being read.")
        chunks.append(block)
        offset += len(block)
        remaining -= len(block)
    extra = os.pread(fd, 1, offset)
    if extra:
        raise CustodyError(f"{label} changed while it was being read.")
    return b"".join(chunks)


def _sha256_fd(fd: int, size: int, label: str) -> str:
    digest = hashlib.sha256()
    remaining = size
    offset = 0
    while remaining:
        block = os.pread(fd, min(READ_CHUNK, remaining), offset)
        if not block:
            raise CustodyError(f"{label} changed while it was being hashed.")
        digest.update(block)
        offset += len(block)
        remaining -= len(block)
    extra = os.pread(fd, 1, offset)
    if extra:
        raise CustodyError(f"{label} changed while it was being hashed.")
    return digest.hexdigest()


def _copy_fd_bytes(src_fd: int, dest_fd: int, size: int, label: str) -> None:
    remaining = size
    offset = 0
    while remaining:
        block = os.pread(src_fd, min(READ_CHUNK, remaining), offset)
        if not block:
            raise CustodyError(f"{label} changed while it was being copied.")
        view = memoryview(block)
        while view:
            written = os.write(dest_fd, view)
            if written <= 0:
                raise CustodyError(f"{label} could not be copied.")
            view = view[written:]
        offset += len(block)
        remaining -= len(block)
    extra = os.pread(src_fd, 1, offset)
    if extra:
        raise CustodyError(f"{label} changed while it was being copied.")
    os.fsync(dest_fd)


def _bind_regular_file(
    path: pathlib.Path,
    label: str,
    minimum_size: int = 1,
) -> tuple[pathlib.Path, int, os.stat_result]:
    original = _original_path(path)
    try:
        info = original.lstat()
    except OSError as exc:
        raise CustodyError(f"{label} does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise CustodyError(f"{label} is unsafe or a symlink: {path}")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size < minimum_size:
        raise CustodyError(f"{label} is unsafe or empty: {path}")
    fd = _open_named(original, _file_read_flags(), label=label, error_path=path)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size < minimum_size:
            raise CustodyError(f"{label} is unsafe or empty: {path}")
        if not _same_stable_file(info, opened):
            raise CustodyError(f"{label} was replaced: {path}")
        return original, fd, opened
    except Exception:
        os.close(fd)
        raise


def _bind_directory(path: pathlib.Path, label: str) -> tuple[pathlib.Path, int, os.stat_result]:
    original = _original_path(path)
    try:
        info = original.lstat()
    except OSError as exc:
        raise CustodyError(f"{label} does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise CustodyError(f"{label} is unsafe or a symlink: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise CustodyError(f"{label} is unsafe or missing: {path}")
    fd = _open_named(original, _dir_flags(), label=label, error_path=path)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode):
            raise CustodyError(f"{label} is unsafe or missing: {path}")
        if not _same_inode(info, opened):
            raise CustodyError(f"{label} was replaced: {path}")
        return original, fd, opened
    except Exception:
        os.close(fd)
        raise


def _confirm_held_directory(path: pathlib.Path, dir_fd: int, label: str) -> pathlib.Path:
    original = _original_path(path)
    try:
        named = original.lstat()
        opened = os.fstat(dir_fd)
    except OSError as exc:
        raise CustodyError(f"{label} does not exist: {path}") from exc
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode) or not stat.S_ISDIR(opened.st_mode):
        raise CustodyError(f"{label} is unsafe or a symlink: {path}")
    if not _same_inode(named, opened):
        raise CustodyError(f"{label} was replaced: {path}")
    return original


def _confirm_held_file(
    path: pathlib.Path,
    fd: int,
    expected: os.stat_result,
    label: str,
) -> pathlib.Path:
    original = _original_path(path)
    try:
        named = original.lstat()
        opened = os.fstat(fd)
    except OSError as exc:
        raise CustodyError(f"{label} does not exist: {path}") from exc
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or named.st_nlink != 1
        or not _same_stable_file(expected, opened)
        or not _same_stable_file(expected, named)
    ):
        raise CustodyError(f"{label} was replaced: {path}")
    return original


def _openat_dir(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    label: str,
    rel: str,
) -> int:
    _reject_component_name(name)
    fd = _open_named(name, _dir_flags(), dir_fd=parent_fd, label=label, error_path=rel)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode) or not _same_inode(expected, opened):
            raise CustodyError(f"{label} was replaced: {rel}")
        return fd
    except Exception:
        os.close(fd)
        raise


def _framework_symlink_target(dir_fd: int, name: str, child_rel: str, label: str) -> str:
    """Admit only the two symlinks a macOS versioned framework is built from.

    `X.framework/Versions/Current -> A` and `X.framework/<entry> -> Versions/Current/<entry>`,
    each relative and inside its own innermost .framework. iOS frameworks are flat and carry
    none; anything else is refused as before.
    """
    try:
        target = os.readlink(name, dir_fd=dir_fd)
    except OSError as exc:
        raise CustodyError(f"{label} is unreadable: {child_rel}") from exc
    parts = child_rel.split("/")
    framework = max(
        (index for index, part in enumerate(parts[:-1]) if part.endswith(".framework")),
        default=None,
    )
    inner = parts[framework + 1 :] if framework is not None else []
    current = inner == ["Versions", "Current"] and re.fullmatch(r"[A-Za-z0-9_]+", target)
    top_level = len(inner) == 1 and target == f"Versions/Current/{inner[0]}"
    if not (current or top_level):
        raise CustodyError(f"{label} contains a symlink: {child_rel}")
    return target


def _iter_entries(
    dir_fd: int,
    rel: str,
    label: str,
    *,
    allow_framework_symlinks: bool = False,
) -> list[tuple[str, str, os.stat_result]]:
    try:
        names = sorted(os.listdir(dir_fd))
    except OSError as exc:
        raise CustodyError(f"{label} is unreadable: {rel or '.'}") from exc
    entries: list[tuple[str, str, os.stat_result]] = []
    for name in names:
        _reject_component_name(name)
        child_rel = f"{rel}/{name}" if rel else name
        try:
            info = os.lstat(name, dir_fd=dir_fd)
        except OSError as exc:
            raise CustodyError(f"{label} is unreadable: {child_rel}") from exc
        if stat.S_ISLNK(info.st_mode):
            if not allow_framework_symlinks:
                raise CustodyError(f"{label} contains a symlink: {child_rel}")
            _framework_symlink_target(dir_fd, name, child_rel, label)
        entries.append((name, child_rel, info))
    return entries


def _ensure_child_dir(parent_fd: int, name: str, rel: str) -> int:
    _reject_component_name(name)
    try:
        existing = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except OSError as exc:
            raise CustodyError(f"Custody destination could not be created: {rel}") from exc
        existing = os.lstat(name, dir_fd=parent_fd)
    if stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode):
        raise CustodyError(f"Custody destination is unsafe or a symlink: {rel}")
    return _openat_dir(parent_fd, name, existing, "Custody destination", rel)


def _copy_regular(
    src_dir_fd: int,
    src_name: str,
    expected: os.stat_result,
    dest_dir_fd: int,
    dest_name: str,
    label: str,
    rel: str,
) -> None:
    src_fd = _open_named(
        src_name, _file_read_flags(), dir_fd=src_dir_fd, label=label, error_path=rel
    )
    try:
        opened = os.fstat(src_fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size == 0:
            raise CustodyError(f"{label} is unsafe or empty: {rel}")
        if not _same_stable_file(expected, opened):
            raise CustodyError(f"{label} was replaced: {rel}")
        source_digest = _sha256_fd(src_fd, opened.st_size, label)
        after_hash = os.fstat(src_fd)
        named_after_hash = os.lstat(src_name, dir_fd=src_dir_fd)
        if not _same_stable_file(opened, after_hash) or not _same_stable_file(
            opened, named_after_hash
        ):
            raise CustodyError(f"{label} was replaced: {rel}")
        dest_fd = _open_named(
            dest_name,
            _file_create_flags(),
            dir_fd=dest_dir_fd,
            label=label,
            error_path=rel,
            mode=0o600,
        )
        try:
            _copy_fd_bytes(src_fd, dest_fd, opened.st_size, label)
            after_copy = os.fstat(src_fd)
            named_after_copy = os.lstat(src_name, dir_fd=src_dir_fd)
            if not _same_stable_file(opened, after_copy) or not _same_stable_file(
                opened, named_after_copy
            ):
                raise CustodyError(f"{label} was replaced: {rel}")
            copied = os.fstat(dest_fd)
            if copied.st_nlink != 1 or copied.st_size != opened.st_size:
                raise CustodyError(f"{label} copy size mismatch: {rel}")
            dest_digest = _sha256_fd(dest_fd, copied.st_size, label)
            if dest_digest != source_digest:
                raise CustodyError(f"{label} copy hash mismatch: {rel}")
        finally:
            os.close(dest_fd)
    finally:
        os.close(src_fd)


def _hash_openat(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    label: str,
    rel: str,
) -> str:
    fd = _open_named(name, _file_read_flags(), dir_fd=parent_fd, label=label, error_path=rel)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise CustodyError(f"{label} is unsafe or empty: {rel}")
        if not _same_stable_file(expected, opened):
            raise CustodyError(f"{label} was replaced: {rel}")
        digest = _sha256_fd(fd, opened.st_size, label)
        after = os.fstat(fd)
        named = os.lstat(name, dir_fd=parent_fd)
        if not _same_stable_file(opened, after) or not _same_stable_file(opened, named):
            raise CustodyError(f"{label} was replaced: {rel}")
        return digest
    finally:
        os.close(fd)


def _walk_hash_files(
    dir_fd: int,
    rel: str,
    label: str,
    *,
    allow_framework_symlinks: bool = False,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for name, child_rel, info in _iter_entries(
        dir_fd, rel, label, allow_framework_symlinks=allow_framework_symlinks
    ):
        if stat.S_ISLNK(info.st_mode):
            # Recorded, never followed: the target bytes are inventoried at their real path.
            target = _framework_symlink_target(dir_fd, name, child_rel, label)
            result.append({"path": child_rel, "symlink": target})
        elif stat.S_ISDIR(info.st_mode):
            child = _openat_dir(dir_fd, name, info, label, child_rel)
            try:
                result.extend(
                    _walk_hash_files(
                        child,
                        child_rel,
                        label,
                        allow_framework_symlinks=allow_framework_symlinks,
                    )
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise CustodyError(f"{label} contains a hard-linked file: {child_rel}")
            if info.st_size == 0:
                raise CustodyError(f"Custody file is unsafe or empty: {child_rel}")
            digest = _hash_openat(dir_fd, name, info, label, child_rel)
            result.append({"path": child_rel, "size": info.st_size, "sha256": digest})
        else:
            raise CustodyError(f"Custody file is unsafe or empty: {child_rel}")
    return result


def _audit_tree(dir_fd: int, rel: str, label: str) -> None:
    for name, child_rel, info in _iter_entries(dir_fd, rel, label):
        if stat.S_ISDIR(info.st_mode):
            child = _openat_dir(dir_fd, name, info, label, child_rel)
            try:
                _audit_tree(child, child_rel, label)
            finally:
                os.close(child)
        elif not stat.S_ISREG(info.st_mode):
            raise CustodyError(f"{label} is unsafe or empty: {child_rel}")


def _list_matching(dir_fd: int, pattern: str, minimum_size: int, label: str) -> list[str]:
    matches: list[str] = []

    def walk(current_fd: int, rel: str) -> None:
        for name, child_rel, info in _iter_entries(current_fd, rel, label):
            if stat.S_ISDIR(info.st_mode):
                child = _openat_dir(current_fd, name, info, label, child_rel)
                try:
                    walk(child, child_rel)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise CustodyError(f"{label} contains a hard-linked file: {child_rel}")
                if fnmatch.fnmatch(name, pattern):
                    if info.st_size < minimum_size:
                        raise CustodyError(f"{label} is unsafe or empty: {child_rel}")
                    matches.append(child_rel)
            else:
                raise CustodyError(f"{label} is unsafe or empty: {child_rel}")

    walk(dir_fd, "")
    return matches


def _copy_rel_file(
    src_root_fd: int,
    dest_root_fd: int,
    rel: str,
    minimum_size: int,
    label: str,
) -> None:
    parts = rel.split("/")
    src_owned: list[int] = []
    dest_owned: list[int] = []
    src_current = src_root_fd
    dest_current = dest_root_fd
    try:
        for part in parts[:-1]:
            info = os.lstat(part, dir_fd=src_current)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise CustodyError(f"{label} is unsafe or a symlink: {rel}")
            src_next = _openat_dir(src_current, part, info, label, rel)
            src_owned.append(src_next)
            src_current = src_next
            dest_next = _ensure_child_dir(dest_current, part, rel)
            dest_owned.append(dest_next)
            dest_current = dest_next
        name = parts[-1]
        _reject_component_name(name)
        info = os.lstat(name, dir_fd=src_current)
        if stat.S_ISLNK(info.st_mode):
            raise CustodyError(f"{label} is unsafe or a symlink: {rel}")
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size < minimum_size:
            raise CustodyError(f"{label} is unsafe or empty: {rel}")
        _copy_regular(src_current, name, info, dest_current, name, label, rel)
    finally:
        for fd in reversed(dest_owned):
            os.close(fd)
        for fd in reversed(src_owned):
            os.close(fd)


def _is_dwarf_payload(rel: str) -> bool:
    parts = rel.split("/")
    try:
        index = parts.index("Contents")
    except ValueError:
        return False
    return (
        index + 3 < len(parts)
        and parts[index + 1] == "Resources"
        and parts[index + 2] == "DWARF"
        and index + 3 == len(parts) - 1
    )


def _copy_tree_contents(src_fd: int, dest_fd: int, label: str, rel: str) -> int:
    dwarf_files = 0
    for name, child_rel, info in _iter_entries(src_fd, rel, label):
        if stat.S_ISDIR(info.st_mode):
            child = _openat_dir(src_fd, name, info, label, child_rel)
            try:
                nested = _ensure_child_dir(dest_fd, name, child_rel)
                try:
                    dwarf_files += _copy_tree_contents(child, nested, label, child_rel)
                finally:
                    os.close(nested)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            if info.st_size == 0:
                raise CustodyError(f"{label} is unsafe or empty: {child_rel}")
            _copy_regular(src_fd, name, info, dest_fd, name, label, child_rel)
            if _is_dwarf_payload(child_rel):
                dwarf_files += 1
        else:
            raise CustodyError(f"{label} is unsafe or empty: {child_rel}")
    return dwarf_files


def _write_exclusive(path: pathlib.Path, text: str) -> None:
    original = _original_path(path)
    _reject_component_name(original.name)
    parent, parent_fd, _ = _bind_directory(original.parent, "Private symbol custody directory")
    try:
        fd = _open_named(
            original.name,
            _file_create_flags(),
            dir_fd=parent_fd,
            label="Apple private symbol manifest",
            error_path=original,
            mode=0o600,
        )
        try:
            data = text.encode("utf-8")
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise CustodyError("Apple private symbol manifest could not be written.")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def sha256_file(path: pathlib.Path) -> str:
    original, fd, info = _bind_regular_file(path, "Custody file")
    try:
        return _sha256_fd(fd, info.st_size, "Custody file")
    finally:
        os.close(fd)


def release_identity() -> tuple[str, str]:
    text = (ROOT / "pubspec.yaml").read_text(encoding="utf-8")
    match = re.search(r"(?m)^version:\s*([^+\s]+)\+(\d+)\s*$", text)
    if not match:
        raise CustodyError("pubspec.yaml must contain version: <semver>+<build>.")
    return match.group(1), match.group(2)


def require_safe_file(path: pathlib.Path, label: str, minimum_size: int = 1) -> pathlib.Path:
    original, fd, _info = _bind_regular_file(path, label, minimum_size)
    os.close(fd)
    return original


def require_private_root(path: pathlib.Path, allow_test_root: bool) -> pathlib.Path:
    resolved = path.expanduser().resolve()
    if not allow_test_root:
        expected = DEFAULT_PRIVATE_ROOT.resolve()
        if resolved != expected:
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                pass
            else:
                raise CustodyError(
                    "Apple private symbol custody inside the repository must stay "
                    f"under ignored path {expected}."
                )
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def safe_source_files(root: pathlib.Path, pattern: str, minimum_size: int) -> list[pathlib.Path]:
    bound, fd, _info = _bind_directory(root, "Private symbol source")
    try:
        matches = _list_matching(fd, pattern, minimum_size, "Private symbol input")
        if not matches:
            raise CustodyError(f"No {pattern} files were found under {root}.")
        return [bound / match for match in matches]
    finally:
        os.close(fd)


def reject_symlinks(root: pathlib.Path) -> None:
    _bound, fd, _info = _bind_directory(root, "Native symbol bundle")
    try:
        _audit_tree(fd, "", "Native symbol bundle")
    finally:
        os.close(fd)


def inventory(root: pathlib.Path) -> list[dict[str, object]]:
    bound, fd, _info = _bind_directory(root, "Custody file")
    try:
        result = _walk_hash_files(fd, "", "Custody file")
        result.sort(key=lambda item: str(item["path"]))
        if not result:
            raise CustodyError(f"Private symbol custody contains no files: {root}")
        return result
    finally:
        os.close(fd)


def _inventory_sha256(records: list[dict[str, object]]) -> str:
    encoded = json.dumps(
        records, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _directory_inventory(
    dir_fd: int,
    label: str,
    *,
    allow_framework_symlinks: bool = False,
) -> list[dict[str, object]]:
    records = _walk_hash_files(
        dir_fd, "", label, allow_framework_symlinks=allow_framework_symlinks
    )
    records.sort(key=lambda item: str(item["path"]))
    if not records:
        raise CustodyError(f"{label} contains no files.")
    return records


def _load_ios_verifier():
    verifier_path = _original_path(IOS_VERIFIER_PATH)
    require_safe_file(verifier_path, "Canonical iOS release verifier", 64)
    module_name = "_winsvpn_symbol_custody_ios_verifier"
    spec = importlib.util.spec_from_file_location(module_name, verifier_path)
    if spec is None or spec.loader is None:
        raise CustodyError("Canonical iOS release verifier could not be loaded.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise CustodyError("Canonical iOS release verifier could not be loaded.") from exc
    loaded_path = pathlib.Path(str(getattr(module, "__file__", "")))
    if _original_path(loaded_path) != verifier_path:
        raise CustodyError("Canonical iOS release verifier origin is invalid.")
    return module


def _authoritative_ios_evidence(
    artifact: pathlib.Path,
    archive: pathlib.Path,
) -> dict[str, object]:
    verifier = _load_ios_verifier()
    try:
        with verifier.bind_ipa(artifact) as ipa, verifier.extract_ipa(ipa.snapshot) as extracted:
            apps = sorted(path for path in (extracted / "Payload").glob("*.app") if path.is_dir())
            if len(apps) != 1:
                raise CustodyError(f"IPA must contain exactly one Payload app, found {apps!r}")
            ipa_evidence = verifier.verify_app_bundle(
                apps[0], "symbol-custody exported IPA", verifier.default_command_runner
            )
            archive_app = verifier._archive_app(archive)
            archive_evidence = verifier.verify_app_bundle(
                archive_app,
                "symbol-custody produced xcarchive",
                verifier.default_command_runner,
                distribution=False,
            )
            if ipa_evidence != archive_evidence:
                raise CustodyError(
                    "IPA and xcarchive app identity, UUID, or version evidence differs."
                )
            dsym_uuids = verifier._archive_dsym_uuids(
                archive, verifier.default_command_runner
            )
    except CustodyError:
        raise
    except Exception as exc:
        raise CustodyError(
            f"Authoritative iOS artifact verification failed: {exc}"
        ) from exc
    required = (
        ipa_evidence.app_uuids
        | ipa_evidence.extension_uuids
        | ipa_evidence.watch_uuids
    )
    if not ipa_evidence.app_uuids or not ipa_evidence.extension_uuids or not ipa_evidence.watch_uuids:
        raise CustodyError("iOS host, PacketTunnel, and Watch UUID evidence is required.")
    if not required.issubset(dsym_uuids):
        raise CustodyError("xcarchive dSYMs do not cover host, PacketTunnel, and Watch UUIDs.")
    return {
        "app_version": ipa_evidence.app_version,
        "build_number": ipa_evidence.build_number,
        "host_uuids": sorted(value.lower() for value in ipa_evidence.app_uuids),
        "packet_tunnel_uuids": sorted(
            value.lower() for value in ipa_evidence.extension_uuids
        ),
        "watch_uuids": sorted(value.lower() for value in ipa_evidence.watch_uuids),
        "dsym_uuids": sorted(value.lower() for value in dsym_uuids),
    }


def _copied_dsym_uuids(destination: pathlib.Path) -> list[str]:
    verifier = _load_ios_verifier()
    try:
        values = verifier._archive_dsym_uuids(
            destination, verifier.default_command_runner
        )
    except Exception as exc:
        raise CustodyError(f"Private dSYM UUID verification failed: {exc}") from exc
    return sorted(value.lower() for value in values)


def secure_permissions(root: pathlib.Path) -> None:
    _bound, fd, _info = _bind_directory(root, "Private symbol custody directory")
    try:

        def walk(current_fd: int) -> None:
            for name, child_rel, info in _iter_entries(
                current_fd, "", "Private symbol custody directory"
            ):
                if stat.S_ISDIR(info.st_mode):
                    child = _openat_dir(
                        current_fd, name, info, "Private symbol custody directory", child_rel
                    )
                    try:
                        walk(child)
                        os.fchmod(child, 0o700)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    file_fd = _open_named(
                        name,
                        _file_read_flags(),
                        dir_fd=current_fd,
                        label="Custody file",
                        error_path=child_rel,
                    )
                    try:
                        os.fchmod(file_fd, 0o600)
                    finally:
                        os.close(file_fd)
                else:
                    raise CustodyError(f"Custody file is unsafe or empty: {child_rel}")

        walk(fd)
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)


def copy_flutter_symbols(
    source: pathlib.Path,
    destination: pathlib.Path,
    *,
    source_fd: int | None = None,
) -> None:
    close_source = False
    if source_fd is None:
        source, source_fd, _info = _bind_directory(source, "Private symbol source")
        close_source = True
    else:
        source = _confirm_held_directory(source, source_fd, "Private symbol source")
    try:
        matches = _list_matching(source_fd, "*.symbols", 64, "Private symbol input")
        if not matches:
            raise CustodyError(f"No *.symbols files were found under {source}.")
        dest = _original_path(destination)
        dest.mkdir(parents=True, exist_ok=True)
        _, dest_fd, _dest_info = _bind_directory(dest, "Private Flutter symbol destination")
        try:
            for rel in matches:
                _copy_rel_file(source_fd, dest_fd, rel, 64, "Private symbol input")
        finally:
            os.close(dest_fd)
    finally:
        if close_source:
            os.close(source_fd)


def copy_archive_dsyms(
    archive: pathlib.Path,
    destination: pathlib.Path,
    *,
    archive_fd: int | None = None,
) -> None:
    close_archive = False
    if archive_fd is None:
        bound, archive_fd, _info = _bind_directory(archive, "Apple symbol custody xcarchive")
        close_archive = True
    else:
        bound = _confirm_held_directory(archive, archive_fd, "Apple symbol custody xcarchive")
    try:
        if bound.suffix != ".xcarchive":
            raise CustodyError(f"Apple symbol custody requires a safe .xcarchive: {archive}")
        try:
            dsym_info = os.lstat("dSYMs", dir_fd=archive_fd)
        except OSError as exc:
            raise CustodyError(f"xcarchive has no safe dSYMs directory: {archive}") from exc
        if stat.S_ISLNK(dsym_info.st_mode) or not stat.S_ISDIR(dsym_info.st_mode):
            raise CustodyError(f"xcarchive has no safe dSYMs directory: {archive}")
        dsym_fd = _openat_dir(archive_fd, "dSYMs", dsym_info, "Native symbol bundle", "dSYMs")
        try:
            dest = _original_path(destination)
            dest.mkdir(parents=True, exist_ok=True)
            _, dest_fd, _dest_info = _bind_directory(dest, "Private dSYM custody destination")
            try:
                bundle_count = 0
                dwarf_files = 0
                for name, child_rel, info in _iter_entries(dsym_fd, "dSYMs", "Native symbol bundle"):
                    if stat.S_ISDIR(info.st_mode):
                        child = _openat_dir(
                            dsym_fd, name, info, "Native symbol bundle", child_rel
                        )
                        try:
                            if fnmatch.fnmatch(name, "*.dSYM"):
                                bundle_count += 1
                                nested = _ensure_child_dir(dest_fd, name, name)
                                try:
                                    dwarf_files += _copy_tree_contents(
                                        child, nested, "Native symbol bundle", name
                                    )
                                finally:
                                    os.close(nested)
                            else:
                                _audit_tree(child, child_rel, "Native symbol bundle")
                        finally:
                            os.close(child)
                    elif not stat.S_ISREG(info.st_mode):
                        raise CustodyError(
                            f"Native symbol bundle is unsafe or empty: {child_rel}"
                        )
                if bundle_count == 0:
                    raise CustodyError(f"xcarchive contains no dSYM bundles: {archive}")
                if dwarf_files == 0:
                    raise CustodyError(
                        f"xcarchive dSYMs contain no non-empty DWARF payload: {archive}"
                    )
                try:
                    maps_info = os.lstat("BCSymbolMaps", dir_fd=archive_fd)
                except FileNotFoundError:
                    maps_info = None
                if maps_info is not None:
                    if stat.S_ISLNK(maps_info.st_mode) or not stat.S_ISDIR(maps_info.st_mode):
                        raise CustodyError(
                            f"xcarchive BCSymbolMaps is unsafe or a symlink: {archive}"
                        )
                    maps_fd = _openat_dir(
                        archive_fd,
                        "BCSymbolMaps",
                        maps_info,
                        "Native BCSymbolMap bundle",
                        "BCSymbolMaps",
                    )
                    try:
                        map_entries = _iter_entries(
                            maps_fd, "", "Native BCSymbolMap bundle"
                        )
                        if not map_entries:
                            raise CustodyError("xcarchive BCSymbolMaps directory is empty.")
                        maps_dest = _ensure_child_dir(
                            dest_fd, "BCSymbolMaps", "BCSymbolMaps"
                        )
                        try:
                            for map_name, map_rel, map_info in map_entries:
                                if (
                                    not stat.S_ISREG(map_info.st_mode)
                                    or map_info.st_nlink != 1
                                    or map_info.st_size == 0
                                    or not map_name.endswith(".bcsymbolmap")
                                ):
                                    raise CustodyError(
                                        f"Native BCSymbolMap bundle is unsafe: {map_rel}"
                                    )
                                _copy_regular(
                                    maps_fd,
                                    map_name,
                                    map_info,
                                    maps_dest,
                                    map_name,
                                    "Native BCSymbolMap bundle",
                                    map_rel,
                                )
                        finally:
                            os.close(maps_dest)
                    finally:
                        os.close(maps_fd)
            finally:
                os.close(dest_fd)
        finally:
            os.close(dsym_fd)
    finally:
        if close_archive:
            os.close(archive_fd)


def expected_destination(
    private_root: pathlib.Path,
    platform: str,
    artifact_sha256: str,
) -> pathlib.Path:
    version, build = release_identity()
    return private_root / "artifact-custody" / platform / f"{version}+{build}" / artifact_sha256


def _bcsymbolmap_uuids(records: list[dict[str, object]]) -> list[str]:
    values: list[str] = []
    pattern = re.compile(
        r"^BCSymbolMaps/([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
        r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\.bcsymbolmap$"
    )
    for record in records:
        path = str(record.get("path", ""))
        if not path.startswith("BCSymbolMaps/"):
            continue
        match = pattern.fullmatch(path)
        if not match:
            raise CustodyError(f"BCSymbolMap filename is not a UUID: {path}")
        values.append(match.group(1).lower())
    return sorted(values)


def _closure_payload(
    artifact: pathlib.Path,
    artifact_sha256: str,
    archive: pathlib.Path,
    archive_inventory: list[dict[str, object]],
    evidence: dict[str, object],
    copied_dsym_inventory: list[dict[str, object]],
) -> dict[str, object]:
    version, build = release_identity()
    if evidence.get("app_version") != version or str(evidence.get("build_number")) != build:
        raise CustodyError("IPA/xcarchive release identity does not match pubspec version/build.")
    map_uuids = _bcsymbolmap_uuids(copied_dsym_inventory)
    dsym_uuids = set(str(value).lower() for value in evidence["dsym_uuids"])
    required_uuids = (
        set(str(value).lower() for value in evidence["host_uuids"])
        | set(str(value).lower() for value in evidence["packet_tunnel_uuids"])
        | set(str(value).lower() for value in evidence["watch_uuids"])
    )
    if (
        not evidence["host_uuids"]
        or not evidence["packet_tunnel_uuids"]
        or not evidence["watch_uuids"]
        or not required_uuids.issubset(dsym_uuids)
    ):
        raise CustodyError("dSYMs do not cover host, PacketTunnel, and Watch UUIDs.")
    if not set(map_uuids).issubset(dsym_uuids):
        raise CustodyError("BCSymbolMap UUIDs are not covered by xcarchive dSYMs.")
    return {
        "schema_version": 1,
        "contract": CLOSURE_CONTRACT,
        "artifact": {
            "filename": artifact.name,
            "sha256": artifact_sha256,
        },
        "xcarchive": {
            "filename": archive.name,
            "inventory_sha256": _inventory_sha256(archive_inventory),
        },
        "app_version": version,
        "build_number": build,
        "host_uuids": evidence["host_uuids"],
        "packet_tunnel_uuids": evidence["packet_tunnel_uuids"],
        "watch_uuids": evidence["watch_uuids"],
        "dsym_uuids": evidence["dsym_uuids"],
        "bcsymbolmap_uuids": map_uuids,
        "producer_source_sha256": sha256_file(pathlib.Path(__file__)),
        "ios_verifier_source_sha256": sha256_file(IOS_VERIFIER_PATH),
    }


def _load_closure(destination: pathlib.Path) -> dict[str, object]:
    closure = destination / "dSYMs" / CLOSURE_FILENAME
    bound, fd, info = _bind_regular_file(closure, "Apple symbol-custody closure", 64)
    try:
        try:
            payload = json.loads(
                _read_fd(fd, info.st_size, "Apple symbol-custody closure").decode("ascii")
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CustodyError(f"Apple symbol-custody closure is invalid: {bound}") from exc
    finally:
        os.close(fd)
    required = {
        "schema_version",
        "contract",
        "artifact",
        "xcarchive",
        "app_version",
        "build_number",
        "host_uuids",
        "packet_tunnel_uuids",
        "watch_uuids",
        "dsym_uuids",
        "bcsymbolmap_uuids",
        "producer_source_sha256",
        "ios_verifier_source_sha256",
    }
    if set(payload) != required or payload.get("schema_version") != 1:
        raise CustodyError("Apple symbol-custody closure schema is invalid.")
    if payload.get("contract") != CLOSURE_CONTRACT:
        raise CustodyError("Apple symbol-custody closure contract is invalid.")
    return payload


def manifest_payload(
    platform: str,
    artifact: pathlib.Path,
    destination: pathlib.Path,
) -> dict[str, object]:
    version, build = release_identity()
    artifact_sha256 = sha256_file(artifact)
    artifact_info = artifact.lstat()
    return {
        "schema_version": 1,
        "contract": CONTRACT,
        "platform": platform,
        "app_version": version,
        "build_number": build,
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "private_symbols_not_packaged": True,
        "artifact": {
            "filename": artifact.name,
            "size": artifact_info.st_size,
            "sha256": artifact_sha256,
        },
        "flutter_symbols": inventory(destination / "flutter"),
        "xcarchive_dsyms": inventory(destination / "dSYMs"),
    }


def validate_manifest(
    destination: pathlib.Path,
    artifact: pathlib.Path,
    platform: str,
    archive: pathlib.Path | None = None,
) -> None:
    manifest = destination / "manifest.json"
    bound, fd, info = _bind_regular_file(manifest, "Apple private symbol manifest")
    try:
        try:
            payload = json.loads(_read_fd(fd, info.st_size, "Apple private symbol manifest").decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CustodyError(f"Apple private symbol manifest is invalid: {bound}") from exc
    finally:
        os.close(fd)
    required = {
        "schema_version",
        "contract",
        "platform",
        "app_version",
        "build_number",
        "created_at_utc",
        "private_symbols_not_packaged",
        "artifact",
        "flutter_symbols",
        "xcarchive_dsyms",
    }
    if set(payload) != required or payload.get("schema_version") != 1:
        raise CustodyError("Apple private symbol manifest schema is invalid.")
    if payload.get("contract") != CONTRACT or payload.get("platform") != platform:
        raise CustodyError("Apple private symbol manifest identity is invalid.")
    version, build = release_identity()
    if payload.get("app_version") != version or str(payload.get("build_number")) != build:
        raise CustodyError("Apple private symbols belong to another app version/build.")
    if payload.get("private_symbols_not_packaged") is not True:
        raise CustodyError("Apple private symbol separation is not asserted.")
    expected_artifact = {
        "filename": artifact.name,
        "size": artifact.lstat().st_size,
        "sha256": sha256_file(artifact),
    }
    if payload.get("artifact") != expected_artifact:
        raise CustodyError("Apple private symbols are not bound to the exact artifact.")
    if destination.name != expected_artifact["sha256"]:
        raise CustodyError("Apple private symbol directory is not keyed by artifact SHA-256.")
    if payload.get("flutter_symbols") != inventory(destination / "flutter"):
        raise CustodyError("Private Flutter symbol hashes do not match the manifest.")
    dsym_inventory = inventory(destination / "dSYMs")
    if payload.get("xcarchive_dsyms") != dsym_inventory:
        raise CustodyError("Private xcarchive dSYM hashes do not match the manifest.")
    if platform == "ios":
        closure = _load_closure(destination)
        expected_closure_artifact = {
            "filename": artifact.name,
            "sha256": expected_artifact["sha256"],
        }
        if closure.get("artifact") != expected_closure_artifact:
            raise CustodyError("Apple symbol-custody closure belongs to another IPA.")
        if closure.get("app_version") != version or str(closure.get("build_number")) != build:
            raise CustodyError("Apple symbol-custody closure version/build is stale.")
        if closure.get("producer_source_sha256") != sha256_file(pathlib.Path(__file__)):
            raise CustodyError("Apple symbol-custody producer source closure is stale.")
        if closure.get("ios_verifier_source_sha256") != sha256_file(IOS_VERIFIER_PATH):
            raise CustodyError("Apple symbol-custody verifier source closure is stale.")
        uuid_keys = (
            "host_uuids",
            "packet_tunnel_uuids",
            "watch_uuids",
            "dsym_uuids",
            "bcsymbolmap_uuids",
        )
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        for key in uuid_keys:
            values = closure.get(key)
            if (
                type(values) is not list
                or values != sorted(set(values))
                or any(
                    type(value) is not str or not uuid_pattern.fullmatch(value)
                    for value in values
                )
            ):
                raise CustodyError(f"Apple symbol-custody {key} evidence is invalid.")
        if (
            not closure["host_uuids"]
            or not closure["packet_tunnel_uuids"]
            or not closure["watch_uuids"]
        ):
            raise CustodyError("Host, PacketTunnel, and Watch UUID evidence is required.")
        required_uuids = (
            set(closure["host_uuids"])
            | set(closure["packet_tunnel_uuids"])
            | set(closure["watch_uuids"])
        )
        if not required_uuids.issubset(set(closure["dsym_uuids"])):
            raise CustodyError("Private dSYMs do not cover host, PacketTunnel, and Watch UUIDs.")
        if closure["bcsymbolmap_uuids"] != _bcsymbolmap_uuids(dsym_inventory):
            raise CustodyError("Private BCSymbolMap inventory differs from the closure.")
        if not set(closure["bcsymbolmap_uuids"]).issubset(set(closure["dsym_uuids"])):
            raise CustodyError("Private BCSymbolMaps do not match dSYM UUIDs.")
        if _copied_dsym_uuids(destination) != closure["dsym_uuids"]:
            raise CustodyError("Private dSYM UUIDs differ from the closure.")
        xcarchive = closure.get("xcarchive")
        if (
            type(xcarchive) is not dict
            or set(xcarchive) != {"filename", "inventory_sha256"}
            or not isinstance(xcarchive.get("filename"), str)
            or not re.fullmatch(
                r"[0-9a-f]{64}", str(xcarchive.get("inventory_sha256", ""))
            )
        ):
            raise CustodyError("Apple symbol-custody xcarchive closure is invalid.")
        if archive is not None:
            archive_bound, archive_fd, _archive_info = _bind_directory(
                archive, "Apple symbol custody xcarchive"
            )
            try:
                if archive_bound.name != xcarchive["filename"]:
                    raise CustodyError("Apple symbol custody belongs to another xcarchive.")
                archive_records = _directory_inventory(
                    archive_fd,
                    "Apple symbol custody xcarchive",
                    allow_framework_symlinks=True,
                )
                if _inventory_sha256(archive_records) != xcarchive["inventory_sha256"]:
                    raise CustodyError("Apple symbol custody xcarchive inventory is stale.")
            finally:
                os.close(archive_fd)
    serialized = json.dumps(payload, sort_keys=True)
    if re.search(r"(?i)(?:[a-z]:[\\/](?:users|documents and settings)[\\/]|/(?:users|home)/)", serialized):
        raise CustodyError("Apple private symbol manifest contains a user-home path.")


def collect(
    platform: str,
    artifact_path: pathlib.Path,
    flutter_symbols: pathlib.Path,
    archive_path: pathlib.Path,
    private_root_path: pathlib.Path,
    allow_test_root: bool = False,
) -> pathlib.Path:
    artifact, artifact_fd, artifact_info = _bind_regular_file(
        artifact_path, "Apple release artifact"
    )
    try:
        expected_suffix = ".ipa" if platform == "ios" else ".pkg"
        if artifact.suffix.lower() != expected_suffix:
            raise CustodyError(
                f"{platform} custody requires an exact {expected_suffix} artifact."
            )
        artifact_sha256 = _sha256_fd(
            artifact_fd, artifact_info.st_size, "Apple release artifact"
        )
        _confirm_held_file(
            artifact, artifact_fd, artifact_info, "Apple release artifact"
        )
        archive_bound, archive_fd, _archive_info = _bind_directory(
            archive_path, "Apple symbol custody xcarchive"
        )
        try:
            if archive_bound.suffix != ".xcarchive":
                raise CustodyError(
                    f"Apple symbol custody requires a safe .xcarchive: {archive_path}"
                )
            archive_inventory = _directory_inventory(
                archive_fd,
                "Apple symbol custody xcarchive",
                allow_framework_symlinks=True,
            )
            evidence = (
                _authoritative_ios_evidence(artifact, archive_bound)
                if platform == "ios"
                else None
            )
            _confirm_held_directory(
                archive_bound, archive_fd, "Apple symbol custody xcarchive"
            )
            symbols_bound, symbols_fd, _symbols_info = _bind_directory(
                flutter_symbols, "Private symbol source"
            )
            try:
                matches = _list_matching(
                    symbols_fd, "*.symbols", 64, "Private symbol input"
                )
                if not matches:
                    raise CustodyError(
                        f"No *.symbols files were found under {flutter_symbols}."
                    )
                private_root = require_private_root(private_root_path, allow_test_root)
                destination = expected_destination(
                    private_root, platform, artifact_sha256
                )
                try:
                    existing = destination.lstat()
                except FileNotFoundError:
                    existing = None
                if existing is not None:
                    if stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode):
                        raise CustodyError(
                            "Apple private symbol directory is unsafe or a symlink."
                        )
                    validate_manifest(destination, artifact, platform, archive_bound)
                    _confirm_held_file(
                        artifact,
                        artifact_fd,
                        artifact_info,
                        "Apple release artifact",
                    )
                    return destination

                destination.parent.mkdir(parents=True, exist_ok=True)
                temporary = pathlib.Path(
                    tempfile.mkdtemp(
                        prefix=f".{artifact_sha256}.", dir=destination.parent
                    )
                )
                try:
                    copy_flutter_symbols(
                        symbols_bound, temporary / "flutter", source_fd=symbols_fd
                    )
                    copy_archive_dsyms(
                        archive_bound, temporary / "dSYMs", archive_fd=archive_fd
                    )
                    if platform == "ios":
                        assert evidence is not None
                        copied_inventory = inventory(temporary / "dSYMs")
                        closure = _closure_payload(
                            artifact,
                            artifact_sha256,
                            archive_bound,
                            archive_inventory,
                            evidence,
                            copied_inventory,
                        )
                        _write_exclusive(
                            temporary / "dSYMs" / CLOSURE_FILENAME,
                            json.dumps(closure, indent=2, sort_keys=True) + "\n",
                        )
                    current_archive_inventory = _directory_inventory(
                        archive_fd,
                        "Apple symbol custody xcarchive",
                        allow_framework_symlinks=True,
                    )
                    if current_archive_inventory != archive_inventory:
                        raise CustodyError(
                            "Apple symbol custody xcarchive changed during collection."
                        )
                    _confirm_held_directory(
                        archive_bound,
                        archive_fd,
                        "Apple symbol custody xcarchive",
                    )
                    _confirm_held_file(
                        artifact,
                        artifact_fd,
                        artifact_info,
                        "Apple release artifact",
                    )
                    payload = manifest_payload(platform, artifact, temporary)
                    _write_exclusive(
                        temporary / "manifest.json",
                        json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    )
                    secure_permissions(temporary)
                    temporary.replace(destination)
                except Exception:
                    shutil.rmtree(temporary, ignore_errors=True)
                    raise
                validate_manifest(destination, artifact, platform, archive_bound)
                _confirm_held_file(
                    artifact,
                    artifact_fd,
                    artifact_info,
                    "Apple release artifact",
                )
                return destination
            finally:
                os.close(symbols_fd)
        finally:
            os.close(archive_fd)
    finally:
        os.close(artifact_fd)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as temp_name:
        root = pathlib.Path(temp_name)
        artifact = root / "WinsVPN.pkg"
        artifact.write_bytes(b"exact-apple-artifact")
        flutter = root / "flutter"
        flutter.mkdir()
        (flutter / "app.ios-arm64.symbols").write_bytes(b"s" * 128)
        archive = root / "Runner.xcarchive"
        dwarf = archive / "dSYMs" / "Runner.app.dSYM" / "Contents" / "Resources" / "DWARF"
        dwarf.mkdir(parents=True)
        (dwarf / "Runner").write_bytes(b"d" * 128)
        private_root = root / "private-release-symbols" / "apple"
        destination = collect(
            "macos", artifact, flutter, archive, private_root, allow_test_root=True
        )
        validate_manifest(destination, artifact, "macos", archive)
        (destination / "flutter" / "app.ios-arm64.symbols").write_bytes(b"changed")
        try:
            validate_manifest(destination, artifact, "ios")
        except CustodyError:
            pass
        else:
            raise CustodyError("Self-test accepted modified private Flutter symbols.")

        def expect_symlink_refusal(
            artifact_path: pathlib.Path,
            flutter_path: pathlib.Path,
            archive_path: pathlib.Path,
            private_path: pathlib.Path,
        ) -> None:
            try:
                collect(
                    "macos",
                    artifact_path,
                    flutter_path,
                    archive_path,
                    private_path,
                    allow_test_root=True,
                )
            except CustodyError:
                return
            raise CustodyError("Self-test accepted a substituted symlink input.")

        alias_archive = root / "alias.xcarchive"
        alias_archive.symlink_to(archive, target_is_directory=True)
        expect_symlink_refusal(artifact, flutter, alias_archive, root / "private-archive-alias")

        alias_flutter = root / "flutter-alias"
        alias_flutter.symlink_to(flutter, target_is_directory=True)
        expect_symlink_refusal(artifact, alias_flutter, archive, root / "private-flutter-alias")

        alias_artifact = root / "alias.pkg"
        alias_artifact.symlink_to(artifact)
        expect_symlink_refusal(alias_artifact, flutter, archive, root / "private-artifact-alias")

        outside = root / "outside-symbols"
        outside.mkdir()
        (outside / "pwned.symbols").write_bytes(b"p" * 128)
        nested_flutter = flutter / "nested"
        nested_flutter.symlink_to(outside, target_is_directory=True)
        expect_symlink_refusal(artifact, flutter, archive, root / "private-flutter-nested")
        nested_flutter.unlink()

        nested_bundle = archive / "dSYMs" / "Linked.app.dSYM"
        nested_bundle.symlink_to(archive / "dSYMs" / "Runner.app.dSYM", target_is_directory=True)
        expect_symlink_refusal(artifact, flutter, archive, root / "private-dsym-nested")
        nested_bundle.unlink()
    print("APPLE PRIVATE SYMBOL CUSTODY SELF-TEST: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("collect", "verify", "self-test"))
    parser.add_argument("--platform", choices=("ios", "macos"))
    parser.add_argument("--artifact")
    parser.add_argument("--flutter-symbols")
    parser.add_argument("--archive")
    parser.add_argument("--private-root", default=str(DEFAULT_PRIVATE_ROOT))
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return 0
    if not args.platform or not args.artifact:
        parser.error("collect/verify require --platform and --artifact")
    artifact = require_safe_file(pathlib.Path(args.artifact), "Apple release artifact")
    private_root = require_private_root(pathlib.Path(args.private_root), False)
    destination = expected_destination(private_root, args.platform, sha256_file(artifact))
    if args.command == "collect":
        if not args.flutter_symbols or not args.archive:
            parser.error("collect requires --flutter-symbols and --archive")
        destination = collect(
            args.platform,
            artifact,
            pathlib.Path(args.flutter_symbols),
            pathlib.Path(args.archive),
            private_root,
        )
    # The closure binds the xcarchive inventory: a named archive is checked, never ignored.
    validate_manifest(
        destination,
        artifact,
        args.platform,
        pathlib.Path(args.archive) if args.archive else None,
    )
    print(f"APPLE PRIVATE SYMBOL CUSTODY: PASS platform={args.platform} key={destination.name}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CustodyError as exc:
        print(f"APPLE PRIVATE SYMBOL CUSTODY: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
