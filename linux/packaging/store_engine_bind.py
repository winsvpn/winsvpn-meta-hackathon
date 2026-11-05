#!/usr/bin/env python3
"""Bind Linux Snap/Flatpak engine sources without host-cache or version-only Go.

Production ``--stage-engines`` calls ``prepare`` then compiles. The production
CLI derives contract pins and does not accept fixture hash overrides.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from types import ModuleType


ELF_MAGIC = b"\x7fELF"
ARCHIVE_BYTES_MAX = 256 * 1024 * 1024
HEX64 = frozenset("0123456789abcdef")
SAFE_ENV_VALUE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./:+-=@"
)
WINN_DATAPATH_BIND = "winsvpn-winn-datapath-sha256-bind"
HOST_GOMODCACHE_REFUSAL = "refusing dirty host Go module cache"
HOST_GOCACHE_REFUSAL = "refusing host Go build cache"
GO_WRAPPER_REFUSAL = "Go executable/tree must be bound to the reviewed archive"
GO_ARCHIVE_MISSING = "declared Go SDK archive is missing"
MODULE_CLOSURE_MISSING = "authenticated Go module closure is missing"
MODULE_TREE_MISSING = "authenticated Go module-closure tree digest is required"
WINN_GOSUM_MISSING = "Winn v3 go.sum is required"
XRAY_TREE_MISSING = "authenticated Xray source tree digest is required"
XRAY_LICENSE_MISSING = "Xray LICENSE is required"
XRAY_IDENTITY_MISSING = "Xray source must carry commit/tag identity without git"
AWG_TOOLCHAIN_REFUSAL = (
    "arm64 AWG requires clang 14.0.6/binutils 2.40-2 or a prebuilt "
    "authenticated payload"
)
ARCHIVE_MEMBER_UNSAFE = "archive member is unsafe"
SYMLINK_REFUSAL = "must be a regular file, not a symbolic link"


def _load_contract() -> ModuleType:
    origin = pathlib.Path(__file__).resolve().with_name("store_manifest_contract.py")
    spec = importlib.util.spec_from_file_location(
        "_winsvpn_store_engine_bind_contract", origin
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load store manifest contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CONTRACT = _load_contract()


class StoreEngineBindError(RuntimeError):
    """Raised when store engine source binding is unsafe."""


def _require_hex64(value: str, label: str) -> str:
    if type(value) is not str or len(value) != 64 or set(value) - HEX64:
        raise StoreEngineBindError(f"{label} must be a 64-hex digest")
    return value


def _contract_pin(getter: Callable[[], str], label: str) -> str:
    try:
        return _require_hex64(getter(), label)
    except CONTRACT.ManifestContractError as suc:
        raise StoreEngineBindError(str(suc)) from suc


def _lstat_regular_file(path: pathlib.Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as suc:
        raise StoreEngineBindError(f"{label} is unreadable") from suc
    if stat.S_ISLNK(info.st_mode):
        raise StoreEngineBindError(f"{label} {SYMLINK_REFUSAL}")
    if not stat.S_ISREG(info.st_mode):
        raise StoreEngineBindError(f"{label} must be a regular file")
    return info


def _lstat_regular_dir(path: pathlib.Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as suc:
        raise StoreEngineBindError(f"{label} is unreadable") from suc
    if stat.S_ISLNK(info.st_mode):
        raise StoreEngineBindError(f"{label} {SYMLINK_REFUSAL}")
    if not stat.S_ISDIR(info.st_mode):
        raise StoreEngineBindError(f"{label} must be a regular directory")
    return info


def sha256_bind_file(path: pathlib.Path, label: str) -> str:
    before = _lstat_regular_file(path, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as suc:
        raise StoreEngineBindError(f"{label} is unreadable") from suc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise StoreEngineBindError(f"{label} changed while opened")
        hasher = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                raise StoreEngineBindError(f"{label} ended before its declared size")
            hasher.update(block)
            remaining -= len(block)
        finished = os.fstat(fd)
        if finished.st_mtime_ns != opened.st_mtime_ns:
            raise StoreEngineBindError(f"{label} changed while hashed")
        return hasher.hexdigest()
    finally:
        os.close(fd)


def hash_regular_tree(root: pathlib.Path, label: str) -> str:
    _lstat_regular_dir(root, label)
    members: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = pathlib.Path(dirpath)
        _lstat_regular_dir(current, label)
        dirnames.sort()
        filenames.sort()
        kept: list[str] = []
        for name in dirnames:
            if name in {".", ".."} or "/" in name or "\\" in name:
                raise StoreEngineBindError(f"{label} member path is unsafe")
            child = current / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise StoreEngineBindError(f"{label} {SYMLINK_REFUSAL}: {child}")
            if not stat.S_ISDIR(info.st_mode):
                raise StoreEngineBindError(f"{label} nested member is not a directory")
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            if name in {".", ".."} or "/" in name or "\\" in name:
                raise StoreEngineBindError(f"{label} member path is unsafe")
            child = current / name
            digest = sha256_bind_file(child, f"{label} {child.name}")
            relative = child.relative_to(root).as_posix()
            members.append(f"file {child.lstat().st_size} {digest} {relative}\n")
    members.sort()
    return hashlib.sha256("".join(members).encode("utf-8")).hexdigest()


def _safe_export_value(value: str, label: str) -> str:
    if type(value) is not str or set(value) - SAFE_ENV_VALUE:
        raise StoreEngineBindError(f"{label} is not a safe export value")
    return value


def go_archive_name(arch: str) -> str:
    if arch == "x64":
        return f"go{CONTRACT.REVIEWED_GO_VERSION}.linux-amd64.tar.gz"
    if arch == "arm64":
        return f"go{CONTRACT.REVIEWED_GO_VERSION}.linux-arm64.tar.gz"
    raise StoreEngineBindError(f"unsupported engine architecture: {arch}")


def go_archive_sha256(arch: str) -> str:
    try:
        return CONTRACT.REVIEWED_GO_ARCHIVE_SHA256[arch]
    except KeyError as suc:
        raise StoreEngineBindError(f"unsupported engine architecture: {arch}") from suc


def _read_exact_fd_bytes(fd: int, size: int, label: str) -> bytes:
    if type(size) is not int or size < 0 or size > ARCHIVE_BYTES_MAX:
        raise StoreEngineBindError(f"{label} exceeds the authenticated size bound")
    buf = bytearray()
    remaining = size
    while remaining:
        block = os.read(fd, min(1024 * 1024, remaining))
        if not block:
            raise StoreEngineBindError(f"{label} ended before its declared size")
        buf.extend(block)
        remaining -= len(block)
    leftover = os.read(fd, 1)
    if leftover:
        raise StoreEngineBindError(f"{label} grew while read")
    return bytes(buf)


def _reject_tar_member(member: tarfile.TarInfo, label: str) -> None:
    if "\\" in member.name:
        raise StoreEngineBindError(
            f"{label} member path is unsafe: {member.name}"
        )
    name = member.name
    parts = [part for part in name.split("/") if part]
    if (
        name.startswith("/")
        or any(part in {".", ".."} for part in parts)
        or not parts
        or parts[0] != "go"
        or len(name.encode("utf-8")) > CONTRACT.MAX_PATH_BYTES
        or len(parts) > CONTRACT.MAX_PATH_DEPTH
    ):
        raise StoreEngineBindError(f"{label} member path is unsafe: {member.name}")
    if (
        member.issym()
        or member.islnk()
        or member.isdev()
        or member.isfifo()
        or member.ischr()
        or member.isblk()
    ):
        raise StoreEngineBindError(
            f"{label} {ARCHIVE_MEMBER_UNSAFE}: {member.name}"
        )
    if member.linkname:
        raise StoreEngineBindError(
            f"{label} link target is not allowed: {member.name} -> {member.linkname}"
        )
    if not (member.isfile() or member.isdir()):
        raise StoreEngineBindError(
            f"{label} {ARCHIVE_MEMBER_UNSAFE}: {member.name}"
        )
    if member.sparse is not None:
        raise StoreEngineBindError(
            f"{label} sparse members are not allowed: {member.name}"
        )
    if member.size < 0 or member.size > CONTRACT.MAX_MEMBER_BYTES:
        raise StoreEngineBindError(
            f"{label} member exceeds the per-member size limit: {member.name}"
        )


def _extract_validated_members(
    tar: tarfile.TarFile,
    members: list[tarfile.TarInfo],
    dest: pathlib.Path,
    label: str,
) -> None:
    """Extract only validated regular files/directories into a new private root."""
    if dest.exists() or dest.is_symlink():
        raise StoreEngineBindError(f"{label} extract destination already exists")
    dest.mkdir(mode=0o700)
    try:
        for member in members:
            parts = tuple(part for part in member.name.split("/") if part)
            target = dest.joinpath(*parts)
            parent = dest
            for part in parts[:-1]:
                parent = parent / part
                try:
                    parent.mkdir(mode=0o755)
                except FileExistsError:
                    info = parent.lstat()
                    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                        raise StoreEngineBindError(
                            f"{label} extraction parent is unsafe: {member.name}"
                        )
            if member.isdir():
                try:
                    target.mkdir(mode=0o755)
                except FileExistsError:
                    info = target.lstat()
                    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                        raise StoreEngineBindError(
                            f"{label} extraction target is unsafe: {member.name}"
                        )
                continue

            source = tar.extractfile(member)
            if source is None:
                raise StoreEngineBindError(
                    f"{label} member is unreadable: {member.name}"
                )
            mode = 0o755 if member.mode & 0o111 else 0o644
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | os.O_NOFOLLOW
            )
            try:
                descriptor = os.open(target, flags, mode)
            except OSError as suc:
                raise StoreEngineBindError(
                    f"{label} extraction target is unsafe: {member.name}"
                ) from suc
            measured = 0
            try:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    measured += len(block)
                    if measured > member.size:
                        raise StoreEngineBindError(
                            f"{label} member size is inconsistent: {member.name}"
                        )
                    view = memoryview(block)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise StoreEngineBindError(
                                f"{label} member could not be written: {member.name}"
                            )
                        view = view[written:]
                if measured != member.size:
                    raise StoreEngineBindError(
                        f"{label} member size is inconsistent: {member.name}"
                    )
                os.fchmod(descriptor, mode)
            finally:
                os.close(descriptor)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise


def _extract_tar_gz(
    archive: pathlib.Path, dest: pathlib.Path, label: str, expected: str
) -> str:
    expected = _require_hex64(expected, f"{label} SHA-256")
    before = _lstat_regular_file(archive, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        fd = os.open(archive, flags)
    except OSError as suc:
        raise StoreEngineBindError(f"{label} is unreadable") from suc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise StoreEngineBindError(f"{label} changed while opened")
        payload = _read_exact_fd_bytes(fd, opened.st_size, label)
        hashed = os.fstat(fd)
        if (hashed.st_dev, hashed.st_ino) != (opened.st_dev, opened.st_ino):
            raise StoreEngineBindError(f"{label} changed while hashed")
    finally:
        os.close(fd)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected:
        raise StoreEngineBindError(f"{label} SHA-256 verification failed")
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
            members = tar.getmembers()
            if not members or len(members) > CONTRACT.MAX_MEMBERS:
                raise StoreEngineBindError(
                    f"{label} member-count limit exceeded"
                )
            seen: set[str] = set()
            folded: set[str] = set()
            total_files = 0
            for member in members:
                _reject_tar_member(member, label)
                canonical = "/".join(
                    part for part in member.name.split("/") if part
                )
                collision = canonical.casefold()
                if canonical in seen or collision in folded:
                    raise StoreEngineBindError(
                        f"{label} duplicate, Unicode, or case-fold member collision: "
                        f"{member.name}"
                    )
                seen.add(canonical)
                folded.add(collision)
                if member.isfile():
                    total_files += member.size
                    CONTRACT._check_expansion(total_files, len(payload), label)
            _extract_validated_members(tar, members, dest, label)
    except StoreEngineBindError:
        raise
    except (tarfile.TarError, OSError) as suc:
        raise StoreEngineBindError(f"{label} extraction failed") from suc
    return digest


def bind_go_archive(
    source_root: pathlib.Path,
    tmp: pathlib.Path,
    arch: str,
    *,
    expected_archive_sha256: str | None = None,
    require_elf: bool | None = None,
) -> dict[str, str]:
    _lstat_regular_dir(source_root, "WINS_ENGINE_SOURCE_ROOT")
    _lstat_regular_dir(tmp, "store engine scratch")
    expected = _require_hex64(
        expected_archive_sha256 or go_archive_sha256(arch),
        "Go archive SHA-256",
    )
    name = go_archive_name(arch)
    archive = source_root / "go-sdk" / name
    wrapper = source_root / "go-sdk" / "go" / "bin" / "go"
    if not archive.exists():
        if wrapper.exists() or wrapper.is_symlink():
            raise StoreEngineBindError(GO_WRAPPER_REFUSAL)
        raise StoreEngineBindError(f"{GO_ARCHIVE_MISSING}: {archive}")
    dest = tmp / "go-sdk"
    if dest.exists() or dest.is_symlink():
        raise StoreEngineBindError("Go extract destination already exists")
    measured = _extract_tar_gz(archive, dest, "Go SDK archive", expected)
    if measured != expected:
        raise StoreEngineBindError(GO_WRAPPER_REFUSAL)
    go_bin = dest / "go" / "bin" / "go"
    _lstat_regular_file(go_bin, "extracted go executable")
    if require_elf is None:
        require_elf = os.uname().sysname == "Linux"
    if require_elf:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
        fd = os.open(go_bin, flags)
        try:
            magic = os.read(fd, 4)
        finally:
            os.close(fd)
        if magic != ELF_MAGIC:
            raise StoreEngineBindError(GO_WRAPPER_REFUSAL)
    go_sha256 = sha256_bind_file(go_bin, "extracted go executable")
    tree_sha256 = hash_regular_tree(dest / "go", "extracted Go install tree")
    if tree_sha256 == go_sha256:
        raise StoreEngineBindError("Go executable hash must not equal the install tree")
    return {
        "LINUX_REVIEWED_GO_BIN": str(go_bin.resolve()),
        "WINS_RELEASE_GO_SHA256": go_sha256,
        "WINS_RELEASE_GO_TREE_SHA256": expected,
        "WINS_RELEASE_GO_INSTALL_TREE_SHA256": tree_sha256,
    }


def install_bound_payload(
    source: pathlib.Path,
    dest: pathlib.Path,
    label: str,
    *,
    mode: int = 0o755,
) -> str:
    digest = sha256_bind_file(source, label)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() or dest.is_symlink():
        raise StoreEngineBindError(f"{label} destination already exists")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    src_fd = os.open(source, flags)
    try:
        info = os.fstat(src_fd)
        write_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | os.O_NOFOLLOW
        )
        dest_fd = os.open(dest, write_flags, mode)
        try:
            remaining = info.st_size
            while remaining:
                block = os.read(src_fd, min(1024 * 1024, remaining))
                if not block:
                    raise StoreEngineBindError(f"{label} ended while installing")
                written = os.write(dest_fd, block)
                if written != len(block):
                    raise StoreEngineBindError(f"{label} install write truncated")
                remaining -= len(block)
            os.fchmod(dest_fd, mode)
        finally:
            os.close(dest_fd)
    finally:
        os.close(src_fd)
    installed = sha256_bind_file(dest, f"installed {label}")
    if installed != digest:
        raise StoreEngineBindError(f"{label} changed while installed")
    return installed


def copy_regular_tree(source: pathlib.Path, dest: pathlib.Path, label: str) -> str:
    _lstat_regular_dir(source, label)
    if dest.exists() or dest.is_symlink():
        raise StoreEngineBindError(f"{label} destination already exists")
    dest.mkdir(mode=0o700)
    _lstat_regular_dir(dest, label)
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        current = pathlib.Path(dirpath)
        _lstat_regular_dir(current, label)
        dirnames.sort()
        filenames.sort()
        relative_dir = current.relative_to(source)
        dest_dir = dest if relative_dir == pathlib.Path(".") else dest / relative_dir
        kept: list[str] = []
        for name in dirnames:
            if name in {".", ".."} or "/" in name or "\\" in name:
                raise StoreEngineBindError(f"{label} member path is unsafe")
            child = current / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise StoreEngineBindError(f"{label} {SYMLINK_REFUSAL}: {child}")
            if not stat.S_ISDIR(info.st_mode):
                raise StoreEngineBindError(f"{label} nested member is not a directory")
            target = dest_dir / name
            if target.exists() or target.is_symlink():
                raise StoreEngineBindError(f"{label} destination already exists")
            target.mkdir(mode=0o700)
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            if name in {".", ".."} or "/" in name or "\\" in name:
                raise StoreEngineBindError(f"{label} member path is unsafe")
            child = current / name
            install_bound_payload(
                child, dest_dir / name, f"{label} {name}", mode=0o644
            )
    source_tree = hash_regular_tree(source, label)
    dest_tree = hash_regular_tree(dest, f"copied {label}")
    if source_tree != dest_tree:
        raise StoreEngineBindError(f"{label} changed while copied")
    return dest_tree


def bind_module_closures(
    source_root: pathlib.Path,
    tmp: pathlib.Path,
    *,
    repo: pathlib.Path | None = None,
    expected_tree_sha256: str | None = None,
) -> dict[str, str]:
    _lstat_regular_dir(source_root, "WINS_ENGINE_SOURCE_ROOT")
    cache = source_root / "go-mod-cache"
    if not cache.exists():
        raise StoreEngineBindError(MODULE_CLOSURE_MISSING)
    _lstat_regular_dir(cache, "Go module closure")
    if list(cache.iterdir()) == []:
        raise StoreEngineBindError(MODULE_CLOSURE_MISSING)
    host = os.environ.get("GOMODCACHE", "")
    home_cache = str(pathlib.Path.home() / "go" / "pkg" / "mod")
    if host and os.path.abspath(host) == os.path.abspath(cache):
        raise StoreEngineBindError(HOST_GOMODCACHE_REFUSAL)
    if os.path.abspath(cache) == os.path.abspath(home_cache):
        raise StoreEngineBindError(HOST_GOMODCACHE_REFUSAL)
    if host and os.path.abspath(host) == os.path.abspath(home_cache):
        raise StoreEngineBindError(HOST_GOMODCACHE_REFUSAL)
    isolated = tmp / "go-mod-cache"
    if isolated.exists() or isolated.is_symlink():
        raise StoreEngineBindError("isolated Go module cache already exists")
    tree = copy_regular_tree(cache, isolated, "Go module closure")
    if expected_tree_sha256 is None:
        raise StoreEngineBindError(MODULE_TREE_MISSING)
    expected = _require_hex64(expected_tree_sha256, "Go module closure identity")
    if tree != expected:
        raise StoreEngineBindError(
            "Go module closure tree does not match the authenticated identity"
        )
    if repo is None:
        raise StoreEngineBindError(WINN_GOSUM_MISSING)
    gosum = repo / "winn_protocol_experimental" / "go.sum"
    if not gosum.exists() and not gosum.is_symlink():
        raise StoreEngineBindError(WINN_GOSUM_MISSING)
    digest = sha256_bind_file(gosum, "Winn v3 go.sum")
    if digest != CONTRACT.WINN_GOSUM_SHA256:
        raise StoreEngineBindError("Winn v3 go.sum is not the authenticated closure")
    return {
        "WINS_STORE_GOMODCACHE": str(isolated.resolve()),
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOENV": "off",
        "GOTOOLCHAIN": "local",
        "GOPRIVATE": "",
        "GONOPROXY": "",
        "GONOSUMDB": "",
        "GOFLAGS": "-mod=readonly",
        "WINS_STORE_GOMODCACHE_TREE_SHA256": tree,
    }


def bind_xray_source(
    source_root: pathlib.Path,
    *,
    expected_tree_sha256: str | None = None,
    expected_license_sha256: str | None = None,
) -> dict[str, str]:
    src = source_root / "xray-core"
    _lstat_regular_dir(src, "Xray source")
    license_path = src / "LICENSE"
    if not license_path.exists():
        raise StoreEngineBindError(XRAY_LICENSE_MISSING)
    license_digest = sha256_bind_file(license_path, "Xray LICENSE")
    expected_license = expected_license_sha256 or CONTRACT.XRAY_LICENSE_SHA256
    if license_digest != expected_license:
        raise StoreEngineBindError("Xray LICENSE is not the authenticated source")
    identity = src / CONTRACT.XRAY_IDENTITY_RELATIVE
    if not identity.exists() and not identity.is_symlink():
        raise StoreEngineBindError(XRAY_IDENTITY_MISSING)
    identity_digest = sha256_bind_file(identity, "Xray identity")
    if identity_digest != CONTRACT.XRAY_IDENTITY_SHA256:
        raise StoreEngineBindError(XRAY_IDENTITY_MISSING)
    go_mod = src / "go.mod"
    if go_mod.exists():
        body = go_mod.read_text(encoding="utf-8")
        if "module github.com/xtls/xray-core" not in body:
            raise StoreEngineBindError("Xray go.mod is not the authenticated module")
    if expected_tree_sha256 is None:
        raise StoreEngineBindError(XRAY_TREE_MISSING)
    expected_tree = _require_hex64(expected_tree_sha256, "Xray source tree")
    tree = hash_regular_tree(src, "Xray source")
    if tree != expected_tree:
        raise StoreEngineBindError("Xray source tree does not match the authenticated identity")
    return {
        "XRAY_SOURCE_DIR": str(src.resolve()),
        "XRAY_BUILD_COMMID": CONTRACT.XRAY_TAG,
        "XRAY_SOURCE_TREE_SHA256": tree,
        "XRAY_LICENSE_SHA256": license_digest,
    }


PACKAGE_CLANG_PATH = "/usr/bin/clang"
CLANG_SYMLINK_HOPS = 8


def _regular_file_identity(
    path: pathlib.Path, label: str, *, max_hops: int = CLANG_SYMLINK_HOPS
) -> tuple[int, int, pathlib.Path]:
    current = path
    for _ in range(max_hops):
        try:
            info = current.lstat()
        except OSError as suc:
            raise StoreEngineBindError(f"{label} is unreadable") from suc
        if stat.S_ISLNK(info.st_mode):
            try:
                target = os.readlink(current)
            except OSError as suc:
                raise StoreEngineBindError(f"{label} is unreadable") from suc
            if os.path.isabs(target):
                current = pathlib.Path(target)
            else:
                current = current.parent / target
            continue
        if not stat.S_ISREG(info.st_mode):
            raise StoreEngineBindError(f"{label} must be a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
        try:
            fd = os.open(current, flags)
        except OSError as suc:
            raise StoreEngineBindError(f"{label} is unreadable") from suc
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise StoreEngineBindError(f"{label} changed while opened")
            return opened.st_dev, opened.st_ino, current
        finally:
            os.close(fd)
    raise StoreEngineBindError(f"{label} symlink chain is too long")


def _probe_awg_arm64_toolchain() -> str | None:
    clang = shutil.which("clang")
    if clang is None:
        return None
    dpkg = shutil.which("dpkg-query")
    if dpkg is None:
        return None
    try:
        invoked_dev, invoked_ino, _invoked_path = _regular_file_identity(
            pathlib.Path(clang), "PATH clang"
        )
        package_dev, package_ino, package_path = _regular_file_identity(
            pathlib.Path(PACKAGE_CLANG_PATH), "package clang"
        )
    except StoreEngineBindError:
        return None
    if (invoked_dev, invoked_ino) != (package_dev, package_ino):
        return None
    canonical = str(package_path)
    try:
        _safe_export_value(canonical, "AWG_ARM64_CLANG")
    except StoreEngineBindError:
        return None
    try:
        completed = subprocess.run(
            [canonical, "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"},
        )
        clang_pkg = subprocess.run(
            [dpkg, "-W", "-f=${Version}", "clang"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        binutils_pkg = subprocess.run(
            [dpkg, "-W", "-f=${Version}", "binutils"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError:
        return None
    if "clang version 14.0.6" not in (completed.stdout or ""):
        return None
    if clang_pkg.stdout != CONTRACT.REVIEWED_CLANG_PACKAGE:
        return None
    if binutils_pkg.stdout != CONTRACT.REVIEWED_BINUTILS_PACKAGE:
        return None
    try:
        after_dev, after_ino, after_path = _regular_file_identity(
            pathlib.Path(PACKAGE_CLANG_PATH), "package clang"
        )
    except StoreEngineBindError:
        return None
    if (after_dev, after_ino, str(after_path)) != (
        package_dev,
        package_ino,
        canonical,
    ):
        return None
    return canonical


def bind_awg_arm64_payload(
    source_root: pathlib.Path,
    *,
    expected_awg_sha256: str | None = None,
    expected_quick_sha256: str | None = None,
    toolchain_probe: Callable[[], str | None] | None = None,
) -> dict[str, str]:
    prebuilt = source_root / "awg-prebuilt" / "awg"
    quick = source_root / "awg-prebuilt" / "awg-quick"
    if prebuilt.exists() or quick.exists():
        awg_digest = sha256_bind_file(prebuilt, "arm64 AWG prebuilt")
        quick_digest = sha256_bind_file(quick, "awg-quick prebuilt")
        expected_awg = expected_awg_sha256 or CONTRACT.REVIEWED_ENGINE_PAYLOAD_SHA256[
            "arm64"
        ]["awg"]
        expected_quick = (
            expected_quick_sha256
            or CONTRACT.REVIEWED_ENGINE_PAYLOAD_SHA256["arm64"]["awg-quick"]
        )
        if awg_digest != expected_awg or quick_digest != expected_quick:
            raise StoreEngineBindError(
                "arm64 AWG prebuilt payload SHA-256 verification failed"
            )
        return {
            "AWG_ARM64_PREBUILT": str(prebuilt.resolve()),
            "AWG_ARM64_QUICK_PREBUILT": str(quick.resolve()),
        }
    probe = toolchain_probe if toolchain_probe is not None else _probe_awg_arm64_toolchain
    bound = probe()
    if type(bound) is str and bound:
        try:
            _safe_export_value(bound, "AWG_ARM64_CLANG")
        except StoreEngineBindError:
            raise StoreEngineBindError(AWG_TOOLCHAIN_REFUSAL) from None
        return {
            "AWG_ARM64_TOOLCHAIN": (
                f"clang-{CONTRACT.REVIEWED_CLANG_VERSION}/"
                f"binutils-{CONTRACT.REVIEWED_BINUTILS_PACKAGE}"
            ),
            "AWG_ARM64_CLANG": bound,
        }
    raise StoreEngineBindError(AWG_TOOLCHAIN_REFUSAL)


def bind_engine_payload(path: pathlib.Path, label: str, expected: str | None = None) -> str:
    digest = sha256_bind_file(path, label)
    if expected is not None and digest != expected:
        raise StoreEngineBindError(f"{label} SHA-256 verification failed")
    return digest


def _isolate_gocache(tmp: pathlib.Path) -> dict[str, str]:
    isolated = tmp / "go-build-cache"
    if isolated.exists() or isolated.is_symlink():
        raise StoreEngineBindError("isolated Go build cache already exists")
    isolated.mkdir(mode=0o700)
    _lstat_regular_dir(isolated, "isolated Go build cache")
    resolved = str(isolated.resolve())
    home_darwin = str(pathlib.Path.home() / "Library" / "Caches" / "go-build")
    home_linux = str(pathlib.Path.home() / ".cache" / "go-build")
    if os.path.abspath(resolved) in {
        os.path.abspath(home_darwin),
        os.path.abspath(home_linux),
    }:
        raise StoreEngineBindError(HOST_GOCACHE_REFUSAL)
    return {
        "GOCACHE": resolved,
        "WINS_STORE_GOCACHE": resolved,
    }


def prepare(
    source_root: pathlib.Path,
    tmp: pathlib.Path,
    arch: str,
    *,
    repo: pathlib.Path | None = None,
    expected_go_archive_sha256: str | None = None,
    expected_module_tree_sha256: str | None = None,
    expected_xray_tree_sha256: str | None = None,
    expected_xray_license_sha256: str | None = None,
    expected_awg_sha256: str | None = None,
    expected_quick_sha256: str | None = None,
    require_go_elf: bool | None = None,
    toolchain_probe: Callable[[], str | None] | None = None,
) -> dict[str, str]:
    if arch not in {"x64", "arm64"}:
        raise StoreEngineBindError(f"unsupported engine architecture: {arch}")
    if expected_module_tree_sha256 is None:
        expected_module_tree_sha256 = _contract_pin(
            CONTRACT.store_gomodcache_tree_sha256, "Go module closure identity"
        )
    if expected_xray_tree_sha256 is None:
        expected_xray_tree_sha256 = _contract_pin(
            CONTRACT.xray_source_tree_sha256, "Xray source tree"
        )
    env = {
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOENV": "off",
        "GOTOOLCHAIN": "local",
    }
    env.update(_isolate_gocache(tmp))
    env.update(
        bind_go_archive(
            source_root,
            tmp,
            arch,
            expected_archive_sha256=expected_go_archive_sha256,
            require_elf=require_go_elf,
        )
    )
    env.update(
        bind_module_closures(
            source_root,
            tmp,
            repo=repo,
            expected_tree_sha256=expected_module_tree_sha256,
        )
    )
    env.update(
        bind_xray_source(
            source_root,
            expected_tree_sha256=expected_xray_tree_sha256,
            expected_license_sha256=expected_xray_license_sha256,
        )
    )
    if arch == "arm64":
        env.update(
            bind_awg_arm64_payload(
                source_root,
                expected_awg_sha256=expected_awg_sha256,
                expected_quick_sha256=expected_quick_sha256,
                toolchain_probe=toolchain_probe,
            )
        )
    env["WINS_ENGINE_SOURCE_ROOT"] = str(source_root.resolve())
    return env


def write_exports(env: dict[str, str], path: pathlib.Path) -> None:
    lines = ["# winsvpn store engine bind exports\n"]
    for key in sorted(env):
        if not key.isascii() or not key.isidentifier() or key != key.upper():
            raise StoreEngineBindError(f"refusing unsafe export name {key}")
        if not all(character.isupper() or character.isdigit() or character == "_" for character in key):
            raise StoreEngineBindError(f"refusing unsafe export name {key}")
        value = _safe_export_value(env[key], key)
        lines.append(f"export {key}={value}\n")
    payload = "".join(lines).encode("ascii")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
    )
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


def stage_isolated_offline(
    source_root: pathlib.Path,
    dest: pathlib.Path,
    arch: str,
    payloads: dict[str, pathlib.Path],
    *,
    tmp: pathlib.Path | None = None,
    repo: pathlib.Path | None = None,
    expected_go_archive_sha256: str | None = None,
    expected_module_tree_sha256: str | None = None,
    expected_xray_tree_sha256: str | None = None,
    expected_xray_license_sha256: str | None = None,
    expected_awg_sha256: str | None = None,
    expected_quick_sha256: str | None = None,
    expected_payload_sha256: dict[str, str] | None = None,
    require_go_elf: bool | None = False,
    toolchain_probe: Callable[[], str | None] | None = None,
) -> dict[str, str]:
    """Production binder plus O_NOFOLLOW payload install.

    Isolated fixture tests may pass explicit pins. The production CLI does not.
    """
    cleanup = False
    if tmp is None:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="winsvpn-store-engine-"))
        cleanup = True
    try:
        env = prepare(
            source_root,
            tmp,
            arch,
            repo=repo,
            expected_go_archive_sha256=expected_go_archive_sha256,
            expected_module_tree_sha256=expected_module_tree_sha256,
            expected_xray_tree_sha256=expected_xray_tree_sha256,
            expected_xray_license_sha256=expected_xray_license_sha256,
            expected_awg_sha256=expected_awg_sha256,
            expected_quick_sha256=expected_quick_sha256,
            require_go_elf=require_go_elf,
            toolchain_probe=toolchain_probe,
        )
        _lstat_regular_dir(dest, "engine destination")
        if dest.is_symlink():
            raise StoreEngineBindError("refusing symlink engine destination")
        installed: dict[str, str] = {}
        order = ("winn-datapath", "awg", "awg-quick", "amneziawg-go", "xray")
        for name in order:
            if name not in payloads:
                raise StoreEngineBindError(f"missing engine payload: {name}")
            expected = None
            if expected_payload_sha256 is not None:
                expected = expected_payload_sha256.get(name)
            installed[name] = install_bound_payload(
                payloads[name], dest / name, name
            )
            if expected is not None and installed[name] != expected:
                raise StoreEngineBindError(f"{name} SHA-256 verification failed")
        env["WINN_DATAPATH_BIND"] = WINN_DATAPATH_BIND
        env["WINN_DATAPATH_SHA256"] = installed["winn-datapath"]
        env.update({f"STAGED_{name.replace('-', '_').upper()}_SHA256": digest for name, digest in installed.items()})
        return env
    finally:
        if cleanup:
            shutil.rmtree(tmp, ignore_errors=True)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_cmd = sub.add_parser("prepare")
    prepare_cmd.add_argument("--source-root", required=True)
    prepare_cmd.add_argument("--tmp", required=True)
    prepare_cmd.add_argument("--arch", required=True, choices=("x64", "arm64"))
    prepare_cmd.add_argument("--repo", required=True)
    prepare_cmd.add_argument("--out-env", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "prepare":
        env = prepare(
            pathlib.Path(args.source_root),
            pathlib.Path(args.tmp),
            args.arch,
            repo=pathlib.Path(args.repo),
        )
        write_exports(env, pathlib.Path(args.out_env))
        json.dump(env, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    raise StoreEngineBindError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except StoreEngineBindError as suc:
        sys.stderr.write(f"STORE ENGINE BIND ERROR: {suc}\n")
        raise SystemExit(65) from suc
    except (tarfile.TarError, OSError) as suc:
        sys.stderr.write(f"STORE ENGINE BIND ERROR: {suc}\n")
        raise SystemExit(65) from suc
