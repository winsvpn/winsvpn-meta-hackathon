#!/usr/bin/env python3
"""Create a local immutable gcloud receipt from a verified official archive."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import zipfile

import gcloud_custody as custody


ARCHIVE_STAGE_NAME = f"{custody.CUSTODY_ARCHIVE_NAME}.stage"
RECEIPT_STAGE_NAME = f"{custody.RECEIPT_NAME}.stage"
STAGE_WRITING_MODE = 0o600
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)


def _inode(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _effective_uid() -> int:
    getter = getattr(os, "geteuid", None)
    return int(getter()) if callable(getter) else 0


def _effective_gid() -> int:
    getter = getattr(os, "getegid", None)
    return int(getter()) if callable(getter) else 0


def _cleanup_name(stage_name: str) -> str:
    return f".{stage_name}.cleanup"


def _stable_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
        int(info.st_mode),
        int(info.st_nlink),
        int(info.st_uid),
        int(info.st_gid),
    )


def _rename_exclusive(directory: int, source: str, target: str) -> None:
    """Rename within one held directory without replacing an existing target."""

    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function_name = "renameatx_np"
        flag = 0x00000004  # RENAME_EXCL from <sys/stdio.h>.
    elif sys.platform.startswith("linux"):
        function_name = "renameat2"
        flag = 0x00000001  # RENAME_NOREPLACE from <stdio.h>.
    else:
        raise custody.GcloudCustodyError(
            "exclusive custody cleanup rename is unsupported on this platform"
        )
    try:
        function = getattr(library, function_name)
    except AttributeError as exc:
        raise custody.GcloudCustodyError(
            "exclusive custody cleanup rename is unavailable"
        ) from exc
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(
        directory,
        os.fsencode(source),
        directory,
        os.fsencode(target),
        flag,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(error, os.strerror(error), target)
    unsupported = {
        errno.EINVAL,
        errno.ENOSYS,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
    if error in unsupported:
        raise custody.GcloudCustodyError(
            "exclusive custody cleanup rename is unsupported by this filesystem"
        )
    raise OSError(error, os.strerror(error), target)


def _open_publication_directory(path: Path) -> tuple[Path, int, tuple[int, int]]:
    resolved = path.resolve(strict=True)
    before = resolved.lstat()
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != _effective_uid()
        or before.st_gid != _effective_gid()
        or stat.S_IMODE(before.st_mode) & 0o7022
    ):
        raise custody.GcloudCustodyError("Google Cloud CLI install root is not a directory")
    descriptor = os.open(resolved, _DIRECTORY_FLAGS)
    try:
        held = os.fstat(descriptor)
        current = resolved.lstat()
        if (
            not stat.S_ISDIR(held.st_mode)
            or held.st_uid != _effective_uid()
            or held.st_gid != _effective_gid()
            or stat.S_IMODE(held.st_mode) & 0o7022
            or _inode(before) != _inode(held)
            or _inode(current) != _inode(held)
        ):
            raise custody.GcloudCustodyError(
                "Google Cloud CLI install root changed during receipt publication"
            )
        return resolved, descriptor, _inode(held)
    except Exception:
        os.close(descriptor)
        raise


def _require_directory_identity(
    root: Path, descriptor: int, expected: tuple[int, int]
) -> None:
    held = os.fstat(descriptor)
    current = root.lstat()
    if (
        not stat.S_ISDIR(held.st_mode)
        or held.st_uid != _effective_uid()
        or held.st_gid != _effective_gid()
        or stat.S_IMODE(held.st_mode) & 0o7022
        or not stat.S_ISDIR(current.st_mode)
        or current.st_uid != _effective_uid()
        or current.st_gid != _effective_gid()
        or stat.S_IMODE(current.st_mode) & 0o7022
        or _inode(held) != expected
        or _inode(current) != expected
    ):
        raise custody.GcloudCustodyError(
            "Google Cloud CLI install root changed during receipt publication"
        )


def _read_leaf(
    directory: int,
    name: str,
    *,
    max_size: int,
    label: str,
    sync: bool = False,
) -> tuple[os.stat_result, bytes] | None:
    try:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
    if before.st_size < 0 or before.st_size > max_size:
        raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
    descriptor = os.open(name, _READ_FLAGS, dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        if _inode(opened) != _inode(before) or not stat.S_ISREG(opened.st_mode):
            raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
        payload = bytearray()
        while len(payload) <= max_size:
            chunk = os.read(descriptor, min(1024 * 1024, max_size + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > max_size:
            raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
        if sync:
            os.fsync(descriptor)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            _stable_identity(opened) != _stable_identity(after)
            or _stable_identity(after) != _stable_identity(current)
            or len(payload) != after.st_size
        ):
            raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
        return after, bytes(payload)
    finally:
        os.close(descriptor)


def _inspect_final(
    directory: int,
    name: str,
    expected: bytes,
    *,
    max_size: int,
    label: str,
    sync: bool = False,
) -> os.stat_result | None:
    selected = _read_leaf(
        directory, name, max_size=max_size, label=label, sync=sync
    )
    if selected is None:
        return None
    info, payload = selected
    if (
        info.st_uid != _effective_uid()
        or info.st_gid != _effective_gid()
        or stat.S_IMODE(info.st_mode) != custody.SEALED_PUBLIC_DATA_MODE
        or payload != expected
    ):
        raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
    return info


def _inspect_stage(
    directory: int,
    name: str,
    expected: bytes,
    *,
    max_size: int,
    label: str,
) -> tuple[os.stat_result, bytes] | None:
    selected = _read_leaf(directory, name, max_size=max_size, label=label)
    if selected is None:
        return None
    info, payload = selected
    mode = stat.S_IMODE(info.st_mode)
    if (
        info.st_uid != _effective_uid()
        or info.st_gid != _effective_gid()
        or mode not in {
            STAGE_WRITING_MODE,
            custody.SEALED_PUBLIC_DATA_MODE,
        }
    ):
        raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
    if mode == custody.SEALED_PUBLIC_DATA_MODE and payload != expected:
        raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
    return info, payload


def _unlink_stage(
    directory: int, name: str, expected_inode: tuple[int, int], *, label: str
) -> None:
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_uid != _effective_uid()
        or current.st_gid != _effective_gid()
        or _inode(current) != expected_inode
    ):
        raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
    quarantine = _cleanup_name(name)
    try:
        os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise custody.GcloudCustodyError(f"unsafe preexisting {label} cleanup")
    try:
        _rename_exclusive(directory, name, quarantine)
    except FileExistsError as exc:
        raise custody.GcloudCustodyError(
            f"unsafe preexisting {label} cleanup; preserved both names"
        ) from exc
    moved = os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
    if _inode(moved) != expected_inode:
        try:
            os.link(
                quarantine,
                name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise custody.GcloudCustodyError(
                f"unsafe raced replacement of {label}; preserved both names"
            ) from exc
        os.unlink(quarantine, dir_fd=directory)
        os.fsync(directory)
        raise custody.GcloudCustodyError(f"unsafe raced replacement of {label}")
    os.unlink(quarantine, dir_fd=directory)
    os.fsync(directory)


def _recover_cleanup(
    directory: int,
    final_name: str,
    stage_name: str,
    expected: bytes,
    *,
    max_size: int,
    label: str,
) -> None:
    cleanup_name = _cleanup_name(stage_name)
    cleanup = _inspect_stage(
        directory,
        cleanup_name,
        expected,
        max_size=max_size,
        label=f"{label} cleanup",
    )
    if cleanup is None:
        return
    try:
        os.stat(stage_name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise custody.GcloudCustodyError(f"unsafe preexisting {label} cleanup")
    final = _inspect_final(
        directory, final_name, expected, max_size=max_size, label=label
    )
    cleanup_info, cleanup_payload = cleanup
    if final is None:
        if cleanup_info.st_nlink != 1:
            raise custody.GcloudCustodyError(f"unsafe preexisting {label} cleanup")
    elif (
        stat.S_IMODE(cleanup_info.st_mode) != custody.SEALED_PUBLIC_DATA_MODE
        or cleanup_payload != expected
        or _inode(cleanup_info) != _inode(final)
        or cleanup_info.st_nlink != 2
        or final.st_nlink != 2
    ):
        raise custody.GcloudCustodyError(f"unsafe preexisting {label} cleanup")
    current = os.stat(cleanup_name, dir_fd=directory, follow_symlinks=False)
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_uid != _effective_uid()
        or current.st_gid != _effective_gid()
        or _inode(current) != _inode(cleanup_info)
    ):
        raise custody.GcloudCustodyError(f"unsafe preexisting {label} cleanup")
    os.unlink(cleanup_name, dir_fd=directory)
    os.fsync(directory)


def _write_exclusive(
    directory: int, name: str, data: bytes, mode: int, *, label: str
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, STAGE_WRITING_MODE, dir_fd=directory)
    created_inode = _inode(os.fstat(descriptor))
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short custody write")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_uid != _effective_uid()
            or final.st_gid != _effective_gid()
            or final.st_nlink != 1
            or final.st_size != len(data)
            or stat.S_IMODE(final.st_mode) != mode
        ):
            raise custody.GcloudCustodyError(f"staged {label} metadata is invalid")
    except Exception:
        try:
            os.close(descriptor)
        finally:
            try:
                _unlink_stage(directory, name, created_inode, label=label)
            except Exception:
                pass
        raise
    os.close(descriptor)
    os.fsync(directory)


def _reconcile_leaf(
    directory: int,
    final_name: str,
    stage_name: str,
    expected: bytes,
    *,
    max_size: int,
    label: str,
) -> bool:
    _recover_cleanup(
        directory,
        final_name,
        stage_name,
        expected,
        max_size=max_size,
        label=label,
    )
    final = _inspect_final(
        directory, final_name, expected, max_size=max_size, label=label
    )
    stage = _inspect_stage(
        directory,
        stage_name,
        expected,
        max_size=max_size,
        label=f"{label} stage",
    )
    if final is not None:
        if stage is None:
            if final.st_nlink != 1:
                raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
        else:
            stage_info, stage_payload = stage
            if (
                stat.S_IMODE(stage_info.st_mode) != custody.SEALED_PUBLIC_DATA_MODE
                or stage_payload != expected
                or _inode(stage_info) != _inode(final)
                or stage_info.st_nlink != 2
                or final.st_nlink != 2
            ):
                raise custody.GcloudCustodyError(f"unsafe preexisting {label} stage")
            _unlink_stage(
                directory,
                stage_name,
                _inode(stage_info),
                label=f"{label} stage",
            )
        durable = _inspect_final(
            directory,
            final_name,
            expected,
            max_size=max_size,
            label=label,
            sync=True,
        )
        if durable is None or durable.st_nlink != 1:
            raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
        os.fsync(directory)
        return True
    if stage is not None:
        stage_info, _stage_payload = stage
        if stage_info.st_nlink != 1:
            raise custody.GcloudCustodyError(f"unsafe preexisting {label} stage")
        _unlink_stage(
            directory,
            stage_name,
            _inode(stage_info),
            label=f"{label} stage",
        )
    return False


def _publish_stage(
    directory: int,
    stage_name: str,
    final_name: str,
    expected: bytes,
    *,
    max_size: int,
    label: str,
) -> None:
    staged = _inspect_stage(
        directory,
        stage_name,
        expected,
        max_size=max_size,
        label=f"{label} stage",
    )
    if staged is None:
        raise custody.GcloudCustodyError(f"staged {label} is missing")
    staged_info, staged_payload = staged
    if (
        stat.S_IMODE(staged_info.st_mode) != custody.SEALED_PUBLIC_DATA_MODE
        or staged_info.st_nlink != 1
        or staged_payload != expected
    ):
        raise custody.GcloudCustodyError(f"staged {label} is invalid")
    try:
        os.link(
            stage_name,
            final_name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
    except FileExistsError:
        incumbent = _inspect_final(
            directory,
            final_name,
            expected,
            max_size=max_size,
            label=label,
            sync=True,
        )
        if incumbent is None or incumbent.st_nlink != 1:
            raise custody.GcloudCustodyError(f"unsafe preexisting {label}")
        os.fsync(directory)
        _unlink_stage(
            directory,
            stage_name,
            _inode(staged_info),
            label=f"{label} stage",
        )
        return
    os.fsync(directory)
    published = _inspect_final(
        directory, final_name, expected, max_size=max_size, label=label
    )
    linked_stage = _inspect_stage(
        directory,
        stage_name,
        expected,
        max_size=max_size,
        label=f"{label} stage",
    )
    if published is None or linked_stage is None:
        raise custody.GcloudCustodyError(f"published {label} identity is invalid")
    linked_info, linked_payload = linked_stage
    if (
        linked_payload != expected
        or _inode(published) != _inode(staged_info)
        or _inode(linked_info) != _inode(staged_info)
        or published.st_nlink != 2
        or linked_info.st_nlink != 2
    ):
        raise custody.GcloudCustodyError(f"published {label} identity is invalid")
    _unlink_stage(
        directory,
        stage_name,
        _inode(staged_info),
        label=f"{label} stage",
    )
    durable = _inspect_final(
        directory,
        final_name,
        expected,
        max_size=max_size,
        label=label,
        sync=True,
    )
    if durable is None or durable.st_nlink != 1:
        raise custody.GcloudCustodyError(f"published {label} identity is invalid")
    os.fsync(directory)


def _publish_pair(
    install_root: Path,
    archive_data: bytes,
    receipt_data: bytes,
    *,
    expected_clean_tree: str,
    expected_tree: str,
) -> tuple[Path, Path]:
    if (
        not archive_data
        or len(archive_data) > custody.MAX_ARCHIVE
        or not receipt_data
        or len(receipt_data) > custody.MAX_TRUST
    ):
        raise custody.GcloudCustodyError("Google Cloud CLI custody publication payload is invalid")
    root, directory, root_identity = _open_publication_directory(install_root)
    try:
        archive_present = _reconcile_leaf(
            directory,
            custody.CUSTODY_ARCHIVE_NAME,
            ARCHIVE_STAGE_NAME,
            archive_data,
            max_size=custody.MAX_ARCHIVE,
            label="Google Cloud CLI retained official archive",
        )
        receipt_present = _reconcile_leaf(
            directory,
            custody.RECEIPT_NAME,
            RECEIPT_STAGE_NAME,
            receipt_data,
            max_size=custody.MAX_TRUST,
            label="Google Cloud CLI custody receipt",
        )
        if receipt_present and not archive_present:
            raise custody.GcloudCustodyError(
                "unsafe preexisting Google Cloud CLI receipt without retained archive"
            )
        _require_directory_identity(root, directory, root_identity)
        observed_tree = custody.install_tree_sha256(root)
        _require_directory_identity(root, directory, root_identity)
        required_tree = expected_tree if archive_present else expected_clean_tree
        if observed_tree != required_tree:
            raise custody.GcloudCustodyError(
                "installed SDK is not byte-identical to the reviewed archive"
            )
        if not archive_present:
            _write_exclusive(
                directory,
                ARCHIVE_STAGE_NAME,
                archive_data,
                custody.SEALED_PUBLIC_DATA_MODE,
                label="Google Cloud CLI retained official archive",
            )
            _publish_stage(
                directory,
                ARCHIVE_STAGE_NAME,
                custody.CUSTODY_ARCHIVE_NAME,
                archive_data,
                max_size=custody.MAX_ARCHIVE,
                label="Google Cloud CLI retained official archive",
            )
        if not receipt_present:
            _write_exclusive(
                directory,
                RECEIPT_STAGE_NAME,
                receipt_data,
                custody.SEALED_PUBLIC_DATA_MODE,
                label="Google Cloud CLI custody receipt",
            )
            _publish_stage(
                directory,
                RECEIPT_STAGE_NAME,
                custody.RECEIPT_NAME,
                receipt_data,
                max_size=custody.MAX_TRUST,
                label="Google Cloud CLI custody receipt",
            )
        _require_directory_identity(root, directory, root_identity)
        if custody.install_tree_sha256(root) != expected_tree:
            raise custody.GcloudCustodyError(
                "installed SDK is not byte-identical to the reviewed archive"
            )
        _require_directory_identity(root, directory, root_identity)
    finally:
        os.close(directory)
    return root / custody.RECEIPT_NAME, root / custody.CUSTODY_ARCHIVE_NAME


def _install_retained_archive(
    archive: Path,
    install_root: Path,
    pin: dict,
):
    platform_key = custody.current_platform_key()
    archive = archive.resolve(strict=True)
    install_root = install_root.resolve(strict=True)
    if archive.name != pin["archive_name"][platform_key]:
        raise custody.GcloudCustodyError("archive filename does not match the reviewed pin")
    archive_data = custody._bind_regular_file_from_parent(
        archive, max_size=custody.MAX_ARCHIVE, label="Google Cloud CLI official archive"
    )
    if hashlib.sha256(archive_data).hexdigest() != pin["archive_sha256"][platform_key]:
        raise custody.GcloudCustodyError("archive hash does not match the reviewed pin")
    with tempfile.TemporaryDirectory(prefix="winsvpn-gcloud-custody-") as scratch:
        extracted = custody.extract_official_archive_bytes(
            archive_data,
            archive.name,
            Path(scratch) / "archive",
        )
        expected_clean_tree = custody.install_tree_sha256(extracted)
        retained_copy = extracted / custody.CUSTODY_ARCHIVE_NAME
        retained_copy.write_bytes(archive_data)
        os.chmod(retained_copy, custody.SEALED_PUBLIC_DATA_MODE)
        expected_tree = custody.install_tree_sha256(extracted)
    executable_name = "gcloud.cmd" if platform_key.startswith("windows_") else "gcloud"
    executable = install_root / "bin" / executable_name
    if not executable.is_file() or executable.is_symlink():
        raise custody.GcloudCustodyError("installed SDK lacks the canonical gcloud executable")
    record_base = {
        "schema_version": 1,
        "contract": custody.RECEIPT_CONTRACT,
        "version": pin["version"],
        "platform": platform_key,
        "archive_name": archive.name,
        "archive_sha256": pin["archive_sha256"][platform_key],
        "install_tree_sha256": expected_tree,
        "executable_path": f"bin/{executable_name}",
    }
    return (
        archive_data,
        expected_clean_tree,
        expected_tree,
        record_base,
        executable,
        install_root,
    )


def create(archive: Path, install_root: Path, pin_manifest: Path) -> Path:
    custody.require_compatible_python()
    pin = custody.validate_google_cloud_cli_pin(pin_manifest)
    (
        archive_data,
        expected_clean_tree,
        expected_tree,
        record,
        executable,
        install_root,
    ) = _install_retained_archive(archive, install_root, pin)
    issuance = custody._bind_owner_issuance(
        custody.OWNER_ISSUANCE_PATH,
        repo=Path(pin_manifest).resolve().parent.parent,
    )
    authorized = dict(issuance["receipt"])
    expected_root = hashlib.sha256(
        str(install_root.resolve(strict=True)).encode("utf-8")
    ).hexdigest()
    for key, value in record.items():
        if authorized.get(key) != value:
            raise custody.GcloudCustodyError(
                "owner issuance does not authorize the exact receipt"
            )
    if authorized.get("install_root_sha256") != expected_root:
        raise custody.GcloudCustodyError(
            "owner issuance does not authorize the exact install root"
        )
    authorized["issuance_signature"] = issuance["signature"]
    encoded = (
        json.dumps(authorized, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    receipt, _retained_archive = _publish_pair(
        install_root,
        archive_data,
        encoded,
        expected_clean_tree=expected_clean_tree,
        expected_tree=expected_tree,
    )
    custody.verify_installed_gcloud(executable, pin_manifest=pin_manifest)
    return receipt


def create_test_only(archive: Path, install_root: Path, pin_manifest: Path) -> Path:
    """TEST ONLY. Structurally unable to satisfy production verify_installed_gcloud."""
    custody.require_compatible_python()
    pin_bytes = custody._bind_regular_file_from_parent(
        Path(pin_manifest), max_size=custody.MAX_MANIFEST, label="test-only Google Cloud CLI pin"
    )
    pin = custody.parse_google_cloud_cli_pin_document(pin_bytes)
    (
        archive_data,
        expected_clean_tree,
        expected_tree,
        record,
        executable,
        install_root,
    ) = _install_retained_archive(archive, install_root, pin)
    record["test_only"] = True
    encoded = (
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    receipt, _retained_archive = _publish_pair(
        install_root,
        archive_data,
        encoded,
        expected_clean_tree=expected_clean_tree,
        expected_tree=expected_tree,
    )
    custody.bind_test_only_installed_gcloud(executable, pin, Path(pin_manifest))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--install-root", required=True, type=Path)
    parser.add_argument(
        "--pin-manifest",
        type=Path,
        default=Path(__file__).with_name("toolchain-pins.json"),
    )
    args = parser.parse_args()
    try:
        receipt = create(args.archive, args.install_root, args.pin_manifest)
    except (custody.GcloudCustodyError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(str(exc), file=os.sys.stderr)
        return 2
    print(receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
