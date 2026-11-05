#!/usr/bin/env python3
"""Standalone authenticated custody for official Inno Setup 7.1.0.

This layer verifies local installer and compiler candidates against
``tools/inno-toolchain-pins.json`` and immutable verifier trust anchors.
It never executes a setup candidate, never executes ISSigTool.exe, never
searches PATH, and never uploads.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
from typing import Any, Mapping


CONTRACT = "winsvpn-inno-toolchain-custody-v1"
SCHEMA_VERSION = 1
VERSION = "7.1.0"
DEFAULT_PIN = Path(__file__).resolve().with_name("inno-toolchain-pins.json")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX_SERIAL = re.compile(r"[0-9a-f]+\Z")
ISO_UTC = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
ZERO_SHA = "0" * 64
REVIEWED_ISSUANCE_UTC = dt.datetime(2026, 8, 1, 0, 0, 0, tzinfo=dt.timezone.utc)
REVIEWED_FRESHNESS = dt.timedelta(hours=24)
INSTALLER_FILE_DESCRIPTION = "Inno Setup Setup"
COMPILER_ORIGINAL_FILENAME = "ISCC.exe"
# The official 7.1.0 ISCC.exe carries VERSIONINFO ProductVersion "0.0.0.0"
# and FileDescription "Inno Setup Command-Line Compiler" (measured on
# Windows 11 x64 and ARM64, 2026-10-15), so VERSIONINFO cannot prove 7.1.0.
# The 7.1.0 identity comes from the pinned, custody-verified installer and,
# after measurement, from the pinned ISCC.exe digest.
COMPILER_FILE_DESCRIPTION = "Inno Setup Command-Line Compiler"
# Setup writes its uninstall log (unins000.dat) per installation; it differs
# between two installs of the same verified installer and ISCC never reads
# it, so it is left out of the install-tree digest (root level only).
PER_INSTALL_TREE_FILE = re.compile(r"unins[0-9]{3}\.dat\Z")
MAX_PIN = 256 * 1024
MAX_INSTALLER = 32 * 1024 * 1024
MAX_COMPILER = 16 * 1024 * 1024
MAX_ISSIG = 4096
MAX_PKCS7 = 256 * 1024
MAX_PKCS7_CERTS = 8
MAX_DER_DEPTH = 12
MAX_TREE_FILES = 4096
MAX_TREE_BYTES = 64 * 1024 * 1024
PE_MACHINE = {"x86": 0x014C, "x64": 0x8664, "arm64": 0xAA64}
PE_MAGIC = {"x86": 0x10B, "x64": 0x20B, "arm64": 0x20B}
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
RT_VERSION = 16
SETUP_NAME = re.compile(r"(?i)\Ainnosetup-.*\.exe\Z")
SIGNED_DATA_OID = "1.2.840.113549.1.7.2"

# Official JRSoftware ISSig trust-root identities. A mutable pin cannot
# replace these keys and self-sign installer hashes.
OFFICIAL_ISSIG_KEYS: dict[str, dict[str, Any]] = {
    "def02": {
        "filename": "def02.ispublickey",
        "key_id": "def020edee3c4835fd54d85eff8b66d4d899b22a777353ca4a114b652e5e7a28",
        "public_x": "515dc7d6c16d4a46272ceb3d158c5630a96466ab4d948e72c2029d737c823097",
        "public_y": "f3c21f6b5156c52a35f6f28016ee3e31a3ded60c325b81fb7b1f88c221081a61",
        "sha256": "32bea6bceb4ac7c4e6b3becdf3fb38de77378c5e76d494ab907d87cfab9e597b",
        "size": 248,
    },
    "def01": {
        "filename": "def01.ispublickey",
        "key_id": "def0147c3bbc17ab99bf7b7a9c2de1390283f38972152418d7c2a4a7d7131a38",
        "public_x": "e3e943066aff8f28d2219fd71c9ffff4c8d1aa26bc4225434be67180ab5e242d",
        "public_y": "e419041c3f54551e86a1c47f387005cd535dfc9d64339b30d37f9a4f7866b650",
        "sha256": "3b0b7e1e478c9ab327746a990512e2b245c9231e88a7fdd60d7874dd439db562",
        "size": 248,
    },
}

OFFICIAL_PUBLISHER: dict[str, str] = {
    "authenticode_publisher_name": "Pyrsys B.V.",
    "authenticode_subject_rfc4514": "CN=Pyrsys B.V.,O=Pyrsys B.V.,ST=Noord-Holland,C=NL",
    "authenticode_issuer_rfc4514": "CN=Sectigo Public Code Signing CA R36,O=Sectigo Limited,C=GB",
    "authenticode_leaf_serial_hex": "b208315c09c02ef1550e0c8d127cf499",
    "authenticode_leaf_sha256": "4efd84e6f1091b19321231743b9aa86482effd6d0bea9f7a44db6211154616f3",
}

TOP_KEYS = (
    "schema_version",
    "contract",
    "product",
    "vendor",
    "version",
    "channel",
    "status",
    "retrieved_utc",
    "official_sources",
    "verification_methods",
    "publisher",
    "issig_keys",
    "installers",
    "compilers",
    "verification_tool",
    "compiler_archive",
)
SOURCE_KEYS = ("url", "retrieved_utc", "role")
SOURCE_NAMES = (
    "downloads",
    "verify",
    "product",
    "whatsnew",
    "files_readme",
    "x64_issig",
    "x86_issig",
    "def02_key",
    "def01_key",
    "issigtool",
    "issigtool_issig",
    "immutable_x64",
    "immutable_x86",
    "immutable_tag",
    "issig_help",
    "issigfunc",
)
METHOD_KEYS = ("authenticode", "issig_ecdsa_p256", "github_release_attestation")
AUTH_METHOD_KEYS = (
    "required",
    "publisher_name",
    "signer_binding",
    "source_url",
    "windows_api",
)
ISSIG_METHOD_KEYS = (
    "required",
    "installer_key",
    "tool_key",
    "trust_anchor",
    "source_url",
    "execute_issigtool",
)
GITHUB_METHOD_KEYS = ("required", "source_url", "reason")
PUBLISHER_KEYS = (
    "authenticode_publisher_name",
    "authenticode_subject_rfc4514",
    "authenticode_issuer_rfc4514",
    "authenticode_leaf_serial_hex",
    "authenticode_leaf_sha256",
)
KEY_RECORD_KEYS = ("filename", "key_id", "public_x", "public_y", "sha256", "size")
INSTALLER_KEYS = (
    "status",
    "filename",
    "edition",
    "pe_machine",
    "recommended_compiler_host",
    "size",
    "sha256",
    "product_name",
    "product_version_string",
    "company_name",
    "file_description",
    "download_url",
    "issig_url",
    "issig_sha256",
    "issig_size",
    "issig_key",
    "issig_file_tag",
    "issig_sig_r",
    "issig_sig_s",
)
COMPILER_SHARED_KEYS = (
    "status",
    "filename",
    "pe_machine",
    "output_architectures",
    "trusted_root_leaf",
    "trusted_root_kind",
    "publisher_name",
    "expected_version",
    "sha256",
    "size",
    "install_tree_sha256",
    "product_version_string",
    "owner_action",
)
COMPILER_RECEIPT_CONTRACT = "winsvpn-inno-compiler-receipt-v1"
COMPILER_VERIFY_KEYS = (
    "architecture",
    "filename",
    "sha256",
    "size",
    "pe_machine",
    "output_architectures",
    "version",
    "product_version_string",
    "publisher_name",
    "authenticode_leaf_sha256",
    "authenticode_leaf_serial_hex",
    "install_tree_sha256",
    "trusted_root_leaf",
)
COMPILER_RECEIPT_KEYS = (
    "contract",
    "product",
    "vendor",
    "version",
    "filename",
    "architecture",
    "pe_machine",
    "output_architectures",
    "sha256",
    "size",
    "product_version_string",
    "publisher_name",
    "authenticode_leaf_sha256",
    "authenticode_leaf_serial_hex",
    "install_tree_sha256",
    "trusted_root_leaf",
    "pin_path",
    "pin_sha256",
)
PIN_RELATIVE_PATH = "tools/inno-toolchain-pins.json"
COMPILER_PIN_FIELDS = ("sha256", "size", "install_tree_sha256", "product_version_string")
TOOL_KEYS = (
    "status",
    "filename",
    "execute",
    "pe_machine",
    "size",
    "sha256",
    "download_url",
    "issig_url",
    "issig_sha256",
    "issig_size",
    "issig_key",
    "issig_file_tag",
    "issig_sig_r",
    "issig_sig_s",
    "note",
)
ARCHIVE_KEYS = ("status", "filename", "sha256", "size", "owner_action")


class Refused(ValueError):
    """A fail-closed Inno toolchain custody refusal."""


# Tests may assign a callable after each directory is bound through
# descriptor-relative open and before child lookup continues.
_POST_PARENT_BIND_HOOK = None


class BoundParent:
    """One held directory descriptor plus the child opened from it."""

    def __init__(
        self,
        path: Path,
        fd: int,
        identity: tuple[int, ...],
        child_name: str | None = None,
        child_identity: tuple[int, ...] | None = None,
    ) -> None:
        self.path = path
        self.fd = fd
        self.identity = identity
        self.child_name = child_name
        self.child_identity = child_identity


class BoundSnapshot:
    """One descriptor-authenticated file plus parent-chain identities."""

    def __init__(
        self,
        path: Path,
        fd: int,
        identity: tuple[int, ...],
        data: bytes,
        digest: str,
        parents: list[BoundParent],
    ) -> None:
        self.path = path
        self.fd = fd
        self.identity = identity
        self.data = data
        self.digest = digest
        self.parents = parents
        self.closed = False

    def assert_unchanged(self, label: str) -> None:
        if self.closed or self.fd < 0:
            fail(f"{label} snapshot descriptor is closed")
        opened = os.fstat(self.fd)
        latest = _identity_stat(self.path, label)
        if not (_identity(opened) == self.identity == _identity(latest)):
            fail(f"{label} mutated while it was inspected: {self.path}")
        if stat.S_ISLNK(latest.st_mode) or not stat.S_ISREG(latest.st_mode):
            fail(f"{label} must be one regular non-reparse file: {self.path}")
        _confirm_bound_parents(self.parents, self.path, label)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        fds = [self.fd, *[parent.fd for parent in self.parents]]
        self.fd = -1
        self.parents = []
        for handle in fds:
            if handle >= 0:
                try:
                    os.close(handle)
                except OSError:
                    pass


class BoundTree:
    """One descriptor-held ISCC install tree plus directory identities."""

    def __init__(
        self,
        root: Path,
        root_identity: tuple[int, ...],
        files: list[tuple[str, BoundSnapshot]],
        directories: list[tuple[Path, tuple[int, ...], int]],
        digest: str,
    ) -> None:
        self.root = root
        self.root_identity = root_identity
        self.files = files
        self.directories = directories
        self.digest = digest
        self.closed = False

    def assert_unchanged(self, label: str) -> None:
        if self.closed:
            fail(f"{label} snapshot descriptor is closed")
        latest_root = _identity_stat(self.root, label)
        if _pathname_identity(latest_root) != self.root_identity:
            fail(f"{label} mutated while it was inspected: {self.root}")
        held = {relative: snapshot for relative, snapshot in self.files}
        for relative, snapshot in self.files:
            snapshot.assert_unchanged(f"{label} file {relative}")
            pathname = self.root.joinpath(*relative.split("/")) if relative else self.root
            current = _identity_stat(pathname, f"{label} file {relative}")
            if _identity(current) != snapshot.identity:
                fail(f"{label} pathname identity changed: {pathname}")
        current_files, current_dirs = _enumerate_install_tree_paths(self.root)
        if current_files != set(held):
            fail(f"{label} mixed old/new tree membership: {self.root}")
        held_dirs = {path: identity for path, identity, _fd in self.directories}
        if current_dirs != set(held_dirs):
            fail(f"{label} mixed old/new tree membership: {self.root}")
        for path, recorded, handle in self.directories:
            current = _pathname_identity(_identity_stat(path, label))
            if current != recorded:
                fail(f"{label} directory mutated: {path}")
            if handle < 0:
                # Windows: os.open() cannot open a directory, so the walk is
                # bound by lstat identity only and re-checked above.
                continue
            try:
                held_dir = os.fstat(handle)
            except OSError as exc:
                raise Refused(f"{label} directory descriptor became unreadable") from exc
            if _pathname_identity(held_dir) != recorded:
                fail(f"{label} directory mutated: {path}")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for _relative, snapshot in self.files:
            snapshot.close()
        self.files = []
        handles = [handle for _path, _identity, handle in self.directories]
        self.directories = []
        for handle in handles:
            if handle >= 0:
                try:
                    os.close(handle)
                except OSError:
                    pass


def fail(message: str) -> None:
    raise Refused(message)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    """Exact file identity, including size and timestamps.

    On Windows, CPython (measured with 3.14.7) reports two fields differently
    for one unchanged file depending on the call: lstat() adds execute bits
    from the file extension (.exe, .bat, .cmd, .com) and reports st_ctime as
    the creation time, while fstat() on the held handle reports no execute
    bits and st_ctime as the NTFS change time. Both report the same
    st_birthtime_ns. The snapshot checks compare an fstat() identity with an
    lstat() identity, so on Windows the mode is compared without execute bits
    and the birth time stands in for st_ctime; the file ID, size, mtime and
    attributes still bind the file.
    """

    attrs = int(getattr(info, "st_file_attributes", 0))
    mode = info.st_mode
    ctime_ns = info.st_ctime_ns
    if os.name == "nt":
        mode &= ~0o111
        ctime_ns = info.st_birthtime_ns
    return (
        info.st_dev,
        info.st_ino,
        mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        ctime_ns,
        attrs,
    )


def _pathname_identity(info: os.stat_result) -> tuple[int, ...]:
    """Stable path identity. Directory ctime/mtime/nlink/size churn is not substitution."""

    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_uid,
        info.st_gid,
    )


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"type coercion refused: {label} must be an object")
    return value


def _require_keys(mapping: Mapping[str, Any], required: tuple[str, ...], label: str) -> None:
    missing = [key for key in required if key not in mapping]
    if missing:
        fail(f"pin field is absent: {label}.{missing[0]}")
    extra = [key for key in mapping if key not in required]
    if extra:
        fail(f"unexpected pin field rejected: {label}.{extra[0]}")


def _text(mapping: Mapping[str, Any], key: str, *, allow_empty: bool = False) -> str:
    value = mapping.get(key)
    if type(value) is not str:
        fail(f"type coercion refused: {key} must be a string")
    if any(ord(character) < 32 for character in value):
        fail(f"pin field contains a control character: {key}")
    if value.strip() != value:
        fail(f"pin field has surrounding whitespace: {key}")
    if not value and not allow_empty:
        fail(f"pin field must be one non-empty string: {key}")
    return value


def _bool(mapping: Mapping[str, Any], key: str) -> bool:
    value = mapping.get(key)
    if type(value) is not bool:
        fail(f"type coercion refused: {key} must be a boolean")
    return value


def _int(mapping: Mapping[str, Any], key: str, *, minimum: int, maximum: int) -> int:
    value = mapping.get(key)
    if type(value) is not int or isinstance(value, bool):
        fail(f"type coercion refused: {key} must be an integer")
    if value < minimum or value > maximum:
        fail(f"pin integer is outside the accepted range: {key}")
    return value


def _hex64(mapping: Mapping[str, Any], key: str) -> str:
    value = _text(mapping, key)
    if not HEX64.fullmatch(value) or value == ZERO_SHA:
        fail(f"pin SHA-256 is not an exact lowercase non-zero digest: {key}")
    return value


def _utc(mapping: Mapping[str, Any], key: str) -> dt.datetime:
    value = _text(mapping, key)
    if ISO_UTC.fullmatch(value) is None:
        fail(f"retrieved timestamp must be exact ISO UTC: {key}")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise Refused(f"retrieved timestamp must be exact ISO UTC: {key}") from exc
    now = dt.datetime.now(dt.timezone.utc)
    if parsed < REVIEWED_ISSUANCE_UTC:
        fail(f"retrieved timestamp is before the reviewed issuance bound: {key}")
    if parsed > now:
        fail(f"retrieved timestamp is after the reviewed issuance bound: {key}")
    return parsed


def _null(mapping: Mapping[str, Any], key: str) -> None:
    if mapping.get(key) is not None:
        fail(f"unmeasured or unpublished field must be JSON null: {key}")


def _string_list(mapping: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = mapping.get(key)
    if type(value) is not list or not value:
        fail(f"type coercion refused: {key} must be a non-empty array")
    items: list[str] = []
    for index, item in enumerate(value):
        if type(item) is not str or not item or item.strip() != item:
            fail(f"type coercion refused: {key}[{index}]")
        if item in items:
            fail(f"duplicate list value rejected: {key}")
        items.append(item)
    return tuple(items)


def _identity_stat(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise Refused(f"{label} is unreadable: {path}") from exc
    return info


def _refuse_reparse(info: os.stat_result, path: Path) -> None:
    if stat.S_ISLNK(info.st_mode):
        fail(f"symbolic path component rejected: {path}")
    if int(getattr(info, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT:
        fail(f"reparse point rejected: {path}")


def _supports_dir_fd() -> bool:
    return os.name != "nt"


def _open_named(dir_fd: int, name: str, flags: int, label: str, full: Path) -> int:
    try:
        if callable(getattr(os, "openat", None)):
            return os.openat(dir_fd, name, flags)
        return os.open(name, flags, dir_fd=dir_fd)
    except OSError as exc:
        raise Refused(f"{label} could not be opened without following links: {full}") from exc
    except (NotImplementedError, TypeError, ValueError) as exc:
        raise Refused(f"{label} could not be opened without following links: {full}") from exc


def _stat_named(dir_fd: int, name: str, label: str, full: Path) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as exc:
        raise Refused(f"{label} is unreadable: {full}") from exc
    except (NotImplementedError, TypeError, ValueError) as exc:
        raise Refused(f"{label} is unreadable: {full}") from exc


def _confirm_bound_parents(parents: list[BoundParent], path: Path, label: str) -> None:
    """Re-check device/inode/type/owner and descriptor-relative child binding."""
    for parent in parents:
        current = _identity_stat(parent.path, label)
        if _pathname_identity(current) != parent.identity:
            fail(f"parent path component mutated: {parent.path}")
        if parent.path != path and not stat.S_ISDIR(current.st_mode):
            fail(f"parent path component mutated: {parent.path}")
        if parent.fd >= 0:
            try:
                held = os.fstat(parent.fd)
            except OSError as exc:
                raise Refused(f"{label} parent descriptor became unreadable") from exc
            if _pathname_identity(held) != parent.identity:
                fail(f"parent path component mutated: {parent.path}")
        if parent.child_name is None or parent.child_identity is None:
            continue
        child_path = parent.path / parent.child_name
        if parent.fd >= 0:
            child = _stat_named(parent.fd, parent.child_name, label, child_path)
        else:
            child = _identity_stat(child_path, label)
        if _pathname_identity(child) != parent.child_identity:
            if child_path == path:
                fail(f"{label} mutated while it was inspected: {path}")
            fail(f"parent path component mutated: {parent.path}")
        _refuse_reparse(child, child_path)


def _require_explicit_absolute(path: Path, label: str) -> None:
    text = os.fspath(path)
    if not text or text != str(path):
        fail(f"type coercion refused: {label} path")
    if os.path.dirname(text) == "":
        fail("PATH substitution refused: candidate must be an explicit path")
    if not path.is_absolute():
        fail("PATH substitution refused: path is not absolute")
    for part in path.parts[1:]:
        if part in {"", ".", ".."}:
            fail(f"unsafe path component rejected: {path}")


def walk_path_components(path: Path, label: str) -> list[tuple[Path, tuple[int, ...]]]:
    _require_explicit_absolute(path, label)
    parents: list[tuple[Path, tuple[int, ...]]] = []
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        info = _identity_stat(current, label)
        _refuse_reparse(info, current)
        if part != path.parts[-1] and not stat.S_ISDIR(info.st_mode):
            fail(f"non-directory path component rejected: {current}")
        parents.append((current, _pathname_identity(info)))
    return parents


def _open_nofollow(path: Path | str, flags: int, label: str) -> int:
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise Refused(f"{label} could not be opened without following links: {path}") from exc


def bind_regular_snapshot(path: Path, label: str, *, maximum: int) -> BoundSnapshot:
    """Hold one immutable descriptor snapshot through later verification."""

    candidate = Path(path)
    _require_explicit_absolute(candidate, label)
    # O_BINARY: the Windows CRT opens in text mode by default, which stops a
    # read at the first 0x1A byte and rewrites CRLF, so a PE never reads whole.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    dir_follow = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    )
    dir_nofollow = dir_follow | getattr(os, "O_NOFOLLOW", 0)
    parents: list[BoundParent] = []
    fd = -1
    try:
        if _supports_dir_fd() and getattr(os, "O_DIRECTORY", 0):
            anchor_fd = _open_nofollow(candidate.anchor, dir_follow, label)
            anchor_path = Path(candidate.anchor)
            anchor_opened = os.fstat(anchor_fd)
            current = BoundParent(anchor_path, anchor_fd, _pathname_identity(anchor_opened))
            parents.append(current)
            current_fd = anchor_fd
            parts = candidate.parts[1:]
            for index, part in enumerate(parts):
                hook = _POST_PARENT_BIND_HOOK
                if hook is not None:
                    hook(candidate, index)
                child_path = current.path / part
                peeked = _stat_named(current_fd, part, label, child_path)
                _refuse_reparse(peeked, child_path)
                current.child_name = part
                current.child_identity = _pathname_identity(peeked)
                last = index == len(parts) - 1
                if last:
                    if not stat.S_ISREG(peeked.st_mode):
                        fail(f"{label} must be one regular non-reparse file: {candidate}")
                    component_flags = flags
                else:
                    if not stat.S_ISDIR(peeked.st_mode):
                        fail(f"non-directory path component rejected: {child_path}")
                    component_flags = dir_nofollow
                next_fd = _open_named(current_fd, part, component_flags, label, child_path)
                opened = os.fstat(next_fd)
                if last:
                    if _identity(peeked) != _identity(opened):
                        os.close(next_fd)
                        fail(f"{label} mutated while it was inspected: {candidate}")
                    fd = next_fd
                else:
                    if _pathname_identity(peeked) != _pathname_identity(opened):
                        os.close(next_fd)
                        fail(f"{label} mutated while it was inspected: {candidate}")
                    nxt = BoundParent(child_path, next_fd, _pathname_identity(opened))
                    parents.append(nxt)
                    current = nxt
                    current_fd = next_fd
        else:
            walk_path_components(candidate, label)
            lexical: list[BoundParent] = []
            current_path = Path(candidate.anchor)
            anchor_info = _identity_stat(current_path, label)
            lexical.append(BoundParent(current_path, -1, _pathname_identity(anchor_info)))
            parts = candidate.parts[1:]
            for index, part in enumerate(parts):
                hook = _POST_PARENT_BIND_HOOK
                if hook is not None:
                    hook(candidate, index)
                child_path = current_path / part
                peeked = _identity_stat(child_path, label)
                _refuse_reparse(peeked, child_path)
                lexical[-1].child_name = part
                lexical[-1].child_identity = _pathname_identity(peeked)
                if index != len(parts) - 1:
                    if not stat.S_ISDIR(peeked.st_mode):
                        fail(f"non-directory path component rejected: {child_path}")
                    lexical.append(BoundParent(child_path, -1, _pathname_identity(peeked)))
                    current_path = child_path
            parents = lexical
            fd = _open_nofollow(candidate, flags, label)
        info = os.fstat(fd)
        latest = _identity_stat(candidate, label)
        if _identity(info) != _identity(latest):
            fail(f"{label} mutated while it was inspected: {candidate}")
        _refuse_reparse(latest, candidate)
        if not stat.S_ISREG(latest.st_mode):
            fail(f"{label} must be one regular non-reparse file: {candidate}")
        if latest.st_nlink != 1:
            fail(f"hardlink refused: {label} must be a single-link file")
        if latest.st_size <= 0 or latest.st_size > maximum:
            fail(f"{label} size is outside the accepted range: {candidate}")
        chunks: list[bytes] = []
        remaining = latest.st_size
        while remaining > 0:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                fail(f"{label} mutated while it was read: {candidate}")
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(fd)
        if _identity(info) != _identity(after):
            fail(f"{label} mutated while it was read: {candidate}")
        data = b"".join(chunks)
        if len(data) != latest.st_size:
            fail(f"{label} mutated while it was read: {candidate}")
        digest = hashlib.sha256(data).hexdigest()
        snapshot = BoundSnapshot(
            candidate,
            fd,
            _identity(info),
            data,
            digest,
            parents,
        )
        fd = -1
        parents = []
        snapshot.assert_unchanged(label)
        return snapshot
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        for parent in parents:
            if parent.fd >= 0:
                try:
                    os.close(parent.fd)
                except OSError:
                    pass
        raise


def require_regular_file(path: Path, label: str, *, maximum: int) -> os.stat_result:
    snapshot = bind_regular_snapshot(path, label, maximum=maximum)
    try:
        return _identity_stat(snapshot.path, label)
    finally:
        snapshot.close()


def digest_file(path: Path, label: str, *, maximum: int) -> str:
    snapshot = bind_regular_snapshot(path, label, maximum=maximum)
    try:
        return snapshot.digest
    finally:
        snapshot.close()


def read_stable_file(path: Path, label: str, *, maximum: int) -> bytes:
    snapshot = bind_regular_snapshot(path, label, maximum=maximum)
    try:
        return snapshot.data
    finally:
        snapshot.close()


def issig_hash_to_sign(filename: str, size: int, file_hash: str, tag: str) -> bytes:
    def prefixed(value: str) -> bytes:
        encoded = value.encode("utf-8")
        return struct.pack("<I", len(encoded)) + encoded

    digest = hashlib.sha256()
    digest.update(prefixed(filename))
    digest.update(prefixed(tag))
    digest.update(struct.pack("<q", size))
    digest.update(bytes.fromhex(file_hash))
    return digest.digest()


def ecdsa_p256_verify(public_x: str, public_y: str, digest: bytes, sig_r: str, sig_s: str) -> None:
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
            encode_dss_signature,
        )
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:
        raise Refused("ISSig ECDSA verification requires the cryptography package") from exc
    try:
        key = ec.EllipticCurvePublicNumbers(
            int(public_x, 16), int(public_y, 16), ec.SECP256R1()
        ).public_key()
        signature = encode_dss_signature(int(sig_r, 16), int(sig_s, 16))
        key.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except Exception as exc:
        raise Refused("ISSig ECDSA-P256 signature verification failed") from exc


def verify_issig_identity(
    *,
    filename: str,
    size: int,
    file_hash: str,
    tag: str,
    key: Mapping[str, str],
    sig_r: str,
    sig_s: str,
) -> None:
    material = bytes.fromhex(key["public_x"] + key["public_y"])
    if hashlib.sha256(material).hexdigest() != key["key_id"]:
        fail("ISSig public key id does not match public-x||public-y")
    digest = issig_hash_to_sign(filename, size, file_hash, tag)
    ecdsa_p256_verify(key["public_x"], key["public_y"], digest, sig_r, sig_s)


def parse_issig_v2(data: bytes) -> dict[str, Any]:
    if not data or len(data) > MAX_ISSIG:
        fail("ISSig sidecar size is outside the accepted range")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise Refused("ISSig sidecar is not ASCII") from exc
    if "\r\n" in text:
        if "\r" in text.replace("\r\n", ""):
            fail("ISSig sidecar contains a control character")
        text = text.replace("\r\n", "\n")
    if any(ord(character) < 32 and character != "\n" for character in text):
        fail("ISSig sidecar contains a control character")
    lines = text.split("\n")
    if len(lines) < 2 or lines[-1] != "":
        fail("ISSig sidecar framing is malformed")
    lines = lines[:-1]
    expected = (
        ("format", False),
        ("file-name", True),
        ("file-size", False),
        ("file-hash", False),
        ("file-tag", True),
        ("key-id", False),
        ("sig-r", False),
        ("sig-s", False),
    )
    if len(lines) != len(expected):
        fail("ISSig sidecar field count mismatch")
    parsed: dict[str, Any] = {}
    for line, (key, quoted) in zip(lines, expected):
        prefix = f"{key} "
        if not line.startswith(prefix):
            fail(f"ISSig sidecar field mismatch: {key}")
        value = line[len(prefix) :]
        if quoted:
            if len(value) < 2 or value[0] != '"' or value[-1] != '"':
                fail(f"ISSig sidecar quoted field is malformed: {key}")
            inner = value[1:-1]
            if '"' in inner or "\\" in inner:
                fail(f"ISSig sidecar quoted field is malformed: {key}")
            parsed[key] = inner
        else:
            parsed[key] = value
    if parsed["format"] != "issig-v2":
        fail("ISSig sidecar format mismatch")
    if not parsed["file-size"].isdigit():
        fail("ISSig sidecar file-size is malformed")
    parsed["file-size"] = int(parsed["file-size"])
    for key in ("file-hash", "key-id", "sig-r", "sig-s"):
        value = parsed[key]
        if type(value) is not str or not HEX64.fullmatch(value) or value == ZERO_SHA:
            fail(f"ISSig sidecar digest is malformed: {key}")
    return parsed


def _der_read(
    blob: bytes, offset: int, *, expected: int | None = None, depth: int = 0
) -> tuple[int, bytes, int]:
    if depth > MAX_DER_DEPTH:
        fail("Authenticode PKCS#7 DER nesting is too deep")
    if offset < 0 or offset >= len(blob):
        fail("Authenticode PKCS#7 is truncated")
    tag = blob[offset]
    if expected is not None and tag != expected:
        fail("Authenticode PKCS#7 DER tag mismatch")
    if tag & 0x1F == 0x1F:
        fail("Authenticode PKCS#7 DER tag is malformed")
    cursor = offset + 1
    if cursor >= len(blob):
        fail("Authenticode PKCS#7 is truncated")
    length_byte = blob[cursor]
    cursor += 1
    if length_byte == 0x80:
        fail("Authenticode PKCS#7 indefinite length is refused")
    if length_byte < 0x80:
        length = length_byte
    else:
        count = length_byte & 0x7F
        if count < 1 or count > 4 or cursor + count > len(blob):
            fail("Authenticode PKCS#7 DER length is malformed")
        if blob[cursor] == 0:
            fail("Authenticode PKCS#7 DER length is malformed")
        length = int.from_bytes(blob[cursor : cursor + count], "big")
        cursor += count
    if length < 0 or length > MAX_PKCS7 or cursor + length > len(blob):
        fail("Authenticode PKCS#7 DER length is malformed")
    return tag, blob[cursor : cursor + length], cursor + length


def _der_full(blob: bytes, offset: int, *, expected: int | None = None, depth: int = 0) -> tuple[bytes, int]:
    tag, content, end = _der_read(blob, offset, expected=expected, depth=depth)
    return blob[offset:end], end


def _decode_oid(content: bytes) -> str:
    if not content:
        fail("Authenticode PKCS#7 OID is malformed")
    first = content[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80:
            if value > 1 << 28:
                fail("Authenticode PKCS#7 OID is malformed")
            continue
        parts.append(str(value))
        value = 0
    if content[-1] & 0x80:
        fail("Authenticode PKCS#7 OID is malformed")
    return ".".join(parts)


def _parse_der_integer(content: bytes) -> int:
    if not content or len(content) > 21:
        fail("Authenticode PKCS#7 INTEGER is malformed")
    if content[0] & 0x80:
        fail("Authenticode PKCS#7 INTEGER is malformed")
    if len(content) > 1 and content[0] == 0 and content[1] < 0x80:
        fail("Authenticode PKCS#7 INTEGER is malformed")
    return int.from_bytes(content, "big")


def _parse_certificate_set(content: bytes) -> list[bytes]:
    certificates: list[bytes] = []
    offset = 0
    while offset < len(content):
        if len(certificates) >= MAX_PKCS7_CERTS:
            fail("Authenticode PKCS#7 certificate count bound exceeded")
        der, offset = _der_full(content, offset, expected=0x30, depth=2)
        certificates.append(der)
    if not certificates:
        fail("Authenticode PKCS#7 contains no certificates")
    return certificates


def _certificate_issuer_serial(der: bytes) -> tuple[bytes, int]:
    _, cert, end = _der_read(der, 0, expected=0x30, depth=0)
    if end != len(der):
        fail("Authenticode certificate DER is malformed")
    _, tbs, cursor = _der_read(cert, 0, expected=0x30, depth=1)
    del cursor
    tbs_cursor = 0
    if tbs and tbs[0] == 0xA0:
        _, _version, tbs_cursor = _der_read(tbs, tbs_cursor, expected=0xA0, depth=2)
    _, serial_content, tbs_cursor = _der_read(tbs, tbs_cursor, expected=0x02, depth=2)
    serial = _parse_der_integer(serial_content)
    _, _signature, tbs_cursor = _der_read(tbs, tbs_cursor, expected=0x30, depth=2)
    issuer_tlv, tbs_cursor = _der_full(tbs, tbs_cursor, expected=0x30, depth=2)
    del tbs_cursor
    return issuer_tlv, serial


def parse_pkcs7_signer(blob: bytes) -> dict[str, Any]:
    if len(blob) > MAX_PKCS7:
        fail("Authenticode PKCS#7 size bound exceeded")
    tag, content, end = _der_read(blob, 0, expected=0x30)
    if end != len(blob) and blob[end:].strip(b"\x00") != b"":
        # WIN_CERTIFICATE may pad the DER to 8-byte alignment.
        padding = blob[end:]
        if any(byte != 0 for byte in padding) or len(padding) > 8:
            fail("Authenticode PKCS#7 has trailing data")
    offset = 0
    oid_tag, oid_content, offset = _der_read(content, offset, expected=0x06, depth=1)
    del oid_tag
    if _decode_oid(oid_content) != SIGNED_DATA_OID:
        fail("Authenticode PKCS#7 is not signedData")
    _, signed_wrapper, offset = _der_read(content, offset, expected=0xA0, depth=1)
    if offset != len(content):
        fail("Authenticode PKCS#7 has unexpected SignedData siblings")
    _, signed, signed_end = _der_read(signed_wrapper, 0, expected=0x30, depth=2)
    if signed_end != len(signed_wrapper):
        fail("Authenticode PKCS#7 SignedData framing is malformed")
    cursor = 0
    _, version, cursor = _der_read(signed, cursor, expected=0x02, depth=3)
    _parse_der_integer(version)
    _, _digest_algs, cursor = _der_read(signed, cursor, expected=0x31, depth=3)
    _, _content_info, cursor = _der_read(signed, cursor, expected=0x30, depth=3)
    certificates_der: list[bytes] = []
    if cursor < len(signed) and signed[cursor] == 0xA0:
        _, cert_content, cursor = _der_read(signed, cursor, expected=0xA0, depth=3)
        certificates_der = _parse_certificate_set(cert_content)
    if cursor < len(signed) and signed[cursor] == 0xA1:
        _, _crls, cursor = _der_read(signed, cursor, expected=0xA1, depth=3)
    _, signer_set, cursor = _der_read(signed, cursor, expected=0x31, depth=3)
    if cursor != len(signed):
        fail("Authenticode PKCS#7 SignedData has trailing fields")
    signer_cursor = 0
    _, signer_info, signer_cursor = _der_read(signer_set, signer_cursor, expected=0x30, depth=4)
    if signer_cursor != len(signer_set):
        fail("Authenticode PKCS#7 must contain exactly one SignerInfo")
    info_cursor = 0
    _, _signer_version, info_cursor = _der_read(signer_info, info_cursor, expected=0x02, depth=5)
    issuer_serial_tlv, info_cursor = _der_full(signer_info, info_cursor, expected=0x30, depth=5)
    _, issuer_serial, _ = _der_read(issuer_serial_tlv, 0, expected=0x30, depth=6)
    issuer_tlv, serial_offset = _der_full(issuer_serial, 0, expected=0x30, depth=7)
    _, serial_content, serial_end = _der_read(issuer_serial, serial_offset, expected=0x02, depth=7)
    if serial_end != len(issuer_serial):
        fail("Authenticode SignerInfo issuer/serial is malformed")
    serial = _parse_der_integer(serial_content)
    return {
        "certificates": certificates_der,
        "issuer_der": issuer_tlv,
        "serial": serial,
    }


def rva_to_offset(data: bytes, rva: int, sections: list[tuple[int, int, int, int]]) -> int:
    for virtual_address, virtual_size, raw_ptr, raw_size in sections:
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            offset = raw_ptr + (rva - virtual_address)
            if offset < 0 or offset > len(data):
                fail("PE RVA is outside the image")
            return offset
    fail("PE RVA is not inside a section")
    raise AssertionError("unreachable")


def parse_pe(data: bytes) -> dict[str, Any]:
    if len(data) < 64 or data[:2] != b"MZ":
        fail("candidate is not a PE image")
    pe = struct.unpack_from("<I", data, 60)[0]
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        fail("candidate has an invalid PE header")
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    if optional + optional_size > len(data) or section_count > 96:
        fail("candidate has a truncated optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    directory_base = optional + (112 if magic == 0x20B else 96)
    number_offset = optional + (108 if magic == 0x20B else 92)
    if number_offset + 4 > optional + optional_size:
        fail("candidate has no Authenticode directory")
    directories = struct.unpack_from("<I", data, number_offset)[0]
    if directories < 5 or directory_base + 40 > optional + optional_size:
        fail("candidate has no Authenticode directory")
    resource_rva = struct.unpack_from("<I", data, directory_base + 16)[0]
    resource_size = struct.unpack_from("<I", data, directory_base + 20)[0]
    cert_offset = struct.unpack_from("<I", data, directory_base + 32)[0]
    cert_size = struct.unpack_from("<I", data, directory_base + 36)[0]
    if cert_offset == 0 or cert_size < 8 or cert_offset + cert_size > len(data):
        fail("candidate has no embedded Authenticode signature")
    if cert_size > MAX_PKCS7 + 16:
        fail("Authenticode PKCS#7 size bound exceeded")
    section_table = optional + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        start = section_table + (index * 40)
        if start + 40 > len(data):
            fail("candidate has a truncated section table")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, start + 8
        )
        sections.append((virtual_address, virtual_size, raw_ptr, raw_size))
    return {
        "machine": machine,
        "magic": magic,
        "cert_offset": cert_offset,
        "cert_size": cert_size,
        "resource_rva": resource_rva,
        "resource_size": resource_size,
        "sections": sections,
    }


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _read_utf16z(data: bytes, offset: int, limit: int) -> tuple[str, int]:
    chars: list[str] = []
    cursor = offset
    while cursor + 1 < limit:
        code = data[cursor] | (data[cursor + 1] << 8)
        cursor += 2
        if code == 0:
            return "".join(chars), cursor
        if code < 32 or 0xD800 <= code <= 0xDFFF:
            fail("candidate VERSIONINFO string is malformed")
        chars.append(chr(code))
        if len(chars) > 256:
            fail("candidate VERSIONINFO string is malformed")
    fail("candidate VERSIONINFO string is truncated")
    raise AssertionError("unreachable")


def _parse_version_block(data: bytes, offset: int, limit: int) -> dict[str, Any]:
    if offset + 6 > limit:
        fail("candidate VERSIONINFO resource is truncated")
    length, value_length, wtype = struct.unpack_from("<HHH", data, offset)
    if length < 6 or offset + length > limit:
        fail("candidate VERSIONINFO resource is truncated")
    end = offset + length
    key, cursor = _read_utf16z(data, offset + 6, end)
    cursor = _align4(cursor)
    value = b""
    if value_length:
        if wtype == 0:
            value_bytes = value_length
        else:
            value_bytes = value_length * 2
        if cursor + value_bytes > end:
            fail("candidate VERSIONINFO resource is truncated")
        value = data[cursor : cursor + value_bytes]
        cursor = _align4(cursor + value_bytes)
    children: list[dict[str, Any]] = []
    while cursor + 6 <= end:
        if data[cursor : cursor + 6] == b"\x00\x00\x00\x00\x00\x00":
            break
        child_length = struct.unpack_from("<H", data, cursor)[0]
        if child_length < 6:
            break
        children.append(_parse_version_block(data, cursor, end))
        cursor = _align4(cursor + child_length)
    return {"key": key, "type": wtype, "value": value, "children": children}


def _collect_version_strings(block: dict[str, Any], found: dict[str, str]) -> None:
    required = {"CompanyName", "FileDescription", "ProductName", "ProductVersion"}
    optional = {"OriginalFileName", "InternalName"}
    if block["key"] in required or block["key"] in optional:
        raw = block["value"]
        if block["key"] in required and (len(raw) < 2 or len(raw) % 2):
            fail(f"candidate VERSIONINFO {block['key']} is empty")
        if raw:
            text, _ = _read_utf16z(raw + b"\x00\x00", 0, len(raw) + 2)
            text = text.rstrip()
            if block["key"] in required and not text:
                fail(f"candidate VERSIONINFO {block['key']} is empty")
            if text:
                if block["key"] in found and found[block["key"]] != text:
                    fail(f"candidate VERSIONINFO {block['key']} is ambiguous")
                found[block["key"]] = text
    for child in block["children"]:
        _collect_version_strings(child, found)


def _resource_entries(data: bytes, offset: int, limit: int) -> list[tuple[int, bool, int]]:
    if offset + 16 > limit:
        fail("candidate VERSIONINFO resource directory is truncated")
    named, ids = struct.unpack_from("<HH", data, offset + 12)
    total = named + ids
    if total < 1 or total > 64 or offset + 16 + (total * 8) > limit:
        fail("candidate VERSIONINFO resource directory is truncated")
    entries: list[tuple[int, bool, int]] = []
    cursor = offset + 16
    for _ in range(total):
        name, data_offset = struct.unpack_from("<II", data, cursor)
        cursor += 8
        entries.append((name & 0x7FFFFFFF, bool(data_offset & 0x80000000), data_offset & 0x7FFFFFFF))
    return entries


def version_strings(data: bytes) -> dict[str, str]:
    parsed = parse_pe(data)
    if parsed["resource_rva"] == 0 or parsed["resource_size"] < 16:
        fail("candidate has no VERSIONINFO resource")
    root = rva_to_offset(data, parsed["resource_rva"], parsed["sections"])
    limit = min(len(data), root + parsed["resource_size"])
    type_entries = _resource_entries(data, root, limit)
    version_dir = None
    for name, is_dir, offset in type_entries:
        if name == RT_VERSION and is_dir:
            version_dir = root + offset
            break
    if version_dir is None:
        fail("candidate has no VERSIONINFO resource")
    name_entries = _resource_entries(data, version_dir, limit)
    language_dir = None
    for _name, is_dir, offset in name_entries:
        if is_dir:
            language_dir = root + offset
            break
    if language_dir is None:
        fail("candidate has no VERSIONINFO resource")
    language_entries = _resource_entries(data, language_dir, limit)
    data_entry = None
    for _name, is_dir, offset in language_entries:
        if not is_dir:
            data_entry = root + offset
            break
    if data_entry is None or data_entry + 16 > limit:
        fail("candidate VERSIONINFO resource is truncated")
    rva, size = struct.unpack_from("<II", data, data_entry)
    file_offset = rva_to_offset(data, rva, parsed["sections"])
    if size < 92 or file_offset + size > len(data):
        fail("candidate VERSIONINFO resource is truncated")
    block = _parse_version_block(data, file_offset, file_offset + size)
    if block["key"] != "VS_VERSION_INFO":
        fail("candidate has no VERSIONINFO resource")
    if len(block["value"]) < 52 or struct.unpack_from("<I", block["value"], 0)[0] != 0xFEEF04BD:
        fail("candidate VERSIONINFO resource is truncated")
    found: dict[str, str] = {}
    _collect_version_strings(block, found)
    for name in ("CompanyName", "FileDescription", "ProductName", "ProductVersion"):
        if name not in found:
            fail(f"candidate VERSIONINFO is missing {name}")
    return found


def authenticode_leaf(data: bytes) -> dict[str, str]:
    parsed = parse_pe(data)
    blob = data[parsed["cert_offset"] : parsed["cert_offset"] + parsed["cert_size"]]
    length, revision, cert_type = struct.unpack_from("<IHH", blob, 0)
    if length < 8 or length > parsed["cert_size"] or revision != 0x0200 or cert_type != 0x0002:
        fail("candidate has an invalid WIN_CERTIFICATE record")
    pkcs7 = blob[8:length]
    if len(pkcs7) > MAX_PKCS7:
        fail("Authenticode PKCS#7 size bound exceeded")
    signer = parse_pkcs7_signer(pkcs7)
    matches = []
    for der in signer["certificates"]:
        issuer_der, serial = _certificate_issuer_serial(der)
        if serial == signer["serial"] and issuer_der == signer["issuer_der"]:
            matches.append(der)
    if len(matches) != 1:
        fail("Authenticode SignerInfo does not resolve to one signing certificate")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise Refused("Authenticode leaf parsing requires the cryptography package") from exc
    leaf = x509.load_der_x509_certificate(matches[0])
    names = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    orgs = leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if not names or not orgs:
        fail("Authenticode publisher mismatch: expected one Pyrsys B.V. leaf")
    if names[0].value != "Pyrsys B.V." or orgs[0].value != "Pyrsys B.V.":
        fail("Authenticode publisher mismatch: expected one Pyrsys B.V. leaf")
    return {
        "publisher_name": "Pyrsys B.V.",
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "serial": format(leaf.serial_number, "x"),
        "sha256": leaf.fingerprint(hashes.SHA256()).hex(),
        "raw": leaf.public_bytes(Encoding.DER),
    }


def windows_known_folder(csidl: int) -> str:
    import ctypes

    buffer = ctypes.create_unicode_buffer(260)
    result = int(ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buffer))
    if result != 0 or not buffer.value:
        fail("untrusted installation root")
    return buffer.value


def windows_program_files() -> str:
    return windows_known_folder(0x0026)


def verify_authenticode_chain(path: Path) -> None:
    snapshot = bind_regular_snapshot(path, "Authenticode candidate", maximum=MAX_INSTALLER)
    try:
        verify_authenticode_chain_bound(snapshot)
    finally:
        snapshot.close()


def verify_authenticode_chain_bound(snapshot: BoundSnapshot) -> None:
    if os.name != "nt":
        fail("Authenticode chain verification requires Windows")
    snapshot.assert_unchanged("Authenticode candidate")
    import ctypes

    try:
        import msvcrt
    except ImportError as exc:
        raise Refused("Authenticode chain verification requires Windows") from exc

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pcwszFilePath", ctypes.c_wchar_p),
            ("hFile", ctypes.c_void_p),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.c_ulong),
            ("fdwRevocationChecks", ctypes.c_ulong),
            ("dwUnionChoice", ctypes.c_ulong),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", ctypes.c_ulong),
            ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", ctypes.c_wchar_p),
            ("dwProvFlags", ctypes.c_ulong),
            ("dwUIContext", ctypes.c_ulong),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    action = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    handle = msvcrt.get_osfhandle(snapshot.fd)
    file_info = WINTRUST_FILE_INFO(
        ctypes.sizeof(WINTRUST_FILE_INFO), str(snapshot.path), handle, None
    )
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = 2
    data.fdwRevocationChecks = 0
    data.dwUnionChoice = 1
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 1
    data.dwProvFlags = 0x1000 | 0x2000
    verify = ctypes.windll.wintrust.WinVerifyTrust
    verify.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(GUID),
        ctypes.POINTER(WINTRUST_DATA),
    ]
    verify.restype = ctypes.c_long
    status = int(verify(None, ctypes.byref(action), ctypes.byref(data)))
    try:
        if status != 0:
            fail(
                "Authenticode chain verification failed with "
                f"0x{status & 0xFFFFFFFF:08x}"
            )
        snapshot.assert_unchanged("Authenticode candidate")
        bind_windows_signer(snapshot)
    finally:
        data.dwStateAction = 2
        verify(None, ctypes.byref(action), ctypes.byref(data))


def bind_windows_signer(snapshot: BoundSnapshot) -> None:
    snapshot.assert_unchanged("Authenticode candidate")
    leaf = authenticode_leaf(snapshot.data)
    assert_publisher(leaf, OFFICIAL_PUBLISHER)
    parsed = parse_pkcs7_signer(authenticode_pkcs7_bytes(snapshot.data))
    import ctypes

    class CRYPT_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.c_void_p)]

    class CMSG_SIGNER_INFO_HEAD(ctypes.Structure):
        _fields_ = [
            ("dwVersion", ctypes.c_uint32),
            ("Issuer", CRYPT_BLOB),
            ("SerialNumber", CRYPT_BLOB),
        ]

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    crypt32 = ctypes.windll.crypt32
    encoding = ctypes.c_uint32()
    content_type = ctypes.c_uint32()
    format_type = ctypes.c_uint32()
    store = ctypes.c_void_p()
    message = ctypes.c_void_p()
    context = ctypes.c_void_p()
    pkcs7 = authenticode_pkcs7_bytes(snapshot.data)
    array = (ctypes.c_ubyte * len(pkcs7)).from_buffer_copy(pkcs7)
    blob = DATA_BLOB(len(pkcs7), ctypes.cast(array, ctypes.POINTER(ctypes.c_ubyte)))
    CERT_QUERY_OBJECT_BLOB = 2
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = 1 << 8
    CERT_QUERY_FORMAT_FLAG_BINARY = 2
    query = crypt32.CryptQueryObject
    query.argtypes = [
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    query.restype = ctypes.c_int
    if not query(
        CERT_QUERY_OBJECT_BLOB,
        ctypes.byref(blob),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        ctypes.byref(encoding),
        ctypes.byref(content_type),
        ctypes.byref(format_type),
        ctypes.byref(store),
        ctypes.byref(message),
        ctypes.byref(context),
    ):
        fail("Authenticode Windows signer query failed")
    try:
        size = ctypes.c_uint32(0)
        CMSG_SIGNER_INFO_PARAM = 6
        get_param = crypt32.CryptMsgGetParam
        get_param.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        get_param.restype = ctypes.c_int
        if not get_param(message, CMSG_SIGNER_INFO_PARAM, 0, None, ctypes.byref(size)):
            fail("Authenticode Windows signer query failed")
        if size.value < ctypes.sizeof(CMSG_SIGNER_INFO_HEAD) or size.value > MAX_PKCS7:
            fail("Authenticode PKCS#7 size bound exceeded")
        buffer = (ctypes.c_ubyte * size.value)()
        if not get_param(message, CMSG_SIGNER_INFO_PARAM, 0, buffer, ctypes.byref(size)):
            fail("Authenticode Windows signer query failed")
        head = CMSG_SIGNER_INFO_HEAD.from_buffer(buffer)
        if head.Issuer.cbData < 2 or head.Issuer.cbData > MAX_PKCS7:
            fail("Authenticode Windows signer query failed")
        if head.SerialNumber.cbData < 1 or head.SerialNumber.cbData > 21:
            fail("Authenticode Windows signer query failed")
        issuer = ctypes.string_at(head.Issuer.pbData, head.Issuer.cbData)
        serial_bytes = ctypes.string_at(head.SerialNumber.pbData, head.SerialNumber.cbData)
        serial = int.from_bytes(serial_bytes, "little")
        if issuer != parsed["issuer_der"] or serial != parsed["serial"]:
            fail("Authenticode Windows signer does not match SignerInfo")
        if leaf["sha256"] != OFFICIAL_PUBLISHER["authenticode_leaf_sha256"]:
            fail("Authenticode publisher mismatch")
        if leaf["serial"] != OFFICIAL_PUBLISHER["authenticode_leaf_serial_hex"]:
            fail("Authenticode publisher mismatch")
    finally:
        if message:
            crypt32.CryptMsgClose(message)
        if store:
            crypt32.CertCloseStore(store, 0)


def authenticode_pkcs7_bytes(data: bytes) -> bytes:
    parsed = parse_pe(data)
    blob = data[parsed["cert_offset"] : parsed["cert_offset"] + parsed["cert_size"]]
    length = struct.unpack_from("<I", blob, 0)[0]
    pkcs7 = blob[8:length]
    tag, _content, end = _der_read(pkcs7, 0, expected=0x30)
    del tag
    return pkcs7[:end]


def _https_url(mapping: Mapping[str, Any], key: str) -> str:
    value = _text(mapping, key)
    if not value.startswith("https://"):
        fail(f"official URL must be https: {key}")
    return value


def _anchor_key(name: str) -> dict[str, Any]:
    if name not in OFFICIAL_ISSIG_KEYS:
        fail(f"ISSig trust-root key is unknown: {name}")
    return dict(OFFICIAL_ISSIG_KEYS[name])


def _load_key_record(record: Mapping[str, Any], name: str) -> dict[str, Any]:
    _require_keys(record, KEY_RECORD_KEYS, f"issig_keys.{name}")
    parsed = {
        "filename": _text(record, "filename"),
        "key_id": _hex64(record, "key_id"),
        "public_x": _hex64(record, "public_x"),
        "public_y": _hex64(record, "public_y"),
        "sha256": _hex64(record, "sha256"),
        "size": _int(record, "size", minimum=32, maximum=4096),
    }
    anchor = _anchor_key(name)
    if parsed != anchor:
        fail(f"ISSig trust-root key does not match immutable code anchor: {name}")
    material = bytes.fromhex(parsed["public_x"] + parsed["public_y"])
    if hashlib.sha256(material).hexdigest() != parsed["key_id"]:
        fail("ISSig public key id does not match public-x||public-y")
    if parsed["filename"] != f"{name}.ispublickey":
        fail(f"ISSig key filename mismatch: {name}")
    return parsed


def _load_installer(record: Mapping[str, Any], name: str, keys: Mapping[str, Any]) -> dict[str, Any]:
    _require_keys(record, INSTALLER_KEYS, f"installers.{name}")
    parsed = {
        "status": _text(record, "status"),
        "filename": _text(record, "filename"),
        "edition": _text(record, "edition"),
        "pe_machine": _text(record, "pe_machine"),
        "recommended_compiler_host": _bool(record, "recommended_compiler_host"),
        "size": _int(record, "size", minimum=1, maximum=MAX_INSTALLER),
        "sha256": _hex64(record, "sha256"),
        "product_name": _text(record, "product_name"),
        "product_version_string": _text(record, "product_version_string"),
        "company_name": _text(record, "company_name"),
        "file_description": _text(record, "file_description"),
        "download_url": _https_url(record, "download_url"),
        "issig_url": _https_url(record, "issig_url"),
        "issig_sha256": _hex64(record, "issig_sha256"),
        "issig_size": _int(record, "issig_size", minimum=32, maximum=MAX_ISSIG),
        "issig_key": _text(record, "issig_key"),
        "issig_file_tag": _text(record, "issig_file_tag", allow_empty=True),
        "issig_sig_r": _hex64(record, "issig_sig_r"),
        "issig_sig_s": _hex64(record, "issig_sig_s"),
    }
    if parsed["status"] != "pinned":
        fail(f"installer status must be pinned: {name}")
    if parsed["pe_machine"] not in PE_MACHINE:
        fail(f"installer architecture is unsupported: {name}")
    if parsed["issig_key"] not in OFFICIAL_ISSIG_KEYS:
        fail(f"installer ISSig key is unknown: {name}")
    if not parsed["filename"].startswith("innosetup-7.1.0-") or not parsed["filename"].endswith(".exe"):
        fail(f"installer filename does not match 7.1.0: {name}")
    verify_issig_identity(
        filename=parsed["filename"],
        size=parsed["size"],
        file_hash=parsed["sha256"],
        tag=parsed["issig_file_tag"],
        key=keys[parsed["issig_key"]],
        sig_r=parsed["issig_sig_r"],
        sig_s=parsed["issig_sig_s"],
    )
    return parsed


def _load_compiler(record: Mapping[str, Any], name: str) -> dict[str, Any]:
    required = COMPILER_SHARED_KEYS + (("native_arm64_compiler",) if name == "windows_arm64" else ())
    _require_keys(record, required, f"compilers.{name}")
    parsed: dict[str, Any] = {
        "status": _text(record, "status"),
        "filename": _text(record, "filename"),
        "pe_machine": _text(record, "pe_machine"),
        "output_architectures": _string_list(record, "output_architectures"),
        "trusted_root_leaf": _text(record, "trusted_root_leaf"),
        "trusted_root_kind": _text(record, "trusted_root_kind"),
        "publisher_name": _text(record, "publisher_name"),
        "expected_version": _text(record, "expected_version"),
        "owner_action": _text(record, "owner_action"),
    }
    if name == "windows_arm64":
        parsed["native_arm64_compiler"] = _text(record, "native_arm64_compiler")
        if parsed["native_arm64_compiler"] != "not_published":
            fail("native ARM64 ISCC must remain not_published for 7.1.0")
    if parsed["filename"] != "ISCC.exe":
        fail("compiler filename must be ISCC.exe")
    if parsed["pe_machine"] != "x64":
        fail("7.1.0 compiler identity for x64 and arm64-capable outputs must be x64 ISCC")
    if parsed["trusted_root_leaf"] != "Inno Setup 7":
        fail("compiler trusted root leaf mismatch")
    if parsed["trusted_root_kind"] != "program_files":
        fail("compiler trusted root kind mismatch")
    if parsed["publisher_name"] != "Pyrsys B.V.":
        fail("compiler publisher mismatch")
    if parsed["expected_version"] != VERSION:
        fail("compiler version mismatch")
    expected_output = "x64" if name == "windows_x64" else "arm64"
    if parsed["output_architectures"] != (expected_output,):
        fail(f"compiler output architecture mismatch: {name}")
    if parsed["status"] == "unmeasured":
        for field in COMPILER_PIN_FIELDS:
            _null(record, field)
            parsed[field] = None
    elif parsed["status"] == "pinned":
        parsed["sha256"] = _hex64(record, "sha256")
        parsed["size"] = _int(record, "size", minimum=1, maximum=MAX_COMPILER)
        parsed["install_tree_sha256"] = _hex64(record, "install_tree_sha256")
        parsed["product_version_string"] = _text(record, "product_version_string")
        if parsed["sha256"] == parsed["install_tree_sha256"]:
            fail("compiler file and install-tree hashes must be independently derived")
    else:
        fail(f"compiler status is unsupported: {name}")
    return parsed


def load_pin(path: Path | None = None) -> dict[str, Any]:
    pin_path = path or DEFAULT_PIN
    snapshot = bind_regular_snapshot(pin_path, "Inno toolchain pin", maximum=MAX_PIN)
    try:
        raw = snapshot.data
        snapshot.assert_unchanged("Inno toolchain pin")
    finally:
        snapshot.close()
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        raise Refused("Inno toolchain pin is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise Refused("Inno toolchain pin is not strict JSON") from exc
    document = _mapping(document, "pin")
    _require_keys(document, TOP_KEYS, "pin")
    if type(document["schema_version"]) is not int or isinstance(document["schema_version"], bool):
        fail("type coercion refused: schema_version must be an integer")
    if document["schema_version"] != SCHEMA_VERSION:
        fail("Inno toolchain pin schema_version mismatch")
    if _text(document, "contract") != CONTRACT:
        fail("Inno toolchain pin contract mismatch")
    if _text(document, "product") != "Inno Setup":
        fail("product mismatch")
    if _text(document, "vendor") != "JRSoftware":
        fail("vendor mismatch")
    if _text(document, "version") != VERSION:
        fail("version mismatch")
    if _text(document, "channel") != "latest-stable":
        fail("channel mismatch")
    document_status = _text(document, "status")
    pin_retrieved = _utc(document, "retrieved_utc")
    sources = _mapping(document["official_sources"], "official_sources")
    _require_keys(sources, SOURCE_NAMES, "official_sources")
    parsed_sources = {}
    retrieved_times = [pin_retrieved]
    for name in SOURCE_NAMES:
        item = _mapping(sources[name], f"official_sources.{name}")
        _require_keys(item, SOURCE_KEYS, f"official_sources.{name}")
        source_retrieved = _utc(item, "retrieved_utc")
        if source_retrieved > pin_retrieved:
            fail(f"retrieved timestamp is after the reviewed issuance bound: official_sources.{name}")
        retrieved_times.append(source_retrieved)
        parsed_sources[name] = {
            "url": _https_url(item, "url"),
            "retrieved_utc": item["retrieved_utc"],
            "role": _text(item, "role"),
        }
    newest = max(retrieved_times)
    oldest = min(retrieved_times)
    if newest - oldest > REVIEWED_FRESHNESS:
        fail("retrieved timestamps exceed the reviewed freshness bound")
    methods = _mapping(document["verification_methods"], "verification_methods")
    _require_keys(methods, METHOD_KEYS, "verification_methods")
    authenticode = _mapping(methods["authenticode"], "verification_methods.authenticode")
    _require_keys(authenticode, AUTH_METHOD_KEYS, "verification_methods.authenticode")
    if not _bool(authenticode, "required"):
        fail("Authenticode verification must be required")
    if _text(authenticode, "publisher_name") != "Pyrsys B.V.":
        fail("Authenticode publisher mismatch")
    if _text(authenticode, "signer_binding") != "pkcs7_signerinfo_issuer_serial":
        fail("Authenticode signer binding mismatch")
    if _text(authenticode, "windows_api") != "WinVerifyTrust":
        fail("Authenticode Windows API mismatch")
    _https_url(authenticode, "source_url")
    issig_method = _mapping(methods["issig_ecdsa_p256"], "verification_methods.issig_ecdsa_p256")
    _require_keys(issig_method, ISSIG_METHOD_KEYS, "verification_methods.issig_ecdsa_p256")
    if not _bool(issig_method, "required"):
        fail("ISSig verification must be required")
    if _bool(issig_method, "execute_issigtool"):
        fail("refusing to execute ISSigTool.exe")
    if _text(issig_method, "trust_anchor") != "immutable_code_constants":
        fail("ISSig trust-root must be the immutable code anchor")
    github_method = _mapping(
        methods["github_release_attestation"], "verification_methods.github_release_attestation"
    )
    _require_keys(github_method, GITHUB_METHOD_KEYS, "verification_methods.github_release_attestation")
    if _bool(github_method, "required"):
        fail("GitHub attestation must not be a custody gate")
    publisher = _mapping(document["publisher"], "publisher")
    _require_keys(publisher, PUBLISHER_KEYS, "publisher")
    parsed_publisher = {
        "authenticode_publisher_name": _text(publisher, "authenticode_publisher_name"),
        "authenticode_subject_rfc4514": _text(publisher, "authenticode_subject_rfc4514"),
        "authenticode_issuer_rfc4514": _text(publisher, "authenticode_issuer_rfc4514"),
        "authenticode_leaf_serial_hex": _text(publisher, "authenticode_leaf_serial_hex"),
        "authenticode_leaf_sha256": _hex64(publisher, "authenticode_leaf_sha256"),
    }
    if parsed_publisher != OFFICIAL_PUBLISHER:
        fail("Authenticode publisher mismatch")
    if not HEX_SERIAL.fullmatch(parsed_publisher["authenticode_leaf_serial_hex"]):
        fail("Authenticode leaf serial is malformed")
    key_root = _mapping(document["issig_keys"], "issig_keys")
    _require_keys(key_root, ("def02", "def01"), "issig_keys")
    keys = {
        "def02": _load_key_record(_mapping(key_root["def02"], "issig_keys.def02"), "def02"),
        "def01": _load_key_record(_mapping(key_root["def01"], "issig_keys.def01"), "def01"),
    }
    if keys["def02"] != OFFICIAL_ISSIG_KEYS["def02"] or keys["def01"] != OFFICIAL_ISSIG_KEYS["def01"]:
        fail("ISSig trust-root key does not match immutable code anchor")
    if _text(issig_method, "installer_key") != "def02" or _text(issig_method, "tool_key") != "def01":
        fail("ISSig key assignment mismatch")
    installers_root = _mapping(document["installers"], "installers")
    _require_keys(installers_root, ("windows_x64", "windows_x86"), "installers")
    installers = {
        "windows_x64": _load_installer(
            _mapping(installers_root["windows_x64"], "installers.windows_x64"),
            "windows_x64",
            keys,
        ),
        "windows_x86": _load_installer(
            _mapping(installers_root["windows_x86"], "installers.windows_x86"),
            "windows_x86",
            keys,
        ),
    }
    if not installers["windows_x64"]["recommended_compiler_host"]:
        fail("64-bit Inno Setup 7 is the required compiler host")
    if installers["windows_x86"]["recommended_compiler_host"]:
        fail("32-bit Inno Setup 7 is not the required compiler host")
    compilers_root = _mapping(document["compilers"], "compilers")
    _require_keys(compilers_root, ("windows_x64", "windows_arm64"), "compilers")
    compilers = {
        "windows_x64": _load_compiler(
            _mapping(compilers_root["windows_x64"], "compilers.windows_x64"),
            "windows_x64",
        ),
        "windows_arm64": _load_compiler(
            _mapping(compilers_root["windows_arm64"], "compilers.windows_arm64"),
            "windows_arm64",
        ),
    }
    tool = _mapping(document["verification_tool"], "verification_tool")
    _require_keys(tool, TOOL_KEYS, "verification_tool")
    parsed_tool = {
        "status": _text(tool, "status"),
        "filename": _text(tool, "filename"),
        "execute": _bool(tool, "execute"),
        "pe_machine": _text(tool, "pe_machine"),
        "size": _int(tool, "size", minimum=1, maximum=MAX_COMPILER),
        "sha256": _hex64(tool, "sha256"),
        "download_url": _https_url(tool, "download_url"),
        "issig_url": _https_url(tool, "issig_url"),
        "issig_sha256": _hex64(tool, "issig_sha256"),
        "issig_size": _int(tool, "issig_size", minimum=32, maximum=MAX_ISSIG),
        "issig_key": _text(tool, "issig_key"),
        "issig_file_tag": _text(tool, "issig_file_tag", allow_empty=True),
        "issig_sig_r": _hex64(tool, "issig_sig_r"),
        "issig_sig_s": _hex64(tool, "issig_sig_s"),
        "note": _text(tool, "note"),
    }
    if parsed_tool["status"] != "pinned" or parsed_tool["filename"] != "ISSigTool.exe":
        fail("verification tool identity mismatch")
    if parsed_tool["execute"]:
        fail("refusing to execute ISSigTool.exe")
    if parsed_tool["issig_key"] != "def01":
        fail("ISSigTool must be bound to def01")
    verify_issig_identity(
        filename=parsed_tool["filename"],
        size=parsed_tool["size"],
        file_hash=parsed_tool["sha256"],
        tag=parsed_tool["issig_file_tag"],
        key=keys["def01"],
        sig_r=parsed_tool["issig_sig_r"],
        sig_s=parsed_tool["issig_sig_s"],
    )
    archive = _mapping(document["compiler_archive"], "compiler_archive")
    _require_keys(archive, ARCHIVE_KEYS, "compiler_archive")
    if _text(archive, "status") != "not_published":
        fail("compiler archive must remain not_published until JRSoftware publishes one")
    _null(archive, "filename")
    _null(archive, "sha256")
    _null(archive, "size")
    _text(archive, "owner_action")
    compilers_pinned = all(item["status"] == "pinned" for item in compilers.values())
    expected_status = "pinned" if compilers_pinned else "unmeasured"
    if document_status != expected_status:
        fail(
            "pin status must be pinned when both compilers carry complete pins, "
            f"otherwise unmeasured: expected {expected_status}"
        )
    return {
        "path": pin_path,
        "publisher": parsed_publisher,
        "keys": keys,
        "installers": installers,
        "compilers": compilers,
        "verification_tool": parsed_tool,
        "sources": parsed_sources,
        "status": expected_status,
        "compilers_pinned": compilers_pinned,
    }


def refuse_execution(path: Path) -> None:
    name = path.name
    if SETUP_NAME.fullmatch(name) or name.lower() in {"setup.exe", "issigtool.exe"}:
        return
    if name.lower() == "iscc.exe":
        return


def refuse_upload_and_execution_request(argv: list[str]) -> None:
    joined = " ".join(argv).lower()
    for token in (
        "upload",
        "scp",
        "sftp",
        "curl -t",
        "invoke-webrequest",
        "github.actions",
        "start-process",
        "winget install",
        "/silent",
        "/verysilent",
    ):
        if token in joined:
            fail("refusing to execute a setup candidate or upload artifact")


def assert_publisher(leaf: Mapping[str, str], publisher: Mapping[str, str]) -> None:
    if leaf["publisher_name"] != publisher["authenticode_publisher_name"]:
        fail("Authenticode publisher mismatch")
    if leaf["subject"] != publisher["authenticode_subject_rfc4514"]:
        fail("Authenticode publisher mismatch")
    if leaf["issuer"] != publisher["authenticode_issuer_rfc4514"]:
        fail("Authenticode chain publisher mismatch")
    if leaf["serial"] != publisher["authenticode_leaf_serial_hex"]:
        fail("Authenticode publisher mismatch")
    if leaf["sha256"] != publisher["authenticode_leaf_sha256"]:
        fail("Authenticode publisher mismatch")


def assert_pe_machine(data: bytes, expected: str) -> None:
    parsed = parse_pe(data)
    if parsed["machine"] != PE_MACHINE[expected] or parsed["magic"] != PE_MAGIC[expected]:
        fail(f"architecture mismatch: expected {expected}")


def _tree_feed(digest: Any, *parts: object) -> None:
    for part in parts:
        encoded = str(part).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)


def _is_per_install_file(relative: str) -> bool:
    return "/" not in relative and PER_INSTALL_TREE_FILE.fullmatch(relative) is not None


def _tree_mode(info: os.stat_result) -> int:
    """Permission bits fed into the install-tree digest.

    On Windows, lstat() invents execute bits for .exe, .bat, .cmd and .com
    files; the PowerShell verifier derives file modes from the read-only
    attribute alone (0o666 or 0o444), so regular files drop the execute bits
    there and both verifiers compute the same digest.
    """
    mode = stat.S_IMODE(info.st_mode)
    if os.name == "nt" and not stat.S_ISDIR(info.st_mode):
        mode &= ~0o111
    return mode


def _enumerate_install_tree_paths(root: Path) -> tuple[set[str], set[Path]]:
    files: set[str] = set()
    directories: set[Path] = {root}

    def walk(directory: Path) -> None:
        with os.scandir(directory) as scan:
            entries = sorted(scan, key=lambda item: os.fsencode(item.name))
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            info = _identity_stat(path, "ISCC install tree")
            _refuse_reparse(info, path)
            if stat.S_ISDIR(info.st_mode):
                directories.add(path)
                walk(path)
                continue
            if not stat.S_ISREG(info.st_mode):
                fail(f"ISCC install tree contains a non-regular file: {relative}")
            if _is_per_install_file(relative):
                continue
            files.add(relative)

    walk(root)
    return files, directories


def snapshot_install_tree(root: Path) -> BoundTree:
    walk_path_components(root, "ISCC install tree")
    info = _identity_stat(root, "ISCC install tree")
    _refuse_reparse(info, root)
    if not stat.S_ISDIR(info.st_mode):
        fail(f"ISCC install tree must be a directory: {root}")
    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    # os.open() refuses directories on Windows (the CRT returns EACCES), so
    # there the walk is stat-based: every entry is lstat()ed by path, never
    # through DirEntry.stat() (which reports st_ino, st_dev and st_nlink as 0
    # on Windows), and directory identity is re-checked by path.
    use_dir_fd = _supports_dir_fd()
    root_fd = _open_nofollow(root, dir_flags, "ISCC install tree") if use_dir_fd else -1
    files: list[tuple[str, BoundSnapshot]] = []
    directories: list[tuple[Path, tuple[int, ...], int]] = [
        (root, _pathname_identity(info), root_fd)
    ]
    digest = hashlib.sha256()
    file_count = 0
    total = 0
    try:
        def walk(directory: Path, dir_fd: int) -> None:
            nonlocal file_count, total
            with os.scandir(directory) as scan:
                entries = sorted(scan, key=lambda item: os.fsencode(item.name))
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                entry_info = _identity_stat(path, "ISCC install tree")
                _refuse_reparse(entry_info, path)
                mode = _tree_mode(entry_info)
                if stat.S_ISDIR(entry_info.st_mode):
                    _tree_feed(digest, "D", relative, "dir", mode)
                    if use_dir_fd:
                        child_fd = _open_named(
                            dir_fd, entry.name, dir_flags, "ISCC install tree", path
                        )
                    else:
                        child_fd = -1
                    directories.append((path, _pathname_identity(entry_info), child_fd))
                    walk(path, child_fd)
                    continue
                if not stat.S_ISREG(entry_info.st_mode):
                    fail(f"ISCC install tree contains a non-regular file: {relative}")
                if _is_per_install_file(relative):
                    continue
                if entry_info.st_nlink != 1:
                    fail(f"hardlink refused: ISCC install tree file {relative}")
                file_count += 1
                total += entry_info.st_size
                if file_count > MAX_TREE_FILES or total > MAX_TREE_BYTES:
                    fail("ISCC install tree size bound exceeded")
                snapshot = bind_regular_snapshot(
                    path, f"ISCC install tree file {relative}", maximum=MAX_COMPILER
                )
                files.append((relative, snapshot))
                _tree_feed(digest, "F", relative, "reg", mode, len(snapshot.data), snapshot.digest)

        walk(root, root_fd)
        if file_count < 1:
            fail("ISCC install tree contains no regular files")
        tree = BoundTree(root, _pathname_identity(info), files, directories, digest.hexdigest())
        files = []
        directories = []
        try:
            tree.assert_unchanged("ISCC install tree")
            return tree
        except Exception:
            tree.close()
            raise
    except Exception:
        for _relative, snapshot in files:
            snapshot.close()
        for _path, _identity_value, handle in directories:
            if handle >= 0:
                try:
                    os.close(handle)
                except OSError:
                    pass
        raise


def install_tree_digest(root: Path) -> str:
    tree = snapshot_install_tree(root)
    try:
        tree.assert_unchanged("ISCC install tree")
        return tree.digest
    finally:
        tree.close()


def _verify_issig_sidecar(
    candidate: Path, snapshot: BoundSnapshot, record: Mapping[str, Any], keys: Mapping[str, Any]
) -> BoundSnapshot:
    sidecar = candidate.with_name(candidate.name + ".issig")
    try:
        sidecar.lstat()
    except FileNotFoundError:
        fail("issig sidecar is required")
    bound = bind_regular_snapshot(sidecar, "Inno Setup installer issig", maximum=MAX_ISSIG)
    try:
        if bound.digest != record["issig_sha256"] or len(bound.data) != record["issig_size"]:
            fail("installer issig sidecar SHA-256 mismatch")
        parsed = parse_issig_v2(bound.data)
        if parsed["file-name"] != record["filename"]:
            fail("installer issig sidecar filename mismatch")
        if parsed["file-size"] != record["size"] or parsed["file-hash"] != snapshot.digest:
            fail("installer issig sidecar identity mismatch")
        if parsed["file-tag"] != record["issig_file_tag"]:
            fail("installer issig sidecar identity mismatch")
        if parsed["key-id"] != keys[record["issig_key"]]["key_id"]:
            fail("installer issig sidecar key mismatch")
        if parsed["sig-r"] != record["issig_sig_r"] or parsed["sig-s"] != record["issig_sig_s"]:
            fail("installer issig sidecar signature mismatch")
        verify_issig_identity(
            filename=record["filename"],
            size=record["size"],
            file_hash=snapshot.digest,
            tag=record["issig_file_tag"],
            key=keys[record["issig_key"]],
            sig_r=parsed["sig-r"],
            sig_s=parsed["sig-s"],
        )
        bound.assert_unchanged("Inno Setup installer issig")
        return bound
    except Exception:
        bound.close()
        raise


def verify_installer_identity(
    path: Path, architecture: str, pin_path: Path | None = None
) -> dict[str, Any]:
    pin, snapshot, sidecar, result = _verify_installer_bound(path, architecture, pin_path)
    del pin
    snapshot.close()
    sidecar.close()
    result.pop("path", None)
    return result


def _verify_installer_bound(
    path: Path, architecture: str, pin_path: Path | None
) -> tuple[dict[str, Any], BoundSnapshot, BoundSnapshot, dict[str, Any]]:
    pin = load_pin(pin_path)
    key = f"windows_{architecture}"
    if key not in pin["installers"]:
        fail("installer architecture is unsupported")
    record = pin["installers"][key]
    candidate = Path(path)
    refuse_execution(candidate)
    if candidate.name != record["filename"]:
        fail("installer filename mismatch")
    snapshot = bind_regular_snapshot(candidate, "Inno Setup installer", maximum=MAX_INSTALLER)
    sidecar: BoundSnapshot | None = None
    try:
        if len(snapshot.data) != record["size"] or snapshot.digest != record["sha256"]:
            fail("installer SHA-256 mismatch")
        sidecar = _verify_issig_sidecar(candidate, snapshot, record, pin["keys"])
        assert_pe_machine(snapshot.data, record["pe_machine"])
        versions = version_strings(snapshot.data)
        if versions["ProductName"] != record["product_name"]:
            fail("version mismatch")
        if versions["ProductVersion"] != record["product_version_string"]:
            fail("version mismatch")
        if versions["CompanyName"] != record["company_name"]:
            fail("version mismatch")
        if versions["FileDescription"] != record["file_description"]:
            fail("version mismatch")
        leaf = authenticode_leaf(snapshot.data)
        assert_publisher(leaf, pin["publisher"])
        snapshot.assert_unchanged("Inno Setup installer")
        sidecar.assert_unchanged("Inno Setup installer issig")
        result = {
            "architecture": architecture,
            "filename": record["filename"],
            "sha256": snapshot.digest,
            "publisher": leaf["publisher_name"],
            "path": candidate,
        }
        return pin, snapshot, sidecar, result
    except Exception:
        snapshot.close()
        if sidecar is not None:
            sidecar.close()
        raise


def verify_installer(path: Path, architecture: str, pin_path: Path | None = None) -> dict[str, Any]:
    pin, snapshot, sidecar, result = _verify_installer_bound(path, architecture, pin_path)
    try:
        snapshot.assert_unchanged("Inno Setup installer")
        verify_authenticode_chain_bound(snapshot)
        snapshot.assert_unchanged("Inno Setup installer")
        sidecar.assert_unchanged("Inno Setup installer issig")
        result.pop("path")
        return result
    finally:
        snapshot.close()
        sidecar.close()
        del pin


def assert_trusted_compiler_root(path: Path, record: Mapping[str, Any]) -> None:
    if path.name != record["filename"]:
        fail("compiler filename mismatch")
    if path.parent.name != record["trusted_root_leaf"]:
        fail("untrusted installation root")
    if os.name == "nt":
        program_files = windows_program_files()
        expected = os.path.normcase(str(Path(program_files) / "Inno Setup 7" / "ISCC.exe"))
        actual = os.path.normcase(str(path))
        if actual != expected:
            fail("untrusted installation root")
        try:
            wow = windows_known_folder(0x002A)
        except Refused:
            wow = ""
        if wow and actual.startswith(os.path.normcase(str(Path(wow))) + os.sep):
            fail("untrusted installation root")


def _require_measured_compiler_pin(
    record: Mapping[str, Any], architecture: str, installers: Mapping[str, Any]
) -> None:
    if record["status"] != "pinned" or any(record[field] is None for field in COMPILER_PIN_FIELDS):
        fail(
            f"ISCC {architecture} pin not measured; run verify-compiler --measure on a Windows "
            "host and record the printed values in tools/inno-toolchain-pins.json"
        )
    for installer in installers.values():
        if record["sha256"] == installer["sha256"]:
            fail("compiler receipt must not reuse the Pyrsys installer digest")


def pin_file_digest(path: Path | None = None) -> str:
    pin_path = path or DEFAULT_PIN
    snapshot = bind_regular_snapshot(pin_path, "Inno toolchain pin", maximum=MAX_PIN)
    try:
        digest = snapshot.digest
        snapshot.assert_unchanged("Inno toolchain pin")
        return digest
    finally:
        snapshot.close()


def compiler_identity_record(
    verified: Mapping[str, Any],
    *,
    pin_sha256: str,
    pin_path: str = PIN_RELATIVE_PATH,
) -> dict[str, Any]:
    _require_keys(verified, COMPILER_VERIFY_KEYS, "compiler identity")
    if not HEX64.fullmatch(pin_sha256) or pin_sha256 == ZERO_SHA:
        fail("pin SHA-256 is not an exact lowercase non-zero digest: pin_sha256")
    if pin_path != PIN_RELATIVE_PATH:
        fail("compiler identity pin path mismatch")
    sha256 = _text(verified, "sha256")
    tree = _text(verified, "install_tree_sha256")
    if not HEX64.fullmatch(sha256) or sha256 == ZERO_SHA:
        fail("compiler SHA-256 mismatch")
    if not HEX64.fullmatch(tree) or tree == ZERO_SHA:
        fail("compiler install-tree SHA-256 mismatch")
    if sha256 == tree:
        fail("compiler file and install-tree hashes must be independently derived")
    leaf_sha = _text(verified, "authenticode_leaf_sha256")
    serial = _text(verified, "authenticode_leaf_serial_hex")
    if not HEX64.fullmatch(leaf_sha) or leaf_sha == ZERO_SHA:
        fail("Authenticode publisher mismatch")
    if HEX_SERIAL.fullmatch(serial) is None:
        fail("Authenticode leaf serial is malformed")
    if _text(verified, "filename") != COMPILER_ORIGINAL_FILENAME:
        fail("compiler filename mismatch")
    if _text(verified, "publisher_name") != OFFICIAL_PUBLISHER["authenticode_publisher_name"]:
        fail("Authenticode publisher mismatch")
    if leaf_sha != OFFICIAL_PUBLISHER["authenticode_leaf_sha256"]:
        fail("Authenticode publisher mismatch")
    if serial != OFFICIAL_PUBLISHER["authenticode_leaf_serial_hex"]:
        fail("Authenticode publisher mismatch")
    version = _text(verified, "version")
    product_version = _text(verified, "product_version_string")
    if version != VERSION:
        fail("version mismatch")
    if _text(verified, "pe_machine") != "x64":
        fail("7.1.0 compiler identity for x64 and arm64-capable outputs must be x64 ISCC")
    if _text(verified, "trusted_root_leaf") != "Inno Setup 7":
        fail("compiler trusted root leaf mismatch")
    architecture = _text(verified, "architecture")
    if architecture not in {"x64", "arm64"}:
        fail("compiler architecture is unsupported")
    outputs = verified["output_architectures"]
    if type(outputs) not in (list, tuple) or any(type(item) is not str for item in outputs):
        fail("compiler output architecture mismatch")
    if tuple(outputs) != (architecture,):
        fail(f"compiler output architecture mismatch: {architecture}")
    size = verified["size"]
    if type(size) is not int or isinstance(size, bool) or size < 1 or size > MAX_COMPILER:
        fail("compiler size mismatch")
    record = {
        "contract": COMPILER_RECEIPT_CONTRACT,
        "product": "Inno Setup",
        "vendor": "JRSoftware",
        "version": VERSION,
        "filename": COMPILER_ORIGINAL_FILENAME,
        "architecture": architecture,
        "pe_machine": "x64",
        "output_architectures": list(outputs),
        "sha256": sha256,
        "size": size,
        "product_version_string": product_version,
        "publisher_name": OFFICIAL_PUBLISHER["authenticode_publisher_name"],
        "authenticode_leaf_sha256": leaf_sha,
        "authenticode_leaf_serial_hex": serial,
        "install_tree_sha256": tree,
        "trusted_root_leaf": "Inno Setup 7",
        "pin_path": PIN_RELATIVE_PATH,
        "pin_sha256": pin_sha256,
    }
    if tuple(record) != COMPILER_RECEIPT_KEYS:
        fail("compiler identity receipt schema mismatch")
    return record


def assert_compiler_product_identity(
    snapshot: BoundSnapshot, pin: Mapping[str, Any], record: Mapping[str, Any]
) -> None:
    if snapshot.path.name != record["filename"] or snapshot.path.name != COMPILER_ORIGINAL_FILENAME:
        fail("compiler filename mismatch")
    for installer in pin["installers"].values():
        if snapshot.digest == installer["sha256"]:
            fail("compiler identity must be ISCC.exe, not the Pyrsys installer")
        if len(snapshot.data) == installer["size"] and snapshot.digest == installer["sha256"]:
            fail("compiler identity must be ISCC.exe, not the Pyrsys installer")
    try:
        versions = version_strings(snapshot.data)
    except Refused:
        return
    if versions["FileDescription"] == INSTALLER_FILE_DESCRIPTION:
        fail("compiler identity must be ISCC.exe, not the Pyrsys installer")
    for installer in pin["installers"].values():
        if versions["FileDescription"] == installer["file_description"]:
            fail("compiler identity must be ISCC.exe, not the Pyrsys installer")
        if versions.get("OriginalFileName") == installer["filename"]:
            fail("compiler identity must be ISCC.exe, not the Pyrsys installer")
    original = versions.get("OriginalFileName")
    if original is not None and original != COMPILER_ORIGINAL_FILENAME:
        fail("compiler filename mismatch")


def verify_compiler(
    path: Path, architecture: str, pin_path: Path | None = None, *, measure: bool = False
) -> dict[str, Any]:
    """Verify ISCC.exe against its pin, or with measure=True report its identity.

    Measure mode runs every check below except equality with the four
    compiler pin fields (sha256, size, install_tree_sha256,
    product_version_string); it reports the VERSIONINFO ProductVersion as
    found (the official 7.1.0 ISCC.exe says "0.0.0.0") and requires the
    compiler FileDescription instead. It only returns values and never
    writes the pin file.
    """
    pin = load_pin(pin_path)
    if architecture not in {"x64", "arm64"}:
        fail("compiler architecture is unsupported")
    record = pin["compilers"][f"windows_{architecture}"]
    candidate = Path(path)
    refuse_execution(candidate)
    walk_path_components(candidate, "ISCC compiler")
    assert_trusted_compiler_root(candidate, record)
    if candidate.name != record["filename"]:
        fail("compiler filename mismatch")
    snapshot = bind_regular_snapshot(candidate, "ISCC compiler", maximum=MAX_COMPILER)
    tree: BoundTree | None = None
    try:
        assert_compiler_product_identity(snapshot, pin, record)
        if measure:
            expected_product_version = None
        else:
            _require_measured_compiler_pin(record, architecture, pin["installers"])
            if len(snapshot.data) != record["size"] or snapshot.digest != record["sha256"]:
                fail("compiler SHA-256 mismatch")
            expected_product_version = record["product_version_string"]
        assert_pe_machine(snapshot.data, record["pe_machine"])
        if architecture == "arm64":
            parsed = parse_pe(snapshot.data)
            if parsed["machine"] == PE_MACHINE["arm64"]:
                fail("architecture mismatch: native ARM64 ISCC is not published for 7.1.0")
        versions = version_strings(snapshot.data)
        if expected_product_version is None:
            if versions["FileDescription"] != COMPILER_FILE_DESCRIPTION:
                fail("compiler identity must be the Inno Setup command-line compiler")
        elif versions["ProductVersion"] != expected_product_version:
            fail("version mismatch")
        if versions["FileDescription"] == INSTALLER_FILE_DESCRIPTION:
            fail("compiler identity must be ISCC.exe, not the Pyrsys installer")
        original = versions.get("OriginalFileName")
        if original is not None and original != COMPILER_ORIGINAL_FILENAME:
            fail("compiler filename mismatch")
        tree = snapshot_install_tree(candidate.parent)
        if not measure and tree.digest != record["install_tree_sha256"]:
            fail("compiler install-tree SHA-256 mismatch")
        leaf = authenticode_leaf(snapshot.data)
        assert_publisher(leaf, pin["publisher"])
        if leaf["publisher_name"] != record["publisher_name"]:
            fail("Authenticode publisher mismatch")
        snapshot.assert_unchanged("ISCC compiler")
        tree.assert_unchanged("ISCC install tree")
        verify_authenticode_chain_bound(snapshot)
        snapshot.assert_unchanged("ISCC compiler")
        tree.assert_unchanged("ISCC install tree")
        if measure:
            if tree.digest == snapshot.digest:
                fail("compiler file and install-tree hashes must be independently derived")
            return {
                "mode": "measure",
                "pin_record": f"compilers.windows_{architecture}",
                "architecture": architecture,
                "sha256": snapshot.digest,
                "size": len(snapshot.data),
                "install_tree_sha256": tree.digest,
                "product_version_string": versions["ProductVersion"],
            }
        verified = {
            "architecture": architecture,
            "filename": record["filename"],
            "sha256": snapshot.digest,
            "size": len(snapshot.data),
            "pe_machine": record["pe_machine"],
            "output_architectures": list(record["output_architectures"]),
            "version": record["expected_version"],
            "product_version_string": versions["ProductVersion"],
            "publisher_name": leaf["publisher_name"],
            "authenticode_leaf_sha256": leaf["sha256"],
            "authenticode_leaf_serial_hex": leaf["serial"],
            "install_tree_sha256": tree.digest,
            "trusted_root_leaf": record["trusted_root_leaf"],
        }
        _require_keys(verified, COMPILER_VERIFY_KEYS, "compiler identity")
        return verified
    finally:
        if tree is not None:
            tree.close()
        snapshot.close()


def verify_pins(pin_path: Path | None = None) -> dict[str, Any]:
    pin = load_pin(pin_path)
    return {
        "contract": CONTRACT,
        "version": VERSION,
        "status": pin["status"],
        "installers_pinned": True,
        "compilers_pinned": bool(pin["compilers_pinned"]),
    }


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    refuse_upload_and_execution_request(args)
    parser = argparse.ArgumentParser(description="Verify official Inno Setup 7.1.0 custody pins.")
    sub = parser.add_subparsers(dest="command", required=True)
    pins = sub.add_parser("verify-pins")
    pins.add_argument("--pin", type=Path, default=None)
    installer = sub.add_parser("verify-installer")
    installer.add_argument("--arch", required=True, choices=("x64", "x86"))
    installer.add_argument("--path", required=True, type=Path)
    installer.add_argument("--pin", type=Path, default=None)
    compiler = sub.add_parser("verify-compiler")
    compiler.add_argument("--arch", required=True, choices=("x64", "arm64"))
    compiler.add_argument("--path", required=True, type=Path)
    compiler.add_argument("--pin", type=Path, default=None)
    compiler.add_argument(
        "--measure",
        action="store_true",
        help="run every compiler check except pin equality and print the values to record",
    )
    parsed = parser.parse_args(args)
    try:
        if parsed.command == "verify-pins":
            result = verify_pins(parsed.pin)
        elif parsed.command == "verify-installer":
            result = verify_installer(parsed.path, parsed.arch, parsed.pin)
        else:
            result = verify_compiler(parsed.path, parsed.arch, parsed.pin, measure=parsed.measure)
    except Refused as exc:
        print(f"INNO CUSTODY REFUSED: {exc}", file=sys.stderr)
        return 1
    for key, value in result.items():
        if isinstance(value, list):
            value = ",".join(str(item) for item in value)
        print(f"{key}|{value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
