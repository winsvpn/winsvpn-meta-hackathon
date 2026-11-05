#!/usr/bin/env python3
"""Prepare and verify a private OpenSSL release-tool runtime.

A locally built OpenSSL archive is accepted only when an externally
authenticated build receipt binds the exact official OpenSSL 4.0.2 source
digest, source archive identity, configuration flags, compiler/toolchain
identity, build transaction, resulting archive/tree/executable hashes, and
current controller bytes. Candidate-controlled self-authored receipts fail
closed as owner-blocked. Official openssl-library.org listed OpenSSL 4.0.2
as the current stable security patch on 2026-08-25. Live toolchain-pins.json
freezes the identity-proven 4.0.2 hashes, while prepare remains fail-closed
until the owner supplies the external authenticated build receipt. This layer
never performs network execution and never self-authorizes a build receipt.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import zipfile


MAX_ARCHIVE = 10 * 1024 * 1024
MAX_SOURCE = 80 * 1024 * 1024
MAX_EXPANDED = 25 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_CONTROLLER = 2 * 1024 * 1024
MAX_RECEIPT = 64 * 1024
EXPECTED_MEMBERS = {
    "openssl/": "dir",
    "openssl/bin/": "dir",
    "openssl/bin/openssl": "file",
    "openssl/share/": "dir",
    "openssl/share/LICENSE.txt": "file",
}
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
CONTROLLER_NAME = "release_openssl_archive_custody.py"
CONTROLLER_RELATIVE = f"tools/{CONTROLLER_NAME}"
RECEIPT_ENV = "WINS_OPENSSL_BUILD_RECEIPT"
RECEIPT_CONTRACT = "winsvpn-openssl-source-to-binary-receipt-v1"
RECEIPT_ISSUER = "winsvpn-owner"
OFFICIAL_VERSION = "4.0.2"
OFFICIAL_PLATFORM = "darwin64-arm64-cc"
OFFICIAL_SOURCE_NAME = "openssl-4.0.2.tar.gz"
OFFICIAL_SOURCE_SHA256 = "736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8"
OFFICIAL_CONFIGURATION = "darwin64-arm64-cc no-shared no-tests no-docs"
OFFICIAL_RELEASE_DATE = "25 Aug 2026"
OFFICIAL_BUILD_TRANSACTION = "52e0e8be0ae52d6725aa507f8796a9a1a2b7d7280f02002186e9c9ccf73ca98b"
OFFICIAL_ARCHIVE_SHA256 = "1c06593f55903b53cd1477532fa17993ab1b3c19a1d02bd3ecb5b6071d1cdd79"
OFFICIAL_TREE_SHA256 = "b862d086d1a9da9dce66d662a4f6e97d969b4bb902e7d63768d6155da4a4108a"
OFFICIAL_EXECUTABLE_SHA256 = "a6a9c103ac97ece042e018e8bc964dcce911997e6e51f223aee469f6a5c5a144"
OFFICIAL_ARCHIVE_NAME = "wins-openssl-4.0.2-darwin-arm64.zip"
OFFICIAL_ROOT = "openssl"
OFFICIAL_EXECUTABLE = "bin/openssl"
FROZEN_COMPILER_IDENTITY = {
    "name": "Apple clang",
    "path": "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
    "sha256": "7def90dd8829726686213a747fc5bff1583df933dae5edc55d755479e0bfe00a",
    "target": "arm64-apple-darwin25.6.0",
    "version": "21.0.0",
    "version_line": "Apple clang version 21.0.0 (clang-2100.1.1.101)",
    "xcode_build": "17F113",
    "xcode_version": "26.6",
}
COMPILER_IDENTITY_KEYS = tuple(FROZEN_COMPILER_IDENTITY.keys())
RECEIPT_KEYS = (
    "contract",
    "schema_version",
    "authenticated",
    "issuer",
    "version",
    "source_archive_name",
    "source_archive_sha256",
    "build_configuration",
    "compiler_identity",
    "build_transaction",
    "archive_sha256",
    "install_tree_sha256",
    "executable_sha256",
    "controller",
    "controller_sha256",
)
OWNER_BLOCKED_UNAVAILABLE = (
    "owner-blocked: current reviewed OpenSSL build receipt is unavailable"
)
OWNER_BLOCKED_WRITABLE = (
    "owner-blocked: current reviewed OpenSSL build receipt is writable"
)
OWNER_BLOCKED_ADJACENT = (
    "owner-blocked: OpenSSL build receipt must be external to the candidate repository"
)
OWNER_BLOCKED_SELF_AUTH = (
    "owner-blocked: candidate-controlled OpenSSL build receipt cannot self-authorize"
)


class Refused(ValueError):
    pass


def fail(message: str) -> None:
    raise Refused(message)


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
    identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_size, value.st_mtime_ns)
    if not (identity(before) == identity(after) == identity(latest)):
        fail(f"file changed while it was hashed: {path}")
    return digest.hexdigest()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _mapping(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    return value


def _text(root: dict[str, object], key: str) -> str:
    value = root.get(key)
    if type(value) is not str or not value or "\0" in value:
        fail(f"{key} must be a non-empty string")
    return value


def _hex_digest(root: dict[str, object], key: str) -> str:
    value = _text(root, key)
    if HEX_RE.fullmatch(value) is None or value == "0" * 64:
        fail(f"invalid OpenSSL digest pin: {key}")
    return value


def _compiler_identity(
    value: object,
    label: str,
    *,
    frozen_message: str,
) -> dict[str, str]:
    root = _mapping(value, label)
    if set(root.keys()) != set(COMPILER_IDENTITY_KEYS):
        fail(f"{label} keys are not the frozen OpenSSL compiler/toolchain identity")
    result = {key: _text(root, key) for key in COMPILER_IDENTITY_KEYS}
    if HEX_RE.fullmatch(result["sha256"]) is None or result["sha256"] == "0" * 64:
        fail("invalid OpenSSL compiler/toolchain digest pin")
    if result != FROZEN_COMPILER_IDENTITY:
        fail(frozen_message)
    return result


def require_safe_file(path: Path, expected_name: str) -> None:
    if not path.is_absolute() or path.name != expected_name or path.is_symlink():
        fail(f"unsafe archive path: {path}")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        fail("archive must be one owner-controlled regular file")
    if stat.S_IMODE(info.st_mode) != 0o444:
        fail("archive must be immutable mode 0444")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        item = current.lstat()
        mode = stat.S_IMODE(item.st_mode)
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            fail("archive path contains a symbolic or non-directory component")
        if item.st_uid not in {0, os.getuid()}:
            fail("archive path contains a foreign-owned component")
        if mode & 0o022 and not (item.st_uid == 0 and mode & stat.S_ISVTX):
            fail("archive path contains an unsafe writable component")


def copy_stable(source: Path, destination: Path, expected_sha: str) -> None:
    before = source.lstat()
    if digest_file(source) != expected_sha:
        fail("OpenSSL archive SHA-256 mismatch")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source, flags)
    destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        while block := os.read(source_fd, 1024 * 1024):
            os.write(destination_fd, block)
        os.fsync(destination_fd)
    finally:
        os.close(source_fd)
        os.close(destination_fd)
    after = source.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after) or digest_file(destination) != expected_sha:
        fail("OpenSSL archive changed during authenticated copying")


def safe_extract(archive: Path, destination: Path) -> None:
    if archive.stat().st_size > MAX_ARCHIVE:
        fail("OpenSSL archive exceeds the size limit")
    raw = archive.read_bytes()
    eocd = raw.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(raw):
        fail("OpenSSL ZIP end record is absent")
    comment_length = int.from_bytes(raw[eocd + 20 : eocd + 22], "little")
    if eocd + 22 + comment_length != len(raw) or comment_length:
        fail("OpenSSL ZIP comments or trailing bytes are forbidden")
    with zipfile.ZipFile(archive) as bundle:
        if bundle.comment or bundle.start_dir <= 0:
            fail("OpenSSL ZIP structure is malformed")
        entries = bundle.infolist()
        if len(entries) != len(EXPECTED_MEMBERS):
            fail("OpenSSL ZIP member count mismatch")
        seen: set[str] = set()
        folded: set[str] = set()
        total = 0
        for entry in entries:
            name = entry.filename
            normalized = unicodedata.normalize("NFC", name)
            collision = normalized.casefold()
            if name != normalized or name in seen or collision in folded:
                fail("OpenSSL ZIP contains duplicate or colliding members")
            seen.add(name)
            folded.add(collision)
            expected_kind = EXPECTED_MEMBERS.get(name)
            if expected_kind is None:
                fail(f"unexpected OpenSSL ZIP member: {name}")
            parts = PurePosixPath(name.rstrip("/")).parts
            if not parts or any(part in {"", ".", ".."} for part in parts) or name.startswith("/"):
                fail("OpenSSL ZIP contains an unsafe path")
            unix_mode = entry.external_attr >> 16
            kind = "dir" if entry.is_dir() else "file"
            if kind != expected_kind or stat.S_ISLNK(unix_mode):
                fail(f"OpenSSL ZIP member type mismatch: {name}")
            if entry.flag_bits & 1:
                fail("encrypted OpenSSL ZIP members are forbidden")
            total += entry.file_size
            if total > MAX_EXPANDED or entry.file_size > MAX_EXPANDED:
                fail("OpenSSL ZIP expanded size exceeds the limit")
            if entry.compress_size == 0 and entry.file_size:
                fail("OpenSSL ZIP member has an invalid compression ratio")
            if entry.compress_size and entry.file_size / entry.compress_size > 100:
                fail("OpenSSL ZIP compression ratio exceeds the limit")
        if set(seen) != set(EXPECTED_MEMBERS):
            fail("OpenSSL ZIP member set mismatch")
        destination.mkdir(mode=0o700)
        for name, kind in EXPECTED_MEMBERS.items():
            target = destination / name
            if kind == "dir":
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with bundle.open(name) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            target.chmod(0o500 if name.endswith("/openssl") else 0o400)
    for directory in sorted((path for path in destination.rglob("*") if path.is_dir()), reverse=True):
        directory.chmod(0o500)
    destination.chmod(0o500)


def tree_hash(root: Path) -> str:
    root = root.resolve(strict=True)
    if root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o500:
        fail("OpenSSL root is not frozen")
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
            if info.st_uid != os.getuid() or mode & 0o022:
                fail(f"unsafe OpenSSL tree ownership or mode: {relative}")
            if stat.S_ISDIR(info.st_mode):
                if mode != 0o500:
                    fail(f"OpenSSL directory is not frozen: {relative}")
                feed("D", relative, mode)
                walk(path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1 or mode not in {0o400, 0o500}:
                    fail(f"OpenSSL file is not frozen: {relative}")
                feed("F", relative, mode, info.st_size, digest_file(path))
            else:
                fail(f"unsupported OpenSSL tree entry: {relative}")

    walk(root)
    return digest.hexdigest()


def runtime_identity(path: Path) -> str:
    info = path.lstat()
    return ":".join(str(value) for value in (info.st_dev, info.st_ino, info.st_uid, format(stat.S_IMODE(info.st_mode), "o")))


def bind_regular_file(path: Path, max_size: int, label: str) -> bytes:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        fail(f"{label} must be one absolute regular file")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail(f"{label} must be one regular non-hardlinked file")
    if info.st_size <= 0 or info.st_size > max_size:
        fail(f"{label} exceeds the size limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    chunks: list[bytes] = []
    try:
        opened = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_size, value.st_mtime_ns)
        if identity(info) != identity(opened):
            fail(f"{label} was replaced before it was opened")
        while block := os.read(fd, 1024 * 1024):
            chunks.append(block)
        after = os.fstat(fd)
        if identity(opened) != identity(after):
            fail(f"{label} changed while it was read")
    finally:
        os.close(fd)
    latest = path.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_size, value.st_mtime_ns)
    if identity(after) != identity(latest):
        fail(f"{label} was replaced after it was opened")
    data = b"".join(chunks)
    if not data:
        fail(f"{label} snapshot is empty")
    if b"\0" in data:
        fail(f"{label} contains a NUL")
    return data


def canonical_build_transaction(pin: dict[str, object]) -> str:
    compiler = pin["compiler_identity"]
    if type(compiler) is not dict:
        fail("OpenSSL compiler/toolchain identity pin mismatch")
    record = {
        "archive_sha256": pin["archive_sha"],
        "build_configuration": pin["build_configuration"],
        "compiler_identity": {key: compiler[key] for key in COMPILER_IDENTITY_KEYS},
        "executable_sha256": pin["executable_sha"],
        "install_tree_sha256": pin["tree_sha"],
        "source_archive_name": pin["source_name"],
        "source_archive_sha256": pin["source_sha"],
        "version": pin["version"],
    }
    payload = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("ascii")
    return digest_bytes(payload)


def controller_path() -> Path:
    path = Path(__file__)
    if not path.is_absolute():
        path = path.resolve(strict=True)
    if path.name != CONTROLLER_NAME:
        fail("malicious or substituted OpenSSL custody controller rejected")
    return path


def snapshot_controller() -> tuple[bytes, str]:
    data = bind_regular_file(controller_path(), MAX_CONTROLLER, "OpenSSL custody controller")
    return data, digest_bytes(data)


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def parse_build_receipt(data: bytes) -> dict[str, object]:
    if b"\0" in data:
        fail("OpenSSL build receipt contains a NUL")
    try:
        document = json.loads(data, object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        fail(f"OpenSSL build receipt is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"OpenSSL build receipt is not JSON: {exc}")
    root = _mapping(document, "OpenSSL build receipt")
    if set(root.keys()) != set(RECEIPT_KEYS):
        fail("OpenSSL build receipt keys are not exact")
    if _text(root, "contract") != RECEIPT_CONTRACT:
        fail("OpenSSL build receipt contract mismatch")
    schema = root.get("schema_version")
    if type(schema) is not int or schema != 1:
        fail("OpenSSL build receipt schema_version mismatch")
    authenticated = root.get("authenticated")
    if type(authenticated) is not bool or authenticated is not True:
        fail("OpenSSL build receipt authenticated must be JSON true")
    if _text(root, "issuer") != RECEIPT_ISSUER:
        fail("OpenSSL build receipt issuer mismatch")
    if _text(root, "version") != OFFICIAL_VERSION:
        fail("OpenSSL build receipt version is not the frozen OpenSSL 4.0.2 release")
    if _text(root, "source_archive_name") != OFFICIAL_SOURCE_NAME:
        fail("OpenSSL build receipt source archive identity mismatch")
    source_sha = _hex_digest(root, "source_archive_sha256")
    if source_sha != OFFICIAL_SOURCE_SHA256:
        fail("OpenSSL build receipt source digest is not the official OpenSSL 4.0.2 digest")
    if _text(root, "build_configuration") != OFFICIAL_CONFIGURATION:
        fail("OpenSSL build receipt configuration flags mismatch")
    compiler = _compiler_identity(
        root.get("compiler_identity"),
        "receipt compiler_identity",
        frozen_message="OpenSSL build receipt compiler/toolchain identity mismatch",
    )
    transaction = _hex_digest(root, "build_transaction")
    archive_sha = _hex_digest(root, "archive_sha256")
    tree_sha = _hex_digest(root, "install_tree_sha256")
    executable_sha = _hex_digest(root, "executable_sha256")
    if _text(root, "controller") != CONTROLLER_RELATIVE:
        fail("OpenSSL build receipt controller path mismatch")
    controller_sha = _hex_digest(root, "controller_sha256")
    return {
        "source_name": OFFICIAL_SOURCE_NAME,
        "source_sha": source_sha,
        "build_configuration": OFFICIAL_CONFIGURATION,
        "compiler_identity": compiler,
        "build_transaction": transaction,
        "archive_sha": archive_sha,
        "tree_sha": tree_sha,
        "executable_sha": executable_sha,
        "controller": CONTROLLER_RELATIVE,
        "controller_sha256": controller_sha,
    }


def bind_source_to_binary(
    receipt: dict[str, object],
    pin: dict[str, object],
    controller_sha: str,
) -> None:
    if receipt["source_sha"] != OFFICIAL_SOURCE_SHA256 or pin["source_sha"] != OFFICIAL_SOURCE_SHA256:
        fail("OpenSSL build receipt source digest is not the official OpenSSL 4.0.2 digest")
    if receipt["source_name"] != OFFICIAL_SOURCE_NAME or pin["source_name"] != OFFICIAL_SOURCE_NAME:
        fail("OpenSSL build receipt source archive identity mismatch")
    if receipt["build_configuration"] != pin["build_configuration"]:
        fail("OpenSSL build receipt configuration flags mismatch")
    if receipt["compiler_identity"] != pin["compiler_identity"]:
        fail("OpenSSL build receipt compiler/toolchain identity mismatch")
    if receipt["build_transaction"] != pin["build_transaction"]:
        fail("OpenSSL build receipt build transaction mismatch")
    if (
        receipt["archive_sha"] != pin["archive_sha"]
        or receipt["tree_sha"] != pin["tree_sha"]
        or receipt["executable_sha"] != pin["executable_sha"]
    ):
        fail("OpenSSL source-to-binary provenance mismatch")
    if receipt["controller_sha256"] != controller_sha:
        fail("OpenSSL build receipt controller digest mismatch")


def require_external_build_receipt(repo: Path) -> bytes:
    raw = os.environ.get(RECEIPT_ENV, "")
    if type(raw) is not str or not raw:
        fail(OWNER_BLOCKED_UNAVAILABLE)
    path = Path(raw)
    if not path.is_absolute():
        fail(OWNER_BLOCKED_UNAVAILABLE)
    if _path_is_within(path, repo):
        fail(OWNER_BLOCKED_ADJACENT)
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(OWNER_BLOCKED_UNAVAILABLE)
    if stat.S_ISLNK(info.st_mode):
        fail("OpenSSL build receipt symbolic link rejected")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail("OpenSSL build receipt must be one regular non-hardlinked file")
    if stat.S_IMODE(info.st_mode) != 0o444:
        fail(OWNER_BLOCKED_WRITABLE)
    if info.st_uid == os.getuid():
        fail(OWNER_BLOCKED_SELF_AUTH)
    return bind_regular_file(path, MAX_RECEIPT, "OpenSSL build receipt")


def verify_build_receipt(repo: Path, pin: dict[str, object], controller_sha: str) -> dict[str, object]:
    data = require_external_build_receipt(repo)
    receipt = parse_build_receipt(data)
    bind_source_to_binary(receipt, pin, controller_sha)
    return receipt


def bind_official_source_archive(pin: dict[str, object]) -> None:
    source = Path(pin["source_archive"])
    require_safe_file(source, OFFICIAL_SOURCE_NAME)
    info = source.lstat()
    if info.st_size <= 0 or info.st_size > MAX_SOURCE:
        fail("OpenSSL source archive exceeds the size limit")
    if digest_file(source) != OFFICIAL_SOURCE_SHA256:
        fail("OpenSSL source archive digest is not the official OpenSSL 4.0.2 digest")


def bind_compiler_identity(pin: dict[str, object]) -> None:
    compiler = pin["compiler_identity"]
    if type(compiler) is not dict:
        fail("OpenSSL compiler/toolchain identity pin mismatch")
    path = Path(compiler["path"])
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        fail("OpenSSL compiler/toolchain identity is absent")
    if digest_file(path) != compiler["sha256"]:
        fail("OpenSSL compiler/toolchain identity mismatch")


def load_pin(manifest: Path) -> dict[str, object]:
    if not manifest.is_absolute() or manifest.is_symlink() or not manifest.is_file():
        fail("OpenSSL pin manifest must be one absolute regular file")
    data = bind_regular_file(manifest, MAX_MANIFEST, "OpenSSL pin manifest")
    try:
        document = json.loads(data, object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        fail(f"OpenSSL pin manifest is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"OpenSSL pin manifest is not JSON: {exc}")
    tools = _mapping(_mapping(document, "pin manifest").get("tools"), "tools")
    pin = _mapping(tools.get("openssl"), "openssl pin")
    compiler = _compiler_identity(
        pin.get("compiler_identity"),
        "openssl compiler_identity",
        frozen_message="OpenSSL compiler/toolchain identity pin mismatch",
    )
    result: dict[str, object] = {
        "version": _text(pin, "version"),
        "platform": _text(pin, "platform"),
        "source_archive": _text(pin, "source_archive_path"),
        "source_name": _text(pin, "source_archive_name"),
        "source_sha": _hex_digest(pin, "source_archive_sha256"),
        "archive": _text(_mapping(pin.get("archive_path"), "archive_path"), "darwin_arm64"),
        "archive_sha": _hex_digest(_mapping(pin.get("archive_sha256"), "archive_sha256"), "darwin_arm64"),
        "tree_sha": _hex_digest(_mapping(pin.get("install_tree_sha256"), "install_tree_sha256"), "darwin_arm64"),
        "root": _text(pin, "top_level_root"),
        "executable": _text(pin, "executable"),
        "executable_sha": _hex_digest(pin, "executable_sha256"),
        "build_configuration": _text(pin, "build_configuration"),
        "compiler_identity": compiler,
        "build_transaction": _hex_digest(pin, "build_transaction"),
        "build_receipt_env": _text(pin, "build_receipt_env"),
    }
    if result["version"] != OFFICIAL_VERSION or result["platform"] != OFFICIAL_PLATFORM:
        fail("OpenSSL release identity pin mismatch")
    if result["source_name"] != OFFICIAL_SOURCE_NAME:
        fail("OpenSSL source archive identity pin mismatch")
    if result["source_sha"] != OFFICIAL_SOURCE_SHA256:
        fail("OpenSSL source digest pin is not the official OpenSSL 4.0.2 digest")
    if result["build_configuration"] != OFFICIAL_CONFIGURATION:
        fail("OpenSSL configuration flags pin mismatch")
    if result["root"] != OFFICIAL_ROOT or result["executable"] != OFFICIAL_EXECUTABLE:
        fail("OpenSSL archive layout pin mismatch")
    if Path(str(result["source_archive"])).name != OFFICIAL_SOURCE_NAME:
        fail("OpenSSL source archive identity pin mismatch")
    if Path(str(result["archive"])).name != OFFICIAL_ARCHIVE_NAME:
        fail("OpenSSL archive layout pin mismatch")
    if result["build_receipt_env"] != RECEIPT_ENV:
        fail("OpenSSL build receipt environment pin mismatch")
    if result["build_transaction"] != canonical_build_transaction(result):
        fail("OpenSSL build transaction pin mismatch")
    if OFFICIAL_BUILD_TRANSACTION and result["build_transaction"] != OFFICIAL_BUILD_TRANSACTION:
        fail("OpenSSL build transaction pin mismatch")
    if OFFICIAL_ARCHIVE_SHA256 and result["archive_sha"] != OFFICIAL_ARCHIVE_SHA256:
        fail("OpenSSL archive digest pin mismatch")
    if OFFICIAL_TREE_SHA256 and result["tree_sha"] != OFFICIAL_TREE_SHA256:
        fail("OpenSSL install tree digest pin mismatch")
    if OFFICIAL_EXECUTABLE_SHA256 and result["executable_sha"] != OFFICIAL_EXECUTABLE_SHA256:
        fail("OpenSSL executable digest pin mismatch")
    return result


def run_checked(binary: Path, state: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {
        "HOME": str(state / "home"),
        "TMPDIR": str(state / "tmp"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "OPENSSL_CONF": "/dev/null",
    }
    return subprocess.run([str(binary), *arguments], env=environment, text=True, capture_output=True, check=True)


def check_capabilities(binary: Path, state: Path, version: str, platform: str) -> None:
    version_line = run_checked(binary, state, "version").stdout.strip()
    if version_line != (
        f"OpenSSL {version} {OFFICIAL_RELEASE_DATE} "
        f"(Library: OpenSSL {version} {OFFICIAL_RELEASE_DATE})"
    ):
        fail("OpenSSL runtime version mismatch")
    details = run_checked(binary, state, "version", "-a").stdout
    if f"platform: {platform}" not in details:
        fail("OpenSSL runtime platform mismatch")
    capability = state / "capability"
    capability.mkdir(mode=0o700)
    private = capability / "private.pem"
    public = capability / "public.pem"
    message = capability / "message"
    signature = capability / "signature"
    cert = capability / "cert.pem"
    message.write_bytes(b"wins-openssl-custody")
    run_checked(binary, state, "genpkey", "-algorithm", "ED25519", "-out", str(private))
    run_checked(binary, state, "pkey", "-in", str(private), "-pubout", "-out", str(public))
    run_checked(binary, state, "pkeyutl", "-sign", "-rawin", "-inkey", str(private), "-in", str(message), "-out", str(signature))
    run_checked(binary, state, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public), "-in", str(message), "-sigfile", str(signature))
    run_checked(binary, state, "req", "-new", "-x509", "-config", "/dev/null", "-key", str(private), "-subj", "/CN=WinsReleaseOpenSSL", "-days", "1", "-out", str(cert))
    fingerprint = run_checked(binary, state, "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256").stdout
    if "sha256 Fingerprint=" not in fingerprint:
        fail("OpenSSL X.509 fingerprint capability is absent")
    run_checked(binary, state, "smime", "-help")


def prepare(manifest_text: str) -> None:
    manifest = Path(manifest_text).resolve(strict=True)
    pin = load_pin(manifest)
    _controller_data, controller_sha = snapshot_controller()
    tools_dir = controller_path().parent
    if tools_dir.name != "tools":
        fail("OpenSSL custody controller is not in the repository tools directory")
    repo = tools_dir.parent
    verify_build_receipt(repo, pin, controller_sha)
    bind_compiler_identity(pin)
    bind_official_source_archive(pin)
    archive = Path(str(pin["archive"]))
    require_safe_file(archive, OFFICIAL_ARCHIVE_NAME)
    runtime = Path(tempfile.mkdtemp(prefix="wins-release-openssl.", dir="/private/tmp"))
    runtime.chmod(0o700)
    incoming = runtime / "incoming.zip"
    extracted = runtime / "extracted"
    state = runtime / "state"
    (state / "home").mkdir(parents=True, mode=0o700)
    (state / "tmp").mkdir(mode=0o700)
    copy_stable(archive, incoming, str(pin["archive_sha"]))
    safe_extract(incoming, extracted)
    root = extracted / str(pin["root"])
    binary = root / str(pin["executable"])
    if tree_hash(root) != pin["tree_sha"] or digest_file(binary) != pin["executable_sha"]:
        fail("OpenSSL extracted tree or executable digest mismatch")
    check_capabilities(binary, state, str(pin["version"]), str(pin["platform"]))
    if tree_hash(root) != pin["tree_sha"] or digest_file(binary) != pin["executable_sha"]:
        fail("OpenSSL runtime changed during capability validation")
    print(f"RUNTIME|{runtime}")
    print(f"RUNTIME_ID|{runtime_identity(runtime)}")
    print(f"ROOT|{root}")
    print(f"TREE_SHA256|{pin['tree_sha']}")
    print(f"BINARY|{binary}")
    print(f"BINARY_SHA256|{pin['executable_sha']}")


def verify(arguments: list[str]) -> None:
    if len(arguments) != 6:
        fail("OpenSSL verify arguments are malformed")
    runtime, expected_id, root, expected_tree, binary, expected_binary = arguments
    runtime_path = Path(runtime)
    root_path = Path(root)
    binary_path = Path(binary)
    if runtime_identity(runtime_path) != expected_id:
        fail("OpenSSL runtime identity changed")
    if root_path != runtime_path / "extracted/openssl" or binary_path != root_path / "bin/openssl":
        fail("OpenSSL runtime pointers changed")
    if tree_hash(root_path) != expected_tree or digest_file(binary_path) != expected_binary:
        fail("OpenSSL runtime tree changed")


def cleanup(runtime_text: str, expected_id: str) -> None:
    runtime = Path(runtime_text)
    if runtime.parent != Path("/private/tmp") or not runtime.name.startswith("wins-release-openssl."):
        fail("refusing OpenSSL cleanup outside the private runtime prefix")
    if runtime_identity(runtime) != expected_id:
        fail("refusing cleanup of a substituted OpenSSL runtime")
    for base, directories, files in os.walk(runtime, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files:
            path = base_path / name
            if path.is_symlink() or not path.is_file():
                fail("refusing cleanup of an unsupported OpenSSL runtime entry")
            path.chmod(0o600)
        for name in directories:
            path = base_path / name
            if path.is_symlink() or not path.is_dir():
                fail("refusing cleanup of an unsupported OpenSSL runtime directory")
            path.chmod(0o700)
        base_path.chmod(0o700)
    shutil.rmtree(runtime)


def main() -> int:
    try:
        action = sys.argv[1]
        if action == "prepare" and len(sys.argv) == 3:
            prepare(sys.argv[2])
        elif action == "verify":
            verify(sys.argv[2:])
        elif action == "cleanup" and len(sys.argv) == 4:
            cleanup(sys.argv[2], sys.argv[3])
        else:
            fail("unknown or malformed OpenSSL custody action")
    except (Refused, OSError, KeyError, json.JSONDecodeError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        print(f"release-openssl custody: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
