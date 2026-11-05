#!/usr/bin/env python3
"""Deterministic, offline-only contract for Linux store manifest artifacts.

The current externally authenticated source-freeze receipt is the trust
anchor for the support module and the exact source archive identity.
Hashing whatever bytes happen to be on disk is measurement only.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import io
import json
import lzma
import os
import pathlib
import re
import stat
import subprocess
import tarfile
import tempfile
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Callable, Mapping
from pathlib import PurePosixPath
from types import MappingProxyType


CONTRACT_MODULE_IDENTITY = "winsvpn-linux-store-manifest-contract-module-v1"
CONTRACT_MODULE_RELATIVE = "linux/packaging/store_manifest_contract.py"
CONTRACT = "winsvpn-linux-store-manifest-receipt-v1"
SCHEMA_VERSION = 3
SOURCE_FREEZE_RECEIPT_CONTRACT = "winsvpn-linux-store-source-freeze-receipt-v1"
SOURCE_FREEZE_RECEIPT_SCHEMA_VERSION = 1
SOURCE_FREEZE_ISSUER = "winsvpn-release-source-freeze"
SOURCE_FREEZE_RECEIPT_NAME = "STORE_SOURCE_RECEIPT.json"
EXTERNAL_TRUST_RELATIVE = "linux/packaging/STORE_SOURCE_TRUST.json"
EXTERNAL_TRUST_CONTRACT = "winsvpn-linux-store-source-toolchain-trust-v1"
EXTERNAL_TRUST_SCHEMA_VERSION = 1
EXTERNAL_TRUST_ISSUER = "winsvpn-release-source-freeze"
SELF_ASSERTED_AUTHENTICATED = (
    "self-asserted authenticated:true is not an externally bound "
    "source/toolchain identity"
)
UNAVAILABLE_EXTERNAL_IDENTITY = (
    "current externally bound source/toolchain identity is unavailable"
)
FLUTTER_RECEIPT_CONTRACT = "winsvpn-linux-flutter-sdk-receipt-v1"
FLUTTER_RECEIPT_SCHEMA_VERSION = 2
FLUTTER_RECEIPT_ISSUER = "winsvpn-linux-flutter-toolchain-custody"
FLUTTER_TREE_ROOT = "flutter"
MAX_AGE = dt.timedelta(hours=72)
MAX_CLOCK_SKEW = dt.timedelta(minutes=5)
MAX_BUILD_TRANSACTION_AGE = dt.timedelta(hours=72)
MAX_SOURCE_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_FLUTTER_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 250
COMPRESSED_BOMB_BYTES = 32 * 1024 * 1024
MAX_PATH_BYTES = 1024
MAX_PATH_DEPTH = 32
MAX_ARCHIVE_DEPTH = 1
TAR_BLOCK = 512
READ_CHUNK = 1024 * 1024
MAX_DECODER_MEMORY = 256 * 1024 * 1024
MAX_DECODE_CHUNK = 8 * 1024 * 1024
RELEASE_IDENTITY_PATH = pathlib.Path(
    "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
)
METADATA_RELATIVE = "linux/packaging/org.winsvpn.app.metainfo.xml"
METADATA_ID = "org.winsvpn.app"
METADATA_DESKTOP_ID = "org.winsvpn.app.desktop"
METADATA_BINARY = "wins_vpn"
METADATA_VALID_OARS_VALUES = frozenset({"none", "mild", "moderate", "intense"})
REQUIRED_METADATA_SINGLES = frozenset(
    {
        "id",
        "name",
        "summary",
        "metadata_license",
        "project_license",
        "launchable",
        "description",
        "categories",
        "provides",
        "releases",
        "content_rating",
    }
)
OARS_ATTRIBUTE_IDS = frozenset(
    {
        "violence-cartoon",
        "violence-fantasy",
        "violence-realistic",
        "violence-bloodshed",
        "violence-sexual",
        "violence-worship",
        "violence-desecration",
        "violence-slavery",
        "drugs-alcohol",
        "drugs-narcotics",
        "drugs-tobacco",
        "sex-nudity",
        "sex-themes",
        "sex-homosexuality",
        "sex-prostitution",
        "sex-adultery",
        "sex-appearance",
        "language-profanity",
        "language-humor",
        "language-discrimination",
        "money-advertising",
        "money-gambling",
        "money-purchasing",
        "social-chat",
        "social-audio",
        "social-contacts",
        "social-info",
        "social-location",
    }
)
REVIEWED_FLUTTER_VERSION = "3.47.6"
REVIEWED_FLUTTER_REVISION = "5fc346839b5d0eef006ed8404392afb4dfae428d"
REVIEWED_FLUTTER_CHANNEL = "stable"
REVIEWED_DART_VERSION = "3.13.5"
REVIEWED_FLUTTER_ARCHIVE_NAMES = MappingProxyType(
    {
        "x64": "flutter_linux_x64_3.47.6-stable.tar.xz",
        "arm64": "flutter_linux_arm64_3.47.6-stable.tar.xz",
    }
)
REVIEWED_FLUTTER_ARCHIVE_URL_PREFIX = (
    "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/"
)
REVIEWED_SOURCE_URL_PREFIX = "https://downloads.winsvpn.org/source/"
BASH = "/bin/bash"
MINIMAL_SUBPROCESS_ENV = MappingProxyType(
    {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
    }
)
GZIP_MAGIC = b"\x1f\x8b"
TAR_MAGIC = b"ustar"
SQUASHFS_MAGIC = b"hsqs"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ISSUANCE_ID = re.compile(r"[0-9a-f]{32}\Z")
RECEIPT_KEYS = {
    "schema_version",
    "contract",
    "target_id",
    "platform",
    "artifact_format",
    "created_utc",
    "artifact",
    "source",
    "source_freeze",
    "flutter_sdk",
    "version",
    "producer",
    "verification_network_accessed",
    "publication_authorized",
    "upload_attempted",
    "manifest_only",
    "package_verified",
    "sha256_anchor",
}
ARTIFACT_KEYS = {"path", "sha256", "bytes", "modified_time_ns"}
SOURCE_KEYS = {"url", "sha256", "archive_path", "bytes", "tree_sha256"}
SOURCE_FREEZE_RECORD_KEYS = {
    "path",
    "sha256",
    "issuance_id",
    "created_utc",
}
PRODUCER_KEYS = {"path", "sha256"}
FLUTTER_RECEIPT_KEYS = {
    "version",
    "revision",
    "channel",
    "dart_version",
    "receipt_path",
    "receipt_sha256",
    "created_utc",
    "issuance_id",
    "authenticated",
    "issuer",
    "archives",
}
FLUTTER_DOCUMENT_KEYS = {
    "schema_version",
    "contract",
    "version",
    "revision",
    "channel",
    "dart_version",
    "created_utc",
    "issuance_id",
    "authenticated",
    "issuer",
    "archives",
}
FLUTTER_ARCHIVE_KEYS = {
    "url",
    "sha256",
    "name",
    "archive_path",
    "bytes",
    "tree_sha256",
}
SOURCE_FREEZE_DOCUMENT_KEYS = {
    "schema_version",
    "contract",
    "created_utc",
    "issuance_id",
    "release",
    "authenticated",
    "issuer",
    "module",
    "source",
}
SOURCE_FREEZE_MODULE_KEYS = {"path", "sha256", "bytes"}
EXTERNAL_TRUST_KEYS = {
    "schema_version",
    "contract",
    "created_utc",
    "issuance_id",
    "release",
    "issuer",
    "module",
    "source",
    "flutter",
}
EXTERNAL_FLUTTER_KEYS = {
    "issuance_id",
    "version",
    "revision",
    "channel",
    "dart_version",
    "issuer",
}
REQUIRED_LIVE_PAYLOAD = (
    "wins_vpn",
    "winn-datapath",
    "awg",
    "awg-quick",
    "amneziawg-go",
    "xray",
    "winsvpn-bypass-bpf",
    "icudtl.dat",
    "flutter_assets",
    "wins_bridge_host",
    "winn3-descriptor-ring-attestation.json",
    "store-recipe.sha256",
    "release-manifest.sha256",
)
# The source script is transformed into a userspace-only packaged script.
AWG_QUICK_SOURCE_SHA256 = (
    "f4bb0f5d63665ade87f0cb9f2185c43515cff09868637eb311f98f65a318722c"
)
AWG_QUICK_USERSPACE_SHA256 = (
    "89dca7788242e542cec249af5d062764fbcb3a6a3ef66999c400d5bbe2f446db"
)

# Architecture-bound output pins matching linux/packaging/install.sh and
# tools/build_linux_release.sh. Winn datapath is first-party and is staged
# explicitly without an output digest pin.
REVIEWED_ENGINE_PAYLOAD_SHA256 = MappingProxyType(
    {
        "x64": MappingProxyType(
            {
                "awg": "23d29323258166183eeeb288c1f9f08b879f3707e54591b1bfb2402413f6d8d8",
                "awg-quick": AWG_QUICK_USERSPACE_SHA256,
                "amneziawg-go": "5e8e2e656d77f9f66102660234fa08d8c2ddb99bf32961db8c02ad19c32e872f",
                "xray": "09e63d5420f26db2bc6144f6d047601909541acf21792878d3859e4fc4980a12",
            }
        ),
        "arm64": MappingProxyType(
            {
                "awg": "bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d",
                "awg-quick": AWG_QUICK_USERSPACE_SHA256,
                "amneziawg-go": "9083c92dbd16422cd590df8fcf2ebae2c604b43539bdd58dddaede74efd0642a",
                "xray": "868fcabbf9a08d1e453bc6dc82dd8ca27cfcf8cdb2b3a8ff31b824361966964b",
            }
        ),
    }
)
BUNDLE_ENGINE_COPY = re.compile(
    r"\$bundle/(?:winn-datapath|awg-quick|amneziawg-go|awg|xray)\b"
)
STAGE_STORE_ENGINES = "linux/packaging/stage_store_engines.sh"
ENGINE_CHECKSUM_COMMAND = "winsvpn-engine-payload-sha256-bind"
WINN_DATAPATH_BIND = "winsvpn-winn-datapath-sha256-bind"
FLUTTER_BUNDLE_ENGINE_REFUSAL = "refusing Flutter-bundle engine leftover"
HOST_TARGET_CROSS_BUILD_REFUSAL = "refusing Flutter host/target cross-build"
SYMLINK_ENGINE_DEST_REFUSAL = "refusing symlink engine destination"
ENGINE_INSTALL_ORDER = (
    "winn-datapath",
    "awg",
    "awg-quick",
    "amneziawg-go",
    "xray",
)
ENGINE_INSTALL_LINE = re.compile(
    r"winsvpn-engine-publish:(winn-datapath|awg-quick|amneziawg-go|awg|xray)"
)
INSTALL_D_ENGINE_REFUSAL = (
    "store recipe must not publish engines with install -D"
)
REVIEWED_GO_VERSION = "1.27.1"
REVIEWED_GO_ARCHIVE_URL = MappingProxyType(
    {
        "x64": f"https://go.dev/dl/go{REVIEWED_GO_VERSION}.linux-amd64.tar.gz",
        "arm64": f"https://go.dev/dl/go{REVIEWED_GO_VERSION}.linux-arm64.tar.gz",
    }
)
REVIEWED_GO_ARCHIVE_SHA256 = MappingProxyType(
    {
        "x64": "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445",
        "arm64": "3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec",
    }
)
REVIEWED_GO_ARCHIVE_NAME = MappingProxyType(
    {
        "x64": f"go{REVIEWED_GO_VERSION}.linux-amd64.tar.gz",
        "arm64": f"go{REVIEWED_GO_VERSION}.linux-arm64.tar.gz",
    }
)
REVIEWED_CLANG_VERSION = "14.0.6"
REVIEWED_CLANG_PACKAGE = "1:14.0-55.7~deb12u1"
REVIEWED_BINUTILS_PACKAGE = "2.40-2"
AWG_TOOLS_VERSION = "v3.1.20260812"
AWG_TOOLS_ZIP_URL = (
    "https://github.com/amnezia-vpn/amneziawg-tools/releases/download/"
    f"{AWG_TOOLS_VERSION}/ubuntu-22.04-amneziawg-tools.zip"
)
AWG_TOOLS_ZIP_SHA256 = "919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56"
AWG_TOOLS_SOURCE_URL = (
    "https://github.com/amnezia-vpn/amneziawg-tools/archive/refs/tags/"
    f"{AWG_TOOLS_VERSION}.tar.gz"
)
AWG_TOOLS_SOURCE_SHA256 = (
    "dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493"
)
AWG_TOOLS_COPYING_URL = (
    "https://raw.githubusercontent.com/amnezia-vpn/amneziawg-tools/"
    f"{AWG_TOOLS_VERSION}/COPYING"
)
AWG_TOOLS_COPYING_SHA256 = (
    "8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643"
)
AWG_GO_COMMIT = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
AWG_GO_SOURCE_URL = (
    f"https://github.com/amnezia-vpn/amneziawg-go/archive/{AWG_GO_COMMIT}.tar.gz"
)
AWG_GO_SOURCE_SHA256 = (
    "10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"
)
XRAY_TAG = "v26.9.30"
XRAY_COMMIT = "b26a91de4f3294e26a0ad0a970b81a386a41f789"
XRAY_GIT_URL = "https://github.com/XTLS/Xray-core.git"
XRAY_SOURCE_URL = f"https://github.com/XTLS/Xray-core/archive/{XRAY_COMMIT}.tar.gz"
XRAY_LICENSE_SHA256 = (
    "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5"
)
XRAY_IDENTITY_RELATIVE = ".winsvpn-xray-identity"
XRAY_IDENTITY_TEXT = (
    f"commit={XRAY_COMMIT}\ntag={XRAY_TAG}\nbuild={XRAY_TAG}\n"
)
XRAY_IDENTITY_SHA256 = hashlib.sha256(XRAY_IDENTITY_TEXT.encode("ascii")).hexdigest()
XRAY_IDENTITY_URL = (
    f"{REVIEWED_SOURCE_URL_PREFIX}xray-{XRAY_TAG}.identity"
)
WINN_GOSUM_SHA256 = (
    "b22ca5ae7951bf4f01a5c5bf6a6617fa6473d46450f90c6cfbc403a38165aab5"
)
STORE_GOMODCACHE_URL = (
    f"{REVIEWED_SOURCE_URL_PREFIX}store-go-mod-cache-winn-awg-xray.tar.gz"
)
ENGINE_ARCHIVE_DIR = "engine-archives"
XRAY_SOURCE_ARCHIVE_NAME = f"Xray-core-{XRAY_COMMIT}.tar.gz"
STORE_GOMODCACHE_ARCHIVE_NAME = "store-go-mod-cache-winn-awg-xray.tar.gz"
XRAY_SOURCE_STRIP_PREFIX = f"Xray-core-{XRAY_COMMIT}"
STORE_GOMODCACHE_STRIP_PREFIX = "go-mod-cache"
OWNER_INPUT_ARCHIVE_MISSING = (
    "owner input required: reviewed {label} archive is absent"
)
AWG_ARM64_PREBUILT_URL = (
    f"{REVIEWED_SOURCE_URL_PREFIX}awg-linux-arm64-{AWG_TOOLS_VERSION}"
)
AWG_QUICK_PREBUILT_URL = (
    f"{REVIEWED_SOURCE_URL_PREFIX}awg-quick-{AWG_TOOLS_VERSION}"
)
ENGINE_SOURCE_SNAP_AFTER = (
    "flutter-sdk-x64, flutter-sdk-arm64, engine-go-sdk-x64, "
    "engine-go-sdk-arm64, engine-awg-go-source, engine-awg-tools-zip, "
    "engine-awg-tools-src, engine-awg-copying, engine-awg-prebuilt-arm64, "
    "engine-awg-quick-prebuilt, engine-xray-source, engine-xray-identity, "
    "engine-go-mod-cache"
)
CLASSIC_SNAP_UNBOUNDED = "Classic confinement is unbounded host access"
CLASSIC_SNAP_NO_APPROVAL = "does not claim Snap Store approval"
CLASSIC_SNAP_REVIEW = "fail-closed Snap Store classic-confinement review"
NATIVE_PACKAGE_TARGETS = MappingProxyType(
    {
        "linux-flathub-manifest": ("org.winsvpn.app.flatpak", "flatpak"),
        "linux-snap-manifest": ("wins-vpn.snap", "snap"),
    }
)


class ManifestContractError(RuntimeError):
    """Raised when a manifest artifact or its receipt is unsafe or stale."""


@dataclasses.dataclass(frozen=True)
class FlutterArchive:
    url: str
    sha256: str
    name: str
    archive_path: str
    size_bytes: int
    tree_sha256: str


@dataclasses.dataclass(frozen=True)
class FlutterSdk:
    version: str
    revision: str
    channel: str
    dart_version: str
    receipt_path: str
    receipt_sha256: str
    created_utc: str
    issuance_id: str
    authenticated: bool
    issuer: str
    archives: Mapping[str, FlutterArchive]


@dataclasses.dataclass(frozen=True)
class SourceFreezeReceipt:
    path: str
    sha256: str
    created_utc: str
    issuance_id: str
    release: str
    module_path: str
    module_sha256: str
    module_bytes: int
    source: dict[str, object]


@dataclasses.dataclass(frozen=True)
class ExternalTrust:
    issuance_id: str
    created_utc: str
    release: str
    module_path: str
    module_sha256: str
    module_bytes: int
    source: dict[str, object]
    flutter_issuance_id: str
    flutter_version: str
    flutter_revision: str
    flutter_channel: str
    flutter_dart_version: str
    flutter_issuer: str


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
        info.st_uid,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
    )


def _is_special_node(info: os.stat_result) -> bool:
    mode = info.st_mode
    return bool(
        stat.S_ISFIFO(mode)
        or stat.S_ISCHR(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISSOCK(mode)
    )


def _reject_leaf_node(info: os.stat_result, label: str) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise ManifestContractError(f"{label} traverses a symbolic link.")
    if _is_special_node(info):
        raise ManifestContractError(
            f"{label} is a FIFO or special node and is rejected before opening."
        )
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ManifestContractError(
            f"{label} must be a distinct regular file, not a hard link."
        )


def _reject_dir_node(info: os.stat_result, label: str) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise ManifestContractError(f"{label} traverses a symbolic link.")
    if _is_special_node(info):
        raise ManifestContractError(
            f"{label} is a FIFO or special node and is rejected before opening."
        )
    if not stat.S_ISDIR(info.st_mode):
        raise ManifestContractError(f"{label} must be a regular directory.")


def _require_nofollow() -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ManifestContractError(
            "descriptor binding requires O_NOFOLLOW and O_DIRECTORY."
        )


def _open_flags() -> int:
    _require_nofollow()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _directory_flags() -> int:
    return _open_flags() | os.O_DIRECTORY


def _open_nofollow(path: pathlib.Path, label: str) -> int:
    try:
        return os.open(path, _open_flags())
    except OSError as exc:
        raise ManifestContractError(f"{label} is unreadable.") from exc


def _open_dir(path: pathlib.Path, label: str) -> int:
    try:
        return os.open(path, _directory_flags())
    except OSError as exc:
        raise ManifestContractError(f"{label} must be a regular directory.") from exc


def _split_relative(relative: str, label: str) -> tuple[str, ...]:
    posix = relative.replace("\\", "/")
    if not posix or posix.startswith("/") or posix.endswith("/") or "//" in posix:
        raise ManifestContractError(f"{label} path is not a canonical repository path.")
    parts = PurePosixPath(posix).parts
    if (
        not parts
        or PurePosixPath(*parts).as_posix() != posix
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ManifestContractError(f"{label} path is not a canonical repository path.")
    return parts


def _repo_root(repo: pathlib.Path) -> pathlib.Path:
    _require_nofollow()
    root = pathlib.Path(os.path.abspath(repo))
    try:
        path_before = root.lstat()
        _reject_dir_node(path_before, "Repository root")
        descriptor = _open_dir(root, "Repository root")
        try:
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = root.lstat()
    except ManifestContractError:
        raise
    except OSError as exc:
        raise ManifestContractError("Repository root must be a regular directory.") from exc
    if (
        stat.S_ISLNK(path_before.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or _identity(path_before) != _identity(opened)
        or _identity(opened) != _identity(path_after)
    ):
        raise ManifestContractError("Repository root must be a regular directory.")
    return root


def _bind_parent_chain(
    root: pathlib.Path,
    relative: str,
    label: str,
    *,
    leaf_must_exist: bool,
) -> tuple[int, os.stat_result, pathlib.Path, str]:
    parts = _split_relative(relative, label)
    cursor = root
    parent_fd = _open_dir(root, f"{label} repository")
    try:
        parent_info = os.fstat(parent_fd)
        if _identity(parent_info) != _identity(root.lstat()):
            raise ManifestContractError(f"{label} repository changed while it was bound.")
        for index, part in enumerate(parts):
            is_leaf = index == len(parts) - 1
            cursor = cursor / part
            try:
                path_info = os.lstat(part, dir_fd=parent_fd)
            except FileNotFoundError as exc:
                if is_leaf and not leaf_must_exist:
                    return parent_fd, parent_info, cursor, "/".join(parts)
                raise ManifestContractError(
                    f"{label} does not exist: {'/'.join(parts)}"
                ) from exc
            except OSError as exc:
                raise ManifestContractError(f"{label} is unreadable.") from exc
            if is_leaf:
                if not leaf_must_exist:
                    if stat.S_ISLNK(path_info.st_mode):
                        raise ManifestContractError(f"{label} traverses a symbolic link.")
                    if _is_special_node(path_info):
                        raise ManifestContractError(
                            f"{label} is a FIFO or special node and is rejected before opening."
                        )
                    raise ManifestContractError(f"Refusing to overwrite {label}: {cursor}")
                _reject_leaf_node(path_info, label)
            else:
                _reject_dir_node(path_info, f"{label} parent")
            flags = _open_flags() if is_leaf else _directory_flags()
            try:
                child_fd = os.open(part, flags, dir_fd=parent_fd)
            except FileNotFoundError as exc:
                raise ManifestContractError(
                    f"{label} does not exist: {'/'.join(parts)}"
                ) from exc
            except OSError as exc:
                raise ManifestContractError(f"{label} is unreadable.") from exc
            try:
                opened = os.fstat(child_fd)
                path_info = os.lstat(part, dir_fd=parent_fd)
            except OSError as exc:
                os.close(child_fd)
                raise ManifestContractError(f"{label} is unreadable.") from exc
            if _identity(opened) != _identity(path_info):
                os.close(child_fd)
                raise ManifestContractError(f"{label} changed while it was bound.")
            if stat.S_ISLNK(path_info.st_mode):
                os.close(child_fd)
                raise ManifestContractError(f"{label} traverses a symbolic link.")
            if is_leaf:
                if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                    os.close(child_fd)
                    raise ManifestContractError(
                        f"{label} must be a distinct regular file, not a hard link."
                    )
                os.close(parent_fd)
                parent_fd = -1
                return child_fd, opened, cursor, "/".join(parts)
            if not stat.S_ISDIR(opened.st_mode):
                os.close(child_fd)
                raise ManifestContractError(f"{label} parent is not a directory.")
            os.close(parent_fd)
            parent_fd = child_fd
        raise ManifestContractError(f"{label} cannot be the repository root.")
    except Exception:
        if parent_fd >= 0:
            os.close(parent_fd)
        raise


def _bind_directory(
    root: pathlib.Path,
    relative: str,
    label: str,
) -> tuple[int, os.stat_result, pathlib.Path, str]:
    parts = _split_relative(relative, label)
    cursor = root
    parent_fd = _open_dir(root, f"{label} repository")
    try:
        parent_info = os.fstat(parent_fd)
        if _identity(parent_info) != _identity(root.lstat()):
            raise ManifestContractError(f"{label} repository changed while it was bound.")
        for part in parts:
            cursor = cursor / part
            try:
                path_info = os.lstat(part, dir_fd=parent_fd)
            except FileNotFoundError as exc:
                raise ManifestContractError(
                    f"{label} does not exist: {'/'.join(parts)}"
                ) from exc
            except OSError as exc:
                raise ManifestContractError(f"{label} is unreadable.") from exc
            _reject_dir_node(path_info, f"{label} parent")
            try:
                child_fd = os.open(part, _directory_flags(), dir_fd=parent_fd)
            except FileNotFoundError as exc:
                raise ManifestContractError(
                    f"{label} does not exist: {'/'.join(parts)}"
                ) from exc
            except OSError as exc:
                raise ManifestContractError(f"{label} is unreadable.") from exc
            try:
                opened = os.fstat(child_fd)
                path_after = os.lstat(part, dir_fd=parent_fd)
            except OSError as exc:
                os.close(child_fd)
                raise ManifestContractError(f"{label} is unreadable.") from exc
            if (
                _identity(opened) != _identity(path_info)
                or _identity(opened) != _identity(path_after)
                or not stat.S_ISDIR(opened.st_mode)
            ):
                os.close(child_fd)
                raise ManifestContractError(
                    f"{label} parent must already be a regular directory."
                )
            os.close(parent_fd)
            parent_fd = child_fd
        return parent_fd, opened, cursor, "/".join(parts)
    except Exception:
        if parent_fd >= 0:
            os.close(parent_fd)
        raise


def bind_repo_file(
    repo: pathlib.Path,
    relative: str,
    label: str,
    *,
    max_bytes: int,
) -> tuple[bytes, os.stat_result, str]:
    root = _repo_root(repo)
    descriptor = -1
    try:
        descriptor, before, _path, posix = _bind_parent_chain(
            root, relative, label, leaf_must_exist=True
        )
        if before.st_size <= 0:
            raise ManifestContractError(f"{label} is empty.")
        if before.st_size > max_bytes:
            raise ManifestContractError(
                f"{label} exceeds the outer size ceiling before reading."
            )
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(READ_CHUNK, remaining))
            if not block:
                raise ManifestContractError(f"{label} ended before its declared size.")
            remaining -= len(block)
            digest.update(block)
            chunks.append(block)
        extra = os.read(descriptor, 1)
        if extra:
            raise ManifestContractError(f"{label} grew while it was read.")
        finished = os.fstat(descriptor)
        if _identity(before) != _identity(finished):
            raise ManifestContractError(f"{label} changed while it was read.")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise ManifestContractError(f"{label} size is inconsistent.")
        del digest
        return payload, before, posix
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_stable_file(
    path: pathlib.Path,
    label: str,
    *,
    max_bytes: int = MAX_JSON_BYTES,
) -> tuple[bytes, os.stat_result]:
    absolute = pathlib.Path(os.path.abspath(path))
    descriptor = -1
    try:
        before = absolute.lstat()
        _reject_leaf_node(before, label)
        if before.st_size <= 0:
            raise ManifestContractError(f"{label} is empty.")
        if before.st_size > max_bytes:
            raise ManifestContractError(
                f"{label} exceeds the outer size ceiling before reading."
            )
        descriptor = _open_nofollow(absolute, label)
        opened = os.fstat(descriptor)
        if _identity(before) != _identity(opened):
            raise ManifestContractError(f"{label} changed while it was opened.")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            block = os.read(descriptor, min(READ_CHUNK, remaining))
            if not block:
                raise ManifestContractError(f"{label} ended before its declared size.")
            remaining -= len(block)
            chunks.append(block)
        extra = os.read(descriptor, 1)
        if extra:
            raise ManifestContractError(f"{label} grew while it was read.")
        finished = os.fstat(descriptor)
        after = absolute.lstat()
    except ManifestContractError:
        raise
    except OSError as exc:
        raise ManifestContractError(f"{label} is unreadable.") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not (_identity(before) == _identity(opened) == _identity(finished) == _identity(after)):
        raise ManifestContractError(f"{label} changed while it was read.")
    payload = b"".join(chunks)
    if len(payload) != before.st_size:
        raise ManifestContractError(f"{label} size is inconsistent.")
    return payload, before


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    payload, _info = read_stable_file(path, "Hashed file")
    return sha256_bytes(payload)


def _packaging_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent


def reviewed_engine_archive_path(name: str, label: str) -> pathlib.Path:
    path = _packaging_dir() / ENGINE_ARCHIVE_DIR / name
    try:
        before = path.lstat()
    except OSError as suc:
        raise ManifestContractError(
            OWNER_INPUT_ARCHIVE_MISSING.format(label=label)
        ) from suc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ManifestContractError(
            OWNER_INPUT_ARCHIVE_MISSING.format(label=label)
        )
    return path


def _require_engine_hex64(value: str, label: str) -> str:
    if type(value) is not str or HEX64.match(value) is None:
        raise ManifestContractError(f"{label} must be a 64-hex digest")
    return value


def _tree_members_from_tar_gz_bytes(
    payload: bytes,
    label: str,
    *,
    strip_prefix: str,
    require_license: bool = False,
) -> list[str]:
    members: list[str] = []
    seen: set[str] = set()
    folded: set[str] = set()
    total_files = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
            for member in tar.getmembers():
                if len(seen) >= MAX_MEMBERS:
                    raise ManifestContractError(
                        f"{label} member-count limit exceeded"
                    )
                name = member.name.replace("\\", "/")
                parts = [part for part in name.split("/") if part]
                if (
                    name.startswith("/")
                    or any(part in {".", ".."} for part in parts)
                    or len(name.encode("utf-8")) > MAX_PATH_BYTES
                    or len(parts) > MAX_PATH_DEPTH
                ):
                    raise ManifestContractError(
                        f"{label} member path is unsafe: {member.name}"
                    )
                canonical = "/".join(parts)
                collision = canonical.casefold()
                if canonical in seen or collision in folded:
                    raise ManifestContractError(
                        f"{label} duplicate, Unicode, or case-fold member collision: "
                        f"{member.name}"
                    )
                seen.add(canonical)
                folded.add(collision)
                if (
                    member.issym()
                    or member.islnk()
                    or member.isdev()
                    or member.isfifo()
                    or member.ischr()
                    or member.isblk()
                ):
                    raise ManifestContractError(
                        f"{label} member type is unsafe: {member.name}"
                    )
                if member.linkname:
                    raise ManifestContractError(
                        f"{label} link target is not allowed: {member.name}"
                    )
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ManifestContractError(
                        f"{label} member type is unsafe: {member.name}"
                    )
                if not parts or parts[0] != strip_prefix:
                    raise ManifestContractError(
                        f"{label} member is outside {strip_prefix}: {member.name}"
                    )
                relative = "/".join(parts[1:])
                if not relative:
                    raise ManifestContractError(
                        f"{label} member path is unsafe: {member.name}"
                    )
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise ManifestContractError(
                        f"{label} member is unreadable: {member.name}"
                    )
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise ManifestContractError(
                        f"{label} member exceeds the per-member size limit: "
                        f"{member.name}"
                    )
                total_files += member.size
                _check_expansion(total_files, len(payload), label)
                hasher = hashlib.sha256()
                measured = 0
                while True:
                    block = extracted.read(READ_CHUNK)
                    if not block:
                        break
                    measured += len(block)
                    if measured > member.size:
                        raise ManifestContractError(
                            f"{label} member size is inconsistent: {member.name}"
                        )
                    hasher.update(block)
                if measured != member.size:
                    raise ManifestContractError(
                        f"{label} member size is inconsistent: {member.name}"
                    )
                digest = hasher.hexdigest()
                members.append(f"file {member.size} {digest} {relative}\n")
    except ManifestContractError:
        raise
    except tarfile.TarError as suc:
        raise ManifestContractError(f"{label} archive is not a safe tar.gz") from suc
    if not members:
        raise ManifestContractError(f"{label} archive has no authenticated files")
    if require_license:
        license_digest = None
        for line in members:
            parts = line.rstrip("\n").split(" ", 3)
            if len(parts) == 4 and parts[0] == "file" and parts[3] == "LICENSE":
                license_digest = parts[2]
                break
        if license_digest is None:
            raise ManifestContractError(f"{label} LICENSE is required")
        if license_digest != XRAY_LICENSE_SHA256:
            raise ManifestContractError(
                f"{label} LICENSE is not the authenticated source"
            )
    return members


def _tree_digest_from_tar_gz_bytes(
    payload: bytes,
    label: str,
    *,
    strip_prefix: str,
    require_license: bool = False,
) -> str:
    members = _tree_members_from_tar_gz_bytes(
        payload,
        label,
        strip_prefix=strip_prefix,
        require_license=require_license,
    )
    members.sort()
    return sha256_bytes("".join(members).encode("utf-8"))


def _overlay_xray_identity_members(members: list[str], label: str) -> list[str]:
    for line in members:
        parts = line.rstrip("\n").split(" ", 3)
        if len(parts) == 4 and parts[0] == "file" and parts[3] == XRAY_IDENTITY_RELATIVE:
            raise ManifestContractError(
                f"{label} archive must not include {XRAY_IDENTITY_RELATIVE}"
            )
    identity_bytes = XRAY_IDENTITY_TEXT.encode("ascii")
    overlaid = list(members)
    overlaid.append(
        f"file {len(identity_bytes)} {XRAY_IDENTITY_SHA256} {XRAY_IDENTITY_RELATIVE}\n"
    )
    overlaid.sort()
    return overlaid


def xray_owner_tree_sha256_from_archive_bytes(payload: bytes) -> str:
    if type(payload) is not bytes or not payload:
        raise ManifestContractError("Xray source archive bytes are required")
    members = _tree_members_from_tar_gz_bytes(
        payload,
        "Xray source",
        strip_prefix=XRAY_SOURCE_STRIP_PREFIX,
        require_license=True,
    )
    overlaid = _overlay_xray_identity_members(members, "Xray source")
    tree_digest = sha256_bytes("".join(overlaid).encode("utf-8"))
    archive_digest = sha256_bytes(payload)
    if archive_digest == tree_digest:
        raise ManifestContractError(
            "Xray source archive digest cannot equal its owner-tree identity"
        )
    return tree_digest


def reviewed_engine_archive_identities(
    name: str,
    label: str,
    *,
    strip_prefix: str,
    require_license: bool = False,
) -> tuple[str, str]:
    path = reviewed_engine_archive_path(name, label)
    try:
        payload, _info = read_stable_file(
            path, label, max_bytes=MAX_SOURCE_ARCHIVE_BYTES
        )
    except ManifestContractError as suc:
        raise ManifestContractError(
            OWNER_INPUT_ARCHIVE_MISSING.format(label=label)
        ) from suc
    archive_digest = sha256_bytes(payload)
    tree_digest = _tree_digest_from_tar_gz_bytes(
        payload,
        label,
        strip_prefix=strip_prefix,
        require_license=require_license,
    )
    if archive_digest == tree_digest:
        raise ManifestContractError(
            f"{label} archive digest cannot equal its tree identity"
        )
    return archive_digest, tree_digest


def xray_source_identities() -> tuple[str, str]:
    path = reviewed_engine_archive_path(XRAY_SOURCE_ARCHIVE_NAME, "Xray source")
    try:
        payload, _info = read_stable_file(
            path, "Xray source", max_bytes=MAX_SOURCE_ARCHIVE_BYTES
        )
    except ManifestContractError as suc:
        raise ManifestContractError(
            OWNER_INPUT_ARCHIVE_MISSING.format(label="Xray source")
        ) from suc
    archive_digest = sha256_bytes(payload)
    tree_digest = xray_owner_tree_sha256_from_archive_bytes(payload)
    if archive_digest == tree_digest:
        raise ManifestContractError(
            "Xray source archive digest cannot equal its owner-tree identity"
        )
    return archive_digest, tree_digest


def xray_source_archive_sha256() -> str:
    return xray_source_identities()[0]


def xray_source_tree_sha256() -> str:
    return xray_source_identities()[1]


def store_gomodcache_archive_sha256() -> str:
    return reviewed_engine_archive_identities(
        STORE_GOMODCACHE_ARCHIVE_NAME,
        "Go module cache",
        strip_prefix=STORE_GOMODCACHE_STRIP_PREFIX,
    )[0]


def store_gomodcache_tree_sha256() -> str:
    return reviewed_engine_archive_identities(
        STORE_GOMODCACHE_ARCHIVE_NAME,
        "Go module cache",
        strip_prefix=STORE_GOMODCACHE_STRIP_PREFIX,
    )[1]


def _engine_source_digests() -> tuple[str, str, str]:
    xray_archive, xray_tree = xray_source_identities()
    gomod = store_gomodcache_archive_sha256()
    return xray_archive, xray_tree, gomod


def secure_repo_path(
    repo: pathlib.Path,
    candidate: pathlib.Path,
    label: str,
    *,
    must_exist: bool,
) -> pathlib.Path:
    root = _repo_root(repo)
    absolute = pathlib.Path(
        os.path.abspath(candidate if candidate.is_absolute() else root / candidate)
    )
    try:
        relative = absolute.relative_to(root)
    except ValueError as exc:
        raise ManifestContractError(
            f"{label} must stay inside the repository."
        ) from exc
    posix = relative.as_posix()
    descriptor = -1
    try:
        descriptor, _info, bound, _posix = _bind_parent_chain(
            root, posix, label, leaf_must_exist=must_exist
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if bound != absolute:
        raise ManifestContractError(f"{label} changed while it was bound.")
    return absolute


def _write_new(path: pathlib.Path, payload: bytes, label: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ManifestContractError(f"Refusing to overwrite {label}: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _timestamp(value: object, label: str) -> dt.datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise ManifestContractError(f"{label} must be an RFC3339 UTC timestamp.")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ManifestContractError(f"{label} is malformed.") from exc
    if parsed.tzinfo is None:
        raise ManifestContractError(f"{label} must include a timezone.")
    return parsed.astimezone(dt.timezone.utc)


def _utc_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _require_fresh(
    created: dt.datetime,
    label: str,
    *,
    now: dt.datetime | None = None,
) -> None:
    checked_at = now or dt.datetime.now(tz=dt.timezone.utc)
    if created > checked_at + MAX_CLOCK_SKEW or checked_at - created > MAX_AGE:
        raise ManifestContractError(f"{label} is stale or future-dated.")


def _require_type(value: object, expected: type, label: str) -> object:
    if type(value) is not expected:
        raise ManifestContractError(
            f"{label} must be an exact {expected.__name__} JSON type."
        )
    return value


def _require_str(value: object, label: str) -> str:
    return _require_type(value, str, label)  # type: ignore[return-value]


def _require_int(value: object, label: str) -> int:
    return _require_type(value, int, label)  # type: ignore[return-value]


def _require_bool(value: object, label: str) -> bool:
    return _require_type(value, bool, label)  # type: ignore[return-value]


def _require_sha256(value: object, label: str) -> str:
    digest = _require_str(value, label)
    if HEX64.fullmatch(digest) is None:
        raise ManifestContractError(f"{label} must be 64 lowercase hex characters.")
    return digest


def _require_issuance(value: object, label: str) -> str:
    issuance = _require_str(value, label)
    if ISSUANCE_ID.fullmatch(issuance) is None:
        raise ManifestContractError(f"{label} must be a 32-hex issuance identity.")
    return issuance


def _assert_json_types(value: object, label: str) -> None:
    kind = type(value)
    if kind is dict:
        for key, nested in value.items():
            if type(key) is not str:
                raise ManifestContractError(f"{label} JSON object keys must be strings.")
            _assert_json_types(nested, label)
        return
    if kind is list:
        for nested in value:
            _assert_json_types(nested, label)
        return
    if kind in {str, int, bool, type(None)}:
        return
    raise ManifestContractError(
        f"{label} contains a non-exact JSON type; bool coercion and floats are refused."
    )


def _exact(record: object, keys: set[str], label: str) -> dict[str, object]:
    if type(record) is not dict or set(record) != keys:
        raise ManifestContractError(f"{label} schema fields are invalid.")
    _assert_json_types(record, label)
    return record


def _strict_json_value(payload: bytes, label: str) -> object:
    if len(payload) > MAX_JSON_BYTES:
        raise ManifestContractError(f"{label} exceeds the JSON size ceiling.")

    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str:
                raise ManifestContractError(f"{label} JSON object keys must be strings.")
            if key in document:
                raise ManifestContractError(f"{label} has a duplicate JSON key.")
            document[key] = value
        return document

    def reject_constant(value: str) -> object:
        raise ManifestContractError(f"{label} contains a non-exact JSON constant.")

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except ManifestContractError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestContractError(f"{label} is not valid UTF-8 JSON.") from exc
    _assert_json_types(document, label)
    return document


def _strict_json_object(payload: bytes, label: str) -> dict[str, object]:
    document = _strict_json_value(payload, label)
    if type(document) is not dict:
        raise ManifestContractError(f"{label} must be one JSON object.")
    return document


def validate_source(source_url: str, source_sha256: str) -> None:
    if type(source_url) is not str or type(source_sha256) is not str:
        raise ManifestContractError("Source identity must use exact string types.")
    parsed = urllib.parse.urlsplit(source_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "downloads.winsvpn.org"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not source_url.startswith(REVIEWED_SOURCE_URL_PREFIX)
        or not parsed.path.endswith(".tar.gz")
    ):
        raise ManifestContractError(
            "Source URL must be credential-free HTTPS archive URL without query or fragment."
        )
    if HEX64.fullmatch(source_sha256) is None:
        raise ManifestContractError(
            "Source SHA-256 must be 64 lowercase hex characters."
        )


def _canonical_linux_versions(root: pathlib.Path) -> tuple[str, str, str]:
    payload, _info, _posix = bind_repo_file(
        root,
        RELEASE_IDENTITY_PATH.as_posix(),
        "Release identity ruling",
        max_bytes=MAX_JSON_BYTES,
    )
    identity = _strict_json_object(payload, "Release identity ruling")
    _exact(
        identity,
        {
            "schema_version",
            "canonical_release",
            "marketing_version",
            "build_number",
            "platform_mappings",
        },
        "Release identity ruling",
    )
    platform_mappings = identity.get("platform_mappings")
    if type(platform_mappings) is not dict:
        raise ManifestContractError(
            "Release identity platform mappings are invalid."
        )
    linux = _exact(
        platform_mappings.get("linux"),
        {"appstream_version", "debian_version"},
        "Linux release identity mapping",
    )
    marketing_version = _require_str(
        identity.get("marketing_version"), "marketing_version"
    )
    build_number = _require_int(identity.get("build_number"), "build_number")
    appstream_version = _require_str(
        linux.get("appstream_version"), "appstream_version"
    )
    debian_version = _require_str(linux.get("debian_version"), "debian_version")
    schema_version = _require_int(identity.get("schema_version"), "schema_version")
    canonical_release = _require_str(
        identity.get("canonical_release"), "canonical_release"
    )
    if (
        schema_version != 2
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", marketing_version) is None
        or build_number < 1
        or canonical_release != f"{marketing_version}+{build_number}"
        or appstream_version != marketing_version
        or debian_version != f"{marketing_version}-{build_number}"
    ):
        raise ManifestContractError(
            "Linux release identity mapping is inconsistent or malformed."
        )
    return marketing_version, debian_version, canonical_release


def source_freeze_receipt_relative(release: str) -> str:
    if type(release) is not str or not release or "/" in release or "\\" in release:
        raise ManifestContractError("source-freeze release identity is unsafe.")
    return f".artifacts/release-freeze-{release}/{SOURCE_FREEZE_RECEIPT_NAME}"


def _minimal_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = dict(MINIMAL_SUBPROCESS_ENV)
    if extra:
        for key, value in extra.items():
            if type(key) is not str or type(value) is not str or not key or "\0" in key:
                raise ManifestContractError("subprocess environment is unsafe.")
            if key in {"PYTHONPATH", "PYTHONHOME", "PYTHONSAFEPATH", "BASH_ENV", "ENV"}:
                raise ManifestContractError("refusing ambient interpreter or shell env.")
            env[key] = value
    return env


def validate_shell(script: str, *, require_pinned_flutter: bool = True) -> None:
    if type(script) is not str or not script or not script.endswith("\n") or "\0" in script:
        raise ManifestContractError("generated shell must be a newline-terminated script.")
    if re.search(r"(?m)^[ \t]*flutter(?:\s|$)", script) or re.search(
        r"(?m)^[ \t]*/usr/bin/env[ \t]+flutter(?:\s|$)", script
    ):
        raise ManifestContractError(
            "generated shell must not invoke ambient flutter."
        )
    if require_pinned_flutter and (
        "flutter_sdk=" not in script or '"$flutter_sdk"' not in script
    ):
        raise ManifestContractError(
            "generated shell must not invoke ambient flutter."
        )
    temporary = tempfile.TemporaryDirectory(prefix="winsvpn-manifest-shell-")
    try:
        path = pathlib.Path(temporary.name) / "script.sh"
        _write_new(path, script.encode("utf-8"), "generated shell snapshot")
        try:
            result = subprocess.run(
                [BASH, "-n", os.path.abspath(path)],
                check=False,
                capture_output=True,
                cwd="/",
                env=_minimal_env(),
                stdin=subprocess.DEVNULL,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ManifestContractError(
                f"unable to execute bash -n on generated shell: {exc}"
            ) from exc
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise ManifestContractError(
                f"generated shell syntax is invalid: {detail or 'bash -n failed'}"
            )
    finally:
        temporary.cleanup()


def live_shell_text(script: str) -> str:
    if type(script) is not str:
        raise ManifestContractError("generated shell must be a newline-terminated script.")
    lines: list[str] = []
    for line in script.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _engine_install_order(live: str) -> list[str]:
    return ENGINE_INSTALL_LINE.findall(live)


def validate_engine_source_declarations(artifact_text: str) -> None:
    if type(artifact_text) is not str or not artifact_text:
        raise ManifestContractError("store recipe artifact text is missing.")
    xray_digest, xray_tree, gomod_digest = _engine_source_digests()
    required = (
        REVIEWED_GO_ARCHIVE_URL["x64"],
        REVIEWED_GO_ARCHIVE_SHA256["x64"],
        REVIEWED_GO_ARCHIVE_NAME["x64"],
        REVIEWED_GO_ARCHIVE_URL["arm64"],
        REVIEWED_GO_ARCHIVE_SHA256["arm64"],
        REVIEWED_GO_ARCHIVE_NAME["arm64"],
        AWG_GO_SOURCE_URL,
        AWG_GO_SOURCE_SHA256,
        AWG_TOOLS_ZIP_URL,
        AWG_TOOLS_ZIP_SHA256,
        AWG_TOOLS_SOURCE_URL,
        AWG_TOOLS_SOURCE_SHA256,
        AWG_TOOLS_COPYING_URL,
        AWG_TOOLS_COPYING_SHA256,
        AWG_ARM64_PREBUILT_URL,
        REVIEWED_ENGINE_PAYLOAD_SHA256["arm64"]["awg"],
        AWG_QUICK_PREBUILT_URL,
        REVIEWED_ENGINE_PAYLOAD_SHA256["arm64"]["awg-quick"],
        XRAY_SOURCE_URL,
        xray_digest,
        xray_tree,
        XRAY_COMMIT,
        XRAY_TAG,
        XRAY_IDENTITY_SHA256,
        STORE_GOMODCACHE_URL,
        gomod_digest,
        WINN_GOSUM_SHA256,
        REVIEWED_CLANG_VERSION,
        REVIEWED_BINUTILS_PACKAGE,
    )
    missing = [marker for marker in required if marker not in artifact_text]
    if missing:
        raise ManifestContractError(
            "store recipe must declare engine source artifacts before build: "
            + ", ".join(missing)
        )
    if "source-type: git" in artifact_text or '"type": "git"' in artifact_text:
        raise ManifestContractError(
            "store recipe must declare Xray as a SHA-256-authenticated archive, not git."
        )
    if XRAY_GIT_URL in artifact_text:
        raise ManifestContractError(
            "store recipe must not clone Xray at build time."
        )


def validate_recipe_payload(script: str) -> None:
    live = live_shell_text(script)
    missing = [marker for marker in REQUIRED_LIVE_PAYLOAD if marker not in live]
    if missing:
        raise ManifestContractError(
            "store recipe payload is incomplete: " + ", ".join(missing)
        )
    if BUNDLE_ENGINE_COPY.search(live) is not None:
        raise ManifestContractError(
            "store recipe must not copy engine payloads from the Flutter bundle."
        )
    if STAGE_STORE_ENGINES not in live:
        raise ManifestContractError(
            "store recipe must stage engine payloads explicitly."
        )
    quoted_helper = f'{BASH} "{STAGE_STORE_ENGINES}"'
    if quoted_helper not in live:
        raise ManifestContractError(
            "store recipe must invoke the engine helper with a pinned quoted bash."
        )
    if ENGINE_CHECKSUM_COMMAND not in live:
        raise ManifestContractError(
            "store recipe must SHA-256 verify architecture-bound engine payloads."
        )
    if WINN_DATAPATH_BIND not in live:
        raise ManifestContractError(
            "store recipe must O_NOFOLLOW/hash-bind winn-datapath before install."
        )
    if FLUTTER_BUNDLE_ENGINE_REFUSAL not in live:
        raise ManifestContractError(
            "store recipe must refuse Flutter-bundle engine leftovers."
        )
    if HOST_TARGET_CROSS_BUILD_REFUSAL not in live:
        raise ManifestContractError(
            "store recipe must bind host/target Flutter architecture before copies."
        )
    if "WINS_ENGINE_SOURCE_ROOT" not in live:
        raise ManifestContractError(
            "store recipe must consume declared local engine source artifacts."
        )
    if 'find "$bundle"' not in live:
        raise ManifestContractError(
            "store recipe must refuse nested Flutter-bundle engine leftovers."
        )
    if SYMLINK_ENGINE_DEST_REFUSAL not in live:
        raise ManifestContractError(
            "store recipe must refuse symlink engine destinations."
        )
    if re.search(r"(?m)^[ \t]*curl\b", live) is not None or "git clone" in live:
        raise ManifestContractError(
            "store recipe must not download engine sources during build."
        )
    order = _engine_install_order(live)
    if order != list(ENGINE_INSTALL_ORDER):
        raise ManifestContractError(
            "store recipe must install Winn v3 then AWG then Xray in that order."
        )
    if 'install -Dm0755 "$engine_stage/' in live or re.search(
        r"install\s+-D[^\n]*\$engine_stage/", live
    ):
        raise ManifestContractError(INSTALL_D_ENGINE_REFUSAL)
    for arch in ("x64", "arm64"):
        pins = REVIEWED_ENGINE_PAYLOAD_SHA256[arch]
        missing_pins = [digest for digest in pins.values() if digest not in live]
        if missing_pins:
            raise ManifestContractError(
                f"store recipe is missing {arch} engine SHA-256 pins."
            )


def validate_metainfo(
    repo: pathlib.Path,
    version: str,
    *,
    app_id: str = METADATA_ID,
    desktop_id: str = METADATA_DESKTOP_ID,
    binary: str = METADATA_BINARY,
) -> dict[str, object]:
    if type(version) is not str or not version:
        raise ManifestContractError("AppStream metainfo version is invalid.")
    root = _repo_root(repo)
    path = secure_repo_path(
        root, pathlib.Path(METADATA_RELATIVE), "AppStream metainfo", must_exist=True
    )
    payload, info = read_stable_file(path, "AppStream metainfo", max_bytes=MAX_JSON_BYTES)
    if info.st_size <= 0:
        raise ManifestContractError("AppStream metainfo is empty.")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ManifestContractError("AppStream metainfo is not UTF-8.") from exc
    try:
        document = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ManifestContractError(
            f"AppStream metainfo is not well-formed XML: {exc}"
        ) from exc
    if document.tag != "component" or document.attrib.get("type") != "desktop-application":
        raise ManifestContractError(
            "AppStream metainfo must be a desktop-application component."
        )
    children = list(document)
    counts: dict[str, int] = {}
    for child in children:
        tag = child.tag
        if not isinstance(tag, str):
            raise ManifestContractError("AppStream metainfo has invalid element tags.")
        counts[tag] = counts.get(tag, 0) + 1
    for required in REQUIRED_METADATA_SINGLES:
        if counts.get(required) != 1:
            raise ManifestContractError(
                f"AppStream metainfo must have exactly one <{required}> element."
            )

    def _one(tag: str):
        return next(child for child in children if child.tag == tag)

    if (_one("id").text or "").strip() != app_id or not app_id:
        raise ManifestContractError(
            "AppStream metainfo <id> does not match the app identity."
        )
    if not (_one("name").text or "").strip():
        raise ManifestContractError("AppStream metainfo <name> is empty.")
    if not (_one("summary").text or "").strip():
        raise ManifestContractError("AppStream metainfo <summary> is empty.")
    for license_tag in ("metadata_license", "project_license"):
        if not (_one(license_tag).text or "").strip():
            raise ManifestContractError(
                f"AppStream metainfo <{license_tag}> is empty."
            )
    launchable = _one("launchable")
    if launchable.attrib.get("type") != "desktop-id":
        raise ManifestContractError("AppStream metainfo launchable must be a desktop-id.")
    if (launchable.text or "").strip() != desktop_id:
        raise ManifestContractError(
            "AppStream metainfo launchable desktop-id does not match the desktop file."
        )
    if not _one("description").findall("p"):
        raise ManifestContractError(
            "AppStream metainfo description must contain paragraphs."
        )
    categories: list[str] = []
    for category in _one("categories").findall("category"):
        value = (category.text or "").strip()
        if not value:
            raise ManifestContractError(
                "AppStream metainfo categories must not be empty."
            )
        categories.append(value)
    if not categories:
        raise ManifestContractError(
            "AppStream metainfo must declare at least one category."
        )
    provided = [(p.text or "").strip() for p in _one("provides").findall("binary")]
    if binary not in provided:
        raise ManifestContractError(
            "AppStream metainfo <provides> must list the wins_vpn binary."
        )
    rating = _one("content_rating")
    if rating.attrib.get("type") != "oars-1.1":
        raise ManifestContractError("AppStream metainfo content_rating must be oars-1.1.")
    seen: set[str] = set()
    for attribute in rating.findall("content_attribute"):
        ident = attribute.attrib.get("id")
        value = attribute.text
        if ident in seen:
            raise ManifestContractError(
                f"AppStream metainfo content_attribute {ident} is duplicated."
            )
        seen.add(ident)
        if ident not in OARS_ATTRIBUTE_IDS or value not in METADATA_VALID_OARS_VALUES:
            raise ManifestContractError(
                f"AppStream metainfo content_attribute {ident} is invalid or out of range."
            )
    missing_oars = sorted(OARS_ATTRIBUTE_IDS - seen)
    if missing_oars:
        raise ManifestContractError(
            "AppStream metainfo content_rating is missing OARS attributes: "
            + ", ".join(missing_oars)
        )
    releases = _one("releases").findall("release")
    if not releases:
        raise ManifestContractError(
            "AppStream metainfo must declare at least one release."
        )
    current = [
        release
        for release in releases
        if (release.attrib.get("version") or "") == version
    ]
    if not current:
        raise ManifestContractError(
            f"AppStream metainfo must declare the current version {version}."
        )
    for release in current:
        release_date = release.attrib.get("date")
        if type(release_date) is not str or not release_date:
            raise ManifestContractError(
                f"AppStream release {version} must declare an ISO date."
            )
        try:
            dt.date.fromisoformat(release_date)
        except ValueError as exc:
            raise ManifestContractError(
                f"AppStream release {version} has an invalid date."
            ) from exc
        if not release.findall("description/p"):
            raise ManifestContractError(
                f"AppStream release {version} must describe changes."
            )
    return {
        "app_id": app_id,
        "release_version": version,
        "categories": categories,
        "oars_attributes": sorted(seen),
        "binary": binary,
        "bytes": info.st_size,
        "sha256": sha256_bytes(payload),
    }


def engine_install_dest(kind: str) -> str:
    if kind == "flatpak":
        return "/app/bin"
    if kind == "snap":
        return '"$CRAFT_PART_INSTALL/bin"'
    raise ManifestContractError(f"unsupported store kind for engine install: {kind}")


def engine_source_root_script(kind: str) -> str:
    if kind == "flatpak":
        root = "$PWD/engine-sources"
    elif kind == "snap":
        root = "$CRAFT_STAGE/engine-sources"
    else:
        raise ManifestContractError(f"unsupported store kind for engine sources: {kind}")
    return (
        f'WINS_ENGINE_SOURCE_ROOT="{root}"\n'
        "export WINS_ENGINE_SOURCE_ROOT\n"
        'test -d "$WINS_ENGINE_SOURCE_ROOT"\n'
        'test ! -L "$WINS_ENGINE_SOURCE_ROOT"\n'
    )


def host_target_arch_bind_script() -> str:
    return (
        'case "$(uname -m)" in\n'
        "  x86_64) host_flutter_arch=x64 ;;\n"
        "  aarch64|arm64) host_flutter_arch=arm64 ;;\n"
        "  *)\n"
        '    printf \'%s\\n\' "unsupported host architecture: $(uname -m)" >&2\n'
        "    exit 1\n"
        "    ;;\n"
        "esac\n"
        'if [ "$host_flutter_arch" != "$flutter_arch" ]; then\n'
        "  printf '%s\\n' "
        f'"{HOST_TARGET_CROSS_BUILD_REFUSAL}: '
        'host $host_flutter_arch, target $flutter_arch" >&2\n'
        "  exit 1\n"
        "fi\n"
    )


def engine_source_snap_parts() -> list[str]:
    arm64_awg = REVIEWED_ENGINE_PAYLOAD_SHA256["arm64"]["awg"]
    awg_quick = REVIEWED_ENGINE_PAYLOAD_SHA256["arm64"]["awg-quick"]
    xray_digest, xray_tree, gomod_digest = _engine_source_digests()
    return [
        "  engine-go-sdk-x64:",
        "    plugin: dump",
        f"    source: {json.dumps(REVIEWED_GO_ARCHIVE_URL['x64'], ensure_ascii=True)}",
        "    source-type: file",
        f"    source-checksum: sha256/{REVIEWED_GO_ARCHIVE_SHA256['x64']}",
        "    build-for: [amd64]",
        "    organize:",
        f"      {REVIEWED_GO_ARCHIVE_NAME['x64']}: engine-sources/go-sdk/{REVIEWED_GO_ARCHIVE_NAME['x64']}",
        "  engine-go-sdk-arm64:",
        "    plugin: dump",
        f"    source: {json.dumps(REVIEWED_GO_ARCHIVE_URL['arm64'], ensure_ascii=True)}",
        "    source-type: file",
        f"    source-checksum: sha256/{REVIEWED_GO_ARCHIVE_SHA256['arm64']}",
        "    build-for: [arm64]",
        "    organize:",
        f"      {REVIEWED_GO_ARCHIVE_NAME['arm64']}: engine-sources/go-sdk/{REVIEWED_GO_ARCHIVE_NAME['arm64']}",
        "  engine-awg-go-source:",
        "    plugin: dump",
        f"    source: {json.dumps(AWG_GO_SOURCE_URL, ensure_ascii=True)}",
        "    source-type: tar",
        f"    source-checksum: sha256/{AWG_GO_SOURCE_SHA256}",
        "    organize:",
        f"      amneziawg-go-{AWG_GO_COMMIT}: engine-sources/amneziawg-go",
        "  engine-awg-tools-zip:",
        "    plugin: dump",
        f"    source: {json.dumps(AWG_TOOLS_ZIP_URL, ensure_ascii=True)}",
        "    source-type: zip",
        f"    source-checksum: sha256/{AWG_TOOLS_ZIP_SHA256}",
        "    build-for: [amd64]",
        "    organize:",
        "      '*': engine-sources/awg-tools/",
        "  engine-awg-tools-src:",
        "    plugin: dump",
        f"    source: {json.dumps(AWG_TOOLS_SOURCE_URL, ensure_ascii=True)}",
        "    source-type: tar",
        f"    source-checksum: sha256/{AWG_TOOLS_SOURCE_SHA256}",
        "    build-for: [arm64]",
        "    organize:",
        f"      amneziawg-tools-{AWG_TOOLS_VERSION[1:]}: engine-sources/awg-tools-src",
        "  engine-awg-copying:",
        "    plugin: dump",
        f"    source: {json.dumps(AWG_TOOLS_COPYING_URL, ensure_ascii=True)}",
        "    source-type: file",
        f"    source-checksum: sha256/{AWG_TOOLS_COPYING_SHA256}",
        "    organize:",
        "      COPYING: engine-sources/amneziawg-tools-COPYING",
        "  engine-awg-prebuilt-arm64:",
        "    plugin: dump",
        f"    source: {json.dumps(AWG_ARM64_PREBUILT_URL, ensure_ascii=True)}",
        "    source-type: file",
        f"    source-checksum: sha256/{arm64_awg}",
        "    build-for: [arm64]",
        "    organize:",
        "      awg: engine-sources/awg-prebuilt/awg",
        "  engine-awg-quick-prebuilt:",
        "    plugin: dump",
        f"    source: {json.dumps(AWG_QUICK_PREBUILT_URL, ensure_ascii=True)}",
        "    source-type: file",
        f"    source-checksum: sha256/{awg_quick}",
        "    organize:",
        "      awg-quick: engine-sources/awg-prebuilt/awg-quick",
        f"    # arm64 AWG clang {REVIEWED_CLANG_VERSION} / binutils {REVIEWED_BINUTILS_PACKAGE} or prebuilt",
        "  engine-xray-source:",
        "    plugin: dump",
        f"    source: {json.dumps(XRAY_SOURCE_URL, ensure_ascii=True)}",
        "    source-type: tar",
        f"    source-checksum: sha256/{xray_digest}",
        "    organize:",
        f"      Xray-core-{XRAY_COMMIT}: engine-sources/xray-core",
        f"    # xray owner-tree {xray_tree}",
        "  engine-xray-identity:",
        "    plugin: dump",
        f"    source: {json.dumps(XRAY_IDENTITY_URL, ensure_ascii=True)}",
        "    source-type: file",
        f"    source-checksum: sha256/{XRAY_IDENTITY_SHA256}",
        "    organize:",
        "      xray-v26.9.30.identity: engine-sources/xray-core/.winsvpn-xray-identity",
        "  engine-go-mod-cache:",
        "    plugin: dump",
        f"    source: {json.dumps(STORE_GOMODCACHE_URL, ensure_ascii=True)}",
        "    source-type: tar",
        f"    source-checksum: sha256/{gomod_digest}",
        "    organize:",
        "      go-mod-cache: engine-sources/go-mod-cache",
        f"    # winn go.sum {WINN_GOSUM_SHA256}",
    ]


def engine_source_flatpak_sources() -> list[dict[str, object]]:
    arm64_awg = REVIEWED_ENGINE_PAYLOAD_SHA256["arm64"]["awg"]
    awg_quick = REVIEWED_ENGINE_PAYLOAD_SHA256["arm64"]["awg-quick"]
    xray_digest, xray_tree, gomod_digest = _engine_source_digests()
    return [
        {
            "type": "file",
            "url": REVIEWED_GO_ARCHIVE_URL["x64"],
            "sha256": REVIEWED_GO_ARCHIVE_SHA256["x64"],
            "dest": "engine-sources/go-sdk",
            "dest-filename": REVIEWED_GO_ARCHIVE_NAME["x64"],
            "only-arches": ["x86_64"],
        },
        {
            "type": "file",
            "url": REVIEWED_GO_ARCHIVE_URL["arm64"],
            "sha256": REVIEWED_GO_ARCHIVE_SHA256["arm64"],
            "dest": "engine-sources/go-sdk",
            "dest-filename": REVIEWED_GO_ARCHIVE_NAME["arm64"],
            "only-arches": ["aarch64"],
        },
        {
            "type": "archive",
            "url": AWG_GO_SOURCE_URL,
            "sha256": AWG_GO_SOURCE_SHA256,
            "dest": "engine-sources/amneziawg-go",
            "strip-components": 1,
        },
        {
            "type": "archive",
            "url": AWG_TOOLS_ZIP_URL,
            "sha256": AWG_TOOLS_ZIP_SHA256,
            "dest": "engine-sources/awg-tools",
            "only-arches": ["x86_64"],
        },
        {
            "type": "archive",
            "url": AWG_TOOLS_SOURCE_URL,
            "sha256": AWG_TOOLS_SOURCE_SHA256,
            "dest": "engine-sources/awg-tools-src",
            "strip-components": 1,
            "only-arches": ["aarch64"],
        },
        {
            "type": "file",
            "url": AWG_TOOLS_COPYING_URL,
            "sha256": AWG_TOOLS_COPYING_SHA256,
            "dest": "engine-sources",
            "dest-filename": "amneziawg-tools-COPYING",
        },
        {
            "type": "file",
            "url": AWG_ARM64_PREBUILT_URL,
            "sha256": arm64_awg,
            "dest": "engine-sources/awg-prebuilt",
            "dest-filename": "awg",
            "only-arches": ["aarch64"],
        },
        {
            "type": "file",
            "url": AWG_QUICK_PREBUILT_URL,
            "sha256": awg_quick,
            "dest": "engine-sources/awg-prebuilt",
            "dest-filename": "awg-quick",
            "x-winsvpn-arm64-awg-clang": REVIEWED_CLANG_VERSION,
            "x-winsvpn-arm64-awg-binutils": REVIEWED_BINUTILS_PACKAGE,
        },
        {
            "type": "archive",
            "url": XRAY_SOURCE_URL,
            "sha256": xray_digest,
            "dest": "engine-sources/xray-core",
            "strip-components": 1,
        },
        {
            "type": "file",
            "url": XRAY_IDENTITY_URL,
            "sha256": XRAY_IDENTITY_SHA256,
            "dest": "engine-sources/xray-core",
            "dest-filename": ".winsvpn-xray-identity",
            "x-winsvpn-xray-owner-tree-sha256": xray_tree,
        },
        {
            "type": "archive",
            "url": STORE_GOMODCACHE_URL,
            "sha256": gomod_digest,
            "dest": "engine-sources/go-mod-cache",
            "strip-components": 1,
            "x-winsvpn-winn-gosum-sha256": WINN_GOSUM_SHA256,
        },
    ]


def engine_stage_script(kind: str) -> str:
    dest = engine_install_dest(kind)
    x64 = REVIEWED_ENGINE_PAYLOAD_SHA256["x64"]
    arm64 = REVIEWED_ENGINE_PAYLOAD_SHA256["arm64"]
    return (
        engine_source_root_script(kind)
        + 'leftovers="$(find "$bundle" '
        '\\( -name winn-datapath -o -name awg-quick -o -name amneziawg-go '
        '-o -name awg -o -name xray \\) \\( -type f -o -type l \\) -print)"\n'
        'if [ -n "$leftovers" ]; then\n'
        "  printf '%s\\n' "
        f'"{FLUTTER_BUNDLE_ENGINE_REFUSAL}: $leftovers" >&2\n'
        "  exit 1\n"
        "fi\n"
        f'if [ -L {dest} ]; then\n'
        "  printf '%s\\n' "
        f'"{SYMLINK_ENGINE_DEST_REFUSAL}: {dest}" >&2\n'
        "  exit 1\n"
        "fi\n"
        f"if [ -e {dest} ]; then\n"
        f"  test -d {dest}\n"
        f"  test ! -L {dest}\n"
        "fi\n"
        f"mkdir -p {dest}\n"
        f"test -d {dest}\n"
        f"test ! -L {dest}\n"
        'if [ -L "$PWD/winsvpn-engine-stage" ]; then\n'
        "  printf '%s\\n' "
        f'"{SYMLINK_ENGINE_DEST_REFUSAL}: $PWD/winsvpn-engine-stage" >&2\n'
        "  exit 1\n"
        "fi\n"
        'engine_stage="$(mktemp -d "$PWD/winsvpn-engine-stage.XXXXXX")"\n'
        'test -d "$engine_stage"\n'
        'test ! -L "$engine_stage"\n'
        f"{BASH} \"{STAGE_STORE_ENGINES}\" "
        '"$engine_stage" "$flutter_arch"\n'
        'case "$flutter_arch" in\n'
        "  x64)\n"
        f"    expected_awg={x64['awg']}\n"
        f"    expected_awg_quick={x64['awg-quick']}\n"
        f"    expected_amneziawg_go={x64['amneziawg-go']}\n"
        f"    expected_xray={x64['xray']}\n"
        "    expected_elf_machine=62\n"
        "    ;;\n"
        "  arm64)\n"
        f"    expected_awg={arm64['awg']}\n"
        f"    expected_awg_quick={arm64['awg-quick']}\n"
        f"    expected_amneziawg_go={arm64['amneziawg-go']}\n"
        f"    expected_xray={arm64['xray']}\n"
        "    expected_elf_machine=183\n"
        "    ;;\n"
        "  *)\n"
        '    printf \'%s\\n\' "unsupported engine architecture: $flutter_arch" >&2\n'
        "    exit 1\n"
        "    ;;\n"
        "esac\n"
        "engine_checksums=\"$engine_stage/engine-payloads.sha256\"\n"
        "printf '%s  %s\\n' \"$expected_awg\" \"awg\" "
        "> \"$engine_checksums\"\n"
        "printf '%s  %s\\n' \"$expected_awg_quick\" \"awg-quick\" "
        ">> \"$engine_checksums\"\n"
        "printf '%s  %s\\n' \"$expected_amneziawg_go\" \"amneziawg-go\" "
        ">> \"$engine_checksums\"\n"
        "printf '%s  %s\\n' \"$expected_xray\" \"xray\" "
        ">> \"$engine_checksums\"\n"
        "python3 - \"$engine_stage\" \"$engine_checksums\" <<'PY'\n"
        "import hashlib, os, stat, sys\n"
        f"marker = {ENGINE_CHECKSUM_COMMAND!r}\n"
        "stage, listing = sys.argv[1], sys.argv[2]\n"
        "if marker != 'winsvpn-engine-payload-sha256-bind':\n"
        "    raise SystemExit('engine payload bind marker is missing')\n"
        "flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | os.O_NOFOLLOW\n"
        "before = os.lstat(listing)\n"
        "if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):\n"
        "    raise SystemExit('engine checksum listing must be a regular file')\n"
        "list_fd = os.open(listing, flags)\n"
        "try:\n"
        "    opened = os.fstat(list_fd)\n"
        "    if (opened.st_dev, opened.st_ino, opened.st_size) != (\n"
        "        before.st_dev, before.st_ino, before.st_size\n"
        "    ):\n"
        "        raise SystemExit('engine checksum listing changed while opened')\n"
        "    payload = os.read(list_fd, opened.st_size + 1)\n"
        "    if len(payload) != opened.st_size:\n"
        "        raise SystemExit('engine checksum listing size is inconsistent')\n"
        "finally:\n"
        "    os.close(list_fd)\n"
        "for line in payload.decode('ascii').splitlines():\n"
        "    digest, name = line.split('  ', 1)\n"
        "    path = os.path.join(stage, name)\n"
        "    path_before = os.lstat(path)\n"
        "    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):\n"
        "        raise SystemExit(name + ' must be a regular file')\n"
        "    fd = os.open(path, flags)\n"
        "    try:\n"
        "        info = os.fstat(fd)\n"
        "        if (info.st_dev, info.st_ino, info.st_size) != (\n"
        "            path_before.st_dev, path_before.st_ino, path_before.st_size\n"
        "        ):\n"
        "            raise SystemExit(name + ' changed while opened')\n"
        "        hasher = hashlib.sha256()\n"
        "        remaining = info.st_size\n"
        "        while remaining:\n"
        "            block = os.read(fd, min(1024 * 1024, remaining))\n"
        "            if not block:\n"
        "                raise SystemExit(name + ' ended before its declared size')\n"
        "            hasher.update(block)\n"
        "            remaining -= len(block)\n"
        "        if hasher.hexdigest() != digest:\n"
        "            raise SystemExit(name + ' SHA-256 verification failed')\n"
        "        finished = os.fstat(fd)\n"
        "        if finished.st_mtime_ns != info.st_mtime_ns:\n"
        "            raise SystemExit(name + ' changed while hashed')\n"
        "    finally:\n"
        "        os.close(fd)\n"
        f"winn_marker = {WINN_DATAPATH_BIND!r}\n"
        "if winn_marker != 'winsvpn-winn-datapath-sha256-bind':\n"
        "    raise SystemExit('winn-datapath bind marker is missing')\n"
        "winn_path = os.path.join(stage, 'winn-datapath')\n"
        "winn_before = os.lstat(winn_path)\n"
        "if stat.S_ISLNK(winn_before.st_mode) or not stat.S_ISREG(winn_before.st_mode):\n"
        "    raise SystemExit('winn-datapath must be a regular file')\n"
        "winn_fd = os.open(winn_path, flags)\n"
        "try:\n"
        "    winn_info = os.fstat(winn_fd)\n"
        "    if (winn_info.st_dev, winn_info.st_ino, winn_info.st_size) != (\n"
        "        winn_before.st_dev, winn_before.st_ino, winn_before.st_size\n"
        "    ):\n"
        "        raise SystemExit('winn-datapath changed while opened')\n"
        "    winn_hasher = hashlib.sha256()\n"
        "    remaining = winn_info.st_size\n"
        "    while remaining:\n"
        "        block = os.read(winn_fd, min(1024 * 1024, remaining))\n"
        "        if not block:\n"
        "            raise SystemExit('winn-datapath ended before its declared size')\n"
        "        winn_hasher.update(block)\n"
        "        remaining -= len(block)\n"
        "    winn_finished = os.fstat(winn_fd)\n"
        "    if winn_finished.st_mtime_ns != winn_info.st_mtime_ns:\n"
        "        raise SystemExit('winn-datapath changed while hashed')\n"
        "    if len(winn_hasher.hexdigest()) != 64:\n"
        "        raise SystemExit('winn-datapath SHA-256 bind failed')\n"
        "finally:\n"
        "    os.close(winn_fd)\n"
        "PY\n"
        "for engine in winn-datapath awg amneziawg-go xray; do\n"
        '  engine_path="$engine_stage/$engine"\n'
        '  test -f "$engine_path"\n'
        '  test ! -L "$engine_path"\n'
        '  test -x "$engine_path"\n'
        '  magic="$(od -An -tx1 -j0 -N4 -- "$engine_path" | tr -d \'[:space:]\')"\n'
        '  test "$magic" = 7f454c46\n'
        '  elf_class="$(od -An -tu1 -j4 -N1 -- "$engine_path" | tr -d \'[:space:]\')"\n'
        '  elf_data="$(od -An -tu1 -j5 -N1 -- "$engine_path" | tr -d \'[:space:]\')"\n'
        '  test "$elf_class" = 2\n'
        '  test "$elf_data" = 1\n'
        '  type_low="$(od -An -tu1 -j16 -N1 -- "$engine_path" | tr -d \'[:space:]\')"\n'
        '  type_high="$(od -An -tu1 -j17 -N1 -- "$engine_path" | tr -d \'[:space:]\')"\n'
        '  machine_low="$(od -An -tu1 -j18 -N1 -- "$engine_path" | tr -d \'[:space:]\')"\n'
        '  machine_high="$(od -An -tu1 -j19 -N1 -- "$engine_path" | tr -d \'[:space:]\')"\n'
        '  elf_type="$((type_low + 256 * type_high))"\n'
        '  machine="$((machine_low + 256 * machine_high))"\n'
        '  if [ "$elf_type" != 2 ] && [ "$elf_type" != 3 ]; then\n'
        "    printf '%s\\n' "
        '"engine ELF type must be ET_EXEC or ET_DYN: $engine" >&2\n'
        "    exit 1\n"
        "  fi\n"
        '  test "$machine" = "$expected_elf_machine"\n'
        "done\n"
        'test -f "$engine_stage/awg-quick"\n'
        'test ! -L "$engine_stage/awg-quick"\n'
        'test -x "$engine_stage/awg-quick"\n'
        "python3 -I - \"$engine_stage\" "
        f"{dest} <<'PY'\n"
        "import hashlib, os, stat, sys\n"
        "stage, dest = sys.argv[1], sys.argv[2]\n"
        "order = (\n"
        "    'winsvpn-engine-publish:winn-datapath',\n"
        "    'winsvpn-engine-publish:awg',\n"
        "    'winsvpn-engine-publish:awg-quick',\n"
        "    'winsvpn-engine-publish:amneziawg-go',\n"
        "    'winsvpn-engine-publish:xray',\n"
        ")\n"
        "read_flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | os.O_NOFOLLOW\n"
        "write_flags = (\n"
        "    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_CLOEXEC', 0)"
        " | os.O_NOFOLLOW\n"
        ")\n"
        "dest_before = os.lstat(dest)\n"
        "if stat.S_ISLNK(dest_before.st_mode) or not stat.S_ISDIR(dest_before.st_mode):\n"
        "    raise SystemExit('engine destination must be a regular directory')\n"
        "for marker in order:\n"
        "    name = marker.split(':', 1)[1]\n"
        "    source = os.path.join(stage, name)\n"
        "    target = os.path.join(dest, name)\n"
        "    before = os.lstat(source)\n"
        "    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):\n"
        "        raise SystemExit(name + ' must be a regular file')\n"
        "    src_fd = os.open(source, read_flags)\n"
        "    try:\n"
        "        info = os.fstat(src_fd)\n"
        "        if (info.st_dev, info.st_ino, info.st_size) != (\n"
        "            before.st_dev, before.st_ino, before.st_size\n"
        "        ):\n"
        "            raise SystemExit(name + ' changed while opened')\n"
        "        dest_fd = os.open(target, write_flags, 0o755)\n"
        "        try:\n"
        "            remaining = info.st_size\n"
        "            while remaining:\n"
        "                block = os.read(src_fd, min(1024 * 1024, remaining))\n"
        "                if not block:\n"
        "                    raise SystemExit(name + ' ended while publishing')\n"
        "                written = os.write(dest_fd, block)\n"
        "                if written != len(block):\n"
        "                    raise SystemExit(name + ' publish write truncated')\n"
        "                remaining -= len(block)\n"
        "            os.fchmod(dest_fd, 0o755)\n"
        "        finally:\n"
        "            os.close(dest_fd)\n"
        "    finally:\n"
        "        os.close(src_fd)\n"
        "    installed = os.lstat(target)\n"
        "    if stat.S_ISLNK(installed.st_mode) or not stat.S_ISREG(installed.st_mode):\n"
        "        raise SystemExit(name + ' destination must be a regular file')\n"
        "PY\n"
    )


def architecture_case_script(kind: str) -> str:
    if kind == "flatpak":
        return (
            'case "${FLATPAK_ARCH}" in\n'
            "  x86_64) flutter_arch=x64 ;;\n"
            "  aarch64) flutter_arch=arm64 ;;\n"
            "  *)\n"
            '    printf \'%s\\n\' "unsupported Flatpak architecture: ${FLATPAK_ARCH}" >&2\n'
            "    exit 1\n"
            "    ;;\n"
            "esac\n"
        )
    if kind == "snap":
        return (
            'case "${CRAFT_ARCH_BUILD_FOR}" in\n'
            "  amd64) flutter_arch=x64 ;;\n"
            "  arm64) flutter_arch=arm64 ;;\n"
            "  *)\n"
            '    printf \'%s\\n\' "unsupported Snap architecture: ${CRAFT_ARCH_BUILD_FOR}" >&2\n'
            "    exit 1\n"
            "    ;;\n"
            "esac\n"
        )
    raise ManifestContractError(f"unsupported store kind for architecture mapping: {kind}")


def run_architecture_mapping(kind: str, arch_value: str) -> str:
    if type(arch_value) is not str or not arch_value or "\0" in arch_value:
        raise ManifestContractError("architecture value is unsafe.")
    env_name = "FLATPAK_ARCH" if kind == "flatpak" else "CRAFT_ARCH_BUILD_FOR"
    script = (
        "set -eu\n"
        + architecture_case_script(kind)
        + 'printf \'%s\\n\' "$flutter_arch"\n'
    )
    validate_shell(script, require_pinned_flutter=False)
    temporary = tempfile.TemporaryDirectory(prefix="winsvpn-manifest-arch-")
    try:
        path = pathlib.Path(temporary.name) / "map.sh"
        _write_new(path, script.encode("utf-8"), "architecture mapping snapshot")
        try:
            result = subprocess.run(
                [BASH, os.path.abspath(path)],
                check=False,
                capture_output=True,
                cwd="/",
                env=_minimal_env({env_name: arch_value}),
                stdin=subprocess.DEVNULL,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ManifestContractError(
                f"unable to execute architecture mapping: {exc}"
            ) from exc
    finally:
        temporary.cleanup()
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ManifestContractError(
            detail or f"unsupported architecture mapping for {arch_value}"
        )
    mapped = result.stdout.decode("ascii", "replace").strip()
    if mapped not in {"x64", "arm64"}:
        raise ManifestContractError("architecture mapping did not yield x64 or arm64.")
    return mapped


def _tar_text(field: bytes, label: str) -> str:
    value, separator, padding = field.partition(b"\0")
    if separator and any(padding):
        raise ManifestContractError(f"non-zero TAR padding in {label}.")
    try:
        text = value.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ManifestContractError(f"non-UTF-8 TAR {label}.") from exc
    if "\x00" in text:
        raise ManifestContractError(f"embedded NUL in TAR {label}.")
    return text


def _tar_number(field: bytes, label: str) -> int:
    if field and field[0] & 0x80:
        raise ManifestContractError(f"base-256 TAR number rejected: {label}.")
    value = field.strip(b" \0")
    if not value:
        return 0
    if any(byte not in b"01234567" for byte in value):
        raise ManifestContractError(f"invalid TAR octal number: {label}.")
    return int(value, 8)


def _canonical_tar_path(name: str, label: str, expected_root: str | None) -> str:
    if any(ord(character) < 32 for character in name):
        raise ManifestContractError(f"{label} TAR member path contains a control character.")
    normalized = unicodedata.normalize("NFC", name)
    if (
        normalized != name
        or not name
        or name.startswith("/")
        or "\\" in name
        or "//" in name
    ):
        raise ManifestContractError(
            f"{label} TAR path traversal or go-style doubled separators rejected."
        )
    body = name[:-1] if name.endswith("/") else name
    if not body or "//" in body or body.startswith("/") or body.endswith("/"):
        raise ManifestContractError(
            f"{label} TAR path traversal or go-style doubled separators rejected."
        )
    parts = tuple(body.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise ManifestContractError(f"{label} TAR path traversal rejected.")
    pure = PurePosixPath(body)
    if pure.as_posix() != body or pure.parts != parts:
        raise ManifestContractError(f"{label} TAR member path is not canonical.")
    if len(body.encode("utf-8")) > MAX_PATH_BYTES:
        raise ManifestContractError(f"{label} TAR member path is too long.")
    if len(parts) > MAX_PATH_DEPTH:
        raise ManifestContractError(f"{label} TAR member path exceeds the depth limit.")
    if expected_root is not None and parts[0] != expected_root:
        raise ManifestContractError(
            f"{label} TAR member escaped its pinned top-level root."
        )
    return body


def _canonical_link_target(
    member: str, target: str, label: str, expected_root: str | None
) -> str:
    if any(ord(character) < 32 for character in target):
        raise ManifestContractError(f"{label} TAR link target contains a control character.")
    normalized = unicodedata.normalize("NFC", target)
    if (
        normalized != target
        or not target
        or target.startswith("/")
        or "\\" in target
        or "//" in target
    ):
        raise ManifestContractError(
            f"{label} TAR link traversal or go-style doubled separators rejected."
        )
    raw_parts = tuple(target.split("/"))
    if any(part in {"", "."} for part in raw_parts):
        raise ManifestContractError(f"{label} TAR link target is not canonical.")
    if PurePosixPath(target).as_posix() != target:
        raise ManifestContractError(f"{label} TAR link target is not canonical.")
    parts = list(PurePosixPath(member).parent.parts)
    for part in raw_parts:
        if part == "..":
            if not parts or (expected_root is not None and parts[0] != expected_root):
                raise ManifestContractError(f"{label} TAR symbolic link escaped its root.")
            if expected_root is not None and len(parts) <= 1:
                raise ManifestContractError(f"{label} TAR symbolic link escaped its root.")
            if not parts:
                raise ManifestContractError(f"{label} TAR symbolic link escaped its root.")
            parts.pop()
        else:
            parts.append(part)
    if expected_root is not None and (not parts or parts[0] != expected_root):
        raise ManifestContractError(f"{label} TAR symbolic link escaped its root.")
    if len(parts) > MAX_PATH_DEPTH:
        raise ManifestContractError(f"{label} TAR link target exceeds the depth limit.")
    resolved = PurePosixPath(*parts).as_posix() if parts else ""
    if not resolved or len(target.encode("utf-8")) > MAX_PATH_BYTES:
        raise ManifestContractError(f"{label} TAR symbolic-link target is too long.")
    return resolved


def _validate_tar_header(
    header: bytes,
    offset: int,
    label: str,
    expected_root: str | None,
    *,
    allow_symlinks: bool,
) -> tuple[str, str, int, str]:
    stored = _tar_number(header[148:156], f"{label} checksum")
    calculated = sum(header[:148]) + (8 * 32) + sum(header[156:])
    if stored != calculated:
        raise ManifestContractError(f"{label} TAR header checksum mismatch at {offset}.")
    if header[257:263] != b"ustar\0" or header[263:265] != b"00":
        raise ManifestContractError(f"only strict POSIX ustar {label} archives are accepted.")
    _tar_number(header[100:108], f"{label} mode")
    _tar_number(header[108:116], f"{label} uid")
    _tar_number(header[116:124], f"{label} gid")
    _tar_number(header[136:148], f"{label} mtime")
    if _tar_number(header[329:337], f"{label} device major") or _tar_number(
        header[337:345], f"{label} device minor"
    ):
        raise ManifestContractError(f"{label} TAR device metadata is forbidden.")
    if any(header[500:512]):
        raise ManifestContractError(f"{label} TAR header padding is non-zero.")
    name = _tar_text(header[0:100], f"{label} name")
    prefix = _tar_text(header[345:500], f"{label} prefix")
    full_name = f"{prefix}/{name}" if prefix else name
    canonical = _canonical_tar_path(full_name, label, expected_root)
    kind_byte = header[156:157]
    if kind_byte in {b"\0", b"0"}:
        kind = "file"
    elif kind_byte == b"5":
        kind = "dir"
    elif kind_byte == b"2":
        if not allow_symlinks:
            raise ManifestContractError(
                f"{label} TAR link/special members are forbidden."
            )
        kind = "symlink"
    else:
        raise ManifestContractError(
            f"{label} TAR hardlinks, special files, and extension records are forbidden."
        )
    link_target = _tar_text(header[157:257], f"{label} link target")
    if kind == "symlink":
        resolved = _canonical_link_target(canonical, link_target, label, expected_root)
    elif link_target:
        raise ManifestContractError(f"{label} TAR link target metadata is forbidden.")
    else:
        resolved = ""
    size = _tar_number(header[124:136], f"{label} size")
    if kind in {"dir", "symlink"} and size != 0:
        raise ManifestContractError(
            f"{label} TAR directory or symbolic link has non-zero content."
        )
    if size > MAX_MEMBER_BYTES:
        raise ManifestContractError(f"{label} TAR member exceeds the per-member size limit.")
    return canonical, kind, size, resolved


def _tree_sha256(members: list[tuple[str, str, int, str, str]]) -> str:
    lines: list[str] = []
    for canonical, kind, size, digest, link in sorted(members, key=lambda item: item[0]):
        lines.append(f"{kind} {size} {digest} {canonical} {link}\n")
    return sha256_bytes("".join(lines).encode("utf-8"))


def scan_tar_file(
    tar_path: pathlib.Path,
    label: str,
    *,
    expected_root: str | None,
    allow_symlinks: bool,
    max_size: int,
) -> tuple[str, list[tuple[str, str, int, str, str]]]:
    info = tar_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ManifestContractError(f"{label} decompressed TAR must be a regular file.")
    if info.st_size <= 0 or info.st_size > max_size:
        raise ManifestContractError(
            f"{label} decompressed TAR exceeds the outer size ceiling before reading."
        )
    if info.st_size % TAR_BLOCK:
        raise ManifestContractError(f"{label} TAR framing is malformed.")
    members: list[tuple[str, str, int, str, str]] = []
    seen: set[str] = set()
    folded: set[str] = set()
    declared_dirs: set[str] = set()
    total_files = 0
    offset = 0
    descriptor = _open_nofollow(tar_path, f"{label} decompressed TAR")
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(info):
            raise ManifestContractError(f"{label} decompressed TAR changed while it was opened.")
        while True:
            header = os.pread(descriptor, TAR_BLOCK, offset)
            if len(header) != TAR_BLOCK:
                raise ManifestContractError(f"{label} TAR ended before its required trailer.")
            if header == b"\0" * TAR_BLOCK:
                second = os.pread(descriptor, TAR_BLOCK, offset + TAR_BLOCK)
                if second != b"\0" * TAR_BLOCK:
                    raise ManifestContractError(
                        f"{label} TAR requires two zero trailer blocks."
                    )
                trailer_at = offset + (TAR_BLOCK * 2)
                while trailer_at < opened.st_size:
                    chunk = os.pread(
                        descriptor, min(READ_CHUNK, opened.st_size - trailer_at), trailer_at
                    )
                    if any(chunk):
                        raise ManifestContractError(
                            f"{label} TAR comments or non-zero trailing data are forbidden."
                        )
                    trailer_at += len(chunk)
                break
            if len(members) >= MAX_MEMBERS:
                raise ManifestContractError(f"{label} TAR member-count limit exceeded.")
            canonical, kind, size, link_target = _validate_tar_header(
                header, offset, label, expected_root, allow_symlinks=allow_symlinks
            )
            collision = canonical.casefold()
            if canonical in seen or collision in folded:
                raise ManifestContractError(
                    f"{label} TAR duplicate, Unicode, or case-fold collision rejected."
                )
            parent = PurePosixPath(canonical).parent.as_posix()
            if parent not in {".", *declared_dirs}:
                raise ManifestContractError(
                    f"{label} TAR member parent directory was not declared first."
                )
            if expected_root is not None and canonical == expected_root and kind != "dir":
                raise ManifestContractError(
                    f"{label} TAR top-level root must be a directory."
                )
            seen.add(canonical)
            folded.add(collision)
            digest = ""
            data_offset = offset + TAR_BLOCK
            if kind == "dir":
                declared_dirs.add(canonical)
            elif kind == "file":
                total_files += size
                if total_files > MAX_UNCOMPRESSED_BYTES:
                    raise ManifestContractError(
                        f"{label} TAR aggregate uncompressed size limit exceeded."
                    )
                hasher = hashlib.sha256()
                remaining = size
                position = data_offset
                while remaining:
                    block = os.pread(
                        descriptor, min(READ_CHUNK, remaining), position
                    )
                    if not block:
                        raise ManifestContractError(
                            f"{label} TAR member extends beyond the archive."
                        )
                    hasher.update(block)
                    remaining -= len(block)
                    position += len(block)
                digest = hasher.hexdigest()
            padded = ((size + TAR_BLOCK - 1) // TAR_BLOCK) * TAR_BLOCK
            next_offset = data_offset + padded
            if next_offset > opened.st_size:
                raise ManifestContractError(
                    f"{label} TAR member extends beyond the archive."
                )
            if padded > size:
                padding = os.pread(descriptor, padded - size, data_offset + size)
                if any(padding):
                    raise ManifestContractError(
                        f"{label} TAR member has non-zero data padding."
                    )
            members.append((canonical, kind, size, digest, link_target))
            offset = next_offset
        finished = os.fstat(descriptor)
        if _identity(opened) != _identity(finished):
            raise ManifestContractError(f"{label} decompressed TAR changed while it was scanned.")
    finally:
        os.close(descriptor)
    if expected_root is not None and expected_root not in declared_dirs:
        raise ManifestContractError(f"{label} TAR pinned top-level root is absent.")
    if not members:
        raise ManifestContractError(f"empty {label} TAR rejected.")
    if any(kind == "file" for _canonical, kind, _size, _digest, _link in members) is False:
        raise ManifestContractError(f"{label} TAR must contain at least one regular file.")
    return _tree_sha256(members), members


def _expansion_limit(compressed_size: int) -> int:
    ratio_limit = (
        compressed_size * MAX_COMPRESSION_RATIO
        if compressed_size > 0
        else MAX_UNCOMPRESSED_BYTES
    )
    bomb_limit = (
        COMPRESSED_BOMB_BYTES
        if compressed_size <= COMPRESSED_BOMB_BYTES
        else MAX_UNCOMPRESSED_BYTES
    )
    return min(MAX_UNCOMPRESSED_BYTES, ratio_limit, bomb_limit)


def _check_expansion(
    total: int, compressed_size: int, label: str, *, upcoming: int = 0
) -> None:
    projected = total + upcoming
    limit = _expansion_limit(compressed_size)
    if projected > limit:
        if compressed_size <= COMPRESSED_BOMB_BYTES or (
            compressed_size > 0 and projected > compressed_size * MAX_COMPRESSION_RATIO
        ):
            raise ManifestContractError(
                f"{label} compressed bomb rejected: expansion exceeds ratio or "
                f"{COMPRESSED_BOMB_BYTES // (1024 * 1024)} MiB ceiling."
            )
        raise ManifestContractError(f"{label} archive expansion limit exceeded.")


def _decompress_gzip(source_fd: int, compressed_size: int, destination: pathlib.Path, label: str) -> int:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    total = 0
    pending = b""
    with destination.open("xb") as target:
        while True:
            if decoder.eof:
                extra = os.read(source_fd, 1)
                if decoder.unused_data or extra:
                    raise ManifestContractError(
                        f"{label} concatenated streams or trailing data are forbidden."
                    )
                break
            if not pending:
                pending = os.read(source_fd, READ_CHUNK)
                if not pending:
                    raise ManifestContractError(f"{label} compressed stream is truncated.")
            remaining = min(
                _expansion_limit(compressed_size) - total,
                MAX_DECODE_CHUNK,
            )
            if remaining <= 0:
                _check_expansion(total, compressed_size, label, upcoming=1)
            try:
                expanded = decoder.decompress(pending, remaining)
            except zlib.error as exc:
                raise ManifestContractError(f"invalid {label} compressed stream.") from exc
            pending = decoder.unconsumed_tail
            _check_expansion(total, compressed_size, label, upcoming=len(expanded))
            total += len(expanded)
            if expanded:
                target.write(expanded)
            elif not pending and not decoder.eof:
                raise ManifestContractError(f"{label} gzip decoder made no progress.")
        target.flush()
        os.fsync(target.fileno())
    if total < TAR_BLOCK * 3 or total % TAR_BLOCK:
        raise ManifestContractError(f"{label} TAR framing is malformed.")
    return total


def _decompress_xz(source_fd: int, compressed_size: int, destination: pathlib.Path, label: str) -> int:
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_DECODER_MEMORY)
    total = 0
    with destination.open("xb") as target:
        while True:
            block = os.read(source_fd, READ_CHUNK)
            if not block:
                break
            pending = block
            while pending or not decoder.needs_input:
                remaining = min(
                    _expansion_limit(compressed_size) - total,
                    MAX_DECODE_CHUNK,
                )
                if remaining <= 0:
                    _check_expansion(total, compressed_size, label, upcoming=1)
                try:
                    expanded = decoder.decompress(pending, max_length=remaining)
                except lzma.LZMAError as exc:
                    raise ManifestContractError(f"invalid {label} compressed stream.") from exc
                pending = b""
                _check_expansion(total, compressed_size, label, upcoming=len(expanded))
                total += len(expanded)
                if expanded:
                    target.write(expanded)
                if decoder.eof:
                    extra = os.read(source_fd, 1)
                    if decoder.unused_data or extra:
                        raise ManifestContractError(
                            f"{label} concatenated streams or trailing data are forbidden."
                        )
                    break
                if decoder.needs_input:
                    break
                if not expanded:
                    raise ManifestContractError(f"{label} XZ decoder made no progress.")
            if decoder.eof:
                break
        if not decoder.eof:
            raise ManifestContractError(f"{label} compressed stream is truncated.")
        target.flush()
        os.fsync(target.fileno())
    if total < TAR_BLOCK * 3 or total % TAR_BLOCK:
        raise ManifestContractError(f"{label} TAR framing is malformed.")
    return total


def _open_bound_archive(
    repo: pathlib.Path,
    relative: str,
    label: str,
    max_bytes: int,
) -> tuple[int, os.stat_result, str]:
    root = _repo_root(repo)
    descriptor, info, _path, posix = _bind_parent_chain(
        root, relative, label, leaf_must_exist=True
    )
    try:
        if info.st_size <= 0:
            raise ManifestContractError(f"{label} is empty.")
        if info.st_size > max_bytes:
            raise ManifestContractError(
                f"{label} exceeds the outer size ceiling before reading."
            )
        return descriptor, info, posix
    except Exception:
        os.close(descriptor)
        raise


def _hash_fd(descriptor: int, size: int, label: str) -> str:
    hasher = hashlib.sha256()
    remaining = size
    offset = 0
    while remaining:
        block = os.pread(descriptor, min(READ_CHUNK, remaining), offset)
        if not block:
            raise ManifestContractError(f"{label} ended before its declared size.")
        hasher.update(block)
        remaining -= len(block)
        offset += len(block)
    extra = os.pread(descriptor, 1, size)
    if extra:
        raise ManifestContractError(f"{label} grew while it was hashed.")
    return hasher.hexdigest()


def stream_archive_identity(
    repo: pathlib.Path,
    archive_path: pathlib.Path,
    label: str,
    *,
    kind: str,
    expected_root: str | None,
    allow_symlinks: bool,
    max_bytes: int,
) -> tuple[str, int, str]:
    """Measure archive digest and normalized tree. This is not a trust anchor."""
    root = _repo_root(repo)
    relative = secure_repo_path(
        root, archive_path, label, must_exist=True
    ).relative_to(root).as_posix()
    descriptor = -1
    try:
        descriptor, info, posix = _open_bound_archive(root, relative, label, max_bytes)
        digest = _hash_fd(descriptor, info.st_size, label)
        os.lseek(descriptor, 0, os.SEEK_SET)
        temporary = tempfile.TemporaryDirectory(prefix="winsvpn-manifest-tar-")
        try:
            tar_path = pathlib.Path(temporary.name) / "archive.tar"
            if kind == "tar.gz":
                if MAX_ARCHIVE_DEPTH != 1:
                    raise ManifestContractError(f"{label} archive depth limit exceeded.")
                _decompress_gzip(descriptor, info.st_size, tar_path, label)
            elif kind == "tar.xz":
                if MAX_ARCHIVE_DEPTH != 1:
                    raise ManifestContractError(f"{label} archive depth limit exceeded.")
                _decompress_xz(descriptor, info.st_size, tar_path, label)
            else:
                raise ManifestContractError(f"{label} archive kind is unsupported.")
            tree, _members = scan_tar_file(
                tar_path,
                label,
                expected_root=expected_root,
                allow_symlinks=allow_symlinks,
                max_size=MAX_UNCOMPRESSED_BYTES,
            )
        finally:
            temporary.cleanup()
        finished = os.fstat(descriptor)
        if _identity(info) != _identity(finished):
            raise ManifestContractError(f"{label} changed while it was parsed.")
        if posix != relative:
            raise ManifestContractError(f"{label} path changed while it was parsed.")
        if digest == tree:
            raise ManifestContractError(
                f"{label} archive digest cannot equal its normalized tree identity."
            )
        return digest, info.st_size, tree
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_external_trust(
    repo: pathlib.Path,
    *,
    now: dt.datetime | None = None,
) -> ExternalTrust:
    root = _repo_root(repo)
    _marketing, _debian, release = _canonical_linux_versions(root)
    try:
        payload, _info, _posix = bind_repo_file(
            root,
            EXTERNAL_TRUST_RELATIVE,
            "externally bound source/toolchain identity",
            max_bytes=MAX_JSON_BYTES,
        )
    except ManifestContractError as suc:
        raise ManifestContractError(f"{UNAVAILABLE_EXTERNAL_IDENTITY}: {suc}") from suc
    document = _exact(
        _strict_json_object(payload, "externally bound source/toolchain identity"),
        set(EXTERNAL_TRUST_KEYS),
        "externally bound source/toolchain identity",
    )
    if "authenticated" in document:
        raise ManifestContractError(SELF_ASSERTED_AUTHENTICATED)
    schema_version = _require_int(
        document.get("schema_version"), "external-trust schema_version"
    )
    contract_name = _require_str(document.get("contract"), "external-trust contract")
    created_text = _require_str(document.get("created_utc"), "external-trust created_utc")
    created = _timestamp(created_text, "external-trust created_utc")
    _require_fresh(created, "externally bound source/toolchain identity", now=now)
    issuance_id = _require_issuance(
        document.get("issuance_id"), "external-trust issuance_id"
    )
    trust_release = _require_str(document.get("release"), "external-trust release")
    issuer = _require_str(document.get("issuer"), "external-trust issuer")
    if (
        schema_version != EXTERNAL_TRUST_SCHEMA_VERSION
        or contract_name != EXTERNAL_TRUST_CONTRACT
        or trust_release != release
        or issuer != EXTERNAL_TRUST_ISSUER
    ):
        raise ManifestContractError(
            "externally bound source/toolchain identity is not the current reviewed issuance."
        )
    module = _exact(
        document.get("module"), set(SOURCE_FREEZE_MODULE_KEYS), "external-trust module"
    )
    module_path = _require_str(module.get("path"), "external-trust module.path")
    module_sha256 = _require_sha256(module.get("sha256"), "external-trust module.sha256")
    module_bytes = _require_int(module.get("bytes"), "external-trust module.bytes")
    if module_path != CONTRACT_MODULE_RELATIVE or module_bytes < 1:
        raise ManifestContractError(
            "externally bound identity does not bind the exact support module path."
        )
    source = _exact(document.get("source"), set(SOURCE_KEYS), "external-trust source")
    validate_source(
        _require_str(source.get("url"), "external-trust source.url"),
        _require_sha256(source.get("sha256"), "external-trust source.sha256"),
    )
    size = _require_int(source.get("bytes"), "external-trust source.bytes")
    tree = _require_sha256(source.get("tree_sha256"), "external-trust source.tree_sha256")
    archive_path = _require_str(
        source.get("archive_path"), "external-trust source.archive_path"
    )
    if size < 1 or tree == source["sha256"]:
        raise ManifestContractError(
            "externally bound source archive identity is malformed."
        )
    flutter = _exact(
        document.get("flutter"), set(EXTERNAL_FLUTTER_KEYS), "external-trust flutter"
    )
    flutter_issuance = _require_issuance(
        flutter.get("issuance_id"), "external-trust flutter.issuance_id"
    )
    flutter_version = _require_str(flutter.get("version"), "external-trust flutter.version")
    flutter_revision = _require_str(
        flutter.get("revision"), "external-trust flutter.revision"
    )
    flutter_channel = _require_str(flutter.get("channel"), "external-trust flutter.channel")
    flutter_dart = _require_str(
        flutter.get("dart_version"), "external-trust flutter.dart_version"
    )
    flutter_issuer = _require_str(flutter.get("issuer"), "external-trust flutter.issuer")
    if (
        flutter_version != REVIEWED_FLUTTER_VERSION
        or flutter_revision != REVIEWED_FLUTTER_REVISION
        or flutter_channel != REVIEWED_FLUTTER_CHANNEL
        or flutter_dart != REVIEWED_DART_VERSION
        or flutter_issuer != FLUTTER_RECEIPT_ISSUER
        or flutter_issuance == issuance_id
    ):
        raise ManifestContractError(
            "externally bound Flutter toolchain identity is not the reviewed 3.47.6 issuance."
        )
    return ExternalTrust(
        issuance_id=issuance_id,
        created_utc=created_text,
        release=trust_release,
        module_path=module_path,
        module_sha256=module_sha256,
        module_bytes=module_bytes,
        source={
            "url": source["url"],
            "sha256": source["sha256"],
            "archive_path": archive_path,
            "bytes": size,
            "tree_sha256": tree,
        },
        flutter_issuance_id=flutter_issuance,
        flutter_version=flutter_version,
        flutter_revision=flutter_revision,
        flutter_channel=flutter_channel,
        flutter_dart_version=flutter_dart,
        flutter_issuer=flutter_issuer,
    )


def load_source_freeze_receipt(
    repo: pathlib.Path,
    *,
    now: dt.datetime | None = None,
) -> SourceFreezeReceipt:
    root = _repo_root(repo)
    trust = load_external_trust(root, now=now)
    _marketing, _debian, release = _canonical_linux_versions(root)
    relative = source_freeze_receipt_relative(release)
    try:
        payload, info, posix = bind_repo_file(
            root, relative, "source-freeze receipt", max_bytes=MAX_JSON_BYTES
        )
    except ManifestContractError as exc:
        raise ManifestContractError(
            "current externally authenticated source-freeze receipt is required "
            f"to bind the support module and source archive identity: {exc}"
        ) from exc
    document = _exact(
        _strict_json_object(payload, "source-freeze receipt"),
        set(SOURCE_FREEZE_DOCUMENT_KEYS),
        "source-freeze receipt",
    )
    schema_version = _require_int(
        document.get("schema_version"), "source-freeze schema_version"
    )
    contract_name = _require_str(document.get("contract"), "source-freeze contract")
    created_text = _require_str(document.get("created_utc"), "source-freeze created_utc")
    created = _timestamp(created_text, "source-freeze created_utc")
    _require_fresh(created, "source-freeze receipt", now=now)
    issuance_id = _require_issuance(
        document.get("issuance_id"), "source-freeze issuance_id"
    )
    freeze_release = _require_str(document.get("release"), "source-freeze release")
    authenticated = _require_bool(
        document.get("authenticated"), "source-freeze authenticated"
    )
    issuer = _require_str(document.get("issuer"), "source-freeze issuer")
    if (
        schema_version != SOURCE_FREEZE_RECEIPT_SCHEMA_VERSION
        or contract_name != SOURCE_FREEZE_RECEIPT_CONTRACT
        or freeze_release != release
        or freeze_release != trust.release
        or issuer != SOURCE_FREEZE_ISSUER
        or issuer != EXTERNAL_TRUST_ISSUER
        or issuance_id != trust.issuance_id
        or created_text != trust.created_utc
    ):
        raise ManifestContractError(
            "source-freeze receipt is unauthenticated or not the current freeze identity."
        )
    if authenticated is not True:
        raise ManifestContractError(SELF_ASSERTED_AUTHENTICATED)
    module = _exact(
        document.get("module"), set(SOURCE_FREEZE_MODULE_KEYS), "source-freeze module"
    )
    module_path = _require_str(module.get("path"), "source-freeze module.path")
    module_sha256 = _require_sha256(module.get("sha256"), "source-freeze module.sha256")
    module_bytes = _require_int(module.get("bytes"), "source-freeze module.bytes")
    if module_path != CONTRACT_MODULE_RELATIVE or module_bytes < 1:
        raise ManifestContractError(
            "source-freeze receipt does not bind the exact support module path."
        )
    if (
        module_path != trust.module_path
        or module_sha256 != trust.module_sha256
        or module_bytes != trust.module_bytes
    ):
        raise ManifestContractError(SELF_ASSERTED_AUTHENTICATED)
    source = _exact(document.get("source"), set(SOURCE_KEYS), "source-freeze source")
    validate_source(
        _require_str(source.get("url"), "source-freeze source.url"),
        _require_sha256(source.get("sha256"), "source-freeze source.sha256"),
    )
    _require_str(source.get("archive_path"), "source-freeze source.archive_path")
    size = _require_int(source.get("bytes"), "source-freeze source.bytes")
    tree = _require_sha256(source.get("tree_sha256"), "source-freeze source.tree_sha256")
    if size < 1 or tree == source["sha256"]:
        raise ManifestContractError(
            "source-freeze source archive identity is malformed."
        )
    if source != trust.source:
        raise ManifestContractError(SELF_ASSERTED_AUTHENTICATED)
    live_payload, live_info, _live_posix = bind_repo_file(
        root,
        CONTRACT_MODULE_RELATIVE,
        "Manifest support module",
        max_bytes=MAX_JSON_BYTES * 4,
    )
    live_digest = sha256_bytes(live_payload)
    if live_digest != module_sha256 or live_info.st_size != module_bytes:
        raise ManifestContractError(
            "support module is not bound to the current source-freeze receipt; "
            "calculating a digest from current bytes is not a trust anchor."
        )
    return SourceFreezeReceipt(
        path=posix,
        sha256=sha256_bytes(payload),
        created_utc=created_text,
        issuance_id=issuance_id,
        release=release,
        module_path=module_path,
        module_sha256=module_sha256,
        module_bytes=module_bytes,
        source={
            "url": source["url"],
            "sha256": source["sha256"],
            "archive_path": source["archive_path"],
            "bytes": size,
            "tree_sha256": tree,
        },
    )


def assert_support_module_bound(
    repo: pathlib.Path, digest: str, *, now: dt.datetime | None = None
) -> SourceFreezeReceipt:
    freeze = load_source_freeze_receipt(repo, now=now)
    if type(digest) is not str or digest != freeze.module_sha256:
        raise ManifestContractError(
            "support module digest is not the source-freeze receipt identity."
        )
    return freeze


def bind_source_archive(
    repo: pathlib.Path,
    source_url: str,
    source_sha256: str,
    source_archive: pathlib.Path,
    *,
    freeze: SourceFreezeReceipt | None = None,
    now: dt.datetime | None = None,
) -> dict[str, object]:
    root = _repo_root(repo)
    bound_freeze = freeze or load_source_freeze_receipt(root, now=now)
    validate_source(source_url, source_sha256)
    archive = secure_repo_path(
        root, source_archive, "Manifest source archive snapshot", must_exist=True
    )
    relative = archive.relative_to(root).as_posix()
    expected = bound_freeze.source
    if (
        source_url != expected["url"]
        or source_sha256 != expected["sha256"]
        or relative != expected["archive_path"]
    ):
        raise ManifestContractError(
            "Source archive identity is not the current source-freeze receipt; "
            "attacker URL+hash self-authentication cannot emit ok."
        )
    digest, size, tree = stream_archive_identity(
        root,
        archive,
        "Manifest source archive snapshot",
        kind="tar.gz",
        expected_root=None,
        allow_symlinks=False,
        max_bytes=MAX_SOURCE_ARCHIVE_BYTES,
    )
    if (
        digest != expected["sha256"]
        or size != expected["bytes"]
        or tree != expected["tree_sha256"]
    ):
        raise ManifestContractError(
            "Source archive bytes/tree do not match the current source-freeze receipt; "
            "calculating a digest from current bytes is not a trust anchor."
        )
    return {
        "url": source_url,
        "sha256": digest,
        "archive_path": relative,
        "bytes": size,
        "tree_sha256": tree,
    }


def _load_flutter_archive(
    repo: pathlib.Path,
    arch: str,
    record: object,
) -> FlutterArchive:
    expected_name = REVIEWED_FLUTTER_ARCHIVE_NAMES.get(arch)
    if expected_name is None:
        raise ManifestContractError("Flutter SDK archives must bind x64 and arm64.")
    archive = _exact(record, set(FLUTTER_ARCHIVE_KEYS), f"Flutter {arch} archive")
    url = _require_str(archive.get("url"), f"Flutter {arch} url")
    digest = _require_sha256(archive.get("sha256"), f"Flutter {arch} sha256")
    name = _require_str(archive.get("name"), f"Flutter {arch} name")
    archive_path = _require_str(
        archive.get("archive_path"), f"Flutter {arch} archive_path"
    )
    size = _require_int(archive.get("bytes"), f"Flutter {arch} bytes")
    tree = _require_sha256(archive.get("tree_sha256"), f"Flutter {arch} tree_sha256")
    expected_url = REVIEWED_FLUTTER_ARCHIVE_URL_PREFIX + expected_name
    if (
        name != expected_name
        or url != expected_url
        or size < 1
        or digest == tree
    ):
        raise ManifestContractError(
            "Flutter SDK archive identity is not the reviewed 3.47.6 stable snapshot."
        )
    measured_digest, measured_size, measured_tree = stream_archive_identity(
        repo,
        pathlib.Path(archive_path),
        f"Flutter {arch} SDK archive",
        kind="tar.xz",
        expected_root=FLUTTER_TREE_ROOT,
        allow_symlinks=True,
        max_bytes=MAX_FLUTTER_ARCHIVE_BYTES,
    )
    local = secure_repo_path(
        repo, pathlib.Path(archive_path), f"Flutter {arch} SDK archive", must_exist=True
    )
    if (
        local.name != expected_name
        or measured_size != size
        or measured_digest != digest
        or measured_tree != tree
        or local.relative_to(_repo_root(repo)).as_posix() != archive_path
    ):
        raise ManifestContractError(
            "Flutter SDK archive bytes do not match authenticated toolchain custody; "
            "caller-created self-authentication cannot emit ok."
        )
    return FlutterArchive(
        url=url,
        sha256=digest,
        name=name,
        archive_path=archive_path,
        size_bytes=size,
        tree_sha256=tree,
    )


def load_flutter_sdk_receipt(
    repo: pathlib.Path,
    receipt: pathlib.Path,
    *,
    now: dt.datetime | None = None,
    expected_issuance_id: str | None = None,
) -> FlutterSdk:
    root = _repo_root(repo)
    trust = load_external_trust(root, now=now)
    receipt_path = secure_repo_path(
        root, receipt, "Flutter SDK toolchain receipt", must_exist=True
    )
    relative = receipt_path.relative_to(root).as_posix()
    payload, _info, _posix = bind_repo_file(
        root, relative, "Flutter SDK toolchain receipt", max_bytes=MAX_JSON_BYTES
    )
    document = _exact(
        _strict_json_object(payload, "Flutter SDK toolchain receipt"),
        set(FLUTTER_DOCUMENT_KEYS),
        "Flutter SDK toolchain receipt",
    )
    version = _require_str(document.get("version"), "Flutter version")
    revision = _require_str(document.get("revision"), "Flutter revision")
    channel = _require_str(document.get("channel"), "Flutter channel")
    dart_version = _require_str(document.get("dart_version"), "Dart version")
    schema_version = _require_int(
        document.get("schema_version"), "Flutter receipt schema_version"
    )
    contract_name = _require_str(document.get("contract"), "Flutter receipt contract")
    created_text = _require_str(document.get("created_utc"), "Flutter receipt created_utc")
    created = _timestamp(created_text, "Flutter receipt created_utc")
    _require_fresh(created, "Flutter SDK toolchain receipt", now=now)
    issuance_id = _require_issuance(
        document.get("issuance_id"), "Flutter receipt issuance_id"
    )
    authenticated = _require_bool(
        document.get("authenticated"), "Flutter receipt authenticated"
    )
    issuer = _require_str(document.get("issuer"), "Flutter receipt issuer")
    if (
        schema_version != FLUTTER_RECEIPT_SCHEMA_VERSION
        or contract_name != FLUTTER_RECEIPT_CONTRACT
        or version != REVIEWED_FLUTTER_VERSION
        or revision != REVIEWED_FLUTTER_REVISION
        or channel != REVIEWED_FLUTTER_CHANNEL
        or dart_version != REVIEWED_DART_VERSION
        or issuer != FLUTTER_RECEIPT_ISSUER
        or issuer != trust.flutter_issuer
        or version != trust.flutter_version
        or revision != trust.flutter_revision
        or channel != trust.flutter_channel
        or dart_version != trust.flutter_dart_version
        or issuance_id != trust.flutter_issuance_id
        or authenticated is not True
    ):
        raise ManifestContractError(
            "Flutter SDK toolchain receipt is unauthenticated or not the reviewed "
            "3.47.6 stable identity from authenticated toolchain custody."
        )
    if expected_issuance_id is not None and issuance_id != expected_issuance_id:
        raise ManifestContractError(
            "Flutter SDK receipt issuance identity is not bound to the build transaction."
        )
    archives_record = document.get("archives")
    if type(archives_record) is not dict or set(archives_record) != {"x64", "arm64"}:
        raise ManifestContractError("Flutter SDK receipt must bind x64 and arm64 archives.")
    archives = {
        arch: _load_flutter_archive(root, arch, archives_record.get(arch))
        for arch in ("x64", "arm64")
    }
    if (
        archives["x64"].sha256 == archives["arm64"].sha256
        or archives["x64"].tree_sha256 == archives["arm64"].tree_sha256
    ):
        raise ManifestContractError(
            "x64/arm64 Flutter SDK archives cannot cross-bind; hashes must be distinct."
        )
    return FlutterSdk(
        version=version,
        revision=revision,
        channel=channel,
        dart_version=dart_version,
        receipt_path=relative,
        receipt_sha256=sha256_bytes(payload),
        created_utc=created_text,
        issuance_id=issuance_id,
        authenticated=True,
        issuer=issuer,
        archives=MappingProxyType(archives),
    )


def flutter_record(flutter: FlutterSdk) -> dict[str, object]:
    return {
        "version": flutter.version,
        "revision": flutter.revision,
        "channel": flutter.channel,
        "dart_version": flutter.dart_version,
        "receipt_path": flutter.receipt_path,
        "receipt_sha256": flutter.receipt_sha256,
        "created_utc": flutter.created_utc,
        "issuance_id": flutter.issuance_id,
        "authenticated": True,
        "issuer": flutter.issuer,
        "archives": {
            arch: {
                "url": archive.url,
                "sha256": archive.sha256,
                "name": archive.name,
                "archive_path": archive.archive_path,
                "bytes": archive.size_bytes,
                "tree_sha256": archive.tree_sha256,
            }
            for arch, archive in flutter.archives.items()
        },
    }


def bind_native_package_receipt(
    *,
    repo: pathlib.Path,
    target_id: str,
    package: pathlib.Path,
    sha256: str,
) -> dict[str, object]:
    expected = NATIVE_PACKAGE_TARGETS.get(target_id)
    if expected is None:
        raise ManifestContractError("native package target binding is incorrect.")
    filename, kind = expected
    if type(sha256) is not str or HEX64.fullmatch(sha256) is None:
        raise ManifestContractError(
            "package/store receipts require an actual exact package artifact digest."
        )
    package_path = secure_repo_path(
        repo, package, "Native store package", must_exist=True
    )
    payload, _info = read_stable_file(
        package_path, "Native store package", max_bytes=MAX_SOURCE_ARCHIVE_BYTES
    )
    digest = sha256_bytes(payload)
    if digest != sha256:
        raise ManifestContractError(
            "package/store receipts require an actual exact package artifact digest."
        )
    if package_path.name != filename:
        raise ManifestContractError("native package target binding is incorrect.")
    header = payload[:512]
    gzip_tar = header.startswith(GZIP_MAGIC) or (
        len(payload) > 262 and payload[257:262] == TAR_MAGIC
    )
    if gzip_tar:
        raise ManifestContractError(
            f"refusing surrogate {kind} extension on a gzip-tar file; "
            "do not label gzip-tar files .flatpak or .snap."
        )
    raise ManifestContractError(
        "native package evidence is owner-blocked until actual native-format "
        f"{kind} artifacts and verified store signatures exist."
    )


def _artifacts_dir(root: pathlib.Path, path: pathlib.Path, label: str) -> None:
    relative = path.relative_to(root)
    if not relative.parts or relative.parts[0] != ".artifacts":
        raise ManifestContractError(f"{label} must stay under .artifacts/.")
    parent_relative = relative.parent.as_posix()
    if parent_relative in {".", ""}:
        raise ManifestContractError(f"{label} parent must already be a regular directory.")
    descriptor = -1
    try:
        descriptor, _info, _path, _posix = _bind_directory(
            root, parent_relative, f"{label} parent"
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_build_transaction(
    freeze: SourceFreezeReceipt,
    flutter: FlutterSdk,
    *,
    now: dt.datetime | None = None,
) -> None:
    checked_at = now or dt.datetime.now(tz=dt.timezone.utc)
    freeze_time = _timestamp(freeze.created_utc, "source-freeze created_utc")
    flutter_time = _timestamp(flutter.created_utc, "Flutter receipt created_utc")
    if abs((flutter_time - freeze_time).total_seconds()) > MAX_BUILD_TRANSACTION_AGE.total_seconds():
        raise ManifestContractError(
            "Flutter receipt issuance is not bounded to the current build transaction."
        )
    if checked_at - flutter_time > MAX_BUILD_TRANSACTION_AGE:
        raise ManifestContractError(
            "Flutter receipt issuance is not bounded to the current build transaction."
        )


def produce(
    *,
    repo: pathlib.Path,
    target_id: str,
    artifact_format: str,
    producer_path: str,
    source_url: str,
    source_sha256: str,
    source_archive: pathlib.Path,
    toolchain_receipt: pathlib.Path,
    version: str,
    output: pathlib.Path,
    receipt: pathlib.Path,
    render: Callable[[str, str, str, FlutterSdk], bytes],
    extract_shell: Callable[[bytes], str],
    now: dt.datetime | None = None,
) -> dict[str, object]:
    root = _repo_root(repo)
    canonical_version, _debian_version, _release = _canonical_linux_versions(root)
    if type(version) is not str or version != canonical_version:
        raise ManifestContractError(
            f"Manifest version must be canonical {canonical_version}."
        )
    validate_metainfo(root, canonical_version)
    freeze = load_source_freeze_receipt(root, now=now)
    source = bind_source_archive(
        root, source_url, source_sha256, source_archive, freeze=freeze, now=now
    )
    flutter = load_flutter_sdk_receipt(root, toolchain_receipt, now=now)
    _require_build_transaction(freeze, flutter, now=now)
    output_path = secure_repo_path(root, output, "Manifest artifact", must_exist=False)
    receipt_path = secure_repo_path(root, receipt, "Manifest receipt", must_exist=False)
    _artifacts_dir(root, output_path, "Manifest artifact")
    _artifacts_dir(root, receipt_path, "Manifest receipt")
    if output_path == receipt_path:
        raise ManifestContractError(
            "Manifest artifact and receipt must be separate files."
        )
    producer = secure_repo_path(
        root, pathlib.Path(producer_path), "Manifest producer", must_exist=True
    )
    artifact_bytes = render(source_url, source_sha256, version, flutter)
    if not artifact_bytes or not artifact_bytes.endswith(b"\n"):
        raise ManifestContractError(
            "Rendered manifest must be non-empty and newline-terminated."
        )
    validate_shell(extract_shell(artifact_bytes))
    _write_new(output_path, artifact_bytes, "immutable manifest artifact")
    artifact_payload, artifact_info = read_stable_file(
        output_path, "immutable manifest artifact"
    )
    if artifact_payload != artifact_bytes:
        raise ManifestContractError("Manifest artifact mutated after write.")
    record: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "contract": CONTRACT,
        "target_id": target_id,
        "platform": "linux",
        "artifact_format": artifact_format,
        "created_utc": _utc_now(),
        "artifact": {
            "path": output_path.relative_to(root).as_posix(),
            "sha256": sha256_bytes(artifact_payload),
            "bytes": artifact_info.st_size,
            "modified_time_ns": artifact_info.st_mtime_ns,
        },
        "source": source,
        "source_freeze": {
            "path": freeze.path,
            "sha256": freeze.sha256,
            "issuance_id": freeze.issuance_id,
            "created_utc": freeze.created_utc,
        },
        "flutter_sdk": flutter_record(flutter),
        "version": version,
        "producer": {
            "path": producer_path,
            "sha256": sha256_file(producer),
        },
        "verification_network_accessed": False,
        "publication_authorized": False,
        "upload_attempted": False,
        "manifest_only": True,
        "package_verified": False,
        "sha256_anchor": receipt_path.name + ".sha256",
    }
    encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_new(receipt_path, encoded, "immutable manifest receipt")
    anchor_path = secure_repo_path(
        root,
        receipt_path.with_name(receipt_path.name + ".sha256"),
        "Manifest receipt anchor",
        must_exist=False,
    )
    _write_new(
        anchor_path,
        f"{sha256_file(receipt_path)}  {receipt_path.name}\n".encode("ascii"),
        "immutable manifest receipt anchor",
    )
    return record


def _source_from_record(
    repo: pathlib.Path,
    source: dict[str, object],
    freeze: SourceFreezeReceipt,
    *,
    now: dt.datetime | None = None,
) -> dict[str, object]:
    bound = bind_source_archive(
        repo,
        _require_str(source.get("url"), "source.url"),
        _require_str(source.get("sha256"), "source.sha256"),
        pathlib.Path(_require_str(source.get("archive_path"), "source.archive_path")),
        freeze=freeze,
        now=now,
    )
    if bound != source:
        raise ManifestContractError("Manifest source archive snapshot binding is invalid.")
    return bound


def _flutter_from_record(
    repo: pathlib.Path,
    record: dict[str, object],
    *,
    now: dt.datetime | None = None,
    expected_issuance_id: str | None = None,
) -> FlutterSdk:
    flutter_record_value = _exact(
        record.get("flutter_sdk"), set(FLUTTER_RECEIPT_KEYS), "Manifest Flutter SDK"
    )
    receipt_path = _require_str(
        flutter_record_value.get("receipt_path"), "flutter_sdk.receipt_path"
    )
    flutter = load_flutter_sdk_receipt(
        repo,
        pathlib.Path(receipt_path),
        now=now,
        expected_issuance_id=expected_issuance_id
        or _require_issuance(
            flutter_record_value.get("issuance_id"), "flutter_sdk.issuance_id"
        ),
    )
    expected = flutter_record(flutter)
    if expected != flutter_record_value:
        raise ManifestContractError("Manifest Flutter SDK receipt binding is invalid.")
    return flutter


def verify(
    *,
    repo: pathlib.Path,
    target_id: str,
    artifact_format: str,
    producer_path: str,
    receipt: pathlib.Path,
    artifact: pathlib.Path,
    render: Callable[[str, str, str, FlutterSdk], bytes],
    extract_shell: Callable[[bytes], str],
    now: dt.datetime | None = None,
) -> dict[str, object]:
    root = _repo_root(repo)
    receipt_path = secure_repo_path(root, receipt, "Manifest receipt", must_exist=True)
    artifact_path = secure_repo_path(
        root, artifact, "Manifest artifact", must_exist=True
    )
    if receipt_path.relative_to(root).parts[0] != ".artifacts":
        raise ManifestContractError("Manifest receipt must stay under .artifacts/.")
    if artifact_path.relative_to(root).parts[0] != ".artifacts":
        raise ManifestContractError("Manifest artifact must stay under .artifacts/.")
    anchor = secure_repo_path(
        root,
        receipt_path.with_name(receipt_path.name + ".sha256"),
        "Manifest receipt anchor",
        must_exist=True,
    )
    receipt_relative = receipt_path.relative_to(root).as_posix()
    receipt_payload, _receipt_info, _receipt_posix = bind_repo_file(
        root, receipt_relative, "Manifest receipt", max_bytes=MAX_JSON_BYTES
    )
    expected_anchor = f"{sha256_bytes(receipt_payload)}  {receipt_path.name}\n"
    try:
        anchor_text = read_stable_file(anchor, "Manifest receipt anchor")[0].decode(
            "ascii"
        )
        record = _strict_json_object(receipt_payload, "Manifest receipt")
    except (OSError, UnicodeError) as exc:
        raise ManifestContractError(f"Unable to read manifest receipt: {exc}") from exc
    if anchor_text != expected_anchor:
        raise ManifestContractError("Manifest receipt SHA-256 anchor changed.")
    record = _exact(record, RECEIPT_KEYS, "Manifest receipt")
    artifact_record = _exact(
        record.get("artifact"), ARTIFACT_KEYS, "Manifest artifact binding"
    )
    _require_str(artifact_record.get("path"), "artifact.path")
    _require_str(artifact_record.get("sha256"), "artifact.sha256")
    _require_int(artifact_record.get("bytes"), "artifact.bytes")
    _require_int(artifact_record.get("modified_time_ns"), "artifact.modified_time_ns")
    source = _exact(record.get("source"), SOURCE_KEYS, "Manifest source")
    freeze_record = _exact(
        record.get("source_freeze"), SOURCE_FREEZE_RECORD_KEYS, "Manifest source-freeze"
    )
    producer_record = _exact(
        record.get("producer"), PRODUCER_KEYS, "Manifest producer"
    )
    _require_str(producer_record.get("path"), "producer.path")
    _require_str(producer_record.get("sha256"), "producer.sha256")
    created = _timestamp(record.get("created_utc"), "Manifest receipt time")
    _require_fresh(created, "Manifest receipt", now=now)
    version = _require_str(record.get("version"), "version")
    canonical_version, _debian_version, _release = _canonical_linux_versions(root)
    if version != canonical_version:
        raise ManifestContractError(
            f"Manifest version must be canonical {canonical_version}."
        )
    validate_metainfo(root, version)
    freeze = load_source_freeze_receipt(root, now=now)
    expected_freeze = {
        "path": freeze.path,
        "sha256": freeze.sha256,
        "issuance_id": freeze.issuance_id,
        "created_utc": freeze.created_utc,
    }
    if freeze_record != expected_freeze:
        raise ManifestContractError(
            "Manifest source-freeze receipt binding is invalid or changed."
        )
    bound_source = _source_from_record(root, source, freeze, now=now)
    flutter = _flutter_from_record(root, record, now=now)
    _require_build_transaction(freeze, flutter, now=now)
    producer = secure_repo_path(
        root, pathlib.Path(producer_path), "Manifest producer", must_exist=True
    )
    artifact_relative = artifact_path.relative_to(root).as_posix()
    artifact_payload, info, _artifact_posix = bind_repo_file(
        root, artifact_relative, "Manifest artifact", max_bytes=MAX_JSON_BYTES
    )
    expected_artifact = {
        "path": artifact_relative,
        "sha256": sha256_bytes(artifact_payload),
        "bytes": info.st_size,
        "modified_time_ns": info.st_mtime_ns,
    }
    expected_producer = {
        "path": producer_path,
        "sha256": sha256_file(producer),
    }
    rendered = render(
        bound_source["url"],  # type: ignore[arg-type]
        bound_source["sha256"],  # type: ignore[arg-type]
        version,
        flutter,
    )
    if artifact_payload != rendered:
        raise ManifestContractError(
            "Manifest bytes do not match the exact target renderer."
        )
    validate_shell(extract_shell(artifact_payload))
    if (
        _require_int(record.get("schema_version"), "schema_version") != SCHEMA_VERSION
        or _require_str(record.get("contract"), "contract") != CONTRACT
        or _require_str(record.get("target_id"), "target_id") != target_id
        or _require_str(record.get("platform"), "platform") != "linux"
        or _require_str(record.get("artifact_format"), "artifact_format")
        != artifact_format
        or artifact_record != expected_artifact
        or producer_record != expected_producer
        or _require_bool(
            record.get("verification_network_accessed"),
            "verification_network_accessed",
        )
        is not False
        or _require_bool(
            record.get("publication_authorized"), "publication_authorized"
        )
        is not False
        or _require_bool(record.get("upload_attempted"), "upload_attempted") is not False
        or _require_bool(record.get("manifest_only"), "manifest_only") is not True
        or _require_bool(record.get("package_verified"), "package_verified") is not False
        or _require_str(record.get("sha256_anchor"), "sha256_anchor") != anchor.name
    ):
        raise ManifestContractError("Manifest receipt binding is invalid or changed.")
    result = {
        "ok": True,
        "target": target_id,
        "receipt_sha256": sha256_bytes(receipt_payload),
        "artifact_sha256": expected_artifact["sha256"],
        "artifact_size_bytes": expected_artifact["bytes"],
        "producer": expected_producer,
        "source": bound_source,
        "source_freeze": expected_freeze,
        "flutter_sdk": flutter_record(flutter),
        "created_utc": record.get("created_utc"),
        "verification_network_accessed": False,
        "publication_authorized": False,
        "upload_attempted": False,
        "manifest_only": True,
        "package_verified": False,
    }
    if "bound_packages" in result or result["package_verified"] is not False:
        raise ManifestContractError("Manifest verification must never claim package verification.")
    return result
