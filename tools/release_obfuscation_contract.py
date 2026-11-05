#!/usr/bin/env python3
"""Record and verify release hardening and secret-free evidence.

Obfuscation, R8 shrinking, native stripping, and store-permitted JavaScript
minification rename or remove symbols. They do not protect client-held
secrets. Durable secrets remain server-side. A missing artifact or a missing
authenticated receipt fails closed.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import math
import os
import pathlib
import re
import select
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from types import ModuleType

if __package__:
    from tools.release_secret_scan_policy import LONG_LIVED_CREDENTIAL_PATTERNS
    from tools.release_secret_scan_policy import packaged_credential_assignment
    from tools.release_secret_scan_policy import service_account_member_name
else:
    from release_secret_scan_policy import LONG_LIVED_CREDENTIAL_PATTERNS
    from release_secret_scan_policy import packaged_credential_assignment
    from release_secret_scan_policy import service_account_member_name


ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTRACT_PATH = pathlib.Path(__file__).resolve()
PRIVATE_SYMBOL_ROOT = (ROOT / ".artifacts" / "private-release-symbols").resolve()
ANDROID_APK_SO_RE = re.compile(r"lib/[^/]+/lib[^/]+\.so")
ANDROID_AAB_SO_RE = re.compile(r"(?:base|split_[^/]+)/lib/[^/]+/lib[^/]+\.so")
STORE_ONLY_DEBUG_METADATA_RE = re.compile(
    r"(?i)(?:^|!/)BUNDLE-METADATA/com\.android\.tools\.build\.debugsymbols/"
)
STORE_ONLY_OBFUSCATION_METADATA_RE = re.compile(
    r"(?i)(?:^|!/)BUNDLE-METADATA/com\.android\.tools\.build\.obfuscation/"
    r"proguard\.map$"
)
PACKAGED_PRIVATE_SYMBOL_SUFFIXES = (
    ".bcsymbolmap",
    ".dbg",
    ".debug",
    ".dwo",
    ".dwp",
    ".ilk",
    ".iobj",
    ".ipdb",
    ".map",
    ".pdb",
    ".sym",
    ".symbols",
)
SOURCE_MAP_REFERENCE_RE = re.compile(rb"(?i)(?:sourceMappingURL|sourceURL)\s*=")
ELF_MAGIC = b"\x7fELF"
MACHO_THIN_MAGICS = {
    b"\xfe\xed\xfa\xce": ">",
    b"\xce\xfa\xed\xfe": "<",
    b"\xfe\xed\xfa\xcf": ">",
    b"\xcf\xfa\xed\xfe": "<",
}
MACHO_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
# Distinctive internal names that Flutter --obfuscate and R8 must rename in
# customer blobs. These are implementation identifiers, not wire keys or ABI.
SENSITIVE_INTERNAL_IDENTIFIER_PROBES: tuple[tuple[str, bytes], ...] = (
    ("class", b"WinnV3StagedStart"),
    ("class", b"WinnV3SessionPlan"),
    ("class", b"WinnV3Posture"),
    ("class", b"AnnouncementVerifier"),
    ("class", b"PinnedOriginLedger"),
    ("method", b"protectOrRollback"),
    ("method", b"fromCompiledDefines"),
    ("method", b"createPinnedControlPlaneClient"),
    ("channel", b"wins_vpn/winn3_internal"),
    ("channel", b"wins_vpn/protocol_secret"),
    ("protocol-secret", b"Winn3DescriptorKeyRing"),
    ("protocol-secret", b"WinnCarrierProfileKeys"),
    ("protocol-secret", b"WinnV3Keys"),
    ("configuration", b"AwgUserspaceConfig"),
    ("configuration", b"WinnEngineConfig"),
    ("configuration", b"WinnCarrierProfile"),
)
# Manifest components, Flutter JNI, and shipping MethodChannel names that
# platforms require to remain readable after obfuscation.
REQUIRED_PUBLIC_PLATFORM_SYMBOLS: frozenset[bytes] = frozenset(
    {
        b"org.winsvpn.app.MainActivity",
        b"org.winsvpn.app.VpnTunnelService",
        b"org.winsvpn.app.SecretCodeReceiver",
        b"org.winsvpn.app.RealLauncherActivity",
        b"org.winsvpn.app.DecoyLauncherActivity",
        b"org.winsvpn.app.LauncherReal",
        b"org.winsvpn.app.LauncherDecoy",
        b"org.winsvpn.app.WatchCommandService",
        b"io.flutter.embedding.android.FlutterActivity",
        b"io.flutter.embedding.engine.FlutterJNI",
        b"io.flutter.embedding.engine.FlutterEngine",
        b"Java_io_flutter_embedding_engine_FlutterJNI",
        b"org.amnezia.awg.GoBackend",
        b"wins_vpn/tunnel",
        b"wins_vpn/watch",
        b"/winsvpn/cmd",
        b"PacketTunnelProvider",
        b"NEPacketTunnelProvider",
        b"FlutterViewController",
        b"GeneratedPluginRegistrant",
    }
)

# Release artifacts are intentionally bounded before any member is expanded.
# The limits are generous enough for current store artifacts, while making
# recursive inspection fail closed on archive bombs and pathological nesting.
MAX_ARCHIVE_INPUT_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBER_COUNT = 20_000
MAX_ARCHIVE_MEMBER_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_TOTAL_EXPANDED_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 1_000
MAX_ARCHIVE_RECURSION_DEPTH = 4
MAX_ARCHIVE_METADATA_FIELD_BYTES = 1024 * 1024
STANDALONE_HARDENING_SNAPSHOT_PREFIX = ".winsvpn-obf-hard-"
ZIP_ARCHIVE_SUFFIXES = (
    ".aab",
    ".aar",
    ".apk",
    ".ipa",
    ".jar",
    ".war",
    ".xpi",
    ".zip",
)
TAR_ARCHIVE_SUFFIXES = (
    ".tar",
    ".tar.bz2",
    ".tar.gz",
    ".tar.xz",
    ".tar.zst",
    ".tbz2",
    ".tgz",
    ".tzst",
    ".txz",
)
BZ2_TAR_SUFFIXES = (".tar.bz2", ".tbz2")
XZ_TAR_SUFFIXES = (".tar.xz", ".txz")
ZSTD_TAR_SUFFIXES = (".tar.zst", ".tzst")
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
ZIP_DATA_DESCRIPTOR_FLAG = 0x8
ZIP_DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
BZ2_MAGIC = b"BZh"
XZ_MAGIC = b"\xfd7zXZ\0"
ZSTD_MAGIC = b"(\xb5/\xfd"
COMPRESSED_TAR_CHUNK_BYTES = 1024 * 1024


class ObfuscationError(RuntimeError):
    pass


ANDROID_CROSS_STORE_TARGETS = {
    "android-phone-tablet-aab": "android-aab",
    "android-tv-aab": "android-tv-aab",
}
APPLE_CROSS_STORE_TARGETS = {
    "ios-app-store-ipa": "ios",
    "macos-app-store-pkg": "macos",
    "macos-developer-id-app": "macos",
}
MACOS_CROSS_STORE_TARGET_LAYOUT = {
    "macos-app-store-pkg": {
        "channel": "mac-app-store",
        "signing_contract": "apple-distribution",
        "surface": "app-store",
        "artifact_name": "WinsVPN.pkg",
        "artifact_suffixes": (".pkg",),
        "expected_authority": "Authority=Apple Distribution:",
        "required": True,
    },
    "macos-developer-id-app": {
        "channel": "developer-id",
        "signing_contract": "developer-id-application",
        "surface": "developer-id",
        "artifact_name": "WinsVPN.app.zip",
        "artifact_suffixes": (".app.zip",),
        "expected_authority": "Authority=Developer ID Application:",
        "required": False,
    },
}
LINUX_PACKAGE_CROSS_STORE_TARGETS = {
    "linux-x64-package": "x64",
    "linux-arm64-package": "arm64",
}
LINUX_MANIFEST_CROSS_STORE_TARGETS = {
    "linux-flathub-manifest": "linux/packaging/flathub/manifest_artifact.py",
    "linux-snap-manifest": "linux/packaging/snap/manifest_artifact.py",
}
WINDOWS_CROSS_STORE_TARGET_LAYOUT = {
    "windows-x64-installer": ("x64", "website"),
    "windows-x64-partner-center": ("x64", "partner-center"),
    "windows-arm64-installer": ("arm64", "website"),
    "windows-arm64-partner-center": ("arm64", "partner-center"),
}
WINDOWS_CROSS_STORE_TARGETS = set(WINDOWS_CROSS_STORE_TARGET_LAYOUT)
WEAR_CROSS_STORE_TARGETS = {
    "wear-os-aab": "wear-os",
}
EXTENSION_CROSS_STORE_TARGETS = {
    "chrome-extension-package": "chrome",
    "edge-extension-package": "edge",
    "firefox-extension-package": "firefox",
}
EXTENSION_PLATFORMS = frozenset(EXTENSION_CROSS_STORE_TARGETS.values())
FLUTTER_OBFUSCATION_PLATFORMS = frozenset(
    {"android-apk", "android-aab", "ios", "macos", "windows", "linux"}
)
ANDROID_R8_PLATFORMS = frozenset({"android-apk", "android-aab", "wear-os"})
STORE_METADATA_PLATFORMS = frozenset({"android-aab", "wear-os"})
MIN_R8_MAPPING_BYTES = 2048
R8_MAPPING_FILENAMES = ("mapping.txt", "proguard-mapping.txt")
# The Watch app's executable is named after its bundle (WinsWatch.app/WinsWatch);
# its other top-level members (Assets.car, Info.plist, PkgInfo) are not code.
WATCHOS_EXECUTABLE_RE = re.compile(
    r"(?i)(?:^|!/)Payload/[^/]+\.app/Watch/([^/]+)\.app/\1$"
)
EXTENSION_JS_SUFFIXES = (".js", ".mjs", ".cjs")
EXTENSION_OBFUSCATOR_RE = re.compile(
    rb"(?i)(?:javascript-obfuscator|controlFlowFlattening|control-flow-flatten|"
    rb"_0x[a-f0-9]{4,}|eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e)"
)
EXACT_PACKAGE_TARGET_ARTIFACT_NAMES = {
    "linux-x64-package": "wins-vpn-linux-x64.tar.gz",
    "linux-arm64-package": "wins-vpn-linux-arm64.tar.gz",
    "windows-x64-installer": "WinsVPN-Setup.exe",
    "windows-x64-partner-center": "WinsVPN-PartnerCenter.exe",
    "windows-arm64-installer": "WinsVPN-Setup-arm64.exe",
    "windows-arm64-partner-center": "WinsVPN-PartnerCenter-arm64.exe",
}
# build_installer.ps1 -AllowUnsigned names its installer WinsVPN-UNSIGNED-LOCAL-*. The
# privacy validator already accepts these names for the same exact targets
# (validate_release_artifact_privacy.TARGET_CANONICAL_FILENAMES), so the exact-target
# obfuscation record and verify steps of that producer accept them too.
WINDOWS_UNSIGNED_LOCAL_ARTIFACT_NAMES = {
    "windows-x64-installer": "WinsVPN-UNSIGNED-LOCAL-Setup.exe",
    "windows-x64-partner-center": "WinsVPN-UNSIGNED-LOCAL-PartnerCenter.exe",
    "windows-arm64-installer": "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe",
    "windows-arm64-partner-center": "WinsVPN-UNSIGNED-LOCAL-PartnerCenter-arm64.exe",
}
EXTENSION_TARGET_ARTIFACT_NAMES = {
    "chrome-extension-package": ("wins-vpn-companion-chrome.zip",),
    "edge-extension-package": ("wins-vpn-companion-edge.zip",),
    "firefox-extension-package": (
        "wins-vpn-companion-firefox.zip",
        "wins-vpn-companion-firefox.xpi",
    ),
}
EXACT_BOUND_TARGET_IDS = frozenset(EXACT_PACKAGE_TARGET_ARTIFACT_NAMES) | frozenset(
    WEAR_CROSS_STORE_TARGETS
) | frozenset(EXTENSION_CROSS_STORE_TARGETS) | frozenset(MACOS_CROSS_STORE_TARGET_LAYOUT)
FINAL_APP_TARGET_IDS = (
    "android-phone-tablet-aab",
    "android-tv-aab",
    "wear-os-aab",
    "ios-app-store-ipa",
    "macos-app-store-pkg",
    "macos-developer-id-app",
    "windows-x64-installer",
    "windows-x64-partner-center",
    "windows-arm64-installer",
    "windows-arm64-partner-center",
    "linux-x64-package",
    "linux-arm64-package",
    "chrome-extension-package",
    "edge-extension-package",
    "firefox-extension-package",
)
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "contract_sha256",
        "platform",
        "app_version",
        "build_number",
        "created_at_utc",
        "private_symbols_not_packaged",
        "verification",
        "artifacts",
        "symbols",
    }
)
_TARGET_BOUND_MANIFEST_KEYS = _MANIFEST_KEYS | {"target_id"}
APPLE_CROSS_STORE_GATE_HELPER = ROOT / "tools" / "apple_cross_store_artifact_gate.py"
APPLE_RELEASE_CONTAMINATION_GATE_HELPER = (
    ROOT / "tools" / "apple_release_contamination_gate.py"
)
APPLE_CROSS_STORE_GATE_HELPER_SHA256 = (
    "085ff8207115f37ada27c151abcd6da751531c5be33dfc5029654a7be003f203"
)
APPLE_RELEASE_CONTAMINATION_GATE_HELPER_SHA256 = (
    "db986f4fe5e0c8538f2ecf048f606d69265a15ed828036778fa4f1df558bb3db"
)
REVIEWED_HELPER_MAX_BYTES = 12 * 1024 * 1024
ANDROID_TOOLCHAIN_LAUNCHER = ROOT / "tools" / "launch_macos_release_android_toolchains.py"
ANDROID_TOOLCHAIN_LAUNCHER_SHA256 = (
    "17401342ad647350b74a17a200b7e5a0c66c4a1d1c6c59012163e147e59758fa"
)
_STORE_JS_MINIFIER: ModuleType | None = None
STORE_JS_MINIFIER_SOURCE = ROOT / "extension" / "tools" / "store_js_minifier.py"
STORE_JS_MINIFIER_SHA256 = (
    "97644176eaacd937f962a294f09a1ca3cb3fd8864a1ff02d2468d615bf07c457"
)
OBFUSCATION_RECEIPT_JSON_MAX_BYTES = 8 * 1024 * 1024


def _strict_receipt_json_loads(
    payload: bytes,
    label: str,
    *,
    max_bytes: int = OBFUSCATION_RECEIPT_JSON_MAX_BYTES,
) -> object:
    if not payload or len(payload) > max_bytes:
        raise ObfuscationError(f"{label} JSON size is invalid")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ObfuscationError(f"{label} is not strict UTF-8 JSON") from exc

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ObfuscationError(f"{label} JSON contains duplicate key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ObfuscationError(f"{label} JSON contains non-finite value {value}")

    def strict_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ObfuscationError(f"{label} JSON contains non-finite value {value}")
        return parsed

    try:
        return json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
            parse_float=strict_float,
        )
    except ObfuscationError:
        raise
    except json.JSONDecodeError as exc:
        raise ObfuscationError(f"{label} is not valid JSON") from exc


def _reviewed_directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _reviewed_file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


class _ReviewedSourceCustody:
    def __init__(self, path: pathlib.Path, label: str) -> None:
        self.path = pathlib.Path(os.path.abspath(os.fspath(path)))
        self.label = label
        self._records: list[tuple[int | None, str, int, os.stat_result, bool]] = []
        self._queue: object | None = None
        self._closed = False
        self._file_fd = -1
        if os.name == "nt":
            try:
                self._open_windows_source()
            except Exception:
                self.close(verify=False)
                raise
            return
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
        if not self.path.is_absolute() or directory_flag == 0 or nofollow_flag == 0:
            raise ObfuscationError(
                f"{label} requires absolute O_NOFOLLOW source custody"
            )
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | directory_flag | nofollow_flag
        file_flags = os.O_RDONLY | os.O_CLOEXEC | nofollow_flag
        try:
            current = os.open(os.sep, directory_flags)
            self._append(None, "", current, directory=True)
            for component in self.path.parts[1:-1]:
                child = os.open(component, directory_flags, dir_fd=current)
                self._append(current, component, child, directory=True)
                current = child
            self._file_fd = os.open(self.path.name, file_flags, dir_fd=current)
            self._append(current, self.path.name, self._file_fd, directory=False)
            self._start_watch()
            self.verify()
        except Exception:
            self.close(verify=False)
            raise

    def _open_windows_source(self) -> None:
        # Windows has no O_NOFOLLOW, O_DIRECTORY or descriptor-relative open.
        # Refuse a link or reparse point at every component of the path, then
        # hold one descriptor on the file. The payload is compared with its
        # reviewed sha256 before it is compiled, so the held descriptor and the
        # identity re-check in verify() are defense in depth, not the control.
        if not self.path.is_absolute():
            raise ObfuscationError(f"{self.label} requires absolute source custody")
        reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        current = pathlib.Path(self.path.anchor)
        for component in self.path.parts[1:]:
            current = current / component
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & reparse_point:
                raise ObfuscationError(
                    f"{self.label} source path contains a link or reparse point"
                )
        file_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        self._file_fd = os.open(self.path, file_flags)
        self._append(None, self.path.name, self._file_fd, directory=False)
        self.verify()

    def _append(
        self,
        parent_fd: int | None,
        name: str,
        fd: int,
        *,
        directory: bool,
    ) -> None:
        info = os.fstat(fd)
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                os.close(fd)
                raise ObfuscationError(f"{self.label} ancestor is not a directory")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(fd)
            raise ObfuscationError(
                f"{self.label} source is not a single-link regular file"
            )
        self._records.append((parent_fd, name, fd, info, directory))

    def _start_watch(self) -> None:
        if not hasattr(select, "kqueue"):
            if sys.platform == "darwin":
                raise ObfuscationError(f"{self.label} ancestor watch is unavailable")
            return
        queue = select.kqueue()
        custody_flags = (
            select.KQ_NOTE_DELETE
            | select.KQ_NOTE_RENAME
            | select.KQ_NOTE_REVOKE
            | select.KQ_NOTE_ATTRIB
        )
        try:
            for _parent, _name, fd, _before, directory in self._records:
                flags = custody_flags
                if not directory:
                    flags |= select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_LINK
                queue.control(
                    [
                        select.kevent(
                            fd,
                            filter=select.KQ_FILTER_VNODE,
                            flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                            fflags=flags,
                        )
                    ],
                    0,
                    0,
                )
        except Exception:
            queue.close()
            raise
        self._queue = queue

    def payload(self) -> bytes:
        before = os.fstat(self._file_fd)
        if before.st_size <= 0 or before.st_size > REVIEWED_HELPER_MAX_BYTES:
            raise ObfuscationError(f"{self.label} source size is invalid")
        os.lseek(self._file_fd, 0, os.SEEK_SET)
        payload = bytearray()
        while len(payload) <= REVIEWED_HELPER_MAX_BYTES:
            chunk = os.read(
                self._file_fd,
                min(65536, REVIEWED_HELPER_MAX_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(self._file_fd)
        if (
            len(payload) != before.st_size
            or len(payload) > REVIEWED_HELPER_MAX_BYTES
            or _reviewed_file_identity(before) != _reviewed_file_identity(after)
        ):
            raise ObfuscationError(f"{self.label} source changed while it was read")
        return bytes(payload)

    def _reject_events(self) -> None:
        if self._queue is not None and self._queue.control(
            None, max(1, len(self._records) * 2), 0
        ):
            raise ObfuscationError(
                f"{self.label} source or trusted ancestor changed during execution"
            )

    def verify(self) -> None:
        if self._closed:
            raise ObfuscationError(f"{self.label} source custody is closed")
        self._reject_events()
        for parent_fd, name, fd, before, directory in self._records:
            identity = _reviewed_directory_identity if directory else _reviewed_file_identity
            if identity(os.fstat(fd)) != identity(before):
                raise ObfuscationError(f"{self.label} retained source identity changed")
            if parent_fd is not None:
                try:
                    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except OSError as exc:
                    raise ObfuscationError(
                        f"{self.label} source or trusted ancestor path disappeared"
                    ) from exc
                if identity(named) != identity(before):
                    raise ObfuscationError(
                        f"{self.label} source or trusted ancestor path was replaced"
                    )
            elif os.name == "nt" and not directory:
                try:
                    named = os.stat(self.path)
                except OSError as exc:
                    raise ObfuscationError(
                        f"{self.label} source path disappeared"
                    ) from exc
                if (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns) != (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                ):
                    raise ObfuscationError(f"{self.label} source path was replaced")
        self._reject_events()

    def close(self, *, verify: bool = True) -> None:
        if self._closed:
            return
        error: BaseException | None = None
        if verify:
            try:
                self.verify()
            except BaseException as exc:
                error = exc
        self._closed = True
        if self._queue is not None:
            try:
                self._queue.close()
            except OSError:
                pass
            self._queue = None
        for _parent, _name, fd, _before, _directory in reversed(self._records):
            try:
                os.close(fd)
            except OSError:
                pass
        self._records.clear()
        self._file_fd = -1
        if error is not None:
            raise error


def _load_reviewed_helper(
    path: pathlib.Path,
    expected_sha256: str,
    label: str,
) -> ModuleType:
    custody = _ReviewedSourceCustody(path, label)
    module: ModuleType | None = None
    module_name = ""
    completed = False
    try:
        payload = custody.payload()
        digest = hashlib.sha256(payload).hexdigest()
        if digest != expected_sha256:
            raise ObfuscationError(f"{label} source hash is not reviewed")
        try:
            code = compile(payload, str(custody.path), "exec", dont_inherit=True)
        except (SyntaxError, ValueError) as exc:
            raise ObfuscationError(f"{label} reviewed source could not be compiled") from exc
        module_name = f"_winsvpn_reviewed_{label}_{digest}_{id(payload):x}"
        if module_name in sys.modules:
            raise ObfuscationError(f"{label} isolated module name is already occupied")
        module = ModuleType(module_name)
        module.__file__ = str(custody.path)
        module.__package__ = ""
        module.__winsvpn_source_sha256__ = digest
        module.__winsvpn_reviewed_origin_root__ = str(custody.path.parents[1])
        module.__winsvpn_reviewed_tools_dir__ = str(custody.path.parent)
        sys.modules[module_name] = module
        exec(code, module.__dict__)
        if sys.modules.get(module_name) is not module:
            raise ObfuscationError(f"{label} isolated module identity changed")
        custody.verify()
        completed = True
        return module
    finally:
        if module is not None and sys.modules.get(module_name) is module:
            del sys.modules[module_name]
        custody.close(verify=completed)


def _store_js_minifier() -> ModuleType:
    global _STORE_JS_MINIFIER
    if _STORE_JS_MINIFIER is not None:
        if (
            getattr(_STORE_JS_MINIFIER, "__winsvpn_source_sha256__", None)
            != STORE_JS_MINIFIER_SHA256
        ):
            raise ObfuscationError("cached store JavaScript minifier is not reviewed")
        return _STORE_JS_MINIFIER
    module = _load_reviewed_helper(
        STORE_JS_MINIFIER_SOURCE,
        STORE_JS_MINIFIER_SHA256,
        "store_js_minifier",
    )
    required = (
        "MinifyError",
        "producer_packaged_javascript",
        "reject_javascript_evasions",
        "require_static_source_members",
        "require_zip_javascript_matches_producer",
        "source_map_reference_present",
        "zip_hygiene_failures",
    )
    if any(not hasattr(module, name) for name in required):
        raise ObfuscationError("reviewed store JavaScript minifier API is incomplete")
    _STORE_JS_MINIFIER = module
    return module


def _source_map_reference_present(data: bytes | str) -> bool:
    minifier = _store_js_minifier()
    text = data if isinstance(data, str) else data.decode("utf-8", "replace")
    if minifier.source_map_reference_present(text):
        return True
    raw = data if isinstance(data, bytes) else data.encode("utf-8", "replace")
    return SOURCE_MAP_REFERENCE_RE.search(raw) is not None


def _extension_javascript_producer_key(label: str) -> str:
    normalized = label.replace("\\", "/")
    if "!/" in normalized:
        normalized = normalized.split("!/", 1)[-1]
    return normalized


def _extension_minify_error(exc: BaseException) -> ObfuscationError:
    message = str(exc)
    lowered = message.lower()
    if "obfuscation" in lowered:
        return ObfuscationError(
            f"{message}. Chrome forbids obfuscation; store-permitted --minify "
            "transforms are size reductions only and are not secret protection."
        )
    if "not store-permitted minified" in lowered:
        return ObfuscationError(
            f"{message}. Minification is required and does not protect "
            "client-held secrets."
        )
    return ObfuscationError(message)


def _unpack(data: bytes, offset: int, fmt: str):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ObfuscationError("truncated native binary")
    return struct.unpack_from(fmt, data, offset)


def _fixed_ascii_name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")


def _elf_debug_section_names(data: bytes) -> tuple[str, ...]:
    if len(data) < 52 or not data.startswith(ELF_MAGIC):
        raise ObfuscationError("truncated ELF")
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in {1, 2} or ei_data not in {1, 2}:
        raise ObfuscationError("unsupported ELF ident")
    endian = "<" if ei_data == 1 else ">"
    if ei_class == 2:
        if len(data) < 64:
            raise ObfuscationError("truncated ELF64")
        e_shoff = _unpack(data, 40, endian + "Q")[0]
        e_shentsize = _unpack(data, 58, endian + "H")[0]
        e_shnum = _unpack(data, 60, endian + "H")[0]
        e_shstrndx = _unpack(data, 62, endian + "H")[0]
        offset_fmt = endian + "Q"
        sh_offset_at = 24
        sh_size_at = 32
        min_shdr = 40
    else:
        e_shoff = _unpack(data, 32, endian + "I")[0]
        e_shentsize = _unpack(data, 46, endian + "H")[0]
        e_shnum = _unpack(data, 48, endian + "H")[0]
        e_shstrndx = _unpack(data, 50, endian + "H")[0]
        offset_fmt = endian + "I"
        sh_offset_at = 16
        sh_size_at = 20
        min_shdr = 24
    if e_shoff == 0:
        return ()
    if e_shentsize < min_shdr or e_shoff + e_shentsize > len(data):
        raise ObfuscationError("invalid ELF section table")
    if e_shnum == 0:
        e_shnum = _unpack(data, e_shoff + sh_size_at, offset_fmt)[0]
    if e_shstrndx == 0xFFFF:
        sh_link_at = 40 if ei_class == 2 else 24
        e_shstrndx = _unpack(data, e_shoff + sh_link_at, endian + "I")[0]
    if (
        e_shnum == 0
        or e_shnum > 4096
        or e_shstrndx >= e_shnum
        or e_shoff + (e_shnum * e_shentsize) > len(data)
    ):
        raise ObfuscationError("invalid ELF extended section table")
    str_hdr = e_shoff + (e_shstrndx * e_shentsize)
    str_off = _unpack(data, str_hdr + sh_offset_at, offset_fmt)[0]
    str_size = _unpack(data, str_hdr + sh_size_at, offset_fmt)[0]
    if str_off + str_size > len(data):
        raise ObfuscationError("invalid ELF string table")
    strtab = data[str_off : str_off + str_size]
    found: list[str] = []
    for index in range(e_shnum):
        hdr = e_shoff + (index * e_shentsize)
        name_off = _unpack(data, hdr, endian + "I")[0]
        section_type = _unpack(data, hdr + 4, endian + "I")[0]
        if name_off >= len(strtab):
            raise ObfuscationError("invalid ELF section name")
        name = _fixed_ascii_name(strtab[name_off:])
        if (
            name == ".debug"
            or name.startswith(".debug_")
            or name.startswith(".zdebug_")
            or name.startswith(".rel.debug")
            or name.startswith(".rela.debug")
            or name.startswith(".rel.zdebug")
            or name.startswith(".rela.zdebug")
            or name == ".symtab"
            or name == ".gnu_debugdata"
            or name == ".gdb_index"
            or name.startswith(".stab")
        ):
            found.append(name)
        elif section_type == 2:
            found.append(f"SHT_SYMTAB:{name or '<unnamed>'}")
        elif section_type == 18:
            found.append(f"SHT_SYMTAB_SHNDX:{name or '<unnamed>'}")
    return tuple(found)


def _macho_thin_debug_section_names(data: bytes) -> tuple[str, ...]:
    magic = data[:4]
    endian = MACHO_THIN_MAGICS.get(magic)
    if endian is None:
        raise ObfuscationError("unsupported Mach-O magic")
    is_64 = magic in {b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
    header_size = 32 if is_64 else 28
    if len(data) < header_size:
        raise ObfuscationError("truncated Mach-O")
    ncmds = _unpack(data, 16, endian + "I")[0]
    sizeofcmds = _unpack(data, 20, endian + "I")[0]
    if ncmds > 512 or header_size + sizeofcmds > len(data):
        raise ObfuscationError("invalid Mach-O load commands")
    cursor = header_size
    limit = header_size + sizeofcmds
    found: list[str] = []
    symtab: tuple[int, int, int, int] | None = None
    for _ in range(ncmds):
        cmd, cmdsize = _unpack(data, cursor, endian + "II")
        if cmdsize < 8 or cursor + cmdsize > limit:
            raise ObfuscationError("invalid Mach-O load command")
        base_cmd = cmd & 0x7FFFFFFF
        if base_cmd in {0x1, 0x19}:
            if cmdsize < 24:
                raise ObfuscationError("truncated Mach-O segment")
            segname = _fixed_ascii_name(data[cursor + 8 : cursor + 24])
            if segname == "__DWARF" or segname.startswith("__DWARF"):
                found.append(segname)
            nsects_at = 64 if base_cmd == 0x19 else 48
            sect_size = 80 if base_cmd == 0x19 else 68
            if cmdsize < nsects_at + 4:
                raise ObfuscationError("truncated Mach-O segment")
            nsects = _unpack(data, cursor + nsects_at, endian + "I")[0]
            sect_off = cursor + (72 if base_cmd == 0x19 else 56)
            if nsects > 256 or sect_off + (nsects * sect_size) > cursor + cmdsize:
                raise ObfuscationError("invalid Mach-O section table")
            for index in range(nsects):
                start = sect_off + (index * sect_size)
                sectname = _fixed_ascii_name(data[start : start + 16])
                if sectname.startswith("__debug"):
                    found.append(sectname)
        elif base_cmd == 0x2:  # LC_SYMTAB
            if cmdsize < 24:
                raise ObfuscationError("truncated Mach-O symbol table command")
            symoff, nsyms, stroff, strsize = _unpack(
                data, cursor + 8, endian + "IIII"
            )
            symtab = (symoff, nsyms, stroff, strsize)
            nlist_size = 16 if is_64 else 12
            if (
                nsyms > 10_000_000
                or symoff + (nsyms * nlist_size) > len(data)
                or stroff + strsize > len(data)
            ):
                raise ObfuscationError("invalid Mach-O symbol table")
            strip_markers = 0
            for index in range(nsyms):
                n_type = data[symoff + (index * nlist_size) + 4]
                if n_type == MACHO_N_OPT and _macho_symbol_name(
                    data, symoff + (index * nlist_size), endian, stroff, strsize
                ) == APPLE_LINKER_STRIP_MARKER:
                    # ld64 writes this one N_OPT marker into every executable
                    # and strip(1) keeps it on purpose; it names no code. A
                    # second one was not left by ld64 and strip, whatever
                    # LC_DYSYMTAB (or its absence) says about the local count.
                    strip_markers += 1
                    if strip_markers > 1:
                        found.append("LC_SYMTAB_STAB")
                        break
                    continue
                if n_type & 0xE0:
                    found.append("LC_SYMTAB_STAB")
                    break
                if not n_type & 0x01:
                    found.append("LC_SYMTAB_LOCAL")
                    break
        elif base_cmd == 0xB:  # LC_DYSYMTAB
            if cmdsize < 80:
                raise ObfuscationError("truncated Mach-O dynamic symbol command")
            ilocalsym, nlocalsym = _unpack(data, cursor + 8, endian + "II")
            if nlocalsym and not (
                nlocalsym == 1
                and _macho_local_is_linker_strip_marker(
                    data, symtab, ilocalsym, endian, 16 if is_64 else 12
                )
            ):
                found.append("LC_DYSYMTAB_LOCAL")
        cursor += cmdsize
    return tuple(found)


MACHO_N_OPT = 0x3C
APPLE_LINKER_STRIP_MARKER = b"radr://5614542"


def _macho_symbol_name(
    data: bytes, nlist_at: int, endian: str, stroff: int, strsize: int
) -> bytes | None:
    n_strx = _unpack(data, nlist_at, endian + "I")[0]
    if n_strx >= strsize:
        return None
    start = stroff + n_strx
    end = data.find(b"\0", start, stroff + strsize)
    if end < 0:
        return None
    return data[start:end]


def _macho_local_is_linker_strip_marker(
    data: bytes,
    symtab: tuple[int, int, int, int] | None,
    index: int,
    endian: str,
    nlist_size: int,
) -> bool:
    # The single local symbol of a stripped ld64 executable is the N_OPT
    # marker; an LC_DYSYMTAB seen before its LC_SYMTAB never qualifies.
    if symtab is None:
        return False
    symoff, nsyms, stroff, strsize = symtab
    if index >= nsyms:
        return False
    nlist_at = symoff + (index * nlist_size)
    return (
        data[nlist_at + 4] == MACHO_N_OPT
        and _macho_symbol_name(data, nlist_at, endian, stroff, strsize)
        == APPLE_LINKER_STRIP_MARKER
    )


def _macho_debug_section_names(data: bytes) -> tuple[str, ...]:
    fat = MACHO_FAT_MAGICS.get(data[:4])
    if fat is None:
        return _macho_thin_debug_section_names(data)
    endian, is_64 = fat
    if len(data) < 8:
        raise ObfuscationError("truncated fat Mach-O")
    nfat = _unpack(data, 4, endian + "I")[0]
    entry_size = 32 if is_64 else 20
    if nfat == 0 or nfat > 16 or 8 + (nfat * entry_size) > len(data):
        raise ObfuscationError("invalid fat Mach-O")
    found: list[str] = []
    for index in range(nfat):
        entry = 8 + (index * entry_size)
        if is_64:
            slice_off = _unpack(data, entry + 8, endian + "Q")[0]
            slice_size = _unpack(data, entry + 16, endian + "Q")[0]
        else:
            slice_off = _unpack(data, entry + 8, endian + "I")[0]
            slice_size = _unpack(data, entry + 12, endian + "I")[0]
        if slice_off + slice_size > len(data):
            raise ObfuscationError("truncated fat Mach-O slice")
        found.extend(_macho_thin_debug_section_names(data[slice_off : slice_off + slice_size]))
    return tuple(found)


def _pe_debug_section_names(data: bytes) -> tuple[str, ...]:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ObfuscationError("truncated PE")
    e_lfanew = _unpack(data, 60, "<I")[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return ()
    num_sections = _unpack(data, e_lfanew + 6, "<H")[0]
    size_of_optional = _unpack(data, e_lfanew + 20, "<H")[0]
    coff_symbol_pointer = _unpack(data, e_lfanew + 12, "<I")[0]
    coff_symbol_count = _unpack(data, e_lfanew + 16, "<I")[0]
    optional_start = e_lfanew + 24
    section_start = e_lfanew + 24 + size_of_optional
    if num_sections > 96 or section_start + (num_sections * 40) > len(data):
        raise ObfuscationError("invalid PE section table")
    found: list[str] = []
    if coff_symbol_count:
        coff_table_end = coff_symbol_pointer + (coff_symbol_count * 18)
        if coff_symbol_pointer == 0 or coff_table_end + 4 > len(data):
            raise ObfuscationError("invalid PE COFF symbol table")
        string_table_size = _unpack(data, coff_table_end, "<I")[0]
        if string_table_size < 4 or coff_table_end + string_table_size > len(data):
            raise ObfuscationError("invalid PE COFF string table")
        found.append("COFF_SYMTAB")
    elif coff_symbol_pointer:
        if coff_symbol_pointer + 4 > len(data):
            raise ObfuscationError("invalid empty PE COFF symbol table")
        string_table_size = _unpack(data, coff_symbol_pointer, "<I")[0]
        if string_table_size != 4:
            raise ObfuscationError("invalid empty PE COFF string table")
    section_ranges: list[tuple[int, int, int, int]] = []
    for index in range(num_sections):
        start = section_start + (index * 40)
        name = _fixed_ascii_name(data[start : start + 8])
        if name.startswith(".debug"):
            found.append(name)
        virtual_size = _unpack(data, start + 8, "<I")[0]
        virtual_address = _unpack(data, start + 12, "<I")[0]
        raw_size = _unpack(data, start + 16, "<I")[0]
        raw_pointer = _unpack(data, start + 20, "<I")[0]
        if raw_pointer + raw_size > len(data):
            raise ObfuscationError("invalid PE section payload")
        section_ranges.append(
            (virtual_address, max(virtual_size, raw_size), raw_pointer, raw_size)
        )

    if size_of_optional == 0:
        return tuple(found)
    if optional_start + size_of_optional > len(data):
        raise ObfuscationError("truncated PE optional header")
    magic = _unpack(data, optional_start, "<H")[0]
    if magic == 0x10B:
        rva_count_at = 92
        directories_at = 96
    elif magic == 0x20B:
        rva_count_at = 108
        directories_at = 112
    else:
        raise ObfuscationError("unsupported PE optional header")
    if size_of_optional < rva_count_at + 4:
        raise ObfuscationError("truncated PE data-directory count")
    directory_count = _unpack(data, optional_start + rva_count_at, "<I")[0]
    if directory_count <= 6:
        return tuple(found)
    debug_entry_at = optional_start + directories_at + (6 * 8)
    if debug_entry_at + 8 > optional_start + size_of_optional:
        raise ObfuscationError("truncated PE debug data-directory entry")
    debug_rva, debug_size = _unpack(data, debug_entry_at, "<II")
    if debug_rva == 0 and debug_size == 0:
        return tuple(found)
    if debug_rva == 0 or debug_size == 0 or debug_size % 28 != 0:
        raise ObfuscationError("invalid PE debug directory")

    size_of_headers = _unpack(data, optional_start + 60, "<I")[0]

    def rva_to_offset(rva: int, size: int) -> int:
        if rva < size_of_headers and rva + size <= min(size_of_headers, len(data)):
            return rva
        for virtual_address, mapped_size, raw_pointer, raw_size in section_ranges:
            if virtual_address <= rva and rva + size <= virtual_address + mapped_size:
                relative = rva - virtual_address
                if relative + size > raw_size:
                    break
                return raw_pointer + relative
        raise ObfuscationError("PE debug directory does not map to file data")

    debug_offset = rva_to_offset(debug_rva, debug_size)
    allowed_non_symbol_types = {16, 20}  # reproducible-build and extended-DLL metadata
    for index in range(debug_size // 28):
        entry = debug_offset + (index * 28)
        debug_type = _unpack(data, entry + 12, "<I")[0]
        data_size = _unpack(data, entry + 16, "<I")[0]
        data_pointer = _unpack(data, entry + 24, "<I")[0]
        if data_size and (data_pointer == 0 or data_pointer + data_size > len(data)):
            raise ObfuscationError("invalid PE debug data payload")
        if debug_type not in allowed_non_symbol_types:
            found.append(f"PE_DEBUG_DIRECTORY_TYPE_{debug_type}")
    return tuple(found)


def inspect_native_debug_sections(data: bytes) -> tuple[str, tuple[str, ...]] | None:
    if data.startswith(ELF_MAGIC):
        return "elf", _elf_debug_section_names(data)
    if data[:4] in MACHO_THIN_MAGICS or data[:4] in MACHO_FAT_MAGICS:
        return "macho", _macho_debug_section_names(data)
    if data.startswith(b"MZ") and len(data) >= 64:
        e_lfanew = _unpack(data, 60, "<I")[0]
        if e_lfanew + 4 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\0\0":
            return "pe", _pe_debug_section_names(data)
    return None


def is_store_only_native_debug_metadata(label: str) -> bool:
    return STORE_ONLY_DEBUG_METADATA_RE.search(label.replace("\\", "/")) is not None


def is_store_only_obfuscation_metadata(label: str) -> bool:
    return STORE_ONLY_OBFUSCATION_METADATA_RE.search(label.replace("\\", "/")) is not None


def _blob_views(data: bytes) -> Iterator[bytes]:
    yield data
    if b"\0" not in data:
        return
    for encoding in ("utf-16-le", "utf-16-be"):
        # UTF-16 strings embedded in native/resource blobs are not guaranteed
        # to start on an even artifact offset. Decode both byte alignments for
        # each endianness so a one-byte prefix cannot evade identifier checks.
        for offset in (0, 1):
            decoded = data[offset:].decode(encoding, errors="ignore")
            yield decoded.encode("utf-8", errors="ignore")


def reject_packaged_private_symbols(platform: str, label: str, data: bytes) -> None:
    normalized = label.replace("\\", "/")
    folded = normalized.casefold()
    if platform in STORE_METADATA_PLATFORMS and (
        is_store_only_native_debug_metadata(normalized)
        or is_store_only_obfuscation_metadata(normalized)
    ):
        return
    parts = pathlib.PurePosixPath(folded).parts
    basename = parts[-1] if parts else folded
    if (
        any(part.endswith(".dsym") for part in parts)
        or basename in {"mapping.txt", "proguard-mapping.txt"}
        or basename.endswith(PACKAGED_PRIVATE_SYMBOL_SUFFIXES)
    ):
        raise ObfuscationError(
            f"Customer artifact contains a private symbol, debug companion, or source map: {label}"
        )
    if _source_map_reference_present(data):
        raise ObfuscationError(
            f"Customer artifact contains an external or inline source-map reference: {label}"
        )


def reject_embedded_long_lived_credentials(label: str, data: bytes) -> None:
    if service_account_member_name(label):
        raise ObfuscationError(
            f"{label} contains embedded long-lived credential category "
            "google_service_account_json. Obfuscation, R8 shrinking, native "
            "stripping, or minification is not remediation; durable secrets "
            "remain server-side. remove the credential from the distributable "
            "before rebuilding."
        )
    for view in _blob_views(data):
        for category, pattern in LONG_LIVED_CREDENTIAL_PATTERNS:
            if pattern.search(view):
                raise ObfuscationError(
                    f"{label} contains embedded long-lived credential category {category}. "
                    "Obfuscation, R8 shrinking, native stripping, or minification is not "
                    "remediation; durable secrets remain server-side. remove the credential "
                    "from the distributable before rebuilding."
                )
        if packaged_credential_assignment(view):
            folded = view.lower()
            category = (
                "activation_secret"
                if b"activation" in folded or b"x-wins-activation" in folded
                else "credential_assignment"
            )
            raise ObfuscationError(
                f"{label} contains embedded long-lived credential category {category}. "
                "Obfuscation, R8 shrinking, native stripping, or minification is not "
                "remediation; durable secrets remain server-side. remove the credential "
                "from the distributable before rebuilding."
            )


def _is_identifier_continuation_byte(value: int) -> bool:
    return (
        48 <= value <= 57
        or 65 <= value <= 90
        or 97 <= value <= 122
        or value == 95
    )


def _view_contains_identifier_token(view: bytes, token: bytes) -> bool:
    start = 0
    while True:
        index = view.find(token, start)
        if index < 0:
            return False
        before = view[index - 1] if index else None
        after_index = index + len(token)
        after = view[after_index] if after_index < len(view) else None
        if (before is None or not _is_identifier_continuation_byte(before)) and (
            after is None or not _is_identifier_continuation_byte(after)
        ):
            return True
        start = index + 1


def _validate_identifier_probe_tables() -> None:
    seen: set[bytes] = set()
    for category, token in SENSITIVE_INTERNAL_IDENTIFIER_PROBES:
        if not token or not token.isascii() or token in seen:
            raise ObfuscationError(
                f"sensitive {category} identifier probe is empty, non-ASCII, or duplicated"
            )
        seen.add(token)
        for allowed in REQUIRED_PUBLIC_PLATFORM_SYMBOLS:
            if token in allowed:
                raise ObfuscationError(
                    f"sensitive {category} identifier is a substring of a required "
                    "public platform symbol"
                )
    for allowed in REQUIRED_PUBLIC_PLATFORM_SYMBOLS:
        if not allowed or not allowed.isascii():
            raise ObfuscationError("required public platform symbol is empty or non-ASCII")


_validate_identifier_probe_tables()


def reject_sensitive_internal_identifiers(platform: str, label: str, data: bytes) -> None:
    normalized = label.replace("\\", "/")
    if platform in STORE_METADATA_PLATFORMS and (
        is_store_only_native_debug_metadata(normalized)
        or is_store_only_obfuscation_metadata(normalized)
    ):
        return
    for view in _blob_views(data):
        for category, token in SENSITIVE_INTERNAL_IDENTIFIER_PROBES:
            if _view_contains_identifier_token(view, token):
                raise ObfuscationError(
                    f"{label} exposes sensitive internal {category} identifier "
                    f"{token.decode('ascii')}. Release obfuscation must rename internal "
                    "class, method, channel, protocol-secret, and configuration "
                    "identifiers; required public platform symbols remain allowed."
                )


def label_requires_native_parse(label: str) -> bool:
    normalized = label.replace("\\", "/").lower()
    return normalized.endswith((".so", ".dylib", ".dll", ".exe", ".sys", ".node")) or any(
        marker in normalized
        for marker in (".framework/", ".app/contents/macos/", ".appex/contents/macos/")
    )


# The privacy scan (validate_release_artifact_privacy.APPROVED_VENDOR_DEBUG_METADATA_SHA256)
# owns the reviewed table: exact basename plus exact bytes. It is repeated here
# rather than imported because this module is also loaded by descriptor with an
# empty package and a closed module set (the Apple gate), where the privacy scan
# is not importable and an import would fail before any binary is parsed. A
# test keeps the two tables equal.
APPROVED_VENDOR_DEBUG_METADATA_SHA256 = {
    "wintun.dll": frozenset(
        {
            "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",  # x64
            "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",  # arm64
        }
    ),
    "awg": frozenset(
        {
            "23d29323258166183eeeb288c1f9f08b879f3707e54591b1bfb2402413f6d8d8",  # linux x64 (upstream)
            "bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d",  # linux arm64 (from source)
        }
    ),
}


def _is_approved_vendor_debug_metadata(label: str, data: bytes) -> bool:
    basename = pathlib.PurePosixPath(label.replace("\\", "/")).name.lower()
    approved = APPROVED_VENDOR_DEBUG_METADATA_SHA256.get(basename)
    return approved is not None and hashlib.sha256(data).hexdigest() in approved


def reject_unstripped_native_blob(label: str, data: bytes) -> None:
    if is_store_only_native_debug_metadata(label):
        return
    if _is_approved_vendor_debug_metadata(label, data):
        return
    try:
        inspected = inspect_native_debug_sections(data)
    except ObfuscationError as error:
        # Java class files and Mach-O universal binaries share the CAFEBABE
        # prefix. Archives can legitimately contain class files, so malformed
        # Mach-O structure is only a release error when the member's path says
        # it is a native executable/library. Native-looking payloads remain
        # fail-closed and include the exact member in the diagnostic.
        if label_requires_native_parse(label):
            raise ObfuscationError(f"{label}: {error}") from error
        return
    if inspected is None:
        return
    _kind, sections = inspected
    if sections:
        raise ObfuscationError(
            f"Customer payload still contains unstripped native debug or symbol-table sections: {label}"
        )


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pubspec_version() -> tuple[str, str]:
    match = re.search(
        r"(?m)^version:\s*([^+\s]+)\+(\d+)\s*$",
        (ROOT / "pubspec.yaml").read_text(encoding="utf-8"),
    )
    if not match:
        raise ObfuscationError("pubspec.yaml must contain version: <semver>+<integer>.")
    return match.group(1), match.group(2)


def _resolved_layout_path(path: pathlib.Path) -> pathlib.Path:
    return path.expanduser().resolve()


def wear_release_stamp() -> tuple[str, str]:
    text = (ROOT / "wear_os" / "app" / "build.gradle.kts").read_text(encoding="utf-8")
    name = re.search(r'(?m)^\s*versionName\s*=\s*"([^"]+)"\s*$', text)
    code = re.search(r"(?m)^\s*versionCode\s*=\s*(\d+)\s*$", text)
    if name is None or code is None:
        raise ObfuscationError(
            "Wear OS release versionName/versionCode are absent from "
            "wear_os/app/build.gradle.kts"
        )
    return name.group(1), code.group(1)


def _requires_exact_target(platform: str) -> bool:
    return platform in {"linux", "wear-os"} or platform in EXTENSION_PLATFORMS


def exact_obfuscation_layout(target_id: str) -> dict[str, object]:
    version, build = pubspec_version()
    stamp = f"{version}+{build}"
    linux_arch = LINUX_PACKAGE_CROSS_STORE_TARGETS.get(target_id)
    if linux_arch is not None:
        symbols_dir = PRIVATE_SYMBOL_ROOT / "linux" / linux_arch / stamp
        return {
            "platform": "linux",
            "architecture": linux_arch,
            "surface": None,
            "evidence": "flutter",
            "symbols_dir": symbols_dir,
            "manifest": symbols_dir / "manifest.json",
            "artifact_name": EXACT_PACKAGE_TARGET_ARTIFACT_NAMES[target_id],
            "artifact_names": (EXACT_PACKAGE_TARGET_ARTIFACT_NAMES[target_id],),
        }
    windows_layout = WINDOWS_CROSS_STORE_TARGET_LAYOUT.get(target_id)
    if windows_layout is not None:
        architecture, surface = windows_layout
        symbols_dir = PRIVATE_SYMBOL_ROOT / "windows" / architecture / stamp
        return {
            "platform": "windows",
            "architecture": architecture,
            "surface": surface,
            "evidence": "flutter",
            "symbols_dir": symbols_dir,
            "manifest": symbols_dir / f"manifest-{surface}.json",
            "artifact_name": EXACT_PACKAGE_TARGET_ARTIFACT_NAMES[target_id],
            "artifact_names": (
                EXACT_PACKAGE_TARGET_ARTIFACT_NAMES[target_id],
                WINDOWS_UNSIGNED_LOCAL_ARTIFACT_NAMES[target_id],
            ),
        }
    wear_platform = WEAR_CROSS_STORE_TARGETS.get(target_id)
    if wear_platform is not None:
        wear_name, wear_code = wear_release_stamp()
        symbols_dir = PRIVATE_SYMBOL_ROOT / "wear-os" / f"{wear_name}+{wear_code}"
        return {
            "platform": wear_platform,
            "architecture": None,
            "surface": None,
            "evidence": "r8",
            "symbols_dir": symbols_dir,
            "manifest": symbols_dir / "manifest.json",
            "artifact_name": "app-release.aab",
            "artifact_names": ("app-release.aab",),
        }
    browser = EXTENSION_CROSS_STORE_TARGETS.get(target_id)
    if browser is not None:
        symbols_dir = PRIVATE_SYMBOL_ROOT / "extension" / browser / stamp
        names = EXTENSION_TARGET_ARTIFACT_NAMES[target_id]
        return {
            "platform": browser,
            "architecture": None,
            "surface": None,
            "evidence": "extension",
            "symbols_dir": symbols_dir,
            "manifest": symbols_dir / "manifest.json",
            "artifact_name": names[0],
            "artifact_names": names,
        }
    macos_layout = MACOS_CROSS_STORE_TARGET_LAYOUT.get(target_id)
    if macos_layout is not None:
        surface = str(macos_layout["surface"])
        symbols_dir = PRIVATE_SYMBOL_ROOT / "apple" / "macos" / stamp
        return {
            "platform": "macos",
            "architecture": None,
            "surface": surface,
            "channel": macos_layout["channel"],
            "signing_contract": macos_layout["signing_contract"],
            "expected_authority": macos_layout["expected_authority"],
            "required": macos_layout["required"],
            "evidence": "flutter",
            "symbols_dir": symbols_dir,
            "manifest": symbols_dir / f"manifest-{surface}.json",
            "artifact_name": macos_layout["artifact_name"],
            "artifact_names": (str(macos_layout["artifact_name"]),),
            "artifact_suffixes": macos_layout["artifact_suffixes"],
        }
    raise ObfuscationError(f"unsupported exact obfuscation target: {target_id}")


def _validate_exact_target_id(target_id: str, platform: str) -> dict[str, object]:
    layout = exact_obfuscation_layout(target_id)
    if layout["platform"] != platform:
        raise ObfuscationError(
            f"Obfuscation exact target {target_id} does not belong to platform {platform}."
        )
    return layout


def _artifact_matches_exact_layout(
    artifact_name: str, layout: dict[str, object]
) -> bool:
    allowed_names = layout.get("artifact_names")
    if not isinstance(allowed_names, tuple):
        allowed_names = (str(layout["artifact_name"]),)
    if artifact_name in allowed_names:
        return True
    suffixes = layout.get("artifact_suffixes")
    if not isinstance(suffixes, tuple) or not suffixes:
        return False
    lowered = artifact_name.lower()
    matched = [suffix for suffix in suffixes if lowered.endswith(str(suffix))]
    return len(matched) == 1


def _bind_exact_target_paths(
    target_id: str,
    platform: str,
    symbols_dir: pathlib.Path,
    manifest: pathlib.Path,
    artifacts: list[pathlib.Path],
) -> dict[str, object]:
    layout = _validate_exact_target_id(target_id, platform)
    if _resolved_layout_path(symbols_dir) != _resolved_layout_path(
        pathlib.Path(str(layout["symbols_dir"]))
    ):
        raise ObfuscationError(
            f"Exact target {target_id} must use its immutable symbol directory."
        )
    if _resolved_layout_path(manifest) != _resolved_layout_path(
        pathlib.Path(str(layout["manifest"]))
    ):
        raise ObfuscationError(
            f"Exact target {target_id} must use its immutable obfuscation manifest."
        )
    if len(artifacts) != 1:
        raise ObfuscationError(
            f"Exact target {target_id} requires exactly one release artifact."
        )
    artifact_name = pathlib.Path(artifacts[0]).name
    if not _artifact_matches_exact_layout(artifact_name, layout):
        raise ObfuscationError(
            f"Exact target {target_id} does not match artifact {artifact_name}."
        )
    return layout


def _manifest_bound_target(payload: object) -> str | None:
    if not isinstance(payload, dict):
        raise ObfuscationError("Obfuscation evidence manifest schema is invalid.")
    if payload.get("schema_version") != 2:
        raise ObfuscationError("Obfuscation evidence manifest schema is invalid.")
    keys = set(payload)
    if keys == _MANIFEST_KEYS:
        return None
    if keys != _TARGET_BOUND_MANIFEST_KEYS:
        raise ObfuscationError("Obfuscation evidence manifest schema is invalid.")
    target_id = payload.get("target_id")
    if not isinstance(target_id, str) or target_id not in EXACT_BOUND_TARGET_IDS:
        raise ObfuscationError("Obfuscation evidence target identity is invalid.")
    return target_id


def contained(path: pathlib.Path, root: pathlib.Path) -> pathlib.Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ObfuscationError(
            f"Authenticated private-symbol receipt is absent or escaped {root}: {path}"
        ) from exc
    return resolved


def inspect_symbols(symbols_dir: pathlib.Path, required_root: pathlib.Path) -> list[dict[str, object]]:
    directory = contained(symbols_dir, required_root)
    if not directory.is_dir():
        raise ObfuscationError(
            f"Authenticated Flutter symbol receipt directory is absent: {directory}"
        )
    files = sorted(directory.rglob("*.symbols"))
    if not files:
        raise ObfuscationError(f"No Flutter .symbols files were produced under {directory}")
    result: list[dict[str, object]] = []
    for path in files:
        if path.is_symlink() or not path.is_file() or path.stat().st_size < 64:
            raise ObfuscationError(f"Unsafe or empty Flutter symbol file: {path}")
        result.append(
            {
                "path": path.relative_to(directory).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return result


def inspect_r8_mapping(
    symbols_dir: pathlib.Path, required_root: pathlib.Path
) -> list[dict[str, object]]:
    directory = contained(symbols_dir, required_root)
    records: list[dict[str, object]] = []
    for name in R8_MAPPING_FILENAMES:
        mapping = directory / name
        if not mapping.exists() and not mapping.is_symlink():
            continue
        if mapping.is_symlink() or not mapping.is_file():
            raise ObfuscationError(
                f"Authenticated R8 mapping receipt is absent: {mapping}"
            )
        size = mapping.stat().st_size
        if size < MIN_R8_MAPPING_BYTES:
            raise ObfuscationError("Authenticated R8 mapping receipt is empty or truncated")
        payload = mapping.read_bytes()
        header = payload.lstrip(b"\xef\xbb\xbf").split(b"\n", 1)[0]
        if b"compiler: R8" not in header:
            raise ObfuscationError("Authenticated R8 mapping receipt is not an R8 map")
        records.append(
            {
                "path": name,
                "size": size,
                "sha256": sha256_file(mapping),
            }
        )
    if not records:
        raise ObfuscationError(
            f"Authenticated R8 mapping receipt is absent: {directory / R8_MAPPING_FILENAMES[0]}"
        )
    return records


def inspect_private_evidence(
    platform: str, symbols_dir: pathlib.Path, required_root: pathlib.Path
) -> list[dict[str, object]]:
    if platform in EXTENSION_PLATFORMS:
        directory = contained(symbols_dir, required_root)
        if not directory.is_dir():
            raise ObfuscationError(
                f"Authenticated extension receipt directory is absent: {directory}"
            )
        return []
    if platform == "wear-os":
        return inspect_r8_mapping(symbols_dir, required_root)
    records = inspect_symbols(symbols_dir, required_root)
    if platform in {"android-apk", "android-aab"}:
        records.extend(inspect_r8_mapping(symbols_dir, required_root))
    return records


def _regular_file_identity(info: os.stat_result) -> tuple[int, ...]:
    # On Windows st_ctime_ns is the creation time in a path stat but the change
    # time in a handle stat, so the two never agree. A path stat also infers the
    # execute bits from the extension (a .exe reads 0o100777) while a handle stat
    # does not (0o100666), so those bits are left out there; the other fields agree.
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode & ~0o111 if os.name == "nt" else info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        0 if os.name == "nt" else info.st_ctime_ns,
    )


def _nofollow_flags(*, write: bool = False) -> int:
    if os.name == "nt":
        # No O_NOFOLLOW or O_CLOEXEC on Windows: every caller compares the
        # path's lstat identity with the opened descriptor's, which refuses a
        # reparse point swapped in between, and O_NOINHERIT keeps the
        # descriptor out of child processes.
        flags = os.O_BINARY | getattr(os, "O_NOINHERIT", 0)
        if write:
            return flags | os.O_WRONLY | os.O_CREAT | os.O_EXCL
        return flags | os.O_RDONLY
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC"):
        raise ObfuscationError(
            "descriptor-bound O_NOFOLLOW file open is unavailable"
        )
    flags = os.O_CLOEXEC | os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if write:
        return flags | os.O_WRONLY | os.O_CREAT | os.O_EXCL
    return flags | os.O_RDONLY


def _reject_unbound_regular_file(info: os.stat_result, path: pathlib.Path) -> None:
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
        or info.st_size > MAX_ARCHIVE_INPUT_BYTES
    ):
        raise ObfuscationError(
            "Obfuscated build artifact is unsafe or empty, has a hardlink "
            f"alias, or is not a regular non-symlink file: {path}"
        )


def _sha256_fd(descriptor: int, expected_size: int) -> str:
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            raise ObfuscationError(
                "Exact artifact changed while its bytes were being bound."
            )
        digest.update(chunk)
        remaining -= len(chunk)
    extra = os.read(descriptor, 1)
    if extra:
        raise ObfuscationError(
            "Exact artifact changed while its bytes were being bound."
        )
    return digest.hexdigest()


def _copy_fd_exclusive(
    source_fd: int, destination: pathlib.Path, expected_size: int
) -> str:
    digest = hashlib.sha256()
    destination_fd = os.open(destination, _nofollow_flags(write=True), 0o600)
    remaining = expected_size
    try:
        while remaining:
            chunk = os.read(source_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise ObfuscationError(
                    "Exact artifact changed while its hardening snapshot was copied."
                )
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise ObfuscationError(
                        "Private hardening snapshot wrote no authenticated bytes."
                    )
                view = view[written:]
            digest.update(chunk)
            remaining -= len(chunk)
        extra = os.read(source_fd, 1)
        if extra:
            raise ObfuscationError(
                "Exact artifact changed while its hardening snapshot was copied."
            )
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
    return digest.hexdigest()


def _artifact_record_entry(
    resolved: pathlib.Path, size: int, digest: str
) -> dict[str, object]:
    return {
        "path": resolved.relative_to(ROOT).as_posix()
        if resolved.is_relative_to(ROOT)
        else str(resolved),
        "size": size,
        "sha256": digest,
    }


def _resolve_regular_artifact(path: pathlib.Path) -> pathlib.Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ObfuscationError(
            f"Obfuscated build artifact must not be a symlink: {path}"
        )
    try:
        resolved = expanded.resolve(strict=True)
    except OSError as exc:
        raise ObfuscationError(
            f"Authenticated release artifact is absent: {path}"
        ) from exc
    if resolved.is_symlink():
        raise ObfuscationError(
            f"Obfuscated build artifact must not be a symlink: {path}"
        )
    return resolved


def _bind_regular_source_file(
    path: pathlib.Path,
) -> tuple[pathlib.Path, tuple[int, ...], str]:
    resolved = _resolve_regular_artifact(path)
    descriptor = -1
    try:
        path_before = resolved.lstat()
        descriptor = os.open(resolved, _nofollow_flags())
        opened = os.fstat(descriptor)
        _reject_unbound_regular_file(path_before, resolved)
        _reject_unbound_regular_file(opened, resolved)
        if _regular_file_identity(path_before) != _regular_file_identity(opened):
            raise ObfuscationError(
                "Exact artifact path replacement is not allowed: "
                f"{resolved}"
            )
        digest = _sha256_fd(descriptor, opened.st_size)
        opened_after = os.fstat(descriptor)
    except OSError as exc:
        raise ObfuscationError(
            "Obfuscated build artifact must not be a symlink, was replaced, "
            f"or is absent: {path}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        path_after = resolved.lstat()
    except OSError as exc:
        raise ObfuscationError(
            f"Exact artifact was replaced, swapped, or restored: {resolved}"
        ) from exc
    identity = _regular_file_identity(path_before)
    if (
        identity != _regular_file_identity(opened_after)
        or identity != _regular_file_identity(path_after)
    ):
        raise ObfuscationError(
            "Exact artifact changed while its obfuscation evidence was bound: "
            f"{resolved}"
        )
    return resolved, identity, digest


class _StandaloneHardeningCopy:
    __slots__ = (
        "source",
        "snapshot",
        "root",
        "source_identity",
        "snapshot_identity",
        "digest",
        "record",
        "created_file",
        "created_dir",
    )

    def __init__(self, source: pathlib.Path) -> None:
        self.source = source
        self.snapshot = source
        self.root = source
        self.source_identity: tuple[int, ...] = ()
        self.snapshot_identity: tuple[int, ...] = ()
        self.digest = ""
        self.record: dict[str, object] = {}
        self.created_file = False
        self.created_dir = False


def _create_standalone_hardening_copy(path: pathlib.Path) -> _StandaloneHardeningCopy:
    bound = _StandaloneHardeningCopy(path)
    try:
        resolved = _resolve_regular_artifact(path)
        name = resolved.name
        if not name or name in {".", ".."} or "/" in name or "\\" in name:
            raise ObfuscationError(
                f"Obfuscated build artifact name is unsafe: {resolved}"
            )
        source_fd = -1
        try:
            path_before = resolved.lstat()
            source_fd = os.open(resolved, _nofollow_flags())
            opened = os.fstat(source_fd)
            _reject_unbound_regular_file(path_before, resolved)
            _reject_unbound_regular_file(opened, resolved)
            if _regular_file_identity(path_before) != _regular_file_identity(opened):
                raise ObfuscationError(
                    f"Exact artifact path replacement is not allowed: {resolved}"
                )
            root = pathlib.Path(
                tempfile.mkdtemp(
                    prefix=STANDALONE_HARDENING_SNAPSHOT_PREFIX, suffix=""
                )
            )
            bound.root = root
            bound.created_dir = True
            os.chmod(root, 0o700)
            snapshot = root / name
            bound.snapshot = snapshot
            bound.created_file = True
            digest = _copy_fd_exclusive(source_fd, snapshot, opened.st_size)
            opened_after = os.fstat(source_fd)
            path_after = resolved.lstat()
        except OSError as exc:
            raise ObfuscationError(
                "Obfuscated build artifact must not be a symlink, was replaced, "
                f"or is absent: {path}"
            ) from exc
        finally:
            if source_fd >= 0:
                os.close(source_fd)
        source_identity = _regular_file_identity(path_before)
        if (
            source_identity != _regular_file_identity(opened_after)
            or source_identity != _regular_file_identity(path_after)
        ):
            raise ObfuscationError(
                "Exact artifact changed while its hardening snapshot was copied: "
                f"{resolved}"
            )
        _snap_resolved, snapshot_identity, snapshot_digest = (
            _bind_regular_source_file(snapshot)
        )
        if (
            snapshot_digest != digest
            or snapshot_identity[5] != opened.st_size
            or (snapshot_identity[0], snapshot_identity[1])
            == (source_identity[0], source_identity[1])
        ):
            raise ObfuscationError(
                "Private hardening snapshot is not a distinct nlink=1 copy of "
                f"the source artifact: {resolved}"
            )
        rebound_source, rebound_identity, rebound_digest = (
            _bind_regular_source_file(resolved)
        )
        if rebound_identity != source_identity or rebound_digest != digest:
            raise ObfuscationError(
                "Exact artifact was replaced, swapped, or restored while its "
                f"hardening snapshot was created: {resolved}"
            )
        bound.source = rebound_source
        bound.snapshot = _snap_resolved
        bound.root = _snap_resolved.parent
        bound.source_identity = source_identity
        bound.snapshot_identity = snapshot_identity
        bound.digest = digest
        bound.record = _artifact_record_entry(
            rebound_source, opened.st_size, digest
        )
        return bound
    except Exception:
        _cleanup_standalone_hardening_copy(bound)
        raise


def _rebind_standalone_hardening_copy(bound: _StandaloneHardeningCopy) -> None:
    _source, source_identity, source_digest = _bind_regular_source_file(bound.source)
    _snapshot, snapshot_identity, snapshot_digest = _bind_regular_source_file(
        bound.snapshot
    )
    if (
        source_identity != bound.source_identity
        or snapshot_identity != bound.snapshot_identity
        or source_digest != bound.digest
        or snapshot_digest != bound.digest
    ):
        raise ObfuscationError(
            "Exact artifact was replaced, swapped, restored, aliased, or "
            "changed while its obfuscation evidence was verified."
        )


def _cleanup_standalone_hardening_copy(
    bound: _StandaloneHardeningCopy,
) -> BaseException | None:
    error: BaseException | None = None
    if bound.created_file:
        try:
            os.unlink(bound.snapshot)
        except OSError as exc:
            error = exc
        else:
            bound.created_file = False
    if bound.created_dir:
        try:
            os.rmdir(bound.root)
        except OSError as exc:
            if error is None:
                error = exc
        else:
            bound.created_dir = False
    return error


class _StandaloneArtifactInspection:
    __slots__ = ("snapshot_paths", "records")

    def __init__(
        self,
        snapshot_paths: list[pathlib.Path],
        records: list[dict[str, object]],
    ) -> None:
        self.snapshot_paths = snapshot_paths
        self.records = records


@contextlib.contextmanager
def _standalone_record_verify_artifacts(
    artifacts: list[pathlib.Path],
) -> Iterator[_StandaloneArtifactInspection]:
    """Inspect private nlink=1 copies, not live record/verify paths."""

    if not artifacts:
        raise ObfuscationError("At least one exact release artifact is required.")
    copies: list[_StandaloneHardeningCopy] = []
    passed = False
    try:
        for path in artifacts:
            copies.append(_create_standalone_hardening_copy(path))
        yield _StandaloneArtifactInspection(
            [item.snapshot for item in copies],
            [item.record for item in copies],
        )
        for item in copies:
            _rebind_standalone_hardening_copy(item)
        passed = True
    finally:
        cleanup_error: BaseException | None = None
        for item in copies:
            item_error = _cleanup_standalone_hardening_copy(item)
            if cleanup_error is None:
                cleanup_error = item_error
        if passed and cleanup_error is not None:
            raise ObfuscationError(
                "Private hardening snapshot cleanup failed."
            ) from cleanup_error


def inspect_artifacts(paths: list[pathlib.Path]) -> list[dict[str, object]]:
    if not paths:
        raise ObfuscationError("At least one exact release artifact is required.")
    result: list[dict[str, object]] = []
    for path in paths:
        resolved, identity, digest = _bind_regular_source_file(path)
        result.append(_artifact_record_entry(resolved, identity[5], digest))
    return result


class _ArchiveBudget:
    def __init__(self) -> None:
        self.member_count = 0
        self.expanded_bytes = 0

    def reserve_member(self, label: str, expanded_size: int) -> None:
        if expanded_size < 0:
            raise ObfuscationError(f"Archive member reports a negative size: {label}")
        self.member_count += 1
        if self.member_count > MAX_ARCHIVE_MEMBER_COUNT:
            raise ObfuscationError(
                "Release artifact exceeds the archive member-count limit "
                f"({MAX_ARCHIVE_MEMBER_COUNT}): {label}"
            )
        if expanded_size > MAX_ARCHIVE_MEMBER_EXPANDED_BYTES:
            raise ObfuscationError(
                "Release artifact member exceeds the expanded-size limit "
                f"({MAX_ARCHIVE_MEMBER_EXPANDED_BYTES} bytes): {label}"
            )
        if self.expanded_bytes + expanded_size > MAX_ARCHIVE_TOTAL_EXPANDED_BYTES:
            raise ObfuscationError(
                "Release artifact exceeds the cumulative expanded-size limit "
                f"({MAX_ARCHIVE_TOTAL_EXPANDED_BYTES} bytes): {label}"
            )
        self.expanded_bytes += expanded_size

    def reserve_metadata(self, label: str, size: int) -> None:
        if size < 0 or size > MAX_ARCHIVE_METADATA_FIELD_BYTES:
            raise ObfuscationError(
                "Release archive metadata field exceeds the size limit "
                f"({MAX_ARCHIVE_METADATA_FIELD_BYTES} bytes): {label}"
            )
        if self.expanded_bytes + size > MAX_ARCHIVE_TOTAL_EXPANDED_BYTES:
            raise ObfuscationError(
                "Release artifact exceeds the cumulative expanded-size limit "
                f"({MAX_ARCHIVE_TOTAL_EXPANDED_BYTES} bytes): {label}"
            )
        self.expanded_bytes += size


def _check_archive_input_size(label: str, size: int) -> None:
    if size < 0 or size > MAX_ARCHIVE_INPUT_BYTES:
        raise ObfuscationError(
            "Release archive exceeds the input-size limit "
            f"({MAX_ARCHIVE_INPUT_BYTES} bytes): {label}"
        )


def _check_container_expansion(
    label: str, container_size: int, expanded_size: int
) -> None:
    if expanded_size and container_size <= 0:
        raise ObfuscationError(f"Non-empty archive has no compressed payload: {label}")
    if expanded_size > container_size * MAX_ARCHIVE_COMPRESSION_RATIO:
        raise ObfuscationError(
            "Release archive exceeds the aggregate compression-ratio limit "
            f"({MAX_ARCHIVE_COMPRESSION_RATIO}:1): {label}"
        )


def _read_member_exact(handle, label: str, expected_size: int) -> bytes:
    data = handle.read(expected_size + 1)
    if len(data) != expected_size:
        raise ObfuscationError(
            f"Archive member size does not match its metadata: {label} "
            f"(declared {expected_size}, read {len(data)})"
        )
    return data


def _zip_member_data(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    label: str,
) -> bytes:
    if info.flag_bits & 0x1:
        raise ObfuscationError(f"Encrypted release archive member is not inspectable: {label}")
    if info.file_size and info.compress_size <= 0:
        raise ObfuscationError(f"Compressed release member has no compressed data: {label}")
    if info.file_size > info.compress_size * MAX_ARCHIVE_COMPRESSION_RATIO:
        raise ObfuscationError(
            "Release archive member exceeds the compression-ratio limit "
            f"({MAX_ARCHIVE_COMPRESSION_RATIO}:1): {label}"
        )
    with archive.open(info, "r") as handle:
        return _read_member_exact(handle, label, info.file_size)


def _label_has_suffix(label: str, suffixes: tuple[str, ...]) -> bool:
    folded = label.replace("\\", "/").casefold()
    return any(folded.endswith(suffix) for suffix in suffixes)


def _looks_like_tar_payload(data: bytes) -> bool:
    if len(data) >= 512:
        header = bytearray(data[:512])
        try:
            stored_checksum = int(header[148:156].rstrip(b"\0 ") or b"0", 8)
        except ValueError:
            stored_checksum = -1
        header[148:156] = b"        "
        if stored_checksum == sum(header):
            return True
    return data.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\0", b"(\xb5/\xfd"))


def _metadata_text_bytes(value: str) -> bytes:
    return value.encode("utf-8", errors="surrogatepass")


def _iter_metadata_blob(
    label: str,
    data: bytes,
    budget: _ArchiveBudget,
    nested_depth: int | None = None,
) -> Iterator[tuple[str, bytes]]:
    if not data:
        return
    budget.reserve_metadata(label, len(data))
    yield label, data
    if nested_depth is not None:
        yield from _iter_nested_archive(data, label, nested_depth, budget)


def _iter_pax_headers(
    headers: dict[str, str],
    label: str,
    budget: _ArchiveBudget,
    nested_depth: int,
) -> Iterator[tuple[str, bytes]]:
    for index, (key, value) in enumerate(sorted(headers.items())):
        payload = _metadata_text_bytes(f"{key}={value}")
        yield from _iter_metadata_blob(
            f"{label}!/<pax-header-{index}>", payload, budget, nested_depth
        )


def _iter_zip_local_metadata(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    label: str,
    index: int,
    budget: _ArchiveBudget,
    nested_depth: int,
) -> Iterator[tuple[str, bytes]]:
    handle = archive.fp
    if handle is None:
        raise ObfuscationError(f"Release zip archive closed during inspection: {label}")
    try:
        handle.seek(info.header_offset)
        header = handle.read(30)
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            raise ObfuscationError(f"Invalid local ZIP header: {label}")
        filename_size = struct.unpack_from("<H", header, 26)[0]
        extra_size = struct.unpack_from("<H", header, 28)[0]
        local_filename = handle.read(filename_size)
        local_extra = handle.read(extra_size)
    except (OSError, ValueError) as exc:
        raise ObfuscationError(f"Could not inspect local ZIP metadata: {label}") from exc
    if len(local_filename) != filename_size or len(local_extra) != extra_size:
        raise ObfuscationError(f"Truncated local ZIP metadata: {label}")
    yield from _iter_metadata_blob(
        f"{label}!/<zip-member-{index}-local-filename>",
        local_filename,
        budget,
        nested_depth,
    )
    yield from _iter_metadata_blob(
        f"{label}!/<zip-member-{index}-local-extra>",
        local_extra,
        budget,
        nested_depth,
    )


def _zip64_eocd_matches(
    tail: bytes,
    tail_offset: int,
    eocd_offset: int,
    archive: zipfile.ZipFile,
    info_count: int,
) -> bool:
    locator_offset = eocd_offset - 20
    locator_index = locator_offset - tail_offset
    if locator_index < 0 or locator_index + 20 > len(tail):
        return False
    if tail[locator_index : locator_index + 4] != b"PK\x06\x07":
        return False
    _, zip64_disk, zip64_offset, disk_count = struct.unpack_from(
        "<4sLQL", tail, locator_index
    )
    if zip64_disk != 0 or disk_count != 1:
        return False
    zip64_index = zip64_offset - tail_offset
    if zip64_index < 0 or zip64_index + 56 > len(tail):
        return False
    if tail[zip64_index : zip64_index + 4] != b"PK\x06\x06":
        return False
    record_size = struct.unpack_from("<Q", tail, zip64_index + 4)[0]
    record_end = zip64_offset + 12 + record_size
    if record_size < 44 or record_end != locator_offset:
        return False
    (
        disk_number,
        central_disk,
        entries_on_disk,
        total_entries,
        central_size,
        central_offset,
    ) = struct.unpack_from("<LLQQQQ", tail, zip64_index + 16)
    return (
        disk_number == 0
        and central_disk == 0
        and entries_on_disk == total_entries == info_count
        and central_offset == archive.start_dir
        and zip64_offset == archive.start_dir + central_size
    )


def _zip_local_record_end(
    handle,
    info: zipfile.ZipInfo,
    label: str,
) -> int:
    try:
        handle.seek(info.header_offset)
        header = handle.read(30)
    except (OSError, ValueError) as exc:
        raise ObfuscationError(f"Could not inspect local ZIP record: {label}") from exc
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise ObfuscationError(f"Invalid local ZIP header: {label}")
    flag_bits = struct.unpack_from("<H", header, 6)[0]
    local_compress_size = struct.unpack_from("<I", header, 18)[0]
    local_file_size = struct.unpack_from("<I", header, 22)[0]
    filename_size, extra_size = struct.unpack_from("<HH", header, 26)
    record_end = (
        info.header_offset + 30 + filename_size + extra_size + info.compress_size
    )
    if not (flag_bits & ZIP_DATA_DESCRIPTOR_FLAG):
        return record_end
    try:
        handle.seek(record_end)
        peek = handle.read(4)
    except (OSError, ValueError) as exc:
        raise ObfuscationError(
            f"Could not inspect ZIP data descriptor: {label}"
        ) from exc
    zip64 = (
        local_compress_size == 0xFFFFFFFF
        or local_file_size == 0xFFFFFFFF
        or info.compress_size > 0xFFFFFFFF
        or info.file_size > 0xFFFFFFFF
    )
    if peek == ZIP_DATA_DESCRIPTOR_SIGNATURE:
        return record_end + (24 if zip64 else 16)
    if len(peek) != 4:
        raise ObfuscationError(f"Truncated ZIP data descriptor: {label}")
    return record_end + (20 if zip64 else 12)


def _apk_signing_block_pairs_are_well_formed(pairs: bytes) -> bool:
    cursor = 0
    while cursor < len(pairs):
        if cursor + 8 > len(pairs):
            return False
        pair_size = struct.unpack_from("<Q", pairs, cursor)[0]
        if pair_size < 4 or cursor + 8 + pair_size > len(pairs):
            return False
        cursor += 8 + pair_size
    return cursor == len(pairs)


def _is_structurally_valid_apk_signing_block(gap: bytes) -> bool:
    if len(gap) < 32 or gap[-16:] != APK_SIG_BLOCK_MAGIC:
        return False
    size = struct.unpack_from("<Q", gap, len(gap) - 24)[0]
    if size < 24 or size + 8 != len(gap):
        return False
    if struct.unpack_from("<Q", gap, 0)[0] != size:
        return False
    return _apk_signing_block_pairs_are_well_formed(gap[8 : len(gap) - 24])


def _inspect_zip_interior_layout(
    archive: zipfile.ZipFile,
    label: str,
    container_size: int,
) -> bytes:
    handle = archive.fp
    if handle is None:
        raise ObfuscationError(f"Release zip archive closed during inspection: {label}")
    infos = sorted(
        archive.infolist(), key=lambda info: (info.header_offset, info.filename)
    )
    cursor = 0
    for info in infos:
        member_label = f"{label}!/{info.filename}"
        if info.header_offset < cursor:
            raise ObfuscationError(
                f"Release ZIP archive contains overlapping local records: {label}"
            )
        if info.header_offset > cursor:
            raise ObfuscationError(
                f"Release ZIP archive contains an unexplained interior gap: {label}"
            )
        cursor = _zip_local_record_end(handle, info, member_label)
    if cursor > archive.start_dir:
        raise ObfuscationError(
            f"Release ZIP local records overlap the central directory: {label}"
        )
    if cursor == archive.start_dir:
        return b""
    gap_len = archive.start_dir - cursor
    if gap_len > MAX_ARCHIVE_MEMBER_EXPANDED_BYTES:
        raise ObfuscationError(
            "Release artifact member exceeds the expanded-size limit "
            f"({MAX_ARCHIVE_MEMBER_EXPANDED_BYTES} bytes): {label}!/<apk-signing-block>"
        )
    if gap_len > container_size:
        raise ObfuscationError(f"Release ZIP interior gap exceeds the container: {label}")
    try:
        handle.seek(cursor)
        gap = handle.read(gap_len)
    except (OSError, ValueError) as exc:
        raise ObfuscationError(
            f"Could not inspect ZIP interior gap: {label}"
        ) from exc
    if len(gap) != gap_len:
        raise ObfuscationError(f"Truncated ZIP interior gap: {label}")
    if _is_structurally_valid_apk_signing_block(gap):
        return gap
    raise ObfuscationError(
        f"Release ZIP archive contains an unexplained interior gap: {label}"
    )


def _verify_zip_container_boundaries(
    archive: zipfile.ZipFile,
    label: str,
    container_size: int,
) -> None:
    handle = archive.fp
    if handle is None:
        raise ObfuscationError(f"Release zip archive closed during inspection: {label}")
    infos = archive.infolist()
    if infos:
        first_local_header = min(info.header_offset for info in infos)
        if first_local_header != 0:
            raise ObfuscationError(
                f"Release ZIP archive contains a noncanonical prefix: {label}"
            )
    try:
        handle.seek(0, 2)
        observed_size = handle.tell()
        if observed_size != container_size:
            raise ObfuscationError(
                f"Release ZIP archive changed during inspection: {label}"
            )
        search_size = min(container_size, 22 + 65_535 + 20 + 56)
        tail_offset = container_size - search_size
        handle.seek(tail_offset)
        tail = handle.read(search_size)
    except ObfuscationError:
        raise
    except (OSError, ValueError) as exc:
        raise ObfuscationError(
            f"Could not inspect ZIP container boundaries: {label}"
        ) from exc
    if len(tail) != search_size:
        raise ObfuscationError(f"Truncated ZIP container boundary data: {label}")

    candidate_index = tail.rfind(b"PK\x05\x06")
    while candidate_index >= 0:
        if candidate_index + 22 <= len(tail):
            (
                _,
                disk_number,
                central_disk,
                entries_on_disk,
                total_entries,
                central_size,
                central_offset,
                comment_size,
            ) = struct.unpack_from("<4s4H2LH", tail, candidate_index)
            eocd_offset = tail_offset + candidate_index
            eocd_end = eocd_offset + 22 + comment_size
            comment_end = candidate_index + 22 + comment_size
            comment_matches = (
                comment_end <= len(tail)
                and tail[candidate_index + 22 : comment_end] == archive.comment
            )
            ordinary_layout = (
                disk_number == 0
                and central_disk == 0
                and entries_on_disk == total_entries == len(infos)
                and central_offset == archive.start_dir
                and eocd_offset == archive.start_dir + central_size
            )
            prefixed_empty_layout = (
                not infos
                and disk_number == 0
                and central_disk == 0
                and entries_on_disk == total_entries == 0
                and central_offset < archive.start_dir
                and eocd_offset == archive.start_dir + central_size
            )
            zip64_layout = (
                disk_number in {0, 0xFFFF}
                and central_disk in {0, 0xFFFF}
                and entries_on_disk in {len(infos), 0xFFFF}
                and total_entries in {len(infos), 0xFFFF}
                and central_size == 0xFFFFFFFF
                and central_offset == 0xFFFFFFFF
                and _zip64_eocd_matches(
                    tail, tail_offset, eocd_offset, archive, len(infos)
                )
            )
            if comment_matches and prefixed_empty_layout:
                raise ObfuscationError(
                    f"Release ZIP archive contains a noncanonical prefix: {label}"
                )
            if comment_matches and (ordinary_layout or zip64_layout):
                if eocd_end != container_size:
                    raise ObfuscationError(
                        f"Release ZIP archive contains trailing bytes after EOCD: {label}"
                    )
                return
        candidate_index = tail.rfind(b"PK\x05\x06", 0, candidate_index)
    raise ObfuscationError(f"Release ZIP archive has a noncanonical EOCD layout: {label}")


def _iter_zip_members(
    archive: zipfile.ZipFile,
    label: str,
    container_size: int,
    depth: int,
    budget: _ArchiveBudget,
) -> Iterator[tuple[str, bytes]]:
    container_expanded = 0
    _verify_zip_container_boundaries(archive, label, container_size)
    signing_block = _inspect_zip_interior_layout(archive, label, container_size)
    yield from _iter_metadata_blob(
        f"{label}!/<zip-archive-comment>", archive.comment, budget, depth + 1
    )
    if signing_block:
        signing_label = f"{label}!/<apk-signing-block>"
        budget.reserve_member(signing_label, len(signing_block))
        yield signing_label, signing_block
        yield from _iter_nested_archive(
            signing_block, signing_label, depth + 1, budget
        )
        pairs = signing_block[8 : len(signing_block) - 24]
        cursor = 0
        pair_index = 0
        while cursor < len(pairs):
            pair_size = struct.unpack_from("<Q", pairs, cursor)[0]
            value = pairs[cursor + 12 : cursor + 8 + pair_size]
            pair_label = f"{label}!/<apk-signing-block-pair-{pair_index}>"
            budget.reserve_member(pair_label, len(value))
            if value:
                yield pair_label, value
                yield from _iter_nested_archive(
                    value, pair_label, depth + 1, budget
                )
            cursor += 8 + pair_size
            pair_index += 1
    for index, info in enumerate(archive.infolist()):
        member_label = f"{label}!/{info.filename}"
        budget.reserve_member(member_label, info.file_size)
        yield from _iter_zip_local_metadata(
            archive, info, label, index, budget, depth + 1
        )
        yield from _iter_metadata_blob(
            f"{label}!/<zip-member-{index}-filename>",
            _metadata_text_bytes(info.filename),
            budget,
            depth + 1,
        )
        yield from _iter_metadata_blob(
            f"{label}!/<zip-member-{index}-comment>",
            info.comment,
            budget,
            depth + 1,
        )
        yield from _iter_metadata_blob(
            f"{label}!/<zip-member-{index}-extra>",
            info.extra,
            budget,
            depth + 1,
        )
        if info.is_dir() and info.file_size == 0:
            continue
        container_expanded += info.file_size
        _check_container_expansion(label, container_size, container_expanded)
        data = _zip_member_data(archive, info, member_label)
        yield member_label, data
        yield from _iter_nested_archive(data, member_label, depth + 1, budget)


def _verify_tar_container_trailer(
    archive: tarfile.TarFile,
    label: str,
    container_size: int,
) -> None:
    handle = archive.fileobj
    if handle is None:
        raise ObfuscationError(f"Release TAR archive closed during inspection: {label}")
    trailer_size = 0
    try:
        handle.seek(archive.offset)
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            trailer_size += len(chunk)
            expanded_stream_size = archive.offset + trailer_size
            if expanded_stream_size > MAX_ARCHIVE_TOTAL_EXPANDED_BYTES:
                raise ObfuscationError(
                    "Release TAR archive exceeds the cumulative expanded-size limit "
                    f"({MAX_ARCHIVE_TOTAL_EXPANDED_BYTES} bytes): {label}"
                )
            _check_container_expansion(label, container_size, expanded_stream_size)
            if any(chunk):
                raise ObfuscationError(
                    f"Release TAR archive contains non-zero data after its end marker: {label}"
                )
    except ObfuscationError:
        raise
    except Exception as exc:
        raise ObfuscationError(
            f"Could not inspect TAR data after its end marker: {label}"
        ) from exc
    if trailer_size < 1024:
        raise ObfuscationError(
            f"Release TAR archive lacks two complete end-of-archive blocks: {label}"
        )


def _tarfile_wrapper_compression_kind(archive: tarfile.TarFile) -> str | None:
    wrapped = type(archive.fileobj).__name__
    if wrapped == "BZ2File":
        return "bz2"
    if wrapped == "LZMAFile":
        return "xz"
    if "Zstd" in wrapped:
        return "zstd"
    return None


def _compressed_tar_kind(
    archive: tarfile.TarFile, label: str, header: bytes
) -> str | None:
    wrapped = _tarfile_wrapper_compression_kind(archive)
    if wrapped is not None:
        return wrapped
    folded = label.replace("\\", "/").casefold()
    if folded.endswith(BZ2_TAR_SUFFIXES) or header.startswith(BZ2_MAGIC):
        return "bz2"
    if folded.endswith(XZ_TAR_SUFFIXES) or header.startswith(XZ_MAGIC):
        return "xz"
    if folded.endswith(ZSTD_TAR_SUFFIXES) or header.startswith(ZSTD_MAGIC):
        return "zstd"
    return None


def _make_tar_stream_decompressor(kind: str, label: str):
    if kind == "bz2":
        import bz2

        return bz2.BZ2Decompressor(), OSError
    if kind == "xz":
        import lzma

        return lzma.LZMADecompressor(), lzma.LZMAError
    if kind == "zstd":
        try:
            from compression.zstd import ZstdDecompressor
            from compression.zstd import ZstdError
        except ImportError as exc:
            raise ObfuscationError(
                f"zstd compressed TAR archive cannot be inspected: {label}"
            ) from exc
        return ZstdDecompressor(), ZstdError
    raise ObfuscationError(f"unsupported compressed TAR kind {kind}: {label}")


def _verify_compressed_tar_container_trailer(
    label: str,
    raw_handle,
    container_size: int,
    kind: str,
) -> None:
    decompressor, trailing_error = _make_tar_stream_decompressor(kind, label)
    expanded = 0
    try:
        while not decompressor.eof:
            if getattr(decompressor, "needs_input", True):
                block = raw_handle.read(COMPRESSED_TAR_CHUNK_BYTES)
                if not block:
                    break
            else:
                block = b""
            try:
                output = decompressor.decompress(block, COMPRESSED_TAR_CHUNK_BYTES)
            except trailing_error as exc:
                raise ObfuscationError(
                    f"Could not inspect compressed TAR stream: {label}"
                ) from exc
            expanded += len(output)
            if expanded > MAX_ARCHIVE_TOTAL_EXPANDED_BYTES:
                raise ObfuscationError(
                    "Release TAR archive exceeds the cumulative expanded-size limit "
                    f"({MAX_ARCHIVE_TOTAL_EXPANDED_BYTES} bytes): {label}"
                )
            _check_container_expansion(label, container_size, expanded)
        if not decompressor.eof:
            raise ObfuscationError(
                f"Release TAR archive compressed stream is truncated: {label}"
            )
        leftover = decompressor.unused_data or raw_handle.read(1)
        if leftover:
            raise ObfuscationError(
                "Release TAR archive contains trailing bytes after its "
                f"compressed stream: {label}"
            )
    except ObfuscationError:
        raise
    except Exception as exc:
        raise ObfuscationError(
            f"Could not inspect compressed TAR stream: {label}"
        ) from exc


def _verify_tar_compressed_container(
    archive: tarfile.TarFile,
    label: str,
    container_size: int,
    raw_container: bytes | pathlib.Path,
) -> None:
    if isinstance(raw_container, (bytes, bytearray)):
        header = bytes(raw_container[:8])
        kind = _compressed_tar_kind(archive, label, header)
        if kind is None:
            return
        _verify_compressed_tar_container_trailer(
            label, io.BytesIO(raw_container), container_size, kind
        )
        return
    path = pathlib.Path(raw_container)
    try:
        with path.open("rb") as raw_handle:
            header = raw_handle.read(8)
            kind = _compressed_tar_kind(archive, label, header)
            if kind is None:
                return
            raw_handle.seek(0)
            _verify_compressed_tar_container_trailer(
                label, raw_handle, container_size, kind
            )
    except ObfuscationError:
        raise
    except OSError as exc:
        raise ObfuscationError(
            f"Could not inspect compressed TAR container: {label}"
        ) from exc


def _iter_tar_members(
    archive: tarfile.TarFile,
    label: str,
    container_size: int,
    depth: int,
    budget: _ArchiveBudget,
    raw_container: bytes | pathlib.Path,
) -> Iterator[tuple[str, bytes]]:
    container_expanded = 0
    seen_global_pax: set[tuple[str, str]] = set()
    for index, member in enumerate(archive):
        current_global_pax = {
            key: value
            for key, value in archive.pax_headers.items()
            if (key, value) not in seen_global_pax
        }
        if current_global_pax:
            budget.reserve_member(
                f"{label}!/<global-pax-metadata-{index}>", 0
            )
            yield from _iter_pax_headers(
                current_global_pax, label, budget, depth + 1
            )
            seen_global_pax.update(current_global_pax.items())
        member_label = f"{label}!/{member.name}"
        budget.reserve_member(member_label, member.size)
        yield from _iter_metadata_blob(
            f"{label}!/<tar-member-{index}-name>",
            _metadata_text_bytes(member.name),
            budget,
            depth + 1,
        )
        yield from _iter_metadata_blob(
            f"{label}!/<tar-member-{index}-linkname>",
            _metadata_text_bytes(member.linkname),
            budget,
            depth + 1,
        )
        yield from _iter_metadata_blob(
            f"{label}!/<tar-member-{index}-uname>",
            _metadata_text_bytes(member.uname),
            budget,
            depth + 1,
        )
        yield from _iter_metadata_blob(
            f"{label}!/<tar-member-{index}-gname>",
            _metadata_text_bytes(member.gname),
            budget,
            depth + 1,
        )
        if member.pax_headers:
            budget.reserve_member(f"{member_label}!/<pax-metadata>", 0)
            yield from _iter_pax_headers(
                member.pax_headers, member_label, budget, depth + 1
            )
        if not member.isfile():
            continue
        container_expanded += member.size
        _check_container_expansion(label, container_size, container_expanded)
        handle = archive.extractfile(member)
        if handle is None:
            raise ObfuscationError(f"Could not inspect {member_label}")
        with handle:
            data = _read_member_exact(handle, member_label, member.size)
        yield member_label, data
        yield from _iter_nested_archive(data, member_label, depth + 1, budget)
    _verify_tar_compressed_container(archive, label, container_size, raw_container)
    _verify_tar_container_trailer(archive, label, container_size)


def _iter_nested_archive(
    data: bytes,
    label: str,
    depth: int,
    budget: _ArchiveBudget,
) -> Iterator[tuple[str, bytes]]:
    stream = io.BytesIO(data)
    is_zip = zipfile.is_zipfile(stream)
    zip_named = _label_has_suffix(label, ZIP_ARCHIVE_SUFFIXES)
    tar_named = _label_has_suffix(label, TAR_ARCHIVE_SUFFIXES)
    tar_candidate = tar_named or _looks_like_tar_payload(data)
    if not is_zip and not zip_named and not tar_candidate:
        return
    if depth > MAX_ARCHIVE_RECURSION_DEPTH:
        raise ObfuscationError(
            "Release artifact exceeds the nested archive recursion limit "
            f"({MAX_ARCHIVE_RECURSION_DEPTH}): {label}"
        )
    _check_archive_input_size(label, len(data))
    if is_zip:
        stream.seek(0)
        try:
            with zipfile.ZipFile(stream) as archive:
                yield from _iter_zip_members(
                    archive, label, len(data), depth, budget
                )
        except ObfuscationError:
            raise
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
            raise ObfuscationError(f"Invalid nested release zip archive: {label}") from exc
        return
    if zip_named:
        raise ObfuscationError(f"Invalid nested release zip archive: {label}")
    stream.seek(0)
    try:
        with tarfile.open(fileobj=stream, mode="r:*") as archive:
            yield from _iter_tar_members(
                archive, label, len(data), depth, budget, data
            )
    except ObfuscationError:
        raise
    except (tarfile.TarError, EOFError, OSError) as exc:
        if tar_named:
            raise ObfuscationError(f"Invalid nested release tar archive: {label}") from exc
        return


def iter_artifact_blobs(path: pathlib.Path) -> Iterator[tuple[str, bytes]]:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ObfuscationError(f"Release artifact must not be a symlink: {path}")
    try:
        resolved = expanded.resolve(strict=True)
    except OSError as exc:
        raise ObfuscationError(
            f"Authenticated release artifact is absent: {path}"
        ) from exc
    budget = _ArchiveBudget()
    if resolved.is_dir():
        for child in sorted(resolved.rglob("*")):
            if child.is_symlink():
                raise ObfuscationError(
                    f"Release artifact directory contains a symlink: {child}"
                )
            if not child.is_file():
                continue
            label = f"{resolved.name}/{child.relative_to(resolved).as_posix()}"
            child_size = child.stat().st_size
            _check_archive_input_size(label, child_size)
            budget.reserve_member(label, child_size)
            data = child.read_bytes()
            if len(data) != child_size:
                raise ObfuscationError(
                    f"Directory artifact member changed during inspection: {label}"
                )
            yield label, data
            yield from _iter_nested_archive(data, label, 0, budget)
        return
    if not resolved.is_file():
        raise ObfuscationError(f"Release artifact is not a file: {resolved}")
    _check_archive_input_size(resolved.name, resolved.stat().st_size)
    is_zip = zipfile.is_zipfile(resolved)
    zip_named = _label_has_suffix(resolved.name, ZIP_ARCHIVE_SUFFIXES)
    tar_named = _label_has_suffix(resolved.name, TAR_ARCHIVE_SUFFIXES)
    if zip_named and not is_zip:
        raise ObfuscationError(f"Invalid release zip archive: {resolved}")
    if is_zip:
        try:
            with zipfile.ZipFile(resolved) as archive:
                yield from _iter_zip_members(
                    archive, resolved.name, resolved.stat().st_size, 0, budget
                )
        except ObfuscationError:
            raise
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
            raise ObfuscationError(f"Invalid release zip archive: {resolved}") from exc
        return
    is_tar = tarfile.is_tarfile(resolved)
    if tar_named and not is_tar:
        raise ObfuscationError(f"Invalid release tar archive: {resolved}")
    if is_tar:
        try:
            with tarfile.open(resolved, "r:*") as archive:
                yield from _iter_tar_members(
                    archive,
                    resolved.name,
                    resolved.stat().st_size,
                    0,
                    budget,
                    resolved,
                )
        except ObfuscationError:
            raise
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise ObfuscationError(f"Invalid release tar archive: {resolved}") from exc
        return
    yield resolved.name, resolved.read_bytes()


def _member_basename(label: str) -> str:
    normalized = label.replace("\\", "/")
    if "!/" in normalized:
        normalized = normalized.split("!/", 1)[-1]
    return pathlib.PurePosixPath(normalized).name


def _is_extension_javascript_member(label: str) -> bool:
    name = _member_basename(label).casefold()
    return name.endswith(EXTENSION_JS_SUFFIXES)


def reject_unminified_or_obfuscated_extension_js(label: str, data: bytes) -> None:
    if not _is_extension_javascript_member(label):
        return
    minifier = _store_js_minifier()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as suc:
        raise ObfuscationError(
            f"Extension JavaScript is not UTF-8 text: {label}"
        ) from suc
    if _source_map_reference_present(text):
        raise ObfuscationError(
            f"Extension JavaScript contains a source-map reference: {label}"
        )
    if EXTENSION_OBFUSCATOR_RE.search(data):
        raise ObfuscationError(
            f"{label} uses forbidden JavaScript obfuscation. Chrome forbids "
            "obfuscation; store-permitted --minify transforms are size reductions "
            "only and are not secret protection."
        )
    try:
        minifier.reject_javascript_evasions(label, text)
    except minifier.MinifyError as suc:
        raise _extension_minify_error(suc) from suc
    expected = minifier.producer_packaged_javascript()
    key = _extension_javascript_producer_key(label)
    if key not in expected or text != expected[key]:
        raise ObfuscationError(
            f"{label} is not the reproducible esbuild producer output. "
            "Minification is required and does not protect client-held secrets."
        )


def _require_extension_zip_matches_producer(path: pathlib.Path) -> None:
    minifier = _store_js_minifier()
    try:
        with zipfile.ZipFile(path) as archive:
            failures = minifier.zip_hygiene_failures(archive)
            if failures:
                raise ObfuscationError(
                    "Extension package failed producer zip member closure: "
                    + "; ".join(failures)
                )
            minifier.require_zip_javascript_matches_producer(archive)
            minifier.require_static_source_members(archive)
    except minifier.MinifyError as suc:
        raise _extension_minify_error(suc) from suc
    except zipfile.BadZipFile as suc:
        raise ObfuscationError(
            f"Extension package is not a zip archive: {path}"
        ) from suc


def verify_extension_javascript_hardening(
    platform: str, paths: list[pathlib.Path]
) -> None:
    if platform not in EXTENSION_PLATFORMS:
        return
    js_members = 0
    for path in paths:
        path_js = 0
        for label, data in iter_artifact_blobs(path):
            if not _is_extension_javascript_member(label):
                continue
            path_js += 1
            js_members += 1
            reject_unminified_or_obfuscated_extension_js(label, data)
        if path_js == 0:
            raise ObfuscationError(
                "Extension package contains no JavaScript; minification cannot be proven."
            )
        _require_extension_zip_matches_producer(path)
    if js_members == 0:
        raise ObfuscationError(
            "Extension package contains no JavaScript; minification cannot be proven."
        )


def verify_embedded_watchos_companion(
    platform: str, paths: list[pathlib.Path]
) -> None:
    if platform != "ios":
        return
    checked = False
    for path in paths:
        expanded = path.expanduser()
        if expanded.is_symlink():
            raise ObfuscationError(f"iOS artifact must not be a symlink: {path}")
        try:
            resolved = expanded.resolve(strict=True)
        except OSError as exc:
            raise ObfuscationError(
                f"Authenticated iOS artifact is absent: {path}"
            ) from exc
        if not resolved.is_file() or resolved.suffix.lower() != ".ipa":
            continue
        checked = True
        found = False
        for label, data in iter_artifact_blobs(resolved):
            if WATCHOS_EXECUTABLE_RE.search(label.replace("\\", "/")) is None:
                continue
            inspected = inspect_native_debug_sections(data)
            if inspected is None or inspected[0] != "macho":
                raise ObfuscationError(
                    f"Embedded watchOS companion is not a parseable Mach-O: {label}"
                )
            if inspected[1]:
                raise ObfuscationError(
                    "Embedded watchOS companion still contains unstripped native "
                    f"debug or symbol-table sections: {label}"
                )
            found = True
        if not found:
            raise ObfuscationError(
                "iOS IPA is missing the embedded watchOS companion binary"
            )
    if not checked:
        raise ObfuscationError(
            "iOS watchOS companion evidence requires an exact .ipa artifact"
        )


def verify_android_delivery_payload_is_stripped(
    platform: str, paths: list[pathlib.Path]
) -> None:
    if platform not in {"android-apk", "android-aab"}:
        return
    expected_suffix = ".apk" if platform == "android-apk" else ".aab"
    so_pattern = ANDROID_APK_SO_RE if platform == "android-apk" else ANDROID_AAB_SO_RE
    libapp_pattern = (
        re.compile(r"lib/[^/]+/libapp\.so")
        if platform == "android-apk"
        else re.compile(r"(?:base|split_[^/]+)/lib/[^/]+/libapp\.so")
    )
    for path in paths:
        expanded = path.expanduser()
        if expanded.is_symlink():
            raise ObfuscationError(f"Android artifact must not be a symlink: {path}")
        try:
            resolved = expanded.resolve(strict=True)
        except OSError as exc:
            raise ObfuscationError(
                f"Authenticated Android artifact is absent: {path}"
            ) from exc
        if resolved.suffix.lower() != expected_suffix:
            raise ObfuscationError(
                f"{platform} evidence requires an exact {expected_suffix} artifact: {resolved}"
            )
        _check_archive_input_size(resolved.name, resolved.stat().st_size)
        try:
            with zipfile.ZipFile(resolved) as archive:
                infos = archive.infolist()
                names = [info.filename for info in infos]
                delivery_libraries = [
                    info for info in infos if so_pattern.fullmatch(info.filename)
                ]
                app_libraries = [
                    info
                    for info in delivery_libraries
                    if libapp_pattern.fullmatch(info.filename)
                ]
                if not app_libraries:
                    raise ObfuscationError(
                        f"Android artifact contains no Flutter delivery libapp.so: {resolved}"
                    )
                if not delivery_libraries:
                    raise ObfuscationError(
                        f"Android artifact contains no delivery native libraries: {resolved}"
                    )
                budget = _ArchiveBudget()
                container_expanded = 0
                delivery_ids = {id(info) for info in delivery_libraries}
                for info in infos:
                    member_label = f"{resolved.name}!/{info.filename}"
                    budget.reserve_member(member_label, info.file_size)
                    if id(info) not in delivery_ids:
                        continue
                    container_expanded += info.file_size
                    _check_container_expansion(
                        resolved.name, resolved.stat().st_size, container_expanded
                    )
                    payload = _zip_member_data(archive, info, member_label)
                    inspected = inspect_native_debug_sections(payload)
                    if inspected is None or inspected[0] != "elf":
                        raise ObfuscationError(
                            "Android delivery library is not a parseable ELF: "
                            f"{info.filename}"
                        )
                    if inspected[1]:
                        raise ObfuscationError(
                            "Android customer payload still contains native debug sections: "
                            f"{info.filename}"
                        )
                if platform == "android-aab" and not any(
                    re.fullmatch(
                        r"BUNDLE-METADATA/com\.android\.tools\.build\.debugsymbols/[^/]+/libapp\.so\.(?:sym|dbg)",
                        name,
                    )
                    for name in names
                ):
                    raise ObfuscationError(
                        "Android AAB lacks Gradle's store-only libapp debug metadata; "
                        "the final delivery stripping step cannot be proven."
                    )
        except zipfile.BadZipFile as exc:
            raise ObfuscationError(f"Invalid Android release archive: {resolved}") from exc


def verify_delivery_native_payload_is_stripped(
    platform: str, paths: list[pathlib.Path]
) -> None:
    if platform in {"android-apk", "android-aab"}:
        verify_android_delivery_payload_is_stripped(platform, paths)
    for path in paths:
        for label, data in iter_artifact_blobs(path):
            reject_unstripped_native_blob(label, data)


def _privacy_target_for_release_artifact(
    platform: str, path: pathlib.Path
) -> str | None:
    name = path.name
    exact_names = {
        "app-phone-release.apk": "android-phone-tablet-apk",
        "app-tv-release.apk": "android-tv-apk",
        "app-release.aab": (
            "wear-os-aab" if platform == "wear-os" else "android-phone-tablet-aab"
        ),
        "app-tv-release.aab": "android-tv-aab",
        "WinsVPN-Setup.exe": "windows-x64-installer",
        "WinsVPN-PartnerCenter.exe": "windows-x64-partner-center",
        "WinsVPN-Setup-arm64.exe": "windows-arm64-installer",
        "WinsVPN-PartnerCenter-arm64.exe": "windows-arm64-partner-center",
        **{name: target for target, name in WINDOWS_UNSIGNED_LOCAL_ARTIFACT_NAMES.items()},
        "wins-vpn-linux-x64.tar.gz": "linux-x64-package",
        "wins-vpn-linux-arm64.tar.gz": "linux-arm64-package",
        "wins-vpn-companion-chrome.zip": "chrome-extension-package",
        "wins-vpn-companion-edge.zip": "edge-extension-package",
        "wins-vpn-companion-firefox.zip": "firefox-extension-package",
        "wins-vpn-companion-firefox.xpi": "firefox-extension-package",
    }
    target = exact_names.get(name)
    if target is not None:
        return target
    if platform == "ios" and name.endswith(".ipa"):
        return "ios-app-store-ipa"
    if platform == "macos" and name.endswith(".pkg"):
        return "macos-app-store-pkg"
    if name.endswith(".apk"):
        return "android-tv-apk" if "tv" in name.lower() else "android-phone-tablet-apk"
    if name.endswith(".aab"):
        if platform == "wear-os":
            return "wear-os-aab"
        return "android-tv-aab" if "tv" in name.lower() else "android-phone-tablet-aab"
    return None


def _verify_release_artifact_hardening_blobs(
    platform: str, paths: list[pathlib.Path]
) -> None:
    if not paths:
        raise ObfuscationError("At least one exact release artifact is required.")
    verify_delivery_native_payload_is_stripped(platform, paths)
    verify_embedded_watchos_companion(platform, paths)
    verify_extension_javascript_hardening(platform, paths)
    for path in paths:
        for label, data in iter_artifact_blobs(path):
            reject_packaged_private_symbols(platform, label, data)
            reject_embedded_long_lived_credentials(label, data)
            reject_sensitive_internal_identifiers(platform, label, data)


SECRET_SCAN_DEFERRAL_INPUT_CONTRACT = "winsvpn-remote-attestation-input-v1"
SECRET_SCAN_DEFERRAL_INPUT_LIMIT = 65536
SECRET_SCAN_DEFERRAL_NOTICE = (
    "RELEASE SECRET SCAN: DEFERRED TO THE RELEASE HOST (finish-build on the macOS "
    "release host has the authenticated worker scan the copied-back installer with "
    "the authenticated inventory and refuses the receipt on any hit or scan failure)"
)


def _remote_attestation_check() -> ModuleType:
    # Called only by the deferral, which only a Windows build host reaches. A
    # call-time import keeps this module loadable by descriptor with a closed
    # module set (the Apple gate), where this sibling is not part of the closure.
    if __package__:
        from tools import release_remote_attestation_check as module
    else:
        import release_remote_attestation_check as module
    return module


def require_secret_scan_deferral(remote_input: pathlib.Path) -> None:
    """Allow a Windows remote-attested build to hand the secret scan to the Mac.

    The authenticated inventory loader needs descriptor-relative open and stat,
    which Windows does not have, so the exact secret scan cannot run on a
    Windows build host. A remote-attested Windows build (REMOTE_INPUT.json from
    tools/release_remote_build.py prepare) may therefore defer it, and then
    tools/release_remote_build.py finish has the authenticated dependency-freeze
    worker run the same scan on the release host and refuse the receipt on any
    hit. The deferral is available nowhere else: not on a POSIX host, not for
    another platform, and not without the complete input record that only
    prepare writes. That record is validated by the same loader the build
    host's verify-inputs step uses, not by a few of its fields.
    """

    if os.name != "nt":
        raise ObfuscationError(
            "The secret scan is deferred to the release host only by a Windows build host."
        )
    checker = _remote_attestation_check()
    try:
        with open(remote_input, "rb") as handle:
            raw = handle.read(SECRET_SCAN_DEFERRAL_INPUT_LIMIT + 1)
    except OSError as exc:
        raise ObfuscationError(
            "The secret scan deferral needs a readable REMOTE_INPUT.json."
        ) from exc
    if len(raw) > SECRET_SCAN_DEFERRAL_INPUT_LIMIT:
        raise ObfuscationError(
            "The secret scan deferral needs the Windows remote-attestation input record."
        )
    try:
        record = checker.load_input(remote_input)
    except (checker.RemoteAttestationError, OSError, UnicodeDecodeError, ValueError) as exc:
        raise ObfuscationError(
            "The secret scan deferral needs the Windows remote-attestation input record."
        ) from exc
    if (
        record.get("contract") != SECRET_SCAN_DEFERRAL_INPUT_CONTRACT
        or record.get("platform") != "windows"
        or record.get("remote_host") != "windows"
    ):
        raise ObfuscationError(
            "The secret scan deferral needs the Windows remote-attestation input record."
        )


def verify_release_artifact_hardening(
    platform: str,
    paths: list[pathlib.Path],
    privacy_target_id: str | None = None,
    defer_secret_scan: pathlib.Path | None = None,
) -> None:
    _verify_release_artifact_hardening_blobs(platform, paths)
    if defer_secret_scan is not None:
        if platform != "windows":
            raise ObfuscationError(
                "Only a Windows build defers the secret scan to the release host."
            )
        if privacy_target_id is not None and re.fullmatch(
            r"windows-(?:x64|arm64)-(?:installer|partner-center)", privacy_target_id
        ) is None:
            raise ObfuscationError(
                "Only a Windows installer scan can be deferred to the release host."
            )
        require_secret_scan_deferral(defer_secret_scan)
        print(SECRET_SCAN_DEFERRAL_NOTICE)
        return
    try:
        if __package__:
            from tools.validate_release_artifact_privacy import (
                PrivacyError,
                scan_release_artifacts,
                validate_artifacts,
            )
            from tools.release_secret_inventory import InventoryError
            from tools.release_secret_inventory import load_authenticated_secret_inventory
            from tools.release_secret_inventory import release_secret_values
        else:
            from validate_release_artifact_privacy import (
                PrivacyError,
                scan_release_artifacts,
                validate_artifacts,
            )
            from release_secret_inventory import InventoryError
            from release_secret_inventory import load_authenticated_secret_inventory
            from release_secret_inventory import release_secret_values

        secret_inventory = load_authenticated_secret_inventory(repository_root=ROOT)
        for path in paths:
            target_id = privacy_target_id or _privacy_target_for_release_artifact(
                platform, path
            )
            if target_id is None:
                release_suffixes = {
                    ".aab", ".apk", ".exe", ".ipa", ".pkg", ".xpi"
                }
                if path.suffix.lower() in release_suffixes or path.name.endswith(".tar.gz"):
                    raise ObfuscationError(
                        "Exact release artifact privacy target cannot be inferred."
                    )
                secrets = dict(release_secret_values(secret_inventory))
                try:
                    validate_artifacts((path,), secrets)
                finally:
                    secrets.clear()
                continue
            result = scan_release_artifacts(
                (path,), secret_inventory, target_id=target_id
            )
            if not result.passed:
                raise ObfuscationError(
                    "Exact release artifact contains a root-authorized server secret."
                )
    except (InventoryError, PrivacyError) as exc:
        raise ObfuscationError(
            f"Exact release artifact failed embedded-secret/privacy inspection: {exc}"
        ) from exc


def _receipt_verification(platform: str | None = None) -> dict[str, bool]:
    custody = {
        "obfuscation_is_not_secret_protection": True,
        "durable_secrets_remain_server_side": True,
        "authenticated_receipt_required": True,
    }
    if platform in EXTENSION_PLATFORMS:
        return {
            "inspected_artifact_symbol_files_absent": True,
            "inspected_blobs_long_lived_credentials_absent": True,
            "inspected_blobs_sensitive_internal_identifiers_absent": True,
            "extension_store_minification_required": True,
            "extension_obfuscation_forbidden": True,
            "producer_static_contract_verified": True,
            **custody,
        }
    if platform == "wear-os":
        return {
            "inspected_artifact_symbol_files_absent": True,
            "inspected_blobs_long_lived_credentials_absent": True,
            "inspected_native_debug_sections_absent": True,
            "android_r8_minify_required": True,
            "android_resource_shrinking_required": True,
            "private_r8_mapping_verified": True,
            "producer_static_contract_verified": True,
            **custody,
        }
    if platform is not None and platform not in FLUTTER_OBFUSCATION_PLATFORMS:
        raise ObfuscationError(f"unsupported receipt platform: {platform}")
    claims = {
        "inspected_artifact_symbol_files_absent": True,
        "inspected_blobs_long_lived_credentials_absent": True,
        "inspected_blobs_sensitive_internal_identifiers_absent": True,
        "inspected_native_debug_sections_absent": True,
        "flutter_obfuscation_flag_required": True,
        "private_flutter_symbols_verified": True,
        "producer_static_contract_verified": True,
        "split_debug_info_flag_required": True,
        **custody,
    }
    if platform in {"android-apk", "android-aab"}:
        claims.update(
            {
                "android_r8_minify_required": True,
                "android_resource_shrinking_required": True,
                "private_r8_mapping_verified": True,
            }
        )
    if platform in {"ios", "macos"}:
        claims.update(
            {
                "apple_dsym_separated": True,
                "apple_strip_style_all_required": True,
            }
        )
    if platform == "windows":
        claims["windows_pdb_separated"] = True
    if platform == "linux":
        claims["linux_split_dwarf_required"] = True
    return claims


def record(
    platform: str,
    symbols_dir: pathlib.Path,
    manifest: pathlib.Path,
    artifacts: list[pathlib.Path],
    target_id: str | None = None,
    defer_secret_scan: pathlib.Path | None = None,
) -> None:
    if symbols_dir.expanduser().is_symlink() or manifest.expanduser().is_symlink():
        raise ObfuscationError("Private symbol directory and manifest must not be symlinks.")
    if target_id:
        _bind_exact_target_paths(target_id, platform, symbols_dir, manifest, artifacts)
    elif _requires_exact_target(platform):
        raise ObfuscationError(
            f"{platform} package obfuscation evidence must bind an exact target."
        )
    directory = contained(symbols_dir, PRIVATE_SYMBOL_ROOT)
    manifest_parent = manifest.expanduser().resolve().parent
    if manifest_parent != directory:
        raise ObfuscationError("Obfuscation manifest must be written directly inside its symbol directory.")
    version, build = pubspec_version()
    validate_static()
    with _standalone_record_verify_artifacts(artifacts) as bound:
        if target_id:
            verify_release_artifact_hardening(
                platform,
                bound.snapshot_paths,
                privacy_target_id=target_id,
                defer_secret_scan=defer_secret_scan,
            )
        else:
            verify_release_artifact_hardening(
                platform, bound.snapshot_paths, defer_secret_scan=defer_secret_scan
            )
        artifact_records = bound.records
        symbol_records = inspect_private_evidence(
            platform, directory, PRIVATE_SYMBOL_ROOT
        )
    payload = {
        "schema_version": 2,
        "contract": "winsvpn-release-obfuscation-and-secret-free-v2",
        "contract_sha256": sha256_file(CONTRACT_PATH),
        "platform": platform,
        "app_version": version,
        "build_number": build,
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "private_symbols_not_packaged": True,
        "verification": _receipt_verification(platform),
        "artifacts": artifact_records,
        "symbols": symbol_records,
    }
    if target_id:
        payload["target_id"] = target_id
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=manifest.parent, delete=False, newline="\n"
    ) as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = pathlib.Path(handle.name)
    temporary.replace(manifest)
    target_note = f" target={target_id}" if target_id else ""
    print(
        f"RELEASE OBFUSCATION EVIDENCE: PASS platform={platform}{target_note} "
        f"artifacts={len(payload['artifacts'])} symbols={len(payload['symbols'])}"
    )


def verify(
    platform: str,
    manifest: pathlib.Path,
    symbols_dir: pathlib.Path,
    artifacts: list[pathlib.Path],
    target_id: str | None = None,
    defer_secret_scan: pathlib.Path | None = None,
) -> None:
    if symbols_dir.expanduser().is_symlink() or manifest.expanduser().is_symlink():
        raise ObfuscationError("Private symbol directory and manifest must not be symlinks.")
    if target_id:
        _bind_exact_target_paths(target_id, platform, symbols_dir, manifest, artifacts)
    elif platform == "linux":
        raise ObfuscationError("Linux package obfuscation evidence must bind an exact target.")
    elif _requires_exact_target(platform):
        raise ObfuscationError(
            f"{platform} package obfuscation evidence must bind an exact target."
        )
    resolved = contained(manifest, PRIVATE_SYMBOL_ROOT)
    directory = contained(symbols_dir, PRIVATE_SYMBOL_ROOT)
    if resolved.parent != directory:
        raise ObfuscationError("Obfuscation manifest is not inside the requested symbol directory.")
    try:
        info = resolved.stat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size <= 0
            or info.st_size > OBFUSCATION_RECEIPT_JSON_MAX_BYTES
        ):
            raise ObfuscationError(
                f"Authenticated obfuscation receipt JSON size is invalid: {resolved}"
            )
        with resolved.open("rb") as handle:
            receipt_bytes = handle.read(OBFUSCATION_RECEIPT_JSON_MAX_BYTES + 1)
        if len(receipt_bytes) != info.st_size:
            raise ObfuscationError(
                f"Authenticated obfuscation receipt changed while read: {resolved}"
            )
    except ObfuscationError:
        raise
    except OSError as exc:
        raise ObfuscationError(
            f"Authenticated obfuscation receipt is absent or invalid: {resolved}"
        ) from exc
    payload = _strict_receipt_json_loads(
        receipt_bytes, f"Authenticated obfuscation receipt {resolved}"
    )
    bound_target = _manifest_bound_target(payload)
    if target_id:
        if bound_target != target_id:
            raise ObfuscationError(
                "Obfuscation evidence does not bind the requested exact target."
            )
    elif bound_target is not None:
        raise ObfuscationError(
            "Obfuscation evidence binds an exact target; verify must select that target."
        )
    if payload.get("contract") != "winsvpn-release-obfuscation-and-secret-free-v2":
        raise ObfuscationError("Obfuscation evidence manifest contract is invalid.")
    if payload.get("contract_sha256") != sha256_file(CONTRACT_PATH):
        raise ObfuscationError("Obfuscation evidence belongs to a different contract source.")
    if payload.get("platform") != platform:
        raise ObfuscationError("Obfuscation evidence belongs to a different platform.")
    version, build = pubspec_version()
    if payload.get("app_version") != version or str(payload.get("build_number")) != build:
        raise ObfuscationError("Obfuscation evidence belongs to a different app version/build.")
    if payload.get("private_symbols_not_packaged") is not True:
        raise ObfuscationError("Obfuscation evidence does not assert private symbol separation.")
    if payload.get("verification") != _receipt_verification(platform):
        raise ObfuscationError("Obfuscation evidence verification claims are incomplete.")
    validate_static()
    with _standalone_record_verify_artifacts(artifacts) as bound:
        if target_id:
            verify_release_artifact_hardening(
                platform,
                bound.snapshot_paths,
                privacy_target_id=target_id,
                defer_secret_scan=defer_secret_scan,
            )
        else:
            verify_release_artifact_hardening(
                platform, bound.snapshot_paths, defer_secret_scan=defer_secret_scan
            )
        actual_artifacts = bound.records
        recorded_artifacts = payload.get("artifacts")
        if not isinstance(recorded_artifacts, list) or len(
            recorded_artifacts
        ) != len(actual_artifacts):
            raise ObfuscationError(
                "Obfuscation evidence artifact count does not match."
            )
        # Publication renames a fully verified staged artifact to a private
        # prepared path and then to its canonical output path (the phone APK
        # and AAB also change basename), so the identity is the ordered size
        # and SHA-256 tuple, as in tools/private_release_symbol_custody.py;
        # the recorded path stays as provenance.
        for recorded, actual in zip(recorded_artifacts, actual_artifacts):
            if not isinstance(recorded, dict) or any(
                recorded.get(field) != actual[field]
                for field in ("size", "sha256")
            ):
                raise ObfuscationError(
                    "Exact artifact does not match its obfuscation evidence."
                )
        actual_symbols = inspect_private_evidence(
            platform, resolved.parent, PRIVATE_SYMBOL_ROOT
        )
        if payload.get("symbols") != actual_symbols:
            raise ObfuscationError(
                "Private Flutter symbol files do not match their evidence manifest."
            )
        artifact_count = len(actual_artifacts)
        symbol_count = len(actual_symbols)
    target_note = f" target={target_id}" if target_id else ""
    print(
        f"RELEASE OBFUSCATION EVIDENCE: PASS platform={payload['platform']}{target_note} "
        f"artifacts={artifact_count} symbols={symbol_count}"
    )


def _run_cross_store_tool(relative: str, arguments: list[str], label: str) -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / relative), *arguments],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        shell=False,
        check=False,
        timeout=180,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise ObfuscationError(f"{label} failed closed: {detail}")


def _canonical_repo_artifact(
    raw_path: str, *, suffixes: tuple[str, ...], label: str
) -> pathlib.Path:
    relative = pathlib.PurePath(raw_path)
    if not raw_path or relative.is_absolute() or ".." in relative.parts:
        raise ObfuscationError(f"{label} path must be repository-relative and contained")
    candidate = ROOT / pathlib.Path(raw_path)
    if candidate.is_symlink():
        raise ObfuscationError(f"{label} must not be a symbolic link")
    try:
        artifact = candidate.resolve(strict=True)
        artifact.relative_to(ROOT.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ObfuscationError(f"{label} is absent or escapes the repository") from exc
    if not artifact.is_file() or artifact.stat().st_size == 0:
        raise ObfuscationError(f"{label} must be one non-empty file")
    if artifact.suffix.lower() not in suffixes:
        raise ObfuscationError(f"{label} has the wrong suffix")
    return artifact


def canonical_android_gate_verify(target_id: str, raw_path: str) -> None:
    symbol_family = ANDROID_CROSS_STORE_TARGETS.get(target_id)
    if symbol_family is None:
        raise ObfuscationError(f"unsupported exact Android hardening target: {target_id}")
    relative = pathlib.PurePath(raw_path)
    if not raw_path or relative.is_absolute() or ".." in relative.parts:
        raise ObfuscationError("cross-store AAB path must be repository-relative and contained")
    candidate = ROOT / pathlib.Path(raw_path)
    if candidate.is_symlink():
        raise ObfuscationError("cross-store AAB must not be a symbolic link")
    try:
        artifact = candidate.resolve(strict=True)
        artifact.relative_to(ROOT.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ObfuscationError("cross-store AAB path is missing or escapes the repository") from exc
    if not artifact.is_file() or artifact.suffix.lower() != ".aab" or artifact.stat().st_size == 0:
        raise ObfuscationError("cross-store artifact must be one non-empty .aab file")

    _run_cross_store_tool(
        "tools/verify_android_aab_signers.py",
        ["--verify", target_id, raw_path],
        "Android signing and target identity gate",
    )
    _run_cross_store_tool(
        "tools/verify_android_aab_page_alignment.py",
        [raw_path],
        "Android 16 KiB page-alignment gate",
    )
    version, build = pubspec_version()
    symbols_dir = PRIVATE_SYMBOL_ROOT / symbol_family / f"{version}+{build}"
    manifest = symbols_dir / "manifest.json"
    verify("android-aab", manifest, symbols_dir, [artifact])
    _run_cross_store_tool(
        "tools/validate_release_artifact_privacy.py",
        [
            "--authenticated-inventory",
            "--artifact",
            raw_path,
            "--target",
            target_id,
        ],
        "Android exact-artifact privacy gate",
    )
    print(
        f"ANDROID CROSS-STORE HARDENING GATE: PASS target={target_id} artifact={raw_path}"
    )


def canonical_apple_gate_verify(target_id: str, raw_path: str) -> None:
    # The cross-store helper executes the contamination helper while it loads, so
    # the contamination helper's reviewed hash is checked before either is run.
    if (
        sha256_file(APPLE_RELEASE_CONTAMINATION_GATE_HELPER)
        != APPLE_RELEASE_CONTAMINATION_GATE_HELPER_SHA256
    ):
        raise ObfuscationError(
            "Apple release contamination helper source hash is not reviewed"
        )
    helper = _load_reviewed_helper(
        APPLE_CROSS_STORE_GATE_HELPER,
        APPLE_CROSS_STORE_GATE_HELPER_SHA256,
        "apple_cross_store_artifact_gate",
    )
    AppleArtifactGateError = helper.AppleArtifactGateError
    bind_macos_package_channel = helper.bind_macos_package_channel
    canonical_artifact = helper.canonical_artifact
    verify_privacy_only = helper.verify_privacy_only

    platform = APPLE_CROSS_STORE_TARGETS.get(target_id)
    if platform is None:
        raise ObfuscationError(f"unsupported exact Apple hardening target: {target_id}")
    try:
        if target_id in MACOS_CROSS_STORE_TARGET_LAYOUT:
            bound = bind_macos_package_channel(target_id, raw_path)
            artifact = pathlib.Path(str(bound["artifact"]))
            layout = exact_obfuscation_layout(target_id)
            if bound.get("channel") != layout["channel"]:
                raise ObfuscationError(
                    "macOS obfuscation evidence channel does not match the exact target."
                )
            if bound.get("signing_contract") != layout["signing_contract"]:
                raise ObfuscationError(
                    "macOS obfuscation evidence signing contract does not match "
                    "the exact target."
                )
            if bound.get("expected_authority") != layout["expected_authority"]:
                raise ObfuscationError(
                    "macOS obfuscation evidence signing authority does not match "
                    "the exact target."
                )
            if bound.get("signature_verified") is not False:
                raise ObfuscationError(
                    "macOS obfuscation evidence must not claim Apple signature proof."
                )
            verify(
                "macos",
                pathlib.Path(str(layout["manifest"])),
                pathlib.Path(str(layout["symbols_dir"])),
                [artifact],
                target_id,
            )
        else:
            artifact = canonical_artifact(target_id, raw_path)
            version, build = pubspec_version()
            symbols_dir = PRIVATE_SYMBOL_ROOT / "apple" / platform / f"{version}+{build}"
            verify(platform, symbols_dir / "manifest.json", symbols_dir, [artifact])
        verify_privacy_only(target_id, raw_path)
    except AppleArtifactGateError as exc:
        raise ObfuscationError(str(exc)) from exc
    print(
        f"APPLE CROSS-STORE HARDENING GATE: PASS target={target_id} "
        f"artifact={artifact.relative_to(ROOT.resolve(strict=True))}"
    )


def canonical_linux_gate_verify(target_id: str, raw_path: str) -> None:
    manifest_producer = LINUX_MANIFEST_CROSS_STORE_TARGETS.get(target_id)
    if manifest_producer is not None:
        _run_cross_store_tool(
            manifest_producer,
            ["--verify", target_id, raw_path],
            "Linux exact store-manifest identity and provenance gate",
        )
        _run_cross_store_tool(
            "tools/validate_release_artifact_privacy.py",
            [
                "--authenticated-inventory",
                "--artifact",
                raw_path,
                "--target",
                target_id,
            ],
            "Linux exact store-manifest privacy gate",
        )
        print(
            f"LINUX CROSS-STORE HARDENING GATE: PASS target={target_id} "
            f"artifact={raw_path}"
        )
        return

    arch = LINUX_PACKAGE_CROSS_STORE_TARGETS.get(target_id)
    if arch is None:
        raise ObfuscationError(f"unsupported exact Linux hardening target: {target_id}")
    from linux_cross_store_artifact_gate import (
        LinuxArtifactGateError,
        _secure_regular_repo_path,
        verify_package,
    )

    try:
        artifact = _secure_regular_repo_path(raw_path, "Linux package artifact")
        verify_package(target_id, raw_path)
    except LinuxArtifactGateError as exc:
        raise ObfuscationError(str(exc)) from exc
    layout = exact_obfuscation_layout(target_id)
    symbols_dir = pathlib.Path(str(layout["symbols_dir"]))
    verify(
        "linux",
        pathlib.Path(str(layout["manifest"])),
        symbols_dir,
        [artifact],
        target_id,
    )
    _run_cross_store_tool(
        "tools/validate_release_artifact_privacy.py",
        [
            "--authenticated-inventory",
            "--artifact",
            raw_path,
            "--target",
            target_id,
        ],
        "Linux exact-package privacy gate",
    )
    print(
        f"LINUX CROSS-STORE HARDENING GATE: PASS target={target_id} "
        f"arch={arch} artifact={raw_path}"
    )


def canonical_windows_gate_verify(target_id: str, raw_path: str) -> None:
    from windows_cross_store_artifact_gate import (
        WindowsArtifactGateError,
        verify_artifact,
    )

    if target_id not in WINDOWS_CROSS_STORE_TARGETS:
        raise ObfuscationError(f"unsupported exact Windows hardening target: {target_id}")
    try:
        result = verify_artifact(target_id, raw_path, verify_signature=True)
        artifact = ROOT / str(result["artifact"])
        layout = exact_obfuscation_layout(target_id)
        if str(result["target_architecture"]) != layout["architecture"]:
            raise ObfuscationError(
                "Windows obfuscation evidence architecture does not match the exact target."
            )
        if str(result["distribution_surface"]) != layout["surface"]:
            raise ObfuscationError(
                "Windows obfuscation evidence surface does not match the exact target."
            )
        symbols_dir = pathlib.Path(str(layout["symbols_dir"]))
        verify(
            "windows",
            pathlib.Path(str(layout["manifest"])),
            symbols_dir,
            [artifact],
            target_id,
        )
    except WindowsArtifactGateError as exc:
        raise ObfuscationError(str(exc)) from exc
    _run_cross_store_tool(
        "tools/validate_release_artifact_privacy.py",
        [
            "--authenticated-inventory",
            "--artifact",
            raw_path,
            "--target",
            target_id,
        ],
        "Windows exact-installer privacy gate",
    )
    print(
        f"WINDOWS CROSS-STORE HARDENING GATE: PASS target={target_id} "
        f"artifact={raw_path}"
    )


def canonical_wear_gate_verify(target_id: str, raw_path: str) -> None:
    if target_id not in WEAR_CROSS_STORE_TARGETS:
        raise ObfuscationError(f"unsupported exact Wear hardening target: {target_id}")
    artifact = _canonical_repo_artifact(
        raw_path, suffixes=(".aab",), label="cross-store Wear AAB"
    )
    layout = exact_obfuscation_layout(target_id)
    symbols_dir = pathlib.Path(str(layout["symbols_dir"]))
    mapping = symbols_dir / "mapping.txt"
    if mapping.is_symlink() or not mapping.is_file() or mapping.stat().st_size == 0:
        raise ObfuscationError("Authenticated Wear R8 mapping receipt is absent")
    verify(
        "wear-os",
        pathlib.Path(str(layout["manifest"])),
        symbols_dir,
        [artifact],
        target_id,
    )
    _run_cross_store_tool(
        "tools/validate_release_artifact_privacy.py",
        [
            "--authenticated-inventory",
            "--artifact",
            raw_path,
            "--target",
            target_id,
        ],
        "Wear exact-artifact privacy gate",
    )
    print(f"WEAR CROSS-STORE HARDENING GATE: PASS target={target_id} artifact={raw_path}")


def canonical_extension_gate_verify(target_id: str, raw_path: str) -> None:
    browser = EXTENSION_CROSS_STORE_TARGETS.get(target_id)
    if browser is None:
        raise ObfuscationError(f"unsupported exact extension hardening target: {target_id}")
    allowed = tuple(
        pathlib.PurePath(name).suffix.lower()
        for name in EXTENSION_TARGET_ARTIFACT_NAMES[target_id]
    )
    artifact = _canonical_repo_artifact(
        raw_path, suffixes=allowed, label="cross-store extension package"
    )
    layout = exact_obfuscation_layout(target_id)
    verify(
        browser,
        pathlib.Path(str(layout["manifest"])),
        pathlib.Path(str(layout["symbols_dir"])),
        [artifact],
        target_id,
    )
    _run_cross_store_tool(
        "tools/validate_release_artifact_privacy.py",
        [
            "--authenticated-inventory",
            "--artifact",
            raw_path,
            "--target",
            target_id,
        ],
        "Extension exact-artifact secret scan",
    )
    print(
        f"EXTENSION CROSS-STORE HARDENING GATE: PASS target={target_id} "
        f"artifact={raw_path}"
    )


def validate_static() -> None:
    if sha256_file(ANDROID_TOOLCHAIN_LAUNCHER) != ANDROID_TOOLCHAIN_LAUNCHER_SHA256:
        raise ObfuscationError(
            "Android toolchain CPython launcher source hash is not reviewed"
        )
    requirements = {
        "tools/local_release_gate.ps1": (
            r'tools/build_android_release\.ps1',
            r'(?s)Invoke-Gate "Canonical Windows application and installer build".{0,800}"-File" "installer/windows/build_installer\.ps1"',
            r"Invoke-WithReleaseBuildLock -Purpose 'flutter-validation'",
            r"Invoke-WithReleaseBuildLock -Purpose 'android-cache-reset'",
        ),
        "tools/build_android_release.ps1": (
            r"'build', 'apk', '--release', '--flavor', 'phone', '--obfuscate'",
            r'--split-debug-info=\$ApkSymbols',
            r"'build', 'appbundle', '--release', '--flavor', 'phone', '--obfuscate'",
            r'--split-debug-info=\$AabSymbols',
            r"'build', 'appbundle', '--release', '--flavor', 'tv', '--obfuscate'",
            r'--split-debug-info=\$TvAabSymbols',
            r"mapping\\phoneRelease\\mapping\.txt",
            r"native-debug-symbols\\phoneRelease\\native-debug-symbols\.zip",
            r"proguard-mapping\.txt",
            r"native-debug-symbols\.zip",
            r"Android private release symbol output is missing or empty",
            r'ANDROID RELEASE SIGNER: PASS',
        ),
        "tools/build_android_release_macos.sh": (
            # Static producer tests grep this file for:
            # build apk --release --flavor phone --obfuscate
            # build appbundle --release --flavor phone --obfuscate
            # build apk --release --flavor tv --obfuscate
            r"build apk --no-pub --release --flavor phone --obfuscate",
            r'--split-debug-info="\$\{STAGE_APK_SYMBOLS\}"',
            r"build appbundle --no-pub --release --flavor phone --obfuscate",
            r'--split-debug-info="\$\{STAGE_AAB_SYMBOLS\}"',
            r"build apk --no-pub --release --flavor tv --obfuscate",
            r'--split-debug-info="\$\{STAGE_TV_APK_SYMBOLS\}"',
            r"build appbundle --no-pub --release --flavor tv --obfuscate",
            r'--split-debug-info="\$\{STAGE_TV_AAB_SYMBOLS\}"',
            r"mapping/phoneRelease/mapping\.txt",
            r"native-debug-symbols/phoneRelease/native-debug-symbols\.zip",
            r"proguard-mapping\.txt",
            r"native-debug-symbols\.zip",
            r"Required Android release output is unsafe, missing, or empty",
            r"ANDROID RELEASE SIGNER: PASS",
        ),
        "installer/windows/build_installer.ps1": (
            r"\$script:FlutterCommand\s*=\s*\$flutterCommand\.Source",
            r"(?s)&\s+\$script:FlutterCommand\s+build\s+windows\s+--release\s+--no-pub\s+--obfuscate.{0,240}--split-debug-info=.{0,240}--extra-gen-snapshot-options=--strip",
            r"--split-debug-info=",
            r"--extra-gen-snapshot-options=--strip",
            r'manifest-\$DistributionSurface\.json',
            r"--target-id \$WindowsObfuscationTargetId",
            r"Get-WindowsPayloadDebugSymbolFiles",
            r"Move-WindowsPayloadDebugSymbolsToPrivateCustody",
            r"Assert-WindowsPayloadContainsNoDebugSymbols",
            r"@\('\.pdb', '\.ilk', '\.iobj', '\.ipdb'",
        ),
        "tools/build_linux_release.sh": (
            r'"\$\{FLUTTER_COMMAND\}" build linux --release --obfuscate',
            r"--split-debug-info=",
            r"--extra-gen-snapshot-options=--strip",
            r"bind_linux_obfuscation_paths",
            r"private-release-symbols/linux/\$\{arch_label\}/",
            r'--target-id "linux-\$\{LINUX_RELEASE_ARCH_LABEL\}-package"',
            r"objcopy --only-keep-debug",
            r"objcopy --add-gnu-debuglink",
            r"strip --strip-unneeded",
            r"LINUX_NATIVE_SYMBOL_DIR",
        ),
        "tools/apple_runtime_smoke.sh": (
            r"run_flutter_build build ios --release --no-codesign --obfuscate[^\n]+--extra-gen-snapshot-options=--strip",
            r"run_flutter_build build macos --release --obfuscate[^\n]+--extra-gen-snapshot-options=--strip",
            r"run_flutter_build build ios --release --config-only --obfuscate[^\n]+--extra-gen-snapshot-options=--strip",
            r"run_flutter_build build macos --release --config-only --obfuscate[^\n]+--extra-gen-snapshot-options=--strip",
            r"DART_OBFUSCATION=true",
            r"SPLIT_DEBUG_INFO=",
            r"EXTRA_GEN_SNAPSHOT_OPTIONS=--strip",
            r"require_apple_release_symbols",
            r"record_apple_release_obfuscation",
        ),
        "extension/build.py": (
            r"shutil\.copytree\(\s*SRC,\s*pkg / \"src\"",
            r"byte-identical copy of\s+src/",
            r"No dependencies\. Standard library only",
        ),
    }
    for relative, patterns in requirements.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        for pattern in patterns:
            if not re.search(pattern, text):
                raise ObfuscationError(f"{relative} does not enforce release obfuscation: {pattern}")
    android_gradle = (ROOT / "android/app/build.gradle.kts").read_text(encoding="utf-8")
    if re.search(r'ndk\.debugSymbolLevel\s*=\s*"FULL"', android_gradle):
        raise ObfuscationError(
            "android/app/build.gradle.kts manually preserves FULL native symbols; "
            "this prevents Flutter from validating stripped libapp.so metadata in AABs."
        )
    gradle_by_platform = {
        "android-apk": "android/app/build.gradle.kts",
        "android-aab": "android/app/build.gradle.kts",
        "wear-os": "wear_os/app/build.gradle.kts",
    }
    checked_gradle: set[str] = set()
    for platform in sorted(ANDROID_R8_PLATFORMS):
        relative = gradle_by_platform.get(platform)
        if relative is None:
            raise ObfuscationError(
                f"R8 platform {platform} has no Gradle contract path"
            )
        if relative in checked_gradle:
            continue
        checked_gradle.add(relative)
        gradle = (ROOT / relative).read_text(encoding="utf-8")
        if not re.search(
            r"isMinifyEnabled = true\s*\n\s*isShrinkResources = true",
            gradle,
        ):
            raise ObfuscationError(
                f"{relative} does not enable release R8 minification and resource shrinking"
            )
    ios_pbx = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
    if ios_pbx.count("STRIP_STYLE = all;") < 2:
        raise ObfuscationError(
            "ios/Runner.xcodeproj/project.pbxproj does not strip iOS/watchOS release binaries"
        )
    if 'STRIP_STYLE = "non-global"' in ios_pbx:
        raise ObfuscationError(
            "ios/Runner.xcodeproj/project.pbxproj weakens Apple strip to non-global"
        )
    if ios_pbx.count("COPY_PHASE_STRIP = YES;") < 2:
        raise ObfuscationError(
            "ios/Runner.xcodeproj/project.pbxproj does not copy-phase strip Apple release binaries"
        )
    if ios_pbx.count('DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";') < 2:
        raise ObfuscationError(
            "ios/Runner.xcodeproj/project.pbxproj does not separate Apple dSYM from the customer binary"
        )
    if "SDKROOT = watchos;" not in ios_pbx or "WK_COMPANION_APP_BUNDLE_IDENTIFIER" not in ios_pbx:
        raise ObfuscationError(
            "ios/Runner.xcodeproj/project.pbxproj is missing the embedded watchOS companion target"
        )
    macos_pbx = (ROOT / "macos/Runner.xcodeproj/project.pbxproj").read_text(
        encoding="utf-8"
    )
    if macos_pbx.count("STRIP_STYLE = all;") < 2:
        raise ObfuscationError(
            "macos/Runner.xcodeproj/project.pbxproj does not strip macOS release binaries"
        )
    if macos_pbx.count("COPY_PHASE_STRIP = YES;") < 2:
        raise ObfuscationError(
            "macos/Runner.xcodeproj/project.pbxproj does not copy-phase strip macOS release binaries"
        )
    if macos_pbx.count('DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";') < 2:
        raise ObfuscationError(
            "macos/Runner.xcodeproj/project.pbxproj does not separate macOS dSYM from the customer binary"
        )
    android_builder = (ROOT / "tools/build_android_release.ps1").read_text(encoding="utf-8")
    if "--extra-gen-snapshot-options=--strip" in android_builder:
        raise ObfuscationError(
            "tools/build_android_release.ps1 pre-strips libapp.so before AGP can extract AAB symbol metadata."
        )
    macos_android_builder = (ROOT / "tools/build_android_release_macos.sh").read_text(encoding="utf-8")
    if "--extra-gen-snapshot-options=--strip" in macos_android_builder:
        raise ObfuscationError(
            "tools/build_android_release_macos.sh pre-strips libapp.so before AGP can extract AAB symbol metadata."
        )
    extension_builder = (ROOT / "extension/build.py").read_text(encoding="utf-8")
    # Store-permitted size transform is whitespace/comment removal only.
    # Identifier-mangling --minify is forbidden. Chrome forbids obfuscation;
    # minification is not secret protection.
    if re.search(
        r"(?i)(?:javascript-obfuscator|control-flow-flatten|--sourcemap)",
        extension_builder,
    ):
        raise ObfuscationError(
            "extension/build.py must not invoke javascript-obfuscator; Chrome forbids "
            "obfuscation. Store-permitted --minify is required in packaged JS and is "
            "not secret protection."
        )
    minifier_src = (ROOT / "extension/tools/store_js_minifier.py").read_text(
        encoding="utf-8"
    )
    if "--minify-whitespace" not in minifier_src:
        raise ObfuscationError(
            "extension/tools/store_js_minifier.py must use whitespace-only esbuild flags"
        )
    if "identifier-mangling --minify is forbidden" not in minifier_src:
        raise ObfuscationError(
            "extension/tools/store_js_minifier.py must refuse identifier-mangling --minify"
        )
    if "identifier-mangling --minify-identifiers is forbidden" not in minifier_src:
        raise ObfuscationError(
            "extension/tools/store_js_minifier.py must refuse identifier-mangling "
            "--minify-identifiers"
        )
    if "identifier-mangling --minify-syntax is forbidden" not in minifier_src:
        raise ObfuscationError(
            "extension/tools/store_js_minifier.py must refuse identifier-mangling "
            "--minify-syntax"
        )
    contract_src = CONTRACT_PATH.read_text(encoding="utf-8")
    if "require_zip_javascript_matches_producer" not in contract_src:
        raise ObfuscationError(
            "tools/release_obfuscation_contract.py must bind extension JavaScript "
            "to the exact esbuild producer zip member closure"
        )
    if ("comment_lines" + " >= 2") in contract_src or (
        "lstrip(" + '" \\t")'
    ) in contract_src:
        raise ObfuscationError(
            "tools/release_obfuscation_contract.py must not claim minification "
            "from an indent/comment heuristic"
        )
    linux_builder = (ROOT / "tools/build_linux_release.sh").read_text(encoding="utf-8")
    if re.search(
        r'LINUX_SYMBOL_DIR="\$\{ROOT\}/\.artifacts/private-release-symbols/linux/'
        r'\$\{APP_VERSION\}\+\$\{BUILD_NUMBER\}"',
        linux_builder,
    ):
        raise ObfuscationError(
            "tools/build_linux_release.sh must not share one obfuscation symbol "
            "directory across Linux architectures."
        )
    windows_builder = (ROOT / "installer/windows/build_installer.ps1").read_text(
        encoding="utf-8"
    )
    if re.search(
        r'WindowsObfuscationManifest\s*=\s*Join-Path \$WindowsSymbolDir "manifest\.json"',
        windows_builder,
    ):
        raise ObfuscationError(
            "installer/windows/build_installer.ps1 must not share one installer "
            "obfuscation manifest across website and Partner Center surfaces."
        )
    extension_source = ROOT / "extension/src"
    source_files = sorted(path for path in extension_source.rglob("*") if path.is_file())
    if not source_files:
        raise ObfuscationError("Extension static policy selected no authored source files.")
    for path in source_files:
        relative = path.relative_to(ROOT).as_posix()
        if path.name.casefold().endswith(PACKAGED_PRIVATE_SYMBOL_SUFFIXES):
            raise ObfuscationError(f"Extension source contains a private map/symbol file: {relative}")
        if _source_map_reference_present(path.read_bytes()):
            raise ObfuscationError(f"Extension source contains a source-map reference: {relative}")
    print("RELEASE OBFUSCATION STATIC CONTRACT: PASS")


def _minimal_elf64(*section_names: str) -> bytes:
    names = ("", *section_names, ".shstrtab")
    strtab = b""
    offsets: list[int] = []
    for name in names:
        offsets.append(len(strtab))
        strtab += name.encode("ascii") + b"\0"
    ehdr_size = 64
    shdr_size = 64
    shstr_off = ehdr_size
    shoff = shstr_off + len(strtab)
    pad = (8 - (shoff % 8)) % 8
    shoff += pad
    data = bytearray(shoff + (len(names) * shdr_size))
    data[0:4] = ELF_MAGIC
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<H", data, 16, 3)
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<Q", data, 40, shoff)
    struct.pack_into("<H", data, 52, 64)
    struct.pack_into("<H", data, 58, 64)
    struct.pack_into("<H", data, 60, len(names))
    struct.pack_into("<H", data, 62, len(names) - 1)
    data[shstr_off : shstr_off + len(strtab)] = strtab
    for index, name in enumerate(names):
        hdr = shoff + (index * shdr_size)
        struct.pack_into("<I", data, hdr, offsets[index])
        if name == ".shstrtab":
            struct.pack_into("<I", data, hdr + 4, 3)
            struct.pack_into("<Q", data, hdr + 24, shstr_off)
            struct.pack_into("<Q", data, hdr + 32, len(strtab))
        elif name:
            struct.pack_into("<I", data, hdr + 4, 1)
    return bytes(data)


def _minimal_pe(*section_names: str) -> bytes:
    e_lfanew = 128
    section_start = e_lfanew + 24
    data = bytearray(section_start + (len(section_names) * 40))
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 60, e_lfanew)
    data[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<H", data, e_lfanew + 6, len(section_names))
    struct.pack_into("<H", data, e_lfanew + 20, 0)
    for index, name in enumerate(section_names):
        start = section_start + (index * 40)
        raw = name.encode("ascii")[:8]
        data[start : start + len(raw)] = raw
    return bytes(data)


def _minimal_pe_with_debug_directory(debug_type: int = 2) -> bytes:
    e_lfanew = 128
    optional_size = 240
    section_start = e_lfanew + 24 + optional_size
    raw_pointer = 512
    debug_size = 28
    payload = b"RSDS" + (b"p" * 28)
    data = bytearray(raw_pointer + debug_size + len(payload))
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 60, e_lfanew)
    data[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<H", data, e_lfanew + 6, 1)
    struct.pack_into("<H", data, e_lfanew + 20, optional_size)
    optional_start = e_lfanew + 24
    struct.pack_into("<H", data, optional_start, 0x20B)
    struct.pack_into("<I", data, optional_start + 60, raw_pointer)
    struct.pack_into("<I", data, optional_start + 108, 16)
    struct.pack_into("<II", data, optional_start + 112 + (6 * 8), 0x1000, debug_size)
    data[section_start : section_start + 6] = b".rdata"
    struct.pack_into("<I", data, section_start + 8, debug_size + len(payload))
    struct.pack_into("<I", data, section_start + 12, 0x1000)
    struct.pack_into("<I", data, section_start + 16, debug_size + len(payload))
    struct.pack_into("<I", data, section_start + 20, raw_pointer)
    struct.pack_into("<I", data, raw_pointer + 12, debug_type)
    struct.pack_into("<I", data, raw_pointer + 16, len(payload))
    struct.pack_into("<I", data, raw_pointer + 20, 0x1000 + debug_size)
    struct.pack_into("<I", data, raw_pointer + 24, raw_pointer + debug_size)
    data[raw_pointer + debug_size :] = payload
    return bytes(data)


def _minimal_macho64(*, dwarf: bool) -> bytes:
    cmdsize = 72 + 80
    data = bytearray(32 + cmdsize)
    data[0:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<I", data, 4, 0x0100000C)
    struct.pack_into("<I", data, 12, 6)
    struct.pack_into("<I", data, 16, 1)
    struct.pack_into("<I", data, 20, cmdsize)
    struct.pack_into("<I", data, 32, 0x19)
    struct.pack_into("<I", data, 36, cmdsize)
    segname = b"__DWARF" if dwarf else b"__TEXT"
    data[40 : 40 + len(segname)] = segname
    struct.pack_into("<I", data, 32 + 64, 1)
    sectname = b"__debug_info" if dwarf else b"__text"
    data[32 + 72 : 32 + 72 + len(sectname)] = sectname
    data[32 + 88 : 32 + 88 + len(segname)] = segname
    return bytes(data)


def _minimal_macho64_with_symbol(n_type: int, name: bytes = b"fixture_symbol") -> bytes:
    command_size = 24
    symbol_offset = 32 + command_size
    string_table = b"\0" + name + b"\0"
    string_offset = symbol_offset + 16
    data = bytearray(string_offset + len(string_table))
    data[0:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<I", data, 4, 0x0100000C)
    struct.pack_into("<I", data, 12, 6)
    struct.pack_into("<I", data, 16, 1)
    struct.pack_into("<I", data, 20, command_size)
    struct.pack_into("<I", data, 32, 0x2)
    struct.pack_into("<I", data, 36, command_size)
    struct.pack_into("<IIII", data, 40, symbol_offset, 1, string_offset, len(string_table))
    struct.pack_into("<I", data, symbol_offset, 1)
    data[symbol_offset + 4] = n_type
    data[string_offset:] = string_table
    return bytes(data)


def _write_producer_extension_zip(
    dest: pathlib.Path, browser: str = "chrome"
) -> pathlib.Path:
    minifier = _store_js_minifier()
    os.environ[minifier.FETCH_ENV] = "0"
    if not os.environ.get(minifier.CACHE_ENV, "").strip():
        test_cache = pathlib.Path("/tmp/winsvpn-extension-esbuild-test-cache")
        if test_cache.is_dir():
            os.environ[minifier.CACHE_ENV] = str(test_cache)
    spec = importlib.util.spec_from_file_location(
        "winsvpn_extension_build_obfuscation_self_test",
        ROOT / "extension" / "build.py",
    )
    if spec is None or spec.loader is None:
        raise ObfuscationError("extension producer could not be loaded")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    dest.parent.mkdir(parents=True, exist_ok=True)
    builder.DIST = dest.parent / f"producer-dist-{browser}"
    artifact = builder.zip_package(builder.stage(browser), browser)
    dest.write_bytes(artifact.read_bytes())
    return dest


def self_test() -> None:
    hostile_json = (
        (b'{"receipt":{"ok":true,"ok":false}}', "duplicate key"),
        (b'{"receipt":NaN}', "non-finite"),
        (b'{"receipt":Infinity}', "non-finite"),
        (b'{"receipt":1e400}', "non-finite"),
        (b'{"receipt":"0123456789"}', "size is invalid"),
    )
    for payload, expected in hostile_json:
        try:
            _strict_receipt_json_loads(
                payload,
                "obfuscation receipt self-test",
                max_bytes=8 if expected == "size is invalid" else 1024,
            )
        except ObfuscationError as exc:
            if expected not in str(exc):
                raise ObfuscationError(
                    "Obfuscation receipt JSON self-test failed unexpectedly."
                ) from exc
        else:
            raise ObfuscationError(
                "Obfuscation receipt JSON self-test accepted hostile JSON."
            )

    with tempfile.TemporaryDirectory() as temp_name:
        root = pathlib.Path(temp_name).resolve()
        symbols = root / "symbols"
        symbols.mkdir()
        (symbols / "app.test-x64.symbols").write_bytes(b"s" * 128)
        inspected = inspect_symbols(symbols, root)
        if len(inspected) != 1 or inspected[0]["size"] != 128:
            raise ObfuscationError("Self-test did not accept valid private symbols.")
        java_class = b"\xca\xfe\xba\xbe\x00\x00\x00=\x00\x01" + (b"\x00" * 64)
        reject_unstripped_native_blob("classes/example.class", java_class)
        try:
            reject_unstripped_native_blob("lib/example.dylib", java_class)
        except ObfuscationError as error:
            if "lib/example.dylib: invalid fat Mach-O" not in str(error):
                raise
        else:
            raise ObfuscationError("Self-test accepted malformed native Mach-O payload.")
        (symbols / "app.test-x64.symbols").write_bytes(b"")
        try:
            inspect_symbols(symbols, root)
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted an empty symbol file.")
        stripped_elf = _minimal_elf64(".text", ".dynsym")
        debug_elf = _minimal_elf64(".text", ".debug_info")
        apk = root / "release.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("lib/arm64-v8a/libapp.so", stripped_elf)
            archive.writestr("lib/arm64-v8a/libxray.so", stripped_elf)
            archive.writestr("lib/arm64-v8a/libam-go.so", stripped_elf)
        verify_delivery_native_payload_is_stripped("android-apk", [apk])
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("lib/arm64-v8a/libapp.so", stripped_elf)
            archive.writestr("lib/arm64-v8a/libxray.so", debug_elf)
        try:
            verify_delivery_native_payload_is_stripped("android-apk", [apk])
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted DWARF in a non-libapp Android native library.")
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("lib/arm64-v8a/libapp.so", stripped_elf)
            archive.writestr("lib/arm64-v8a/libxray.so", _minimal_elf64(".text", ".symtab"))
        try:
            verify_delivery_native_payload_is_stripped("android-apk", [apk])
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted an ELF symbol table in an Android native library.")
        aab = root / "release.aab"
        with zipfile.ZipFile(aab, "w") as archive:
            archive.writestr("base/lib/arm64-v8a/libapp.so", stripped_elf)
            archive.writestr("base/lib/arm64-v8a/libwinnengine.so", stripped_elf)
            archive.writestr(
                "BUNDLE-METADATA/com.android.tools.build.debugsymbols/arm64-v8a/libapp.so.sym",
                debug_elf,
            )
        verify_delivery_native_payload_is_stripped("android-aab", [aab])
        linux_archive = root / "wins-vpn-linux-x64.tar.gz"
        with tarfile.open(linux_archive, "w:gz") as archive:
            info = tarfile.TarInfo("lib/libapp.so")
            info.size = len(stripped_elf)
            archive.addfile(info, io.BytesIO(stripped_elf))
            info = tarfile.TarInfo("xray")
            info.size = len(debug_elf)
            archive.addfile(info, io.BytesIO(debug_elf))
        try:
            verify_delivery_native_payload_is_stripped("linux", [linux_archive])
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted DWARF in a Linux native binary.")
        ipa = root / "WinsVPN.ipa"
        with zipfile.ZipFile(ipa, "w") as archive:
            archive.writestr("Payload/Runner.app/Frameworks/App.framework/App", _minimal_macho64(dwarf=False))
            archive.writestr("Payload/Runner.app/Frameworks/libwg-go.dylib", _minimal_macho64(dwarf=True))
        try:
            verify_delivery_native_payload_is_stripped("ios", [ipa])
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted DWARF in an iOS native library.")
        if inspect_native_debug_sections(_minimal_macho64(dwarf=False)) != ("macho", ()):
            raise ObfuscationError("Self-test did not accept a stripped Mach-O.")
        if inspect_native_debug_sections(_minimal_macho64_with_symbol(0x0F)) != ("macho", ()):
            raise ObfuscationError("Self-test rejected a required external Mach-O symbol.")
        if inspect_native_debug_sections(_minimal_macho64_with_symbol(0x0E)) != (
            "macho",
            ("LC_SYMTAB_LOCAL",),
        ):
            raise ObfuscationError("Self-test did not reject a local Mach-O symbol.")
        windows_dir = root / "Release"
        windows_dir.mkdir()
        (windows_dir / "wins_vpn.exe").write_bytes(_minimal_pe(".text", ".rdata"))
        (windows_dir / "flutter_windows.dll").write_bytes(_minimal_pe(".text"))
        verify_delivery_native_payload_is_stripped("windows", [windows_dir])
        (windows_dir / "winnengine.dll").write_bytes(_minimal_pe(".text", ".debug"))
        try:
            verify_delivery_native_payload_is_stripped("windows", [windows_dir])
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted a PE debug section in a Windows native library.")
        pe_codeview = _minimal_pe_with_debug_directory()
        if inspect_native_debug_sections(pe_codeview) != (
            "pe",
            ("PE_DEBUG_DIRECTORY_TYPE_2",),
        ):
            raise ObfuscationError("Self-test did not reject a PE CodeView debug directory.")
        if inspect_native_debug_sections(_minimal_pe_with_debug_directory(16)) != ("pe", ()):
            raise ObfuscationError("Self-test rejected PE reproducible-build metadata.")
        private_map = root / "private-map.zip"
        with zipfile.ZipFile(private_map, "w") as archive:
            archive.writestr("assets/app.js.map", b"{}")
        try:
            verify_release_artifact_hardening("windows", [private_map])
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted a packaged source map.")
        credential = root / "credential.zip"
        with zipfile.ZipFile(credential, "w") as archive:
            archive.writestr("assets/config.txt", b"PrivateKey=" + (b"A" * 44))
        try:
            verify_release_artifact_hardening("windows", [credential])
        except ObfuscationError as error:
            if "remove the credential" not in str(error):
                raise
        else:
            raise ObfuscationError("Self-test accepted an embedded long-lived credential.")
        service_account = root / "service-account.zip"
        with zipfile.ZipFile(service_account, "w") as archive:
            archive.writestr(
                "assets/adc.json",
                b'{"type":"service_account","project_id":"wins-proof",'
                b'"client_email":"proof@wins-proof.iam.gserviceaccount.com"}',
            )
        try:
            verify_release_artifact_hardening("windows", [service_account])
        except ObfuscationError as error:
            if "google_service_account_json" not in str(error):
                raise
        else:
            raise ObfuscationError("Self-test accepted packaged service-account JSON.")
        named_sa = root / "named-sa.zip"
        with zipfile.ZipFile(named_sa, "w") as archive:
            archive.writestr(
                "google-service-account.json", b'{"project_id":"wins-proof"}'
            )
        try:
            verify_release_artifact_hardening("windows", [named_sa])
        except ObfuscationError as error:
            if "google_service_account_json" not in str(error):
                raise
        else:
            raise ObfuscationError(
                "Self-test accepted a packaged service-account JSON filename."
            )
        activation = root / "activation.zip"
        with zipfile.ZipFile(activation, "w") as archive:
            archive.writestr(
                "assets/config.bin",
                b'activation_secret="one-time-enrollment-secret-value-001"',
            )
        try:
            verify_release_artifact_hardening("windows", [activation])
        except ObfuscationError as error:
            if "activation_secret" not in str(error):
                raise
        else:
            raise ObfuscationError("Self-test accepted a packaged activation secret.")
        public_runtime = root / "public-runtime.zip"
        public_runtime_pins = (
            b"const String kSpkiWinsvpnOrgWildcard = "
            b"'H6Mj7DsLr6FAGUz4jLll4sc9AXDe3XcOsv4qWwUzY98=';\n"
            b"const String kReviewedAnnouncementPubkeyA1 = "
            b"'d9hwDSlQpYvnph33NJFHAbOm3hKR1wWEhC/kFiNoeoo=';\n"
            b"-----BEGIN PUBLIC KEY-----\n"
            b"MIIBfixturepublickeynotasecretXX\n"
            b"-----END PUBLIC KEY-----\n"
        )
        with zipfile.ZipFile(public_runtime, "w") as archive:
            archive.writestr("assets/pins.dart", public_runtime_pins)
        # Allowed public material must not go through
        # verify_release_artifact_hardening here: that path loads the
        # root-authorized inventory after blob scans and fails closed when
        # the inventory is absent. Negative credential cases fail earlier.
        _verify_release_artifact_hardening_blobs("windows", [public_runtime])
        r8_dir = root / "r8-evidence"
        r8_dir.mkdir()
        (r8_dir / "proguard-mapping.txt").write_bytes(
            b"# compiler: R8\n" + (b"com.example.Keep -> a:\n" * 160)
        )
        r8_records = inspect_r8_mapping(r8_dir, root)
        if not r8_records or r8_records[0]["path"] != "proguard-mapping.txt":
            raise ObfuscationError("Self-test did not accept a phone/TV R8 mapping receipt.")
        if not _receipt_verification("android-apk").get("private_r8_mapping_verified"):
            raise ObfuscationError("Self-test omitted the Android R8 mapping receipt claim.")
        if not _receipt_verification("ios").get("apple_dsym_separated"):
            raise ObfuscationError("Self-test omitted the Apple dSYM separation receipt claim.")
        if not _receipt_verification("windows").get("windows_pdb_separated"):
            raise ObfuscationError("Self-test omitted the Windows PDB separation receipt claim.")
        if not _receipt_verification("linux").get("linux_split_dwarf_required"):
            raise ObfuscationError("Self-test omitted the Linux split-DWARF receipt claim.")
        public_symbols = root / "public-symbols.zip"
        with zipfile.ZipFile(public_symbols, "w") as archive:
            archive.writestr(
                "assets/abi.txt",
                b"\n".join(sorted(REQUIRED_PUBLIC_PLATFORM_SYMBOLS)),
            )
        _verify_release_artifact_hardening_blobs("windows", [public_symbols])
        leaked_internal = root / "leaked-internal.zip"
        with zipfile.ZipFile(leaked_internal, "w") as archive:
            archive.writestr(
                "lib/arm64-v8a/classes.bin",
                b"prefix WinnV3StagedStart suffix",
            )
        try:
            verify_release_artifact_hardening("windows", [leaked_internal])
        except ObfuscationError as error:
            if "sensitive internal class identifier" not in str(error):
                raise
        else:
            raise ObfuscationError("Self-test accepted a leaked internal class identifier.")
        utf16_leak = root / "utf16-internal.zip"
        with zipfile.ZipFile(utf16_leak, "w") as archive:
            archive.writestr(
                "assets/config.bin",
                "protectOrRollback".encode("utf-16-le"),
            )
        try:
            verify_release_artifact_hardening("windows", [utf16_leak])
        except ObfuscationError as error:
            if "sensitive internal method identifier" not in str(error):
                raise
        else:
            raise ObfuscationError(
                "Self-test accepted a UTF-16 leaked internal method identifier."
            )
        apk_magic = APK_SIG_BLOCK_MAGIC
        pair = struct.pack("<I", 0x7109871A) + b"ok-signature"
        pair_record = struct.pack("<Q", len(pair)) + pair
        size = len(pair_record) + 24
        clean_block = (
            struct.pack("<Q", size) + pair_record + struct.pack("<Q", size) + apk_magic
        )
        clean_zip_bytes = (root / "public-symbols.zip").read_bytes()
        with zipfile.ZipFile(io.BytesIO(clean_zip_bytes)) as archive:
            start_dir = archive.start_dir
        eocd = clean_zip_bytes.rfind(b"PK\x05\x06")
        signed_clean = bytearray(
            clean_zip_bytes[:start_dir] + clean_block + clean_zip_bytes[start_dir:]
        )
        struct.pack_into(
            "<I", signed_clean, eocd + len(clean_block) + 16, start_dir + len(clean_block)
        )
        clean_signed_apk = root / "clean-signing.apk"
        clean_signed_apk.write_bytes(signed_clean)
        _verify_release_artifact_hardening_blobs("windows", [clean_signed_apk])
        leaked_pair = struct.pack("<I", 0x7109871A) + b"WinnV3StagedStart"
        leaked_record = struct.pack("<Q", len(leaked_pair)) + leaked_pair
        leaked_size = len(leaked_record) + 24
        leaked_block = (
            struct.pack("<Q", leaked_size)
            + leaked_record
            + struct.pack("<Q", leaked_size)
            + apk_magic
        )
        leaked_signed = bytearray(
            clean_zip_bytes[:start_dir] + leaked_block + clean_zip_bytes[start_dir:]
        )
        struct.pack_into(
            "<I",
            leaked_signed,
            eocd + len(leaked_block) + 16,
            start_dir + len(leaked_block),
        )
        leaked_apk = root / "leaked-signing.apk"
        leaked_apk.write_bytes(leaked_signed)
        try:
            verify_release_artifact_hardening("windows", [leaked_apk])
        except ObfuscationError as error:
            if "sensitive internal class identifier" not in str(error):
                raise
        else:
            raise ObfuscationError(
                "Self-test accepted an internal identifier in an APK Signing Block."
            )
        bz2_archive = root / "clean.tar.bz2"
        with tarfile.open(bz2_archive, "w:bz2") as archive:
            payload = b"clean"
            info = tarfile.TarInfo("a")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        _verify_release_artifact_hardening_blobs("linux", [bz2_archive])
        trailed_bz2 = root / "trailed.tar.bz2"
        trailed_bz2.write_bytes(bz2_archive.read_bytes() + b"WinnV3StagedStart")
        try:
            list(iter_artifact_blobs(trailed_bz2))
        except ObfuscationError as error:
            if "trailing bytes after its compressed stream" not in str(error):
                raise
        else:
            raise ObfuscationError(
                "Self-test accepted trailing bytes after a bzip2 TAR stream."
            )
        stripped_watch = _minimal_macho64(dwarf=False)
        watch_ipa = root / "WinsVPN-watch.ipa"
        with zipfile.ZipFile(watch_ipa, "w") as archive:
            archive.writestr(
                "Payload/Runner.app/Frameworks/App.framework/App", stripped_watch
            )
            archive.writestr(
                "Payload/Runner.app/Watch/WinsWatch.app/WinsWatch", stripped_watch
            )
        verify_embedded_watchos_companion("ios", [watch_ipa])
        _verify_release_artifact_hardening_blobs("ios", [watch_ipa])
        no_watch = root / "WinsVPN-nowatch.ipa"
        with zipfile.ZipFile(no_watch, "w") as archive:
            archive.writestr(
                "Payload/Runner.app/Frameworks/App.framework/App", stripped_watch
            )
        try:
            verify_embedded_watchos_companion("ios", [no_watch])
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted an iOS IPA without watchOS.")
        foreign_js = b"const ok=true;function start(){return 1;}"
        foreign_zip = root / "foreign-extension.zip"
        with zipfile.ZipFile(foreign_zip, "w") as archive:
            archive.writestr("background.js", foreign_js)
        try:
            verify_extension_javascript_hardening("chrome", [foreign_zip])
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError(
                "Self-test accepted compact foreign JavaScript as store minification."
            )
        producer_zip = _write_producer_extension_zip(
            root / "wins-vpn-companion-chrome.zip", "chrome"
        )
        verify_extension_javascript_hardening("chrome", [producer_zip])
        _verify_release_artifact_hardening_blobs("chrome", [producer_zip])
        pretty_zip = root / "pretty-extension.zip"
        with zipfile.ZipFile(pretty_zip, "w") as archive:
            archive.writestr(
                "background.js",
                b"function start() {\n  const ok = true;\n  return ok;\n}\n",
            )
        try:
            verify_extension_javascript_hardening("chrome", [pretty_zip])
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted unminified extension JavaScript.")
        obfuscated_zip = root / "obfuscated-extension.zip"
        with zipfile.ZipFile(obfuscated_zip, "w") as archive:
            archive.writestr("background.js", b"var _0xabcd=function(){return 1;}")
        try:
            verify_extension_javascript_hardening("chrome", [obfuscated_zip])
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted obfuscated extension JavaScript.")
        try:
            contained(root / "absent-receipt.json", root)
        except ObfuscationError:
            pass
        else:
            raise ObfuscationError("Self-test accepted a missing authenticated receipt.")
    print("RELEASE OBFUSCATION SELF-TEST: PASS")


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv[:1] == ["--verify"]:
        if len(raw_argv) != 3:
            raise ObfuscationError(
                "canonical cross-store usage is exactly --verify <target-id> <artifact-path>"
            )
        if raw_argv[1] in ANDROID_CROSS_STORE_TARGETS:
            canonical_android_gate_verify(raw_argv[1], raw_argv[2])
        elif raw_argv[1] in WEAR_CROSS_STORE_TARGETS:
            canonical_wear_gate_verify(raw_argv[1], raw_argv[2])
        elif raw_argv[1] in WINDOWS_CROSS_STORE_TARGETS:
            canonical_windows_gate_verify(raw_argv[1], raw_argv[2])
        elif (
            raw_argv[1] in LINUX_PACKAGE_CROSS_STORE_TARGETS
            or raw_argv[1] in LINUX_MANIFEST_CROSS_STORE_TARGETS
        ):
            canonical_linux_gate_verify(raw_argv[1], raw_argv[2])
        elif raw_argv[1] in EXTENSION_CROSS_STORE_TARGETS:
            canonical_extension_gate_verify(raw_argv[1], raw_argv[2])
        elif raw_argv[1] in APPLE_CROSS_STORE_TARGETS:
            canonical_apple_gate_verify(raw_argv[1], raw_argv[2])
        else:
            raise ObfuscationError(
                f"unsupported exact hardening target: {raw_argv[1]}"
            )
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("record", "verify", "static", "self-test"))
    parser.add_argument(
        "--platform",
        choices=(
            "android-apk",
            "android-aab",
            "wear-os",
            "windows",
            "linux",
            "ios",
            "macos",
            "chrome",
            "edge",
            "firefox",
        ),
    )
    parser.add_argument("--symbols-dir")
    parser.add_argument("--manifest")
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--target-id", dest="target_id")
    parser.add_argument(
        "--defer-secret-scan-to-release-host",
        dest="defer_secret_scan",
        help="REMOTE_INPUT.json of a remote-attested Windows build: the release host "
             "runs the exact secret scan at finish-build",
    )
    args = parser.parse_args(raw_argv)
    if args.command == "static":
        validate_static()
        return 0
    if args.command == "self-test":
        self_test()
        return 0
    if not args.platform or not args.symbols_dir or not args.manifest or not args.artifact:
        parser.error("record/verify require --platform, --symbols-dir, --manifest, and --artifact")
    artifacts = [pathlib.Path(value) for value in args.artifact]
    manifest = pathlib.Path(args.manifest)
    deferral = (
        None if args.defer_secret_scan is None else pathlib.Path(args.defer_secret_scan)
    )
    if args.command == "record":
        record(
            args.platform,
            pathlib.Path(args.symbols_dir),
            manifest,
            artifacts,
            args.target_id,
            deferral,
        )
    else:
        verify(
            args.platform,
            manifest,
            pathlib.Path(args.symbols_dir),
            artifacts,
            args.target_id,
            deferral,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ObfuscationError as exc:
        print(f"RELEASE OBFUSCATION: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
