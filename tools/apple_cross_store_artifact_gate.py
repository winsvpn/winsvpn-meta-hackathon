#!/usr/bin/env python3
"""Offline, artifact-only verification helpers for Apple cross-store gates."""

from __future__ import annotations

import __future__ as future
import argparse
import builtins
import contextlib
import contextvars
import ctypes
import datetime
import errno
import fcntl
import functools
import hashlib
import io
import json
import os
import pathlib
import platform
import plistlib
import re
import resource
import secrets
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import typing
import unicodedata
import uuid
import zipfile
from collections.abc import Mapping
from types import ModuleType


_REVIEWED_ORIGIN_ROOT = globals().get("__winsvpn_reviewed_origin_root__")
_REVIEWED_TOOLS_DIR = globals().get("__winsvpn_reviewed_tools_dir__")
if (_REVIEWED_ORIGIN_ROOT is None) != (_REVIEWED_TOOLS_DIR is None):
    raise RuntimeError("reviewed Apple helper root injection is incomplete")
if _REVIEWED_ORIGIN_ROOT is None:
    ORIGIN_ROOT = pathlib.Path(__file__).resolve().parents[1]
    TOOLS_DIR = pathlib.Path(__file__).resolve().parent
else:
    if type(_REVIEWED_ORIGIN_ROOT) is not str or type(_REVIEWED_TOOLS_DIR) is not str:
        raise RuntimeError("reviewed Apple helper root injection is malformed")
    ORIGIN_ROOT = pathlib.Path(_REVIEWED_ORIGIN_ROOT)
    TOOLS_DIR = pathlib.Path(_REVIEWED_TOOLS_DIR)
    if (
        not ORIGIN_ROOT.is_absolute()
        or TOOLS_DIR != ORIGIN_ROOT / "tools"
        or pathlib.Path(__file__) != TOOLS_DIR / "apple_cross_store_artifact_gate.py"
    ):
        raise RuntimeError("reviewed Apple helper root injection is not exact")
ROOT = ORIGIN_ROOT
TEAM_ID = "5YT8H4U72M"
OWNER_COMMON_NAME = "Win's VPN Inc"
APPLE_DISTRIBUTION_LEAF_OID = "1.2.840.113635.100.6.1.7"
APPLE_WWDR_INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1"
DEVELOPER_ID_APPLICATION_LEAF_OID = "1.2.840.113635.100.6.1.13"
DEVELOPER_ID_INSTALLER_LEAF_OID = "1.2.840.113635.100.6.1.14"
DEVELOPER_ID_CA_OID = "1.2.840.113635.100.6.2.6"
MAC_APP_STORE_INSTALLER_PREFIX = "3rd Party Mac Developer Installer:"
DEVELOPER_ID_INSTALLER_PREFIX = "Developer ID Installer:"
# pkgutil reports a Mac App Store installer signature (3rd Party Mac Developer Installer)
# as "(Development)"; "for distribution" is its wording for Developer ID Installer, which
# the leaf check below refuses for this route.
APP_STORE_INSTALLER_STATUS = (
    "status: signed by a developer certificate issued by apple (development)"
)
# pkgutil and codesign format times with ICU's narrow no-break space (U+202F) before
# AM/PM under every locale, including the C locale this gate sets: pkgutil's certificate
# "Expires:" lines and codesign's "Signed Time=" / "Timestamp=" lines. Only those exact
# date-time shapes are normalized; any other non-ASCII text is still refused.
ICU_TIME_LINES = (
    re.compile(
        r"^(\s+Expires: \d{4}-\d{2}-\d{2} \d{1,2}:\d{2}:\d{2})\u202f((?:AM|PM) \+0000)$"
    ),
    re.compile(
        r"^((?:Signed Time|Timestamp)=(?:\d{1,2} [A-Z][a-z]{2} \d{4}|[A-Z][a-z]{2} \d{1,2}, \d{4})"
        r" at \d{1,2}:\d{2}:\d{2})\u202f((?:AM|PM))$"
    ),
)


def _normalize_icu_time_spacing(output: object) -> object:
    if type(output) is not str:
        return output
    lines = []
    for line in output.split("\n"):
        for pattern in ICU_TIME_LINES:
            line = pattern.sub(r"\1 \2", line)
        lines.append(line)
    return "\n".join(lines)
QUARANTINE_NAME_PREFIX = ".wins-gate-quarantine."
HOST_BUNDLE_ID = "org.winsvpn.app"
TUNNEL_BUNDLE_ID = "org.winsvpn.app.PacketTunnel"
WATCH_BUNDLE_ID = "org.winsvpn.app.watchkitapp"
WATCH_EXECUTABLE = "WinsWatch"
WATCH_CONNECTIVITY_DEPENDENCY = (
    "/System/Library/Frameworks/WatchConnectivity.framework/WatchConnectivity"
)
WATCH_WC_SESSION_IMPORT = "_OBJC_CLASS_$_WCSession"
# Exactly sorted(apple_watch_artifact_verifier.REQUIRED_SELECTORS), the list the
# verifier reports; this gate pins that verifier's source digest.
WATCH_REQUIRED_SELECTORS = (
    "activationState",
    "isReachable",
    "receivedApplicationContext",
    "sendMessage:replyHandler:errorHandler:",
    "session:activationDidCompleteWithState:error:",
    "session:didReceiveApplicationContext:",
    "session:didReceiveMessage:",
    "sessionReachabilityDidChange:",
)
PRIVACY_FILE_TIMESTAMP_API = "NSPrivacyAccessedAPICategoryFileTimestamp"
PRIVACY_USER_DEFAULTS_API = "NSPrivacyAccessedAPICategoryUserDefaults"
PRIVACY_SYSTEM_BOOT_TIME_API = "NSPrivacyAccessedAPICategorySystemBootTime"
HOST_PRIVACY_API_REASONS = {
    PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
    PRIVACY_USER_DEFAULTS_API: frozenset({"CA92.1"}),
    PRIVACY_SYSTEM_BOOT_TIME_API: frozenset({"35F9.1"}),
}
TUNNEL_PRIVACY_API_REASONS = {
    PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
    PRIVACY_SYSTEM_BOOT_TIME_API: frozenset({"35F9.1"}),
}
FLUTTER_IOS_PRIVACY_API_REASONS = {
    PRIVACY_FILE_TIMESTAMP_API: frozenset({"0A2A.1", "C617.1"}),
    PRIVACY_SYSTEM_BOOT_TIME_API: frozenset({"35F9.1"}),
}
HOST_PRIVACY_COLLECTED_TYPES = frozenset(
    {
        "NSPrivacyCollectedDataTypeCoarseLocation",
        "NSPrivacyCollectedDataTypeDeviceID",
        "NSPrivacyCollectedDataTypeUserID",
        "NSPrivacyCollectedDataTypeProductInteraction",
    }
)
PRIVACY_APP_FUNCTIONALITY_PURPOSE = (
    "NSPrivacyCollectedDataTypePurposeAppFunctionality"
)
CANONICAL_RELEASE = "1.0.17+34"
CANONICAL_MARKETING_VERSION = "1.0.17"
CANONICAL_BUNDLE_VERSION = "34"
PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION = 2
PACKAGE_UPLOAD_RECEIPT_CONTRACT = "winsvpn-apple-package-upload-receipt-v2"
OWNER_AUTHORIZATION_CONTRACT = "winsvpn-apple-owner-authorization-v2"
RELEASE_IDENTITY_RELATIVE_PATH = pathlib.Path(
    "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
)
TARGET_SUFFIXES = {
    "ios-app-store-ipa": (".ipa",),
    "macos-app-store-pkg": (".pkg",),
    "macos-developer-id-app": (".app.zip",),
}
REQUIRED_APPLE_UPLOAD_TARGETS = ("ios-app-store-ipa", "macos-app-store-pkg")
OPTIONAL_APPLE_UPLOAD_TARGETS = ("macos-developer-id-app",)
REQUIRED_APPLE_ARTIFACTS = (
    "ios_app_store_ipa_with_embedded_watchos",
    "macos_app_store_pkg",
)
OPTIONAL_APPLE_DISTRIBUTION = ("macos_developer_id",)
APPLE_SHIPPING_SURFACES = ("ios", "watchos", "macos")
TVOS_NOT_A_CURRENT_SURFACE = (
    "tvOS is not a 1.0.17+34 shipping, upload, signing, or receipt surface"
)
WATCHOS_NOT_A_SEPARATE_TARGET = (
    "watchOS is embedded in the iOS IPA and is not a separate 1.0.17+34 upload target"
)
FORBIDDEN_TVOS_IDENTITY_TOKENS = frozenset(
    {"tvos", "appletvos", "apple-tv", "apple_tv", "tv"}
)
REQUIRED_IOS_ARCHITECTURES = ("arm64",)
REQUIRED_MACOS_ARCHITECTURES = ("arm64", "x86_64")
PACKAGE_UPLOAD_RECEIPT_KEYS = frozenset(
    {
        "ok",
        "schema_version",
        "contract",
        "release",
        "target_id",
        "platform",
        "artifact",
        "build_receipt",
        "producer",
        "bundle_ids",
        "architectures",
        "signing",
        "store_evidence",
        "descriptor",
        "source_freeze",
        "obfuscation_privacy",
        "publication_authorized",
        "upload_attempted",
        "owner_authorization",
        "authentication",
    }
)
IOS_PACKAGE_UPLOAD_RECEIPT_KEYS = PACKAGE_UPLOAD_RECEIPT_KEYS | {"watchos"}
BUILD_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "release",
        "platform",
        "begun_utc",
        "finished_utc",
        "build_begin_receipt",
        "build_attempt",
        "release_input_index",
        "platform_manifest",
        "shared_revision",
        "producer",
        "toolchain",
        "source_freeze",
        "toolchain_custody",
        "artifact",
        "sha256_anchor",
        "publication_authorized",
    }
)
BUILD_ATTEMPT_KEYS = frozenset(
    {
        "contract",
        "nonce",
        "directory",
        "directory_identity",
        "artifacts_directory_identity",
        "begin_receipt",
        "claim_sha256",
        "commit_journal_sha256",
        "claim_record",
        "commit_record",
    }
)
DESCRIPTOR_RELATIVE = "tools/apple_cross_store_artifact_gate.py"
OBFUSCATION_PRIVACY_RELATIVE = "tools/release_obfuscation_contract.py"
WATCH_ARTIFACT_VERIFIER_RELATIVE = "tools/apple_watch_artifact_verifier.py"
PRODUCER_RELATIVE = "tools/apple_runtime_smoke.sh"
HELD_ARTIFACT_CONTRACT = "winsvpn-apple-held-release-artifact-v1"
MACOS_INDEPENDENT_VERIFIER_CONTRACT = (
    "winsvpn-macos-app-store-independent-verification-v1"
)
HELD_ARTIFACT_REVIEW_SOURCES = (
    ("verify_macos_release_artifact.py", "macos_release_artifact_verifier"),
    ("test_verify_macos_release_artifact.py", "macos_release_artifact_verifier_test"),
    ("apple_watch_artifact_verifier.py", "watch_artifact_verifier"),
)
HELD_ARTIFACT_REVIEW_SOURCE_SHA256 = {
    "verify_macos_release_artifact.py": (
        "167360ffaf608c088bc5f5c060f4756d2b05c12ddd9bcd7ebdb19a9bf531d746"
    ),
    "test_verify_macos_release_artifact.py": (
        "57f4df2a5313f42838696c389e101c06dccaa077d9204ac43c8151b9b46d468a"
    ),
    "apple_watch_artifact_verifier.py": (
        "9282c14eb209d3639ba6f50f6d884e6ea809ec62ad04dacdd4225343637baeb2"
    ),
}
UNIQUE_UPLOAD_RECEIPT_DIGEST_FIELDS = ("artifact", "build_receipt")
SHARED_UPLOAD_RECEIPT_PATH_FIELDS = (
    "producer",
    "descriptor",
    "source_freeze",
    "obfuscation_privacy",
)
UPLOAD_RECEIPT_ISSUER = "winsvpn-apple-package-upload-receipt"
UPLOAD_RECEIPT_JOURNAL_RELATIVE = ".artifacts/upload-receipt-journal/apple.jsonl"
UPLOAD_RECEIPT_JOURNAL_SCHEMA = "winsvpn-apple-upload-receipt-journal-v1"
UPLOAD_RECEIPT_MAX_AGE_SECONDS = 300
UPLOAD_RECEIPT_FUTURE_SKEW_SECONDS = 30
UPLOAD_RECEIPT_AUTH_KEYS = frozenset(
    {
        "authenticated",
        "issuer",
        "run_id",
        "nonce",
        "issued_at",
        "challenge",
        "target_id",
        "architectures",
        "release",
        "artifact_sha256",
        "artifact_bytes",
    }
)
UPLOAD_RECEIPT_JOURNAL_AUTH_KEYS = frozenset(
    {"schema", "kind", *UPLOAD_RECEIPT_AUTH_KEYS}
)
UPLOAD_RECEIPT_JOURNAL_TRANSACTION_KEYS = frozenset(
    {"schema", "kind", "transaction_id", "committed", "authentications"}
)
UPLOAD_RECEIPT_PLACEHOLDER_TRUST_MARKERS = (
    "placeholder",
    "ed25519privatekey",
    "ed25519publickey",
)
RECEIPT_REPLAY_ERROR = (
    "Apple package/upload receipt nonce or run_id was already consumed"
)
RECEIPT_STALE_ERROR = "Apple package/upload receipt is not fresh"
RECEIPT_UNAUTHENTICATED_ERROR = (
    "Apple package/upload receipt is not authenticated by the trusted issuer"
)
RECEIPT_PLACEHOLDER_TRUST_ERROR = (
    "Apple package/upload receipt trust key is a placeholder"
)
_LIVE_INODES: contextvars.ContextVar[dict[tuple[int, int], str] | None] = (
    contextvars.ContextVar("_LIVE_INODES", default=None)
)
_LIVE_REPO_FILES: contextvars.ContextVar[dict[str, object] | None] = (
    contextvars.ContextVar("_LIVE_REPO_FILES", default=None)
)
_UPLOAD_RECEIPT_JOURNAL_CUSTODY: contextvars.ContextVar[object | None] = (
    contextvars.ContextVar("_UPLOAD_RECEIPT_JOURNAL_CUSTODY", default=None)
)
_ACTIVE_HELD_EVIDENCE_KEYS: set[tuple[object, ...]] = set()
_ACTIVE_HELD_EVIDENCE_LOCK = threading.Lock()
APPLE_PACKAGE_UPLOAD_TARGETS = {
    "ios-app-store-ipa": {
        "platform": "ios",
        "required": True,
        "build_receipt_target": "app-store-connect",
        "signing_contract": "apple-distribution",
        "expected_authority": "Authority=Apple Distribution:",
        "store_surface": "apple-app-store-iphone-watch",
        "architectures": REQUIRED_IOS_ARCHITECTURES,
        "bundle_ids": {
            "host": HOST_BUNDLE_ID,
            "tunnel": TUNNEL_BUNDLE_ID,
            "watch": WATCH_BUNDLE_ID,
        },
        "testflight": "not_uploaded",
        "app_store": "not_uploaded",
        "notarization": None,
    },
    "macos-app-store-pkg": {
        "platform": "macos",
        "required": True,
        "build_receipt_target": "app-store-connect",
        "signing_contract": "apple-distribution",
        "expected_authority": "Authority=Apple Distribution:",
        "store_surface": "mac-app-store",
        "architectures": REQUIRED_MACOS_ARCHITECTURES,
        "bundle_ids": {
            "host": HOST_BUNDLE_ID,
            "tunnel": TUNNEL_BUNDLE_ID,
        },
        "testflight": None,
        "app_store": "not_uploaded",
        "notarization": None,
    },
    "macos-developer-id-app": {
        "platform": "macos",
        "required": False,
        "build_receipt_target": "developer-id",
        "signing_contract": "developer-id-application",
        "expected_authority": "Authority=Developer ID Application:",
        "store_surface": "developer-id",
        "architectures": REQUIRED_MACOS_ARCHITECTURES,
        "bundle_ids": {
            "host": HOST_BUNDLE_ID,
            "tunnel": TUNNEL_BUNDLE_ID,
        },
        "testflight": None,
        "app_store": None,
        "notarization": "Notarized Developer ID",
    },
}
REVIEWED_APPLE_TOOLS = frozenset(
    {
        "/usr/bin/codesign",
        "/usr/bin/ditto",
        "/usr/bin/lipo",
        "/usr/bin/nm",
        "/usr/bin/xcrun",
        "/usr/sbin/pkgutil",
        "/usr/sbin/spctl",
    }
)
# /usr/bin/lipo, /usr/bin/nm and /usr/bin/xcrun on the SSV are xcrun shims: they
# find the real Xcode tool through a per-user cache keyed by HOME and, on a miss,
# spawn xcodebuild to fill it. The gate's private HOME always misses, so the
# no-fork boundary refuses that spawn ("couldn't spawn ... xcodebuild", exit 71)
# and, without the boundary, the 1 MiB file cap kills the cache rewrite (SIGXFSZ,
# exit -25). One unconfined `xcrun --find <tool>` per tool and environment fills
# the cache entry first, so the confined inspection never spawns or writes.
# Xcode 27's otool is llvm-otool, which forks llvm-objdump; the gate runs the
# single-process otool-classic through xcrun instead (same -l and -hv output).
XCRUN = "/usr/bin/xcrun"
XCRUN_SHIM_TOOLS = {"/usr/bin/lipo": "lipo", "/usr/bin/nm": "nm"}
XCRUN_RUN_TOOLS = frozenset({"otool-classic"})
_XCRUN_WARMED: set[tuple[str, str, str]] = set()
MACOS_DESCENDANT_BOUNDARY = "/usr/bin/sandbox-exec"
MACOS_DESCENDANT_BOUNDARY_PROFILE = (
    "(version 1)(allow default)(deny process-fork)"
)
REVIEWED_EXECUTION_BOUNDARIES = frozenset({MACOS_DESCENDANT_BOUNDARY})
VOLFS_ARGV_TOOLS = frozenset(
    {
        "/usr/bin/lipo",
        "/usr/bin/nm",
        "/usr/bin/xcrun",
        "/usr/sbin/pkgutil",
        "/usr/sbin/spctl",
    }
)
NON_VOLFS_ARGV_TOOLS = frozenset(
    {
        "/usr/bin/codesign",
        "/usr/bin/ditto",
    }
)
INSPECT_DIR_PREFIX = ".wins-gate-inspect."
INSPECT_HELD_NAME = "held"
QUARANTINE_HELD_NAME = "held"
if VOLFS_ARGV_TOOLS & NON_VOLFS_ARGV_TOOLS:
    raise RuntimeError("Apple volfs and non-volfs tool sets overlap")
if VOLFS_ARGV_TOOLS | NON_VOLFS_ARGV_TOOLS != REVIEWED_APPLE_TOOLS:
    raise RuntimeError("Apple reviewed tools must be split between volfs and sealed inspect")
REQUIRED_MODULE_FILES = (
    ("release_secret_scan_policy.py", "release_secret_scan_policy"),
    ("release_source_freeze.py", "release_source_freeze"),
    ("apple_release_contamination_gate.py", "apple_release_contamination_gate"),
    ("release_obfuscation_contract.py", "release_obfuscation_contract"),
)
SYSTEM_VERSION_COMPONENTS = (
    "System",
    "Library",
    "CoreServices",
    "SystemVersion.plist",
)
SF_RESTRICTED = getattr(stat, "SF_RESTRICTED", 0x00080000)
UF_IMMUTABLE = getattr(stat, "UF_IMMUTABLE", 0)
UF_APPEND = getattr(stat, "UF_APPEND", 0)
UF_NOUNLINK = getattr(stat, "UF_NOUNLINK", 0)
ZIP_UNLINK_BLOCKING_USER_FLAGS = UF_IMMUTABLE | UF_APPEND | UF_NOUNLINK
MNT_RDONLY = 0x00000001
MAX_SUPPORT_BYTES = 8 * 1024 * 1024
MAX_SYSTEM_VERSION_BYTES = 64 * 1024
REVIEWED_SUBPROCESS_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
INNER_PAYLOAD_SCHEMA = "winsvpn-macos-app-store-pkg-inner-payload-v3"
ALLOWED_MACHO_ARCHITECTURES = frozenset({"arm64", "x86_64"})
REQUIRED_MACHO_ARCHITECTURE = "arm64"
REQUIRED_AOT_ARCHITECTURES = frozenset({"arm64", "x86_64"})
REQUIRED_NATIVE_HOST_ARCHITECTURES = frozenset({"arm64", "x86_64"})
# Owner ruling 2026-10-16: for release line 1.0.16 the macOS native-messaging
# companion ships for Apple silicon only. The release Mac has an arm64-only
# Dart SDK and no Rosetta, so no x86_64 slice can be built there. The ruling
# carries over to release line 1.0.17 (owner rulings carried to the 1.0.17
# release, relayed by the coordinator 2026-11-02). The exception names these
# release lines only; every other release still requires the universal
# arm64+x86_64 executable.
NATIVE_HOST_ARM64_ONLY_OWNER_RULING_DATE = "2026-10-16"
NATIVE_HOST_ARM64_ONLY_RELEASE_LINES = frozenset({"1.0.16", "1.0.17"})
NATIVE_HOST_ARM64_ONLY_ARCHITECTURES = frozenset({"arm64"})
NATIVE_HOST_BASENAME = "wins_bridge_host"
NATIVE_HOST_JSON_NAME = "org.winsvpn.bridge"
NATIVE_HOST_JSON_DESCRIPTION = "Win's VPN browser bridge"
FIREFOX_NATIVE_EXTENSION_ID = "companion@winsvpn.org"
MACOS_NATIVE_HOST_SYSTEM_PATH = (
    "/Library/Application Support/Win's VPN/NativeMessagingHost/wins_bridge_host"
)
OPTIONAL_NATIVE_HOST_SOURCE = "tools/native_messaging/manifests/store_ids.json"
MACOS_NATIVE_HOST_EXTRA_SOURCES = (
    "tools/native_messaging/build_native_host.sh",
    "tools/native_messaging/install_macos_native_host.sh",
)
# Reviewed digest of compute_macos_native_host_source_closure() over the 17
# native-host inputs as they are now (store_ids.json included). Any host source,
# lockfile, installer, manifest or store-id change is a plain refusal until the
# changed inputs are reviewed and this pin is updated in the same change.
MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256 = (
    "65cd7fd153953a4b44468d8d319eec8bc2af3e936d333245adf84bf6466d6f7e"
)
CHROMIUM_EXTENSION_ID = re.compile(r"^[a-p]{32}$")
DEVELOPER_ID_APPLICATION_AUTHORITY = "Authority=Developer ID Application:"
APP_STORE_DISTRIBUTION_AUTHORITY = "Authority=Apple Distribution:"
MACOS_PACKAGE_CHANNEL_CONTRACT = {
    "macos-app-store-pkg": {
        "channel": "mac-app-store",
        "signing_contract": "apple-distribution",
        "expected_authority": APP_STORE_DISTRIBUTION_AUTHORITY,
        "required": True,
    },
    "macos-developer-id-app": {
        "channel": "developer-id",
        "signing_contract": "developer-id-application",
        "expected_authority": DEVELOPER_ID_APPLICATION_AUTHORITY,
        "required": False,
    },
}
MACOS_NATIVE_MESSAGING_INCOMPATIBILITY_REASONS = (
    "The shipping macOS app is sandboxed with com.apple.security.app-sandbox.",
    "Chrome and Firefox launch the native-messaging host themselves, so the "
    "binary must live outside that sandbox and outside TCC-protected folders.",
    "Inner payload schema winsvpn-macos-app-store-pkg-inner-payload-v3 allows "
    "exactly the host app and PacketTunnel; extra helpers are not an allowed "
    "Payload.",
    "Mac App Store installation cannot register native-messaging manifests into "
    "Chrome or Firefox NativeMessagingHosts directories.",
)
MACOS_NATIVE_MESSAGING_INCOMPATIBILITY = (
    "macOS App Store cannot deliver wins_bridge_host outside the sandboxed app: "
    + " ".join(MACOS_NATIVE_MESSAGING_INCOMPATIBILITY_REASONS)
)
BUNDLE_SUFFIXES = (".appex", ".app")
VOLFS_ROOT = pathlib.Path("/.vol")
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
# The pinned Flutter 3.47.6 engine (FlutterMacOS, Flutter.framework) resolves only
# these two AOT snapshot symbols; the four kDartVm/kDartIsolate names of older
# engines are absent from it and from the App.framework/App it builds.
FLUTTER_AOT_SYMBOLS = (
    "_kDartSnapshotData",
    "_kDartSnapshotText",
)
NM_DEBUG_SYMBOL_TYPES = frozenset(
    {
        "BNSYM",
        "ENSYM",
        "FUN",
        "GSYM",
        "LCSYM",
        "OSO",
        "SLINE",
        "SO",
        "SOL",
        "STSYM",
    }
)
PRIVATE_SYMBOL_SUFFIXES = (
    ".bcsymbolmap",
    ".dbg",
    ".debug",
    ".dsym",
    ".dwo",
    ".dwp",
    ".map",
    ".pdb",
    ".sym",
    ".symbols",
)
ENGINE_COMPONENT_BY_NAME = {
    "WinsAmneziaWGPacketEngine.framework": "amneziawg_packet_engine",
    "libWinsAmneziaWGPacketEngine.dylib": "amneziawg_packet_engine",
    "WinsXrayVlessWsTransport.framework": "xray_vless_ws_transport",
    "libWinsXrayVlessWsTransport.dylib": "xray_vless_ws_transport",
    "WinsWinnPacketEngine.framework": "winn_packet_engine",
    "libWinsWinnPacketEngine.dylib": "winn_packet_engine",
}
AWG_ENGINE_COMPONENTS = frozenset(
    {"amneziawg_packet_engine", "xray_vless_ws_transport"}
)
# Provenance field beside "sha256" in each macOS wrapper record: the engine
# digest after its code signature is normalized away (see
# _signature_normalized_sha256 and the macOS verifier's helper of the same name).
SIGNATURE_NORMALIZED_FIELD = "signature_normalized_sha256"
REVIEWED_AWG_SOURCE = {
    "commit": "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d",
    "generation": "3.1",
    "tag": "v3.1.20260814",
}
MACOS_BUNDLE_ALLOWLIST = {
    HOST_BUNDLE_ID: {
        "role": "host",
        "suffix": ".app",
        "privacy": "Contents/Resources/PrivacyInfo.xcprivacy",
        "info": "Contents/Info.plist",
    },
    TUNNEL_BUNDLE_ID: {
        "role": "tunnel",
        "suffix": ".appex",
        "privacy": "Contents/Resources/PrivacyInfo.xcprivacy",
        "info": "Contents/Info.plist",
    },
}
MACHO_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }
)
FAT_ENDIAN = {
    b"\xca\xfe\xba\xbe": ">",
    b"\xca\xfe\xba\xbf": ">",
    b"\xbe\xba\xfe\xca": "<",
    b"\xbf\xba\xfe\xca": "<",
}
FAT_64 = {b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
MAX_PKG_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_INNER_FILE_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_ENTRIES = 200_000
MAX_EXPANDED_DEPTH = 40
MAX_PATH_BYTES = 1024
MAX_SYMLINKS = 4_096
MAX_HARDLINKS = 0
MAX_SPECIAL_FILES = 0
MAX_SYMLINK_TARGET_BYTES = 4_096
MAX_COMPRESSION_RATIO = 64
MAX_OUTPUT_BYTES = MAX_EXPANDED_BYTES
FREE_SPACE_MARGIN_BYTES = 64 * 1024 * 1024
TOOL_TIMEOUT_SEC = 60
PKGUTIL_EXPAND_TIMEOUT_SEC = 120
PKGUTIL_CPU_SEC = 60
CHILD_NOFILE = 256
MAX_FAILURE_BYTES = 512
MAX_TOOL_OUTPUT_BYTES = 1024 * 1024
MAX_VERIFIER_OUTPUT_BYTES = 1024 * 1024
MAX_RECEIPT_FILE_BYTES = 1024 * 1024
MAX_PLIST_BYTES = 256 * 1024
MAX_INNER_METADATA_BYTES = 64 * 1024
SECRET_ENV_KEY_RE = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|AUTHORIZATION|COOKIE|CREDENTIAL|PRIVATE|AWS_|SSH_)",
    re.IGNORECASE,
)
READ_CHUNK = 1024 * 1024


class _DarwinStatfs(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


_LIBC: ctypes.CDLL | None
try:
    if sys.platform == "darwin":
        _LIBC = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        _LIBC.fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(_DarwinStatfs)]
        _LIBC.fstatfs.restype = ctypes.c_int
        _LIBC.fchflags.argtypes = [ctypes.c_int, ctypes.c_uint]
        _LIBC.fchflags.restype = ctypes.c_int
    else:
        _LIBC = None
except OSError:
    _LIBC = None


class AppleArtifactGateError(RuntimeError):
    """Raised when an Apple release artifact is not independently verifiable."""


class AppleArtifactUnverified(AppleArtifactGateError):
    """Raised when no real signed PKG exists to verify."""


def _owner_environment_blocker(message: str) -> AppleArtifactGateError:
    return AppleArtifactGateError(f"owner/environment blocker: {message}")


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
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


def _pkg_vnode_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_nlink,
        info.st_size,
    )


def _open_flags(*, write: bool = False, exclusive: bool = False) -> int:
    flags = os.O_CLOEXEC | os.O_NOFOLLOW
    if write:
        flags |= os.O_RDWR | os.O_CREAT
        if exclusive:
            flags |= os.O_EXCL
        return flags
    return flags | os.O_RDONLY


def _dir_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if directory == 0:
        raise AppleArtifactGateError("Apple gate requires O_DIRECTORY")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | directory


def _sha256_fd(fd: int, size: int | None = None) -> str:
    digest = hashlib.sha256()
    if size is None:
        offset = 0
        while True:
            block = os.pread(fd, READ_CHUNK, offset)
            if not block:
                return digest.hexdigest()
            digest.update(block)
            offset += len(block)
    remaining = size
    offset = 0
    while remaining:
        block = os.pread(fd, min(READ_CHUNK, remaining), offset)
        if not block:
            raise AppleArtifactGateError("descriptor read was truncated")
        digest.update(block)
        offset += len(block)
        remaining -= len(block)
    extra = os.pread(fd, 1, offset)
    if extra:
        raise AppleArtifactGateError("descriptor grew while it was hashed")
    return digest.hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json_sha256(value: object) -> str:
    return _sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
    )


def _macos_descendant_boundary_argv(argv: list[str]) -> list[str]:
    """Deny descendant creation in-kernel before executing one macOS tool."""

    if sys.platform != "darwin":
        return list(argv)
    try:
        boundary = _authenticate_system_tool(MACOS_DESCENDANT_BOUNDARY)
    except AppleArtifactGateError as exc:
        raise _owner_environment_blocker(
            "complete macOS descendant containment requires the authenticated "
            "fixed no-fork execution boundary"
        ) from exc
    return [
        boundary,
        "-p",
        MACOS_DESCENDANT_BOUNDARY_PROFILE,
        *argv,
    ]


def _bounded_subprocess(
    argv: list[str],
    label: str,
    *,
    cwd: str = "/",
    env: Mapping[str, str] | None = None,
    stdin: int | None = subprocess.DEVNULL,
    stdout: int | None = subprocess.PIPE,
    stderr: int | None = subprocess.PIPE,
    timeout: int = TOOL_TIMEOUT_SEC,
    stdout_limit: int = MAX_TOOL_OUTPUT_BYTES,
    stderr_limit: int = MAX_TOOL_OUTPUT_BYTES,
    pass_fds: tuple[int, ...] = (),
    preexec_fn=None,
    input_data: bytes | None = None,
    descendant_boundary: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Run one process with streaming byte caps and deterministic group cleanup.

    ``descendant_boundary=False`` is reserved for ``_warm_xcrun_lookup``, which
    touches no artifact.
    """

    if (
        type(argv) is not list
        or not argv
        or any(type(item) is not str or not item for item in argv)
        or type(timeout) is not int
        or timeout <= 0
        or type(stdout_limit) is not int
        or stdout_limit < 0
        or type(stderr_limit) is not int
        or stderr_limit < 0
        or stdout not in {subprocess.PIPE, subprocess.DEVNULL, None}
        or stderr not in {subprocess.PIPE, subprocess.DEVNULL, None}
        or (input_data is not None and type(input_data) is not bytes)
    ):
        raise AppleArtifactGateError(f"{label} process contract is invalid")
    original_argv = list(argv)
    command = (
        _macos_descendant_boundary_argv(original_argv)
        if descendant_boundary
        else list(original_argv)
    )
    boundary_enforced = command != original_argv
    proc: subprocess.Popen[bytes] | None = None
    streams: dict[int, tuple[object, bytearray, int, str]] = {}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    input_file = None
    deadline = time.monotonic() + timeout
    alarm_state: tuple[typing.Any, tuple[float, float]] | None = None
    try:
        stdin_value = stdin
        if input_data is not None:
            if stdin != subprocess.DEVNULL:
                raise AppleArtifactGateError(
                    f"{label} process input contract is invalid"
                )
            input_file = tempfile.TemporaryFile()
            input_file.write(input_data)
            input_file.seek(0)
            stdin_value = input_file
        if threading.current_thread() is not threading.main_thread():
            raise _owner_environment_blocker(
                f"{label} requires main-thread process-start deadline custody"
            )

        def process_start_timeout(_signum, _frame):
            raise AppleArtifactGateError(f"{label} exceeded the process-start time bound")

        alarm_state = (signal.getsignal(signal.SIGALRM), signal.getitimer(signal.ITIMER_REAL))
        signal.signal(signal.SIGALRM, process_start_timeout)
        signal.setitimer(
            signal.ITIMER_REAL,
            max(0.001, deadline - time.monotonic()),
        )
        try:
            proc = subprocess.Popen(
                command,
                cwd=cwd,
                env=None if env is None else dict(env),
                stdin=stdin_value,
                stdout=stdout,
                stderr=stderr,
                text=False,
                shell=False,
                close_fds=True,
                pass_fds=pass_fds,
                start_new_session=True,
                preexec_fn=preexec_fn,
            )
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, alarm_state[0])
            signal.setitimer(signal.ITIMER_REAL, *alarm_state[1])
            alarm_state = None
        for stream, limit, stream_label in (
            (proc.stdout, stdout_limit, "stdout"),
            (proc.stderr, stderr_limit, "stderr"),
        ):
            if stream is None:
                continue
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            streams[descriptor] = (
                stream,
                captured[stream_label],
                limit,
                stream_label,
            )
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AppleArtifactGateError(f"{label} exceeded the time bound")
            readable, _writable, _exceptional = select.select(
                list(streams), [], [], min(0.1, remaining)
            )
            if not readable:
                continue
            for descriptor in readable:
                stream, payload, limit, stream_label = streams[descriptor]
                try:
                    chunk = os.read(descriptor, min(65536, limit + 1 - len(payload)))
                except BlockingIOError:
                    continue
                if not chunk:
                    stream.close()
                    del streams[descriptor]
                    continue
                payload.extend(chunk)
                if len(payload) > limit:
                    raise AppleArtifactGateError(
                        f"{label} exceeded the {stream_label} output bound"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AppleArtifactGateError(f"{label} exceeded the time bound")
        try:
            returncode = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise AppleArtifactGateError(f"{label} exceeded the time bound") from exc
        stdout_raw = bytes(captured["stdout"])
        stderr_raw = bytes(captured["stderr"])
        if (
            boundary_enforced
            and returncode != 0
            and b"sandbox_apply" in stderr_raw
        ):
            raise _owner_environment_blocker(
                "the authenticated fixed macOS no-fork boundary could not be applied; "
                "a privileged Endpoint Security helper is required on this host"
            )
        return subprocess.CompletedProcess(
            original_argv, returncode, stdout_raw, stderr_raw
        )
    except AppleArtifactGateError:
        if proc is not None:
            _kill_process_group(proc)
        raise
    except OSError as exc:
        if proc is not None:
            _kill_process_group(proc)
        raise AppleArtifactGateError(
            f"{label} could not execute: {_redact_tool_output(str(exc))}"
        ) from exc
    finally:
        if alarm_state is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, alarm_state[0])
            signal.setitimer(signal.ITIMER_REAL, *alarm_state[1])
        if proc is not None:
            _kill_process_group(proc)
        for stream, _payload, _limit, _stream_label in list(streams.values()):
            try:
                stream.close()
            except OSError:
                pass
        if input_file is not None:
            input_file.close()


def _reviewed_verifier_subprocess_module() -> ModuleType:
    proxy = ModuleType("subprocess")
    for name in (
        "CompletedProcess",
        "DEVNULL",
        "PIPE",
        "STDOUT",
        "SubprocessError",
        "TimeoutExpired",
    ):
        setattr(proxy, name, getattr(subprocess, name))

    def run(argv, **kwargs):
        command = list(argv)
        if not command:
            raise OSError("empty reviewed verifier command")
        if command[0] == "/usr/bin/otool":
            # Xcode 27's otool forks llvm-objdump, which the descendant boundary
            # refuses; the verifiers' otool calls run the single-process
            # otool-classic through xcrun, as the gate's own inspections do.
            command = [XCRUN, "otool-classic", *command[1:]]
        command[0] = _reviewed_tool(command[0])
        if command[0] == XCRUN:
            if len(command) < 2 or command[1] not in XCRUN_RUN_TOOLS:
                raise OSError("reviewed verifier names an unreviewed xcrun tool")
            _warm_xcrun_lookup(command[1])
        elif command[0] in XCRUN_SHIM_TOOLS:
            _warm_xcrun_lookup(XCRUN_SHIM_TOOLS[command[0]])
        if kwargs.pop("check", False):
            raise OSError("reviewed verifier subprocess check mode is unsupported")
        if kwargs.pop("shell", False):
            raise OSError("reviewed verifier subprocess shell mode is forbidden")
        text_mode = bool(kwargs.pop("text", False))
        encoding = kwargs.pop("encoding", "utf-8")
        errors = kwargs.pop("errors", "strict")
        completed = _bounded_subprocess(
            command,
            "reviewed verifier tool",
            cwd=str(kwargs.pop("cwd", "/")),
            env=kwargs.pop("env", None),
            stdin=kwargs.pop("stdin", subprocess.DEVNULL),
            stdout=kwargs.pop("stdout", subprocess.PIPE),
            stderr=kwargs.pop("stderr", subprocess.PIPE),
            timeout=int(kwargs.pop("timeout", TOOL_TIMEOUT_SEC)),
        )
        if kwargs:
            raise OSError("reviewed verifier subprocess arguments are unsupported")
        if not text_mode:
            return completed
        try:
            output = completed.stdout.decode(encoding, errors)
            failure = completed.stderr.decode(encoding, errors)
        except UnicodeError as exc:
            raise OSError("reviewed verifier tool returned invalid text") from exc
        return subprocess.CompletedProcess(
            completed.args, completed.returncode, output, failure
        )

    proxy.run = run  # type: ignore[attr-defined]
    return proxy


def _isolated_reviewed_source_namespace(
    source: bytes,
    *,
    logical_path: pathlib.Path,
    expected_sha256: str,
    label: str,
) -> dict[str, object]:
    """Compile and execute exact reviewed bytes without sys.path or pyc lookup."""

    if (
        type(source) is not bytes
        or not source
        or _sha256_bytes(source) != expected_sha256
        or not logical_path.is_absolute()
    ):
        raise AppleArtifactGateError(f"{label} retained source is not exact")
    reviewed_subprocess = _reviewed_verifier_subprocess_module()
    imports: dict[str, ModuleType] = {
        "__future__": future,
        "argparse": argparse,
        "contextlib": contextlib,
        "hashlib": hashlib,
        "io": io,
        "json": json,
        "os": os,
        "pathlib": pathlib,
        "plistlib": plistlib,
        "re": re,
        "select": select,
        "shutil": shutil,
        "stat": stat,
        "struct": struct,
        "subprocess": reviewed_subprocess,
        "sys": sys,
        "tempfile": tempfile,
        "types": types,
        "typing": typing,
        "uuid": uuid,
        "zipfile": zipfile,
    }

    def isolated_import(name, globals=None, locals=None, fromlist=(), level=0):
        del globals, locals, fromlist
        if level != 0 or name not in imports:
            raise ImportError(f"{label} refused non-reviewed import: {name}")
        return imports[name]

    private_builtins = dict(vars(builtins))
    private_builtins["__import__"] = isolated_import
    namespace: dict[str, object] = {
        "__name__": f"_winsvpn_reviewed_{secrets.token_hex(16)}",
        "__file__": os.fspath(logical_path),
        "__package__": "",
        "__builtins__": private_builtins,
    }
    try:
        code = compile(
            source,
            os.fspath(logical_path),
            "exec",
            dont_inherit=True,
        )
        exec(code, namespace)
    except (ImportError, OSError, RuntimeError, SyntaxError, ValueError) as exc:
        raise AppleArtifactGateError(
            f"{label} retained source could not execute in isolation"
        ) from exc
    return namespace


def verify_watch_artifact_snapshot(
    ipa_path: pathlib.Path,
    *,
    artifact_sha256: str,
    verifier_source: bytes,
    expected_verifier_sha256: str,
    artifact_size: int | None = None,
    verifier_kernel_path: str | None = None,
) -> dict[str, object]:
    """Execute exact reviewed Watch source against one held IPA snapshot."""

    del verifier_kernel_path
    reviewed_verifier_sha256 = HELD_ARTIFACT_REVIEW_SOURCE_SHA256.get(
        "apple_watch_artifact_verifier.py"
    )
    if (
        type(verifier_source) is not bytes
        or not verifier_source
        or type(expected_verifier_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_verifier_sha256) is None
        or expected_verifier_sha256 != reviewed_verifier_sha256
        or _sha256_bytes(verifier_source) != expected_verifier_sha256
    ):
        raise AppleArtifactGateError(
            "Apple Watch artifact verifier does not match the externally authenticated source closure"
        )
    verifier_sha256 = expected_verifier_sha256
    if artifact_size is None:
        try:
            artifact_size = ipa_path.lstat().st_size
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple Watch held IPA size is unavailable"
            ) from exc
    namespace = _isolated_reviewed_source_namespace(
        verifier_source,
        logical_path=ORIGIN_ROOT / WATCH_ARTIFACT_VERIFIER_RELATIVE,
        expected_sha256=verifier_sha256,
        label="Apple Watch artifact verifier",
    )
    verifier = namespace.get("verify_ipa")
    if (
        not isinstance(verifier, types.FunctionType)
        or verifier.__globals__ is not namespace
    ):
        raise AppleArtifactGateError(
            "Apple Watch artifact verifier entry point is not isolated"
        )
    try:
        result = verifier(pathlib.Path(ipa_path))
    except Exception as exc:
        watch_error = namespace.get("WatchArtifactError")
        if isinstance(watch_error, type) and isinstance(exc, watch_error):
            raise AppleArtifactGateError(
                "Apple Watch artifact verifier rejected the held IPA: "
                + _redact_tool_output(str(exc))
            ) from exc
        raise
    if type(result) is not dict:
        raise AppleArtifactGateError(
            "Apple Watch artifact verifier output is not exact JSON data"
        )
    result = json.loads(
        json.dumps(result, sort_keys=True, separators=(",", ":")),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonfinite,
    )
    expected_result_keys = {
        "schema_version",
        "bundle_id",
        "companion_bundle_id",
        "version",
        "build_number",
        "parent_version",
        "parent_build_number",
        "ipa_sha256",
        "ipa_bytes",
        "executable",
        "executable_sha256",
        "architectures",
        "watch_connectivity_dependency",
        "wc_session_import",
        "required_selectors",
        "privacy_manifest_sha256",
        "debug_sections",
    }
    result = _receipt_exact_mapping(
        result, expected_result_keys, "Apple Watch artifact verifier output"
    )
    architectures = result.get("architectures")
    artifact_digest = _receipt_hex64(artifact_sha256, "Watch verifier IPA")
    if (
        result.get("schema_version") != 1
        or result.get("bundle_id") != WATCH_BUNDLE_ID
        or result.get("companion_bundle_id") != HOST_BUNDLE_ID
        or result.get("version") != CANONICAL_MARKETING_VERSION
        or result.get("build_number") != CANONICAL_BUNDLE_VERSION
        or result.get("parent_version") != CANONICAL_MARKETING_VERSION
        or result.get("parent_build_number") != CANONICAL_BUNDLE_VERSION
        or result.get("ipa_sha256") != artifact_digest
        or type(result.get("ipa_bytes")) is not int
        or isinstance(result.get("ipa_bytes"), bool)
        or int(result.get("ipa_bytes")) != artifact_size
        or result.get("executable") != WATCH_EXECUTABLE
        or type(architectures) is not list
        or not architectures
        or len(architectures) != len(set(architectures))
        or not set(architectures).issubset({"arm64", "arm64_32"})
        or result.get("watch_connectivity_dependency")
        != WATCH_CONNECTIVITY_DEPENDENCY
        or result.get("wc_session_import") != WATCH_WC_SESSION_IMPORT
        or result.get("required_selectors") != list(WATCH_REQUIRED_SELECTORS)
        or result.get("debug_sections") is not False
    ):
        raise AppleArtifactGateError(
            "Apple Watch artifact verifier output is unsupported or incomplete"
        )
    _receipt_hex64(result.get("executable_sha256"), "Watch verifier executable")
    _receipt_hex64(result.get("privacy_manifest_sha256"), "Watch verifier privacy")
    return {
        "contract": "winsvpn-watch-artifact-verification-v1",
        "artifact_sha256": artifact_digest,
        "verifier": {
            "path": WATCH_ARTIFACT_VERIFIER_RELATIVE,
            "sha256": verifier_sha256,
            "reviewed_verifier": True,
        },
        "result": dict(result),
        "result_sha256": _canonical_json_sha256(result),
    }


def _main_app_tree_digest(inner_payload: Mapping[str, object]) -> str:
    app_relative = inner_payload.get("app")
    tree = inner_payload.get("tree")
    if type(app_relative) is not str or type(tree) is not list:
        raise AppleArtifactGateError(
            "macOS independent verifier cannot bind the main app tree"
        )
    prefix = app_relative.rstrip("/") + "/"
    normalized: list[dict[str, object]] = []
    for raw in tree:
        if type(raw) is not dict or type(raw.get("path")) is not str:
            raise AppleArtifactGateError(
                "macOS independent verifier main tree record is malformed"
            )
        path = str(raw["path"])
        if not path.startswith(prefix):
            continue
        relative = path[len(prefix) :]
        if not relative:
            continue
        kind = raw.get("type")
        record: dict[str, object] = {
            "path": relative,
            "mode": raw.get("mode"),
            "type": kind,
        }
        if kind == "file":
            record["bytes"] = raw.get("bytes")
            record["sha256"] = raw.get("sha256")
        elif kind == "symlink":
            record["target"] = raw.get("link_target")
        elif kind != "dir":
            raise AppleArtifactGateError(
                "macOS independent verifier main tree type is unsupported"
            )
        normalized.append(record)
    normalized.sort(key=lambda item: str(item["path"]))
    if not normalized:
        raise AppleArtifactGateError(
            "macOS independent verifier main app tree is empty"
        )
    return _canonical_json_sha256(normalized)


def _verify_macos_independent_snapshot(
    *,
    app: pathlib.Path,
    snapshot: AuthenticatedPkgSnapshot,
    inner_payload: Mapping[str, object],
    verifier_source: bytes,
    expected_verifier_sha256: str,
) -> dict[str, object]:
    """Execute exact retained macOS review bytes and cross-check the main gate."""

    snapshot.rehash()
    namespace = _isolated_reviewed_source_namespace(
        verifier_source,
        logical_path=ORIGIN_ROOT / "tools" / "verify_macos_release_artifact.py",
        expected_sha256=expected_verifier_sha256,
        label="macOS independent artifact verifier",
    )
    required_functions = (
        "audit_code_topology",
        "verify_all_privacy",
        "tree_records",
        "tree_digest",
        "macho_architectures",
        "sha256_file",
    )
    functions: dict[str, types.FunctionType] = {}
    for name in required_functions:
        candidate = namespace.get(name)
        if (
            not isinstance(candidate, types.FunctionType)
            or candidate.__globals__ is not namespace
        ):
            raise AppleArtifactGateError(
                f"macOS independent verifier entry point is not isolated: {name}"
            )
        functions[name] = candidate
    try:
        artifact_sha256 = functions["sha256_file"](snapshot.path)
        records = functions["tree_records"](app)
        topology = functions["audit_code_topology"](app)
        functions["verify_all_privacy"](app, topology)
        app_tree_sha256 = functions["tree_digest"](records)
        host_info = topology["host_info"]
        tunnel_info = topology["tunnel_info"]
        macho_files = topology["macho_files"]
        architecture_sets = [
            functions["macho_architectures"](
                path,
                pathlib.Path(path).relative_to(app).as_posix(),
            )
            for path in macho_files
        ]
    except Exception as exc:
        verification_error = namespace.get("VerificationError")
        if isinstance(verification_error, type) and isinstance(exc, verification_error):
            raise AppleArtifactGateError(
                "macOS independent verifier rejected the held PKG: "
                + _redact_tool_output(str(exc))
            ) from exc
        raise
    required_architectures = set(REQUIRED_MACOS_ARCHITECTURES)
    if not architecture_sets or any(
        type(architectures) not in {list, tuple}
        or len(architectures) != len(set(architectures))
        or set(architectures) != required_architectures
        for architectures in architecture_sets
    ):
        raise AppleArtifactGateError(
            "macOS independent verifier found a thin or mixed-thin required Mach-O image"
        )
    architectures = sorted(set().union(*architecture_sets))
    result: dict[str, object] = {
        "schema_version": 1,
        "artifact_sha256": artifact_sha256,
        "artifact_bytes": snapshot.size,
        "release": CANONICAL_RELEASE,
        "bundle_id": host_info.get("CFBundleIdentifier"),
        "packet_tunnel_bundle_id": tunnel_info.get("CFBundleIdentifier"),
        "version": host_info.get("CFBundleShortVersionString"),
        "build_number": str(host_info.get("CFBundleVersion")),
        "packet_tunnel_version": tunnel_info.get("CFBundleShortVersionString"),
        "packet_tunnel_build_number": str(tunnel_info.get("CFBundleVersion")),
        "architectures": architectures,
        "app_tree_sha256": app_tree_sha256,
        "macho_count": len(macho_files),
        "privacy_verified": True,
    }
    expected_keys = {
        "schema_version",
        "artifact_sha256",
        "artifact_bytes",
        "release",
        "bundle_id",
        "packet_tunnel_bundle_id",
        "version",
        "build_number",
        "packet_tunnel_version",
        "packet_tunnel_build_number",
        "architectures",
        "app_tree_sha256",
        "macho_count",
        "privacy_verified",
    }
    result = _receipt_exact_mapping(
        result, expected_keys, "macOS independent verifier output"
    )
    bundles = inner_payload.get("bundles")
    natives = inner_payload.get("natives")
    if type(bundles) is not list or type(natives) is not list:
        raise AppleArtifactGateError(
            "macOS independent verifier cannot cross-check the main gate"
        )
    bundle_by_role = {
        record.get("role"): record for record in bundles if type(record) is dict
    }
    main_architectures = sorted(
        {
            str(architecture)
            for record in natives
            if type(record) is dict and type(record.get("architectures")) is list
            for architecture in record["architectures"]
        }
    )
    main_native_architectures_exact = all(
        type(record) is dict
        and type(record.get("architectures")) is list
        and len(record["architectures"]) == len(set(record["architectures"]))
        and set(record["architectures"]) == required_architectures
        for record in natives
    )
    host = bundle_by_role.get("host")
    tunnel = bundle_by_role.get("tunnel")
    if (
        result["schema_version"] != 1
        or result["artifact_sha256"] != snapshot.rehash()
        or result["artifact_bytes"] != snapshot.size
        or result["release"] != CANONICAL_RELEASE
        or result["bundle_id"] != HOST_BUNDLE_ID
        or result["packet_tunnel_bundle_id"] != TUNNEL_BUNDLE_ID
        or result["version"] != CANONICAL_MARKETING_VERSION
        or result["build_number"] != CANONICAL_BUNDLE_VERSION
        or result["packet_tunnel_version"] != CANONICAL_MARKETING_VERSION
        or result["packet_tunnel_build_number"] != CANONICAL_BUNDLE_VERSION
        or result["architectures"] != list(REQUIRED_MACOS_ARCHITECTURES)
        or result["architectures"] != main_architectures
        or not main_native_architectures_exact
        or result["app_tree_sha256"] != _main_app_tree_digest(inner_payload)
        or type(result["macho_count"]) is not int
        or int(result["macho_count"]) <= 0
        or result["privacy_verified"] is not True
        or type(host) is not dict
        or type(tunnel) is not dict
        or host.get("bundle_id") != result["bundle_id"]
        or tunnel.get("bundle_id") != result["packet_tunnel_bundle_id"]
        or host.get("version") != result["version"]
        or host.get("build") != result["build_number"]
        or tunnel.get("version") != result["packet_tunnel_version"]
        or tunnel.get("build") != result["packet_tunnel_build_number"]
    ):
        raise AppleArtifactGateError(
            "macOS independent verifier output disagrees with the main gate"
        )
    snapshot.rehash()
    return {
        "contract": MACOS_INDEPENDENT_VERIFIER_CONTRACT,
        "artifact_sha256": snapshot.digest,
        "verifier": {
            "path": "tools/verify_macos_release_artifact.py",
            "sha256": expected_verifier_sha256,
        },
        "result": dict(result),
        "result_sha256": _canonical_json_sha256(result),
    }


def _copy_exclusive(source_fd: int, destination: pathlib.Path, size: int) -> str:
    dest_fd = os.open(destination, _open_flags(write=True, exclusive=True), 0o400)
    try:
        os.fchmod(dest_fd, 0o400)
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            block = os.read(source_fd, min(READ_CHUNK, remaining))
            if not block:
                raise AppleArtifactGateError("authenticated snapshot source truncated")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(dest_fd, view)
                if written <= 0:
                    raise AppleArtifactGateError("authenticated snapshot write truncated")
                view = view[written:]
            remaining -= len(block)
        extra = os.read(source_fd, 1)
        if extra:
            raise AppleArtifactGateError(
                "authenticated snapshot source mutated while copying"
            )
        os.fsync(dest_fd)
        return digest.hexdigest()
    finally:
        os.close(dest_fd)


def _openat_child(parent_fd: int, name: str, flags: int) -> int:
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise AppleArtifactGateError("Apple gate path component is unsafe")
    try:
        info = os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            f"Apple gate could not bind path component {name!r}"
        ) from exc
    if stat.S_ISLNK(info.st_mode):
        raise AppleArtifactGateError(
            f"Apple gate path must not contain symlinks: {name}"
        )
    if flags & getattr(os, "O_DIRECTORY", 0):
        if not stat.S_ISDIR(info.st_mode):
            raise AppleArtifactGateError(
                f"Apple gate path component is not a directory: {name}"
            )
    elif not stat.S_ISREG(info.st_mode):
        raise AppleArtifactGateError(
            f"{name} must be a non-empty regular single-link file"
        )
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        if getattr(exc, "errno", None) in {errno.ELOOP, errno.ENOTDIR}:
            raise AppleArtifactGateError(
                f"Apple gate path must not contain symlinks: {name}"
            ) from exc
        raise AppleArtifactGateError(
            f"Apple gate could not bind path component {name!r}"
        ) from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise AppleArtifactGateError(
                f"Apple gate path component was replaced: {name}"
            )
        return fd
    except Exception:
        os.close(fd)
        raise


def _support_identity(info: os.stat_result) -> tuple[int, ...]:
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


def _support_directory_identity(info: os.stat_result) -> tuple[int, ...]:
    # Directory size, link count, and timestamps legitimately change when an
    # unrelated sibling is created.  Rename/delete/revoke/attribute events and
    # the retained inode/path binding below cover custody without making those
    # unrelated writes release authority.
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
    )


class _HeldSupportSources:
    """Retain exact reviewed support bytes and every lexical ancestor."""

    def __init__(
        self,
        files: tuple[tuple[str, str], ...] = REQUIRED_MODULE_FILES,
    ) -> None:
        if not hasattr(os, "O_NOFOLLOW") or not callable(getattr(os, "open", None)):
            raise AppleArtifactGateError(
                "Apple gate requires O_NOFOLLOW descriptor binding"
            )
        if (
            type(files) is not tuple
            or not files
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not str
                or not item[0]
                or pathlib.PurePosixPath(item[0]).name != item[0]
                for item in files
            )
            or len({item[0] for item in files}) != len(files)
        ):
            raise AppleArtifactGateError("Apple support source inventory is invalid")
        self._files = files
        self._records: list[
            tuple[int | None, str, int, os.stat_result, bool]
        ] = []
        self._file_records: dict[str, tuple[int, os.stat_result]] = {}
        self._payloads: dict[str, bytes] = {}
        self._digests: dict[str, str] = {}
        self._queue: object | None = None
        self._closed = False
        try:
            self._open_all()
            self._start_watch()
            self._read_all()
            self.verify()
        except Exception:
            self.close(verify=False)
            raise

    @property
    def payloads(self) -> dict[str, bytes]:
        return dict(self._payloads)

    @property
    def digests(self) -> dict[str, str]:
        return dict(self._digests)

    def kernel_path(self, filename: str) -> str:
        record = self._file_records.get(filename)
        if record is None:
            raise AppleArtifactGateError(
                "Apple support source is outside the retained closure"
            )
        self.verify()
        fd, before = record
        return _authenticate_volfs(fd, _pkg_vnode_identity(before))

    def _append(
        self,
        parent_fd: int | None,
        name: str,
        fd: int,
        *,
        directory: bool,
    ) -> int:
        info = os.fstat(fd)
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                raise AppleArtifactGateError(
                    f"Apple support ancestor is not a directory: {name or '/'}"
                )
        elif (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > MAX_SUPPORT_BYTES
        ):
            raise AppleArtifactGateError(
                f"{name} must be one non-empty, single-link regular origin file"
            )
        self._records.append((parent_fd, name, fd, info, directory))
        return fd

    def _open_all(self) -> None:
        origin = ORIGIN_ROOT.absolute()
        if not origin.is_absolute() or not origin.parts or origin.parts[0] != os.sep:
            raise AppleArtifactGateError("Apple support origin must be absolute")
        current = self._append(
            None,
            "",
            os.open(os.sep, _dir_open_flags()),
            directory=True,
        )
        for component in origin.parts[1:]:
            child = _openat_child(current, component, _dir_open_flags())
            current = self._append(
                current, component, child, directory=True
            )
        tools_fd = _openat_child(current, "tools", _dir_open_flags())
        tools_fd = self._append(current, "tools", tools_fd, directory=True)
        for filename, _public_name in self._files:
            fd = _openat_child(tools_fd, filename, _open_flags())
            info = os.fstat(fd)
            self._append(tools_fd, filename, fd, directory=False)
            self._file_records[filename] = (fd, info)

    def _start_watch(self) -> None:
        if not hasattr(select, "kqueue"):
            if sys.platform == "darwin":
                raise AppleArtifactGateError(
                    "Apple support source custody requires Darwin kqueue"
                )
            return
        queue = select.kqueue()
        custody_flags = (
            getattr(select, "KQ_NOTE_DELETE", 0)
            | getattr(select, "KQ_NOTE_RENAME", 0)
            | getattr(select, "KQ_NOTE_REVOKE", 0)
            | getattr(select, "KQ_NOTE_ATTRIB", 0)
        )
        try:
            for _parent_fd, _name, fd, _before, directory in self._records:
                flags = custody_flags
                if not directory:
                    flags |= (
                        getattr(select, "KQ_NOTE_WRITE", 0)
                        | getattr(select, "KQ_NOTE_EXTEND", 0)
                        | getattr(select, "KQ_NOTE_LINK", 0)
                    )
                event = select.kevent(
                    fd,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=flags,
                )
                queue.control([event], 0, 0)
        except Exception:
            queue.close()
            raise
        self._queue = queue

    def _read_all(self) -> None:
        for filename, (fd, before) in self._file_records.items():
            os.lseek(fd, 0, os.SEEK_SET)
            payload = bytearray()
            while len(payload) <= MAX_SUPPORT_BYTES:
                chunk = os.read(
                    fd, min(READ_CHUNK, MAX_SUPPORT_BYTES + 1 - len(payload))
                )
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) != before.st_size or len(payload) > MAX_SUPPORT_BYTES:
                raise AppleArtifactGateError(
                    f"{filename} support source was truncated or exceeded its limit"
                )
            self._payloads[filename] = bytes(payload)
            self._digests[filename] = hashlib.sha256(payload).hexdigest()

    def _reject_events(self) -> None:
        if self._queue is None:
            return
        events = self._queue.control(None, max(1, len(self._records) * 2), 0)
        if events:
            raise AppleArtifactGateError(
                "Apple support source or ancestor changed during descriptor execution"
            )

    def verify(self) -> None:
        if self._closed:
            raise AppleArtifactGateError("Apple support source custody is closed")
        self._reject_events()
        for parent_fd, name, fd, before, directory in self._records:
            after = os.fstat(fd)
            identity = (
                _support_directory_identity if directory else _support_identity
            )
            if identity(after) != identity(before):
                raise AppleArtifactGateError(
                    f"Apple support source identity changed: {name or '/'}"
                )
            if parent_fd is not None:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if identity(named) != identity(before):
                    raise AppleArtifactGateError(
                        f"Apple support source path was replaced: {name}"
                    )
                if directory != stat.S_ISDIR(named.st_mode):
                    raise AppleArtifactGateError(
                        f"Apple support source path type changed: {name}"
                    )
        for filename, (fd, before) in self._file_records.items():
            if _sha256_fd(fd, before.st_size) != self._digests[filename]:
                raise AppleArtifactGateError(
                    f"Apple support source bytes changed: {filename}"
                )
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
        for _parent_fd, _name, fd, _before, _directory in reversed(self._records):
            try:
                os.close(fd)
            except OSError:
                pass
        self._records.clear()
        self._file_records.clear()
        if error is not None:
            raise error


def _load_required_modules() -> dict[str, ModuleType]:
    custody = _HeldSupportSources()
    token = secrets.token_hex(16)
    completed = False
    loaded: dict[str, ModuleType] = {}
    private_names: dict[str, str] = {}
    previous_public: dict[str, ModuleType | None] = {}
    try:
        payloads = custody.payloads
        digests_by_file = custody.digests
        for filename, public_name in REQUIRED_MODULE_FILES:
            private_name = f"_winsvpn_apple_gate_{public_name}_{token}"
            if private_name in sys.modules:
                raise AppleArtifactGateError(
                    f"private module identity collided: {private_name}"
                )
            try:
                code = compile(
                    payloads[filename], os.fspath(TOOLS_DIR / filename), "exec",
                    dont_inherit=True,
                )
            except (SyntaxError, ValueError) as exc:
                raise AppleArtifactGateError(
                    f"{filename} reviewed descriptor bytes could not be compiled"
                ) from exc
            module = ModuleType(private_name)
            module.__file__ = os.fspath(TOOLS_DIR / filename)
            module.__package__ = ""
            module.__winsvpn_source_sha256__ = digests_by_file[filename]
            module.__winsvpn_compiled_code__ = code
            loaded[public_name] = module
            private_names[public_name] = private_name
            previous_public[public_name] = sys.modules.get(public_name)
            sys.modules[private_name] = module
            sys.modules[public_name] = module
        for filename, public_name in REQUIRED_MODULE_FILES:
            module = loaded[public_name]
            code = module.__dict__.pop("__winsvpn_compiled_code__")
            exec(code, module.__dict__)
            if (
                sys.modules.get(private_names[public_name]) is not module
                or sys.modules.get(public_name) is not module
            ):
                raise AppleArtifactGateError(
                    f"{filename} isolated module identity changed during execution"
                )
            custody.verify()
        custody.verify()
        completed = True
    finally:
        for public_name, private_name in private_names.items():
            module = loaded.get(public_name)
            if sys.modules.get(private_name) is module:
                del sys.modules[private_name]
            previous = previous_public.get(public_name)
            if previous is None:
                if sys.modules.get(public_name) is module:
                    del sys.modules[public_name]
            else:
                sys.modules[public_name] = previous
        custody.close(verify=completed)
    loaded["_digests"] = {
        public_name: digests_by_file[filename]
        for filename, public_name in REQUIRED_MODULE_FILES
    }  # type: ignore[assignment]
    return loaded


_MODULES = _load_required_modules()
_MODULE_DIGESTS: dict[str, str] = _MODULES.pop("_digests")  # type: ignore[arg-type]
source_freeze = _MODULES["release_source_freeze"]
contamination = _MODULES["apple_release_contamination_gate"]
obfuscation = _MODULES["release_obfuscation_contract"]
AppleReleaseContaminationError = contamination.AppleReleaseContaminationError
verify_release_contamination = contamination.verify_app_bundle
ObfuscationError = obfuscation.ObfuscationError
inspect_native_debug_sections = obfuscation.inspect_native_debug_sections
reject_embedded_long_lived_credentials = obfuscation.reject_embedded_long_lived_credentials
reject_packaged_private_symbols = obfuscation.reject_packaged_private_symbols
reject_unstripped_native_blob = obfuscation.reject_unstripped_native_blob


def _validate_support_custody(custody: _HeldSupportSources) -> dict[str, str]:
    bound: dict[str, str] = {}
    current = custody.digests
    for filename, public_name in REQUIRED_MODULE_FILES:
        expected = _MODULE_DIGESTS.get(public_name)
        module = _MODULES.get(public_name)
        if expected is None or module is None:
            raise AppleArtifactGateError(
                f"imported support module {public_name} has no origin digest"
            )
        if (
            current.get(filename) != expected
            or getattr(module, "__winsvpn_source_sha256__", None) != expected
        ):
            raise AppleArtifactGateError(
                f"imported support module origin bytes changed: {filename}"
            )
        bound[filename] = expected
    custody.verify()
    return bound


def _validate_held_artifact_review_custody(
    custody: _HeldSupportSources,
) -> dict[str, str]:
    """Bind the exact independently accepted verifier review snapshot."""

    current = custody.digests
    expected_names = {filename for filename, _label in HELD_ARTIFACT_REVIEW_SOURCES}
    if set(current) != expected_names:
        raise AppleArtifactGateError(
            "Apple held-artifact verifier source closure is incomplete"
        )
    for filename in sorted(expected_names):
        expected = HELD_ARTIFACT_REVIEW_SOURCE_SHA256.get(filename)
        if expected is None or current.get(filename) != expected:
            raise _owner_environment_blocker(
                "accepted Apple held-artifact verifier source review is stale: "
                + filename
            )
    custody.verify()
    return {filename: current[filename] for filename in sorted(expected_names)}


@contextlib.contextmanager
def held_reviewed_watch_verifier_source(
    *, expected_sha256: str
) -> typing.Iterator[bytes]:
    """Retain the exact caller-pinned Watch verifier source through one use."""

    filename = "apple_watch_artifact_verifier.py"
    custody = _HeldSupportSources(((filename, "watch_artifact_verifier"),))
    completed = False
    try:
        reviewed = HELD_ARTIFACT_REVIEW_SOURCE_SHA256.get(filename)
        digests = custody.digests
        payloads = custody.payloads
        if (
            type(expected_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
            or expected_sha256 != reviewed
            or digests.get(filename) != expected_sha256
            or _sha256_bytes(payloads.get(filename, b"")) != expected_sha256
        ):
            raise _owner_environment_blocker(
                "accepted Apple Watch verifier source review is stale"
            )
        custody.verify()
        yield payloads[filename]
        custody.verify()
        completed = True
    finally:
        custody.close(verify=completed)


def _support_custody_operation(operation):
    # Every operation re-holds and re-hashes the imported support modules and
    # refuses when their origin bytes differ from the bytes that were executed.
    # Release source custody is bound by release_dependency_freeze.py
    # verify-index in the producer, not by an owner-provisioned trust file.
    @functools.wraps(operation)
    def wrapped(*args, **kwargs):
        custody = _HeldSupportSources()
        try:
            _validate_support_custody(custody)
            result = operation(*args, **kwargs)
            if isinstance(result, HeldAppleArtifactEvidence):
                try:
                    result._adopt_gate_support_custody(custody)
                except BaseException:
                    result.close(verify=False)
                    raise
                custody = None
            return result
        finally:
            if custody is not None:
                custody.close()

    return wrapped


def _fstatfs(fd: int) -> _DarwinStatfs:
    if _LIBC is None or sys.platform != "darwin":
        raise _owner_environment_blocker(
            "Apple system tool custody requires Darwin fstatfs SSV evidence"
        )
    buf = _DarwinStatfs()
    rc = _LIBC.fstatfs(fd, ctypes.byref(buf))
    if rc != 0:
        raise _owner_environment_blocker(
            "Apple system tool fstatfs SSV evidence is unavailable"
        )
    return buf


def _ssv_volume_identity(fd: int) -> tuple[int, int, bytes, int]:
    info = os.fstat(fd)
    flags = int(getattr(info, "st_flags", 0))
    if info.st_uid != 0 or flags & SF_RESTRICTED != SF_RESTRICTED:
        raise _owner_environment_blocker(
            "Apple system object is not SF_RESTRICTED root-owned SSV evidence"
        )
    buf = _fstatfs(fd)
    if buf.f_fstypename.split(b"\0", 1)[0] != b"apfs":
        raise _owner_environment_blocker(
            "Apple system object is not on an APFS Signed System Volume"
        )
    if buf.f_flags & MNT_RDONLY != MNT_RDONLY:
        raise _owner_environment_blocker(
            "Apple system object is not on a read-only Signed System Volume"
        )
    return (int(buf.f_fsid[0]), int(buf.f_fsid[1]), buf.f_mntfromname, flags)


def _bind_system_version_platform() -> tuple[tuple[int, int], str, str]:
    fd = os.open("/", _dir_open_flags())
    try:
        for index, part in enumerate(SYSTEM_VERSION_COMPONENTS):
            last = index == len(SYSTEM_VERSION_COMPONENTS) - 1
            flags = _open_flags() if last else _dir_open_flags()
            child = _openat_child(fd, part, flags)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size <= 0
            or info.st_size > MAX_SYSTEM_VERSION_BYTES
        ):
            raise _owner_environment_blocker(
                "macOS SystemVersion.plist is not exact SSV platform evidence"
            )
        volume = _ssv_volume_identity(fd)
        payload = os.pread(fd, info.st_size, 0)
        if len(payload) != info.st_size:
            raise _owner_environment_blocker(
                "macOS SystemVersion.plist mutated while it was read"
            )
    finally:
        os.close(fd)
    try:
        document = plistlib.loads(payload)
    except (plistlib.InvalidFileException, ValueError, TypeError) as exc:
        raise _owner_environment_blocker(
            "macOS SystemVersion.plist is not exact SSV platform evidence"
        ) from exc
    product = document.get("ProductName") if type(document) is dict else None
    version = document.get("ProductVersion") if type(document) is dict else None
    build = document.get("ProductBuildVersion") if type(document) is dict else None
    reported = platform.mac_ver()[0]
    if (
        product != "macOS"
        or type(version) is not str
        or type(build) is not str
        or re.fullmatch(r"[0-9]+(\.[0-9]+){1,3}", version) is None
        or re.fullmatch(r"[0-9]+[A-Z][0-9]+", build) is None
        or reported != version
    ):
        raise _owner_environment_blocker(
            "Apple platform/SSV evidence does not match this Darwin host"
        )
    return (volume[0], volume[1]), version, build


def _authenticate_system_tool(path: str) -> str:
    if (
        path not in REVIEWED_APPLE_TOOLS | REVIEWED_EXECUTION_BOUNDARIES
        or not path.startswith("/")
    ):
        raise AppleArtifactGateError(
            f"Apple gate refuses an unreviewed or PATH-relative extractor: {path}"
        )
    platform_fsid, _version, _build = _bind_system_version_platform()
    parts = pathlib.PurePosixPath(path).parts
    if parts[0] != "/":
        raise AppleArtifactGateError(f"reviewed Apple tool path is not absolute: {path}")
    fd = os.open("/", _dir_open_flags())
    try:
        try:
            for index, part in enumerate(parts[1:]):
                last = index == len(parts) - 2
                flags = _open_flags() if last else _dir_open_flags()
                child = _openat_child(fd, part, flags)
                os.close(fd)
                fd = child
        except AppleArtifactGateError as exc:
            raise _owner_environment_blocker(
                "reviewed Apple tool is not authenticated platform/SSV evidence: "
                f"{path}"
            ) from exc
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not (info.st_mode & stat.S_IXUSR):
            raise AppleArtifactGateError(
                f"reviewed Apple tool must be a regular executable: {path}"
            )
        volume = _ssv_volume_identity(fd)
        if (volume[0], volume[1]) != platform_fsid:
            raise _owner_environment_blocker(
                f"reviewed Apple tool is not on the authenticated SSV: {path}"
            )
        named = os.lstat(path)
        if (
            stat.S_ISLNK(named.st_mode)
            or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise AppleArtifactGateError(
                f"reviewed Apple tool pathname does not match SSV descriptor: {path}"
            )
        return path
    finally:
        os.close(fd)


def _vnode_identity(info: os.stat_result, *, directory: bool = False) -> tuple[int, ...]:
    if directory:
        return (info.st_dev, info.st_ino)
    return _pkg_vnode_identity(info)


def _lexical_parts_under(
    root: pathlib.Path, path: pathlib.Path
) -> tuple[str, ...] | None:
    root_parts = pathlib.PurePosixPath(os.fspath(root)).parts
    path_parts = pathlib.PurePosixPath(os.fspath(path)).parts
    if not root_parts or path_parts[: len(root_parts)] != root_parts:
        return None
    return path_parts[len(root_parts) :]


def _openat_relative(
    dir_fd: int,
    parts: tuple[str, ...],
    *,
    last_directory: bool = False,
) -> int:
    if any(
        part in {"", ".", ".."}
        or "/" in part
        or _contains_ascii_control(part)
        for part in parts
    ):
        raise AppleArtifactGateError("Apple gate path must not contain unsafe components")
    if not parts:
        if not last_directory:
            raise AppleArtifactGateError("Apple gate file path is empty")
        return os.dup(dir_fd)
    fd = os.dup(dir_fd)
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            flags = _dir_open_flags() if (not last or last_directory) else _open_flags()
            child = _openat_child(fd, part, flags)
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def _openat_from_root(
    root: pathlib.Path,
    parts: tuple[str, ...],
    *,
    last_directory: bool = False,
) -> int:
    if any(
        part in {"", ".", ".."}
        or "/" in part
        or _contains_ascii_control(part)
        for part in parts
    ):
        raise AppleArtifactGateError("Apple gate path must not contain unsafe components")
    fd = os.open(root, _dir_open_flags())
    if not parts:
        return fd
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            flags = _dir_open_flags() if (not last or last_directory) else _open_flags()
            child = _openat_child(fd, part, flags)
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def _bind_path_from_known_roots(
    path: pathlib.Path, *, directory: bool = False
) -> int:
    path = pathlib.Path(path)
    private = _PRIVATE_ROOT.get()
    if private is not None and private.root_fd >= 0:
        parts = _lexical_parts_under(private.root, path)
        if parts is not None:
            return _openat_relative(
                private.root_fd, parts, last_directory=directory
            )
    parts = _lexical_parts_under(ROOT, path)
    if parts:
        return _openat_from_root(ROOT, parts, last_directory=directory)
    flags = _dir_open_flags() if directory else _open_flags()
    try:
        return os.open(path, flags)
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ELOOP:
            raise AppleArtifactGateError(
                "Apple gate path must not contain symlinks"
            ) from exc
        raise AppleArtifactGateError(
            "Apple gate could not bind an execution target"
        ) from exc


def _bind_repo_relative(
    relative: pathlib.Path,
    *,
    last_directory: bool = False,
) -> tuple[int, pathlib.Path, tuple[int, ...]]:
    if relative.is_absolute():
        raise AppleArtifactGateError("Apple gate artifact path must be repository-relative")
    parts = relative.parts
    if not parts:
        raise AppleArtifactGateError("Apple gate artifact path is empty")
    fd = _openat_from_root(ROOT, parts, last_directory=last_directory)
    try:
        info = os.fstat(fd)
        identity = _vnode_identity(info, directory=last_directory)
        lexical = ROOT.joinpath(*parts)
        return fd, lexical, identity
    except Exception:
        os.close(fd)
        raise


def _fchflags(fd: int, flags: int) -> None:
    if _LIBC is None or not hasattr(_LIBC, "fchflags"):
        return
    rc = _LIBC.fchflags(fd, flags)
    if rc != 0:
        errno = ctypes.get_errno()
        if errno not in {0, 1, 13}:
            raise AppleArtifactGateError("Apple gate could not update descriptor flags")


class BoundExecutionTarget:
    def __init__(
        self,
        fd: int,
        identity: tuple[int, ...],
        kernel: str,
        directory: bool,
    ) -> None:
        self.fd = fd
        self.identity = identity
        self.kernel = kernel
        self.directory = directory

    def ensure_bound(self) -> None:
        if self.fd < 0:
            raise AppleArtifactGateError(
                "Apple gate execution target descriptor is closed"
            )
        try:
            current = os.fstat(self.fd)
            kernel = os.lstat(self.kernel)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple gate execution target was replaced"
            ) from exc
        if _vnode_identity(current, directory=self.directory) != self.identity:
            raise AppleArtifactGateError(
                "Apple gate execution target identity changed"
            )
        if _vnode_identity(kernel, directory=self.directory) != self.identity:
            raise AppleArtifactGateError(
                "Apple gate execution target volfs identity changed"
            )

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def _bind_execution_target(
    path: pathlib.Path, *, directory: bool = False
) -> BoundExecutionTarget:
    fd = _bind_path_from_known_roots(path, directory=directory)
    try:
        info = os.fstat(fd)
        if directory:
            if not stat.S_ISDIR(info.st_mode):
                raise AppleArtifactGateError(
                    "Apple gate execution target must be a directory"
                )
        elif not stat.S_ISREG(info.st_mode):
            raise AppleArtifactGateError(
                "Apple gate execution target must be a regular file"
            )
        identity = _vnode_identity(info, directory=directory)
        kernel = _authenticate_volfs(fd, identity, directory=directory)
        target = BoundExecutionTarget(fd, identity, kernel, directory)
        fd = -1
        target.ensure_bound()
        return target
    finally:
        if fd >= 0:
            os.close(fd)


def _is_volfs_path(value: str) -> bool:
    return type(value) is str and value.startswith("/.vol/")


def _fd_has_user_immutable(fd: int) -> bool:
    if not UF_IMMUTABLE:
        return False
    try:
        info = os.fstat(fd)
    except OSError:
        return False
    return bool(int(getattr(info, "st_flags", 0)) & UF_IMMUTABLE)


def _inspect_dir_name() -> str:
    return INSPECT_DIR_PREFIX + secrets.token_hex(16)


class SealedInspectionTarget:
    def __init__(
        self,
        path: str,
        identity: tuple[int, int],
        directory: bool,
    ) -> None:
        self.path = path
        self.identity = identity
        self.directory = directory
        self._inspect_fd = -1
        self._base_fd = -1
        self._inspect_name = ""
        self._hardlinked = False
        self._renamed = False
        self._original_parent_fd = -1
        self._original_name = ""
        self._froze_inspect = False
        self._froze_original_parent = False
        self._restored = False

    def ensure_same_inode(self, target: BoundExecutionTarget) -> None:
        if self._restored:
            raise AppleArtifactGateError("Apple sealed inspection target was restored")
        if _is_volfs_path(self.path):
            raise AppleArtifactGateError(
                "codesign cannot inspect /.vol kernel identity paths"
            )
        try:
            current = os.fstat(target.fd)
            named = os.lstat(self.path)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple sealed inspection target was replaced"
            ) from exc
        if _zip_inode_key(current) != self.identity or _zip_inode_key(named) != self.identity:
            raise AppleArtifactGateError(
                "Apple sealed inspection target was replaced"
            )
        if self.directory:
            if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
                raise AppleArtifactGateError(
                    "Apple sealed inspection target was replaced"
                )
            return
        if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
            raise AppleArtifactGateError(
                "Apple sealed inspection target was replaced"
            )

    def restore(self) -> None:
        if self._restored:
            return
        self._restored = True
        try:
            if self._froze_inspect and self._inspect_fd >= 0:
                try:
                    _clear_held_unlink_blocking_flags(self._inspect_fd)
                    os.fchmod(self._inspect_fd, 0o700)
                except AppleArtifactGateError:
                    pass
            if self._hardlinked and self._inspect_fd >= 0:
                try:
                    os.unlink(INSPECT_HELD_NAME, dir_fd=self._inspect_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
            if (
                self._renamed
                and self._inspect_fd >= 0
                and self._original_parent_fd >= 0
                and self._original_name
            ):
                try:
                    os.rename(
                        INSPECT_HELD_NAME,
                        self._original_name,
                        src_dir_fd=self._inspect_fd,
                        dst_dir_fd=self._original_parent_fd,
                    )
                except OSError:
                    pass
            if self._froze_original_parent and self._original_parent_fd >= 0:
                try:
                    _clear_held_unlink_blocking_flags(self._original_parent_fd)
                    os.fchmod(self._original_parent_fd, 0o700)
                except AppleArtifactGateError:
                    pass
        finally:
            if self._inspect_fd >= 0:
                os.close(self._inspect_fd)
                self._inspect_fd = -1
            if self._base_fd >= 0:
                if self._inspect_name:
                    try:
                        os.rmdir(self._inspect_name, dir_fd=self._base_fd)
                    except OSError:
                        pass
                os.close(self._base_fd)
                self._base_fd = -1
            if self._original_parent_fd >= 0:
                os.close(self._original_parent_fd)
                self._original_parent_fd = -1


def _create_inspect_dir(base_fd: int) -> tuple[int, str]:
    name = _inspect_dir_name()
    try:
        os.mkdir(name, 0o700, dir_fd=base_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple sealed inspection directory could not be created"
        ) from exc
    inspect_fd = -1
    try:
        inspect_fd = os.open(name, _dir_open_flags(), dir_fd=base_fd)
        os.fchmod(inspect_fd, 0o700)
        info = os.fstat(inspect_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid()
        ):
            raise AppleArtifactGateError("Apple sealed inspection directory is unsafe")
        return inspect_fd, name
    except Exception:
        if inspect_fd >= 0:
            os.close(inspect_fd)
        try:
            os.rmdir(name, dir_fd=base_fd)
        except OSError:
            pass
        raise


def _open_inspect_base(
    target_fd: int, path: pathlib.Path | None = None
) -> tuple[int, pathlib.Path] | None:
    try:
        target_info = os.fstat(target_fd)
    except OSError:
        return None
    private = _PRIVATE_ROOT.get()
    if private is not None and private.root_fd >= 0:
        tmp_fd = -1
        try:
            tmp_fd = _openat_relative(private.root_fd, ("tmp",), last_directory=True)
            tmp_info = os.fstat(tmp_fd)
            if tmp_info.st_dev == target_info.st_dev:
                return tmp_fd, private.tmp
            os.close(tmp_fd)
        except (AppleArtifactGateError, OSError):
            if tmp_fd >= 0:
                os.close(tmp_fd)
    if path is None:
        return None
    parent = pathlib.Path(os.fspath(path)).parent
    parent_fd = -1
    try:
        parent_fd = _bind_path_from_known_roots(parent, directory=True)
        parent_info = os.fstat(parent_fd)
        if parent_info.st_dev != target_info.st_dev or _fd_has_user_immutable(parent_fd):
            os.close(parent_fd)
            return None
        return parent_fd, parent
    except (AppleArtifactGateError, OSError):
        if parent_fd >= 0:
            os.close(parent_fd)
        return None


def _release_inspect_dir(sealed: SealedInspectionTarget) -> None:
    if sealed._froze_inspect and sealed._inspect_fd >= 0:
        try:
            _clear_held_unlink_blocking_flags(sealed._inspect_fd)
            os.fchmod(sealed._inspect_fd, 0o700)
        except AppleArtifactGateError:
            pass
    sealed._froze_inspect = False
    if sealed._inspect_fd >= 0:
        try:
            os.unlink(INSPECT_HELD_NAME, dir_fd=sealed._inspect_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        os.close(sealed._inspect_fd)
        sealed._inspect_fd = -1
    if sealed._base_fd >= 0:
        if sealed._inspect_name:
            try:
                os.rmdir(sealed._inspect_name, dir_fd=sealed._base_fd)
            except OSError:
                pass
        os.close(sealed._base_fd)
        sealed._base_fd = -1
    sealed._inspect_name = ""
    sealed._hardlinked = False
    sealed._renamed = False


def _freeze_original_parent_inspect(
    sealed: SealedInspectionTarget,
    path: pathlib.Path,
    identity: tuple[int, int],
) -> None:
    lexical = os.fspath(path)
    original_name = pathlib.Path(lexical).name
    parent = pathlib.Path(lexical).parent
    if sealed._original_parent_fd < 0:
        sealed._original_parent_fd = _bind_path_from_known_roots(
            parent, directory=True
        )
        sealed._original_name = original_name
    named = os.lstat(sealed._original_name, dir_fd=sealed._original_parent_fd)
    if _zip_inode_key(named) != identity:
        raise AppleArtifactGateError("Apple sealed inspection target was replaced")
    if not _fd_has_user_immutable(sealed._original_parent_fd) and UF_IMMUTABLE:
        _require_fchflags(sealed._original_parent_fd, UF_IMMUTABLE)
        sealed._froze_original_parent = True
        named = os.lstat(sealed._original_name, dir_fd=sealed._original_parent_fd)
        if _zip_inode_key(named) != identity:
            raise AppleArtifactGateError("Apple sealed inspection target was replaced")
    sealed.path = lexical


def _seal_file_inspection(
    sealed: SealedInspectionTarget,
    target: BoundExecutionTarget,
    path: pathlib.Path,
    identity: tuple[int, int],
) -> None:
    base = _open_inspect_base(target.fd, path)
    if base is not None:
        base_fd, base_path = base
        sealed._base_fd = base_fd
        try:
            inspect_fd, inspect_name = _create_inspect_dir(base_fd)
            sealed._inspect_fd = inspect_fd
            sealed._inspect_name = inspect_name
            os.link(
                target.kernel,
                INSPECT_HELD_NAME,
                dst_dir_fd=inspect_fd,
                follow_symlinks=False,
            )
            held = os.lstat(INSPECT_HELD_NAME, dir_fd=inspect_fd)
            if (
                _zip_inode_key(held) != identity
                or stat.S_ISLNK(held.st_mode)
                or not stat.S_ISREG(held.st_mode)
            ):
                raise AppleArtifactGateError(
                    "Apple sealed inspection hardlink identity changed"
                )
            if UF_IMMUTABLE:
                _require_fchflags(inspect_fd, UF_IMMUTABLE)
                sealed._froze_inspect = True
            sealed._hardlinked = True
            sealed.path = os.fspath(base_path / inspect_name / INSPECT_HELD_NAME)
            if not _is_volfs_path(sealed.path):
                return
        except (AppleArtifactGateError, OSError, NotImplementedError):
            pass
        _release_inspect_dir(sealed)
    _freeze_original_parent_inspect(sealed, path, identity)


def _seal_directory_inspection(
    sealed: SealedInspectionTarget,
    target: BoundExecutionTarget,
    path: pathlib.Path,
    identity: tuple[int, int],
) -> None:
    lexical = os.fspath(path)
    original_name = pathlib.Path(lexical).name
    parent = pathlib.Path(lexical).parent
    sealed._original_parent_fd = _bind_path_from_known_roots(parent, directory=True)
    sealed._original_name = original_name
    named = os.lstat(original_name, dir_fd=sealed._original_parent_fd)
    if _zip_inode_key(named) != identity:
        raise AppleArtifactGateError("Apple sealed inspection target was replaced")
    if not _fd_has_user_immutable(sealed._original_parent_fd):
        base = _open_inspect_base(target.fd, path)
        if base is not None:
            base_fd, base_path = base
            sealed._base_fd = base_fd
            try:
                inspect_fd, inspect_name = _create_inspect_dir(base_fd)
                sealed._inspect_fd = inspect_fd
                sealed._inspect_name = inspect_name
                os.rename(
                    original_name,
                    INSPECT_HELD_NAME,
                    src_dir_fd=sealed._original_parent_fd,
                    dst_dir_fd=inspect_fd,
                )
                moved = os.lstat(INSPECT_HELD_NAME, dir_fd=inspect_fd)
                if _zip_inode_key(moved) != identity:
                    raise AppleArtifactGateError(
                        "Apple sealed inspection rename identity changed"
                    )
                if UF_IMMUTABLE:
                    _require_fchflags(inspect_fd, UF_IMMUTABLE)
                    sealed._froze_inspect = True
                sealed._renamed = True
                sealed.path = os.fspath(base_path / inspect_name / INSPECT_HELD_NAME)
                if not _is_volfs_path(sealed.path):
                    return
            except (AppleArtifactGateError, OSError):
                pass
            if sealed._renamed:
                try:
                    if sealed._froze_inspect and sealed._inspect_fd >= 0:
                        _clear_held_unlink_blocking_flags(sealed._inspect_fd)
                    os.rename(
                        INSPECT_HELD_NAME,
                        original_name,
                        src_dir_fd=sealed._inspect_fd,
                        dst_dir_fd=sealed._original_parent_fd,
                    )
                except OSError:
                    pass
                sealed._renamed = False
            _release_inspect_dir(sealed)
    _freeze_original_parent_inspect(sealed, path, identity)


def _open_sealed_inspection_target(
    target: BoundExecutionTarget,
    path: pathlib.Path,
) -> SealedInspectionTarget:
    lexical = os.fspath(path)
    if _is_volfs_path(lexical):
        raise AppleArtifactGateError(
            "codesign cannot inspect /.vol kernel identity paths"
        )
    if _contains_ascii_control(lexical):
        raise AppleArtifactGateError(
            "Apple gate execution target path contains control characters"
        )
    current = os.fstat(target.fd)
    identity = _zip_inode_key(current)
    if identity != (target.identity[0], target.identity[1]):
        raise AppleArtifactGateError("Apple gate execution target identity changed")
    sealed = SealedInspectionTarget(lexical, identity, target.directory)
    try:
        if target.directory:
            _seal_directory_inspection(sealed, target, path, identity)
        else:
            _seal_file_inspection(sealed, target, path, identity)
        if _is_volfs_path(sealed.path):
            raise AppleArtifactGateError(
                "codesign cannot inspect /.vol kernel identity paths"
            )
        sealed.ensure_same_inode(target)
        return sealed
    except Exception:
        sealed.restore()
        raise


def _cleanup_tree_fd(dir_fd: int) -> None:
    _clear_held_unlink_blocking_flags(dir_fd)
    try:
        os.fchmod(dir_fd, 0o700)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    try:
        names = os.listdir(dir_fd)
    except OSError as exc:
        raise AppleArtifactGateError("Apple gate cleanup directory is unreadable") from exc
    for name in sorted(names):
        if name in {".", ".."}:
            continue
        try:
            info = os.lstat(name, dir_fd=dir_fd)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple gate cleanup entry is unreadable"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            _identity_safe_unlink(dir_fd, name, (info.st_dev, info.st_ino))
            continue
        if stat.S_ISDIR(info.st_mode):
            child = _openat_child(dir_fd, name, _dir_open_flags())
            try:
                _cleanup_tree_fd(child)
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        try:
            child = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=dir_fd,
            )
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ELOOP:
                raise AppleArtifactGateError(
                    "Apple gate cleanup refused a substituted symlink"
                ) from exc
            raise AppleArtifactGateError(
                "Apple gate cleanup could not open an entry without following"
            ) from exc
        try:
            opened = os.fstat(child)
            if stat.S_ISLNK(opened.st_mode) or not stat.S_ISREG(opened.st_mode):
                raise AppleArtifactGateError(
                    "Apple gate cleanup refused a substituted symlink"
                )
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise AppleArtifactGateError(
                    "Apple gate cleanup entry changed while being opened"
                )
            if opened.st_nlink != 1:
                _identity_safe_unlink(
                    dir_fd,
                    name,
                    (opened.st_dev, opened.st_ino),
                    child,
                )
                continue
            _clear_held_unlink_blocking_flags(child)
            os.fchmod(child, 0o600)
        finally:
            os.close(child)


def _unlock_tree_fd(dir_fd: int) -> None:
    _cleanup_tree_fd(dir_fd)


class PrivateGateRoot:
    def __init__(
        self,
        root: pathlib.Path,
        snapshot_dir: pathlib.Path,
        snapshot_file: pathlib.Path,
        tree_dir: pathlib.Path,
        home: pathlib.Path,
        tmp: pathlib.Path,
        root_fd: int,
    ) -> None:
        canonical_root = root.resolve(strict=True)
        self.root = canonical_root
        self.snapshot_dir = canonical_root / snapshot_dir.name
        self.snapshot_file = self.snapshot_dir / snapshot_file.name
        self.tree_dir = canonical_root / tree_dir.name
        self.home = canonical_root / home.name
        self.tmp = canonical_root / tmp.name
        self.root_fd = root_fd
        self._ancestor_records: list[
            tuple[int | None, str, int, tuple[int, ...]]
        ] = []
        self._ancestor_queue: object | None = None
        try:
            self._bind_ancestors()
        except Exception:
            self.close_ancestors()
            raise

    def _bind_ancestors(self) -> None:
        absolute = self.root.absolute()
        if not absolute.is_absolute() or absolute.parts[0] != os.sep:
            raise AppleArtifactGateError("Apple gate private root path is invalid")
        current = os.open(os.sep, _dir_open_flags())
        self._ancestor_records.append(
            (None, "", current, _held_directory_identity(os.fstat(current)))
        )
        for component in absolute.parts[1:]:
            child = _openat_child(current, component, _dir_open_flags())
            self._ancestor_records.append(
                (
                    current,
                    component,
                    child,
                    _held_directory_identity(os.fstat(child)),
                )
            )
            current = child
        if _held_directory_identity(os.fstat(current)) != _held_directory_identity(
            os.fstat(self.root_fd)
        ):
            raise AppleArtifactGateError(
                "Apple gate private root descriptor does not match its retained path"
            )
        if hasattr(select, "kqueue"):
            queue = select.kqueue()
            flags = (
                getattr(select, "KQ_NOTE_DELETE", 0)
                | getattr(select, "KQ_NOTE_RENAME", 0)
                | getattr(select, "KQ_NOTE_REVOKE", 0)
                | getattr(select, "KQ_NOTE_ATTRIB", 0)
            )
            queue.control(
                [
                    select.kevent(
                        descriptor,
                        filter=select.KQ_FILTER_VNODE,
                        flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                        fflags=flags,
                    )
                    for _parent, _name, descriptor, _identity in self._ancestor_records
                ],
                0,
                0,
            )
            self._ancestor_queue = queue

    def verify_ancestors(self) -> None:
        if self.root_fd < 0:
            raise AppleArtifactGateError("Apple gate private root custody is closed")
        if self._ancestor_queue is not None and self._ancestor_queue.control(
            None, max(1, len(self._ancestor_records) * 2), 0
        ):
            raise AppleArtifactGateError(
                "Apple gate private root or an ancestor changed"
            )
        for parent_fd, name, descriptor, expected in self._ancestor_records:
            if _held_directory_identity(os.fstat(descriptor)) != expected:
                raise AppleArtifactGateError(
                    "Apple gate private root ancestor identity changed"
                )
            if parent_fd is not None:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _held_directory_identity(named) != expected:
                    raise AppleArtifactGateError(
                        "Apple gate private root ancestor was substituted"
                    )
        if _held_directory_identity(os.fstat(self.root_fd)) != self._ancestor_records[-1][3]:
            raise AppleArtifactGateError("Apple gate private root was substituted")

    def close_ancestors(self) -> None:
        if self._ancestor_queue is not None:
            try:
                self._ancestor_queue.close()
            except OSError:
                pass
            self._ancestor_queue = None
        for _parent, _name, descriptor, _identity in reversed(
            self._ancestor_records
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._ancestor_records.clear()


def _snapshot_file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_mode),
        int(info.st_nlink),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
        int(getattr(info, "st_flags", 0)),
        int(getattr(info, "st_gen", 0)),
    )


def _snapshot_directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_mode),
        int(info.st_nlink),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
        int(getattr(info, "st_flags", 0)),
        int(getattr(info, "st_gen", 0)),
    )


class AuthenticatedPkgSnapshot:
    def __init__(
        self,
        path: pathlib.Path,
        fd: int,
        identity: tuple[int, ...],
        vnode_identity: tuple[int, ...],
        parent_fd: int,
        parent_identity: tuple[int, ...],
        digest: str,
        size: int,
        volfs: str,
        expected_mode: int = 0o400,
    ) -> None:
        self.path = path
        self.fd = fd
        self.identity = identity
        self.vnode_identity = vnode_identity
        self.parent_fd = parent_fd
        self.parent_identity = parent_identity
        self.digest = digest
        self.size = size
        self.volfs = volfs
        self.expected_mode = expected_mode

    def ensure_bound(self) -> None:
        if self.fd < 0 or self.parent_fd < 0:
            raise AppleArtifactGateError(
                "Apple PKG authenticated snapshot descriptor is closed"
            )
        try:
            current = os.fstat(self.fd)
            parent = os.fstat(self.parent_fd)
            named = os.stat(
                self.path.name,
                dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
            kernel = os.lstat(self.volfs)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple PKG authenticated snapshot was replaced"
            ) from exc
        if (
            _snapshot_file_identity(current) != self.identity
            or _snapshot_file_identity(named) != self.identity
            or _snapshot_file_identity(kernel) != self.identity
            or _snapshot_directory_identity(parent) != self.parent_identity
            or _pkg_vnode_identity(current) != self.vnode_identity
            or _pkg_vnode_identity(kernel) != self.vnode_identity
            or stat.S_IMODE(current.st_mode) != self.expected_mode
            or current.st_mode & 0o222
            or current.st_nlink != 1
            or (UF_IMMUTABLE and not int(getattr(current, "st_flags", 0)) & UF_IMMUTABLE)
            or (UF_IMMUTABLE and not int(getattr(parent, "st_flags", 0)) & UF_IMMUTABLE)
        ):
            raise AppleArtifactGateError(
                "Apple PKG authenticated snapshot identity changed"
            )
        _require_read_only_descriptor(self.fd, "Apple PKG authenticated snapshot")

    def rehash(self) -> str:
        self.ensure_bound()
        digest = _sha256_fd(self.fd, self.size)
        if digest != self.digest:
            raise AppleArtifactGateError(
                "Apple PKG authenticated snapshot digest changed"
            )
        self.ensure_bound()
        return digest

    def kernel_path(self) -> str:
        self.ensure_bound()
        return _authenticate_volfs(self.fd, self.vnode_identity)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1


def _held_artifact_identity(info: os.stat_result) -> tuple[int, ...]:
    """Match the release-freeze full regular-file identity tuple exactly."""

    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_nlink),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
        int(getattr(info, "st_flags", 0)),
    )


def _held_directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
    )


def _require_read_only_descriptor(fd: int, label: str) -> None:
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except (OSError, ValueError) as exc:
        raise AppleArtifactGateError(f"{label} descriptor flags are unreadable") from exc
    if flags & os.O_ACCMODE != os.O_RDONLY:
        raise AppleArtifactGateError(f"{label} descriptor must be exact O_RDONLY")


def _require_unique_casefold_child(parent_fd: int, name: str, label: str) -> None:
    try:
        names = os.listdir(parent_fd)
    except OSError as exc:
        raise AppleArtifactGateError(f"{label} parent directory is unreadable") from exc
    folded = unicodedata.normalize("NFKC", name).casefold()
    matches = [
        candidate
        for candidate in names
        if unicodedata.normalize("NFKC", candidate).casefold() == folded
    ]
    if matches != [name]:
        raise AppleArtifactGateError(
            f"{label} name is missing, duplicated, or case-fold ambiguous"
        )


class HeldAppleArtifactCustody:
    """Retain one release-freeze artifact, its name, and every ancestor."""

    def __init__(
        self,
        *,
        source_fd: int,
        source_parent_fd: int,
        source_name: str,
        source_relative_path: str,
        expected_identity: tuple[int, ...],
        expected_size: int,
        expected_sha256: str,
    ) -> None:
        if (
            type(source_fd) is not int
            or source_fd < 0
            or type(source_parent_fd) is not int
            or source_parent_fd < 0
            or type(source_name) is not str
            or source_name in {"", ".", ".."}
            or "/" in source_name
            or "\\" in source_name
            or _contains_ascii_control(source_name)
            or type(expected_identity) is not tuple
            or len(expected_identity) != 10
            or any(type(value) is not int for value in expected_identity)
            or type(expected_size) is not int
            or isinstance(expected_size, bool)
            or expected_size <= 0
            or expected_size > MAX_PKG_BYTES
            or type(expected_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        ):
            raise AppleArtifactGateError("held Apple artifact binding is invalid")
        relative_text = _require_canonical_relative_path(
            source_relative_path, "held Apple artifact"
        )
        relative = pathlib.PurePosixPath(relative_text)
        if relative.name != source_name:
            raise AppleArtifactGateError(
                "held Apple artifact path does not match its retained name"
            )

        self.origin = ROOT.joinpath(*relative.parts)
        self.relative_path = relative_text
        self.source_name = source_name
        self.source_identity = expected_identity
        self.source_size = expected_size
        self.source_sha256 = expected_sha256
        self.source_fd = -1
        self.source_parent_fd = -1
        self._canonical_parent_fd = -1
        self._records: list[
            tuple[int | None, str, int, tuple[int, ...]]
        ] = []
        self._watch_labels: dict[int, str] = {}
        self._queue: object | None = None
        self._closed = False
        try:
            _require_read_only_descriptor(source_fd, "held Apple artifact")
            _require_read_only_descriptor(
                source_parent_fd, "held Apple artifact parent"
            )
            self.source_fd = os.dup(source_fd)
            self.source_parent_fd = os.dup(source_parent_fd)
            os.set_inheritable(self.source_fd, False)
            os.set_inheritable(self.source_parent_fd, False)
            self._bind_canonical_parent(relative.parts[:-1])
            self._start_watch()
            self.verify(rehash=True)
        except Exception:
            self.close(verify=False)
            raise

    def _append_directory(
        self, parent_fd: int | None, name: str, fd: int
    ) -> int:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise AppleArtifactGateError(
                "held Apple artifact ancestor is not a directory"
            )
        self._records.append(
            (parent_fd, name, fd, _held_directory_identity(info))
        )
        return fd

    def _bind_canonical_parent(self, relative_parent: tuple[str, ...]) -> None:
        root = ROOT.absolute()
        if not root.is_absolute() or root.parts[0] != os.sep:
            raise AppleArtifactGateError("held Apple artifact root is not absolute")
        current = self._append_directory(
            None, "", os.open(os.sep, _dir_open_flags())
        )
        for component in root.parts[1:]:
            child = _openat_child(current, component, _dir_open_flags())
            current = self._append_directory(current, component, child)
        for component in relative_parent:
            child = _openat_child(current, component, _dir_open_flags())
            current = self._append_directory(current, component, child)
        self._canonical_parent_fd = current

    def _start_watch(self) -> None:
        if not hasattr(select, "kqueue"):
            if sys.platform == "darwin":
                raise AppleArtifactGateError(
                    "held Apple artifact custody requires Darwin kqueue"
                )
            return
        queue = select.kqueue()
        directory_flags = (
            getattr(select, "KQ_NOTE_DELETE", 0)
            | getattr(select, "KQ_NOTE_RENAME", 0)
            | getattr(select, "KQ_NOTE_REVOKE", 0)
            | getattr(select, "KQ_NOTE_ATTRIB", 0)
        )
        file_flags = (
            directory_flags
            | getattr(select, "KQ_NOTE_WRITE", 0)
            | getattr(select, "KQ_NOTE_EXTEND", 0)
            | getattr(select, "KQ_NOTE_LINK", 0)
        )
        directory_descriptors = [record[2] for record in self._records]
        self._watch_labels = {
            record[2]: (record[1] or "/") for record in self._records
        }
        self._watch_labels[self.source_parent_fd] = "retained-parent"
        self._watch_labels[self.source_fd] = "retained-artifact"
        try:
            events = [
                select.kevent(
                    fd,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=directory_flags,
                )
                for fd in (*directory_descriptors, self.source_parent_fd)
            ]
            events.append(
                select.kevent(
                    self.source_fd,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=file_flags,
                )
            )
            queue.control(events, 0, 0)
        except Exception:
            queue.close()
            raise
        self._queue = queue

    def _reject_events(self) -> None:
        if self._queue is None:
            return
        events = self._queue.control(
            None,
            max(1, (len(self._records) + 2) * 2),
            0,
        )
        if events:
            detail = ",".join(
                f"{self._watch_labels.get(int(event.ident), 'descriptor')}:"
                f"0x{int(event.fflags):x}"
                for event in events[:8]
            )
            raise AppleArtifactGateError(
                "held Apple artifact, path, or ancestor changed during verification: "
                + detail
            )

    @staticmethod
    def _reject_reparse(info: os.stat_result) -> None:
        attributes = int(getattr(info, "st_file_attributes", 0))
        if attributes & 0x400:
            raise AppleArtifactGateError(
                "held Apple artifact path contains a reparse point"
            )

    def verify(self, *, rehash: bool = False) -> None:
        if self._closed or self.source_fd < 0 or self.source_parent_fd < 0:
            raise AppleArtifactGateError("held Apple artifact custody is closed")
        self._reject_events()
        _require_read_only_descriptor(self.source_fd, "held Apple artifact")
        _require_read_only_descriptor(
            self.source_parent_fd, "held Apple artifact parent"
        )
        for parent_fd, name, fd, expected in self._records:
            current = os.fstat(fd)
            self._reject_reparse(current)
            if _held_directory_identity(current) != expected:
                raise AppleArtifactGateError(
                    "held Apple artifact ancestor identity changed"
                )
            if parent_fd is not None:
                try:
                    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except OSError as exc:
                    raise AppleArtifactGateError(
                        "held Apple artifact ancestor was replaced or removed"
                    ) from exc
                self._reject_reparse(named)
                if _held_directory_identity(named) != expected:
                    raise AppleArtifactGateError(
                        "held Apple artifact ancestor was substituted or restored"
                    )

        source = os.fstat(self.source_fd)
        parent = os.fstat(self.source_parent_fd)
        canonical_parent = os.fstat(self._canonical_parent_fd)
        try:
            named = os.stat(
                self.source_name,
                dir_fd=self.source_parent_fd,
                follow_symlinks=False,
            )
            canonical_named = os.stat(
                self.source_name,
                dir_fd=self._canonical_parent_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise AppleArtifactGateError(
                "held Apple artifact name was replaced or removed"
            ) from exc
        for info in (source, named, canonical_named):
            self._reject_reparse(info)
        _require_unique_casefold_child(
            self.source_parent_fd, self.source_name, "held Apple artifact"
        )
        _require_unique_casefold_child(
            self._canonical_parent_fd, self.source_name, "held Apple artifact"
        )
        if (
            not stat.S_ISREG(source.st_mode)
            or source.st_nlink != 1
            or source.st_size != self.source_size
            or _held_artifact_identity(source) != self.source_identity
            or _held_artifact_identity(named) != self.source_identity
            or _held_artifact_identity(canonical_named) != self.source_identity
            or _held_directory_identity(parent)
            != _held_directory_identity(canonical_parent)
        ):
            raise AppleArtifactGateError(
                "held Apple artifact descriptor, name, parent, path, size, or identity is not exact"
            )
        if rehash and _sha256_fd(self.source_fd, self.source_size) != self.source_sha256:
            raise AppleArtifactGateError(
                "held Apple artifact SHA-256 does not match the frozen candidate"
            )
        self._reject_events()

    def rehash(self) -> str:
        self.verify(rehash=True)
        return self.source_sha256

    def close(self, *, verify: bool = True) -> None:
        if self._closed:
            return
        error: BaseException | None = None
        if verify:
            try:
                self.verify(rehash=True)
            except BaseException as exc:
                error = exc
        self._closed = True
        if self._queue is not None:
            try:
                self._queue.close()
            except OSError:
                pass
            self._queue = None
        if self.source_fd >= 0:
            os.close(self.source_fd)
            self.source_fd = -1
        if self.source_parent_fd >= 0:
            os.close(self.source_parent_fd)
            self.source_parent_fd = -1
        for _parent_fd, _name, fd, _expected in reversed(self._records):
            try:
                os.close(fd)
            except OSError:
                pass
        self._records.clear()
        self._watch_labels.clear()
        self._canonical_parent_fd = -1
        if error is not None:
            raise error


class HeldAppleArtifactEvidence:
    """Closeable, one-consumer evidence that retains every release authority."""

    def __init__(
        self,
        *,
        evidence: Mapping[str, object],
        private: PrivateGateRoot,
        temporary_owner: tempfile.TemporaryDirectory[str],
        private_token: contextvars.Token[PrivateGateRoot | None],
        custody: HeldAppleArtifactCustody,
        snapshot: AuthenticatedPkgSnapshot,
        review_custody: _HeldSupportSources,
        candidate_key: tuple[object, ...],
    ) -> None:
        payload = json.dumps(
            dict(evidence),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        with _ACTIVE_HELD_EVIDENCE_LOCK:
            if _ACTIVE_HELD_EVIDENCE_KEYS:
                raise AppleArtifactGateError(
                    "held Apple evidence cannot overlap or replay another candidate"
                )
            _ACTIVE_HELD_EVIDENCE_KEYS.add(candidate_key)
        self._payload = payload
        self._private = private
        self._temporary_owner = temporary_owner
        self._private_token = private_token
        self._custody = custody
        self._snapshot = snapshot
        self._review_custody = review_custody
        self._gate_support_custody: _HeldSupportSources | None = None
        self._candidate_key = candidate_key
        self._consumed = False
        self._closed = False
        try:
            self._revalidate()
        except Exception:
            with _ACTIVE_HELD_EVIDENCE_LOCK:
                _ACTIVE_HELD_EVIDENCE_KEYS.discard(candidate_key)
            self._closed = True
            raise

    @property
    def closed(self) -> bool:
        return self._closed

    def _adopt_gate_support_custody(self, custody: _HeldSupportSources) -> None:
        if self._closed or self._gate_support_custody is not None:
            raise AppleArtifactGateError(
                "held Apple evidence gate-support custody cannot be replayed"
            )
        _validate_support_custody(custody)
        self._gate_support_custody = custody
        self._revalidate()

    def _revalidate(self) -> None:
        if self._closed:
            raise AppleArtifactGateError("held Apple evidence custody is closed")
        self._snapshot.rehash()
        self._custody.rehash()
        self._review_custody.verify()
        if self._gate_support_custody is not None:
            _validate_support_custody(self._gate_support_custody)

    def consume(self, callback):
        """Expose one plain dict only while all custody remains live."""

        if not callable(callback):
            raise AppleArtifactGateError(
                "held Apple evidence consumer must be callable"
            )
        if self._consumed:
            raise AppleArtifactGateError("held Apple evidence was already consumed")
        if self._gate_support_custody is None:
            raise AppleArtifactGateError(
                "held Apple evidence support custody is incomplete"
            )
        self._consumed = True
        try:
            self._revalidate()
            evidence = json.loads(
                self._payload.decode("ascii"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
            result = callback(evidence)
            self._revalidate()
            if result is evidence or isinstance(result, (dict, list, set)):
                raise AppleArtifactGateError(
                    "held Apple evidence consumer cannot return mutable evidence"
                )
            return result
        finally:
            self.close(verify=True)

    def close(self, *, verify: bool = True) -> None:
        if self._closed:
            return
        error: BaseException | None = None
        if verify:
            try:
                self._revalidate()
            except BaseException as exc:
                error = exc
        self._closed = True
        with _ACTIVE_HELD_EVIDENCE_LOCK:
            _ACTIVE_HELD_EVIDENCE_KEYS.discard(self._candidate_key)

        def remember(exc: BaseException) -> None:
            nonlocal error
            if error is None:
                error = exc

        try:
            self._snapshot.close()
        except BaseException as exc:
            remember(exc)
        try:
            _cleanup_private_root(self._private)
        except BaseException as exc:
            remember(exc)
        try:
            self._temporary_owner.cleanup()
        except BaseException as exc:
            remember(exc)
        try:
            _PRIVATE_ROOT.reset(self._private_token)
        except BaseException as exc:
            remember(exc)
        try:
            self._custody.close(verify=verify)
        except BaseException as exc:
            remember(exc)
        try:
            self._review_custody.close(verify=verify)
        except BaseException as exc:
            remember(exc)
        if self._gate_support_custody is not None:
            try:
                self._gate_support_custody.close(verify=verify)
            except BaseException as exc:
                remember(exc)
            self._gate_support_custody = None
        if error is not None:
            raise error

    def __enter__(self) -> HeldAppleArtifactEvidence:
        if self._closed:
            raise AppleArtifactGateError("held Apple evidence custody is closed")
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close(verify=True)

    def __del__(self) -> None:
        try:
            self.close(verify=False)
        except Exception:
            pass


class AuthenticatedTreeSnapshot:
    def __init__(
        self,
        root: pathlib.Path,
        fd: int,
        identity: tuple[int, ...],
        records: list[dict[str, object]],
        digest: str,
    ) -> None:
        self.root = root
        self.fd = fd
        self.identity = identity
        self.records = records
        self.digest = digest

    def ensure_bound(self) -> None:
        if self.fd < 0:
            raise AppleArtifactGateError(
                "Apple PKG expanded-tree snapshot descriptor is closed"
            )
        try:
            current = os.fstat(self.fd)
            latest = self.root.lstat()
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple PKG expanded-tree snapshot was replaced"
            ) from exc
        if _file_identity(current) != self.identity or _file_identity(latest) != self.identity:
            raise AppleArtifactGateError(
                "Apple PKG expanded-tree snapshot identity changed"
            )

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


_PRIVATE_ROOT: contextvars.ContextVar[PrivateGateRoot | None] = contextvars.ContextVar(
    "winsvpn_apple_gate_private_root",
    default=None,
)
_TREE_SNAPSHOT: contextvars.ContextVar[AuthenticatedTreeSnapshot | None] = contextvars.ContextVar(
    "winsvpn_apple_gate_tree_snapshot",
    default=None,
)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AppleArtifactGateError(
                f"Apple JSON document has duplicate key: {key}"
            )
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> typing.NoReturn:
    raise AppleArtifactGateError(
        f"Apple JSON document contains a nonfinite number: {value}"
    )


def _contains_ascii_control(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _reject_signer_text(output: str, label: str) -> None:
    if type(output) is not str:
        raise AppleArtifactGateError(f"{label} is not exact ASCII line-oriented text")
    for character in output:
        code = ord(character)
        if character == "\n":
            continue
        if code < 0x20 or code > 0x7E:
            raise AppleArtifactGateError(
                f"{label} contains forbidden Unicode, bidi, BOM, or control characters"
            )


def _exact_release_authority_line(expected_authority: str) -> str:
    if type(expected_authority) is not str or not expected_authority.endswith(":"):
        raise AppleArtifactGateError("Apple signature authority prefix is malformed")
    return f"{expected_authority} {OWNER_COMMON_NAME} ({TEAM_ID})"


def _codesign_requirement_for_authority(expected_authority: str) -> str:
    if expected_authority == APP_STORE_DISTRIBUTION_AUTHORITY:
        common_name = f"Apple Distribution: {OWNER_COMMON_NAME} ({TEAM_ID})"
        return (
            f'anchor apple generic and certificate leaf[subject.OU] = "{TEAM_ID}" '
            f'and certificate leaf[subject.CN] = "{common_name}" '
            f"and certificate leaf[field.{APPLE_DISTRIBUTION_LEAF_OID}] exists "
            f"and certificate 1[field.{APPLE_WWDR_INTERMEDIATE_OID}] exists"
        )
    if expected_authority == DEVELOPER_ID_APPLICATION_AUTHORITY:
        common_name = f"Developer ID Application: {OWNER_COMMON_NAME} ({TEAM_ID})"
        return (
            f'anchor apple generic and certificate leaf[subject.OU] = "{TEAM_ID}" '
            f'and certificate leaf[subject.CN] = "{common_name}" '
            f"and certificate leaf[field.{DEVELOPER_ID_APPLICATION_LEAF_OID}] exists "
            f"and certificate 1[field.{DEVELOPER_ID_CA_OID}] exists"
        )
    raise AppleArtifactGateError("Apple code-signature designated requirement is unknown")


def _tree_entry_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        int(getattr(info, "st_flags", 0)),
        int(getattr(info, "st_gen", 0)),
    )


def _require_fchflags(fd: int, flags: int) -> None:
    if flags == 0:
        return
    if _LIBC is None or not hasattr(_LIBC, "fchflags"):
        raise AppleArtifactGateError("Apple gate could not update descriptor flags")
    rc = _LIBC.fchflags(fd, flags)
    if rc != 0:
        err = ctypes.get_errno()
        raise AppleArtifactGateError(
            "Apple gate could not update descriptor flags"
        ) from OSError(err, os.strerror(err))
    try:
        current = os.fstat(fd)
    except OSError as exc:
        raise AppleArtifactGateError("Apple gate could not update descriptor flags") from exc
    if int(getattr(current, "st_flags", 0)) & flags != flags:
        raise AppleArtifactGateError("Apple gate could not seal descriptor flags")


def _directory_tree_identities(dir_fd: int) -> tuple[tuple[str, tuple[int, ...]], ...]:
    records: list[tuple[str, tuple[int, ...]]] = []

    def walk(current_fd: int, prefix: str) -> None:
        try:
            names = os.listdir(current_fd)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple gate execution target tree is unreadable"
            ) from exc
        for name in sorted(names):
            if name in {".", ".."}:
                continue
            if name in {"", "."} or "/" in name or "\x00" in name:
                raise AppleArtifactGateError("Apple gate path component is unsafe")
            try:
                info = os.lstat(name, dir_fd=current_fd)
            except OSError as exc:
                raise AppleArtifactGateError(
                    "Apple gate execution target tree is unreadable"
                ) from exc
            relative = name if not prefix else f"{prefix}/{name}"
            records.append((relative, _tree_entry_identity(info)))
            if stat.S_ISLNK(info.st_mode):
                continue
            if stat.S_ISDIR(info.st_mode):
                child = _openat_child(current_fd, name, _dir_open_flags())
                try:
                    walk(child, relative)
                finally:
                    os.close(child)

    duplicate = os.dup(dir_fd)
    try:
        try:
            root_info = os.fstat(duplicate)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple gate execution target tree is unreadable"
            ) from exc
        if not stat.S_ISDIR(root_info.st_mode):
            raise AppleArtifactGateError("Apple gate execution target must be a directory")
        records.append((".", _tree_entry_identity(root_info)))
        walk(duplicate, "")
    finally:
        os.close(duplicate)
    return tuple(sorted(records))


def _root_rename_stable_identity(identity: tuple[int, ...]) -> tuple[int, ...]:
    try:
        (
            st_dev,
            st_ino,
            st_uid,
            st_mode,
            st_nlink,
            st_size,
            st_mtime_ns,
            _st_ctime_ns,
            st_flags,
            st_gen,
        ) = identity
    except ValueError as exc:
        raise AppleArtifactGateError(
            "Apple gate execution target tree is unreadable"
        ) from exc
    return (
        st_dev,
        st_ino,
        st_uid,
        st_mode,
        st_nlink,
        st_size,
        st_mtime_ns,
        0,
        st_flags,
        st_gen,
    )


def _execution_tree_identity(
    records: tuple[tuple[str, tuple[int, ...]], ...],
) -> tuple[tuple[str, tuple[int, ...]], ...]:
    normalized: list[tuple[str, tuple[int, ...]]] = []
    saw_root = False
    for path, identity in records:
        if path != ".":
            normalized.append((path, identity))
            continue
        if saw_root:
            raise AppleArtifactGateError(
                "Apple gate execution target tree was replaced"
            )
        saw_root = True
        normalized.append((path, _root_rename_stable_identity(identity)))
    if not saw_root:
        raise AppleArtifactGateError("Apple gate execution target tree was replaced")
    return tuple(normalized)


def _require_execution_tree_unchanged(
    before: tuple[tuple[str, tuple[int, ...]], ...],
    after: tuple[tuple[str, tuple[int, ...]], ...],
    *,
    raw: bool,
) -> None:
    if raw:
        matched = after == before
    else:
        matched = _execution_tree_identity(after) == _execution_tree_identity(before)
    if not matched:
        raise AppleArtifactGateError(
            "Apple gate execution target tree was replaced"
        )


def _quarantine_name() -> str:
    return QUARANTINE_NAME_PREFIX + secrets.token_hex(16)


def _identity_safe_unlink(
    dir_fd: int,
    name: str,
    expected: tuple[int, int],
    file_fd: int | None = None,
    *,
    clear_held_flags: bool = False,
) -> None:
    if not _zip_member_name_is_safe(name):
        raise AppleArtifactGateError("Apple zip contains an unsafe member path")
    if clear_held_flags and file_fd is not None:
        _clear_held_unlink_blocking_flags(file_fd)
    qdir = _quarantine_name()
    try:
        os.mkdir(qdir, 0o700, dir_fd=dir_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    qdir_fd = -1
    opened = -1
    moved = False
    leave_quarantined = False
    try:
        qdir_fd = os.open(qdir, _dir_open_flags(), dir_fd=dir_fd)
        os.fchmod(qdir_fd, 0o700)
        try:
            os.rename(
                name,
                QUARANTINE_HELD_NAME,
                src_dir_fd=dir_fd,
                dst_dir_fd=qdir_fd,
            )
        except FileNotFoundError:
            return
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple zip failed extraction could not be cleaned"
            ) from exc
        moved = True
        try:
            named = os.lstat(QUARANTINE_HELD_NAME, dir_fd=qdir_fd)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple zip failed extraction could not be cleaned"
            ) from exc
        if _zip_inode_key(named) != expected:
            try:
                os.rename(
                    QUARANTINE_HELD_NAME,
                    name,
                    src_dir_fd=qdir_fd,
                    dst_dir_fd=dir_fd,
                )
                moved = False
            except OSError:
                pass
            raise AppleArtifactGateError(
                "Apple gate cleanup refused a substituted name"
            )
        is_link = stat.S_ISLNK(named.st_mode)
        is_reg = stat.S_ISREG(named.st_mode) and not is_link
        if is_reg:
            try:
                opened = os.open(
                    QUARANTINE_HELD_NAME,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=qdir_fd,
                )
            except OSError as exc:
                raise AppleArtifactGateError(
                    "Apple zip failed extraction could not be cleaned"
                ) from exc
            opened_info = os.fstat(opened)
            if _zip_inode_key(opened_info) != expected:
                raise AppleArtifactGateError(
                    "Apple gate cleanup refused a substituted name"
                )
            _clear_held_unlink_blocking_flags(opened)
        if file_fd is not None:
            try:
                held = os.fstat(file_fd)
            except OSError as exc:
                raise AppleArtifactGateError(
                    "Apple zip failed extraction could not be cleaned"
                ) from exc
            if _zip_inode_key(held) != expected:
                raise AppleArtifactGateError(
                    "Apple gate cleanup refused a substituted name"
                )
        if UF_IMMUTABLE:
            _require_fchflags(qdir_fd, UF_IMMUTABLE)
        named = os.lstat(QUARANTINE_HELD_NAME, dir_fd=qdir_fd)
        if _zip_inode_key(named) != expected:
            raise AppleArtifactGateError(
                "Apple gate cleanup refused a substituted name"
            )
        nlink_before = int(named.st_nlink)
        if is_reg:
            if opened < 0:
                raise AppleArtifactGateError(
                    "Apple zip failed extraction could not be cleaned"
                )
            opened_info = os.fstat(opened)
            if _zip_inode_key(opened_info) != expected:
                raise AppleArtifactGateError(
                    "Apple gate cleanup refused a substituted name"
                )
            nlink_before = int(opened_info.st_nlink)
            kernel = _authenticate_volfs(
                opened,
                _vnode_identity(opened_info, directory=False),
                directory=False,
            )
        else:
            kernel = _volfs_path(named)
            try:
                kernel_info = os.lstat(kernel)
            except OSError as exc:
                raise AppleArtifactGateError(
                    "Apple zip failed extraction could not be cleaned"
                ) from exc
            if _zip_inode_key(kernel_info) != expected:
                raise AppleArtifactGateError(
                    "Apple gate cleanup refused a substituted name"
                )
        if nlink_before < 1:
            raise AppleArtifactGateError(
                "Apple zip failed extraction could not be cleaned"
            )
        _clear_held_unlink_blocking_flags(qdir_fd)
        os.fchmod(qdir_fd, 0o700)
        os.unlink(kernel)
        try:
            os.lstat(QUARANTINE_HELD_NAME, dir_fd=qdir_fd)
        except FileNotFoundError:
            pass
        else:
            raise AppleArtifactGateError(
                "Apple zip failed extraction could not be cleaned"
            )
        if is_reg and opened >= 0:
            after = os.fstat(opened)
            if int(after.st_nlink) != nlink_before - 1:
                raise AppleArtifactGateError(
                    "Apple zip failed extraction could not be cleaned"
                )
        moved = False
    except AppleArtifactGateError:
        raise
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    finally:
        if opened >= 0:
            os.close(opened)
        if qdir_fd >= 0:
            try:
                _clear_held_unlink_blocking_flags(qdir_fd)
                os.fchmod(qdir_fd, 0o700)
            except (AppleArtifactGateError, OSError):
                pass
            if moved and not leave_quarantined:
                try:
                    os.rename(
                        QUARANTINE_HELD_NAME,
                        name,
                        src_dir_fd=qdir_fd,
                        dst_dir_fd=dir_fd,
                    )
                except OSError:
                    leave_quarantined = True
            os.close(qdir_fd)
        if not leave_quarantined:
            try:
                os.rmdir(qdir, dir_fd=dir_fd)
            except OSError:
                pass


def _identity_safe_rmdir(dir_fd: int, name: str, expected: tuple[int, int]) -> None:
    if not _zip_member_name_is_safe(name):
        raise AppleArtifactGateError("Apple zip contains an unsafe member path")
    quarantine = _quarantine_name()
    try:
        os.rename(name, quarantine, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    try:
        named = os.lstat(quarantine, dir_fd=dir_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or _zip_inode_key(named) != expected
    ):
        try:
            os.rename(quarantine, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except OSError:
            pass
        raise AppleArtifactGateError(
            "Apple gate cleanup refused a substituted name"
        )
    try:
        os.rmdir(quarantine, dir_fd=dir_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        if getattr(exc, "errno", None) in {
            errno.ENOTEMPTY,
            errno.EEXIST,
            errno.EPERM,
            errno.EACCES,
        }:
            try:
                os.rename(quarantine, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            except OSError:
                pass
            return
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc


def reviewed_apple_release_identity() -> tuple[str, str]:
    """Return the exact marketing and build versions from the reviewed ruling."""

    fd = -1
    try:
        fd, _path, _identity = _bind_repo_relative(RELEASE_IDENTITY_RELATIVE_PATH)
        info = os.fstat(fd)
        if info.st_size <= 0 or info.st_size > MAX_RECEIPT_FILE_BYTES:
            raise AppleArtifactGateError("Apple release identity is unreadable")
        payload = os.pread(fd, info.st_size, 0)
        if len(payload) != info.st_size:
            raise AppleArtifactGateError("Apple release identity mutated while it was read")
        identity = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except AppleArtifactGateError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AppleArtifactGateError("Apple release identity is unreadable") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if type(identity) is not dict or set(identity) != {
        "schema_version",
        "canonical_release",
        "marketing_version",
        "build_number",
        "platform_mappings",
    }:
        raise AppleArtifactGateError("Apple release identity top-level schema is not exact")
    marketing = identity.get("marketing_version")
    build = identity.get("build_number")
    mappings = identity.get("platform_mappings")
    apple = mappings.get("apple") if type(mappings) is dict else None
    required_upload = apple.get("required_upload_targets") if type(apple) is dict else None
    required_artifacts = apple.get("required_artifacts") if type(apple) is dict else None
    optional_distribution = apple.get("optional_distribution") if type(apple) is dict else None
    optional_evidence = apple.get("optional_evidence_targets") if type(apple) is dict else None
    shipping = apple.get("shipping_surfaces") if type(apple) is dict else None
    identity_tokens: list[str] = []
    for value in (
        required_upload,
        required_artifacts,
        optional_distribution,
        optional_evidence,
        shipping,
    ):
        if type(value) is list:
            identity_tokens.extend(str(item).casefold().replace("_", "-") for item in value)
    if any(
        token in FORBIDDEN_TVOS_IDENTITY_TOKENS
        or "tvos" in token
        or "appletv" in token
        or token.startswith("apple-tv")
        or "-apple-tv" in token
        for token in identity_tokens
    ):
        raise AppleArtifactGateError(TVOS_NOT_A_CURRENT_SURFACE)
    if (
        identity.get("schema_version") != 2
        or type(marketing) is not str
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", marketing) is None
        or type(build) is not int
        or isinstance(build, bool)
        or build <= 0
        or identity.get("canonical_release") != CANONICAL_RELEASE
        or identity.get("canonical_release") != f"{marketing}+{build}"
        or marketing != CANONICAL_MARKETING_VERSION
        or str(build) != CANONICAL_BUNDLE_VERSION
        or type(apple) is not dict
        or apple.get("short_version") != marketing
        or apple.get("bundle_version") != CANONICAL_BUNDLE_VERSION
        or list(required_upload or []) != list(REQUIRED_APPLE_UPLOAD_TARGETS)
        or list(required_artifacts or []) != list(REQUIRED_APPLE_ARTIFACTS)
        or list(optional_distribution or []) != list(OPTIONAL_APPLE_DISTRIBUTION)
        or list(optional_evidence or []) != list(OPTIONAL_APPLE_UPLOAD_TARGETS)
        or type(shipping) is not list
        or tuple(shipping) != APPLE_SHIPPING_SURFACES
    ):
        raise AppleArtifactGateError("Apple release identity is inconsistent")
    return marketing, str(build)


def _macos_exclusive_suffixes(target_id: str) -> tuple[str, ...]:
    suffixes = TARGET_SUFFIXES.get(target_id)
    if suffixes is None or target_id not in MACOS_PACKAGE_CHANNEL_CONTRACT:
        raise AppleArtifactGateError(
            f"unsupported macOS package channel target: {target_id}"
        )
    foreign: list[str] = []
    for other_id in MACOS_PACKAGE_CHANNEL_CONTRACT:
        if other_id == target_id:
            continue
        foreign.extend(TARGET_SUFFIXES[other_id])
    for suffix in suffixes:
        if suffix in foreign:
            raise AppleArtifactGateError(
                f"{target_id} package suffix {suffix} is not exclusive to its channel"
            )
    return suffixes


def _apple_target_suffixes(target_id: str) -> tuple[str, ...]:
    _refuse_non_shipping_apple_target(target_id)
    suffixes = TARGET_SUFFIXES.get(target_id)
    if suffixes is None:
        raise AppleArtifactGateError(f"unsupported Apple target: {target_id}")
    if target_id in MACOS_PACKAGE_CHANNEL_CONTRACT:
        return _macos_exclusive_suffixes(target_id)
    return suffixes


def macos_package_channel_contract(target_id: str) -> dict[str, object]:
    contract = MACOS_PACKAGE_CHANNEL_CONTRACT.get(target_id)
    if contract is None:
        raise AppleArtifactGateError(
            f"unsupported macOS package channel target: {target_id}"
        )
    return {
        "target_id": target_id,
        "channel": contract["channel"],
        "signing_contract": contract["signing_contract"],
        "expected_authority": contract["expected_authority"],
        "required": contract["required"],
        "suffixes": _macos_exclusive_suffixes(target_id),
        "signature_gate": "verify_signature",
        "signature_verified": False,
    }


def bind_macos_package_channel(
    target_id: str, raw_path: str | pathlib.Path
) -> dict[str, object]:
    contract = macos_package_channel_contract(target_id)
    artifact = canonical_artifact(target_id, raw_path)
    lowered = artifact.name.lower()
    suffixes = tuple(str(item) for item in contract["suffixes"])
    matched = [suffix for suffix in suffixes if lowered.endswith(suffix)]
    if len(matched) != 1:
        raise AppleArtifactGateError(
            f"{target_id} artifact suffix does not bind its package channel"
        )
    return {
        "target_id": target_id,
        "artifact": artifact,
        "channel": contract["channel"],
        "signing_contract": contract["signing_contract"],
        "expected_authority": contract["expected_authority"],
        "required": contract["required"],
        "suffix": matched[0],
        "signature_gate": contract["signature_gate"],
        "signature_verified": False,
    }


def canonical_artifact(target_id: str, raw_path: str | pathlib.Path) -> pathlib.Path:
    suffixes = _apple_target_suffixes(target_id)
    path = pathlib.Path(raw_path)
    fd, lexical, identity = _bind_repo_relative(path)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size <= 0
            or info.st_nlink != 1
            or identity != _pkg_vnode_identity(info)
        ):
            raise AppleArtifactGateError(
                "Apple gate artifact must be a non-empty regular single-link file"
            )
        named = lexical.lstat()
        if stat.S_ISLNK(named.st_mode) or _pkg_vnode_identity(named) != identity:
            raise AppleArtifactGateError(
                "Apple gate artifact path must not contain symlinks"
            )
        lowered = lexical.name.lower()
        if not any(lowered.endswith(suffix) for suffix in suffixes):
            raise AppleArtifactGateError(
                f"{target_id} requires artifact suffix: {', '.join(suffixes)}"
            )
        return lexical
    finally:
        os.close(fd)


def _sha256_file(path: pathlib.Path) -> str:
    fd = _bind_path_from_known_roots(path, directory=False)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 0:
            raise AppleArtifactGateError("Apple gate file hash requires a regular file")
        return _sha256_fd(fd, info.st_size)
    finally:
        os.close(fd)


def _volfs_path(info: os.stat_result) -> str:
    return f"/.vol/{info.st_dev}/{info.st_ino}"


def _authenticate_volfs(
    fd: int,
    identity: tuple[int, ...],
    *,
    directory: bool = False,
) -> str:
    if sys.platform != "darwin":
        raise _owner_environment_blocker(
            "exact PKG execution custody requires the macOS /.vol kernel boundary"
        )
    declared = pathlib.Path(os.path.normpath(os.fspath(VOLFS_ROOT)))
    if declared != pathlib.Path("/.vol"):
        raise _owner_environment_blocker(
            "macOS /.vol kernel identity path is unavailable"
        )
    try:
        root_info = pathlib.Path("/.vol").lstat()
    except OSError as exc:
        raise _owner_environment_blocker(
            "macOS /.vol kernel identity path is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != 0
    ):
        raise _owner_environment_blocker(
            "macOS /.vol is not the genuine kernel volume identity root"
        )
    try:
        current = os.fstat(fd)
        kernel_path = _volfs_path(current)
        named = os.lstat(kernel_path)
    except OSError as exc:
        raise _owner_environment_blocker(
            "authenticated inode is not addressable through /.vol"
        ) from exc
    current_id = _vnode_identity(current, directory=directory)
    named_id = _vnode_identity(named, directory=directory)
    type_ok = stat.S_ISDIR(named.st_mode) if directory else stat.S_ISREG(named.st_mode)
    if (
        stat.S_ISLNK(named.st_mode)
        or not type_ok
        or current_id != identity
        or named_id != identity
    ):
        raise AppleArtifactGateError(
            "Apple volfs identity does not match the authenticated snapshot"
        )
    return kernel_path


def _bundle_suffix(name: str) -> str | None:
    folded = name.casefold()
    for suffix in BUNDLE_SUFFIXES:
        if folded.endswith(suffix):
            return suffix
    return None


def _casefold_relative(relative: str) -> str:
    parts = pathlib.PurePosixPath(relative).parts
    return "/".join(part.casefold() for part in parts)


class _UniquePlist(dict):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__()
        if args:
            items = args[0]
            if isinstance(items, dict):
                items = items.items()
            for key, value in items:
                self[key] = value
        for key, value in kwargs.items():
            self[key] = value

    def __setitem__(self, key, value) -> None:
        if key in self:
            raise AppleArtifactGateError(f"plist has a duplicate key: {key}")
        super().__setitem__(key, value)


def _lstat_entry(path: pathlib.Path, relative: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise AppleArtifactGateError(
            f"Apple PKG expanded entry is unreadable: {relative}"
        ) from exc


def _scandir_children(directory: pathlib.Path, relative_dir: str) -> tuple[list[str], list[str]]:
    dirnames: list[str] = []
    filenames: list[str] = []
    folded: dict[str, str] = {}
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                name = entry.name
                if _contains_ascii_control(name):
                    raise AppleArtifactGateError(
                        "Apple PKG expanded path contains control characters"
                    )
                key = name.casefold()
                if key in folded:
                    raise AppleArtifactGateError(
                        "Apple PKG expanded path has a case-fold collision: "
                        f"{folded[key]} and {name}"
                    )
                folded[key] = name
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError as exc:
                    location = name if relative_dir == "." else f"{relative_dir}/{name}"
                    raise AppleArtifactGateError(
                        f"Apple PKG expanded entry is unreadable: {location}"
                    ) from exc
                if is_dir:
                    dirnames.append(name)
                else:
                    filenames.append(name)
    except AppleArtifactGateError:
        raise
    except OSError as exc:
        raise AppleArtifactGateError(
            f"Apple PKG expansion is unreadable: {relative_dir}"
        ) from exc
    dirnames.sort()
    filenames.sort()
    return dirnames, filenames


def _walk_tree(root: pathlib.Path) -> list[tuple[pathlib.Path, str, os.stat_result]]:
    if root.is_symlink() or not root.is_dir():
        raise AppleArtifactGateError("Apple PKG expansion destination is unsafe")
    entries: list[tuple[pathlib.Path, str, os.stat_result]] = []
    folded_seen: dict[str, str] = {}
    stack = [root]
    while stack:
        current = stack.pop()
        relative_dir = "." if current == root else _lexical_relative(current, root)
        if current != root and current.is_symlink():
            raise AppleArtifactGateError("Apple PKG expansion followed a directory symlink")
        dirnames, filenames = _scandir_children(current, relative_dir)
        for name in dirnames:
            path = current / name
            relative = _lexical_relative(path, root)
            folded = _casefold_relative(relative)
            if folded in folded_seen and folded_seen[folded] != relative:
                raise AppleArtifactGateError(
                    "Apple PKG expanded path has a case-fold collision: "
                    f"{folded_seen[folded]} and {relative}"
                )
            folded_seen[folded] = relative
            info = _lstat_entry(path, relative)
            entries.append((path, relative, info))
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                stack.append(path)
        for name in filenames:
            path = current / name
            relative = _lexical_relative(path, root)
            folded = _casefold_relative(relative)
            if folded in folded_seen and folded_seen[folded] != relative:
                raise AppleArtifactGateError(
                    "Apple PKG expanded path has a case-fold collision: "
                    f"{folded_seen[folded]} and {relative}"
                )
            folded_seen[folded] = relative
            info = _lstat_entry(path, relative)
            entries.append((path, relative, info))
    entries.sort(key=lambda item: item[1])
    return entries


def _reviewed_tool(path: str) -> str:
    return _authenticate_system_tool(path)


def _redact_tool_output(text: str) -> str:
    if not text:
        return ""
    redacted = text.replace("\x00", "")
    for key, value in os.environ.items():
        if (
            SECRET_ENV_KEY_RE.search(key)
            and isinstance(value, str)
            and len(value) >= 8
            and value in redacted
        ):
            redacted = redacted.replace(value, "<redacted>")
    redacted = re.sub(
        r"(?i)(?:token|secret|password|api[_-]?key|authorization|cookie)\s*[=:]\s*\S+",
        "<redacted>",
        redacted,
    )
    if len(redacted) > MAX_FAILURE_BYTES:
        redacted = redacted[:MAX_FAILURE_BYTES] + "<truncated>"
    return redacted


def _subprocess_env() -> dict[str, str]:
    private = _PRIVATE_ROOT.get()
    home = str(private.home) if private is not None else "/var/empty"
    tmpdir = str(private.tmp) if private is not None else "/tmp"
    return {
        "PATH": REVIEWED_SUBPROCESS_PATH,
        "HOME": home,
        "TMPDIR": tmpdir,
        "LANG": "C",
        "LC_ALL": "C",
    }


def _apply_child_rlimits() -> None:
    def set_limit(resource_id: int, value: int) -> None:
        soft, hard = resource.getrlimit(resource_id)
        if hard != resource.RLIM_INFINITY and hard < value:
            raise OSError("reviewed child resource bound exceeds the hard limit")
        cap = value if hard == resource.RLIM_INFINITY else min(value, hard)
        new_hard = hard if hard != resource.RLIM_INFINITY else cap
        resource.setrlimit(resource_id, (cap, new_hard))

    try:
        set_limit(resource.RLIMIT_CORE, 0)
        set_limit(resource.RLIMIT_CPU, PKGUTIL_CPU_SEC)
        set_limit(resource.RLIMIT_FSIZE, MAX_INNER_FILE_BYTES)
        set_limit(resource.RLIMIT_NOFILE, CHILD_NOFILE)
    except (ValueError, OSError):
        os._exit(127)


def _apply_tool_rlimits() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        cpu_soft, cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)
        del cpu_soft
        cpu_cap = TOOL_TIMEOUT_SEC if cpu_hard == resource.RLIM_INFINITY else min(
            TOOL_TIMEOUT_SEC, cpu_hard
        )
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_cap, cpu_cap))
        nofile_soft, nofile_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        del nofile_soft
        nofile_cap = CHILD_NOFILE if nofile_hard == resource.RLIM_INFINITY else min(
            CHILD_NOFILE, nofile_hard
        )
        resource.setrlimit(resource.RLIMIT_NOFILE, (nofile_cap, nofile_cap))
        fsize_soft, fsize_hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        del fsize_soft
        fsize_cap = (
            MAX_TOOL_OUTPUT_BYTES
            if fsize_hard == resource.RLIM_INFINITY
            else min(MAX_TOOL_OUTPUT_BYTES, fsize_hard)
        )
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_cap, fsize_cap))
    except (ValueError, OSError):
        os._exit(127)


def _reviewed_xcrun_lookup(found: str, name: str) -> bool:
    path = pathlib.PurePosixPath(found)
    if (
        not found
        or _contains_ascii_control(found)
        or not path.is_absolute()
        or ".." in path.parts
        or path.name != name
        or path.parent.name != "bin"
    ):
        return False
    try:
        info = os.stat(found)
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _warm_xcrun_lookup(name: str) -> None:
    """Fill xcrun's cache entry for ``name`` in the exact child environment."""

    env = _subprocess_env()
    key = (env["HOME"], env["TMPDIR"], name)
    if key in _XCRUN_WARMED:
        return
    completed = _bounded_subprocess(
        [_reviewed_tool(XCRUN), "--find", name],
        f"xcrun lookup of {name}",
        cwd="/",
        env=env,
        timeout=TOOL_TIMEOUT_SEC,
        descendant_boundary=False,
    )
    found = completed.stdout.decode("utf-8", "replace").strip()
    if completed.returncode != 0 or not _reviewed_xcrun_lookup(found, name):
        raise _owner_environment_blocker(
            f"xcrun cannot resolve the reviewed Xcode tool {name}"
        )
    _XCRUN_WARMED.add(key)


def _run(
    argv: list[str],
    label: str,
    *,
    allow_exit: frozenset[int] = frozenset({0}),
    timeout: int = TOOL_TIMEOUT_SEC,
) -> subprocess.CompletedProcess[str]:
    if not argv:
        raise AppleArtifactGateError(f"{label} command is empty")
    argv = [_reviewed_tool(argv[0]), *argv[1:]]
    if argv[0] == XCRUN:
        if len(argv) < 2 or argv[1] not in XCRUN_RUN_TOOLS:
            raise AppleArtifactGateError(f"{label} names an unreviewed xcrun tool")
        _warm_xcrun_lookup(argv[1])
    elif argv[0] in XCRUN_SHIM_TOOLS:
        _warm_xcrun_lookup(XCRUN_SHIM_TOOLS[argv[0]])
    try:
        raw_completed = _bounded_subprocess(
            argv,
            label,
            cwd="/",
            env=_subprocess_env(),
            timeout=timeout,
            preexec_fn=_apply_tool_rlimits,
        )
        if (
            len(raw_completed.stdout) > MAX_TOOL_OUTPUT_BYTES
            or len(raw_completed.stderr) > MAX_TOOL_OUTPUT_BYTES
        ):
            raise AppleArtifactGateError(f"{label} exceeded the output bound")
        completed = subprocess.CompletedProcess(
            raw_completed.args,
            raw_completed.returncode,
            raw_completed.stdout.decode("utf-8", "strict"),
            raw_completed.stderr.decode("utf-8", "strict"),
        )
    except UnicodeError as exc:
        raise AppleArtifactGateError(f"{label} returned invalid UTF-8") from exc
    except OSError as exc:
        raise AppleArtifactGateError(
            f"{label} could not execute: {_redact_tool_output(str(exc))}"
        ) from exc
    if completed.returncode not in allow_exit:
        detail = _redact_tool_output((completed.stderr or completed.stdout).strip())
        raise AppleArtifactGateError(
            f"{label} failed with exit {completed.returncode}: {detail}"
        )
    return completed


def _run_on_path(
    argv_prefix: list[str],
    path: pathlib.Path,
    label: str,
    *,
    directory: bool = False,
    extra_argv: list[str] | None = None,
    allow_exit: frozenset[int] = frozenset({0}),
    timeout: int = TOOL_TIMEOUT_SEC,
) -> subprocess.CompletedProcess[str]:
    if not argv_prefix:
        raise AppleArtifactGateError(f"{label} command is empty")
    lexical_path = os.fspath(path)
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in lexical_path):
        raise AppleArtifactGateError(f"{label} path contains control characters")
    target = _bind_execution_target(path, directory=directory)
    inspect: SealedInspectionTarget | None = None
    try:
        tool = argv_prefix[0]
        if tool in NON_VOLFS_ARGV_TOOLS:
            inspect = _open_sealed_inspection_target(target, path)
            argument = inspect.path
            if _is_volfs_path(argument):
                raise AppleArtifactGateError(
                    "codesign cannot inspect /.vol kernel identity paths"
                )
        elif tool in VOLFS_ARGV_TOOLS:
            argument = target.kernel
        else:
            argument = lexical_path
        argv = [*argv_prefix, argument, *(extra_argv or [])]
        before_tree = (
            _directory_tree_identities(target.fd) if directory else None
        )
        private = _PRIVATE_ROOT.get()
        if private is not None:
            private.verify_ancestors()
        completed = _run(argv, label, allow_exit=allow_exit, timeout=timeout)
        if private is not None:
            private.verify_ancestors()
        if before_tree is not None:
            after_tool_tree = _directory_tree_identities(target.fd)
            _require_execution_tree_unchanged(
                before_tree, after_tool_tree, raw=True
            )
        if inspect is not None:
            inspect.ensure_same_inode(target)
            inspect.restore()
            inspect = None
        target.ensure_bound()
        if before_tree is not None:
            after_tree = _directory_tree_identities(target.fd)
            _require_execution_tree_unchanged(
                before_tree, after_tree, raw=False
            )
        try:
            named = os.lstat(path)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple gate execution target was replaced"
            ) from exc
        if _vnode_identity(named, directory=directory) != target.identity:
            raise AppleArtifactGateError(
                "Apple gate execution target was replaced"
            )
        return completed
    finally:
        if inspect is not None:
            inspect.restore()
        target.close()


def _zip_member_name(member: zipfile.ZipInfo) -> str:
    name = member.filename
    if (
        not name
        or "\\" in name
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
    ):
        raise AppleArtifactGateError("Apple zip contains an unsafe member path")
    try:
        name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AppleArtifactGateError("Apple zip member path is not UTF-8") from exc
    if unicodedata.normalize("NFC", name) != name:
        raise AppleArtifactGateError(
            "Apple zip contains a Unicode-normalization alias"
        )
    body = name.rstrip("/")
    path = pathlib.PurePosixPath(body)
    if (
        not body
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise AppleArtifactGateError("Apple zip contains an unsafe member path")
    return name


def _safe_zip_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    if not members or len(members) > MAX_EXPANDED_ENTRIES:
        raise AppleArtifactGateError("Apple zip member count is invalid")
    expanded_bytes = 0
    names: set[str] = set()
    nfc_folded: set[str] = set()
    declared_total = 0
    for member in members:
        name = _zip_member_name(member)
        encoded_name = name.rstrip("/").encode("utf-8")
        member_parts = pathlib.PurePosixPath(name.rstrip("/")).parts
        if len(encoded_name) > MAX_PATH_BYTES:
            raise AppleArtifactGateError("Apple zip member path exceeds the gate limit")
        if len(member_parts) > MAX_EXPANDED_DEPTH:
            raise AppleArtifactGateError("Apple zip member depth exceeds the gate limit")
        folded = unicodedata.normalize("NFC", name.rstrip("/")).casefold()
        if not folded or folded in nfc_folded or name in names:
            raise AppleArtifactGateError(
                "Apple zip contains duplicate, empty, or Unicode-normalization alias paths"
            )
        names.add(name)
        nfc_folded.add(folded)
        if member.flag_bits & 0x1:
            raise AppleArtifactGateError("Apple zip contains an encrypted member")
        if member.file_size < 0 or member.compress_size < 0:
            raise AppleArtifactGateError("Apple zip member size is invalid")
        if member.file_size > MAX_INNER_FILE_BYTES:
            raise AppleArtifactGateError("Apple zip expanded size exceeds the gate limit")
        compressed = max(member.compress_size, 1)
        if member.file_size / compressed > MAX_COMPRESSION_RATIO:
            raise AppleArtifactGateError("Apple zip compression ratio exceeds the gate limit")
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise AppleArtifactGateError("Apple app zip symlink entries are forbidden")
        file_type = stat.S_IFMT(mode)
        if file_type and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise AppleArtifactGateError("Apple zip contains a special filesystem entry")
        expanded_bytes += member.file_size
        declared_total += member.file_size
        if expanded_bytes > MAX_EXPANDED_BYTES or declared_total > MAX_OUTPUT_BYTES:
            raise AppleArtifactGateError("Apple zip expanded size exceeds the gate limit")
    if declared_total > MAX_EXPANDED_BYTES:
        raise AppleArtifactGateError("Apple zip expanded size exceeds the gate limit")
    return members


def _preflight_zip_local_headers(
    archive: zipfile.ZipFile, members: list[zipfile.ZipInfo]
) -> None:
    """Make every local header agree with the reviewed central-directory entry."""

    for member in members:
        try:
            with archive.open(member, "r") as source:
                if member.is_dir() and source.read(1):
                    raise AppleArtifactGateError(
                        "Apple zip directory member contains file data"
                    )
        except AppleArtifactGateError:
            raise
        except (
            EOFError,
            NotImplementedError,
            OSError,
            RuntimeError,
            UnicodeError,
            ValueError,
            struct.error,
            zipfile.BadZipFile,
        ) as exc:
            raise AppleArtifactGateError(
                "Apple zip local header does not match the central directory"
            ) from exc


def _bound_tree_entries(
    dir_fd: int,
) -> tuple[dict[str, os.stat_result], dict[str, str]]:
    """Walk a tree through held directory descriptors without following links."""

    records: dict[str, os.stat_result] = {}
    digests: dict[str, str] = {}
    folded_seen: dict[str, str] = {}

    def walk(current_fd: int, parents: tuple[str, ...]) -> None:
        before = os.fstat(current_fd)
        if not stat.S_ISDIR(before.st_mode):
            raise AppleArtifactGateError(
                "Apple expanded-tree descriptor is not a directory"
            )
        try:
            names = sorted(os.listdir(current_fd))
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple expanded tree is unreadable through its directory descriptor"
            ) from exc
        local_folded: dict[str, str] = {}
        for name in names:
            if (
                not name
                or name in {".", ".."}
                or _contains_ascii_control(name)
                or unicodedata.normalize("NFC", name) != name
            ):
                raise AppleArtifactGateError(
                    "Apple expanded path contains an unsafe name"
                )
            try:
                name.encode("utf-8", "strict")
            except UnicodeError as exc:
                raise AppleArtifactGateError(
                    "Apple expanded path is not valid UTF-8"
                ) from exc
            local_key = name.casefold()
            if local_key in local_folded:
                raise AppleArtifactGateError(
                    "Apple expanded path has a case-fold collision: "
                    f"{local_folded[local_key]} and {name}"
                )
            local_folded[local_key] = name
            parts = (*parents, name)
            relative = "/".join(parts)
            if (
                len(parts) > MAX_EXPANDED_DEPTH
                or len(relative.encode("utf-8")) > MAX_PATH_BYTES
            ):
                raise AppleArtifactGateError(
                    "Apple expanded path exceeds the gate limit"
                )
            folded = relative.casefold()
            if folded in folded_seen:
                raise AppleArtifactGateError(
                    "Apple expanded path has a case-fold collision: "
                    f"{folded_seen[folded]} and {relative}"
                )
            folded_seen[folded] = relative
            try:
                named = os.lstat(name, dir_fd=current_fd)
            except OSError as exc:
                raise AppleArtifactGateError(
                    f"Apple expanded entry is unreadable: {relative}"
                ) from exc
            records[relative] = named
            if len(records) > MAX_EXPANDED_ENTRIES:
                raise AppleArtifactGateError(
                    "Apple expanded entry count exceeds the gate limit"
                )
            if stat.S_ISDIR(named.st_mode) and not stat.S_ISLNK(named.st_mode):
                child = _openat_child(current_fd, name, _dir_open_flags())
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (
                        named.st_dev,
                        named.st_ino,
                    ):
                        raise AppleArtifactGateError(
                            f"Apple expanded directory changed: {relative}"
                        )
                    walk(child, parts)
                finally:
                    os.close(child)
            elif stat.S_ISREG(named.st_mode):
                child = _openat_child(current_fd, name, _open_flags())
                try:
                    opened = os.fstat(child)
                    if _pkg_vnode_identity(opened) != _pkg_vnode_identity(named):
                        raise AppleArtifactGateError(
                            f"Apple expanded file changed: {relative}"
                        )
                    digest = _sha256_fd(child, opened.st_size)
                    after_file = os.fstat(child)
                    if _file_identity(after_file) != _file_identity(opened):
                        raise AppleArtifactGateError(
                            f"Apple expanded file changed: {relative}"
                        )
                    records[relative] = after_file
                    digests[relative] = digest
                finally:
                    os.close(child)
        try:
            after_names = sorted(os.listdir(current_fd))
            after = os.fstat(current_fd)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple expanded directory changed during its descriptor walk"
            ) from exc
        for name in names:
            relative = "/".join((*parents, name))
            try:
                latest = os.lstat(name, dir_fd=current_fd)
            except OSError as exc:
                raise AppleArtifactGateError(
                    "Apple expanded directory changed during its descriptor walk"
                ) from exc
            if _file_identity(latest) != _file_identity(records[relative]):
                raise AppleArtifactGateError(
                    f"Apple expanded entry changed: {relative}"
                )
        if (
            after_names != names
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise AppleArtifactGateError(
                "Apple expanded directory changed during its descriptor walk"
            )

    root_fd = os.dup(dir_fd)
    try:
        walk(root_fd, ())
    finally:
        os.close(root_fd)
    return records, digests


def _validate_extracted_zip_tree(
    destination: pathlib.Path,
    dest_fd: int,
    members: list[zipfile.ZipInfo],
    expected_digests: Mapping[str, str],
) -> None:
    expected_dirs: set[str] = set()
    expected_files: dict[str, int] = {}
    for member in members:
        name = _zip_member_name(member).rstrip("/")
        parts = pathlib.PurePosixPath(name).parts
        mode = member.external_attr >> 16
        is_dir = member.filename.endswith("/") or (
            stat.S_IFMT(mode) and stat.S_ISDIR(mode)
        )
        for depth in range(1, len(parts)):
            expected_dirs.add("/".join(parts[:depth]))
        if is_dir:
            if member.file_size != 0:
                raise AppleArtifactGateError(
                    "Apple zip directory member contains file data"
                )
            expected_dirs.add(name)
        else:
            expected_files[name] = member.file_size

    actual, actual_digests = _bound_tree_entries(dest_fd)
    expected = expected_dirs | set(expected_files)
    if set(actual) != expected:
        raise AppleArtifactGateError(
            "Apple zip extracted tree does not match the authenticated member set"
        )
    total_bytes = 0
    for relative, info in actual.items():
        if relative in expected_dirs:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise AppleArtifactGateError(
                    "Apple zip extracted an unsafe intermediate entry"
                )
            continue
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size != expected_files[relative]
            or actual_digests.get(relative) != expected_digests.get(relative)
        ):
            raise AppleArtifactGateError(
                "Apple zip extracted file does not match its authenticated member"
            )
        total_bytes += info.st_size
        if total_bytes > MAX_EXPANDED_BYTES:
            raise AppleArtifactGateError(
                "Apple zip expanded size exceeds the gate limit"
            )
    opened = os.fstat(dest_fd)
    try:
        named = destination.lstat()
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip extract destination was replaced"
        ) from exc
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise AppleArtifactGateError(
            "Apple zip extract destination was replaced"
        )


def _clear_failed_zip_extract(dir_fd: int) -> None:
    try:
        names = sorted(os.listdir(dir_fd), reverse=True)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    for name in names:
        try:
            info = os.lstat(name, dir_fd=dir_fd)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple zip failed extraction could not be cleaned"
            ) from exc
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            child = _openat_child(dir_fd, name, _dir_open_flags())
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise AppleArtifactGateError(
                        "Apple zip failed extraction could not be cleaned"
                    )
                _clear_failed_zip_extract(child)
            finally:
                os.close(child)
            _identity_safe_rmdir(dir_fd, name, (info.st_dev, info.st_ino))
            continue
        try:
            _identity_safe_unlink(dir_fd, name, (info.st_dev, info.st_ino))
        except AppleArtifactGateError as exc:
            if "substituted name" in str(exc):
                continue
            raise


def _open_directory_nofollow(path: pathlib.Path) -> int:
    try:
        fd = os.open(os.fspath(path), _dir_open_flags())
    except OSError as exc:
        if getattr(exc, "errno", None) in {errno.ELOOP, errno.ENOTDIR}:
            raise AppleArtifactGateError(
                "Apple zip extract refused to follow a destination symlink"
            ) from exc
        raise AppleArtifactGateError(
            "Apple zip extract destination is not a directory"
        ) from exc
    try:
        opened = os.fstat(fd)
        named = path.lstat()
        if (
            stat.S_ISLNK(named.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise AppleArtifactGateError(
                "Apple zip extract destination identity changed"
            )
        return fd
    except Exception:
        os.close(fd)
        raise


def _mkdirat_nofollow(parent_fd: int, name: str) -> int:
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise AppleArtifactGateError("Apple zip contains an unsafe member path")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except OSError as exc:
        if getattr(exc, "errno", None) in {errno.ELOOP, errno.ENOTDIR}:
            raise AppleArtifactGateError(
                f"Apple zip extract refused to follow an intermediate symlink: {name}"
            ) from exc
        if getattr(exc, "errno", None) != errno.EEXIST:
            raise AppleArtifactGateError(
                f"Apple zip extract could not create directory: {name}"
            ) from exc
    try:
        return _openat_child(parent_fd, name, _dir_open_flags())
    except AppleArtifactGateError as exc:
        if "symlink" in str(exc).casefold():
            raise AppleArtifactGateError(
                f"Apple zip extract refused to follow an intermediate symlink: {name}"
            ) from exc
        raise


def _openat_create_exclusive_file(parent_fd: int, name: str) -> int:
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise AppleArtifactGateError("Apple zip contains an unsafe member path")
    try:
        info = os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        if getattr(exc, "errno", None) != errno.ENOENT:
            raise AppleArtifactGateError(
                f"Apple zip extract could not bind {name!r}"
            ) from exc
    else:
        if stat.S_ISLNK(info.st_mode):
            raise AppleArtifactGateError(
                f"Apple zip extract refused to follow an intermediate symlink: {name}"
            )
        raise AppleArtifactGateError("Apple zip extract destination already exists")
    try:
        fd = os.open(
            name,
            _open_flags(write=True, exclusive=True),
            0o600,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        if getattr(exc, "errno", None) in {errno.ELOOP, errno.EEXIST}:
            raise AppleArtifactGateError(
                f"Apple zip extract refused to follow an intermediate symlink: {name}"
            ) from exc
        raise AppleArtifactGateError(
            f"Apple zip extract could not create {name!r}"
        ) from exc
    try:
        opened = os.fstat(fd)
        if stat.S_ISLNK(opened.st_mode) or not stat.S_ISREG(opened.st_mode):
            raise AppleArtifactGateError(
                f"Apple zip extract refused to follow an intermediate symlink: {name}"
            )
        return fd
    except Exception:
        os.close(fd)
        raise


def _zip_publish_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_size,
    )


def _hidden_temp_matches_held_fd(
    parent_fd: int,
    name: str,
    file_fd: int,
) -> os.stat_result:
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise AppleArtifactGateError("Apple zip contains an unsafe member path")
    held = os.fstat(file_fd)
    if not stat.S_ISREG(held.st_mode) or held.st_nlink != 1:
        raise AppleArtifactGateError(
            "Apple zip extract hidden temp is not a regular single-link inode"
        )
    try:
        named = os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip extract hidden temp identity does not match the verified descriptor"
        ) from exc
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or named.st_nlink != 1
        or _zip_publish_identity(named) != _zip_publish_identity(held)
    ):
        raise AppleArtifactGateError(
            "Apple zip extract hidden temp identity does not match the verified descriptor"
        )
    named_fd = -1
    try:
        named_fd = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        opened = os.fstat(named_fd)
        held_after = os.fstat(file_fd)
        if (
            opened.st_nlink != 1
            or held_after.st_nlink != 1
            or _zip_publish_identity(opened) != _zip_publish_identity(held)
            or _zip_publish_identity(held_after) != _zip_publish_identity(held)
            or _sha256_fd(named_fd, opened.st_size) != _sha256_fd(file_fd, held.st_size)
        ):
            raise AppleArtifactGateError(
                "Apple zip extract hidden temp identity does not match the verified descriptor"
            )
        return held
    except AppleArtifactGateError:
        raise
    except OSError as exc:
        if getattr(exc, "errno", None) in {errno.ELOOP, errno.ENOTDIR}:
            raise AppleArtifactGateError(
                f"Apple zip extract refused to follow an intermediate symlink: {name}"
            ) from exc
        raise AppleArtifactGateError(
            "Apple zip extract hidden temp identity does not match the verified descriptor"
        ) from exc
    finally:
        if named_fd >= 0:
            os.close(named_fd)


def _descriptor_bound_publish_hidden_temp(
    parent_fd: int,
    final_name: str,
    file_fd: int,
) -> bool:
    try:
        held = os.fstat(file_fd)
    except OSError:
        return False
    if not stat.S_ISREG(held.st_mode):
        return False
    try:
        kernel = _authenticate_volfs(
            file_fd,
            _vnode_identity(held, directory=False),
            directory=False,
        )
    except AppleArtifactGateError:
        return False
    try:
        os.link(
            kernel,
            final_name,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except (NotImplementedError, OSError):
        return False
    return True


def _zip_inode_key(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _zip_member_name_is_safe(name: str) -> bool:
    return bool(name) and name not in {".", ".."} and "/" not in name and "\x00" not in name


def _held_name_matches_descriptor(
    parent_fd: int,
    name: str,
    file_fd: int,
) -> os.stat_result | None:
    if not _zip_member_name_is_safe(name):
        return None
    try:
        named = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    try:
        held = os.fstat(file_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or not stat.S_ISREG(held.st_mode)
        or _zip_inode_key(named) != _zip_inode_key(held)
    ):
        return None
    return named


def _clear_held_unlink_blocking_flags(file_fd: int) -> None:
    blocking = ZIP_UNLINK_BLOCKING_USER_FLAGS
    if not blocking:
        return
    try:
        held = os.fstat(file_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    current = int(getattr(held, "st_flags", 0))
    if current & blocking == 0:
        return
    if _LIBC is None or not hasattr(_LIBC, "fchflags"):
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        )
    rc = _LIBC.fchflags(file_fd, current & ~blocking)
    if rc != 0:
        err = ctypes.get_errno()
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from OSError(err, os.strerror(err))
    try:
        held_after = os.fstat(file_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    if int(getattr(held_after, "st_flags", 0)) & blocking:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        )


def _rollback_held_publish_names(
    parent_fd: int,
    temporary: str,
    final_name: str,
    file_fd: int,
) -> None:
    names = tuple(
        name for name in (final_name, temporary) if _zip_member_name_is_safe(name)
    )
    matching = [
        name
        for name in names
        if _held_name_matches_descriptor(parent_fd, name, file_fd) is not None
    ]
    if not matching:
        return
    try:
        held = os.fstat(file_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple zip failed extraction could not be cleaned"
        ) from exc
    if int(held.st_nlink) <= len(matching):
        _clear_held_unlink_blocking_flags(file_fd)
    expected = _zip_inode_key(held)
    for name in matching:
        if _held_name_matches_descriptor(parent_fd, name, file_fd) is None:
            continue
        try:
            _identity_safe_unlink(
                parent_fd,
                name,
                expected,
                file_fd,
                clear_held_flags=False,
            )
        except AppleArtifactGateError as exc:
            if "substituted name" not in str(exc):
                raise


def _publish_verified_hidden_temp(
    parent_fd: int,
    temporary: str,
    final_name: str,
    file_fd: int,
) -> None:
    if not _zip_member_name_is_safe(final_name):
        raise AppleArtifactGateError("Apple zip contains an unsafe member path")
    publish_failed = False
    try:
        _hidden_temp_matches_held_fd(parent_fd, temporary, file_fd)
        published_from_fd = _descriptor_bound_publish_hidden_temp(
            parent_fd,
            final_name,
            file_fd,
        )
        if not published_from_fd:
            _hidden_temp_matches_held_fd(parent_fd, temporary, file_fd)
            try:
                os.link(
                    temporary,
                    final_name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                if getattr(exc, "errno", None) == errno.EEXIST:
                    raise AppleArtifactGateError(
                        "Apple zip extract destination already exists"
                    ) from exc
                raise AppleArtifactGateError(
                    "Apple zip extract could not publish a verified member"
                ) from exc
        held = os.fstat(file_fd)
        try:
            published = os.lstat(final_name, dir_fd=parent_fd)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple zip extract hidden temp identity does not match the verified descriptor"
            ) from exc
        if (
            stat.S_ISLNK(published.st_mode)
            or not stat.S_ISREG(held.st_mode)
            or not stat.S_ISREG(published.st_mode)
            or _zip_publish_identity(held) != _zip_publish_identity(published)
        ):
            raise AppleArtifactGateError(
                "Apple zip extract hidden temp identity does not match the verified descriptor"
            )
        if _held_name_matches_descriptor(parent_fd, temporary, file_fd) is not None:
            _identity_safe_unlink(
                parent_fd,
                temporary,
                _zip_inode_key(held),
                file_fd,
            )
        else:
            try:
                os.lstat(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise AppleArtifactGateError(
                    "Apple zip extract could not publish a verified member"
                ) from exc
        held_after = os.fstat(file_fd)
        try:
            published_after = os.lstat(final_name, dir_fd=parent_fd)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple zip extract hidden temp identity does not match the verified descriptor"
            ) from exc
        if (
            held_after.st_nlink != 1
            or published_after.st_nlink != 1
            or _zip_publish_identity(held_after) != _zip_publish_identity(published_after)
        ):
            raise AppleArtifactGateError(
                "Apple zip extract hidden temp identity does not match the verified descriptor"
            )
    except AppleArtifactGateError:
        publish_failed = True
        raise
    except OSError as exc:
        publish_failed = True
        raise AppleArtifactGateError(
            "Apple zip extract could not publish a verified member"
        ) from exc
    finally:
        if publish_failed:
            _rollback_held_publish_names(parent_fd, temporary, final_name, file_fd)


def _extract_zip_members(
    archive: zipfile.ZipFile,
    destination: pathlib.Path,
    members: list[zipfile.ZipInfo],
) -> None:
    budget = 0
    for member in members:
        budget += member.file_size
        if budget > MAX_EXPANDED_BYTES:
            raise AppleArtifactGateError("Apple zip expanded size exceeds the gate limit")
    _preflight_zip_local_headers(archive, members)
    dest_fd = _open_directory_nofollow(destination)
    try:
        existing = os.listdir(dest_fd)
        if existing:
            first = sorted(existing)[0]
            info = os.lstat(first, dir_fd=dest_fd)
            if stat.S_ISLNK(info.st_mode):
                raise AppleArtifactGateError(
                    "Apple zip extract refused to follow a preexisting destination symlink"
                )
            raise AppleArtifactGateError(
                "Apple zip extract destination already exists"
            )
        try:
            written = 0
            verified_digests: dict[str, str] = {}
            for member in members:
                name = _zip_member_name(member)
                parts = pathlib.PurePosixPath(name.rstrip("/")).parts
                if not parts:
                    raise AppleArtifactGateError("Apple zip contains an unsafe member path")
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise AppleArtifactGateError("Apple app zip symlink entries are forbidden")
                is_dir = name.endswith("/") or (stat.S_IFMT(mode) and stat.S_ISDIR(mode))
                if is_dir:
                    cursor_fd = os.dup(dest_fd)
                    try:
                        for part in parts:
                            child = _mkdirat_nofollow(cursor_fd, part)
                            os.close(cursor_fd)
                            cursor_fd = child
                    finally:
                        os.close(cursor_fd)
                    continue
                remaining_budget = MAX_EXPANDED_BYTES - written
                if member.file_size > remaining_budget:
                    raise AppleArtifactGateError("Apple zip expanded size exceeds the gate limit")
                cursor_fd = os.dup(dest_fd)
                file_fd = -1
                temporary = f".{parts[-1]}.{os.urandom(8).hex()}"
                try:
                    for part in parts[:-1]:
                        child = _mkdirat_nofollow(cursor_fd, part)
                        os.close(cursor_fd)
                        cursor_fd = child
                    file_fd = _openat_create_exclusive_file(cursor_fd, temporary)
                except Exception:
                    if file_fd >= 0:
                        os.close(file_fd)
                    os.close(cursor_fd)
                    raise
                copied = 0
                member_digest = hashlib.sha256()
                try:
                    with archive.open(member, "r") as source:
                        while True:
                            block = source.read(READ_CHUNK)
                            if not block:
                                break
                            copied += len(block)
                            member_digest.update(block)
                            if copied > member.file_size or written + copied > MAX_EXPANDED_BYTES:
                                raise AppleArtifactGateError(
                                    "Apple zip member exceeded its bounded preallocation"
                                )
                            view = memoryview(block)
                            while view:
                                n = os.write(file_fd, view)
                                if n <= 0:
                                    raise AppleArtifactGateError(
                                        "Apple zip extract write was truncated"
                                    )
                                view = view[n:]
                    os.fchmod(file_fd, 0o700 if stat.S_IMODE(mode) & 0o111 else 0o600)
                    os.fsync(file_fd)
                    if copied != member.file_size:
                        raise AppleArtifactGateError(
                            "Apple zip member size did not match its declared bound"
                        )
                    _publish_verified_hidden_temp(
                        cursor_fd,
                        temporary,
                        parts[-1],
                        file_fd,
                    )
                    temporary = ""
                    verified_digests[name.rstrip("/")] = member_digest.hexdigest()
                    os.fsync(cursor_fd)
                finally:
                    try:
                        if temporary and file_fd >= 0:
                            _rollback_held_publish_names(
                                cursor_fd,
                                temporary,
                                "",
                                file_fd,
                            )
                    finally:
                        os.close(file_fd)
                        os.close(cursor_fd)
                written += copied
            _validate_extracted_zip_tree(
                destination, dest_fd, members, verified_digests
            )
        except Exception:
            _clear_failed_zip_extract(dest_fd)
            raise
    finally:
        os.close(dest_fd)


def _zipfile_from_snapshot(snapshot: AuthenticatedPkgSnapshot) -> zipfile.ZipFile:
    snapshot.ensure_bound()
    os.lseek(snapshot.fd, 0, os.SEEK_SET)
    handle = os.fdopen(os.dup(snapshot.fd), "rb")
    try:
        archive = zipfile.ZipFile(handle)
    except Exception:
        handle.close()
        raise
    original_close = archive.close

    def close() -> None:
        original_close()
        try:
            handle.close()
        except OSError:
            pass

    archive.close = close  # type: ignore[method-assign]
    return archive


def _extract_zip(snapshot: AuthenticatedPkgSnapshot, destination: pathlib.Path) -> None:
    archive = None
    try:
        snapshot.rehash()
        archive = _zipfile_from_snapshot(snapshot)
        members = _safe_zip_members(archive)
        snapshot.rehash()
        _mkdir_private_relative(destination)
        _extract_zip_members(archive, destination, members)
        _reject_unsafe_expansion(destination, pkg_size=snapshot.size)
        snapshot.ensure_bound()
        snapshot.rehash()
    except AppleArtifactGateError:
        raise
    except (
        EOFError,
        NotImplementedError,
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        struct.error,
        zipfile.BadZipFile,
    ) as exc:
        raise AppleArtifactGateError("invalid Apple zip artifact") from exc
    finally:
        if archive is not None:
            archive.close()


def _extract_app_zip(snapshot: AuthenticatedPkgSnapshot, destination: pathlib.Path) -> None:
    try:
        _extract_zip(snapshot, destination)
    except AppleArtifactGateError as exc:
        raise AppleArtifactGateError(f"invalid Developer ID app zip: {exc}") from exc


def _one_app(root: pathlib.Path, pattern: str) -> pathlib.Path:
    apps = [
        path
        for path, relative, info in _walk_tree(root)
        if _bundle_suffix(path.name) == ".app"
        and not stat.S_ISLNK(info.st_mode)
        and stat.S_ISDIR(info.st_mode)
    ]
    if pattern == "Payload/*.app":
        apps = [
            path
            for path, relative, info in _walk_tree(root)
            if _bundle_suffix(path.name) == ".app"
            and not stat.S_ISLNK(info.st_mode)
            and stat.S_ISDIR(info.st_mode)
            and len(pathlib.PurePosixPath(relative).parts) == 2
            and pathlib.PurePosixPath(relative).parts[0].casefold() == "payload"
        ]
    if len(apps) != 1:
        raise AppleArtifactGateError(
            f"Apple artifact must contain exactly one host app, found {len(apps)}"
        )
    return apps[0]


def _read_bounded_regular_file(
    path: pathlib.Path,
    label: str,
    max_bytes: int,
) -> bytes:
    fd = -1
    try:
        fd = _bind_path_from_known_roots(path, directory=False)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > max_bytes
        ):
            raise AppleArtifactGateError(
                f"{label} exceeds the metadata bound"
            )
        payload = os.pread(fd, info.st_size, 0)
        after = os.fstat(fd)
        if (
            len(payload) != info.st_size
            or os.pread(fd, 1, info.st_size)
            or _pkg_vnode_identity(after) != _pkg_vnode_identity(info)
        ):
            raise AppleArtifactGateError(f"{label} changed while it was read")
        return payload
    except AppleArtifactGateError:
        raise
    except OSError as exc:
        raise AppleArtifactGateError(f"{label} is missing or invalid") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _read_plist(path: pathlib.Path, label: str) -> dict[str, object]:
    try:
        payload = _read_bounded_regular_file(path, f"{label} plist", MAX_PLIST_BYTES)
        value = plistlib.loads(payload, dict_type=_UniquePlist)
    except AppleArtifactGateError:
        raise
    except (plistlib.InvalidFileException, ValueError, TypeError) as exc:
        raise AppleArtifactGateError(f"{label} plist is missing or invalid") from exc
    if not isinstance(value, dict):
        raise AppleArtifactGateError(f"{label} plist must be a dictionary")
    return value


def _verify_privacy(
    path: pathlib.Path,
    label: str,
    expected_api_reasons: Mapping[str, frozenset[str]],
    *,
    require_empty_collection: bool,
    require_host_collection: bool = False,
) -> None:
    value = _read_plist(path, label)
    required = {
        "NSPrivacyTracking",
        "NSPrivacyTrackingDomains",
        "NSPrivacyCollectedDataTypes",
    }
    if not required.issubset(value):
        raise AppleArtifactGateError(f"{label} privacy manifest schema is incomplete")
    if value.get("NSPrivacyTracking") is not False:
        raise AppleArtifactGateError(f"{label} privacy manifest enables tracking")
    if value.get("NSPrivacyTrackingDomains") != []:
        raise AppleArtifactGateError(f"{label} privacy manifest lists tracking domains")
    collected = value.get("NSPrivacyCollectedDataTypes")
    accessed = value.get("NSPrivacyAccessedAPITypes", [])
    if not isinstance(collected, list) or not isinstance(accessed, list):
        raise AppleArtifactGateError(f"{label} privacy manifest arrays are malformed")
    if require_empty_collection and collected:
        raise AppleArtifactGateError(f"{label} privacy manifest declares collected data")
    if require_host_collection:
        by_type: dict[str, dict[str, object]] = {}
        for item in collected:
            if not isinstance(item, dict):
                raise AppleArtifactGateError(f"{label} collected data entry is malformed")
            data_type = item.get("NSPrivacyCollectedDataType")
            if not isinstance(data_type, str) or not data_type:
                raise AppleArtifactGateError(f"{label} collected data type is malformed")
            if data_type in by_type:
                raise AppleArtifactGateError(f"{label} collected data type is duplicated")
            by_type[data_type] = item
        if set(by_type) != set(HOST_PRIVACY_COLLECTED_TYPES):
            raise AppleArtifactGateError(
                f"{label} collected data types do not match the release contract"
            )
        for data_type, item in by_type.items():
            if item.get("NSPrivacyCollectedDataTypeLinked") is not True:
                raise AppleArtifactGateError(f"{label} {data_type} must be linked")
            if item.get("NSPrivacyCollectedDataTypeTracking") is not False:
                raise AppleArtifactGateError(f"{label} {data_type} must not be tracking")
            purposes = item.get("NSPrivacyCollectedDataTypePurposes")
            if not isinstance(purposes, list) or set(purposes) != {
                PRIVACY_APP_FUNCTIONALITY_PURPOSE
            }:
                raise AppleArtifactGateError(
                    f"{label} {data_type} purpose does not match the release contract"
                )
    actual_api_reasons: dict[str, frozenset[str]] = {}
    for item in accessed:
        if not isinstance(item, dict):
            raise AppleArtifactGateError(f"{label} privacy API entry is malformed")
        api_type = item.get("NSPrivacyAccessedAPIType")
        reasons = item.get("NSPrivacyAccessedAPITypeReasons")
        if not isinstance(api_type, str) or not api_type or not isinstance(reasons, list):
            raise AppleArtifactGateError(f"{label} privacy API entry is malformed")
        if api_type in actual_api_reasons:
            raise AppleArtifactGateError(f"{label} privacy API type is duplicated")
        if any(not isinstance(reason, str) or not reason for reason in reasons):
            raise AppleArtifactGateError(f"{label} privacy API reason is malformed")
        if len(reasons) != len(set(reasons)):
            raise AppleArtifactGateError(f"{label} privacy API reason is duplicated")
        actual_api_reasons[api_type] = frozenset(reasons)
    if actual_api_reasons != dict(expected_api_reasons):
        raise AppleArtifactGateError(
            f"{label} privacy API categories or reasons do not match the release contract"
        )


def _verify_bundle(app: pathlib.Path, platform: str) -> None:
    expected_short_version, expected_bundle_version = reviewed_apple_release_identity()

    def verify_version(info: dict[str, object], label: str) -> None:
        if (
            info.get("CFBundleShortVersionString") != expected_short_version
            or info.get("CFBundleVersion") != expected_bundle_version
        ):
            raise AppleArtifactGateError(
                f"{label} version does not match the reviewed Apple release identity"
            )

    if platform == "ios":
        contents = app
        plug_ins = app / "PlugIns"
        privacy = app / "PrivacyInfo.xcprivacy"
        info_path = app / "Info.plist"
    else:
        contents = app / "Contents"
        plug_ins = contents / "PlugIns"
        privacy = contents / "Resources" / "PrivacyInfo.xcprivacy"
        info_path = contents / "Info.plist"
    info = _read_plist(info_path, "host app")
    if info.get("CFBundleIdentifier") != HOST_BUNDLE_ID:
        raise AppleArtifactGateError("Apple host bundle identifier is not current")
    verify_version(info, "Apple host app")
    if not plug_ins.is_dir() or plug_ins.is_symlink():
        raise AppleArtifactGateError("Apple artifact must contain exactly one PacketTunnel extension")
    extensions = [
        path
        for path, relative, info in _walk_tree(plug_ins)
        if _bundle_suffix(path.name) == ".appex"
        and len(pathlib.PurePosixPath(relative).parts) == 1
        and not stat.S_ISLNK(info.st_mode)
        and stat.S_ISDIR(info.st_mode)
    ]
    if len(extensions) != 1:
        raise AppleArtifactGateError("Apple artifact must contain exactly one PacketTunnel extension")
    extension = extensions[0]
    extension_info = _read_plist(
        extension / ("Info.plist" if platform == "ios" else "Contents/Info.plist"),
        "PacketTunnel extension",
    )
    if extension_info.get("CFBundleIdentifier") != TUNNEL_BUNDLE_ID:
        raise AppleArtifactGateError("PacketTunnel bundle identifier is not current")
    verify_version(extension_info, "PacketTunnel extension")
    extension_privacy = extension / (
        "PrivacyInfo.xcprivacy"
        if platform == "ios"
        else "Contents/Resources/PrivacyInfo.xcprivacy"
    )
    _verify_privacy(
        privacy,
        "host app",
        HOST_PRIVACY_API_REASONS,
        require_empty_collection=False,
        require_host_collection=True,
    )
    _verify_privacy(
        extension_privacy,
        "PacketTunnel extension",
        TUNNEL_PRIVACY_API_REASONS,
        require_empty_collection=True,
    )
    if platform == "ios":
        watch_root = app / "Watch"
        if not watch_root.is_dir() or watch_root.is_symlink():
            raise AppleArtifactGateError("iOS artifact must contain exactly one Watch app")
        watch_apps = [
            path
            for path, relative, info in _walk_tree(watch_root)
            if _bundle_suffix(path.name) == ".app"
            and len(pathlib.PurePosixPath(relative).parts) == 1
            and not stat.S_ISLNK(info.st_mode)
            and stat.S_ISDIR(info.st_mode)
        ]
        if len(watch_apps) != 1:
            raise AppleArtifactGateError("iOS artifact must contain exactly one Watch app")
        watch = watch_apps[0]
        watch_info = _read_plist(watch / "Info.plist", "Watch app")
        if watch_info.get("CFBundleIdentifier") != WATCH_BUNDLE_ID:
            raise AppleArtifactGateError("Watch bundle identifier is not current")
        verify_version(watch_info, "Watch app")
        _verify_privacy(
            watch / "PrivacyInfo.xcprivacy",
            "Watch app",
            {},
            require_empty_collection=True,
        )
    frameworks_root = contents / "Frameworks"
    if not frameworks_root.is_dir() or frameworks_root.is_symlink():
        raise AppleArtifactGateError("Apple artifact frameworks directory is missing")
    required_engine_frameworks = {
        "WinsAmneziaWGPacketEngine.framework": {
            PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
        },
        "WinsXrayVlessWsTransport.framework": {
            PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
        },
        "WinsWinnPacketEngine.framework": {
            PRIVACY_FILE_TIMESTAMP_API: frozenset({"C617.1"}),
            PRIVACY_SYSTEM_BOOT_TIME_API: frozenset({"35F9.1"}),
        },
    }
    for framework_name, expected_apis in required_engine_frameworks.items():
        framework = frameworks_root / framework_name
        if not framework.exists() and not framework.is_symlink():
            raise AppleArtifactGateError(
                f"Apple artifact is missing required engine framework: {framework_name}"
            )
        if not framework.is_dir() or framework.is_symlink():
            raise AppleArtifactGateError(f"Apple engine framework is unsafe: {framework_name}")
        executable_name = framework_name.removesuffix(".framework")
        executable = (
            framework / executable_name
            if platform == "ios"
            else framework / "Versions" / "A" / executable_name
        )
        try:
            executable_info = executable.lstat()
        except OSError as exc:
            raise AppleArtifactGateError(
                f"Apple engine framework executable is missing: {framework_name}"
            ) from exc
        if (
            not stat.S_ISREG(executable_info.st_mode)
            or executable_info.st_nlink != 1
            or not _is_macho(executable)
        ):
            raise AppleArtifactGateError(
                f"Apple engine framework executable is unsafe: {framework_name}"
            )
        framework_privacy = (
            framework / "PrivacyInfo.xcprivacy"
            if platform == "ios"
            else framework / "Versions/A/Resources/PrivacyInfo.xcprivacy"
        )
        _verify_privacy(
            framework_privacy,
            f"{framework_name} privacy manifest",
            expected_apis,
            require_empty_collection=True,
        )
    flutter_name = "Flutter.framework" if platform == "ios" else "FlutterMacOS.framework"
    flutter = frameworks_root / flutter_name
    if flutter.exists() or flutter.is_symlink():
        if not flutter.is_dir() or flutter.is_symlink():
            raise AppleArtifactGateError(f"Apple Flutter framework is unsafe: {flutter_name}")
        flutter_privacy = (
            flutter / "PrivacyInfo.xcprivacy"
            if platform == "ios"
            else flutter / "Versions/A/Resources/PrivacyInfo.xcprivacy"
        )
        _verify_privacy(
            flutter_privacy,
            f"{flutter_name} privacy manifest",
            FLUTTER_IOS_PRIVACY_API_REASONS if platform == "ios" else {},
            require_empty_collection=True,
        )
    if not contents.is_dir():
        raise AppleArtifactGateError("Apple host bundle layout is invalid")
    try:
        verify_release_contamination(app, platform)
    except AppleReleaseContaminationError as exc:
        raise AppleArtifactGateError(str(exc)) from exc


def _codesign_requirement_text(requirement: str) -> str:
    if type(requirement) is not str or not requirement:
        raise AppleArtifactGateError("Apple code-signature designated requirement is unknown")
    for character in requirement:
        code = ord(character)
        if code < 0x20 or code > 0x7E:
            raise AppleArtifactGateError(
                "Apple code-signature designated requirement contains forbidden characters"
            )
    return requirement


def _codesign_requirement_token(requirement: str) -> str:
    return "-R=" + _codesign_requirement_text(requirement)


def _codesign_requirement_from_argv(argv: list[str]) -> str:
    if type(argv) is not list:
        raise AppleArtifactGateError(
            "codesign designated requirement must be passed as one -R=<requirement> argv token"
        )
    attached = [
        item[3:]
        for item in argv
        if type(item) is str and item.startswith("-R=")
    ]
    if "-R" in argv or len(attached) != 1:
        raise AppleArtifactGateError(
            "codesign designated requirement must be passed as one -R=<requirement> argv token"
        )
    return _codesign_requirement_text(attached[0])


def _codesign_verify_argv(requirement: str, *, deep: bool = False) -> list[str]:
    argv = ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2"]
    if deep:
        argv.insert(2, "--deep")
    argv.append(_codesign_requirement_token(requirement))
    _codesign_requirement_from_argv(argv)
    return argv


def _verify_codesign(
    app: pathlib.Path,
    expected_authority: str,
    *,
    platform: str | None = None,
    deep: bool = True,
) -> None:
    requirement = _codesign_requirement_for_authority(expected_authority)
    _run_on_path(
        _codesign_verify_argv(requirement, deep=deep),
        app,
        "Apple code-signature verification",
        directory=True,
    )
    _verify_codesign_identity(app, expected_authority)
    if platform is not None:
        _verify_nested_release_identities(app, platform, expected_authority)


def _iter_nested_signable_paths(
    app: pathlib.Path, platform: str
) -> list[pathlib.Path]:
    if platform == "ios":
        contents = app
        plugins = app / "PlugIns"
        watch_root = app / "Watch"
        frameworks = app / "Frameworks"
    else:
        contents = app / "Contents"
        plugins = contents / "PlugIns"
        watch_root = None
        frameworks = contents / "Frameworks"
    found: list[pathlib.Path] = []
    if plugins.is_dir() and not plugins.is_symlink():
        for path, relative, info in _walk_tree(plugins):
            if (
                _bundle_suffix(path.name) == ".appex"
                and len(pathlib.PurePosixPath(relative).parts) == 1
                and not stat.S_ISLNK(info.st_mode)
                and stat.S_ISDIR(info.st_mode)
            ):
                found.append(path)
    if watch_root is not None and watch_root.is_dir() and not watch_root.is_symlink():
        for path, relative, info in _walk_tree(watch_root):
            if (
                _bundle_suffix(path.name) == ".app"
                and len(pathlib.PurePosixPath(relative).parts) == 1
                and not stat.S_ISLNK(info.st_mode)
                and stat.S_ISDIR(info.st_mode)
            ):
                found.append(path)
    if frameworks.is_dir() and not frameworks.is_symlink():
        for path, relative, info in _walk_tree(frameworks):
            parts = pathlib.PurePosixPath(relative).parts
            if stat.S_ISLNK(info.st_mode):
                continue
            if (
                path.name.casefold().endswith(".framework")
                and len(parts) == 1
                and stat.S_ISDIR(info.st_mode)
            ):
                found.append(path)
            elif (
                path.name.casefold().endswith(".dylib")
                and stat.S_ISREG(info.st_mode)
            ):
                found.append(path)
    found.sort(key=lambda item: item.as_posix())
    return found


def _verify_nested_release_identities(
    app: pathlib.Path,
    platform: str,
    expected_authority: str,
) -> None:
    requirement = _codesign_requirement_for_authority(expected_authority)
    nested = _iter_nested_signable_paths(app, platform)
    if not nested:
        raise AppleArtifactGateError("Apple nested signed identities are missing")
    for path in nested:
        directory = path.is_dir() and not path.is_symlink()
        _run_on_path(
            _codesign_verify_argv(requirement, deep=False),
            path,
            "Apple nested code-signature verification",
            directory=directory,
        )
        _verify_codesign_identity(path, expected_authority)


def _verify_codesign_identity(path: pathlib.Path, expected_authority: str) -> None:
    directory = path.is_dir() and not path.is_symlink()
    details = _run_on_path(
        ["/usr/bin/codesign", "-d", "--verbose=4"],
        path,
        "Apple code-signature identity inspection",
        directory=directory,
    )
    if details.stdout:
        raise AppleArtifactGateError(
            "Apple code-signature identity inspection returned unexpected stdout"
        )
    _require_release_codesign_identity(details.stderr, expected_authority)


def _codesign_authority_and_team(output: str) -> tuple[list[str], list[str]]:
    output = _normalize_icu_time_spacing(output)
    _reject_signer_text(output, "Apple code-signature identity")
    lines = output.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    authorities: list[str] = []
    teams: list[str] = []
    for line in lines:
        if line.startswith("Authority"):
            if (
                not line.startswith("Authority=")
                or line != line.strip()
                or len(line) <= len("Authority=")
            ):
                raise AppleArtifactGateError(
                    "Apple code-signature authority output is malformed"
                )
            authorities.append(line)
        if line.startswith("TeamIdentifier"):
            if not line.startswith("TeamIdentifier=") or line != line.strip():
                raise AppleArtifactGateError(
                    "Apple code-signature team output is malformed"
                )
            teams.append(line.removeprefix("TeamIdentifier="))
    return authorities, teams


def _require_release_codesign_identity(output: str, expected_authority: str) -> None:
    authorities, teams = _codesign_authority_and_team(output)
    expected_line = _exact_release_authority_line(expected_authority)
    if (
        len(teams) != 1
        or teams[0] != TEAM_ID
        or not authorities
        or authorities[0] != expected_line
    ):
        raise AppleArtifactGateError("Apple signature identity or team is not release-valid")


def _posix_relative(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        relative = path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise AppleArtifactGateError("Apple PKG path escaped the inspected root") from exc
    return relative.as_posix()


def _lexical_relative(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError as exc:
        raise AppleArtifactGateError("Apple PKG path escaped the inspected root") from exc


def _reject_unsafe_symlink(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        target = os.readlink(path)
    except OSError as exc:
        raise AppleArtifactGateError("Apple PKG symlink could not be read") from exc
    if (
        not target
        or "\x00" in target
        or pathlib.PurePosixPath(target).is_absolute()
        or len(target.encode("utf-8", "surrogateescape")) > MAX_SYMLINK_TARGET_BYTES
    ):
        raise AppleArtifactGateError("Apple PKG contains an absolute or empty symlink")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as exc:
        raise AppleArtifactGateError("Apple PKG symlink escapes the expanded payload") from exc
    return target


def _expansion_usage(root: pathlib.Path) -> tuple[int, int]:
    if not root.exists():
        return 0, 0
    total_bytes = 0
    entries = 0
    for _path, _relative, info in _walk_tree(root):
        entries += 1
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            total_bytes += info.st_size
    return total_bytes, entries


def _expansion_usage_fd(root_fd: int) -> tuple[int, int]:
    total_bytes = 0
    entries = 0

    def walk(current_fd: int) -> None:
        nonlocal entries, total_bytes
        try:
            names = os.listdir(current_fd)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple installer expansion destination is unreadable"
            ) from exc
        for name in names:
            if name in {".", ".."}:
                continue
            try:
                info = os.lstat(name, dir_fd=current_fd)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise AppleArtifactGateError(
                    "Apple installer expansion entry is unreadable"
                ) from exc
            entries += 1
            if entries > MAX_EXPANDED_ENTRIES:
                return
            if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                total_bytes += info.st_size
                if total_bytes > MAX_EXPANDED_BYTES:
                    return
            elif stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                try:
                    child = os.open(name, _dir_open_flags(), dir_fd=current_fd)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise AppleArtifactGateError(
                        "Apple installer expansion directory is unsafe"
                    ) from exc
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (
                        info.st_dev,
                        info.st_ino,
                    ):
                        raise AppleArtifactGateError(
                            "Apple installer expansion directory changed"
                        )
                    walk(child)
                finally:
                    os.close(child)

    duplicate = os.dup(root_fd)
    try:
        walk(duplicate)
    finally:
        os.close(duplicate)
    return total_bytes, entries


def _reject_unsafe_expansion(root: pathlib.Path, *, pkg_size: int | None = None) -> None:
    if root.is_symlink() or not root.is_dir():
        raise AppleArtifactGateError("Apple PKG expansion destination is unsafe")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise AppleArtifactGateError("Apple PKG expansion destination is unreadable") from exc
    entries = 0
    total_bytes = 0
    symlink_count = 0
    hardlink_count = 0
    special_count = 0
    for path, relative, info in _walk_tree(root):
        encoded = relative.encode("utf-8", "surrogateescape")
        if not relative or "\x00" in relative or len(encoded) > MAX_PATH_BYTES:
            raise AppleArtifactGateError("Apple PKG expanded path exceeds the gate limit")
        depth = len(pathlib.PurePosixPath(relative).parts)
        if depth > MAX_EXPANDED_DEPTH:
            raise AppleArtifactGateError("Apple PKG expanded depth exceeds the gate limit")
        entries += 1
        if entries > MAX_EXPANDED_ENTRIES:
            raise AppleArtifactGateError("Apple PKG expanded entry count exceeds the gate limit")
        if stat.S_ISLNK(info.st_mode):
            symlink_count += 1
            if symlink_count > MAX_SYMLINKS:
                raise AppleArtifactGateError(
                    "Apple PKG expanded symlink count exceeds the gate limit"
                )
            _reject_unsafe_symlink(path, resolved_root)
            continue
        try:
            path.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise AppleArtifactGateError(
                "Apple PKG expansion escaped the destination"
            ) from exc
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                hardlink_count += 1
                if hardlink_count > MAX_HARDLINKS:
                    raise AppleArtifactGateError(
                        "Apple PKG expansion contains a hardlink"
                    )
            if info.st_size > MAX_INNER_FILE_BYTES:
                raise AppleArtifactGateError("Apple PKG expanded file exceeds the gate limit")
            total_bytes += info.st_size
            if total_bytes > MAX_OUTPUT_BYTES or total_bytes > MAX_EXPANDED_BYTES:
                raise AppleArtifactGateError(
                    "Apple PKG expanded byte count exceeds the gate limit"
                )
            continue
        if stat.S_ISDIR(info.st_mode):
            continue
        special_count += 1
        if special_count > MAX_SPECIAL_FILES:
            raise AppleArtifactGateError("Apple PKG contains a special filesystem entry")
    if pkg_size is not None and pkg_size > 0:
        if total_bytes > pkg_size * MAX_COMPRESSION_RATIO:
            raise AppleArtifactGateError(
                "Apple PKG expanded byte count exceeds the compression ratio limit"
            )
    if hardlink_count > MAX_HARDLINKS:
        raise AppleArtifactGateError("Apple PKG expansion contains a hardlink")
    if special_count > MAX_SPECIAL_FILES:
        raise AppleArtifactGateError("Apple PKG contains a special filesystem entry")


def _payload_directories(expanded: pathlib.Path) -> list[pathlib.Path]:
    found: list[pathlib.Path] = []
    try:
        resolved_root = expanded.resolve(strict=True)
    except OSError as exc:
        raise AppleArtifactGateError("Apple PKG expansion is unreadable") from exc
    for path, _relative, info in _walk_tree(expanded):
        if path.name != "Payload" or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            continue
        try:
            path.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise AppleArtifactGateError(
                "Apple PKG Payload escaped the expanded root"
            ) from exc
        found.append(path)
    found.sort(key=lambda path: path.as_posix())
    return found


def _iter_named_bundles(root: pathlib.Path) -> list[pathlib.Path]:
    bundles: list[pathlib.Path] = []
    for path, _relative, info in _walk_tree(root):
        suffix = _bundle_suffix(path.name)
        if suffix is None:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise AppleArtifactGateError(
                "Apple PKG contains a substituted non-directory bundle"
            )
        bundles.append(path)
    bundles.sort(key=lambda path: path.as_posix())
    return bundles


def _reject_hidden_bundle(path: pathlib.Path, expanded: pathlib.Path) -> None:
    relative = _lexical_relative(path, expanded)
    parts = pathlib.PurePosixPath(relative).parts
    if any(part.startswith(".") and part not in {".", ".."} for part in parts):
        raise AppleArtifactGateError(f"Apple PKG contains a hidden app: {relative}")
    if path.is_symlink():
        raise AppleArtifactGateError("Apple PKG host app must not be a symlink")
    if not path.is_dir():
        raise AppleArtifactGateError("Apple PKG host app is not a directory")


def _bind_macos_packaged_bundles(
    expanded: pathlib.Path,
    *,
    inspect_signing: bool,
    expected_authority: str,
) -> tuple[pathlib.Path, list[dict[str, object]]]:
    payloads = _payload_directories(expanded)
    if len(payloads) != 1:
        raise AppleArtifactGateError(
            f"Apple PKG must contain exactly one expanded Payload, found {len(payloads)}"
        )
    payload = payloads[0]
    expected_short_version, expected_bundle_version = reviewed_apple_release_identity()
    records: list[dict[str, object]] = []
    hosts: list[pathlib.Path] = []
    tunnels: list[pathlib.Path] = []
    for bundle in _iter_named_bundles(payload):
        _reject_hidden_bundle(bundle, expanded)
        relative = _lexical_relative(bundle, expanded)
        suffix = _bundle_suffix(bundle.name)
        info_path = bundle / "Contents" / "Info.plist"
        if info_path.is_symlink() or not info_path.is_file():
            raise AppleArtifactGateError(
                f"Apple PKG nested bundle is missing a regular Info.plist: {relative}"
            )
        info = _read_plist(info_path, f"nested bundle {relative}")
        bundle_id = info.get("CFBundleIdentifier")
        spec = MACOS_BUNDLE_ALLOWLIST.get(bundle_id) if type(bundle_id) is str else None
        if spec is None:
            raise AppleArtifactGateError(
                f"Apple PKG nested app is not on the exact allowlist: {relative}"
            )
        if suffix is None or spec["suffix"] != suffix:
            raise AppleArtifactGateError(
                f"Apple PKG nested bundle suffix does not match the allowlist: {relative}"
            )
        if (
            info.get("CFBundleShortVersionString") != expected_short_version
            or info.get("CFBundleVersion") != expected_bundle_version
        ):
            raise AppleArtifactGateError(
                f"{relative} version does not match the reviewed Apple release identity"
            )
        privacy_path = bundle / spec["privacy"]
        role = str(spec["role"])
        _verify_privacy(
            privacy_path,
            f"{relative} privacy manifest",
            HOST_PRIVACY_API_REASONS if role == "host" else TUNNEL_PRIVACY_API_REASONS,
            require_empty_collection=role != "host",
            require_host_collection=role == "host",
        )
        if inspect_signing:
            _verify_codesign_identity(bundle, expected_authority)
        record = {
            "path": relative,
            "bundle_id": bundle_id,
            "role": spec["role"],
            "version": expected_short_version,
            "build": expected_bundle_version,
            "team_id": TEAM_ID if inspect_signing else None,
        }
        records.append(record)
        if spec["role"] == "host":
            hosts.append(bundle)
        elif spec["role"] == "tunnel":
            tunnels.append(bundle)
    for bundle in _iter_named_bundles(expanded):
        try:
            bundle.relative_to(payload)
        except ValueError:
            raise AppleArtifactGateError(
                f"Apple PKG contains a hidden app outside Payload: "
                f"{_lexical_relative(bundle, expanded)}"
            ) from None
    if len(hosts) != 1 or len(tunnels) != 1:
        raise AppleArtifactGateError(
            "Apple PKG payload must contain exactly the allowlisted host app and PacketTunnel"
        )
    app = hosts[0]
    info_path = app / "Contents" / "Info.plist"
    if info_path.is_symlink() or not info_path.is_file():
        raise AppleArtifactGateError("Apple PKG host app is missing a regular Info.plist")
    records.sort(key=lambda item: str(item["path"]))
    return app, records


def _exact_payload_app(expanded: pathlib.Path) -> pathlib.Path:
    app, _records = _bind_macos_packaged_bundles(
        expanded,
        inspect_signing=False,
        expected_authority="Authority=Apple Distribution:",
    )
    return app


def _macos_aot_image(app: pathlib.Path) -> pathlib.Path:
    framework = app / "Contents" / "Frameworks" / "App.framework"
    candidates = (
        framework / "App",
        framework / "Versions" / "A" / "App",
        framework / "Versions" / "Current" / "App",
    )
    unique: list[pathlib.Path] = []
    seen: set[tuple[int, int]] = set()
    for candidate in candidates:
        if not candidate.exists() and not candidate.is_symlink():
            continue
        if candidate.is_symlink():
            _reject_unsafe_symlink(candidate, app)
        try:
            resolved = candidate.resolve(strict=True)
            info = resolved.lstat()
        except OSError as exc:
            raise AppleArtifactGateError("Flutter AOT payload could not be resolved") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
            raise AppleArtifactGateError("Flutter AOT payload must be a non-empty regular file")
        if info.st_nlink != 1:
            raise AppleArtifactGateError("Flutter AOT payload must not be a hardlink")
        if resolved.name != "App" or "App.framework" not in resolved.parts:
            raise AppleArtifactGateError(
                "Flutter AOT payload is not App.framework/App"
            )
        key = (info.st_dev, info.st_ino)
        if key in seen:
            continue
        seen.add(key)
        unique.append(resolved)
    if len(unique) != 1:
        raise AppleArtifactGateError(
            "Apple PKG is missing exactly one Flutter AOT App.framework/App payload"
        )
    return unique[0]


def _cpu_architecture(cputype: int) -> str:
    if cputype == CPU_TYPE_ARM64:
        return "arm64"
    if cputype == CPU_TYPE_X86_64:
        return "x86_64"
    raise AppleArtifactGateError(f"Mach-O CPU type is not an allowed macOS architecture: {cputype}")


def _thin_macho_slice(data: bytes) -> tuple[str, int]:
    if len(data) < 32:
        raise AppleArtifactGateError("Mach-O header is truncated")
    magic = data[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        endian = "<"
    elif magic == b"\xfe\xed\xfa\xcf":
        endian = ">"
    else:
        raise AppleArtifactGateError("Mach-O slice is not a 64-bit Mach-O image")
    cputype = struct.unpack_from(endian + "I", data, 4)[0]
    filetype = struct.unpack_from(endian + "I", data, 12)[0]
    return _cpu_architecture(cputype), filetype


def _macho_slices(data: bytes) -> list[tuple[str, int]]:
    if len(data) < 8:
        raise AppleArtifactGateError("Mach-O image is truncated")
    magic = data[:4]
    if magic in FAT_ENDIAN:
        endian = FAT_ENDIAN[magic]
        is_64 = magic in FAT_64
        count = struct.unpack_from(endian + "I", data, 4)[0]
        entry_size = 32 if is_64 else 20
        if count <= 0 or count > 8 or 8 + count * entry_size > len(data):
            raise AppleArtifactGateError("fat Mach-O header is malformed")
        slices: list[tuple[str, int]] = []
        seen_arch: set[str] = set()
        for index in range(count):
            entry = 8 + index * entry_size
            cputype = struct.unpack_from(endian + "I", data, entry)[0]
            if is_64:
                offset = struct.unpack_from(endian + "Q", data, entry + 8)[0]
                size = struct.unpack_from(endian + "Q", data, entry + 16)[0]
            else:
                offset = struct.unpack_from(endian + "I", data, entry + 8)[0]
                size = struct.unpack_from(endian + "I", data, entry + 12)[0]
            if offset < 0 or size < 32 or offset + size > len(data):
                raise AppleArtifactGateError("fat Mach-O slice is truncated")
            arch, filetype = _thin_macho_slice(data[offset : offset + size])
            if arch in seen_arch:
                raise AppleArtifactGateError("fat Mach-O contains a duplicate architecture")
            seen_arch.add(arch)
            if _cpu_architecture(cputype) != arch:
                raise AppleArtifactGateError("fat Mach-O architecture table is inconsistent")
            slices.append((arch, filetype))
        return slices
    return [_thin_macho_slice(data)]


def _macho_architectures(path: pathlib.Path) -> tuple[str, ...]:
    completed = _run_on_path(
        ["/usr/bin/lipo", "-archs"],
        path,
        "Mach-O architecture inspection",
    )
    archs = tuple(part for part in completed.stdout.split() if part)
    if not archs:
        raise AppleArtifactGateError(f"Mach-O architecture list is empty: {path.name}")
    unknown = [arch for arch in archs if arch not in ALLOWED_MACHO_ARCHITECTURES]
    if (
        unknown
        or len(archs) != len(set(archs))
        or set(archs) != REQUIRED_AOT_ARCHITECTURES
    ):
        raise AppleArtifactGateError(
            f"{path.name} is not one exact arm64 plus x86_64 macOS image"
        )
    return archs


def _reject_otool_debug_sections(path: pathlib.Path) -> str:
    completed = _run_on_path(
        [XCRUN, "otool-classic", "-l"],
        path,
        "Mach-O load-command inspection",
    )
    for raw_line in completed.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("segname ") and "__DWARF" in line.split(None, 1)[-1]:
            raise AppleArtifactGateError(f"{path.name} retains a DWARF debug segment")
        if line.startswith("sectname ") and line.split(None, 1)[-1].startswith("__debug"):
            raise AppleArtifactGateError(f"{path.name} retains a debug section")
    return completed.stdout


def _reject_nm_debug_symbols(path: pathlib.Path, arch: str | None = None) -> str:
    argv = ["/usr/bin/nm", "-a"]
    if arch is not None:
        argv.extend(["-arch", arch])
    completed = _run_on_path(
        argv,
        path,
        "Mach-O symbol-table inspection",
        allow_exit=frozenset({0, 1}),
    )
    output = f"{completed.stdout}{completed.stderr}"
    lowered = output.lower()
    if "truncated" in lowered or "malformed" in lowered:
        raise AppleArtifactGateError(f"{path.name} is not a parseable Mach-O symbol table")
    if completed.returncode == 1 and "no symbols" in lowered:
        return completed.stdout
    if completed.returncode != 0:
        detail = _redact_tool_output(output.strip())
        raise AppleArtifactGateError(
            f"Mach-O symbol-table inspection failed with exit {completed.returncode}: {detail}"
        )
    for line in completed.stdout.splitlines():
        if NM_DEBUG_SYMBOL_TYPES.intersection(line.split()):
            raise AppleArtifactGateError(f"{path.name} retains private or debug symbols")
    return completed.stdout


def _require_flutter_aot_contract(
    path: pathlib.Path,
    data: bytes,
    archs: tuple[str, ...],
    load_commands: str,
    symbols: str,
) -> None:
    relative = path.name
    try:
        slices = _macho_slices(data)
    except struct.error as exc:
        raise AppleArtifactGateError("Flutter AOT Mach-O header is malformed") from exc
    slice_archs = {arch for arch, _filetype in slices}
    filetypes = {filetype for _arch, filetype in slices}
    if MH_EXECUTE in filetypes or filetypes != {MH_DYLIB}:
        raise AppleArtifactGateError(
            f"{relative} is not an MH_DYLIB App.framework/App Flutter AOT image"
        )
    if slice_archs != REQUIRED_AOT_ARCHITECTURES or set(archs) != REQUIRED_AOT_ARCHITECTURES:
        raise AppleArtifactGateError(
            f"{relative} is not a universal arm64 plus x86_64 Flutter AOT image"
        )
    header = _run_on_path(
        [XCRUN, "otool-classic", "-hv"],
        path,
        "Flutter AOT Mach-O header inspection",
    )
    header_text = f"{header.stdout}\n{header.stderr}"
    if "DYLIB" not in header_text:
        raise AppleArtifactGateError(
            f"{relative} lacks exact MH_DYLIB App.framework/App semantics"
        )
    if re.search(r"\bEXECUTE\b", header_text):
        raise AppleArtifactGateError(
            f"{relative} rejects generic MH_EXECUTE Flutter AOT fixtures"
        )
    if "segname __TEXT" not in load_commands or "sectname __const" not in load_commands:
        raise AppleArtifactGateError(
            f"{relative} lacks the Flutter AOT __TEXT/__const section contract"
        )
    missing = [name for name in FLUTTER_AOT_SYMBOLS if name not in symbols]
    if missing:
        raise AppleArtifactGateError(
            f"{relative} lacks the Flutter AOT snapshot signature: {', '.join(missing)}"
        )
    for arch in sorted(REQUIRED_AOT_ARCHITECTURES):
        arch_symbols = _reject_nm_debug_symbols(path, arch=arch)
        arch_missing = [name for name in FLUTTER_AOT_SYMBOLS if name not in arch_symbols]
        if arch_missing:
            raise AppleArtifactGateError(
                f"{relative} lacks the Flutter AOT snapshot signature on {arch}: "
                f"{', '.join(arch_missing)}"
            )


def _reject_private_symbol_path(relative: str) -> None:
    folded = relative.casefold()
    parts = pathlib.PurePosixPath(folded).parts
    basename = parts[-1] if parts else folded
    if (
        any(part.endswith(".dsym") for part in parts)
        or basename.endswith(PRIVATE_SYMBOL_SUFFIXES)
        or basename in {"mapping.txt", "proguard-mapping.txt"}
    ):
        raise AppleArtifactGateError(
            f"Apple PKG inner payload contains packaged private symbols: {relative}"
        )


def _is_macho(path: pathlib.Path) -> bool:
    try:
        flags = _open_flags()
        fd = os.open(path, flags)
        try:
            magic = os.read(fd, 4)
        finally:
            os.close(fd)
    except OSError as exc:
        raise AppleArtifactGateError("Apple PKG inner binary could not be read") from exc
    return magic in MACHO_MAGICS


def _inspect_native_binary(
    path: pathlib.Path,
    app: pathlib.Path,
    *,
    relative: str | None = None,
    expected_authority: str,
) -> dict[str, object]:
    if relative is None:
        relative = _posix_relative(path, app)
    _reject_private_symbol_path(relative)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AppleArtifactGateError(f"Apple PKG inner binary is unreadable: {relative}") from exc
    if len(data) <= 0:
        raise AppleArtifactGateError(f"Apple PKG inner binary is empty: {relative}")
    try:
        reject_packaged_private_symbols("macos", relative, data)
        reject_embedded_long_lived_credentials(relative, data)
        reject_unstripped_native_blob(relative, data)
        inspected = inspect_native_debug_sections(data)
    except ObfuscationError as exc:
        raise AppleArtifactGateError(str(exc)) from exc
    if inspected is None or inspected[0] != "macho":
        raise AppleArtifactGateError(f"Apple PKG inner binary is not Mach-O: {relative}")
    if inspected[1]:
        raise AppleArtifactGateError(
            f"Apple PKG inner binary retains debug sections: {relative}"
        )
    archs = _macho_architectures(path)
    load_commands = _reject_otool_debug_sections(path)
    symbols = _reject_nm_debug_symbols(path)
    _run_on_path(
        _codesign_verify_argv(
            _codesign_requirement_for_authority(expected_authority),
            deep=False,
        ),
        path,
        "Apple inner binary code-signature verification",
    )
    details = _run_on_path(
        ["/usr/bin/codesign", "-d", "--verbose=4"],
        path,
        "Apple inner binary signature inspection",
    )
    if details.stdout:
        raise AppleArtifactGateError(
            "Apple inner binary signature inspection returned unexpected stdout"
        )
    _require_release_codesign_identity(details.stderr, expected_authority)
    return {
        "path": relative,
        "sha256": _sha256_bytes(data),
        "bytes": len(data),
        "architectures": list(archs),
        "load_commands": load_commands,
        "symbols": symbols,
        "image": data,
    }


def _iter_app_regular_files(app: pathlib.Path) -> list[tuple[pathlib.Path, pathlib.Path, str]]:
    files: list[tuple[pathlib.Path, pathlib.Path, str]] = []
    for path, relative, info in _walk_tree(app):
        _reject_private_symbol_path(relative)
        if stat.S_ISLNK(info.st_mode):
            _reject_unsafe_symlink(path, app)
            try:
                resolved = path.resolve(strict=True)
                resolved_info = resolved.lstat()
            except OSError as exc:
                raise AppleArtifactGateError(
                    f"Apple PKG inner symlink could not be resolved: {relative}"
                ) from exc
            try:
                resolved.relative_to(app.resolve(strict=True))
            except (OSError, ValueError) as exc:
                raise AppleArtifactGateError(
                    "Apple PKG symlink escapes the expanded payload"
                ) from exc
            if stat.S_ISLNK(resolved_info.st_mode) or not stat.S_ISREG(resolved_info.st_mode):
                continue
            if resolved_info.st_nlink != 1:
                raise AppleArtifactGateError(
                    f"Apple PKG inner payload contains a hardlink: {relative}"
                )
            if resolved_info.st_size > MAX_INNER_FILE_BYTES:
                raise AppleArtifactGateError(
                    f"Apple PKG inner file exceeds the gate limit: {relative}"
                )
            files.append((path, resolved, relative))
            continue
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise AppleArtifactGateError(
                f"Apple PKG inner payload contains a special file: {relative}"
            )
        if info.st_nlink != 1:
            raise AppleArtifactGateError(
                f"Apple PKG inner payload contains a hardlink: {relative}"
            )
        if info.st_size > MAX_INNER_FILE_BYTES:
            raise AppleArtifactGateError(
                f"Apple PKG inner file exceeds the gate limit: {relative}"
            )
        files.append((path, path, relative))
    return files


def _tree_entry_record(path: pathlib.Path, root: pathlib.Path, info: os.stat_result) -> dict[str, object]:
    relative = _lexical_relative(path, root)
    mode = stat.S_IMODE(info.st_mode)
    base = {
        "path": relative,
        "owner": info.st_uid,
        "mode": mode,
        "nlink": info.st_nlink,
        "device": info.st_dev,
        "inode": info.st_ino,
        "ctime_ns": info.st_ctime_ns,
    }
    if stat.S_ISLNK(info.st_mode):
        target = _reject_unsafe_symlink(path, root)
        return {
            **base,
            "type": "symlink",
            "link_target": target,
            "bytes": 0,
            "sha256": "",
        }
    if stat.S_ISDIR(info.st_mode):
        return {
            **base,
            "type": "dir",
            "link_target": "",
            "bytes": 0,
            "sha256": "",
        }
    if stat.S_ISREG(info.st_mode):
        if info.st_nlink != 1:
            raise AppleArtifactGateError(
                f"Apple PKG inner payload contains a hardlink: {relative}"
            )
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise AppleArtifactGateError(
                f"Apple PKG inner file is unreadable: {relative}"
            ) from exc
        if len(data) != info.st_size:
            raise AppleArtifactGateError(
                f"Apple PKG inner file changed while it was hashed: {relative}"
            )
        return {
            **base,
            "type": "file",
            "link_target": "",
            "bytes": len(data),
            "sha256": _sha256_bytes(data),
        }
    raise AppleArtifactGateError(
        f"Apple PKG inner payload contains a special file: {relative}"
    )


def _inner_tree_records(root: pathlib.Path) -> list[dict[str, object]]:
    records = [_tree_entry_record(path, root, info) for path, _relative, info in _walk_tree(root)]
    records.sort(key=lambda item: str(item["path"]))
    bound = {str(item["path"]) for item in records}
    walked = _walk_tree(root)
    if len(walked) != len(records):
        raise AppleArtifactGateError("Apple PKG inner payload path binding is incomplete")
    for path, relative, _info in walked:
        if relative not in bound:
            raise AppleArtifactGateError(
                f"Apple PKG inner payload left a path unbound: {relative}"
            )
    return records


def _load_json_object(path: pathlib.Path, label: str) -> dict[str, object]:
    fd = -1
    try:
        fd = _bind_path_from_known_roots(path, directory=False)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > MAX_INNER_METADATA_BYTES
        ):
            raise AppleArtifactGateError(f"{label} is missing or invalid")
        raw = os.pread(fd, info.st_size, 0)
        after = os.fstat(fd)
        if (
            len(raw) != info.st_size
            or os.pread(fd, 1, info.st_size)
            or _pkg_vnode_identity(after) != _pkg_vnode_identity(info)
        ):
            raise AppleArtifactGateError(f"{label} changed while it was read")
    except AppleArtifactGateError:
        raise
    except OSError as exc:
        raise AppleArtifactGateError(f"{label} is missing or invalid") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        payload = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AppleArtifactGateError(f"{label} is missing or invalid") from exc
    if type(payload) is not dict:
        raise AppleArtifactGateError(f"{label} must be one JSON object")
    return payload


def _find_unique_named_file(app: pathlib.Path, filename: str) -> pathlib.Path | None:
    matches = [
        readable
        for _logical, readable, relative in _iter_app_regular_files(app)
        if pathlib.PurePosixPath(relative).name == filename
        or pathlib.PurePosixPath(relative).name.casefold() == filename.casefold()
    ]
    # Deduplicate by inode so a symlink and its target are one file.
    unique: list[pathlib.Path] = []
    seen: set[tuple[int, int]] = set()
    for path in matches:
        info = path.lstat()
        key = (info.st_dev, info.st_ino)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    if len(unique) > 1:
        raise AppleArtifactGateError(f"Apple PKG contains duplicate {filename} files")
    return unique[0] if unique else None


def _engine_component_for_relative(relative: str) -> str | None:
    folded_map = {name.casefold(): component for name, component in ENGINE_COMPONENT_BY_NAME.items()}
    for part in pathlib.PurePosixPath(relative).parts:
        mapped = folded_map.get(part.casefold())
        if mapped is not None:
            return mapped
    return None


def _hex_digest(value: object) -> str | None:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        return None
    return value


def _macos_wrapper_digest(document: dict[str, object], component: str) -> str:
    wrappers = document.get("wrappers")
    macosx = wrappers.get("macosx") if type(wrappers) is dict else None
    if type(macosx) is not dict:
        raise AppleArtifactGateError(
            f"Apple {component} inner provenance is missing a macosx wrapper record"
        )
    if component == "winn_packet_engine":
        digest = _hex_digest(macosx.get("sha256"))
        if digest is None:
            raise AppleArtifactGateError(
                "Apple Winn inner provenance does not bind a macosx wrapper digest"
            )
        return digest
    record = macosx.get(component)
    if type(record) is not dict:
        raise AppleArtifactGateError(
            f"Apple {component} inner provenance is missing a macosx wrapper record"
        )
    digest = _hex_digest(record.get("sha256"))
    if digest is None:
        raise AppleArtifactGateError(
            f"Apple {component} inner provenance does not bind a macosx wrapper digest"
        )
    return digest


def _macos_wrapper_normalized_digest(
    document: dict[str, object], component: str
) -> str | None:
    """The record's signature-normalized digest, None when it records none."""

    wrappers = document.get("wrappers")
    macosx = wrappers.get("macosx") if type(wrappers) is dict else None
    record = macosx if component == "winn_packet_engine" else (
        macosx.get(component) if type(macosx) is dict else None
    )
    if type(record) is not dict:
        raise AppleArtifactGateError(
            f"Apple {component} inner provenance is missing a macosx wrapper record"
        )
    if SIGNATURE_NORMALIZED_FIELD not in record:
        return None
    digest = _hex_digest(record.get(SIGNATURE_NORMALIZED_FIELD))
    if digest is None:
        raise AppleArtifactGateError(
            f"Apple {component} inner provenance signature-normalized digest is malformed"
        )
    return digest


def _signature_normalized_sha256(data: bytes, label: str) -> str:
    """SHA-256 of Mach-O bytes with their code signature normalized away.

    The provenance producers and the macOS verifier run the same procedure: a
    private copy is re-signed ad hoc, which replaces any linker, ad hoc or
    distribution signature on every slice, the signature is then removed, and
    the result is hashed. Signature validity and the signer are verified
    separately by the signed-code checks.
    """

    private = _PRIVATE_ROOT.get()
    parent = str(private.tmp) if private is not None else None
    with tempfile.TemporaryDirectory(prefix="wins-gate-normalize-", dir=parent) as scratch:
        copy = pathlib.Path(scratch) / "engine"
        fd = os.open(copy, _open_flags(write=True, exclusive=True), 0o600)
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        codesign = _reviewed_tool("/usr/bin/codesign")
        for argv, step in (
            (
                [codesign, "--force", "--sign", "-", "--timestamp=none", str(copy)],
                "signature normalization",
            ),
            ([codesign, "--remove-signature", str(copy)], "signature removal"),
        ):
            # codesign rewrites the whole copy, so the child gets the file-size
            # bound of an inner payload file, not the tool-output bound.
            completed = _bounded_subprocess(
                argv,
                f"{label} {step}",
                cwd="/",
                env=_subprocess_env(),
                timeout=TOOL_TIMEOUT_SEC,
                preexec_fn=_apply_child_rlimits,
            )
            if completed.returncode != 0:
                detail = _redact_tool_output(
                    (completed.stderr or completed.stdout).decode("utf-8", "replace").strip()
                )
                raise AppleArtifactGateError(
                    f"{label} {step} failed with exit {completed.returncode}: {detail}"
                )
        return _sha256_file(copy)


def _bind_engine_digests(
    app: pathlib.Path,
    staged_engines: set[str],
    awg: dict[str, object] | None,
    winn: dict[str, object] | None,
) -> list[dict[str, object]]:
    bound: list[dict[str, object]] = []
    normalized_by_digest: dict[str, str] = {}
    for _logical, readable, relative in _iter_app_regular_files(app):
        component = _engine_component_for_relative(relative)
        if component is None or not _is_macho(readable):
            continue
        digest = _sha256_file(readable)
        if component in AWG_ENGINE_COMPONENTS:
            if awg is None:
                raise AppleArtifactGateError(
                    "Apple PKG engine binaries are present without inner provenance"
                )
            document = awg
        elif component == "winn_packet_engine":
            if winn is None:
                raise AppleArtifactGateError(
                    "Apple PKG engine binaries are present without inner provenance"
                )
            document = winn
        else:
            raise AppleArtifactGateError(
                f"Apple PKG engine binary is not mapped to provenance: {relative}"
            )
        expected = _macos_wrapper_digest(document, component)
        recorded_normalized = _macos_wrapper_normalized_digest(document, component)
        normalized = normalized_by_digest.get(digest)
        if normalized is None:
            try:
                data = readable.read_bytes()
            except OSError as exc:
                raise AppleArtifactGateError(
                    f"Apple PKG inner binary is unreadable: {relative}"
                ) from exc
            if _sha256_bytes(data) != digest:
                raise AppleArtifactGateError(
                    f"Apple packaged {component} changed while it was hashed: {relative}"
                )
            normalized = _signature_normalized_sha256(data, f"Apple packaged {component}")
            normalized_by_digest[digest] = normalized
        # Staging signs the frameworks after provenance is written and Xcode
        # export signs them again, so a shipped engine matches its raw digest
        # only before signing. Otherwise the signature-normalized digest of the
        # same provenance record must match; a record without one refuses.
        if digest != expected and (
            recorded_normalized is None or normalized != recorded_normalized
        ):
            raise AppleArtifactGateError(
                f"Apple packaged {component} digest is not bound to inner provenance: {relative}"
            )
        bound.append(
            {
                "path": relative,
                "component": component,
                "sha256": digest,
                SIGNATURE_NORMALIZED_FIELD: normalized,
            }
        )
    bound_components = {item["component"] for item in bound}
    if bound_components != staged_engines:
        raise AppleArtifactGateError(
            "Apple engine artifact manifest does not match staged inner engine binaries"
        )
    bound.sort(key=lambda item: str(item["path"]))
    return bound


def _verify_inner_provenance(app: pathlib.Path) -> dict[str, object]:
    manifest_path = _find_unique_named_file(app, "apple_engine_artifacts_manifest.json")
    awg_path = _find_unique_named_file(app, "apple_awg_31_engine_provenance.json")
    winn_path = _find_unique_named_file(app, "apple_winn_v3_engine_provenance.json")
    staged_engines: set[str] = set()
    for _logical, readable, relative in _iter_app_regular_files(app):
        component = _engine_component_for_relative(relative)
        if component is not None and _is_macho(readable):
            staged_engines.add(component)
    if staged_engines and manifest_path is None:
        raise AppleArtifactGateError(
            "Apple PKG engine binaries are present without inner provenance"
        )
    if manifest_path is None:
        if awg_path is not None or winn_path is not None:
            raise AppleArtifactGateError(
                "Apple PKG provenance files are not bound by an engine manifest"
            )
        return {"present": False, "staged_components": [], "engine_bindings": []}

    manifest = _load_json_object(manifest_path, "Apple engine artifact manifest")
    staged = manifest.get("staged_components")
    if type(staged) is not list or any(type(item) is not str for item in staged):
        raise AppleArtifactGateError("Apple engine artifact manifest staged_components is invalid")
    if set(staged) != staged_engines:
        raise AppleArtifactGateError(
            "Apple engine artifact manifest does not match staged inner engine binaries"
        )
    awg_hash = manifest.get("apple_awg_31_provenance_sha256")
    winn_hash = manifest.get("apple_winn_v3_provenance_sha256")
    awg_doc: dict[str, object] | None = None
    winn_doc: dict[str, object] | None = None
    if staged_engines.intersection(AWG_ENGINE_COMPONENTS):
        if type(awg_hash) is not str or re.fullmatch(r"[0-9a-f]{64}", awg_hash) is None:
            raise AppleArtifactGateError("Apple AWG inner provenance hash is missing")
        if awg_path is None or _sha256_file(awg_path) != awg_hash:
            raise AppleArtifactGateError("Apple AWG inner provenance hash does not match")
        awg_doc = _load_json_object(awg_path, "Apple AWG engine provenance")
        source = awg_doc.get("source") if type(awg_doc.get("source")) is dict else {}
        if (
            awg_doc.get("generation") != REVIEWED_AWG_SOURCE["generation"]
            or source.get("commit") != REVIEWED_AWG_SOURCE["commit"]
            or source.get("tag") != REVIEWED_AWG_SOURCE["tag"]
        ):
            raise AppleArtifactGateError("Apple AWG inner provenance is not the reviewed recipe")
    if "winn_packet_engine" in staged_engines:
        if type(winn_hash) is not str or re.fullmatch(r"[0-9a-f]{64}", winn_hash) is None:
            raise AppleArtifactGateError("Apple Winn inner provenance hash is missing")
        if winn_path is None or _sha256_file(winn_path) != winn_hash:
            raise AppleArtifactGateError("Apple Winn inner provenance hash does not match")
        winn_doc = _load_json_object(winn_path, "Apple Winn engine provenance")
    engine_bindings = _bind_engine_digests(app, staged_engines, awg_doc, winn_doc)
    return {
        "present": True,
        "manifest_sha256": _sha256_file(manifest_path),
        "staged_components": sorted(staged_engines),
        "engine_bindings": engine_bindings,
    }


def _posix_normalize_source(parts: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    for part in parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not out:
                raise AppleArtifactGateError("native-host source path escapes the repository")
            out.pop()
            continue
        out.append(part)
    return tuple(out)


def macos_native_host_source_paths() -> tuple[str, ...]:
    paths = list(source_freeze.SOURCE_PATHS_NATIVE_HOST)
    paths.extend(MACOS_NATIVE_HOST_EXTRA_SOURCES)
    for alias, target in source_freeze.SOURCE_SYMLINK_ALIASES:
        resolved = pathlib.PurePosixPath(alias).parent.joinpath(target)
        paths.append(pathlib.PurePosixPath(*_posix_normalize_source(resolved.parts)).as_posix())
    return tuple(sorted(set(paths)))


def _read_origin_regular(relative: str, label: str) -> bytes:
    path = ORIGIN_ROOT / relative
    flags = _open_flags()
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AppleArtifactGateError(f"{label} is missing.") from exc
    try:
        info = os.fstat(fd)
        path_info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or _file_identity(info) != _file_identity(path_info)
        ):
            raise AppleArtifactGateError(f"{label} must be one non-empty, single-link file.")
        payload = os.pread(fd, info.st_size, 0)
        after = os.fstat(fd)
        if len(payload) != info.st_size or _file_identity(after) != _file_identity(info):
            raise AppleArtifactGateError(f"{label} mutated while it was read.")
        return payload
    finally:
        os.close(fd)


def compute_macos_native_host_source_closure() -> tuple[str, list[dict[str, object]]]:
    records: list[dict[str, object]] = []
    for relative in macos_native_host_source_paths():
        path = ORIGIN_ROOT / relative
        if relative == OPTIONAL_NATIVE_HOST_SOURCE and not path.is_file():
            continue
        payload = _read_origin_regular(relative, f"native-host source {relative}")
        records.append(
            {
                "path": relative,
                "sha256": _sha256_bytes(payload),
                "bytes": len(payload),
            }
        )
    encoded = (
        json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")
    return _sha256_bytes(encoded), records


def bind_macos_native_host_source_freeze() -> str:
    # The digest covers every native-host source as one non-empty, single-link
    # regular file read without following symlinks, and must equal the
    # committed reviewed pin.
    digest, _records = compute_macos_native_host_source_closure()
    if digest != MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256:
        raise AppleArtifactGateError(
            "native-host source closure changed: "
            f"reviewed={MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256} current={digest}; "
            "review the changed inputs and update "
            "MACOS_NATIVE_HOST_SOURCE_CLOSURE_SHA256 in the same change"
        )
    return digest


def macos_native_messaging_packaging_scope(target_id: str) -> dict[str, object]:
    return {
        "delivered": False,
        "incompatible": True,
        "target_id": target_id,
        "installed_host_path": MACOS_NATIVE_HOST_SYSTEM_PATH,
        "reasons": list(MACOS_NATIVE_MESSAGING_INCOMPATIBILITY_REASONS),
    }


def _is_packaged_native_messaging_path(relative: str) -> bool:
    name = pathlib.PurePosixPath(relative).name
    if name == NATIVE_HOST_BASENAME or name.startswith(f"{NATIVE_HOST_JSON_NAME}."):
        return True
    if name == f"{NATIVE_HOST_JSON_NAME}.json":
        return True
    parts = pathlib.PurePosixPath(relative).parts
    return "NativeMessagingHost" in parts or "NativeMessagingHosts" in parts


def packaged_native_messaging_paths(root: pathlib.Path) -> list[str]:
    found: list[str] = []
    for _path, relative, _info in _walk_tree(root):
        if _is_packaged_native_messaging_path(relative):
            found.append(relative)
    found.sort()
    return found


def reject_packaged_native_messaging_host(root: pathlib.Path) -> None:
    found = packaged_native_messaging_paths(root)
    if found:
        raise AppleArtifactGateError(
            MACOS_NATIVE_MESSAGING_INCOMPATIBILITY + " packaged path: " + found[0]
        )


def _native_host_json(payload: bytes, label: str) -> dict[str, object]:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise AppleArtifactGateError(f"{label} has a duplicate JSON key.")
            result[key] = value
        return result

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AppleArtifactGateError(f"{label} is not canonical JSON.") from exc
    if type(document) is not dict:
        raise AppleArtifactGateError(f"{label} must be one JSON object.")
    encoded = json.dumps(document, ensure_ascii=True)
    if "placeholder" in encoded.casefold():
        raise AppleArtifactGateError(f"{label} still contains a placeholder.")
    return document


def _shared_native_host_manifest(host_path: str) -> dict[str, object]:
    if not host_path or not pathlib.PurePosixPath(host_path).is_absolute():
        raise AppleArtifactGateError("native-host manifest path must be the exact installed absolute path.")
    if "placeholder" in host_path.casefold():
        raise AppleArtifactGateError("native-host manifest path is still a placeholder.")
    return {
        "name": NATIVE_HOST_JSON_NAME,
        "description": NATIVE_HOST_JSON_DESCRIPTION,
        "path": host_path,
        "type": "stdio",
    }


def verify_macos_native_host_manifests(
    *,
    host_path: str,
    firefox: dict[str, object],
    chrome: dict[str, object] | None,
    owner_chrome_id: str | None,
) -> None:
    if "placeholder" in json.dumps({"path": host_path, "firefox": firefox, "chrome": chrome}, ensure_ascii=True).casefold():
        raise AppleArtifactGateError("native-host manifest still contains a placeholder.")
    shared = _shared_native_host_manifest(host_path)
    if firefox != {**shared, "allowed_extensions": [FIREFOX_NATIVE_EXTENSION_ID]}:
        raise AppleArtifactGateError("Firefox native-host manifest is not exact.")
    if owner_chrome_id is None:
        if chrome is not None:
            raise AppleArtifactGateError(
                "Chrome native-host manifest is owner-blocked until a current "
                "owner-issued store-listing id exists."
            )
        return
    if CHROMIUM_EXTENSION_ID.fullmatch(owner_chrome_id) is None:
        raise AppleArtifactGateError("native-host Chrome store-listing id is invalid.")
    if chrome is None:
        raise AppleArtifactGateError("Chrome native-host manifest is missing for an owner-issued id.")
    expected = {
        **shared,
        "allowed_origins": [f"chrome-extension://{owner_chrome_id}/"],
    }
    if chrome != expected:
        raise AppleArtifactGateError("Chrome native-host manifest is not exact.")


def native_host_release_line() -> str:
    """Return the MAJOR.MINOR.PATCH release line from pubspec.yaml."""

    try:
        text = (ROOT / "pubspec.yaml").read_text(encoding="utf-8")
    except OSError as exc:
        raise AppleArtifactGateError("pubspec.yaml is unreadable.") from exc
    match = re.search(r"(?m)^version:\s*([0-9]+\.[0-9]+\.[0-9]+)\+[0-9]+\s*$", text)
    if match is None:
        raise AppleArtifactGateError("pubspec.yaml release version is unreadable.")
    return match.group(1)


def verify_macos_native_host_slices(data: bytes) -> tuple[str, ...]:
    try:
        slices = _macho_slices(data)
    except struct.error as exc:
        raise AppleArtifactGateError("native-host Mach-O header is malformed") from exc
    archs = tuple(arch for arch, _filetype in slices)
    filetypes = {filetype for _arch, filetype in slices}
    if filetypes != {MH_EXECUTE}:
        raise AppleArtifactGateError("native-host Mach-O filetype must be MH_EXECUTE")
    accepted = [REQUIRED_NATIVE_HOST_ARCHITECTURES]
    if native_host_release_line() in NATIVE_HOST_ARM64_ONLY_RELEASE_LINES:
        accepted.append(NATIVE_HOST_ARM64_ONLY_ARCHITECTURES)
    if set(archs) not in accepted:
        raise AppleArtifactGateError(
            "native-host must be a universal x86_64+arm64 Mach-O executable"
            + (
                " or, under the owner ruling of "
                + NATIVE_HOST_ARM64_ONLY_OWNER_RULING_DATE
                + ", an arm64 executable"
                if len(accepted) > 1
                else ""
            )
        )
    if len(archs) != len(set(archs)):
        raise AppleArtifactGateError("native-host Mach-O contains a duplicate architecture")
    return archs


def _reject_app_store_native_host_authority(output: str) -> None:
    authorities, _teams = _codesign_authority_and_team(output)
    if authorities and (
        authorities[0].startswith(APP_STORE_DISTRIBUTION_AUTHORITY)
        or authorities[0].casefold().startswith("authority=3rd party mac developer")
    ):
        raise AppleArtifactGateError(
            MACOS_NATIVE_MESSAGING_INCOMPATIBILITY
            + " App Store signing cannot cover a native-messaging host outside the sandboxed app."
        )


def verify_macos_native_host_binary(
    path: pathlib.Path,
    *,
    require_signature: bool = False,
    require_notarization: bool = False,
    require_source_closure: bool = False,
) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise AppleArtifactGateError("native-host binary must be one regular file")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AppleArtifactGateError("native-host binary is unreadable") from exc
    if not data:
        raise AppleArtifactGateError("native-host binary is empty")
    archs = verify_macos_native_host_slices(data)
    record: dict[str, object] = {
        "path": NATIVE_HOST_BASENAME,
        "sha256": _sha256_bytes(data),
        "bytes": len(data),
        "architectures": sorted(archs),
        "installed_host_path": MACOS_NATIVE_HOST_SYSTEM_PATH,
    }
    if require_source_closure:
        record["source_closure_sha256"] = bind_macos_native_host_source_freeze()
    if require_signature or require_notarization:
        if require_signature:
            _run_on_path(
                _codesign_verify_argv(
                    _codesign_requirement_for_authority(
                        DEVELOPER_ID_APPLICATION_AUTHORITY
                    ),
                    deep=False,
                ),
                path,
                "native-host cryptographic signature verification",
            )
        details = _run_on_path(
            ["/usr/bin/codesign", "-d", "--verbose=4"],
            path,
            "native-host signature identity inspection",
        )
        output = details.stdout + details.stderr
        _reject_app_store_native_host_authority(output)
        if require_signature:
            _require_release_codesign_identity(
                output, DEVELOPER_ID_APPLICATION_AUTHORITY
            )
            record["team_id"] = TEAM_ID
        if require_notarization:
            _assess_notarization(path, "execute")
            record["notarized"] = True
    return record


def macos_native_host_handshake(path: pathlib.Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise AppleArtifactGateError("native-host handshake requires a regular executable")
    with tempfile.TemporaryDirectory(
        prefix="wins-native-host-handshake-"
    ) as temporary:
        private = _prepare_private_root(pathlib.Path(temporary))
        token = _PRIVATE_ROOT.set(private)
        snapshot: AuthenticatedPkgSnapshot | None = None
        try:
            snapshot = _snapshot_pkg(
                path,
                private.snapshot_dir / NATIVE_HOST_BASENAME,
                destination_mode=0o500,
            )
            return _macos_native_host_handshake_snapshot(snapshot)
        finally:
            if snapshot is not None:
                snapshot.close()
            _cleanup_private_root(private)
            _PRIVATE_ROOT.reset(token)


def _macos_native_host_handshake_snapshot(
    snapshot: AuthenticatedPkgSnapshot,
) -> dict[str, object]:
    snapshot.ensure_bound()
    verified = verify_macos_native_host_binary(
        snapshot.path,
        require_signature=True,
        require_notarization=True,
        require_source_closure=True,
    )
    if (
        verified.get("sha256") != snapshot.digest
        or verified.get("bytes") != snapshot.size
        or snapshot.rehash() != snapshot.digest
    ):
        raise AppleArtifactGateError(
            "native-host verified bytes do not match the retained executable"
        )
    candidate_binding = _receipt_exact_mapping(
        {
            key: verified.get(key)
            for key in (
                "sha256",
                "bytes",
                "architectures",
                "source_closure_sha256",
                "team_id",
                "notarized",
            )
        },
        {
            "sha256",
            "bytes",
            "architectures",
            "source_closure_sha256",
            "team_id",
            "notarized",
        },
        "native-host authenticated candidate binding",
    )
    _receipt_hex64(candidate_binding.get("sha256"), "native-host candidate")
    _receipt_hex64(
        candidate_binding.get("source_closure_sha256"),
        "native-host source closure",
    )
    accepted_architectures = [sorted(REQUIRED_NATIVE_HOST_ARCHITECTURES)]
    if native_host_release_line() in NATIVE_HOST_ARM64_ONLY_RELEASE_LINES:
        accepted_architectures.append(sorted(NATIVE_HOST_ARM64_ONLY_ARCHITECTURES))
    if (
        type(candidate_binding.get("bytes")) is not int
        or int(candidate_binding["bytes"]) <= 0
        or candidate_binding.get("architectures") not in accepted_architectures
        or candidate_binding.get("team_id") != TEAM_ID
        or candidate_binding.get("notarized") is not True
    ):
        raise AppleArtifactGateError(
            "native-host authenticated candidate binding is incomplete"
        )
    request_id = secrets.token_hex(32)
    frame = json.dumps(
        {
            "type": "hello",
            "request_id": request_id,
            "protocol_version": 1,
            "candidate_binding": candidate_binding,
        },
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    completed = _bounded_subprocess(
        [snapshot.kernel_path()],
        "native-host handshake",
        cwd="/",
        env={
            "PATH": REVIEWED_SUBPROCESS_PATH,
            "HOME": "/var/empty",
            "TMPDIR": "/tmp",
            "LANG": "C",
            "LC_ALL": "C",
        },
        timeout=8,
        stderr=subprocess.DEVNULL,
        preexec_fn=_apply_tool_rlimits,
        input_data=struct.pack("<I", len(frame)) + frame,
    )
    out = completed.stdout
    if completed.returncode != 0 or len(out) < 4:
        raise AppleArtifactGateError("native-host handshake did not return a framed reply")
    (size,) = struct.unpack("<I", out[:4])
    if size <= 0 or 4 + size != len(out):
        raise AppleArtifactGateError("native-host handshake frame is truncated")
    try:
        reply = json.loads(
            out[4 : 4 + size].decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AppleArtifactGateError("native-host handshake reply is not JSON") from exc
    reply = _receipt_exact_mapping(
        reply,
        {
            "type",
            "request_id",
            "protocol_version",
            "candidate_binding",
            "accepted",
        },
        "native-host handshake reply",
    )
    if (
        reply.get("type") != "hello"
        or reply.get("request_id") != request_id
        or reply.get("protocol_version") != 1
        or reply.get("candidate_binding") != candidate_binding
        or reply.get("accepted") is not True
    ):
        raise AppleArtifactGateError(
            "native-host handshake reply is not bound to the authenticated candidate"
        )
    if snapshot.rehash() != str(candidate_binding["sha256"]):
        raise AppleArtifactGateError(
            "native-host executed bytes changed after the handshake"
        )
    return reply


def _load_manifest_file(path: pathlib.Path, label: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise AppleArtifactGateError(f"{label} must be one regular file")
    return _native_host_json(path.read_bytes(), label)


def native_host_main(argv: list[str]) -> int:
    if not argv:
        raise AppleArtifactGateError(
            "usage: apple_cross_store_artifact_gate.py native-host "
            "verify-binary|handshake|verify-manifests|refuse-packaged|scope"
        )
    command = argv[0]
    if command == "scope":
        document = macos_native_messaging_packaging_scope("macos-app-store-pkg")
        sys.stdout.write(
            json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        )
        return 0
    if command == "verify-binary":
        host = ""
        require_signature = False
        require_notarization = False
        require_source_closure = False
        rest = argv[1:]
        while rest:
            if rest[0] == "--host":
                host = rest[1] if len(rest) > 1 else ""
                rest = rest[2:]
                continue
            if rest[0] == "--require-signature":
                require_signature = True
                rest = rest[1:]
                continue
            if rest[0] == "--require-notarization":
                require_notarization = True
                rest = rest[1:]
                continue
            if rest[0] == "--require-source-closure":
                require_source_closure = True
                rest = rest[1:]
                continue
            raise AppleArtifactGateError("native-host verify-binary arguments are invalid")
        if not host:
            raise AppleArtifactGateError("native-host verify-binary requires --host")
        record = verify_macos_native_host_binary(
            pathlib.Path(host),
            require_signature=require_signature,
            require_notarization=require_notarization,
            require_source_closure=require_source_closure,
        )
        sys.stdout.write(
            json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        )
        return 0
    if command == "handshake":
        if len(argv) != 3 or argv[1] != "--host":
            raise AppleArtifactGateError("native-host handshake requires --host PATH")
        macos_native_host_handshake(pathlib.Path(argv[2]))
        print("APPLE NATIVE-HOST HANDSHAKE: PASS")
        return 0
    if command == "verify-manifests":
        host_path = ""
        firefox_path = ""
        chrome_path = ""
        owner_chrome_id: str | None = None
        rest = argv[1:]
        while rest:
            if rest[0] == "--host-path" and len(rest) > 1:
                host_path = rest[1]
                rest = rest[2:]
                continue
            if rest[0] == "--firefox" and len(rest) > 1:
                firefox_path = rest[1]
                rest = rest[2:]
                continue
            if rest[0] == "--chrome" and len(rest) > 1:
                chrome_path = rest[1]
                rest = rest[2:]
                continue
            if rest[0] == "--owner-chrome-id" and len(rest) > 1:
                owner_chrome_id = rest[1]
                rest = rest[2:]
                continue
            raise AppleArtifactGateError("native-host verify-manifests arguments are invalid")
        if not host_path or not firefox_path:
            raise AppleArtifactGateError("native-host verify-manifests requires --host-path and --firefox")
        chrome_doc = None
        if chrome_path:
            chrome_doc = _load_manifest_file(pathlib.Path(chrome_path), "Chrome native-host manifest")
        verify_macos_native_host_manifests(
            host_path=host_path,
            firefox=_load_manifest_file(pathlib.Path(firefox_path), "Firefox native-host manifest"),
            chrome=chrome_doc,
            owner_chrome_id=owner_chrome_id,
        )
        print("APPLE NATIVE-HOST MANIFESTS: PASS")
        return 0
    if command == "refuse-packaged":
        if len(argv) != 3 or argv[1] not in {"--root", "--artifact"}:
            raise AppleArtifactGateError("native-host refuse-packaged requires --root|--artifact PATH")
        root = pathlib.Path(argv[2])
        if argv[1] == "--root":
            reject_packaged_native_messaging_host(root)
            print("APPLE NATIVE-HOST PACKAGING: PASS packaged=absent")
            return 0
        with tempfile.TemporaryDirectory(prefix="wins-apple-native-host-") as temporary:
            private = _prepare_private_root(pathlib.Path(temporary))
            token = _PRIVATE_ROOT.set(private)
            snapshot: AuthenticatedPkgSnapshot | None = None
            tree: AuthenticatedTreeSnapshot | None = None
            try:
                artifact, snapshot = _snapshot_canonical_artifact(
                    "macos-app-store-pkg", root, private.snapshot_file
                )
                del artifact
                tree_root = private.root / "expanded"
                _app, tree = _expand_pkg(snapshot, tree_root)
                reject_packaged_native_messaging_host(tree.root)
            finally:
                if snapshot is not None:
                    snapshot.close()
                if tree is not None:
                    tree.close()
                _cleanup_private_root(private)
                _PRIVATE_ROOT.reset(token)
        print("APPLE NATIVE-HOST PACKAGING: PASS packaged=absent")
        return 0
    raise AppleArtifactGateError(
        "usage: apple_cross_store_artifact_gate.py native-host "
        "verify-binary|handshake|verify-manifests|refuse-packaged|scope"
    )


def _inspect_macos_inner_payload(
    app: pathlib.Path,
    expanded: pathlib.Path,
    *,
    bundles: list[dict[str, object]] | None = None,
    target_id: str = "macos-app-store-pkg",
) -> dict[str, object]:
    reject_packaged_native_messaging_host(expanded)
    aot = _macos_aot_image(app)
    natives: list[dict[str, object]] = []
    for _logical, readable, relative in _iter_app_regular_files(app):
        try:
            data = readable.read_bytes()
        except OSError as exc:
            raise AppleArtifactGateError(f"Apple PKG inner file is unreadable: {relative}") from exc
        try:
            reject_packaged_private_symbols("macos", relative, data)
            reject_embedded_long_lived_credentials(relative, data)
        except ObfuscationError as exc:
            raise AppleArtifactGateError(str(exc)) from exc
        if not _is_macho(readable):
            continue
        natives.append(
            _inspect_native_binary(
                readable,
                app,
                relative=relative,
                expected_authority=str(
                    APPLE_PACKAGE_UPLOAD_TARGETS[target_id]["expected_authority"]
                ),
            )
        )
    aot_resolved = aot.resolve(strict=True)
    aot_records = []
    for record in natives:
        logical = app / str(record["path"])
        if logical.is_symlink():
            # A versioned App.framework's top-level App link names the same file
            # as Versions/A/App; only the real file's record may count.
            continue
        candidate = logical.resolve(strict=True)
        if candidate == aot_resolved:
            aot_records.append(record)
    if len(aot_records) != 1:
        raise AppleArtifactGateError("Flutter AOT payload was not inspected as Mach-O")
    aot_record = aot_records[0]
    _require_flutter_aot_contract(
        aot,
        bytes(aot_record.pop("image")),
        tuple(str(arch) for arch in aot_record["architectures"]),
        str(aot_record.pop("load_commands")),
        str(aot_record.pop("symbols")),
    )
    for record in natives:
        record.pop("image", None)
        record.pop("load_commands", None)
        record.pop("symbols", None)
    natives.sort(key=lambda record: str(record["path"]))
    provenance = _verify_inner_provenance(app)
    tree = _inner_tree_records(expanded)
    snapshot = _TREE_SNAPSHOT.get()
    if snapshot is not None:
        snapshot.ensure_bound()
        try:
            expanded.resolve(strict=True).relative_to(snapshot.root.resolve(strict=True))
            app.resolve(strict=True).relative_to(snapshot.root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise AppleArtifactGateError(
                "Apple PKG inspection escaped the expanded-tree snapshot"
            ) from exc
        for record in snapshot.records:
            if record["type"] != "file":
                continue
            path = snapshot.root / str(record["path"])
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise AppleArtifactGateError(
                    f"Apple PKG inner file is unreadable: {record['path']}"
                ) from exc
            if _sha256_bytes(data) != record["sha256"] or len(data) != record["bytes"]:
                raise AppleArtifactGateError(
                    f"Apple PKG expanded-tree snapshot mutated: {record['path']}"
                )
        tree = snapshot.records
    document = {
        "schema": INNER_PAYLOAD_SCHEMA,
        "app": _posix_relative(app, expanded),
        "aot": aot_record,
        "natives": natives,
        "bundles": bundles or [],
        "provenance": provenance,
        "native_messaging": macos_native_messaging_packaging_scope(target_id),
        "tree": tree,
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    document["inner_payload_sha256"] = _sha256_bytes(encoded)
    return document


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise AppleArtifactGateError("Apple PKG snapshot write was truncated")
        view = view[written:]


def _mkdir_private_relative(destination: pathlib.Path) -> None:
    private = _PRIVATE_ROOT.get()
    if private is None or private.root_fd < 0:
        raise AppleArtifactGateError("Apple gate private root is required")
    parts = _lexical_parts_under(private.root, destination)
    if not parts:
        raise AppleArtifactGateError(
            "Apple gate destination is not inside the private root"
        )
    fd = os.dup(private.root_fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except OSError as exc:
                raise AppleArtifactGateError(
                    "Apple gate destination already exists"
                ) from exc
            child = _openat_child(fd, part, _dir_open_flags())
            os.close(fd)
            fd = child
            os.fchmod(fd, 0o700)
    finally:
        os.close(fd)


def _create_exclusive_under_known_root(destination: pathlib.Path) -> int:
    private = _PRIVATE_ROOT.get()
    if private is not None and private.root_fd >= 0:
        parts = _lexical_parts_under(private.root, destination)
        if parts:
            parent_parts, name = parts[:-1], parts[-1]
            parent_fd = _openat_relative(
                private.root_fd, parent_parts, last_directory=True
            )
            try:
                return os.open(
                    name,
                    _open_flags(write=True, exclusive=True),
                    0o400,
                    dir_fd=parent_fd,
                )
            finally:
                os.close(parent_fd)
    return os.open(destination, _open_flags(write=True, exclusive=True), 0o400)


def _fchmod_directory_under_known_root(path: pathlib.Path, mode: int) -> None:
    fd = _bind_path_from_known_roots(path, directory=True)
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _prepare_private_root(root: pathlib.Path) -> PrivateGateRoot:
    if root.is_symlink():
        raise AppleArtifactGateError("Apple gate private root must not be a symlink")
    root_fd = -1
    try:
        root_fd = os.open(root, _dir_open_flags())
        os.fchmod(root_fd, 0o700)
        info = os.fstat(root_fd)
    except OSError as exc:
        if root_fd >= 0:
            os.close(root_fd)
        raise AppleArtifactGateError("Apple gate private root is unreadable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.getuid()
    ):
        os.close(root_fd)
        raise AppleArtifactGateError(
            "Apple gate private root must be a 0700 owner directory"
        )
    snapshot_dir = root / "snapshot"
    tree_dir = root / "tree"
    home = root / "home"
    tmp = root / "tmp"
    for name, path in (
        ("snapshot", snapshot_dir),
        ("tree", tree_dir),
        ("home", home),
        ("tmp", tmp),
    ):
        try:
            os.mkdir(name, 0o700, dir_fd=root_fd)
            child = _openat_child(root_fd, name, _dir_open_flags())
            try:
                os.fchmod(child, 0o700)
                path_info = os.fstat(child)
            finally:
                os.close(child)
        except OSError as exc:
            os.close(root_fd)
            raise AppleArtifactGateError("Apple gate private root could not be created") from exc
        if not stat.S_ISDIR(path_info.st_mode) or stat.S_IMODE(path_info.st_mode) != 0o700:
            os.close(root_fd)
            raise AppleArtifactGateError("Apple gate private directory is unsafe")
    try:
        private = PrivateGateRoot(
            root=root,
            snapshot_dir=snapshot_dir,
            snapshot_file=snapshot_dir / "package.pkg",
            tree_dir=tree_dir,
            home=home,
            tmp=tmp,
            root_fd=root_fd,
        )
    except Exception:
        os.close(root_fd)
        raise
    private.verify_ancestors()
    return private


def _snapshot_pkg(
    source: pathlib.Path,
    destination: pathlib.Path,
    *,
    source_fd: int | None = None,
    destination_mode: int = 0o400,
) -> AuthenticatedPkgSnapshot:
    if destination_mode not in {0o400, 0o500}:
        raise AppleArtifactGateError("Apple authenticated snapshot mode is invalid")
    if destination.exists() or destination.is_symlink():
        raise AppleArtifactGateError("Apple PKG snapshot destination already exists")
    close_source = source_fd is None
    dest_fd = -1
    snapshot_fd = -1
    parent_fd = -1
    try:
        if source_fd is None:
            source_fd = os.open(source, _open_flags())
        before = os.fstat(source_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_PKG_BYTES
        ):
            raise AppleArtifactGateError(
                "Apple PKG must be one regular non-hardlinked file within the package bound"
            )
        dest_fd = _create_exclusive_under_known_root(destination)
        os.fchmod(dest_fd, destination_mode)
        digest = hashlib.sha256()
        remaining = before.st_size
        offset = 0
        while remaining:
            block = os.pread(source_fd, min(READ_CHUNK, remaining), offset)
            if not block:
                raise AppleArtifactGateError("Apple PKG mutated during authenticated snapshot")
            digest.update(block)
            _write_all(dest_fd, block)
            offset += len(block)
            remaining -= len(block)
        extra = os.pread(source_fd, 1, offset)
        if extra:
            raise AppleArtifactGateError("Apple PKG mutated during authenticated snapshot")
        after_source = os.fstat(source_fd)
        if _file_identity(before) != _file_identity(after_source):
            raise AppleArtifactGateError("Apple PKG mutated during authenticated snapshot")
        if close_source:
            latest_source = source.lstat()
            if _file_identity(before) != _file_identity(latest_source):
                raise AppleArtifactGateError("Apple PKG mutated during authenticated snapshot")
        os.fsync(dest_fd)
        if _sha256_fd(dest_fd, before.st_size) != digest.hexdigest():
            raise AppleArtifactGateError("Apple PKG snapshot digest mismatch")
        os.fchmod(dest_fd, destination_mode)
        if UF_IMMUTABLE:
            _require_fchflags(dest_fd, UF_IMMUTABLE)
        sealed_writer = os.fstat(dest_fd)
        identity = _snapshot_file_identity(sealed_writer)
        vnode_identity = _pkg_vnode_identity(sealed_writer)
        os.close(dest_fd)
        dest_fd = -1

        parent_fd = _bind_path_from_known_roots(destination.parent, directory=True)
        os.fchmod(parent_fd, 0o500)
        if UF_IMMUTABLE:
            _require_fchflags(parent_fd, UF_IMMUTABLE)
        parent_identity = _snapshot_directory_identity(os.fstat(parent_fd))
        snapshot_fd = os.open(
            destination.name,
            _open_flags(),
            dir_fd=parent_fd,
        )
        reopened = os.fstat(snapshot_fd)
        named = os.stat(
            destination.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            _snapshot_file_identity(reopened) != identity
            or _snapshot_file_identity(named) != identity
            or _sha256_fd(snapshot_fd, before.st_size) != digest.hexdigest()
        ):
            raise AppleArtifactGateError(
                "Apple PKG snapshot changed before read-only custody"
            )
        _require_read_only_descriptor(snapshot_fd, "Apple PKG authenticated snapshot")
        volfs = _authenticate_volfs(snapshot_fd, vnode_identity)
        snapshot = AuthenticatedPkgSnapshot(
            path=destination,
            fd=snapshot_fd,
            identity=identity,
            vnode_identity=vnode_identity,
            parent_fd=parent_fd,
            parent_identity=parent_identity,
            digest=digest.hexdigest(),
            size=before.st_size,
            volfs=volfs,
            expected_mode=destination_mode,
        )
        snapshot_fd = -1
        parent_fd = -1
    except OSError as exc:
        raise AppleArtifactGateError(
            f"Apple PKG snapshot failed: {_redact_tool_output(str(exc))}"
        ) from exc
    finally:
        if close_source and source_fd is not None and source_fd >= 0:
            os.close(source_fd)
            source_fd = -1
        if dest_fd >= 0:
            os.close(dest_fd)
        if snapshot_fd >= 0:
            os.close(snapshot_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
    try:
        snapshot.ensure_bound()
    except BaseException:
        snapshot.close()
        raise
    return snapshot


def _snapshot_held_apple_artifact(
    *,
    private: PrivateGateRoot,
    source_fd: int,
    source_parent_fd: int,
    source_name: str,
    source_relative_path: str,
    expected_identity: tuple[int, ...],
    expected_size: int,
    expected_sha256: str,
) -> tuple[HeldAppleArtifactCustody, AuthenticatedPkgSnapshot]:
    custody: HeldAppleArtifactCustody | None = None
    snapshot: AuthenticatedPkgSnapshot | None = None
    try:
        custody = HeldAppleArtifactCustody(
            source_fd=source_fd,
            source_parent_fd=source_parent_fd,
            source_name=source_name,
            source_relative_path=source_relative_path,
            expected_identity=expected_identity,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        )
        snapshot = _snapshot_pkg(
            custody.origin,
            private.snapshot_file,
            source_fd=custody.source_fd,
        )
        if (
            snapshot.digest != expected_sha256
            or snapshot.size != expected_size
            or snapshot.rehash() != custody.rehash()
        ):
            raise AppleArtifactGateError(
                "held Apple artifact private snapshot does not match the frozen candidate"
            )
        return custody, snapshot
    except Exception:
        if snapshot is not None:
            snapshot.close()
        if custody is not None:
            custody.close(verify=False)
        raise


def _snapshot_canonical_artifact(
    target_id: str,
    raw_path: str | pathlib.Path,
    destination: pathlib.Path,
) -> tuple[pathlib.Path, AuthenticatedPkgSnapshot]:
    suffixes = _apple_target_suffixes(target_id)
    path = pathlib.Path(raw_path)
    fd, lexical, identity = _bind_repo_relative(path)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size <= 0
            or info.st_nlink != 1
            or identity != _pkg_vnode_identity(info)
        ):
            raise AppleArtifactGateError(
                "Apple gate artifact must be a non-empty regular single-link file"
            )
        lowered = lexical.name.lower()
        if not any(lowered.endswith(suffix) for suffix in suffixes):
            raise AppleArtifactGateError(
                f"{target_id} requires artifact suffix: {', '.join(suffixes)}"
            )
        snapshot = _snapshot_pkg(lexical, destination, source_fd=fd)
        return lexical, snapshot
    finally:
        os.close(fd)


def _filesystem_free_bytes(path: pathlib.Path) -> int:
    try:
        status = os.statvfs(path)
    except OSError as exc:
        raise AppleArtifactGateError("Apple PKG expansion filesystem is unreadable") from exc
    return int(status.f_frsize) * int(status.f_bavail)


def _require_expansion_budget(private: PrivateGateRoot, pkg_size: int) -> None:
    if pkg_size <= 0 or pkg_size > MAX_PKG_BYTES:
        raise AppleArtifactGateError(
            "Apple PKG exceeds the explicit outer package bound"
        )
    output_ceiling = min(MAX_OUTPUT_BYTES, pkg_size * MAX_COMPRESSION_RATIO)
    required = output_ceiling * 2 + pkg_size + FREE_SPACE_MARGIN_BYTES
    free = _filesystem_free_bytes(private.root)
    if free < required:
        raise AppleArtifactGateError(
            "Apple PKG expansion lacks a private-directory free-space budget"
        )


def _kill_process_group(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=2)
    except Exception:
        pass


def _lock_tree_fd(dir_fd: int) -> None:
    try:
        names = os.listdir(dir_fd)
    except OSError as exc:
        raise AppleArtifactGateError("Apple PKG expanded-tree snapshot could not be locked") from exc
    for name in sorted(names):
        if name in {".", ".."}:
            continue
        try:
            info = os.lstat(name, dir_fd=dir_fd)
        except OSError as exc:
            raise AppleArtifactGateError("Apple PKG expanded-tree snapshot could not be locked") from exc
        if stat.S_ISLNK(info.st_mode):
            continue
        if stat.S_ISDIR(info.st_mode):
            child = _openat_child(dir_fd, name, _dir_open_flags())
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise AppleArtifactGateError(
                        "Apple PKG expanded-tree snapshot could not be locked"
                    )
                _lock_tree_fd(child)
                os.fchmod(child, 0o500)
                if UF_IMMUTABLE:
                    _require_fchflags(child, UF_IMMUTABLE)
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(info.st_mode):
            raise AppleArtifactGateError("Apple PKG contains a special filesystem entry")
        try:
            child = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=dir_fd,
            )
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ELOOP:
                raise AppleArtifactGateError(
                    "Apple gate cleanup refused a substituted symlink"
                ) from exc
            raise AppleArtifactGateError(
                "Apple PKG expanded-tree snapshot could not be locked"
            ) from exc
        try:
            opened = os.fstat(child)
            if not stat.S_ISREG(opened.st_mode):
                raise AppleArtifactGateError(
                    "Apple gate cleanup refused a substituted symlink"
                )
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise AppleArtifactGateError(
                    "Apple PKG expanded-tree snapshot could not be locked"
                )
            os.fchmod(child, 0o400)
            if UF_IMMUTABLE:
                _require_fchflags(child, UF_IMMUTABLE)
        finally:
            os.close(child)


def _lock_tree(root: pathlib.Path) -> None:
    fd = os.open(root, _dir_open_flags())
    try:
        _lock_tree_fd(fd)
        os.fchmod(fd, 0o500)
        if UF_IMMUTABLE:
            _require_fchflags(fd, UF_IMMUTABLE)
    finally:
        os.close(fd)


def _seal_extracted_bundle_tree(app: pathlib.Path) -> None:
    snapshot = _TREE_SNAPSHOT.get()
    if snapshot is not None:
        snapshot.ensure_bound()
        return
    _lock_tree(app)


def _unlock_tree(root: pathlib.Path) -> None:
    try:
        fd = os.open(root, _dir_open_flags())
    except OSError:
        return
    try:
        _clear_held_unlink_blocking_flags(fd)
        os.fchmod(fd, 0o700)
        _unlock_tree_fd(fd)
    except AppleArtifactGateError:
        return
    finally:
        os.close(fd)


def _cleanup_private_root(private: PrivateGateRoot) -> None:
    if private.root_fd < 0:
        return
    try:
        _clear_held_unlink_blocking_flags(private.root_fd)
        os.fchmod(private.root_fd, 0o700)
        _cleanup_tree_fd(private.root_fd)
    finally:
        os.close(private.root_fd)
        private.root_fd = -1
        private.close_ancestors()


def _copy_exclusive_file(source: pathlib.Path, destination: pathlib.Path, size: int) -> str:
    source_fd = _bind_path_from_known_roots(source, directory=False)
    dest_fd = -1
    try:
        dest_fd = _create_exclusive_under_known_root(destination)
        os.fchmod(dest_fd, 0o400)
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            block = os.read(source_fd, min(READ_CHUNK, remaining))
            if not block:
                raise AppleArtifactGateError("Apple PKG expanded file truncated during snapshot")
            digest.update(block)
            _write_all(dest_fd, block)
            remaining -= len(block)
        extra = os.read(source_fd, 1)
        if extra:
            raise AppleArtifactGateError("Apple PKG expanded file mutated during snapshot")
        os.fsync(dest_fd)
        return digest.hexdigest()
    finally:
        os.close(source_fd)
        if dest_fd >= 0:
            os.close(dest_fd)


def _copy_tree_snapshot(source: pathlib.Path, destination: pathlib.Path) -> AuthenticatedTreeSnapshot:
    if destination.exists():
        if any(destination.iterdir()) if destination.is_dir() else True:
            raise AppleArtifactGateError("Apple PKG expanded-tree snapshot destination already exists")
    else:
        os.mkdir(destination, 0o700)
        os.chmod(destination, 0o700)
    source_records = _inner_tree_records(source)
    for record in source_records:
        relative = str(record["path"])
        src = source / relative
        dest = destination / relative
        kind = record["type"]
        if kind == "dir":
            os.mkdir(dest, 0o700)
            os.chmod(dest, int(record["mode"]))
        elif kind == "symlink":
            os.symlink(str(record["link_target"]), dest)
        elif kind == "file":
            dest.parent.mkdir(parents=True, exist_ok=True)
            copied = _copy_exclusive_file(src, dest, int(record["bytes"]))
            if copied != record["sha256"]:
                raise AppleArtifactGateError(
                    f"Apple PKG expanded file digest changed during snapshot: {relative}"
                )
            os.chmod(dest, int(record["mode"]))
        else:
            raise AppleArtifactGateError(
                f"Apple PKG inner payload contains a special file: {relative}"
            )
    copied_records = _inner_tree_records(destination)
    source_by_path = {str(item["path"]): item for item in source_records}
    if {str(item["path"]) for item in copied_records} != set(source_by_path):
        raise AppleArtifactGateError("Apple PKG expanded-tree snapshot is incomplete")
    for record in copied_records:
        original = source_by_path[str(record["path"])]
        if (
            record["type"] != original["type"]
            or record["sha256"] != original["sha256"]
            or record["bytes"] != original["bytes"]
            or record["link_target"] != original["link_target"]
        ):
            raise AppleArtifactGateError(
                f"Apple PKG expanded-tree snapshot mutated: {record['path']}"
            )
    _lock_tree(destination)
    dest_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        identity = _file_identity(os.fstat(dest_fd))
        encoded = json.dumps(copied_records, sort_keys=True, separators=(",", ":")).encode("utf-8")
        tree = AuthenticatedTreeSnapshot(
            root=destination,
            fd=dest_fd,
            identity=identity,
            records=copied_records,
            digest=_sha256_bytes(encoded),
        )
        dest_fd = -1
    finally:
        if dest_fd >= 0:
            os.close(dest_fd)
    tree.ensure_bound()
    return tree


def _run_pkgutil_check_signature(snapshot: AuthenticatedPkgSnapshot) -> None:
    package = snapshot.kernel_path()
    completed = _run(
        ["/usr/sbin/pkgutil", "--check-signature", package],
        "Apple installer signature verification",
        allow_exit=frozenset({0, 1}),
    )
    snapshot.ensure_bound()
    output = f"{completed.stdout}{completed.stderr}"
    _require_pkg_installer_signature(output, completed.returncode)


def _require_pkg_installer_signature(output: str, returncode: int) -> None:
    output = _normalize_icu_time_spacing(output)
    _reject_signer_text(output, "Apple installer signature")
    lines = output.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    statuses = [
        line.strip().casefold().rstrip(".")
        for line in lines
        if line.strip().casefold().startswith("status:")
    ]
    if any(status.startswith("status: no signature") for status in statuses):
        raise AppleArtifactUnverified("no real signed PKG exists")
    if returncode != 0:
        detail = _redact_tool_output(output.strip())
        raise AppleArtifactGateError(
            "Apple installer signature verification failed with "
            f"exit {returncode}: {detail}"
        )
    if len(statuses) != 1 or statuses[0] != APP_STORE_INSTALLER_STATUS:
        raise AppleArtifactGateError("Apple installer signature is not release-valid")
    leaves: list[str] = []
    for line in lines:
        stripped = line.strip()
        match = re.match(r"^1\.\s+(.+)$", stripped)
        if match:
            leaves.append(match.group(1))
    expected_leaf = (
        f"{MAC_APP_STORE_INSTALLER_PREFIX} {OWNER_COMMON_NAME} ({TEAM_ID})"
    )
    if (
        len(leaves) != 1
        or leaves[0] != expected_leaf
        or DEVELOPER_ID_INSTALLER_PREFIX in leaves[0]
    ):
        raise AppleArtifactGateError(
            "Apple installer certificate chain is not the owner Mac App Store identity"
        )


def _pkgutil_expand_argv(package: str, destination_kernel: str) -> list[str]:
    return [
        _reviewed_tool("/usr/sbin/pkgutil"),
        "--expand-full",
        package,
        destination_kernel,
    ]


def _pkgutil_existing_destination_error(stderr: str) -> bool:
    folded = stderr.casefold()
    return "file exists" in folded or "error 17" in folded


def _directory_fd_empty(dir_fd: int) -> bool:
    try:
        names = os.listdir(dir_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple installer expansion destination is unreadable"
        ) from exc
    return not any(name not in {".", ".."} for name in names)


def _ensure_directory_inode(fd: int, identity: tuple[int, ...]) -> None:
    try:
        current = os.fstat(fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple installer expansion destination was replaced"
        ) from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or _vnode_identity(current, directory=True) != identity
    ):
        raise AppleArtifactGateError(
            "Apple installer expansion destination identity changed"
        )


def _ensure_named_directory_inode(
    parent_fd: int, name: str, identity: tuple[int, ...]
) -> None:
    named_fd = _openat_child(parent_fd, name, _dir_open_flags())
    try:
        _ensure_directory_inode(named_fd, identity)
    finally:
        os.close(named_fd)


def _renameat_children(source_fd: int, dest_fd: int) -> None:
    try:
        names = os.listdir(source_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple installer expansion work directory is unreadable"
        ) from exc
    for name in names:
        if name in {".", ".."}:
            continue
        try:
            os.rename(name, name, src_dir_fd=source_fd, dst_dir_fd=dest_fd)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple installer expansion could not bind expanded contents"
            ) from exc


def _spawn_pkgutil_expand(
    argv: list[str],
    stderr_fd: int,
    destination_fd: int,
    destination_identity: tuple[int, ...],
    output_ceiling: int,
) -> tuple[int, str]:
    original_argv = list(argv)
    command = _macos_descendant_boundary_argv(original_argv)
    boundary_enforced = command != original_argv
    try:
        proc = subprocess.Popen(
            command,
            cwd="/",
            env=_subprocess_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr_fd,
            shell=False,
            start_new_session=True,
            preexec_fn=_apply_child_rlimits,
        )
    except OSError as exc:
        raise AppleArtifactGateError(
            f"Apple installer expansion could not execute: {_redact_tool_output(str(exc))}"
        ) from exc
    deadline = time.monotonic() + PKGUTIL_EXPAND_TIMEOUT_SEC
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(proc)
                raise AppleArtifactGateError(
                    "Apple installer expansion exceeded the time bound"
                )
            try:
                proc.wait(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                _ensure_directory_inode(destination_fd, destination_identity)
                try:
                    stderr_bytes = os.fstat(stderr_fd).st_size
                except OSError as exc:
                    _kill_process_group(proc)
                    raise AppleArtifactGateError(
                        "Apple installer expansion output became unreadable"
                    ) from exc
                if stderr_bytes > MAX_TOOL_OUTPUT_BYTES:
                    _kill_process_group(proc)
                    raise AppleArtifactGateError(
                        "Apple installer expansion exceeded the output bound"
                    )
                used_bytes, used_entries = _expansion_usage_fd(destination_fd)
                if (
                    used_bytes > output_ceiling
                    or used_bytes > MAX_EXPANDED_BYTES
                    or used_entries > MAX_EXPANDED_ENTRIES
                ):
                    _kill_process_group(proc)
                    raise AppleArtifactGateError(
                        "Apple installer expansion exceeded the monitored aggregate bound"
                    )
        if proc.returncode is None:
            _kill_process_group(proc)
            raise AppleArtifactGateError(
                "Apple installer expansion exceeded the time bound"
            )
        _ensure_directory_inode(destination_fd, destination_identity)
        try:
            stderr_size = os.fstat(stderr_fd).st_size
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple installer expansion output became unreadable"
            ) from exc
        if stderr_size > MAX_TOOL_OUTPUT_BYTES:
            raise AppleArtifactGateError(
                "Apple installer expansion exceeded the output bound"
            )
        os.lseek(stderr_fd, 0, os.SEEK_SET)
        stderr_raw = os.read(stderr_fd, MAX_TOOL_OUTPUT_BYTES + 1)
        if len(stderr_raw) > MAX_TOOL_OUTPUT_BYTES:
            raise AppleArtifactGateError(
                "Apple installer expansion exceeded the output bound"
            )
        try:
            stderr = stderr_raw.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise AppleArtifactGateError(
                "Apple installer expansion returned invalid UTF-8"
            ) from exc
        if (
            boundary_enforced
            and proc.returncode != 0
            and "sandbox_apply" in stderr
        ):
            raise _owner_environment_blocker(
                "the authenticated fixed macOS no-fork boundary could not be applied; "
                "a privileged Endpoint Security helper is required on this host"
            )
        return int(proc.returncode), stderr
    finally:
        if proc.returncode is None:
            _kill_process_group(proc)


def _pkgutil_expand_into_bound_inode(
    snapshot: AuthenticatedPkgSnapshot,
    dest_fd: int,
    dest_identity: tuple[int, ...],
    destination_kernel: str,
    stderr_fd: int,
    output_ceiling: int,
    package: str,
) -> None:
    token = secrets.token_hex(16)
    try:
        os.lstat(token, dir_fd=dest_fd)
    except OSError as exc:
        if getattr(exc, "errno", None) != errno.ENOENT:
            raise AppleArtifactGateError(
                "Apple installer expansion work path could not be bound"
            ) from exc
    else:
        raise AppleArtifactGateError(
            "Apple installer expansion work path already exists"
        )
    try:
        os.lseek(stderr_fd, 0, os.SEEK_SET)
        os.ftruncate(stderr_fd, 0)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple installer expansion could not reset its failure log"
        ) from exc
    work_kernel = f"{destination_kernel}/{token}"
    returncode, stderr = _spawn_pkgutil_expand(
        _pkgutil_expand_argv(package, work_kernel),
        stderr_fd,
        dest_fd,
        dest_identity,
        output_ceiling,
    )
    snapshot.rehash()
    _ensure_directory_inode(dest_fd, dest_identity)
    if returncode == 127:
        raise AppleArtifactGateError(
            "Apple installer expansion could not be prebounded; package bound refused"
        )
    if returncode != 0:
        detail = _redact_tool_output(stderr.strip())
        raise AppleArtifactGateError(
            f"Apple installer expansion failed with exit {returncode}: {detail}"
        )
    work_fd = _openat_child(dest_fd, token, _dir_open_flags())
    try:
        _renameat_children(work_fd, dest_fd)
    finally:
        os.close(work_fd)
    try:
        os.rmdir(token, dir_fd=dest_fd)
    except OSError as exc:
        raise AppleArtifactGateError(
            "Apple installer expansion could not bind the destination inode"
        ) from exc
    _ensure_directory_inode(dest_fd, dest_identity)


def _run_pkgutil_expand(snapshot: AuthenticatedPkgSnapshot, destination: pathlib.Path) -> None:
    snapshot.rehash()
    private = _PRIVATE_ROOT.get()
    if private is None or private.root_fd < 0:
        raise AppleArtifactGateError("Apple PKG expansion requires a private 0700 root")
    dest_parts = _lexical_parts_under(private.root, destination)
    if not dest_parts:
        raise AppleArtifactGateError(
            "Apple PKG expansion destination is not inside the private root"
        )
    dest_name = dest_parts[-1]
    parent_fd = _openat_relative(
        private.root_fd, dest_parts[:-1], last_directory=True
    )
    dest_fd = -1
    stderr_fd = -1
    try:
        try:
            os.lstat(dest_name, dir_fd=parent_fd)
        except OSError as exc:
            if getattr(exc, "errno", None) != errno.ENOENT:
                raise AppleArtifactGateError(
                    "Apple PKG expansion destination could not be bound"
                ) from exc
        else:
            raise AppleArtifactGateError("Apple PKG expansion destination already exists")
        try:
            os.mkdir(dest_name, 0o700, dir_fd=parent_fd)
        except OSError as exc:
            raise AppleArtifactGateError(
                "Apple PKG expansion destination already exists"
            ) from exc
        dest_fd = _openat_child(parent_fd, dest_name, _dir_open_flags())
        os.fchmod(dest_fd, 0o700)
        dest_info = os.fstat(dest_fd)
        dest_identity = _vnode_identity(dest_info, directory=True)
        destination_kernel = _authenticate_volfs(
            dest_fd, dest_identity, directory=True
        )
        package = snapshot.kernel_path()
        stderr_path = private.tmp / "pkgutil-expand.stderr"
        stderr_fd = _create_exclusive_under_known_root(stderr_path)
        output_ceiling = min(MAX_OUTPUT_BYTES, max(snapshot.size, 1) * MAX_COMPRESSION_RATIO)
        returncode, stderr = _spawn_pkgutil_expand(
            _pkgutil_expand_argv(package, destination_kernel),
            stderr_fd,
            dest_fd,
            dest_identity,
            output_ceiling,
        )
        snapshot.rehash()
        _ensure_directory_inode(dest_fd, dest_identity)
        if returncode == 127:
            raise AppleArtifactGateError(
                "Apple installer expansion could not be prebounded; package bound refused"
            )
        if returncode == 0:
            _ensure_named_directory_inode(parent_fd, dest_name, dest_identity)
            return
        if not _pkgutil_existing_destination_error(stderr) or not _directory_fd_empty(
            dest_fd
        ):
            detail = _redact_tool_output(stderr.strip())
            raise AppleArtifactGateError(
                f"Apple installer expansion failed with exit {returncode}: {detail}"
            )
        _pkgutil_expand_into_bound_inode(
            snapshot,
            dest_fd,
            dest_identity,
            destination_kernel,
            stderr_fd,
            output_ceiling,
            package,
        )
        _ensure_named_directory_inode(parent_fd, dest_name, dest_identity)
    finally:
        if dest_fd >= 0:
            os.close(dest_fd)
        if stderr_fd >= 0:
            os.close(stderr_fd)
        os.close(parent_fd)


def _expand_pkg(
    snapshot: AuthenticatedPkgSnapshot, destination: pathlib.Path
) -> tuple[pathlib.Path, AuthenticatedTreeSnapshot]:
    if not isinstance(snapshot, AuthenticatedPkgSnapshot):
        raise AppleArtifactGateError(
            "Apple PKG expansion requires an authenticated snapshot"
        )
    if destination.exists() or destination.is_symlink():
        raise AppleArtifactGateError("Apple PKG expansion destination already exists")
    snapshot.ensure_bound()
    private = _PRIVATE_ROOT.get()
    if private is None:
        raise AppleArtifactGateError("Apple PKG expansion requires a private 0700 root")
    _require_expansion_budget(private, snapshot.size)
    _run_pkgutil_check_signature(snapshot)
    snapshot.rehash()
    _run_pkgutil_expand(snapshot, destination)
    snapshot.ensure_bound()
    _reject_unsafe_expansion(destination, pkg_size=snapshot.size)
    app, _records = _bind_macos_packaged_bundles(
        destination,
        inspect_signing=False,
        expected_authority="Authority=Apple Distribution:",
    )
    tree = _copy_tree_snapshot(destination, private.tree_dir)
    snapshot_app = tree.root / _lexical_relative(app, destination)
    tree.ensure_bound()
    return snapshot_app, tree


def _assess_notarization(path: pathlib.Path, artifact_kind: str) -> None:
    directory = artifact_kind == "execute"
    completed = _run_on_path(
        ["/usr/sbin/spctl", "--assess", "--verbose=4", "--type", artifact_kind],
        path,
        "offline Gatekeeper notarization assessment",
        directory=directory,
    )
    output = completed.stdout + completed.stderr
    _reject_signer_text(output, "offline Gatekeeper notarization assessment")
    if not any(
        line.strip() == "source=Notarized Developer ID"
        for line in output.split("\n")
    ):
        raise AppleArtifactGateError("artifact lacks a locally assessable notarized Developer ID ticket")


def _receipt_hex64(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise AppleArtifactGateError(f"{label} digest is invalid")
    return value


def _receipt_exact_mapping(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise AppleArtifactGateError(f"{label} schema fields are invalid")
    return value


def _receipt_exact_str(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise AppleArtifactGateError(f"{label} is not exact")
    return value


def _receipt_hex128(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{128}", value) is None:
        raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    return value


def _receipt_document(record: object, label: str) -> dict[str, object]:
    if type(record) is bytes:
        if not record or len(record) > MAX_RECEIPT_FILE_BYTES:
            raise AppleArtifactGateError(
                f"{label} exceeds the live receipt input bound"
            )
        try:
            parsed = json.loads(
                record.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AppleArtifactGateError(f"{label} must be exact JSON bytes or one JSON object") from exc
        if type(parsed) is not dict:
            raise AppleArtifactGateError(f"{label} must be exact JSON bytes or one JSON object")
        return parsed
    if type(record) is dict:
        try:
            encoded = json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            parsed = json.loads(
                encoded,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AppleArtifactGateError(
                f"{label} must contain only finite exact JSON data"
            ) from exc
        if type(parsed) is not dict:
            raise AppleArtifactGateError(
                f"{label} must be exact JSON bytes or one JSON object"
            )
        return parsed
    raise AppleArtifactGateError(f"{label} must be exact JSON bytes or one JSON object")


def _require_exact_build_receipt_schema(
    document: object,
    *,
    target_id: str,
    receipt: Mapping[str, object],
    spec: Mapping[str, object],
) -> None:
    build = _receipt_exact_mapping(
        document, set(BUILD_RECEIPT_KEYS), f"{target_id} live build receipt"
    )
    for field, keys in (
        ("build_begin_receipt", {"path", "sha256"}),
        ("release_input_index", {"path", "sha256"}),
        (
            "platform_manifest",
            {"path", "sha256", "artifact_input_fingerprint_sha256"},
        ),
        ("producer", {"path", "sha256"}),
        ("toolchain", {"name", "version", "revision", "target"}),
        ("source_freeze", {"path", "sha256", "issuance_id"}),
        ("toolchain_custody", {"path", "sha256", "issuance_id"}),
        ("artifact", {"name", "size_bytes", "sha256", "modified_time_ns"}),
    ):
        _receipt_exact_mapping(
            build.get(field), set(keys), f"{target_id} build receipt {field}"
        )
    attempt = _receipt_exact_mapping(
        build.get("build_attempt"),
        set(BUILD_ATTEMPT_KEYS),
        f"{target_id} build attempt",
    )
    for field in ("directory_identity", "artifacts_directory_identity"):
        _receipt_exact_mapping(
            attempt.get(field),
            {"device", "inode", "uid", "gid", "mode"},
            f"{target_id} build attempt {field}",
        )
    claim = _receipt_exact_mapping(
        attempt.get("claim_record"),
        {
            "schema_version",
            "contract",
            "claimed_utc",
            "release",
            "platform",
            "nonce",
            "build_begin_sha256",
            "release_input_index",
            "platform_manifest",
            "source_freeze",
            "toolchain_custody",
            "producer",
            "toolchain",
            "artifact_path",
        },
        f"{target_id} build attempt claim",
    )
    commit = _receipt_exact_mapping(
        attempt.get("commit_record"),
        {
            "schema_version",
            "contract",
            "nonce",
            "build_begin_sha256",
            "claim_sha256",
            "build_receipt_path",
            "artifact",
        },
        f"{target_id} build attempt commit",
    )
    _receipt_exact_mapping(
        commit.get("artifact"),
        {"path", "name", "size_bytes", "sha256", "modified_time_ns", "device", "inode"},
        f"{target_id} build attempt commit artifact",
    )
    for nested, keys in (
        (claim, ("release_input_index", "platform_manifest", "source_freeze", "toolchain_custody", "producer", "toolchain")),
    ):
        for key in keys:
            expected = build.get(key)
            if nested.get(key) != expected:
                raise AppleArtifactGateError(
                    f"{target_id} build receipt {key} binding is not exact"
                )
    artifact = build["artifact"]
    receipt_artifact = receipt.get("artifact")
    toolchain = build["toolchain"]
    if (
        build.get("schema_version") != 1
        or build.get("contract") != "winsvpn-build-receipt-v1"
        or build.get("release") != CANONICAL_RELEASE
        or build.get("platform") != spec.get("platform")
        or build.get("publication_authorized") is not False
        or type(receipt_artifact) is not dict
        or artifact.get("sha256") != receipt_artifact.get("sha256")
        or artifact.get("size_bytes") != receipt_artifact.get("bytes")
        or toolchain.get("target") != spec.get("build_receipt_target")
        or claim.get("release") != CANONICAL_RELEASE
        or claim.get("platform") != spec.get("platform")
        or commit.get("nonce") != attempt.get("nonce")
        or claim.get("nonce") != attempt.get("nonce")
    ):
        raise AppleArtifactGateError(
            f"{target_id} build receipt identity is not exact"
        )
    _require_utc_timestamp(build.get("begun_utc"), f"{target_id} build begun")
    _require_utc_timestamp(build.get("finished_utc"), f"{target_id} build finished")
    _require_utc_timestamp(claim.get("claimed_utc"), f"{target_id} build claim")
    for value, label in (
        (attempt.get("nonce"), "build attempt nonce"),
        (attempt.get("claim_sha256"), "build claim"),
        (attempt.get("commit_journal_sha256"), "build commit"),
        (claim.get("build_begin_sha256"), "build claim begin"),
        (commit.get("build_begin_sha256"), "build commit begin"),
        (commit.get("claim_sha256"), "build commit claim"),
    ):
        _receipt_hex64(value, f"{target_id} {label}")


def _require_canonical_relative_path(path: object, label: str) -> str:
    if (
        type(path) is not str
        or not path
        or "\\" in path
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in path)
    ):
        raise AppleArtifactGateError(
            f"{label} must be one canonical repository-relative path"
        )
    relative = pathlib.PurePosixPath(path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise AppleArtifactGateError(
            f"{label} must be one canonical repository-relative path"
        )
    return path


def _upload_receipt_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _require_utc_timestamp(value: object, label: str) -> datetime.datetime:
    if type(value) is not str or not value:
        raise AppleArtifactGateError(f"{label} is not an RFC3339 UTC timestamp")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AppleArtifactGateError(f"{label} is not an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise AppleArtifactGateError(f"{label} is not an RFC3339 UTC timestamp")
    return parsed.astimezone(datetime.timezone.utc)


def _upload_receipt_canonical_bytes(auth: Mapping[str, object]) -> bytes:
    payload = {
        "authenticated": True,
        "issuer": auth.get("issuer"),
        "run_id": auth.get("run_id"),
        "nonce": auth.get("nonce"),
        "issued_at": auth.get("issued_at"),
        "challenge": auth.get("challenge"),
        "target_id": auth.get("target_id"),
        "architectures": auth.get("architectures"),
        "release": auth.get("release"),
        "artifact_sha256": auth.get("artifact_sha256"),
        "artifact_bytes": auth.get("artifact_bytes"),
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _reject_placeholder_trust_material(material: object) -> None:
    if type(material) is dict:
        for key, value in material.items():
            folded = str(key).casefold()
            if folded in {
                "public_key",
                "issuer_public_key",
                "trust_root",
                "signature",
                "ed25519",
            }:
                raise AppleArtifactGateError(RECEIPT_PLACEHOLDER_TRUST_ERROR)
            if type(value) is str and folded.endswith("public_key"):
                if _hex_looks_like_placeholder_key(value):
                    raise AppleArtifactGateError(RECEIPT_PLACEHOLDER_TRUST_ERROR)
    try:
        dumped = json.dumps(material, ensure_ascii=True).casefold()
    except (TypeError, ValueError) as exc:
        raise AppleArtifactGateError(RECEIPT_PLACEHOLDER_TRUST_ERROR) from exc
    for marker in UPLOAD_RECEIPT_PLACEHOLDER_TRUST_MARKERS:
        if marker in dumped:
            raise AppleArtifactGateError(RECEIPT_PLACEHOLDER_TRUST_ERROR)


def _hex_looks_like_placeholder_key(value: str) -> bool:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        return False
    for width in (2, 4, 8, 16, 32):
        unit = value[:width]
        if unit * (len(value) // width) == value:
            return True
    return False


def _journal_parts() -> tuple[str, ...]:
    relative = pathlib.PurePosixPath(UPLOAD_RECEIPT_JOURNAL_RELATIVE)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise AppleArtifactGateError("upload receipt journal path is not canonical")
    return relative.parts


def _mkdirat_directory(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as exc:
        raise AppleArtifactGateError(
            f"Apple gate could not bind path component {name!r}"
        ) from exc
    child = _openat_child(parent_fd, name, _dir_open_flags())
    try:
        info = os.fstat(child)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise AppleArtifactGateError(
                f"{name} must be a directory for the upload receipt journal"
            )
        os.fsync(parent_fd)
        return child
    except Exception:
        os.close(child)
        raise


def _open_upload_receipt_journal() -> tuple[int, int]:
    parts = _journal_parts()
    if len(parts) < 2:
        raise AppleArtifactGateError("upload receipt journal path is not canonical")
    dir_parts = parts[:-1]
    journal_name = parts[-1]
    root_fd = os.open(ROOT, _dir_open_flags())
    parent_fd = -1
    journal_fd = -1
    try:
        root_info = os.fstat(root_fd)
        parent_fd = os.dup(root_fd)
        for part in dir_parts:
            child = _mkdirat_directory(parent_fd, part)
            os.close(parent_fd)
            parent_fd = child
        parent_info = os.fstat(parent_fd)
        if parent_info.st_uid != root_info.st_uid:
            raise AppleArtifactGateError(
                "upload receipt journal directory is not root-owned"
            )
        create_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
        )
        try:
            journal_fd = os.open(
                journal_name, create_flags, 0o600, dir_fd=parent_fd
            )
            os.fsync(journal_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            journal_fd = os.open(
                journal_name,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        info = os.fstat(journal_fd)
        named = os.lstat(journal_name, dir_fd=parent_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or info.st_nlink != 1
            or info.st_uid != root_info.st_uid
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise AppleArtifactGateError(
                "upload receipt journal must be a root-owned single-link regular file"
            )
        owned = journal_fd
        journal_fd = -1
        return owned, root_info.st_uid
    finally:
        if journal_fd >= 0:
            os.close(journal_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


class _HeldUploadReceiptJournal:
    """Retain the canonical journal leaf and every ancestor through readback."""

    def __init__(self) -> None:
        self.fd = -1
        self.root_uid = -1
        self._records: list[
            tuple[int | None, str, int, tuple[int, ...], bool]
        ] = []
        self._closed = False
        try:
            self._open()
            self.verify()
        except BaseException:
            self.close(verify=False)
            raise

    def _open(self) -> None:
        parts = _journal_parts()
        if len(parts) < 2:
            raise AppleArtifactGateError("upload receipt journal path is not canonical")
        root_fd = os.open(ROOT, _dir_open_flags())
        held_dirs = [root_fd]
        parent_fd = root_fd
        journal_fd = -1
        try:
            root_info = os.fstat(root_fd)
            self.root_uid = int(root_info.st_uid)
            for part in parts[:-1]:
                child = _mkdirat_directory(parent_fd, part)
                held_dirs.append(child)
                parent_fd = child
            parent_info = os.fstat(parent_fd)
            if parent_info.st_uid != self.root_uid:
                raise AppleArtifactGateError(
                    "upload receipt journal directory is not root-owned"
                )
            journal_name = parts[-1]
            create_flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW
            )
            try:
                journal_fd = os.open(
                    journal_name, create_flags, 0o600, dir_fd=parent_fd
                )
                os.fsync(journal_fd)
                os.fsync(parent_fd)
            except FileExistsError:
                journal_fd = os.open(
                    journal_name,
                    os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
            info = os.fstat(journal_fd)
            named = os.lstat(journal_name, dir_fd=parent_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(named.st_mode)
                or info.st_nlink != 1
                or info.st_uid != self.root_uid
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise AppleArtifactGateError(
                    "upload receipt journal must be a root-owned single-link regular file"
                )
            for index, directory_fd in enumerate(held_dirs):
                parent = None if index == 0 else held_dirs[index - 1]
                name = "" if index == 0 else parts[index - 1]
                self._records.append(
                    (
                        parent,
                        name,
                        directory_fd,
                        _file_identity(os.fstat(directory_fd)),
                        True,
                    )
                )
            # Capture mutable journal metadata only after acquiring custody.
            # Keep the pre-lock inode, owner, mode, link count and ancestors.
            fcntl.flock(journal_fd, fcntl.LOCK_EX)
            for record in self._records:
                self._verify_record(record)
            current = os.fstat(journal_fd)
            named = os.lstat(journal_name, dir_fd=parent_fd)
            stable_identity = _file_identity(info)[:5]
            if (
                _file_identity(current)[:5] != stable_identity
                or _file_identity(named)[:5] != stable_identity
            ):
                raise AppleArtifactGateError(
                    "upload receipt journal ancestor was replaced"
                )
            self._records.append(
                (
                    parent_fd,
                    journal_name,
                    journal_fd,
                    _file_identity(current),
                    False,
                )
            )
            self.fd = journal_fd
        except BaseException:
            if journal_fd >= 0:
                os.close(journal_fd)
            for descriptor in reversed(held_dirs):
                os.close(descriptor)
            self._records.clear()
            self.fd = -1
            raise

    def _verify_record(
        self,
        record: tuple[int | None, str, int, tuple[int, ...], bool],
        *,
        stable_leaf_only: bool = False,
    ) -> os.stat_result:
        parent_fd, name, fd, expected, directory = record
        try:
            current = os.fstat(fd)
            named = (
                ROOT.lstat()
                if parent_fd is None
                else os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            )
        except OSError as exc:
            raise AppleArtifactGateError(
                "upload receipt journal ancestor was replaced"
            ) from exc
        if stable_leaf_only and not directory:
            current_identity = _file_identity(current)[:5]
            named_identity = _file_identity(named)[:5]
            expected_identity = expected[:5]
        else:
            current_identity = _file_identity(current)
            named_identity = _file_identity(named)
            expected_identity = expected
        if (
            current_identity != expected_identity
            or named_identity != expected_identity
            or (directory and not stat.S_ISDIR(current.st_mode))
            or (not directory and not stat.S_ISREG(current.st_mode))
        ):
            raise AppleArtifactGateError(
                "upload receipt journal ancestor was replaced"
            )
        return current

    def verify(self) -> None:
        if self._closed or self.fd < 0:
            raise AppleArtifactGateError("upload receipt journal custody is closed")
        for record in self._records:
            self._verify_record(record)

    def refresh_after_write(self) -> None:
        for record in self._records[:-1]:
            self._verify_record(record)
        current = self._verify_record(self._records[-1], stable_leaf_only=True)
        parent_fd, name, fd, _expected, directory = self._records[-1]
        self._records[-1] = (
            parent_fd,
            name,
            fd,
            _file_identity(current),
            directory,
        )
        self.verify()

    def read_payload(self) -> bytes:
        self.verify()
        os.lseek(self.fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(self.fd, 65536)
            if not block:
                break
            total += len(block)
            if total > MAX_RECEIPT_FILE_BYTES:
                raise AppleArtifactGateError(
                    "upload receipt journal exceeds the live receipt bound"
                )
            chunks.append(block)
        self.verify()
        return b"".join(chunks)

    def close(self, *, verify: bool) -> None:
        if self._closed:
            return
        try:
            if verify:
                self.verify()
        finally:
            self._closed = True
            self.fd = -1
            for _parent_fd, _name, fd, _expected, _directory in reversed(
                self._records
            ):
                os.close(fd)
            self._records.clear()


def _parse_upload_receipt_journal(payload: bytes) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    if not payload:
        return records
    if len(payload) > MAX_RECEIPT_FILE_BYTES:
        raise AppleArtifactGateError(
            "upload receipt journal exceeds the live receipt bound"
        )
    try:
        text = payload.decode("ascii")
    except UnicodeError as exc:
        raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR) from exc
    if not text.endswith("\n"):
        raise AppleArtifactGateError("upload receipt journal is truncated")
    for line in text.splitlines():
        if not line:
            raise AppleArtifactGateError("upload receipt journal contains an empty record")
        try:
            parsed = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
        except json.JSONDecodeError as exc:
            raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR) from exc
        if type(parsed) is not dict:
            raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
        kind = parsed.get("kind")
        if kind in {"issued", "consumed"}:
            _receipt_exact_mapping(
                parsed,
                set(UPLOAD_RECEIPT_JOURNAL_AUTH_KEYS),
                "upload receipt journal authentication record",
            )
            _validate_upload_receipt_journal_authentication(parsed)
        elif kind == "consumed-set":
            _receipt_exact_mapping(
                parsed,
                set(UPLOAD_RECEIPT_JOURNAL_TRANSACTION_KEYS),
                "upload receipt journal transaction record",
            )
            transaction_id = parsed.get("transaction_id")
            authentications = parsed.get("authentications")
            if (
                parsed.get("schema") != UPLOAD_RECEIPT_JOURNAL_SCHEMA
                or type(transaction_id) is not str
                or re.fullmatch(r"[0-9a-f]{64}", transaction_id) is None
                or parsed.get("committed") is not True
                or type(authentications) is not list
                or not authentications
            ):
                raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
            for authentication in authentications:
                _receipt_exact_mapping(
                    authentication,
                    set(UPLOAD_RECEIPT_AUTH_KEYS),
                    "upload receipt journal transaction authentication",
                )
                _validate_upload_receipt_journal_authentication(authentication)
        else:
            raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
        records.append(parsed)
    return records


def _validate_upload_receipt_journal_authentication(
    authentication: Mapping[str, object],
) -> None:
    if (
        authentication.get("schema", UPLOAD_RECEIPT_JOURNAL_SCHEMA)
        != UPLOAD_RECEIPT_JOURNAL_SCHEMA
        or authentication.get("authenticated") is not True
        or authentication.get("issuer") != UPLOAD_RECEIPT_ISSUER
        or authentication.get("target_id") not in APPLE_PACKAGE_UPLOAD_TARGETS
        or authentication.get("release") != CANONICAL_RELEASE
        or type(authentication.get("architectures")) is not list
        or type(authentication.get("artifact_bytes")) is not int
        or isinstance(authentication.get("artifact_bytes"), bool)
        or int(authentication.get("artifact_bytes")) <= 0
    ):
        raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    _receipt_hex64(authentication.get("run_id"), "upload journal run_id")
    _receipt_hex64(authentication.get("nonce"), "upload journal nonce")
    _receipt_hex128(authentication.get("challenge"), "upload journal challenge")
    _receipt_hex64(
        authentication.get("artifact_sha256"), "upload journal artifact"
    )
    _require_utc_timestamp(
        authentication.get("issued_at"), "upload journal issued_at"
    )


def _journal_binding_tuple(record: Mapping[str, object]) -> tuple[object, ...]:
    architectures = record.get("architectures")
    if type(architectures) is not list:
        architectures = None
    return (
        record.get("nonce"),
        record.get("run_id"),
        record.get("challenge"),
        record.get("target_id"),
        tuple(architectures) if architectures is not None else None,
        record.get("release"),
        record.get("artifact_sha256"),
        record.get("artifact_bytes"),
        record.get("issued_at"),
        record.get("issuer"),
    )


def _journal_record_authentications(
    record: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    if record.get("kind") == "consumed-set":
        authentications = record.get("authentications")
        if type(authentications) is not list:
            raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
        return tuple(authentications)
    return (record,)


def _with_upload_receipt_journal(
    mutate: object,
) -> list[dict[str, object]]:
    current = _UPLOAD_RECEIPT_JOURNAL_CUSTODY.get()
    owned = current is None
    custody = _HeldUploadReceiptJournal() if owned else current
    if not isinstance(custody, _HeldUploadReceiptJournal):
        raise AppleArtifactGateError("upload receipt journal custody is invalid")
    fd = custody.fd
    try:
        original_payload = custody.read_payload()
        records = _parse_upload_receipt_journal(original_payload)
        extra = mutate(records) if callable(mutate) else None
        if extra is not None:
            line = (
                json.dumps(
                    extra, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                )
                + "\n"
            ).encode("ascii")
            original_size = len(original_payload)
            os.lseek(fd, 0, os.SEEK_END)
            try:
                written = os.write(fd, line)
                if written != len(line):
                    raise AppleArtifactGateError(
                        "upload receipt journal write was truncated"
                    )
                os.fsync(fd)
            except BaseException:
                try:
                    os.ftruncate(fd, original_size)
                    os.fsync(fd)
                    custody.refresh_after_write()
                except OSError as rollback_exc:
                    raise AppleArtifactGateError(
                        "upload receipt journal rollback could not be committed"
                    ) from rollback_exc
                raise
            custody.refresh_after_write()
            readback_payload = custody.read_payload()
            if readback_payload != original_payload + line:
                raise AppleArtifactGateError(
                    "upload receipt journal commit readback changed"
                )
            readback = _parse_upload_receipt_journal(readback_payload)
            if readback != [*records, extra]:
                raise AppleArtifactGateError(
                    "upload receipt journal commit readback changed"
                )
            records = readback
        custody.verify()
        return records
    finally:
        if owned:
            custody.close(verify=True)


def issue_upload_receipt_challenge(
    target_id: str,
    *,
    artifact_sha256: str,
    artifact_bytes: int,
    architectures: tuple[str, ...],
    release: str,
) -> dict[str, object]:
    """Issue a durable one-use verifier challenge bound to exact candidate bytes."""

    spec = _package_upload_target(target_id)
    if tuple(str(item) for item in spec["architectures"]) != architectures:
        raise AppleArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
        )
    if release != canonical_apple_release():
        raise AppleArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
        )
    digest = _receipt_hex64(artifact_sha256, f"{target_id} candidate bytes")
    if type(artifact_bytes) is not int or isinstance(artifact_bytes, bool) or artifact_bytes <= 0:
        raise AppleArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
        )
    issued_at = _upload_receipt_now().strftime("%Y-%m-%dT%H:%M:%SZ")
    auth = {
        "authenticated": True,
        "issuer": UPLOAD_RECEIPT_ISSUER,
        "run_id": secrets.token_hex(32),
        "nonce": secrets.token_hex(32),
        "issued_at": issued_at,
        "challenge": secrets.token_hex(64),
        "target_id": target_id,
        "architectures": list(architectures),
        "release": release,
        "artifact_sha256": digest,
        "artifact_bytes": int(artifact_bytes),
    }
    _reject_placeholder_trust_material(auth)

    def _append_issued(records: list[dict[str, object]]) -> dict[str, object]:
        for existing in records:
            for previous in _journal_record_authentications(existing):
                if (
                    previous.get("nonce") == auth["nonce"]
                    or previous.get("run_id") == auth["run_id"]
                    or previous.get("challenge") == auth["challenge"]
                ):
                    raise AppleArtifactGateError(RECEIPT_REPLAY_ERROR)
        return {
            "schema": UPLOAD_RECEIPT_JOURNAL_SCHEMA,
            "kind": "issued",
            **auth,
        }

    _with_upload_receipt_journal(_append_issued)
    return auth


def _consume_upload_receipt_challenge(auth: Mapping[str, object]) -> None:
    _commit_upload_receipt_challenges((auth,))


def _commit_upload_receipt_challenges(
    authentications: tuple[Mapping[str, object], ...],
) -> None:
    """Atomically consume a complete verified receipt set in one journal record."""

    if not authentications:
        raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    copied: list[dict[str, object]] = []
    identifiers: set[tuple[object, object, object]] = set()
    targets: set[object] = set()
    for authentication in authentications:
        exact = _receipt_exact_mapping(
            dict(authentication),
            set(UPLOAD_RECEIPT_AUTH_KEYS),
            "upload receipt transaction authentication",
        )
        _validate_upload_receipt_journal_authentication(exact)
        identifier = (
            exact.get("nonce"),
            exact.get("run_id"),
            exact.get("challenge"),
        )
        if identifier in identifiers or exact.get("target_id") in targets:
            raise AppleArtifactGateError(RECEIPT_REPLAY_ERROR)
        identifiers.add(identifier)
        targets.add(exact.get("target_id"))
        copied.append(exact)

    def _append_transaction(
        records: list[dict[str, object]],
    ) -> dict[str, object]:
        for authentication in copied:
            binding = _journal_binding_tuple(authentication)
            issued_count = 0
            for existing in records:
                kind = existing.get("kind")
                for previous in _journal_record_authentications(existing):
                    overlaps = (
                        previous.get("nonce") == authentication.get("nonce")
                        or previous.get("run_id") == authentication.get("run_id")
                        or previous.get("challenge")
                        == authentication.get("challenge")
                    )
                    if not overlaps:
                        continue
                    if kind in {"consumed", "consumed-set"}:
                        raise AppleArtifactGateError(RECEIPT_REPLAY_ERROR)
                    if kind != "issued" or _journal_binding_tuple(previous) != binding:
                        raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
                    issued_count += 1
            if issued_count != 1:
                raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
        return {
            "schema": UPLOAD_RECEIPT_JOURNAL_SCHEMA,
            "kind": "consumed-set",
            "transaction_id": secrets.token_hex(32),
            "committed": True,
            "authentications": copied,
        }

    _with_upload_receipt_journal(_append_transaction)


def _require_upload_receipt_challenge_issued(auth: Mapping[str, object]) -> None:
    binding = _journal_binding_tuple(auth)
    issued_count = 0
    for existing in _with_upload_receipt_journal(None):
        kind = existing.get("kind")
        for previous in _journal_record_authentications(existing):
            overlaps = (
                previous.get("nonce") == auth.get("nonce")
                or previous.get("run_id") == auth.get("run_id")
                or previous.get("challenge") == auth.get("challenge")
            )
            if not overlaps:
                continue
            if kind in {"consumed", "consumed-set"}:
                raise AppleArtifactGateError(RECEIPT_REPLAY_ERROR)
            if kind != "issued" or _journal_binding_tuple(previous) != binding:
                raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
            issued_count += 1
    if issued_count != 1:
        raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)


def _bind_upload_receipt_authentication(
    target_id: str,
    receipt: Mapping[str, object],
    *,
    artifact_sha256: str,
    artifact_bytes: int,
    architectures: tuple[str, ...],
    release: str,
) -> dict[str, object]:
    raw_auth = receipt.get("authentication")
    _reject_placeholder_trust_material(raw_auth)
    auth = _receipt_exact_mapping(
        raw_auth,
        set(UPLOAD_RECEIPT_AUTH_KEYS),
        f"{target_id} upload authentication",
    )
    if (
        auth.get("authenticated") is not True
        or auth.get("issuer") != UPLOAD_RECEIPT_ISSUER
    ):
        raise AppleArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    run_id = _receipt_hex64(auth.get("run_id"), f"{target_id} upload run_id")
    nonce = _receipt_hex64(auth.get("nonce"), f"{target_id} upload nonce")
    _receipt_hex128(auth.get("challenge"), f"{target_id} upload challenge")
    del run_id, nonce
    issued_at = _require_utc_timestamp(auth.get("issued_at"), f"{target_id} upload issued_at")
    now = _upload_receipt_now()
    age = (now - issued_at).total_seconds()
    if age > UPLOAD_RECEIPT_MAX_AGE_SECONDS or age < -UPLOAD_RECEIPT_FUTURE_SKEW_SECONDS:
        raise AppleArtifactGateError(RECEIPT_STALE_ERROR)
    auth_architectures = auth.get("architectures")
    if (
        auth.get("target_id") != target_id
        or type(auth_architectures) is not list
        or tuple(auth_architectures) != architectures
        or auth.get("release") != release
        or auth.get("artifact_sha256") != artifact_sha256
        or type(auth.get("artifact_bytes")) is not int
        or isinstance(auth.get("artifact_bytes"), bool)
        or int(auth.get("artifact_bytes")) != artifact_bytes
    ):
        raise AppleArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
        )
    _require_upload_receipt_challenge_issued(auth)
    return dict(auth)


def _register_live_inode(relative: str, info: os.stat_result, label: str) -> None:
    bound = _LIVE_INODES.get()
    if bound is None:
        return
    key = (int(info.st_dev), int(info.st_ino))
    previous = bound.get(key)
    if previous is not None and previous != relative:
        raise AppleArtifactGateError(
            f"{label} is a hardlink or duplicate of {previous}"
        )
    bound[key] = relative


class _HeldLiveRepoFile:
    """Retain one repository file and every ancestor for a receipt transaction."""

    def __init__(self, relative: str, label: str, *, max_bytes: int) -> None:
        self.relative = _require_canonical_relative_path(relative, label)
        self.label = label
        self.max_bytes = max_bytes
        self.path = ROOT.joinpath(*pathlib.PurePosixPath(self.relative).parts)
        self.fd = -1
        self.digest = ""
        self.size = 0
        self.payload = b""
        self._records: list[
            tuple[int | None, str, int, tuple[int, ...], bool]
        ] = []
        self._closed = False
        try:
            self._open()
            self.verify()
        except Exception:
            self.close(verify=False)
            raise

    def _open(self) -> None:
        parts = pathlib.PurePosixPath(self.relative).parts
        try:
            root_fd = os.open(ROOT, _dir_open_flags())
        except OSError as exc:
            raise _owner_environment_blocker(
                "Apple package/upload receipts remain pending without owner evidence: "
                + self.relative
            ) from exc
        self._records.append(
            (None, "", root_fd, _file_identity(os.fstat(root_fd)), True)
        )
        parent_fd = root_fd
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            try:
                child = _openat_child(
                    parent_fd, part, _open_flags() if last else _dir_open_flags()
                )
            except AppleArtifactGateError as exc:
                if "could not bind path component" in str(exc):
                    raise _owner_environment_blocker(
                        "Apple package/upload receipts remain pending without owner evidence: "
                        + self.relative
                    ) from exc
                raise
            info = os.fstat(child)
            if not last and not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise AppleArtifactGateError(
                    f"{self.label} ancestor must be a directory"
                )
            self._records.append(
                (parent_fd, part, child, _file_identity(info), not last)
            )
            parent_fd = child
        self.fd = self._records[-1][2]
        info = os.fstat(self.fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISFIFO(info.st_mode)
            or stat.S_ISCHR(info.st_mode)
            or stat.S_ISBLK(info.st_mode)
            or stat.S_ISSOCK(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > self.max_bytes
        ):
            raise AppleArtifactGateError(
                f"{self.label} must be a non-empty regular single-link file"
            )
        _register_live_inode(self.relative, info, self.label)
        self.size = int(info.st_size)
        self.payload = os.pread(self.fd, self.size, 0)
        self.digest = hashlib.sha256(self.payload).hexdigest()
        if (
            len(self.payload) != self.size
            or _sha256_fd(self.fd, self.size) != self.digest
        ):
            raise AppleArtifactGateError(f"{self.label} mutated while it was read")

    def verify(self) -> None:
        if self._closed or self.fd < 0:
            raise AppleArtifactGateError(f"{self.label} retained custody is closed")
        for parent_fd, name, fd, expected, directory in self._records:
            try:
                current = os.fstat(fd)
                named = (
                    ROOT.lstat()
                    if parent_fd is None
                    else os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                )
            except OSError as exc:
                raise AppleArtifactGateError(
                    f"{self.label} ancestor was replaced"
                ) from exc
            if (
                _file_identity(current) != expected
                or _file_identity(named) != expected
                or (directory and not stat.S_ISDIR(current.st_mode))
                or (not directory and not stat.S_ISREG(current.st_mode))
            ):
                raise AppleArtifactGateError(
                    f"{self.label} ancestor was replaced"
                )
        if _sha256_fd(self.fd, self.size) != self.digest:
            raise AppleArtifactGateError(f"{self.label} mutated while retained")

    def close(self, *, verify: bool) -> None:
        if self._closed:
            return
        try:
            if verify:
                self.verify()
        finally:
            self._closed = True
            self.fd = -1
            for _parent_fd, _name, fd, _expected, _directory in reversed(
                self._records
            ):
                os.close(fd)
            self._records.clear()


def _hash_live_repo_file(
    relative: str,
    label: str,
    *,
    max_bytes: int = MAX_PKG_BYTES,
) -> tuple[str, int, bytes]:
    path = _require_canonical_relative_path(relative, label)
    retained = _LIVE_REPO_FILES.get()
    if retained is not None:
        existing = retained.get(path)
        if existing is None:
            existing = _HeldLiveRepoFile(path, label, max_bytes=max_bytes)
            retained[path] = existing
        if not isinstance(existing, _HeldLiveRepoFile):
            raise AppleArtifactGateError("live repository custody is invalid")
        if existing.size > max_bytes:
            raise AppleArtifactGateError(
                f"{label} must be a non-empty regular single-link file"
            )
        existing.verify()
        return existing.digest, existing.size, existing.payload
    held = _HeldLiveRepoFile(path, label, max_bytes=max_bytes)
    try:
        held.verify()
        return held.digest, held.size, held.payload
    finally:
        held.close(verify=True)


def _require_live_upload_bindings(
    target_id: str, receipt: dict[str, object], spec: dict[str, object]
) -> None:
    artifact = receipt["artifact"]
    artifact_path = str(artifact["path"])
    live_digest, live_size, _payload = _hash_live_repo_file(
        artifact_path, f"{target_id} artifact"
    )
    if live_digest != artifact["sha256"] or live_size != artifact["bytes"]:
        raise AppleArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
        )
    exact_paths = {
        "producer": PRODUCER_RELATIVE,
        "descriptor": DESCRIPTOR_RELATIVE,
        "obfuscation_privacy": OBFUSCATION_PRIVACY_RELATIVE,
    }
    for field, expected_path in exact_paths.items():
        record = receipt[field]
        path = str(record["path"])
        if path != expected_path:
            raise AppleArtifactGateError(f"{target_id} {field} path is not exact")
        live_digest, _live_size, _payload = _hash_live_repo_file(
            path, f"{target_id} {field}", max_bytes=MAX_RECEIPT_FILE_BYTES
        )
        if live_digest != record["sha256"]:
            raise AppleArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
            )
    for field in ("build_receipt", "source_freeze"):
        record = receipt[field]
        path = str(record["path"])
        if pathlib.PurePosixPath(path).parts[0] != ".artifacts":
            raise AppleArtifactGateError(
                f"{target_id} {field} path must stay under .artifacts/"
            )
        live_digest, _live_size, payload = _hash_live_repo_file(
            path, f"{target_id} {field}", max_bytes=MAX_RECEIPT_FILE_BYTES
        )
        if live_digest != record["sha256"]:
            raise AppleArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
            )
        if field == "build_receipt":
            try:
                parsed = json.loads(
                    payload.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_nonfinite,
                )
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise AppleArtifactGateError(
                    f"{target_id} build receipt must be exact JSON"
                ) from exc
            if type(parsed) is not dict:
                raise AppleArtifactGateError(f"{target_id} build receipt must be exact JSON")
            _require_exact_build_receipt_schema(
                parsed,
                target_id=target_id,
                receipt=receipt,
                spec=spec,
            )


def _require_owner_issued_apple_signature(
    target_id: str,
    relative: str,
    *,
    expected_sha256: str,
    expected_bytes: int,
    expected_watch_verification: Mapping[str, object] | None = None,
    held_artifact: _HeldLiveRepoFile,
) -> None:
    spec = _package_upload_target(target_id)
    canonical = _require_canonical_relative_path(relative, f"{target_id} artifact")
    if held_artifact.relative != canonical:
        raise AppleArtifactGateError(
            f"{target_id} signature custody does not bind the receipt artifact"
        )
    held_artifact.verify()
    with tempfile.TemporaryDirectory(prefix="wins-apple-receipt-signature-") as temporary:
        private = _prepare_private_root(pathlib.Path(temporary))
        token = _PRIVATE_ROOT.set(private)
        snapshot: AuthenticatedPkgSnapshot | None = None
        try:
            artifact = held_artifact.path
            lowered = artifact.name.lower()
            if not any(
                lowered.endswith(suffix) for suffix in _apple_target_suffixes(target_id)
            ):
                raise AppleArtifactGateError(
                    f"{target_id} signature custody has the wrong artifact type"
                )
            snapshot = _snapshot_pkg(
                artifact,
                private.snapshot_file,
                source_fd=held_artifact.fd,
            )
            if snapshot.size != expected_bytes or snapshot.rehash() != expected_sha256:
                raise AppleArtifactGateError(
                    f"{target_id} signature snapshot does not bind the receipt artifact"
                )
            expected_authority = str(spec["expected_authority"])
            if target_id == "ios-app-store-ipa":
                watch_custody = _HeldSupportSources(HELD_ARTIFACT_REVIEW_SOURCES)
                try:
                    reviewed = _validate_held_artifact_review_custody(
                        watch_custody
                    )
                    watch_source = "apple_watch_artifact_verifier.py"
                    actual_watch_verification = verify_watch_artifact_snapshot(
                        snapshot.path,
                        artifact_sha256=expected_sha256,
                        artifact_size=snapshot.size,
                        verifier_source=watch_custody.payloads[watch_source],
                        expected_verifier_sha256=reviewed[watch_source],
                    )
                    watch_custody.verify()
                finally:
                    watch_custody.close(verify=True)
                if dict(expected_watch_verification or {}) != actual_watch_verification:
                    raise AppleArtifactGateError(
                        "watchOS artifact verifier evidence is missing, stale, or substituted"
                    )
                ipa_root = private.root / "ipa"
                _extract_zip(snapshot, ipa_root)
                app = _one_app(ipa_root, "Payload/*.app")
                _verify_bundle(app, "ios")
                _seal_extracted_bundle_tree(app)
                _verify_codesign(app, expected_authority, platform="ios")
            elif target_id == "macos-app-store-pkg":
                _verify_pkg_target(
                    target_id,
                    artifact,
                    private,
                    expected_authority=expected_authority,
                    inspect_signing=True,
                    notarize_install=False,
                    snapshot=snapshot,
                )
            elif target_id == "macos-developer-id-app":
                app_root = private.root / "app-zip"
                _extract_app_zip(snapshot, app_root)
                app = _one_app(app_root, "**/*.app")
                reject_packaged_native_messaging_host(app)
                _verify_bundle(app, "macos")
                _seal_extracted_bundle_tree(app)
                _verify_codesign(app, expected_authority, platform="macos")
                _assess_notarization(app, "execute")
            else:
                raise AppleArtifactGateError(f"unsupported Apple target: {target_id}")
            if snapshot.rehash() != expected_sha256:
                raise AppleArtifactGateError(
                    f"{target_id} signature snapshot changed during verification"
                )
            held_artifact.verify()
        finally:
            if snapshot is not None:
                snapshot.close()
            _cleanup_private_root(private)
            _PRIVATE_ROOT.reset(token)


def _unique_receipt_digest_pairs(
    target_id: str, record: Mapping[str, object]
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for field in UNIQUE_UPLOAD_RECEIPT_DIGEST_FIELDS:
        value = record.get(field)
        if type(value) is dict:
            pairs.append(
                (
                    f"{target_id}.{field}",
                    _receipt_hex64(value.get("sha256"), f"{target_id} {field}"),
                )
            )
    return pairs


def _bind_shared_upload_paths(
    shared: dict[str, tuple[str, str]], target_id: str, record: Mapping[str, object]
) -> None:
    for field in SHARED_UPLOAD_RECEIPT_PATH_FIELDS:
        value = record.get(field)
        if type(value) is not dict:
            continue
        path = _require_canonical_relative_path(value.get("path"), f"{target_id} {field}")
        digest = _receipt_hex64(value.get("sha256"), f"{target_id} {field}")
        previous = shared.get(path)
        if previous is not None and previous[0] != digest:
            raise AppleArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
            )
        for other_path, (other_digest, other_label) in shared.items():
            if other_digest == digest and other_path != path:
                raise AppleArtifactGateError(
                    f"receipt reuse is refused: {target_id}.{field} reuses {other_label}"
                )
        shared[path] = (digest, f"{target_id}.{field}")


def canonical_apple_release() -> str:
    marketing, build = reviewed_apple_release_identity()
    stamp = f"{marketing}+{build}"
    if stamp != CANONICAL_RELEASE:
        raise AppleArtifactGateError(
            "Apple release stamp is not the canonical 1.0.17+34 identity"
        )
    return stamp


def _refuse_non_shipping_apple_target(target_id: str) -> None:
    folded = str(target_id or "").casefold().replace("_", "-")
    if (
        "tvos" in folded
        or "appletv" in folded
        or folded.startswith("apple-tv")
        or "-apple-tv" in folded
        or folded in FORBIDDEN_TVOS_IDENTITY_TOKENS
    ):
        raise AppleArtifactGateError(TVOS_NOT_A_CURRENT_SURFACE)
    if (
        folded == "watchos"
        or folded.startswith("watchos-")
        or "-watchos-" in folded
        or folded.endswith("-watchos")
        or "watchkit" in folded
    ):
        raise AppleArtifactGateError(WATCHOS_NOT_A_SEPARATE_TARGET)


def _package_upload_target(target_id: str) -> dict[str, object]:
    _refuse_non_shipping_apple_target(target_id)
    spec = APPLE_PACKAGE_UPLOAD_TARGETS.get(target_id)
    if spec is None:
        raise AppleArtifactGateError(f"unsupported Apple package/upload target: {target_id}")
    return spec


def _bound_receipt_digest_pairs(
    target_id: str, record: Mapping[str, object]
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    artifact = record.get("artifact")
    build_receipt = record.get("build_receipt")
    producer = record.get("producer")
    descriptor = record.get("descriptor")
    source = record.get("source_freeze")
    hardening = record.get("obfuscation_privacy")
    if type(artifact) is dict:
        pairs.append((f"{target_id}.artifact", _receipt_hex64(artifact.get("sha256"), f"{target_id} artifact")))
    if type(build_receipt) is dict:
        pairs.append(
            (
                f"{target_id}.build_receipt",
                _receipt_hex64(build_receipt.get("sha256"), f"{target_id} build receipt"),
            )
        )
    if type(producer) is dict:
        pairs.append((f"{target_id}.producer", _receipt_hex64(producer.get("sha256"), f"{target_id} producer")))
    if type(descriptor) is dict:
        pairs.append(
            (f"{target_id}.descriptor", _receipt_hex64(descriptor.get("sha256"), f"{target_id} descriptor"))
        )
    if type(source) is dict:
        pairs.append(
            (f"{target_id}.source_freeze", _receipt_hex64(source.get("sha256"), f"{target_id} source freeze"))
        )
    if type(hardening) is dict:
        pairs.append(
            (
                f"{target_id}.obfuscation_privacy",
                _receipt_hex64(hardening.get("sha256"), f"{target_id} obfuscation/privacy"),
            )
        )
    watch = record.get("watchos")
    if type(watch) is dict:
        pairs.append(
            (
                f"{target_id}.watch_executable",
                _receipt_hex64(watch.get("executable_sha256"), f"{target_id} watch executable"),
            )
        )
        pairs.append(
            (
                f"{target_id}.watch_privacy",
                _receipt_hex64(watch.get("privacy_info_sha256"), f"{target_id} watch privacy"),
            )
        )
        verification = watch.get("artifact_verification")
        if type(verification) is dict:
            pairs.append(
                (
                    f"{target_id}.watch_verifier_output",
                    _receipt_hex64(
                        verification.get("result_sha256"),
                        f"{target_id} Watch verifier output",
                    ),
                )
            )
    return pairs


def _reject_receipt_digest_reuse(pairs: list[tuple[str, str]]) -> None:
    seen: dict[str, str] = {}
    for label, digest in pairs:
        previous = seen.get(digest)
        if previous is not None:
            raise AppleArtifactGateError(
                f"receipt reuse is refused: {label} reuses {previous}"
            )
        seen[digest] = label


class _UploadBindingTransaction:
    def __init__(self) -> None:
        self.journal = _HeldUploadReceiptJournal()
        self.files: dict[str, object] = {}

    def held_file(self, relative: str, label: str) -> _HeldLiveRepoFile:
        canonical = _require_canonical_relative_path(relative, label)
        held = self.files.get(canonical)
        if not isinstance(held, _HeldLiveRepoFile):
            raise AppleArtifactGateError(
                f"{label} was not retained before signature verification"
            )
        held.verify()
        return held

    def verify(self) -> None:
        self.journal.verify()
        for held in self.files.values():
            if not isinstance(held, _HeldLiveRepoFile):
                raise AppleArtifactGateError("live repository custody is invalid")
            held.verify()

    def close(self, *, verify: bool) -> None:
        first_error: BaseException | None = None
        for held in reversed(tuple(self.files.values())):
            if not isinstance(held, _HeldLiveRepoFile):
                continue
            try:
                held.close(verify=verify)
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        self.files.clear()
        try:
            self.journal.close(verify=verify)
        except BaseException as exc:
            if first_error is None:
                first_error = exc
        if first_error is not None:
            raise first_error


@contextlib.contextmanager
def _retained_upload_binding_transaction() -> typing.Iterator[_UploadBindingTransaction]:
    if (
        _LIVE_REPO_FILES.get() is not None
        or _UPLOAD_RECEIPT_JOURNAL_CUSTODY.get() is not None
    ):
        raise AppleArtifactGateError("nested upload receipt custody is refused")
    transaction = _UploadBindingTransaction()
    inode_token = _LIVE_INODES.set({})
    files_token = _LIVE_REPO_FILES.set(transaction.files)
    journal_token = _UPLOAD_RECEIPT_JOURNAL_CUSTODY.set(transaction.journal)
    completed = False
    try:
        yield transaction
        transaction.verify()
        completed = True
    finally:
        _UPLOAD_RECEIPT_JOURNAL_CUSTODY.reset(journal_token)
        _LIVE_REPO_FILES.reset(files_token)
        _LIVE_INODES.reset(inode_token)
        transaction.close(verify=completed)


def bind_package_upload_receipt(
    target_id: str,
    record: Mapping[str, object] | bytes,
    *,
    artifact_sha256: str,
    artifact_bytes: int,
) -> dict[str, object]:
    """Bind one Apple package/upload receipt to exact 1.0.17+34 candidate bytes."""

    with _retained_upload_binding_transaction() as transaction:
        parsed = _receipt_document(record, f"{target_id} upload receipt")
        bound, authentication = _bind_package_upload_receipt_locked(
            target_id,
            parsed,
            artifact_sha256=artifact_sha256,
            artifact_bytes=artifact_bytes,
        )
        watch = parsed.get("watchos")
        expected_watch_verification = (
            watch.get("artifact_verification") if type(watch) is dict else None
        )
        artifact = parsed.get("artifact")
        if type(artifact) is not dict:
            raise AppleArtifactGateError(f"{target_id} artifact schema is invalid")
        _require_owner_issued_apple_signature(
            target_id,
            str(artifact.get("path")),
            expected_sha256=artifact_sha256,
            expected_bytes=artifact_bytes,
            expected_watch_verification=expected_watch_verification,
            held_artifact=transaction.held_file(
                str(artifact.get("path")), f"{target_id} artifact"
            ),
        )
        _commit_upload_receipt_challenges((authentication,))
        transaction.verify()
        return bound


def _bind_package_upload_receipt_locked(
    target_id: str,
    record: Mapping[str, object] | bytes,
    *,
    artifact_sha256: str,
    artifact_bytes: int,
) -> tuple[dict[str, object], dict[str, object]]:
    spec = _package_upload_target(target_id)
    expected_keys = (
        IOS_PACKAGE_UPLOAD_RECEIPT_KEYS
        if target_id == "ios-app-store-ipa"
        else PACKAGE_UPLOAD_RECEIPT_KEYS
    )
    receipt = _receipt_exact_mapping(
        _receipt_document(record, f"{target_id} upload receipt"),
        set(expected_keys),
        f"{target_id} upload receipt",
    )
    release = canonical_apple_release()
    if (
        receipt.get("ok") is not True
        or receipt.get("schema_version") != PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION
        or receipt.get("contract") != PACKAGE_UPLOAD_RECEIPT_CONTRACT
        or receipt.get("release") != release
        or receipt.get("target_id") != target_id
        or receipt.get("platform") != spec["platform"]
        or receipt.get("publication_authorized") is not False
        or receipt.get("upload_attempted") is not False
    ):
        raise AppleArtifactGateError(f"{target_id} receipt binding is invalid or changed")
    artifact = _receipt_exact_mapping(
        receipt.get("artifact"), {"path", "sha256", "bytes"}, f"{target_id} artifact"
    )
    path = _require_canonical_relative_path(artifact.get("path"), f"{target_id} artifact")
    suffixes = TARGET_SUFFIXES[target_id]
    lowered = pathlib.PurePosixPath(path).name.lower()
    if not any(lowered.endswith(suffix) for suffix in suffixes):
        raise AppleArtifactGateError(f"{target_id} artifact type is not allowed")
    bound_digest = _receipt_hex64(artifact_sha256, f"{target_id} candidate bytes")
    if (
        artifact.get("sha256") != bound_digest
        or type(artifact.get("bytes")) is not int
        or isinstance(artifact.get("bytes"), bool)
        or int(artifact.get("bytes")) != artifact_bytes
        or int(artifact.get("bytes")) <= 0
    ):
        raise AppleArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
        )
    build_receipt = _receipt_exact_mapping(
        receipt.get("build_receipt"),
        {"path", "sha256", "target"},
        f"{target_id} build receipt",
    )
    _receipt_exact_str(
        build_receipt.get("target"),
        str(spec["build_receipt_target"]),
        f"{target_id} build receipt target",
    )
    _receipt_hex64(build_receipt.get("sha256"), f"{target_id} build receipt")
    producer = _receipt_exact_mapping(
        receipt.get("producer"), {"id", "path", "sha256"}, f"{target_id} producer"
    )
    producer_id = producer.get("id")
    if (
        type(producer_id) is not str
        or producer_id != PRODUCER_RELATIVE
        or producer.get("path") != producer_id
    ):
        raise AppleArtifactGateError(f"{target_id} producer id is not allowed")
    _receipt_hex64(producer.get("sha256"), f"{target_id} producer")
    expected_bundles = dict(spec["bundle_ids"])
    bundle_ids = _receipt_exact_mapping(
        receipt.get("bundle_ids"), set(expected_bundles), f"{target_id} bundle IDs"
    )
    if dict(bundle_ids) != expected_bundles:
        raise AppleArtifactGateError(f"{target_id} bundle IDs are not current")
    architectures = receipt.get("architectures")
    if (
        type(architectures) is not list
        or tuple(architectures) != spec["architectures"]
        or len(architectures) != len(set(architectures))
    ):
        raise AppleArtifactGateError(f"{target_id} architecture inventory is not exact")
    signing = _receipt_exact_mapping(
        receipt.get("signing"),
        {"contract", "authority", "team_id"},
        f"{target_id} signing evidence",
    )
    if (
        signing.get("contract") != spec["signing_contract"]
        or signing.get("authority") != spec["expected_authority"]
        or signing.get("team_id") != TEAM_ID
    ):
        raise AppleArtifactGateError(f"{target_id} signing evidence is not release-valid")
    store_keys = {"surface", "testflight", "app_store", "notarization"}
    store = _receipt_exact_mapping(
        receipt.get("store_evidence"), store_keys, f"{target_id} TestFlight/App Store evidence"
    )
    if (
        store.get("surface") != spec["store_surface"]
        or store.get("testflight") != spec["testflight"]
        or store.get("app_store") != spec["app_store"]
        or store.get("notarization") != spec["notarization"]
    ):
        raise AppleArtifactGateError(
            f"{target_id} TestFlight/App Store/notarization evidence is not exact"
        )
    descriptor = _receipt_exact_mapping(
        receipt.get("descriptor"),
        {"path", "sha256"},
        f"{target_id} descriptor binding",
    )
    source = _receipt_exact_mapping(
        receipt.get("source_freeze"),
        {"path", "sha256"},
        f"{target_id} source-freeze binding",
    )
    hardening = _receipt_exact_mapping(
        receipt.get("obfuscation_privacy"),
        {"path", "sha256"},
        f"{target_id} obfuscation/privacy binding",
    )
    for label, relative in (
        ("descriptor", descriptor.get("path")),
        ("source freeze", source.get("path")),
        ("obfuscation/privacy", hardening.get("path")),
        ("build receipt", build_receipt.get("path")),
        ("producer", producer.get("path")),
    ):
        _require_canonical_relative_path(relative, f"{target_id} {label}")
    if descriptor.get("path") != DESCRIPTOR_RELATIVE:
        raise AppleArtifactGateError(f"{target_id} descriptor path is not exact")
    if hardening.get("path") != OBFUSCATION_PRIVACY_RELATIVE:
        raise AppleArtifactGateError(f"{target_id} obfuscation/privacy path is not exact")
    if pathlib.PurePosixPath(str(source.get("path"))).parts[0] != ".artifacts":
        raise AppleArtifactGateError(
            f"{target_id} source freeze path must stay under .artifacts/"
        )
    if pathlib.PurePosixPath(str(build_receipt.get("path"))).parts[0] != ".artifacts":
        raise AppleArtifactGateError(
            f"{target_id} build receipt path must stay under .artifacts/"
        )
    if target_id == "ios-app-store-ipa":
        watch = _receipt_exact_mapping(
            receipt.get("watchos"),
            {
                "bundle_id",
                "companion_bundle_id",
                "version",
                "build",
                "executable",
                "executable_sha256",
                "privacy_info_sha256",
                "artifact_verification",
            },
            f"{target_id} watchOS companion",
        )
        if (
            watch.get("bundle_id") != WATCH_BUNDLE_ID
            or watch.get("companion_bundle_id") != HOST_BUNDLE_ID
            or watch.get("version") != CANONICAL_MARKETING_VERSION
            or watch.get("build") != CANONICAL_BUNDLE_VERSION
            or watch.get("executable") != WATCH_EXECUTABLE
        ):
            raise AppleArtifactGateError("watchOS companion identity is not the current 1.0.17+34 companion")
        _receipt_hex64(watch.get("executable_sha256"), "watchOS executable")
        _receipt_hex64(watch.get("privacy_info_sha256"), "watchOS privacy")
        verification = _receipt_exact_mapping(
            watch.get("artifact_verification"),
            {"contract", "artifact_sha256", "verifier", "result", "result_sha256"},
            "watchOS artifact verification",
        )
        verifier = _receipt_exact_mapping(
            verification.get("verifier"),
            {"path", "sha256", "reviewed_verifier"},
            "watchOS artifact verifier identity",
        )
        if (
            verification.get("contract") != "winsvpn-watch-artifact-verification-v1"
            or verification.get("artifact_sha256") != bound_digest
            or verifier.get("path") != WATCH_ARTIFACT_VERIFIER_RELATIVE
            or verifier.get("reviewed_verifier") is not True
        ):
            raise AppleArtifactGateError(
                "watchOS artifact verification does not bind the exact candidate"
            )
        _receipt_hex64(verifier.get("sha256"), "watchOS artifact verifier")
        result = _receipt_exact_mapping(
            verification.get("result"),
            {
                "schema_version", "bundle_id", "companion_bundle_id", "version",
                "build_number", "parent_version", "parent_build_number",
                "ipa_sha256", "ipa_bytes", "executable", "executable_sha256",
                "architectures", "watch_connectivity_dependency", "wc_session_import",
                "required_selectors", "privacy_manifest_sha256", "debug_sections",
            },
            "watchOS artifact verifier result",
        )
        if (
            result.get("executable_sha256") != watch.get("executable_sha256")
            or result.get("privacy_manifest_sha256") != watch.get("privacy_info_sha256")
            or result.get("version") != watch.get("version")
            or result.get("build_number") != watch.get("build")
            or result.get("parent_version") != watch.get("version")
            or result.get("parent_build_number") != watch.get("build")
            or result.get("ipa_sha256") != bound_digest
            or result.get("ipa_bytes") != artifact_bytes
            or verification.get("result_sha256") != _canonical_json_sha256(result)
        ):
            raise AppleArtifactGateError(
                "watchOS artifact verifier result is stale or substituted"
            )
        _receipt_hex64(verification.get("result_sha256"), "watchOS verifier result")
    owner = _receipt_exact_mapping(
        receipt.get("owner_authorization"),
        {
            "contract",
            "schema_version",
            "status",
            "credentials_authorized",
            "upload_authorized",
        },
        f"{target_id} owner authorization",
    )
    if (
        owner.get("contract") != OWNER_AUTHORIZATION_CONTRACT
        or owner.get("schema_version") != PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION
        or owner.get("status") != "pending"
        or owner.get("credentials_authorized") is not False
        or owner.get("upload_authorized") is not False
    ):
        raise AppleArtifactGateError(
            f"{target_id} owner authorization must remain pending without owner evidence"
        )
    _reject_receipt_digest_reuse(_bound_receipt_digest_pairs(target_id, receipt))
    authentication = _bind_upload_receipt_authentication(
        target_id,
        receipt,
        artifact_sha256=bound_digest,
        artifact_bytes=int(artifact_bytes),
        architectures=tuple(str(item) for item in spec["architectures"]),
        release=release,
    )
    _require_live_upload_bindings(target_id, receipt, spec)
    return (
        {
            "ok": True,
            "target_id": target_id,
            "release": release,
            "artifact_sha256": bound_digest,
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": "pending",
        },
        authentication,
    )


def bind_apple_package_upload_receipts(
    records: Mapping[str, object],
    artifacts: Mapping[str, tuple[str, int]],
) -> dict[str, object]:
    """Bind the required iOS/watchOS and macOS receipts, refusing reuse or approval."""

    with _retained_upload_binding_transaction() as transaction:
        return _bind_apple_package_upload_receipts_locked(
            records, artifacts, transaction=transaction
        )


def _bind_apple_package_upload_receipts_locked(
    records: Mapping[str, object],
    artifacts: Mapping[str, tuple[str, int]],
    *,
    transaction: _UploadBindingTransaction,
) -> dict[str, object]:
    if type(records) is not dict or type(artifacts) is not dict:
        raise AppleArtifactGateError("Apple package/upload receipt set is invalid")
    parsed: dict[str, dict[str, object]] = {}
    for target_id, record in records.items():
        parsed[str(target_id)] = _receipt_document(
            record, f"{target_id} upload receipt"
        )
    for target_id in parsed:
        _refuse_non_shipping_apple_target(str(target_id))
    unexpected = set(parsed) - set(APPLE_PACKAGE_UPLOAD_TARGETS)
    if unexpected:
        raise AppleArtifactGateError(
            "unexpected Apple package/upload receipt target: " + ", ".join(sorted(unexpected))
        )
    missing = [target_id for target_id in REQUIRED_APPLE_UPLOAD_TARGETS if target_id not in parsed]
    if missing:
        raise _owner_environment_blocker(
            "Apple package/upload receipts remain pending without owner evidence: "
            + ", ".join(missing)
        )
    unique_pairs: list[tuple[str, str]] = []
    shared: dict[str, tuple[str, str]] = {}
    for target_id, record in parsed.items():
        unique_pairs.extend(_unique_receipt_digest_pairs(target_id, record))
        _bind_shared_upload_paths(shared, target_id, record)
    _reject_receipt_digest_reuse(unique_pairs)
    bound: dict[str, object] = {}
    authentications: list[dict[str, object]] = []
    for target_id in sorted(parsed):
        record = parsed[target_id]
        artifact = artifacts.get(target_id)
        if artifact is None or len(artifact) != 2:
            raise AppleArtifactGateError(f"{target_id} exact candidate bytes are missing")
        digest, size = artifact
        result, authentication = _bind_package_upload_receipt_locked(
            target_id,
            record,
            artifact_sha256=str(digest),
            artifact_bytes=int(size),
        )
        bound[target_id] = result
        authentications.append(authentication)
    for target_id in sorted(parsed):
        record = parsed[target_id]
        watch = record.get("watchos")
        expected_watch_verification = (
            watch.get("artifact_verification") if type(watch) is dict else None
        )
        _require_owner_issued_apple_signature(
            target_id,
            str(record["artifact"]["path"]),
            expected_sha256=str(record["artifact"]["sha256"]),
            expected_bytes=int(record["artifact"]["bytes"]),
            expected_watch_verification=expected_watch_verification,
            held_artifact=transaction.held_file(
                str(record["artifact"]["path"]), f"{target_id} artifact"
            ),
        )
    _commit_upload_receipt_challenges(tuple(authentications))
    transaction.verify()
    return {
        "ok": True,
        "release": CANONICAL_RELEASE,
        "required_targets": list(REQUIRED_APPLE_UPLOAD_TARGETS),
        "bound_targets": sorted(bound),
        "publication_authorized": False,
        "upload_attempted": False,
        "owner_authorization": "pending",
        "receipts": bound,
    }


def _print_signature_pass(
    target_id: str,
    artifact: pathlib.Path,
    inner_payload: dict[str, object] | None,
    *,
    artifact_sha256: str | None = None,
) -> None:
    try:
        relative = artifact.relative_to(ROOT).as_posix()
    except ValueError:
        relative = artifact.relative_to(ROOT.resolve(strict=True)).as_posix()
    extra = ""
    if inner_payload is not None:
        aot = inner_payload.get("aot")
        if type(aot) is not dict:
            raise AppleArtifactGateError("Apple PKG inner AOT binding is missing")
        digest = artifact_sha256
        if digest is None:
            raise AppleArtifactGateError("Apple PKG snapshot digest was not bound")
        native_messaging = inner_payload.get("native_messaging")
        if (
            type(native_messaging) is not dict
            or native_messaging.get("incompatible") is not True
            or native_messaging.get("delivered") is not False
        ):
            raise AppleArtifactGateError(MACOS_NATIVE_MESSAGING_INCOMPATIBILITY)
        extra = (
            f" sha256={digest}"
            f" inner_payload_sha256={inner_payload['inner_payload_sha256']}"
            f" inner_app={inner_payload['app']}"
            f" aot_sha256={aot['sha256']}"
            f" native_messaging=incompatible"
        )
    print(
        f"APPLE CROSS-STORE SIGNATURE GATE: PASS target={target_id} "
        f"artifact={relative}{extra}"
    )


def _verify_pkg_target(
    target_id: str,
    artifact: pathlib.Path,
    private: PrivateGateRoot,
    *,
    expected_authority: str,
    inspect_signing: bool,
    notarize_install: bool,
    snapshot: AuthenticatedPkgSnapshot | None = None,
) -> tuple[pathlib.Path, dict[str, object] | None, str]:
    close_snapshot = snapshot is None
    if snapshot is None:
        snapshot = _snapshot_pkg(artifact, private.snapshot_file)
    tree: AuthenticatedTreeSnapshot | None = None
    try:
        expanded = private.root / "expanded"
        app, tree = _expand_pkg(snapshot, expanded)
        token = _TREE_SNAPSHOT.set(tree)
        try:
            app, bundles = _bind_macos_packaged_bundles(
                tree.root,
                inspect_signing=inspect_signing,
                expected_authority=expected_authority,
            )
            inner_payload = _inspect_macos_inner_payload(
                app, tree.root, bundles=bundles, target_id=target_id
            )
            _verify_bundle(app, "macos")
            if inspect_signing:
                _seal_extracted_bundle_tree(app)
                _verify_codesign(app, expected_authority, platform="macos")
            if notarize_install:
                _assess_notarization(snapshot.path, "install")
            digest = snapshot.rehash()
            tree.ensure_bound()
            return app, inner_payload, digest
        finally:
            _TREE_SNAPSHOT.reset(token)
    finally:
        if close_snapshot:
            snapshot.close()
        if tree is not None:
            tree.close()


@_support_custody_operation
def verify_held_release_artifact(
    *,
    target_id: str,
    source_fd: int,
    source_parent_fd: int,
    source_name: str,
    source_relative_path: str,
    expected_identity: tuple[int, ...],
    expected_size: int,
    expected_sha256: str,
    frozen_release: str,
) -> HeldAppleArtifactEvidence:
    """Verify one exact release-freeze-retained App Store PKG or IPA."""

    if target_id not in REQUIRED_APPLE_UPLOAD_TARGETS:
        raise AppleArtifactGateError(
            f"unsupported exact held Apple release target: {target_id}"
        )
    if type(frozen_release) is not str or frozen_release != CANONICAL_RELEASE:
        raise AppleArtifactGateError(
            "held Apple artifact release does not match the frozen canonical release"
        )
    marketing, build = reviewed_apple_release_identity()
    if frozen_release != f"{marketing}+{build}":
        raise AppleArtifactGateError(
            "held Apple artifact release identity is not current"
        )
    suffixes = _apple_target_suffixes(target_id)
    lowered_name = source_name.casefold() if type(source_name) is str else ""
    if not any(lowered_name.endswith(suffix) for suffix in suffixes):
        raise AppleArtifactGateError(
            f"{target_id} held artifact requires suffix: {', '.join(suffixes)}"
        )

    review_custody = _HeldSupportSources(HELD_ARTIFACT_REVIEW_SOURCES)
    private: PrivateGateRoot | None = None
    temporary_owner: tempfile.TemporaryDirectory[str] | None = None
    token: contextvars.Token[PrivateGateRoot | None] | None = None
    custody: HeldAppleArtifactCustody | None = None
    snapshot: AuthenticatedPkgSnapshot | None = None
    try:
        reviewed_sources = _validate_held_artifact_review_custody(review_custody)
        temporary_owner = tempfile.TemporaryDirectory(
            prefix="wins-apple-held-artifact-"
        )
        temporary = temporary_owner.name
        if temporary:
            private = _prepare_private_root(pathlib.Path(temporary))
            token = _PRIVATE_ROOT.set(private)
            custody, snapshot = _snapshot_held_apple_artifact(
                private=private,
                source_fd=source_fd,
                source_parent_fd=source_parent_fd,
                source_name=source_name,
                source_relative_path=source_relative_path,
                expected_identity=expected_identity,
                expected_size=expected_size,
                expected_sha256=expected_sha256,
            )
            target = APPLE_PACKAGE_UPLOAD_TARGETS[target_id]
            inner_payload: dict[str, object] | None = None
            watch_evidence: dict[str, object] | None = None
            macos_independent: dict[str, object] | None = None
            if target_id == "macos-app-store-pkg":
                app, inner_payload, digest = _verify_pkg_target(
                    target_id,
                    custody.origin,
                    private,
                    expected_authority=str(target["expected_authority"]),
                    inspect_signing=True,
                    notarize_install=False,
                    snapshot=snapshot,
                )
                macos_source = "verify_macos_release_artifact.py"
                macos_independent = _verify_macos_independent_snapshot(
                    app=app,
                    snapshot=snapshot,
                    inner_payload=inner_payload,
                    verifier_source=review_custody.payloads[macos_source],
                    expected_verifier_sha256=reviewed_sources[macos_source],
                )
            elif target_id == "ios-app-store-ipa":
                ipa_root = private.root / "ipa"
                _extract_zip(snapshot, ipa_root)
                app = _one_app(ipa_root, "Payload/*.app")
                _verify_bundle(app, "ios")
                _seal_extracted_bundle_tree(app)
                _verify_codesign(
                    app,
                    str(target["expected_authority"]),
                    platform="ios",
                )
                digest = snapshot.rehash()
                watch_source = "apple_watch_artifact_verifier.py"
                watch_evidence = verify_watch_artifact_snapshot(
                    pathlib.Path(snapshot.kernel_path()),
                    artifact_sha256=digest,
                    artifact_size=snapshot.size,
                    expected_verifier_sha256=reviewed_sources[watch_source],
                    verifier_source=review_custody.payloads[watch_source],
                )
            else:
                raise AppleArtifactGateError(
                    f"unsupported exact held Apple release target: {target_id}"
                )

            if digest != expected_sha256:
                raise AppleArtifactGateError(
                    "held Apple artifact verifier returned a different candidate digest"
                )
            snapshot.rehash()
            custody.rehash()
            review_custody.verify()
            support_sources = {
                filename: _MODULE_DIGESTS[public_name]
                for filename, public_name in REQUIRED_MODULE_FILES
            }
            evidence: dict[str, object] = {
                "ok": True,
                "contract": HELD_ARTIFACT_CONTRACT,
                "target_id": target_id,
                "platform": target["platform"],
                "release": frozen_release,
                "artifact_name": source_name,
                "artifact_path": source_relative_path,
                "artifact_sha256": digest,
                "artifact_bytes": expected_size,
                "artifact_identity": list(expected_identity),
                "architectures": list(target["architectures"]),
                "bundle_ids": dict(target["bundle_ids"]),
                "signing_contract": target["signing_contract"],
                "expected_authority": target["expected_authority"],
                "authenticated_source_closure": {
                    "gate_support": dict(sorted(support_sources.items())),
                    "independent_review": dict(sorted(reviewed_sources.items())),
                },
                "network_accessed": False,
                "publication_authorized": False,
                "upload_attempted": False,
                "owner_authorization": "pending",
            }
            if inner_payload is not None:
                evidence["inner_payload"] = {
                    "app": inner_payload["app"],
                    "inner_payload_sha256": inner_payload[
                        "inner_payload_sha256"
                    ],
                    "aot": dict(inner_payload["aot"]),
                    "native_messaging": dict(inner_payload["native_messaging"]),
                }
            if watch_evidence is not None:
                evidence["watchos"] = watch_evidence
            if macos_independent is not None:
                evidence["macos_independent"] = macos_independent
            snapshot.rehash()
            custody.rehash()
            review_custody.verify()
            return HeldAppleArtifactEvidence(
                evidence=evidence,
                private=private,
                temporary_owner=temporary_owner,
                private_token=token,
                custody=custody,
                snapshot=snapshot,
                review_custody=review_custody,
                candidate_key=(
                    target_id,
                    expected_sha256,
                    expected_size,
                    expected_identity,
                ),
            )
        raise AppleArtifactGateError(
            "held Apple artifact private custody could not be established"
        )
    except BaseException:
        if snapshot is not None:
            snapshot.close()
        if private is not None:
            _cleanup_private_root(private)
        if temporary_owner is not None:
            temporary_owner.cleanup()
        if token is not None:
            _PRIVATE_ROOT.reset(token)
        if custody is not None:
            custody.close(verify=False)
        review_custody.close(verify=False)
        raise


@_support_custody_operation
def verify_signature(target_id: str, raw_path: str | pathlib.Path) -> pathlib.Path:
    inner_payload: dict[str, object] | None = None
    artifact_sha256: str | None = None
    artifact: pathlib.Path | None = None
    with tempfile.TemporaryDirectory(prefix="wins-apple-artifact-gate-") as temporary:
        private = _prepare_private_root(pathlib.Path(temporary))
        token = _PRIVATE_ROOT.set(private)
        snapshot: AuthenticatedPkgSnapshot | None = None
        try:
            artifact, snapshot = _snapshot_canonical_artifact(
                target_id, raw_path, private.snapshot_file
            )
            if target_id == "ios-app-store-ipa":
                ipa_root = private.root / "ipa"
                _extract_zip(snapshot, ipa_root)
                app = _one_app(ipa_root, "Payload/*.app")
                _verify_bundle(app, "ios")
                _seal_extracted_bundle_tree(app)
                _verify_codesign(
                    app, "Authority=Apple Distribution:", platform="ios"
                )
                artifact_sha256 = snapshot.rehash()
            elif target_id == "macos-app-store-pkg":
                _app, inner_payload, artifact_sha256 = _verify_pkg_target(
                    target_id,
                    artifact,
                    private,
                    expected_authority="Authority=Apple Distribution:",
                    inspect_signing=True,
                    notarize_install=False,
                    snapshot=snapshot,
                )
            elif target_id == "macos-developer-id-app":
                app_root = private.root / "app-zip"
                _extract_app_zip(snapshot, app_root)
                app = _one_app(app_root, "**/*.app")
                reject_packaged_native_messaging_host(app)
                _verify_bundle(app, "macos")
                _seal_extracted_bundle_tree(app)
                _verify_codesign(
                    app,
                    "Authority=Developer ID Application:",
                    platform="macos",
                )
                _assess_notarization(app, "execute")
                artifact_sha256 = snapshot.rehash()
            else:
                raise AppleArtifactGateError(f"unsupported Apple target: {target_id}")
        finally:
            if snapshot is not None:
                snapshot.close()
            _cleanup_private_root(private)
            _PRIVATE_ROOT.reset(token)
    if artifact is None:
        raise AppleArtifactGateError("Apple gate artifact was not bound")
    _print_signature_pass(
        target_id,
        artifact,
        inner_payload,
        artifact_sha256=artifact_sha256,
    )
    return artifact


@_support_custody_operation
def verify_privacy_only(target_id: str, raw_path: str | pathlib.Path) -> pathlib.Path:
    artifact: pathlib.Path | None = None
    with tempfile.TemporaryDirectory(prefix="wins-apple-privacy-gate-") as temporary:
        private = _prepare_private_root(pathlib.Path(temporary))
        token = _PRIVATE_ROOT.set(private)
        snapshot: AuthenticatedPkgSnapshot | None = None
        try:
            artifact, snapshot = _snapshot_canonical_artifact(
                target_id, raw_path, private.snapshot_file
            )
            if target_id == "ios-app-store-ipa":
                ipa_root = private.root / "ipa"
                _extract_zip(snapshot, ipa_root)
                app = _one_app(ipa_root, "Payload/*.app")
                snapshot.rehash()
                _verify_bundle(app, "ios")
            elif target_id == "macos-developer-id-app":
                app_root = private.root / "app-zip"
                _extract_app_zip(snapshot, app_root)
                app = _one_app(app_root, "**/*.app")
                snapshot.rehash()
                _verify_bundle(app, "macos")
            elif target_id == "macos-app-store-pkg":
                tree: AuthenticatedTreeSnapshot | None = None
                try:
                    _require_expansion_budget(private, snapshot.size)
                    app, tree = _expand_pkg(snapshot, private.root / "expanded")
                    snapshot.rehash()
                    token_tree = _TREE_SNAPSHOT.set(tree)
                    try:
                        _verify_bundle(app, "macos")
                    finally:
                        _TREE_SNAPSHOT.reset(token_tree)
                finally:
                    if tree is not None:
                        tree.close()
                return artifact
            else:
                raise AppleArtifactGateError(f"unsupported Apple target: {target_id}")
        finally:
            if snapshot is not None:
                snapshot.close()
            _cleanup_private_root(private)
            _PRIVATE_ROOT.reset(token)
    if artifact is None:
        raise AppleArtifactGateError("Apple gate artifact was not bound")
    return artifact


@_support_custody_operation
def watch_artifact_evidence(raw_path: str | pathlib.Path) -> dict[str, object]:
    """Return verifier identity/output bound to one authenticated IPA snapshot."""

    review_custody = _HeldSupportSources(HELD_ARTIFACT_REVIEW_SOURCES)
    try:
        reviewed = _validate_held_artifact_review_custody(review_custody)
        watch_source = "apple_watch_artifact_verifier.py"
        with tempfile.TemporaryDirectory(prefix="wins-apple-watch-evidence-") as temporary:
            private = _prepare_private_root(pathlib.Path(temporary))
            token = _PRIVATE_ROOT.set(private)
            snapshot: AuthenticatedPkgSnapshot | None = None
            try:
                _artifact, snapshot = _snapshot_canonical_artifact(
                    "ios-app-store-ipa", raw_path, private.snapshot_file
                )
                digest = snapshot.rehash()
                evidence = verify_watch_artifact_snapshot(
                    snapshot.path,
                    artifact_sha256=digest,
                    artifact_size=snapshot.size,
                    verifier_source=review_custody.payloads[watch_source],
                    expected_verifier_sha256=reviewed[watch_source],
                )
                if snapshot.rehash() != digest:
                    raise AppleArtifactGateError(
                        "held iOS IPA changed during Watch artifact verification"
                    )
                review_custody.verify()
                return evidence
            finally:
                if snapshot is not None:
                    snapshot.close()
                _cleanup_private_root(private)
                _PRIVATE_ROOT.reset(token)
    finally:
        review_custody.close(verify=True)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args and args[0] == "native-host":
            return native_host_main(args[1:])
        if len(args) == 2 and args[0] == "watch-evidence":
            print(
                json.dumps(
                    watch_artifact_evidence(args[1]),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if len(args) != 3 or args[0] not in {"signature", "privacy"}:
            raise AppleArtifactGateError(
                "usage: apple_cross_store_artifact_gate.py signature|privacy "
                "<target-id> <repo-relative-artifact> | watch-evidence "
                "<repo-relative-ios-ipa>"
            )
        if args[0] == "signature":
            verify_signature(args[1], args[2])
        else:
            verify_privacy_only(args[1], args[2])
            print(f"APPLE CROSS-STORE PRIVACY GATE: PASS target={args[1]}")
    except AppleArtifactUnverified as exc:
        print(
            f"APPLE CROSS-STORE ARTIFACT GATE: UNVERIFIED: {_redact_tool_output(str(exc))}",
            file=sys.stderr,
        )
        return 2
    except AppleArtifactGateError as exc:
        print(
            f"APPLE CROSS-STORE ARTIFACT GATE: FAIL: {_redact_tool_output(str(exc))}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
