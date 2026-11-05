#!/usr/bin/env python3
"""Fail closed unless an AAB has one signer and exact held-byte identity.

Identity, split/module contract, signer set, and embedded metadata are derived
from the exact held AAB bytes with a closed-format proto/ZIP parser. The latest
stable frozen bundletool (1.18.3) is required as an independent decoder of the
same held bytes. AAB paths are never inspected with the SDK APK analyzer CLI.
"""

from __future__ import annotations

import argparse
import base64
import contextvars
import datetime
import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from contextlib import ExitStack, contextmanager
from typing import Callable, Iterator


ROOT = pathlib.Path(__file__).resolve().parent.parent
CANONICAL_TARGETS = frozenset(
    {"android-phone-tablet-aab", "android-tv-aab", "wear-os-aab"}
)
EXPECTED_APPLICATION_ID = "org.winsvpn.app"
CANONICAL_RELEASE = "1.0.16+33"
CANONICAL_MARKETING_VERSION = "1.0.16"
CANONICAL_BUILD_NUMBER = 33
RELEASE_IDENTITY_SOURCE_SHA256 = {
    "pubspec.yaml": "ded4a0b883dca97aea5cbedce75d110c1d410bc7d1d415a14996fdc99d16a59e",
    "android/app/build.gradle.kts": (
        "64a53b58239eef312962f6eaad038221f14f5d9e207423ec1834bfcfaccf11eb"
    ),
}
TARGET_IDENTITY_MAPPING = {
    "android-phone-tablet-aab": "android_phone",
    "android-tv-aab": "android_tv",
    "wear-os-aab": "wear_os",
}
PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION = 2
PACKAGE_UPLOAD_RECEIPT_CONTRACT = "winsvpn-android-package-upload-receipt-v2"
OWNER_AUTHORIZATION_CONTRACT = "winsvpn-android-owner-authorization-v2"
DESCRIPTOR_RELATIVE = "tools/verify_android_aab_signers.py"
OBFUSCATION_PRIVACY_RELATIVE = "tools/release_obfuscation_contract.py"
PHONE_TV_PRODUCER_RELATIVE = "tools/verify_android_aab_signers.py"
WEAR_PRODUCER_RELATIVE = "wear_os/tools/signed_aab_receipt.py"
UNIQUE_UPLOAD_RECEIPT_DIGEST_FIELDS = ("artifact", "build_receipt")
SHARED_UPLOAD_RECEIPT_PATH_FIELDS = (
    "descriptor",
    "source_freeze",
    "obfuscation_privacy",
)
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
        "package_identity",
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
REQUIRED_ANDROID_UPLOAD_TARGETS = (
    "android-phone-tablet-aab",
    "android-tv-aab",
    "wear-os-aab",
)
UPLOAD_RECEIPT_ISSUER = "winsvpn-android-package-upload-receipt"
UPLOAD_RECEIPT_JOURNAL_RELATIVE = ".artifacts/upload-receipt-journal/android.jsonl"
UPLOAD_RECEIPT_JOURNAL_SCHEMA = "winsvpn-android-upload-receipt-journal-v1"
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
UPLOAD_RECEIPT_PLACEHOLDER_TRUST_MARKERS = (
    "placeholder",
    "ed25519privatekey",
    "ed25519publickey",
)
RECEIPT_REPLAY_ERROR = (
    "Android package/upload receipt nonce or run_id was already consumed"
)
RECEIPT_STALE_ERROR = "Android package/upload receipt is not fresh"
RECEIPT_UNAUTHENTICATED_ERROR = (
    "Android package/upload receipt is not authenticated by the trusted issuer"
)
RECEIPT_PLACEHOLDER_TRUST_ERROR = (
    "Android package/upload receipt trust key is a placeholder"
)
OWNER_BLOCKED_MISSING_EVIDENCE = (
    "Android package/upload receipts remain pending without owner evidence: "
)
OWNER_BLOCKED_NO_SIGNATURE = (
    "no owner-issued Play upload signature is bound to the exact artifact"
)
OWNER_SIGNATURE_PENDING_MARKERS = (
    "pending without owner evidence",
    "did not prove a cryptographically verified",
    "jar is unsigned",
    "was reported as unsigned",
    OWNER_BLOCKED_NO_SIGNATURE,
    "retained private jdk tool paths are required",
)
OWNER_SIGNATURE_HARD_FAIL_MARKERS = (
    "reviewed upload certificate",
    "debug signer",
    "another exact target",
    "r8 proguard.map",
    "too trivial",
    "native engine",
    "form-factor identity",
    "version identity",
    "private r8",
)
_LIVE_INODES: contextvars.ContextVar[dict[tuple[int, int], str] | None] = (
    contextvars.ContextVar("_LIVE_INODES", default=None)
)
REVIEWED_UPLOAD_CERTIFICATE_SHA256 = (
    "4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee"
)
TOOLCHAIN_PINS_RELATIVE = "tools/toolchain-pins.json"
JDK_ROOT_ENV = "WINS_RELEASE_JAVA_HOME"
OWNER_JDK_TREE_SHA256 = (
    "db1c82d16dcda3fda01523da938f2c32783f4fc441d6fc93e13be3313d5ed798"
)
OWNER_JDK_TOOL_SHA256 = {
    "java": "af8b122943345320b179c75c3404d56a981017739746b75f9caf583632f0bea0",
    "jarsigner": "fe9a1276c5a18c115177f0e7a5bea9b3163739e280332044564089be7f766c64",
    "keytool": "af587a253678cda7ca2704daee936af1993305ce9a9bc6d5018f37f49d425fcb",
}
RELEASE_PYTHON_VERSION = (3, 14, 7)
APKSIGNER_BUILD_TOOLS_VERSION = "37.0.0"
APKSIGNER_JAR_RELATIVE = ("build-tools", APKSIGNER_BUILD_TOOLS_VERSION, "lib", "apksigner.jar")
OWNER_APKSIGNER_JAR_SHA256 = (
    "2defad215d7ff52968a409cde528cdaef7918b115e276b8e3378ca7a178e4180"
)
MAX_JDK_RELEASE_FILE_BYTES = 64 * 1024
TOOL_ENVIRONMENT_FORBIDDEN_NAMES = frozenset(
    {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "JAVA_OPTS"}
)
TOOL_ENVIRONMENT_FORBIDDEN_PREFIXES = ("DYLD_", "LD_")
TOOL_REAP_GRACE_SECONDS = 10
ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID = f"{{{ANDROID_NS}}}"
BUNDLETOOL_VERSION = "1.18.3"
BUNDLETOOL_ALL_SHA256 = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
BUNDLETOOL_ENV = "WINS_BUNDLETOOL_JAR"
MAX_BUNDLETOOL_BYTES = 64 * 1024 * 1024
HELD_TOOL_SNAPSHOT_PREFIX = "winsvpn-held-android-tools-"
BUNDLETOOL_SNAPSHOT_NAME = "bundletool.jar"
APKSIGNER_SNAPSHOT_NAME = "apksigner.jar"
MAX_TOOL_STDOUT_BYTES = 4 * 1024 * 1024
MAX_TOOL_STDERR_BYTES = 2 * 1024 * 1024
HELD_AAB_VALIDATION_SCHEMA_VERSION = 1
HELD_AAB_VALIDATION_CONTRACT = "winsvpn-android-held-aab-validation-v1"
MAX_HELD_AAB_BYTES = 512 * 1024 * 1024
HELD_AAB_READ_CHUNK = 1024 * 1024
HELD_AAB_SNAPSHOT_PREFIX = "winsvpn-held-aab-"
MAX_AAB_ZIP_ENTRIES = 10_000
MAX_AAB_ZIP_MEMBER_BYTES = 256 * 1024 * 1024
MAX_AAB_ZIP_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_AAB_ZIP_COMPRESSION_RATIO = 200
MAX_AAB_ZIP_MEMBER_NAME_BYTES = 4096
MAX_AAB_NESTED_ARCHIVE_DEPTH = 3
MAX_AAB_NESTED_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_AAB_RECURSIVE_ZIP_ENTRIES = 20_000
PHONE_TV_ABIS = frozenset({"arm64-v8a", "armeabi-v7a", "x86_64"})
WEAR_ABIS = frozenset({"arm64-v8a", "armeabi-v7a", "x86", "x86_64"})
REQUIRED_ABIS = {
    "android-phone-tablet-aab": PHONE_TV_ABIS,
    "android-tv-aab": PHONE_TV_ABIS,
    "wear-os-aab": WEAR_ABIS,
}
ANDROID_PACKAGE_UPLOAD_TARGETS = {
    "android-phone-tablet-aab": {
        "platform": "android",
        "required": True,
        "form": "phone-tablet",
        "package": EXPECTED_APPLICATION_ID,
        "version_name": CANONICAL_MARKETING_VERSION,
        "version_code": 33,
        "architectures": tuple(sorted(PHONE_TV_ABIS)),
        "producer": PHONE_TV_PRODUCER_RELATIVE,
        "build_receipt_target": "google-play-phone-tablet",
        "signing_contract": "play-upload-certificate",
        "store_surface": "google-play-phone-tablet",
    },
    "android-tv-aab": {
        "platform": "android",
        "required": True,
        "form": "tv",
        "package": EXPECTED_APPLICATION_ID,
        "version_name": CANONICAL_MARKETING_VERSION,
        "version_code": 3302,
        "architectures": tuple(sorted(PHONE_TV_ABIS)),
        "producer": PHONE_TV_PRODUCER_RELATIVE,
        "build_receipt_target": "google-play-tv",
        "signing_contract": "play-upload-certificate",
        "store_surface": "google-play-tv",
    },
    "wear-os-aab": {
        "platform": "wear-os",
        "required": True,
        "form": "wear",
        "package": EXPECTED_APPLICATION_ID,
        "version_name": CANONICAL_MARKETING_VERSION,
        "version_code": 3301,
        "architectures": tuple(sorted(WEAR_ABIS)),
        "producer": WEAR_PRODUCER_RELATIVE,
        "build_receipt_target": "google-play-wear-os",
        "signing_contract": "play-upload-certificate",
        "store_surface": "google-play-wear-os",
    },
}
MANIFEST_MEMBER = "base/manifest/AndroidManifest.xml"
BUNDLE_CONFIG_MEMBER = "BundleConfig.pb"
OFFICIAL_PROGUARD_MAP = "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map"
NATIVE_LIB_RE = re.compile(r"^base/lib/([^/]+)/[^/]+\.so$")
APK_NATIVE_LIB_RE = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")
DEBUG_SYMBOL_RE = re.compile(
    r"^BUNDLE-METADATA/com\.android\.tools\.build\.debugsymbols/([^/]+)/"
    r"(libapp|libflutter)\.so\.(sym|dbg)$"
)
PRIVATE_SYMBOL_MEMBER_RE = re.compile(
    r"(?i)(?:^|/)(?:mapping\.txt|proguard\.map|.+\.symbols|"
    r"libapp\.so\.(?:sym|dbg)|libflutter\.so\.(?:sym|dbg))$"
)
AXML_MAGIC = b"\x03\x00\x08\x00"
ATTR_VERSION_CODE = 0x0101021B
ATTR_VERSION_NAME = 0x0101021C
ATTR_NAME = 0x01010003
ATTR_LABEL = 0x01010001
ATTR_PERMISSION = 0x01010006
ATTR_REQUIRED = 0x0101028E
ATTR_BANNER = 0x0101033F
ATTR_SCREEN_ORIENTATION = 0x0101001E
SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
MAX_PKCS7 = 256 * 1024
MAX_PKCS7_CERTS = 4
MAX_DER_DEPTH = 12
CN_OID_DER = bytes.fromhex("0603550403")
DEBUG_SIGNER_MARKER = "android debug"
PHONE_TV_AAB_TARGETS = frozenset({"android-phone-tablet-aab", "android-tv-aab"})
PHONE_TV_APK_TARGETS = frozenset({"android-phone-tablet-apk", "android-tv-apk"})
APK_TARGET_IDENTITY_MAPPING = {
    "android-phone-tablet-apk": "android_phone",
    "android-tv-apk": "android_tv",
}
REVIEWED_ANDROID_TARGET_IDENTITIES = {
    "android_phone": (EXPECTED_APPLICATION_ID, CANONICAL_MARKETING_VERSION, 33),
    "android_tv": (EXPECTED_APPLICATION_ID, CANONICAL_MARKETING_VERSION, 3302),
    "wear_os": (EXPECTED_APPLICATION_ID, CANONICAL_MARKETING_VERSION, 3301),
}
APK_REQUIRED_ABIS = {
    "android-phone-tablet-apk": PHONE_TV_ABIS,
    "android-tv-apk": PHONE_TV_ABIS,
}
APK_MANIFEST_MEMBER = "AndroidManifest.xml"
# Android refuses Xray mode (VpnTunnelService.kt) and the Gradle packaging
# excludes libxray.so, so the exact engine set is Winn v3 plus AmneziaWG and a
# package carrying libxray.so is refused. libwinn_tun_bulk.so is neither
# required nor forbidden here: it is an optional bulk tun reader that the app
# loads with a fallback, and the standalone-v3 gate ELF-checks it when present.
PHONE_TV_REQUIRED_NATIVE_ENGINES = frozenset({"libwinnengine.so", "libam-go.so"})
PHONE_TV_FORBIDDEN_NATIVE_ENGINES = frozenset(
    {"libam.so", "libam-quick.so", "libxray.so"}
)
PHONE_TV_REQUIRED_PERMISSIONS = frozenset(
    {
        "android.permission.INTERNET",
        "android.permission.QUERY_ALL_PACKAGES",
    }
)
MIN_R8_MAPPING_BYTES = 2048
MIN_R8_CLASS_MAPPINGS = 32
R8_CLASS_MAPPING_RE = re.compile(r"^[^\s#].* -> .+:\s*$", re.MULTILINE)
RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12
UTF8_FLAG = 1 << 8
NO_INDEX = 0xFFFFFFFF
TUNNEL_PROTOCOL_CONTRACT = {
    "executed_on": "local-device",
    "primary": "winn-v3",
    "fallback": ["awg"],
    "required_local_engines": [
        "libwinnengine.so",
        "libam-go.so",
    ],
    "forbidden_local_engines": ["libam.so", "libam-quick.so", "libxray.so"],
}
COLLECTED_CATEGORIES = [
    "device_or_other_ids",
    "user_ids",
    "email_address",
    "approximate_location",
    "purchase_history",
    "app_info",
    "diagnostics_if_sdk_report_proves",
]
NOT_COLLECTED_CATEGORIES = [
    "browsing_history",
    "dns_query_history",
    "traffic_content",
    "raw_vpn_traffic",
    "destination_activity",
]
PHONE_TV_STORE_SPECS = {
    "android-phone-tablet-aab": {
        "form": "phone-tablet",
        "root": "app_store/android/phone",
        "privacy_contract": "winsvpn-android-phone-privacy-label-v1",
        "signoff_contract": "winsvpn-android-phone-owner-signoff-v1",
        "candidate_contract": "winsvpn-android-phone-release-candidate-v1",
        "target_id": "android-phone-tablet-aab",
        "apk_target_id": "android-phone-tablet-apk",
        "version_code": 33,
        "application_label": "Calculator",
        "play_listing_name": "Win's VPN",
        "camouflage": True,
        "leanback": False,
        "aab_path": "build/app/outputs/bundle/release/app-release.aab",
        "apk_path": "build/app/outputs/flutter-apk/app-phone-release.apk",
        "private_aab": ".artifacts/private-release-symbols/android-aab",
        "private_apk": ".artifacts/private-release-symbols/android-apk",
    },
    "android-tv-aab": {
        "form": "tv",
        "root": "app_store/android/tv",
        "privacy_contract": "winsvpn-android-tv-privacy-label-v1",
        "signoff_contract": "winsvpn-android-tv-owner-signoff-v1",
        "candidate_contract": "winsvpn-android-tv-release-candidate-v1",
        "target_id": "android-tv-aab",
        "apk_target_id": "android-tv-apk",
        "version_code": 3302,
        "application_label": "Win's VPN",
        "play_listing_name": "Win's VPN",
        "camouflage": False,
        "leanback": True,
        "aab_path": "build/app/outputs/bundle/tvRelease/app-tv-release.aab",
        "apk_path": "build/app/outputs/flutter-apk/app-tv-release.apk",
        "private_aab": ".artifacts/private-release-symbols/android-tv-aab",
        "private_apk": ".artifacts/private-release-symbols/android-tv-apk",
    },
}
PHONE_TV_STORE_FILES = (
    "README.md",
    "metadata/en-US/title.txt",
    "metadata/en-US/short_description.txt",
    "metadata/en-US/full_description.txt",
    "metadata/en-US/whats_new.txt",
    "review/play_console_notes.txt",
    "review/data_safety.md",
    "review/privacy_label_manifest.json",
    "review/owner_signoff.json",
    "artifacts/release_candidate.json",
)
WEAR_PRODUCER_PATH = pathlib.Path(__file__).resolve().parent.parent / WEAR_PRODUCER_RELATIVE
_WEAR_RECEIPT_MODULE = None


class SignerError(RuntimeError):
    pass


def _owner_environment_blocker(message: str) -> SignerError:
    return SignerError(f"owner/environment blocker: {message}")


def canonical_android_release() -> str:
    package, version_name, version_code = _reviewed_target_identity(
        "android-phone-tablet-aab"
    )
    if (
        package != EXPECTED_APPLICATION_ID
        or version_name != CANONICAL_MARKETING_VERSION
        or version_code != CANONICAL_BUILD_NUMBER
    ):
        raise SignerError("Android release identity is inconsistent")
    stamp = f"{version_name}+{CANONICAL_BUILD_NUMBER}"
    if stamp != CANONICAL_RELEASE:
        raise SignerError("Android release stamp is not the canonical 1.0.16+33 identity")
    return stamp


def _reviewed_target_identity(target_id: str) -> tuple[str, str, int]:
    platform = TARGET_IDENTITY_MAPPING.get(target_id) or APK_TARGET_IDENTITY_MAPPING.get(
        target_id
    )
    if platform is None:
        raise SignerError(f"unsupported exact Android upload target: {target_id}")
    package, version_name, base_code, tv_code = _source_bound_android_release_identity()
    version_code = {
        "android_phone": base_code,
        "android_tv": tv_code,
        "wear_os": base_code * 100 + 1,
    }[platform]
    expected_code = {
        "android_phone": CANONICAL_BUILD_NUMBER,
        "android_tv": CANONICAL_BUILD_NUMBER * 100 + 2,
        "wear_os": CANONICAL_BUILD_NUMBER * 100 + 1,
    }[platform]
    if (
        package != EXPECTED_APPLICATION_ID
        or version_name != CANONICAL_MARKETING_VERSION
        or version_code != expected_code
        or REVIEWED_ANDROID_TARGET_IDENTITIES[platform]
        != (package, version_name, version_code)
        or CANONICAL_RELEASE != f"{version_name}+{base_code}"
    ):
        raise SignerError("Android release identity is inconsistent")
    return package, version_name, version_code


def _canonical_gate_artifact(target_id: str, raw_path: str) -> pathlib.Path:
    if target_id not in CANONICAL_TARGETS:
        raise SignerError(f"unsupported exact Android upload target: {target_id}")
    relative = _require_canonical_relative_path(raw_path, "cross-store AAB")
    if not pathlib.PurePosixPath(relative).name.lower().endswith(".aab"):
        raise SignerError("cross-store artifact must be one non-empty .aab file")
    return ROOT / pathlib.Path(relative)


def _scrub_tool_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Drop JVM option injection, class-path, and dynamic-loader variables."""

    scrubbed: dict[str, str] = {}
    for key, value in environment.items():
        if (
            type(key) is not str
            or type(value) is not str
            or not key
            or "=" in key
            or "\x00" in key
            or "\x00" in value
            or key in TOOL_ENVIRONMENT_FORBIDDEN_NAMES
            or key.startswith(TOOL_ENVIRONMENT_FORBIDDEN_PREFIXES)
        ):
            continue
        scrubbed[key] = value
    return scrubbed


def _safe_tool_environment() -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    for name in ("HOME", "TMPDIR"):
        value = os.environ.get(name, "")
        if value and "\x00" not in value and os.path.isabs(value):
            environment[name] = value
    if _ACTIVE_ANDROID_TOOLS.get() is not None:
        java, _jarsigner, _keytool = _bound_jdk_tools()
        environment["JAVA_HOME"] = str(pathlib.Path(java).parent.parent)
    return _scrub_tool_environment(environment)


_JAVA_IDENTITY_TOOLS: contextvars.ContextVar[tuple[str, str, str] | None] = (
    contextvars.ContextVar("wins_aab_java_identity_tools", default=None)
)
_ACTIVE_ANDROID_TOOLS: contextvars.ContextVar[
    _HeldAndroidVerificationTools | None
] = contextvars.ContextVar("wins_aab_active_android_tools", default=None)


def _authenticate_jdk_tool(raw: str, name: str) -> pathlib.Path:
    if type(raw) is not str or not raw or "\x00" in raw:
        raise SignerError(f"{name} must be an absolute authenticated JDK tool path")
    if os.name != "nt" and "\\" in raw:
        raise SignerError(f"{name} must be an absolute authenticated JDK tool path")
    path = pathlib.Path(raw)
    expected_names = {name}
    if os.name == "nt":
        expected_names.add(f"{name}.exe")
    expected_path = _pinned_jdk_identity()["root"] / "bin" / name
    if (
        not path.is_absolute()
        or path.name not in expected_names
        or path != expected_path
    ):
        raise SignerError(f"{name} must be an absolute authenticated JDK tool path")
    current = pathlib.Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except OSError as suc:
            raise SignerError(f"{name} path is not a readable regular file") from suc
        if stat.S_ISLNK(info.st_mode):
            raise SignerError(f"{name} must resolve to a regular non-symlink executable")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    elif os.name != "nt":
        raise SignerError("Android live binding requires O_NOFOLLOW")
    try:
        fd = os.open(path, flags)
    except OSError as suc:
        raise SignerError(f"{name} must resolve to a regular non-symlink executable") from suc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise SignerError(f"{name} must resolve to a regular non-symlink executable")
        if os.name != "nt" and stat.S_IMODE(opened.st_mode) & 0o111 == 0:
            raise SignerError(f"{name} must resolve to a regular non-symlink executable")
    finally:
        os.close(fd)
    return path


def bind_java_identity_tools(java: str, jarsigner: str, keytool: str) -> tuple[str, str, str]:
    java_path = _authenticate_jdk_tool(java, "java")
    jarsigner_path = _authenticate_jdk_tool(jarsigner, "jarsigner")
    keytool_path = _authenticate_jdk_tool(keytool, "keytool")
    if len({java_path.parent, jarsigner_path.parent, keytool_path.parent}) != 1:
        raise SignerError("AAB identity JDK tools must share one authenticated bin directory")
    with _HeldAndroidVerificationTools(bind_bundletool=False) as held:
        held.revalidate(full_tree=True)
    bound = (str(java_path), str(jarsigner_path), str(keytool_path))
    _JAVA_IDENTITY_TOOLS.set(bound)
    return bound


def _bound_jdk_tools() -> tuple[str, str, str]:
    active = _ACTIVE_ANDROID_TOOLS.get()
    if active is None:
        raise SignerError(
            "retained private JDK tool paths are required for AAB identity verification"
        )
    return active.jdk_tools


def _bound_jdk_tool(name: str) -> str:
    java, jarsigner, keytool = _bound_jdk_tools()
    mapping = {"java": java, "jarsigner": jarsigner, "keytool": keytool}
    if name not in mapping:
        raise SignerError(f"{name} is required for exact AAB verification")
    return mapping[name]


def _bound_jdk_tool_fd(name: str) -> int:
    active = _ACTIVE_ANDROID_TOOLS.get()
    if active is None:
        raise SignerError(
            "retained private JDK tool paths are required for AAB identity verification"
        )
    return active.jdk_tool_fd(name)


def _run(
    arguments: list[str],
    label: str,
    *,
    timeout: int = 120,
    pass_fds: tuple[int, ...] = (),
    revalidate: Callable[[], None] | None = None,
    watch_fds: tuple[int, ...] = (),
) -> bytes:
    """Run one reviewed tool with a scrubbed environment and bounded output.

    The child starts in a new session, so it leads its own process group. The
    whole group is sent SIGKILL on timeout, on an output bound overflow, and
    after the leader exits (before the leader is reaped, so the group id
    cannot be reused) to reap stragglers. A descendant that calls setsid()
    leaves the group and is not killed; it still cannot keep this call open
    past the deadline because the run fails closed when the deadline expires.
    That residual risk is accepted by the 2026-10-09 owner ruling that
    replaced the owner-provisioned cleanup-helper requirement.
    """

    if type(timeout) is not int or isinstance(timeout, bool) or timeout <= 0:
        raise SignerError(f"{label} deadline is invalid")
    if (
        type(arguments) is not list
        or not arguments
        or any(type(value) is not str or not value or "\x00" in value for value in arguments)
        or not os.path.isabs(arguments[0])
    ):
        raise SignerError(f"{label} command is not one absolute reviewed tool invocation")
    descriptors = tuple(dict.fromkeys(pass_fds))
    watched = tuple(dict.fromkeys(watch_fds))
    for descriptor in (*descriptors, *watched):
        if type(descriptor) is not int or isinstance(descriptor, bool) or descriptor < 3:
            raise SignerError(f"{label} descriptor set is invalid")
    environment = _scrub_tool_environment(_safe_tool_environment())
    if revalidate is not None:
        revalidate()
    try:
        before = {descriptor: _held_stat_identity(os.fstat(descriptor)) for descriptor in watched}
        for descriptor in descriptors:
            os.fstat(descriptor)
    except OSError as exc:
        raise SignerError(f"{label} retained descriptor is not open") from exc
    try:
        output = _run_bounded_process(arguments, label, timeout, descriptors, environment)
    except BaseException as exc:
        _require_post_run_custody(label, before, revalidate, cause=exc)
        raise
    _require_post_run_custody(label, before, revalidate, cause=None)
    return output


def _require_post_run_custody(
    label: str,
    before: Mapping[int, tuple[int, ...]],
    revalidate: Callable[[], None] | None,
    *,
    cause: BaseException | None,
) -> None:
    try:
        for descriptor, expected in before.items():
            if _held_stat_identity(os.fstat(descriptor)) != expected:
                raise SignerError(f"{label} retained descriptor custody changed")
        if revalidate is not None:
            revalidate()
    except SignerError as exc:
        if cause is None:
            raise
        raise exc from cause
    except OSError as exc:
        raise SignerError(f"{label} retained descriptor custody changed") from (
            cause if cause is not None else exc
        )


def _kill_process_group(process_group: int) -> None:
    try:
        os.killpg(process_group, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _leader_has_exited(process: subprocess.Popen) -> bool:
    """Report leader exit without reaping it when the platform allows that."""

    waitid = getattr(os, "waitid", None)
    no_wait = getattr(os, "WNOWAIT", None)
    if waitid is not None and no_wait is not None and process.returncode is None:
        try:
            result = waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | no_wait)
        except ChildProcessError:
            return process.poll() is not None
        return result is not None
    # Without waitid(WNOWAIT) the leader is reaped here, so the later group
    # kill has a theoretical group-id reuse window. The release entry point
    # requires CPython 3.14.7 on macOS, where waitid is available.
    return process.poll() is not None


def _run_bounded_process(
    arguments: list[str],
    label: str,
    timeout: int,
    pass_fds: tuple[int, ...],
    environment: dict[str, str],
) -> bytes:
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            cwd="/",
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise SignerError(f"{label} could not execute and failed closed") from exc
    process_group = process.pid
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    streams = {
        process.stdout.fileno(): (stdout, MAX_TOOL_STDOUT_BYTES, "stdout"),
        process.stderr.fileno(): (stderr, MAX_TOOL_STDERR_BYTES, "stderr"),
    }
    failure: str | None = None
    leader_exited = False
    returncode: int | None = None
    selector = selectors.DefaultSelector()
    try:
        for descriptor in streams:
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)
        while True:
            if not leader_exited and _leader_has_exited(process):
                leader_exited = True
                _kill_process_group(process_group)
            if leader_exited and not selector.get_map():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"{label} timed out after {timeout}s and failed closed"
                break
            if not selector.get_map():
                time.sleep(min(remaining, 0.01))
                continue
            for key, _mask in selector.select(min(remaining, 0.05)):
                buffer, bound, name = streams[key.fd]
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                buffer.extend(chunk)
                if len(buffer) > bound:
                    failure = f"{label} {name} exceeded {bound} bytes and failed closed"
                    break
            if failure is not None:
                break
    finally:
        selector.close()
        _kill_process_group(process_group)
        try:
            returncode = process.wait(timeout=TOOL_REAP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = process.wait()
        finally:
            process.stdout.close()
            process.stderr.close()
    if failure is not None:
        raise SignerError(failure)
    if returncode != 0:
        detail = bytes(stderr[-512:] or stdout[-512:]).decode("ascii", errors="replace").strip()
        raise SignerError(
            f"{label} failed closed with exit status {returncode}"
            + (f": {detail}" if detail else "")
        )
    return bytes(stdout)


def _reviewed_upload_certificate() -> str:
    value = REVIEWED_UPLOAD_CERTIFICATE_SHA256
    if re.fullmatch(r"[0-9a-f]{64}", value) is None or value == "0" * 64:
        raise SignerError("reviewed Android upload certificate pin is not exact")
    return value


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


def _vnode_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (int(info.st_dev), int(info.st_ino), int(info.st_nlink), int(info.st_size))


def _open_flags(*, write: bool = False, exclusive: bool = False) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise SignerError("Android live binding requires O_NOFOLLOW")
    flags = os.O_CLOEXEC | nofollow
    if write:
        flags |= os.O_RDWR | os.O_CREAT
        if exclusive:
            flags |= os.O_EXCL
        return flags
    return flags | os.O_RDONLY


def _dir_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if directory == 0 or nofollow == 0:
        raise SignerError("Android live binding requires O_DIRECTORY and O_NOFOLLOW")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | directory


def _openat_child(parent_fd: int, name: str, flags: int) -> int:
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise SignerError("Android gate path component is unsafe")
    try:
        info = os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        raise SignerError(f"Android gate could not bind path component {name!r}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise SignerError(f"Android gate path must not contain symlinks: {name}")
    if flags & getattr(os, "O_DIRECTORY", 0):
        if not stat.S_ISDIR(info.st_mode):
            raise SignerError(f"Android gate path component is not a directory: {name}")
    elif not stat.S_ISREG(info.st_mode):
        raise SignerError(f"{name} must be a non-empty regular single-link file")
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        if getattr(exc, "errno", None) in {errno.ELOOP, errno.ENOTDIR}:
            raise SignerError(
                f"Android gate path must not contain symlinks: {name}"
            ) from exc
        raise SignerError(
            f"Android gate could not bind path component {name!r}"
        ) from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise SignerError(f"Android gate path component was replaced: {name}")
        return fd
    except Exception:
        os.close(fd)
        raise


def _hold_aab_bytes(path: pathlib.Path) -> tuple[bytes, tuple[int, int, int, int], str]:
    source = path.expanduser()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
    except OSError as exc:
        raise SignerError(f"AAB must be a readable regular non-symlink file: {source}") from exc
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise SignerError(f"AAB must be a regular file: {source}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        if len(data) != before.st_size or not data:
            raise SignerError("AAB current bytes could not be held")
        return data, _file_identity(before), _sha256_bytes(data)
    finally:
        os.close(source_fd)


def _revalidate_held_aab(
    path: pathlib.Path, identity: tuple[int, int, int, int], digest: str
) -> None:
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise SignerError("AAB source path disappeared during inspection") from exc
    if _file_identity(after) != identity:
        raise SignerError("AAB current bytes changed during inspection")
    held, held_identity, held_digest = _hold_aab_bytes(path)
    if held_identity != identity or held_digest != digest or _sha256_bytes(held) != digest:
        raise SignerError("AAB current bytes changed during inspection")


@contextmanager
def _private_held_copy(data: bytes) -> Iterator[pathlib.Path]:
    with tempfile.TemporaryDirectory(prefix="winsvpn-aab-hold-") as directory:
        custody = pathlib.Path(directory)
        os.chmod(custody, 0o700)
        directory_fd = os.open(custody, _dir_open_flags())
        stage = custody / "held.aab"
        destination_fd = os.open(
            "held.aab",
            _open_flags(write=True, exclusive=True),
            0o400,
            dir_fd=directory_fd,
        )
        try:
            view = memoryview(data)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise SignerError("private held AAB write truncated")
                view = view[written:]
            os.fchmod(destination_fd, 0o400)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        os.fsync(directory_fd)
        held_fd = _openat_child(directory_fd, "held.aab", _open_flags())
        expected_file = _held_stat_identity(os.fstat(held_fd))
        expected_directory = _held_stat_identity(os.fstat(directory_fd))
        expected_digest = _sha256_bytes(data)
        try:
            if (
                stat.S_IMODE(os.fstat(held_fd).st_mode) != 0o400
                or _sha256_pread(held_fd, len(data), "private held AAB")
                != expected_digest
            ):
                raise SignerError("private held AAB custody is invalid")
            try:
                yield stage
            finally:
                named = os.stat("held.aab", dir_fd=directory_fd, follow_symlinks=False)
                path_directory = os.lstat(custody)
                if (
                    _held_stat_identity(os.fstat(held_fd)) != expected_file
                    or _held_stat_identity(named) != expected_file
                    or _held_stat_identity(os.fstat(directory_fd)) != expected_directory
                    or (path_directory.st_dev, path_directory.st_ino)
                    != (expected_directory[0], expected_directory[1])
                    or os.listdir(directory_fd) != ["held.aab"]
                    or _sha256_pread(held_fd, len(data), "private held AAB")
                    != expected_digest
                ):
                    raise SignerError("private held AAB custody changed")
        finally:
            os.close(held_fd)
            os.close(directory_fd)


def _held_stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_nlink),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _sha256_pread(descriptor: int, expected_size: int, label: str) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        block = os.pread(
            descriptor,
            min(HELD_AAB_READ_CHUNK, expected_size - offset),
            offset,
        )
        if not block:
            raise SignerError(f"{label} truncated during descriptor custody")
        digest.update(block)
        offset += len(block)
    if os.pread(descriptor, 1, offset):
        raise SignerError(f"{label} grew during descriptor custody")
    return digest.hexdigest()


def _custody_stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (*_held_stat_identity(info), int(getattr(info, "st_flags", 0)))


def _ancestor_directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(getattr(info, "st_flags", 0)),
    )


def _feed_tree_digest(digest: hashlib._Hash, *parts: object) -> None:
    for part in parts:
        value = str(part).encode("utf-8", "surrogateescape")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)


def _require_safe_ancestor(info: os.stat_result, label: str) -> None:
    """An ancestor may be owned by root or this user and writable only by its owner.

    A root-owned sticky directory (for example /private/tmp) is accepted: other
    users cannot rename or replace entries they do not own inside it, and the
    next component must still pass this check.
    """

    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or (mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX))
    ):
        raise SignerError(f"{label} ancestor is not a safe owner-writable-only directory")


def _require_safe_pinned_file(
    info: os.stat_result, label: str, *, executable: bool = False
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(info.st_mode) & 0o022
        or (executable and not stat.S_IMODE(info.st_mode) & 0o100)
    ):
        raise SignerError(
            f"{label} must be a regular single-link file owned by root or this user "
            "and not group or world writable"
        )


@contextmanager
def _retained_pinned_file(
    path: pathlib.Path,
    label: str,
    expected_sha256: str,
    *,
    executable: bool = False,
) -> Iterator[int]:
    """Retain one sha256-pinned file and every absolute-path ancestor.

    Every component is opened relative to its parent descriptor with
    O_NOFOLLOW, so no ancestor may be a symlink. The file must be a regular
    single-link file whose bytes, hashed through the retained descriptor,
    equal the pin. The chain and the bytes are checked again on exit.
    """

    if (
        not path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or "\x00" in str(path)
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        or expected_sha256 == "0" * 64
    ):
        raise SignerError(f"{label} path or sha256 pin is invalid")
    descriptors: list[int] = []
    identities: list[tuple[int, ...]] = []
    names: list[str] = []
    body_error: BaseException | None = None
    try:
        current = os.open(path.anchor, _dir_open_flags())
        descriptors.append(current)
        identities.append(_ancestor_directory_identity(os.fstat(current)))
        names.append(path.anchor)
        for index, part in enumerate(path.parts[1:]):
            is_file = index == len(path.parts[1:]) - 1
            try:
                child = _openat_child(
                    current,
                    part,
                    _open_flags() if is_file else _dir_open_flags(),
                )
            except SignerError as exc:
                raise SignerError(f"{label} is absent or unsafe at {path}: {exc}") from exc
            descriptors.append(child)
            identities.append(
                _custody_stat_identity(os.fstat(child))
                if is_file
                else _ancestor_directory_identity(os.fstat(child))
            )
            names.append(part)
            current = child
        for descriptor in descriptors[:-1]:
            _require_safe_ancestor(os.fstat(descriptor), label)
        file_info = os.fstat(descriptors[-1])
        _require_safe_pinned_file(file_info, label, executable=executable)
        if _sha256_pread(descriptors[-1], file_info.st_size, label) != expected_sha256:
            raise SignerError(f"{label} sha256 does not match the reviewed pin")
        try:
            yield descriptors[-1]
        except BaseException as exc:
            body_error = exc
            raise
        finally:
            for index, (descriptor, expected) in enumerate(
                zip(descriptors, identities)
            ):
                identity = (
                    _custody_stat_identity
                    if index == len(descriptors) - 1
                    else _ancestor_directory_identity
                )
                if identity(os.fstat(descriptor)) != expected:
                    raise SignerError(f"{label} descriptor custody changed") from body_error
                if index == 0:
                    named = os.lstat(path.anchor)
                else:
                    named = os.stat(
                        names[index],
                        dir_fd=descriptors[index - 1],
                        follow_symlinks=False,
                    )
                if identity(named) != expected:
                    raise SignerError(f"{label} path was substituted") from body_error
            current_info = os.fstat(descriptors[-1])
            if (
                _sha256_pread(descriptors[-1], current_info.st_size, label)
                != expected_sha256
            ):
                raise SignerError(f"{label} bytes changed") from body_error
    except FileNotFoundError as exc:
        raise SignerError(f"{label} is absent at {path}") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _release_host_key() -> str:
    system = {"darwin": "darwin", "linux": "linux"}.get(sys.platform)
    machine = {
        "arm64": "arm64",
        "aarch64": "arm64",
        "x86_64": "x86_64",
        "amd64": "x86_64",
    }.get(os.uname().machine.lower())
    if system is None or machine is None:
        raise SignerError("this release host has no reviewed toolchain pin")
    return f"{system}_{machine}"


def _toolchain_pins() -> dict[str, object]:
    label = "release toolchain pins"
    _digest, _size, payload = _hash_live_repo_file(TOOLCHAIN_PINS_RELATIVE, label)
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise SignerError(f"{label} must be UTF-8 JSON") from exc
    parsed = _strict_json_loads(text, label)
    tools = parsed.get("tools") if type(parsed) is dict else None
    if type(tools) is not dict:
        raise SignerError(f"{label} must contain one tools object")
    return tools


def _pinned_tool_section(tools: Mapping[str, object], name: str) -> Mapping[str, object]:
    section = tools.get(name)
    if type(section) is not dict:
        raise SignerError(f"release toolchain pins lack tools.{name}")
    return section


def _pinned_host_value(
    section: Mapping[str, object], field: str, host: str, label: str
) -> str:
    values = section.get(field)
    value = values.get(host) if type(values) is dict else None
    if type(value) is not str or not value or "\x00" in value:
        raise SignerError(f"release toolchain pins lack {label} {field} for {host}")
    return value


def _pinned_hex64(value: str, label: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None or value == "0" * 64:
        raise SignerError(f"{label} sha256 pin is not exact")
    return value


def _pinned_absolute_path(raw: str, label: str) -> pathlib.Path:
    if (
        type(raw) is not str
        or not raw
        or "\x00" in raw
        or not os.path.isabs(raw)
        or any(part in {".", ".."} for part in pathlib.PurePosixPath(raw).parts)
    ):
        raise SignerError(f"{label} must be one absolute normalized path")
    return pathlib.Path(raw)


def _pinned_python_identity() -> tuple[pathlib.Path, str]:
    tools = _toolchain_pins()
    host = _release_host_key()
    python = _pinned_tool_section(tools, "python")
    expected_version = ".".join(str(part) for part in RELEASE_PYTHON_VERSION)
    if python.get("version") != expected_version:
        raise SignerError("release toolchain pins do not name CPython 3.14.7")
    path = _pinned_absolute_path(
        _pinned_host_value(python, "reviewed_executable_path", host, "python"),
        "pinned release Python",
    )
    digest = _pinned_hex64(
        _pinned_host_value(python, "executable_sha256", host, "python"),
        "pinned release Python",
    )
    return path, digest


def _pinned_jdk_identity() -> dict[str, object]:
    """Resolve the pinned JDK root and its reviewed identity from the pins file."""

    tools = _toolchain_pins()
    host = _release_host_key()
    java = _pinned_tool_section(tools, "java")
    version = java.get("version")
    release_name = java.get("release_name")
    vendor = java.get("vendor")
    if (
        type(version) is not str
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version) is None
        or type(release_name) is not str
        or not release_name.startswith(f"jdk-{version}+")
        or type(vendor) is not str
        or not vendor
    ):
        raise SignerError("release toolchain pins do not name one exact JDK")
    tree_sha256 = _pinned_hex64(
        _pinned_host_value(java, "install_tree_sha256", host, "java"),
        "pinned JDK tree",
    )
    if tree_sha256 != OWNER_JDK_TREE_SHA256:
        raise SignerError("pinned JDK tree sha256 disagrees with the verifier pin")
    configured = os.environ.get(JDK_ROOT_ENV, "")
    if configured:
        root = _pinned_absolute_path(configured, JDK_ROOT_ENV)
    else:
        root = pathlib.Path.home() / ".local" / "toolchains" / f"jdk-{version}"
        root = _pinned_absolute_path(str(root), "default pinned JDK root")
    return {
        "root": root,
        "tree_sha256": tree_sha256,
        "version": version,
        "runtime_version": release_name[len("jdk-") :],
        "vendor": vendor,
    }


def _pinned_android_sdk_root() -> pathlib.Path:
    for name in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        configured = os.environ.get(name, "")
        if configured:
            return _pinned_absolute_path(configured, name)
    return _pinned_absolute_path(
        str(pathlib.Path.home() / ".local" / "android-sdk"), "default Android SDK root"
    )


def _pinned_apksigner_jar() -> pathlib.Path:
    return _pinned_android_sdk_root().joinpath(*APKSIGNER_JAR_RELATIVE)


@contextmanager
def _pinned_release_python_runtime() -> Iterator[None]:
    """Require the sha256-pinned CPython 3.14.7 started with -I -S."""

    if (
        tuple(sys.version_info[:3]) != RELEASE_PYTHON_VERSION
        or not sys.flags.isolated
        or not sys.flags.no_site
    ):
        raise SignerError(
            "pinned release Python 3.14.7 started with -I -S is required before authority"
        )
    path, digest = _pinned_python_identity()
    if pathlib.Path(sys.executable) != path:
        raise SignerError(
            f"pinned release Python 3.14.7 must run from its reviewed path {path}"
        )
    with _retained_pinned_file(
        path, "pinned release Python 3.14.7", digest, executable=True
    ):
        yield


class _HeldAndroidVerificationTools:
    """Retain the sha256-pinned JDK closure and a private bundletool image."""

    def __init__(self, *, bind_bundletool: bool = True) -> None:
        self._bind_bundletool = bind_bundletool
        self._jdk_root: pathlib.Path | None = None
        self._jdk_tree_sha256 = ""
        self._chain: list[tuple[int, tuple[int, ...], str]] = []
        self._directories: dict[str, tuple[int, tuple[int, ...]]] = {}
        self._tool_fds: dict[str, tuple[int, tuple[int, ...]]] = {}
        self._tree_inventory: dict[str, tuple[int, ...]] = {}
        self._private_jdk_path: pathlib.Path | None = None
        self._private_jdk_fd = -1
        self._private_jdk_stat: tuple[int, ...] | None = None
        self._private_jdk_inventory: dict[str, tuple[int, ...]] = {}
        self._private_tool_fds: dict[str, tuple[int, tuple[int, ...]]] = {}
        self._bundle_source_fd = -1
        self._bundle_source_path: pathlib.Path | None = None
        self._bundle_source_chain: list[tuple[int, tuple[int, ...], str]] = []
        self._bundle_snapshot_fd = -1
        self._bundle_directory_fd = -1
        self._bundle_directory_path: pathlib.Path | None = None
        self._bundle_source_stat: tuple[int, ...] | None = None
        self._bundle_snapshot_stat: tuple[int, ...] | None = None
        self._bundle_directory_stat: tuple[int, ...] | None = None
        self._token: contextvars.Token[_HeldAndroidVerificationTools | None] | None = None

    @property
    def jdk_root(self) -> pathlib.Path:
        if not self._tool_fds or self._jdk_root is None:
            raise SignerError("reviewed Android JDK custody is not active")
        return self._jdk_root

    @property
    def jdk_tools(self) -> tuple[str, str, str]:
        root = self.jdk_root
        return tuple(
            str(root / "bin" / name)
            for name in ("java", "jarsigner", "keytool")
        )

    def jdk_tool_fd(self, name: str) -> int:
        bound = self._tool_fds.get(name)
        if bound is None:
            raise SignerError(f"reviewed Android JDK {name} custody is not active")
        return bound[0]

    @property
    def bundletool_path(self) -> pathlib.Path:
        # The JVM cannot load classes from a /dev/fd/N class-path entry on
        # macOS, so java -jar receives the private snapshot's real path. The
        # snapshot directory is private (0o500) and holds exactly that file,
        # whose name, identity, and bytes revalidate() checks before and after
        # every tool run.
        if self._bundle_snapshot_fd < 0 or self._bundle_directory_path is None:
            raise SignerError("held bundletool custody is not active")
        return self._bundle_directory_path / BUNDLETOOL_SNAPSHOT_NAME

    @property
    def pass_fds(self) -> tuple[int, ...]:
        descriptors = [fd for fd, _identity in self._tool_fds.values()]
        if self._bundle_snapshot_fd >= 0:
            descriptors.append(self._bundle_snapshot_fd)
        return tuple(dict.fromkeys(descriptors))

    @staticmethod
    def _require_root_directory(info: os.stat_result, label: str) -> None:
        _require_safe_ancestor(info, f"pinned Android JDK path component {label}")

    @staticmethod
    def _require_sealed_entry(
        info: os.stat_result, label: str, *, directory: bool
    ) -> None:
        if (
            (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or info.st_uid not in {0, os.geteuid()}
            or (not directory and info.st_nlink != 1)
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise SignerError(
                "pinned Android JDK entry must be a regular single-link file or "
                "directory owned by root or this user and not group or world "
                f"writable: {label}"
            )

    def _open_chain(self) -> None:
        if self._jdk_root is None:
            raise SignerError("pinned Android JDK root is not resolved")
        jdk_root = self._jdk_root
        current_fd = os.open(jdk_root.anchor, _dir_open_flags())
        try:
            current_info = os.fstat(current_fd)
            self._require_root_directory(current_info, jdk_root.anchor)
            self._chain.append(
                (current_fd, _ancestor_directory_identity(current_info), jdk_root.anchor)
            )
            current_fd = -1
            for part in jdk_root.parts[1:]:
                parent_fd = self._chain[-1][0]
                child_fd = _openat_child(parent_fd, part, _dir_open_flags())
                child_info = os.fstat(child_fd)
                self._require_root_directory(child_info, part)
                self._chain.append(
                    (child_fd, _ancestor_directory_identity(child_info), part)
                )
            root_fd, _root_ancestor_identity, _label = self._chain[-1]
            root_info = os.fstat(root_fd)
            self._require_sealed_entry(root_info, ".", directory=True)
            self._directories[""] = (root_fd, _custody_stat_identity(root_info))
        except BaseException:
            if current_fd >= 0:
                os.close(current_fd)
            raise

    def _scan_directory(
        self,
        relative: str,
        directory_fd: int,
        digest: hashlib._Hash,
        inventory: dict[str, tuple[int, ...]],
        *,
        retain_directories: bool,
    ) -> None:
        try:
            names = sorted(os.listdir(directory_fd), key=os.fsencode)
        except OSError as exc:
            raise SignerError("pinned Android JDK tree is unreadable") from exc
        for name in names:
            if name in {"", ".", ".."} or "/" in name or "\x00" in name:
                raise SignerError("pinned Android JDK entry is malformed")
            child_relative = f"{relative}/{name}" if relative else name
            try:
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise SignerError(
                    f"pinned Android JDK entry disappeared: {child_relative}"
                ) from exc
            if stat.S_ISLNK(named.st_mode):
                raise SignerError(
                    f"pinned Android JDK closure contains a symlink: "
                    f"{child_relative}"
                )
            if stat.S_ISDIR(named.st_mode):
                self._require_sealed_entry(named, child_relative, directory=True)
                child_fd = _openat_child(directory_fd, name, _dir_open_flags())
                opened = os.fstat(child_fd)
                if _custody_stat_identity(opened) != _custody_stat_identity(named):
                    os.close(child_fd)
                    raise SignerError("reviewed Android JDK directory changed while opening")
                identity = _custody_stat_identity(opened)
                inventory[child_relative] = identity
                _feed_tree_digest(digest, "D", child_relative, 0o500)
                if retain_directories:
                    self._directories[child_relative] = (child_fd, identity)
                try:
                    self._scan_directory(
                        child_relative,
                        child_fd,
                        digest,
                        inventory,
                        retain_directories=retain_directories,
                    )
                finally:
                    if not retain_directories:
                        os.close(child_fd)
            elif stat.S_ISREG(named.st_mode):
                self._require_sealed_entry(named, child_relative, directory=False)
                child_fd = _openat_child(directory_fd, name, _open_flags())
                try:
                    opened = os.fstat(child_fd)
                    identity = _custody_stat_identity(opened)
                    if identity != _custody_stat_identity(named):
                        raise SignerError("reviewed Android JDK file changed while opening")
                    content = _sha256_pread(
                        child_fd, opened.st_size, f"reviewed Android JDK {child_relative}"
                    )
                    inventory[child_relative] = identity
                    canonical_mode = (
                        0o500 if stat.S_IMODE(opened.st_mode) & 0o111 else 0o400
                    )
                    _feed_tree_digest(
                        digest,
                        "F",
                        child_relative,
                        canonical_mode,
                        opened.st_size,
                        content,
                    )
                    tool_name = pathlib.PurePosixPath(child_relative).name
                    if child_relative == f"bin/{tool_name}" and tool_name in OWNER_JDK_TOOL_SHA256:
                        if content != OWNER_JDK_TOOL_SHA256[tool_name]:
                            raise SignerError(
                                f"pinned Android JDK {tool_name} sha256 does not match the pin"
                            )
                        if retain_directories:
                            self._tool_fds[tool_name] = (child_fd, identity)
                            child_fd = -1
                finally:
                    if child_fd >= 0:
                        os.close(child_fd)
            else:
                raise SignerError(
                    f"pinned Android JDK closure contains a special file: "
                    f"{child_relative}"
                )

    def _tree_state(
        self, *, retain_directories: bool
    ) -> tuple[str, dict[str, tuple[int, ...]]]:
        root_fd = self._directories[""][0]
        digest = hashlib.sha256()
        inventory: dict[str, tuple[int, ...]] = {}
        self._scan_directory(
            "",
            root_fd,
            digest,
            inventory,
            retain_directories=retain_directories,
        )
        return digest.hexdigest(), inventory

    def _require_release_identity(self, identity: Mapping[str, object]) -> None:
        """Bind the JDK release file to the pinned version, build, and vendor."""

        root_fd = self._directories[""][0]
        release_fd = _openat_child(root_fd, "release", _open_flags())
        try:
            info = os.fstat(release_fd)
            if info.st_size <= 0 or info.st_size > MAX_JDK_RELEASE_FILE_BYTES:
                raise SignerError("pinned Android JDK release file size is not exact")
            payload = os.pread(release_fd, info.st_size, 0)
        finally:
            os.close(release_fd)
        try:
            text = payload.decode("utf-8")
        except UnicodeError as exc:
            raise SignerError("pinned Android JDK release file is not UTF-8") from exc
        fields: dict[str, str] = {}
        for line in text.splitlines():
            match = re.fullmatch(r'([A-Z_][A-Z0-9_]*)="([^"\n]*)"', line.strip())
            if match is None:
                continue
            if match.group(1) in fields:
                raise SignerError("pinned Android JDK release file repeats a key")
            fields[match.group(1)] = match.group(2)
        if (
            fields.get("JAVA_VERSION") != identity["version"]
            or fields.get("JAVA_RUNTIME_VERSION") != identity["runtime_version"]
            or fields.get("IMPLEMENTOR") != identity["vendor"]
        ):
            raise SignerError(
                "pinned Android JDK release file does not report the pinned "
                "JAVA_VERSION, JAVA_RUNTIME_VERSION, and IMPLEMENTOR"
            )

    def _bind_jdk(self) -> None:
        identity = _pinned_jdk_identity()
        root = identity["root"]
        if not isinstance(root, pathlib.Path):
            raise SignerError("pinned Android JDK root is not resolved")
        self._jdk_root = root
        self._jdk_tree_sha256 = str(identity["tree_sha256"])
        try:
            self._open_chain()
        except (FileNotFoundError, SignerError) as exc:
            raise SignerError(
                f"pinned Android JDK is absent or unsafe at {root}: {exc}"
            ) from exc
        observed, inventory = self._tree_state(retain_directories=True)
        if observed != self._jdk_tree_sha256:
            raise SignerError(
                "pinned Android JDK install tree sha256 does not match the pin"
            )
        if set(self._tool_fds) != set(OWNER_JDK_TOOL_SHA256):
            raise SignerError("pinned Android JDK tools are incomplete")
        self._require_release_identity(identity)
        self._tree_inventory = inventory

    def _copy_jdk_directory(
        self,
        source_fd: int,
        destination_fd: int,
        relative: str,
        digest: hashlib._Hash,
        inventory: dict[str, tuple[int, ...]],
    ) -> None:
        for name in sorted(os.listdir(source_fd), key=os.fsencode):
            child_relative = f"{relative}/{name}" if relative else name
            source_named = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if _custody_stat_identity(source_named) != self._tree_inventory.get(
                child_relative
            ):
                raise SignerError("reviewed Android JDK changed before private copy")
            if stat.S_ISDIR(source_named.st_mode):
                os.mkdir(name, 0o700, dir_fd=destination_fd)
                source_child = _openat_child(source_fd, name, _dir_open_flags())
                destination_child = _openat_child(
                    destination_fd, name, _dir_open_flags()
                )
                try:
                    if _custody_stat_identity(os.fstat(source_child)) != self._tree_inventory[
                        child_relative
                    ]:
                        raise SignerError("reviewed Android JDK directory changed during copy")
                    destination_info = os.fstat(destination_child)
                    if stat.S_IMODE(destination_info.st_mode) != 0o700:
                        raise SignerError("private Android JDK directory mode is not exact")
                    _feed_tree_digest(digest, "D", child_relative, 0o500)
                    self._copy_jdk_directory(
                        source_child,
                        destination_child,
                        child_relative,
                        digest,
                        inventory,
                    )
                    os.fsync(destination_child)
                    inventory[child_relative] = _held_stat_identity(
                        os.fstat(destination_child)
                    )
                finally:
                    os.close(destination_child)
                    os.close(source_child)
                continue
            if not stat.S_ISREG(source_named.st_mode):
                raise SignerError("reviewed Android JDK contains an unsafe copy input")
            source_child = _openat_child(source_fd, name, _open_flags())
            private_mode = 0o500 if stat.S_IMODE(source_named.st_mode) & 0o111 else 0o400
            destination_child = os.open(
                name,
                _open_flags(write=True, exclusive=True),
                private_mode,
                dir_fd=destination_fd,
            )
            try:
                source_info = os.fstat(source_child)
                if _custody_stat_identity(source_info) != self._tree_inventory[child_relative]:
                    raise SignerError("reviewed Android JDK file changed during copy")
                source_digest = hashlib.sha256()
                offset = 0
                while offset < source_info.st_size:
                    block = os.pread(
                        source_child,
                        min(HELD_AAB_READ_CHUNK, source_info.st_size - offset),
                        offset,
                    )
                    if not block:
                        raise SignerError("reviewed Android JDK file truncated during copy")
                    source_digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(destination_child, view)
                        if written <= 0:
                            raise SignerError("private Android JDK file write truncated")
                        view = view[written:]
                    offset += len(block)
                if os.pread(source_child, 1, offset):
                    raise SignerError("reviewed Android JDK file grew during copy")
                os.fchmod(destination_child, private_mode)
                os.fsync(destination_child)
                destination_info = os.fstat(destination_child)
                content_digest = source_digest.hexdigest()
                if (
                    _custody_stat_identity(os.fstat(source_child))
                    != self._tree_inventory[child_relative]
                    or not stat.S_ISREG(destination_info.st_mode)
                    or destination_info.st_nlink != 1
                    or destination_info.st_uid != os.geteuid()
                    or stat.S_IMODE(destination_info.st_mode) != private_mode
                    or destination_info.st_size != source_info.st_size
                    or _sha256_pread(
                        destination_child,
                        destination_info.st_size,
                        f"private Android JDK {child_relative}",
                    )
                    != content_digest
                ):
                    raise SignerError("private Android JDK file custody is invalid")
                inventory[child_relative] = _held_stat_identity(destination_info)
                _feed_tree_digest(
                    digest,
                    "F",
                    child_relative,
                    private_mode,
                    destination_info.st_size,
                    content_digest,
                )
            finally:
                os.close(destination_child)
                os.close(source_child)

    def _private_tree_state(self) -> tuple[str, dict[str, tuple[int, ...]]]:
        if self._private_jdk_fd < 0:
            raise SignerError("private Android JDK custody is not active")
        digest = hashlib.sha256()
        inventory: dict[str, tuple[int, ...]] = {}

        def scan(directory_fd: int, relative: str) -> None:
            for name in sorted(os.listdir(directory_fd), key=os.fsencode):
                child_relative = f"{relative}/{name}" if relative else name
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(named.st_mode):
                    raise SignerError("private Android JDK contains a symlink")
                if stat.S_ISDIR(named.st_mode):
                    child = _openat_child(directory_fd, name, _dir_open_flags())
                    try:
                        opened = os.fstat(child)
                        if (
                            _held_stat_identity(opened) != _held_stat_identity(named)
                            or opened.st_uid != os.geteuid()
                            or stat.S_IMODE(opened.st_mode) != 0o700
                        ):
                            raise SignerError("private Android JDK directory custody changed")
                        inventory[child_relative] = _held_stat_identity(opened)
                        _feed_tree_digest(digest, "D", child_relative, 0o500)
                        scan(child, child_relative)
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
                    raise SignerError("private Android JDK contains a special file")
                mode = stat.S_IMODE(named.st_mode)
                if mode not in {0o400, 0o500} or named.st_uid != os.geteuid():
                    raise SignerError("private Android JDK file mode is not exact")
                child = _openat_child(directory_fd, name, _open_flags())
                try:
                    opened = os.fstat(child)
                    if _held_stat_identity(opened) != _held_stat_identity(named):
                        raise SignerError("private Android JDK file custody changed")
                    content = _sha256_pread(
                        child, opened.st_size, f"private Android JDK {child_relative}"
                    )
                    inventory[child_relative] = _held_stat_identity(opened)
                    _feed_tree_digest(
                        digest,
                        "F",
                        child_relative,
                        mode,
                        opened.st_size,
                        content,
                    )
                finally:
                    os.close(child)

        scan(self._private_jdk_fd, "")
        return digest.hexdigest(), inventory

    def _bind_private_jdk(self) -> None:
        self._private_jdk_path = pathlib.Path(
            tempfile.mkdtemp(prefix=HELD_TOOL_SNAPSHOT_PREFIX + "jdk-")
        )
        os.chmod(self._private_jdk_path, 0o700)
        self._private_jdk_fd = os.open(self._private_jdk_path, _dir_open_flags())
        root_info = os.fstat(self._private_jdk_fd)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.geteuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise SignerError("private Android JDK directory custody is invalid")
        digest = hashlib.sha256()
        copied_inventory: dict[str, tuple[int, ...]] = {}
        self._copy_jdk_directory(
            self._directories[""][0],
            self._private_jdk_fd,
            "",
            digest,
            copied_inventory,
        )
        os.fsync(self._private_jdk_fd)
        self._private_jdk_stat = _held_stat_identity(os.fstat(self._private_jdk_fd))
        observed_source, source_inventory = self._tree_state(retain_directories=False)
        observed_private, private_inventory = self._private_tree_state()
        if (
            digest.hexdigest() != self._jdk_tree_sha256
            or observed_source != self._jdk_tree_sha256
            or source_inventory != self._tree_inventory
            or observed_private != self._jdk_tree_sha256
            or private_inventory != copied_inventory
        ):
            raise SignerError("private Android JDK support-tree copy is not exact")
        self._private_jdk_inventory = private_inventory
        bin_fd = _openat_child(self._private_jdk_fd, "bin", _dir_open_flags())
        try:
            for name, expected_digest in OWNER_JDK_TOOL_SHA256.items():
                descriptor = _openat_child(bin_fd, name, _open_flags())
                info = os.fstat(descriptor)
                if (
                    stat.S_IMODE(info.st_mode) != 0o500
                    or _sha256_pread(
                        descriptor, info.st_size, f"private Android JDK {name}"
                    )
                    != expected_digest
                ):
                    os.close(descriptor)
                    raise SignerError(f"private Android JDK {name} is not exact")
                self._private_tool_fds[name] = (
                    descriptor,
                    _held_stat_identity(info),
                )
        finally:
            os.close(bin_fd)

    def _bind_bundletool_image(self) -> None:
        configured = os.environ.get(BUNDLETOOL_ENV, "").strip()
        if not configured or "\x00" in configured:
            raise SignerError(
                f"{BUNDLETOOL_ENV} must name the exact bundletool-all-{BUNDLETOOL_VERSION}.jar"
            )
        source = pathlib.Path(configured)
        if not source.is_absolute():
            raise SignerError(f"{BUNDLETOOL_ENV} must be one absolute path")
        try:
            source = source.resolve(strict=True)
        except OSError as exc:
            raise SignerError("reviewed bundletool source path is unreadable") from exc
        self._bundle_source_path = source
        current_fd = os.open(source.anchor, _dir_open_flags())
        current_info = os.fstat(current_fd)
        self._bundle_source_chain.append(
            (current_fd, _ancestor_directory_identity(current_info), source.anchor)
        )
        try:
            for part in source.parts[1:-1]:
                child_fd = _openat_child(current_fd, part, _dir_open_flags())
                child_info = os.fstat(child_fd)
                self._bundle_source_chain.append(
                    (child_fd, _ancestor_directory_identity(child_info), part)
                )
                current_fd = child_fd
            source_fd = _openat_child(current_fd, source.name, _open_flags())
        except BaseException:
            raise
        self._bundle_source_fd = source_fd
        source_info = os.fstat(source_fd)
        if (
            not stat.S_ISREG(source_info.st_mode)
            or source_info.st_nlink != 1
            or source_info.st_size <= 0
            or source_info.st_size > MAX_BUNDLETOOL_BYTES
            or stat.S_IMODE(source_info.st_mode) & 0o022
        ):
            raise SignerError("reviewed bundletool source custody is unsafe")
        self._bundle_source_stat = _custody_stat_identity(source_info)
        if (
            _sha256_pread(source_fd, source_info.st_size, "reviewed bundletool source")
            != BUNDLETOOL_ALL_SHA256
        ):
            raise SignerError(
                f"bundletool-all-{BUNDLETOOL_VERSION}.jar SHA-256 does not match the reviewed pin"
            )
        self._bundle_directory_path = pathlib.Path(
            tempfile.mkdtemp(prefix=HELD_TOOL_SNAPSHOT_PREFIX)
        )
        os.chmod(self._bundle_directory_path, 0o700)
        self._bundle_directory_fd = os.open(
            self._bundle_directory_path, _dir_open_flags()
        )
        directory_info = os.fstat(self._bundle_directory_fd)
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or stat.S_IMODE(directory_info.st_mode) != 0o700
            or directory_info.st_uid != os.geteuid()
        ):
            raise SignerError("private bundletool directory custody is invalid")
        writer = os.open(
            "bundletool.jar",
            _open_flags(write=True, exclusive=True),
            0o400,
            dir_fd=self._bundle_directory_fd,
        )
        try:
            offset = 0
            while offset < source_info.st_size:
                block = os.pread(
                    source_fd,
                    min(HELD_AAB_READ_CHUNK, source_info.st_size - offset),
                    offset,
                )
                if not block:
                    raise SignerError("reviewed bundletool source truncated during snapshot")
                view = memoryview(block)
                while view:
                    written = os.write(writer, view)
                    if written <= 0:
                        raise SignerError("private bundletool snapshot write truncated")
                    view = view[written:]
                offset += len(block)
            os.fchmod(writer, 0o400)
            os.fsync(writer)
        finally:
            os.close(writer)
        os.fsync(self._bundle_directory_fd)
        self._bundle_directory_stat = _custody_stat_identity(
            os.fstat(self._bundle_directory_fd)
        )
        self._bundle_snapshot_fd = _openat_child(
            self._bundle_directory_fd, "bundletool.jar", _open_flags()
        )
        snapshot_info = os.fstat(self._bundle_snapshot_fd)
        if (
            not stat.S_ISREG(snapshot_info.st_mode)
            or snapshot_info.st_nlink != 1
            or snapshot_info.st_size != source_info.st_size
            or stat.S_IMODE(snapshot_info.st_mode) != 0o400
            or _sha256_pread(
                self._bundle_snapshot_fd,
                snapshot_info.st_size,
                "private bundletool snapshot",
            )
            != BUNDLETOOL_ALL_SHA256
        ):
            raise SignerError("private bundletool snapshot custody is invalid")
        os.fchmod(self._bundle_directory_fd, 0o500)
        self._bundle_snapshot_stat = _custody_stat_identity(
            os.fstat(self._bundle_snapshot_fd)
        )
        self._bundle_directory_stat = _custody_stat_identity(
            os.fstat(self._bundle_directory_fd)
        )

    def __enter__(self) -> _HeldAndroidVerificationTools:
        try:
            self._bind_jdk()
            if self._bind_bundletool:
                self._bind_bundletool_image()
            self._token = _ACTIVE_ANDROID_TOOLS.set(self)
            self.revalidate(full_tree=True)
            return self
        except BaseException:
            self.close()
            raise

    def revalidate(self, *, full_tree: bool = False) -> None:
        del full_tree
        if not self._directories or not self._tool_fds or self._jdk_root is None:
            raise SignerError("reviewed Android verification tool custody is not active")
        # Ancestors are bound by (dev, inode, mode, owner, flags); entries other
        # processes add next to the JDK (for example in $HOME) do not matter,
        # a substituted or re-permissioned ancestor does.
        for fd, expected, label in self._chain:
            if _ancestor_directory_identity(os.fstat(fd)) != expected:
                raise SignerError(f"reviewed Android JDK ancestor changed: {label}")
        if _ancestor_directory_identity(os.lstat(self._jdk_root.anchor)) != self._chain[0][1]:
            raise SignerError("reviewed Android JDK root path was substituted")
        for index in range(1, len(self._chain)):
            parent_fd = self._chain[index - 1][0]
            _fd, expected, name = self._chain[index]
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if _ancestor_directory_identity(named) != expected:
                raise SignerError(f"reviewed Android JDK path was substituted: {name}")
        for relative, (fd, expected) in self._directories.items():
            if _custody_stat_identity(os.fstat(fd)) != expected:
                raise SignerError(f"reviewed Android JDK directory changed: {relative or '.'}")
        for name, (fd, expected) in self._tool_fds.items():
            info = os.fstat(fd)
            if (
                _custody_stat_identity(info) != expected
                or _sha256_pread(fd, info.st_size, f"reviewed Android JDK {name}")
                != OWNER_JDK_TOOL_SHA256[name]
            ):
                raise SignerError(f"reviewed Android JDK {name} changed")
        observed, inventory = self._tree_state(retain_directories=False)
        if observed != self._jdk_tree_sha256 or inventory != self._tree_inventory:
            raise SignerError("reviewed Android JDK support-tree custody changed")
        if self._bundle_source_fd >= 0:
            source = os.fstat(self._bundle_source_fd)
            snapshot = os.fstat(self._bundle_snapshot_fd)
            directory = os.fstat(self._bundle_directory_fd)
            if self._bundle_source_path is None or self._bundle_directory_path is None:
                raise SignerError("reviewed bundletool path custody is not active")
            for index, (fd, expected, name) in enumerate(self._bundle_source_chain):
                if _ancestor_directory_identity(os.fstat(fd)) != expected:
                    raise SignerError("reviewed bundletool ancestor changed")
                if index == 0:
                    path_info = os.lstat(self._bundle_source_path.anchor)
                else:
                    path_info = os.stat(
                        name,
                        dir_fd=self._bundle_source_chain[index - 1][0],
                        follow_symlinks=False,
                    )
                if _ancestor_directory_identity(path_info) != expected:
                    raise SignerError("reviewed bundletool path was substituted")
            source_named = os.stat(
                self._bundle_source_path.name,
                dir_fd=self._bundle_source_chain[-1][0],
                follow_symlinks=False,
            )
            private_directory_named = os.lstat(self._bundle_directory_path)
            if (
                _custody_stat_identity(source) != self._bundle_source_stat
                or _custody_stat_identity(source_named) != self._bundle_source_stat
                or _custody_stat_identity(snapshot) != self._bundle_snapshot_stat
                or _custody_stat_identity(directory) != self._bundle_directory_stat
                or (private_directory_named.st_dev, private_directory_named.st_ino)
                != (self._bundle_directory_stat[0], self._bundle_directory_stat[1])
                or os.listdir(self._bundle_directory_fd) != [BUNDLETOOL_SNAPSHOT_NAME]
                or _custody_stat_identity(
                    os.stat(
                        BUNDLETOOL_SNAPSHOT_NAME,
                        dir_fd=self._bundle_directory_fd,
                        follow_symlinks=False,
                    )
                )
                != self._bundle_snapshot_stat
                or _sha256_pread(
                    self._bundle_source_fd,
                    source.st_size,
                    "reviewed bundletool source",
                )
                != BUNDLETOOL_ALL_SHA256
                or _sha256_pread(
                    self._bundle_snapshot_fd,
                    snapshot.st_size,
                    "private bundletool snapshot",
                )
                != BUNDLETOOL_ALL_SHA256
            ):
                raise SignerError("reviewed bundletool custody changed")

    @staticmethod
    def _clear_private_directory(directory_fd: int) -> None:
        for name in os.listdir(directory_fd):
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = _openat_child(directory_fd, name, _dir_open_flags())
                try:
                    _HeldAndroidVerificationTools._clear_private_directory(child)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=directory_fd)
            elif stat.S_ISREG(info.st_mode):
                os.unlink(name, dir_fd=directory_fd)
            else:
                raise SignerError("private Android tool custody contains a special file")
        os.fsync(directory_fd)

    def close(self) -> None:
        cleanup_error: BaseException | None = None
        if self._token is not None:
            try:
                _ACTIVE_ANDROID_TOOLS.reset(self._token)
            except BaseException as exc:
                cleanup_error = exc
            self._token = None
        for descriptor in (
            self._bundle_snapshot_fd,
            self._bundle_source_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    cleanup_error = cleanup_error or exc
        self._bundle_snapshot_fd = -1
        self._bundle_source_fd = -1
        if self._bundle_directory_fd >= 0:
            try:
                os.fchmod(self._bundle_directory_fd, 0o700)
                try:
                    os.unlink(BUNDLETOOL_SNAPSHOT_NAME, dir_fd=self._bundle_directory_fd)
                except FileNotFoundError:
                    pass
                os.fsync(self._bundle_directory_fd)
            except (OSError, SignerError) as exc:
                cleanup_error = cleanup_error or exc
            try:
                os.close(self._bundle_directory_fd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
            self._bundle_directory_fd = -1
        if self._bundle_directory_path is not None:
            try:
                path_info = os.lstat(self._bundle_directory_path)
                if (
                    self._bundle_directory_stat is not None
                    and (path_info.st_dev, path_info.st_ino)
                    != (self._bundle_directory_stat[0], self._bundle_directory_stat[1])
                ):
                    raise SignerError("private bundletool directory path was substituted")
                os.rmdir(self._bundle_directory_path)
            except FileNotFoundError:
                pass
            except (OSError, SignerError) as exc:
                cleanup_error = cleanup_error or exc
            self._bundle_directory_path = None
        for fd, _expected, _name in reversed(self._bundle_source_chain):
            try:
                os.close(fd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        self._bundle_source_chain.clear()
        self._bundle_source_path = None
        for fd, _expected in self._private_tool_fds.values():
            try:
                os.close(fd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        self._private_tool_fds.clear()
        private_path_matches = False
        if self._private_jdk_path is not None and self._private_jdk_stat is not None:
            try:
                path_info = os.lstat(self._private_jdk_path)
                private_path_matches = (path_info.st_dev, path_info.st_ino) == (
                    self._private_jdk_stat[0],
                    self._private_jdk_stat[1],
                )
                if not private_path_matches:
                    raise SignerError("private Android JDK directory path was substituted")
                if self._private_jdk_fd >= 0:
                    self._clear_private_directory(self._private_jdk_fd)
            except (OSError, SignerError) as exc:
                cleanup_error = cleanup_error or exc
        if self._private_jdk_fd >= 0:
            try:
                os.close(self._private_jdk_fd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
            self._private_jdk_fd = -1
        if self._private_jdk_path is not None and private_path_matches:
            try:
                os.rmdir(self._private_jdk_path)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
        self._private_jdk_path = None
        self._private_jdk_stat = None
        self._private_jdk_inventory.clear()
        closed: set[int] = set()
        for fd, _expected in [*self._tool_fds.values(), *self._directories.values()]:
            if fd not in closed and all(fd != chain_fd for chain_fd, _identity, _label in self._chain):
                try:
                    os.close(fd)
                except OSError as exc:
                    cleanup_error = cleanup_error or exc
                closed.add(fd)
        for fd, _identity, _label in reversed(self._chain):
            if fd not in closed:
                try:
                    os.close(fd)
                except OSError as exc:
                    cleanup_error = cleanup_error or exc
                closed.add(fd)
        self._tool_fds.clear()
        self._directories.clear()
        self._chain.clear()
        if cleanup_error is not None:
            raise SignerError("reviewed Android verification tool cleanup failed") from cleanup_error

    def __exit__(self, exc_type, exc, traceback) -> bool:
        custody_error: BaseException | None = None
        try:
            self.revalidate(full_tree=True)
        except BaseException as failure:
            custody_error = failure
        try:
            self.close()
        except BaseException as cleanup_error:
            if custody_error is None:
                custody_error = cleanup_error
        if custody_error is not None:
            if exc is not None:
                raise custody_error from exc
            raise custody_error
        return False


class _HeldAabArtifact:
    def __init__(
        self,
        *,
        source_fd: int,
        expected_identity: tuple[int, int],
        expected_size: int,
        expected_sha256: str,
    ) -> None:
        self._caller_fd = source_fd
        self._source_fd = -1
        self._directory_fd = -1
        self._snapshot_fd = -1
        self._directory_path: pathlib.Path | None = None
        self._expected_identity = expected_identity
        self._expected_size = expected_size
        self._expected_sha256 = expected_sha256
        self.payload = b""
        self._source_stat: tuple[int, ...] | None = None
        self._directory_stat: tuple[int, ...] | None = None
        self._snapshot_stat: tuple[int, ...] | None = None

    @property
    def pass_fds(self) -> tuple[int, ...]:
        if self._snapshot_fd < 0:
            raise SignerError("held Android AAB snapshot is closed")
        return (self._snapshot_fd,)

    @property
    def tool_path(self) -> pathlib.Path:
        if self._snapshot_fd < 0:
            raise SignerError("held Android AAB snapshot is closed")
        return pathlib.Path(f"/dev/fd/{self._snapshot_fd}")

    def _validate_arguments(self) -> None:
        if os.name == "nt":
            raise SignerError("held Android AAB validation requires POSIX descriptors")
        if type(self._caller_fd) is not int or self._caller_fd < 0:
            raise SignerError("held Android AAB source descriptor is invalid")
        if (
            type(self._expected_identity) is not tuple
            or len(self._expected_identity) != 2
            or any(type(value) is not int or value < 0 for value in self._expected_identity)
        ):
            raise SignerError("held Android AAB expected descriptor identity is invalid")
        if (
            type(self._expected_size) is not int
            or isinstance(self._expected_size, bool)
            or self._expected_size <= 0
            or self._expected_size > MAX_HELD_AAB_BYTES
        ):
            raise SignerError("held Android AAB expected size is invalid or exceeds the bound")
        if (
            type(self._expected_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self._expected_sha256) is None
        ):
            raise SignerError("held Android AAB expected SHA-256 is invalid")

    def __enter__(self) -> _HeldAabArtifact:
        self._validate_arguments()
        try:
            caller_info = os.fstat(self._caller_fd)
            if (
                not stat.S_ISREG(caller_info.st_mode)
                or caller_info.st_nlink != 1
                or caller_info.st_size != self._expected_size
                or (caller_info.st_dev, caller_info.st_ino) != self._expected_identity
                or stat.S_IMODE(caller_info.st_mode) & 0o022
                or fcntl.fcntl(self._caller_fd, fcntl.F_GETFL) & os.O_ACCMODE
                != os.O_RDONLY
            ):
                raise SignerError("held Android AAB source descriptor identity is not exact")
            self._source_fd = os.dup(self._caller_fd)
            os.set_inheritable(self._source_fd, False)
            source_info = os.fstat(self._source_fd)
            if _held_stat_identity(source_info) != _held_stat_identity(caller_info):
                raise SignerError("held Android AAB source descriptor changed during binding")
            self._source_stat = _held_stat_identity(source_info)

            self._directory_path = pathlib.Path(
                tempfile.mkdtemp(prefix=HELD_AAB_SNAPSHOT_PREFIX)
            )
            os.chmod(self._directory_path, 0o700)
            self._directory_fd = os.open(self._directory_path, _dir_open_flags())
            directory_info = os.fstat(self._directory_fd)
            if (
                not stat.S_ISDIR(directory_info.st_mode)
                or stat.S_IMODE(directory_info.st_mode) != 0o700
                or directory_info.st_uid != os.geteuid()
            ):
                raise SignerError("held Android AAB private directory custody is invalid")
            writer_fd = os.open(
                "artifact.aab",
                _open_flags(write=True, exclusive=True),
                0o400,
                dir_fd=self._directory_fd,
            )
            digest = hashlib.sha256()
            chunks: list[bytes] = []
            try:
                offset = 0
                while offset < self._expected_size:
                    block = os.pread(
                        self._source_fd,
                        min(HELD_AAB_READ_CHUNK, self._expected_size - offset),
                        offset,
                    )
                    if not block:
                        raise SignerError("held Android AAB source truncated during snapshot")
                    digest.update(block)
                    chunks.append(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(writer_fd, view)
                        if written <= 0:
                            raise SignerError("held Android AAB snapshot write truncated")
                        view = view[written:]
                    offset += len(block)
                if os.pread(self._source_fd, 1, offset):
                    raise SignerError("held Android AAB source grew during snapshot")
                os.fchmod(writer_fd, 0o400)
                os.fsync(writer_fd)
            finally:
                os.close(writer_fd)
            os.fsync(self._directory_fd)
            if digest.hexdigest() != self._expected_sha256:
                raise SignerError("held Android AAB source SHA-256 is not exact")
            self.payload = b"".join(chunks)
            if len(self.payload) != self._expected_size:
                raise SignerError("held Android AAB source size changed during snapshot")

            self._snapshot_fd = _openat_child(
                self._directory_fd,
                "artifact.aab",
                _open_flags(),
            )
            snapshot_info = os.fstat(self._snapshot_fd)
            if (
                not stat.S_ISREG(snapshot_info.st_mode)
                or snapshot_info.st_nlink != 1
                or snapshot_info.st_size != self._expected_size
                or stat.S_IMODE(snapshot_info.st_mode) != 0o400
                or _sha256_pread(
                    self._snapshot_fd,
                    self._expected_size,
                    "held Android AAB snapshot",
                )
                != self._expected_sha256
            ):
                raise SignerError("held Android AAB private snapshot custody is invalid")
            os.unlink("artifact.aab", dir_fd=self._directory_fd)
            os.fsync(self._directory_fd)
            os.fchmod(self._directory_fd, 0o500)
            self._snapshot_stat = _held_stat_identity(os.fstat(self._snapshot_fd))
            self._directory_stat = _held_stat_identity(os.fstat(self._directory_fd))
            self.revalidate()
            return self
        except BaseException:
            self.close()
            raise

    def revalidate(self) -> None:
        if (
            self._source_fd < 0
            or self._directory_fd < 0
            or self._snapshot_fd < 0
            or self._source_stat is None
            or self._directory_stat is None
            or self._snapshot_stat is None
            or self._directory_path is None
        ):
            raise SignerError("held Android AAB custody is not active")
        try:
            caller_info = os.fstat(self._caller_fd)
        except OSError as exc:
            raise SignerError("held Android AAB caller descriptor was closed") from exc
        source_info = os.fstat(self._source_fd)
        directory_info = os.fstat(self._directory_fd)
        snapshot_info = os.fstat(self._snapshot_fd)
        path_directory_info = os.lstat(self._directory_path)
        if (
            _held_stat_identity(caller_info) != self._source_stat
            or _held_stat_identity(source_info) != self._source_stat
            or _held_stat_identity(directory_info) != self._directory_stat
            or _held_stat_identity(snapshot_info) != self._snapshot_stat
            or (path_directory_info.st_dev, path_directory_info.st_ino)
            != (self._directory_stat[0], self._directory_stat[1])
            or os.listdir(self._directory_fd) != []
            or _sha256_pread(
                self._source_fd,
                self._expected_size,
                "held Android AAB source",
            )
            != self._expected_sha256
            or _sha256_pread(
                self._snapshot_fd,
                self._expected_size,
                "held Android AAB snapshot",
            )
            != self._expected_sha256
        ):
            raise SignerError("held Android AAB source or snapshot custody changed")

    def close(self) -> None:
        cleanup_error: BaseException | None = None
        if self._snapshot_fd >= 0:
            try:
                os.close(self._snapshot_fd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
            self._snapshot_fd = -1
        if self._directory_fd >= 0:
            try:
                os.fchmod(self._directory_fd, 0o700)
                os.fsync(self._directory_fd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
            try:
                os.close(self._directory_fd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
            self._directory_fd = -1
        if self._source_fd >= 0:
            try:
                os.close(self._source_fd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
            self._source_fd = -1
        if self._directory_path is not None:
            try:
                path_info = os.lstat(self._directory_path)
                if (
                    self._directory_stat is not None
                    and (path_info.st_dev, path_info.st_ino)
                    != (self._directory_stat[0], self._directory_stat[1])
                ):
                    raise SignerError(
                        "held Android AAB private directory path was substituted"
                    )
                os.rmdir(self._directory_path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                cleanup_error = cleanup_error or exc
            self._directory_path = None
        if cleanup_error is not None:
            raise SignerError("held Android AAB private snapshot cleanup failed") from cleanup_error

    def __exit__(self, exc_type, exc, traceback) -> bool:
        custody_error: BaseException | None = None
        try:
            self.revalidate()
        except BaseException as failure:
            custody_error = failure
        try:
            self.close()
        except BaseException as cleanup_error:
            if custody_error is None:
                custody_error = cleanup_error
        if custody_error is not None:
            if exc is not None:
                raise custody_error from exc
            raise custody_error
        return False


def _assert_frozen_bundletool(
    *,
    pass_fds: tuple[int, ...] = (),
    revalidate: Callable[[], None] | None = None,
) -> pathlib.Path:
    active = _ACTIVE_ANDROID_TOOLS.get()
    if active is None:
        raise SignerError(
            "retained Android JDK and bundletool custody is required"
        )
    jar = active.bundletool_path
    java = _bound_jdk_tool("java")

    def validate_all() -> None:
        if revalidate is not None:
            revalidate()
        active.revalidate(full_tree=True)

    output = _run(
        [java, "-jar", str(jar), "version"],
        "pinned bundletool version verification",
        timeout=30,
        pass_fds=tuple(dict.fromkeys((*pass_fds, *active.pass_fds))),
        revalidate=validate_all,
        watch_fds=tuple(dict.fromkeys((*pass_fds, *active.pass_fds))),
    )
    if output.decode("ascii", errors="replace").strip() != BUNDLETOOL_VERSION:
        raise SignerError("pinned bundletool did not report the required version")
    return jar


def _bundletool_dump_manifest(data: bytes) -> bytes:
    active = _ACTIVE_ANDROID_TOOLS.get()
    if active is None:
        raise SignerError("retained Android JDK and bundletool custody is required")
    java = _bound_jdk_tool("java")
    jar = _assert_frozen_bundletool()
    with _private_held_copy(data) as held:
        output = _run(
            [
                java,
                "-jar",
                str(jar),
                "dump",
                "manifest",
                f"--bundle={held}",
                "--module=base",
            ],
            "pinned bundletool AAB manifest decoder",
            timeout=60,
            pass_fds=active.pass_fds,
            watch_fds=active.pass_fds,
        )
    if not output.strip():
        raise SignerError("pinned bundletool could not decode the held AAB")
    return output


def _verify_cryptographic_signature(
    path: pathlib.Path,
    *,
    pass_fds: tuple[int, ...] = (),
    revalidate: Callable[[], None] | None = None,
) -> None:
    # The Android upload certificate is self-signed, so jarsigner -strict can
    # only validate its chain against a truststore. Check the signer against the
    # reviewed pin first, then verify -strict against a per-run truststore that
    # holds exactly that one certificate.
    keytool = _bound_jdk_tool("keytool")
    certificate = _run(
        [keytool, "-printcert", "-jarfile", str(path)],
        "AAB signer certificate inspection",
        pass_fds=pass_fds,
        revalidate=revalidate,
        watch_fds=pass_fds,
    ).decode("utf-8", errors="replace")
    digests = {
        match.replace(":", "").lower()
        for match in re.findall(
            r"(?im)^\s*SHA256:\s*([0-9A-F:]{64,95})\s*$", certificate
        )
    }
    if digests != {_reviewed_upload_certificate()}:
        raise SignerError("AAB signer does not exactly match the reviewed upload certificate")
    exported = _run(
        [keytool, "-printcert", "-rfc", "-jarfile", str(path)],
        "AAB signer certificate export",
        pass_fds=pass_fds,
        revalidate=revalidate,
        watch_fds=pass_fds,
    ).decode("ascii", errors="replace")
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+?-----END CERTIFICATE-----",
        exported,
    )
    if len(blocks) != 1:
        raise SignerError("AAB must carry exactly one signer certificate")
    jarsigner = _bound_jdk_tool("jarsigner")
    with tempfile.TemporaryDirectory(prefix="wins-aab-truststore.") as work:
        pem_path = os.path.join(work, "upload.pem")
        descriptor = os.open(pem_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(blocks[0] + "\n")
        store = os.path.join(work, "upload-truststore.p12")
        # A random password for a throwaway store that holds one public certificate.
        store_password = secrets.token_hex(16)
        _run(
            [keytool, "-importcert", "-noprompt", "-alias", "upload", "-file", pem_path,
             "-keystore", store, "-storetype", "PKCS12", "-storepass", store_password],
            "AAB pinned truststore",
        )
        output = _run(
            [jarsigner, "-verify", "-strict", "-keystore", store, "-storetype", "PKCS12",
             "-storepass", store_password, str(path)],
            "AAB JAR signature verification",
            pass_fds=pass_fds,
            revalidate=revalidate,
            watch_fds=pass_fds,
        ).lower()
    if b"jar verified" not in output or b"jar is unsigned" in output:
        raise SignerError("jarsigner did not prove a cryptographically verified AAB")


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise SignerError("invalid protobuf varint")
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _ld(number: int, payload: bytes) -> bytes:
    return _encode_varint((number << 3) | 2) + _encode_varint(len(payload)) + payload


def _varint_field(number: int, value: int) -> bytes:
    return _encode_varint(number << 3) + _encode_varint(value)


def _varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise SignerError("invalid protobuf varint")


def _fields(data: bytes) -> list[tuple[int, int, int | bytes]]:
    result: list[tuple[int, int, int | bytes]] = []
    offset = 0
    while offset < len(data):
        tag, offset = _varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise SignerError("invalid protobuf field number")
        if wire == 0:
            value, offset = _varint(data, offset)
        elif wire == 1:
            if offset + 8 > len(data):
                raise SignerError("truncated fixed64 field")
            value, offset = data[offset : offset + 8], offset + 8
        elif wire == 2:
            size, offset = _varint(data, offset)
            if size > len(data) - offset:
                raise SignerError("truncated length-delimited field")
            value, offset = data[offset : offset + size], offset + size
        elif wire == 5:
            if offset + 4 > len(data):
                raise SignerError("truncated fixed32 field")
            value, offset = data[offset : offset + 4], offset + 4
        else:
            raise SignerError(f"unsupported protobuf wire type {wire}")
        result.append((number, wire, value))
    return result


def encode_xml_attribute(
    name: str,
    value: str,
    *,
    namespace: str = "",
    resource_id: int = 0,
    compiled: bytes | None = None,
) -> bytes:
    parts: list[bytes] = []
    if namespace:
        parts.append(_ld(1, namespace.encode("utf-8")))
    parts.append(_ld(2, name.encode("utf-8")))
    parts.append(_ld(3, value.encode("utf-8")))
    if resource_id:
        parts.append(_varint_field(5, resource_id))
    if compiled is not None:
        parts.append(_ld(6, compiled))
    return b"".join(parts)


def encode_compiled_int(value: int) -> bytes:
    return _ld(7, _varint_field(6, value))


def encode_compiled_bool(value: bool) -> bytes:
    return _ld(7, _varint_field(8, 1 if value else 0))


def encode_xml_namespace(prefix: str, uri: str) -> bytes:
    return _ld(1, prefix.encode("utf-8")) + _ld(2, uri.encode("utf-8"))


def encode_xml_element(
    name: str,
    attributes: list[bytes],
    children: list[bytes],
    *,
    namespace: str = "",
    ns_decls: list[bytes] | None = None,
) -> bytes:
    parts: list[bytes] = []
    for decl in ns_decls or []:
        parts.append(_ld(1, decl))
    if namespace:
        parts.append(_ld(2, namespace.encode("utf-8")))
    parts.append(_ld(3, name.encode("utf-8")))
    for attribute in attributes:
        parts.append(_ld(4, attribute))
    for child in children:
        parts.append(_ld(5, child))
    return b"".join(parts)


def encode_xml_node_element(element: bytes) -> bytes:
    return _ld(1, element)


def encode_bundle_config(version: str = BUNDLETOOL_VERSION) -> bytes:
    bundletool = _ld(1, version.encode("utf-8"))
    abi_dimension = _varint_field(1, 1)
    splits = _ld(1, abi_dimension)
    optimizations = _ld(1, splits)
    return _ld(1, bundletool) + _ld(2, optimizations)


def _decode_utf8(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SignerError(f"{label} is not UTF-8") from exc


def _decode_primitive(data: bytes) -> int | bool | None:
    decoded: int | bool | None = None
    value_present = False
    for number, wire, value in _fields(data):
        if not 1 <= number <= 14:
            continue
        if value_present:
            raise SignerError("AAB proto XML primitive is duplicated")
        value_present = True
        if number == 8 and wire == 0 and type(value) is int:
            decoded = bool(value)
        elif number in {6, 7} and wire == 0 and type(value) is int:
            # 6 is int_decimal_value; 7 is int_hexadecimal_value, which aapt2
            # uses for flag attributes such as protectionLevel.
            decoded = value & 0xFFFFFFFF
            if decoded >= 1 << 31:
                decoded -= 1 << 32
    return decoded


def _decode_reference(data: bytes) -> str | None:
    # aapt2 Reference: id (2) and name (3), for example "mipmap/ic_launcher" or
    # "android:style/Theme.Translucent.NoTitleBar". The manifest's raw text
    # for such an attribute is "@" followed by that name.
    resource_id: int | None = None
    name: str | None = None
    for number, wire, value in _fields(data):
        if number == 2 and wire == 0 and type(value) is int:
            if resource_id is not None:
                raise SignerError("AAB proto XML reference id is duplicated")
            resource_id = value
        elif number == 3 and wire == 2 and type(value) is bytes:
            if name is not None:
                raise SignerError("AAB proto XML reference name is duplicated")
            name = _decode_utf8(value, "AAB proto XML reference name")
    if not resource_id or not name:
        return None
    return "@" + name


def _decode_item(data: bytes) -> str | int | bool | None:
    decoded: str | int | bool | None = None
    value_present = False
    for number, wire, value in _fields(data):
        if not 1 <= number <= 7:
            continue
        if value_present:
            raise SignerError("AAB proto XML item is duplicated")
        value_present = True
        if number == 1 and wire == 2 and type(value) is bytes:
            decoded = _decode_reference(value)
        elif number == 2 and wire == 2 and type(value) is bytes:
            decoded = _decode_utf8(value, "AAB proto XML item")
        elif number == 7 and wire == 2 and type(value) is bytes:
            decoded = _decode_primitive(value)
    return decoded


# Symbolic manifest attributes that aapt2 compiles to integers, with the
# name values from frameworks/base core/res/res/values/attrs_manifest.xml.
# The raw text is one name or names joined by "|"; their OR must equal the
# compiled value, and an unknown name never agrees.
SYMBOLIC_INT_ATTRIBUTES = {
    "protectionLevel": {
        "normal": 0x0, "dangerous": 0x1, "signature": 0x2, "signatureOrSystem": 0x3,
        "privileged": 0x10, "system": 0x10, "development": 0x20, "appop": 0x40,
        "pre23": 0x80, "installer": 0x100, "verifier": 0x200, "preinstalled": 0x400,
        "setup": 0x800, "instant": 0x1000, "runtime": 0x2000,
    },
    "configChanges": {
        "mcc": 0x0001, "mnc": 0x0002, "locale": 0x0004, "touchscreen": 0x0008,
        "keyboard": 0x0010, "keyboardHidden": 0x0020, "navigation": 0x0040,
        "orientation": 0x0080, "screenLayout": 0x0100, "uiMode": 0x0200,
        "screenSize": 0x0400, "smallestScreenSize": 0x0800, "density": 0x1000,
        "layoutDirection": 0x2000, "colorMode": 0x4000, "grammaticalGender": 0x8000,
        "fontWeightAdjustment": 0x10000000, "fontScale": 0x40000000,
    },
    "foregroundServiceType": {
        "dataSync": 0x1, "mediaPlayback": 0x2, "phoneCall": 0x4, "location": 0x8,
        "connectedDevice": 0x10, "mediaProjection": 0x20, "camera": 0x40,
        "microphone": 0x80, "health": 0x100, "remoteMessaging": 0x200,
        "systemExempted": 0x400, "shortService": 0x800, "fileManagement": 0x1000,
        "mediaProcessing": 0x2000, "specialUse": 0x40000000,
    },
    "launchMode": {
        "standard": 0, "singleTop": 1, "singleTask": 2, "singleInstance": 3,
        "singleInstancePerTask": 4,
    },
    "windowSoftInputMode": {
        "stateUnspecified": 0x0, "stateUnchanged": 0x1, "stateHidden": 0x2,
        "stateAlwaysHidden": 0x3, "stateVisible": 0x4, "stateAlwaysVisible": 0x5,
        "adjustUnspecified": 0x00, "adjustResize": 0x10, "adjustPan": 0x20,
        "adjustNothing": 0x30,
    },
}


def _protobuf_raw_compiled_agree(
    name: str, raw: str, compiled: str | int | bool
) -> bool:
    if type(compiled) is bool:
        return raw.casefold() in (
            {"true", "1"} if compiled else {"false", "0"}
        )
    if type(compiled) is int:
        if name == "screenOrientation" and raw == "landscape":
            return compiled == 0
        names = SYMBOLIC_INT_ATTRIBUTES.get(name)
        if names is not None and not re.fullmatch(r"-?(0|[1-9][0-9]*)", raw):
            flags = 0
            for part in raw.split("|"):
                if part not in names:
                    return False
                flags |= names[part]
            return flags == compiled
        return re.fullmatch(r"-?(0|[1-9][0-9]*)", raw) is not None and int(raw) == compiled
    return raw == compiled


def _decode_xml_attribute(data: bytes) -> tuple[str, str, str]:
    namespace = ""
    name: str | None = None
    text = ""
    resource_id = 0
    compiled: str | int | bool | None = None
    compiled_present = False
    scalar_fields: set[int] = set()
    for number, wire, value in _fields(data):
        if number in {1, 2, 3, 5}:
            if number in scalar_fields:
                raise SignerError("AAB proto XML attribute scalar is duplicated")
            scalar_fields.add(number)
        if number == 1 and wire == 2 and type(value) is bytes:
            namespace = _decode_utf8(value, "AAB proto XML attribute namespace")
        elif number == 2 and wire == 2 and type(value) is bytes:
            name = _decode_utf8(value, "AAB proto XML attribute name")
        elif number == 3 and wire == 2 and type(value) is bytes:
            text = _decode_utf8(value, "AAB proto XML attribute value")
        elif number == 5 and wire == 0 and type(value) is int:
            resource_id = value
        elif number == 6 and wire == 2 and type(value) is bytes:
            if compiled_present:
                raise SignerError("AAB proto XML compiled item is duplicated")
            compiled_present = True
            compiled = _decode_item(value)
    if name is None:
        raise SignerError("AAB proto XML attribute lacks a name")
    if compiled_present:
        if compiled is None:
            raise SignerError("AAB proto XML compiled identity is not canonical")
        if text and not _protobuf_raw_compiled_agree(name, text, compiled):
            raise SignerError(
                f"AAB proto {name} raw and compiled values disagree"
            )
    if name == "versionCode" or resource_id == ATTR_VERSION_CODE:
        if type(compiled) is int:
            text = str(compiled)
        elif not text:
            raise SignerError("AAB proto XML versionCode is missing")
    elif name == "versionName" or resource_id == ATTR_VERSION_NAME:
        if type(compiled) is str and compiled:
            text = compiled
        elif not text:
            raise SignerError("AAB proto XML versionName is missing")
    elif name == "screenOrientation" or resource_id == ATTR_SCREEN_ORIENTATION:
        if (
            namespace != ANDROID_NS
            or name != "screenOrientation"
            or resource_id != ATTR_SCREEN_ORIENTATION
            or not compiled_present
            or type(compiled) is not int
        ):
            raise SignerError("AAB proto screenOrientation attribute is malformed")
        raw_is_landscape = text in {"landscape", "0"}
        compiled_is_landscape = compiled == 0
        if text and raw_is_landscape != compiled_is_landscape:
            raise SignerError(
                "AAB proto screenOrientation raw and compiled values disagree"
            )
        if not text:
            text = str(compiled)
    elif type(compiled) is bool and not text:
        text = "true" if compiled else "false"
    elif type(compiled) is str and not text:
        text = compiled
    elif type(compiled) is int and not text:
        text = str(compiled)
    return namespace, name, text


def _decode_xml_element(data: bytes) -> ET.Element:
    namespace = ""
    name: str | None = None
    attributes: list[tuple[str, str, str]] = []
    children: list[ET.Element | str] = []
    scalar_fields: set[int] = set()
    for number, wire, value in _fields(data):
        if number in {2, 3}:
            if number in scalar_fields:
                raise SignerError("AAB proto XML element scalar is duplicated")
            scalar_fields.add(number)
        if number == 2 and wire == 2 and type(value) is bytes:
            namespace = _decode_utf8(value, "AAB proto XML element namespace")
        elif number == 3 and wire == 2 and type(value) is bytes:
            name = _decode_utf8(value, "AAB proto XML element name")
        elif number == 4 and wire == 2 and type(value) is bytes:
            attributes.append(_decode_xml_attribute(value))
        elif number == 5 and wire == 2 and type(value) is bytes:
            children.append(_decode_xml_node(value))
    if not name:
        raise SignerError("AAB proto XML element lacks a name")
    tag = f"{{{namespace}}}{name}" if namespace else name
    element = ET.Element(tag)
    seen: set[str] = set()
    for attr_ns, attr_name, attr_value in attributes:
        key = f"{{{attr_ns}}}{attr_name}" if attr_ns else attr_name
        if key in seen:
            raise SignerError(f"AAB proto XML attribute is duplicated: {attr_name}")
        seen.add(key)
        element.set(key, attr_value)
    for child in children:
        if isinstance(child, ET.Element):
            element.append(child)
        else:
            element.text = (element.text or "") + child
    return element


def _decode_xml_node(data: bytes) -> ET.Element | str:
    element: ET.Element | None = None
    text: str | None = None
    for number, wire, value in _fields(data):
        if number == 1 and wire == 2 and type(value) is bytes:
            if element is not None:
                raise SignerError("AAB proto XML node has duplicate elements")
            element = _decode_xml_element(value)
        elif number == 2 and wire == 2 and type(value) is bytes:
            if text is not None:
                raise SignerError("AAB proto XML node has duplicate text")
            text = _decode_utf8(value, "AAB proto XML text")
    if element is not None and text is None:
        return element
    if text is not None and element is None:
        return text
    raise SignerError("AAB proto XML node is malformed")


def _decode_proto_manifest(data: bytes) -> ET.Element:
    if data.startswith(AXML_MAGIC):
        raise SignerError("AAB merged manifest is APK binary XML, not proto XML")
    root = _decode_xml_node(data)
    if not isinstance(root, ET.Element) or root.tag not in {"manifest", f"{{{ANDROID_NS}}}manifest"}:
        raise SignerError("AAB proto XML root is not <manifest>")
    if root.tag != "manifest":
        mapped = ET.Element("manifest", root.attrib)
        mapped.extend(list(root))
        return mapped
    return root


def _pad4(payload: bytes) -> bytes:
    remainder = len(payload) % 4
    if remainder == 0:
        return payload
    return payload + b"\x00" * (4 - remainder)


def _utf16_axml_string(value: str) -> bytes:
    encoded = value.encode("utf-16le")
    count = len(value)
    if count > 0x7FFF:
        raise SignerError("APK binary XML string is too long")
    return _pad4(struct.pack("<H", count) + encoded + b"\x00\x00")


def _decode_axml_utf16_string(data: bytes, offset: int) -> str:
    if offset + 2 > len(data):
        raise SignerError("APK binary XML string is truncated")
    count = struct.unpack_from("<H", data, offset)[0]
    if count & 0x8000:
        if offset + 4 > len(data):
            raise SignerError("APK binary XML string is truncated")
        count = ((count & 0x7FFF) << 16) | struct.unpack_from("<H", data, offset + 2)[0]
        start = offset + 4
    else:
        start = offset + 2
    end = start + count * 2
    if end + 2 > len(data):
        raise SignerError("APK binary XML string is truncated")
    return data[start:end].decode("utf-16le")


def _decode_axml_utf8_string(data: bytes, offset: int) -> str:
    if offset >= len(data):
        raise SignerError("APK binary XML string is truncated")

    def _len(cursor: int) -> tuple[int, int]:
        if cursor >= len(data):
            raise SignerError("APK binary XML string is truncated")
        first = data[cursor]
        if first & 0x80:
            if cursor + 1 >= len(data):
                raise SignerError("APK binary XML string is truncated")
            return ((first & 0x7F) << 8) | data[cursor + 1], cursor + 2
        return first, cursor + 1

    _chars, cursor = _len(offset)
    byte_count, cursor = _len(cursor)
    end = cursor + byte_count
    if end > len(data):
        raise SignerError("APK binary XML string is truncated")
    return data[cursor:end].decode("utf-8")


def _decode_axml_string_pool(chunk: bytes) -> list[str]:
    if len(chunk) < 28:
        raise SignerError("APK binary XML string pool is truncated")
    type_, header_size, size = struct.unpack_from("<HHI", chunk, 0)
    if type_ != RES_STRING_POOL_TYPE or header_size < 28 or size > len(chunk):
        raise SignerError("APK binary XML string pool is malformed")
    string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", chunk, 8
    )
    offset_start = header_size
    if offset_start + 4 * string_count > len(chunk) or strings_start > len(chunk):
        raise SignerError("APK binary XML string pool is malformed")
    utf8 = bool(flags & UTF8_FLAG)
    strings: list[str] = []
    for index in range(string_count):
        relative = struct.unpack_from("<I", chunk, offset_start + 4 * index)[0]
        absolute = strings_start + relative
        if absolute >= len(chunk):
            raise SignerError("APK binary XML string pool is malformed")
        if utf8:
            strings.append(_decode_axml_utf8_string(chunk, absolute))
        else:
            strings.append(_decode_axml_utf16_string(chunk, absolute))
    return strings


def _axml_string(strings: list[str], index: int) -> str:
    if index == NO_INDEX:
        return ""
    if index < 0 or index >= len(strings):
        raise SignerError("APK binary XML string index is invalid")
    return strings[index]


def encode_apk_binary_manifest(
    *,
    package: str = "org.winsvpn.app",
    version_name: str = "1.0.16",
    version_code: int = 33,
    form: str = "phone",
) -> bytes:
    """Encode a focused APK binary XML manifest for identity gates and tests."""

    interned: dict[str, int] = {}
    strings: list[str] = []
    resource_ids: list[int] = []

    def intern(value: str, resource_id: int = 0) -> int:
        existing = interned.get(value)
        if existing is not None:
            return existing
        interned[value] = len(strings)
        strings.append(value)
        resource_ids.append(resource_id)
        return interned[value]

    intern("android")
    intern(ANDROID_NS)
    intern("name", ATTR_NAME)
    intern("label", ATTR_LABEL)
    intern("permission", ATTR_PERMISSION)
    intern("required", ATTR_REQUIRED)
    intern("banner", ATTR_BANNER)
    intern("icon")
    intern("exported")
    intern("debuggable")
    intern("usesCleartextTraffic")
    intern("networkSecurityConfig")
    intern("minSdkVersion")
    intern("targetSdkVersion")
    intern("versionCode", ATTR_VERSION_CODE)
    intern("versionName", ATTR_VERSION_NAME)
    intern("package")
    intern("manifest")
    intern("uses-permission")
    intern("uses-sdk")
    intern("uses-feature")
    intern("application")
    intern("activity")
    intern("intent-filter")
    intern("action")
    intern("category")
    intern("service")
    intern(package)
    intern(version_name)
    intern("android.permission.INTERNET")
    intern("android.permission.QUERY_ALL_PACKAGES")
    intern("android.permission.BIND_VPN_SERVICE")
    intern("org.winsvpn.app.MainActivity")
    intern("org.winsvpn.app.VpnTunnelService")
    intern("android.intent.action.MAIN")
    intern("android.intent.category.LAUNCHER")
    intern("android.net.VpnService")
    intern("@mipmap/ic_launcher")
    intern("@xml/network_security_config")
    label = "Win's VPN" if form == "tv" else "Calculator"
    intern(label)
    if form == "tv":
        intern("android.software.leanback")
        intern("android.hardware.touchscreen")
        intern("android.intent.category.LEANBACK_LAUNCHER")
        intern("@drawable/banner")
        intern("false")

    def start_ns() -> bytes:
        body = struct.pack("<II", intern("android"), intern(ANDROID_NS))
        return struct.pack("<HHI II", RES_XML_START_NAMESPACE_TYPE, 16, 24, 1, NO_INDEX) + body

    def end_ns() -> bytes:
        body = struct.pack("<II", intern("android"), intern(ANDROID_NS))
        return struct.pack("<HHI II", RES_XML_END_NAMESPACE_TYPE, 16, 24, 1, NO_INDEX) + body

    def attr(ns: int, name: str, *, string: str | None = None, integer: int | None = None, boolean: bool | None = None, resource_id: int = 0) -> bytes:
        name_index = intern(name, resource_id)
        if string is not None:
            value_index = intern(string)
            raw = value_index
            typed = struct.pack("<HBBI", 8, 0, TYPE_STRING, value_index)
        elif integer is not None:
            raw = NO_INDEX
            typed = struct.pack("<HBBI", 8, 0, TYPE_INT_DEC, integer & 0xFFFFFFFF)
        elif boolean is not None:
            raw = NO_INDEX
            typed = struct.pack("<HBBI", 8, 0, TYPE_INT_BOOLEAN, 0xFFFFFFFF if boolean else 0)
        else:
            raise SignerError("APK binary XML attribute value is missing")
        return struct.pack("<III", ns, name_index, raw) + typed

    def element(name: str, attributes: list[bytes], children: list[bytes]) -> bytes:
        name_index = intern(name)
        attr_blob = b"".join(attributes)
        ext = struct.pack("<IIHHHHHH", NO_INDEX, name_index, 20, 20, len(attributes), 0, 0, 0)
        start_size = 16 + 20 + 20 * len(attributes)
        start = struct.pack("<HHI II", RES_XML_START_ELEMENT_TYPE, 16, start_size, 1, NO_INDEX) + ext + attr_blob
        end = struct.pack("<HHI II II", RES_XML_END_ELEMENT_TYPE, 16, 24, 1, NO_INDEX, NO_INDEX, name_index)
        return start + b"".join(children) + end

    ns = intern(ANDROID_NS)

    permission_nodes = [
        element(
            "uses-sdk",
            [
                attr(ns, "minSdkVersion", integer=26),
                attr(ns, "targetSdkVersion", integer=37),
            ],
            [],
        ),
        element(
            "uses-permission",
            [attr(ns, "name", string="android.permission.INTERNET", resource_id=ATTR_NAME)],
            [],
        ),
        element(
            "uses-permission",
            [
                attr(
                    ns,
                    "name",
                    string="android.permission.QUERY_ALL_PACKAGES",
                    resource_id=ATTR_NAME,
                )
            ],
            [],
        ),
    ]
    feature_nodes: list[bytes] = []
    application_attrs = [
        attr(ns, "label", string=label, resource_id=ATTR_LABEL),
        attr(ns, "icon", string="@mipmap/ic_launcher"),
        attr(ns, "debuggable", boolean=False),
        attr(ns, "usesCleartextTraffic", boolean=False),
        attr(ns, "networkSecurityConfig", string="@xml/network_security_config"),
    ]
    activity_categories = ["android.intent.category.LAUNCHER"]
    if form == "tv":
        feature_nodes.extend(
            [
                element(
                    "uses-feature",
                    [
                        attr(ns, "name", string="android.software.leanback", resource_id=ATTR_NAME),
                        attr(ns, "required", boolean=False, resource_id=ATTR_REQUIRED),
                    ],
                    [],
                ),
                element(
                    "uses-feature",
                    [
                        attr(
                            ns,
                            "name",
                            string="android.hardware.touchscreen",
                            resource_id=ATTR_NAME,
                        ),
                        attr(ns, "required", boolean=False, resource_id=ATTR_REQUIRED),
                    ],
                    [],
                ),
            ]
        )
        application_attrs.append(
            attr(ns, "banner", string="@drawable/banner", resource_id=ATTR_BANNER)
        )
        activity_categories.append("android.intent.category.LEANBACK_LAUNCHER")
    intent_children = [
        element(
            "action",
            [attr(ns, "name", string="android.intent.action.MAIN", resource_id=ATTR_NAME)],
            [],
        )
    ]
    for category in activity_categories:
        intent_children.append(
            element(
                "category",
                [attr(ns, "name", string=category, resource_id=ATTR_NAME)],
                [],
            )
        )
    activity = element(
        "activity",
        [
            attr(
                ns,
                "name",
                string="org.winsvpn.app.MainActivity",
                resource_id=ATTR_NAME,
            ),
            attr(ns, "exported", boolean=True),
        ],
        [element("intent-filter", [], intent_children)],
    )
    vpn_intent = element(
        "intent-filter",
        [],
        [
            element(
                "action",
                [attr(ns, "name", string="android.net.VpnService", resource_id=ATTR_NAME)],
                [],
            )
        ],
    )
    service = element(
        "service",
        [
            attr(
                ns,
                "name",
                string="org.winsvpn.app.VpnTunnelService",
                resource_id=ATTR_NAME,
            ),
            attr(
                ns,
                "permission",
                string="android.permission.BIND_VPN_SERVICE",
                resource_id=ATTR_PERMISSION,
            ),
            attr(ns, "exported", boolean=False),
        ],
        [vpn_intent],
    )
    application = element("application", application_attrs, [activity, service])
    manifest_attrs = [
        attr(NO_INDEX, "package", string=package),
        attr(ns, "versionName", string=version_name, resource_id=ATTR_VERSION_NAME),
        attr(ns, "versionCode", integer=version_code, resource_id=ATTR_VERSION_CODE),
    ]
    manifest = element(
        "manifest",
        manifest_attrs,
        permission_nodes + feature_nodes + [application],
    )

    offsets = []
    blob = b""
    for value in strings:
        offsets.append(len(blob))
        blob += _utf16_axml_string(value)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    pool_body = (
        struct.pack("<IIIII", len(strings), 0, 0, strings_start, 0)
        + struct.pack("<" + "I" * len(strings), *offsets)
        + blob
    )
    pool = struct.pack("<HHI", RES_STRING_POOL_TYPE, header_size, 8 + len(pool_body)) + pool_body
    resid_body = struct.pack("<" + "I" * len(resource_ids), *resource_ids)
    resource_map = struct.pack(
        "<HHI", RES_XML_RESOURCE_MAP_TYPE, 8, 8 + len(resid_body)
    ) + resid_body
    xml_body = start_ns() + manifest + end_ns()
    inner = pool + resource_map + xml_body
    return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(inner)) + inner


def _decode_axml_manifest(data: bytes) -> ET.Element:
    if not data.startswith(AXML_MAGIC):
        raise SignerError("APK merged manifest is not APK binary XML")
    if len(data) < 8:
        raise SignerError("APK binary XML is truncated")
    type_, header_size, size = struct.unpack_from("<HHI", data, 0)
    if type_ != RES_XML_TYPE or header_size < 8 or size > len(data):
        raise SignerError("APK binary XML header is malformed")
    cursor = header_size
    strings: list[str] | None = None
    resource_ids: list[int] = []
    stack: list[ET.Element] = []
    root: ET.Element | None = None
    while cursor < size:
        if cursor + 8 > len(data):
            raise SignerError("APK binary XML is truncated")
        chunk_type, chunk_header, chunk_size = struct.unpack_from("<HHI", data, cursor)
        if chunk_size < 8 or cursor + chunk_size > len(data):
            raise SignerError("APK binary XML chunk is malformed")
        chunk = data[cursor : cursor + chunk_size]
        if chunk_type == RES_STRING_POOL_TYPE:
            strings = _decode_axml_string_pool(chunk)
        elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            count = (chunk_size - 8) // 4
            resource_ids = list(struct.unpack_from("<" + "I" * count, chunk, 8)) if count else []
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            if strings is None:
                raise SignerError("APK binary XML element precedes the string pool")
            if chunk_size < 36:
                raise SignerError("APK binary XML start element is truncated")
            ns_index, name_index, attr_start, attr_size, attr_count = struct.unpack_from(
                "<IIHHH", chunk, 16
            )
            del ns_index, attr_start
            if attr_size < 20:
                raise SignerError("APK binary XML attribute size is malformed")
            tag = _axml_string(strings, name_index)
            element = ET.Element(tag)
            attr_offset = 16 + 20
            for _index in range(attr_count):
                if attr_offset + 20 > len(chunk):
                    raise SignerError("APK binary XML attribute is truncated")
                attr_ns, attr_name, raw_value, value_size, _res0, data_type, value_data = (
                    struct.unpack_from("<IIIHBBI", chunk, attr_offset)
                )
                del value_size
                name = _axml_string(strings, attr_name)
                resid = resource_ids[attr_name] if attr_name < len(resource_ids) else 0
                raw_text = (
                    _axml_string(strings, raw_value)
                    if raw_value != NO_INDEX
                    else ""
                )
                if data_type == TYPE_STRING:
                    typed_text = _axml_string(strings, value_data)
                elif data_type == TYPE_INT_BOOLEAN:
                    typed_text = "true" if value_data else "false"
                elif data_type == TYPE_INT_DEC:
                    typed_text = str(value_data)
                else:
                    typed_text = str(value_data)
                if raw_text and not _protobuf_raw_compiled_agree(
                    name,
                    raw_text,
                    (
                        value_data != 0
                        if data_type == TYPE_INT_BOOLEAN
                        else value_data
                        if data_type == TYPE_INT_DEC
                        else typed_text
                    ),
                ):
                    raise SignerError(
                        f"APK binary XML {name} raw and typed values disagree"
                    )
                text = raw_text or typed_text
                if name == "versionCode" or resid == ATTR_VERSION_CODE:
                    if data_type == TYPE_INT_DEC:
                        text = str(value_data)
                elif name == "versionName" or resid == ATTR_VERSION_NAME:
                    if data_type == TYPE_STRING and not text:
                        text = _axml_string(strings, value_data)
                key = f"{{{ANDROID_NS}}}{name}" if attr_ns != NO_INDEX else name
                element.set(key, text)
                attr_offset += attr_size
            if stack:
                stack[-1].append(element)
            else:
                root = element
            stack.append(element)
        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()
        cursor += chunk_size
    if root is None or root.tag != "manifest":
        raise SignerError("APK binary XML root is not <manifest>")
    return root


def canonicalize_r8_mapping_bytes(data: bytes) -> bytes:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    text = data.decode("utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _r8_mapping_body(canonical_text: str) -> tuple[str, str]:
    line_end = -1
    compiler_r8 = False
    while True:
        line_start = line_end + 1
        line_end = canonical_text.find("\n", line_start)
        if line_end < 0:
            raise SignerError("Android phone/TV R8 mapping is missing pg_map_hash")
        line = canonical_text[line_start:line_end].strip()
        if not line:
            continue
        if not line.startswith("#"):
            raise SignerError("Android phone/TV R8 mapping header is missing pg_map_hash")
        header_line = line[1:].strip()
        if header_line == "compiler: R8":
            compiler_r8 = True
        if not header_line.startswith("pg_map_hash"):
            continue
        sha_index = header_line.find("SHA-256 ", len("pg_map_hash"))
        if sha_index < 0:
            raise SignerError("Android phone/TV R8 mapping uses an unknown map hash function")
        header_hash = header_line[sha_index + len("SHA-256") :].strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", header_hash):
            raise SignerError("Android phone/TV R8 mapping pg_map_hash is malformed")
        body = canonical_text[line_end + 1 :]
        computed = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if computed != header_hash:
            raise SignerError("Android phone/TV R8 mapping pg_map_hash does not match mapping bytes")
        if not compiler_r8:
            raise SignerError("Android phone/TV R8 mapping header is missing compiler: R8")
        return header_hash, body


def validate_r8_mapping_bytes(data: bytes, label: str = "embedded AAB proguard.map") -> dict[str, object]:
    if len(data) < MIN_R8_MAPPING_BYTES:
        raise SignerError(f"{label} is too small to be Android phone/TV R8 custody")
    try:
        canonical = canonicalize_r8_mapping_bytes(data)
    except UnicodeDecodeError as exc:
        raise SignerError(f"{label} is not UTF-8") from exc
    if len(canonical) < MIN_R8_MAPPING_BYTES:
        raise SignerError(f"{label} is too small to be Android phone/TV R8 custody")
    header_hash, body = _r8_mapping_body(canonical.decode("utf-8"))
    class_count = len(R8_CLASS_MAPPING_RE.findall(body))
    if class_count < MIN_R8_CLASS_MAPPINGS:
        raise SignerError(f"{label} is too trivial to be Android phone/TV R8 custody")
    return {
        "ok": True,
        "pg_map_hash": header_hash,
        "class_mapping_count": class_count,
        "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def bind_private_r8_mapping_bytes(
    target_id: str, artifact_data: bytes, mapping_data: bytes
) -> dict[str, object]:
    """Bind a private R8 map to one exact phone/TV APK or AAB candidate."""

    private = validate_r8_mapping_bytes(mapping_data, "private R8 mapping")
    if target_id in PHONE_TV_AAB_TARGETS:
        analysis = analyze_held_aab(artifact_data)
        r8 = analysis.get("r8")
        if type(r8) is not dict or r8.get("ok") is not True:
            raise SignerError("Android AAB is missing verified R8 proguard.map")
        if (
            r8.get("pg_map_hash") != private["pg_map_hash"]
            or r8.get("canonical_sha256") != private["canonical_sha256"]
        ):
            raise SignerError("private R8 mapping is not bound to the exact artifact")
        if bool(analysis.get("is_tv")) != (target_id == "android-tv-aab"):
            raise SignerError("AAB form-factor identity belongs to another exact target")
    elif target_id in PHONE_TV_APK_TARGETS:
        analysis = analyze_held_apk(artifact_data)
        if analysis.get("private_symbols_leaked") is True:
            raise SignerError("Android APK ships private R8 or native debug symbols")
        if bool(analysis.get("is_tv")) != (target_id == "android-tv-apk"):
            raise SignerError("APK form-factor identity belongs to another exact target")
    else:
        raise SignerError(f"unsupported exact Android R8 target: {target_id}")
    return {
        "ok": True,
        "target_id": target_id,
        "pg_map_hash": private["pg_map_hash"],
        "canonical_sha256": private["canonical_sha256"],
        "class_mapping_count": private["class_mapping_count"],
    }


def bind_private_r8_mapping(
    target_id: str, artifact_relative: str, mapping_relative: str
) -> dict[str, object]:
    if target_id in PHONE_TV_AAB_TARGETS:
        path = _canonical_gate_artifact(target_id, artifact_relative)
    elif target_id in PHONE_TV_APK_TARGETS:
        path = _canonical_gate_apk(target_id, artifact_relative)
    else:
        raise SignerError(f"unsupported exact Android R8 target: {target_id}")
    data, identity, digest = _hold_aab_bytes(path)
    _mapping_digest, _mapping_size, mapping_data = _hash_live_repo_file(
        mapping_relative, "private R8 mapping"
    )
    result = bind_private_r8_mapping_bytes(target_id, data, mapping_data)
    _revalidate_held_aab(path, identity, digest)
    return result


def _store_spec_for_target(target_id: str) -> dict[str, object]:
    if target_id in PHONE_TV_STORE_SPECS:
        return PHONE_TV_STORE_SPECS[target_id]
    if target_id == "android-phone-tablet-apk":
        return PHONE_TV_STORE_SPECS["android-phone-tablet-aab"]
    if target_id == "android-tv-apk":
        return PHONE_TV_STORE_SPECS["android-tv-aab"]
    raise SignerError(f"unsupported exact Android phone/TV store target: {target_id}")


def _load_store_json(relative: str, label: str) -> dict[str, object]:
    _digest, _size, payload = _hash_live_repo_file(relative, label)
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise SignerError(f"{label} is unreadable") from exc
    parsed = _strict_json_loads(text, label)
    if type(parsed) is not dict:
        raise SignerError(f"{label} must be one JSON object")
    return parsed


def _require_listing_protocol(text: str, label: str) -> None:
    folded = " ".join(text.split())
    if "Winn v3" not in text:
        raise SignerError(f"{label} must name Winn v3 as the primary protocol")
    if "AWG" not in folded:
        raise SignerError(f"{label} must name Winn v1 AWG as the fallback")
    if "Xray" in folded:
        raise SignerError(
            f"{label} must not claim an Xray fallback: Android refuses Xray mode"
        )


def _tunnel_protocol_matches(value: object) -> bool:
    if type(value) is not dict:
        return False
    return (
        value.get("executed_on") == TUNNEL_PROTOCOL_CONTRACT["executed_on"]
        and value.get("primary") == TUNNEL_PROTOCOL_CONTRACT["primary"]
        and value.get("fallback") == TUNNEL_PROTOCOL_CONTRACT["fallback"]
        and value.get("required_local_engines")
        == TUNNEL_PROTOCOL_CONTRACT["required_local_engines"]
        and value.get("forbidden_local_engines")
        == TUNNEL_PROTOCOL_CONTRACT["forbidden_local_engines"]
    )


def _reviewed_store_metadata(target_id: str) -> dict[str, object]:
    spec = _store_spec_for_target(target_id)
    root = str(spec["root"])
    files: dict[str, str] = {}
    for name in PHONE_TV_STORE_FILES:
        relative = f"{root}/{name}"
        digest, _size, payload = _hash_live_repo_file(relative, f"{target_id} store metadata")
        try:
            payload.decode("ascii")
        except UnicodeError as exc:
            raise SignerError(f"{relative} must be ASCII") from exc
        files[relative] = digest
    privacy = _load_store_json(f"{root}/review/privacy_label_manifest.json", f"{target_id} privacy label")
    signoff = _load_store_json(f"{root}/review/owner_signoff.json", f"{target_id} owner signoff")
    candidate = _load_store_json(
        f"{root}/artifacts/release_candidate.json", f"{target_id} release candidate"
    )
    listing = _hash_live_repo_file(
        f"{root}/metadata/en-US/full_description.txt", f"{target_id} listing"
    )[2].decode("ascii")
    notes = _hash_live_repo_file(
        f"{root}/review/play_console_notes.txt", f"{target_id} Play notes"
    )[2].decode("ascii")
    safety = _hash_live_repo_file(
        f"{root}/review/data_safety.md", f"{target_id} data safety"
    )[2].decode("ascii")
    title = _hash_live_repo_file(
        f"{root}/metadata/en-US/title.txt", f"{target_id} title"
    )[2].decode("ascii").strip()
    short = _hash_live_repo_file(
        f"{root}/metadata/en-US/short_description.txt", f"{target_id} short description"
    )[2].decode("ascii").strip()
    whats_new = _hash_live_repo_file(
        f"{root}/metadata/en-US/whats_new.txt", f"{target_id} what's new"
    )[2].decode("ascii").strip()
    _require_listing_protocol(listing, f"{target_id} listing")
    _require_listing_protocol(notes, f"{target_id} Play notes")
    _require_listing_protocol(safety, f"{target_id} data safety")
    _require_listing_protocol(whats_new, f"{target_id} what's new")
    if "Winn v3" not in short or "AWG fallback" not in short:
        raise SignerError(f"{target_id} short description must name the release protocol")
    if title != "Win's VPN":
        raise SignerError(f"{target_id} Play listing title is not Win's VPN")
    if len(short) > 80:
        raise SignerError(f"{target_id} short description exceeds Play's 80-character limit")
    if len(whats_new) > 500:
        raise SignerError(f"{target_id} what's new exceeds Play's 500-character limit")
    protocol = privacy.get("tunnel_protocol")
    candidate_protocol = candidate.get("tunnel_protocol")
    artifact = candidate.get("artifact")
    symbols = candidate.get("private_symbols")
    if (
        privacy.get("schema_version") != 1
        or privacy.get("contract") != spec["privacy_contract"]
        or privacy.get("canonical_release") != CANONICAL_RELEASE
        or privacy.get("application_id") != EXPECTED_APPLICATION_ID
        or privacy.get("version_name") != CANONICAL_MARKETING_VERSION
        or privacy.get("version_code") != spec["version_code"]
        or privacy.get("form_factor") != spec["form"]
        or privacy.get("privacy_policy_url") != "https://www.winsvpn.org/privacy/"
        or privacy.get("play_listing_name") != spec["play_listing_name"]
        or privacy.get("application_label") != spec["application_label"]
        or privacy.get("internet_permission") is not True
        or privacy.get("vpn_service") is not True
        or privacy.get("query_all_packages") is not True
        or privacy.get("query_all_packages_status") != "PENDING"
        or privacy.get("camouflage") is not spec["camouflage"]
        or privacy.get("tracking") is not False
        or privacy.get("data_collected") is not True
        or privacy.get("data_shared") is not False
        or privacy.get("listing_screenshot_inventory") != "owner-blocked"
        or privacy.get("collected_categories") != COLLECTED_CATEGORIES
        or privacy.get("not_collected") != NOT_COLLECTED_CATEGORIES
        or not _tunnel_protocol_matches(protocol)
    ):
        raise SignerError(
            f"{target_id} privacy label is not the canonical 1.0.16+33 phone/TV contract"
        )
    if spec["leanback"] and privacy.get("leanback") is not True:
        raise SignerError(f"{target_id} privacy label is not the canonical 1.0.16+33 phone/TV contract")
    if (
        signoff.get("schema_version") != 1
        or signoff.get("contract") != spec["signoff_contract"]
        or signoff.get("canonical_release") != CANONICAL_RELEASE
        or signoff.get("application_id") != EXPECTED_APPLICATION_ID
        or signoff.get("version_name") != CANONICAL_MARKETING_VERSION
        or signoff.get("version_code") != spec["version_code"]
        or signoff.get("form_factor") != spec["form"]
        or signoff.get("submission_approved") is not False
        or signoff.get("upload_authorized") is not False
        or signoff.get("query_all_packages_status") != "PENDING"
        or signoff.get("listing_screenshot_inventory") != "owner-blocked"
    ):
        raise SignerError(
            f"{target_id} owner signoff is not the canonical 1.0.16+33 phone/TV contract"
        )
    if (
        candidate.get("schema_version") != 1
        or candidate.get("contract") != spec["candidate_contract"]
        or candidate.get("canonical_release") != CANONICAL_RELEASE
        or candidate.get("target_id") != spec["target_id"]
        or candidate.get("apk_target_id") != spec["apk_target_id"]
        or candidate.get("package") != EXPECTED_APPLICATION_ID
        or candidate.get("version_name") != CANONICAL_MARKETING_VERSION
        or candidate.get("version_code") != spec["version_code"]
        or candidate.get("form_factor") != spec["form"]
        or type(artifact) is not dict
        or artifact.get("aab_path") != spec["aab_path"]
        or artifact.get("apk_path") != spec["apk_path"]
        or artifact.get("build_variant") != "release"
        or artifact.get("obfuscated") is not True
        or artifact.get("debug_artifact_allowed") is not False
        or artifact.get("owner_signing_required") is not True
        or artifact.get("produced") is not False
        or artifact.get("upload_performed") is not False
        or artifact.get("publication_authorized") is not False
        or type(symbols) is not dict
        or symbols.get("aab") != spec["private_aab"]
        or symbols.get("apk") != spec["private_apk"]
        or symbols.get("uploaded") is not False
        or type(candidate_protocol) is not dict
        or candidate_protocol.get("executed_on") != TUNNEL_PROTOCOL_CONTRACT["executed_on"]
        or candidate_protocol.get("primary") != TUNNEL_PROTOCOL_CONTRACT["primary"]
        or candidate_protocol.get("fallback") != TUNNEL_PROTOCOL_CONTRACT["fallback"]
    ):
        raise SignerError(
            f"{target_id} release candidate is not the canonical 1.0.16+33 phone/TV contract"
        )
    payload = {
        "canonical_release": CANONICAL_RELEASE,
        "application_id": EXPECTED_APPLICATION_ID,
        "version_name": CANONICAL_MARKETING_VERSION,
        "version_code": spec["version_code"],
        "form": spec["form"],
        "submission_approved": False,
        "upload_authorized": False,
        "query_all_packages_status": "PENDING",
        "listing_screenshot_inventory": "owner-blocked",
        "tunnel_protocol": TUNNEL_PROTOCOL_CONTRACT,
        "files": files,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    payload["sha256"] = _sha256_bytes(encoded)
    return payload


def _logical_parts(name: str) -> tuple[str, ...]:
    if (
        "\\" in name
        or "\x00" in name
        or name.startswith("/")
        or "//" in name
        or (len(name) >= 2 and name[1] == ":")
    ):
        raise SignerError("AAB ZIP member path alias is refused")
    pieces = name.split("/")
    if name.endswith("/"):
        pieces = pieces[:-1]
    if not pieces or any(part in {"", ".", ".."} for part in pieces):
        raise SignerError("AAB ZIP member path alias is refused")
    return tuple(pieces)


def _zip_extra_fields(extra: bytes, label: str) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    offset = 0
    while offset < len(extra):
        if offset + 4 > len(extra):
            # zipalign pads a local header's extra field with up to three zero
            # bytes so STORED data is aligned; any other short tail is refused.
            if label == "local-file entry" and not any(extra[offset:]):
                break
            raise SignerError(f"{label} ZIP extra field is truncated")
        field_id, size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if offset + size > len(extra) or field_id in fields:
            raise SignerError(f"{label} ZIP extra field is duplicated or truncated")
        fields[field_id] = extra[offset : offset + size]
        offset += size
    return fields


def _zip64_resolve(
    extra: bytes,
    label: str,
    values: tuple[int, int, int, int],
) -> tuple[int, int, int, int, bool]:
    fields = _zip_extra_fields(extra, label)
    payload = fields.get(0x0001)
    needs = tuple(
        value == sentinel
        for value, sentinel in zip(
            values, (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF)
        )
    )
    if payload is None:
        if any(needs):
            raise SignerError(f"{label} ZIP64 values are missing")
        return (*values, False)
    if not any(needs):
        raise SignerError(f"{label} contains contradictory unneeded ZIP64 values")
    resolved = list(values)
    offset = 0
    for index, needed in enumerate(needs):
        if not needed:
            continue
        width = 4 if index == 3 else 8
        if offset + width > len(payload):
            raise SignerError(f"{label} ZIP64 values are truncated")
        resolved[index] = int.from_bytes(payload[offset : offset + width], "little")
        offset += width
    if offset != len(payload):
        raise SignerError(f"{label} ZIP64 values are contradictory")
    return (*resolved, True)


def _decode_zip_name(raw: bytes, flags: int, label: str) -> str:
    try:
        return raw.decode("utf-8" if flags & 0x800 else "cp437")
    except UnicodeError as exc:
        raise SignerError(f"{label} ZIP member name encoding is invalid") from exc


def _apk_signing_block_start(data: bytes, central_offset: int) -> int:
    if central_offset < 24 or data[central_offset - 16 : central_offset] != b"APK Sig Block 42":
        return central_offset
    size = struct.unpack_from("<Q", data, central_offset - 24)[0]
    if size < 24 or size > central_offset - 8:
        raise SignerError("APK Signing Block size is invalid")
    start = central_offset - size - 8
    if struct.unpack_from("<Q", data, start)[0] != size:
        raise SignerError("APK Signing Block header and footer sizes disagree")
    return start


def _reconcile_raw_zip(
    data: bytes,
    archive: zipfile.ZipFile,
    *,
    allow_apk_signing_block: bool,
) -> None:
    """Cross-check local headers, descriptors, central records, and ZIP64."""

    if len(data) < 22:
        raise SignerError("ZIP end-of-central-directory record is missing")
    search_start = max(0, len(data) - 22 - 0xFFFF)
    eocd_offset = data.rfind(b"PK\x05\x06", search_start)
    if eocd_offset < 0 or eocd_offset + 22 > len(data):
        raise SignerError("ZIP end-of-central-directory record is missing")
    (
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = struct.unpack_from("<4H2LH", data, eocd_offset + 4)
    if eocd_offset + 22 + comment_size != len(data):
        raise SignerError("ZIP end-of-central-directory extent is not exact")
    if disk_number != 0 or central_disk != 0:
        raise SignerError("multi-disk ZIP archives are refused")
    locator_offset = eocd_offset - 20
    uses_zip64 = (
        disk_entries == 0xFFFF
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    )
    if uses_zip64:
        if locator_offset < 0 or data[locator_offset : locator_offset + 4] != b"PK\x06\x07":
            raise SignerError("ZIP64 locator is missing")
        zip64_disk, zip64_offset, disk_count = struct.unpack_from(
            "<LQL", data, locator_offset + 4
        )
        if zip64_disk != 0 or disk_count != 1 or zip64_offset + 56 != locator_offset:
            raise SignerError("ZIP64 locator offsets are inconsistent")
        if data[zip64_offset : zip64_offset + 4] != b"PK\x06\x06":
            raise SignerError("ZIP64 end-of-central-directory record is missing")
        record_size = struct.unpack_from("<Q", data, zip64_offset + 4)[0]
        if record_size != 44:
            raise SignerError("ZIP64 end-of-central-directory extent is not exact")
        (
            _made_by,
            needed,
            zip64_disk_number,
            zip64_central_disk,
            zip64_disk_entries,
            zip64_total_entries,
            zip64_central_size,
            zip64_central_offset,
        ) = struct.unpack_from("<2H2L4Q", data, zip64_offset + 12)
        if zip64_disk_number != 0 or zip64_central_disk != 0:
            raise SignerError("multi-disk ZIP64 archives are refused")
        disk_entries = int(zip64_disk_entries)
        total_entries = int(zip64_total_entries)
        central_size = int(zip64_central_size)
        central_offset = int(zip64_central_offset)
        central_extent = zip64_offset
    else:
        if locator_offset >= 0 and data[locator_offset : locator_offset + 4] == b"PK\x06\x07":
            raise SignerError("ZIP64 locator contradicts the classic directory record")
        central_extent = eocd_offset
    if disk_entries != total_entries or total_entries != len(archive.infolist()):
        raise SignerError("ZIP central-directory entry counts disagree")
    if central_offset + central_size != central_extent:
        raise SignerError("ZIP central-directory size or offset is inconsistent")

    records: list[dict[str, object]] = []
    cursor = central_offset
    for index in range(total_entries):
        if cursor + 46 > central_extent or data[cursor : cursor + 4] != b"PK\x01\x02":
            raise SignerError("ZIP central-directory record is truncated")
        (
            _made_by,
            needed,
            flags,
            method,
            modified_time,
            modified_date,
            crc,
            compressed32,
            uncompressed32,
            name_size,
            extra_size,
            member_comment_size,
            start_disk32,
            _internal,
            _external,
            local_offset32,
        ) = struct.unpack_from("<6H3L5H2L", data, cursor + 4)
        end = cursor + 46 + name_size + extra_size + member_comment_size
        if end > central_extent:
            raise SignerError("ZIP central-directory record extent is truncated")
        raw_name = data[cursor + 46 : cursor + 46 + name_size]
        extra = data[
            cursor + 46 + name_size : cursor + 46 + name_size + extra_size
        ]
        (
            uncompressed,
            compressed,
            local_offset,
            start_disk,
            _central_zip64,
        ) = _zip64_resolve(
            extra,
            "central-directory entry",
            (uncompressed32, compressed32, local_offset32, start_disk32),
        )
        if start_disk != 0:
            raise SignerError("multi-disk ZIP member is refused")
        name = _decode_zip_name(raw_name, flags, "central-directory entry")
        info = archive.infolist()[index]
        if (
            info.filename != name
            or info.header_offset != local_offset
            or info.CRC != crc
            or info.compress_size != compressed
            or info.file_size != uncompressed
            or info.compress_type != method
            or info.flag_bits != flags
            or info.extract_version != needed
        ):
            raise SignerError("ZIP parser and central-directory values disagree")
        records.append(
            {
                "name": name,
                "raw_name": raw_name,
                "needed": needed,
                "flags": flags,
                "method": method,
                "time": modified_time,
                "date": modified_date,
                "crc": crc,
                "compressed": compressed,
                "uncompressed": uncompressed,
                "offset": local_offset,
            }
        )
        cursor = end
    if cursor != central_extent:
        raise SignerError("ZIP central-directory extent contains trailing records")
    ordered = sorted(records, key=lambda item: int(item["offset"]))
    if not ordered or int(ordered[0]["offset"]) != 0:
        raise SignerError("ZIP local-file offsets do not start at byte zero")
    if len({int(item["offset"]) for item in ordered}) != len(ordered):
        raise SignerError("ZIP local-file offsets are duplicated")
    payload_extent = (
        _apk_signing_block_start(data, central_offset)
        if allow_apk_signing_block
        else central_offset
    )
    if not allow_apk_signing_block and _apk_signing_block_start(data, central_offset) != central_offset:
        raise SignerError("AAB ZIP contains an APK Signing Block")
    for index, record in enumerate(ordered):
        offset = int(record["offset"])
        boundary = (
            int(ordered[index + 1]["offset"])
            if index + 1 < len(ordered)
            else payload_extent
        )
        if offset + 30 > boundary or data[offset : offset + 4] != b"PK\x03\x04":
            raise SignerError("ZIP local-file header is truncated")
        (
            local_needed,
            local_flags,
            local_method,
            local_time,
            local_date,
            local_crc,
            local_compressed32,
            local_uncompressed32,
            local_name_size,
            local_extra_size,
        ) = struct.unpack_from("<5H3L2H", data, offset + 4)
        header_end = offset + 30 + local_name_size + local_extra_size
        if header_end > boundary:
            raise SignerError("ZIP local-file header extent is truncated")
        local_name = data[offset + 30 : offset + 30 + local_name_size]
        local_extra = data[offset + 30 + local_name_size : header_end]
        (
            local_uncompressed,
            local_compressed,
            _unused_offset,
            _unused_disk,
            local_uses_zip64,
        ) = _zip64_resolve(
            local_extra,
            "local-file entry",
            (local_uncompressed32, local_compressed32, 0, 0),
        )
        if (
            local_name != record["raw_name"]
            or local_needed != record["needed"]
            or local_flags != record["flags"]
            or local_method != record["method"]
            or local_time != record["time"]
            or local_date != record["date"]
        ):
            raise SignerError("ZIP local header and central directory disagree")
        descriptor_present = bool(local_flags & 0x08)
        expected_crc = int(record["crc"])
        expected_compressed = int(record["compressed"])
        expected_uncompressed = int(record["uncompressed"])
        if local_uses_zip64 and local_needed < 45:
            raise SignerError("ZIP64 local-file entry has an invalid extraction version")
        if (
            not local_uses_zip64
            and (expected_compressed > 0xFFFFFFFF or expected_uncompressed > 0xFFFFFFFF)
        ):
            raise SignerError("ZIP64 member sizes are absent from the local-file entry")
        if descriptor_present:
            if local_crc not in {0, expected_crc}:
                raise SignerError("ZIP local-header CRC contradicts the data descriptor")
            if (
                local_compressed not in {0, expected_compressed}
                or local_uncompressed not in {0, expected_uncompressed}
            ):
                raise SignerError("ZIP local-header sizes contradict the data descriptor")
        elif (
            local_crc != expected_crc
            or local_compressed != expected_compressed
            or local_uncompressed != expected_uncompressed
        ):
            raise SignerError("ZIP local-header CRC or sizes disagree with the central directory")
        data_end = header_end + expected_compressed
        if data_end > boundary:
            raise SignerError("ZIP compressed member extent exceeds its local-file boundary")
        if descriptor_present:
            raw_descriptor = data[data_end:boundary]
            expected_length = 20 if local_uses_zip64 else 12
            if len(raw_descriptor) == expected_length:
                descriptor = raw_descriptor
            elif len(raw_descriptor) == expected_length + 4:
                if raw_descriptor[:4] != b"PK\x07\x08":
                    raise SignerError("ZIP data descriptor signature is invalid")
                descriptor = raw_descriptor[4:]
            else:
                raise SignerError("ZIP data descriptor extent is not exact")
            if local_uses_zip64:
                descriptor_crc, descriptor_compressed, descriptor_uncompressed = (
                    struct.unpack("<LQQ", descriptor)
                )
            else:
                descriptor_crc, descriptor_compressed, descriptor_uncompressed = (
                    struct.unpack("<3L", descriptor)
                )
            if (
                descriptor_crc != expected_crc
                or descriptor_compressed != expected_compressed
                or descriptor_uncompressed != expected_uncompressed
            ):
                raise SignerError("ZIP data descriptor and central directory disagree")
        elif data_end != boundary:
            raise SignerError("ZIP local-file extent contains unauthenticated trailing bytes")


def _validate_zip_limits(
    archive: zipfile.ZipFile,
    *,
    depth: int = 0,
    recursive_budget: dict[str, int] | None = None,
) -> None:
    if depth < 0 or depth > MAX_AAB_NESTED_ARCHIVE_DEPTH:
        raise SignerError("AAB nested archive depth exceeds the strict limit")
    if recursive_budget is None:
        recursive_budget = {"entries": 0, "bytes": 0}
    infos = archive.infolist()
    if not infos or len(infos) > MAX_AAB_ZIP_ENTRIES:
        raise SignerError("AAB ZIP entry count is empty or exceeds the strict limit")
    exact: set[str] = set()
    folded: dict[str, str] = {}
    total_size = 0
    for info in infos:
        name = info.filename
        if len(name.encode("utf-8", errors="surrogatepass")) > MAX_AAB_ZIP_MEMBER_NAME_BYTES:
            raise SignerError("AAB ZIP member name exceeds the strict limit")
        parts = _logical_parts(name)
        logical = "/".join(parts)
        casefolded = logical.casefold()
        if name in exact:
            raise SignerError("AAB contains duplicate ZIP member names")
        if casefolded in folded:
            raise SignerError(f"AAB ZIP member path alias is refused: {name}")
        exact.add(name)
        folded[casefolded] = name
        if info.flag_bits & 0x1:
            raise SignerError("AAB ZIP encrypted members are refused")
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise SignerError("AAB ZIP compression method is not allowed")
        file_type = stat.S_IFMT(info.external_attr >> 16)
        if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise SignerError("AAB ZIP special-file members are refused")
        if info.file_size < 0 or info.compress_size < 0:
            raise SignerError("AAB ZIP member size is invalid")
        if info.file_size > MAX_AAB_ZIP_MEMBER_BYTES:
            raise SignerError("AAB ZIP member exceeds the strict uncompressed limit")
        total_size += info.file_size
        if total_size > MAX_AAB_ZIP_TOTAL_BYTES:
            raise SignerError("AAB ZIP aggregate size exceeds the strict limit")
        if info.file_size:
            if info.compress_size == 0:
                raise SignerError("AAB ZIP member has an invalid compression ratio")
            if info.file_size > info.compress_size * MAX_AAB_ZIP_COMPRESSION_RATIO:
                raise SignerError("AAB ZIP member exceeds the strict compression ratio")
        recursive_budget["entries"] += 1
        recursive_budget["bytes"] += info.file_size
        if recursive_budget["entries"] > MAX_AAB_RECURSIVE_ZIP_ENTRIES:
            raise SignerError("AAB recursive ZIP entry count exceeds the strict limit")
        if recursive_budget["bytes"] > MAX_AAB_ZIP_TOTAL_BYTES:
            raise SignerError("AAB recursive ZIP aggregate size exceeds the strict limit")
        if info.is_dir() or info.file_size < 4:
            continue
        with archive.open(info, "r") as member:
            prefix = member.read(4)
            if prefix not in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}:
                continue
            if depth >= MAX_AAB_NESTED_ARCHIVE_DEPTH:
                raise SignerError("AAB nested archive depth exceeds the strict limit")
            if info.file_size > MAX_AAB_NESTED_ARCHIVE_BYTES:
                raise SignerError("AAB nested archive exceeds the strict size limit")
            nested_payload = prefix + member.read(MAX_AAB_NESTED_ARCHIVE_BYTES + 1)
        if len(nested_payload) != info.file_size:
            raise SignerError("AAB nested archive size is inconsistent")
        try:
            with zipfile.ZipFile(io.BytesIO(nested_payload)) as nested:
                _reconcile_raw_zip(
                    nested_payload,
                    nested,
                    allow_apk_signing_block=False,
                )
                _validate_zip_limits(
                    nested,
                    depth=depth + 1,
                    recursive_budget=recursive_budget,
                )
        except zipfile.BadZipFile as exc:
            raise SignerError("AAB nested archive is malformed") from exc


def _open_held_zip(
    data: bytes, *, allow_apk_signing_block: bool = False
) -> zipfile.ZipFile:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise SignerError("invalid AAB ZIP archive") from exc
    try:
        _reconcile_raw_zip(
            data,
            archive,
            allow_apk_signing_block=allow_apk_signing_block,
        )
        _validate_zip_limits(archive)
        bad_member = archive.testzip()
        if bad_member is not None:
            raise SignerError(f"AAB ZIP CRC failure: {bad_member}")
        return archive
    except SignerError:
        archive.close()
        raise
    except Exception as exc:
        archive.close()
        raise SignerError("AAB ZIP decompression failed closed") from exc


def _zip_contract(archive: zipfile.ZipFile) -> tuple[list[str], frozenset[str], frozenset[str]]:
    infos = archive.infolist()
    raw_names = [info.filename for info in infos]
    if len(raw_names) != len(set(raw_names)):
        raise SignerError("AAB contains duplicate ZIP member names")
    logical_fold: dict[str, str] = {}
    modules: set[str] = set()
    abis: set[str] = set()
    for info in infos:
        name = info.filename
        parts = _logical_parts(name)
        folded = "/".join(part.casefold() for part in parts)
        previous = logical_fold.get(folded)
        if previous is not None:
            raise SignerError(f"AAB ZIP member path alias is refused: {name}")
        logical_fold[folded] = name
        root = parts[0]
        if root == BUNDLE_CONFIG_MEMBER and len(parts) == 1:
            continue
        if root in {"META-INF", "BUNDLE-METADATA"}:
            continue
        if root.casefold() in {"meta-inf", "bundle-metadata", "bundleconfig.pb"}:
            raise SignerError(f"AAB ZIP member path alias is refused: {name}")
        modules.add(root)
        native = NATIVE_LIB_RE.fullmatch(name)
        if native is not None:
            if info.is_dir() or info.file_size <= 0 or stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK:
                raise SignerError(f"AAB native library is empty, a directory, or a symlink: {name}")
            abis.add(native.group(1))
    if len({module.casefold() for module in modules}) != len(modules):
        raise SignerError("AAB contains duplicate modules")
    if modules != {"base"}:
        raise SignerError("AAB split/module contract is not exact")
    if raw_names.count(MANIFEST_MEMBER) != 1:
        raise SignerError("AAB must contain exactly one base proto manifest")
    if raw_names.count(BUNDLE_CONFIG_MEMBER) != 1:
        raise SignerError("AAB must contain exactly one BundleConfig.pb")
    return raw_names, frozenset(modules), frozenset(abis)


def _der_read(
    blob: bytes, offset: int, *, expected: int | None = None, depth: int = 0
) -> tuple[int, bytes, int]:
    if depth > MAX_DER_DEPTH:
        raise SignerError("AAB PKCS#7 DER nesting is too deep")
    if offset < 0 or offset >= len(blob):
        raise SignerError("AAB PKCS#7 is truncated")
    tag = blob[offset]
    if expected is not None and tag != expected:
        raise SignerError("AAB PKCS#7 DER tag mismatch")
    if tag & 0x1F == 0x1F:
        raise SignerError("AAB PKCS#7 DER tag is malformed")
    cursor = offset + 1
    if cursor >= len(blob):
        raise SignerError("AAB PKCS#7 is truncated")
    length_byte = blob[cursor]
    cursor += 1
    if length_byte == 0x80:
        raise SignerError("AAB PKCS#7 indefinite length is refused")
    if length_byte < 0x80:
        length = length_byte
    else:
        count = length_byte & 0x7F
        if count < 1 or count > 4 or cursor + count > len(blob):
            raise SignerError("AAB PKCS#7 DER length is malformed")
        if blob[cursor] == 0:
            raise SignerError("AAB PKCS#7 DER length is malformed")
        length = int.from_bytes(blob[cursor : cursor + count], "big")
        cursor += count
    if length < 0 or length > MAX_PKCS7 or cursor + length > len(blob):
        raise SignerError("AAB PKCS#7 DER length is malformed")
    return tag, blob[cursor : cursor + length], cursor + length


def _decode_oid(content: bytes) -> str:
    if not content:
        raise SignerError("AAB PKCS#7 OID is malformed")
    first = content[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80:
            if value > 1 << 28:
                raise SignerError("AAB PKCS#7 OID is malformed")
            continue
        parts.append(str(value))
        value = 0
    if content[-1] & 0x80:
        raise SignerError("AAB PKCS#7 OID is malformed")
    return ".".join(parts)


def _parse_certificate_set(content: bytes) -> list[bytes]:
    certificates: list[bytes] = []
    offset = 0
    while offset < len(content):
        if len(certificates) >= MAX_PKCS7_CERTS:
            raise SignerError("AAB PKCS#7 certificate count bound exceeded")
        tag, body, end = _der_read(content, offset, expected=0x30, depth=2)
        del tag, body
        certificates.append(content[offset:end])
        offset = end
    if len(certificates) != 1:
        raise SignerError("AAB PKCS#7 must contain exactly one certificate")
    return certificates


def _parse_pkcs7_certificate(blob: bytes) -> bytes:
    if len(blob) > MAX_PKCS7:
        raise SignerError("AAB PKCS#7 size bound exceeded")
    _tag, content, end = _der_read(blob, 0, expected=0x30)
    if end != len(blob) and blob[end:].strip(b"\x00") != b"":
        raise SignerError("AAB PKCS#7 has trailing data")
    offset = 0
    _oid_tag, oid_content, offset = _der_read(content, offset, expected=0x06, depth=1)
    if _decode_oid(oid_content) != SIGNED_DATA_OID:
        raise SignerError("AAB PKCS#7 is not signedData")
    _wrap_tag, signed_wrapper, offset = _der_read(content, offset, expected=0xA0, depth=1)
    if offset != len(content):
        raise SignerError("AAB PKCS#7 has unexpected SignedData siblings")
    _signed_tag, signed, signed_end = _der_read(signed_wrapper, 0, expected=0x30, depth=2)
    if signed_end != len(signed_wrapper):
        raise SignerError("AAB PKCS#7 SignedData framing is malformed")
    cursor = 0
    _ver_tag, _version, cursor = _der_read(signed, cursor, expected=0x02, depth=3)
    _algs_tag, _digest_algs, cursor = _der_read(signed, cursor, expected=0x31, depth=3)
    _ci_tag, _content_info, cursor = _der_read(signed, cursor, expected=0x30, depth=3)
    if cursor >= len(signed) or signed[cursor] != 0xA0:
        raise SignerError("AAB PKCS#7 lacks certificates")
    _certs_tag, cert_content, cursor = _der_read(signed, cursor, expected=0xA0, depth=3)
    return _parse_certificate_set(cert_content)[0]


def _certificate_common_names(cert: bytes) -> list[str]:
    names: list[str] = []
    index = 0
    while True:
        position = cert.find(CN_OID_DER, index)
        if position < 0:
            return names
        rest = cert[position + len(CN_OID_DER) :]
        if rest and rest[0] in {0x0C, 0x13, 0x14, 0x16, 0x1B}:
            _tag, body, _end = _der_read(rest, 0, depth=8)
            names.append(_decode_utf8(body, "AAB signer certificate CN"))
        index = position + 1


def _signer_set_from_archive(archive: zipfile.ZipFile, names: list[str]) -> dict[str, str]:
    upper_names = [name.upper() for name in names]
    if len(upper_names) != len(set(upper_names)):
        raise SignerError("AAB contains case-colliding ZIP member names")
    block_files = [
        name
        for name in upper_names
        if name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC"))
    ]
    signature_files = [
        name for name in upper_names if name.startswith("META-INF/") and name.endswith(".SF")
    ]
    if len(block_files) != 1 or len(signature_files) != 1:
        raise SignerError("AAB must contain exactly one signature block and one .SF file")
    if block_files[0].rsplit(".", 1)[0] != signature_files[0].rsplit(".", 1)[0]:
        raise SignerError("AAB signature block and .SF signer names do not match")
    block_name = names[upper_names.index(block_files[0])]
    certificate = _parse_pkcs7_certificate(archive.read(block_name))
    common_names = _certificate_common_names(certificate)
    subject = ", ".join(common_names)
    if any(DEBUG_SIGNER_MARKER in name.casefold() for name in common_names):
        raise SignerError("AAB is signed by the Android debug signer")
    return {
        "certificate_sha256": _sha256_bytes(certificate),
        "certificate_subject": subject,
        "signature_file": names[upper_names.index(signature_files[0])],
        "block_file": block_name,
    }


def _canonical_component_name(package: str, raw: str) -> str:
    if not raw or raw != raw.strip():
        raise SignerError("AAB manifest component identity is malformed")
    if raw.startswith("."):
        return package + raw
    if "." not in raw:
        return f"{package}.{raw}"
    return raw


def _manifest_bool(value: str | None, label: str) -> bool | None:
    if value is None:
        return None
    normalized = value.casefold()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise SignerError(f"AAB manifest {label} is not a decoded boolean")


def _manifest_int(value: str | None, label: str) -> int:
    if value is None or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        raise SignerError(f"AAB manifest {label} is not a decoded integer")
    return int(value)


def _manifest_named_children(node: ET.Element, path: str, label: str) -> frozenset[str]:
    names: list[str] = []
    for child in node.findall(path):
        name = child.get(ANDROID + "name")
        if not name:
            raise SignerError(f"AAB manifest {label} identity is not decoded")
        names.append(name)
    if len(names) != len(set(names)):
        raise SignerError(f"AAB manifest contains duplicate {label} identities")
    return frozenset(names)


def _manifest_projection_node(node: ET.Element) -> tuple[object, ...]:
    """Canonicalize the complete manifest tree, including every security field."""

    if type(node.tag) is not str or not node.tag:
        raise SignerError("AAB manifest contains a malformed element tag")
    attributes: list[tuple[str, str]] = []
    for key, raw_value in node.attrib.items():
        if type(key) is not str or type(raw_value) is not str:
            raise SignerError("AAB manifest contains a malformed attribute")
        value = raw_value
        if key == ANDROID + "screenOrientation" and value == "0":
            value = "landscape"
        attributes.append((key, value))
    text = node.text or ""
    if text.strip():
        raise SignerError("AAB manifest contains unexpected element text")
    children = tuple(
        sorted(
            (_manifest_projection_node(child) for child in list(node)),
            key=repr,
        )
    )
    return node.tag, tuple(sorted(attributes)), children


def _manifest_identity(root: ET.Element) -> dict[str, object]:
    package = root.get("package")
    version_name = root.get(ANDROID + "versionName")
    version_code_text = root.get(ANDROID + "versionCode")
    if package is None or version_name is None or version_code_text is None:
        raise SignerError("AAB proto manifest lacks package or version identity")
    version_code = _manifest_int(version_code_text, "versionCode")
    uses_sdk = root.findall("uses-sdk")
    if len(uses_sdk) != 1:
        raise SignerError("AAB manifest must decode exactly one uses-sdk posture")
    min_sdk = _manifest_int(uses_sdk[0].get(ANDROID + "minSdkVersion"), "minSdkVersion")
    target_sdk = _manifest_int(
        uses_sdk[0].get(ANDROID + "targetSdkVersion"), "targetSdkVersion"
    )
    feature_nodes = root.findall("uses-feature")
    feature_names: set[str] = set()
    required: dict[str, str] = {}
    for node in feature_nodes:
        name = node.get(ANDROID + "name")
        if not name or name in feature_names:
            raise SignerError("AAB manifest feature identity is not exact")
        decoded_required = _manifest_bool(node.get(ANDROID + "required", "true"), "feature required")
        if decoded_required is None:
            raise SignerError("AAB manifest feature required flag is not decoded")
        feature_names.add(name)
        required[name] = "true" if decoded_required else "false"
    activity_nodes = root.findall("./application/activity")
    activity_names: list[str] = []
    activity_exported: dict[str, bool | None] = {}
    activity_categories: dict[str, frozenset[str]] = {}
    activity_actions: dict[str, frozenset[str]] = {}
    activity_orientations: dict[str, str | None] = {}
    for node in activity_nodes:
        raw_name = node.get(ANDROID + "name")
        if not raw_name:
            raise SignerError("AAB manifest activity identity is not decoded")
        name = _canonical_component_name(package, raw_name)
        activity_names.append(name)
        activity_exported[name] = _manifest_bool(
            node.get(ANDROID + "exported"), "activity exported"
        )
        activity_categories[name] = _manifest_named_children(
            node, "./intent-filter/category", "activity category"
        )
        activity_actions[name] = _manifest_named_children(
            node, "./intent-filter/action", "activity action"
        )
        activity_orientations[name] = node.get(ANDROID + "screenOrientation")
    if len(activity_names) != len(set(activity_names)):
        raise SignerError("AAB manifest contains duplicate activity identities")
    leanback_launcher_activities: set[str] = set()
    leanback_launcher_components: dict[str, str] = {}
    categories: set[str | None] = set()
    for activity in activity_nodes:
        raw_activity_name = activity.get(ANDROID + "name")
        activity_name = (
            _canonical_component_name(package, raw_activity_name)
            if raw_activity_name
            else None
        )
        component_categories = activity_categories.get(activity_name or "", frozenset())
        categories.update(component_categories)
        if (
            activity_name
            and "android.intent.category.LEANBACK_LAUNCHER" in component_categories
        ):
            leanback_launcher_activities.add(activity_name)
            leanback_launcher_components[activity_name] = activity_name
    alias_nodes = root.findall("./application/activity-alias")
    alias_names: list[str] = []
    alias_posture: dict[str, tuple[str, bool | None, frozenset[str], frozenset[str]]] = {}
    for node in alias_nodes:
        raw_name = node.get(ANDROID + "name")
        raw_target = node.get(ANDROID + "targetActivity")
        if not raw_name or not raw_target:
            raise SignerError("AAB manifest activity-alias identity is not decoded")
        alias_name = _canonical_component_name(package, raw_name)
        target_name = _canonical_component_name(package, raw_target)
        alias_names.append(alias_name)
        alias_posture[alias_name] = (
            target_name,
            _manifest_bool(node.get(ANDROID + "exported"), "activity-alias exported"),
            _manifest_named_children(
                node, "./intent-filter/category", "activity-alias category"
            ),
            _manifest_named_children(
                node, "./intent-filter/action", "activity-alias action"
            ),
        )
    if len(alias_names) != len(set(alias_names)) or set(alias_names) & set(activity_names):
        raise SignerError("AAB manifest contains duplicate activity identities")
    for alias in alias_nodes:
        raw_alias_name = alias.get(ANDROID + "name")
        alias_categories = _manifest_named_children(
            alias, "./intent-filter/category", "activity-alias category"
        )
        categories.update(alias_categories)
        if "android.intent.category.LEANBACK_LAUNCHER" not in alias_categories:
            continue
        raw_target = alias.get(ANDROID + "targetActivity")
        if not raw_alias_name or not raw_target:
            raise SignerError("AAB manifest leanback activity-alias is malformed")
        alias_name = _canonical_component_name(package, raw_alias_name)
        target_name = _canonical_component_name(package, raw_target)
        if target_name not in activity_names:
            raise SignerError("AAB manifest leanback activity-alias target is missing")
        leanback_launcher_activities.add(target_name)
        leanback_launcher_components[alias_name] = target_name
    applications = root.findall("application")
    if len(applications) != 1:
        raise SignerError("AAB manifest must decode exactly one application")
    application = applications[0]
    permissions = set(_manifest_named_children(root, "uses-permission", "permission"))
    services: dict[str, tuple[str | None, bool | None, frozenset[str]]] = {}
    vpn_services: list[str] = []
    for node in root.findall("./application/service"):
        raw_name = node.get(ANDROID + "name")
        if not raw_name:
            raise SignerError("AAB manifest service identity is not decoded")
        name = _canonical_component_name(package, raw_name)
        if name in services:
            raise SignerError("AAB manifest contains duplicate service identities")
        permission = node.get(ANDROID + "permission")
        exported = _manifest_bool(node.get(ANDROID + "exported"), "service exported")
        actions = _manifest_named_children(node, "./intent-filter/action", "service action")
        services[name] = (permission, exported, actions)
        if permission == "android.permission.BIND_VPN_SERVICE":
            vpn_services.append(name)
    metadata: dict[str, str] = {}
    for node in application.findall("meta-data"):
        name = node.get(ANDROID + "name")
        value = node.get(ANDROID + "value")
        if not name or value is None or name in metadata:
            raise SignerError("AAB manifest application metadata is not exact")
        metadata[name] = value
    wear_standalone = _manifest_bool(
        metadata.get("com.google.android.wearable.standalone"),
        "Wear standalone posture",
    )
    return {
        "package": package,
        "version_name": version_name,
        "version_code": version_code,
        "is_tv": (
            "android.software.leanback" in feature_names
            and "android.intent.category.LEANBACK_LAUNCHER" in categories
        ),
        "is_wear": "android.hardware.type.watch" in feature_names,
        "has_leanback_launcher": "android.intent.category.LEANBACK_LAUNCHER" in categories,
        "feature_required": required,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "application_label": application.get(ANDROID + "label"),
        "application_icon": application.get(ANDROID + "icon"),
        "application_banner": application.get(ANDROID + "banner"),
        "debuggable": _manifest_bool(application.get(ANDROID + "debuggable"), "debuggable"),
        "uses_cleartext_traffic": _manifest_bool(
            application.get(ANDROID + "usesCleartextTraffic"), "usesCleartextTraffic"
        ),
        "network_security_config": application.get(ANDROID + "networkSecurityConfig"),
        "activities": activity_names,
        "activity_exported": activity_exported,
        "activity_categories": activity_categories,
        "activity_actions": activity_actions,
        "activity_orientations": activity_orientations,
        "activity_aliases": alias_posture,
        "leanback_launcher_activities": frozenset(leanback_launcher_activities),
        "leanback_launcher_components": leanback_launcher_components,
        "permissions": permissions,
        "services": services,
        "vpn_services": vpn_services,
        "wear_standalone": wear_standalone,
        "manifest_projection": _manifest_projection_node(root),
    }


def _embedded_metadata(names: list[str]) -> dict[str, object]:
    debug = [name for name in names if DEBUG_SYMBOL_RE.fullmatch(name)]
    unofficial = [
        name
        for name in names
        if name.casefold().endswith("proguard.map") and name != OFFICIAL_PROGUARD_MAP
    ]
    if unofficial:
        raise SignerError("AAB contains a non-official proguard.map")
    if names.count(OFFICIAL_PROGUARD_MAP) > 1:
        raise SignerError("AAB contains duplicate official R8 proguard.map members")
    libapp_abis: set[str] = set()
    libflutter_abis: set[str] = set()
    for name in debug:
        match = DEBUG_SYMBOL_RE.fullmatch(name)
        if match is None:
            continue
        abi, libname = match.group(1), match.group(2)
        if libname == "libapp":
            libapp_abis.add(abi)
        else:
            libflutter_abis.add(abi)
    return {
        "libapp_debug": bool(libapp_abis),
        "libflutter_debug": bool(libflutter_abis),
        "libapp_debug_abis": frozenset(libapp_abis),
        "libflutter_debug_abis": frozenset(libflutter_abis),
        "proguard_map": names.count(OFFICIAL_PROGUARD_MAP) == 1,
    }


def _native_engine_inventory(
    archive: zipfile.ZipFile, names: list[str], *, aab: bool
) -> tuple[dict[str, set[str]], tuple[str, ...]]:
    engines: dict[str, set[str]] = {}
    forbidden: list[str] = []
    prefix = "base/lib/" if aab else "lib/"
    for name in names:
        if name.endswith("/") or not name.startswith(prefix) or not name.endswith(".so"):
            continue
        parts = name.split("/")
        if (aab and len(parts) != 4) or (not aab and len(parts) != 3):
            continue
        abi = parts[-2]
        basename = parts[-1]
        payload = archive.read(name)
        if basename in PHONE_TV_REQUIRED_NATIVE_ENGINES | PHONE_TV_FORBIDDEN_NATIVE_ENGINES:
            if not payload.startswith(b"\x7fELF"):
                raise SignerError(f"native VPN engine is not ELF: {name}")
        if basename in PHONE_TV_FORBIDDEN_NATIVE_ENGINES:
            forbidden.append(basename)
        if basename in PHONE_TV_REQUIRED_NATIVE_ENGINES:
            engines.setdefault(abi, set()).add(basename)
    return engines, tuple(sorted(set(forbidden)))


def _private_symbol_members(names: list[str], *, aab: bool) -> tuple[str, ...]:
    leaked: list[str] = []
    for name in names:
        if PRIVATE_SYMBOL_MEMBER_RE.search(name) is None:
            continue
        if aab and name == OFFICIAL_PROGUARD_MAP:
            continue
        if aab and DEBUG_SYMBOL_RE.fullmatch(name):
            continue
        leaked.append(name)
    return tuple(leaked)


def analyze_held_aab(data: bytes) -> dict[str, object]:
    with _open_held_zip(data) as archive:
        names, modules, abis = _zip_contract(archive)
        signer = _signer_set_from_archive(archive, names)
        _verify_manifest_coverage(archive, names, signer["signature_file"])
        root = _decode_proto_manifest(archive.read(MANIFEST_MEMBER))
        identity = _manifest_identity(root)
        metadata = _embedded_metadata(names)
        engines, forbidden = _native_engine_inventory(archive, names, aab=True)
        r8 = None
        if metadata["proguard_map"]:
            r8 = validate_r8_mapping_bytes(archive.read(OFFICIAL_PROGUARD_MAP))
        leaked = _private_symbol_members(names, aab=True)
        archive.read(BUNDLE_CONFIG_MEMBER)
    identity.update(
        {
            "modules": modules,
            "abis": abis,
            "metadata": metadata,
            "native_engines": engines,
            "forbidden_native": forbidden,
            "private_symbols_leaked": bool(leaked),
            "r8": r8,
            "certificate_sha256": signer["certificate_sha256"],
            "certificate_subject": signer["certificate_subject"],
            "decoder": "closed-format",
        }
    )
    return identity


def _cross_check_bundletool_identity(data: bytes, analysis: dict[str, object]) -> None:
    _cross_check_bundletool_manifest(_bundletool_dump_manifest(data), analysis)


ANDROID_ATTRIBUTE_NAMESPACE = "{http://schemas.android.com/apk/res/android}"


def _canonical_symbolic_value(name: str, value: str) -> str:
    # The held parser keeps a symbolic attribute's raw text, bundletool prints
    # its compiled integer (hex or decimal). Both become one decimal string;
    # an unknown symbolic name is returned unchanged and so never matches.
    names = SYMBOLIC_INT_ATTRIBUTES.get(name)
    if names is None:
        return value
    if re.fullmatch(r"0x[0-9a-fA-F]+", value):
        return str(int(value, 16))
    if re.fullmatch(r"-?(0|[1-9][0-9]*)", value):
        return str(int(value))
    flags = 0
    for part in value.split("|"):
        if part not in names:
            return value
        flags |= names[part]
    return str(flags)


def _canonical_projection(node: object) -> object:
    if type(node) is tuple:
        if (
            len(node) == 2
            and type(node[0]) is str
            and type(node[1]) is str
            and node[0].startswith(ANDROID_ATTRIBUTE_NAMESPACE)
        ):
            name = node[0][len(ANDROID_ATTRIBUTE_NAMESPACE):]
            return (node[0], _canonical_symbolic_value(name, node[1]))
        return tuple(_canonical_projection(child) for child in node)
    return node


def _cross_check_bundletool_manifest(
    raw: bytes, analysis: dict[str, object]
) -> None:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise SignerError("pinned bundletool returned malformed manifest XML") from exc
    parsed = _manifest_identity(root)
    package = parsed["package"]
    version_name = parsed["version_name"]
    version_code = parsed["version_code"]
    if (
        package != analysis.get("package")
        or version_name != analysis.get("version_name")
        or version_code != analysis.get("version_code")
    ):
        raise SignerError("pinned bundletool identity disagrees with the held AAB parser")
    parsed_orientations = parsed.get("activity_orientations")
    held_orientations = analysis.get("activity_orientations")
    if type(parsed_orientations) is not dict or type(held_orientations) is not dict:
        raise SignerError("pinned bundletool manifest posture is not exact")

    def normalized_orientation(value: object) -> object:
        return "landscape" if value in {"landscape", "0"} else value

    normalized_parsed_orientations = {
            name: normalized_orientation(value)
            for name, value in parsed_orientations.items()
        }
    normalized_held_orientations = {
            name: normalized_orientation(value)
            for name, value in held_orientations.items()
        }
    security_posture_keys = (
        "manifest_projection",
        "permissions",
        "services",
        "vpn_services",
        "activities",
        "activity_exported",
        "activity_categories",
        "activity_actions",
        "activity_aliases",
        "leanback_launcher_activities",
        "leanback_launcher_components",
        "feature_required",
        "application_label",
        "application_icon",
        "application_banner",
        "debuggable",
        "uses_cleartext_traffic",
        "network_security_config",
        "min_sdk",
        "target_sdk",
        "is_tv",
        "is_wear",
        "has_leanback_launcher",
        "wear_standalone",
    )
    def posture(source: dict[str, object], key: str) -> object:
        value = source.get(key)
        return _canonical_projection(value) if key == "manifest_projection" else value

    if normalized_parsed_orientations != normalized_held_orientations or any(
        posture(parsed, key) != posture(analysis, key) for key in security_posture_keys
    ):
        raise SignerError(
            "pinned bundletool manifest posture disagrees with the held AAB parser"
        )


def _enforce_target_identity(target_id: str, analysis: dict[str, object]) -> None:
    expected_package, expected_version_name, expected_version_code = _reviewed_target_identity(
        target_id
    )
    if (
        analysis.get("package") != expected_package
        or analysis.get("version_name") != expected_version_name
        or analysis.get("version_code") != expected_version_code
    ):
        raise SignerError("AAB application or version identity belongs to another target")
    expected_form = {
        "android-phone-tablet-aab": (False, False),
        "android-tv-aab": (True, False),
        "wear-os-aab": (False, True),
    }[target_id]
    if (analysis.get("is_tv"), analysis.get("is_wear")) != expected_form:
        raise SignerError("AAB form-factor identity belongs to another exact target")
    if analysis.get("modules") != frozenset({"base"}):
        raise SignerError("AAB split/module contract is not exact")
    if analysis.get("abis") != REQUIRED_ABIS[target_id]:
        raise SignerError("AAB architecture identity belongs to another exact target")
    if analysis.get("certificate_sha256") != _reviewed_upload_certificate():
        raise SignerError("AAB signer does not exactly match the reviewed upload certificate")
    subject = analysis.get("certificate_subject")
    if type(subject) is not str or DEBUG_SIGNER_MARKER in subject.casefold():
        raise SignerError("AAB is signed by the Android debug signer")
    metadata = analysis.get("metadata")
    if type(metadata) is not dict:
        raise SignerError("AAB embedded metadata contract is missing")
    expected_min_sdk = 30 if target_id == "wear-os-aab" else 26
    if analysis.get("min_sdk") != expected_min_sdk or analysis.get("target_sdk") != 37:
        raise SignerError("AAB min/target SDK posture is not exact")
    if analysis.get("debuggable") is not False:
        raise SignerError("AAB release application must be explicitly non-debuggable")
    if analysis.get("application_icon") != "@mipmap/ic_launcher":
        raise SignerError("AAB application icon posture is not exact")
    if target_id == "android-phone-tablet-aab":
        if (
            analysis.get("application_label") != "Calculator"
            or analysis.get("uses_cleartext_traffic") is not False
            or analysis.get("network_security_config")
            != "@xml/network_security_config"
        ):
            raise SignerError("Android phone AAB must carry the Calculator application label")
    if target_id == "android-tv-aab":
        required = analysis.get("feature_required")
        if type(required) is not dict:
            raise SignerError("Android TV AAB feature requirements are not Play-compatible")
        if required.get("android.software.leanback") not in {"false", "0"} or required.get(
            "android.hardware.touchscreen"
        ) not in {"false", "0"}:
            raise SignerError("Android TV AAB feature requirements are not Play-compatible")
        if (
            analysis.get("application_label") != "Win's VPN"
            or analysis.get("application_banner") != "@drawable/banner"
            or analysis.get("uses_cleartext_traffic") is not False
            or analysis.get("network_security_config")
            != "@xml/network_security_config"
            or "org.winsvpn.app.MainActivity" not in set(analysis.get("activities") or [])
        ):
            raise SignerError("Android TV AAB must carry the real Win's VPN label and @drawable/banner")
        orientations = analysis.get("activity_orientations")
        leanback_activities = analysis.get("leanback_launcher_activities")
        if (
            type(orientations) is not dict
            or orientations.get("org.winsvpn.app.MainActivity")
            not in {"landscape", "0"}
        ):
            raise SignerError(
                "Android TV AAB MainActivity must be landscape in produced bytes"
            )
        if (
            type(leanback_activities) is not frozenset
            or not leanback_activities
            or any(
                orientations.get(activity) not in {"landscape", "0"}
                for activity in leanback_activities
            )
        ):
            raise SignerError(
                "Android TV AAB leanback launcher must be landscape in produced bytes"
            )
    if target_id in PHONE_TV_AAB_TARGETS:
        _enforce_phone_tv_payload(target_id, analysis)
        if analysis.get("has_leanback_launcher") and target_id == "android-phone-tablet-aab":
            raise SignerError("AAB form-factor identity belongs to another exact target")
    elif target_id == "wear-os-aab":
        _enforce_wear_payload(analysis)


def _enforce_phone_tv_payload(target_id: str, analysis: dict[str, object]) -> None:
    metadata = analysis.get("metadata")
    if target_id in PHONE_TV_AAB_TARGETS:
        if type(metadata) is not dict or metadata.get("proguard_map") is not True:
            raise SignerError("Android AAB is missing verified R8 proguard.map")
        r8 = analysis.get("r8")
        if type(r8) is not dict or r8.get("ok") is not True:
            raise SignerError("Android AAB R8 mapping is not a release R8 map")
        if not metadata.get("libapp_debug") or not metadata.get("libflutter_debug"):
            raise SignerError(
                "Android AAB is missing verified libflutter/libapp native debug-symbol metadata"
            )
        required_symbol_abis = REQUIRED_ABIS[target_id]
        if (
            metadata.get("libapp_debug_abis") != required_symbol_abis
            or metadata.get("libflutter_debug_abis") != required_symbol_abis
        ):
            raise SignerError(
                "Android AAB is missing verified libflutter/libapp native debug-symbol metadata"
            )
        if analysis.get("private_symbols_leaked") is True:
            raise SignerError("Android AAB ships private R8 or native debug symbols")
    else:
        if analysis.get("private_symbols_leaked") is not False:
            raise SignerError("Android APK ships private R8 or native debug symbols")
    permissions = analysis.get("permissions")
    if type(permissions) is not set or not PHONE_TV_REQUIRED_PERMISSIONS.issubset(permissions):
        raise SignerError("Android phone/TV artifact is missing required Play permissions")
    vpn_services = analysis.get("vpn_services")
    if type(vpn_services) is not list or not vpn_services:
        raise SignerError("Android phone/TV artifact is missing VpnService")
    services = analysis.get("services")
    if type(services) is not dict or any(
        services.get(name)
        != (
            "android.permission.BIND_VPN_SERVICE",
            False,
            frozenset({"android.net.VpnService"}),
        )
        for name in vpn_services
    ):
        raise SignerError("Android phone/TV VpnService posture is not exact")
    required_abis = REQUIRED_ABIS.get(target_id) or APK_REQUIRED_ABIS.get(target_id)
    if required_abis is None:
        raise SignerError(f"unsupported exact Android phone/TV target: {target_id}")
    engines = analysis.get("native_engines")
    if type(engines) is not dict:
        raise SignerError(
            "Android phone/TV artifact is missing required Winn v3/AWG native engines"
        )
    for abi in sorted(required_abis):
        present = engines.get(abi)
        if type(present) is not set or present != set(PHONE_TV_REQUIRED_NATIVE_ENGINES):
            raise SignerError(
                "Android phone/TV artifact is missing required Winn v3/AWG native engines"
            )
    forbidden = analysis.get("forbidden_native")
    if forbidden:
        raise SignerError("Android phone/TV artifact contains a forbidden native payload")


def _enforce_wear_payload(analysis: dict[str, object]) -> None:
    permissions = analysis.get("permissions")
    if type(permissions) is not set:
        raise SignerError("Wear AAB permission set is missing")
    forbidden_permissions = permissions & PHONE_TV_REQUIRED_PERMISSIONS
    if forbidden_permissions:
        raise SignerError("Wear AAB requests a phone/TV Play permission")
    vpn_services = analysis.get("vpn_services")
    if vpn_services:
        raise SignerError("Wear AAB contains a VPN service")
    if analysis.get("wear_standalone") is not False:
        raise SignerError("Wear AAB companion posture is not exact")
    required = analysis.get("feature_required")
    if type(required) is not dict or required.get("android.hardware.type.watch") not in {
        "true",
        "1",
    }:
        raise SignerError("Wear AAB must declare required android.hardware.type.watch")
    engines = analysis.get("native_engines")
    if type(engines) is dict and any(engines.values()):
        raise SignerError("Wear AAB contains a forbidden native payload")
    forbidden = analysis.get("forbidden_native")
    if forbidden:
        raise SignerError("Wear AAB contains a forbidden native payload")


def _load_wear_receipt_module():
    global _WEAR_RECEIPT_MODULE
    if _WEAR_RECEIPT_MODULE is None:
        spec = importlib.util.spec_from_file_location(
            "winsvpn_wear_signed_aab_receipt", WEAR_PRODUCER_PATH
        )
        if spec is None or spec.loader is None:
            raise SignerError("Wear store-metadata producer is unreadable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _WEAR_RECEIPT_MODULE = module
    return _WEAR_RECEIPT_MODULE


def _reviewed_wear_store_metadata() -> dict[str, object]:
    reviewed = _load_wear_receipt_module()._reviewed_store_metadata(ROOT)
    digest = reviewed.get("sha256") if type(reviewed) is dict else None
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise SignerError("wear-os-aab store metadata is not exact")
    return reviewed


def _verify_target_identity(target_id: str, path: pathlib.Path) -> None:
    if target_id not in CANONICAL_TARGETS:
        raise SignerError(f"unsupported exact Android upload target: {target_id}")
    data, identity, digest = _hold_aab_bytes(path)
    _assert_frozen_bundletool()
    analysis = analyze_held_aab(data)
    _cross_check_bundletool_identity(data, analysis)
    _enforce_target_identity(target_id, analysis)
    _revalidate_held_aab(path, identity, digest)


def _active_jdk_root() -> pathlib.Path:
    active = _ACTIVE_ANDROID_TOOLS.get()
    if active is None:
        raise SignerError(
            "retained private JDK tool paths are required for AAB identity verification"
        )
    return active.jdk_root


def _canonical_held_aab_evidence(
    target_id: str,
    expected_sha256: str,
    expected_size: int,
    analysis: Mapping[str, object],
) -> dict[str, object]:
    package, version_name, version_code = _reviewed_target_identity(target_id)
    form = ANDROID_PACKAGE_UPLOAD_TARGETS[target_id]["form"]
    r8 = analysis.get("r8")
    mapping = None
    if type(r8) is dict:
        mapping = {
            "sha256": r8.get("sha256"),
            "canonical_sha256": r8.get("canonical_sha256"),
            "pg_map_hash": r8.get("pg_map_hash"),
            "class_mapping_count": r8.get("class_mapping_count"),
        }
    native_engines = analysis.get("native_engines")
    canonical_engines: dict[str, list[str]] = {}
    if type(native_engines) is dict:
        for architecture, names in sorted(native_engines.items()):
            if type(architecture) is not str or type(names) is not set:
                raise SignerError("held Android AAB native-engine evidence is malformed")
            canonical_engines[architecture] = sorted(names)
    evidence: dict[str, object] = {
        "ok": True,
        "schema_version": HELD_AAB_VALIDATION_SCHEMA_VERSION,
        "contract": HELD_AAB_VALIDATION_CONTRACT,
        "target_id": target_id,
        "artifact": {
            "sha256": expected_sha256,
            "bytes": expected_size,
        },
        "package_identity": {
            "package": package,
            "version_name": version_name,
            "version_code": version_code,
            "form": form,
        },
        "modules": sorted(analysis.get("modules") or []),
        "architectures": sorted(analysis.get("abis") or []),
        "native_engines": canonical_engines,
        "r8_mapping": mapping,
        "signing": {
            "contract": "play-upload-certificate",
            "certificate_sha256": analysis.get("certificate_sha256"),
            "certificate_subject": analysis.get("certificate_subject"),
            "jar_signature": "jarsigner-strict-verified",
        },
        "decoders": {
            "closed_format": True,
            "bundletool_version": BUNDLETOOL_VERSION,
            "bundletool_sha256": BUNDLETOOL_ALL_SHA256,
            "jdk_root": str(_active_jdk_root()),
            "jdk_tree_sha256": OWNER_JDK_TREE_SHA256,
            "jdk_tools_sha256": dict(sorted(OWNER_JDK_TOOL_SHA256.items())),
        },
        "upload_certificate_pin": {
            "sha256": _reviewed_upload_certificate(),
            "source": DESCRIPTOR_RELATIVE,
            "custody": "release-freeze-held-verifier-source",
        },
    }
    try:
        canonical = json.dumps(
            evidence,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SignerError("held Android AAB canonical evidence is malformed") from exc
    if json.loads(canonical.decode("ascii")) != evidence:
        raise SignerError("held Android AAB canonical evidence is not stable")
    return evidence


def verify_held_aab_artifact(
    *,
    target_id: str,
    source_fd: int,
    expected_identity: tuple[int, int],
    expected_size: int,
    expected_sha256: str,
) -> dict[str, object]:
    """Validate one release-freeze-held AAB without reopening its source path."""
    if target_id not in CANONICAL_TARGETS:
        raise SignerError(f"unsupported exact Android upload target: {target_id}")
    with _HeldAabArtifact(
        source_fd=source_fd,
        expected_identity=expected_identity,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
    ) as held, _HeldAndroidVerificationTools() as tools:
        pass_fds = tuple(dict.fromkeys((*held.pass_fds, *tools.pass_fds)))

        def validate_all() -> None:
            held.revalidate()
            tools.revalidate(full_tree=True)

        verify_bytes(held.payload)
        analysis = analyze_held_aab(held.payload)
        validate_all()

        _verify_cryptographic_signature(
            held.tool_path,
            pass_fds=pass_fds,
            revalidate=validate_all,
        )
        bundletool = _assert_frozen_bundletool(
            pass_fds=pass_fds,
            revalidate=validate_all,
        )
        java = _bound_jdk_tool("java")
        manifest = _run(
            [
                java,
                "-jar",
                str(bundletool),
                "dump",
                "manifest",
                f"--bundle={held.tool_path}",
                "--module=base",
            ],
            "pinned bundletool AAB manifest decoder",
            timeout=60,
            pass_fds=pass_fds,
            revalidate=validate_all,
            watch_fds=pass_fds,
        )
        if not manifest.strip():
            raise SignerError("pinned bundletool could not decode the held AAB")
        _cross_check_bundletool_manifest(manifest, analysis)
        _enforce_target_identity(target_id, analysis)
        validate_all()
        evidence = _canonical_held_aab_evidence(
            target_id,
            expected_sha256,
            expected_size,
            analysis,
        )
        validate_all()
        return evidence


def canonical_gate_verify(target_id: str, raw_path: str) -> None:
    path = _canonical_gate_artifact(target_id, raw_path)
    relative = path.relative_to(ROOT).as_posix()
    with _retained_live_repo_file(relative, "cross-store AAB") as bound:
        source_fd, identity, size, digest = bound
        verify_held_aab_artifact(
            target_id=target_id,
            source_fd=source_fd,
            expected_identity=identity,
            expected_size=size,
            expected_sha256=digest,
        )
        if target_id == "wear-os-aab":
            _reviewed_wear_store_metadata()
        elif target_id in PHONE_TV_AAB_TARGETS:
            _reviewed_store_metadata(target_id)
    print(
        f"ANDROID CROSS-STORE SIGNING GATE: PASS target={target_id} artifact={raw_path}"
    )


def _receipt_hex64(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SignerError(f"{label} digest is invalid")
    return value


def _receipt_hex128(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{128}", value) is None:
        raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
    return value


def _receipt_exact_mapping(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise SignerError(f"{label} schema fields are invalid")
    return value


def _receipt_exact_str(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise SignerError(f"{label} is not exact")
    return value


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is refused: {value}")


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key is refused: {key}")
        result[key] = value
    return result


def _strict_json_loads(payload: str, label: str) -> object:
    try:
        return json.loads(
            payload,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SignerError(f"{label} must be strict duplicate-free finite JSON") from exc


def _require_strict_json_value(value: object, label: str) -> None:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise SignerError(f"{label} must be strict duplicate-free finite JSON") from exc
    _strict_json_loads(encoded, label)


def _receipt_document(record: object, label: str) -> dict[str, object]:
    if type(record) is bytes:
        try:
            text = record.decode("utf-8")
        except UnicodeError as exc:
            raise SignerError(f"{label} must be exact JSON bytes or one JSON object") from exc
        parsed = _strict_json_loads(text, label)
        if type(parsed) is not dict:
            raise SignerError(f"{label} must be exact JSON bytes or one JSON object")
        return parsed
    if type(record) is dict:
        _require_strict_json_value(record, label)
        return dict(record)
    raise SignerError(f"{label} must be exact JSON bytes or one JSON object")


def _require_canonical_relative_path(path: object, label: str) -> str:
    if type(path) is not str or not path or "\\" in path:
        raise SignerError(f"{label} must be one canonical repository-relative path")
    relative = pathlib.PurePosixPath(path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SignerError(f"{label} must be one canonical repository-relative path")
    return path


def _package_upload_target(target_id: str) -> dict[str, object]:
    spec = ANDROID_PACKAGE_UPLOAD_TARGETS.get(target_id)
    if spec is None:
        raise SignerError(f"unsupported exact Android package/upload target: {target_id}")
    return spec


def _upload_receipt_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _hex_looks_like_placeholder_key(value: str) -> bool:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        return False
    for width in (2, 4, 8, 16, 32):
        unit = value[:width]
        if unit * (len(value) // width) == value:
            return True
    return False


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
                raise SignerError(RECEIPT_PLACEHOLDER_TRUST_ERROR)
            if type(value) is str and folded.endswith("public_key"):
                if _hex_looks_like_placeholder_key(value):
                    raise SignerError(RECEIPT_PLACEHOLDER_TRUST_ERROR)
    try:
        dumped = json.dumps(material, ensure_ascii=True).casefold()
    except (TypeError, ValueError) as exc:
        raise SignerError(RECEIPT_PLACEHOLDER_TRUST_ERROR) from exc
    for marker in UPLOAD_RECEIPT_PLACEHOLDER_TRUST_MARKERS:
        if marker in dumped:
            raise SignerError(RECEIPT_PLACEHOLDER_TRUST_ERROR)


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
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _require_utc_timestamp(value: object, label: str) -> datetime.datetime:
    if type(value) is not str or not value:
        raise SignerError(f"{label} is not an RFC3339 UTC timestamp")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SignerError(f"{label} is not an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise SignerError(f"{label} is not an RFC3339 UTC timestamp")
    return parsed.astimezone(datetime.timezone.utc)


def _journal_parts() -> tuple[str, ...]:
    relative = pathlib.PurePosixPath(UPLOAD_RECEIPT_JOURNAL_RELATIVE)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SignerError("upload receipt journal path is not canonical")
    return relative.parts


def _mkdirat_directory(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as exc:
        raise SignerError(f"Android gate could not bind path component {name!r}") from exc
    child = _openat_child(parent_fd, name, _dir_open_flags())
    try:
        info = os.fstat(child)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SignerError(f"{name} must be a directory for the upload receipt journal")
        os.fsync(parent_fd)
        return child
    except Exception:
        os.close(child)
        raise


def _open_upload_receipt_journal() -> int:
    parts = _journal_parts()
    if len(parts) < 2:
        raise SignerError("upload receipt journal path is not canonical")
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
            raise SignerError("upload receipt journal directory is not root-owned")
        create_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            journal_fd = os.open(journal_name, create_flags, 0o600, dir_fd=parent_fd)
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
            raise SignerError(
                "upload receipt journal must be a root-owned single-link regular file"
            )
        owned = journal_fd
        journal_fd = -1
        return owned
    finally:
        if journal_fd >= 0:
            os.close(journal_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


def _parse_upload_receipt_journal(payload: bytes) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    if not payload:
        return records
    try:
        text = payload.decode("ascii")
    except UnicodeError as exc:
        raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR) from exc
    if not text.endswith("\n"):
        raise SignerError("upload receipt journal is truncated")
    for line in text.splitlines():
        if not line:
            raise SignerError("upload receipt journal contains an empty record")
        parsed = _strict_json_loads(line, "upload receipt journal record")
        if type(parsed) is not dict or parsed.get("schema") != UPLOAD_RECEIPT_JOURNAL_SCHEMA:
            raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
        kind = parsed.get("kind")
        if kind in {"issued", "consumed"}:
            if set(parsed) != {"schema", "kind", *UPLOAD_RECEIPT_AUTH_KEYS}:
                raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
            _receipt_exact_mapping(
                {key: parsed[key] for key in UPLOAD_RECEIPT_AUTH_KEYS},
                set(UPLOAD_RECEIPT_AUTH_KEYS),
                "upload receipt journal authentication",
            )
        elif kind == "consumed-batch":
            if set(parsed) != {"schema", "kind", "bindings"}:
                raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
            bindings = parsed.get("bindings")
            if type(bindings) is not list or not bindings:
                raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
            for binding in bindings:
                _receipt_exact_mapping(
                    binding,
                    set(UPLOAD_RECEIPT_AUTH_KEYS),
                    "upload receipt journal batch binding",
                )
        else:
            raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
        records.append(parsed)
    return records


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


def _with_upload_receipt_journal(mutate: object) -> list[dict[str, object]]:
    fd = _open_upload_receipt_journal()
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            chunks.append(block)
        records = _parse_upload_receipt_journal(b"".join(chunks))
        extra = mutate(records) if callable(mutate) else None
        if extra is not None:
            line = (
                json.dumps(
                    extra,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                )
                + "\n"
            ).encode("ascii")
            os.lseek(fd, 0, os.SEEK_END)
            written = os.write(fd, line)
            if written != len(line):
                raise SignerError("upload receipt journal write was truncated")
            os.fsync(fd)
            records.append(extra)
        return records
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


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
        raise SignerError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
        )
    if release != canonical_android_release():
        raise SignerError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
        )
    digest = _receipt_hex64(artifact_sha256, f"{target_id} candidate bytes")
    if type(artifact_bytes) is not int or isinstance(artifact_bytes, bool) or artifact_bytes <= 0:
        raise SignerError(
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
            candidates = (
                existing.get("bindings")
                if existing.get("kind") == "consumed-batch"
                else [existing]
            )
            if type(candidates) is not list:
                raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
            for candidate in candidates:
                if type(candidate) is not dict:
                    raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
                if (
                    candidate.get("nonce") == auth["nonce"]
                    or candidate.get("run_id") == auth["run_id"]
                    or candidate.get("challenge") == auth["challenge"]
                ):
                    raise SignerError(RECEIPT_REPLAY_ERROR)
        return {"schema": UPLOAD_RECEIPT_JOURNAL_SCHEMA, "kind": "issued", **auth}

    _with_upload_receipt_journal(_append_issued)
    return auth


def _journal_record_bindings(record: Mapping[str, object]) -> list[Mapping[str, object]]:
    if record.get("kind") == "consumed-batch":
        bindings = record.get("bindings")
        if type(bindings) is not list or any(type(item) is not dict for item in bindings):
            raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
        return bindings
    return [record]


def _validate_upload_receipt_challenge_records(
    auth: Mapping[str, object], records: list[dict[str, object]]
) -> None:
    binding = _journal_binding_tuple(auth)
    issued = False
    for existing in records:
        for candidate in _journal_record_bindings(existing):
            collides = (
                candidate.get("nonce") == auth.get("nonce")
                or candidate.get("run_id") == auth.get("run_id")
                or candidate.get("challenge") == auth.get("challenge")
            )
            if not collides:
                continue
            if existing.get("kind") in {"consumed", "consumed-batch"}:
                raise SignerError(RECEIPT_REPLAY_ERROR)
            if (
                existing.get("kind") != "issued"
                or _journal_binding_tuple(candidate) != binding
            ):
                raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
            issued = True
    if not issued:
        raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)


def _validate_upload_receipt_challenge(auth: Mapping[str, object]) -> None:
    def _validate(records: list[dict[str, object]]) -> None:
        _validate_upload_receipt_challenge_records(auth, records)
        return None

    _with_upload_receipt_journal(_validate)


def _consume_upload_receipt_challenges(
    authentications: list[Mapping[str, object]],
) -> None:
    if not authentications:
        raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
    canonical: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for auth in authentications:
        exact = _receipt_exact_mapping(
            dict(auth),
            set(UPLOAD_RECEIPT_AUTH_KEYS),
            "upload receipt commit authentication",
        )
        binding = _journal_binding_tuple(exact)
        if binding in seen:
            raise SignerError(RECEIPT_REPLAY_ERROR)
        seen.add(binding)
        canonical.append(exact)

    def _append_consumed(records: list[dict[str, object]]) -> dict[str, object]:
        for auth in canonical:
            _validate_upload_receipt_challenge_records(auth, records)
        return {
            "schema": UPLOAD_RECEIPT_JOURNAL_SCHEMA,
            "kind": "consumed-batch",
            "bindings": canonical,
        }

    _with_upload_receipt_journal(_append_consumed)


def _consume_upload_receipt_challenge(auth: Mapping[str, object]) -> None:
    _consume_upload_receipt_challenges([auth])


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
    if auth.get("authenticated") is not True or auth.get("issuer") != UPLOAD_RECEIPT_ISSUER:
        raise SignerError(RECEIPT_UNAUTHENTICATED_ERROR)
    _receipt_hex64(auth.get("run_id"), f"{target_id} upload run_id")
    _receipt_hex64(auth.get("nonce"), f"{target_id} upload nonce")
    _receipt_hex128(auth.get("challenge"), f"{target_id} upload challenge")
    issued_at = _require_utc_timestamp(auth.get("issued_at"), f"{target_id} upload issued_at")
    now = _upload_receipt_now()
    age = (now - issued_at).total_seconds()
    if age > UPLOAD_RECEIPT_MAX_AGE_SECONDS or age < -UPLOAD_RECEIPT_FUTURE_SKEW_SECONDS:
        raise SignerError(RECEIPT_STALE_ERROR)
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
        raise SignerError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
        )
    _validate_upload_receipt_challenge(auth)
    return auth


def _register_live_inode(relative: str, info: os.stat_result, label: str) -> None:
    bound = _LIVE_INODES.get()
    if bound is None:
        return
    key = (int(info.st_dev), int(info.st_ino))
    previous = bound.get(key)
    if previous is not None and previous != relative:
        raise SignerError(f"{label} is a hardlink or duplicate of {previous}")
    bound[key] = relative


def _hash_live_repo_file(relative: str, label: str) -> tuple[str, int, bytes]:
    path = _require_canonical_relative_path(relative, label)
    parts = pathlib.PurePosixPath(path).parts
    if not parts:
        raise SignerError(f"{label} must be one canonical repository-relative path")
    held: list[int] = []
    ancestor_ids: list[tuple[int, int]] = []
    try:
        try:
            root_fd = os.open(ROOT, _dir_open_flags())
        except OSError as exc:
            raise _owner_environment_blocker(
                "Android package/upload receipts remain pending without owner evidence: "
                + relative
            ) from exc
        held.append(root_fd)
        root_info = os.fstat(root_fd)
        ancestor_ids.append((int(root_info.st_dev), int(root_info.st_ino)))
        parent_fd = root_fd
        file_fd = -1
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            flags = _open_flags() if last else _dir_open_flags()
            try:
                child = _openat_child(parent_fd, part, flags)
            except SignerError as exc:
                if "could not bind path component" in str(exc):
                    raise _owner_environment_blocker(
                        "Android package/upload receipts remain pending without owner evidence: "
                        + relative
                    ) from exc
                raise
            held.append(child)
            child_info = os.fstat(child)
            if last:
                file_fd = child
            else:
                if not stat.S_ISDIR(child_info.st_mode):
                    raise SignerError(f"{label} ancestor must be a directory")
                ancestor_ids.append((int(child_info.st_dev), int(child_info.st_ino)))
                parent_fd = child
        if file_fd < 0:
            raise SignerError(f"{label} could not be bound")
        info = os.fstat(file_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISFIFO(info.st_mode)
            or stat.S_ISCHR(info.st_mode)
            or stat.S_ISBLK(info.st_mode)
            or stat.S_ISSOCK(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
        ):
            raise SignerError(f"{label} must be a non-empty regular single-link file")
        _register_live_inode(path, info, label)
        snapshot = _vnode_identity(info)
        payload = os.pread(file_fd, info.st_size, 0)
        digest = hashlib.sha256(payload).hexdigest()
        after = os.fstat(file_fd)
        reread = os.pread(file_fd, info.st_size, 0)
        if (
            len(payload) != info.st_size
            or reread != payload
            or hashlib.sha256(reread).hexdigest() != digest
            or _vnode_identity(after) != snapshot
        ):
            raise SignerError(f"{label} mutated while it was read")
        lexical = ROOT.joinpath(*parts)
        try:
            named = lexical.lstat()
        except OSError as exc:
            raise SignerError(f"{label} ancestor was replaced") from exc
        if _vnode_identity(named) != snapshot:
            raise SignerError(f"{label} ancestor was replaced")
        for depth, expected in enumerate(ancestor_ids):
            ancestor_path = ROOT.joinpath(*parts[:depth]) if depth else ROOT
            try:
                ancestor_named = ancestor_path.lstat()
            except OSError as exc:
                raise SignerError(f"{label} ancestor was replaced") from exc
            held_info = os.fstat(held[depth])
            if (
                (int(held_info.st_dev), int(held_info.st_ino)) != expected
                or (int(ancestor_named.st_dev), int(ancestor_named.st_ino)) != expected
            ):
                raise SignerError(f"{label} ancestor was replaced")
        return digest, info.st_size, payload
    finally:
        for fd in reversed(held):
            os.close(fd)


def _source_bound_android_release_identity() -> tuple[str, str, int, int]:
    """Derive release identity from two exact verifier-pinned source files."""

    payloads: dict[str, bytes] = {}
    for relative, expected_digest in RELEASE_IDENTITY_SOURCE_SHA256.items():
        observed, _size, payload = _hash_live_repo_file(
            relative, f"Android release identity source {relative}"
        )
        if observed != expected_digest:
            raise SignerError(
                f"Android release identity source hash changed: {relative}"
            )
        payloads[relative] = payload
    try:
        pubspec = payloads["pubspec.yaml"].decode("ascii")
        gradle = payloads["android/app/build.gradle.kts"].decode("ascii")
    except UnicodeError as exc:
        raise SignerError("Android release identity sources are not ASCII") from exc
    pubspec_versions = re.findall(
        r"(?m)^version:[ \t]*([0-9]+\.[0-9]+\.[0-9]+)\+([1-9][0-9]*)[ \t]*\r?$",
        pubspec,
    )
    application_ids = re.findall(
        r'(?m)^[ \t]*applicationId[ \t]*=[ \t]*"([^"]+)"[ \t]*$',
        gradle,
    )
    version_names = re.findall(
        r'(?m)^[ \t]*versionName[ \t]*=[ \t]*"([0-9]+\.[0-9]+\.[0-9]+)"[ \t]*$',
        gradle,
    )
    version_codes = [
        int(value)
        for value in re.findall(
            r"(?m)^[ \t]*versionCode[ \t]*=[ \t]*([1-9][0-9]*)[ \t]*$",
            gradle,
        )
    ]
    if (
        len(pubspec_versions) != 1
        or application_ids != [EXPECTED_APPLICATION_ID]
        or len(version_names) != 1
        or len(version_codes) != 2
    ):
        raise SignerError("Android release identity source assignments are ambiguous")
    pubspec_version, pubspec_code_text = pubspec_versions[0]
    base_code = int(pubspec_code_text)
    if (
        version_names[0] != pubspec_version
        or version_codes[0] != base_code
        or version_codes[1] != base_code * 100 + 2
    ):
        raise SignerError("Android release identity sources disagree")
    return application_ids[0], pubspec_version, base_code, version_codes[1]


@contextmanager
def _retained_live_repo_file(
    relative: str, label: str
) -> Iterator[tuple[int, tuple[int, int], int, str]]:
    """Retain one repository file and every lexical ancestor for one operation."""

    path = _require_canonical_relative_path(relative, label)
    parts = pathlib.PurePosixPath(path).parts
    descriptors: list[int] = []
    identities: list[tuple[int, ...]] = []
    file_fd = -1
    body_error: BaseException | None = None
    try:
        current = os.open(ROOT, _dir_open_flags())
        descriptors.append(current)
        identities.append(_custody_stat_identity(os.fstat(current)))
        for index, part in enumerate(parts):
            child = _openat_child(
                current,
                part,
                _open_flags() if index == len(parts) - 1 else _dir_open_flags(),
            )
            descriptors.append(child)
            identities.append(_custody_stat_identity(os.fstat(child)))
            current = child
        file_fd = descriptors[-1]
        info = os.fstat(file_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > MAX_HELD_AAB_BYTES
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise SignerError(f"{label} must be a non-empty non-writable single-link file")
        digest = _sha256_pread(file_fd, info.st_size, label)
        try:
            yield file_fd, (int(info.st_dev), int(info.st_ino)), int(info.st_size), digest
        except BaseException as exc:
            body_error = exc
            raise
        finally:
            for index, (descriptor, expected) in enumerate(
                zip(descriptors, identities, strict=True)
            ):
                if _custody_stat_identity(os.fstat(descriptor)) != expected:
                    raise SignerError(f"{label} descriptor custody changed") from body_error
                named_path = ROOT.joinpath(*parts[:index]) if index else ROOT
                if _custody_stat_identity(named_path.lstat()) != expected:
                    raise SignerError(f"{label} ancestor was substituted") from body_error
            current_info = os.fstat(file_fd)
            if _sha256_pread(file_fd, current_info.st_size, label) != digest:
                raise SignerError(f"{label} bytes changed during verification") from body_error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _bound_receipt_digest_pairs(
    target_id: str, record: Mapping[str, object]
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for field in (
        "artifact",
        "build_receipt",
        "producer",
        "descriptor",
        "source_freeze",
        "obfuscation_privacy",
    ):
        value = record.get(field)
        if type(value) is dict:
            pairs.append(
                (
                    f"{target_id}.{field}",
                    _receipt_hex64(value.get("sha256"), f"{target_id} {field}"),
                )
            )
    return pairs


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


def _reject_receipt_digest_reuse(pairs: list[tuple[str, str]]) -> None:
    seen: dict[str, str] = {}
    for label, digest in pairs:
        previous = seen.get(digest)
        if previous is not None:
            raise SignerError(f"receipt reuse is refused: {label} reuses {previous}")
        seen[digest] = label


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
            raise SignerError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
            )
        for other_path, (other_digest, other_label) in shared.items():
            if other_digest == digest and other_path != path:
                raise SignerError(
                    f"receipt reuse is refused: {target_id}.{field} reuses {other_label}"
                )
        shared[path] = (digest, f"{target_id}.{field}")


def _require_live_upload_bindings(
    target_id: str,
    receipt: dict[str, object],
    spec: dict[str, object],
    candidate: tuple[int, tuple[int, int], int, str],
) -> None:
    artifact = receipt["artifact"]
    source_fd, identity, live_size, live_digest = candidate
    source_info = os.fstat(source_fd)
    if (
        (int(source_info.st_dev), int(source_info.st_ino)) != identity
        or int(source_info.st_size) != live_size
        or _sha256_pread(source_fd, live_size, f"{target_id} artifact") != live_digest
        or live_digest != artifact["sha256"]
        or live_size != artifact["bytes"]
    ):
        raise SignerError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
        )
    exact_paths = {
        "producer": str(spec["producer"]),
        "descriptor": DESCRIPTOR_RELATIVE,
        "obfuscation_privacy": OBFUSCATION_PRIVACY_RELATIVE,
    }
    for field, expected_path in exact_paths.items():
        record = receipt[field]
        path = str(record["path"])
        if path != expected_path:
            raise SignerError(f"{target_id} {field} path is not exact")
        live_digest, _live_size, _payload = _hash_live_repo_file(
            path, f"{target_id} {field}"
        )
        if live_digest != record["sha256"]:
            raise SignerError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
            )
    for field in ("build_receipt", "source_freeze"):
        record = receipt[field]
        path = str(record["path"])
        if pathlib.PurePosixPath(path).parts[0] != ".artifacts":
            raise SignerError(f"{target_id} {field} path must stay under .artifacts/")
        live_digest, _live_size, payload = _hash_live_repo_file(
            path, f"{target_id} {field}"
        )
        if live_digest != record["sha256"]:
            raise SignerError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes"
            )
        if field == "build_receipt":
            try:
                text = payload.decode("utf-8")
            except UnicodeError as exc:
                raise SignerError(f"{target_id} build receipt must be exact JSON") from exc
            parsed = _strict_json_loads(text, f"{target_id} build receipt")
            if type(parsed) is not dict:
                raise SignerError(f"{target_id} build receipt must be exact JSON")


def _require_owner_issued_android_signature_held(
    target_id: str,
    candidate: tuple[int, tuple[int, int], int, str],
) -> dict[str, object]:
    source_fd, identity, size, digest = candidate
    try:
        return verify_held_aab_artifact(
            target_id=target_id,
            source_fd=source_fd,
            expected_identity=identity,
            expected_size=size,
            expected_sha256=digest,
        )
    except SignerError as exc:
        text = str(exc).lower()
        if any(marker in text for marker in OWNER_SIGNATURE_HARD_FAIL_MARKERS):
            raise
        if any(marker in text for marker in OWNER_SIGNATURE_PENDING_MARKERS):
            raise _owner_environment_blocker(OWNER_BLOCKED_NO_SIGNATURE) from exc
        raise


def _require_owner_issued_android_signature(target_id: str, relative: str) -> None:
    path = _canonical_gate_artifact(target_id, relative)
    canonical = path.relative_to(ROOT).as_posix()
    try:
        with _retained_live_repo_file(canonical, f"{target_id} artifact") as candidate:
            _require_owner_issued_android_signature_held(target_id, candidate)
    except SignerError as exc:
        text = str(exc).lower()
        if any(marker in text for marker in OWNER_SIGNATURE_HARD_FAIL_MARKERS):
            raise
        if (
            "pending without owner evidence" in text
            or "could not bind path component" in text
            or "must be a non-empty" in text
        ):
            raise _owner_environment_blocker(
                OWNER_BLOCKED_MISSING_EVIDENCE + relative
            ) from exc
        raise


def bind_package_upload_receipt(
    target_id: str,
    record: Mapping[str, object] | bytes,
    *,
    artifact_sha256: str,
    artifact_bytes: int,
) -> dict[str, object]:
    """Bind one Android/Wear Play AAB receipt to exact 1.0.16+33 candidate bytes."""

    token = None
    if _LIVE_INODES.get() is None:
        token = _LIVE_INODES.set({})
    try:
        parsed = _receipt_exact_mapping(
            _receipt_document(record, f"{target_id} upload receipt"),
            set(PACKAGE_UPLOAD_RECEIPT_KEYS),
            f"{target_id} upload receipt",
        )
        artifact = _receipt_exact_mapping(
            parsed.get("artifact"),
            {"path", "sha256", "bytes"},
            f"{target_id} artifact",
        )
        relative = _require_canonical_relative_path(
            artifact.get("path"), f"{target_id} artifact"
        )
        with _retained_live_repo_file(relative, f"{target_id} artifact") as candidate:
            result, authentication = _bind_package_upload_receipt_locked(
                target_id,
                parsed,
                artifact_sha256=artifact_sha256,
                artifact_bytes=artifact_bytes,
                candidate=candidate,
            )
        _consume_upload_receipt_challenges([authentication])
        return result
    finally:
        if token is not None:
            _LIVE_INODES.reset(token)


def _bind_package_upload_receipt_locked(
    target_id: str,
    record: Mapping[str, object] | bytes,
    *,
    artifact_sha256: str,
    artifact_bytes: int,
    candidate: tuple[int, tuple[int, int], int, str],
) -> tuple[dict[str, object], dict[str, object]]:
    spec = _package_upload_target(target_id)
    receipt = _receipt_exact_mapping(
        _receipt_document(record, f"{target_id} upload receipt"),
        set(PACKAGE_UPLOAD_RECEIPT_KEYS),
        f"{target_id} upload receipt",
    )
    release = canonical_android_release()
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
        raise SignerError(f"{target_id} receipt binding is invalid or changed")
    artifact = _receipt_exact_mapping(
        receipt.get("artifact"), {"path", "sha256", "bytes"}, f"{target_id} artifact"
    )
    path = _require_canonical_relative_path(artifact.get("path"), f"{target_id} artifact")
    if not pathlib.PurePosixPath(path).name.lower().endswith(".aab"):
        raise SignerError(f"{target_id} artifact type is not allowed")
    bound_digest = _receipt_hex64(artifact_sha256, f"{target_id} candidate bytes")
    if (
        artifact.get("sha256") != bound_digest
        or type(artifact.get("bytes")) is not int
        or isinstance(artifact.get("bytes"), bool)
        or int(artifact.get("bytes")) != artifact_bytes
        or int(artifact.get("bytes")) <= 0
    ):
        raise SignerError(
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
        or producer_id != spec["producer"]
        or producer.get("path") != producer_id
    ):
        raise SignerError(f"{target_id} producer id is not allowed")
    _receipt_hex64(producer.get("sha256"), f"{target_id} producer")
    identity = _receipt_exact_mapping(
        receipt.get("package_identity"),
        {"package", "version_name", "version_code", "form"},
        f"{target_id} package identity",
    )
    if (
        identity.get("package") != spec["package"]
        or identity.get("version_name") != spec["version_name"]
        or identity.get("version_code") != spec["version_code"]
        or identity.get("form") != spec["form"]
    ):
        raise SignerError(
            f"{target_id} package identity is not the current 1.0.16+33 Android identity"
        )
    architectures = receipt.get("architectures")
    if (
        type(architectures) is not list
        or tuple(architectures) != spec["architectures"]
        or len(architectures) != len(set(architectures))
    ):
        raise SignerError(f"{target_id} architecture inventory is not exact")
    signing = _receipt_exact_mapping(
        receipt.get("signing"),
        {"contract", "certificate_sha256"},
        f"{target_id} signing evidence",
    )
    if signing.get("contract") != spec["signing_contract"]:
        raise SignerError(f"{target_id} signing evidence is not release-valid")
    _receipt_hex64(signing.get("certificate_sha256"), f"{target_id} upload certificate")
    if signing.get("certificate_sha256") != _reviewed_upload_certificate():
        raise SignerError(f"{target_id} signing evidence is not release-valid")
    store_keys = {"surface", "status", "metadata_sha256"}
    store = _receipt_exact_mapping(
        receipt.get("store_evidence"),
        store_keys,
        f"{target_id} store evidence",
    )
    if store.get("surface") != spec["store_surface"] or store.get("status") != "not_uploaded":
        raise SignerError(f"{target_id} store evidence is not exact")
    if target_id == "wear-os-aab":
        reviewed = _reviewed_wear_store_metadata()
    else:
        reviewed = _reviewed_store_metadata(target_id)
    if store.get("metadata_sha256") != reviewed["sha256"]:
        raise SignerError(f"{target_id} store metadata is not exact")
    descriptor = _receipt_exact_mapping(
        receipt.get("descriptor"), {"path", "sha256"}, f"{target_id} descriptor binding"
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
        raise SignerError(f"{target_id} descriptor path is not exact")
    if hardening.get("path") != OBFUSCATION_PRIVACY_RELATIVE:
        raise SignerError(f"{target_id} obfuscation/privacy path is not exact")
    if pathlib.PurePosixPath(str(source.get("path"))).parts[0] != ".artifacts":
        raise SignerError(f"{target_id} source freeze path must stay under .artifacts/")
    if pathlib.PurePosixPath(str(build_receipt.get("path"))).parts[0] != ".artifacts":
        raise SignerError(f"{target_id} build receipt path must stay under .artifacts/")
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
        raise SignerError(
            f"{target_id} owner authorization must remain pending without owner evidence"
        )
    _reject_receipt_digest_reuse(_unique_receipt_digest_pairs(target_id, receipt))
    authentication = _bind_upload_receipt_authentication(
        target_id,
        receipt,
        artifact_sha256=bound_digest,
        artifact_bytes=int(artifact_bytes),
        architectures=tuple(str(item) for item in spec["architectures"]),
        release=release,
    )
    _require_live_upload_bindings(target_id, receipt, spec, candidate)
    _require_owner_issued_android_signature_held(target_id, candidate)
    result = {
        "ok": True,
        "target_id": target_id,
        "release": release,
        "artifact_sha256": bound_digest,
        "publication_authorized": False,
        "upload_attempted": False,
        "owner_authorization": "pending",
    }
    return result, authentication


def bind_android_package_upload_receipts(
    records: Mapping[str, object],
    artifacts: Mapping[str, tuple[str, int]],
) -> dict[str, object]:
    """Bind required phone/TV/Wear Play receipts, refusing reuse or approval."""

    token = _LIVE_INODES.set({})
    try:
        return _bind_android_package_upload_receipts_locked(records, artifacts)
    finally:
        _LIVE_INODES.reset(token)


def _bind_android_package_upload_receipts_locked(
    records: Mapping[str, object],
    artifacts: Mapping[str, tuple[str, int]],
) -> dict[str, object]:
    if type(records) is not dict or type(artifacts) is not dict:
        raise SignerError("Android package/upload receipt set is invalid")
    parsed: dict[str, dict[str, object]] = {}
    for target_id, record in records.items():
        parsed[str(target_id)] = _receipt_document(
            record, f"{target_id} upload receipt"
        )
    unexpected = set(parsed) - set(ANDROID_PACKAGE_UPLOAD_TARGETS)
    if unexpected:
        raise SignerError(
            "unexpected Android package/upload receipt target: "
            + ", ".join(sorted(unexpected))
        )
    missing = [
        target_id
        for target_id in REQUIRED_ANDROID_UPLOAD_TARGETS
        if target_id not in parsed
    ]
    if missing:
        raise _owner_environment_blocker(
            "Android package/upload receipts remain pending without owner evidence: "
            + ", ".join(missing)
        )
    unique_pairs: list[tuple[str, str]] = []
    shared: dict[str, tuple[str, str]] = {}
    for target_id, record in parsed.items():
        unique_pairs.extend(_unique_receipt_digest_pairs(target_id, record))
        _bind_shared_upload_paths(shared, target_id, record)
    _reject_receipt_digest_reuse(unique_pairs)
    bound: dict[str, object] = {}
    authentications: list[Mapping[str, object]] = []
    with ExitStack() as stack:
        for target_id, record in parsed.items():
            artifact_binding = artifacts.get(target_id)
            if artifact_binding is None or len(artifact_binding) != 2:
                raise SignerError(f"{target_id} exact candidate bytes are missing")
            digest, size = artifact_binding
            receipt_artifact = _receipt_exact_mapping(
                record.get("artifact"),
                {"path", "sha256", "bytes"},
                f"{target_id} artifact",
            )
            relative = _require_canonical_relative_path(
                receipt_artifact.get("path"), f"{target_id} artifact"
            )
            candidate = stack.enter_context(
                _retained_live_repo_file(relative, f"{target_id} artifact")
            )
            result, authentication = _bind_package_upload_receipt_locked(
                target_id,
                record,
                artifact_sha256=str(digest),
                artifact_bytes=int(size),
                candidate=candidate,
            )
            bound[target_id] = result
            authentications.append(authentication)
        response = {
            "ok": True,
            "release": CANONICAL_RELEASE,
            "required_targets": list(REQUIRED_ANDROID_UPLOAD_TARGETS),
            "bound_targets": sorted(bound),
            "publication_authorized": False,
            "upload_attempted": False,
            "owner_authorization": "pending",
            "receipts": bound,
        }
    _consume_upload_receipt_challenges(authentications)
    return response


class _HeldApksigner:
    """Retain the sha256-pinned Android SDK build-tools apksigner JAR.

    The pinned source file stays retained through its descriptor chain. The
    JVM cannot load classes from a /dev/fd/N class-path entry on macOS, so
    java -jar receives a private snapshot copy: a 0o400 file alone in a 0o500
    directory this process created, checked by name, identity, and sha256.
    """

    def __init__(self) -> None:
        self._context = None
        self._fd = -1
        self._snapshot_fd = -1
        self._directory_fd = -1
        self._directory_path: pathlib.Path | None = None
        self._snapshot_stat: tuple[int, ...] | None = None
        self._directory_stat: tuple[int, ...] | None = None

    @property
    def path(self) -> pathlib.Path:
        if self._snapshot_fd < 0 or self._directory_path is None:
            raise SignerError("retained Android SDK apksigner custody is not active")
        return self._directory_path / APKSIGNER_SNAPSHOT_NAME

    @property
    def pass_fds(self) -> tuple[int, ...]:
        if self._fd < 0 or self._snapshot_fd < 0:
            raise SignerError("retained Android SDK apksigner custody is not active")
        return (self._fd, self._snapshot_fd)

    def revalidate(self) -> None:
        if (
            self._fd < 0
            or self._snapshot_fd < 0
            or self._directory_fd < 0
            or self._directory_path is None
            or self._snapshot_stat is None
            or self._directory_stat is None
        ):
            raise SignerError("retained Android SDK apksigner custody is not active")
        info = os.fstat(self._fd)
        snapshot = os.fstat(self._snapshot_fd)
        directory_named = os.lstat(self._directory_path)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or _sha256_pread(self._fd, info.st_size, "Android SDK apksigner")
            != OWNER_APKSIGNER_JAR_SHA256
            or _custody_stat_identity(snapshot) != self._snapshot_stat
            or _custody_stat_identity(os.fstat(self._directory_fd)) != self._directory_stat
            or (directory_named.st_dev, directory_named.st_ino)
            != (self._directory_stat[0], self._directory_stat[1])
            or os.listdir(self._directory_fd) != [APKSIGNER_SNAPSHOT_NAME]
            or _custody_stat_identity(
                os.stat(
                    APKSIGNER_SNAPSHOT_NAME,
                    dir_fd=self._directory_fd,
                    follow_symlinks=False,
                )
            )
            != self._snapshot_stat
            or _sha256_pread(
                self._snapshot_fd, snapshot.st_size, "private Android SDK apksigner"
            )
            != OWNER_APKSIGNER_JAR_SHA256
        ):
            raise SignerError("Android SDK apksigner custody changed")

    def _bind_snapshot(self) -> None:
        source = os.fstat(self._fd)
        self._directory_path = pathlib.Path(
            tempfile.mkdtemp(prefix=HELD_TOOL_SNAPSHOT_PREFIX + "apksigner-")
        )
        os.chmod(self._directory_path, 0o700)
        self._directory_fd = os.open(self._directory_path, _dir_open_flags())
        directory_info = os.fstat(self._directory_fd)
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or stat.S_IMODE(directory_info.st_mode) != 0o700
            or directory_info.st_uid != os.geteuid()
        ):
            raise SignerError("private apksigner directory custody is invalid")
        writer = os.open(
            APKSIGNER_SNAPSHOT_NAME,
            _open_flags(write=True, exclusive=True),
            0o400,
            dir_fd=self._directory_fd,
        )
        try:
            offset = 0
            while offset < source.st_size:
                block = os.pread(
                    self._fd, min(HELD_AAB_READ_CHUNK, source.st_size - offset), offset
                )
                if not block:
                    raise SignerError("Android SDK apksigner truncated during snapshot")
                view = memoryview(block)
                while view:
                    written = os.write(writer, view)
                    if written <= 0:
                        raise SignerError("private apksigner snapshot write truncated")
                    view = view[written:]
                offset += len(block)
            os.fchmod(writer, 0o400)
            os.fsync(writer)
        finally:
            os.close(writer)
        self._snapshot_fd = _openat_child(
            self._directory_fd, APKSIGNER_SNAPSHOT_NAME, _open_flags()
        )
        snapshot_info = os.fstat(self._snapshot_fd)
        if (
            not stat.S_ISREG(snapshot_info.st_mode)
            or snapshot_info.st_nlink != 1
            or snapshot_info.st_size != source.st_size
            or stat.S_IMODE(snapshot_info.st_mode) != 0o400
        ):
            raise SignerError("private apksigner snapshot custody is invalid")
        os.fchmod(self._directory_fd, 0o500)
        os.fsync(self._directory_fd)
        self._snapshot_stat = _custody_stat_identity(os.fstat(self._snapshot_fd))
        self._directory_stat = _custody_stat_identity(os.fstat(self._directory_fd))

    def _close_snapshot(self) -> None:
        cleanup_error: BaseException | None = None
        if self._snapshot_fd >= 0:
            try:
                os.close(self._snapshot_fd)
            except OSError as exc:
                cleanup_error = exc
            self._snapshot_fd = -1
        if self._directory_fd >= 0:
            try:
                os.fchmod(self._directory_fd, 0o700)
                try:
                    os.unlink(APKSIGNER_SNAPSHOT_NAME, dir_fd=self._directory_fd)
                except FileNotFoundError:
                    pass
            except OSError as exc:
                cleanup_error = cleanup_error or exc
            try:
                os.close(self._directory_fd)
            except OSError as exc:
                cleanup_error = cleanup_error or exc
            self._directory_fd = -1
        if self._directory_path is not None:
            try:
                path_info = os.lstat(self._directory_path)
                if self._directory_stat is not None and (
                    path_info.st_dev,
                    path_info.st_ino,
                ) != (self._directory_stat[0], self._directory_stat[1]):
                    raise SignerError("private apksigner directory path was substituted")
                os.rmdir(self._directory_path)
            except FileNotFoundError:
                pass
            except (OSError, SignerError) as exc:
                cleanup_error = cleanup_error or exc
            self._directory_path = None
        self._snapshot_stat = None
        self._directory_stat = None
        if cleanup_error is not None:
            raise SignerError("private apksigner snapshot cleanup failed") from cleanup_error

    def __enter__(self) -> _HeldApksigner:
        jar = _pinned_apksigner_jar()
        if not os.path.lexists(jar):
            raise SignerError(
                f"Android SDK apksigner {APKSIGNER_BUILD_TOOLS_VERSION} is absent at "
                f"{jar}; APK PASS is unavailable"
            )
        self._context = _retained_pinned_file(
            jar,
            f"Android SDK apksigner {APKSIGNER_BUILD_TOOLS_VERSION}",
            OWNER_APKSIGNER_JAR_SHA256,
        )
        context = self._context
        try:
            self._fd = context.__enter__()
            self._bind_snapshot()
            self.revalidate()
            return self
        except BaseException:
            self._fd = -1
            self._context = None
            try:
                self._close_snapshot()
            finally:
                context.__exit__(*sys.exc_info())
            raise

    def __exit__(self, exc_type, exc, traceback) -> bool:
        custody_error: BaseException | None = None
        try:
            if self._context is not None:
                self.revalidate()
        except BaseException as failure:
            custody_error = failure
        try:
            self._close_snapshot()
        except BaseException as cleanup_error:
            custody_error = custody_error or cleanup_error
        context = self._context
        self._context = None
        self._fd = -1
        if context is not None:
            context.__exit__(exc_type, exc, traceback)
        if custody_error is not None:
            if exc is not None:
                raise custody_error from exc
            raise custody_error
        return False


def _parse_apksigner_verification(raw: bytes) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise SignerError("Android SDK apksigner output is not UTF-8") from exc
    scheme_matches = re.findall(
        r"(?im)^Verified using v(2|3) scheme(?: \([^\r\n]*\))?: (true|false)\s*$",
        text,
    )
    schemes: dict[str, bool] = {}
    for scheme, value in scheme_matches:
        if scheme in schemes:
            raise SignerError("Android SDK apksigner reported duplicate scheme posture")
        schemes[scheme] = value == "true"
    signer_counts = re.findall(r"(?im)^Number of signers: ([0-9]+)\s*$", text)
    # apksigner prints "Signer #1 certificate ..." for a v2 signer and, from
    # build-tools 37, "V3.0 Signer: certificate ..." when v3 verifies. Build-tools
    # 37 also labels rotation and hybrid signers ("V3.1 Signer: (minSdkVersion=...)",
    # "V3.2 Hybrid PQC Signer: (...)"). Every signer role label counts, so no
    # signer can hide under a label this parser does not list; all of them must
    # name one and the same certificate. Only the source stamp is not a signer.
    signer_label = (
        r"(?!Source Stamp Signer:)(?:[A-Za-z0-9.]+ )*Signer(?: #[0-9]+)?:?"
        r"(?: \([^\r\n]*?\))?"
    )
    digest_matches = sorted(
        {
            value.replace(":", "").lower()
            for value in re.findall(
                rf"(?im)^{signer_label} certificate SHA-256 digest: ([0-9a-f:]+)\s*$",
                text,
            )
        }
    )
    subjects = sorted(
        set(re.findall(rf"(?im)^{signer_label} certificate DN: ([^\r\n]+)\s*$", text))
    )
    if schemes != {"2": True, "3": True}:
        raise SignerError("APK must verify with both APK Signature Scheme v2 and v3")
    if signer_counts != ["1"] or len(digest_matches) != 1 or len(subjects) != 1:
        raise SignerError("APK must have exactly one effective apksigner signer")
    digest = digest_matches[0]
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise SignerError("APK apksigner certificate digest is malformed")
    if DEBUG_SIGNER_MARKER in subjects[0].casefold():
        raise SignerError("APK is signed by the Android debug signer")
    return {
        "verified_v2": True,
        "verified_v3": True,
        "signer_count": 1,
        "certificate_sha256": digest,
        "certificate_subject": subjects[0],
        "tool": "android-sdk-build-tools-37.0.0-apksigner",
        "tool_sha256": OWNER_APKSIGNER_JAR_SHA256,
    }


def _apk_zip_contract(archive: zipfile.ZipFile) -> tuple[list[str], frozenset[str]]:
    infos = archive.infolist()
    raw_names = [info.filename for info in infos]
    if len(raw_names) != len(set(raw_names)):
        raise SignerError("APK contains duplicate ZIP member names")
    logical_fold: dict[str, str] = {}
    abis: set[str] = set()
    for info in infos:
        name = info.filename
        parts = _logical_parts(name)
        folded = "/".join(part.casefold() for part in parts)
        previous = logical_fold.get(folded)
        if previous is not None:
            raise SignerError(f"APK ZIP member path alias is refused: {name}")
        logical_fold[folded] = name
        native = APK_NATIVE_LIB_RE.fullmatch(name)
        if native is not None:
            if info.is_dir() or info.file_size <= 0 or stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK:
                raise SignerError(f"APK native library is empty, a directory, or a symlink: {name}")
            abis.add(native.group(1))
    if raw_names.count(APK_MANIFEST_MEMBER) != 1:
        raise SignerError("APK must contain exactly one AndroidManifest.xml")
    if any(name == MANIFEST_MEMBER or name == BUNDLE_CONFIG_MEMBER for name in raw_names):
        raise SignerError("APK identity belongs to an AAB")
    return raw_names, frozenset(abis)


MAX_APK_RESOURCE_TABLE_BYTES = 64 * 1024 * 1024


def _arsc_pool_string(table: bytes, start: int, index: int) -> str:
    # ResStringPool: type 0x0001, headerSize, size, stringCount, styleCount,
    # flags (0x100 = UTF-8), stringsStart, stylesStart, then u32 offsets.
    if struct.unpack_from("<H", table, start)[0] != 0x0001:
        raise ValueError("not a string pool")
    header_size, size, count, _styles, flags, strings_start = struct.unpack_from(
        "<HIIIII", table, start + 2
    )
    end = start + size
    if end > len(table) or not 0 <= index < count or start + header_size + 4 * count > end:
        raise ValueError("string pool bounds")
    offset = start + strings_start + struct.unpack_from("<I", table, start + header_size + 4 * index)[0]
    if flags & 0x100:
        for _ in range(2):  # character length, then byte length
            length = table[offset]
            offset += 1
            if length & 0x80:
                length = ((length & 0x7F) << 8) | table[offset]
                offset += 1
        if offset + length > end:
            raise ValueError("string bounds")
        return table[offset : offset + length].decode("utf-8")
    length = struct.unpack_from("<H", table, offset)[0]
    offset += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", table, offset)[0]
        offset += 2
    if offset + 2 * length > end:
        raise ValueError("string bounds")
    return table[offset : offset + 2 * length].decode("utf-16-le")


def _arsc_resource_name(table: bytes, resource_id: int) -> str | None:
    """Resolve one app resource id to "@type/name" from resources.arsc, or None."""
    package_id, type_id, entry_index = resource_id >> 24, (resource_id >> 16) & 0xFF, resource_id & 0xFFFF
    try:
        if type_id == 0 or len(table) < 12 or struct.unpack_from("<H", table, 0)[0] != 0x0002:
            return None
        header_size, total = struct.unpack_from("<HI", table, 2)
        total = min(total, len(table))
        offset = header_size
        while offset + 8 <= total:
            chunk_type, chunk_header, chunk_size = struct.unpack_from("<HHI", table, offset)
            if chunk_size < 8 or offset + chunk_size > total:
                return None
            if chunk_type == 0x0200 and struct.unpack_from("<I", table, offset + 8)[0] == package_id:
                type_strings = offset + struct.unpack_from("<I", table, offset + 268)[0]
                key_strings = offset + struct.unpack_from("<I", table, offset + 276)[0]
                package_end = offset + chunk_size
                inner = offset + chunk_header
                while inner + 8 <= package_end:
                    inner_type, inner_header, inner_size = struct.unpack_from("<HHI", table, inner)
                    if inner_size < 8 or inner + inner_size > package_end:
                        return None
                    if inner_type == 0x0201 and table[inner + 8] == type_id:
                        flags = table[inner + 9]
                        count, entries_start = struct.unpack_from("<II", table, inner + 12)
                        offsets_at = inner + inner_header
                        entry_offset = None
                        if flags & 0x01:  # FLAG_SPARSE: (index, offset / 4) pairs
                            for slot in range(count):
                                index, quarter = struct.unpack_from("<HH", table, offsets_at + 4 * slot)
                                if index == entry_index:
                                    entry_offset = quarter * 4
                                    break
                        elif entry_index < count:
                            if flags & 0x02:  # FLAG_OFFSET16: offset / 4, 0xFFFF = none
                                value = struct.unpack_from("<H", table, offsets_at + 2 * entry_index)[0]
                                entry_offset = None if value == 0xFFFF else value * 4
                            else:
                                value = struct.unpack_from("<I", table, offsets_at + 4 * entry_index)[0]
                                entry_offset = None if value == 0xFFFFFFFF else value
                        if entry_offset is not None:
                            entry = inner + entries_start + entry_offset
                            if entry + 8 > inner + inner_size:
                                return None
                            entry_flags = struct.unpack_from("<H", table, entry + 2)[0]
                            if entry_flags & 0x0008:  # FLAG_COMPACT: u16 key first
                                key = struct.unpack_from("<H", table, entry)[0]
                            else:
                                key = struct.unpack_from("<I", table, entry + 4)[0]
                            type_name = _arsc_pool_string(table, type_strings, type_id - 1)
                            key_name = _arsc_pool_string(table, key_strings, key)
                            return f"@{type_name}/{key_name}"
                    inner += inner_size
                return None
            offset += chunk_size
    except (struct.error, IndexError, ValueError, UnicodeDecodeError):
        return None
    return None


def analyze_held_apk(data: bytes) -> dict[str, object]:
    with _open_held_zip(data, allow_apk_signing_block=True) as archive:
        names, abis = _apk_zip_contract(archive)
        root = _decode_axml_manifest(archive.read(APK_MANIFEST_MEMBER))
        identity = _manifest_identity(root)
        # APK binary XML carries resource ids, not names; resolve the icon and
        # banner through resources.arsc so they compare like the AAB proto form.
        table = b""
        if "resources.arsc" in names:
            info = archive.getinfo("resources.arsc")
            if info.file_size <= MAX_APK_RESOURCE_TABLE_BYTES:
                table = archive.read("resources.arsc")
        for key in ("application_icon", "application_banner"):
            value = identity.get(key)
            if type(value) is str and value.isdigit() and int(value) >> 24 == 0x7F:
                resolved = _arsc_resource_name(table, int(value))
                if resolved is not None:
                    identity[key] = resolved
        engines, forbidden = _native_engine_inventory(archive, names, aab=False)
        leaked = _private_symbol_members(names, aab=False)
    identity.update(
        {
            "modules": frozenset({"base"}),
            "abis": abis,
            "metadata": {
                "libapp_debug": False,
                "libflutter_debug": False,
                "proguard_map": False,
            },
            "native_engines": engines,
            "forbidden_native": forbidden,
            "private_symbols_leaked": bool(leaked),
            "r8": None,
            "apk_signing": None,
            "decoder": "apk-binary-xml",
        }
    )
    return identity


def _canonical_gate_apk(target_id: str, raw_path: str) -> pathlib.Path:
    if target_id not in PHONE_TV_APK_TARGETS:
        raise SignerError(f"unsupported exact Android APK target: {target_id}")
    relative = _require_canonical_relative_path(raw_path, "phone/TV APK")
    if not pathlib.PurePosixPath(relative).name.lower().endswith(".apk"):
        raise SignerError("phone/TV APK artifact must be one non-empty .apk file")
    return ROOT / pathlib.Path(relative)


def _enforce_apk_target_identity(target_id: str, analysis: dict[str, object]) -> None:
    expected_package, expected_version_name, expected_version_code = _reviewed_target_identity(
        target_id
    )
    if (
        analysis.get("package") != expected_package
        or analysis.get("version_name") != expected_version_name
        or analysis.get("version_code") != expected_version_code
    ):
        raise SignerError("APK application or version identity belongs to another target")
    expected_form = {
        "android-phone-tablet-apk": (False, False),
        "android-tv-apk": (True, False),
    }[target_id]
    if (analysis.get("is_tv"), analysis.get("is_wear")) != expected_form:
        raise SignerError("APK form-factor identity belongs to another exact target")
    if analysis.get("abis") != APK_REQUIRED_ABIS[target_id]:
        raise SignerError("APK architecture identity belongs to another exact target")
    signing = analysis.get("apk_signing")
    if (
        type(signing) is not dict
        or signing.get("verified_v2") is not True
        or signing.get("verified_v3") is not True
        or signing.get("signer_count") != 1
        or signing.get("certificate_sha256") != _reviewed_upload_certificate()
    ):
        raise SignerError("APK signer does not exactly match the reviewed upload certificate")
    subject = signing.get("certificate_subject")
    if type(subject) is not str or DEBUG_SIGNER_MARKER in subject.casefold():
        raise SignerError("APK is signed by the Android debug signer")
    if analysis.get("target_sdk") != 37:
        raise SignerError("APK target SDK posture is not current or exact")
    if analysis.get("debuggable") is not False:
        raise SignerError("APK release application must be explicitly non-debuggable")
    if target_id == "android-phone-tablet-apk":
        if analysis.get("application_label") != "Calculator":
            raise SignerError("Android phone APK must carry the Calculator application label")
    if target_id == "android-tv-apk":
        required = analysis.get("feature_required")
        if type(required) is not dict:
            raise SignerError("Android TV APK feature requirements are not Play-compatible")
        if required.get("android.software.leanback") not in {"false", "0"} or required.get(
            "android.hardware.touchscreen"
        ) not in {"false", "0"}:
            raise SignerError("Android TV APK feature requirements are not Play-compatible")
        if (
            analysis.get("application_label") != "Win's VPN"
            or analysis.get("application_banner") != "@drawable/banner"
            or "org.winsvpn.app.MainActivity" not in set(analysis.get("activities") or [])
        ):
            raise SignerError("Android TV APK must carry the real Win's VPN label and @drawable/banner")
    if analysis.get("has_leanback_launcher") and target_id == "android-phone-tablet-apk":
        raise SignerError("APK form-factor identity belongs to another exact target")
    _enforce_phone_tv_payload(target_id, analysis)


def verify_held_apk_artifact(
    *,
    target_id: str,
    source_fd: int,
    expected_identity: tuple[int, int],
    expected_size: int,
    expected_sha256: str,
) -> dict[str, object]:
    """Verify one descriptor-held APK with the exact Android SDK apksigner."""

    if target_id not in PHONE_TV_APK_TARGETS:
        raise SignerError(f"unsupported exact Android APK target: {target_id}")
    with (
        _HeldAabArtifact(
            source_fd=source_fd,
            expected_identity=expected_identity,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        ) as held,
        _HeldAndroidVerificationTools(bind_bundletool=False) as tools,
        _HeldApksigner() as apksigner,
    ):
        pass_fds = tuple(
            dict.fromkeys(
                (*held.pass_fds, *tools.pass_fds, *apksigner.pass_fds)
            )
        )

        def validate_all() -> None:
            held.revalidate()
            tools.revalidate(full_tree=True)
            apksigner.revalidate()

        analysis = analyze_held_apk(held.payload)
        validate_all()
        output = _run(
            [
                _bound_jdk_tool("java"),
                "-jar",
                str(apksigner.path),
                "verify",
                "-Werr",
                "--verbose",
                "--print-certs",
                str(held.tool_path),
            ],
            "custody-pinned Android SDK apksigner APK verification",
            timeout=60,
            pass_fds=pass_fds,
            revalidate=validate_all,
            watch_fds=pass_fds,
        )
        analysis["apk_signing"] = _parse_apksigner_verification(output)
        _enforce_apk_target_identity(target_id, analysis)
        validate_all()
        return {
            "ok": True,
            "target_id": target_id,
            "artifact": {
                "sha256": expected_sha256,
                "bytes": expected_size,
            },
            "package_identity": {
                "package": analysis["package"],
                "version_name": analysis["version_name"],
                "version_code": analysis["version_code"],
                "target_sdk": analysis["target_sdk"],
                "debuggable": analysis["debuggable"],
            },
            "signing": analysis["apk_signing"],
        }


def _verify_apk_target_identity(target_id: str, path: pathlib.Path) -> None:
    relative = path.relative_to(ROOT).as_posix()
    with _retained_live_repo_file(relative, "phone/TV APK") as bound:
        source_fd, identity, size, digest = bound
        verify_held_apk_artifact(
            target_id=target_id,
            source_fd=source_fd,
            expected_identity=identity,
            expected_size=size,
            expected_sha256=digest,
        )


def verify_apk(path: pathlib.Path) -> None:
    resolved = path.expanduser()
    if resolved.suffix.lower() != ".apk":
        raise SignerError(f"expected an exact .apk artifact: {resolved}")
    data, identity, digest = _hold_aab_bytes(resolved)
    analyze_held_apk(data)
    _revalidate_held_aab(resolved, identity, digest)


def canonical_apk_gate_verify(target_id: str, raw_path: str) -> None:
    path = _canonical_gate_apk(target_id, raw_path)
    relative = path.relative_to(ROOT).as_posix()
    with _retained_live_repo_file(relative, "phone/TV APK") as bound:
        source_fd, identity, size, digest = bound
        verify_held_apk_artifact(
            target_id=target_id,
            source_fd=source_fd,
            expected_identity=identity,
            expected_size=size,
            expected_sha256=digest,
        )
        _reviewed_store_metadata(target_id)
    print(
        f"ANDROID PHONE/TV APK GATE: PASS target={target_id} artifact={raw_path}"
    )


def _parse_manifest(raw: bytes) -> list[dict[str, str]]:
    physical_lines = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    logical_lines: list[bytes] = []
    for line in physical_lines:
        if line.startswith(b" "):
            if not logical_lines or logical_lines[-1] == b"":
                raise SignerError("invalid continuation line in AAB JAR manifest")
            logical_lines[-1] += line[1:]
        else:
            logical_lines.append(line)

    sections: list[dict[str, str]] = []
    section: dict[str, str] = {}
    for line in logical_lines + [b""]:
        if line == b"":
            if section:
                sections.append(section)
                section = {}
            continue
        if b": " not in line:
            raise SignerError("invalid header in AAB JAR manifest")
        raw_key, raw_value = line.split(b": ", 1)
        try:
            key = raw_key.decode("ascii")
            value = raw_value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SignerError("invalid text encoding in AAB JAR manifest") from exc
        folded_key = key.casefold()
        if folded_key in section:
            raise SignerError(f"duplicate {key} header in AAB JAR manifest")
        section[folded_key] = value
    if not sections:
        raise SignerError("AAB JAR manifest is empty")
    return sections


def _is_signature_metadata(name: str) -> bool:
    upper = name.upper()
    if upper == "META-INF/MANIFEST.MF":
        return True
    if not upper.startswith("META-INF/") or "/" in upper[len("META-INF/") :]:
        return False
    basename = upper[len("META-INF/") :]
    return basename.startswith("SIG-") or upper.endswith((".SF", ".RSA", ".DSA", ".EC"))


def _verify_manifest_coverage(
    archive: zipfile.ZipFile, names: list[str], signature_file: str
) -> None:
    manifest_names = [name for name in names if name.upper() == "META-INF/MANIFEST.MF"]
    if len(manifest_names) != 1:
        raise SignerError("AAB must contain exactly one META-INF/MANIFEST.MF")
    raw_manifest = archive.read(manifest_names[0])
    sections = _parse_manifest(raw_manifest)
    if "manifest-version" not in sections[0]:
        raise SignerError("AAB JAR manifest lacks Manifest-Version")

    covered: dict[str, str] = {}
    for section in sections[1:]:
        name = section.get("name")
        digest = section.get("sha-256-digest")
        if name is None or digest is None:
            raise SignerError("AAB JAR manifest entry lacks Name or SHA-256-Digest")
        if name in covered:
            raise SignerError(f"duplicate AAB JAR manifest section: {name}")
        covered[name] = digest

    required = {
        name for name in names if not name.endswith("/") and not _is_signature_metadata(name)
    }
    missing = sorted(required - covered.keys())
    extra = sorted(covered.keys() - required)
    if missing:
        raise SignerError(f"AAB contains unsigned manifest entry: {missing[0]}")
    if extra:
        raise SignerError(f"AAB manifest references a missing entry: {extra[0]}")
    for name in sorted(required):
        expected = base64.b64encode(hashlib.sha256(archive.read(name)).digest()).decode("ascii")
        if covered[name] != expected:
            raise SignerError(f"AAB manifest SHA-256 mismatch: {name}")

    signature_sections = _parse_manifest(archive.read(signature_file))
    if "signature-version" not in signature_sections[0]:
        raise SignerError("AAB .SF file lacks Signature-Version")
    signed_manifest_digest = signature_sections[0].get("sha-256-digest-manifest")
    expected_manifest_digest = base64.b64encode(hashlib.sha256(raw_manifest).digest()).decode(
        "ascii"
    )
    if signed_manifest_digest != expected_manifest_digest:
        raise SignerError("AAB .SF file does not authenticate the complete JAR manifest")


def verify_bytes(data: bytes) -> None:
    with _open_held_zip(data) as archive:
        raw_names = archive.namelist()
        if len(raw_names) != len(set(raw_names)):
            raise SignerError("AAB contains duplicate ZIP member names")
        upper_names = [name.upper() for name in raw_names]
        if len(upper_names) != len(set(upper_names)):
            raise SignerError("AAB contains case-colliding ZIP member names")
        block_files = [
            name
            for name in upper_names
            if name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC"))
        ]
        signature_files = [
            name for name in upper_names if name.startswith("META-INF/") and name.endswith(".SF")
        ]
        if len(block_files) != 1 or len(signature_files) != 1:
            raise SignerError("AAB must contain exactly one signature block and one .SF file")
        if block_files[0].rsplit(".", 1)[0] != signature_files[0].rsplit(".", 1)[0]:
            raise SignerError("AAB signature block and .SF signer names do not match")
        signature_file = raw_names[upper_names.index(signature_files[0])]
        _verify_manifest_coverage(archive, raw_names, signature_file)


def verify(path: pathlib.Path) -> None:
    resolved = path.expanduser()
    if resolved.suffix.lower() != ".aab":
        raise SignerError(f"expected an exact .aab artifact: {resolved}")
    data, identity, digest = _hold_aab_bytes(resolved)
    verify_bytes(data)
    _revalidate_held_aab(resolved, identity, digest)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = pathlib.Path(name)

        def write_aab(path: pathlib.Path, signers: tuple[str, ...], payload: bytes = b"payload") -> None:
            digest = base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")
            manifest = (
                "Manifest-Version: 1.0\r\n\r\n"
                "Name: base/root/file.txt\r\n"
                f"SHA-256-Digest: {digest}\r\n\r\n"
            ).encode("ascii")
            manifest_digest = base64.b64encode(hashlib.sha256(manifest).digest()).decode("ascii")
            signature = (
                "Signature-Version: 1.0\r\n"
                f"SHA-256-Digest-Manifest: {manifest_digest}\r\n\r\n"
            ).encode("ascii")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", manifest)
                for signer in signers:
                    archive.writestr(f"META-INF/{signer}.RSA", b"block")
                    archive.writestr(f"META-INF/{signer}.SF", signature)
                archive.writestr("base/root/file.txt", payload)

        valid = root / "valid.aab"
        write_aab(valid, ("UPLOAD",))
        verify(valid)
        multiple = root / "multiple.aab"
        write_aab(multiple, ("UPLOAD", "EXTRA"))
        try:
            verify(multiple)
        except SignerError:
            pass
        else:
            raise SignerError("self-test accepted multiple AAB signers")
        same_stem = root / "same-stem.aab"
        write_aab(same_stem, ("UPLOAD",))
        with zipfile.ZipFile(same_stem, "a") as archive:
            archive.writestr("META-INF/UPLOAD.EC", b"second block")
        try:
            verify(same_stem)
        except SignerError:
            pass
        else:
            raise SignerError("self-test accepted multiple same-stem signature blocks")
        bad_signature = root / "bad-signature-file.aab"
        with zipfile.ZipFile(valid) as source, zipfile.ZipFile(bad_signature, "w") as target:
            for member in source.infolist():
                data = source.read(member.filename)
                if member.filename.upper().endswith(".SF"):
                    data = (
                        b"Signature-Version: 1.0\r\n"
                        b"SHA-256-Digest-Manifest: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n"
                    )
                target.writestr(member, data)
        try:
            verify(bad_signature)
        except SignerError:
            pass
        else:
            raise SignerError("self-test accepted an unauthenticated complete manifest")
        tampered = root / "tampered.aab"
        write_aab(tampered, ("UPLOAD",), b"original")
        with zipfile.ZipFile(tampered, "a") as archive:
            archive.writestr("base/root/unsigned.txt", b"unsigned")
        try:
            verify(tampered)
        except SignerError:
            pass
        else:
            raise SignerError("self-test accepted an entry absent from the manifest")
        proto = encode_xml_node_element(
            encode_xml_element(
                "manifest",
                [
                    encode_xml_attribute("package", EXPECTED_APPLICATION_ID),
                    encode_xml_attribute(
                        "versionName",
                        "1.0.16",
                        namespace=ANDROID_NS,
                        resource_id=ATTR_VERSION_NAME,
                    ),
                    encode_xml_attribute(
                        "versionCode",
                        "33",
                        namespace=ANDROID_NS,
                        resource_id=ATTR_VERSION_CODE,
                        compiled=encode_compiled_int(33),
                    ),
                ],
                [],
                ns_decls=[encode_xml_namespace("android", ANDROID_NS)],
            )
        )
        decoded = _decode_proto_manifest(proto)
        if decoded.get("package") != EXPECTED_APPLICATION_ID:
            raise SignerError("self-test failed to decode proto package identity")
        if decoded.get(ANDROID + "versionCode") != "33":
            raise SignerError("self-test failed to decode proto versionCode")
    print("ANDROID AAB SINGLE SIGNER SELF-TEST: PASS")


def _parse_identity_verify_argv(raw_argv: list[str], *, kind: str) -> tuple[str, str]:
    usage = (
        f"canonical cross-store usage is exactly --{kind} <target-id> <artifact-path> "
        "--java <pinned-jdk>/bin/java --jarsigner <pinned-jdk>/bin/jarsigner "
        "--keytool <pinned-jdk>/bin/keytool"
    )
    rest = raw_argv[1:]
    if (
        len(rest) != 8
        or rest[2] != "--java"
        or rest[4] != "--jarsigner"
        or rest[6] != "--keytool"
    ):
        raise SignerError(usage)
    if kind == "verify":
        _canonical_gate_artifact(rest[0], rest[1])
    elif kind == "verify-apk":
        _canonical_gate_apk(rest[0], rest[1])
    else:
        raise SignerError("unsupported Android identity verification kind")
    java = _authenticate_jdk_tool(rest[3], "java")
    jarsigner = _authenticate_jdk_tool(rest[5], "jarsigner")
    keytool = _authenticate_jdk_tool(rest[7], "keytool")
    if len({java.parent, jarsigner.parent, keytool.parent}) != 1:
        raise SignerError("AAB identity JDK tools must share one authenticated bin directory")
    return rest[0], rest[1]


def _main_authenticated(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv[:1] == ["--verify"]:
        target_id, artifact_path = _parse_identity_verify_argv(raw_argv, kind="verify")
        with _HeldAndroidVerificationTools():
            canonical_gate_verify(target_id, artifact_path)
        return 0
    if raw_argv[:1] == ["--verify-apk"]:
        target_id, artifact_path = _parse_identity_verify_argv(raw_argv, kind="verify-apk")
        with _HeldAndroidVerificationTools():
            canonical_apk_gate_verify(target_id, artifact_path)
        return 0
    if raw_argv[:1] == ["--bind-r8"]:
        rest = raw_argv[1:]
        if len(rest) != 3:
            raise SignerError(
                "canonical R8 bind usage is exactly --bind-r8 <target-id> "
                "<artifact-path> <mapping-path>"
            )
        bound = bind_private_r8_mapping(rest[0], rest[1], rest[2])
        print(
            "ANDROID R8 BIND: PASS "
            f"target={bound['target_id']} pg_map_hash={bound['pg_map_hash']}"
        )
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("aab", nargs="?", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(raw_argv)
    if args.self_test:
        self_test()
    elif args.aab:
        verify(args.aab)
        print(f"ANDROID AAB SINGLE SIGNER: PASS {args.aab}")
    else:
        parser.error("provide an AAB or --self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    with _pinned_release_python_runtime():
        return _main_authenticated(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SignerError as exc:
        print(f"ANDROID AAB SIGNER: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
