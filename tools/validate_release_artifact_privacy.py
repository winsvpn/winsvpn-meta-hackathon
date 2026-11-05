#!/usr/bin/env python3
"""Fail closed when release clients contain control-origin or secret material."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import warnings
import zipfile
import zlib
from collections.abc import Iterable, Iterator, Mapping

if __package__:
    from tools.release_obfuscation_contract import ObfuscationError
    from tools.release_obfuscation_contract import SECRET_SCAN_DEFERRAL_NOTICE
    from tools.release_obfuscation_contract import require_secret_scan_deferral
    from tools.release_obfuscation_contract import inspect_native_debug_sections
    from tools.release_obfuscation_contract import is_store_only_native_debug_metadata
    from tools.release_obfuscation_contract import label_requires_native_parse
    from tools.release_secret_inventory import InventoryError
    from tools.release_secret_inventory import SecretInventory
    from tools.release_secret_inventory import load_authenticated_secret_inventory
    from tools.release_secret_inventory import release_secret_values
    from tools.release_secret_scan_policy import CREDENTIAL_ASSIGNMENT_RE
    from tools.release_secret_scan_policy import CREDENTIAL_PLACEHOLDER_RE
    from tools.release_secret_scan_policy import CREDENTIAL_REFERENCE_RE
    from tools.release_secret_scan_policy import ED25519_SPKI_PREFIX
    from tools.release_secret_scan_policy import PUBLIC_PEM_MARKERS
    from tools.release_secret_scan_policy import REUSABLE_SECRET_PATTERNS
    from tools.release_secret_scan_policy import SOURCE_MEMBER_REFERENCE_RE
    from tools.release_secret_scan_policy import contains_only_public_crypto_material
    from tools.release_secret_scan_policy import packaged_credential_assignment
    from tools.release_secret_scan_policy import reusable_secret_category
    from tools.release_secret_scan_policy import service_account_member_name
else:
    from release_obfuscation_contract import ObfuscationError
    from release_obfuscation_contract import SECRET_SCAN_DEFERRAL_NOTICE
    from release_obfuscation_contract import require_secret_scan_deferral
    from release_obfuscation_contract import inspect_native_debug_sections
    from release_obfuscation_contract import is_store_only_native_debug_metadata
    from release_obfuscation_contract import label_requires_native_parse
    from release_secret_inventory import InventoryError
    from release_secret_inventory import SecretInventory
    from release_secret_inventory import load_authenticated_secret_inventory
    from release_secret_inventory import release_secret_values
    from release_secret_scan_policy import CREDENTIAL_ASSIGNMENT_RE
    from release_secret_scan_policy import CREDENTIAL_PLACEHOLDER_RE
    from release_secret_scan_policy import CREDENTIAL_REFERENCE_RE
    from release_secret_scan_policy import ED25519_SPKI_PREFIX
    from release_secret_scan_policy import PUBLIC_PEM_MARKERS
    from release_secret_scan_policy import REUSABLE_SECRET_PATTERNS
    from release_secret_scan_policy import SOURCE_MEMBER_REFERENCE_RE
    from release_secret_scan_policy import contains_only_public_crypto_material
    from release_secret_scan_policy import packaged_credential_assignment
    from release_secret_scan_policy import reusable_secret_category
    from release_secret_scan_policy import service_account_member_name


ROOT = pathlib.Path(__file__).resolve().parent.parent
EXTENSION_CROSS_STORE_TARGETS = {
    "chrome-extension-package": ("chrome", frozenset({".zip"})),
    "edge-extension-package": ("edge", frozenset({".zip"})),
    "firefox-extension-package": ("firefox", frozenset({".zip", ".xpi"})),
}
EXTENSION_PRIVATE_MEMBER_SUFFIXES = frozenset(
    {
        ".a",
        ".dll",
        ".dylib",
        ".exe",
        ".jks",
        ".key",
        ".keystore",
        ".map",
        ".node",
        ".p12",
        ".pem",
        ".pfx",
        ".so",
        ".wasm",
    }
)
BASE_DEFAULT_ARTIFACTS = (
    ROOT / "build" / "app" / "outputs" / "flutter-apk" / "app-release.apk",
    ROOT / "build" / "app" / "outputs" / "bundle" / "release" / "app-release.aab",
    ROOT / "build" / "windows" / "x64" / "runner" / "Release",
    ROOT / "build" / "windows-installer" / "WinsVPN-Setup.exe",
    ROOT / "web" / "downloads" / "wins-vpn-linux-x64.tar.gz",
)
APPLE_RELEASE_CANDIDATE_MANIFEST = (
    ROOT / "app_store" / "apple" / "artifacts" / "release_candidate.json"
)
STATIC_PATHS = (
    ROOT / "lib",
    ROOT / "android" / "app" / "src" / "main",
    ROOT / "wear_os" / "app" / "src" / "main",
    ROOT / "extension" / "src",
    ROOT / "extension" / "manifest",
    ROOT / "windows" / "runner",
    ROOT / "linux" / "runner",
    ROOT / "ios",
    ROOT / "macos",
    ROOT / "apple",
    ROOT / "tools" / "local_release_gate.ps1",
    ROOT / "tools" / "build_linux_release.sh",
    ROOT / "installer" / "windows" / "build_installer.ps1",
)
IGNORED_STATIC_PARTS = {
    "build",
    ".gradle",
    "pods",
    "deriveddata",
    "ephemeral",
    "xcuserdata",
}
IGNORED_STATIC_NAMES = {"Generated.xcconfig", "flutter_export_environment.sh"}

# These names/endpoints belonged to the removed direct-origin/SPA client path.
# They may remain server-local, but must never enter a customer application.
FORBIDDEN_CLIENT_LITERALS = {
    "admin_token_name": b"ADMIN_TOKEN",
    "paypal_secret_name": b"PAYPAL_CLIENT_SECRET",
    "cloudflare_secret_name": b"CLOUDFLARE_API_TOKEN",
    "rclone_secret_name": b"RCLONE_CONFIG_B64",
    "legacy_spa_ip_name": b"WINS_SPA_IP",
    "legacy_spa_port_name": b"WINS_SPA_PORT",
    "legacy_spa_target_name": b"WINS_SPA_TARGET_PORT",
    "legacy_spa_key_name": b"WINS_SPA_KEY",
    "legacy_spa_hmac_name": b"WINS_SPA_HMAC",
    "legacy_direct_api_port": b":8000",
    "plaintext_hub_hostname": b"http://hub.winsvpn.org",
    "plaintext_sync_hostname": b"http://sync.app-cloud-sync.net",
}
# Windows native code carries the same names as UTF-16 code units. The wide forms
# are scanned for every ASCII literal long enough to be unambiguous: a five-byte
# token such as ":8000" interleaved with NULs is too short to rule out vendor
# wide strings, so it keeps its single-byte scan only (R24 V2 F-13).
UTF16_MIN_LITERAL_BYTES = 8


def _utf16_literal_forms(literal: bytes) -> tuple[bytes, ...]:
    if len(literal) < UTF16_MIN_LITERAL_BYTES or any(byte >= 0x80 for byte in literal):
        return ()
    return (
        b"".join(bytes((byte, 0)) for byte in literal),
        b"".join(bytes((0, byte)) for byte in literal),
    )


FORBIDDEN_CLIENT_LITERAL_PATTERNS = {
    # Match the retired numeric port as a complete decimal token. R8 mapping
    # method hashes can contain the same five digits inside a larger number,
    # which is not an embedded endpoint (for example m$622015610).
    "legacy_spa_udp_port": re.compile(rb"(?<![0-9])62201(?![0-9])"),
}
# Keep sensitive control/operator addresses out of the repository as well as
# out of customer artifacts.  The scanner extracts complete IPv4 tokens from
# ASCII and UTF-16 blobs and compares their SHA-256 digests.  A digest cannot
# disclose the original address, while an exact client-side occurrence still
# fails closed with a named category.
FORBIDDEN_CLIENT_ADDRESS_SHA256 = {
    "historic_control_origin": "9b3bd762b22be297338da1d0226c0a4a5db85fad4e367e3fc4b8119df590282d",
    "trusted_operator_ip_1": "0e538368ac6a1ee2f8ed563824766e323c3676196d8841f8f8c5acb5e1b8e395",
    "trusted_operator_ip_2": "7bf1edfdde055cdd62710aedb80b4a722aed872b5a56a04e0f947be89c785876",
    "physical_core_lan_ip": "5185fcadd1ad3a51d40e2a6d5c523e10a96c49f31b107cb58598160a235b470e",
}
IPV4_TOKEN_RE = re.compile(
    rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"
)
IPV4_TOKEN_UTF16_LE_RE = re.compile(
    rb"(?<![0-9]\x00)(?:(?:[0-9]\x00){1,3}\.\x00){3}(?:[0-9]\x00){1,3}(?![0-9]\x00)"
)
IPV4_TOKEN_UTF16_BE_RE = re.compile(
    rb"(?<!\x00[0-9])(?:(?:\x00[0-9]){1,3}\x00\.){3}(?:\x00[0-9]){1,3}(?!\x00[0-9])"
)
PUBLIC_IP_URI_RE = re.compile(
    rb"(?i)(?:https?|wss?)://(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    rb"(?::[0-9]{1,5})?(?:/[^\x00\s\"'<>$]*)?"
)
# The same URI as UTF-16 code units (Windows wide strings, R23 W1-14). Like
# the IPv4 token forms above these match at any byte alignment; the match is
# decoded to ASCII so the approved digests keep their meaning.
PUBLIC_IP_URI_UTF16_LE_RE = re.compile(
    rb"(?i)(?:h\x00t\x00t\x00p\x00(?:s\x00)?|w\x00s\x00(?:s\x00)?):\x00/\x00/\x00"
    rb"(?:(?:[0-9]\x00){1,3}\.\x00){3}(?:[0-9]\x00){1,3}"
    rb"(?::\x00(?:[0-9]\x00){1,5})?(?:/\x00(?:[^\x00\s\"'<>$]\x00)*)?"
)
PUBLIC_IP_URI_UTF16_BE_RE = re.compile(
    rb"(?i)(?:\x00h\x00t\x00t\x00p(?:\x00s)?|\x00w\x00s(?:\x00s)?)\x00:\x00/\x00/"
    rb"(?:(?:\x00[0-9]){1,3}\x00\.){3}(?:\x00[0-9]){1,3}"
    rb"(?:\x00:(?:\x00[0-9]){1,5})?(?:\x00/(?:\x00[^\x00\s\"'<>$])*)?"
)
# The current Android AmneziaWG bridge contains one fixed Cloudflare DNS-over-
# HTTPS fallback. Keep only its digest here so the scanner itself never becomes
# another source for an IP URI. Every other IP-based URI remains release-fatal.
APPROVED_THIRD_PARTY_IP_URI_SHA256 = {
    "e5a04c48dac20c60cff5befef3723a71be058edf6ed729d7a2d044639bca71cf",
}
# Exact executables extracted from the pinned Xray 26.9.30 release archives.
# Their own upstream data tables contain public service IP URIs. An altered
# executable gets no exception and is rejected before it can be released.
APPROVED_VENDOR_BINARY_SHA256 = {
    "30772382fcee4fe18b6c31a3daf9a53878b5bfa775e05ea3f3c8cb0b0ec73b2b",  # Android arm64 source
    "35e5256bce15bc30bd3dbf7ba82c7ac6b138782eae811e0ae4ab535fbedec1b9",  # Android armv7 source
    "82885af5bc2c89eb10201af08049d865c398025fe89f2b8cd02178fc275876b4",  # Android x64 source
    "78ecc9ebaf6e0cd43132fb0f72b7915e0ad7970f7868e2454f7308151797c6f6",  # APK-stripped Android arm64
    "26e2688e76e15bc96fdbdbbbbbd98b26090e88cacf51936569f9400f2e55188b",  # APK-stripped Android armv7
    "9c2045c1e201128916bc2bac5cee65fdd8de35520a31d601c71cdbd51e202032",  # APK-stripped Android x64
    "fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224",  # Windows x64
    "09e63d5420f26db2bc6144f6d047601909541acf21792878d3859e4fc4980a12",  # Linux x64
    "868fcabbf9a08d1e453bc6dc82dd8ca27cfcf8cdb2b3a8ff31b824361966964b",  # Linux arm64
}
# Wintun 0.14.1 is redistributed as the upstream, WireGuard-signed binary.
# Those exact binaries contain upstream CodeView/PDB build paths and cannot be
# stripped without invalidating the vendor signature. This exception is
# deliberately narrower than APPROVED_VENDOR_BINARY_SHA256: it applies only to
# a member whose basename is exactly wintun.dll and whose complete bytes match
# one reviewed architecture pin. Secret and credential scans still run.
APPROVED_VENDOR_DEBUG_METADATA_SHA256 = {
    "wintun.dll": frozenset(
        {
            "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",  # x64
            "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",  # arm64
        }
    ),
    # The AmneziaWG `awg` CLI ships with its ELF symbol table (.symtab; no
    # DWARF). linux/x64 is the upstream binary from the digest-pinned
    # amneziawg-tools zip (AWG_BINARY_SHA256) and cannot be stripped without
    # leaving its pin; linux/arm64 is the from-source build pinned by
    # AWG_BINARY_SHA256_ARM64. Both pins live in tools/build_linux_release.sh and
    # the owner's store contract; the symbols are upstream's public ones.
    "awg": frozenset(
        {
            "23d29323258166183eeeb288c1f9f08b879f3707e54591b1bfb2402413f6d8d8",  # linux x64 (upstream)
            "bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d",  # linux arm64 (from source)
        }
    ),
}
LOCAL_USER_HOME_PATH_RE = re.compile(
    r"(?i)(?:[a-z]:[\\/](?:users|documents and settings)[\\/]"
    r"[^\\/\x00\r\n]{1,128}[\\/]|/(?:users|home)/[^/\x00\r\n]{1,128}/)"
)
SOURCE_TREE_PATH_RE = re.compile(
    r"(?i)(?:[a-z]:[\\/]|/)(?:[^\\/\x00\r\n]{1,128}[\\/]){0,12}"
    r"(?:wins_vpn|wins-vpn)[\\/]"
    r"(?:android|apple|build|ios|lib|linux|macos|tools|windows)[\\/]"
)
# Stable re-exports for tests and sibling scanners.
_POLICY_REEXPORTS = (
    CREDENTIAL_ASSIGNMENT_RE,
    CREDENTIAL_PLACEHOLDER_RE,
    CREDENTIAL_REFERENCE_RE,
    ED25519_SPKI_PREFIX,
    PUBLIC_PEM_MARKERS,
    REUSABLE_SECRET_PATTERNS,
    SOURCE_MEMBER_REFERENCE_RE,
)



MAX_ENCODED_SECRET_FORMS = 96
TARGET_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,80}")
MAX_ARCHIVE_INPUT_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBER_COUNT = 20_000
MAX_ARCHIVE_MEMBER_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_TOTAL_EXPANDED_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 1_000
MAX_ARCHIVE_PATH_DEPTH = 16
MAX_ARCHIVE_PATH_BYTES = 4_096
MAX_ARCHIVE_NEST_DEPTH = 4
MAX_NESTED_ARCHIVE_COUNT = 64
MAX_METADATA_BYTES = 64 * 1024
SNAPSHOT_READ_CHUNK = 1024 * 1024
MEMBER_READ_CHUNK = 64 * 1024
PUBLIC_MEMBER_LABEL = "archive-member"
ZIP_MAGIC_SUFFIXES = frozenset(
    {".aab", ".apk", ".ipa", ".jar", ".war", ".xpi", ".zip", ".app.zip"}
)
GZIP_TAR_SUFFIXES = frozenset({".tar.gz", ".tgz"})
TAR_SUFFIXES = frozenset({".tar", ".tar.bz2", ".tar.xz", ".tar.zst", ".tbz2", ".txz", ".tzst"})
TARGET_ARTIFACT_SUFFIXES: dict[str, tuple[str, ...]] = {
    "android-phone-tablet-apk": (".apk",),
    "android-phone-tablet-aab": (".aab",),
    "android-tv-apk": (".apk",),
    "android-tv-aab": (".aab",),
    "wear-os-aab": (".aab",),
    "ios-app-store-ipa": (".ipa",),
    "macos-app-store-pkg": (".pkg",),
    "windows-x64-installer": (".exe",),
    "windows-x64-partner-center": (".exe",),
    "windows-arm64-installer": (".exe",),
    "windows-arm64-partner-center": (".exe",),
    "linux-x64-package": (".tar.gz",),
    "linux-arm64-package": (".tar.gz",),
    "linux-flathub-manifest": (".json",),
    "linux-snap-manifest": (".yaml", ".yml"),
    "chrome-extension-package": (".zip",),
    "edge-extension-package": (".zip",),
    "firefox-extension-package": (".xpi", ".zip"),
    "macos-developer-id-app": (".app.zip",),
}
REQUIRED_PRIVACY_TARGET_IDS: tuple[str, ...] = (
    "android-phone-tablet-apk",
    "android-phone-tablet-aab",
    "android-tv-apk",
    "android-tv-aab",
    "wear-os-aab",
    "ios-app-store-ipa",
    "macos-app-store-pkg",
    "windows-x64-installer",
    "windows-x64-partner-center",
    "windows-arm64-installer",
    "windows-arm64-partner-center",
    "linux-x64-package",
    "linux-arm64-package",
    "linux-flathub-manifest",
    "linux-snap-manifest",
    "chrome-extension-package",
    "edge-extension-package",
    "firefox-extension-package",
)
OPTIONAL_PRIVACY_TARGET_IDS: frozenset[str] = frozenset({"macos-developer-id-app"})
KNOWN_PRIVACY_TARGET_IDS: frozenset[str] = (
    frozenset(REQUIRED_PRIVACY_TARGET_IDS) | OPTIONAL_PRIVACY_TARGET_IDS
)
DEFAULT_TARGET_RELATIVE_PATHS: dict[str, str] = {
    "android-phone-tablet-apk": "build/app/outputs/flutter-apk/app-phone-release.apk",
    "android-phone-tablet-aab": "build/app/outputs/bundle/release/app-release.aab",
    "android-tv-apk": "build/app/outputs/flutter-apk/app-tv-release.apk",
    "android-tv-aab": "build/app/outputs/bundle/tvRelease/app-tv-release.aab",
    "wear-os-aab": "wear_os/app/build/outputs/bundle/release/app-release.aab",
    "windows-x64-installer": "build/windows-installer/WinsVPN-Setup.exe",
    "windows-x64-partner-center": "build/windows-installer/WinsVPN-PartnerCenter.exe",
    "windows-arm64-installer": "build/windows-installer/WinsVPN-Setup-arm64.exe",
    "windows-arm64-partner-center": "build/windows-installer/WinsVPN-PartnerCenter-arm64.exe",
    "linux-x64-package": "web/downloads/wins-vpn-linux-x64.tar.gz",
    "linux-arm64-package": "web/downloads/wins-vpn-linux-arm64.tar.gz",
    "linux-flathub-manifest": ".artifacts/linux/org.winsvpn.app.json",
    "linux-snap-manifest": ".artifacts/linux/snapcraft.yaml",
    "chrome-extension-package": "extension/dist/wins-vpn-companion-chrome.zip",
    "edge-extension-package": "extension/dist/wins-vpn-companion-edge.zip",
    "firefox-extension-package": "extension/dist/wins-vpn-companion-firefox.zip",
}
# Only a Windows installer scan can be deferred to the release host (the Windows
# build host cannot load the authenticated inventory). Every other target keeps
# its scan on the host that builds it.
DEFERRABLE_SECRET_SCAN_TARGET_IDS: frozenset[str] = frozenset(
    {
        "windows-x64-installer",
        "windows-x64-partner-center",
        "windows-arm64-installer",
        "windows-arm64-partner-center",
    }
)
TARGET_CANONICAL_FILENAMES: dict[str, frozenset[str]] = {
    "android-phone-tablet-apk": frozenset(
        {"app-phone-release.apk", "app-release.apk"}
    ),
    "android-phone-tablet-aab": frozenset(
        {"app-phone-release.aab", "app-release.aab"}
    ),
    "android-tv-apk": frozenset({"app-tv-release.apk"}),
    "android-tv-aab": frozenset({"app-tv-release.aab"}),
    "wear-os-aab": frozenset({"app-release.aab"}),
    "ios-app-store-ipa": frozenset({"winsvpn.ipa"}),
    "macos-app-store-pkg": frozenset({"winsvpn.pkg"}),
    "macos-developer-id-app": frozenset({"winsvpn.app.zip"}),
    "windows-x64-installer": frozenset(
        {"winsvpn-setup.exe", "winsvpn-unsigned-local-setup.exe"}
    ),
    "windows-x64-partner-center": frozenset(
        {
            "winsvpn-partnercenter.exe",
            "winsvpn-unsigned-local-partnercenter.exe",
        }
    ),
    "windows-arm64-installer": frozenset(
        {
            "winsvpn-setup-arm64.exe",
            "winsvpn-unsigned-local-setup-arm64.exe",
        }
    ),
    "windows-arm64-partner-center": frozenset(
        {
            "winsvpn-partnercenter-arm64.exe",
            "winsvpn-unsigned-local-partnercenter-arm64.exe",
        }
    ),
    "linux-x64-package": frozenset({"wins-vpn-linux-x64.tar.gz"}),
    "linux-arm64-package": frozenset({"wins-vpn-linux-arm64.tar.gz"}),
    "linux-flathub-manifest": frozenset({"org.winsvpn.app.json"}),
    "linux-snap-manifest": frozenset({"snapcraft.yaml", "snapcraft.yml"}),
    "chrome-extension-package": frozenset({"wins-vpn-companion-chrome.zip"}),
    "edge-extension-package": frozenset({"wins-vpn-companion-edge.zip"}),
    "firefox-extension-package": frozenset(
        {
            "wins-vpn-companion-firefox.zip",
            "wins-vpn-companion-firefox.xpi",
        }
    ),
}
TARGET_CANONICAL_SHARED_FILENAMES: frozenset[str] = frozenset({"app-release.aab"})
TARGET_REQUIRED_PATH_MARKERS: dict[str, frozenset[str]] = {
    "wear-os-aab": frozenset({"wear_os"}),
}
TARGET_FORBIDDEN_PATH_MARKERS: dict[str, frozenset[str]] = {
    "android-phone-tablet-apk": frozenset({"wear_os"}),
    "android-phone-tablet-aab": frozenset({"wear_os"}),
    "android-tv-apk": frozenset({"wear_os"}),
    "android-tv-aab": frozenset({"wear_os"}),
}
APPLE_MANIFEST_TOP_ALLOWED: frozenset[str] = frozenset(
    {
        "schema_version",
        "generated_at_utc",
        "app_version",
        "build_number",
        "candidate_set_status",
        "upload_status",
        "submission_package_validation_status",
        "submission_package_validation_log",
        "notes",
        "artifacts",
    }
)
APPLE_ARTIFACT_REQUIRED: frozenset[str] = frozenset(
    {"platform", "path", "size_bytes", "sha256"}
)
APPLE_ARTIFACT_ALLOWED: frozenset[str] = APPLE_ARTIFACT_REQUIRED | frozenset(
    {
        "lane",
        "type",
        "bundle_id",
        "packet_tunnel_bundle_id",
        "expected_current_bundle_id",
        "expected_current_packet_tunnel_bundle_id",
        "artifact_status",
        "upload_status",
        "archive_export_log",
        "verification_log",
        "source_fingerprint_contract",
        "source_fingerprint_sha256",
        "source_file_count",
        "verification_contract",
    }
)
APPLE_ARTIFACT_INT_KEYS: frozenset[str] = frozenset({"size_bytes", "source_file_count"})
JS_STRING_TOKEN_PATTERN = (
    rb'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)'
)
JS_STRING_TOKEN_RE = re.compile(JS_STRING_TOKEN_PATTERN)
# "a" + "b", ("a") + ("b"), `a` + `b`. Every whitespace run sits beside at most
# one optional parenthesis and a literal character, so a long run cannot
# backtrack quadratically (two adjacent \s* around an optional ")" can).
JS_CONCAT_STRINGS_RE = re.compile(
    rb"(?:"
    + JS_STRING_TOKEN_PATTERN
    + rb"\s*(?:\)\s*)?\+\s*(?:\(\s*)?)+"
    + JS_STRING_TOKEN_PATTERN
)
JS_DOT_CONCAT_RE = re.compile(
    JS_STRING_TOKEN_PATTERN
    + rb"\s*\.\s*concat\s*\(\s*"
    + JS_STRING_TOKEN_PATTERN
    + rb"(?:\s*,\s*"
    + JS_STRING_TOKEN_PATTERN
    + rb")*\s*\)"
)
# A join is bounded by the size of its result, not by its piece count: a secret
# split into hundreds of pieces is still one small value at runtime, while a
# long separator repeated per piece is the costly, amplifying form.
MAX_JS_JOIN_PIECES = 65536
MAX_JS_JOINED_BYTES = 16 * 1024 * 1024
JS_ARRAY_JOIN_RE = re.compile(
    rb"\[\s*(?P<body>"
    + JS_STRING_TOKEN_PATTERN
    + rb"(?:\s*,\s*"
    + JS_STRING_TOKEN_PATTERN
    + rb")+)\s*\]\s*\.\s*join\s*\(\s*"
    + rb"(?P<separator>"
    + JS_STRING_TOKEN_PATTERN
    + rb")\s*\)"
)
ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ACTIVE_SNAPSHOTS: list[dict[tuple[int, int], "ArtifactSnapshot"]] = []
_POST_PARENT_BIND_HOOK = None


class PrivacyError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class ArtifactPrivacyScanResult:
    passed: bool
    revision: str
    labels: tuple[str, ...]
    label_count: int
    unique_value_count: int
    target_id: str
    artifact_identity: str
    matched_labels: tuple[str, ...]
    blob_count: int
    # SHA-256 of the authenticated inventory file the scan loaded ("" for an
    # inventory that was not loaded as release coverage). It identifies the
    # inventory without disclosing a value, and the authenticated worker binds it
    # into the receipt of a Windows installer.
    inventory_sha256: str = ""


@dataclasses.dataclass(frozen=True)
class ArtifactSnapshot:
    data: bytes
    identity: tuple[int, ...]
    digest: str
    size: int
    suffix: str


class _ArchiveBudget:
    def __init__(self) -> None:
        self.member_count = 0
        self.expanded_bytes = 0
        self.nested_count = 0

    def reserve(self, expanded_size: int) -> None:
        if expanded_size < 0:
            raise PrivacyError("archive member reports a negative size")
        self.member_count += 1
        if self.member_count > MAX_ARCHIVE_MEMBER_COUNT:
            raise PrivacyError("release archive exceeds the member-count limit")
        if expanded_size > MAX_ARCHIVE_MEMBER_EXPANDED_BYTES:
            raise PrivacyError("archive member exceeds the expanded-size limit")
        if self.expanded_bytes + expanded_size > MAX_ARCHIVE_TOTAL_EXPANDED_BYTES:
            raise PrivacyError("release archive exceeds the aggregate expanded-size limit")
        self.expanded_bytes += expanded_size

    def reserve_nested(self) -> None:
        self.nested_count += 1
        if self.nested_count > MAX_NESTED_ARCHIVE_COUNT:
            raise PrivacyError("release archive exceeds the nested-archive limit")


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    """Exact file identity, including size and timestamps."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
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


class _BoundParent:
    """One descriptor-bound path component plus the child opened from it."""

    __slots__ = ("fd", "path", "lexical", "symlink", "child_name", "child")

    def __init__(
        self,
        fd: int,
        path: pathlib.Path,
        lexical: tuple[int, ...],
        *,
        symlink: bool,
    ) -> None:
        self.fd = fd
        self.path = path
        self.lexical = lexical
        self.symlink = symlink
        self.child_name: str | None = None
        self.child: tuple[int, ...] | None = None


def _fail_closed_parser(exc: BaseException) -> PrivacyError:
    del exc
    return PrivacyError("archive is not inspectable")


def _close_fds(fds: list[int]) -> None:
    for descriptor in fds:
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass


def _reject_artifact_stat(
    info: os.stat_result, *, directory_ok: bool = False
) -> None:
    mode = info.st_mode
    if stat.S_ISLNK(mode):
        raise PrivacyError("release artifact must be a regular non-symlink file")
    if (
        stat.S_ISFIFO(mode)
        or stat.S_ISCHR(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISSOCK(mode)
    ):
        raise PrivacyError("release artifact has an unsupported special file type")
    if stat.S_ISDIR(mode):
        if not directory_ok:
            raise PrivacyError("release artifact must be a regular non-symlink file")
    elif not stat.S_ISREG(mode):
        raise PrivacyError("release artifact must be a regular non-symlink file")
    if stat.S_ISREG(mode) and info.st_nlink != 1:
        raise PrivacyError("release artifact must have link count 1")
    if info.st_uid != os.getuid():
        raise PrivacyError("release artifact must be owned by the current user")
    filemode = stat.S_IMODE(mode)
    if filemode & 0o022 or filemode & 0o7000:
        raise PrivacyError("release artifact has an unsafe mode")


def _openat_available() -> bool:
    return callable(getattr(os, "openat", None))


def _open_nofollow_flags(*, write: bool = False, directory: bool = False, follow_root: bool = False) -> int:
    flags = getattr(os, "O_CLOEXEC", 0)
    if not follow_root:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow == 0:
            raise PrivacyError("artifact privacy scanning requires O_NOFOLLOW")
        flags |= nofollow
    if directory:
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        if directory_flag == 0:
            raise PrivacyError("artifact privacy scanning requires O_DIRECTORY")
        return flags | os.O_RDONLY | directory_flag
    if write:
        return flags | os.O_WRONLY | os.O_CREAT | os.O_EXCL
    return flags | os.O_RDONLY


def _peek_artifact_component(
    current_fd: int, current_path: pathlib.Path, part: str
) -> os.stat_result:
    try:
        if _openat_available():
            return os.stat(part, dir_fd=current_fd, follow_symlinks=False)
        return os.lstat(current_path)
    except OSError:
        raise PrivacyError("Required release artifact does not exist") from None


def _open_artifact_component(
    current_fd: int, current_path: pathlib.Path, part: str, flags: int
) -> int:
    try:
        if _openat_available():
            return os.openat(current_fd, part, flags)
        return os.open(current_path, flags)
    except OSError:
        raise PrivacyError(
            "release artifact must be a readable regular non-symlink file"
        ) from None


def _descriptor_child_stat(parent: _BoundParent) -> os.stat_result:
    if parent.child_name is None:
        raise PrivacyError("release artifact parent path was replaced")
    try:
        if _openat_available():
            return os.stat(parent.child_name, dir_fd=parent.fd, follow_symlinks=False)
        return os.lstat(parent.path / parent.child_name)
    except OSError:
        raise PrivacyError("release artifact parent path was replaced") from None


def _confirm_bound_parents(parents: list[_BoundParent], path: pathlib.Path) -> None:
    for parent in parents:
        try:
            parent_after = os.lstat(parent.path)
        except OSError:
            raise PrivacyError("release artifact parent path was replaced") from None
        if _pathname_identity(parent_after) != parent.lexical:
            raise PrivacyError("release artifact parent path was replaced")
        if parent.symlink:
            if not stat.S_ISLNK(parent_after.st_mode):
                raise PrivacyError("release artifact parent path was replaced")
        elif not stat.S_ISDIR(parent_after.st_mode):
            raise PrivacyError("release artifact parent path was replaced")
        if parent.child_name is None or parent.child is None:
            continue
        child_path = parent.path / parent.child_name
        child_message = (
            "release artifact was replaced"
            if child_path == path
            else "release artifact parent path was replaced"
        )
        try:
            child_after = _descriptor_child_stat(parent)
        except PrivacyError:
            raise PrivacyError(child_message) from None
        if _pathname_identity(child_after) != parent.child:
            raise PrivacyError(child_message)


def _artifact_suffix(path: pathlib.Path) -> str:
    name = path.name.casefold()
    for suffix in (
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".tar.zst",
        ".app.zip",
        ".tbz2",
        ".tgz",
        ".txz",
        ".tzst",
    ):
        if name.endswith(suffix):
            return suffix
    return path.suffix.lower()


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PrivacyError("duplicate JSON key")
        result[key] = value
    return result


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise PrivacyError("short write while recording an artifact snapshot")
        view = view[written:]


def _bound_member_path(name: str) -> None:
    encoded = name.encode("utf-8", errors="surrogateescape")
    if len(encoded) > MAX_ARCHIVE_PATH_BYTES:
        raise PrivacyError("archive member path exceeds the accepted bound")
    trimmed = name[:-1] if name.endswith("/") else name
    parts = trimmed.replace("\\", "/").split("/")
    if len(parts) > MAX_ARCHIVE_PATH_DEPTH:
        raise PrivacyError("archive member path exceeds the accepted depth")


def _read_stream_exact(handle: object, expected: int) -> bytes:
    if expected < 0 or expected > MAX_ARCHIVE_MEMBER_EXPANDED_BYTES:
        raise PrivacyError("archive member exceeds the expanded-size limit")
    chunks: list[bytes] = []
    remaining = expected
    while remaining:
        block = handle.read(min(MEMBER_READ_CHUNK, remaining))
        if not block:
            raise PrivacyError("archive member ended before its declared size")
        remaining -= len(block)
        chunks.append(block)
    extra = handle.read(1)
    if extra:
        raise PrivacyError("archive member exceeded its declared size")
    payload = b"".join(chunks)
    if len(payload) != expected:
        raise PrivacyError("archive member size does not match its metadata")
    return payload


def _snapshot_regular_file(path: pathlib.Path) -> ArtifactSnapshot:
    if not isinstance(path, pathlib.Path):
        path = pathlib.Path(path)
    if not path.is_absolute():
        path = pathlib.Path(os.path.abspath(path))
    try:
        initial = os.lstat(path)
    except OSError:
        raise PrivacyError("Required release artifact does not exist") from None
    if _ACTIVE_SNAPSHOTS:
        bound = None
        for snapshot in _ACTIVE_SNAPSHOTS[-1].values():
            if snapshot.identity == _stat_identity(initial):
                bound = snapshot
                break
        if bound is None:
            raise PrivacyError("release artifact was replaced")
        return bound
    _reject_artifact_stat(initial)
    if initial.st_size <= 0 or initial.st_size > MAX_ARCHIVE_INPUT_BYTES:
        raise PrivacyError("release artifact size is outside the accepted bound")
    file_flags = _open_nofollow_flags()
    dir_nofollow_flags = _open_nofollow_flags(directory=True)
    dir_follow_flags = _open_nofollow_flags(directory=True, follow_root=True)
    parent_fds: list[int] = []
    parents: list[_BoundParent] = []
    fd = -1
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    try:
        try:
            current_fd = os.open(path.anchor, dir_follow_flags)
        except OSError:
            raise PrivacyError("Required release artifact does not exist") from None
        parent_fds.append(current_fd)
        try:
            anchor_info = os.lstat(path.anchor)
        except OSError:
            raise PrivacyError("Required release artifact does not exist") from None
        anchor_path = pathlib.Path(path.anchor)
        parents.append(
            _BoundParent(
                current_fd,
                anchor_path,
                _pathname_identity(anchor_info),
                symlink=stat.S_ISLNK(anchor_info.st_mode),
            )
        )
        current_path = anchor_path
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            hook = _POST_PARENT_BIND_HOOK
            if hook is not None:
                hook(path, index)
            current_path = current_path / part
            peeked = _peek_artifact_component(current_fd, current_path, part)
            last = index == len(parts) - 1
            parents[-1].child_name = part
            parents[-1].child = _pathname_identity(peeked)
            if last:
                _reject_artifact_stat(peeked)
                component_flags = file_flags
            elif stat.S_ISLNK(peeked.st_mode):
                component_flags = dir_follow_flags
            elif stat.S_ISDIR(peeked.st_mode):
                component_flags = dir_nofollow_flags
            else:
                raise PrivacyError(
                    "release artifact must be a readable regular non-symlink file"
                )
            next_fd = _open_artifact_component(
                current_fd, current_path, part, component_flags
            )
            opened = os.fstat(next_fd)
            if last:
                if _stat_identity(peeked) != _stat_identity(opened):
                    os.close(next_fd)
                    raise PrivacyError("release artifact was replaced")
            elif not stat.S_ISLNK(peeked.st_mode):
                if _pathname_identity(peeked) != _pathname_identity(opened):
                    os.close(next_fd)
                    raise PrivacyError("release artifact was replaced")
            if last:
                fd = next_fd
            else:
                parent_fds.append(next_fd)
                parents.append(
                    _BoundParent(
                        next_fd,
                        current_path,
                        _pathname_identity(peeked),
                        symlink=stat.S_ISLNK(peeked.st_mode),
                    )
                )
                current_fd = next_fd
        before = os.fstat(fd)
        if _stat_identity(initial) != _stat_identity(before):
            raise PrivacyError("release artifact was replaced")
        _reject_artifact_stat(before)
        if before.st_size <= 0 or before.st_size > MAX_ARCHIVE_INPUT_BYTES:
            raise PrivacyError("release artifact size is outside the accepted bound")
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(SNAPSHOT_READ_CHUNK, remaining))
            if not block:
                raise PrivacyError("release artifact ended before its declared size")
            remaining -= len(block)
            digest.update(block)
            chunks.append(block)
        extra = os.read(fd, 1)
        if extra:
            raise PrivacyError("release artifact size changed while it was read")
        after = os.fstat(fd)
        if _stat_identity(before) != _stat_identity(after):
            raise PrivacyError("release artifact changed while it was read")
        try:
            path_after = os.lstat(path)
        except OSError:
            raise PrivacyError("release artifact was replaced") from None
        if _stat_identity(path_after) != _stat_identity(after):
            raise PrivacyError("release artifact was replaced")
        _confirm_bound_parents(parents, path)
    finally:
        if fd >= 0:
            parent_fds.append(fd)
        _close_fds(parent_fds)
    payload = b"".join(chunks)
    if len(payload) != before.st_size:
        raise PrivacyError("release artifact size is outside the accepted bound")
    return ArtifactSnapshot(
        data=payload,
        identity=_stat_identity(before),
        digest=digest.hexdigest(),
        size=before.st_size,
        suffix=_artifact_suffix(path),
    )


@contextlib.contextmanager
def _bind_snapshot(snapshot: ArtifactSnapshot) -> Iterator[ArtifactSnapshot]:
    _ACTIVE_SNAPSHOTS.append({(snapshot.identity[0], snapshot.identity[1]): snapshot})
    try:
        yield snapshot
    finally:
        _ACTIVE_SNAPSHOTS.pop()


def _canonical_filename_error(target_id: str) -> str:
    if target_id in EXTENSION_CROSS_STORE_TARGETS:
        return "target identity does not match the exact extension artifact filename"
    return "target identity does not match the exact canonical artifact filename"


def _canonical_filename_owners(name: str) -> tuple[str, ...]:
    folded = name.casefold()
    return tuple(
        target
        for target, names in TARGET_CANONICAL_FILENAMES.items()
        if folded in names
    )


def _path_markers_match(target_id: str, path: pathlib.Path) -> bool:
    parts = frozenset(part.casefold() for part in path.parts)
    required = TARGET_REQUIRED_PATH_MARKERS.get(target_id, frozenset())
    forbidden = TARGET_FORBIDDEN_PATH_MARKERS.get(target_id, frozenset())
    return required <= parts and parts.isdisjoint(forbidden)


def _assert_canonical_filename_tables() -> None:
    if set(TARGET_CANONICAL_FILENAMES) != set(KNOWN_PRIVACY_TARGET_IDS):
        raise PrivacyError(
            "canonical privacy filenames are not exact for all release targets"
        )
    owned: dict[str, set[str]] = {}
    for target_id, names in TARGET_CANONICAL_FILENAMES.items():
        for name in names:
            owned.setdefault(name, set()).add(target_id)
    shared = frozenset(
        name for name, owners in owned.items() if len(owners) > 1
    )
    if shared != TARGET_CANONICAL_SHARED_FILENAMES:
        raise PrivacyError(
            "canonical privacy filenames have unexpected cross-target overlap"
        )


def _assert_canonical_artifact_filename(
    target_id: str,
    path: pathlib.Path,
    *,
    exact_target: bool,
) -> None:
    _assert_canonical_filename_tables()
    allowed = TARGET_CANONICAL_FILENAMES[target_id]
    folded = path.name.casefold()
    owners = _canonical_filename_owners(path.name)
    bound = folded in allowed and _path_markers_match(target_id, path)
    if exact_target:
        if not bound:
            raise PrivacyError(_canonical_filename_error(target_id))
        return
    if not owners:
        return
    if target_id not in owners or not bound:
        raise PrivacyError(_canonical_filename_error(target_id))


def _assert_target_artifact_type(
    target_id: str,
    path: pathlib.Path,
    snapshot: ArtifactSnapshot | None = None,
    *,
    exact_target: bool = False,
) -> None:
    if not target_id:
        return
    if TARGET_ID_RE.fullmatch(target_id) is None:
        raise PrivacyError("target identity is not a validated ASCII label")
    suffixes = TARGET_ARTIFACT_SUFFIXES.get(target_id)
    if suffixes is None or target_id not in KNOWN_PRIVACY_TARGET_IDS:
        raise PrivacyError("target identity is not a known release target")
    actual = _artifact_suffix(path)
    if actual not in suffixes:
        raise PrivacyError("target identity does not match the artifact type")
    _assert_canonical_artifact_filename(
        target_id, path, exact_target=exact_target
    )
    if snapshot is None:
        return
    data = snapshot.data
    if actual in ZIP_MAGIC_SUFFIXES and not data.startswith(b"PK"):
        raise PrivacyError("target identity does not match the artifact type")
    if actual in GZIP_TAR_SUFFIXES and not data.startswith(b"\x1f\x8b"):
        raise PrivacyError("target identity does not match the artifact type")
    if actual == ".exe" and not data.startswith(b"MZ"):
        raise PrivacyError("target identity does not match the artifact type")


def _canonical_extension_artifact(target_id: str, raw_path: str) -> pathlib.Path:
    target = EXTENSION_CROSS_STORE_TARGETS.get(target_id)
    if target is None:
        raise PrivacyError(f"unsupported exact extension privacy target: {target_id}")
    browser, suffixes = target
    relative = pathlib.Path(raw_path)
    raw_parts = raw_path.split("/")
    if (
        not raw_path
        or "\\" in raw_path
        or re.match(r"^[A-Za-z]:[\\/]", raw_path)
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        raise PrivacyError("extension artifact path must be repository-relative and contained")
    candidate = ROOT / relative
    current = ROOT
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise PrivacyError("extension artifact path must not contain a symbolic link")
    try:
        artifact = candidate.resolve(strict=True)
        artifact.relative_to(ROOT.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise PrivacyError("extension artifact is missing or escapes the repository") from exc
    info = artifact.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or artifact.suffix.lower() not in suffixes:
        raise PrivacyError("extension artifact has the wrong suffix, type, or size")
    stem = artifact.stem.casefold()
    tokens = {"chrome", "edge", "firefox"}
    has_browser_token = re.search(rf"(?:^|[-_.]){re.escape(browser)}(?:[-_.]|$)", stem)
    has_other_token = any(
        re.search(rf"(?:^|[-_.]){re.escape(token)}(?:[-_.]|$)", stem)
        for token in tokens - {browser}
    )
    if not has_browser_token or has_other_token:
        raise PrivacyError("extension artifact filename belongs to another exact target")
    return artifact


def _validate_extension_members(data: bytes) -> None:
    try:
        if not zipfile.is_zipfile(io.BytesIO(data)):
            raise PrivacyError("extension artifact is not an inspectable ZIP/XPI")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBER_COUNT:
                raise PrivacyError("release archive exceeds the member-count limit")
            for info in members:
                if info.is_dir():
                    continue
                _bound_member_path(info.filename)
                member = pathlib.PurePosixPath(info.filename)
                folded_parts = {part.casefold() for part in member.parts}
                folded_name = member.name.casefold()
                if (
                    member.suffix.casefold() in EXTENSION_PRIVATE_MEMBER_SUFFIXES
                    or "native_messaging" in folded_parts
                    or "native-host" in folded_name
                    or "native_host" in folded_name
                    or folded_name.startswith("wins_bridge_host")
                ):
                    raise PrivacyError(
                        "archive-member contains forbidden native-host or private material"
                    )
    except PrivacyError:
        raise
    except Exception as exc:
        raise _fail_closed_parser(exc) from None


def _validate_extension_member_policy(path: pathlib.Path) -> None:
    snapshot = _snapshot_regular_file(path)
    _validate_extension_members(snapshot.data)


def canonical_extension_gate_verify(target_id: str, raw_path: str) -> None:
    artifact = _canonical_extension_artifact(target_id, raw_path)
    snapshot = _snapshot_regular_file(artifact)
    _validate_extension_members(snapshot.data)
    with _bind_snapshot(snapshot):
        try:
            secret_inventory = load_authenticated_secret_inventory(
                repository_root=ROOT
            )
        except InventoryError as exc:
            raise PrivacyError(str(exc)) from None
        result = scan_release_artifacts(
            (artifact,), secret_inventory, target_id=target_id
        )
        if not result.passed:
            raise PrivacyError(
                "extension artifact contains a root-authorized server secret"
            )
    try:
        after = os.lstat(artifact)
    except OSError:
        raise PrivacyError("extension artifact mutated during privacy verification") from None
    if _stat_identity(after) != snapshot.identity:
        raise PrivacyError("extension artifact mutated during privacy verification")
    print(
        f"EXTENSION CROSS-STORE PRIVACY GATE: PASS target={target_id} "
        f"artifact={artifact.relative_to(ROOT)} sha256={snapshot.digest}"
    )


def _json_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise PrivacyError(f"{label} must be an integer, not bool-as-int")
    return value


def _json_str(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise PrivacyError(f"{label} must be a nonempty string")
    return value


def _validate_apple_manifest_value(value: object, *, allow_nested: bool) -> None:
    kind = type(value)
    if kind is str or kind is bool or value is None:
        return
    if kind is int:
        return
    if kind is list:
        for item in value:
            _validate_apple_manifest_value(item, allow_nested=allow_nested)
        return
    if kind is dict:
        if not allow_nested:
            raise PrivacyError("Final Apple release candidate manifest is not recursively exact.")
        for nested in value.values():
            _validate_apple_manifest_value(nested, allow_nested=False)
        return
    raise PrivacyError("Final Apple release candidate manifest is not recursively exact.")


def _parse_apple_manifest(payload: dict[str, object]) -> list[dict[str, object]]:
    if type(payload) is not dict:
        raise PrivacyError("Final Apple release candidate manifest is missing or malformed.")
    extra = set(payload) - APPLE_MANIFEST_TOP_ALLOWED
    if extra:
        raise PrivacyError("Final Apple release candidate manifest is not recursively exact.")
    if "artifacts" not in payload:
        raise PrivacyError("Final Apple release candidate manifest has no artifact list.")
    schema_version = payload.get("schema_version")
    if schema_version is not None:
        _json_int(schema_version, "schema_version")
    artifacts = payload.get("artifacts")
    if type(artifacts) is not list:
        raise PrivacyError("Final Apple release candidate manifest has no artifact list.")
    for key, value in payload.items():
        if key in {"artifacts", "schema_version"}:
            continue
        _validate_apple_manifest_value(value, allow_nested=False)
    parsed: list[dict[str, object]] = []
    for entry in artifacts:
        if type(entry) is not dict:
            raise PrivacyError("Final Apple release candidate entry is malformed.")
        keys = set(entry)
        if not APPLE_ARTIFACT_REQUIRED <= keys or keys - APPLE_ARTIFACT_ALLOWED:
            raise PrivacyError("Final Apple release candidate entry is not recursively exact.")
        for key, value in entry.items():
            if key in APPLE_ARTIFACT_INT_KEYS:
                _json_int(value, key)
            else:
                _validate_apple_manifest_value(value, allow_nested=False)
                if key in {"platform", "path", "sha256"} and type(value) is not str:
                    raise PrivacyError("Final Apple release candidate hash metadata is invalid.")
        parsed.append(entry)
    return parsed


def apple_default_artifacts(
    manifest_path: pathlib.Path = APPLE_RELEASE_CANDIDATE_MANIFEST,
    repository_root: pathlib.Path = ROOT,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Resolve the exact manifest-pinned final IPA and PKG without path escape."""
    try:
        manifest_bytes = _snapshot_regular_file(manifest_path).data
        payload = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except PrivacyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise PrivacyError(
            "Final Apple release candidate manifest is missing or malformed."
        ) from None
    artifacts = _parse_apple_manifest(payload if type(payload) is dict else {})
    selected: dict[str, pathlib.Path] = {}
    for entry in artifacts:
        platform = entry.get("platform")
        if platform not in {"ios", "macos"} or platform in selected:
            raise PrivacyError("Final Apple release candidate platforms are malformed or duplicated.")
        raw_path = entry.get("path")
        if not isinstance(raw_path, str) or not raw_path or pathlib.PurePath(raw_path).is_absolute():
            raise PrivacyError("Final Apple release candidate path must be repository-relative.")
        resolved = (repository_root / raw_path).resolve()
        try:
            resolved.relative_to(repository_root.resolve())
        except ValueError as exc:
            raise PrivacyError("Final Apple release candidate path escapes the repository.") from exc
        expected_suffix = ".ipa" if platform == "ios" else ".pkg"
        if resolved.suffix.lower() != expected_suffix:
            raise PrivacyError(
                f"Final {platform} release candidate must use {expected_suffix}."
            )
        recorded_size = _json_int(entry.get("size_bytes"), "size_bytes")
        recorded_sha256 = entry.get("sha256")
        if (
            recorded_size <= 0
            or not isinstance(recorded_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", recorded_sha256)
        ):
            raise PrivacyError(f"Final {platform} release candidate hash metadata is invalid.")
        try:
            candidate = _snapshot_regular_file(resolved)
        except PrivacyError:
            raise PrivacyError(f"Final {platform} release candidate cannot be read.") from None
        if candidate.size != recorded_size:
            raise PrivacyError(f"Final {platform} release candidate size does not match its manifest.")
        if candidate.digest != recorded_sha256:
            raise PrivacyError(f"Final {platform} release candidate hash does not match its manifest.")
        selected[platform] = resolved
    if set(selected) != {"ios", "macos"}:
        raise PrivacyError("Final Apple release candidates must include one IPA and one PKG.")
    return selected["ios"], selected["macos"]


def default_artifacts_by_target() -> dict[str, pathlib.Path]:
    ios, macos = apple_default_artifacts()
    mapping: dict[str, pathlib.Path] = {
        target: ROOT / relative for target, relative in DEFAULT_TARGET_RELATIVE_PATHS.items()
    }
    mapping["ios-app-store-ipa"] = ios
    mapping["macos-app-store-pkg"] = macos
    if set(mapping) != set(REQUIRED_PRIVACY_TARGET_IDS):
        raise PrivacyError("default privacy coverage is not exact for all release targets")
    return mapping


def default_artifacts() -> tuple[pathlib.Path, ...]:
    by_target = default_artifacts_by_target()
    ordered: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for path in BASE_DEFAULT_ARTIFACTS + tuple(
        by_target[target] for target in REQUIRED_PRIVACY_TARGET_IDS
    ):
        if path in seen:
            continue
        seen.add(path)
        ordered.append(path)
    if set(by_target) != set(REQUIRED_PRIVACY_TARGET_IDS):
        raise PrivacyError("default privacy coverage is not exact for all release targets")
    return tuple(ordered)


def decoded_path_views(data: bytes) -> Iterator[str]:
    yield data.decode("latin-1", errors="ignore")
    if b"\x00" in data:
        yield data.decode("utf-16-le", errors="ignore")
        yield data.decode("utf-16-be", errors="ignore")


def reject_local_build_paths(label: str, data: bytes) -> None:
    for view in decoded_path_views(data):
        if LOCAL_USER_HOME_PATH_RE.search(view):
            raise PrivacyError(f"{label} contains a local user-home path.")
        if SOURCE_TREE_PATH_RE.search(view):
            raise PrivacyError(f"{label} contains a local source-tree path.")


def is_approved_vendor_debug_metadata(label: str, data: bytes) -> bool:
    normalized = label.replace("\\", "/")
    basename = pathlib.PurePosixPath(normalized).name.lower()
    approved = APPROVED_VENDOR_DEBUG_METADATA_SHA256.get(basename)
    return approved is not None and hashlib.sha256(data).hexdigest() in approved


def _is_hex_ascii(value: int) -> bool:
    return (
        48 <= value <= 57
        or 65 <= value <= 70
        or 97 <= value <= 102
    )


def _lower_hex_ascii(value: int) -> int:
    if 65 <= value <= 70:
        return value + 32
    return value


def _lower_percent_hex(encoded: str) -> str:
    chars: list[str] = []
    index = 0
    length = len(encoded)
    while index < length:
        if encoded[index] == "%" and index + 2 < length:
            first = encoded[index + 1]
            second = encoded[index + 2]
            if first in "0123456789abcdefABCDEF" and second in "0123456789abcdefABCDEF":
                chars.append("%")
                chars.append(first.lower())
                chars.append(second.lower())
                index += 3
                continue
        chars.append(encoded[index])
        index += 1
    return "".join(chars)


def _fold_percent_hex_bytes(data: bytes) -> bytes:
    out = bytearray()
    index = 0
    length = len(data)
    while index < length:
        if data[index] == 0x25 and index + 2 < length:
            first = data[index + 1]
            second = data[index + 2]
            if _is_hex_ascii(first) and _is_hex_ascii(second):
                out.append(0x25)
                out.append(_lower_hex_ascii(first))
                out.append(_lower_hex_ascii(second))
                index += 3
                continue
        out.append(data[index])
        index += 1
    return bytes(out)


def _wrap_base64(encoded: bytes, width: int, newline: bytes) -> bytes:
    parts = [encoded[index : index + width] for index in range(0, len(encoded), width)]
    return newline.join(parts)


def _bounded_wrapped_base64(encoded: bytes) -> set[bytes]:
    wrapped: set[bytes] = set()
    for width in (64, 76):
        if len(encoded) <= width:
            continue
        for newline in (b"\n", b"\r\n"):
            body = _wrap_base64(encoded, width, newline)
            wrapped.add(body)
            wrapped.add(body + newline)
    return wrapped


def _unicode_escape(text: str, *, uppercase: bool) -> bytes:
    spec = "04X" if uppercase else "04x"
    parts: list[str] = []
    for character in text:
        code = ord(character)
        if code <= 0xFFFF:
            parts.append("\\u" + format(code, spec))
            continue
        code -= 0x10000
        high = 0xD800 + (code >> 10)
        low = 0xDC00 + (code & 0x3FF)
        parts.append("\\u" + format(high, spec) + "\\u" + format(low, spec))
    return "".join(parts).encode("ascii")


def encoded_forms(value: bytes) -> tuple[bytes, ...]:
    """Bounded exact-match encodings. Never hash or log the source value."""
    text = value.decode("utf-8")
    digest = hashlib.sha256(value).hexdigest()
    forms: set[bytes] = {
        value,
        text.encode("utf-16-le"),
        text.encode("utf-16-be"),
        b"\xff\xfe" + text.encode("utf-16-le"),
        b"\xfe\xff" + text.encode("utf-16-be"),
        text.encode("utf-32-le"),
        text.encode("utf-32-be"),
        b"\xff\xfe\x00\x00" + text.encode("utf-32-le"),
        b"\x00\x00\xfe\xff" + text.encode("utf-32-be"),
        binascii.hexlify(value),
        binascii.hexlify(value).upper(),
        digest.encode("ascii"),
        digest.upper().encode("ascii"),
    }
    colon_hex = binascii.hexlify(value, b":")
    space_hex = binascii.hexlify(value, b" ")
    forms.add(colon_hex)
    forms.add(colon_hex.upper())
    forms.add(space_hex)
    forms.add(space_hex.upper())
    forms.add("".join(f"\\x{byte:02x}" for byte in value).encode("ascii"))
    forms.add("".join(f"\\x{byte:02X}" for byte in value).encode("ascii"))
    quoted = binascii.b2a_qp(value, quotetabs=True, header=False)
    if quoted:
        forms.add(quoted)
    standard32 = base64.b32encode(value)
    forms.add(standard32)
    stripped32 = standard32.rstrip(b"=")
    if stripped32 != standard32:
        forms.add(stripped32)
    standard = base64.b64encode(value)
    urlsafe = base64.urlsafe_b64encode(value)
    for encoded in (standard, urlsafe):
        forms.add(encoded)
        stripped = encoded.rstrip(b"=")
        if stripped != encoded:
            forms.add(stripped)
        forms.update(_bounded_wrapped_base64(encoded))
    mime = base64.encodebytes(value)
    if mime:
        forms.add(mime)
        forms.add(mime.replace(b"\n", b"\r\n"))
    for quoted_text in (
        urllib.parse.quote(text, safe=""),
        urllib.parse.quote(text, safe="/"),
        urllib.parse.quote_plus(text),
    ):
        forms.add(quoted_text.encode("ascii"))
        lowered = _lower_percent_hex(quoted_text)
        forms.add(lowered.encode("ascii"))
    json_dumped = json.dumps(text, ensure_ascii=True)
    forms.add(json_dumped.encode("utf-8"))
    if len(json_dumped) >= 2 and json_dumped[0] == '"' and json_dumped[-1] == '"':
        forms.add(json_dumped[1:-1].encode("utf-8"))
    forms.add(_unicode_escape(text, uppercase=False))
    forms.add(_unicode_escape(text, uppercase=True))
    if "\n" in text or "\r" in text:
        lf = text.replace("\r\n", "\n").replace("\r", "\n")
        forms.add(lf.replace("\n", "\\n").encode("utf-8"))
        forms.add(lf.replace("\n", "\\r\\n").encode("utf-8"))
        forms.add(lf.replace("\n", "\r\n").encode("utf-8"))
    bounded = [form for form in forms if form]
    if len(bounded) > MAX_ENCODED_SECRET_FORMS:
        raise PrivacyError("exact-secret encoding expansion exceeded the accepted bound")
    bounded.sort(key=lambda item: (-len(item), item))
    return tuple(bounded)


def compile_exact_secret_forms(secrets: Mapping[str, str]) -> dict[str, tuple[bytes, ...]]:
    compiled: dict[str, tuple[bytes, ...]] = {}
    for name, value in secrets.items():
        if len(value) < 12:
            raise PrivacyError(
                f"Secret scan input {name} is too short for safe exact matching."
            )
        compiled[name] = encoded_forms(value.encode("utf-8"))
    return compiled


def exact_secret_labels(
    data: bytes, compiled: Mapping[str, tuple[bytes, ...]]
) -> list[str]:
    matched: list[str] = []
    folded = _fold_percent_hex_bytes(data)
    views = (data,) if folded == data else (data, folded)
    for name, forms in compiled.items():
        if any(form and any(form in view for view in views) for form in forms):
            matched.append(name)
    return matched


def exact_secret_labels_in_text(
    text: str, compiled: Mapping[str, tuple[bytes, ...]]
) -> list[str]:
    matched = set(
        exact_secret_labels(text.encode("utf-8", errors="surrogateescape"), compiled)
    )
    matched.update(exact_secret_labels(text.encode("utf-16-le"), compiled))
    matched.update(exact_secret_labels(text.encode("utf-16-be"), compiled))
    return sorted(matched)


def redact_diagnostic(message: str, compiled: Mapping[str, tuple[bytes, ...]]) -> str:
    if not message:
        return message
    data = message.encode("utf-8", errors="surrogateescape")
    folded = _fold_percent_hex_bytes(data)
    forms = sorted(
        {form for needles in compiled.values() for form in needles if form},
        key=lambda item: (-len(item), item),
    )
    for form in forms:
        if form in data:
            data = data.replace(form, b"(redacted)")
        if folded != data and form in folded:
            folded = folded.replace(form, b"(redacted)")
            data = folded
    try:
        redacted = data.decode("utf-8")
    except UnicodeDecodeError:
        redacted = data.decode("latin-1")
    return _redact_local_paths(redacted)


def _redact_local_paths(message: str) -> str:
    message = LOCAL_USER_HOME_PATH_RE.sub("(redacted)/", message)
    message = SOURCE_TREE_PATH_RE.sub("(redacted)/", message)
    message = re.sub(
        r"(?i)(?:/Users/|/home/|/private/|/Volumes/|/tmp/|/var/|[A-Za-z]:[\\/])[^\s\"']+",
        "(redacted)",
        message,
    )
    return message


def format_inventory_scan_report(result: ArtifactPrivacyScanResult) -> str:
    status = "PASS" if result.passed else "FAIL"
    return "\n".join(
        (
            f"RELEASE ARTIFACT PRIVACY: {status}",
            f"revision={result.revision}",
            f"labels={','.join(result.labels)}",
            f"label_count={result.label_count}",
            f"unique_value_count={result.unique_value_count}",
            f"inventory_sha256={result.inventory_sha256}",
            f"target={result.target_id}",
            f"artifact={result.artifact_identity}",
            f"matched_labels={','.join(result.matched_labels)}",
        )
    )


def ipv4_token_digests(data: bytes) -> set[str]:
    """Return exact IPv4-token digests without retaining their clear text."""
    digests: set[str] = set()
    encoded_patterns = (
        (IPV4_TOKEN_RE, "ascii"),
        (IPV4_TOKEN_UTF16_LE_RE, "utf-16-le"),
        (IPV4_TOKEN_UTF16_BE_RE, "utf-16-be"),
    )
    for pattern, encoding in encoded_patterns:
        for match in pattern.finditer(data):
            try:
                token = match.group(0).decode(encoding).encode("ascii")
            except (UnicodeDecodeError, UnicodeEncodeError):
                continue
            octets = token.split(b".")
            if len(octets) != 4 or any(int(octet) > 255 for octet in octets):
                continue
            digests.add(hashlib.sha256(token).hexdigest())
    return digests


def blob_contains_pattern(data: bytes, pattern: re.Pattern[bytes]) -> bool:
    if pattern.search(data):
        return True
    if b"\x00" not in data:
        return False
    for view in decoded_path_views(data):
        if pattern.search(view.encode("utf-8", errors="ignore")):
            return True
    return False


def blob_contains_credential_assignment(data: bytes) -> bool:
    return packaged_credential_assignment(data)


def _decode_js_string_body(body: bytes) -> bytes:
    out = bytearray()
    index = 0
    length = len(body)
    while index < length:
        if body[index] != 0x5C or index + 1 >= length:
            out.append(body[index])
            index += 1
            continue
        marker = body[index + 1]
        if marker in {0x4E, 0x6E}:  # \n
            out.append(0x0A)
            index += 2
            continue
        if marker in {0x52, 0x72}:
            out.append(0x0D)
            index += 2
            continue
        if marker in {0x54, 0x74}:
            out.append(0x09)
            index += 2
            continue
        if marker in {0x22, 0x27, 0x5C}:
            out.append(marker)
            index += 2
            continue
        if marker in {0x58, 0x78} and index + 3 < length:
            try:
                out.append(int(body[index + 2 : index + 4], 16))
            except ValueError:
                out.extend(body[index : index + 2])
                index += 2
                continue
            index += 4
            continue
        if marker in {0x55, 0x75} and index + 5 < length:
            try:
                code = int(body[index + 2 : index + 6], 16)
                out.extend(chr(code).encode("utf-8"))
            except (ValueError, UnicodeEncodeError):
                out.extend(body[index : index + 2])
                index += 2
                continue
            index += 6
            continue
        out.append(marker)
        index += 2
    return bytes(out)


def _js_concat_value(match: re.Match[bytes]) -> bytes | None:
    pieces = JS_STRING_TOKEN_RE.findall(match.group(0))
    if len(pieces) < 2 or len(pieces) > MAX_JS_JOIN_PIECES:
        return None
    joined = b"".join(_decode_js_string_body(token[1:-1]) for token in pieces)
    return joined if len(joined) <= MAX_JS_JOINED_BYTES else None


def _js_array_join_value(match: re.Match[bytes]) -> bytes | None:
    pieces = JS_STRING_TOKEN_RE.findall(match.group("body"))
    if len(pieces) < 2 or len(pieces) > MAX_JS_JOIN_PIECES:
        return None
    separator = _decode_js_string_body(match.group("separator")[1:-1])
    estimated = sum(len(token) for token in pieces) + len(separator) * (len(pieces) - 1)
    if estimated > MAX_JS_JOINED_BYTES or estimated > 8 * len(match.group(0)) + 4096:
        return None
    return separator.join(_decode_js_string_body(token[1:-1]) for token in pieces)


def _js_quoted(value: bytes) -> bytes:
    out = bytearray(b'"')
    for byte in value:
        if byte in (0x22, 0x5C):
            out.extend((0x5C, byte))
        elif 0x20 <= byte < 0x7F:
            out.append(byte)
        else:
            out.extend(b"\\x%02x" % byte)
    out.append(0x22)
    return bytes(out)


def javascript_join_views(data: bytes) -> tuple[tuple[bytes, ...], bytes | None]:
    """(joined values, merged-code view) for every evaluable string join in `data`.

    The joined values alone drop the surrounding code, so a scan that needs it (a
    credential name beside its value, a JSON member name) cannot fire on them, and
    the raw view still holds the value split. The merged view is `data` with each
    join replaced by its joined literal: it keeps the code and merges only the
    string expressions. It is None when nothing in `data` joins. Array joins merge
    first, then .concat(), then "+", so a mixed chain collapses into one literal.
    """

    values: list[bytes] = []
    merged = data
    changed = False

    def replace(value: bytes | None, match: re.Match[bytes]) -> bytes:
        nonlocal changed
        if value is None:
            return match.group(0)
        changed = True
        if value:
            values.append(value)
        return _js_quoted(value)

    if b"join" in merged:
        merged = JS_ARRAY_JOIN_RE.sub(lambda m: replace(_js_array_join_value(m), m), merged)
    if b"concat" in merged:
        merged = JS_DOT_CONCAT_RE.sub(lambda m: replace(_js_concat_value(m), m), merged)
    merged = JS_CONCAT_STRINGS_RE.sub(lambda m: replace(_js_concat_value(m), m), merged)
    return tuple(values), (merged if changed else None)


def javascript_concatenated_blobs(data: bytes) -> tuple[bytes, ...]:
    reconstructed: list[bytes] = []
    for pattern in (JS_CONCAT_STRINGS_RE, JS_DOT_CONCAT_RE):
        for match in pattern.finditer(data):
            joined = _js_concat_value(match)
            if joined:
                reconstructed.append(joined)
    return tuple(reconstructed)


def javascript_array_join_blobs(data: bytes) -> tuple[bytes, ...]:
    reconstructed: list[bytes] = []
    for match in JS_ARRAY_JOIN_RE.finditer(data):
        joined = _js_array_join_value(match)
        if joined:
            reconstructed.append(joined)
    return tuple(reconstructed)


def _contains_only_public_crypto_material(data: bytes) -> bool:
    return contains_only_public_crypto_material(data)


def _public_ip_uris(data: bytes) -> Iterator[bytes]:
    yield from (match.group(0) for match in PUBLIC_IP_URI_RE.finditer(data))
    if b"\x00" not in data:
        return
    for pattern, encoding in (
        (PUBLIC_IP_URI_UTF16_LE_RE, "utf-16-le"),
        (PUBLIC_IP_URI_UTF16_BE_RE, "utf-16-be"),
    ):
        for match in pattern.finditer(data):
            # Code units are below U+0100 by construction, so latin-1 gives
            # the same bytes the single-byte form of this URI would carry.
            yield match.group(0).decode(encoding).encode("latin-1")


def check_blob(
    label: str,
    data: bytes,
    secrets: dict[str, str],
    *,
    compiled: dict[str, tuple[bytes, ...]] | None = None,
    matches: set[str] | None = None,
) -> None:
    # Every scan below also runs over the strings a JavaScript bundle joins at
    # runtime ("..." + "...", [...].join("...")): splitting a value is not a
    # way past any category (R23 W1-03).
    joined_values, merged = javascript_join_views(data)
    views = [data, *joined_values]
    # The joined values drop the code around them. The scans that read a name
    # beside its value (credential assignment, JSON member names) also read the
    # merged-code view, where `api_key="SYNTH"+"ETIC..."` is `api_key="SYNTHETIC..."`
    # (R24 V2 F-01). The other scans need only the values, so they skip that copy.
    code_views = views if merged is None else [*views, merged]
    for view in views:
        lowered = view.lower()
        for name, literal in FORBIDDEN_CLIENT_LITERALS.items():
            folded = literal.lower()
            if folded in lowered or any(
                form in lowered for form in _utf16_literal_forms(folded)
            ):
                raise PrivacyError(f"{label} contains forbidden client literal category {name}.")
        for name, pattern in FORBIDDEN_CLIENT_LITERAL_PATTERNS.items():
            if blob_contains_pattern(view, pattern):
                raise PrivacyError(f"{label} contains forbidden client literal category {name}.")
    for view in views:
        address_digests = ipv4_token_digests(view)
        for name, digest in FORBIDDEN_CLIENT_ADDRESS_SHA256.items():
            if digest in address_digests:
                raise PrivacyError(f"{label} contains forbidden client address category {name}.")
    blob_digest = hashlib.sha256(data).hexdigest()
    if blob_digest not in APPROVED_VENDOR_BINARY_SHA256:
        for view in views:
            for uri in _public_ip_uris(view):
                digest = hashlib.sha256(uri).hexdigest()
                if digest not in APPROVED_THIRD_PARTY_IP_URI_SHA256:
                    raise PrivacyError(
                        f"{label} contains a non-approved public-IP URI instead of a hostname route."
                    )
    # Vendor approval may allow a reviewed binary to contain a public-IP URI,
    # but it must never exempt that binary from credential scanning.
    if service_account_member_name(label):
        raise PrivacyError(
            f"{label} contains reusable secret category google_service_account_json. "
            "Obfuscation or stripping is not remediation; remove the credential from the distributable before rebuilding."
        )
    for view in code_views:
        secret_category = reusable_secret_category(view)
        if secret_category is not None:
            raise PrivacyError(
                f"{label} contains reusable secret category {secret_category}. "
                "Obfuscation or stripping is not remediation; remove the credential from the distributable before rebuilding."
            )
    assignment = next(
        (view for view in code_views if blob_contains_credential_assignment(view)), None
    )
    if assignment is not None:
        folded = assignment.lower()
        assignment_category = (
            "activation_secret"
            if b"activation" in folded or b"x-wins-activation" in folded
            else "credential_assignment"
        )
        raise PrivacyError(
            f"{label} contains reusable secret category {assignment_category}. "
            "Obfuscation or stripping is not remediation; remove the credential from the distributable before rebuilding."
        )
    needles = compiled
    if needles is None:
        needles = compile_exact_secret_forms(secrets) if secrets else {}
    found: set[str] = set()
    for view in views:
        found.update(exact_secret_labels(view, needles))
    if not found:
        return
    if matches is not None:
        matches.update(found)
        return
    raise PrivacyError(
        f"{PUBLIC_MEMBER_LABEL} contains exact known-server-secret label(s) "
        f"{', '.join(sorted(found))}."
    )


def reject_unstripped_native_library(label: str, data: bytes) -> None:
    if is_store_only_native_debug_metadata(label):
        return
    if is_approved_vendor_debug_metadata(label, data):
        return
    try:
        inspected = inspect_native_debug_sections(data)
    except ObfuscationError as exc:
        # Java class metadata and Mach-O universal binaries share the CAFEBABE
        # prefix. Archive members that are not native-looking may therefore
        # reach the Mach-O parser even though they are ordinary JVM payloads.
        # Native-looking paths remain fail-closed on every parse error.
        if not label_requires_native_parse(label):
            return
        raise PrivacyError(
            f"{PUBLIC_MEMBER_LABEL} native debug inspection failed."
        ) from None
    if inspected is None:
        return
    _kind, sections = inspected
    if sections:
        raise PrivacyError(
            f"{PUBLIC_MEMBER_LABEL} contains unstripped native debug sections."
        )


def file_bytes(path: pathlib.Path) -> bytes:
    return _snapshot_regular_file(path).data


def validate_tar_metadata(path: pathlib.Path, members: list[tarfile.TarInfo]) -> None:
    """Reject archive traversal, special files, ambient host modes, and owners."""
    reviewed_executables = {
        "wins_vpn",
        "winsvpn-bypass-bpf",
        "xray",
        "awg",
        "awg-quick",
        "amneziawg-go",
        "winn-datapath",
        "install.sh",
        "share/wins-vpn/winsvpn-recover",
        "tools/native_messaging/host/wins_bridge_host",
        "tools/native_messaging/install_native_host.sh",
    }
    if not members:
        raise PrivacyError("Release archive is empty")
    for member in members:
        normalized = member.name.removeprefix("./")
        if normalized in {"", "."}:
            if not member.isdir() or member.mode != 0o755 or member.uid != 0 or member.gid != 0:
                raise PrivacyError("archive-member has unsafe archive-root metadata.")
            continue
        member_path = pathlib.PurePosixPath(normalized)
        _bound_member_path(normalized)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise PrivacyError("archive-member has an unsafe archive path.")
        if member.uid != 0 or member.gid != 0:
            raise PrivacyError("archive-member is not numerically root-owned.")
        if member.isdir():
            expected_mode = 0o755
        elif member.isfile():
            expected_mode = 0o755 if normalized in reviewed_executables else 0o644
        else:
            raise PrivacyError("archive-member has an unsupported archive member type.")
        if member.mode != expected_mode:
            raise PrivacyError(
                f"archive-member has unsafe mode {member.mode:#o}; "
                f"expected {expected_mode:#o}."
            )


def validate_zip_metadata(path: pathlib.Path, members: list[zipfile.ZipInfo]) -> None:
    """Reject ambiguous names, traversal, encryption, and link-like ZIP entries."""
    if not members:
        raise PrivacyError("Release archive is empty")
    seen: set[str] = set()
    for member in members:
        name = member.filename
        _bound_member_path(name)
        trimmed = name[:-1] if name.endswith("/") else name
        parts = trimmed.split("/")
        if (
            not trimmed
            or name.startswith("/")
            or "\\" in name
            or re.match(r"^[A-Za-z]:", trimmed)
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise PrivacyError("archive-member has an unsafe archive path.")
        collision_key = trimmed.casefold()
        if collision_key in seen:
            raise PrivacyError("archive-member has a duplicate or case-colliding path.")
        seen.add(collision_key)
        if member.flag_bits & 0x1:
            raise PrivacyError("archive-member is encrypted and cannot be inspected safely.")
        if member.create_system == 3:
            file_type = stat.S_IFMT(member.external_attr >> 16)
            allowed_types = {0, stat.S_IFDIR} if member.is_dir() else {0, stat.S_IFREG}
            if file_type not in allowed_types:
                raise PrivacyError("archive-member has an unsupported archive member type.")


def validate_external_archive_names(path: pathlib.Path, names: list[str]) -> None:
    if not names:
        raise PrivacyError("Release package archive is empty")
    if len(names) > MAX_ARCHIVE_MEMBER_COUNT:
        raise PrivacyError("release archive exceeds the member-count limit")
    seen: set[str] = set()
    for name in names:
        _bound_member_path(name)
        trimmed = name.rstrip("/")
        parts = pathlib.PurePosixPath(trimmed).parts
        if (
            not trimmed
            or trimmed.startswith("/")
            or "\\" in trimmed
            or re.match(r"^[A-Za-z]:", trimmed)
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise PrivacyError("archive-member has an unsafe package archive path.")
        collision_key = trimmed.casefold()
        if collision_key in seen:
            raise PrivacyError("archive-member has a duplicate package archive path.")
        seen.add(collision_key)


def bsdtar_names(tar_bin: str, path: pathlib.Path) -> list[str]:
    try:
        completed = subprocess.run(
            [tar_bin, "-tf", str(path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        raise PrivacyError("Could not inspect Apple package archive.") from None
    return [line for line in completed.stdout.splitlines() if line]


def extract_with_bsdtar(tar_bin: str, source: pathlib.Path, destination: pathlib.Path) -> None:
    names = bsdtar_names(tar_bin, source)
    validate_external_archive_names(source, names)
    destination.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [tar_bin, "-xf", str(source), "-C", str(destination)],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        raise PrivacyError("Could not extract Apple package archive.") from None
    resolved_destination = destination.resolve()
    for child in destination.rglob("*"):
        if child.is_symlink():
            try:
                target = pathlib.Path(os.readlink(child))
                if target.is_absolute():
                    raise ValueError("absolute symlink target")
                (child.parent / target).resolve(strict=False).relative_to(
                    resolved_destination
                )
            except (OSError, ValueError):
                raise PrivacyError(
                    "package archive contains an escaping package symlink."
                ) from None


def _tar_open_mode(data: bytes) -> str:
    if data.startswith(b"\x1f\x8b"):
        return "r:gz"
    if data.startswith(b"BZh"):
        return "r:bz2"
    if data.startswith(b"\xfd7zXZ"):
        return "r:xz"
    if data.startswith(b"(\xb5/\xfd"):
        return "r:zst"
    return "r:"


def _check_member_ratio(*, expanded: int, compressed: int, outer: int) -> None:
    if expanded < 0 or compressed < 0:
        raise PrivacyError("archive member reports a negative size")
    if expanded and compressed <= 0:
        raise PrivacyError("compressed archive member has no compressed data")
    if compressed > 0 and expanded > compressed * MAX_ARCHIVE_COMPRESSION_RATIO:
        raise PrivacyError("archive member exceeds the compression-ratio limit")
    if expanded > outer * MAX_ARCHIVE_COMPRESSION_RATIO:
        raise PrivacyError("release archive exceeds the aggregate compression-ratio limit")


def _write_private_snapshot(directory: pathlib.Path, data: bytes, name: str) -> pathlib.Path:
    destination = directory / name
    fd = os.open(destination, _open_nofollow_flags(write=True), 0o600)
    try:
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return destination


def iter_macos_pkg(path: pathlib.Path) -> Iterator[tuple[str, bytes]]:
    snapshot = _snapshot_regular_file(path)
    yield from _iter_pkg_bytes(snapshot.data)


def _iter_pkg_bytes(data: bytes) -> Iterator[tuple[str, bytes]]:
    tar_bin = shutil.which("bsdtar") or shutil.which("tar")
    if not tar_bin:
        raise PrivacyError(
            "macOS PKG privacy inspection requires bsdtar/tar to expand the signed payload."
        )
    with tempfile.TemporaryDirectory(prefix="wins-macos-pkg-privacy-") as temp_name:
        temp = pathlib.Path(temp_name)
        snapshot_path = _write_private_snapshot(temp, data, "snapshot.pkg")
        outer = temp / "outer"
        extract_with_bsdtar(tar_bin, snapshot_path, outer)
        payloads = sorted(candidate for candidate in outer.rglob("Payload") if candidate.is_file())
        if not payloads:
            raise PrivacyError("package archive contains no inspectable component Payload.")
        budget = _ArchiveBudget()
        for metadata in sorted(candidate for candidate in outer.rglob("*") if candidate.is_file()):
            if metadata.name not in {"Payload", "Bom"}:
                payload = _snapshot_regular_file(metadata).data
                budget.reserve(len(payload))
                relative = metadata.relative_to(outer).as_posix()
                yield relative, payload
                yield from _iter_nested_archive(relative, payload, budget, 0)
        for index, payload in enumerate(payloads):
            component_root = temp / f"payload-{index}"
            extract_with_bsdtar(tar_bin, payload, component_root)
            files: list[pathlib.Path] = []
            for candidate in component_root.rglob("*"):
                try:
                    info = candidate.lstat()
                except OSError:
                    raise PrivacyError(
                        "package archive contains an unreadable package payload entry."
                    ) from None
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    continue
                files.append(candidate)
            files.sort()
            if not files:
                raise PrivacyError("package archive contains an empty component Payload.")
            for child in files:
                body = _snapshot_regular_file(child).data
                budget.reserve(len(body))
                relative = child.relative_to(component_root).as_posix()
                yield relative, body
                # Same recursion as zip, tar and directory members: a gzip
                # NOTICES.Z or a nested archive in the app bundle is expanded.
                yield from _iter_nested_archive(relative, body, budget, 0)


@contextlib.contextmanager
def _tolerate_zip_extra_decode() -> Iterator[None]:
    original = zipfile.ZipInfo._decodeExtra

    def tolerated(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        try:
            return original(self, *args, **kwargs)
        except zipfile.BadZipFile:
            return None

    zipfile.ZipInfo._decodeExtra = tolerated  # type: ignore[method-assign]
    try:
        yield
    finally:
        zipfile.ZipInfo._decodeExtra = original  # type: ignore[method-assign]


def _zip_eocd_index(data: bytes) -> int:
    index = data.rfind(ZIP_EOCD_SIGNATURE)
    if index < 0 or index + 22 > len(data):
        raise PrivacyError("archive is not inspectable")
    return index


def _zip_comment_and_trailer_blobs(data: bytes) -> tuple[bytes, ...]:
    index = _zip_eocd_index(data)
    comment_len = int.from_bytes(data[index + 20 : index + 22], "little")
    comment_start = index + 22
    comment_end = comment_start + comment_len
    if comment_end > len(data):
        raise PrivacyError("archive is not inspectable")
    blobs: list[bytes] = []
    comment = data[comment_start:comment_end]
    if comment:
        blobs.append(comment)
    trailer = data[comment_end:]
    if trailer:
        blobs.append(trailer)
    return tuple(blobs)


def _bounded_zip_slice(data: bytes, start: int, length: int) -> bytes:
    if length < 0 or start < 0 or start + length > len(data):
        raise PrivacyError("archive is not inspectable")
    if length > MAX_METADATA_BYTES:
        raise PrivacyError("archive metadata exceeds the accepted bound")
    return data[start : start + length]


def _iter_raw_zip_metadata(
    data: bytes, budget: _ArchiveBudget
) -> Iterator[tuple[str, bytes]]:
    index = _zip_eocd_index(data)
    comment_len = int.from_bytes(data[index + 20 : index + 22], "little")
    comment_start = index + 22
    comment_end = comment_start + comment_len
    if comment_end > len(data):
        raise PrivacyError("archive is not inspectable")
    comment = data[comment_start:comment_end]
    if comment:
        _reserve_metadata(budget, comment)
        yield "archive-comment", comment
    trailer = data[comment_end:]
    if trailer:
        _reserve_metadata(budget, trailer)
        yield "archive-trailer", trailer
    cd_size = int.from_bytes(data[index + 12 : index + 16], "little")
    cd_offset = int.from_bytes(data[index + 16 : index + 20], "little")
    total_entries = int.from_bytes(data[index + 10 : index + 12], "little")
    if total_entries > MAX_ARCHIVE_MEMBER_COUNT:
        raise PrivacyError("release archive exceeds the member-count limit")
    if cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF or total_entries == 0xFFFF:
        return
    if cd_offset > len(data) or cd_offset + cd_size > len(data):
        raise PrivacyError("archive is not inspectable")
    cursor = cd_offset
    cd_end = cd_offset + cd_size
    for _ in range(total_entries):
        if cursor + 46 > cd_end or data[cursor : cursor + 4] != b"PK\x01\x02":
            raise PrivacyError("archive is not inspectable")
        filename_len = int.from_bytes(data[cursor + 28 : cursor + 30], "little")
        extra_len = int.from_bytes(data[cursor + 30 : cursor + 32], "little")
        member_comment_len = int.from_bytes(data[cursor + 32 : cursor + 34], "little")
        local_offset = int.from_bytes(data[cursor + 42 : cursor + 46], "little")
        header_end = cursor + 46
        extra = _bounded_zip_slice(data, header_end + filename_len, extra_len)
        member_comment = _bounded_zip_slice(
            data, header_end + filename_len + extra_len, member_comment_len
        )
        if extra:
            _reserve_metadata(budget, extra)
            yield "archive-member-extra", extra
        if member_comment:
            _reserve_metadata(budget, member_comment)
            yield "archive-member-comment", member_comment
        if (
            local_offset != 0xFFFFFFFF
            and local_offset + 30 <= len(data)
            and data[local_offset : local_offset + 4] == b"PK\x03\x04"
        ):
            local_name_len = int.from_bytes(
                data[local_offset + 26 : local_offset + 28], "little"
            )
            local_extra_len = int.from_bytes(
                data[local_offset + 28 : local_offset + 30], "little"
            )
            local_extra = _bounded_zip_slice(
                data, local_offset + 30 + local_name_len, local_extra_len
            )
            if local_extra and local_extra != extra:
                _reserve_metadata(budget, local_extra)
                yield "archive-local-extra", local_extra
        cursor = header_end + filename_len + extra_len + member_comment_len
        if cursor > cd_end:
            raise PrivacyError("archive is not inspectable")


def _reserve_metadata(budget: _ArchiveBudget, payload: bytes) -> None:
    if len(payload) > MAX_METADATA_BYTES:
        raise PrivacyError("archive metadata exceeds the accepted bound")
    budget.reserve(len(payload))


def _nested_kind(data: bytes) -> str | None:
    if len(data) < 4:
        return None
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if data.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"(\xb5/\xfd")):
        return "tar"
    try:
        if tarfile.is_tarfile(io.BytesIO(data)):
            return "tar"
    except Exception:
        return None
    return None


def _iter_nested_archive(
    name: str,
    data: bytes,
    budget: _ArchiveBudget,
    depth: int,
) -> Iterator[tuple[str, bytes]]:
    kind = _nested_kind(data)
    if kind is None:
        return
    if depth >= MAX_ARCHIVE_NEST_DEPTH:
        raise PrivacyError("release archive exceeds the nested-archive limit")
    budget.reserve_nested()
    if kind == "zip":
        yield from _iter_zip_bytes(data, budget=budget, depth=depth + 1)
        return
    if data.startswith(b"\x1f\x8b"):
        expanded = _gunzip_bounded(data)
        if not _is_plain_tar(expanded):
            if name.lower().endswith(tuple(GZIP_TAR_SUFFIXES)):
                raise PrivacyError("archive is not inspectable")
            # A gzip stream that is not a tarball (every Flutter release ships
            # assets/flutter_assets/NOTICES.Z): scan the expanded bytes under the
            # inner file name, so suffix-based member checks still apply.
            budget.reserve(len(expanded))
            member = _gunzip_member_name(name)
            yield member, expanded
            yield from _iter_nested_archive(member, expanded, budget, depth + 1)
            return
    yield from _iter_tar_bytes(data, budget=budget, depth=depth + 1)
    del name


def _gunzip_bounded(data: bytes) -> bytes:
    # Bound the output before allocating it: never more than the per-member
    # limit or the compression-ratio limit allows for this input.
    limit = min(MAX_ARCHIVE_MEMBER_EXPANDED_BYTES, len(data) * MAX_ARCHIVE_COMPRESSION_RATIO)
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        expanded = decompressor.decompress(data, limit + 1)
    except zlib.error as exc:
        raise _fail_closed_parser(exc) from None
    if len(expanded) > limit or decompressor.unconsumed_tail:
        raise PrivacyError("archive member exceeds the compression-ratio limit")
    if not decompressor.eof or decompressor.unused_data:
        raise PrivacyError("archive is not inspectable")
    return expanded


def _is_plain_tar(data: bytes) -> bool:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:"):
            return True
    except Exception:
        return False


def _gunzip_member_name(name: str) -> str:
    lowered = name.lower()
    if lowered.endswith(".tgz"):
        return f"{name[:-4]}.tar"
    if lowered.endswith(".gz"):
        return name[:-3]
    if lowered.endswith(".z"):
        return name[:-2]
    return f"{name}!gunzip"


def _iter_zip_bytes(
    data: bytes,
    *,
    budget: _ArchiveBudget | None = None,
    depth: int = 0,
) -> Iterator[tuple[str, bytes]]:
    if len(data) > MAX_ARCHIVE_INPUT_BYTES:
        raise PrivacyError("release archive exceeds the outer-size limit")
    if depth > MAX_ARCHIVE_NEST_DEPTH:
        raise PrivacyError("release archive exceeds the nested-archive limit")
    try:
        if budget is None:
            budget = _ArchiveBudget()
        yield from _iter_raw_zip_metadata(data, budget)
        with _tolerate_zip_extra_decode():
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                validate_zip_metadata(pathlib.Path("archive"), members)
                for info in members:
                    if info.is_dir():
                        continue
                    _check_member_ratio(
                        expanded=info.file_size,
                        compressed=info.compress_size,
                        outer=len(data),
                    )
                    budget.reserve(info.file_size)
                    with archive.open(info, "r") as handle:
                        payload = _read_stream_exact(handle, info.file_size)
                    yield info.filename, payload
                    yield from _iter_nested_archive(info.filename, payload, budget, depth)
                residual = _zip_residual_bytes(data, members)
                budget.reserve(len(residual))
                yield "archive-zip-residual", residual
    except PrivacyError:
        raise
    except Exception as exc:
        raise _fail_closed_parser(exc) from None


def _zip_residual_bytes(data: bytes, members: list[zipfile.ZipInfo]) -> bytes:
    """Every zip byte outside the compressed member payloads.

    Local headers, data descriptors, bytes between entries (where an APK
    Signing Block legitimately sits), the central directory and the end record
    are readable by anyone holding the archive but are not member payloads, so
    they are scanned as one blob.
    """
    payloads: list[tuple[int, int]] = []
    for info in members:
        offset = info.header_offset
        if offset < 0 or offset + 30 > len(data) or data[offset : offset + 4] != b"PK\x03\x04":
            raise PrivacyError("archive is not inspectable")
        name_len = int.from_bytes(data[offset + 26 : offset + 28], "little")
        extra_len = int.from_bytes(data[offset + 28 : offset + 30], "little")
        start = offset + 30 + name_len + extra_len
        end = start + info.compress_size
        if info.compress_size < 0 or end > len(data):
            raise PrivacyError("archive is not inspectable")
        if info.compress_size:
            payloads.append((start, end))
    residual = bytearray()
    position = 0
    for start, end in sorted(payloads):
        if start < position:
            raise PrivacyError("archive is not inspectable")
        residual += data[position:start]
        position = end
    residual += data[position:]
    return bytes(residual)


def _iter_tar_metadata(
    member: tarfile.TarInfo, budget: _ArchiveBudget
) -> Iterator[tuple[str, bytes]]:
    fields = (
        ("archive-uname", member.uname),
        ("archive-gname", member.gname),
        ("archive-linkname", member.linkname),
    )
    for label, text in fields:
        if not text:
            continue
        payload = text.encode("utf-8", errors="surrogateescape")
        _reserve_metadata(budget, payload)
        yield f"{label}:{member.name}", payload
    for key, value in member.pax_headers.items():
        payload = f"{key}={value}".encode("utf-8", errors="surrogateescape")
        _reserve_metadata(budget, payload)
        yield f"archive-pax:{member.name}", payload


def _gzip_header_fields(data: bytes) -> tuple[bytes, ...]:
    """Return the optional FEXTRA, FNAME and FCOMMENT bytes of a gzip header.

    Decompression skips these fields, so they are scanned as metadata.
    """
    if len(data) < 10 or not data.startswith(b"\x1f\x8b"):
        raise PrivacyError("archive is not inspectable")
    flags = data[3]
    position = 10
    fields: list[bytes] = []
    if flags & 0x04:
        if position + 2 > len(data):
            raise PrivacyError("archive is not inspectable")
        length = int.from_bytes(data[position : position + 2], "little")
        position += 2
        if position + length > len(data):
            raise PrivacyError("archive is not inspectable")
        fields.append(data[position : position + length])
        position += length
    for flag in (0x08, 0x10):
        if flags & flag:
            end = data.find(b"\0", position)
            if end < 0:
                raise PrivacyError("archive is not inspectable")
            fields.append(data[position:end])
            position = end + 1
    return tuple(field for field in fields if field)


def _tar_residual_bytes(
    archive: tarfile.TarFile, members: list[tarfile.TarInfo]
) -> bytes:
    """Every plain tar stream byte that is not a regular-file payload.

    Headers, payload padding, blocks between members, the end blocks and any
    bytes after them are invisible to member extraction but readable by anyone
    holding the stream, so they are scanned as one blob. Payloads are excluded
    so a reviewed vendor member keeps its own per-member exemption.
    """
    stream = archive.fileobj
    if stream is None:
        raise PrivacyError("archive is not inspectable")
    payloads = sorted(
        (member.offset_data, member.offset_data + member.size)
        for member in members
        if member.isfile() and member.size
    )
    residual = bytearray()

    def keep(length: int | None) -> None:
        while length is None or length > 0:
            want = MEMBER_READ_CHUNK if length is None else min(MEMBER_READ_CHUNK, length)
            block = stream.read(want)
            if not block:
                if length is None:
                    return
                raise PrivacyError("archive is not inspectable")
            residual.extend(block)
            if len(residual) > MAX_ARCHIVE_MEMBER_EXPANDED_BYTES:
                raise PrivacyError("archive member exceeds the expanded-size limit")
            if length is not None:
                length -= len(block)

    stream.seek(0)
    position = 0
    for start, end in payloads:
        if start < position:
            raise PrivacyError("archive is not inspectable")
        keep(start - position)
        stream.seek(end)
        position = end
    keep(None)
    return bytes(residual)


def _iter_tar_bytes(
    data: bytes,
    *,
    budget: _ArchiveBudget | None = None,
    depth: int = 0,
) -> Iterator[tuple[str, bytes]]:
    if len(data) > MAX_ARCHIVE_INPUT_BYTES:
        raise PrivacyError("release archive exceeds the outer-size limit")
    if depth > MAX_ARCHIVE_NEST_DEPTH:
        raise PrivacyError("release archive exceeds the nested-archive limit")
    try:
        if budget is None:
            budget = _ArchiveBudget()
        mode = _tar_open_mode(data)
        stream = data
        if mode == "r:gz":
            # One bounded gzip member, as for nested gzip members: no second
            # member and no bytes after the gzip trailer. The header's optional
            # text fields are skipped by decompression, so scan them here.
            for field in _gzip_header_fields(data):
                _reserve_metadata(budget, field)
                yield "archive-gzip-header", field
            stream = _gunzip_bounded(data)
            mode = "r:"
        with tarfile.open(fileobj=io.BytesIO(stream), mode=mode) as archive:
            members = archive.getmembers()
            validate_tar_metadata(pathlib.Path("archive"), members)
            for member in members:
                yield from _iter_tar_metadata(member, budget)
                if not member.isfile():
                    continue
                _bound_member_path(member.name)
                _check_member_ratio(
                    expanded=member.size,
                    compressed=len(data),
                    outer=len(data),
                )
                budget.reserve(member.size)
                handle = archive.extractfile(member)
                if handle is None:
                    raise PrivacyError("Could not inspect archive-member")
                payload = _read_stream_exact(handle, member.size)
                yield member.name, payload
                yield from _iter_nested_archive(member.name, payload, budget, depth)
            residual = _tar_residual_bytes(archive, members)
            budget.reserve(len(residual))
            yield "archive-tar-residual", residual
    except PrivacyError:
        raise
    except Exception as exc:
        raise _fail_closed_parser(exc) from None


def _iter_directory(path: pathlib.Path) -> Iterator[tuple[str, bytes]]:
    budget = _ArchiveBudget()
    try:
        root_info = os.lstat(path)
    except OSError:
        raise PrivacyError("Required release artifact does not exist") from None
    _reject_artifact_stat(root_info, directory_ok=True)
    for root, dirnames, filenames in os.walk(path, followlinks=False):
        for name in list(dirnames):
            child = pathlib.Path(root) / name
            try:
                info = child.lstat()
            except OSError:
                raise PrivacyError("release artifact has an unreadable directory entry") from None
            _reject_artifact_stat(info, directory_ok=True)
        dirnames[:] = sorted(dirnames)
        for name in sorted(filenames):
            child = pathlib.Path(root) / name
            try:
                info = child.lstat()
            except OSError:
                raise PrivacyError("release artifact has an unreadable directory entry") from None
            _reject_artifact_stat(info)
            relative = child.relative_to(path).as_posix()
            _bound_member_path(relative)
            payload = _snapshot_regular_file(child).data
            budget.reserve(len(payload))
            yield relative, payload
            yield from _iter_nested_archive(relative, payload, budget, 0)


def iter_container(path: pathlib.Path) -> Iterator[tuple[str, bytes]]:
    try:
        info = os.lstat(path)
    except OSError:
        raise PrivacyError("Required release artifact does not exist") from None
    if stat.S_ISDIR(info.st_mode):
        _reject_artifact_stat(info, directory_ok=True)
        yield from _iter_directory(path)
        return
    _reject_artifact_stat(info)
    snapshot = _snapshot_regular_file(path)
    yield from _iter_snapshot(snapshot)


def _iter_snapshot(snapshot: ArtifactSnapshot) -> Iterator[tuple[str, bytes]]:
    data = snapshot.data
    suffix = snapshot.suffix
    try:
        if suffix == ".pkg":
            yield from _iter_pkg_bytes(data)
            return
        if suffix in GZIP_TAR_SUFFIXES or suffix in TAR_SUFFIXES:
            yield from _iter_tar_bytes(data)
            return
        zip_like = suffix in ZIP_MAGIC_SUFFIXES or data.startswith(
            (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
        )
        if zip_like or zipfile.is_zipfile(io.BytesIO(data)):
            yield from _iter_zip_bytes(data)
            return
        if tarfile.is_tarfile(io.BytesIO(data)):
            yield from _iter_tar_bytes(data)
            return
    except PrivacyError:
        raise
    except Exception as exc:
        raise _fail_closed_parser(exc) from None
    yield "artifact", data


def iter_static_files() -> Iterator[pathlib.Path]:
    seen: set[pathlib.Path] = set()
    for entry in STATIC_PATHS:
        candidates: Iterable[pathlib.Path]
        if entry.is_dir():
            candidates = entry.rglob("*")
        else:
            candidates = (entry,)
        for path in candidates:
            if path.is_symlink() or not path.is_file() or path in seen:
                continue
            relative = path.relative_to(ROOT)
            if any(part.lower() in IGNORED_STATIC_PARTS for part in relative.parts):
                continue
            if path.name in IGNORED_STATIC_NAMES:
                continue
            if any(part.lower() == "test" or part.lower().endswith("tests") for part in relative.parts):
                continue
            if path.suffix.lower() in {
                ".a",
                ".aar",
                ".apk",
                ".dll",
                ".dylib",
                ".exe",
                ".ipa",
                ".jpg",
                ".jpeg",
                ".mp4",
                ".png",
                ".so",
                ".webp",
                ".zip",
            }:
                continue
            seen.add(path)
            yield path


def validate_static() -> int:
    count = 0
    for path in iter_static_files():
        check_blob(path.relative_to(ROOT).as_posix(), file_bytes(path), {})
        count += 1
    if count == 0:
        raise PrivacyError("Static client/release-tooling scan selected no files.")
    return count


def _inspect_member(
    member_name: str,
    data: bytes,
    secrets: Mapping[str, str],
    compiled: Mapping[str, tuple[bytes, ...]],
    matches: set[str],
) -> None:
    if not is_approved_vendor_debug_metadata(member_name, data):
        reject_local_build_paths(PUBLIC_MEMBER_LABEL, data)
    if service_account_member_name(member_name):
        raise PrivacyError(
            f"{PUBLIC_MEMBER_LABEL} contains reusable secret category "
            "google_service_account_json. Obfuscation or stripping is not "
            "remediation; remove the credential from the distributable before "
            "rebuilding."
        )
    check_blob(
        PUBLIC_MEMBER_LABEL,
        data,
        dict(secrets),
        compiled=dict(compiled),
        matches=matches,
    )
    name_hits = set(
        exact_secret_labels(member_name.encode("utf-8", errors="surrogateescape"), compiled)
    )
    name_hits.update(exact_secret_labels_in_text(member_name, compiled))
    matches.update(name_hits)
    reject_unstripped_native_library(member_name, data)


def _scan_artifacts(
    paths: Iterable[pathlib.Path],
    secrets: Mapping[str, str],
    *,
    target_id: str = "",
    exact_target: bool = False,
) -> tuple[int, tuple[str, ...], tuple[str, ...]]:
    compiled = compile_exact_secret_forms(secrets) if secrets else {}
    blobs = 0
    matches: set[str] = set()
    identities: list[str] = []
    for path in paths:
        if not isinstance(path, pathlib.Path):
            path = pathlib.Path(path)
        try:
            info = os.lstat(path)
        except OSError:
            raise PrivacyError("Required release artifact does not exist") from None
        if stat.S_ISLNK(info.st_mode):
            raise PrivacyError("release artifact must be a regular non-symlink file")
        try:
            if stat.S_ISDIR(info.st_mode):
                _reject_artifact_stat(info, directory_ok=True)
                if target_id:
                    raise PrivacyError("target identity does not match the artifact type")
                iterator = _iter_directory(path)
                identities.append("directory")
            else:
                _reject_artifact_stat(info)
                snapshot = _snapshot_regular_file(path)
                _assert_target_artifact_type(
                    target_id, path, snapshot, exact_target=exact_target
                )
                identities.append(snapshot.digest)
                iterator = _iter_snapshot(snapshot)
            if service_account_member_name(path.name):
                raise PrivacyError(
                    f"{PUBLIC_MEMBER_LABEL} contains reusable secret category "
                    "google_service_account_json. Obfuscation or stripping is not "
                    "remediation; remove the credential from the distributable before "
                    "rebuilding."
                )
            for member_name, data in iterator:
                _inspect_member(member_name, data, secrets, compiled, matches)
                blobs += 1
        except PrivacyError as exc:
            raise PrivacyError(redact_diagnostic(str(exc), compiled)) from None
        except Exception as exc:
            raise PrivacyError(redact_diagnostic("archive is not inspectable", compiled)) from None
    if blobs == 0:
        raise PrivacyError("Artifact privacy scan inspected no files.")
    return blobs, tuple(sorted(matches)), tuple(identities)


def validate_artifacts(paths: Iterable[pathlib.Path], secrets: dict[str, str]) -> int:
    blobs, matched, _identities = _scan_artifacts(paths, secrets)
    if matched:
        raise PrivacyError(
            "artifact contains exact known-server-secret label(s) "
            + ", ".join(matched)
            + "."
        )
    return blobs


def scan_release_artifacts(
    paths: Iterable[pathlib.Path],
    inventory: SecretInventory,
    *,
    target_id: str = "",
    require_target: bool = False,
) -> ArtifactPrivacyScanResult:
    if require_target and not target_id:
        raise PrivacyError("authenticated release artifact scan requires an exact target identity")
    if target_id and TARGET_ID_RE.fullmatch(target_id) is None:
        raise PrivacyError("target identity is not a validated ASCII label")
    if target_id and target_id not in KNOWN_PRIVACY_TARGET_IDS:
        raise PrivacyError("target identity is not a known release target")
    try:
        secrets = dict(release_secret_values(inventory))
    except InventoryError as exc:
        raise PrivacyError(str(exc)) from None
    try:
        blobs, matched, identities = _scan_artifacts(
            paths, secrets, target_id=target_id, exact_target=require_target
        )
    finally:
        secrets.clear()
    return ArtifactPrivacyScanResult(
        passed=not matched,
        revision=inventory.revision,
        labels=inventory.labels,
        label_count=inventory.label_count,
        unique_value_count=inventory.unique_value_count,
        target_id=target_id,
        artifact_identity=",".join(identities),
        matched_labels=matched,
        blob_count=blobs,
        inventory_sha256=str(inventory.public_summary().get("inventory_sha256", "")),
    )


def read_secrets_stdin() -> dict[str, str]:
    try:
        raw = sys.stdin.buffer.read()
        payload = json.loads(
            raw.decode("utf-8-sig"), object_pairs_hook=_reject_duplicate_json_keys
        )
    except PrivacyError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise PrivacyError("Secret scan input must be one UTF-8 JSON object on stdin.") from None
    if not isinstance(payload, dict) or not payload:
        raise PrivacyError("Secret scan input must be a non-empty JSON object.")
    result: dict[str, str] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", key):
            raise PrivacyError("Secret scan input contains an invalid field label.")
        if not isinstance(value, str) or len(value) < 12:
            raise PrivacyError(f"Secret scan input {key} must contain at least 12 characters.")
        result[key] = value
    return result


def read_secret_environment(names: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in names:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", name):
            raise PrivacyError("Secret environment input contains an invalid field label.")
        if name in result:
            raise PrivacyError(f"Secret environment input repeats {name}.")
        value = os.environ.get(name, "")
        if len(value) < 12:
            raise PrivacyError(
                f"Secret environment input {name} must be present and contain at least 12 characters."
            )
        result[name] = value
    return result


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as temp_name:
        temp = pathlib.Path(temp_name)
        clean = temp / "clean.zip"
        with zipfile.ZipFile(clean, "w") as archive:
            archive.writestr("client.bin", b"https://sync.app-cloud-sync.net/nodes")
        validate_artifacts((clean,), {})

        approved_vendor_uri = temp / "approved-vendor-uri.zip"
        with zipfile.ZipFile(approved_vendor_uri, "w") as archive:
            archive.writestr(
                "vendor.bin", b"https://" + b"1.1.1.1" + b"/dns-query"
            )
        validate_artifacts((approved_vendor_uri,), {})

        unapproved_ip_uri = temp / "unapproved-ip-uri.zip"
        with zipfile.ZipFile(unapproved_ip_uri, "w") as archive:
            archive.writestr(
                "client.bin", b"https://" + b"203.0.113.10" + b"/api"
            )
        try:
            validate_artifacts((unapproved_ip_uri,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted a non-approved public-IP URI.")

        forbidden = temp / "forbidden.zip"
        with zipfile.ZipFile(forbidden, "w") as archive:
            archive.writestr("client.bin", b"prefix WINS_SPA_KEY suffix")
        try:
            validate_artifacts((forbidden,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted a legacy SPA client literal.")

        numeric_collision = temp / "numeric-collision.zip"
        with zipfile.ZipFile(numeric_collision, "w") as archive:
            archive.writestr("proguard.map", b"method -> m$622015610")
        validate_artifacts((numeric_collision,), {})
        forbidden_port = temp / "forbidden-port.zip"
        with zipfile.ZipFile(forbidden_port, "w") as archive:
            archive.writestr("client.bin", b"udp_port=62201")
        try:
            validate_artifacts((forbidden_port,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted the complete retired SPA UDP port token.")

        # Exercise the digest-only address denylist with a documentation-range
        # fixture.  It is inserted only for this self-test and always removed.
        fixture_address = b"203.0.113.200"
        fixture_digest = hashlib.sha256(fixture_address).hexdigest()
        FORBIDDEN_CLIENT_ADDRESS_SHA256["self_test_address"] = fixture_digest
        try:
            for encoding in ("ascii", "utf-16-le", "utf-16-be"):
                forbidden_address = temp / f"forbidden-address-{encoding}.zip"
                with zipfile.ZipFile(forbidden_address, "w") as archive:
                    archive.writestr("client.bin", fixture_address.decode("ascii").encode(encoding))
                try:
                    validate_artifacts((forbidden_address,), {})
                except PrivacyError:
                    pass
                else:
                    raise PrivacyError(
                        f"Self-test accepted a {encoding} forbidden client address."
                    )
        finally:
            del FORBIDDEN_CLIENT_ADDRESS_SHA256["self_test_address"]

        unsafe_zip_path = temp / "unsafe-path.zip"
        with zipfile.ZipFile(unsafe_zip_path, "w") as archive:
            archive.writestr("../client.bin", b"fixture")
        try:
            validate_artifacts((unsafe_zip_path,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted ZIP path traversal.")

        duplicate_zip_path = temp / "duplicate-path.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate_zip_path, "w") as archive:
                archive.writestr("client.bin", b"first")
                archive.writestr("CLIENT.bin", b"second")
        try:
            validate_artifacts((duplicate_zip_path,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted a case-colliding ZIP path.")

        symlink_zip = temp / "symlink.zip"
        link = zipfile.ZipInfo("client.bin")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(symlink_zip, "w") as archive:
            archive.writestr(link, b"target")
        try:
            validate_artifacts((symlink_zip,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted a link-like ZIP member.")

        secret = "fixture-secret-value-123456789"
        utf16 = temp / "secret.tar.gz"
        payload = "fixture-secret-value-123456789".encode("utf-16-le")
        info = tarfile.TarInfo("client.bin")
        info.size = len(payload)
        with tarfile.open(utf16, "w:gz") as archive:
            archive.addfile(info, io.BytesIO(payload))
        try:
            validate_artifacts((utf16,), {"FIXTURE_SECRET": secret})
        except PrivacyError as exc:
            disclosed = str(exc)
            if secret in disclosed:
                raise PrivacyError("Self-test disclosed the fixture secret.") from exc
            digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
            if digest in disclosed:
                raise PrivacyError("Self-test hashed the fixture secret into output.") from exc
        else:
            raise PrivacyError("Self-test accepted a UTF-16 encoded secret.")

        b64_secret = temp / "secret-b64.zip"
        encoded_secret = base64.b64encode(secret.encode("utf-8"))
        with zipfile.ZipFile(b64_secret, "w") as archive:
            archive.writestr("client.bin", encoded_secret)
        try:
            validate_artifacts((b64_secret,), {"FIXTURE_SECRET": secret})
        except PrivacyError as exc:
            disclosed = str(exc)
            if secret in disclosed or encoded_secret.decode("ascii") in disclosed:
                raise PrivacyError("Self-test disclosed a Base64 fixture secret.") from exc
        else:
            raise PrivacyError("Self-test accepted a Base64 encoded secret.")

        unsafe_mode = temp / "unsafe-mode.tar.gz"
        payload = b"fixture"
        info = tarfile.TarInfo("wins_vpn")
        info.size = len(payload)
        info.mode = 0o777
        with tarfile.open(unsafe_mode, "w:gz") as archive:
            archive.addfile(info, io.BytesIO(payload))
        try:
            validate_artifacts((unsafe_mode,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted a world-writable Linux executable.")

        for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
            leaked_home = temp / f"home-path-{encoding}.zip"
            payload = "/Users/release-builder/Downloads/wins_vpn/ios/Runner.app".encode(
                encoding
            )
            with zipfile.ZipFile(leaked_home, "w") as archive:
                archive.writestr("client.bin", payload)
            try:
                validate_artifacts((leaked_home,), {})
            except PrivacyError:
                pass
            else:
                raise PrivacyError(
                    f"Self-test accepted a {encoding} user-home/source-tree path."
                )

        source_tree = temp / "source-tree.zip"
        with zipfile.ZipFile(source_tree, "w") as archive:
            archive.writestr("client.bin", b"/Volumes/build/wins_vpn/macos/Runner.app")
        try:
            validate_artifacts((source_tree,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted a non-home source-tree path.")

        safe_runtime = temp / "safe-runtime.zip"
        with zipfile.ZipFile(safe_runtime, "w") as archive:
            archive.writestr(
                "client.bin", b"Library/Group Containers/group.org.winsvpn.app/status.json"
            )
        validate_artifacts((safe_runtime,), {})

        if __package__:
            from tools.release_obfuscation_contract import _minimal_elf64
            from tools.release_obfuscation_contract import _minimal_macho64
        else:
            from release_obfuscation_contract import _minimal_elf64
            from release_obfuscation_contract import _minimal_macho64

        stripped_elf = _minimal_elf64(".text", ".dynsym")
        debug_elf = _minimal_elf64(".text", ".debug_info")
        pem_marker = b"-----BEGIN PRIVATE KEY-----"
        native_secret = temp / "native-secret.apk"
        with zipfile.ZipFile(native_secret, "w") as archive:
            archive.writestr("lib/arm64-v8a/libxray.so", stripped_elf + pem_marker)
        try:
            validate_artifacts((native_secret,), {})
        except PrivacyError as exc:
            message = str(exc)
            if "private_key_material" not in message or "remove the credential" not in message:
                raise PrivacyError(
                    "Self-test secret rejection did not require removal from the distributable."
                ) from exc
        else:
            raise PrivacyError("Self-test accepted reusable private-key material in a native library.")
        github_secret = temp / "github-secret.apk"
        with zipfile.ZipFile(github_secret, "w") as archive:
            archive.writestr(
                "lib/arm64-v8a/libapp.so",
                stripped_elf + b"ghp_" + b"A" * 36,
            )
        try:
            validate_artifacts((github_secret,), {})
        except PrivacyError as exc:
            if "remove the credential" not in str(exc):
                raise PrivacyError("Self-test GitHub token rejection omitted distributable removal.") from exc
        else:
            raise PrivacyError("Self-test accepted an embedded reusable GitHub token.")

        native_debug = temp / "native-debug.apk"
        with zipfile.ZipFile(native_debug, "w") as archive:
            archive.writestr("lib/arm64-v8a/libam-go.so", debug_elf)
        try:
            validate_artifacts((native_debug,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted unstripped DWARF in a native library.")

        native_clean = temp / "native-clean.apk"
        with zipfile.ZipFile(native_clean, "w") as archive:
            archive.writestr("lib/arm64-v8a/libapp.so", stripped_elf)
            archive.writestr("lib/arm64-v8a/libwinnengine.so", stripped_elf)
        validate_artifacts((native_clean,), {})

        java_magic_collision = temp / "java-magic-collision.apk"
        with zipfile.ZipFile(java_magic_collision, "w") as archive:
            archive.writestr("DebugProbesKt.bin", b"\xca\xfe\xba\xbe" + b"not-a-macho")
        validate_artifacts((java_magic_collision,), {})

        malformed_native = temp / "malformed-native.ipa"
        with zipfile.ZipFile(malformed_native, "w") as archive:
            archive.writestr(
                "Payload/Runner.app/Frameworks/libbroken.dylib",
                b"\xca\xfe\xba\xbe" + b"not-a-macho",
            )
        try:
            validate_artifacts((malformed_native,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted a malformed native-looking Mach-O library.")

        store_only = temp / "store-only-debug.aab"
        with zipfile.ZipFile(store_only, "w") as archive:
            archive.writestr("base/lib/arm64-v8a/libapp.so", stripped_elf)
            archive.writestr(
                "BUNDLE-METADATA/com.android.tools.build.debugsymbols/arm64-v8a/libapp.so.dbg",
                debug_elf,
            )
        validate_artifacts((store_only,), {})

        ipa_debug = temp / "native-debug.ipa"
        with zipfile.ZipFile(ipa_debug, "w") as archive:
            archive.writestr(
                "Payload/Runner.app/Frameworks/libwg-go.dylib",
                _minimal_macho64(dwarf=True),
            )
        try:
            validate_artifacts((ipa_debug,), {})
        except PrivacyError:
            pass
        else:
            raise PrivacyError("Self-test accepted unstripped DWARF in an iOS native library.")

        secret = "fixture-secret-value-123456789"
        utf32 = temp / "secret-utf32.zip"
        with zipfile.ZipFile(utf32, "w") as archive:
            archive.writestr("client.bin", secret.encode("utf-32-le"))
        try:
            validate_artifacts((utf32,), {"FIXTURE_SECRET": secret})
        except PrivacyError as exc:
            if secret in str(exc):
                raise PrivacyError("Self-test disclosed a UTF-32 fixture secret.") from exc
        else:
            raise PrivacyError("Self-test accepted a UTF-32 encoded secret.")

        split_js = temp / "secret-split-js.zip"
        with zipfile.ZipFile(split_js, "w") as archive:
            archive.writestr(
                "background.js",
                b'const token = "fixture-secret-value-" + "123456789";\n',
            )
        try:
            validate_artifacts((split_js,), {"FIXTURE_SECRET": secret})
        except PrivacyError as exc:
            if secret in str(exc):
                raise PrivacyError("Self-test disclosed a split JavaScript secret.") from exc
        else:
            raise PrivacyError("Self-test accepted a split JavaScript secret.")

        commented = temp / "secret-zip-comment.zip"
        with zipfile.ZipFile(commented, "w") as archive:
            archive.writestr("client.bin", b"clean-fixture")
            archive.comment = secret.encode("utf-8")
        try:
            validate_artifacts((commented,), {"FIXTURE_SECRET": secret})
        except PrivacyError as exc:
            if secret in str(exc):
                raise PrivacyError("Self-test disclosed a ZIP comment secret.") from exc
        else:
            raise PrivacyError("Self-test accepted a ZIP comment secret.")

        public_pem = temp / "public-cert.zip"
        with zipfile.ZipFile(public_pem, "w") as archive:
            archive.writestr(
                "client.pem",
                b"-----BEGIN CERTIFICATE-----\nMIIBfixturepubliccertnotasecretXX\n-----END CERTIFICATE-----\n",
            )
        validate_artifacts((public_pem,), {})
        public_key = temp / "public-key.zip"
        with zipfile.ZipFile(public_key, "w") as archive:
            archive.writestr(
                "client.pub",
                b"-----BEGIN PUBLIC KEY-----\nMIIBfixturepublickeynotasecretXX\n-----END PUBLIC KEY-----\n",
            )
        validate_artifacts((public_key,), {})
        spki = temp / "public-spki.zip"
        with zipfile.ZipFile(spki, "w") as archive:
            archive.writestr("client.spki", ED25519_SPKI_PREFIX + (b"\x11" * 32))
        validate_artifacts((spki,), {})

        service_account = temp / "service-account.zip"
        with zipfile.ZipFile(service_account, "w") as archive:
            archive.writestr(
                "assets/adc.json",
                b'{"type":"service_account","project_id":"wins-proof",'
                b'"client_email":"proof@wins-proof.iam.gserviceaccount.com"}',
            )
        try:
            validate_artifacts((service_account,), {})
        except PrivacyError as exc:
            if "google_service_account_json" not in str(exc):
                raise PrivacyError(
                    "Self-test rejected service-account JSON without the named category."
                ) from exc
        else:
            raise PrivacyError("Self-test accepted packaged service-account JSON.")

        sa_named = temp / "named-sa.zip"
        with zipfile.ZipFile(sa_named, "w") as archive:
            archive.writestr("google-service-account.json", b'{"project_id":"wins-proof"}')
        try:
            validate_artifacts((sa_named,), {})
        except PrivacyError as exc:
            if "google_service_account_json" not in str(exc):
                raise PrivacyError(
                    "Self-test rejected a service-account filename without the named category."
                ) from exc
        else:
            raise PrivacyError("Self-test accepted a service-account JSON filename.")

        loose_sa = temp / "application_default_credentials.json"
        loose_sa.write_bytes(b'{"project_id":"wins-proof"}')
        try:
            validate_artifacts((loose_sa,), {})
        except PrivacyError as exc:
            if "google_service_account_json" not in str(exc):
                raise PrivacyError(
                    "Self-test rejected a loose service-account filename without the named category."
                ) from exc
        else:
            raise PrivacyError("Self-test accepted a loose service-account JSON filename.")

        activation = temp / "activation.zip"
        with zipfile.ZipFile(activation, "w") as archive:
            archive.writestr(
                "assets/config.bin",
                b'activation_secret="one-time-enrollment-secret-value-001"',
            )
        try:
            validate_artifacts((activation,), {})
        except PrivacyError as exc:
            if "activation_secret" not in str(exc):
                raise PrivacyError(
                    "Self-test rejected an activation secret without the named category."
                ) from exc
        else:
            raise PrivacyError("Self-test accepted a packaged activation secret.")

        public_pins = temp / "public-pins.zip"
        with zipfile.ZipFile(public_pins, "w") as archive:
            archive.writestr(
                "pins.dart",
                b"const String kSpkiWinsvpnOrgWildcard = "
                b"'H6Mj7DsLr6FAGUz4jLll4sc9AXDe3XcOsv4qWwUzY98=';\n"
                b"const String kReviewedAnnouncementPubkeyA1 = "
                b"'d9hwDSlQpYvnph33NJFHAbOm3hKR1wWEhC/kFiNoeoo=';\n"
                b"const String server_public_key = "
                b"'d9hwDSlQpYvnph33NJFHAbOm3hKR1wWEhC/kFiNoeoo=';\n",
            )
        validate_artifacts((public_pins,), {})


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv[:1] == ["--verify"]:
        if len(raw_argv) != 3:
            raise PrivacyError(
                "canonical cross-store usage is exactly --verify <target-id> <artifact-path>"
            )
        canonical_extension_gate_verify(raw_argv[1], raw_argv[2])
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("--static", action="store_true")
    parser.add_argument("--artifacts", action="store_true")
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--secrets-stdin", action="store_true")
    parser.add_argument("--secret-env", action="append", default=[])
    parser.add_argument("--authenticated-inventory", action="store_true")
    parser.add_argument("--target", default="")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--defer-secret-scan-to-release-host",
        dest="defer_secret_scan",
        help="REMOTE_INPUT.json of a remote-attested Windows build: finish-build on the "
             "macOS release host runs this scan against the copied-back installer",
    )
    args = parser.parse_args(raw_argv)
    if not any(
        (
            args.static,
            args.artifacts,
            args.secrets_stdin,
            args.secret_env,
            args.authenticated_inventory,
            args.self_test,
        )
    ):
        parser.error(
            "select --static, --artifacts, --secrets-stdin, "
            "--authenticated-inventory, or --self-test"
        )
    if args.target and TARGET_ID_RE.fullmatch(args.target) is None:
        raise PrivacyError("target identity is not a validated ASCII label")
    if args.target and args.target not in KNOWN_PRIVACY_TARGET_IDS:
        raise PrivacyError("target identity is not a known release target")
    if args.self_test:
        run_self_test()
        print("RELEASE ARTIFACT PRIVACY SELF-TEST: PASS")
    if args.static:
        count = validate_static()
        print(f"RELEASE CLIENT STATIC PRIVACY: PASS ({count} files)")
    if args.defer_secret_scan:
        # A Windows host cannot load the authenticated inventory (no
        # descriptor-relative open). The remote-attested Windows build hands the
        # scan to finish-build on the release host, which runs this same command
        # against the copied-back installer and refuses the receipt on any hit.
        if (
            not args.artifacts
            or args.authenticated_inventory
            or args.secrets_stdin
            or args.secret_env
            or args.target not in DEFERRABLE_SECRET_SCAN_TARGET_IDS
            or len(args.artifact) != 1
            or pathlib.Path(args.artifact[0]).name.lower()
            not in TARGET_CANONICAL_FILENAMES.get(args.target, frozenset())
        ):
            raise PrivacyError(
                "the deferred secret scan covers exactly one --artifacts scan of one "
                "Windows installer whose name belongs to its --target"
            )
        try:
            require_secret_scan_deferral(pathlib.Path(args.defer_secret_scan))
        except ObfuscationError as exc:
            raise PrivacyError(str(exc)) from None
        print(SECRET_SCAN_DEFERRAL_NOTICE)
        return 0
    if (
        args.authenticated_inventory
        or args.artifacts
        or args.secrets_stdin
        or args.secret_env
    ):
        try:
            inventory = load_authenticated_secret_inventory(
                repository_root=ROOT
            )
        except InventoryError as exc:
            raise PrivacyError(str(exc)) from None
        if args.artifact and not args.target:
            raise PrivacyError(
                "explicit release artifacts require --target for exact custody binding"
            )
        if args.target:
            paths = (
                tuple(pathlib.Path(value) for value in args.artifact)
                if args.artifact
                else (default_artifacts_by_target()[args.target],)
            )
            scan_jobs = ((args.target, paths),)
        else:
            by_target = default_artifacts_by_target()
            scan_jobs = tuple(
                (target_id, (by_target[target_id],))
                for target_id in REQUIRED_PRIVACY_TARGET_IDS
            )
            paths = tuple(job_paths[0] for _target, job_paths in scan_jobs)
        for target_id, target_paths in scan_jobs:
            result = scan_release_artifacts(
                target_paths,
                inventory,
                target_id=target_id,
                require_target=True,
            )
            print(format_inventory_scan_report(result))
            if not result.passed:
                return 1
        secrets = read_secrets_stdin() if args.secrets_stdin else {}
        environment_secrets = read_secret_environment(args.secret_env)
        overlap = set(secrets).intersection(environment_secrets)
        if overlap:
            raise PrivacyError(f"Secret input repeats {sorted(overlap)[0]} across sources.")
        secrets.update(environment_secrets)
        if secrets:
            count = validate_artifacts(paths, secrets)
            print(
                "RELEASE SUPPLEMENTAL EPHEMERAL SECRET SCAN: PASS "
                f"({count} embedded files, {len(secrets)} fields)"
            )
        return 0
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PrivacyError, InventoryError) as exc:
        print(f"RELEASE ARTIFACT PRIVACY: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
