#!/usr/bin/env python3
"""Offline verification of exact Windows native-architecture Inno candidates.

The uploaded EXE is the only payload authority. Mutable JSON sidecars, loose
repository files, and producer booleans cannot prove packed ``data/app.so`` or
inner PE files. Inner-payload proof is a reviewed exact Inno extractor or an
authenticated Windows install-run capture that consumes one descriptor-bound
immutable installer snapshot and emits a separately authenticated execution
receipt tied to its digest, signer and build transaction. Either missing
capability is an owner/environment blocker.
"""

from __future__ import annotations

import atexit
import datetime
import errno
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from types import ModuleType
from typing import NamedTuple


ORIGIN_ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS_DIR = pathlib.Path(__file__).resolve().parent
ROOT = ORIGIN_ROOT
TEST_ONLY = False
READ_CHUNK = 1024 * 1024
TARGET_FILENAMES = {
    "windows-x64-installer": "WinsVPN-Setup.exe",
    "windows-x64-partner-center": "WinsVPN-PartnerCenter.exe",
    "windows-arm64-installer": "WinsVPN-Setup-arm64.exe",
    "windows-arm64-partner-center": "WinsVPN-PartnerCenter-arm64.exe",
}
TARGET_SURFACES = {
    "windows-x64-installer": "website",
    "windows-x64-partner-center": "partner-center",
    "windows-arm64-installer": "website",
    "windows-arm64-partner-center": "partner-center",
}
TARGET_ARCHITECTURES = {
    "windows-x64-installer": "x64",
    "windows-x64-partner-center": "x64",
    "windows-arm64-installer": "arm64",
    "windows-arm64-partner-center": "arm64",
}
TARGET_FILE_DESCRIPTIONS = {
    "windows-x64-installer": "Win's VPN x64 website installer",
    "windows-x64-partner-center": "Win's VPN x64 Partner Center Win32 installer",
    "windows-arm64-installer": "Win's VPN arm64 website installer",
    "windows-arm64-partner-center": "Win's VPN arm64 Partner Center Win32 installer",
}
CANONICAL_RELEASE = "1.0.17+34"
CANONICAL_PRODUCT_VERSION = "1.0.17"
CANONICAL_FILE_VERSION = "1.0.17.34"
PACKAGE_UPLOAD_RECEIPT_SCHEMA_VERSION = 2
PACKAGE_UPLOAD_RECEIPT_CONTRACT = "winsvpn-windows-package-upload-receipt-v2"
OWNER_AUTHORIZATION_CONTRACT = "winsvpn-windows-owner-authorization-v2"
DESCRIPTOR_RELATIVE = "tools/windows_cross_store_artifact_gate.py"
EVIDENCE_COLLECTOR_RELATIVE = "tools/windows_release_matrix_evidence.py"
OBFUSCATION_PRIVACY_RELATIVE = "tools/release_obfuscation_contract.py"
CERTIFICATION_NOTES_RELATIVE = "installer/windows/store/certification-notes.md"
STORE_METADATA_ROOT = "app_store/windows"
EXPECTED_UPLOAD_ARTIFACT_DIRECTORY = "build/windows-installer"
UNIQUE_UPLOAD_RECEIPT_DIGEST_FIELDS = ("artifact", "build_receipt")
SHARED_UPLOAD_RECEIPT_PATH_FIELDS = (
    "descriptor",
    "source_freeze",
    "obfuscation_privacy",
    "evidence_collector",
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
        "evidence_collector",
        "publication_authorized",
        "upload_attempted",
        "owner_authorization",
        "authentication",
    }
)
REQUIRED_WINDOWS_UPLOAD_TARGETS = (
    "windows-x64-installer",
    "windows-x64-partner-center",
    "windows-arm64-installer",
    "windows-arm64-partner-center",
)
WINDOWS_PACKAGE_UPLOAD_TARGETS = {
    "windows-x64-installer": {
        "platform": "windows",
        "architectures": ("x64",),
        "artifact_name": "WinsVPN-Setup.exe",
        "signing_contract": "windows-x64-authenticode",
        "signing_status": "required",
        "store_surface": "website",
        "producer": "installer/windows/build_installer.ps1",
        "producer_id": "winsvpn-windows-website-inno-x64",
        "build_receipt_target": "windows-x64-inno-signed",
        "file_description": "Win's VPN x64 website installer",
        "identity_keys": frozenset(
            {
                "product_version",
                "four_part_version",
                "architecture",
                "filename",
                "file_description",
                "surface",
            }
        ),
    },
    "windows-x64-partner-center": {
        "platform": "windows",
        "architectures": ("x64",),
        "artifact_name": "WinsVPN-PartnerCenter.exe",
        "signing_contract": "windows-x64-store-signature",
        "signing_status": "required",
        "store_surface": "partner-center",
        "producer": "installer/windows/build_installer.ps1",
        "producer_id": "winsvpn-windows-partner-center-inno-x64",
        "build_receipt_target": "windows-x64-inno-signed",
        "file_description": "Win's VPN x64 Partner Center Win32 installer",
        "identity_keys": frozenset(
            {
                "product_version",
                "four_part_version",
                "architecture",
                "filename",
                "file_description",
                "surface",
            }
        ),
    },
    "windows-arm64-installer": {
        "platform": "windows",
        "architectures": ("arm64",),
        "artifact_name": "WinsVPN-Setup-arm64.exe",
        "signing_contract": "windows-arm64-authenticode",
        "signing_status": "required",
        "store_surface": "website",
        "producer": "installer/windows/build_installer.ps1",
        "producer_id": "winsvpn-windows-website-inno-arm64",
        "build_receipt_target": "windows-arm64-inno-signed",
        "file_description": "Win's VPN arm64 website installer",
        "identity_keys": frozenset(
            {
                "product_version",
                "four_part_version",
                "architecture",
                "filename",
                "file_description",
                "surface",
            }
        ),
    },
    "windows-arm64-partner-center": {
        "platform": "windows",
        "architectures": ("arm64",),
        "artifact_name": "WinsVPN-PartnerCenter-arm64.exe",
        "signing_contract": "windows-arm64-store-signature",
        "signing_status": "required",
        "store_surface": "partner-center",
        "producer": "installer/windows/build_installer.ps1",
        "producer_id": "winsvpn-windows-partner-center-inno-arm64",
        "build_receipt_target": "windows-arm64-inno-signed",
        "file_description": "Win's VPN arm64 Partner Center Win32 installer",
        "identity_keys": frozenset(
            {
                "product_version",
                "four_part_version",
                "architecture",
                "filename",
                "file_description",
                "surface",
            }
        ),
    },
}
WINDOWS_STORE_FILES = (
    "README.md",
    "metadata/en-US/title.txt",
    "metadata/en-US/short_description.txt",
    "metadata/en-US/full_description.txt",
    "metadata/en-US/whats_new.txt",
    "metadata/en-US/features.txt",
    "metadata/en-US/search_terms.txt",
    "metadata/en-US/copyright.txt",
    "metadata/en-US/support_url.txt",
    "metadata/en-US/privacy_url.txt",
    "metadata/en-US/website_url.txt",
    "review/partner_center_notes.txt",
    "review/privacy_label_manifest.json",
    "review/owner_signoff.json",
    "artifacts/release_candidate.json",
)
WINDOWS_TITLE_MAX = 50
WINDOWS_SHORT_DESCRIPTION_MAX = 200
WINDOWS_FULL_DESCRIPTION_MAX = 10000
WINDOWS_WHATS_NEW_MAX = 1500
WINDOWS_FEATURE_MAX_COUNT = 20
WINDOWS_FEATURE_MAX_CHARS = 200
WINDOWS_SEARCH_TERM_MAX_COUNT = 7
WINDOWS_SEARCH_TERM_MAX_CHARS = 30
WINDOWS_COPYRIGHT = "Copyright (C) 2026 Win's VPN Inc. All rights reserved."
WINDOWS_PRIVACY_POLICY_URL = "https://www.winsvpn.org/privacy/"
WINDOWS_SUPPORT_URL = "https://www.winsvpn.org/support/"
WINDOWS_WEBSITE_URL = "https://winsvpn.org"
WINDOWS_MSIX_PACKAGE_FILENAME = "WinsVPN-Store-1.0.17.34-x64.msix"
WINDOWS_OWNER_SIGNOFF_BLOCKERS = [
    "Windows listing/screenshot inventory is owner-blocked",
    "Public-trust Authenticode identity remains owner-held",
    "Partner Center enrollment remains owner-held",
    "No current signed x64 website or Partner Center receipt for 1.0.17+34",
    "Website and Partner Center upload remain owner-authorized only",
    "Production MSIX is not a 1.0.17+34 upload target",
    "Private Flutter symbols and per-surface obfuscation receipts remain unpublished",
]
WINDOWS_TUNNEL_PROTOCOL = {
    "executed_on": "local-device",
    "primary": "winn-v3",
    "fallback": ["awg", "xray"],
    "required_local_engines": [
        "winn-datapath.exe",
        "winsvpn_winn3_engine.exe",
        "winsvpn_awg_engine.exe",
        "amneziawg.exe",
        "awg.exe",
        "xray.exe",
    ],
}
WINDOWS_COLLECTED_CATEGORIES = [
    "device_or_other_ids",
    "user_ids",
    "email_address",
    "approximate_location",
    "purchase_history",
    "app_info",
    "diagnostics_if_sdk_report_proves",
]
WINDOWS_NOT_COLLECTED_CATEGORIES = [
    "browsing_history",
    "dns_query_history",
    "traffic_content",
    "raw_vpn_traffic",
    "destination_activity",
]
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
REVIEWED_PRODUCER_IDENTITIES = {
    "windows-x64-installer": "winsvpn-windows-website-inno-x64",
    "windows-x64-partner-center": "winsvpn-windows-partner-center-inno-x64",
    "windows-arm64-installer": "winsvpn-windows-website-inno-arm64",
    "windows-arm64-partner-center": "winsvpn-windows-partner-center-inno-arm64",
}
AWG_GO_VERSION = "v3.1.20260828"
AWG_GO_MODULE = "github.com/amnezia-vpn/amneziawg-go/v3"
AWG_GO_COMMIT = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
AWG_TOOL_SHA256 = {
    "x64": "272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12",
    "arm64": "3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43",
}
WINTUN_SHA256 = {
    "x64": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
    "arm64": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
}
XRAY_SHA256 = {
    "x64": "fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224",
    "arm64": "c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af",
}
VC_REDIST_VERSION = "14.44.35211.0"
VC_REDIST_BASENAME = {
    "x64": "VC_redist.x64.exe",
    "arm64": "VC_redist.arm64.exe",
}
VC_REDIST_SHA256 = {
    "x64": "cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b",
    "arm64": "5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0",
}
VC_REDIST_PUBLISHER_CN = "Microsoft Corporation"
VC_REDIST_PRODUCT_NAME = {
    "x64": "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211",
    "arm64": "Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.44.35211",
}
MAX_VC_REDIST_BYTES = 104857600
AMNEZIAWG_MSI_BASENAME = {
    "x64": "amneziawg-amd64.msi",
    "arm64": "amneziawg-arm64.msi",
}
AMNEZIAWG_MSI_SHA256 = {
    "x64": "a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b",
    "arm64": "3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa",
}
AMNEZIAWG_MSI_PUBLISHER_O = "Privacy Technologies OU"
MAX_AMNEZIAWG_MSI_BYTES = 16777216
MSI_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
WINTUN_PUBLISHER_O = "WireGuard LLC"
ALL_VC_REDIST_BASENAMES = frozenset(VC_REDIST_BASENAME.values())
ALL_AMNEZIAWG_MSI_BASENAMES = frozenset(AMNEZIAWG_MSI_BASENAME.values())
VENDOR_DEBUG_EXCEPTION_PE_BASENAMES = ALL_VC_REDIST_BASENAMES | frozenset({"wintun.dll"})
WITHDRAWN_MULLVAD_SHA256 = frozenset(
    {
        "10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201",
        "c599926a0327d7ae06b534f4cd039db30392e1897bb9d03e4fec3631744a4e6d",
        "3dd5905e5fb98d61a942a33e8c9a5ba07c3a2de1e4f319e1fec3e54df6591608",
        "6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534",
        "c3d27636739ebaa7dde369d113347de83e3e2173b8a512bb8863d11b148de7ce",
        "0bfdb044e40535dabbeb3620b655c1563714b3a6f3231d3492c972c6e8dea6f1",
    }
)
SHARED_PAYLOAD_BASENAMES = frozenset(
    {
        "wins_vpn.exe",
        "wins_vpn_tunnel_service.exe",
        "winn-datapath.exe",
        "winsvpn_winn3_engine.exe",
        "wintun.dll",
        "flutter_windows.dll",
        "wins_bridge_host.exe",
        "org.winsvpn.bridge.chrome.json",
        "org.winsvpn.bridge.edge.json",
        "org.winsvpn.bridge.firefox.json",
    }
)
CLASSICAL_ENGINE_BASENAMES = frozenset(
    {
        "winsvpn_awg_engine.exe",
        "winsvpn_awg_engine.exe.provenance.json",
        "amneziawg.exe",
        "amneziawg.exe.provenance.json",
        "awg.exe",
        "xray.exe",
    }
)
CLASSICAL_PROVENANCE_BASENAMES = frozenset(
    {
        "winsvpn_awg_engine.exe.provenance.json",
        "amneziawg.exe.provenance.json",
    }
)
NATIVE_HOST_BASENAME = "wins_bridge_host.exe"
REQUIRED_NATIVE_MANIFEST_BASENAMES = frozenset(
    {
        "org.winsvpn.bridge.chrome.json",
        "org.winsvpn.bridge.edge.json",
        "org.winsvpn.bridge.firefox.json",
    }
)
OPTIONAL_NATIVE_MANIFEST_BASENAMES = frozenset()
ALLOWED_NATIVE_MANIFEST_BASENAMES = (
    REQUIRED_NATIVE_MANIFEST_BASENAMES | OPTIONAL_NATIVE_MANIFEST_BASENAMES
)
NATIVE_HOST_JSON_NAME = "org.winsvpn.bridge"
NATIVE_HOST_JSON_DESCRIPTION = "Win's VPN browser bridge"
NATIVE_HOST_RELATIVE_PATH_VALUE = "wins_bridge_host.exe"
FIREFOX_NATIVE_EXTENSION_ID = "companion@winsvpn.org"
REQUIRED_PACKED_AOT_PATH = "data/app.so"
INSTALL_PROOF_SCHEMA = "winsvpn-windows-inno-install-proof-v1"
INSTALL_PROOF_SCHEMA_VERSION = 1
INSTALL_PROOF_SUFFIX = ".install-proof.json"
INSTALL_PROOF_REQUIRED_ERROR = (
    "mutable JSON is not proof of installer contents"
)
INNO_INNER_EXTRACTOR_ERROR = (
    "owner/environment blocker: no reviewed Inno inner-payload extractor is "
    "available to prove packed data/app.so and required executables/DLLs from "
    "the exact installer bytes"
)
AUTHENTICATED_CAPTURE_ERROR = (
    "owner/environment blocker: authenticated Windows install-run capture is "
    "unavailable; a reviewed capture must consume one descriptor-bound "
    "immutable installer snapshot and emit a separately authenticated "
    "execution receipt tied to its digest, signer and build transaction"
)
OWNER_INNER_PROOF_ERROR = (
    "owner/environment blocker: no reviewed exact Inno extractor or "
    "authenticated Windows install-run capture is available to consume one "
    "descriptor-bound immutable installer snapshot and emit a separately "
    "authenticated execution receipt tied to its digest, signer and build "
    "transaction"
)
MUTABLE_JSON_PROOF_ERROR = (
    "mutable JSON is not proof of installer contents"
)
AUTHENTICODE_LEAF_CN = "WIN'S VPN INC."
AUTHENTICODE_LEAF_O = "WIN'S VPN INC."
OWNER_AUTHENTICODE_LEAF_SHA256 = "OWNER-BLOCKED: ABSENT"
OWNER_AUTHENTICODE_BLOCKED = "OWNER-BLOCKED: ABSENT"
EXPECTED_PRODUCT_NAME = "Win's VPN"
PAYLOAD_TYPES = frozenset({"pe", "aot", "json", "file"})
REQUIRED_PAYLOAD_BASENAMES = SHARED_PAYLOAD_BASENAMES | CLASSICAL_ENGINE_BASENAMES
REQUIRED_PE_BASENAMES = (
    REQUIRED_PAYLOAD_BASENAMES
    - CLASSICAL_PROVENANCE_BASENAMES
    - ALLOWED_NATIVE_MANIFEST_BASENAMES
)
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
MAX_SUPPORT_BYTES = 8 * 1024 * 1024
MAX_IDENTITY_BYTES = 64 * 1024
MAX_INNER_FILE_BYTES = 512 * 1024 * 1024
MAX_AGGREGATE_INNER_BYTES = 2 * 1024 * 1024 * 1024
MAX_INNER_ENTRIES = 256
MAX_PKCS7 = 256 * 1024
MAX_PKCS7_CERTS = 8
MAX_DER_DEPTH = 12
MAX_RESOURCE_BYTES = 1024 * 1024
MAX_VERSION_STRING = 256
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
PE_MACHINE_X86 = 0x014C
PE_MACHINE_X64 = 0x8664
PE_MACHINE_ARM64 = 0xAA64
INNO_BOOTSTRAP_MACHINE = PE_MACHINE_X86
INNO_BOOTSTRAP_ERROR = (
    "Windows Inno bootstrap is not the reviewed PE32 x86 vendor stub."
)
SOURCE_ONLY_INSTALLER_ERROR = (
    "Windows source files are not an installer upload candidate."
)
COLLECTOR_SELFTEST_ERROR = (
    "Windows evidence collector self-test is not upload evidence."
)
RT_VERSION = 16
SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
OID_DATA = "1.2.840.113549.1.7.1"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SPC_RFC3161 = "1.3.6.1.4.1.311.3.3.1"
OID_ID_SMIME_AA_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"
OID_PKCS9_COUNTERSIGNATURE = "1.2.840.113549.1.9.6"
OID_CN = "2.5.4.3"
OID_O = "2.5.4.10"
RELEASE_IDENTITY_RELATIVE_PATH = pathlib.Path(
    "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
)
TOOLCHAIN_PIN_RELATIVE_PATH = pathlib.Path("tools/toolchain-pins.json")
PRODUCER_RELATIVE_PATH = "installer/windows/build_installer.ps1"
INNO_SCRIPT_RELATIVE_PATH = "installer/windows/winsvpn.iss"
SIGNING_WRAPPER_RELATIVE_PATH = "tools/windows_inno_sign.ps1"
NATIVE_HOST_RENDERER_RELATIVE_PATH = "tools/native_messaging/render_host_manifest.py"
WINDOWS_INSTALLER_SOURCE_PATHS = (
    "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json",
    "extension/manifest/firefox.jsonc",
    "extension/tools/jsonc.py",
    PRODUCER_RELATIVE_PATH,
    INNO_SCRIPT_RELATIVE_PATH,
    "lib/browser_bridge_app_ipc.dart",
    "lib/browser_bridge_framing.dart",
    "lib/browser_bridge_protocol.dart",
    "lib/browser_bridge_proxy.dart",
    "lib/vpn_config_validation.dart",
    "lib/windows_system_executable.dart",
    "lib/winn_carrier_profile_keys.dart",
    "lib/winn_protocol_dispatch.dart",
    "tools/native_messaging/host/bin/wins_bridge_host.dart",
    "tools/native_messaging/host/pubspec.lock",
    "tools/native_messaging/host/pubspec.yaml",
    "tools/native_messaging/install_native_host.sh",
    "tools/native_messaging/manifests/store_ids.json",
    "tools/native_messaging/native_host_layout.py",
    NATIVE_HOST_RENDERER_RELATIVE_PATH,
    "tools/toolchain-pins.json",
    SIGNING_WRAPPER_RELATIVE_PATH,
)
PRIVACY_MODULE_FILENAME = "validate_release_artifact_privacy.py"
PRIVACY_MODULE_NAME = "validate_release_artifact_privacy"
REQUIRED_VERSIONED_PAYLOAD_BASENAMES = frozenset({"wins_vpn.exe"})
PRODUCER_SCHEMA_KEYS = {
    "path",
    "sha256",
    "inno_script_path",
    "inno_script_sha256",
    "inno_signing_wrapper_path",
    "inno_signing_wrapper_sha256",
}
RELEASE_INPUT_SCHEMA_KEYS = {"path", "sha256"}
# build_installer.ps1 Bind-WinsInnoCompilerCustody identity, written into the
# v3 payload manifest as inno_compiler.
INNO_COMPILER_PIN_RELATIVE_PATH = "tools/inno-toolchain-pins.json"
INNO_COMPILER_RECEIPT_CONTRACT = "winsvpn-inno-compiler-receipt-v1"
INNO_COMPILER_IDENTITY_KEYS = {
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
}
TOOLCHAIN_SCHEMA_KEYS = {
    "framework_version",
    "framework_revision",
    "engine_revision",
    "dart_sdk_version",
}
EXECUTION_RECEIPT_SCHEMA = "winsvpn-windows-authenticated-install-run-v1"
EXECUTION_RECEIPT_ISSUER = "winsvpn-windows-authenticated-install-run"
EXECUTION_RECEIPT_ISSUER_PUBLIC_KEY_HEX = (
    "0accb562ad566837f930e391065d37aebb1a736072a242789c0d58e0b54b1cb1"
)
EXECUTION_RECEIPT_MAX_AGE_SECONDS = 300
EXECUTION_RECEIPT_FUTURE_SKEW_SECONDS = 30
EXECUTION_RECEIPT_KEYS = {
    "schema",
    "authenticated",
    "issuer",
    "run_id",
    "nonce",
    "issued_at",
    "target_id",
    "target_architecture",
    "installer_sha256",
    "installer_size",
    "authenticode_leaf_sha256",
    "build_transaction",
    "inner_payload_digests",
    "signature",
    "inner_payloads",
}
RECEIPT_REUSE_ERROR = (
    "Windows execution receipt reuse across targets is forbidden."
)
RECEIPT_REPLAY_ERROR = (
    "Windows execution receipt nonce or run_id was already consumed."
)
RECEIPT_STALE_ERROR = (
    "Windows execution receipt is not fresh."
)
RECEIPT_UNAUTHENTICATED_ERROR = (
    "Windows execution receipt is not authenticated by the trusted issuer."
)
OUTER_SIGNATURE_SKIP_ERROR = (
    "outer Authenticode verification cannot be skipped"
)
OUTER_AUTHENTICODE_ERROR = (
    "outer PE Authenticode is cryptographically invalid or untrusted"
)
TIMESTAMP_MISSING_ERROR = "Authenticode timestamp is missing."
TIMESTAMP_UNVERIFIED_ERROR = (
    "Authenticode timestamp is not cryptographically bound to the signature."
)
OID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"
UPLOAD_RECEIPT_ISSUER = "winsvpn-windows-package-upload-receipt"
OWNER_UPLOAD_RECEIPT_PUBLIC_KEY_HEX = "OWNER-BLOCKED: ABSENT"
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
        "signature",
    }
)
UPLOAD_RECEIPT_PLACEHOLDER_TRUST_MARKERS = (
    "placeholder",
    "ed25519privatekey",
    "ed25519publickey",
)
UPLOAD_RECEIPT_UNAUTHENTICATED_ERROR = (
    "Windows package/upload receipt is not authenticated by the trusted issuer."
)
UPLOAD_RECEIPT_PLACEHOLDER_TRUST_ERROR = (
    "Windows package/upload receipt trust key is a placeholder."
)
UPLOAD_RECEIPT_STALE_ERROR = "Windows package/upload receipt is not fresh."
UPLOAD_RECEIPT_REPLAY_ERROR = (
    "Windows package/upload receipt nonce or run_id was already consumed."
)
AUTHENTICODE_VERIFY_TOOL_NAME = "signtool.exe"
AUTHENTICODE_VERIFY_ARGV_PREFIX = ("verify", "/pa", "/all", "/v", "/tw")
OWNER_AUTHENTICODE_SIGNTOOL = "OWNER-BLOCKED: ABSENT"
WEBSITE_WINVERIFYTRUST_SCHEMA = "winsvpn-windows-publication-winverifytrust-v1"
CALLER_AUTHORED_AUTHENTICODE_JSON_ERROR = (
    "caller-authored Authenticode success JSON is not verification evidence"
)
AUTHENTICODE_ARGV_ERROR = (
    "Authenticode verification requires exact non-shell signtool argv"
)
WEAK_DIGEST_ERROR = "Authenticode digest algorithm is weaker than SHA-256."
REVOCATION_UNCERTAIN_ERROR = (
    "Authenticode chain or revocation status is uncertain."
)
WEBSITE_SIGNING_AS_PARTNER_CENTER_ERROR = (
    "website Authenticode evidence is not Partner Center upload proof"
)
BUILD_RECEIPT_STALE_ERROR = "Windows build receipt is stale or unbound."
BUILD_RECEIPT_IDENTITY_ERROR = (
    "Windows build receipt does not bind the exact artifact identity."
)
MAX_BUILD_RECEIPT_AGE_SECONDS = 72 * 3600
MAX_BUILD_RECEIPT_FUTURE_SKEW_SECONDS = 300
AUTHENTICODE_SUCCESS_MARK = "Successfully verified"
AUTHENTICODE_TIMESTAMP_MARKS = (
    "Timestamp Verified by:",
    "The signature is timestamped",
    "Signing time:",
)
AUTHENTICODE_SHA1_MARKS = (
    "hash of file (sha1)",
    "digest algorithm: sha1",
    "file digest algorithm: sha1",
)
AUTHENTICODE_REVOCATION_SKIP_MARKS = (
    "revocation check skipped",
    "revocation server offline",
    "the revocation function was unable to check revocation",
    "certificate chain was not verified",
    "revocation status unknown",
)
OFFLINE_AUTHENTICODE_PROOF_KEYS = frozenset(
    {
        "argv",
        "shell",
        "exit_code",
        "stdout_sha256",
        "timestamp_verified",
        "digest_algorithm",
        "revocation",
        "owner_authenticode_leaf_sha256",
        "signer_subject",
        "thumbprint",
        "snapshot_sha256",
        "target_id",
        "surface",
    }
)
INNER_AUTHENTICODE_ERROR = (
    "inner PE Authenticode is cryptographically invalid or untrusted"
)
INNER_PAYLOAD_EVIDENCE_PENDING = "PENDING"
INNER_PROOF_EXTRACTOR = "inno-extractor"
INNER_PROOF_CAPTURE = "authenticated-capture"
_SEEN_RECEIPT_NONCES: set[str] = set()
_SEEN_RECEIPT_RUN_IDS: set[str] = set()
_SEEN_UPLOAD_RECEIPT_NONCES: set[str] = set()
_SEEN_UPLOAD_RECEIPT_RUN_IDS: set[str] = set()


class WindowsArtifactGateError(RuntimeError):
    pass


class AuthenticodeCustodyPolicy(NamedTuple):
    leaf_sha256: str
    leaf_der: bytes
    anchor_ders: tuple[bytes, ...]
    intermediate_ders: tuple[bytes, ...]


class InnerPayloadRecord(NamedTuple):
    packed_name: str
    source_path: str
    sha256: str
    size: int


class InstallProofRecord(NamedTuple):
    packed_name: str
    installed_path: str
    payload_type: str
    sha256: str
    size: int
    pe_machine: int | None


class AuthenticatedSnapshot:
    def __init__(
        self,
        origin: pathlib.Path,
        path: pathlib.Path,
        fd: int,
        origin_identity: tuple[int, ...],
        identity: tuple[int, ...],
        digest: str,
        size: int,
        root: pathlib.Path,
    ) -> None:
        self.origin = origin
        self.path = path
        self.fd = fd
        self.origin_identity = origin_identity
        self.identity = identity
        self.digest = digest
        self.size = size
        self.root = root
        self._bytes: bytes | None = None

    def ensure_bound(self) -> None:
        if self.fd < 0:
            raise WindowsArtifactGateError(
                "authenticated Windows snapshot descriptor is closed."
            )
        current = os.fstat(self.fd)
        latest = self.path.lstat()
        if _file_identity(current) != self.identity or _file_identity(latest) != self.identity:
            raise WindowsArtifactGateError(
                "authenticated Windows snapshot identity changed."
            )

    def reject_origin_swap(self) -> None:
        try:
            latest = self.origin.lstat()
        except OSError as exc:
            raise WindowsArtifactGateError(
                "artifact origin was swapped or restored during verification."
            ) from exc
        if _file_identity(latest) != self.origin_identity:
            raise WindowsArtifactGateError(
                "artifact origin was swapped or restored during verification."
            )

    def assert_custody(self) -> None:
        self.ensure_bound()
        self.reject_origin_swap()

    def bytes(self) -> bytes:
        self.ensure_bound()
        if self._bytes is not None:
            return self._bytes
        if self.size > MAX_ARTIFACT_BYTES:
            raise WindowsArtifactGateError(
                "Windows snapshot exceeds the reviewed size ceiling."
            )
        payload = os.pread(self.fd, self.size, 0)
        extra = os.pread(self.fd, 1, self.size)
        if len(payload) != self.size or extra:
            raise WindowsArtifactGateError(
                "authenticated Windows snapshot mutated while it was read."
            )
        digest = hashlib.sha256(payload).hexdigest()
        if digest != self.digest:
            raise WindowsArtifactGateError(
                "authenticated Windows snapshot digest changed."
            )
        self.ensure_bound()
        self._bytes = payload
        return payload

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
        try:
            os.unlink(self.path)
        except OSError:
            pass
        try:
            os.rmdir(self.root)
        except OSError:
            shutil.rmtree(self.root, ignore_errors=True)


def _owner_environment_blocker(message: str) -> WindowsArtifactGateError:
    return WindowsArtifactGateError(f"owner/environment blocker: {message}")


def _reject_test_only_production_pass() -> None:
    if TEST_ONLY is True:
        raise WindowsArtifactGateError(
            "TEST_ONLY Windows gate cannot emit a production pass."
        )


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


def _open_flags(*, write: bool = False, exclusive: bool = False) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC"):
        raise _owner_environment_blocker(
            "descriptor-bound O_NOFOLLOW file open is unavailable"
        )
    flags = os.O_CLOEXEC | os.O_NOFOLLOW
    if write:
        flags |= os.O_RDWR | os.O_CREAT
        if exclusive:
            flags |= os.O_EXCL
        return flags
    return flags | os.O_RDONLY


def _dir_open_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if not directory:
        raise _owner_environment_blocker(
            "descriptor-relative O_DIRECTORY open is unavailable"
        )
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC"):
        raise _owner_environment_blocker(
            "descriptor-bound O_NOFOLLOW file open is unavailable"
        )
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | directory


def _is_symlink_stat(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _openat_child(parent_fd: int, name: str, flags: int) -> int:
    if name in {"", ".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise WindowsArtifactGateError("Windows gate path component is unsafe.")
    try:
        info = os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        raise WindowsArtifactGateError(
            f"Windows gate could not bind path component {name!r}."
        ) from exc
    if _is_symlink_stat(info):
        raise WindowsArtifactGateError(
            f"Windows gate path must not contain a symlink ancestor: {name}"
        )
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        if getattr(exc, "errno", None) in {errno.ELOOP, errno.ENOTDIR}:
            raise WindowsArtifactGateError(
                f"Windows gate path must not contain a symlink ancestor: {name}"
            ) from exc
        raise WindowsArtifactGateError(
            f"Windows gate could not bind path component {name!r}."
        ) from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise WindowsArtifactGateError(
                f"Windows gate path component was replaced: {name}"
            )
        directory = bool(flags & getattr(os, "O_DIRECTORY", 0))
        if directory and not stat.S_ISDIR(opened.st_mode):
            raise WindowsArtifactGateError(
                f"Windows gate path component is not a directory: {name}"
            )
        if not directory and _is_symlink_stat(opened):
            raise WindowsArtifactGateError(
                f"Windows gate path must not contain a symlink ancestor: {name}"
            )
        return fd
    except Exception:
        os.close(fd)
        raise


def _lexical_parts_under(
    root: pathlib.Path, path: pathlib.Path
) -> tuple[str, ...] | None:
    root_abs = os.path.abspath(os.fspath(root))
    path_abs = os.path.abspath(os.fspath(path))
    try:
        relative = os.path.relpath(path_abs, root_abs)
    except ValueError:
        return None
    if relative.startswith("..") or os.path.isabs(relative):
        return None
    if relative in {".", ""}:
        return ()
    posix = relative.replace("\\", "/")
    parts = tuple(pathlib.PurePosixPath(posix).parts)
    if any(
        part in {"", ".", ".."} or "/" in part or "\\" in part or "\x00" in part
        for part in parts
    ):
        return None
    return parts


def _openat_from_root(
    root: pathlib.Path,
    parts: tuple[str, ...],
    *,
    last_directory: bool = False,
) -> int:
    if any(
        part in {"", ".", ".."} or "/" in part or "\\" in part or "\x00" in part
        for part in parts
    ):
        raise WindowsArtifactGateError(
            "Windows gate path must not contain unsafe components."
        )
    try:
        fd = os.open(root, _dir_open_flags())
    except OSError as exc:
        if getattr(exc, "errno", None) in {errno.ELOOP, errno.ENOTDIR}:
            raise WindowsArtifactGateError(
                "Windows gate root must not be a symlink ancestor."
            ) from exc
        raise WindowsArtifactGateError("Windows gate root could not be bound.") from exc
    if not parts:
        if not last_directory:
            os.close(fd)
            raise WindowsArtifactGateError("Windows gate file path is empty.")
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


def _bind_known_file(path: pathlib.Path, label: str) -> int:
    path = pathlib.Path(path)
    seen_roots: list[pathlib.Path] = []
    for root in (ROOT, ORIGIN_ROOT):
        if any(root == prior for prior in seen_roots):
            continue
        seen_roots.append(root)
        parts = _lexical_parts_under(root, path)
        if parts is None:
            continue
        if not parts:
            raise WindowsArtifactGateError(
                f"{label} must be a file, not the tree root."
            )
        return _openat_from_root(root, parts, last_directory=False)
    raise WindowsArtifactGateError(
        f"{label} is outside the bound Windows gate roots."
    )


def _sha256_fd(fd: int, size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    offset = 0
    while remaining:
        block = os.pread(fd, min(READ_CHUNK, remaining), offset)
        if not block:
            raise WindowsArtifactGateError("authenticated snapshot source truncated.")
        digest.update(block)
        offset += len(block)
        remaining -= len(block)
    extra = os.pread(fd, 1, offset)
    if extra:
        raise WindowsArtifactGateError("authenticated snapshot source mutated while hashing.")
    return digest.hexdigest()


def _copy_exclusive(
    source_fd: int,
    destination: pathlib.Path,
    size: int,
    *,
    dir_fd: int | None = None,
    name: str | None = None,
) -> str:
    if dir_fd is not None:
        if name is None or name in {"", ".", ".."} or "/" in name or "\\" in name:
            raise WindowsArtifactGateError("authenticated snapshot destination is unsafe.")
        dest_fd = os.open(
            name, _open_flags(write=True, exclusive=True), 0o400, dir_fd=dir_fd
        )
    else:
        dest_fd = os.open(destination, _open_flags(write=True, exclusive=True), 0o400)
    try:
        os.fchmod(dest_fd, 0o400)
        digest = hashlib.sha256()
        remaining = size
        os.lseek(source_fd, 0, os.SEEK_SET)
        while remaining:
            block = os.read(source_fd, min(READ_CHUNK, remaining))
            if not block:
                raise WindowsArtifactGateError("authenticated snapshot source truncated.")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(dest_fd, view)
                if written <= 0:
                    raise WindowsArtifactGateError("authenticated snapshot write truncated.")
                view = view[written:]
            remaining -= len(block)
        extra = os.read(source_fd, 1)
        if extra:
            raise WindowsArtifactGateError(
                "authenticated snapshot source mutated while copying."
            )
        os.fsync(dest_fd)
        return digest.hexdigest()
    finally:
        os.close(dest_fd)


def _snapshot_directory() -> pathlib.Path:
    artifacts = ROOT / ".artifacts"
    if artifacts.is_dir() and not _is_reparse(artifacts):
        path = pathlib.Path(
            tempfile.mkdtemp(prefix="winsvpn-win-gate-", dir=str(artifacts))
        )
    else:
        path = pathlib.Path(tempfile.mkdtemp(prefix="winsvpn-win-gate-"))
    os.chmod(path, 0o700)
    return path


def snapshot_regular_file(
    origin: pathlib.Path, label: str, *, maximum: int
) -> AuthenticatedSnapshot:
    private = _snapshot_directory()
    snapshot_path = private / "snapshot.bin"
    origin_fd = -1
    dest_fd = -1
    private_fd = -1
    try:
        origin_fd = _bind_known_file(origin, label)
        private_fd = os.open(private, _dir_open_flags())
        before = os.fstat(origin_fd)
        path_before = origin.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum
            or _file_identity(before) != _file_identity(path_before)
        ):
            raise WindowsArtifactGateError(
                f"{label} must be one non-empty, single-link regular file within the size ceiling."
            )
        copied = _copy_exclusive(
            origin_fd,
            snapshot_path,
            before.st_size,
            dir_fd=private_fd,
            name="snapshot.bin",
        )
        dest_fd = _openat_child(private_fd, "snapshot.bin", _open_flags())
        dest_info = os.fstat(dest_fd)
        if copied != _sha256_fd(dest_fd, before.st_size) or dest_info.st_nlink != 1:
            raise WindowsArtifactGateError(
                f"{label} snapshot digest or link identity is invalid."
            )
        after = os.fstat(origin_fd)
        path_after = origin.lstat()
        if _file_identity(before) != _file_identity(after) or _file_identity(
            before
        ) != _file_identity(path_after):
            raise WindowsArtifactGateError(
                f"{label} mutated during authenticated snapshot."
            )
        snapshot = AuthenticatedSnapshot(
            origin=origin,
            path=snapshot_path,
            fd=dest_fd,
            origin_identity=_file_identity(before),
            identity=_file_identity(dest_info),
            digest=copied,
            size=before.st_size,
            root=private,
        )
        dest_fd = -1
        return snapshot
    except Exception:
        if dest_fd >= 0:
            os.close(dest_fd)
        shutil.rmtree(private, ignore_errors=True)
        raise
    finally:
        if origin_fd >= 0:
            os.close(origin_fd)
        if private_fd >= 0:
            os.close(private_fd)


def _module_file_digest(module: ModuleType) -> str | None:
    path = getattr(module, "__file__", None)
    if type(path) is not str or not path:
        return None
    fd = -1
    try:
        fd = _bind_known_file(pathlib.Path(path), "required module snapshot")
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
            return None
        return _sha256_fd(fd, info.st_size)
    except (OSError, WindowsArtifactGateError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _reject_module_poison(public_name: str, expected_digest: str) -> None:
    existing = sys.modules.get(public_name)
    if existing is None:
        return
    actual = _module_file_digest(existing)
    if actual != expected_digest:
        raise WindowsArtifactGateError(
            f"required module {public_name} is poisoned via PYTHONPATH, "
            "sitecustomize, or sys.modules substitution."
        )


_PRIVACY_SNAPSHOTS: list[pathlib.Path] = []


def _cleanup_privacy_snapshots() -> None:
    for path in _PRIVACY_SNAPSHOTS:
        try:
            os.unlink(path)
        except OSError:
            pass


atexit.register(_cleanup_privacy_snapshots)


def _authenticated_privacy_module() -> ModuleType:
    origin = TOOLS_DIR / PRIVACY_MODULE_FILENAME
    origin_fd = -1
    tools_fd = -1
    try:
        origin_fd = _bind_known_file(origin, "privacy module")
        tools_fd = _openat_from_root(ORIGIN_ROOT, ("tools",), last_directory=True)
        before = os.fstat(origin_fd)
        path_before = origin.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_SUPPORT_BYTES
            or _file_identity(before) != _file_identity(path_before)
        ):
            raise WindowsArtifactGateError(
                "privacy module must be one non-empty, single-link regular file."
            )
        digest_before = _sha256_fd(origin_fd, before.st_size)
        _reject_module_poison(PRIVACY_MODULE_NAME, digest_before)
        token = secrets.token_hex(16)
        snapshot_name = f".validate_release_artifact_privacy.winsvpn-mod-{token}.py"
        snapshot = TOOLS_DIR / snapshot_name
        if snapshot.exists() or snapshot.is_symlink():
            raise WindowsArtifactGateError("privacy-module snapshot identity collided.")
        copied = _copy_exclusive(
            origin_fd,
            snapshot,
            before.st_size,
            dir_fd=tools_fd,
            name=snapshot_name,
        )
        _PRIVACY_SNAPSHOTS.append(snapshot)
        snap_fd = _openat_child(tools_fd, snapshot_name, _open_flags())
        try:
            snap_info = os.fstat(snap_fd)
            if (
                copied != digest_before
                or snap_info.st_nlink != 1
                or _sha256_fd(snap_fd, before.st_size) != digest_before
            ):
                raise WindowsArtifactGateError(
                    "privacy module snapshot bytes do not match the origin."
                )
        finally:
            os.close(snap_fd)
        after = os.fstat(origin_fd)
        path_after = origin.lstat()
        if (
            _file_identity(before) != _file_identity(after)
            or _file_identity(before) != _file_identity(path_after)
            or _sha256_fd(origin_fd, before.st_size) != digest_before
        ):
            raise WindowsArtifactGateError(
                "privacy module origin mutated during authenticated load."
            )
    finally:
        if origin_fd >= 0:
            os.close(origin_fd)
        if tools_fd >= 0:
            os.close(tools_fd)
    private_name = f"_winsvpn_windows_gate_{PRIVACY_MODULE_NAME}_{secrets.token_hex(8)}"
    if private_name in sys.modules:
        raise WindowsArtifactGateError("private privacy-module identity collided.")
    spec = importlib.util.spec_from_file_location(private_name, snapshot)
    if spec is None or spec.loader is None:
        raise WindowsArtifactGateError("privacy module could not be loaded from snapshot.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[private_name] = module
    if PRIVACY_MODULE_NAME not in sys.modules:
        sys.modules[PRIVACY_MODULE_NAME] = module
    else:
        _reject_module_poison(PRIVACY_MODULE_NAME, digest_before)
    spec.loader.exec_module(module)
    if getattr(module, "__file__", None) != os.fspath(snapshot):
        raise WindowsArtifactGateError(
            "privacy module snapshot identity changed after import."
        )
    _reject_module_poison(PRIVACY_MODULE_NAME, digest_before)
    return module


def _verify_privacy_of_paths(paths: Sequence[pathlib.Path]) -> None:
    module = _authenticated_privacy_module()
    privacy_error = getattr(module, "PrivacyError", RuntimeError)
    try:
        module.validate_artifacts(tuple(paths), {})
    except privacy_error as exc:
        raise WindowsArtifactGateError(
            f"Windows exact payload privacy verification failed: {exc}"
        ) from exc


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]], label: str
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WindowsArtifactGateError(f"{label} has a duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    return _reject_duplicate_json_keys(pairs, "release identity")


def _load_json_bytes(data: bytes, label: str) -> dict[str, object]:
    if len(data) <= 0 or len(data) > MAX_JSON_BYTES:
        raise WindowsArtifactGateError(
            f"{label} exceeds the reviewed JSON size ceiling."
        )
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=lambda pairs: _reject_duplicate_json_keys(pairs, label),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WindowsArtifactGateError(f"{label} is not valid UTF-8 JSON.") from exc
    if type(document) is not dict:
        raise WindowsArtifactGateError(f"{label} must be one JSON object.")
    return document


def _load_json_object(path: pathlib.Path, label: str) -> dict[str, object]:
    snapshot = snapshot_regular_file(path, label, maximum=MAX_JSON_BYTES)
    try:
        return _load_json_bytes(snapshot.bytes(), label)
    finally:
        snapshot.close()


def _require_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise WindowsArtifactGateError(
            f"{label} must be a JSON boolean; string/number coercion is refused."
        )
    return value


def _require_int(value: object, label: str) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise WindowsArtifactGateError(
            f"{label} must be a JSON integer; bool/string coercion is refused."
        )
    return value


def _require_text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise WindowsArtifactGateError(f"{label} must be a non-empty JSON string.")
    return value


def _require_hex64(value: object, label: str) -> str:
    text = _require_text(value, label)
    if re.fullmatch(r"[0-9a-f]{64}", text) is None:
        raise WindowsArtifactGateError(f"{label} must be a lowercase SHA-256 hex digest.")
    return text


def _standalone_winn3_fact(record: Mapping[str, object]) -> bool:
    standalone = _require_bool(record.get("standalone_winn3"), "standalone_winn3")
    verified = _require_bool(
        record.get("standalone_payload_verified"), "standalone_payload_verified"
    )
    if verified is not standalone:
        raise WindowsArtifactGateError(
            "standalone_payload_verified must match the standalone_winn3 fact."
        )
    return standalone


def _support_payload_architecture(architecture: str) -> str:
    if architecture not in VC_REDIST_BASENAME or architecture not in AMNEZIAWG_MSI_BASENAME:
        raise WindowsArtifactGateError(
            f"unsupported exact Windows support-payload architecture: {architecture}"
        )
    return architecture


def _vc_redist_basename(architecture: str) -> str:
    return VC_REDIST_BASENAME[_support_payload_architecture(architecture)]


def _amneziawg_msi_basename(architecture: str) -> str:
    return AMNEZIAWG_MSI_BASENAME[_support_payload_architecture(architecture)]


def _foreign_support_payload_basenames(architecture: str) -> frozenset[str]:
    architecture = _support_payload_architecture(architecture)
    foreign = set()
    for arch, name in VC_REDIST_BASENAME.items():
        if arch != architecture:
            foreign.add(name)
    for arch, name in AMNEZIAWG_MSI_BASENAME.items():
        if arch != architecture:
            foreign.add(name)
    return frozenset(foreign)


def _required_payload_basenames(
    standalone_winn3: bool,
    architecture: str,
    inventory_names: set[str] | None = None,
) -> frozenset[str]:
    required = set(SHARED_PAYLOAD_BASENAMES)
    required.add(_vc_redist_basename(architecture))
    if not standalone_winn3:
        required |= CLASSICAL_ENGINE_BASENAMES
        required.add(_amneziawg_msi_basename(architecture))
    names = inventory_names or set()
    folded = {name.casefold() for name in names}
    for optional in OPTIONAL_NATIVE_MANIFEST_BASENAMES:
        if optional.casefold() in folded:
            required.add(optional)
    required.add(REQUIRED_PACKED_AOT_PATH)
    return frozenset(required)


def _required_pe_basenames(standalone_winn3: bool, architecture: str) -> frozenset[str]:
    required = _required_payload_basenames(standalone_winn3, architecture)
    excluded = {name.casefold() for name in ALL_VC_REDIST_BASENAMES}
    return frozenset(
        name
        for name in required
        if (name.casefold().endswith(".exe") or name.casefold().endswith(".dll"))
        and name.casefold() not in excluded
    )


def _forbidden_payload_basenames(
    standalone_winn3: bool, architecture: str
) -> frozenset[str]:
    forbidden = set(_foreign_support_payload_basenames(architecture))
    if standalone_winn3:
        forbidden |= CLASSICAL_ENGINE_BASENAMES
        forbidden |= ALL_AMNEZIAWG_MSI_BASENAMES
    return frozenset(forbidden)


def _pe_machine_for_architecture(architecture: str) -> int:
    return {"x64": PE_MACHINE_X64, "arm64": PE_MACHINE_ARM64}[architecture]


def _expected_payload_type(packed_name: str) -> str:
    folded = packed_name.casefold()
    if folded == REQUIRED_PACKED_AOT_PATH.casefold():
        return "aot"
    if folded.endswith(".json"):
        return "json"
    if folded.endswith(".msi"):
        return "file"
    if folded.endswith(".exe") or folded.endswith(".dll"):
        return "pe"
    return "file"


def _is_vc_redist_name(packed_name: str) -> bool:
    return packed_name.casefold() in {name.casefold() for name in ALL_VC_REDIST_BASENAMES}


def _is_amneziawg_msi_name(packed_name: str) -> bool:
    return packed_name.casefold() in {name.casefold() for name in ALL_AMNEZIAWG_MSI_BASENAMES}


def _is_vendor_support_pe_name(packed_name: str) -> bool:
    return packed_name.casefold() in {
        name.casefold() for name in VENDOR_DEBUG_EXCEPTION_PE_BASENAMES
    }


def _vendor_support_pe_pin(packed_name: str, architecture: str) -> str | None:
    folded = packed_name.casefold()
    if folded == _vc_redist_basename(architecture).casefold():
        return VC_REDIST_SHA256[architecture]
    if folded == "wintun.dll":
        return WINTUN_SHA256[architecture]
    return None


def _certificate_cn_values(leaf) -> tuple[str, ...]:
    from cryptography.x509.oid import NameOID

    return tuple(
        attr.value
        for attr in leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if type(attr.value) is str
    )


def _certificate_o_values(leaf) -> tuple[str, ...]:
    from cryptography.x509.oid import NameOID

    return tuple(
        attr.value
        for attr in leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if type(attr.value) is str
    )


def _inspect_inner_pe_debug_sections(
    data: bytes,
) -> tuple[str, tuple[str, ...]] | None:
    try:
        from release_obfuscation_contract import (
            ObfuscationError,
            inspect_native_debug_sections,
        )
    except ImportError:
        try:
            from tools.release_obfuscation_contract import (
                ObfuscationError,
                inspect_native_debug_sections,
            )
        except ImportError as exc:
            raise _owner_environment_blocker(
                "native debug inspection requires release_obfuscation_contract"
            ) from exc
    try:
        return inspect_native_debug_sections(data)
    except ObfuscationError as exc:
        raise WindowsArtifactGateError(
            "inner PE native debug inspection failed."
        ) from exc


def _inner_pe_debug_sections(data: bytes) -> tuple[str, ...]:
    inspected = _inspect_inner_pe_debug_sections(data)
    if inspected is None:
        return ()
    kind, sections = inspected
    if kind != "pe":
        return ()
    return sections


def _is_executable_name(packed_name: str) -> bool:
    folded = packed_name.casefold()
    return folded.endswith((".exe", ".dll", ".sys", ".com", ".scr", ".drv", ".msi"))


def _load_toolchain_pins() -> Mapping[str, str]:
    pin_path = TOOLS_DIR / TOOLCHAIN_PIN_RELATIVE_PATH.name
    snapshot = snapshot_regular_file(
        pin_path, "Windows toolchain pins", maximum=MAX_JSON_BYTES
    )
    try:
        document = _load_json_bytes(snapshot.bytes(), "Windows toolchain pins")
    finally:
        snapshot.close()
    tools = document.get("tools")
    flutter = tools.get("flutter") if type(tools) is dict else None
    if type(flutter) is not dict:
        raise WindowsArtifactGateError("Windows toolchain pins omit Flutter identity.")
    version = _require_text(flutter.get("version"), "toolchain flutter.version")
    revision = _require_text(flutter.get("revision"), "toolchain flutter.revision")
    dart = _require_text(flutter.get("dart_version"), "toolchain flutter.dart_version")
    return {
        "framework_version": version,
        "framework_revision": revision,
        "dart_sdk_version": dart,
    }


def _origin_digest(relative: str, label: str, *, maximum: int) -> str:
    path = _secure_origin_file(relative, label)
    snapshot = snapshot_regular_file(path, label, maximum=maximum)
    try:
        return snapshot.digest
    finally:
        snapshot.close()


def compute_windows_installer_source_closure() -> str:
    declared = tuple(WINDOWS_INSTALLER_SOURCE_PATHS)
    if declared != tuple(sorted(set(declared))):
        raise WindowsArtifactGateError(
            "Windows installer source closure paths must be unique and sorted."
        )
    records: list[dict[str, str]] = []
    for relative in declared:
        digest = _origin_digest(
            relative, f"Windows source {relative}", maximum=MAX_SUPPORT_BYTES
        )
        records.append({"path": relative, "sha256": digest})
    encoded = (
        json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    return _sha256_bytes(encoded)


def _secure_origin_file(raw_path: str, label: str) -> pathlib.Path:
    return _secure_tree_file(ORIGIN_ROOT, raw_path, label)


def _reviewed_windows_release_identity() -> tuple[str, str]:
    identity_path = _secure_repo_file(
        RELEASE_IDENTITY_RELATIVE_PATH.as_posix(), "Windows release identity"
    )
    snapshot = snapshot_regular_file(
        identity_path, "Windows release identity", maximum=MAX_IDENTITY_BYTES
    )
    try:
        identity = _load_json_bytes(snapshot.bytes(), "Windows release identity")
    finally:
        snapshot.close()
    if set(identity) != {
        "schema_version",
        "canonical_release",
        "marketing_version",
        "build_number",
        "platform_mappings",
    }:
        raise WindowsArtifactGateError(
            "Windows release identity top-level schema is not exact."
        )
    marketing = identity.get("marketing_version")
    build = identity.get("build_number")
    mappings = identity.get("platform_mappings")
    windows = mappings.get("windows") if type(mappings) is dict else None
    expected_file_version = (
        f"{marketing}.{build}"
        if type(marketing) is str and type(build) is int and not isinstance(build, bool)
        else None
    )
    if (
        identity.get("schema_version") != 2
        or type(marketing) is not str
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", marketing) is None
        or type(build) is not int
        or isinstance(build, bool)
        or build <= 0
        or build > 65535
        or identity.get("canonical_release") != f"{marketing}+{build}"
        or type(windows) is not dict
        or set(windows) != {"product_version", "four_part_version"}
        or windows.get("product_version") != marketing
        or windows.get("four_part_version") != expected_file_version
    ):
        raise WindowsArtifactGateError(
            "Windows release identity mapping is inconsistent."
        )
    return marketing, expected_file_version


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse(path: pathlib.Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _secure_tree_file(root: pathlib.Path, raw_path: str, label: str) -> pathlib.Path:
    pure = pathlib.PurePosixPath(raw_path)
    if (
        not raw_path
        or "\\" in raw_path
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise WindowsArtifactGateError(
            f"{label} must be one canonical repository-relative path."
        )
    parts = tuple(pure.parts)
    fd = _openat_from_root(root, parts, last_directory=False)
    try:
        info = os.fstat(fd)
        lexical = pathlib.Path(root, *parts)
        try:
            named = lexical.lstat()
        except OSError as exc:
            raise WindowsArtifactGateError(f"{label} is missing.") from exc
        if _file_identity(info) != _file_identity(named):
            raise WindowsArtifactGateError(
                f"{label} was replaced during descriptor-relative open."
            )
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
            raise WindowsArtifactGateError(
                f"{label} must be one non-empty, singly-linked regular file."
            )
        return lexical
    finally:
        os.close(fd)


def _secure_repo_file(raw_path: str, label: str) -> pathlib.Path:
    return _secure_tree_file(ROOT, raw_path, label)


def canonical_artifact(target_id: str, raw_path: str) -> pathlib.Path:
    expected_name = TARGET_FILENAMES.get(target_id)
    if expected_name is None:
        raise WindowsArtifactGateError(
            f"unsupported exact Windows target: {target_id}"
        )
    artifact = _secure_repo_file(raw_path, "Windows installer artifact")
    if artifact.name != expected_name or artifact.suffix.lower() != ".exe":
        raise WindowsArtifactGateError(
            "Windows artifact filename belongs to another exact target."
        )
    bound = _bind_known_file(artifact, "Windows installer artifact")
    try:
        info = os.fstat(bound)
        if info.st_size > MAX_ARTIFACT_BYTES:
            raise WindowsArtifactGateError(
                "Windows artifact exceeds the reviewed size ceiling."
            )
    finally:
        os.close(bound)
    return artifact


def _stable_file(path: pathlib.Path, label: str) -> tuple[int, int, int, int, str]:
    snapshot = snapshot_regular_file(path, label, maximum=MAX_ARTIFACT_BYTES)
    try:
        info = os.fstat(snapshot.fd)
        return (info.st_dev, info.st_ino, snapshot.size, info.st_mtime_ns, snapshot.digest)
    finally:
        snapshot.close()


def _read_u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise WindowsArtifactGateError("truncated PE structure.")
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise WindowsArtifactGateError("truncated PE structure.")
    return struct.unpack_from("<I", data, offset)[0]


def _parse_pe_image(
    name: str,
    data: bytes,
    *,
    expected_machine: int | None,
    require_certificate: bool = True,
) -> dict[str, object]:
    if len(data) < 64 or data[:2] != b"MZ":
        raise WindowsArtifactGateError(f"{name} is not a PE image.")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise WindowsArtifactGateError(f"{name} exceeds the reviewed PE size ceiling.")
    pe = _read_u32(data, 60)
    if pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        raise WindowsArtifactGateError(f"{name} has an invalid PE header.")
    machine = _read_u16(data, pe + 4)
    section_count = _read_u16(data, pe + 6)
    optional_size = _read_u16(data, pe + 20)
    optional = pe + 24
    if optional + optional_size > len(data) or section_count > 96:
        raise WindowsArtifactGateError(f"{name} has a truncated optional header.")
    magic = _read_u16(data, optional)
    if expected_machine is not None and (
        machine != expected_machine or magic != 0x20B
    ):
        expected = {
            PE_MACHINE_X64: "x64",
            PE_MACHINE_ARM64: "arm64",
        }.get(expected_machine, f"machine-0x{expected_machine:04x}")
        raise WindowsArtifactGateError(f"{name} is not PE32+ {expected}.")
    if expected_machine is None and machine not in {
        PE_MACHINE_X86,
        PE_MACHINE_X64,
        PE_MACHINE_ARM64,
    }:
        raise WindowsArtifactGateError(
            f"{name} has an unsupported Inno bootstrap machine."
        )
    directory_base = optional + (112 if magic == 0x20B else 96)
    number_offset = optional + (108 if magic == 0x20B else 92)
    if (
        _read_u32(data, number_offset) < 5
        or directory_base + 40 > optional + optional_size
    ):
        raise WindowsArtifactGateError(f"{name} has no Authenticode directory.")
    resource_rva = _read_u32(data, directory_base + 16)
    resource_size = _read_u32(data, directory_base + 20)
    cert_offset = _read_u32(data, directory_base + 32)
    cert_size = _read_u32(data, directory_base + 36)
    checksum_offset = optional + 64
    security_directory_offset = directory_base + 32
    size_of_headers = _read_u32(data, optional + 60)
    if cert_offset == 0 or cert_size < 8 or cert_offset + cert_size > len(data):
        if require_certificate:
            raise WindowsArtifactGateError(
                f"{name} has no embedded Authenticode signature."
            )
        cert_offset = len(data)
        cert_size = 0
        length = 0
        revision = 0
        cert_type = 0
    else:
        if cert_size > MAX_PKCS7 + 16:
            raise WindowsArtifactGateError(
                f"{name} Authenticode PKCS#7 size bound exceeded."
            )
        length, revision, cert_type = struct.unpack_from("<IHH", data, cert_offset)
        if (
            length < 8
            or length > cert_size
            or revision != 0x0200
            or cert_type != 0x0002
        ):
            raise WindowsArtifactGateError(
                f"{name} has an invalid WIN_CERTIFICATE record."
            )
    if resource_size > MAX_RESOURCE_BYTES:
        raise WindowsArtifactGateError(f"{name} VERSIONINFO resource exceeds the size bound.")
    section_table = optional + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        start = section_table + (index * 40)
        if start + 40 > len(data):
            raise WindowsArtifactGateError(f"{name} has a truncated section table.")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, start + 8
        )
        sections.append((virtual_address, virtual_size, raw_ptr, raw_size))
    return {
        "machine": machine,
        "magic": magic,
        "cert_offset": cert_offset,
        "cert_size": cert_size,
        "cert_length": length,
        "resource_rva": resource_rva,
        "resource_size": resource_size,
        "sections": sections,
        "checksum_offset": checksum_offset,
        "security_directory_offset": security_directory_offset,
        "size_of_headers": size_of_headers,
    }


def _parse_pe_bytes(
    name: str, data: bytes, *, expected_machine: int | None
) -> tuple[int, int, int]:
    parsed = _parse_pe_image(name, data, expected_machine=expected_machine)
    return int(parsed["machine"]), int(parsed["cert_offset"]), int(parsed["cert_size"])


def _der_tlv(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def authenticode_image_digest(
    name: str, data: bytes, *, require_certificate: bool = True
) -> bytes:
    parsed = _parse_pe_image(
        name, data, expected_machine=None, require_certificate=require_certificate
    )
    checksum_offset = int(parsed["checksum_offset"])
    security_directory_offset = int(parsed["security_directory_offset"])
    size_of_headers = int(parsed["size_of_headers"])
    cert_offset = int(parsed["cert_offset"])
    cert_size = int(parsed["cert_size"])
    sections = parsed["sections"]
    if type(sections) is not list:
        raise WindowsArtifactGateError(f"{name} has a truncated section table.")
    if (
        checksum_offset < 0
        or security_directory_offset < checksum_offset + 4
        or checksum_offset + 4 > len(data)
        or security_directory_offset + 8 > len(data)
    ):
        raise WindowsArtifactGateError(f"{name} Authenticode digest coverage is malformed.")
    hasher = hashlib.sha256()
    hasher.update(data[0:checksum_offset])
    hasher.update(data[checksum_offset + 4 : security_directory_offset])
    header_end = size_of_headers
    if header_end < security_directory_offset + 8 or header_end > len(data):
        header_end = security_directory_offset + 8
        hasher.update(b"")
    else:
        hasher.update(data[security_directory_offset + 8 : header_end])
    ordered = sorted(
        (
            (int(raw_ptr), int(raw_size))
            for _virtual_address, _virtual_size, raw_ptr, raw_size in sections
            if type(raw_ptr) is int and type(raw_size) is int
        ),
        key=lambda item: item[0],
    )
    last = header_end
    for raw_ptr, raw_size in ordered:
        if raw_ptr <= 0 or raw_size <= 0:
            continue
        if raw_ptr + raw_size > len(data):
            raise WindowsArtifactGateError(f"{name} Authenticode section is truncated.")
        hasher.update(data[raw_ptr : raw_ptr + raw_size])
        last = max(last, raw_ptr + raw_size)
    extra_end = cert_offset if cert_size else len(data)
    if extra_end > len(data):
        raise WindowsArtifactGateError(f"{name} Authenticode digest coverage is malformed.")
    if last < extra_end:
        hasher.update(data[last:extra_end])
    return hasher.digest()


def _parse_pe(
    path: pathlib.Path, *, expected_machine: int | None
) -> tuple[int, int, int]:
    snapshot = snapshot_regular_file(path, path.name, maximum=MAX_ARTIFACT_BYTES)
    try:
        return _parse_pe_bytes(
            path.name, snapshot.bytes(), expected_machine=expected_machine
        )
    finally:
        snapshot.close()


def _rva_to_offset(data: bytes, rva: int, sections: Sequence[tuple[int, int, int, int]]) -> int:
    for virtual_address, virtual_size, raw_ptr, raw_size in sections:
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            offset = raw_ptr + (rva - virtual_address)
            if offset < 0 or offset > len(data):
                raise WindowsArtifactGateError("PE RVA is outside the image.")
            return offset
    raise WindowsArtifactGateError("PE RVA is not inside a section.")


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
            raise WindowsArtifactGateError("VERSIONINFO string is malformed.")
        chars.append(chr(code))
        if len(chars) > MAX_VERSION_STRING:
            raise WindowsArtifactGateError("VERSIONINFO string exceeds the size bound.")
    raise WindowsArtifactGateError("VERSIONINFO string is truncated.")


def _parse_version_block(data: bytes, offset: int, limit: int) -> dict[str, object]:
    if offset + 6 > limit:
        raise WindowsArtifactGateError("VERSIONINFO resource is truncated.")
    length, value_length, wtype = struct.unpack_from("<HHH", data, offset)
    if length < 6 or offset + length > limit or length > MAX_RESOURCE_BYTES:
        raise WindowsArtifactGateError("VERSIONINFO resource is truncated.")
    end = offset + length
    key, cursor = _read_utf16z(data, offset + 6, end)
    cursor = _align4(cursor)
    value = b""
    if value_length:
        value_bytes = value_length if wtype == 0 else value_length * 2
        if cursor + value_bytes > end:
            raise WindowsArtifactGateError("VERSIONINFO resource is truncated.")
        value = data[cursor : cursor + value_bytes]
        cursor = _align4(cursor + value_bytes)
    children: list[dict[str, object]] = []
    while cursor + 6 <= end:
        if data[cursor : cursor + 6] == b"\x00\x00\x00\x00\x00\x00":
            break
        child_length = struct.unpack_from("<H", data, cursor)[0]
        if child_length < 6:
            break
        children.append(_parse_version_block(data, cursor, end))
        cursor = _align4(cursor + child_length)
    return {"key": key, "type": wtype, "value": value, "children": children}


def _collect_version_strings(block: Mapping[str, object], found: dict[str, str]) -> None:
    wanted = {
        "CompanyName",
        "FileDescription",
        "OriginalFilename",
        "ProductName",
        "ProductVersion",
    }
    key = block["key"]
    if type(key) is str and key in wanted:
        raw = block["value"]
        if type(raw) is not bytes or len(raw) < 2 or len(raw) % 2:
            raise WindowsArtifactGateError(f"VERSIONINFO {key} is empty.")
        text, _ = _read_utf16z(raw + b"\x00\x00", 0, len(raw) + 2)
        text = text.rstrip()
        if not text:
            raise WindowsArtifactGateError(f"VERSIONINFO {key} is empty.")
        if key in found and found[key] != text:
            raise WindowsArtifactGateError(f"VERSIONINFO {key} is ambiguous.")
        found[key] = text
    for child in block["children"]:
        if type(child) is dict:
            _collect_version_strings(child, found)


def _resource_entries(data: bytes, offset: int, limit: int) -> list[tuple[int, bool, int]]:
    if offset + 16 > limit:
        raise WindowsArtifactGateError("VERSIONINFO resource directory is truncated.")
    named, ids = struct.unpack_from("<HH", data, offset + 12)
    total = named + ids
    if total < 1 or total > 64 or offset + 16 + (total * 8) > limit:
        raise WindowsArtifactGateError("VERSIONINFO resource directory is truncated.")
    entries: list[tuple[int, bool, int]] = []
    cursor = offset + 16
    for _ in range(total):
        name, data_offset = struct.unpack_from("<II", data, cursor)
        cursor += 8
        entries.append((name & 0x7FFFFFFF, bool(data_offset & 0x80000000), data_offset & 0x7FFFFFFF))
    return entries


def _fixed_file_version(ms: int, ls: int) -> str:
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def _fixed_product_version(ms: int, ls: int) -> str:
    parts = (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
    if parts[-1] == 0:
        return ".".join(str(value) for value in parts[:-1])
    return ".".join(str(value) for value in parts)


def pe_version_info(
    name: str, data: bytes, *, require_certificate: bool = True
) -> dict[str, str]:
    # require_certificate=False reads VERSIONINFO from an owner-waived unsigned
    # website installer (tools/website_download_custody.py); every other caller
    # keeps the default and still refuses an image without Authenticode.
    parsed = _parse_pe_image(
        name, data, expected_machine=None, require_certificate=require_certificate
    )
    resource_rva = int(parsed["resource_rva"])
    resource_size = int(parsed["resource_size"])
    if resource_rva == 0 or resource_size < 16:
        raise WindowsArtifactGateError(f"{name} has no VERSIONINFO resource.")
    sections = parsed["sections"]
    if type(sections) is not list:
        raise WindowsArtifactGateError(f"{name} has no VERSIONINFO resource.")
    root = _rva_to_offset(data, resource_rva, sections)
    limit = min(len(data), root + resource_size, root + MAX_RESOURCE_BYTES)
    type_entries = _resource_entries(data, root, limit)
    version_dir = None
    for entry_name, is_dir, offset in type_entries:
        if entry_name == RT_VERSION and is_dir:
            version_dir = root + offset
            break
    if version_dir is None:
        raise WindowsArtifactGateError(f"{name} has no VERSIONINFO resource.")
    name_entries = _resource_entries(data, version_dir, limit)
    language_dir = None
    for _entry_name, is_dir, offset in name_entries:
        if is_dir:
            language_dir = root + offset
            break
    if language_dir is None:
        raise WindowsArtifactGateError(f"{name} has no VERSIONINFO resource.")
    language_entries = _resource_entries(data, language_dir, limit)
    data_entry = None
    for _entry_name, is_dir, offset in language_entries:
        if not is_dir:
            data_entry = root + offset
            break
    if data_entry is None or data_entry + 16 > limit:
        raise WindowsArtifactGateError(f"{name} VERSIONINFO resource is truncated.")
    rva, size = struct.unpack_from("<II", data, data_entry)
    if size < 92 or size > MAX_RESOURCE_BYTES:
        raise WindowsArtifactGateError(f"{name} VERSIONINFO resource is truncated.")
    file_offset = _rva_to_offset(data, rva, sections)
    if file_offset + size > len(data):
        raise WindowsArtifactGateError(f"{name} VERSIONINFO resource is truncated.")
    block = _parse_version_block(data, file_offset, file_offset + size)
    if block["key"] != "VS_VERSION_INFO":
        raise WindowsArtifactGateError(f"{name} has no VERSIONINFO resource.")
    value = block["value"]
    if type(value) is not bytes or len(value) < 52 or struct.unpack_from("<I", value, 0)[0] != 0xFEEF04BD:
        raise WindowsArtifactGateError(f"{name} has an invalid fixed VERSIONINFO signature.")
    found: dict[str, str] = {}
    _collect_version_strings(block, found)
    for key in ("CompanyName", "FileDescription", "ProductName", "ProductVersion"):
        if key not in found:
            raise WindowsArtifactGateError(f"{name} VERSIONINFO is missing {key}.")
    product_ms, product_ls = struct.unpack_from("<II", value, 16)
    file_ms, file_ls = struct.unpack_from("<II", value, 8)
    found["FileVersion"] = _fixed_file_version(file_ms, file_ls)
    found["ProductVersion"] = found.get("ProductVersion") or _fixed_product_version(
        product_ms, product_ls
    )
    return found


def _read_windows_pe_versions(path: pathlib.Path) -> Mapping[str, object]:
    snapshot = snapshot_regular_file(path, path.name, maximum=MAX_ARTIFACT_BYTES)
    try:
        versions = pe_version_info(path.name, snapshot.bytes())
    finally:
        snapshot.close()
    return {
        "ProductVersion": versions["ProductVersion"],
        "FileVersion": versions["FileVersion"],
        "FileDescription": versions["FileDescription"],
        "ProductName": versions["ProductName"],
    }


def _der_read(
    blob: bytes, offset: int, *, expected: int | None = None, depth: int = 0
) -> tuple[int, bytes, int]:
    if depth > MAX_DER_DEPTH:
        raise WindowsArtifactGateError("Authenticode PKCS#7 DER nesting is too deep.")
    if offset < 0 or offset >= len(blob):
        raise WindowsArtifactGateError("Authenticode PKCS#7 is truncated.")
    tag = blob[offset]
    if expected is not None and tag != expected:
        raise WindowsArtifactGateError("Authenticode PKCS#7 DER tag mismatch.")
    if tag & 0x1F == 0x1F:
        raise WindowsArtifactGateError("Authenticode PKCS#7 DER tag is malformed.")
    cursor = offset + 1
    if cursor >= len(blob):
        raise WindowsArtifactGateError("Authenticode PKCS#7 is truncated.")
    length_byte = blob[cursor]
    cursor += 1
    if length_byte == 0x80:
        raise WindowsArtifactGateError("Authenticode PKCS#7 indefinite length is refused.")
    if length_byte < 0x80:
        length = length_byte
    else:
        count = length_byte & 0x7F
        if count < 1 or count > 4 or cursor + count > len(blob):
            raise WindowsArtifactGateError("Authenticode PKCS#7 DER length is malformed.")
        if blob[cursor] == 0:
            raise WindowsArtifactGateError("Authenticode PKCS#7 DER length is malformed.")
        length = int.from_bytes(blob[cursor : cursor + count], "big")
        cursor += count
    if length < 0 or length > MAX_PKCS7 or cursor + length > len(blob):
        raise WindowsArtifactGateError("Authenticode PKCS#7 DER length is malformed.")
    return tag, blob[cursor : cursor + length], cursor + length


def _der_full(
    blob: bytes, offset: int, *, expected: int | None = None, depth: int = 0
) -> tuple[bytes, int]:
    _tag, _content, end = _der_read(blob, offset, expected=expected, depth=depth)
    return blob[offset:end], end


def _decode_oid(content: bytes) -> str:
    if not content:
        raise WindowsArtifactGateError("Authenticode PKCS#7 OID is malformed.")
    first = content[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80:
            if value > 1 << 28:
                raise WindowsArtifactGateError("Authenticode PKCS#7 OID is malformed.")
            continue
        parts.append(str(value))
        value = 0
    if content[-1] & 0x80:
        raise WindowsArtifactGateError("Authenticode PKCS#7 OID is malformed.")
    return ".".join(parts)


def _parse_der_integer(content: bytes) -> int:
    if not content or len(content) > 21:
        raise WindowsArtifactGateError("Authenticode PKCS#7 INTEGER is malformed.")
    if content[0] & 0x80:
        raise WindowsArtifactGateError("Authenticode PKCS#7 INTEGER is malformed.")
    if len(content) > 1 and content[0] == 0 and content[1] < 0x80:
        raise WindowsArtifactGateError("Authenticode PKCS#7 INTEGER is malformed.")
    return int.from_bytes(content, "big")


def _parse_certificate_set(content: bytes) -> list[bytes]:
    certificates: list[bytes] = []
    offset = 0
    while offset < len(content):
        if len(certificates) >= MAX_PKCS7_CERTS:
            raise WindowsArtifactGateError(
                "Authenticode PKCS#7 certificate count bound exceeded."
            )
        der, offset = _der_full(content, offset, expected=0x30, depth=2)
        certificates.append(der)
    if not certificates:
        raise WindowsArtifactGateError("Authenticode PKCS#7 contains no certificates.")
    return certificates


def _parse_pkcs7_signer(blob: bytes) -> dict[str, object]:
    if len(blob) > MAX_PKCS7:
        raise WindowsArtifactGateError("Authenticode PKCS#7 size bound exceeded.")
    _tag, content, end = _der_read(blob, 0, expected=0x30)
    if end != len(blob) and blob[end:].strip(b"\x00") != b"":
        padding = blob[end:]
        if any(byte != 0 for byte in padding) or len(padding) > 8:
            raise WindowsArtifactGateError("Authenticode PKCS#7 has trailing data.")
    offset = 0
    _oid_tag, oid_content, offset = _der_read(content, offset, expected=0x06, depth=1)
    if _decode_oid(oid_content) != SIGNED_DATA_OID:
        raise WindowsArtifactGateError("Authenticode PKCS#7 is not signedData.")
    _wrap_tag, signed_wrapper, offset = _der_read(content, offset, expected=0xA0, depth=1)
    if offset != len(content):
        raise WindowsArtifactGateError("Authenticode PKCS#7 has unexpected SignedData siblings.")
    _signed_tag, signed, signed_end = _der_read(signed_wrapper, 0, expected=0x30, depth=2)
    if signed_end != len(signed_wrapper):
        raise WindowsArtifactGateError("Authenticode PKCS#7 SignedData framing is malformed.")
    cursor = 0
    _ver_tag, version, cursor = _der_read(signed, cursor, expected=0x02, depth=3)
    _parse_der_integer(version)
    _algs_tag, _digest_algs, cursor = _der_read(signed, cursor, expected=0x31, depth=3)
    _ci_tag, content_info, cursor = _der_read(signed, cursor, expected=0x30, depth=3)
    ci_cursor = 0
    _ct_tag, content_oid_bytes, ci_cursor = _der_read(
        content_info, ci_cursor, expected=0x06, depth=4
    )
    content_oid = _decode_oid(content_oid_bytes)
    content_bytes = b""
    if ci_cursor < len(content_info):
        _explicit_tag, wrapped, ci_end = _der_read(
            content_info, ci_cursor, expected=0xA0, depth=4
        )
        if ci_end != len(content_info):
            raise WindowsArtifactGateError(
                "Authenticode PKCS#7 ContentInfo is malformed."
            )
        _oct_tag, content_bytes, wrapped_end = _der_read(
            wrapped, 0, expected=0x04, depth=5
        )
        if wrapped_end != len(wrapped):
            raise WindowsArtifactGateError(
                "Authenticode PKCS#7 signed content is malformed."
            )
    certificates_der: list[bytes] = []
    if cursor < len(signed) and signed[cursor] == 0xA0:
        _certs_tag, cert_content, cursor = _der_read(signed, cursor, expected=0xA0, depth=3)
        certificates_der = _parse_certificate_set(cert_content)
    if cursor < len(signed) and signed[cursor] == 0xA1:
        _crl_tag, _crls, cursor = _der_read(signed, cursor, expected=0xA1, depth=3)
    _set_tag, signer_set, cursor = _der_read(signed, cursor, expected=0x31, depth=3)
    if cursor != len(signed):
        raise WindowsArtifactGateError("Authenticode PKCS#7 SignedData has trailing fields.")
    signer_cursor = 0
    _info_tag, signer_info, signer_cursor = _der_read(
        signer_set, signer_cursor, expected=0x30, depth=4
    )
    if signer_cursor != len(signer_set):
        raise WindowsArtifactGateError(
            "Authenticode PKCS#7 must contain exactly one SignerInfo."
        )
    info_cursor = 0
    _sv_tag, _signer_version, info_cursor = _der_read(
        signer_info, info_cursor, expected=0x02, depth=5
    )
    issuer_serial_tlv, info_cursor = _der_full(
        signer_info, info_cursor, expected=0x30, depth=5
    )
    _is_tag, issuer_serial, _is_end = _der_read(issuer_serial_tlv, 0, expected=0x30, depth=6)
    issuer_tlv, serial_offset = _der_full(issuer_serial, 0, expected=0x30, depth=7)
    _serial_tag, serial_content, serial_end = _der_read(
        issuer_serial, serial_offset, expected=0x02, depth=7
    )
    if serial_end != len(issuer_serial):
        raise WindowsArtifactGateError(
            "Authenticode SignerInfo issuer/serial is malformed."
        )
    serial = _parse_der_integer(serial_content)
    _dig_tag, digest_alg, info_cursor = _der_read(
        signer_info, info_cursor, expected=0x30, depth=5
    )
    _da_oid_tag, digest_oid_bytes, digest_alg_end = _der_read(
        digest_alg, 0, expected=0x06, depth=6
    )
    del digest_alg_end
    digest_oid = _decode_oid(digest_oid_bytes)
    authenticated_attributes: bytes | None = None
    if info_cursor < len(signer_info) and signer_info[info_cursor] == 0xA0:
        _attr_tag, attr_content, info_cursor = _der_read(
            signer_info, info_cursor, expected=0xA0, depth=5
        )
        authenticated_attributes = attr_content
    _enc_tag, enc_alg, info_cursor = _der_read(
        signer_info, info_cursor, expected=0x30, depth=5
    )
    _enc_oid_tag, enc_oid_bytes, enc_end = _der_read(enc_alg, 0, expected=0x06, depth=6)
    del enc_end
    encryption_oid = _decode_oid(enc_oid_bytes)
    _sig_tag, signature, info_cursor = _der_read(
        signer_info, info_cursor, expected=0x04, depth=5
    )
    unauthenticated_attributes: bytes | None = None
    if info_cursor < len(signer_info) and signer_info[info_cursor] == 0xA1:
        _ua_tag, unauthenticated_attributes, info_cursor = _der_read(
            signer_info, info_cursor, expected=0xA1, depth=5
        )
    if info_cursor != len(signer_info):
        raise WindowsArtifactGateError("Authenticode SignerInfo has trailing fields.")
    return {
        "certificates": certificates_der,
        "issuer_der": issuer_tlv,
        "serial": serial,
        "content_oid": content_oid,
        "content": content_bytes,
        "digest_oid": digest_oid,
        "encryption_oid": encryption_oid,
        "authenticated_attributes": authenticated_attributes,
        "unauthenticated_attributes": unauthenticated_attributes,
        "signature": signature,
    }


def _load_der_certificate(der: bytes):
    try:
        from cryptography import x509
    except ImportError as exc:
        raise _owner_environment_blocker(
            "Authenticode cryptographic verification requires the cryptography package"
        ) from exc
    if type(der) is not bytes:
        raise WindowsArtifactGateError(
            "Authenticode SignerInfo does not resolve to one signing certificate."
        )
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR) from exc


def _certificate_name_der(name) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    return name.public_bytes(Encoding.DER)


def _certificate_sha256(certificate) -> str:
    from cryptography.hazmat.primitives import hashes

    return certificate.fingerprint(hashes.SHA256()).hex()


def _certificate_thumbprint(certificate) -> str:
    from cryptography.hazmat.primitives import hashes

    return certificate.fingerprint(hashes.SHA1()).hex()


def _certificate_der(certificate) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    return certificate.public_bytes(Encoding.DER)


def _reject_certificate_time(certificate, now: datetime.datetime, error: str) -> None:
    before = certificate.not_valid_before_utc
    after = certificate.not_valid_after_utc
    if before > now or after < now:
        raise WindowsArtifactGateError(error)


def _verify_certificate_signature(certificate, issuer, error: str) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as exc:
        raise _owner_environment_blocker(
            "Authenticode cryptographic verification requires the cryptography package"
        ) from exc
    algorithm = certificate.signature_hash_algorithm
    public_key = issuer.public_key()
    if algorithm is None or not isinstance(public_key, rsa.RSAPublicKey):
        raise WindowsArtifactGateError(error)
    try:
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            algorithm,
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise WindowsArtifactGateError(error) from exc


def _authenticode_pkcs7(name: str, data: bytes) -> bytes:
    parsed = _parse_pe_image(name, data, expected_machine=None)
    cert_offset = int(parsed["cert_offset"])
    cert_length = int(parsed["cert_length"])
    pkcs7 = data[cert_offset + 8 : cert_offset + cert_length]
    if len(pkcs7) > MAX_PKCS7:
        raise WindowsArtifactGateError("Authenticode PKCS#7 size bound exceeded.")
    return pkcs7


def _authenticode_leaf_certificate(
    name: str, data: bytes
) -> tuple[object, bytes, list[bytes], dict[str, object]]:
    pkcs7 = _authenticode_pkcs7(name, data)
    signer = _parse_pkcs7_signer(pkcs7)
    certificates = signer["certificates"]
    if type(certificates) is not list:
        raise WindowsArtifactGateError(
            "Authenticode SignerInfo does not resolve to one signing certificate."
        )
    matches: list[tuple[object, bytes]] = []
    for der in certificates:
        certificate = _load_der_certificate(der)
        issuer_der = _certificate_name_der(certificate.issuer)
        if certificate.serial_number == signer["serial"] and issuer_der == signer["issuer_der"]:
            matches.append((certificate, der))
    if len(matches) != 1:
        raise WindowsArtifactGateError(
            "Authenticode SignerInfo does not resolve to one signing certificate."
        )
    leaf, leaf_der = matches[0]
    if _certificate_name_der(leaf.subject) == _certificate_name_der(leaf.issuer):
        raise WindowsArtifactGateError(
            "self-signed Authenticode leaf is forbidden for production distribution."
        )
    return leaf, leaf_der, certificates, signer


def _verified_issuer(
    certificate, pool: Sequence[object], error: str
):
    issuer_der = _certificate_name_der(certificate.issuer)
    for candidate in pool:
        if _certificate_name_der(candidate.subject) != issuer_der:
            continue
        try:
            _verify_certificate_signature(certificate, candidate, error)
        except WindowsArtifactGateError:
            continue
        return candidate
    return None


def _verified_cert_path(leaf, certificates: Sequence[object], error: str) -> list:
    path = [leaf]
    current = leaf
    seen = {_certificate_sha256(leaf)}
    for _ in range(MAX_PKCS7_CERTS):
        if _certificate_name_der(current.subject) == _certificate_name_der(current.issuer):
            if current is not leaf:
                _verify_certificate_signature(current, current, error)
            break
        issuer = _verified_issuer(current, certificates, error)
        if issuer is None:
            break
        fingerprint = _certificate_sha256(issuer)
        if fingerprint in seen:
            raise WindowsArtifactGateError(error)
        path.append(issuer)
        seen.add(fingerprint)
        current = issuer
    return path


def _verify_chain_to_anchors(
    leaf, pool: Sequence[object], anchor_sha256s: set[str], error: str
) -> None:
    if not anchor_sha256s:
        raise WindowsArtifactGateError(error)
    current = leaf
    seen = {_certificate_sha256(leaf)}
    for _ in range(MAX_PKCS7_CERTS):
        issuer = _verified_issuer(current, pool, error)
        if issuer is None:
            raise WindowsArtifactGateError(error)
        fingerprint = _certificate_sha256(issuer)
        if fingerprint in anchor_sha256s:
            return
        if fingerprint in seen:
            raise WindowsArtifactGateError(error)
        seen.add(fingerprint)
        current = issuer
    raise WindowsArtifactGateError(error)


def authenticode_leaf_identity(name: str, data: bytes) -> dict[str, str]:
    try:
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise _owner_environment_blocker(
            "Authenticode leaf parsing requires the cryptography package"
        ) from exc
    leaf, _leaf_der, _certificates, _signer = _authenticode_leaf_certificate(name, data)
    names = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    orgs = leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if (
        not names
        or not orgs
        or names[0].value != AUTHENTICODE_LEAF_CN
        or orgs[0].value != AUTHENTICODE_LEAF_O
    ):
        raise WindowsArtifactGateError(
            "Authenticode publisher leaf is not the reviewed WIN'S VPN INC. identity."
        )
    return {
        "common_name": AUTHENTICODE_LEAF_CN,
        "organization": AUTHENTICODE_LEAF_O,
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "serial": format(leaf.serial_number, "x"),
        "sha256": _certificate_sha256(leaf),
        "thumbprint": _certificate_thumbprint(leaf),
    }


def authenticode_timestamp_present(name: str, data: bytes) -> bool:
    """True only when Authenticode unauthenticated attributes carry a timestamp."""

    try:
        signer = _parse_pkcs7_signer(_authenticode_pkcs7(name, data))
    except WindowsArtifactGateError:
        return False
    unauth = signer.get("unauthenticated_attributes")
    if type(unauth) is not bytes or not unauth:
        return False
    try:
        values = _pkcs7_attribute_values(unauth)
    except WindowsArtifactGateError:
        return False
    for oid in (
        OID_SPC_RFC3161,
        OID_ID_SMIME_AA_TIMESTAMP_TOKEN,
        OID_PKCS9_COUNTERSIGNATURE,
    ):
        token = values.get(oid)
        if type(token) is bytes and token:
            return True
    return False


def _unwrap_rfc3161_token(raw: bytes) -> bytes:
    if type(raw) is not bytes or not raw:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    if raw[0] == 0x04:
        _tag, inner, end = _der_read(raw, 0, expected=0x04, depth=8)
        if end != len(raw) or type(inner) is not bytes or not inner:
            raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
        return inner
    if raw[0] == 0x30:
        _tag, _content, end = _der_read(raw, 0, expected=0x30, depth=8)
        if end != len(raw):
            raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
        return raw
    raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)


def _tstinfo_message_imprint(content: bytes) -> bytes:
    if type(content) is not bytes or not content:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    payload = content
    if payload[0] == 0x04:
        _tag, payload, end = _der_read(payload, 0, expected=0x04, depth=8)
        if end != len(content) or type(payload) is not bytes or not payload:
            raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    _tag, seq, end = _der_read(payload, 0, expected=0x30, depth=8)
    if end != len(payload):
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    offset = 0
    _ver_tag, _version, offset = _der_read(seq, offset, expected=0x02, depth=9)
    _policy_tag, _policy, offset = _der_read(seq, offset, expected=0x06, depth=9)
    _mi_tag, imprint_seq, offset = _der_read(seq, offset, expected=0x30, depth=9)
    del offset
    _alg_tag, alg, alg_end = _der_read(imprint_seq, 0, expected=0x30, depth=10)
    _oid_tag, oid_bytes, oid_end = _der_read(alg, 0, expected=0x06, depth=11)
    del oid_end
    if _decode_oid(oid_bytes) != OID_SHA256:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    _hash_tag, hashed, hash_end = _der_read(imprint_seq, alg_end, expected=0x04, depth=10)
    if hash_end != len(imprint_seq) or type(hashed) is not bytes or len(hashed) != 32:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    return hashed


def _verify_timestamp_token_signature(token: bytes, authenticode_signature: bytes) -> None:
    if type(token) is not bytes or type(authenticode_signature) is not bytes:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    if not token or not authenticode_signature:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    try:
        signer = _parse_pkcs7_signer(token)
    except WindowsArtifactGateError as exc:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR) from exc
    if signer.get("digest_oid") != OID_SHA256 or signer.get("encryption_oid") != OID_RSA_ENCRYPTION:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    content = signer.get("content")
    signature = signer.get("signature")
    attributes = signer.get("authenticated_attributes")
    certificates = signer.get("certificates")
    if (
        type(content) is not bytes
        or type(signature) is not bytes
        or type(attributes) is not bytes
        or type(certificates) is not list
        or not content
        or not signature
        or not attributes
        or not certificates
    ):
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    values = _pkcs7_attribute_values(attributes)
    raw_digest = values.get(OID_MESSAGE_DIGEST)
    raw_type = values.get(OID_CONTENT_TYPE)
    if type(raw_digest) is not bytes or type(raw_type) is not bytes:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    _md_tag, message_digest, md_end = _der_read(raw_digest, 0, expected=0x04, depth=8)
    if md_end != len(raw_digest) or message_digest != hashlib.sha256(content).digest():
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    _ct_tag, type_oid, ct_end = _der_read(raw_type, 0, expected=0x06, depth=8)
    content_oid = _decode_oid(type_oid)
    if ct_end != len(raw_type) or content_oid not in {OID_DATA, OID_CT_TSTINFO}:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    matches: list[object] = []
    for der in certificates:
        certificate = _load_der_certificate(der)
        issuer_der = _certificate_name_der(certificate.issuer)
        if certificate.serial_number == signer["serial"] and issuer_der == signer["issuer_der"]:
            matches.append(certificate)
    if len(matches) != 1:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    leaf = matches[0]
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as exc:
        raise _owner_environment_blocker(
            "Authenticode cryptographic verification requires the cryptography package"
        ) from exc
    signed_attrs = _der_tlv(0x31, attributes)
    try:
        leaf.public_key().verify(
            signature, signed_attrs, padding.PKCS1v15(), hashes.SHA256()
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR) from exc
    imprint = _tstinfo_message_imprint(content)
    if imprint != hashlib.sha256(authenticode_signature).digest():
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)


def _verify_authenticode_timestamp(name: str, data: bytes) -> None:
    """Require an RFC3161 timestamp cryptographically bound to the signature."""

    try:
        signer = _parse_pkcs7_signer(_authenticode_pkcs7(name, data))
    except WindowsArtifactGateError as exc:
        raise WindowsArtifactGateError(TIMESTAMP_MISSING_ERROR) from exc
    signature = signer.get("signature")
    unauth = signer.get("unauthenticated_attributes")
    if type(signature) is not bytes or not signature:
        raise WindowsArtifactGateError(TIMESTAMP_MISSING_ERROR)
    if type(unauth) is not bytes or not unauth:
        raise WindowsArtifactGateError(TIMESTAMP_MISSING_ERROR)
    try:
        values = _pkcs7_attribute_values(unauth)
    except WindowsArtifactGateError as exc:
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR) from exc
    raw_token = values.get(OID_SPC_RFC3161)
    if type(raw_token) is not bytes or not raw_token:
        raise WindowsArtifactGateError(TIMESTAMP_MISSING_ERROR)
    token = _unwrap_rfc3161_token(raw_token)
    _verify_timestamp_token_signature(token, signature)


def owner_authenticode_pin_blocked() -> bool:
    pin = OWNER_AUTHENTICODE_LEAF_SHA256
    return type(pin) is not str or pin == OWNER_AUTHENTICODE_BLOCKED or re.fullmatch(
        r"[0-9a-f]{64}", pin
    ) is None


def owner_authenticode_signtool_blocked() -> bool:
    pin = OWNER_AUTHENTICODE_SIGNTOOL
    return type(pin) is not str or pin == OWNER_AUTHENTICODE_BLOCKED or not pin


def authenticode_host_is_windows() -> bool:
    return os.name == "nt"


def _require_owner_authenticode_leaf(leaf: Mapping[str, str]) -> None:
    if owner_authenticode_pin_blocked():
        raise _owner_environment_blocker(
            "offline Authenticode owner certificate remains OWNER-BLOCKED: ABSENT"
        )
    if (
        type(leaf) is not dict
        or leaf.get("sha256") != OWNER_AUTHENTICODE_LEAF_SHA256
        or leaf.get("common_name") != AUTHENTICODE_LEAF_CN
        or leaf.get("organization") != AUTHENTICODE_LEAF_O
    ):
        raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR)


def authenticode_verify_argv(tool: str, snapshot_path: str) -> list[str]:
    if type(tool) is not str or not tool or tool == OWNER_AUTHENTICODE_BLOCKED:
        raise _owner_environment_blocker(
            "offline Authenticode signtool remains OWNER-BLOCKED: ABSENT"
        )
    if type(snapshot_path) is not str or not snapshot_path:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    tool_name = pathlib.PurePath(tool).name
    if tool_name.casefold() != AUTHENTICODE_VERIFY_TOOL_NAME:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    argv = [tool, *AUTHENTICODE_VERIFY_ARGV_PREFIX, snapshot_path]
    _require_exact_authenticode_argv(argv, snapshot_path)
    return argv


def _require_exact_authenticode_argv(argv: object, snapshot_path: str) -> list[str]:
    if type(argv) is not list or len(argv) != 7:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    for item in argv:
        if type(item) is not str or not item:
            raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
        folded = item.casefold()
        if "powershell" in folded or "cmd.exe" in folded or "/c" == folded:
            raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
        if "get-authenticodesignature" in folded:
            raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    prefix = tuple(argv[1:6])
    if prefix != AUTHENTICODE_VERIFY_ARGV_PREFIX or argv[6] != snapshot_path:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    if pathlib.PurePath(argv[0]).name.casefold() != AUTHENTICODE_VERIFY_TOOL_NAME:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    if not (
        pathlib.PurePosixPath(argv[0]).is_absolute()
        or pathlib.PureWindowsPath(argv[0]).is_absolute()
    ):
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    if not (
        pathlib.PurePosixPath(argv[6]).is_absolute()
        or pathlib.PureWindowsPath(argv[6]).is_absolute()
    ):
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    return argv


def _authenticode_subprocess_env() -> dict[str, str]:
    system_root = os.environ.get("SystemRoot", "") if os.name == "nt" else ""
    windir = os.environ.get("WINDIR", "") if os.name == "nt" else ""
    path = ""
    if system_root:
        path = str(pathlib.Path(system_root) / "System32")
    return {
        "PATH": path,
        "SystemRoot": system_root,
        "WINDIR": windir,
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _bind_absolute_regular_file(path: pathlib.Path, label: str) -> int:
    if not path.is_absolute():
        raise WindowsArtifactGateError(f"{label} must be an absolute path.")
    try:
        info = path.lstat()
    except OSError as exc:
        raise WindowsArtifactGateError(f"{label} could not be bound.") from exc
    if _is_symlink_stat(info):
        raise WindowsArtifactGateError(f"{label} must not be a symlink or reparse point.")
    try:
        fd = os.open(path, _open_flags())
    except OSError as exc:
        if getattr(exc, "errno", None) in {errno.ELOOP, errno.ENOTDIR}:
            raise WindowsArtifactGateError(
                f"{label} must not be a symlink or reparse point."
            ) from exc
        raise WindowsArtifactGateError(f"{label} could not be bound.") from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise WindowsArtifactGateError(f"{label} was replaced.")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size <= 0:
            raise WindowsArtifactGateError(
                f"{label} must be one non-empty, single-link regular file."
            )
        return fd
    except Exception:
        os.close(fd)
        raise


def _bind_authenticode_signtool() -> tuple[str, tuple[int, ...]]:
    if owner_authenticode_signtool_blocked():
        raise _owner_environment_blocker(
            "offline Authenticode signtool remains OWNER-BLOCKED: ABSENT"
        )
    raw = OWNER_AUTHENTICODE_SIGNTOOL
    path = pathlib.Path(raw)
    if not path.is_absolute():
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    if path.name.casefold() != AUTHENTICODE_VERIFY_TOOL_NAME:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    fd = _bind_absolute_regular_file(path, "Authenticode signtool")
    try:
        info = os.fstat(fd)
        named = path.lstat()
        if _file_identity(info) != _file_identity(named):
            raise WindowsArtifactGateError(
                "Authenticode signtool must be one non-empty, single-link regular file."
            )
        return str(path), _file_identity(info)
    finally:
        os.close(fd)


def _parse_authenticode_verify_output(
    stdout: str,
    stderr: str,
    leaf: Mapping[str, str],
) -> dict[str, str]:
    if type(stdout) is not str or type(stderr) is not str:
        raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR)
    combined = stdout + "\n" + stderr
    stripped = stdout.strip()
    if stripped.startswith("{") and (
        "winverifytrust_status" in stripped
        or WEBSITE_WINVERIFYTRUST_SCHEMA in stripped
        or '"signature_verified"' in stripped
    ):
        raise WindowsArtifactGateError(CALLER_AUTHORED_AUTHENTICODE_JSON_ERROR)
    folded = combined.casefold()
    if AUTHENTICODE_SUCCESS_MARK.casefold() not in folded:
        raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR)
    if not any(mark.casefold() in folded for mark in AUTHENTICODE_TIMESTAMP_MARKS):
        raise WindowsArtifactGateError(TIMESTAMP_UNVERIFIED_ERROR)
    if any(mark in folded for mark in AUTHENTICODE_SHA1_MARKS):
        raise WindowsArtifactGateError(WEAK_DIGEST_ERROR)
    if "sha256" not in folded and "sha-256" not in folded:
        raise WindowsArtifactGateError(WEAK_DIGEST_ERROR)
    if any(mark in folded for mark in AUTHENTICODE_REVOCATION_SKIP_MARKS):
        raise WindowsArtifactGateError(REVOCATION_UNCERTAIN_ERROR)
    if "revocation" not in folded and "chain" not in folded:
        raise WindowsArtifactGateError(REVOCATION_UNCERTAIN_ERROR)
    cn = leaf.get("common_name")
    subject = leaf.get("subject")
    thumbprint = leaf.get("thumbprint")
    if type(cn) is not str or cn.casefold() not in folded:
        raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR)
    if type(subject) is not str or not subject:
        raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR)
    if type(thumbprint) is not str or re.fullmatch(r"[0-9a-f]{40}", thumbprint) is None:
        raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR)
    compact = re.sub(r"[\s:]", "", folded)
    if thumbprint.casefold() not in compact:
        raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR)
    return {
        "digest_algorithm": "sha256",
        "revocation": "checked",
        "thumbprint": thumbprint,
    }


def _run_authenticode_verify(
    argv: list[str], snapshot: AuthenticatedSnapshot
) -> subprocess.CompletedProcess[str]:
    _require_exact_authenticode_argv(argv, str(snapshot.path))
    snapshot.ensure_bound()
    try:
        completed = subprocess.run(
            argv,
            cwd=str(snapshot.root),
            env=_authenticode_subprocess_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            shell=False,
            check=False,
            timeout=90,
        )
    except subprocess.TimeoutExpired as exc:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR) from exc
    except OSError as exc:
        raise _owner_environment_blocker(
            "offline Authenticode trust verification requires the disposable "
            "Windows verification host"
        ) from exc
    snapshot.assert_custody()
    return completed


def _require_offline_authenticode_proof(
    proof: object,
    leaf: Mapping[str, str],
    *,
    target_id: str,
    snapshot_sha256: str,
) -> None:
    if type(proof) is not dict:
        raise WindowsArtifactGateError(OUTER_SIGNATURE_SKIP_ERROR)
    if "winverifytrust_status" in proof:
        raise WindowsArtifactGateError(CALLER_AUTHORED_AUTHENTICODE_JSON_ERROR)
    if set(proof) != OFFLINE_AUTHENTICODE_PROOF_KEYS:
        raise WindowsArtifactGateError(OUTER_SIGNATURE_SKIP_ERROR)
    argv = proof.get("argv")
    if proof.get("shell") is not False:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    if type(argv) is not list:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    if len(argv) != 7:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    bound_argv = _require_exact_authenticode_argv(list(argv), str(argv[6]))
    if owner_authenticode_signtool_blocked():
        raise _owner_environment_blocker(
            "offline Authenticode signtool remains OWNER-BLOCKED: ABSENT"
        )
    if bound_argv[0] != OWNER_AUTHENTICODE_SIGNTOOL:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    expected_surface = TARGET_SURFACES.get(target_id)
    if expected_surface is None:
        raise WindowsArtifactGateError(
            f"unsupported exact Windows target: {target_id}"
        )
    if proof.get("target_id") != target_id:
        raise WindowsArtifactGateError(
            "Authenticode evidence belongs to another exact target."
        )
    if (
        proof.get("surface") != expected_surface
        or (
            expected_surface == "partner-center"
            and proof.get("surface") == "website"
        )
    ):
        if expected_surface == "partner-center":
            raise WindowsArtifactGateError(WEBSITE_SIGNING_AS_PARTNER_CENTER_ERROR)
        raise WindowsArtifactGateError(
            "Authenticode evidence belongs to another exact target."
        )
    if (
        proof.get("exit_code") != 0
        or proof.get("timestamp_verified") is not True
        or proof.get("digest_algorithm") != "sha256"
        or proof.get("revocation") != "checked"
        or proof.get("owner_authenticode_leaf_sha256") != leaf.get("sha256")
        or proof.get("signer_subject") != leaf.get("subject")
        or proof.get("thumbprint") != leaf.get("thumbprint")
        or proof.get("snapshot_sha256") != snapshot_sha256
    ):
        raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR)
    stdout_digest = proof.get("stdout_sha256")
    if type(stdout_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", stdout_digest) is None:
        raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR)
    _require_owner_authenticode_leaf(leaf)


def authenticode_custody_policy(
    name: str, data: bytes, authenticated_leaf: Mapping[str, str]
) -> AuthenticodeCustodyPolicy:
    """Bind inner PE trust to the authenticated outer signer chain, not CN/O."""

    leaf, leaf_der, certificates_der, _signer = _authenticode_leaf_certificate(name, data)
    leaf_sha256 = _certificate_sha256(leaf)
    if (
        type(authenticated_leaf) is not dict
        or authenticated_leaf.get("sha256") != leaf_sha256
        or type(leaf_der) is not bytes
        or not leaf_der
    ):
        raise WindowsArtifactGateError(
            "Authenticode custody policy does not match the authenticated outer leaf."
        )
    pool = [_load_der_certificate(der) for der in certificates_der]
    path = _verified_cert_path(leaf, pool, INNER_AUTHENTICODE_ERROR)
    now = datetime.datetime.now(datetime.timezone.utc)
    _reject_certificate_time(leaf, now, INNER_AUTHENTICODE_ERROR)
    if len(path) < 2:
        raise WindowsArtifactGateError(
            "Authenticode custody policy has no verified issuer/anchor."
        )
    for certificate in path:
        _reject_certificate_time(certificate, now, INNER_AUTHENTICODE_ERROR)
    return AuthenticodeCustodyPolicy(
        leaf_sha256=leaf_sha256,
        leaf_der=leaf_der,
        anchor_ders=(_certificate_der(path[-1]),),
        intermediate_ders=tuple(_certificate_der(item) for item in path[1:-1]),
    )


def _require_custody_policy(
    custody_policy: AuthenticodeCustodyPolicy,
) -> AuthenticodeCustodyPolicy:
    if type(custody_policy) is not AuthenticodeCustodyPolicy:
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    if (
        type(custody_policy.leaf_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", custody_policy.leaf_sha256) is None
        or type(custody_policy.leaf_der) is not bytes
        or not custody_policy.leaf_der
        or type(custody_policy.anchor_ders) is not tuple
        or type(custody_policy.intermediate_ders) is not tuple
        or len(custody_policy.anchor_ders) < 1
        or len(custody_policy.anchor_ders) > MAX_PKCS7_CERTS
        or len(custody_policy.intermediate_ders) > MAX_PKCS7_CERTS
    ):
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    for der in custody_policy.anchor_ders + custody_policy.intermediate_ders:
        if type(der) is not bytes or not der or len(der) > MAX_PKCS7:
            raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    return custody_policy


def _pkcs7_attribute_values(attr_content: bytes) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    offset = 0
    while offset < len(attr_content):
        _tag, seq, offset = _der_read(attr_content, offset, expected=0x30, depth=6)
        _oid_tag, oid_bytes, seq_off = _der_read(seq, 0, expected=0x06, depth=7)
        oid = _decode_oid(oid_bytes)
        _set_tag, set_content, seq_end = _der_read(seq, seq_off, expected=0x31, depth=7)
        if seq_end != len(seq):
            raise WindowsArtifactGateError(
                "Authenticode authenticated attribute is malformed."
            )
        if oid in found:
            raise WindowsArtifactGateError(
                "Authenticode authenticated attribute is duplicated."
            )
        found[oid] = set_content
    return found


def _verify_pe_image_signature(
    name: str, data: bytes
) -> tuple[object, bytes, list[bytes], dict[str, object]]:
    leaf, leaf_der, certificates_der, signer = _authenticode_leaf_certificate(name, data)
    if (
        signer.get("content_oid") != OID_DATA
        or signer.get("digest_oid") != OID_SHA256
        or signer.get("encryption_oid") != OID_RSA_ENCRYPTION
    ):
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    content = signer.get("content")
    signature = signer.get("signature")
    attributes = signer.get("authenticated_attributes")
    if (
        type(content) is not bytes
        or type(signature) is not bytes
        or type(attributes) is not bytes
        or not signature
        or not attributes
    ):
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    image_digest = authenticode_image_digest(name, data)
    if content != image_digest or len(content) != 32:
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    values = _pkcs7_attribute_values(attributes)
    raw_digest = values.get(OID_MESSAGE_DIGEST)
    raw_type = values.get(OID_CONTENT_TYPE)
    if type(raw_digest) is not bytes or type(raw_type) is not bytes:
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    _md_tag, message_digest, md_end = _der_read(raw_digest, 0, expected=0x04, depth=8)
    if md_end != len(raw_digest) or message_digest != hashlib.sha256(content).digest():
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    _ct_tag, type_oid, ct_end = _der_read(raw_type, 0, expected=0x06, depth=8)
    if ct_end != len(raw_type) or _decode_oid(type_oid) != OID_DATA:
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as exc:
        raise _owner_environment_blocker(
            "Authenticode cryptographic verification requires the cryptography package"
        ) from exc
    signed_attrs = _der_tlv(0x31, attributes)
    try:
        leaf.public_key().verify(
            signature, signed_attrs, padding.PKCS1v15(), hashes.SHA256()
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR) from exc
    now = datetime.datetime.now(datetime.timezone.utc)
    _reject_certificate_time(leaf, now, INNER_AUTHENTICODE_ERROR)
    return leaf, leaf_der, certificates_der, signer


def _verify_inner_pe_authenticode(
    name: str, data: bytes, custody_policy: AuthenticodeCustodyPolicy
) -> dict[str, str]:
    policy = _require_custody_policy(custody_policy)
    leaf, leaf_der, certificates_der, _signer = _verify_pe_image_signature(name, data)
    if leaf_der != policy.leaf_der or _certificate_sha256(leaf) != policy.leaf_sha256:
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    now = datetime.datetime.now(datetime.timezone.utc)
    if not policy.anchor_ders:
        raise WindowsArtifactGateError(INNER_AUTHENTICODE_ERROR)
    inner_pool = [_load_der_certificate(der) for der in certificates_der]
    anchors = [_load_der_certificate(der) for der in policy.anchor_ders]
    intermediates = [_load_der_certificate(der) for der in policy.intermediate_ders]
    for certificate in anchors + intermediates:
        _reject_certificate_time(certificate, now, INNER_AUTHENTICODE_ERROR)
    pool = inner_pool + intermediates + anchors
    _verify_chain_to_anchors(
        leaf,
        pool,
        {_certificate_sha256(item) for item in anchors},
        INNER_AUTHENTICODE_ERROR,
    )
    return {
        "sha256": policy.leaf_sha256,
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "serial": format(leaf.serial_number, "x"),
    }


def _vendor_redistributable_publisher_bound(packed_name: str, leaf) -> bool:
    cns = _certificate_cn_values(leaf)
    orgs = _certificate_o_values(leaf)
    folded = packed_name.casefold()
    if folded in {name.casefold() for name in ALL_VC_REDIST_BASENAMES}:
        return VC_REDIST_PUBLISHER_CN in cns
    if folded == "wintun.dll":
        return WINTUN_PUBLISHER_O in orgs
    return False


def _verify_vendor_redistributable_pe(
    packed_name: str, data: bytes, architecture: str
) -> dict[str, str]:
    if _is_vc_redist_name(packed_name) and packed_name.casefold() != _vc_redist_basename(
        architecture
    ).casefold():
        raise WindowsArtifactGateError(
            f"wrong-architecture Windows support payload: {packed_name.casefold()}"
        )
    if _is_vc_redist_name(packed_name) and len(data) > MAX_VC_REDIST_BYTES:
        raise WindowsArtifactGateError(
            f"packed {packed_name} exceeds the reviewed VC_redist size ceiling."
        )
    _parse_pe_bytes(packed_name, data, expected_machine=None)
    leaf, _leaf_der, _certs, _signer = _verify_pe_image_signature(packed_name, data)
    if not _vendor_redistributable_publisher_bound(packed_name, leaf):
        raise WindowsArtifactGateError(
            f"packed {packed_name} Authenticode publisher is not the reviewed vendor identity."
        )
    if _is_vc_redist_name(packed_name):
        versions = pe_version_info(packed_name, data)
        expected_name = _vc_redist_basename(architecture)
        if versions.get("OriginalFilename") != expected_name:
            raise WindowsArtifactGateError(
                f"{packed_name} OriginalFilename is not the reviewed {architecture} VC_redist."
            )
        if (
            versions.get("FileVersion") != VC_REDIST_VERSION
            or versions.get("ProductVersion") != VC_REDIST_VERSION
            or versions.get("ProductName") != VC_REDIST_PRODUCT_NAME[architecture]
        ):
            raise WindowsArtifactGateError(
                f"{packed_name} version identity is not the reviewed {VC_REDIST_VERSION} {architecture} package."
            )
    return {
        "sha256": _certificate_sha256(leaf),
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "serial": format(leaf.serial_number, "x"),
    }


def _vendor_debug_metadata_exception_allowed(
    packed_name: str, data: bytes, architecture: str
) -> bool:
    if not _is_vendor_support_pe_name(packed_name):
        return False
    expected = _vendor_support_pe_pin(packed_name, architecture)
    if expected is None or _sha256_bytes(data) != expected:
        return False
    try:
        leaf, _leaf_der, _certs, _signer = _verify_pe_image_signature(packed_name, data)
    except WindowsArtifactGateError:
        return False
    return _vendor_redistributable_publisher_bound(packed_name, leaf)


def _reject_inner_pe_debug_metadata(
    packed_name: str, data: bytes, architecture: str
) -> None:
    sections = _inner_pe_debug_sections(data)
    if not sections:
        return
    if _vendor_debug_metadata_exception_allowed(packed_name, data, architecture):
        return
    raise WindowsArtifactGateError(
        f"packed {packed_name} retains native debug metadata. "
        "Signed vendor redistributables may keep vendor debug metadata only when "
        "the exact reviewed hash and publisher are bound; vendor bytes are never stripped."
    )


def _verify_amneziawg_msi_payload(
    packed_name: str,
    data: bytes,
    architecture: str,
    *,
    require_reviewed_hash: bool,
) -> None:
    expected_name = _amneziawg_msi_basename(architecture)
    if packed_name.casefold() != expected_name.casefold():
        raise WindowsArtifactGateError(
            f"packed {packed_name} is not the reviewed {architecture} AmneziaWG MSI."
        )
    if len(data) > MAX_AMNEZIAWG_MSI_BYTES:
        raise WindowsArtifactGateError(
            f"packed {packed_name} exceeds the reviewed AmneziaWG MSI size ceiling."
        )
    if not data.startswith(MSI_OLE_MAGIC):
        raise WindowsArtifactGateError(
            f"packed {packed_name} is not an OLE compound MSI payload."
        )
    publisher_utf16 = AMNEZIAWG_MSI_PUBLISHER_O.encode("utf-16-le")
    if publisher_utf16 not in data and AMNEZIAWG_MSI_PUBLISHER_O.encode("ascii") not in data:
        raise WindowsArtifactGateError(
            f"packed {packed_name} is not publisher-bound to {AMNEZIAWG_MSI_PUBLISHER_O}."
        )
    if require_reviewed_hash and _sha256_bytes(data) != AMNEZIAWG_MSI_SHA256[architecture]:
        raise WindowsArtifactGateError(
            f"packed {packed_name} is not the reviewed {architecture} AmneziaWG MSI."
        )


def _verify_outer_pe_authenticode(
    name: str, data: bytes, custody_policy: AuthenticodeCustodyPolicy
) -> dict[str, str]:
    try:
        identity = _verify_inner_pe_authenticode(name, data, custody_policy)
    except WindowsArtifactGateError as exc:
        text = str(exc)
        if text == INNER_AUTHENTICODE_ERROR or "Authenticode PKCS#7" in text:
            raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR) from exc
        raise
    _verify_authenticode_timestamp(name, data)
    return identity


def _verify_authenticode_offline(
    path: pathlib.Path,
    snapshot: AuthenticatedSnapshot | None = None,
    *,
    target_id: str | None = None,
    leaf: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Run exact non-shell signtool argv against one bound installer snapshot."""

    del path
    if not authenticode_host_is_windows():
        raise _owner_environment_blocker(
            "offline Authenticode trust verification requires the disposable "
            "Windows verification host"
        )
    if type(target_id) is not str or target_id not in TARGET_FILENAMES:
        raise WindowsArtifactGateError(
            f"unsupported exact Windows target: {target_id}"
        )
    if snapshot is None or type(leaf) is not dict:
        raise WindowsArtifactGateError(AUTHENTICODE_ARGV_ERROR)
    snapshot.assert_custody()
    tool, tool_identity = _bind_authenticode_signtool()
    argv = authenticode_verify_argv(tool, str(snapshot.path))
    completed = _run_authenticode_verify(argv, snapshot)
    rebound = _bind_absolute_regular_file(pathlib.Path(tool), "Authenticode signtool")
    try:
        if _file_identity(os.fstat(rebound)) != tool_identity:
            raise WindowsArtifactGateError(
                "Authenticode signtool was replaced during verification."
            )
    finally:
        os.close(rebound)
    if completed.returncode != 0:
        raise WindowsArtifactGateError(OUTER_AUTHENTICODE_ERROR)
    parsed = _parse_authenticode_verify_output(
        completed.stdout or "", completed.stderr or "", leaf
    )
    snapshot.assert_custody()
    return {
        "argv": list(argv),
        "shell": False,
        "exit_code": int(completed.returncode),
        "stdout_sha256": _sha256_bytes((completed.stdout or "").encode("utf-8")),
        "timestamp_verified": True,
        "digest_algorithm": parsed["digest_algorithm"],
        "revocation": parsed["revocation"],
        "owner_authenticode_leaf_sha256": leaf["sha256"],
        "signer_subject": leaf["subject"],
        "thumbprint": parsed["thumbprint"],
        "snapshot_sha256": snapshot.digest,
        "target_id": target_id,
        "surface": TARGET_SURFACES[target_id],
    }


def _exact_mapping(
    value: object, keys: set[str], label: str
) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise WindowsArtifactGateError(f"{label} does not have its exact schema.")
    return value


def _manifest_path(artifact: pathlib.Path) -> pathlib.Path:
    relative = (
        artifact.relative_to(ROOT.resolve(strict=True)).as_posix()
        + ".payload-manifest.json"
    )
    return _secure_repo_file(relative, "Windows payload manifest")


def _payload_inventory(
    record: Mapping[str, object],
) -> list[InnerPayloadRecord]:
    raw_payload = record.get("payload")
    if type(raw_payload) is not list or not raw_payload:
        raise WindowsArtifactGateError(
            "Windows payload manifest has no payload inventory."
        )
    if len(raw_payload) > MAX_INNER_ENTRIES:
        raise WindowsArtifactGateError(
            "Windows payload inventory exceeds the reviewed entry-count ceiling."
        )
    inventory: list[InnerPayloadRecord] = []
    seen_paths: set[str] = set()
    seen_packed: set[str] = set()
    aggregate = 0
    for raw_entry in raw_payload:
        entry = _exact_mapping(
            raw_entry,
            {"path", "size", "sha256"},
            "Windows payload entry",
        )
        raw_path = entry.get("path")
        size = _require_int(entry.get("size"), "Windows payload entry size")
        digest = _require_hex64(entry.get("sha256"), "Windows payload entry sha256")
        if type(raw_path) is not str or raw_path in seen_paths or size <= 0:
            raise WindowsArtifactGateError(
                "Windows payload entry is malformed or duplicated."
            )
        if size > MAX_INNER_FILE_BYTES:
            raise WindowsArtifactGateError(
                f"Windows payload entry {raw_path} exceeds the reviewed per-file size ceiling."
            )
        aggregate += size
        if aggregate > MAX_AGGREGATE_INNER_BYTES:
            raise WindowsArtifactGateError(
                "Windows payload inventory exceeds the reviewed aggregate size ceiling."
            )
        packed_name = _packed_inner_name(raw_path)
        packed_key = packed_name.casefold()
        if packed_key in seen_packed:
            raise WindowsArtifactGateError(
                f"Windows payload inventory has a duplicated packed name: {packed_name}"
            )
        _reject_private_symbol_name(raw_path)
        _reject_private_symbol_name(packed_name)
        seen_paths.add(raw_path)
        seen_packed.add(packed_key)
        if digest in WITHDRAWN_MULLVAD_SHA256:
            raise WindowsArtifactGateError(
                "withdrawn Mullvad payload bytes are present, including when renamed."
            )
        suffix = pathlib.PurePosixPath(raw_path).suffix.casefold()
        if "mullvad" in raw_path.casefold() or suffix in {".sys", ".cat", ".inf"}:
            raise WindowsArtifactGateError(
                f"withdrawn Windows driver payload is forbidden: {raw_path}"
            )
        inventory.append(
            InnerPayloadRecord(
                packed_name=packed_name,
                source_path=raw_path,
                sha256=digest,
                size=size,
            )
        )
    return inventory


def _reject_hidden_payload_path(raw_path: str, label: str) -> None:
    posix = pathlib.PurePosixPath(raw_path.replace("\\", "/"))
    if any(part.startswith(".") and part not in {".", ".."} for part in posix.parts):
        raise WindowsArtifactGateError(f"{label} contains a hidden file: {raw_path}")


def _packed_inner_name(raw_path: str) -> str:
    posix = pathlib.PurePosixPath(raw_path)
    if (
        not raw_path
        or "\\" in raw_path
        or posix.is_absolute()
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise WindowsArtifactGateError(
            "Windows payload entry must be one canonical repository-relative path."
        )
    _reject_hidden_payload_path(raw_path, "Windows payload entry")
    if raw_path == REQUIRED_PACKED_AOT_PATH or raw_path.endswith(
        "/" + REQUIRED_PACKED_AOT_PATH
    ):
        return REQUIRED_PACKED_AOT_PATH
    return posix.name


def _find_unique_record(
    inventory: Sequence[InnerPayloadRecord], packed_name: str
) -> InnerPayloadRecord:
    matches = [
        item
        for item in inventory
        if item.packed_name.casefold() == packed_name.casefold()
    ]
    if len(matches) != 1:
        raise WindowsArtifactGateError(
            f"Windows package requires exactly one {packed_name}."
        )
    return matches[0]


def _find_extracted(extracted: Mapping[str, bytes], packed_name: str) -> bytes:
    matches = [
        blob
        for name, blob in extracted.items()
        if name.casefold() == packed_name.casefold()
    ]
    if len(matches) != 1:
        raise WindowsArtifactGateError(
            f"packed Windows installer is missing exact inner payload {packed_name}."
        )
    return matches[0]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject_private_symbol_name(raw_path: str) -> None:
    folded = raw_path.replace("\\", "/").casefold()
    basename = pathlib.PurePosixPath(folded).name
    if basename.endswith(PACKAGED_PRIVATE_SYMBOL_SUFFIXES):
        raise WindowsArtifactGateError(
            f"packed Windows installer contains a private symbol file: {raw_path}"
        )


def _reject_packaged_private_symbols(packed_name: str, data: bytes) -> None:
    _reject_private_symbol_name(packed_name)
    if SOURCE_MAP_REFERENCE_RE.search(data):
        raise WindowsArtifactGateError(
            f"packed {packed_name} contains a source-map reference."
        )


def extract_packed_inner_payloads(artifact: pathlib.Path) -> dict[str, bytes]:
    """Return packed inner files from the exact installer bytes.

    This tree has no reviewed Inno extractor. PATH tools and running the
    installer are forbidden.
    """

    del artifact
    raise WindowsArtifactGateError(INNO_INNER_EXTRACTOR_ERROR)


def authenticated_windows_install_run_capture(
    snapshot: AuthenticatedSnapshot,
) -> Mapping[str, object]:
    """Consume one descriptor-bound installer snapshot and emit a receipt.

    A reviewed Windows capture must bind the returned execution receipt to the
    snapshot digest, Authenticode leaf, target, and source closure. This host
    has no such capture.
    """

    snapshot.assert_custody()
    raise WindowsArtifactGateError(AUTHENTICATED_CAPTURE_ERROR)


def _execution_receipt_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _execution_receipt_public_key_bytes() -> bytes:
    raw = bytes.fromhex(EXECUTION_RECEIPT_ISSUER_PUBLIC_KEY_HEX)
    if len(raw) != 32:
        raise WindowsArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    return raw


def _require_utc_timestamp(value: object, label: str) -> datetime.datetime:
    text = _require_text(value, label)
    try:
        parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WindowsArtifactGateError(f"{label} is not an RFC3339 UTC timestamp.") from exc
    if parsed.tzinfo is None:
        raise WindowsArtifactGateError(f"{label} is not an RFC3339 UTC timestamp.")
    return parsed.astimezone(datetime.timezone.utc)


def _execution_receipt_canonical_bytes(
    record: Mapping[str, object], inner_digests: Mapping[str, str]
) -> bytes:
    payload = {
        "schema": record.get("schema"),
        "authenticated": True,
        "issuer": record.get("issuer"),
        "run_id": record.get("run_id"),
        "nonce": record.get("nonce"),
        "issued_at": record.get("issued_at"),
        "target_id": record.get("target_id"),
        "target_architecture": record.get("target_architecture"),
        "installer_sha256": record.get("installer_sha256"),
        "installer_size": record.get("installer_size"),
        "authenticode_leaf_sha256": record.get("authenticode_leaf_sha256"),
        "build_transaction": record.get("build_transaction"),
        "inner_payload_digests": dict(inner_digests),
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _verify_execution_receipt_signature(
    record: Mapping[str, object], canonical: bytes
) -> None:
    signature_hex = _require_text(record.get("signature"), "execution receipt signature")
    if re.fullmatch(r"[0-9a-f]{128}", signature_hex) is None:
        raise WindowsArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise _owner_environment_blocker(
            "Windows execution receipt authentication requires the cryptography package"
        ) from exc
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            _execution_receipt_public_key_bytes()
        )
        public_key.verify(bytes.fromhex(signature_hex), canonical)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise WindowsArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR) from exc


def _bind_execution_receipt(
    snapshot: AuthenticatedSnapshot,
    leaf: Mapping[str, str],
    receipt: Mapping[str, object],
    target_id: str,
    architecture: str,
    source_closure: str,
) -> dict[str, bytes]:
    snapshot.assert_custody()
    record = _exact_mapping(receipt, EXECUTION_RECEIPT_KEYS, "Windows execution receipt")
    if record.get("schema") != EXECUTION_RECEIPT_SCHEMA:
        raise WindowsArtifactGateError(
            "Windows execution receipt schema is not the authenticated install-run contract."
        )
    if _require_bool(record.get("authenticated"), "execution receipt authenticated") is not True:
        raise WindowsArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    if _require_text(record.get("issuer"), "execution receipt issuer") != EXECUTION_RECEIPT_ISSUER:
        raise WindowsArtifactGateError(RECEIPT_UNAUTHENTICATED_ERROR)
    run_id = _require_hex64(record.get("run_id"), "execution receipt run_id")
    nonce = _require_hex64(record.get("nonce"), "execution receipt nonce")
    issued_at = _require_utc_timestamp(record.get("issued_at"), "execution receipt issued_at")
    now = _execution_receipt_now()
    age = (now - issued_at).total_seconds()
    if age > EXECUTION_RECEIPT_MAX_AGE_SECONDS or age < -EXECUTION_RECEIPT_FUTURE_SKEW_SECONDS:
        raise WindowsArtifactGateError(RECEIPT_STALE_ERROR)
    if nonce in _SEEN_RECEIPT_NONCES or run_id in _SEEN_RECEIPT_RUN_IDS:
        raise WindowsArtifactGateError(RECEIPT_REPLAY_ERROR)
    receipt_target = _require_text(record.get("target_id"), "execution receipt target_id")
    receipt_architecture = _require_text(
        record.get("target_architecture"), "execution receipt target_architecture"
    )
    if receipt_target != target_id or receipt_architecture != architecture:
        raise WindowsArtifactGateError(RECEIPT_REUSE_ERROR)
    if receipt_architecture != TARGET_ARCHITECTURES[target_id]:
        raise WindowsArtifactGateError(RECEIPT_REUSE_ERROR)
    if (
        record.get("installer_sha256") != snapshot.digest
        or _require_int(record.get("installer_size"), "execution receipt installer_size")
        != snapshot.size
        or record.get("authenticode_leaf_sha256") != leaf.get("sha256")
    ):
        raise WindowsArtifactGateError(
            "Windows execution receipt is not tied to the snapshot digest, size, and signer."
        )
    build_transaction = _require_hex64(
        record.get("build_transaction"), "execution receipt build_transaction"
    )
    if build_transaction != source_closure:
        raise WindowsArtifactGateError(
            "Windows execution receipt is not bound to the current installer source closure."
        )
    raw_digests = record.get("inner_payload_digests")
    if type(raw_digests) is not dict or not raw_digests:
        raise WindowsArtifactGateError(
            "Windows execution receipt has no inner payload digests."
        )
    if len(raw_digests) > MAX_INNER_ENTRIES:
        raise WindowsArtifactGateError(
            "Windows execution receipt exceeds the reviewed entry-count ceiling."
        )
    inner_digests: dict[str, str] = {}
    for name, digest in raw_digests.items():
        if type(name) is not str:
            raise WindowsArtifactGateError(
                "Windows execution receipt inner payload digest names are not exact."
            )
        packed = _packed_inner_name(name)
        if name != packed:
            raise WindowsArtifactGateError(
                "Windows execution receipt inner payload name is not the packed name."
            )
        inner_digests[packed] = _require_hex64(
            digest, f"execution receipt inner digest {packed}"
        )
    canonical = _execution_receipt_canonical_bytes(record, inner_digests)
    _verify_execution_receipt_signature(record, canonical)
    raw_payloads = record.get("inner_payloads")
    if type(raw_payloads) is not dict or not raw_payloads:
        raise WindowsArtifactGateError(
            "Windows execution receipt has no inner payloads."
        )
    if len(raw_payloads) != len(inner_digests):
        raise WindowsArtifactGateError(
            "Windows execution receipt inner payloads are not bound to the signed digests."
        )
    if len(raw_payloads) > MAX_INNER_ENTRIES:
        raise WindowsArtifactGateError(
            "Windows execution receipt exceeds the reviewed entry-count ceiling."
        )
    extracted: dict[str, bytes] = {}
    seen: set[str] = set()
    aggregate = 0
    for name, blob in raw_payloads.items():
        if type(name) is not str or type(blob) is not bytes:
            raise WindowsArtifactGateError(
                "Windows execution receipt inner payload types are not exact."
            )
        packed = _packed_inner_name(name)
        if name != packed:
            raise WindowsArtifactGateError(
                "Windows execution receipt inner payload name is not the packed name."
            )
        packed_key = packed.casefold()
        if packed_key in seen:
            raise WindowsArtifactGateError(
                f"Windows execution receipt has a duplicated packed name: {packed}"
            )
        if packed not in inner_digests:
            raise WindowsArtifactGateError(
                "Windows execution receipt inner payloads are not bound to the signed digests."
            )
        if len(blob) <= 0 or len(blob) > MAX_INNER_FILE_BYTES:
            raise WindowsArtifactGateError(
                f"packed {packed} exceeds the reviewed per-file size ceiling."
            )
        if _sha256_bytes(blob) != inner_digests[packed]:
            raise WindowsArtifactGateError(
                "Windows execution receipt is not tied to the exact inner payload bytes."
            )
        aggregate += len(blob)
        if aggregate > MAX_AGGREGATE_INNER_BYTES:
            raise WindowsArtifactGateError(
                "Windows execution receipt exceeds the reviewed aggregate size ceiling."
            )
        seen.add(packed_key)
        extracted[packed] = blob
    if set(extracted) != set(inner_digests):
        raise WindowsArtifactGateError(
            "Windows execution receipt inner payloads are not bound to the signed digests."
        )
    _SEEN_RECEIPT_NONCES.add(nonce)
    _SEEN_RECEIPT_RUN_IDS.add(run_id)
    snapshot.assert_custody()
    return extracted


def _install_proof_sidecar(artifact: pathlib.Path) -> pathlib.Path | None:
    relative = (
        artifact.relative_to(ROOT.resolve(strict=True)).as_posix() + INSTALL_PROOF_SUFFIX
    )
    try:
        return _secure_repo_file(relative, "Windows install-proof receipt")
    except WindowsArtifactGateError:
        return None


def _prove_inner_payloads(
    artifact: pathlib.Path,
    snapshot: AuthenticatedSnapshot,
    leaf: Mapping[str, str],
    target_id: str,
    architecture: str,
    source_closure: str,
) -> tuple[dict[str, bytes], str]:
    sidecar = _install_proof_sidecar(artifact)
    extract_error: WindowsArtifactGateError | None = None
    capture_error: WindowsArtifactGateError | None = None
    snapshot.assert_custody()
    try:
        extracted = extract_packed_inner_payloads(snapshot.path)
        snapshot.assert_custody()
        return extracted, INNER_PROOF_EXTRACTOR
    except WindowsArtifactGateError as exc:
        if str(exc) != INNO_INNER_EXTRACTOR_ERROR:
            raise
        extract_error = exc
    try:
        receipt = authenticated_windows_install_run_capture(snapshot)
        extracted = _bind_execution_receipt(
            snapshot, leaf, receipt, target_id, architecture, source_closure
        )
        snapshot.assert_custody()
        return extracted, INNER_PROOF_CAPTURE
    except WindowsArtifactGateError as exc:
        if str(exc) != AUTHENTICATED_CAPTURE_ERROR:
            raise
        capture_error = exc
    if sidecar is not None:
        raise WindowsArtifactGateError(
            f"{INNER_PAYLOAD_EVIDENCE_PENDING}: {MUTABLE_JSON_PROOF_ERROR}; "
            f"{OWNER_INNER_PROOF_ERROR}"
        )
    detail = f"{extract_error}; {capture_error}"
    raise WindowsArtifactGateError(
        f"{INNER_PAYLOAD_EVIDENCE_PENDING}: {OWNER_INNER_PROOF_ERROR} ({detail})"
    )


# The runner's CMake project builds unit-test programs next to the application
# (windows_winn_gate_test.exe, winsvpn-carrierhost-test.exe, ...). build_installer.ps1 removes
# them and winsvpn.iss excludes them; an installer that still packs one is refused by name.
WINDOWS_TEST_EXECUTABLE_RE = re.compile(r"[-_]test\.exe$", re.IGNORECASE)


def _require_complete_inner_inventory(
    inventory: Sequence[InnerPayloadRecord],
    standalone_winn3: bool,
    architecture: str,
) -> None:
    names = {item.packed_name.casefold() for item in inventory}
    test_executables = sorted(
        name for name in names if WINDOWS_TEST_EXECUTABLE_RE.search(name)
    )
    if test_executables:
        raise WindowsArtifactGateError(
            "Windows package ships test executables: " + ", ".join(test_executables)
        )
    required = {
        name.casefold()
        for name in _required_payload_basenames(standalone_winn3, architecture, names)
    }
    missing = sorted(required - names)
    if missing:
        raise WindowsArtifactGateError(
            "Windows package inventory is incomplete: " + ", ".join(missing)
        )
    forbidden = {
        name.casefold()
        for name in _forbidden_payload_basenames(standalone_winn3, architecture)
    }
    present_forbidden = sorted(names & forbidden)
    if present_forbidden:
        foreign = {
            name.casefold() for name in _foreign_support_payload_basenames(architecture)
        }
        present_foreign = [name for name in present_forbidden if name in foreign]
        if present_foreign:
            raise WindowsArtifactGateError(
                "wrong-architecture Windows support payload: "
                + ", ".join(present_foreign)
            )
        msi_names = {item.casefold() for item in ALL_AMNEZIAWG_MSI_BASENAMES}
        present_engines = [name for name in present_forbidden if name not in msi_names]
        if present_engines:
            raise WindowsArtifactGateError(
                "Windows standalone package contains forbidden legacy engines: "
                + ", ".join(present_forbidden)
            )
        raise WindowsArtifactGateError(
            "Windows standalone package contains forbidden AmneziaWG MSI support payload: "
            + ", ".join(present_forbidden)
        )
    extra_manifests = sorted(
        name
        for name in names
        if name.startswith("org.winsvpn.bridge.")
        and name.endswith(".json")
        and name not in {item.casefold() for item in ALLOWED_NATIVE_MANIFEST_BASENAMES}
    )
    if extra_manifests:
        raise WindowsArtifactGateError(
            "Windows package contains extra native-messaging manifests: "
            + ", ".join(extra_manifests)
        )
    allowed = set(required)
    extra = sorted(names - allowed)
    if extra:
        extra_exec = [name for name in extra if _is_executable_name(name)]
        if extra_exec:
            raise WindowsArtifactGateError(
                "packed Windows inner payloads include extra executables: "
                + ", ".join(extra_exec)
            )
        raise WindowsArtifactGateError(
            "Windows package contains unallowlisted inner payloads: "
            + ", ".join(extra)
        )


_NATIVE_HOST_RENDERER: ModuleType | None = None


def _native_host_renderer() -> ModuleType:
    global _NATIVE_HOST_RENDERER
    if _NATIVE_HOST_RENDERER is not None:
        return _NATIVE_HOST_RENDERER
    path = _secure_origin_file(
        NATIVE_HOST_RENDERER_RELATIVE_PATH, "Windows native-host identity renderer"
    )
    spec = importlib.util.spec_from_file_location(
        "_winsvpn_windows_native_host_renderer", path
    )
    if spec is None or spec.loader is None:
        raise WindowsArtifactGateError("native-host identity renderer could not be loaded.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _NATIVE_HOST_RENDERER = module
    return module


def _owner_issued_chromium_ids() -> dict[str, str]:
    renderer = _native_host_renderer()
    try:
        return renderer.owner_issued_chromium_ids()
    except renderer.OwnerIdentityBlocked as exc:
        raise _owner_environment_blocker(str(exc)) from exc
    except renderer.OwnerIdentityInvalid as exc:
        raise WindowsArtifactGateError(str(exc)) from exc


def _native_manifest_browser(packed_name: str) -> str | None:
    folded = packed_name.casefold()
    prefix = "org.winsvpn.bridge."
    suffix = ".json"
    if not folded.startswith(prefix) or not folded.endswith(suffix):
        return None
    browser = folded[len(prefix) : -len(suffix)]
    if browser in {"chrome", "edge", "firefox"}:
        return browser
    return None


def _verify_native_manifest_bytes(
    packed_name: str, blob: bytes, owner_ids: Mapping[str, str]
) -> None:
    browser = _native_manifest_browser(packed_name)
    if browser is None:
        raise WindowsArtifactGateError(
            f"Windows native-messaging manifest is not recognized: {packed_name}"
        )
    document = _load_json_bytes(blob, f"{packed_name} native-messaging manifest")
    shared = {
        "name": NATIVE_HOST_JSON_NAME,
        "description": NATIVE_HOST_JSON_DESCRIPTION,
        "path": NATIVE_HOST_RELATIVE_PATH_VALUE,
        "type": "stdio",
    }
    if browser == "firefox":
        expected = {**shared, "allowed_extensions": [FIREFOX_NATIVE_EXTENSION_ID]}
    else:
        extension_id = owner_ids.get(browser)
        if type(extension_id) is not str or not extension_id:
            raise WindowsArtifactGateError(
                f"{packed_name} native-messaging origin is not bound to an owner-issued id."
            )
        expected = {
            **shared,
            "allowed_origins": [f"chrome-extension://{extension_id}/"],
        }
    if document != expected:
        raise WindowsArtifactGateError(
            f"{packed_name} native-messaging manifest is not exact."
        )
    encoded = blob.decode("utf-8")
    if "placeholder" in encoded.casefold():
        raise WindowsArtifactGateError(
            f"{packed_name} native-messaging manifest still contains a placeholder."
        )


def _verify_installer_release_versions(
    name: str, data: bytes, target_id: str
) -> tuple[str, str, str]:
    product_version, file_version = _reviewed_windows_release_identity()
    versions = pe_version_info(name, data)
    expected_description = TARGET_FILE_DESCRIPTIONS[target_id]
    if versions.get("ProductVersion") != product_version:
        raise WindowsArtifactGateError(
            f"{name} ProductVersion is not exact canonical {product_version}."
        )
    if versions.get("FileVersion") != file_version:
        raise WindowsArtifactGateError(
            f"{name} FileVersion is not exact canonical {file_version}."
        )
    if versions.get("FileDescription") != expected_description:
        raise WindowsArtifactGateError(
            f"{name} FileDescription is not the reviewed {TARGET_SURFACES[target_id]} producer identity."
        )
    if versions.get("OriginalFilename") != TARGET_FILENAMES[target_id]:
        raise WindowsArtifactGateError(
            f"{name} OriginalFilename is not the reviewed "
            f"{TARGET_ARCHITECTURES[target_id]} artifact filename."
        )
    if versions.get("ProductName") != EXPECTED_PRODUCT_NAME:
        raise WindowsArtifactGateError(
            f"{name} ProductName is not the reviewed product identity."
        )
    return product_version, file_version, expected_description


def _materialize_extracted(
    extracted: Mapping[str, bytes], root: pathlib.Path
) -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    aggregate = 0
    if len(extracted) > MAX_INNER_ENTRIES:
        raise WindowsArtifactGateError(
            "packed Windows inner payloads exceed the reviewed entry-count ceiling."
        )
    for packed_name, blob in extracted.items():
        posix = pathlib.PurePosixPath(packed_name)
        if posix.is_absolute() or any(part in {"", ".", ".."} for part in posix.parts):
            raise WindowsArtifactGateError(
                f"packed inner payload name is not canonical: {packed_name}"
            )
        if len(blob) > MAX_INNER_FILE_BYTES:
            raise WindowsArtifactGateError(
                f"packed {packed_name} exceeds the reviewed per-file size ceiling."
            )
        aggregate += len(blob)
        if aggregate > MAX_AGGREGATE_INNER_BYTES:
            raise WindowsArtifactGateError(
                "packed Windows inner payloads exceed the reviewed aggregate size ceiling."
            )
        destination = root.joinpath(*posix.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(blob)
        paths.append(destination)
    return paths


def verify_packed_inner_payloads(
    extracted: Mapping[str, bytes],
    inventory: Sequence[InnerPayloadRecord],
    architecture: str,
    product_version: str,
    file_version: str,
    standalone_winn3: bool,
    *,
    custody_policy: AuthenticodeCustodyPolicy,
) -> None:
    policy = _require_custody_policy(custody_policy)
    if len(extracted) > MAX_INNER_ENTRIES:
        raise WindowsArtifactGateError(
            "packed Windows inner payloads exceed the reviewed entry-count ceiling."
        )
    packed_names = {item.packed_name.casefold() for item in inventory}
    extracted_names = {name.casefold() for name in extracted}
    extra = sorted(extracted_names - packed_names)
    missing = sorted(packed_names - extracted_names)
    for packed_name, blob in extracted.items():
        if _sha256_bytes(blob) in WITHDRAWN_MULLVAD_SHA256:
            raise WindowsArtifactGateError(
                "withdrawn Mullvad payload bytes are present, including when renamed."
            )
    if extra or missing:
        detail = []
        extra_exec = [name for name in extra if _is_executable_name(name)]
        if extra_exec:
            raise WindowsArtifactGateError(
                "packed Windows inner payloads include extra executables: "
                + ", ".join(extra_exec)
            )
        if extra:
            detail.append("extra files: " + ", ".join(extra))
        if missing:
            detail.append("missing files: " + ", ".join(missing))
        raise WindowsArtifactGateError(
            "packed Windows inner payloads do not match the producer inventory ("
            + "; ".join(detail)
            + ")."
        )
    aggregate = 0
    for packed_name in extracted:
        _packed_inner_name(packed_name)
    for record in inventory:
        if record.size > MAX_INNER_FILE_BYTES:
            raise WindowsArtifactGateError(
                f"packed {record.packed_name} exceeds the reviewed per-file size ceiling."
            )
        blob = _find_extracted(extracted, record.packed_name)
        if len(blob) > MAX_INNER_FILE_BYTES:
            raise WindowsArtifactGateError(
                f"packed {record.packed_name} exceeds the reviewed per-file size ceiling."
            )
        _reject_packaged_private_symbols(record.packed_name, blob)
        aggregate += len(blob)
        if aggregate > MAX_AGGREGATE_INNER_BYTES:
            raise WindowsArtifactGateError(
                "packed Windows inner payloads exceed the reviewed aggregate size ceiling."
            )
        digest = _sha256_bytes(blob)
        if len(blob) != record.size or digest != record.sha256:
            raise WindowsArtifactGateError(
                f"packed {record.packed_name} does not match the producer inventory."
            )
        if digest in WITHDRAWN_MULLVAD_SHA256:
            raise WindowsArtifactGateError(
                "withdrawn Mullvad payload bytes are present, including when renamed."
            )
        expected_type = _expected_payload_type(record.packed_name)
        if expected_type == "aot" and not blob.startswith(b"\x7fELF"):
            raise WindowsArtifactGateError(
                "packed data/app.so is not the stripped Flutter AOT payload."
            )
        if expected_type == "pe":
            if _is_vc_redist_name(record.packed_name):
                before = bytes(blob)
                _verify_vendor_redistributable_pe(
                    record.packed_name, blob, architecture
                )
                if _find_extracted(extracted, record.packed_name) != before:
                    raise WindowsArtifactGateError(
                        f"packed {record.packed_name} vendor bytes must not be stripped or rewritten."
                    )
            else:
                machine, _, _ = _parse_pe_bytes(
                    record.packed_name,
                    blob,
                    expected_machine=_pe_machine_for_architecture(architecture),
                )
                if machine != _pe_machine_for_architecture(architecture):
                    raise WindowsArtifactGateError(
                        f"{record.packed_name} executable identity is not PE32+ {architecture}."
                    )
                _verify_inner_pe_authenticode(record.packed_name, blob, policy)
            _reject_inner_pe_debug_metadata(record.packed_name, blob, architecture)
        elif blob.startswith(b"MZ"):
            _reject_inner_pe_debug_metadata(record.packed_name, blob, architecture)
        if _is_amneziawg_msi_name(record.packed_name):
            _verify_amneziawg_msi_payload(
                record.packed_name,
                blob,
                architecture,
                require_reviewed_hash=False,
            )
        if expected_type == "json":
            _load_json_bytes(blob, f"packed {record.packed_name}")
    _require_complete_inner_inventory(inventory, standalone_winn3, architecture)
    machine = _pe_machine_for_architecture(architecture)
    for basename in sorted(_required_pe_basenames(standalone_winn3, architecture)):
        blob = _find_extracted(extracted, basename)
        parsed_machine, _, _ = _parse_pe_bytes(basename, blob, expected_machine=machine)
        if parsed_machine != machine:
            raise WindowsArtifactGateError(
                f"{basename} executable identity is not PE32+ {architecture}."
            )
    vc_redist_name = _vc_redist_basename(architecture)
    if _sha256_bytes(_find_extracted(extracted, vc_redist_name)) != VC_REDIST_SHA256[
        architecture
    ]:
        raise WindowsArtifactGateError(
            f"{vc_redist_name} payload identity is not the reviewed {architecture} VC_redist."
        )
    if _sha256_bytes(_find_extracted(extracted, "wintun.dll")) != WINTUN_SHA256[
        architecture
    ]:
        raise WindowsArtifactGateError("Wintun payload identity is not reviewed.")
    if not standalone_winn3:
        msi_name = _amneziawg_msi_basename(architecture)
        _verify_amneziawg_msi_payload(
            msi_name,
            _find_extracted(extracted, msi_name),
            architecture,
            require_reviewed_hash=True,
        )
        if _sha256_bytes(_find_extracted(extracted, "awg.exe")) != AWG_TOOL_SHA256[
            architecture
        ]:
            raise WindowsArtifactGateError(
                "AWG tool is not the official 3.1.20260814 payload."
            )
        if _sha256_bytes(_find_extracted(extracted, "xray.exe")) != XRAY_SHA256[
            architecture
        ]:
            raise WindowsArtifactGateError(
                "Xray payload is not the reviewed 26.9.30 rebuild."
            )
        helper = _load_json_bytes(
            _find_extracted(extracted, "amneziawg.exe.provenance.json"),
            "AmneziaWG helper provenance",
        )
        engine = _load_json_bytes(
            _find_extracted(extracted, "winsvpn_awg_engine.exe.provenance.json"),
            "Windows AWG engine provenance",
        )
        if (
            helper.get("source_version") != "3.1.0"
            or helper.get("engine_module") != AWG_GO_MODULE
            or helper.get("engine_version") != AWG_GO_VERSION
            or helper.get("engine_commit") != AWG_GO_COMMIT
            or helper.get("target")
            != f"windows-{'amd64' if architecture == 'x64' else 'arm64'}"
            or (
                architecture == "arm64"
                and (
                    helper.get("reproducibility_builds") != 2
                    or helper.get("reproducibility_status")
                    != "two_clean_builds_byte_identical"
                )
            )
        ):
            raise WindowsArtifactGateError(
                "AmneziaWG helper provenance is not the official 3.1 contract."
            )
        if (
            engine.get("engine_module") != AWG_GO_MODULE
            or engine.get("engine_version") != AWG_GO_VERSION
            or engine.get("engine_commit") != AWG_GO_COMMIT
            or engine.get("execution_guard_status")
            != "verified_after_authenticode_phase"
            or engine.get("artifact_sha256")
            != _sha256_bytes(_find_extracted(extracted, "winsvpn_awg_engine.exe"))
            or engine.get("target_architecture")
            != ("amd64" if architecture == "x64" else "arm64")
        ):
            raise WindowsArtifactGateError(
                "Windows AWG engine provenance is not finalized and exact."
            )
    owner_ids = _owner_issued_chromium_ids()
    for packed_name in sorted(REQUIRED_NATIVE_MANIFEST_BASENAMES):
        if packed_name.casefold() not in packed_names:
            raise WindowsArtifactGateError(
                f"Windows package is missing the {packed_name} native-messaging manifest."
            )
        _verify_native_manifest_bytes(
            packed_name, _find_extracted(extracted, packed_name), owner_ids
        )
    if NATIVE_HOST_BASENAME.casefold() not in packed_names:
        raise WindowsArtifactGateError(
            "Windows package is missing the browser native-messaging host."
        )
    with tempfile.TemporaryDirectory(prefix="winsvpn-win-inner-") as temporary:
        materialized = _materialize_extracted(extracted, pathlib.Path(temporary))
        for basename in sorted(REQUIRED_VERSIONED_PAYLOAD_BASENAMES):
            path = next(
                item
                for item in materialized
                if item.name.casefold() == basename.casefold()
            )
            versions = pe_version_info(basename, path.read_bytes())
            if versions.get("ProductVersion") != product_version:
                raise WindowsArtifactGateError(
                    f"{basename} ProductVersion is not exact canonical "
                    f"{product_version}."
                )
            if versions.get("FileVersion") != file_version:
                raise WindowsArtifactGateError(
                    f"{basename} FileVersion is not exact canonical {file_version}."
                )
        privacy_paths = [
            path
            for path in materialized
            if not _is_vc_redist_name(path.name) and not _is_amneziawg_msi_name(path.name)
        ]
        _verify_privacy_of_paths(privacy_paths)


def _install_proof_path(artifact: pathlib.Path) -> pathlib.Path:
    raise WindowsArtifactGateError(
        f"{MUTABLE_JSON_PROOF_ERROR}; {INSTALL_PROOF_REQUIRED_ERROR}."
    )


def _install_proof_records(
    raw_installed: object,
) -> list[InstallProofRecord]:
    raise WindowsArtifactGateError(MUTABLE_JSON_PROOF_ERROR)


def _verify_install_proof(
    artifact: pathlib.Path,
    target_id: str,
    architecture: str,
    standalone_winn3: bool,
    inventory: Sequence[InnerPayloadRecord],
    installer_size: int,
    installer_sha256: str,
) -> tuple[pathlib.Path, list[InstallProofRecord]]:
    del (
        artifact,
        target_id,
        architecture,
        standalone_winn3,
        inventory,
        installer_size,
        installer_sha256,
    )
    raise WindowsArtifactGateError(MUTABLE_JSON_PROOF_ERROR)


def _verify_producer_schema(
    producer: Mapping[str, object], target_id: str
) -> str:
    record = _exact_mapping(producer, PRODUCER_SCHEMA_KEYS, "Windows producer identity")
    if _require_text(record.get("path"), "producer.path") != PRODUCER_RELATIVE_PATH:
        raise WindowsArtifactGateError("Windows producer path is not the reviewed script.")
    if (
        _require_text(record.get("inno_script_path"), "producer.inno_script_path")
        != INNO_SCRIPT_RELATIVE_PATH
    ):
        raise WindowsArtifactGateError("Windows Inno script path is not the reviewed script.")
    if (
        _require_text(
            record.get("inno_signing_wrapper_path"),
            "producer.inno_signing_wrapper_path",
        )
        != SIGNING_WRAPPER_RELATIVE_PATH
    ):
        raise WindowsArtifactGateError(
            "Windows signing wrapper path is not the reviewed script."
        )
    expected_producer = _origin_digest(
        PRODUCER_RELATIVE_PATH, "Windows producer script", maximum=MAX_SUPPORT_BYTES
    )
    expected_script = _origin_digest(
        INNO_SCRIPT_RELATIVE_PATH, "Windows Inno script", maximum=MAX_SUPPORT_BYTES
    )
    expected_wrapper = _origin_digest(
        SIGNING_WRAPPER_RELATIVE_PATH,
        "Windows signing wrapper",
        maximum=MAX_SUPPORT_BYTES,
    )
    if _require_hex64(record.get("sha256"), "producer.sha256") != expected_producer:
        raise WindowsArtifactGateError("Windows producer digest is not the reviewed script.")
    if (
        _require_hex64(record.get("inno_script_sha256"), "producer.inno_script_sha256")
        != expected_script
    ):
        raise WindowsArtifactGateError("Windows Inno script digest is not the reviewed script.")
    if (
        _require_hex64(
            record.get("inno_signing_wrapper_sha256"),
            "producer.inno_signing_wrapper_sha256",
        )
        != expected_wrapper
    ):
        raise WindowsArtifactGateError(
            "Windows signing wrapper digest is not the reviewed script."
        )
    return REVIEWED_PRODUCER_IDENTITIES[target_id]


def _verify_release_input_schema(release_input: Mapping[str, object]) -> None:
    record = _exact_mapping(
        release_input, RELEASE_INPUT_SCHEMA_KEYS, "Windows release_input"
    )
    relative = _require_text(record.get("path"), "release_input.path")
    digest = _require_hex64(record.get("sha256"), "release_input.sha256")
    path = _secure_repo_file(relative, "Windows release_input")
    snapshot = snapshot_regular_file(
        path, "Windows release_input", maximum=MAX_JSON_BYTES
    )
    try:
        if snapshot.digest != digest:
            raise WindowsArtifactGateError(
                "Windows release_input digest does not match the frozen index."
            )
    finally:
        snapshot.close()


def _verify_toolchain_schema(toolchain: Mapping[str, object]) -> None:
    record = _exact_mapping(toolchain, TOOLCHAIN_SCHEMA_KEYS, "Windows toolchain")
    pins = _load_toolchain_pins()
    version = _require_text(record.get("framework_version"), "toolchain.framework_version")
    revision = _require_text(
        record.get("framework_revision"), "toolchain.framework_revision"
    )
    dart = _require_text(record.get("dart_sdk_version"), "toolchain.dart_sdk_version")
    engine = _require_text(record.get("engine_revision"), "toolchain.engine_revision")
    if (
        version != pins["framework_version"]
        or revision != pins["framework_revision"]
        or not dart.startswith(pins["dart_sdk_version"])
        or re.fullmatch(r"[0-9a-f]{40}", engine) is None
    ):
        raise WindowsArtifactGateError(
            "Windows toolchain identity is not the reviewed Flutter pin set."
        )


def _verify_inno_compiler_identity(value: object, architecture: str) -> None:
    """Bind the producer's Inno compiler identity to the reviewed pin bytes."""

    record = _exact_mapping(
        value, INNO_COMPILER_IDENTITY_KEYS, "Windows Inno compiler identity"
    )
    path = _secure_origin_file(INNO_COMPILER_PIN_RELATIVE_PATH, "Inno toolchain pins")
    snapshot = snapshot_regular_file(path, "Inno toolchain pins", maximum=MAX_JSON_BYTES)
    try:
        pin_digest = snapshot.digest
        document = _load_json_bytes(snapshot.bytes(), "Inno toolchain pins")
    finally:
        snapshot.close()
    compilers = document.get("compilers")
    pinned = compilers.get(f"windows_{architecture}") if type(compilers) is dict else None
    publisher = document.get("publisher")
    if (
        document.get("status") != "pinned"
        or type(pinned) is not dict
        or pinned.get("status") != "pinned"
        or pinned.get("output_architectures") != [architecture]
        or type(publisher) is not dict
    ):
        raise WindowsArtifactGateError(
            "Inno toolchain pins do not pin the compiler for this architecture."
        )
    expected = {
        "contract": INNO_COMPILER_RECEIPT_CONTRACT,
        "product": document.get("product"),
        "vendor": document.get("vendor"),
        "version": pinned.get("expected_version"),
        "filename": pinned.get("filename"),
        "architecture": architecture,
        "pe_machine": pinned.get("pe_machine"),
        "output_architectures": [architecture],
        "sha256": pinned.get("sha256"),
        "size": pinned.get("size"),
        "product_version_string": pinned.get("product_version_string"),
        "publisher_name": pinned.get("publisher_name"),
        "authenticode_leaf_sha256": publisher.get("authenticode_leaf_sha256"),
        "authenticode_leaf_serial_hex": publisher.get("authenticode_leaf_serial_hex"),
        "install_tree_sha256": pinned.get("install_tree_sha256"),
        "trusted_root_leaf": pinned.get("trusted_root_leaf"),
        "pin_path": INNO_COMPILER_PIN_RELATIVE_PATH,
        "pin_sha256": pin_digest,
    }
    _require_int(record.get("size"), "inno_compiler.size")
    _require_hex64(record.get("sha256"), "inno_compiler.sha256")
    _require_hex64(record.get("install_tree_sha256"), "inno_compiler.install_tree_sha256")
    if dict(record) != expected:
        raise WindowsArtifactGateError(
            "Windows Inno compiler identity is not the reviewed pin for this architecture."
        )


def _verify_signing_evidence(
    signing: Mapping[str, object], standalone_winn3: bool
) -> None:
    """Require producer signing flags. They are not Authenticode proof."""

    required_true = {
        "production_signed",
        "every_loose_pe_verified",
        "inno_setup_and_uninstaller_signed",
        "self_signed_certificate_forbidden",
    }
    for key in required_true:
        if _require_bool(signing.get(key), f"signing.{key}") is not True:
            raise WindowsArtifactGateError(
                "Windows production signing evidence is incomplete."
            )
    xray_signed = _require_bool(
        signing.get("staged_xray_product_signed"), "signing.staged_xray_product_signed"
    )
    if xray_signed is standalone_winn3:
        raise WindowsArtifactGateError(
            "Windows Xray signing evidence does not match the standalone_winn3 fact."
        )


def canonical_windows_release() -> str:
    product_version, file_version = _reviewed_windows_release_identity()
    if (
        product_version != CANONICAL_PRODUCT_VERSION
        or file_version != CANONICAL_FILE_VERSION
    ):
        raise WindowsArtifactGateError(
            "Windows release identity is not the canonical 1.0.17+34 mapping."
        )
    stamp = f"{product_version}+{file_version.rsplit('.', 1)[-1]}"
    if stamp != CANONICAL_RELEASE:
        raise WindowsArtifactGateError(
            "Windows release stamp is not the canonical 1.0.17+34 identity."
        )
    return stamp


def _require_canonical_relative_path(path: object, label: str) -> str:
    if type(path) is not str or not path or "\\" in path:
        raise WindowsArtifactGateError(
            f"{label} must be one canonical repository-relative path."
        )
    relative = pathlib.PurePosixPath(path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise WindowsArtifactGateError(
            f"{label} must be one canonical repository-relative path."
        )
    return path


def _receipt_hex64(value: object, label: str) -> str:
    return _require_hex64(value, label)


def _receipt_hex128(value: object, label: str) -> str:
    text = _require_text(value, label)
    if re.fullmatch(r"[0-9a-f]{128}", text) is None:
        raise WindowsArtifactGateError(f"{label} is not an exact SHA-512 hex digest.")
    return text


def _receipt_exact_mapping(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise WindowsArtifactGateError(f"{label} schema fields are invalid.")
    return value


def _receipt_exact_str(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise WindowsArtifactGateError(f"{label} is not exact.")
    return value


def _receipt_document(record: object, label: str) -> dict[str, object]:
    if type(record) is bytes:
        return _load_json_bytes(record, label)
    if type(record) is dict:
        return dict(record)
    raise WindowsArtifactGateError(
        f"{label} must be exact JSON bytes or one JSON object."
    )


def _package_upload_target(target_id: str) -> dict[str, object]:
    spec = WINDOWS_PACKAGE_UPLOAD_TARGETS.get(target_id)
    if spec is None:
        raise WindowsArtifactGateError(
            f"unsupported exact Windows package/upload target: {target_id}"
        )
    return spec


def expected_upload_artifact_path(target_id: str) -> str:
    spec = _package_upload_target(target_id)
    return f"{EXPECTED_UPLOAD_ARTIFACT_DIRECTORY}/{spec['artifact_name']}"


def _require_inno_bootstrap_machine(name: str, machine: int) -> None:
    if machine != INNO_BOOTSTRAP_MACHINE:
        raise WindowsArtifactGateError(INNO_BOOTSTRAP_ERROR)


def _reject_source_only_installer_bytes(name: str, payload: bytes) -> None:
    if payload[:2] == b"MZ":
        return
    head = payload[:4096]
    stripped = head.lstrip()
    if (
        stripped.startswith(b"#!")
        or b"[Setup]" in head
        or b"Write-Host" in head
        or b"from __future__" in head
        or stripped.startswith(b"using ")
    ):
        raise WindowsArtifactGateError(SOURCE_ONLY_INSTALLER_ERROR)


def _reject_false_green_selftest(record: Mapping[str, object]) -> None:
    _reject_test_only_production_pass()
    try:
        encoded = json.dumps(record, ensure_ascii=True).casefold()
    except (TypeError, ValueError) as exc:
        raise WindowsArtifactGateError(COLLECTOR_SELFTEST_ERROR) from exc
    if (
        "self_test" in encoded
        or "self-test" in encoded
        or "--self-test" in encoded
    ):
        raise WindowsArtifactGateError(COLLECTOR_SELFTEST_ERROR)


def _bind_evidence_collector(target_id: str, record: Mapping[str, object]) -> None:
    collector = _receipt_exact_mapping(
        record.get("evidence_collector"),
        {"path", "sha256"},
        f"{target_id} evidence collector",
    )
    path = _require_canonical_relative_path(
        collector.get("path"), f"{target_id} evidence collector"
    )
    if path != EVIDENCE_COLLECTOR_RELATIVE:
        raise WindowsArtifactGateError(
            f"{target_id} evidence collector path is not exact."
        )
    digest = _origin_digest(
        EVIDENCE_COLLECTOR_RELATIVE,
        "Windows evidence collector",
        maximum=MAX_SUPPORT_BYTES,
    )
    bound = _receipt_hex64(
        collector.get("sha256"), f"{target_id} evidence collector"
    )
    if bound != digest:
        raise WindowsArtifactGateError(
            f"{target_id} evidence collector was swapped or does not bind "
            "the exact candidate bytes."
        )


def _reject_windows_receipt_set_collisions(
    parsed: Mapping[str, dict[str, object]]
) -> None:
    unique_pairs: list[tuple[str, str]] = []
    shared: dict[str, tuple[str, str]] = {}
    seen_artifact_paths: dict[str, str] = {}
    seen_filenames: dict[str, str] = {}
    seen_producers: dict[str, str] = {}
    seen_signing: dict[str, str] = {}
    for target_id, record in parsed.items():
        if record.get("target_id") != target_id:
            raise WindowsArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
            )
        spec = WINDOWS_PACKAGE_UPLOAD_TARGETS[target_id]
        architectures = record.get("architectures")
        if (
            type(architectures) is list
            and tuple(architectures) != spec["architectures"]
        ):
            raise WindowsArtifactGateError(
                f"{target_id} architecture inventory is not exact."
            )
        identity = record.get("package_identity")
        if type(identity) is dict:
            if (
                identity.get("architecture") != TARGET_ARCHITECTURES[target_id]
                or identity.get("surface") != spec["store_surface"]
                or identity.get("filename") != spec["artifact_name"]
                or identity.get("file_description") != spec["file_description"]
            ):
                raise WindowsArtifactGateError(
                    f"{target_id} package identity is not the current 1.0.17+34 Windows identity."
                )
            filename = identity.get("filename")
            if type(filename) is str:
                previous = seen_filenames.get(filename)
                if previous is not None:
                    raise WindowsArtifactGateError(
                        f"receipt reuse is refused: {target_id} reuses {previous}"
                    )
                seen_filenames[filename] = target_id
        artifact = record.get("artifact")
        if type(artifact) is dict:
            path = artifact.get("path")
            if type(path) is str:
                previous = seen_artifact_paths.get(path)
                if previous is not None:
                    raise WindowsArtifactGateError(
                        f"receipt reuse is refused: {target_id} reuses {previous}"
                    )
                seen_artifact_paths[path] = target_id
        producer = record.get("producer")
        if type(producer) is dict:
            producer_id = producer.get("id")
            if type(producer_id) is str:
                previous = seen_producers.get(producer_id)
                if previous is not None:
                    raise WindowsArtifactGateError(
                        f"receipt reuse is refused: {target_id} reuses {previous}"
                    )
                seen_producers[producer_id] = target_id
        signing = record.get("signing")
        if type(signing) is dict:
            contract = signing.get("contract")
            if type(contract) is str:
                previous = seen_signing.get(contract)
                if previous is not None:
                    raise WindowsArtifactGateError(
                        f"receipt reuse is refused: {target_id} reuses {previous}"
                    )
                seen_signing[contract] = target_id
        unique_pairs.extend(_unique_receipt_digest_pairs(target_id, record))
        _bind_shared_upload_paths(shared, target_id, record)
    _reject_receipt_digest_reuse(unique_pairs)


def _hash_live_repo_file(
    relative: str, label: str, *, maximum: int = MAX_SUPPORT_BYTES
) -> tuple[str, int, bytes]:
    try:
        path = _secure_repo_file(relative, label)
    except WindowsArtifactGateError as exc:
        text = str(exc)
        if "is missing" in text or "could not bind" in text:
            raise _owner_environment_blocker(
                "Windows package/upload receipts remain pending without owner evidence: "
                + relative
            ) from exc
        raise
    snapshot = snapshot_regular_file(path, label, maximum=maximum)
    try:
        payload = snapshot.bytes()
        if len(payload) != snapshot.size or _sha256_bytes(payload) != snapshot.digest:
            raise WindowsArtifactGateError(f"{label} mutated while it was read.")
        return snapshot.digest, snapshot.size, payload
    finally:
        snapshot.close()


def _load_store_json(relative: str, label: str) -> dict[str, object]:
    _digest, _size, payload = _hash_live_repo_file(relative, label)
    del _digest, _size
    try:
        payload.decode("ascii")
    except UnicodeError as exc:
        raise WindowsArtifactGateError(f"{relative} must be ASCII") from exc
    return _load_json_bytes(payload, label)


def _require_listing_protocol(text: str, label: str) -> None:
    if "Winn v3" not in text or "AWG then Xray" not in text:
        raise WindowsArtifactGateError(
            f"{label} must name Winn v3 primary and Winn v1 AWG then Xray fallback."
        )


def obfuscation_receipt_relative(target_id: str) -> str:
    if target_id not in WINDOWS_PACKAGE_UPLOAD_TARGETS:
        raise WindowsArtifactGateError(
            f"unsupported exact Windows package/upload target: {target_id}"
        )
    architecture = TARGET_ARCHITECTURES[target_id]
    surface = TARGET_SURFACES[target_id]
    return (
        f".artifacts/private-release-symbols/windows/{architecture}/"
        f"{CANONICAL_RELEASE}/manifest-{surface}.json"
    )


def _ascii_listing_text(relative: str, label: str) -> str:
    payload = _hash_live_repo_file(relative, label)[2]
    try:
        return payload.decode("ascii")
    except UnicodeError as exc:
        raise WindowsArtifactGateError(f"{relative} must be ASCII") from exc


def _require_single_line(text: str, label: str) -> str:
    stripped = text.strip()
    if not stripped or "\n" in stripped or "\r" in stripped:
        raise WindowsArtifactGateError(f"{label} must be one ASCII line.")
    return stripped


def _require_bounded_text(text: str, maximum: int, label: str) -> str:
    if len(text) == 0 or len(text) > maximum:
        raise WindowsArtifactGateError(
            f"{label} must stay within the Partner Center {maximum}-character limit."
        )
    return text


def _require_listing_lines(
    text: str, *, maximum_count: int, maximum_chars: int, label: str
) -> list[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or len(lines) > maximum_count:
        raise WindowsArtifactGateError(
            f"{label} must contain 1 to {maximum_count} ASCII lines."
        )
    for line in lines:
        if len(line) > maximum_chars:
            raise WindowsArtifactGateError(
                f"{label} entries must stay within {maximum_chars} characters."
            )
    if len(set(lines)) != len(lines):
        raise WindowsArtifactGateError(f"{label} entries must be unique.")
    return lines


def _reviewed_store_metadata(target_id: str | None = None) -> dict[str, object]:
    if target_id is not None and target_id not in WINDOWS_PACKAGE_UPLOAD_TARGETS:
        raise WindowsArtifactGateError(
            f"unsupported exact Windows package/upload target: {target_id}"
        )
    files: dict[str, str] = {}
    for name in WINDOWS_STORE_FILES:
        relative = f"{STORE_METADATA_ROOT}/{name}"
        digest, _size, payload = _hash_live_repo_file(relative, "Windows store metadata")
        try:
            payload.decode("ascii")
        except UnicodeError as exc:
            raise WindowsArtifactGateError(f"{relative} must be ASCII") from exc
        files[relative] = digest
    notes_digest, _notes_size, notes_payload = _hash_live_repo_file(
        CERTIFICATION_NOTES_RELATIVE, "Windows certification notes"
    )
    try:
        notes_payload.decode("ascii")
    except UnicodeError as exc:
        raise WindowsArtifactGateError(
            f"{CERTIFICATION_NOTES_RELATIVE} must be ASCII"
        ) from exc
    files[CERTIFICATION_NOTES_RELATIVE] = notes_digest
    privacy = _load_store_json(
        f"{STORE_METADATA_ROOT}/review/privacy_label_manifest.json",
        "Windows privacy label",
    )
    signoff = _load_store_json(
        f"{STORE_METADATA_ROOT}/review/owner_signoff.json",
        "Windows owner signoff",
    )
    candidate = _load_store_json(
        f"{STORE_METADATA_ROOT}/artifacts/release_candidate.json",
        "Windows release candidate",
    )
    listing = _ascii_listing_text(
        f"{STORE_METADATA_ROOT}/metadata/en-US/full_description.txt",
        "Windows listing",
    )
    notes = _ascii_listing_text(
        f"{STORE_METADATA_ROOT}/review/partner_center_notes.txt",
        "Windows Partner Center notes",
    )
    title = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/title.txt",
            "Windows title",
        ),
        "Windows title",
    )
    short = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/short_description.txt",
            "Windows short description",
        ),
        "Windows short description",
    )
    whats_new = _ascii_listing_text(
        f"{STORE_METADATA_ROOT}/metadata/en-US/whats_new.txt",
        "Windows what's new",
    )
    features = _require_listing_lines(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/features.txt",
            "Windows features",
        ),
        maximum_count=WINDOWS_FEATURE_MAX_COUNT,
        maximum_chars=WINDOWS_FEATURE_MAX_CHARS,
        label="Windows features",
    )
    search_terms = _require_listing_lines(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/search_terms.txt",
            "Windows search terms",
        ),
        maximum_count=WINDOWS_SEARCH_TERM_MAX_COUNT,
        maximum_chars=WINDOWS_SEARCH_TERM_MAX_CHARS,
        label="Windows search terms",
    )
    copyright_line = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/copyright.txt",
            "Windows copyright",
        ),
        "Windows copyright",
    )
    support_url = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/support_url.txt",
            "Windows support URL",
        ),
        "Windows support URL",
    )
    privacy_url = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/privacy_url.txt",
            "Windows privacy URL",
        ),
        "Windows privacy URL",
    )
    website_url = _require_single_line(
        _ascii_listing_text(
            f"{STORE_METADATA_ROOT}/metadata/en-US/website_url.txt",
            "Windows website URL",
        ),
        "Windows website URL",
    )
    _require_listing_protocol(listing, "Windows listing")
    _require_listing_protocol(notes, "Windows Partner Center notes")
    _require_listing_protocol(short, "Windows short description")
    _require_listing_protocol(whats_new, "Windows what's new")
    _require_listing_protocol("\n".join(features), "Windows features")
    _require_bounded_text(title, WINDOWS_TITLE_MAX, "Windows title")
    _require_bounded_text(short, WINDOWS_SHORT_DESCRIPTION_MAX, "Windows short description")
    _require_bounded_text(listing, WINDOWS_FULL_DESCRIPTION_MAX, "Windows listing")
    _require_bounded_text(whats_new, WINDOWS_WHATS_NEW_MAX, "Windows what's new")
    if title != EXPECTED_PRODUCT_NAME:
        raise WindowsArtifactGateError("Windows listing title is not Win's VPN")
    if "Calculator" in listing:
        raise WindowsArtifactGateError(
            "Windows listing must refuse calculator camouflage."
        )
    if "not an MSIX" not in listing:
        raise WindowsArtifactGateError(
            "Windows listing must name that it is not MSIX."
        )
    if copyright_line != WINDOWS_COPYRIGHT:
        raise WindowsArtifactGateError("Windows copyright is not the canonical 1.0.17+34 line.")
    if (
        privacy_url != WINDOWS_PRIVACY_POLICY_URL
        or support_url != WINDOWS_SUPPORT_URL
        or website_url != WINDOWS_WEBSITE_URL
    ):
        raise WindowsArtifactGateError(
            "Windows listing URLs are not the canonical privacy, support, and website values."
        )
    if EXPECTED_PRODUCT_NAME.casefold() in " ".join(search_terms).casefold():
        raise WindowsArtifactGateError(
            "Windows search terms must not repeat the product name."
        )
    protocol = privacy.get("tunnel_protocol")
    candidate_protocol = candidate.get("tunnel_protocol")
    symbols = candidate.get("private_symbols")
    targets = candidate.get("targets")
    msix = candidate.get("msix")
    obfuscation_receipts = candidate.get("obfuscation_receipts")
    expected_obfuscation = {
        target: obfuscation_receipt_relative(target)
        for target in ("windows-x64-installer", "windows-x64-partner-center")
    }
    if (
        privacy.get("schema_version") != 1
        or privacy.get("contract") != "winsvpn-windows-privacy-label-v1"
        or privacy.get("canonical_release") != CANONICAL_RELEASE
        or privacy.get("product_version") != CANONICAL_PRODUCT_VERSION
        or privacy.get("four_part_version") != CANONICAL_FILE_VERSION
        or privacy.get("application_label") != EXPECTED_PRODUCT_NAME
        or privacy.get("store_listing_name") != EXPECTED_PRODUCT_NAME
        or privacy.get("privacy_policy_url") != WINDOWS_PRIVACY_POLICY_URL
        or privacy.get("form_factor") != "windows-x64"
        or privacy.get("camouflage") is not False
        or privacy.get("tracking") is not False
        or privacy.get("data_collected") is not True
        or privacy.get("data_shared") is not False
        or privacy.get("listing_screenshot_inventory") != "owner-blocked"
        or privacy.get("private_symbols_uploaded") is not False
        or privacy.get("msix_upload_target") is not False
        or privacy.get("collected_categories") != WINDOWS_COLLECTED_CATEGORIES
        or privacy.get("not_collected") != WINDOWS_NOT_COLLECTED_CATEGORIES
        or type(protocol) is not dict
        or protocol.get("executed_on") != WINDOWS_TUNNEL_PROTOCOL["executed_on"]
        or protocol.get("primary") != WINDOWS_TUNNEL_PROTOCOL["primary"]
        or protocol.get("fallback") != WINDOWS_TUNNEL_PROTOCOL["fallback"]
        or protocol.get("required_local_engines")
        != WINDOWS_TUNNEL_PROTOCOL["required_local_engines"]
    ):
        raise WindowsArtifactGateError(
            "Windows privacy label is not the canonical 1.0.17+34 contract."
        )
    if (
        signoff.get("schema_version") != 1
        or signoff.get("contract") != "winsvpn-windows-owner-signoff-v1"
        or signoff.get("canonical_release") != CANONICAL_RELEASE
        or signoff.get("product_version") != CANONICAL_PRODUCT_VERSION
        or signoff.get("four_part_version") != CANONICAL_FILE_VERSION
        or signoff.get("form_factor") != "windows-x64"
        or signoff.get("submission_approved") is not False
        or signoff.get("upload_authorized") is not False
        or signoff.get("msix_upload_authorized") is not False
        or signoff.get("listing_screenshot_inventory") != "owner-blocked"
        or signoff.get("blockers") != WINDOWS_OWNER_SIGNOFF_BLOCKERS
    ):
        raise WindowsArtifactGateError(
            "Windows owner signoff is not the canonical 1.0.17+34 contract."
        )
    if (
        candidate.get("schema_version") != 1
        or candidate.get("contract") != "winsvpn-windows-release-candidate-v1"
        or candidate.get("canonical_release") != CANONICAL_RELEASE
        or candidate.get("product_version") != CANONICAL_PRODUCT_VERSION
        or candidate.get("four_part_version") != CANONICAL_FILE_VERSION
        or candidate.get("form_factor") != "windows-x64"
        or candidate.get("candidate_set_status") != "no_current_candidate"
        or candidate.get("arm64_targets_status") != "pending-owner-evidence"
        or type(targets) is not dict
        or set(targets) != {"windows-x64-installer", "windows-x64-partner-center"}
        or type(symbols) is not dict
        or symbols.get("x64")
        != ".artifacts/private-release-symbols/windows/x64/1.0.17+34"
        or symbols.get("arm64")
        != ".artifacts/private-release-symbols/windows/arm64/1.0.17+34"
        or symbols.get("uploaded") is not False
        or type(msix) is not dict
        or msix.get("upload_target") is not False
        or msix.get("production_allowed") is not False
        or msix.get("development_identity_only") is not True
        or msix.get("canonical_release") != CANONICAL_RELEASE
        or msix.get("package_version") != CANONICAL_FILE_VERSION
        or msix.get("architecture") != "x64"
        or msix.get("filename") != WINDOWS_MSIX_PACKAGE_FILENAME
        or type(obfuscation_receipts) is not dict
        or obfuscation_receipts != expected_obfuscation
        or type(candidate_protocol) is not dict
        or candidate_protocol.get("executed_on") != WINDOWS_TUNNEL_PROTOCOL["executed_on"]
        or candidate_protocol.get("primary") != WINDOWS_TUNNEL_PROTOCOL["primary"]
        or candidate_protocol.get("fallback") != WINDOWS_TUNNEL_PROTOCOL["fallback"]
    ):
        raise WindowsArtifactGateError(
            "Windows release candidate is not the canonical 1.0.17+34 contract."
        )
    for candidate_target, expected_name, expected_arch, expected_surface, expected_path in (
        (
            "windows-x64-installer",
            "WinsVPN-Setup.exe",
            "x64",
            "website",
            "build/windows-installer/WinsVPN-Setup.exe",
        ),
        (
            "windows-x64-partner-center",
            "WinsVPN-PartnerCenter.exe",
            "x64",
            "partner-center",
            "build/windows-installer/WinsVPN-PartnerCenter.exe",
        ),
    ):
        record = targets.get(candidate_target)
        if (
            type(record) is not dict
            or record.get("filename") != expected_name
            or record.get("architecture") != expected_arch
            or record.get("surface") != expected_surface
            or record.get("path") != expected_path
            or record.get("produced") is not False
            or record.get("upload_performed") is not False
            or record.get("publication_authorized") is not False
        ):
            raise WindowsArtifactGateError(
                "Windows release candidate is not the canonical 1.0.17+34 contract."
            )
    if target_id is not None and TARGET_ARCHITECTURES[target_id] != "x64":
        raise _owner_environment_blocker(
            f"{target_id} store metadata remains pending without owner ARM64 evidence."
        )
    certification = notes_payload.decode("ascii")
    for required in (
        "separate x64",
        "native ARM64",
        "port 80",
        "port 443",
        "9110",
        "1.0.17+34",
        "OWNER-BLOCKED: ABSENT",
    ):
        if required not in certification:
            raise WindowsArtifactGateError(
                "Windows certification notes are not the canonical 1.0.17+34 contract."
            )
    payload = {
        "canonical_release": CANONICAL_RELEASE,
        "product_version": CANONICAL_PRODUCT_VERSION,
        "four_part_version": CANONICAL_FILE_VERSION,
        "form": "windows-x64",
        "submission_approved": False,
        "upload_authorized": False,
        "msix_upload_target": False,
        "listing_screenshot_inventory": "owner-blocked",
        "private_symbols_uploaded": False,
        "obfuscation_receipts": expected_obfuscation,
        "tunnel_protocol": WINDOWS_TUNNEL_PROTOCOL,
        "files": files,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    payload["sha256"] = _sha256_bytes(encoded)
    return payload


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
        "evidence_collector",
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


def _bind_shared_upload_paths(
    shared: dict[str, tuple[str, str]], target_id: str, record: Mapping[str, object]
) -> None:
    for field in SHARED_UPLOAD_RECEIPT_PATH_FIELDS:
        value = record.get(field)
        if type(value) is not dict:
            continue
        path = _require_canonical_relative_path(
            value.get("path"), f"{target_id} {field}"
        )
        digest = _receipt_hex64(value.get("sha256"), f"{target_id} {field}")
        previous = shared.get(path)
        if previous is not None and previous[0] != digest:
            raise WindowsArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
            )
        for other_path, (other_digest, other_label) in shared.items():
            if other_digest == digest and other_path != path:
                raise WindowsArtifactGateError(
                    f"receipt reuse is refused: {target_id}.{field} reuses {other_label}"
                )
        shared[path] = (digest, f"{target_id}.{field}")


def _reject_receipt_digest_reuse(pairs: list[tuple[str, str]]) -> None:
    seen: dict[str, str] = {}
    for label, digest in pairs:
        previous = seen.get(digest)
        if previous is not None:
            raise WindowsArtifactGateError(
                f"receipt reuse is refused: {label} reuses {previous}"
            )
        seen[digest] = label


def _reject_website_signing_evidence(target_id: str, receipt: Mapping[str, object]) -> None:
    if TARGET_SURFACES.get(target_id) != "partner-center":
        return
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    folded = encoded.casefold()
    if (
        ".authenticode.json" in folded
        or WEBSITE_WINVERIFYTRUST_SCHEMA.casefold() in folded
        or "winverifytrust_receipt" in folded
        or '"windows-x64-authenticode"' in folded
        or '"windows-arm64-authenticode"' in folded
    ):
        raise WindowsArtifactGateError(WEBSITE_SIGNING_AS_PARTNER_CENTER_ERROR)


def _bind_windows_build_receipt(
    target_id: str,
    payload: bytes,
    *,
    expected_sha256: str,
    expected_bytes: int,
) -> None:
    record = _load_json_bytes(payload, f"{target_id} build receipt")
    spec = _package_upload_target(target_id)
    artifact = record.get("artifact")
    if type(artifact) is not dict:
        raise WindowsArtifactGateError(BUILD_RECEIPT_IDENTITY_ERROR)
    name = artifact.get("name")
    digest = artifact.get("sha256")
    size = artifact.get("size_bytes")
    if (
        name != TARGET_FILENAMES[target_id]
        or digest != expected_sha256
        or type(size) is not int
        or isinstance(size, bool)
        or int(size) != expected_bytes
    ):
        raise WindowsArtifactGateError(BUILD_RECEIPT_IDENTITY_ERROR)
    if (
        record.get("release") != CANONICAL_RELEASE
        or record.get("platform") != "windows"
        or record.get("publication_authorized") is not False
    ):
        raise WindowsArtifactGateError(BUILD_RECEIPT_IDENTITY_ERROR)
    toolchain = record.get("toolchain")
    receipt_target = record.get("target")
    if type(toolchain) is dict:
        receipt_target = toolchain.get("target")
    if receipt_target != spec["build_receipt_target"]:
        raise WindowsArtifactGateError(BUILD_RECEIPT_IDENTITY_ERROR)
    finished = _require_utc_timestamp(
        record.get("finished_utc"), f"{target_id} build receipt finished_utc"
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    age = (now - finished).total_seconds()
    if (
        finished > now + datetime.timedelta(seconds=MAX_BUILD_RECEIPT_FUTURE_SKEW_SECONDS)
        or age > MAX_BUILD_RECEIPT_AGE_SECONDS
    ):
        raise WindowsArtifactGateError(BUILD_RECEIPT_STALE_ERROR)


def _require_live_upload_bindings(
    target_id: str, receipt: dict[str, object], spec: dict[str, object]
) -> None:
    artifact = receipt["artifact"]
    artifact_path = str(artifact["path"])
    live_digest, live_size, payload = _hash_live_repo_file(
        artifact_path, f"{target_id} artifact", maximum=MAX_ARTIFACT_BYTES
    )
    if live_digest != artifact["sha256"] or live_size != artifact["bytes"]:
        raise WindowsArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
        )
    _verify_held_installer_bytes(
        target_id,
        artifact_path,
        payload,
        expected_sha256=str(artifact["sha256"]),
        expected_bytes=int(artifact["bytes"]),
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
            raise WindowsArtifactGateError(f"{target_id} {field} path is not exact.")
        live_digest, _live_size, _payload = _hash_live_repo_file(
            path, f"{target_id} {field}"
        )
        if live_digest != record["sha256"]:
            raise WindowsArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
            )
    for field in ("build_receipt", "source_freeze"):
        record = receipt[field]
        path = str(record["path"])
        if pathlib.PurePosixPath(path).parts[0] != ".artifacts":
            raise WindowsArtifactGateError(
                f"{target_id} {field} path must stay under .artifacts/."
            )
        live_digest, _live_size, payload = _hash_live_repo_file(
            path, f"{target_id} {field}"
        )
        if live_digest != record["sha256"]:
            raise WindowsArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
            )
        if field == "build_receipt":
            _bind_windows_build_receipt(
                target_id,
                payload,
                expected_sha256=str(artifact["sha256"]),
                expected_bytes=int(artifact["bytes"]),
            )


def _bind_package_identity(
    identity: dict[str, object], spec: dict[str, object], target_id: str
) -> None:
    product_version, file_version = _reviewed_windows_release_identity()
    architecture = TARGET_ARCHITECTURES[target_id]
    if (
        identity.get("product_version") != product_version
        or identity.get("four_part_version") != file_version
        or identity.get("architecture") != architecture
        or identity.get("filename") != spec["artifact_name"]
        or identity.get("file_description") != spec["file_description"]
        or identity.get("surface") != spec["store_surface"]
    ):
        raise WindowsArtifactGateError(
            f"{target_id} package identity is not the current 1.0.17+34 Windows identity."
        )


def _bind_obfuscation_receipt(
    target_id: str,
    reviewed: Mapping[str, object],
    *,
    artifact_sha256: str,
    artifact_bytes: int,
    artifact_name: str,
) -> None:
    receipts = reviewed.get("obfuscation_receipts")
    if type(receipts) is not dict:
        raise WindowsArtifactGateError(
            f"{target_id} store metadata is missing obfuscation receipt paths."
        )
    relative = receipts.get(target_id)
    expected = obfuscation_receipt_relative(target_id)
    if relative != expected:
        raise WindowsArtifactGateError(
            f"{target_id} obfuscation receipt path is not the current 1.0.17+34 layout."
        )
    _require_canonical_relative_path(relative, f"{target_id} obfuscation receipt")
    if pathlib.PurePosixPath(str(relative)).parts[0] != ".artifacts":
        raise WindowsArtifactGateError(
            f"{target_id} obfuscation receipt path must stay under .artifacts/."
        )
    _digest, size, payload = _hash_live_repo_file(
        str(relative), f"{target_id} obfuscation receipt"
    )
    del _digest
    record = _load_json_bytes(payload, f"{target_id} obfuscation receipt")
    artifacts = record.get("artifacts")
    if (
        record.get("schema_version") != 2
        or record.get("contract") != "winsvpn-release-obfuscation-and-secret-free-v2"
        or record.get("platform") != "windows"
        or record.get("app_version") != CANONICAL_PRODUCT_VERSION
        or record.get("build_number") != "34"
        or record.get("target_id") != target_id
        or record.get("private_symbols_not_packaged") is not True
        or type(artifacts) is not list
        or len(artifacts) != 1
        or type(artifacts[0]) is not dict
    ):
        raise WindowsArtifactGateError(
            f"{target_id} obfuscation receipt is not the current 1.0.17+34 Windows identity."
        )
    bound = artifacts[0]
    path = bound.get("path")
    if (
        type(path) is not str
        or pathlib.PurePosixPath(path).name != artifact_name
        or bound.get("sha256") != artifact_sha256
        or bound.get("size") != artifact_bytes
        or type(bound.get("size")) is not int
        or isinstance(bound.get("size"), bool)
        or size <= 0
    ):
        raise WindowsArtifactGateError(
            f"{target_id} obfuscation receipt was swapped or does not bind the exact candidate bytes."
        )


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
                "ed25519",
            }:
                raise WindowsArtifactGateError(UPLOAD_RECEIPT_PLACEHOLDER_TRUST_ERROR)
            if type(value) is str and folded.endswith("public_key"):
                if _hex_looks_like_placeholder_key(value):
                    raise WindowsArtifactGateError(UPLOAD_RECEIPT_PLACEHOLDER_TRUST_ERROR)
    try:
        dumped = json.dumps(material, ensure_ascii=True).casefold()
    except (TypeError, ValueError) as exc:
        raise WindowsArtifactGateError(UPLOAD_RECEIPT_PLACEHOLDER_TRUST_ERROR) from exc
    for marker in UPLOAD_RECEIPT_PLACEHOLDER_TRUST_MARKERS:
        if marker in dumped:
            raise WindowsArtifactGateError(UPLOAD_RECEIPT_PLACEHOLDER_TRUST_ERROR)


def owner_upload_receipt_key_blocked() -> bool:
    pin = OWNER_UPLOAD_RECEIPT_PUBLIC_KEY_HEX
    return type(pin) is not str or pin == OWNER_AUTHENTICODE_BLOCKED or re.fullmatch(
        r"[0-9a-f]{64}", pin
    ) is None


def _upload_receipt_public_key_bytes() -> bytes:
    if owner_upload_receipt_key_blocked():
        raise _owner_environment_blocker(
            "Windows package/upload receipt issuer remains OWNER-BLOCKED: ABSENT"
        )
    raw = bytes.fromhex(OWNER_UPLOAD_RECEIPT_PUBLIC_KEY_HEX)
    if len(raw) != 32:
        raise _owner_environment_blocker(
            "Windows package/upload receipt issuer remains OWNER-BLOCKED: ABSENT"
        )
    return raw


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


def _verify_upload_receipt_signature(auth: Mapping[str, object]) -> None:
    signature_hex = _require_text(auth.get("signature"), "upload receipt signature")
    if re.fullmatch(r"[0-9a-f]{128}", signature_hex) is None:
        raise WindowsArtifactGateError(UPLOAD_RECEIPT_UNAUTHENTICATED_ERROR)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise _owner_environment_blocker(
            "Windows package/upload receipt authentication requires the cryptography package"
        ) from exc
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_upload_receipt_public_key_bytes())
        public_key.verify(
            bytes.fromhex(signature_hex), _upload_receipt_canonical_bytes(auth)
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise WindowsArtifactGateError(UPLOAD_RECEIPT_UNAUTHENTICATED_ERROR) from exc


def _bind_upload_receipt_authentication(
    target_id: str,
    receipt: Mapping[str, object],
    *,
    artifact_sha256: str,
    artifact_bytes: int,
    architectures: tuple[str, ...],
    release: str,
) -> None:
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
        raise WindowsArtifactGateError(UPLOAD_RECEIPT_UNAUTHENTICATED_ERROR)
    run_id = _receipt_hex64(auth.get("run_id"), f"{target_id} upload run_id")
    nonce = _receipt_hex64(auth.get("nonce"), f"{target_id} upload nonce")
    _receipt_hex128(auth.get("challenge"), f"{target_id} upload challenge")
    issued_at = _require_utc_timestamp(
        auth.get("issued_at"), f"{target_id} upload issued_at"
    )
    now = _execution_receipt_now()
    age = (now - issued_at).total_seconds()
    if age > UPLOAD_RECEIPT_MAX_AGE_SECONDS or age < -UPLOAD_RECEIPT_FUTURE_SKEW_SECONDS:
        raise WindowsArtifactGateError(UPLOAD_RECEIPT_STALE_ERROR)
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
        raise WindowsArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
        )
    if nonce in _SEEN_UPLOAD_RECEIPT_NONCES or run_id in _SEEN_UPLOAD_RECEIPT_RUN_IDS:
        raise WindowsArtifactGateError(UPLOAD_RECEIPT_REPLAY_ERROR)
    _verify_upload_receipt_signature(auth)
    _SEEN_UPLOAD_RECEIPT_NONCES.add(nonce)
    _SEEN_UPLOAD_RECEIPT_RUN_IDS.add(run_id)


def _verify_held_installer_bytes(
    target_id: str,
    relative: str,
    payload: bytes,
    *,
    expected_sha256: str,
    expected_bytes: int,
) -> None:
    if _sha256_bytes(payload) != expected_sha256 or len(payload) != expected_bytes:
        raise WindowsArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
        )
    name = pathlib.PurePosixPath(relative).name
    if name != TARGET_FILENAMES[target_id]:
        raise WindowsArtifactGateError(f"{target_id} artifact type is not allowed.")
    _reject_source_only_installer_bytes(name, payload)
    machine, _, _ = _parse_pe_bytes(name, payload, expected_machine=None)
    _require_inno_bootstrap_machine(name, machine)
    _verify_installer_release_versions(name, payload, target_id)
    leaf = authenticode_leaf_identity(name, payload)
    custody_policy = authenticode_custody_policy(name, payload, leaf)
    _verify_outer_pe_authenticode(name, payload, custody_policy)
    _require_owner_authenticode_leaf(leaf)
    origin = _secure_repo_file(relative, f"{target_id} artifact")
    snapshot = snapshot_regular_file(
        origin, "Windows installer artifact", maximum=MAX_ARTIFACT_BYTES
    )
    try:
        if snapshot.digest != expected_sha256 or snapshot.size != expected_bytes:
            raise WindowsArtifactGateError(
                f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
            )
        proof = _verify_authenticode_offline(
            snapshot.path,
            snapshot,
            target_id=target_id,
            leaf=leaf,
        )
        _require_offline_authenticode_proof(
            proof,
            leaf,
            target_id=target_id,
            snapshot_sha256=snapshot.digest,
        )
        snapshot.assert_custody()
    finally:
        snapshot.close()


def bind_package_upload_receipt(
    target_id: str,
    record: Mapping[str, object] | bytes,
    *,
    artifact_sha256: str,
    artifact_bytes: int,
) -> dict[str, object]:
    """Bind one Windows Inno upload receipt to exact 1.0.17+34 bytes."""

    _reject_test_only_production_pass()
    spec = _package_upload_target(target_id)
    receipt = _receipt_exact_mapping(
        _receipt_document(record, f"{target_id} upload receipt"),
        set(PACKAGE_UPLOAD_RECEIPT_KEYS),
        f"{target_id} upload receipt",
    )
    _reject_false_green_selftest(receipt)
    release = canonical_windows_release()
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
        raise WindowsArtifactGateError(
            f"{target_id} receipt binding is invalid or changed."
        )
    artifact = _receipt_exact_mapping(
        receipt.get("artifact"), {"path", "sha256", "bytes"}, f"{target_id} artifact"
    )
    path = _require_canonical_relative_path(artifact.get("path"), f"{target_id} artifact")
    filename = pathlib.PurePosixPath(path).name
    expected_path = expected_upload_artifact_path(target_id)
    if (
        filename != spec["artifact_name"]
        or path != expected_path
        or not filename.lower().endswith(".exe")
    ):
        raise WindowsArtifactGateError(f"{target_id} artifact type is not allowed.")
    bound_digest = _receipt_hex64(artifact_sha256, f"{target_id} candidate bytes")
    if (
        artifact.get("sha256") != bound_digest
        or type(artifact.get("bytes")) is not int
        or isinstance(artifact.get("bytes"), bool)
        or int(artifact.get("bytes")) != artifact_bytes
        or int(artifact.get("bytes")) <= 0
    ):
        raise WindowsArtifactGateError(
            f"{target_id} receipt was swapped or does not bind the exact candidate bytes."
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
        or producer_id != spec["producer_id"]
        or producer.get("path") != spec["producer"]
    ):
        raise WindowsArtifactGateError(f"{target_id} producer id is not allowed.")
    _receipt_hex64(producer.get("sha256"), f"{target_id} producer")
    identity = _receipt_exact_mapping(
        receipt.get("package_identity"),
        set(spec["identity_keys"]),
        f"{target_id} package identity",
    )
    _bind_package_identity(identity, spec, target_id)
    architectures = receipt.get("architectures")
    if (
        type(architectures) is not list
        or tuple(architectures) != spec["architectures"]
        or len(architectures) != len(set(architectures))
    ):
        raise WindowsArtifactGateError(
            f"{target_id} architecture inventory is not exact."
        )
    signing = _receipt_exact_mapping(
        receipt.get("signing"),
        {"contract", "status"},
        f"{target_id} signing evidence",
    )
    if (
        signing.get("contract") != spec["signing_contract"]
        or signing.get("status") != spec["signing_status"]
    ):
        raise WindowsArtifactGateError(
            f"{target_id} signing evidence is not release-valid."
        )
    store = _receipt_exact_mapping(
        receipt.get("store_evidence"),
        {"surface", "status", "metadata_sha256"},
        f"{target_id} store evidence",
    )
    reviewed = _reviewed_store_metadata(target_id)
    if (
        store.get("surface") != spec["store_surface"]
        or store.get("status") != "not_uploaded"
        or store.get("metadata_sha256") != reviewed["sha256"]
    ):
        raise WindowsArtifactGateError(f"{target_id} store evidence is not exact.")
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
        ("evidence collector", receipt.get("evidence_collector")),
    ):
        if type(relative) is dict:
            relative = relative.get("path")
        _require_canonical_relative_path(relative, f"{target_id} {label}")
    if descriptor.get("path") != DESCRIPTOR_RELATIVE:
        raise WindowsArtifactGateError(f"{target_id} descriptor path is not exact.")
    if hardening.get("path") != OBFUSCATION_PRIVACY_RELATIVE:
        raise WindowsArtifactGateError(
            f"{target_id} obfuscation/privacy path is not exact."
        )
    _bind_evidence_collector(target_id, receipt)
    _bind_obfuscation_receipt(
        target_id,
        reviewed,
        artifact_sha256=bound_digest,
        artifact_bytes=int(artifact.get("bytes")),
        artifact_name=str(spec["artifact_name"]),
    )
    if pathlib.PurePosixPath(str(source.get("path"))).parts[0] != ".artifacts":
        raise WindowsArtifactGateError(
            f"{target_id} source freeze path must stay under .artifacts/."
        )
    if pathlib.PurePosixPath(str(build_receipt.get("path"))).parts[0] != ".artifacts":
        raise WindowsArtifactGateError(
            f"{target_id} build receipt path must stay under .artifacts/."
        )
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
        raise WindowsArtifactGateError(
            f"{target_id} owner authorization must remain pending without owner evidence."
        )
    _reject_receipt_digest_reuse(_bound_receipt_digest_pairs(target_id, receipt))
    _reject_website_signing_evidence(target_id, receipt)
    _require_live_upload_bindings(target_id, receipt, spec)
    _bind_upload_receipt_authentication(
        target_id,
        receipt,
        artifact_sha256=bound_digest,
        artifact_bytes=int(artifact.get("bytes")),
        architectures=tuple(spec["architectures"]),
        release=release,
    )
    _reject_test_only_production_pass()
    return {
        "ok": True,
        "target_id": target_id,
        "release": release,
        "artifact_sha256": bound_digest,
        "publication_authorized": False,
        "upload_attempted": False,
        "owner_authorization": "pending",
        "architecture": TARGET_ARCHITECTURES[target_id],
    }


def bind_windows_package_upload_receipts(
    records: Mapping[str, object],
    artifacts: Mapping[str, tuple[str, int]],
) -> dict[str, object]:
    """Bind required Windows Inno receipts, refusing reuse or approval."""

    _reject_test_only_production_pass()
    if type(records) is not dict or type(artifacts) is not dict:
        raise WindowsArtifactGateError("Windows package/upload receipt set is invalid.")
    parsed: dict[str, dict[str, object]] = {}
    for target_id, record in records.items():
        parsed[str(target_id)] = _receipt_document(
            record, f"{target_id} upload receipt"
        )
    unexpected = set(parsed) - set(WINDOWS_PACKAGE_UPLOAD_TARGETS)
    if unexpected:
        raise WindowsArtifactGateError(
            "unexpected Windows package/upload receipt target: "
            + ", ".join(sorted(unexpected))
        )
    _reject_windows_receipt_set_collisions(parsed)
    missing = [
        target_id
        for target_id in REQUIRED_WINDOWS_UPLOAD_TARGETS
        if target_id not in parsed
    ]
    if missing:
        raise _owner_environment_blocker(
            "Windows package/upload receipts remain pending without owner evidence: "
            + ", ".join(missing)
        )
    bound: dict[str, object] = {}
    for target_id, record in parsed.items():
        artifact = artifacts.get(target_id)
        if artifact is None or len(artifact) != 2:
            raise WindowsArtifactGateError(
                f"{target_id} exact candidate bytes are missing."
            )
        digest, size = artifact
        bound[target_id] = bind_package_upload_receipt(
            target_id,
            record,
            artifact_sha256=str(digest),
            artifact_bytes=int(size),
        )
    return {
        "ok": True,
        "release": CANONICAL_RELEASE,
        "required_targets": list(REQUIRED_WINDOWS_UPLOAD_TARGETS),
        "bound_targets": sorted(bound),
        "publication_authorized": False,
        "upload_attempted": False,
        "owner_authorization": "pending",
        "receipts": bound,
    }


def verify_artifact(
    target_id: str, raw_path: str, *, verify_signature: bool = True
) -> dict[str, object]:
    _reject_test_only_production_pass()
    if verify_signature is not True:
        raise WindowsArtifactGateError(OUTER_SIGNATURE_SKIP_ERROR)
    if target_id not in TARGET_FILENAMES:
        raise WindowsArtifactGateError(
            f"unsupported exact Windows target: {target_id}"
        )
    artifact = canonical_artifact(target_id, raw_path)
    architecture = TARGET_ARCHITECTURES[target_id]
    source_closure = compute_windows_installer_source_closure()
    snapshots: list[AuthenticatedSnapshot] = []
    try:
        artifact_snapshot = snapshot_regular_file(
            artifact, "Windows installer artifact", maximum=MAX_ARTIFACT_BYTES
        )
        snapshots.append(artifact_snapshot)
        artifact_snapshot.assert_custody()
        manifest_path = _manifest_path(artifact)
        manifest_snapshot = snapshot_regular_file(
            manifest_path, "Windows payload manifest", maximum=MAX_JSON_BYTES
        )
        snapshots.append(manifest_snapshot)
        manifest_snapshot.assert_custody()
        identity_path = _secure_repo_file(
            RELEASE_IDENTITY_RELATIVE_PATH.as_posix(), "Windows release identity"
        )
        identity_snapshot = snapshot_regular_file(
            identity_path, "Windows release identity", maximum=MAX_IDENTITY_BYTES
        )
        snapshots.append(identity_snapshot)
        identity_snapshot.assert_custody()
        installer_bytes = artifact_snapshot.bytes()
        bootstrap_machine, _, _ = _parse_pe_bytes(
            artifact.name, installer_bytes, expected_machine=None
        )
        _require_inno_bootstrap_machine(artifact.name, bootstrap_machine)
        product_version, file_version, file_description = (
            _verify_installer_release_versions(artifact.name, installer_bytes, target_id)
        )
        leaf = authenticode_leaf_identity(artifact.name, installer_bytes)
        custody_policy = authenticode_custody_policy(
            artifact.name, installer_bytes, leaf
        )
        _verify_outer_pe_authenticode(artifact.name, installer_bytes, custody_policy)
        _require_owner_authenticode_leaf(leaf)
        offline_proof = _verify_authenticode_offline(
            artifact_snapshot.path,
            artifact_snapshot,
            target_id=target_id,
            leaf=leaf,
        )
        _require_offline_authenticode_proof(
            offline_proof,
            leaf,
            target_id=target_id,
            snapshot_sha256=artifact_snapshot.digest,
        )
        artifact_snapshot.assert_custody()
        record = _exact_mapping(
            _load_json_bytes(manifest_snapshot.bytes(), "Windows payload manifest"),
            {
                "schema_version",
                "target_architecture",
                "distribution_surface",
                "standalone_winn3",
                "standalone_payload_verified",
                "installer",
                "producer",
                "signing",
                "release_input",
                "toolchain",
                "inno_compiler",
                "payload",
            },
            "Windows payload manifest",
        )
        if (
            _require_int(record.get("schema_version"), "schema_version") != 3
            or record.get("target_architecture") != architecture
        ):
            raise WindowsArtifactGateError(
                "Windows payload manifest does not match the target architecture v3 contract."
            )
        if record.get("distribution_surface") != TARGET_SURFACES[target_id]:
            raise WindowsArtifactGateError(
                "Windows payload manifest belongs to another exact target."
            )
        standalone_winn3 = _standalone_winn3_fact(record)
        installer = _exact_mapping(
            record.get("installer"),
            {"name", "size", "sha256"},
            "Windows installer binding",
        )
        if installer != {
            "name": artifact.name,
            "size": artifact_snapshot.size,
            "sha256": artifact_snapshot.digest,
        }:
            raise WindowsArtifactGateError(
                "Windows payload manifest does not bind the exact installer."
            )
        producer_identity = _verify_producer_schema(
            record.get("producer") if type(record.get("producer")) is dict else {},
            target_id,
        )
        _verify_release_input_schema(
            record.get("release_input") if type(record.get("release_input")) is dict else {}
        )
        _verify_toolchain_schema(
            record.get("toolchain") if type(record.get("toolchain")) is dict else {}
        )
        _verify_inno_compiler_identity(record.get("inno_compiler"), architecture)
        signing = _exact_mapping(
            record.get("signing"),
            {
                "production_signed",
                "every_loose_pe_verified",
                "staged_xray_product_signed",
                "inno_setup_and_uninstaller_signed",
                "self_signed_certificate_forbidden",
            },
            "Windows signing evidence",
        )
        _verify_signing_evidence(signing, standalone_winn3)
        inventory = _payload_inventory(record)
        _require_complete_inner_inventory(inventory, standalone_winn3, architecture)
        extracted, inner_proof_method = _prove_inner_payloads(
            artifact,
            artifact_snapshot,
            leaf,
            target_id,
            architecture,
            source_closure,
        )
        if inner_proof_method not in {INNER_PROOF_EXTRACTOR, INNER_PROOF_CAPTURE}:
            raise WindowsArtifactGateError(OWNER_INNER_PROOF_ERROR)
        verify_packed_inner_payloads(
            extracted,
            inventory,
            architecture,
            product_version,
            file_version,
            standalone_winn3,
            custody_policy=custody_policy,
        )
        artifact_snapshot.assert_custody()
        manifest_snapshot.assert_custody()
        identity_snapshot.assert_custody()
        _reject_test_only_production_pass()
        descriptor_digest = _origin_digest(
            DESCRIPTOR_RELATIVE, "Windows descriptor", maximum=MAX_SUPPORT_BYTES
        )
        result = {
            "ok": True,
            "target_id": target_id,
            "artifact": artifact.relative_to(ROOT.resolve(strict=True)).as_posix(),
            "sha256": artifact_snapshot.digest,
            "bytes": artifact_snapshot.size,
            "bootstrap_machine": bootstrap_machine,
            "target_architecture": architecture,
            "distribution_surface": TARGET_SURFACES[target_id],
            "producer_identity": producer_identity,
            "file_description": file_description,
            "descriptor": DESCRIPTOR_RELATIVE,
            "descriptor_sha256": descriptor_digest,
            "authenticode_leaf_sha256": leaf["sha256"],
            "authenticode_leaf_cn": leaf["common_name"],
            "authenticode_thumbprint": leaf["thumbprint"],
            "owner_authenticode_pin": OWNER_AUTHENTICODE_LEAF_SHA256,
            "timestamp_verified": offline_proof["timestamp_verified"] is True,
            "authenticode_digest_algorithm": offline_proof["digest_algorithm"],
            "authenticode_revocation": offline_proof["revocation"],
            "authenticode_argv": list(AUTHENTICODE_VERIFY_ARGV_PREFIX),
            "standalone_winn3": standalone_winn3,
            "product_version": product_version,
            "file_version": file_version,
            "source_closure_sha256": source_closure,
            "payload_files": len(inventory),
            "inner_payloads_proven_from_install_proof": False,
            "inner_payloads_proven_from_snapshot": inner_proof_method
            == INNER_PROOF_EXTRACTOR,
            "inner_payloads_proven_from_authenticated_capture": inner_proof_method
            == INNER_PROOF_CAPTURE,
            "packed_app_so": REQUIRED_PACKED_AOT_PATH,
            "authenticode_verified_offline": True,
            "network_accessed": False,
        }
        print(json.dumps(result, sort_keys=True))
        return result
    finally:
        for snapshot in snapshots:
            snapshot.close()


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 3 or arguments[0] != "--verify":
        raise WindowsArtifactGateError(
            "canonical cross-store usage is exactly --verify "
            "<target-id> <artifact-path>"
        )
    verify_artifact(arguments[1], arguments[2])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (WindowsArtifactGateError, OSError, ValueError) as exc:
        print(f"WINDOWS CROSS-STORE ARTIFACT GATE: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
