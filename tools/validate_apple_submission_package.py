#!/usr/bin/env python3
"""Validate local App Store Connect submission metadata drafts."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import plistlib
import re
import select
import stat
import ssl
import subprocess
import sys
import struct
import tempfile
import zipfile
import zlib
from pathlib import Path
from urllib.parse import urlparse
import urllib.request
from types import ModuleType

from release_dependency_freeze import DependencyFreezeError
from release_freeze_client import verify_build_receipt
from validate_apple_owner_signoff import (
    validate_no_stale_build_29_current_state,
    validate_owner_signoff,
    _artifact_map as owner_artifact_map,
    _pending_artifact,
    _pending_watch,
    _watch_companion,
)

import apple_store_listing_metadata as listing
import apple_watch_companion_smoke as watch_companion_smoke


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "app_store" / "apple"
METADATA = PACKAGE / "metadata" / "en-US"
ARTIFACT_MANIFEST = PACKAGE / "artifacts" / "release_candidate.json"
RUNTIME_EVIDENCE_MANIFEST = PACKAGE / "artifacts" / "runtime_evidence.json"
ROLLOUT_READINESS_MANIFEST = PACKAGE / "review" / "rollout_readiness.json"
PRIVACY_LABEL_MANIFEST = PACKAGE / "review" / "privacy_label_manifest.json"
OWNER_REVIEW_PACKET = PACKAGE / "review" / "owner_review_packet.md"
APP_REVIEW_SUBMISSION_TOOL = ROOT / "tools" / "apple_submit_for_app_review.py"
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
SUBMISSION_JSON_MAX_BYTES = 8 * 1024 * 1024


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
    def __init__(self, path: Path, label: str) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.label = label
        self._records: list[tuple[int | None, str, int, os.stat_result, bool]] = []
        self._queue: object | None = None
        self._closed = False
        self._file_fd = -1
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
        if not self.path.is_absolute() or directory_flag == 0 or nofollow_flag == 0:
            raise AssertionError(f"{label} requires absolute O_NOFOLLOW source custody")
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
                raise AssertionError(f"{self.label} ancestor is not a directory")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(fd)
            raise AssertionError(f"{self.label} source is not a single-link regular file")
        self._records.append((parent_fd, name, fd, info, directory))

    def _start_watch(self) -> None:
        if not hasattr(select, "kqueue"):
            if sys.platform == "darwin":
                raise AssertionError(f"{self.label} ancestor watch is unavailable")
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
            raise AssertionError(f"{self.label} source size is invalid")
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
            raise AssertionError(f"{self.label} source changed while it was read")
        return bytes(payload)

    def _reject_events(self) -> None:
        if self._queue is not None and self._queue.control(
            None, max(1, len(self._records) * 2), 0
        ):
            raise AssertionError(
                f"{self.label} source or trusted ancestor changed during execution"
            )

    def verify(self) -> None:
        if self._closed:
            raise AssertionError(f"{self.label} source custody is closed")
        self._reject_events()
        for parent_fd, name, fd, before, directory in self._records:
            identity = _reviewed_directory_identity if directory else _reviewed_file_identity
            if identity(os.fstat(fd)) != identity(before):
                raise AssertionError(f"{self.label} retained source identity changed")
            if parent_fd is not None:
                try:
                    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except OSError as exc:
                    raise AssertionError(
                        f"{self.label} source or trusted ancestor path disappeared"
                    ) from exc
                if identity(named) != identity(before):
                    raise AssertionError(
                        f"{self.label} source or trusted ancestor path was replaced"
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
        for _parent, _name, fd, _before, _directory in reversed(self._records):
            try:
                os.close(fd)
            except OSError:
                pass
        self._records.clear()
        self._file_fd = -1
        if error is not None:
            raise error


def _load_reviewed_helper(path: Path, expected_sha256: str, label: str) -> ModuleType:
    custody = _ReviewedSourceCustody(path, label)
    module: ModuleType | None = None
    module_name = ""
    completed = False
    try:
        payload = custody.payload()
        digest = hashlib.sha256(payload).hexdigest()
        if digest != expected_sha256:
            raise AssertionError(f"{label} source hash is not reviewed")
        try:
            code = compile(payload, str(custody.path), "exec", dont_inherit=True)
        except (SyntaxError, ValueError) as exc:
            raise AssertionError(f"{label} reviewed source could not be compiled") from exc
        module_name = f"_winsvpn_reviewed_{label}_{digest}_{id(payload):x}"
        if module_name in sys.modules:
            raise AssertionError(f"{label} isolated module name is already occupied")
        module = ModuleType(module_name)
        module.__file__ = str(custody.path)
        module.__package__ = ""
        module.__winsvpn_source_sha256__ = digest
        module.__winsvpn_reviewed_origin_root__ = str(custody.path.parents[1])
        module.__winsvpn_reviewed_tools_dir__ = str(custody.path.parent)
        sys.modules[module_name] = module
        exec(code, module.__dict__)
        if sys.modules.get(module_name) is not module:
            raise AssertionError(f"{label} isolated module identity changed")
        custody.verify()
        completed = True
        return module
    finally:
        if module is not None and sys.modules.get(module_name) is module:
            del sys.modules[module_name]
        custody.close(verify=completed)

TEXT_LIMITS = {
    "name.txt": 30,
    "subtitle.txt": 30,
    "promotional_text.txt": 170,
    "keywords.txt": 100,
    "description.txt": 4000,
    "release_notes.txt": 4000,
    "copyright.txt": 500,
}

FROZEN_MARKETING_COPY_FILES = (
    "description.txt",
    "promotional_text.txt",
    "release_notes.txt",
)

FROZEN_MARKETING_COPY_SHA256 = {
    "description.txt": "a96f8de48d8b2c61cba99e519fa3ef64f138f7d1224b20c174c7e641d7022f42",
    "promotional_text.txt": "37ad9d68f437b4d3fd32fb8d4a7f3ea3b3091a3847289424ab735f28b4bd362a",
    "release_notes.txt": "4071fabddc8d686243385f48c654cc0220f401b9cc27739f96cb5f4655d60efd",
}

FROZEN_MARKETING_COPY_LENGTH = {
    "description.txt": 2669,
    "promotional_text.txt": 136,
    "release_notes.txt": 750,
}

URL_FILES = {
    "support_url.txt",
    "marketing_url.txt",
    "privacy_url.txt",
}

OWNER_PACKET_METADATA_HASH_FILES = [
    METADATA / "name.txt",
    METADATA / "subtitle.txt",
    METADATA / "promotional_text.txt",
    METADATA / "description.txt",
    METADATA / "keywords.txt",
    METADATA / "release_notes.txt",
    METADATA / "copyright.txt",
    METADATA / "support_url.txt",
    METADATA / "marketing_url.txt",
    METADATA / "privacy_url.txt",
    PACKAGE / "metadata" / "app_information.md",
    PACKAGE / "metadata" / "pricing_availability.md",
    PACKAGE / "review" / "app_review_information.md",
    PACKAGE / "testflight" / "test_information.md",
]

LIVE_URL_MARKERS = {
    "support_url.txt": [
        "Win's VPN Support",
        "Get help with setup",
        "Email support",
        "Business phone",
        "winsvpn dot org",
    ],
    "marketing_url.txt": [
        "Win's VPN",
        "Get Win's VPN",
    ],
    "privacy_url.txt": [
        "privacy-policy",
        "Verified No Log Policy",
        "Win's VPN",
    ],
}

REQUIRED_REVIEW_FILES = [
    PACKAGE / "README.md",
    PACKAGE / "metadata" / "app_information.md",
    PACKAGE / "metadata" / "pricing_availability.md",
    PACKAGE / "review" / "age_rating_answers.md",
    PACKAGE / "review" / "accessibility_evidence.md",
    PACKAGE / "review" / "app_review_information.md",
    PACKAGE / "review" / "ios_review_notes.txt",
    PACKAGE / "review" / "macos_review_notes.txt",
    PACKAGE / "review" / "export_compliance_facts.txt",
    PACKAGE / "review" / "privacy_answers.md",
    PACKAGE / "review" / "privacy_label_manifest.json",
    PACKAGE / "review" / "export_compliance_status.json",
    PACKAGE / "review" / "apple_tv_post_release_scope.json",
    PACKAGE / "review" / "owner_signoff.json",
    OWNER_REVIEW_PACKET,
    PACKAGE / "review" / "rollout_readiness.json",
    PACKAGE / "screenshots" / "screenshot_plan.md",
    PACKAGE / "testflight" / "test_information.md",
    APP_REVIEW_SUBMISSION_TOOL,
]

REQUIRED_CONTENT_MARKERS = {
    PACKAGE / "metadata" / "app_information.md": [
        "SKU: winsvpn-apple-20260709",
        "Primary Category: Utilities",
        "Bundle ID, iOS: org.winsvpn.app",
        "Bundle ID, macOS: org.winsvpn.app",
        "Support URL: https://www.winsvpn.org/support/",
        "Privacy Policy URL: https://www.winsvpn.org/privacy/",
        "Apple Watch: embedded",
        "not in this release",
    ],
    PACKAGE / "metadata" / "pricing_availability.md": [
        "App price: Free.",
        "In-App Purchases: None",
        "Manual release after approval",
    ],
    PACKAGE / "review" / "app_review_information.md": [
        "Try Free Server",
        "org.winsvpn.app.PacketTunnel",
        "universal-purchase",
        "https://www.winsvpn.org/support/",
        "support@winsvpn.org",
    ],
    PACKAGE / "review" / "age_rating_answers.md": [
        "No embedded web browser",
        "VPN/network utility",
        "owner review",
    ],
    PACKAGE / "review" / "accessibility_evidence.md": [
        "zero accessibility declaration resources",
        "Claims Not Yet Proven For Publication",
        "Leave all App Accessibility claims unpublished for build "
        f"`{listing.CANONICAL_BUNDLE_VERSION}`",
        "activation workflow exposes semantic names and control roles",
    ],
    PACKAGE / "review" / "export_compliance_facts.txt": [
        "The app is a VPN client.",
        "ITSAppUsesNonExemptEncryption",
        "Unsigned, ad-hoc",
    ],
    PACKAGE / "review" / "export_compliance_status.json": [
        "\"status\": \"approved\"",
        "\"counsel_review_status\": \"pending\"",
        "\"filings_status\": \"none_filed\"",
        "unsigned_artifact_may_carry_declaration",
        "embedded_watchos_companion",
    ],
    PACKAGE / "review" / "apple_tv_post_release_scope.json": [
        "not_in_this_release",
        "must_not_reuse_ios_artifact",
        "unbound_not_shipping",
        "refused_not_a_current_target",
    ],
    PACKAGE / "testflight" / "test_information.md": [
        "Try Free Server",
        "support@winsvpn.org",
        "No demo credentials",
    ],
    OWNER_REVIEW_PACKET: [
        "Apple Owner Review Packet",
        "submission_approved",
        "Do not paste Apple API keys",
        "WINS_APPLE_AUTHENTICATION_KEY_PATH",
        "final_upload_authorization",
        "Release Candidate Artifacts",
        "Candidate Screenshots",
        "Runtime Evidence",
        "Full source-readiness log",
    ],
    APP_REVIEW_SUBMISSION_TOOL: [
        "EXPECTED_SUBMIT_CONFIRMATION",
        "APP_VERSION.replace('.', '_')",
        "require_build_encryption_declarations",
        "non_app_store_version_item_count",
        "same-run cleanup completed",
    ],
}

SCREENSHOT_SPECS = {
    PACKAGE
    / "screenshots"
    / "candidates"
    / "ios-6_9"
    / "01-main.png": {
        (1260, 2736),
        (2736, 1260),
        (1290, 2796),
        (2796, 1290),
        (1320, 2868),
        (2868, 1320),
    },
    PACKAGE
    / "screenshots"
    / "candidates"
    / "macos-16_10"
    / "01-main.png": {
        (1280, 800),
        (1440, 900),
        (2560, 1600),
        (2880, 1800),
    },
}

SCREENSHOT_VISUAL_MIN_LUMINANCE_RANGE = 48
SCREENSHOT_VISUAL_MIN_COLOR_BINS = 24
SCREENSHOT_VISUAL_MIN_OPAQUE_FRACTION = 0.995

VERIFICATION_LOG_MARKERS = {
    ("ios", "app_store_local", "ipa"): [
        "Verified existing iOS App Store local export metadata",
        "Exported existing iOS App Store local app: verified Apple engine artifacts",
        # apple_runtime_smoke.sh prints " plus watch companion" for the iOS layout
        # since the embedded Watch app became a required payload.
        "Exported existing iOS App Store local app: host app and embedded PacketTunnel plus watch companion verified",
        "Verified iOS App Store local IPA payload app",
        "Verified existing iOS App Store local IPA",
        "valid on disk",
        "satisfies its Designated Requirement",
    ],
    ("macos", "app_store_local", "pkg"): [
        "Verified existing macOS App Store local export metadata",
        "macOS App Store local package PackageInfo metadata verified",
        "macOS App Store local package Distribution metadata verified",
        "Exported existing macOS App Store local app: verified Apple engine artifacts",
        "Exported existing macOS App Store local app: host app and embedded PacketTunnel verified",
        "Verified macOS App Store local package payload app",
        "Verified existing macOS App Store local package",
        "valid on disk",
        "satisfies its Designated Requirement",
    ],
}

ARCHIVE_EXPORT_LOG_MARKERS = [
    "Exported iOS App Store local IPA: build/apple/exports/ios-app-store-local/Win's VPN.ipa",
    "Exported macOS App Store local package: build/apple/exports/macos-app-store-local/Win's VPN.pkg",
]

IOS_COMPILED_ICON_VERIFICATION_CONTRACT = "ios_compiled_app_icon_asset_catalog_v1"
IOS_COMPILED_ICON_VERIFICATION_MARKER = (
    "Exported existing iOS App Store local app: "
    "compiled iOS AppIcon and CalculatorIcon asset catalogs verified"
)
ARTIFACT_SOURCE_FINGERPRINT_CONTRACT = "apple_release_runtime_sources_v2"

RUNTIME_LOG_MARKERS = [
    "Apple live tunnel smoke result: status=passed passed=True probe_ok=True disconnect_ok=True",
    "Physical iOS live tunnel smoke sanitized stdout log",
    "Apple signing keychain probe: passed",
    "Bundled AWG/Xray engine artifact gate: passed",
]
RUNTIME_IOS_PERMISSION_UI_SUCCESS_MARKER = "** TEST SUCCEEDED **"
RUNTIME_IOS_PERMISSION_DIRECT_PASS_MARKERS = [
    "Physical iOS live tunnel smoke: passed.",
    "Physical iOS live tunnel smoke sanitized stdout log",
]

CURRENT_APPLE_BUNDLE_IDS = {
    "ios": ("org.winsvpn.app", "org.winsvpn.app.PacketTunnel"),
    "macos": ("org.winsvpn.app", "org.winsvpn.app.PacketTunnel"),
}
CURRENT_RELEASE_CANDIDATE_BUNDLE_IDS = dict(CURRENT_APPLE_BUNDLE_IDS)
CURRENT_ARTIFACT_STATUS = "current_candidate"
SUPERSEDED_MACOS_ARTIFACT_STATUS = "superseded_pending_universal_rebuild"
RUNTIME_NOT_STARTED_CANDIDATE_SET_STATUS = "pending_current_runtime_evidence"
RUNTIME_PENDING_CANDIDATE_SET_STATUS = "partial_pending_universal_macos_rebuild"
RUNTIME_COMPLETE_CANDIDATE_SET_STATUS = "complete_current_candidates"
RUNTIME_CANDIDATE_SET_STATUSES = {
    RUNTIME_NOT_STARTED_CANDIDATE_SET_STATUS,
    RUNTIME_PENDING_CANDIDATE_SET_STATUS,
    RUNTIME_COMPLETE_CANDIDATE_SET_STATUS,
}
RUNTIME_NOT_STARTED_PENDING_REASONS = list(listing.RUNTIME_NOT_STARTED_PENDING_REASONS)
RUNTIME_MACOS_LOG_MARKERS = [
    "Apple live tunnel smoke result: status=passed passed=True probe_ok=True disconnect_ok=True",
    "Apple live tunnel smoke sanitized result:",
    "Apple live tunnel smoke sanitized stdout log:",
    "Apple signing keychain probe: passed.",
    "Apple live tunnel smoke: passed.",
    "Bundled AWG/Xray engine artifact gate: passed.",
]

RUNTIME_STDOUT_RESULT_PREFIX = "WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT "

RUNTIME_EXPECTED_FIELDS = {
    "status",
    "passed",
    "disconnect_ok",
    "local_state_restored",
    "external_leak_audit_requested",
    "external_leak_audit_attempted",
    "external_leak_audit_passed",
    "external_leak_audit_endpoint_count",
    "external_leak_audit_minimum_endpoint_count",
    "external_leak_audit_success_count",
    "external_leak_audit_failure_count",
    "external_leak_audit_transport_error_count",
    "external_leak_audit_server_error_count",
    "external_leak_audit_invalid_endpoint_count",
    "external_leak_audit_https_canary_count",
    "external_leak_audit_dns_canary_count",
    "external_leak_audit_non_google_cloudflare_only",
    "external_leak_audit_blocked_by_configuration",
    "external_leak_audit_url_kind",
    "leak_protection_config_passed",
    "internet_probe_ok",
    "internet_probe_status_code",
}

RUNTIME_REQUIRED_TRUE_FIELDS = [
    "secret_material_redacted",
    "active",
    "connected",
    "ready",
    "readiness_available",
    "provider_status_available",
    "provider_status_current",
    "provider_ready",
    "provider_healthy",
    "provider_engine_ready",
    "provider_network_settings_ready",
    "provider_message_probe_accepted",
    "provider_message_probe_engine_running",
    "provider_message_probe_healthy",
    "network_extension_connected",
    "internet_probe_attempted",
    "internet_probe_available",
    "leak_protection_config_checked",
    "leak_protection_provider_status_current",
    "leak_protection_default_route_enabled",
    "leak_protection_ipv6_enabled",
    "leak_protection_engine_ipv6_enabled",
    "leak_protection_dns_full_tunnel_match_enabled",
    "leak_protection_engine_dns_full_tunnel_match_enabled",
    "disconnect_attempted",
]

RUNTIME_REQUIRED_FALSE_FIELDS = [
    "internet_probe_blocked_by_leak_protection_config",
    "internet_probe_blocked_by_provider_readiness",
    "vpn_configuration_permission_pending",
    "vpn_manager_invalid_after_config_save",
]

RUNTIME_REQUIRED_STRING_FIELDS = {
    "smoke": "apple_live_tunnel",
    "phase": "connected_probe_complete",
    "native_tunnel_status": "connected",
    "provider_stage": "app_message",
    "internet_probe_url_kind": "public_https",
    "internet_probe_summary": "internet_probe_ok",
    "leak_protection_config_kind": "full_tunnel_route_dns_ipv6",
}

RUNTIME_REQUIRED_EMPTY_STRING_FIELDS = [
    "internet_probe_error",
    "internet_probe_native_error_code",
    "internet_probe_native_error_domain",
]

RUNTIME_FORBIDDEN_MANIFEST_MARKERS = [
    "BEGIN PRIVATE KEY",
    "AuthKey_",
    "WINS_APPLE_AUTHENTICATION_KEY_ID=",
    "WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID=",
    "client_private_key",
    "Password:",
    "ssh root@",
    "https://www.wikipedia.org",
    "https://www.gnu.org",
    "wikipedia.org",
    "gnu.org",
]

ROLLOUT_REQUIRED_SOURCE_LOG_MARKERS = [
    "PASS: owner sign-off approved-value marker self-test rejected 18 vague approvals",
    "PASS: owner approval dry-run validated 18 packet values against the current owner gate",
    "PASS: owner approval dry-run left the real owner_signoff.json",
    "PASS: upload lanes run the full Apple submission package validator",
    "Apple native XCTest source gate passed with ",
    "iOS native XCTest passed with ",
    "macOS native XCTest passed with ",
    "All tests passed!",
    "Apple source checks completed.",
]

ROLLOUT_NEGATIVE_LOG_MARKERS = {
    "missing_auth": (
        "App Store Connect upload lanes require "
        "WINS_APPLE_AUTHENTICATION_KEY_PATH"
    ),
    "pending_owner_signoff": (
        "owner_signoff.json submission_approved must be true before upload"
    ),
}

ROLLOUT_EXPECTED_MANIFEST_PATHS = {
    "release_candidate_manifest": "app_store/apple/artifacts/release_candidate.json",
    "runtime_evidence_manifest": "app_store/apple/artifacts/runtime_evidence.json",
    "owner_signoff_manifest": "app_store/apple/review/owner_signoff.json",
}

ROLLOUT_BASE_BLOCKERS = {
    "apple_processing_and_review",
    "digital_services_act_trader_verification",
    "encryption_export_documentation",
}
ROLLOUT_UPLOAD_GATE = "testflight_or_app_store_upload"
ROLLOUT_API_AUTH_GATE = "app_store_connect_api_auth"
ROLLOUT_API_ACCESS_READY_STATUS = "configured_external_and_api_verified"
ROLLOUT_API_ACCESS_PENDING_STATUS = "pending_external_credentials_refresh"

ROLLOUT_MACOS_PKG_GATE = "macos_pkg_clean_install"
ROLLOUT_MACOS_PKG_PENDING_STATUS = "pending_clean_system_install"
ROLLOUT_DSA_GATE = "digital_services_act_trader_verification"
ROLLOUT_ENCRYPTION_GATE = "encryption_export_documentation"

ROLLOUT_OWNER_PENDING_BLOCKERS = {
    "owner_signoff",
    "final_metadata_privacy_review",
}

ROLLOUT_REQUIRED_ENV = [
    "WINS_APPLE_AUTHENTICATION_KEY_PATH",
    "WINS_APPLE_AUTHENTICATION_KEY_ID",
    "WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID",
]

ROLLOUT_MACOS_PKG_LOG_MARKERS = [
    "Package \"Win's VPN.pkg\"",
    "macOS App Store local package PackageInfo metadata verified",
    "macOS App Store local package Distribution metadata verified",
    "Verified macOS App Store local package payload app",
]

ROLLOUT_MACOS_PKG_AUTHORIZATION_BOUNDARY_MARKERS = [
    "requires root or non-interactive sudo",
    "requires root, non-interactive sudo, or WINS_MACOS_APP_STORE_PKG_INSTALL_GUI_AUTH=1",
    "administrator-authorized installer -pkg",
    "ERROR: macOS App Store package install smoke did not install Win's VPN.app into /Applications.",
]

ROLLOUT_MACOS_PKG_SUCCESS_MARKERS = [
    *ROLLOUT_MACOS_PKG_LOG_MARKERS,
    "Installed macOS App Store local app: verified Apple engine artifacts",
    "Installed macOS App Store local app: host app and embedded PacketTunnel verified "
    "(org.winsvpn.app / org.winsvpn.app.PacketTunnel; MacOSX Mach-O)",
    "Installed and verified macOS App Store local package on clean system volume",
    "Current macOS App Store package clean-install verification completed",
]

PRIVACY_REQUIRED_DATA_TYPES = {
    "NSPrivacyCollectedDataTypeCoarseLocation",
    "NSPrivacyCollectedDataTypeDeviceID",
    "NSPrivacyCollectedDataTypeUserID",
    "NSPrivacyCollectedDataTypeProductInteraction",
}

PRIVACY_REQUIRED_LABELS = {
    "Coarse Location",
    "Device ID",
    "User ID",
    "Product Interaction",
}

PRIVACY_APP_FUNCTIONALITY_PURPOSE = (
    "NSPrivacyCollectedDataTypePurposeAppFunctionality"
)

PRIVACY_PRODUCT_INTERACTION = "NSPrivacyCollectedDataTypeProductInteraction"
PRIVACY_PURCHASE_HISTORY = "NSPrivacyCollectedDataTypePurchaseHistory"

PRIVACY_LINKED_CATEGORIES = {
    "NSPrivacyCollectedDataTypeCoarseLocation": "Location",
    "NSPrivacyCollectedDataTypeDeviceID": "Identifiers",
    "NSPrivacyCollectedDataTypeUserID": "Identifiers",
    "NSPrivacyCollectedDataTypeProductInteraction": "Usage Data",
}

PRIVACY_LINKED_LABELS = {
    "NSPrivacyCollectedDataTypeCoarseLocation": "Coarse Location",
    "NSPrivacyCollectedDataTypeDeviceID": "Device ID",
    "NSPrivacyCollectedDataTypeUserID": "User ID",
    "NSPrivacyCollectedDataTypeProductInteraction": "Product Interaction",
}

PRIVACY_HOST_ARCHIVE_MARKDOWN = (
    "collected data: NSPrivacyCollectedDataTypeCoarseLocation, "
    "NSPrivacyCollectedDataTypeDeviceID, "
    "NSPrivacyCollectedDataTypeProductInteraction, "
    "NSPrivacyCollectedDataTypeUserID"
)

LIVE_PORTAL_STALE_MESSAGE = (
    "live App Store Connect privacy labels are stale; "
    "add Product Interaction; remove Purchase History. "
    "This gate does not claim App Store Connect was updated."
)

PRIVACY_FILE_TIMESTAMP_API = "NSPrivacyAccessedAPICategoryFileTimestamp"
PRIVACY_USER_DEFAULTS_API = "NSPrivacyAccessedAPICategoryUserDefaults"
PRIVACY_SYSTEM_BOOT_TIME_API = "NSPrivacyAccessedAPICategorySystemBootTime"
PRIVACY_FILE_TIMESTAMP_REASON = "C617.1"
PRIVACY_USER_DEFAULTS_REASON = "CA92.1"
PRIVACY_SYSTEM_BOOT_TIME_REASON = "35F9.1"

PRIVACY_HOST_ACCESSED_APIS: dict[str, frozenset[str]] = {
    PRIVACY_FILE_TIMESTAMP_API: frozenset({PRIVACY_FILE_TIMESTAMP_REASON}),
    PRIVACY_USER_DEFAULTS_API: frozenset({PRIVACY_USER_DEFAULTS_REASON}),
    PRIVACY_SYSTEM_BOOT_TIME_API: frozenset({PRIVACY_SYSTEM_BOOT_TIME_REASON}),
}
PRIVACY_WATCH_ACCESSED_APIS: dict[str, frozenset[str]] = {}

PRIVACY_CUSTOM_ENGINE_FRAMEWORKS = (
    "WinsAmneziaWGPacketEngine",
    "WinsXrayVlessWsTransport",
    "WinsWinnPacketEngine",
)
PRIVACY_WINN_ENGINE_FRAMEWORK = "WinsWinnPacketEngine"
PRIVACY_ENGINE_SOURCE_FILES = {
    "WinsAmneziaWGPacketEngine": (
        ROOT / "apple" / "EngineWrappers" / "WinsAmneziaWGPacketEngine.m"
    ),
    "WinsXrayVlessWsTransport": (
        ROOT / "apple" / "EngineWrappers" / "WinsXrayVlessWsTransport.m"
    ),
    "WinsWinnPacketEngine": (
        ROOT / "apple" / "EngineWrappers" / "WinsWinnPacketEngine.m"
    ),
}
PRIVACY_PACKET_TUNNEL_SOURCE_ROOTS = (
    ROOT / "ios" / "PacketTunnel",
    ROOT / "macos" / "PacketTunnel",
)
PRIVACY_SOURCE_SCAN_SUFFIXES = {".c", ".h", ".m", ".mm", ".swift"}
PRIVACY_MACH_ABSOLUTE_TIME_IMPORT_RE = re.compile(
    r"\b(?:mach_absolute_time|clock_gettime_nsec_np)\b"
)

PRIVACY_SOURCE_MANIFESTS = {
    "ios_host": ("ios/Runner/PrivacyInfo.xcprivacy", "host"),
    "ios_packet_tunnel": ("ios/PacketTunnel/PrivacyInfo.xcprivacy", "tunnel"),
    "ios_watch": ("ios/WinsWatch Watch App/PrivacyInfo.xcprivacy", "watch"),
    "macos_host": ("macos/Runner/PrivacyInfo.xcprivacy", "host"),
    "macos_packet_tunnel": ("macos/PacketTunnel/PrivacyInfo.xcprivacy", "tunnel"),
}

PRIVACY_REQUIRED_DOC_MARKERS = {
    PACKAGE / "review" / "privacy_answers.md": [
        "Data Used to Track You: No",
        "Tracking domains: none",
        "Identifiers: User ID",
        "Identifiers: Device ID",
        "Coarse Location: linked to the user for app functionality",
        "Usage Data: Product Interaction",
        "Purchase History: **not collected by the Apple app.**",
        "PacketTunnel extension",
    ],
    ROOT / "docs" / "APPLE_APP_PRIVACY_LABEL_AUDIT.md": [
        "Data Used to Track You: No",
        "Identifiers: User ID",
        "Identifiers: Device ID",
        "Coarse Location: linked to the user for app functionality",
        "Usage Data: Product Interaction",
        "Purchase History: not collected by the Apple app",
        "No analytics, ads, or crash-reporting SDK",
        "Premium Access Info button opens the developer's home page, https://www.winsvpn.org",
        "Generate Xcode privacy report",
        "App Store Connect",
    ],
}

RUNTIME_FORBIDDEN_PAYLOAD_MARKERS = [
    "BEGIN PRIVATE KEY",
    "AuthKey_",
    "WINS_APPLE_AUTHENTICATION_KEY_ID=",
    "WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID=",
    "client_private_key",
    "PrivateKey",
    "PresharedKey",
    "Password:",
    "ssh root@",
    "http://",
    "https://",
    "/Users/",
    "/private/",
    "/var/",
    "/tmp/",
    "[Interface]",
    "[Peer]",
    "AllowedIPs",
    "Endpoint",
]

IPV4_LITERAL_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
UUID_LITERAL_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def read_text(path: Path, *, max_bytes: int | None = None) -> str:
    try:
        if max_bytes is None:
            text = path.read_text(encoding="utf-8")
        else:
            with path.open("rb") as handle:
                payload = handle.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise AssertionError(f"JSON input exceeds byte ceiling: {path}")
            text = payload.decode("utf-8", errors="strict")
    except FileNotFoundError:
        raise AssertionError(f"missing required file: {path.relative_to(ROOT)}")
    except UnicodeDecodeError as exc:
        raise AssertionError(f"required file is not strict UTF-8: {path}") from exc
    if not text.strip():
        raise AssertionError(f"empty required file: {path.relative_to(ROOT)}")
    return text


def _strict_json_loads(
    text: str,
    label: str,
    *,
    max_bytes: int = SUBMISSION_JSON_MAX_BYTES,
) -> object:
    encoded = text.encode("utf-8", errors="strict")
    if not encoded or len(encoded) > max_bytes:
        raise AssertionError(f"{label} JSON size is invalid")

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise AssertionError(f"{label} JSON contains duplicate key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise AssertionError(f"{label} JSON contains non-finite value {value}")

    def strict_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise AssertionError(f"{label} JSON contains non-finite value {value}")
        return parsed

    try:
        return json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
            parse_float=strict_float,
        )
    except AssertionError:
        raise
    except json.JSONDecodeError as exc:
        raise AssertionError(f"{label} is not valid JSON: {exc}") from exc


def read_json(path: Path) -> object:
    text = read_text(path, max_bytes=SUBMISSION_JSON_MAX_BYTES)
    try:
        label = path.relative_to(ROOT).as_posix()
    except ValueError:
        label = os.fspath(path)
    return _strict_json_loads(text, label)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_durable_receipt_evidence_file(path_text: object, label: str) -> Path:
    """Resolve an owner-only, non-symbolic evidence file below ``.artifacts``."""
    relative = Path(str(path_text or ""))
    if relative.is_absolute() or ".." in relative.parts:
        raise AssertionError(f"{label} must be a repository-relative .artifacts path")
    if len(relative.parts) < 3 or relative.parts[0] != ".artifacts":
        raise AssertionError(f"{label} must be a durable repository .artifacts path")

    expected_uid = os.getuid() if hasattr(os, "getuid") else None
    if expected_uid is None:
        raise AssertionError(f"{label} owner verification requires a Unix host")
    current = ROOT
    for index, part in enumerate(relative.parts):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise AssertionError(f"{label} evidence file does not exist: {relative}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise AssertionError(f"{label} must not traverse a symbolic link: {relative}")
        is_final = index == len(relative.parts) - 1
        if is_final:
            if not stat.S_ISREG(metadata.st_mode):
                raise AssertionError(f"{label} must be a regular evidence file")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise AssertionError(f"{label} parent must be a directory")
        if metadata.st_uid != expected_uid:
            raise AssertionError(f"{label} path is not owned by the current user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AssertionError(f"{label} path is not owner-only")

    artifacts_root = (ROOT / ".artifacts").resolve(strict=True)
    try:
        current.resolve(strict=True).relative_to(artifacts_root)
    except ValueError as exc:
        raise AssertionError(f"{label} escapes repository .artifacts") from exc
    if current.stat().st_size <= 0:
        raise AssertionError(f"{label} evidence file is empty")
    return current


def require_hashed_durable_file(
    path_value: object,
    sha_value: object,
    label: str,
) -> Path:
    path = require_durable_receipt_evidence_file(path_value, label)
    expected = str(sha_value or "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise AssertionError(f"{label} SHA-256 must be lowercase hexadecimal")
    actual = sha256_file(path)
    if actual != expected:
        raise AssertionError(
            f"{label} SHA-256 mismatch: expected {expected}, got {actual}"
        )
    return path


def validate_formal_build_receipt_binding(
    platform: str,
    artifact: dict[str, object],
    artifact_path: Path,
    release_input_index: Path,
    verified_result: dict[str, object] | None = None,
) -> None:
    receipt = require_hashed_durable_file(
        artifact.get("build_receipt"),
        artifact.get("build_receipt_sha256"),
        f"{platform} build receipt",
    )
    anchor = require_hashed_durable_file(
        artifact.get("build_receipt_anchor"),
        artifact.get("build_receipt_anchor_sha256"),
        f"{platform} build receipt anchor",
    )
    if anchor != receipt.with_name(receipt.name + ".sha256"):
        raise AssertionError(f"{platform} build receipt anchor path is not canonical")
    if verified_result is not None:
        # The freeze verified this receipt on the clean tree moments before it
        # wrote the (tracked) candidate manifest; re-running the worker now
        # would only see the freeze's own uncommitted manifest as dirty source.
        # Every binding below is still checked against that verified result.
        result = verified_result
    else:
        try:
            result = verify_build_receipt(
                ROOT,
                release_input_index,
                platform,
                receipt,
                artifact_path,
            )
        except (DependencyFreezeError, OSError, ValueError, json.JSONDecodeError) as exc:
            raise AssertionError(
                f"{platform} formal build receipt verification failed: {exc}"
            ) from exc
    expected_values = {
        "receipt_sha256": artifact.get("build_receipt_sha256"),
        "artifact_sha256": artifact.get("sha256"),
        "artifact_size_bytes": artifact.get("size_bytes"),
        "artifact_input_fingerprint_sha256": artifact.get(
            "artifact_input_fingerprint_sha256"
        ),
        "platform_manifest_sha256": artifact.get("platform_manifest_sha256"),
    }
    for field, expected in expected_values.items():
        if result.get(field) != expected:
            raise AssertionError(
                f"{platform} formal build receipt {field} binding changed"
            )


def pubspec_version() -> tuple[str, str]:
    pubspec = ROOT / "pubspec.yaml"
    for line in read_text(pubspec).splitlines():
        if not line.strip().startswith("version:"):
            continue
        value = line.split(":", 1)[1].strip()
        if "+" not in value:
            raise AssertionError("pubspec.yaml version must include a build number")
        version, build = value.split("+", 1)
        return version.strip(), build.strip()
    raise AssertionError("pubspec.yaml missing version field")


def validate_metadata_lengths() -> list[str]:
    messages: list[str] = []
    for filename, limit in TEXT_LIMITS.items():
        path = METADATA / filename
        text = read_text(path).strip()
        length = len(text)
        if length > limit:
            raise AssertionError(
                f"{path.relative_to(ROOT)} is {length} chars, limit {limit}"
            )
        messages.append(f"PASS: {filename} length {length}/{limit}")
    return messages


def validate_frozen_marketing_copy() -> list[str]:
    messages: list[str] = []
    expected_files = set(FROZEN_MARKETING_COPY_FILES)
    if set(FROZEN_MARKETING_COPY_SHA256) != expected_files:
        raise AssertionError(
            "frozen marketing copy hash map must pin description.txt, "
            "promotional_text.txt, and release_notes.txt"
        )
    if set(FROZEN_MARKETING_COPY_LENGTH) != expected_files:
        raise AssertionError(
            "frozen marketing copy length map must pin description.txt, "
            "promotional_text.txt, and release_notes.txt"
        )
    for filename in FROZEN_MARKETING_COPY_FILES:
        path = METADATA / filename
        expected_hash = FROZEN_MARKETING_COPY_SHA256[filename]
        expected_length = FROZEN_MARKETING_COPY_LENGTH[filename]
        limit = TEXT_LIMITS[filename]
        if expected_length > limit:
            raise AssertionError(
                f"{filename} frozen length {expected_length} exceeds App Store limit {limit}"
            )
        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            raise AssertionError(
                f"{display_path(path)} changed but must be preserved exactly; "
                f"sha256 is {actual_hash}, expected {expected_hash}"
            )
        actual_length = len(read_text(path).strip())
        if actual_length != expected_length:
            raise AssertionError(
                f"{display_path(path)} changed but must be preserved exactly; "
                f"length is {actual_length}, expected {expected_length}"
            )
        messages.append(
            f"PASS: {filename} preserved exactly ({actual_hash}, {actual_length} chars)"
        )
    return messages


def validate_urls() -> list[str]:
    messages: list[str] = []
    for filename in sorted(URL_FILES):
        path = METADATA / filename
        url = read_text(path).strip()
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise AssertionError(
                f"{path.relative_to(ROOT)} must be an absolute HTTPS URL"
            )
        messages.append(f"PASS: {filename} is HTTPS")
    return messages


def fetch_url_text(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "WinsVPN-Apple-Submission-Validator/1.0",
            "Accept": "text/html,application/xhtml+xml",
            "Connection": "close",
        },
    )
    try:
        context = ssl.create_default_context()
        try:
            import certifi
        except ImportError:
            pass
        else:
            # Homebrew Pythons carry no system CA store on macOS, so the default
            # context verifies nothing and every HTTPS check fails even when the
            # site is up. certifi supplies a real bundle; verification stays on.
            context = ssl.create_default_context(cafile=certifi.where())
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            status = getattr(response, "status", 200)
            final_url = response.geturl()
            content_type = response.headers.get("content-type", "")
            body = response.read(2 * 1024 * 1024 + 1)
    except Exception as exc:
        raise AssertionError(f"{url} is not reachable: {exc}") from exc

    if status < 200 or status >= 400:
        raise AssertionError(f"{url} returned HTTP {status}")
    if len(body) > 2 * 1024 * 1024:
        raise AssertionError(f"{url} response exceeded 2 MiB")
    if not final_url.startswith("https://"):
        raise AssertionError(f"{url} redirected to non-HTTPS URL {final_url}")
    if "text/html" not in content_type.lower():
        raise AssertionError(f"{url} returned unexpected content-type {content_type!r}")
    return body.decode("utf-8", errors="replace")


def validate_live_urls() -> list[str]:
    if os.environ.get("WINS_SKIP_APPLE_URL_LIVE_CHECKS") == "1":
        return ["SKIP: live App Store URL checks disabled by environment"]

    messages: list[str] = []
    for filename, markers in sorted(LIVE_URL_MARKERS.items()):
        url = read_text(METADATA / filename).strip()
        body = fetch_url_text(url)
        for marker in markers:
            if marker not in body:
                raise AssertionError(f"{filename} live page missing marker {marker!r}")
        messages.append(f"PASS: {filename} live HTTPS page reachable with expected content")
    return messages


def validate_keywords() -> list[str]:
    keywords = read_text(METADATA / "keywords.txt").strip()
    parts = [part.strip() for part in keywords.split(",")]
    if any(not part for part in parts):
        raise AssertionError("keywords.txt contains an empty keyword")
    if len({part.lower() for part in parts}) != len(parts):
        raise AssertionError("keywords.txt contains duplicate keywords")
    return [f"PASS: keywords count {len(parts)}"]


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def validate_review_files() -> list[str]:
    messages: list[str] = []
    for path in REQUIRED_REVIEW_FILES:
        read_text(path)
        messages.append(f"PASS: {path.relative_to(ROOT)} present")
    return messages


def validate_content_markers() -> list[str]:
    messages: list[str] = []
    for path, markers in REQUIRED_CONTENT_MARKERS.items():
        text = read_text(path)
        for marker in markers:
            if marker not in text:
                raise AssertionError(
                    f"{path.relative_to(ROOT)} missing required marker {marker!r}"
                )
        messages.append(
            f"PASS: {path.relative_to(ROOT)} required App Store markers present"
        )
    copyright_text = read_text(METADATA / "copyright.txt")
    if "2026" not in copyright_text or "Win's VPN Inc." not in copyright_text:
        raise AssertionError("copyright.txt must name 2026 and Win's VPN Inc.")
    messages.append("PASS: copyright.txt names 2026 Win's VPN Inc.")
    return messages


def owner_review_packet_required_values() -> list[str]:
    release_candidate = read_json(ARTIFACT_MANIFEST)
    runtime_evidence = read_json(RUNTIME_EVIDENCE_MANIFEST)
    rollout_readiness = read_json(ROLLOUT_READINESS_MANIFEST)
    expected_version, expected_build = pubspec_version()

    required_values = [
        expected_version,
        expected_build,
        str(rollout_readiness.get("source_readiness_log") or ""),
        ARTIFACT_MANIFEST.relative_to(ROOT).as_posix(),
        RUNTIME_EVIDENCE_MANIFEST.relative_to(ROOT).as_posix(),
        ROLLOUT_READINESS_MANIFEST.relative_to(ROOT).as_posix(),
    ]

    for metadata_path in OWNER_PACKET_METADATA_HASH_FILES:
        if not metadata_path.is_file():
            raise AssertionError(
                f"owner review metadata file is missing: {metadata_path.relative_to(ROOT)}"
            )
        # The packet's own row pairs the path with its current hash. Requiring
        # the two strings anywhere in the document would let a hash that drifted
        # to a different row satisfy the cross-reference (R24 X-02).
        required_values.append(
            f"`{metadata_path.relative_to(ROOT).as_posix()}`:\n"
            f"  `{sha256_file(metadata_path)}`"
        )

    artifacts = release_candidate.get("artifacts")
    if not isinstance(artifacts, list):
        raise AssertionError("release_candidate.json artifacts must be a list")
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise AssertionError("release_candidate.json artifacts must be objects")
        required_values.extend(
            [
                str(artifact.get("path") or ""),
                str(artifact.get("sha256") or ""),
                str(artifact.get("archive_export_log") or ""),
                str(artifact.get("archive_export_log_sha256") or ""),
                str(artifact.get("verification_log") or ""),
                str(artifact.get("verification_log_sha256") or ""),
                str(artifact.get("artifact_status") or ""),
                str(artifact.get("bundle_id") or ""),
                str(artifact.get("packet_tunnel_bundle_id") or ""),
                str(artifact.get("expected_current_bundle_id") or ""),
                str(artifact.get("expected_current_packet_tunnel_bundle_id") or ""),
            ]
        )

    for screenshot_path in SCREENSHOT_SPECS:
        if not screenshot_path.is_file():
            raise AssertionError(
                f"missing screenshot candidate: {screenshot_path.relative_to(ROOT)}"
            )
        required_values.append(screenshot_path.relative_to(ROOT).as_posix())
        required_values.append(sha256_file(screenshot_path))

    for key in ["runtime_log", "macos_runtime_log"]:
        required_values.append(str(runtime_evidence.get(key) or ""))
    platform_results = runtime_evidence.get("platform_results")
    if not isinstance(platform_results, list):
        raise AssertionError("runtime_evidence.json platform_results must be a list")
    for result in platform_results:
        if not isinstance(result, dict):
            raise AssertionError("runtime_evidence.json platform_results must be objects")
        required_values.extend(
            [
                str(result.get("path") or ""),
                str(result.get("evidence_status") or ""),
                str(result.get("bundle_id_at_test") or ""),
                str(result.get("expected_current_bundle_id") or ""),
            ]
        )

    return required_values


def assert_owner_review_packet_has_values(
    packet_text: str,
    required_values: list[str],
) -> None:
    missing = sorted({value for value in required_values if value and value not in packet_text})
    if missing:
        raise AssertionError(
            "owner_review_packet.md is missing current release cross-reference(s): "
            + ", ".join(repr(value) for value in missing)
        )


def validate_owner_review_packet_cross_references() -> list[str]:
    packet_text = read_text(OWNER_REVIEW_PACKET)
    assert_owner_review_packet_has_values(
        packet_text,
        owner_review_packet_required_values(),
    )
    return [
        "PASS: owner review packet cross-references current metadata, artifacts, screenshots, runtime evidence, and readiness logs"
    ]


def selftest_frozen_marketing_copy() -> str:
    global METADATA

    live_messages = validate_frozen_marketing_copy()
    if len(live_messages) != len(FROZEN_MARKETING_COPY_FILES):
        raise AssertionError(
            "frozen marketing copy self-test did not pin every en-US metadata file"
        )

    original_metadata = METADATA
    try:
        with tempfile.TemporaryDirectory(prefix="wins-apple-frozen-copy-") as tmp_dir:
            meta = Path(tmp_dir)
            stale_name = FROZEN_MARKETING_COPY_FILES[0]
            for filename in FROZEN_MARKETING_COPY_FILES:
                payload = (original_metadata / filename).read_bytes()
                if filename == stale_name:
                    payload = payload + b" "
                (meta / filename).write_bytes(payload)
            METADATA = meta
            try:
                validate_frozen_marketing_copy()
            except AssertionError as exc:
                detail = str(exc)
                if "must be preserved exactly" not in detail:
                    raise AssertionError(
                        "frozen marketing copy self-test failed for an unexpected reason"
                    ) from exc
                if stale_name not in detail:
                    raise AssertionError(
                        "frozen marketing copy self-test did not report the stale copy"
                    ) from exc
            else:
                raise AssertionError(
                    "frozen marketing copy self-test accepted stale copy"
                )
    finally:
        METADATA = original_metadata
    return "PASS: frozen marketing copy self-test rejects stale copy"


def run_selftest() -> list[str]:
    global ROLLOUT_READINESS_MANIFEST

    hostile_json = (
        ('{"receipt":{"ok":true,"ok":false}}', "duplicate key"),
        ('{"receipt":NaN}', "non-finite"),
        ('{"receipt":Infinity}', "non-finite"),
        ('{"receipt":1e400}', "non-finite"),
        ('{"receipt":"0123456789"}', "size is invalid"),
    )
    for payload, expected in hostile_json:
        try:
            _strict_json_loads(
                payload,
                "submission receipt self-test",
                max_bytes=8 if expected == "size is invalid" else 1024,
            )
        except AssertionError as exc:
            if expected not in str(exc):
                raise AssertionError(
                    "submission receipt JSON self-test failed for an unexpected reason"
                ) from exc
        else:
            raise AssertionError(
                "submission receipt JSON self-test accepted hostile JSON"
            )

    frozen_copy_message = selftest_frozen_marketing_copy()

    packet_text = read_text(OWNER_REVIEW_PACKET)
    required_values = owner_review_packet_required_values()
    assert_owner_review_packet_has_values(packet_text, required_values)

    stale_marker = next(
        (value for value in required_values if re.fullmatch(r"[0-9a-f]{64}", value)),
        "",
    )
    if not stale_marker:
        raise AssertionError("owner review packet cross-reference self-test needs a SHA-256 marker")
    stale_packet_text = packet_text.replace(stale_marker, "0" * 64)
    try:
        assert_owner_review_packet_has_values(stale_packet_text, required_values)
    except AssertionError as exc:
        if stale_marker not in str(exc):
            raise AssertionError(
                "owner review packet cross-reference self-test did not report "
                "the stale marker"
            ) from exc
    else:
        raise AssertionError(
            "owner review packet cross-reference self-test accepted stale evidence text"
        )

    with tempfile.TemporaryDirectory(prefix="wins-apple-screenshot-selftest-") as tmp_dir:
        blank_png = Path(tmp_dir) / "blank.png"
        width, height = 32, 32
        row = bytes([255, 255, 255, 255]) * width
        raw = b"".join(bytes([0]) + row for _ in range(height))

        def chunk(kind: bytes, payload: bytes) -> bytes:
            crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
            return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)

        blank_png.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(
                b"IHDR",
                struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0),
            )
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b"")
        )
        try:
            require_screenshot_visual_sanity(blank_png)
        except AssertionError as exc:
            if "visually flat" not in str(exc) and "color variation" not in str(exc):
                raise AssertionError(
                    "screenshot visual sanity self-test failed for an unexpected reason"
                ) from exc
        else:
            raise AssertionError("screenshot visual sanity self-test accepted a blank PNG")

    for candidate_status, platform, evidence_status, bundle_id in [
        (
            RUNTIME_PENDING_CANDIDATE_SET_STATUS,
            "ios",
            CURRENT_ARTIFACT_STATUS,
            "org.winsvpn.app",
        ),
        (
            RUNTIME_PENDING_CANDIDATE_SET_STATUS,
            "macos",
            SUPERSEDED_MACOS_ARTIFACT_STATUS,
            "org.winsvpn.macos",
        ),
        (
            RUNTIME_COMPLETE_CANDIDATE_SET_STATUS,
            "macos",
            CURRENT_ARTIFACT_STATUS,
            "org.winsvpn.app",
        ),
    ]:
        _validate_runtime_result_identity(
            candidate_status=candidate_status,
            platform=platform,
            evidence_status=evidence_status,
            bundle_id_at_test=bundle_id,
        )
    for candidate_status, evidence_status, bundle_id in [
        (
            RUNTIME_PENDING_CANDIDATE_SET_STATUS,
            CURRENT_ARTIFACT_STATUS,
            "org.winsvpn.app",
        ),
        (
            RUNTIME_COMPLETE_CANDIDATE_SET_STATUS,
            SUPERSEDED_MACOS_ARTIFACT_STATUS,
            "org.winsvpn.macos",
        ),
        (
            RUNTIME_COMPLETE_CANDIDATE_SET_STATUS,
            CURRENT_ARTIFACT_STATUS,
            "org.winsvpn.macos",
        ),
    ]:
        try:
            _validate_runtime_result_identity(
                candidate_status=candidate_status,
                platform="macos",
                evidence_status=evidence_status,
                bundle_id_at_test=bundle_id,
            )
        except AssertionError:
            continue
        raise AssertionError(
            "runtime transition self-test accepted an invalid macOS evidence state"
        )

    rollout_manifest = read_json(ROLLOUT_READINESS_MANIFEST)
    release_candidate = read_json(ARTIFACT_MANIFEST)
    artifacts = release_candidate.get("artifacts")
    if not isinstance(rollout_manifest, dict) or not isinstance(artifacts, list):
        raise AssertionError("package-gate transition self-test needs valid manifests")
    macos_candidates = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict)
        and artifact.get("platform") == "macos"
        and artifact.get("lane") == "app_store_local"
        and artifact.get("type") == "pkg"
    ]
    if len(macos_candidates) != 1:
        raise AssertionError(
            "package-gate transition self-test needs one macOS App Store-local PKG"
        )
    macos_candidate_hash = str(macos_candidates[0].get("sha256") or "")
    with tempfile.TemporaryDirectory(
        prefix="wins_apple_pkg_gate_selftest_",
        dir="/tmp",
    ) as tmp_dir:
        tmp_root = Path(tmp_dir)
        hermetic_manifest = copy.deepcopy(rollout_manifest)
        negative_logs: dict[str, str] = {}
        for key, marker in sorted(ROLLOUT_NEGATIVE_LOG_MARKERS.items()):
            log_path = tmp_root / f"{key}-negative-control.log"
            log_path.write_text(marker + "\n", encoding="utf-8")
            negative_logs[key] = str(log_path)
        hermetic_manifest["negative_upload_guard_logs"] = negative_logs

        success_log = tmp_root / "package-install-success.log"
        success_log.write_text(
            "\n".join(ROLLOUT_MACOS_PKG_SUCCESS_MARKERS) + "\n",
            encoding="utf-8",
        )
        completed_manifest = copy.deepcopy(hermetic_manifest)
        completed_manifest["completed_gates"] = {
            ROLLOUT_MACOS_PKG_GATE: {
                "status": "passed",
                "verification_log": str(success_log),
                "artifact_sha256": macos_candidate_hash,
            }
        }
        completed_manifest["remaining_blockers"].pop(ROLLOUT_MACOS_PKG_GATE, None)
        completed_manifest_path = tmp_root / "rollout-readiness-complete.json"
        completed_manifest_path.write_text(
            json.dumps(completed_manifest, indent=2) + "\n",
            encoding="utf-8",
        )

        original_rollout_manifest = ROLLOUT_READINESS_MANIFEST
        try:
            ROLLOUT_READINESS_MANIFEST = completed_manifest_path
            validate_rollout_readiness_manifest()

            missing_auth_log = Path(negative_logs["missing_auth"])
            missing_auth_log.write_text(
                "missing credentials were incorrectly accepted\n",
                encoding="utf-8",
            )
            try:
                validate_rollout_readiness_manifest()
            except AssertionError as exc:
                expected = (
                    "rollout_readiness.json negative log 'missing_auth' "
                    f"missing marker {ROLLOUT_NEGATIVE_LOG_MARKERS['missing_auth']!r}"
                )
                if str(exc) != expected:
                    raise AssertionError(
                        "authentication-guard self-test failed for an unexpected reason"
                    ) from exc
            else:
                raise AssertionError(
                    "authentication-guard self-test accepted evidence without the "
                    "required missing-auth rejection"
                )
            missing_auth_log.write_text(
                ROLLOUT_NEGATIVE_LOG_MARKERS["missing_auth"] + "\n",
                encoding="utf-8",
            )

            completed_manifest["completed_gates"][ROLLOUT_MACOS_PKG_GATE][
                "artifact_sha256"
            ] = "0" * 64
            completed_manifest_path.write_text(
                json.dumps(completed_manifest, indent=2) + "\n",
                encoding="utf-8",
            )
            try:
                validate_rollout_readiness_manifest()
            except AssertionError as exc:
                if "artifact hash mismatch" not in str(exc):
                    raise AssertionError(
                        "package-gate transition self-test failed for an unexpected reason"
                    ) from exc
            else:
                raise AssertionError(
                    "package-gate transition self-test accepted a mismatched PKG hash"
                )
        finally:
            ROLLOUT_READINESS_MANIFEST = original_rollout_manifest

    return [
        frozen_copy_message,
        "PASS: owner review packet cross-reference self-test rejects stale evidence text",
        "PASS: screenshot visual sanity self-test rejects blank PNGs",
        "PASS: runtime transition self-test enforces pending and current macOS evidence states",
        "PASS: authentication-guard self-test rejects missing-auth evidence without the exact fail-closed marker",
        "PASS: package-gate transition self-test enforces success markers and current PKG hash",
    ]


def _plist_bundle_id(payload: bytes, label: str) -> str:
    try:
        plist = plistlib.loads(payload)
    except Exception as exc:
        raise AssertionError(f"{label} is not a valid plist: {exc}") from exc
    bundle_id = plist.get("CFBundleIdentifier") if isinstance(plist, dict) else None
    if not isinstance(bundle_id, str) or not bundle_id.strip():
        raise AssertionError(f"{label} is missing CFBundleIdentifier")
    return bundle_id.strip()


def _ios_artifact_bundle_ids(artifact_path: Path) -> tuple[str, str]:
    try:
        with zipfile.ZipFile(artifact_path) as archive:
            host_plists = [
                name
                for name in archive.namelist()
                if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)
            ]
            if len(host_plists) != 1:
                raise AssertionError(
                    f"{artifact_path} must contain exactly one top-level app plist"
                )
            host_plist = host_plists[0]
            app_prefix = host_plist[: -len("/Info.plist")]
            extension_plist = (
                f"{app_prefix}/PlugIns/PacketTunnel.appex/Info.plist"
            )
            try:
                host_payload = archive.read(host_plist)
                extension_payload = archive.read(extension_plist)
            except KeyError as exc:
                raise AssertionError(
                    f"{artifact_path} is missing embedded PacketTunnel Info.plist"
                ) from exc
    except zipfile.BadZipFile as exc:
        raise AssertionError(f"{artifact_path} is not a valid IPA ZIP") from exc
    return (
        _plist_bundle_id(host_payload, f"{artifact_path} host Info.plist"),
        _plist_bundle_id(
            extension_payload,
            f"{artifact_path} PacketTunnel Info.plist",
        ),
    )


def _macos_artifact_bundle_ids(artifact_path: Path) -> tuple[str, str]:
    pkgutil = Path("/usr/sbin/pkgutil")
    if not pkgutil.is_file():
        raise AssertionError("pkgutil is required to inspect the macOS package payload")
    with tempfile.TemporaryDirectory(prefix="wins-apple-pkg-audit-") as tmp_dir:
        expanded = Path(tmp_dir) / "expanded"
        completed = subprocess.run(
            [str(pkgutil), "--expand-full", str(artifact_path), str(expanded)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise AssertionError(
                f"could not expand {artifact_path} for bundle-ID audit: {stderr}"
            )

        host_plists = [
            path
            for path in expanded.rglob("Info.plist")
            if path.parent.name == "Contents"
            and path.parent.parent.suffix == ".app"
        ]
        if len(host_plists) != 1:
            raise AssertionError(
                f"{artifact_path} must contain exactly one macOS app payload plist"
            )
        host_plist = host_plists[0]
        host_app = host_plist.parent.parent
        extension_plist = (
            host_app
            / "Contents"
            / "PlugIns"
            / "PacketTunnel.appex"
            / "Contents"
            / "Info.plist"
        )
        if not extension_plist.is_file():
            raise AssertionError(
                f"{artifact_path} is missing embedded PacketTunnel Info.plist"
            )
        return (
            _plist_bundle_id(
                host_plist.read_bytes(),
                f"{artifact_path} host Info.plist",
            ),
            _plist_bundle_id(
                extension_plist.read_bytes(),
                f"{artifact_path} PacketTunnel Info.plist",
            ),
        )


def _artifact_bundle_ids(platform: str, artifact_path: Path) -> tuple[str, str]:
    if platform == "ios":
        return _ios_artifact_bundle_ids(artifact_path)
    if platform == "macos":
        return _macos_artifact_bundle_ids(artifact_path)
    raise AssertionError(f"unsupported artifact platform {platform!r}")


FORBIDDEN_MAP_RUNTIME_MARKERS = [
    b"ipapi.co",
    b"ipwho.is",
]


def _assert_payload_has_no_forbidden_map_markers(
    platform: str, artifact_path: Path
) -> None:
    def inspect(label: str, payload: bytes) -> None:
        lowered = payload.lower()
        for marker in FORBIDDEN_MAP_RUNTIME_MARKERS:
            if marker in lowered:
                raise AssertionError(
                    f"{artifact_path} payload {label} contains forbidden runtime "
                    f"direct geolocation marker {marker.decode('ascii')!r}"
                )

    if platform == "ios":
        try:
            with zipfile.ZipFile(artifact_path) as archive:
                for name in archive.namelist():
                    if not name.endswith("/"):
                        inspect(name, archive.read(name))
        except zipfile.BadZipFile as exc:
            raise AssertionError(f"{artifact_path} is not a valid IPA ZIP") from exc
        return

    if platform == "macos":
        pkgutil = Path("/usr/sbin/pkgutil")
        with tempfile.TemporaryDirectory(prefix="wins-apple-map-audit-") as tmp_dir:
            expanded = Path(tmp_dir) / "expanded"
            completed = subprocess.run(
                [str(pkgutil), "--expand-full", str(artifact_path), str(expanded)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace").strip()
                raise AssertionError(
                    f"could not expand {artifact_path} for map-host audit: {stderr}"
                )
            for path in expanded.rglob("*"):
                if path.is_file():
                    inspect(str(path.relative_to(expanded)), path.read_bytes())
        return

    raise AssertionError(f"unsupported artifact platform {platform!r}")


def _artifact_runtime_source_files(platform: str) -> list[Path]:
    if platform not in CURRENT_RELEASE_CANDIDATE_BUNDLE_IDS:
        raise AssertionError(f"unsupported artifact platform {platform!r}")
    source_platform = platform
    roots = [
        ROOT / "lib",
        ROOT / "assets",
        ROOT / source_platform / "Runner",
        ROOT / source_platform / "PacketTunnel",
        ROOT / "apple" / "WinsTunnelCore",
        ROOT / "apple" / "EngineWrappers",
        ROOT / "apple" / "EngineArtifacts" / source_platform,
    ]
    files = [
        ROOT / "pubspec.yaml",
        ROOT / "pubspec.lock",
        ROOT / source_platform / "Podfile",
        ROOT / source_platform / "Podfile.lock",
        ROOT / source_platform / "Runner.xcodeproj" / "project.pbxproj",
        ROOT
        / source_platform
        / "Runner.xcodeproj"
        / "xcshareddata"
        / "xcschemes"
        / "Runner.xcscheme",
        ROOT / "tools" / "stage_apple_engine_artifacts.sh",
    ]
    if source_platform == "ios":
        files.extend(
            [
                ROOT / "ios" / "Flutter" / "AppFrameworkInfo.plist",
                ROOT / "ios" / "Flutter" / "Debug.xcconfig",
                ROOT / "ios" / "Flutter" / "Profile.xcconfig",
                ROOT / "ios" / "Flutter" / "Release.xcconfig",
            ]
        )
    else:
        files.extend(
            [
                ROOT / "macos" / "Flutter" / "Flutter-Debug.xcconfig",
                ROOT / "macos" / "Flutter" / "Flutter-Release.xcconfig",
            ]
        )
    for root in roots:
        if not root.is_dir():
            raise AssertionError(
                f"artifact runtime source root is missing: {display_path(root)}"
            )
        files.extend(path for path in root.rglob("*") if path.is_file())
    unique = sorted({path.resolve() for path in files}, key=lambda path: str(path))
    missing = [display_path(path) for path in unique if not path.is_file()]
    if missing:
        raise AssertionError(
            "artifact runtime source file(s) are missing: " + ", ".join(missing)
        )
    return unique


def _artifact_source_fingerprint(platform: str) -> tuple[str, int, float, str]:
    digest = hashlib.sha256()
    files = _artifact_runtime_source_files(platform)
    latest = max(files, key=lambda path: path.stat().st_mtime_ns)
    for path in files:
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return (
        digest.hexdigest(),
        len(files),
        latest.stat().st_mtime,
        latest.relative_to(ROOT).as_posix(),
    )


def _validate_artifact_source_fingerprint(
    platform: str,
    artifact: dict[str, object],
    artifact_path: Path,
) -> None:
    if artifact.get("source_fingerprint_contract") != ARTIFACT_SOURCE_FINGERPRINT_CONTRACT:
        raise AssertionError(
            f"{artifact_path} source fingerprint contract must be "
            f"{ARTIFACT_SOURCE_FINGERPRINT_CONTRACT!r}"
        )
    actual_hash, actual_count, _, _ = (
        _artifact_source_fingerprint(platform)
    )
    if artifact.get("source_fingerprint_sha256") != actual_hash:
        raise AssertionError(
            f"{artifact_path} runtime source fingerprint changed; rebuild the release artifact"
        )
    if artifact.get("source_file_count") != actual_count:
        raise AssertionError(
            f"{artifact_path} runtime source file count changed; rebuild the release artifact"
        )


def _require_recorded_app_store_signing(
    artifact: dict[str, object],
    platform: str,
    *,
    required: bool,
) -> None:
    try:
        listing.require_recorded_app_store_signing(
            artifact, platform, required=required
        )
    except listing.AppleListingGateError as exc:
        raise AssertionError(str(exc)) from exc


def validate_artifact_manifest(
    *, verified_receipts: dict[str, dict[str, object]] | None = None
) -> list[str]:
    manifest = read_json(ARTIFACT_MANIFEST)
    if not isinstance(manifest, dict):
        raise AssertionError("release_candidate.json must contain a JSON object")
    if manifest.get("schema_version") != 1:
        raise AssertionError("release_candidate.json must use schema_version 1")
    upload_status = str(manifest.get("upload_status") or "")
    allowed_upload_states = {
        "not_uploaded": {
            "complete_local_candidates",
            "preliminary_local_candidates_invalidated_by_shared_revision",
            "no_current_candidate",
        },
        "uploaded_processed_and_attached": {"uploaded_processed_and_attached"},
    }
    if upload_status not in allowed_upload_states:
        raise AssertionError("release_candidate.json upload_status is not supported")
    if manifest.get("candidate_set_status") not in allowed_upload_states[upload_status]:
        raise AssertionError(
            "release_candidate.json candidate_set_status does not match its upload state"
        )

    expected_version, expected_build = pubspec_version()
    if manifest.get("app_version") != expected_version:
        raise AssertionError(
            f"release_candidate.json app_version={manifest.get('app_version')!r}, "
            f"expected {expected_version!r}"
        )
    if str(manifest.get("build_number")) != expected_build:
        raise AssertionError(
            f"release_candidate.json build_number={manifest.get('build_number')!r}, "
            f"expected {expected_build!r}"
        )

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise AssertionError(
            "release_candidate.json must list exactly two artifacts: "
            "iOS with embedded watchOS and macOS"
        )

    if manifest.get("candidate_set_status") == "no_current_candidate":
        validate_no_stale_build_29_current_state(manifest, "release_candidate.json")
        pending_artifacts = owner_artifact_map(manifest)
        _pending_artifact(pending_artifacts["ios"], "ios")
        _pending_artifact(pending_artifacts["macos"], "macos")
        _pending_watch(_watch_companion(pending_artifacts["ios"]))
        _require_recorded_app_store_signing(
            pending_artifacts["ios"], "ios", required=False
        )
        _require_recorded_app_store_signing(
            pending_artifacts["macos"], "macos", required=False
        )
        return [
            f"PASS: {ARTIFACT_MANIFEST.relative_to(ROOT)} present",
            "PASS: Apple candidate set is fail-closed with no_current_candidate",
            "PASS: iOS embedded watchOS companion identity is reserved and unbound",
            "PASS: recorded signing identities stay unbound until real Apple Distribution artifacts exist",
        ]

    release_input_index: Path | None = None
    if manifest.get("candidate_set_status") == "complete_local_candidates":
        release_input_index = require_hashed_durable_file(
            manifest.get("release_input_index"),
            manifest.get("release_input_index_sha256"),
            "release candidate input index",
        )
        release_input_index_anchor = require_hashed_durable_file(
            manifest.get("release_input_index_anchor"),
            manifest.get("release_input_index_anchor_sha256"),
            "release candidate input index anchor",
        )
        if release_input_index_anchor != release_input_index.with_name(
            release_input_index.name + ".sha256"
        ):
            raise AssertionError(
                "release candidate input index anchor path is not canonical"
            )
        # The freeze binds this archive report to the privacy manifests inside
        # the exact IPA and PKG; the owner evidence set carries its digest.
        require_hashed_durable_file(
            manifest.get("archive_privacy_inventory"),
            manifest.get("archive_privacy_inventory_sha256"),
            "archive privacy inventory",
        )

    expected_artifacts = {
        ("ios", "app_store_local", "ipa"),
        ("macos", "app_store_local", "pkg"),
    }
    seen: set[tuple[str, str, str]] = set()
    messages = [f"PASS: {ARTIFACT_MANIFEST.relative_to(ROOT)} present"]

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise AssertionError("release_candidate.json artifacts must be objects")
        key = (
            str(artifact.get("platform") or ""),
            str(artifact.get("lane") or ""),
            str(artifact.get("type") or ""),
        )
        if key not in expected_artifacts:
            raise AssertionError(f"unexpected artifact tuple {key!r}")
        if key in seen:
            raise AssertionError(f"duplicate artifact tuple {key!r}")
        seen.add(key)

        relative_path = str(artifact.get("path") or "")
        if not relative_path or relative_path.startswith("/"):
            raise AssertionError(f"{key!r} artifact path must be repository-relative")
        artifact_path = ROOT / relative_path
        if not artifact_path.is_file():
            raise AssertionError(f"{relative_path} does not exist")
        if artifact_path.suffix.lower().lstrip(".") != key[2]:
            raise AssertionError(f"{relative_path} extension does not match {key[2]}")

        expected_size = artifact.get("size_bytes")
        actual_size = artifact_path.stat().st_size
        if not isinstance(expected_size, int) or expected_size != actual_size:
            raise AssertionError(
                f"{relative_path} size is {actual_size}, expected {expected_size!r}"
            )

        expected_sha = str(artifact.get("sha256") or "")
        actual_sha = sha256_file(artifact_path)
        if expected_sha != actual_sha:
            raise AssertionError(
                f"{relative_path} sha256 is {actual_sha}, expected {expected_sha}"
            )
        _validate_artifact_source_fingerprint(key[0], artifact, artifact_path)

        recorded_bundle_ids = (
            str(artifact.get("bundle_id") or ""),
            str(artifact.get("packet_tunnel_bundle_id") or ""),
        )
        actual_bundle_ids = _artifact_bundle_ids(key[0], artifact_path)
        _assert_payload_has_no_forbidden_map_markers(key[0], artifact_path)
        if recorded_bundle_ids != actual_bundle_ids:
            raise AssertionError(
                f"{relative_path} bundle IDs are {actual_bundle_ids!r}, "
                f"manifest records {recorded_bundle_ids!r}"
            )
        expected_current_bundle_ids = CURRENT_RELEASE_CANDIDATE_BUNDLE_IDS[key[0]]
        manifest_expected_current = (
            str(artifact.get("expected_current_bundle_id") or ""),
            str(artifact.get("expected_current_packet_tunnel_bundle_id") or ""),
        )
        if manifest_expected_current != expected_current_bundle_ids:
            raise AssertionError(
                f"{relative_path} expected current bundle IDs must be "
                f"{expected_current_bundle_ids!r}"
            )
        artifact_status = str(artifact.get("artifact_status") or "")
        if artifact_status != CURRENT_ARTIFACT_STATUS:
            raise AssertionError(f"{relative_path} must be a current local candidate")
        _require_recorded_app_store_signing(artifact, key[0], required=True)
        if actual_bundle_ids != expected_current_bundle_ids:
            raise AssertionError(
                f"{relative_path} current bundle IDs are stale: {actual_bundle_ids!r}"
            )

        if release_input_index is not None:
            if artifact.get("release_input_index") != manifest.get(
                "release_input_index"
            ) or artifact.get("release_input_index_sha256") != manifest.get(
                "release_input_index_sha256"
            ):
                raise AssertionError(
                    f"{relative_path} release input index binding differs from the paired candidate set"
                )
            validate_formal_build_receipt_binding(
                key[0],
                artifact,
                artifact_path,
                release_input_index,
                verified_result=(verified_receipts or {}).get(key[0]),
            )

        archive_log_path = require_durable_receipt_evidence_file(
            artifact.get("archive_export_log"),
            f"{relative_path} archive_export_log",
        )
        verification_log_path = require_durable_receipt_evidence_file(
            artifact.get("verification_log"),
            f"{relative_path} verification_log",
        )
        for field, evidence_path in (
            ("archive_export_log_sha256", archive_log_path),
            ("verification_log_sha256", verification_log_path),
        ):
            expected_log_sha = str(artifact.get(field) or "")
            if not re.fullmatch(r"[0-9a-f]{64}", expected_log_sha):
                raise AssertionError(f"{relative_path} {field} must be lowercase SHA-256")
            actual_log_sha = sha256_file(evidence_path)
            if actual_log_sha != expected_log_sha:
                raise AssertionError(
                    f"{relative_path} {field} mismatch: expected "
                    f"{expected_log_sha}, got {actual_log_sha}"
                )

        archive_log_text = archive_log_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
        for marker in ARCHIVE_EXPORT_LOG_MARKERS:
            if marker not in archive_log_text:
                raise AssertionError(
                    f"{relative_path} archive_export_log missing proof marker {marker!r}"
                )
        if archive_log_text.count("** ARCHIVE SUCCEEDED **") < 2:
            raise AssertionError(
                f"{relative_path} archive_export_log must prove two successful archives"
            )
        if archive_log_text.count("** EXPORT SUCCEEDED **") < 2:
            raise AssertionError(
                f"{relative_path} archive_export_log must prove two successful exports"
            )

        verification_log_text = verification_log_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
        for marker in VERIFICATION_LOG_MARKERS[key]:
            if marker not in verification_log_text:
                raise AssertionError(
                    f"{relative_path} verification_log missing proof marker {marker!r}"
                )
        if key == ("ios", "app_store_local", "ipa"):
            contract = str(artifact.get("verification_contract") or "")
            if contract:
                if contract != IOS_COMPILED_ICON_VERIFICATION_CONTRACT:
                    raise AssertionError(
                        f"{relative_path} verification_contract {contract!r} is not supported"
                    )
                if IOS_COMPILED_ICON_VERIFICATION_MARKER not in verification_log_text:
                    raise AssertionError(
                        f"{relative_path} verification_log missing proof marker "
                        f"{IOS_COMPILED_ICON_VERIFICATION_MARKER!r}"
                    )
        messages.append(
            f"PASS: {key[0]} {key[1]} {key[2]} artifact hash, size, and source fingerprint match manifest"
        )
        messages.append(
            f"PASS: {key[0]} {key[1]} {key[2]} durable receipt logs and hashes prove artifact checks"
        )
        messages.append(
            f"PASS: {key[0]} artifact payload bundle IDs match the universal candidate"
        )
        messages.append(
            f"PASS: {key[0]} artifact contains no forbidden direct geolocation marker"
        )

    missing = expected_artifacts.difference(seen)
    if missing:
        raise AssertionError(f"release_candidate.json missing artifacts {sorted(missing)!r}")
    if upload_status == "uploaded_processed_and_attached":
        evidence = manifest.get("upload_evidence")
        if not isinstance(evidence, dict):
            raise AssertionError("uploaded release_candidate.json requires upload_evidence")
        evidence_paths = {
            "upload_log": evidence.get("upload_log"),
            "attach_log": evidence.get("attach_log"),
            "screenshot_upload_log": evidence.get("screenshot_upload_log"),
            "live_status_log": evidence.get("live_status_log"),
        }
        evidence_text: dict[str, str] = {}
        for label, path_value in evidence_paths.items():
            path_text = str(path_value or "")
            if not path_text.startswith("/tmp/wins_"):
                raise AssertionError(f"release_candidate.json {label} must be a /tmp/wins_* path")
            evidence_text[label] = _read_tmp_evidence_log(
                path_text,
                f"release_candidate.json upload_evidence.{label}",
            )
        artifact_by_platform = {
            str(artifact.get("platform")): artifact for artifact in artifacts
        }
        for platform in ("ios", "macos"):
            artifact = artifact_by_platform[platform]
            sha = str(artifact.get("sha256") or "")
            build_id = str(artifact.get("app_store_build_id") or "")
            if artifact.get("upload_status") != "uploaded_processed_and_attached":
                raise AssertionError(f"{platform} artifact upload status mismatch")
            if artifact.get("processing_state") != "VALID":
                raise AssertionError(f"{platform} artifact must have VALID processing state")
            if not re.fullmatch(r"[0-9a-f-]{36}", build_id):
                raise AssertionError(f"{platform} artifact App Store build ID is invalid")
            if f"PASS: Apple accepted exact {platform} candidate sha256={sha}" not in evidence_text["upload_log"]:
                raise AssertionError(f"upload log does not prove exact {platform} artifact acceptance")
            expected_attachment = (
                f"PASS: attached {platform} build {expected_build} "
                f"to App Store version {expected_version}"
            )
            if expected_attachment not in evidence_text["attach_log"]:
                raise AssertionError(f"attach log does not prove {platform} build attachment")
        if evidence_text["upload_log"].count("UPLOAD SUCCEEDED with no errors") != 2:
            raise AssertionError("upload log must prove exactly two successful Apple uploads")
        for platform, screenshot_path in (
            (
                "ios",
                PACKAGE / "screenshots" / "candidates" / "ios-6_9" / "01-main.png",
            ),
            (
                "macos",
                PACKAGE / "screenshots" / "candidates" / "macos-16_10" / "01-main.png",
            ),
        ):
            screenshot_sha = sha256_file(screenshot_path)
            marker = f"PASS: Apple processed exact {platform} screenshot sha256={screenshot_sha}"
            if marker not in evidence_text["screenshot_upload_log"]:
                raise AssertionError(f"screenshot log does not prove exact {platform} upload")
        live_status = _strict_json_loads(
            evidence_text["live_status_log"], "post-upload live status log"
        )
        live_builds = live_status.get("builds") if isinstance(live_status, dict) else None
        live_platforms = live_status.get("platforms") if isinstance(live_status, dict) else None
        if not isinstance(live_builds, list) or not isinstance(live_platforms, dict):
            raise AssertionError("post-upload live status is missing builds or platforms")
        for platform, api_platform in (("ios", "IOS"), ("macos", "MAC_OS")):
            build_id = str(artifact_by_platform[platform].get("app_store_build_id") or "")
            matches = [
                build for build in live_builds
                if isinstance(build, dict)
                and build.get("id") == build_id
                and build.get("platform") == api_platform
                and str(build.get("version") or "") == expected_build
                and build.get("processing_state") == "VALID"
            ]
            platform_status = live_platforms.get(platform)
            if len(matches) != 1 or not isinstance(platform_status, dict):
                raise AssertionError(
                    f"post-upload live status does not prove {platform} "
                    f"build {expected_build}"
                )
            if platform_status.get("selected_build_id") != build_id:
                raise AssertionError(f"post-upload live status does not prove {platform} attachment")
        messages.append(
            "PASS: exact iOS/macOS uploads, processing, attachments, and screenshots are proven by live Apple evidence"
        )
    return messages


def validate_cross_store_artifact(target_id: str, raw_path: str) -> list[str]:
    expected = {
        "ios-app-store-ipa": ("ios", "app_store_local", "ipa"),
        "macos-app-store-pkg": ("macos", "app_store_local", "pkg"),
        "macos-developer-id-app": None,
    }
    if target_id not in expected:
        raise AssertionError(f"unsupported Apple submission target: {target_id}")
    # The cross-store helper executes the contamination helper while it loads, so
    # the contamination helper's reviewed hash is checked before either is run.
    actual_contamination_sha256 = sha256_file(
        APPLE_RELEASE_CONTAMINATION_GATE_HELPER
    )
    if (
        actual_contamination_sha256
        != APPLE_RELEASE_CONTAMINATION_GATE_HELPER_SHA256
    ):
        raise AssertionError(
            "Apple release contamination helper source hash is not reviewed"
        )
    helper = _load_reviewed_helper(
        APPLE_CROSS_STORE_GATE_HELPER,
        APPLE_CROSS_STORE_GATE_HELPER_SHA256,
        "apple_cross_store_artifact_gate",
    )
    try:
        expected_version, expected_build = helper.reviewed_apple_release_identity()
    except helper.AppleArtifactGateError as exc:
        raise AssertionError(str(exc)) from exc
    expected_tuple = expected[target_id]
    if expected_tuple is not None:
        manifest = read_json(ARTIFACT_MANIFEST)
        if not isinstance(manifest, dict):
            raise AssertionError("release_candidate.json must contain a JSON object")
        if (
            manifest.get("app_version") != expected_version
            or str(manifest.get("build_number")) != expected_build
        ):
            raise AssertionError(
                f"{target_id} release candidate version/build is not the canonical "
                f"{expected_version}+{expected_build}"
            )
    try:
        artifact_path = helper.canonical_artifact(target_id, raw_path)
    except helper.AppleArtifactGateError as exc:
        raise AssertionError(str(exc)) from exc
    if expected_tuple is None:
        try:
            helper.verify_signature(target_id, raw_path)
        except helper.AppleArtifactGateError as exc:
            raise AssertionError(str(exc)) from exc
        return [f"PASS: {target_id} exact artifact-only signature gate"]
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    if not isinstance(artifacts, list):
        raise AssertionError("release_candidate.json artifacts are malformed")
    matches = [
        item
        for item in artifacts
        if isinstance(item, dict)
        and (
            str(item.get("platform") or ""),
            str(item.get("lane") or ""),
            str(item.get("type") or ""),
        )
        == expected_tuple
    ]
    if len(matches) != 1:
        raise AssertionError(f"{target_id} must bind exactly one release candidate")
    candidate = matches[0]
    recorded_path = str(candidate.get("path") or "")
    if not recorded_path or (ROOT / recorded_path).resolve(strict=True) != artifact_path:
        raise AssertionError(f"{target_id} artifact path does not match release_candidate.json")
    if candidate.get("size_bytes") != artifact_path.stat().st_size:
        raise AssertionError(f"{target_id} artifact size does not match release_candidate.json")
    if candidate.get("sha256") != sha256_file(artifact_path):
        raise AssertionError(f"{target_id} artifact hash does not match release_candidate.json")
    if (
        candidate.get("artifact_status") != CURRENT_ARTIFACT_STATUS
        or candidate.get("upload_status") != "not_uploaded"
    ):
        raise AssertionError(f"{target_id} is not the current release candidate")
    expected_bundle_ids = CURRENT_APPLE_BUNDLE_IDS[expected_tuple[0]]
    recorded_bundle_ids = (
        str(candidate.get("bundle_id") or ""),
        str(candidate.get("packet_tunnel_bundle_id") or ""),
    )
    if recorded_bundle_ids != expected_bundle_ids:
        raise AssertionError(f"{target_id} release candidate bundle IDs are stale")
    try:
        helper.verify_signature(target_id, raw_path)
    except helper.AppleArtifactGateError as exc:
        raise AssertionError(str(exc)) from exc
    return [
        f"PASS: {target_id} exact release-candidate manifest binding",
        f"PASS: {target_id} exact artifact-only signature gate",
    ]


def _require_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AssertionError(f"{label} must be an integer")
    return value


def _walk_runtime_strings(value: object, label: str) -> list[tuple[str, str]]:
    strings: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise AssertionError(f"{label} contains a non-string JSON key")
            strings.extend(_walk_runtime_strings(child, f"{label}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            strings.extend(_walk_runtime_strings(child, f"{label}[{index}]"))
    elif isinstance(value, str):
        strings.append((label, value))
    elif value is None or isinstance(value, (bool, int)):
        pass
    else:
        raise AssertionError(f"{label} contains unsupported JSON value {value!r}")
    return strings


def _validate_runtime_payload_safety(platform: str, payload: dict[str, object]) -> None:
    for label, value in _walk_runtime_strings(payload, platform):
        for marker in RUNTIME_FORBIDDEN_PAYLOAD_MARKERS:
            if marker in value:
                raise AssertionError(
                    f"{platform} runtime payload contains unsafe marker {marker!r} at {label}"
                )
        if IPV4_LITERAL_RE.search(value):
            raise AssertionError(f"{platform} runtime payload contains IPv4 literal at {label}")
        if UUID_LITERAL_RE.search(value):
            raise AssertionError(f"{platform} runtime payload contains UUID-like value at {label}")


def _read_runtime_payload(path: Path, result_type: str) -> dict[str, object]:
    if not path.is_file():
        raise AssertionError(f"runtime evidence result does not exist: {path}")
    text = read_text(path, max_bytes=SUBMISSION_JSON_MAX_BYTES)
    if result_type == "json_result":
        payload = _strict_json_loads(text, f"{path} runtime JSON result")
    elif result_type == "stdout_log":
        result_lines = [
            line[len(RUNTIME_STDOUT_RESULT_PREFIX) :]
            for line in text.splitlines()
            if line.startswith(RUNTIME_STDOUT_RESULT_PREFIX)
        ]
        if not result_lines:
            raise AssertionError(f"{path} does not contain a sanitized runtime result line")
        payload = _strict_json_loads(
            result_lines[-1], f"{path} runtime stdout result"
        )
    else:
        raise AssertionError(f"unknown runtime evidence result type {result_type!r}")

    if not isinstance(payload, dict):
        raise AssertionError(f"{path} runtime result must contain a JSON object")
    return payload


def _validate_runtime_payload(
    platform: str,
    result_type: str,
    result_path: Path,
    expected: dict[str, object],
) -> None:
    payload = _read_runtime_payload(result_path, result_type)
    _validate_runtime_payload_safety(platform, payload)

    if payload.get("schema_version") != 1:
        raise AssertionError(f"{platform} runtime payload must use schema_version 1")
    if payload.get("platform") != platform:
        raise AssertionError(
            f"{platform} runtime payload platform is {payload.get('platform')!r}"
        )
    for key, value in RUNTIME_REQUIRED_STRING_FIELDS.items():
        if payload.get(key) != value:
            raise AssertionError(
                f"{platform} runtime payload {key} is {payload.get(key)!r}, expected {value!r}"
            )
    for key in RUNTIME_REQUIRED_EMPTY_STRING_FIELDS:
        if payload.get(key) != "":
            raise AssertionError(f"{platform} runtime payload {key} must be empty")
    for key in RUNTIME_REQUIRED_TRUE_FIELDS:
        if payload.get(key) is not True:
            raise AssertionError(f"{platform} runtime payload {key} must be true")
    for key in RUNTIME_REQUIRED_FALSE_FIELDS:
        if payload.get(key) is not False:
            raise AssertionError(f"{platform} runtime payload {key} must be false")

    updated_at = payload.get("updated_at")
    if not isinstance(updated_at, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
        updated_at,
    ):
        raise AssertionError(f"{platform} runtime payload updated_at must be UTC ISO-8601")

    if set(expected) != RUNTIME_EXPECTED_FIELDS:
        missing = RUNTIME_EXPECTED_FIELDS.difference(expected)
        extra = set(expected).difference(RUNTIME_EXPECTED_FIELDS)
        raise AssertionError(
            f"{platform} runtime manifest expected fields mismatch; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )
    for key, expected_value in sorted(expected.items()):
        actual_value = payload.get(key)
        if actual_value != expected_value:
            raise AssertionError(
                f"{platform} runtime payload {key} is {actual_value!r}, "
                f"expected {expected_value!r}"
            )

    for key in [
        "external_leak_audit_endpoint_count",
        "external_leak_audit_minimum_endpoint_count",
        "external_leak_audit_success_count",
        "external_leak_audit_failure_count",
        "external_leak_audit_transport_error_count",
        "external_leak_audit_server_error_count",
        "external_leak_audit_invalid_endpoint_count",
        "external_leak_audit_https_canary_count",
        "external_leak_audit_dns_canary_count",
        "internet_probe_status_code",
        "leak_protection_dns_server_count",
        "leak_protection_engine_dns_server_count",
    ]:
        _require_int(payload.get(key), f"{platform} runtime payload {key}")

    if _require_int(payload.get("external_leak_audit_endpoint_count"), "endpoint count") < 2:
        raise AssertionError(f"{platform} runtime external audit must include at least two endpoints")
    if _require_int(payload.get("external_leak_audit_minimum_endpoint_count"), "minimum count") < 2:
        raise AssertionError(f"{platform} runtime external audit minimum must be at least two")
    if _require_int(payload.get("external_leak_audit_success_count"), "success count") < 2:
        raise AssertionError(f"{platform} runtime external audit must have at least two successes")
    if _require_int(payload.get("external_leak_audit_https_canary_count"), "HTTPS canary count") < 2:
        raise AssertionError(f"{platform} runtime external audit must have at least two HTTPS canaries")
    if _require_int(payload.get("external_leak_audit_dns_canary_count"), "DNS canary count") < 2:
        raise AssertionError(f"{platform} runtime external audit must have at least two DNS canaries")
    if _require_int(payload.get("leak_protection_dns_server_count"), "DNS server count") < 1:
        raise AssertionError(f"{platform} runtime leak protection must expose DNS servers")
    if _require_int(
        payload.get("leak_protection_engine_dns_server_count"),
        "engine DNS server count",
    ) < 1:
        raise AssertionError(f"{platform} runtime engine leak protection must expose DNS servers")


def _validate_runtime_result_identity(
    *,
    candidate_status: str,
    platform: str,
    evidence_status: str,
    bundle_id_at_test: str,
) -> None:
    if candidate_status not in RUNTIME_CANDIDATE_SET_STATUSES:
        raise AssertionError("runtime evidence candidate-set status is invalid")
    expected_current_bundle_id = CURRENT_APPLE_BUNDLE_IDS[platform][0]
    if platform == "ios":
        if evidence_status != CURRENT_ARTIFACT_STATUS:
            raise AssertionError("iOS runtime evidence must be current_candidate")
        if bundle_id_at_test != expected_current_bundle_id:
            raise AssertionError(
                "iOS runtime evidence bundle ID does not match the current candidate"
            )
        return
    if candidate_status == RUNTIME_PENDING_CANDIDATE_SET_STATUS:
        if evidence_status != SUPERSEDED_MACOS_ARTIFACT_STATUS:
            raise AssertionError(
                "pending macOS runtime evidence must remain marked superseded until rerun"
            )
        if bundle_id_at_test != "org.winsvpn.macos":
            raise AssertionError(
                "superseded macOS runtime evidence must identify its retired bundle ID"
            )
        return
    if evidence_status != CURRENT_ARTIFACT_STATUS:
        raise AssertionError("complete macOS runtime evidence must be current_candidate")
    if bundle_id_at_test != expected_current_bundle_id:
        raise AssertionError(
            "complete macOS runtime evidence bundle ID does not match the current candidate"
        )


def validate_runtime_evidence_manifest() -> list[str]:
    raw_manifest = read_text(
        RUNTIME_EVIDENCE_MANIFEST, max_bytes=SUBMISSION_JSON_MAX_BYTES
    )
    for marker in RUNTIME_FORBIDDEN_MANIFEST_MARKERS:
        if marker in raw_manifest:
            raise AssertionError(
                f"runtime_evidence.json contains forbidden marker {marker!r}"
            )
    manifest = _strict_json_loads(raw_manifest, "runtime_evidence.json")
    if not isinstance(manifest, dict):
        raise AssertionError("runtime_evidence.json must contain a JSON object")
    if manifest.get("schema_version") != 1:
        raise AssertionError("runtime_evidence.json must use schema_version 1")
    candidate_set_status = str(manifest.get("candidate_set_status") or "")
    if candidate_set_status not in RUNTIME_CANDIDATE_SET_STATUSES:
        raise AssertionError(
            "runtime_evidence.json candidate_set_status must reflect pending current "
            "runtime, a partial universal macOS rerun, or complete current evidence"
        )

    generated_at = manifest.get("generated_at_utc")
    if not isinstance(generated_at, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
        generated_at,
    ):
        raise AssertionError("runtime_evidence.json generated_at_utc must be UTC ISO-8601 seconds")

    expected_version, expected_build = pubspec_version()
    if manifest.get("app_version") != expected_version:
        raise AssertionError(
            f"runtime_evidence.json app_version={manifest.get('app_version')!r}, "
            f"expected {expected_version!r}"
        )
    if str(manifest.get("build_number")) != expected_build:
        raise AssertionError(
            f"runtime_evidence.json build_number={manifest.get('build_number')!r}, "
            f"expected {expected_build!r}"
        )

    release_manifest = read_json(ARTIFACT_MANIFEST)
    release_artifacts = release_manifest.get("artifacts")
    if not isinstance(release_artifacts, list):
        raise AssertionError("release_candidate.json artifacts must be a list")
    current_artifacts: dict[str, dict[str, object]] = {}
    for artifact in release_artifacts:
        if not isinstance(artifact, dict):
            raise AssertionError("release_candidate.json artifact entries must be objects")
        platform = artifact.get("platform")
        if platform in CURRENT_APPLE_BUNDLE_IDS:
            current_artifacts[str(platform)] = artifact
    if set(current_artifacts) != set(CURRENT_APPLE_BUNDLE_IDS):
        raise AssertionError("release_candidate.json current Apple artifacts are incomplete")

    if candidate_set_status == RUNTIME_NOT_STARTED_CANDIDATE_SET_STATUS:
        if manifest.get("runtime_log") not in {None, ""}:
            raise AssertionError(
                "pending runtime_evidence.json must not name an iOS runtime log"
            )
        if manifest.get("macos_runtime_log") not in {None, ""}:
            raise AssertionError(
                "pending runtime_evidence.json must not name a macOS runtime log"
            )
        if manifest.get("platform_results") != []:
            raise AssertionError(
                "pending runtime_evidence.json must not contain platform results"
            )
        if manifest.get("pending_reasons") != RUNTIME_NOT_STARTED_PENDING_REASONS:
            raise AssertionError(
                "pending runtime_evidence.json pending_reasons must list the exact "
                "iOS, macOS, and embedded watchOS companion gates"
            )
        watch_smoke = manifest.get("watch_companion_smoke")
        if (
            not isinstance(watch_smoke, dict)
            or watch_smoke.get("status") != "pending"
            or watch_smoke.get("receipt_path") not in {None, ""}
            or watch_smoke.get("receipt_sha256") not in {None, ""}
        ):
            raise AssertionError(
                "pending embedded watchOS companion smoke must stay unbound"
            )
        return [
            f"PASS: {RUNTIME_EVIDENCE_MANIFEST.relative_to(ROOT)} present",
            "PASS: current Apple runtime evidence is explicitly pending with no stale result reuse",
            "PASS: embedded watchOS companion smoke remains pending without a current candidate",
        ]

    # R22 Y3 D2: outside the not-started state a passed smoke must name a
    # durable .artifacts receipt that is re-hashed and re-derived against the
    # candidate set; complete runtime evidence requires it.
    try:
        watch_smoke_sha256 = watch_companion_smoke.runtime_watch_smoke_sha256(
            ROOT,
            manifest,
            release_manifest,
            release=f"{expected_version}+{expected_build}",
            require_passed=candidate_set_status == RUNTIME_COMPLETE_CANDIDATE_SET_STATUS,
        )
    except watch_companion_smoke.WatchSmokeError as exc:
        raise AssertionError(str(exc)) from exc
    watch_smoke_message = (
        f"PASS: embedded watchOS companion smoke receipt re-verified ({watch_smoke_sha256})"
        if watch_smoke_sha256
        else "PASS: embedded watchOS companion smoke remains pending"
    )

    runtime_log = str(manifest.get("runtime_log") or "")
    if not runtime_log.startswith("/tmp/wins_"):
        raise AssertionError("runtime_evidence.json runtime_log must be a /tmp/wins_* path")
    runtime_log_path = Path(runtime_log)
    if not runtime_log_path.is_file():
        raise AssertionError(f"runtime evidence log does not exist: {runtime_log}")
    runtime_log_text = runtime_log_path.read_text(encoding="utf-8", errors="replace")
    for marker in RUNTIME_LOG_MARKERS:
        if marker not in runtime_log_text:
            raise AssertionError(f"runtime evidence log missing proof marker {marker!r}")
    ios_permission_proof = "ui_automation"
    if RUNTIME_IOS_PERMISSION_UI_SUCCESS_MARKER not in runtime_log_text:
        missing = [
            marker
            for marker in RUNTIME_IOS_PERMISSION_DIRECT_PASS_MARKERS
            if marker not in runtime_log_text
        ]
        if missing:
            raise AssertionError(
                "runtime evidence log missing iOS VPN-permission proof: expected "
                f"{RUNTIME_IOS_PERMISSION_UI_SUCCESS_MARKER!r} or direct-pass markers "
                f"{missing!r}"
            )
        ios_permission_proof = "direct_live_tunnel_no_pending_permission"

    macos_runtime_log = str(manifest.get("macos_runtime_log") or "")
    if not macos_runtime_log.startswith("/tmp/wins_"):
        raise AssertionError(
            "runtime_evidence.json macos_runtime_log must be a /tmp/wins_* path"
        )
    macos_runtime_log_path = Path(macos_runtime_log)
    if not macos_runtime_log_path.is_file():
        raise AssertionError(
            f"macOS runtime evidence log does not exist: {macos_runtime_log}"
        )
    macos_runtime_log_text = macos_runtime_log_path.read_text(
        encoding="utf-8", errors="replace"
    )
    for marker in RUNTIME_MACOS_LOG_MARKERS:
        if marker not in macos_runtime_log_text:
            raise AssertionError(
                f"macOS runtime evidence log missing proof marker {marker!r}"
            )

    results = manifest.get("platform_results")
    if not isinstance(results, list) or len(results) != 2:
        raise AssertionError("runtime_evidence.json must list exactly two platform results")
    expected_results = {
        ("ios", "physical_device_live_tunnel", "stdout_log"),
        ("macos", "signed_live_tunnel", "json_result"),
    }
    seen: set[tuple[str, str, str]] = set()
    messages = [
        f"PASS: {RUNTIME_EVIDENCE_MANIFEST.relative_to(ROOT)} present",
        "PASS: runtime evidence log contains required live-smoke proof markers "
        f"({ios_permission_proof})",
        watch_smoke_message,
    ]

    for result in results:
        if not isinstance(result, dict):
            raise AssertionError("runtime_evidence.json platform results must be objects")
        key = (
            str(result.get("platform") or ""),
            str(result.get("lane") or ""),
            str(result.get("type") or ""),
        )
        if key not in expected_results:
            raise AssertionError(f"unexpected runtime evidence tuple {key!r}")
        if key in seen:
            raise AssertionError(f"duplicate runtime evidence tuple {key!r}")
        seen.add(key)

        result_path_text = str(result.get("path") or "")
        if not result_path_text.startswith("/"):
            raise AssertionError(f"{key!r} runtime result path must be absolute local evidence")
        expected = result.get("expected")
        if not isinstance(expected, dict):
            raise AssertionError(f"{key!r} runtime expected values must be an object")
        expected_current_bundle_id = CURRENT_APPLE_BUNDLE_IDS[key[0]][0]
        if result.get("expected_current_bundle_id") != expected_current_bundle_id:
            raise AssertionError(
                f"{key!r} expected_current_bundle_id must be "
                f"{expected_current_bundle_id!r}"
            )
        evidence_status = str(result.get("evidence_status") or "")
        bundle_id_at_test = str(result.get("bundle_id_at_test") or "")
        _validate_runtime_result_identity(
            candidate_status=candidate_set_status,
            platform=key[0],
            evidence_status=evidence_status,
            bundle_id_at_test=bundle_id_at_test,
        )
        validated_artifact_hash = str(
            result.get("validated_candidate_artifact_sha256") or ""
        )
        validated_source_hash = str(
            result.get("validated_candidate_source_fingerprint_sha256") or ""
        )
        current_artifact = current_artifacts[key[0]]
        if evidence_status == CURRENT_ARTIFACT_STATUS:
            expected_artifact_hash = str(current_artifact.get("sha256") or "")
            expected_source_hash = str(
                current_artifact.get("source_fingerprint_sha256") or ""
            )
            if validated_artifact_hash != expected_artifact_hash:
                raise AssertionError(
                    f"{key[0]} runtime evidence does not identify the current candidate artifact"
                )
            if validated_source_hash != expected_source_hash:
                raise AssertionError(
                    f"{key[0]} runtime evidence does not identify the current source fingerprint"
                )
            platform_log_text = (
                runtime_log_text if key[0] == "ios" else macos_runtime_log_text
            )
            for marker in [
                f"Runtime candidate artifact SHA-256: {expected_artifact_hash}",
                f"Runtime candidate source fingerprint SHA-256: {expected_source_hash}",
            ]:
                if marker not in platform_log_text:
                    raise AssertionError(
                        f"{key[0]} runtime evidence log missing candidate-binding marker {marker!r}"
                    )
            artifact_path_text = str(current_artifact.get("path") or "")
            artifact_path = ROOT / artifact_path_text
            result_path = Path(result_path_text)
            platform_log_path = (
                runtime_log_path if key[0] == "ios" else macos_runtime_log_path
            )
            artifact_mtime = artifact_path.stat().st_mtime
            if result_path.stat().st_mtime < artifact_mtime:
                raise AssertionError(
                    f"{key[0]} runtime result predates the current candidate artifact"
                )
            if platform_log_path.stat().st_mtime < artifact_mtime:
                raise AssertionError(
                    f"{key[0]} runtime evidence log predates the current candidate artifact"
                )
        elif validated_artifact_hash or validated_source_hash:
            raise AssertionError(
                f"{key[0]} superseded runtime evidence must not claim current candidate hashes"
            )
        _validate_runtime_payload(
            platform=key[0],
            result_type=key[2],
            result_path=Path(result_path_text),
            expected=expected,
        )
        if key[0] == "ios":
            messages.append(
                "PASS: ios current-candidate live tunnel evidence proves external canary checks"
            )
        elif evidence_status == CURRENT_ARTIFACT_STATUS:
            messages.append(
                "PASS: macos current-candidate live tunnel evidence proves external canary checks"
            )
        else:
            messages.append(
                "PASS: macos historical live tunnel evidence is valid but marked "
                "superseded pending universal rerun"
            )

    missing = expected_results.difference(seen)
    if missing:
        raise AssertionError(f"runtime_evidence.json missing platform results {sorted(missing)!r}")
    return messages


def _privacy_format_api_mapping(mapping: dict[str, frozenset[str]]) -> str:
    parts = []
    for api_type in sorted(mapping):
        reasons = ",".join(sorted(mapping[api_type]))
        parts.append(f"{api_type}={reasons}")
    return "{" + "; ".join(parts) + "}"


def _privacy_source_text_imports_mach_absolute_time(text: str) -> bool:
    return PRIVACY_MACH_ABSOLUTE_TIME_IMPORT_RE.search(text) is not None


def _privacy_source_paths(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise AssertionError(
            f"missing privacy source scan path: {path.relative_to(ROOT)}"
        )
    found = [
        child
        for child in sorted(path.rglob("*"))
        if child.is_file() and child.suffix in PRIVACY_SOURCE_SCAN_SUFFIXES
    ]
    if not found:
        raise AssertionError(
            f"privacy source scan path has no source files: {path.relative_to(ROOT)}"
        )
    return found


def _privacy_paths_import_mach_absolute_time(paths: tuple[Path, ...] | list[Path]) -> bool:
    for path in paths:
        for source in _privacy_source_paths(path):
            text = source.read_text(encoding="utf-8", errors="replace")
            if _privacy_source_text_imports_mach_absolute_time(text):
                return True
    return False


def packet_tunnel_imports_mach_absolute_time() -> bool:
    return _privacy_paths_import_mach_absolute_time(PRIVACY_PACKET_TUNNEL_SOURCE_ROOTS)


def winn_engine_imports_mach_absolute_time() -> bool:
    return _privacy_paths_import_mach_absolute_time(
        [PRIVACY_ENGINE_SOURCE_FILES[PRIVACY_WINN_ENGINE_FRAMEWORK]]
    )


def _expected_engine_accessed_apis(engine_name: str) -> dict[str, frozenset[str]]:
    if engine_name not in PRIVACY_ENGINE_SOURCE_FILES:
        raise AssertionError(f"unknown custom engine framework {engine_name}")
    source_path = PRIVACY_ENGINE_SOURCE_FILES[engine_name]
    if not source_path.is_file():
        raise AssertionError(
            f"missing custom engine source: {source_path.relative_to(ROOT)}"
        )
    mapping: dict[str, frozenset[str]] = {
        PRIVACY_FILE_TIMESTAMP_API: frozenset({PRIVACY_FILE_TIMESTAMP_REASON}),
    }
    if engine_name == PRIVACY_WINN_ENGINE_FRAMEWORK and (
        winn_engine_imports_mach_absolute_time()
    ):
        mapping[PRIVACY_SYSTEM_BOOT_TIME_API] = frozenset(
            {PRIVACY_SYSTEM_BOOT_TIME_REASON}
        )
    return mapping


def expected_tunnel_accessed_apis() -> dict[str, frozenset[str]]:
    return {
        PRIVACY_FILE_TIMESTAMP_API: frozenset({PRIVACY_FILE_TIMESTAMP_REASON}),
        # The compiled PacketTunnel image imports mach_absolute_time. Keep this
        # exact release contract independent of source-only or sibling-engine
        # scans, which cannot prove the extension binary's imported APIs.
        PRIVACY_SYSTEM_BOOT_TIME_API: frozenset(
            {PRIVACY_SYSTEM_BOOT_TIME_REASON}
        ),
    }


def expected_source_accessed_apis(kind: str) -> dict[str, frozenset[str]]:
    if kind == "watch":
        return dict(PRIVACY_WATCH_ACCESSED_APIS)
    if kind == "host":
        return dict(PRIVACY_HOST_ACCESSED_APIS)
    if kind == "tunnel":
        return expected_tunnel_accessed_apis()
    raise AssertionError(f"unknown privacy source kind {kind}")


def _require_exact_api_mapping(
    actual: dict[str, frozenset[str]],
    expected: dict[str, frozenset[str]],
    label: str,
) -> None:
    if actual == expected:
        return
    raise AssertionError(
        f"{label} accessed API mapping {_privacy_format_api_mapping(actual)}, "
        f"expected {_privacy_format_api_mapping(expected)}"
    )


def _privacy_api_reasons(
    manifest: dict[str, object],
    label: str,
    type_key: str = "NSPrivacyAccessedAPIType",
    reasons_key: str = "NSPrivacyAccessedAPITypeReasons",
    items_key: str = "NSPrivacyAccessedAPITypes",
) -> dict[str, frozenset[str]]:
    result: dict[str, frozenset[str]] = {}
    api_items = manifest.get(items_key) or []
    if not isinstance(api_items, list):
        raise AssertionError(f"{label} {items_key} must be a list")
    for item in api_items:
        if not isinstance(item, dict):
            raise AssertionError(f"{label} accessed API entries must be objects")
        extra_keys = set(item) - {type_key, reasons_key}
        if extra_keys:
            raise AssertionError(
                f"{label} unexpected accessed API keys {sorted(extra_keys)}"
            )
        api_type = item.get(type_key)
        reasons = item.get(reasons_key)
        if not isinstance(api_type, str) or not api_type:
            raise AssertionError(f"{label} accessed API type must be a string")
        if not isinstance(reasons, list) or not reasons:
            raise AssertionError(f"{label} accessed API reasons must be a non-empty list")
        if not all(isinstance(reason, str) and reason for reason in reasons):
            raise AssertionError(f"{label} accessed API reasons must be strings")
        if len(reasons) != len(set(reasons)):
            raise AssertionError(
                f"{label} duplicate accessed API reason for {api_type}"
            )
        if api_type in result:
            raise AssertionError(f"{label} duplicate accessed API type {api_type}")
        result[api_type] = frozenset(reasons)
    return result


def _privacy_collected_data_from_plist(
    manifest: dict[str, object],
    label: str,
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    data_items = manifest.get("NSPrivacyCollectedDataTypes") or []
    if not isinstance(data_items, list):
        raise AssertionError(f"{label} NSPrivacyCollectedDataTypes must be a list")
    for item in data_items:
        if not isinstance(item, dict):
            raise AssertionError(f"{label} collected data entries must be objects")
        data_type = item.get("NSPrivacyCollectedDataType")
        if not isinstance(data_type, str) or not data_type:
            raise AssertionError(f"{label} collected data type must be a string")
        if data_type in result:
            raise AssertionError(f"{label} duplicate collected data type {data_type}")
        result[data_type] = item
    return result


def _validate_tracking_disabled(manifest: dict[str, object], label: str) -> None:
    if manifest.get("NSPrivacyTracking") is not False:
        raise AssertionError(f"{label} NSPrivacyTracking must be false")
    if manifest.get("NSPrivacyTrackingDomains") not in ([], None):
        raise AssertionError(f"{label} NSPrivacyTrackingDomains must be empty")


def _validate_host_collected_plist(
    manifest: dict[str, object],
    label: str,
) -> None:
    collected = _privacy_collected_data_from_plist(manifest, label)
    actual = set(collected)
    if actual != PRIVACY_REQUIRED_DATA_TYPES:
        raise AssertionError(
            f"{label} collected data {sorted(actual)}, "
            f"expected {sorted(PRIVACY_REQUIRED_DATA_TYPES)}"
        )
    for data_type in sorted(PRIVACY_REQUIRED_DATA_TYPES):
        item = collected[data_type]
        if item.get("NSPrivacyCollectedDataTypeLinked") is not True:
            raise AssertionError(f"{label} {data_type} must be linked")
        if item.get("NSPrivacyCollectedDataTypeTracking") is not False:
            raise AssertionError(f"{label} {data_type} must not be tracking")
        purposes = item.get("NSPrivacyCollectedDataTypePurposes") or []
        if not isinstance(purposes, list):
            raise AssertionError(f"{label} {data_type} purposes must be a list")
        if set(purposes) != {PRIVACY_APP_FUNCTIONALITY_PURPOSE}:
            raise AssertionError(
                f"{label} {data_type} must include app functionality purpose"
            )


def _validate_source_privacy_plist(relative_path: str, kind: str) -> None:
    path = ROOT / relative_path
    if not path.is_file():
        raise AssertionError(f"missing source privacy manifest: {relative_path}")
    with path.open("rb") as handle:
        manifest = plistlib.load(handle)
    if not isinstance(manifest, dict):
        raise AssertionError(f"{relative_path} must contain a plist dictionary")

    _validate_tracking_disabled(manifest, relative_path)
    api_reasons = _privacy_api_reasons(manifest, relative_path)
    _require_exact_api_mapping(
        api_reasons,
        expected_source_accessed_apis(kind),
        relative_path,
    )
    if kind == "watch":
        if _privacy_collected_data_from_plist(manifest, relative_path):
            raise AssertionError(f"{relative_path} watch companion must collect no data")
        return
    if kind == "host":
        _validate_host_collected_plist(manifest, relative_path)
    elif _privacy_collected_data_from_plist(manifest, relative_path):
        raise AssertionError(f"{relative_path} PacketTunnel must collect no data")


def _archive_collected_data_types(manifest: dict[str, object], label: str) -> set[str]:
    data_items = manifest.get("collected_data_types")
    if not isinstance(data_items, list):
        raise AssertionError(f"{label} collected_data_types must be a list")
    result: set[str] = set()
    for item in data_items:
        if not isinstance(item, dict):
            raise AssertionError(f"{label} collected_data_types entries must be objects")
        data_type = item.get("data_type")
        if not isinstance(data_type, str) or not data_type:
            raise AssertionError(f"{label} collected data type must be a string")
        if data_type in result:
            raise AssertionError(f"{label} duplicate collected data type {data_type}")
        result.add(data_type)
    return result


def _validate_archive_host_data(manifest: dict[str, object], label: str) -> None:
    if _archive_collected_data_types(manifest, label) != PRIVACY_REQUIRED_DATA_TYPES:
        raise AssertionError(f"{label} host archive collected data mismatch")
    for item in manifest.get("collected_data_types") or []:
        if item.get("linked") is not True:
            raise AssertionError(f"{label} host collected data must be linked")
        if item.get("tracking") is not False:
            raise AssertionError(f"{label} host collected data must not be tracking")
        purposes = item.get("purposes")
        if not isinstance(purposes, list):
            raise AssertionError(f"{label} host collected purposes must be a list")
        if set(purposes) != {PRIVACY_APP_FUNCTIONALITY_PURPOSE}:
            raise AssertionError(
                f"{label} host collected data missing app functionality purpose"
            )


def _archive_api_reasons(manifest: dict[str, object], label: str) -> dict[str, frozenset[str]]:
    return _privacy_api_reasons(
        manifest,
        label,
        type_key="api_type",
        reasons_key="reasons",
        items_key="accessed_api_types",
    )


ARCHIVE_HOST_PRIVACY_PATHS = (
    re.compile(r"Products/Applications/[^/]+\.app/PrivacyInfo\.xcprivacy"),
    re.compile(r"Products/Applications/[^/]+\.app/Contents/Resources/PrivacyInfo\.xcprivacy"),
)


def required_archive_privacy_subjects(archive_name: str) -> list[str]:
    engines = list(PRIVACY_CUSTOM_ENGINE_FRAMEWORKS)
    if "macos" in archive_name:
        return ["runner", "packet_tunnel", "flutter", *engines]
    if "ios" in archive_name:
        return ["runner", "packet_tunnel", "watch", "flutter", *engines]
    raise AssertionError(f"{archive_name} is not a known Apple archive")


def archive_privacy_subject(relative_path: str) -> str:
    path = relative_path.replace("\\", "/")
    if not path.endswith("PrivacyInfo.xcprivacy"):
        raise AssertionError(f"unexpected privacy manifest path {relative_path}")
    # Classified by whole path segment, not substring: a directory that merely
    # contains one of these names (XWinsWinnPacketEngine.framework,
    # NotFlutter.framework) is not that subject (R24 X-01).
    segments = path.split("/")
    if "Watch" in segments or "WinsWatch.app" in segments:
        return "watch"
    if "PacketTunnel.appex" in segments:
        return "packet_tunnel"
    for engine in PRIVACY_CUSTOM_ENGINE_FRAMEWORKS:
        if f"{engine}.framework" in segments:
            return engine
    if "Flutter.framework" in segments or "FlutterMacOS.framework" in segments:
        return "flutter"
    if "/Frameworks/" in path or "/PlugIns/" in path:
        raise AssertionError(f"unexpected privacy manifest path {relative_path}")
    # The archive's single host app, whatever its product name (BasicCalc.app on
    # iOS, Win's VPN.app on macOS since the owner rulings of 2026-10-16).
    if any(pattern.fullmatch(path) for pattern in ARCHIVE_HOST_PRIVACY_PATHS):
        return "runner"
    raise AssertionError(f"unexpected privacy manifest path {relative_path}")


def _expected_archive_accessed_apis(subject: str) -> dict[str, frozenset[str]] | None:
    if subject == "runner":
        return dict(PRIVACY_HOST_ACCESSED_APIS)
    if subject == "packet_tunnel":
        return expected_tunnel_accessed_apis()
    if subject == "watch":
        return dict(PRIVACY_WATCH_ACCESSED_APIS)
    if subject == "flutter":
        return None
    if subject in PRIVACY_CUSTOM_ENGINE_FRAMEWORKS:
        return _expected_engine_accessed_apis(subject)
    raise AssertionError(f"unexpected privacy subject {subject}")


def _named_archive_entries(
    entries: list[object],
    label: str,
    name_key: str,
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise AssertionError(f"{label} entries must be objects")
        name = item.get(name_key)
        if not isinstance(name, str) or not name:
            raise AssertionError(f"{label} entries must be named objects")
        if name in result:
            raise AssertionError(f"{label} duplicate {name}")
        result[name] = item
    return result


def _validate_archive_privacy_report(
    manifest: dict[str, object],
    expected_archives: list[object],
) -> None:
    if manifest.get("report_type") != "local_archive_privacy_manifest_inventory":
        raise AssertionError("archive-privacy-manifests.json report_type mismatch")
    generated_at = manifest.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at.endswith("Z"):
        raise AssertionError("archive-privacy-manifests.json generated_at must be UTC")
    archives = manifest.get("archives")
    if not isinstance(archives, list):
        raise AssertionError("archive-privacy-manifests.json archives must be a list")
    if not isinstance(expected_archives, list):
        raise AssertionError("privacy_label_manifest expected_archives must be a list")

    archive_by_name = _named_archive_entries(archives, "archive-privacy-manifests.json", "archive")
    expected_by_name = _named_archive_entries(
        expected_archives,
        "privacy_label_manifest expected_archives",
        "archive",
    )
    if set(archive_by_name) != set(expected_by_name):
        raise AssertionError(
            "privacy archive names mismatch; "
            f"expected {sorted(expected_by_name)}, got {sorted(archive_by_name)}"
        )

    for archive_name, expected in sorted(expected_by_name.items()):
        archive = archive_by_name[archive_name]
        required_subjects = required_archive_privacy_subjects(archive_name)
        required_count = len(required_subjects)
        if expected.get("privacy_manifest_count") != required_count:
            raise AssertionError(
                f"{archive_name} expected privacy_manifest_count is "
                f"{expected.get('privacy_manifest_count')!r}, expected {required_count}"
            )
        if archive.get("application_count") != expected.get("application_count"):
            raise AssertionError(
                f"{archive_name} application_count is {archive.get('application_count')!r}, "
                f"expected {expected.get('application_count')!r}"
            )
        if archive.get("privacy_manifest_count") != required_count:
            raise AssertionError(
                f"{archive_name} privacy_manifest_count is "
                f"{archive.get('privacy_manifest_count')!r}, expected {required_count}"
            )
        manifests = archive.get("privacy_manifests")
        if not isinstance(manifests, list):
            raise AssertionError(f"{archive_name} privacy_manifests must be a list")
        if len(manifests) != required_count:
            raise AssertionError(
                f"{archive_name} privacy_manifests has {len(manifests)} entries, "
                f"expected {required_count}"
            )
        by_subject: dict[str, dict[str, object]] = {}
        for item in manifests:
            if not isinstance(item, dict):
                raise AssertionError(f"{archive_name} privacy manifest entries must be objects")
            path = item.get("path")
            if not isinstance(path, str) or not path:
                raise AssertionError(f"{archive_name} privacy manifest path must be a string")
            try:
                subject = archive_privacy_subject(path)
            except AssertionError as exc:
                raise AssertionError(f"{archive_name} {exc}") from exc
            if subject in by_subject:
                raise AssertionError(
                    f"{archive_name} duplicate privacy manifest for {subject}"
                )
            by_subject[subject] = item
            if item.get("tracking") is not False:
                raise AssertionError(f"{archive_name} {subject} tracking must be false")
            if item.get("tracking_domains") != []:
                raise AssertionError(
                    f"{archive_name} {subject} tracking domains must be empty"
                )
            actual_data = _archive_collected_data_types(
                item, f"{archive_name} {subject}"
            )
            if subject == "runner":
                expected_types = set(PRIVACY_REQUIRED_DATA_TYPES)
            else:
                expected_types = set()
            if actual_data != expected_types:
                raise AssertionError(
                    f"{archive_name} {subject} collected data {sorted(actual_data)}, "
                    f"expected {sorted(expected_types)}"
                )
            if subject == "runner":
                _validate_archive_host_data(item, f"{archive_name} runner")
            expected_apis = _expected_archive_accessed_apis(subject)
            if expected_apis is not None:
                actual_apis = _archive_api_reasons(item, f"{archive_name} {subject}")
                _require_exact_api_mapping(
                    actual_apis,
                    expected_apis,
                    f"{archive_name} {subject}",
                )

        missing = [subject for subject in required_subjects if subject not in by_subject]
        unexpected = sorted(set(by_subject) - set(required_subjects))
        if missing or unexpected:
            details = []
            if missing:
                details.append(f"missing {missing}")
            if unexpected:
                details.append(f"unexpected {unexpected}")
            raise AssertionError(
                f"{archive_name} privacy manifest inventory " + "; ".join(details)
            )


def live_portal_stale_message(published: set[str]) -> str:
    missing = sorted(PRIVACY_REQUIRED_LABELS - published)
    extra = sorted(published - PRIVACY_REQUIRED_LABELS)
    parts = ["live App Store Connect privacy labels are stale"]
    if missing:
        parts.append("add " + ", ".join(missing))
    if extra:
        parts.append("remove " + ", ".join(extra))
    return (
        "; ".join(parts)
        + ". This gate does not claim App Store Connect was updated."
    )


def require_live_portal_stale_status_recorded(manifest: dict[str, object]) -> None:
    live = manifest.get("live_app_store_connect_sync")
    if not isinstance(live, dict):
        raise AssertionError(
            "privacy_label_manifest.json live_app_store_connect_sync must be an object"
        )
    if live.get("app_store_connect_updated") is not False:
        raise AssertionError(
            "privacy_label_manifest.json must not claim App Store Connect was updated"
        )
    published = live.get("published_data_types")
    if not isinstance(published, list) or tuple(published) != (
        "Coarse Location",
        "User ID",
        "Device ID",
        "Purchase History",
    ):
        raise AssertionError(
            "privacy_label_manifest.json must record the stale live portal labels"
        )


def require_live_portal_matches_source_privacy(manifest: dict[str, object]) -> None:
    live = manifest.get("live_app_store_connect_sync")
    if not isinstance(live, dict):
        raise AssertionError(
            "privacy_label_manifest.json live_app_store_connect_sync must be an object"
        )
    published = live.get("published_data_types")
    if not isinstance(published, list) or not all(
        isinstance(item, str) and item for item in published
    ):
        raise AssertionError(
            "privacy_label_manifest.json published_data_types must be strings"
        )
    if len(published) != len(set(published)):
        raise AssertionError(
            "privacy_label_manifest.json published_data_types must not contain duplicates"
        )
    published_set = set(published)
    if published_set != PRIVACY_REQUIRED_LABELS:
        raise AssertionError(live_portal_stale_message(published_set))


def require_live_portal_flip_recorded(manifest: dict[str, object]) -> None:
    # R24 F-R24-01: after the owner updates the App Privacy answers, the
    # release-ready flip records App Store Connect as updated to exactly the
    # source labels; the pre-flip stale record is refused here, and the flipped
    # record is refused by require_live_portal_stale_status_recorded.
    require_live_portal_matches_source_privacy(manifest)
    live = manifest.get("live_app_store_connect_sync")
    if not isinstance(live, dict) or live.get("app_store_connect_updated") is not True:
        raise AssertionError(
            "privacy_label_manifest.json must record app_store_connect_updated true "
            "after the release-ready flip"
        )


PREMIUM_ACCESS_LINK_SOURCE = ROOT / "lib" / "premium_access_link.dart"
PREMIUM_ACCESS_OPEN_HEADER = "  Future<void> _openPremiumAccessHomePage() async {"


def _dart_method_body(source: str, header: str) -> str:
    start = source.find(header)
    if start < 0 or source.find(header, start + len(header)) >= 0:
        raise AssertionError(f"Apple purchase gate expects exactly one {header.strip()!r}")
    end = source.find("\n  }\n", start)
    if end < 0:
        raise AssertionError(f"Apple purchase gate cannot find the end of {header.strip()!r}")
    return source[start:end]


def _validate_apple_premium_access_home_page(
    purchase_gate: dict[str, object], main_text: str
) -> None:
    """Owner ruling 2026-10-24: the Apple build's Premium Access Info button
    opens exactly the developer's home page in the browser, and nothing else.

    Pins the NEW behavior rather than dropping the check: the exact URL (no
    path, query or anchor), the single label, every button routed to the one
    opener, an opener that reaches no payment sheet, payment route or checkout,
    no payment SDK in pubspec.yaml, and a widget test that taps the button and
    asserts the one launched URL and the absence of plan offers.
    """
    url = str(purchase_gate.get("premium_access_url") or "")
    label = str(purchase_gate.get("premium_access_label") or "")
    if url != "https://www.winsvpn.org":
        raise AssertionError("Apple purchase gate URL must be exactly https://www.winsvpn.org")
    if label != "Premium Access Info":
        raise AssertionError("Apple purchase gate label must be Premium Access Info")
    link_source = read_text(PREMIUM_ACCESS_LINK_SOURCE)
    for marker in (
        f"const String kPremiumAccessHomePageUrl = '{url}';",
        f"const String kPremiumAccessActionLabel = '{label}';",
    ):
        if marker not in link_source:
            raise AssertionError(f"Apple purchase gate link source missing {marker!r}")
    if "String get _premiumAccessActionLabel => kPremiumAccessActionLabel;" not in main_text:
        raise AssertionError("Apple purchase gate: the button label is not the single pinned label")
    opener = _dart_method_body(main_text, PREMIUM_ACCESS_OPEN_HEADER)
    for marker in (
        "if (_showDecoyCalculator) return;",
        "await _launchURL(",
        "kPremiumAccessHomePageUrl,",
    ):
        if marker not in opener:
            raise AssertionError(f"Apple purchase gate opener missing {marker!r}")
    forbidden = purchase_gate.get("forbidden_premium_action_markers")
    if not isinstance(forbidden, list) or not forbidden or not all(
        isinstance(item, str) and item for item in forbidden
    ):
        raise AssertionError("Apple purchase gate forbidden premium action markers missing")
    for marker in forbidden:
        if marker in opener:
            raise AssertionError(f"Apple purchase gate opener reaches {marker!r}")
    if main_text.count("_openPremiumAccessHomePage())") != 3:
        raise AssertionError(
            "Apple purchase gate: every premium button (activation, settings, renew) "
            "must open the home page"
        )
    if main_text.count("_showPaymentOptions(") != 1:
        raise AssertionError(
            "Apple purchase gate: the in-app plan sheet must have no call site"
        )
    sdk_markers = purchase_gate.get("forbidden_payment_sdk_dependency_markers")
    if not isinstance(sdk_markers, list) or not sdk_markers or not all(
        isinstance(item, str) and item for item in sdk_markers
    ):
        raise AssertionError("Apple purchase gate payment SDK markers missing")
    pubspec = read_text(ROOT / "pubspec.yaml").lower()
    for marker in sdk_markers:
        if marker.lower() in pubspec:
            raise AssertionError(f"Apple purchase gate: payment SDK present: {marker}")
    widget_test = read_text(ROOT / "test" / "widget_test.dart")
    test_name = str(purchase_gate.get("widget_test_marker") or "")
    start = widget_test.find(f"testWidgets('{test_name}'")
    if not test_name or start < 0:
        raise AssertionError("Apple purchase gate widget test marker missing")
    end = widget_test.find("\n  });", start)
    body = widget_test[start:end if end > start else len(widget_test)]
    for marker in (
        "Platform.isIOS || Platform.isMacOS",
        f"expect(launchedExternalUrls, <String>['{url}']);",
        "expect(find.text('1 Month Subscription'), findsNothing);",
        "expect(find.text(\"Open Win's VPN Website\"), findsNothing);",
        "expect(find.textContaining('For the Apple App Store build'), findsNothing);",
    ):
        if marker not in body:
            raise AssertionError(f"Apple purchase gate widget test missing {marker!r}")


def validate_privacy_label_manifest(*, release_ready: bool = False) -> list[str]:
    raw_manifest = read_text(
        PRIVACY_LABEL_MANIFEST, max_bytes=SUBMISSION_JSON_MAX_BYTES
    )
    for marker in RUNTIME_FORBIDDEN_MANIFEST_MARKERS:
        if marker in raw_manifest:
            raise AssertionError(
                f"privacy_label_manifest.json contains forbidden marker {marker!r}"
            )
    manifest = _strict_json_loads(raw_manifest, "privacy_label_manifest.json")
    if not isinstance(manifest, dict):
        raise AssertionError("privacy_label_manifest.json must contain a JSON object")
    if manifest.get("schema_version") != 1:
        raise AssertionError("privacy_label_manifest.json must use schema_version 1")
    expected_version, expected_build = pubspec_version()
    if manifest.get("app_version") != expected_version:
        raise AssertionError("privacy_label_manifest.json app_version mismatch")
    if str(manifest.get("build_number")) != expected_build:
        raise AssertionError("privacy_label_manifest.json build_number mismatch")

    if manifest.get("privacy_policy_url") != read_text(METADATA / "privacy_url.txt").strip():
        raise AssertionError("privacy_label_manifest.json privacy_policy_url mismatch")
    if manifest.get("privacy_choices_url") != read_text(METADATA / "support_url.txt").strip():
        raise AssertionError("privacy_label_manifest.json privacy_choices_url mismatch")

    summary = manifest.get("app_store_connect_summary")
    if not isinstance(summary, dict):
        raise AssertionError("privacy_label_manifest.json summary must be an object")
    if summary.get("data_used_to_track_you") is not False:
        raise AssertionError("privacy_label_manifest.json tracking answer must be false")
    if summary.get("tracking_domains") != []:
        raise AssertionError("privacy_label_manifest.json tracking domains must be empty")
    if summary.get("data_not_linked_to_user") != []:
        raise AssertionError("privacy_label_manifest.json unlinked data must be empty")
    if summary.get("packet_tunnel_collected_data_types") != []:
        raise AssertionError("privacy_label_manifest.json PacketTunnel data must be empty")
    if summary.get("framework_collected_data_types") != []:
        raise AssertionError("privacy_label_manifest.json framework data must be empty")
    if summary.get("diagnostics_uploaded_by_app") is not False:
        raise AssertionError("privacy_label_manifest.json diagnostics upload must be false")
    if summary.get("coarse_location_status") != "disclosed_linked_app_functionality":
        raise AssertionError("privacy_label_manifest.json coarse location status mismatch")
    if release_ready:
        # Once the portal matches source truth, the statuses no longer describe
        # a live over- or under-declaration.
        require_live_portal_flip_recorded(manifest)
        purchase_history_status = "not_collected"
        product_interaction_status = "disclosed_linked_app_functionality"
    else:
        purchase_history_status = "source_truth_not_collected_live_portal_over_declared"
        product_interaction_status = (
            "source_truth_disclosed_linked_app_functionality_live_portal_under_declared"
        )
    if summary.get("purchase_history_status") != purchase_history_status:
        raise AssertionError("privacy_label_manifest.json purchase history status mismatch")
    if summary.get("product_interaction_status") != product_interaction_status:
        raise AssertionError(
            "privacy_label_manifest.json product interaction status mismatch"
        )
    if not release_ready:
        require_live_portal_stale_status_recorded(manifest)

    linked_data = summary.get("data_linked_to_user")
    if not isinstance(linked_data, list):
        raise AssertionError("privacy_label_manifest.json linked data must be a list")
    linked_types: list[str] = []
    for item in linked_data:
        if not isinstance(item, dict):
            raise AssertionError("privacy_label_manifest.json linked data entries must be objects")
        data_type = item.get("apple_manifest_data_type")
        if not isinstance(data_type, str) or not data_type:
            raise AssertionError("privacy_label_manifest.json linked data type must be a string")
        if data_type == PRIVACY_PURCHASE_HISTORY:
            raise AssertionError(
                "privacy_label_manifest.json linked data must not include Purchase History"
            )
        if data_type in linked_types:
            raise AssertionError(
                f"privacy_label_manifest.json duplicate linked data type {data_type}"
            )
        linked_types.append(data_type)
        if item.get("label") != PRIVACY_LINKED_LABELS.get(data_type):
            raise AssertionError("privacy_label_manifest.json linked data label mismatch")
        if item.get("category") != PRIVACY_LINKED_CATEGORIES.get(data_type):
            raise AssertionError("privacy_label_manifest.json linked data category mismatch")
        if item.get("linked") is not True or item.get("tracking") is not False:
            raise AssertionError("privacy_label_manifest.json linked data flags mismatch")
        if item.get("purposes") != [PRIVACY_APP_FUNCTIONALITY_PURPOSE]:
            raise AssertionError("privacy_label_manifest.json linked data purposes mismatch")
    if set(linked_types) != PRIVACY_REQUIRED_DATA_TYPES:
        raise AssertionError("privacy_label_manifest.json linked data type mismatch")

    source_manifests = manifest.get("source_privacy_manifests")
    if not isinstance(source_manifests, dict):
        raise AssertionError("privacy_label_manifest.json source_privacy_manifests must be an object")
    for key, (relative_path, kind) in PRIVACY_SOURCE_MANIFESTS.items():
        if source_manifests.get(key) != relative_path:
            raise AssertionError(f"privacy_label_manifest.json source path mismatch for {key}")
        _validate_source_privacy_plist(relative_path, kind)

    evidence = manifest.get("binary_evidence")
    if not isinstance(evidence, dict):
        raise AssertionError("privacy_label_manifest.json binary_evidence must be an object")
    source_host_types = evidence.get("source_host_collected_data_types")
    if not isinstance(source_host_types, list) or not all(
        isinstance(item, str) and item for item in source_host_types
    ):
        raise AssertionError(
            "privacy_label_manifest.json source_host_collected_data_types must be strings"
        )
    if len(source_host_types) != len(set(source_host_types)):
        raise AssertionError(
            "privacy_label_manifest.json source host collected data has duplicates"
        )
    if set(source_host_types) != PRIVACY_REQUIRED_DATA_TYPES:
        raise AssertionError(
            "privacy_label_manifest.json source host collected data mismatch"
        )
    archive_json_path = str(evidence.get("archive_privacy_json") or "")
    archive_markdown_path = str(evidence.get("archive_privacy_markdown") or "")
    if archive_json_path != "build/apple/privacy/archive-privacy-manifests.json":
        raise AssertionError("privacy_label_manifest.json archive JSON path mismatch")
    if archive_markdown_path != "build/apple/privacy/archive-privacy-manifests.md":
        raise AssertionError("privacy_label_manifest.json archive Markdown path mismatch")
    candidate_manifest = read_json(ARTIFACT_MANIFEST)
    pending_candidate = (
        str(candidate_manifest.get("candidate_set_status") or "") == "no_current_candidate"
    )
    archive_json = ROOT / archive_json_path
    archive_markdown_file = ROOT / archive_markdown_path
    if pending_candidate and not archive_json.is_file() and not archive_markdown_file.is_file():
        archive_message = (
            "PASS: Apple archive privacy inventory remains unbound without a current candidate"
        )
    else:
        archive_report = read_json(archive_json)
        if not isinstance(archive_report, dict):
            raise AssertionError("archive-privacy-manifests.json must contain an object")
        _validate_archive_privacy_report(archive_report, evidence.get("expected_archives"))
        archive_markdown = read_text(archive_markdown_file)
        for marker in [
            "Privacy manifests found: 7",
            "Privacy manifests found: 6",
            "tracking: False",
            PRIVACY_HOST_ARCHIVE_MARKDOWN,
            "Watch/WinsWatch.app",
            "Flutter.framework",
            "WinsAmneziaWGPacketEngine.framework",
            "WinsXrayVlessWsTransport.framework",
            "WinsWinnPacketEngine.framework",
        ]:
            if marker not in archive_markdown:
                raise AssertionError(f"archive privacy markdown missing marker {marker!r}")
        archive_message = "PASS: Apple archive privacy report matches privacy-label manifest"

    purchase_gate = manifest.get("apple_purchase_gate")
    if not isinstance(purchase_gate, dict):
        raise AssertionError("privacy_label_manifest.json apple_purchase_gate must be an object")
    if purchase_gate.get("dart_define") != "WINS_ENABLE_EXTERNAL_PAYMENT_LINKS":
        raise AssertionError("privacy_label_manifest.json Apple purchase dart define mismatch")
    if purchase_gate.get("default_external_payment_links_enabled") is not False:
        raise AssertionError("privacy_label_manifest.json Apple purchase default must be false")
    main_text = read_text(ROOT / "lib" / "main.dart")
    for marker in [
        "'WINS_ENABLE_EXTERNAL_PAYMENT_LINKS'",
        "defaultValue: false",
    ]:
        if marker not in main_text:
            raise AssertionError(f"Apple purchase gate source missing marker {marker!r}")
    _validate_apple_premium_access_home_page(purchase_gate, main_text)

    forbidden_dependencies = manifest.get("forbidden_pubspec_dependency_markers")
    if not isinstance(forbidden_dependencies, list) or not all(
        isinstance(item, str) and item for item in forbidden_dependencies
    ):
        raise AssertionError("privacy_label_manifest.json forbidden dependencies must be strings")
    pubspec = read_text(ROOT / "pubspec.yaml").lower()
    for marker in forbidden_dependencies:
        if marker.lower() in pubspec:
            raise AssertionError(
                f"privacy_label_manifest.json forbidden dependency present: {marker}"
            )

    for path, markers in PRIVACY_REQUIRED_DOC_MARKERS.items():
        text = read_text(path)
        for marker in markers:
            if marker not in text:
                raise AssertionError(
                    f"{path.relative_to(ROOT)} missing privacy marker {marker!r}"
                )

    return [
        f"PASS: {PRIVACY_LABEL_MANIFEST.relative_to(ROOT)} present",
        "PASS: Apple privacy-label manifest matches source PrivacyInfo plists",
        archive_message,
        "PASS: Apple default purchase path stays store-safe for privacy review",
        "PASS: Apple privacy-label docs and dependency exclusions verified",
    ]


def _read_tmp_evidence_log(path_text: object, label: str) -> str:
    path = str(path_text or "")
    if not path.startswith("/tmp/wins_"):
        raise AssertionError(f"{label} must be a /tmp/wins_* evidence log path")
    log_path = Path(path)
    if not log_path.is_file():
        raise AssertionError(f"{label} evidence log does not exist: {path}")
    return log_path.read_text(encoding="utf-8", errors="replace")


def _require_blocker(
    blockers: dict[str, object],
    key: str,
    status: str,
) -> dict[str, object]:
    value = blockers.get(key)
    if not isinstance(value, dict):
        raise AssertionError(f"rollout_readiness.json blocker {key!r} must be an object")
    if value.get("status") != status:
        raise AssertionError(
            f"rollout_readiness.json blocker {key!r} status is "
            f"{value.get('status')!r}, expected {status!r}"
        )
    return value


def validate_rollout_readiness_manifest() -> list[str]:
    raw_manifest = read_text(
        ROLLOUT_READINESS_MANIFEST, max_bytes=SUBMISSION_JSON_MAX_BYTES
    )
    for marker in RUNTIME_FORBIDDEN_MANIFEST_MARKERS:
        if marker in raw_manifest:
            raise AssertionError(
                f"rollout_readiness.json contains forbidden marker {marker!r}"
            )
    manifest = _strict_json_loads(raw_manifest, "rollout_readiness.json")
    if not isinstance(manifest, dict):
        raise AssertionError("rollout_readiness.json must contain a JSON object")
    if manifest.get("schema_version") != 1:
        raise AssertionError("rollout_readiness.json must use schema_version 1")
    if manifest.get("production_ready") is not False:
        raise AssertionError(
            "rollout_readiness.json production_ready must remain false "
            "until owner sign-off, upload, Apple processing/review, and "
            "macOS package install rehearsal are complete"
        )

    last_reviewed = manifest.get("last_reviewed")
    if not isinstance(last_reviewed, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}",
        last_reviewed,
    ):
        raise AssertionError("rollout_readiness.json last_reviewed must be YYYY-MM-DD")

    expected_version, expected_build = pubspec_version()
    if manifest.get("app_version") != expected_version:
        raise AssertionError(
            f"rollout_readiness.json app_version={manifest.get('app_version')!r}, "
            f"expected {expected_version!r}"
        )
    if str(manifest.get("build_number")) != expected_build:
        raise AssertionError(
            f"rollout_readiness.json build_number={manifest.get('build_number')!r}, "
            f"expected {expected_build!r}"
        )

    for key, expected_path in ROLLOUT_EXPECTED_MANIFEST_PATHS.items():
        if manifest.get(key) != expected_path:
            raise AssertionError(
                f"rollout_readiness.json {key} is {manifest.get(key)!r}, "
                f"expected {expected_path!r}"
            )
        if not (ROOT / expected_path).is_file():
            raise AssertionError(f"rollout_readiness.json {key} target is missing")

    source_readiness_status = manifest.get("source_readiness_status", "complete")
    if source_readiness_status == "pending_current_refresh":
        if manifest.get("source_readiness_log") not in {None, ""}:
            raise AssertionError(
                "pending rollout readiness must not reuse a stale source_readiness_log"
            )
        source_readiness_message = (
            "PASS: current source-readiness evidence is explicitly pending without stale log reuse"
        )
    elif source_readiness_status == "complete":
        source_log_text = _read_tmp_evidence_log(
            manifest.get("source_readiness_log"),
            "rollout_readiness.json source_readiness_log",
        )
        for marker in ROLLOUT_REQUIRED_SOURCE_LOG_MARKERS:
            if marker not in source_log_text:
                raise AssertionError(
                    f"rollout_readiness.json source_readiness_log missing marker {marker!r}"
                )
        native_source_match = re.search(
            r"Apple native XCTest source gate passed with "
            r"iOS=([1-9][0-9]*) and macOS=([1-9][0-9]*) tests\.",
            source_log_text,
        )
        ios_execution_match = re.search(
            r"iOS native XCTest passed with ([1-9][0-9]*) tests\.",
            source_log_text,
        )
        macos_execution_match = re.search(
            r"macOS native XCTest passed with ([1-9][0-9]*) tests\.",
            source_log_text,
        )
        for match, label in (
            (native_source_match, "native XCTest source counts"),
            (ios_execution_match, "iOS native XCTest execution count"),
            (macos_execution_match, "macOS native XCTest execution count"),
        ):
            if match is None:
                raise AssertionError(
                    f"rollout_readiness.json source_readiness_log missing positive {label}"
                )
        source_ios_count, source_macos_count = (
            int(native_source_match.group(1)),
            int(native_source_match.group(2)),
        )
        if source_ios_count != int(ios_execution_match.group(1)):
            raise AssertionError(
                "rollout_readiness.json iOS native XCTest source/execution counts differ"
            )
        if source_macos_count != int(macos_execution_match.group(1)):
            raise AssertionError(
                "rollout_readiness.json macOS native XCTest source/execution counts differ"
            )
        source_readiness_message = "PASS: rollout source-readiness evidence log verified"
    else:
        raise AssertionError(
            "rollout_readiness.json source_readiness_status must be "
            "'pending_current_refresh' or 'complete'"
        )

    negative_logs = manifest.get("negative_upload_guard_logs")
    if not isinstance(negative_logs, dict):
        raise AssertionError("rollout_readiness.json negative_upload_guard_logs must be an object")
    if set(negative_logs) != set(ROLLOUT_NEGATIVE_LOG_MARKERS):
        raise AssertionError(
            "rollout_readiness.json negative_upload_guard_logs must contain "
            f"{sorted(ROLLOUT_NEGATIVE_LOG_MARKERS)}"
        )
    logs_present = any(str(negative_logs.get(key) or "") for key in ROLLOUT_NEGATIVE_LOG_MARKERS)
    if source_readiness_status == "pending_current_refresh" and not logs_present:
        pass
    else:
        for key, marker in sorted(ROLLOUT_NEGATIVE_LOG_MARKERS.items()):
            text = _read_tmp_evidence_log(
                negative_logs.get(key),
                f"rollout_readiness.json negative_upload_guard_logs.{key}",
            )
            if marker not in text:
                raise AssertionError(
                    f"rollout_readiness.json negative log {key!r} missing marker {marker!r}"
                )

    release_candidate = read_json(ARTIFACT_MANIFEST)
    if not isinstance(release_candidate, dict):
        raise AssertionError("release_candidate.json must contain a JSON object")
    release_upload_status = str(release_candidate.get("upload_status") or "")
    if release_upload_status not in {"not_uploaded", "uploaded_processed_and_attached"}:
        raise AssertionError("rollout_readiness.json release upload status is unsupported")
    upload_complete = release_upload_status == "uploaded_processed_and_attached"
    release_artifacts = release_candidate.get("artifacts")
    if not isinstance(release_artifacts, list):
        raise AssertionError("release_candidate.json artifacts must be a list")
    macos_candidates = [
        artifact
        for artifact in release_artifacts
        if isinstance(artifact, dict)
        and artifact.get("platform") == "macos"
        and artifact.get("lane") == "app_store_local"
        and artifact.get("type") == "pkg"
    ]
    if len(macos_candidates) != 1:
        raise AssertionError(
            "release_candidate.json must contain exactly one macOS App Store-local PKG"
        )
    macos_candidate = macos_candidates[0]
    owner_signoff = read_json(PACKAGE / "review" / "owner_signoff.json")
    if not isinstance(owner_signoff, dict):
        raise AssertionError("owner_signoff.json must contain a JSON object")
    owner_approved = owner_signoff.get("submission_approved") is True

    api_access = manifest.get("app_store_connect_api_access")
    if not isinstance(api_access, dict):
        raise AssertionError("rollout_readiness.json App Store API access must be an object")
    api_access_status = api_access.get("status")
    if api_access_status not in {
        ROLLOUT_API_ACCESS_READY_STATUS,
        ROLLOUT_API_ACCESS_PENDING_STATUS,
    }:
        raise AssertionError("rollout_readiness.json App Store API access status mismatch")
    api_access_ready = api_access_status == ROLLOUT_API_ACCESS_READY_STATUS

    blockers = manifest.get("remaining_blockers")
    if not isinstance(blockers, dict):
        raise AssertionError("rollout_readiness.json remaining_blockers must be an object")
    completed_gates = manifest.get("completed_gates", {})
    if not isinstance(completed_gates, dict):
        raise AssertionError("rollout_readiness.json completed_gates must be an object")
    if set(completed_gates) - {ROLLOUT_MACOS_PKG_GATE}:
        raise AssertionError(
            "rollout_readiness.json completed_gates contains an unknown gate"
        )
    macos_pkg_completed = ROLLOUT_MACOS_PKG_GATE in completed_gates
    expected_blockers = set(ROLLOUT_BASE_BLOCKERS)
    if not upload_complete:
        expected_blockers.add(ROLLOUT_UPLOAD_GATE)
    if not macos_pkg_completed:
        expected_blockers.add(ROLLOUT_MACOS_PKG_GATE)
    if not owner_approved:
        expected_blockers.update(ROLLOUT_OWNER_PENDING_BLOCKERS)
    if not api_access_ready:
        expected_blockers.add(ROLLOUT_API_AUTH_GATE)
    if set(blockers) != expected_blockers:
        raise AssertionError(
            "rollout_readiness.json remaining_blockers mismatch; "
            f"expected {sorted(expected_blockers)}, got {sorted(blockers)}"
        )

    if not owner_approved:
        owner_blocker = _require_blocker(blockers, "owner_signoff", "pending")
        if owner_blocker.get("source_file") != "app_store/apple/review/owner_signoff.json":
            raise AssertionError("rollout_readiness.json owner_signoff source_file mismatch")
        if owner_blocker.get("required_before") != [
            "testflight_upload",
            "app_store_connect_upload",
        ]:
            raise AssertionError("rollout_readiness.json owner_signoff required_before mismatch")

    app_record = manifest.get("app_store_connect_record")
    if not isinstance(app_record, dict):
        raise AssertionError("rollout_readiness.json app_store_connect_record must be an object")
    if app_record != {
        "status": "created",
        "apple_id": "6789417002",
        "company_name": "Win's VPN Inc",
        "platforms": ["ios", "macos"],
        "bundle_id": "org.winsvpn.app",
        "sku": "winsvpn-apple-20260709",
    }:
        raise AssertionError("rollout_readiness.json universal App Store record mismatch")

    if api_access.get("required_env") != ROLLOUT_REQUIRED_ENV:
        raise AssertionError("rollout_readiness.json App Store auth env list mismatch")
    if api_access.get("storage_rule") != "outside_repo_chmod_600":
        raise AssertionError("rollout_readiness.json App Store auth storage rule mismatch")
    if api_access.get("expected_apple_id") != "6789417002":
        raise AssertionError("rollout_readiness.json App Store API Apple ID mismatch")
    if api_access.get("expected_bundle_id") != "org.winsvpn.app":
        raise AssertionError("rollout_readiness.json App Store API bundle ID mismatch")
    if api_access_ready:
        api_log_text = _read_tmp_evidence_log(
            api_access.get("verification_log"),
            "rollout_readiness.json app_store_connect_api_access.verification_log",
        )
        for marker in (
            "PASS: App Store Connect API authentication succeeded (HTTP 200)",
            "Apple ID 6789417002; bundle ID org.winsvpn.app",
            "SUMMARY: 2/2 checks passing",
        ):
            if marker not in api_log_text:
                raise AssertionError(
                    "rollout_readiness.json App Store API log missing marker "
                    f"{marker!r}"
                )
    else:
        if api_access.get("verification_log") not in {None, ""}:
            raise AssertionError(
                "pending App Store API access must not reuse a stale verification_log"
            )
        api_blocker = _require_blocker(
            blockers,
            ROLLOUT_API_AUTH_GATE,
            ROLLOUT_API_ACCESS_PENDING_STATUS,
        )
        if api_blocker.get("required_env") != ROLLOUT_REQUIRED_ENV:
            raise AssertionError("rollout readiness App Store API blocker env mismatch")
        if api_blocker.get("storage_rule") != "outside_repo_chmod_600":
            raise AssertionError("rollout readiness App Store API blocker storage mismatch")

    if not upload_complete:
        upload_blocker = _require_blocker(
            blockers,
            ROLLOUT_UPLOAD_GATE,
            "not_run",
        )
        expected_upload_blockers = []
        if not owner_approved:
            expected_upload_blockers.append("owner_signoff")
        if not api_access_ready:
            expected_upload_blockers.append(ROLLOUT_API_AUTH_GATE)
        if upload_blocker.get("blocked_by") != expected_upload_blockers:
            raise AssertionError("rollout_readiness.json upload blocker dependencies mismatch")

    review_blocker = _require_blocker(
        blockers,
        "apple_processing_and_review",
        "not_started",
    )
    expected_review_blockers = [ROLLOUT_DSA_GATE, ROLLOUT_ENCRYPTION_GATE]
    if not upload_complete:
        expected_review_blockers.insert(0, ROLLOUT_UPLOAD_GATE)
    if review_blocker.get("blocked_by") != expected_review_blockers:
        raise AssertionError("rollout_readiness.json Apple review dependency mismatch")

    dsa_blocker = _require_blocker(blockers, ROLLOUT_DSA_GATE, "not_configured")
    if dsa_blocker.get("source_url") != (
        "https://appstoreconnect.apple.com/business"
    ):
        raise AssertionError("rollout_readiness.json DSA source URL mismatch")
    if dsa_blocker.get("blocked_by") != [
        "account_holder_trader_declaration_and_verification"
    ]:
        raise AssertionError("rollout_readiness.json DSA dependency mismatch")

    encryption_blocker = _require_blocker(
        blockers,
        ROLLOUT_ENCRYPTION_GATE,
        "pending_legal_determination_and_apple_review",
    )
    if encryption_blocker.get("source_file") != (
        "app_store/apple/review/export_compliance_facts.txt"
    ):
        raise AssertionError(
            "rollout_readiness.json encryption source file mismatch"
        )
    if encryption_blocker.get("blocked_by") != [
        "owner_legal_export_classification",
        "app_store_connect_encryption_questionnaire",
    ]:
        raise AssertionError("rollout_readiness.json encryption dependency mismatch")

    if macos_pkg_completed:
        macos_gate = completed_gates.get(ROLLOUT_MACOS_PKG_GATE)
        if not isinstance(macos_gate, dict):
            raise AssertionError(
                "rollout_readiness.json completed macOS package gate must be an object"
            )
        if macos_gate.get("status") != "passed":
            raise AssertionError(
                "rollout_readiness.json completed macOS package gate must be passed"
            )
        if macos_gate.get("artifact_sha256") != macos_candidate.get("sha256"):
            raise AssertionError(
                "rollout_readiness.json completed macOS package gate artifact hash mismatch"
            )
        macos_log_text = _read_tmp_evidence_log(
            macos_gate.get("verification_log"),
            "rollout_readiness.json completed_gates.macos_pkg_clean_install.verification_log",
        )
        for marker in ROLLOUT_MACOS_PKG_SUCCESS_MARKERS:
            if marker not in macos_log_text:
                raise AssertionError(
                    "rollout_readiness.json completed macOS package log missing marker "
                    f"{marker!r}"
                )
    else:
        macos_blocker = _require_blocker(
            blockers,
            ROLLOUT_MACOS_PKG_GATE,
            ROLLOUT_MACOS_PKG_PENDING_STATUS,
        )
        if str(release_candidate.get("candidate_set_status") or "") == "no_current_candidate":
            if macos_blocker.get("latest_root_gate_log") not in {None, ""}:
                raise AssertionError(
                    "pending macOS package gate must not reuse a stale install log "
                    "while no current candidate exists"
                )
        else:
            macos_log_text = _read_tmp_evidence_log(
                macos_blocker.get("latest_root_gate_log"),
                "rollout_readiness.json macos_pkg_clean_install.latest_root_gate_log",
            )
            for marker in ROLLOUT_MACOS_PKG_LOG_MARKERS:
                if marker not in macos_log_text:
                    raise AssertionError(
                        "rollout_readiness.json macOS package log missing marker "
                        f"{marker!r}"
                    )
            if not any(
                marker in macos_log_text
                for marker in ROLLOUT_MACOS_PKG_AUTHORIZATION_BOUNDARY_MARKERS
            ):
                raise AssertionError(
                    "rollout_readiness.json macOS package log does not prove an "
                    "administrator-authorization or clean-system boundary"
                )

    if not owner_approved:
        metadata_blocker = _require_blocker(
            blockers,
            "final_metadata_privacy_review",
            "pending_owner_review",
        )
        if metadata_blocker.get("source_file") != "app_store/apple/review/owner_review_packet.md":
            raise AssertionError(
                "rollout_readiness.json final metadata source_file mismatch"
            )

    return [
        f"PASS: {display_path(ROLLOUT_READINESS_MANIFEST)} present",
        source_readiness_message,
        "PASS: rollout readiness API-auth and upload-negative evidence logs verified",
        "PASS: rollout readiness blockers match owner sign-off and upload manifests",
        "PASS: rollout readiness macOS package gate evidence verified",
    ]


def png_chunks(data: bytes, path: Path) -> list[tuple[bytes, bytes]]:
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise AssertionError(f"{display_path(path)} is not a valid PNG")
    chunks: list[tuple[bytes, bytes]] = []
    offset = 8
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_start = offset + 8
        chunk_end = chunk_start + length
        crc_end = chunk_end + 4
        if crc_end > len(data):
            raise AssertionError(f"{display_path(path)} has a truncated PNG chunk")
        chunks.append((chunk_type, data[chunk_start:chunk_end]))
        offset = crc_end
        if chunk_type == b"IEND":
            break
    if not chunks or chunks[-1][0] != b"IEND":
        raise AssertionError(f"{display_path(path)} is missing PNG IEND")
    return chunks


def png_info(path: Path) -> tuple[int, int, int, int, int]:
    data = path.read_bytes()
    chunks = png_chunks(data, path)
    if chunks[0][0] != b"IHDR" or len(chunks[0][1]) != 13:
        raise AssertionError(f"{display_path(path)} is not a valid PNG")
    width, height, bit_depth, color_type, _compression, _filter, interlace = (
        struct.unpack(">IIBBBBB", chunks[0][1])
    )
    return int(width), int(height), int(bit_depth), int(color_type), int(interlace)


def png_dimensions(path: Path) -> tuple[int, int]:
    width, height, _bit_depth, _color_type, _interlace = png_info(path)
    return width, height


def _paeth_predictor(left: int, up: int, upper_left: int) -> int:
    estimate = left + up - upper_left
    left_distance = abs(estimate - left)
    up_distance = abs(estimate - up)
    upper_left_distance = abs(estimate - upper_left)
    if left_distance <= up_distance and left_distance <= upper_left_distance:
        return left
    if up_distance <= upper_left_distance:
        return up
    return upper_left


def png_visual_metrics(path: Path) -> dict[str, float]:
    data = path.read_bytes()
    chunks = png_chunks(data, path)
    width, height, bit_depth, color_type, interlace = png_info(path)
    if bit_depth != 8 or color_type not in {2, 6} or interlace != 0:
        raise AssertionError(
            f"{display_path(path)} must be an 8-bit non-interlaced RGB/RGBA PNG"
        )
    channels = 4 if color_type == 6 else 3
    bytes_per_pixel = channels
    row_bytes = width * channels
    compressed = b"".join(payload for kind, payload in chunks if kind == b"IDAT")
    try:
        decoded = zlib.decompress(compressed)
    except zlib.error as exc:
        raise AssertionError(f"{display_path(path)} has invalid PNG image data") from exc
    expected_decoded = (row_bytes + 1) * height
    if len(decoded) != expected_decoded:
        raise AssertionError(
            f"{display_path(path)} decoded length is {len(decoded)}, "
            f"expected {expected_decoded}"
        )

    total_pixels = width * height
    sample_stride = max(1, total_pixels // 50_000)
    sampled_pixels = 0
    opaque_pixels = 0
    min_luminance = 255
    max_luminance = 0
    color_bins: set[tuple[int, int, int]] = set()
    previous = bytearray(row_bytes)
    pixel_index = 0

    for y in range(height):
        row_start = y * (row_bytes + 1)
        filter_type = decoded[row_start]
        raw = decoded[row_start + 1 : row_start + 1 + row_bytes]
        row = bytearray(row_bytes)
        for index, value in enumerate(raw):
            left = row[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            up = previous[index]
            upper_left = (
                previous[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            )
            if filter_type == 0:
                restored = value
            elif filter_type == 1:
                restored = value + left
            elif filter_type == 2:
                restored = value + up
            elif filter_type == 3:
                restored = value + ((left + up) // 2)
            elif filter_type == 4:
                restored = value + _paeth_predictor(left, up, upper_left)
            else:
                raise AssertionError(
                    f"{display_path(path)} has unsupported PNG filter {filter_type}"
                )
            row[index] = restored & 0xFF

        for x in range(width):
            if pixel_index % sample_stride == 0:
                offset = x * channels
                r, g, b = row[offset], row[offset + 1], row[offset + 2]
                alpha = row[offset + 3] if channels == 4 else 255
                luminance = int(round((0.2126 * r) + (0.7152 * g) + (0.0722 * b)))
                min_luminance = min(min_luminance, luminance)
                max_luminance = max(max_luminance, luminance)
                color_bins.add((r // 16, g // 16, b // 16))
                sampled_pixels += 1
                if alpha >= 250:
                    opaque_pixels += 1
            pixel_index += 1
        previous = row

    if sampled_pixels == 0:
        raise AssertionError(f"{display_path(path)} visual sample is empty")
    return {
        "luminance_range": float(max_luminance - min_luminance),
        "color_bins": float(len(color_bins)),
        "opaque_fraction": opaque_pixels / sampled_pixels,
        "sampled_pixels": float(sampled_pixels),
    }


def require_screenshot_visual_sanity(path: Path) -> dict[str, float]:
    metrics = png_visual_metrics(path)
    if metrics["luminance_range"] < SCREENSHOT_VISUAL_MIN_LUMINANCE_RANGE:
        raise AssertionError(
            f"{display_path(path)} appears too visually flat: "
            f"luminance_range={metrics['luminance_range']:.0f}"
        )
    if metrics["color_bins"] < SCREENSHOT_VISUAL_MIN_COLOR_BINS:
        raise AssertionError(
            f"{display_path(path)} has too little color variation: "
            f"color_bins={metrics['color_bins']:.0f}"
        )
    if metrics["opaque_fraction"] < SCREENSHOT_VISUAL_MIN_OPAQUE_FRACTION:
        raise AssertionError(
            f"{display_path(path)} must be effectively opaque: "
            f"opaque_fraction={metrics['opaque_fraction']:.3f}"
        )
    return metrics


def validate_screenshots() -> list[str]:
    messages: list[str] = []
    for path, allowed_sizes in SCREENSHOT_SPECS.items():
        if not path.exists():
            platform = path.parent.name
            messages.append(
                f"SKIP: {platform} candidate screenshot not present yet"
            )
            continue
        width, height = png_dimensions(path)
        if (width, height) not in allowed_sizes:
            allowed = ", ".join(f"{w}x{h}" for w, h in sorted(allowed_sizes))
            raise AssertionError(
                f"{display_path(path)} is {width}x{height}, expected one of {allowed}"
            )
        metrics = require_screenshot_visual_sanity(path)
        messages.append(
            f"PASS: {display_path(path)} dimensions {width}x{height}"
        )
        messages.append(
            f"PASS: {display_path(path)} visual sanity "
            f"luminance_range={metrics['luminance_range']:.0f} "
            f"color_bins={metrics['color_bins']:.0f} "
            f"opaque_fraction={metrics['opaque_fraction']:.3f}"
        )
    return messages


def validate_secret_hygiene() -> list[str]:
    forbidden = [
        "BEGIN PRIVATE KEY",
        "AuthKey_",
        "WINS_APPLE_AUTHENTICATION_KEY_ID=",
        "WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID=",
        "client_private_key",
        "Password:",
        "ssh root@",
    ]
    for path in sorted(PACKAGE.rglob("*")):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(PACKAGE).parts
        if any(part.startswith("v3_submission_") for part in relative_parts):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for marker in forbidden:
            if marker in text:
                raise AssertionError(
                    f"secret-like marker {marker!r} found in {path.relative_to(ROOT)}"
                )
    return ["PASS: no forbidden secret-like markers in Apple submission package"]


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    messages: list[str] = []
    try:
        if len(argv) == 3 and argv[0] == "--verify":
            messages.extend(validate_cross_store_artifact(argv[1], argv[2]))
        elif argv == ["--selftest"]:
            messages.extend(run_selftest())
        elif argv == ["--release-ready"]:
            messages.extend(validate_metadata_lengths())
            messages.extend(validate_frozen_marketing_copy())
            messages.extend(validate_urls())
            messages.extend(validate_live_urls())
            messages.extend(validate_keywords())
            messages.extend(validate_review_files())
            messages.extend(validate_owner_signoff(ROOT, require_approved=True))
            messages.extend(validate_content_markers())
            messages.extend(validate_owner_review_packet_cross_references())
            messages.extend(validate_artifact_manifest())
            messages.extend(validate_runtime_evidence_manifest())
            messages.extend(validate_privacy_label_manifest(release_ready=True))
            try:
                messages.extend(listing.review_messages(release_ready=True))
            except listing.AppleListingGateError as exc:
                raise AssertionError(str(exc)) from exc
            messages.extend(validate_rollout_readiness_manifest())
            messages.extend(validate_screenshots())
            messages.extend(validate_secret_hygiene())
        elif argv:
            raise AssertionError(f"unknown argument(s): {' '.join(argv)}")
        else:
            messages.extend(validate_metadata_lengths())
            messages.extend(validate_frozen_marketing_copy())
            messages.extend(validate_urls())
            messages.extend(validate_live_urls())
            messages.extend(validate_keywords())
            messages.extend(validate_review_files())
            messages.extend(validate_owner_signoff(ROOT, require_approved=False))
            messages.extend(validate_content_markers())
            messages.extend(validate_owner_review_packet_cross_references())
            messages.extend(validate_artifact_manifest())
            messages.extend(validate_runtime_evidence_manifest())
            messages.extend(validate_privacy_label_manifest())
            try:
                messages.extend(listing.review_messages(release_ready=False))
            except listing.AppleListingGateError as exc:
                raise AssertionError(str(exc)) from exc
            messages.extend(validate_rollout_readiness_manifest())
            messages.extend(validate_screenshots())
            messages.extend(validate_secret_hygiene())
    except AssertionError as exc:
        print(f"FAIL: {exc}")
        return 1

    for message in messages:
        print(message)
    print(f"SUMMARY: {len(messages)}/{len(messages)} checks passing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
