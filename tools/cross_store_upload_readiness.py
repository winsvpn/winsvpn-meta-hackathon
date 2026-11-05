#!/usr/bin/env python3
"""Create fail-closed, local-only cross-store upload-readiness evidence.

The required upload target matrix is explicit and immutable. A target is
locally ready only when its own receipt, artifact, source freeze, producer, and
two executed gate records all verify. Store approvals remain separate and this
tool never uploads or authorizes publication.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import functools
import gc
import hashlib
import importlib.util
import io
import json
import math
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import zipfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from types import CodeType, FunctionType, MappingProxyType, ModuleType

import cross_store_gate_runner as gate_runner
import gcp_proof_fleet as gcp_proof
import release_dependency_freeze as freeze


CONTRACT = "winsvpn-cross-store-upload-readiness-v4"
TARGET_RECEIPT_CONTRACT = "winsvpn-upload-target-receipt-v2"
LOCAL_GATE_EVIDENCE_CONTRACT = "winsvpn-executed-local-gate-v4"
SCHEMA_VERSION = 4
TARGET_RECEIPT_SCHEMA_VERSION = 2
LOCAL_GATE_EVIDENCE_SCHEMA_VERSION = 4
READINESS_STATUS_BLOCKED = "BLOCKED"
READINESS_STATUS_LOCAL_READY = "LOCAL_READY"
LOCAL_GATE_COMMAND_COUNT = 2
LOCAL_GATE_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "transaction_id",
        "target_id",
        "gate_id",
        "command_order",
        "command_count",
        "previous_evidence_sha256",
        "command",
        "producer",
        "runner",
        "started_utc",
        "ended_utc",
        "exit_code",
        "status",
        "stdout",
        "stderr",
        "stdout_sha256",
        "stderr_sha256",
        "artifact_before",
        "artifact_after",
        "artifact_custody",
        "publication_authorized",
        "upload_attempted",
    }
)
ARTIFACT_CUSTODY_EVIDENCE_KEYS = frozenset(
    {
        "strategy",
        "source_path",
        "execution_path",
        "ancestor_closure_sha256",
        "retained_object_count",
        "retained_objects",
        "source_identity",
        "snapshot_identity",
        "source_sha256",
        "snapshot_sha256",
        "bytes",
        "verification_generation",
        "kernel_mutation_events_observed",
        "windows_delete_write_sharing_denied",
    }
)
ARTIFACT_CUSTODY_STRATEGIES = frozenset(
    {
        "posix-retained-descriptors-kqueue-v1",
        "posix-retained-descriptors-inotify-v1",
        "windows-retained-deny-write-delete-handles-v1",
    }
)
MAX_RECEIPT_AGE = dt.timedelta(hours=72)
MAX_CLOCK_SKEW = dt.timedelta(minutes=5)
CHECKLIST = "docs/CROSS_STORE_RELEASE_CHECKLIST.md"
PLAY_DECLARATIONS = "docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md"
OWNER_SIGNOFF = "app_store/apple/review/owner_signoff.json"
APPLE_RELEASE_CANDIDATE = "app_store/apple/artifacts/release_candidate.json"
APPLE_RUNTIME_EVIDENCE = "app_store/apple/artifacts/runtime_evidence.json"
APPLE_PRIVACY_SNAPSHOT = "app_store/apple/review/privacy_label_manifest.json"
OWNER_SIGNOFF_DOCUMENT_SCHEMA_VERSION = 1
OWNER_AUTHORIZATION_SCHEMA_VERSION = 2
OWNER_AUTHORIZATION_KEYS = frozenset(
    {
        "contract",
        "status",
        "credentials_authorized",
        "upload_authorized",
        "approved_evidence_set_sha256",
        "evidence",
    }
)
OWNER_PLACEHOLDER_SIGNERS = frozenset(
    {
        "",
        "owner",
        "tbd",
        "pending",
        "placeholder",
        "team",
        "candidate",
        "ci",
        "bot",
        "producer",
    }
)
OWNER_DRAFT_SCOPE = ("ios", "macos")
OWNER_FINAL_SCOPE = ("ios", "macos", "watchos")
OWNER_APPROVED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
CANDIDATE_MINTED_AUTHORIZATION_KEYS = frozenset(
    {
        "owner_authorization",
        "authorization_schema_version",
        "submission_approved",
        "approved_by",
        "approved_at_utc",
        "approved_evidence_set_sha256",
    }
)
OWNER_BOUND_HASH_FIELDS = (
    "release_input_index_sha256",
    "ios_artifact_sha256",
    "watch_executable_sha256",
    "watch_privacy_info_sha256",
    "macos_artifact_sha256",
    "runtime_evidence_sha256",
    "watch_companion_smoke_sha256",
    "archive_privacy_inventory_sha256",
    "app_store_privacy_snapshot_sha256",
)
QUERY_STATUS_RE = re.compile(r"Approval status:\s*`([A-Z]+)(?: \([^)]+\))?`")


@dataclasses.dataclass(frozen=True)
class UploadTarget:
    target_id: str
    platform: str
    store_surface: str
    build_receipt_target: str
    artifact_suffixes: tuple[str, ...]
    producer_ids: tuple[str, ...]
    signing_gate_id: str
    hardening_gate_id: str
    manifest_verifier_path: str | None = None


@dataclasses.dataclass(frozen=True)
class PlatformOwnerEvidence:
    blocker_id: str
    path: str
    contract: str
    target_ids: tuple[str, ...]
    label: str


# Phone and tablet are one Play upload target because they use one AAB. The
# matrix includes distinct native Windows x64 and ARM64 artifacts. ARM64 must
# be produced on a Windows ARM64 host; x64 emulation never satisfies it.
REQUIRED_UPLOAD_TARGETS = (
    UploadTarget(
        "android-phone-tablet-aab",
        "android",
        "google-play-phone-tablet",
        "android-release-aab",
        (".aab",),
        ("tools/build_android_release.ps1",),
        "android-upload-certificate",
        "android-obfuscation-privacy",
    ),
    UploadTarget(
        "android-tv-aab",
        "android",
        "google-play-tv",
        "android-tv-release-aab",
        (".aab",),
        ("tools/build_android_release.ps1",),
        "android-upload-certificate",
        "android-obfuscation-privacy",
    ),
    UploadTarget(
        "wear-os-aab",
        "wear_os",
        "google-play-wear-os",
        "wear-os-release-aab",
        (".aab",),
        ("wear_os/tools/signed_aab_receipt.py",),
        "android-upload-certificate",
        "wear-r8-privacy",
    ),
    UploadTarget(
        "ios-app-store-ipa",
        "ios",
        "apple-app-store-iphone-watch",
        "app-store-connect",
        (".ipa",),
        ("tools/apple_runtime_smoke.sh",),
        "apple-distribution-signature",
        "apple-obfuscation-privacy",
    ),
    UploadTarget(
        "macos-app-store-pkg",
        "macos",
        "mac-app-store",
        "app-store-connect",
        (".pkg",),
        ("tools/apple_runtime_smoke.sh",),
        "apple-installer-signature",
        "apple-obfuscation-privacy",
    ),
    UploadTarget(
        "windows-x64-installer",
        "windows",
        "website-windows-x64",
        "windows-x64-inno-signed",
        (".exe",),
        ("installer/windows/build_installer.ps1",),
        "windows-x64-authenticode",
        "windows-obfuscation-privacy",
    ),
    UploadTarget(
        "windows-x64-partner-center",
        "windows",
        "partner-center-windows-x64",
        "windows-x64-inno-signed",
        (".exe",),
        ("installer/windows/build_installer.ps1",),
        "windows-x64-store-signature",
        "windows-obfuscation-privacy",
    ),
    UploadTarget(
        "windows-arm64-installer",
        "windows",
        "website-windows-arm64",
        "windows-arm64-inno-signed",
        (".exe",),
        ("installer/windows/build_installer.ps1",),
        "windows-arm64-authenticode",
        "windows-obfuscation-privacy",
    ),
    UploadTarget(
        "windows-arm64-partner-center",
        "windows",
        "partner-center-windows-arm64",
        "windows-arm64-inno-signed",
        (".exe",),
        ("installer/windows/build_installer.ps1",),
        "windows-arm64-store-signature",
        "windows-obfuscation-privacy",
    ),
    UploadTarget(
        "linux-x64-package",
        "linux",
        "website-tarball-x64",
        "linux-x64",
        (".tar.gz",),
        ("tools/build_linux_release.sh",),
        "linux-x64-package-verification",
        "linux-obfuscation-privacy",
    ),
    UploadTarget(
        "linux-arm64-package",
        "linux",
        "website-tarball-arm64",
        "linux-arm64",
        (".tar.gz",),
        ("tools/build_linux_release.sh",),
        "linux-arm64-package-verification",
        "linux-obfuscation-privacy",
    ),
    UploadTarget(
        "linux-flathub-manifest",
        "linux",
        "flathub-separate-manifest",
        "linux-flathub-manifest",
        (".json",),
        ("linux/packaging/flathub/manifest_artifact.py",),
        "linux-flathub-manifest-verification",
        "linux-obfuscation-privacy",
        "linux/packaging/flathub/manifest_artifact.py",
    ),
    UploadTarget(
        "linux-snap-manifest",
        "linux",
        "snap-separate-manifest",
        "linux-snap-manifest",
        (".yaml", ".yml"),
        ("linux/packaging/snap/manifest_artifact.py",),
        "linux-snap-manifest-verification",
        "linux-obfuscation-privacy",
        "linux/packaging/snap/manifest_artifact.py",
    ),
    UploadTarget(
        "chrome-extension-package",
        "extension",
        "chrome-web-store",
        "chrome-zip",
        (".zip",),
        ("extension/build.py",),
        "chrome-package-verification",
        "extension-minification-privacy",
    ),
    UploadTarget(
        "edge-extension-package",
        "extension",
        "edge-add-ons",
        "edge-zip",
        (".zip",),
        ("extension/build.py",),
        "edge-package-verification",
        "extension-minification-privacy",
    ),
    UploadTarget(
        "firefox-extension-package",
        "extension",
        "firefox-amo",
        "firefox-zip",
        (".xpi", ".zip"),
        ("extension/build.py",),
        "firefox-package-verification",
        "extension-minification-privacy",
    ),
)

# Developer ID distribution is a separate, optional macOS channel. Its local
# artifact receipt can be produced and verified, but it is intentionally not
# part of the required App Store denominator or aggregate readiness evidence.
OPTIONAL_UPLOAD_TARGETS = (
    UploadTarget(
        "macos-developer-id-app",
        "macos",
        "developer-id",
        "developer-id",
        (".app.zip", ".pkg"),
        ("tools/apple_runtime_smoke.sh",),
        "apple-developer-id-notarization",
        "apple-obfuscation-privacy",
    ),
)
ALL_UPLOAD_TARGETS = REQUIRED_UPLOAD_TARGETS + OPTIONAL_UPLOAD_TARGETS

# Flutter 3.47.6 supports a native windows-arm64 target when invoked on a
# Windows ARM64 host. Stable still has no supported x64-host cross-target flag,
# so the producer and receipts fail closed on host/target mismatch.
PLANNED_UNSUPPORTED_TARGETS: dict[str, str] = {}
REQUIRED_TARGET_IDS = frozenset(target.target_id for target in REQUIRED_UPLOAD_TARGETS)
OPTIONAL_TARGET_IDS = frozenset(target.target_id for target in OPTIONAL_UPLOAD_TARGETS)
KNOWN_TARGET_IDS = REQUIRED_TARGET_IDS | OPTIONAL_TARGET_IDS
TARGET_BY_ID = {target.target_id: target for target in ALL_UPLOAD_TARGETS}
APPLE_REQUIRED_UPLOAD_TARGET_IDS = tuple(
    target.target_id
    for target in REQUIRED_UPLOAD_TARGETS
    if target.platform in {"ios", "macos"}
)
ANDROID_PHONE_UPLOAD_TARGET_IDS = ("android-phone-tablet-aab",)
ANDROID_TV_UPLOAD_TARGET_IDS = ("android-tv-aab",)
WEAR_OS_UPLOAD_TARGET_IDS = ("wear-os-aab",)
WINDOWS_UPLOAD_TARGET_IDS = (
    "windows-x64-installer",
    "windows-x64-partner-center",
    "windows-arm64-installer",
    "windows-arm64-partner-center",
)
LINUX_UPLOAD_TARGET_IDS = (
    "linux-x64-package",
    "linux-arm64-package",
    "linux-flathub-manifest",
    "linux-snap-manifest",
)
EXTENSION_UPLOAD_TARGET_IDS = (
    "chrome-extension-package",
    "edge-extension-package",
    "firefox-extension-package",
)
PLAY_QUERY_UPLOAD_TARGET_IDS = ANDROID_PHONE_UPLOAD_TARGET_IDS + ANDROID_TV_UPLOAD_TARGET_IDS
PLATFORM_OWNER_EVIDENCE = (
    PlatformOwnerEvidence(
        "android-phone-owner-signoff",
        "app_store/android/phone/review/owner_signoff.json",
        "winsvpn-android-phone-owner-signoff-v1",
        ANDROID_PHONE_UPLOAD_TARGET_IDS,
        "Android phone/tablet owner signoff",
    ),
    PlatformOwnerEvidence(
        "android-tv-owner-signoff",
        "app_store/android/tv/review/owner_signoff.json",
        "winsvpn-android-tv-owner-signoff-v1",
        ANDROID_TV_UPLOAD_TARGET_IDS,
        "Android TV owner signoff",
    ),
    PlatformOwnerEvidence(
        "wear-os-owner-signoff",
        "app_store/android/wear/review/owner_signoff.json",
        "winsvpn-wear-os-owner-signoff-v1",
        WEAR_OS_UPLOAD_TARGET_IDS,
        "Wear OS owner signoff",
    ),
    PlatformOwnerEvidence(
        "windows-owner-signoff",
        "app_store/windows/review/owner_signoff.json",
        "winsvpn-windows-owner-signoff-v1",
        WINDOWS_UPLOAD_TARGET_IDS,
        "Windows owner signoff",
    ),
    PlatformOwnerEvidence(
        "linux-owner-signoff",
        "app_store/linux/review/owner_signoff.json",
        "winsvpn-linux-owner-signoff-v1",
        LINUX_UPLOAD_TARGET_IDS,
        "Linux owner signoff",
    ),
    PlatformOwnerEvidence(
        "extension-owner-signoff",
        "extension/store_listings/owner_signoff.json",
        "winsvpn-browser-extension-owner-signoff-v1",
        EXTENSION_UPLOAD_TARGET_IDS,
        "Browser extension owner signoff",
    ),
)
GATE_PRODUCER_IDS = MappingProxyType(
    {
        "android-upload-certificate": ("tools/verify_android_aab_signers.py",),
        "android-obfuscation-privacy": ("tools/release_obfuscation_contract.py",),
        "wear-r8-privacy": ("wear_os/tools/signed_aab_receipt.py",),
        "apple-distribution-signature": (
            "tools/validate_apple_submission_package.py",
            "tools/apple_cross_store_artifact_gate.py",
        ),
        "apple-installer-signature": (
            "tools/validate_apple_submission_package.py",
            "tools/apple_cross_store_artifact_gate.py",
        ),
        "apple-developer-id-notarization": (
            "tools/apple_runtime_smoke.sh",
            "tools/apple_cross_store_artifact_gate.py",
        ),
        "apple-obfuscation-privacy": ("tools/release_obfuscation_contract.py",),
        "windows-x64-authenticode": ("tools/windows_cross_store_artifact_gate.py",),
        "windows-x64-store-signature": ("tools/windows_cross_store_artifact_gate.py",),
        "windows-arm64-authenticode": ("tools/windows_cross_store_artifact_gate.py",),
        "windows-arm64-store-signature": ("tools/windows_cross_store_artifact_gate.py",),
        "windows-obfuscation-privacy": ("tools/release_obfuscation_contract.py",),
        "linux-x64-package-verification": (
            "tools/linux_cross_store_artifact_gate.py",
        ),
        "linux-arm64-package-verification": (
            "tools/linux_cross_store_artifact_gate.py",
        ),
        "linux-flathub-manifest-verification": (
            "tools/linux_cross_store_artifact_gate.py",
        ),
        "linux-snap-manifest-verification": (
            "tools/linux_cross_store_artifact_gate.py",
        ),
        "linux-obfuscation-privacy": ("tools/release_obfuscation_contract.py",),
        "chrome-package-verification": ("extension/tools/assert_chrome_zip.py",),
        "edge-package-verification": ("extension/tools/assert_chrome_zip.py",),
        "firefox-package-verification": ("extension/tools/assert_firefox_zip.py",),
        "extension-minification-privacy": (
            "tools/validate_release_artifact_privacy.py",
            "tools/release_obfuscation_contract.py",
        ),
    }
)
EXTENSION_HARDENING_PRODUCER_IDS = GATE_PRODUCER_IDS["extension-minification-privacy"]
DEFAULT_GATE_RUNNER_FACTORY = gate_runner.SubprocessExplicitArgvRunner
PRODUCTION_GATE_CONTROLLER = "tools/cross_store_gate_runner.py"
TEST_ONLY_GATE_RUNNER_ID = "winsvpn-test-only-explicit-argv"
_SEALED_GATE_RUNNER_MODULE_PREFIX = "winsvpn_prod_gate_runner_"
_PRODUCTION_RUNNER_CLASS_NAME = "SubprocessExplicitArgvRunner"
_LIVE_EXTENSION_HARDENING_MODULES: dict[str, object] = {}
EXTENSION_TARGET_IDS = frozenset(
    {
        "chrome-extension-package",
        "edge-extension-package",
        "firefox-extension-package",
    }
)
EXTENSION_BROWSER_BY_TARGET_ID = {
    "chrome-extension-package": "chrome",
    "edge-extension-package": "edge",
    "firefox-extension-package": "firefox",
}
RELEASE_IDENTITY_RELATIVE = "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
LINUX_ARTIFACT_GATE_RELATIVE = "tools/linux_cross_store_artifact_gate.py"
APPLE_ARTIFACT_GATE_RELATIVE = "tools/apple_cross_store_artifact_gate.py"
WINDOWS_ARTIFACT_GATE_RELATIVE = "tools/windows_cross_store_artifact_gate.py"
OWNER_BLOCKED_ABSENT = "OWNER-BLOCKED: ABSENT"
RELEASE_IDENTITY_KEYS = frozenset(
    {
        "schema_version",
        "canonical_release",
        "marketing_version",
        "build_number",
        "platform_mappings",
    }
)
PLATFORM_OWNER_IDENTITY_FIELDS = MappingProxyType(
    {
        "android-phone-owner-signoff": (
            ("application_id", "android_phone", "package", str),
            ("version_name", "android_phone", "version_name", str),
            ("version_code", "android_phone", "version_code", int),
        ),
        "android-tv-owner-signoff": (
            ("application_id", "android_tv", "package", str),
            ("version_name", "android_tv", "version_name", str),
            ("version_code", "android_tv", "version_code", int),
        ),
        "wear-os-owner-signoff": (
            ("application_id", "wear_os", "package", str),
            ("version_name", "wear_os", "version_name", str),
            ("version_code", "wear_os", "version_code", int),
        ),
        "windows-owner-signoff": (
            ("product_version", "windows", "product_version", str),
            ("four_part_version", "windows", "four_part_version", str),
        ),
        "linux-owner-signoff": (
            ("appstream_version", "linux", "appstream_version", str),
            ("debian_version", "linux", "debian_version", str),
        ),
        "extension-owner-signoff": (
            ("package_version", "browser_extensions", "version", str),
        ),
    }
)
EXTENSION_VERIFIER_SOURCE_PATHS = (
    RELEASE_IDENTITY_RELATIVE,
    "extension/build.py",
    "extension/tools/checks.py",
    "extension/tools/jsonc.py",
    "extension/tools/leakscan.py",
    "extension/tools/store_js_minifier.py",
    "extension/tools/store_version.py",
    "pubspec.yaml",
    "tools/native_messaging/manifests/org.winsvpn.bridge.chrome.json",
    "tools/native_messaging/manifests/org.winsvpn.bridge.edge.json",
    "tools/native_messaging/manifests/org.winsvpn.bridge.firefox.json",
)
EXTENSION_AUTHORED_SOURCE_RELATIVE = "extension/src"
EXTENSION_MANIFEST_RELATIVE = "extension/manifest"
_EXTENSION_RUNTIME_PYTHON_SOURCES: tuple[tuple[str, str], ...] = (
    ("store_version", "extension/tools/store_version.py"),
    ("jsonc", "extension/tools/jsonc.py"),
    ("checks", "extension/tools/checks.py"),
    ("leakscan", "extension/tools/leakscan.py"),
    ("store_js_minifier", "extension/tools/store_js_minifier.py"),
    ("builder", "extension/build.py"),
)
_EXTENSION_PUBLIC_HELPER_NAMES: tuple[str, ...] = (
    "store_version",
    "jsonc",
    "checks",
    "leakscan",
    "store_js_minifier",
)
_GATE_ARTIFACT_ARG_OFFSET = 3
_MISSING_SYS_MODULE = object()
TARGET_RECEIPT_BASE_KEYS = frozenset(
    {
        "ok",
        "schema_version",
        "contract",
        "release",
        "target_id",
        "platform",
        "verified_utc",
        "build_receipt",
        "artifact",
        "producer",
        "signing_verification_gate",
        "obfuscation_privacy_gate",
        "dependency_source_freeze",
        "publication_authorized",
        "upload_attempted",
    }
)
EXTENSION_TARGET_RECEIPT_KEYS = TARGET_RECEIPT_BASE_KEYS | {"verifier_source_closure"}
EXTENSION_VERIFIER_CLOSURE_KEYS = frozenset({"inputs", "sha256"})
EXTENSION_VERIFIER_INPUT_KEYS = frozenset({"path", "sha256", "bytes"})


class UploadReadinessError(RuntimeError):
    """Raised when cross-store upload-readiness evidence is not exact."""


def _assert_target_contract() -> None:
    required_ids = [target.target_id for target in REQUIRED_UPLOAD_TARGETS]
    optional_ids = [target.target_id for target in OPTIONAL_UPLOAD_TARGETS]
    all_ids = required_ids + optional_ids
    if (
        len(required_ids) != len(set(required_ids))
        or set(required_ids) != REQUIRED_TARGET_IDS
    ):
        raise UploadReadinessError(
            "Required upload target ids are not unique and exact."
        )
    if (
        len(optional_ids) != len(set(optional_ids))
        or set(optional_ids) != OPTIONAL_TARGET_IDS
        or REQUIRED_TARGET_IDS & OPTIONAL_TARGET_IDS
        or len(all_ids) != len(set(all_ids))
        or set(TARGET_BY_ID) != KNOWN_TARGET_IDS
    ):
        raise UploadReadinessError(
            "Optional upload target ids are not unique, exact, and disjoint."
        )
    for target in ALL_UPLOAD_TARGETS:
        if target.platform not in freeze.CANONICAL_FREEZE_PLATFORMS:
            raise UploadReadinessError(
                f"Unsupported target platform: {target.platform}"
            )
        if not target.producer_ids or not target.artifact_suffixes:
            raise UploadReadinessError(
                f"{target.target_id} target contract is incomplete."
            )
        if (
            target.signing_gate_id not in GATE_PRODUCER_IDS
            or target.hardening_gate_id not in GATE_PRODUCER_IDS
        ):
            raise UploadReadinessError(
                f"{target.target_id} gate producer contract is incomplete."
            )
    if set(EXTENSION_TARGET_IDS) != {
        target.target_id
        for target in ALL_UPLOAD_TARGETS
        if target.platform == "extension"
    }:
        raise UploadReadinessError("Extension upload target set is not exact.")
    for target_id, browser in EXTENSION_BROWSER_BY_TARGET_ID.items():
        target = TARGET_BY_ID[target_id]
        if (
            target.platform != "extension"
            or target.producer_ids != ("extension/build.py",)
            or browser not in {"chrome", "edge", "firefox"}
        ):
            raise UploadReadinessError(
                f"{target_id} extension producer contract is incomplete."
            )
        if (
            target.hardening_gate_id != "extension-minification-privacy"
            or GATE_PRODUCER_IDS[target.hardening_gate_id]
            != EXTENSION_HARDENING_PRODUCER_IDS
            or EXTENSION_HARDENING_PRODUCER_IDS
            != (
                "tools/validate_release_artifact_privacy.py",
                "tools/release_obfuscation_contract.py",
            )
        ):
            raise UploadReadinessError(
                f"{target_id} hardening must invoke generic privacy and exact "
                "extension minification/obfuscation verification."
            )
    store_surfaces = [target.store_surface for target in ALL_UPLOAD_TARGETS]
    if len(store_surfaces) != len(set(store_surfaces)):
        raise UploadReadinessError("Upload target store surfaces are not unique.")
    if set(EXTENSION_UPLOAD_TARGET_IDS) != set(EXTENSION_TARGET_IDS):
        raise UploadReadinessError("Extension owner-evidence target set is not exact.")
    linux_gate = (LINUX_ARTIFACT_GATE_RELATIVE,)
    windows_gate = (WINDOWS_ARTIFACT_GATE_RELATIVE,)
    for target_id in LINUX_UPLOAD_TARGET_IDS:
        target = TARGET_BY_ID[target_id]
        if GATE_PRODUCER_IDS[target.signing_gate_id] != linux_gate:
            raise UploadReadinessError(
                f"{target_id} signing must invoke the current Linux artifact gate."
            )
    for target_id in WINDOWS_UPLOAD_TARGET_IDS:
        target = TARGET_BY_ID[target_id]
        if GATE_PRODUCER_IDS[target.signing_gate_id] != windows_gate:
            raise UploadReadinessError(
                f"{target_id} signing must invoke the current Windows artifact gate."
            )
    for target_id in APPLE_REQUIRED_UPLOAD_TARGET_IDS + ("macos-developer-id-app",):
        target = TARGET_BY_ID[target_id]
        if APPLE_ARTIFACT_GATE_RELATIVE not in GATE_PRODUCER_IDS[target.signing_gate_id]:
            raise UploadReadinessError(
                f"{target_id} signing must bind the current Apple artifact gate."
            )
    if set(PLATFORM_OWNER_IDENTITY_FIELDS) != {
        spec.blocker_id for spec in PLATFORM_OWNER_EVIDENCE
    }:
        raise UploadReadinessError(
            "Platform owner identity/version field table is not exact."
        )
    covered: set[str] = set(APPLE_REQUIRED_UPLOAD_TARGET_IDS)
    owner_ids: list[str] = []
    for spec in PLATFORM_OWNER_EVIDENCE:
        owner_ids.append(spec.blocker_id)
        if not spec.target_ids or set(spec.target_ids) - REQUIRED_TARGET_IDS:
            raise UploadReadinessError(
                f"{spec.blocker_id} owner evidence target set is not exact."
            )
        overlap = covered.intersection(spec.target_ids)
        if overlap:
            raise UploadReadinessError(
                f"{spec.blocker_id} owner evidence overlaps another target: "
                + ", ".join(sorted(overlap))
            )
        covered.update(spec.target_ids)
    if (
        len(owner_ids) != len(set(owner_ids))
        or covered != REQUIRED_TARGET_IDS
        or set(APPLE_REQUIRED_UPLOAD_TARGET_IDS)
        != {"ios-app-store-ipa", "macos-app-store-pkg"}
        or set(PLAY_QUERY_UPLOAD_TARGET_IDS)
        != {"android-phone-tablet-aab", "android-tv-aab"}
    ):
        raise UploadReadinessError(
            "Sixteen-target owner evidence coverage is not exact and disjoint."
        )


def _repo_path(repo: pathlib.Path, relative: str, label: str) -> pathlib.Path:
    return freeze.secure_repo_path(repo, pathlib.Path(relative), label, must_exist=True)


def _query_all_packages_status(repo: pathlib.Path) -> str:
    text = _repo_path(repo, PLAY_DECLARATIONS, "Play declarations").read_text(
        encoding="utf-8"
    )
    matches = QUERY_STATUS_RE.findall(text)
    if len(matches) != 1:
        raise UploadReadinessError(
            "Google Play QUERY_ALL_PACKAGES approval status must appear exactly once."
        )
    return matches[0]


def _owner_v2_error(kind: str, detail: str) -> UploadReadinessError:
    return UploadReadinessError(
        f"Apple owner authorization schema v2 is {kind}: {detail}"
    )


def _owner_collector_call(collector_error: type[BaseException], fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except collector_error as exc:
        text = str(exc)
        lowered = text.lower()
        if "stale" in lowered:
            kind = "stale"
        elif any(
            token in lowered
            for token in ("missing", "omitted", "incomplete", "empty")
        ):
            kind = "partial"
        else:
            kind = "invalid"
        raise _owner_v2_error(kind, text) from exc


def _owner_release_identity(repo: pathlib.Path) -> tuple[str, str, str]:
    try:
        release = freeze._release_identity(repo)
    except freeze.DependencyFreezeError as exc:
        raise UploadReadinessError(str(exc)) from exc
    if "+" not in release:
        raise UploadReadinessError("Release identity is not version+build.")
    app_version, build_number = release.split("+", 1)
    return release, app_version, build_number


def _owner_repo_file(repo: pathlib.Path, relative: str, label: str) -> pathlib.Path:
    try:
        return _repo_path(repo, relative, label)
    except freeze.DependencyFreezeError as exc:
        raise _owner_v2_error("partial", str(exc)) from exc


def _owner_file_sha256(path: pathlib.Path, label: str) -> str:
    return _stable_identity(path, label)[2]


def _owner_require_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise _owner_v2_error("invalid", f"{label} must be a JSON boolean.")
    return value


def _owner_require_str(value: object, label: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise _owner_v2_error("invalid", f"{label} must be a JSON string.")
    if not allow_empty and not value.strip():
        raise _owner_v2_error("partial", f"{label} must not be empty.")
    return value


def _owner_approved_scope(record: Mapping[str, object]) -> tuple[str, ...]:
    scope = record.get("approved_scope")
    if type(scope) is not list or any(type(item) is not str for item in scope):
        raise _owner_v2_error("invalid", "approved_scope must be an array of strings.")
    return tuple(scope)


def _apple_targets_covered_by_surfaces(surfaces: Sequence[object]) -> tuple[str, ...]:
    names = [str(item) for item in surfaces]
    covered: list[str] = []
    if "ios" in names and "embedded_watchos_companion" in names:
        covered.append("ios-app-store-ipa")
    if "macos" in names:
        covered.append("macos-app-store-pkg")
    return tuple(covered)


def _apple_candidate_artifacts(
    candidate: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    artifacts = candidate.get("artifacts")
    if type(artifacts) is not list or len(artifacts) != 2:
        raise _owner_v2_error(
            "partial",
            "candidate manifest must list exactly the iOS and macOS artifacts.",
        )
    mapping: dict[str, dict[str, object]] = {}
    for artifact in artifacts:
        if type(artifact) is not dict:
            raise _owner_v2_error("invalid", "candidate artifacts must be objects.")
        platform = artifact.get("platform")
        if platform not in {"ios", "macos"} or platform in mapping:
            raise _owner_v2_error(
                "mixed",
                "candidate manifest has an unexpected or duplicate platform.",
            )
        mapping[str(platform)] = artifact
    if set(mapping) != {"ios", "macos"}:
        raise _owner_v2_error("partial", "candidate manifest must cover iOS and macOS.")
    return mapping


def _assert_unbound_apple_candidate(
    collector: object,
    artifacts: Mapping[str, Mapping[str, object]],
) -> None:
    for platform in ("ios", "macos"):
        artifact = artifacts[platform]
        if artifact.get("artifact_status") != collector.NO_CURRENT_CANDIDATE:
            raise _owner_v2_error(
                "mixed",
                f"{platform} artifact_status is not {collector.NO_CURRENT_CANDIDATE}.",
            )
        if artifact.get("sha256") not in {"", None} or artifact.get("size_bytes") not in {
            0,
            None,
        }:
            raise _owner_v2_error(
                "mixed",
                f"{platform} candidate still binds artifact bytes without a current set.",
            )
        _owner_collector_call(
            collector.CollectorError,
            collector.reject_mutable_tmp_authority,
            artifact.get("path"),
            f"{platform} path",
        )
        _owner_collector_call(
            collector.CollectorError,
            collector.reject_stale_build_29_digest,
            artifact.get("sha256"),
            f"{platform} sha256",
        )
    watch = artifacts["ios"].get("embedded_watchos_companion")
    if type(watch) is not dict:
        raise _owner_v2_error(
            "partial", "iOS artifact omitted the embedded watchOS companion identity."
        )
    if watch.get("status") != collector.NO_CURRENT_CANDIDATE:
        raise _owner_v2_error(
            "mixed", "embedded watchOS companion is not unbound with the candidate set."
        )
    for field in ("executable_sha256", "privacy_info_sha256"):
        if watch.get(field) not in {"", None}:
            raise _owner_v2_error(
                "mixed", f"pending watch {field} still binds a hash."
            )
    inventory = artifacts["macos"].get("shipped_architecture_inventory")
    _owner_collector_call(
        collector.CollectorError,
        collector.validate_macos_architecture_inventory,
        inventory,
        require_complete=False,
    )


def _complete_owner_evidence_from_candidate(
    collector: object,
    *,
    repo: pathlib.Path,
    candidate: Mapping[str, object],
    artifacts: Mapping[str, Mapping[str, object]],
    runtime: Mapping[str, object],
    runtime_sha256: str,
    privacy_sha256: str,
) -> dict[str, object]:
    ios = artifacts["ios"]
    macos = artifacts["macos"]
    watch = ios.get("embedded_watchos_companion")
    if type(watch) is not dict:
        raise _owner_v2_error(
            "partial", "iOS artifact omitted the embedded watchOS companion identity."
        )
    if (
        ios.get("artifact_status") != "current_candidate"
        or macos.get("artifact_status") != "current_candidate"
        or watch.get("status") != "current_candidate"
    ):
        raise _owner_v2_error(
            "mixed",
            "complete candidate set must mark iOS, watchOS companion, and macOS current.",
        )
    for platform, artifact in (("ios", ios), ("macos", macos)):
        relative = _owner_require_str(artifact.get("path"), f"{platform} candidate path")
        _owner_collector_call(
            collector.CollectorError,
            collector.reject_mutable_tmp_authority,
            relative,
            f"{platform} path",
        )
        if relative.startswith("/") or ".." in pathlib.Path(relative).parts:
            raise _owner_v2_error(
                "invalid", f"{platform} candidate path must be repository-relative."
            )
        _owner_collector_call(
            collector.CollectorError,
            collector.reject_stale_build_29_digest,
            artifact.get("sha256"),
            f"{platform} sha256",
        )
    # R22 Y3 D2: a passed watch smoke names a durable .artifacts receipt that
    # is re-hashed here and whose verdict, release and source commit are
    # re-derived against this candidate set; a pending one binds nothing.
    import apple_watch_companion_smoke as watch_smoke

    watch_smoke_sha = _owner_collector_call(
        watch_smoke.WatchSmokeError,
        watch_smoke.runtime_watch_smoke_sha256,
        repo,
        runtime,
        candidate,
        release=collector.CANONICAL_RELEASE,
    )
    receipts = candidate.get("final_receipt_sha256")
    if type(receipts) is not dict:
        # R24: the freeze records no final_receipt_sha256 map, only the input
        # index and per-artifact build receipt digests; derive the map exactly
        # as validate_apple_owner_signoff.evidence_from_repo does, or no real
        # candidate set could ever match the owner-approved evidence set.
        receipts = {}
        for name in (
            "release_input_index_sha256",
            "build_receipt_sha256",
            "build_receipt_anchor_sha256",
        ):
            value = candidate.get(name) or ios.get(name) or macos.get(name)
            if value:
                receipts[name] = value
    if not receipts:
        raise _owner_v2_error("partial", "complete candidate omitted final receipt hashes.")
    inventory = _owner_collector_call(
        collector.CollectorError,
        collector.validate_macos_architecture_inventory,
        macos.get("shipped_architecture_inventory"),
        require_complete=True,
    )
    if not watch_smoke_sha:
        # R24 F-R24-03: the Watch companion smoke records only on a complete
        # candidate set, so a complete set with a pending smoke is an honest
        # intermediate state: the owner evidence stays the pending set.
        return _owner_collector_call(
            collector.CollectorError,
            collector.pending_owner_evidence_set,
            app_store_privacy_snapshot_sha256=privacy_sha256,
        )
    evidence = {
        "contract": collector.OWNER_AUTHORIZATION_CONTRACT,
        "release": collector.CANONICAL_RELEASE,
        "app_version": collector.CANONICAL_APP_VERSION,
        "build_number": collector.CANONICAL_BUILD_NUMBER,
        "required_surfaces": list(collector.REQUIRED_OWNER_SURFACES),
        "release_input_index_sha256": candidate.get("release_input_index_sha256"),
        "ios_artifact_sha256": ios.get("sha256"),
        "ios_artifact_size_bytes": ios.get("size_bytes"),
        "ios_bundle_id": ios.get("bundle_id"),
        "ios_packet_tunnel_bundle_id": ios.get("packet_tunnel_bundle_id"),
        "watch_bundle_id": watch.get("bundle_id"),
        "watch_companion_bundle_id": watch.get("companion_bundle_id"),
        "watch_version": watch.get("version"),
        "watch_build": watch.get("build"),
        "watch_executable": watch.get("executable"),
        "watch_executable_sha256": watch.get("executable_sha256"),
        "watch_privacy_info_sha256": watch.get("privacy_info_sha256"),
        "macos_artifact_sha256": macos.get("sha256"),
        "macos_artifact_size_bytes": macos.get("size_bytes"),
        "macos_bundle_id": macos.get("bundle_id"),
        "macos_packet_tunnel_bundle_id": macos.get("packet_tunnel_bundle_id"),
        "macos_architecture_inventory": inventory,
        "runtime_evidence_sha256": runtime_sha256,
        "watch_companion_smoke_sha256": watch_smoke_sha,
        "archive_privacy_inventory_sha256": candidate.get(
            "archive_privacy_inventory_sha256"
        ),
        "app_store_privacy_snapshot_sha256": privacy_sha256,
        "final_receipt_sha256": receipts,
    }
    canonical = _owner_collector_call(
        collector.CollectorError, collector.canonical_owner_evidence_set, evidence
    )
    if not _owner_collector_call(
        collector.CollectorError,
        collector.evidence_set_is_complete,
        canonical,
        validate=False,
    ):
        raise _owner_v2_error(
            "partial", "complete candidate did not bind every required evidence hash."
        )
    return canonical


def _owner_evidence_from_repo(
    repo: pathlib.Path, collector: object
) -> dict[str, object]:
    candidate_path = _owner_repo_file(
        repo, APPLE_RELEASE_CANDIDATE, "Apple release candidate"
    )
    runtime_path = _owner_repo_file(
        repo, APPLE_RUNTIME_EVIDENCE, "Apple runtime evidence"
    )
    privacy_path = _owner_repo_file(
        repo, APPLE_PRIVACY_SNAPSHOT, "Apple privacy snapshot"
    )
    candidate = _load_json(candidate_path, "Apple release candidate")
    runtime = _load_json(runtime_path, "Apple runtime evidence")
    privacy_sha256 = _owner_file_sha256(privacy_path, "Apple privacy snapshot")
    runtime_sha256 = _owner_file_sha256(runtime_path, "Apple runtime evidence")
    release, app_version, build_number = _owner_release_identity(repo)
    if (
        candidate.get("app_version") != app_version
        or str(candidate.get("build_number")) != build_number
        or runtime.get("app_version") != app_version
        or str(runtime.get("build_number")) != build_number
    ):
        raise _owner_v2_error(
            "stale",
            "candidate manifest identity does not match the exact release/version/build.",
        )
    if release != collector.CANONICAL_RELEASE:
        raise _owner_v2_error(
            "stale",
            f"owner authorization cannot bind release {release}; "
            f"{collector.CANONICAL_RELEASE} is required.",
        )
    artifacts = _apple_candidate_artifacts(candidate)
    _assert_not_candidate_minted_authorization(candidate)
    status = candidate.get("candidate_set_status")
    if status == collector.NO_CURRENT_CANDIDATE:
        if runtime.get("candidate_set_status") != "pending_current_runtime_evidence":
            raise _owner_v2_error(
                "mixed",
                "runtime evidence is not pending while the candidate set is unbound.",
            )
        _assert_unbound_apple_candidate(collector, artifacts)
        import apple_watch_companion_smoke as watch_smoke

        _owner_collector_call(
            watch_smoke.WatchSmokeError,
            watch_smoke.runtime_watch_smoke_sha256,
            repo,
            runtime,
            candidate,
            release=collector.CANONICAL_RELEASE,
        )
        return _owner_collector_call(
            collector.CollectorError,
            collector.pending_owner_evidence_set,
            app_store_privacy_snapshot_sha256=privacy_sha256,
        )
    if status != collector.COMPLETE_LOCAL_CANDIDATES:
        raise _owner_v2_error(
            "invalid",
            "candidate_set_status must be no_current_candidate or "
            "complete_local_candidates.",
        )
    return _complete_owner_evidence_from_candidate(
        collector,
        repo=repo,
        candidate=candidate,
        artifacts=artifacts,
        runtime=runtime,
        runtime_sha256=runtime_sha256,
        privacy_sha256=privacy_sha256,
    )


def _assert_not_candidate_minted_authorization(
    candidate: Mapping[str, object],
) -> None:
    overlap = CANDIDATE_MINTED_AUTHORIZATION_KEYS.intersection(candidate)
    if overlap:
        raise _owner_v2_error(
            "invalid",
            "candidate-minted authorization is refused; "
            + ", ".join(sorted(overlap))
            + " must not appear on the candidate manifest.",
        )
    artifacts = candidate.get("artifacts")
    if type(artifacts) is not list:
        return
    for artifact in artifacts:
        if type(artifact) is not dict:
            continue
        if CANDIDATE_MINTED_AUTHORIZATION_KEYS.intersection(artifact):
            raise _owner_v2_error(
                "invalid",
                "candidate-minted authorization is refused; artifact records "
                "cannot carry owner authorization fields.",
            )


def _owner_bound_digest_pairs(
    canonical: Mapping[str, object],
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for field in OWNER_BOUND_HASH_FIELDS:
        digest = canonical.get(field)
        if type(digest) is str and digest:
            pairs.append((field, digest))
    receipts = canonical.get("final_receipt_sha256")
    if type(receipts) is dict:
        for name, digest in receipts.items():
            if type(name) is str and type(digest) is str and digest:
                pairs.append((f"final_receipt_sha256.{name}", digest))
    inventory = canonical.get("macos_architecture_inventory")
    if type(inventory) is dict:
        shipped = inventory.get("shipped")
        if type(shipped) is list:
            for item in shipped:
                if type(item) is not dict:
                    continue
                digest = item.get("sha256")
                path = item.get("path")
                if type(digest) is str and digest:
                    pairs.append((f"macos_shipped.{path}", digest))
    return pairs


def _assert_owner_hashes_not_reused(canonical: Mapping[str, object]) -> None:
    seen: dict[str, str] = {}
    for label, digest in _owner_bound_digest_pairs(canonical):
        previous = seen.get(digest)
        if previous is not None:
            raise _owner_v2_error(
                "invalid",
                f"receipt reuse is refused: {label} reuses {previous}.",
            )
        seen[digest] = label


def _assert_owner_approval_identity(
    record: Mapping[str, object],
    *,
    candidate_generated_at: object = None,
) -> None:
    approved_by = _owner_require_str(
        record.get("approved_by"), "owner signoff approved_by"
    )
    lowered = approved_by.strip().lower()
    if lowered in OWNER_PLACEHOLDER_SIGNERS or "candidate" in lowered:
        raise _owner_v2_error(
            "partial", "approved_by must name the signer/team identity."
        )
    approved_at = _owner_require_str(
        record.get("approved_at_utc"), "owner signoff approved_at_utc"
    )
    if OWNER_APPROVED_AT_RE.fullmatch(approved_at) is None:
        raise _owner_v2_error(
            "invalid", "approved_at_utc must be UTC ISO-8601 seconds."
        )
    approved_at_dt = _safe_time(approved_at, "owner signoff approved_at_utc")
    now = dt.datetime.now(tz=dt.timezone.utc)
    if approved_at_dt > now + MAX_CLOCK_SKEW or now - approved_at_dt > MAX_RECEIPT_AGE:
        raise _owner_v2_error(
            "stale",
            "owner authorization timestamp is stale or future-dated.",
        )
    if (
        type(candidate_generated_at) is str
        and candidate_generated_at
        and approved_at == candidate_generated_at
    ):
        raise _owner_v2_error(
            "invalid",
            "candidate-minted authorization is refused; approved_at_utc must "
            "not copy the candidate generated_at_utc.",
        )


def _owner_authorization_schema_v2_approved(
    repo: pathlib.Path, record: Mapping[str, object], submission_approved: bool
) -> bool:
    import apple_final_evidence_collector as collector

    if APPLE_REQUIRED_UPLOAD_TARGET_IDS != ("ios-app-store-ipa", "macos-app-store-pkg"):
        raise UploadReadinessError(
            "Required Apple upload target contract is invalid."
        )
    auth_schema = record.get("authorization_schema_version")
    if (
        type(auth_schema) is not int
        or auth_schema != OWNER_AUTHORIZATION_SCHEMA_VERSION
    ):
        raise _owner_v2_error(
            "mixed",
            "authorization_schema_version must be integer 2 with nested authorization.",
        )
    authorization = record.get("owner_authorization")
    if type(authorization) is not dict or set(authorization) != OWNER_AUTHORIZATION_KEYS:
        raise _owner_v2_error(
            "partial", "owner_authorization schema fields are invalid."
        )
    if authorization.get("contract") != collector.OWNER_AUTHORIZATION_CONTRACT:
        raise _owner_v2_error("invalid", "owner authorization contract is invalid.")
    status = _owner_require_str(authorization.get("status"), "owner authorization status")
    if status not in {"pending", "approved"}:
        raise _owner_v2_error("invalid", "owner authorization status is not recognized.")
    credentials_authorized = _owner_require_bool(
        authorization.get("credentials_authorized"), "credentials_authorized"
    )
    upload_authorized = _owner_require_bool(
        authorization.get("upload_authorized"), "upload_authorized"
    )
    approved_hash = _owner_require_str(
        authorization.get("approved_evidence_set_sha256"),
        "approved_evidence_set_sha256",
        allow_empty=True,
    )
    scope = _owner_approved_scope(record)
    if scope not in {OWNER_DRAFT_SCOPE, OWNER_FINAL_SCOPE}:
        raise _owner_v2_error(
            "partial",
            "approved_scope must cover iOS/macOS draft scope or the final "
            "iOS/macOS/watchOS Apple targets.",
        )
    expected = _owner_evidence_from_repo(repo, collector)
    evidence = authorization.get("evidence")
    canonical = _owner_collector_call(
        collector.CollectorError, collector.canonical_owner_evidence_set, evidence
    )
    if canonical != expected:
        raise _owner_v2_error(
            "stale",
            "evidence no longer matches the candidate manifest identity and hashes.",
        )
    covered_targets = _apple_targets_covered_by_surfaces(
        canonical["required_surfaces"]
    )
    if tuple(canonical["required_surfaces"]) != collector.REQUIRED_OWNER_SURFACES:
        raise _owner_v2_error(
            "partial",
            "authorization must cover ios, embedded_watchos_companion, and macos.",
        )
    if covered_targets != APPLE_REQUIRED_UPLOAD_TARGET_IDS:
        raise _owner_v2_error(
            "partial",
            "authorization does not cover every required Apple upload target: "
            + ", ".join(APPLE_REQUIRED_UPLOAD_TARGET_IDS),
        )
    complete = _owner_collector_call(
        collector.CollectorError,
        collector.evidence_set_is_complete,
        canonical,
        validate=False,
    )
    approval_material = (
        bool(approved_hash)
        or credentials_authorized
        or upload_authorized
        or submission_approved
        or bool(record.get("approved_by"))
        or bool(record.get("approved_at_utc"))
    )
    if status == "pending":
        if approval_material:
            if complete:
                raise _owner_v2_error(
                    "self-contradictory",
                    "complete evidence still requires explicit owner approval "
                    "before upload.",
                )
            raise _owner_v2_error(
                "self-contradictory",
                "pending authorization cannot carry approval flags, a signer, "
                "or an evidence-set hash.",
            )
        return False
    if not complete:
        raise _owner_v2_error(
            "partial",
            "approved authorization requires a complete current evidence set.",
        )
    _assert_owner_hashes_not_reused(canonical)
    digest = _owner_collector_call(
        collector.CollectorError, collector.owner_evidence_set_sha256, canonical
    )
    if approved_hash != digest:
        raise _owner_v2_error(
            "stale",
            "approved_evidence_set_sha256 no longer matches the bound evidence set.",
        )
    if (
        not credentials_authorized
        or not upload_authorized
        or submission_approved is not True
    ):
        raise _owner_v2_error(
            "self-contradictory",
            "approved authorization must set credentials, upload, and "
            "submission_approved together.",
        )
    if scope != OWNER_FINAL_SCOPE:
        raise _owner_v2_error(
            "partial",
            "approved authorization must cover every required Apple target, "
            "including the embedded watchOS companion.",
        )
    candidate = _load_json(
        _owner_repo_file(repo, APPLE_RELEASE_CANDIDATE, "Apple release candidate"),
        "Apple release candidate",
    )
    _assert_owner_approval_identity(
        record,
        candidate_generated_at=candidate.get("generated_at_utc"),
    )
    return True


def _owner_signoff_submission_approved(repo: pathlib.Path) -> bool:
    path = _repo_path(repo, OWNER_SIGNOFF, "Apple owner signoff")
    record = _load_json(path, "Apple owner signoff")
    schema = record.get("schema_version")
    if type(schema) is not int:
        raise UploadReadinessError(
            "Apple owner signoff schema_version is invalid."
        )
    if schema == OWNER_AUTHORIZATION_SCHEMA_VERSION:
        raise _owner_v2_error(
            "mixed",
            "top-level document schema 1 and nested authorization schema 2 "
            "must not be confused.",
        )
    if schema != OWNER_SIGNOFF_DOCUMENT_SCHEMA_VERSION:
        raise UploadReadinessError(
            "Apple owner signoff schema_version is invalid."
        )
    approved = record.get("submission_approved")
    if type(approved) is not bool:
        raise UploadReadinessError(
            "Apple owner signoff submission_approved is invalid."
        )
    auth_schema = record.get("authorization_schema_version")
    has_authorization = "owner_authorization" in record
    if auth_schema is None and not has_authorization:
        # Schema 1 can record pending owner decisions, but it has no structured
        # binding to the exact IPA/PKG, candidate manifest, or Apple targets.
        if approved:
            raise UploadReadinessError(
                "Apple owner signoff schema 1 cannot approve submission because it "
                "is not bound to exact release artifacts and evidence."
            )
        return False
    return _owner_authorization_schema_v2_approved(repo, record, approved)


def _checklist_records_purchase_history_owner_gate(repo: pathlib.Path) -> bool:
    text = _repo_path(repo, CHECKLIST, "Cross-store checklist").read_text(
        encoding="utf-8"
    )
    return (
        "Purchase History is **not collected**" in text
        and "Live App Store Connect still lists it" in text
        and "Do not publish" in text
    )


def _owner_blocker_record(
    blocker_id: str,
    detail: str,
    target_ids: Sequence[str],
    *,
    evidence_path: str | None = None,
    evidence_sha256: str | None = None,
) -> dict[str, object]:
    ordered = [target_id for target_id in target_ids]
    if not ordered or set(ordered) - REQUIRED_TARGET_IDS:
        raise UploadReadinessError(
            f"{blocker_id} owner blocker target set is not exact."
        )
    record: dict[str, object] = {
        "id": blocker_id,
        "detail": detail,
        "target_ids": ordered,
    }
    if evidence_path is not None:
        if not evidence_path or evidence_path.startswith(".artifacts/"):
            raise UploadReadinessError(
                f"{blocker_id} owner evidence must be a separate non-receipt path."
            )
        record["evidence_path"] = evidence_path
    if evidence_sha256 is not None:
        if re.fullmatch(r"[0-9a-f]{64}", evidence_sha256) is None:
            raise UploadReadinessError(
                f"{blocker_id} owner evidence hash is invalid."
            )
        record["evidence_sha256"] = evidence_sha256
    return record


def _readiness_status(
    *,
    owner_blockers: Sequence[Mapping[str, object]],
    local_artifacts_ready: bool,
) -> str:
    if owner_blockers or not local_artifacts_ready:
        return READINESS_STATUS_BLOCKED
    return READINESS_STATUS_LOCAL_READY


def _release_identity_map(repo: pathlib.Path) -> dict[str, object]:
    path = _repo_path(repo, RELEASE_IDENTITY_RELATIVE, "Release identity map")
    record = _exact(
        _load_json(path, "Release identity map"),
        set(RELEASE_IDENTITY_KEYS),
        "Release identity map",
    )
    mappings = record.get("platform_mappings")
    if type(mappings) is not dict:
        raise UploadReadinessError("Release identity map platform set is malformed.")
    release = freeze._release_identity(repo)
    if record.get("canonical_release") != release:
        raise UploadReadinessError(
            f"Release identity map is stale for release {release}."
        )
    return record


def _schema1_signer_is_absent(value: object) -> bool:
    if type(value) is not str:
        return False
    lowered = value.strip().lower()
    return (
        value == OWNER_BLOCKED_ABSENT
        or lowered in OWNER_PLACEHOLDER_SIGNERS
        or lowered.replace(" ", "-") in {"owner-blocked-absent", "absent"}
    )


def _schema1_platform_owner_blocker(
    repo: pathlib.Path, spec: PlatformOwnerEvidence
) -> dict[str, object]:
    try:
        path = _repo_path(repo, spec.path, spec.label)
    except freeze.DependencyFreezeError:
        return _owner_blocker_record(
            spec.blocker_id,
            f"{OWNER_BLOCKED_ABSENT} {spec.path}",
            spec.target_ids,
        )
    record = _load_json(path, spec.label)
    schema = record.get("schema_version")
    approved = record.get("submission_approved")
    upload_authorized = record.get("upload_authorized")
    canonical = record.get("canonical_release")
    if type(schema) is not int or schema != OWNER_SIGNOFF_DOCUMENT_SCHEMA_VERSION:
        raise UploadReadinessError(f"{spec.label} schema_version is invalid.")
    if record.get("contract") != spec.contract:
        raise UploadReadinessError(
            f"{spec.label} contract is not {spec.contract}."
        )
    if type(approved) is not bool or type(upload_authorized) is not bool:
        raise UploadReadinessError(
            f"{spec.label} submission_approved/upload_authorized are invalid."
        )
    if approved or upload_authorized:
        raise UploadReadinessError(
            f"{spec.label} schema 1 cannot approve submission because it "
            "is not bound to exact release artifacts and evidence."
        )
    release = freeze._release_identity(repo)
    if type(canonical) is not str or not canonical:
        raise UploadReadinessError(f"{spec.label} omitted canonical_release.")
    if canonical != release:
        raise UploadReadinessError(
            f"{spec.label} is stale for release {release}."
        )
    identity_map = _release_identity_map(repo)
    mappings = identity_map.get("platform_mappings")
    if type(mappings) is not dict:
        raise UploadReadinessError("Release identity map platform set is malformed.")
    for field, map_key, map_field, expected_type in PLATFORM_OWNER_IDENTITY_FIELDS[
        spec.blocker_id
    ]:
        actual = record.get(field)
        mapped = mappings.get(map_key)
        if type(mapped) is not dict or map_field not in mapped:
            raise UploadReadinessError(
                f"{spec.label} identity map is missing {map_key}.{map_field}."
            )
        expected = mapped.get(map_field)
        if actual is None or (isinstance(actual, str) and not actual.strip()):
            return _owner_blocker_record(
                spec.blocker_id,
                f"{OWNER_BLOCKED_ABSENT} {spec.path} {field}",
                spec.target_ids,
                evidence_path=spec.path,
                evidence_sha256=_owner_file_sha256(path, spec.label),
            )
        if type(actual) is not expected_type or actual != expected:
            raise UploadReadinessError(
                f"{spec.label} is stale for identity/version field {field}."
            )
    signer = record.get("authenticode_leaf_sha256")
    if signer is not None:
        if type(signer) is str and re.fullmatch(r"[0-9a-f]{64}", signer) is not None:
            raise UploadReadinessError(
                f"{spec.label} schema 1 cannot bind an Authenticode signer because "
                "it is not bound to exact release artifacts and evidence."
            )
        if not _schema1_signer_is_absent(signer):
            return _owner_blocker_record(
                spec.blocker_id,
                f"{OWNER_BLOCKED_ABSENT} {spec.path} authenticode signer",
                spec.target_ids,
                evidence_path=spec.path,
                evidence_sha256=_owner_file_sha256(path, spec.label),
            )
    return _owner_blocker_record(
        spec.blocker_id,
        (
            f"{spec.path} submission_approved is false; "
            f"{spec.label} upload stays unauthorized."
        ),
        spec.target_ids,
        evidence_path=spec.path,
        evidence_sha256=_owner_file_sha256(path, spec.label),
    )


def _owner_blockers(repo: pathlib.Path) -> list[dict[str, object]]:
    blockers: list[dict[str, object]] = []
    query_status = _query_all_packages_status(repo)
    play_path = _repo_path(repo, PLAY_DECLARATIONS, "Play declarations")
    if query_status != "APPROVED":
        blockers.append(
            _owner_blocker_record(
                "play-query-all-packages",
                (
                    "Google Play QUERY_ALL_PACKAGES declaration remains "
                    f"{query_status}; owner Play Console approval is required."
                ),
                PLAY_QUERY_UPLOAD_TARGET_IDS,
                evidence_path=PLAY_DECLARATIONS,
                evidence_sha256=_owner_file_sha256(play_path, "Play declarations"),
            )
        )
    apple_path = _repo_path(repo, OWNER_SIGNOFF, "Apple owner signoff")
    if not _owner_signoff_submission_approved(repo):
        blockers.append(
            _owner_blocker_record(
                "apple-owner-signoff",
                (
                    "app_store/apple/review/owner_signoff.json submission_approved "
                    "is false; Apple upload stays unauthorized."
                ),
                APPLE_REQUIRED_UPLOAD_TARGET_IDS,
                evidence_path=OWNER_SIGNOFF,
                evidence_sha256=_owner_file_sha256(apple_path, "Apple owner signoff"),
            )
        )
    if _checklist_records_purchase_history_owner_gate(repo):
        checklist_path = _repo_path(repo, CHECKLIST, "Cross-store checklist")
        blockers.append(
            _owner_blocker_record(
                "apple-live-purchase-history",
                (
                    "Source privacy manifests omit Purchase History, but live App "
                    "Store Connect still lists it. The owner must correct the console "
                    "before publication."
                ),
                APPLE_REQUIRED_UPLOAD_TARGET_IDS,
                evidence_path=CHECKLIST,
                evidence_sha256=_owner_file_sha256(
                    checklist_path, "Cross-store checklist"
                ),
            )
        )
    for spec in PLATFORM_OWNER_EVIDENCE:
        blockers.append(_schema1_platform_owner_blocker(repo, spec))
    return blockers


def _required_producer_verifier_paths() -> tuple[str, ...]:
    paths: list[str] = []
    seen: set[str] = set()

    def add(relative: str) -> None:
        if relative not in seen:
            seen.add(relative)
            paths.append(relative)

    for target in REQUIRED_UPLOAD_TARGETS:
        for producer_id in target.producer_ids:
            add(producer_id)
        for gate_id in (target.signing_gate_id, target.hardening_gate_id):
            for producer_id in GATE_PRODUCER_IDS[gate_id]:
                add(producer_id)
        if target.manifest_verifier_path is not None:
            add(target.manifest_verifier_path)
    for relative in EXTENSION_VERIFIER_SOURCE_PATHS:
        add(relative)
    add(RELEASE_IDENTITY_RELATIVE)
    add(LINUX_ARTIFACT_GATE_RELATIVE)
    add(APPLE_ARTIFACT_GATE_RELATIVE)
    add(WINDOWS_ARTIFACT_GATE_RELATIVE)
    return tuple(paths)


def _producer_verifier_closure(repo: pathlib.Path) -> dict[str, object]:
    inputs: list[dict[str, object]] = []
    for relative in _required_producer_verifier_paths():
        path = freeze.secure_repo_path(
            repo,
            pathlib.Path(relative),
            f"producer/verifier {relative}",
            must_exist=True,
        )
        size, _, digest = _stable_identity(path, f"producer/verifier {relative}")
        inputs.append({"path": relative, "sha256": digest, "bytes": size})
    encoded = (
        json.dumps(inputs, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    return {
        "inputs": inputs,
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _target_description(target: UploadTarget) -> dict[str, object]:
    return {
        "platform": target.platform,
        "store_surface": target.store_surface,
        "build_receipt_target": target.build_receipt_target,
        "build_receipt_target_supported": _build_receipt_target_supported(target),
        "manifest_verifier_path": target.manifest_verifier_path,
        "artifact_suffixes": list(target.artifact_suffixes),
        "producer_ids": list(target.producer_ids),
        "signing_verification_gate": target.signing_gate_id,
        "obfuscation_privacy_gate": target.hardening_gate_id,
    }


def _build_receipt_target_supported(target: UploadTarget) -> bool:
    if target.manifest_verifier_path is not None:
        return (
            target.platform == "linux"
            and target.target_id == target.build_receipt_target
            and target.producer_ids == (target.manifest_verifier_path,)
        )
    return target.build_receipt_target in freeze.allowed_targets(target.platform)


def evaluate_source_gates(repo: pathlib.Path) -> dict[str, object]:
    repo = freeze.secure_repo_path(
        repo, pathlib.Path("."), "Repository root", must_exist=True
    )
    freeze._assert_canonical_platforms()
    _assert_target_contract()
    platforms: dict[str, dict[str, object]] = {}
    for platform in freeze.CANONICAL_FREEZE_PLATFORMS:
        freeze._assert_required_gate_producers(platform)
        platforms[platform] = {
            "store_surfaces": list(freeze.store_surfaces(platform)),
            "allowed_build_receipt_targets": list(freeze.allowed_targets(platform)),
            "build_producer": freeze.PLATFORM_BUILD_PRODUCERS[platform],
            "required_gate_producers": list(freeze.required_gate_producers(platform)),
        }
    for target in ALL_UPLOAD_TARGETS:
        for producer_id in target.producer_ids:
            producer = freeze.secure_repo_path(
                repo,
                pathlib.Path(producer_id),
                f"{target.target_id} producer",
                must_exist=True,
            )
            if not producer.is_file():
                raise UploadReadinessError(
                    f"{target.target_id} producer is not a regular file."
                )
    unsupported_target_bindings = [
        target.target_id
        for target in REQUIRED_UPLOAD_TARGETS
        if not _build_receipt_target_supported(target)
    ]
    owner_blockers = _owner_blockers(repo)
    local_artifacts_ready = False
    status = _readiness_status(
        owner_blockers=owner_blockers,
        local_artifacts_ready=local_artifacts_ready,
    )
    return {
        "ok": False,
        "status": status,
        "contract": CONTRACT,
        "schema_version": SCHEMA_VERSION,
        "release": freeze._release_identity(repo),
        "privacy_policy_url": freeze.PRIVACY_POLICY_URL,
        "freeze_platforms_complete": True,
        "platforms": platforms,
        "required_targets": {
            target.target_id: _target_description(target)
            for target in REQUIRED_UPLOAD_TARGETS
        },
        "required_target_ids": [target.target_id for target in REQUIRED_UPLOAD_TARGETS],
        "optional_targets": {
            target.target_id: _target_description(target)
            for target in OPTIONAL_UPLOAD_TARGETS
        },
        "optional_target_ids": [target.target_id for target in OPTIONAL_UPLOAD_TARGETS],
        "planned_unsupported_targets": dict(PLANNED_UNSUPPORTED_TARGETS),
        "missing_target_receipts": [
            target.target_id for target in REQUIRED_UPLOAD_TARGETS
        ],
        "unsupported_build_receipt_targets": unsupported_target_bindings,
        "local_gate_bindings_complete": not unsupported_target_bindings,
        "local_gates_executed": False,
        "local_artifacts_ready": local_artifacts_ready,
        "producer_verifier_closure": _producer_verifier_closure(repo),
        "publication_authorized": False,
        "store_upload_authorized": False,
        "upload_attempted": False,
        "owner_blockers": owner_blockers,
    }


def _parse_receipt_binding(raw: str) -> tuple[str, pathlib.Path]:
    if raw.count("=") != 1:
        raise UploadReadinessError(
            "Receipt binding must use target-id=.artifacts/.../RECEIPT.json."
        )
    target_id, path = (part.strip() for part in raw.split("=", 1))
    if target_id not in REQUIRED_TARGET_IDS:
        raise UploadReadinessError(f"Unexpected upload target: {target_id}")
    if not path or not path.startswith(".artifacts/"):
        raise UploadReadinessError(
            "Receipt binding must use target-id=.artifacts/.../RECEIPT.json."
        )
    return target_id, pathlib.Path(path)


def _load_json(path: pathlib.Path, label: str) -> dict[str, object]:
    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        record: dict[str, object] = {}
        for key, value in pairs:
            if key in record:
                raise UploadReadinessError(
                    f"{label} contains duplicate JSON key: {key}"
                )
            record[key] = value
        return record

    try:
        record = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UploadReadinessError(f"Unable to read {label}: {exc}") from exc
    if not isinstance(record, dict):
        raise UploadReadinessError(f"{label} must be a JSON object.")
    return record


def _exact(record: object, keys: set[str], label: str) -> dict[str, object]:
    try:
        return freeze._require_exact_keys(record, keys, label)
    except freeze.DependencyFreezeError as exc:
        raise UploadReadinessError(str(exc)) from exc


def _verify_gcp_proof_acceptance_receipt(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    receipt_path: pathlib.Path,
) -> dict[str, object]:
    """Revalidate the isolated three-VM acceptance receipt for this freeze.

    The GCP proof tool owns the receipt schema and immutable state bundle.
    Cross-store readiness owns only the release-order binding: it accepts a
    receipt only when the proof's revalidated Linux client binding names this
    exact release-input index, by path and digest.
    """
    candidate = receipt_path.expanduser()
    if (
        not candidate.is_absolute()
        or os.path.normpath(str(candidate)) != str(candidate)
    ):
        raise UploadReadinessError(
            "GCP proof acceptance receipt path must be absolute and canonical."
        )
    if candidate.name != gcp_proof.RECEIPT_NAME:
        raise UploadReadinessError(
            "GCP proof acceptance receipt must be named "
            f"{gcp_proof.RECEIPT_NAME}."
        )
    state_dir = candidate.parent
    try:
        state_info = state_dir.lstat()
    except OSError as exc:
        raise UploadReadinessError(
            "GCP proof acceptance state directory is not readable."
        ) from exc
    if (
        stat.S_ISLNK(state_info.st_mode)
        or not stat.S_ISDIR(state_info.st_mode)
        or stat.S_IMODE(state_info.st_mode) != 0o700
    ):
        raise UploadReadinessError(
            "GCP proof acceptance state directory must be a private mode-0700 directory."
        )
    try:
        verified = gcp_proof.verify_acceptance_receipt_for_release(
            candidate,
            repo_root=repo,
            release_input_index=index_path,
        )
    except gcp_proof.FleetRefused as exc:
        raise UploadReadinessError(
            f"GCP proof acceptance receipt is invalid: {exc}"
        ) from exc
    return {
        "path": str(candidate),
        "sha256": verified["receipt_sha256"],
        "created_utc": verified["receipt_created_utc"],
        "release": verified["release"],
        "release_input_index": {
            "path": verified["release_input_index"]["path"],
            "sha256": verified["release_input_index"]["sha256"],
        },
        "client_build_identity": verified["client_build_identity"],
    }


def _valid_stat_identity(value: object, length: int) -> bool:
    return (
        isinstance(value, list)
        and len(value) == length
        and all(isinstance(part, int) and not isinstance(part, bool) for part in value)
    )


def _verify_artifact_custody_evidence(
    repo: pathlib.Path,
    target_id: str,
    value: object,
    artifact_binding: Mapping[str, object],
    artifact_before: Mapping[str, object],
    artifact_after: Mapping[str, object],
) -> tuple[dict[str, object], pathlib.Path]:
    """Validate the retained-object closure used for one gate execution."""

    custody = _exact(
        value,
        set(ARTIFACT_CUSTODY_EVIDENCE_KEYS),
        f"{target_id} artifact custody",
    )
    strategy = custody.get("strategy")
    if strategy not in ARTIFACT_CUSTODY_STRATEGIES:
        raise UploadReadinessError(
            f"{target_id} artifact custody strategy is not reviewed."
        )
    windows_strategy = strategy == "windows-retained-deny-write-delete-handles-v1"
    original_artifact = freeze.secure_repo_path(
        repo,
        pathlib.Path(str(artifact_binding["path"])),
        f"{target_id} custody artifact",
        must_exist=True,
    )
    artifact_relative = original_artifact.relative_to(repo).as_posix()
    execution_artifact = (
        original_artifact
        if windows_strategy
        else gate_runner.artifact_snapshot_path_for(
            original_artifact, str(artifact_binding["sha256"])
        )
    )
    execution_relative = execution_artifact.relative_to(repo).as_posix()
    expected_paths = ["."]
    parent_parts = original_artifact.relative_to(repo).parts[:-1]
    accumulated: list[str] = []
    for part in parent_parts:
        accumulated.append(part)
        expected_paths.append("/".join(accumulated))
    expected_paths.append(artifact_relative)
    if not windows_strategy:
        expected_paths.extend(
            (execution_artifact.parent.relative_to(repo).as_posix(), execution_relative)
        )
    retained = custody.get("retained_objects")
    identity_length = 9 if windows_strategy else 7
    if (
        not isinstance(retained, list)
        or custody.get("retained_object_count") != len(expected_paths)
        or len(retained) != len(expected_paths)
    ):
        raise UploadReadinessError(
            f"{target_id} artifact custody retained-object inventory is invalid."
        )
    normalized_records: list[dict[str, object]] = []
    observed_paths: list[str] = []
    for index, item in enumerate(retained):
        record = _exact(
            item,
            {"path", "identity"},
            f"{target_id} artifact custody retained object {index}",
        )
        path = record.get("path")
        identity = record.get("identity")
        if (
            not isinstance(path, str)
            or path != expected_paths[index]
            or (path != "." and (
                pathlib.PurePosixPath(path).is_absolute()
                or any(part in {"", ".", ".."} for part in path.split("/"))
            ))
            or not _valid_stat_identity(identity, identity_length)
        ):
            raise UploadReadinessError(
                f"{target_id} artifact custody retained object is invalid."
            )
        observed_paths.append(path)
        normalized_records.append({"path": path, "identity": identity})
    if len(set(observed_paths)) != len(observed_paths):
        raise UploadReadinessError(
            f"{target_id} artifact custody retained paths are duplicated."
        )
    closure_sha256 = hashlib.sha256(
        json.dumps(
            normalized_records,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    source_identity = custody.get("source_identity")
    snapshot_identity = custody.get("snapshot_identity")
    expected_source_fields = (
        (0, "device"),
        (1, "inode"),
        (2, "mode"),
        (4, "bytes"),
        (5, "mtime_ns"),
        (6, "ctime_ns"),
    )
    source_matches_path_evidence = _valid_stat_identity(source_identity, 7) and all(
        source_identity[index] == snapshot.get(field)
        for snapshot in (artifact_before, artifact_after)
        for index, field in expected_source_fields
    )
    hashes_are_exact = (
        re.fullmatch(r"[0-9a-f]{64}", str(custody.get("ancestor_closure_sha256")))
        is not None
        and custody.get("ancestor_closure_sha256") == closure_sha256
        and custody.get("source_sha256") == artifact_binding["sha256"]
        and custody.get("snapshot_sha256") == artifact_binding["sha256"]
    )
    generation = custody.get("verification_generation")
    if (
        custody.get("source_path") != artifact_relative
        or custody.get("execution_path") != execution_relative
        or not hashes_are_exact
        or not source_matches_path_evidence
        or not _valid_stat_identity(snapshot_identity, 7)
        or source_identity[3] != 1
        or snapshot_identity[3] != 1
        or custody.get("bytes") != artifact_binding["bytes"]
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 3
        or custody.get("kernel_mutation_events_observed") is not False
        or custody.get("windows_delete_write_sharing_denied") is not windows_strategy
    ):
        raise UploadReadinessError(
            f"{target_id} artifact custody binding is invalid."
        )
    if windows_strategy:
        if snapshot_identity != source_identity:
            raise UploadReadinessError(
                f"{target_id} Windows artifact custody identity is invalid."
            )
    else:
        artifact_record = normalized_records[-3]["identity"]
        snapshot_record = normalized_records[-1]["identity"]
        if (
            artifact_record != source_identity
            or snapshot_record != snapshot_identity
            or stat.S_IMODE(snapshot_identity[2]) & 0o077
        ):
            raise UploadReadinessError(
                f"{target_id} POSIX artifact custody identity is invalid."
            )
    return custody, execution_artifact


def _stable_identity(path: pathlib.Path, label: str) -> tuple[int, int, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    identity_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    try:
        path_before = path.lstat()
        descriptor = os.open(path, flags)
        try:
            descriptor_before = os.fstat(descriptor)
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            descriptor_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = path.lstat()
    except OSError as exc:
        raise UploadReadinessError(f"Unable to verify {label}: {exc}") from exc
    identities = [
        tuple(getattr(info, field) for field in identity_fields)
        for info in (path_before, descriptor_before, descriptor_after, path_after)
    ]
    if (
        len(set(identities)) != 1
        or not stat.S_ISREG(path_after.st_mode)
        or path_after.st_nlink != 1
    ):
        raise UploadReadinessError(
            f"{label} changed, is not regular, or has a hardlink alias."
        )
    if path_after.st_size <= 0:
        raise UploadReadinessError(f"{label} is empty.")
    return path_after.st_size, path_after.st_mtime_ns, digest.hexdigest()


def _authenticated_file_bytes(path: pathlib.Path, label: str) -> tuple[bytes, str]:
    """Read one regular file and bind the returned bytes to its digest."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    identity_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    try:
        path_before = path.lstat()
        descriptor = os.open(path, flags)
        try:
            descriptor_before = os.fstat(descriptor)
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                digest.update(chunk)
            descriptor_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = path.lstat()
    except OSError as exc:
        raise UploadReadinessError(f"Unable to read {label}: {exc}") from exc
    identities = [
        tuple(getattr(info, field) for field in identity_fields)
        for info in (path_before, descriptor_before, descriptor_after, path_after)
    ]
    payload = b"".join(chunks)
    if (
        len(set(identities)) != 1
        or not stat.S_ISREG(path_after.st_mode)
        or path_after.st_nlink != 1
        or path_after.st_size <= 0
        or len(payload) != path_after.st_size
    ):
        raise UploadReadinessError(
            f"{label} changed, is not regular, or has a hardlink alias."
        )
    return payload, digest.hexdigest()


@contextlib.contextmanager
def _private_extension_hardening_artifact(
    payload: bytes,
    filename: str,
    digest: str,
):
    """Inspect a private copy of authenticated zip bytes, not a live path."""

    if not filename or "/" in filename or "\\" in filename or filename in {".", ".."}:
        raise UploadReadinessError("extension hardening copy filename is invalid.")
    directory = pathlib.Path(
        tempfile.mkdtemp(prefix=".winsvpn-ext-hard-", suffix="")
    )
    path = directory / filename
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    created = False
    try:
        os.chmod(directory, 0o700)
        descriptor = os.open(path, flags, 0o600)
        created = True
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise UploadReadinessError(
                    "extension hardening copy wrote no authenticated bytes."
                )
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        copy_size, _mtime_ns, copy_digest = _stable_identity(
            path, "extension hardening snapshot copy"
        )
        if copy_digest != digest or copy_size != len(payload):
            raise UploadReadinessError(
                "extension hardening copy is not the authenticated snapshot bytes."
            )
        yield path
        after_size, _after_mtime_ns, after_digest = _stable_identity(
            path, "extension hardening snapshot copy"
        )
        if after_digest != digest or after_size != len(payload):
            raise UploadReadinessError(
                "extension hardening copy changed during privacy or minification."
            )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            try:
                os.unlink(path)
            except OSError:
                pass
        try:
            os.rmdir(directory)
        except OSError:
            pass


def _python_interpreter_identity(path: pathlib.Path) -> tuple[int, int, str]:
    """Return opened-file identity of a Python interpreter.

    Cross-session substitution is rejected by device, inode, and digest of the
    opened regular file. Interpreter symlink spelling is not an identity check;
    a python3 name that follows to the same authenticated binary is the same
    interpreter.
    """

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            raise UploadReadinessError(
                "Python interpreter is not a non-empty regular file."
            )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise UploadReadinessError(
            f"Unable to authenticate Python interpreter identity: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise UploadReadinessError("Python interpreter identity changed while hashing.")
    return before.st_dev, before.st_ino, digest.hexdigest()


def _utc_timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise UploadReadinessError("Gate runner clock returned a naive timestamp.")
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _artifact_execution_snapshot(
    repo: pathlib.Path, artifact_path: pathlib.Path, target_id: str
) -> dict[str, object]:
    artifact_path = freeze.secure_repo_path(
        repo, artifact_path, f"{target_id} gate artifact", must_exist=True
    )
    try:
        path_before = artifact_path.lstat()
        if not stat.S_ISREG(path_before.st_mode):
            raise UploadReadinessError(
                f"{target_id} gate artifact must be a regular file."
            )
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(artifact_path, flags)
        try:
            descriptor_before = os.fstat(descriptor)
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            descriptor_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = artifact_path.lstat()
    except OSError as exc:
        raise UploadReadinessError(
            f"Unable to snapshot {target_id} gate artifact: {exc}"
        ) from exc
    identity_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    identities = [
        tuple(getattr(info, field) for field in identity_fields)
        for info in (path_before, descriptor_before, descriptor_after, path_after)
    ]
    if (
        len(set(identities)) != 1
        or path_after.st_size <= 0
        or path_after.st_nlink != 1
        or path_after.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise UploadReadinessError(
            f"{target_id} gate artifact changed, has a hardlink alias, or is "
            "writable by group or other."
        )
    return {
        "path": freeze._relative_repo_path(repo, artifact_path),
        "sha256": digest.hexdigest(),
        "bytes": path_after.st_size,
        "device": path_after.st_dev,
        "inode": path_after.st_ino,
        "mode": path_after.st_mode,
        "mtime_ns": path_after.st_mtime_ns,
        "ctime_ns": path_after.st_ctime_ns,
    }


def _command_identity(
    target_id: str,
    gate_id: str,
    order: int,
    argv: tuple[str, ...],
    producer_path: str,
    producer_sha256: str,
) -> str:
    encoded = json.dumps(
        {
            "target_id": target_id,
            "gate_id": gate_id,
            "order": order,
            "argv": list(argv),
            "producer_path": producer_path,
            "producer_sha256": producer_sha256,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclasses.dataclass(frozen=True)
class _SealedProductionGateRunner:
    runner: object
    runner_class: type
    result_type: type
    module: object
    module_name: str
    controller_path: pathlib.Path
    snapshot_path: pathlib.Path
    controller_sha256: str


def _production_gate_controller_path() -> pathlib.Path:
    controller = pathlib.Path(__file__).resolve().parent / "cross_store_gate_runner.py"
    expected = controller.parent.parent / PRODUCTION_GATE_CONTROLLER
    if controller != expected.resolve():
        raise UploadReadinessError(
            "Production gate runner path is not the sealed internal controller."
        )
    return controller


def _live_production_controller_digest() -> str:
    _size, _mtime, digest = _stable_identity(
        _production_gate_controller_path(),
        "production gate runner controller",
    )
    return digest


def _runner_is_test_only(runner: object) -> bool:
    return (
        getattr(type(runner), "TEST_ONLY", False) is True
        or getattr(runner, "TEST_ONLY", False) is True
    )


def _reject_caller_supplied_runner(runner: object | None) -> None:
    if runner is None:
        return
    if _runner_is_test_only(runner):
        return
    raise UploadReadinessError(
        "Production evidence does not accept a caller-supplied or mocked "
        "runner identity."
    )


@contextlib.contextmanager
def _sealed_production_gate_runner():
    """Load SubprocessExplicitArgvRunner from frozen controller bytes."""

    controller = _production_gate_controller_path()
    live_digest = _live_production_controller_digest()
    previous_dont_write = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    module_name = f"{_SEALED_GATE_RUNNER_MODULE_PREFIX}{live_digest}"
    if module_name in sys.modules:
        raise UploadReadinessError(
            "Sealed production gate runner identity collided."
        )
    temporary = tempfile.TemporaryDirectory(prefix="winsvpn-gate-runner-")
    snapshot = pathlib.Path(temporary.name) / "cross_store_gate_runner.py"
    module = None
    try:
        try:
            copied = gate_runner.exclusive_copy_file(controller, snapshot)
        except gate_runner.ExactSnapshotError as exc:
            raise UploadReadinessError(
                f"Unable to seal the production gate runner controller: {exc}"
            ) from exc
        snap_size, _snap_mtime, snap_digest = _stable_identity(
            snapshot, "sealed production gate runner snapshot"
        )
        live_size, _live_mtime, after_copy_digest = _stable_identity(
            controller, "production gate runner controller"
        )
        if (
            copied != live_digest
            or snap_digest != live_digest
            or after_copy_digest != live_digest
            or snap_size != live_size
            or snap_size <= 0
        ):
            raise UploadReadinessError(
                "Sealed production gate runner snapshot is not the exact "
                "controller bytes."
            )
        spec = importlib.util.spec_from_file_location(module_name, snapshot)
        if spec is None or spec.loader is None:
            raise UploadReadinessError(
                "Sealed production gate runner snapshot cannot be loaded."
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        runner_class = getattr(module, _PRODUCTION_RUNNER_CLASS_NAME, None)
        result_type = getattr(module, "GateProcessResult", None)
        if (
            not isinstance(runner_class, type)
            or not isinstance(result_type, type)
            or getattr(runner_class, "TEST_ONLY", False) is True
            or getattr(runner_class, "RUNNER_ID", None)
            != gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID
            or getattr(runner_class, "ENVIRONMENT_OVERRIDES", None)
            != gate_runner.SubprocessExplicitArgvRunner.ENVIRONMENT_OVERRIDES
            or getattr(module, "__name__", None) != module_name
            or spec.name != module_name
            or sys.modules.get(module_name) is not module
            or not _same_bound_path(getattr(module, "__file__", None), snapshot)
            or not _same_bound_path(getattr(spec, "origin", None), snapshot)
        ):
            raise UploadReadinessError(
                "Sealed production gate runner is not bound to the controller."
            )
        runner = runner_class()
        if _runner_is_test_only(runner) or type(runner) is not runner_class:
            raise UploadReadinessError(
                "Sealed production gate runner cannot emit production PASS."
            )
        bound = _SealedProductionGateRunner(
            runner=runner,
            runner_class=runner_class,
            result_type=result_type,
            module=module,
            module_name=module_name,
            controller_path=controller,
            snapshot_path=snapshot,
            controller_sha256=live_digest,
        )
        yield bound
        _revalidate_sealed_production_runner(bound, runner, None)
    finally:
        sys.dont_write_bytecode = previous_dont_write
        if module is not None and sys.modules.get(module_name) is module:
            sys.modules.pop(module_name, None)
        else:
            sys.modules.pop(module_name, None)
        temporary.cleanup()


def _revalidate_sealed_production_runner(
    bound: _SealedProductionGateRunner,
    process_runner: object,
    result: object | None,
) -> None:
    live_digest = _live_production_controller_digest()
    _snap_size, _snap_mtime, snap_digest = _stable_identity(
        bound.snapshot_path, "sealed production gate runner snapshot"
    )
    if (
        live_digest != bound.controller_sha256
        or snap_digest != bound.controller_sha256
        or type(process_runner) is not bound.runner_class
        or process_runner is not bound.runner
        or _runner_is_test_only(process_runner)
        or sys.modules.get(bound.module_name) is not bound.module
        or getattr(bound.module, "__name__", None) != bound.module_name
        or not _same_bound_path(
            getattr(bound.module, "__file__", None), bound.snapshot_path
        )
        or getattr(bound.runner_class, "RUNNER_ID", None)
        != gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID
        or getattr(bound.runner_class, "TEST_ONLY", False) is True
    ):
        raise UploadReadinessError(
            "Sealed production gate runner identity changed during execution."
        )
    if result is not None and type(result) is not bound.result_type:
        raise UploadReadinessError(
            "Production gate runner returned an invalid result identity."
        )


def _revalidate_gate_process_fields(
    result: object,
    executed_argv: tuple[str, ...],
    target_id: str,
    gate_id: str,
    *,
    expected_result_type: type | None,
    expected_environment: tuple[tuple[str, str], ...] | None,
) -> tuple[str, str]:
    if expected_result_type is not None:
        valid_result = type(result) is expected_result_type
    else:
        valid_result = isinstance(result, gate_runner.GateProcessResult)
    if not valid_result:
        raise UploadReadinessError(
            f"{target_id} {gate_id} runner returned an invalid result."
        )
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    exit_code = getattr(result, "exit_code", None)
    if (
        getattr(result, "executed", None) is not True
        or getattr(result, "shell_enabled", None) is not False
        or getattr(result, "argv", None) != executed_argv
        or not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
        or not isinstance(stdout, str)
        or not isinstance(stderr, str)
        or (
            expected_environment is not None
            and getattr(result, "environment_overrides", None) != expected_environment
        )
    ):
        raise UploadReadinessError(
            f"{target_id} {gate_id} runner did not prove exact "
            "shell-disabled execution."
        )
    stdout_sha256 = hashlib.sha256(stdout.encode("utf-8")).hexdigest()
    stderr_sha256 = hashlib.sha256(stderr.encode("utf-8")).hexdigest()
    return stdout_sha256, stderr_sha256


def _live_extension_hardening_module(filename: str) -> object:
    cached = _LIVE_EXTENSION_HARDENING_MODULES.get(filename)
    if cached is not None:
        return cached
    path = pathlib.Path(__file__).resolve().parent / pathlib.Path(filename).name
    if path.is_symlink() or not path.is_file():
        raise UploadReadinessError(
            f"Extension hardening producer is missing: {filename}"
        )
    name = f"winsvpn_live_extension_hardening_{path.stem}"
    existing = sys.modules.get(name)
    if existing is not None and _same_bound_path(
        getattr(existing, "__file__", None), path
    ):
        _LIVE_EXTENSION_HARDENING_MODULES[filename] = existing
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise UploadReadinessError(
            f"Extension hardening producer cannot be loaded: {filename}"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(name, None)
        raise UploadReadinessError(
            f"Extension hardening producer failed to load: {filename}: {exc}"
        ) from exc
    _LIVE_EXTENSION_HARDENING_MODULES[filename] = module
    return module


def _verify_extension_manifest_json_numbers(
    target_id: str, payload: bytes
) -> None:
    """Reject JSON numbers that decode to non-finite Python floats."""

    def reject_duplicate_keys(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        record: dict[str, object] = {}
        for key, value in pairs:
            if key in record:
                raise ValueError(f"duplicate manifest key: {key}")
            record[key] = value
        return record

    def finite_float(raw: str) -> float:
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError(f"non-finite manifest number: {raw}")
        return value

    def reject_constant(raw: str) -> None:
        raise ValueError(f"non-finite manifest number: {raw}")

    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            manifests = [
                info for info in archive.infolist() if info.filename == "manifest.json"
            ]
            if len(manifests) != 1 or manifests[0].file_size > 1024 * 1024:
                raise ValueError("manifest.json membership or size is not exact")
            manifest_bytes = archive.read(manifests[0])
        json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        raise UploadReadinessError(
            f"{target_id} extension manifest numeric boundary is invalid: {exc}"
        ) from exc


def verify_extension_cross_store_hardening(
    target_id: str,
    artifact_path: pathlib.Path,
    *,
    expected_sha256: str | None = None,
) -> None:
    """Fail closed unless generic privacy and exact JS minification both pass.

    Canonical Chrome/Edge/Firefox hardening argv may identify one listed
    producer. Release and cross-store artifact paths still invoke both the
    generic privacy scanner and the exact extension minification/obfuscation
    contract against the bound artifact bytes.
    """

    if target_id not in EXTENSION_TARGET_IDS:
        raise UploadReadinessError(f"Unexpected extension upload target: {target_id}")
    browser = EXTENSION_BROWSER_BY_TARGET_ID[target_id]
    required = (
        "tools/validate_release_artifact_privacy.py",
        "tools/release_obfuscation_contract.py",
    )
    if EXTENSION_HARDENING_PRODUCER_IDS != required:
        raise UploadReadinessError(
            f"{target_id} hardening producer pair is not generic privacy plus "
            "exact extension minification/obfuscation verification."
        )
    privacy = _live_extension_hardening_module(required[0])
    obfuscation = _live_extension_hardening_module(required[1])
    privacy_error = getattr(privacy, "PrivacyError", RuntimeError)
    obfuscation_error = getattr(obfuscation, "ObfuscationError", RuntimeError)
    validate_artifacts = getattr(privacy, "validate_artifacts", None)
    validate_members = getattr(privacy, "_validate_extension_members", None)
    verify_js = getattr(obfuscation, "verify_extension_javascript_hardening", None)
    if not callable(validate_artifacts) or not callable(verify_js):
        raise UploadReadinessError(
            f"{target_id} privacy and minification/obfuscation producers are "
            "not invocable."
        )
    payload, digest = _authenticated_file_bytes(
        artifact_path, f"{target_id} extension hardening artifact"
    )
    if expected_sha256 is not None and digest != expected_sha256:
        raise UploadReadinessError(
            f"{target_id} extension hardening artifact is not the bound snapshot identity."
        )
    _verify_extension_manifest_json_numbers(target_id, payload)
    with _private_extension_hardening_artifact(
        payload, artifact_path.name, digest
    ) as inspect_path:
        try:
            validate_artifacts((inspect_path,), {})
            if callable(validate_members):
                validate_members(payload)
        except privacy_error as exc:
            raise UploadReadinessError(
                f"{target_id} generic privacy gate refused the extension artifact: {exc}"
            ) from exc
        except UploadReadinessError:
            raise
        except (OSError, RuntimeError) as exc:
            raise UploadReadinessError(
                f"{target_id} generic privacy gate refused the extension artifact: {exc}"
            ) from exc
        try:
            verify_js(browser, [inspect_path])
        except obfuscation_error as exc:
            raise UploadReadinessError(
                f"{target_id} exact extension minification/obfuscation gate refused "
                f"the artifact: {exc}"
            ) from exc
        except UploadReadinessError:
            raise
        except (OSError, RuntimeError) as exc:
            raise UploadReadinessError(
                f"{target_id} exact extension minification/obfuscation gate refused "
                f"the artifact: {exc}"
            ) from exc
    after_payload, after_digest = _authenticated_file_bytes(
        artifact_path, f"{target_id} extension hardening artifact"
    )
    if after_digest != digest or after_payload != payload:
        raise UploadReadinessError(
            f"{target_id} extension hardening artifact changed after privacy "
            "and minification/obfuscation."
        )


def _validate_gate_argv(
    repo: pathlib.Path,
    target_id: str,
    gate_id: str,
    artifact_path: pathlib.Path,
    raw_argv: Sequence[str],
) -> tuple[tuple[str, ...], str, pathlib.Path, int]:
    if (
        isinstance(raw_argv, (str, bytes))
        or not raw_argv
        or any(
            not isinstance(part, str)
            or not part
            or "\x00" in part
            or "\n" in part
            or "\r" in part
            for part in raw_argv
        )
    ):
        raise UploadReadinessError(f"{target_id} {gate_id} argv is malformed.")
    argv = tuple(raw_argv)
    executable = pathlib.Path(argv[0]).name.lower()
    eval_flags = {part.lower() for part in argv[1:]}
    if (
        executable in {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe"}
        and ({"-c", "/c"} & eval_flags)
    ) or (
        executable
        in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
        and ({"-command", "-encodedcommand", "-enc"} & eval_flags)
    ):
        raise UploadReadinessError(
            f"{target_id} {gate_id} argv requests shell command evaluation."
        )
    matches: list[tuple[str, pathlib.Path, int]] = []
    producer_ids = GATE_PRODUCER_IDS[gate_id]
    for producer_id in producer_ids:
        producer_leaf = repo / producer_id
        if (
            len(producer_ids) > 1
            and not producer_leaf.exists()
            and not os.path.lexists(producer_leaf)
        ):
            # Argv identifies exactly one allowed producer. Companion producers
            # listed for extension hardening are enforced from live producer
            # bytes, not from a missing checkout copy.
            continue
        producer_file = freeze.secure_repo_path(
            repo,
            pathlib.Path(producer_id),
            f"{target_id} {gate_id} gate producer",
            must_exist=True,
        )
        for index, part in enumerate(argv):
            candidate = pathlib.Path(part)
            if not candidate.is_absolute():
                candidate = repo / candidate
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if resolved == producer_file.resolve(strict=True):
                matches.append((producer_id, producer_file, index))
    if len(matches) != 1:
        raise UploadReadinessError(
            f"{target_id} {gate_id} argv must identify exactly one allowed producer."
        )
    producer_id, producer_file, producer_arg_index = matches[0]
    direct_execution = producer_arg_index == 0
    python_name_allowed = re.fullmatch(
        r"python(?:\d+(?:\.\d+)*)?(?:\.exe)?", executable
    ) is not None
    try:
        exact_python = _python_interpreter_identity(
            pathlib.Path(argv[0])
        ) == _python_interpreter_identity(pathlib.Path(sys.executable))
    except UploadReadinessError:
        exact_python = False
    python_execution = (
        producer_arg_index == 1
        and python_name_allowed
        and exact_python
        and not ({"-c", "-m"} & eval_flags)
    )
    script_shell_execution = (
        producer_arg_index == 3
        and pathlib.Path(argv[0]) == pathlib.Path("/bin/bash")
        and argv[1:3] == ("--noprofile", "--norc")
    )
    powershell_file_execution = (
        producer_arg_index == 4
        and executable
        in {"powershell.exe", "pwsh", "pwsh.exe"}
        and tuple(part.lower() for part in argv[1:4])
        == ("-noprofile", "-noninteractive", "-file")
    )
    if not (
        direct_execution
        or python_execution
        or script_shell_execution
        or powershell_file_execution
    ):
        raise UploadReadinessError(
            f"{target_id} {gate_id} argv does not execute the bound producer."
        )
    artifact_path = freeze.secure_repo_path(
        repo,
        artifact_path,
        f"{target_id} {gate_id} command artifact",
        must_exist=True,
    )
    canonical_artifact = freeze._relative_repo_path(repo, artifact_path)
    expected_suffix = ("--verify", target_id, canonical_artifact)
    if (
        argv[producer_arg_index] != producer_id
        or argv[producer_arg_index + 1 :] != expected_suffix
    ):
        raise UploadReadinessError(
            f"{target_id} {gate_id} argv is not bound to the exact target and artifact."
        )
    return argv, producer_id, producer_file, producer_arg_index


def execute_target_gate_transaction(
    repo: pathlib.Path,
    target_id: str,
    artifact_path: pathlib.Path,
    commands: Mapping[str, Sequence[str]],
    evidence_dir: pathlib.Path,
    *,
    runner: gate_runner.ExplicitArgvRunner | None = None,
    clock: Callable[[], dt.datetime] | None = None,
) -> dict[str, dict[str, object]]:
    """Execute and record the exact ordered gate pair for one upload target."""

    repo = freeze.secure_repo_path(
        repo, pathlib.Path("."), "Repository root", must_exist=True
    )
    if target_id not in TARGET_BY_ID:
        raise UploadReadinessError(f"Unexpected upload target: {target_id}")
    target = TARGET_BY_ID[target_id]
    ordered_gates = (target.signing_gate_id, target.hardening_gate_id)
    if set(commands) != set(ordered_gates) or len(commands) != LOCAL_GATE_COMMAND_COUNT:
        raise UploadReadinessError(
            f"{target_id} requires exactly its signing and hardening gate commands."
        )
    artifact_path = freeze.secure_repo_path(
        repo, artifact_path, f"{target_id} gate artifact", must_exist=True
    )
    evidence_dir = freeze.secure_repo_path(
        repo, evidence_dir, f"{target_id} gate evidence directory", must_exist=False
    )
    if evidence_dir.relative_to(repo).parts[0] != ".artifacts":
        raise UploadReadinessError(
            f"{target_id} gate evidence must stay under .artifacts/."
        )
    evidence_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    evidence_dir = freeze.secure_repo_path(
        repo,
        evidence_dir,
        f"{target_id} gate evidence directory",
        must_exist=True,
    )
    evidence_info = evidence_dir.lstat()
    if (
        not stat.S_ISDIR(evidence_info.st_mode)
        or stat.S_IMODE(evidence_info.st_mode) != 0o700
        or (hasattr(os, "getuid") and evidence_info.st_uid != os.getuid())
    ):
        raise UploadReadinessError(
            f"{target_id} gate evidence directory must be owner-controlled mode 0700."
        )
    _reject_caller_supplied_runner(runner)
    now = clock or (lambda: dt.datetime.now(tz=dt.timezone.utc))
    transaction_id = str(uuid.uuid4())
    prior_evidence_sha256: str | None = None
    prior_ended: dt.datetime | None = None
    references: dict[str, dict[str, object]] = {}
    pending_evidence: list[
        tuple[str, str, str, pathlib.Path, dict[str, object], str]
    ] = []
    failed_gate: tuple[str, int] | None = None
    live_artifact = _artifact_execution_snapshot(repo, artifact_path, target_id)
    try:
        with _sealed_production_gate_runner() as bound:
            production_pass_allowed = runner is None
            process_runner = bound.runner if production_pass_allowed else runner
            with gate_runner.ExactArtifactSnapshot(
                source_path=artifact_path,
                cwd=repo,
                expected_sha256=str(live_artifact["sha256"]),
            ) as artifact_snap:
                for order, gate_id in enumerate(ordered_gates):
                    argv, producer_id, producer_file, producer_arg_index = (
                        _validate_gate_argv(
                            repo, target_id, gate_id, artifact_path, commands[gate_id]
                        )
                    )
                    producer_sha256 = freeze._sha256_file(producer_file)
                    artifact_before = _artifact_execution_snapshot(
                        repo, artifact_path, target_id
                    )
                    if (
                        artifact_before["sha256"] != live_artifact["sha256"]
                        or artifact_before["bytes"] != live_artifact["bytes"]
                        or artifact_before["path"] != live_artifact["path"]
                    ):
                        raise UploadReadinessError(
                            f"{target_id} gate artifact identity changed before execution."
                        )
                    started = now()
                    if prior_ended is not None and started < prior_ended:
                        raise UploadReadinessError(
                            f"{target_id} gate commands did not start in canonical order."
                        )
                    boundary = gate_runner.ExactProducerExecution(
                        requested_argv=argv,
                        cwd=repo,
                        producer_arg_index=producer_arg_index,
                        producer_path=producer_file,
                        expected_sha256=producer_sha256,
                    )
                    artifact_arg_index = producer_arg_index + _GATE_ARTIFACT_ARG_OFFSET
                    try:
                        with boundary as exact_execution:
                            if artifact_arg_index >= len(exact_execution.executed_argv):
                                raise UploadReadinessError(
                                    f"{target_id} {gate_id} argv is missing the bound artifact."
                                )
                            executed = list(exact_execution.executed_argv)
                            executed[artifact_arg_index] = (
                                artifact_snap.executed_artifact_arg(
                                    argv[artifact_arg_index]
                                )
                            )
                            executed_argv = tuple(executed)
                            result = process_runner.run(executed_argv, cwd=repo)
                    except UploadReadinessError:
                        raise
                    except Exception as exc:
                        raise UploadReadinessError(
                            f"{target_id} {gate_id} gate process did not execute: {exc}"
                        ) from exc
                    try:
                        artifact_custody = artifact_snap.verify_execution_boundary()
                    except gate_runner.ExactSnapshotError as exc:
                        raise UploadReadinessError(
                            f"{target_id} {gate_id} mutated the artifact execution "
                            f"boundary: {exc}"
                        ) from exc
                    ended = now()
                    if ended < started:
                        raise UploadReadinessError(
                            f"{target_id} {gate_id} runner clock moved backwards."
                        )
                    stdout_sha256, stderr_sha256 = _revalidate_gate_process_fields(
                        result,
                        executed_argv,
                        target_id,
                        gate_id,
                        expected_result_type=(
                            bound.result_type if production_pass_allowed else None
                        ),
                        expected_environment=(
                            bound.runner_class.ENVIRONMENT_OVERRIDES
                            if production_pass_allowed
                            else None
                        ),
                    )
                    if production_pass_allowed:
                        _revalidate_sealed_production_runner(
                            bound, process_runner, result
                        )
                        if (
                            getattr(result, "runner_id", None)
                            != bound.runner_class.RUNNER_ID
                        ):
                            raise UploadReadinessError(
                                f"{target_id} {gate_id} runner did not prove exact "
                                "shell-disabled execution."
                            )
                    artifact_after = _artifact_execution_snapshot(
                        repo, artifact_path, target_id
                    )
                    if artifact_after != artifact_before:
                        raise UploadReadinessError(
                            f"{target_id} {gate_id} mutated the artifact during verification."
                        )
                    snapshot_size, _, snapshot_digest = _stable_identity(
                        artifact_snap.snapshot_path,
                        f"{target_id} {gate_id} artifact snapshot",
                    )
                    if (
                        snapshot_digest != live_artifact["sha256"]
                        or snapshot_size != live_artifact["bytes"]
                    ):
                        raise UploadReadinessError(
                            f"{target_id} {gate_id} artifact snapshot is not the bound identity."
                        )
                    if (
                        target.platform == "extension"
                        and gate_id == target.hardening_gate_id
                    ):
                        verify_extension_cross_store_hardening(
                            target_id,
                            artifact_snap.snapshot_path,
                            expected_sha256=str(live_artifact["sha256"]),
                        )
                        snapshot_size_after, _, snapshot_digest_after = _stable_identity(
                            artifact_snap.snapshot_path,
                            f"{target_id} {gate_id} artifact snapshot",
                        )
                        if (
                            snapshot_digest_after != live_artifact["sha256"]
                            or snapshot_size_after != live_artifact["bytes"]
                        ):
                            raise UploadReadinessError(
                                f"{target_id} {gate_id} artifact snapshot changed after hardening."
                            )
                        try:
                            artifact_custody = (
                                artifact_snap.verify_execution_boundary()
                            )
                        except gate_runner.ExactSnapshotError as exc:
                            raise UploadReadinessError(
                                f"{target_id} {gate_id} mutated the artifact execution "
                                f"boundary after hardening: {exc}"
                            ) from exc
                    if not production_pass_allowed:
                        if result.exit_code == 0:
                            raise UploadReadinessError(
                                f"{target_id} {gate_id} test-only runner cannot emit "
                                "accepted production PASS"
                            )
                        raise UploadReadinessError(
                            f"{target_id} {gate_id} gate exited with {result.exit_code}."
                        )
                    started_utc = _utc_timestamp(started)
                    ended_utc = _utc_timestamp(ended)
                    command_sha256 = _command_identity(
                        target_id,
                        gate_id,
                        order,
                        argv,
                        producer_id,
                        producer_sha256,
                    )
                    status = "passed" if result.exit_code == 0 else "failed"
                    evidence = {
                        "schema_version": LOCAL_GATE_EVIDENCE_SCHEMA_VERSION,
                        "contract": LOCAL_GATE_EVIDENCE_CONTRACT,
                        "transaction_id": transaction_id,
                        "target_id": target_id,
                        "gate_id": gate_id,
                        "command_order": order,
                        "command_count": LOCAL_GATE_COMMAND_COUNT,
                        "previous_evidence_sha256": prior_evidence_sha256,
                        "command": {
                            "argv": list(argv),
                            "executed_argv": list(executed_argv),
                            "identity_sha256": command_sha256,
                            "producer_arg_index": producer_arg_index,
                        },
                        "producer": {"path": producer_id, "sha256": producer_sha256},
                        "runner": {
                            "id": bound.runner_class.RUNNER_ID,
                            "executed": True,
                            "shell_enabled": False,
                            "environment_overrides": dict(
                                bound.runner_class.ENVIRONMENT_OVERRIDES
                            ),
                            "controller_path": PRODUCTION_GATE_CONTROLLER,
                            "controller_sha256": bound.controller_sha256,
                            "production_pass_allowed": True,
                            "exact_byte_execution": boundary.evidence(),
                        },
                        "started_utc": started_utc,
                        "ended_utc": ended_utc,
                        "exit_code": result.exit_code,
                        "status": status,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "stdout_sha256": stdout_sha256,
                        "stderr_sha256": stderr_sha256,
                        "artifact_before": artifact_before,
                        "artifact_after": artifact_after,
                        "artifact_custody": artifact_custody,
                        "publication_authorized": False,
                        "upload_attempted": False,
                    }
                    evidence_path = evidence_dir / f"{target_id}-{order:02d}-{gate_id}.json"
                    evidence_sha256 = hashlib.sha256(
                        freeze._canonical_json(evidence)
                    ).hexdigest()
                    pending_evidence.append(
                        (
                            gate_id,
                            status,
                            ended_utc,
                            evidence_path,
                            evidence,
                            evidence_sha256,
                        )
                    )
                    prior_evidence_sha256 = evidence_sha256
                    prior_ended = ended
                    if status != "passed":
                        failed_gate = (gate_id, result.exit_code)
                        break
            for (
                gate_id,
                status,
                ended_utc,
                evidence_path,
                evidence,
                expected_evidence_sha256,
            ) in pending_evidence:
                freeze._write_anchored_record(
                    repo,
                    evidence_path,
                    evidence,
                    f"{target_id} {gate_id} executed gate",
                )
                try:
                    evidence_mode = stat.S_IMODE(evidence_path.lstat().st_mode)
                    anchor_mode = stat.S_IMODE(
                        evidence_path.with_name(
                            evidence_path.name + ".sha256"
                        ).lstat().st_mode
                    )
                except OSError as exc:
                    raise UploadReadinessError(
                        f"{target_id} {gate_id} evidence custody became unavailable."
                    ) from exc
                if evidence_mode != 0o400 or anchor_mode != 0o400:
                    raise UploadReadinessError(
                        f"{target_id} {gate_id} evidence custody mode is invalid."
                    )
                evidence_sha256 = freeze._sha256_file(evidence_path)
                if evidence_sha256 != expected_evidence_sha256:
                    raise UploadReadinessError(
                        f"{target_id} {gate_id} evidence changed during publication."
                    )
                references[gate_id] = {
                    "id": gate_id,
                    "status": status,
                    "executed_utc": ended_utc,
                    "evidence_path": freeze._relative_repo_path(repo, evidence_path),
                    "evidence_sha256": evidence_sha256,
                }
            if failed_gate is not None:
                failed_gate_id, failed_exit_code = failed_gate
                raise UploadReadinessError(
                    f"{target_id} {failed_gate_id} gate exited with "
                    f"{failed_exit_code}."
                )
    except (
        gate_runner.ExactSnapshotError,
        gate_runner.ExactProducerExecutionError,
    ) as exc:
        raise UploadReadinessError(
            f"{target_id} artifact snapshot execution failed: {exc}"
        ) from exc
    return references


def _safe_time(value: object, label: str) -> dt.datetime:
    try:
        return freeze._parse_timestamp(value, label)
    except freeze.DependencyFreezeError as exc:
        raise UploadReadinessError(str(exc)) from exc


def _verify_manifest_build_receipt(
    repo: pathlib.Path,
    target: UploadTarget,
    receipt_path: pathlib.Path,
    artifact_path: pathlib.Path,
) -> dict[str, object]:
    verifier_id = target.manifest_verifier_path
    if verifier_id is None or target.producer_ids != (verifier_id,):
        raise UploadReadinessError(
            f"{target.target_id} manifest verifier contract is incomplete."
        )
    verifier = freeze.secure_repo_path(
        repo,
        pathlib.Path(verifier_id),
        f"{target.target_id} manifest verifier",
        must_exist=True,
    )
    module_name = "winsvpn_manifest_" + re.sub(r"[^a-z0-9]", "_", target.target_id)
    spec = importlib.util.spec_from_file_location(module_name, verifier)
    if spec is None or spec.loader is None:
        raise UploadReadinessError(
            f"{target.target_id} manifest verifier cannot be loaded."
        )
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        if getattr(module, "TEST_ONLY", False) is True:
            allowed = getattr(module, "production_pass_allowed", None)
            if not callable(allowed) or allowed() is not False:
                raise UploadReadinessError(
                    f"{target.target_id} test-only manifest verifier cannot emit "
                    "production PASS."
                )
        verify_receipt = getattr(module, "verify_receipt")
        result = verify_receipt(repo, receipt_path, artifact_path)
    except UploadReadinessError:
        raise
    except Exception as exc:
        raise UploadReadinessError(
            f"{target.target_id} manifest receipt verification failed: {exc}"
        ) from exc
    if not isinstance(result, dict):
        raise UploadReadinessError(
            f"{target.target_id} manifest verifier returned malformed evidence."
        )
    producer = result.get("producer")
    if (
        result.get("ok") is not True
        or result.get("target") != target.target_id
        or result.get("verification_network_accessed") is not False
        or result.get("publication_authorized") is not False
        or result.get("upload_attempted") is not False
        or producer
        != {"path": verifier_id, "sha256": freeze._sha256_file(verifier)}
    ):
        raise UploadReadinessError(
            f"{target.target_id} manifest verifier binding is invalid."
        )
    return result


def _verify_gate_evidence(
    repo: pathlib.Path,
    target: UploadTarget,
    gate_value: object,
    expected_gate_id: str,
    artifact_binding: dict[str, object],
    artifact_time: dt.datetime,
    verified_at: dt.datetime,
) -> dict[str, object]:
    gate = _exact(
        gate_value,
        {"id", "status", "executed_utc", "evidence_path", "evidence_sha256"},
        f"{target.target_id} {expected_gate_id} gate",
    )
    if gate.get("id") != expected_gate_id or gate.get("status") != "passed":
        raise UploadReadinessError(
            f"{target.target_id} {expected_gate_id} gate did not pass."
        )
    executed = _safe_time(
        gate.get("executed_utc"),
        f"{target.target_id} {expected_gate_id} execution",
    )
    if (
        executed > verified_at
        or executed + MAX_CLOCK_SKEW < artifact_time
        or verified_at - executed > MAX_RECEIPT_AGE
    ):
        raise UploadReadinessError(
            f"{target.target_id} {expected_gate_id} gate evidence is stale "
            "or future-dated."
        )
    evidence_path = freeze.secure_repo_path(
        repo,
        pathlib.Path(str(gate.get("evidence_path"))),
        f"{target.target_id} {expected_gate_id} evidence",
        must_exist=True,
    )
    if evidence_path.relative_to(repo).parts[0] != ".artifacts":
        raise UploadReadinessError(
            f"{target.target_id} gate evidence must stay under .artifacts/."
        )
    _, _, evidence_sha = _stable_identity(
        evidence_path, f"{target.target_id} {expected_gate_id} evidence"
    )
    if gate.get("evidence_sha256") != evidence_sha:
        raise UploadReadinessError(
            f"{target.target_id} {expected_gate_id} evidence hash changed."
        )
    freeze._verify_anchor(repo, evidence_path, f"{target.target_id} gate evidence")
    evidence = _exact(
        _load_json(evidence_path, f"{target.target_id} {expected_gate_id} evidence"),
        set(LOCAL_GATE_EVIDENCE_KEYS),
        f"{target.target_id} {expected_gate_id} evidence",
    )
    artifact_before = _exact(
        evidence.get("artifact_before"),
        {
            "path",
            "sha256",
            "bytes",
            "device",
            "inode",
            "mode",
            "mtime_ns",
            "ctime_ns",
        },
        f"{target.target_id} gate artifact before",
    )
    artifact_after = _exact(
        evidence.get("artifact_after"),
        {
            "path",
            "sha256",
            "bytes",
            "device",
            "inode",
            "mode",
            "mtime_ns",
            "ctime_ns",
        },
        f"{target.target_id} gate artifact after",
    )
    artifact_custody, expected_artifact_execution = (
        _verify_artifact_custody_evidence(
            repo,
            target.target_id,
            evidence.get("artifact_custody"),
            artifact_binding,
            artifact_before,
            artifact_after,
        )
    )
    producer = _exact(
        evidence.get("producer"),
        {"path", "sha256"},
        f"{target.target_id} gate producer",
    )
    command = _exact(
        evidence.get("command"),
        {"argv", "executed_argv", "identity_sha256", "producer_arg_index"},
        f"{target.target_id} gate command",
    )
    runner = _exact(
        evidence.get("runner"),
        {
            "id",
            "executed",
            "shell_enabled",
            "environment_overrides",
            "controller_path",
            "controller_sha256",
            "production_pass_allowed",
            "exact_byte_execution",
        },
        f"{target.target_id} gate runner",
    )
    producer_path = str(producer.get("path"))
    if producer_path not in GATE_PRODUCER_IDS[expected_gate_id]:
        raise UploadReadinessError(
            f"{target.target_id} {expected_gate_id} gate producer is not allowed."
        )
    producer_file = freeze.secure_repo_path(
        repo,
        pathlib.Path(producer_path),
        f"{target.target_id} gate producer",
        must_exist=True,
    )
    argv, command_producer, command_producer_file, producer_arg_index = (
        _validate_gate_argv(
            repo,
            target.target_id,
            expected_gate_id,
            pathlib.Path(str(artifact_binding["path"])),
            command.get("argv"),
        )
    )
    executed_argv_raw = command.get("executed_argv")
    if (
        not isinstance(executed_argv_raw, list)
        or any(not isinstance(part, str) for part in executed_argv_raw)
    ):
        raise UploadReadinessError(
            f"{target.target_id} {expected_gate_id} executed argv is invalid."
        )
    executed_argv = tuple(executed_argv_raw)
    producer_sha256 = str(producer.get("sha256"))
    if re.fullmatch(r"[0-9a-f]{64}", producer_sha256) is None:
        raise UploadReadinessError(
            f"{target.target_id} {expected_gate_id} producer hash is invalid."
        )
    expected_snapshot = gate_runner.snapshot_path_for(
        command_producer_file, producer_sha256
    )
    expected_snapshot_arg = (
        str(expected_snapshot)
        if pathlib.Path(argv[producer_arg_index]).is_absolute()
        else expected_snapshot.relative_to(repo).as_posix()
    )
    expected_executed_argv_list = list(argv)
    expected_executed_argv_list[producer_arg_index] = expected_snapshot_arg
    artifact_arg_index = producer_arg_index + _GATE_ARTIFACT_ARG_OFFSET
    if artifact_arg_index >= len(expected_executed_argv_list):
        raise UploadReadinessError(
            f"{target.target_id} {expected_gate_id} argv is missing the bound artifact."
        )
    expected_artifact_arg = (
        str(expected_artifact_execution)
        if pathlib.Path(argv[artifact_arg_index]).is_absolute()
        else expected_artifact_execution.relative_to(repo).as_posix()
    )
    expected_executed_argv_list[artifact_arg_index] = expected_artifact_arg
    expected_executed_argv = tuple(expected_executed_argv_list)
    exact_byte_execution = _exact(
        runner.get("exact_byte_execution"),
        {
            "snapshot_path",
            "snapshot_sha256",
            "hardlink_same_inode",
            "producer_identity_before",
            "producer_identity_after",
            "snapshot_identity_before",
            "snapshot_identity_after",
            "parent_identity_before",
            "parent_identity_after",
            "cleanup_complete",
        },
        f"{target.target_id} {expected_gate_id} exact-byte execution",
    )
    started = _safe_time(
        evidence.get("started_utc"),
        f"{target.target_id} {expected_gate_id} start",
    )
    ended = _safe_time(
        evidence.get("ended_utc"),
        f"{target.target_id} {expected_gate_id} end",
    )
    stdout = evidence.get("stdout")
    stderr = evidence.get("stderr")
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        raise UploadReadinessError(
            f"{target.target_id} {expected_gate_id} raw process output is invalid."
        )
    current_artifact = _artifact_execution_snapshot(
        repo, pathlib.Path(str(artifact_binding["path"])), target.target_id
    )
    snapshot_binding = {
        key: artifact_before.get(key) for key in ("path", "sha256", "bytes")
    }
    order = evidence.get("command_order")
    exit_code = evidence.get("exit_code")
    recorded_producer_arg_index = command.get("producer_arg_index")
    command_identity = _command_identity(
        target.target_id,
        expected_gate_id,
        order if isinstance(order, int) and not isinstance(order, bool) else -1,
        argv,
        producer_path,
        str(producer.get("sha256")),
    )
    if (
        type(evidence.get("schema_version")) is not int
        or evidence.get("schema_version") != LOCAL_GATE_EVIDENCE_SCHEMA_VERSION
        or evidence.get("contract") != LOCAL_GATE_EVIDENCE_CONTRACT
        or not isinstance(evidence.get("transaction_id"), str)
        or not evidence.get("transaction_id")
        or evidence.get("target_id") != target.target_id
        or evidence.get("gate_id") != expected_gate_id
        or not isinstance(order, int)
        or isinstance(order, bool)
        or evidence.get("command_count") != LOCAL_GATE_COMMAND_COUNT
        or evidence.get("ended_utc") != gate.get("executed_utc")
        or started > ended
        or started + MAX_CLOCK_SKEW < artifact_time
        or ended > verified_at
        or ended != executed
        or not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
        or exit_code != 0
        or evidence.get("status")
        != ("passed" if exit_code == 0 else "failed")
        or runner.get("executed") is not True
        or runner.get("shell_enabled") is not False
        or runner.get("environment_overrides")
        != dict(gate_runner.SubprocessExplicitArgvRunner.ENVIRONMENT_OVERRIDES)
        or runner.get("id")
        != gate_runner.SubprocessExplicitArgvRunner.RUNNER_ID
        or runner.get("controller_path") != PRODUCTION_GATE_CONTROLLER
        or runner.get("controller_sha256") != _live_production_controller_digest()
        or runner.get("production_pass_allowed") is not True
        or executed_argv != expected_executed_argv
        or exact_byte_execution.get("snapshot_path")
        != expected_snapshot.relative_to(repo).as_posix()
        or exact_byte_execution.get("snapshot_sha256") != producer_sha256
        or exact_byte_execution.get("hardlink_same_inode") is not True
        or exact_byte_execution.get("cleanup_complete") is not True
        or not _valid_stat_identity(
            exact_byte_execution.get("producer_identity_before"), 7
        )
        or not _valid_stat_identity(
            exact_byte_execution.get("producer_identity_after"), 7
        )
        or not _valid_stat_identity(
            exact_byte_execution.get("snapshot_identity_before"), 7
        )
        or not _valid_stat_identity(
            exact_byte_execution.get("snapshot_identity_after"), 7
        )
        or not _valid_stat_identity(
            exact_byte_execution.get("parent_identity_before"), 6
        )
        or not _valid_stat_identity(
            exact_byte_execution.get("parent_identity_after"), 6
        )
        or exact_byte_execution.get("producer_identity_before")
        != exact_byte_execution.get("producer_identity_after")
        or exact_byte_execution.get("snapshot_identity_before")
        != exact_byte_execution.get("snapshot_identity_after")
        or exact_byte_execution.get("producer_identity_before")
        != exact_byte_execution.get("snapshot_identity_before")
        or exact_byte_execution.get("parent_identity_before")
        != exact_byte_execution.get("parent_identity_after")
        or artifact_before != artifact_after
        or artifact_after != current_artifact
        or snapshot_binding != artifact_binding
        or command_producer != producer_path
        or command_producer_file != producer_file
        or not isinstance(recorded_producer_arg_index, int)
        or isinstance(recorded_producer_arg_index, bool)
        or recorded_producer_arg_index != producer_arg_index
        or command.get("identity_sha256") != command_identity
        or producer.get("sha256") != freeze._sha256_file(producer_file)
        or evidence.get("stdout_sha256")
        != hashlib.sha256(stdout.encode("utf-8")).hexdigest()
        or evidence.get("stderr_sha256")
        != hashlib.sha256(stderr.encode("utf-8")).hexdigest()
        or evidence.get("publication_authorized") is not False
        or evidence.get("upload_attempted") is not False
    ):
        raise UploadReadinessError(
            f"{target.target_id} {expected_gate_id} evidence binding is invalid."
        )
    return {
        "id": expected_gate_id,
        "executed_utc": gate.get("executed_utc"),
        "started_utc": evidence.get("started_utc"),
        "ended_utc": evidence.get("ended_utc"),
        "transaction_id": evidence.get("transaction_id"),
        "command_order": order,
        "command_identity_sha256": command_identity,
        "previous_evidence_sha256": evidence.get("previous_evidence_sha256"),
        "evidence_path": freeze._relative_repo_path(repo, evidence_path),
        "evidence_sha256": evidence_sha,
    }


def _execution_request_from_receipt(
    repo: pathlib.Path,
    target: UploadTarget,
    receipt_path: pathlib.Path,
) -> tuple[pathlib.Path, dict[str, tuple[str, ...]]]:
    """Read only argv requests from a receipt; never trust its claimed outcome."""

    receipt_path = freeze.secure_repo_path(
        repo,
        receipt_path,
        f"{target.target_id} upload receipt execution request",
        must_exist=True,
    )
    receipt = _load_json(receipt_path, f"{target.target_id} upload receipt")
    artifact = _exact(
        receipt.get("artifact"),
        {"path", "sha256", "bytes"},
        f"{target.target_id} execution request artifact",
    )
    artifact_path = freeze.secure_repo_path(
        repo,
        pathlib.Path(str(artifact.get("path"))),
        f"{target.target_id} execution request artifact",
        must_exist=True,
    )
    commands: dict[str, tuple[str, ...]] = {}
    fields = (
        ("signing_verification_gate", target.signing_gate_id),
        ("obfuscation_privacy_gate", target.hardening_gate_id),
    )
    for field, gate_id in fields:
        reference = _exact(
            receipt.get(field),
            {"id", "status", "executed_utc", "evidence_path", "evidence_sha256"},
            f"{target.target_id} {gate_id} execution request reference",
        )
        evidence_path = freeze.secure_repo_path(
            repo,
            pathlib.Path(str(reference.get("evidence_path"))),
            f"{target.target_id} {gate_id} execution request evidence",
            must_exist=True,
        )
        if evidence_path.relative_to(repo).parts[0] != ".artifacts":
            raise UploadReadinessError(
                f"{target.target_id} gate request evidence must stay under .artifacts/."
            )
        _, _, evidence_sha256 = _stable_identity(
            evidence_path, f"{target.target_id} {gate_id} execution request"
        )
        if evidence_sha256 != reference.get("evidence_sha256"):
            raise UploadReadinessError(
                f"{target.target_id} {gate_id} execution request hash changed."
            )
        freeze._verify_anchor(
            repo, evidence_path, f"{target.target_id} gate execution request"
        )
        evidence = _exact(
            _load_json(evidence_path, f"{target.target_id} {gate_id} request"),
            set(LOCAL_GATE_EVIDENCE_KEYS),
            f"{target.target_id} {gate_id} execution request",
        )
        command = _exact(
            evidence.get("command"),
            {"argv", "executed_argv", "identity_sha256", "producer_arg_index"},
            f"{target.target_id} {gate_id} execution request command",
        )
        if (
            type(evidence.get("schema_version")) is not int
            or evidence.get("schema_version") != LOCAL_GATE_EVIDENCE_SCHEMA_VERSION
            or evidence.get("contract") != LOCAL_GATE_EVIDENCE_CONTRACT
            or evidence.get("target_id") != target.target_id
            or evidence.get("gate_id") != gate_id
        ):
            raise UploadReadinessError(
                f"{target.target_id} {gate_id} execution request binding is invalid."
            )
        argv, _, _, _ = _validate_gate_argv(
            repo,
            target.target_id,
            gate_id,
            artifact_path,
            command.get("argv"),
        )
        commands[gate_id] = argv
    return artifact_path, commands


def _target_receipt_keys(target: UploadTarget) -> set[str]:
    if target.platform == "extension":
        return set(EXTENSION_TARGET_RECEIPT_KEYS)
    return set(TARGET_RECEIPT_BASE_KEYS)


def _recorded_target_receipt_keys(target: UploadTarget) -> set[str]:
    keys = {
        "receipt_path",
        "receipt_sha256",
        "release",
        "build_receipt",
        "artifact",
        "producer_id",
        "signing_verification_gate",
        "obfuscation_privacy_gate",
        "dependency_source_freeze",
        "verified_utc",
    }
    if target.platform == "extension":
        keys.add("verifier_source_closure")
    return keys


def _same_bound_path(value: object, expected: pathlib.Path) -> bool:
    if not isinstance(value, str) or not value:
        return False
    actual = pathlib.Path(value)
    return actual == expected or os.path.abspath(actual) == os.path.abspath(expected)


def _exclusive_extension_source_snapshot(
    repo: pathlib.Path,
    relative: str,
    label: str,
) -> tuple[pathlib.Path, pathlib.Path, str, int]:
    original = freeze.secure_repo_path(
        repo, pathlib.Path(relative), label, must_exist=True
    )
    size, _, digest = _stable_identity(original, label)
    snapshot = gate_runner.extension_source_snapshot_path_for(original, digest)
    if os.path.lexists(snapshot):
        raise UploadReadinessError(
            f"{label} snapshot collision or concurrent execution detected."
        )
    try:
        copied = gate_runner.exclusive_copy_file(original, snapshot)
        snap_size, _, snap_digest = _stable_identity(snapshot, f"{label} snapshot")
        after_size, _, after_digest = _stable_identity(original, label)
    except Exception:
        try:
            os.unlink(snapshot)
        except OSError:
            pass
        raise
    if (
        copied != digest
        or snap_digest != digest
        or after_digest != digest
        or snap_size != size
        or after_size != size
    ):
        try:
            os.unlink(snapshot)
        except OSError:
            pass
        raise UploadReadinessError(f"{label} snapshot is not the exact bound bytes.")
    return original, snapshot, digest, size


def _exec_private_snapshot_module(
    role: str,
    snapshot_path: pathlib.Path,
    digest: str,
):
    module_name = f"winsvpn_ext_receipt_{role}_{digest}"
    if module_name in sys.modules:
        raise UploadReadinessError(
            f"extension {role} private module identity collided."
        )
    spec = importlib.util.spec_from_file_location(module_name, snapshot_path)
    if spec is None or spec.loader is None:
        raise UploadReadinessError(f"extension {role} snapshot cannot be loaded.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(module_name, None)
        raise UploadReadinessError(
            f"extension {role} snapshot failed to load: {exc}"
        ) from exc
    if (
        sys.modules.get(module_name) is not module
        or getattr(module, "__name__", None) != module_name
        or spec.name != module_name
        or not _same_bound_path(getattr(module, "__file__", None), snapshot_path)
        or not _same_bound_path(spec.origin, snapshot_path)
    ):
        sys.modules.pop(module_name, None)
        raise UploadReadinessError(
            f"extension {role} snapshot origin is not the bound private identity."
        )
    return module, module_name


def _unlink_extension_snapshots(paths: Sequence[pathlib.Path]) -> None:
    leftover = False
    for snapshot in paths:
        try:
            os.unlink(snapshot)
        except FileNotFoundError:
            continue
        except OSError:
            leftover = True
            continue
        if os.path.lexists(snapshot):
            leftover = True
    if leftover:
        raise UploadReadinessError(
            "extension verifier snapshot cleanup did not remove execution paths."
        )


@contextlib.contextmanager
def _bound_extension_builder(repo: pathlib.Path):
    """Load the exact bound extension verifier bytes under private identities.

    This binds the helpers inside the caller's own interpreter, so it can only
    detect changes to state the helpers own. The production verification path
    (`verify_extension_zip_artifact`) does not use it: it runs the same pinned
    bytes in a fresh interpreter through `_isolated_extension_verification`,
    which no code in the caller's process can reach.
    """

    repo = freeze.secure_repo_path(
        repo, pathlib.Path("."), "Repository root", must_exist=True
    )
    saved_path = list(sys.path)
    previous_dont_write = sys.dont_write_bytecode
    saved_public = {
        name: sys.modules.get(name, _MISSING_SYS_MODULE)
        for name in _EXTENSION_PUBLIC_HELPER_NAMES
    }
    snapshots: list[pathlib.Path] = []
    private_names: list[str] = []
    modules: dict[str, object] = {}
    snapshot_digest_by_role: dict[str, tuple[pathlib.Path, str]] = {}
    bound_closure: dict[str, object] | None = None
    bound_verify_existing_package: Callable[..., object] | None = None
    bound_module_bindings: dict[tuple[str, str], tuple[object, ...]] | None = None
    sys.dont_write_bytecode = True
    caught: BaseException | None = None
    try:
        for public in _EXTENSION_PUBLIC_HELPER_NAMES:
            sys.modules.pop(public, None)
        for role, relative in _EXTENSION_RUNTIME_PYTHON_SOURCES:
            _original, snapshot, digest, _size = _exclusive_extension_source_snapshot(
                repo,
                relative,
                f"extension verifier source {relative}",
            )
            snapshots.append(snapshot)
            snapshot_digest_by_role[role] = (snapshot, digest)
            module, module_name = _exec_private_snapshot_module(
                role, snapshot, digest
            )
            private_names.append(module_name)
            modules[role] = module
            if role in _EXTENSION_PUBLIC_HELPER_NAMES:
                sys.modules[role] = module
        sys.path[:] = saved_path
        builder = modules["builder"]
        store_version_mod = modules["store_version"]
        jsonc_mod = modules["jsonc"]
        checks_mod = modules["checks"]
        leakscan_mod = modules["leakscan"]
        minifier_mod = modules["store_js_minifier"]
        if (
            tuple(getattr(builder, "VERIFIER_SOURCE_PATHS", ()) or ())
            != EXTENSION_VERIFIER_SOURCE_PATHS
            or not callable(getattr(builder, "verify_existing_package", None))
            or getattr(builder, "jsonc", None) is not jsonc_mod
            or getattr(builder, "checks", None) is not checks_mod
            or getattr(builder, "leakscan", None) is not leakscan_mod
            or getattr(builder, "store_js_minifier", None) is not minifier_mod
            or getattr(checks_mod, "jsonc", None) is not jsonc_mod
            or getattr(builder, "read_pubspec_manifest_version", None)
            is not getattr(store_version_mod, "read_pubspec_manifest_version", object())
            or getattr(checks_mod, "read_pubspec_manifest_version", None)
            is not getattr(store_version_mod, "read_pubspec_manifest_version", object())
        ):
            raise UploadReadinessError(
                "extension verify-only producer is not bound to the "
                "authenticated helper snapshots."
            )
        bound_verify_existing_package = builder.verify_existing_package
        bound_module_bindings = _extension_module_bindings(modules)
        bound_closure = extension_verifier_source_closure(repo)
        try:
            yield builder
        except BaseException as exc:
            caught = exc
            raise
        _reverify_bound_extension_execution(
            repo,
            modules,
            snapshot_digest_by_role,
            bound_closure,
            bound_verify_existing_package,
            bound_module_bindings,
        )
    except gate_runner.ExactSnapshotError as exc:
        raise UploadReadinessError(
            f"extension verifier snapshot failed: {exc}"
        ) from exc
    finally:
        reverify_error: BaseException | None = None
        if caught is not None and bound_closure is not None and modules:
            try:
                _reverify_bound_extension_execution(
                    repo,
                    modules,
                    snapshot_digest_by_role,
                    bound_closure,
                    bound_verify_existing_package,
                    bound_module_bindings,
                )
            except BaseException as exc:
                reverify_error = exc
        sys.dont_write_bytecode = previous_dont_write
        sys.path[:] = saved_path
        for public, original in saved_public.items():
            if original is _MISSING_SYS_MODULE:
                current = sys.modules.get(public)
                if current is modules.get(public):
                    sys.modules.pop(public, None)
            else:
                sys.modules[public] = original
        for name in private_names:
            sys.modules.pop(name, None)
        try:
            _unlink_extension_snapshots(snapshots)
        except UploadReadinessError:
            if reverify_error is None and caught is None:
                raise
        if reverify_error is not None and caught is None:
            raise reverify_error
        if reverify_error is not None and caught is not None:
            raise reverify_error from caught


# Module globals the bound helpers legitimately rebind while verifying.
_EXTENSION_MUTABLE_MODULE_GLOBALS: frozenset[tuple[str, str]] = frozenset(
    {
        ("store_js_minifier", "_PRODUCER_PACKAGED_JS"),
    }
)
# Module globals whose binding stays fixed but whose contents the bound helpers
# legitimately fill while verifying: the private esbuild engine snapshot cache,
# whose entries store_js_minifier.private_engine_snapshot rehashes on every use.
_EXTENSION_MUTABLE_MODULE_CONTENTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("store_js_minifier", "_ENGINE_CUSTODY"),
        ("store_js_minifier", "_ENGINE_SNAPSHOTS"),
    }
)
# Namespace keys CPython fills lazily without changing behavior: warnings
# registries and the PEP 649 annotation caches of modules and classes.
_EXTENSION_LAZY_NAMESPACE_KEYS: frozenset[str] = frozenset(
    {
        "__warningregistry__",
        "__annotations__",
        "__annotate_func__",
        "__annotations_cache__",
    }
)


# Values with no state of their own to walk: recorded by identity only.
_EXTENSION_IDENTITY_ONLY_TYPES: tuple[type, ...] = (
    str,
    bytes,
    int,
    float,
    complex,
    type(None),
    ModuleType,
    CodeType,
)


class _ExtensionFingerprintValue(tuple):
    """A recorded shape or copied value, compared by equality, not identity."""

    __slots__ = ()


def _extension_fingerprint_items(
    items: Iterable[tuple[object, object]],
    owned: frozenset[object],
    out: list[object],
    seen: set[int],
) -> None:
    pairs = [
        (key, value)
        for key, value in items
        if not (isinstance(key, str) and key in _EXTENSION_LAZY_NAMESPACE_KEYS)
    ]
    out.append(_ExtensionFingerprintValue(("items", len(pairs))))
    for key, value in pairs:
        out.append(key)
        _extension_fingerprint(value, owned, out, seen)


def _extension_fingerprint(
    value: object,
    owned: frozenset[object],
    out: list[object],
    seen: set[int],
) -> None:
    """Flatten everything a bound helper object owns into identities."""

    out.append(value)
    if id(value) in seen:
        return
    seen.add(id(value))
    if isinstance(value, FunctionType):
        out.extend(
            (
                value.__code__,
                value.__defaults__,
                value.__closure__,
                value.__kwdefaults__,
            )
        )
        for item in value.__defaults__ or ():
            _extension_fingerprint(item, owned, out, seen)
        _extension_fingerprint_items(
            (value.__kwdefaults__ or {}).items(), owned, out, seen
        )
        for cell in value.__closure__ or ():
            try:
                contents = cell.cell_contents
            except ValueError:
                out.append(_ExtensionFingerprintValue(("empty-cell",)))
                continue
            _extension_fingerprint(contents, owned, out, seen)
        _extension_fingerprint_items(vars(value).items(), owned, out, seen)
    elif isinstance(value, (dict, MappingProxyType)):
        _extension_fingerprint_items(value.items(), owned, out, seen)
    elif isinstance(value, (list, tuple, set, frozenset)):
        out.append(_ExtensionFingerprintValue(("items", len(value))))
        for item in value:
            _extension_fingerprint(item, owned, out, seen)
    elif isinstance(value, bytearray):
        out.append(_ExtensionFingerprintValue(("bytes", bytes(value))))
    elif isinstance(value, type):
        if getattr(value, "__module__", None) in owned:
            out.append(value.__bases__)
            _extension_fingerprint_items(vars(value).items(), owned, out, seen)
    elif not isinstance(value, _EXTENSION_IDENTITY_ONLY_TYPES):
        # Any other instance the helpers hold, whatever class defines it (the
        # leak scanner's ipaddress allowlist, the pathlib roots): fill its lazy
        # caches first, so a later fill is no change and a rebound cache is.
        if isinstance(value, pathlib.PurePath):
            os.fspath(value)
            hash(value)
            value.__lt__(value)
        for klass in type(value).__mro__:
            for name, attribute in vars(klass).items():
                if isinstance(attribute, functools.cached_property):
                    try:
                        getattr(value, name)
                    except Exception:
                        pass
        if hasattr(value, "__dict__"):
            # Materialize inline instance values so the referents keep one shape.
            vars(value)
        referents = gc.get_referents(value)
        out.append(type(value))
        out.append(_ExtensionFingerprintValue(("items", len(referents))))
        for referent in referents:
            _extension_fingerprint(referent, owned, out, seen)


def _extension_module_bindings(
    modules: Mapping[str, object],
) -> dict[tuple[str, str], tuple[object, ...]]:
    """Fingerprint all state the bound helper modules own, by object identity.

    Every module global is walked: function code, defaults, closure cells and
    attributes; every container, class and instance the helpers define; and
    the builtins namespace their code resolves unbound names through; and
    every other instance reached, whatever class defines it, through its
    referents. Other modules, classes the helpers do not define, and
    immutable atoms are recorded by identity only.
    """

    owned = frozenset(
        getattr(module, "__name__", None) for module in modules.values()
    )
    bindings: dict[tuple[str, str], tuple[object, ...]] = {}
    for role, module in modules.items():
        for name, value in vars(module).items():
            if (
                name in _EXTENSION_LAZY_NAMESPACE_KEYS
                or (role, name) in _EXTENSION_MUTABLE_MODULE_GLOBALS
            ):
                continue
            if (role, name) in _EXTENSION_MUTABLE_MODULE_CONTENTS:
                bindings[(role, name)] = (value,)
                continue
            out: list[object] = []
            _extension_fingerprint(value, owned, out, set())
            bindings[(role, name)] = tuple(out)
    return bindings


def _same_extension_module_bindings(
    bound: Mapping[tuple[str, str], tuple[object, ...]] | None,
    current: Mapping[tuple[str, str], tuple[object, ...]],
    *,
    _zip: Callable[..., Iterable[tuple[object, object]]] = zip,
) -> bool:
    if bound is None or bound.keys() != current.keys():
        return False
    for key, expected in bound.items():
        observed = current[key]
        if len(observed) != len(expected):
            return False
        for left, right in _zip(observed, expected):
            if type(right) is _ExtensionFingerprintValue:
                if type(left) is not _ExtensionFingerprintValue or left != right:
                    return False
            elif left is not right:
                return False
    return True


def _reverify_extension_source_custody(
    repo: pathlib.Path,
    snapshot_digest_by_role: Mapping[str, tuple[pathlib.Path, str]],
    bound_closure: Mapping[str, object],
) -> None:
    """Reject any change to the verifier closure or a private snapshot."""

    current_closure = extension_verifier_source_closure(repo)
    if current_closure != bound_closure:
        raise UploadReadinessError(
            "extension verifier source closure changed during execution."
        )
    for role, (snapshot, digest) in snapshot_digest_by_role.items():
        _size, _, current = _stable_identity(
            snapshot, f"extension verifier snapshot {role}"
        )
        if current != digest:
            raise UploadReadinessError(
                f"extension {role} snapshot changed during execution."
            )


def _reverify_bound_extension_execution(
    repo: pathlib.Path,
    modules: Mapping[str, object],
    snapshot_digest_by_role: Mapping[str, tuple[pathlib.Path, str]],
    bound_closure: Mapping[str, object],
    bound_verify_existing_package: Callable[..., object] | None,
    bound_module_bindings: Mapping[tuple[str, str], tuple[object, ...]] | None,
) -> None:
    _reverify_extension_source_custody(repo, snapshot_digest_by_role, bound_closure)
    for role, (snapshot, digest) in snapshot_digest_by_role.items():
        module = modules.get(role)
        module_name = f"winsvpn_ext_receipt_{role}_{digest}"
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None) if spec is not None else None
        spec_name = getattr(spec, "name", None) if spec is not None else None
        if (
            module is None
            or sys.modules.get(module_name) is not module
            or getattr(module, "__name__", None) != module_name
            or spec_name != module_name
            or not _same_bound_path(getattr(module, "__file__", None), snapshot)
            or not _same_bound_path(origin, snapshot)
        ):
            raise UploadReadinessError(
                f"extension {role} executed origin is not the bound snapshot."
            )
    builder = modules.get("builder")
    if (
        tuple(getattr(builder, "VERIFIER_SOURCE_PATHS", ()) or ())
        != EXTENSION_VERIFIER_SOURCE_PATHS
        or not callable(getattr(builder, "verify_existing_package", None))
        or getattr(builder, "verify_existing_package", None)
        is not bound_verify_existing_package
        or not _same_extension_module_bindings(
            bound_module_bindings, _extension_module_bindings(modules)
        )
        or getattr(
            getattr(builder, "verify_existing_package", None), "__module__", None
        )
        != getattr(builder, "__name__", object())
        or getattr(modules.get("checks"), "jsonc", None) is not modules.get("jsonc")
        or getattr(builder, "jsonc", None) is not modules.get("jsonc")
        or getattr(builder, "checks", None) is not modules.get("checks")
        or getattr(builder, "leakscan", None) is not modules.get("leakscan")
        or getattr(builder, "store_js_minifier", None)
        is not modules.get("store_js_minifier")
        or getattr(builder, "read_pubspec_manifest_version", None)
        is not getattr(
            modules.get("store_version"), "read_pubspec_manifest_version", object()
        )
        or getattr(modules.get("checks"), "read_pubspec_manifest_version", None)
        is not getattr(
            modules.get("store_version"), "read_pubspec_manifest_version", object()
        )
    ):
        raise UploadReadinessError(
            "extension verify-only producer helper binding changed during execution."
        )


# The in-process binding walk above cannot be closed: every object a helper
# reaches (builtins, stdlib classes, interpreter state) is rebindable by any
# code in the same process, and each fingerprint turn found another one. The
# production verification therefore never runs the verifier in the caller's
# process. It runs it in a fresh `python -I -S -B` interpreter that starts from
# stdin and a `-c` string, and executes only the six helper sources it has
# re-hashed against the pins the parent computed from its exclusive snapshots.
_EXTENSION_ISOLATED_TIMEOUT_SECONDS = 900
_EXTENSION_ISOLATED_RESULT_LIMIT = 4 * 1024 * 1024
_EXTENSION_ISOLATED_STDERR_TAIL = 2000
_EXTENSION_ISOLATED_POSTURE = {
    "isolated": 1,
    "ignore_environment": 1,
    "no_user_site": 1,
    "no_site": 1,
    "dont_write_bytecode": 1,
    "argv": ["-c"],
}
_EXTENSION_ISOLATED_WORKER_SOURCE = r'''
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import sys
from pathlib import Path


def _fail(message):
    raise SystemExit("isolated extension verifier: " + message)


def _file_identity(path):
    # Trust decisions compare files, never path strings: a resolved path, a
    # case variant or a symlink names the same file. No identity, no trust.
    try:
        info = os.stat(path)
    except (OSError, TypeError, ValueError):
        return None
    return (info.st_dev, info.st_ino)


def _read_pinned(path, pin):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        data = handle.read()
    if hashlib.sha256(data).hexdigest() != pin:
        _fail("pinned source bytes changed before load: " + path)
    return data, (info.st_dev, info.st_ino)


class _RepositoryBoundary:
    """Refuses repository code the parent did not pin, before it runs."""

    def __init__(self, repo):
        self.identity = _file_identity(repo)
        if self.identity is None:
            _fail("repository root cannot be identified")
        # identity -> the exact snapshot path the worker compiled. A pinned
        # file is trusted only under that path: any other name for it (a
        # repository symlink to the snapshot) is an import origin whose loader
        # may run different bytes, such as cached bytecode beside it.
        self.pinned = {}
        self.refused = []
        # Memo keys carry the directory's current identity, so a directory
        # replaced after its first check is a cache miss and is walked again.
        self._resolved = {}
        self._directories = {}

    def _resolved_inside(self, resolved):
        # `resolved` has no symlink component, so its parents are resolved too;
        # a match is decided by identity (case variants, firmlinks, mounts).
        identity = _file_identity(resolved)
        key = (resolved, identity)
        if identity is not None and key in self._resolved:
            return self._resolved[key]
        if identity is not None and identity == self.identity:
            inside = True
        else:
            parent = os.path.dirname(resolved)
            inside = parent != resolved and self._resolved_inside(parent)
        if identity is not None:
            self._resolved[key] = inside
        return inside

    def _directory_inside(self, directory):
        # Inside if the directory resolves into the repository, or if any
        # lexical ancestor does (a repository symlink that points elsewhere).
        identity = _file_identity(directory)
        key = (directory, identity)
        if identity is not None and key in self._directories:
            return self._directories[key]
        inside = self._resolved_inside(os.path.realpath(directory))
        if not inside:
            parent = os.path.dirname(directory)
            inside = parent != directory and self._directory_inside(parent)
        if identity is not None:
            self._directories[key] = inside
        return inside

    def untrusted(self, path):
        if not isinstance(path, str) or not path:
            return True
        identity = _file_identity(path)
        if identity is None:
            return True
        if self.pinned.get(identity) == path:
            return False
        absolute = os.path.abspath(path)
        if self._directory_inside(os.path.dirname(absolute)):
            return True
        # A file that is itself a symlink is judged by its target as well.
        return os.path.islink(absolute) and self._directory_inside(
            os.path.dirname(os.path.realpath(absolute))
        )

    def refuse(self, path):
        self.refused.append(str(path))
        raise ImportError(
            "isolated extension verifier refused unpinned repository code: "
            + str(path)
        )

    def audit(self, event, args):
        # Every Python code object a module import or an explicit loader runs
        # passes through exec(); the hook vetoes it before the first bytecode.
        if event != "exec" or not args:
            return
        filename = getattr(args[0], "co_filename", None)
        if (
            isinstance(filename, str)
            and filename.startswith("<")
            and filename.endswith(">")
        ):
            return
        if self.untrusted(filename):
            self.refuse(filename)


class _RepositoryImportGuard:
    """Path-based import finder that refuses unpinned repository origins.

    Sits in front of PathFinder so extension modules and sourceless bytecode,
    which carry no trustworthy code filename, are judged by their real origin.
    """

    boundary = None

    @classmethod
    def find_spec(cls, name, path=None, target=None):
        spec = importlib.machinery.PathFinder.find_spec(name, path, target)
        if spec is None:
            return None
        if spec.has_location and cls.boundary.untrusted(spec.origin):
            cls.boundary.refuse(spec.origin)
        return spec

    @classmethod
    def invalidate_caches(cls):
        return None


def _install_repository_boundary(repo):
    boundary = _RepositoryBoundary(repo)
    _RepositoryImportGuard.boundary = boundary
    position = len(sys.meta_path)
    for index, finder in enumerate(sys.meta_path):
        if finder is importlib.machinery.PathFinder:
            position = index
            break
    sys.meta_path.insert(position, _RepositoryImportGuard)
    sys.addaudithook(boundary.audit)
    return boundary


def main():
    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    boundary = _install_repository_boundary(request["repo"])
    flags = sys.flags
    posture = {
        "isolated": flags.isolated,
        "ignore_environment": flags.ignore_environment,
        "no_user_site": flags.no_user_site,
        "no_site": flags.no_site,
        "dont_write_bytecode": flags.dont_write_bytecode,
        "argv": list(sys.argv),
    }
    public = set(request["public"])
    saved_path = list(sys.path)
    modules = {}
    for role, path, pin in request["modules"]:
        data, identity = _read_pinned(path, pin)
        boundary.pinned[identity] = path
        name = "winsvpn_ext_receipt_" + role + "_" + pin
        if name in sys.modules or (role in public and role in sys.modules):
            _fail("module identity collided: " + role)
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None:
            _fail("cannot build a module spec for " + role)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        exec(compile(data, path, "exec", dont_inherit=True), module.__dict__)
        if (
            sys.modules.get(name) is not module
            or module.__name__ != name
            or spec.name != name
            or _file_identity(getattr(module, "__file__", None)) != identity
            or _file_identity(spec.origin) != identity
        ):
            _fail("loaded origin is not the pinned snapshot: " + role)
        modules[role] = module
        if role in public:
            sys.modules[role] = module
    sys.path[:] = saved_path
    builder = modules["builder"]
    store_version_mod = modules["store_version"]
    jsonc_mod = modules["jsonc"]
    checks_mod = modules["checks"]
    leakscan_mod = modules["leakscan"]
    minifier_mod = modules["store_js_minifier"]
    parse_version = getattr(store_version_mod, "read_pubspec_manifest_version", object())
    if (
        list(getattr(builder, "VERIFIER_SOURCE_PATHS", ()) or ())
        != request["verifier_source_paths"]
        or not callable(getattr(builder, "verify_existing_package", None))
        or getattr(builder, "jsonc", None) is not jsonc_mod
        or getattr(builder, "checks", None) is not checks_mod
        or getattr(builder, "leakscan", None) is not leakscan_mod
        or getattr(builder, "store_js_minifier", None) is not minifier_mod
        or getattr(checks_mod, "jsonc", None) is not jsonc_mod
        or getattr(builder, "read_pubspec_manifest_version", None) is not parse_version
        or getattr(checks_mod, "read_pubspec_manifest_version", None) is not parse_version
    ):
        _fail("verify-only producer is not bound to the pinned helper snapshots")
    loads = getattr(jsonc_mod, "loads", None)
    if not callable(loads):
        _fail("native-host identity parser is not bound")
    native_host = {}
    for browser, text in request["native_host"].items():
        # The parent read these bytes once and bound them to the closure digest;
        # the child never reopens the repository path.
        try:
            native_host[browser] = {"manifest": loads(text)}
        except (UnicodeError, ValueError) as exc:
            native_host[browser] = {"error": str(exc)}
    payload = {"posture": posture, "native_host": native_host}
    try:
        payload["result"] = builder.verify_existing_package(
            Path(request["artifact"]),
            request["target_id"],
            repo=Path(request["repo"]),
            verbose=False,
        )
    except Exception as exc:
        payload["error"] = str(exc)
    foreign = set(boundary.refused)
    pinned_modules = list(modules.values())
    for name, module in list(sys.modules.items()):
        if any(module is pinned for pinned in pinned_modules):
            continue
        spec = getattr(module, "__spec__", None)
        origins = [getattr(module, "__file__", None)]
        if spec is not None and getattr(spec, "has_location", False):
            origins.append(getattr(spec, "origin", None))
        for origin in origins:
            if isinstance(origin, str) and boundary.untrusted(origin):
                foreign.add(name)
    payload["unpinned_repo_modules"] = sorted(foreign)
    payload["loaded"] = {
        role: [module.__file__, module.__name__] for role, module in modules.items()
    }
    encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("ascii")
    flags_out = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(request["result_path"], flags_out, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)


main()
'''


@dataclasses.dataclass(frozen=True)
class _IsolatedExtensionOutcome:
    """What the fresh-interpreter verifier reported, before any parent check."""

    native_host: Mapping[str, object]
    result: object
    error: str | None


def _same_existing_file(value: str, expected: str) -> bool:
    """Compare two paths by file identity; a path that cannot be stat'ed fails."""

    try:
        actual = os.stat(value)
        bound = os.stat(expected)
    except (OSError, TypeError, ValueError):
        return False
    return (actual.st_dev, actual.st_ino) == (bound.st_dev, bound.st_ino)


def _isolated_extension_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("PYTHON")
        and not name.startswith("WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT")
    }


def _run_isolated_extension_child(
    request: Mapping[str, object],
    repo: pathlib.Path,
    result_path: pathlib.Path,
) -> _IsolatedExtensionOutcome:
    """Run the pinned verifier in a fresh `python -I` interpreter and parse it."""

    executable = sys.executable
    if not executable or not os.path.isfile(executable):
        raise UploadReadinessError(
            "extension verifier needs a Python executable for its isolated run."
        )
    payload = json.dumps(request, ensure_ascii=True, allow_nan=False).encode("ascii")
    try:
        process = subprocess.Popen(
            [executable, "-I", "-S", "-B", "-c", _EXTENSION_ISOLATED_WORKER_SOURCE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=repo,
            env=_isolated_extension_environment(),
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise UploadReadinessError(
            f"extension isolated verifier could not start: {exc}"
        ) from exc
    try:
        _stdout, stderr = process.communicate(
            payload, timeout=_EXTENSION_ISOLATED_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as exc:
        if hasattr(os, "killpg"):
            try:
                os.killpg(process.pid, 9)
            except OSError:
                pass
        process.kill()
        process.communicate()
        raise UploadReadinessError(
            "extension isolated verifier timed out and was killed."
        ) from exc
    if process.returncode != 0:
        tail = stderr.decode("utf-8", errors="replace")[
            -_EXTENSION_ISOLATED_STDERR_TAIL:
        ].strip()
        raise UploadReadinessError(
            f"extension isolated verifier exited {process.returncode}: {tail}"
        )
    try:
        info = result_path.lstat()
    except OSError as exc:
        raise UploadReadinessError(
            f"extension isolated verifier produced no result: {exc}"
        ) from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > _EXTENSION_ISOLATED_RESULT_LIMIT:
        raise UploadReadinessError(
            "extension isolated verifier result is not a bounded regular file."
        )
    try:
        report = json.loads(result_path.read_bytes().decode("ascii"))
    except (OSError, ValueError) as exc:
        raise UploadReadinessError(
            f"extension isolated verifier produced no valid result: {exc}"
        ) from exc
    if not isinstance(report, dict):
        raise UploadReadinessError("extension isolated verifier result is malformed.")
    expected_keys = {
        "posture",
        "native_host",
        "loaded",
        "unpinned_repo_modules",
    }
    if not expected_keys <= set(report) or not set(report) <= expected_keys | {
        "result",
        "error",
    }:
        raise UploadReadinessError("extension isolated verifier result is malformed.")
    if report["posture"] != _EXTENSION_ISOLATED_POSTURE:
        raise UploadReadinessError(
            "extension isolated verifier did not run in an isolated interpreter."
        )
    if report["unpinned_repo_modules"] != []:
        raise UploadReadinessError(
            "extension isolated verifier imported unpinned repository modules."
        )
    expected_loaded = request.get("modules")
    loaded = report["loaded"]
    if (
        not isinstance(expected_loaded, list)
        or not isinstance(loaded, dict)
        or set(loaded) != {role for role, _path, _pin in expected_loaded}
    ):
        raise UploadReadinessError(
            "extension isolated verifier loaded an unexpected helper set."
        )
    for role, path, pin in expected_loaded:
        origin = loaded[role]
        if (
            not isinstance(origin, list)
            or len(origin) != 2
            or not isinstance(origin[0], str)
            or not _same_existing_file(origin[0], path)
            or origin[1] != f"winsvpn_ext_receipt_{role}_{pin}"
        ):
            raise UploadReadinessError(
                f"extension {role} executed origin is not the bound snapshot."
            )
    native_host = report["native_host"]
    if not isinstance(native_host, dict):
        raise UploadReadinessError("extension isolated verifier result is malformed.")
    error = report.get("error")
    if error is not None and not isinstance(error, str):
        raise UploadReadinessError("extension isolated verifier result is malformed.")
    if error is None and "result" not in report:
        raise UploadReadinessError("extension isolated verifier result is malformed.")
    return _IsolatedExtensionOutcome(
        native_host=native_host, result=report.get("result"), error=error
    )


def _bound_native_host_texts(
    repo: pathlib.Path, bound_closure: Mapping[str, object]
) -> dict[str, str]:
    """Read each Chromium native-host template once, bound to the closure digest.

    The child parses exactly these bytes. It never reopens the repository path,
    so a template swapped (or replaced by a symlink) and restored around the
    child's run cannot be what the identity rules judge.
    """

    bound_digests = {
        item.get("path"): item.get("sha256")
        for item in bound_closure.get("inputs", ())
        if isinstance(item, dict)
    }
    texts: dict[str, str] = {}
    for browser in ("chrome", "edge"):
        relative = (
            f"tools/native_messaging/manifests/org.winsvpn.bridge.{browser}.json"
        )
        path = freeze.secure_repo_path(
            repo,
            pathlib.Path(relative),
            f"{browser} native-host template",
            must_exist=True,
        )
        payload, digest = _authenticated_file_bytes(
            path, f"{browser} native-host template"
        )
        if bound_digests.get(relative) != digest:
            raise UploadReadinessError(
                f"{browser} native-host template changed after the verifier "
                "closure was bound."
            )
        try:
            text = payload.decode("utf-8")
        except UnicodeError as exc:
            raise UploadReadinessError(
                f"{browser} native-host template is invalid: {exc}"
            ) from exc
        # Same newline translation as the text-mode read this replaces.
        texts[browser] = text.replace("\r\n", "\n").replace("\r", "\n")
    return texts


@contextlib.contextmanager
def _isolated_extension_verification(
    repo: pathlib.Path,
    target_id: str,
    artifact_path: pathlib.Path,
):
    """Verify one exact artifact with the bound sources in a fresh interpreter.

    Nothing the caller's process or the verifier's own process does to its
    interpreter state can reach the other: the child shares no memory, no
    ``sys.modules``, no builtins and no stdlib module objects with the caller,
    and the only repository bytes it executes are the six helper sources it
    re-hashes against the parent's pins. The parent still re-hashes the source
    closure and every snapshot after the run, so a file swapped mid-run is
    rejected exactly as before.
    """

    repo = freeze.secure_repo_path(
        repo, pathlib.Path("."), "Repository root", must_exist=True
    )
    snapshots: list[pathlib.Path] = []
    snapshot_digest_by_role: dict[str, tuple[pathlib.Path, str]] = {}
    bound_closure: dict[str, object] | None = None
    work_dir: pathlib.Path | None = None
    caught: BaseException | None = None
    try:
        for role, relative in _EXTENSION_RUNTIME_PYTHON_SOURCES:
            _original, snapshot, digest, _size = _exclusive_extension_source_snapshot(
                repo,
                relative,
                f"extension verifier source {relative}",
            )
            snapshots.append(snapshot)
            snapshot_digest_by_role[role] = (snapshot, digest)
        bound_closure = extension_verifier_source_closure(repo)
        native_host_texts = _bound_native_host_texts(repo, bound_closure)
        work_dir = pathlib.Path(tempfile.mkdtemp(prefix="winsvpn-ext-isolated-"))
        request = {
            "modules": [
                [role, str(snapshot_digest_by_role[role][0]), snapshot_digest_by_role[role][1]]
                for role, _relative in _EXTENSION_RUNTIME_PYTHON_SOURCES
            ],
            "public": list(_EXTENSION_PUBLIC_HELPER_NAMES),
            "verifier_source_paths": list(EXTENSION_VERIFIER_SOURCE_PATHS),
            "native_host": native_host_texts,
            "artifact": str(artifact_path),
            "target_id": target_id,
            "repo": str(repo),
            "result_path": str(work_dir / "result.json"),
        }
        outcome = _run_isolated_extension_child(
            request, repo, work_dir / "result.json"
        )
        try:
            yield outcome
        except BaseException as exc:
            caught = exc
            raise
        _reverify_extension_source_custody(
            repo, snapshot_digest_by_role, bound_closure
        )
    except gate_runner.ExactSnapshotError as exc:
        raise UploadReadinessError(
            f"extension verifier snapshot failed: {exc}"
        ) from exc
    finally:
        reverify_error: BaseException | None = None
        if caught is not None and bound_closure is not None:
            try:
                _reverify_extension_source_custody(
                    repo, snapshot_digest_by_role, bound_closure
                )
            except BaseException as exc:
                reverify_error = exc
        if work_dir is not None:
            shutil.rmtree(work_dir, ignore_errors=True)
        try:
            _unlink_extension_snapshots(snapshots)
        except UploadReadinessError:
            if reverify_error is None and caught is None:
                raise
        if reverify_error is not None and caught is None:
            raise reverify_error
        if reverify_error is not None and caught is not None:
            raise reverify_error from caught


def _chromium_native_host_identity(browser: str, manifest: object) -> str:
    origins = manifest.get("allowed_origins") if isinstance(manifest, dict) else None
    if not isinstance(origins, list) or len(origins) != 1:
        raise UploadReadinessError(
            f"{browser} native-host release identity is not exact."
        )
    origin = origins[0]
    match = (
        re.fullmatch(r"chrome-extension://([a-p]{32})/", origin)
        if isinstance(origin, str)
        else None
    )
    if match is None:
        raise UploadReadinessError(
            f"{browser} native-host release identity is placeholder or invalid."
        )
    return match.group(1)


def _verify_isolated_chromium_native_host_identities(
    native_host: Mapping[str, object],
) -> None:
    """Apply the native-host identity rules to manifests parsed by the child."""

    identities: dict[str, str] = {}
    for browser in ("chrome", "edge"):
        entry = native_host.get(browser)
        if not isinstance(entry, dict) or set(entry) not in ({"manifest"}, {"error"}):
            raise UploadReadinessError(
                f"{browser} native-host template is invalid: not reported."
            )
        if "error" in entry:
            raise UploadReadinessError(
                f"{browser} native-host template is invalid: {entry['error']}"
            )
        identities[browser] = _chromium_native_host_identity(
            browser, entry["manifest"]
        )
    if identities["chrome"] == identities["edge"]:
        raise UploadReadinessError(
            "Chrome and Edge native-host release identities must be distinct."
        )



def _extension_authored_source_ignored(name: str) -> bool:
    # Mirrors extension/tools/store_js_minifier.py:_ignore_source_name.
    if name.startswith("._") or name in {".DS_Store", "__pycache__"}:
        return True
    return name.endswith(".pyc") or name.endswith(".bak_20260807_webrequest")


def extension_verifier_source_paths(repo: pathlib.Path) -> tuple[str, ...]:
    """Mirror extension/build.py:_verifier_source_relatives for one repository."""

    repo = pathlib.Path(os.path.abspath(repo))
    relatives = set(EXTENSION_VERIFIER_SOURCE_PATHS)
    source_root = freeze.secure_repo_path(
        repo,
        pathlib.Path(EXTENSION_AUTHORED_SOURCE_RELATIVE),
        "extension authored source",
        must_exist=True,
    )
    authored = 0
    for path in sorted(source_root.rglob("*")):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise UploadReadinessError(
                f"extension authored source is a symbolic link: {path}"
            )
        if not stat.S_ISREG(info.st_mode):
            continue
        if _extension_authored_source_ignored(path.name):
            continue
        relatives.add(
            f"{EXTENSION_AUTHORED_SOURCE_RELATIVE}/"
            f"{path.relative_to(source_root).as_posix()}"
        )
        authored += 1
    if authored == 0:
        raise UploadReadinessError("extension authored source contains no files.")
    manifest_root = freeze.secure_repo_path(
        repo,
        pathlib.Path(EXTENSION_MANIFEST_RELATIVE),
        "extension manifest directory",
        must_exist=True,
    )
    for path in sorted(manifest_root.glob("*.jsonc")):
        relatives.add(
            f"{EXTENSION_MANIFEST_RELATIVE}/{path.relative_to(manifest_root).as_posix()}"
        )
    return tuple(sorted(relatives))


def extension_verifier_source_closure(repo: pathlib.Path) -> dict[str, object]:
    inputs: list[dict[str, object]] = []
    for relative in extension_verifier_source_paths(repo):
        path = freeze.secure_repo_path(
            repo,
            pathlib.Path(relative),
            f"extension verifier source {relative}",
            must_exist=True,
        )
        size, _, digest = _stable_identity(path, f"extension verifier source {relative}")
        inputs.append({"path": relative, "sha256": digest, "bytes": size})
    encoded = (
        json.dumps(inputs, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    return {
        "inputs": inputs,
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _verify_extension_verifier_closure(
    repo: pathlib.Path,
    target_id: str,
    raw: object,
) -> dict[str, object]:
    expected = extension_verifier_source_closure(repo)
    expected_paths = extension_verifier_source_paths(repo)
    closure = _exact(
        raw,
        set(EXTENSION_VERIFIER_CLOSURE_KEYS),
        f"{target_id} verifier source closure",
    )
    inputs = closure.get("inputs")
    if not isinstance(inputs, list) or len(inputs) != len(expected_paths):
        raise UploadReadinessError(
            f"{target_id} verifier source closure input set is not exact."
        )
    checked: list[dict[str, object]] = []
    for index, item in enumerate(inputs):
        record = _exact(
            item,
            set(EXTENSION_VERIFIER_INPUT_KEYS),
            f"{target_id} verifier source input {index}",
        )
        path = record.get("path")
        digest = record.get("sha256")
        size = record.get("bytes")
        if (
            not isinstance(path, str)
            or path not in expected_paths
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or type(size) is not int
            or size <= 0
        ):
            raise UploadReadinessError(
                f"{target_id} verifier source input {index} is malformed."
            )
        checked.append({"path": path, "sha256": digest, "bytes": size})
    paths = [str(item["path"]) for item in checked]
    if paths != list(expected_paths):
        raise UploadReadinessError(
            f"{target_id} verifier source closure paths are not exact and ordered."
        )
    if closure != expected or checked != expected["inputs"]:
        raise UploadReadinessError(f"{target_id} verifier source closure changed.")
    return expected


def _verify_bound_chromium_native_host_identities(
    repo: pathlib.Path, builder: object
) -> None:
    """Reject placeholder or reused Chromium identities at receipt time.

    Parses through an in-process bound builder. The production path applies the
    same rules to manifests the isolated child parsed, through
    `_verify_isolated_chromium_native_host_identities`.
    """

    identities: dict[str, str] = {}
    jsonc_mod = getattr(builder, "jsonc", None)
    loads = getattr(jsonc_mod, "loads", None)
    if not callable(loads):
        raise UploadReadinessError(
            "extension native-host identity parser is not bound."
        )
    for browser in ("chrome", "edge"):
        relative = (
            f"tools/native_messaging/manifests/org.winsvpn.bridge.{browser}.json"
        )
        path = freeze.secure_repo_path(
            repo,
            pathlib.Path(relative),
            f"{browser} native-host template",
            must_exist=True,
        )
        try:
            manifest = loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise UploadReadinessError(
                f"{browser} native-host template is invalid: {exc}"
            ) from exc
        identities[browser] = _chromium_native_host_identity(browser, manifest)
    if identities["chrome"] == identities["edge"]:
        raise UploadReadinessError(
            "Chrome and Edge native-host release identities must be distinct."
        )


def verify_extension_zip_artifact(
    repo: pathlib.Path,
    target_id: str,
    artifact_path: pathlib.Path,
) -> dict[str, object]:
    """Rerun producer leak and policy checks against one exact extension zip."""

    if target_id not in EXTENSION_TARGET_IDS:
        raise UploadReadinessError(f"Unexpected extension upload target: {target_id}")
    target = TARGET_BY_ID[target_id]
    repo = freeze.secure_repo_path(
        repo, pathlib.Path("."), "Repository root", must_exist=True
    )
    artifact_path = freeze.secure_repo_path(
        repo, artifact_path, f"{target_id} artifact", must_exist=True
    )
    identity = _stable_identity(artifact_path, f"{target_id} artifact")
    try:
        with gate_runner.ExactArtifactSnapshot(
            source_path=artifact_path,
            cwd=repo,
            expected_sha256=identity[2],
        ) as artifact_snap:
            with _isolated_extension_verification(
                repo, target_id, artifact_snap.snapshot_path
            ) as outcome:
                closure = extension_verifier_source_closure(repo)
                _verify_isolated_chromium_native_host_identities(outcome.native_host)
                if outcome.error is not None:
                    raise UploadReadinessError(
                        f"{target_id} exact zip leak/policy verification failed: "
                        f"{outcome.error}"
                    )
                result = outcome.result
                snapshot_size, _, snapshot_digest = _stable_identity(
                    artifact_snap.snapshot_path,
                    f"{target_id} artifact snapshot",
                )
                after_original = _stable_identity(
                    artifact_path, f"{target_id} artifact"
                )
                reported_closure = (
                    result.get("verifier_source_closure")
                    if isinstance(result, dict)
                    else None
                )
                if after_original != identity:
                    raise UploadReadinessError(
                        f"{target_id} artifact changed during zip leak/policy verification."
                    )
                if (
                    snapshot_digest != identity[2]
                    or snapshot_size != identity[0]
                ):
                    raise UploadReadinessError(
                        f"{target_id} artifact snapshot is not the bound identity."
                    )
                if (
                    not isinstance(result, dict)
                    or result.get("ok") is not True
                    or result.get("target_id") != target_id
                    or result.get("browser")
                    != EXTENSION_BROWSER_BY_TARGET_ID[target_id]
                    or result.get("rebuilt") is not False
                    or result.get("trusted_loose_source") is not False
                    or result.get("sha256") != identity[2]
                    or result.get("bytes") != identity[0]
                    or reported_closure != closure
                ):
                    raise UploadReadinessError(
                        f"{target_id} exact zip leak/policy evidence is not bound "
                        "to the artifact."
                    )
                verify_extension_cross_store_hardening(
                    target_id,
                    artifact_snap.snapshot_path,
                    expected_sha256=identity[2],
                )
                snapshot_size, _, snapshot_digest = _stable_identity(
                    artifact_snap.snapshot_path,
                    f"{target_id} artifact snapshot",
                )
                after_original = _stable_identity(
                    artifact_path, f"{target_id} artifact"
                )
                if after_original != identity:
                    raise UploadReadinessError(
                        f"{target_id} artifact changed during zip leak/policy verification."
                    )
                if (
                    snapshot_digest != identity[2]
                    or snapshot_size != identity[0]
                ):
                    raise UploadReadinessError(
                        f"{target_id} artifact snapshot is not the bound identity."
                    )
    except (
        gate_runner.ExactSnapshotError,
        gate_runner.ExactProducerExecutionError,
    ) as exc:
        raise UploadReadinessError(
            f"{target_id} artifact snapshot verification failed: {exc}"
        ) from exc
    if target.producer_ids != ("extension/build.py",):
        raise UploadReadinessError(f"{target_id} verify-only producer is not exact.")
    return {
        "ok": True,
        "target_id": target_id,
        "browser": EXTENSION_BROWSER_BY_TARGET_ID[target_id],
        "verifier_source_closure": closure,
        "artifact_sha256": identity[2],
        "artifact_bytes": identity[0],
        "rebuilt": False,
        "trusted_loose_source": False,
    }


def _verify_target_receipt(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    target_id: str,
    receipt_path: pathlib.Path,
    now: dt.datetime | None = None,
    gate_references: Mapping[str, object] | None = None,
    gate_verified_at: dt.datetime | None = None,
) -> dict[str, object]:
    target = TARGET_BY_ID[target_id]
    now = now or dt.datetime.now(tz=dt.timezone.utc)
    receipt_path = freeze.secure_repo_path(
        repo, receipt_path, f"{target_id} upload receipt", must_exist=True
    )
    if receipt_path.relative_to(repo).parts[0] != ".artifacts":
        raise UploadReadinessError(f"{target_id} receipt must stay under .artifacts/.")
    _, _, receipt_sha = _stable_identity(receipt_path, f"{target_id} upload receipt")
    record = _exact(
        _load_json(receipt_path, f"{target_id} upload receipt"),
        _target_receipt_keys(target),
        f"{target_id} upload receipt",
    )
    artifact = _exact(
        record.get("artifact"), {"path", "sha256", "bytes"}, f"{target_id} artifact"
    )
    build_receipt = _exact(
        record.get("build_receipt"),
        {"path", "sha256", "target"},
        f"{target_id} build receipt",
    )
    producer = _exact(
        record.get("producer"),
        {"id", "path", "sha256"},
        f"{target_id} producer",
    )
    source = _exact(
        record.get("dependency_source_freeze"),
        {
            "index_path",
            "index_sha256",
            "platform_manifest_path",
            "platform_manifest_sha256",
            "artifact_input_fingerprint_sha256",
            "shared_revision",
        },
        f"{target_id} source freeze",
    )
    if (
        not isinstance(artifact.get("path"), str)
        or not artifact.get("path")
        or not isinstance(artifact.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256"))) is None
        or type(artifact.get("bytes")) is not int
        or int(artifact.get("bytes")) <= 0
        or not isinstance(build_receipt.get("path"), str)
        or not build_receipt.get("path")
        or not isinstance(build_receipt.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(build_receipt.get("sha256"))) is None
        or not isinstance(build_receipt.get("target"), str)
        or not isinstance(producer.get("id"), str)
        or not isinstance(producer.get("path"), str)
        or not isinstance(producer.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(producer.get("sha256"))) is None
        or any(not isinstance(source.get(key), str) or not source.get(key) for key in source)
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(source.get(key))) is None
            for key in (
                "index_sha256",
                "platform_manifest_sha256",
                "artifact_input_fingerprint_sha256",
            )
        )
    ):
        raise UploadReadinessError(f"{target_id} receipt scalar types are invalid.")
    verified_at = _safe_time(record.get("verified_utc"), f"{target_id} receipt")
    if verified_at > now + MAX_CLOCK_SKEW or now - verified_at > MAX_RECEIPT_AGE:
        raise UploadReadinessError(f"{target_id} receipt is stale or future-dated.")
    artifact_path = freeze.secure_repo_path(
        repo,
        pathlib.Path(str(artifact.get("path"))),
        f"{target_id} artifact",
        must_exist=True,
    )
    if not any(
        artifact_path.name.lower().endswith(suffix)
        for suffix in target.artifact_suffixes
    ):
        raise UploadReadinessError(f"{target_id} artifact type is not allowed.")
    artifact_bytes, artifact_mtime_ns, artifact_sha = _stable_identity(
        artifact_path, f"{target_id} artifact"
    )
    artifact_binding = {
        "path": freeze._relative_repo_path(repo, artifact_path),
        "sha256": artifact_sha,
        "bytes": artifact_bytes,
    }
    artifact_time = dt.datetime.fromtimestamp(
        artifact_mtime_ns / 1_000_000_000, tz=dt.timezone.utc
    )
    if (
        artifact_time > verified_at + MAX_CLOCK_SKEW
        or artifact_time > now + MAX_CLOCK_SKEW
        or now - artifact_time > MAX_RECEIPT_AGE
        or artifact != artifact_binding
    ):
        raise UploadReadinessError(
            f"{target_id} artifact identity or freshness changed."
        )
    producer_id = str(producer.get("id"))
    if producer_id not in target.producer_ids or producer.get("path") != producer_id:
        raise UploadReadinessError(f"{target_id} producer id is not allowed.")
    producer_path = freeze.secure_repo_path(
        repo, pathlib.Path(producer_id), f"{target_id} producer", must_exist=True
    )
    if producer.get("sha256") != freeze._sha256_file(producer_path):
        raise UploadReadinessError(f"{target_id} producer identity changed.")
    verified_index = freeze.verify_release_index(repo, index_path, target.platform)
    index_record = _load_json(index_path, "Release input index")
    platform_refs = index_record.get("platform_manifests")
    if not isinstance(platform_refs, dict):
        raise UploadReadinessError("Release input index platform set is malformed.")
    platform_ref = _exact(
        platform_refs.get(target.platform),
        {"path", "sha256", "artifact_input_fingerprint_sha256"},
        f"Indexed {target.platform} manifest",
    )
    platform_manifest_path = freeze.secure_repo_path(
        repo,
        index_path.parent / str(platform_ref.get("path")),
        f"Indexed {target.platform} manifest",
        must_exist=True,
    )
    expected_source = {
        "index_path": freeze._relative_repo_path(repo, index_path),
        "index_sha256": freeze._sha256_file(index_path),
        "platform_manifest_path": freeze._relative_repo_path(
            repo, platform_manifest_path
        ),
        "platform_manifest_sha256": platform_ref.get("sha256"),
        "artifact_input_fingerprint_sha256": platform_ref.get(
            "artifact_input_fingerprint_sha256"
        ),
        "shared_revision": verified_index.get("shared_revision"),
    }
    if source != expected_source:
        raise UploadReadinessError(
            f"{target_id} dependency/source freeze binding changed."
        )
    build_receipt_path = freeze.secure_repo_path(
        repo,
        pathlib.Path(str(build_receipt.get("path"))),
        f"{target_id} build receipt",
        must_exist=True,
    )
    if target.manifest_verifier_path is not None:
        build_result = _verify_manifest_build_receipt(
            repo, target, build_receipt_path, artifact_path
        )
        build_target = build_result.get("target")
        build_producer = build_result.get("producer")
    else:
        build_result = freeze.verify_build_receipt(
            repo,
            index_path,
            target.platform,
            build_receipt_path,
            artifact_path,
        )
        build_record = _load_json(build_receipt_path, f"{target_id} build receipt")
        build_toolchain = _exact(
            build_record.get("toolchain"),
            {"name", "version", "revision", "target"},
            f"{target_id} build receipt toolchain",
        )
        build_producer = _exact(
            build_record.get("producer"),
            {"path", "sha256"},
            f"{target_id} build receipt producer",
        )
        build_target = build_toolchain.get("target")
    expected_build_receipt = {
        "path": freeze._relative_repo_path(repo, build_receipt_path),
        "sha256": build_result["receipt_sha256"],
        "target": target.build_receipt_target,
    }
    if (
        build_receipt != expected_build_receipt
        or build_target != target.build_receipt_target
        or build_producer
        != {
            "path": producer_id,
            "sha256": producer.get("sha256"),
        }
        or build_result["artifact_sha256"] != artifact_sha
        or build_result["artifact_size_bytes"] != artifact_bytes
    ):
        raise UploadReadinessError(
            f"{target_id} exact build receipt binding is invalid."
        )
    if gate_references is not None and set(gate_references) != {
        target.signing_gate_id,
        target.hardening_gate_id,
    }:
        raise UploadReadinessError(
            f"{target_id} executed gate reference set is not exact."
        )
    signing_reference = (
        gate_references[target.signing_gate_id]
        if gate_references is not None
        else record.get("signing_verification_gate")
    )
    hardening_reference = (
        gate_references[target.hardening_gate_id]
        if gate_references is not None
        else record.get("obfuscation_privacy_gate")
    )
    gate_verified_at = gate_verified_at or verified_at
    signing = _verify_gate_evidence(
        repo,
        target,
        signing_reference,
        target.signing_gate_id,
        artifact_binding,
        artifact_time,
        gate_verified_at,
    )
    hardening = _verify_gate_evidence(
        repo,
        target,
        hardening_reference,
        target.hardening_gate_id,
        artifact_binding,
        artifact_time,
        gate_verified_at,
    )
    signing_end = _safe_time(
        signing.get("ended_utc"), f"{target_id} signing gate end"
    )
    hardening_start = _safe_time(
        hardening.get("started_utc"), f"{target_id} hardening gate start"
    )
    if (
        signing.get("transaction_id") != hardening.get("transaction_id")
        or signing.get("command_order") != 0
        or hardening.get("command_order") != 1
        or signing.get("previous_evidence_sha256") is not None
        or hardening.get("previous_evidence_sha256")
        != signing.get("evidence_sha256")
        or signing_end > hardening_start
    ):
        raise UploadReadinessError(
            f"{target_id} executed gate command order or hash chain is invalid."
        )
    if target.platform == "extension":
        expected_closure = _verify_extension_verifier_closure(
            repo, target_id, record.get("verifier_source_closure")
        )
        zip_result = verify_extension_zip_artifact(repo, target_id, artifact_path)
        if zip_result["verifier_source_closure"] != expected_closure:
            raise UploadReadinessError(
                f"{target_id} verifier source closure changed during zip verification."
            )
        if (
            zip_result["artifact_sha256"] != artifact_sha
            or zip_result["artifact_bytes"] != artifact_bytes
        ):
            raise UploadReadinessError(
                f"{target_id} zip verification is not bound to the receipt artifact identity."
            )
    elif "verifier_source_closure" in record:
        raise UploadReadinessError(
            f"{target_id} receipt must not carry an extension verifier closure."
        )
    if (
        record.get("ok") is not True
        or type(record.get("schema_version")) is not int
        or record.get("schema_version") != TARGET_RECEIPT_SCHEMA_VERSION
        or record.get("contract") != TARGET_RECEIPT_CONTRACT
        or record.get("release") != freeze._release_identity(repo)
        or record.get("target_id") != target_id
        or record.get("platform") != target.platform
        or record.get("publication_authorized") is not False
        or record.get("upload_attempted") is not False
    ):
        raise UploadReadinessError(
            f"{target_id} receipt binding is invalid or changed."
        )
    verified = {
        "receipt_path": freeze._relative_repo_path(repo, receipt_path),
        "receipt_sha256": receipt_sha,
        "release": record.get("release"),
        "build_receipt": expected_build_receipt,
        "artifact": artifact_binding,
        "producer_id": producer_id,
        "signing_verification_gate": signing,
        "obfuscation_privacy_gate": hardening,
        "dependency_source_freeze": expected_source,
        "verified_utc": record.get("verified_utc"),
    }
    if target.platform == "extension":
        verified["verifier_source_closure"] = record.get("verifier_source_closure")
    return verified


def verify_target_receipt_current(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    target_id: str,
    receipt_path: pathlib.Path,
    *,
    now: dt.datetime | None = None,
    runner: gate_runner.ExplicitArgvRunner | None = None,
    evidence_dir: pathlib.Path | None = None,
) -> dict[str, object]:
    """Verify one receipt and re-execute both gates against its current artifact.

    Historical gate evidence proves what ran when the receipt was produced. It
    does not prove that the artifact still passes the platform verifier now.
    This entry point first validates the complete stored receipt, then derives
    the canonical gate argv from that receipt and runs the exact signing and
    hardening pair against the currently bound bytes.
    """

    if target_id not in TARGET_BY_ID:
        raise UploadReadinessError(f"Unexpected upload target: {target_id}")
    _reject_caller_supplied_runner(runner)
    verification_time = now or dt.datetime.now(tz=dt.timezone.utc)
    repo = freeze.secure_repo_path(
        repo, pathlib.Path("."), "Repository root", must_exist=True
    )
    index_path = freeze.secure_repo_path(
        repo, index_path, "Release input index", must_exist=True
    )
    receipt_path = freeze.secure_repo_path(
        repo, receipt_path, f"{target_id} upload receipt", must_exist=True
    )
    _verify_target_receipt(
        repo,
        index_path,
        target_id,
        receipt_path,
        now=verification_time,
    )
    target = TARGET_BY_ID[target_id]
    artifact_path, commands = _execution_request_from_receipt(
        repo, target, receipt_path
    )
    if evidence_dir is None:
        evidence_dir = pathlib.Path(
            ".artifacts/cross-store-current-verification/"
            f"{uuid.uuid4()}/{target_id}"
        )
    fresh_gate_references = execute_target_gate_transaction(
        repo,
        target_id,
        artifact_path,
        commands,
        evidence_dir,
        runner=runner,
        clock=lambda: verification_time,
    )
    return _verify_target_receipt(
        repo,
        index_path,
        target_id,
        receipt_path,
        now=verification_time,
        gate_references=fresh_gate_references,
        gate_verified_at=verification_time,
    )


def _receipt_paths(
    repo: pathlib.Path, receipts: Iterable[str]
) -> dict[str, pathlib.Path]:
    parsed: dict[str, pathlib.Path] = {}
    identities: set[tuple[int, int]] = set()
    for raw in receipts:
        target_id, path = _parse_receipt_binding(raw)
        if target_id in parsed:
            raise UploadReadinessError(f"Duplicate receipt for target: {target_id}")
        path = freeze.secure_repo_path(
            repo, path, f"{target_id} upload receipt", must_exist=True
        )
        info = path.stat()
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise UploadReadinessError(
                "Each upload target requires a distinct receipt path."
            )
        parsed[target_id] = path
        identities.add(identity)
    missing = REQUIRED_TARGET_IDS - set(parsed)
    unexpected = set(parsed) - REQUIRED_TARGET_IDS
    if missing or unexpected:
        detail = []
        if missing:
            detail.append("missing: " + ", ".join(sorted(missing)))
        if unexpected:
            detail.append("unexpected: " + ", ".join(sorted(unexpected)))
        raise UploadReadinessError(
            "Upload target receipt set is not exact (" + "; ".join(detail) + ")."
        )
    return parsed


def _assert_distinct_build_receipts(
    repo: pathlib.Path,
    target_receipts: dict[str, dict[str, object]],
) -> None:
    identities: set[tuple[int, int]] = set()
    for target_id, receipt in target_receipts.items():
        path = freeze.secure_repo_path(
            repo,
            pathlib.Path(str(receipt["build_receipt"]["path"])),
            f"{target_id} exact build receipt",
            must_exist=True,
        )
        info = path.stat()
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise UploadReadinessError(
                "Each upload target requires a distinct exact build receipt."
            )
        identities.add(identity)


def _assert_distinct_artifacts(
    repo: pathlib.Path,
    target_receipts: dict[str, dict[str, object]],
) -> None:
    file_identities: set[tuple[int, int]] = set()
    content_hashes: set[str] = set()
    for target_id, receipt in target_receipts.items():
        artifact = receipt.get("artifact")
        if not isinstance(artifact, dict):
            raise UploadReadinessError(f"{target_id} exact artifact binding is malformed.")
        path = freeze.secure_repo_path(
            repo,
            pathlib.Path(str(artifact.get("path"))),
            f"{target_id} exact artifact",
            must_exist=True,
        )
        info = path.stat()
        identity = (info.st_dev, info.st_ino)
        digest = str(artifact.get("sha256") or "")
        if info.st_nlink != 1:
            raise UploadReadinessError(
                f"{target_id} exact artifact must be an immutable exclusive file identity."
            )
        if identity in file_identities or digest in content_hashes:
            raise UploadReadinessError(
                "Each upload target requires distinct artifact bytes and file identity."
            )
        file_identities.add(identity)
        content_hashes.add(digest)


def record_evidence(
    repo: pathlib.Path,
    output: pathlib.Path,
    index_path: pathlib.Path | None = None,
    receipts: tuple[str, ...] = (),
    gcp_proof_acceptance_receipt: pathlib.Path | None = None,
    *,
    runner: gate_runner.ExplicitArgvRunner | None = None,
) -> dict[str, object]:
    evaluation = evaluate_source_gates(repo)
    repo = freeze.secure_repo_path(
        repo, pathlib.Path("."), "Repository root", must_exist=True
    )
    if index_path is None:
        raise UploadReadinessError("A complete release input index is required.")
    if not evaluation["local_gate_bindings_complete"]:
        raise UploadReadinessError(
            "Required upload targets are not all supported by dependency-freeze "
            "build receipts: "
            + ", ".join(evaluation["unsupported_build_receipt_targets"])
        )
    index_path = freeze.secure_repo_path(
        repo, index_path, "Release input index", must_exist=True
    )
    verified_index = freeze.verify_release_index(repo, index_path)
    if set(verified_index["platforms"]) != set(freeze.CANONICAL_FREEZE_PLATFORMS):
        raise UploadReadinessError("Release input index platform set is incomplete.")
    if gcp_proof_acceptance_receipt is None:
        configured_receipt = os.environ.get(
            "WINS_GCP_PROOF_ACCEPTANCE_RECEIPT", ""
        ).strip()
        if not configured_receipt:
            raise UploadReadinessError(
                "A current WINS_GCP_PROOF_ACCEPTANCE_RECEIPT is required before "
                "cross-store readiness can be recorded."
            )
        gcp_proof_acceptance_receipt = pathlib.Path(configured_receipt)
    gcp_receipt_reference = _verify_gcp_proof_acceptance_receipt(
        repo, index_path, gcp_proof_acceptance_receipt
    )
    parsed = _receipt_paths(repo, receipts)
    owner_evidence_paths = {
        PLAY_DECLARATIONS,
        OWNER_SIGNOFF,
        CHECKLIST,
        *(spec.path for spec in PLATFORM_OWNER_EVIDENCE),
    }
    for target_id, receipt_path in parsed.items():
        relative = freeze._relative_repo_path(repo, receipt_path)
        if relative in owner_evidence_paths:
            raise UploadReadinessError(
                f"{target_id} upload receipt must stay separate from owner evidence."
            )
    _reject_caller_supplied_runner(runner)
    execution_batch = str(uuid.uuid4())
    target_receipts: dict[str, dict[str, object]] = {}
    for target in REQUIRED_UPLOAD_TARGETS:
        _verify_target_receipt(
            repo,
            index_path,
            target.target_id,
            parsed[target.target_id],
        )
        artifact_path, commands = _execution_request_from_receipt(
            repo, target, parsed[target.target_id]
        )
        gate_references = execute_target_gate_transaction(
            repo,
            target.target_id,
            artifact_path,
            commands,
            pathlib.Path(
                f".artifacts/cross-store-machine-gates/{execution_batch}/"
                f"{target.target_id}"
            ),
            runner=runner,
        )
        gate_verified_at = dt.datetime.now(tz=dt.timezone.utc)
        target_receipts[target.target_id] = _verify_target_receipt(
            repo,
            index_path,
            target.target_id,
            parsed[target.target_id],
            gate_references=gate_references,
            gate_verified_at=gate_verified_at,
        )
    _assert_distinct_build_receipts(repo, target_receipts)
    _assert_distinct_artifacts(repo, target_receipts)
    current_closure = _producer_verifier_closure(repo)
    if current_closure != evaluation["producer_verifier_closure"]:
        raise UploadReadinessError(
            "Producer/verifier closure changed while recording upload readiness."
        )
    recorded_index = {
        "path": freeze._relative_repo_path(repo, index_path),
        "sha256": freeze._sha256_file(index_path),
        "release": verified_index["release"],
        "shared_revision": verified_index["shared_revision"],
    }
    owner_blockers = evaluation["owner_blockers"]
    status = _readiness_status(
        owner_blockers=owner_blockers,
        local_artifacts_ready=True,
    )
    record = {
        "ok": status == READINESS_STATUS_LOCAL_READY,
        "status": status,
        "schema_version": SCHEMA_VERSION,
        "contract": CONTRACT,
        "release": verified_index["release"],
        "created_utc": freeze._utc_now(),
        "privacy_policy_url": freeze.PRIVACY_POLICY_URL,
        "checklist": CHECKLIST,
        "freeze_platforms_complete": True,
        "platforms": evaluation["platforms"],
        "required_targets": evaluation["required_targets"],
        "required_target_ids": evaluation["required_target_ids"],
        "planned_unsupported_targets": evaluation["planned_unsupported_targets"],
        "release_input_index": recorded_index,
        "gcp_proof_acceptance_receipt": gcp_receipt_reference,
        "target_receipts": target_receipts,
        "missing_target_receipts": [],
        "unsupported_build_receipt_targets": [],
        "local_gate_bindings_complete": True,
        "local_gates_executed": True,
        "local_artifacts_ready": True,
        "producer_verifier_closure": evaluation["producer_verifier_closure"],
        "publication_authorized": False,
        "store_upload_authorized": False,
        "upload_attempted": False,
        "owner_blockers": owner_blockers,
        "sha256_anchor": pathlib.Path(str(output)).name + ".sha256",
    }
    freeze._write_anchored_record(
        repo, output, record, "Cross-store upload-readiness evidence"
    )
    return record


def verify_evidence(
    repo: pathlib.Path,
    evidence_path: pathlib.Path,
    index_path: pathlib.Path | None = None,
    *,
    runner: gate_runner.ExplicitArgvRunner | None = None,
) -> dict[str, object]:
    evaluation = evaluate_source_gates(repo)
    repo = freeze.secure_repo_path(
        repo, pathlib.Path("."), "Repository root", must_exist=True
    )
    evidence_path = freeze.secure_repo_path(
        repo,
        evidence_path,
        "Cross-store upload-readiness evidence",
        must_exist=True,
    )
    digest = freeze._verify_anchor(
        repo, evidence_path, "Cross-store upload-readiness evidence"
    )
    record = _exact(
        _load_json(evidence_path, "Cross-store upload-readiness evidence"),
        {
            "ok",
            "status",
            "schema_version",
            "contract",
            "release",
            "created_utc",
            "privacy_policy_url",
            "checklist",
            "freeze_platforms_complete",
            "platforms",
            "required_targets",
            "required_target_ids",
            "planned_unsupported_targets",
            "release_input_index",
            "gcp_proof_acceptance_receipt",
            "target_receipts",
            "missing_target_receipts",
            "unsupported_build_receipt_targets",
            "local_gate_bindings_complete",
            "local_gates_executed",
            "local_artifacts_ready",
            "producer_verifier_closure",
            "publication_authorized",
            "store_upload_authorized",
            "upload_attempted",
            "owner_blockers",
            "sha256_anchor",
        },
        "Cross-store upload-readiness evidence",
    )
    expected_status = _readiness_status(
        owner_blockers=evaluation["owner_blockers"],
        local_artifacts_ready=True,
    )
    expected_ok = expected_status == READINESS_STATUS_LOCAL_READY
    if record.get("status") != expected_status or record.get("ok") is not expected_ok:
        raise UploadReadinessError(
            "Cross-store upload-readiness evidence status is not an honest "
            "BLOCKED/LOCAL_READY record of current owner evidence."
        )
    created = _safe_time(
        record.get("created_utc"), "Cross-store upload-readiness evidence"
    )
    now = dt.datetime.now(tz=dt.timezone.utc)
    if created > now + MAX_CLOCK_SKEW or now - created > MAX_RECEIPT_AGE:
        raise UploadReadinessError(
            "Cross-store upload-readiness evidence is stale or future-dated."
        )
    index_ref = _exact(
        record.get("release_input_index"),
        {"path", "sha256", "release", "shared_revision"},
        "Recorded release input index",
    )
    recorded_index_path = freeze.secure_repo_path(
        repo,
        pathlib.Path(str(index_ref.get("path"))),
        "Recorded release input index",
        must_exist=True,
    )
    if index_path is not None:
        index_path = freeze.secure_repo_path(
            repo, index_path, "Release input index", must_exist=True
        )
        if recorded_index_path != index_path:
            raise UploadReadinessError("Evidence is bound to a different freeze index.")
    verified_index = freeze.verify_release_index(repo, recorded_index_path)
    expected_index = {
        "path": freeze._relative_repo_path(repo, recorded_index_path),
        "sha256": freeze._sha256_file(recorded_index_path),
        "release": verified_index["release"],
        "shared_revision": verified_index["shared_revision"],
    }
    recorded_gcp_receipt = _exact(
        record.get("gcp_proof_acceptance_receipt"),
        {
            "path",
            "sha256",
            "created_utc",
            "release",
            "release_input_index",
            "client_build_identity",
        },
        "Recorded GCP proof acceptance receipt",
    )
    reverified_gcp_receipt = _verify_gcp_proof_acceptance_receipt(
        repo,
        recorded_index_path,
        pathlib.Path(str(recorded_gcp_receipt["path"])),
    )
    if reverified_gcp_receipt != recorded_gcp_receipt:
        raise UploadReadinessError(
            "Recorded GCP proof acceptance receipt identity changed."
        )
    receipts = record.get("target_receipts")
    if not isinstance(receipts, dict) or set(receipts) != REQUIRED_TARGET_IDS:
        raise UploadReadinessError("Recorded upload target receipt set is not exact.")
    verified_receipts: dict[str, dict[str, object]] = {}
    used_paths: set[str] = set()
    _reject_caller_supplied_runner(runner)
    reexecution_batch = str(uuid.uuid4())
    reexecuted_target_count = 0
    for target in REQUIRED_UPLOAD_TARGETS:
        binding = _exact(
            receipts[target.target_id],
            _recorded_target_receipt_keys(target),
            f"Recorded {target.target_id} receipt",
        )
        receipt_path = str(binding.get("receipt_path"))
        if receipt_path in used_paths:
            raise UploadReadinessError(
                "Each upload target must bind a distinct receipt path."
            )
        used_paths.add(receipt_path)
        recorded_gate_references: dict[str, dict[str, object]] = {}
        for gate_field, gate_id in (
            ("signing_verification_gate", target.signing_gate_id),
            ("obfuscation_privacy_gate", target.hardening_gate_id),
        ):
            recorded_gate = binding.get(gate_field)
            if not isinstance(recorded_gate, dict):
                raise UploadReadinessError(
                    f"{target.target_id} recorded {gate_id} gate is malformed."
                )
            recorded_gate_references[gate_id] = {
                "id": gate_id,
                "status": "passed",
                "executed_utc": recorded_gate.get("executed_utc"),
                "evidence_path": recorded_gate.get("evidence_path"),
                "evidence_sha256": recorded_gate.get("evidence_sha256"),
            }
        verified_receipts[target.target_id] = _verify_target_receipt(
            repo,
            recorded_index_path,
            target.target_id,
            pathlib.Path(receipt_path),
            now=now,
            gate_references=recorded_gate_references,
            gate_verified_at=now,
        )
        if verified_receipts[target.target_id] != binding:
            raise UploadReadinessError(
                f"{target.target_id} recorded receipt identity changed."
            )
        source_receipt_path = freeze.secure_repo_path(
            repo,
            pathlib.Path(receipt_path),
            f"{target.target_id} source receipt",
            must_exist=True,
        )
        artifact_path, commands = _execution_request_from_receipt(
            repo, target, source_receipt_path
        )
        fresh_gate_references = execute_target_gate_transaction(
            repo,
            target.target_id,
            artifact_path,
            commands,
            pathlib.Path(
                f".artifacts/cross-store-reverification/{reexecution_batch}/"
                f"{target.target_id}"
            ),
            runner=runner,
        )
        _verify_target_receipt(
            repo,
            recorded_index_path,
            target.target_id,
            source_receipt_path,
            now=now,
            gate_references=fresh_gate_references,
            gate_verified_at=dt.datetime.now(tz=dt.timezone.utc),
        )
        reexecuted_target_count += 1
    _assert_distinct_build_receipts(repo, verified_receipts)
    _assert_distinct_artifacts(repo, verified_receipts)
    if _producer_verifier_closure(repo) != evaluation["producer_verifier_closure"]:
        raise UploadReadinessError(
            "Producer/verifier closure changed while verifying upload readiness."
        )
    if (
        record.get("schema_version") != SCHEMA_VERSION
        or record.get("contract") != CONTRACT
        or record.get("release") != verified_index["release"]
        or record.get("privacy_policy_url") != freeze.PRIVACY_POLICY_URL
        or record.get("checklist") != CHECKLIST
        or record.get("freeze_platforms_complete") is not True
        or record.get("platforms") != evaluation["platforms"]
        or record.get("required_targets") != evaluation["required_targets"]
        or record.get("required_target_ids") != evaluation["required_target_ids"]
        or record.get("planned_unsupported_targets")
        != evaluation["planned_unsupported_targets"]
        or record.get("release_input_index") != expected_index
        or record.get("gcp_proof_acceptance_receipt") != reverified_gcp_receipt
        or record.get("missing_target_receipts") != []
        or record.get("unsupported_build_receipt_targets") != []
        or evaluation["unsupported_build_receipt_targets"] != []
        or record.get("local_gate_bindings_complete") is not True
        or record.get("local_gates_executed") is not True
        or record.get("local_artifacts_ready") is not True
        or record.get("producer_verifier_closure")
        != evaluation["producer_verifier_closure"]
        or record.get("status") != expected_status
        or record.get("ok") is not expected_ok
        or record.get("publication_authorized") is not False
        or record.get("store_upload_authorized") is not False
        or record.get("upload_attempted") is not False
        or record.get("owner_blockers") != evaluation["owner_blockers"]
        or record.get("sha256_anchor") != evidence_path.name + ".sha256"
    ):
        raise UploadReadinessError(
            "Cross-store upload-readiness evidence binding is invalid or changed."
        )
    return {
        "ok": expected_ok,
        "status": expected_status,
        "kind": "cross-store-upload-readiness",
        "release": record.get("release"),
        "evidence_sha256": digest,
        "required_target_count": len(REQUIRED_UPLOAD_TARGETS),
        "verified_target_count": len(verified_receipts),
        "local_gates_executed": True,
        "local_gates_reexecuted": True,
        "reexecuted_target_count": reexecuted_target_count,
        "local_artifacts_ready": True,
        "gcp_proof_accepted": True,
        "publication_authorized": False,
        "store_upload_authorized": False,
        "owner_blockers": evaluation["owner_blockers"],
        "owner_blocker_count": len(evaluation["owner_blockers"]),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Record or verify local cross-store upload readiness. Never uploads."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--repo", default=".")
    record = subparsers.add_parser("record")
    record.add_argument("--repo", default=".")
    record.add_argument("--output", required=True)
    record.add_argument("--index", required=True)
    record.add_argument("--receipt", action="append", default=[])
    record.add_argument("--gcp-proof-acceptance-receipt", type=pathlib.Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--repo", default=".")
    verify.add_argument("--evidence", required=True)
    verify.add_argument("--index")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "evaluate":
            result = evaluate_source_gates(pathlib.Path(args.repo))
        elif args.command == "record":
            result = record_evidence(
                pathlib.Path(args.repo),
                pathlib.Path(args.output),
                pathlib.Path(args.index),
                tuple(args.receipt),
                args.gcp_proof_acceptance_receipt,
            )
        else:
            result = verify_evidence(
                pathlib.Path(args.repo),
                pathlib.Path(args.evidence),
                pathlib.Path(args.index) if args.index else None,
            )
    except (UploadReadinessError, freeze.DependencyFreezeError) as exc:
        print(f"CROSS-STORE UPLOAD READINESS: FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
