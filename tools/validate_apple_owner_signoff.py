#!/usr/bin/env python3
"""Validate the local App Store owner sign-off manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

import apple_store_listing_metadata as listing
import apple_watch_companion_smoke as watch_smoke
from apple_final_evidence_collector import (
    CANONICAL_APP_VERSION,
    CANONICAL_BUILD_NUMBER,
    CANONICAL_RELEASE,
    COMPLETE_LOCAL_CANDIDATES,
    HOST_BUNDLE_ID,
    NO_CURRENT_CANDIDATE,
    OWNER_AUTHORIZATION_CONTRACT,
    OWNER_EVIDENCE_SET_KEYS,
    PACKET_TUNNEL_BUNDLE_ID,
    REQUIRED_MACOS_ARCHITECTURES,
    REQUIRED_OWNER_SURFACES,
    STALE_BUILD_29_SHA256,
    WATCH_BUNDLE_ID,
    WATCH_EXECUTABLE,
    CollectorError,
    canonical_owner_evidence_set,
    embedded_watch_identity_from_ipa,
    evidence_set_is_complete,
    owner_evidence_set_sha256,
    pending_owner_evidence_set,
    reject_mutable_tmp_authority,
    reject_stale_build_29_digest,
    sha256_file as collector_sha256_file,
    validate_macos_architecture_inventory,
)


REQUIRED_DECISIONS = {
    "app_information",
    "storefront_description",
    "storefront_release_notes",
    "pricing_and_availability",
    "app_privacy_answers",
    "coarse_location_privacy_answer",
    "purchase_history_privacy_answer",
    "export_compliance_answers",
    "age_rating_answers",
    "review_contact_and_notes",
    "ios_review_notes",
    "macos_review_notes",
    "testflight_information",
    "screenshot_set",
    "platform_submission_order",
    "release_candidate_artifacts",
    "credentials_and_secret_hygiene",
    "final_upload_authorization",
}

ALLOWED_STATUSES = {"pending", "approved", "rejected"}

# The iOS app and its embedded watchOS companion install under this display
# name (owner ruling 2026-10-25: "Win's VPN", matching the Mac app and the App
# Store record; it was the cover name "Calculator" from the 2026-10-16 ruling
# until App Store Connect refused that name with ITMS-90129). It is the
# CFBundleDisplayName of ios/Runner/Info.plist and of the Watch app's
# Info.plist, which test_apple_owner_authorization binds to this constant.
# Review copy and owner approvals take the device label from here only.
IOS_DISPLAY_NAME = "Win's VPN"
# The calculator safety screen and alternate calculator icon stay, so the
# feature is still called calculator camouflage; only the installed name changed.
CAMOUFLAGE_FEATURE_NAME = "Calculator camouflage"
# Review copy discloses the device label only through a phrase that puts the
# exact, case-sensitive name after the label and ends it at a word boundary, so
# an older name ("Calculator", "Basic Calc") or a lower-case variant does not
# count. Whitespace is collapsed first, so a wrapped line still counts.
DEVICE_LABEL_DISCLOSURE_PATTERNS = tuple(
    re.compile(rf"{re.escape(lead)} {re.escape(IOS_DISPLAY_NAME)}\b")
    for lead in ("device-visible name", "device label", "device label is")
)
# Owner approvals name the device label the same way.
APPROVED_INSTALLED_NAME_MARKER = f"installed name {IOS_DISPLAY_NAME}"
APPROVED_DEVICE_LABEL_MARKER = f"device label {IOS_DISPLAY_NAME}"

SECRET_MARKERS = [
    "BEGIN PRIVATE KEY",
    "AuthKey_",
    "WINS_APPLE_AUTHENTICATION_KEY_ID=",
    "WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID=",
    "client_private_key",
    "Password:",
    "ssh root@",
]

REQUIRED_APPROVED_VALUE_MARKERS = {
    "app_information": [
        "Win's VPN",
        "org.winsvpn.app",
        "universal purchase",
        "support",
        "privacy",
    ],
    "storefront_description": [
        "App Store description",
        CAMOUFLAGE_FEATURE_NAME,
        APPROVED_INSTALLED_NAME_MARKER,
        "privacy types",
    ],
    "storefront_release_notes": [
        "What's New",
        CAMOUFLAGE_FEATURE_NAME,
        APPROVED_INSTALLED_NAME_MARKER,
        "no in-app purchases",
    ],
    "pricing_and_availability": [
        "Free",
        "no IAP",
        "manual release",
    ],
    "app_privacy_answers": [
        "Tracking no",
        "User ID",
        "Device ID",
        "Coarse Location",
        "Product Interaction",
        "Purchase History not collected",
        "PacketTunnel",
    ],
    "coarse_location_privacy_answer": [
        "Coarse Location",
        "linked to the user",
        "app functionality",
        "Cloudflare",
        "first-party",
        "Apple MapKit",
    ],
    "purchase_history_privacy_answer": [
        "Purchase History",
        "not collected",
        "Apple app",
    ],
    "export_compliance_answers": [
        "VPN",
        "encryption",
        "App Store Connect",
    ],
    "age_rating_answers": [
        "Age",
        "App Store Connect",
    ],
    "review_contact_and_notes": [
        "App Review",
        "support",
        "Try Free Server",
    ],
    "ios_review_notes": [
        "iOS",
        "test flow",
        "six-digit",
        APPROVED_DEVICE_LABEL_MARKER,
        "non-VPN",
        "watchOS",
        "Product Interaction",
    ],
    "macos_review_notes": [
        "macOS",
        "test flow",
        "Product Interaction",
    ],
    "testflight_information": [
        "TestFlight",
        "feedback",
    ],
    "screenshot_set": [
        "screenshot",
        "iPhone",
        "Mac",
    ],
    "platform_submission_order": [
        "iOS",
        "macOS",
        "watchOS",
    ],
    "release_candidate_artifacts": [
        "iOS",
        "macOS",
        "watchOS",
        "IPA",
        "PKG",
        "runtime evidence",
        "arm64",
        "x86_64",
    ],
    "credentials_and_secret_hygiene": [
        "outside repo",
        "environment",
    ],
    "final_upload_authorization": [
        "upload lane",
        "authorized",
    ],
}

SCREENSHOT_CANDIDATES = [
    "app_store/apple/screenshots/candidates/ios-6_9/01-main.png",
    "app_store/apple/screenshots/candidates/macos-16_10/01-main.png",
]

OWNER_REVIEW_PACKET = "app_store/apple/review/owner_review_packet.md"
PRIVACY_SNAPSHOT = "app_store/apple/review/privacy_label_manifest.json"
# The two review notes are owner-approved decisions (owner_signoff.json
# ios_review_notes and macos_review_notes) that reach App Review as typed. Unlike
# the marketing copy they have no frozen hash in the submission validator, so
# their exact bytes are pinned here: any later edit fails this validator until
# the owner re-approves and the pin is refreshed in the same change (R24 V2 F-12).
REVIEW_NOTES_SHA256 = {
    "app_store/apple/review/ios_review_notes.txt": "ecc9fffc8106ef7ec86908f0c2a3dfa00a4ec374303e06d843a4acaa15b1559d",
    "app_store/apple/review/macos_review_notes.txt": "c1ddd7bc7397892ded6cbada722bed78c82668623b4a3ed8cf5f9f54c3c06a39",
}
REVIEW_COPY_RELATIVE_PATHS = (
    "app_store/apple/review/ios_review_notes.txt",
    "app_store/apple/review/macos_review_notes.txt",
    "app_store/apple/review/app_review_information.md",
    "app_store/apple/review/privacy_answers.md",
    OWNER_REVIEW_PACKET,
    "app_store/apple/review/owner_signoff.json",
)
REVIEW_COPY_REQUIRED_MARKERS = {
    "app_store/apple/review/ios_review_notes.txt": [
        "six-digit",
        "non-VPN",
        "watchOS companion",
        "Product Interaction",
        "User ID",
        "Device ID",
        "Coarse Location",
        f"no current {CANONICAL_RELEASE}",
    ],
    "app_store/apple/review/macos_review_notes.txt": [
        "Product Interaction",
        "User ID",
        "Device ID",
        "Coarse Location",
        f"no current {CANONICAL_RELEASE}",
        "non-VPN",
    ],
    "app_store/apple/review/app_review_information.md": [
        "six-digit",
        "non-VPN",
        "watchOS",
        "Product Interaction",
        f"no current {CANONICAL_RELEASE}",
        "Try Free Server",
    ],
    "app_store/apple/review/privacy_answers.md": [
        "Usage Data: Product Interaction",
        "six-digit",
        "non-VPN",
        "Identifiers: User ID",
        "Identifiers: Device ID",
        "Coarse Location: linked to the user for app functionality",
    ],
    OWNER_REVIEW_PACKET: [
        "Product Interaction",
        "six-digit",
        "non-VPN",
        "submission_approved",
        f"no current `{CANONICAL_RELEASE}` candidate set",
        "pending-owner-review: iPhone screenshot",
    ],
    "app_store/apple/review/owner_signoff.json": [
        "Product Interaction",
        "six-digit",
        "non-VPN",
    ],
}
STALE_PIN_COPY_MARKERS = (
    "four-digit",
    "4-digit",
    "`0000`",
    "tap 0 six times",
)
STALE_ALL_ZERO_PIN_RE = re.compile(r"(?<![0-9a-fA-F])000000(?![0-9a-fA-F])")
STALE_CURRENT_CANDIDATE_CLAIM_MARKERS = (
    "candidate passed",
    "current universal-identifier",
)
RELEASE_CANDIDATE = "app_store/apple/artifacts/release_candidate.json"
RUNTIME_EVIDENCE = "app_store/apple/artifacts/runtime_evidence.json"
FINAL_APPROVED_SCOPE = ["ios", "macos", "watchos"]
WATCH_COMPANION_FIELDS = {
    "status",
    "bundle_id",
    "companion_bundle_id",
    "version",
    "build",
    "executable",
    "executable_sha256",
    "privacy_info_sha256",
}
OWNER_AUTHORIZATION_FIELDS = {
    "contract",
    "status",
    "credentials_authorized",
    "upload_authorized",
    "approved_evidence_set_sha256",
    "evidence",
}
EVIDENCE_PATH_FIELDS = (
    "path",
    "archive_export_log",
    "verification_log",
    "release_input_index",
    "release_input_index_anchor",
    "runtime_log",
    "macos_runtime_log",
    "receipt_path",
)


def _read_ascii_text(path: Path, label: str) -> str:
    raw = path.read_bytes()
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AssertionError(f"{label} must be ASCII only: {exc}") from exc


def validate_review_copy(root: Path | None = None) -> list[str]:
    """Fail closed if local Apple review copy drifts from current policy."""
    root = (root or Path(__file__).resolve().parents[1]).resolve()
    for relative in REVIEW_COPY_RELATIVE_PATHS:
        path = root / relative
        if not path.is_file():
            raise AssertionError(f"missing Apple review copy: {relative}")
        text = _read_ascii_text(path, relative)
        lowered = text.lower()
        for marker in REVIEW_COPY_REQUIRED_MARKERS[relative]:
            if marker.lower() not in lowered:
                raise AssertionError(
                    f"{relative} must disclose {marker!r}"
                )
            if marker == "Product Interaction" and "Product Interaction" not in text:
                raise AssertionError(
                    f"{relative} must disclose Product Interaction"
                )
        collapsed = " ".join(text.split())
        if not any(pattern.search(collapsed) for pattern in DEVICE_LABEL_DISCLOSURE_PATTERNS):
            raise AssertionError(
                f"{relative} must disclose the {IOS_DISPLAY_NAME!r} device label"
            )
        for marker in STALE_PIN_COPY_MARKERS:
            if marker.lower() in lowered:
                raise AssertionError(
                    f"{relative} still contains stale four-digit/000000 PIN copy "
                    f"({marker!r})"
                )
        if STALE_ALL_ZERO_PIN_RE.search(text):
            raise AssertionError(
                f"{relative} still contains stale four-digit/000000 PIN copy "
                "('000000')"
            )
        for marker in STALE_CURRENT_CANDIDATE_CLAIM_MARKERS:
            if marker.lower() in lowered:
                raise AssertionError(
                    f"{relative} still claims a current {CANONICAL_RELEASE} candidate or "
                    f"runtime receipt ({marker!r})"
                )
        pinned = REVIEW_NOTES_SHA256.get(relative)
        if pinned is not None and _sha256_file(path) != pinned:
            raise AssertionError(
                f"{relative} differs from the owner-approved review notes; "
                "re-approval and a REVIEW_NOTES_SHA256 refresh are required"
            )
    return [
        "PASS: review copy discloses Product Interaction, the "
        f"{IOS_DISPLAY_NAME} device label, and six-digit nontrivial PIN policy",
        "PASS: review copy rejects stale four-digit/000000 PIN instructions",
        f"PASS: review copy does not claim a current {CANONICAL_RELEASE} candidate or runtime receipt",
    ]


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _read_json(path: Path) -> tuple[object, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise AssertionError(f"missing owner sign-off manifest: {path}")
    if not text.strip():
        raise AssertionError(f"empty owner sign-off manifest: {path}")
    try:
        return json.loads(text), text
    except json.JSONDecodeError as exc:
        raise AssertionError(f"{path} is not valid JSON: {exc}") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _assert_plain_string(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise AssertionError(f"{label} must be a string")
    if not allow_empty and not value.strip():
        raise AssertionError(f"{label} must not be empty")
    return value.strip()


def _collector(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except CollectorError as exc:
        raise AssertionError(str(exc)) from exc


def _reject_tmp(value: object, label: str) -> None:
    _collector(reject_mutable_tmp_authority, value, label)


def _watch_smoke_sha256(
    root: Path, runtime: dict[str, object], candidate: dict[str, object]
) -> str:
    # R22 Y3 D2: the receipt is re-hashed and its verdict re-derived, as the
    # archive privacy inventory and release input index are, never taken on
    # the recorded digest alone.
    try:
        return watch_smoke.runtime_watch_smoke_sha256(
            root, runtime, candidate, release=CANONICAL_RELEASE
        )
    except watch_smoke.WatchSmokeError as exc:
        raise AssertionError(str(exc)) from exc


def _reject_stale(value: object, label: str) -> None:
    _collector(reject_stale_build_29_digest, value, label)


def _scan_tmp_paths(value: object, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_label = f"{label}.{key}"
            if key in EVIDENCE_PATH_FIELDS:
                _reject_tmp(child, child_label)
            _scan_tmp_paths(child, child_label)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _scan_tmp_paths(child, f"{label}[{index}]")


def _artifact_map(manifest: dict[str, object]) -> dict[str, dict[str, object]]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise AssertionError(
            "release_candidate.json must list exactly two artifacts: "
            "iOS with embedded watchOS and macOS"
        )
    mapping: dict[str, dict[str, object]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise AssertionError("release_candidate.json artifacts must be objects")
        platform = artifact.get("platform")
        if platform not in {"ios", "macos"} or platform in mapping:
            raise AssertionError("release_candidate.json has an unexpected or duplicate platform")
        mapping[str(platform)] = artifact
    if set(mapping) != {"ios", "macos"}:
        raise AssertionError("release_candidate.json must cover iOS and macOS")
    return mapping


def _watch_companion(artifact: dict[str, object]) -> dict[str, object]:
    watch = artifact.get("embedded_watchos_companion")
    if not isinstance(watch, dict) or set(watch) != WATCH_COMPANION_FIELDS:
        raise AssertionError("iOS artifact omitted the embedded watchOS companion identity")
    return watch


def privacy_snapshot_sha256(root: Path) -> str:
    path = root / PRIVACY_SNAPSHOT
    if not path.is_file():
        raise AssertionError(f"missing App Store privacy snapshot: {PRIVACY_SNAPSHOT}")
    return _sha256_file(path)


def _load_manifest(root: Path, relative: str) -> dict[str, object]:
    data, _ = _read_json(root / relative)
    if not isinstance(data, dict):
        raise AssertionError(f"{relative} must contain a JSON object")
    return data


def validate_current_identity(manifest: dict[str, object], label: str) -> None:
    if manifest.get("app_version") != CANONICAL_APP_VERSION:
        raise AssertionError(f"{label} app_version must be {CANONICAL_APP_VERSION}")
    if str(manifest.get("build_number")) != CANONICAL_BUILD_NUMBER:
        raise AssertionError(f"{label} build_number must be {CANONICAL_BUILD_NUMBER}")


def validate_no_stale_build_29_current_state(manifest: dict[str, object], label: str) -> None:
    validate_current_identity(manifest, label)
    for artifact in manifest.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        for field in ("sha256", "path"):
            value = str(artifact.get(field) or "")
            _reject_stale(value, f"{label} {field}")
            if "1.0.14+29" in value or "1.0.14_29" in value:
                raise AssertionError(
                    f"{label} still presents stale build 29 as the current candidate"
                )


def _pending_artifact(artifact: dict[str, object], platform: str) -> None:
    if artifact.get("artifact_status") != NO_CURRENT_CANDIDATE:
        raise AssertionError(
            f"{platform} artifact_status must be {NO_CURRENT_CANDIDATE} until a current candidate exists"
        )
    if artifact.get("lane") != "app_store_local":
        raise AssertionError(f"{platform} lane must remain app_store_local")
    expected_type = "ipa" if platform == "ios" else "pkg"
    if artifact.get("type") != expected_type:
        raise AssertionError(f"{platform} type must be {expected_type}")
    for field in ("path", "sha256", "archive_export_log", "verification_log"):
        if artifact.get(field) not in {"", None}:
            raise AssertionError(
                f"{platform} {field} must stay empty while candidate_set_status is {NO_CURRENT_CANDIDATE}"
            )
    if artifact.get("size_bytes") not in {0, None}:
        raise AssertionError(f"{platform} size_bytes must be 0 while no current candidate exists")
    if artifact.get("bundle_id") != HOST_BUNDLE_ID:
        raise AssertionError(f"{platform} bundle_id must be {HOST_BUNDLE_ID}")
    if artifact.get("packet_tunnel_bundle_id") != PACKET_TUNNEL_BUNDLE_ID:
        raise AssertionError(
            f"{platform} packet_tunnel_bundle_id must be {PACKET_TUNNEL_BUNDLE_ID}"
        )
    if artifact.get("expected_current_bundle_id") != HOST_BUNDLE_ID:
        raise AssertionError(f"{platform} expected_current_bundle_id must be {HOST_BUNDLE_ID}")
    if artifact.get("expected_current_packet_tunnel_bundle_id") != PACKET_TUNNEL_BUNDLE_ID:
        raise AssertionError(
            f"{platform} expected_current_packet_tunnel_bundle_id must be {PACKET_TUNNEL_BUNDLE_ID}"
        )
    if platform == "macos" and "embedded_watchos_companion" in artifact:
        raise AssertionError("macOS must not embed a watchOS companion")
    if platform == "ios" and "shipped_architecture_inventory" in artifact:
        raise AssertionError("iOS must not claim the macOS architecture inventory")
    _reject_tmp(artifact.get("path"), f"{platform} path")
    _require_recorded_app_store_signing(artifact, platform, required=False)


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


def _pending_watch(watch: dict[str, object]) -> None:
    if watch.get("status") != NO_CURRENT_CANDIDATE:
        raise AssertionError("embedded watchOS companion status must stay no_current_candidate")
    if watch.get("bundle_id") != WATCH_BUNDLE_ID:
        raise AssertionError("embedded watchOS companion bundle_id is invalid")
    if watch.get("companion_bundle_id") != HOST_BUNDLE_ID:
        raise AssertionError("embedded watchOS companion host bundle_id is invalid")
    if watch.get("version") != CANONICAL_APP_VERSION:
        raise AssertionError("embedded watchOS companion version must be 1.0.17")
    if str(watch.get("build")) != CANONICAL_BUILD_NUMBER:
        raise AssertionError("embedded watchOS companion build must be 33")
    if watch.get("executable") != WATCH_EXECUTABLE:
        raise AssertionError("embedded watchOS companion executable must be WinsWatch")
    for field in ("executable_sha256", "privacy_info_sha256"):
        if watch.get(field) not in {"", None}:
            raise AssertionError(f"pending watch {field} must be empty")


def evidence_from_repo(root: Path) -> dict[str, object]:
    candidate = _load_manifest(root, RELEASE_CANDIDATE)
    runtime = _load_manifest(root, RUNTIME_EVIDENCE)
    _scan_tmp_paths(
        {key: value for key, value in candidate.items() if key != "historical_non_authoritative"},
        RELEASE_CANDIDATE,
    )
    _scan_tmp_paths(runtime, RUNTIME_EVIDENCE)
    validate_no_stale_build_29_current_state(candidate, RELEASE_CANDIDATE)
    validate_current_identity(runtime, RUNTIME_EVIDENCE)
    snapshot = privacy_snapshot_sha256(root)
    status = candidate.get("candidate_set_status")
    if status == NO_CURRENT_CANDIDATE:
        if candidate.get("upload_status") != "not_uploaded":
            raise AssertionError("no_current_candidate upload_status must be not_uploaded")
        artifacts = _artifact_map(candidate)
        _pending_artifact(artifacts["ios"], "ios")
        _pending_artifact(artifacts["macos"], "macos")
        _pending_watch(_watch_companion(artifacts["ios"]))
        inventory = artifacts["macos"].get("shipped_architecture_inventory")
        _collector(validate_macos_architecture_inventory, inventory, require_complete=False)
        if runtime.get("candidate_set_status") != "pending_current_runtime_evidence":
            raise AssertionError(
                "runtime_evidence.json must stay pending_current_runtime_evidence "
                "while no current Apple candidate exists"
            )
        if runtime.get("runtime_log") not in {"", None} or runtime.get("macos_runtime_log") not in {
            "",
            None,
        }:
            raise AssertionError("pending runtime evidence must not name a log as authority")
        if runtime.get("platform_results") != []:
            raise AssertionError("pending runtime evidence must not reuse platform results")
        _watch_smoke_sha256(root, runtime, candidate)
        return _collector(pending_owner_evidence_set, app_store_privacy_snapshot_sha256=snapshot)

    if status != COMPLETE_LOCAL_CANDIDATES:
        raise AssertionError(
            "release_candidate.json candidate_set_status must be "
            f"{NO_CURRENT_CANDIDATE} or {COMPLETE_LOCAL_CANDIDATES}"
        )
    artifacts = _artifact_map(candidate)
    ios = artifacts["ios"]
    macos = artifacts["macos"]
    watch = _watch_companion(ios)
    for platform, artifact in (("ios", ios), ("macos", macos)):
        relative = str(artifact.get("path") or "")
        _reject_tmp(relative, f"{platform} path")
        if not relative or relative.startswith("/"):
            raise AssertionError(f"{platform} candidate path must be repository-relative")
        path = root / relative
        if not path.is_file():
            raise AssertionError(f"{platform} candidate does not exist: {relative}")
        digest = collector_sha256_file(path)
        if digest != artifact.get("sha256"):
            raise AssertionError(f"{platform} candidate sha256 does not match the artifact bytes")
        _reject_stale(digest, f"{platform} candidate sha256")
        if artifact.get("size_bytes") != path.stat().st_size:
            raise AssertionError(f"{platform} candidate size does not match the artifact bytes")
        if artifact.get("artifact_status") != "current_candidate":
            raise AssertionError(f"{platform} artifact_status must be current_candidate")
        _require_recorded_app_store_signing(artifact, platform, required=True)
    if watch.get("status") != "current_candidate":
        raise AssertionError("embedded watchOS companion must be a current candidate")
    # The watch identity and the release input index are measured from bytes,
    # as the iOS and macOS artifact hashes are above, never taken on shape.
    derived_watch = _collector(
        embedded_watch_identity_from_ipa, root / str(ios.get("path") or "")
    )
    for field, value in derived_watch.items():
        if str(watch.get(field) or "") != str(value):
            raise AssertionError(
                f"embedded watchOS companion {field} does not match the iOS artifact bytes"
            )
    index_relative = str(candidate.get("release_input_index") or "")
    _reject_tmp(index_relative, "release input index")
    if (
        not index_relative
        or index_relative.startswith("/")
        or ".." in Path(index_relative).parts
    ):
        raise AssertionError("release input index path must be repository-relative")
    index_path = root / index_relative
    if not index_path.is_file():
        raise AssertionError(f"release input index does not exist: {index_relative}")
    if collector_sha256_file(index_path) != candidate.get("release_input_index_sha256"):
        raise AssertionError("release input index sha256 does not match the index bytes")
    inventory_relative = str(candidate.get("archive_privacy_inventory") or "")
    _reject_tmp(inventory_relative, "archive privacy inventory")
    if (
        not inventory_relative
        or inventory_relative.startswith("/")
        or ".." in Path(inventory_relative).parts
    ):
        raise AssertionError("archive privacy inventory path must be repository-relative")
    inventory_path = root / inventory_relative
    if not inventory_path.is_file():
        raise AssertionError(f"archive privacy inventory does not exist: {inventory_relative}")
    if collector_sha256_file(inventory_path) != candidate.get("archive_privacy_inventory_sha256"):
        raise AssertionError(
            "archive privacy inventory sha256 does not match the inventory bytes"
        )
    inventory = _collector(
        validate_macos_architecture_inventory,
        macos.get("shipped_architecture_inventory"),
        require_complete=True,
    )
    runtime_path = root / RUNTIME_EVIDENCE
    receipts = candidate.get("final_receipt_sha256")
    if not isinstance(receipts, dict):
        receipts = ios.get("build_receipt_sha256")
        receipt_map = {}
        for name in (
            "release_input_index_sha256",
            "build_receipt_sha256",
            "build_receipt_anchor_sha256",
        ):
            value = candidate.get(name) or ios.get(name) or macos.get(name)
            if value:
                receipt_map[name] = value
        receipts = receipt_map
    watch_companion_smoke_sha256 = _watch_smoke_sha256(root, runtime, candidate)
    if not watch_companion_smoke_sha256:
        # R24 F-R24-03: the freeze completes the candidate set before the Watch
        # companion smoke can be recorded against it (the smoke records only on
        # a complete set), so a complete set with a pending smoke is an honest
        # intermediate state. Every candidate byte above is still measured, but
        # there is no complete evidence set to approve: the owner evidence
        # stays the pending set until the smoke receipt binds.
        return _collector(pending_owner_evidence_set, app_store_privacy_snapshot_sha256=snapshot)
    evidence = {
        "contract": OWNER_AUTHORIZATION_CONTRACT,
        "release": CANONICAL_RELEASE,
        "app_version": CANONICAL_APP_VERSION,
        "build_number": CANONICAL_BUILD_NUMBER,
        "required_surfaces": list(REQUIRED_OWNER_SURFACES),
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
        "runtime_evidence_sha256": _sha256_file(runtime_path),
        "watch_companion_smoke_sha256": watch_companion_smoke_sha256,
        "archive_privacy_inventory_sha256": candidate.get("archive_privacy_inventory_sha256"),
        "app_store_privacy_snapshot_sha256": snapshot,
        "final_receipt_sha256": receipts,
    }
    return _collector(canonical_owner_evidence_set, evidence)


def validate_owner_authorization_schema(
    root: Path,
    *,
    signoff: dict[str, object],
    release_candidate: dict[str, object] | None = None,
    runtime_evidence: dict[str, object] | None = None,
    require_approved: bool = False,
) -> list[str]:
    authorization = signoff.get("owner_authorization")
    if not isinstance(authorization, dict) or set(authorization) != OWNER_AUTHORIZATION_FIELDS:
        raise AssertionError("owner_signoff.json owner_authorization schema is invalid")
    if authorization.get("contract") != OWNER_AUTHORIZATION_CONTRACT:
        raise AssertionError("owner_signoff.json owner authorization contract is invalid")
    evidence = authorization.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != set(OWNER_EVIDENCE_SET_KEYS):
        raise AssertionError("owner_signoff.json owner evidence set fields are invalid")
    canonical = _collector(canonical_owner_evidence_set, evidence)
    if list(canonical["required_surfaces"]) != list(REQUIRED_OWNER_SURFACES):
        raise AssertionError(
            "owner authorization must cover ios, embedded watchos companion, and macos"
        )
    snapshot = privacy_snapshot_sha256(root)
    if canonical["app_store_privacy_snapshot_sha256"] != snapshot:
        raise AssertionError(
            "owner authorization App Store privacy snapshot hash is stale"
        )
    derived = evidence_from_repo(root)
    if canonical != derived:
        raise AssertionError(
            "owner authorization evidence no longer matches the post-build evidence set"
        )
    credentials_authorized = authorization.get("credentials_authorized")
    upload_authorized = authorization.get("upload_authorized")
    if not isinstance(credentials_authorized, bool) or not isinstance(upload_authorized, bool):
        raise AssertionError("owner authorization credential/upload flags must be boolean")
    approved_hash = str(authorization.get("approved_evidence_set_sha256") or "")
    status = str(authorization.get("status") or "")
    candidate_status = (_load_manifest(root, RELEASE_CANDIDATE)).get("candidate_set_status")
    complete = _collector(evidence_set_is_complete, canonical, validate=False)

    if candidate_status == NO_CURRENT_CANDIDATE:
        if status != "pending":
            raise AssertionError("owner authorization status must stay pending without a candidate")
        if complete:
            raise AssertionError("no_current_candidate cannot carry a complete evidence set")
        if credentials_authorized or upload_authorized:
            raise AssertionError(
                "credentials and upload authorization must stay false until real evidence exists"
            )
        if approved_hash:
            raise AssertionError(
                "pending owner authorization cannot carry an approval hash; "
                "that is a false-positive pending state"
            )
        if signoff.get("submission_approved") is True:
            raise AssertionError(
                "submission_approved cannot be true while candidate_set_status is no_current_candidate"
            )
        if require_approved:
            raise AssertionError(
                "owner approval requires a complete current 1.0.17+34 evidence set"
            )
        return [
            "PASS: owner authorization schema is fail-closed with no_current_candidate",
            "PASS: owner authorization covers iOS, embedded watchOS companion, and macOS",
        ]

    if candidate_status == COMPLETE_LOCAL_CANDIDATES and not complete:
        # R24 F-R24-03: a complete candidate set whose Watch companion smoke is
        # still pending derives the pending evidence set; nothing can approve it.
        if status != "pending":
            raise AssertionError(
                "owner authorization status must stay pending until the watch "
                "companion smoke passes on the complete candidate set"
            )
        if credentials_authorized or upload_authorized:
            raise AssertionError(
                "credentials and upload authorization must stay false until real evidence exists"
            )
        if approved_hash:
            raise AssertionError(
                "pending owner authorization cannot carry an approval hash; "
                "that is a false-positive pending state"
            )
        if signoff.get("submission_approved") is True:
            raise AssertionError(
                "submission_approved cannot be true while the watch companion smoke is pending"
            )
        if require_approved:
            raise AssertionError(
                "owner approval requires a passed watch companion smoke on the "
                "complete 1.0.17+34 candidate set"
            )
        return [
            "PASS: owner authorization stays pending while the complete candidate set "
            "awaits its watch companion smoke receipt",
            "PASS: owner authorization covers iOS, embedded watchOS companion, and macOS",
        ]
    if candidate_status != COMPLETE_LOCAL_CANDIDATES or not complete:
        raise AssertionError("owner authorization is neither pending nor complete")
    digest = _collector(owner_evidence_set_sha256, canonical)
    if status == "pending":
        if approved_hash:
            raise AssertionError(
                "pending owner authorization cannot pre-hash a complete evidence set"
            )
        if credentials_authorized or upload_authorized or signoff.get("submission_approved") is True:
            raise AssertionError(
                "complete evidence still requires explicit owner approval before upload"
            )
        if require_approved:
            raise AssertionError("owner_signoff.json submission is not approved")
        return [
            "PASS: owner authorization schema bound a complete unapproved evidence set",
        ]
    if status != "approved":
        raise AssertionError("owner authorization status must be pending or approved")
    if approved_hash != digest:
        raise AssertionError(
            "owner approval is stale; the post-build evidence set hash no longer matches"
        )
    if not credentials_authorized or not upload_authorized:
        raise AssertionError("approved owner authorization must explicitly authorize credentials and upload")
    if require_approved and signoff.get("submission_approved") is not True:
        raise AssertionError("owner_signoff.json submission_approved must be true before upload")
    _ = (release_candidate, runtime_evidence)
    return [
        "PASS: owner authorization hashes the complete post-build evidence set",
        f"PASS: owner authorization evidence set sha256 {digest}",
    ]


def _release_candidate_hash_markers(root: Path) -> list[str]:
    candidate = _load_manifest(root, RELEASE_CANDIDATE)
    if candidate.get("candidate_set_status") == NO_CURRENT_CANDIDATE:
        return [
            NO_CURRENT_CANDIDATE,
            CANONICAL_APP_VERSION,
            CANONICAL_BUILD_NUMBER,
            CANONICAL_RELEASE,
            "watchOS",
            "arm64",
            "x86_64",
        ]
    evidence = evidence_from_repo(root)
    if not _collector(evidence_set_is_complete, evidence, validate=False):
        # R24 F-R24-03: the candidate set is complete but its Watch companion
        # smoke is pending, so there is no evidence-set hash to approve yet.
        return [
            CANONICAL_APP_VERSION,
            CANONICAL_BUILD_NUMBER,
            CANONICAL_RELEASE,
            "watchOS",
            "arm64",
            "x86_64",
            "watch companion smoke",
        ]
    digest = _collector(owner_evidence_set_sha256, evidence)
    markers = [digest, CANONICAL_RELEASE, "watchOS", "arm64", "x86_64"]
    for field in OWNER_EVIDENCE_SET_KEYS:
        value = evidence[field]
        if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
            markers.append(value)
    return markers


def _screenshot_hash_markers(root: Path) -> list[str]:
    markers: list[str] = []
    for relative_path in SCREENSHOT_CANDIDATES:
        path = root / relative_path
        if not path.is_file():
            raise AssertionError(f"missing screenshot candidate for owner approval: {relative_path}")
        markers.append(_sha256_file(path))
    return markers


def _approved_value_markers(root: Path, decision_key: str) -> list[str]:
    markers = list(REQUIRED_APPROVED_VALUE_MARKERS[decision_key])
    if decision_key == "release_candidate_artifacts":
        markers.extend(_release_candidate_hash_markers(root))
    elif decision_key == "screenshot_set":
        markers.extend(_screenshot_hash_markers(root))
    return markers


def _assert_approved_value_is_specific(root: Path, decision_key: str, approved_value: str) -> None:
    normalized_value = approved_value.lower()
    for marker in _approved_value_markers(root, decision_key):
        missing = marker.lower() not in normalized_value
        if not missing and marker.endswith(IOS_DISPLAY_NAME):
            # The device name must match exactly (case-sensitive) and end at a
            # word boundary.
            missing = re.search(rf"{re.escape(marker)}\b", approved_value) is None
        if missing:
            raise AssertionError(
                f"owner_signoff.json decision {decision_key!r} approved_value "
                f"missing required marker {marker!r}"
            )


def owner_packet_approval_values(root: Path | None = None) -> dict[str, str]:
    """Read proposed owner-approved values from the human review packet."""
    root = (root or Path(__file__).resolve().parents[1]).resolve()
    packet_path = root / OWNER_REVIEW_PACKET
    try:
        text = packet_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise AssertionError(f"missing owner review packet: {OWNER_REVIEW_PACKET}")

    values: dict[str, str] = {}
    in_table = False
    for line in text.splitlines():
        if line.strip() == "## Owner Decisions To Approve":
            in_table = True
            continue
        if in_table and line.startswith("## "):
            break
        if not in_table:
            continue
        match = re.match(r"^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|\s*$", line)
        if not match:
            continue
        key, value = match.groups()
        if key in values:
            raise AssertionError(f"duplicate owner review packet decision key: {key}")
        values[key] = value

    missing = REQUIRED_DECISIONS - set(values)
    extra = set(values) - REQUIRED_DECISIONS
    if missing:
        raise AssertionError(f"owner review packet missing decisions: {sorted(missing)}")
    if extra:
        raise AssertionError(f"owner review packet has unknown decisions: {sorted(extra)}")

    for key, value in values.items():
        for marker in SECRET_MARKERS:
            if marker in value:
                raise AssertionError(
                    f"secret-like marker {marker!r} found in owner review packet decision {key!r}"
                )
        _assert_approved_value_is_specific(root, key, value)
    return values


def owner_approval_template(root: Path | None = None) -> dict[str, object]:
    """Build a copy-aid template without approving upload."""
    root = (root or Path(__file__).resolve().parents[1]).resolve()
    values = owner_packet_approval_values(root)
    return {
        "schema_version": 1,
        "template_type": "owner_signoff_approved_value_copy_aid",
        "generated_from": OWNER_REVIEW_PACKET,
        "not_authorization": True,
        "submission_approved": False,
        "approved_scope": ["ios", "macos"],
        "owner_action": (
            "Review each value. Only after owner approval, copy each "
            "status/approved_value pair into app_store/apple/review/owner_signoff.json, "
            "then set approved_by, approved_at_utc, and submission_approved manually. "
            "This template does not authorize upload and must not contain Apple API keys."
        ),
        "required_decisions": {
            key: {
                "status": "approved",
                "approved_value": values[key],
            }
            for key in sorted(REQUIRED_DECISIONS)
        },
    }


def validate_owner_signoff(
    root: Path | None = None,
    *,
    require_approved: bool = False,
    manifest_path: Path | None = None,
) -> list[str]:
    root = (root or Path(__file__).resolve().parents[1]).resolve()
    manifest_path = (
        manifest_path
        if manifest_path is not None
        else root / "app_store" / "apple" / "review" / "owner_signoff.json"
    )
    data, raw_text = _read_json(manifest_path)
    if not isinstance(data, dict):
        raise AssertionError("owner_signoff.json must contain a JSON object")
    if data.get("schema_version") != 1:
        raise AssertionError("owner_signoff.json must use schema_version 1")

    owner_packet_approval_values(root)
    review_copy_messages = validate_review_copy(root)
    authorization_messages = validate_owner_authorization_schema(
        root,
        signoff=data,
        require_approved=require_approved,
    )

    for marker in SECRET_MARKERS:
        if marker in raw_text:
            raise AssertionError(
                f"secret-like marker {marker!r} found in {_relative(manifest_path, root)}"
            )

    submission_approved = data.get("submission_approved")
    if not isinstance(submission_approved, bool):
        raise AssertionError("owner_signoff.json submission_approved must be boolean")

    approved_scope = data.get("approved_scope")
    allowed_draft_scopes = (["ios", "macos"], FINAL_APPROVED_SCOPE)
    if approved_scope not in allowed_draft_scopes:
        raise AssertionError(
            "owner_signoff.json approved_scope must cover iOS/macOS draft scope or "
            "the final iOS/macOS/watchOS scope"
        )

    decisions = data.get("required_decisions")
    if not isinstance(decisions, dict):
        raise AssertionError("owner_signoff.json required_decisions must be an object")

    decision_keys = set(decisions)
    missing = REQUIRED_DECISIONS - decision_keys
    extra = decision_keys - REQUIRED_DECISIONS
    if missing:
        raise AssertionError(f"owner_signoff.json missing decisions: {sorted(missing)}")
    if extra:
        raise AssertionError(f"owner_signoff.json has unknown decisions: {sorted(extra)}")

    pending: list[str] = []
    rejected: list[str] = []
    for key in sorted(REQUIRED_DECISIONS):
        decision = decisions[key]
        if not isinstance(decision, dict):
            raise AssertionError(f"owner_signoff.json decision {key!r} must be an object")
        status = decision.get("status")
        if status not in ALLOWED_STATUSES:
            raise AssertionError(
                f"owner_signoff.json decision {key!r} status must be one of "
                f"{sorted(ALLOWED_STATUSES)}"
            )
        approved_value = _assert_plain_string(
            decision.get("approved_value"),
            f"owner_signoff.json decision {key!r} approved_value",
        )
        source_file = _assert_plain_string(
            decision.get("source_file"),
            f"owner_signoff.json decision {key!r} source_file",
        )
        notes = _assert_plain_string(
            decision.get("notes"),
            f"owner_signoff.json decision {key!r} notes",
        )
        source_path = root / source_file
        if source_file.startswith("/") or ".." in Path(source_file).parts:
            raise AssertionError(
                f"owner_signoff.json decision {key!r} source_file must be repository-relative"
            )
        if not source_path.is_file():
            raise AssertionError(
                f"owner_signoff.json decision {key!r} source file does not exist: {source_file}"
            )
        if "pending-owner-review" in approved_value and status == "approved":
            raise AssertionError(
                f"owner_signoff.json decision {key!r} cannot be approved with pending value"
            )
        if status == "approved":
            _assert_approved_value_is_specific(root, key, approved_value)
        if status == "pending":
            pending.append(key)
        elif status == "rejected":
            rejected.append(key)
        if not notes.endswith("."):
            raise AssertionError(
                f"owner_signoff.json decision {key!r} notes should be a complete sentence"
            )

    if require_approved:
        if approved_scope != FINAL_APPROVED_SCOPE:
            raise AssertionError(
                "owner_signoff.json approved_scope must cover iOS, macOS, and "
                "watchOS before upload"
            )
        if not submission_approved:
            raise AssertionError("owner_signoff.json submission_approved must be true before upload")
        approved_by = _assert_plain_string(data.get("approved_by"), "owner_signoff.json approved_by")
        approved_at = _assert_plain_string(
            data.get("approved_at_utc"),
            "owner_signoff.json approved_at_utc",
        )
        if approved_by.lower() in {"owner", "tbd", "pending", "placeholder"}:
            raise AssertionError("owner_signoff.json approved_by must name the approving person")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", approved_at):
            raise AssertionError("owner_signoff.json approved_at_utc must be UTC ISO-8601 seconds")
        if pending or rejected:
            raise AssertionError(
                "owner_signoff.json has unapproved decisions before upload: "
                f"pending={pending}, rejected={rejected}"
            )
        release_value = str(
            decisions["release_candidate_artifacts"].get("approved_value") or ""
        )
        digest = _collector(owner_evidence_set_sha256, evidence_from_repo(root))
        if digest not in release_value:
            raise AssertionError(
                "owner_signoff.json release_candidate_artifacts approval is stale; "
                f"missing exact post-build evidence hash {digest}"
            )
        return review_copy_messages + authorization_messages + [
            "PASS: owner sign-off manifest is approved for iOS, macOS, and watchOS upload",
            f"PASS: owner sign-off approved by {approved_by} at {approved_at}",
        ]

    state = "approved" if submission_approved else "draft"
    messages = (
        authorization_messages
        + review_copy_messages
        + [
            f"PASS: owner sign-off manifest schema valid ({state}; {len(pending)} pending, {len(rejected)} rejected)",
            f"PASS: owner sign-off manifest covers {len(REQUIRED_DECISIONS)} required App Store decisions",
        ]
    )
    if submission_approved and (pending or rejected):
        raise AssertionError(
            "owner_signoff.json cannot set submission_approved=true while decisions remain "
            f"pending={pending}, rejected={rejected}"
        )
    return messages


def run_owner_packet_approval_dry_run(root: Path | None = None) -> list[str]:
    """Validate exact owner-packet values without changing the real signoff."""
    root = (root or Path(__file__).resolve().parents[1]).resolve()
    real_manifest_path = root / "app_store" / "apple" / "review" / "owner_signoff.json"
    real_manifest_sha_before = _sha256_file(real_manifest_path)
    real_manifest, _ = _read_json(real_manifest_path)
    if not isinstance(real_manifest, dict):
        raise AssertionError("owner_signoff.json must contain a JSON object")
    real_submission_approved = real_manifest.get("submission_approved") is True

    approval_values = owner_packet_approval_values(root)
    dry_run_manifest = json.loads(json.dumps(real_manifest))
    if not isinstance(dry_run_manifest, dict):
        raise AssertionError("owner approval dry-run manifest must be a JSON object")

    decisions = dry_run_manifest.get("required_decisions")
    if not isinstance(decisions, dict):
        raise AssertionError("owner approval dry-run decisions must be an object")
    pending_decisions: list[str] = []
    for key, approved_value in approval_values.items():
        decision = decisions.get(key)
        if not isinstance(decision, dict):
            raise AssertionError(f"owner approval dry-run missing decision {key!r}")
        decision["approved_value"] = approved_value
        if "pending-owner-review" in approved_value:
            decision["status"] = "pending"
            pending_decisions.append(key)
        else:
            decision["status"] = "approved"

    dry_run_manifest["submission_approved"] = not pending_decisions
    if pending_decisions:
        dry_run_manifest["approved_by"] = ""
        dry_run_manifest["approved_at_utc"] = ""
        dry_run_manifest["submission_approved"] = False
    else:
        dry_run_manifest["approved_by"] = "Win's VPN Release Owner Dry Run"
        dry_run_manifest["approved_at_utc"] = "2026-07-09T00:00:00Z"

    with tempfile.TemporaryDirectory(prefix="wins-apple-owner-signoff-") as tmp_dir:
        temp_manifest_path = Path(tmp_dir) / "owner_signoff.approved.dry-run.json"
        temp_manifest_path.write_text(
            json.dumps(dry_run_manifest, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        validate_owner_signoff(
            root,
            require_approved=not pending_decisions,
            manifest_path=temp_manifest_path,
        )

    real_manifest_sha_after = _sha256_file(real_manifest_path)
    if real_manifest_sha_before != real_manifest_sha_after:
        raise AssertionError("owner approval dry-run changed the real owner_signoff.json")
    current_manifest, _ = _read_json(real_manifest_path)
    if not isinstance(current_manifest, dict):
        raise AssertionError("owner_signoff.json must contain a JSON object after dry-run")
    if (current_manifest.get("submission_approved") is True) != real_submission_approved:
        raise AssertionError("owner approval dry-run must leave submission_approved unchanged")

    unchanged_state = "approved" if real_submission_approved else "pending"

    messages = [
        f"PASS: owner approval dry-run validated {len(REQUIRED_DECISIONS)} packet values against the current owner gate",
    ]
    if pending_decisions:
        messages.append(
            "PASS: owner approval dry-run preserved "
            f"{len(pending_decisions)} pending decision(s): {', '.join(sorted(pending_decisions))}"
        )
    else:
        messages.append("PASS: owner approval dry-run reached the approved upload gate")
    messages.append(
        f"PASS: owner approval dry-run left the real owner_signoff.json {unchanged_state} and unchanged"
    )
    return messages


def run_selftest(root: Path | None = None) -> list[str]:
    root = (root or Path(__file__).resolve().parents[1]).resolve()
    checked = 0
    for key in sorted(REQUIRED_DECISIONS):
        good_value = " / ".join(_approved_value_markers(root, key))
        _assert_approved_value_is_specific(root, key, good_value)

        try:
            _assert_approved_value_is_specific(root, key, "approved")
        except AssertionError:
            checked += 1
        else:
            raise AssertionError(
                f"owner sign-off self-test expected vague approval rejection for {key!r}"
            )

    return [
        f"PASS: owner sign-off approved-value marker self-test rejected {checked} vague approvals",
        "PASS: owner sign-off approved-value marker self-test accepted marker-complete approvals",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-approved",
        action="store_true",
        help="Fail unless the manifest explicitly approves every upload decision.",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="Run owner approval marker self-tests without reading approval state.",
    )
    parser.add_argument(
        "--print-owner-approval-template",
        action="store_true",
        help="Print a JSON copy-aid with owner-packet approval values without approving upload.",
    )
    parser.add_argument(
        "--dry-run-owner-approval",
        action="store_true",
        help="Validate owner-packet values in a temporary manifest without changing owner_signoff.json.",
    )
    args = parser.parse_args()

    try:
        selected_modes = [
            args.selftest,
            args.print_owner_approval_template,
            args.dry_run_owner_approval,
        ]
        if sum(1 for selected in selected_modes if selected) > 1:
            raise AssertionError(
                "--selftest, --print-owner-approval-template, and "
                "--dry-run-owner-approval are mutually exclusive"
            )
        if args.dry_run_owner_approval and args.require_approved:
            raise AssertionError("--dry-run-owner-approval already validates the current owner gate")
        if args.selftest:
            messages = run_selftest()
        elif args.print_owner_approval_template:
            print(json.dumps(owner_approval_template(), indent=2, sort_keys=True))
            return 0
        elif args.dry_run_owner_approval:
            messages = run_owner_packet_approval_dry_run()
        else:
            messages = validate_owner_signoff(require_approved=args.require_approved)
    except AssertionError as exc:
        print(f"FAIL: {exc}")
        return 1

    for message in messages:
        print(message)
    print(f"SUMMARY: {len(messages)}/{len(messages)} checks passing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
