#!/usr/bin/env python3
"""Fail-closed Apple App Store listing, privacy, export, signing, and receipt gates.

Release 1.0.17+34 has two required App Store artifacts: one iOS IPA that embeds
the non-VPN watchOS companion, and one macOS App Store PKG. tvOS is not a
shipping surface, upload target, freeze platform, or readiness denominator.
Unsigned, ad-hoc, Apple Development, placeholder, and historical 1.0.14+29
identities fail closed. This module never uploads, signs, deploys, or invents
portal evidence.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from collections.abc import Mapping

import apple_watch_companion_smoke as watch_smoke


ROOT = pathlib.Path(__file__).resolve().parents[1]
RELEASE_IDENTITY_RELATIVE = "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
TV_SCOPE_RELATIVE = "app_store/apple/review/apple_tv_post_release_scope.json"
EXPORT_STATUS_RELATIVE = "app_store/apple/review/export_compliance_status.json"
CANONICAL_RELEASE = "1.0.17+34"
CANONICAL_MARKETING_VERSION = "1.0.17"
CANONICAL_BUNDLE_VERSION = "34"
REQUIRED_APPLE_ARTIFACTS = (
    "ios_app_store_ipa_with_embedded_watchos",
    "macos_app_store_pkg",
)
REQUIRED_APPLE_UPLOAD_TARGETS = ("ios-app-store-ipa", "macos-app-store-pkg")
OPTIONAL_APPLE_UPLOAD_TARGETS = ("macos-developer-id-app",)
REQUIRED_MACOS_ARCHITECTURES = ["arm64", "x86_64"]
RUNTIME_NOT_STARTED_PENDING_REASONS = [
    "ios_physical_device_live_tunnel",
    "macos_signed_live_tunnel",
    "embedded_watchos_companion_smoke",
]
TVOS_REQUIRED_FUTURE_WORK = [
    "native_tvos_host_and_packet_tunnel_targets",
    "tvos_engine_slices",
    "focus_driven_ui",
    "tvos_privacy_and_store_metadata",
    "physical_apple_tv_runtime_evidence",
    "dedicated_build_freeze_receipt_and_upload_contract",
]
FORBIDDEN_TVOS_IDENTITY_TOKENS = frozenset(
    {"tvos", "appletvos", "apple-tv", "apple_tv", "tv"}
)
TEAM_ID = "5YT8H4U72M"
HOST_BUNDLE_ID = "org.winsvpn.app"
TUNNEL_BUNDLE_ID = "org.winsvpn.app.PacketTunnel"
WATCH_BUNDLE_ID = "org.winsvpn.app.watchkitapp"
WATCH_EXECUTABLE = "WinsWatch"
APPLE_DISTRIBUTION_AUTHORITY = "Authority=Apple Distribution:"
APPLE_DISTRIBUTION_CONTRACT = "apple-distribution"
PRIVACY_POLICY_URL = "https://www.winsvpn.org/privacy/"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_SIGNING_MARKERS = (
    "ad-hoc",
    "adhoc",
    "ad hoc",
    "apple development",
    "iphone developer",
    "iphone distribution",
    "placeholder",
    "unsigned",
    "tbd",
    "xxxxxxxxxx",
)
STALE_BUILD_29_SHA256 = {
    "1f92c7e291f68ebbdc93586f8db49157fb35067971c3da569af9095cbd81d4a9",
    "b4c4ce430c61931306b3d151d4a19809285fa28266b38f233cdab48d90d46eec",
}
LISTING_FILES = (
    "app_store/apple/metadata/en-US/name.txt",
    "app_store/apple/metadata/en-US/subtitle.txt",
    "app_store/apple/metadata/en-US/promotional_text.txt",
    "app_store/apple/metadata/en-US/description.txt",
    "app_store/apple/metadata/en-US/keywords.txt",
    "app_store/apple/metadata/en-US/release_notes.txt",
    "app_store/apple/metadata/en-US/copyright.txt",
    "app_store/apple/metadata/en-US/support_url.txt",
    "app_store/apple/metadata/en-US/marketing_url.txt",
    "app_store/apple/metadata/en-US/privacy_url.txt",
    "app_store/apple/metadata/app_information.md",
    "app_store/apple/metadata/pricing_availability.md",
    "app_store/apple/review/ios_review_notes.txt",
    "app_store/apple/review/macos_review_notes.txt",
    "app_store/apple/review/app_review_information.md",
    "app_store/apple/review/privacy_answers.md",
    "app_store/apple/review/submission_answer_sheet.md",
    "app_store/apple/review/privacy_label_manifest.json",
    "app_store/apple/review/export_compliance_facts.txt",
    EXPORT_STATUS_RELATIVE,
    TV_SCOPE_RELATIVE,
    "app_store/apple/review/owner_signoff.json",
    "app_store/apple/artifacts/release_candidate.json",
    "app_store/apple/artifacts/runtime_evidence.json",
    "app_store/apple/review/rollout_readiness.json",
)
PROTOCOL_FALLBACK_MARKERS = ("AWG then Xray", "AWG first")
STALE_RELEASE_MARKERS = ("1.0.14+29", "1.0.14_29")
REQUIRED_PRIVACY_LABELS = (
    "Coarse Location",
    "Device ID",
    "User ID",
    "Product Interaction",
)
STALE_LIVE_PRIVACY_LABELS = (
    "Coarse Location",
    "User ID",
    "Device ID",
    "Purchase History",
)
TV_SCOPE_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "canonical_release",
        "app_version",
        "build_number",
        "shipping_surface",
        "upload_target",
        "freeze_platform",
        "release_blocker",
        "readiness_denominator",
        "dashboard_target",
        "artifact_status",
        "listing_status",
        "privacy_label_status",
        "export_compliance_status",
        "signing_status",
        "receipt_status",
        "must_not_reuse_ios_artifact",
        "must_not_reuse_watchos_companion",
        "publication_authorized",
        "upload_authorized",
        "required_future_work",
    }
)
EXPORT_STATUS_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "last_reviewed",
        "status_scope",
        "counsel_review_status",
        "export_classification_status",
        "filings_status",
        "exact_artifact_verification_status",
        "marking_note",
        "canonical_release",
        "app_version",
        "build_number",
        "status",
        "uses_encryption",
        "implements_standard_encryption_outside_apple_os",
        "implements_proprietary_or_nonstandard_encryption",
        "exemption_claimed",
        "its_app_uses_non_exempt_encryption",
        "apple_declaration_approved",
        "export_compliance_code_present",
        "unsigned_artifact_may_carry_declaration",
        "owner_signoff_status",
        "facts_file",
        "required_surfaces",
        "non_shipping_surfaces",
    }
)
SIGNING_KEYS = frozenset({"status", "contract", "authority", "team_id"})


class AppleListingGateError(RuntimeError):
    """Raised when Apple listing, privacy, export, signing, or receipt state is invalid."""


def _load_json(relative: str) -> dict[str, object]:
    path = ROOT / relative
    if not path.is_file():
        raise AppleListingGateError(f"missing Apple store metadata: {relative}")
    try:
        payload = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AppleListingGateError(f"{relative} must be ASCII JSON") from exc
    if type(payload) is not dict:
        raise AppleListingGateError(f"{relative} must contain one JSON object")
    return payload


def _read_ascii(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        raise AppleListingGateError(f"missing Apple store metadata: {relative}")
    try:
        return path.read_text(encoding="ascii")
    except UnicodeError as exc:
        raise AppleListingGateError(f"{relative} must be ASCII") from exc


def _folded(text: str) -> str:
    return " ".join(text.split())


def _require_listing_protocol(text: str, label: str) -> None:
    folded = _folded(text)
    if "Winn v3" not in text:
        raise AppleListingGateError(f"{label} must name Winn v3 as the primary protocol")
    if not any(marker in folded for marker in PROTOCOL_FALLBACK_MARKERS):
        raise AppleListingGateError(f"{label} must name Winn v1 AWG then Xray fallback")


def _reject_stale_current_identity(value: object, label: str) -> None:
    text = str(value or "")
    lowered = text.casefold()
    for marker in STALE_RELEASE_MARKERS:
        if marker.casefold() in lowered:
            raise AppleListingGateError(
                f"{label} still presents stale build 29 as the current candidate"
            )
    if HEX64.fullmatch(text) and text in STALE_BUILD_29_SHA256:
        raise AppleListingGateError(
            f"{label} still presents stale build 29 as the current candidate"
        )


def _reject_forbidden_signing_text(value: object, label: str) -> None:
    text = str(value or "").casefold()
    if not text:
        return
    for marker in FORBIDDEN_SIGNING_MARKERS:
        if marker in text:
            raise AppleListingGateError(
                f"{label} is not a real Apple Distribution signing identity"
            )


def require_recorded_app_store_signing(
    artifact: Mapping[str, object],
    platform: str,
    *,
    required: bool,
) -> None:
    """Refuse unsigned, ad-hoc, development, placeholder, or forged identities."""

    signing = artifact.get("signing")
    if type(signing) is not dict or set(signing) != SIGNING_KEYS:
        raise AppleListingGateError(f"{platform} omitted a real signed artifact identity")
    contract = str(signing.get("contract") or "")
    authority = str(signing.get("authority") or "")
    team_id = str(signing.get("team_id") or "")
    status = str(signing.get("status") or "")
    _reject_forbidden_signing_text(authority, f"{platform} signing authority")
    _reject_forbidden_signing_text(team_id, f"{platform} signing team")
    _reject_forbidden_signing_text(status, f"{platform} signing status")
    _reject_stale_current_identity(authority, f"{platform} signing authority")
    if contract != APPLE_DISTRIBUTION_CONTRACT:
        raise AppleListingGateError(f"{platform} signing contract is not Apple Distribution")
    if required:
        if status != "current_candidate":
            raise AppleListingGateError(
                f"{platform} current candidate must bind a real signed identity"
            )
        if authority != APPLE_DISTRIBUTION_AUTHORITY:
            raise AppleListingGateError(
                f"{platform} signing identity is not a real Apple Distribution identity"
            )
        if team_id != TEAM_ID:
            raise AppleListingGateError(
                f"{platform} signing team is not the release-valid team"
            )
        return
    if status not in {"unbound", "no_current_candidate"}:
        raise AppleListingGateError(
            f"{platform} pending candidate must not claim a current signed identity"
        )
    if authority or team_id:
        raise AppleListingGateError(
            f"{platform} pending candidate must not claim a signing identity"
        )


def _require_watch_embedded(watch: object, *, required: bool) -> None:
    if type(watch) is not dict:
        raise AppleListingGateError(
            "iOS artifact omitted the embedded watchOS companion identity"
        )
    if (
        watch.get("bundle_id") != WATCH_BUNDLE_ID
        or watch.get("companion_bundle_id") != HOST_BUNDLE_ID
        or watch.get("version") != CANONICAL_MARKETING_VERSION
        or str(watch.get("build")) != CANONICAL_BUNDLE_VERSION
        or watch.get("executable") != WATCH_EXECUTABLE
    ):
        raise AppleListingGateError(
            "watchOS companion identity is not the current 1.0.17+34 companion"
        )
    executable = str(watch.get("executable_sha256") or "")
    privacy = str(watch.get("privacy_info_sha256") or "")
    if required:
        if watch.get("status") != "current_candidate":
            raise AppleListingGateError(
                "embedded watchOS companion must be a current candidate"
            )
        if HEX64.fullmatch(executable) is None or HEX64.fullmatch(privacy) is None:
            raise AppleListingGateError(
                "embedded watchOS companion omitted real signed artifact hashes"
            )
        _reject_stale_current_identity(executable, "watchOS executable")
        _reject_stale_current_identity(privacy, "watchOS privacy")
        return
    if watch.get("status") != "no_current_candidate":
        raise AppleListingGateError(
            "embedded watchOS companion status must stay no_current_candidate"
        )
    if executable or privacy:
        raise AppleListingGateError(
            "pending watchOS companion must not claim executable or privacy hashes"
        )


def _require_macos_architecture(macos: Mapping[str, object], *, required: bool) -> None:
    if "embedded_watchos_companion" in macos:
        raise AppleListingGateError("macOS must not embed a watchOS companion")
    inventory = macos.get("shipped_architecture_inventory")
    if type(inventory) is not dict:
        raise AppleListingGateError("macOS omitted the shipped architecture inventory")
    if inventory.get("required_architectures") != REQUIRED_MACOS_ARCHITECTURES:
        raise AppleListingGateError(
            "macOS architecture inventory must require arm64 and x86_64"
        )
    shipped = inventory.get("shipped")
    if type(shipped) is not list:
        raise AppleListingGateError("macOS architecture inventory shipped list is invalid")
    if required:
        if not shipped:
            raise AppleListingGateError(
                "macOS current candidate must inventory arm64 and x86_64 binaries"
            )
        return
    if shipped:
        raise AppleListingGateError(
            "pending macOS architecture inventory must not claim shipped binaries"
        )


def _require_pending_watch_smoke(runtime: Mapping[str, object]) -> None:
    smoke = runtime.get("watch_companion_smoke")
    if (
        type(smoke) is not dict
        or smoke.get("status") != "pending"
        or smoke.get("receipt_path") not in {"", None}
        or smoke.get("receipt_sha256") not in {"", None}
    ):
        raise AppleListingGateError(
            "embedded watchOS companion smoke must stay pending without a current candidate"
        )
    if runtime.get("pending_reasons") != RUNTIME_NOT_STARTED_PENDING_REASONS:
        raise AppleListingGateError(
            "runtime evidence pending reasons must include embedded watchOS companion smoke"
        )


def _require_bound_watch_smoke(
    candidate: Mapping[str, object],
    runtime: Mapping[str, object],
    *,
    release_ready: bool,
) -> None:
    # R22 Y3 D2: a complete candidate set may still carry a pending smoke; a
    # passed one is re-hashed and its verdict, release and source commit are
    # re-derived, and a release-ready upload requires it.
    try:
        watch_smoke.runtime_watch_smoke_sha256(
            ROOT,
            runtime,
            candidate,
            release=CANONICAL_RELEASE,
            require_passed=release_ready,
        )
    except watch_smoke.WatchSmokeError as exc:
        raise AppleListingGateError(str(exc)) from exc


def _require_tvos_non_shipping() -> dict[str, object]:
    scope = _load_json(TV_SCOPE_RELATIVE)
    if set(scope) != TV_SCOPE_KEYS:
        raise AppleListingGateError("Apple TV post-release scope schema is invalid")
    if (
        scope.get("schema_version") != 1
        or scope.get("contract") != "winsvpn-apple-tv-post-release-scope-v1"
        or scope.get("canonical_release") != CANONICAL_RELEASE
        or scope.get("app_version") != CANONICAL_MARKETING_VERSION
        or str(scope.get("build_number")) != CANONICAL_BUNDLE_VERSION
        or scope.get("shipping_surface") is not False
        or scope.get("upload_target") is not False
        or scope.get("freeze_platform") is not False
        or scope.get("release_blocker") is not False
        or scope.get("readiness_denominator") is not False
        or scope.get("dashboard_target") is not False
        or scope.get("artifact_status") != "not_a_current_candidate"
        or scope.get("listing_status") != "not_in_this_release"
        or scope.get("privacy_label_status") != "not_applicable_not_shipping"
        or scope.get("export_compliance_status") != "not_applicable_not_shipping"
        or scope.get("signing_status") != "unbound_not_shipping"
        or scope.get("receipt_status") != "refused_not_a_current_target"
        or scope.get("must_not_reuse_ios_artifact") is not True
        or scope.get("must_not_reuse_watchos_companion") is not True
        or scope.get("publication_authorized") is not False
        or scope.get("upload_authorized") is not False
    ):
        raise AppleListingGateError(
            "tvOS is not a 1.0.17+34 shipping, upload, signing, or receipt surface"
        )
    future = scope.get("required_future_work")
    if future != TVOS_REQUIRED_FUTURE_WORK:
        raise AppleListingGateError(
            "tvOS post-release scope omitted the required native product work"
        )
    return scope


def _require_export_compliance(signoff: Mapping[str, object]) -> dict[str, object]:
    status = _load_json(EXPORT_STATUS_RELATIVE)
    if set(status) != EXPORT_STATUS_KEYS:
        raise AppleListingGateError("Apple export-compliance status schema is invalid")
    decisions = signoff.get("required_decisions")
    export_decision = (
        decisions.get("export_compliance_answers") if type(decisions) is dict else None
    )
    owner_status = (
        str(export_decision.get("status") or "") if type(export_decision) is dict else ""
    )
    if owner_status not in {"pending", "approved"}:
        raise AppleListingGateError("Apple export-compliance owner decision is invalid")
    expected_export_status = (
        "approved" if owner_status == "approved" else "pending_owner_legal"
    )
    if (
        status.get("schema_version") != 1
        or status.get("contract") != "winsvpn-apple-export-compliance-v1"
        or status.get("last_reviewed") != "2026-08-31"
        or status.get("status_scope") != "owner_decision_only"
        or status.get("counsel_review_status") != "pending"
        or status.get("export_classification_status") != "pending"
        or status.get("filings_status") != "none_filed"
        or status.get("exact_artifact_verification_status") != "pending"
        or "OWNER APPROVED 2026-08-31; COUNSEL REVIEW PENDING"
        not in str(status.get("marking_note") or "")
        or status.get("canonical_release") != CANONICAL_RELEASE
        or status.get("app_version") != CANONICAL_MARKETING_VERSION
        or str(status.get("build_number")) != CANONICAL_BUNDLE_VERSION
        or status.get("status") != expected_export_status
        or status.get("uses_encryption") is not True
        or status.get("implements_standard_encryption_outside_apple_os") is not True
        or status.get("implements_proprietary_or_nonstandard_encryption") is not True
        or status.get("exemption_claimed") is not False
        or status.get("its_app_uses_non_exempt_encryption")
        != (True if owner_status == "approved" else None)
        or status.get("apple_declaration_approved") is not False
        or status.get("export_compliance_code_present") is not False
        or status.get("unsigned_artifact_may_carry_declaration") is not False
        or status.get("owner_signoff_status") != owner_status
        or status.get("facts_file")
        != "app_store/apple/review/export_compliance_facts.txt"
        or status.get("required_surfaces")
        != ["ios", "embedded_watchos_companion", "macos"]
        or status.get("non_shipping_surfaces") != ["tvos"]
    ):
        raise AppleListingGateError(
            "Apple export-compliance status is not the fail-closed 1.0.17+34 contract"
        )
    facts = _read_ascii("app_store/apple/review/export_compliance_facts.txt")
    for marker in (
        "The app is a VPN client.",
        'Do not claim "no encryption"',
        "ITSAppUsesNonExemptEncryption",
        "Unsigned",
    ):
        if marker not in facts:
            raise AppleListingGateError(
                f"export_compliance_facts.txt missing marker {marker!r}"
            )
    return status


def _require_privacy(manifest: Mapping[str, object], *, release_ready: bool) -> None:
    if (
        manifest.get("app_version") != CANONICAL_MARKETING_VERSION
        or str(manifest.get("build_number")) != CANONICAL_BUNDLE_VERSION
        or manifest.get("privacy_policy_url") != PRIVACY_POLICY_URL
    ):
        raise AppleListingGateError(
            "Apple privacy label is not the canonical 1.0.17+34 contract"
        )
    summary = manifest.get("app_store_connect_summary")
    if type(summary) is not dict:
        raise AppleListingGateError("Apple privacy summary is invalid")
    linked = summary.get("data_linked_to_user")
    if type(linked) is not list:
        raise AppleListingGateError("Apple privacy linked data is invalid")
    labels = tuple(item.get("label") for item in linked if type(item) is dict)
    if set(labels) != set(REQUIRED_PRIVACY_LABELS) or len(labels) != 4:
        raise AppleListingGateError(
            "Apple privacy labels must be Coarse Location, Device ID, User ID, "
            "and Product Interaction"
        )
    if any(
        type(item) is dict and item.get("label") == "Purchase History" for item in linked
    ):
        raise AppleListingGateError(
            "Apple privacy labels must not include Purchase History"
        )
    live = manifest.get("live_app_store_connect_sync")
    if type(live) is not dict:
        raise AppleListingGateError("Apple live privacy snapshot is invalid")
    published = live.get("published_data_types")
    if type(published) is not list:
        raise AppleListingGateError("Apple live privacy labels are invalid")
    if release_ready:
        if tuple(published) != REQUIRED_PRIVACY_LABELS:
            raise AppleListingGateError(
                "live App Store Connect privacy labels are stale; "
                "add Product Interaction; remove Purchase History. "
                "This gate does not claim App Store Connect was updated."
            )
        return
    if live.get("app_store_connect_updated") is not False:
        raise AppleListingGateError(
            "Apple privacy draft must not claim App Store Connect was updated"
        )
    if tuple(published) != STALE_LIVE_PRIVACY_LABELS:
        raise AppleListingGateError(
            "Apple live privacy snapshot must record the stale portal labels"
        )


def _artifact_map(candidate: Mapping[str, object]) -> dict[str, dict[str, object]]:
    artifacts = candidate.get("artifacts")
    if type(artifacts) is not list or len(artifacts) != 2:
        raise AppleListingGateError(
            "release_candidate.json must list exactly two artifacts: "
            "iOS with embedded watchOS and macOS"
        )
    mapping: dict[str, dict[str, object]] = {}
    for artifact in artifacts:
        if type(artifact) is not dict:
            raise AppleListingGateError(
                "release_candidate.json artifacts must be objects"
            )
        platform = artifact.get("platform")
        if platform in {"tvos", "appletvos", "tv"}:
            raise AppleListingGateError(
                "tvOS is not a 1.0.17+34 shipping, upload, signing, or receipt surface"
            )
        if platform not in {"ios", "macos"} or platform in mapping:
            raise AppleListingGateError(
                "release_candidate.json has an unexpected or duplicate platform"
            )
        mapping[str(platform)] = artifact
    if set(mapping) != {"ios", "macos"}:
        raise AppleListingGateError("release_candidate.json must cover iOS and macOS")
    return mapping


def current_apple_store_blockers(
    reviewed: Mapping[str, object] | None = None,
) -> dict[str, list[str]]:
    payload = reviewed if reviewed is not None else review_current_apple_store_metadata()
    return {
        "owner": list(payload["owner_blockers"]),
        "device": list(payload["device_blockers"]),
        "store": list(payload["store_blockers"]),
    }


def review_current_apple_store_metadata(*, release_ready: bool = False) -> dict[str, object]:
    """Review 1.0.17+34 listing/privacy/export/signing/receipt state and fail closed."""

    identity = _load_json(RELEASE_IDENTITY_RELATIVE)
    mappings = identity.get("platform_mappings")
    apple = mappings.get("apple") if type(mappings) is dict else None
    shipping = list(apple.get("shipping_surfaces") or ()) if type(apple) is dict else []
    identity_tokens: list[str] = []
    if type(apple) is dict:
        for key in (
            "shipping_surfaces",
            "required_artifacts",
            "required_upload_targets",
            "optional_evidence_targets",
            "optional_distribution",
        ):
            value = apple.get(key)
            if type(value) is list:
                identity_tokens.extend(
                    str(item).casefold().replace("_", "-") for item in value
                )
    if (
        identity.get("canonical_release") != CANONICAL_RELEASE
        or type(apple) is not dict
        or set(shipping) != {"ios", "watchos", "macos"}
        or any(
            token in FORBIDDEN_TVOS_IDENTITY_TOKENS
            or "tvos" in token
            or "appletv" in token
            or token.startswith("apple-tv")
            or "-apple-tv" in token
            for token in identity_tokens
        )
        or set(apple.get("required_artifacts") or ()) != set(REQUIRED_APPLE_ARTIFACTS)
        or list(apple.get("optional_distribution") or []) != ["macos_developer_id"]
        or set(apple.get("required_upload_targets") or ())
        != set(REQUIRED_APPLE_UPLOAD_TARGETS)
        or set(apple.get("optional_evidence_targets") or ())
        != set(OPTIONAL_APPLE_UPLOAD_TARGETS)
    ):
        raise AppleListingGateError(
            "Apple release identity is not the canonical 1.0.17+34 iOS/watchOS/macOS contract"
        )

    files: dict[str, str] = {}
    for relative in LISTING_FILES:
        path = ROOT / relative
        if not path.is_file():
            raise AppleListingGateError(f"missing Apple store metadata: {relative}")
        payload = path.read_bytes()
        try:
            payload.decode("ascii")
        except UnicodeError as exc:
            raise AppleListingGateError(f"{relative} must be ASCII") from exc
        files[relative] = hashlib.sha256(payload).hexdigest()

    description = _read_ascii("app_store/apple/metadata/en-US/description.txt")
    promotional = _read_ascii("app_store/apple/metadata/en-US/promotional_text.txt")
    notes = _read_ascii("app_store/apple/metadata/en-US/release_notes.txt")
    ios_notes = _read_ascii("app_store/apple/review/ios_review_notes.txt")
    macos_notes = _read_ascii("app_store/apple/review/macos_review_notes.txt")
    app_info = _read_ascii("app_store/apple/metadata/app_information.md")
    _require_listing_protocol(description, "description")
    _require_listing_protocol(notes, "release notes")
    if "Winn v3" not in promotional:
        raise AppleListingGateError("promotional text must name Winn v3")
    if "Apple Watch" not in description or "embedded" not in description.casefold():
        raise AppleListingGateError("listing must keep watchOS embedded in the iPhone app")
    if "not a standalone VPN" not in description:
        raise AppleListingGateError(
            "listing must say the Apple Watch companion is not a standalone VPN"
        )
    if "does not include an Apple TV app" not in description:
        raise AppleListingGateError("listing must say this release is not an Apple TV app")
    if "Apple TV" not in app_info:
        raise AppleListingGateError("app information must keep Apple TV out of this release")
    if "org.winsvpn.app.watchkitapp" not in ios_notes:
        raise AppleListingGateError(
            "iOS review notes must name the embedded watchOS companion"
        )
    if "Apple TV" not in ios_notes or "Apple TV" not in macos_notes:
        raise AppleListingGateError("review notes must say this binary is not an Apple TV app")

    tv_scope = _require_tvos_non_shipping()
    signoff = _load_json("app_store/apple/review/owner_signoff.json")
    export_status = _require_export_compliance(signoff)
    privacy = _load_json("app_store/apple/review/privacy_label_manifest.json")
    _require_privacy(privacy, release_ready=release_ready)
    candidate = _load_json("app_store/apple/artifacts/release_candidate.json")
    runtime = _load_json("app_store/apple/artifacts/runtime_evidence.json")
    if (
        candidate.get("app_version") != CANONICAL_MARKETING_VERSION
        or str(candidate.get("build_number")) != CANONICAL_BUNDLE_VERSION
        or runtime.get("app_version") != CANONICAL_MARKETING_VERSION
        or str(runtime.get("build_number")) != CANONICAL_BUNDLE_VERSION
    ):
        raise AppleListingGateError("Apple candidate version is not 1.0.17+34")
    artifacts = _artifact_map(candidate)
    ios = artifacts["ios"]
    macos = artifacts["macos"]
    for platform, artifact in (("ios", ios), ("macos", macos)):
        _reject_stale_current_identity(artifact.get("path"), f"{platform} path")
        _reject_stale_current_identity(artifact.get("sha256"), f"{platform} sha256")
        if (
            artifact.get("bundle_id") != HOST_BUNDLE_ID
            or artifact.get("packet_tunnel_bundle_id") != TUNNEL_BUNDLE_ID
        ):
            raise AppleListingGateError(
                f"{platform} bundle IDs are not the current universal app IDs"
            )
    candidate_status = str(candidate.get("candidate_set_status") or "")
    required = candidate_status == "complete_local_candidates"
    if candidate_status not in {"no_current_candidate", "complete_local_candidates"}:
        raise AppleListingGateError(
            "release_candidate.json candidate_set_status must be "
            "no_current_candidate or complete_local_candidates"
        )
    if required:
        if candidate.get("upload_status") not in {
            "not_uploaded",
            "uploaded_processed_and_attached",
        }:
            raise AppleListingGateError(
                "complete Apple candidates have an invalid upload status"
            )
    elif candidate.get("upload_status") != "not_uploaded":
        raise AppleListingGateError("no_current_candidate upload_status must be not_uploaded")
    require_recorded_app_store_signing(ios, "ios", required=required)
    require_recorded_app_store_signing(macos, "macos", required=required)
    _require_watch_embedded(ios.get("embedded_watchos_companion"), required=required)
    _require_macos_architecture(macos, required=required)
    if "shipped_architecture_inventory" in ios:
        raise AppleListingGateError(
            "iOS must not claim the macOS architecture inventory"
        )
    if ios.get("type") != "ipa" or macos.get("type") != "pkg":
        raise AppleListingGateError("Apple artifacts must remain one IPA and one PKG")
    if not required:
        _require_pending_watch_smoke(runtime)
    else:
        _require_bound_watch_smoke(candidate, runtime, release_ready=release_ready)

    if signoff.get("submission_approved") is not False and not release_ready:
        raise AppleListingGateError(
            "owner signoff cannot approve upload without a complete current evidence set"
        )
    authorization = signoff.get("owner_authorization")
    if type(authorization) is not dict:
        raise AppleListingGateError("owner authorization schema is invalid")
    if (
        authorization.get("credentials_authorized") is not False
        or authorization.get("upload_authorized") is not False
    ) and not release_ready:
        raise AppleListingGateError(
            "credentials and upload authorization must stay false until real evidence exists"
        )
    if release_ready:
        if candidate_status != "complete_local_candidates":
            raise AppleListingGateError(
                "release-ready Apple upload requires a complete current 1.0.17+34 candidate set"
            )
        if signoff.get("submission_approved") is not True:
            raise AppleListingGateError(
                "release-ready Apple upload requires owner submission approval"
            )
        if export_status.get("status") != "approved":
            raise AppleListingGateError(
                "release-ready Apple upload requires approved export-compliance answers"
            )

    owner_blockers = [
        "owner_signoff.submission_approved is false",
        "export counsel review, classification, and filings remain pending",
        "App Store Connect API credentials are not restored outside the repo",
    ]
    device_blockers = [
        "no current signed iOS IPA with embedded watchOS companion",
        "no current signed macOS App Store PKG with arm64 and x86_64 inventory",
        "no current physical-iPhone or signed-macOS runtime evidence",
        "local keychain still lacks 3rd Party Mac Developer Installer for a Mac App Store PKG",
    ]
    store_blockers = [
        "live App Store Connect privacy labels still omit Product Interaction and still list Purchase History",
        "Digital Services Act trader declaration is not verified",
        "Apple encryption questionnaire is unanswered",
        "tvOS remains not-in-this-release and must not be uploaded",
    ]
    reviewed = {
        "ok": True,
        "canonical_release": CANONICAL_RELEASE,
        "app_version": CANONICAL_MARKETING_VERSION,
        "build_number": CANONICAL_BUNDLE_VERSION,
        "required_surfaces": ["ios", "embedded_watchos_companion", "macos"],
        "non_shipping_surfaces": ["tvos"],
        "watchos_embedded_in_ios_ipa": True,
        "tvos_shipping_surface": False,
        "submission_approved": bool(signoff.get("submission_approved")),
        "upload_authorized": False,
        "publication_authorized": False,
        "candidate_set_status": candidate_status,
        "signing_status": "unbound" if not required else "apple-distribution",
        "export_compliance_status": export_status.get("status"),
        "privacy_policy_url": PRIVACY_POLICY_URL,
        "team_id": TEAM_ID,
        "files": files,
        "sha256": hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest(),
        "owner_blockers": owner_blockers,
        "device_blockers": device_blockers,
        "store_blockers": store_blockers,
        "tv_scope": {
            "shipping_surface": tv_scope.get("shipping_surface"),
            "upload_target": tv_scope.get("upload_target"),
            "receipt_status": tv_scope.get("receipt_status"),
        },
    }
    return reviewed


def review_messages(*, release_ready: bool = False) -> list[str]:
    reviewed = review_current_apple_store_metadata(release_ready=release_ready)
    signing_message = (
        "PASS: recorded Apple signing identities fail closed until real Apple Distribution artifacts exist"
        if reviewed["candidate_set_status"] == "no_current_candidate"
        else "PASS: recorded Apple signing identities are Apple Distribution team 5YT8H4U72M"
    )
    export_message = (
        "PASS: Apple export-compliance remains owner/legal pending"
        if reviewed["export_compliance_status"] == "pending_owner_legal"
        else "PASS: Apple export-compliance answers are approved"
    )
    return [
        "PASS: Apple listing metadata is ASCII and bound to 1.0.17+34",
        "PASS: iOS listing keeps watchOS embedded in the iPhone IPA",
        "PASS: tvOS remains a non-shipping listing/privacy/export/signing/receipt surface",
        signing_message,
        export_message,
        f"PASS: Apple store metadata hash {reviewed['sha256']}",
    ]


if __name__ == "__main__":
    try:
        for message in review_messages():
            print(message)
    except AppleListingGateError as exc:
        raise SystemExit(f"FAIL: {exc}") from exc
