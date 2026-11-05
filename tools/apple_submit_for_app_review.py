#!/usr/bin/env python3
"""Prepare or submit the exact Win's VPN iOS/macOS release for App Review."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import apple_app_store_connect_auth_probe as auth_probe
from apple_app_store_connect_release_status import (
    APP_ID,
    APP_VERSION,
    BUILD_NUMBER,
    AppStoreConnectClient,
    ReleaseStatusError,
    _attributes,
    _collection,
    _load_client,
    _resource_or_none,
    _review_submission_status,
    audit,
)
from apple_upload_exact_release_candidates import (
    Candidate,
    UploadGateError,
    candidate_map,
    run_release_gates,
)


ROOT = Path(__file__).resolve().parents[1]
ROLLOUT_PATH = ROOT / "app_store/apple/review/rollout_readiness.json"
RELEASE_CANDIDATE_PATH = ROOT / "app_store/apple/artifacts/release_candidate.json"
RUNTIME_EVIDENCE_PATH = ROOT / "app_store/apple/artifacts/runtime_evidence.json"
OWNER_SIGNOFF_PATH = ROOT / "app_store/apple/review/owner_signoff.json"
EXPECTED_SCOPE = "IOS_AND_MACOS_TOGETHER"
EXPECTED_SUBMIT_CONFIRMATION = (
    "SUBMIT_IOS_AND_MACOS_"
    f"{APP_VERSION.replace('.', '_')}_BUILD_{BUILD_NUMBER}"
)
EXPECTED_STOREFRONT_COUNT = 175
EXPECTED_SCREENSHOT_TYPES = {
    "ios": ["APP_IPHONE_67"],
    "macos": ["APP_DESKTOP"],
}
API_PLATFORM = {"ios": "IOS", "macos": "MAC_OS"}
PREFLIGHT_SCHEMA_VERSION = 1
RESOURCE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
REVIEW_SUBMISSION_STATES = {
    "READY_FOR_REVIEW",
    "WAITING_FOR_REVIEW",
    "IN_REVIEW",
    "UNRESOLVED_ISSUES",
    "CANCELING",
    "COMPLETING",
    "COMPLETE",
}
ACCEPTED_POST_SUBMIT_STATES = {
    "WAITING_FOR_REVIEW",
    "IN_REVIEW",
    "COMPLETING",
    "COMPLETE",
}
REVIEW_ITEM_STATES = {
    "READY_FOR_REVIEW",
    "ACCEPTED",
    "APPROVED",
    "REJECTED",
    "REMOVED",
}
REJECTED_ITEM_STATES = {"REJECTED", "REMOVED"}
ACTIVE_STATES = {
    "READY_FOR_REVIEW",
    "WAITING_FOR_REVIEW",
    "IN_REVIEW",
    "UNRESOLVED_ISSUES",
    "CANCELING",
    "COMPLETING",
}


class ReviewSubmitError(RuntimeError):
    pass


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewSubmitError("rollout readiness contains duplicate JSON keys")
        result[key] = value
    return result


def _reject_non_finite_json(value: str) -> None:
    raise ReviewSubmitError(f"rollout readiness contains non-finite JSON: {value}")


def read_rollout() -> dict[str, Any]:
    try:
        value = json.loads(
            ROLLOUT_PATH.read_text(encoding="utf-8"),
            object_pairs_hook=_json_object_no_duplicates,
            parse_constant=_reject_non_finite_json,
        )
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise ReviewSubmitError("could not read rollout readiness") from exc
    if not isinstance(value, dict):
        raise ReviewSubmitError("rollout readiness must contain a JSON object")
    return value


def require_confirmation(label: str, supplied: str | None, expected: str) -> None:
    if supplied != expected:
        raise ReviewSubmitError(f"{label} confirmation does not match the release")


def _require_resource_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or RESOURCE_ID_RE.fullmatch(value) is None:
        raise ReviewSubmitError(f"{label} resource ID is invalid")
    return value


def _file_sha256(path: Path, label: str) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ReviewSubmitError(f"could not read {label}") from exc
    return hashlib.sha256(data).hexdigest()


def require_rollout_compliance() -> None:
    rollout = read_rollout()
    compliance = rollout.get("app_store_connect_compliance_status")
    blockers = rollout.get("remaining_blockers")
    if not isinstance(compliance, dict) or not isinstance(blockers, dict):
        raise ReviewSubmitError("rollout compliance state is malformed")
    if compliance.get("dsa_trader_status") != "verified":
        raise ReviewSubmitError("DSA trader information is not verified")
    for blocker in (
        "digital_services_act_trader_verification",
        "encryption_export_documentation",
        "macos_pkg_clean_install",
    ):
        if blocker in blockers:
            raise ReviewSubmitError(f"release blocker is still active: {blocker}")


def target_version_ids(result: dict[str, Any]) -> dict[str, str]:
    platforms = result.get("platforms")
    if not isinstance(platforms, dict):
        raise ReviewSubmitError("live platform status is malformed")
    version_ids: dict[str, str] = {}
    for platform in ("ios", "macos"):
        item = platforms.get(platform)
        if not isinstance(item, dict):
            raise ReviewSubmitError(f"live {platform} platform status is missing")
        version_id = _require_resource_id(
            item.get("version_id"), f"live {platform} version"
        )
        version_ids[platform] = version_id
    if len(set(version_ids.values())) != len(version_ids):
        raise ReviewSubmitError("live iOS and macOS versions share a resource ID")
    return version_ids


def find_target_submission(
    review_status: dict[str, Any],
    version_ids: dict[str, str],
) -> dict[str, Any] | None:
    if not isinstance(review_status, dict):
        raise ReviewSubmitError("review submission status is malformed")
    records = review_status.get("records")
    if not isinstance(records, list):
        raise ReviewSubmitError("review submission status is malformed")
    if type(review_status.get("count")) is not int or review_status["count"] != len(
        records
    ):
        raise ReviewSubmitError("review submission count is ambiguous")
    if set(version_ids) != {"ios", "macos"}:
        raise ReviewSubmitError("target version identity is incomplete")
    expected_by_id = {
        _require_resource_id(version_ids[platform], f"{platform} target version"): (
            API_PLATFORM[platform],
            platform,
        )
        for platform in ("ios", "macos")
    }
    if len(expected_by_id) != 2:
        raise ReviewSubmitError("target versions are ambiguous")
    expected_ids = set(expected_by_id)
    exact: list[dict[str, Any]] = []
    seen_submission_ids: set[str] = set()
    seen_item_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ReviewSubmitError("review submission record is malformed")
        submission_id = _require_resource_id(
            record.get("id"), "review submission"
        )
        if submission_id in seen_submission_ids:
            raise ReviewSubmitError("review submission resource is duplicated")
        seen_submission_ids.add(submission_id)
        state = record.get("state")
        if state not in REVIEW_SUBMISSION_STATES:
            raise ReviewSubmitError("review submission state is unknown")
        record_platform = record.get("platform")
        if record_platform not in {"IOS", "MAC_OS", "MULTI_PLATFORM"}:
            raise ReviewSubmitError("review submission platform is invalid")
        platforms = record.get("platforms")
        if (
            not isinstance(platforms, list)
            or any(platform not in {"IOS", "MAC_OS"} for platform in platforms)
            or len(platforms) != len(set(platforms))
        ):
            raise ReviewSubmitError("review submission platforms are malformed")
        items = record.get("items")
        if not isinstance(items, list):
            raise ReviewSubmitError("review submission items are malformed")
        item_count = record.get("item_count")
        non_version_count = record.get("non_app_store_version_item_count")
        if (
            type(item_count) is not int
            or type(non_version_count) is not int
            or item_count < 0
            or non_version_count < 0
            or non_version_count > item_count
            or len(items) != item_count - non_version_count
        ):
            raise ReviewSubmitError("review submission item counts are inconsistent")
        item_version_ids: set[str] = set()
        item_platforms: set[str] = set()
        target_item_states: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                raise ReviewSubmitError("review submission item is malformed")
            item_id = _require_resource_id(item.get("id"), "review submission item")
            if item_id in seen_item_ids:
                raise ReviewSubmitError("review submission item resource is duplicated")
            seen_item_ids.add(item_id)
            item_state = item.get("state")
            if item_state not in REVIEW_ITEM_STATES:
                raise ReviewSubmitError("review submission item state is unknown")
            version_id = _require_resource_id(
                item.get("app_store_version_id"),
                "review submission item App Store version",
            )
            if version_id in item_version_ids:
                raise ReviewSubmitError(
                    "review submission contains a duplicate App Store version"
                )
            item_version_ids.add(version_id)
            item_platform = item.get("platform")
            item_version = item.get("version")
            if item_platform not in {"IOS", "MAC_OS"} or not isinstance(
                item_version, str
            ):
                raise ReviewSubmitError("review submission item identity is malformed")
            item_platforms.add(item_platform)
            if version_id in expected_by_id:
                expected_platform, _ = expected_by_id[version_id]
                if item_platform != expected_platform or item_version != APP_VERSION:
                    raise ReviewSubmitError(
                        "review submission item does not match its target version"
                    )
                if item_state in REJECTED_ITEM_STATES:
                    raise ReviewSubmitError(
                        "target review submission contains a rejected or removed item"
                    )
                target_item_states.add(item_state)
        if set(platforms) != item_platforms | (
            {record_platform} if record_platform in {"IOS", "MAC_OS"} else set()
        ):
            raise ReviewSubmitError("review submission platform identity drifted")
        touches_target = bool(item_version_ids & expected_ids)
        is_exact = (
            item_version_ids == expected_ids
            and item_count == 2
            and non_version_count == 0
            and set(platforms) == {"IOS", "MAC_OS"}
            and record_platform == "MULTI_PLATFORM"
        )
        if touches_target and not is_exact:
            raise ReviewSubmitError(
                "an existing review submission partially or incompatibly uses this release"
            )
        if is_exact:
            if state == "READY_FOR_REVIEW" and target_item_states != {
                "READY_FOR_REVIEW"
            }:
                raise ReviewSubmitError(
                    "prepared review submission item state is not exact"
                )
            exact.append(record)
        elif state in ACTIVE_STATES:
            raise ReviewSubmitError(
                "an unrelated active App Review submission must be resolved first"
            )
    if len(exact) > 1:
        raise ReviewSubmitError("multiple review submissions target this exact release")
    submitted_states = {
        "WAITING_FOR_REVIEW",
        "IN_REVIEW",
        "UNRESOLVED_ISSUES",
        "COMPLETING",
        "COMPLETE",
    }
    derived_submitted_platforms = sorted(
        {
            platform
            for record in records
            if record.get("state") in submitted_states
            for platform in record.get("platforms", [])
        }
    )
    if (
        review_status.get("submitted_platforms") != derived_submitted_platforms
        or review_status.get("both_platforms_submitted")
        is not (set(derived_submitted_platforms) == {"IOS", "MAC_OS"})
    ):
        raise ReviewSubmitError("review submission aggregate state is inconsistent")
    return exact[0] if exact else None


def require_live_release_contract(
    result: dict[str, Any],
    *,
    expected_version_state: str,
) -> dict[str, str]:
    if result.get("schema_version") != 1:
        raise ReviewSubmitError("live App Store audit schema is stale")
    if result.get("app_id") != APP_ID or result.get("app_version") != APP_VERSION:
        raise ReviewSubmitError("live app identity or version does not match")
    if result.get("build_number") != BUILD_NUMBER:
        raise ReviewSubmitError("live build number does not match")
    if result.get("bundle_id") != "org.winsvpn.app":
        raise ReviewSubmitError("live bundle ID does not match")

    versions = target_version_ids(result)
    platforms = result["platforms"]
    builds = result.get("builds")
    if not isinstance(builds, list) or len(builds) != 2:
        raise ReviewSubmitError("live build status is malformed")
    if (
        result.get("processed_platforms") != ["ios", "macos"]
        or result.get("both_platform_builds_processed") is not True
    ):
        raise ReviewSubmitError("both exact platform builds are not processed")
    builds_by_platform: dict[str, dict[str, Any]] = {}
    seen_build_ids: set[str] = set()
    for build in builds:
        if not isinstance(build, dict):
            raise ReviewSubmitError("live build record is malformed")
        platform = build.get("platform")
        if platform not in set(API_PLATFORM.values()) or platform in builds_by_platform:
            raise ReviewSubmitError("live processed build platforms are ambiguous")
        build_id = _require_resource_id(build.get("id"), f"live {platform} build")
        if build_id in seen_build_ids:
            raise ReviewSubmitError("live processed build resource is duplicated")
        seen_build_ids.add(build_id)
        if (
            build.get("version") != BUILD_NUMBER
            or build.get("processing_state") != "VALID"
            or build.get("expired") is not False
        ):
            raise ReviewSubmitError(
                f"live {platform} build is not the exact processed release build"
            )
        builds_by_platform[platform] = build
    build_ids: dict[str, str] = {}
    for platform in ("ios", "macos"):
        item = platforms[platform]
        if item.get("state") != expected_version_state:
            raise ReviewSubmitError(
                f"{platform} version state is not exactly {expected_version_state}"
            )
        if item.get("release_type") != "MANUAL":
            raise ReviewSubmitError(f"{platform} release type is not manual")
        if item.get("metadata_matches") is not True:
            raise ReviewSubmitError(f"{platform} metadata does not match")
        if item.get("screenshot_count") != 1:
            raise ReviewSubmitError(f"{platform} must have exactly one approved screenshot")
        if item.get("screenshot_display_types") != EXPECTED_SCREENSHOT_TYPES[platform]:
            raise ReviewSubmitError(f"{platform} screenshot display type does not match")
        if (
            item.get("review_detail_present") is not True
            or item.get("review_contact_complete") is not True
            or item.get("review_notes_present") is not True
            or item.get("demo_account_required") is not False
        ):
            raise ReviewSubmitError(f"{platform} App Review details are incomplete")
        selected_build_id = _require_resource_id(
            item.get("selected_build_id"), f"selected {platform} build"
        )
        build_id = _require_resource_id(
            builds_by_platform[API_PLATFORM[platform]].get("id"),
            f"live {platform} build",
        )
        if selected_build_id != build_id:
            raise ReviewSubmitError(
                f"{platform} build {BUILD_NUMBER} is not valid, current, and selected"
            )
        build_ids[platform] = build_id

    app_info = result.get("app_info")
    if not isinstance(app_info, dict) or app_info.get("privacy_policy_url_matches") is not True:
        raise ReviewSubmitError("published privacy policy URL does not match")
    price = result.get("price_schedule")
    if not isinstance(price, dict) or not (
        price.get("configured") is True
        and price.get("all_free") is True
        and price.get("territory_count") == EXPECTED_STOREFRONT_COUNT
        and price.get("active_territory_count") == EXPECTED_STOREFRONT_COUNT
        and not price.get("missing_territories")
        and not price.get("unexpected_territories")
    ):
        raise ReviewSubmitError("free 175-storefront price schedule is not exact")
    availability = result.get("availability")
    if not isinstance(availability, dict) or not (
        availability.get("configured") is True
        and availability.get("available_in_new_territories") is True
        and availability.get("available_territory_count")
        == EXPECTED_STOREFRONT_COUNT
        and availability.get("active_territory_count")
        == EXPECTED_STOREFRONT_COUNT
        and not availability.get("missing_territories")
        and not availability.get("unexpected_territories")
    ):
        raise ReviewSubmitError("all 175 storefronts are not exactly available")
    encryption = result.get("encryption_declarations")
    if not isinstance(encryption, dict) or encryption.get("accepted_count", 0) < 1:
        raise ReviewSubmitError("Apple has no accepted encryption declaration")
    accessibility = result.get("accessibility_declarations")
    if not isinstance(accessibility, dict) or accessibility.get(
        "matches_release_decision"
    ) is not True:
        raise ReviewSubmitError("accessibility declarations do not match release decision")
    return build_ids


def accepted_encryption_declaration_ids(
    client: AppStoreConnectClient,
) -> set[str]:
    declarations = _collection(
        client.get(
            "/v1/appEncryptionDeclarations",
            {"filter[app]": APP_ID, "limit": "50"},
        ),
        "app encryption declarations",
    )
    accepted: set[str] = set()
    for declaration in declarations:
        declaration_id = str(declaration.get("id") or "")
        state = _attributes(
            declaration, "app encryption declaration"
        ).get("appEncryptionDeclarationState")
        if state == "APPROVED" and declaration_id:
            accepted.add(declaration_id)
    return accepted


def require_build_encryption_declarations(
    client: AppStoreConnectClient,
    build_ids: dict[str, str],
) -> dict[str, str]:
    accepted = accepted_encryption_declaration_ids(client)
    if not accepted:
        raise ReviewSubmitError("Apple has no accepted encryption declaration ID")
    linked: dict[str, str] = {}
    for platform in ("ios", "macos"):
        build_id = _require_resource_id(
            build_ids.get(platform), f"{platform} encryption-bound build"
        )
        declaration = _resource_or_none(
            client.get(
                f"/v1/builds/{build_id}/appEncryptionDeclaration",
                allow_missing_relationship=True,
            ),
            f"{platform} build encryption declaration",
        )
        if declaration is None or declaration.get("type") != "appEncryptionDeclarations":
            raise ReviewSubmitError(
                f"{platform} build is not linked to an accepted encryption declaration"
            )
        declaration_id = _require_resource_id(
            declaration.get("id"), f"{platform} encryption declaration"
        )
        if declaration_id not in accepted:
            raise ReviewSubmitError(
                f"{platform} build is not linked to an accepted encryption declaration"
            )
        linked[platform] = declaration_id
    return linked


def submission_relationships() -> dict[str, Any]:
    return {"app": {"data": {"type": "apps", "id": APP_ID}}}


def item_relationships(submission_id: str, version_id: str) -> dict[str, Any]:
    submission_id = _require_resource_id(submission_id, "review submission relationship")
    version_id = _require_resource_id(version_id, "App Store version relationship")
    return {
        "reviewSubmission": {
            "data": {"type": "reviewSubmissions", "id": submission_id}
        },
        "appStoreVersion": {
            "data": {"type": "appStoreVersions", "id": version_id}
        },
    }


def _require_relationship(
    resource: dict[str, Any],
    name: str,
    expected_type: str,
    expected_id: str,
) -> None:
    relationships = resource.get("relationships")
    relationship = relationships.get(name) if isinstance(relationships, dict) else None
    data = relationship.get("data") if isinstance(relationship, dict) else None
    if not isinstance(data, dict) or set(data) != {"type", "id"}:
        raise ReviewSubmitError(f"{name} response relationship is malformed")
    if data.get("type") != expected_type or data.get("id") != expected_id:
        raise ReviewSubmitError(f"{name} response relationship identity drifted")


def require_submission_response(
    payload: dict[str, Any],
    *,
    expected_id: str | None = None,
) -> dict[str, Any]:
    resource = _resource_or_none(payload, "review submission mutation")
    if resource is None or resource.get("type") != "reviewSubmissions":
        raise ReviewSubmitError("review submission mutation returned no exact resource")
    submission_id = _require_resource_id(
        resource.get("id"), "review submission mutation"
    )
    if expected_id is not None and submission_id != expected_id:
        raise ReviewSubmitError("review submission mutation returned another resource")
    _require_relationship(resource, "app", "apps", APP_ID)
    state = _attributes(resource, "review submission mutation").get("state")
    if state not in REVIEW_SUBMISSION_STATES:
        raise ReviewSubmitError("review submission mutation returned an unknown state")
    return resource


def require_submission_item_response(
    payload: dict[str, Any],
    *,
    submission_id: str,
    version_id: str,
) -> dict[str, Any]:
    resource = _resource_or_none(payload, "review submission item mutation")
    if resource is None or resource.get("type") != "reviewSubmissionItems":
        raise ReviewSubmitError("review item mutation returned no exact resource")
    _require_resource_id(resource.get("id"), "review submission item mutation")
    _require_relationship(
        resource,
        "reviewSubmission",
        "reviewSubmissions",
        submission_id,
    )
    _require_relationship(
        resource,
        "appStoreVersion",
        "appStoreVersions",
        version_id,
    )
    state = _attributes(resource, "review submission item mutation").get("state")
    if state != "READY_FOR_REVIEW":
        raise ReviewSubmitError("created review item is not ready for review")
    return resource


def preflight_digest(
    candidates: dict[str, Candidate],
    result: dict[str, Any],
    build_ids: dict[str, str],
    encryption_links: dict[str, str],
) -> str:
    if set(candidates) != {"ios", "macos"}:
        raise ReviewSubmitError("frozen Apple candidate set is incomplete")
    candidate_records: dict[str, dict[str, Any]] = {}
    for platform in ("ios", "macos"):
        candidate = candidates[platform]
        expected_type = "ipa" if platform == "ios" else "pkg"
        if (
            candidate.platform != platform
            or candidate.artifact_type != expected_type
            or not isinstance(candidate.relative_path, str)
            or not candidate.relative_path
            or Path(candidate.relative_path).is_absolute()
            or type(candidate.size_bytes) is not int
            or candidate.size_bytes <= 0
            or re.fullmatch(r"[0-9a-f]{64}", candidate.sha256) is None
        ):
            raise ReviewSubmitError("frozen Apple candidate platform drifted")
        candidate_records[platform] = {
            "artifact_type": candidate.artifact_type,
            "relative_path": candidate.relative_path,
            "sha256": candidate.sha256,
            "size_bytes": candidate.size_bytes,
        }
    payload = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "app_id": APP_ID,
        "bundle_id": "org.winsvpn.app",
        "app_version": APP_VERSION,
        "build_number": BUILD_NUMBER,
        "scope": EXPECTED_SCOPE,
        "release_candidate_manifest_sha256": _file_sha256(
            RELEASE_CANDIDATE_PATH, "release candidate manifest"
        ),
        "runtime_evidence_sha256": _file_sha256(
            RUNTIME_EVIDENCE_PATH, "runtime evidence manifest"
        ),
        "owner_signoff_sha256": _file_sha256(
            OWNER_SIGNOFF_PATH, "owner signoff manifest"
        ),
        "rollout_readiness_sha256": _file_sha256(
            ROLLOUT_PATH, "rollout readiness"
        ),
        "candidates": candidate_records,
        "selected_build_ids": {
            platform: _require_resource_id(
                build_ids.get(platform), f"{platform} preflight build"
            )
            for platform in ("ios", "macos")
        },
        "encryption_declaration_ids": {
            platform: _require_resource_id(
                encryption_links.get(platform),
                f"{platform} preflight encryption declaration",
            )
            for platform in ("ios", "macos")
        },
        "authenticated_audit": result,
    }
    try:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ReviewSubmitError("App Review preflight state is not canonical") from exc
    return hashlib.sha256(canonical).hexdigest()


def owner_authorization_for_digest(digest: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ReviewSubmitError("App Review preflight digest is invalid")
    return f"AUTHORIZE_APP_REVIEW_SHA256_{digest}"


def refresh_frozen_candidates(
    expected: dict[str, Candidate],
) -> dict[str, Candidate]:
    current = candidate_map(
        allowed_upload_statuses=frozenset(
            {"not_uploaded", "uploaded_processed_and_attached"}
        )
    )
    if current != expected:
        raise ReviewSubmitError(
            "frozen Apple candidate identity changed after owner confirmation"
        )
    return current


def capture_preflight(
    client: AppStoreConnectClient,
    candidates: dict[str, Candidate],
) -> dict[str, Any]:
    result = audit(client)
    version_ids = target_version_ids(result)
    existing = find_target_submission(result.get("review_submissions"), version_ids)
    if existing is None:
        expected_version_state = "PREPARE_FOR_SUBMISSION"
    else:
        state = existing.get("state")
        if state != "READY_FOR_REVIEW":
            if state in ACCEPTED_POST_SUBMIT_STATES:
                raise ReviewSubmitError("the exact release is already submitted")
            raise ReviewSubmitError(
                "the exact release has a rejected, canceling, or unresolved submission"
            )
        expected_version_state = "READY_FOR_REVIEW"
    build_ids = require_live_release_contract(
        result,
        expected_version_state=expected_version_state,
    )
    encryption_links = require_build_encryption_declarations(client, build_ids)
    digest = preflight_digest(candidates, result, build_ids, encryption_links)
    return {
        "result": result,
        "version_ids": version_ids,
        "build_ids": build_ids,
        "encryption_links": encryption_links,
        "existing": existing,
        "digest": digest,
    }


def require_unchanged_preflight(
    client: AppStoreConnectClient,
    candidates: dict[str, Candidate],
    expected_digest: str,
) -> dict[str, Any]:
    current = capture_preflight(client, candidates)
    if current["digest"] != expected_digest:
        raise ReviewSubmitError(
            "authenticated App Review state changed after owner confirmation"
        )
    return current


def cleanup_created_submission(
    client: AppStoreConnectClient,
    submission_id: str,
    item_ids: list[str],
) -> list[str]:
    failures: list[str] = []
    for item_id in reversed(item_ids):
        try:
            client.delete_resource(
                f"/v1/reviewSubmissionItems/{item_id}",
                "reviewSubmissionItems",
                item_id,
            )
        except ReleaseStatusError:
            failures.append(f"item:{item_id}")
    try:
        client.delete_resource(
            f"/v1/reviewSubmissions/{submission_id}",
            "reviewSubmissions",
            submission_id,
        )
    except ReleaseStatusError:
        failures.append(f"submission:{submission_id}")
    return failures


def prepare_submission(
    client: AppStoreConnectClient,
    version_ids: dict[str, str],
) -> dict[str, Any]:
    if find_target_submission(
        _review_submission_status(client), version_ids
    ) is not None:
        raise ReviewSubmitError(
            "an exact review submission appeared immediately before preparation"
        )
    created = client.post_resource(
        "/v1/reviewSubmissions",
        "reviewSubmissions",
        {},
        submission_relationships(),
    )
    resource = require_submission_response(created)
    submission_id = _require_resource_id(
        resource.get("id"), "created review submission"
    )
    item_ids: list[str] = []
    try:
        if _attributes(resource, "created review submission").get("state") != (
            "READY_FOR_REVIEW"
        ):
            raise ReviewSubmitError(
                "created review submission is not ready for review"
            )
        for platform in ("ios", "macos"):
            response = client.post_resource(
                "/v1/reviewSubmissionItems",
                "reviewSubmissionItems",
                {},
                item_relationships(submission_id, version_ids[platform]),
            )
            item = require_submission_item_response(
                response,
                submission_id=submission_id,
                version_id=version_ids[platform],
            )
            item_id = _require_resource_id(
                item.get("id"), f"created {platform} review submission item"
            )
            if item_id in item_ids:
                raise ReviewSubmitError("Apple returned a duplicate review item ID")
            item_ids.append(item_id)
        status = _review_submission_status(client)
        exact = find_target_submission(status, version_ids)
        if exact is None or exact.get("id") != submission_id:
            raise ReviewSubmitError("prepared review submission did not persist exactly")
        if exact.get("state") != "READY_FOR_REVIEW":
            raise ReviewSubmitError("prepared review submission is not ready for review")
        persisted_item_ids = {
            _require_resource_id(item.get("id"), "persisted review item")
            for item in exact.get("items", [])
            if isinstance(item, dict)
        }
        if persisted_item_ids != set(item_ids):
            raise ReviewSubmitError(
                "prepared review submission item identity did not persist exactly"
            )
        print(
            "PASS: prepared one cross-platform App Review submission with exact "
            "iOS and macOS version items"
        )
        return exact
    except Exception as exc:
        failures = cleanup_created_submission(client, submission_id, item_ids)
        if failures:
            raise ReviewSubmitError(
                "review submission preparation failed and cleanup was incomplete: "
                + ",".join(failures)
            ) from exc
        raise ReviewSubmitError(
            "review submission preparation failed; same-run cleanup completed"
        ) from exc


def submit_prepared_submission(
    client: AppStoreConnectClient,
    record: dict[str, Any],
    version_ids: dict[str, str],
) -> None:
    state = str(record.get("state") or "")
    submission_id = _require_resource_id(
        record.get("id"), "prepared review submission"
    )
    if state in ACCEPTED_POST_SUBMIT_STATES:
        raise ReviewSubmitError("the exact review submission is already submitted")
    if state != "READY_FOR_REVIEW":
        raise ReviewSubmitError("exact review submission is not ready to submit")
    current = find_target_submission(
        _review_submission_status(client), version_ids
    )
    if current is None or current != record:
        raise ReviewSubmitError(
            "prepared review submission changed immediately before mutation"
        )
    response = client.patch_attributes(
        f"/v1/reviewSubmissions/{submission_id}",
        "reviewSubmissions",
        submission_id,
        {"submitted": True},
    )
    patched = require_submission_response(response, expected_id=submission_id)
    patched_state = _attributes(
        patched, "submitted review submission"
    ).get("state")
    if patched_state not in ACCEPTED_POST_SUBMIT_STATES:
        raise ReviewSubmitError(
            "review submission mutation returned an unaccepted state"
        )
    updated = find_target_submission(_review_submission_status(client), version_ids)
    if (
        updated is None
        or updated.get("id") != submission_id
        or updated.get("state") not in ACCEPTED_POST_SUBMIT_STATES
    ):
        raise ReviewSubmitError("Apple did not accept the exact review submission")
    print(
        f"PASS: submitted exact iOS and macOS version {APP_VERSION} "
        f"build {BUILD_NUMBER} together state={updated['state']}"
    )


def run_selftest() -> None:
    version_ids = {"ios": "version-ios", "macos": "version-macos"}
    exact_record = {
        "id": "submission-one",
        "platform": "MULTI_PLATFORM",
        "platforms": ["IOS", "MAC_OS"],
        "state": "READY_FOR_REVIEW",
        "item_count": 2,
        "non_app_store_version_item_count": 0,
        "items": [
            {
                "id": "item-ios",
                "state": "READY_FOR_REVIEW",
                "app_store_version_id": "version-ios",
                "platform": "IOS",
                "version": APP_VERSION,
            },
            {
                "id": "item-macos",
                "state": "READY_FOR_REVIEW",
                "app_store_version_id": "version-macos",
                "platform": "MAC_OS",
                "version": APP_VERSION,
            },
        ],
    }
    found = find_target_submission(
        {
            "count": 1,
            "records": [exact_record],
            "submitted_platforms": [],
            "both_platforms_submitted": False,
        },
        version_ids,
    )
    if found is not exact_record:
        raise ReviewSubmitError("self-test did not select the exact submission")
    partial = dict(
        exact_record,
        platforms=["IOS"],
        item_count=1,
        items=exact_record["items"][:1],
    )
    try:
        find_target_submission(
            {
                "count": 1,
                "records": [partial],
                "submitted_platforms": [],
                "both_platforms_submitted": False,
            },
            version_ids,
        )
    except ReviewSubmitError as exc:
        if "partially or incompatibly" not in str(exc):
            raise
    else:
        raise ReviewSubmitError("self-test accepted a partial review submission")
    relationships = item_relationships("submission-one", "version-ios")
    if (
        relationships["reviewSubmission"]["data"]["id"] != "submission-one"
        or relationships["appStoreVersion"]["data"]["id"] != "version-ios"
        or submission_relationships()["app"]["data"]["id"] != APP_ID
    ):
        raise ReviewSubmitError("self-test built incorrect review relationships")

    platform_template = {
        "state": "PREPARE_FOR_SUBMISSION",
        "release_type": "MANUAL",
        "metadata_matches": True,
        "screenshot_count": 1,
        "review_detail_present": True,
        "review_contact_complete": True,
        "review_notes_present": True,
        "demo_account_required": False,
    }
    live_result: dict[str, Any] = {
        "schema_version": 1,
        "app_id": APP_ID,
        "app_version": APP_VERSION,
        "build_number": BUILD_NUMBER,
        "bundle_id": "org.winsvpn.app",
        "platforms": {
            "ios": {
                **platform_template,
                "version_id": "version-ios",
                "screenshot_display_types": ["APP_IPHONE_67"],
                "selected_build_id": "build-ios",
            },
            "macos": {
                **platform_template,
                "version_id": "version-macos",
                "screenshot_display_types": ["APP_DESKTOP"],
                "selected_build_id": "build-macos",
            },
        },
        "builds": [
            {
                "id": "build-ios",
                "platform": "IOS",
                "version": BUILD_NUMBER,
                "processing_state": "VALID",
                "expired": False,
            },
            {
                "id": "build-macos",
                "platform": "MAC_OS",
                "version": BUILD_NUMBER,
                "processing_state": "VALID",
                "expired": False,
            },
        ],
        "processed_platforms": ["ios", "macos"],
        "both_platform_builds_processed": True,
        "app_info": {"privacy_policy_url_matches": True},
        "price_schedule": {
            "configured": True,
            "all_free": True,
            "territory_count": EXPECTED_STOREFRONT_COUNT,
            "active_territory_count": EXPECTED_STOREFRONT_COUNT,
            "missing_territories": [],
            "unexpected_territories": [],
        },
        "availability": {
            "configured": True,
            "available_in_new_territories": True,
            "available_territory_count": EXPECTED_STOREFRONT_COUNT,
            "active_territory_count": EXPECTED_STOREFRONT_COUNT,
            "missing_territories": [],
            "unexpected_territories": [],
        },
        "encryption_declarations": {"accepted_count": 1},
        "accessibility_declarations": {"matches_release_decision": True},
    }
    if require_live_release_contract(
        live_result, expected_version_state="PREPARE_FOR_SUBMISSION"
    ) != {"ios": "build-ios", "macos": "build-macos"}:
        raise ReviewSubmitError("self-test lost exact build selection")
    for label, mutate in (
        (
            "screenshot",
            lambda value: value["platforms"]["ios"].update(
                {"screenshot_display_types": ["APP_IPHONE_65"]}
            ),
        ),
        (
            "availability",
            lambda value: value["availability"].update({"configured": False}),
        ),
        (
            "encryption",
            lambda value: value["encryption_declarations"].update(
                {"accepted_count": 0}
            ),
        ),
    ):
        invalid = json.loads(json.dumps(live_result))
        mutate(invalid)
        try:
            require_live_release_contract(
                invalid,
                expected_version_state="PREPARE_FOR_SUBMISSION",
            )
        except ReviewSubmitError:
            continue
        raise ReviewSubmitError(f"self-test accepted invalid {label} state")
    print("PASS: exact cross-platform App Review submission self-test")
    print("SUMMARY: 1/1 checks passing")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--preflight", action="store_true")
    actions.add_argument("--prepare", action="store_true")
    actions.add_argument("--submit", action="store_true")
    parser.add_argument("--confirm-apple-id")
    parser.add_argument("--confirm-version")
    parser.add_argument("--confirm-build")
    parser.add_argument("--confirm-ios-sha256")
    parser.add_argument("--confirm-macos-sha256")
    parser.add_argument("--confirm-scope")
    parser.add_argument("--confirm-submit")
    parser.add_argument("--confirm-preflight-sha256")
    parser.add_argument("--confirm-owner-authorization")
    parser.add_argument("--selftest", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.selftest:
            if args.preflight or args.prepare or args.submit:
                raise ReviewSubmitError(
                    "--selftest cannot be combined with release actions"
                )
            run_selftest()
            return 0

        candidates: dict[str, Candidate] = candidate_map(
            allowed_upload_statuses=frozenset(
                {"not_uploaded", "uploaded_processed_and_attached"}
            )
        )
        for platform in ("ios", "macos"):
            print(
                f"PASS: frozen {platform} artifact verified "
                f"sha256={candidates[platform].sha256}"
            )
        if not (args.preflight or args.prepare or args.submit):
            print("DRY RUN: no App Review resource was queried or changed")
            return 0

        require_confirmation("Apple ID", args.confirm_apple_id, APP_ID)
        require_confirmation("version", args.confirm_version, APP_VERSION)
        require_confirmation("build", args.confirm_build, BUILD_NUMBER)
        require_confirmation(
            "iOS SHA-256", args.confirm_ios_sha256, candidates["ios"].sha256
        )
        require_confirmation(
            "macOS SHA-256",
            args.confirm_macos_sha256,
            candidates["macos"].sha256,
        )
        require_confirmation("submission scope", args.confirm_scope, EXPECTED_SCOPE)
        if args.submit:
            require_confirmation(
                "final submit",
                args.confirm_submit,
                EXPECTED_SUBMIT_CONFIRMATION,
            )

        run_release_gates(candidates)
        require_rollout_compliance()
        client = _load_client()
        preflight = capture_preflight(client, candidates)
        digest = preflight["digest"]
        owner_authorization = owner_authorization_for_digest(digest)
        print(
            "PASS: owner, package, clean-install, DSA, metadata, screenshots, "
            "builds, availability, and encryption gates passed"
        )
        print(f"APP_REVIEW_PREFLIGHT_SHA256={digest}")
        print(f"APP_REVIEW_OWNER_AUTHORIZATION={owner_authorization}")
        if args.preflight:
            print("PREFLIGHT ONLY: no App Review resource was changed")
            return 0
        require_confirmation(
            "preflight SHA-256",
            args.confirm_preflight_sha256,
            digest,
        )
        require_confirmation(
            "owner authorization",
            args.confirm_owner_authorization,
            owner_authorization,
        )
        candidates = refresh_frozen_candidates(candidates)
        current = require_unchanged_preflight(client, candidates, digest)
        existing = current["existing"]
        version_ids = current["version_ids"]
        if args.prepare:
            if existing is None:
                prepared = prepare_submission(client, version_ids)
                verified = capture_preflight(client, candidates)
                persisted = verified["existing"]
                if (
                    persisted is None
                    or persisted.get("id") != prepared.get("id")
                    or persisted.get("state") != "READY_FOR_REVIEW"
                ):
                    raise ReviewSubmitError(
                        "prepared App Review state failed full authenticated revalidation"
                    )
            else:
                print(
                    "PASS: exact cross-platform App Review submission already exists "
                    f"state={existing['state']}"
                )
            print(
                "PREPARED ONLY: the exact App Review submission was not submitted"
            )
            return 0
        if existing is None:
            raise ReviewSubmitError(
                "no exact prepared submission exists; run --prepare, then a new "
                "--preflight before --submit"
            )
        submit_prepared_submission(client, existing, version_ids)
        return 0
    except (
        ReviewSubmitError,
        UploadGateError,
        ReleaseStatusError,
        auth_probe.ProbeError,
        AssertionError,
        OSError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
