#!/usr/bin/env python3
"""Create exact all-storefront availability after owner-authorized preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import apple_app_store_connect_auth_probe as auth_probe
import apple_attach_processed_builds as build_attach
from apple_app_store_connect_release_status import (
    APP_ID,
    APP_VERSION,
    BUILD_NUMBER,
    BUNDLE_ID,
    AppStoreConnectClient,
    ReleaseStatusError,
    _attributes,
    _collection,
    _load_client,
    _price_status,
    _relationship_data,
    _resource_or_none,
)
from apple_upload_exact_release_candidates import (
    Candidate,
    UploadGateError,
    candidate_map,
)
from validate_apple_owner_signoff import validate_owner_signoff


ROOT = Path(__file__).resolve().parents[1]
ROLLOUT_PATH = ROOT / "app_store/apple/review/rollout_readiness.json"
EXPECTED_STOREFRONT_COUNT = 175
EXPECTED_SCOPE_CONFIRMATION = "ALL_175_ACTIVE_STOREFRONTS"
PREFLIGHT_SCHEMA_VERSION = 1
OWNER_AUTHORIZATION_PREFIX = "AUTHORIZE_APPLE_AVAILABILITY_SHA256_"
RESOURCE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")


class AvailabilityError(RuntimeError):
    pass


def _json_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AvailabilityError("rollout readiness contains duplicate JSON keys")
        result[key] = value
    return result


def _reject_non_finite_json(value: str) -> None:
    raise AvailabilityError(f"rollout readiness contains non-finite JSON: {value}")


def read_rollout() -> dict[str, Any]:
    try:
        value = json.loads(
            ROLLOUT_PATH.read_text(encoding="utf-8"),
            object_pairs_hook=_json_object_no_duplicates,
            parse_constant=_reject_non_finite_json,
        )
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise AvailabilityError("could not read rollout readiness") from exc
    if not isinstance(value, dict):
        raise AvailabilityError("rollout readiness must contain a JSON object")
    return value


def require_dsa_verified() -> None:
    rollout = read_rollout()
    compliance = rollout.get("app_store_connect_compliance_status")
    blockers = rollout.get("remaining_blockers")
    if not isinstance(compliance, dict) or not isinstance(blockers, dict):
        raise AvailabilityError("rollout compliance state is malformed")
    if compliance.get("dsa_trader_status") != "verified":
        raise AvailabilityError(
            "Digital Services Act trader information is not verified"
        )
    if "digital_services_act_trader_verification" in blockers:
        raise AvailabilityError("Digital Services Act rollout blocker is still active")


def _require_resource_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or RESOURCE_ID_RE.fullmatch(value) is None:
        raise AvailabilityError(f"{label} resource ID is invalid")
    return value


def _file_sha256(path: Path, label: str) -> str:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise AvailabilityError(f"could not read {label}") from exc
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha256(payload: dict[str, Any], label: str) -> str:
    try:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AvailabilityError(f"{label} is not canonical") from exc
    return hashlib.sha256(canonical).hexdigest()


def availability_payload(territory_ids: set[str]) -> dict[str, Any]:
    if (
        len(territory_ids) != EXPECTED_STOREFRONT_COUNT
        or any(_require_resource_id(value, "territory") != value for value in territory_ids)
    ):
        raise AvailabilityError("active territory set is not the exact approved scope")
    relationship_data: list[dict[str, str]] = []
    included: list[dict[str, Any]] = []
    for territory_id in sorted(territory_ids):
        local_id = f"winsvpn-availability-{territory_id}"
        relationship_data.append(
            {"type": "territoryAvailabilities", "id": local_id}
        )
        included.append(
            {
                "type": "territoryAvailabilities",
                "id": local_id,
                "attributes": {
                    "available": True,
                    "preOrderEnabled": False,
                },
                "relationships": {
                    "territory": {
                        "data": {"type": "territories", "id": territory_id}
                    }
                },
            }
        )
    return {
        "data": {
            "type": "appAvailabilities",
            "attributes": {"availableInNewTerritories": True},
            "relationships": {
                "app": {"data": {"type": "apps", "id": APP_ID}},
                "territoryAvailabilities": {"data": relationship_data},
            },
        },
        "included": included,
    }


def payload_sha256(payload: dict[str, Any]) -> str:
    return _canonical_sha256(payload, "all-storefront availability payload")


def require_confirmations(args: argparse.Namespace) -> None:
    if args.confirm_apple_id != APP_ID:
        raise AvailabilityError(f"--confirm-apple-id must be {APP_ID}")
    if args.confirm_version != APP_VERSION:
        raise AvailabilityError(f"--confirm-version must be {APP_VERSION}")
    if args.confirm_build != BUILD_NUMBER:
        raise AvailabilityError(f"--confirm-build must be {BUILD_NUMBER}")
    if args.confirm_storefront_count != EXPECTED_STOREFRONT_COUNT:
        raise AvailabilityError(
            f"--confirm-storefront-count must be {EXPECTED_STOREFRONT_COUNT}"
        )
    if args.confirm_scope != EXPECTED_SCOPE_CONFIRMATION:
        raise AvailabilityError(
            f"--confirm-scope must be {EXPECTED_SCOPE_CONFIRMATION}"
        )


def require_confirmation(label: str, supplied: str | None, expected: str) -> None:
    if supplied != expected:
        raise AvailabilityError(f"{label} confirmation does not match the release")


def require_owner_approval() -> None:
    try:
        validate_owner_signoff(ROOT, require_approved=True)
    except AssertionError as exc:
        raise AvailabilityError(str(exc)) from exc


def active_territory_state(client: AppStoreConnectClient) -> list[str]:
    payload = client.get("/v1/territories", {"limit": "200"})
    resources = _collection(payload, "territories")
    links = payload.get("links")
    if isinstance(links, dict) and links.get("next"):
        raise AvailabilityError("active territory response unexpectedly requires paging")
    territory_ids: list[str] = []
    seen: set[str] = set()
    for resource in resources:
        if resource.get("type") != "territories":
            raise AvailabilityError("active territory resource type is invalid")
        territory_id = _require_resource_id(resource.get("id"), "active territory")
        if territory_id in seen:
            raise AvailabilityError("active territory resource is duplicated")
        seen.add(territory_id)
        territory_ids.append(territory_id)
    if len(territory_ids) != EXPECTED_STOREFRONT_COUNT:
        raise AvailabilityError(
            "Apple's active storefront set changed; exact owner approval must be refreshed"
        )
    return sorted(territory_ids)


def exact_free_price_state(
    client: AppStoreConnectClient,
    territory_ids: set[str],
) -> dict[str, Any]:
    status = _price_status(client, territory_ids)
    if not (
        status.get("configured") is True
        and status.get("all_free") is True
        and status.get("entry_count") == EXPECTED_STOREFRONT_COUNT
        and status.get("territory_count") == EXPECTED_STOREFRONT_COUNT
        and status.get("active_territory_count") == EXPECTED_STOREFRONT_COUNT
        and status.get("missing_territories") == []
        and status.get("unexpected_territories") == []
    ):
        raise AvailabilityError("the free 175-storefront price schedule is not exact")
    return status


def availability_relationship_state(
    client: AppStoreConnectClient,
    active_territory_ids: set[str],
) -> dict[str, Any]:
    availability = _resource_or_none(
        client.get(
            f"/v1/apps/{APP_ID}/appAvailabilityV2",
            allow_missing_relationship=True,
        ),
        "app availability",
    )
    if availability is None:
        return {
            "configured": False,
            "app_availability_id": None,
            "available_in_new_territories": None,
            "territory_availabilities": [],
        }
    if availability.get("type") != "appAvailabilities":
        raise AvailabilityError("app availability relationship type is invalid")
    availability_id = _require_resource_id(
        availability.get("id"), "app availability"
    )
    detail = _resource_or_none(
        client.get(f"/v2/appAvailabilities/{availability_id}"),
        "app availability detail",
    )
    if (
        detail is None
        or detail.get("type") != "appAvailabilities"
        or detail.get("id") != availability_id
    ):
        raise AvailabilityError("app availability detail identity is substituted")
    detail_attributes = _attributes(detail, "app availability detail")
    available_in_new = detail_attributes.get("availableInNewTerritories")
    if not isinstance(available_in_new, bool):
        raise AvailabilityError("new-territory availability state is malformed")
    payload = client.get(
        f"/v2/appAvailabilities/{availability_id}/territoryAvailabilities",
        {"limit": "200", "include": "territory"},
    )
    entries = _collection(payload, "territory availabilities")
    links = payload.get("links")
    if isinstance(links, dict) and links.get("next"):
        raise AvailabilityError(
            "territory availability response unexpectedly requires paging"
        )
    records: list[dict[str, Any]] = []
    seen_entry_ids: set[str] = set()
    seen_territory_ids: set[str] = set()
    for entry in entries:
        if entry.get("type") != "territoryAvailabilities":
            raise AvailabilityError("territory availability resource type is invalid")
        entry_id = _require_resource_id(entry.get("id"), "territory availability")
        if entry_id in seen_entry_ids:
            raise AvailabilityError("territory availability resource is duplicated")
        seen_entry_ids.add(entry_id)
        territory = _relationship_data(
            entry, "territory", "territory availability"
        )
        if territory.get("type") != "territories":
            raise AvailabilityError("territory availability relationship type is invalid")
        territory_id = _require_resource_id(
            territory.get("id"), "territory availability relationship"
        )
        if territory_id in seen_territory_ids:
            raise AvailabilityError("territory availability relationship is duplicated")
        seen_territory_ids.add(territory_id)
        attributes = _attributes(entry, "territory availability")
        available = attributes.get("available")
        preorder = attributes.get("preOrderEnabled")
        if not isinstance(available, bool) or not isinstance(preorder, bool):
            raise AvailabilityError("territory availability attributes are malformed")
        records.append(
            {
                "id": entry_id,
                "territory_id": territory_id,
                "available": available,
                "pre_order_enabled": preorder,
                "release_date": attributes.get("releaseDate"),
                "pre_order_publish_date": attributes.get("preOrderPublishDate"),
                "content_statuses": attributes.get("contentStatuses"),
            }
        )
    configured_ids = {record["territory_id"] for record in records}
    missing = sorted(active_territory_ids - configured_ids)
    unexpected = sorted(configured_ids - active_territory_ids)
    return {
        "configured": True,
        "app_availability_id": availability_id,
        "available_in_new_territories": available_in_new,
        "territory_availabilities": sorted(
            records, key=lambda record: (record["territory_id"], record["id"])
        ),
        "missing_territories": missing,
        "unexpected_territories": unexpected,
    }


def is_exact_target_availability(
    state: dict[str, Any],
    active_territory_ids: set[str],
) -> bool:
    records = state.get("territory_availabilities")
    if not isinstance(records, list):
        return False
    record_ids = {
        record.get("territory_id")
        for record in records
        if isinstance(record, dict)
    }
    return (
        state.get("configured") is True
        and isinstance(state.get("app_availability_id"), str)
        and state.get("available_in_new_territories") is True
        and len(records) == EXPECTED_STOREFRONT_COUNT
        and record_ids == active_territory_ids
        and state.get("missing_territories") == []
        and state.get("unexpected_territories") == []
        and all(
            isinstance(record, dict)
            and record.get("available") is True
            and record.get("pre_order_enabled") is False
            for record in records
        )
    )


def preflight_digests(
    candidates: dict[str, Candidate],
    build_state: dict[str, Any],
    territory_ids: list[str],
    price_state: dict[str, Any],
    availability_state: dict[str, Any],
) -> tuple[str, str]:
    target_payload = availability_payload(set(territory_ids))
    identity_payload = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "contract": "winsvpn-apple-storefront-availability-v1",
        "app_id": APP_ID,
        "bundle_id": BUNDLE_ID,
        "app_version": APP_VERSION,
        "build_number": BUILD_NUMBER,
        "scope": EXPECTED_SCOPE_CONFIRMATION,
        "release_candidate_manifest_sha256": _file_sha256(
            build_attach.RELEASE_CANDIDATE_PATH, "release candidate manifest"
        ),
        "runtime_evidence_sha256": _file_sha256(
            build_attach.RUNTIME_EVIDENCE_PATH, "runtime evidence manifest"
        ),
        "owner_signoff_sha256": _file_sha256(
            build_attach.OWNER_SIGNOFF_PATH, "owner signoff manifest"
        ),
        "rollout_readiness_sha256": _file_sha256(
            ROLLOUT_PATH, "rollout readiness"
        ),
        "frozen_candidates": build_attach._require_exact_candidates(candidates),
        "authenticated_build_attachment_state": build_state,
        "active_territory_ids": territory_ids,
        "price_state": price_state,
        "intended_payload_sha256": payload_sha256(target_payload),
    }
    identity_digest = _canonical_sha256(
        identity_payload, "Apple availability immutable preflight"
    )
    authorization_payload = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "contract": "winsvpn-apple-storefront-availability-authorization-v1",
        "identity_preflight_sha256": identity_digest,
        "current_availability_state": availability_state,
    }
    return identity_digest, _canonical_sha256(
        authorization_payload, "Apple availability authorization preflight"
    )


def capture_preflight(
    client: AppStoreConnectClient,
    candidates: dict[str, Candidate],
) -> dict[str, Any]:
    require_owner_approval()
    require_dsa_verified()
    build_state = build_attach.capture_preflight(client, candidates)
    if build_state.get("mode") != "already_attached":
        raise AvailabilityError(
            "exact iOS and macOS builds must already be attached before availability"
        )
    territory_ids = active_territory_state(client)
    territory_set = set(territory_ids)
    price_state = exact_free_price_state(client, territory_set)
    availability_state = availability_relationship_state(client, territory_set)
    if availability_state.get("configured") is False:
        mode = "unconfigured"
    elif is_exact_target_availability(availability_state, territory_set):
        mode = "already_exact"
    else:
        raise AvailabilityError(
            "existing partial or incompatible availability requires owner reconciliation"
        )
    identity_digest, digest = preflight_digests(
        candidates,
        build_state,
        territory_ids,
        price_state,
        availability_state,
    )
    return {
        "build_state": build_state,
        "territory_ids": territory_ids,
        "price_state": price_state,
        "availability_state": availability_state,
        "mode": mode,
        "identity_digest": identity_digest,
        "digest": digest,
    }


def owner_authorization_for_digest(digest: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise AvailabilityError("availability preflight digest is invalid")
    return OWNER_AUTHORIZATION_PREFIX + digest


def _require_unchanged_preflight(
    current: dict[str, Any], expected: dict[str, Any]
) -> None:
    if current.get("digest") != expected.get("digest"):
        raise AvailabilityError(
            "authenticated storefront state changed after owner confirmation"
        )


def _validate_creation_response(payload: dict[str, Any]) -> str:
    resource = _resource_or_none(payload, "created app availability")
    if resource is None or resource.get("type") != "appAvailabilities":
        raise AvailabilityError("availability creation response identity is malformed")
    return _require_resource_id(resource.get("id"), "created app availability")


def _failure_after_creation(
    client: AppStoreConnectClient,
    candidates: dict[str, Candidate],
    cause: Exception,
) -> AvailabilityError:
    try:
        build_attach.refresh_frozen_candidates(candidates)
        current = capture_preflight(client, candidates)
    except Exception:
        return AvailabilityError(
            "availability creation failed and current state cannot be reconciled "
            "safely; no cleanup was attempted"
        )
    if current.get("mode") == "already_exact":
        return AvailabilityError(
            "availability creation reported failure after state may have persisted; "
            "owner reconciliation and a fresh preflight are required; "
            f"cause: {cause}"
        )
    return AvailabilityError(f"availability creation failed without persistence: {cause}")


def execute_availability(
    client: AppStoreConnectClient,
    candidates: dict[str, Candidate],
    preflight: dict[str, Any],
    *,
    expected_digest: str,
    owner_authorization: str,
) -> str:
    require_confirmation("preflight SHA-256", expected_digest, preflight["digest"])
    require_confirmation(
        "owner authorization",
        owner_authorization,
        owner_authorization_for_digest(preflight["digest"]),
    )
    build_attach.refresh_frozen_candidates(candidates)
    before = capture_preflight(client, candidates)
    _require_unchanged_preflight(before, preflight)
    if before.get("mode") == "already_exact":
        return "already_exact"
    if before.get("mode") != "unconfigured":
        raise AvailabilityError("availability state is not safe to create")
    territory_ids = set(before["territory_ids"])
    payload = availability_payload(territory_ids)
    try:
        response = client.create_app_availability(payload, territory_ids)
        response_id = _validate_creation_response(response)
        build_attach.refresh_frozen_candidates(candidates)
        after = capture_preflight(client, candidates)
        if after.get("identity_digest") != preflight.get("identity_digest"):
            raise AvailabilityError(
                "authenticated storefront identity changed during availability creation"
            )
        if after.get("mode") != "already_exact":
            raise AvailabilityError("all-storefront availability did not persist exactly")
        persisted_id = after["availability_state"].get("app_availability_id")
        if persisted_id != response_id:
            raise AvailabilityError("availability creation response was substituted")
    except (AvailabilityError, ReleaseStatusError, UploadGateError, OSError) as exc:
        raise _failure_after_creation(client, candidates, exc) from exc
    return "created"


def run_selftest() -> None:
    territory_ids = {f"T{index:03d}" for index in range(EXPECTED_STOREFRONT_COUNT)}
    payload = availability_payload(territory_ids)
    data = payload["data"]
    included = payload["included"]
    if data["attributes"] != {"availableInNewTerritories": True}:
        raise AvailabilityError("self-test lost new-territory availability")
    if len(included) != EXPECTED_STOREFRONT_COUNT:
        raise AvailabilityError("self-test lost an included territory")
    if any(
        item.get("attributes") != {"available": True, "preOrderEnabled": False}
        for item in included
    ):
        raise AvailabilityError("self-test created preorder or unavailable data")
    linked_ids = {
        item["relationships"]["territory"]["data"]["id"] for item in included
    }
    if linked_ids != territory_ids:
        raise AvailabilityError("self-test territory relationships do not match")
    if payload_sha256(payload) != payload_sha256(availability_payload(territory_ids)):
        raise AvailabilityError("self-test payload is not deterministic")
    print("PASS: all-storefront availability payload self-test")
    print("SUMMARY: 1/1 checks passing")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--preflight", action="store_true")
    actions.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-apple-id")
    parser.add_argument("--confirm-version")
    parser.add_argument("--confirm-build")
    parser.add_argument("--confirm-ios-sha256")
    parser.add_argument("--confirm-macos-sha256")
    parser.add_argument("--confirm-storefront-count", type=int)
    parser.add_argument("--confirm-scope")
    parser.add_argument("--confirm-preflight-sha256")
    parser.add_argument("--confirm-owner-authorization")
    parser.add_argument("--selftest", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.selftest:
            if args.preflight or args.apply:
                raise AvailabilityError(
                    "--selftest cannot be combined with release actions"
                )
            run_selftest()
            return 0
        if not args.preflight and not args.apply:
            print(
                "DRY RUN: use --preflight with exact confirmations to query live "
                "storefront state without changing it"
            )
            return 0
        require_confirmations(args)
        candidates = candidate_map(
            allowed_upload_statuses=frozenset(
                {"not_uploaded", "uploaded_processed_and_attached"}
            )
        )
        require_confirmation(
            "iOS SHA-256", args.confirm_ios_sha256, candidates["ios"].sha256
        )
        require_confirmation(
            "macOS SHA-256", args.confirm_macos_sha256, candidates["macos"].sha256
        )
        require_owner_approval()
        require_dsa_verified()
        auth_probe.probe()
        client = _load_client()
        preflight = capture_preflight(client, candidates)
        target_payload = availability_payload(set(preflight["territory_ids"]))
        digest = str(preflight["digest"])
        authorization = owner_authorization_for_digest(digest)
        print(
            "PASS: exact app, frozen builds, price schedule, and storefront "
            f"scope verified count={EXPECTED_STOREFRONT_COUNT} "
            f"payload_sha256={payload_sha256(target_payload)}"
        )
        print(f"APPLE_AVAILABILITY_PREFLIGHT_SHA256={digest}")
        print(f"APPLE_AVAILABILITY_OWNER_AUTHORIZATION={authorization}")
        if not args.apply:
            print("PREFLIGHT ONLY: App Store availability was not changed")
            return 0
        outcome = execute_availability(
            client,
            candidates,
            preflight,
            expected_digest=str(args.confirm_preflight_sha256 or ""),
            owner_authorization=str(args.confirm_owner_authorization or ""),
        )
        if outcome == "already_exact":
            print("PASS: exact all-storefront availability is already configured")
        else:
            print("PASS: all 175 active storefronts are configured and verified")
        return 0
    except (
        AvailabilityError,
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
