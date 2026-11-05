#!/usr/bin/env python3
"""Attach the exact owner-authorized iOS and macOS builds to their versions."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import apple_app_store_connect_auth_probe as auth_probe
from apple_app_store_connect_release_status import (
    APP_ID,
    APP_VERSION,
    BUILD_NUMBER,
    BUNDLE_ID,
    AppStoreConnectClient,
    ReleaseStatusError,
    _attributes,
    _build_status,
    _collection,
    _editable_versions,
    _load_client,
    _resource_or_none,
    _review_submission_status,
)
from apple_upload_exact_release_candidates import (
    Candidate,
    UploadGateError,
    candidate_map,
    require_clean_macos_install,
)
from validate_apple_owner_signoff import validate_owner_signoff


ROOT = Path(__file__).resolve().parents[1]
RELEASE_CANDIDATE_PATH = ROOT / "app_store/apple/artifacts/release_candidate.json"
RUNTIME_EVIDENCE_PATH = ROOT / "app_store/apple/artifacts/runtime_evidence.json"
OWNER_SIGNOFF_PATH = ROOT / "app_store/apple/review/owner_signoff.json"
ROLLOUT_PATH = ROOT / "app_store/apple/review/rollout_readiness.json"
PLATFORMS = ("ios", "macos")
API_PLATFORM = {"ios": "IOS", "macos": "MAC_OS"}
API_PLATFORM_TO_LOCAL = {value: key for key, value in API_PLATFORM.items()}
RESOURCE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
PREFLIGHT_SCHEMA_VERSION = 1
OWNER_AUTHORIZATION_PREFIX = "AUTHORIZE_APPLE_BUILD_ATTACHMENT_SHA256_"
TERMINAL_REVIEW_STATES = {"COMPLETE"}


class BuildAttachError(RuntimeError):
    pass


def selected_platforms(value: str) -> list[str]:
    return list(PLATFORMS) if value == "both" else [value]


def require_confirmation(label: str, supplied: str | None, expected: str) -> None:
    if supplied != expected:
        raise BuildAttachError(f"{label} confirmation does not match the release")


def _require_resource_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or RESOURCE_ID_RE.fullmatch(value) is None:
        raise BuildAttachError(f"{label} resource ID is invalid")
    return value


def _file_sha256(path: Path, label: str) -> str:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise BuildAttachError(f"could not read {label}") from exc
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha256(payload: dict[str, Any], label: str) -> str:
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BuildAttachError(f"{label} is not canonical") from exc
    return hashlib.sha256(encoded).hexdigest()


def require_owner_and_install_gates(candidates: dict[str, Candidate]) -> None:
    try:
        validate_owner_signoff(require_approved=True)
    except AssertionError as exc:
        raise BuildAttachError(str(exc)) from exc
    try:
        require_clean_macos_install(candidates)
    except UploadGateError as exc:
        raise BuildAttachError(str(exc)) from exc


def _require_exact_candidates(
    candidates: dict[str, Candidate],
) -> dict[str, dict[str, Any]]:
    if set(candidates) != set(PLATFORMS):
        raise BuildAttachError("frozen Apple candidate set is incomplete")
    records: dict[str, dict[str, Any]] = {}
    for platform in PLATFORMS:
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
            or SHA256_RE.fullmatch(candidate.sha256) is None
        ):
            raise BuildAttachError(f"frozen {platform} candidate identity is invalid")
        records[platform] = {
            "artifact_type": candidate.artifact_type,
            "relative_path": candidate.relative_path,
            "sha256": candidate.sha256,
            "size_bytes": candidate.size_bytes,
        }
    return records


def _require_related_app(
    client: AppStoreConnectClient,
    resource_type: str,
    resource_id: str,
    label: str,
) -> None:
    app = _resource_or_none(
        client.get(f"/v1/{resource_type}/{resource_id}/app"),
        f"{label} app",
    )
    if app is None or app.get("type") != "apps" or app.get("id") != APP_ID:
        raise BuildAttachError(f"{label} is not related to the exact app")


def editable_version_records(
    client: AppStoreConnectClient,
) -> dict[str, dict[str, Any]]:
    versions = _editable_versions(client)
    if set(versions) != set(PLATFORMS):
        raise BuildAttachError("exact iOS and macOS App Store versions are required")
    records: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()
    for platform in PLATFORMS:
        resource = versions[platform]
        if not isinstance(resource, dict) or resource.get("type") != "appStoreVersions":
            raise BuildAttachError(f"{platform} App Store version is malformed")
        version_id = _require_resource_id(
            resource.get("id"), f"{platform} App Store version"
        )
        if version_id in seen_ids:
            raise BuildAttachError("iOS and macOS App Store versions share an ID")
        seen_ids.add(version_id)
        attributes = _attributes(resource, f"{platform} App Store version")
        if (
            attributes.get("platform") != API_PLATFORM[platform]
            or attributes.get("versionString") != APP_VERSION
            or attributes.get("appStoreState") != "PREPARE_FOR_SUBMISSION"
        ):
            raise BuildAttachError(
                f"{platform} App Store version identity or state changed"
            )
        _require_related_app(client, "appStoreVersions", version_id, platform)
        records[platform] = {
            "id": version_id,
            "platform": API_PLATFORM[platform],
            "version": APP_VERSION,
            "state": "PREPARE_FOR_SUBMISSION",
        }
    return records


def _require_uploaded_date(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise BuildAttachError(f"{label} uploaded date is missing")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise BuildAttachError(f"{label} uploaded date is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BuildAttachError(f"{label} uploaded date has no timezone")
    return value


def processed_builds(
    client: AppStoreConnectClient,
    platforms: list[str] | tuple[str, ...] = PLATFORMS,
) -> dict[str, dict[str, Any]]:
    if tuple(platforms) != PLATFORMS:
        raise BuildAttachError("build attachment requires iOS and macOS together")
    raw_builds = _build_status(client)
    if not isinstance(raw_builds, list) or len(raw_builds) != len(PLATFORMS):
        count = len(raw_builds) if isinstance(raw_builds, list) else "invalid"
        raise BuildAttachError(
            f"expected exactly two current processed builds, found {count}"
        )
    selected: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()
    for build in raw_builds:
        if not isinstance(build, dict):
            raise BuildAttachError("processed build record is malformed")
        platform = API_PLATFORM_TO_LOCAL.get(build.get("platform"))
        if platform is None or platform in selected:
            raise BuildAttachError("processed build platforms are ambiguous")
        build_id = _require_resource_id(build.get("id"), f"{platform} build")
        if build_id in seen_ids:
            raise BuildAttachError("processed build resource is duplicated")
        seen_ids.add(build_id)
        if build.get("version") != BUILD_NUMBER:
            raise BuildAttachError(f"{platform} build number is not {BUILD_NUMBER}")
        if build.get("processing_state") != "VALID":
            raise BuildAttachError(
                f"{platform} build {BUILD_NUMBER} is not valid and processed"
            )
        if build.get("expired") is not False:
            raise BuildAttachError(f"{platform} build {BUILD_NUMBER} is expired or ambiguous")
        if build.get("uses_non_exempt_encryption") is not True:
            raise BuildAttachError(
                f"{platform} build encryption classification is not exact"
            )
        uploaded_date = _require_uploaded_date(
            build.get("uploaded_date"), f"{platform} build"
        )
        _require_related_app(client, "builds", build_id, f"{platform} build")
        selected[platform] = {
            "id": build_id,
            "platform": API_PLATFORM[platform],
            "version": BUILD_NUMBER,
            "processing_state": "VALID",
            "expired": False,
            "uses_non_exempt_encryption": True,
            "uploaded_date": uploaded_date,
        }
    if set(selected) != set(PLATFORMS):
        raise BuildAttachError("exact iOS and macOS processed builds are required")
    return selected


def accepted_encryption_declaration_ids(
    client: AppStoreConnectClient,
) -> set[str]:
    resources = _collection(
        client.get(
            "/v1/appEncryptionDeclarations",
            {"filter[app]": APP_ID, "limit": "50"},
        ),
        "app encryption declarations",
    )
    accepted: set[str] = set()
    seen: set[str] = set()
    for resource in resources:
        declaration_id = _require_resource_id(
            resource.get("id"), "app encryption declaration"
        )
        if declaration_id in seen:
            raise BuildAttachError("app encryption declaration is duplicated")
        seen.add(declaration_id)
        state = _attributes(
            resource, "app encryption declaration"
        ).get("appEncryptionDeclarationState")
        if not isinstance(state, str) or not state:
            raise BuildAttachError("app encryption declaration state is malformed")
        if state == "APPROVED":
            accepted.add(declaration_id)
    if not accepted:
        raise BuildAttachError("Apple has no accepted encryption declaration")
    return accepted


def build_encryption_links(
    client: AppStoreConnectClient,
    builds: dict[str, dict[str, Any]],
) -> dict[str, str]:
    accepted = accepted_encryption_declaration_ids(client)
    links: dict[str, str] = {}
    for platform in PLATFORMS:
        build_id = _require_resource_id(
            builds[platform].get("id"), f"{platform} encryption-bound build"
        )
        declaration = _resource_or_none(
            client.get(
                f"/v1/builds/{build_id}/appEncryptionDeclaration",
                allow_missing_relationship=True,
            ),
            f"{platform} build encryption declaration",
        )
        if declaration is None or declaration.get("type") != "appEncryptionDeclarations":
            raise BuildAttachError(
                f"{platform} build is not linked to an accepted encryption declaration"
            )
        declaration_id = _require_resource_id(
            declaration.get("id"), f"{platform} encryption declaration"
        )
        if declaration_id not in accepted:
            raise BuildAttachError(
                f"{platform} build is not linked to an accepted encryption declaration"
            )
        links[platform] = declaration_id
    return links


def current_build_id(
    client: AppStoreConnectClient,
    version_id: str,
) -> str | None:
    version_id = _require_resource_id(version_id, "App Store version")
    resource = _resource_or_none(
        client.get(
            f"/v1/appStoreVersions/{version_id}/build",
            allow_missing_relationship=True,
        ),
        "selected App Store build",
    )
    if resource is None:
        return None
    if resource.get("type") != "builds":
        raise BuildAttachError("selected App Store build relationship is malformed")
    return _require_resource_id(resource.get("id"), "selected App Store build")


def relationship_state(
    client: AppStoreConnectClient,
    versions: dict[str, dict[str, Any]],
) -> dict[str, str | None]:
    return {
        platform: current_build_id(client, str(versions[platform]["id"]))
        for platform in PLATFORMS
    }


def require_no_active_review_submission(client: AppStoreConnectClient) -> dict[str, Any]:
    status = _review_submission_status(client)
    records = status.get("records") if isinstance(status, dict) else None
    if (
        not isinstance(records, list)
        or type(status.get("count")) is not int
        or status["count"] != len(records)
    ):
        raise BuildAttachError("review submission status is malformed")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise BuildAttachError("review submission record is malformed")
        record_id = _require_resource_id(record.get("id"), "review submission")
        if record_id in seen:
            raise BuildAttachError("review submission record is duplicated")
        seen.add(record_id)
        state = record.get("state")
        if not isinstance(state, str) or not state:
            raise BuildAttachError("review submission state is malformed")
        if state not in TERMINAL_REVIEW_STATES:
            raise BuildAttachError(
                "an active or unresolved App Review submission blocks build attachment"
            )
    return status


def _initial_relationship_mode(
    relationships: dict[str, str | None],
    builds: dict[str, dict[str, Any]],
) -> str:
    expected = {platform: str(builds[platform]["id"]) for platform in PLATFORMS}
    for platform in PLATFORMS:
        current = relationships.get(platform)
        if current is not None and current != expected[platform]:
            raise BuildAttachError(
                f"{platform} App Store version already selects a different build"
            )
    attached = [relationships.get(platform) == expected[platform] for platform in PLATFORMS]
    if all(attached):
        return "already_attached"
    if any(attached):
        raise BuildAttachError(
            "only one platform is attached; partial state requires owner reconciliation"
        )
    return "unattached"


def preflight_digests(
    candidates: dict[str, Candidate],
    versions: dict[str, dict[str, Any]],
    builds: dict[str, dict[str, Any]],
    encryption_links: dict[str, str],
    review_status: dict[str, Any],
    relationships: dict[str, str | None],
) -> tuple[str, str]:
    immutable_payload = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "contract": "winsvpn-apple-build-attachment-v1",
        "app_id": APP_ID,
        "bundle_id": BUNDLE_ID,
        "app_version": APP_VERSION,
        "build_number": BUILD_NUMBER,
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
        "candidates": _require_exact_candidates(candidates),
        "versions": versions,
        "builds": builds,
        "encryption_declaration_ids": encryption_links,
        "review_submissions": review_status,
    }
    immutable_digest = _canonical_sha256(
        immutable_payload, "Apple build attachment immutable preflight"
    )
    authorization_payload = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "contract": "winsvpn-apple-build-attachment-authorization-v1",
        "immutable_preflight_sha256": immutable_digest,
        "initial_relationships": relationships,
        "intended_relationships": {
            platform: builds[platform]["id"] for platform in PLATFORMS
        },
    }
    return immutable_digest, _canonical_sha256(
        authorization_payload, "Apple build attachment authorization preflight"
    )


def owner_authorization_for_digest(digest: str) -> str:
    if SHA256_RE.fullmatch(digest) is None:
        raise BuildAttachError("build attachment preflight digest is invalid")
    return OWNER_AUTHORIZATION_PREFIX + digest


def capture_preflight(
    client: AppStoreConnectClient,
    candidates: dict[str, Candidate],
    *,
    allow_authorized_partial: bool = False,
) -> dict[str, Any]:
    _require_exact_candidates(candidates)
    versions = editable_version_records(client)
    builds = processed_builds(client)
    encryption_links = build_encryption_links(client, builds)
    review_status = require_no_active_review_submission(client)
    relationships = relationship_state(client, versions)
    if allow_authorized_partial:
        expected_ids = {
            platform: str(builds[platform]["id"]) for platform in PLATFORMS
        }
        if any(
            relationships[platform] not in {None, expected_ids[platform]}
            for platform in PLATFORMS
        ):
            raise BuildAttachError(
                "an App Store version selects a build outside the authorized sequence"
            )
        mode = "authorized_progress"
    else:
        mode = _initial_relationship_mode(relationships, builds)
    immutable_digest, digest = preflight_digests(
        candidates,
        versions,
        builds,
        encryption_links,
        review_status,
        relationships,
    )
    return {
        "versions": versions,
        "builds": builds,
        "encryption_links": encryption_links,
        "review_status": review_status,
        "relationships": relationships,
        "mode": mode,
        "immutable_digest": immutable_digest,
        "digest": digest,
    }


def refresh_frozen_candidates(
    expected: dict[str, Candidate],
) -> dict[str, Candidate]:
    current = candidate_map(
        allowed_upload_statuses=frozenset(
            {"not_uploaded", "uploaded_processed_and_attached"}
        )
    )
    if current != expected:
        raise BuildAttachError(
            "frozen Apple candidate identity changed after owner confirmation"
        )
    return current


def _require_progress_snapshot(
    current: dict[str, Any],
    *,
    immutable_digest: str,
    expected_relationships: dict[str, str | None],
) -> None:
    if current.get("immutable_digest") != immutable_digest:
        raise BuildAttachError(
            "authenticated Apple build state changed after owner confirmation"
        )
    if current.get("relationships") != expected_relationships:
        raise BuildAttachError(
            "App Store build relationships changed outside the authorized sequence"
        )


def _failure_after_mutation(
    client: AppStoreConnectClient,
    candidates: dict[str, Candidate],
    initial_relationships: dict[str, str | None],
    cause: Exception,
) -> BuildAttachError:
    try:
        current_candidates = refresh_frozen_candidates(candidates)
        current = capture_preflight(
            client, current_candidates, allow_authorized_partial=True
        )
        relationships = current["relationships"]
    except Exception:
        return BuildAttachError(
            "build attachment failed and current relationship state cannot be "
            "reconciled safely; no cleanup was attempted"
        )
    if relationships != initial_relationships:
        return BuildAttachError(
            "build attachment stopped in partial state; no cleanup was attempted; "
            "owner reconciliation and a fresh preflight are required"
        )
    return BuildAttachError(f"build attachment failed before any persistent change: {cause}")


def execute_attachment(
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
    initial_relationships = dict(preflight["relationships"])
    if preflight["mode"] == "already_attached":
        refresh_frozen_candidates(candidates)
        current = capture_preflight(client, candidates)
        if current["digest"] != preflight["digest"]:
            raise BuildAttachError(
                "authenticated Apple build state changed after owner confirmation"
            )
        return "already_attached"

    expected_relationships = dict(initial_relationships)
    immutable_digest = str(preflight["immutable_digest"])
    for platform in PLATFORMS:
        try:
            refresh_frozen_candidates(candidates)
            before = capture_preflight(
                client, candidates, allow_authorized_partial=True
            )
            _require_progress_snapshot(
                before,
                immutable_digest=immutable_digest,
                expected_relationships=expected_relationships,
            )
            version_id = str(preflight["versions"][platform]["id"])
            build_id = str(preflight["builds"][platform]["id"])
            client.patch_relationship(
                "appStoreVersions",
                version_id,
                "build",
                "builds",
                build_id,
            )
            expected_relationships[platform] = build_id
            refresh_frozen_candidates(candidates)
            after = capture_preflight(
                client, candidates, allow_authorized_partial=True
            )
            _require_progress_snapshot(
                after,
                immutable_digest=immutable_digest,
                expected_relationships=expected_relationships,
            )
        except (BuildAttachError, ReleaseStatusError, UploadGateError, OSError) as exc:
            raise _failure_after_mutation(
                client, candidates, initial_relationships, exc
            ) from exc
        print(
            f"PASS: attached {platform} build {BUILD_NUMBER} to App Store "
            f"version {APP_VERSION}"
        )
    return "attached"


def run_selftest() -> None:
    valid = [
        {
            "id": "ios-build",
            "platform": "IOS",
            "version": BUILD_NUMBER,
            "processing_state": "VALID",
            "uploaded_date": "2026-08-25T00:00:00Z",
            "expired": False,
            "uses_non_exempt_encryption": True,
        },
        {
            "id": "mac-build",
            "platform": "MAC_OS",
            "version": BUILD_NUMBER,
            "processing_state": "VALID",
            "uploaded_date": "2026-08-25T00:01:00+00:00",
            "expired": False,
            "uses_non_exempt_encryption": True,
        },
    ]

    class FakeClient:
        def get(self, path: str, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            if path.endswith("/app"):
                return {"data": {"type": "apps", "id": APP_ID}}
            raise BuildAttachError("self-test requested an unexpected endpoint")

    original = globals()["_build_status"]
    try:
        globals()["_build_status"] = lambda _client: valid
        selected = processed_builds(FakeClient())
        if set(selected) != set(PLATFORMS):
            raise BuildAttachError("self-test did not select both processed builds")
        globals()["_build_status"] = lambda _client: [
            valid[0],
            dict(valid[0], id="duplicate-ios"),
        ]
        try:
            processed_builds(FakeClient())
        except BuildAttachError as exc:
            if "ambiguous" not in str(exc):
                raise
        else:
            raise BuildAttachError("self-test accepted ambiguous processed builds")
        if owner_authorization_for_digest("a" * 64) != (
            OWNER_AUTHORIZATION_PREFIX + "a" * 64
        ):
            raise BuildAttachError("self-test produced the wrong authorization token")
    finally:
        globals()["_build_status"] = original
    print("PASS: processed Apple build attachment self-test")
    print("SUMMARY: 1/1 checks passing")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("both", "ios", "macos"), default="both")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--preflight", action="store_true")
    actions.add_argument("--attach", action="store_true")
    parser.add_argument("--confirm-apple-id")
    parser.add_argument("--confirm-version")
    parser.add_argument("--confirm-build")
    parser.add_argument("--confirm-ios-sha256")
    parser.add_argument("--confirm-macos-sha256")
    parser.add_argument("--confirm-preflight-sha256")
    parser.add_argument("--confirm-owner-authorization")
    parser.add_argument("--selftest", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.selftest:
            if args.preflight or args.attach:
                raise BuildAttachError("--selftest cannot be combined with release actions")
            run_selftest()
            return 0
        candidates = candidate_map(
            allowed_upload_statuses=frozenset(
                {"not_uploaded", "uploaded_processed_and_attached"}
            )
        )
        for platform in PLATFORMS:
            print(
                f"PASS: frozen {platform} artifact verified "
                f"sha256={candidates[platform].sha256}"
            )
        if not args.preflight and not args.attach:
            print("DRY RUN: no App Store build relationship was queried or changed")
            return 0
        if args.platform != "both":
            raise BuildAttachError(
                "processed build preflight and attachment require iOS and macOS together"
            )
        require_confirmation("Apple ID", args.confirm_apple_id, APP_ID)
        require_confirmation("version", args.confirm_version, APP_VERSION)
        require_confirmation("build", args.confirm_build, BUILD_NUMBER)
        require_confirmation(
            "iOS SHA-256", args.confirm_ios_sha256, candidates["ios"].sha256
        )
        require_confirmation(
            "macOS SHA-256", args.confirm_macos_sha256, candidates["macos"].sha256
        )
        require_owner_and_install_gates(candidates)
        auth_probe.probe()
        client = _load_client()
        preflight = capture_preflight(client, candidates)
        digest = str(preflight["digest"])
        authorization = owner_authorization_for_digest(digest)
        print(
            "PASS: exact app, candidates, versions, processed builds, encryption, "
            "review-state, and relationship gates passed"
        )
        print(f"APPLE_BUILD_ATTACHMENT_PREFLIGHT_SHA256={digest}")
        print(f"APPLE_BUILD_ATTACHMENT_OWNER_AUTHORIZATION={authorization}")
        if not args.attach:
            print("PREFLIGHT ONLY: no App Store build relationship was changed")
            return 0
        outcome = execute_attachment(
            client,
            candidates,
            preflight,
            expected_digest=str(args.confirm_preflight_sha256 or ""),
            owner_authorization=str(args.confirm_owner_authorization or ""),
        )
        if outcome == "already_attached":
            print(
                f"PASS: exact iOS and macOS build {BUILD_NUMBER} relationships "
                f"are already attached to version {APP_VERSION}"
            )
        return 0
    except (
        BuildAttachError,
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
