#!/usr/bin/env python3
"""Hostile local tests for the exact App Review submission boundary."""

from __future__ import annotations

import copy
import pathlib
import sys
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_submit_for_app_review as submit


VERSION_IDS = {"ios": "version-ios", "macos": "version-macos"}
BUILD_IDS = {"ios": "build-ios", "macos": "build-macos"}


def candidates() -> dict[str, submit.Candidate]:
    return {
        "ios": submit.Candidate(
            platform="ios",
            artifact_type="ipa",
            path=pathlib.Path("/held/ios.ipa"),
            relative_path="app_store/apple/artifacts/ios.ipa",
            size_bytes=101,
            sha256="a" * 64,
            app_version=submit.APP_VERSION,
            build_number=submit.BUILD_NUMBER,
        ),
        "macos": submit.Candidate(
            platform="macos",
            artifact_type="pkg",
            path=pathlib.Path("/held/macos.pkg"),
            relative_path="app_store/apple/artifacts/macos.pkg",
            size_bytes=202,
            sha256="b" * 64,
            app_version=submit.APP_VERSION,
            build_number=submit.BUILD_NUMBER,
        ),
    }


def exact_record(
    *,
    submission_id: str = "submission-one",
    state: str = "READY_FOR_REVIEW",
    item_state: str = "READY_FOR_REVIEW",
) -> dict[str, object]:
    return {
        "id": submission_id,
        "platform": "MULTI_PLATFORM",
        "platforms": ["IOS", "MAC_OS"],
        "state": state,
        "item_count": 2,
        "non_app_store_version_item_count": 0,
        "items": [
            {
                "id": "item-ios",
                "state": item_state,
                "app_store_version_id": VERSION_IDS["ios"],
                "platform": "IOS",
                "version": submit.APP_VERSION,
            },
            {
                "id": "item-macos",
                "state": item_state,
                "app_store_version_id": VERSION_IDS["macos"],
                "platform": "MAC_OS",
                "version": submit.APP_VERSION,
            },
        ],
    }


def review_status(record: dict[str, object] | None = None) -> dict[str, object]:
    records = [] if record is None else [record]
    submitted_states = {
        "WAITING_FOR_REVIEW",
        "IN_REVIEW",
        "UNRESOLVED_ISSUES",
        "COMPLETING",
        "COMPLETE",
    }
    submitted_platforms = sorted(
        {
            platform
            for current in records
            if current.get("state") in submitted_states
            for platform in current.get("platforms", [])
        }
    )
    return {
        "count": len(records),
        "records": records,
        "submitted_platforms": submitted_platforms,
        "both_platforms_submitted": set(submitted_platforms) == {"IOS", "MAC_OS"},
    }


def live_result(
    *,
    record: dict[str, object] | None = None,
    version_state: str | None = None,
) -> dict[str, object]:
    if version_state is None:
        version_state = (
            "PREPARE_FOR_SUBMISSION" if record is None else "READY_FOR_REVIEW"
        )
    platform_template = {
        "state": version_state,
        "release_type": "MANUAL",
        "metadata_matches": True,
        "screenshot_count": 1,
        "review_detail_present": True,
        "review_contact_complete": True,
        "review_notes_present": True,
        "demo_account_required": False,
    }
    return {
        "schema_version": 1,
        "app_id": submit.APP_ID,
        "app_version": submit.APP_VERSION,
        "build_number": submit.BUILD_NUMBER,
        "bundle_id": "org.winsvpn.app",
        "platforms": {
            "ios": {
                **platform_template,
                "version_id": VERSION_IDS["ios"],
                "screenshot_display_types": ["APP_IPHONE_67"],
                "selected_build_id": BUILD_IDS["ios"],
            },
            "macos": {
                **platform_template,
                "version_id": VERSION_IDS["macos"],
                "screenshot_display_types": ["APP_DESKTOP"],
                "selected_build_id": BUILD_IDS["macos"],
            },
        },
        "builds": [
            {
                "id": BUILD_IDS["ios"],
                "platform": "IOS",
                "version": submit.BUILD_NUMBER,
                "processing_state": "VALID",
                "uploaded_date": "2026-08-25T00:00:00Z",
                "expired": False,
            },
            {
                "id": BUILD_IDS["macos"],
                "platform": "MAC_OS",
                "version": submit.BUILD_NUMBER,
                "processing_state": "VALID",
                "uploaded_date": "2026-08-25T00:00:00Z",
                "expired": False,
            },
        ],
        "processed_platforms": ["ios", "macos"],
        "both_platform_builds_processed": True,
        "app_info": {"privacy_policy_url_matches": True},
        "price_schedule": {
            "configured": True,
            "all_free": True,
            "territory_count": submit.EXPECTED_STOREFRONT_COUNT,
            "active_territory_count": submit.EXPECTED_STOREFRONT_COUNT,
            "missing_territories": [],
            "unexpected_territories": [],
        },
        "availability": {
            "configured": True,
            "available_in_new_territories": True,
            "available_territory_count": submit.EXPECTED_STOREFRONT_COUNT,
            "active_territory_count": submit.EXPECTED_STOREFRONT_COUNT,
            "missing_territories": [],
            "unexpected_territories": [],
        },
        "encryption_declarations": {"count": 1, "accepted_count": 1},
        "accessibility_declarations": {"matches_release_decision": True},
        "review_submissions": review_status(record),
    }


def submission_resource(
    *,
    submission_id: str = "submission-one",
    app_id: str = submit.APP_ID,
    state: str = "READY_FOR_REVIEW",
) -> dict[str, object]:
    return {
        "data": {
            "type": "reviewSubmissions",
            "id": submission_id,
            "attributes": {"state": state},
            "relationships": {
                "app": {"data": {"type": "apps", "id": app_id}}
            },
        }
    }


def item_resource(
    platform: str,
    *,
    submission_id: str = "submission-one",
    version_id: str | None = None,
    item_id: str | None = None,
) -> dict[str, object]:
    version_id = VERSION_IDS[platform] if version_id is None else version_id
    item_id = f"item-{platform}" if item_id is None else item_id
    return {
        "data": {
            "type": "reviewSubmissionItems",
            "id": item_id,
            "attributes": {"state": "READY_FOR_REVIEW"},
            "relationships": {
                "reviewSubmission": {
                    "data": {
                        "type": "reviewSubmissions",
                        "id": submission_id,
                    }
                },
                "appStoreVersion": {
                    "data": {"type": "appStoreVersions", "id": version_id}
                },
            },
        }
    }


def cli_args(
    action: str,
    *,
    digest: str,
    owner_authorization: str,
) -> types.SimpleNamespace:
    current_candidates = candidates()
    return types.SimpleNamespace(
        preflight=action == "preflight",
        prepare=action == "prepare",
        submit=action == "submit",
        confirm_apple_id=submit.APP_ID,
        confirm_version=submit.APP_VERSION,
        confirm_build=submit.BUILD_NUMBER,
        confirm_ios_sha256=current_candidates["ios"].sha256,
        confirm_macos_sha256=current_candidates["macos"].sha256,
        confirm_scope=submit.EXPECTED_SCOPE,
        confirm_submit=(
            submit.EXPECTED_SUBMIT_CONFIRMATION if action == "submit" else None
        ),
        confirm_preflight_sha256=digest,
        confirm_owner_authorization=owner_authorization,
        selftest=False,
    )


class EncryptionClient:
    def get(
        self,
        path: str,
        params: dict[str, str] | None = None,
        *,
        allow_missing_relationship: bool = False,
    ) -> dict[str, object]:
        del params, allow_missing_relationship
        if path == "/v1/appEncryptionDeclarations":
            return {
                "data": [
                    {
                        "type": "appEncryptionDeclarations",
                        "id": "declaration-current",
                        "attributes": {
                            "appEncryptionDeclarationState": "APPROVED"
                        },
                    }
                ]
            }
        if path in {
            "/v1/builds/build-ios/appEncryptionDeclaration",
            "/v1/builds/build-macos/appEncryptionDeclaration",
        }:
            return {
                "data": {
                    "type": "appEncryptionDeclarations",
                    "id": "declaration-current",
                    "attributes": {
                        "appEncryptionDeclarationState": "APPROVED"
                    },
                }
            }
        raise AssertionError(f"unexpected GET {path}")


class MutationClient:
    def __init__(self, *, fail_second_item: bool = False) -> None:
        self.fail_second_item = fail_second_item
        self.posts: list[tuple[str, str, dict, dict]] = []
        self.patches: list[tuple[str, str, str, dict]] = []
        self.deletes: list[tuple[str, str, str]] = []

    def post_resource(
        self,
        path: str,
        resource_type: str,
        attributes: dict,
        relationships: dict,
    ) -> dict[str, object]:
        self.posts.append((path, resource_type, attributes, relationships))
        if path == "/v1/reviewSubmissions":
            return submission_resource()
        if path == "/v1/reviewSubmissionItems":
            platform = "ios" if len(self.posts) == 2 else "macos"
            if self.fail_second_item and platform == "macos":
                return item_resource(platform, version_id="version-cross-candidate")
            return item_resource(platform)
        raise AssertionError(f"unexpected POST {path}")

    def patch_attributes(
        self,
        path: str,
        resource_type: str,
        resource_id: str,
        attributes: dict,
    ) -> dict[str, object]:
        self.patches.append((path, resource_type, resource_id, attributes))
        return submission_resource(state="WAITING_FOR_REVIEW")

    def delete_resource(
        self,
        path: str,
        resource_type: str,
        resource_id: str,
    ) -> None:
        self.deletes.append((path, resource_type, resource_id))


class AppleSubmitForAppReviewTests(unittest.TestCase):
    def test_exact_prepared_submission_is_selected(self) -> None:
        record = exact_record()
        self.assertIs(
            submit.find_target_submission(review_status(record), VERSION_IDS),
            record,
        )

    def test_duplicate_missing_partial_and_cross_version_records_fail(self) -> None:
        duplicate_record = exact_record()
        duplicate_status = {
            "count": 2,
            "records": [duplicate_record, copy.deepcopy(duplicate_record)],
        }
        cases: list[dict[str, object]] = [
            {"records": []},
            duplicate_status,
        ]
        partial = exact_record()
        partial["items"] = partial["items"][:1]
        partial["item_count"] = 1
        partial["platforms"] = ["IOS"]
        cases.append(review_status(partial))
        cross_version = exact_record()
        cross_version["items"][0]["app_store_version_id"] = "version-other-ios"
        cases.append(review_status(cross_version))
        duplicate_item = exact_record()
        duplicate_item["items"][1]["id"] = "item-ios"
        cases.append(review_status(duplicate_item))
        for status in cases:
            with self.subTest(status=status):
                with self.assertRaises(submit.ReviewSubmitError):
                    submit.find_target_submission(status, VERSION_IDS)

    def test_rejected_removed_and_unknown_states_fail(self) -> None:
        for state in ("REJECTED", "REMOVED", "UNKNOWN"):
            with self.subTest(state=state):
                record = exact_record(item_state=state)
                with self.assertRaises(submit.ReviewSubmitError):
                    submit.find_target_submission(review_status(record), VERSION_IDS)
        record = exact_record(state="UNKNOWN")
        with self.assertRaises(submit.ReviewSubmitError):
            submit.find_target_submission(review_status(record), VERSION_IDS)

    def test_live_contract_rejects_cross_identity_and_build_drift(self) -> None:
        baseline = live_result()
        mutations = (
            lambda value: value.update({"app_id": "cross-app"}),
            lambda value: value.update({"bundle_id": "org.example.cross"}),
            lambda value: value.update({"app_version": "9.9.9"}),
            lambda value: value.update({"build_number": "999"}),
            lambda value: value["platforms"]["ios"].update(
                {"version_id": VERSION_IDS["macos"]}
            ),
            lambda value: value["platforms"]["ios"].update(
                {"selected_build_id": BUILD_IDS["macos"]}
            ),
            lambda value: value["builds"][0].update({"platform": "MAC_OS"}),
            lambda value: value["builds"][0].update({"expired": None}),
            lambda value: value["builds"][0].update(
                {"processing_state": "PROCESSING"}
            ),
            lambda value: value.update({"processed_platforms": ["ios"]}),
            lambda value: value["platforms"]["ios"].update(
                {"state": "READY_FOR_REVIEW"}
            ),
        )
        for mutate in mutations:
            value = copy.deepcopy(baseline)
            mutate(value)
            with self.subTest(value=value):
                with self.assertRaises(submit.ReviewSubmitError):
                    submit.require_live_release_contract(
                        value,
                        expected_version_state="PREPARE_FOR_SUBMISSION",
                    )

    def test_preflight_digest_binds_candidate_and_authenticated_state(self) -> None:
        result = live_result()
        links = {"ios": "declaration-current", "macos": "declaration-current"}
        with mock.patch.object(submit, "_file_sha256", return_value="f" * 64):
            digest = submit.preflight_digest(
                candidates(), result, BUILD_IDS, links
            )
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertEqual(
                submit.preflight_digest(candidates(), result, BUILD_IDS, links),
                digest,
            )
            changed_result = copy.deepcopy(result)
            changed_result["builds"][0]["uploaded_date"] = "changed"
            self.assertNotEqual(
                submit.preflight_digest(
                    candidates(), changed_result, BUILD_IDS, links
                ),
                digest,
            )
            changed_candidates = candidates()
            changed_candidates["ios"] = copy.copy(changed_candidates["ios"])
            object.__setattr__(changed_candidates["ios"], "sha256", "c" * 64)
            self.assertNotEqual(
                submit.preflight_digest(
                    changed_candidates, result, BUILD_IDS, links
                ),
                digest,
            )
        self.assertEqual(
            submit.owner_authorization_for_digest(digest),
            f"AUTHORIZE_APP_REVIEW_SHA256_{digest}",
        )

    def test_capture_rejects_already_submitted_and_rejected_state(self) -> None:
        client = EncryptionClient()
        for state, item_state in (
            ("WAITING_FOR_REVIEW", "ACCEPTED"),
            ("IN_REVIEW", "ACCEPTED"),
            ("COMPLETE", "APPROVED"),
            ("UNRESOLVED_ISSUES", "REJECTED"),
        ):
            with self.subTest(state=state):
                result = live_result(
                    record=exact_record(state=state, item_state=item_state),
                    version_state=(
                        "WAITING_FOR_REVIEW"
                        if state != "COMPLETE"
                        else "READY_FOR_DISTRIBUTION"
                    ),
                )
                with mock.patch.object(submit, "audit", return_value=result):
                    with self.assertRaises(submit.ReviewSubmitError):
                        submit.capture_preflight(client, candidates())

    def test_changed_authenticated_state_invalidates_owner_digest(self) -> None:
        first = live_result()
        second = copy.deepcopy(first)
        second["builds"][0]["uploaded_date"] = "2026-08-25T00:00:01Z"
        client = EncryptionClient()
        with mock.patch.object(submit, "_file_sha256", return_value="f" * 64):
            with mock.patch.object(submit, "audit", return_value=first):
                expected = submit.capture_preflight(client, candidates())["digest"]
            with mock.patch.object(submit, "audit", return_value=second):
                with self.assertRaisesRegex(
                    submit.ReviewSubmitError, "state changed"
                ):
                    submit.require_unchanged_preflight(
                        client, candidates(), expected
                    )

    def test_candidate_refresh_rejects_post_confirmation_drift(self) -> None:
        expected = candidates()
        with mock.patch.object(submit, "candidate_map", return_value=expected):
            self.assertEqual(submit.refresh_frozen_candidates(expected), expected)
        drifted = candidates()
        drifted["ios"] = submit.Candidate(
            **{
                **drifted["ios"].__dict__,
                "sha256": "c" * 64,
            }
        )
        with mock.patch.object(submit, "candidate_map", return_value=drifted):
            with self.assertRaisesRegex(
                submit.ReviewSubmitError, "changed after owner confirmation"
            ):
                submit.refresh_frozen_candidates(expected)

    def test_create_responses_require_exact_relationships(self) -> None:
        resource = submit.require_submission_response(submission_resource())
        self.assertEqual(resource["id"], "submission-one")
        submit.require_submission_item_response(
            item_resource("ios"),
            submission_id="submission-one",
            version_id=VERSION_IDS["ios"],
        )
        for payload in (
            submission_resource(app_id="cross-app"),
            submission_resource(submission_id="cross-submission"),
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(submit.ReviewSubmitError):
                    submit.require_submission_response(
                        payload, expected_id="submission-one"
                    )
        with self.assertRaises(submit.ReviewSubmitError):
            submit.require_submission_item_response(
                item_resource("ios", version_id="version-cross"),
                submission_id="submission-one",
                version_id=VERSION_IDS["ios"],
            )

    def test_prepare_persists_exact_items_and_relationships(self) -> None:
        client = MutationClient()
        with mock.patch.object(
            submit,
            "_review_submission_status",
            side_effect=[review_status(), review_status(exact_record())],
        ):
            result = submit.prepare_submission(client, VERSION_IDS)
        self.assertEqual(result["id"], "submission-one")
        self.assertEqual(
            [call[0] for call in client.posts],
            [
                "/v1/reviewSubmissions",
                "/v1/reviewSubmissionItems",
                "/v1/reviewSubmissionItems",
            ],
        )
        self.assertEqual(client.deletes, [])

    def test_partial_prepare_failure_cleans_only_same_run_resources(self) -> None:
        client = MutationClient(fail_second_item=True)
        with mock.patch.object(
            submit,
            "_review_submission_status",
            return_value=review_status(),
        ):
            with self.assertRaisesRegex(
                submit.ReviewSubmitError, "same-run cleanup completed"
            ):
                submit.prepare_submission(client, VERSION_IDS)
        self.assertEqual(
            client.deletes,
            [
                (
                    "/v1/reviewSubmissionItems/item-ios",
                    "reviewSubmissionItems",
                    "item-ios",
                ),
                (
                    "/v1/reviewSubmissions/submission-one",
                    "reviewSubmissions",
                    "submission-one",
                ),
            ],
        )

    def test_final_prepare_drift_cleans_every_same_run_resource(self) -> None:
        client = MutationClient()
        drifted = exact_record(submission_id="submission-other")
        with mock.patch.object(
            submit,
            "_review_submission_status",
            side_effect=[review_status(), review_status(drifted)],
        ):
            with self.assertRaisesRegex(
                submit.ReviewSubmitError, "same-run cleanup completed"
            ):
                submit.prepare_submission(client, VERSION_IDS)
        self.assertEqual(
            client.deletes,
            [
                (
                    "/v1/reviewSubmissionItems/item-macos",
                    "reviewSubmissionItems",
                    "item-macos",
                ),
                (
                    "/v1/reviewSubmissionItems/item-ios",
                    "reviewSubmissionItems",
                    "item-ios",
                ),
                (
                    "/v1/reviewSubmissions/submission-one",
                    "reviewSubmissions",
                    "submission-one",
                ),
            ],
        )

    def test_cleanup_failure_is_never_reported_as_recovered(self) -> None:
        client = MutationClient(fail_second_item=True)
        client.delete_resource = mock.Mock(
            side_effect=[submit.ReleaseStatusError("delete failed"), None]
        )
        with mock.patch.object(
            submit,
            "_review_submission_status",
            return_value=review_status(),
        ):
            with self.assertRaisesRegex(
                submit.ReviewSubmitError, "cleanup was incomplete"
            ):
                submit.prepare_submission(client, VERSION_IDS)

    def test_prepare_rechecks_absence_immediately_before_post(self) -> None:
        client = MutationClient()
        with mock.patch.object(
            submit,
            "_review_submission_status",
            return_value=review_status(exact_record()),
        ):
            with self.assertRaisesRegex(
                submit.ReviewSubmitError, "appeared immediately"
            ):
                submit.prepare_submission(client, VERSION_IDS)
        self.assertEqual(client.posts, [])

    def test_submit_rejects_retry_and_verifies_mutation_identity(self) -> None:
        client = MutationClient()
        submitted = exact_record(
            state="WAITING_FOR_REVIEW", item_state="ACCEPTED"
        )
        with mock.patch.object(
            submit,
            "_review_submission_status",
            side_effect=[
                review_status(exact_record()),
                review_status(submitted),
            ],
        ):
            submit.submit_prepared_submission(
                client, exact_record(), VERSION_IDS
            )
        self.assertEqual(
            client.patches,
            [
                (
                    "/v1/reviewSubmissions/submission-one",
                    "reviewSubmissions",
                    "submission-one",
                    {"submitted": True},
                )
            ],
        )
        retry_client = MutationClient()
        with self.assertRaisesRegex(submit.ReviewSubmitError, "already submitted"):
            submit.submit_prepared_submission(
                retry_client, submitted, VERSION_IDS
            )
        self.assertEqual(retry_client.patches, [])

    def test_submit_fails_closed_on_patch_response_drift(self) -> None:
        client = MutationClient()
        client.patch_attributes = mock.Mock(
            return_value=submission_resource(app_id="cross-app")
        )
        with mock.patch.object(
            submit,
            "_review_submission_status",
            return_value=review_status(exact_record()),
        ):
            with self.assertRaises(submit.ReviewSubmitError):
                submit.submit_prepared_submission(
                    client, exact_record(), VERSION_IDS
                )
        client.patch_attributes.assert_called_once()

    def test_submit_rechecks_state_immediately_before_patch(self) -> None:
        client = MutationClient()
        changed = exact_record()
        changed["items"][0]["id"] = "item-ios-changed"
        with mock.patch.object(
            submit,
            "_review_submission_status",
            return_value=review_status(changed),
        ):
            with self.assertRaisesRegex(
                submit.ReviewSubmitError, "changed immediately"
            ):
                submit.submit_prepared_submission(
                    client, exact_record(), VERSION_IDS
                )
        self.assertEqual(client.patches, [])

    def test_cli_refuses_stale_owner_digest_before_any_mutation(self) -> None:
        digest = "d" * 64
        args = cli_args(
            "prepare",
            digest="e" * 64,
            owner_authorization=submit.owner_authorization_for_digest(digest),
        )
        preflight = {
            "digest": digest,
            "existing": None,
            "version_ids": VERSION_IDS,
        }
        with mock.patch.object(submit, "parse_args", return_value=args), mock.patch.object(
            submit, "candidate_map", return_value=candidates()
        ), mock.patch.object(submit, "run_release_gates"), mock.patch.object(
            submit, "require_rollout_compliance"
        ), mock.patch.object(
            submit, "_load_client", return_value=object()
        ), mock.patch.object(
            submit, "capture_preflight", return_value=preflight
        ), mock.patch.object(
            submit, "prepare_submission"
        ) as prepare_mock:
            self.assertEqual(submit.main(), 1)
        prepare_mock.assert_not_called()

    def test_prepare_retry_is_idempotent_and_does_not_duplicate(self) -> None:
        digest = "d" * 64
        args = cli_args(
            "prepare",
            digest=digest,
            owner_authorization=submit.owner_authorization_for_digest(digest),
        )
        current_candidates = candidates()
        preflight = {
            "digest": digest,
            "existing": exact_record(),
            "version_ids": VERSION_IDS,
        }
        with mock.patch.object(submit, "parse_args", return_value=args), mock.patch.object(
            submit, "candidate_map", return_value=current_candidates
        ), mock.patch.object(submit, "run_release_gates"), mock.patch.object(
            submit, "require_rollout_compliance"
        ), mock.patch.object(
            submit, "_load_client", return_value=object()
        ), mock.patch.object(
            submit, "capture_preflight", return_value=preflight
        ), mock.patch.object(
            submit, "refresh_frozen_candidates", return_value=current_candidates
        ), mock.patch.object(
            submit, "require_unchanged_preflight", return_value=preflight
        ), mock.patch.object(
            submit, "prepare_submission"
        ) as prepare_mock:
            self.assertEqual(submit.main(), 0)
        prepare_mock.assert_not_called()

    def test_submit_requires_separately_prepared_current_submission(self) -> None:
        digest = "d" * 64
        args = cli_args(
            "submit",
            digest=digest,
            owner_authorization=submit.owner_authorization_for_digest(digest),
        )
        current_candidates = candidates()
        preflight = {
            "digest": digest,
            "existing": None,
            "version_ids": VERSION_IDS,
        }
        with mock.patch.object(submit, "parse_args", return_value=args), mock.patch.object(
            submit, "candidate_map", return_value=current_candidates
        ), mock.patch.object(submit, "run_release_gates"), mock.patch.object(
            submit, "require_rollout_compliance"
        ), mock.patch.object(
            submit, "_load_client", return_value=object()
        ), mock.patch.object(
            submit, "capture_preflight", return_value=preflight
        ), mock.patch.object(
            submit, "refresh_frozen_candidates", return_value=current_candidates
        ), mock.patch.object(
            submit, "require_unchanged_preflight", return_value=preflight
        ), mock.patch.object(
            submit, "submit_prepared_submission"
        ) as submit_mock:
            self.assertEqual(submit.main(), 1)
        submit_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
