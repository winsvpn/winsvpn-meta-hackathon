#!/usr/bin/env python3
"""Hostile local tests for the processed-build attachment boundary."""

from __future__ import annotations

import copy
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
import sys

if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_attach_processed_builds as attach


VERSION_IDS = {"ios": "version-ios", "macos": "version-macos"}
BUILD_IDS = {"ios": "build-ios", "macos": "build-macos"}


def candidates() -> dict[str, attach.Candidate]:
    return {
        "ios": attach.Candidate(
            platform="ios",
            artifact_type="ipa",
            path=pathlib.Path("/held/ios.ipa"),
            relative_path="build/apple/ios.ipa",
            size_bytes=101,
            sha256="a" * 64,
            app_version=attach.APP_VERSION,
            build_number=attach.BUILD_NUMBER,
        ),
        "macos": attach.Candidate(
            platform="macos",
            artifact_type="pkg",
            path=pathlib.Path("/held/macos.pkg"),
            relative_path="build/apple/macos.pkg",
            size_bytes=202,
            sha256="b" * 64,
            app_version=attach.APP_VERSION,
            build_number=attach.BUILD_NUMBER,
        ),
    }


def versions() -> dict[str, dict[str, object]]:
    return {
        platform: {
            "type": "appStoreVersions",
            "id": VERSION_IDS[platform],
            "attributes": {
                "platform": attach.API_PLATFORM[platform],
                "versionString": attach.APP_VERSION,
                "appStoreState": "PREPARE_FOR_SUBMISSION",
            },
        }
        for platform in attach.PLATFORMS
    }


def builds() -> list[dict[str, object]]:
    return [
        {
            "id": BUILD_IDS[platform],
            "platform": attach.API_PLATFORM[platform],
            "version": attach.BUILD_NUMBER,
            "processing_state": "VALID",
            "uploaded_date": f"2026-08-25T00:0{index}:00Z",
            "expired": False,
            "uses_non_exempt_encryption": True,
        }
        for index, platform in enumerate(attach.PLATFORMS)
    ]


def empty_review_status() -> dict[str, object]:
    return {
        "count": 0,
        "records": [],
        "submitted_platforms": [],
        "both_platforms_submitted": False,
    }


class FixtureClient:
    def __init__(
        self,
        *,
        relationships: dict[str, str | None] | None = None,
        wrong_app: bool = False,
        wrong_encryption: bool = False,
    ) -> None:
        self.relationships = relationships or {"ios": None, "macos": None}
        self.wrong_app = wrong_app
        self.wrong_encryption = wrong_encryption
        self.patches: list[tuple[str, str]] = []

    def get(self, path: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        if path == "/v1/appEncryptionDeclarations":
            return {
                "data": [
                    {
                        "type": "appEncryptionDeclarations",
                        "id": "encryption-approved",
                        "attributes": {
                            "appEncryptionDeclarationState": "APPROVED"
                        },
                    }
                ]
            }
        if path.endswith("/appEncryptionDeclaration"):
            declaration_id = (
                "encryption-other" if self.wrong_encryption else "encryption-approved"
            )
            return {
                "data": {
                    "type": "appEncryptionDeclarations",
                    "id": declaration_id,
                }
            }
        if path.endswith("/app"):
            return {
                "data": {
                    "type": "apps",
                    "id": "cross-app" if self.wrong_app else attach.APP_ID,
                }
            }
        if path.endswith("/build"):
            version_id = path.split("/")[3]
            platform = next(
                key for key, value in VERSION_IDS.items() if value == version_id
            )
            build_id = self.relationships[platform]
            return {
                "data": None
                if build_id is None
                else {"type": "builds", "id": build_id}
            }
        raise AssertionError(f"unexpected fixture request {path}")

    def patch_relationship(
        self,
        _parent_type: str,
        version_id: str,
        _relationship: str,
        _related_type: str,
        build_id: str,
    ) -> None:
        platform = next(key for key, value in VERSION_IDS.items() if value == version_id)
        self.patches.append((platform, build_id))
        self.relationships[platform] = build_id


def preflight(
    *,
    mode: str = "unattached",
    relationships: dict[str, str | None] | None = None,
) -> dict[str, object]:
    relation_state = relationships or {"ios": None, "macos": None}
    return {
        "versions": {
            platform: {"id": VERSION_IDS[platform]} for platform in attach.PLATFORMS
        },
        "builds": {
            platform: {"id": BUILD_IDS[platform]} for platform in attach.PLATFORMS
        },
        "relationships": relation_state,
        "mode": mode,
        "immutable_digest": "1" * 64,
        "digest": "2" * 64,
    }


class AttachmentContractTests(unittest.TestCase):
    def source_file_patches(self, root: pathlib.Path) -> list[mock._patch]:
        paths = []
        for name in ("release.json", "runtime.json", "owner.json", "rollout.json"):
            path = root / name
            path.write_text(name, encoding="ascii")
            paths.append(path)
        return [
            mock.patch.object(attach, "RELEASE_CANDIDATE_PATH", paths[0]),
            mock.patch.object(attach, "RUNTIME_EVIDENCE_PATH", paths[1]),
            mock.patch.object(attach, "OWNER_SIGNOFF_PATH", paths[2]),
            mock.patch.object(attach, "ROLLOUT_PATH", paths[3]),
        ]

    def capture(self, client: FixtureClient) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temp_dir:
            patches = self.source_file_patches(pathlib.Path(temp_dir))
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                mock.patch.object(attach, "_editable_versions", return_value=versions()),
                mock.patch.object(attach, "_build_status", return_value=builds()),
                mock.patch.object(
                    attach,
                    "_review_submission_status",
                    return_value=empty_review_status(),
                ),
            ):
                return attach.capture_preflight(client, candidates())

    def test_capture_binds_exact_current_state(self) -> None:
        result = self.capture(FixtureClient())
        self.assertEqual(result["mode"], "unattached")
        self.assertRegex(str(result["digest"]), r"^[0-9a-f]{64}$")
        self.assertEqual(
            result["encryption_links"],
            {"ios": "encryption-approved", "macos": "encryption-approved"},
        )

    def test_candidate_substitution_changes_authorization_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            patches = self.source_file_patches(pathlib.Path(temp_dir))
            common = (
                mock.patch.object(attach, "_editable_versions", return_value=versions()),
                mock.patch.object(attach, "_build_status", return_value=builds()),
                mock.patch.object(
                    attach,
                    "_review_submission_status",
                    return_value=empty_review_status(),
                ),
            )
            with patches[0], patches[1], patches[2], patches[3], common[0], common[1], common[2]:
                first = attach.capture_preflight(FixtureClient(), candidates())
                changed = candidates()
                changed["ios"] = attach.Candidate(
                    **{**changed["ios"].__dict__, "sha256": "c" * 64}
                )
                second = attach.capture_preflight(FixtureClient(), changed)
        self.assertNotEqual(first["digest"], second["digest"])

    def test_cross_app_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(attach.BuildAttachError, "exact app"):
            self.capture(FixtureClient(wrong_app=True))

    def test_cross_encryption_declaration_is_rejected(self) -> None:
        with self.assertRaisesRegex(attach.BuildAttachError, "accepted encryption"):
            self.capture(FixtureClient(wrong_encryption=True))

    def test_wrong_or_partial_existing_relationship_is_rejected(self) -> None:
        with self.assertRaisesRegex(attach.BuildAttachError, "different build"):
            self.capture(
                FixtureClient(relationships={"ios": "wrong-build", "macos": None})
            )
        with self.assertRaisesRegex(attach.BuildAttachError, "partial state"):
            self.capture(
                FixtureClient(relationships={"ios": BUILD_IDS["ios"], "macos": None})
            )

    def test_processed_build_hostile_fields_fail_closed(self) -> None:
        client = FixtureClient()
        hostile = (
            ("ambiguous", lambda value: value.__setitem__(1, copy.deepcopy(value[0]))),
            ("build", lambda value: value[0].update({"version": "29"})),
            ("processed", lambda value: value[0].update({"processing_state": "PROCESSING"})),
            ("expired", lambda value: value[0].update({"expired": True})),
            ("encryption", lambda value: value[0].update({"uses_non_exempt_encryption": None})),
            ("uploaded date", lambda value: value[0].update({"uploaded_date": "stale"})),
            ("ambiguous", lambda value: value[1].update({"platform": "IOS"})),
        )
        for message, mutate in hostile:
            with self.subTest(message=message):
                current = builds()
                mutate(current)
                with (
                    mock.patch.object(attach, "_build_status", return_value=current),
                    self.assertRaisesRegex(attach.BuildAttachError, message),
                ):
                    attach.processed_builds(client)

    def test_version_identity_and_state_drift_fail_closed(self) -> None:
        client = FixtureClient()
        for key, value in (
            ("platform", "MAC_OS"),
            ("versionString", "1.0.14"),
            ("appStoreState", "READY_FOR_REVIEW"),
        ):
            with self.subTest(key=key):
                current = versions()
                current["ios"]["attributes"][key] = value
                with (
                    mock.patch.object(attach, "_editable_versions", return_value=current),
                    self.assertRaisesRegex(attach.BuildAttachError, "identity or state"),
                ):
                    attach.editable_version_records(client)

    def test_active_and_duplicate_review_submissions_are_rejected(self) -> None:
        client = FixtureClient()
        active = {"id": "review-one", "state": "READY_FOR_REVIEW"}
        with (
            mock.patch.object(
                attach,
                "_review_submission_status",
                return_value={"count": 1, "records": [active]},
            ),
            self.assertRaisesRegex(attach.BuildAttachError, "blocks build attachment"),
        ):
            attach.require_no_active_review_submission(client)
        complete = {"id": "review-one", "state": "COMPLETE"}
        with (
            mock.patch.object(
                attach,
                "_review_submission_status",
                return_value={"count": 2, "records": [complete, complete]},
            ),
            self.assertRaisesRegex(attach.BuildAttachError, "duplicated"),
        ):
            attach.require_no_active_review_submission(client)

    def test_owner_authorization_is_digest_bound(self) -> None:
        digest = "d" * 64
        token = attach.owner_authorization_for_digest(digest)
        self.assertEqual(token, attach.OWNER_AUTHORIZATION_PREFIX + digest)
        with self.assertRaisesRegex(attach.BuildAttachError, "invalid"):
            attach.owner_authorization_for_digest("not-a-digest")


class MutationSequenceTests(unittest.TestCase):
    def run_execute(
        self,
        client: FixtureClient,
        state: dict[str, object],
        capture_side_effect=None,
    ) -> str:
        if capture_side_effect is None:
            def capture_side_effect(
                _client: FixtureClient,
                _candidates: dict[str, attach.Candidate],
                **_kwargs: object,
            ) -> dict[str, object]:
                return {
                    "immutable_digest": state["immutable_digest"],
                    "relationships": dict(client.relationships),
                    "digest": state["digest"],
                }

        with (
            mock.patch.object(attach, "refresh_frozen_candidates", return_value=candidates()),
            mock.patch.object(attach, "capture_preflight", side_effect=capture_side_effect),
        ):
            return attach.execute_attachment(
                client,
                candidates(),
                state,
                expected_digest=str(state["digest"]),
                owner_authorization=attach.owner_authorization_for_digest(
                    str(state["digest"])
                ),
            )

    def test_fresh_reaudit_wraps_each_exact_mutation(self) -> None:
        client = FixtureClient()
        result = self.run_execute(client, preflight())
        self.assertEqual(result, "attached")
        self.assertEqual(
            client.patches,
            [("ios", BUILD_IDS["ios"]), ("macos", BUILD_IDS["macos"])],
        )

    def test_exact_already_attached_retry_is_idempotent(self) -> None:
        relationships = dict(BUILD_IDS)
        client = FixtureClient(relationships=relationships)
        state = preflight(mode="already_attached", relationships=relationships)
        result = self.run_execute(client, state)
        self.assertEqual(result, "already_attached")
        self.assertEqual(client.patches, [])

    def test_stale_preflight_blocks_before_mutation(self) -> None:
        client = FixtureClient()
        state = preflight()

        def stale(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {
                "immutable_digest": "9" * 64,
                "relationships": dict(client.relationships),
                "digest": state["digest"],
            }

        with self.assertRaisesRegex(attach.BuildAttachError, "before any persistent change"):
            self.run_execute(client, state, stale)
        self.assertEqual(client.patches, [])

    def test_state_drift_after_first_mutation_reports_partial_state(self) -> None:
        client = FixtureClient()
        state = preflight()
        calls = 0

        def drifting(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            immutable = state["immutable_digest"] if calls <= 2 else "8" * 64
            return {
                "immutable_digest": immutable,
                "relationships": dict(client.relationships),
                "digest": state["digest"],
            }

        with self.assertRaisesRegex(attach.BuildAttachError, "partial state"):
            self.run_execute(client, state, drifting)
        self.assertEqual(client.patches, [("ios", BUILD_IDS["ios"])])

    def test_missing_persistence_never_reports_success(self) -> None:
        client = FixtureClient()

        def no_persist(*args: object, **kwargs: object) -> None:
            platform = next(
                key for key, value in VERSION_IDS.items() if value == args[1]
            )
            client.patches.append((platform, str(args[4])))

        client.patch_relationship = no_persist  # type: ignore[method-assign]
        with self.assertRaisesRegex(attach.BuildAttachError, "before any persistent change"):
            self.run_execute(client, preflight())

    def test_wrong_confirmation_causes_zero_mutations(self) -> None:
        client = FixtureClient()
        state = preflight()
        with self.assertRaisesRegex(attach.BuildAttachError, "preflight SHA-256"):
            attach.execute_attachment(
                client,
                candidates(),
                state,
                expected_digest="0" * 64,
                owner_authorization=attach.owner_authorization_for_digest(
                    str(state["digest"])
                ),
            )
        self.assertEqual(client.patches, [])


if __name__ == "__main__":
    unittest.main()
