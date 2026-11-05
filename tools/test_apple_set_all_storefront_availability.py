#!/usr/bin/env python3
"""Hostile local tests for exact all-storefront availability mutation."""

from __future__ import annotations

import copy
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_set_all_storefront_availability as availability


TERRITORY_IDS = [
    f"T{index:03d}" for index in range(availability.EXPECTED_STOREFRONT_COUNT)
]


def candidates() -> dict[str, availability.Candidate]:
    return {
        "ios": availability.Candidate(
            platform="ios",
            artifact_type="ipa",
            path=pathlib.Path("/held/ios.ipa"),
            relative_path="build/apple/ios.ipa",
            size_bytes=101,
            sha256="a" * 64,
            app_version=availability.APP_VERSION,
            build_number=availability.BUILD_NUMBER,
        ),
        "macos": availability.Candidate(
            platform="macos",
            artifact_type="pkg",
            path=pathlib.Path("/held/macos.pkg"),
            relative_path="build/apple/macos.pkg",
            size_bytes=202,
            sha256="b" * 64,
            app_version=availability.APP_VERSION,
            build_number=availability.BUILD_NUMBER,
        ),
    }


def exact_price_state() -> dict[str, object]:
    return {
        "configured": True,
        "entry_count": availability.EXPECTED_STOREFRONT_COUNT,
        "territory_count": availability.EXPECTED_STOREFRONT_COUNT,
        "active_territory_count": availability.EXPECTED_STOREFRONT_COUNT,
        "all_free": True,
        "missing_territories": [],
        "unexpected_territories": [],
    }


def build_state(mode: str = "already_attached") -> dict[str, object]:
    return {
        "mode": mode,
        "digest": "c" * 64,
        "immutable_digest": "d" * 64,
        "versions": {
            "ios": {"id": "version-ios", "platform": "IOS"},
            "macos": {"id": "version-macos", "platform": "MAC_OS"},
        },
        "builds": {
            "ios": {"id": "build-ios", "version": availability.BUILD_NUMBER},
            "macos": {"id": "build-macos", "version": availability.BUILD_NUMBER},
        },
        "relationships": {"ios": "build-ios", "macos": "build-macos"},
        "encryption_links": {"ios": "enc", "macos": "enc"},
    }


class StorefrontClient:
    def __init__(self, *, configured: bool = False) -> None:
        self.configured = configured
        self.availability_id = "availability-one"
        self.entries = self._entries()
        self.create_calls = 0
        self.persist_creation = True
        self.response_id = self.availability_id

    @staticmethod
    def _entries() -> list[dict[str, object]]:
        return [
            {
                "type": "territoryAvailabilities",
                "id": f"entry-{territory_id}",
                "attributes": {
                    "available": True,
                    "preOrderEnabled": False,
                    "releaseDate": None,
                    "preOrderPublishDate": None,
                    "contentStatuses": ["AVAILABLE"],
                },
                "relationships": {
                    "territory": {
                        "data": {"type": "territories", "id": territory_id}
                    }
                },
            }
            for territory_id in TERRITORY_IDS
        ]

    def get(self, path: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        if path == "/v1/territories":
            return {
                "data": [
                    {"type": "territories", "id": value}
                    for value in TERRITORY_IDS
                ],
                "links": {"next": None},
            }
        if path == f"/v1/apps/{availability.APP_ID}/appAvailabilityV2":
            return {
                "data": None
                if not self.configured
                else {"type": "appAvailabilities", "id": self.availability_id}
            }
        if path == f"/v2/appAvailabilities/{self.availability_id}":
            return {
                "data": {
                    "type": "appAvailabilities",
                    "id": self.availability_id,
                    "attributes": {"availableInNewTerritories": True},
                }
            }
        if path.endswith("/territoryAvailabilities"):
            return {"data": copy.deepcopy(self.entries), "links": {"next": None}}
        raise AssertionError(f"unexpected fixture request {path}")

    def create_app_availability(
        self, payload: dict[str, object], expected_ids: set[str]
    ) -> dict[str, object]:
        self.create_calls += 1
        if expected_ids != set(TERRITORY_IDS):
            raise AssertionError("mutation received the wrong territory set")
        if availability.payload_sha256(payload) != availability.payload_sha256(
            availability.availability_payload(set(TERRITORY_IDS))
        ):
            raise AssertionError("mutation received a substituted payload")
        if self.persist_creation:
            self.configured = True
        return {
            "data": {"type": "appAvailabilities", "id": self.response_id}
        }


def synthetic_preflight(
    *,
    mode: str = "unconfigured",
    digest: str = "1" * 64,
    identity_digest: str = "2" * 64,
    availability_id: str | None = None,
) -> dict[str, object]:
    return {
        "mode": mode,
        "digest": digest,
        "identity_digest": identity_digest,
        "territory_ids": list(TERRITORY_IDS),
        "availability_state": {
            "configured": mode == "already_exact",
            "app_availability_id": availability_id,
        },
    }


class StorefrontContractTests(unittest.TestCase):
    def source_patches(self, root: pathlib.Path):
        release = root / "release.json"
        runtime = root / "runtime.json"
        owner = root / "owner.json"
        rollout = root / "rollout.json"
        for path in (release, runtime, owner, rollout):
            path.write_text(path.name, encoding="ascii")
        return (
            mock.patch.object(availability.build_attach, "RELEASE_CANDIDATE_PATH", release),
            mock.patch.object(availability.build_attach, "RUNTIME_EVIDENCE_PATH", runtime),
            mock.patch.object(availability.build_attach, "OWNER_SIGNOFF_PATH", owner),
            mock.patch.object(availability, "ROLLOUT_PATH", rollout),
        )

    def capture(self, client: StorefrontClient, *, state=None):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self.source_patches(pathlib.Path(temp_dir))
            with (
                paths[0],
                paths[1],
                paths[2],
                paths[3],
                mock.patch.object(
                    availability.build_attach,
                    "capture_preflight",
                    return_value=state or build_state(),
                ),
                mock.patch.object(
                    availability,
                    "_price_status",
                    return_value=exact_price_state(),
                ),
                mock.patch.object(availability, "require_owner_approval"),
                mock.patch.object(availability, "require_dsa_verified"),
            ):
                return availability.capture_preflight(client, candidates())

    def test_capture_binds_unconfigured_full_scope(self) -> None:
        result = self.capture(StorefrontClient())
        self.assertEqual(result["mode"], "unconfigured")
        self.assertEqual(result["territory_ids"], TERRITORY_IDS)
        self.assertRegex(str(result["digest"]), r"^[0-9a-f]{64}$")

    def test_exact_existing_state_is_the_only_idempotent_state(self) -> None:
        result = self.capture(StorefrontClient(configured=True))
        self.assertEqual(result["mode"], "already_exact")
        partial = StorefrontClient(configured=True)
        partial.entries[0]["attributes"]["available"] = False
        with self.assertRaisesRegex(availability.AvailabilityError, "partial"):
            self.capture(partial)

    def test_build_attachment_identity_must_be_exact(self) -> None:
        with self.assertRaisesRegex(availability.AvailabilityError, "already be attached"):
            self.capture(StorefrontClient(), state=build_state("unattached"))

    def test_each_capture_revalidates_owner_and_dsa_gates(self) -> None:
        client = StorefrontClient()
        with (
            mock.patch.object(
                availability,
                "require_owner_approval",
                side_effect=availability.AvailabilityError("owner gate drift"),
            ),
            self.assertRaisesRegex(availability.AvailabilityError, "owner gate drift"),
        ):
            availability.capture_preflight(client, candidates())
        with (
            mock.patch.object(availability, "require_owner_approval"),
            mock.patch.object(
                availability,
                "require_dsa_verified",
                side_effect=availability.AvailabilityError("DSA gate drift"),
            ),
            self.assertRaisesRegex(availability.AvailabilityError, "DSA gate drift"),
        ):
            availability.capture_preflight(client, candidates())

    def test_candidate_substitution_changes_preflight_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = self.source_patches(pathlib.Path(temp_dir))
            with (
                paths[0],
                paths[1],
                paths[2],
                paths[3],
                mock.patch.object(
                    availability.build_attach,
                    "capture_preflight",
                    return_value=build_state(),
                ),
                mock.patch.object(
                    availability,
                    "_price_status",
                    return_value=exact_price_state(),
                ),
                mock.patch.object(availability, "require_owner_approval"),
                mock.patch.object(availability, "require_dsa_verified"),
            ):
                first = availability.capture_preflight(StorefrontClient(), candidates())
                changed = candidates()
                changed["ios"] = availability.Candidate(
                    **{**changed["ios"].__dict__, "sha256": "e" * 64}
                )
                second = availability.capture_preflight(StorefrontClient(), changed)
        self.assertNotEqual(first["digest"], second["digest"])

    def test_duplicate_missing_and_cross_type_territories_fail_closed(self) -> None:
        client = StorefrontClient()
        duplicate = [
            {"type": "territories", "id": value} for value in TERRITORY_IDS
        ]
        duplicate[-1]["id"] = duplicate[0]["id"]
        for label, resources in (
            ("duplicated", duplicate),
            ("changed", duplicate[:-1]),
            (
                "type",
                [
                    {"type": "crossType", "id": TERRITORY_IDS[0]},
                    *[
                        {"type": "territories", "id": value}
                        for value in TERRITORY_IDS[1:]
                    ],
                ],
            ),
        ):
            with self.subTest(label=label):
                with (
                    mock.patch.object(
                        client,
                        "get",
                        return_value={"data": resources, "links": {"next": None}},
                    ),
                    self.assertRaisesRegex(availability.AvailabilityError, label),
                ):
                    availability.active_territory_state(client)

    def test_duplicate_and_substituted_availability_relationships_fail(self) -> None:
        duplicate = StorefrontClient(configured=True)
        duplicate.entries[-1]["relationships"] = copy.deepcopy(
            duplicate.entries[0]["relationships"]
        )
        with self.assertRaisesRegex(availability.AvailabilityError, "duplicated"):
            availability.availability_relationship_state(
                duplicate, set(TERRITORY_IDS)
            )
        substituted = StorefrontClient(configured=True)
        original_get = substituted.get

        def wrong_detail(path: str, *args: object, **kwargs: object):
            result = original_get(path, *args, **kwargs)
            if path == f"/v2/appAvailabilities/{substituted.availability_id}":
                result["data"]["id"] = "another-availability"
            return result

        substituted.get = wrong_detail  # type: ignore[method-assign]
        with self.assertRaisesRegex(availability.AvailabilityError, "substituted"):
            availability.availability_relationship_state(
                substituted, set(TERRITORY_IDS)
            )

    def test_price_schedule_must_cover_exact_free_set(self) -> None:
        invalid = exact_price_state()
        invalid["entry_count"] = availability.EXPECTED_STOREFRONT_COUNT - 1
        with (
            mock.patch.object(availability, "_price_status", return_value=invalid),
            self.assertRaisesRegex(availability.AvailabilityError, "price schedule"),
        ):
            availability.exact_free_price_state(
                StorefrontClient(), set(TERRITORY_IDS)
            )

    def test_rollout_json_rejects_duplicate_and_nonfinite_values(self) -> None:
        for payload, message in (
            ('{"x":1,"x":2}', "duplicate"),
            ('{"x":NaN}', "non-finite"),
        ):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temp_dir:
                path = pathlib.Path(temp_dir) / "rollout.json"
                path.write_text(payload, encoding="ascii")
                with (
                    mock.patch.object(availability, "ROLLOUT_PATH", path),
                    self.assertRaisesRegex(availability.AvailabilityError, message),
                ):
                    availability.read_rollout()


class MutationBoundaryTests(unittest.TestCase):
    def execute(
        self,
        client: StorefrontClient,
        state: dict[str, object],
        capture=None,
    ) -> str:
        if capture is None:
            def capture(
                _client: StorefrontClient,
                _candidates: dict[str, availability.Candidate],
            ) -> dict[str, object]:
                if client.configured:
                    if state.get("mode") == "already_exact":
                        return copy.deepcopy(state)
                    return synthetic_preflight(
                        mode="already_exact",
                        digest="9" * 64,
                        identity_digest=str(state["identity_digest"]),
                        availability_id=client.availability_id,
                    )
                return copy.deepcopy(state)

        with (
            mock.patch.object(
                availability.build_attach,
                "refresh_frozen_candidates",
                return_value=candidates(),
            ),
            mock.patch.object(availability, "capture_preflight", side_effect=capture),
        ):
            return availability.execute_availability(
                client,
                candidates(),
                state,
                expected_digest=str(state["digest"]),
                owner_authorization=availability.owner_authorization_for_digest(
                    str(state["digest"])
                ),
            )

    def test_fresh_full_reaudit_wraps_creation_and_persistence(self) -> None:
        client = StorefrontClient()
        result = self.execute(client, synthetic_preflight())
        self.assertEqual(result, "created")
        self.assertEqual(client.create_calls, 1)
        self.assertTrue(client.configured)

    def test_exact_existing_state_is_idempotent(self) -> None:
        client = StorefrontClient(configured=True)
        state = synthetic_preflight(
            mode="already_exact", availability_id=client.availability_id
        )
        result = self.execute(client, state)
        self.assertEqual(result, "already_exact")
        self.assertEqual(client.create_calls, 0)

    def test_state_drift_after_confirmation_blocks_before_creation(self) -> None:
        client = StorefrontClient()
        state = synthetic_preflight()

        def stale(*_args: object, **_kwargs: object) -> dict[str, object]:
            return synthetic_preflight(digest="8" * 64)

        with self.assertRaisesRegex(availability.AvailabilityError, "changed"):
            self.execute(client, state, stale)
        self.assertEqual(client.create_calls, 0)

    def test_candidate_drift_blocks_before_creation(self) -> None:
        client = StorefrontClient()
        state = synthetic_preflight()
        with (
            mock.patch.object(
                availability.build_attach,
                "refresh_frozen_candidates",
                side_effect=availability.build_attach.BuildAttachError("candidate drift"),
            ),
            self.assertRaisesRegex(
                availability.build_attach.BuildAttachError, "candidate drift"
            ),
        ):
            availability.execute_availability(
                client,
                candidates(),
                state,
                expected_digest=str(state["digest"]),
                owner_authorization=availability.owner_authorization_for_digest(
                    str(state["digest"])
                ),
            )
        self.assertEqual(client.create_calls, 0)

    def test_response_substitution_never_reports_success(self) -> None:
        client = StorefrontClient()
        client.response_id = "substituted-response"
        with self.assertRaisesRegex(availability.AvailabilityError, "substituted"):
            self.execute(client, synthetic_preflight())
        self.assertEqual(client.create_calls, 1)

    def test_missing_persistence_never_reports_success(self) -> None:
        client = StorefrontClient()
        client.persist_creation = False
        with self.assertRaisesRegex(availability.AvailabilityError, "without persistence"):
            self.execute(client, synthetic_preflight())
        self.assertEqual(client.create_calls, 1)

    def test_post_creation_identity_drift_requires_reconciliation(self) -> None:
        client = StorefrontClient()
        state = synthetic_preflight()

        def drift(*_args: object, **_kwargs: object) -> dict[str, object]:
            if client.configured:
                return synthetic_preflight(
                    mode="already_exact",
                    digest="9" * 64,
                    identity_digest="7" * 64,
                    availability_id=client.availability_id,
                )
            return copy.deepcopy(state)

        with self.assertRaisesRegex(availability.AvailabilityError, "identity changed"):
            self.execute(client, state, drift)
        self.assertEqual(client.create_calls, 1)

    def test_wrong_owner_digest_causes_zero_creation(self) -> None:
        client = StorefrontClient()
        state = synthetic_preflight()
        with self.assertRaisesRegex(availability.AvailabilityError, "preflight SHA-256"):
            availability.execute_availability(
                client,
                candidates(),
                state,
                expected_digest="0" * 64,
                owner_authorization=availability.owner_authorization_for_digest(
                    str(state["digest"])
                ),
            )
        self.assertEqual(client.create_calls, 0)


if __name__ == "__main__":
    unittest.main()
