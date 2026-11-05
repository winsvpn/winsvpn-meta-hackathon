#!/usr/bin/env python3
"""Fail-closed Apple listing, privacy, export, signing, and receipt gates."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import apple_store_listing_metadata as listing
import apple_watch_companion_smoke_testkit as watch_kit
import validate_apple_submission_package as submission


CANDIDATE = "app_store/apple/artifacts/release_candidate.json"
TV_SCOPE = listing.TV_SCOPE_RELATIVE
STALE_IOS = "1f92c7e291f68ebbdc93586f8db49157fb35067971c3da569af9095cbd81d4a9"


def _load(relative: str) -> dict[str, object]:
    payload = json.loads((ROOT / relative).read_text(encoding="ascii"))
    if type(payload) is not dict:
        raise AssertionError(f"{relative} must contain one JSON object")
    return payload


class AppleStoreListingMetadataTests(unittest.TestCase):
    def test_listing_files_and_gate_source_are_ascii(self) -> None:
        (ROOT / "tools/apple_store_listing_metadata.py").read_text(encoding="ascii")
        (ROOT / "tools/test_apple_store_listing_metadata.py").read_text(encoding="ascii")
        for relative in listing.LISTING_FILES:
            (ROOT / relative).read_bytes().decode("ascii")

    def test_live_draft_review_passes_and_keeps_watch_embedded(self) -> None:
        reviewed = listing.review_current_apple_store_metadata()
        self.assertTrue(reviewed["ok"])
        self.assertEqual(reviewed["canonical_release"], "1.0.17+34")
        self.assertEqual(
            reviewed["required_surfaces"],
            ["ios", "embedded_watchos_companion", "macos"],
        )
        self.assertTrue(reviewed["watchos_embedded_in_ios_ipa"])
        self.assertFalse(reviewed["tvos_shipping_surface"])
        self.assertFalse(reviewed["tv_scope"]["shipping_surface"])
        self.assertFalse(reviewed["tv_scope"]["upload_target"])
        self.assertEqual(
            reviewed["tv_scope"]["receipt_status"],
            "refused_not_a_current_target",
        )
        self.assertEqual(reviewed["candidate_set_status"], "no_current_candidate")
        self.assertEqual(reviewed["signing_status"], "unbound")
        self.assertFalse(reviewed["submission_approved"])
        self.assertFalse(reviewed["upload_authorized"])
        blockers = listing.current_apple_store_blockers(reviewed)
        self.assertTrue(blockers["owner"])
        self.assertTrue(blockers["device"])
        self.assertTrue(blockers["store"])
        messages = listing.review_messages()
        self.assertTrue(any("watchOS embedded" in item for item in messages))
        self.assertTrue(any("non-shipping" in item for item in messages))

    def test_release_ready_fails_closed_on_the_current_tree(self) -> None:
        with self.assertRaises(listing.AppleListingGateError) as caught:
            listing.review_current_apple_store_metadata(release_ready=True)
        detail = str(caught.exception)
        self.assertRegex(
            detail,
            r"stale|complete current|owner submission|export-compliance",
        )

    def test_tvos_shipping_upload_and_receipt_are_refused(self) -> None:
        original = listing._load_json

        def load_shipping(relative: str) -> dict[str, object]:
            payload = original(relative)
            if relative == TV_SCOPE:
                mutated = copy.deepcopy(payload)
                mutated["shipping_surface"] = True
                return mutated
            return payload

        with mock.patch.object(listing, "_load_json", side_effect=load_shipping):
            with self.assertRaisesRegex(
                listing.AppleListingGateError,
                "shipping, upload, signing, or receipt",
            ):
                listing.review_current_apple_store_metadata()

        def load_upload(relative: str) -> dict[str, object]:
            payload = original(relative)
            if relative == TV_SCOPE:
                mutated = copy.deepcopy(payload)
                mutated["upload_target"] = True
                return mutated
            return payload

        with mock.patch.object(listing, "_load_json", side_effect=load_upload):
            with self.assertRaisesRegex(listing.AppleListingGateError, "upload"):
                listing.review_current_apple_store_metadata()

        def load_receipt(relative: str) -> dict[str, object]:
            payload = original(relative)
            if relative == TV_SCOPE:
                mutated = copy.deepcopy(payload)
                mutated["receipt_status"] = "current_candidate"
                return mutated
            return payload

        with mock.patch.object(listing, "_load_json", side_effect=load_receipt):
            with self.assertRaisesRegex(listing.AppleListingGateError, "receipt"):
                listing.review_current_apple_store_metadata()

        def load_tvos_artifact(relative: str) -> dict[str, object]:
            payload = original(relative)
            if relative == CANDIDATE:
                mutated = copy.deepcopy(payload)
                mutated["artifacts"][0]["platform"] = "tvos"
                return mutated
            return payload

        with mock.patch.object(listing, "_load_json", side_effect=load_tvos_artifact):
            with self.assertRaisesRegex(
                listing.AppleListingGateError,
                "shipping, upload, signing, or receipt",
            ):
                listing.review_current_apple_store_metadata()

    def test_unsigned_adhoc_development_placeholder_and_stale_29_fail_closed(
        self,
    ) -> None:
        candidate = _load(CANDIDATE)
        ios = candidate["artifacts"][0]
        macos = candidate["artifacts"][1]
        listing.require_recorded_app_store_signing(ios, "ios", required=False)
        listing.require_recorded_app_store_signing(macos, "macos", required=False)

        unsigned = copy.deepcopy(ios)
        unsigned.pop("signing")
        with self.assertRaisesRegex(
            listing.AppleListingGateError, "real signed artifact identity"
        ):
            listing.require_recorded_app_store_signing(unsigned, "ios", required=False)

        adhoc = copy.deepcopy(ios)
        adhoc["signing"]["authority"] = "ad-hoc"
        with self.assertRaisesRegex(
            listing.AppleListingGateError, "Apple Distribution signing identity"
        ):
            listing.require_recorded_app_store_signing(adhoc, "ios", required=False)

        development = copy.deepcopy(ios)
        development["signing"]["authority"] = "Apple Development"
        with self.assertRaisesRegex(
            listing.AppleListingGateError, "Apple Distribution signing identity"
        ):
            listing.require_recorded_app_store_signing(
                development, "ios", required=False
            )

        placeholder = copy.deepcopy(ios)
        placeholder["signing"]["team_id"] = "XXXXXXXXXX"
        with self.assertRaisesRegex(
            listing.AppleListingGateError, "Apple Distribution signing identity"
        ):
            listing.require_recorded_app_store_signing(
                placeholder, "ios", required=False
            )

        stale = copy.deepcopy(ios)
        stale["sha256"] = STALE_IOS
        original = listing._load_json

        def load_stale(relative: str) -> dict[str, object]:
            payload = original(relative)
            if relative == CANDIDATE:
                mutated = copy.deepcopy(payload)
                mutated["artifacts"][0]["sha256"] = STALE_IOS
                return mutated
            return payload

        with mock.patch.object(listing, "_load_json", side_effect=load_stale):
            with self.assertRaisesRegex(
                listing.AppleListingGateError, "stale build 29"
            ):
                listing.review_current_apple_store_metadata()

        complete = copy.deepcopy(ios)
        complete["signing"]["status"] = "current_candidate"
        complete["signing"]["authority"] = listing.APPLE_DISTRIBUTION_AUTHORITY
        complete["signing"]["team_id"] = listing.TEAM_ID
        listing.require_recorded_app_store_signing(complete, "ios", required=True)
        complete["signing"]["authority"] = "Authority=Apple Development:"
        with self.assertRaisesRegex(
            listing.AppleListingGateError, "Apple Distribution signing identity"
        ):
            listing.require_recorded_app_store_signing(complete, "ios", required=True)

    def test_watchos_must_stay_embedded_in_the_ios_ipa(self) -> None:
        candidate = _load(CANDIDATE)
        watch = copy.deepcopy(candidate["artifacts"][0]["embedded_watchos_companion"])
        listing._require_watch_embedded(watch, required=False)
        watch["companion_bundle_id"] = "org.winsvpn.app.watchkitapp"
        with self.assertRaisesRegex(
            listing.AppleListingGateError, "current 1.0.17\\+34 companion"
        ):
            listing._require_watch_embedded(watch, required=False)
        standalone = copy.deepcopy(candidate["artifacts"][0]["embedded_watchos_companion"])
        standalone["status"] = "current_candidate"
        standalone["executable_sha256"] = "a" * 64
        standalone["privacy_info_sha256"] = "b" * 64
        listing._require_watch_embedded(standalone, required=True)
        standalone["bundle_id"] = "org.winsvpn.watch.standalone"
        with self.assertRaisesRegex(
            listing.AppleListingGateError, "current 1.0.17\\+34 companion"
        ):
            listing._require_watch_embedded(standalone, required=True)

    def test_macos_must_not_embed_watch_and_must_keep_both_architectures(self) -> None:
        original = listing._load_json

        def load_macos_watch(relative: str) -> dict[str, object]:
            payload = original(relative)
            if relative == CANDIDATE:
                mutated = copy.deepcopy(payload)
                mutated["artifacts"][1]["embedded_watchos_companion"] = copy.deepcopy(
                    mutated["artifacts"][0]["embedded_watchos_companion"]
                )
                return mutated
            return payload

        with mock.patch.object(listing, "_load_json", side_effect=load_macos_watch):
            with self.assertRaisesRegex(
                listing.AppleListingGateError, "must not embed a watchOS companion"
            ):
                listing.review_current_apple_store_metadata()

        def load_ios_inventory(relative: str) -> dict[str, object]:
            payload = original(relative)
            if relative == CANDIDATE:
                mutated = copy.deepcopy(payload)
                mutated["artifacts"][0]["shipped_architecture_inventory"] = {
                    "required_architectures": ["arm64"],
                    "shipped": [],
                }
                return mutated
            return payload

        with mock.patch.object(listing, "_load_json", side_effect=load_ios_inventory):
            with self.assertRaisesRegex(
                listing.AppleListingGateError, "macOS architecture inventory"
            ):
                listing.review_current_apple_store_metadata()

        def load_missing_x86(relative: str) -> dict[str, object]:
            payload = original(relative)
            if relative == CANDIDATE:
                mutated = copy.deepcopy(payload)
                mutated["artifacts"][1]["shipped_architecture_inventory"][
                    "required_architectures"
                ] = ["arm64"]
                return mutated
            return payload

        with mock.patch.object(listing, "_load_json", side_effect=load_missing_x86):
            with self.assertRaisesRegex(
                listing.AppleListingGateError, "arm64 and x86_64"
            ):
                listing.review_current_apple_store_metadata()

    def test_complete_candidates_reverify_a_passed_watch_smoke(self) -> None:
        # R22 Y3 D2: with a complete candidate set the smoke may stay pending,
        # a passed one is re-hashed and re-derived, and release-ready needs it.
        commit = "e" * 40
        candidate = _load(CANDIDATE)
        candidate["candidate_set_status"] = "complete_local_candidates"
        candidate["source_commit"] = commit
        for artifact in candidate["artifacts"]:
            artifact["signing"].update(
                status="current_candidate",
                authority=listing.APPLE_DISTRIBUTION_AUTHORITY,
                team_id=listing.TEAM_ID,
            )
        watch = candidate["artifacts"][0]["embedded_watchos_companion"]
        watch.update(status="current_candidate", executable_sha256="a" * 64, privacy_info_sha256="b" * 64)
        candidate["artifacts"][1]["shipped_architecture_inventory"]["shipped"] = [
            {"path": "WinsVPN.app/Contents/MacOS/WinsVPN", "sha256": "c" * 64, "size_bytes": 9, "architectures": ["arm64", "x86_64"]}
        ]
        runtime = _load("app_store/apple/artifacts/runtime_evidence.json")
        original = listing._load_json

        def load(relative: str) -> dict[str, object]:
            if relative == CANDIDATE:
                return copy.deepcopy(candidate)
            if relative == "app_store/apple/artifacts/runtime_evidence.json":
                return copy.deepcopy(runtime)
            return original(relative)

        with tempfile.TemporaryDirectory(prefix="wins-listing-watch-smoke-") as temporary:
            root = Path(temporary).resolve()
            path, digest = watch_kit.write_receipt(
                root, watch_kit.receipt_document(release=listing.CANONICAL_RELEASE, source_commit=commit)
            )
            real_check = listing.watch_smoke.runtime_watch_smoke_sha256

            def check_in_fixture_root(_root, *args, **kwargs):
                return real_check(root, *args, **kwargs)

            with mock.patch.object(listing, "_load_json", side_effect=load), mock.patch.object(
                listing.watch_smoke, "runtime_watch_smoke_sha256", side_effect=check_in_fixture_root
            ):
                reviewed = listing.review_current_apple_store_metadata()
                self.assertEqual(reviewed["candidate_set_status"], "complete_local_candidates")
                with self.assertRaisesRegex(listing.AppleListingGateError, "requires a passed"):
                    listing._require_bound_watch_smoke(candidate, runtime, release_ready=True)
                runtime["watch_companion_smoke"] = {
                    "status": "passed",
                    "receipt_path": path,
                    "receipt_sha256": digest,
                }
                listing.review_current_apple_store_metadata()
                listing._require_bound_watch_smoke(candidate, runtime, release_ready=True)
                for label, change, message in (
                    ("hash", {"receipt_sha256": "7" * 64}, "does not match the receipt bytes"),
                    ("path", {"receipt_path": path.replace("000000Z", "000009Z")}, "does not exist"),
                    ("status", {"status": "current"}, "pending or passed"),
                ):
                    with self.subTest(case=label):
                        runtime["watch_companion_smoke"] = {
                            "status": "passed",
                            "receipt_path": path,
                            "receipt_sha256": digest,
                            **change,
                        }
                        with self.assertRaisesRegex(listing.AppleListingGateError, message):
                            listing.review_current_apple_store_metadata()
                runtime["watch_companion_smoke"] = {
                    "status": "passed",
                    "receipt_path": path,
                    "receipt_sha256": digest,
                }
                candidate["source_commit"] = "f" * 40
                with self.assertRaisesRegex(listing.AppleListingGateError, "source commit"):
                    listing.review_current_apple_store_metadata()

    def test_export_status_and_identity_artifacts_fail_closed(self) -> None:
        original = listing._load_json

        def load_stale_export(relative: str) -> dict[str, object]:
            payload = original(relative)
            if relative == listing.EXPORT_STATUS_RELATIVE:
                mutated = copy.deepcopy(payload)
                mutated["app_version"] = "1.0.14"
                mutated["build_number"] = "29"
                return mutated
            return payload

        with mock.patch.object(listing, "_load_json", side_effect=load_stale_export):
            with self.assertRaisesRegex(
                listing.AppleListingGateError, "export-compliance status"
            ):
                listing.review_current_apple_store_metadata()

        def load_tvos_artifact_identity(relative: str) -> dict[str, object]:
            payload = original(relative)
            if relative == listing.RELEASE_IDENTITY_RELATIVE:
                mutated = copy.deepcopy(payload)
                mutated["platform_mappings"]["apple"]["required_artifacts"] = [
                    "ios_app_store_ipa_with_embedded_watchos",
                    "macos_app_store_pkg",
                    "tvos_app_store_ipa",
                ]
                return mutated
            return payload

        with mock.patch.object(
            listing, "_load_json", side_effect=load_tvos_artifact_identity
        ):
            with self.assertRaisesRegex(
                listing.AppleListingGateError,
                "canonical 1.0.17\\+34 iOS/watchOS/macOS contract",
            ):
                listing.review_current_apple_store_metadata()

    def test_draft_privacy_records_stale_portal_and_release_ready_does_not(
        self,
    ) -> None:
        privacy = _load("app_store/apple/review/privacy_label_manifest.json")
        listing._require_privacy(privacy, release_ready=False)
        submission.require_live_portal_stale_status_recorded(privacy)
        with self.assertRaises(AssertionError):
            submission.require_live_portal_matches_source_privacy(privacy)
        with self.assertRaisesRegex(listing.AppleListingGateError, "stale"):
            listing._require_privacy(privacy, release_ready=True)
        messages = submission.validate_privacy_label_manifest()
        self.assertTrue(
            any("matches source PrivacyInfo plists" in item for item in messages)
        )
        self.assertTrue(
            any(
                "unbound without a current candidate" in item
                or "archive privacy report matches" in item
                for item in messages
            )
        )


if __name__ == "__main__":
    unittest.main()
