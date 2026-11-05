#!/usr/bin/env python3
"""Machine-check the canonical Apple release scope for 1.0.17+34."""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import apple_upload_exact_release_candidates as uploader
import apple_store_listing_metadata as listing
import cross_store_upload_readiness as cross_store
import release_dependency_freeze as freeze
import validate_apple_owner_signoff as owner_signoff
import validate_apple_submission_package as submission


RELEASE = "1.0.17+34"
REQUIRED_ARTIFACTS = {
    "ios_app_store_ipa_with_embedded_watchos",
    "macos_app_store_pkg",
}
SHIPPING_SURFACES = {"ios", "watchos", "macos"}
CURRENT_APPLE_UPLOAD_TARGETS = {
    "ios-app-store-ipa",
    "macos-app-store-pkg",
}
OPTIONAL_APPLE_UPLOAD_TARGETS = {"macos-developer-id-app"}


def strict_json(path: Path) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise AssertionError(f"{path} has duplicate JSON key {key!r}")
            result[key] = value
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must contain a JSON object")
    return value


class AppleReleaseScopeConsistencyTest(unittest.TestCase):
    def test_blueprint_and_ruling_define_current_scope(self) -> None:
        blueprint = (
            ROOT / "docs/blueprints/WINS_VPN_COMPLETE_HANDOFF_BLUEPRINT.md"
        ).read_text(encoding="utf-8")
        shipping_row = next(
            line for line in blueprint.splitlines() if "**Win's VPN** (the app)" in line
        )
        for platform in ("Android", "iOS", "macOS", "Windows", "Linux", "Wear OS", "watchOS"):
            self.assertIn(platform, shipping_row)
        self.assertNotIn("tvOS", shipping_row)

        ruling = strict_json(
            ROOT / "docs/rulings/TVOS_POST_RELEASE_PRODUCT_SCOPE_20260824.json"
        )
        self.assertIn(ruling["release"], ("1.0.15+30", RELEASE))
        self.assertEqual(ruling["status"], "post_release_native_product_only")
        current = ruling["current_release"]
        self.assertEqual(set(current["required_apple_artifacts"]), REQUIRED_ARTIFACTS)
        self.assertEqual(current["optional_separate_distribution"], ["macos_developer_id"])
        self.assertEqual(
            set(current["required_app_store_upload_targets"]),
            CURRENT_APPLE_UPLOAD_TARGETS,
        )
        self.assertEqual(
            set(current["optional_evidence_targets"]),
            OPTIONAL_APPLE_UPLOAD_TARGETS,
        )
        self.assertIs(current["developer_id_is_required_readiness_target"], False)
        self.assertIs(current["developer_id_affects_freeze_completeness"], False)
        self.assertIs(
            current["developer_id_affects_app_store_upload_readiness"],
            False,
        )
        self.assertIs(current["tvos_is_shipping_surface"], False)
        self.assertIs(current["tvos_is_release_blocker"], False)
        self.assertIs(current["tvos_is_readiness_denominator"], False)

    def test_submission_docs_define_two_uploads_and_separate_optional_lane(self) -> None:
        readme = (ROOT / "app_store/apple/README.md").read_text(encoding="utf-8")
        owner_packet = (
            ROOT / "app_store/apple/review/owner_review_packet.md"
        ).read_text(encoding="utf-8")
        for document in (readme, owner_packet):
            self.assertIn("exactly two", document)
            self.assertRegex(document, r"iOS\s+IPA")
            self.assertIn("macOS", document)
            self.assertIn("Developer ID", document)
            self.assertIn("optional", document)
            self.assertIn("tvOS", document)
            self.assertIn("post-release", document)

    def test_xcode_targets_match_ios_watchos_product(self) -> None:
        project = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text(
            encoding="utf-8"
        )
        native_section = project.split("/* Begin PBXNativeTarget section */", 1)[1].split(
            "/* End PBXNativeTarget section */", 1
        )[0]
        target_names = set(re.findall(r"(?m)^\s*name = ([^;]+);$", native_section))
        self.assertTrue({"Runner", "PacketTunnel", "WinsWatch"}.issubset(target_names))
        self.assertFalse(any("tv" in name.lower() for name in target_names))
        self.assertNotIn("appletvos", project.lower())
        self.assertNotIn("tvos_deployment_target", project.lower())

    def test_producer_freezer_and_manifest_require_exact_pair(self) -> None:
        producer = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        freezer = (ROOT / "tools/freeze_apple_release_candidates.py").read_text(
            encoding="utf-8"
        )
        for marker in ("IOS_ARTIFACT=", "MACOS_ARTIFACT=", "finish_receipt ios", "finish_receipt macos"):
            self.assertIn(marker, producer)
        for marker in ("DEFAULT_IOS", "DEFAULT_MACOS", 'artifact_entry(\n            "ios"', 'artifact_entry(\n            "macos"'):
            self.assertIn(marker, freezer)
        self.assertNotIn("TVOS", producer.upper())
        self.assertNotIn("TVOS", freezer.upper())

        manifest = strict_json(
            ROOT / "app_store/apple/artifacts/release_candidate.json"
        )
        self.assertEqual(
            {entry["platform"] for entry in manifest["artifacts"]}, {"ios", "macos"}
        )

    def test_freeze_cross_store_and_dashboard_denominators_align(self) -> None:
        self.assertEqual(
            set(freeze.CANONICAL_FREEZE_PLATFORMS),
            {"android", "wear_os", "ios", "macos", "windows", "linux", "extension"},
        )
        apple_targets = {
            target.target_id
            for target in cross_store.REQUIRED_UPLOAD_TARGETS
            if target.platform in {"ios", "macos"}
        }
        self.assertEqual(
            apple_targets,
            CURRENT_APPLE_UPLOAD_TARGETS,
        )
        optional_apple_targets = {
            target.target_id
            for target in cross_store.OPTIONAL_UPLOAD_TARGETS
            if target.platform in {"ios", "macos"}
        }
        self.assertEqual(
            optional_apple_targets,
            OPTIONAL_APPLE_UPLOAD_TARGETS,
        )
        self.assertFalse(
            cross_store.REQUIRED_TARGET_IDS & cross_store.OPTIONAL_TARGET_IDS
        )
        ios_target = next(
            target
            for target in cross_store.REQUIRED_UPLOAD_TARGETS
            if target.target_id == "ios-app-store-ipa"
        )
        self.assertIn("watch", ios_target.store_surface)

        config = strict_json(ROOT / "dashboard/state.json")
        configured = {
            target["id"]: tuple(target["upload_targets"])
            for target in config["targets"]
        }
        configured_optional = {
            target["id"]: tuple(target["optional_upload_targets"])
            for target in config["targets"]
        }
        self.assertEqual(
            config["cross_store"]["required_upload_targets"],
            [target.target_id for target in cross_store.REQUIRED_UPLOAD_TARGETS],
        )
        self.assertEqual(
            config["cross_store"]["optional_upload_targets"],
            [target.target_id for target in cross_store.OPTIONAL_UPLOAD_TARGETS],
        )
        self.assertEqual(configured["ios"], ("ios-app-store-ipa",))
        self.assertEqual(configured["apple-watch-watchos"], ("ios-app-store-ipa",))
        self.assertEqual(configured["macos-x86"], ("macos-app-store-pkg",))
        self.assertEqual(configured["macos-arm64"], ("macos-app-store-pkg",))
        self.assertEqual(
            configured_optional["macos-x86"],
            ("macos-developer-id-app",),
        )
        self.assertEqual(
            configured_optional["macos-arm64"],
            ("macos-developer-id-app",),
        )
        self.assertFalse(any("tv" in target_id.lower() for target_id in configured if target_id != "android"))

    def test_release_map_and_apple_validators_align(self) -> None:
        identity = strict_json(
            ROOT / "docs/rulings/RELEASE_IDENTITY_MAP_20260824.json"
        )
        self.assertEqual(identity["canonical_release"], RELEASE)
        apple = identity["platform_mappings"]["apple"]
        self.assertEqual(set(apple["required_artifacts"]), REQUIRED_ARTIFACTS)
        self.assertEqual(set(apple["shipping_surfaces"]), SHIPPING_SURFACES)
        self.assertEqual(apple["optional_distribution"], ["macos_developer_id"])
        self.assertEqual(
            set(apple["required_upload_targets"]),
            CURRENT_APPLE_UPLOAD_TARGETS,
        )
        self.assertEqual(
            set(apple["optional_evidence_targets"]),
            OPTIONAL_APPLE_UPLOAD_TARGETS,
        )

        self.assertEqual(uploader.selected_platforms("both"), ["ios", "macos"])
        with mock.patch.object(sys, "argv", ["apple_upload_exact_release_candidates.py"]):
            self.assertEqual(uploader.parse_args().platform, "both")
        self.assertEqual(owner_signoff.FINAL_APPROVED_SCOPE, ["ios", "macos", "watchos"])
        self.assertEqual(set(submission.CURRENT_RELEASE_CANDIDATE_BUNDLE_IDS), {"ios", "macos"})
        for path in (
            "tools/release_dependency_freeze.py",
            "tools/apple_upload_exact_release_candidates.py",
            "tools/validate_apple_submission_package.py",
            "tools/validate_apple_owner_signoff.py",
        ):
            self.assertNotIn("tvos", (ROOT / path).read_text(encoding="utf-8").lower(), path)

        reviewed = listing.review_current_apple_store_metadata()
        self.assertFalse(reviewed["tvos_shipping_surface"])
        self.assertFalse(reviewed["tv_scope"]["shipping_surface"])
        self.assertFalse(reviewed["tv_scope"]["upload_target"])
        self.assertEqual(
            reviewed["tv_scope"]["receipt_status"],
            "refused_not_a_current_target",
        )
        self.assertTrue(reviewed["watchos_embedded_in_ios_ipa"])
        self.assertEqual(
            reviewed["required_surfaces"],
            ["ios", "embedded_watchos_companion", "macos"],
        )


class AppleIpaExportNameTests(unittest.TestCase):
    def test_every_release_tool_names_the_wins_vpn_ipa(self) -> None:
        # The iOS host ships as "Win's VPN" (owner ruling 2026-10-25; it was Calculator from
        # 2026-10-16 until App Store Connect refused that name with ITMS-90129), and the App Store
        # export names the IPA after the bundle name, so it writes Win's VPN.ipa; the runtime
        # smoke finds it by glob, so the
        # producer, the freeze helper and the submission validator must name the same file.
        expected = "build/apple/exports/ios-app-store-local/Win's VPN.ipa"
        for relative, count in (
            ("tools/build_apple_release_candidates.sh", 2),
            ("tools/freeze_apple_release_candidates.py", 2),
            ("tools/validate_apple_submission_package.py", 1),
        ):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertEqual(text.count(expected), count, relative)
            self.assertNotIn("ios-app-store-local/Calculator.ipa", text, relative)


if __name__ == "__main__":
    unittest.main()
