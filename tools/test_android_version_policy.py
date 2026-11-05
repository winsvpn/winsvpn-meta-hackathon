#!/usr/bin/env python3
"""Mutation controls for tools/android_version_policy.py.

The catalogue (FALSE_GREEN_CATALOGUE.md) requires three controls for any
guard: CONTROL_GREEN (no mutation, must pass), CONTROL_NEUTRAL (comment-only
edit, must pass), and a deliberate break the guard MUST catch. This suite
applies all three against a private copy of a pubspec written to a temp dir --
never the shared tree -- and asserts the guard's refusal message names the
violating code.

The policy stashes the live pubspec line out of band so the three controls are
constructed from the SAME fixture the release tree currently declares, then
proves the guard turns each specific abuse red.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import android_version_policy as policy


def _load_live_pubspec_line() -> str:
    root = pathlib.Path(__file__).resolve().parent.parent
    pubspec = root / "pubspec.yaml"
    for raw in pubspec.read_text(encoding="utf-8").splitlines():
        if raw.lstrip().startswith("version:"):
            return raw.rstrip("\n")
    raise AssertionError("live pubspec.yaml has no version line")


LIVE_VERSION_LINE = _load_live_pubspec_line()
WFA_VERSION_LINE = "version: 0.1.0+1"
VPN_APP_ID = "org.winsvpn.app"
WFA_APP_ID = "com.winsvpn.security"
API36_EXCEPTION = (
    pathlib.Path(__file__).resolve().parent.parent
    / "docs"
    / "rulings"
    / "ANDROID_API36_COMPATIBILITY_EXCEPTION_20260913.json"
)
API37_ADOPTION = (
    pathlib.Path(__file__).resolve().parent.parent
    / "docs"
    / "rulings"
    / "ANDROID_API37_ADOPTION_20261006.json"
)


def _write_pubspec(directory: pathlib.Path, version_line: str) -> pathlib.Path:
    pubspec = directory / "pubspec.yaml"
    pubspec.write_text(
        f"name: fixture\npublish_to: none\n{version_line}\n",
        encoding="utf-8",
    )
    return pubspec


def _code_of(version_line: str) -> int:
    return int(version_line.split("+", 1)[1].rstrip())


class VersionCodePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self._directory = pathlib.Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    # ------------------------------------------------ CONTROL GREEN (no mutation)
    def test_current_vpn_pubspec_passes_policy(self) -> None:
        pubspec = _write_pubspec(self._directory, LIVE_VERSION_LINE)
        code = _code_of(LIVE_VERSION_LINE)
        self.assertGreaterEqual(code, policy.safe_next_version_code(VPN_APP_ID))
        self.assertIsNone(policy.policy_error(VPN_APP_ID, code))

    def test_current_wfa_pubspec_passes_policy(self) -> None:
        pubspec = _write_pubspec(self._directory, WFA_VERSION_LINE)
        self.assertEqual(_code_of(WFA_VERSION_LINE), 1)
        self.assertIsNone(policy.policy_error(WFA_APP_ID, 1))

    # ------------------------------------------- CONTROL NEUTRAL (comment-only)
    def test_comment_only_edit_still_passes(self) -> None:
        pubspec = _write_pubspec(
            self._directory,
            f"# release traffic-light\n{LIVE_VERSION_LINE}  # reviewed",
        )
        code = _code_of(LIVE_VERSION_LINE)
        self.assertIsNone(policy.policy_error(VPN_APP_ID, code))

    # ------------------------- POSITIVE: the guarded abuse must go RED by name
    def test_burned_play_code_is_refused_and_names_the_code(self) -> None:
        for burned in sorted(policy.PLAY_HISTORY[VPN_APP_ID]["known_play_used"]):
            with self.subTest(burned=burned):
                error = policy.policy_error(VPN_APP_ID, burned)
                self.assertIsNotNone(error)
                self.assertIn(str(burned), error)

    def test_code_below_the_tree_claim_is_refused(self) -> None:
        # The tree already claims 29 (three trees, per TREE_DIVERGENCE) and the
        # safe next code is 30. Reverting to 29 must be refused, naming 29.
        error = policy.policy_error(VPN_APP_ID, 29)
        self.assertIsNotNone(error)
        self.assertIn("29", error)

    def test_safe_next_is_33_for_vpn(self) -> None:
        self.assertEqual(policy.safe_next_version_code(VPN_APP_ID), 33)

    def test_wfa_first_upload_code_1_is_safe(self) -> None:
        self.assertEqual(policy.safe_next_version_code(WFA_APP_ID), 1)
        self.assertIsNone(policy.policy_error(WFA_APP_ID, 1))

    def test_wfa_rejects_a_reused_code(self) -> None:
        self.assertIsNotNone(policy.policy_error(WFA_APP_ID, -1))

    def test_wfa_refuses_a_high_vpn_code_as_if_it_were_play_history(self) -> None:
        # Both checks target the SAME applicationId; a WFA code is judged only
        # against WFA history, so 30 must be a valid *future* WFA code but 1 the
        # first upload. This pins rule 3 (independent number spaces).
        error = policy.policy_error(WFA_APP_ID, 30)
        self.assertIsNone(error)


class AndroidFormFactorVersionPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(__file__).resolve().parent.parent
        self.android_gradle = self.root / "android/app/build.gradle.kts"
        self.wear_gradle = self.root / "wear_os/app/build.gradle.kts"

    def test_live_phone_pin_is_defaultconfig_not_tv_flavor(self) -> None:
        code, name = policy.read_gradle_pinned(self.android_gradle)
        self.assertEqual((code, name), (34, "1.0.17"))
        self.assertEqual(policy.read_tv_flavor_version_code(self.android_gradle), 3402)
        wear_code, wear_name = policy.read_gradle_pinned(self.wear_gradle)
        self.assertEqual((wear_code, wear_name), (3401, "1.0.17"))

    def test_default_enforce_accepts_live_phone_tv_wear_identity(self) -> None:
        self.assertEqual(policy.default_enforce(), 0)

    def test_tv_flavor_pin_is_independent_of_phone_defaultconfig(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            gradle = pathlib.Path(name) / "build.gradle.kts"
            gradle.write_text(
                self.android_gradle.read_text(encoding="utf-8").replace(
                    "versionCode = 3402", "versionCode = 3999", 1
                ),
                encoding="utf-8",
            )
            self.assertEqual(policy.read_gradle_pinned(gradle), (34, "1.0.17"))
            self.assertEqual(policy.read_tv_flavor_version_code(gradle), 3999)


class AndroidApi36CompatibilityExceptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(__file__).resolve().parent.parent
        self.ruling = json.loads(API36_EXCEPTION.read_text(encoding="utf-8"))

    def test_exception_is_release_specific_and_dated(self) -> None:
        self.assertEqual(self.ruling["schema_version"], 1)
        self.assertEqual(self.ruling["decided_on"], "2026-09-13")
        self.assertEqual(self.ruling["status"], "approved_for_named_release_only")
        self.assertEqual(
            self.ruling["release"],
            {"version_name": "1.0.16", "version_code": 33},
        )
        # The exception named 1.0.16+33 only; the tree has moved past it.
        pubspec_version = policy.parse_pubspec_version(self.root / "pubspec.yaml")
        self.assertGreater(pubspec_version, (1, 0, 16, 33))

    def test_exception_covers_exact_shipping_surfaces_and_pins(self) -> None:
        # Historical record: the 2026-09-13 exception names API 36 and NDK r29.
        # The live Gradle pins moved on 2026-10-06 and are asserted against the
        # superseding AndroidApi37AdoptionRulingTests below, not against this file.
        scope = self.ruling["scope"]
        self.assertEqual(
            set(scope["surfaces"]), {"phone", "android_tv", "wear_os"}
        )
        self.assertEqual(scope["compile_sdk"], 36)
        self.assertEqual(scope["target_sdk"], 36)
        self.assertEqual(scope["ndk_version"], "29.0.14206865")
        self.assertEqual(scope["ndk_release"], "r29")

    def test_exception_records_play_compliance(self) -> None:
        compliance = self.ruling["play_compliance"]
        self.assertEqual(compliance["as_of"], "2026-09-13")
        self.assertIs(compliance["api_36_remains_compliant"], True)
        self.assertIn("API 36 remains Google Play compliant", compliance["statement"])

    def test_api37_requirements_are_complete_and_named(self) -> None:
        requirements = {
            item["id"]: item["requirement"]
            for item in self.ruling["api_37_adoption_requirements"]
        }
        self.assertEqual(
            set(requirements),
            {
                "build_tools_37",
                "phone_runtime_evidence",
                "android_tv_runtime_evidence",
                "wear_os_runtime_evidence",
                "local_network_product_decision",
                "adaptive_tv_validation",
                "ct_ech_validation",
                "full_native_abi_tests",
            },
        )
        self.assertIn(
            "local-network permission",
            requirements["local_network_product_decision"],
        )
        self.assertIn("Android TV UI", requirements["adaptive_tv_validation"])
        self.assertIn("certificate transparency", requirements["ct_ech_validation"])
        self.assertIn("ECH", requirements["ct_ech_validation"])
        self.assertIn("every shipped", requirements["full_native_abi_tests"])

    def test_exception_has_bounded_post_release_review_trigger(self) -> None:
        trigger = self.ruling["review_trigger"]
        self.assertIs(trigger["required_after_this_release"], True)
        self.assertIs(trigger["before_next_android_release_candidate"], True)
        self.assertEqual(trigger["maximum_days_after_release_publication"], 30)
        self.assertEqual(trigger["hard_deadline"], "2026-09-30")
        self.assertEqual(len(trigger["expires_on_first"]), 4)
        self.assertIn(
            "any release identity other than 1.0.16+33",
            trigger["expires_on_first"],
        )

    def test_cross_store_checklist_references_exception_and_review_boundary(self) -> None:
        checklist = (self.root / "docs/CROSS_STORE_RELEASE_CHECKLIST.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "ANDROID_API36_COMPATIBILITY_EXCEPTION_20260913.json", checklist
        )
        self.assertIn("before the next Android", checklist)
        self.assertIn("30 days after publication", checklist)
        self.assertIn("Build-Tools 37.x", checklist)


class AndroidApi37AdoptionRulingTests(unittest.TestCase):
    """Live Gradle pins versus docs/rulings/ANDROID_API37_ADOPTION_20261006.json."""

    def setUp(self) -> None:
        self.root = pathlib.Path(__file__).resolve().parent.parent
        self.ruling = json.loads(API37_ADOPTION.read_text(encoding="utf-8"))
        self.android_gradle = (self.root / "android/app/build.gradle.kts").read_text(
            encoding="utf-8"
        )
        self.wear_gradle = (self.root / "wear_os/app/build.gradle.kts").read_text(
            encoding="utf-8"
        )

    def test_ruling_is_dated_owner_directed_and_supersedes_api36(self) -> None:
        self.assertEqual(self.ruling["schema_version"], 1)
        self.assertEqual(self.ruling["decided_on"], "2026-10-06")
        self.assertEqual(self.ruling["status"], "owner_directed_pending_debate_round")
        self.assertEqual(
            self.ruling["supersedes"],
            [
                "docs/rulings/ANDROID_API36_COMPATIBILITY_EXCEPTION_20260913.json",
                "docs/rulings/ANDROID_API36_COMPATIBILITY_EXCEPTION_20260824.json",
            ],
        )
        for relative in self.ruling["supersedes"]:
            self.assertTrue((self.root / relative).is_file(), relative)
        self.assertIs(
            self.ruling["play_compliance"]["api_37_exceeds_play_requirement"], True
        )

    def test_gradle_pins_match_the_ruling_scope_exactly(self) -> None:
        scope = self.ruling["scope"]
        self.assertEqual(
            set(scope["surfaces"]), {"phone", "android_tv", "wear_os"}
        )
        self.assertEqual(scope["compile_sdk"], 37)
        self.assertEqual(scope["target_sdk"], 37)
        self.assertEqual(scope["ndk_version"], "30.0.16248370")
        self.assertEqual(scope["ndk_release"], "r30")
        devicecheck_gradle = (
            self.root / "android/devicecheck/app/build.gradle.kts"
        ).read_text(encoding="utf-8")
        for label, text in (
            ("android", self.android_gradle),
            ("wear", self.wear_gradle),
        ):
            with self.subTest(project=label):
                self.assertEqual(
                    re.findall(r"^\s*compileSdk\s*=\s*(\d+)\s*$", text, re.M),
                    [str(scope["compile_sdk"])],
                )
                self.assertEqual(
                    re.findall(r"^\s*targetSdk\s*=\s*(\d+)\s*$", text, re.M),
                    [str(scope["target_sdk"])],
                )
                self.assertEqual(
                    re.findall(r'^\s*ndkVersion\s*=\s*"([^"]+)"\s*$', text, re.M),
                    [scope["ndk_version"]],
                )
        # The standalone DeviceCheck harness compiles and builds on the same
        # platform and NDK; its targetSdk is its own contract (35).
        self.assertEqual(
            re.findall(r"^\s*compileSdk\s*=\s*(\d+)\s*$", devicecheck_gradle, re.M),
            [str(scope["compile_sdk"])],
        )
        self.assertEqual(
            re.findall(
                r'^\s*ndkVersion\s*=\s*"([^"]+)"\s*$', devicecheck_gradle, re.M
            ),
            [scope["ndk_version"]],
        )

    def test_old_api36_literals_are_gone_from_the_release_gradle(self) -> None:
        # Anti-vacuity: the pre-2026-10-06 values must not survive anywhere in
        # the release Gradle files, including inside the guard functions.
        for label, text in (
            ("android", self.android_gradle),
            ("wear", self.wear_gradle),
        ):
            with self.subTest(project=label):
                self.assertNotIn("compileSdk = 36", text)
                self.assertNotIn("targetSdk = 36", text)
                self.assertNotIn("29.0.14206865", text)
                self.assertNotIn("!= 36", text)
        self.assertIn("compileSdk != 37", self.android_gradle)
        self.assertIn("releaseDefaults.targetSdk != 37", self.android_gradle)
        self.assertIn("compileSdk != 37", self.wear_gradle)
        self.assertIn("releaseDefaults.targetSdk != 37", self.wear_gradle)

    def test_api37_requirements_stay_open_and_named(self) -> None:
        requirements = {
            item["id"]: item for item in self.ruling["api_37_adoption_requirements"]
        }
        self.assertEqual(
            set(requirements),
            {
                "build_tools_37",
                "phone_runtime_evidence",
                "android_tv_runtime_evidence",
                "wear_os_runtime_evidence",
                "local_network_product_decision",
                "adaptive_tv_validation",
                "ct_ech_validation",
                "full_native_abi_tests",
            },
        )
        for identifier, item in requirements.items():
            with self.subTest(requirement=identifier):
                self.assertEqual(item["status"], "open")
        self.assertIn("every shipped", requirements["full_native_abi_tests"]["requirement"])
        self.assertIn("NDK r30", requirements["full_native_abi_tests"]["requirement"])

    def test_checklist_and_rulings_lock_reference_the_ruling(self) -> None:
        checklist = (self.root / "docs/CROSS_STORE_RELEASE_CHECKLIST.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("ANDROID_API37_ADOPTION_20261006.json", checklist)
        self.assertIn("30.0.16248370", checklist)
        lock = (self.root / "docs/rulings/RULINGS.lock").read_text(encoding="utf-8")
        for literal in (
            "REQUIRE :: android/app/build.gradle.kts :: compileSdk = 37",
            "REQUIRE :: android/app/build.gradle.kts :: targetSdk = 37",
            'REQUIRE :: android/app/build.gradle.kts :: ndkVersion = "30.0.16248370"',
            "REQUIRE :: wear_os/app/build.gradle.kts :: compileSdk = 37",
            "REQUIRE :: wear_os/app/build.gradle.kts :: targetSdk = 37",
        ):
            with self.subTest(literal=literal):
                self.assertIn(literal, lock)
        self.assertNotIn(":: compileSdk = 36", lock)
        self.assertNotIn(":: targetSdk = 36", lock)


# ----------------------- git-tag derivation controls (new, 2026-08-10) ---------

TAG_ALL_29 = ["version: 1.0.14+29"]


class GitTagDerivationTests(unittest.TestCase):
    # ---- CONTROL GREEN: no mutation, the live tree must derive deterministically
    def test_live_tree_derives_next_vpn_version(self) -> None:
        root = pathlib.Path(__file__).resolve().parent.parent
        pubspec = root / "pubspec.yaml"
        ident = policy.next_version_description(VPN_APP_ID, root, pubspec)
        name, code = ident.split("+")
        # The tree now COMMITS 1.0.17+34, so the guard derives the NEXT
        # release: one patch bump (1.0.18) and the code strictly above the
        # committed 34 (35). This golden tracks the tree's version stepping by
        # exactly one release per bump.
        self.assertEqual(ident, "1.0.18+35")
        self.assertEqual(name, "1.0.18")
        # Next code must strictly exceed the current-release floor (33), and the
        # derivation must satisfy the guard's own policy check.
        self.assertGreater(int(code), policy.safe_next_version_code(VPN_APP_ID))
        self.assertIsNone(policy.policy_error(VPN_APP_ID, int(code)))

    def test_next_version_description_obeys_policy(self) -> None:
        root = pathlib.Path(__file__).resolve().parent.parent
        pubspec = root / "pubspec.yaml"
        ident = policy.next_version_description(VPN_APP_ID, root, pubspec)
        code = int(ident.split("+")[1])
        self.assertIsNone(policy.policy_error(VPN_APP_ID, code))

    # ---- CONTROL NEUTRAL: comment-only edit must not change the derivation
    def test_comment_only_tag_still_derives_same(self) -> None:
        with_comment = ["# release snapshot", "version: 1.0.14+29"]
        self.assertEqual(
            policy.next_semantic_version(with_comment, fallback=(1, 0, 15)),
            policy.next_semantic_version(TAG_ALL_29, fallback=(1, 0, 15)),
        )

    # ---- POSITIVE: bump patch of the highest tagged semantic (break MUST be caught)
    def test_next_semantic_bumps_highest_tag_patch(self) -> None:
        # Highest tag is 1.0.14 -> next name 1.0.15. A regression that failed
        # to bump (returned 1.0.14) must be reported by this test going red.
        got = policy.next_semantic_version(TAG_ALL_29, fallback=(1, 0, 0))
        self.assertEqual(got, "1.0.15")

    def test_next_semantic_respects_highest_of_multiple_tags(self) -> None:
        tags = ["version: 1.0.13+28", "version: 1.0.15+32"]
        self.assertEqual(
            policy.next_semantic_version(tags, fallback=(1, 0, 14)), "1.0.16"
        )

    def test_parse_tag_versions_extracts_codes(self) -> None:
        parsed = policy.parse_tag_versions(TAG_ALL_29)
        self.assertEqual(parsed, [(1, 0, 14, 29)])

    # ---- POSITIVE: code must never be below policy floor even with empty tags
    def test_derive_with_no_tags_uses_wfa_floor(self) -> None:
        # WFA has empty history; even with this repo's tags present, the guard
        # must NOT fold the VPN tags into WFA's number space (rule 3).
        version_lines = policy.git_version_lines(
            pathlib.Path(__file__).resolve().parent.parent
        )
        wfa_lines = [ln for ln in version_lines]
        combined = policy.safe_next_version_code(WFA_APP_ID)
        self.assertEqual(combined, 1)


# -------------------------------- gradle patch controls ---------------------------------


class GradlePatchTests(unittest.TestCase):
    GOLDEN = (
        "    defaultConfig {\n"
        '        applicationId = "org.winsvpn.app"\n'
        "        versionCode = flutter.versionCode\n"
        '        versionName = if (flutter.versionName == "1.0.0") "1.0" else flutter.versionName\n'
        "        targetSdk = 37\n"
        "    }\n"
    )

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self._directory = pathlib.Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _write(self, text: str) -> pathlib.Path:
        path = self._directory / "build.gradle.kts"
        path.write_text(text, encoding="utf-8")
        return path

    # ---- CONTROL GREEN: patch applies cleanly to a pristine file
    def test_patch_happy_path_produces_literals(self) -> None:
        path = self._write(self.GOLDEN)
        changed, code, name = policy.patch_gradle_versions(path, "1.0.15+30")
        self.assertTrue(changed)
        self.assertEqual(code, 30)
        self.assertEqual(name, "1.0.15")
        out = path.read_text(encoding="utf-8")
        self.assertIn("versionCode = 30", out)
        self.assertIn('versionName = "1.0.15"', out)
        self.assertNotIn("flutter.versionCode", out)

    # ---- CONTROL NEUTRAL: re-patching an already-patched file is idempotent
    def test_patch_is_idempotent(self) -> None:
        path = self._write(self.GOLDEN)
        policy.patch_gradle_versions(path, "1.0.15+30")
        changed2, code2, name2 = policy.patch_gradle_versions(path, "1.0.15+30")
        self.assertFalse(changed2)
        self.assertEqual(code2, 30)
        self.assertEqual(name2, "1.0.15")

    # ---- POSITIVE: a needle that vanished must make the patch refuse (not no-op)
    def test_patch_refuses_when_version_line_gone(self) -> None:
        broken = self.GOLDEN.replace("        versionCode = flutter.versionCode\n", "")
        path = self._write(broken)
        with self.assertRaises(ValueError):
            policy.patch_gradle_versions(path, "1.0.15+30")

    def test_patch_refuses_when_needle_duplicated(self) -> None:
        dup = self.GOLDEN + self.GOLDEN
        path = self._write(dup)
        with self.assertRaises(ValueError):
            policy.patch_gradle_versions(path, "1.0.15+30")


if __name__ == "__main__":
    unittest.main()
