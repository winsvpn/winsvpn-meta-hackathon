#!/usr/bin/env python3
"""Fail-closed consistency checks for cross-store packets and public-web copy."""

from __future__ import annotations

import json
import pathlib
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent
import sys

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
if str(TOOLS.parent) not in sys.path:
    sys.path.insert(0, str(TOOLS.parent))

import apple_store_listing_metadata as apple_listing
import linux_cross_store_artifact_gate as linux_gate
import website_security_audit as website_audit
import windows_cross_store_artifact_gate as windows_gate
from dashboard import server as dashboard_server


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKLIST = ROOT / "docs/CROSS_STORE_RELEASE_CHECKLIST.md"
RULING = ROOT / "docs/rulings/ANDROID_API37_ADOPTION_20261006.json"
WINDOWS_CANDIDATE = ROOT / "app_store/windows/artifacts/release_candidate.json"
LINUX_CANDIDATE = ROOT / "app_store/linux/artifacts/release_candidate.json"
PHONE_CANDIDATE = ROOT / "app_store/android/phone/artifacts/release_candidate.json"
APPLE_README = ROOT / "app_store/apple/README.md"
ACCESSIBILITY = ROOT / "app_store/apple/review/accessibility_evidence.md"
GITIGNORE = ROOT / ".gitignore"
REDIRECTS = ROOT / "web/_redirects"
WORKER = ROOT / "web/_worker.js"
PRIVACY_PAGE = ROOT / "web/privacy/index.html"
DASHBOARD_INDEX = ROOT / "dashboard/index.html"
DASHBOARD_STATIC = ROOT / "dashboard/static/index.html"
DASHBOARD_APP = ROOT / "dashboard/static/app.js"
LINUX_SEARCH = ROOT / "app_store/linux/metadata/en-US/search_terms.txt"


class CrossStorePacketConsistencyTests(unittest.TestCase):
    def test_checklist_ndk_matches_ruled_r30(self) -> None:
        checklist = CHECKLIST.read_text(encoding="ascii")
        ruling = json.loads(RULING.read_text(encoding="ascii"))
        self.assertNotIn("r28c", checklist)
        self.assertNotIn("NDK r29", checklist)
        self.assertNotIn("29.0.14206865", checklist)
        self.assertIn("NDK r30", checklist)
        self.assertIn("30.0.16248370", checklist)
        self.assertEqual(ruling["scope"]["ndk_release"], "r30")
        self.assertEqual(ruling["scope"]["ndk_version"], "30.0.16248370")

    def test_windows_candidate_names_all_required_targets_pending(self) -> None:
        candidate = json.loads(WINDOWS_CANDIDATE.read_text(encoding="ascii"))
        self.assertEqual(
            candidate["required_upload_targets"],
            [
                "windows-x64-installer",
                "windows-x64-partner-center",
                "windows-arm64-installer",
                "windows-arm64-partner-center",
            ],
        )
        self.assertEqual(
            set(candidate["targets"]),
            {"windows-x64-installer", "windows-x64-partner-center"},
        )
        self.assertEqual(candidate["candidate_set_status"], "no_current_candidate")
        self.assertEqual(candidate["arm64_targets_status"], "pending-owner-evidence")
        for record in candidate["targets"].values():
            self.assertFalse(record["produced"])
            self.assertFalse(record["upload_performed"])
            self.assertFalse(record["publication_authorized"])
        for record in candidate["pending_required_targets"].values():
            self.assertFalse(record["produced"])
            self.assertFalse(record["upload_performed"])
            self.assertFalse(record["publication_authorized"])
            self.assertEqual(record["status"], "pending-owner-evidence")
        windows_gate._reviewed_store_metadata("windows-x64-installer")

    def test_linux_candidate_tarball_kind_and_dual_arch_pending(self) -> None:
        candidate = json.loads(LINUX_CANDIDATE.read_text(encoding="ascii"))
        self.assertEqual(
            candidate["required_upload_targets"],
            [
                "linux-x64-package",
                "linux-arm64-package",
                "linux-flathub-manifest",
                "linux-snap-manifest",
            ],
        )
        self.assertEqual(candidate["required_artifact_kinds"]["linux-x64-package"], "tarball")
        self.assertEqual(candidate["required_artifact_kinds"]["linux-arm64-package"], "tarball")
        self.assertNotEqual(candidate["required_artifact_kinds"]["linux-x64-package"], "DEB")
        self.assertEqual(candidate["targets"]["linux-x64-package"]["kind"], "tarball")
        self.assertNotEqual(candidate["targets"]["linux-x64-package"]["kind"], "DEB")
        self.assertEqual(
            candidate["targets"]["linux-flathub-manifest"]["required_architectures"],
            ["x64", "arm64"],
        )
        self.assertEqual(
            candidate["targets"]["linux-snap-manifest"]["required_architectures"],
            ["x64", "arm64"],
        )
        self.assertFalse(candidate["deb"]["upload_target"])
        self.assertEqual(candidate["arm64_targets_status"], "pending-owner-evidence")
        arm64 = candidate["pending_required_targets"]["linux-arm64-package"]
        self.assertEqual(arm64["kind"], "tarball")
        self.assertFalse(arm64["produced"])
        self.assertEqual(arm64["status"], "pending-owner-evidence")
        linux_gate._reviewed_store_metadata("linux-x64-package")

    def test_linux_search_terms_are_privacy_compatible(self) -> None:
        text = LINUX_SEARCH.read_text(encoding="ascii")
        self.assertNotIn("no logs", text)
        self.assertIn("no browsing history", text)

    def test_phone_aab_is_production_upload_and_apk_is_sidecar(self) -> None:
        candidate = json.loads(PHONE_CANDIDATE.read_text(encoding="ascii"))
        readme = (ROOT / "app_store/android/phone/README.md").read_text(encoding="ascii")
        checklist = CHECKLIST.read_text(encoding="ascii")
        self.assertEqual(candidate["production_upload"], "android-phone-tablet-aab")
        self.assertTrue(candidate["apk_sidecar_only"])
        self.assertEqual(candidate["artifact"]["production_upload"], "aab")
        self.assertEqual(candidate["artifact"]["apk_role"], "sidecar-only")
        self.assertFalse(candidate["artifact"]["produced"])
        self.assertIn("production Play upload is the phone/tablet AAB", readme)
        self.assertIn("sidecar-only", readme)
        self.assertIn("phone APK is sidecar-only", checklist)

    def test_privacy_routes_match_worker_dedicated_document(self) -> None:
        redirects = REDIRECTS.read_text(encoding="ascii")
        worker = WORKER.read_text(encoding="utf-8")
        privacy = PRIVACY_PAGE.read_text(encoding="ascii")
        self.assertIn("/privacy /privacy/index.html 200", redirects)
        self.assertIn('["/privacy/", "/privacy/"]', worker)
        self.assertNotIn("/privacy /index.html 200", redirects)
        self.assertNotIn("/privacy/ /index.html 200", redirects)
        self.assertIn("dedicatedDocumentRoutes.get(url.pathname)", worker)
        self.assertIn('<h1 id="privacy-policy">Privacy Policy</h1>', privacy)
        redirect_results = {
            message: status for status, message in website_audit.audit_redirects()
        }
        self.assertEqual(
            redirect_results[
                "canonical /privacy/ route is mapped by the advanced-mode Pages Worker"
            ],
            "PASS",
        )
        self.assertEqual(
            redirect_results["dedicated /privacy/ document is headed Privacy Policy"],
            "PASS",
        )

    def test_apple_readme_does_not_overclaim_privacy_sync_or_build_17(self) -> None:
        readme = APPLE_README.read_text(encoding="ascii")
        evidence = ACCESSIBILITY.read_text(encoding="ascii")
        self.assertNotIn("privacy is synchronized and published", readme)
        self.assertIn("are not claimed", readme)
        self.assertIn("synchronized or published", readme)
        self.assertIn(f"build `{apple_listing.CANONICAL_BUNDLE_VERSION}`", readme)
        self.assertNotIn("build `17`", readme)
        self.assertIn(f"build `{apple_listing.CANONICAL_BUNDLE_VERSION}`", evidence)
        self.assertNotIn("build `17`", evidence)

    def test_gitignore_ignores_xpi(self) -> None:
        text = GITIGNORE.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^\*\.xpi$")

    def test_dashboard_distinguishes_20_engineering_from_16_uploads(self) -> None:
        for path in (DASHBOARD_INDEX, DASHBOARD_STATIC, DASHBOARD_APP):
            text = path.read_text(encoding="ascii")
            self.assertTrue(all(ord(character) < 128 for character in text), path)
        for path in (DASHBOARD_INDEX, DASHBOARD_STATIC):
            html = path.read_text(encoding="ascii")
            self.assertIn("Store-upload coverage (16)", html)
            self.assertIn("Engineering/operator targets (20)", html)
            self.assertIn("0 / 16", html)
            self.assertIn("0 / 20", html)
            self.assertNotIn("0 / 21", html)
            self.assertIn("strict store denominator", html)
            self.assertIn("not a store denominator", html)
        app = DASHBOARD_APP.read_text(encoding="ascii")
        self.assertIn("scoredReq !== 20 || uploadReq !== 16 || operatorCardCount !== 21", app)
        self.assertIn("coverage.store_upload.required_receipts === operatorCardCount", app)
        self.assertEqual(len(dashboard_server.REQUIRED_UPLOAD_TARGET_IDS), 16)
        self.assertEqual(len(dashboard_server.REQUIRED_TARGETS), 20)
        self.assertEqual(len(dashboard_server.OPERATOR_UPLOAD_TARGET_MAP), 21)
        self.assertNotEqual(
            len(dashboard_server.REQUIRED_UPLOAD_TARGET_IDS),
            len(dashboard_server.OPERATOR_UPLOAD_TARGET_MAP),
        )

    def test_owner_blockers_and_fail_closed_upload_state_are_preserved(self) -> None:
        windows_signoff = json.loads(
            (ROOT / "app_store/windows/review/owner_signoff.json").read_text(
                encoding="ascii"
            )
        )
        linux_signoff = json.loads(
            (ROOT / "app_store/linux/review/owner_signoff.json").read_text(
                encoding="ascii"
            )
        )
        phone_signoff = json.loads(
            (ROOT / "app_store/android/phone/review/owner_signoff.json").read_text(
                encoding="ascii"
            )
        )
        self.assertFalse(windows_signoff["submission_approved"])
        self.assertFalse(windows_signoff["upload_authorized"])
        self.assertEqual(
            windows_signoff["blockers"], windows_gate.WINDOWS_OWNER_SIGNOFF_BLOCKERS
        )
        self.assertFalse(linux_signoff["submission_approved"])
        self.assertFalse(linux_signoff["upload_authorized"])
        self.assertEqual(
            linux_signoff["blockers"], linux_gate.LINUX_OWNER_SIGNOFF_BLOCKERS
        )
        self.assertFalse(phone_signoff["submission_approved"])
        self.assertFalse(phone_signoff["upload_authorized"])
        self.assertGreaterEqual(len(windows_signoff["blockers"]), 1)
        self.assertGreaterEqual(len(linux_signoff["blockers"]), 1)


if __name__ == "__main__":
    unittest.main()
