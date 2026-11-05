#!/usr/bin/env python3
"""Hostile tests for the final local website public-download gate."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "verify_website_public_download_gate.py"
SPEC = importlib.util.spec_from_file_location(
    "verify_website_public_download_gate", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


def fake_custody(status: str) -> SimpleNamespace:
    if status == GATE.PENDING_STATUS:
        return SimpleNamespace(
            ok=False,
            status=status,
            summary="PENDING owner-signed artifacts are absent",
            findings=("owner-signed artifacts are absent",),
        )
    if status == GATE.AVAILABLE_STATUS:
        return SimpleNamespace(
            ok=True,
            status=status,
            summary="PASS exact artifacts",
            findings=(),
        )
    return SimpleNamespace(
        ok=False,
        status="failed",
        summary="FAIL exact artifact substitution",
        findings=("exact artifact substitution",),
    )


class VerifyWebsitePublicDownloadGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in (
            Path("web/index.html"),
            Path("web/_worker.js"),
            Path("web/_redirects"),
            Path("web/.assetsignore"),
            Path("web/releases/downloads.json"),
            Path("netlify/functions/wins-ai-chat.js"),
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

    def evaluate(self, custody_status: str = GATE.PENDING_STATUS) -> GATE.GateReport:
        report = fake_custody(custody_status)
        return GATE.evaluate_tree(
            self.root, custody_evaluator=lambda _root: report
        )

    def mutate(self, relative: str, old: str, new: str) -> None:
        path = self.root / relative
        source = path.read_text(encoding="utf-8")
        self.assertIn(old, source)
        path.write_text(source.replace(old, new, 1), encoding="utf-8")

    def test_safe_pending_is_owner_blocked_not_ready(self) -> None:
        report = self.evaluate()
        self.assertEqual(report.status, GATE.STATUS_BLOCKED, report.summary)
        self.assertEqual(report.exit_code, GATE.EXIT_BLOCKED)
        self.assertTrue(report.owner_actions)
        self.assertFalse(report.findings)
        self.assertNotIn("PASS", GATE.render_report(report).splitlines()[0])

    def test_current_repository_is_blocked_with_exit_78(self) -> None:
        report = GATE.evaluate_repository()
        self.assertEqual(report.status, GATE.STATUS_BLOCKED, report.summary)
        self.assertEqual(report.exit_code, 78)

    def test_hardcoded_platform_availability_fails(self) -> None:
        self.mutate(
            "netlify/functions/wins-ai-chat.js",
            "The Download menu is the release authority for every platform.",
            "Windows and Android downloads are available from winsvpn.org.",
        )
        report = self.evaluate()
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        rendered = "\n".join(report.findings)
        self.assertIn("android download availability", rendered)
        self.assertIn("windows download availability", rendered)

    def test_hardcoded_platform_origin_claim_fails(self) -> None:
        self.mutate(
            "netlify/functions/wins-ai-chat.js",
            "The Download menu is the release authority for every platform.",
            "Windows and Android are available from winsvpn.org.",
        )
        report = self.evaluate()
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        rendered = "\n".join(report.findings)
        self.assertIn("android download availability", rendered)
        self.assertIn("windows download availability", rendered)

    def test_pending_store_anchor_fails(self) -> None:
        self.mutate(
            "web/index.html",
            "</body>",
            '<a href="https://apps.apple.com/app/id1234567890">iOS App Store</a></body>',
        )
        report = self.evaluate()
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertTrue(
            any("not exactly bound by the manifest" in item for item in report.findings)
        )

    def test_github_download_placeholder_in_public_function_fails(self) -> None:
        path = self.root / "netlify/functions/wins-ai-chat.js"
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\nconst oldDownload = "
            + '"https://github.com/winsvpn/winsvpn-downloads/releases/download/'
            + 'v1.0.0/wins-vpn-android.apk";\n',
            encoding="utf-8",
        )
        report = self.evaluate()
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertTrue(any("GitHub" in item or "obsolete" in item for item in report.findings))

    def test_manifest_unbound_binary_fails_even_if_custody_is_stubbed(self) -> None:
        downloads = self.root / "web/downloads"
        downloads.mkdir()
        (downloads / "wins-vpn-android-debug.apk").write_bytes(b"debug")
        report = self.evaluate()
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertTrue(any("manifest-unbound" in item for item in report.findings))

    def test_worker_redirect_or_pending_route_enablement_fails(self) -> None:
        self.mutate(
            "web/_worker.js",
            "const downloadRedirects = new Map();",
            "const downloadRedirects = new Map([[\"/downloads/app.apk\", \"https://evil.example/app.apk\"]]);",
        )
        report = self.evaluate()
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertTrue(any("redirect map is not exactly empty" in item for item in report.findings))

    def test_source_failure_does_not_consume_custody_evidence(self) -> None:
        self.mutate(
            "web/_worker.js",
            "const downloadRedirects = new Map();",
            "const downloadRedirects = new Map([[\"/downloads/app.apk\", \"https://evil.example/app.apk\"]]);",
        )
        calls = 0

        def evaluator(_root: Path) -> SimpleNamespace:
            nonlocal calls
            calls += 1
            return fake_custody(GATE.AVAILABLE_STATUS)

        report = GATE.evaluate_tree(self.root, custody_evaluator=evaluator)
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertEqual(calls, 0)

    def test_mutable_release_and_debug_identity_fail(self) -> None:
        manifest_path = self.root / "web/releases/downloads.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["release_id"] = "v1.0.0"
        payload["artifacts"][1]["artifact"]["sha256"] = (
            "89e8ba316dd2a041bde8d019fd407aebf6250a1840a73c98f053e0b6b4621d0f"
        )
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        report = self.evaluate()
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        rendered = "\n".join(report.findings)
        self.assertIn("release_id", rendered)
        self.assertIn("debug APK digest", rendered)

    def test_failed_custody_cannot_be_downgraded_to_blocked(self) -> None:
        report = self.evaluate("failed")
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertEqual(report.exit_code, GATE.EXIT_FAILED)
        self.assertIn("substitution", report.summary)

    def test_available_custody_cannot_override_pending_manifest(self) -> None:
        report = self.evaluate(GATE.AVAILABLE_STATUS)
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertTrue(any("makes no entry available" in item for item in report.findings))

    def _audit(self):
        return GATE._load_sibling("website_security_audit")

    def _publish_entry(self, index: int, entry_id: str, label: str, artifact: dict) -> None:
        manifest_path = self.root / "web/releases/downloads.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["artifacts"][index] = {
            "id": entry_id,
            "label": label,
            "status": GATE.AVAILABLE_STATUS,
            "delivery": {
                "kind": "direct",
                "url": f"https://winsvpn.org/downloads/{artifact['filename']}",
            },
            "artifact": artifact,
        }
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        assetsignore = self.root / "web/.assetsignore"
        assetsignore.write_text(
            "\n".join(
                line
                for line in assetsignore.read_text(encoding="utf-8").splitlines()
                if line.strip() != "downloads/"
            )
            + "\n",
            encoding="utf-8",
        )

    def _linux_artifact(self) -> dict:
        audit = self._audit()
        return audit._selftest_available_artifact(
            "linux-x64",
            "wins-vpn-linux-x64.tar.gz",
            "a" * 64,
            1000,
            ["x64"],
            signer_sha256="c" * 64,
            privacy_sha256="d" * 64,
            release_sha256="e" * 64,
            winn_sha256="f" * 64,
        )

    def test_per_platform_launch_is_ready_with_other_entries_pending(self) -> None:
        self._publish_entry(3, "linux-x64", "Linux x64", self._linux_artifact())
        report = self.evaluate(GATE.AVAILABLE_STATUS)
        self.assertEqual(report.status, GATE.STATUS_READY, report.summary)
        self.assertEqual(report.exit_code, 0)
        self.assertIn("available linux-x64", report.summary)
        self.assertIn("macos=store_pending", report.summary)
        self.assertIn("android=verification_pending", report.summary)

    def test_unsigned_windows_without_visible_label_fails(self) -> None:
        audit = self._audit()
        filename = "WinsVPN-UNSIGNED-LOCAL-Setup.exe"
        artifact = audit._selftest_available_artifact(
            "windows-x64",
            filename,
            "a" * 64,
            1000,
            ["x64"],
            signer_sha256="9" * 64,
            privacy_sha256="d" * 64,
            release_sha256="e" * 64,
            winn_sha256="f" * 64,
        )
        artifact["signature"] = {"kind": "unsigned_owner_waiver", "sha256": "9" * 64}
        artifact["unsigned_waiver"] = {
            "label": "Unsigned",
            "waiver_filename": "download-unsigned-waiver.json",
            "waiver_sha256": "9" * 64,
        }
        self._publish_entry(0, "windows-x64", "Windows x64", artifact)
        self.assertEqual(self.evaluate(GATE.AVAILABLE_STATUS).status, GATE.STATUS_READY)
        artifact["unsigned_waiver"]["label"] = ""
        self._publish_entry(0, "windows-x64", "Windows x64", artifact)
        report = self.evaluate(GATE.AVAILABLE_STATUS)
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertTrue(any("labelled Unsigned" in item for item in report.findings), report.findings)

    def test_pinned_github_release_entry_is_ready(self) -> None:
        artifact = self._linux_artifact()
        self._publish_entry(3, "linux-x64", "Linux x64", artifact)
        manifest_path = self.root / "web/releases/downloads.json"
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["artifacts"][3]["delivery"] = {
            "kind": "github_release",
            "url": "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/wins-vpn-linux-x64.tar.gz",
        }
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        report = self.evaluate(GATE.AVAILABLE_STATUS)
        self.assertEqual(report.status, GATE.STATUS_READY, report.summary)
        payload["artifacts"][3]["delivery"]["url"] = (
            "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/wins-vpn-linux-x64.tar.gz"
        )
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        report = self.evaluate(GATE.AVAILABLE_STATUS)
        self.assertEqual(report.status, GATE.STATUS_FAILED)

    def test_available_android_fails_the_full_gate(self) -> None:
        audit = self._audit()
        artifact = audit._selftest_available_artifact(
            "android", "wins-vpn-android.apk", "a" * 64, 1000,
            sorted(audit.PLATFORM_ARCHITECTURES["android"]),
            signer_sha256=audit.ANDROID_PUBLIC_SIGNER_SHA256,
            privacy_sha256="d" * 64, release_sha256="e" * 64, winn_sha256="f" * 64,
        )
        self._publish_entry(2, "android", "Android", artifact)
        report = self.evaluate(GATE.AVAILABLE_STATUS)
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertTrue(
            any("outside the owner-authorized 1.0.16+33 desktop launch" in item for item in report.findings),
            report.findings,
        )

    def test_worker_with_any_other_github_release_url_fails(self) -> None:
        self.mutate(
            "web/_worker.js",
            "const downloadRedirects = new Map();",
            'const downloadRedirects = new Map();\nconst stale = "https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.0/x.exe";',
        )
        report = self.evaluate()
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertTrue(any("GitHub publication placeholder" in item for item in report.findings), report.findings)

    def test_worker_without_r2_stream_verifier_fails(self) -> None:
        self.mutate(
            "web/_worker.js",
            "env ? env.DOWNLOADS_BUCKET : undefined",
            "env ? env.PUBLIC_BUCKET : undefined",
        )
        report = self.evaluate()
        self.assertEqual(report.status, GATE.STATUS_FAILED)
        self.assertTrue(any("_worker.js" in item for item in report.findings), report.findings)

    def test_source_and_test_are_ascii(self) -> None:
        MODULE_PATH.read_bytes().decode("ascii")
        Path(__file__).read_bytes().decode("ascii")


if __name__ == "__main__":
    unittest.main()
