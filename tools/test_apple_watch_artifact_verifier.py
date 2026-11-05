#!/usr/bin/env python3
"""Focused adversarial tests for the produced Watch Mach-O verifier."""

from __future__ import annotations

import pathlib
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import apple_watch_artifact_verifier as subject


class AppleWatchArtifactVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def ipa(
        self,
        *,
        executable: bytes = b"macho",
        companion: str | None = None,
        watch_version: str = "1.0.15",
        watch_build: str = "30",
        parent_version: str = "1.0.15",
        parent_build: str = "30",
        privacy: bytes | None = None,
    ) -> pathlib.Path:
        path = self.root / "WinsVPN.ipa"
        parent = "Payload/Win's VPN.app"
        base = "Payload/Win's VPN.app/Watch/WinsWatch.app"
        info = {
            "CFBundleIdentifier": subject.WATCH_BUNDLE_ID,
            "CFBundleExecutable": subject.WATCH_EXECUTABLE,
            "CFBundleShortVersionString": watch_version,
            "CFBundleVersion": watch_build,
            "WKCompanionAppBundleIdentifier": companion or subject.COMPANION_BUNDLE_ID,
            "WKRunsIndependentlyOfCompanionApp": False,
        }
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(
                f"{parent}/Info.plist",
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": subject.COMPANION_BUNDLE_ID,
                        "CFBundleShortVersionString": parent_version,
                        "CFBundleVersion": parent_build,
                    }
                ),
            )
            archive.writestr(f"{base}/Info.plist", plistlib.dumps(info))
            archive.writestr(
                f"{base}/PrivacyInfo.xcprivacy",
                privacy
                if privacy is not None
                else subject.WATCH_PRIVACY_SOURCE.read_bytes(),
            )
            item = zipfile.ZipInfo(f"{base}/{subject.WATCH_EXECUTABLE}")
            item.external_attr = 0o100755 << 16
            archive.writestr(item, executable)
        return path

    @staticmethod
    def completed(argv: list[str], *, missing: str = "") -> subprocess.CompletedProcess[str]:
        tool = pathlib.Path(argv[0]).name
        if tool == "lipo":
            output = "arm64_32\n"
        elif tool == "nm" and "-u" in argv:
            output = "_OBJC_CLASS_$_WCSession\n"
        elif tool == "nm":
            output = ""
        elif tool == "otool" and "-hv" in argv:
            output = "Mach header\nMH_MAGIC_64 ARM64_32 ALL 0x00 EXECUTE 25 3000 0x0\n"
        elif tool == "otool" and "-L" in argv:
            output = f"WinsWatch:\n\t{subject.WATCHCONNECTIVITY_DYLIB} (compatibility version 1.0.0)\n"
        elif tool == "otool" and "-ov" in argv:
            selectors = subject.REQUIRED_SELECTORS - ({missing} if missing else set())
            output = "\n".join(
                ["WCSessionDelegate"]
                + [f"    0x1000{index:04x} {value}" for index, value in enumerate(sorted(selectors))]
            )
        elif tool == "otool" and "-l" in argv:
            output = "sectname __objc_methname\nsectname __objc_selrefs\n"
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, output, "")

    def test_accepts_structurally_bound_stripped_watch_image(self) -> None:
        path = self.ipa()
        with mock.patch.object(subject, "_run", side_effect=lambda argv: self.completed(argv)):
            result = subject.verify_ipa(path)
        self.assertEqual(result["architectures"], ["arm64_32"])
        self.assertEqual(result["wc_session_import"], "_OBJC_CLASS_$_WCSession")
        self.assertEqual(result["version"], "1.0.15")
        self.assertEqual(result["build_number"], "30")
        self.assertEqual(len(result["ipa_sha256"]), 64)
        self.assertEqual(len(result["privacy_manifest_sha256"]), 64)
        self.assertFalse(result["debug_sections"])

    def test_rejects_wrong_companion_pairing(self) -> None:
        path = self.ipa(companion="org.example.other")
        with self.assertRaisesRegex(subject.WatchArtifactError, "not paired"):
            subject.verify_ipa(path)

    def test_rejects_missing_message_selector(self) -> None:
        path = self.ipa()
        missing = "sendMessage:replyHandler:errorHandler:"
        with mock.patch.object(
            subject, "_run", side_effect=lambda argv: self.completed(argv, missing=missing)
        ):
            with self.assertRaisesRegex(subject.WatchArtifactError, "lacks pairing/message"):
                subject.verify_ipa(path)

    def test_rejects_missing_watchconnectivity_dependency(self) -> None:
        path = self.ipa()

        def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
            result = self.completed(argv)
            if pathlib.Path(argv[0]).name == "otool" and "-L" in argv:
                result.stdout = "WinsWatch:\n\t/System/Library/Frameworks/Foundation.framework/Foundation (compatibility version 1.0.0)\n"
            return result

        with mock.patch.object(subject, "_run", side_effect=run):
            with self.assertRaisesRegex(subject.WatchArtifactError, "does not load"):
                subject.verify_ipa(path)

    def test_rejects_watch_version_or_build_drift_from_parent(self) -> None:
        for kwargs, message in (
            ({"parent_version": "1.0.14"}, "marketing version differs"),
            ({"parent_build": "29"}, "build number differs"),
            ({"watch_version": "release"}, "marketing version is invalid"),
            ({"watch_build": "0"}, "build number is invalid"),
        ):
            with self.subTest(message=message):
                path = self.ipa(**kwargs)
                with self.assertRaisesRegex(subject.WatchArtifactError, message):
                    subject.verify_ipa(path)

    def test_rejects_missing_or_drifted_watch_privacy_manifest(self) -> None:
        missing = self.ipa()
        replacement = self.root / "missing-privacy.ipa"
        with zipfile.ZipFile(missing, "r") as source, zipfile.ZipFile(replacement, "w") as target:
            for item in source.infolist():
                if not item.filename.endswith("/PrivacyInfo.xcprivacy"):
                    target.writestr(item, source.read(item))
        with self.assertRaisesRegex(subject.WatchArtifactError, "privacy manifest is missing"):
            subject.verify_ipa(replacement)

        drifted = self.ipa(privacy=plistlib.dumps({"NSPrivacyTracking": True}))
        with self.assertRaisesRegex(subject.WatchArtifactError, "differs from reviewed source"):
            subject.verify_ipa(drifted)

    def test_rejects_debug_section(self) -> None:
        path = self.ipa()

        def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
            result = self.completed(argv)
            if pathlib.Path(argv[0]).name == "otool" and "-l" in argv:
                result.stdout += "segname __DWARF\n"
            return result

        with mock.patch.object(subject, "_run", side_effect=run):
            with self.assertRaisesRegex(subject.WatchArtifactError, "retains debug"):
                subject.verify_ipa(path)

    def test_rejects_duplicate_watch_app(self) -> None:
        path = self.ipa()
        with zipfile.ZipFile(path, "a") as archive:
            other = "Payload/Win's VPN.app/Watch/Other.app"
            info = {
                "CFBundleIdentifier": subject.WATCH_BUNDLE_ID,
                "CFBundleExecutable": subject.WATCH_EXECUTABLE,
                "WKCompanionAppBundleIdentifier": subject.COMPANION_BUNDLE_ID,
                "WKRunsIndependentlyOfCompanionApp": False,
            }
            archive.writestr(f"{other}/Info.plist", plistlib.dumps(info))
        with self.assertRaisesRegex(subject.WatchArtifactError, "exactly one"):
            subject.verify_ipa(path)


if __name__ == "__main__":
    unittest.main()
