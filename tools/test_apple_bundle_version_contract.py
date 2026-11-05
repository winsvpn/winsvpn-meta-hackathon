#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import plistlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class AppleBundleVersionContractTests(unittest.TestCase):
    def load_plist(self, relative: str) -> dict:
        return plistlib.loads((ROOT / relative).read_bytes())

    def test_every_ios_shipping_bundle_follows_flutter_version_source(self) -> None:
        bundle_plists = (
            "ios/Runner/Info.plist",
            "ios/PacketTunnel/Info.plist",
            "ios/WinsWatch Watch App/Info.plist",
            "macos/Runner/Info.plist",
            "macos/PacketTunnel/Info.plist",
        )
        for relative in bundle_plists:
            with self.subTest(relative=relative):
                plist = self.load_plist(relative)
                self.assertEqual(
                    plist["CFBundleShortVersionString"], "$(FLUTTER_BUILD_NAME)"
                )
                self.assertEqual(plist["CFBundleVersion"], "$(FLUTTER_BUILD_NUMBER)")

        pubspec = (ROOT / "pubspec.yaml").read_text(encoding="utf-8")
        self.assertRegex(pubspec, r"(?m)^version: [0-9]+(?:\.[0-9]+){2}\+[0-9]+\s*$")
        self.assertFalse((ROOT / "ios/Info.plist").exists())

    def test_watch_identity_and_companion_contract(self) -> None:
        watch = self.load_plist("ios/WinsWatch Watch App/Info.plist")
        self.assertEqual(watch["CFBundlePackageType"], "APPL")
        self.assertEqual(watch["CFBundleIdentifier"], "$(PRODUCT_BUNDLE_IDENTIFIER)")
        self.assertEqual(watch["CFBundleDisplayName"], "Win's VPN")
        self.assertEqual(watch["CFBundleName"], "Win's VPN")
        self.assertEqual(
            watch["CFBundleShortVersionString"], "$(FLUTTER_BUILD_NAME)"
        )
        self.assertEqual(watch["CFBundleVersion"], "$(FLUTTER_BUILD_NUMBER)")
        self.assertIs(watch["WKApplication"], True)
        self.assertEqual(
            watch["WKCompanionAppBundleIdentifier"],
            "$(WK_COMPANION_APP_BUNDLE_IDENTIFIER)",
        )
        self.assertIs(watch["WKRunsIndependentlyOfCompanionApp"], False)

    def test_watch_debug_ids_cannot_collide_with_the_shipping_companion(self) -> None:
        project = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text()
        watch_blocks = re.findall(
            r"buildSettings = \{(.*?)INFOPLIST_FILE = "
            r'"WinsWatch Watch App/Info\.plist";(.*?)\n\t\t\t\};',
            project,
            re.DOTALL,
        )
        self.assertEqual(len(watch_blocks), 3)
        debug_blocks = 0
        shipping_blocks = 0
        for before, after in watch_blocks:
            block = before + after
            if "org.winsvpn.app.debug.watchkitapp;" in block:
                debug_blocks += 1
                self.assertIn(
                    "WK_COMPANION_APP_BUNDLE_IDENTIFIER = org.winsvpn.app.debug;",
                    block,
                )
                self.assertNotIn(
                    "PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.watchkitapp;",
                    block,
                )
            else:
                shipping_blocks += 1
                self.assertIn(
                    "PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.watchkitapp;",
                    block,
                )
                self.assertIn(
                    "WK_COMPANION_APP_BUNDLE_IDENTIFIER = org.winsvpn.app;",
                    block,
                )
        self.assertEqual((debug_blocks, shipping_blocks), (1, 2))

    def test_watch_target_configs_use_the_same_flutter_version_variables(self) -> None:
        project = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text()
        blocks = re.findall(
            r"buildSettings = \{(.*?)INFOPLIST_FILE = "
            r'"WinsWatch Watch App/Info\.plist";(.*?)\n\t\t\t\};',
            project,
            re.DOTALL,
        )
        self.assertEqual(len(blocks), 3)
        for before, after in blocks:
            block = before + after
            self.assertIn('CURRENT_PROJECT_VERSION = "$(FLUTTER_BUILD_NUMBER)";', block)
            self.assertIn('MARKETING_VERSION = "$(FLUTTER_BUILD_NAME)";', block)
            self.assertIn("CODE_SIGN_STYLE = Automatic;", block)
            self.assertNotIn("CODE_SIGNING_ALLOWED = NO;", block)
            self.assertNotIn("CODE_SIGNING_REQUIRED = NO;", block)

    def test_watch_graph_is_single_target_and_legacy_extension_is_absent(self) -> None:
        project_root = ROOT / "ios/Runner.xcodeproj"
        project_files = sorted(project_root.glob("project.pbxproj*"))
        project_files.extend(sorted(project_root.rglob("*.xcscheme")))
        legacy_references = (
            "WinsWatchExtension",
            "WinsWatch Extension",
            "WinsWatch Extension.appex",
            "Embed Watch Extensions",
            "watchkitapp.extension",
            "com.apple.product-type.watchkit2-extension",
            "WK_APP_BUNDLE_IDENTIFIER",
        )
        for path in project_files:
            contents = path.read_text(encoding="utf-8")
            for legacy_reference in legacy_references:
                with self.subTest(path=path, reference=legacy_reference):
                    self.assertNotIn(legacy_reference, contents)

        legacy_files = (
            "ios/WinsWatch Extension/ChannelTests.swift",
            "ios/WinsWatch Extension/ExtensionDelegate.swift",
            "ios/WinsWatch Extension/Info.plist",
            "ios/WinsWatch Extension/PrivacyInfo.xcprivacy",
            "ios/WinsWatch Extension/WinsWatchExtension.entitlements",
            "ios/WinsWatch Watch App/WKInterfaceControllerCompliance.swift",
        )
        for relative in legacy_files:
            with self.subTest(relative=relative):
                self.assertFalse((ROOT / relative).exists())

        legacy_directory = ROOT / "ios/WinsWatch Extension"
        if legacy_directory.exists():
            self.assertEqual(list(legacy_directory.rglob("*")), [])

        project = (project_root / "project.pbxproj").read_text(encoding="utf-8")
        self.assertEqual(project.count("name = WinsWatch;"), 1)
        self.assertIn('productType = "com.apple.product-type.application";', project)

        channel_tests = ROOT / "ios/WinsWatchTests/ChannelTests.swift"
        self.assertTrue(channel_tests.is_file())
        self.assertIn("final class ChannelTests: XCTestCase", channel_tests.read_text())
        self.assertIn("path = WinsWatchTests;", project)
        self.assertIn("ChannelTests.swift in Sources", project)

    def test_runner_embeds_signed_watch_content_and_watch_privacy_manifests(self) -> None:
        project = (ROOT / "ios/Runner.xcodeproj/project.pbxproj").read_text()
        runner = project.split(
            "97C146ED1CF9000F007C117D /* Runner */ = {", 1
        )[1].split("\n\t\t};", 1)[0]
        self.assertIn("D6FEB55DC141707CAB0C014B /* Embed Watch Content */", runner)
        self.assertIn("DA622D358992B48FDB79EB94 /* PBXTargetDependency */", runner)
        self.assertRegex(
            project,
            r"WinsWatch\.app in Embed Watch Content \*/ = \{[^\n]+"
            r"ATTRIBUTES = \(CodeSignOnCopy, \)",
        )
        watch_sources = project.split(
            "D2C03EE75E674C56072DA0B3 /* Sources */ = {", 1
        )[1].split("\n\t\t};", 1)[0]
        self.assertNotIn("WinsNativeEngineArtifactLocator.swift", watch_sources)
        self.assertNotIn("WinsNetworkSettingsRelease.swift", watch_sources)
        watch_resources = project.split(
            "8B31866CB285211662F45A40 /* Resources */ = {", 1
        )[1].split("\n\t\t};", 1)[0]
        self.assertIn("PrivacyInfo.xcprivacy in Resources", watch_resources)

        watch_privacy_path = ROOT / "ios/WinsWatch Watch App/PrivacyInfo.xcprivacy"
        self.assertTrue(watch_privacy_path.is_file())
        watch_privacy = self.load_plist(
            "ios/WinsWatch Watch App/PrivacyInfo.xcprivacy"
        )
        self.assertIs(watch_privacy["NSPrivacyTracking"], False)
        self.assertEqual(watch_privacy["NSPrivacyTrackingDomains"], [])
        self.assertEqual(watch_privacy["NSPrivacyAccessedAPITypes"], [])
        self.assertEqual(watch_privacy["NSPrivacyCollectedDataTypes"], [])

        host_manifests = (
            "ios/Runner/PrivacyInfo.xcprivacy",
            "macos/Runner/PrivacyInfo.xcprivacy",
        )
        expected_host_types = {
            "NSPrivacyCollectedDataTypeCoarseLocation",
            "NSPrivacyCollectedDataTypeDeviceID",
            "NSPrivacyCollectedDataTypeUserID",
            "NSPrivacyCollectedDataTypeProductInteraction",
        }
        for relative in host_manifests:
            manifest = self.load_plist(relative)
            collected = {
                item["NSPrivacyCollectedDataType"]
                for item in manifest["NSPrivacyCollectedDataTypes"]
            }
            self.assertEqual(collected, expected_host_types, relative)

    def test_distribution_export_cannot_mutate_source_version(self) -> None:
        for relative in (
            "apple/ExportOptions/ios-app-store-connect.plist",
            "apple/ExportOptions/ios-testflight-internal.plist",
        ):
            with self.subTest(relative=relative):
                options = self.load_plist(relative)
                self.assertIs(options.get("manageAppVersionAndBuildNumber"), False)
        self.assertFalse((ROOT / "ios/exportOptions_distribution.plist").exists())

    def test_go_bridge_resolves_each_platform_sdk_instead_of_ambient_sdkroot(self) -> None:
        builder = (ROOT / "tools/build_apple_wg_go_bridge.sh").read_text()
        self.assertIn('sdk_root="$(xcrun --sdk "${platform}" --show-sdk-path)"', builder)
        self.assertIn('SDKROOT="${sdk_root}"', builder)

    def test_unsigned_dry_run_and_debug_bundle_gates_are_wired(self) -> None:
        smoke = (ROOT / "tools/apple_runtime_smoke.sh").read_text()
        staging = (ROOT / "tools/stage_apple_engine_artifacts.sh").read_text()
        self.assertIn('IOS_DEBUG_BUNDLE_ID="${IOS_DEBUG_BUNDLE_ID:-${IOS_BUNDLE_ID}.debug}"', smoke)
        self.assertIn('"${IOS_DEBUG_BUNDLE_ID}"', smoke)
        self.assertIn("WatchSimulator", smoke)
        self.assertIn("WATCHSIMULATOR", smoke)
        self.assertIn("CODE_SIGNING_ALLOWED=NO", smoke)
        self.assertIn("CODE_SIGNING_REQUIRED=NO", smoke)
        self.assertIn(
            'watch_supported_platform = (\n'
            '        "WatchSimulator" if expected_supported_platform == "iPhoneSimulator" '
            'else "WatchOS"\n'
            '    )',
            smoke,
        )
        self.assertIn(
            'if [[ "${WINS_APPLE_WINN3_RELEASE}" == "1" || "${WINS_REQUIRE_APPLE_ENGINE}" == "1" ]]; then',
            staging,
        )
        self.assertIn(
            "Apple engine artifact staging skipped missing components",
            staging,
        )
        self.assertIn(
            'Missing required Apple engine artifacts: xray_vless_ws_transport winn_packet_engine',
            staging,
        )


if __name__ == "__main__":
    unittest.main()
