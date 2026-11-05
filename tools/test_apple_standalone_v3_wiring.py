#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
V3_SOURCES = (
    "WinsWinn3HostContract.swift",
    "WinsWinn3Datapath.swift",
    "WinsWinn3SessionStart.swift",
)
LINK_REQUIREMENTS = (
    "-lWinsAmneziaWGPacketEngine",
    "-lWinsXrayVlessWsTransport",
    "-Wl,-force_load,$(WINN3_DATAPATH_ARCHIVE)",
    "-Wl,-u,_WinnTunnelCreateWinn3",
    "libwinn-datapath-darwin-arm64.a",
    "libwinn-datapath-darwin-amd64.a",
)


class AppleStandaloneV3WiringTests(unittest.TestCase):
    def test_ios_and_macos_providers_fork_before_legacy_engine(self) -> None:
        for platform in ("ios", "macos"):
            provider = (ROOT / platform / "PacketTunnel/PacketTunnelProvider.swift").read_text()
            bind = provider.index("try bindWinn3DescriptorToSelectedNode(")
            fork = provider.index("if parsedConfig.winn3Enabled {")
            standalone = provider.index("try startWinn3StandaloneSession(", fork)
            legacy_engine = provider.index("WinsPacketTunnelEngineFactory.makeEngine", standalone)
            self.assertLess(bind, fork, platform)
            self.assertLess(fork, standalone, platform)
            self.assertLess(standalone, legacy_engine, platform)

    def test_node_binding_is_mandatory_and_duplicates_fail_before_parse(self) -> None:
        core = (ROOT / "apple/WinsTunnelCore/WinsTunnelConfig.swift").read_text()
        self.assertIn("try validateUniqueWinnSecurityBindings(rawConfig)", core)
        self.assertIn('key == "node" || key == "selected_node"', core)
        self.assertIn("counts[key, default: 0] > 1", core)
        for platform in ("ios", "macos"):
            provider = (ROOT / platform / "PacketTunnel/PacketTunnelProvider.swift").read_text()
            self.assertNotIn(
                "if descriptorNode.isEmpty && selectedNode.isEmpty",
                provider,
                platform,
            )
            binding_start = provider.index("func winn3SelectedNodeIdentity(")
            binding_end = provider.index('\n    let winn = config.sections["winn"]', binding_start)
            binding = provider[binding_start:binding_end]
            self.assertIn(
                "let selectedNode = winn3SelectedNodeIdentity(winn: winn, options: options)",
                provider,
                platform,
            )
            self.assertIn('"selected_node"', binding, platform)
            # Persisted aliases may only confirm a transient selected identity.
            self.assertIn("switch winn3ReadNodeIdentityValue(options?[key])", binding, platform)
            self.assertIn("guard sawTransientIdentity, let bound else", binding, platform)
            self.assertIn("switch winn3ReadNodeIdentityValue(winn[key])", binding, platform)
            self.assertIn("if value != bound", binding, platform)
            self.assertIn("descriptorNode == selectedNode", provider, platform)

    def test_both_providers_refuse_persisted_ini_and_live_secrets(self) -> None:
        for platform in ("ios", "macos"):
            provider = (ROOT / platform / "PacketTunnel/PacketTunnelProvider.swift").read_text()
            self.assertNotIn('source: "injected_winn3_ini"', provider, platform)
            self.assertIn(
                "Ignoring persisted winn3_ini in providerConfiguration",
                provider,
                platform,
            )
            self.assertIn("its bytes are never parsed", provider, platform)
            self.assertIn("runtimeConfigContainsLiveSecretMaterial", provider, platform)
            self.assertIn('source != "transient_start_options"', provider, platform)
            self.assertIn("persisted_live_secret_material_refused", provider, platform)
            self.assertIn("-lWinsAmneziaWGPacketEngine", (ROOT / platform / "Runner.xcodeproj/project.pbxproj").read_text())
            self.assertIn("-lWinsXrayVlessWsTransport", (ROOT / platform / "Runner.xcodeproj/project.pbxproj").read_text())

    def test_persisted_winn3_secrets_round_trip_through_shared_keychain(self) -> None:
        core = (ROOT / "apple/WinsTunnelCore/WinsTunnelConfig.swift").read_text()
        self.assertIn('static let format = "wins-tunnel-secrets-v2"', core)
        self.assertIn('static let legacyFormat = "wins-tunnel-secrets-v1"', core)
        self.assertIn('"winn_static_private": winnStaticPrivate', core)
        self.assertIn('"winn_admission_key": winnAdmissionKey', core)
        for platform in ("ios", "macos"):
            provider = (ROOT / platform / "PacketTunnel/PacketTunnelProvider.swift").read_text()
            self.assertIn("containsRedactedWinnStaticPrivate", provider, platform)
            self.assertIn("containsRedactedWinnAdmissionKey", provider, platform)
            self.assertIn("winnStaticPrivate: winnStaticPrivate", provider, platform)
            self.assertIn("winnAdmissionKey: winnAdmissionKey", provider, platform)
        for path in (
            ROOT / "ios/Runner/AppDelegate.swift",
            ROOT / "macos/Runner/MainFlutterWindow.swift",
        ):
            app = path.read_text()
            self.assertIn("winnStaticPrivate: parsedConfig.winn3StaticPrivate", app)
            self.assertIn("winnAdmissionKey: parsedConfig.winn3AdmissionKey", app)
        ios = (ROOT / "ios/Runner/AppDelegate.swift").read_text()
        delivery = ios[ios.index("private func installWinn3ControlPlaneConfig") :]
        self.assertIn("WinsTunnelSecretStore.save", delivery)
        self.assertIn('"client_key_account_scope": accountScope', delivery)

    def test_host_apps_never_persist_full_winn3_ini_in_provider_preferences(self) -> None:
        for platform in ("ios", "macos"):
            app_delegate = (ROOT / platform / "Runner/AppDelegate.swift").read_text()
            self.assertIsNone(
                re.search(r'["\u0027]winn3_ini["\u0027]\s*:', app_delegate),
                f"{platform} must not persist full winn3 INI in providerConfiguration",
            )

    def test_both_xcode_projects_compile_all_six_v3_source_memberships(self) -> None:
        for platform in ("ios", "macos"):
            project = (ROOT / platform / "Runner.xcodeproj/project.pbxproj").read_text()
            for source in V3_SOURCES:
                self.assertEqual(
                    len(re.findall(rf"{re.escape(source)} in Sources", project)),
                    4,
                    f"{platform} must carry one build-file declaration and one "
                    f"source-phase entry for both app and PacketTunnel: {source}",
                )

    def test_packet_tunnel_link_configs_refuse_missing_v3_archive_or_symbol(self) -> None:
        config_ids = {
            "ios": ((
                "A10000000000000000000010",
                "A10000000000000000000011",
                "A10000000000000000000012",
            ), (
                "libwinn-datapath-ios-arm64.a",
                "libwinn-datapath-iossimulator-arm64.a",
                "libwinn-datapath-iossimulator-amd64.a",
            )),
            "macos": ((
                "B1000000000000000000000F",
                "B10000000000000000000010",
                "B10000000000000000000011",
            ), (
                "libwinn-datapath-darwin-arm64.a",
                "libwinn-datapath-darwin-amd64.a",
            )),
        }
        for platform, (identifiers, archive_names) in config_ids.items():
            project = (ROOT / platform / "Runner.xcodeproj/project.pbxproj").read_text()
            for identifier in identifiers:
                match = re.search(
                    rf"{identifier} /\* (?:Debug|Release|Profile) \*/ = \{{"
                    rf"(.*?)\n\t\t\}};",
                    project,
                    re.DOTALL,
                )
                self.assertIsNotNone(match, f"missing PacketTunnel config {identifier}")
                block = match.group(1)
                for requirement in LINK_REQUIREMENTS[:4] + archive_names:
                    self.assertIn(requirement, block, f"{platform} {identifier}")


if __name__ == "__main__":
    unittest.main()
