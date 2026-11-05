#!/usr/bin/env python3
"""Static and artifact gates for the native Windows ARM64 release lane."""

from __future__ import annotations

import hashlib
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = (ROOT / "installer/windows/build_installer.ps1").read_text(encoding="utf-8")
INNO = (ROOT / "installer/windows/winsvpn.iss").read_text(encoding="utf-8")
REMOTE = (ROOT / "tools/windows_remote_candidate_build.ps1").read_text(encoding="utf-8")
AWG_ENGINE = (ROOT / "tools/build_windows_awg_engine.ps1").read_text(encoding="utf-8")
AWG_HELPER = (ROOT / "tools/build_windows_amneziawg_client.ps1").read_text(
    encoding="utf-8"
)
XRAY = (ROOT / "tools/build_xray_engine.sh").read_text(encoding="utf-8")
CROSS_STORE = (ROOT / "tools/cross_store_upload_readiness.py").read_text(
    encoding="utf-8"
)
WINDOWS_GATE = (ROOT / "tools/windows_cross_store_artifact_gate.py").read_text(
    encoding="utf-8"
)
FREEZE = (ROOT / "tools/release_dependency_freeze.py").read_text(encoding="utf-8")
CMAKE = (ROOT / "windows/CMakeLists.txt").read_text(encoding="utf-8")
CHECKLIST = (ROOT / "docs/CROSS_STORE_RELEASE_CHECKLIST.md").read_text(
    encoding="utf-8"
)
DEPENDENCIES = ROOT / "installer/windows/dependencies"


def _pe_machine(path: pathlib.Path) -> int:
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b"MZ":
        raise AssertionError(f"{path.name} is not a DOS/PE image")
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise AssertionError(f"{path.name} is not a PE image")
    return int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")


class WindowsArm64ReleaseReadinessTests(unittest.TestCase):
    def test_native_host_only_flutter_lane_is_explicit(self) -> None:
        self.assertIn("[ValidateSet('x64', 'arm64')]", INSTALLER)
        self.assertIn("if ($TargetArchitecture -cne $normalizedHost)", INSTALLER)
        self.assertIn("Flutter build windows has no target-platform override", INSTALLER)
        self.assertNotIn("Windows arm64 release is fail-closed until", INSTALLER)
        self.assertNotIn("Windows arm64 remote candidates are fail-closed", REMOTE)
        self.assertIn("-TargetArchitecture $TargetArchitecture", REMOTE)
        self.assertNotIn("/MACHINE:X64", CMAKE)
        self.assertNotIn("CMAKE_GENERATOR_PLATFORM x64", CMAKE)

    def test_every_engine_has_a_native_arm64_target(self) -> None:
        self.assertIn("'arm64' = 'arm64'", INSTALLER)
        self.assertIn(
            '$ReleaseDir = Join-Path $RepoRoot '
            '"build\\windows\\$($script:WindowsFlutterArchDirectory)\\runner\\$Configuration"',
            INSTALLER,
        )
        self.assertIn('$WinnEngineArtifact = Join-Path $ReleaseDir "winn-datapath.exe"', INSTALLER)
        self.assertIn('$Winn3RelayArtifact = Join-Path $ReleaseDir "winsvpn_winn3_engine.exe"', INSTALLER)
        verifier_start = INSTALLER.index("function Invoke-Winn3ArtifactProvenanceVerification")
        verifier_end = INSTALLER.index("\n}", verifier_start)
        verifier = INSTALLER[verifier_start:verifier_end]
        for fragment in (
            # The release target follows the installer architecture for both
            # images: amd64 for x64 and arm64 for arm64.
            '$target = "datapath-windows-$($script:WindowsAwgGoArch)"',
            '$relayTarget = "winn3-relay-windows-$($script:WindowsAwgGoArch)"',
            "$releaseTool.Path, 'verify', '--release', $releaseRoot, '--print-manifest'",
            "$manifest = ([string]$verification.Stdout[0]) | ConvertFrom-Json -ErrorAction Stop",
            "if ($verification.ExitCode -ne 0 -or $verification.Stdout.Count -ne 1)",
            "Remove-Winn3PairStage",
            "$core = Get-WinsBoundedRegularFile -Path $WinnEngineArtifact",
            "$relay = Get-WinsBoundedRegularFile -Path $Winn3RelayArtifact",
            "Assert-PeCoffMachine -Path $core.Path -Expected $script:WindowsPeMachine",
            "Assert-PeCoffMachine -Path $relay.Path -Expected $script:WindowsPeMachine",
        ):
            self.assertIn(fragment, verifier)
        role_start = INSTALLER.index("function Assert-Winn3CompiledRole")
        role_check = INSTALLER[role_start:INSTALLER.index("\n}", role_start)]
        self.assertIn(
            "'check-role', '--role', $Role, '--architecture', $TargetArchitecture",
            role_check,
        )
        self.assertNotIn("verify-sealed-pair", INSTALLER)
        self.assertNotIn("$Winn3ArtifactInputDir", INSTALLER)
        self.assertIn("[ValidateSet('amd64', 'arm64')]", AWG_ENGINE)
        self.assertIn("GOARCH = $TargetArchitecture", AWG_ENGINE)
        self.assertIn("GOARM64 = 'v8.0'", AWG_ENGINE)
        self.assertIn("windows-arm64) goos=windows; goarch=arm64", XRAY)
        self.assertIn("0xAA64", XRAY)

    def test_arm64_awg_dependency_producer_is_pinned_and_reproducible(self) -> None:
        for value in (
            "523857871",
            "3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa",
            "3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43",
            "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
            "two_clean_builds_byte_identical",
        ):
            self.assertIn(value, AWG_HELPER)
        self.assertNotIn("no owner-reviewed windows/arm64 pin", AWG_HELPER)
        self.assertIn("windows-$TargetArchitecture", AWG_HELPER)
        self.assertIn("[uint16]0xAA64", AWG_HELPER)

    def test_inno_and_freeze_have_distinct_arm64_surfaces(self) -> None:
        self.assertIn('#define SetupArchitecture "arm64"', INNO)
        self.assertIn('ArchitecturesAllowed={#SetupArchitecture}', INNO)
        self.assertIn('ArchitecturesInstallIn64BitMode={#SetupArchitecture}', INNO)
        self.assertIn('#define VcRedistFile "VC_redist.arm64.exe"', INNO)
        self.assertIn('#define AmneziaWgMsiFile "amneziawg-arm64.msi"', INNO)
        self.assertIn('#define OutputArchitectureSuffix "-arm64"', INNO)
        for target in (
            "windows-arm64-inno-signed",
            "windows-arm64-inno-unsigned",
            "windows-arm64-inno-unsigned-prebuilt",
        ):
            self.assertIn(target, INSTALLER)
            self.assertIn(target, FREEZE)
        self.assertIn("WinsVPN-Setup-arm64.exe", REMOTE)

    def test_cross_store_requires_both_native_arm64_candidates(self) -> None:
        for target in (
            "windows-arm64-installer",
            "windows-arm64-partner-center",
        ):
            self.assertIn(target, CROSS_STORE)
            self.assertIn(target, WINDOWS_GATE)
        self.assertIn("PLANNED_UNSUPPORTED_TARGETS: dict[str, str] = {}", CROSS_STORE)
        self.assertIn('"windows-arm64-installer": "WinsVPN-Setup-arm64.exe"', WINDOWS_GATE)
        self.assertIn("PE_MACHINE_ARM64 = 0xAA64", WINDOWS_GATE)

    def test_pinned_arm64_xray_and_wintun_are_real_native_pe_images(self) -> None:
        expected = {
            "xray-arm64.exe": (
                "c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af",
                0xAA64,
            ),
            "wintun-arm64.dll": (
                "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
                0xAA64,
            ),
        }
        for name, (digest, machine) in expected.items():
            path = DEPENDENCIES / name
            self.assertTrue(path.is_file(), f"missing native ARM64 dependency: {name}")
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(_pe_machine(path), machine)

    def test_external_cross_compile_constraint_is_named_without_false_emulation(self) -> None:
        self.assertIn("Windows ARM64 host", CHECKLIST)
        self.assertIn("x64-to-ARM64", CHECKLIST)
        self.assertIn("emulation", CHECKLIST.lower())

    def test_gate_keeps_exact_arm64_inno_candidates_without_zip_msix(self) -> None:
        self.assertIn("TEST_ONLY = False", WINDOWS_GATE)
        self.assertIn("reject_origin_swap", WINDOWS_GATE)
        self.assertIn("compute_windows_installer_source_closure", WINDOWS_GATE)
        self.assertIn(
            "offline Authenticode trust verification requires the disposable",
            WINDOWS_GATE,
        )
        self.assertIn("Windows execution receipt reuse across targets is forbidden", WINDOWS_GATE)
        self.assertIn('"windows-arm64-partner-center": "WinsVPN-PartnerCenter-arm64.exe"', WINDOWS_GATE)
        self.assertIn('"windows-x64-partner-center": "WinsVPN-PartnerCenter.exe"', WINDOWS_GATE)
        self.assertNotIn("windows-arm64-zip", WINDOWS_GATE)
        self.assertNotIn("windows-arm64-msix", WINDOWS_GATE)
        self.assertNotIn("windows-x64-zip", WINDOWS_GATE)
        self.assertNotIn("windows-x64-msix", WINDOWS_GATE)
        self.assertNotIn("WinsVPN-Setup.zip", WINDOWS_GATE)
        self.assertNotIn("WinsVPN-PartnerCenter.msix", WINDOWS_GATE)
        self.assertIn("WinsVPN-Setup-arm64.exe", WINDOWS_GATE)
        self.assertIn("PE_MACHINE_X64 = 0x8664", WINDOWS_GATE)
        self.assertNotEqual(
            "272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12",
            "3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43",
        )
        self.assertIn(
            '"x64": "272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12"',
            WINDOWS_GATE,
        )
        self.assertIn(
            '"arm64": "3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43"',
            WINDOWS_GATE,
        )
        self.assertIn(
            '"x64": "fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224"',
            WINDOWS_GATE,
        )
        self.assertIn(
            '"arm64": "c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af"',
            WINDOWS_GATE,
        )


if __name__ == "__main__":
    unittest.main()
