#!/usr/bin/env python3
"""Focused source and mutation contracts for standalone Winn v3 Windows packaging."""

from __future__ import annotations

import subprocess
import struct
import sys
import tempfile
import unittest
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_windows_standalone_v3_artifact as verifier  # noqa: E402


BUILD_SCRIPT = ROOT / "installer/windows/build_installer.ps1"
INNO_SCRIPT = ROOT / "installer/windows/winsvpn.iss"
REMOTE_SCRIPT = ROOT / "tools/windows_remote_candidate_build.ps1"
APP_SOURCE = ROOT / "lib/main.dart"
WIX_X64 = ROOT / "installer/windows/wix/winsvpn_winn3_payload.wxs"
WIX_ARM64 = ROOT / "installer/windows/wix/winsvpn_winn3_payload_arm64.wxs"
AMNEZIA_VERIFIED_EXTRACT = (
    "if not ExtractVerifiedEmbeddedPrerequisite(\n"
    "    '{#AmneziaWgMsiFile}', '{#AmneziaWgMsiExpectedSha256}',\n"
    "    {#AmneziaWgMsiExpectedBytes}, Result\n"
    "  ) then"
)
AMNEZIA_IDENTITY = "VerifyEmbeddedPrerequisiteIdentity(\n    AmneziaMsiPath,"
AMNEZIA_REVERIFY = (
    "EmbeddedPrerequisiteMatchesExpected(\n"
    "    AmneziaMsiPath, '{#AmneziaWgMsiExpectedSha256}', {#AmneziaWgMsiExpectedBytes}"
)
AMNEZIA_INSTALL_CAPTION = (
    "WizardForm.StatusLabel.Caption :=\n"
    "    'Installing AmneziaWG Windows tunnel engine...';"
)
AMNEZIA_EXEC = "'/i \"' + AmneziaMsiPath +"
AMNEZIA_POSTINSTALL = (
    "#ifndef StandaloneWinn3Release\n"
    "  if (not FileExists(ExpandConstant('{app}\\amneziawg.exe'))) or"
)


def windows_embedded_extraction_errors(inno: str) -> list[str]:
    errors: list[str] = []
    try:
        prepare = inno[
            inno.index(
                "function PrepareToInstall(var NeedsRestart: Boolean): String;"
            ) : inno.index("procedure RaiseFatalPostInstallException(")
        ]
        extract_fn = inno[
            inno.index("function ExtractVerifiedEmbeddedPrerequisite") : inno.index(
                "function EmbeddedPrerequisiteMatchesExpected"
            )
        ]
    except ValueError:
        return ["missing PrepareToInstall or ExtractVerifiedEmbeddedPrerequisite"]
    gated = (
        "#ifndef StandaloneWinn3Release\n"
        "  AmneziaMsiPath := ExpandConstant('{tmp}\\{#AmneziaWgMsiFile}');\n"
        "  " + AMNEZIA_VERIFIED_EXTRACT
    )
    if gated not in prepare:
        errors.append("PrepareToInstall lost the exact gated Amnezia verified extraction")
    if "ExtractFreshEmbeddedFile('{#AmneziaWgMsiFile}'" in prepare:
        errors.append("PrepareToInstall fell back to retired ExtractFreshEmbeddedFile")
    try:
        extract_at = prepare.index(AMNEZIA_VERIFIED_EXTRACT)
        identity_at = prepare.index(AMNEZIA_IDENTITY)
        reverify_at = prepare.index(AMNEZIA_REVERIFY)
        caption_at = prepare.index(AMNEZIA_INSTALL_CAPTION)
        exec_at = prepare.index(AMNEZIA_EXEC)
    except ValueError:
        errors.append("Amnezia extract/identity/reverify/exec markers are missing")
        return errors
    if not extract_at < identity_at < reverify_at < caption_at < exec_at:
        errors.append("Amnezia extract/identity/reverify/exec fail-closed order was removed")
    if AMNEZIA_POSTINSTALL not in inno:
        errors.append("postinstall Amnezia helper check lost StandaloneWinn3Release gating")
    if "CompareText(ExtractedSha256, ExpectedSha256)" not in extract_fn:
        errors.append("verified extract dropped expected SHA-256")
    if "FileSize(ExtractedPath, ExtractedBytes) or (ExtractedBytes <> ExpectedBytes)" not in extract_fn:
        errors.append("verified extract dropped expected bytes")
    if "Exec(" in extract_fn:
        errors.append("verified extract gained Exec")
    return errors


class ArtifactVerifierTests(unittest.TestCase):
    @staticmethod
    def _pe(machine: int, *, marker: bool = False) -> bytes:
        data = bytearray(256)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x84, machine)
        if marker:
            data.extend(verifier.WINN3_MARKER)
        return bytes(data)

    def _write_zip(
        self,
        names: set[str],
        *,
        machine: int = verifier.PE_MACHINE_X64,
        marker_names: set[str] | None = None,
    ) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        temp_dir = Path(temp.name)
        archive_path = temp_dir / "candidate.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            for name in sorted(names):
                markers = marker_names if marker_names is not None else {"winn-datapath.exe"}
                data = (
                    self._pe(machine, marker=name in markers)
                    if name in verifier.REQUIRED_PE_BASENAMES
                    else b"fixture"
                )
                archive.writestr(f"payload/{name}", data)
        return archive_path

    def test_complete_standalone_fixture_passes(self) -> None:
        self.assertEqual(verifier.verify(self._write_zip(set(verifier.REQUIRED_BASENAMES))), [])

    def test_every_missing_required_payload_breaks_the_gate(self) -> None:
        for missing in verifier.REQUIRED_BASENAMES:
            with self.subTest(missing=missing):
                names = set(verifier.REQUIRED_BASENAMES) - {missing}
                errors = verifier.verify(self._write_zip(names))
                self.assertTrue(any(missing in error for error in errors), errors)

    def test_every_forbidden_legacy_payload_breaks_the_gate(self) -> None:
        for forbidden in verifier.FORBIDDEN_BASENAMES:
            with self.subTest(forbidden=forbidden):
                names = set(verifier.REQUIRED_BASENAMES) | {forbidden}
                errors = verifier.verify(self._write_zip(names))
                self.assertTrue(any(forbidden in error for error in errors), errors)

    def test_x64_payload_under_arm64_expectation_breaks_the_gate(self) -> None:
        archive = self._write_zip(
            set(verifier.REQUIRED_BASENAMES), machine=verifier.PE_MACHINE_X64
        )
        errors = verifier.verify(archive, expected_architecture="arm64")
        self.assertEqual(len([error for error in errors if "arm64 requires" in error]), 5)

    def test_relay_marker_is_rejected_because_datapath_is_the_only_carrier(self) -> None:
        archive = self._write_zip(
            set(verifier.REQUIRED_BASENAMES),
            marker_names={"winn-datapath.exe", "winsvpn_winn3_engine.exe"},
        )
        errors = verifier.verify(archive)
        self.assertTrue(any("only winn-datapath.exe" in error for error in errors), errors)

    def test_legacy_provenance_sidecar_breaks_the_gate(self) -> None:
        forbidden = "winsvpn_awg_engine.exe.provenance.json"
        names = set(verifier.REQUIRED_BASENAMES) | {forbidden}
        errors = verifier.verify(self._write_zip(names))
        self.assertTrue(any(forbidden in error for error in errors), errors)

    def test_cli_fails_and_passes_on_zip_fixtures(self) -> None:
        good = self._write_zip(set(verifier.REQUIRED_BASENAMES))
        bad = self._write_zip(set(verifier.REQUIRED_BASENAMES) | {"xray.exe"})
        good_run = subprocess.run(
            [sys.executable, str(ROOT / "tools/verify_windows_standalone_v3_artifact.py"), str(good)],
            check=False,
            capture_output=True,
            text=True,
        )
        bad_run = subprocess.run(
            [sys.executable, str(ROOT / "tools/verify_windows_standalone_v3_artifact.py"), str(bad)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(good_run.returncode, 0, good_run.stderr)
        self.assertNotEqual(bad_run.returncode, 0)


class ProducerSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build = BUILD_SCRIPT.read_text(encoding="utf-8")
        cls.inno = INNO_SCRIPT.read_text(encoding="utf-8")
        cls.remote = REMOTE_SCRIPT.read_text(encoding="utf-8")
        cls.app = APP_SOURCE.read_text(encoding="utf-8")
        cls.wix = (
            WIX_X64.read_text(encoding="utf-8"),
            WIX_ARM64.read_text(encoding="utf-8"),
        )

    def test_remote_rc_path_defaults_to_full_v3_and_v1_payload(self) -> None:
        self.assertIn("-SkipRuntimeDownload @standaloneArgument", self.remote)
        self.assertIn("[switch]$StandaloneWinn3Release", self.remote)
        self.assertNotIn(
            "-SkipRuntimeDownload -StandaloneWinn3Release",
            self.remote,
        )
        self.assertIn("if ($StandaloneWinn3Release) {", self.remote)
        self.assertIn(
            "verify_windows_standalone_v3_artifact.py $installer",
            self.remote,
        )
        self.assertIn("manifest.standalone_winn3", self.remote)
        self.assertIn("ExpectStandaloneWinn3", self.remote)
        self.assertIn(
            "Winn v3 primary plus Winn v1 AWG/Xray fallback",
            self.remote,
        )

    def test_producer_rejects_missing_winn_override_in_standalone_mode(self) -> None:
        self.assertIn("$StandaloneWinn3Release -and $AllowMissingWinn3Carrier", self.build)
        self.assertIn("'/DStandaloneWinn3Release=1'", self.build)

    def test_producer_runs_content_gate_before_publication(self) -> None:
        verify_index = self.build.index("$WindowsStandaloneVerifier $stagedInstaller")
        publish_index = self.build.index("[IO.File]::Move($stagedInstaller, $CanonicalInstaller)")
        self.assertLess(verify_index, publish_index)

    def test_producer_does_not_stage_legacy_dependencies_in_standalone_mode(self) -> None:
        gate = "if (-not $StandaloneWinn3Release) {"
        stage_index = self.build.index(
            "$stagedDependencyMap[$dependencyNames.AmneziaMsi]"
        )
        self.assertGreater(stage_index, self.build.rfind(gate, 0, stage_index))
        self.assertIn("staged_xray_product_signed = [bool]($mustSign -and -not $StandaloneWinn3Release)", self.build)

    def test_standalone_stages_and_hash_validates_required_wintun(self) -> None:
        self.assertIn("'wintun.dll' = $WintunDll", self.build)
        self.assertIn("Test-FileSha256 -Path $WintunDll -ExpectedSha256 $WintunDllSha256", self.build)
        self.assertIn('"/DWintunDllSha256=$WintunDllSha256"', self.build)
        files = self.inno[self.inno.index("[Files]"):self.inno.index("[Icons]")]
        wintun_source = 'Source: "{#DependenciesDir}\\{#WintunFile}"'
        self.assertIn(wintun_source, files[:files.index("#ifndef StandaloneWinn3Release")])
        self.assertGreaterEqual(self.inno.count('#define WintunFile "wintun.dll"'), 2)
        self.assertIn("Wintun-Prebuilt-Binaries-License.txt", files)
        self.assertIn("GetSHA256OfFile(ExpandConstant('{app}\\wintun.dll'))", self.inno)

    def test_standalone_uses_its_variant_specific_license_index(self) -> None:
        files = self.inno[self.inno.index("[Files]") : self.inno.index("[Icons]")]
        branch_start = files.index("#ifdef StandaloneWinn3Release")
        branch_else = files.index("#else", branch_start)
        branch_end = files.index("#endif", branch_else)
        standalone = files[branch_start:branch_else]
        full = files[branch_else:branch_end]
        self.assertIn("README-STANDALONE-WINN3.txt", standalone)
        self.assertNotIn('\\README.txt"', standalone)
        self.assertIn('\\README.txt"', full)
        self.assertNotIn("README-STANDALONE-WINN3.txt", full)

        verify_start = self.inno.index("procedure VerifyInstalledLicences;")
        verify_end = self.inno.index("procedure VerifyInstalledWintunRuntime;")
        verify = self.inno[verify_start:verify_end]
        branch_start = verify.index("#ifdef StandaloneWinn3Release")
        branch_else = verify.index("#else", branch_start)
        branch_end = verify.index("#endif", branch_else)
        self.assertIn(
            "StandaloneLicensesIndexSha256",
            verify[branch_start:branch_else],
        )
        self.assertIn("LicensesIndexSha256", verify[branch_else:branch_end])

        for wix in self.wix:
            self.assertIn(
                'Source="$(var.LicensesDir)\\README-STANDALONE-WINN3.txt" '
                'Name="README.txt"',
                wix,
            )
            self.assertNotIn(
                'Source="$(var.LicensesDir)\\README.txt"', wix
            )

    def test_inno_legacy_payload_sources_are_preprocessor_gated(self) -> None:
        block_start = self.inno.index("#ifndef StandaloneWinn3Release", self.inno.index("[Files]"))
        block_end = self.inno.index("#endif", block_start)
        block = self.inno[block_start:block_end]
        for macro in (
            "AmneziaWgMsiFile",
            "AmneziaWgHelperFile",
            "AwgToolFile",
            "XrayFile",
        ):
            self.assertIn(f'{{#{macro}}}', block)
        for name in (
            "amneziawg-amd64.msi",
            "amneziawg-arm64.msi",
            "amneziawg.exe",
            "awg.exe",
            "xray.exe",
        ):
            self.assertIn(f'"{name}"', self.inno[: self.inno.index("[Files]")])
        for name in (
            "mullvad-split-tunnel.sys",
            "mullvad-split-tunnel.cat",
            "mullvad-split-tunnel.inf",
        ):
            self.assertNotIn(name, self.inno)

    def test_known_affected_split_driver_is_rejected_before_packaging(self) -> None:
        self.assertIn("$affectedSplitTunnelDriverNames = @(", self.build)
        self.assertIn("Known-affected Mullvad split-tunnel driver 1.3.0.0", self.build)
        self.assertIn("function Assert-InnoStagingContainsNoWithdrawnMullvadPayloads {", self.build)
        self.assertIn("withdrawn kernel split-tunnel bytes, including when renamed", self.build)
        self.assertGreaterEqual(
            self.build.count("Assert-InnoStagingContainsNoWithdrawnMullvadPayloads"),
            2,
        )
        iscc = self.build.index("& $iscc @innoArguments")
        self.assertLess(
            self.build.rindex("Assert-InnoStagingContainsNoWithdrawnMullvadPayloads", 0, iscc),
            iscc,
        )
        for name in (
            "mullvad-split-tunnel.sys",
            "mullvad-split-tunnel.cat",
            "mullvad-split-tunnel.inf",
        ):
            self.assertIn(f"'{name}'", self.build)

    def test_windows_ui_does_not_advertise_per_app_split_tunneling(self) -> None:
        support_start = self.app.index("bool get _supportsPerAppSplitTunneling")
        support_end = self.app.index(";", support_start) + 1
        support_expression = self.app[support_start:support_end]
        self.assertIn("Platform.isAndroid || Platform.isLinux", support_expression)
        self.assertNotIn("Platform.isWindows", support_expression)

    def test_inno_legacy_install_and_postinstall_work_are_gated(self) -> None:
        self.assertEqual(windows_embedded_extraction_errors(self.inno), [])
        self.assertIn(AMNEZIA_VERIFIED_EXTRACT, self.inno)
        self.assertIn(
            "#ifndef StandaloneWinn3Release\n"
            "  AmneziaMsiPath := ExpandConstant('{tmp}\\{#AmneziaWgMsiFile}');",
            self.inno,
        )
        self.assertIn(AMNEZIA_REVERIFY, self.inno)
        self.assertIn(AMNEZIA_INSTALL_CAPTION, self.inno)
        self.assertIn(AMNEZIA_POSTINSTALL, self.inno)

    def test_embedded_extraction_transaction_mutations_are_rejected(self) -> None:
        self.assertEqual(windows_embedded_extraction_errors(self.inno), [])

        retired = self.inno.replace(
            AMNEZIA_VERIFIED_EXTRACT,
            "if not ExtractFreshEmbeddedFile('{#AmneziaWgMsiFile}', Result) then",
            1,
        )
        self.assertNotEqual(retired, self.inno)
        self.assertTrue(windows_embedded_extraction_errors(retired))

        no_hash = self.inno.replace(
            "'{#AmneziaWgMsiFile}', '{#AmneziaWgMsiExpectedSha256}',",
            "'{#AmneziaWgMsiFile}',",
            1,
        )
        self.assertNotEqual(no_hash, self.inno)
        self.assertTrue(windows_embedded_extraction_errors(no_hash))

        exec_first = self.inno.replace(
            "  AmneziaMsiPath := ExpandConstant('{tmp}\\{#AmneziaWgMsiFile}');\n",
            "  AmneziaMsiPath := ExpandConstant('{tmp}\\{#AmneziaWgMsiFile}');\n"
            "  if not Exec(ExpandConstant('{sys}\\msiexec.exe'), "
            "'/i \"' + AmneziaMsiPath +, SW_HIDE, ewWaitUntilTerminated, ResultCode) then\n"
            "    exit;\n",
            1,
        )
        self.assertNotEqual(exec_first, self.inno)
        self.assertTrue(windows_embedded_extraction_errors(exec_first))

        no_identity = self.inno.replace(AMNEZIA_IDENTITY, "SkipAmneziaIdentity(\n    AmneziaMsiPath,", 1)
        self.assertNotEqual(no_identity, self.inno)
        self.assertTrue(windows_embedded_extraction_errors(no_identity))

        no_reverify = self.inno.replace(AMNEZIA_REVERIFY, "True or EmbeddedPrerequisiteMatchesExpected(\n    OtherPath", 1)
        self.assertNotEqual(no_reverify, self.inno)
        self.assertTrue(windows_embedded_extraction_errors(no_reverify))


if __name__ == "__main__":
    unittest.main()
