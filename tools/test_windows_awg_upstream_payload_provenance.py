#!/usr/bin/env python3
"""Fail-closed contract for official Windows AWG 3.1 MSI/awg.exe provenance."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CLIENT_PATH = ROOT / "tools/build_windows_amneziawg_client.ps1"
CLIENT = CLIENT_PATH.read_text(encoding="utf-8")
ENGINE = (ROOT / "tools/build_windows_awg_engine.ps1").read_text(
    encoding="utf-8"
)
ZIP_PATH = ROOT / "installer/windows/build_zip_installer.ps1"
ZIP = ZIP_PATH.read_text(encoding="utf-8")
VERIFY_PATH = ROOT / "tools/verify_deployment_supply_chain.py"
VERIFY = VERIFY_PATH.read_text(encoding="utf-8")
INSTALLER_PATH = ROOT / "installer/windows/build_installer.ps1"
INSTALLER = INSTALLER_PATH.read_text(encoding="utf-8")
DEPENDENCIES = ROOT / "installer/windows/dependencies"
PROVENANCE = DEPENDENCIES / "amneziawg.exe.provenance.json"

OFFICIAL_RELEASE_ID = 374470280
OFFICIAL_ASSET_ID = 523857174
OFFICIAL_ARM64_ASSET_ID = 523857871
OFFICIAL_MSI_BYTES = 3_641_344
OFFICIAL_MSI_SHA256 = (
    "a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b"
)
OFFICIAL_AWG_EXE_SHA256 = (
    "272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12"
)
OFFICIAL_MSI_HELPER_SHA256 = (
    "ba446f6e1a4093e43a65d6ff45f4b8c7b6485dc419327eedaa1a218549740e3a"
)
OFFICIAL_WINTUN_SHA256 = (
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
)
OFFICIAL_ARM64_MSI_SHA256 = (
    "3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa"
)
OFFICIAL_ARM64_AWG_EXE_SHA256 = (
    "3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43"
)
OFFICIAL_ARM64_MSI_HELPER_SHA256 = (
    "25fa81103152699bf416f394059b40d447001c3d0dea5ef889a9426f315e4c0a"
)
OFFICIAL_ARM64_WINTUN_SHA256 = (
    "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"
)
PRODUCT_HELPER_SHA256 = (
    "12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41"
)
LEGACY_MSI_SHA256 = (
    "a0fa81022a6e0204b67c92f0046aaebac923bf6ffc786f503c5acff483807b4a"
)
LEGACY_AWG_EXE_SHA256 = (
    "cd17f8641bb78ea6476c7341fb7339731ecd8f682e46ab1b43618cea75185552"
)
LEGACY_PRODUCT_HELPER_SHA256 = (
    "c1a9500254948ac4a1562d8ddf0808b45441ed36bf6746499b67efee6eef1ae9"
)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class WindowsAwgUpstreamPayloadProvenanceTests(unittest.TestCase):
    def test_official_3_1_release_and_asset_pins_are_immutable(self) -> None:
        for marker in (
            "$upstreamMsiVersion = '3.1.0'",
            f"$upstreamReleaseId = {OFFICIAL_RELEASE_ID}",
            f"amd64 = {OFFICIAL_ASSET_ID}",
            f"arm64 = {OFFICIAL_ARM64_ASSET_ID}",
            "$upstreamMsiName = \"amneziawg-$TargetArchitecture-$upstreamMsiVersion.msi\"",
            "releases/tags/$upstreamMsiVersion",
            "releases?per_page=100",
            OFFICIAL_MSI_SHA256,
            OFFICIAL_AWG_EXE_SHA256,
            OFFICIAL_MSI_HELPER_SHA256,
            OFFICIAL_WINTUN_SHA256,
            OFFICIAL_ARM64_MSI_SHA256,
            OFFICIAL_ARM64_AWG_EXE_SHA256,
            OFFICIAL_ARM64_MSI_HELPER_SHA256,
            OFFICIAL_ARM64_WINTUN_SHA256,
        ):
            self.assertIn(marker, CLIENT)
        self.assertNotIn(OFFICIAL_MSI_SHA256, ENGINE)
        self.assertIn(f"MsiBytes = {OFFICIAL_MSI_BYTES}", CLIENT)
        for variable, pin_field in (
            ("upstreamMsiSha256", "MsiSha256"),
            ("upstreamAwgExeSha256", "AwgSha256"),
            ("upstreamMsiHelperSha256", "MsiHelperSha256"),
            ("expectedProductHelperSha256", "ProductHelperSha256"),
        ):
            self.assertRegex(
                CLIENT,
                rf"\${variable}\s*=\s*\$architecturePins\.{pin_field}",
            )
        self.assertIn(PRODUCT_HELPER_SHA256, CLIENT)
        self.assertIn(
            "ProductHelperSha256 = '0e88c6d049d0905b5aa1e53c63ffa24f2760701be4b28eee5975b381393ef73f'",
            CLIENT,
        )
        self.assertIn("ProductHelperBytes = 8483840", CLIENT)
        self.assertIn("The reproducible ARM64 product maintenance helper changed.", CLIENT)

    def test_live_metadata_must_still_be_latest_and_match_exact_asset(self) -> None:
        for marker in (
            "Get-VerifiedOfficialReleaseAsset",
            "$latestStable.tag_name -cne $upstreamMsiVersion",
            "Review and freeze its exact inputs before building.",
            "[long]$release.id -ne $upstreamReleaseId",
            "[long]$asset.id -ne $upstreamAssetId",
            "[long]$asset.size -ne $upstreamMsiBytes",
            '"sha256:$upstreamMsiSha256"',
            "$asset.browser_download_url -cne $upstreamMsiUrl",
            "release_metadata_verified = $true",
        ):
            self.assertIn(marker, CLIENT)

    def test_legacy_2_0_1_payloads_are_rejected_not_accepted(self) -> None:
        for marker in (
            "$rejectedLegacyMsiSha256 =",
            "$rejectedLegacyAwgExeSha256 =",
            "$rejectedLegacyProductHelperSha256 =",
            LEGACY_MSI_SHA256,
            LEGACY_AWG_EXE_SHA256,
            LEGACY_PRODUCT_HELPER_SHA256,
        ):
            self.assertIn(marker, CLIENT)
        self.assertNotRegex(
            CLIENT,
            rf"\$upstreamMsiSha256\s*=\s*'{LEGACY_MSI_SHA256}'",
        )
        self.assertNotRegex(
            CLIENT,
            rf"\$upstreamAwgExeSha256\s*=\s*'{LEGACY_AWG_EXE_SHA256}'",
        )
        self.assertNotRegex(
            CLIENT,
            rf"\$expectedProductHelperSha256\s*=\s*'{LEGACY_PRODUCT_HELPER_SHA256}'",
        )

    def test_current_cache_matches_reviewed_3_1_payloads(self) -> None:
        msi = sha256(DEPENDENCIES / "amneziawg-amd64.msi")
        awg = sha256(DEPENDENCIES / "awg.exe")
        self.assertEqual((msi, awg), (OFFICIAL_MSI_SHA256, OFFICIAL_AWG_EXE_SHA256))
        self.assertNotEqual(msi, LEGACY_MSI_SHA256)
        self.assertNotEqual(awg, LEGACY_AWG_EXE_SHA256)
        self.assertEqual(
            sha256(DEPENDENCIES / "amneziawg.exe"), PRODUCT_HELPER_SHA256
        )
        self.assertEqual(
            sha256(DEPENDENCIES / "wintun.dll"), OFFICIAL_WINTUN_SHA256
        )

    def test_current_provenance_was_refreshed_by_one_producer_transaction(
        self,
    ) -> None:
        evidence = json.loads(PROVENANCE.read_text(encoding="utf-8"))
        self.assertEqual(evidence.get("schema_version"), 2)
        self.assertNotIn("owner_blocked", evidence)
        self.assertNotIn("required_schema_version", evidence)
        self.assertRegex(
            evidence.get("publication_transaction_id", ""), r"^[0-9a-f]{32}$"
        )
        self.assertIs(evidence.get("provenance_is_commit_marker"), True)
        self.assertEqual(
            evidence.get("expected_unsigned_artifact_sha256"), PRODUCT_HELPER_SHA256
        )
        self.assertEqual(
            evidence.get("helper_kind"),
            "canonical_unsigned_product_maintenance_helper",
        )
        self.assertEqual(evidence.get("go_version"), "1.27.1")
        self.assertEqual(evidence.get("engine_version"), "v3.1.20260828")
        self.assertEqual(evidence.get("windows_library_version"), "v3.1.20260814")
        self.assertEqual(
            evidence.get("unsigned_artifact_sha256"), PRODUCT_HELPER_SHA256
        )

    def test_refresh_stages_and_validates_before_non_destructive_publish(self) -> None:
        for marker in (
            "Resolve-OfficialMsiCandidate",
            "Publish-AwgGenerationTransaction",
            ".artifacts\\rejected-dependency-cache\\windows-awg",
            "Official AmneziaWG 3.1.0 MSI administrative extract failed",
            "[IO.FileShare]::None",
            "Restore-AwgTransaction",
            "winsvpn.windows-awg-publication.v2",
            "provenance_is_commit_marker = $true",
            "Flush-DurableFile",
        ):
            self.assertIn(marker, CLIENT)
        self.assertNotRegex(
            CLIENT,
            r"Move-Item[^\n]+-Destination\s+(?:\$MsiPath|\$AwgPath|\$WintunPath|\$Destination)\s+-Force",
        )
        self.assertNotRegex(
            CLIENT,
            r"Remove-Item[^\n]*(?:\$upstreamMsiFull|\$awgToolFull|\$outputFull)",
        )
        transaction_start = CLIENT.index("$transactionEntries = @(")
        provenance_entry = CLIENT.index("$provenanceFull", transaction_start)
        for marker in ("$upstreamMsiFull", "$awgToolFull", "$wintunFull", "$outputFull"):
            self.assertLess(CLIENT.index(marker, transaction_start), provenance_entry)
        allow_download = CLIENT.index("if (-not $AllowDownload)")
        rejected_message = CLIENT.index("rejected 2.0.1 asset", allow_download)
        download = CLIENT.index("Invoke-PinnedHttpsDownload", rejected_message)
        self.assertLess(allow_download, rejected_message)
        self.assertLess(rejected_message, download)

    def test_transport_signature_size_architecture_and_reparse_gates_exist(self) -> None:
        for marker in (
            "--proto '=https'",
            "--proto-redir '=https'",
            "--connect-timeout 30",
            "function Assert-AuthenticodeSigner",
            "SignatureStatus]::Valid",
            "O=Privacy Technologies OU",
            "O=WireGuard LLC",
            "function Assert-FileSize",
            "function Assert-RegularPath",
            "FileAttributes]::ReparsePoint",
            "function Assert-NoReparseTree",
            "Assert-NoReparseTree -Root $ExtractRoot",
            "Assert-TargetPe -Path $payloadPath",
            "O=Microsoft Corporation",
        ):
            self.assertIn(marker, CLIENT)
        self.assertNotIn("Authorization", CLIENT)

    def test_upstream_msi_helper_is_not_the_product_helper(self) -> None:
        for marker in (
            "helper_kind = 'canonical_unsigned_product_maintenance_helper'",
            "signing_boundary = 'release_staged_copy_only'",
            "upstream_msi_helper_kind = 'official_upstream_signed_gui_helper_not_published'",
            "The rebuilt product maintenance helper must not match the official MSI amneziawg.exe.",
            "$unsignedSha256 -ceq $upstreamMsiHelperSha256",
            "$unsignedSha256 -cne $expectedProductHelperSha256",
            "SignatureStatus]::NotSigned",
        ):
            self.assertIn(marker, CLIENT)
        transaction_entries = CLIENT[CLIENT.index("$transactionEntries = @(") :]
        self.assertNotIn("$extracted['amneziawg.exe']", transaction_entries)
        self.assertIn("Source = $builtExe; Destination = $outputFull", transaction_entries)

    def test_refreshed_payloads_and_signers_are_recorded_in_provenance(self) -> None:
        for marker in (
            "upstream_release_id = $upstreamReleaseId",
            "upstream_asset_id = $upstreamAssetId",
            "upstream_asset_name = $upstreamMsiName",
            "upstream_asset_size = $upstreamMsiBytes",
            "upstream_release_metadata_verified =",
            "upstream_msi_sha256 = $upstreamMsiSha256",
            "upstream_awg_exe_sha256 = $upstreamAwgExeSha256",
            "upstream_msi_helper_sha256 = $upstreamMsiHelperSha256",
            "upstream_msi_signer_thumbprint =",
            "upstream_awg_signer_thumbprint =",
            "expected_unsigned_artifact_sha256 = $expectedProductHelperSha256",
        ):
            self.assertIn(marker, CLIENT)

    def test_zip_and_deployment_verification_require_schema_2_identities(
        self,
    ) -> None:
        begin = "# BEGIN-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT"
        end = "# END-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT"
        zip_contract = ZIP[ZIP.index(begin) : ZIP.index(end) + len(end)]
        installer_contract = INSTALLER[
            INSTALLER.index(begin) : INSTALLER.index(end) + len(end)
        ]
        # Depends on lane WP copying the installer block into the ZIP producer.
        self.assertEqual(zip_contract, installer_contract)
        for source in (ZIP, INSTALLER):
            self.assertIn(
                "function Assert-WindowsAwgSchema2OwnerPublicationContract",
                source,
            )
            self.assertNotIn("[int]$evidence.schema_version -ne 2", source)
            self.assertNotIn(
                "-not [bool]$evidence.provenance_is_commit_marker", source
            )
            self.assertIn(
                "Re-verifying staged dependency bytes against reviewed pins after copy",
                source,
            )
        for marker in (
            "expected_unsigned_artifact_sha256",
            "source_repository",
            "go_archive",
            "go_archive_sha256",
            "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d",
            "module_build_info",
            "v3.1.20260814",
            "v3.1.20260828",
            "ca5dd3b983bd19c335ab095ccd21fc2f804ec968",
            "b5928efb6ca19f0153958460c3d141f04abc5c2e",
            "e90531d15802cb976773f3b63443bc281f738ca3",
        ):
            self.assertIn(marker, ZIP)
            self.assertIn(marker, INSTALLER)
            self.assertIn(marker, VERIFY)
        for retired in (
            "Get-RequiredJsonProperty $evidence 'owner_blocked'",
            "Get-RequiredJsonProperty $evidence 'publication_transaction_id'",
            "Get-RequiredJsonProperty $evidence 'provenance_is_commit_marker'",
            "Get-RequiredJsonProperty $evidence 'helper_kind'",
        ):
            self.assertNotIn(retired, installer_contract)
        self.assertNotIn("owner-blocked until a", VERIFY)
        self.assertNotIn("refusing to invent hashes or transaction IDs", VERIFY)
        self.assertIn(PRODUCT_HELPER_SHA256, VERIFY)
        self.assertIn(PRODUCT_HELPER_SHA256, INSTALLER)
        self.assertIn("type(actual) is not type(expected)", VERIFY)

    def test_committed_schema_2_artifact_passes_deployment_verification(
        self,
    ) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_deployment_supply_chain", VERIFY_PATH
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # The committed helper was rebuilt on Windows with Go 1.27.1 on
        # 2026-10-09; its schema-2 provenance meets the real archive pin.
        module.verify_windows_amneziawg_client_rebuild_pins()

    def test_script_is_powershell_5_1_compatible_at_parse_boundary(self) -> None:
        self.assertNotIn("??", CLIENT)
        self.assertNotRegex(ZIP, r"(?m)\$[^\n]*\?\?")
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("pwsh is unavailable for parser validation")
        for path in (CLIENT_PATH, ZIP_PATH, INSTALLER_PATH):
            with self.subTest(path=str(path)):
                command = (
                    "$tokens=$null; $errors=$null; "
                    "[System.Management.Automation.Language.Parser]::ParseFile("
                    f"'{path}', [ref]$tokens, [ref]$errors) > $null; "
                    "if ($errors.Count) { $errors | ForEach-Object { "
                    "Write-Error $_.Message }; exit 1 }"
                )
                completed = subprocess.run(
                    [pwsh, "-NoLogo", "-NoProfile", "-Command", command],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

if __name__ == "__main__":
    unittest.main(verbosity=2)
