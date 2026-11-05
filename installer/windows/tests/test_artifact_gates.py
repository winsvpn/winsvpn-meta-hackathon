#!/usr/bin/env python3
"""Source-inspection gates for Windows x64/arm64 ZIP, MSIX, WiX, and Inno artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]
WINDOWS = ROOT / "installer/windows"
ZIP_BUILD = (WINDOWS / "build_zip_installer.ps1").read_text(encoding="utf-8")
ZIP_INSTALL = (WINDOWS / "install_winsvpn_zip.ps1").read_text(encoding="utf-8")
MSIX = (WINDOWS / "build_store_msix.ps1").read_text(encoding="utf-8")
APPX = (WINDOWS / "store/AppxManifest.xml.template").read_text(encoding="utf-8")
WIX_X64 = (WINDOWS / "build_winn3_msi.ps1").read_text(encoding="utf-8")
WIX_ARM64 = (WINDOWS / "build_winn3_msi_arm64.ps1").read_text(encoding="utf-8")
VERIFY_ARM64 = (WINDOWS / "verify_arm64_msi_payload.ps1").read_text(encoding="utf-8")
PROVENANCE = (WINDOWS / "dependencies/amneziawg.exe.provenance.json").read_text(
    encoding="utf-8"
)
INNO_BUILD = (WINDOWS / "build_installer.ps1").read_text(encoding="utf-8")
INNO_SIGN = (ROOT / "tools/windows_inno_sign.ps1").read_text(encoding="utf-8")
PWSH = shutil.which("pwsh")
APPROVED_TIMESTAMP_URLS = (
    "http://timestamp.acs.microsoft.com",
    "http://timestamp.digicert.com",
    "https://timestamp.digicert.com",
)
HOSTILE_TIMESTAMP_URLS = (
    "https://evil.example/ts",
    "https://evil.example/ts /f C:\\pwn.pfx",
    "https://timestamp.digicert.com extra",
    "http://timestamp.digicert.com/evil",
    "http://evil.example",
)

X64_VC = "cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b"
X64_MSI = "a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b"
X64_HELPER = "12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41"
X64_AWG = "272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12"
X64_WINTUN = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
X64_XRAY = "fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224"
ARM64_VC = "5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0"
ARM64_MSI = "3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa"
ARM64_MSI_RUNTIME = "25fa81103152699bf416f394059b40d447001c3d0dea5ef889a9426f315e4c0a"
ARM64_AWG = "3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43"
ARM64_WINTUN = "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"
ARM64_XRAY = "c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af"
UNREVIEWED_ARM64_MSI = (
    "1699f9e6b313d8b90ec812f1ed0ec70b7d8d2e129010d179029d6990d9955fca"
)
GO_ARCHIVE_PIN = "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d"
SIGNING_ENV = (
    "WINS_WINDOWS_ARTIFACT_SIGNING_METADATA",
    "WINS_WINDOWS_SIGN_CERT_SHA1",
    "WINS_WINDOWS_SIGN_PFX",
    "WINS_WINDOWS_SIGN_PFX_PASSWORD",
)
SIGNING_BEGIN = "# BEGIN-WINDOWS-PRODUCER-AUTHENTICODE-POLICY"
SIGNING_END = "# END-WINDOWS-PRODUCER-AUTHENTICODE-POLICY"
AWG_BEGIN = "# BEGIN-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT"
AWG_END = "# END-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT"
PRODUCERS = {
    "zip": ZIP_BUILD,
    "msix": MSIX,
    "msi-x64": WIX_X64,
    "msi-arm64": WIX_ARM64,
}
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def marked_block(source: str, begin: str, end: str) -> str:
    return source[source.index(begin) : source.index(end) + len(end)]


def signing_block() -> str:
    return marked_block(ZIP_BUILD, SIGNING_BEGIN, SIGNING_END)


def run_pwsh(script: str, timeout: int = 60) -> tuple[int, str]:
    if PWSH is None:
        raise unittest.SkipTest("pwsh is unavailable")
    env = dict(os.environ)
    for name in (
        *SIGNING_ENV,
        "WINS_WINDOWS_TIMESTAMP_URL",
        "WINS_WINDOWS_SIGNER_SUBJECT_REGEX",
        "WINS_WINDOWS_SIGN_CERT_STORE",
    ):
        env.pop(name, None)
    env["NO_COLOR"] = "1"
    with tempfile.TemporaryDirectory(prefix="winsvpn-gates-") as raw:
        path = pathlib.Path(raw) / "probe.ps1"
        path.write_text(script, encoding="utf-8")
        completed = subprocess.run(
            [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(path)],
            cwd=raw,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    output = ANSI.sub("", completed.stdout + completed.stderr)
    return completed.returncode, " ".join(output.split())


def ps_quote(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


class ZipProducerArtifactGateTests(unittest.TestCase):
    def test_dual_arch_pin_tables_and_default_x64_assignment(self) -> None:
        self.assertIn("[ValidateSet('x64', 'arm64')]", ZIP_BUILD)
        self.assertIn("$ZipDependencyPins = $ZipX64DependencyPins", ZIP_BUILD)
        self.assertIn("$ZipDependencyContract = $ZipX64DependencyContract", ZIP_BUILD)
        self.assertIn(X64_HELPER, ZIP_BUILD)
        self.assertIn(X64_AWG, ZIP_BUILD)
        self.assertIn(X64_MSI, ZIP_BUILD)
        self.assertIn(ARM64_MSI, ZIP_BUILD)
        self.assertIn(ARM64_AWG, ZIP_BUILD)
        self.assertIn(ARM64_WINTUN, ZIP_BUILD)
        self.assertIn(ARM64_XRAY, ZIP_BUILD)
        self.assertIn(ARM64_VC, ZIP_BUILD)
        self.assertIn("source = 'awg-arm64.exe'", ZIP_BUILD)
        self.assertIn("source = 'wintun-arm64.dll'", ZIP_BUILD)
        self.assertIn("source = 'xray-arm64.exe'", ZIP_BUILD)
        self.assertNotIn(UNREVIEWED_ARM64_MSI, ZIP_BUILD)

    def test_arm64_zip_has_no_owner_refusal_and_no_invented_helper_pin(self) -> None:
        self.assertIn("function Initialize-ZipArchitectureContract", ZIP_BUILD)
        self.assertNotIn("owner-blocked", ZIP_BUILD)
        self.assertNotIn("Assert-ZipArchitecturePublicationReady", ZIP_BUILD)
        self.assertIn("amneziawg-arm64.exe", ZIP_BUILD)
        self.assertNotIn(
            "'amneziawg.exe' = [ordered]@{ sha256 =",
            ZIP_BUILD[
                ZIP_BUILD.index("$ZipArm64DependencyPins =") : ZIP_BUILD.index(
                    "$ZipX64DependencyContract ="
                )
            ],
        )
        # The helper contract runs exactly when the pin table pins a helper.
        inputs = ZIP_BUILD[
            ZIP_BUILD.index("function Assert-ZipDependencyInputs") : ZIP_BUILD.index(
                "function Assert-StagedPeMachines"
            )
        ]
        self.assertIn("if ($ZipDependencyPins.Contains('amneziawg.exe')) {", inputs)
        self.assertIn(
            "-ExpectedUnsignedSha256 ([string]$ZipDependencyPins['amneziawg.exe'].sha256)",
            inputs,
        )
        self.assertIn(
            "if ($ZipDependencyPins.Contains('amneziawg.exe')) {\n    Assert-WindowsAwgSchema2OwnerPublicationContract",
            ZIP_BUILD,
        )

    def test_zip_signs_with_the_build_installer_policy_when_configured(self) -> None:
        for marker in (
            "The ZIP route is unsigned by contract",
            "function Assert-ZipAuthenticodePreconditions",
            "OWNER-BLOCKED",
            "publication_authorized",
            "ZIP BUILD: BLOCKED",
            "ZIP BUILD: PASS",
        ):
            self.assertNotIn(marker, ZIP_BUILD)
        self.assertIn("[switch]$RequireCodeSigning,", ZIP_BUILD)
        self.assertIn(
            "$script:ZipSigning = Resolve-WinsProducerSigningConfiguration -RepoRoot $RepoRoot `\n"
            "    -Architecture $TargetArchitecture -RequireSigning:$RequireCodeSigning",
            ZIP_BUILD,
        )
        machines = ZIP_BUILD.index("Assert-StagedPeMachines -StageRoot $stage\n")
        sign = ZIP_BUILD.index("    Invoke-ZipFirstPartySigning -StageRoot $stage\n")
        state = ZIP_BUILD.index("Assert-ZipEngineProductSigningState -StageRoot $stage\n")
        manifest = ZIP_BUILD.index("$manifest = Write-PayloadManifest -StageRoot $stage")
        self.assertLess(machines, sign)
        self.assertLess(sign, state)
        self.assertLess(state, manifest)
        reaudit = ZIP_BUILD[
            ZIP_BUILD.index("function Invoke-ZipExtractedPayloadReaudit") : ZIP_BUILD.index(
                "function Assert-ZipReceiptMatchesArtifact"
            )
        ]
        self.assertIn("Assert-ZipEngineProductSigningState -StageRoot $StageRoot", reaudit)
        self.assertIn("Assert-StagedDependencyPins -StageRoot $StageRoot", reaudit)
        plan = ZIP_BUILD[
            ZIP_BUILD.index("function Get-ZipSignedPayloadPlan") : ZIP_BUILD.index(
                "function Invoke-ZipFirstPartySigning"
            )
        ]
        self.assertIn("StartsWith('dependencies/'", plan)
        self.assertLess(plan.index("$engines"), plan.index("$products"))
        self.assertIn("return @($engines) + @($products)", plan)

    def test_v3_primary_and_v1_awg_then_xray_completeness(self) -> None:
        self.assertNotIn("[switch]$AllowMissingWinn3Carrier", ZIP_BUILD)
        self.assertIn("winsvpn.local/winnprotocol/winn3", ZIP_BUILD)
        self.assertIn("winsvpn_awg_engine.exe was not staged", ZIP_BUILD)
        self.assertIn("dependencies/awg.exe was not staged", ZIP_BUILD)
        self.assertIn("dependencies/xray.exe was not staged", ZIP_BUILD)
        self.assertIn("winn_v3_primary = $true", ZIP_BUILD)
        self.assertIn("winn_v1_awg_then_xray = $true", ZIP_BUILD)
        self.assertIn("schema_version = 2", ZIP_BUILD)

    def test_pe_and_receipt_honesty(self) -> None:
        self.assertIn("$ZipX64PeMachine = [uint16]0x8664", ZIP_BUILD)
        self.assertIn("$ZipArm64PeMachine = [uint16]0xAA64", ZIP_BUILD)
        self.assertIn("$ZipX86PeMachine = [uint16]0x014c", ZIP_BUILD)
        self.assertIn("architecture = $script:ZipArchitecture", ZIP_BUILD)
        self.assertIn("private_symbol_custody_established = $false", ZIP_BUILD)
        self.assertIn("debug_symbols_excluded = $true", ZIP_BUILD)
        self.assertIn("authenticode_status = $zipAuthenticodeStatus", ZIP_BUILD)
        self.assertIn("timestamp_verified = $zipSigned", ZIP_BUILD)
        self.assertIn("signed_payloads = @($script:ZipSignatureEvidence)", ZIP_BUILD)
        self.assertIn("ZIP BUILD: SIGNED", ZIP_BUILD)
        self.assertIn("ZIP BUILD: UNSIGNED REHEARSAL", ZIP_BUILD)
        receipt = ZIP_BUILD[
            ZIP_BUILD.index("function Assert-ZipReceiptMatchesArtifact") : ZIP_BUILD.index(
                AWG_BEGIN
            )
        ]
        self.assertIn("[string]$receipt.authenticode_status -cne $expectedStatus", receipt)
        self.assertIn("[bool]$receipt.timestamp_verified -ne $signed", receipt)
        self.assertNotIn("OWNER-BLOCKED", receipt)


class ZipInstallerArtifactGateTests(unittest.TestCase):
    def test_manifest_selects_architecture_and_keeps_x64_pin_assignment(self) -> None:
        self.assertIn("$ExpectedDependencyPins = [ordered]@{", ZIP_INSTALL)
        self.assertIn("$ExpectedDependencyContract = [ordered]@{", ZIP_INSTALL)
        self.assertIn("function Initialize-ZipInstallArchitecture", ZIP_INSTALL)
        self.assertIn("[int]$manifest.schema_version -ne 2", ZIP_INSTALL)
        self.assertIn("Initialize-ZipInstallArchitecture -Architecture $architecture", ZIP_INSTALL)
        self.assertNotIn("owner-blocked", ZIP_INSTALL)
        self.assertNotIn("native ARM64 ZIP install is unpublished", ZIP_INSTALL)
        self.assertNotIn("exact ZIP schema v2 x64 contract", ZIP_INSTALL)
        pins = ZIP_INSTALL[
            ZIP_INSTALL.index("$ExpectedDependencyPins =") : ZIP_INSTALL.index(
                "$ExpectedDependencyContract ="
            )
        ]
        self.assertIn(X64_HELPER, pins)
        self.assertIn(X64_AWG, pins)
        self.assertNotIn(ARM64_AWG, pins)

    def test_arm64_pins_are_recorded_without_an_invented_helper_hash(self) -> None:
        arm64_pins = ZIP_INSTALL[
            ZIP_INSTALL.index("$ExpectedArm64DependencyPins =") : ZIP_INSTALL.index(
                "$ExpectedArm64DependencyContract ="
            )
        ]
        self.assertIn(ARM64_MSI, arm64_pins)
        self.assertIn(ARM64_AWG, arm64_pins)
        self.assertIn(ARM64_WINTUN, arm64_pins)
        self.assertIn(ARM64_XRAY, arm64_pins)
        self.assertIn(ARM64_VC, arm64_pins)
        self.assertNotIn("amneziawg.exe", arm64_pins)
        self.assertNotIn(UNREVIEWED_ARM64_MSI, ZIP_INSTALL)

    def test_pe_host_and_v3_required_before_elevation(self) -> None:
        self.assertIn("$ZipArm64PeMachine = [uint16]0xAA64", ZIP_INSTALL)
        self.assertIn("normalizedHost -cne [string]$manifest.architecture", ZIP_INSTALL)
        self.assertIn("winn-datapath.exe does not carry the required Winn Protocol v3 marker", ZIP_INSTALL)
        self.assertIn("winsvpn_awg_engine.exe", ZIP_INSTALL)
        self.assertIn("Package contains debug symbol files that must not be installed", ZIP_INSTALL)


class MsixArtifactGateTests(unittest.TestCase):
    def test_production_msix_needs_only_the_partner_center_identity(self) -> None:
        for marker in (
            "Production MSIX generation is disabled",
            "intentionally disabled",
            "OWNER-BLOCKED",
            "owner-blocked",
            "publication_authorized",
            "store_upload_authorized",
            "production_submission_allowed",
            "WINDOWS STORE MSIX CANDIDATE: BLOCKED",
            "WINDOWS STORE MSIX CANDIDATE: PASS",
            "1.0.15",
        ):
            self.assertNotIn(marker, MSIX)
        self.assertIn(
            "} elseif ([string]::IsNullOrWhiteSpace($IdentityName) -or\n"
            "    [string]::IsNullOrWhiteSpace($Publisher) -or\n"
            "    [string]::IsNullOrWhiteSpace($PublisherDisplayName)) {\n"
            "    throw $ProductionMsixBlockedReason\n}",
            MSIX,
        )
        self.assertIn("Production MSIX needs the Partner Center package identity", MSIX)
        self.assertIn("-Production:(-not $DevelopmentIdentity)", MSIX)
        self.assertIn("WINDOWS STORE MSIX CANDIDATE: BUILT", MSIX)

    def test_arm64_msix_refusal_is_policy_while_the_helper_pin_exists(self) -> None:
        self.assertIn(
            "ARM64 MSIX packaging is disabled: this MSIX producer reviews only the x64 dependency pins",
            MSIX,
        )
        self.assertNotIn("(ProductHelperSha256 is unset)", MSIX)
        client = (ROOT / "tools/build_windows_amneziawg_client.ps1").read_text(
            encoding="utf-8"
        )
        start = client.index("    arm64 = @{")
        arm64 = client[start : client.index("}[$TargetArchitecture]", start)]
        self.assertIn(
            "ProductHelperSha256 = '0e88c6d049d0905b5aa1e53c63ffa24f2760701be4b28eee5975b381393ef73f'",
            arm64,
        )
        self.assertIn("ProductHelperBytes = 8483840", arm64)

    def test_msix_version_is_derived_from_pubspec(self) -> None:
        self.assertIn("function Read-MsixPubspecReleaseIdentity", MSIX)
        self.assertIn(
            "$PubspecReleaseIdentity = Read-MsixPubspecReleaseIdentity -Path $Pubspec", MSIX
        )
        self.assertIn(
            '$CanonicalMsixFilename = "WinsVPN-Store-$CanonicalPackageVersion-x64.msix"', MSIX
        )
        self.assertNotRegex(MSIX, r"\$CanonicalPackageVersion\s*=\s*'")

    def test_v3_description_and_native_components(self) -> None:
        self.assertIn("Winn Protocol v3", APPX)
        self.assertIn("Winn v1 AmneziaWG then Xray fallback", APPX)
        self.assertNotIn(
            "Private, censorship-resistant AmneziaWG and Xray VPN connectivity.",
            APPX,
        )
        self.assertIn("'winn-datapath.exe'", MSIX)
        self.assertIn("'winsvpn_winn3_engine.exe'", MSIX)
        self.assertIn("'winsvpn_awg_engine.exe'", MSIX)

    def test_helper_provenance_binds_producer_pins_and_unreviewed_arm64_msi_is_not_a_pin(
        self,
    ) -> None:
        helper = MSIX[
            MSIX.index("function Assert-AmneziaWgHelperProvenance") : MSIX.index(
                "function Assert-OfficialAwg31Dependencies"
            )
        ]
        self.assertNotIn("owner_blocked", helper)
        self.assertIn("unsigned_artifact_sha256 = $Pinned['amneziawg.exe']", helper)
        self.assertIn("go_version = $AmneziaWgHelperGoVersion", helper)
        self.assertIn("go_archive_sha256 = $AmneziaWgHelperGoArchiveSha256", helper)
        self.assertIn("$AmneziaWgHelperGoVersion = '1.27.1'", MSIX)
        self.assertIn(f"$AmneziaWgHelperGoArchiveSha256 = '{GO_ARCHIVE_PIN}'", MSIX)
        self.assertIn(f"'amneziawg.exe' = '{X64_HELPER}'", MSIX)
        self.assertIn(ARM64_MSI, MSIX)
        self.assertIn(UNREVIEWED_ARM64_MSI, MSIX)
        self.assertNotRegex(
            MSIX,
            rf"(?i)'amneziawg-arm64\.msi'\s*=\s*'{UNREVIEWED_ARM64_MSI}'",
        )
        self.assertNotRegex(
            MSIX,
            rf"(?i)'amneziawg-amd64\.msi'\s*=\s*'{UNREVIEWED_ARM64_MSI}'",
        )
        self.assertIn('"schema_version": 2', PROVENANCE)
        self.assertIn('"go_version": "1.27.1"', PROVENANCE)

    def test_committed_arm64_msi_is_the_official_file_and_the_unreviewed_one_stays_rejected(self) -> None:
        # The official 3.1.0 MSI replaced the unreviewed file that used to be committed here.
        # Its digest stays only as a reject value: it must never equal an official pin.
        committed = hashlib.sha256((WINDOWS / "dependencies/amneziawg-arm64.msi").read_bytes()).hexdigest()
        self.assertEqual(committed, ARM64_MSI)
        self.assertNotEqual(committed, UNREVIEWED_ARM64_MSI)
        self.assertNotEqual(ARM64_MSI, UNREVIEWED_ARM64_MSI)
        self.assertNotIn(UNREVIEWED_ARM64_MSI, ZIP_BUILD)

    def test_symbols_pe_and_signing_policy(self) -> None:
        self.assertIn("function Remove-MsixDebugSymbolFiles", MSIX)
        self.assertIn("function Assert-MsixStageCompleteness", MSIX)
        self.assertNotIn("function Assert-MsixAuthenticodePreconditions", MSIX)
        self.assertNotIn("The MSIX route is unsigned and is not a Store upload target", MSIX)
        self.assertIn(
            "$script:MsixSigning = Resolve-WinsProducerSigningConfiguration -RepoRoot $Root `\n"
            "    -Architecture $TargetArchitecture -RequireSigning:$RequireCodeSigning",
            MSIX,
        )
        self.assertIn("$MsixX64PeMachine = [uint16]0x8664", MSIX)
        self.assertIn("private_symbol_custody_established = $false", MSIX)
        self.assertIn(
            'private-release-symbols\\windows\\$($script:StoreArchitecture)\\$($identity.SourceVersion)',
            MSIX,
        )
        self.assertIn("uploaded = $false", MSIX)
        copy = MSIX.index("Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Stage $_.Name) -Recurse -Force")
        sign_payload = MSIX.index("        Invoke-MsixFirstPartySigning -StageRoot $Stage")
        pinned = MSIX.index("$amneziaMsi = Assert-PinnedFile 'amneziawg-amd64.msi'")
        pack = MSIX.index("Invoke-Native $makeAppx @packArgs")
        sign_package = MSIX.index(
            "[void](Invoke-WinsProducerSigning -Path $script:MsixStagedPackage -Signing $script:MsixSigning)"
        )
        unpack = MSIX.index("Invoke-Native $makeAppx @unpackArgs")
        state = MSIX.index(
            "Assert-MsixPackageSignatureState -PackagePath $script:MsixStagedPackage"
        )
        self.assertLess(copy, sign_payload)
        self.assertLess(sign_payload, pinned)
        self.assertLess(pinned, pack)
        self.assertLess(pack, sign_package)
        self.assertLess(sign_package, unpack)
        self.assertLess(unpack, state)
        self.assertIn(
            "throw 'A signed MSIX needs the Partner Center identity: the WinsVPN.Development publisher",
            MSIX,
        )


class WixArtifactGateTests(unittest.TestCase):
    def test_engine_fragments_sign_engines_then_msi_when_configured(self) -> None:
        for source in (WIX_X64, WIX_ARM64):
            self.assertIn("complete_windows_product = $false", source)
            self.assertNotIn("publication_authorized", source)
            self.assertNotIn("OWNER-BLOCKED", source)
            self.assertNotIn("function Assert-WixAuthenticodePreconditions", source)
            self.assertNotIn("refusing to mix signing credentials", source)
            self.assertIn("authenticode_verified = $msiSigned", source)
            self.assertIn("timestamp_verified = $msiSigned", source)
            self.assertIn("authenticode_status = $msiAuthenticodeStatus", source)
            self.assertIn("signed_payloads = @($signedPayloads)", source)
            self.assertIn("payload = @($entries)", source)
            self.assertNotIn("MSI BUILD: PASS", source)
            self.assertNotIn("MSI BUILD: BLOCKED", source)
            self.assertIn("MSI BUILD: SIGNED engine fragment", source)
            self.assertIn("MSI BUILD: UNSIGNED REHEARSAL engine fragment", source)
            self.assertIn("winn_v1_awg_then_xray = $false", source)
            self.assertIn("winsvpn_awg_engine.exe", source)
            self.assertIn("xray.exe", source)
            self.assertIn("debug symbol files", source)
            self.assertIn("[switch]$RequireCodeSigning", source)
            resolve = source.index("$Signing = Resolve-WinsProducerSigningConfiguration")
            stage = source.index("# ---- stage")
            sign_engines = source.index(
                "$evidence = Invoke-WinsProducerSigning -Path $enginePath -Signing $Signing"
            )
            gate = source.index("# ---- the v3 carrier-completeness gate")
            manifest = source.index("# ---- payload manifest")
            build = source.index("# ---- build")
            sign_msi = source.index(
                "$msiSignature = Invoke-WinsProducerSigning -Path $msi -Signing $Signing"
            )
            digest = source.index("$msiHash = Get-Sha256 $msi")
            receipt = source.index("$receipt = [ordered]@{")
            self.assertLess(resolve, stage)
            self.assertLess(stage, sign_engines)
            self.assertLess(sign_engines, gate)
            self.assertLess(gate, manifest)
            self.assertLess(manifest, build)
            self.assertLess(build, sign_msi)
            self.assertLess(sign_msi, digest)
            self.assertLess(digest, receipt)
            loop = source.index("    foreach ($engine in @(")
            engines = source[loop : source.index("\n", loop)]
            self.assertLess(loop, sign_engines)
            self.assertEqual(
                engines,
                "    foreach ($engine in @('winn-datapath.exe', 'winsvpn_winn3_engine.exe')) {",
            )

    def test_wintun_pins_are_architecture_specific(self) -> None:
        self.assertIn(X64_WINTUN, WIX_X64)
        self.assertNotIn(ARM64_WINTUN, WIX_X64)
        self.assertIn(ARM64_WINTUN, WIX_ARM64)
        self.assertNotIn(X64_WINTUN, WIX_ARM64)

    def test_arm64_verifier_throws_on_wrong_pe_or_missing_v3_marker(self) -> None:
        self.assertIn("throw (", VERIFY_ARM64)
        self.assertIn("0xAA64", VERIFY_ARM64)
        self.assertIn("missing the required Winn Protocol v3 marker", VERIFY_ARM64)
        self.assertIn(ARM64_WINTUN, VERIFY_ARM64)
        self.assertIn("Wintun is not a v3 carrier", VERIFY_ARM64)


def _pe(machine: int, marker: bool = False) -> bytes:
    image = bytearray(256)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    data = bytes(image)
    return data + (b"winsvpn.local/winnprotocol/winn3" if marker else b"")


@unittest.skipUnless(PWSH, "pwsh is required")
class WixUnsignedRehearsalExecutionTests(unittest.TestCase):
    """G-W6: with no signing identity the x64 WiX producer builds and records it truthfully."""

    def test_unsigned_rehearsal_receipt_is_truthful(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-wix-") as raw:
            root = pathlib.Path(raw)
            release = root / "release"
            release.mkdir()
            (release / "winn-datapath.exe").write_bytes(_pe(0x8664, marker=True))
            (release / "winsvpn_winn3_engine.exe").write_bytes(_pe(0x8664))
            fake_bin = root / "bin"
            fake_bin.mkdir()
            wix = fake_bin / "wix"
            wix.write_text(
                "#!/usr/bin/env bash\n"
                "while [ \"$#\" -gt 0 ]; do if [ \"$1\" = -o ]; then shift; "
                "printf 'fake msi' > \"$1\"; exit 0; fi; shift; done; exit 2\n",
                encoding="ascii",
            )
            wix.chmod(0o755)
            env = dict(os.environ)
            for name in (*SIGNING_ENV, "WINS_WINDOWS_TIMESTAMP_URL", "WINS_WINDOWS_SIGNER_SUBJECT_REGEX"):
                env.pop(name, None)
            env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
            env["NO_COLOR"] = "1"
            out = root / "out"
            completed = subprocess.run(
                [
                    PWSH, "-NoProfile", "-NonInteractive", "-File", str(WINDOWS / "build_winn3_msi.ps1"),
                    "-EngineDir", str(release), "-DependenciesDir", str(WINDOWS / "dependencies"),
                    "-LicensesDir", str(WINDOWS / "licenses"), "-OutDir", str(out),
                    "-StageDir", str(root / "stage"), "-AppVersion", "1.0.0.0",
                ],
                capture_output=True, text=True, timeout=120, check=False, env=env,
            )
            output = ANSI.sub("", completed.stdout + completed.stderr)
            self.assertEqual(completed.returncode, 0, output)
            self.assertIn("UNSIGNED REHEARSAL engine fragment", output)
            receipt = json.loads(
                (out / "WinsVPN-Winn3-Engines-1.0.0.0-x64.msi.receipt.json").read_text(encoding="utf-8-sig")
            )
            self.assertEqual(receipt["authenticode_status"], "unsigned")
            self.assertIs(receipt["authenticode_verified"], False)
            self.assertIs(receipt["timestamp_verified"], False)
            self.assertEqual(receipt["signing_mode"], "none")
            self.assertEqual(receipt["signed_payloads"], [])
            self.assertNotIn("publication_authorized", receipt)
            self.assertNotIn("owner_authenticode_leaf_sha256", receipt)
            self.assertEqual(
                sorted(entry["name"] for entry in receipt["payload"]),
                ["winn-datapath.exe", "winsvpn_winn3_engine.exe", "wintun.dll"],
            )
            completed = subprocess.run(
                [
                    PWSH, "-NoProfile", "-NonInteractive", "-File", str(WINDOWS / "build_winn3_msi.ps1"),
                    "-EngineDir", str(release), "-DependenciesDir", str(WINDOWS / "dependencies"),
                    "-LicensesDir", str(WINDOWS / "licenses"), "-OutDir", str(root / "out2"),
                    "-StageDir", str(root / "stage2"), "-AppVersion", "1.0.0.0", "-RequireCodeSigning",
                ],
                capture_output=True, text=True, timeout=120, check=False, env=env,
            )
            output = " ".join(ANSI.sub("", completed.stdout + completed.stderr).split())
            self.assertNotEqual(completed.returncode, 0, output)
            self.assertIn("Windows release signing is required", output)
            self.assertFalse((root / "out2").exists() and any((root / "out2").glob("*.msi")))

    def test_receipt_lists_are_not_new_object_wrapped(self) -> None:
        # @() of an empty New-Object List[object] inside an [ordered]@{} literal
        # throws "Argument types do not match" in pwsh 7, so an unsigned
        # rehearsal could never write its receipt.
        for name, source in PRODUCERS.items():
            with self.subTest(producer=name):
                self.assertNotIn("New-Object 'System.Collections.Generic.List[object]'", source)


class SharedProducerSigningPolicyTests(unittest.TestCase):
    """The ZIP, MSIX and both WiX producers carry one signing policy block."""

    def test_signing_block_is_byte_identical_in_every_producer(self) -> None:
        block = signing_block()
        for name, source in PRODUCERS.items():
            with self.subTest(producer=name):
                self.assertEqual(source.count(SIGNING_BEGIN), 1)
                self.assertEqual(marked_block(source, SIGNING_BEGIN, SIGNING_END), block)

    def test_signing_block_keeps_every_build_installer_protection(self) -> None:
        block = signing_block()
        for marker in (
            "Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\\10\\bin'",
            "Release signing tool is outside every approved root",
            "'(^|,\\s*)O=Microsoft Corporation(,|$)'",
            "Get-AuthenticodeSignature -LiteralPath $resolved",
            "Azure.CodeSigning.Dlib.dll",
            "Artifact Signing metadata must be stored outside the repository tree.",
            "'^[a-z0-9-]+\\.codesigning\\.azure\\.net$'",
            "A self-signed certificate is forbidden for production distribution",
            "'1.3.6.1.5.5.7.3.3'",
            "subject does not match WINS_WINDOWS_SIGNER_SUBJECT_REGEX",
            "WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required for a signed release.",
            "PFX command-line signing (WINS_WINDOWS_SIGN_PFX/WINS_WINDOWS_SIGN_PFX_PASSWORD) is disabled",
            "foreach ($forbidden in @('/as', '/f', '/p', '/ac', '/a'))",
            "@('sign', '/v', '/fd', 'SHA256', '/tr', $Timestamp, '/td', 'SHA256', '/d', \"Win's VPN\")",
            "& $SignTool verify /pa /all /v /tw $Path 2>&1 | Out-String",
            "if (-not $signature.TimeStamperCertificate)",
            "Assert-WinsProducerTrustedRootChain -Certificate $signature.SignerCertificate -Path $Path",
            "tools.windows_authenticode.leaf_sha256",
            "The signer does not terminate in AuthRoot or an explicitly pinned Microsoft system root",
        ):
            self.assertIn(marker, block)
        approved = re.search(
            r"\$WinsProducerApprovedTimestampUrls = @\((.*?)\)", block, re.S
        ).group(1)
        reference = re.search(r"\$ApprovedTimestampUrls = @\((.*?)\)", INNO_BUILD, re.S).group(1)
        self.assertEqual(
            sorted(re.findall(r"'([^']+)'", approved)),
            sorted(re.findall(r"'([^']+)'", reference)),
        )
        self.assertEqual(sorted(re.findall(r"'([^']+)'", approved)), sorted(APPROVED_TIMESTAMP_URLS))
        for root in ("3B1EFD3A66EA28B16697394703A72CA340A05BD5", "8F43288AD272F3103B6FB1428485EA3014C0BCFE"):
            self.assertIn(root, block)
            self.assertIn(root, INNO_BUILD)
        # build_installer.ps1's release path ignores these overrides; so must
        # the shared block, in code and in prose alike.
        self.assertNotIn("WINDOWS_SIGNTOOL", block)
        self.assertNotIn("WINS_WINDOWS_ARTIFACT_SIGNING_DLIB", block)
        self.assertNotIn("Get-Command signtool", block)
        self.assertNotIn("localappdata", block.lower())

    def _resolve(self, env: dict[str, str], extra: str = "") -> tuple[int, str]:
        assignments = "\n".join(
            f"Set-Item -Path Env:{name} -Value {ps_quote(value)}" for name, value in env.items()
        )
        script = (
            "$ErrorActionPreference = 'Stop'\n"
            "Set-StrictMode -Version Latest\n"
            f"{signing_block()}\n"
            f"{assignments}\n"
            "try {\n"
            f"    $r = Resolve-WinsProducerSigningConfiguration -RepoRoot {ps_quote(ROOT)} -Architecture x64 {extra}\n"
            "    if ($null -eq $r) { Write-Output 'RESOLVED-UNSIGNED' } else { Write-Output ('RESOLVED-' + $r.Mode) }\n"
            "    exit 0\n"
            "} catch {\n"
            "    Write-Output ('REFUSED: ' + $_.Exception.Message)\n"
            "    exit 2\n"
            "}\n"
        )
        return run_pwsh(script)

    @unittest.skipUnless(PWSH, "pwsh is required")
    def test_resolver_signs_only_with_a_configured_identity_and_refuses_unsafe_ones(self) -> None:
        code, output = self._resolve({})
        self.assertEqual(code, 0, output)
        self.assertIn("RESOLVED-UNSIGNED", output)
        code, output = self._resolve({}, "-RequireSigning")
        self.assertEqual(code, 2, output)
        self.assertIn("Windows release signing is required", output)
        with tempfile.TemporaryDirectory(prefix="winsvpn-signing-meta-") as raw:
            outside = pathlib.Path(raw)
            good = outside / "meta.json"
            good.write_text(
                json.dumps(
                    {
                        "Endpoint": "https://eus.codesigning.azure.net",
                        "CodeSigningAccountName": "account",
                        "CertificateProfileName": "profile",
                    }
                ),
                encoding="utf-8",
            )
            secret = outside / "secret.json"
            secret.write_text(
                json.dumps(
                    {
                        "Endpoint": "https://eus.codesigning.azure.net",
                        "CodeSigningAccountName": "account",
                        "CertificateProfileName": "profile",
                        "AccessToken": "not-allowed",
                    }
                ),
                encoding="utf-8",
            )
            plain_http = outside / "http.json"
            plain_http.write_text(
                json.dumps(
                    {
                        "Endpoint": "http://eus.codesigning.azure.net",
                        "CodeSigningAccountName": "account",
                        "CertificateProfileName": "profile",
                    }
                ),
                encoding="utf-8",
            )
            regex = {"WINS_WINDOWS_SIGNER_SUBJECT_REGEX": "^CN=Example"}
            cases = (
                ({"WINS_WINDOWS_SIGN_PFX": "C:\\evil.pfx"}, "PFX command-line signing"),
                ({"WINS_WINDOWS_SIGN_PFX_PASSWORD": "pw"}, "PFX command-line signing"),
                (
                    {"WINS_WINDOWS_TIMESTAMP_URL": "https://evil.example/ts /f C:\\pwn.pfx"},
                    "exact approved Microsoft/DigiCert RFC 3161 endpoint",
                ),
                (
                    {"WINS_WINDOWS_SIGN_CERT_SHA1": "A" * 40, "WINS_WINDOWS_ARTIFACT_SIGNING_METADATA": str(good), **regex},
                    "not both",
                ),
                ({"WINS_WINDOWS_SIGN_CERT_SHA1": "A" * 40}, "WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required"),
                ({"WINS_WINDOWS_SIGN_CERT_SHA1": "ABC", **regex}, "40-character certificate thumbprint"),
                (
                    {"WINS_WINDOWS_SIGN_CERT_SHA1": "A" * 40, "WINS_WINDOWS_SIGN_CERT_STORE": "Other", **regex},
                    "CurrentUser or LocalMachine",
                ),
                (
                    {"WINS_WINDOWS_ARTIFACT_SIGNING_METADATA": str(ROOT / "pubspec.yaml"), **regex},
                    "outside the repository tree",
                ),
                ({"WINS_WINDOWS_ARTIFACT_SIGNING_METADATA": str(secret), **regex}, "'AccessToken' is forbidden"),
                ({"WINS_WINDOWS_ARTIFACT_SIGNING_METADATA": str(plain_http), **regex}, "regional HTTPS"),
                ({"WINS_WINDOWS_ARTIFACT_SIGNING_METADATA": str(good), **regex}, "Artifact Signing Client Tools were not found"),
            )
            for env, needle in cases:
                with self.subTest(env=sorted(env)):
                    code, output = self._resolve(env)
                    self.assertEqual(code, 2, output)
                    self.assertIn(needle, output)

    @unittest.skipUnless(PWSH, "pwsh is required")
    def test_sign_argv_tool_root_and_leaf_pin_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="winsvpn-leaf-pin-") as raw:
            repo = pathlib.Path(raw)
            (repo / "tools").mkdir()
            pins = repo / "tools/toolchain-pins.json"
            script = (
                "$ErrorActionPreference = 'Stop'\n"
                "Set-StrictMode -Version Latest\n"
                f"{signing_block()}\n"
                "$a = @(New-WinsProducerSignArgumentList -Timestamp 'http://timestamp.digicert.com' "
                "-SignerArguments @('/s', 'My', '/sha1', 'AB') -Target 'C:\\x.exe')\n"
                "Write-Output ('ARGV=' + ($a -join '|'))\n"
                "foreach ($bad in @('/as', '/f', '/p', '/ac', '/a')) {\n"
                "    try { [void](New-WinsProducerSignArgumentList -Timestamp 'http://timestamp.digicert.com' -SignerArguments @($bad, 'x') -Target 'C:\\x.exe'); Write-Output \"ACCEPTED $bad\" }\n"
                "    catch { Write-Output (\"REFUSED $bad \" + $_.Exception.Message) }\n"
                "}\n"
                "try { [void](New-WinsProducerSignArgumentList -Timestamp 'https://evil.example/ts' -SignerArguments @('/s') -Target 'C:\\x.exe'); Write-Output 'ACCEPTED ts' }\n"
                "catch { Write-Output ('REFUSED ts ' + $_.Exception.Message) }\n"
                "try { [void](Assert-WinsProducerMicrosoftReleaseTool -Path $PSCommandPath -AllowedRoots @('/nonexistent-root')); Write-Output 'ACCEPTED tool' }\n"
                "catch { Write-Output ('REFUSED tool ' + $_.Exception.Message) }\n"
                f"Write-Output ('PIN-ABSENT=[' + (Get-WinsProducerAuthenticodeLeafPin -RepoRoot {ps_quote(repo)}) + ']')\n"
                f"Set-Content -LiteralPath {ps_quote(pins)} -Value '{{\"tools\":{{\"windows_authenticode\":{{\"leaf_sha256\":\"{'ab' * 32}\"}}}}}}'\n"
                f"Write-Output ('PIN=' + (Get-WinsProducerAuthenticodeLeafPin -RepoRoot {ps_quote(repo)}))\n"
                f"Set-Content -LiteralPath {ps_quote(pins)} -Value '{{\"tools\":{{\"windows_authenticode\":{{\"leaf_sha256\":\"ABC\"}}}}}}'\n"
                f"try {{ [void](Get-WinsProducerAuthenticodeLeafPin -RepoRoot {ps_quote(repo)}); Write-Output 'ACCEPTED pin' }}\n"
                "catch { Write-Output ('REFUSED pin ' + $_.Exception.Message) }\n"
                "exit 0\n"
            )
            code, output = run_pwsh(script)
        self.assertEqual(code, 0, output)
        self.assertIn(
            "ARGV=sign|/v|/fd|SHA256|/tr|http://timestamp.digicert.com|/td|SHA256|/d|Win's VPN|/s|My|/sha1|AB|C:\\x.exe",
            output,
        )
        for bad in ("/as", "/f", "/p", "/ac", "/a"):
            self.assertIn(f"REFUSED {bad} SignTool argument {bad} is forbidden", output)
        self.assertNotIn("ACCEPTED", output)
        self.assertIn("REFUSED ts The signing timestamp URL must be an exact approved", output)
        self.assertIn("REFUSED tool Release signing tool is outside every approved root", output)
        self.assertIn("PIN-ABSENT=[]", output)
        self.assertIn("PIN=" + "ab" * 32, output)
        self.assertIn("REFUSED pin tools.windows_authenticode.leaf_sha256", output)


SIGNATURE_FIXTURE = r"""
function New-FixtureCertificate {
    param([string]$Subject, $Issuer = $null)
    $key = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $Subject, $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $notBefore = [DateTimeOffset]::UtcNow.AddDays(-1)
    $notAfter = [DateTimeOffset]::UtcNow.AddDays(30)
    if ($null -eq $Issuer) {
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
        return $request.CreateSelfSigned($notBefore, $notAfter)
    }
    # Stay well inside the issuer's validity window so Create never races it.
    return $request.Create($Issuer, $notBefore, [DateTimeOffset]::UtcNow.AddDays(20), [byte[]](1, 2, 3, 4))
}
$script:FixtureRoot = New-FixtureCertificate -Subject 'CN=Fixture Root'
$script:FixtureLeaf = New-FixtureCertificate -Subject 'CN=WIN''S VPN INC., O=WIN''S VPN INC.' -Issuer $script:FixtureRoot
$script:FixtureLeafSha256 = Get-WinsProducerCertificateSha256 -Certificate $script:FixtureLeaf
$script:FixtureState = @{
    Status = [System.Management.Automation.SignatureStatus]::Valid
    Certificate = $script:FixtureLeaf
    Timestamped = $true
    VerifyExit = 0
    VerifyText = 'Successfully verified: x Timestamp Verified by: Fixture TSA'
    SignExit = 0
}
$script:SignToolCalls = New-Object 'System.Collections.Generic.List[string]'
$script:ChainChecks = New-Object 'System.Collections.Generic.List[string]'
function Get-AuthenticodeSignature {
    param([string]$LiteralPath)
    $timestamper = if ($script:FixtureState.Timestamped) { $script:FixtureRoot } else { $null }
    return [pscustomobject]@{
        Status = $script:FixtureState.Status
        SignerCertificate = $script:FixtureState.Certificate
        TimeStamperCertificate = $timestamper
    }
}
# The X509 AuthRoot/Root stores are Windows-only; record that the chain check ran.
function Assert-WinsProducerTrustedRootChain {
    param($Certificate, [string]$Path)
    $script:ChainChecks.Add($Path)
}
function fixture-signtool {
    $script:SignToolCalls.Add(($args -join ' '))
    if ($args[0] -ceq 'sign') {
        $global:LASTEXITCODE = $script:FixtureState.SignExit
        return 'signed'
    }
    $global:LASTEXITCODE = $script:FixtureState.VerifyExit
    return $script:FixtureState.VerifyText
}
function Test-Fixture {
    param([string]$Label, [scriptblock]$Body)
    try { $result = & $Body; Write-Output ("$Label ACCEPTED " + ($result | ConvertTo-Json -Compress)) }
    catch { Write-Output ("$Label REFUSED " + $_.Exception.Message) }
}
"""


@unittest.skipUnless(PWSH, "pwsh is required")
class SharedProducerSignatureVerificationTests(unittest.TestCase):
    """G-W6: a signed producer verifies exactly what build_installer.ps1 verifies."""

    def _run(self, body: str) -> str:
        script = (
            "$ErrorActionPreference = 'Stop'\n"
            "Set-StrictMode -Version Latest\n"
            f"{signing_block()}\n"
            f"{SIGNATURE_FIXTURE}\n"
            f"{body}\n"
            "exit 0\n"
        )
        code, output = run_pwsh(script, timeout=120)
        self.assertEqual(code, 0, output)
        return output

    def test_signature_verification_enforces_signer_chain_leaf_and_timestamp(self) -> None:
        verify = (
            "-Path 'C:\\pkg\\x.exe' -SignerPattern '^CN=WIN''S VPN INC\\.' -SignTool 'fixture-signtool'"
        )
        output = self._run(
            "Write-Output ('LEAF=' + $script:FixtureLeafSha256)\n"
            f"Test-Fixture 'plain' {{ Assert-WinsProducerSignature {verify} }}\n"
            f"Test-Fixture 'pinned' {{ Assert-WinsProducerSignature {verify} -ExpectedLeafSha256 $script:FixtureLeafSha256 }}\n"
            f"Test-Fixture 'otherpin' {{ Assert-WinsProducerSignature {verify} -ExpectedLeafSha256 ('0' * 64) }}\n"
            "Write-Output ('CALLS=' + ($script:SignToolCalls -join ';'))\n"
            "Write-Output ('CHAINS=' + $script:ChainChecks.Count)\n"
            "Test-Fixture 'subject' { Assert-WinsProducerSignature -Path 'C:\\pkg\\x.exe' -SignerPattern '^CN=Someone Else' -SignTool 'fixture-signtool' }\n"
            "$script:FixtureState.Status = [System.Management.Automation.SignatureStatus]::NotSigned\n"
            f"Test-Fixture 'status' {{ Assert-WinsProducerSignature {verify} }}\n"
            "$script:FixtureState.Status = [System.Management.Automation.SignatureStatus]::Valid\n"
            "$script:FixtureState.Certificate = $script:FixtureRoot\n"
            "Test-Fixture 'selfsigned' { Assert-WinsProducerSignature -Path 'C:\\pkg\\x.exe' -SignerPattern '^CN=Fixture Root' -SignTool 'fixture-signtool' }\n"
            "$script:FixtureState.Certificate = $script:FixtureLeaf\n"
            "$script:FixtureState.Timestamped = $false\n"
            f"Test-Fixture 'notimestamp' {{ Assert-WinsProducerSignature {verify} }}\n"
            "$script:FixtureState.Timestamped = $true\n"
            "$script:FixtureState.VerifyExit = 1\n"
            f"Test-Fixture 'verifyexit' {{ Assert-WinsProducerSignature {verify} }}\n"
            "$script:FixtureState.VerifyExit = 0\n"
            "$script:FixtureState.VerifyText = 'Successfully verified: x'\n"
            f"Test-Fixture 'verifynots' {{ Assert-WinsProducerSignature {verify} }}\n"
            "$script:FixtureState.VerifyText = 'SignTool Error: x Timestamp Verified by: y'\n"
            f"Test-Fixture 'verifyfail' {{ Assert-WinsProducerSignature {verify} }}\n"
        )
        leaf = re.search(r"LEAF=([0-9a-f]{64})", output).group(1)
        self.assertRegex(output, r"plain ACCEPTED .*\"signer_leaf_sha256\":\"" + leaf)
        self.assertIn('"signer_subject":"CN=WIN\'S VPN INC., O=WIN\'S VPN INC."', output)
        self.assertIn('"timestamp_verified":true', output)
        self.assertIn("pinned ACCEPTED", output)
        self.assertIn(
            "otherpin REFUSED Authenticode leaf certificate of C:\\pkg\\x.exe does not match "
            "tools.windows_authenticode.leaf_sha256",
            output,
        )
        self.assertIn(
            "CALLS=verify /pa /all /v /tw C:\\pkg\\x.exe;verify /pa /all /v /tw C:\\pkg\\x.exe", output
        )
        self.assertIn("CHAINS=3", output)
        self.assertIn("subject REFUSED Product signature verification failed", output)
        self.assertIn("status REFUSED Product signature verification failed", output)
        self.assertIn("selfsigned REFUSED A self-signed certificate is forbidden", output)
        self.assertIn("notimestamp REFUSED The Authenticode signature on C:\\pkg\\x.exe is missing a trusted timestamp", output)
        for label in ("verifyexit", "verifynots", "verifyfail"):
            self.assertIn(f"{label} REFUSED SignTool policy/timestamp verification failed", output)

    def test_signing_runs_the_reviewed_argv_then_verifies(self) -> None:
        output = self._run(
            "$signing = [pscustomobject]@{ Mode = 'certificate-store'; SignTool = 'fixture-signtool'; "
            "SignerArguments = @('/s', 'My', '/sha1', ('A' * 40)); TimestampUrl = 'http://timestamp.digicert.com'; "
            "SignerPattern = '^CN=WIN''S VPN INC\\.'; LeafSha256Pin = '' }\n"
            "Test-Fixture 'sign' { Invoke-WinsProducerSigning -Path 'C:\\pkg\\x.exe' -Signing $signing }\n"
            "Write-Output ('CALLS=' + ($script:SignToolCalls -join ';'))\n"
            "$script:SignToolCalls.Clear()\n"
            "$script:FixtureState.SignExit = 1\n"
            "Test-Fixture 'signfail' { Invoke-WinsProducerSigning -Path 'C:\\pkg\\x.exe' -Signing $signing }\n"
            "Write-Output ('FAILCALLS=' + ($script:SignToolCalls -join ';'))\n"
            "$script:FixtureState.SignExit = 0\n"
            "$signing.LeafSha256Pin = ('0' * 64)\n"
            "Test-Fixture 'signpin' { Invoke-WinsProducerSigning -Path 'C:\\pkg\\x.exe' -Signing $signing }\n"
            "$signing.LeafSha256Pin = ''\n"
            "$signing.TimestampUrl = 'https://evil.example/ts'\n"
            "Test-Fixture 'signts' { Invoke-WinsProducerSigning -Path 'C:\\pkg\\x.exe' -Signing $signing }\n"
        )
        self.assertIn("sign ACCEPTED", output)
        self.assertIn(
            "CALLS=sign /v /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /d Win's VPN /s My /sha1 "
            + "A" * 40
            + " C:\\pkg\\x.exe;verify /pa /all /v /tw C:\\pkg\\x.exe",
            output,
        )
        self.assertIn("signfail REFUSED Authenticode signing failed for C:\\pkg\\x.exe.", output)
        self.assertNotIn("FAILCALLS=sign /v /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /d Win's VPN /s My /sha1 " + "A" * 40 + " C:\\pkg\\x.exe;verify", output)
        self.assertIn("signpin REFUSED Authenticode leaf certificate", output)
        self.assertIn("signts REFUSED The signing timestamp URL must be an exact approved", output)

    def test_signature_verification_pins_the_committed_publisher_identity(self) -> None:
        # The environment regex is the README_FINAL_DEPLOYMENT.md value. It
        # alone matches every subject below (PowerShell -match ignores case);
        # the committed CN and O pin accepts only the exact publisher.
        accepted = {
            "exact": "CN=WIN'S VPN INC., O=WIN'S VPN INC.",
            "quoted": "CN=\"WIN'S VPN INC.\", O=\"WIN'S VPN INC.\"",
            "reordered": "O=WIN'S VPN INC., CN=WIN'S VPN INC.",
        }
        refused = {
            "lookalike": "CN=WIN'S VPN INC. Lookalike, O=WIN'S VPN INC.",
            "noorg": "CN=WIN'S VPN INC.",
            "twocn": "CN=WIN'S VPN INC., CN=Other, O=WIN'S VPN INC.",
            "samecntwice": "CN=WIN'S VPN INC., CN=WIN'S VPN INC., O=WIN'S VPN INC.",
            "twoorg": "CN=WIN'S VPN INC., O=WIN'S VPN INC., O=WIN'S VPN INC.",
            "lowercase": "CN=win's vpn inc., O=win's vpn inc.",
            "lowerorg": "CN=WIN'S VPN INC., O=win's vpn inc.",
            "othercn": "CN=Someone Else, O=WIN'S VPN INC.",
            "quotedcomma": "CN=\"WIN'S VPN INC., O=WIN'S VPN INC.\", O=Evil WIN'S VPN INC.",
            "escapedcomma": "CN=WIN'S VPN INC.\\, O=WIN'S VPN INC.",
        }
        verify = (
            "-Path 'C:\\pkg\\x.exe' -SignerPattern 'WIN''S VPN INC\\.' -SignTool 'fixture-signtool'"
        )
        lines = []
        for label, subject in {**accepted, **refused}.items():
            lines.append(
                f"$script:FixtureState.Certificate = New-FixtureCertificate -Subject {ps_quote(subject)} "
                "-Issuer $script:FixtureRoot"
            )
            lines.append(f"Test-Fixture '{label}' {{ Assert-WinsProducerSignature {verify} }}")
        # A line break inside the CN would otherwise forge a decoded O= line.
        lines.append(
            "$builder = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameBuilder]::new()\n"
            "$builder.AddCommonName(\"WIN'S VPN INC.`nO=WIN'S VPN INC.\")\n"
            "$key = [System.Security.Cryptography.RSA]::Create(2048)\n"
            "$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("
            "$builder.Build(), $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, "
            "[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)\n"
            "$script:FixtureState.Certificate = $request.Create($script:FixtureRoot, "
            "[DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(20), [byte[]](5, 6, 7, 8))"
        )
        lines.append(f"Test-Fixture 'newline' {{ Assert-WinsProducerSignature {verify} }}")
        output = self._run("\n".join(lines) + "\n")
        for label in accepted:
            self.assertIn(f"{label} ACCEPTED", output)
        for label in (*refused, "newline"):
            self.assertIn(
                f"{label} REFUSED Authenticode signer of C:\\pkg\\x.exe is not the reviewed "
                "WIN'S VPN INC. publisher",
                output,
            )
            self.assertNotIn(f"{label} ACCEPTED", output)


def _producer_provenance(digest: str, **overrides: object) -> dict[str, object]:
    evidence: dict[str, object] = {
        "schema_version": 2,
        "publication_transaction_id": "0123456789abcdef0123456789abcdef",
        "publication_contract": "winsvpn.windows-awg-publication.v2",
        "provenance_is_commit_marker": True,
        "source_repository": "https://github.com/amnezia-vpn/amneziawg-windows-client.git",
        "source_version": "3.1.0",
        "source_commit": "ca5dd3b983bd19c335ab095ccd21fc2f804ec968",
        "source_go_mod_sha256": "ad578b6a2107ae4c1bab214c8057e89608ac516d6e381675c3d9441ccc4da70a",
        "source_go_sum_sha256": "268286d6183ec93c39e5295e73e660d9920481c66ecff8331ab64fa082230723",
        "source_build_bat_sha256": "c501fd947d08a4bfdb29f65a9f06ced004779be7a90a125f703c1c5a5130350b",
        "patched_build_bat_sha256": "79bd946166bc6e87d4ff1602889557590703fc8a64737fbfe7f0b64ebda431d7",
        "windows_library_repository": "https://github.com/amnezia-vpn/amneziawg-windows.git",
        "windows_library_version": "v3.1.20260814",
        "windows_library_commit": "e90531d15802cb976773f3b63443bc281f738ca3",
        "engine_module": "github.com/amnezia-vpn/amneziawg-go/v3",
        "engine_version": "v3.1.20260828",
        "engine_commit": "b5928efb6ca19f0153958460c3d141f04abc5c2e",
        "go_version": "1.27.1",
        "go_archive": "go1.27.1.windows-amd64.zip",
        "go_archive_sha256": GO_ARCHIVE_PIN,
        "go_toolchain_policy": "verified_archive_only",
        "go_module_policy": "readonly",
        "go_checksum_database": "sum.golang.org",
        "build_patch_sha256": "a5ad25797aadc29f0e7aa0bf91e6197ce57c48cb845194a18ae7c2dbbebadcbd",
        "target": "windows-amd64",
        "unsigned_artifact_sha256": digest,
        "expected_unsigned_artifact_sha256": digest,
        "authenticode_status": "pending_release_signing",
        "release_signing_required": True,
        "helper_kind": "canonical_unsigned_product_maintenance_helper",
        "signing_boundary": "release_staged_copy_only",
        "module_build_info": [
            "\tdep\tgithub.com/amnezia-vpn/amneziawg-go/v3\tv3.1.20260828\th1:test=",
            "\tdep\tgithub.com/amnezia-vpn/amneziawg-windows/v3\tv3.1.20260814\th1:test=",
        ],
    }
    evidence.update(overrides)
    return evidence


@unittest.skipUnless(PWSH, "pwsh is required")
class ZipAwgHelperContractTests(unittest.TestCase):
    """G-W3: the ZIP helper contract accepts what the real producer writes."""

    def _probe(self, evidence: object, helper: bytes, pin: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory(prefix="winsvpn-awg-contract-") as raw:
            root = pathlib.Path(raw)
            helper_path = root / "amneziawg.exe"
            helper_path.write_bytes(helper)
            provenance = root / "amneziawg.exe.provenance.json"
            if isinstance(evidence, str):
                provenance.write_text(evidence, encoding="utf-8")
            else:
                provenance.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            script = (
                "$ErrorActionPreference = 'Stop'\n"
                f"{marked_block(ZIP_BUILD, AWG_BEGIN, AWG_END)}\n"
                "try {\n"
                "    Assert-WindowsAwgSchema2OwnerPublicationContract `\n"
                f"        -ProvenancePath {ps_quote(provenance)} `\n"
                f"        -HelperPath {ps_quote(helper_path)} `\n"
                f"        -ExpectedUnsignedSha256 {ps_quote(pin)} `\n"
                "        -ExpectedTarget 'windows-amd64'\n"
                "    Write-Output 'CONTRACT-ACCEPTED'\n"
                "    exit 0\n"
                "} catch {\n"
                "    Write-Output ('CONTRACT-REFUSED: ' + $_.Exception.Message)\n"
                "    exit 2\n"
                "}\n"
            )
            return run_pwsh(script)

    def test_producer_output_without_owner_tokens_is_accepted(self) -> None:
        helper = b"winsvpn-awg-helper-fixture"
        digest = hashlib.sha256(helper).hexdigest()
        code, output = self._probe(_producer_provenance(digest), helper, digest)
        self.assertEqual(code, 0, output)
        self.assertIn("CONTRACT-ACCEPTED", output)

    def test_committed_generation_is_accepted(self) -> None:
        helper = (WINDOWS / "dependencies/amneziawg.exe").read_bytes()
        self.assertEqual(hashlib.sha256(helper).hexdigest(), X64_HELPER)
        code, output = self._probe(PROVENANCE, helper, X64_HELPER)
        self.assertEqual(code, 0, output)
        self.assertIn("CONTRACT-ACCEPTED", output)

    def test_real_pins_still_refuse(self) -> None:
        helper = b"winsvpn-awg-helper-fixture"
        digest = hashlib.sha256(helper).hexdigest()
        other = "cd" * 32
        probes = {
            "go-1.27.0": (_producer_provenance(digest, go_version="1.27.0"), helper, digest, "go_version"),
            "go-archive": (
                _producer_provenance(digest, go_archive_sha256="f0c0a0d33ba94f4d2c5dbc887334ce678b21813504ddb3aafcb06e60a5a667c4"),
                helper,
                digest,
                "go_archive_sha256",
            ),
            "source-commit": (_producer_provenance(digest, source_commit="0" * 40), helper, digest, "source_commit"),
            "target": (_producer_provenance(digest, target="windows-arm64"), helper, digest, "target"),
            "schema-1": (_producer_provenance(digest, schema_version=1), helper, digest, "schema_version"),
            "string-schema": (_producer_provenance(digest, schema_version="2"), helper, digest, "schema_version"),
            "helper-bytes": (_producer_provenance(digest), b"tampered-helper", digest, "unsigned digest"),
            "provenance-not-pin": (
                _producer_provenance(other),
                helper,
                digest,
                "unsigned digest",
            ),
            "module-identity": (
                _producer_provenance(
                    digest,
                    module_build_info=["\tdep\tgithub.com/other/mod\tv1\th1:x=", "\tbuild\tGOOS=windows"],
                ),
                helper,
                digest,
                "AWG 3.1 module identities",
            ),
            "committed-provenance-foreign-helper": (PROVENANCE, helper, digest, "unsigned digest"),
            "committed-provenance-go-1.27.0": (
                PROVENANCE.replace('"go_version": "1.27.1"', '"go_version": "1.27.0"', 1),
                (WINDOWS / "dependencies/amneziawg.exe").read_bytes(),
                X64_HELPER,
                "go_version",
            ),
        }
        for name, (evidence, helper_bytes, pin, needle) in probes.items():
            with self.subTest(probe=name):
                code, output = self._probe(evidence, helper_bytes, pin)
                self.assertEqual(code, 2, output)
                self.assertIn("CONTRACT-REFUSED", output)
                self.assertIn(needle, output)
                self.assertNotIn("owner_blocked", output)

    def test_zip_passes_the_producer_pin_not_the_file_hash(self) -> None:
        calls = re.findall(
            r"Assert-WindowsAwgSchema2OwnerPublicationContract `\n(?:.*`\n)*?\s*-ExpectedUnsignedSha256 ([^\n]*)",
            ZIP_BUILD,
        )
        self.assertEqual(len(calls), 2, calls)
        for argument in calls:
            self.assertIn("$ZipDependencyPins['amneziawg.exe'].sha256", argument)
        self.assertIn(f"'amneziawg.exe' = [ordered]@{{ sha256 = '{X64_HELPER}'", ZIP_BUILD)
        client = (ROOT / "tools/build_windows_amneziawg_client.ps1").read_text(encoding="utf-8")
        self.assertIn(f"ProductHelperSha256 = '{X64_HELPER}'", client)


class PrerequisiteCustodyHonestyTests(unittest.TestCase):
    def test_tree_does_not_invent_missing_prerequisite_provenance(self) -> None:
        # amneziawg-arm64.exe, awg-arm64.exe and amneziawg-arm64.exe.provenance.json are no
        # longer invented: they are the published outputs of the reviewed ARM64 dependency
        # producer, pinned by build_installer.ps1 (tools/test_windows_arm64_dependency_set.py).
        deps = WINDOWS / "dependencies"
        for name in (
            "VC_redist.x64.exe.provenance.json",
            "VC_redist.arm64.exe.provenance.json",
            "amneziawg-amd64.msi.provenance.json",
            "amneziawg-arm64.msi.provenance.json",
        ):
            self.assertFalse(
                (deps / name).exists(),
                f"do not invent {name}",
            )


def _approved_timestamp_block(source: str) -> str:
    start = source.index("$ApprovedTimestampUrls = @(")
    return source[start : source.index(")", start)]


class InnoProducerSigningGateTests(unittest.TestCase):
    def test_timestamp_policy_is_exact_allowlist_not_arbitrary_https(self) -> None:
        producer = _approved_timestamp_block(INNO_BUILD)
        wrapper = _approved_timestamp_block(INNO_SIGN)
        for url in APPROVED_TIMESTAMP_URLS:
            quoted = "'" + url + "'"
            self.assertIn(quoted, producer)
            self.assertIn(quoted, wrapper)
            self.assertIn(url, INNO_BUILD)
            self.assertIn(url, INNO_SIGN)
        self.assertEqual(producer.count("http://"), 2)
        self.assertEqual(producer.count("https://"), 1)
        self.assertEqual(wrapper.count("http://"), 2)
        self.assertEqual(wrapper.count("https://"), 1)
        self.assertIn("function Assert-ApprovedTimestampUrl", INNO_BUILD)
        self.assertIn("function Assert-ApprovedTimestampUrl", INNO_SIGN)
        self.assertIn(
            "The signing timestamp URL must be an exact approved Microsoft/DigiCert RFC 3161 endpoint.",
            INNO_BUILD,
        )
        self.assertIn(
            "The signing timestamp URL must be an exact approved Microsoft/DigiCert RFC 3161 endpoint.",
            INNO_SIGN,
        )
        self.assertIn("Assert-ApprovedTimestampUrl -Value $signingTimestampUrl", INNO_BUILD)
        self.assertNotIn(
            "WINS_WINDOWS_TIMESTAMP_URL must use HTTPS or the exact DigiCert RFC 3161 HTTP endpoint.",
            INNO_BUILD,
        )
        self.assertNotIn("$TimestampUrl -notmatch '^https://'", INNO_BUILD)
        self.assertNotIn("$signingTimestampUrl -notmatch '^https://'", INNO_BUILD)
        self.assertNotIn("$configuration.Timestamp -notmatch '^https://'", INNO_SIGN)
        for hostile in HOSTILE_TIMESTAMP_URLS:
            self.assertNotIn(hostile, producer)
            self.assertNotIn(hostile, wrapper)
            self.assertIn(hostile, INNO_BUILD)
            self.assertIn(hostile, INNO_SIGN)
        self.assertIn(
            "Signing policy self-test accepted hostile timestamp $url",
            INNO_BUILD,
        )
        self.assertIn(
            "Inno signing self-test accepted hostile timestamp $url",
            INNO_SIGN,
        )

    def test_x64_arm64_product_and_embedded_engine_signing_order(self) -> None:
        pe_gate = INNO_BUILD.index("Assert-StagedReleasePeMachines")
        timestamp = INNO_BUILD.index(
            "Assert-ApprovedTimestampUrl -Value $signingTimestampUrl"
        )
        product = INNO_BUILD.index("Invoke-ProductSigning -Path $binary.FullName")
        awg = INNO_BUILD.index("Invoke-ProductSigning -Path $stagedAmneziaWg")
        xray = INNO_BUILD.index("Invoke-ProductSigning -Path $stagedXray")
        enable = INNO_BUILD.index("$innoArguments += '/DEnableSigning=1'")
        wrapper_hook = INNO_BUILD.index(
            '$innoArguments += "/Swinsvpn=$innoSignCommand"'
        )
        iscc = INNO_BUILD.index("& $iscc @innoArguments")
        staged_installer = INNO_BUILD.index(
            "Assert-ProductSignature -Path $stagedInstaller"
        )
        self.assertLess(timestamp, product)
        self.assertLess(pe_gate, product)
        self.assertLess(product, awg)
        self.assertLess(awg, xray)
        self.assertLess(xray, enable)
        self.assertLess(enable, wrapper_hook)
        self.assertLess(wrapper_hook, iscc)
        self.assertLess(iscc, staged_installer)
        self.assertIn(
            "$innoSignCommand = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $q' + $InnoSigningWrapper + '$q -TargetFile $f'",
            INNO_BUILD,
        )
        self.assertIn("tools\\windows_inno_sign.ps1", INNO_BUILD)
        self.assertIn(
            "$installerArchitectureSuffix = if ($TargetArchitecture -ceq 'arm64') { '-arm64' } else { '' }",
            INNO_BUILD,
        )
        self.assertIn(
            '"WinsVPN-Setup$installerArchitectureSuffix.exe"', INNO_BUILD
        )
        self.assertIn(
            '"WinsVPN-PartnerCenter$installerArchitectureSuffix.exe"', INNO_BUILD
        )
        for name in (
            "WinsVPN-Setup.exe",
            "WinsVPN-Setup-arm64.exe",
            "WinsVPN-PartnerCenter.exe",
            "WinsVPN-PartnerCenter-arm64.exe",
            "uninst.e32.tmp",
        ):
            self.assertIn("'" + name + "'", INNO_SIGN)
        for engine in (
            "amneziawg.exe",
            "awg.exe",
            "xray.exe",
            "wins_vpn.exe",
            "wins_vpn_tunnel_service.exe",
        ):
            self.assertIn("'" + engine + "'", INNO_SIGN)
        self.assertIn(
            "Inno signing target refuses engine/product payload", INNO_SIGN
        )
        self.assertIn("[ValidateSet('x64', 'arm64')]", INNO_BUILD)

    def test_product_sign_argv_matches_inno_wrapper_contract(self) -> None:
        self.assertIn("function New-ProductSignArgumentList", INNO_BUILD)
        self.assertIn("function New-InnoSignArgumentList", INNO_SIGN)
        argv = (
            "@('sign', '/v', '/fd', 'SHA256', '/tr', $Timestamp, "
            "'/td', 'SHA256', '/d', \"Win's VPN\")"
        )
        self.assertIn(argv, INNO_BUILD)
        self.assertIn(argv, INNO_SIGN)
        self.assertIn("& $SignTool @signArgs", INNO_BUILD)
        self.assertIn("& $signTool @signArgs", INNO_SIGN)
        self.assertNotIn(
            "& $SignTool sign /v /fd SHA256 /tr $SigningTimestampUrl",
            INNO_BUILD,
        )
        self.assertIn("'/as', '/f', '/p', '/ac', '/a'", INNO_BUILD)
        self.assertIn("'/as', '/f', '/p', '/ac', '/a'", INNO_SIGN)
        self.assertIn(
            "SignTool argument $forbidden is forbidden for release signing.",
            INNO_BUILD,
        )
        self.assertIn(
            "SignTool argument $forbidden is forbidden for release signing.",
            INNO_SIGN,
        )
        self.assertIn(
            "Signing policy self-test accepted a hostile timestamp in argv construction.",
            INNO_BUILD,
        )
        self.assertIn(
            "Signing policy self-test accepted appending an additional Authenticode signature.",
            INNO_BUILD,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
