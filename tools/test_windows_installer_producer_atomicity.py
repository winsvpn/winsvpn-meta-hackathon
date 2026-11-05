import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCER = (ROOT / "installer/windows/build_installer.ps1").read_text(
    encoding="utf-8"
)


def body(start: str, end: str) -> str:
    begin = PRODUCER.index(start)
    return PRODUCER[begin : PRODUCER.index(end, begin)]


class WindowsInstallerProducerAtomicityTests(unittest.TestCase):
    def test_verified_download_uses_unique_same_directory_temporary_files(self) -> None:
        download = body("function Get-VerifiedDownload", "function Write-AtomicNewUtf8File")
        for marker in (
            "[guid]::NewGuid().ToString('N')",
            "Save-Download -Uri $Uri -OutFile $temporary",
            "Test-FileSha256 -Path $temporary",
            "[IO.File]::Move($temporary, $OutFile)",
            "finally",
            "Remove-Item -LiteralPath $temporary",
            "MaximumAttempts = 2",
            "Rejected download cache could not be removed safely",
        ):
            self.assertIn(marker, download)
        self.assertLess(
            download.index("Test-FileSha256 -Path $temporary"),
            download.index("[IO.File]::Move($temporary, $OutFile)"),
        )
        self.assertLess(
            download.index("& $AdditionalValidation $temporary"),
            download.index("[IO.File]::Move($temporary, $OutFile)"),
        )

    def test_vc_and_msi_prerequisites_are_pin_bound_without_network_fetch(self) -> None:
        self.assertNotIn("Get-VerifiedDownload -Uri $VcRedistUrl", PRODUCER)
        self.assertNotIn("Get-VerifiedDownload -Uri $AmneziaWgUrl", PRODUCER)
        self.assertIn("function Assert-WinsEmbeddedPrerequisiteCustody", PRODUCER)
        self.assertIn("Re-verifying embedded prerequisite custody immediately before ISCC", PRODUCER)
        self.assertIn("/DVcRedistExpectedSha256=", PRODUCER)
        self.assertIn("/DAmneziaWgMsiExpectedSha256=", PRODUCER)
        self.assertIn("SkipRuntimeDownload never fetches VC_redist", PRODUCER)
        custody = body(
            "# BEGIN-WINDOWS-EMBEDDED-PREREQUISITE-CUSTODY",
            "# END-WINDOWS-EMBEDDED-PREREQUISITE-CUSTODY",
        )
        self.assertIn("hardlink refused", custody)
        self.assertIn("reparse point rejected", custody)
        self.assertIn("function Assert-WinsPrerequisitePin", custody)
        self.assertIn("Assert-WinsPrerequisitePin -Kind $Kind -ExpectedSha256 $ExpectedSha256", custody)
        self.assertNotIn("owner-blocked", custody)
        self.assertNotIn("Read-WinsPrerequisiteProvenance", PRODUCER)
        self.assertNotIn("$VcRedistProvenance", PRODUCER)
        self.assertNotIn("$AmneziaWgMsiProvenance", PRODUCER)

    def test_stale_canonical_outputs_are_quarantined_before_build_work(self) -> None:
        main = PRODUCER[PRODUCER.index("Enter-ReleaseBuildLock\ntry {") :]
        quarantine = main.index("Quarantine-CanonicalInstallerOutputs")
        metadata = main.index("Assert-ReleaseImageMetadataClean")
        iscc = main.index("& $iscc @innoArguments")
        self.assertLess(quarantine, metadata)
        self.assertLess(quarantine, iscc)
        quarantine_body = body(
            "function Quarantine-CanonicalInstallerOutputs",
            "function Assert-AuthenticodeSigner",
        )
        self.assertIn("$CanonicalInstaller", quarantine_body)
        self.assertIn("$CanonicalPayloadManifest", quarantine_body)
        self.assertIn(".artifacts\\quarantine\\windows-installer", quarantine_body)
        self.assertIn("Move-Item -LiteralPath $path", quarantine_body)
        self.assertIn("finally", quarantine_body)
        self.assertIn("Remove-Item -LiteralPath $path", quarantine_body)
        self.assertIn("Stale canonical Windows output survived quarantine", quarantine_body)

    def test_iscc_compiles_to_isolated_stage_then_atomically_publishes(self) -> None:
        compile_part = PRODUCER[PRODUCER.index("$script:IsccStageDir =") :]
        self.assertIn('"/DOutputDir=$($script:IsccStageDir)"', compile_part)
        self.assertIn("$stagedInstaller", compile_part)
        self.assertIn("Assert-ProductSignature -Path $stagedInstaller", compile_part)
        self.assertIn("[IO.File]::Move($stagedInstaller, $CanonicalInstaller)", compile_part)
        self.assertIn("$script:CanonicalInstallerPublishedByThisRun = $true", compile_part)
        self.assertLess(
            compile_part.index("Assert-ProductSignature -Path $stagedInstaller"),
            compile_part.index("[IO.File]::Move($stagedInstaller, $CanonicalInstaller)"),
        )

    def test_manifest_and_failure_cleanup_are_transactional(self) -> None:
        writer = body("function Write-AtomicNewUtf8File", "function Quarantine-CanonicalInstallerOutputs")
        self.assertIn("[IO.FileMode]::CreateNew", writer)
        self.assertIn("$stream.Flush($true)", writer)
        self.assertIn("[IO.File]::Move($temporary, $Path)", writer)
        self.assertIn("finally", writer)
        self.assertIn("Write-AtomicNewUtf8File -Path $manifestPath", PRODUCER)
        cleanup = PRODUCER[PRODUCER.rindex("} catch {") :]
        self.assertIn("$script:CanonicalManifestPublishedByThisRun", cleanup)
        self.assertIn("Remove-Item -LiteralPath $CanonicalPayloadManifest", cleanup)
        self.assertIn("$script:CanonicalInstallerPublishedByThisRun", cleanup)
        self.assertIn("Remove-Item -LiteralPath $CanonicalInstaller", cleanup)
        self.assertIn("Remove-Item -LiteralPath $script:IsccStageDir", cleanup)


if __name__ == "__main__":
    unittest.main()
