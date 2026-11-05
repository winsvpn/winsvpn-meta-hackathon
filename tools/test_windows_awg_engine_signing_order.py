import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILDER = (ROOT / "tools" / "build_windows_awg_engine.ps1").read_text(
    encoding="utf-8"
)
INSTALLER = (
    ROOT / "installer" / "windows" / "build_installer.ps1"
).read_text(encoding="utf-8")
INNO_SIGN = (ROOT / "tools" / "windows_inno_sign.ps1").read_text(encoding="utf-8")


class WindowsAwgEngineSigningOrderTests(unittest.TestCase):
    def test_builder_has_explicit_two_phase_execution_guard(self) -> None:
        for fragment in (
            "[switch]$DeferExecutionGuard",
            "[switch]$FinalizeExecutionGuard",
            "[switch]$RequireValidAuthenticode",
            "function Complete-ExecutionGuardProvenance",
            "execution_guard_status = 'pending_authenticode'",
            "unsigned_artifact_sha256",
            "Get-AuthenticodeSignature -LiteralPath $outputFull",
            "$signatureStatus -cne 'Valid'",
            "execution_guard_status = 'verified_after_authenticode_phase'",
            "$document.artifact_sha256 = $artifactSha256After",
        ):
            self.assertIn(fragment, BUILDER)
        self.assertEqual(BUILDER.count("& $outputFull"), 1)
        self.assertNotRegex(
            BUILDER, r"(?m)^\s*artifact_sha256 = \(Get-FileHash"
        )

    def test_installer_never_executes_engine_until_product_signing_finishes(self) -> None:
        build = INSTALLER.index(
            "& $AwgEngineBuilder -Output $AwgEngineArtifact -DeferExecutionGuard"
        )
        provisional_validation = INSTALLER.index(
            "'pending_authenticode'", build
        )
        signing_loop = INSTALLER.index("foreach ($binary in $productBinaries)")
        signing_call = INSTALLER.index(
            "Invoke-ProductSigning -Path $binary.FullName", signing_loop
        )
        finalization = INSTALLER.index(
            "& $AwgEngineBuilder -Output $AwgEngineArtifact -FinalizeExecutionGuard"
        )
        final_validation = INSTALLER.index(
            "'verified_after_authenticode_phase'", finalization
        )
        service_self_test = INSTALLER.index(
            "& $TunnelServiceArtifact --protocol-self-test", final_validation
        )
        payload_manifest = INSTALLER.index(
            "$manifestPath = $CanonicalPayloadManifest"
        )

        self.assertLess(build, provisional_validation)
        self.assertLess(provisional_validation, signing_loop)
        self.assertLess(signing_loop, signing_call)
        self.assertLess(signing_call, finalization)
        self.assertLess(finalization, final_validation)
        self.assertLess(final_validation, service_self_test)
        self.assertLess(service_self_test, payload_manifest)
        self.assertIn("-RequireValidAuthenticode:$mustSign", INSTALLER)
        self.assertIn(
            "[string]$awgEngineEvidence.artifact_sha256 -cne", INSTALLER
        )

    def test_inno_wrapper_refuses_engines_before_any_authenticode_mutation(self) -> None:
        engine_guard = INNO_SIGN.index("amneziawg.exe")
        xray_guard = INNO_SIGN.index("xray.exe")
        target = INNO_SIGN.index("$target = Assert-Target -Path $TargetFile")
        unsigned = INNO_SIGN.index("Assert-TargetNotAlreadySigned -Path $target")
        pin = INNO_SIGN.index("$leafPin = Get-WinsAuthenticodeLeafPin")
        self.assertNotIn("OWNER-BLOCKED", INNO_SIGN)
        sign = INNO_SIGN.index("& $signTool @signArgs")
        verify = INNO_SIGN.index("& $signTool @verifyArgs")
        self.assertLess(engine_guard, target)
        self.assertLess(xray_guard, target)
        self.assertLess(target, unsigned)
        self.assertLess(target, pin)
        self.assertLess(unsigned, sign)
        self.assertLess(pin, sign)
        self.assertLess(sign, verify)
        self.assertNotIn("& $outputFull", INNO_SIGN)
        self.assertIn("Inno signing target refuses engine/product payload", INNO_SIGN)
        self.assertIn("partially signed artifact is not shippable", INNO_SIGN)


if __name__ == "__main__":
    unittest.main()
