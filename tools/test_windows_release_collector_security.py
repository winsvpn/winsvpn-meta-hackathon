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


ROOT = pathlib.Path(__file__).resolve().parent


def powershell_executable() -> str | None:
    names = (
        ("powershell.exe", "pwsh")
        if os.name == "nt"
        else ("pwsh", "powershell.exe")
    )
    for name in names:
        value = shutil.which(name)
        if value:
            return value
    bundled = (
        pathlib.Path.home()
        / "Library"
        / "Application Support"
        / "WinsVPN"
        / "toolchains"
        / "powershell-7.6.4"
        / "pwsh"
    )
    return str(bundled) if bundled.is_file() else None


class WindowsReleaseCollectorSecurityTests(unittest.TestCase):
    def text(self, name: str) -> str:
        return (ROOT / name).read_text(encoding="utf-8")

    def function_text(self, file_name: str, function_name: str) -> str:
        text = self.text(file_name)
        start = text.index(f"function {function_name}")
        opening = text.index("{", start)
        depth = 0
        for offset, character in enumerate(text[opening:], opening):
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return text[start : offset + 1]
        self.fail(f"unterminated function {function_name} in {file_name}")

    def test_legacy_system_watchdog_is_hard_quarantined(self) -> None:
        text = self.text("windows_test_failsafe_watchdog.ps1")
        self.assertIn("throw 'QUARANTINED:", text)

    def test_collector_has_fixed_system_boundary(self) -> None:
        text = self.text("windows_release_physical_collector.ps1")
        parameter_block = text[: text.index("Set-StrictMode")]
        for forbidden in (
            "WatchdogScript",
            "InvokeTool",
            "MachineEvidence",
            "Pass",
            "Observed",
            "ExpectedPublicEgress",
        ):
            self.assertNotIn(forbidden, parameter_block)
        self.assertIn("System32\\WindowsPowerShell", text)
        self.assertIn("WinsVPN\\ReleaseEvidence", text)
        self.assertIn("FileShare]::None", text)
        self.assertIn("Assert-NoReparsePath", text)
        self.assertIn("Protect-LockedFile", text)
        self.assertGreaterEqual(text.count("Unregister-ScheduledTask"), 1)
        self.assertIn("publication_authorized = $false", text)
        self.assertIn("WINDOWS_RELEASE_BUNDLE_INDEX_SHA256", text)

    def test_worker_cannot_transition_without_armed_exact_baseline(self) -> None:
        text = self.text("windows_release_interactive_worker.ps1")
        execute = text[
            text.index("function Invoke-Execute") : text.index("function Invoke-Finalize")
        ]
        for required in (
            "windows-release-watchdog-arm-v1",
            "Get-CanonicalSha256 (Get-StateDocument)",
            "baseline.state_sha256",
            "Invoke-RapidCancelTest",
            "Invoke-RouteLane",
            "Invoke-SplitTunnelTest",
            "Invoke-NetworkChangeTest",
            "Invoke-LeakTest",
            "Invoke-MapTest",
            "normal-disarm.json",
        ):
            self.assertIn(required, execute)
        self.assertLess(
            execute.index("baseline.state_sha256"),
            execute.index("Invoke-RapidCancelTest"),
        )
        self.assertLess(
            execute.index("Execute matrix did not naturally restore"),
            execute.index("normal-disarm.json"),
        )

    def test_worker_and_watchdog_verify_full_canonical_helper_closure(self) -> None:
        for name in (
            "windows_release_interactive_worker.ps1",
            "windows_release_safe_watchdog.ps1",
        ):
            text = self.text(name)
            self.assertIn("function Assert-ExactHelperClosure", text)
            self.assertIn("Get-ChildItem -LiteralPath $HelperRoot -File -Force", text)
            self.assertIn("IncrementalHash", text)
            self.assertIn("FileShare]::None", text)
            self.assertIn("Assert-CanonicalRunIdentity", text)

    def test_live_dns_and_observer_nonce_are_dynamic_and_authenticated(self) -> None:
        worker = self.text("windows_release_interactive_worker.ps1")
        self.assertNotIn("10.8.1.1", worker)
        self.assertIn("Get-CurrentTunnelDns", worker)
        self.assertIn("WINS_OBSERVATION_NONCE", worker)
        self.assertIn("server.observation_window_nonce", worker)
        for name in (
            "windows_spain_live_observation.py",
            "windows_core_live_observation.py",
        ):
            observer = self.text(name)
            self.assertIn("WINS_OBSERVATION_NONCE", observer)
            self.assertIn("observation_window_nonce", observer)

    def test_watchdog_emergency_can_never_be_release_pass(self) -> None:
        text = self.text("windows_release_safe_watchdog.ps1")
        self.assertIn("$emergency = $true", text)
        self.assertIn("$pass = $normal -and -not $emergency", text)
        self.assertIn("$runtime = $latestRuntime", text)
        self.assertIn("Test-ExactImage", text)
        self.assertIn("kill_switch_wfp_state", text)

    def test_worker_and_watchdog_capture_the_exact_same_state_document(self) -> None:
        worker = self.function_text(
            "windows_release_interactive_worker.ps1", "Get-StateDocument"
        )
        watchdog = self.function_text(
            "windows_release_safe_watchdog.ps1", "Get-StateDocument"
        )
        self.assertEqual(worker, watchdog)

    def test_ui_is_exact_candidate_and_semantic_action_bound(self) -> None:
        text = self.text("windows_release_fixed_ui.ps1")
        for required in (
            "candidate_pid",
            "candidate_session_id",
            "installed_gui_sha256",
            "Get-AuthenticodeSignature",
            "accDoDefaultAction",
            "Connect VPN",
            "Cancel VPN connection",
            "Disconnect VPN",
        ):
            self.assertIn(required, text)
        self.assertNotIn("[string]$Script", text)
        self.assertNotIn("[string]$Executable", text)

    def test_compiler_uses_share_deny_and_reparse_open(self) -> None:
        text = self.text("windows_release_matrix_evidence.py")
        self.assertIn("0x00200000", text)
        self.assertRegex(text, r"0x80000000,\s*\n\s*0,")
        self.assertIn("path contains a reparse point", text)
        self.assertIn("observer_host_key_sha256", text)
        self.assertIn("previous_payload_manifest_sha256", text)
        self.assertIn("evidence_bundle_index_sha256", text)
        self.assertIn("GetFileInformationByHandle", text)
        self.assertIn("descriptor opened a reparse point", text)
        self.assertIn("changed after the first secure read", text)
        self.assertIn("mixes x64 and arm64 PE images", text)
        self.assertIn("winsvpn-windows-machine-identity-v1", text)
        self.assertIn("72-hour live-evidence window", text)
        self.assertIn("WINDOWS RELEASE MATRIX COMPILER SELF-TEST: PASS", text)
        self.assertIn('print("WINDOWS RELEASE MATRIX EVIDENCE: PASS")', text)
        self.assertIn("if args.self_test:", text)
        self.assertLess(text.index("if args.self_test:"), text.index('print("WINDOWS RELEASE MATRIX EVIDENCE: PASS")'))

    def test_collector_binds_native_arch_identity_and_cleanup(self) -> None:
        text = self.text("windows_release_physical_collector.ps1")
        for required in (
            "0x00200000",
            "Get-PeArchitecture",
            "Get-NativeWindowsArchitecture",
            "PROCESSOR_ARCHITEW6432",
            "ProcessArchitecture",
            "OSArchitecture",
            "MachineGuid",
            "winsvpn-windows-machine-identity-v1",
            "process_wow64",
            "refusing to seal mixed evidence",
            "Failed to unregister release watchdog task",
            "Payload PE architecture is mixed",
            "Wait-JsonSecure $watchdogReceipt",
            "Open-ExclusiveFile",
            "GetFileInformationByHandle",
            "nNumberOfLinks",
            "hardlink substitution",
            "source_only",
            "release_identity",
            "winsvpn-windows-runtime-receipt-v1",
            "winsvpn-windows-uninstall-receipt-v1",
            "winsvpn-windows-winn-v3-receipt-v1",
            "winsvpn-windows-winn-v1-awg-receipt-v1",
            "winsvpn-windows-winn-v1-xray-receipt-v1",
            "winsvpn-windows-native-host-receipt-v1",
            "refusing to seal partial evidence",
            "partial false green",
            "JSON output size is unbounded",
            "Physical receipt set is empty or unbounded",
        ):
            self.assertIn(required, text)
        self.assertNotIn(
            "Get-Content -LiteralPath $watchdogReceipt",
            text,
        )
        unregister = text[
            text.index("$collectionPassed = $true") : text.index(
                "refusing to seal mixed evidence"
            )
        ]
        self.assertIn("Unregister-ScheduledTask", unregister)
        self.assertNotIn(
            "Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false `\n"
            "            -ErrorAction SilentlyContinue",
            text,
        )
        self.assertLess(
            text.index("function Assert-RequiredBoundReceipts"),
            text.index("WINDOWS_RELEASE_PHYSICAL_COLLECTOR=PASS"),
        )
        self.assertLess(
            text.index("Assert-RequiredBoundReceipts @($liveReceipts)"),
            text.index("WINDOWS_RELEASE_PHYSICAL_COLLECTOR=PASS"),
        )
        self.assertLess(
            text.index("winn_v1_awg"),
            text.index("winn_v1_xray"),
        )

    def test_collector_rejects_wow64_mixed_omitted_and_source_only_receipts(
        self,
    ) -> None:
        text = self.text("windows_release_physical_collector.ps1")
        binding = self.function_text(
            "windows_release_physical_collector.ps1",
            "Assert-ArchitectureBinding",
        )
        required_fn = self.function_text(
            "windows_release_physical_collector.ps1",
            "Assert-RequiredBoundReceipts",
        )
        bound_fn = self.function_text(
            "windows_release_physical_collector.ps1",
            "Assert-BoundPhysicalReceipt",
        )
        property_fn = self.function_text(
            "windows_release_physical_collector.ps1",
            "Get-ReceiptProperty",
        )
        self.assertIn("Physical receipt omitted architecture binding.", binding)
        self.assertIn(
            "Physical receipt architecture is mixed, WOW64, omitted, or unsupported.",
            binding,
        )
        self.assertIn(
            "Physical receipt PE machine does not match the native host and candidate.",
            binding,
        )
        self.assertIn("source-only; refusing non-physical substitution", bound_fn)
        self.assertIn("not bound to the exact candidate hash", bound_fn)
        self.assertIn("release identity is stale or mixed", bound_fn)
        self.assertIn("belongs to another live run", bound_fn)
        self.assertIn("partial false green", bound_fn)
        self.assertIn("refusing to seal partial evidence", required_fn)
        self.assertIn("Winn v1 Xray fallback is not after AWG", required_fn)
        self.assertIn("mixed fallback order", text)
        self.assertIn("native_host_observed", required_fn)
        self.assertIn("runtime_observed", required_fn)
        self.assertIn("uninstalled", required_fn)
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        helpers = "\n\n".join((property_fn, binding, bound_fn, required_fn))
        command = r"""
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PeMachineX64 = 0x8664
$PeMachineArm64 = 0xAA64
$RunId = '11111111-1111-1111-1111-111111111111'
$closureSha = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$candidateHash = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
$releaseIdentity = '1.0.14+29'
function New-TestReceipt {
    param(
        [Parameter(Mandatory)][string]$Contract,
        [Parameter(Mandatory)][int]$Sequence,
        [string]$Architecture = 'x64',
        [int]$PeMachine = 0x8664,
        [string]$OsArchitecture = 'X64',
        [object]$Wow64 = $false,
        [string]$Artifact = $candidateHash,
        [string]$Identity = $releaseIdentity,
        [object]$SourceOnly = $false,
        [object]$Passed = $true,
        [string]$Run = $RunId,
        [hashtable]$Extra = @{}
    )
    $receipt = [ordered]@{
        contract = $Contract
        run_id = $Run
        collector_closure_sha256 = $closureSha
        artifact_sha256 = $Artifact
        release_identity = $Identity
        source_only = $SourceOnly
        passed = $Passed
        architecture = $Architecture
        pe_machine = $PeMachine
        native_architecture = $Architecture
        os_architecture = $OsArchitecture
        process_wow64 = $Wow64
        sequence = $Sequence
        step_nonce = [Guid]::NewGuid().ToString('D')
    }
    foreach ($key in $Extra.Keys) { $receipt[$key] = $Extra[$key] }
    $receipt
}
function New-ClosedSet {
    param([string]$Architecture, [int]$PeMachine, [string]$OsArchitecture)
    @(
        (New-TestReceipt 'winsvpn-windows-signature-receipt-v1' 1 -Architecture $Architecture -PeMachine $PeMachine -OsArchitecture $OsArchitecture),
        (New-TestReceipt 'winsvpn-windows-install-receipt-v1' 2 -Architecture $Architecture -PeMachine $PeMachine -OsArchitecture $OsArchitecture),
        (New-TestReceipt 'winsvpn-windows-runtime-receipt-v1' 3 -Architecture $Architecture -PeMachine $PeMachine -OsArchitecture $OsArchitecture -Extra @{ runtime_observed = $true }),
        (New-TestReceipt 'winsvpn-windows-uninstall-receipt-v1' 4 -Architecture $Architecture -PeMachine $PeMachine -OsArchitecture $OsArchitecture -Extra @{ uninstalled = $true }),
        (New-TestReceipt 'winsvpn-windows-teardown-rollback-receipt-v1' 5 -Architecture $Architecture -PeMachine $PeMachine -OsArchitecture $OsArchitecture),
        (New-TestReceipt 'winsvpn-windows-winn-v3-receipt-v1' 6 -Architecture $Architecture -PeMachine $PeMachine -OsArchitecture $OsArchitecture -Extra @{
            primary_transport = 'winn_v3'
            fallback_transports = @('winn_v1_awg', 'winn_v1_xray')
            winn_v3_session_observed = $true
        }),
        (New-TestReceipt 'winsvpn-windows-winn-v1-awg-receipt-v1' 7 -Architecture $Architecture -PeMachine $PeMachine -OsArchitecture $OsArchitecture -Extra @{
            transport = 'winn_v1_awg'
            observed = $true
        }),
        (New-TestReceipt 'winsvpn-windows-winn-v1-xray-receipt-v1' 8 -Architecture $Architecture -PeMachine $PeMachine -OsArchitecture $OsArchitecture -Extra @{
            transport = 'winn_v1_xray'
            observed = $true
        }),
        (New-TestReceipt 'winsvpn-windows-native-host-receipt-v1' 9 -Architecture $Architecture -PeMachine $PeMachine -OsArchitecture $OsArchitecture -Extra @{
            native_host_observed = $true
        })
    )
}
function Assert-Throws {
    param([scriptblock]$Body, [string]$Needle)
    $failed = $false
    try { & $Body } catch {
        $failed = $true
        if ($_.Exception.Message -notlike "*$Needle*") {
            throw "expected '$Needle' in '$($_.Exception.Message)'"
        }
    }
    if (-not $failed) { throw "expected failure matching $Needle" }
}
HELPERS
$cases = @(
    @{ Arch = 'x64'; Machine = 0x8664; Os = 'X64' },
    @{ Arch = 'arm64'; Machine = 0xAA64; Os = 'Arm64' }
)
foreach ($case in $cases) {
    $artifactArch = $case.Arch
    $osArchName = $case.Os
    $candidatePe = [ordered]@{ Name = $case.Arch; Machine = $case.Machine }
    $good = New-ClosedSet $case.Arch $case.Machine $case.Os
    Assert-RequiredBoundReceipts $good
    Assert-Throws { Assert-ArchitectureBinding $null } 'omitted architecture binding'
    $omitted = New-TestReceipt 'winsvpn-windows-signature-receipt-v1' 1 -Architecture $case.Arch -PeMachine $case.Machine -OsArchitecture $case.Os
    $omitted.Remove('pe_machine')
    Assert-Throws { Assert-ArchitectureBinding $omitted } 'omitted architecture binding'
    $wow = New-TestReceipt 'winsvpn-windows-signature-receipt-v1' 1 -Architecture $case.Arch -PeMachine $case.Machine -OsArchitecture $case.Os -Wow64 $true
    Assert-Throws { Assert-ArchitectureBinding $wow } 'WOW64'
    $mixedMachine = if ($case.Arch -eq 'x64') { 0xAA64 } else { 0x8664 }
    $mixed = New-TestReceipt 'winsvpn-windows-signature-receipt-v1' 1 -Architecture $case.Arch -PeMachine $mixedMachine -OsArchitecture $case.Os
    Assert-Throws { Assert-ArchitectureBinding $mixed } 'mixed, WOW64, omitted, or unsupported'
    $crossArch = if ($case.Arch -eq 'x64') { 'arm64' } else { 'x64' }
    $crossOs = if ($case.Arch -eq 'x64') { 'Arm64' } else { 'X64' }
    $crossPe = if ($case.Arch -eq 'x64') { 0xAA64 } else { 0x8664 }
    $foreign = New-TestReceipt 'winsvpn-windows-signature-receipt-v1' 1 -Architecture $crossArch -PeMachine $crossPe -OsArchitecture $crossOs
    Assert-Throws { Assert-ArchitectureBinding $foreign } 'does not match the native host and candidate'
    $staleHash = New-TestReceipt 'winsvpn-windows-signature-receipt-v1' 1 -Architecture $case.Arch -PeMachine $case.Machine -OsArchitecture $case.Os -Artifact ('cc' * 32)
    Assert-Throws { Assert-BoundPhysicalReceipt $staleHash 'winsvpn-windows-signature-receipt-v1' 'sig' -RequirePass } 'exact candidate hash'
    $staleIdentity = New-TestReceipt 'winsvpn-windows-signature-receipt-v1' 1 -Architecture $case.Arch -PeMachine $case.Machine -OsArchitecture $case.Os -Identity '9.9.9+1'
    Assert-Throws { Assert-BoundPhysicalReceipt $staleIdentity 'winsvpn-windows-signature-receipt-v1' 'sig' -RequirePass } 'release identity'
    $crossRun = New-TestReceipt 'winsvpn-windows-signature-receipt-v1' 1 -Architecture $case.Arch -PeMachine $case.Machine -OsArchitecture $case.Os -Run '22222222-2222-2222-2222-222222222222'
    Assert-Throws { Assert-BoundPhysicalReceipt $crossRun 'winsvpn-windows-signature-receipt-v1' 'sig' -RequirePass } 'another live run'
    $sourceOnly = New-TestReceipt 'winsvpn-windows-signature-receipt-v1' 1 -Architecture $case.Arch -PeMachine $case.Machine -OsArchitecture $case.Os -SourceOnly $true
    Assert-Throws { Assert-BoundPhysicalReceipt $sourceOnly 'winsvpn-windows-signature-receipt-v1' 'sig' -RequirePass } 'source-only'
    $falseGreen = New-TestReceipt 'winsvpn-windows-signature-receipt-v1' 1 -Architecture $case.Arch -PeMachine $case.Machine -OsArchitecture $case.Os -Passed $false
    Assert-Throws { Assert-BoundPhysicalReceipt $falseGreen 'winsvpn-windows-signature-receipt-v1' 'sig' -RequirePass } 'partial false green'
    $missing = @($good[0..($good.Count - 2)])
    Assert-Throws { Assert-RequiredBoundReceipts $missing } 'partial evidence'
    $swapped = New-ClosedSet $case.Arch $case.Machine $case.Os
    $swapped[6] = New-TestReceipt 'winsvpn-windows-winn-v1-awg-receipt-v1' 8 -Architecture $case.Arch -PeMachine $case.Machine -OsArchitecture $case.Os -Extra @{ transport = 'winn_v1_awg'; observed = $true }
    $swapped[7] = New-TestReceipt 'winsvpn-windows-winn-v1-xray-receipt-v1' 7 -Architecture $case.Arch -PeMachine $case.Machine -OsArchitecture $case.Os -Extra @{ transport = 'winn_v1_xray'; observed = $true }
    Assert-Throws { Assert-RequiredBoundReceipts $swapped } 'not after AWG'
    $badFallback = New-ClosedSet $case.Arch $case.Machine $case.Os
    $badFallback[5] = New-TestReceipt 'winsvpn-windows-winn-v3-receipt-v1' 6 -Architecture $case.Arch -PeMachine $case.Machine -OsArchitecture $case.Os -Extra @{
        primary_transport = 'winn_v3'
        fallback_transports = @('winn_v1_xray', 'winn_v1_awg')
        winn_v3_session_observed = $true
    }
    Assert-Throws { Assert-RequiredBoundReceipts $badFallback } 'mixed fallback order'
}
Write-Output 'HOSTILE_RECEIPT_BINDING=PASS'
"""
        command = command.replace("HELPERS", helpers)
        with tempfile.TemporaryDirectory() as temp_root:
            script = pathlib.Path(temp_root) / "hostile_receipt_binding.ps1"
            script.write_text(command, encoding="ascii")
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-File", str(script)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("HOSTILE_RECEIPT_BINDING=PASS", result.stdout)

    def test_payload_manifest_consumers_follow_the_v3_producer(self) -> None:
        # R22 Y3-04: installer/windows/build_installer.ps1 writes the payload
        # manifest as schema_version 3; every consumer of that document must
        # accept 3 and refuse the retired 2.
        producer = (ROOT.parent / "installer" / "windows" / "build_installer.ps1").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            producer, r"\$payloadManifest = \[ordered\]@\{\s*schema_version = 3\s"
        )
        for name in (
            "windows_release_physical_collector.ps1",
            "windows_lab_physical_collector.ps1",
        ):
            with self.subTest(collector=name):
                text = self.text(name)
                self.assertIn("if ($payloadDocument.schema_version -ne 3 -or", text)
                self.assertNotIn("$payloadDocument.schema_version -ne 2", text)
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        functions = "\n".join(
            self.function_text("public_release_gate.ps1", name)
            for name in ("Get-Sha256", "Test-WindowsPayloadManifest")
        )
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw).resolve()
            files = {
                "installer/windows/build_installer.ps1": b"producer",
                "installer/windows/winsvpn.iss": b"inno script",
                "tools/windows_inno_sign.ps1": b"signing wrapper",
                "stage/data/app.so": b"payload bytes",
                "WinsVPN-Setup.exe": b"MZ installer bytes",
            }
            for relative, payload in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)

            def digest(relative: str) -> str:
                return hashlib.sha256(files[relative]).hexdigest()

            def manifest(version: int) -> dict[str, object]:
                return {
                    "schema_version": version,
                    "installer": {
                        "name": "WinsVPN-Setup.exe",
                        "size": len(files["WinsVPN-Setup.exe"]),
                        "sha256": digest("WinsVPN-Setup.exe"),
                    },
                    "producer": {
                        "path": "installer/windows/build_installer.ps1",
                        "sha256": digest("installer/windows/build_installer.ps1"),
                        "inno_script_path": "installer/windows/winsvpn.iss",
                        "inno_script_sha256": digest("installer/windows/winsvpn.iss"),
                        "inno_signing_wrapper_path": "tools/windows_inno_sign.ps1",
                        "inno_signing_wrapper_sha256": digest("tools/windows_inno_sign.ps1"),
                    },
                    "signing": {
                        "production_signed": True,
                        "every_loose_pe_verified": True,
                        "staged_xray_product_signed": True,
                        "inno_setup_and_uninstaller_signed": True,
                        "self_signed_certificate_forbidden": True,
                    },
                    "inno_compiler": {"contract": "winsvpn-inno-compiler-receipt-v1"},
                    "payload": [
                        {
                            "path": "stage/data/app.so",
                            "size": len(files["stage/data/app.so"]),
                            "sha256": digest("stage/data/app.so"),
                        }
                    ],
                }

            for version in (2, 3):
                (root / f"v{version}.json").write_text(
                    json.dumps(manifest(version)), encoding="utf-8"
                )
            installer = (root / "WinsVPN-Setup.exe").as_posix()
            command = (
                f"$RepoRoot = '{root.as_posix()}'\n"
                + functions
                + "\n"
                + "".join(
                    f"Write-Output ('V{version}=' + (Test-WindowsPayloadManifest "
                    f"-Installer '{installer}' -ManifestPath '{(root / f'v{version}.json').as_posix()}'))\n"
                    for version in (2, 3)
                )
            )
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", command],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=60,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("V3=True", result.stdout)
        self.assertIn("V2=False", result.stdout)

    @staticmethod
    def statements_before_refusal(text: str) -> list[str]:
        """Lines between the param block and the OWNER-BLOCKED refusal that are
        not blank, a comment, or the two-line strict-mode head."""
        lines = text.splitlines()
        param_close = next(index for index, line in enumerate(lines) if line == ")")
        refusal = next(
            index for index, line in enumerate(lines) if "throw ('OWNER-BLOCKED: " in line
        )
        allowed = {"", "Set-StrictMode -Version Latest", "$ErrorActionPreference = 'Stop'"}
        return [
            line
            for line in lines[param_close + 1 : refusal]
            if line not in allowed and not line.startswith("#")
        ]

    def test_physical_collectors_refuse_before_any_python_or_elevated_step(self) -> None:
        # R23 W1-07, Arbiter ruling option 1: both collectors are OWNER-BLOCKED
        # until a Windows-verifiable release input receipt route exists. The
        # refusal is the first statement, ahead of the PATH python.exe lookup
        # and every elevated step, and the rest of each script is kept.
        names = (
            "windows_release_physical_collector.ps1",
            "windows_lab_physical_collector.ps1",
        )
        for name in names:
            with self.subTest(collector=name):
                text = self.text(name)
                refusal = text.index("throw ('OWNER-BLOCKED: ")
                # R24 V2 F-09: the span runs from the end of the param block, so a
                # statement placed before the strict-mode head cannot slip past.
                self.assertEqual(
                    self.statements_before_refusal(text),
                    [],
                    "only the strict-mode head and comments may precede the refusal",
                )
                injected = text.replace(
                    "\nSet-StrictMode -Version Latest\n",
                    "\nInvoke-WebRequest https://example.invalid/x\nSet-StrictMode -Version Latest\n",
                    1,
                )
                self.assertNotEqual(injected, text)
                self.assertEqual(
                    self.statements_before_refusal(injected),
                    ["Invoke-WebRequest https://example.invalid/x"],
                )
                self.assertIn("signed remote-attested route is the planned fix", text)
                for later in (
                    "(Get-Command python.exe -ErrorAction Stop).Source",
                    "\nAssert-AdministratorInteractive\n",
                    "\n$RepoRoot = (Resolve-Path",
                    "Register-ScheduledTask",
                ):
                    self.assertLess(refusal, text.index(later), later)
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw).resolve()
            fakebin = root / "fakebin"
            fakebin.mkdir()
            marker = root / "python-ran"
            for fake in ("python.exe", "python", "python3"):
                path = fakebin / fake
                path.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n", encoding="utf-8")
                path.chmod(0o755)
            program_data = root / "programdata"
            program_data.mkdir()
            environment = dict(os.environ)
            environment.update(
                {
                    "PATH": f"{fakebin}{os.pathsep}{environment.get('PATH', '')}",
                    "ProgramData": str(program_data),
                    "SystemRoot": str(root / "systemroot"),
                }
            )
            digest = "0" * 64
            arguments = {
                "windows_release_physical_collector.ps1": [
                    "-Artifact", "a.exe", "-PayloadManifest", "p.json", "-PayloadRoot", "p",
                    "-ReleaseInputIndex", "i.json", "-BuildReceipt", "r.json",
                    "-CandidateManifest", "c.json", "-PreviousArtifact", "b.exe",
                    "-PreviousPayloadManifest", "q.json", "-PreviousReleaseRecord", "s.json",
                    "-CredentialStore", "k.dat", "-Gazetteer", "g.json",
                ],
                "windows_lab_physical_collector.ps1": [
                    "-Artifact", "a.exe", "-ExpectedArtifactSha256", digest,
                    "-PayloadManifest", "p.json", "-ExpectedPayloadManifestSha256", digest,
                    "-PayloadRoot", "p", "-ReleaseInputIndex", "i.json",
                    "-BuildReceipt", "r.json", "-CandidateManifest", "c.json",
                    "-PreviousArtifact", "b.exe", "-ExpectedPreviousArtifactSha256", digest,
                    "-PreviousPayloadManifest", "q.json", "-PreviousReleaseRecord", "s.json",
                    "-CredentialStore", "k.dat", "-Gazetteer", "g.json",
                ],
            }
            for name in names:
                with self.subTest(run=name):
                    # The script itself runs; the wrapper only prints the
                    # terminating error's message without console formatting.
                    script = str(ROOT / name).replace("'", "''")
                    quoted = " ".join(
                        item if item.startswith("-") else "'" + item + "'"
                        for item in arguments[name]
                    )
                    command = (
                        f"try {{ & '{script}' {quoted} }} catch {{ "
                        "[Console]::Out.WriteLine('REFUSED: ' + $_.Exception.Message); exit 3 }; exit 0"
                    )
                    result = subprocess.run(
                        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
                        env=environment,
                        cwd=root,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=60,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 3, result.stdout)
                    self.assertIn("REFUSED: OWNER-BLOCKED: ", result.stdout)
                    self.assertIn("No Python was resolved or run.", result.stdout)
                    self.assertFalse(marker.exists())
                    self.assertEqual(list(program_data.iterdir()), [])

    def test_public_gate_live_check_compares_the_downloaded_bytes(self) -> None:
        # R23 W1-10: -VerifyLive passed on any 2xx/3xx HEAD answer. The live
        # body must be the candidate: same size and SHA-256.
        gate = self.text("public_release_gate.ps1")
        live = gate[gate.index("if ($VerifyLive) {"):]
        live = live[: live.index("\nforeach ($message in $passes)")]
        self.assertNotIn("-Method Head", live)
        self.assertIn("Test-LiveDownloadMatches -Url $url", live)
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        functions = "\n".join(
            self.function_text("public_release_gate.ps1", name)
            for name in ("Get-Sha256", "Test-LiveDownloadMatches")
        )
        candidate = b"MZ exact candidate installer bytes"
        expected = hashlib.sha256(candidate).hexdigest()
        cases = {
            "EXACT": candidate,
            "FLIPPED": candidate[:-1] + bytes([candidate[-1] ^ 1]),
            "TRUNCATED": candidate[:-4],
            "PLACEHOLDER": b"<html>placeholder</html>",
        }
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw).resolve()
            for label, payload in cases.items():
                (root / label).write_bytes(payload)
            # A stand-in for the network: the function under test calls
            # Invoke-WebRequest by name, and a function shadows the cmdlet.
            stub = (
                "function Invoke-WebRequest {\n"
                "    param([switch]$UseBasicParsing, [string]$Method, [int]$MaximumRedirection,\n"
                "          [int]$TimeoutSec, [string]$Uri, [string]$OutFile)\n"
                f"    Copy-Item -LiteralPath (Join-Path '{root.as_posix()}' ([Uri]$Uri).Segments[-1]) "
                "-Destination $OutFile\n"
                "}\n"
            )
            command = (
                stub
                + functions
                + "\n"
                + "".join(
                    f"Write-Output ('{label}=' + (Test-LiveDownloadMatches "
                    f"-Url 'https://www.winsvpn.org/downloads/{label}' "
                    f"-ExpectedSha256 '{expected}' -ExpectedSize {len(candidate)}))\n"
                    for label in cases
                )
            )
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", command],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=60,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("EXACT=True", result.stdout)
        for label in ("FLIPPED", "TRUNCATED", "PLACEHOLDER"):
            self.assertIn(f"{label}=False", result.stdout)

    def test_public_gate_keeps_the_linked_download_name_escaped(self) -> None:
        # R24 V2 F-08: the gate unescaped the linked segment and rebuilt the live
        # URL from it, so downloads/app%3F.apk was fetched as downloads/app?.apk,
        # whose path is /downloads/app, and an escaped slash became a local path
        # separator. The URL uses the linked segment; only the local file name is
        # unescaped, and it must be a plain file name.
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        functions = "\n".join(
            self.function_text("public_release_gate.ps1", name)
            for name in ("Get-LinkedDownloadNames", "Get-LocalDownloadFileName")
        )
        index = (
            '<a href="https://www.winsvpn.org/downloads/app%3F.apk">a</a>'
            '<a href="https://www.winsvpn.org/downloads/Win%27s%20VPN.exe">b</a>'
            '<a href="https://www.winsvpn.org/downloads/a%2Fb.tar.gz">c</a>'
            '<a href="https://www.winsvpn.org/downloads/%2E%2E">d</a>'
            '<a href="https://www.winsvpn.org/downloads/plain.exe">e</a>'
        )
        command = (
            functions
            + f"\n$names = @(Get-LinkedDownloadNames -Index '{index}')\n"
            + "Write-Output ('NAMES=' + ($names -join '|'))\n"
            + "foreach ($name in $names) {\n"
            + "    $local = Get-LocalDownloadFileName -LinkedName $name\n"
            + "    if ($null -eq $local) { $local = '<refused>' }\n"
            + "    Write-Output ('LOCAL ' + $name + ' => ' + $local)\n"
            + "}\n"
        )
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", command],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        lines = result.stdout.splitlines()
        names_line = next(line for line in lines if line.startswith("NAMES="))
        self.assertEqual(
            sorted(names_line[len("NAMES="):].split("|")),
            sorted(["app%3F.apk", "Win%27s%20VPN.exe", "a%2Fb.tar.gz", "%2E%2E", "plain.exe"]),
        )
        self.assertIn("LOCAL app%3F.apk => app?.apk", lines)
        self.assertIn("LOCAL Win%27s%20VPN.exe => Win's VPN.exe", lines)
        self.assertIn("LOCAL a%2Fb.tar.gz => <refused>", lines)
        self.assertIn("LOCAL %2E%2E => <refused>", lines)
        self.assertIn("LOCAL plain.exe => plain.exe", lines)
        gate = self.text("public_release_gate.ps1")
        live = gate[gate.index("if ($VerifyLive) {"):]
        self.assertIn('$url = "https://www.winsvpn.org/downloads/$name"', live)
        self.assertNotIn("UnescapeDataString($_.Groups[1].Value)", gate)

    def test_windows_schemas_are_strict_json(self) -> None:
        for name in (
            "windows_release_bundle_index.schema.json",
            "windows_release_machine_evidence.schema.json",
        ):
            schema = json.loads((ROOT / name).read_text(encoding="utf-8"))
            self.assertFalse(schema["additionalProperties"])

    def test_powershell_sources_parse(self) -> None:
        files = [
            "windows_release_physical_collector.ps1",
            "windows_release_interactive_worker.ps1",
            "windows_release_safe_watchdog.ps1",
            "windows_release_fixed_ui.ps1",
            "windows_release_matrix_driver.ps1",
            "windows_public_release_live_smoke.ps1",
        ]
        command = (
            "$bad=$false;"
            + ";".join(
                "$e=$null;[void][System.Management.Automation.Language.Parser]::"
                f"ParseFile((Resolve-Path '{(ROOT / name).as_posix()}'),[ref]$null,[ref]$e);"
                "if($e){$bad=$true;$e|% ToString}"
                for name in files
            )
            + ";if($bad){exit 1}"
        )
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", command],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
