from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


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


class WindowsLabHarnessSecurityTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (TOOLS / name).read_text(encoding="utf-8")

    def test_public_release_stack_has_no_unsigned_override(self) -> None:
        collector = self.read("windows_release_physical_collector.ps1")
        worker = self.read("windows_release_interactive_worker.ps1")
        fixed_ui = self.read("windows_release_fixed_ui.ps1")
        driver = self.read("windows_release_matrix_driver.ps1")
        for text in (collector, worker, fixed_ui, driver):
            self.assertNotIn("AllowUnsigned", text)
            self.assertNotIn("LabEvidence", text)
        self.assertIn("lacks valid public-trust Authenticode", collector)
        self.assertIn("lacks valid public-trust Authenticode", worker)
        self.assertIn("does not retain valid Authenticode", fixed_ui)
        self.assertIn("WinsVPN\\ReleaseEvidence", driver)

    def test_lab_collector_is_hash_pinned_and_unsigned_only(self) -> None:
        text = self.read("windows_lab_physical_collector.ps1")
        for token in (
            "ExpectedArtifactSha256",
            "ExpectedPayloadManifestSha256",
            "ExpectedPreviousArtifactSha256",
            "Status -ne 'NotSigned'",
            "WinsVPN\\LabEvidence",
            "winsvpn-windows-lab-collector-context-v1",
        ):
            self.assertIn(token, text)
        self.assertNotIn("Status -ne 'Valid'", text)
        self.assertNotIn("ReleaseEvidence", text)

    def test_lab_worker_and_ui_bind_exact_unsigned_image(self) -> None:
        worker = self.read("windows_lab_interactive_worker.ps1")
        fixed_ui = self.read("windows_lab_fixed_ui.ps1")
        self.assertIn("function Assert-ExactUnsignedLabProduct", worker)
        self.assertIn("Get-Sha256 $InstalledGui", worker)
        self.assertIn("candidate manifest", worker.lower())
        self.assertIn("candidate PID/session/window/path/hash binding failed", fixed_ui)
        self.assertIn("Status -ne 'NotSigned'", fixed_ui)
        self.assertNotIn("ReleaseEvidence", worker + fixed_ui)

    def test_both_workers_reject_suppressed_installer_exceptions(self) -> None:
        for name in (
            "windows_lab_interactive_worker.ps1",
            "windows_release_interactive_worker.ps1",
        ):
            worker = self.read(name)
            with self.subTest(name=name):
                self.assertIn(
                    "function Assert-InstallerLogHasNoSuppressedException",
                    worker,
                )
                self.assertGreaterEqual(worker.count('"/LOG=$'), 2)
                self.assertGreaterEqual(
                    worker.count("Assert-InstallerLogHasNoSuppressedException"),
                    3,
                )
                self.assertIn("CurStepChanged raised an exception", worker)
                self.assertIn("Runtime error \\(at", worker)

    def test_verify_configs_attach_protected_local_client_keys(self) -> None:
        for name in (
            "windows_lab_interactive_worker.ps1",
            "windows_release_interactive_worker.ps1",
        ):
            worker = self.read(name)
            with self.subTest(name=name):
                self.assertIn("function Add-LocalClientKeys", worker)
                self.assertGreaterEqual(worker.count("Add-LocalClientKeys -Config"), 3)
                self.assertIn("$withKeys['client_private_key'] = $privateKey", worker)
                self.assertIn("$withKeys['client_public_key'] = $publicKey", worker)
                self.assertIn(
                    "Live /verify response contradicts the protected client public key",
                    worker,
                )
                self.assertNotIn("$nodeConfig = $node.Json.vpn_config", worker)
                self.assertNotIn("$coreConfig = $core.Json.vpn_config", worker)
                self.assertNotIn("$config = $verified.Json.vpn_config", worker)

    def test_tunnel_lane_waits_for_exact_committed_flutter_state(self) -> None:
        for name in (
            "windows_lab_interactive_worker.ps1",
            "windows_release_interactive_worker.ps1",
        ):
            worker = self.read(name)
            wait = worker[
                worker.index("function Wait-TunnelActive") : worker.index(
                    "function Wait-TunnelClean"
                )
            ]
            self.assertIn("-Action InspectDisconnect", wait)
            self.assertIn("$ui.label -ceq 'Disconnect VPN'", wait)
            self.assertIn("$ui.role -eq 43", wait)
            self.assertIn("$ui.visible -eq $true", wait)
            self.assertIn("$ui.enabled -eq $true", wait)
            self.assertIn("$xrayPresent -eq $Xray", wait)
            self.assertIn("$uiCommitted = $false", wait)

    def test_powershell_property_operator_never_splits_before_value(self) -> None:
        split_operator = re.compile(
            r"Where-Object\s+[A-Za-z_][A-Za-z0-9_.]*\s+"
            r"-(?:[ci]?(?:eq|ne|like|notlike|match|notmatch|gt|ge|lt|le|"
            r"contains|notcontains|in|notin)|is|isnot)\s*\r?\n",
            re.IGNORECASE,
        )
        offenders = []
        for path in TOOLS.rglob("*.ps1"):
            for match in split_operator.finditer(path.read_text(encoding="utf-8")):
                line = path.read_text(encoding="utf-8").count("\n", 0, match.start()) + 1
                offenders.append(f"{path.relative_to(ROOT)}:{line}")
        self.assertEqual(offenders, [])

    def test_manifest_predicates_filter_in_memory_objects_at_runtime(self) -> None:
        for name in (
            "windows_lab_interactive_worker.ps1",
            "windows_release_interactive_worker.ps1",
        ):
            worker = self.read(name)
            self.assertIn(
                "$_.name -ceq 'wins_vpn.exe'",
                worker,
            )
            self.assertIn(
                "$_.name -ceq 'wins_vpn_tunnel_service.exe'",
                worker,
            )

        command = r"""
$ErrorActionPreference = 'Stop'
$candidateManifest = [pscustomobject]@{
    artifacts = @(
        [pscustomobject]@{name='wins_vpn.exe'; sha256='gui'},
        [pscustomobject]@{name='wins_vpn_tunnel_service.exe'; sha256='service'},
        [pscustomobject]@{name='other.exe'; sha256='other'}
    )
}
$guiEntry = @($candidateManifest.artifacts | Where-Object {
    $_.name -ceq 'wins_vpn.exe'
})
$serviceEntry = @($candidateManifest.artifacts | Where-Object {
    $_.name -ceq 'wins_vpn_tunnel_service.exe'
})
if ($guiEntry.Count -ne 1 -or $guiEntry[0].sha256 -cne 'gui') { exit 1 }
if ($serviceEntry.Count -ne 1 -or $serviceEntry[0].sha256 -cne 'service') { exit 2 }
"""
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_watchdog_ready_handoff_retries_only_exclusive_io_lock(self) -> None:
        for name in (
            "windows_lab_physical_collector.ps1",
            "windows_release_physical_collector.ps1",
        ):
            collector = self.read(name)
            wait = collector[
                collector.index("function Wait-JsonSecure") : collector.index(
                    "function Assert-Previous"
                )
            ]
            self.assertIn("Read-JsonSecure $Path", wait)
            self.assertIn("$exception -is [IO.IOException]", wait)
            self.assertIn("$exception.InnerException -is [IO.IOException]", wait)
            self.assertIn("if (-not $locked) { throw }", wait)
            self.assertIn(
                "$watchdogReady = Wait-JsonSecure $readyPath -TimeoutSeconds 30",
                collector,
            )

    def test_flutter_msaa_action_uses_exact_flutterview_push_button(self) -> None:
        for name in (
            "windows_lab_fixed_ui.ps1",
            "windows_release_fixed_ui.ps1",
        ):
            fixed_ui = self.read(name)
            self.assertIn("$invokableButton -and $match.Role -ne 43", fixed_ui)
            self.assertIn("[WinsVpnFixedMsaa]::Invoke($match)", fixed_ui)
            self.assertIn("FindWindowEx", fixed_ui)
            self.assertIn("'FLUTTERVIEW'", fixed_ui)
            self.assertIn(
                "[WinsVpnFixedMsaa]::Find($accessibilityHandle, $expectedLabel)",
                fixed_ui,
            )
            self.assertIn("flutterview_semantic_default_action", fixed_ui)
            self.assertIn(
                "depth > 0 ? Candidate(node, ChildSelf, label) : null",
                fixed_ui,
            )
            self.assertNotIn("mouse_event", fixed_ui)
            self.assertNotIn("SetCursorPos", fixed_ui)
            self.assertIn("($match.State -band 0x8000) -eq 0", fixed_ui)
            self.assertIn("($match.State -band 0x10000) -ne 0", fixed_ui)
            self.assertNotIn("($match.State -band 0x18000) -eq 0", fixed_ui)
            self.assertIn("[AllowEmptyCollection()][byte[]]$Bytes", fixed_ui)
            self.assertIn("'OpenSplit'", fixed_ui)

    def test_lab_atomic_json_uses_explicit_backup_and_scrubs_temporary_files(self) -> None:
        worker = self.read("windows_lab_interactive_worker.ps1")
        atomic = worker[
            worker.index("function Write-AtomicJson") : worker.index(
                "function Assert-ValidPublicSignature"
            )
        ]
        self.assertIn("[IO.Path]::IsPathRooted", atomic)
        self.assertIn("[IO.File]::Replace($temporary, $Path, $backup, $true)", atomic)
        self.assertIn("[IO.File]::Move($temporary, $Path)", atomic)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", atomic)
        self.assertNotIn("[IO.File]::Replace($temporary, $Path, $null", atomic)
        self.assertGreaterEqual(atomic.count("Remove-Item -LiteralPath"), 2)

    def test_lab_atomic_json_replaces_and_creates_on_windows_powershell(self) -> None:
        worker = self.read("windows_lab_interactive_worker.ps1")
        functions = worker[
            worker.index("function Write-NewJson") : worker.index(
                "function Assert-ValidPublicSignature"
            )
        ]
        with tempfile.TemporaryDirectory() as value:
            root = value.replace("'", "''")
            command = functions + rf"""
$root = '{root}'
$existing = Join-Path $root 'existing.json'
$created = Join-Path $root 'created.json'
'{{"value":0}}' | Set-Content -LiteralPath $existing -Encoding UTF8
Write-AtomicJson $existing ([ordered]@{{value=1}})
Write-AtomicJson $created ([ordered]@{{value=2}})
if ((Get-Content $existing -Raw | ConvertFrom-Json).value -ne 1) {{ exit 1 }}
if ((Get-Content $created -Raw | ConvertFrom-Json).value -ne 2) {{ exit 1 }}
if (@(Get-ChildItem $root -File | Where-Object Name -Match '\.(tmp|bak)$').Count) {{ exit 1 }}
"""
            shell = powershell_executable()
            if shell is None:
                self.skipTest("PowerShell is unavailable")
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", command],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)

    def test_every_lab_layer_has_immutable_nonpublishable_markers(self) -> None:
        expected = (
            "evidence_class",
            "nonpublishable_lab",
            "lab_only",
            "publication_authorized",
            "public_release_gate_eligible",
            "unsigned_local_candidate",
        )
        for name in (
            "windows_lab_physical_collector.ps1",
            "windows_lab_interactive_worker.ps1",
            "windows_lab_fixed_ui.ps1",
            "windows_lab_safe_watchdog.ps1",
            "windows_lab_matrix_evidence.py",
        ):
            text = self.read(name)
            for token in expected:
                self.assertIn(token, text, f"{name} lacks {token}")

    def test_lab_schemas_constantly_reject_publication(self) -> None:
        for name in (
            "windows_lab_bundle_index.schema.json",
            "windows_lab_machine_evidence.schema.json",
        ):
            document = json.loads(self.read(name))
            properties = document["properties"]
            self.assertEqual(properties["evidence_class"]["const"], "nonpublishable_lab")
            self.assertIs(properties["lab_only"]["const"], True)
            self.assertIs(properties["publication_authorized"]["const"], False)
            self.assertIs(properties["public_release_gate_eligible"]["const"], False)
            self.assertIs(properties["unsigned_local_candidate"]["const"], True)

    def test_lab_compiler_contract_cannot_match_public_native_schema(self) -> None:
        text = self.read("windows_lab_matrix_evidence.py")
        self.assertIn('NATIVE_CONTRACT = "winsvpn-windows-lab-native-evidence-v1"', text)
        self.assertNotIn('NATIVE_CONTRACT = "winsvpn-native-live-smoke-v2"', text)
        self.assertIn('signature["authenticode_status"] != "NotSigned"', text)
        self.assertIn('"artifact_signature": False', text)

    def test_preparer_dpapi_wraps_credentials_and_redacts_output(self) -> None:
        text = self.read("prepare_windows_lab_evidence.ps1")
        self.assertIn("ConvertFrom-SecureString -SecureString", text)
        self.assertIn("DPAPI_CURRENT_USER_REDACTED", text)
        self.assertNotRegex(text, re.compile(r"Write-Output.*(?:private_key|account_number|user_pin)", re.I))
        self.assertIn(".SetAccessControl($acl)", text)
        self.assertIn("[IO.FileSystemAclExtensions]::SetAccessControl", text)
        self.assertIn("[IO.FileSystemAclExtensions]::GetAccessControl", text)
        self.assertIn("[Security.SecureString]$AccountNumberOverride", text)
        self.assertIn("SecureStringToBSTR", text)
        self.assertIn("ZeroFreeBSTR", text)
        self.assertNotIn("Set-Acl -LiteralPath", text)
        self.assertIn("Owner-only ACL verification failed", text)

    def test_preparer_binds_current_awg_engine_into_candidate_manifest(self) -> None:
        text = self.read("prepare_windows_lab_evidence.ps1")
        self.assertIn("$awgEngine = @($candidatePayload.payload", text)
        self.assertIn("$awgEngine.Count -ne 1", text)
        self.assertIn("name = 'winsvpn_awg_engine.exe'", text)
        self.assertIn("sha256 = [string]$awgEngine[0].sha256", text)
        self.assertIn("size = [long]$awgEngine[0].size", text)

    def test_lab_powershell_syntax(self) -> None:
        files = [
            TOOLS / "prepare_windows_lab_evidence.ps1",
            TOOLS / "windows_lab_physical_collector.ps1",
            TOOLS / "windows_lab_interactive_worker.ps1",
            TOOLS / "windows_lab_fixed_ui.ps1",
            TOOLS / "windows_lab_safe_watchdog.ps1",
        ]
        quoted = ",".join("'" + str(path).replace("'", "''") + "'" for path in files)
        command = (
            f"$files=@({quoted});$failed=$false;foreach($f in $files){{"
            "$t=$null;$e=$null;[Management.Automation.Language.Parser]::ParseFile($f,[ref]$t,[ref]$e)|Out-Null;"
            "if($e.Count){$failed=$true;$e|%{$_.Message}}};if($failed){exit 1}"
        )
        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
