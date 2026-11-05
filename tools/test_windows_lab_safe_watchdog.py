from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
WATCHDOG = ROOT / "windows_lab_safe_watchdog.ps1"


class WindowsLabSafeWatchdogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WATCHDOG.read_text(encoding="utf-8")

    def test_powershell_syntax(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is unavailable")
        command = (
            "$t=$null;$e=$null;"
            "[void][Management.Automation.Language.Parser]::ParseFile("
            f"'{WATCHDOG.as_posix()}',[ref]$t,[ref]$e);"
            "if($e.Count){$e|% Message;exit 1}"
        )
        subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_isolated_lab_root_and_contract_namespace(self) -> None:
        self.assertIn("WinsVPN\\LabEvidence", self.text)
        self.assertNotIn("WinsVPN\\ReleaseEvidence", self.text)
        self.assertNotIn("winsvpn-windows-release-", self.text)
        self.assertNotIn("windows_release_", self.text)
        for contract in (
            "winsvpn-windows-lab-collector-closure-v1",
            "winsvpn-windows-lab-collector-context-v1",
            "winsvpn-windows-lab-runtime-context-v1",
            "winsvpn-windows-lab-baseline-v1",
            "winsvpn-windows-lab-watchdog-arm-v1",
            "winsvpn-windows-lab-watchdog-ready-v1",
            "winsvpn-windows-lab-watchdog-disarm-v1",
            "winsvpn-windows-lab-watchdog-receipt-v1",
        ):
            self.assertIn(contract, self.text)

    def test_parameter_surface_is_fixed(self) -> None:
        parameter_block = self.text[: self.text.index("Set-StrictMode")]
        for required in ("RunId", "CollectorClosureSha256", "DeadlineSeconds"):
            self.assertIn(required, parameter_block)
        for forbidden in (
            "WatchdogScript",
            "InvokeTool",
            "OutputRoot",
            "HelperRoot",
            "FirewallGroup",
            "InstalledGui",
        ):
            self.assertNotIn(forbidden, parameter_block)

    def test_exact_ten_entry_lab_helper_closure(self) -> None:
        closure_start = self.text.index("function Assert-ExactHelperClosure")
        closure_end = self.text.index("function Get-StateDocument")
        closure = self.text[closure_start:closure_end]
        expected_names = [
            "windows_lab_physical_collector.ps1",
            "windows_lab_interactive_worker.ps1",
            "windows_secure_state_helpers.ps1",
            "windows_lab_safe_watchdog.ps1",
            "windows_lab_fixed_ui.ps1",
            "windows_lab_matrix_evidence.py",
            "windows_lab_bundle_index.schema.json",
            "windows_lab_machine_evidence.schema.json",
            "windows_spain_live_observation.py",
            "windows_core_live_observation.py",
        ]
        entries = re.findall(r"source = 'tools/([^']+)'", closure)
        self.assertEqual(entries, expected_names)
        self.assertIn("helper root contains unexpected execution material", closure)
        self.assertIn("FileShare]::None", closure)
        self.assertIn("full helper composite closure digest changed", closure)

    def test_system_acl_and_locked_read_boundary(self) -> None:
        self.assertIn("Assert-SystemIdentity", self.text)
        self.assertIn("S-1-5-18", self.text)
        self.assertIn("Assert-NoReparsePath", self.text)
        self.assertIn("Assert-OwnerOnlyAcl", self.text)
        self.assertIn("S-1-5-32-544", self.text)
        self.assertGreaterEqual(self.text.count("FileShare]::None"), 2)
        self.assertIn("windows_lab_safe_watchdog.ps1'", self.text)
        self.assertIn("must execute only from the locked helper root", self.text)

    def test_nonpublishable_invariants_are_checked_and_emitted(self) -> None:
        for required in (
            "$Context.evidence_class -cne 'nonpublishable_lab'",
            "$Context.lab_only -ne $true",
            "$Context.publication_authorized -ne $false",
            "$Context.public_release_gate_eligible -ne $false",
            "$Context.unsigned_local_candidate -ne $true",
            "$Context.authenticode_status -cne 'NotSigned'",
            "$Context.payload_manifest_sha256 -notmatch '^[0-9a-f]{64}$'",
            "evidence_class = 'nonpublishable_lab'",
            "lab_only = $true",
            "publication_authorized = $false",
            "public_release_gate_eligible = $false",
            "unsigned_local_candidate = $true",
        ):
            self.assertIn(required, self.text)

    def test_ready_is_written_only_after_exact_healthy_baseline(self) -> None:
        identity = self.text.index("Assert-SystemIdentity\n")
        baseline = self.text.index("$readyStateSha256 = Get-CanonicalSha256")
        health_rejection = self.text.index(
            "Lab watchdog refused to arm away from its exact healthy baseline"
        )
        ready = self.text.index("Write-NewJson $readyPath")
        transition_wait = self.text.index("$started = [DateTime]::UtcNow")
        self.assertLess(identity, baseline)
        self.assertLess(baseline, health_rejection)
        self.assertLess(health_rejection, ready)
        self.assertLess(ready, transition_wait)
        self.assertIn("$readyEgressSha256", self.text)
        self.assertIn("$readyManagement", self.text)
        self.assertIn("$readyDns", self.text)

    def test_disarm_is_nonce_bound_and_requires_exact_baseline(self) -> None:
        wait_start = self.text.index("do {", self.text.index("$normal = $false"))
        emergency_start = self.text.index("if (-not $normal)", wait_start)
        wait = self.text[wait_start:emergency_start]
        for required in (
            "$disarm.step_nonce -ceq [string]$arm.step_nonce",
            "$disarm.sequence -eq [int]$arm.sequence",
            "$disarm.normal_teardown_proven -eq $true",
            "$disarm.fail_safe_triggered -eq $false",
            "$disarm.baseline_state_sha256",
            "$stateSha256 -ceq [string]$baseline.state_sha256",
        ):
            self.assertIn(required, wait)

    def test_emergency_cleanup_can_never_pass(self) -> None:
        emergency = self.text.index("$emergency = $true")
        stop_gui = self.text.index("Stop-Process -Id", emergency)
        pass_expression = self.text.index(
            "$pass = $normal -and -not $emergency", emergency
        )
        receipt = self.text.index("pass = $pass", pass_expression)
        self.assertLess(emergency, stop_gui)
        self.assertLess(stop_gui, pass_expression)
        self.assertLess(pass_expression, receipt)
        self.assertIn("fail_safe_triggered = $emergency", self.text)
        self.assertIn("normal_teardown_proven = $normal", self.text)

    def test_emergency_cleanup_is_scoped_to_exact_lab_resources(self) -> None:
        for required in (
            '"WinsVPN-Lab-$RunId"',
            "'WinsVPNSplitTunnel'",
            "'AmneziaWGTunnel$winsvpn'",
            "'AmneziaWGTunnel$awg2'",
            "Test-ExactImage -Pid ([int]$runtime.candidate_pid)",
            "Test-ExactImage -Pid $xrayProcess.Id",
            "Restart-Service -Name 'WinsVpnTunnelManager'",
        ):
            self.assertIn(required, self.text)
        self.assertNotIn("Get-Service AmneziaWG*", self.text)
        self.assertNotIn("Get-Process wins_vpn |", self.text)

    def test_receipt_requires_natural_full_restoration(self) -> None:
        pass_start = self.text.index("$pass = $normal -and -not $emergency")
        pass_block = self.text[pass_start : self.text.index("$receipt =", pass_start)]
        for required in (
            "$cleanupErrors.Count -eq 0",
            "$finalStateSha256 -ceq [string]$baseline.state_sha256",
            "$finalDns",
            "$finalManagement",
            "$finalEgressSha256 -ceq [string]$baseline.egress_state_sha256",
        ):
            self.assertIn(required, pass_block)
        self.assertIn("Unregister-ScheduledTask -TaskName $TaskName", self.text)

    def test_worker_and_watchdog_use_the_identical_state_document(self) -> None:
        def function_text(text: str, function_name: str) -> str:
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
            self.fail(f"unterminated function {function_name}")

        worker = (ROOT / "windows_lab_interactive_worker.ps1").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            function_text(worker, "Get-StateDocument"),
            function_text(self.text, "Get-StateDocument"),
        )


if __name__ == "__main__":
    unittest.main()
