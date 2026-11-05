#!/usr/bin/env python3
"""Focused regression contract for the exact Windows pre-freeze hardening."""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
SCRIPTS = {
    "binder": TOOLS / "windows_prefreeze_bind_exact_case.ps1",
    "runner": TOOLS / "windows_prefreeze_exact_matrix_case.ps1",
    "watchdog": TOOLS / "windows_prefreeze_exact_watchdog.ps1",
}
RUNTIME_TEST = TOOLS / "test_windows_prefreeze_hardening_runtime.ps1"
LIVE_CYCLE = TOOLS / "windows_interactive_live_cycle.ps1"
WINDOWS_SECURE_STATE_HELPER = TOOLS / "windows_secure_state_helpers.ps1"
GUI_VERIFIER = TOOLS / "windows_prefreeze_interactive_gui_verify.ps1"
BIND_LAUNCHER = TOOLS / "windows_prefreeze_interactive_bind_launcher.ps1"
WINDOWS_BACKEND = ROOT / "windows" / "runner" / "windows_tunnel_backend.cpp"


def function_body(text: str, name: str, next_name: str) -> str:
    return text.split(f"function {name} {{", 1)[1].split(
        f"function {next_name} {{", 1
    )[0]


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


class WindowsPreFreezeHardeningContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = {
            name: path.read_text(encoding="utf-8")
            for name, path in SCRIPTS.items()
        }

    def test_residue_providers_fail_loud_with_structured_evidence(self) -> None:
        for name, text in self.text.items():
            with self.subTest(script=name):
                self.assertIn("function Invoke-ResidueProviderQuery", text)
                self.assertRegex(text, r"Get-Service(?:\s+-\S+)*\s+-ErrorAction Stop")
                self.assertRegex(text, r"Get-NetAdapter(?:\s+-\S+)*\s+-ErrorAction Stop")
                self.assertRegex(text, r"Get-NetRoute\s+-ErrorAction Stop")
                self.assertIn(
                    "Get-Process xray -ErrorAction SilentlyContinue", text
                )
                self.assertIn(
                    "error_id = 'WINS_PREFREEZE_RESIDUE_PROVIDER_FAILURE'",
                    text,
                )
                self.assertIn("provider = $Provider", text)
                self.assertIn("residue_provider_errors", text)
                self.assertIn("xray_absence_is_expected_zero = $true", text)

    def test_state_roots_and_enumerated_entries_reject_reparse_points(self) -> None:
        for name, text in self.text.items():
            with self.subTest(script=name):
                self.assertIn("function Assert-NoReparsePath", text)
                self.assertIn("[IO.FileAttributes]::ReparsePoint", text)
                self.assertIn("function Get-VerifiedStateFiles", text)
                self.assertIn("Assert-NoReparsePath $item.FullName", text)
                self.assertIn("if ($item.PSIsContainer)", text)
                self.assertIn("state_reparse_checks_enforced = $true", text)

        watchdog = self.text["watchdog"]
        restore = function_body(
            watchdog, "Restore-StateFromBackup", "Test-RecoveredStateContract"
        )
        self.assertIn("Get-VerifiedStateFiles $SecureBackup", restore)
        self.assertIn("Get-VerifiedStateFiles $LegacyBackup", restore)
        self.assertIn("Get-VerifiedStateFiles $SecureStateRoot", restore)
        self.assertIn("Get-VerifiedStateFiles $LegacyStateRoot", restore)
        self.assertNotRegex(
            restore,
            r"Get-ChildItem\s+-LiteralPath\s+\$(?:Secure|Legacy)(?:StateRoot|Backup)\s+-File",
        )
        self.assertGreaterEqual(restore.count("Assert-NoReparsePath $temporary"), 4)

    def test_exact_gui_stop_and_new_pid_proofs_are_bounded(self) -> None:
        for name in ("runner", "watchdog"):
            text = self.text[name]
            stop = function_body(text, "Stop-ExactGui", "Invoke-GuiLaunchTimedStep")
            with self.subTest(script=name):
                self.assertIn("AddSeconds(10)", stop)
                self.assertIn("old_exact_hash_pids", stop)
                self.assertIn("remaining_old_pids", stop)
                self.assertIn("all_old_pids_exited", stop)
                self.assertGreaterEqual(
                    stop.count("$remainingPids = @($oldPids | Where-Object"), 2
                )
                self.assertIn("-ErrorAction Stop", stop)

        runner = self.text["runner"]
        watchdog = self.text["watchdog"]
        self.assertRegex(
            runner,
            r"Get-OnlyNormalExactGui\s+-SessionId\s+\$sessionId\s+`?\s*"
            r"-ExcludedPids\s+\$stoppedPids",
        )
        self.assertIn("$stoppedPids -notcontains [int]$process.Id", runner)
        self.assertIn("Get-NormalGuiProcess -ExcludedPids $stoppedPids", watchdog)
        self.assertIn("$stoppedPids -notcontains [int]$process.Id", watchdog)
        self.assertIn("FindExactWindow", runner)
        self.assertNotIn("user32.dll", watchdog)
        self.assertNotIn("EnumWindows", watchdog)

    def test_gui_task_steps_have_timing_and_no_job_wrappers(self) -> None:
        for name in ("runner", "watchdog"):
            text = self.text[name]
            timed = function_body(
                text, "Invoke-GuiLaunchTimedStep", "Assert-GuiTaskSemanticContract"
            )
            with self.subTest(script=name):
                self.assertIn("ValidateSet('register', 'semantic', 'start')", timed)
                self.assertIn("[Diagnostics.Stopwatch]::StartNew()", timed)
                self.assertIn("_duration_ms", timed)
                self.assertIn("_within_limit", timed)
                self.assertNotIn("Start-Job", timed)
                self.assertIn("-LimitSeconds 30", text)
                self.assertIn("AddSeconds(20)", text)
                self.assertIn("gui_launch_timing_evidence", text)

        self.assertNotIn("Start-Job", self.text["binder"])
        self.assertNotIn("Start-Job", self.text["watchdog"])
        self.assertEqual(1, self.text["runner"].count("Start-Job"))
        observer = function_body(
            self.text["runner"], "Start-XrayPortObserver", "Stop-XrayPortObserver"
        )
        self.assertIn("Start-Job", observer)

    def test_exact_tasks_have_bound_identity_arguments_triggers_and_limits(self) -> None:
        binder = self.text["binder"]
        self.assertIn("function Assert-RegisteredTaskContract", binder)
        self.assertIn("$registeredTriggers.Count -ne 0", binder)
        self.assertIn("$xmlTriggers.Count -ne 0", binder)
        self.assertIn("$registeredActions.Count -ne 1", binder)
        self.assertIn("$ExpectedArguments", binder)
        self.assertIn("$limitSeconds -ne $ExpectedExecutionLimitSeconds", binder)
        self.assertIn("-ExpectedRunnerSha256 ' + $ExpectedRunnerSha256", binder)
        self.assertIn("-ExpectedWatchdogSha256 ' + $ExpectedWatchdogSha256", binder)
        self.assertIn(
            "-ExpectedGuiVerifierSha256 ' + $ExpectedGuiVerifierSha256",
            binder,
        )
        self.assertIn("$watchdogExecutionLimitSeconds", binder)
        self.assertIn(
            "task_termination_margin_seconds = $taskTerminationMarginSeconds",
            binder,
        )

    def test_runner_watchdog_and_gui_verifier_are_self_hash_bound(self) -> None:
        runner = self.text["runner"]
        watchdog = self.text["watchdog"]
        verifier = GUI_VERIFIER.read_text(encoding="utf-8")
        self.assertIn("(Get-Sha256 $PSCommandPath) -cne $ExpectedRunnerSha256", runner)
        self.assertIn("runner_self_hash_verified", runner)
        self.assertIn("(Get-Sha256 $PSCommandPath) -cne $ExpectedWatchdogSha256", watchdog)
        self.assertIn("$watchdogSelfHashVerified", watchdog)
        self.assertIn(
            "Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256",
            verifier,
        )
        self.assertIn("$ExpectedVerifierSha256", verifier)
        self.assertIn("verifier_sha256", verifier)

    def test_watchdog_uses_terminal_stage_budget_and_interactive_window_proof(self) -> None:
        watchdog = self.text["watchdog"]
        self.assertIn("$status.result -in @('passed', 'failed')", watchdog)
        self.assertIn("$stageFreshSeconds = 180", watchdog)
        self.assertIn("$stageAge -ge -5 -and $stageAge -le $stageFreshSeconds", watchdog)
        self.assertIn("$recoveryMustStartBy", watchdog)
        self.assertIn("Assert-RecoveryBudgetRemaining -MinimumSeconds 300", watchdog)
        self.assertIn("function Restore-TunnelManagerRunning", watchdog)
        self.assertIn("finally {", watchdog)
        self.assertIn("function Invoke-InteractiveVisibleGuiProof", watchdog)
        self.assertIn("<LogonType>InteractiveToken</LogonType>", watchdog)
        self.assertIn("interactive_visible_window_verified", watchdog)

    def test_live_cycle_gates_observed_double_dns_ipv6_wfp_and_privacy(self) -> None:
        live = LIVE_CYCLE.read_text(encoding="utf-8")
        secure_helper = WINDOWS_SECURE_STATE_HELPER.read_text(encoding="utf-8")
        self.assertIn("double_vpn_active = $observedDoubleVpnActive", live)
        self.assertIn("double_vpn_core_id_sha256", live)
        self.assertIn("double_vpn_exit_slug_sha256", live)
        self.assertIn("configured_first_hop_sha256", live)
        self.assertIn("client_physical_two_hop_proven = $false", live)
        self.assertIn("external_core_pairing_required = $doubleVpnExpected", live)
        self.assertIn("stable_within_manager_generation = $true", live)
        self.assertIn("windows_secure_state_helpers.ps1", live)
        self.assertIn("Read-WinsVpnSecureJson", live)
        self.assertIn("legacy plaintext $Name state is forbidden", secure_helper)
        self.assertIn("direct_external_dns_blocked_while_connected", live)
        self.assertIn("direct_external_dns_restored_after_disconnect", live)
        self.assertIn("connected_ipv6_non_tunnel_default_route_count", live)
        self.assertIn("forced_literal_egress_failed = $true", live)
        self.assertIn("original_ipv6_default_routes_restored = $true", live)
        self.assertIn("original_physical_ms_tcpip6_bindings_restored = $true", live)
        self.assertIn("final_owned_wfp_filters_zero = $true", live)
        self.assertIn("final_xray_process_zero", live)
        self.assertIn("WINS_PREFREEZE_PRIVACY_CONSENT_REQUIRED", live)
        power = function_body(live, "Invoke-PowerButton", "Get-TunnelManagerCommitState")
        self.assertGreaterEqual(power.count("Assert-NoPrivacyConsentOverlay"), 2)
        self.assertLess(
            power.rindex("Assert-NoPrivacyConsentOverlay"),
            power.index("[WinsVpnLiveNative]::mouse_event(0x0002"),
        )

    def test_final_residue_includes_owned_wfp_and_is_a_result_gate(self) -> None:
        for name, text in self.text.items():
            with self.subTest(script=name):
                self.assertIn("function Get-OwnedWfpFilterCount", text)
                self.assertIn("21e068a2-2851-43c5-8a29-7afe3f260384", text)
                self.assertIn("e65841b6-82f6-4d55-bde2-61f84d4508d4", text)
        runner = self.text["runner"]
        self.assertIn("if (-not $finalResidue.is_zero)", runner)
        self.assertIn("owned_wfp_filter_count", runner)
        self.assertIn("Final native, Xray, or WFP residue remained.", runner)

    def test_native_strict_acl_rejects_inherited_aces(self) -> None:
        backend = WINDOWS_BACKEND.read_text(encoding="utf-8")
        strict = backend.split("bool HasStrictCurrentUserSystemDacl", 1)[1]
        strict = strict.split("#endif", 1)[0]
        self.assertIn("(control & SE_DACL_PROTECTED) != 0", strict)
        self.assertIn("info.AceCount == 2", strict)
        self.assertIn("(ace->Header.AceFlags & INHERITED_ACE) == 0", strict)

    def test_worker_predicates_and_all_powershell_parsers_are_clean(self) -> None:
        worker = (TOOLS / "windows_lab_interactive_worker.ps1").read_text(
            encoding="utf-8"
        )
        split_operator = re.compile(
            r"Where-Object\s+[A-Za-z_][A-Za-z0-9_.]*\s+"
            r"-(?:[ci]?(?:eq|ne|like|notlike|match|notmatch|gt|ge|lt|le)|"
            r"contains|notcontains|in|notin)\s*\r?\n",
            re.IGNORECASE,
        )
        self.assertIsNone(split_operator.search(worker))

        shell = powershell_executable()
        if shell is None:
            self.skipTest("PowerShell is unavailable")
        quoted = ",".join(
            "'" + str(path).replace("'", "''") + "'"
            for path in (
                *SCRIPTS.values(), LIVE_CYCLE, GUI_VERIFIER, BIND_LAUNCHER,
                TOOLS / "windows_lab_interactive_worker.ps1",
            )
        )
        command = (
            f"$files=@({quoted}); foreach($f in $files){{"
            "$t=$null;$e=$null;"
            "[void][System.Management.Automation.Language.Parser]::ParseFile("
            "$f,[ref]$t,[ref]$e); if($e.Count){throw ($e|Out-String)}}"
        )
        completed = subprocess.run(
            [str(shell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

    @unittest.skipUnless(os.name == "nt", "Windows reparse/provider regression")
    def test_provider_and_reparse_runtime_regressions(self) -> None:
        shell = powershell_executable()
        self.assertIsNotNone(shell)
        completed = subprocess.run(
            [
                str(shell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(RUNTIME_TEST),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        receipts = [
            json.loads(line)
            for line in completed.stdout.splitlines()
            if line.strip().startswith("{")
        ]
        self.assertTrue(receipts, completed.stdout)
        receipt = receipts[-1]
        self.assertTrue(receipt["pass"])
        self.assertTrue(receipt["provider_failed_loud"])
        self.assertTrue(receipt["provider_error_structured"])
        self.assertTrue(receipt["root_reparse_rejected"])
        self.assertTrue(receipt["file_below_reparse_rejected"])
        self.assertTrue(receipt["cleanup_verified"])


if __name__ == "__main__":
    unittest.main()
