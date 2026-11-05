from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tools" / "windows_guarded_power_harness.ps1"


class WindowsGuardedPowerHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = HARNESS.read_text(encoding="utf-8")

    def test_rejects_cross_session_main_window_handle_shortcut(self) -> None:
        self.assertNotIn("MainWindowHandle", self.text)
        self.assertIn("EnumWindows", self.text)
        self.assertIn("GetWindowThreadProcessId", self.text)
        self.assertIn("FLUTTER_RUNNER_WIN32_WINDOW", self.text)
        self.assertIn("Win's VPN", self.text)
        self.assertIn("IsWindowVisible", self.text)
        self.assertIn("IsIconic", self.text)
        self.assertIn("DwmGetWindowAttribute", self.text)
        self.assertIn("Where-Object { $_.SessionId -eq $sessionId }", self.text)

    def test_flutter_surface_is_unique_same_pid_descendant_not_direct_lookup(self) -> None:
        self.assertIn("EnumChildWindows", self.text)
        self.assertIn("EnumerateDescendants", self.text)
        self.assertIn("FindExactFlutterView", self.text)
        self.assertIn('String.Equals(window.ClassName, "FLUTTERVIEW"', self.text)
        self.assertIn("processId != expectedProcessId", self.text)
        self.assertIn("matches == 1 ? match : IntPtr.Zero", self.text)
        self.assertNotIn("FindWindowEx", self.text)

    def test_dry_run_receipts_record_surface_and_msaa_binding(self) -> None:
        for token in (
            "window_tree",
            "flutter_view",
            "direct_child",
            "msaa_label_root",
            "class_name",
            "process_id",
            "visible",
        ):
            self.assertIn(token, self.text)

    def test_failed_msaa_probe_records_read_only_exact_uia_observation(self) -> None:
        self.assertIn("UIAutomationClient", self.text)
        self.assertIn("AutomationElement]::FromHandle($RootWindow)", self.text)
        self.assertIn("AutomationElement]::NameProperty, $Label", self.text)
        self.assertIn("ControlType]::Button", self.text)
        self.assertIn("TreeScope]::Subtree", self.text)
        self.assertIn("exact_button_match_count", self.text)
        self.assertIn("accessibility_observation", self.text)

    def test_exact_binary_and_geometry_guards_are_mandatory(self) -> None:
        for token in (
            "ExpectedGuiSha256",
            "Get-StructuralUiSignature",
            "Get-JsonSha256",
            "app_sha256 = $AppSha256",
            "process_id = $ProcessId",
            "session_id = $SessionId",
            "top_level_hwnd = $TopLevelWindow.ToInt64()",
            "parent = [long]$FlutterBinding.parent",
            "class_name = [string]$FlutterBinding.class_name",
            "visible = [bool]$FlutterBinding.visible",
            "direct_child = (",
            "GetClientRect",
            "ClientToScreen",
            "GetDpiForWindow",
            "left = [int]$Client.left",
            "top = [int]$Client.top",
            "width = [int]$Client.width",
            "height = [int]$Client.height",
            "dpi = $Dpi",
            "label = [string]$ConnectObservation.label",
            "role = [int]$ConnectObservation.role",
            "state = [int]$ConnectObservation.state",
            "x_fraction =",
            "y_fraction =",
        ):
            self.assertIn(token, self.text)

    def test_visual_hash_and_one_use_guards_are_fail_closed(self) -> None:
        self.assertIn("screenshot_sha256", self.text)
        self.assertIn("baseline.png", self.text)
        self.assertIn("cancel-state.png", self.text)
        self.assertIn("Visual state did not change", self.text)
        self.assertIn(
            "if (-not $script:DiagnosticTransitionScreenshotChanged)",
            self.text,
        )
        self.assertIn("ui_signature=$uiSignature", self.text)
        self.assertIn("ui_signature_sha256=$uiSignatureHash", self.text)
        self.assertIn(
            "$readySignatureHash -cne $uiSignatureHash", self.text
        )
        self.assertIn(
            "$readySignatureJson -cne $currentSignatureJson", self.text
        )
        self.assertIn("baseline_screenshot_changed", self.text)
        self.assertNotIn(
            "[string]$ready.screenshot_sha256 -cne $screenshotHash",
            self.text,
        )
        self.assertIn("Remove-Item -LiteralPath $readyPath -Force", self.text)
        structural_guard = self.text.index(
            "$readySignatureJson -cne $currentSignatureJson"
        )
        consume = self.text.index("Remove-Item -LiteralPath $readyPath -Force")
        self.assertLess(structural_guard, consume)
        self.assertLess(
            consume,
            self.text.index("mouse_event(0x0002"),
        )

    def test_cancel_uses_unique_guarded_dynamic_center(self) -> None:
        self.assertIn("FindLabel($flutterView, 'Connect VPN')", self.text)
        self.assertIn("FindLabel($flutterView, 'Cancel VPN connection')", self.text)
        self.assertIn(
            "return matches.Count == 1 ? matches[0] : null;", self.text
        )
        self.assertIn("Assert-DynamicCancel", self.text)
        self.assertIn("Get-ControlRelationship", self.text)
        self.assertIn("max_center_fraction_delta_x = 0.08", self.text)
        self.assertIn("max_center_fraction_delta_y = 0.25", self.text)
        self.assertIn("overlap_required = $false", self.text)
        self.assertNotIn("min_overlap_fraction_of_smaller", self.text)
        self.assertIn("$Observation.center.y_fraction -lt 0.55", self.text)
        self.assertIn("$Observation.center.y_fraction -gt 0.75", self.text)
        self.assertIn("$Match.Role -ne 43", self.text)
        self.assertIn("($Match.State -band 0x8000) -ne 0", self.text)
        self.assertIn("($Match.State -band 0x10000) -ne 0", self.text)
        self.assertIn("($Match.State -band 0x1) -ne 0", self.text)
        self.assertIn("Guarded control is outside the exact client rectangle", self.text)
        self.assertIn("overlap = [ordered]@{", self.text)
        self.assertIn("fraction_of_smaller", self.text)
        self.assertIn(
            "$script:DiagnosticTransitionScreenshotChanged", self.text
        )
        self.assertIn("SetCursorPos($cancelX, $cancelY)", self.text)
        self.assertNotIn(
            "Cancel state no longer contains the guarded coordinate", self.text
        )
        self.assertGreaterEqual(self.text.count("mouse_event(0x0002"), 2)
        self.assertGreaterEqual(self.text.count("mouse_event(0x0004"), 2)

        label = self.text.index("Enter-ExecuteStage 'cancel_label_seen'")
        observation = self.text.index(
            "$script:DiagnosticCancelObservation = $cancelObservation", label
        )
        image = self.text.index("Enter-ExecuteStage 'cancel_image'", observation)
        capture = self.text.index("Capture-Client $window $transitionPath", image)
        geometry = self.text.index(
            "Enter-ExecuteStage 'cancel_geometry_valid'", capture
        )
        dynamic_guard = self.text.index("Assert-DynamicCancel", geometry)
        dynamic_click = self.text.index(
            "SetCursorPos($cancelX, $cancelY)", dynamic_guard
        )
        self.assertEqual(
            [label, observation, image, capture, geometry, dynamic_guard, dynamic_click],
            sorted(
                [
                    label,
                    observation,
                    image,
                    capture,
                    geometry,
                    dynamic_guard,
                    dynamic_click,
                ]
            ),
        )

    def test_all_searches_and_post_click_cleanup_are_bounded(self) -> None:
        self.assertIn("MaxNodes = 2048", self.text)
        self.assertIn("MaxDepth = 32", self.text)
        self.assertIn("$connectDeadline = [DateTime]::UtcNow.AddSeconds(5)", self.text)
        self.assertIn("Start-Sleep -Milliseconds 100", self.text)
        self.assertIn("AddSeconds(3)", self.text)
        self.assertIn("AddSeconds(12)", self.text)
        self.assertIn("Test-ZeroResidue", self.text)

    def test_every_pre_receipt_failure_emits_private_sanitized_error(self) -> None:
        self.assertIn("try {", self.text)
        self.assertIn("} catch {", self.text)
        self.assertIn("} finally {", self.text)
        self.assertIn("$env:LOCALAPPDATA", self.text)
        self.assertIn("dry-run-error.json", self.text)
        self.assertIn("winsvpn-guarded-power-dry-run-error-v1", self.text)
        self.assertIn("sanitized_message", self.text)
        self.assertIn("secret_material_redacted = $true", self.text)
        self.assertIn("exception_type", self.text)
        self.assertIn("app_sha256", self.text)
        self.assertIn("session_id", self.text)
        self.assertIn("process_id", self.text)
        self.assertIn("$allowedStages", self.text)
        self.assertIn("exit 1", self.text)
        catch = self.text.index("} catch {")
        receipt = self.text.index("dry-run-error.json")
        self.assertGreater(catch, receipt)

    def test_execute_stages_are_bounded_ordered_and_mark_input(self) -> None:
        expected = (
            "nonce_validated",
            "nonce_consumed",
            "foreground",
            "cursor_verified",
            "connect_input_sent",
            "cancel_label_seen",
            "cancel_image",
            "cancel_geometry_valid",
            "cancel_input_sent",
            "zero_residue",
        )
        allowlist = self.text.split(
            "$script:ExecuteStageAllowList = @(", 1
        )[1].split(")", 1)[0]
        self.assertEqual(re.findall(r"'([^']+)'", allowlist), list(expected))

        flow_start = self.text.index("Enter-ExecuteStage 'nonce_validated'")
        positions = [
            self.text.index(f"Enter-ExecuteStage '{stage}'", flow_start)
            for stage in expected
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("$script:ConnectInputSent = $true", self.text)
        self.assertIn("$script:CancelInputSent = $true", self.text)
        self.assertIn("Complete-ExecuteStage", self.text)

    def test_execute_failure_receipt_is_private_sanitized_and_exact(self) -> None:
        for token in (
            "execute-error.json",
            "winsvpn-guarded-power-execute-error-v1",
            "completed_stages",
            "connect_input_sent",
            "cancel_input_sent",
            "sanitized_message",
            "Get-SanitizedExceptionMessage",
            "app_sha256",
            "process_id",
            "session_id",
            "hwnd",
            "final_zero_residue",
            "Get-ZeroResidueSnapshot",
            "Set-OwnerOnlyAcl",
            "SetAccessRuleProtection($true, $false)",
        ):
            self.assertIn(token, self.text)
        self.assertIn("elseif ($Mode -eq 'Execute')", self.text)
        self.assertIn("Write-PrivateJson $executeErrorPath $errorReceipt", self.text)

    def test_private_receipt_acl_preserves_verified_current_owner(self) -> None:
        self.assertNotIn(".SetOwner(", self.text)
        for token in (
            "$acl.GetOwner(",
            "$owner.Equals($identity)",
            "SetAccessRuleProtection($true, $false)",
            "$acl.GetAccessRules(",
            "RemoveAccessRuleSpecific($rule)",
            "FileSystemRights]::FullControl",
            "$verified.GetOwner(",
            "$verified.AreAccessRulesProtected",
            "$foreignAllowRules.Count -ne 0",
            "$allowRules.Count -ne 1",
            "$currentFullControlRules.Count -ne 1",
            "$verifiedRules.Count -ne 1",
            "Private receipt owner does not match the current user.",
            "Private receipt ACL verification failed.",
        ):
            self.assertIn(token, self.text)

    def test_execute_success_receipt_records_stages_inputs_and_screenshots(
        self,
    ) -> None:
        for token in (
            "execute-success.json",
            "winsvpn-guarded-power-execute-success-v1",
            "completed_stages = @($script:ExecuteCompletedStages)",
            "connect_input_sent = $script:ConnectInputSent",
            "cancel_input_sent = $script:CancelInputSent",
            "connect = $script:DiagnosticConnectObservation",
            "cancel = $script:DiagnosticCancelObservation",
            "relationship = $script:DiagnosticControlRelationship",
            "baseline",
            "ready_sha256",
            "execute_sha256",
            "baseline_screenshot_changed",
            "cancel_state",
            "transition_screenshot_changed",
            "final_zero_residue = $finalResidue",
            "Write-PrivateJson $executeSuccessPath $successReceipt",
            "WINDOWS_GUARDED_POWER_CANCEL=PASS",
        ):
            self.assertIn(token, self.text)

    def test_powershell_parser_accepts_harness(self) -> None:
        powershell = (
            shutil.which("pwsh")
            or shutil.which("powershell")
            or shutil.which("powershell.exe")
        )
        if powershell is None:
            self.skipTest("PowerShell parser is unavailable")
        path = str(HARNESS).replace("'", "''")
        command = (
            "$tokens=$null;$errors=$null;"
            "[void][System.Management.Automation.Language.Parser]::ParseFile("
            f"'{path}',[ref]$tokens,[ref]$errors);"
            "if($errors.Count){$errors|ForEach-Object{$_.ToString()};exit 1}"
        )
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"{result.stdout}\n{result.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
