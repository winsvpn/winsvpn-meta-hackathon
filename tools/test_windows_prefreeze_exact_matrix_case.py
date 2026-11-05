#!/usr/bin/env python3
"""Static safety contract for the exact pre-freeze Windows case runner."""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "windows_prefreeze_exact_matrix_case.ps1"
WINDOWS_BACKEND = ROOT / "windows" / "runner" / "windows_tunnel_backend.cpp"
ACL_RUNTIME_TEST = (
    ROOT / "tools" / "test_windows_prefreeze_securestate_acl_runtime.ps1"
)


class WindowsPreFreezeExactMatrixCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = SCRIPT.read_text(encoding="utf-8")
        cls.backend = WINDOWS_BACKEND.read_text(encoding="utf-8")

    def test_cases_are_explicit_and_bounded(self) -> None:
        for case in (
            "double-natural",
            "double-xray80",
            "double-xray443",
            "single-natural",
            "single-xray80",
            "single-xray443",
            "single-split-curl",
        ):
            self.assertIn(f"'{case}'", self.text)
        self.assertIn("[ValidateRange(60, 120)]", self.text)
        self.assertIn("ConnectTimeoutSeconds", self.text)

    def test_exact_candidate_and_nonpublication_markers_are_mandatory(self) -> None:
        self.assertIn("ExpectedGuiSha256", self.text)
        self.assertIn("ExpectedServiceSha256", self.text)
        self.assertIn("Installed Windows payload does not match", self.text)
        self.assertIn("evidence_class = 'prefreeze_nonpublishable'", self.text)
        self.assertIn("publication_authorized = $false", self.text)
        self.assertIn("public_release_gate_eligible = $false", self.text)

    def test_state_is_backed_up_and_restored_before_success(self) -> None:
        self.assertIn("Backup-StateFiles $SecureStateRoot", self.text)
        self.assertIn("Restore-StateFiles $SecureStateRoot", self.text)
        self.assertIn("protected_state_restored_byte_for_byte", self.text)
        self.assertIn("Final protected state digest changed", self.text)
        self.assertIn("$secureStateRootExisted", self.text)
        self.assertIn("$legacyStateRootExisted", self.text)
        self.assertIn("if (-not $RootExisted)", self.text)
        self.assertRegex(
            self.text,
            r"if \(\$result -ne 'passed'\) \{ exit 1 \}",
        )

    def test_forcing_is_scoped_and_removed(self) -> None:
        self.assertIn("WinsVPN-PreFreeze-$RunLeaf", self.text)
        self.assertIn("RemotePort $port", self.text)
        self.assertIn("RemotePort $otherPort", self.text)
        self.assertIn("Get-NetFirewallRule -Group $FirewallGroup", self.text)
        self.assertIn("Remove-NetFirewallRule -ErrorAction Stop", self.text)
        self.assertIn("Temporary fallback forcing rules remained", self.text)
        self.assertNotIn("Set-NetFirewallProfile", self.text)
        self.assertNotIn("netsh advfirewall reset", self.text.lower())

    def test_actual_xray_port_and_zero_residue_are_required(self) -> None:
        self.assertIn("Get-NetTCPConnection", self.text)
        self.assertIn("observed_xray_remote_ports", self.text)
        self.assertIn("$observedXrayPorts -notcontains $target", self.text)
        self.assertIn("final_zero_residue", self.text)
        self.assertIn("Exact normal-token GUI did not restore", self.text)

    def test_gui_launch_is_interactive_and_never_inherits_elevation(self) -> None:
        self.assertIn("<LogonType>InteractiveToken</LogonType>", self.text)
        self.assertIn("<RunLevel>LeastPrivilege</RunLevel>", self.text)
        self.assertIn("Principal.LogonType -cne 'Interactive'", self.text)
        self.assertIn("Principal.RunLevel -cne 'Limited'", self.text)
        self.assertIn("$null -ne $runLevel -and", self.text)
        self.assertIn("$runLevel.InnerText -cne 'LeastPrivilege'", self.text)
        self.assertIn("[string]$actions[0].Execute", self.text)
        self.assertNotIn("$registeredXml -notmatch", self.text)
        self.assertIn("IsProcessElevated", self.text)
        self.assertIn("FindExactWindow", self.text)
        self.assertIn("live_gui_normal_token_verified", self.text)
        self.assertIn("final_gui_normal_token_verified", self.text)
        self.assertIn("Unregister-ScheduledTask", self.text)
        self.assertNotIn("Start-Process -FilePath $InstalledGui", self.text)

    def test_restore_is_armed_and_reapplies_the_native_dacl_contract(self) -> None:
        self.assertIn("$baselineArmed = $false", self.text)
        self.assertIn("$baselineArmed = $true", self.text)
        self.assertGreater(
            self.text.index("$baselineArmed = $true"),
            self.text.index("Backup-StateFiles $LegacyStateRoot"),
        )
        self.assertIn("if (-not $BaselineArmed)", self.text)
        self.assertIn("SetFileSecurityW", self.text)
        self.assertIn(
            "DaclSecurityInformation | ProtectedDaclSecurityInformation",
            self.text,
        )
        self.assertIn("D:P(A;;FA;;;SY)(A;;FA;;;$UserSid)", self.text)
        self.assertIn("Set-StrictSecureStateAcl -Root $Root", self.text)
        self.assertIn("Test-StrictSecureStateAcl", self.text)
        self.assertIn("$entries.Count -eq 2", self.text)
        self.assertNotIn("OwnerSecurityInformation", self.text)

    def test_preference_replacement_secures_temp_before_atomic_move(self) -> None:
        writer = self.text.split("function Write-ProtectedJson {", 1)[1]
        writer = writer.split("function Set-TestPreference {", 1)[0]
        ordered_contract = (
            "[IO.File]::WriteAllBytes($temporary, $framed)",
            "Set-StrictSecureStatePathAcl -Path $temporary",
            "Test-StrictSecureStatePathAcl -Path $temporary",
            "Move-Item -LiteralPath $temporary -Destination $path -Force",
            "Set-StrictSecureStatePathAcl -Path $path",
            "Test-StrictSecureStateAcl -Root $SecureStateRoot",
        )
        positions = [writer.index(marker) for marker in ordered_contract]
        self.assertEqual(sorted(positions), positions)
        self.assertIn("[string]$StrictDaclUserSid", writer)
        self.assertIn("Test-Path -LiteralPath $temporary", writer)
        self.assertIn("Remove-Item -LiteralPath $temporary", writer)

        preference = self.text.split("function Set-TestPreference {", 1)[1]
        preference = preference.split("function Add-ForcingRules {", 1)[0]
        self.assertIn("-StrictDaclUserSid $TargetUserSid", preference)
        self.assertIn(
            "Test-StrictSecureStateAcl -Root $SecureStateRoot",
            preference,
        )
        self.assertIn(
            "The test preference write did not preserve the strict DACL.",
            preference,
        )

    def test_runner_matches_native_fail_closed_secure_text_acl(self) -> None:
        self.assertIn("HasStrictCurrentUserSystemDacl", self.backend)
        self.assertIn("(control & SE_DACL_PROTECTED) != 0", self.backend)
        self.assertIn("info.AceCount == 2", self.backend)
        self.assertIn("ace->Mask == FILE_ALL_ACCESS", self.backend)
        self.assertIn(
            "(ace->Header.AceFlags & INHERITED_ACE) == 0",
            self.backend,
        )
        self.assertIn("found_user && found_system", self.backend)
        self.assertRegex(
            self.backend,
            r"if \(!HasStrictCurrentUserSystemDacl\(secure_path\)\) \{"
            r"\s*\*error = "
            r'"Stored secure text has an invalid access-control policy\."',
        )
        self.assertIn(
            "D:P(A;;FA;;;SY)(A;;FA;;;$UserSid)",
            self.text,
        )

    @unittest.skipUnless(os.name == "nt", "Windows ACL regression")
    def test_preference_atomic_acl_runtime_regression(self) -> None:
        shell = shutil.which("pwsh") or shutil.which("powershell")
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
                str(ACL_RUNTIME_TEST),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        json_lines = [
            line for line in completed.stdout.splitlines()
            if line.strip().startswith("{")
        ]
        self.assertTrue(json_lines, completed.stdout)
        receipt = json.loads(json_lines[-1])
        self.assertTrue(receipt["pass"])
        self.assertFalse(receipt["old_write_strict"])
        self.assertTrue(receipt["patched_temporary_strict"])
        self.assertTrue(receipt["atomic_replacement_strict"])
        self.assertTrue(receipt["scratch_removed"])

    def test_post_startup_state_handoff_has_two_stable_reads(self) -> None:
        self.assertIn("Start-Sleep -Seconds 8", self.text)
        self.assertIn("Start-Sleep -Seconds 2", self.text)
        self.assertIn("$firstStableRead", self.text)
        self.assertIn("$secondStableRead", self.text)
        self.assertIn("stable_state_handoff_verified", self.text)
        self.assertGreaterEqual(
            self.text.count("Restore-StateFiles $SecureStateRoot"), 3
        )
        self.assertIn("Test-StateFilesExact $LegacyStateRoot", self.text)

    def test_no_embedded_infrastructure_or_credentials(self) -> None:
        forbidden = (
            r"212\.227\.83\.9",
            r"66\.179\.190\.227",
            r"Oz2rbln9",
            r"9UZWGOuy",
            r"P@ssw0rd",
            r"client_private_key\s*=",
            r"preshared_key\s*=",
        )
        for pattern in forbidden:
            self.assertIsNone(re.search(pattern, self.text, re.IGNORECASE))


if __name__ == "__main__":
    unittest.main()
