#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import unittest


SCRIPT = pathlib.Path(__file__).with_name(
    "windows_prefreeze_exact_watchdog.ps1"
)


class WatchdogContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = SCRIPT.read_text(encoding="utf-8")

    def test_system_and_bounded(self) -> None:
        self.assertIn("$identity.User.Value -cne 'S-1-5-18'", self.text)
        self.assertIn("[ValidateRange(660, 900)]", self.text)
        self.assertIn("$DeadlineSeconds = 660", self.text)
        self.assertIn("[ValidateRange(300, 360)]", self.text)
        self.assertIn("$RecoveryReserveSeconds = 360", self.text)

    def test_recovery_is_nonce_scoped(self) -> None:
        self.assertIn("WinsVPN-PreFreeze-$RunLeaf", self.text)
        self.assertIn("Get-NetFirewallRule -Group $FirewallGroup", self.text)
        self.assertIn("$MainTaskName", self.text)
        self.assertNotIn("Set-NetFirewallProfile", self.text)
        self.assertNotIn("netsh advfirewall reset", self.text.lower())

    def test_state_and_normal_gui_are_recovered(self) -> None:
        self.assertIn("ExpectedSecureStateClosureSha256", self.text)
        self.assertIn("ExpectedLegacyStateClosureSha256", self.text)
        self.assertIn("ExpectedLegacyRootTopology", self.text)
        self.assertIn("Test-LegacyTopology", self.text)
        self.assertIn("Restore-StateFromBackup", self.text)
        self.assertIn("<LogonType>InteractiveToken</LogonType>", self.text)
        self.assertIn("<RunLevel>LeastPrivilege</RunLevel>", self.text)
        self.assertIn("Principal.LogonType -cne 'Interactive'", self.text)
        self.assertIn("Principal.RunLevel -cne 'Limited'", self.text)
        self.assertIn("$null -ne $runLevel -and", self.text)
        self.assertNotIn("$registered -notmatch", self.text)
        self.assertIn("IsElevated", self.text)
        self.assertIn("normal_gui_verified", self.text)

    def test_system_session_uses_process_proof_not_window_enumeration(self) -> None:
        self.assertIn("function Get-NormalGuiProcess", self.text)
        self.assertIn("$matches[0].SessionId -ne $TargetSessionId", self.text)
        self.assertIn("[IO.Path]::GetFullPath($InstalledGui)", self.text)
        self.assertNotIn("EnumWindows", self.text)
        self.assertNotIn("FindWindow", self.text)
        self.assertNotIn("DwmGetWindowAttribute", self.text)
        self.assertNotIn("user32.dll", self.text)

    def test_recovery_is_armed_and_restores_strict_dacl_only(self) -> None:
        self.assertIn("$baselineArmed = $false", self.text)
        self.assertIn("$script:baselineArmed = $true", self.text)
        self.assertIn("if (-not $script:baselineArmed)", self.text)
        self.assertIn("SetFileSecurityW", self.text)
        self.assertIn("DaclSecurity|ProtectedDacl", self.text)
        self.assertIn(
            '"D:P(A;;FA;;;SY)(A;;FA;;;$TargetUserSid)"', self.text
        )
        self.assertIn("Set-StrictSecureStateAcl", self.text)
        self.assertIn("Test-StrictSecureStateAcl", self.text)
        self.assertIn("$entries.Count -ne 2", self.text)
        self.assertNotIn("OwnerSecurityInformation", self.text)

    def test_watchdog_property_operator_never_splits_before_value(self) -> None:
        split_operator = re.compile(
            r"Where-Object\s+[A-Za-z_][A-Za-z0-9_.]*\s+"
            r"-(?:[ci]?(?:eq|ne|like|notlike|match|notmatch|gt|ge|lt|le)|"
            r"contains|notcontains|in|notin)\s*\r?\n",
            re.IGNORECASE,
        )
        self.assertIsNone(split_operator.search(self.text))
        self.assertIn(
            "$_.Name -eq 'vpn_settings.txt.wvdp'",
            self.text,
        )
        self.assertIn(
            "$_.Name -eq 'vpn_config.txt.wvdp'",
            self.text,
        )

    def test_post_startup_restore_requires_two_stable_reads(self) -> None:
        self.assertIn("Restore-StateFromBackup -KeepGui", self.text)
        self.assertIn("Start-Sleep -Seconds 8", self.text)
        self.assertIn("Start-Sleep -Seconds 2", self.text)
        self.assertIn("$firstStableRead", self.text)
        self.assertIn("$secondStableRead", self.text)
        self.assertIn("stable_state_handoff_verified", self.text)
        self.assertIn("final_strict_secure_acl_contract", self.text)

    def test_receipt_is_nonpublishable_and_fail_closed(self) -> None:
        self.assertIn("winsvpn-windows-prefreeze-watchdog-v1", self.text)
        self.assertIn("evidence_class = 'prefreeze_nonpublishable'", self.text)
        self.assertIn("publication_authorized = $false", self.text)
        self.assertIn("if (-not $pass) { exit 1 }", self.text)


if __name__ == "__main__":
    unittest.main()
