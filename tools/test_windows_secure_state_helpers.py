#!/usr/bin/env python3
"""Static contracts for fail-closed Windows DPAPI secure-state consumers."""

from __future__ import annotations

import pathlib
import os
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
HELPER_PATH = ROOT / "tools" / "windows_secure_state_helpers.ps1"
HELPER = HELPER_PATH.read_text(encoding="utf-8")
CONSUMERS = (
    ROOT / "tools" / "windows_xray_awg_handshake_matrix.ps1",
    ROOT / "tools" / "windows_xray_udp_carrier_probe.ps1",
    ROOT / "tools" / "windows_transport_live_probe.ps1",
)


class WindowsSecureStateHelperTests(unittest.TestCase):
    def test_helper_exposes_bounded_text_and_json_read_write_api(self) -> None:
        for function in (
            "Read-WinsVpnSecureText",
            "Read-WinsVpnSecureJson",
            "Write-WinsVpnSecureText",
            "Write-WinsVpnSecureJson",
        ):
            self.assertRegex(HELPER, rf"function\s+{re.escape(function)}\s*\{{")
        for name in (
            "client_keypair.json",
            "install_id.txt",
            "pending_logout.json",
            "user_pin.txt",
            "vpn_config.txt",
            "vpn_settings.txt",
            "wins_vpn_restart_config.conf",
        ):
            self.assertIn(f"'{name}'", HELPER)

    def test_helper_matches_native_wvdp_and_current_user_dpapi_contract(self) -> None:
        for marker in (
            "[byte[]](0x57, 0x56, 0x44, 0x50, 1, 0, 0, 0)",
            "'WinsVPN:WindowsSecureText:v1:' + $Name",
            "[Security.Cryptography.ProtectedData]::Unprotect(",
            "[Security.Cryptography.ProtectedData]::Protect(",
            "[Security.Cryptography.DataProtectionScope]::CurrentUser",
            "$length -gt 5MB",
            "$plaintext.Length -gt 4MB",
        ):
            self.assertIn(marker, HELPER)

    def test_helper_rejects_legacy_reparse_and_weak_acl_state(self) -> None:
        for marker in (
            "Join-Path $PSHOME",
            "Microsoft.PowerShell.Security.psd1",
            "Import-Module -Name $script:WinsVpnSecurityModuleManifest",
            "legacy plaintext $Name state is forbidden",
            "[IO.FileAttributes]::ReparsePoint",
            "$acl.AreAccessRulesProtected",
            "$entries.Count -ne 2",
            "@('S-1-5-18', $currentSid)",
            "[Security.AccessControl.FileSystemRights]::FullControl",
            "$_.IsInherited",
        ):
            self.assertIn(marker, HELPER)
        self.assertGreaterEqual(
            HELPER.count("Assert-WinsVpnNoLegacySecureText -Paths $paths"), 4
        )

    def test_write_is_same_directory_atomic_and_zeroes_byte_buffers(self) -> None:
        for marker in (
            "$temporary = Join-Path $paths.Root",
            "$replacementBackup = Join-Path $paths.Root",
            "[IO.FileMode]::CreateNew",
            "$stream.Flush($true)",
            "$temporary, $paths.Secure, $replacementBackup, $true",
            "[IO.File]::Move($temporary, $paths.Secure)",
            "Assert-WinsVpnSecureStateAcl $temporary",
        ):
            self.assertIn(marker, HELPER)
        self.assertNotIn(
            "[IO.File]::Replace($temporary, $paths.Secure, $null, $true)", HELPER
        )
        for name in ("plaintext", "entropy", "ciphertext", "framed", "encoded"):
            self.assertIn(f"[Array]::Clear(${name}, 0, ${name}.Length)", HELPER)
        self.assertNotIn("WriteAllText", HELPER)

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI runtime required")
    def test_existing_secure_file_replacement_works_in_windows_powershell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            local = root / "Local"
            roaming = root / "Roaming"
            (roaming / "wins_vpn").mkdir(parents=True)
            script = rf"""
$ErrorActionPreference = 'Stop'
$env:LOCALAPPDATA = '{str(local).replace("'", "''")}'
$env:APPDATA = '{str(roaming).replace("'", "''")}'
. '{str(HELPER_PATH).replace("'", "''")}'
Write-WinsVpnSecureJson -Name 'vpn_settings.txt' -Value ([ordered]@{{sequence=1}})
Write-WinsVpnSecureJson -Name 'vpn_settings.txt' -Value ([ordered]@{{sequence=2}})
$value = Read-WinsVpnSecureJson -Name 'vpn_settings.txt'
$paths = Get-WinsVpnSecureStatePaths -Name 'vpn_settings.txt'
if ([int]$value.sequence -ne 2) {{ throw 'replacement round-trip failed' }}
if (Get-ChildItem -LiteralPath $paths.Root -Filter '*.backup-*' -Force) {{
  throw 'replacement backup residue remains'
}}
'WINDOWS_SECURE_STATE_REPLACEMENT_RUNTIME=PASS'
"""
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=completed.stdout + completed.stderr,
            )
            self.assertIn(
                "WINDOWS_SECURE_STATE_REPLACEMENT_RUNTIME=PASS",
                completed.stdout,
            )

    def test_live_probes_only_read_secure_json_through_shared_helper(self) -> None:
        for path in CONSUMERS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertIn("windows_secure_state_helpers.ps1", source)
                self.assertIn(". $secureStateHelpers", source)
                self.assertIn("[IO.FileAttributes]::ReparsePoint", source)
                self.assertNotIn("function Read-WinsVpnSecureJson", source)
                self.assertNotIn("function Assert-WinsVpnSecureStateAcl", source)
                self.assertIn(
                    "Read-WinsVpnSecureJson -Name 'vpn_config.txt'", source
                )
                self.assertIn(
                    "Read-WinsVpnSecureJson -Name 'client_keypair.json'", source
                )
                self.assertNotRegex(
                    source,
                    r"Get-Content\s+-LiteralPath\s+\(Join-Path\s+\$appData\s+"
                    r"'(?:vpn_config\.txt|client_keypair\.json)'\)",
                )
                self.assertNotIn("Write-WinsVpnSecureText", source)
                self.assertNotIn("Write-WinsVpnSecureJson", source)


if __name__ == "__main__":
    unittest.main()
