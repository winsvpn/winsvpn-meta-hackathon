#!/usr/bin/env python3
"""Static contract for the Windows browser-bridge owner receipt (R20 A1).

The app's browser IPC server and the native host refuse to run without
%ProgramData%\\wins_vpn\\browser_bridge.identity, an owner-installed secret an
ordinary user cannot write (lib/browser_bridge_app_ipc.dart,
_assertWindowsOwnerInstalledReceipt). Before this change no Windows installer
issued it, so the bridge could not start on Windows at all. The Inno Setup
post-install step below issues it.

PowerShell is not run here (no Windows host in this lane); these checks pin
the script's shape so an edit cannot quietly weaken it. Runtime behaviour on
Windows is NOT VERIFIED by this file.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ISS = (ROOT / "installer/windows/winsvpn.iss").read_text(encoding="utf-8")
IPC = (ROOT / "lib/browser_bridge_app_ipc.dart").read_text(encoding="utf-8")


def _script_lines() -> list[str]:
    start = ISS.index("function WriteBrowserBridgeIdentityScript(")
    end = ISS.index("end;", start)
    body = ISS[start:end]
    lines = []
    for match in re.finditer(r"^    '(.*)' \+ #13#10", body, re.MULTILINE):
        lines.append(match.group(1).replace("''", "'"))
    return lines


class WindowsBrowserBridgeIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lines = _script_lines()
        self.script = "\n".join(self.lines)

    def test_script_is_present_and_whole(self) -> None:
        self.assertGreater(len(self.lines), 40)
        self.assertEqual(self.lines[0], "$ErrorActionPreference='Stop'")
        self.assertEqual(self.lines[-1], "} catch { exit 30 }")

    def test_exact_receipt_path_matches_the_app(self) -> None:
        self.assertIn("GetFolderPath('CommonApplicationData')", self.script)
        self.assertIn("Join-Path $root 'wins_vpn'", self.script)
        self.assertIn("Join-Path $dir 'browser_bridge.identity'", self.script)
        self.assertIn(
            "const String kBrowserBridgeAppIpcTrustFileName = 'browser_bridge.identity';",
            IPC,
        )
        self.assertIn("'$root\\\\wins_vpn\\\\$kBrowserBridgeAppIpcTrustFileName'", IPC)

    def test_protected_dacl_admin_owned_users_read_only(self) -> None:
        for needle in (
            "SetAccessRuleProtection($true, $false)",
            "SetOwner($admins)",
            "SecurityIdentifier('S-1-5-18')",
            "SecurityIdentifier('S-1-5-32-544')",
            "SecurityIdentifier('S-1-5-32-545')",
            "($users, 'ReadAndExecute', $inherit, $none, $allow)",
            "($users, 'Read', $allow)",
        ):
            self.assertIn(needle, self.script)
        # Ordinary users never get a write-capable right.
        for line in self.lines:
            if "$users" in line and "AddAccessRule" in line:
                self.assertNotRegex(line, r"Modify|Write|FullControl|Delete|ChangePermissions|TakeOwnership")
        self.assertEqual(self.script.count("Set-Acl"), 2)

    def test_reparse_points_refused_and_valid_receipt_kept(self) -> None:
        self.assertEqual(self.script.count("ReparsePoint) -ne 0"), 2)
        self.assertIn(
            "if ($raw -cmatch '^\\{\"v\":1,\"secret\":\"[0-9a-f]{64}\"\\}$') { $valid = $true }",
            self.script,
        )
        self.assertIn("if (-not $valid) {", self.script)

    def test_secret_from_csprng_written_in_app_format_never_printed(self) -> None:
        self.assertIn("[Security.Cryptography.RandomNumberGenerator]::Create()", self.script)
        self.assertIn("New-Object byte[] 32", self.script)
        self.assertNotIn("Get-Random", self.script)
        self.assertNotRegex(self.script, r"Write-(Output|Host|Verbose|Information)")
        self.assertIn("'{\"v\":1,\"secret\":\"' + $hex + '\"}'", self.script)
        self.assertIn("New-Object Text.UTF8Encoding($false)", self.script)
        # The exact keys the app accepts: v and secret, nothing else.
        self.assertRegex(IPC, r"const Set<String> _kTrustFileKeys = <String>\{\s*'v',\s*'secret',\s*\};")

    def test_post_install_runs_it_non_fatally_before_success(self) -> None:
        start = ISS.index("procedure CurStepChanged(CurStep: TSetupStep);")
        end = ISS.index("function GetCustomSetupExitCode: Integer;", start)
        body = ISS[start:end]
        call = body.index("InstallBrowserBridgeIdentity;")
        self.assertLess(body.index("PreviousTunnelManagerNeedsRestore := False;"), call)
        self.assertLess(call, body.index("FatalPostInstallFailure := False;"))
        proc_start = ISS.index("procedure InstallBrowserBridgeIdentity;")
        proc = ISS[proc_start:ISS.index("\nend;", proc_start)]
        self.assertNotIn("RaiseFatalPostInstallException", proc)
        self.assertIn("-NoProfile -NonInteractive -ExecutionPolicy Bypass -File", proc)
        self.assertIn("DeleteFile(ScriptPath);", proc)
        self.assertNotIn("secret", proc.lower().replace("browser bridge owner receipt", ""))

    def test_elevated_scripts_are_staged_under_app_never_tmp(self) -> None:
        # PAIR-01: {tmp} is the installing user's %TEMP%; a non-elevated
        # process of that user could rewrite the script before the elevated
        # Exec. Both elevated scripts are written under {app} (Program Files).
        helper_start = ISS.index("function ElevatedScriptPath(const Name: String): String;")
        helper = ISS[helper_start:ISS.index("\nend;", helper_start)]
        self.assertIn("AppDir := ExpandConstant('{app}');", helper)
        self.assertIn("ForceDirectories(AppDir)", helper)
        self.assertNotIn("{tmp}", helper)
        for name in ("winsvpn-browser-bridge-identity.ps1", "winsvpn-prereq-verify.ps1"):
            self.assertIn(f"ElevatedScriptPath('{name}')", ISS)
            self.assertNotIn("{tmp}\\" + name, ISS)
            self.assertNotIn(name, ISS.replace(f"ElevatedScriptPath('{name}')", ""))
        # Defined before either caller, and every .ps1 the installer executes
        # through -File comes from ElevatedScriptPath.
        self.assertLess(helper_start, ISS.index("ElevatedScriptPath('winsvpn-browser-bridge-identity.ps1')"))
        self.assertLess(helper_start, ISS.index("ElevatedScriptPath('winsvpn-prereq-verify.ps1')"))
        self.assertEqual(ISS.count("-ExecutionPolicy Bypass -File"), 2)
        self.assertEqual(ISS.count("ScriptPath := ElevatedScriptPath("), 2)
        # The verifier script is removed again after it ran.
        verifier_start = ISS.index("function VerifyEmbeddedPrerequisiteIdentity(")
        verifier = ISS[verifier_start:ISS.index("\nend;", verifier_start)]
        self.assertEqual(verifier.count("DeleteFile(ScriptPath);"), 3)


if __name__ == "__main__":
    unittest.main()
