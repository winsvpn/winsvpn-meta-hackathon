#!/usr/bin/env python3
"""Hostile fail-closed tests for Windows fixed-UI and release watchdog bounds."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
UI = ROOT / "windows_release_fixed_ui.ps1"
WATCHDOG = ROOT / "windows_release_safe_watchdog.ps1"
WORKER = ROOT / "windows_release_interactive_worker.ps1"
PE_MACHINE_X64 = 0x8664
PE_MACHINE_ARM64 = 0xAA64


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


def minimal_pe32_plus(
    machine: int = PE_MACHINE_X64,
    payload: bytes = b"winsvpn",
    minimum: int = 2048,
    *,
    magic: int = 0x20B,
    cert: bool = True,
) -> bytes:
    dos = bytearray(128)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (128).to_bytes(4, "little")
    coff = machine.to_bytes(2, "little") + (0).to_bytes(2, "little")
    coff += (0).to_bytes(4, "little") * 3
    coff += (240).to_bytes(2, "little") + (0x0022).to_bytes(2, "little")
    optional = bytearray(240)
    optional[0:2] = magic.to_bytes(2, "little")
    optional[36:40] = (512).to_bytes(4, "little")
    optional[108:112] = (16).to_bytes(4, "little")
    cert_bytes = b""
    if cert:
        cert_bytes = bytearray(8 + len(payload))
        cert_bytes[0:4] = (8 + len(payload)).to_bytes(4, "little")
        cert_bytes[4:6] = (0x0200).to_bytes(2, "little")
        cert_bytes[6:8] = (0x0002).to_bytes(2, "little")
        cert_bytes[8:] = payload
        while len(cert_bytes) % 8:
            cert_bytes.append(0)
        cert_bytes[0:4] = len(cert_bytes).to_bytes(4, "little")
        optional[144:148] = (512).to_bytes(4, "little")
        optional[148:152] = len(cert_bytes).to_bytes(4, "little")
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional)
    blob = headers.ljust(512, b"\x00") + bytes(cert_bytes)
    if len(blob) < minimum:
        blob += b"\x00" * (minimum - len(blob))
    return blob


class WindowsReleaseUiWatchdogSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ui = UI.read_text(encoding="utf-8")
        cls.watchdog = WATCHDOG.read_text(encoding="utf-8")
        cls.worker = WORKER.read_text(encoding="utf-8")
        cls.shell = powershell_executable()

    def function_text(self, text: str, name: str) -> str:
        start = text.index(f"function {name}")
        opening = text.index("{", start)
        depth = 0
        for offset, character in enumerate(text[opening:], opening):
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return text[start : offset + 1]
        self.fail(f"unterminated function {name}")

    def run_ps(self, command: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        if self.shell is None:
            self.skipTest("PowerShell is unavailable")
        return subprocess.run(
            [self.shell, "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )

    def exclusive_stub(self) -> str:
        return r"""
function Open-ExclusiveFile {
    param($Path, [IO.FileMode]$Mode, [IO.FileAccess]$Access, [IO.FileShare]$Share = [IO.FileShare]::None)
    [IO.File]::Open($Path, $Mode, $Access, $Share)
}
"""

    def test_parameter_surface_rejects_unsafe_arguments(self) -> None:
        ui_params = self.ui[: self.ui.index("Set-StrictMode")]
        watchdog_params = self.watchdog[: self.watchdog.index("Set-StrictMode")]
        for text in (ui_params, watchdog_params):
            for forbidden in (
                "WatchdogScript",
                "InvokeTool",
                "OutputRoot",
                "HelperRoot",
                "Script",
                "Executable",
                "FirewallGroup",
                "InstalledGui",
            ):
                self.assertNotIn(forbidden, text)
        self.assertIn("$RunId", ui_params)
        self.assertIn("$Action", ui_params)
        self.assertIn("CollectorClosureSha256", watchdog_params)
        self.assertIn("rejected unsafe or extra arguments", self.ui)
        self.assertIn("rejected unsafe or extra arguments", self.watchdog)

    def test_native_root_reparse_hardlink_and_wow64_are_fail_closed(self) -> None:
        for text in (self.ui, self.watchdog):
            for required in (
                "0x00200000",
                "nNumberOfLinks",
                "hardlink substitution",
                "PROCESSOR_ARCHITEW6432",
                "ProcessArchitecture",
                "OSArchitecture",
                "must not run under WOW64",
                "escaped the fixed ReleaseEvidence root",
                "Parent traversal is forbidden.",
                "FileShare]::None",
                "source_only",
            ):
                self.assertIn(required, text)
        self.assertIn("WinsVPN\\ReleaseEvidence", self.ui)
        self.assertIn("WinsVPN\\ReleaseEvidence", self.watchdog)
        self.assertIn("must execute only from the locked helper root", self.ui)
        self.assertIn("must execute only from the locked helper root", self.watchdog)

    def test_ui_and_watchdog_bind_native_x64_or_arm64_candidate(self) -> None:
        for text in (self.ui, self.watchdog):
            for required in (
                "function Get-PeArchitecture",
                "function Get-NativeWindowsArchitecture",
                "function Assert-ArchitectureBinding",
                "$PeMachineX64",
                "$PeMachineArm64",
                "File is not PE32+ x64 or arm64",
                "PE image lacks an Authenticode certificate table",
                "mixed, WOW64, or unsupported",
                "omitted architecture binding",
                "process_wow64",
                "installed_gui_path",
                "winsvpn_awg_engine.exe",
                "winsvpn_winn3_engine.exe",
                "xray.exe",
            ):
                self.assertIn(required, text)
        self.assertIn("Get-AuthenticodeSignature", self.ui)
        self.assertIn("candidate PID/session/window/path/hash binding failed", self.ui)
        self.assertIn("accDoDefaultAction", self.ui)

    def test_winn_v3_primary_then_awg_then_xray_are_phase_bound(self) -> None:
        self.assertLess(
            self.ui.index("primary_transport = 'winn_v3'"),
            self.ui.index("fallback_transports = @('winn_v1_awg', 'winn_v1_xray')"),
        )
        self.assertLess(
            self.ui.index("'winn_v1_awg'"),
            self.ui.index("'winn_v1_xray'"),
        )
        self.assertIn("function Resolve-ObservedTransport", self.ui)
        self.assertIn("function Assert-PhaseBoundUiAction", self.ui)
        self.assertIn("observed mixed Winn v3/v1 transports", self.ui)
        self.assertIn("not phase-bound to the observed Winn transport", self.ui)
        self.assertIn("observed_transport = $observedTransport", self.ui)
        self.assertIn("InspectDisconnect = @('winn_v3', 'winn_v1_awg', 'winn_v1_xray')", self.ui)
        self.assertIn("Connect = @('disconnected')", self.ui)
        self.assertIn("winsvpn_winn3_engine", self.watchdog)

    def test_watchdog_rejects_escape_partial_cleanup_and_source_only_pass(self) -> None:
        for required in (
            "Release watchdog escaped the fixed ReleaseEvidence root.",
            "Release watchdog refused a source-only PASS.",
            "$cleanupErrors.Count -eq 0",
            "$pass = $normal -and -not $emergency",
            "Emergency cleanup rejected a stale runtime process pin.",
            "function Invoke-CleanupStep",
            "Failed to unregister release watchdog task",
            "JSON output size is unbounded",
            "passed = $pass",
            "source_only = $false",
            "must execute as LocalSystem",
            "refused to arm away from its exact healthy baseline",
        ):
            self.assertIn(required, self.watchdog)
        self.assertNotIn(
            "path.StartsWith",
            self.watchdog,
        )
        self.assertIn("$runtime = $latestRuntime", self.watchdog)
        self.assertIn("Test-ExactImage", self.watchdog)
        unregister = self.watchdog[
            self.watchdog.index("$taskRemoved = $false") :
        ]
        self.assertIn("Unregister-ScheduledTask -TaskName $TaskName", unregister)

    def test_ui_rejects_source_only_and_unbounded_output(self) -> None:
        self.assertIn("Fixed UI refused a source-only substitution.", self.ui)
        self.assertIn("Fixed UI JSON output size is unbounded.", self.ui)
        self.assertIn("source_only = $false", self.ui)
        self.assertIn("$MaxObservationBytes = 65536", self.ui)

    def test_worker_and_watchdog_state_documents_stay_identical(self) -> None:
        self.assertEqual(
            self.function_text(self.worker, "Get-StateDocument"),
            self.function_text(self.watchdog, "Get-StateDocument"),
        )

    def test_powershell_sources_parse(self) -> None:
        files = [UI, WATCHDOG]
        command = (
            "$bad=$false;"
            + ";".join(
                "$e=$null;[void][System.Management.Automation.Language.Parser]::"
                f"ParseFile((Resolve-Path '{path.as_posix()}'),[ref]$null,[ref]$e);"
                "if($e){$bad=$true;$e|% ToString}"
                for path in files
            )
            + ";if($bad){exit 1}; Write-Output 'PARSE_OK'"
        )
        result = self.run_ps(command)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("PARSE_OK", result.stdout)

    def test_native_architecture_rejects_wow64_for_ui_and_watchdog(self) -> None:
        for name, text, needle in (
            ("ui", self.ui, "Fixed UI must not run under WOW64"),
            ("watchdog", self.watchdog, "Release watchdog must not run under WOW64"),
        ):
            command = (
                "$ErrorActionPreference='Stop'\n"
                + self.function_text(text, "Get-NativeWindowsArchitecture")
                + r"""
$env:PROCESSOR_ARCHITEW6432 = 'AMD64'
try {
    [void](Get-NativeWindowsArchitecture)
    Write-Output 'WOW64_ACCEPTED'
    exit 1
} catch {
    if ("$_" -notmatch 'must not run under WOW64') {
        Write-Output $_
        exit 2
    }
}
Remove-Item Env:PROCESSOR_ARCHITEW6432
$arch = Get-NativeWindowsArchitecture
if ($arch -cne 'x64' -and $arch -cne 'arm64') { Write-Output $arch; exit 3 }
Write-Output "NATIVE=$arch"
"""
            )
            result = self.run_ps(command)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertRegex(result.stdout, r"NATIVE=(x64|arm64)")
            self.assertNotIn("WOW64_ACCEPTED", result.stdout, name)
            self.assertIn(needle.split("must not")[0].strip(), text)

    def test_pe_parser_accepts_x64_or_arm64_and_rejects_hostile_images(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "x64.exe").write_bytes(minimal_pe32_plus(PE_MACHINE_X64, b"x64"))
            (root / "arm64.exe").write_bytes(
                minimal_pe32_plus(PE_MACHINE_ARM64, b"arm64")
            )
            (root / "x86.exe").write_bytes(
                minimal_pe32_plus(0x014C, b"x86", magic=0x10B)
            )
            (root / "stub.exe").write_bytes(b"MZ" + b"installer" * 64)
            (root / "nocert.exe").write_bytes(
                minimal_pe32_plus(PE_MACHINE_X64, b"nocert", cert=False)
            )
            posix = str(root).replace("'", "''")
            command = (
                "$ErrorActionPreference='Stop'\n"
                + self.exclusive_stub()
                + "$PeMachineX64=0x8664;$PeMachineArm64=0xAA64\n"
                + self.function_text(self.ui, "Get-PeArchitecture")
                + f"\n$root='{posix}'\n"
                + r"""
$x64 = Get-PeArchitecture (Join-Path $root 'x64.exe')
$arm = Get-PeArchitecture (Join-Path $root 'arm64.exe')
if ($x64.Name -cne 'x64' -or [int]$x64.Machine -ne 0x8664) { exit 1 }
if ($arm.Name -cne 'arm64' -or [int]$arm.Machine -ne 0xAA64) { exit 2 }
foreach ($name in @('x86.exe','stub.exe','nocert.exe')) {
    try {
        [void](Get-PeArchitecture (Join-Path $root $name))
        Write-Output "ACCEPTED=$name"
        exit 3
    } catch {
        if ("$_" -notmatch 'PE32\+ x64 or arm64|not a PE image|Authenticode certificate table|truncated') {
            Write-Output $_
            exit 4
        }
    }
}
Write-Output 'PE_PARSER_OK'
"""
            )
            result = self.run_ps(command)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("PE_PARSER_OK", result.stdout)
            self.assertNotIn("ACCEPTED=", result.stdout)

    def test_architecture_binding_rejects_omitted_mixed_wow64_and_host_mismatch(
        self,
    ) -> None:
        command = (
            "$ErrorActionPreference='Stop'\n"
            + self.function_text(self.ui, "Get-BindingProperty")
            + "\n"
            + self.function_text(self.ui, "Assert-ArchitectureBinding")
            + r"""
function Get-NativeWindowsArchitecture { 'x64' }
$PeMachineX64=0x8664;$PeMachineArm64=0xAA64
$good = [ordered]@{
    architecture='x64'; pe_machine=0x8664; native_architecture='x64'
    os_architecture='X64'; process_wow64=$false
}
Assert-ArchitectureBinding $good
try {
    Assert-ArchitectureBinding $null
    Write-Output 'NULL_ACCEPTED'; exit 1
} catch {
    if ("$_" -notmatch 'omitted architecture binding') { Write-Output $_; exit 2 }
}
$omitted = [ordered]@{ architecture='x64'; pe_machine=0x8664 }
try {
    Assert-ArchitectureBinding $omitted
    Write-Output 'OMITTED_ACCEPTED'; exit 3
} catch {
    if ("$_" -notmatch 'omitted architecture binding') { Write-Output $_; exit 4 }
}
$mixed = [ordered]@{
    architecture='x64'; pe_machine=0xAA64; native_architecture='x64'
    os_architecture='X64'; process_wow64=$false
}
try {
    Assert-ArchitectureBinding $mixed
    Write-Output 'MIXED_ACCEPTED'; exit 5
} catch {
    if ("$_" -notmatch 'mixed, WOW64, or unsupported') { Write-Output $_; exit 6 }
}
$wow = [ordered]@{
    architecture='x64'; pe_machine=0x8664; native_architecture='x64'
    os_architecture='X64'; process_wow64=$true
}
try {
    Assert-ArchitectureBinding $wow
    Write-Output 'WOW_ACCEPTED'; exit 7
} catch {
    if ("$_" -notmatch 'mixed, WOW64, or unsupported') { Write-Output $_; exit 8 }
}
$hostMixed = [ordered]@{
    architecture='arm64'; pe_machine=0xAA64; native_architecture='arm64'
    os_architecture='Arm64'; process_wow64=$false
}
try {
    Assert-ArchitectureBinding $hostMixed
    Write-Output 'HOST_MIXED_ACCEPTED'; exit 9
} catch {
    if ("$_" -notmatch 'does not match bound PE architecture') { Write-Output $_; exit 10 }
}
Write-Output 'BINDING_OK'
"""
        )
        result = self.run_ps(command)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("BINDING_OK", result.stdout)
        for marker in (
            "NULL_ACCEPTED",
            "OMITTED_ACCEPTED",
            "MIXED_ACCEPTED",
            "WOW_ACCEPTED",
            "HOST_MIXED_ACCEPTED",
        ):
            self.assertNotIn(marker, result.stdout)

    def test_observed_transport_rejects_mixed_unbound_and_wrong_fallback_order(
        self,
    ) -> None:
        command = (
            "$ErrorActionPreference='Stop'\n"
            + self.function_text(self.ui, "Resolve-ObservedTransport")
            + "\n"
            + self.function_text(self.ui, "Assert-PhaseBoundUiAction")
            + r"""
function Assert-Throws {
    param([scriptblock]$Body, [string]$Needle)
    $failed = $false
    try { & $Body } catch {
        $failed = $true
        if ("$_" -notlike "*$Needle*") {
            throw "expected '$Needle' in '$_'"
        }
    }
    if (-not $failed) { throw "expected failure matching $Needle" }
}
if ((Resolve-ObservedTransport 1 0 0 0) -cne 'winn_v3') { exit 1 }
if ((Resolve-ObservedTransport 0 1 0 0) -cne 'winn_v1_awg') { exit 2 }
if ((Resolve-ObservedTransport 0 1 1 0) -cne 'winn_v1_xray') { exit 3 }
if ((Resolve-ObservedTransport 0 0 0 0) -cne 'disconnected') { exit 4 }
Assert-Throws { Resolve-ObservedTransport 0 0 1 0 } 'mixed Winn v3/v1'
Assert-Throws { Resolve-ObservedTransport 1 1 0 0 } 'mixed Winn v3/v1'
Assert-Throws { Resolve-ObservedTransport 1 0 1 0 } 'mixed Winn v3/v1'
Assert-Throws { Resolve-ObservedTransport 0 0 0 1 } 'unbound engine process'
Assert-Throws { Resolve-ObservedTransport 2 0 0 0 } 'mixed Winn v3/v1'
Assert-PhaseBoundUiAction 'Connect' 'disconnected'
Assert-PhaseBoundUiAction 'InspectDisconnect' 'winn_v3'
Assert-PhaseBoundUiAction 'InspectDisconnect' 'winn_v1_awg'
Assert-PhaseBoundUiAction 'InspectDisconnect' 'winn_v1_xray'
Assert-PhaseBoundUiAction 'Disconnect' 'winn_v1_xray'
Assert-Throws { Assert-PhaseBoundUiAction 'Connect' 'winn_v1_awg' } 'not phase-bound'
Assert-Throws { Assert-PhaseBoundUiAction 'Disconnect' 'disconnected' } 'not phase-bound'
Assert-Throws { Assert-PhaseBoundUiAction 'InspectDisconnect' 'disconnected' } 'not phase-bound'
Assert-Throws { Assert-PhaseBoundUiAction 'OpenSplit' 'winn_v1_xray' } 'not phase-bound'
Assert-Throws { Assert-PhaseBoundUiAction 'InspectMapRadius' 'disconnected' } 'not phase-bound'
Write-Output 'PHASE_OK'
"""
        )
        result = self.run_ps(command)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("PHASE_OK", result.stdout)

    def test_watchdog_write_rejects_unbounded_output(self) -> None:
        command = (
            "$ErrorActionPreference='Stop'\n"
            "$MaxJsonBytes = 64\n"
            + self.exclusive_stub()
            + self.function_text(self.watchdog, "Write-NewJson")
            + r"""
$out = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N') + '.json')
try {
    Write-NewJson $out ([ordered]@{
        pad = ('x' * 200)
    })
    Write-Output 'UNBOUNDED_ACCEPTED'
    exit 1
} catch {
    if ("$_" -notmatch 'JSON output size is unbounded') {
        Write-Output $_
        exit 2
    }
}
Write-Output 'BOUNDED_OK'
"""
        )
        result = self.run_ps(command)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("BOUNDED_OK", result.stdout)
        self.assertNotIn("UNBOUNDED_ACCEPTED", result.stdout)

    def test_watchdog_pass_expression_cannot_green_emergency_or_source_only(
        self,
    ) -> None:
        pass_start = self.watchdog.index("$pass = $normal -and -not $emergency")
        pass_block = self.watchdog[
            pass_start : self.watchdog.index("$receipt =", pass_start)
        ]
        for required in (
            "$cleanupErrors.Count -eq 0",
            "$sourceOnlyClosed",
            "$finalSha -ceq $baseline.state_sha256",
        ):
            self.assertIn(required, pass_block)
        self.assertIn("source_only = $false", self.watchdog)
        self.assertIn("passed = $pass", self.watchdog)
        emergency = self.watchdog.index("$emergency = $true")
        self.assertLess(emergency, pass_start)


if __name__ == "__main__":
    unittest.main()
