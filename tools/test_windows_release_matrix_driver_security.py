#!/usr/bin/env python3
"""Hostile fail-closed tests for Windows release-matrix driver architecture."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
DRIVER = TOOLS / "windows_release_matrix_driver.ps1"
PE_MACHINE_X64 = 0x8664
PE_MACHINE_ARM64 = 0xAA64
FOUR_TARGETS = (
    "windows-x64-installer",
    "windows-x64-partner-center",
    "windows-arm64-installer",
    "windows-arm64-partner-center",
)


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


def minimal_pe32_plus(machine: int, payload: bytes = b"winsvpn") -> bytes:
    dos = bytearray(128)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (128).to_bytes(4, "little")
    coff = machine.to_bytes(2, "little") + (0).to_bytes(2, "little")
    coff += (0).to_bytes(4, "little") * 3
    coff += (240).to_bytes(2, "little") + (0x0022).to_bytes(2, "little")
    optional = bytearray(240)
    optional[0:2] = (0x20B).to_bytes(2, "little")
    optional[36:40] = (512).to_bytes(4, "little")
    optional[108:112] = (16).to_bytes(4, "little")
    cert = bytearray(8 + len(payload))
    cert[0:4] = (8 + len(payload)).to_bytes(4, "little")
    cert[4:6] = (0x0200).to_bytes(2, "little")
    cert[6:8] = (0x0002).to_bytes(2, "little")
    cert[8:] = payload
    while len(cert) % 8:
        cert.append(0)
    cert[0:4] = len(cert).to_bytes(4, "little")
    optional[144:148] = (512).to_bytes(4, "little")
    optional[148:152] = len(cert).to_bytes(4, "little")
    blob = bytes(dos) + b"PE\0\0" + coff + bytes(optional)
    blob = blob.ljust(512, b"\x00") + bytes(cert)
    if len(blob) < 2048:
        blob += b"\x00" * (2048 - len(blob))
    return blob


class WindowsReleaseMatrixDriverSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DRIVER.read_text(encoding="ascii")
        cls.shell = powershell_executable()

    def function_text(self, name: str) -> str:
        start = self.text.index(f"function {name}")
        opening = self.text.index("{", start)
        depth = 0
        for offset, character in enumerate(self.text[opening:], opening):
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return self.text[start : offset + 1]
        self.fail(f"unterminated function {name}")

    def helpers(self) -> str:
        start = self.text.index("function Get-CanonicalWindowsMatrixTargets")
        end = self.text.index("function Invoke-MatrixDriverSelfTest")
        return self.text[start:end]

    def prefix(self, root: pathlib.Path) -> str:
        worker = str(TOOLS / "windows_release_interactive_worker.ps1")
        collector = str(TOOLS / "windows_release_physical_collector.ps1")
        return (
            "Set-StrictMode -Version Latest\n"
            "$ErrorActionPreference='Stop'\n"
            f"$RepoRoot='{str(ROOT)}'\n"
            f"$PSScriptRoot='{str(TOOLS)}'\n"
            f"$WorkerScript='{worker}'\n"
            f"$CollectorScript='{collector}'\n"
            "$SystemPowerShell='powershell.exe'\n"
            "$PeMachineX64=0x8664;$PeMachineArm64=0xAA64\n"
            "$OpenReparsePoint=[IO.FileOptions]0x00200000\n"
            "$ReparseAttribute=[uint32]0x400\n"
            "$MaxChildOutputBytes=16777216\n"
            "$script:MatrixState=$null\n"
            "$script:WinsVpnByHandleReady=$false\n"
            f"$root='{str(root)}'\n"
        )

    def run_ps(self, command: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
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

    def write_pe(self, path: pathlib.Path, machine: int) -> None:
        path.write_bytes(minimal_pe32_plus(machine))

    def test_driver_is_ascii_and_parses(self) -> None:
        DRIVER.read_text(encoding="ascii")
        self.assertNotIn("\ufeff", self.text)
        if self.shell is None:
            self.skipTest("PowerShell is unavailable")
        path = str(DRIVER).replace("'", "''")
        result = self.run_ps(
            "$t=$null;$e=$null;"
            f"$null=[Management.Automation.Language.Parser]::ParseFile('{path}',"
            "[ref]$t,[ref]$e); if($e.Count){$e|%{$_.ToString()}; exit 1}"
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_source_binds_four_native_targets_and_winn_order(self) -> None:
        for target in FOUR_TARGETS:
            self.assertIn(target, self.text)
        self.assertIn("WinsVPN-Setup.exe", self.text)
        self.assertIn("WinsVPN-PartnerCenter.exe", self.text)
        self.assertIn("WinsVPN-Setup-arm64.exe", self.text)
        self.assertIn("WinsVPN-PartnerCenter-arm64.exe", self.text)
        self.assertIn("architecture_expectation", self.text)
        self.assertIn("New-WorkerInvocation", self.text)
        self.assertIn("New-CollectorInvocation", self.text)
        self.assertIn("-RunId", self.text)
        self.assertIn("-Phase", self.text)
        self.assertIn("-Artifact", self.text)
        self.assertIn("must not run under WOW64", self.text)
        self.assertIn("hardlink substitution", self.text)
        self.assertIn("reparse point", self.text)
        self.assertIn("unbounded", self.text)
        self.assertIn("partial false green", self.text)
        self.assertIn("Stale Windows matrix retry", self.text)
        self.assertIn("wrong four-target coverage", self.text)
        self.assertIn("winn_v3", self.text)
        self.assertIn("winn_v1_awg", self.text)
        self.assertIn("winn_v1_xray", self.text)
        self.assertLess(self.text.index("winn_v3"), self.text.index("winn_v1_awg"))
        self.assertLess(self.text.index("winn_v1_awg"), self.text.index("winn_v1_xray"))
        self.assertIn("tools/windows_secure_state_helpers.ps1", self.text)
        self.assertIn("WinsVPN\\ReleaseEvidence", self.text)
        self.assertNotIn("AllowUnsigned", self.text)
        self.assertNotIn("LabEvidence", self.text)
        deny = self.function_text("Assert-SafeChildArgumentList")
        self.assertIn("$text -ceq 'Invoke-Expression'", deny)
        self.assertIn("$text -ceq 'cmd.exe'", deny)
        self.assertEqual(self.text.count("Invoke-Expression"), 1)
        self.assertNotIn("IEX", self.text)
        self.assertNotIn("iex", self.text)
        self.assertNotIn("cmd.exe /c", self.text)
        self.assertNotIn("cmd.exe -c", self.text)
        worker_fn = self.function_text("New-WorkerInvocation")
        collector_fn = self.function_text("New-CollectorInvocation")
        self.assertNotIn("-Command", worker_fn)
        self.assertNotIn("-Command", collector_fn)
        self.assertIn("ArgumentList.Add", self.function_text("Invoke-BoundedNative"))

    def test_self_test_pass(self) -> None:
        if self.shell is None:
            self.skipTest("PowerShell is unavailable")
        result = subprocess.run(
            [
                self.shell,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(DRIVER),
                "-SelfTest",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("WINDOWS_RELEASE_MATRIX_DRIVER_SELF_TEST=PASS", result.stdout)

    def test_native_architecture_rejects_wow64(self) -> None:
        command = (
            self.prefix(pathlib.Path("/tmp"))
            + self.function_text("Get-NativeWindowsArchitecture")
            + r"""
$env:PROCESSOR_ARCHITEW6432 = 'AMD64'
try {
    [void](Get-NativeWindowsArchitecture)
    Write-Output 'WOW64_ACCEPTED'
    exit 1
} catch {
    if ("$_" -notmatch 'must not run under WOW64') { Write-Output $_; exit 2 }
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
        self.assertNotIn("WOW64_ACCEPTED", result.stdout)

    def test_pe_and_assignment_reject_mixed_wow64_and_wrong_surface(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            x64 = root / "WinsVPN-Setup.exe"
            arm = root / "WinsVPN-Setup-arm64.exe"
            self.write_pe(x64, PE_MACHINE_X64)
            self.write_pe(arm, PE_MACHINE_ARM64)
            command = (
                self.prefix(root)
                + self.helpers()
                + r"""
Reset-MatrixDriverState
$x64 = Join-Path $root 'WinsVPN-Setup.exe'
$arm = Join-Path $root 'WinsVPN-Setup-arm64.exe'
$pe = Get-PeArchitecture $x64
if ($pe.Name -cne 'x64' -or [int]$pe.Machine -ne 0x8664) { exit 1 }
$armPe = Get-PeArchitecture $arm
if ($armPe.Name -cne 'arm64') { exit 2 }
$good = New-SelfTestAssignment 'windows-x64-installer' 'windows-x64-host' $x64 '11111111-1111-1111-1111-111111111111'
Assert-ArchitectureAssignment $good
$good['process_wow64'] = $true
try {
    Assert-ArchitectureAssignment $good
    Write-Output 'WOW_ASSIGNMENT_ACCEPTED'; exit 3
} catch {
    if ("$_" -notmatch 'mixed, WOW64, or unsupported') { Write-Output $_; exit 4 }
}
$namedArm = Join-Path $root 'WinsVPN-Setup.exe'
[IO.File]::WriteAllBytes($namedArm, [IO.File]::ReadAllBytes($arm))
try {
    $mixed = New-SelfTestAssignment 'windows-x64-installer' 'windows-x64-host' $namedArm '22222222-2222-2222-2222-222222222222'
    Assert-ArchitectureAssignment $mixed
    Write-Output 'MIXED_PE_ACCEPTED'; exit 5
} catch {
    if ("$_" -notmatch 'mixed with the native host') { Write-Output $_; exit 6 }
}
Write-Output 'ASSIGNMENT_OK'
"""
            )
            result = self.run_ps(command)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("ASSIGNMENT_OK", result.stdout)
            self.assertNotIn("WOW_ASSIGNMENT_ACCEPTED", result.stdout)
            self.assertNotIn("MIXED_PE_ACCEPTED", result.stdout)

    def test_four_target_coverage_duplicates_and_host_mix(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            files = {
                "windows-x64-installer": ("WinsVPN-Setup.exe", PE_MACHINE_X64),
                "windows-x64-partner-center": (
                    "WinsVPN-PartnerCenter.exe",
                    PE_MACHINE_X64,
                ),
                "windows-arm64-installer": (
                    "WinsVPN-Setup-arm64.exe",
                    PE_MACHINE_ARM64,
                ),
                "windows-arm64-partner-center": (
                    "WinsVPN-PartnerCenter-arm64.exe",
                    PE_MACHINE_ARM64,
                ),
            }
            for name, machine in files.values():
                self.write_pe(root / name, machine)
            command = (
                self.prefix(root)
                + self.helpers()
                + r"""
Reset-MatrixDriverState
$rows = [Collections.Generic.List[object]]::new()
$nonces = @(
    '11111111-1111-1111-1111-111111111111',
    '22222222-2222-2222-2222-222222222222',
    '33333333-3333-3333-3333-333333333333',
    '44444444-4444-4444-4444-444444444444'
)
$names = @(
    @('windows-x64-installer','WinsVPN-Setup.exe','windows-x64-host'),
    @('windows-x64-partner-center','WinsVPN-PartnerCenter.exe','windows-x64-host'),
    @('windows-arm64-installer','WinsVPN-Setup-arm64.exe','windows-arm64-host'),
    @('windows-arm64-partner-center','WinsVPN-PartnerCenter-arm64.exe','windows-arm64-host')
)
for ($i=0; $i -lt 4; $i++) {
    $path = Join-Path $root $names[$i][1]
    [void]$rows.Add((New-SelfTestAssignment $names[$i][0] $names[$i][2] $path $nonces[$i]))
}
$frozen = [object[]]::new($rows.Count)
$rows.CopyTo($frozen)
Assert-FourTargetCoverage -AssignmentSet @{ rows = $frozen }
$dup = [Collections.Generic.List[object]]::new()
foreach ($row in $rows) { [void]$dup.Add($row) }
[void]$dup.Add($rows[0])
try {
    Assert-FourTargetCoverage -AssignmentSet @{ rows = $dup }
    Write-Output 'DUP_ACCEPTED'; exit 1
} catch {
    if ("$_" -notmatch 'Duplicate Windows matrix assignment') { Write-Output $_; exit 2 }
}
$missing = [Collections.Generic.List[object]]::new()
[void]$missing.Add($rows[0]); [void]$missing.Add($rows[1]); [void]$missing.Add($rows[2])
try {
    Assert-FourTargetCoverage -AssignmentSet @{ rows = $missing }
    Write-Output 'MISSING_ACCEPTED'; exit 3
} catch {
    if ("$_" -notmatch 'wrong four-target coverage') { Write-Output $_; exit 4 }
}
$rows[2]['host_id'] = 'windows-x64-host'
try {
    $mixedFrozen = [object[]]::new($rows.Count)
    $rows.CopyTo($mixedFrozen)
    Assert-FourTargetCoverage -AssignmentSet @{ rows = $mixedFrozen }
    Write-Output 'HOST_MIX_ACCEPTED'; exit 5
} catch {
    if ("$_" -notmatch 'mixed, WOW64, or unsupported') { Write-Output $_; exit 6 }
}
Write-Output 'COVERAGE_OK'
"""
            )
            result = self.run_ps(command)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("COVERAGE_OK", result.stdout)
            for marker in ("DUP_ACCEPTED", "MISSING_ACCEPTED", "HOST_MIX_ACCEPTED"):
                self.assertNotIn(marker, result.stdout)

    def test_worker_and_collector_invocations_are_argv_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            candidate = root / "WinsVPN-Setup.exe"
            self.write_pe(candidate, PE_MACHINE_X64)
            command = (
                self.prefix(root)
                + self.helpers()
                + r"""
Reset-MatrixDriverState
$path = Join-Path $root 'WinsVPN-Setup.exe'
$row = New-SelfTestAssignment 'windows-x64-installer' 'windows-x64-host' $path '11111111-1111-1111-1111-111111111111'
$worker = New-WorkerInvocation $row 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' 'Prepare'
if ($worker.argument_list -contains '-Command') { Write-Output 'WORKER_COMMAND'; exit 1 }
$runAt = [array]::IndexOf(@($worker.argument_list), '-RunId')
$phaseAt = [array]::IndexOf(@($worker.argument_list), '-Phase')
if ($worker.argument_list[$runAt+1] -cne 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') { exit 2 }
if ($worker.argument_list[$phaseAt+1] -cne 'Prepare') { exit 3 }
if ($worker.architecture_expectation.architecture -cne 'x64') { exit 4 }
if ($worker.architecture_expectation.surface -cne 'website') { exit 5 }
if ($worker.architecture_expectation.process_wow64 -ne $false) { exit 6 }
$inputs = [ordered]@{
    PayloadManifest = Join-Path $root 'payload.json'
    PayloadRoot = $root
    ReleaseInputIndex = Join-Path $root 'index.json'
    BuildReceipt = Join-Path $root 'receipt.json'
    CandidateManifest = Join-Path $root 'candidate.json'
    PreviousArtifact = Join-Path $root 'previous.exe'
    PreviousPayloadManifest = Join-Path $root 'previous.json'
    PreviousReleaseRecord = Join-Path $root 'previous-record.json'
    CredentialStore = Join-Path $root 'credentials.dat'
    Gazetteer = Join-Path $root 'gazetteer.json'
}
$collector = New-CollectorInvocation $row $inputs
if ($collector.argument_list -contains '-Command') { Write-Output 'COLLECTOR_COMMAND'; exit 7 }
$artAt = [array]::IndexOf(@($collector.argument_list), '-Artifact')
if ($collector.argument_list[$artAt+1] -cne $path) { exit 8 }
if ($collector.architecture_expectation.native_architecture -cne 'x64') { exit 9 }
if ($collector.architecture_expectation.host_id -cne 'windows-x64-host') { exit 10 }
try {
    New-WorkerInvocation $row 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' 'Prepare'
    Write-Output 'STALE_PHASE_ACCEPTED'; exit 11
} catch {
    if ("$_" -notmatch 'Stale Windows matrix retry') { Write-Output $_; exit 12 }
}
try {
    Assert-SafeChildArgumentList @('-NoProfile', '-Command', 'calc')
    Write-Output 'INJECTION_ACCEPTED'; exit 13
} catch {
    if ("$_" -notmatch 'string/shell injection') { Write-Output $_; exit 14 }
}
try {
    Assert-SafeChildArgumentList @('safe', 'bad;rm')
    Write-Output 'META_ACCEPTED'; exit 15
} catch {
    if ("$_" -notmatch 'shell metacharacters') { Write-Output $_; exit 16 }
}
Write-Output 'INVOCATION_OK'
"""
            )
            result = self.run_ps(command)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("INVOCATION_OK", result.stdout)
            for marker in (
                "WORKER_COMMAND",
                "COLLECTOR_COMMAND",
                "STALE_PHASE_ACCEPTED",
                "INJECTION_ACCEPTED",
                "META_ACCEPTED",
            ):
                self.assertNotIn(marker, result.stdout)

    def test_winn_order_and_partial_false_green(self) -> None:
        command = (
            self.prefix(pathlib.Path("/tmp"))
            + self.helpers()
            + r"""
function New-WinnReceipt {
    param($Contract, $Sequence, $Extra)
    $receipt = [ordered]@{
        contract = $Contract
        passed = $true
        architecture = 'x64'
        pe_machine = 0x8664
        native_architecture = 'x64'
        os_architecture = 'X64'
        process_wow64 = $false
        sequence = $Sequence
    }
    foreach ($key in $Extra.Keys) { $receipt[$key] = $Extra[$key] }
    $receipt
}
$v3 = New-WinnReceipt 'winsvpn-windows-winn-v3-receipt-v1' 6 @{
    primary_transport = 'winn_v3'
    fallback_transports = @('winn_v1_awg','winn_v1_xray')
    winn_v3_session_observed = $true
}
$awg = New-WinnReceipt 'winsvpn-windows-winn-v1-awg-receipt-v1' 7 @{
    transport = 'winn_v1_awg'; observed = $true
}
$xray = New-WinnReceipt 'winsvpn-windows-winn-v1-xray-receipt-v1' 8 @{
    transport = 'winn_v1_xray'; observed = $true
}
Assert-WinnEvidenceOrder -ReceiptSet @($v3, $awg, $xray)
$swappedAwg = New-WinnReceipt 'winsvpn-windows-winn-v1-awg-receipt-v1' 8 @{
    transport = 'winn_v1_awg'; observed = $true
}
$swappedXray = New-WinnReceipt 'winsvpn-windows-winn-v1-xray-receipt-v1' 7 @{
    transport = 'winn_v1_xray'; observed = $true
}
try {
    Assert-WinnEvidenceOrder -ReceiptSet @($v3, $swappedAwg, $swappedXray)
    Write-Output 'ORDER_ACCEPTED'; exit 1
} catch {
    if ("$_" -notmatch 'not after AWG') { Write-Output $_; exit 2 }
}
$falseGreen = New-WinnReceipt 'winsvpn-windows-winn-v3-receipt-v1' 6 @{
    primary_transport = 'winn_v3'
    fallback_transports = @('winn_v1_awg','winn_v1_xray')
    winn_v3_session_observed = $true
    passed = $false
}
try {
    Assert-WinnEvidenceOrder -ReceiptSet @($falseGreen, $awg, $xray)
    Write-Output 'FALSE_GREEN_ACCEPTED'; exit 3
} catch {
    if ("$_" -notmatch 'partial false green') { Write-Output $_; exit 4 }
}
try {
    Assert-WinnEvidenceOrder -ReceiptSet @($v3, $awg)
    Write-Output 'PARTIAL_SET_ACCEPTED'; exit 5
} catch {
    if ("$_" -notmatch 'partial evidence') { Write-Output $_; exit 6 }
}
$mixedFallback = New-WinnReceipt 'winsvpn-windows-winn-v3-receipt-v1' 6 @{
    primary_transport = 'winn_v3'
    fallback_transports = @('winn_v1_xray','winn_v1_awg')
    winn_v3_session_observed = $true
}
try {
    Assert-WinnEvidenceOrder -ReceiptSet @($mixedFallback, $awg, $xray)
    Write-Output 'FALLBACK_ACCEPTED'; exit 7
} catch {
    if ("$_" -notmatch 'mixed fallback order') { Write-Output $_; exit 8 }
}
try {
    Assert-MatrixSeal -ResultSet @(@{ passed = $true; target_id = 'windows-x64-installer'; receipts = @($v3,$awg,$xray) })
    Write-Output 'SEAL_ACCEPTED'; exit 9
} catch {
    if ("$_" -notmatch 'wrong four-target coverage') { Write-Output $_; exit 10 }
}
Write-Output 'WINN_OK'
"""
        )
        result = self.run_ps(command)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("WINN_OK", result.stdout)
        for marker in (
            "ORDER_ACCEPTED",
            "FALSE_GREEN_ACCEPTED",
            "PARTIAL_SET_ACCEPTED",
            "FALLBACK_ACCEPTED",
            "SEAL_ACCEPTED",
        ):
            self.assertNotIn(marker, result.stdout)

    def test_reparse_hardlink_and_unbounded_child_output(self) -> None:
        python = shutil.which("python3") or shutil.which("python")
        if python is None:
            self.skipTest("Python is unavailable")
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            real = root / "real.bin"
            real.write_bytes(b"winsvpn")
            linked = root / "hard.bin"
            os.link(real, linked)
            symlink = root / "sym.bin"
            os.symlink(real, symlink)
            evidence = root / "evidence"
            evidence.mkdir()
            command = (
                self.prefix(root)
                + self.helpers()
                + f"$Python='{python}'\n"
                + r"""
Reset-MatrixDriverState
$sym = Join-Path $root 'sym.bin'
try {
    Assert-NoReparsePath $sym
    Write-Output 'SYMLINK_ACCEPTED'; exit 1
} catch {
    if ("$_" -notmatch 'reparse point') { Write-Output $_; exit 2 }
}
$hard = Join-Path $root 'hard.bin'
try {
    Assert-NoReparsePath $hard
    Write-Output 'HARDLINK_ACCEPTED'; exit 3
} catch {
    if ("$_" -notmatch 'hardlink substitution') { Write-Output $_; exit 4 }
}
$out = Join-Path $root 'escape.txt'
try {
    Assert-SafeEvidencePath $out (Join-Path $root 'evidence') -MustNotExist
    Write-Output 'ESCAPE_ACCEPTED'; exit 5
} catch {
    if ("$_" -notmatch 'allowed evidence root') { Write-Output $_; exit 6 }
}
try {
    Assert-SafeChildArgumentList @('-c', 'print(1); calc')
    Write-Output 'SEMI_ACCEPTED'; exit 7
} catch {
    if ("$_" -notmatch 'shell metacharacters') { Write-Output $_; exit 8 }
}
try {
    [void](Invoke-BoundedNative $Python @('-c', 'print("A"*5000)') -TimeoutMilliseconds 10000 -MaxOutputBytes 64)
    Write-Output 'UNBOUNDED_ACCEPTED'; exit 9
} catch {
    if ("$_" -notmatch 'unbounded|shell metacharacters') { Write-Output $_; exit 10 }
}
$ok = Invoke-BoundedNative $Python @('--version') -TimeoutMilliseconds 10000 -MaxOutputBytes 4096
if ([string]::IsNullOrWhiteSpace($ok) -and [string]::IsNullOrWhiteSpace($ok)) { }
Write-Output 'PATH_OK'
"""
            )
            result = self.run_ps(command)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("PATH_OK", result.stdout)
            for marker in (
                "SYMLINK_ACCEPTED",
                "HARDLINK_ACCEPTED",
                "ESCAPE_ACCEPTED",
                "UNBOUNDED_ACCEPTED",
            ):
                self.assertNotIn(marker, result.stdout)

    def test_stale_retry_and_assignments_entrypoint_refuses_false_green(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            installer = root / "WinsVPN-Setup.exe"
            partner = root / "WinsVPN-PartnerCenter.exe"
            self.write_pe(installer, PE_MACHINE_X64)
            self.write_pe(partner, PE_MACHINE_X64)
            command = (
                self.prefix(root)
                + self.helpers()
                + r"""
Reset-MatrixDriverState
$path = Join-Path $root 'WinsVPN-Setup.exe'
$partner = Join-Path $root 'WinsVPN-PartnerCenter.exe'
$row = New-SelfTestAssignment 'windows-x64-installer' 'windows-x64-host' $path '11111111-1111-1111-1111-111111111111'
Register-AssignmentAttempt $row 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
try {
    Register-AssignmentAttempt $row 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    Write-Output 'STALE_NONCE_ACCEPTED'; exit 1
} catch {
    if ("$_" -notmatch 'Stale Windows matrix retry') { Write-Output $_; exit 2 }
}
Reset-MatrixDriverState
Register-AssignmentAttempt $row 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
$row2 = New-SelfTestAssignment 'windows-x64-partner-center' 'windows-x64-host' $partner '22222222-2222-2222-2222-222222222222'
try {
    Register-AssignmentAttempt $row2 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    Write-Output 'STALE_RUN_ACCEPTED'; exit 3
} catch {
    if ("$_" -notmatch 'Stale Windows matrix retry') { Write-Output $_; exit 4 }
}
Write-Output 'RETRY_OK'
"""
            )
            result = self.run_ps(command)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("RETRY_OK", result.stdout)
            self.assertNotIn("STALE_NONCE_ACCEPTED", result.stdout)
            self.assertNotIn("STALE_RUN_ACCEPTED", result.stdout)
        if self.shell is None:
            return
        result = subprocess.run(
            [
                self.shell,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(DRIVER),
                "-Assignments",
                "missing.json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertRegex(
            result.stdout,
            r"partial false green|does not invent host evidence",
        )


if __name__ == "__main__":
    unittest.main()
