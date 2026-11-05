#!/usr/bin/env python3
"""Hostile fail-closed tests for Windows interactive-worker architecture receipts."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
WORKER = ROOT / "windows_release_interactive_worker.ps1"
PE_MACHINE_X64 = 0x8664
PE_MACHINE_ARM64 = 0xAA64
ARCH_FIELDS = (
    "architecture",
    "pe_machine",
    "native_architecture",
    "os_architecture",
    "process_wow64",
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


class WindowsReleaseInteractiveWorkerSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKER.read_text(encoding="utf-8")
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

    def slice_between(self, start_name: str, end_name: str) -> str:
        return self.text[
            self.text.index(f"function {start_name}") : self.text.index(
                f"function {end_name}"
            )
        ]

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
    param($Path, [IO.FileMode]$Mode, [IO.FileAccess]$Access)
    [IO.File]::Open($Path, $Mode, $Access, [IO.FileShare]::None)
}
"""

    def helpers(self) -> str:
        return (
            "$PeMachineX64=0x8664;$PeMachineArm64=0xAA64;"
            "$script:ArchitectureBinding=$null;"
            "$RunId='00000000-0000-0000-0000-000000000001';"
            "$InstallRoot='C:\\Program Files\\WinsVPN';"
            "$InstalledNativeHost='C:\\Program Files\\WinsVPN\\wins_bridge_host.exe';"
            "$InstalledNativeHostRoot='C:\\Program Files\\WinsVPN\\NativeMessagingHost'\n"
            + self.exclusive_stub()
            + self.function_text("Get-PeArchitecture")
            + "\n"
            + self.function_text("Get-NativeWindowsArchitecture")
            + "\n"
            + self.function_text("Get-BindingProperty")
            + "\n"
            + self.function_text("Assert-ArchitectureBinding")
            + "\n"
            + self.function_text("New-ArchitectureBinding")
            + "\n"
            + self.function_text("Get-RuntimeArchitectureBinding")
            + "\n"
            + self.function_text("Assert-PeMatchesBinding")
            + "\n"
            + self.function_text("Get-WorkerReceiptProperty")
            + "\n"
            + self.function_text("Assert-ContextIdentityBinding")
            + "\n"
            + self.function_text("Assert-FieldIdentityLock")
            + "\n"
            + self.function_text("New-BoundReceipt")
            + "\n"
            + self.function_text("Assert-WorkerBoundPhysicalReceipt")
            + "\n"
            + self.function_text("Assert-RequiredWorkerPhysicalReceipts")
            + "\n"
            + self.function_text("Write-RequiredPhysicalReceipt")
            + "\n"
            + self.function_text("Write-BoundReceiptJson")
            + "\n"
            + self.function_text("Resolve-WorkerObservedTransport")
            + "\n"
            + self.function_text("Get-NativeHostContract")
            + "\n"
            + self.function_text("Assert-NativeHostObservationFacts")
            + "\n"
        )

    def bound_context_ps(self) -> str:
        return r"""
$context = [pscustomobject]@{
    release_input_index_sha256=('a'*64)
    platform_manifest_sha256=('b'*64)
    artifact_input_fingerprint_sha256=('c'*64)
    build_receipt_sha256=('d'*64)
    producer_contract_sha256=('e'*64)
    collector_closure_sha256=('f'*64)
    artifact_sha256=('1'*64)
    release_identity='1.0.14+29'
    source_only=$false
}
"""

    def test_worker_uses_reparse_flag_and_exclusive_bound_output(self) -> None:
        text = self.text
        self.assertIn("$OpenReparsePoint = [IO.FileOptions]0x00200000", text)
        self.assertIn("function Open-ExclusiveFile", text)
        self.assertIn("function Write-BoundReceiptJson", text)
        self.assertIn("function Write-BoundAtomicJson", text)
        bound = self.function_text("Write-BoundReceiptJson")
        self.assertIn("Open-ExclusiveFile $Path ([IO.FileMode]::CreateNew)", bound)
        self.assertNotIn("[IO.File]::Open", bound)
        exclusive = self.function_text("Open-ExclusiveFile")
        self.assertIn("$OpenReparsePoint", exclusive)
        self.assertIn("Interactive worker descriptor opened a reparse point", exclusive)
        writers = self.slice_between("Write-NewJson", "Assert-Valid")
        self.assertIn("[IO.File]::Open", writers)
        self.assertNotIn("Open-ExclusiveFile", writers)

    def test_bound_receipts_emit_native_pe_architecture(self) -> None:
        text = self.text
        prepare = text[
            text.index("function Invoke-Prepare") : text.index("function Set-CurrentAppMode")
        ]
        execute = text[
            text.index("function Invoke-Execute") : text.index("function Invoke-Finalize")
        ]
        finalize = text[text.index("function Invoke-Finalize") :]
        for token in (
            "Get-PeArchitecture",
            "Get-NativeWindowsArchitecture",
            "New-ArchitectureBinding",
            "Assert-PeMatchesBinding",
            "Assert-InstalledNativeImages",
            "-EmitArchitecture",
            "Write-RequiredPhysicalReceipt (Join-Path $ReceiptRoot 'signature.json')",
            "Write-RequiredPhysicalReceipt (Join-Path $ReceiptRoot 'install.json')",
            "Write-BoundReceiptJson (Join-Path $PrivateRoot 'payload-receipt.json')",
            "Write-BoundReceiptJson (Join-Path $PrivateRoot 'runtime-context.json')",
            "winsvpn-windows-payload-receipt-v1",
            "winsvpn-windows-runtime-receipt-v1",
            "winsvpn-windows-uninstall-receipt-v1",
            "winsvpn-windows-winn-v3-receipt-v1",
            "winsvpn-windows-winn-v1-awg-receipt-v1",
            "winsvpn-windows-winn-v1-xray-receipt-v1",
            "winsvpn-windows-native-host-receipt-v1",
            "PROCESSOR_ARCHITEW6432",
            "Windows release worker must not run under WOW64.",
            "Worker receipt omitted architecture binding.",
            "PE architecture is mixed with the native host.",
            r"\.(exe|dll|sys)$",
            "Get-RuntimeArchitectureBinding $runtime",
            "source_only = $false",
            "release_identity",
            "refusing non-physical substitution",
            "refusing a partial false green",
            "mixed fallback order",
            "not after AWG",
        ):
            self.assertIn(token, text)
        self.assertIn(
            "Write-RequiredPhysicalReceipt $teardownPath $teardownReceipt",
            finalize,
        )
        self.assertIn("-EmitArchitecture", finalize)
        self.assertIn("Get-PeArchitecture $candidatePath", prepare)
        self.assertGreaterEqual(text.count("Get-RuntimeArchitectureBinding $runtime"), 4)
        self.assertGreaterEqual(text.count("-EmitArchitecture"), 4)
        self.assertIn("process_wow64 = $false", prepare)
        self.assertIn("pe_machine = [int]$script:ArchitectureBinding.pe_machine", prepare)
        self.assertNotIn(
            "Write-NewJson (Join-Path $ReceiptRoot 'signature.json')",
            text,
        )
        self.assertNotIn(
            "Write-NewJson (Join-Path $ReceiptRoot 'install.json')",
            text,
        )
        self.assertNotIn(
            "Write-NewJson (Join-Path $ReceiptRoot 'runtime.json')",
            text,
        )
        self.assertLess(
            execute.index("Invoke-WinnV3PrimaryObservation"),
            execute.index("Invoke-RapidCancelTest"),
        )
        self.assertLess(
            execute.index("winn-v1-awg.json"),
            execute.index("winn-v1-xray.json"),
        )

    def test_wow64_mixed_and_omitted_architecture_are_fail_closed(self) -> None:
        native = self.function_text("Get-NativeWindowsArchitecture")
        self.assertIn("PROCESSOR_ARCHITEW6432", native)
        self.assertIn("ProcessArchitecture", native)
        self.assertIn("OSArchitecture", native)
        self.assertIn("Windows release worker must not run under WOW64.", native)
        self.assertIn("'X64' { 'x64' }", native)
        self.assertIn("'Arm64' { 'arm64' }", native)
        binding = self.function_text("Assert-ArchitectureBinding")
        self.assertIn("Worker receipt omitted architecture binding.", binding)
        self.assertIn("Worker architecture binding is mixed, WOW64, or unsupported.", binding)
        self.assertIn("$architecture -cne 'x64' -and $architecture -cne 'arm64'", binding)
        self.assertIn("$wow64 -ne $false", binding)
        new_binding = self.function_text("New-ArchitectureBinding")
        self.assertIn("does not match artifact PE architecture", new_binding)
        pe = self.function_text("Get-PeArchitecture")
        self.assertIn("File is not PE32+ x64 or arm64", pe)
        self.assertIn("PE image lacks an Authenticode certificate table", pe)
        self.assertIn("$PeMachineX64", pe)
        self.assertIn("$PeMachineArm64", pe)
        self.assertIn("0x20B", pe)
        receipt = self.function_text("New-BoundReceipt")
        self.assertIn("Assert-ArchitectureBinding $script:ArchitectureBinding", receipt)
        self.assertIn("[switch]$EmitArchitecture", receipt)
        execute = self.text[
            self.text.index("function Invoke-Execute") : self.text.index(
                "function Invoke-Finalize"
            )
        ]
        self.assertIn(
            "$script:ArchitectureBinding = Get-RuntimeArchitectureBinding $runtime",
            execute,
        )

    def test_powershell_source_parses(self) -> None:
        path = str(WORKER).replace("'", "''")
        result = self.run_ps(
            "$t=$null;$e=$null;"
            f"$null=[Management.Automation.Language.Parser]::ParseFile('{path}',"
            "[ref]$t,[ref]$e); if($e.Count){$e|%{$_.ToString()}; exit 1}"
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_native_architecture_rejects_wow64(self) -> None:
        command = (
            "$ErrorActionPreference='Stop'\n"
            + self.function_text("Get-NativeWindowsArchitecture")
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
        self.assertNotIn("WOW64_ACCEPTED", result.stdout)

    def test_pe_parser_accepts_exact_x64_or_arm64_and_rejects_hostile_images(self) -> None:
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
                + self.function_text("Get-PeArchitecture")
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

    def test_architecture_binding_rejects_omitted_mixed_and_wow64(self) -> None:
        command = (
            "$ErrorActionPreference='Stop'\n"
            + self.helpers()
            + r"""
function Get-NativeWindowsArchitecture { 'x64' }
$good = [ordered]@{
    architecture='x64'; pe_machine=0x8664; native_architecture='x64'
    os_architecture='X64'; process_wow64=$false
}
Assert-ArchitectureBinding $good
$script:ArchitectureBinding = $good
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
$runtime = [pscustomobject]@{ architecture='x64'; pe_machine=0x8664 }
try {
    [void](Get-RuntimeArchitectureBinding $runtime)
    Write-Output 'RUNTIME_OMITTED_ACCEPTED'; exit 11
} catch {
    if ("$_" -notmatch 'omitted architecture binding') { Write-Output $_; exit 12 }
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
            "RUNTIME_OMITTED_ACCEPTED",
        ):
            self.assertNotIn(marker, result.stdout)

    def test_new_bound_receipt_requires_architecture_and_emits_on_request(self) -> None:
        command = (
            "$ErrorActionPreference='Stop'\n"
            + self.helpers()
            + self.bound_context_ps()
            + r"""
function Get-NativeWindowsArchitecture { 'x64' }
$started = [DateTime]::UtcNow
try {
    [void](New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context -EmitArchitecture)
    Write-Output 'OMITTED_RECEIPT_ACCEPTED'; exit 1
} catch {
    if ("$_" -notmatch 'omitted architecture binding') { Write-Output $_; exit 2 }
}
$script:ArchitectureBinding = [ordered]@{
    architecture='x64'; pe_machine=0x8664; native_architecture='x64'
    os_architecture='X64'; process_wow64=$false
}
$plain = New-BoundReceipt 'winsvpn-windows-route-advertisement-receipt-v1' 3 $started ([ordered]@{passed=$true}) $context
$bound = New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context -EmitArchitecture
if ($plain.architecture -cne 'x64' -or $plain.source_only -ne $false) { Write-Output 'PLAIN_UNBOUND'; exit 3 }
if ($plain.release_identity -cne '1.0.14+29') { Write-Output 'PLAIN_IDENTITY'; exit 3 }
if ($bound.architecture -cne 'x64' -or [int]$bound.pe_machine -ne 0x8664) { exit 4 }
if ($bound.native_architecture -cne 'x64' -or $bound.os_architecture -cne 'X64') { exit 5 }
if ($bound.process_wow64 -ne $false -or $bound.source_only -ne $false) { exit 6 }
if ($bound.release_identity -cne '1.0.14+29') { exit 7 }
$sourceContext = [pscustomobject]@{
    release_input_index_sha256=('a'*64); platform_manifest_sha256=('b'*64)
    artifact_input_fingerprint_sha256=('c'*64); build_receipt_sha256=('d'*64)
    producer_contract_sha256=('e'*64); collector_closure_sha256=('f'*64)
    artifact_sha256=('1'*64); release_identity='1.0.14+29'; source_only=$true
}
try {
    [void](New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $sourceContext)
    Write-Output 'SOURCE_ONLY_ACCEPTED'; exit 8
} catch {
    if ("$_" -notmatch 'source-only') { Write-Output $_; exit 9 }
}
Write-Output 'RECEIPT_OK'
"""
        )
        result = self.run_ps(command)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("RECEIPT_OK", result.stdout)
        self.assertNotIn("OMITTED_RECEIPT_ACCEPTED", result.stdout)
        self.assertNotIn("PLAIN_UNBOUND", result.stdout)
        self.assertNotIn("SOURCE_ONLY_ACCEPTED", result.stdout)

    def test_mixed_payload_pe_is_rejected_and_bound_json_is_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "x64.exe").write_bytes(minimal_pe32_plus(PE_MACHINE_X64, b"x64"))
            (root / "arm64.exe").write_bytes(
                minimal_pe32_plus(PE_MACHINE_ARM64, b"arm64")
            )
            posix = str(root).replace("'", "''")
            command = (
                "$ErrorActionPreference='Stop'\n"
                + self.helpers()
                + f"\n$root='{posix}'\n"
                + r"""
function Get-NativeWindowsArchitecture { 'x64' }
$script:ArchitectureBinding = New-ArchitectureBinding (Get-PeArchitecture (Join-Path $root 'x64.exe'))
Assert-PeMatchesBinding (Join-Path $root 'x64.exe') 'Candidate installer'
try {
    Assert-PeMatchesBinding (Join-Path $root 'arm64.exe') 'Payload wins_vpn.exe'
    Write-Output 'MIXED_PE_ACCEPTED'; exit 1
} catch {
    if ("$_" -notmatch 'PE architecture is mixed with the native host') {
        Write-Output $_
        exit 2
    }
}
$out = Join-Path $root 'payload-receipt.json'
Write-BoundReceiptJson $out ([ordered]@{ contract='winsvpn-windows-payload-receipt-v1'; passed=$true })
try {
    Write-BoundReceiptJson $out ([ordered]@{ contract='dup'; passed=$true })
    Write-Output 'CREATE_NEW_OVERWRITE'; exit 3
} catch { }
$parsed = Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
if ($parsed.contract -cne 'winsvpn-windows-payload-receipt-v1') { exit 4 }
Write-Output 'WRITE_OK'
"""
            )
            result = self.run_ps(command)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("WRITE_OK", result.stdout)
            self.assertNotIn("MIXED_PE_ACCEPTED", result.stdout)
            self.assertNotIn("CREATE_NEW_OVERWRITE", result.stdout)
            receipt = json.loads((root / "payload-receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["contract"], "winsvpn-windows-payload-receipt-v1")

    def test_new_architecture_binding_rejects_host_mismatch(self) -> None:
        command = (
            "$ErrorActionPreference='Stop'\n"
            + self.helpers()
            + r"""
function Get-NativeWindowsArchitecture { 'arm64' }
$pe = [ordered]@{ Name='x64'; Machine=0x8664 }
try {
    [void](New-ArchitectureBinding $pe)
    Write-Output 'HOST_MISMATCH_ACCEPTED'; exit 1
} catch {
    if ("$_" -notmatch 'does not match artifact PE architecture') { Write-Output $_; exit 2 }
}
try {
    [void](New-ArchitectureBinding ([ordered]@{}))
    Write-Output 'NULL_PE_ACCEPTED'; exit 3
} catch {
    if ("$_" -notmatch 'omitted architecture binding') { Write-Output $_; exit 4 }
}
Write-Output 'HOST_OK'
"""
        )
        result = self.run_ps(command)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("HOST_OK", result.stdout)
        self.assertNotIn("HOST_MISMATCH_ACCEPTED", result.stdout)
        self.assertNotIn("NULL_PE_ACCEPTED", result.stdout)


    def test_required_physical_receipts_reject_hostile_bindings(self) -> None:
        command = (
            "$ErrorActionPreference='Stop'\n"
            + self.helpers()
            + self.bound_context_ps()
            + r"""
function Get-NativeWindowsArchitecture { 'x64' }
$script:ArchitectureBinding = [ordered]@{
    architecture='x64'; pe_machine=0x8664; native_architecture='x64'
    os_architecture='X64'; process_wow64=$false
}
$started = [DateTime]::UtcNow
function New-ClosedSet {
    @(
        (New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context),
        (New-BoundReceipt 'winsvpn-windows-install-receipt-v1' 2 $started ([ordered]@{passed=$true}) $context),
        (New-BoundReceipt 'winsvpn-windows-runtime-receipt-v1' 3 $started ([ordered]@{runtime_observed=$true; passed=$true}) $context),
        (New-BoundReceipt 'winsvpn-windows-uninstall-receipt-v1' 4 $started ([ordered]@{uninstalled=$true; passed=$true}) $context),
        (New-BoundReceipt 'winsvpn-windows-teardown-rollback-receipt-v1' 5 $started ([ordered]@{passed=$true}) $context),
        (New-BoundReceipt 'winsvpn-windows-winn-v3-receipt-v1' 6 $started ([ordered]@{
            primary_transport='winn_v3'; fallback_transports=@('winn_v1_awg','winn_v1_xray')
            winn_v3_session_observed=$true; passed=$true
        }) $context),
        (New-BoundReceipt 'winsvpn-windows-winn-v1-awg-receipt-v1' 7 $started ([ordered]@{
            transport='winn_v1_awg'; observed=$true; passed=$true
        }) $context),
        (New-BoundReceipt 'winsvpn-windows-winn-v1-xray-receipt-v1' 8 $started ([ordered]@{
            transport='winn_v1_xray'; observed=$true; passed=$true
        }) $context),
        (New-BoundReceipt 'winsvpn-windows-native-host-receipt-v1' 9 $started ([ordered]@{
            native_host_observed=$true; passed=$true
        }) $context)
    )
}
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
$good = New-ClosedSet
Assert-RequiredWorkerPhysicalReceipts $good $context

$staleHash = New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context
$staleHash['artifact_sha256'] = ('c'*64)
Assert-Throws { Assert-WorkerBoundPhysicalReceipt $staleHash 'winsvpn-windows-signature-receipt-v1' 'sig' $context -RequirePass } 'exact candidate hash'

$staleIdentity = New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context
$staleIdentity['release_identity'] = '9.9.9+1'
Assert-Throws { Assert-WorkerBoundPhysicalReceipt $staleIdentity 'winsvpn-windows-signature-receipt-v1' 'sig' $context -RequirePass } 'release identity'

$crossRun = New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context
$crossRun['run_id'] = '22222222-2222-2222-2222-222222222222'
Assert-Throws { Assert-WorkerBoundPhysicalReceipt $crossRun 'winsvpn-windows-signature-receipt-v1' 'sig' $context -RequirePass } 'another live run'

$sourceOnly = New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context
$sourceOnly['source_only'] = $true
Assert-Throws { Assert-WorkerBoundPhysicalReceipt $sourceOnly 'winsvpn-windows-signature-receipt-v1' 'sig' $context -RequirePass } 'source-only'

$falseGreen = New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context
$falseGreen['passed'] = $false
Assert-Throws { Assert-WorkerBoundPhysicalReceipt $falseGreen 'winsvpn-windows-signature-receipt-v1' 'sig' $context -RequirePass } 'partial false green'

$omitted = New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context
$omitted.Remove('pe_machine')
Assert-Throws { Assert-ArchitectureBinding $omitted } 'omitted architecture binding'

$wow = New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context
$wow['process_wow64'] = $true
Assert-Throws { Assert-ArchitectureBinding $wow } 'mixed, WOW64, or unsupported'

$mixed = New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$true}) $context
$mixed['pe_machine'] = 0xAA64
Assert-Throws { Assert-ArchitectureBinding $mixed } 'mixed, WOW64, or unsupported'

$missing = @($good[0..($good.Count - 2)])
Assert-Throws { Assert-RequiredWorkerPhysicalReceipts $missing $context } 'partial evidence'

$swapped = New-ClosedSet
$swapped[6] = New-BoundReceipt 'winsvpn-windows-winn-v1-awg-receipt-v1' 8 $started ([ordered]@{transport='winn_v1_awg'; observed=$true; passed=$true}) $context
$swapped[7] = New-BoundReceipt 'winsvpn-windows-winn-v1-xray-receipt-v1' 7 $started ([ordered]@{transport='winn_v1_xray'; observed=$true; passed=$true}) $context
Assert-Throws { Assert-RequiredWorkerPhysicalReceipts $swapped $context } 'not after AWG'

$badFallback = New-ClosedSet
$badFallback[5] = New-BoundReceipt 'winsvpn-windows-winn-v3-receipt-v1' 6 $started ([ordered]@{
    primary_transport='winn_v3'; fallback_transports=@('winn_v1_xray','winn_v1_awg')
    winn_v3_session_observed=$true; passed=$true
}) $context
Assert-Throws { Assert-RequiredWorkerPhysicalReceipts $badFallback $context } 'mixed fallback order'

try {
    [void](New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{passed=$false}) $context)
    Write-Output 'FALSE_PASS_FIELDS'; exit 10
} catch {
    if ("$_" -notmatch 'partial false green') { Write-Output $_; exit 11 }
}
try {
    [void](New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{source_only=$true; passed=$true}) $context)
    Write-Output 'SOURCE_ONLY_FIELDS'; exit 12
} catch {
    if ("$_" -notmatch 'source-only') { Write-Output $_; exit 13 }
}
try {
    [void](New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{release_identity='9.9.9+1'; passed=$true}) $context)
    Write-Output 'CROSS_IDENTITY_FIELDS'; exit 14
} catch {
    if ("$_" -notmatch 'release identity') { Write-Output $_; exit 15 }
}
try {
    [void](New-BoundReceipt 'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{artifact_sha256=('c'*64); passed=$true}) $context)
    Write-Output 'CROSS_CANDIDATE_FIELDS'; exit 16
} catch {
    if ("$_" -notmatch 'exact candidate hash') { Write-Output $_; exit 17 }
}

if ((Resolve-WorkerObservedTransport 1 0 0) -cne 'winn_v3') { exit 18 }
if ((Resolve-WorkerObservedTransport 0 1 0) -cne 'winn_v1_awg') { exit 19 }
if ((Resolve-WorkerObservedTransport 0 1 1) -cne 'winn_v1_xray') { exit 20 }
try {
    [void](Resolve-WorkerObservedTransport 1 1 0)
    Write-Output 'MIXED_TRANSPORT'; exit 21
} catch {
    if ("$_" -notmatch 'mixed Winn v3/v1') { Write-Output $_; exit 22 }
}
try {
    [void](Resolve-WorkerObservedTransport 0 0 1)
    Write-Output 'XRAY_ONLY'; exit 23
} catch {
    if ("$_" -notmatch 'mixed Winn v3/v1') { Write-Output $_; exit 24 }
}
Assert-Throws {
    Assert-NativeHostObservationFacts ([ordered]@{
        native_host_observed=$false; host_name='org.winsvpn.bridge'
        host_image='C:\Program Files\WinsVPN\wins_bridge_host.exe'
        browsers=@()
    })
} 'source-only or unobserved'
$nativeOk = Get-NativeHostContract
if ($nativeOk.host_name -cne 'org.winsvpn.bridge') { exit 25 }
if (@($nativeOk.browsers).Count -ne 3) { exit 26 }
if ($nativeOk.browsers[0].browser -cne 'chrome' -or $nativeOk.browsers[2].browser -cne 'firefox') { exit 27 }
Write-Output 'HOSTILE_RECEIPT_BINDING=PASS'
"""
        )
        result = self.run_ps(command)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("HOSTILE_RECEIPT_BINDING=PASS", result.stdout)
        for marker in (
            "FALSE_PASS_FIELDS",
            "SOURCE_ONLY_FIELDS",
            "CROSS_IDENTITY_FIELDS",
            "CROSS_CANDIDATE_FIELDS",
            "MIXED_TRANSPORT",
            "XRAY_ONLY",
        ):
            self.assertNotIn(marker, result.stdout)

    def test_receipt_mutation_and_partial_run_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            posix = str(root).replace("'", "''")
            command = (
                "$ErrorActionPreference='Stop'\n"
                + self.helpers()
                + self.bound_context_ps()
                + f"\n$root='{posix}'\n"
                + r"""
function Get-NativeWindowsArchitecture { 'x64' }
$script:ArchitectureBinding = [ordered]@{
    architecture='x64'; pe_machine=0x8664; native_architecture='x64'
    os_architecture='X64'; process_wow64=$false
}
$started = [DateTime]::UtcNow
$out = Join-Path $root 'runtime.json'
$receipt = New-BoundReceipt 'winsvpn-windows-runtime-receipt-v1' 3 $started ([ordered]@{
    runtime_observed=$true; passed=$true
}) $context
Write-RequiredPhysicalReceipt $out $receipt 'winsvpn-windows-runtime-receipt-v1' $context
try {
    Write-RequiredPhysicalReceipt $out $receipt 'winsvpn-windows-runtime-receipt-v1' $context
    Write-Output 'MUTATION_OVERWRITE'; exit 1
} catch { }
$parsed = Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
$parsed.artifact_sha256 = ('c'*64)
$mutated = Join-Path $root 'runtime-mutated.json'
($parsed | ConvertTo-Json -Depth 8 -Compress) + [Environment]::NewLine |
    Set-Content -LiteralPath $mutated -Encoding utf8
$mutatedDoc = Get-Content -LiteralPath $mutated -Raw | ConvertFrom-Json
try {
    Assert-WorkerBoundPhysicalReceipt $mutatedDoc 'winsvpn-windows-runtime-receipt-v1' 'runtime' $context -RequirePass
    Write-Output 'MUTATED_HASH_ACCEPTED'; exit 2
} catch {
    if ("$_" -notmatch 'exact candidate hash') { Write-Output $_; exit 3 }
}
$parsed.source_only = $true
$parsed.artifact_sha256 = ('1'*64)
try {
    Assert-WorkerBoundPhysicalReceipt $parsed 'winsvpn-windows-runtime-receipt-v1' 'runtime' $context -RequirePass
    Write-Output 'MUTATED_SOURCE_ONLY_ACCEPTED'; exit 4
} catch {
    if ("$_" -notmatch 'source-only') { Write-Output $_; exit 5 }
}
Write-Output 'MUTATION_OK'
"""
            )
            result = self.run_ps(command)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("MUTATION_OK", result.stdout)
            self.assertNotIn("MUTATION_OVERWRITE", result.stdout)
            self.assertNotIn("MUTATED_HASH_ACCEPTED", result.stdout)
            self.assertNotIn("MUTATED_SOURCE_ONLY_ACCEPTED", result.stdout)
            written = json.loads((root / "runtime.json").read_text(encoding="utf-8"))
            self.assertEqual(written["contract"], "winsvpn-windows-runtime-receipt-v1")
            self.assertFalse(written["source_only"])
            self.assertTrue(written["runtime_observed"])
            self.assertEqual(written["release_identity"], "1.0.14+29")
            self.assertEqual(written["architecture"], "x64")


if __name__ == "__main__":
    unittest.main()
