#!/usr/bin/env python3
"""Executable security tests for the Windows ZIP producer and installer."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "installer/windows/build_zip_installer.ps1"
INSTALL_SCRIPT = ROOT / "installer/windows/install_winsvpn_zip.ps1"
DEPENDENCIES = ROOT / "installer/windows/dependencies"
LICENSES = ROOT / "installer/windows/licenses"
NOTICES = ROOT / "docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md"
PWSh = shutil.which("pwsh")

WITHDRAWN_KERNEL_PAYLOADS = (
    "mullvad-split-tunnel.sys",
    "mullvad-split-tunnel.cat",
    "mullvad-split-tunnel.inf",
    "mullvad-split-tunnel-arm64.sys",
    "mullvad-split-tunnel-arm64.cat",
    "mullvad-split-tunnel-arm64.inf",
)
WITHDRAWN_KERNEL_PAYLOAD_SHA256 = {
    "mullvad-split-tunnel.sys": "10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201",
    "mullvad-split-tunnel.cat": "c599926a0327d7ae06b534f4cd039db30392e1897bb9d03e4fec3631744a4e6d",
    "mullvad-split-tunnel.inf": "3dd5905e5fb98d61a942a33e8c9a5ba07c3a2de1e4f319e1fec3e54df6591608",
    "mullvad-split-tunnel-arm64.sys": "6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534",
    "mullvad-split-tunnel-arm64.cat": "c3d27636739ebaa7dde369d113347de83e3e2173b8a512bb8863d11b148de7ce",
    "mullvad-split-tunnel-arm64.inf": "0bfdb044e40535dabbeb3620b655c1563714b3a6f3231d3492c972c6e8dea6f1",
}


# The withdrawn kernel split-tunnel blobs were removed from
# installer/windows/dependencies in ee48a2f (and must stay absent there, see
# test_withdrawn_mullvad_shipping_surfaces.py). Their last tree is that
# commit's parent; every byte read from it must equal the reviewed digest.
WITHDRAWN_KERNEL_PAYLOAD_COMMIT = "eea17adb5cc9c0337246d6727cc3a5ca3512226a"


def git_dependency_bytes(name: str) -> bytes:
    path = DEPENDENCIES / name
    if path.is_file():
        return path.read_bytes()
    if name in WITHDRAWN_KERNEL_PAYLOAD_SHA256:
        data = subprocess.check_output(
            [
                "git",
                "show",
                f"{WITHDRAWN_KERNEL_PAYLOAD_COMMIT}:installer/windows/dependencies/{name}",
            ],
            cwd=ROOT,
        )
        if hashlib.sha256(data).hexdigest() != WITHDRAWN_KERNEL_PAYLOAD_SHA256[name]:
            raise AssertionError(
                f"{name} from {WITHDRAWN_KERNEL_PAYLOAD_COMMIT} is not the reviewed withdrawn payload"
            )
        return data
    return subprocess.check_output(
        ["git", "show", f"HEAD:installer/windows/dependencies/{name}"],
        cwd=ROOT,
    )


def wrap_payload(data: bytes) -> bytes:
    return b"WRAP-HEAD\0" + data + b"\0WRAP-TAIL"


DEPENDENCY_CONTRACT = {
    "amneziawg_client_version": "3.1.0",
    "amneziawg_msi_sha256": "a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b",
    "amneziawg_msi_runtime_amneziawg_sha256": "ba446f6e1a4093e43a65d6ff45f4b8c7b6485dc419327eedaa1a218549740e3a",
    "amneziawg_maintenance_helper_sha256": "12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41",
    "amneziawg_source_commit": "ca5dd3b983bd19c335ab095ccd21fc2f804ec968",
    "amneziawg_engine_version": "v3.1.20260828",
    "amneziawg_engine_commit": "b5928efb6ca19f0153958460c3d141f04abc5c2e",
    "awg_exe_sha256": "272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12",
    "wintun_version": "0.14.1",
    "wintun_dll_sha256": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
    "xray_version": "v26.9.30",
    "xray_source_commit": "b26a91de4f3294e26a0ad0a970b81a386a41f789",
    "xray_exe_sha256": "fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224",
    "xray_go_version": "1.27.1",
    "vc_redist_version": "14.44.35211.0",
    "vc_redist_sha256": "cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b",
}


ARM64_DEPENDENCY_CONTRACT = {
    "amneziawg_client_version": "3.1.0",
    "amneziawg_msi_sha256": "3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa",
    "amneziawg_msi_runtime_amneziawg_sha256": "25fa81103152699bf416f394059b40d447001c3d0dea5ef889a9426f315e4c0a",
    "amneziawg_source_commit": "ca5dd3b983bd19c335ab095ccd21fc2f804ec968",
    "amneziawg_engine_version": "v3.1.20260828",
    "amneziawg_engine_commit": "b5928efb6ca19f0153958460c3d141f04abc5c2e",
    "awg_exe_sha256": "3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43",
    "wintun_version": "0.14.1",
    "wintun_dll_sha256": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
    "xray_version": "v26.9.30",
    "xray_source_commit": "b26a91de4f3294e26a0ad0a970b81a386a41f789",
    "xray_exe_sha256": "c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af",
    "xray_go_version": "1.27.1",
    "vc_redist_version": "14.44.35211.0",
    "vc_redist_sha256": "5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0",
}
SIGNING_ENVIRONMENT = (
    "WINS_WINDOWS_ARTIFACT_SIGNING_METADATA",
    "WINS_WINDOWS_SIGN_CERT_SHA1",
    "WINS_WINDOWS_SIGN_CERT_STORE",
    "WINS_WINDOWS_SIGN_PFX",
    "WINS_WINDOWS_SIGN_PFX_PASSWORD",
    "WINS_WINDOWS_SIGNER_SUBJECT_REGEX",
    "WINS_WINDOWS_TIMESTAMP_URL",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pe_with_certificate_table(machine: int = 0x8664, cert_size: int = 64) -> bytes:
    image = bytearray(512)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x40).to_bytes(4, "little")
    image[0x40:0x44] = b"PE\0\0"
    image[0x44:0x46] = machine.to_bytes(2, "little")
    image[0x46:0x48] = (1).to_bytes(2, "little")
    image[0x54:0x56] = (152).to_bytes(2, "little")
    optional_magic = 0x20B if machine in (0x8664, 0xAA64) else 0x10B
    image[0x58:0x5A] = optional_magic.to_bytes(2, "little")
    image[0xC4:0xC8] = (16).to_bytes(4, "little")
    image[0xEC:0xF0] = cert_size.to_bytes(4, "little")
    return bytes(image)


def carrying_pe(machine: int = 0x8664) -> bytes:
    return minimal_pe(machine) + b"winsvpn.local/winnprotocol/winn3"


def ps_single(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def flatten_ps(output: str) -> str:
    output = ANSI.sub("", output)
    collapsed = re.sub(r"\s+\|\s+", " ", output.replace("\r", " "))
    return " ".join(collapsed.split())


def minimal_pe(machine: int) -> bytes:
    image = bytearray(128)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x40).to_bytes(4, "little")
    image[0x40:0x44] = b"PE\0\0"
    image[0x44:0x46] = machine.to_bytes(2, "little")
    image[0x46:0x48] = (1).to_bytes(2, "little")
    image[0x54:0x56] = (2).to_bytes(2, "little")
    optional_magic = 0x20B if machine in (0x8664, 0xAA64) else 0x10B
    image[0x58:0x5A] = optional_magic.to_bytes(2, "little")
    return bytes(image)


@unittest.skipUnless(PWSh, "pwsh is required for executable ZIP-route tests")
class WindowsZipRouteExecutableSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="winsvpn-zip-security-")
        self.root = pathlib.Path(self.temp.name)
        self.stage = self.root / "stage"
        self.stage.mkdir()
        self.install_root = self.root / "install"
        self.archive_harness = self.root / "archive-harness.ps1"
        self.archive_harness.write_text(
            r"""
param([string]$BuildScript, [string]$ZipPath, [string]$DestinationRoot)
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $BuildScript, [ref]$tokens, [ref]$errors
)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @(
    'ConvertTo-CanonicalPayloadPath',
    'Assert-CanonicalReservedPayloadPath',
    'Assert-ZipPayloadAllowed',
    'Assert-ZipPayloadHashAllowed',
    'Assert-ZipPayloadBytesAllowed',
    'Get-ValidatedContainerRoot',
    'Assert-NoReparsePointChain',
    'Get-ContainedPayloadPath',
    'Expand-SafeZipArchive'
)) {
    $definitions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($definitions.Count -ne 1) { throw "Expected one function $name" }
    Set-Item -Path ("Function:\script:" + $name) -Value $definitions[0].Body.GetScriptBlock()
}
foreach ($variableName in @(
    'ForbiddenZipPayloadLeafNames',
    'ForbiddenZipPayloadLeafPrefixes',
    'ForbiddenZipPayloadExtensions',
    'ForbiddenZipPayloadPaths',
    'ForbiddenZipPayloadSha256',
    'ForbiddenZipPayloadFingerprints'
)) {
    $target = '$' + $variableName
    $assignments = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq $target
    }, $true))
    if ($assignments.Count -ne 1) { throw "Expected one assignment for $target" }
    $value = @(& ([scriptblock]::Create($assignments[0].Right.Extent.Text)))
    Set-Variable -Scope Script -Name $variableName -Value $value
}
$script:ZipPeMachine = [uint16]0x8664
$script:ZipX86PeMachine = [uint16]0x014c
Expand-SafeZipArchive -ZipPath $ZipPath -DestinationRoot $DestinationRoot
""".strip()
            + "\n",
            encoding="utf-8",
        )
        self.copy_harness = self.root / "copy-harness.ps1"
        self.copy_harness.write_text(
            r"""
param([string]$BuildScript, [string]$SourceRoot, [string]$DestinationRoot)
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $BuildScript, [ref]$tokens, [ref]$errors
)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @(
    'ConvertTo-CanonicalPayloadPath',
    'Assert-CanonicalReservedPayloadPath',
    'Assert-ZipPayloadAllowed',
    'Assert-ZipPayloadHashAllowed',
    'Assert-ZipPayloadBytesAllowed',
    'Get-ValidatedContainerRoot',
    'Assert-NoReparsePointChain',
    'Get-ContainedPayloadPath',
    'Get-ContainedFileItems',
    'Sha256-Of',
    'Copy-ContainedDirectoryFiles'
)) {
    $definitions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($definitions.Count -ne 1) { throw "Expected one function $name" }
    Set-Item -Path ("Function:\script:" + $name) -Value $definitions[0].Body.GetScriptBlock()
}
foreach ($variableName in @(
    'ForbiddenZipPayloadLeafNames',
    'ForbiddenZipPayloadLeafPrefixes',
    'ForbiddenZipPayloadExtensions',
    'ForbiddenZipPayloadPaths',
    'ForbiddenZipPayloadSha256',
    'ForbiddenZipPayloadFingerprints'
)) {
    $target = '$' + $variableName
    $assignments = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq $target
    }, $true))
    if ($assignments.Count -ne 1) { throw "Expected one assignment for $target" }
    $value = @(& ([scriptblock]::Create($assignments[0].Right.Extent.Text)))
    Set-Variable -Scope Script -Name $variableName -Value $value
}
Copy-ContainedDirectoryFiles `
    -SourceRoot $SourceRoot `
    -DestinationRoot $DestinationRoot `
    -Purpose 'test release copy'
""".strip()
            + "\n",
            encoding="utf-8",
        )
        self.invoke_harness = self.root / "invoke-harness.ps1"
        self.invoke_harness.write_text(
            r"""
param([string]$BuildScript, [string]$Call)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $BuildScript, [ref]$tokens, [ref]$errors
)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
$functionNames = @(
    'Write-Step',
    'Initialize-ZipArchitectureContract',
    'Assert-SafeZipPathArgument',
    'Reset-ZipPartialOutputs',
    'Register-ZipPartialOutput',
    'Remove-ZipPartialOutputs',
    'Assert-RegularContainer',
    'Assert-RegularLeafFile',
    'Assert-Dir',
    'Test-FileContainsMarker',
    'Sha256-Of',
    'Get-PeCoffMachine',
    'Get-PeCertificateTableSize',
    'ConvertTo-CanonicalPayloadPath',
    'Assert-CanonicalReservedPayloadPath',
    'Assert-ZipPayloadAllowed',
    'Assert-ZipPayloadHashAllowed',
    'Assert-ZipPayloadBytesAllowed',
    'Get-ValidatedContainerRoot',
    'Get-ContainedPayloadPath',
    'Assert-NoReparsePointChain',
    'Get-ContainedFileItems',
    'Copy-ContainedDirectoryFiles',
    'Copy-ExactContainedFile',
    'Copy-ZipEnginePayloads',
    'Copy-ZipPinnedDependencies',
    'Get-ZipFirstPartyEnginePaths',
    'Assert-ZipUnsignedEngineProductOrdering',
    'Get-ZipSignedPayloadPlan',
    'Assert-ZipSignedEngineProductPayloads',
    'Assert-ZipEngineProductSigningState',
    'Assert-ZipDependencyInputs',
    'Assert-WindowsAwgSchema2OwnerPublicationContract',
    'Assert-StagedDependencyPins',
    'New-DeterministicZipArchive',
    'Assert-ZipArchiveInventory',
    'Invoke-ZipExtractedPayloadReaudit',
    'Assert-ZipReceiptMatchesArtifact',
    'Assert-StagedPeMachines',
    'Remove-StagedDebugSymbolFiles',
    'Test-Winn3CarrierCompleteness',
    'Get-RelativePaths',
    'Expand-SafeZipArchive',
    'Test-ZipRoundTrip'
)
foreach ($name in $functionNames) {
    $definitions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true))
    if ($definitions.Count -ne 1) { throw "Expected one function $name" }
    Set-Item -Path ("Function:\script:" + $name) -Value $definitions[0].Body.GetScriptBlock()
}
foreach ($variableName in @(
    'ForbiddenZipPayloadLeafNames',
    'ForbiddenZipPayloadLeafPrefixes',
    'ForbiddenZipPayloadExtensions',
    'ForbiddenZipPayloadPaths',
    'ForbiddenZipPayloadSha256',
    'ForbiddenZipPayloadFingerprints',
    'ZipX86PeMachine',
    'ZipX64PeMachine',
    'ZipArm64PeMachine',
    'ZipX64DependencyPins',
    'ZipArm64DependencyPins',
    'ZipX64DependencyContract',
    'ZipArm64DependencyContract',
    'ZipDependencyPins',
    'ZipDependencyContract',
    'ZipPeMachine',
    'ZipArchitecture',
    'ZipAwgGoTarget',
    'ZipHelperSourceName',
    'ZipLicenseFiles',
    'ZipFirstPartyEnginePaths',
    'ZipFirstPartyProductPaths',
    'Marker',
    'AmneziaWgHelperProvenance'
)) {
    $target = '$' + $variableName
    $assignments = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq $target
    }, $true))
    if ($assignments.Count -ne 1) { throw "Expected one assignment for $target" }
    $value = & ([scriptblock]::Create($assignments[0].Right.Extent.Text))
    Set-Variable -Scope Script -Name $variableName -Value $value
}
$vcLeaf = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$script:ZipVcRedistLeaf'
}, $true))
if ($vcLeaf.Count -lt 1) { throw 'Expected ZipVcRedistLeaf assignment' }
Set-Variable -Scope Script -Name 'ZipVcRedistLeaf' -Value (& ([scriptblock]::Create($vcLeaf[0].Right.Extent.Text)))
$script:ZipVcRedistLeaf = $ZipVcRedistLeaf
$script:ZipSigning = $null
$script:ZipSignatureEvidence = [System.Collections.Generic.List[object]]::new()
Initialize-ZipArchitectureContract -Architecture x64
Reset-ZipPartialOutputs
& ([scriptblock]::Create($Call))
""".strip()
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def entry(
        self,
        path: str,
        data: bytes = b"x",
        *,
        dest: str = "app",
        declared_sha256: str | None = None,
        declared_bytes: int | str | None = None,
        write_path: str | None = None,
    ) -> dict[str, object]:
        relative = write_path if write_path is not None else path
        if relative and not relative.startswith(("/", "\\")) and ".." not in relative.split("/"):
            target = self.stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return {
            "path": path,
            "bytes": len(data) if declared_bytes is None else declared_bytes,
            "sha256": sha256(data) if declared_sha256 is None else declared_sha256,
            "dest": dest,
        }

    def manifest(self, entries: list[dict[str, object]], **overrides: object) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": 2,
            "route": "zip-plus-powershell",
            "app": "Win's VPN",
            "app_version": "1.0.0",
            "architecture": "x64",
            "built_at_utc": "2026-08-23T00:00:00.0000000Z",
            "file_count": len(entries),
            "dependency_contract": dict(DEPENDENCY_CONTRACT),
            "files": entries,
        }
        result.update(overrides)
        return result

    def verify(
        self, manifest: dict[str, object], script: pathlib.Path = INSTALL_SCRIPT
    ) -> subprocess.CompletedProcess[str]:
        (self.stage / "payload-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        return subprocess.run(
            [
                PWSh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(script),
                "-StageDir",
                str(self.stage),
                "-VerificationInstallRoot",
                str(self.install_root),
                "-VerifyManifestOnly",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def extract_zip(self, archive: pathlib.Path, destination: pathlib.Path) -> subprocess.CompletedProcess[str]:
        destination.mkdir()
        return subprocess.run(
            [
                PWSh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(self.archive_harness),
                str(BUILD_SCRIPT),
                str(archive),
                str(destination),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def copy_release(
        self, source: pathlib.Path, destination: pathlib.Path
    ) -> subprocess.CompletedProcess[str]:
        destination.mkdir()
        return subprocess.run(
            [
                PWSh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(self.copy_harness),
                str(BUILD_SCRIPT),
                str(source),
                str(destination),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def invoke(self, call: str, timeout: int = 45) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                PWSh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(self.invoke_harness),
                str(BUILD_SCRIPT),
                call,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    def assert_invoke_rejected(self, call: str, marker: str) -> str:
        result = self.invoke(call)
        output = result.stdout + result.stderr
        flattened = flatten_ps(output)
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn(marker, flattened)
        return flattened

    def assert_rejected(
        self,
        manifest: dict[str, object],
        marker: str,
        script: pathlib.Path = INSTALL_SCRIPT,
    ) -> str:
        result = self.verify(manifest, script)
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn(marker, output)
        self.assertNotIn("Elevation required", output)
        self.assertFalse(self.install_root.exists(), "verification mode wrote install state")
        return output

    def test_rejects_parent_traversal_before_elevation(self) -> None:
        entry = self.entry("../outside.exe", write_path="safe.bin")
        self.assert_rejected(self.manifest([entry]), "dot segment")

    def test_rejects_rooted_drive_and_backslash_paths(self) -> None:
        for path in (
            "/Windows/Temp/evil.exe",
            "C:/Windows/Temp/evil.exe",
            "dir\\evil.exe",
            "//server/share/evil.exe",
        ):
            with self.subTest(path=path):
                entry = self.entry(path, write_path="safe.bin")
                self.assert_rejected(self.manifest([entry]), "relative and use forward slashes")

    def test_rejects_ambiguous_or_reserved_windows_segments(self) -> None:
        for path, marker in (
            ("dir/./file.bin", "dot segment"),
            ("dir//file.bin", "dot segment"),
            ("CON.exe", "reserved Windows device"),
            ("dir./file.bin", "Windows-ambiguous"),
            ("dir /file.bin", "Windows-ambiguous"),
            ("file.bin:stream", "relative and use forward slashes"),
        ):
            with self.subTest(path=path):
                entry = self.entry(path, write_path="safe.bin")
                self.assert_rejected(self.manifest([entry]), marker)

    def test_rejects_case_insensitive_duplicate_paths(self) -> None:
        first = self.entry("data/file.bin", b"a")
        second = self.entry("DATA/FILE.BIN", b"a", write_path="data/file.bin")
        self.assert_rejected(self.manifest([first, second]), "Duplicate manifest path")

    def test_rejects_mixed_case_reserved_prefixes(self) -> None:
        for index, path in enumerate(
            ("Dependencies/amneziawg.exe", "Licenses/README.txt")
        ):
            with self.subTest(path=path):
                self.stage = self.root / f"stage-reserved-{index}"
                self.stage.mkdir()
                entry = self.entry(path)
                self.assert_rejected(
                    self.manifest([entry]), "must use canonical lowercase spelling"
                )

    def test_rejects_duplicate_flattened_install_destination(self) -> None:
        helper_pin = DEPENDENCY_CONTRACT["amneziawg_maintenance_helper_sha256"]
        dependency = self.entry(
            "dependencies/amneziawg.exe", b"helper", declared_sha256=helper_pin
        )
        top_level = self.entry("amneziawg.exe", b"other")
        self.assert_rejected(
            self.manifest([dependency, top_level]), "Duplicate install destination"
        )

    def test_rejects_unsupported_destination(self) -> None:
        entry = self.entry("safe.bin", dest="windows-system32")
        self.assert_rejected(self.manifest([entry]), "Unsupported manifest destination")

    def test_rejects_malformed_hash_and_size(self) -> None:
        bad_hash = self.entry("bad-hash.bin", declared_sha256="ABC")
        self.assert_rejected(self.manifest([bad_hash]), "Malformed lowercase SHA-256")

        self.stage = self.root / "stage-size"
        self.stage.mkdir()
        bad_size = self.entry("bad-size.bin", declared_bytes="1")
        self.assert_rejected(self.manifest([bad_size]), "Malformed byte count")

    def test_rejects_unlisted_physical_payload(self) -> None:
        listed = self.entry("listed.bin")
        (self.stage / "rogue.exe").write_bytes(minimal_pe(0x8664))
        self.assert_rejected(self.manifest([listed]), "rogue.exe is present but unlisted")

    def test_rejects_reparse_point_payload(self) -> None:
        outside = self.root / "outside.bin"
        outside.write_bytes(b"outside")
        link = self.stage / "linked.bin"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        entry = {
            "path": "linked.bin",
            "bytes": len(b"outside"),
            "sha256": sha256(b"outside"),
            "dest": "app",
        }
        self.assert_rejected(self.manifest([entry]), "reparse point")

    def test_rejects_arm64_or_invalid_pe_payload(self) -> None:
        arm64 = minimal_pe(0xAA64)
        entry = self.entry("wins_vpn.exe", arm64)
        self.assert_rejected(self.manifest([entry]), "PE/COFF machine 0xaa64")

        self.stage = self.root / "stage-malformed-pe"
        self.stage.mkdir()
        malformed = bytearray(minimal_pe(0x8664))
        malformed[0x58:0x5A] = b"\x00\x00"
        entry = self.entry("wins_vpn.exe", bytes(malformed))
        self.assert_rejected(self.manifest([entry]), "PE/COFF machine 0x0000")

    ARM64_HELPER_MISSING_PIN = (
        "Missing pin: this arm64 ZIP installer requires its app-owned "
        "amneziawg.exe maintenance helper."
    )

    def arm64_installer_with_fixture_helper_pin(self, helper: bytes) -> pathlib.Path:
        # Test harness only: a private copy of the installer whose ARM64 table
        # pins a fixture helper. The committed ARM64 table stays without one.
        source = INSTALL_SCRIPT.read_text(encoding="utf-8")
        table = "$ExpectedArm64DependencyPins = [ordered]@{\n"
        self.assertEqual(source.count(table), 1)
        self.assertNotIn(
            "'dependencies/amneziawg.exe'",
            source[source.index(table) : source.index("$ExpectedArm64DependencyContract =")],
        )
        injected = (
            table
            + f"    'dependencies/amneziawg.exe' = [ordered]@{{ sha256 = '{sha256(helper)}'; dest = 'app' }}\n"
        )
        harness = self.root / "fixture-helper-pin" / "install_winsvpn_zip.ps1"
        harness.parent.mkdir(exist_ok=True)
        harness.write_text(source.replace(table, injected, 1), encoding="utf-8")
        return harness

    def test_arm64_manifest_without_a_helper_pin_is_refused(self) -> None:
        arm64 = {"architecture": "arm64", "dependency_contract": dict(ARM64_DEPENDENCY_CONTRACT)}
        entry = self.entry("wins_vpn.exe", minimal_pe(0xAA64))
        output = self.assert_rejected(
            self.manifest([entry], **arm64), self.ARM64_HELPER_MISSING_PIN
        )
        self.assertIn("schema validation failed", output)
        self.assertIn("Get-FileHash -Algorithm SHA256", output)
        self.assertNotIn("winn-datapath.exe", output)
        self.assertNotIn("owner-blocked", output)

        # A helper listed by the manifest itself never stands in for the pin.
        self.stage = self.root / "stage-arm64-manifest-helper"
        self.stage.mkdir()
        helper = minimal_pe(0xAA64) + b"manifest-supplied helper"
        entries = [
            self.entry("wins_vpn.exe", minimal_pe(0xAA64)),
            self.entry("dependencies/amneziawg.exe", helper),
        ]
        output = self.assert_rejected(
            self.manifest(entries, **arm64), self.ARM64_HELPER_MISSING_PIN
        )
        self.assertNotIn("winn-datapath.exe", output)

        # The x64 table pins the helper, so x64 manifests still reach the
        # payload gates.
        self.stage = self.root / "stage-x64-helper-pinned"
        self.stage.mkdir()
        entry = self.entry("wins_vpn.exe", minimal_pe(0x8664))
        output = self.assert_rejected(self.manifest([entry]), "winn-datapath.exe")
        self.assertNotIn("Missing pin", output)

    def test_arm64_manifest_with_a_harness_helper_pin_reaches_the_arm64_payload_gates(
        self,
    ) -> None:
        helper = minimal_pe(0xAA64) + b"arm64 helper fixture"
        script = self.arm64_installer_with_fixture_helper_pin(helper)
        arm64 = {"architecture": "arm64", "dependency_contract": dict(ARM64_DEPENDENCY_CONTRACT)}
        entry = self.entry("wins_vpn.exe", minimal_pe(0xAA64))
        output = self.assert_rejected(
            self.manifest([entry], **arm64), "winn-datapath.exe", script
        )
        self.assertNotIn("owner-blocked", output)
        self.assertNotIn("schema validation failed", output)
        self.assertNotIn("Missing pin", output)

        self.stage = self.root / "stage-arm64-pinned-helper"
        self.stage.mkdir()
        entries = [
            self.entry("wins_vpn.exe", minimal_pe(0xAA64)),
            self.entry("dependencies/amneziawg.exe", helper),
        ]
        output = self.assert_rejected(
            self.manifest(entries, **arm64), "winn-datapath.exe", script
        )
        self.assertNotIn("exact reviewed hash and destination", output)
        self.assertNotIn("Missing pin", output)

        self.stage = self.root / "stage-arm64-unpinned-helper"
        self.stage.mkdir()
        entry = self.entry("dependencies/amneziawg.exe", helper + b"tampered")
        self.assert_rejected(
            self.manifest([entry], **arm64), "exact reviewed hash and destination", script
        )

        self.stage = self.root / "stage-arm64-x64-pe"
        self.stage.mkdir()
        entry = self.entry("wins_vpn.exe", minimal_pe(0x8664))
        output = self.assert_rejected(
            self.manifest([entry], **arm64), "PE/COFF machine 0x8664", script
        )
        self.assertNotIn("owner-blocked", output)

        self.stage = self.root / "stage-arm64-x64-pin"
        self.stage.mkdir()
        x64_wintun = git_dependency_bytes("wintun.dll")
        entry = self.entry("dependencies/wintun.dll", x64_wintun)
        self.assert_rejected(
            self.manifest([entry], **arm64), "exact reviewed hash and destination", script
        )

        self.stage = self.root / "stage-arm64-x64-contract"
        self.stage.mkdir()
        entry = self.entry("wins_vpn.exe", minimal_pe(0xAA64))
        self.assert_rejected(
            self.manifest([entry], architecture="arm64"),
            "Dependency contract has an invalid property set",
            script,
        )

    def test_rejects_missing_winn_v3_carrier_before_elevation(self) -> None:
        entry = self.entry("ordinary.bin")
        output = self.assert_rejected(self.manifest([entry]), "winn-datapath.exe")
        self.assertIn("winsvpn_winn3_engine.exe", output)

    def test_rejects_manifest_authorized_dependency_substitution(self) -> None:
        entry = self.entry("dependencies/amneziawg-amd64.msi", b"stale")
        self.assert_rejected(self.manifest([entry]), "exact reviewed hash and destination")

    def test_rejects_withdrawn_mullvad_kernel_split_payloads(self) -> None:
        cases = (
            (
                "dependencies/mullvad-split-tunnel.sys",
                minimal_pe(0x8664),
                "app",
            ),
            ("drivers/MULLVAD-SPLIT-TUNNEL.CAT", b"catalog", "app"),
            ("mullvad-split-tunnel.inf", b"inf", "app"),
            ("nested/mullvad-split-tunnel-arm64.inf", b"arm64 inf", "app"),
            ("nested/renamed-driver.sys", minimal_pe(0x8664), "tooling"),
            ("nested/renamed-driver.cat", b"catalog", "temp"),
            (
                "licenses/mullvad-split-tunnel-MPL-2.0.txt",
                b"license",
                "app-license",
            ),
            ("licenses/README.txt", b"obsolete feature map", "app-license"),
        )
        for index, (path, data, dest) in enumerate(cases):
            with self.subTest(path=path):
                self.stage = self.root / f"stage-forbidden-split-{index}"
                self.stage.mkdir()
                entry = self.entry(path, data, dest=dest)
                if path.casefold() == "licenses/readme.txt":
                    marker = "obsolete kernel split-tunnel notice"
                elif pathlib.PurePosixPath(path).name.casefold().startswith(
                    "mullvad-split-tunnel"
                ):
                    marker = "withdrawn kernel split-tunnel artifact"
                else:
                    marker = "forbids kernel driver package files"
                self.assert_rejected(self.manifest([entry]), marker)

    def test_rejects_renamed_withdrawn_mullvad_kernel_split_bytes(self) -> None:
        for index, name in enumerate(WITHDRAWN_KERNEL_PAYLOADS):
            with self.subTest(name=name):
                self.stage = self.root / f"stage-renamed-split-{index}"
                self.stage.mkdir()
                entry = self.entry(
                    "drivers/neutral-name.bin",
                    git_dependency_bytes(name),
                )
                self.assert_rejected(
                    self.manifest([entry]),
                    "withdrawn kernel split-tunnel bytes, including when renamed",
                )

    def test_rejects_nested_withdrawn_mullvad_kernel_split_bytes(self) -> None:
        for index, name in enumerate(WITHDRAWN_KERNEL_PAYLOADS):
            with self.subTest(name=name):
                self.stage = self.root / f"stage-nested-split-{index}"
                self.stage.mkdir()
                entry = self.entry(
                    "assets/helper.bin",
                    wrap_payload(git_dependency_bytes(name)),
                )
                self.assert_rejected(
                    self.manifest([entry]),
                    "withdrawn kernel split-tunnel bytes, including when renamed",
                )

    def test_upstream_msi_runtime_hash_is_not_helper_hash(self) -> None:
        contract = dict(DEPENDENCY_CONTRACT)
        contract["amneziawg_msi_runtime_amneziawg_sha256"] = contract[
            "amneziawg_maintenance_helper_sha256"
        ]
        entry = self.entry("ordinary.bin")
        self.assert_rejected(
            self.manifest([entry], dependency_contract=contract),
            "amneziawg_msi_runtime_amneziawg_sha256",
        )

    def test_producer_rejects_stale_mixed_dependency_fixture(self) -> None:
        release = self.root / "release"
        release.mkdir()
        # An explicit, empty engine directory keeps this fixture independent of
        # the default build/windows/winn3/x64 output, which a clean checkout lacks.
        engines = self.root / "engines"
        engines.mkdir()
        mixed_dependencies = self.root / "mixed-dependencies"
        mixed_dependencies.mkdir()
        shutil.copy2(
            DEPENDENCIES / "VC_redist.x64.exe",
            mixed_dependencies / "VC_redist.x64.exe",
        )
        for name in (
            "amneziawg-amd64.msi",
            "amneziawg.exe",
            "awg.exe",
            "wintun.dll",
            "xray.exe",
        ):
            (mixed_dependencies / name).write_bytes(f"stale-{name}".encode("ascii"))
        result = subprocess.run(
            [
                PWSh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(BUILD_SCRIPT),
                "-ReleaseDir",
                str(release),
                "-DependenciesDir",
                str(mixed_dependencies),
                "-LicensesDir",
                str(LICENSES),
                "-EngineDir",
                str(engines),
                "-ThirdPartiesDoc",
                str(NOTICES),
                "-OutDir",
                str(self.root / "out"),
                "-SkipZip",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("Refusing to package stale or mixed Windows dependencies", output)
        self.assertIn("amneziawg-amd64.msi", output)

    def test_producer_has_no_v1_only_bypass_parameter(self) -> None:
        result = subprocess.run(
            [
                PWSh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(BUILD_SCRIPT),
                "-AllowMissingWinn3Carrier",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("AllowMissingWinn3Carrier", output)
        self.assertIn("cannot be found", output)

    def test_producer_rejects_output_name_traversal(self) -> None:
        result = subprocess.run(
            [
                PWSh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(BUILD_SCRIPT),
                "-AppVersion",
                "../../outside",
                "-SkipZip",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("AppVersion is not safe", output)

    def test_producer_rejects_release_directory_reparse_before_copy(self) -> None:
        release = self.root / "release-reparse"
        release.mkdir()
        outside = self.root / "outside-directory"
        outside.mkdir()
        (outside / "secret.txt").write_bytes(b"must-not-package")
        try:
            os.symlink(outside, release / "linked-directory", target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"directory symlinks unavailable: {exc}")
        destination = self.root / "copy-reparse"
        result = self.copy_release(release, destination)
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("reparse point", output)
        self.assertEqual(list(destination.rglob("*")), [])

    def test_producer_rejects_injected_mullvad_kernel_split_payload(self) -> None:
        cases = [
            (
                "mullvad-split-tunnel.sys",
                minimal_pe(0x8664),
                "withdrawn kernel split-tunnel artifact",
            ),
            (
                "mullvad-split-tunnel-arm64.inf",
                b"arm64 inf",
                "withdrawn kernel split-tunnel artifact",
            ),
        ]
        cases.extend(
            (
                f"neutral-{name}.bin",
                git_dependency_bytes(name),
                "including when renamed",
            )
            for name in WITHDRAWN_KERNEL_PAYLOADS
        )
        cases.extend(
            (
                f"nested-{name}.bin",
                wrap_payload(git_dependency_bytes(name)),
                "including when renamed",
            )
            for name in WITHDRAWN_KERNEL_PAYLOADS
        )
        for index, (name, data, marker) in enumerate(cases):
            with self.subTest(name=name):
                release = self.root / f"release-forbidden-split-{index}"
                (release / "nested").mkdir(parents=True)
                (release / "nested" / name).write_bytes(data)
                destination = self.root / f"copy-forbidden-split-{index}"
                result = self.copy_release(release, destination)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn(marker, output)
                self.assertEqual(list(destination.rglob("*")), [])

    def test_producer_rejects_filesystem_root_source(self) -> None:
        destination = self.root / "copy-root"
        result = self.copy_release(pathlib.Path(ROOT.anchor), destination)
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("filesystem-root container", output)
        self.assertEqual(list(destination.rglob("*")), [])

    def test_rejects_unknown_manifest_properties(self) -> None:
        entry = self.entry("ordinary.bin")
        manifest = self.manifest([entry])
        manifest["unexpected"] = True
        self.assert_rejected(manifest, "invalid property set")

    def test_safe_zip_extractor_rejects_zip_slip_before_writing(self) -> None:
        archive = self.root / "zip-slip.zip"
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("../escaped.txt", b"must-not-write")
        destination = self.root / "extract-slip"
        result = self.extract_zip(archive, destination)
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("dot segment", output)
        self.assertFalse((self.root / "escaped.txt").exists())
        self.assertEqual(list(destination.rglob("*")), [])

    def test_safe_zip_extractor_rejects_case_duplicates_and_symlinks(self) -> None:
        duplicate = self.root / "duplicate.zip"
        with zipfile.ZipFile(duplicate, "w") as package:
            package.writestr("data/file.bin", b"one")
            package.writestr("DATA/FILE.BIN", b"two")
        result = self.extract_zip(duplicate, self.root / "extract-duplicate")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("duplicate path", result.stdout + result.stderr)

        symlink = self.root / "symlink.zip"
        info = zipfile.ZipInfo("linked.bin")
        info.create_system = 3
        info.external_attr = (0o120777 << 16) | 0xA000
        with zipfile.ZipFile(symlink, "w") as package:
            package.writestr(info, b"../outside")
        result = self.extract_zip(symlink, self.root / "extract-symlink")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("symlink entries are forbidden", result.stdout + result.stderr)

    def test_safe_zip_extractor_accepts_contained_regular_files(self) -> None:
        archive = self.root / "contained.zip"
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("data/file.bin", b"contained")
        destination = self.root / "extract-contained"
        result = self.extract_zip(archive, destination)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((destination / "data/file.bin").read_bytes(), b"contained")

    def test_safe_zip_extractor_rejects_kernel_driver_package_members(self) -> None:
        for index, name in enumerate(
            ("mullvad-split-tunnel.sys", "nested/mullvad-split-tunnel-arm64.inf")
        ):
            with self.subTest(name=name):
                archive = self.root / f"forbidden-driver-{index}.zip"
                with zipfile.ZipFile(archive, "w") as package:
                    package.writestr(name, b"must-not-write")
                destination = self.root / f"extract-forbidden-driver-{index}"
                result = self.extract_zip(archive, destination)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn("withdrawn kernel split-tunnel", output)
                self.assertEqual(list(destination.rglob("*")), [])

    def test_safe_zip_extractor_rejects_renamed_and_nested_kernel_payload_bytes(self) -> None:
        cases = []
        for name in WITHDRAWN_KERNEL_PAYLOADS:
            payload = git_dependency_bytes(name)
            cases.append((f"renamed-{name}.bin", payload))
            cases.append((f"nested/wrapped-{name}.bin", wrap_payload(payload)))
        for index, (member, data) in enumerate(cases):
            with self.subTest(member=member):
                archive = self.root / f"forbidden-bytes-{index}.zip"
                with zipfile.ZipFile(archive, "w") as package:
                    package.writestr(member, data)
                destination = self.root / f"extract-forbidden-bytes-{index}"
                result = self.extract_zip(archive, destination)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn("including when renamed", output)
                self.assertEqual(list(destination.rglob("*")), [])

    def test_safe_zip_extractor_normalizes_powershell_51_separators(self) -> None:
        archive = self.root / "powershell-51-separators.zip"
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("data\\file.bin", b"contained")
        destination = self.root / "extract-powershell-51"
        result = self.extract_zip(archive, destination)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((destination / "data/file.bin").read_bytes(), b"contained")

        traversal = self.root / "powershell-51-traversal.zip"
        with zipfile.ZipFile(traversal, "w") as package:
            package.writestr("..\\escaped.txt", b"must-not-write")
        traversal_destination = self.root / "extract-powershell-51-traversal"
        result = self.extract_zip(traversal, traversal_destination)
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("dot segment", output)
        self.assertFalse((self.root / "escaped.txt").exists())
        self.assertEqual(list(traversal_destination.rglob("*")), [])

    def run_producer(
        self, env_overrides: dict[str, str], *args: str
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        env = dict(os.environ)
        for name in SIGNING_ENVIRONMENT:
            env.pop(name, None)
        env["NO_COLOR"] = "1"
        env.update(env_overrides)
        result = subprocess.run(
            [
                PWSh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(BUILD_SCRIPT),
                "-AppVersion",
                "0.0.0",
                # SE-01: the ZIP itself is refused; payload staging still validates.
                "-SkipZip",
                *args,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
            env=env,
        )
        return result, flatten_ps(result.stdout + result.stderr)

    def test_producer_resolves_signing_identity_instead_of_refusing_it(self) -> None:
        cases = (
            (
                {"WINS_WINDOWS_SIGN_PFX": str(self.root / "evil.pfx")},
                (),
                "PFX command-line signing (WINS_WINDOWS_SIGN_PFX/WINS_WINDOWS_SIGN_PFX_PASSWORD) is disabled",
            ),
            (
                {"WINS_WINDOWS_SIGN_CERT_SHA1": "A" * 40},
                (),
                "WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required for a signed release.",
            ),
            (
                {
                    "WINS_WINDOWS_SIGN_CERT_SHA1": "A" * 40,
                    "WINS_WINDOWS_SIGNER_SUBJECT_REGEX": "^CN=Example",
                    "WINS_WINDOWS_TIMESTAMP_URL": "https://evil.example/ts /f C:\\pwn.pfx",
                },
                (),
                "exact approved Microsoft/DigiCert RFC 3161 endpoint",
            ),
            ({}, ("-RequireCodeSigning",), "Windows release signing is required."),
        )
        for env, args, marker in cases:
            with self.subTest(env=sorted(env), args=args):
                result, output = self.run_producer(env, *args)
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn(marker, output)
                self.assertNotIn("unsigned by contract", output)
                self.assertNotIn("refusing to mix signing credentials", output)
        result, output = self.run_producer({})
        self.assertIn("this is an unsigned rehearsal ZIP", output)
        self.assertNotIn("unsigned by contract", output)

    def test_producer_rejects_argument_injection_in_paths_and_version(self) -> None:
        for version in ("0.0.0;calc", "0.0.0$(id)", "0.0.0|whoami", "0.0.0`n1"):
            with self.subTest(version=version):
                result = subprocess.run(
                    [
                        PWSh,
                        "-NoProfile",
                        "-NonInteractive",
                        "-File",
                        str(BUILD_SCRIPT),
                        "-AppVersion",
                        version,
                        "-SkipZip",
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn("AppVersion is not safe", output)
        result = subprocess.run(
            [
                PWSh,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(BUILD_SCRIPT),
                "-OutDir",
                str(self.root / "out*side"),
                "-SkipZip",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("forbidden path or argument character", output)

    def test_producer_arm64_is_gated_by_real_pins_not_an_owner_refusal(self) -> None:
        result = self.invoke(
            "Initialize-ZipArchitectureContract -Architecture arm64; "
            "if ($null -ne $ZipDependencyPins['amneziawg.exe']) { throw 'invented helper pin' }; "
            "if ($ZipDependencyPins['amneziawg-arm64.msi'].sha256 -cne "
            "'3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa') { throw 'arm64 MSI pin moved' }"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Inputs that hash to the arm64 pin table are accepted end to end.
        deps = self.root / "arm64-deps"
        deps.mkdir()
        rebind = []
        for index, name in enumerate(
            ("VC_redist.arm64.exe", "amneziawg-arm64.msi", "awg.exe", "wintun.dll", "xray.exe")
        ):
            data = f"arm64 fixture {index}".encode()
            (deps / f"fixture-{index}.bin").write_bytes(data)
            rebind.append(
                f"$ZipDependencyPins['{name}'] = [ordered]@{{ source = 'fixture-{index}.bin'; "
                f"sha256 = '{sha256(data)}'; dest = $ZipDependencyPins['{name}'].dest }}"
            )
        call = (
            "Initialize-ZipArchitectureContract -Architecture arm64; "
            f"$DependenciesDir = {ps_single(deps)}; "
            + "; ".join(rebind)
            + "; Assert-ZipDependencyInputs; Write-Output 'ARM64-INPUTS-ACCEPTED'"
        )
        # Every other ARM64 input matches its pin, but the table has no
        # reviewed amneziawg.exe helper pin, so the producer refuses plainly
        # instead of shipping a ZIP that cannot connect over Winn v1.
        output = self.assert_invoke_rejected(
            call,
            "Missing pin: the arm64 ZIP requires its app-owned amneziawg.exe maintenance helper.",
        )
        self.assertIn("Get-FileHash -Algorithm SHA256", output)
        self.assertNotIn("ARM64-INPUTS-ACCEPTED", output)
        self.assertNotIn("owner-blocked", output)
        # The real pin refuses any amneziawg-arm64.msi that is not the reviewed 3aec0238
        # MSI: the previously committed 1699f9e6 file (its bytes are no longer in the tree,
        # so a fixture stands in for it and for anything else unreviewed), and the committed
        # file is the reviewed one (a fixture helper pin is injected in the harness only, to
        # reach that check).
        helper = minimal_pe(0xAA64) + b"arm64 helper fixture"
        (deps / "amneziawg-arm64.exe").write_bytes(helper)
        unreviewed = b"unreviewed arm64 msi fixture"
        (deps / "amneziawg-arm64.msi").write_bytes(unreviewed)
        msi_call = (
            "Initialize-ZipArchitectureContract -Architecture arm64; "
            f"$DependenciesDir = {ps_single(deps)}; "
            "$ZipDependencyPins['amneziawg-arm64.msi'] = [ordered]@{ source = 'amneziawg-arm64.msi'; "
            "sha256 = '3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa'; dest = 'temp' }; "
            "$ZipDependencyPins['amneziawg.exe'] = [ordered]@{ source = 'amneziawg-arm64.exe'; "
            f"sha256 = '{sha256(helper)}'; dest = 'app' }}; "
            "foreach ($k in @($ZipDependencyPins.Keys)) { if ($k -cnotin @('amneziawg-arm64.msi', 'amneziawg.exe')) { $ZipDependencyPins.Remove($k) } }; "
            "Assert-ZipDependencyInputs"
        )
        output = self.assert_invoke_rejected(
            msi_call,
            "Pinned dependency amneziawg-arm64.msi has SHA-256 "
            f"{sha256(unreviewed)}; expected "
            "3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa",
        )
        self.assertNotIn("owner-blocked", output)
        self.assertNotIn("Missing pin", output)
        (deps / "amneziawg-arm64.msi").write_bytes(git_dependency_bytes("amneziawg-arm64.msi"))
        output = self.assert_invoke_rejected(
            msi_call, "The rebuilt AmneziaWG maintenance-helper provenance is missing."
        )
        self.assertNotIn("Pinned dependency amneziawg-arm64.msi has SHA-256", output)

    def test_producer_arm64_with_a_harness_helper_pin_proceeds_to_helper_provenance(
        self,
    ) -> None:
        deps = self.root / "arm64-pinned-deps"
        deps.mkdir()
        rebind = []
        for index, name in enumerate(
            ("VC_redist.arm64.exe", "amneziawg-arm64.msi", "awg.exe", "wintun.dll", "xray.exe")
        ):
            data = f"arm64 fixture {index}".encode()
            (deps / f"fixture-{index}.bin").write_bytes(data)
            rebind.append(
                f"$ZipDependencyPins['{name}'] = [ordered]@{{ source = 'fixture-{index}.bin'; "
                f"sha256 = '{sha256(data)}'; dest = $ZipDependencyPins['{name}'].dest }}"
            )
        helper = minimal_pe(0xAA64) + b"arm64 helper fixture"
        (deps / "amneziawg-arm64.exe").write_bytes(helper)
        # Test harness only: the fixture helper pin lives in this process's
        # copy of the ARM64 table, never in the committed producer.
        rebind.append(
            "$ZipDependencyPins['amneziawg.exe'] = [ordered]@{ source = 'amneziawg-arm64.exe'; "
            f"sha256 = '{sha256(helper)}'; dest = 'app' }}"
        )
        prefix = (
            "Initialize-ZipArchitectureContract -Architecture arm64; "
            f"$DependenciesDir = {ps_single(deps)}; "
            + "; ".join(rebind)
            + "; "
        )
        # Past the missing-pin check, the real helper provenance contract runs
        # against the injected pin and refuses the absent ARM64 provenance.
        output = self.assert_invoke_rejected(
            prefix + "Assert-ZipDependencyInputs",
            "The rebuilt AmneziaWG maintenance-helper provenance is missing.",
        )
        self.assertNotIn("Missing pin", output)
        recorder = (
            "function script:Assert-WindowsAwgSchema2OwnerPublicationContract { "
            "param($ProvenancePath, $HelperPath, $ExpectedUnsignedSha256, $ExpectedTarget) "
            "Write-Output ('CONTRACT ' + [IO.Path]::GetFileName($ProvenancePath) + ' ' + "
            "[IO.Path]::GetFileName($HelperPath) + ' ' + $ExpectedUnsignedSha256 + ' ' + $ExpectedTarget) }; "
        )
        result = self.invoke(
            prefix + recorder + "Assert-ZipDependencyInputs; Write-Output 'ARM64-INPUTS-ACCEPTED'"
        )
        output = flatten_ps(result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, output)
        self.assertIn(
            "CONTRACT amneziawg-arm64.exe.provenance.json amneziawg-arm64.exe "
            f"{sha256(helper)} windows-arm64",
            output,
        )
        self.assertIn("ARM64-INPUTS-ACCEPTED", output)
        self.assertNotIn("Missing pin", output)
        # A helper whose bytes miss the injected pin is still refused.
        (deps / "amneziawg-arm64.exe").write_bytes(helper + b"tampered")
        self.assert_invoke_rejected(
            prefix + recorder + "Assert-ZipDependencyInputs",
            "Pinned dependency amneziawg-arm64.exe has SHA-256",
        )

    def test_engine_dir_reparse_and_path_injection_are_refused(self) -> None:
        engines = self.root / "engines"
        engines.mkdir()
        outside = self.root / "outside-engine.exe"
        outside.write_bytes(carrying_pe())
        linked = engines / "winn-datapath.exe"
        try:
            os.symlink(outside, linked)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        stage = self.root / "engine-stage"
        stage.mkdir()
        self.assert_invoke_rejected(
            f"Copy-ZipEnginePayloads -EngineRoot {ps_single(engines)} -StageRoot {ps_single(stage)}",
            "reparse point",
        )
        self.assertEqual(list(stage.iterdir()), [])
        self.assert_invoke_rejected(
            "Assert-SafeZipPathArgument -Path 'C:\\stage|evil' -Name 'EngineDir'",
            "forbidden path or argument character",
        )

    def test_v3_primary_requires_awg_then_xray_then_product(self) -> None:
        stage = self.root / "carrier-stage"
        stage.mkdir()
        (stage / "winn-datapath.exe").write_bytes(carrying_pe())
        (stage / "winsvpn_winn3_engine.exe").write_bytes(minimal_pe(0x8664))
        (stage / "winsvpn_awg_engine.exe").write_bytes(minimal_pe(0x8664))
        (stage / "wins_vpn.exe").write_bytes(minimal_pe(0x8664))
        (stage / "wins_vpn_tunnel_service.exe").write_bytes(minimal_pe(0x8664))
        deps = stage / "dependencies"
        deps.mkdir()
        (deps / "awg.exe").write_bytes(minimal_pe(0x8664))
        output = self.assert_invoke_rejected(
            f"Test-Winn3CarrierCompleteness -StageRoot {ps_single(stage)}",
            "Winn v1 Xray fallback is required",
        )
        self.assertIn("Refusing to produce a v1-only zip", output)
        self.assertIn("dependencies/xray.exe", output)
        (deps / "xray.exe").write_bytes(minimal_pe(0x8664))
        (stage / "wins_vpn_tunnel_service.exe").unlink()
        output = self.assert_invoke_rejected(
            f"Test-Winn3CarrierCompleteness -StageRoot {ps_single(stage)}",
            "wins_vpn_tunnel_service.exe was not",
        )
        self.assertNotIn("Winn v1 Xray fallback is required", output)
        (stage / "wins_vpn_tunnel_service.exe").write_bytes(minimal_pe(0x8664))
        result = self.invoke(
            f"Test-Winn3CarrierCompleteness -StageRoot {ps_single(stage)}"
        )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, combined)
        self.assertIn("Winn v1 AWG then Xray fallback payloads are present", combined)

    def test_unsigned_engine_then_product_ordering_refuses_signed_first_party_pe(self) -> None:
        stage = self.root / "signed-stage"
        stage.mkdir()
        (stage / "winn-datapath.exe").write_bytes(carrying_pe())
        (stage / "winsvpn_winn3_engine.exe").write_bytes(minimal_pe(0x8664))
        (stage / "winsvpn_awg_engine.exe").write_bytes(minimal_pe(0x8664))
        (stage / "wins_vpn.exe").write_bytes(pe_with_certificate_table())
        (stage / "wins_vpn_tunnel_service.exe").write_bytes(minimal_pe(0x8664))
        deps = stage / "dependencies"
        deps.mkdir()
        (deps / "xray.exe").write_bytes(minimal_pe(0x8664))
        output = self.assert_invoke_rejected(
            f"Assert-ZipUnsignedEngineProductOrdering -StageRoot {ps_single(stage)}",
            "Signed product payloads with unsigned first-party engines",
        )
        self.assertIn("wins_vpn.exe", output)
        (stage / "winn-datapath.exe").write_bytes(pe_with_certificate_table())
        (stage / "wins_vpn.exe").write_bytes(minimal_pe(0x8664))
        output = self.assert_invoke_rejected(
            f"Assert-ZipUnsignedEngineProductOrdering -StageRoot {ps_single(stage)}",
            "Signed first-party engines with unsigned product payloads",
        )
        self.assertIn("winn-datapath.exe", output)

    def test_signed_state_signs_engines_then_product_and_leaves_pins_alone(self) -> None:
        stage = self.root / "signed-plan-stage"
        stage.mkdir()
        for name in (
            "winn-datapath.exe",
            "winsvpn_winn3_engine.exe",
            "winsvpn_awg_engine.exe",
            "wins_vpn.exe",
            "wins_vpn_tunnel_service.exe",
            "flutter_windows.dll",
        ):
            (stage / name).write_bytes(minimal_pe(0x8664))
        deps = stage / "dependencies"
        deps.mkdir()
        for name in ("xray.exe", "awg.exe", "amneziawg.exe", "wintun.dll"):
            (deps / name).write_bytes(minimal_pe(0x8664))
        result = self.invoke(
            f"(@(Get-ZipSignedPayloadPlan -StageRoot {ps_single(stage)}) -join ',')"
        )
        output = (result.stdout + result.stderr).strip()
        self.assertEqual(result.returncode, 0, output)
        self.assertIn(
            "winn-datapath.exe,winsvpn_winn3_engine.exe,winsvpn_awg_engine.exe,"
            "flutter_windows.dll,wins_vpn.exe,wins_vpn_tunnel_service.exe",
            output,
        )
        self.assertNotIn("dependencies/", output)
        fake = (
            "$script:ZipSigning = [pscustomobject]@{ SignerPattern = '^CN=Example'; "
            "SignTool = 'signtool.exe'; LeafSha256Pin = '' }; "
            "function script:Assert-WinsProducerSignature { param($Path, $SignerPattern, $SignTool, "
            "$ExpectedLeafSha256) Write-Host ('VERIFIED ' + [IO.Path]::GetFileName($Path)) }; "
        )
        output = self.assert_invoke_rejected(
            fake + f"Assert-ZipEngineProductSigningState -StageRoot {ps_single(stage)}",
            "Signed ZIP left first-party payloads without an Authenticode signature",
        )
        self.assertIn("winn-datapath.exe", output)
        for name in (
            "winn-datapath.exe",
            "winsvpn_winn3_engine.exe",
            "winsvpn_awg_engine.exe",
            "flutter_windows.dll",
            "wins_vpn.exe",
        ):
            (stage / name).write_bytes(pe_with_certificate_table())
        output = self.assert_invoke_rejected(
            fake + f"Assert-ZipEngineProductSigningState -StageRoot {ps_single(stage)}",
            "without an Authenticode signature: wins_vpn_tunnel_service.exe",
        )
        (stage / "wins_vpn_tunnel_service.exe").write_bytes(pe_with_certificate_table())
        result = self.invoke(
            fake + f"Assert-ZipEngineProductSigningState -StageRoot {ps_single(stage)}"
        )
        output = flatten_ps(result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, output)
        for name in (
            "winn-datapath.exe",
            "winsvpn_winn3_engine.exe",
            "winsvpn_awg_engine.exe",
            "flutter_windows.dll",
            "wins_vpn.exe",
            "wins_vpn_tunnel_service.exe",
        ):
            self.assertIn("VERIFIED " + name, output)
        self.assertNotIn("VERIFIED xray.exe", output)
        self.assertNotIn("VERIFIED amneziawg.exe", output)
        # Without an identity, already-signed first-party inputs are refused:
        # this producer only ships signatures it applied and verified itself.
        for name in ("xray.exe", "amneziawg.exe"):
            (deps / name).write_bytes(pe_with_certificate_table())
        self.assert_invoke_rejected(
            f"Assert-ZipEngineProductSigningState -StageRoot {ps_single(stage)}",
            "no signing identity is configured to verify them",
        )

    def test_receipt_reaudit_records_signing_state_truthfully(self) -> None:
        archive = self.root / "receipt.zip"
        archive.write_bytes(b"zip bytes")
        digest = sha256(b"zip bytes")
        receipt = self.root / "receipt.zip.receipt.json"

        def write(status: str, verified: bool, payloads: int, timestamp: bool | None = None) -> None:
            receipt.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "contract": "winsvpn-windows-zip-artifact-receipt-v1",
                        "architecture": "x64",
                        "route": "zip-plus-powershell",
                        "store_upload_authorized": False,
                        "authenticode_status": status,
                        "authenticode_verified": verified,
                        "timestamp_verified": verified if timestamp is None else timestamp,
                        "signed_payloads": [{"path": f"p{i}"} for i in range(payloads)],
                        "winn_v3_primary": True,
                        "winn_v1_awg_then_xray": True,
                        "zip": {"sha256": digest},
                    }
                ),
                encoding="utf-8",
            )

        check = (
            f"Assert-ZipReceiptMatchesArtifact -ZipPath {ps_single(archive)} "
            f"-ReceiptPath {ps_single(receipt)} -ExpectedSha256 '{digest}'; Write-Output 'RECEIPT-OK'"
        )
        signed = (
            "$script:ZipSigning = [pscustomobject]@{ Mode = 'certificate-store' }; "
            "[void]$script:ZipSignatureEvidence.Add(@{ path = 'wins_vpn.exe' }); "
        )
        write("unsigned", False, 0)
        result = self.invoke(check)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RECEIPT-OK", result.stdout)
        self.assert_invoke_rejected(signed + check, "does not match the signed v3-primary")
        write("signed", True, 1)
        result = self.invoke(signed + check)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RECEIPT-OK", result.stdout)
        self.assert_invoke_rejected(check, "does not match the unsigned v3-primary")
        write("signed", False, 1)
        self.assert_invoke_rejected(signed + check, "does not match the signed v3-primary")
        write("signed", True, 0)
        self.assert_invoke_rejected(signed + check, "does not match the signed v3-primary")
        write("signed", True, 1, timestamp=False)
        self.assert_invoke_rejected(signed + check, "does not match the signed v3-primary")
        write("unsigned", False, 0, timestamp=True)
        self.assert_invoke_rejected(check, "does not match the unsigned v3-primary")

    def test_staged_pe_machines_reject_mixed_architecture_payload(self) -> None:
        stage = self.root / "mixed-pe"
        stage.mkdir()
        (stage / "wins_vpn.exe").write_bytes(minimal_pe(0xAA64))
        self.assert_invoke_rejected(
            f"Assert-StagedPeMachines -StageRoot {ps_single(stage)}",
            "PE/COFF machine 0xaa64",
        )

    def test_relative_paths_and_zip_inventory_are_ordinal_sorted_and_stable(self) -> None:
        stage = self.root / "sorted-stage"
        stage.mkdir()
        (stage / "z.bin").write_bytes(b"z")
        nested = stage / "a"
        nested.mkdir()
        (nested / "b.bin").write_bytes(b"b")
        (stage / "m.bin").write_bytes(b"m")
        result = self.invoke(
            f"$paths = @(Get-RelativePaths -Root {ps_single(stage)}); "
            "$paths -join ','"
        )
        output = (result.stdout + result.stderr).strip()
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("a/b.bin,m.bin,z.bin", output.replace("\r", ""))
        zip_one = self.root / "one.zip"
        zip_two = self.root / "two.zip"
        result = self.invoke(
            f"New-DeterministicZipArchive -StageRoot {ps_single(stage)} -ZipPath {ps_single(zip_one)}; "
            f"New-DeterministicZipArchive -StageRoot {ps_single(stage)} -ZipPath {ps_single(zip_two)}; "
            f"Assert-ZipArchiveInventory -ZipPath {ps_single(zip_one)}"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sha256(zip_one.read_bytes()), sha256(zip_two.read_bytes()))
        with zipfile.ZipFile(zip_one) as package:
            names = [info.filename for info in package.infolist()]
            self.assertEqual(names, sorted(names))
            self.assertEqual(names, ["a/b.bin", "m.bin", "z.bin"])
            for info in package.infolist():
                self.assertEqual(info.date_time[0], 1980)
                self.assertFalse(info.is_dir())

    def test_partial_outputs_are_removed_after_failure(self) -> None:
        zip_path = self.root / "partial.zip"
        sha_path = self.root / "partial.zip.sha256"
        receipt = self.root / "partial.zip.receipt.json"
        zip_path.write_bytes(b"partial")
        sha_path.write_text("deadbeef  partial.zip\n", encoding="ascii")
        receipt.write_text("{}", encoding="ascii")
        output = self.assert_invoke_rejected(
            f"Reset-ZipPartialOutputs; "
            f"Register-ZipPartialOutput -Path {ps_single(zip_path)}; "
            f"Register-ZipPartialOutput -Path {ps_single(sha_path)}; "
            f"Register-ZipPartialOutput -Path {ps_single(receipt)}; "
            "try { throw 'simulated zip failure' } catch { Remove-ZipPartialOutputs; throw }",
            "simulated zip failure",
        )
        self.assertFalse(zip_path.exists(), output)
        self.assertFalse(sha_path.exists(), output)
        self.assertFalse(receipt.exists(), output)

    def test_post_build_reaudit_rejects_zip_missing_v3_and_fallback(self) -> None:
        stage = self.root / "reaudit-stage"
        stage.mkdir()
        payload = b"no-carrier"
        (stage / "ordinary.bin").write_bytes(payload)
        (stage / "payload-manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "route": "zip-plus-powershell",
                    "architecture": "x64",
                    "file_count": 1,
                    "files": [
                        {
                            "path": "ordinary.bin",
                            "bytes": len(payload),
                            "sha256": sha256(payload),
                            "dest": "app",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        archive = self.root / "reaudit.zip"
        result = self.invoke(
            f"New-DeterministicZipArchive -StageRoot {ps_single(stage)} -ZipPath {ps_single(archive)}; "
            f"Test-ZipRoundTrip -ZipPath {ps_single(archive)} -ReauditPayloadIdentity"
        )
        output = flatten_ps(result.stdout + result.stderr)
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("winn-datapath.exe was not", output)
        self.assertIn("Winn v1 AWG fallback is required", output)
        self.assertIn("Winn v1 Xray fallback is required", output)


class WindowsZipRouteSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build = BUILD_SCRIPT.read_text(encoding="utf-8")
        cls.install = INSTALL_SCRIPT.read_text(encoding="utf-8")

    def test_exact_dependency_pins_are_independent_of_manifest(self) -> None:
        for value in DEPENDENCY_CONTRACT.values():
            self.assertIn(value, self.build)
            self.assertIn(value, self.install)

    def test_every_zip_requires_v3_and_strict_manifest_v2(self) -> None:
        self.assertNotIn("[switch]$AllowMissingWinn3Carrier", self.build)
        self.assertIn("Refusing to produce a v1-only zip", self.build)
        self.assertIn("schema_version = 2", self.build)
        self.assertIn("[int]$manifest.schema_version -ne 2", self.install)
        self.assertIn("function Expand-SafeZipArchive", self.build)
        self.assertNotIn("Expand-Archive", self.build)
        self.assertIn("function New-DeterministicZipArchive", self.build)
        self.assertNotRegex(self.build, r"(?m)^\s*Compress-Archive\b")
        self.assertIn("Winn v1 AWG then Xray fallback payloads are present", self.build)
        self.assertIn("dependencies/xray.exe was not staged; Winn v1 Xray fallback is required", self.build)
        self.assertIn("winsvpn_awg_engine.exe was not staged; Winn v1 AWG fallback is required", self.build)

    def test_producer_boundary_hardening_is_wired(self) -> None:
        self.assertIn("function Assert-ZipUnsignedEngineProductOrdering", self.build)
        self.assertIn("function Remove-ZipPartialOutputs", self.build)
        self.assertIn("function Invoke-ZipExtractedPayloadReaudit", self.build)
        self.assertIn("function Assert-SafeZipPathArgument", self.build)
        self.assertIn("function Copy-ZipEnginePayloads", self.build)
        self.assertIn("function Copy-ZipPinnedDependencies", self.build)
        self.assertIn("function Get-PeCertificateTableSize", self.build)
        self.assertIn("-ReauditPayloadIdentity", self.build)
        self.assertIn("ZIP inventory is not ordinal-sorted", self.build)
        begin = "# BEGIN-WINDOWS-PRODUCER-AUTHENTICODE-POLICY"
        end = "# END-WINDOWS-PRODUCER-AUTHENTICODE-POLICY"
        self.assertEqual(self.build.count(begin), 1)
        outside = (
            self.build[: self.build.index(begin)]
            + self.build[self.build.index(end) + len(end) :]
        )
        # SignTool and Authenticode verification run only through the shared
        # build_installer.ps1-equivalent policy block.
        self.assertNotIn("signtool.exe", outside.casefold())
        self.assertNotRegex(outside, r"(?i)&\s*\(?\s*(\[string\])?\$\S*signtool")
        self.assertNotIn("Get-AuthenticodeSignature", outside)
        self.assertIn("Invoke-WinsProducerSigning -Path $full -Signing $script:ZipSigning", outside)
        self.assertNotIn("Invoke-ProductSigning", self.build)
        self.assertNotIn("Assert-ZipAuthenticodePreconditions", self.build)
        self.assertNotIn("OWNER-BLOCKED", self.build)
        self.assertNotIn("publication_authorized", self.build)
        self.assertLess(
            self.build.index("$ZipFirstPartyEnginePaths ="),
            self.build.index("$ZipFirstPartyProductPaths ="),
        )
        unsigned = self.build[
            self.build.index("function Assert-ZipUnsignedEngineProductOrdering") : self.build.index(
                "function Assert-StagedDependencyPins"
            )
        ]
        self.assertLess(
            unsigned.index("Get-ZipFirstPartyEnginePaths"),
            unsigned.index("ZipFirstPartyProductPaths"),
        )
        self.assertIn("engine then product signing", unsigned)

    def test_reserved_prefixes_and_container_roots_are_normalized(self) -> None:
        for source in (self.build, self.install):
            self.assertIn("Assert-CanonicalReservedPayloadPath", source)
            self.assertIn("$pathRootTrimmed = $pathRoot.TrimEnd", source)
            self.assertIn("[StringComparison]::OrdinalIgnoreCase", source)
        self.assertNotIn(
            "Get-ChildItem -LiteralPath $ReleaseDir -Force -ErrorAction SilentlyContinue | Copy-Item",
            self.build,
        )
        self.assertIn("Copy-ContainedDirectoryFiles -SourceRoot $ReleaseDir", self.build)

    def test_mullvad_kernel_split_is_forbidden_not_pinned_or_advertised(self) -> None:
        build_pins = self.build[
            self.build.index("$ZipDependencyPins =") : self.build.index(
                "$ZipDependencyContract ="
            )
        ]
        build_contract = self.build[
            self.build.index("$ZipDependencyContract =") : self.build.index(
                "$ZipLicenseFiles ="
            )
        ]
        build_licenses = self.build[
            self.build.index("$ZipLicenseFiles =") : self.build.index(
                "$ForbiddenZipPayloadLeafNames ="
            )
        ]
        install_pins = self.install[
            self.install.index("$ExpectedDependencyPins =") : self.install.index(
                "$ExpectedDependencyContract ="
            )
        ]
        install_contract = self.install[
            self.install.index("$ExpectedDependencyContract =") : self.install.index(
                "$ForbiddenZipPayloadLeafNames ="
            )
        ]
        required = self.install[
            self.install.index("$RequiredPayloadPaths =") : self.install.index(
                "function Out-Step"
            )
        ]
        for block in (build_pins, build_contract, install_pins, install_contract, required):
            self.assertNotIn("split_driver", block)
            self.assertNotIn("split_catalog", block)
            self.assertNotIn("split_inf", block)
            self.assertNotIn("mullvad-split-tunnel.sys", block)
            self.assertNotIn("mullvad-split-tunnel.cat", block)
            self.assertNotIn("mullvad-split-tunnel.inf", block)
            self.assertNotIn("mullvad-split-tunnel-MPL-2.0.txt", block)
            self.assertNotIn(
                "10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201",
                block,
            )
        self.assertNotIn("'licenses/README.txt',", required)
        self.assertNotIn("mullvad-split-tunnel", build_licenses.casefold())
        self.assertNotIn("README.txt", build_licenses)
        self.assertIn("$ZipLicenseFiles =", self.build)
        self.assertNotIn(
            "Get-ChildItem -LiteralPath $LicensesDir -File", self.build
        )
        self.assertIn("Assert-ZipPayloadAllowed", self.build)
        self.assertIn("Assert-ZipPayloadAllowed", self.install)
        self.assertIn("Assert-ZipPayloadHashAllowed", self.build)
        self.assertIn("Assert-ZipPayloadHashAllowed", self.install)
        self.assertIn("Assert-ZipPayloadBytesAllowed", self.build)
        self.assertIn("Assert-ZipPayloadBytesAllowed", self.install)
        self.assertIn("$ForbiddenZipPayloadFingerprints =", self.build)
        self.assertIn("$ForbiddenZipPayloadFingerprints =", self.install)
        for digest in WITHDRAWN_KERNEL_PAYLOAD_SHA256.values():
            self.assertIn(digest, self.build)
            self.assertIn(digest, self.install)
        self.assertIn("$ForbiddenZipPayloadExtensions = @('.sys', '.cat', '.inf')", self.build)
        self.assertIn("$ForbiddenZipPayloadExtensions = @('.sys', '.cat', '.inf')", self.install)

    def test_installer_verifies_before_elevation(self) -> None:
        verify = self.install.index("$manifest = Test-PayloadManifest -Stage $StageDir")
        elevation = self.install.index("Assert-Elevated", verify)
        first_write = self.install.index("New-Item -ItemType Directory -Path $InstallDir", elevation)
        self.assertLess(verify, elevation)
        self.assertLess(elevation, first_write)

    def test_self_test_has_runtime_but_precedes_service_and_payload_mutation(self) -> None:
        vc_gate = self.install.index("if (-not (Test-VcRuntimeInstalledAtLeastRequired))")
        msi_gate = self.install.index("if (-not (Test-AmneziaWgRuntimeInstalled -Manifest $manifest))")
        self_test = self.install.index("staged tunnel manager --protocol-self-test", msi_gate)
        service_state = self.install.index("$state = [ordered]@", self_test)
        payload_copy = self.install.index("Copy-ManifestFile -Entry $entry", service_state)
        service_install = self.install.index("new tunnel manager --install", payload_copy)
        installed_v3 = self.install.index("$installedDatapath =", payload_copy)
        self.assertLess(vc_gate, msi_gate)
        self.assertLess(msi_gate, self_test)
        self.assertLess(self_test, service_state)
        self.assertLess(installed_v3, service_install)


if __name__ == "__main__":
    unittest.main()
