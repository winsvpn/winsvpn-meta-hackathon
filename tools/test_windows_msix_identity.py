#!/usr/bin/env python3
"""Hostile contracts for the Windows MSIX producer identity boundary."""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import windows_cross_store_artifact_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGER_PATH = ROOT / "installer/windows/build_store_msix.ps1"
TEMPLATE = (
    ROOT / "installer/windows/store/AppxManifest.xml.template"
).read_text(encoding="utf-8")
PACKAGER = PACKAGER_PATH.read_text(encoding="utf-8")
PWSH = shutil.which("pwsh") or shutil.which("powershell")

_PUBSPEC_VERSION = re.search(
    r"(?m)^version:\s*(\d+)\.(\d+)\.(\d+)\+(\d+)\s*$",
    (ROOT / "pubspec.yaml").read_text(encoding="utf-8"),
)
assert _PUBSPEC_VERSION is not None
PUBSPEC_SOURCE_VERSION = "{}.{}.{}+{}".format(*_PUBSPEC_VERSION.groups())
PUBSPEC_PACKAGE_VERSION = ".".join(_PUBSPEC_VERSION.groups())
CANONICAL_MSIX = f"WinsVPN-Store-{PUBSPEC_PACKAGE_VERSION}-x64.msix"
PARTNER_CENTER_X64 = "WinsVPN-PartnerCenter.exe"
PARTNER_CENTER_ARM64 = "WinsVPN-PartnerCenter-arm64.exe"
WEBSITE_X64 = "WinsVPN-Setup.exe"
WEBSITE_ARM64 = "WinsVPN-Setup-arm64.exe"
SIGNING_ENVIRONMENT = (
    "WINS_WINDOWS_ARTIFACT_SIGNING_METADATA",
    "WINS_WINDOWS_SIGN_CERT_SHA1",
    "WINS_WINDOWS_SIGN_CERT_STORE",
    "WINS_WINDOWS_SIGN_PFX",
    "WINS_WINDOWS_SIGN_PFX_PASSWORD",
    "WINS_WINDOWS_SIGNER_SUBJECT_REGEX",
    "WINS_WINDOWS_TIMESTAMP_URL",
)
SIGNING_BEGIN = "# BEGIN-WINDOWS-PRODUCER-AUTHENTICODE-POLICY"
SIGNING_END = "# END-WINDOWS-PRODUCER-AUTHENTICODE-POLICY"
IDENTITY_HARNESS = r"""
param([string]$Packager, [string]$Pubspec, [string]$Call)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Packager, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @('Assert-MsixSafeToken', 'Assert-MsixIdentityContract', 'Read-MsixPubspecReleaseIdentity')) {
    $definitions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true))
    if ($definitions.Count -ne 1) { throw "Expected one function $name" }
    Set-Item -Path ("Function:\script:" + $name) -Value $definitions[0].Body.GetScriptBlock()
}
foreach ($variableName in @(
    'PubspecReleaseIdentity', 'CanonicalSourceVersion', 'CanonicalPackageVersion',
    'CanonicalMsixArchitecture', 'CanonicalMsixFilename', 'DevelopmentIdentityName',
    'DevelopmentPublisher', 'DevelopmentPublisherDisplayName'
)) {
    $target = '$' + $variableName
    $assignments = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq $target
    }, $true))
    if ($assignments.Count -ne 1) { throw "Expected one assignment for $target" }
    Set-Variable -Scope Script -Name $variableName -Value (& ([scriptblock]::Create($assignments[0].Right.Extent.Text)))
}
& ([scriptblock]::Create($Call))
"""


SIGNATURE_STATE_HARNESS = r"""
param([string]$Packager, [string]$VerifyRoot, [string]$Mode)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Packager, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @('Assert-MsixPackageSignatureState', 'Assert-MsixPackageSigned', 'Assert-MsixPackageUnsigned', 'Get-MsixSigningPlan')) {
    $definitions = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true))
    if ($definitions.Count -ne 1) { throw "Expected one function $name" }
    Set-Item -Path ("Function:\script:" + $name) -Value $definitions[0].Body.GetScriptBlock()
}
foreach ($variableName in @('MsixFirstPartyEngineLeaves', 'MsixPinnedDependencyLeaves')) {
    $target = '$' + $variableName
    $assignments = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq $target
    }, $true))
    if ($assignments.Count -ne 1) { throw "Expected one assignment for $target" }
    Set-Variable -Scope Script -Name $variableName -Value (& ([scriptblock]::Create($assignments[0].Right.Extent.Text)))
}
function Assert-WinsProducerSignature {
    param($Path, $SignerPattern, $SignTool, $ExpectedLeafSha256)
    Write-Host ('VERIFIED ' + [IO.Path]::GetFileName($Path))
    return @{ signer_subject = 'CN=Example'; signer_leaf_sha256 = ('ab' * 32) }
}
$script:MsixSigning = if ($Mode -ceq 'signed') {
    [pscustomobject]@{ SignerPattern = '^CN=Example'; SignTool = 'signtool.exe'; LeafSha256Pin = '' }
} else { $null }
Assert-MsixPackageSignatureState -PackagePath (Join-Path $VerifyRoot 'WinsVPN.msix') -VerifyRoot $VerifyRoot
Write-Host 'STATE-OK'
"""


def body(start: str, end: str) -> str:
    begin = PACKAGER.index(start)
    return PACKAGER[begin : PACKAGER.index(end, begin)]


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def flatten(output: str) -> str:
    # pwsh wraps error records across "| " continuation lines.
    plain = ANSI.sub("", output).replace("\r", " ")
    return " ".join(re.sub(r"\s+\|\s+", " ", plain).split())


def signing_free_env(**overrides: str) -> dict[str, str]:
    env = os.environ.copy()
    for name in SIGNING_ENVIRONMENT:
        env.pop(name, None)
    env["NO_COLOR"] = "1"
    env.update(overrides)
    return env


def run_pwsh(*args: str) -> subprocess.CompletedProcess[str]:
    if PWSH is None:
        raise unittest.SkipTest("pwsh is unavailable for MSIX producer tests")
    return subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(PACKAGER_PATH), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=signing_free_env(),
    )


def run_identity(call: str) -> subprocess.CompletedProcess[str]:
    if PWSH is None:
        raise unittest.SkipTest("pwsh is unavailable for MSIX producer tests")
    with tempfile.TemporaryDirectory(prefix="winsvpn-msix-identity-") as raw:
        harness = pathlib.Path(raw) / "identity-harness.ps1"
        harness.write_text(IDENTITY_HARNESS, encoding="utf-8")
        return subprocess.run(
            [
                PWSH,
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(harness),
                str(PACKAGER_PATH),
                str(ROOT / "pubspec.yaml"),
                call,
            ],
            cwd=raw,
            capture_output=True,
            text=True,
            check=False,
            env=signing_free_env(),
        )


class WindowsMsixIdentityTests(unittest.TestCase):
    def test_template_takes_identity_and_version_from_the_producer(self) -> None:
        for token in (
            "@IDENTITY_NAME@",
            "@PUBLISHER@",
            "@PACKAGE_VERSION@",
            "@PUBLISHER_DISPLAY_NAME@",
            "@PROCESSOR_ARCHITECTURE@",
        ):
            self.assertIn(token, TEMPLATE)
        self.assertIn('Version="@PACKAGE_VERSION@"', TEMPLATE)
        self.assertNotRegex(TEMPLATE, r'(?m)^\s*Version="\d')
        self.assertIn("Wintun kernel-mode driver", TEMPLATE)
        self.assertIn("Winn Protocol v3", TEMPLATE)
        self.assertIn("Winn v1 AmneziaWG then Xray fallback", TEMPLATE)
        self.assertNotIn(
            "feature-complete app requires a Windows kernel driver",
            TEMPLATE,
        )
        self.assertNotIn("mullvad", TEMPLATE.casefold())

    def test_production_needs_only_the_partner_center_identity(self) -> None:
        for retired in (
            "Production MSIX generation is disabled",
            "1.0.15",
            "never a Store upload target",
            "Assert-MsixAuthenticodePreconditions",
            "The MSIX route is unsigned and is not a Store upload target",
            "OWNER-BLOCKED",
            "owner-blocked",
            "publication_authorized",
            "production_submission_allowed",
        ):
            self.assertNotIn(retired, PACKAGER)
        self.assertIn("$identity = Get-ReleaseIdentity", PACKAGER)
        self.assertIn("WinsVPN.Development", PACKAGER)
        self.assertIn("CN=WinsVPNDevelopment", PACKAGER)
        self.assertIn(
            "Development MSIX identity must not use the production Store name",
            PACKAGER,
        )
        self.assertIn(
            "} elseif ([string]::IsNullOrWhiteSpace($IdentityName) -or\n"
            "    [string]::IsNullOrWhiteSpace($Publisher) -or\n"
            "    [string]::IsNullOrWhiteSpace($PublisherDisplayName)) {\n"
            "    throw $ProductionMsixBlockedReason\n}",
            PACKAGER,
        )
        self.assertIn("Production MSIX needs the Partner Center package identity", PACKAGER)
        self.assertIn("-Production:(-not $DevelopmentIdentity)", PACKAGER)
        self.assertIn(
            "$script:MsixSigning = Resolve-WinsProducerSigningConfiguration -RepoRoot $Root `\n"
            "    -Architecture $TargetArchitecture -RequireSigning:$RequireCodeSigning",
            PACKAGER,
        )
        production_throw = PACKAGER.index("throw $ProductionMsixBlockedReason")
        development_block = PACKAGER.index("if ($DevelopmentIdentity)")
        self.assertLess(development_block, production_throw)

    def test_identity_contract_executes_with_pubspec_version_and_production_identity(self) -> None:
        call = (
            "Assert-MsixIdentityContract -IdentityName 'WinsVPN.Product' "
            "-Publisher 'CN=00000000-0000-0000-0000-000000000000' -PublisherDisplayName \"Win's VPN\" "
            "-Architecture 'x64' -PackageVersion '%s' -Production; "
            "Write-Output ('PRODUCTION-OK ' + $CanonicalMsixFilename)" % PUBSPEC_PACKAGE_VERSION
        )
        completed = run_identity(call)
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, output)
        self.assertIn("PRODUCTION-OK " + CANONICAL_MSIX, output)
        refusals = (
            (
                "Assert-MsixIdentityContract -IdentityName $DevelopmentIdentityName "
                "-Publisher $DevelopmentPublisher -PublisherDisplayName $DevelopmentPublisherDisplayName "
                "-Architecture 'x64' -PackageVersion $CanonicalPackageVersion -Production",
                "Production MSIX identity must be the Partner Center identity",
            ),
            (
                "Assert-MsixIdentityContract -IdentityName 'WinsVPN.Product' "
                "-Publisher 'CN=Example' -PublisherDisplayName 'Example' "
                "-Architecture 'x64' -PackageVersion '1.0.15.30' -Production",
                "is not the pubspec.yaml release mapping " + PUBSPEC_SOURCE_VERSION,
            ),
            (
                "Assert-MsixIdentityContract -IdentityName 'WinsVPN.Product' "
                "-Publisher 'CN=Example' -PublisherDisplayName 'Example' "
                "-Architecture 'arm64' -PackageVersion $CanonicalPackageVersion -Production",
                "exactly x64",
            ),
            (
                "Assert-MsixIdentityContract -IdentityName 'WinsVPN.Product' "
                "-Publisher 'Example' -PublisherDisplayName 'Example' "
                "-Architecture 'x64' -PackageVersion $CanonicalPackageVersion -Production",
                "must start with CN=",
            ),
            (
                "Assert-MsixIdentityContract -IdentityName 'WinsVPN.Product' "
                "-Publisher 'CN=Example' -PublisherDisplayName 'Example' "
                "-Architecture 'x64' -PackageVersion $CanonicalPackageVersion",
                "exact WinsVPN.Development / CN=WinsVPNDevelopment contract",
            ),
        )
        for call, needle in refusals:
            with self.subTest(needle=needle):
                completed = run_identity(call)
                output = flatten(completed.stdout + completed.stderr)
                self.assertNotEqual(completed.returncode, 0, output)
                self.assertIn(needle, output)

    def test_msix_is_not_a_windows_upload_target(self) -> None:
        for invented in (
            "windows-x64-store-msix",
            "windows-x64-msix",
            "windows-arm64-store-msix",
        ):
            with self.assertRaisesRegex(
                gate.WindowsArtifactGateError,
                "unsupported exact Windows package/upload target",
            ):
                gate._package_upload_target(invented)
        self.assertEqual(
            gate.WINDOWS_MSIX_PACKAGE_FILENAME,
            CANONICAL_MSIX,
        )
        self.assertNotIn(
            gate.WINDOWS_MSIX_PACKAGE_FILENAME,
            gate.TARGET_FILENAMES.values(),
        )

    def test_exact_package_version_publisher_architecture_and_capability(self) -> None:
        self.assertIn(
            '$CanonicalMsixFilename = "WinsVPN-Store-$CanonicalPackageVersion-x64.msix"',
            PACKAGER,
        )
        self.assertIn(
            "$CanonicalPackageVersion = [string]$PubspecReleaseIdentity.PackageVersion",
            PACKAGER,
        )
        self.assertNotRegex(PACKAGER, r"\$CanonicalPackageVersion\s*=\s*'")
        self.assertIn("$CanonicalMsixArchitecture = 'x64'", PACKAGER)
        self.assertIn("$DevelopmentIdentityName = 'WinsVPN.Development'", PACKAGER)
        self.assertIn("$DevelopmentPublisher = 'CN=WinsVPNDevelopment'", PACKAGER)
        self.assertIn("function Assert-MsixIdentityContract", PACKAGER)
        identity = body(
            "function Assert-MsixIdentityContract",
            "function New-MsixMsiexecExtractArgumentList",
        )
        self.assertIn("exactly x64", identity)
        self.assertIn("exact WinsVPN.Development / CN=WinsVPNDevelopment contract", identity)
        self.assertIn("Production MSIX identity must be the Partner Center identity", identity)
        self.assertIn("function Assert-MsixPackedManifestText", PACKAGER)
        self.assertIn("$RequiredMsixCapabilityNames = @(", PACKAGER)
        for capability in (
            "internetClient",
            "privateNetworkClientServer",
            "runFullTrust",
            "allowElevation",
        ):
            self.assertIn("'" + capability + "'", PACKAGER)
        packed = body(
            "function Assert-MsixPackedManifestText",
            "function Assert-MsixStageForbidsForeignIdentities",
        )
        self.assertIn("broadFileSystemAccess", PACKAGER)
        self.assertIn("Packed MSIX capability set is not the exact reviewed contract.", packed)
        self.assertIn(
            "Packed MSIX identity does not match the requested Partner Center identity.",
            packed,
        )

    def test_signed_partner_center_payloads_are_bound_and_refused(self) -> None:
        self.assertIn("$PartnerCenterX64Filename = '%s'" % PARTNER_CENTER_X64, PACKAGER)
        self.assertIn(
            "$PartnerCenterArm64Filename = '%s'" % PARTNER_CENTER_ARM64,
            PACKAGER,
        )
        self.assertIn("$WebsiteX64Filename = '%s'" % WEBSITE_X64, PACKAGER)
        self.assertIn("$WebsiteArm64Filename = '%s'" % WEBSITE_ARM64, PACKAGER)
        self.assertIn(
            '$Arm64MsixFilename = "WinsVPN-Store-$CanonicalPackageVersion-arm64.msix"',
            PACKAGER,
        )
        self.assertIn("function Assert-MsixNotPartnerCenterPath", PACKAGER)
        self.assertIn("signed_partner_center_payloads", PACKAGER)
        self.assertIn("x64 = $PartnerCenterX64Filename", PACKAGER)
        self.assertIn("arm64 = $PartnerCenterArm64Filename", PACKAGER)
        self.assertIn("producer = 'installer/windows/build_installer.ps1'", PACKAGER)
        self.assertIn("signer = 'tools/windows_inno_sign.ps1'", PACKAGER)
        self.assertIn("cannot relabel ARM64 Partner Center payloads as MSIX", PACKAGER)
        self.assertNotIn("Start-Process -FilePath 'msiexec.exe'", PACKAGER)

    def test_path_and_argument_injection_are_fail_closed(self) -> None:
        self.assertIn("function Assert-MsixSafeToken", PACKAGER)
        self.assertIn("function Assert-MsixMsiexecPath", PACKAGER)
        self.assertIn("function Assert-MsixArgumentList", PACKAGER)
        self.assertIn("function New-MsixMsiexecExtractArgumentList", PACKAGER)
        self.assertIn("function New-MsixMakeAppxPackArgumentList", PACKAGER)
        self.assertIn("would inject msiexec arguments", PACKAGER)
        self.assertIn("PowerShell stop-parsing token", PACKAGER)
        self.assertIn("Assert-MsixRepoBoundPath", PACKAGER)
        self.assertIn("must stay inside the repository tree", PACKAGER)
        self.assertIn("function Assert-NoReparsePointChain", PACKAGER)
        native = body("function Invoke-Native", "function Find-WindowsSdkTool")
        self.assertIn("MSIX producer refuses SignTool", native)
        self.assertIn("makeappx is limited to pack and unpack", native)
        self.assertLess(
            native.index("MSIX producer refuses SignTool"),
            native.index("& $FilePath @Arguments"),
        )
        sdk = body("function Find-WindowsSdkTool", "function Write-AtomicNewUtf8File")
        self.assertNotIn("-Recurse", sdk)
        self.assertIn("Windows Kits\\10\\bin", sdk)
        self.assertIn("exact executable leaf", sdk)
        msiexec = body(
            "function New-MsixMsiexecExtractArgumentList",
            "function New-MsixMakeAppxPackArgumentList",
        )
        self.assertIn("TARGETDIR=' + $Destination", msiexec)
        self.assertNotIn("'\"' + $", msiexec)

    def test_partial_output_is_quarantined_and_removed_on_failure(self) -> None:
        self.assertIn("function Quarantine-StaleMsixOutputs", PACKAGER)
        self.assertIn("function Remove-MsixPartialOutputs", PACKAGER)
        self.assertIn("function Write-AtomicNewUtf8File", PACKAGER)
        self.assertIn("Stale canonical MSIX output survived quarantine", PACKAGER)
        self.assertIn("Partial MSIX output could not be removed", PACKAGER)
        self.assertIn("[IO.File]::Move($script:MsixStagedPackage, $Package)", PACKAGER)
        self.assertIn("msix-partial-", PACKAGER)
        self.assertIn("Remove-MsixPartialOutputs", PACKAGER)
        quarantine = PACKAGER.index("Quarantine-StaleMsixOutputs -PackagePath $Package")
        pack = PACKAGER.index("New-MsixMakeAppxPackArgumentList -StageDirectory $Stage")
        move = PACKAGER.index("[IO.File]::Move($script:MsixStagedPackage, $Package)")
        receipt = PACKAGER.index("Write-AtomicNewUtf8File -Path $PayloadManifest")
        published = PACKAGER.index("$script:MsixPublishedByThisRun = $true", receipt)
        cleanup = PACKAGER.index("Remove-MsixPartialOutputs\n    throw")
        self.assertLess(quarantine, pack)
        self.assertLess(pack, move)
        self.assertLess(move, receipt)
        self.assertLess(receipt, published)
        self.assertGreater(cleanup, pack)

    def test_signer_then_timestamp_order_and_signing_through_the_shared_policy(self) -> None:
        self.assertIn("function Assert-MsixSignerTimestampOrder", PACKAGER)
        self.assertIn("timestamp must not precede signer", PACKAGER)
        self.assertIn("partially signed artifact is not shippable", PACKAGER)
        self.assertIn("timestamp verification /tw must follow SignTool verify", PACKAGER)
        self.assertIn(
            "$msixSignerOrder = if ($msixSigned) { 'sign-then-rfc3161-timestamp-then-verify' } else { 'unsigned' }",
            PACKAGER,
        )
        self.assertIn("WINS_WINDOWS_TIMESTAMP_URL", PACKAGER)
        self.assertIn("function Assert-MsixPackageUnsigned", PACKAGER)
        self.assertIn("function Assert-MsixPackageSigned", PACKAGER)
        self.assertIn("AppxSignature.p7x", PACKAGER)
        order = body(
            "function Assert-MsixSignerTimestampOrder",
            "function Test-MsixPathIsInsideRoot",
        )
        sign = order.index("$token.Equals('sign'")
        timestamp = order.index("$token.Equals('/tr'")
        digest = order.index("$token.Equals('/td'")
        verify = order.index("$token.Equals('verify'")
        tw = order.index("$token.Equals('/tw'")
        self.assertLess(sign, timestamp)
        self.assertLess(timestamp, digest)
        self.assertLess(digest, verify)
        self.assertLess(verify, tw)
        self.assertEqual(PACKAGER.count(SIGNING_BEGIN), 1)
        block_start = PACKAGER.index(SIGNING_BEGIN)
        block_end = PACKAGER.index(SIGNING_END) + len(SIGNING_END)
        outside = PACKAGER[:block_start] + PACKAGER[block_end:]
        # SignTool runs only inside the shared build_installer.ps1-equivalent
        # policy block; the producer body never calls it directly.
        self.assertNotRegex(outside, r"(?im)^\s*(\$\w+\s*=\s*)?& \$sign")
        self.assertIn("& $SignTool verify /pa /all /v /tw $Path", PACKAGER[block_start:block_end])
        self.assertNotIn("Invoke-Native $makeAppx sign", PACKAGER)
        self.assertNotIn("pack /d $Stage /p $Package /o", PACKAGER)
        payload = PACKAGER.index("        Invoke-MsixFirstPartySigning -StageRoot $Stage")
        package = PACKAGER.index(
            "[void](Invoke-WinsProducerSigning -Path $script:MsixStagedPackage -Signing $script:MsixSigning)"
        )
        pack = PACKAGER.index("Invoke-Native $makeAppx @packArgs")
        self.assertLess(payload, pack)
        self.assertLess(pack, package)

    def test_post_build_re_audit_binds_identity_payload_and_receipt(self) -> None:
        self.assertIn("function Assert-MsixPostBuildReAudit", PACKAGER)
        self.assertIn("Post-build MSIX receipt hash does not match the packed artifact.", PACKAGER)
        self.assertIn(
            "Post-build MSIX receipt lost the exact x64/arm64 Partner Center signed payload binding.",
            PACKAGER,
        )
        reaudit = body(
            "function Assert-MsixPostBuildReAudit",
            "function Get-ReleaseIdentity",
        )
        self.assertIn("Assert-MsixPackedManifestText", reaudit)
        self.assertIn("Assert-MsixStageCompleteness", reaudit)
        self.assertIn(
            "Assert-MsixPackageSignatureState -PackagePath $PackagePath -VerifyRoot $VerifyRoot",
            reaudit,
        )
        self.assertNotIn("owner_authenticode_leaf_sha256", reaudit)
        self.assertNotIn("publication_authorized", reaudit)
        self.assertIn("[string]$receipt.authenticode_status -cne $expectedStatus", reaudit)
        self.assertIn("[bool]$receipt.timestamp_verified -ne $signed", reaudit)
        self.assertIn("awg.exe", reaudit)
        self.assertIn("wintun.dll", reaudit)
        self.assertIn("xray.exe", reaudit)
        self.assertIn("amneziawg.exe", reaudit)
        unpack = PACKAGER.index("New-MsixMakeAppxUnpackArgumentList")
        reaudit_call = PACKAGER.index("Assert-MsixPostBuildReAudit -VerifyRoot")
        self.assertLess(unpack, reaudit_call)
        self.assertLess(
            PACKAGER.index("Write-AtomicNewUtf8File -Path $PayloadManifest"),
            reaudit_call,
        )

    def test_signature_state_verifies_package_and_first_party_payloads(self) -> None:
        if PWSH is None:
            self.skipTest("pwsh is unavailable for MSIX producer tests")
        with tempfile.TemporaryDirectory(prefix="winsvpn-msix-state-") as raw:
            root = pathlib.Path(raw)
            verify = root / "verify"
            (verify / "plugins").mkdir(parents=True)
            for name in (
                "wins_vpn.exe",
                "wins_vpn_tunnel_service.exe",
                "winn-datapath.exe",
                "winsvpn_winn3_engine.exe",
                "winsvpn_awg_engine.exe",
                "flutter_windows.dll",
                "awg.exe",
                "wintun.dll",
                "xray.exe",
                "amneziawg.exe",
            ):
                (verify / name).write_bytes(b"MZ")
            (verify / "plugins" / "plugin.dll").write_bytes(b"MZ")
            harness = root / "state.ps1"
            harness.write_text(SIGNATURE_STATE_HARNESS, encoding="utf-8")

            def run(mode: str) -> tuple[int, str]:
                completed = subprocess.run(
                    [PWSH, "-NoProfile", "-NonInteractive", "-File", str(harness),
                     str(PACKAGER_PATH), str(verify), mode],
                    cwd=raw, capture_output=True, text=True, check=False, env=signing_free_env(),
                )
                return completed.returncode, flatten(completed.stdout + completed.stderr)

            code, output = run("signed")
            self.assertNotEqual(code, 0, output)
            self.assertIn("Signed MSIX is missing AppxSignature.p7x.", output)
            (verify / "AppxSignature.p7x").write_bytes(b"p7x")
            code, output = run("signed")
            self.assertEqual(code, 0, output)
            self.assertIn("STATE-OK", output)
            verified = re.findall(r"VERIFIED (\S+)", output)
            self.assertEqual(verified[0], "WinsVPN.msix")
            self.assertEqual(
                verified[1:4],
                ["winn-datapath.exe", "winsvpn_winn3_engine.exe", "winsvpn_awg_engine.exe"],
            )
            self.assertEqual(
                sorted(verified[4:]),
                sorted(["flutter_windows.dll", "plugin.dll", "wins_vpn.exe", "wins_vpn_tunnel_service.exe"]),
            )
            for pinned in ("awg.exe", "wintun.dll", "xray.exe", "amneziawg.exe"):
                self.assertNotIn(pinned, verified)
            code, output = run("unsigned")
            self.assertNotEqual(code, 0, output)
            self.assertIn("Packed MSIX contains AppxSignature.p7x but no signing identity is configured", output)
            (verify / "AppxSignature.p7x").unlink()
            code, output = run("unsigned")
            self.assertEqual(code, 0, output)
            self.assertNotIn("VERIFIED", output)

    def test_source_is_ascii(self) -> None:
        raw = PACKAGER_PATH.read_bytes()
        raw.decode("ascii")
        pathlib.Path(__file__).read_bytes().decode("ascii")


@unittest.skipUnless(PWSH, "pwsh is required for executable MSIX producer tests")
class WindowsMsixIdentityHostileTests(unittest.TestCase):
    def test_boundary_selftest_rejects_hostile_inputs(self) -> None:
        completed = run_pwsh("-BoundarySelfTest")
        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, msg=output)
        self.assertIn("WINDOWS STORE MSIX BOUNDARY SELF-TEST: PASS", output)
        self.assertNotIn("WINDOWS STORE MSIX CANDIDATE: PASS", output)

    def test_selftest_cannot_be_combined_with_boundary_selftest(self) -> None:
        completed = run_pwsh("-BoundarySelfTest", "-SelfTest")
        output = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0, output)
        self.assertIn("BoundarySelfTest cannot be combined with -SelfTest", output)

    def test_current_awg_generation_passes_packager_selftest(self) -> None:
        completed = run_pwsh("-SelfTest")
        output = flatten(completed.stdout + completed.stderr)
        self.assertEqual(completed.returncode, 0, output)
        self.assertIn("WINDOWS STORE MSIX SELF-TEST: PASS", output)
        self.assertNotIn("WINDOWS STORE MSIX CANDIDATE: BUILT", output)

    def test_signing_environment_is_resolved_by_the_shared_policy(self) -> None:
        cases = (
            (
                {"WINS_WINDOWS_TIMESTAMP_URL": "https://evil.example/ts /f C:\\pwn.pfx"},
                "exact approved Microsoft/DigiCert RFC 3161 endpoint",
            ),
            (
                {"WINS_WINDOWS_SIGN_PFX": "C:\\evil.pfx"},
                "PFX command-line signing (WINS_WINDOWS_SIGN_PFX/WINS_WINDOWS_SIGN_PFX_PASSWORD) is disabled",
            ),
            (
                {"WINS_WINDOWS_SIGN_CERT_SHA1": "A" * 40},
                "WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required for a signed release.",
            ),
        )
        for overrides, needle in cases:
            with self.subTest(env=sorted(overrides)), tempfile.TemporaryDirectory(
                prefix="winsvpn-msix-env-"
            ) as tmp:
                completed = subprocess.run(
                    [
                        PWSH,
                        "-NoProfile",
                        "-NonInteractive",
                        "-File",
                        str(PACKAGER_PATH),
                        "-DevelopmentIdentity",
                        "-SkipFlutterBuild",
                        "-OutputDirectory",
                        tmp,
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    env=signing_free_env(**overrides),
                )
                output = flatten(completed.stdout + completed.stderr)
                self.assertNotEqual(completed.returncode, 0, output)
                self.assertIn(needle, output)
                self.assertNotIn("refusing to mix signing credentials", output)
                self.assertFalse(list(pathlib.Path(tmp).glob("*.msix")))
        completed = run_pwsh("-SkipFlutterBuild", "-RequireCodeSigning")
        output = flatten(completed.stdout + completed.stderr)
        self.assertNotEqual(completed.returncode, 0, output)
        self.assertIn("Windows release signing is required.", output)

    def test_repo_bound_output_is_checked_before_makeappx_pack(self) -> None:
        bind = PACKAGER.index("Assert-MsixRepoBoundPath -Path $OutputDirectory")
        pack = PACKAGER.index(
            "New-MsixMakeAppxPackArgumentList -StageDirectory $Stage"
        )
        self.assertLess(bind, pack)
        self.assertLess(
            PACKAGER.index("Assert-MsixIdentityContract -IdentityName $IdentityName"),
            pack,
        )


if __name__ == "__main__":
    unittest.main()
